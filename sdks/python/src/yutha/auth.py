"""Bearer-token authentication for the async gRPC client.

The Yutha control plane (Rust ``crates/yutha-control-plane/src/auth.rs``)
gates every authenticated RPC on an ``authorization: bearer <hex>``
metadata header. The hex bytes are a prost-encoded
:class:`yutha._proto.control_plane.v1.AgentBearerToken` with the
signature already attached; the server hex-decodes, prost-decodes,
checks swarm binding + expiry + Ed25519 signature against the
registered passport public key, and rejects on any mismatch.

This module is the Python side of that contract:

  - :class:`BearerSession` owns a private signing key and mints fresh
    ``AgentBearerToken`` instances on demand. It caches the active token
    and re-mints it as the expiry approaches (controlled by
    ``refresh_lead_seconds``).
  - :func:`make_interceptors` returns the four
    ``grpc.aio`` client interceptors (unary-unary, unary-stream,
    stream-unary, stream-stream) wired to a session. Hand them to
    ``grpc.aio.secure_channel(..., interceptors=...)`` and every
    outbound call picks up the ``authorization`` header automatically.

The interceptor is "soft" in one specific way: if the
``yutha-no-auth`` metadata key is present on a call (set by the SDK's
high-level :meth:`YuthaClient.admission.register`), the interceptor
skips injecting the header. ``AdmissionService.Register`` is the only
RPC the server allows without a bearer — the passport IS the
credential — and we can't mint a token before registering.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import grpc
from grpc.aio import (
    ClientCallDetails,
    Metadata,
    StreamStreamClientInterceptor,
    StreamUnaryClientInterceptor,
    UnaryStreamClientInterceptor,
    UnaryUnaryClientInterceptor,
)

from yutha._proto.control_plane import v1_pb2 as cp_pb2
from yutha.canonical import canonical_bytes
from yutha.crypto import SigningKey
from yutha.identity import AgentId, SwarmId, Timestamp

# Metadata sentinel: callers attach this key to a call's metadata to
# tell the bearer interceptor to skip injection. Only `Register`
# (anonymous per spec) sets this.
NO_AUTH_METADATA_KEY = "yutha-no-auth"


# =============================================================================
# Session
# =============================================================================


def _advance_wall_clock(rfc3339: str, seconds: float) -> str:
    """Advance an RFC 3339 wall-clock string by ``seconds`` and re-render
    in the same Z-suffixed UTC shape ``Timestamp.now()`` emits.

    Used by :class:`BearerSession` to compute a future ``expires_at``
    that the server's wall-clock expiry check (RFC 0008) reads as
    not-yet-elapsed. Python's ``datetime.fromisoformat`` handles
    ``"…Z"`` natively on 3.11+, so we round-trip through naive UTC
    aware datetime arithmetic."""
    # `fromisoformat` accepts both "...+00:00" and "...Z" on 3.11+.
    # Normalize a trailing 'Z' to '+00:00' for older runtimes too.
    parsed = datetime.fromisoformat(rfc3339.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    future = parsed + timedelta(seconds=seconds)
    # Render in the same Z-suffixed UTC shape `Timestamp.now()` emits.
    return future.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class _CachedToken:
    """A minted token plus the wall-clock + monotonic deadlines we use
    to decide when to re-mint. Stored together so we can mint once and
    serve many requests without re-parsing."""

    hex_value: str
    expires_monotonic_ns: int


class BearerSession:
    """Owns a passport signing key; mints and caches
    ``AgentBearerToken`` headers for outbound gRPC calls.

    A single session is safe to share across many concurrent RPCs.
    Token minting is serialized through an :class:`asyncio.Lock` so
    only one coroutine renews at a time when the active token nears
    expiry.

    Parameters
    ----------
    agent_id, swarm_id, signing_key
        The bearer's identity. ``signing_key``'s public counterpart
        MUST match the public key on the registered passport; the
        server resolves ``agent_id`` against the passport store and
        verifies the token's signature with that public key.
    token_lifetime_seconds
        How long each minted token is valid. Recommended ≤ 5 minutes
        per the spec rationale (short-lived tokens limit blast radius
        if a token leaks). Default 300 s.
    refresh_lead_seconds
        Re-mint when the active token has less than this much remaining
        validity. Should be larger than worst-case RPC latency so a
        renewal can complete before the existing token expires.
        Default 30 s.
    """

    def __init__(
        self,
        agent_id: AgentId,
        swarm_id: SwarmId,
        signing_key: SigningKey,
        *,
        token_lifetime_seconds: int = 300,
        refresh_lead_seconds: int = 30,
    ) -> None:
        if refresh_lead_seconds >= token_lifetime_seconds:
            raise ValueError(
                "refresh_lead_seconds must be smaller than token_lifetime_seconds; "
                "otherwise the cache is always expired"
            )
        self._agent_id = agent_id
        self._swarm_id = swarm_id
        self._signing_key = signing_key
        self._lifetime_ns = token_lifetime_seconds * 1_000_000_000
        self._refresh_lead_ns = refresh_lead_seconds * 1_000_000_000
        self._cache: _CachedToken | None = None
        self._lock = asyncio.Lock()

    @property
    def agent_id(self) -> AgentId:
        return self._agent_id

    @property
    def swarm_id(self) -> SwarmId:
        return self._swarm_id

    async def header_value(self) -> str:
        """Return ``"bearer <hex>"`` suitable for the
        ``authorization`` metadata header. Mints (or re-mints) the
        underlying token as needed."""
        now_ns = time.monotonic_ns()
        cached = self._cache
        # Fast path: token still has plenty of life.
        if cached is not None and cached.expires_monotonic_ns - now_ns > self._refresh_lead_ns:
            return f"bearer {cached.hex_value}"

        async with self._lock:
            # Re-check under the lock — another waiter may have already
            # renewed.
            cached = self._cache
            now_ns = time.monotonic_ns()
            if cached is not None and cached.expires_monotonic_ns - now_ns > self._refresh_lead_ns:
                return f"bearer {cached.hex_value}"
            minted = self._mint()
            self._cache = minted
            return f"bearer {minted.hex_value}"

    def _mint(self) -> _CachedToken:
        """Build, sign, and hex-encode a fresh bearer token.

        Mirrors the Rust server's expectations:
          1. Construct the AgentBearerToken proto with required fields.
          2. Serialize with signature/extensions cleared → canonical bytes.
          3. Ed25519-sign the canonical bytes with the passport key.
          4. Re-encode the token with the signature attached.
          5. Hex-encode the wire bytes.
        """
        now = Timestamp.now()
        expires_monotonic_ns = now.monotonic_ns + self._lifetime_ns
        # RFC 0008: the server checks expiry on `wall_clock`, not
        # `monotonic_ns`. Advance both: wall_clock by lifetime
        # seconds (parsed as RFC 3339, advanced as a real datetime,
        # re-rendered Z-suffixed UTC) so the future-anchored token
        # actually reads as not-yet-expired server-side. monotonic_ns
        # still advances too — kept for the in-process cache's
        # refresh-lead logic and for audit-log correlation.
        expires_at = Timestamp(
            wall_clock=_advance_wall_clock(now.wall_clock, self._lifetime_ns / 1_000_000_000),
            monotonic_ns=expires_monotonic_ns,
        )

        token = cp_pb2.AgentBearerToken(
            agent_id=self._agent_id.to_proto(),
            swarm_id=self._swarm_id.to_proto(),
            issued_at=now.to_proto(),
            expires_at=expires_at.to_proto(),
            # 16-byte random nonce — same convention as the Rust side.
            nonce=os.urandom(16),
        )
        # Canonical bytes: token with signature + extensions cleared.
        canonical = canonical_bytes(token)
        sig = self._signing_key.sign_message(canonical)
        token.signature.CopyFrom(sig.to_proto())

        wire = token.SerializeToString()
        return _CachedToken(
            hex_value=wire.hex(),
            expires_monotonic_ns=expires_monotonic_ns,
        )


class OperatorBearerSession:
    """Owns an operator signing key; mints and caches
    ``OperatorBearerToken`` headers for outbound gRPC calls.

    Sibling of :class:`BearerSession` for the operator credential path
    (RFC 0009). Same cache + async-lock semantics; same wall-clock
    expiry rules. The wire prefix is ``"bearer operator <hex>"`` —
    that's how the server's auth helper distinguishes operator tokens
    from agent tokens on the same ``authorization`` header.

    The ``operator_signing_key``'s public counterpart MUST match the
    public key the control plane was started with
    (``--operator-public-key``). The server rejects tokens whose
    signature can't be verified against that configured key.

    Parameters
    ----------
    operator_id
        Free-form identifier persisted on the receipt's evidence.
        Useful for distinguishing multiple operators when (a future
        RFC ships) the server accepts multiple operator public keys.
    swarm_id
        The swarm this operator's tokens target.
    operator_signing_key
        Ed25519 private key. Stays in operator tooling; never
        transmitted.
    """

    def __init__(
        self,
        operator_id: str,
        swarm_id: SwarmId,
        operator_signing_key: SigningKey,
        *,
        token_lifetime_seconds: int = 300,
        refresh_lead_seconds: int = 30,
    ) -> None:
        if refresh_lead_seconds >= token_lifetime_seconds:
            raise ValueError(
                "refresh_lead_seconds must be smaller than token_lifetime_seconds; "
                "otherwise the cache is always expired"
            )
        self._operator_id = operator_id
        self._swarm_id = swarm_id
        self._signing_key = operator_signing_key
        self._lifetime_ns = token_lifetime_seconds * 1_000_000_000
        self._refresh_lead_ns = refresh_lead_seconds * 1_000_000_000
        self._cache: _CachedToken | None = None
        self._lock = asyncio.Lock()

    @property
    def operator_id(self) -> str:
        return self._operator_id

    @property
    def swarm_id(self) -> SwarmId:
        return self._swarm_id

    async def header_value(self) -> str:
        """Return ``"bearer operator <hex>"`` for the
        ``authorization`` metadata header. Mints (or re-mints) as
        needed; protocol matches :meth:`BearerSession.header_value`
        so the same interceptors can consume either session type."""
        now_ns = time.monotonic_ns()
        cached = self._cache
        if cached is not None and cached.expires_monotonic_ns - now_ns > self._refresh_lead_ns:
            return f"bearer operator {cached.hex_value}"

        async with self._lock:
            cached = self._cache
            now_ns = time.monotonic_ns()
            if cached is not None and cached.expires_monotonic_ns - now_ns > self._refresh_lead_ns:
                return f"bearer operator {cached.hex_value}"
            minted = self._mint()
            self._cache = minted
            return f"bearer operator {minted.hex_value}"

    def _mint(self) -> _CachedToken:
        """Build, sign, and hex-encode a fresh operator token. Same
        canonical-bytes-with-signature-cleared shape every other Yutha
        signed message uses."""
        now = Timestamp.now()
        expires_monotonic_ns = now.monotonic_ns + self._lifetime_ns
        expires_at = Timestamp(
            wall_clock=_advance_wall_clock(
                now.wall_clock, self._lifetime_ns / 1_000_000_000
            ),
            monotonic_ns=expires_monotonic_ns,
        )

        token = cp_pb2.OperatorBearerToken(
            operator_id=self._operator_id,
            swarm_id=self._swarm_id.to_proto(),
            issued_at=now.to_proto(),
            expires_at=expires_at.to_proto(),
            nonce=os.urandom(16),
        )
        canonical = canonical_bytes(token)
        sig = self._signing_key.sign_message(canonical)
        token.signature.CopyFrom(sig.to_proto())

        wire = token.SerializeToString()
        return _CachedToken(
            hex_value=wire.hex(),
            expires_monotonic_ns=expires_monotonic_ns,
        )


# =============================================================================
# Async gRPC interceptors
# =============================================================================


def _metadata_pairs(
    metadata: Metadata | None,
) -> Iterable[tuple[str, str | bytes]]:
    """Coerce a ``Metadata`` to the (key, value)-pair iterable it
    actually is at runtime.

    Stub-vs-runtime gotcha: types-grpcio declares
    ``Metadata.__iter__`` as ``Iterator[str]`` (as if Metadata were
    dict-like), but the real ``grpc.aio.Metadata`` class iterates as
    pairs (sequence-like). We cast once here so the rest of the file
    stays type-clean.
    """
    if metadata is None:
        return []
    return cast("Iterable[tuple[str, str | bytes]]", metadata)


def _augment_metadata(
    details: ClientCallDetails, additions: list[tuple[str, str]]
) -> ClientCallDetails:
    """Return a new ``ClientCallDetails`` with ``additions`` appended
    to ``metadata`` and the no-auth sentinel stripped out.

    grpc.aio's ``ClientCallDetails`` is implementation-defined as a
    NamedTuple-like structure; we copy it field-by-field rather than
    mutating the original (which is sometimes frozen)."""
    items: list[tuple[str, str | bytes]] = [
        (k, v) for k, v in _metadata_pairs(details.metadata) if k.lower() != NO_AUTH_METADATA_KEY
    ]
    items.extend(additions)
    return ClientCallDetails(
        method=details.method,
        timeout=details.timeout,
        metadata=Metadata(*items),
        credentials=details.credentials,
        wait_for_ready=details.wait_for_ready,
    )


def _has_no_auth_sentinel(details: ClientCallDetails) -> bool:
    return any(k.lower() == NO_AUTH_METADATA_KEY for k, _ in _metadata_pairs(details.metadata))


class _BearerUnaryUnary(UnaryUnaryClientInterceptor):
    def __init__(self, session: BearerSession | OperatorBearerSession) -> None:
        self._session = session

    async def intercept_unary_unary(
        self,
        continuation: Callable[..., Any],
        client_call_details: ClientCallDetails,
        request: Any,
    ) -> Any:
        if _has_no_auth_sentinel(client_call_details):
            new_details = _augment_metadata(client_call_details, [])
            return await continuation(new_details, request)
        header = await self._session.header_value()
        new_details = _augment_metadata(client_call_details, [("authorization", header)])
        return await continuation(new_details, request)


class _BearerUnaryStream(UnaryStreamClientInterceptor):
    def __init__(self, session: BearerSession | OperatorBearerSession) -> None:
        self._session = session

    async def intercept_unary_stream(
        self,
        continuation: Callable[..., Any],
        client_call_details: ClientCallDetails,
        request: Any,
    ) -> Any:
        if _has_no_auth_sentinel(client_call_details):
            new_details = _augment_metadata(client_call_details, [])
            return await continuation(new_details, request)
        header = await self._session.header_value()
        new_details = _augment_metadata(client_call_details, [("authorization", header)])
        return await continuation(new_details, request)


class _BearerStreamUnary(StreamUnaryClientInterceptor):
    def __init__(self, session: BearerSession | OperatorBearerSession) -> None:
        self._session = session

    async def intercept_stream_unary(
        self,
        continuation: Callable[..., Any],
        client_call_details: ClientCallDetails,
        request_iterator: Any,
    ) -> Any:
        if _has_no_auth_sentinel(client_call_details):
            new_details = _augment_metadata(client_call_details, [])
            return await continuation(new_details, request_iterator)
        header = await self._session.header_value()
        new_details = _augment_metadata(client_call_details, [("authorization", header)])
        return await continuation(new_details, request_iterator)


class _BearerStreamStream(StreamStreamClientInterceptor):
    def __init__(self, session: BearerSession | OperatorBearerSession) -> None:
        self._session = session

    async def intercept_stream_stream(
        self,
        continuation: Callable[..., Any],
        client_call_details: ClientCallDetails,
        request_iterator: Any,
    ) -> Any:
        if _has_no_auth_sentinel(client_call_details):
            new_details = _augment_metadata(client_call_details, [])
            return await continuation(new_details, request_iterator)
        header = await self._session.header_value()
        new_details = _augment_metadata(client_call_details, [("authorization", header)])
        return await continuation(new_details, request_iterator)


def make_interceptors(
    session: BearerSession | OperatorBearerSession,
) -> tuple[
    UnaryUnaryClientInterceptor,
    UnaryStreamClientInterceptor,
    StreamUnaryClientInterceptor,
    StreamStreamClientInterceptor,
]:
    """Build the four-interceptor tuple grpc.aio expects.

    Pass the result as ``interceptors=`` to
    :func:`grpc.aio.insecure_channel` /
    :func:`grpc.aio.secure_channel`. Works with either an agent
    :class:`BearerSession` or an :class:`OperatorBearerSession` —
    both implement the same ``async header_value()`` protocol the
    interceptors call into."""
    return (
        _BearerUnaryUnary(session),
        _BearerUnaryStream(session),
        _BearerStreamUnary(session),
        _BearerStreamStream(session),
    )


def skip_auth_metadata() -> list[tuple[str, str]]:
    """Convenience helper for callers that need to mark a single RPC as
    "no bearer" (only :meth:`YuthaClient.admission.register` uses
    this). Append this to your call's ``metadata`` argument."""
    return [(NO_AUTH_METADATA_KEY, "1")]


# `grpc` re-export so callers don't need to import it just to reference
# `grpc.aio` types in their own signatures.
__all__ = [
    "BearerSession",
    "OperatorBearerSession",
    "make_interceptors",
    "skip_auth_metadata",
    "NO_AUTH_METADATA_KEY",
    "grpc",
]

"""``YuthaClient`` — the top-level async client.

Aggregates the four gRPC service stubs over a single shared channel and
exposes ergonomic high-level methods that take and return the Pydantic
models from :mod:`yutha.models`.

Typical usage::

    async with YuthaClient.connect(
        address="127.0.0.1:50051",
        agent_id=my_agent_id,
        swarm_id=my_swarm_id,
        signing_key=my_signing_key,
    ) as client:
        outcome = await client.admission.register(my_passport)
        async for env, deliver_receipt in client.envelope.subscribe():
            ...

The four sub-objects (``client.admission``, ``client.capability``,
``client.envelope``, ``client.receipt``) wrap the corresponding gRPC
service stubs from
:mod:`yutha._proto.control_plane.v1_pb2_grpc`. They give Pydantic-typed
arguments and return values; the raw stubs remain accessible as
``client.<svc>._stub`` for callers who need an escape hatch.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Self, cast

import grpc

from yutha._proto.control_plane import v1_pb2 as cp_pb2
from yutha._proto.control_plane import v1_pb2_grpc as cp_grpc
from yutha.auth import BearerSession, OperatorBearerSession, skip_auth_metadata
from yutha.channel import make_channel
from yutha.crypto import SigningKey
from yutha.identity import AgentId, Hash, SwarmId
from yutha.models import (
    Capability,
    Envelope,
    Passport,
    Receipt,
)
from yutha.models.capability import ActionDescriptor, CheckOutcome

# Note on type-suppressions in this file:
#
# protoc generates the `_pb2_grpc.py` service stubs WITHOUT companion
# `.pyi` files, so every stub constructor (`AdmissionServiceStub(...)`)
# and every async call on a stub returns `Any` at the type level.
# Strict mypy then rejects them with `no-untyped-call` /
# `no-any-return`. We can't fix this upstream without writing our own
# stubs for the four service classes — substantial work for cosmetic
# benefit. Instead, the call sites use `cast()` to assert the return
# proto type (which IS typed in `_pb2.pyi`), and the four
# stub-constructor calls in `YuthaClient.__init__` carry per-line
# ignores.

# =============================================================================
# Service wrappers
# =============================================================================


# Prefix the Rust Send handler uses for capability-deny errors. We
# match on this string to convert server-side cap denies into the
# structured `CapabilityDenied` exception. Keep in sync with
# ``crates/yutha-control-plane/src/grpc/envelope.rs``.
_CAP_DENY_PREFIX = "capability check denied:"


def _maybe_raise_capability_denied(err: grpc.aio.AioRpcError) -> None:
    """If ``err`` is a server-side capability deny, translate it into
    :class:`yutha.langgraph.CapabilityDenied`. Otherwise return so the
    caller can re-raise the original ``AioRpcError``.

    Lazy-imports the exception class to keep :mod:`yutha.client` free
    of any ``yutha.langgraph`` dependency (which is an optional extra)."""
    if err.code() != grpc.StatusCode.PERMISSION_DENIED:
        return
    details = err.details() or ""
    if not details.startswith(_CAP_DENY_PREFIX):
        return
    reason = details[len(_CAP_DENY_PREFIX) :].strip()
    # Lazy import: yutha.langgraph depends on yutha.client, not the
    # other way around.
    from yutha.langgraph.tools import CapabilityDenied

    raise CapabilityDenied(reason) from err


async def _wrap_subscribe_stream(
    response_stream: AsyncIterator[cp_pb2.SubscribedEnvelope],
) -> AsyncIterator[tuple[Envelope, Hash]]:
    """Adapt the proto-typed response stream to the Pydantic-typed
    pairs callers want.

    Kept as a module-level async generator (rather than nested inside
    :meth:`EnvelopeAPI.subscribe`) so the parent method can construct
    the underlying :class:`grpc.aio.UnaryStreamCall` eagerly — only
    *this* body waits lazily for the first response.
    """
    async for item in response_stream:
        yield (
            Envelope.from_proto(item.envelope),
            Hash.from_proto(item.deliver_receipt),
        )


@dataclass(frozen=True)
class OperatorRevokeOutcome:
    """Both halves of an
    :meth:`AdmissionAPI.operator_revoke` result.

    ``eviction_receipt`` is the content-address of the
    ``agent.operator_revoke`` substrate receipt — present on every
    call. ``cascade_receipts`` carries the per-capability
    ``capability.revoke`` receipts produced when the caller passed
    ``cascade_capabilities=True``; the list is empty when cascade was
    not requested or when the target held no live capabilities (RFC
    0009 §3.2).

    Ordering of ``cascade_receipts`` mirrors the server's
    ``list_for_subject`` iteration order; the server gives no
    stability guarantee beyond "matches the order of the
    ``capability.revoke`` receipts in the receipt log over the same
    window", so audit consumers should sort by
    ``Receipt.monotonic_ns`` rather than relying on list position.
    """

    eviction_receipt: Hash
    cascade_receipts: list[Hash]


class AdmissionAPI:
    """Wraps :class:`AdmissionServiceStub`.

    :meth:`register` is the only RPC in the whole control-plane surface
    that's unauthenticated — the passport is the credential. Every
    other method requires the parent client's bearer session.
    """

    def __init__(self, stub: cp_grpc.AdmissionServiceStub) -> None:
        self._stub = stub

    async def register(self, passport: Passport) -> cp_pb2.RegisterResponse:
        """Register an agent. Returns the raw proto response — callers
        typically just want ``result.registration_receipt``. The
        registration receipt itself is queryable via
        :class:`ReceiptAPI`.

        Anonymous: no bearer token attached. The ``yutha-no-auth``
        metadata sentinel signals the bearer interceptor to skip
        injection.
        """
        resp = await self._stub.Register(
            cp_pb2.RegisterRequest(passport=passport.to_proto()),
            metadata=skip_auth_metadata(),
        )
        return cast(cp_pb2.RegisterResponse, resp)

    async def get_topology(self) -> cp_pb2.GetTopologyResponse:
        """Fetch the swarm's immutable topology. Returns the raw proto
        for now — a Pydantic Topology model is on the to-do list when
        client code starts caring about its fields."""
        resp = await self._stub.GetTopology(cp_pb2.GetTopologyRequest())
        return cast(cp_pb2.GetTopologyResponse, resp)

    async def revoke(self, target: AgentId, reason: str) -> Hash:
        """Self-revoke ``target`` — agent-bearer-authenticated;
        ``target`` MUST equal the bearer's own agent id (the server
        returns ``PERMISSION_DENIED`` otherwise). For cross-agent
        eviction by a swarm operator, see :meth:`operator_revoke`."""
        resp = cast(
            cp_pb2.RevokeResponse,
            await self._stub.Revoke(
                cp_pb2.RevokeRequest(agent_id=target.to_proto(), reason=reason)
            ),
        )
        return Hash.from_proto(resp.revocation_receipt)

    async def operator_revoke(
        self,
        target: AgentId,
        reason: str,
        *,
        cascade_capabilities: bool = False,
    ) -> OperatorRevokeOutcome:
        """Operator-level eviction of ``target`` (RFC 0009).

        Requires the client to have been built via
        :meth:`YuthaClient.connect_as_operator` so the bearer
        interceptor mints ``OperatorBearerToken`` headers; calling
        this from an agent-authenticated client gets
        ``UNAUTHENTICATED`` from the server.

        Returns an :class:`OperatorRevokeOutcome` carrying the
        ``agent.operator_revoke`` eviction receipt and — when the
        caller asked for ``cascade_capabilities=True`` — the list of
        per-capability ``capability.revoke`` receipts emitted as the
        server walked the target's outstanding caps (RFC 0009 §3.2).
        With cascade off, ``cascade_receipts`` is always the empty
        list; with cascade on, the list may still be empty if the
        target held no live caps at the moment of eviction.

        Note: prior to the cascade implementation landing, this
        method returned a bare ``Hash`` and the server returned
        ``UNIMPLEMENTED`` whenever ``cascade_capabilities=True``.
        Callers updating across that boundary need both the new
        return-type adoption and the awareness that cascade now
        succeeds rather than failing."""
        resp = cast(
            cp_pb2.OperatorRevokeResponse,
            await self._stub.OperatorRevoke(
                cp_pb2.OperatorRevokeRequest(
                    target=target.to_proto(),
                    reason=reason,
                    cascade_capabilities=cascade_capabilities,
                )
            ),
        )
        return OperatorRevokeOutcome(
            eviction_receipt=Hash.from_proto(resp.revocation_receipt),
            cascade_receipts=[Hash.from_proto(h) for h in resp.cascade_receipts],
        )


class CapabilityAPI:
    """Wraps :class:`CapabilityServiceStub`. All four methods require
    bearer auth.
    """

    def __init__(self, stub: cp_grpc.CapabilityServiceStub) -> None:
        self._stub = stub

    async def issue(self, capability: Capability) -> tuple[Hash, Hash]:
        """Issue a root capability. Returns ``(capability_id,
        issuance_receipt)``. The capability arrives unsigned in the
        wire shape; the server signs it with the control-plane's key
        as a scaffolding shortcut (see Rust ``capability.rs`` for the
        spec-gap callout)."""
        resp = cast(
            cp_pb2.IssueCapabilityResponse,
            await self._stub.Issue(cp_pb2.IssueCapabilityRequest(capability=capability.to_proto())),
        )
        return Hash.from_proto(resp.capability_id), Hash.from_proto(resp.issuance_receipt)

    async def revoke(self, capability_id: Hash, reason: str) -> Hash:
        """Revoke a capability. Returns the ``capability.revoke``
        receipt id."""
        from yutha._proto.capability import capability_v1_pb2 as cap_pb2

        resp = cast(
            cp_pb2.RevokeCapabilityResponse,
            await self._stub.Revoke(
                cp_pb2.RevokeCapabilityRequest(
                    request=cap_pb2.RevokeRequest(
                        capability=capability_id.to_proto(),
                        reason=reason,
                    )
                )
            ),
        )
        return Hash.from_proto(resp.response.revocation_receipt)

    async def check(self, capability: Capability, action: ActionDescriptor) -> CheckOutcome:
        """Stateless capability evaluation. Returns the policy outcome.

        Every check produces a server-side receipt — ``capability.check.pass``
        on permit, ``capability.check.deny`` on refusal — both signed by
        the control-plane and queryable via ``ReceiptAPI.query_by_action_kind``.
        See Rust ``yutha-capability::memory::check_inner`` for the
        receipt-emission path."""
        from yutha._proto.capability import capability_v1_pb2 as cap_pb2

        resp = cast(
            cp_pb2.CheckResponse,
            await self._stub.Check(
                cp_pb2.CheckRequest(
                    request=cap_pb2.CheckRequest(
                        capability=capability.to_proto(),
                        action=action.to_proto(),
                    )
                )
            ),
        )
        return CheckOutcome.from_proto(resp.response)


class EnvelopeAPI:
    """Wraps :class:`EnvelopeServiceStub`. Both methods require bearer
    auth.
    """

    def __init__(self, stub: cp_grpc.EnvelopeServiceStub) -> None:
        self._stub = stub

    async def send(self, envelope: Envelope, *, capability_id: Hash | None = None) -> Hash:
        """Send an envelope. Returns the ``envelope.send`` receipt id.

        ``envelope.from_agent`` MUST equal the bearer's agent id; the
        server rejects mismatched-sender envelopes with
        ``PERMISSION_DENIED``.

        ``capability_id`` is the content-address of the capability
        authorizing this send (RFC 0007). Required when the swarm's
        topology declares ``require_capability_for_send = true``; the
        server returns ``INVALID_ARGUMENT`` if it's missing. Optional
        in permissive topologies — but if supplied, the server runs
        the check anyway and emits a ``capability.check.{pass,deny}``
        receipt, which is useful for audit-trail completeness.

        On a server-side cap-check deny (revoked, expired, out-of-scope,
        unmet caveat), this method translates the resulting
        ``PERMISSION_DENIED: capability check denied: …`` into a
        :class:`yutha.langgraph.CapabilityDenied` exception so callers
        get a structured Python error rather than a raw gRPC one. Other
        ``PERMISSION_DENIED`` codes (e.g. sender/bearer mismatch)
        propagate unchanged as :class:`grpc.aio.AioRpcError`."""
        request = cp_pb2.SendEnvelopeRequest(envelope=envelope.to_proto())
        if capability_id is not None:
            request.capability_id.CopyFrom(capability_id.to_proto())
        try:
            resp = cast(
                cp_pb2.SendEnvelopeResponse,
                await self._stub.Send(request),
            )
        except grpc.aio.AioRpcError as e:
            _maybe_raise_capability_denied(e)
            raise
        return Hash.from_proto(resp.send_receipt)

    def subscribe(self, agent_id: AgentId | None = None) -> AsyncIterator[tuple[Envelope, Hash]]:
        """Open a long-lived subscription. Yields ``(envelope,
        deliver_receipt_id)`` pairs as envelopes arrive.

        ``agent_id`` defaults to the bearer's agent id; explicitly
        passing a different id triggers a server-side
        ``PERMISSION_DENIED`` (no cross-agent eavesdropping).

        Note this is a regular function (not an ``async def`` with
        yields). The :class:`grpc.aio.UnaryStreamCall` is constructed
        eagerly when ``subscribe()`` is called, which causes grpc-aio
        to dispatch the initial Subscribe request immediately. Callers
        that need a hard guarantee that the inbox is registered
        server-side before doing anything else (e.g. they're about to
        send to their own agent id) can ``await
        response_stream.read()`` on the returned iterator's underlying
        call — but in practice, awaiting any subsequent unary RPC on
        the same channel (or even a brief ``asyncio.sleep``) gives the
        request plenty of time to land.
        """
        request = cp_pb2.SubscribeRequest()
        if agent_id is not None:
            request.agent_id.CopyFrom(agent_id.to_proto())
        # Eager call. The returned object is a UnaryStreamCall, which
        # is itself an async iterator. grpc-aio puts the initial
        # request on the wire here, before we return to the caller.
        response_stream = self._stub.Subscribe(request)
        return _wrap_subscribe_stream(response_stream)


class ReceiptAPI:
    """Wraps :class:`ReceiptServiceStub`. Both methods require bearer
    auth.
    """

    def __init__(self, stub: cp_grpc.ReceiptServiceStub) -> None:
        self._stub = stub

    async def get(self, receipt_id: Hash) -> Receipt | None:
        """Fetch a single receipt by content-address. Returns ``None``
        if the server replies ``NOT_FOUND`` (the canonical "doesn't
        exist" signal, distinct from server errors)."""
        try:
            resp = cast(
                cp_pb2.GetReceiptResponse,
                await self._stub.Get(cp_pb2.GetReceiptRequest(receipt_id=receipt_id.to_proto())),
            )
        except grpc.aio.AioRpcError as e:
            if e.code() == grpc.StatusCode.NOT_FOUND:
                return None
            raise
        return Receipt.from_proto(resp.receipt)

    async def query_by_action_kind(
        self,
        action_kind: str,
        *,
        limit: int = 0,
        page_token: bytes = b"",
    ) -> tuple[list[Receipt], bytes]:
        """Query receipts by ``action_kind`` (e.g. ``"envelope.send"``,
        ``"agent.register"``). Returns ``(receipts, next_page_token)``.
        ``next_page_token`` is empty when the page is the last.
        """
        from yutha._proto.receipt import receipt_v1_pb2 as receipt_pb2

        inner = receipt_pb2.QueryRequest(
            by_action_kind=receipt_pb2.ActionKindQuery(action_kind=action_kind),
            limit=limit,
            page_token=page_token,
        )
        resp = cast(
            cp_pb2.QueryReceiptsResponse,
            await self._stub.Query(cp_pb2.QueryReceiptsRequest(query=inner)),
        )
        return (
            [Receipt.from_proto(r) for r in resp.receipts],
            bytes(resp.next_page_token),
        )

    async def query_by_agent(
        self,
        agent_id: AgentId,
        *,
        limit: int = 0,
        page_token: bytes = b"",
    ) -> tuple[list[Receipt], bytes]:
        """Query receipts authored by ``agent_id`` (i.e. its actor
        field). Returns ``(receipts, next_page_token)``."""
        from yutha._proto.receipt import receipt_v1_pb2 as receipt_pb2

        inner = receipt_pb2.QueryRequest(
            by_agent=receipt_pb2.AgentQuery(agent_id=agent_id.to_proto()),
            limit=limit,
            page_token=page_token,
        )
        resp = cast(
            cp_pb2.QueryReceiptsResponse,
            await self._stub.Query(cp_pb2.QueryReceiptsRequest(query=inner)),
        )
        return (
            [Receipt.from_proto(r) for r in resp.receipts],
            bytes(resp.next_page_token),
        )


# =============================================================================
# YuthaClient
# =============================================================================


class YuthaClient:
    """Async client for a Yutha control plane.

    Construct via :meth:`connect` (returns a context-manager-friendly
    client), then access the four service surfaces through
    :attr:`admission`, :attr:`capability`, :attr:`envelope`,
    :attr:`receipt`.

    Holds a :class:`BearerSession` internally; the same session
    services every authenticated call across all four services. Auto-
    renewing tokens means callers don't manage refresh themselves.
    """

    def __init__(
        self,
        channel: grpc.aio.Channel,
        session: BearerSession | OperatorBearerSession,
    ) -> None:
        self._channel = channel
        self._session = session
        # The four service-stub constructors are untyped (no .pyi
        # alongside the protoc-generated `_pb2_grpc.py`); ignores are
        # local to the four lines that hit them.
        self.admission = AdmissionAPI(cp_grpc.AdmissionServiceStub(channel))  # type: ignore[no-untyped-call]
        self.capability = CapabilityAPI(cp_grpc.CapabilityServiceStub(channel))  # type: ignore[no-untyped-call]
        self.envelope = EnvelopeAPI(cp_grpc.EnvelopeServiceStub(channel))  # type: ignore[no-untyped-call]
        self.receipt = ReceiptAPI(cp_grpc.ReceiptServiceStub(channel))  # type: ignore[no-untyped-call]

    @classmethod
    def connect(
        cls,
        address: str,
        *,
        agent_id: AgentId,
        swarm_id: SwarmId,
        signing_key: SigningKey,
        token_lifetime_seconds: int = 300,
        refresh_lead_seconds: int = 30,
        tls_root_ca: str | Path | bytes | None = None,
        client_cert: str | Path | bytes | None = None,
        client_key: str | Path | bytes | None = None,
    ) -> Self:
        """Build a client connected to ``address``.

        See :func:`yutha.channel.make_channel` for TLS knob semantics.
        The returned client is an async context manager — entering /
        exiting handles channel teardown.
        """
        session = BearerSession(
            agent_id=agent_id,
            swarm_id=swarm_id,
            signing_key=signing_key,
            token_lifetime_seconds=token_lifetime_seconds,
            refresh_lead_seconds=refresh_lead_seconds,
        )
        channel = make_channel(
            address,
            session,
            tls_root_ca=tls_root_ca,
            client_cert=client_cert,
            client_key=client_key,
        )
        return cls(channel, session)

    @classmethod
    def connect_as_operator(
        cls,
        address: str,
        *,
        operator_id: str,
        swarm_id: SwarmId,
        operator_signing_key: SigningKey,
        token_lifetime_seconds: int = 300,
        refresh_lead_seconds: int = 30,
        tls_root_ca: str | Path | bytes | None = None,
        client_cert: str | Path | bytes | None = None,
        client_key: str | Path | bytes | None = None,
    ) -> Self:
        """Build a client whose bearer interceptor mints
        ``OperatorBearerToken`` headers (RFC 0009).

        The control plane must have been started with
        ``--operator-public-key`` matching ``operator_signing_key``'s
        public counterpart, otherwise every operator RPC returns
        ``FAILED_PRECONDITION: operator credentials not enabled``.

        The returned client carries the same four service surfaces
        agent clients do, but most RPCs reject operator tokens with
        ``UNAUTHENTICATED: this RPC requires an agent bearer; got
        operator variant``. Today the only RPC that accepts operator
        bearers is :meth:`AdmissionAPI.operator_revoke` — calls
        through any other endpoint are expected to fail until the
        spec grows additional operator-only RPCs (key rotation,
        per-RFC-future scenarios).

        Parameters
        ----------
        operator_id
            Free-form identifier embedded in the token and persisted
            on the resulting ``agent.operator_revoke`` receipt's
            evidence. Useful for distinguishing multiple operators in
            audit-trail queries.
        swarm_id
            The swarm this operator manages. Must match the running
            control plane's swarm.
        operator_signing_key
            Ed25519 private key. The control plane is configured
            with its public counterpart at startup.
        """
        session = OperatorBearerSession(
            operator_id=operator_id,
            swarm_id=swarm_id,
            operator_signing_key=operator_signing_key,
            token_lifetime_seconds=token_lifetime_seconds,
            refresh_lead_seconds=refresh_lead_seconds,
        )
        channel = make_channel(
            address,
            session,
            tls_root_ca=tls_root_ca,
            client_cert=client_cert,
            client_key=client_key,
        )
        return cls(channel, session)

    @property
    def agent_id(self) -> AgentId:
        """The bearer's agent id. Raises :class:`AttributeError` for
        operator-authenticated clients — they don't carry an agent
        identity (use :attr:`operator_id` instead)."""
        if isinstance(self._session, OperatorBearerSession):
            raise AttributeError(
                "operator-authenticated clients have no agent_id; "
                "use `operator_id` instead"
            )
        return self._session.agent_id

    @property
    def operator_id(self) -> str:
        """The bearer's operator id. Raises :class:`AttributeError`
        for agent-authenticated clients."""
        if isinstance(self._session, BearerSession):
            raise AttributeError(
                "agent-authenticated clients have no operator_id; "
                "use `agent_id` instead"
            )
        return self._session.operator_id

    @property
    def swarm_id(self) -> SwarmId:
        return self._session.swarm_id

    async def close(self) -> None:
        """Tear down the channel. Safe to call multiple times."""
        await self._channel.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()


__all__ = [
    "YuthaClient",
    "AdmissionAPI",
    "CapabilityAPI",
    "EnvelopeAPI",
    "ReceiptAPI",
]

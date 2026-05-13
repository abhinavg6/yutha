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
from pathlib import Path
from types import TracebackType
from typing import Self, cast

import grpc

from yutha._proto.control_plane import v1_pb2 as cp_pb2
from yutha._proto.control_plane import v1_pb2_grpc as cp_grpc
from yutha.auth import BearerSession, skip_auth_metadata
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
        """Revoke ``target`` (must equal the bearer's own agent id —
        operator-level revocation is not yet permitted by the server)."""
        resp = cast(
            cp_pb2.RevokeResponse,
            await self._stub.Revoke(
                cp_pb2.RevokeRequest(agent_id=target.to_proto(), reason=reason)
            ),
        )
        return Hash.from_proto(resp.revocation_receipt)


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

    async def send(self, envelope: Envelope) -> Hash:
        """Send an envelope. Returns the ``envelope.send`` receipt id.
        The envelope's ``from_agent`` MUST equal the bearer's agent id
        — the server rejects mismatched-sender envelopes with
        ``PERMISSION_DENIED``."""
        resp = cast(
            cp_pb2.SendEnvelopeResponse,
            await self._stub.Send(cp_pb2.SendEnvelopeRequest(envelope=envelope.to_proto())),
        )
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
        session: BearerSession,
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

    @property
    def agent_id(self) -> AgentId:
        return self._session.agent_id

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

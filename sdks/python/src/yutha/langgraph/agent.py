"""YuthaAgent — the high-level wrapper LangGraph nodes interact with.

A ``YuthaAgent`` couples a registered passport + :class:`~yutha.crypto.Signer`
to a :class:`yutha.YuthaClient` channel and exposes three things a typical
LangGraph workflow needs:

  - **A background subscribe-and-dispatch loop.** Calls
    ``client.envelope.subscribe()``, drains the stream, and invokes a
    caller-supplied async handler for each ``(envelope,
    deliver_receipt_id)`` pair. Cancel-safe via :meth:`stop`.
  - **A ``send`` convenience.** Constructs, signs, and ships an
    envelope from inside a LangGraph node (or anywhere else),
    auto-managing the envelope id, nonce, and monotonic epoch.
  - **Lifecycle management.** Async context manager that handles
    channel teardown and graceful drain of the dispatch loop on exit.

This is deliberately *not* opinionated about LangGraph itself — the
handler is just an async callback. The 4c demo wires it up to a
LangGraph compiled graph; a custom workflow could use the same agent
with a different callback shape.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Awaitable, Callable
from pathlib import Path
from types import TracebackType
from typing import Self

from yutha.client import YuthaClient
from yutha.crypto import Signer
from yutha.identity import AgentId, Hash, SwarmId, Timestamp
from yutha.models import (
    Envelope,
    Passport,
    Performative,
    Receipt,
    Recipient,
)

# Type of an envelope handler. Receives the owning agent (so the
# handler can send replies), the inbound envelope, and the
# content-address of the `envelope.deliver` receipt the control plane
# emitted on delivery.
EnvelopeHandler = Callable[["YuthaAgent", Envelope, Hash], Awaitable[None]]


class YuthaAgent:
    """A long-lived agent identity bound to a Yutha control plane.

    Construct with a :class:`YuthaClient` that's already connected, or
    build one in one step via :meth:`connect`. The passport supplied
    here is the agent's identity *as registered on the control plane*
    — if you registered via :meth:`yutha.YuthaClient.admission.register`,
    pass the same passport object. If the swarm is closed-mode and the
    agent was pre-registered by the operator (e.g. the bootstrap-seed
    case), build the passport locally with the same fields and pass
    that.
    """

    def __init__(
        self,
        client: YuthaClient,
        passport: Passport,
        signer: Signer,
        handler: EnvelopeHandler,
        *,
        epoch_start: int = 1,
    ) -> None:
        if signer.public_key().value != passport.agent_public_key.value:
            raise ValueError(
                "signer does not match passport.agent_public_key — "
                "the agent would fail to sign envelopes the control plane accepts"
            )
        self._client = client
        self._passport = passport
        self._signer = signer
        self._handler = handler
        self._epoch = epoch_start
        self._epoch_lock = asyncio.Lock()
        self._dispatch_task: asyncio.Task[None] | None = None
        self._stopped = asyncio.Event()
        # Set by the dispatch loop once it has actually called
        # subscribe() on the client (which puts the Subscribe request
        # on the wire). start() awaits this so callers don't race the
        # subscription-setup work and miss the first envelope.
        self._subscription_ready = asyncio.Event()
        # If the dispatch loop dies on something other than
        # CancelledError, we surface it here so stop() (or the next
        # send) can re-raise instead of leaving the agent in a
        # silently-broken state.
        self._dispatch_error: BaseException | None = None

    # -------------------------------------------------------------------------
    # Construction
    # -------------------------------------------------------------------------

    @classmethod
    def connect(
        cls,
        address: str,
        *,
        passport: Passport,
        signer: Signer,
        handler: EnvelopeHandler,
        token_lifetime_seconds: int = 300,
        refresh_lead_seconds: int = 30,
        tls_root_ca: str | Path | bytes | None = None,
        client_cert: str | Path | bytes | None = None,
        client_key: str | Path | bytes | None = None,
        epoch_start: int = 1,
    ) -> Self:
        """Build a connected agent in one call. Wraps
        :meth:`yutha.YuthaClient.connect` with the same TLS knobs.

        The returned agent is *not* yet running its dispatch loop —
        call :meth:`start` (or use the async context manager) to
        begin pulling envelopes.
        """
        client = YuthaClient.connect(
            address,
            agent_id=passport.agent_id,
            swarm_id=passport.swarm_id,
            signer=signer,
            token_lifetime_seconds=token_lifetime_seconds,
            refresh_lead_seconds=refresh_lead_seconds,
            tls_root_ca=tls_root_ca,
            client_cert=client_cert,
            client_key=client_key,
        )
        return cls(
            client=client,
            passport=passport,
            signer=signer,
            handler=handler,
            epoch_start=epoch_start,
        )

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    @property
    def client(self) -> YuthaClient:
        """The underlying :class:`YuthaClient`. Exposed so handlers can
        reach the other services (capability check, receipt query)
        without juggling a second reference."""
        return self._client

    @property
    def agent_id(self) -> AgentId:
        return self._passport.agent_id

    @property
    def swarm_id(self) -> SwarmId:
        return self._passport.swarm_id

    @property
    def passport(self) -> Passport:
        return self._passport

    @property
    def is_running(self) -> bool:
        return self._dispatch_task is not None and not self._dispatch_task.done()

    # -------------------------------------------------------------------------
    # Registration
    # -------------------------------------------------------------------------

    async def register(self) -> Hash | None:
        """Register the agent's passport with the control plane.

        Returns the registration receipt id on success, or ``None``
        when the passport is already present (e.g. the bootstrap-seed
        case where the operator pre-registered the agent). Use this
        for open-swarm workflows where the SDK admits itself.
        """
        resp = await self._client.admission.register(self._passport)
        if not resp.result.HasField("registration_receipt"):
            return None
        return Hash.from_proto(resp.result.registration_receipt)

    # -------------------------------------------------------------------------
    # Dispatch loop
    # -------------------------------------------------------------------------

    async def start(self, *, ready_timeout: float = 10.0) -> None:
        """Open the subscribe stream and start dispatching incoming
        envelopes to the handler. Safe to call once per agent
        instance; subsequent calls raise ``RuntimeError``.

        Blocks until the dispatch loop has actually called
        ``client.envelope.subscribe()`` — without this, a caller that
        immediately invokes :meth:`send` may race the subscription
        setup and miss the corresponding delivery on the stream.
        """
        if self._dispatch_task is not None:
            raise RuntimeError("YuthaAgent.start() called twice; create a fresh agent")
        self._stopped.clear()
        self._subscription_ready.clear()
        self._dispatch_error = None
        dispatch_task: asyncio.Task[None] = asyncio.create_task(self._dispatch_loop())
        self._dispatch_task = dispatch_task
        # Wait for the dispatch loop to open the subscribe stream
        # before returning. If the loop dies before getting there,
        # surface its exception instead of timing out blindly.
        ready_task: asyncio.Task[bool] = asyncio.create_task(self._subscription_ready.wait())
        try:
            await asyncio.wait(
                {ready_task, dispatch_task},
                timeout=ready_timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            if not ready_task.done():
                ready_task.cancel()
        if self._subscription_ready.is_set():
            return
        # Dispatch task finished before signalling ready — propagate.
        if dispatch_task.done():
            exc = dispatch_task.exception()
            if exc is not None:
                raise exc
            raise RuntimeError("YuthaAgent dispatch loop exited before subscribing")
        # Timed out without either event firing.
        dispatch_task.cancel()
        raise TimeoutError(
            f"YuthaAgent.start() timed out after {ready_timeout}s waiting for "
            "the subscribe stream to open"
        )

    async def _dispatch_loop(self) -> None:
        """Pull envelopes from the subscribe stream until cancelled.

        Handler exceptions are caught and logged-via-print (Stage 4b
        keeps the dependency surface small; a future stage can route
        them to a proper logger or to a constitution-style enforcement
        path). The loop survives handler-raised exceptions so a single
        bad message doesn't kill the agent. Anything raised *outside*
        the handler (e.g. a stream-level RPC error) is captured to
        :attr:`_dispatch_error` so it's not silently swallowed.
        """
        try:
            # subscribe() is an async coroutine that returns AFTER the
            # server has received the Subscribe RPC (initial metadata
            # received → server-side handler entered → inbox
            # registered). Signal ready immediately after the await
            # resolves; any send the caller does next will hit a
            # registered subscription.
            sub_iter = await self._client.envelope.subscribe()
            self._subscription_ready.set()
            async for envelope, deliver_receipt in sub_iter:
                try:
                    await self._handler(self, envelope, deliver_receipt)
                except Exception as e:
                    # Catch-all is intentional: the handler is
                    # user-supplied and may raise anything. Surfacing
                    # to stderr keeps the loop alive while making the
                    # failure visible. Handlers that want different
                    # semantics should catch internally.
                    print(
                        f"YuthaAgent({self.agent_id}): handler raised {type(e).__name__}: {e}",
                        flush=True,
                    )
        except asyncio.CancelledError:
            # Normal shutdown path. Don't re-raise — let stop() observe
            # the task as cleanly cancelled.
            pass
        except Exception as e:
            # Stream-level failure (auth, transport, malformed proto).
            # Surface it for stop() / the next API call to observe
            # rather than dying silently.
            self._dispatch_error = e
        finally:
            # Make sure start() unblocks even on early failure.
            self._subscription_ready.set()
            self._stopped.set()

    async def stop(self) -> None:
        """Cancel the dispatch loop and await its shutdown. Idempotent."""
        if self._dispatch_task is None:
            return
        if not self._dispatch_task.done():
            self._dispatch_task.cancel()
        await self._stopped.wait()
        self._dispatch_task = None

    # -------------------------------------------------------------------------
    # Send
    # -------------------------------------------------------------------------

    async def send(
        self,
        recipient: Recipient,
        performative: Performative,
        payload: bytes = b"",
        *,
        payload_schema_id: str = "",
        tags: list[str] | None = None,
        in_reply_to: Hash | None = None,
        capability_id: Hash | None = None,
    ) -> Hash:
        """Construct, sign, and ship an envelope from this agent.

        The envelope id and nonce are freshly minted from
        :func:`secrets.token_bytes`. The epoch is auto-incremented
        per call (atomic via an asyncio lock) so the substrate's
        replay-protection sees strictly-increasing values from this
        agent.

        ``capability_id`` is the content-address of the capability
        authorizing this send (RFC 0007). Resolution order:

        1. Explicit kwarg, when supplied.
        2. The context-local
           :data:`yutha.langgraph.tools.ACTIVE_CAPABILITY_ID`, set by
           the :func:`yutha.langgraph.capability_required` decorator.
        3. None (cap omitted; server-side check is skipped unless the
           topology declares ``require_capability_for_send = true``,
           in which case the server rejects with
           ``INVALID_ARGUMENT``).

        On a server-side cap deny, raises
        :class:`yutha.langgraph.CapabilityDenied`. On any other
        ``PERMISSION_DENIED`` (e.g. sender/bearer mismatch), the raw
        :class:`grpc.aio.AioRpcError` propagates.

        Returns the ``envelope.send`` receipt id on permit.
        """
        async with self._epoch_lock:
            epoch = self._epoch
            self._epoch += 1

        envelope = await Envelope(
            spec_version="1.0.0",
            swarm_id=self.swarm_id,
            envelope_id=secrets.token_bytes(16),
            from_agent=self.agent_id,
            recipient=recipient,
            performative=performative,
            payload=payload,
            payload_schema_id=payload_schema_id,
            tags=tags or [],
            nonce=secrets.token_bytes(16),
            epoch=epoch,
            sent_at=Timestamp.now(),
            in_reply_to=in_reply_to,
        ).sign(self._signer)

        # Resolve cap_id: explicit kwarg wins; otherwise pick up the
        # decorator-supplied context-local id; otherwise None.
        if capability_id is None:
            # Lazy import: keeps `yutha.langgraph.agent` from
            # cycle-depending on `tools` at module-load time.
            from yutha.langgraph.tools import ACTIVE_CAPABILITY_ID

            capability_id = ACTIVE_CAPABILITY_ID.get()

        return await self._client.envelope.send(envelope, capability_id=capability_id)

    async def get_receipt(self, receipt_id: Hash) -> Receipt | None:
        """Pass-through to ``client.receipt.get`` for handler
        convenience. ``None`` when the server replies ``NOT_FOUND``."""
        return await self._client.receipt.get(receipt_id)

    # -------------------------------------------------------------------------
    # Async context manager
    # -------------------------------------------------------------------------

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.stop()
        await self._client.close()


__all__ = ["YuthaAgent", "EnvelopeHandler"]

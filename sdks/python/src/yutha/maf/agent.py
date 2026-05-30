"""YuthaChatAgent — couples a Microsoft Agent Framework
``Agent`` to a Yutha identity.

The headline export is :class:`YuthaChatAgent`. Each instance wraps:

  - **a Yutha-registered passport + :class:`~yutha.crypto.Signer`**
    (cryptographic identity on every envelope this agent emits),
  - **an agent_framework ``Agent`` instance** (the LLM-backed
    reasoning loop, its instructions/tools/client), and
  - **an input-factory callable** that converts an inbound
    Yutha envelope into the ``input`` argument for the next
    :meth:`Agent.run` invocation.

Lifecycle is identical in shape to the other adapters:
construct, ``register()``, enter the async context manager,
``send()`` to emit envelopes, exit drains the subscribe stream
and closes the channel.

## What happens on an inbound envelope

The dispatch loop pulls ``(envelope, deliver_receipt_id)`` from
``client.envelope.subscribe()``. For each pair:

1. The input-factory builds the next-turn input from the
   envelope. The default factory uses ``envelope.payload`` as a
   UTF-8 string passed straight to ``Agent.run`` — most users
   will pass a custom factory that does some payload-schema-
   aware framing, or a no-op lambda when the demo orchestrator
   drives every run directly.
2. :meth:`Agent.run` is invoked on the wrapped agent. Tool calls
   inside that run that go through :func:`capability_required`-
   wrapped callables thread the held cap_id into outbound sends.
3. The result is handed to an optional ``on_output`` callback
   if one was supplied.

The dispatch loop catches every handler-level exception and
prints a one-line diagnostic. Stream-level failures (auth,
transport, malformed proto) land on :attr:`_dispatch_error` so
:meth:`stop` can re-raise.

## Package name note

The PyPI package is ``agent-framework`` but the importable
Python module is ``agent_framework``. This adapter follows the
upstream convention internally.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Awaitable, Callable
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, Self

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

if TYPE_CHECKING:
    # Type-only — keeps `yutha.maf.agent` importable without the
    # `agent-framework` extra installed. The actual import lives
    # inside `__init__()` and only fires when the user
    # constructs a YuthaChatAgent.
    from agent_framework import Agent as MAFAgentT


# A factory that turns an inbound envelope into an Agent.run input.
# Receives the owning YuthaChatAgent plus the inbound envelope and
# its delivery-receipt id. Returns the input MAF expects (typically
# a string for single-turn or a more structured list for multi-
# turn); returns ``None`` to skip this envelope.
#
# Typed as Any rather than str to avoid pulling MAF types into the
# adapter's public surface when the optional dep isn't installed.
InputFactory = Callable[["YuthaChatAgent", Envelope, Hash], "Any | None"]

# Callback invoked after the per-envelope Agent.run finishes.
# Receives the owning agent + the inbound envelope + whatever
# Agent.run returned. Use this to emit follow-on envelopes when
# the result needs to be surfaced as a Yutha event.
OutputCallback = Callable[["YuthaChatAgent", Envelope, Any], Awaitable[None]]


def _default_input_factory(
    agent: YuthaChatAgent,
    envelope: Envelope,
    deliver_receipt: Hash,
) -> Any | None:
    """Fallback factory: payload (UTF-8) becomes the next
    :meth:`Agent.run` input string.

    For demos where the orchestrator drives every run directly
    (and dispatch loops should be no-ops to avoid cascade
    behavior), pass ``input_factory=lambda a, e, d: None``
    explicitly. The default here is "act on whatever shows up",
    which is the right choice for inbox-driven agents but the
    wrong choice for orchestrator-driven demos.
    """
    _ = (agent, deliver_receipt)
    return envelope.payload.decode("utf-8", errors="replace")


class YuthaChatAgent:
    """A long-lived MAF Agent identity bound to a Yutha control plane.

    Constructor params mirror :class:`yutha.openai_agents.YuthaOpenAIAgent`
    with the MAF-specific knobs:

    Parameters
    ----------
    client
        Connected :class:`YuthaClient`.
    passport
        The agent's registered passport.
    signer
        The :class:`~yutha.crypto.Signer` whose public counterpart is
        on the passport. The constructor enforces the mismatch check
        that the other adapters do.
    maf_agent
        The :class:`agent_framework.Agent` instance the dispatch
        loop will invoke :meth:`Agent.run` against. Its tools
        list may include any number of
        :func:`yutha.maf.capability_required`-wrapped callables.
    input_factory
        Optional callable that converts inbound envelopes into
        :meth:`Agent.run` input. Defaults to a payload-as-string
        factory; pass ``lambda a, e, d: None`` to make the
        dispatch loop a no-op.
    on_output
        Optional async callback that runs after the per-envelope
        Agent.run completes.
    epoch_start
        Starting value for the per-agent monotonic epoch counter.
    """

    def __init__(
        self,
        client: YuthaClient,
        passport: Passport,
        signer: Signer,
        maf_agent: MAFAgentT,
        *,
        input_factory: InputFactory | None = None,
        on_output: OutputCallback | None = None,
        epoch_start: int = 1,
    ) -> None:
        # Validate agent-framework is importable before we hand
        # back an agent.
        from yutha.maf import _require_maf

        _require_maf()

        if signer.public_key().value != passport.agent_public_key.value:
            raise ValueError(
                "signer does not match passport.agent_public_key — "
                "the agent would fail to sign envelopes the control plane accepts"
            )
        self._client = client
        self._passport = passport
        self._signer = signer
        self._maf_agent = maf_agent
        self._input_factory: InputFactory = input_factory or _default_input_factory
        self._on_output = on_output
        self._epoch = epoch_start
        self._epoch_lock = asyncio.Lock()
        self._dispatch_task: asyncio.Task[None] | None = None
        self._stopped = asyncio.Event()
        self._subscription_ready = asyncio.Event()
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
        maf_agent: MAFAgentT,
        input_factory: InputFactory | None = None,
        on_output: OutputCallback | None = None,
        token_lifetime_seconds: int = 300,
        refresh_lead_seconds: int = 30,
        tls_root_ca: str | Path | bytes | None = None,
        client_cert: str | Path | bytes | None = None,
        client_key: str | Path | bytes | None = None,
        epoch_start: int = 1,
    ) -> Self:
        """Build a connected agent in one call. Wraps
        :meth:`yutha.YuthaClient.connect`."""
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
            maf_agent=maf_agent,
            input_factory=input_factory,
            on_output=on_output,
            epoch_start=epoch_start,
        )

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    @property
    def client(self) -> YuthaClient:
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
    def maf_agent(self) -> MAFAgentT:
        """The wrapped :class:`agent_framework.Agent`."""
        return self._maf_agent

    @property
    def is_running(self) -> bool:
        return self._dispatch_task is not None and not self._dispatch_task.done()

    # -------------------------------------------------------------------------
    # Registration
    # -------------------------------------------------------------------------

    async def register(self, external_credential: bytes = b"") -> Hash | None:
        """Register the agent's passport. Returns the
        registration receipt id on success, ``None`` if the
        passport was already present.

        ``external_credential`` is forwarded to the control plane's
        configured ``Attestor`` (RFC 0016); empty bytes is the right
        default against a ``NativeAttestor`` server."""
        resp = await self._client.admission.register(self._passport, external_credential)
        if not resp.result.HasField("registration_receipt"):
            return None
        return Hash.from_proto(resp.result.registration_receipt)

    # -------------------------------------------------------------------------
    # Dispatch loop
    # -------------------------------------------------------------------------

    async def start(self, *, ready_timeout: float = 10.0) -> None:
        """Open the subscribe stream and start dispatching
        incoming envelopes through :meth:`Agent.run`. Blocks
        until subscription is confirmed open."""
        if self._dispatch_task is not None:
            raise RuntimeError("YuthaChatAgent.start() called twice; create a fresh agent")
        self._stopped.clear()
        self._subscription_ready.clear()
        self._dispatch_error = None
        dispatch_task: asyncio.Task[None] = asyncio.create_task(self._dispatch_loop())
        self._dispatch_task = dispatch_task
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
        if dispatch_task.done():
            exc = dispatch_task.exception()
            if exc is not None:
                raise exc
            raise RuntimeError("YuthaChatAgent dispatch loop exited before subscribing")
        dispatch_task.cancel()
        raise TimeoutError(
            f"YuthaChatAgent.start() timed out after {ready_timeout}s waiting for "
            "the subscribe stream to open"
        )

    async def run(self, input: Any) -> Any:
        """Invoke :meth:`agent_framework.Agent.run` on the wrapped
        agent.

        The orchestrator can call this directly (bypassing the
        dispatch loop) when it wants to drive a single run with
        a specific input — useful for deterministic happy-path
        and bypass-scenario phases in demos. The dispatch loop
        also routes through this method on every inbound
        envelope.
        """
        return await self._maf_agent.run(input)

    async def _dispatch_loop(self) -> None:
        """Pull envelopes, convert each to an Agent.run input,
        execute the run, hand the result to the on_output callback.

        MAF's Agent.run is fully async, so no worker-thread
        bridging is needed. Capability-required tools inside
        the run read ``ACTIVE_CAPABILITY_ID`` from contextvars
        — those propagate naturally inside the same event loop.
        """
        try:
            sub_iter = await self._client.envelope.subscribe()
            self._subscription_ready.set()
            async for envelope, deliver_receipt in sub_iter:
                try:
                    input = self._input_factory(self, envelope, deliver_receipt)
                    if input is None:
                        continue
                    result = await self.run(input)
                    if self._on_output is not None:
                        await self._on_output(self, envelope, result)
                except Exception as e:
                    print(
                        f"YuthaChatAgent({self.agent_id}): handler raised {type(e).__name__}: {e}",
                        flush=True,
                    )
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self._dispatch_error = e
        finally:
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

        Resolution order for ``capability_id`` is identical to
        the other adapters: explicit kwarg → contextvar set by
        :func:`yutha.maf.capability_required` → None.
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

        if capability_id is None:
            from yutha._capability_context import ACTIVE_CAPABILITY_ID

            capability_id = ACTIVE_CAPABILITY_ID.get()

        return await self._client.envelope.send(envelope, capability_id=capability_id)

    async def get_receipt(self, receipt_id: Hash) -> Receipt | None:
        """Pass-through to ``client.receipt.get`` for convenience."""
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


__all__ = ["YuthaChatAgent", "InputFactory", "OutputCallback"]

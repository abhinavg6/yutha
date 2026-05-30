"""YuthaOpenAIAgent — couples an openai-agents ``Agent`` to a Yutha
identity.

The headline export is :class:`YuthaOpenAIAgent`. Each instance wraps:

  - **a Yutha-registered passport + :class:`~yutha.crypto.Signer`**
    (cryptographic identity on every envelope this agent emits),
  - **an openai_agents ``Agent`` instance** (the LLM-backed
    reasoning loop, its instructions/tools/handoffs/guardrails), and
  - **an input-factory callable** that converts an inbound Yutha
    envelope into the ``input`` argument for the next
    :meth:`Runner.run` invocation.

Lifecycle is identical in shape to :class:`yutha.crewai.YuthaCrewAgent`:
construct, ``register()``, enter the async context manager,
``send()`` to emit envelopes, exit drains the subscribe stream and
closes the channel.

## What happens on an inbound envelope

The dispatch loop pulls ``(envelope, deliver_receipt_id)`` from
``client.envelope.subscribe()``. For each pair:

1. The input-factory builds the next-turn input from the envelope.
   The default factory uses ``envelope.payload`` as a UTF-8 string
   passed straight to ``Runner.run`` — most users will pass a
   custom factory that does some payload-schema-aware framing.
2. :meth:`Runner.run` is invoked with a :class:`YuthaRunHooks`
   subclass attached. The hooks:
     * emit a Yutha receipt + envelope on every ``on_handoff``
       (the substrate's audit trail captures inter-agent transfers
       the LLM picked), and
     * emit a Yutha receipt on tool boundaries (optional, off by
       default to keep audit-deltas predictable for demos).
3. The :class:`RunResult` is handed to an optional ``on_output``
   callback if one was supplied.

The dispatch loop catches every handler-level exception and prints
a one-line diagnostic. Stream-level failures (auth, transport,
malformed proto) land on :attr:`_dispatch_error` so :meth:`stop`
can re-raise.

## Package name note

The PyPI package is ``openai-agents`` but the importable Python
module is ``agents``. ``from agents import Agent, Runner`` — not
``from openai_agents import ...``. This adapter follows the same
convention internally.
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
    # Type-only — keeps `yutha.openai_agents.agent` importable
    # without the `openai-agents` extra installed. The actual
    # `agents` import lives inside `__init__()` and only fires when
    # the user constructs a YuthaOpenAIAgent.
    from agents import Agent as OAIAgentT
    from agents.result import RunResult as OAIRunResultT


# A factory that turns an inbound envelope into a Runner.run input.
# Receives the owning YuthaOpenAIAgent (so the factory can read
# identity / passport / framework fields) plus the inbound envelope
# and its delivery-receipt id. Returns a string (treated as a
# single-turn user input) or a list of TResponseInputItem-shaped
# dicts for richer multi-turn contexts; returns ``None`` to skip
# this envelope (useful for filtering by performative or tag).
#
# We type the return as ``Any`` rather than ``str | list`` to avoid
# pulling the openai-agents type into the adapter's public surface
# when the optional dep isn't installed.
InputFactory = Callable[["YuthaOpenAIAgent", Envelope, Hash], "Any | None"]

# Callback invoked after the per-envelope Runner.run finishes.
# Receives the owning agent + the inbound envelope + the RunResult.
# Use this to emit follow-on envelopes (typed responses, escalations,
# etc.) when the result needs to be surfaced as a Yutha event.
OutputCallback = Callable[["YuthaOpenAIAgent", Envelope, "OAIRunResultT"], Awaitable[None]]


def _default_input_factory(
    agent: YuthaOpenAIAgent,
    envelope: Envelope,
    deliver_receipt: Hash,
) -> Any | None:
    """Fallback factory: payload (UTF-8) becomes a single-turn
    user message string.

    Substrate-audit envelopes that the adapter itself emits (the
    handoff bridge's ``type.yutha.dev/v1/HandoffAudit`` envelopes,
    or any envelope tagged ``openai_agents_handoff``) are
    **skipped** — they're audit artifacts, not prompts to act on.
    Without this filter, every handoff that the adapter records
    would cascade into a fresh ``Runner.run`` on the target
    agent's inbox, multiplying the per-handoff envelope count
    and producing unpredictable audit-delta inflation.

    Suitable for text-payload demos where dispatch-loop-driven
    runs are wanted. Demos where the orchestrator drives every
    run directly (and dispatch loops should be no-ops) should
    pass ``input_factory=lambda a, e, d: None``.
    """
    # `agent` + `deliver_receipt` are part of the protocol so
    # factories can choose to thread them as context.
    _ = (agent, deliver_receipt)
    if envelope.payload_schema_id == "type.yutha.dev/v1/HandoffAudit":
        return None
    if "openai_agents_handoff" in envelope.tags:
        return None
    return envelope.payload.decode("utf-8", errors="replace")


class YuthaOpenAIAgent:
    """A long-lived OpenAI Agents Agent identity bound to a Yutha
    control plane.

    Constructor params mirror :class:`yutha.crewai.YuthaCrewAgent`
    plus two OpenAI-Agents-specific knobs:

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
    oai_agent
        The :class:`agents.Agent` (or :class:`agents.SandboxAgent`)
        instance the dispatch loop will invoke
        :meth:`agents.Runner.run` against. Its ``tools`` list may
        include any number of :func:`yutha.openai_agents.capability_required`
        -wrapped function tools — those are what give server-side
        enforcement reach into the agent's tool calls.
    input_factory
        Optional callable that converts inbound envelopes into
        :meth:`Runner.run` input. Defaults to a payload-as-string
        factory.
    on_output
        Optional async callback that runs after the per-envelope
        Runner.run completes. Receives the :class:`RunResult`
        and may emit follow-on envelopes via :meth:`send`.
    emit_handoff_envelopes
        When ``True`` (default), the auto-attached
        :class:`YuthaRunHooks` emits a Yutha envelope from this
        agent to the target agent's inbox on every handoff. This
        is the substrate's audit hook on inter-agent transfers.
        Set to ``False`` for setups where you don't want handoff
        envelopes (e.g. internal handoffs within a single Yutha
        identity).
    epoch_start
        Starting value for the per-agent monotonic epoch counter,
        mirroring the other adapters' knob.
    """

    def __init__(
        self,
        client: YuthaClient,
        passport: Passport,
        signer: Signer,
        oai_agent: OAIAgentT,
        *,
        input_factory: InputFactory | None = None,
        on_output: OutputCallback | None = None,
        emit_handoff_envelopes: bool = True,
        epoch_start: int = 1,
    ) -> None:
        # Validate openai-agents is importable before we hand back
        # an agent. Lazy `_require_openai_agents` keeps
        # `import yutha.openai_agents` cheap; constructor-time is
        # when we actually need the dep.
        from yutha.openai_agents import _require_openai_agents

        _require_openai_agents()

        if signer.public_key().value != passport.agent_public_key.value:
            raise ValueError(
                "signer does not match passport.agent_public_key — "
                "the agent would fail to sign envelopes the control plane accepts"
            )
        self._client = client
        self._passport = passport
        self._signer = signer
        self._oai_agent = oai_agent
        self._input_factory: InputFactory = input_factory or _default_input_factory
        self._on_output = on_output
        self._emit_handoff_envelopes = emit_handoff_envelopes
        self._epoch = epoch_start
        self._epoch_lock = asyncio.Lock()
        self._dispatch_task: asyncio.Task[None] | None = None
        self._stopped = asyncio.Event()
        # Set by the dispatch loop once it has actually called
        # subscribe() — start() awaits this so callers don't race
        # the subscription-setup and miss the first envelope.
        self._subscription_ready = asyncio.Event()
        self._dispatch_error: BaseException | None = None
        # The hooks instance is constructed lazily on first run so
        # we don't import the optional dep until it's actually used.
        self._hooks: Any | None = None

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
        oai_agent: OAIAgentT,
        input_factory: InputFactory | None = None,
        on_output: OutputCallback | None = None,
        emit_handoff_envelopes: bool = True,
        token_lifetime_seconds: int = 300,
        refresh_lead_seconds: int = 30,
        tls_root_ca: str | Path | bytes | None = None,
        client_cert: str | Path | bytes | None = None,
        client_key: str | Path | bytes | None = None,
        epoch_start: int = 1,
    ) -> Self:
        """Build a connected agent in one call. Wraps
        :meth:`yutha.YuthaClient.connect` with the same TLS knobs as
        the other adapters; see :class:`yutha.langgraph.YuthaAgent`
        for the argument semantics.

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
            oai_agent=oai_agent,
            input_factory=input_factory,
            on_output=on_output,
            emit_handoff_envelopes=emit_handoff_envelopes,
            epoch_start=epoch_start,
        )

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    @property
    def client(self) -> YuthaClient:
        """The underlying :class:`YuthaClient`."""
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
    def oai_agent(self) -> OAIAgentT:
        """The wrapped :class:`agents.Agent`. Exposed so input
        factories / on_output callbacks can introspect
        instructions / tools / etc."""
        return self._oai_agent

    @property
    def is_running(self) -> bool:
        return self._dispatch_task is not None and not self._dispatch_task.done()

    # -------------------------------------------------------------------------
    # Registration
    # -------------------------------------------------------------------------

    async def register(self, external_credential: bytes = b"") -> Hash | None:
        """Register the agent's passport. Same semantics as the
        other adapters: returns the registration receipt id on
        success, ``None`` if the passport was already present.

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
        """Open the subscribe stream and start dispatching incoming
        envelopes through :meth:`Runner.run`. Blocks until subscription
        is confirmed open."""
        if self._dispatch_task is not None:
            raise RuntimeError("YuthaOpenAIAgent.start() called twice; create a fresh agent")
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
            raise RuntimeError("YuthaOpenAIAgent dispatch loop exited before subscribing")
        dispatch_task.cancel()
        raise TimeoutError(
            f"YuthaOpenAIAgent.start() timed out after {ready_timeout}s waiting for "
            "the subscribe stream to open"
        )

    def _get_hooks(self) -> Any:
        """Lazily construct (and cache) the :class:`YuthaRunHooks`
        bound to this wrapper. Constructed on first use rather than
        in ``__init__`` so the openai-agents dep is only required
        when an actual Runner.run is invoked."""
        if self._hooks is None:
            from yutha.openai_agents.hooks import YuthaRunHooks

            self._hooks = YuthaRunHooks(
                wrapper=self,
                emit_handoff_envelopes=self._emit_handoff_envelopes,
            )
        return self._hooks

    async def run(
        self,
        input: Any,
        *,
        max_turns: int | None = None,
        run_config: Any = None,
    ) -> OAIRunResultT:
        """Invoke :func:`agents.Runner.run` on the wrapped agent with
        the Yutha hooks attached.

        The orchestrator can call this directly (bypassing the
        dispatch loop) when it wants to drive a single agent run
        with a specific input — useful for deterministic-bypass
        scenarios in demos. The dispatch loop also routes through
        this method on every inbound envelope.
        """
        from agents import Runner

        kwargs: dict[str, Any] = {"hooks": self._get_hooks()}
        if max_turns is not None:
            kwargs["max_turns"] = max_turns
        if run_config is not None:
            kwargs["run_config"] = run_config
        return await Runner.run(self._oai_agent, input, **kwargs)

    async def _dispatch_loop(self) -> None:
        """Pull envelopes, convert each to a Runner.run input,
        execute the run with Yutha hooks attached, hand the result
        to the on_output callback.

        Unlike the CrewAI adapter, openai-agents' Runner is fully
        async, so no worker-thread bridging is needed. Capability-
        required tools inside the run read ``ACTIVE_CAPABILITY_ID``
        from contextvars — those propagate naturally inside the
        same event loop.
        """
        try:
            # subscribe() is async — it returns after the server has
            # acknowledged the Subscribe RPC (initial metadata
            # received). That guarantees the inbox is registered
            # server-side before we signal ready, eliminating the
            # send-before-subscribe race on fast loopback channels.
            sub_iter = await self._client.envelope.subscribe()
            self._subscription_ready.set()
            async for envelope, deliver_receipt in sub_iter:
                try:
                    input = self._input_factory(self, envelope, deliver_receipt)
                    if input is None:
                        # Factory chose to skip this envelope.
                        continue
                    result = await self.run(input)
                    if self._on_output is not None:
                        await self._on_output(self, envelope, result)
                except Exception as e:  # handlers can raise anything — keep loop alive
                    print(
                        f"YuthaOpenAIAgent({self.agent_id}): handler raised "
                        f"{type(e).__name__}: {e}",
                        flush=True,
                    )
        except asyncio.CancelledError:
            pass
        except Exception as e:  # stream-level — surface for stop() to re-raise
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

        Resolution order for ``capability_id`` is identical to the
        other adapters:

        1. Explicit kwarg.
        2. Context-local
           :data:`yutha._capability_context.ACTIVE_CAPABILITY_ID`
           (set by :func:`yutha.openai_agents.capability_required`).
        3. None.
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
        """Pass-through to ``client.receipt.get`` for convenience.
        ``None`` when the server replies ``NOT_FOUND``."""
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


__all__ = ["YuthaOpenAIAgent", "InputFactory", "OutputCallback"]

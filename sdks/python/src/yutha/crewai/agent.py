"""YuthaCrewAgent — couples a CrewAI ``Agent`` to a Yutha identity.

The headline export is :class:`YuthaCrewAgent`. Each instance wraps:

  - **a Yutha-registered passport + signing key** (cryptographic
    identity on every envelope this agent emits),
  - **a CrewAI ``Agent`` instance** (the LLM-backed reasoning loop,
    its role/goal/tools/backstory), and
  - **a task-factory callable** that converts an inbound Yutha
    envelope into a CrewAI ``Task`` for the wrapped Agent to
    execute.

Lifecycle is identical in shape to :class:`yutha.langgraph.YuthaAgent`:
construct, ``register()``, enter the async context manager,
``send()`` to emit envelopes, exit drains the subscribe stream and
closes the channel.

## What happens on an inbound envelope

The dispatch loop pulls ``(envelope, deliver_receipt_id)`` from
``client.envelope.subscribe()``. For each pair:

1. The task-factory builds a CrewAI ``Task`` from the envelope.
   The default factory uses ``envelope.payload`` as the task
   description (UTF-8 decoded) — most users will pass a custom
   factory that does some payload-schema-aware framing.
2. A single-task, single-agent ``Crew`` is spawned and
   ``kickoff()``-ed asynchronously. The wrapped CrewAI Agent
   executes the task, calling any of its registered tools — and
   any tool wrapped via :func:`yutha.crewai.capability_required`
   automatically threads the held cap_id into outbound sends.
3. The crew's output (a ``CrewOutput``) is handed to an optional
   ``on_output`` callback if one was supplied. The callback can
   inspect the output and emit a follow-on envelope via
   :meth:`YuthaCrewAgent.send`.

The dispatch loop catches every handler-level exception and prints
a one-line diagnostic, exactly like the langgraph adapter. Stream-
level failures (auth, transport, malformed proto) land on
:attr:`_dispatch_error` so :meth:`stop` can re-raise.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Awaitable, Callable
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, Self

from yutha.client import YuthaClient
from yutha.crypto import SigningKey
from yutha.identity import AgentId, Hash, SwarmId, Timestamp
from yutha.models import (
    Envelope,
    Passport,
    Performative,
    Receipt,
    Recipient,
)

if TYPE_CHECKING:
    # Type-only — keeps `yutha.crewai.agent` importable without the
    # `crewai` extra installed. The actual `crewai` import lives
    # inside `__init__()` and only fires when the user constructs a
    # YuthaCrewAgent.
    from crewai import Agent as CrewAgentT
    from crewai import Task as CrewTaskT


# A factory that turns an inbound envelope into a CrewAI Task for the
# wrapped Agent to execute. Receives the owning YuthaCrewAgent (so the
# factory can read identity / passport fields) plus the inbound
# envelope and its delivery-receipt id. Returns a CrewAI Task, or
# ``None`` to skip this envelope (useful for filtering, e.g. only
# acting on certain performatives).
TaskFactory = Callable[["YuthaCrewAgent", Envelope, Hash], "CrewTaskT | None"]

# Callback invoked after the per-envelope crew finishes. Receives the
# owning agent + the inbound envelope + the CrewAI output. Use this to
# emit follow-on envelopes (typed responses, escalations, etc.).
OutputCallback = Callable[["YuthaCrewAgent", Envelope, Any], Awaitable[None]]


def _default_task_factory(
    agent: YuthaCrewAgent,
    envelope: Envelope,
    deliver_receipt: Hash,
) -> CrewTaskT | None:
    """Fallback factory: payload (UTF-8) becomes the task description.

    Always re-uses the wrapped CrewAI Agent. Suitable for
    text-payload demos; production integrations should pass a
    custom factory that understands the envelope's
    ``payload_schema_id`` and constructs a structured task.
    """
    from crewai import Task

    # The lint suppression is intentional: deliver_receipt is part of
    # the protocol so factories can choose to thread it as evidence.
    _ = deliver_receipt
    description = envelope.payload.decode("utf-8", errors="replace")
    return Task(
        description=description,
        expected_output="A short natural-language response.",
        agent=agent.crew_agent,
    )


class YuthaCrewAgent:
    """A long-lived CrewAI Agent identity bound to a Yutha control plane.

    Constructor params mirror :class:`yutha.langgraph.YuthaAgent` plus
    two CrewAI-specific knobs:

    Parameters
    ----------
    client
        Connected :class:`YuthaClient`.
    passport
        The agent's registered passport.
    signing_key
        The Ed25519 signing key whose public counterpart is on
        the passport. The constructor enforces the mismatch
        check that the langgraph adapter does.
    crew_agent
        The CrewAI ``Agent`` instance the dispatch loop will
        execute tasks against. Its ``tools`` list may include
        any number of :func:`yutha.crewai.capability_required`
        -wrapped tools — those are what give server-side
        enforcement reach into the CrewAI agent.
    task_factory
        Optional callable that converts inbound envelopes into
        CrewAI ``Task``s. Defaults to a payload-as-description
        factory.
    on_output
        Optional async callback that runs after the per-envelope
        crew finishes. Receives the CrewAI output and may emit
        follow-on envelopes via :meth:`send`.
    epoch_start
        Starting value for the per-agent monotonic epoch
        counter, mirroring langgraph's knob.
    """

    def __init__(
        self,
        client: YuthaClient,
        passport: Passport,
        signing_key: SigningKey,
        crew_agent: CrewAgentT,
        *,
        task_factory: TaskFactory | None = None,
        on_output: OutputCallback | None = None,
        epoch_start: int = 1,
    ) -> None:
        # Validate crewai is importable before we hand back an agent.
        # The lazy `_require_crewai` keeps `import yutha.crewai` cheap;
        # constructor-time is when we actually need the dep.
        from yutha.crewai import _require_crewai

        _require_crewai()

        if signing_key.public_key_bytes() != passport.agent_public_key.value:
            raise ValueError(
                "signing_key does not match passport.agent_public_key — "
                "the agent would fail to sign envelopes the control plane accepts"
            )
        self._client = client
        self._passport = passport
        self._signing_key = signing_key
        self._crew_agent = crew_agent
        self._task_factory: TaskFactory = task_factory or _default_task_factory
        self._on_output = on_output
        self._epoch = epoch_start
        self._epoch_lock = asyncio.Lock()
        self._dispatch_task: asyncio.Task[None] | None = None
        self._stopped = asyncio.Event()
        # Set by the dispatch loop once it has actually called
        # subscribe() — start() awaits this so callers don't race
        # the subscription-setup and miss the first envelope.
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
        signing_key: SigningKey,
        crew_agent: CrewAgentT,
        task_factory: TaskFactory | None = None,
        on_output: OutputCallback | None = None,
        token_lifetime_seconds: int = 300,
        refresh_lead_seconds: int = 30,
        tls_root_ca: str | Path | bytes | None = None,
        client_cert: str | Path | bytes | None = None,
        client_key: str | Path | bytes | None = None,
        epoch_start: int = 1,
    ) -> Self:
        """Build a connected agent in one call. Wraps
        :meth:`yutha.YuthaClient.connect` with the same TLS knobs as
        the langgraph adapter; see that adapter's docs for the
        argument semantics.

        The returned agent is *not* yet running its dispatch loop —
        call :meth:`start` (or use the async context manager) to
        begin pulling envelopes.
        """
        client = YuthaClient.connect(
            address,
            agent_id=passport.agent_id,
            swarm_id=passport.swarm_id,
            signing_key=signing_key,
            token_lifetime_seconds=token_lifetime_seconds,
            refresh_lead_seconds=refresh_lead_seconds,
            tls_root_ca=tls_root_ca,
            client_cert=client_cert,
            client_key=client_key,
        )
        return cls(
            client=client,
            passport=passport,
            signing_key=signing_key,
            crew_agent=crew_agent,
            task_factory=task_factory,
            on_output=on_output,
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
    def crew_agent(self) -> CrewAgentT:
        """The wrapped CrewAI ``Agent``. Exposed so handlers /
        task-factories can introspect role / tools / etc."""
        return self._crew_agent

    @property
    def is_running(self) -> bool:
        return self._dispatch_task is not None and not self._dispatch_task.done()

    # -------------------------------------------------------------------------
    # Registration
    # -------------------------------------------------------------------------

    async def register(self) -> Hash | None:
        """Register the agent's passport. Same semantics as the
        langgraph adapter: returns the registration receipt id on
        success, ``None`` if the passport was already present."""
        resp = await self._client.admission.register(self._passport)
        if not resp.result.HasField("registration_receipt"):
            return None
        return Hash.from_proto(resp.result.registration_receipt)

    # -------------------------------------------------------------------------
    # Dispatch loop
    # -------------------------------------------------------------------------

    async def start(self, *, ready_timeout: float = 10.0) -> None:
        """Open the subscribe stream and start dispatching incoming
        envelopes to the CrewAI agent. Blocks until subscription is
        confirmed open. Same semantics as the langgraph adapter."""
        if self._dispatch_task is not None:
            raise RuntimeError("YuthaCrewAgent.start() called twice; create a fresh agent")
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
            raise RuntimeError("YuthaCrewAgent dispatch loop exited before subscribing")
        dispatch_task.cancel()
        raise TimeoutError(
            f"YuthaCrewAgent.start() timed out after {ready_timeout}s waiting for "
            "the subscribe stream to open"
        )

    async def _dispatch_loop(self) -> None:
        """Pull envelopes, convert each to a CrewAI Task, kick off the
        single-task crew, hand the output to the on_output callback.

        ``Crew.kickoff()`` is synchronous in CrewAI 0.x; we run it on
        a worker thread via :func:`asyncio.to_thread` so the dispatch
        loop stays responsive (the LLM call inside can take seconds).
        """
        from crewai import Crew, Process

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
                    task = self._task_factory(self, envelope, deliver_receipt)
                    if task is None:
                        # Factory chose to skip this envelope.
                        continue
                    crew = Crew(
                        agents=[self._crew_agent],
                        tasks=[task],
                        process=Process.sequential,
                        verbose=False,
                    )
                    # CrewAI's kickoff is blocking; offload it so we
                    # don't stall the gRPC stream. Capability-required
                    # tools inside the crew read ACTIVE_CAPABILITY_ID
                    # from contextvars — those propagate into the
                    # worker thread on Python 3.11+ because
                    # asyncio.to_thread copies the context.
                    output = await asyncio.to_thread(crew.kickoff)
                    if self._on_output is not None:
                        await self._on_output(self, envelope, output)
                except Exception as e:  # handlers can raise anything — keep loop alive
                    print(
                        f"YuthaCrewAgent({self.agent_id}): handler raised {type(e).__name__}: {e}",
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
        langgraph adapter:

        1. Explicit kwarg.
        2. Context-local
           :data:`yutha._capability_context.ACTIVE_CAPABILITY_ID`
           (set by :func:`yutha.crewai.capability_required`).
        3. None.
        """
        async with self._epoch_lock:
            epoch = self._epoch
            self._epoch += 1

        envelope = Envelope(
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
        ).sign(self._signing_key)

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


__all__ = ["YuthaCrewAgent", "TaskFactory", "OutputCallback"]

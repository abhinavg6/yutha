"""Unit tests for the CrewAI adapter primitives.

These don't touch a live control plane or an LLM — they verify the
adapter's local behavior (capability_required validation,
contextvar threading, constructor validation). The full
control-plane integration test lives in
``test_crewai_integration.py`` and is gated on
``YUTHA_BOOTSTRAP_SEED`` + a running server.

The whole file skips when the ``crewai`` extra is not installed —
the wrapper functions construct CrewAI ``BaseTool`` subclasses
under the hood, which we can't fake without the real class.
"""

from __future__ import annotations

import asyncio
import secrets
from typing import Any
from unittest import mock

import pytest

import yutha
from yutha._capability_context import ACTIVE_CAPABILITY_ID

pytest.importorskip(
    "crewai",
    reason="crewai extra not installed; install with `pip install 'yutha[crewai]'`",
)

# Imports kept after the importorskip so the file is collectable
# (the module-level skip prevents collection past this line when
# crewai is missing).
from crewai.tools import BaseTool

from yutha.crewai import (
    CapabilityDenied,
    YuthaCrewAgent,
    capability_required,
)
from yutha.crewai.agent import _default_task_factory

# =============================================================================
# Helpers — fake passport + capability + envelope, no server contact
# =============================================================================


def _fake_identity() -> tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId]:
    """Mint a deterministic passport identity locally.

    Mirrors the seed-derived approach used in the other test files,
    but uses random bytes since we're not coordinating with a server.
    """
    seed = secrets.token_bytes(32)
    signing_key = yutha.SigningKey.from_seed_bytes(seed)
    agent_id = yutha.AgentId(value=secrets.token_bytes(16))
    swarm_id = yutha.SwarmId(value=secrets.token_bytes(16))
    return signing_key, agent_id, swarm_id


def _build_passport(
    signing_key: yutha.SigningKey,
    agent_id: yutha.AgentId,
    swarm_id: yutha.SwarmId,
) -> yutha.Passport:
    return yutha.Passport(
        spec_version="1.0.0",
        agent_id=agent_id,
        swarm_id=swarm_id,
        agent_public_key=signing_key.public_key(),
        owner="yutha-test:crewai-unit",
        framework="crewai",
        framework_version="0.x",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
    ).sign(signing_key)


def _build_capability(
    swarm_id: yutha.SwarmId,
    issuer_agent: yutha.AgentId,
    subject: yutha.AgentId,
    *,
    permitted_actions: list[str],
) -> yutha.Capability:
    return yutha.Capability(
        spec_version="1.0.0",
        capability_id=secrets.token_bytes(16),
        swarm_id=swarm_id,
        issuer=yutha.Issuer.for_agent(issuer_agent),
        subject=subject,
        scope=yutha.Scope(permitted_actions=permitted_actions),
        valid_from=yutha.Timestamp.now(),
        valid_until=yutha.Timestamp(
            wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62
        ),
    )


class _RecordingTool(BaseTool):  # type: ignore[misc]  # BaseTool is Any under strict-mypy + ignore_missing_imports
    """Minimal BaseTool subclass that records the contextvar value
    observed inside ``_run``. Used by the contextvar-threading tests
    so we can assert the wrapper set the value before invoking the
    tool body and reset it after."""

    name: str = "recording_tool"
    description: str = "Records ACTIVE_CAPABILITY_ID during _run."

    # Class-level slot for the observation. Using a class attribute
    # (rather than an instance attribute set in __init__) keeps us
    # within the constraints of CrewAI's pydantic-validated BaseTool,
    # which is conservative about extra attributes.
    observed_cap_id: yutha.Hash | None = None

    def _run(self) -> str:
        type(self).observed_cap_id = ACTIVE_CAPABILITY_ID.get()
        return "ok"


# =============================================================================
# capability_required: local validation
# =============================================================================


def test_capability_required_rejects_both_action_kind_and_descriptor() -> None:
    """Mutually-exclusive params: passing both raises ValueError."""
    _, agent_id, swarm_id = _fake_identity()
    cap = _build_capability(
        swarm_id, agent_id, agent_id, permitted_actions=["envelope.send"]
    )
    descriptor = yutha.ActionDescriptor(action_kind="envelope.send")

    with pytest.raises(ValueError, match=r"exactly one of `action_kind` or `descriptor`"):
        capability_required(cap, action_kind="envelope.send", descriptor=descriptor)


def test_capability_required_rejects_neither_action_kind_nor_descriptor() -> None:
    """Mutually-exclusive params: passing neither raises ValueError."""
    _, agent_id, swarm_id = _fake_identity()
    cap = _build_capability(
        swarm_id, agent_id, agent_id, permitted_actions=["envelope.send"]
    )

    with pytest.raises(ValueError, match=r"exactly one of `action_kind` or `descriptor`"):
        capability_required(cap)


def test_capability_required_rejects_scope_mismatch() -> None:
    """Cap scope must include the declared action_kind; mismatch
    raises CapabilityDenied at decoration time, before any tool runs."""
    _, agent_id, swarm_id = _fake_identity()
    cap = _build_capability(
        swarm_id, agent_id, agent_id, permitted_actions=["envelope.send"]
    )

    with pytest.raises(CapabilityDenied, match=r"does not include.*Yutha::SupportQueue"):
        capability_required(cap, action_kind="Yutha::SupportQueue::Action::IssueRefund")


def test_capability_required_accepts_empty_scope_as_wildcard() -> None:
    """Empty `permitted_actions` means "all actions allowed" per
    yutha.models.capability.Scope semantics. The wrapper must NOT
    raise on this case."""
    _, agent_id, swarm_id = _fake_identity()
    cap = _build_capability(swarm_id, agent_id, agent_id, permitted_actions=[])
    tool = _RecordingTool()

    wrap = capability_required(cap, action_kind="envelope.send")
    wrapped = wrap(tool)
    assert wrapped is tool  # mutation-in-place returns the same instance


# =============================================================================
# capability_required: contextvar threading
# =============================================================================


def test_capability_required_sets_contextvar_during_run() -> None:
    """The wrapper sets ACTIVE_CAPABILITY_ID to the cap's content-
    address for the duration of ``_run``, and resets it afterwards."""
    _, agent_id, swarm_id = _fake_identity()
    cap = _build_capability(
        swarm_id, agent_id, agent_id, permitted_actions=["envelope.send"]
    )

    # Outside any wrapper, the contextvar is None.
    assert ACTIVE_CAPABILITY_ID.get() is None

    tool = _RecordingTool()
    type(tool).observed_cap_id = None
    capability_required(cap, action_kind="envelope.send")(tool)
    result = tool._run()

    assert result == "ok"
    observed = type(tool).observed_cap_id
    assert observed is not None
    assert observed.algorithm == yutha.HashAlgorithm.SHA256
    # Resets after _run returns.
    assert ACTIVE_CAPABILITY_ID.get() is None


def test_capability_required_resets_contextvar_on_exception() -> None:
    """If the tool body raises, the contextvar still resets so a
    later send outside the tool doesn't pick up a stale cap_id."""

    class _ExplodingTool(BaseTool):  # type: ignore[misc]  # BaseTool is Any
        name: str = "exploder"
        description: str = "Raises during _run."

        def _run(self) -> str:
            raise RuntimeError("kaboom")

    _, agent_id, swarm_id = _fake_identity()
    cap = _build_capability(
        swarm_id, agent_id, agent_id, permitted_actions=["envelope.send"]
    )

    tool = _ExplodingTool()
    capability_required(cap, action_kind="envelope.send")(tool)

    assert ACTIVE_CAPABILITY_ID.get() is None
    with pytest.raises(RuntimeError, match="kaboom"):
        tool._run()
    assert ACTIVE_CAPABILITY_ID.get() is None


def test_capability_required_rejects_tool_without_run_methods() -> None:
    """A bare object that's not actually a BaseTool gets a clear
    TypeError rather than silently doing nothing."""
    _, agent_id, swarm_id = _fake_identity()
    cap = _build_capability(
        swarm_id, agent_id, agent_id, permitted_actions=["envelope.send"]
    )

    class _NotATool:
        """No `_run` or `_arun`."""

    with pytest.raises(TypeError, match=r"defines neither _run nor _arun"):
        capability_required(cap, action_kind="envelope.send")(_NotATool())


# =============================================================================
# YuthaCrewAgent constructor validation
# =============================================================================


def test_crew_agent_constructor_rejects_passport_signing_key_mismatch() -> None:
    """Same invariant as YuthaAgent: the signing_key's public half
    must match passport.agent_public_key, or the agent would fail
    to sign envelopes the control plane accepts."""
    from crewai import Agent

    signing_key, agent_id, swarm_id = _fake_identity()
    other_signing_key = yutha.SigningKey.generate()
    passport = _build_passport(signing_key, agent_id, swarm_id)

    crew_agent = Agent(
        role="Test", goal="Test", backstory="Test", allow_delegation=False
    )

    # Bypass the dispatch loop / actual gRPC connection — we just
    # want to hit the constructor's validation path.
    fake_client = mock.MagicMock()

    with pytest.raises(ValueError, match=r"signing_key does not match passport.agent_public_key"):
        YuthaCrewAgent(
            client=fake_client,
            passport=passport,
            signing_key=other_signing_key,  # WRONG key
            crew_agent=crew_agent,
        )


# =============================================================================
# Default task factory
# =============================================================================


def test_default_task_factory_uses_payload_as_description() -> None:
    """The fallback factory decodes payload as UTF-8 and uses it as
    the task description, with the wrapped CrewAI Agent as the
    executor."""
    from crewai import Agent

    signing_key, agent_id, swarm_id = _fake_identity()
    passport = _build_passport(signing_key, agent_id, swarm_id)
    crew_agent = Agent(
        role="Greeter", goal="Say hello.", backstory="Polite.", allow_delegation=False
    )

    fake_client = mock.MagicMock()
    crew_wrapper = YuthaCrewAgent(
        client=fake_client,
        passport=passport,
        signing_key=signing_key,
        crew_agent=crew_agent,
    )

    envelope = yutha.Envelope(
        spec_version="1.0.0",
        swarm_id=swarm_id,
        envelope_id=secrets.token_bytes(16),
        from_agent=agent_id,
        recipient=yutha.Recipient.for_agent(agent_id),
        performative=yutha.Performative.INFORM,
        payload=b"hello crewai",
        nonce=secrets.token_bytes(16),
        epoch=1,
        sent_at=yutha.Timestamp.now(),
    ).sign(signing_key)
    fake_deliver_receipt = yutha.Hash(
        algorithm=yutha.HashAlgorithm.SHA256, digest=b"\x00" * 32
    )

    task = _default_task_factory(crew_wrapper, envelope, fake_deliver_receipt)

    assert task is not None
    assert task.description == "hello crewai"
    assert task.agent is crew_agent


# =============================================================================
# Async-context-manager contextvar propagation (Python 3.11+ asyncio.to_thread)
# =============================================================================


def test_wrapper_still_sets_contextvar_under_to_thread() -> None:
    """The dispatch loop runs CrewAI's blocking ``Crew.kickoff()`` on
    a worker thread via ``asyncio.to_thread``. The wrapper sets the
    contextvar locally inside the patched ``_run``, so it must
    function regardless of which thread the call happens on. Confirm
    that here so we don't ship an adapter whose tool wiring works in
    pytest but silently fails when the dispatch loop offloads the
    crew to a worker."""

    _, agent_id, swarm_id = _fake_identity()
    cap = _build_capability(
        swarm_id, agent_id, agent_id, permitted_actions=["envelope.send"]
    )

    tool = _RecordingTool()
    type(tool).observed_cap_id = None
    capability_required(cap, action_kind="envelope.send")(tool)

    async def driver() -> Any:
        return await asyncio.to_thread(tool._run)

    asyncio.run(driver())

    observed = type(tool).observed_cap_id
    assert observed is not None
    assert observed.algorithm == yutha.HashAlgorithm.SHA256

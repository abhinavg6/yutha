"""Live-server integration test for the CrewAI adapter.

Mirrors ``test_langgraph_agent.py`` in shape and skip semantics
(``YUTHA_BOOTSTRAP_SEED`` + a running control plane required). The
focus is the :class:`YuthaCrewAgent` lifecycle wiring — register,
subscribe stream, send-to-self, on_output dispatch — **without**
invoking a real LLM. Each inbound envelope's ``task_factory`` is
configured to return ``None``, which short-circuits
``crew.kickoff()`` before any model call.

The full LLM-driven path is exercised manually via
``examples/s1_support_queue_crewai.py``; running it in CI would
require ``OPENAI_API_KEY`` and is out of scope for v1.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
from typing import Any

import pytest

import yutha

pytest.importorskip(
    "crewai",
    reason="crewai extra not installed; install with `pip install 'yutha[crewai]'`",
)

# Imports below the importorskip so the module is collectable even
# when the crewai extra is missing. (ruff doesn't flag these as E402
# under the project's current rule set; the importorskip is treated
# as a guard, not a statement.)
from crewai import Agent

from yutha.crewai import YuthaCrewAgent

INTEGRATION_SEED_VAR = "YUTHA_BOOTSTRAP_SEED"
INTEGRATION_ADDR_VAR = "YUTHA_GRPC_ADDR"

pytestmark = pytest.mark.integration


# =============================================================================
# Shared fixtures — mirror of test_langgraph_agent.py
# =============================================================================


def _derive_identity_from_seed(
    seed: bytes,
) -> tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId]:
    if len(seed) != 32:
        raise ValueError(f"seed must be exactly 32 bytes, got {len(seed)}")
    signing_key = yutha.SigningKey.from_seed_bytes(seed)
    agent_id_bytes = hashlib.sha256(seed + b"\x01").digest()[:16]
    swarm_id_bytes = hashlib.sha256(seed + b"\x02").digest()[:16]
    return (
        signing_key,
        yutha.AgentId(value=agent_id_bytes),
        yutha.SwarmId(value=swarm_id_bytes),
    )


@pytest.fixture
def bootstrap_identity() -> tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId]:
    seed_hex = os.environ.get(INTEGRATION_SEED_VAR)
    if not seed_hex:
        pytest.skip(f"set {INTEGRATION_SEED_VAR}=<64 hex chars> to run integration tests")
    try:
        seed = bytes.fromhex(seed_hex.strip())
    except ValueError:
        pytest.skip(f"{INTEGRATION_SEED_VAR} is not valid hex")
    if len(seed) != 32:
        pytest.skip(f"{INTEGRATION_SEED_VAR} must be 64 hex chars; got {len(seed)} bytes")
    return _derive_identity_from_seed(seed)


@pytest.fixture
def address() -> str:
    return os.environ.get(INTEGRATION_ADDR_VAR, "127.0.0.1:50051")


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
        owner="yutha-crewai integration test",
        framework="crewai",
        framework_version="test",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
    ).sign(signing_key)


async def _issue_self_send_cap(
    client: yutha.YuthaClient,
    agent_id: yutha.AgentId,
    swarm_id: yutha.SwarmId,
) -> yutha.Hash:
    """Same self-cap issuance helper as test_langgraph_agent.py.
    Required when the server enforces RFC 0007 cap-check on Send."""
    cap = yutha.Capability(
        spec_version="1.0.0",
        capability_id=secrets.token_bytes(16),
        swarm_id=swarm_id,
        issuer=yutha.Issuer.for_agent(agent_id),
        subject=agent_id,
        scope=yutha.Scope.for_action("envelope.send"),
        valid_from=yutha.Timestamp.now(),
        valid_until=yutha.Timestamp(
            wall_clock="2099-01-01T00:00:00Z",
            monotonic_ns=2**62,
        ),
    )
    cap_id, _ = await client.capability.issue(cap)
    return cap_id


# =============================================================================
# YuthaCrewAgent lifecycle
# =============================================================================


@pytest.mark.asyncio
async def test_crew_agent_lifecycle_via_dispatch_loop(
    bootstrap_identity: tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId],
    address: str,
    activated_permissive_constitution: object,  # fixture has side-effects only
) -> None:
    """Smoke test for YuthaCrewAgent's subscribe + dispatch wiring.

    Register, send-to-self, observe that the dispatch loop fires the
    ``on_output`` callback. The per-envelope ``task_factory`` returns
    ``None`` so the inner ``crew.kickoff()`` short-circuits — we're
    testing the lifecycle wiring, not LLM-driven CrewAI behavior.
    """
    _ = activated_permissive_constitution  # only here for the fixture side-effect

    signing_key, agent_id, swarm_id = bootstrap_identity
    passport = _build_passport(signing_key, agent_id, swarm_id)
    received: list[yutha.Envelope] = []
    output_callback_fires: list[Any] = []

    # A bare CrewAI Agent — never actually executed because the
    # task_factory returns None for every envelope. Construction
    # still validates the role/goal/backstory fields, which is enough
    # to exercise the constructor's crewai-presence check.
    crew_agent = Agent(
        role="Test Echo",
        goal="Acknowledge inbound envelopes.",
        backstory="A minimal test agent.",
        allow_delegation=False,
    )

    def skip_task_factory(
        agent: YuthaCrewAgent, env: yutha.Envelope, deliver_id: yutha.Hash
    ) -> None:
        # Capture the envelope so we can assert on it after.
        received.append(env)
        return None  # skip the actual crew.kickoff

    async def on_output(
        agent: YuthaCrewAgent, env: yutha.Envelope, output: Any
    ) -> None:
        output_callback_fires.append((env, output))

    crew_wrapper = YuthaCrewAgent.connect(
        address,
        passport=passport,
        signing_key=signing_key,
        crew_agent=crew_agent,
        task_factory=skip_task_factory,
        on_output=on_output,
    )

    async with crew_wrapper:
        await asyncio.sleep(0.1)
        cap_id = await _issue_self_send_cap(
            crew_wrapper.client, agent_id, swarm_id
        )
        send_receipt = await crew_wrapper.send(
            recipient=yutha.Recipient.for_agent(agent_id),
            performative=yutha.Performative.INFORM,
            payload=b"hello from the crewai adapter",
            payload_schema_id="type.yutha.dev/v1/Text",
            tags=["crewai-integration"],
            capability_id=cap_id,
        )
        assert len(send_receipt.digest) == 32

        # Wait for the task_factory to observe the inbound envelope.
        # The on_output callback should NOT fire (task was None →
        # crew.kickoff is skipped).
        for _ in range(50):
            if received:
                break
            await asyncio.sleep(0.1)

        assert received, "send → subscribe → task_factory never fired"
        assert received[0].payload == b"hello from the crewai adapter"
        assert received[0].from_agent == agent_id
        # task_factory returned None, so on_output never gets called.
        assert output_callback_fires == [], (
            f"on_output should not fire when task_factory returns None, "
            f"got {output_callback_fires!r}"
        )


@pytest.mark.asyncio
async def test_crew_agent_send_auto_increments_epoch(
    bootstrap_identity: tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId],
    address: str,
    activated_permissive_constitution: object,  # fixture has side-effects only
) -> None:
    """Same epoch invariant as the langgraph adapter — two back-to-back
    sends carry strictly-increasing epochs."""
    _ = activated_permissive_constitution

    signing_key, agent_id, swarm_id = bootstrap_identity
    passport = _build_passport(signing_key, agent_id, swarm_id)
    received: list[yutha.Envelope] = []

    crew_agent = Agent(
        role="Recorder",
        goal="Note inbound envelopes.",
        backstory="Just records.",
        allow_delegation=False,
    )

    def skip_factory(
        agent: YuthaCrewAgent, env: yutha.Envelope, deliver_id: yutha.Hash
    ) -> None:
        received.append(env)
        return None

    crew_wrapper = YuthaCrewAgent.connect(
        address,
        passport=passport,
        signing_key=signing_key,
        crew_agent=crew_agent,
        task_factory=skip_factory,
    )

    async with crew_wrapper:
        await asyncio.sleep(0.1)
        cap_id = await _issue_self_send_cap(
            crew_wrapper.client, agent_id, swarm_id
        )
        await crew_wrapper.send(
            yutha.Recipient.for_agent(agent_id),
            yutha.Performative.INFORM,
            b"one",
            capability_id=cap_id,
        )
        await crew_wrapper.send(
            yutha.Recipient.for_agent(agent_id),
            yutha.Performative.INFORM,
            b"two",
            capability_id=cap_id,
        )
        for _ in range(50):
            if len(received) >= 2:
                break
            await asyncio.sleep(0.1)
        assert len(received) >= 2, (
            f"expected 2 envelopes on the stream, got {len(received)}"
        )
        epochs = [e.epoch for e in received[:2]]
        assert epochs[0] < epochs[1], f"epochs not strictly increasing: {epochs}"

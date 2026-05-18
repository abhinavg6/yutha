"""Integration tests for the LangGraph adapter primitives (Stage 4b).

Same skip-or-run pattern as ``test_integration.py``: requires
``YUTHA_BOOTSTRAP_SEED`` set to the same hex the Rust control plane
is running with, so the test acts as the pre-registered bootstrap
agent.

Exercises:
  - :class:`YuthaAgent` lifecycle (connect, start, send-to-self,
    receive on the dispatch loop, stop, channel close).
  - :func:`capability_required` permit + deny paths against the live
    capability service.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets

import pytest

import yutha
from yutha.langgraph import CapabilityDenied, YuthaAgent, capability_required

INTEGRATION_SEED_VAR = "YUTHA_BOOTSTRAP_SEED"
INTEGRATION_ADDR_VAR = "YUTHA_GRPC_ADDR"

pytestmark = pytest.mark.integration


# =============================================================================
# Shared fixtures — mirror of test_integration.py
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
    """Build a passport that mirrors what the Rust server registered
    via the bootstrap seed. The contents don't need to match the
    server's exactly — the bootstrap-seed handshake gives both sides
    the same (agent_id, public_key) pair, and that's what bearer-token
    auth uses. The local passport object is just so YuthaAgent's
    constructor has something to bind to."""
    return yutha.Passport(
        spec_version="1.0.0",
        agent_id=agent_id,
        swarm_id=swarm_id,
        agent_public_key=signing_key.public_key(),
        owner="yutha-langgraph integration test",
        framework="langgraph",
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
    """Issue a root capability that grants ``agent_id`` permission to
    perform ``envelope.send`` to itself, and return its content-
    address.

    Required when the server has
    ``topology.require_capability_for_send=true`` (the post-E1 / RFC
    0007 default) — without a threaded cap, every Send rejects with
    ``INVALID_ARGUMENT``. The cap is self-issued (issuer == subject
    == ``agent_id``) which keeps these tests independent of any
    operator/control-plane issuance flow.

    Valid-until is anchored well into the future so the cap doesn't
    expire mid-test under RFC 0008's wall-clock window semantics.
    """
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
    cap_id, _issuance = await client.capability.issue(cap)
    return cap_id


# =============================================================================
# YuthaAgent
# =============================================================================


@pytest.mark.asyncio
async def test_agent_receives_envelopes_via_dispatch_loop(
    bootstrap_identity: tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId],
    address: str,
    activated_permissive_constitution: object,  # fixture has side-effects only
) -> None:
    """Smoke test for the agent's subscribe + dispatch path: send to
    self, the handler is called with the delivered envelope and its
    deliver-receipt id.

    Depends on ``activated_permissive_constitution`` (F11d) — F10's
    SendEnvelope gate refuses every call until an operator activates
    a constitution."""
    signing_key, agent_id, swarm_id = bootstrap_identity
    passport = _build_passport(signing_key, agent_id, swarm_id)
    received: list[tuple[yutha.Envelope, yutha.Hash]] = []

    async def handler(agent: YuthaAgent, env: yutha.Envelope, deliver_id: yutha.Hash) -> None:
        received.append((env, deliver_id))

    agent = YuthaAgent.connect(
        address,
        passport=passport,
        signing_key=signing_key,
        handler=handler,
    )

    async with agent:
        # start() blocks until the subscribe stream is open, so no
        # explicit wait is strictly necessary here — keep a brief one
        # as defence in depth against any server-side registration lag.
        await asyncio.sleep(0.1)

        # Servers with `topology.require_capability_for_send=true`
        # (the post-E1 default) reject sends without a cap. Issue a
        # root self-cap for envelope.send and thread it through.
        cap_id = await _issue_self_send_cap(agent.client, agent_id, swarm_id)

        send_receipt = await agent.send(
            recipient=yutha.Recipient.for_agent(agent_id),
            performative=yutha.Performative.INFORM,
            payload=b"hello from the 4b adapter",
            payload_schema_id="type.yutha.dev/v1/Text",
            tags=["langgraph-4b"],
            capability_id=cap_id,
        )
        assert len(send_receipt.digest) == 32

        # Wait for the handler to fire (bounded so a stuck dispatch
        # doesn't hang the test).
        for _ in range(50):
            if received:
                break
            await asyncio.sleep(0.1)
        assert received, "agent.send → subscribe stream → handler never fired"

        env, deliver_id = received[0]
        assert env.payload == b"hello from the 4b adapter"
        assert env.from_agent == agent_id
        assert len(deliver_id.digest) == 32


@pytest.mark.asyncio
async def test_agent_send_auto_increments_epoch(
    bootstrap_identity: tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId],
    address: str,
    activated_permissive_constitution: object,  # fixture has side-effects only
) -> None:
    """Two back-to-back sends carry strictly-increasing epoch values.
    The server's replay-protection relies on this; we surface it as a
    client-side invariant so future bugs in `agent.send` don't silently
    break replay-protection acceptance.

    Depends on ``activated_permissive_constitution`` (F11d)."""
    signing_key, agent_id, swarm_id = bootstrap_identity
    passport = _build_passport(signing_key, agent_id, swarm_id)
    received: list[yutha.Envelope] = []

    async def handler(agent: YuthaAgent, env: yutha.Envelope, _: yutha.Hash) -> None:
        received.append(env)

    agent = YuthaAgent.connect(
        address,
        passport=passport,
        signing_key=signing_key,
        handler=handler,
    )

    async with agent:
        # start() already waits for the subscribe stream to open; the
        # sleep is harmless defence in depth.
        await asyncio.sleep(0.1)
        # Single cap is reused across both sends — see E1 / RFC 0007.
        cap_id = await _issue_self_send_cap(agent.client, agent_id, swarm_id)
        await agent.send(
            yutha.Recipient.for_agent(agent_id),
            yutha.Performative.INFORM,
            b"one",
            capability_id=cap_id,
        )
        await agent.send(
            yutha.Recipient.for_agent(agent_id),
            yutha.Performative.INFORM,
            b"two",
            capability_id=cap_id,
        )
        # Poll inside the context manager so stop() doesn't cancel the
        # dispatch loop while we're still waiting on the second message.
        for _ in range(50):
            if len(received) >= 2:
                break
            await asyncio.sleep(0.1)
        assert len(received) >= 2, (
            f"expected at least 2 envelopes from the stream, got {len(received)}"
        )
        epochs = [e.epoch for e in received[:2]]
        assert epochs[0] < epochs[1], f"epochs not strictly increasing: {epochs}"


@pytest.mark.asyncio
async def test_agent_rejects_signing_key_mismatch(
    bootstrap_identity: tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId],
    address: str,
) -> None:
    """Constructing an agent with a passport that doesn't match the
    signing key would silently fail later (envelope signatures would
    not verify server-side). Catch it at construction with a clean
    ValueError."""
    _signing_key, agent_id, swarm_id = bootstrap_identity
    wrong_key = yutha.SigningKey.generate()
    passport = _build_passport(wrong_key, agent_id, swarm_id)

    async def noop(*_args: object) -> None:
        return None

    with pytest.raises(ValueError, match="signing_key does not match"):
        YuthaAgent.connect(
            address,
            passport=passport,
            signing_key=yutha.SigningKey.generate(),  # third unrelated key
            handler=noop,
        )


# =============================================================================
# capability_required
# =============================================================================


@pytest.mark.asyncio
async def test_capability_required_permits_in_scope_action(
    bootstrap_identity: tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId],
    address: str,
) -> None:
    """Issue a capability scoped to "send_message", wire the decorator
    onto a node that gates on the same action_kind, invoke it. The
    wrapped function runs; its return value flows through."""
    signing_key, agent_id, swarm_id = bootstrap_identity
    passport = _build_passport(signing_key, agent_id, swarm_id)

    async def noop(*_args: object) -> None:
        return None

    agent = YuthaAgent.connect(address, passport=passport, signing_key=signing_key, handler=noop)
    try:
        cap = yutha.Capability(
            spec_version="1.0.0",
            capability_id=secrets.token_bytes(16),
            swarm_id=swarm_id,
            issuer=yutha.Issuer.for_agent(agent_id),
            subject=agent_id,
            scope=yutha.Scope.for_action("send_message"),
            valid_from=yutha.Timestamp.now(),
            valid_until=yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62),
        )
        await agent.client.capability.issue(cap)

        @capability_required(agent.client, cap, action_kind="send_message")
        async def gated_node(state: int) -> int:
            return state + 1

        result = await gated_node(41)
        assert result == 42
    finally:
        await agent.client.close()


@pytest.mark.asyncio
async def test_capability_required_denies_out_of_scope_action(
    bootstrap_identity: tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId],
    address: str,
) -> None:
    """Same capability, different action_kind on the decorator: the
    server's check returns ``permitted=False`` and the decorator
    raises :class:`CapabilityDenied` without invoking the wrapped fn."""
    signing_key, agent_id, swarm_id = bootstrap_identity
    passport = _build_passport(signing_key, agent_id, swarm_id)

    async def noop(*_args: object) -> None:
        return None

    agent = YuthaAgent.connect(address, passport=passport, signing_key=signing_key, handler=noop)
    try:
        cap = yutha.Capability(
            spec_version="1.0.0",
            capability_id=secrets.token_bytes(16),
            swarm_id=swarm_id,
            issuer=yutha.Issuer.for_agent(agent_id),
            subject=agent_id,
            scope=yutha.Scope.for_action("send_message"),
            valid_from=yutha.Timestamp.now(),
            valid_until=yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62),
        )
        await agent.client.capability.issue(cap)

        invoked = False

        @capability_required(agent.client, cap, action_kind="exfiltrate")
        async def gated_node() -> None:
            nonlocal invoked
            invoked = True

        with pytest.raises(CapabilityDenied):
            await gated_node()
        assert not invoked, "wrapped fn must not run on deny"
    finally:
        await agent.client.close()


def test_capability_required_rejects_both_action_and_descriptor() -> None:
    """The decorator's arg-validation: exactly one of ``action_kind``
    or ``descriptor`` must be supplied. Pure unit test — no live
    server needed."""
    from yutha.models.capability import ActionDescriptor

    fake_client = object()  # never reached; validation runs first
    fake_cap = object()
    with pytest.raises(ValueError, match="exactly one"):
        capability_required(
            fake_client,  # type: ignore[arg-type]
            fake_cap,  # type: ignore[arg-type]
            action_kind="x",
            descriptor=ActionDescriptor(action_kind="y"),
        )
    with pytest.raises(ValueError, match="exactly one"):
        capability_required(
            fake_client,  # type: ignore[arg-type]
            fake_cap,  # type: ignore[arg-type]
        )

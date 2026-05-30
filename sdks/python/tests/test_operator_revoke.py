"""Integration tests for operator-revoke (RFC 0009).

Skipped unless the control plane is running with **both** an
operator public key configured AND open admission mode (so the
two demo agents we register here are admitted). Mirrors the
existing ``test_s1_support_queue_demo.py`` env-var pattern.

To run::

    # Terminal A — mint a seed, derive the operator pubkey, start
    # the server with both pieces:
    export YUTHA_BOOTSTRAP_SEED=$(python -c \
        'import secrets; print(secrets.token_hex(32))')
    OPERATOR_PUBKEY=$(python -c "
    import hashlib, sys
    sys.path.insert(0, 'sdks/python/src')
    from yutha import SigningKey
    seed = bytes.fromhex('$YUTHA_BOOTSTRAP_SEED'.strip())
    op_seed = hashlib.sha256(seed + b'\\x03').digest()
    print(SigningKey.from_seed_bytes(op_seed).public_key().value.hex())
    ")
    cargo run -p yutha-control-plane -- \
        --admission-mode open \
        --operator-public-key $OPERATOR_PUBKEY

    # Terminal B:
    YUTHA_GRPC_ADDR_OPEN=127.0.0.1:50051 \
    YUTHA_BOOTSTRAP_SEED=<same hex> \
        pytest -m integration -q \
        tests/test_operator_revoke.py
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets

import grpc
import pytest

import yutha
from yutha.langgraph import YuthaAgent

# Same env-var contract as the S1 demo wrapper.
INTEGRATION_OPEN_ADDR_VAR = "YUTHA_GRPC_ADDR_OPEN"
INTEGRATION_SEED_VAR = "YUTHA_BOOTSTRAP_SEED"

pytestmark = pytest.mark.integration


FAR_FUTURE = yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def server_addr() -> str:
    addr = os.environ.get(INTEGRATION_OPEN_ADDR_VAR)
    seed = os.environ.get(INTEGRATION_SEED_VAR)
    if not addr or not seed:
        pytest.skip(
            f"set {INTEGRATION_OPEN_ADDR_VAR} and {INTEGRATION_SEED_VAR} "
            "to run operator-revoke integration tests; the control plane "
            "must also be started with --operator-public-key matching the "
            "seed-derived operator pubkey (see module docstring)"
        )
    return addr


@pytest.fixture
def seed_bytes() -> bytes:
    return bytes.fromhex(os.environ[INTEGRATION_SEED_VAR].strip())


def _derive_swarm_id(seed: bytes) -> yutha.SwarmId:
    return yutha.SwarmId(value=hashlib.sha256(seed + b"\x02").digest()[:16])


def _derive_operator_keypair(seed: bytes) -> tuple[yutha.InProcessSigner, yutha.PublicKey]:
    op_seed = hashlib.sha256(seed + b"\x03").digest()
    signer = yutha.InProcessSigner.from_seed_bytes(op_seed)
    return signer, signer.public_key()


async def _make_demo_passport(
    name: str, swarm_id: yutha.SwarmId, signer: yutha.Signer, agent_id: yutha.AgentId
) -> yutha.Passport:
    return await yutha.Passport(
        spec_version="1.0.0",
        agent_id=agent_id,
        swarm_id=swarm_id,
        agent_public_key=signer.public_key(),
        owner=f"yutha-test:operator-revoke:{name}",
        framework="test",
        framework_version="1.0.0",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
        expires_at=FAR_FUTURE,
    ).sign(signer)


# =============================================================================
# Tests
# =============================================================================


@pytest.mark.asyncio
async def test_operator_revokes_target_and_targets_subsequent_auth_fails(
    server_addr: str, seed_bytes: bytes
) -> None:
    """Happy path: operator client calls operator_revoke on a registered
    demo agent. The revocation_receipt comes back. The target's
    subsequent bearer auth fails with UNAUTHENTICATED (revoked-set
    check, RFC 0009 §3.3)."""
    swarm_id = _derive_swarm_id(seed_bytes)
    op_signer, _ = _derive_operator_keypair(seed_bytes)

    # Register a demo agent ("target") via anonymous register.
    target_signer = yutha.InProcessSigner.generate()
    target_id = yutha.AgentId(value=secrets.token_bytes(16))
    target_passport = await _make_demo_passport("target", swarm_id, target_signer, target_id)

    async with yutha.YuthaClient.connect(
        server_addr,
        agent_id=target_id,
        swarm_id=swarm_id,
        signer=target_signer,
    ) as target_client:
        await target_client.admission.register(target_passport)

        # Sanity: target can issue a get_topology before revocation.
        await target_client.admission.get_topology()

        # Operator evicts target.
        async with yutha.YuthaClient.connect_as_operator(
            server_addr,
            operator_id="test-operator",
            swarm_id=swarm_id,
            operator_signer=op_signer,
        ) as op_client:
            outcome = await op_client.admission.operator_revoke(
                target_id, "test: operator eviction"
            )
            assert len(outcome.eviction_receipt.digest) == 32
            # Default cascade=False — server must not return any
            # capability.revoke receipts on this path.
            assert outcome.cascade_receipts == []

        # Now target's bearer auth should fail. Wait a beat for the
        # revoked-set update to land (it lands synchronously inside
        # the handler, but the bearer-session cache on the client side
        # may serve a still-valid hex token from cache). force a fresh
        # mint by sleeping past the cache window — simpler: just
        # observe the first subsequent RPC fails.
        with pytest.raises(grpc.aio.AioRpcError) as exc_info:
            await target_client.admission.get_topology()
        assert exc_info.value.code() == grpc.StatusCode.UNAUTHENTICATED
        assert "revoked" in (exc_info.value.details() or "").lower()


@pytest.mark.asyncio
async def test_active_stream_tear_down_on_operator_revoke(
    server_addr: str, seed_bytes: bytes
) -> None:
    """Subscriber's stream closes promptly when the operator revokes
    them (RFC 0009 §3.3 — the load-bearing property of this RFC).
    Bound: ≤ 3 seconds (we aim for tens of milliseconds in practice).

    Uses :class:`YuthaAgent` rather than raw client.subscribe so we
    catch the deny via the agent's `_dispatch_error` capture path that
    Stage 4b ships."""
    swarm_id = _derive_swarm_id(seed_bytes)
    op_signer, _ = _derive_operator_keypair(seed_bytes)

    subscriber_signer = yutha.InProcessSigner.generate()
    subscriber_id = yutha.AgentId(value=secrets.token_bytes(16))
    subscriber_passport = await _make_demo_passport(
        "subscriber", swarm_id, subscriber_signer, subscriber_id
    )

    received: list[object] = []

    async def handler(*_args: object) -> None:
        received.append(_args)

    agent = YuthaAgent.connect(
        server_addr,
        passport=subscriber_passport,
        signer=subscriber_signer,
        handler=handler,
    )
    await agent.register()

    async with agent:
        # Give the subscribe stream a beat to fully open.
        await asyncio.sleep(0.1)

        # Operator evicts the subscriber. The Subscribe handler's
        # Notify-aware wrapper should fire and close the stream.
        async with yutha.YuthaClient.connect_as_operator(
            server_addr,
            operator_id="test-operator",
            swarm_id=swarm_id,
            operator_signer=op_signer,
        ) as op_client:
            await op_client.admission.operator_revoke(subscriber_id, "test: tear-down probe")

        # Poll for the dispatch loop to observe the closure. Bound the
        # wait so a stuck stream doesn't hang the test.
        for _ in range(30):  # ~3 seconds total
            if agent._dispatch_error is not None or not agent.is_running:
                break
            await asyncio.sleep(0.1)

    # After exiting the context manager, the agent should be stopped
    # and `_dispatch_error` should hold the UNAUTHENTICATED grpc error.
    err = agent._dispatch_error
    assert err is not None, (
        "dispatch loop should have surfaced an error from the tear-down; "
        "either the Notify didn't fire or the wrapper didn't propagate"
    )
    # The error path goes through `_wrap_subscribe_stream` which raises
    # AioRpcError from the gRPC stream's status frame.
    assert isinstance(err, grpc.aio.AioRpcError), (
        f"expected AioRpcError, got {type(err).__name__}: {err}"
    )
    assert err.code() == grpc.StatusCode.UNAUTHENTICATED
    assert "revoked" in (err.details() or "").lower()


@pytest.mark.asyncio
async def test_operator_revoke_cascade_capabilities_revokes_outstanding_caps(
    server_addr: str, seed_bytes: bytes
) -> None:
    """End-to-end coverage of RFC 0009 §3.2 cascade. Target registers,
    self-issues two root caps, then the operator evicts with
    ``cascade_capabilities=True``. We assert that:

    1. ``OperatorRevokeOutcome.cascade_receipts`` carries one entry per
       outstanding cap the target held.
    2. Each entry has a 32-byte SHA-256 digest (i.e. they are real
       content-addresses, not zero / placeholder hashes).
    3. The receipts are *queryable* under ``capability.revoke`` after
       the call — proves the cascade actually landed against the
       receipt log rather than just producing IDs.

    Cross-checks the cascade path that the existing first test
    (``cascade=False``) explicitly negates.
    """
    swarm_id = _derive_swarm_id(seed_bytes)
    op_signer, _ = _derive_operator_keypair(seed_bytes)

    target_signer = yutha.InProcessSigner.generate()
    target_id = yutha.AgentId(value=secrets.token_bytes(16))
    target_passport = await _make_demo_passport(
        "cascade-target", swarm_id, target_signer, target_id
    )

    # Auditor exists purely to read `capability.revoke` receipts back
    # post-cascade — the target's bearer is invalid after eviction and
    # the operator bearer doesn't speak the receipt query surface.
    auditor_signer = yutha.InProcessSigner.generate()
    auditor_id = yutha.AgentId(value=secrets.token_bytes(16))
    auditor_passport = await _make_demo_passport(
        "cascade-auditor", swarm_id, auditor_signer, auditor_id
    )

    async with yutha.YuthaClient.connect(
        server_addr,
        agent_id=target_id,
        swarm_id=swarm_id,
        signer=target_signer,
    ) as target_client:
        await target_client.admission.register(target_passport)

        # Target self-issues two root caps. Distinct action-kinds so
        # the two have different content addresses; subject=target so
        # `list_for_subject(target)` picks them both up.
        far_future = yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62)
        cap_ids: list[yutha.Hash] = []
        for action in ("envelope.send", "send_message"):
            cap = yutha.Capability(
                spec_version="1.0.0",
                capability_id=secrets.token_bytes(16),
                swarm_id=swarm_id,
                issuer=yutha.Issuer.for_agent(target_id),
                subject=target_id,
                scope=yutha.Scope.for_action(action),
                valid_from=yutha.Timestamp.now(),
                valid_until=far_future,
            )
            cap_id, _issuance = await target_client.capability.issue(cap)
            cap_ids.append(cap_id)
        assert len(cap_ids) == 2

    # Register auditor + grab the baseline `capability.revoke` count
    # BEFORE we ask the operator to cascade. We compare counts later
    # rather than full receipts because the test fixture may share a
    # server with previous tests in the same module.
    async with yutha.YuthaClient.connect(
        server_addr,
        agent_id=auditor_id,
        swarm_id=swarm_id,
        signer=auditor_signer,
    ) as auditor_client:
        await auditor_client.admission.register(auditor_passport)
        before, _ = await auditor_client.receipt.query_by_action_kind("capability.revoke")
        baseline_count = len(before)

        # Operator evicts target with cascade=True. Expect exactly
        # two cascade receipts back, one per cap issued above.
        async with yutha.YuthaClient.connect_as_operator(
            server_addr,
            operator_id="test-operator",
            swarm_id=swarm_id,
            operator_signer=op_signer,
        ) as op_client:
            outcome = await op_client.admission.operator_revoke(
                target_id,
                "test: cascade eviction",
                cascade_capabilities=True,
            )

        assert len(outcome.eviction_receipt.digest) == 32
        assert len(outcome.cascade_receipts) == 2, (
            f"expected 2 cascade receipts (one per outstanding cap), got "
            f"{len(outcome.cascade_receipts)}: {outcome.cascade_receipts}"
        )
        for cascade_id in outcome.cascade_receipts:
            assert len(cascade_id.digest) == 32

        # Each returned cascade receipt must be queryable under the
        # `capability.revoke` action-kind. We don't probe individual
        # IDs (the query API is by-action-kind, not by-id) — instead
        # we verify the global count went up by exactly two.
        after, _ = await auditor_client.receipt.query_by_action_kind("capability.revoke")
        assert len(after) - baseline_count == 2, (
            f"capability.revoke receipt count rose by "
            f"{len(after) - baseline_count}, expected 2 (one per cascaded cap)"
        )


@pytest.mark.asyncio
async def test_agent_client_cannot_call_operator_revoke(
    server_addr: str, seed_bytes: bytes
) -> None:
    """An agent-authenticated client trying to invoke
    `operator_revoke` gets UNAUTHENTICATED with the documented
    "this RPC requires an operator bearer" message — the server's
    bearer-variant parser rejects mismatched variants
    (RFC 0009 §3.1)."""
    swarm_id = _derive_swarm_id(seed_bytes)

    agent_signer = yutha.InProcessSigner.generate()
    agent_id = yutha.AgentId(value=secrets.token_bytes(16))
    agent_passport = await _make_demo_passport("agent", swarm_id, agent_signer, agent_id)
    target_id = yutha.AgentId(value=secrets.token_bytes(16))

    async with yutha.YuthaClient.connect(
        server_addr,
        agent_id=agent_id,
        swarm_id=swarm_id,
        signer=agent_signer,
    ) as agent_client:
        await agent_client.admission.register(agent_passport)

        with pytest.raises(grpc.aio.AioRpcError) as exc_info:
            await agent_client.admission.operator_revoke(target_id, "test: should not succeed")
        # The server's variant parser surfaces this as UNAUTHENTICATED.
        assert exc_info.value.code() == grpc.StatusCode.UNAUTHENTICATED
        assert "operator" in (exc_info.value.details() or "").lower()

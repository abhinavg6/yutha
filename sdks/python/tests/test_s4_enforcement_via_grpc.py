"""S4: four-stage enforcement loop end-to-end via gRPC.

Python mirror of
``crates/yutha-conformance/src/scenarios/s4_enforcement_loop.rs``.
Validates that the gRPC handler path produces the same receipts the
Rust-only scenario does — catches drift between the in-process
substrate and the wire-level surface.

Flow:

1. Activate the forbid-with-fallback constitution
   (:func:`yutha.testing.forbid_constitution`) so the bootstrap-style
   tests in the same session continue to work on non-forbidden
   payloads.
2. Register a throwaway "alice" agent + issue her a self-send
   capability. Quarantine state lands on alice, not on the shared
   bootstrap agent — so this test never side-effects the other
   integration tests.
3. Alice sends 2 envelopes with ``payload_schema_id =
   "type.yutha.dev/v1/Forbidden"``. Both fail with
   :class:`yutha.ConstitutionDenied` (deny_reason
   ``"forbid_rule_matched"``).
4. Two ``constitution.evaluate.deny`` receipts appear immediately
   in the audit log.
5. The enforcement engine fires ``enforcement.detect`` after the
   second deny; coach / quarantine / evict follow on the
   1s-cadence scheduler tick. The test polls the receipt store
   with bounded retries.
6. Between quarantine + evict, alice's pre-existing send-cap
   denies with ``deny_reason = "subject_quarantined"`` (validates
   F10g + F12 over the wire).

Env-var contract identical to the other integration tests:
``YUTHA_BOOTSTRAP_SEED`` (32 hex bytes) plus a server started with
``--operator-public-key`` matching the seed-derived operator pubkey
and ``--admission-mode open`` (alice needs to self-admit).
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
from collections.abc import Callable

import grpc
import pytest

import yutha
from yutha.testing import forbid_constitution

pytestmark = pytest.mark.integration


# Sentinel payload schema the forbid rule matches. Anything else
# passes through the trailing permit-all rule.
FORBIDDEN_SCHEMA_ID = "type.yutha.dev/v1/Forbidden"

# How long we'll wait for the enforcement chain's scheduler tick +
# cooldowns to land each stage. Each stage advances at most ~2s past
# the prior one (1s scheduler tick + 1s configured cooldown), so 10s
# is generous and leaves headroom for slow CI hardware.
CHAIN_TIMEOUT_SECONDS = 10.0
POLL_INTERVAL_SECONDS = 0.25


# =============================================================================
# Fixtures
# =============================================================================


def _derive_identity(
    seed: bytes,
) -> tuple[yutha.InProcessSigner, yutha.AgentId, yutha.SwarmId]:
    signer = yutha.InProcessSigner.from_seed_bytes(seed)
    agent_id_bytes = hashlib.sha256(seed + b"\x01").digest()[:16]
    swarm_id_bytes = hashlib.sha256(seed + b"\x02").digest()[:16]
    return (
        signer,
        yutha.AgentId(value=agent_id_bytes),
        yutha.SwarmId(value=swarm_id_bytes),
    )


def _derive_operator_keypair(
    seed: bytes,
) -> tuple[yutha.InProcessSigner, yutha.PublicKey]:
    op_seed = hashlib.sha256(seed + b"\x03").digest()
    signer = yutha.InProcessSigner.from_seed_bytes(op_seed)
    return signer, signer.public_key()


@pytest.fixture
def bootstrap_identity() -> tuple[yutha.InProcessSigner, yutha.AgentId, yutha.SwarmId]:
    seed_hex = os.environ.get("YUTHA_BOOTSTRAP_SEED")
    if not seed_hex:
        pytest.skip("set YUTHA_BOOTSTRAP_SEED")
    return _derive_identity(bytes.fromhex(seed_hex.strip()))


@pytest.fixture
def seed_bytes() -> bytes:
    seed_hex = os.environ.get("YUTHA_BOOTSTRAP_SEED")
    if not seed_hex:
        pytest.skip("set YUTHA_BOOTSTRAP_SEED")
    return bytes.fromhex(seed_hex.strip())


@pytest.fixture
def address() -> str:
    return (
        os.environ.get("YUTHA_GRPC_ADDR_OPEN")
        or os.environ.get("YUTHA_GRPC_ADDR")
        or "127.0.0.1:50051"
    )


@pytest.fixture
async def forbid_active(
    seed_bytes: bytes,
    address: str,
) -> None:
    """Module-isolated activation of the forbid constitution. Runs
    before the test body and silently replaces whatever
    constitution the session-scoped permissive fixture activated.
    The forbid constitution carries a permit-all fallback so other
    tests in the session still work."""
    operator_signer, _ = _derive_operator_keypair(seed_bytes)
    _, _, swarm_id = _derive_identity(seed_bytes)
    constitution = forbid_constitution(swarm_id)

    client = yutha.YuthaClient.connect_as_operator(
        address,
        operator_id="yutha-test:s4-grpc",
        swarm_id=swarm_id,
        operator_signer=operator_signer,
    )
    try:
        try:
            await client.constitution.activate(constitution)
        except grpc.aio.AioRpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                pytest.skip(f"control plane not reachable at {address}")
            if e.code() == grpc.StatusCode.FAILED_PRECONDITION:
                pytest.skip(f"server at {address} returned FAILED_PRECONDITION: {e.details()}")
            raise
    finally:
        await client.close()


# =============================================================================
# Helpers
# =============================================================================


async def _wait_for_receipt_count(
    client: yutha.YuthaClient,
    action_kind: str,
    minimum: int,
    *,
    predicate: Callable[[yutha.Receipt], bool] | None = None,
    timeout_seconds: float = CHAIN_TIMEOUT_SECONDS,
) -> list[yutha.Receipt]:
    """Poll ``ReceiptAPI.query_by_action_kind`` until at least
    ``minimum`` receipts match. When ``predicate`` is set it's
    applied as an additional filter — useful for distinguishing
    pre-existing receipts (e.g. ``capability.check.deny`` from
    other tests) from the ones this test produces."""
    deadline = asyncio.get_event_loop().time() + timeout_seconds
    last: list[yutha.Receipt] = []
    while asyncio.get_event_loop().time() < deadline:
        receipts, _ = await client.receipt.query_by_action_kind(action_kind)
        filtered = [r for r in receipts if predicate(r)] if predicate else receipts
        if len(filtered) >= minimum:
            return filtered
        last = filtered
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
    raise AssertionError(
        f"timed out after {timeout_seconds}s waiting for {minimum} "
        f"{action_kind!r} receipt(s); last count = {len(last)}"
    )


def _evidence(receipt: yutha.Receipt, key: str) -> bytes | None:
    for e in receipt.evidence:
        if e.key == key:
            return e.value
    return None


def _evidence_str(receipt: yutha.Receipt, key: str) -> str | None:
    v = _evidence(receipt, key)
    return v.decode("utf-8") if v is not None else None


# =============================================================================
# Test
# =============================================================================


@pytest.mark.asyncio
async def test_s4_full_enforcement_chain_via_grpc(
    bootstrap_identity: tuple[yutha.InProcessSigner, yutha.AgentId, yutha.SwarmId],
    address: str,
    forbid_active: None,  # fixture has side-effects only — name kept so pytest injects it
) -> None:
    """End-to-end Python mirror of the Rust S4 conformance scenario."""
    bootstrap_signer, _bootstrap_id, swarm_id = bootstrap_identity

    # ---- Step 1: register a throwaway "alice" agent ----
    #
    # Open admission mode admits any well-formed passport. Alice's
    # quarantine state stays scoped to alice; the bootstrap agent
    # remains usable for other tests.
    alice_signer = yutha.InProcessSigner.generate()
    alice_id = yutha.AgentId.new()
    alice_passport = await yutha.Passport(
        spec_version="1.0.0",
        agent_id=alice_id,
        swarm_id=swarm_id,
        agent_public_key=alice_signer.public_key(),
        owner="yutha-test:s4-grpc:alice",
        framework="test",
        framework_version="1.0.0",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
        expires_at=yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62),
    ).sign(alice_signer)

    # The bootstrap client registers alice (Admission.Register is
    # anonymous, but bearer auth still needs SOMEONE to be the
    # client identity for the subsequent calls). Then we open a
    # second client as alice for her own sends.
    bootstrap_client = yutha.YuthaClient.connect(
        address,
        agent_id=bootstrap_identity[1],
        swarm_id=swarm_id,
        signer=bootstrap_signer,
    )
    alice_client = yutha.YuthaClient.connect(
        address,
        agent_id=alice_id,
        swarm_id=swarm_id,
        signer=alice_signer,
    )

    try:
        await bootstrap_client.admission.register(alice_passport)

        # Pre-quarantine: issue alice a self-send capability. We'll
        # re-check it after the quarantine fires to validate F10g
        # over the wire.
        cap = yutha.Capability(
            spec_version="1.0.0",
            capability_id=secrets.token_bytes(16),
            swarm_id=swarm_id,
            issuer=yutha.Issuer.for_agent(alice_id),
            subject=alice_id,
            scope=yutha.Scope.for_action("envelope.send"),
            valid_from=yutha.Timestamp.now(),
            valid_until=yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62),
        )
        cap_id, _ = await alice_client.capability.issue(cap)

        # ---- Step 2: alice sends two forbidden envelopes ----
        #
        # Each send hits the constitution layer, evaluates against
        # the forbid rule, and gets denied with PERMISSION_DENIED.
        # The corresponding constitution.evaluate.deny receipt
        # lands in the audit log regardless of the wire response.
        async def send_forbidden(nonce: bytes) -> None:
            envelope = await yutha.Envelope(
                spec_version="1.0.0",
                swarm_id=swarm_id,
                envelope_id=secrets.token_bytes(16),
                from_agent=alice_id,
                recipient=yutha.Recipient.for_agent(alice_id),
                performative=yutha.Performative.INFORM,
                payload=b"forbidden payload",
                payload_schema_id=FORBIDDEN_SCHEMA_ID,
                nonce=nonce,
                epoch=1,
                sent_at=yutha.Timestamp.now(),
            ).sign(alice_signer)
            # `EnvelopeAPI.send` translates the server-side
            # `PERMISSION_DENIED: constitution check denied: ...`
            # into a structured `ConstitutionDenied` carrying the
            # deny_reason as an attribute. (Prior to that
            # translation this test caught the raw AioRpcError.)
            with pytest.raises(yutha.ConstitutionDenied) as exc_info:
                await alice_client.envelope.send(envelope, capability_id=cap_id)
            # The forbid rule the constitution fixture defines is a
            # plain Cedar `forbid` — the evaluator should report
            # `forbid_rule_matched` as the deny_reason.
            assert exc_info.value.deny_reason == "forbid_rule_matched"

        await send_forbidden(secrets.token_bytes(16))
        await send_forbidden(secrets.token_bytes(16))

        # ---- Step 3: verify the two deny receipts landed ----
        #
        # Filter by subject_agent_id so we count only alice's denies,
        # not anything leaked from prior runs against this server.
        alice_id_bytes = str(alice_id).encode("utf-8")

        def is_alice(r: yutha.Receipt) -> bool:
            return _evidence(r, "subject_agent_id") == alice_id_bytes

        deny_receipts = await _wait_for_receipt_count(
            bootstrap_client,
            "constitution.evaluate.deny",
            minimum=2,
            predicate=is_alice,
            timeout_seconds=3.0,
        )
        assert len(deny_receipts) == 2

        # ---- Step 4: enforcement chain fires ----
        #
        # The engine sees the second deny, fires enforcement.detect.
        # The scheduler tick (1s) + coach.cooldown (1s) brings
        # enforcement.coach; quarantine.escalate_after another 1s
        # brings enforcement.quarantine; evict.escalate_after one
        # more brings enforcement.evict.
        await _wait_for_receipt_count(
            bootstrap_client,
            "enforcement.detect",
            minimum=1,
            predicate=lambda r: _evidence(r, "target_agent_id") == alice_id_bytes,
        )
        await _wait_for_receipt_count(
            bootstrap_client,
            "enforcement.coach",
            minimum=1,
            predicate=lambda r: _evidence(r, "target_agent_id") == alice_id_bytes,
        )
        await _wait_for_receipt_count(
            bootstrap_client,
            "enforcement.quarantine",
            minimum=1,
            predicate=lambda r: _evidence(r, "target_agent_id") == alice_id_bytes,
        )

        # ---- Step 5: cap layer denies alice while quarantined ----
        #
        # Re-check the pre-quarantine cap. The cap-layer's
        # QuarantineSource consults the engine; alice is currently
        # quarantined; the check returns deny with the F10g reason.
        check_outcome = await alice_client.capability.check(
            cap,
            yutha.ActionDescriptor(action_kind="envelope.send"),
        )
        assert not check_outcome.permitted
        assert check_outcome.deny_reason == "subject_quarantined"

        # And the deny gets a receipt that filters by reason.
        await _wait_for_receipt_count(
            bootstrap_client,
            "capability.check.deny",
            minimum=1,
            predicate=lambda r: _evidence_str(r, "deny_reason") == "subject_quarantined",
            timeout_seconds=3.0,
        )

        # ---- Step 6: evict eventually lands ----
        await _wait_for_receipt_count(
            bootstrap_client,
            "enforcement.evict",
            minimum=1,
            predicate=lambda r: _evidence(r, "target_agent_id") == alice_id_bytes,
        )
    finally:
        await alice_client.close()
        await bootstrap_client.close()

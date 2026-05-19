"""End-to-end integration test against a running Rust control plane.

Skipped by default. To run:

  1. Pick a 32-byte (64 hex chars) seed. ANY randomly-chosen seed
     works as long as both sides use the same one. Example:

       python -c "import secrets; print(secrets.token_hex(32))"

  2. Start the Rust control plane with that seed:

       YUTHA_BOOTSTRAP_SEED=<hex> cargo run -p yutha-control-plane

     Both sides derive (signing_key, agent_id, swarm_id) from the
     same seed via the documented Rust ``BootstrapIdentity::from_seed_hex``
     in ``crates/yutha-control-plane/src/main.rs``. The Python side
     mirrors that derivation in :func:`_derive_identity_from_seed`
     below.

  3. Run:

       YUTHA_BOOTSTRAP_SEED=<hex> pytest -m integration

What this test proves end-to-end:

  - Bearer-token auth: every authenticated RPC succeeds because the
    Python-minted token verifies against the bootstrap public key the
    Rust server resolved via its passport store.
  - Topology round-trip: ``GetTopology`` returns the swarm id derived
    from the same seed (catch-most-things sanity).
  - Capability issue → receipt: ``CapabilityService.Issue`` lands a
    real cap, returns its content-address + the issuance receipt id.
  - Envelope send → stream-subscribe → receive: the full async path
    through ``EnvelopeService.Send`` and the server-streaming
    ``Subscribe``, including the in-process MemoryTransport's
    deliver-receipt emission.
  - Receipt audit trail: querying by action_kind surfaces the
    ``capability.issue``, ``envelope.send``, and ``envelope.deliver``
    receipts that just landed.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets

import grpc
import pytest

import yutha

INTEGRATION_SEED_VAR = "YUTHA_BOOTSTRAP_SEED"
INTEGRATION_ADDR_VAR = "YUTHA_GRPC_ADDR"

pytestmark = pytest.mark.integration


# =============================================================================
# Identity derivation — mirror of Rust BootstrapIdentity::from_seed_hex
# =============================================================================


def _derive_identity_from_seed(
    seed: bytes,
) -> tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId]:
    """Mirror of the Rust ``BootstrapIdentity::from_seed_hex``
    derivation in ``crates/yutha-control-plane/src/main.rs``. Both
    sides MUST agree on these bytes or the test silently
    authenticates as a different agent than the server registered.
    """
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


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def bootstrap_identity() -> tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId]:
    seed_hex = os.environ.get(INTEGRATION_SEED_VAR)
    if not seed_hex:
        pytest.skip(
            f"set {INTEGRATION_SEED_VAR}=<64 hex chars> to run integration tests "
            "(the Rust server must be started with the same seed)"
        )
    try:
        seed = bytes.fromhex(seed_hex.strip())
    except ValueError:
        pytest.skip(f"{INTEGRATION_SEED_VAR} is not valid hex")
    if len(seed) != 32:
        pytest.skip(
            f"{INTEGRATION_SEED_VAR} must be exactly 64 hex chars (32 bytes); got {len(seed)} bytes"
        )
    return _derive_identity_from_seed(seed)


@pytest.fixture
def address() -> str:
    return os.environ.get(INTEGRATION_ADDR_VAR, "127.0.0.1:50051")


# =============================================================================
# Unit: derivation determinism
# =============================================================================
#
# Sanity check that doesn't need the server running. Marked integration
# because the rest of the module is, but it'll always run when invoked.


def test_seed_derivation_is_deterministic() -> None:
    """Same seed → same triple, every time. Different seeds → different
    triples. Both invariants are load-bearing for the cross-language
    handoff to work."""
    seed = secrets.token_bytes(32)
    a = _derive_identity_from_seed(seed)
    b = _derive_identity_from_seed(seed)
    assert a[0].public_key_bytes() == b[0].public_key_bytes()
    assert a[1] == b[1]
    assert a[2] == b[2]

    other_seed = secrets.token_bytes(32)
    c = _derive_identity_from_seed(other_seed)
    assert c[1] != a[1]
    assert c[2] != a[2]


# =============================================================================
# Live tests against the running Rust control plane
# =============================================================================


@pytest.mark.asyncio
async def test_get_topology_returns_our_swarm(
    bootstrap_identity: tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId],
    address: str,
) -> None:
    """Simplest live check: connect, bearer-authenticate, fetch the
    topology, verify the swarm_id matches the derived one. If the
    server is using a different seed (or no seed), the swarm_id
    won't match and this fails loudly."""
    signing_key, agent_id, swarm_id = bootstrap_identity
    async with yutha.YuthaClient.connect(
        address,
        agent_id=agent_id,
        swarm_id=swarm_id,
        signing_key=signing_key,
    ) as client:
        resp = await client.admission.get_topology()
        assert bytes(resp.topology.swarm_id.value) == swarm_id.value, (
            "topology.swarm_id from the server does not match our derived "
            "swarm_id — does the Rust server have the same "
            f"{INTEGRATION_SEED_VAR}?"
        )


@pytest.mark.asyncio
async def test_full_lifecycle(
    bootstrap_identity: tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId],
    address: str,
    activated_permissive_constitution: object,  # fixture has side-effects only
) -> None:
    """The load-bearing end-to-end test: issue a capability, send an
    envelope to self, receive it via the subscribe stream, query the
    resulting receipts. Exercises all four services.

    Depends on ``activated_permissive_constitution`` (F11d) — F10's
    SendEnvelope gate refuses every call until an operator activates
    a constitution. The fixture does that once per session against the
    same control plane this test connects to."""
    signing_key, agent_id, swarm_id = bootstrap_identity

    async with yutha.YuthaClient.connect(
        address,
        agent_id=agent_id,
        swarm_id=swarm_id,
        signing_key=signing_key,
    ) as client:
        # ---------------------------------------------------------------
        # 1. Issue a capability scoped to envelope.send.
        # ---------------------------------------------------------------
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
        cap_id, issuance_receipt_id = await client.capability.issue(cap)
        assert cap_id.algorithm == yutha.HashAlgorithm.SHA256
        assert len(cap_id.digest) == 32
        assert len(issuance_receipt_id.digest) == 32

        # ---------------------------------------------------------------
        # 2. Start the subscribe stream BEFORE sending so the server has
        #    the inbox registered when send arrives. MemoryTransport's
        #    subscribe() idempotently registers; we just need to give
        #    its forwarder task a tick to spin up.
        # ---------------------------------------------------------------
        received: list[tuple[yutha.Envelope, yutha.Hash]] = []

        async def collect_one() -> None:
            async for env, deliver_receipt in client.envelope.subscribe():
                received.append((env, deliver_receipt))
                return

        subscribe_task = asyncio.create_task(collect_one())
        await asyncio.sleep(0.2)  # let server-side inbox registration land

        # ---------------------------------------------------------------
        # 3. Send a signed envelope addressed to self.
        # ---------------------------------------------------------------
        envelope = yutha.Envelope(
            spec_version="1.0.0",
            swarm_id=swarm_id,
            envelope_id=secrets.token_bytes(16),
            from_agent=agent_id,
            recipient=yutha.Recipient.for_agent(agent_id),
            performative=yutha.Performative.INFORM,
            payload=b"hello from the python integration test",
            payload_schema_id="type.yutha.dev/v1/Text",
            tags=["integration", "self-test"],
            nonce=secrets.token_bytes(16),
            epoch=1,
            sent_at=yutha.Timestamp.now(),
        ).sign(signing_key)
        # Thread the cap issued in step 1 through send — required when
        # the server has `topology.require_capability_for_send=true`
        # (E1 / RFC 0007). The pre-E1 shape of this test omitted
        # capability_id; the post-E1 server rejects with
        # INVALID_ARGUMENT until we pass it explicitly.
        send_receipt_id = await client.envelope.send(envelope, capability_id=cap_id)
        assert len(send_receipt_id.digest) == 32

        # ---------------------------------------------------------------
        # 4. Wait for the subscribe stream to surface the envelope.
        # ---------------------------------------------------------------
        await asyncio.wait_for(subscribe_task, timeout=3.0)
        assert len(received) == 1, "expected exactly one envelope on the stream"
        delivered, deliver_receipt_id = received[0]
        assert delivered.payload == b"hello from the python integration test"
        assert delivered.from_agent == agent_id
        assert delivered.envelope_id == envelope.envelope_id
        assert len(deliver_receipt_id.digest) == 32

        # ---------------------------------------------------------------
        # 5. Round-trip the send receipt by content-address. The
        #    Receipt's action_kind should be "envelope.send".
        # ---------------------------------------------------------------
        send_receipt = await client.receipt.get(send_receipt_id)
        assert send_receipt is not None
        assert send_receipt.action_kind == "envelope.send"
        assert send_receipt.actor != agent_id, (
            "envelope.send receipts are signed by the control plane, "
            "not the sender; actor should be the cp identity"
        )

        # ---------------------------------------------------------------
        # 6. Audit-trail query: every action_kind we just exercised
        #    must surface at least one matching receipt.
        # ---------------------------------------------------------------
        for action_kind in (
            "capability.issue",
            "envelope.send",
            "envelope.deliver",
        ):
            receipts, _ = await client.receipt.query_by_action_kind(action_kind)
            assert receipts, f"no {action_kind} receipts in the audit log"


@pytest.mark.asyncio
async def test_send_to_role_recipient_passes_constitution_eval(
    bootstrap_identity: tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId],
    address: str,
    activated_permissive_constitution: object,  # fixture has side-effects only
) -> None:
    """Regression test for the schema-widening fix.

    Pre-fix, the gRPC handler synthesized a ``Yutha::Resource`` UID as
    the eval-request resource for non-Agent recipients, but the
    canonical v1.1 schema's ``SendEnvelope.appliesTo.resource`` only
    listed ``[Agent, Envelope]``. Cedar's Strict-mode request
    validation rejected the request and the handler returned
    ``INTERNAL: constitution eval: entity unresolved: ...``.

    Post-fix: schema widened to ``[Agent, Envelope, Resource]`` AND the
    handler adds the synthesized Resource entity to the snapshot with
    the schema-required attrs. A Role recipient now passes Cedar
    request validation; the permissive constitution's permit-all rule
    fires; the send succeeds.

    We send with capability_id omitted — the topology in this test
    pipeline accepts sends without a cap (closed-mode bootstrap path)
    so the resource-shape failure shows up cleanly without other
    error paths in the way.
    """
    signing_key, agent_id, swarm_id = bootstrap_identity
    # Self-issue a cap permitting envelope.send for the role-recipient
    # case. Required when the server enforces require_capability_for_send
    # (closed mode); harmless otherwise.
    async with yutha.YuthaClient.connect(
        address,
        agent_id=agent_id,
        swarm_id=swarm_id,
        signing_key=signing_key,
    ) as client:
        cap = yutha.Capability(
            spec_version="1.0.0",
            capability_id=secrets.token_bytes(16),
            swarm_id=swarm_id,
            issuer=yutha.Issuer.for_agent(agent_id),
            subject=agent_id,
            scope=yutha.Scope.for_action("envelope.send"),
            valid_from=yutha.Timestamp.now(),
            valid_until=yutha.Timestamp(
                wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62
            ),
        )
        cap_id, _ = await client.capability.issue(cap)

        envelope = yutha.Envelope(
            spec_version="1.0.0",
            swarm_id=swarm_id,
            envelope_id=secrets.token_bytes(16),
            from_agent=agent_id,
            recipient=yutha.Recipient.for_role("billing"),
            performative=yutha.Performative.INFORM,
            payload=b"role-recipient regression check",
            payload_schema_id="type.yutha.dev/v1/Text",
            nonce=secrets.token_bytes(16),
            epoch=1,
            sent_at=yutha.Timestamp.now(),
        ).sign(signing_key)

        # Three legal outcomes — the fix is asserted by the ABSENCE of
        # the pre-fix Cedar-shape error:
        #   1. The send succeeds (the in-memory transport learned to
        #      handle role broadcasts).
        #   2. The send fails with "Role broadcast not implemented"
        #      (the current MemoryTransport state — known limitation
        #      downstream of the constitution gate; out of scope here).
        #   3. The send fails with a constitution-eval error
        #      (pre-fix; the regression).
        #
        # Outcome 3 is what we're catching. Outcomes 1 and 2 both pass.
        try:
            receipt_id = await client.envelope.send(envelope, capability_id=cap_id)
            # Outcome 1: send succeeded end-to-end.
            assert len(receipt_id.digest) == 32
        except grpc.aio.AioRpcError as e:
            details = e.details() or ""
            # Outcome 3 (regression) — fail loudly.
            assert "constitution eval" not in details, (
                f"role recipient still tripping the constitution-eval gate: {details}"
            )
            assert "entity unresolved" not in details, (
                f"role recipient still tripping Cedar's entity-resolution check: {details}"
            )
            # Outcome 2 — known-downstream transport limitation. Any
            # other message is unexpected and worth surfacing.
            assert "Role broadcast not implemented" in details, (
                f"unexpected error past the constitution gate: {details}"
            )


@pytest.mark.asyncio
async def test_get_receipt_returns_none_for_unknown_id(
    bootstrap_identity: tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId],
    address: str,
) -> None:
    """The ReceiptAPI.get NOT_FOUND → None translation, against the
    live server. Verifies the gRPC error-code mapping in
    ``client.py::ReceiptAPI.get`` works end-to-end."""
    signing_key, agent_id, swarm_id = bootstrap_identity

    async with yutha.YuthaClient.connect(
        address,
        agent_id=agent_id,
        swarm_id=swarm_id,
        signing_key=signing_key,
    ) as client:
        unknown = yutha.Hash(
            algorithm=yutha.HashAlgorithm.SHA256,
            digest=b"\x00" * 32,
        )
        result = await client.receipt.get(unknown)
        assert result is None

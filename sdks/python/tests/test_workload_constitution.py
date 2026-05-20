"""Integration test for workload-schema-extension constitutions
activated via gRPC.

Python parallel to the Rust F14 + S5 path. Authors a constitution
that references the `Yutha::SupportQueue` workload namespace, sends
it through ``ConstitutionService.Activate``, and verifies the server
accepts + serves it. This validates the full chain:

  client → ConstitutionAPI.activate
        → server cedar-plus loader runs with the workload-extension
          schema source loaded at startup
        → Cedar Validator accepts the cross-namespace policy
        → constitution.activate receipt lands
        → get_active returns the same artifact

The test depends on the control plane having been started with
``--workload support-queue`` so the server-side Cedar Validator
recognizes the namespace. Without that flag the server returns
``INVALID_ARGUMENT`` and the test skips with a pointer.

Env-var contract identical to the other integration tests:
``YUTHA_BOOTSTRAP_SEED`` + a server with ``--operator-public-key``
matching the seed-derived operator pubkey.
"""

from __future__ import annotations

import hashlib
import os

import grpc
import pytest

import yutha
from yutha.testing import support_queue_refund_cap_constitution

pytestmark = pytest.mark.integration


def _derive_identity(
    seed: bytes,
) -> tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId]:
    signing_key = yutha.SigningKey.from_seed_bytes(seed)
    agent_id_bytes = hashlib.sha256(seed + b"\x01").digest()[:16]
    swarm_id_bytes = hashlib.sha256(seed + b"\x02").digest()[:16]
    return (
        signing_key,
        yutha.AgentId(value=agent_id_bytes),
        yutha.SwarmId(value=swarm_id_bytes),
    )


def _derive_operator_keypair(
    seed: bytes,
) -> tuple[yutha.SigningKey, yutha.PublicKey]:
    op_seed = hashlib.sha256(seed + b"\x03").digest()
    signing = yutha.SigningKey.from_seed_bytes(op_seed)
    return signing, signing.public_key()


@pytest.fixture
def bootstrap_identity() -> tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId]:
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


@pytest.mark.asyncio
async def test_support_queue_workload_constitution_activates_via_grpc(
    bootstrap_identity: tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId],
    seed_bytes: bytes,
    address: str,
) -> None:
    """Activate the F14 support-queue refund-cap constitution + read
    it back via ``get_active``. The test asserts the constitution
    survives proto round-trip and that the server returned a valid
    activate-receipt id."""
    _, _, swarm_id = bootstrap_identity
    operator_signing_key, _ = _derive_operator_keypair(seed_bytes)
    constitution = support_queue_refund_cap_constitution(swarm_id)

    # --- Activate via operator-bearer client ---
    op_client = yutha.YuthaClient.connect_as_operator(
        address,
        operator_id="yutha-test:workload-constitution",
        swarm_id=swarm_id,
        operator_signing_key=operator_signing_key,
    )
    try:
        try:
            activated = await op_client.constitution.activate(constitution)
        except grpc.aio.AioRpcError as e:
            details = e.details() or ""
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                pytest.skip(f"control plane not reachable at {address}")
            if e.code() == grpc.StatusCode.FAILED_PRECONDITION:
                pytest.skip(
                    f"server at {address} returned FAILED_PRECONDITION: {details}. "
                    "Start with --operator-public-key matching the seed-derived "
                    "operator pubkey."
                )
            # The most informative failure for this test is the server
            # complaining about the workload namespace — surface a
            # specific skip with the fix.
            if e.code() == grpc.StatusCode.INVALID_ARGUMENT and "SupportQueue" in details:
                pytest.skip(
                    f"server at {address} doesn't recognize the SupportQueue "
                    f"namespace: {details}. Start the control plane with "
                    "`--workload support-queue` so the workload-schema "
                    "extension loads at startup."
                )
            raise
        assert len(activated.constitution_hash.digest) == 32
        assert len(activated.activate_receipt.digest) == 32
    finally:
        await op_client.close()

    # --- Read back via agent-bearer client ---
    signing_key, agent_id, _ = bootstrap_identity
    async with yutha.YuthaClient.connect(
        address,
        agent_id=agent_id,
        swarm_id=swarm_id,
        signing_key=signing_key,
    ) as client:
        active = await client.constitution.get_active()
    assert active is not None
    assert active.constitution_hash == activated.constitution_hash
    # Cedar source is preserved verbatim through the server's
    # storage path (unlike engine_config_yaml, which the server
    # re-emits via serde_yaml). The forbid-rule sentinel survives.
    assert "refund-cap-requires-supervisor" in active.constitution.cedar_source

"""Integration tests for ``ConstitutionAPI`` + the F11d activation fixture.

These exercise the constitution-layer plumbing end-to-end against a
running control plane. Same env-var contract as
``test_integration.py``:

  * ``YUTHA_BOOTSTRAP_SEED`` — 32 hex bytes shared with the server.
  * ``YUTHA_GRPC_ADDR`` (default ``127.0.0.1:50051``) — server bind.
  * The control plane MUST have been started with
    ``--operator-public-key`` matching the seed-derived operator
    pubkey, otherwise ``Activate`` returns ``FAILED_PRECONDITION``
    and the fixture skips.

To run::

    cd sdks/python
    YUTHA_BOOTSTRAP_SEED=<64 hex chars> pytest -m integration \
        tests/test_constitution_integration.py -v
"""

from __future__ import annotations

import hashlib
import os
from typing import TYPE_CHECKING

import pytest

import yutha

if TYPE_CHECKING:
    # Conftest exposes the F11d session fixture's return type. Imported
    # under TYPE_CHECKING because pytest's conftest-discovery puts
    # ``conftest`` on the sys.path only at test-collection time —
    # importing it at module-load time would fail under tools that
    # parse the file outside pytest (e.g. ruff's import sorter).
    from conftest import ActivatedConstitutionFixture

pytestmark = pytest.mark.integration


# =============================================================================
# Fixture for an agent-bearer client (for GetActive, which is agent-auth)
# =============================================================================
#
# The activation fixture itself uses an operator-bearer client (Activate
# is operator-only). GetActive is agent-bearer, so this test module
# needs a separate client built from the bootstrap agent's seed-derived
# identity. Mirror the helper from test_integration.py.


def _derive_identity(seed: bytes) -> tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId]:
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
    seed_hex = os.environ.get("YUTHA_BOOTSTRAP_SEED")
    if not seed_hex:
        pytest.skip("set YUTHA_BOOTSTRAP_SEED")
    return _derive_identity(bytes.fromhex(seed_hex.strip()))


@pytest.fixture
def address() -> str:
    return (
        os.environ.get("YUTHA_GRPC_ADDR")
        or os.environ.get("YUTHA_GRPC_ADDR_OPEN")
        or "127.0.0.1:50051"
    )


# =============================================================================
# Tests
# =============================================================================


@pytest.mark.asyncio
async def test_fixture_returns_well_formed_activation(
    activated_permissive_constitution: ActivatedConstitutionFixture,
) -> None:
    """The fixture's smallest contract: after activation, the returned
    hashes are 32-byte SHA-256 digests. Catches "did the activation
    actually happen" without poking the server."""
    fixture = activated_permissive_constitution
    activated = fixture.activated
    # `activated` is yutha.ActivatedConstitution; using a duck-typed
    # check rather than isinstance to avoid the runtime import dance
    # in the conftest type annotations.
    assert len(activated.constitution_hash.digest) == 32
    assert len(activated.activate_receipt.digest) == 32
    # And the constitution itself matches what the fixture handed in.
    assert fixture.constitution.cedar_source.startswith("permit")


@pytest.mark.asyncio
async def test_get_active_returns_what_we_activated(
    activated_permissive_constitution: ActivatedConstitutionFixture,
    bootstrap_identity: tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId],
    address: str,
) -> None:
    """An agent-bearer client calling ``get_active`` immediately after
    the fixture activates should see the same constitution come back.
    Verifies the round-trip of activate → read on the server side."""
    signing_key, agent_id, swarm_id = bootstrap_identity
    expected_hash = activated_permissive_constitution.activated.constitution_hash

    async with yutha.YuthaClient.connect(
        address,
        agent_id=agent_id,
        swarm_id=swarm_id,
        signing_key=signing_key,
    ) as client:
        active = await client.constitution.get_active()

    assert active is not None, (
        "get_active returned None even though the fixture just activated. "
        "Did another test session reset the server state mid-run?"
    )
    # The control plane returns the activate-time content-address; the
    # client compares against the hash the activate call returned.
    assert active.constitution_hash == expected_hash

    # Field-by-field equality on the constitution body. We deliberately
    # do NOT assert full-model equality: the server stores the parsed
    # EngineConfig and re-emits YAML on get_active via
    # `serde_yaml::to_string(&engine_config)`, which doesn't preserve
    # the original byte form (no quotes around "1.1.0", BTreeMap key
    # order, etc.). The semantic content round-trips; the literal YAML
    # bytes do not. Hash equality (above) is the load-bearing check
    # that the activate-time canonical bytes match.
    original = activated_permissive_constitution.constitution
    assert active.constitution.spec_version == original.spec_version
    assert active.constitution.schema_version == original.schema_version
    assert active.constitution.constitution_version == original.constitution_version
    assert active.constitution.parent_version == original.parent_version
    assert active.constitution.swarm_id == original.swarm_id
    assert active.constitution.cedar_source == original.cedar_source
    assert active.constitution.issued_at == original.issued_at


@pytest.mark.asyncio
async def test_activate_receipt_is_queryable(
    activated_permissive_constitution: ActivatedConstitutionFixture,
    bootstrap_identity: tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId],
    address: str,
) -> None:
    """The activate-receipt id the server returned must resolve via
    ``ReceiptAPI.get`` to a real ``constitution.activate`` receipt.
    Verifies the activate path emits the audit-trail anchor F10c
    promises."""
    signing_key, agent_id, swarm_id = bootstrap_identity
    activate_receipt = activated_permissive_constitution.activated.activate_receipt

    async with yutha.YuthaClient.connect(
        address,
        agent_id=agent_id,
        swarm_id=swarm_id,
        signing_key=signing_key,
    ) as client:
        receipt = await client.receipt.get(activate_receipt)

    assert receipt is not None, (
        f"activate_receipt id {activate_receipt.digest.hex()} resolved to None — "
        "the server reported a receipt id that doesn't exist in its store."
    )
    assert receipt.action_kind == "constitution.activate"

"""pytest configuration shim.

When pytest is invoked from the repo root rather than from
``sdks/python/``, its ``rootdir`` resolves to the repo root and the
``[tool.pytest.ini_options]`` block in ``sdks/python/pyproject.toml``
isn't picked up. That's harmless — tests still run — but it causes a
``PytestUnknownMarkWarning`` for the ``integration`` marker.

This file lives at ``sdks/python/conftest.py`` so pytest discovers it
on the way down from the repo root and registers the marker before
collection.

Also home to the shared :func:`activated_permissive_constitution`
session-scoped fixture (F11d). Any integration test that wants to
exercise ``EnvelopeService.Send`` past the F10 constitution gate
should depend on it.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import grpc
import pytest

if TYPE_CHECKING:
    # Type-only imports — kept out of the runtime path so this
    # conftest stays loadable when pytest's collection sweep runs
    # over the broader repo (the package may not be installed in
    # every interpreter pytest spawns).
    import yutha

# Make example scripts under sdks/python/examples/ importable from
# tests/ so the S1 LangGraph demo can be re-used as an integration
# test without duplicating its body. The directory is a sibling of
# both tests/ and src/.
_EXAMPLES_DIR = Path(__file__).parent / "examples"
if _EXAMPLES_DIR.is_dir() and str(_EXAMPLES_DIR) not in sys.path:
    sys.path.insert(0, str(_EXAMPLES_DIR))

# LangGraph 0.2/0.3 fires a LangChainPendingDeprecationWarning at
# import time inside langgraph.checkpoint.base, regardless of whether
# we use checkpointing. The same suppression lives in
# ``pyproject.toml::[tool.pytest.ini_options].filterwarnings``, but
# pytest's chain applies that filter LATE — after the warning has
# already been recorded. Registering it directly with the warnings
# module at conftest-load time catches the warning at its source.
warnings.filterwarnings(
    "ignore",
    message=r"The default value of `allowed_objects`.*",
    category=PendingDeprecationWarning,
)


def pytest_configure(config) -> None:  # type: ignore[no-untyped-def]
    config.addinivalue_line(
        "markers",
        "integration: tests that require a running yutha control plane "
        "(skipped by default; set YUTHA_BOOTSTRAP_SEED to run)",
    )


# =============================================================================
# F11d: shared constitution-activation fixture
# =============================================================================
#
# After F10, EnvelopeService.Send refuses every call until an operator
# activates a constitution. All four send-using integration tests
# (test_integration::test_full_lifecycle, test_langgraph_agent's two
# send-path tests, test_s1_support_queue_demo) need the same setup:
# derive the operator key from YUTHA_BOOTSTRAP_SEED, connect as
# operator, activate a permissive constitution. The fixture below
# does it once per pytest session and hands the result to whichever
# tests opt in.
#
# The seed-to-operator-key derivation matches
# `tests/test_operator_revoke.py::_derive_operator_keypair` —
# `sha256(seed || 0x03)`. Centralizing here would require breaking
# circular imports between conftest and that test module; for now,
# we duplicate the 3-line helper. If a third caller appears, factor
# both into a shared `tests/_helpers.py`.

_INTEGRATION_SEED_VAR = "YUTHA_BOOTSTRAP_SEED"
_INTEGRATION_ADDR_VAR = "YUTHA_GRPC_ADDR"
_INTEGRATION_OPEN_ADDR_VAR = "YUTHA_GRPC_ADDR_OPEN"


@dataclass(frozen=True)
class ActivatedConstitutionFixture:
    """Both halves of the F11d activation fixture's output.

    Tests can either ignore the contents (they just want the gate
    open) or assert on the receipt / hash for audit-trail checks.

    Fields are typed through the ``TYPE_CHECKING`` import above so
    mypy can resolve attribute access on them without forcing a
    runtime import of the SDK at module-load time.
    """

    constitution: "yutha.Constitution"
    activated: "yutha.ActivatedConstitution"


def _derive_swarm_id_from_seed(seed: bytes) -> "yutha.SwarmId":
    """Same derivation as ``test_integration._derive_identity_from_seed``
    and the Rust ``BootstrapIdentity::from_seed_hex``. Returns
    :class:`yutha.SwarmId`."""
    import yutha

    return yutha.SwarmId(value=hashlib.sha256(seed + b"\x02").digest()[:16])


def _derive_operator_keypair_from_seed(
    seed: bytes,
) -> tuple["yutha.SigningKey", "yutha.PublicKey"]:
    """Same derivation as
    ``tests/test_operator_revoke._derive_operator_keypair``. Returns
    (SigningKey, PublicKey)."""
    import yutha

    op_seed = hashlib.sha256(seed + b"\x03").digest()
    signing = yutha.SigningKey.from_seed_bytes(op_seed)
    return signing, signing.public_key()


async def _activate_permissive_constitution(
    addr: str, seed: bytes
) -> ActivatedConstitutionFixture:
    """Connect as operator, build + activate a permissive constitution.

    Surfaces the two failure modes that tend to confuse contributors
    as ``pytest.skip``s with actionable messages:
      * gRPC ``UNAVAILABLE`` → no server reachable on ``addr``.
      * gRPC ``FAILED_PRECONDITION`` on Activate → the server is
        running but wasn't started with ``--operator-public-key``
        matching the seed-derived operator pubkey.
    """
    import yutha
    from yutha.testing import permissive_constitution

    swarm_id = _derive_swarm_id_from_seed(seed)
    operator_signing_key, _ = _derive_operator_keypair_from_seed(seed)
    constitution = permissive_constitution(swarm_id)

    client = yutha.YuthaClient.connect_as_operator(
        addr,
        operator_id="yutha-test:permissive-constitution-fixture",
        swarm_id=swarm_id,
        operator_signing_key=operator_signing_key,
    )
    try:
        try:
            activated = await client.constitution.activate(constitution)
        except grpc.aio.AioRpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                pytest.skip(
                    f"control plane not reachable at {addr}: {e.details()}. "
                    "Start the server (see test_integration.py module docstring)."
                )
            if e.code() == grpc.StatusCode.FAILED_PRECONDITION:
                # Most likely: --operator-public-key wasn't set at
                # server startup. The Rust side returns FAILED_PRECONDITION
                # with "operator credentials not enabled" in this case.
                pytest.skip(
                    f"server at {addr} returned FAILED_PRECONDITION on "
                    f"Activate: {e.details()}. Start the control plane "
                    "with --operator-public-key matching the seed-derived "
                    "operator pubkey (see test_operator_revoke module "
                    "docstring for the derivation)."
                )
            raise
    finally:
        await client.close()

    return ActivatedConstitutionFixture(constitution=constitution, activated=activated)


@pytest.fixture(scope="session")
def activated_permissive_constitution() -> ActivatedConstitutionFixture:
    """Session-scoped fixture: activate a permissive constitution against
    the running control plane.

    Depended-on by every integration test that needs the F10
    SendEnvelope gate open. Skips cleanly if:

      * ``YUTHA_BOOTSTRAP_SEED`` isn't set (no integration mode);
      * the seed isn't valid hex / wrong length;
      * the server at ``YUTHA_GRPC_ADDR`` (default ``127.0.0.1:50051``)
        isn't reachable;
      * the server wasn't started with ``--operator-public-key``.

    The address is read from ``YUTHA_GRPC_ADDR`` first; if unset,
    falls back to ``YUTHA_GRPC_ADDR_OPEN`` (some test modules use the
    open-mode variant), then to the default loopback port. Activating
    on one address activates on the single control-plane instance
    running there — there's no per-fixture-instance state.
    """
    seed_hex = os.environ.get(_INTEGRATION_SEED_VAR)
    if not seed_hex:
        pytest.skip(
            f"set {_INTEGRATION_SEED_VAR}=<64 hex chars> to run "
            "constitution-fixture-dependent integration tests"
        )
    try:
        seed = bytes.fromhex(seed_hex.strip())
    except ValueError:
        pytest.skip(f"{_INTEGRATION_SEED_VAR} is not valid hex")
    if len(seed) != 32:
        pytest.skip(
            f"{_INTEGRATION_SEED_VAR} must be exactly 64 hex chars "
            f"(32 bytes); got {len(seed)} bytes"
        )

    addr = (
        os.environ.get(_INTEGRATION_ADDR_VAR)
        or os.environ.get(_INTEGRATION_OPEN_ADDR_VAR)
        or "127.0.0.1:50051"
    )

    return asyncio.run(_activate_permissive_constitution(addr, seed))

"""Integration test wrapping the S1 customer-support queue demo.

Imports ``run_s1`` from the example script under
``sdks/python/examples/s1_support_queue.py`` (re-exposed onto
``sys.path`` by ``sdks/python/conftest.py``) and asserts the
audit-trail delta exactly matches :data:`EXPECTED_AUDIT_DELTA`.

Skipped unless BOTH env vars are set:

- ``YUTHA_GRPC_ADDR_OPEN`` — the open-mode server's host:port. A
  separate env var from the closed-mode one so the 3d/4b tests and
  this demo test can coexist without one accidentally clobbering the
  other's contract.
- ``YUTHA_BOOTSTRAP_SEED`` — 32-byte hex seed shared with the running
  control plane. The demo derives the registry's swarm_id from this
  (registry rejects cross-swarm passports; the seed is the simplest
  out-of-band way for client + server to agree).

To run::

    # Terminal A
    export YUTHA_BOOTSTRAP_SEED=$(python -c \
        'import secrets; print(secrets.token_hex(32))')
    cargo run -p yutha-control-plane -- --admission-mode open

    # Terminal B
    YUTHA_BOOTSTRAP_SEED=<same hex> \
    YUTHA_GRPC_ADDR_OPEN=127.0.0.1:50051 \
        pytest -m integration -q tests/test_s1_support_queue_demo.py
"""

from __future__ import annotations

import os

import pytest

INTEGRATION_OPEN_ADDR_VAR = "YUTHA_GRPC_ADDR_OPEN"
INTEGRATION_SEED_VAR = "YUTHA_BOOTSTRAP_SEED"

pytestmark = pytest.mark.integration


@pytest.fixture
def open_mode_addr() -> str:
    addr = os.environ.get(INTEGRATION_OPEN_ADDR_VAR)
    if not addr:
        pytest.skip(
            f"set {INTEGRATION_OPEN_ADDR_VAR}=<host:port> to run the S1 "
            "LangGraph demo (the control plane must be started with "
            "--admission-mode open; closed mode rejects fresh passports)"
        )
    if not os.environ.get(INTEGRATION_SEED_VAR):
        pytest.skip(
            f"set {INTEGRATION_SEED_VAR}=<64 hex chars> to run the S1 "
            "demo — the demo derives the swarm_id from this seed and "
            "the control plane must have been started with the same seed"
        )
    return addr


@pytest.mark.asyncio
async def test_s1_demo_audit_shape(open_mode_addr: str) -> None:
    """Run the demo end-to-end and verify the audit-trail delta exactly
    matches the documented expectations (5 registers, 4 send/deliver
    pairs, 1 issue + 3 check.pass + 1 check.deny + 1 cap-revoke, 1
    agent.revoke). Drift in either direction is a behavioral regression
    worth investigating."""
    # Importable thanks to the sys.path shim in conftest.py.
    from s1_support_queue import EXPECTED_AUDIT_DELTA, run_s1

    delta = await run_s1(server_addr=open_mode_addr)

    assert delta == EXPECTED_AUDIT_DELTA, (
        f"audit-trail delta mismatch\n  got:      {delta}\n  expected: {EXPECTED_AUDIT_DELTA}"
    )

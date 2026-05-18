"""Smoke tests for the Stage 3a scaffolding.

Once 3b/3c land, this file gets the higher-level "client constructs"
and "round-trip a token" tests. For now it just checks that the
package imports, the proto stubs load, and the codegen output is
in sync with the spec (the latter only when run in a tree that has
both ``yutha-`` Rust crates and the Python SDK side by side).
"""

from __future__ import annotations

import pytest


def test_package_imports() -> None:
    """`import yutha` succeeds and exposes the version."""
    import yutha

    assert yutha.__version__.startswith("0.1.0")


def test_proto_descriptors_load() -> None:
    """Every generated module imports cleanly and has at least one
    populated descriptor — the cheapest possible check that the
    codegen output isn't structurally broken."""
    from yutha._proto import common_pb2
    from yutha._proto.capability import capability_v1_pb2
    from yutha._proto.control_plane import v1_pb2 as cp_pb2
    from yutha._proto.envelope import envelope_v1_pb2
    from yutha._proto.passport import passport_v1_pb2
    from yutha._proto.receipt import receipt_v1_pb2
    from yutha._proto.topology import topology_v1_pb2

    # The common module must define our identifier types.
    assert hasattr(common_pb2, "AgentId")
    assert hasattr(common_pb2, "Hash")
    assert hasattr(common_pb2, "Signature")

    # Spot-check each top-level message we'll need from each module.
    assert hasattr(passport_v1_pb2, "Passport")
    assert hasattr(envelope_v1_pb2, "Envelope")
    assert hasattr(receipt_v1_pb2, "Receipt")
    assert hasattr(capability_v1_pb2, "Capability")
    assert hasattr(topology_v1_pb2, "Topology")
    assert hasattr(cp_pb2, "AgentBearerToken")
    assert hasattr(cp_pb2, "RegisterRequest")


def test_grpc_stubs_load() -> None:
    """The five service stubs are importable. ``ConstitutionServiceStub``
    arrived in F10a; check explicitly so a stale codegen doesn't slip
    through (the four other stubs predate it)."""
    from yutha._proto.control_plane import v1_pb2_grpc

    assert hasattr(v1_pb2_grpc, "AdmissionServiceStub")
    assert hasattr(v1_pb2_grpc, "CapabilityServiceStub")
    assert hasattr(v1_pb2_grpc, "ConstitutionServiceStub")
    assert hasattr(v1_pb2_grpc, "EnvelopeServiceStub")
    assert hasattr(v1_pb2_grpc, "ReceiptServiceStub")


@pytest.mark.asyncio
async def test_yuthaclient_exposes_five_service_apis() -> None:
    """``YuthaClient`` attaches one API wrapper per service. We don't
    connect (no live server in unit-test land) — just construct a
    client over a no-op channel and check the attributes exist.

    ``grpc.aio.insecure_channel`` requires a running event loop at
    construction time, so this test is async; pytest-asyncio's AUTO
    mode in ``pyproject.toml`` provides the loop."""
    import grpc

    import yutha

    channel = grpc.aio.insecure_channel("localhost:0")
    try:
        session = yutha.BearerSession(
            agent_id=yutha.AgentId.new(),
            swarm_id=yutha.SwarmId.new(),
            signing_key=yutha.SigningKey.generate(),
        )
        client = yutha.YuthaClient(channel, session)
        assert isinstance(client.admission, yutha.AdmissionAPI)
        assert isinstance(client.capability, yutha.CapabilityAPI)
        assert isinstance(client.constitution, yutha.ConstitutionAPI)
        assert isinstance(client.envelope, yutha.EnvelopeAPI)
        assert isinstance(client.receipt, yutha.ReceiptAPI)
    finally:
        await channel.close()

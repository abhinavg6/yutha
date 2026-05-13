"""Unit tests for the bearer-token minting path.

These tests don't touch the network — they construct a
:class:`BearerSession` with a known key, mint a token, hex-decode it
back into the proto, and verify the signature against the canonical
bytes the way the Rust server (``yutha-control-plane/src/auth.rs``)
will. If the Python side produces a token that doesn't satisfy the
Rust verifier, this test will catch it before the wire ever runs.
"""

from __future__ import annotations

import asyncio

import pytest

import yutha
from yutha._proto.control_plane import v1_pb2 as cp_pb2
from yutha.auth import BearerSession, _has_no_auth_sentinel, skip_auth_metadata
from yutha.canonical import canonical_bytes


def _new_session(
    *,
    token_lifetime_seconds: int = 300,
    refresh_lead_seconds: int = 30,
) -> tuple[BearerSession, yutha.SigningKey, yutha.AgentId, yutha.SwarmId]:
    key = yutha.SigningKey.generate()
    agent_id = yutha.AgentId.new()
    swarm_id = yutha.SwarmId.new()
    session = BearerSession(
        agent_id=agent_id,
        swarm_id=swarm_id,
        signing_key=key,
        token_lifetime_seconds=token_lifetime_seconds,
        refresh_lead_seconds=refresh_lead_seconds,
    )
    return session, key, agent_id, swarm_id


@pytest.mark.asyncio
async def test_session_mints_well_formed_header() -> None:
    session, _key, _agent_id, _swarm_id = _new_session()
    header = await session.header_value()
    assert header.startswith("bearer ")
    # The hex portion decodes to a valid AgentBearerToken proto.
    hex_part = header.removeprefix("bearer ")
    bytes_ = bytes.fromhex(hex_part)
    token = cp_pb2.AgentBearerToken()
    token.ParseFromString(bytes_)
    assert token.HasField("agent_id")
    assert token.HasField("swarm_id")
    assert token.HasField("issued_at")
    assert token.HasField("expires_at")
    assert token.HasField("signature")
    assert len(token.nonce) == 16


@pytest.mark.asyncio
async def test_minted_token_signature_verifies_against_passport_key() -> None:
    """The signature the SDK attaches MUST be the same one the Rust
    server will reconstruct + verify: Ed25519 over canonical bytes
    (token with signature + extensions cleared)."""
    session, key, agent_id, swarm_id = _new_session()
    header = await session.header_value()
    bytes_ = bytes.fromhex(header.removeprefix("bearer "))
    token = cp_pb2.AgentBearerToken()
    token.ParseFromString(bytes_)

    # Decoded fields match the session's identity.
    assert bytes(token.agent_id.value) == agent_id.value
    assert bytes(token.swarm_id.value) == swarm_id.value

    # Reconstruct canonical bytes the same way the server does.
    signature_bytes = bytes(token.signature.value)
    canonical = cp_pb2.AgentBearerToken()
    canonical.CopyFrom(token)
    canonical.ClearField("signature")
    canonical.ClearField("extensions")
    canonical_wire = canonical_bytes(canonical)

    sig = yutha.Signature.from_proto(token.signature)
    yutha.verify(key.public_key(), canonical_wire, sig)
    # And the signature bytes match what `cryptography` would produce
    # — sanity check against the wire payload.
    assert len(signature_bytes) == 64


@pytest.mark.asyncio
async def test_session_caches_until_refresh_window() -> None:
    """Two back-to-back calls share the same minted token — until the
    refresh window kicks in."""
    session, *_ = _new_session(token_lifetime_seconds=300, refresh_lead_seconds=30)
    a = await session.header_value()
    b = await session.header_value()
    assert a == b


@pytest.mark.asyncio
async def test_session_remints_when_close_to_expiry() -> None:
    """Use a tight lifetime + lead-time so two mints actually happen
    within the test's wall-clock budget."""
    session, *_ = _new_session(token_lifetime_seconds=2, refresh_lead_seconds=1)
    a = await session.header_value()
    # Wait past the refresh threshold (1s lead-time on a 2s token —
    # remint when <1s remaining ⇒ wait >1s).
    await asyncio.sleep(1.2)
    b = await session.header_value()
    assert a != b, "session should have re-minted after the refresh window"


@pytest.mark.asyncio
async def test_session_concurrent_callers_serialize_one_renewal() -> None:
    """Many concurrent ``header_value()`` calls during a renewal
    should produce a single mint — the lock funnels them through."""
    session, *_ = _new_session(token_lifetime_seconds=300, refresh_lead_seconds=30)
    # Force a renewal by clobbering the cache.
    session._cache = None
    results = await asyncio.gather(*(session.header_value() for _ in range(8)))
    assert len(set(results)) == 1, "all concurrent callers should see the same token"


@pytest.mark.asyncio
async def test_session_rejects_bad_refresh_window() -> None:
    with pytest.raises(ValueError, match="smaller than token_lifetime"):
        BearerSession(
            agent_id=yutha.AgentId.new(),
            swarm_id=yutha.SwarmId.new(),
            signing_key=yutha.SigningKey.generate(),
            token_lifetime_seconds=60,
            refresh_lead_seconds=120,
        )


def test_skip_auth_metadata_round_trips_through_helpers() -> None:
    """The ``yutha-no-auth`` sentinel survives metadata-list round
    trips and is detected by the interceptor."""
    from grpc.aio import ClientCallDetails, Metadata

    md = skip_auth_metadata()
    assert md == [("yutha-no-auth", "1")]

    details = ClientCallDetails(
        method="/x/y",
        timeout=None,
        metadata=Metadata(*md),
        credentials=None,
        wait_for_ready=None,
    )
    assert _has_no_auth_sentinel(details)


def test_no_auth_sentinel_absent_returns_false() -> None:
    from grpc.aio import ClientCallDetails, Metadata

    details = ClientCallDetails(
        method="/x/y",
        timeout=None,
        metadata=Metadata(("other-key", "value")),
        credentials=None,
        wait_for_ready=None,
    )
    assert not _has_no_auth_sentinel(details)

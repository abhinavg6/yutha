"""Round-trip + sign/verify tests for the Pydantic models."""

from __future__ import annotations

from collections.abc import Callable

import pytest

import yutha

# -----------------------------------------------------------------------------
# Passport
# -----------------------------------------------------------------------------


def _build_passport(key: yutha.SigningKey | None = None) -> yutha.Passport:
    key = key or yutha.SigningKey.generate()
    return yutha.Passport(
        spec_version="1.0.0",
        agent_id=yutha.AgentId.new(),
        swarm_id=yutha.SwarmId.new(),
        agent_public_key=key.public_key(),
        owner="test-owner",
        framework="langgraph",
        framework_version="0.2.0",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
    )


def test_passport_round_trip_through_proto() -> None:
    original = _build_passport()
    p = original.to_proto()
    back = yutha.Passport.from_proto(p)
    assert back == original


def test_passport_sign_and_verify() -> None:
    key = yutha.SigningKey.generate()
    passport = _build_passport(key).sign(key)
    assert passport.agent_signature is not None
    passport.verify_self_signature()  # raises on failure


def test_passport_sign_rejects_wrong_key() -> None:
    k1 = yutha.SigningKey.generate()
    k2 = yutha.SigningKey.generate()
    passport = _build_passport(k1)
    with pytest.raises(ValueError, match="signing key does not match"):
        passport.sign(k2)


def test_passport_tampered_payload_fails_verification() -> None:
    key = yutha.SigningKey.generate()
    signed = _build_passport(key).sign(key)
    tampered = signed.model_copy(update={"owner": "evil"})
    with pytest.raises(yutha.VerificationFailed):
        tampered.verify_self_signature()


def test_passport_with_capabilities_and_resources_round_trips() -> None:
    key = yutha.SigningKey.generate()
    original = yutha.Passport(
        spec_version="1.0.0",
        agent_id=yutha.AgentId.new(),
        swarm_id=yutha.SwarmId.new(),
        agent_public_key=key.public_key(),
        capabilities=[
            yutha.CapabilityDeclaration(
                kind="issue_refund",
                resource_tags=["finance"],
                bounds={"usd_max": "500.00"},
                description="customer support refunds",
            )
        ],
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.STANDARD,
        resources=yutha.ResourceDeclaration(
            max_concurrent_actions=4,
            max_messages_per_minute=120,
            max_usd_per_day_cents="100.00",
        ),
        issued_at=yutha.Timestamp.now(),
        expires_at=yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62),
    ).sign(key)
    back = yutha.Passport.from_proto(original.to_proto())
    assert back == original
    back.verify_self_signature()


# -----------------------------------------------------------------------------
# Envelope
# -----------------------------------------------------------------------------


def _build_envelope(key: yutha.SigningKey, sender: yutha.AgentId) -> yutha.Envelope:
    return yutha.Envelope(
        spec_version="1.0.0",
        swarm_id=yutha.SwarmId.new(),
        envelope_id=b"\x01" * 16,
        from_agent=sender,
        recipient=yutha.Recipient.for_agent(yutha.AgentId.new()),
        performative=yutha.Performative.INFORM,
        payload=b"hello",
        payload_schema_id="type.yutha.dev/v1/Text",
        tags=["test"],
        nonce=b"\x02" * 16,
        epoch=1,
        sent_at=yutha.Timestamp.now(),
    )


def test_envelope_round_trip_through_proto() -> None:
    key = yutha.SigningKey.generate()
    sender = yutha.AgentId.new()
    original = _build_envelope(key, sender).sign(key)
    back = yutha.Envelope.from_proto(original.to_proto())
    assert back == original


def test_envelope_sign_and_verify() -> None:
    key = yutha.SigningKey.generate()
    sender = yutha.AgentId.new()
    env = _build_envelope(key, sender).sign(key)
    env.verify_signature(key.public_key())


def test_envelope_tampered_payload_fails_verification() -> None:
    key = yutha.SigningKey.generate()
    sender = yutha.AgentId.new()
    env = _build_envelope(key, sender).sign(key)
    tampered = env.model_copy(update={"payload": b"different"})
    with pytest.raises(yutha.VerificationFailed):
        tampered.verify_signature(key.public_key())


@pytest.mark.parametrize(
    "factory",
    [
        lambda: yutha.Recipient.for_agent(yutha.AgentId.new()),
        lambda: yutha.Recipient.for_role("supervisor"),
        lambda: yutha.Recipient.for_swarm(filter_tags=["billing"]),
        lambda: yutha.Recipient.for_external("https", "api.example.com", "/v1/invoke"),
    ],
    ids=["agent", "role", "swarm", "external"],
)
def test_recipient_round_trip_for_each_variant(
    factory: Callable[[], yutha.Recipient],
) -> None:
    r = factory()
    back = yutha.Recipient.from_proto(r.to_proto())
    assert back == r


def test_recipient_rejects_zero_or_multiple_variants() -> None:
    with pytest.raises(ValueError):
        yutha.Recipient()  # zero
    with pytest.raises(ValueError):
        yutha.Recipient(agent=yutha.AgentId.new(), role="supervisor")


# -----------------------------------------------------------------------------
# Capability
# -----------------------------------------------------------------------------


def _build_capability(key: yutha.SigningKey) -> yutha.Capability:
    return yutha.Capability(
        spec_version="1.0.0",
        capability_id=b"\x03" * 16,
        swarm_id=yutha.SwarmId.new(),
        issuer=yutha.Issuer.for_agent(yutha.AgentId.new()),
        subject=yutha.AgentId.new(),
        scope=yutha.Scope.for_action("issue_refund"),
        valid_from=yutha.Timestamp.now(),
        valid_until=yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62),
        caveats=[
            yutha.Caveat(never_if_tagged=yutha.NeverIfTaggedCaveat(forbidden_tags=["external"]))
        ],
    )


def test_capability_round_trip_through_proto() -> None:
    key = yutha.SigningKey.generate()
    original = _build_capability(key).sign(key)
    back = yutha.Capability.from_proto(original.to_proto())
    # Compare fields individually — full-equality would require the
    # signature's key_fingerprint to round-trip, which it does, but
    # we also want to spot-check non-signature fields exactly.
    assert back.capability_id == original.capability_id
    assert back.subject == original.subject
    assert back.scope == original.scope
    assert back.caveats == original.caveats
    assert back.issuer_signature == original.issuer_signature


def test_capability_sign_and_verify() -> None:
    key = yutha.SigningKey.generate()
    cap = _build_capability(key).sign(key)
    cap.verify_signature(key.public_key())


def test_capability_tampered_scope_fails_verification() -> None:
    key = yutha.SigningKey.generate()
    cap = _build_capability(key).sign(key)
    tampered = cap.model_copy(update={"scope": yutha.Scope.for_action("different_action")})
    with pytest.raises(yutha.VerificationFailed):
        tampered.verify_signature(key.public_key())


@pytest.mark.parametrize(
    "caveat",
    [
        yutha.Caveat(time_of_day=yutha.TimeOfDayCaveat(from_utc="09:00", to_utc="17:00")),
        yutha.Caveat(
            constitution_version=yutha.ConstitutionVersionCaveat(
                min_version="1.0.0", max_version="1.5.0"
            )
        ),
        yutha.Caveat(constitution_version=yutha.ConstitutionVersionCaveat(min_version="1.0.0")),
        yutha.Caveat(
            supervisor_required=yutha.SupervisorRequiredCaveat(supervisor_role="approver")
        ),
        yutha.Caveat(rate_limit=yutha.RateLimitCaveat(max_actions=10, window_seconds=60)),
        yutha.Caveat(only_if_tagged=yutha.OnlyIfTaggedCaveat(required_tags=["pii"])),
        yutha.Caveat(never_if_tagged=yutha.NeverIfTaggedCaveat(forbidden_tags=["external"])),
    ],
    ids=["tod", "cv-with-max", "cv-no-max", "supervisor", "rate", "only", "never"],
)
def test_caveat_round_trip_for_each_variant(caveat: yutha.Caveat) -> None:
    back = yutha.Caveat.from_proto(caveat.to_proto())
    assert back == caveat


# -----------------------------------------------------------------------------
# Receipt
# -----------------------------------------------------------------------------


def test_receipt_round_trip_through_proto() -> None:
    original = yutha.Receipt(
        spec_version="1.0.0",
        swarm_id=yutha.SwarmId.new(),
        actor=yutha.AgentId.new(),
        action_kind="envelope.send",
        evidence=[
            yutha.Evidence(
                key="envelope_hash",
                type_url="type.yutha.dev/v1/Hash",
                value=b"\x04" * 32,
            )
        ],
        constitution_version="1.0.0",
        occurred_at=yutha.Timestamp.now(),
    )
    back = yutha.Receipt.from_proto(original.to_proto())
    assert back == original


def test_receipt_canonical_bytes_omit_signatures() -> None:
    """Adding a signature MUST NOT change canonical bytes (the same
    invariant the Rust side enforces)."""
    base = yutha.Receipt(
        spec_version="1.0.0",
        swarm_id=yutha.SwarmId.new(),
        actor=yutha.AgentId.new(),
        action_kind="envelope.send",
        constitution_version="1.0.0",
        occurred_at=yutha.Timestamp.now(),
    )
    bytes_a = base.canonical_bytes()

    signed = base.model_copy(
        update={
            "signatures": [
                yutha.SignedBy(
                    role=yutha.SignatureRole.ACTOR,
                    signature=yutha.Signature(
                        algorithm=yutha.SignatureAlgorithm.ED25519,
                        value=b"\x05" * 64,
                        key_fingerprint=b"\x06" * 32,
                    ),
                    signed_at=yutha.Timestamp.now(),
                )
            ]
        }
    )
    bytes_b = signed.canonical_bytes()
    assert bytes_a == bytes_b


# -----------------------------------------------------------------------------
# Constitution (F11a)
# -----------------------------------------------------------------------------


# A small valid Cedar policy + non-empty engine config. The Activate
# server rejects empty cedar_source per RFC 0010, but the model itself
# is free-form on these fields — the round-trip test should still
# exercise a non-trivial value to catch encoding regressions.
_CEDAR_PERMIT_ALL = "permit (principal, action, resource);"
_ENGINE_CONFIG_EMPTY = "scoring_rules: []\nprocedures: []\nenforcement_rules: []\n"


def _build_constitution(
    *,
    parent: yutha.Hash | None = None,
) -> yutha.Constitution:
    return yutha.Constitution(
        spec_version="1.0.0",
        schema_version="1.1.0",
        constitution_version="1.0.0",
        parent_version=parent,
        swarm_id=yutha.SwarmId.new(),
        cedar_source=_CEDAR_PERMIT_ALL,
        engine_config_yaml=_ENGINE_CONFIG_EMPTY,
        issued_at=yutha.Timestamp.now(),
    )


def test_constitution_round_trip_genesis() -> None:
    """Genesis constitution has no parent — the proto's parent_version
    field is left unset and from_proto must surface it as None."""
    original = _build_constitution()
    assert original.parent_version is None
    back = yutha.Constitution.from_proto(original.to_proto())
    assert back == original
    assert back.parent_version is None


def test_constitution_round_trip_amendment() -> None:
    """Amendment constitutions carry the parent's content-address; the
    proto must round-trip it byte-for-byte."""
    # A 32-byte SHA-256-shaped digest. We don't care what it actually
    # hashes — we just want a real Hash value that to_proto / from_proto
    # has to preserve.
    parent = yutha.Hash(
        algorithm=yutha.HashAlgorithm.SHA256,
        digest=b"\xab" * 32,
    )
    original = _build_constitution(parent=parent)
    back = yutha.Constitution.from_proto(original.to_proto())
    assert back == original
    assert back.parent_version == parent


def test_constitution_to_proto_omits_unset_parent_version() -> None:
    """When parent_version is None, the proto must NOT have the field
    set (callers downstream check HasField). This is the inverse of
    the from_proto genesis path."""
    proto = _build_constitution().to_proto()
    assert not proto.HasField("parent_version")


def test_constitution_to_proto_sets_parent_version_when_present() -> None:
    parent = yutha.Hash(
        algorithm=yutha.HashAlgorithm.SHA256,
        digest=b"\xcd" * 32,
    )
    proto = _build_constitution(parent=parent).to_proto()
    assert proto.HasField("parent_version")
    assert yutha.Hash.from_proto(proto.parent_version) == parent


def test_constitution_default_issued_at_is_now() -> None:
    """The model defaults issued_at to Timestamp.now() if the caller
    doesn't supply one. The default factory should fire at construction
    time, not module import time."""
    c1 = yutha.Constitution(
        spec_version="1.0.0",
        schema_version="1.1.0",
        constitution_version="1.0.0",
        swarm_id=yutha.SwarmId.new(),
        cedar_source=_CEDAR_PERMIT_ALL,
        engine_config_yaml=_ENGINE_CONFIG_EMPTY,
    )
    # Issued-at populated, RFC 3339 with a 'Z' suffix.
    assert c1.issued_at.wall_clock.endswith("Z")
    # Construct a second one; monotonic_ns must be strictly increasing
    # within the same process (this is what Timestamp.now() promises).
    c2 = yutha.Constitution(
        spec_version="1.0.0",
        schema_version="1.1.0",
        constitution_version="1.0.0",
        swarm_id=yutha.SwarmId.new(),
        cedar_source=_CEDAR_PERMIT_ALL,
        engine_config_yaml=_ENGINE_CONFIG_EMPTY,
    )
    assert c2.issued_at.monotonic_ns > c1.issued_at.monotonic_ns


def test_constitution_is_frozen() -> None:
    """Constitutions are immutable after construction (matches the
    other signed-blob models, which are all frozen). Pydantic v2
    raises ValidationError on frozen-model mutation."""
    import pydantic

    c = _build_constitution()
    with pytest.raises(pydantic.ValidationError):
        c.constitution_version = "2.0.0"

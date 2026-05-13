"""Cross-language canonical-bytes conformance.

For every JSON fixture under ``/spec/vectors/``, build a proto message
from the declared fields, run the canonical normalization
(clear ``signatures`` / ``seal`` / ``extensions``), serialize with
``deterministic=True``, and assert the hex matches the committed
``expected_canonical_hex``.

If any byte differs, this implementation is by definition
non-conformant — regardless of what the round-trip tests say.
``test_vectors.py`` is the load-bearing test for "the Python SDK can
produce wire bytes that the Rust control plane will accept."
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from yutha._proto import common_pb2
from yutha._proto.capability import capability_v1_pb2 as cap_proto
from yutha._proto.envelope import envelope_v1_pb2 as env_proto
from yutha._proto.passport import passport_v1_pb2 as passport_proto
from yutha._proto.receipt import receipt_v1_pb2 as receipt_proto

# /spec/vectors/ lives at the repo root, two levels up from sdks/python/.
VECTORS_ROOT = Path(__file__).resolve().parents[3] / "spec" / "vectors"


# =============================================================================
# Helpers — common.proto field builders
# =============================================================================


def _build_agent_id(hex_str: str) -> common_pb2.AgentId:
    return common_pb2.AgentId(value=bytes.fromhex(hex_str))


def _build_swarm_id(hex_str: str) -> common_pb2.SwarmId:
    return common_pb2.SwarmId(value=bytes.fromhex(hex_str))


def _build_hash(hex_str: str) -> common_pb2.Hash:
    # Vectors use raw SHA-256 digest hex (32 bytes = 64 chars).
    return common_pb2.Hash(
        algorithm=common_pb2.HASH_ALGORITHM_SHA256, digest=bytes.fromhex(hex_str)
    )


def _build_signature_algorithm(name: str) -> common_pb2.SignatureAlgorithm:
    if name == "ed25519":
        return common_pb2.SIGNATURE_ALGORITHM_ED25519
    raise ValueError(f"unknown signature algorithm: {name}")


def _build_public_key(d: dict[str, Any]) -> common_pb2.PublicKey:
    return common_pb2.PublicKey(
        algorithm=_build_signature_algorithm(d["algorithm"]),
        value=bytes.fromhex(d["value_hex"]),
    )


def _build_timestamp(d: dict[str, Any]) -> common_pb2.Timestamp:
    return common_pb2.Timestamp(wall_clock=d["wall_clock"], monotonic_ns=d["monotonic_ns"])


def _build_causal_ref(predecessors_hex: list[str]) -> common_pb2.CausalRef:
    return common_pb2.CausalRef(predecessors=[_build_hash(h) for h in predecessors_hex])


def _build_cost(d: dict[str, Any]) -> common_pb2.CostAnnotation:
    return common_pb2.CostAnnotation(
        input_tokens=d.get("input_tokens", 0),
        output_tokens=d.get("output_tokens", 0),
        tool_call_count=d.get("tool_call_count", 0),
        wall_time_ms=d.get("wall_time_ms", 0),
        usd_cents_estimate=d.get("usd_cents_estimate", ""),
        model_provider=d.get("model_provider", ""),
        model_name=d.get("model_name", ""),
        model_version=d.get("model_version", ""),
    )


# =============================================================================
# Receipt
# =============================================================================


def _build_evidence(d: dict[str, Any]) -> receipt_proto.Evidence:
    return receipt_proto.Evidence(
        key=d["key"],
        type_url=d["type_url"],
        value=bytes.fromhex(d["value_hex"]),
        sensitive=d.get("sensitive", False),
    )


def _build_receipt(fields: dict[str, Any]) -> receipt_proto.Receipt:
    msg = receipt_proto.Receipt(
        spec_version=common_pb2.Version(value=fields["spec_version"]),
        swarm_id=_build_swarm_id(fields["swarm_id_hex"]),
        actor=_build_agent_id(fields["actor_hex"]),
        action_kind=fields["action_kind"],
        causal=_build_causal_ref(fields["predecessors_hex"]),
        evidence=[_build_evidence(e) for e in fields["evidence"]],
        constitution_version=fields["constitution_version"],
        occurred_at=_build_timestamp(fields["occurred_at"]),
    )
    if fields.get("cost") is not None:
        msg.cost.CopyFrom(_build_cost(fields["cost"]))
    return msg


def _canonicalize_receipt(msg: receipt_proto.Receipt) -> receipt_proto.Receipt:
    # to_canonical_proto semantics: clear signatures, seal, extensions.
    msg.ClearField("signatures")
    msg.ClearField("seal")
    msg.ClearField("extensions")
    return msg


# =============================================================================
# Passport
# =============================================================================


_PASSPORT_TIERS = {
    "minimal": passport_proto.PASSPORT_TIER_MINIMAL,
    "standard": passport_proto.PASSPORT_TIER_STANDARD,
    "verifiable": passport_proto.PASSPORT_TIER_VERIFIABLE,
}


def _build_capability_declaration(d: dict[str, Any]) -> passport_proto.CapabilityDeclaration:
    out = passport_proto.CapabilityDeclaration(
        kind=d["kind"],
        resource_tags=list(d.get("resource_tags", [])),
        description=d.get("description", ""),
    )
    for k, v in d.get("bounds", {}).items():
        out.bounds[k] = v
    return out


def _build_resource_declaration(d: dict[str, Any]) -> passport_proto.ResourceDeclaration:
    return passport_proto.ResourceDeclaration(
        max_concurrent_actions=d.get("max_concurrent_actions", 0),
        max_messages_per_minute=d.get("max_messages_per_minute", 0),
        max_tool_calls_per_hour=d.get("max_tool_calls_per_hour", 0),
        max_usd_per_day_cents=d.get("max_usd_per_day_cents", ""),
        max_memory_bytes=d.get("max_memory_bytes", 0),
    )


def _build_passport(fields: dict[str, Any]) -> passport_proto.Passport:
    msg = passport_proto.Passport(
        spec_version=common_pb2.Version(value=fields["spec_version"]),
        agent_id=_build_agent_id(fields["agent_id_hex"]),
        swarm_id=_build_swarm_id(fields["swarm_id_hex"]),
        agent_public_key=_build_public_key(fields["agent_public_key"]),
        owner=fields.get("owner", ""),
        framework=fields.get("framework", ""),
        framework_version=fields.get("framework_version", ""),
        capabilities=[_build_capability_declaration(c) for c in fields.get("capabilities", [])],
        accepted_constitution_version=fields["accepted_constitution_version"],
        tier=_PASSPORT_TIERS[fields["tier"]],
        resources=_build_resource_declaration(fields.get("resources", {})),
        issued_at=_build_timestamp(fields["issued_at"]),
        default_model_provider=fields.get("default_model_provider", ""),
        default_model_name=fields.get("default_model_name", ""),
    )
    if fields.get("expires_at") is not None:
        msg.expires_at.CopyFrom(_build_timestamp(fields["expires_at"]))
    return msg


def _canonicalize_passport(msg: passport_proto.Passport) -> passport_proto.Passport:
    msg.ClearField("agent_signature")
    msg.ClearField("extensions")
    return msg


# =============================================================================
# Envelope
# =============================================================================


_PERFORMATIVES = {
    "propose": env_proto.PERFORMATIVE_PROPOSE,
    "counter": env_proto.PERFORMATIVE_COUNTER,
    "commit": env_proto.PERFORMATIVE_COMMIT,
    "abort": env_proto.PERFORMATIVE_ABORT,
    "release": env_proto.PERFORMATIVE_RELEASE,
    "query": env_proto.PERFORMATIVE_QUERY,
    "inform": env_proto.PERFORMATIVE_INFORM,
    "error": env_proto.PERFORMATIVE_ERROR,
    "request_action": env_proto.PERFORMATIVE_REQUEST_ACTION,
    "confirm": env_proto.PERFORMATIVE_CONFIRM,
    "decline": env_proto.PERFORMATIVE_DECLINE,
}


def _build_recipient(d: dict[str, Any]) -> env_proto.Recipient:
    out = env_proto.Recipient()
    kind = d["kind"]
    if kind == "agent":
        out.agent.CopyFrom(_build_agent_id(d["agent_hex"]))
    elif kind == "role":
        out.role = d["role"]
    elif kind == "swarm":
        out.swarm.CopyFrom(env_proto.SwarmBroadcast(filter_tags=list(d.get("filter_tags", []))))
    elif kind == "external":
        out.external.CopyFrom(
            env_proto.ExternalEndpoint(
                scheme=d["scheme"],
                authority=d["authority"],
                path_hint=d.get("path_hint", ""),
            )
        )
    else:
        raise ValueError(f"unknown recipient kind in vector: {kind}")
    return out


def _build_envelope(fields: dict[str, Any]) -> env_proto.Envelope:
    msg = env_proto.Envelope(
        spec_version=common_pb2.Version(value=fields["spec_version"]),
        swarm_id=_build_swarm_id(fields["swarm_id_hex"]),
        envelope_id=bytes.fromhex(fields["envelope_id_hex"]),
        from_agent=_build_agent_id(fields["from_agent_hex"]),
        recipient=_build_recipient(fields["recipient"]),
        performative=_PERFORMATIVES[fields["performative"]],
        payload=bytes.fromhex(fields.get("payload_hex", "")),
        payload_schema_id=fields.get("payload_schema_id", ""),
        tags=list(fields.get("tags", [])),
        causal=_build_causal_ref(fields.get("predecessors_hex", [])),
        nonce=bytes.fromhex(fields["nonce_hex"]),
        epoch=fields["epoch"],
        sent_at=_build_timestamp(fields["sent_at"]),
    )
    if fields.get("expires_at") is not None:
        msg.expires_at.CopyFrom(_build_timestamp(fields["expires_at"]))
    if fields.get("in_reply_to_hex"):
        msg.in_reply_to.CopyFrom(_build_hash(fields["in_reply_to_hex"]))
    return msg


def _canonicalize_envelope(msg: env_proto.Envelope) -> env_proto.Envelope:
    msg.ClearField("agent_signature")
    msg.ClearField("extensions")
    return msg


# =============================================================================
# Capability
# =============================================================================


def _build_issuer(d: dict[str, Any]) -> cap_proto.Issuer:
    out = cap_proto.Issuer()
    kind = d["kind"]
    if kind == "agent":
        out.agent.CopyFrom(_build_agent_id(d["agent_hex"]))
    elif kind == "operator":
        out.operator_key_fingerprint = bytes.fromhex(d["key_fingerprint_hex"])
    elif kind == "control_plane":
        # Vectors use `control_plane_key_fingerprint_hex` here, mirroring
        # the proto field name, not the generic `key_fingerprint_hex`
        # the operator variant uses.
        out.control_plane.CopyFrom(
            cap_proto.ControlPlaneIssuer(
                control_plane_key_fingerprint=bytes.fromhex(d["control_plane_key_fingerprint_hex"]),
                instance_id=d.get("instance_id", ""),
            )
        )
    else:
        raise ValueError(f"unknown issuer kind in vector: {kind}")
    return out


def _build_scope(d: dict[str, Any]) -> cap_proto.Scope:
    out = cap_proto.Scope(
        permitted_actions=list(d.get("permitted_actions", [])),
        resource_tags=list(d.get("resource_tags", [])),
        permitted_recipients=list(d.get("permitted_recipients", [])),
        memory_scopes=list(d.get("memory_scopes", [])),
    )
    for k, v in d.get("bounds", {}).items():
        out.bounds[k] = v
    return out


def _build_caveat(d: dict[str, Any]) -> cap_proto.Caveat:
    out = cap_proto.Caveat()
    kind = d["kind"]
    if kind == "time_of_day":
        out.time_of_day.CopyFrom(
            cap_proto.TimeOfDayCaveat(from_utc=d["from_utc"], to_utc=d["to_utc"])
        )
    elif kind == "constitution_version":
        out.constitution_version.CopyFrom(
            cap_proto.ConstitutionVersionCaveat(
                min_version=d["min_version"], max_version=d.get("max_version", "")
            )
        )
    elif kind == "supervisor_required":
        out.supervisor_required.CopyFrom(
            cap_proto.SupervisorRequiredCaveat(supervisor_role=d["supervisor_role"])
        )
    elif kind == "rate_limit":
        out.rate_limit.CopyFrom(
            cap_proto.RateLimitCaveat(
                max_actions=d["max_actions"], window_seconds=d["window_seconds"]
            )
        )
    elif kind == "only_if_tagged":
        out.only_if_tagged.CopyFrom(
            cap_proto.OnlyIfTaggedCaveat(required_tags=list(d["required_tags"]))
        )
    elif kind == "never_if_tagged":
        out.never_if_tagged.CopyFrom(
            cap_proto.NeverIfTaggedCaveat(forbidden_tags=list(d["forbidden_tags"]))
        )
    else:
        raise ValueError(f"unknown caveat kind in vector: {kind}")
    return out


def _build_capability(fields: dict[str, Any]) -> cap_proto.Capability:
    msg = cap_proto.Capability(
        spec_version=common_pb2.Version(value=fields["spec_version"]),
        capability_id=bytes.fromhex(fields["capability_id_hex"]),
        swarm_id=_build_swarm_id(fields["swarm_id_hex"]),
        issuer=_build_issuer(fields["issuer"]),
        subject=_build_agent_id(fields["subject_hex"]),
        scope=_build_scope(fields["scope"]),
        valid_from=_build_timestamp(fields["valid_from"]),
        valid_until=_build_timestamp(fields["valid_until"]),
        caveats=[_build_caveat(c) for c in fields.get("caveats", [])],
        revocation_endpoint=fields.get("revocation_endpoint", ""),
    )
    if fields.get("parent_hex"):
        msg.parent.CopyFrom(_build_hash(fields["parent_hex"]))
    return msg


def _canonicalize_capability(msg: cap_proto.Capability) -> cap_proto.Capability:
    msg.ClearField("signatures")
    msg.ClearField("extensions")
    return msg


# =============================================================================
# Parametrized vector runner
# =============================================================================


_BUILDERS: dict[str, tuple[Any, Any]] = {
    "receipt": (_build_receipt, _canonicalize_receipt),
    "passport": (_build_passport, _canonicalize_passport),
    "envelope": (_build_envelope, _canonicalize_envelope),
    "capability": (_build_capability, _canonicalize_capability),
}


def _discover_vectors() -> list[tuple[str, Path]]:
    """Return ``(test-id, json-path)`` pairs for every vector on disk."""
    out: list[tuple[str, Path]] = []
    if not VECTORS_ROOT.is_dir():
        return out
    for kind_dir in sorted(VECTORS_ROOT.iterdir()):
        if not kind_dir.is_dir():
            continue
        kind = kind_dir.name
        if kind not in _BUILDERS:
            continue
        for fixture in sorted(kind_dir.glob("*.json")):
            out.append((f"{kind}/{fixture.stem}", fixture))
    return out


@pytest.mark.parametrize(
    "fixture_path",
    [pytest.param(path, id=tid) for tid, path in _discover_vectors()],
)
def test_canonical_bytes_match_vector(fixture_path: Path) -> None:
    """Build the proto from the fixture's fields, canonicalize,
    serialize deterministically, and assert byte-equality with the
    committed ``expected_canonical_hex``."""
    data = json.loads(fixture_path.read_text())
    kind = data["kind"]
    builder, canonicalizer = _BUILDERS[kind]

    msg = builder(data["fields"])
    canonicalizer(msg)
    actual_hex = msg.SerializeToString(deterministic=True).hex()

    assert actual_hex == data["expected_canonical_hex"], (
        f"canonical bytes mismatch for {kind}/{fixture_path.stem}.\n"
        f"  expected: {data['expected_canonical_hex']}\n"
        f"  actual:   {actual_hex}"
    )

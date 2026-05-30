"""Passport ergonomic model + supporting types.

Mirrors ``/spec/passport/passport-v1.proto`` and the Rust ``Passport``
in ``crates/yutha-passport/src/passport.rs``.
"""

from __future__ import annotations

from enum import IntEnum

from pydantic import BaseModel, ConfigDict, Field

from yutha._proto import common_pb2
from yutha._proto.passport import passport_v1_pb2 as proto
from yutha.canonical import canonical_bytes as _canonical_bytes
from yutha.crypto import Signer, VerificationFailed, verify
from yutha.identity import AgentId, PublicKey, Signature, SwarmId, Timestamp


class PassportTier(IntEnum):
    """Conformance tier. Wire numbers match the proto enum directly."""

    MINIMAL = 1
    STANDARD = 2
    VERIFIABLE = 3


class CapabilityDeclaration(BaseModel):
    """Declared capability (NOT authority — see capability spec).

    ``bounds`` is a sorted dict on the wire (the Rust side uses BTreeMap
    so canonical bytes are deterministic). On the Python side we let the
    user pass a plain dict; we sort it on the way to proto.
    """

    model_config = ConfigDict(frozen=True)

    kind: str
    resource_tags: list[str] = Field(default_factory=list)
    bounds: dict[str, str] = Field(default_factory=dict)
    description: str = ""

    @classmethod
    def from_proto(cls, p: proto.CapabilityDeclaration) -> CapabilityDeclaration:
        return cls(
            kind=p.kind,
            resource_tags=list(p.resource_tags),
            bounds=dict(p.bounds),
            description=p.description,
        )

    def to_proto(self) -> proto.CapabilityDeclaration:
        out = proto.CapabilityDeclaration(
            kind=self.kind,
            resource_tags=list(self.resource_tags),
            description=self.description,
        )
        # Protobuf maps don't preserve insertion order; deterministic
        # encoding sorts them at write time. We just copy.
        for k, v in self.bounds.items():
            out.bounds[k] = v
        return out


class ResourceDeclaration(BaseModel):
    """Declared resource budget. Pure scalars — round-trips cleanly."""

    model_config = ConfigDict(frozen=True)

    max_concurrent_actions: int = 0
    max_messages_per_minute: int = 0
    max_tool_calls_per_hour: int = 0
    max_usd_per_day_cents: str = ""
    max_memory_bytes: int = 0

    @classmethod
    def from_proto(cls, p: proto.ResourceDeclaration) -> ResourceDeclaration:
        return cls(
            max_concurrent_actions=p.max_concurrent_actions,
            max_messages_per_minute=p.max_messages_per_minute,
            max_tool_calls_per_hour=p.max_tool_calls_per_hour,
            max_usd_per_day_cents=p.max_usd_per_day_cents,
            max_memory_bytes=p.max_memory_bytes,
        )

    def to_proto(self) -> proto.ResourceDeclaration:
        return proto.ResourceDeclaration(
            max_concurrent_actions=self.max_concurrent_actions,
            max_messages_per_minute=self.max_messages_per_minute,
            max_tool_calls_per_hour=self.max_tool_calls_per_hour,
            max_usd_per_day_cents=self.max_usd_per_day_cents,
            max_memory_bytes=self.max_memory_bytes,
        )


class Passport(BaseModel):
    """A signed identity manifest — what an agent presents at swarm
    join.

    Construct, then ``await passport.sign(signer)`` to attach
    ``agent_signature`` over canonical bytes. The returned Passport is
    a new immutable instance; the original is unchanged.
    """

    model_config = ConfigDict(frozen=True)

    spec_version: str
    agent_id: AgentId
    swarm_id: SwarmId
    agent_public_key: PublicKey
    owner: str = ""
    framework: str = ""
    framework_version: str = ""
    capabilities: list[CapabilityDeclaration] = Field(default_factory=list)
    accepted_constitution_version: str
    tier: PassportTier = PassportTier.MINIMAL
    resources: ResourceDeclaration = Field(default_factory=ResourceDeclaration)
    issued_at: Timestamp
    expires_at: Timestamp | None = None
    default_model_provider: str = ""
    default_model_name: str = ""
    agent_signature: Signature | None = None

    # -------------------------------------------------------------------------
    # Round-trip
    # -------------------------------------------------------------------------

    @classmethod
    def from_proto(cls, p: proto.Passport) -> Passport:
        return cls(
            spec_version=p.spec_version.value,
            agent_id=AgentId.from_proto(p.agent_id),
            swarm_id=SwarmId.from_proto(p.swarm_id),
            agent_public_key=PublicKey.from_proto(p.agent_public_key),
            owner=p.owner,
            framework=p.framework,
            framework_version=p.framework_version,
            capabilities=[CapabilityDeclaration.from_proto(c) for c in p.capabilities],
            accepted_constitution_version=p.accepted_constitution_version,
            tier=PassportTier(p.tier),
            resources=ResourceDeclaration.from_proto(p.resources),
            issued_at=Timestamp.from_proto(p.issued_at),
            expires_at=Timestamp.from_proto(p.expires_at) if p.HasField("expires_at") else None,
            default_model_provider=p.default_model_provider,
            default_model_name=p.default_model_name,
            agent_signature=Signature.from_proto(p.agent_signature)
            if p.HasField("agent_signature")
            else None,
        )

    def to_proto(self) -> proto.Passport:
        out = proto.Passport(
            spec_version=common_pb2.Version(value=self.spec_version),
            agent_id=self.agent_id.to_proto(),
            swarm_id=self.swarm_id.to_proto(),
            agent_public_key=self.agent_public_key.to_proto(),
            owner=self.owner,
            framework=self.framework,
            framework_version=self.framework_version,
            capabilities=[c.to_proto() for c in self.capabilities],
            accepted_constitution_version=self.accepted_constitution_version,
            # proto.Passport's `tier` parameter is typed as
            # `proto.PassportTier | str | None`; we pass an int from our
            # IntEnum. Same wire numbers, nominally distinct types.
            tier=self.tier.value,  # type: ignore[arg-type]
            resources=self.resources.to_proto(),
            issued_at=self.issued_at.to_proto(),
            default_model_provider=self.default_model_provider,
            default_model_name=self.default_model_name,
        )
        if self.expires_at is not None:
            out.expires_at.CopyFrom(self.expires_at.to_proto())
        if self.agent_signature is not None:
            out.agent_signature.CopyFrom(self.agent_signature.to_proto())
        return out

    # -------------------------------------------------------------------------
    # Canonical bytes + signing
    # -------------------------------------------------------------------------

    def canonical_bytes(self) -> bytes:
        """Canonical wire encoding with ``agent_signature`` and
        ``extensions`` cleared — what the agent signature is over and
        what the content-address hashes."""
        p = self.to_proto()
        p.ClearField("agent_signature")
        p.ClearField("extensions")
        return _canonical_bytes(p)

    async def sign(self, signer: Signer) -> Passport:
        """Return a copy of this Passport with ``agent_signature`` set.

        The signer's public key MUST match ``agent_public_key``; this
        is verified before signing. ``signer.sign_message`` is awaited
        — for the default :class:`yutha.crypto.InProcessSigner` this
        completes immediately, for cloud-KMS-backed signers it's one
        network round-trip.
        """
        if signer.public_key().value != self.agent_public_key.value:
            raise ValueError("signer does not match agent_public_key")
        sig = await signer.sign_message(self.canonical_bytes())
        return self.model_copy(update={"agent_signature": sig})

    def verify_self_signature(self) -> None:
        """Verify ``agent_signature`` against ``agent_public_key`` and
        the canonical bytes.

        Raises ``VerificationFailed`` if the signature is missing,
        malformed, or doesn't match. Returns ``None`` on success.
        """
        if self.agent_signature is None:
            raise VerificationFailed("passport has no agent_signature to verify")
        verify(self.agent_public_key, self.canonical_bytes(), self.agent_signature)

"""Capability ergonomic model + supporting types.

Mirrors ``/spec/capability/capability-v1.proto`` and the Rust
``Capability`` in ``crates/yutha-capability/src/capability.rs``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from yutha._proto import common_pb2
from yutha._proto.capability import capability_v1_pb2 as proto
from yutha.canonical import canonical_bytes as _canonical_bytes
from yutha.crypto import Signer, VerificationFailed, verify
from yutha.identity import AgentId, Hash, PublicKey, Signature, SwarmId, Timestamp

# =============================================================================
# Issuer (oneof)
# =============================================================================


class ControlPlaneIssuer(BaseModel):
    """Control-plane issuer identity."""

    model_config = ConfigDict(frozen=True)

    control_plane_key_fingerprint: bytes
    instance_id: str = ""


class Issuer(BaseModel):
    """Tagged union: exactly one of ``agent``, ``operator_key_fingerprint``,
    ``control_plane`` set."""

    model_config = ConfigDict(frozen=True)

    agent: AgentId | None = None
    operator_key_fingerprint: bytes | None = None
    control_plane: ControlPlaneIssuer | None = None

    def model_post_init(self, __context: Any, /) -> None:
        populated = sum(
            x is not None for x in (self.agent, self.operator_key_fingerprint, self.control_plane)
        )
        if populated != 1:
            raise ValueError(
                "Issuer must have exactly one variant set "
                "(agent / operator_key_fingerprint / control_plane); "
                f"got {populated}"
            )

    @classmethod
    def for_agent(cls, agent_id: AgentId) -> Issuer:
        return cls(agent=agent_id)

    @classmethod
    def for_operator(cls, key_fingerprint: bytes) -> Issuer:
        return cls(operator_key_fingerprint=key_fingerprint)

    @classmethod
    def for_control_plane(cls, fingerprint: bytes, instance_id: str = "") -> Issuer:
        return cls(
            control_plane=ControlPlaneIssuer(
                control_plane_key_fingerprint=fingerprint, instance_id=instance_id
            )
        )

    @classmethod
    def from_proto(cls, p: proto.Issuer) -> Issuer:
        which = p.WhichOneof("kind")
        if which == "agent":
            return cls(agent=AgentId.from_proto(p.agent))
        if which == "operator_key_fingerprint":
            return cls(operator_key_fingerprint=bytes(p.operator_key_fingerprint))
        if which == "control_plane":
            return cls(
                control_plane=ControlPlaneIssuer(
                    control_plane_key_fingerprint=bytes(
                        p.control_plane.control_plane_key_fingerprint
                    ),
                    instance_id=p.control_plane.instance_id,
                )
            )
        raise ValueError("Issuer proto has no `kind` variant set")

    def to_proto(self) -> proto.Issuer:
        out = proto.Issuer()
        if self.agent is not None:
            out.agent.CopyFrom(self.agent.to_proto())
        elif self.operator_key_fingerprint is not None:
            out.operator_key_fingerprint = self.operator_key_fingerprint
        elif self.control_plane is not None:
            out.control_plane.CopyFrom(
                proto.ControlPlaneIssuer(
                    control_plane_key_fingerprint=self.control_plane.control_plane_key_fingerprint,
                    instance_id=self.control_plane.instance_id,
                )
            )
        return out


# =============================================================================
# Scope
# =============================================================================


class Scope(BaseModel):
    """What a capability permits along five dimensions. Empty list /
    empty dict on a dimension means "all" (no constraint)."""

    model_config = ConfigDict(frozen=True)

    permitted_actions: list[str] = Field(default_factory=list)
    resource_tags: list[str] = Field(default_factory=list)
    bounds: dict[str, str] = Field(default_factory=dict)
    permitted_recipients: list[str] = Field(default_factory=list)
    memory_scopes: list[str] = Field(default_factory=list)

    @classmethod
    def for_action(cls, action: str) -> Scope:
        return cls(permitted_actions=[action])

    @classmethod
    def empty(cls) -> Scope:
        return cls()

    @classmethod
    def from_proto(cls, p: proto.Scope) -> Scope:
        return cls(
            permitted_actions=list(p.permitted_actions),
            resource_tags=list(p.resource_tags),
            bounds=dict(p.bounds),
            permitted_recipients=list(p.permitted_recipients),
            memory_scopes=list(p.memory_scopes),
        )

    def to_proto(self) -> proto.Scope:
        out = proto.Scope(
            permitted_actions=list(self.permitted_actions),
            resource_tags=list(self.resource_tags),
            permitted_recipients=list(self.permitted_recipients),
            memory_scopes=list(self.memory_scopes),
        )
        for k, v in self.bounds.items():
            out.bounds[k] = v
        return out


# =============================================================================
# Caveats (oneof on the wire; one class per variant on the Python side)
# =============================================================================


class TimeOfDayCaveat(BaseModel):
    model_config = ConfigDict(frozen=True)
    from_utc: str  # "HH:MM"
    to_utc: str


class ConstitutionVersionCaveat(BaseModel):
    model_config = ConfigDict(frozen=True)
    min_version: str
    max_version: str | None = None


class SupervisorRequiredCaveat(BaseModel):
    model_config = ConfigDict(frozen=True)
    supervisor_role: str


class RateLimitCaveat(BaseModel):
    model_config = ConfigDict(frozen=True)
    max_actions: int
    window_seconds: int


class OnlyIfTaggedCaveat(BaseModel):
    """AND logic: all listed tags must be present."""

    model_config = ConfigDict(frozen=True)
    required_tags: list[str] = Field(default_factory=list)


class NeverIfTaggedCaveat(BaseModel):
    """OR-deny logic: any listed tag forbids the action."""

    model_config = ConfigDict(frozen=True)
    forbidden_tags: list[str] = Field(default_factory=list)


class Caveat(BaseModel):
    """Tagged union over the six caveat variants. Exactly one field must
    be set."""

    model_config = ConfigDict(frozen=True)

    time_of_day: TimeOfDayCaveat | None = None
    constitution_version: ConstitutionVersionCaveat | None = None
    supervisor_required: SupervisorRequiredCaveat | None = None
    rate_limit: RateLimitCaveat | None = None
    only_if_tagged: OnlyIfTaggedCaveat | None = None
    never_if_tagged: NeverIfTaggedCaveat | None = None

    def model_post_init(self, __context: Any, /) -> None:
        populated = sum(
            x is not None
            for x in (
                self.time_of_day,
                self.constitution_version,
                self.supervisor_required,
                self.rate_limit,
                self.only_if_tagged,
                self.never_if_tagged,
            )
        )
        if populated != 1:
            raise ValueError(f"Caveat must have exactly one variant set, got {populated}")

    @classmethod
    def from_proto(cls, p: proto.Caveat) -> Caveat:
        which = p.WhichOneof("kind")
        if which == "time_of_day":
            return cls(
                time_of_day=TimeOfDayCaveat(
                    from_utc=p.time_of_day.from_utc, to_utc=p.time_of_day.to_utc
                )
            )
        if which == "constitution_version":
            mv = p.constitution_version.max_version
            return cls(
                constitution_version=ConstitutionVersionCaveat(
                    min_version=p.constitution_version.min_version,
                    max_version=mv if mv else None,
                )
            )
        if which == "supervisor_required":
            return cls(
                supervisor_required=SupervisorRequiredCaveat(
                    supervisor_role=p.supervisor_required.supervisor_role
                )
            )
        if which == "rate_limit":
            return cls(
                rate_limit=RateLimitCaveat(
                    max_actions=p.rate_limit.max_actions,
                    window_seconds=p.rate_limit.window_seconds,
                )
            )
        if which == "only_if_tagged":
            return cls(
                only_if_tagged=OnlyIfTaggedCaveat(
                    required_tags=list(p.only_if_tagged.required_tags)
                )
            )
        if which == "never_if_tagged":
            return cls(
                never_if_tagged=NeverIfTaggedCaveat(
                    forbidden_tags=list(p.never_if_tagged.forbidden_tags)
                )
            )
        raise ValueError("Caveat proto has no `kind` variant set")

    def to_proto(self) -> proto.Caveat:
        out = proto.Caveat()
        if self.time_of_day is not None:
            out.time_of_day.CopyFrom(
                proto.TimeOfDayCaveat(
                    from_utc=self.time_of_day.from_utc, to_utc=self.time_of_day.to_utc
                )
            )
        elif self.constitution_version is not None:
            out.constitution_version.CopyFrom(
                proto.ConstitutionVersionCaveat(
                    min_version=self.constitution_version.min_version,
                    max_version=self.constitution_version.max_version or "",
                )
            )
        elif self.supervisor_required is not None:
            out.supervisor_required.CopyFrom(
                proto.SupervisorRequiredCaveat(
                    supervisor_role=self.supervisor_required.supervisor_role
                )
            )
        elif self.rate_limit is not None:
            out.rate_limit.CopyFrom(
                proto.RateLimitCaveat(
                    max_actions=self.rate_limit.max_actions,
                    window_seconds=self.rate_limit.window_seconds,
                )
            )
        elif self.only_if_tagged is not None:
            out.only_if_tagged.CopyFrom(
                proto.OnlyIfTaggedCaveat(required_tags=list(self.only_if_tagged.required_tags))
            )
        elif self.never_if_tagged is not None:
            out.never_if_tagged.CopyFrom(
                proto.NeverIfTaggedCaveat(forbidden_tags=list(self.never_if_tagged.forbidden_tags))
            )
        return out


# =============================================================================
# ActionDescriptor + CheckOutcome
# =============================================================================


class ActionDescriptor(BaseModel):
    """Describes an action being checked against a capability."""

    model_config = ConfigDict(frozen=True)

    action_kind: str
    resource_tags: list[str] = Field(default_factory=list)
    numeric_values: dict[str, str] = Field(default_factory=dict)
    recipient: str | None = None
    memory_scope: str | None = None

    @classmethod
    def from_proto(cls, p: proto.ActionDescriptor) -> ActionDescriptor:
        return cls(
            action_kind=p.action_kind,
            resource_tags=list(p.resource_tags),
            numeric_values=dict(p.numeric_values),
            recipient=p.recipient if p.recipient else None,
            memory_scope=p.memory_scope if p.memory_scope else None,
        )

    def to_proto(self) -> proto.ActionDescriptor:
        out = proto.ActionDescriptor(
            action_kind=self.action_kind,
            resource_tags=list(self.resource_tags),
            recipient=self.recipient or "",
            memory_scope=self.memory_scope or "",
        )
        for k, v in self.numeric_values.items():
            out.numeric_values[k] = v
        return out


class CheckOutcome(BaseModel):
    """Outcome of a capability check."""

    model_config = ConfigDict(frozen=True)

    permitted: bool
    deny_reason: str = ""
    matched_caveats: list[str] = Field(default_factory=list)
    unmet_caveats: list[str] = Field(default_factory=list)
    check_receipt: Hash | None = None

    @classmethod
    def from_proto(cls, p: proto.CheckResponse) -> CheckOutcome:
        return cls(
            permitted=p.permitted,
            deny_reason=p.deny_reason,
            matched_caveats=list(p.matched_caveats),
            unmet_caveats=list(p.unmet_caveats),
            check_receipt=Hash.from_proto(p.check_receipt) if p.HasField("check_receipt") else None,
        )


# =============================================================================
# Capability
# =============================================================================


class Capability(BaseModel):
    """A signed authority token. Construct, then ``await
    capability.sign(signer)`` to attach ``issuer_signature``."""

    model_config = ConfigDict(frozen=True)

    spec_version: str
    capability_id: bytes
    swarm_id: SwarmId
    issuer: Issuer
    subject: AgentId
    scope: Scope = Field(default_factory=Scope.empty)
    parent: Hash | None = None
    valid_from: Timestamp
    valid_until: Timestamp
    caveats: list[Caveat] = Field(default_factory=list)
    revocation_endpoint: str = ""
    issuer_signature: Signature | None = None

    @classmethod
    def from_proto(cls, p: proto.Capability) -> Capability:
        # Find the ISSUER-role signature; ignore others (future
        # attestation signatures). Same behavior as the Rust reverse
        # conversion in yutha-capability/src/proto_conv.rs.
        issuer_sig = None
        for sig_entry in p.signatures:
            if sig_entry.role == proto.CAPABILITY_SIGNATURE_ROLE_ISSUER and sig_entry.HasField(
                "signature"
            ):
                issuer_sig = Signature.from_proto(sig_entry.signature)
                break
        return cls(
            spec_version=p.spec_version.value,
            capability_id=bytes(p.capability_id),
            swarm_id=SwarmId.from_proto(p.swarm_id),
            issuer=Issuer.from_proto(p.issuer),
            subject=AgentId.from_proto(p.subject),
            scope=Scope.from_proto(p.scope),
            parent=Hash.from_proto(p.parent) if p.HasField("parent") else None,
            valid_from=Timestamp.from_proto(p.valid_from),
            valid_until=Timestamp.from_proto(p.valid_until),
            caveats=[Caveat.from_proto(c) for c in p.caveats],
            revocation_endpoint=p.revocation_endpoint,
            issuer_signature=issuer_sig,
        )

    def to_proto(self) -> proto.Capability:
        out = proto.Capability(
            spec_version=common_pb2.Version(value=self.spec_version),
            capability_id=self.capability_id,
            swarm_id=self.swarm_id.to_proto(),
            issuer=self.issuer.to_proto(),
            subject=self.subject.to_proto(),
            scope=self.scope.to_proto(),
            valid_from=self.valid_from.to_proto(),
            valid_until=self.valid_until.to_proto(),
            caveats=[c.to_proto() for c in self.caveats],
            revocation_endpoint=self.revocation_endpoint,
        )
        if self.parent is not None:
            out.parent.CopyFrom(self.parent.to_proto())
        if self.issuer_signature is not None:
            out.signatures.add(
                role=proto.CAPABILITY_SIGNATURE_ROLE_ISSUER,
                signature=self.issuer_signature.to_proto(),
                signed_at=common_pb2.Timestamp(wall_clock="", monotonic_ns=0),
            )
        return out

    def canonical_bytes(self) -> bytes:
        p = self.to_proto()
        # The forward conversion above always emits the ISSUER signature
        # if present; the canonical form clears all of them.
        p.ClearField("signatures")
        p.ClearField("extensions")
        return _canonical_bytes(p)

    async def sign(self, signer: Signer) -> Capability:
        """Return a copy with ``issuer_signature`` attached.

        ``signer.sign_message`` is awaited — see :meth:`Passport.sign`
        for the rationale (cloud-KMS-backed signers are async; the
        in-process default's overhead is negligible).
        """
        sig = await signer.sign_message(self.canonical_bytes())
        return self.model_copy(update={"issuer_signature": sig})

    def verify_signature(self, issuer_public_key: PublicKey) -> None:
        """Verify ``issuer_signature`` against the supplied public key.

        Caller is responsible for resolving the right public key (the
        agent's, the operator's, or the control plane's) based on which
        ``Issuer`` variant the capability declares.
        """
        if self.issuer_signature is None:
            raise VerificationFailed("capability has no issuer_signature to verify")
        verify(issuer_public_key, self.canonical_bytes(), self.issuer_signature)

import common_pb2 as _common_pb2
from capability import capability_v1_pb2 as _capability_v1_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class TopologyMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TOPOLOGY_MODE_UNKNOWN: _ClassVar[TopologyMode]
    TOPOLOGY_MODE_CLOSED: _ClassVar[TopologyMode]
    TOPOLOGY_MODE_OPEN: _ClassVar[TopologyMode]
    TOPOLOGY_MODE_HYBRID: _ClassVar[TopologyMode]
TOPOLOGY_MODE_UNKNOWN: TopologyMode
TOPOLOGY_MODE_CLOSED: TopologyMode
TOPOLOGY_MODE_OPEN: TopologyMode
TOPOLOGY_MODE_HYBRID: TopologyMode

class Topology(_message.Message):
    __slots__ = ("spec_version", "swarm_id", "mode", "admission", "max_capability_lifetime_seconds", "max_capability_chain_depth", "default_envelope_ttl_seconds", "max_epoch_skew", "external_sends_permitted", "initial_constitution_version", "operator_key_fingerprint", "require_capability_for_send", "extensions", "operator_signature")
    SPEC_VERSION_FIELD_NUMBER: _ClassVar[int]
    SWARM_ID_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    ADMISSION_FIELD_NUMBER: _ClassVar[int]
    MAX_CAPABILITY_LIFETIME_SECONDS_FIELD_NUMBER: _ClassVar[int]
    MAX_CAPABILITY_CHAIN_DEPTH_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_ENVELOPE_TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    MAX_EPOCH_SKEW_FIELD_NUMBER: _ClassVar[int]
    EXTERNAL_SENDS_PERMITTED_FIELD_NUMBER: _ClassVar[int]
    INITIAL_CONSTITUTION_VERSION_FIELD_NUMBER: _ClassVar[int]
    OPERATOR_KEY_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    REQUIRE_CAPABILITY_FOR_SEND_FIELD_NUMBER: _ClassVar[int]
    EXTENSIONS_FIELD_NUMBER: _ClassVar[int]
    OPERATOR_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    spec_version: _common_pb2.Version
    swarm_id: _common_pb2.SwarmId
    mode: TopologyMode
    admission: AdmissionPolicy
    max_capability_lifetime_seconds: int
    max_capability_chain_depth: int
    default_envelope_ttl_seconds: int
    max_epoch_skew: int
    external_sends_permitted: bool
    initial_constitution_version: str
    operator_key_fingerprint: bytes
    require_capability_for_send: bool
    extensions: _common_pb2.Extensions
    operator_signature: _common_pb2.Signature
    def __init__(self, spec_version: _Optional[_Union[_common_pb2.Version, _Mapping]] = ..., swarm_id: _Optional[_Union[_common_pb2.SwarmId, _Mapping]] = ..., mode: _Optional[_Union[TopologyMode, str]] = ..., admission: _Optional[_Union[AdmissionPolicy, _Mapping]] = ..., max_capability_lifetime_seconds: _Optional[int] = ..., max_capability_chain_depth: _Optional[int] = ..., default_envelope_ttl_seconds: _Optional[int] = ..., max_epoch_skew: _Optional[int] = ..., external_sends_permitted: bool = ..., initial_constitution_version: _Optional[str] = ..., operator_key_fingerprint: _Optional[bytes] = ..., require_capability_for_send: bool = ..., extensions: _Optional[_Union[_common_pb2.Extensions, _Mapping]] = ..., operator_signature: _Optional[_Union[_common_pb2.Signature, _Mapping]] = ...) -> None: ...

class AdmissionPolicy(_message.Message):
    __slots__ = ("closed", "open", "hybrid")
    CLOSED_FIELD_NUMBER: _ClassVar[int]
    OPEN_FIELD_NUMBER: _ClassVar[int]
    HYBRID_FIELD_NUMBER: _ClassVar[int]
    closed: ClosedPolicy
    open: OpenPolicy
    hybrid: HybridPolicy
    def __init__(self, closed: _Optional[_Union[ClosedPolicy, _Mapping]] = ..., open: _Optional[_Union[OpenPolicy, _Mapping]] = ..., hybrid: _Optional[_Union[HybridPolicy, _Mapping]] = ...) -> None: ...

class ClosedPolicy(_message.Message):
    __slots__ = ("allowlisted_agents", "allowlisted_owner_key_fingerprints", "pending_review_on_unknown")
    ALLOWLISTED_AGENTS_FIELD_NUMBER: _ClassVar[int]
    ALLOWLISTED_OWNER_KEY_FINGERPRINTS_FIELD_NUMBER: _ClassVar[int]
    PENDING_REVIEW_ON_UNKNOWN_FIELD_NUMBER: _ClassVar[int]
    allowlisted_agents: _containers.RepeatedCompositeFieldContainer[_common_pb2.AgentId]
    allowlisted_owner_key_fingerprints: _containers.RepeatedScalarFieldContainer[bytes]
    pending_review_on_unknown: bool
    def __init__(self, allowlisted_agents: _Optional[_Iterable[_Union[_common_pb2.AgentId, _Mapping]]] = ..., allowlisted_owner_key_fingerprints: _Optional[_Iterable[bytes]] = ..., pending_review_on_unknown: bool = ...) -> None: ...

class OpenPolicy(_message.Message):
    __slots__ = ("requirements", "min_passport_tier", "max_passport_lifetime_seconds", "default_initial_scope")
    REQUIREMENTS_FIELD_NUMBER: _ClassVar[int]
    MIN_PASSPORT_TIER_FIELD_NUMBER: _ClassVar[int]
    MAX_PASSPORT_LIFETIME_SECONDS_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_INITIAL_SCOPE_FIELD_NUMBER: _ClassVar[int]
    requirements: _containers.RepeatedCompositeFieldContainer[SybilResistanceRequirement]
    min_passport_tier: PassportTierRequirement
    max_passport_lifetime_seconds: int
    default_initial_scope: _capability_v1_pb2.Scope
    def __init__(self, requirements: _Optional[_Iterable[_Union[SybilResistanceRequirement, _Mapping]]] = ..., min_passport_tier: _Optional[_Union[PassportTierRequirement, _Mapping]] = ..., max_passport_lifetime_seconds: _Optional[int] = ..., default_initial_scope: _Optional[_Union[_capability_v1_pb2.Scope, _Mapping]] = ...) -> None: ...

class HybridPolicy(_message.Message):
    __slots__ = ("core", "periphery", "periphery_capability_constraint", "periphery_may_delegate")
    CORE_FIELD_NUMBER: _ClassVar[int]
    PERIPHERY_FIELD_NUMBER: _ClassVar[int]
    PERIPHERY_CAPABILITY_CONSTRAINT_FIELD_NUMBER: _ClassVar[int]
    PERIPHERY_MAY_DELEGATE_FIELD_NUMBER: _ClassVar[int]
    core: ClosedPolicy
    periphery: OpenPolicy
    periphery_capability_constraint: _capability_v1_pb2.Scope
    periphery_may_delegate: bool
    def __init__(self, core: _Optional[_Union[ClosedPolicy, _Mapping]] = ..., periphery: _Optional[_Union[OpenPolicy, _Mapping]] = ..., periphery_capability_constraint: _Optional[_Union[_capability_v1_pb2.Scope, _Mapping]] = ..., periphery_may_delegate: bool = ...) -> None: ...

class SybilResistanceRequirement(_message.Message):
    __slots__ = ("proof_of_work", "hardware_attestation", "idp_attestation", "stake", "invite")
    PROOF_OF_WORK_FIELD_NUMBER: _ClassVar[int]
    HARDWARE_ATTESTATION_FIELD_NUMBER: _ClassVar[int]
    IDP_ATTESTATION_FIELD_NUMBER: _ClassVar[int]
    STAKE_FIELD_NUMBER: _ClassVar[int]
    INVITE_FIELD_NUMBER: _ClassVar[int]
    proof_of_work: ProofOfWorkRequirement
    hardware_attestation: HardwareAttestationRequirement
    idp_attestation: IdpAttestationRequirement
    stake: StakeRequirement
    invite: InviteRequirement
    def __init__(self, proof_of_work: _Optional[_Union[ProofOfWorkRequirement, _Mapping]] = ..., hardware_attestation: _Optional[_Union[HardwareAttestationRequirement, _Mapping]] = ..., idp_attestation: _Optional[_Union[IdpAttestationRequirement, _Mapping]] = ..., stake: _Optional[_Union[StakeRequirement, _Mapping]] = ..., invite: _Optional[_Union[InviteRequirement, _Mapping]] = ...) -> None: ...

class ProofOfWorkRequirement(_message.Message):
    __slots__ = ("difficulty_bits", "challenge_prefix")
    DIFFICULTY_BITS_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_PREFIX_FIELD_NUMBER: _ClassVar[int]
    difficulty_bits: int
    challenge_prefix: bytes
    def __init__(self, difficulty_bits: _Optional[int] = ..., challenge_prefix: _Optional[bytes] = ...) -> None: ...

class HardwareAttestationRequirement(_message.Message):
    __slots__ = ("accepted_kinds",)
    class AttestationKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ATTESTATION_KIND_UNKNOWN: _ClassVar[HardwareAttestationRequirement.AttestationKind]
        ATTESTATION_KIND_NAUTILUS: _ClassVar[HardwareAttestationRequirement.AttestationKind]
        ATTESTATION_KIND_INTEL_SGX: _ClassVar[HardwareAttestationRequirement.AttestationKind]
        ATTESTATION_KIND_AMD_SEV: _ClassVar[HardwareAttestationRequirement.AttestationKind]
        ATTESTATION_KIND_TPM: _ClassVar[HardwareAttestationRequirement.AttestationKind]
    ATTESTATION_KIND_UNKNOWN: HardwareAttestationRequirement.AttestationKind
    ATTESTATION_KIND_NAUTILUS: HardwareAttestationRequirement.AttestationKind
    ATTESTATION_KIND_INTEL_SGX: HardwareAttestationRequirement.AttestationKind
    ATTESTATION_KIND_AMD_SEV: HardwareAttestationRequirement.AttestationKind
    ATTESTATION_KIND_TPM: HardwareAttestationRequirement.AttestationKind
    ACCEPTED_KINDS_FIELD_NUMBER: _ClassVar[int]
    accepted_kinds: _containers.RepeatedScalarFieldContainer[HardwareAttestationRequirement.AttestationKind]
    def __init__(self, accepted_kinds: _Optional[_Iterable[_Union[HardwareAttestationRequirement.AttestationKind, str]]] = ...) -> None: ...

class IdpAttestationRequirement(_message.Message):
    __slots__ = ("accepted_issuers", "accepted_formats")
    ACCEPTED_ISSUERS_FIELD_NUMBER: _ClassVar[int]
    ACCEPTED_FORMATS_FIELD_NUMBER: _ClassVar[int]
    accepted_issuers: _containers.RepeatedScalarFieldContainer[str]
    accepted_formats: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, accepted_issuers: _Optional[_Iterable[str]] = ..., accepted_formats: _Optional[_Iterable[str]] = ...) -> None: ...

class StakeRequirement(_message.Message):
    __slots__ = ("stake_resource", "min_stake_amount", "slashing_endpoint")
    STAKE_RESOURCE_FIELD_NUMBER: _ClassVar[int]
    MIN_STAKE_AMOUNT_FIELD_NUMBER: _ClassVar[int]
    SLASHING_ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    stake_resource: str
    min_stake_amount: str
    slashing_endpoint: str
    def __init__(self, stake_resource: _Optional[str] = ..., min_stake_amount: _Optional[str] = ..., slashing_endpoint: _Optional[str] = ...) -> None: ...

class InviteRequirement(_message.Message):
    __slots__ = ("permitted_inviters", "max_invites_per_inviter", "invite_window_seconds")
    PERMITTED_INVITERS_FIELD_NUMBER: _ClassVar[int]
    MAX_INVITES_PER_INVITER_FIELD_NUMBER: _ClassVar[int]
    INVITE_WINDOW_SECONDS_FIELD_NUMBER: _ClassVar[int]
    permitted_inviters: _containers.RepeatedCompositeFieldContainer[_common_pb2.AgentId]
    max_invites_per_inviter: int
    invite_window_seconds: int
    def __init__(self, permitted_inviters: _Optional[_Iterable[_Union[_common_pb2.AgentId, _Mapping]]] = ..., max_invites_per_inviter: _Optional[int] = ..., invite_window_seconds: _Optional[int] = ...) -> None: ...

class PassportTierRequirement(_message.Message):
    __slots__ = ("required",)
    class Required(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        PASSPORT_TIER_REQUIREMENT_UNKNOWN: _ClassVar[PassportTierRequirement.Required]
        PASSPORT_TIER_REQUIREMENT_MINIMAL: _ClassVar[PassportTierRequirement.Required]
        PASSPORT_TIER_REQUIREMENT_STANDARD: _ClassVar[PassportTierRequirement.Required]
        PASSPORT_TIER_REQUIREMENT_VERIFIABLE: _ClassVar[PassportTierRequirement.Required]
    PASSPORT_TIER_REQUIREMENT_UNKNOWN: PassportTierRequirement.Required
    PASSPORT_TIER_REQUIREMENT_MINIMAL: PassportTierRequirement.Required
    PASSPORT_TIER_REQUIREMENT_STANDARD: PassportTierRequirement.Required
    PASSPORT_TIER_REQUIREMENT_VERIFIABLE: PassportTierRequirement.Required
    REQUIRED_FIELD_NUMBER: _ClassVar[int]
    required: PassportTierRequirement.Required
    def __init__(self, required: _Optional[_Union[PassportTierRequirement.Required, str]] = ...) -> None: ...

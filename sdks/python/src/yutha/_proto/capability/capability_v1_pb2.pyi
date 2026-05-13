import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CapabilitySignatureRole(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CAPABILITY_SIGNATURE_ROLE_UNKNOWN: _ClassVar[CapabilitySignatureRole]
    CAPABILITY_SIGNATURE_ROLE_ISSUER: _ClassVar[CapabilitySignatureRole]
    CAPABILITY_SIGNATURE_ROLE_ATTESTATION: _ClassVar[CapabilitySignatureRole]
CAPABILITY_SIGNATURE_ROLE_UNKNOWN: CapabilitySignatureRole
CAPABILITY_SIGNATURE_ROLE_ISSUER: CapabilitySignatureRole
CAPABILITY_SIGNATURE_ROLE_ATTESTATION: CapabilitySignatureRole

class Capability(_message.Message):
    __slots__ = ("spec_version", "capability_id", "swarm_id", "issuer", "subject", "scope", "parent", "valid_from", "valid_until", "caveats", "revocation_endpoint", "extensions", "signatures")
    SPEC_VERSION_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_ID_FIELD_NUMBER: _ClassVar[int]
    SWARM_ID_FIELD_NUMBER: _ClassVar[int]
    ISSUER_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    PARENT_FIELD_NUMBER: _ClassVar[int]
    VALID_FROM_FIELD_NUMBER: _ClassVar[int]
    VALID_UNTIL_FIELD_NUMBER: _ClassVar[int]
    CAVEATS_FIELD_NUMBER: _ClassVar[int]
    REVOCATION_ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    EXTENSIONS_FIELD_NUMBER: _ClassVar[int]
    SIGNATURES_FIELD_NUMBER: _ClassVar[int]
    spec_version: _common_pb2.Version
    capability_id: bytes
    swarm_id: _common_pb2.SwarmId
    issuer: Issuer
    subject: _common_pb2.AgentId
    scope: Scope
    parent: _common_pb2.Hash
    valid_from: _common_pb2.Timestamp
    valid_until: _common_pb2.Timestamp
    caveats: _containers.RepeatedCompositeFieldContainer[Caveat]
    revocation_endpoint: str
    extensions: _common_pb2.Extensions
    signatures: _containers.RepeatedCompositeFieldContainer[CapabilitySignature]
    def __init__(self, spec_version: _Optional[_Union[_common_pb2.Version, _Mapping]] = ..., capability_id: _Optional[bytes] = ..., swarm_id: _Optional[_Union[_common_pb2.SwarmId, _Mapping]] = ..., issuer: _Optional[_Union[Issuer, _Mapping]] = ..., subject: _Optional[_Union[_common_pb2.AgentId, _Mapping]] = ..., scope: _Optional[_Union[Scope, _Mapping]] = ..., parent: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., valid_from: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ..., valid_until: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ..., caveats: _Optional[_Iterable[_Union[Caveat, _Mapping]]] = ..., revocation_endpoint: _Optional[str] = ..., extensions: _Optional[_Union[_common_pb2.Extensions, _Mapping]] = ..., signatures: _Optional[_Iterable[_Union[CapabilitySignature, _Mapping]]] = ...) -> None: ...

class Issuer(_message.Message):
    __slots__ = ("agent", "operator_key_fingerprint", "control_plane")
    AGENT_FIELD_NUMBER: _ClassVar[int]
    OPERATOR_KEY_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    CONTROL_PLANE_FIELD_NUMBER: _ClassVar[int]
    agent: _common_pb2.AgentId
    operator_key_fingerprint: bytes
    control_plane: ControlPlaneIssuer
    def __init__(self, agent: _Optional[_Union[_common_pb2.AgentId, _Mapping]] = ..., operator_key_fingerprint: _Optional[bytes] = ..., control_plane: _Optional[_Union[ControlPlaneIssuer, _Mapping]] = ...) -> None: ...

class ControlPlaneIssuer(_message.Message):
    __slots__ = ("control_plane_key_fingerprint", "instance_id")
    CONTROL_PLANE_KEY_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    INSTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    control_plane_key_fingerprint: bytes
    instance_id: str
    def __init__(self, control_plane_key_fingerprint: _Optional[bytes] = ..., instance_id: _Optional[str] = ...) -> None: ...

class Scope(_message.Message):
    __slots__ = ("permitted_actions", "resource_tags", "bounds", "permitted_recipients", "memory_scopes")
    class BoundsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    PERMITTED_ACTIONS_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_TAGS_FIELD_NUMBER: _ClassVar[int]
    BOUNDS_FIELD_NUMBER: _ClassVar[int]
    PERMITTED_RECIPIENTS_FIELD_NUMBER: _ClassVar[int]
    MEMORY_SCOPES_FIELD_NUMBER: _ClassVar[int]
    permitted_actions: _containers.RepeatedScalarFieldContainer[str]
    resource_tags: _containers.RepeatedScalarFieldContainer[str]
    bounds: _containers.ScalarMap[str, str]
    permitted_recipients: _containers.RepeatedScalarFieldContainer[str]
    memory_scopes: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, permitted_actions: _Optional[_Iterable[str]] = ..., resource_tags: _Optional[_Iterable[str]] = ..., bounds: _Optional[_Mapping[str, str]] = ..., permitted_recipients: _Optional[_Iterable[str]] = ..., memory_scopes: _Optional[_Iterable[str]] = ...) -> None: ...

class Caveat(_message.Message):
    __slots__ = ("time_of_day", "constitution_version", "supervisor_required", "rate_limit", "only_if_tagged", "never_if_tagged")
    TIME_OF_DAY_FIELD_NUMBER: _ClassVar[int]
    CONSTITUTION_VERSION_FIELD_NUMBER: _ClassVar[int]
    SUPERVISOR_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    RATE_LIMIT_FIELD_NUMBER: _ClassVar[int]
    ONLY_IF_TAGGED_FIELD_NUMBER: _ClassVar[int]
    NEVER_IF_TAGGED_FIELD_NUMBER: _ClassVar[int]
    time_of_day: TimeOfDayCaveat
    constitution_version: ConstitutionVersionCaveat
    supervisor_required: SupervisorRequiredCaveat
    rate_limit: RateLimitCaveat
    only_if_tagged: OnlyIfTaggedCaveat
    never_if_tagged: NeverIfTaggedCaveat
    def __init__(self, time_of_day: _Optional[_Union[TimeOfDayCaveat, _Mapping]] = ..., constitution_version: _Optional[_Union[ConstitutionVersionCaveat, _Mapping]] = ..., supervisor_required: _Optional[_Union[SupervisorRequiredCaveat, _Mapping]] = ..., rate_limit: _Optional[_Union[RateLimitCaveat, _Mapping]] = ..., only_if_tagged: _Optional[_Union[OnlyIfTaggedCaveat, _Mapping]] = ..., never_if_tagged: _Optional[_Union[NeverIfTaggedCaveat, _Mapping]] = ...) -> None: ...

class TimeOfDayCaveat(_message.Message):
    __slots__ = ("from_utc", "to_utc")
    FROM_UTC_FIELD_NUMBER: _ClassVar[int]
    TO_UTC_FIELD_NUMBER: _ClassVar[int]
    from_utc: str
    to_utc: str
    def __init__(self, from_utc: _Optional[str] = ..., to_utc: _Optional[str] = ...) -> None: ...

class ConstitutionVersionCaveat(_message.Message):
    __slots__ = ("min_version", "max_version")
    MIN_VERSION_FIELD_NUMBER: _ClassVar[int]
    MAX_VERSION_FIELD_NUMBER: _ClassVar[int]
    min_version: str
    max_version: str
    def __init__(self, min_version: _Optional[str] = ..., max_version: _Optional[str] = ...) -> None: ...

class SupervisorRequiredCaveat(_message.Message):
    __slots__ = ("supervisor_role",)
    SUPERVISOR_ROLE_FIELD_NUMBER: _ClassVar[int]
    supervisor_role: str
    def __init__(self, supervisor_role: _Optional[str] = ...) -> None: ...

class RateLimitCaveat(_message.Message):
    __slots__ = ("max_actions", "window_seconds")
    MAX_ACTIONS_FIELD_NUMBER: _ClassVar[int]
    WINDOW_SECONDS_FIELD_NUMBER: _ClassVar[int]
    max_actions: int
    window_seconds: int
    def __init__(self, max_actions: _Optional[int] = ..., window_seconds: _Optional[int] = ...) -> None: ...

class OnlyIfTaggedCaveat(_message.Message):
    __slots__ = ("required_tags",)
    REQUIRED_TAGS_FIELD_NUMBER: _ClassVar[int]
    required_tags: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, required_tags: _Optional[_Iterable[str]] = ...) -> None: ...

class NeverIfTaggedCaveat(_message.Message):
    __slots__ = ("forbidden_tags",)
    FORBIDDEN_TAGS_FIELD_NUMBER: _ClassVar[int]
    forbidden_tags: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, forbidden_tags: _Optional[_Iterable[str]] = ...) -> None: ...

class CapabilitySignature(_message.Message):
    __slots__ = ("role", "signature", "signed_at")
    ROLE_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SIGNED_AT_FIELD_NUMBER: _ClassVar[int]
    role: CapabilitySignatureRole
    signature: _common_pb2.Signature
    signed_at: _common_pb2.Timestamp
    def __init__(self, role: _Optional[_Union[CapabilitySignatureRole, str]] = ..., signature: _Optional[_Union[_common_pb2.Signature, _Mapping]] = ..., signed_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class IssueRequest(_message.Message):
    __slots__ = ("capability",)
    CAPABILITY_FIELD_NUMBER: _ClassVar[int]
    capability: Capability
    def __init__(self, capability: _Optional[_Union[Capability, _Mapping]] = ...) -> None: ...

class IssueResponse(_message.Message):
    __slots__ = ("capability_id", "issuance_receipt")
    CAPABILITY_ID_FIELD_NUMBER: _ClassVar[int]
    ISSUANCE_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    capability_id: _common_pb2.Hash
    issuance_receipt: _common_pb2.Hash
    def __init__(self, capability_id: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., issuance_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class AttenuateRequest(_message.Message):
    __slots__ = ("parent", "additional_constraints", "additional_caveats", "valid_until")
    PARENT_FIELD_NUMBER: _ClassVar[int]
    ADDITIONAL_CONSTRAINTS_FIELD_NUMBER: _ClassVar[int]
    ADDITIONAL_CAVEATS_FIELD_NUMBER: _ClassVar[int]
    VALID_UNTIL_FIELD_NUMBER: _ClassVar[int]
    parent: _common_pb2.Hash
    additional_constraints: Scope
    additional_caveats: _containers.RepeatedCompositeFieldContainer[Caveat]
    valid_until: _common_pb2.Timestamp
    def __init__(self, parent: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., additional_constraints: _Optional[_Union[Scope, _Mapping]] = ..., additional_caveats: _Optional[_Iterable[_Union[Caveat, _Mapping]]] = ..., valid_until: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class AttenuateResponse(_message.Message):
    __slots__ = ("child", "attenuation_receipt")
    CHILD_FIELD_NUMBER: _ClassVar[int]
    ATTENUATION_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    child: Capability
    attenuation_receipt: _common_pb2.Hash
    def __init__(self, child: _Optional[_Union[Capability, _Mapping]] = ..., attenuation_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class RevokeRequest(_message.Message):
    __slots__ = ("capability", "reason")
    CAPABILITY_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    capability: _common_pb2.Hash
    reason: str
    def __init__(self, capability: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., reason: _Optional[str] = ...) -> None: ...

class RevokeResponse(_message.Message):
    __slots__ = ("revocation_receipt", "effective_at")
    REVOCATION_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    EFFECTIVE_AT_FIELD_NUMBER: _ClassVar[int]
    revocation_receipt: _common_pb2.Hash
    effective_at: _common_pb2.Timestamp
    def __init__(self, revocation_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., effective_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class CheckRequest(_message.Message):
    __slots__ = ("capability", "action", "at_time")
    CAPABILITY_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    AT_TIME_FIELD_NUMBER: _ClassVar[int]
    capability: Capability
    action: ActionDescriptor
    at_time: _common_pb2.Timestamp
    def __init__(self, capability: _Optional[_Union[Capability, _Mapping]] = ..., action: _Optional[_Union[ActionDescriptor, _Mapping]] = ..., at_time: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class CheckResponse(_message.Message):
    __slots__ = ("permitted", "deny_reason", "matched_caveats", "unmet_caveats", "check_receipt")
    PERMITTED_FIELD_NUMBER: _ClassVar[int]
    DENY_REASON_FIELD_NUMBER: _ClassVar[int]
    MATCHED_CAVEATS_FIELD_NUMBER: _ClassVar[int]
    UNMET_CAVEATS_FIELD_NUMBER: _ClassVar[int]
    CHECK_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    permitted: bool
    deny_reason: str
    matched_caveats: _containers.RepeatedScalarFieldContainer[str]
    unmet_caveats: _containers.RepeatedScalarFieldContainer[str]
    check_receipt: _common_pb2.Hash
    def __init__(self, permitted: bool = ..., deny_reason: _Optional[str] = ..., matched_caveats: _Optional[_Iterable[str]] = ..., unmet_caveats: _Optional[_Iterable[str]] = ..., check_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class ActionDescriptor(_message.Message):
    __slots__ = ("action_kind", "resource_tags", "numeric_values", "recipient", "memory_scope")
    class NumericValuesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ACTION_KIND_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_TAGS_FIELD_NUMBER: _ClassVar[int]
    NUMERIC_VALUES_FIELD_NUMBER: _ClassVar[int]
    RECIPIENT_FIELD_NUMBER: _ClassVar[int]
    MEMORY_SCOPE_FIELD_NUMBER: _ClassVar[int]
    action_kind: str
    resource_tags: _containers.RepeatedScalarFieldContainer[str]
    numeric_values: _containers.ScalarMap[str, str]
    recipient: str
    memory_scope: str
    def __init__(self, action_kind: _Optional[str] = ..., resource_tags: _Optional[_Iterable[str]] = ..., numeric_values: _Optional[_Mapping[str, str]] = ..., recipient: _Optional[str] = ..., memory_scope: _Optional[str] = ...) -> None: ...

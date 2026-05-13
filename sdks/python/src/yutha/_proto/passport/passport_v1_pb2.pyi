import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class PassportTier(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PASSPORT_TIER_UNKNOWN: _ClassVar[PassportTier]
    PASSPORT_TIER_MINIMAL: _ClassVar[PassportTier]
    PASSPORT_TIER_STANDARD: _ClassVar[PassportTier]
    PASSPORT_TIER_VERIFIABLE: _ClassVar[PassportTier]
PASSPORT_TIER_UNKNOWN: PassportTier
PASSPORT_TIER_MINIMAL: PassportTier
PASSPORT_TIER_STANDARD: PassportTier
PASSPORT_TIER_VERIFIABLE: PassportTier

class Passport(_message.Message):
    __slots__ = ("spec_version", "agent_id", "swarm_id", "agent_public_key", "owner", "framework", "framework_version", "capabilities", "accepted_constitution_version", "tier", "resources", "issued_at", "expires_at", "default_model_provider", "default_model_name", "extensions", "agent_signature")
    SPEC_VERSION_FIELD_NUMBER: _ClassVar[int]
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    SWARM_ID_FIELD_NUMBER: _ClassVar[int]
    AGENT_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    FRAMEWORK_FIELD_NUMBER: _ClassVar[int]
    FRAMEWORK_VERSION_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    ACCEPTED_CONSTITUTION_VERSION_FIELD_NUMBER: _ClassVar[int]
    TIER_FIELD_NUMBER: _ClassVar[int]
    RESOURCES_FIELD_NUMBER: _ClassVar[int]
    ISSUED_AT_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_MODEL_PROVIDER_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_MODEL_NAME_FIELD_NUMBER: _ClassVar[int]
    EXTENSIONS_FIELD_NUMBER: _ClassVar[int]
    AGENT_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    spec_version: _common_pb2.Version
    agent_id: _common_pb2.AgentId
    swarm_id: _common_pb2.SwarmId
    agent_public_key: _common_pb2.PublicKey
    owner: str
    framework: str
    framework_version: str
    capabilities: _containers.RepeatedCompositeFieldContainer[CapabilityDeclaration]
    accepted_constitution_version: str
    tier: PassportTier
    resources: ResourceDeclaration
    issued_at: _common_pb2.Timestamp
    expires_at: _common_pb2.Timestamp
    default_model_provider: str
    default_model_name: str
    extensions: _common_pb2.Extensions
    agent_signature: _common_pb2.Signature
    def __init__(self, spec_version: _Optional[_Union[_common_pb2.Version, _Mapping]] = ..., agent_id: _Optional[_Union[_common_pb2.AgentId, _Mapping]] = ..., swarm_id: _Optional[_Union[_common_pb2.SwarmId, _Mapping]] = ..., agent_public_key: _Optional[_Union[_common_pb2.PublicKey, _Mapping]] = ..., owner: _Optional[str] = ..., framework: _Optional[str] = ..., framework_version: _Optional[str] = ..., capabilities: _Optional[_Iterable[_Union[CapabilityDeclaration, _Mapping]]] = ..., accepted_constitution_version: _Optional[str] = ..., tier: _Optional[_Union[PassportTier, str]] = ..., resources: _Optional[_Union[ResourceDeclaration, _Mapping]] = ..., issued_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ..., expires_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ..., default_model_provider: _Optional[str] = ..., default_model_name: _Optional[str] = ..., extensions: _Optional[_Union[_common_pb2.Extensions, _Mapping]] = ..., agent_signature: _Optional[_Union[_common_pb2.Signature, _Mapping]] = ...) -> None: ...

class CapabilityDeclaration(_message.Message):
    __slots__ = ("kind", "resource_tags", "bounds", "description")
    class BoundsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    KIND_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_TAGS_FIELD_NUMBER: _ClassVar[int]
    BOUNDS_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    kind: str
    resource_tags: _containers.RepeatedScalarFieldContainer[str]
    bounds: _containers.ScalarMap[str, str]
    description: str
    def __init__(self, kind: _Optional[str] = ..., resource_tags: _Optional[_Iterable[str]] = ..., bounds: _Optional[_Mapping[str, str]] = ..., description: _Optional[str] = ...) -> None: ...

class ResourceDeclaration(_message.Message):
    __slots__ = ("max_concurrent_actions", "max_messages_per_minute", "max_tool_calls_per_hour", "max_usd_per_day_cents", "max_memory_bytes")
    MAX_CONCURRENT_ACTIONS_FIELD_NUMBER: _ClassVar[int]
    MAX_MESSAGES_PER_MINUTE_FIELD_NUMBER: _ClassVar[int]
    MAX_TOOL_CALLS_PER_HOUR_FIELD_NUMBER: _ClassVar[int]
    MAX_USD_PER_DAY_CENTS_FIELD_NUMBER: _ClassVar[int]
    MAX_MEMORY_BYTES_FIELD_NUMBER: _ClassVar[int]
    max_concurrent_actions: int
    max_messages_per_minute: int
    max_tool_calls_per_hour: int
    max_usd_per_day_cents: str
    max_memory_bytes: int
    def __init__(self, max_concurrent_actions: _Optional[int] = ..., max_messages_per_minute: _Optional[int] = ..., max_tool_calls_per_hour: _Optional[int] = ..., max_usd_per_day_cents: _Optional[str] = ..., max_memory_bytes: _Optional[int] = ...) -> None: ...

class RegistrationResult(_message.Message):
    __slots__ = ("status", "agent_id", "registration_receipt", "rejection_reason")
    class Status(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        REGISTRATION_STATUS_UNKNOWN: _ClassVar[RegistrationResult.Status]
        REGISTRATION_STATUS_ACCEPTED: _ClassVar[RegistrationResult.Status]
        REGISTRATION_STATUS_REJECTED: _ClassVar[RegistrationResult.Status]
        REGISTRATION_STATUS_PENDING_REVIEW: _ClassVar[RegistrationResult.Status]
    REGISTRATION_STATUS_UNKNOWN: RegistrationResult.Status
    REGISTRATION_STATUS_ACCEPTED: RegistrationResult.Status
    REGISTRATION_STATUS_REJECTED: RegistrationResult.Status
    REGISTRATION_STATUS_PENDING_REVIEW: RegistrationResult.Status
    STATUS_FIELD_NUMBER: _ClassVar[int]
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    REGISTRATION_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    REJECTION_REASON_FIELD_NUMBER: _ClassVar[int]
    status: RegistrationResult.Status
    agent_id: _common_pb2.AgentId
    registration_receipt: _common_pb2.Hash
    rejection_reason: str
    def __init__(self, status: _Optional[_Union[RegistrationResult.Status, str]] = ..., agent_id: _Optional[_Union[_common_pb2.AgentId, _Mapping]] = ..., registration_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., rejection_reason: _Optional[str] = ...) -> None: ...

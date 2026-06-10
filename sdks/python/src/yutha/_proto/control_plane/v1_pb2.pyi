import common_pb2 as _common_pb2
from passport import passport_v1_pb2 as _passport_v1_pb2
from envelope import envelope_v1_pb2 as _envelope_v1_pb2
from receipt import receipt_v1_pb2 as _receipt_v1_pb2
from capability import capability_v1_pb2 as _capability_v1_pb2
from topology import topology_v1_pb2 as _topology_v1_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ReplayMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    REPLAY_MODE_COLD: _ClassVar[ReplayMode]
    REPLAY_MODE_WARM: _ClassVar[ReplayMode]
REPLAY_MODE_COLD: ReplayMode
REPLAY_MODE_WARM: ReplayMode

class AgentBearerToken(_message.Message):
    __slots__ = ("agent_id", "swarm_id", "issued_at", "expires_at", "nonce", "extensions", "signature")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    SWARM_ID_FIELD_NUMBER: _ClassVar[int]
    ISSUED_AT_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    NONCE_FIELD_NUMBER: _ClassVar[int]
    EXTENSIONS_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    agent_id: _common_pb2.AgentId
    swarm_id: _common_pb2.SwarmId
    issued_at: _common_pb2.Timestamp
    expires_at: _common_pb2.Timestamp
    nonce: bytes
    extensions: _common_pb2.Extensions
    signature: _common_pb2.Signature
    def __init__(self, agent_id: _Optional[_Union[_common_pb2.AgentId, _Mapping]] = ..., swarm_id: _Optional[_Union[_common_pb2.SwarmId, _Mapping]] = ..., issued_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ..., expires_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ..., nonce: _Optional[bytes] = ..., extensions: _Optional[_Union[_common_pb2.Extensions, _Mapping]] = ..., signature: _Optional[_Union[_common_pb2.Signature, _Mapping]] = ...) -> None: ...

class OperatorBearerToken(_message.Message):
    __slots__ = ("operator_id", "swarm_id", "issued_at", "expires_at", "nonce", "extensions", "signature")
    OPERATOR_ID_FIELD_NUMBER: _ClassVar[int]
    SWARM_ID_FIELD_NUMBER: _ClassVar[int]
    ISSUED_AT_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    NONCE_FIELD_NUMBER: _ClassVar[int]
    EXTENSIONS_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    operator_id: str
    swarm_id: _common_pb2.SwarmId
    issued_at: _common_pb2.Timestamp
    expires_at: _common_pb2.Timestamp
    nonce: bytes
    extensions: _common_pb2.Extensions
    signature: _common_pb2.Signature
    def __init__(self, operator_id: _Optional[str] = ..., swarm_id: _Optional[_Union[_common_pb2.SwarmId, _Mapping]] = ..., issued_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ..., expires_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ..., nonce: _Optional[bytes] = ..., extensions: _Optional[_Union[_common_pb2.Extensions, _Mapping]] = ..., signature: _Optional[_Union[_common_pb2.Signature, _Mapping]] = ...) -> None: ...

class RegisterRequest(_message.Message):
    __slots__ = ("passport", "external_credential")
    PASSPORT_FIELD_NUMBER: _ClassVar[int]
    EXTERNAL_CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    passport: _passport_v1_pb2.Passport
    external_credential: bytes
    def __init__(self, passport: _Optional[_Union[_passport_v1_pb2.Passport, _Mapping]] = ..., external_credential: _Optional[bytes] = ...) -> None: ...

class RegisterResponse(_message.Message):
    __slots__ = ("result",)
    RESULT_FIELD_NUMBER: _ClassVar[int]
    result: _passport_v1_pb2.RegistrationResult
    def __init__(self, result: _Optional[_Union[_passport_v1_pb2.RegistrationResult, _Mapping]] = ...) -> None: ...

class RevokeRequest(_message.Message):
    __slots__ = ("agent_id", "reason")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    agent_id: _common_pb2.AgentId
    reason: str
    def __init__(self, agent_id: _Optional[_Union[_common_pb2.AgentId, _Mapping]] = ..., reason: _Optional[str] = ...) -> None: ...

class RevokeResponse(_message.Message):
    __slots__ = ("revocation_receipt",)
    REVOCATION_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    revocation_receipt: _common_pb2.Hash
    def __init__(self, revocation_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class OperatorRevokeRequest(_message.Message):
    __slots__ = ("target", "reason", "cascade_capabilities")
    TARGET_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    CASCADE_CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    target: _common_pb2.AgentId
    reason: str
    cascade_capabilities: bool
    def __init__(self, target: _Optional[_Union[_common_pb2.AgentId, _Mapping]] = ..., reason: _Optional[str] = ..., cascade_capabilities: _Optional[bool] = ...) -> None: ...

class OperatorRevokeResponse(_message.Message):
    __slots__ = ("revocation_receipt", "cascade_receipts")
    REVOCATION_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    CASCADE_RECEIPTS_FIELD_NUMBER: _ClassVar[int]
    revocation_receipt: _common_pb2.Hash
    cascade_receipts: _containers.RepeatedCompositeFieldContainer[_common_pb2.Hash]
    def __init__(self, revocation_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., cascade_receipts: _Optional[_Iterable[_Union[_common_pb2.Hash, _Mapping]]] = ...) -> None: ...

class RotateKeyRequest(_message.Message):
    __slots__ = ("agent_id", "new_public_key", "authorization_signature")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    NEW_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    AUTHORIZATION_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    agent_id: _common_pb2.AgentId
    new_public_key: _common_pb2.PublicKey
    authorization_signature: _common_pb2.Signature
    def __init__(self, agent_id: _Optional[_Union[_common_pb2.AgentId, _Mapping]] = ..., new_public_key: _Optional[_Union[_common_pb2.PublicKey, _Mapping]] = ..., authorization_signature: _Optional[_Union[_common_pb2.Signature, _Mapping]] = ...) -> None: ...

class RotateKeyResponse(_message.Message):
    __slots__ = ("rotation_receipt",)
    ROTATION_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    rotation_receipt: _common_pb2.Hash
    def __init__(self, rotation_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class GetTopologyRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetTopologyResponse(_message.Message):
    __slots__ = ("topology",)
    TOPOLOGY_FIELD_NUMBER: _ClassVar[int]
    topology: _topology_v1_pb2.Topology
    def __init__(self, topology: _Optional[_Union[_topology_v1_pb2.Topology, _Mapping]] = ...) -> None: ...

class IssueCapabilityRequest(_message.Message):
    __slots__ = ("capability",)
    CAPABILITY_FIELD_NUMBER: _ClassVar[int]
    capability: _capability_v1_pb2.Capability
    def __init__(self, capability: _Optional[_Union[_capability_v1_pb2.Capability, _Mapping]] = ...) -> None: ...

class IssueCapabilityResponse(_message.Message):
    __slots__ = ("capability_id", "issuance_receipt")
    CAPABILITY_ID_FIELD_NUMBER: _ClassVar[int]
    ISSUANCE_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    capability_id: _common_pb2.Hash
    issuance_receipt: _common_pb2.Hash
    def __init__(self, capability_id: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., issuance_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class AttenuateRequest(_message.Message):
    __slots__ = ("request",)
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    request: _capability_v1_pb2.AttenuateRequest
    def __init__(self, request: _Optional[_Union[_capability_v1_pb2.AttenuateRequest, _Mapping]] = ...) -> None: ...

class AttenuateResponse(_message.Message):
    __slots__ = ("response",)
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    response: _capability_v1_pb2.AttenuateResponse
    def __init__(self, response: _Optional[_Union[_capability_v1_pb2.AttenuateResponse, _Mapping]] = ...) -> None: ...

class RevokeCapabilityRequest(_message.Message):
    __slots__ = ("request",)
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    request: _capability_v1_pb2.RevokeRequest
    def __init__(self, request: _Optional[_Union[_capability_v1_pb2.RevokeRequest, _Mapping]] = ...) -> None: ...

class RevokeCapabilityResponse(_message.Message):
    __slots__ = ("response",)
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    response: _capability_v1_pb2.RevokeResponse
    def __init__(self, response: _Optional[_Union[_capability_v1_pb2.RevokeResponse, _Mapping]] = ...) -> None: ...

class CheckRequest(_message.Message):
    __slots__ = ("request",)
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    request: _capability_v1_pb2.CheckRequest
    def __init__(self, request: _Optional[_Union[_capability_v1_pb2.CheckRequest, _Mapping]] = ...) -> None: ...

class CheckResponse(_message.Message):
    __slots__ = ("response",)
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    response: _capability_v1_pb2.CheckResponse
    def __init__(self, response: _Optional[_Union[_capability_v1_pb2.CheckResponse, _Mapping]] = ...) -> None: ...

class SendEnvelopeRequest(_message.Message):
    __slots__ = ("envelope", "capability_id")
    ENVELOPE_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_ID_FIELD_NUMBER: _ClassVar[int]
    envelope: _envelope_v1_pb2.Envelope
    capability_id: _common_pb2.Hash
    def __init__(self, envelope: _Optional[_Union[_envelope_v1_pb2.Envelope, _Mapping]] = ..., capability_id: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class SendEnvelopeResponse(_message.Message):
    __slots__ = ("send_receipt",)
    SEND_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    send_receipt: _common_pb2.Hash
    def __init__(self, send_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class SubscribeRequest(_message.Message):
    __slots__ = ("agent_id",)
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    agent_id: _common_pb2.AgentId
    def __init__(self, agent_id: _Optional[_Union[_common_pb2.AgentId, _Mapping]] = ...) -> None: ...

class SubscribedEnvelope(_message.Message):
    __slots__ = ("envelope", "deliver_receipt")
    ENVELOPE_FIELD_NUMBER: _ClassVar[int]
    DELIVER_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    envelope: _envelope_v1_pb2.Envelope
    deliver_receipt: _common_pb2.Hash
    def __init__(self, envelope: _Optional[_Union[_envelope_v1_pb2.Envelope, _Mapping]] = ..., deliver_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class GetReceiptRequest(_message.Message):
    __slots__ = ("receipt_id",)
    RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    receipt_id: _common_pb2.Hash
    def __init__(self, receipt_id: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class GetReceiptResponse(_message.Message):
    __slots__ = ("receipt",)
    RECEIPT_FIELD_NUMBER: _ClassVar[int]
    receipt: _receipt_v1_pb2.Receipt
    def __init__(self, receipt: _Optional[_Union[_receipt_v1_pb2.Receipt, _Mapping]] = ...) -> None: ...

class QueryReceiptsRequest(_message.Message):
    __slots__ = ("query",)
    QUERY_FIELD_NUMBER: _ClassVar[int]
    query: _receipt_v1_pb2.QueryRequest
    def __init__(self, query: _Optional[_Union[_receipt_v1_pb2.QueryRequest, _Mapping]] = ...) -> None: ...

class QueryReceiptsResponse(_message.Message):
    __slots__ = ("receipts", "next_page_token")
    RECEIPTS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    receipts: _containers.RepeatedCompositeFieldContainer[_receipt_v1_pb2.Receipt]
    next_page_token: bytes
    def __init__(self, receipts: _Optional[_Iterable[_Union[_receipt_v1_pb2.Receipt, _Mapping]]] = ..., next_page_token: _Optional[bytes] = ...) -> None: ...

class Constitution(_message.Message):
    __slots__ = ("spec_version", "schema_version", "constitution_version", "parent_version", "swarm_id", "cedar_source", "engine_config_yaml", "issued_at")
    SPEC_VERSION_FIELD_NUMBER: _ClassVar[int]
    SCHEMA_VERSION_FIELD_NUMBER: _ClassVar[int]
    CONSTITUTION_VERSION_FIELD_NUMBER: _ClassVar[int]
    PARENT_VERSION_FIELD_NUMBER: _ClassVar[int]
    SWARM_ID_FIELD_NUMBER: _ClassVar[int]
    CEDAR_SOURCE_FIELD_NUMBER: _ClassVar[int]
    ENGINE_CONFIG_YAML_FIELD_NUMBER: _ClassVar[int]
    ISSUED_AT_FIELD_NUMBER: _ClassVar[int]
    spec_version: _common_pb2.Version
    schema_version: str
    constitution_version: str
    parent_version: _common_pb2.Hash
    swarm_id: _common_pb2.SwarmId
    cedar_source: str
    engine_config_yaml: str
    issued_at: _common_pb2.Timestamp
    def __init__(self, spec_version: _Optional[_Union[_common_pb2.Version, _Mapping]] = ..., schema_version: _Optional[str] = ..., constitution_version: _Optional[str] = ..., parent_version: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., swarm_id: _Optional[_Union[_common_pb2.SwarmId, _Mapping]] = ..., cedar_source: _Optional[str] = ..., engine_config_yaml: _Optional[str] = ..., issued_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ActivateConstitutionRequest(_message.Message):
    __slots__ = ("constitution",)
    CONSTITUTION_FIELD_NUMBER: _ClassVar[int]
    constitution: Constitution
    def __init__(self, constitution: _Optional[_Union[Constitution, _Mapping]] = ...) -> None: ...

class ActivateConstitutionResponse(_message.Message):
    __slots__ = ("constitution_hash", "activate_receipt")
    CONSTITUTION_HASH_FIELD_NUMBER: _ClassVar[int]
    ACTIVATE_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    constitution_hash: _common_pb2.Hash
    activate_receipt: _common_pb2.Hash
    def __init__(self, constitution_hash: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., activate_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class GetActiveConstitutionRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetActiveConstitutionResponse(_message.Message):
    __slots__ = ("constitution", "constitution_hash")
    CONSTITUTION_FIELD_NUMBER: _ClassVar[int]
    CONSTITUTION_HASH_FIELD_NUMBER: _ClassVar[int]
    constitution: Constitution
    constitution_hash: _common_pb2.Hash
    def __init__(self, constitution: _Optional[_Union[Constitution, _Mapping]] = ..., constitution_hash: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class ActivateShadowConstitutionRequest(_message.Message):
    __slots__ = ("constitution",)
    CONSTITUTION_FIELD_NUMBER: _ClassVar[int]
    constitution: Constitution
    def __init__(self, constitution: _Optional[_Union[Constitution, _Mapping]] = ...) -> None: ...

class ActivateShadowConstitutionResponse(_message.Message):
    __slots__ = ("shadow_constitution_hash", "shadow_activate_receipt")
    SHADOW_CONSTITUTION_HASH_FIELD_NUMBER: _ClassVar[int]
    SHADOW_ACTIVATE_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    shadow_constitution_hash: _common_pb2.Hash
    shadow_activate_receipt: _common_pb2.Hash
    def __init__(self, shadow_constitution_hash: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., shadow_activate_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class ClearShadowConstitutionRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ClearShadowConstitutionResponse(_message.Message):
    __slots__ = ("shadow_clear_receipt", "previously_shadowed_constitution_hash")
    SHADOW_CLEAR_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    PREVIOUSLY_SHADOWED_CONSTITUTION_HASH_FIELD_NUMBER: _ClassVar[int]
    shadow_clear_receipt: _common_pb2.Hash
    previously_shadowed_constitution_hash: _common_pb2.Hash
    def __init__(self, shadow_clear_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., previously_shadowed_constitution_hash: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class PromoteShadowConstitutionRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class PromoteShadowConstitutionResponse(_message.Message):
    __slots__ = ("to_active_constitution_hash", "shadow_promote_receipt", "from_active_constitution_hash")
    TO_ACTIVE_CONSTITUTION_HASH_FIELD_NUMBER: _ClassVar[int]
    SHADOW_PROMOTE_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    FROM_ACTIVE_CONSTITUTION_HASH_FIELD_NUMBER: _ClassVar[int]
    to_active_constitution_hash: _common_pb2.Hash
    shadow_promote_receipt: _common_pb2.Hash
    from_active_constitution_hash: _common_pb2.Hash
    def __init__(self, to_active_constitution_hash: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., shadow_promote_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., from_active_constitution_hash: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class GetActiveShadowConstitutionRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetActiveShadowConstitutionResponse(_message.Message):
    __slots__ = ("constitution", "shadow_constitution_hash")
    CONSTITUTION_FIELD_NUMBER: _ClassVar[int]
    SHADOW_CONSTITUTION_HASH_FIELD_NUMBER: _ClassVar[int]
    constitution: Constitution
    shadow_constitution_hash: _common_pb2.Hash
    def __init__(self, constitution: _Optional[_Union[Constitution, _Mapping]] = ..., shadow_constitution_hash: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class ReplaySessionWindow(_message.Message):
    __slots__ = ("from_unix_ns", "to_unix_ns", "action_kind_filter")
    FROM_UNIX_NS_FIELD_NUMBER: _ClassVar[int]
    TO_UNIX_NS_FIELD_NUMBER: _ClassVar[int]
    ACTION_KIND_FILTER_FIELD_NUMBER: _ClassVar[int]
    from_unix_ns: int
    to_unix_ns: int
    action_kind_filter: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, from_unix_ns: _Optional[int] = ..., to_unix_ns: _Optional[int] = ..., action_kind_filter: _Optional[_Iterable[str]] = ...) -> None: ...

class CreateReplaySessionRequest(_message.Message):
    __slots__ = ("candidate", "window", "mode", "warm_lookback_hours")
    CANDIDATE_FIELD_NUMBER: _ClassVar[int]
    WINDOW_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    WARM_LOOKBACK_HOURS_FIELD_NUMBER: _ClassVar[int]
    candidate: Constitution
    window: ReplaySessionWindow
    mode: ReplayMode
    warm_lookback_hours: int
    def __init__(self, candidate: _Optional[_Union[Constitution, _Mapping]] = ..., window: _Optional[_Union[ReplaySessionWindow, _Mapping]] = ..., mode: _Optional[_Union[ReplayMode, str]] = ..., warm_lookback_hours: _Optional[int] = ...) -> None: ...

class CreateReplaySessionResponse(_message.Message):
    __slots__ = ("replay_session_id", "session_create_receipt")
    REPLAY_SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_CREATE_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    replay_session_id: str
    session_create_receipt: _common_pb2.Hash
    def __init__(self, replay_session_id: _Optional[str] = ..., session_create_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class RunReplaySessionRequest(_message.Message):
    __slots__ = ("replay_session_id",)
    REPLAY_SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    replay_session_id: str
    def __init__(self, replay_session_id: _Optional[str] = ...) -> None: ...

class ReplayProgress(_message.Message):
    __slots__ = ("replay_session_id", "progress_unix_ns", "receipts_replayed", "latest_replay_receipt_id", "window_complete")
    REPLAY_SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PROGRESS_UNIX_NS_FIELD_NUMBER: _ClassVar[int]
    RECEIPTS_REPLAYED_FIELD_NUMBER: _ClassVar[int]
    LATEST_REPLAY_RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    WINDOW_COMPLETE_FIELD_NUMBER: _ClassVar[int]
    replay_session_id: str
    progress_unix_ns: int
    receipts_replayed: int
    latest_replay_receipt_id: _common_pb2.Hash
    window_complete: bool
    def __init__(self, replay_session_id: _Optional[str] = ..., progress_unix_ns: _Optional[int] = ..., receipts_replayed: _Optional[int] = ..., latest_replay_receipt_id: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., window_complete: _Optional[bool] = ...) -> None: ...

class QueryReplayReceiptsRequest(_message.Message):
    __slots__ = ("replay_session_id", "query")
    REPLAY_SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    QUERY_FIELD_NUMBER: _ClassVar[int]
    replay_session_id: str
    query: _receipt_v1_pb2.QueryRequest
    def __init__(self, replay_session_id: _Optional[str] = ..., query: _Optional[_Union[_receipt_v1_pb2.QueryRequest, _Mapping]] = ...) -> None: ...

class QueryReplayReceiptsResponse(_message.Message):
    __slots__ = ("receipts", "next_page_token")
    RECEIPTS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    receipts: _containers.RepeatedCompositeFieldContainer[_receipt_v1_pb2.Receipt]
    next_page_token: bytes
    def __init__(self, receipts: _Optional[_Iterable[_Union[_receipt_v1_pb2.Receipt, _Mapping]]] = ..., next_page_token: _Optional[bytes] = ...) -> None: ...

class CloseReplaySessionRequest(_message.Message):
    __slots__ = ("replay_session_id",)
    REPLAY_SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    replay_session_id: str
    def __init__(self, replay_session_id: _Optional[str] = ...) -> None: ...

class CloseReplaySessionResponse(_message.Message):
    __slots__ = ("session_close_receipt", "receipts_replayed_total")
    SESSION_CLOSE_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    RECEIPTS_REPLAYED_TOTAL_FIELD_NUMBER: _ClassVar[int]
    session_close_receipt: _common_pb2.Hash
    receipts_replayed_total: int
    def __init__(self, session_close_receipt: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., receipts_replayed_total: _Optional[int] = ...) -> None: ...

class ListReplaySessionsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ReplaySessionDescriptor(_message.Message):
    __slots__ = ("replay_session_id", "candidate_constitution_hash", "candidate_constitution_version", "window", "mode", "created_at", "last_active_at", "receipts_replayed")
    REPLAY_SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    CANDIDATE_CONSTITUTION_HASH_FIELD_NUMBER: _ClassVar[int]
    CANDIDATE_CONSTITUTION_VERSION_FIELD_NUMBER: _ClassVar[int]
    WINDOW_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    LAST_ACTIVE_AT_FIELD_NUMBER: _ClassVar[int]
    RECEIPTS_REPLAYED_FIELD_NUMBER: _ClassVar[int]
    replay_session_id: str
    candidate_constitution_hash: _common_pb2.Hash
    candidate_constitution_version: str
    window: ReplaySessionWindow
    mode: ReplayMode
    created_at: _common_pb2.Timestamp
    last_active_at: _common_pb2.Timestamp
    receipts_replayed: int
    def __init__(self, replay_session_id: _Optional[str] = ..., candidate_constitution_hash: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., candidate_constitution_version: _Optional[str] = ..., window: _Optional[_Union[ReplaySessionWindow, _Mapping]] = ..., mode: _Optional[_Union[ReplayMode, str]] = ..., created_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ..., last_active_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ..., receipts_replayed: _Optional[int] = ...) -> None: ...

class ListReplaySessionsResponse(_message.Message):
    __slots__ = ("sessions",)
    SESSIONS_FIELD_NUMBER: _ClassVar[int]
    sessions: _containers.RepeatedCompositeFieldContainer[ReplaySessionDescriptor]
    def __init__(self, sessions: _Optional[_Iterable[_Union[ReplaySessionDescriptor, _Mapping]]] = ...) -> None: ...

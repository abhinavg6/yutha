import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SignatureRole(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SIGNATURE_ROLE_UNKNOWN: _ClassVar[SignatureRole]
    SIGNATURE_ROLE_ACTOR: _ClassVar[SignatureRole]
    SIGNATURE_ROLE_CONTROL_PLANE: _ClassVar[SignatureRole]
    SIGNATURE_ROLE_SUPERVISOR: _ClassVar[SignatureRole]
    SIGNATURE_ROLE_ATTESTATION: _ClassVar[SignatureRole]
    SIGNATURE_ROLE_BATCH_ROOT: _ClassVar[SignatureRole]
SIGNATURE_ROLE_UNKNOWN: SignatureRole
SIGNATURE_ROLE_ACTOR: SignatureRole
SIGNATURE_ROLE_CONTROL_PLANE: SignatureRole
SIGNATURE_ROLE_SUPERVISOR: SignatureRole
SIGNATURE_ROLE_ATTESTATION: SignatureRole
SIGNATURE_ROLE_BATCH_ROOT: SignatureRole

class Receipt(_message.Message):
    __slots__ = ("spec_version", "swarm_id", "actor", "action_kind", "causal", "evidence", "constitution_version", "cost", "occurred_at", "seal", "extensions", "signatures")
    SPEC_VERSION_FIELD_NUMBER: _ClassVar[int]
    SWARM_ID_FIELD_NUMBER: _ClassVar[int]
    ACTOR_FIELD_NUMBER: _ClassVar[int]
    ACTION_KIND_FIELD_NUMBER: _ClassVar[int]
    CAUSAL_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    CONSTITUTION_VERSION_FIELD_NUMBER: _ClassVar[int]
    COST_FIELD_NUMBER: _ClassVar[int]
    OCCURRED_AT_FIELD_NUMBER: _ClassVar[int]
    SEAL_FIELD_NUMBER: _ClassVar[int]
    EXTENSIONS_FIELD_NUMBER: _ClassVar[int]
    SIGNATURES_FIELD_NUMBER: _ClassVar[int]
    spec_version: _common_pb2.Version
    swarm_id: _common_pb2.SwarmId
    actor: _common_pb2.AgentId
    action_kind: str
    causal: _common_pb2.CausalRef
    evidence: _containers.RepeatedCompositeFieldContainer[Evidence]
    constitution_version: str
    cost: _common_pb2.CostAnnotation
    occurred_at: _common_pb2.Timestamp
    seal: SealStatus
    extensions: _common_pb2.Extensions
    signatures: _containers.RepeatedCompositeFieldContainer[SignedBy]
    def __init__(self, spec_version: _Optional[_Union[_common_pb2.Version, _Mapping]] = ..., swarm_id: _Optional[_Union[_common_pb2.SwarmId, _Mapping]] = ..., actor: _Optional[_Union[_common_pb2.AgentId, _Mapping]] = ..., action_kind: _Optional[str] = ..., causal: _Optional[_Union[_common_pb2.CausalRef, _Mapping]] = ..., evidence: _Optional[_Iterable[_Union[Evidence, _Mapping]]] = ..., constitution_version: _Optional[str] = ..., cost: _Optional[_Union[_common_pb2.CostAnnotation, _Mapping]] = ..., occurred_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ..., seal: _Optional[_Union[SealStatus, _Mapping]] = ..., extensions: _Optional[_Union[_common_pb2.Extensions, _Mapping]] = ..., signatures: _Optional[_Iterable[_Union[SignedBy, _Mapping]]] = ...) -> None: ...

class Evidence(_message.Message):
    __slots__ = ("key", "type_url", "value", "sensitive")
    KEY_FIELD_NUMBER: _ClassVar[int]
    TYPE_URL_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    SENSITIVE_FIELD_NUMBER: _ClassVar[int]
    key: str
    type_url: str
    value: bytes
    sensitive: bool
    def __init__(self, key: _Optional[str] = ..., type_url: _Optional[str] = ..., value: _Optional[bytes] = ..., sensitive: bool = ...) -> None: ...

class SignedBy(_message.Message):
    __slots__ = ("role", "signature", "signed_at")
    ROLE_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SIGNED_AT_FIELD_NUMBER: _ClassVar[int]
    role: SignatureRole
    signature: _common_pb2.Signature
    signed_at: _common_pb2.Timestamp
    def __init__(self, role: _Optional[_Union[SignatureRole, str]] = ..., signature: _Optional[_Union[_common_pb2.Signature, _Mapping]] = ..., signed_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class SealStatus(_message.Message):
    __slots__ = ("state", "batch_root", "merkle_path", "sealed_at")
    class State(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        SEAL_STATE_UNKNOWN: _ClassVar[SealStatus.State]
        SEAL_STATE_UNSEALED: _ClassVar[SealStatus.State]
        SEAL_STATE_SEALED: _ClassVar[SealStatus.State]
    SEAL_STATE_UNKNOWN: SealStatus.State
    SEAL_STATE_UNSEALED: SealStatus.State
    SEAL_STATE_SEALED: SealStatus.State
    STATE_FIELD_NUMBER: _ClassVar[int]
    BATCH_ROOT_FIELD_NUMBER: _ClassVar[int]
    MERKLE_PATH_FIELD_NUMBER: _ClassVar[int]
    SEALED_AT_FIELD_NUMBER: _ClassVar[int]
    state: SealStatus.State
    batch_root: _common_pb2.Hash
    merkle_path: _containers.RepeatedCompositeFieldContainer[_common_pb2.Hash]
    sealed_at: _common_pb2.Timestamp
    def __init__(self, state: _Optional[_Union[SealStatus.State, str]] = ..., batch_root: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., merkle_path: _Optional[_Iterable[_Union[_common_pb2.Hash, _Mapping]]] = ..., sealed_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class AppendRequest(_message.Message):
    __slots__ = ("receipt", "wait_for_seal")
    RECEIPT_FIELD_NUMBER: _ClassVar[int]
    WAIT_FOR_SEAL_FIELD_NUMBER: _ClassVar[int]
    receipt: Receipt
    wait_for_seal: bool
    def __init__(self, receipt: _Optional[_Union[Receipt, _Mapping]] = ..., wait_for_seal: bool = ...) -> None: ...

class AppendResponse(_message.Message):
    __slots__ = ("receipt_id", "seal")
    RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    SEAL_FIELD_NUMBER: _ClassVar[int]
    receipt_id: _common_pb2.Hash
    seal: SealStatus
    def __init__(self, receipt_id: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., seal: _Optional[_Union[SealStatus, _Mapping]] = ...) -> None: ...

class QueryRequest(_message.Message):
    __slots__ = ("by_receipt_id", "by_predecessor", "by_agent", "by_action_kind", "by_time", "limit", "page_token")
    BY_RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    BY_PREDECESSOR_FIELD_NUMBER: _ClassVar[int]
    BY_AGENT_FIELD_NUMBER: _ClassVar[int]
    BY_ACTION_KIND_FIELD_NUMBER: _ClassVar[int]
    BY_TIME_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    by_receipt_id: _common_pb2.Hash
    by_predecessor: PredecessorQuery
    by_agent: AgentQuery
    by_action_kind: ActionKindQuery
    by_time: TimeRangeQuery
    limit: int
    page_token: bytes
    def __init__(self, by_receipt_id: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., by_predecessor: _Optional[_Union[PredecessorQuery, _Mapping]] = ..., by_agent: _Optional[_Union[AgentQuery, _Mapping]] = ..., by_action_kind: _Optional[_Union[ActionKindQuery, _Mapping]] = ..., by_time: _Optional[_Union[TimeRangeQuery, _Mapping]] = ..., limit: _Optional[int] = ..., page_token: _Optional[bytes] = ...) -> None: ...

class PredecessorQuery(_message.Message):
    __slots__ = ("predecessor",)
    PREDECESSOR_FIELD_NUMBER: _ClassVar[int]
    predecessor: _common_pb2.Hash
    def __init__(self, predecessor: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ...) -> None: ...

class AgentQuery(_message.Message):
    __slots__ = ("agent_id",)
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    agent_id: _common_pb2.AgentId
    def __init__(self, agent_id: _Optional[_Union[_common_pb2.AgentId, _Mapping]] = ...) -> None: ...

class ActionKindQuery(_message.Message):
    __slots__ = ("action_kind",)
    ACTION_KIND_FIELD_NUMBER: _ClassVar[int]
    action_kind: str
    def __init__(self, action_kind: _Optional[str] = ...) -> None: ...

class TimeRangeQuery(_message.Message):
    __slots__ = ("to",)
    FROM_FIELD_NUMBER: _ClassVar[int]
    TO_FIELD_NUMBER: _ClassVar[int]
    to: _common_pb2.Timestamp
    def __init__(self, to: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ..., **kwargs) -> None: ...

class QueryResponse(_message.Message):
    __slots__ = ("receipts", "next_page_token")
    RECEIPTS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    receipts: _containers.RepeatedCompositeFieldContainer[Receipt]
    next_page_token: bytes
    def __init__(self, receipts: _Optional[_Iterable[_Union[Receipt, _Mapping]]] = ..., next_page_token: _Optional[bytes] = ...) -> None: ...

class ExportRequest(_message.Message):
    __slots__ = ("range", "action_kinds", "include_unsealed")
    RANGE_FIELD_NUMBER: _ClassVar[int]
    ACTION_KINDS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_UNSEALED_FIELD_NUMBER: _ClassVar[int]
    range: TimeRangeQuery
    action_kinds: _containers.RepeatedScalarFieldContainer[str]
    include_unsealed: bool
    def __init__(self, range: _Optional[_Union[TimeRangeQuery, _Mapping]] = ..., action_kinds: _Optional[_Iterable[str]] = ..., include_unsealed: bool = ...) -> None: ...

class ExportManifest(_message.Message):
    __slots__ = ("receipt_ids", "manifest_root", "manifest_signature", "generated_at")
    RECEIPT_IDS_FIELD_NUMBER: _ClassVar[int]
    MANIFEST_ROOT_FIELD_NUMBER: _ClassVar[int]
    MANIFEST_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    GENERATED_AT_FIELD_NUMBER: _ClassVar[int]
    receipt_ids: _containers.RepeatedCompositeFieldContainer[_common_pb2.Hash]
    manifest_root: _common_pb2.Hash
    manifest_signature: _common_pb2.Signature
    generated_at: _common_pb2.Timestamp
    def __init__(self, receipt_ids: _Optional[_Iterable[_Union[_common_pb2.Hash, _Mapping]]] = ..., manifest_root: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., manifest_signature: _Optional[_Union[_common_pb2.Signature, _Mapping]] = ..., generated_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ...) -> None: ...

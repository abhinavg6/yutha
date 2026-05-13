import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Performative(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PERFORMATIVE_UNKNOWN: _ClassVar[Performative]
    PERFORMATIVE_PROPOSE: _ClassVar[Performative]
    PERFORMATIVE_COUNTER: _ClassVar[Performative]
    PERFORMATIVE_COMMIT: _ClassVar[Performative]
    PERFORMATIVE_ABORT: _ClassVar[Performative]
    PERFORMATIVE_RELEASE: _ClassVar[Performative]
    PERFORMATIVE_QUERY: _ClassVar[Performative]
    PERFORMATIVE_INFORM: _ClassVar[Performative]
    PERFORMATIVE_ERROR: _ClassVar[Performative]
    PERFORMATIVE_REQUEST_ACTION: _ClassVar[Performative]
    PERFORMATIVE_CONFIRM: _ClassVar[Performative]
    PERFORMATIVE_DECLINE: _ClassVar[Performative]
PERFORMATIVE_UNKNOWN: Performative
PERFORMATIVE_PROPOSE: Performative
PERFORMATIVE_COUNTER: Performative
PERFORMATIVE_COMMIT: Performative
PERFORMATIVE_ABORT: Performative
PERFORMATIVE_RELEASE: Performative
PERFORMATIVE_QUERY: Performative
PERFORMATIVE_INFORM: Performative
PERFORMATIVE_ERROR: Performative
PERFORMATIVE_REQUEST_ACTION: Performative
PERFORMATIVE_CONFIRM: Performative
PERFORMATIVE_DECLINE: Performative

class Envelope(_message.Message):
    __slots__ = ("spec_version", "swarm_id", "envelope_id", "from_agent", "recipient", "performative", "payload", "payload_schema_id", "tags", "causal", "nonce", "epoch", "sent_at", "expires_at", "in_reply_to", "extensions", "agent_signature")
    SPEC_VERSION_FIELD_NUMBER: _ClassVar[int]
    SWARM_ID_FIELD_NUMBER: _ClassVar[int]
    ENVELOPE_ID_FIELD_NUMBER: _ClassVar[int]
    FROM_AGENT_FIELD_NUMBER: _ClassVar[int]
    RECIPIENT_FIELD_NUMBER: _ClassVar[int]
    PERFORMATIVE_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_SCHEMA_ID_FIELD_NUMBER: _ClassVar[int]
    TAGS_FIELD_NUMBER: _ClassVar[int]
    CAUSAL_FIELD_NUMBER: _ClassVar[int]
    NONCE_FIELD_NUMBER: _ClassVar[int]
    EPOCH_FIELD_NUMBER: _ClassVar[int]
    SENT_AT_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    IN_REPLY_TO_FIELD_NUMBER: _ClassVar[int]
    EXTENSIONS_FIELD_NUMBER: _ClassVar[int]
    AGENT_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    spec_version: _common_pb2.Version
    swarm_id: _common_pb2.SwarmId
    envelope_id: bytes
    from_agent: _common_pb2.AgentId
    recipient: Recipient
    performative: Performative
    payload: bytes
    payload_schema_id: str
    tags: _containers.RepeatedScalarFieldContainer[str]
    causal: _common_pb2.CausalRef
    nonce: bytes
    epoch: int
    sent_at: _common_pb2.Timestamp
    expires_at: _common_pb2.Timestamp
    in_reply_to: _common_pb2.Hash
    extensions: _common_pb2.Extensions
    agent_signature: _common_pb2.Signature
    def __init__(self, spec_version: _Optional[_Union[_common_pb2.Version, _Mapping]] = ..., swarm_id: _Optional[_Union[_common_pb2.SwarmId, _Mapping]] = ..., envelope_id: _Optional[bytes] = ..., from_agent: _Optional[_Union[_common_pb2.AgentId, _Mapping]] = ..., recipient: _Optional[_Union[Recipient, _Mapping]] = ..., performative: _Optional[_Union[Performative, str]] = ..., payload: _Optional[bytes] = ..., payload_schema_id: _Optional[str] = ..., tags: _Optional[_Iterable[str]] = ..., causal: _Optional[_Union[_common_pb2.CausalRef, _Mapping]] = ..., nonce: _Optional[bytes] = ..., epoch: _Optional[int] = ..., sent_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ..., expires_at: _Optional[_Union[_common_pb2.Timestamp, _Mapping]] = ..., in_reply_to: _Optional[_Union[_common_pb2.Hash, _Mapping]] = ..., extensions: _Optional[_Union[_common_pb2.Extensions, _Mapping]] = ..., agent_signature: _Optional[_Union[_common_pb2.Signature, _Mapping]] = ...) -> None: ...

class Recipient(_message.Message):
    __slots__ = ("agent", "role", "swarm", "external")
    AGENT_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    SWARM_FIELD_NUMBER: _ClassVar[int]
    EXTERNAL_FIELD_NUMBER: _ClassVar[int]
    agent: _common_pb2.AgentId
    role: str
    swarm: SwarmBroadcast
    external: ExternalEndpoint
    def __init__(self, agent: _Optional[_Union[_common_pb2.AgentId, _Mapping]] = ..., role: _Optional[str] = ..., swarm: _Optional[_Union[SwarmBroadcast, _Mapping]] = ..., external: _Optional[_Union[ExternalEndpoint, _Mapping]] = ...) -> None: ...

class SwarmBroadcast(_message.Message):
    __slots__ = ("filter_tags",)
    FILTER_TAGS_FIELD_NUMBER: _ClassVar[int]
    filter_tags: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, filter_tags: _Optional[_Iterable[str]] = ...) -> None: ...

class ExternalEndpoint(_message.Message):
    __slots__ = ("scheme", "authority", "path_hint")
    SCHEME_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_FIELD_NUMBER: _ClassVar[int]
    PATH_HINT_FIELD_NUMBER: _ClassVar[int]
    scheme: str
    authority: str
    path_hint: str
    def __init__(self, scheme: _Optional[str] = ..., authority: _Optional[str] = ..., path_hint: _Optional[str] = ...) -> None: ...

class EnvelopeError(_message.Message):
    __slots__ = ("reason", "detail", "envelope_id")
    class Reason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ENVELOPE_ERROR_UNKNOWN: _ClassVar[EnvelopeError.Reason]
        ENVELOPE_ERROR_SIGNATURE_INVALID: _ClassVar[EnvelopeError.Reason]
        ENVELOPE_ERROR_UNKNOWN_SPEC_VERSION: _ClassVar[EnvelopeError.Reason]
        ENVELOPE_ERROR_REPLAY_DETECTED: _ClassVar[EnvelopeError.Reason]
        ENVELOPE_ERROR_EXPIRED: _ClassVar[EnvelopeError.Reason]
        ENVELOPE_ERROR_MALFORMED: _ClassVar[EnvelopeError.Reason]
        ENVELOPE_ERROR_UNKNOWN_PERFORMATIVE: _ClassVar[EnvelopeError.Reason]
        ENVELOPE_ERROR_RECIPIENT_UNKNOWN: _ClassVar[EnvelopeError.Reason]
        ENVELOPE_ERROR_CAPABILITY_DENIED: _ClassVar[EnvelopeError.Reason]
    ENVELOPE_ERROR_UNKNOWN: EnvelopeError.Reason
    ENVELOPE_ERROR_SIGNATURE_INVALID: EnvelopeError.Reason
    ENVELOPE_ERROR_UNKNOWN_SPEC_VERSION: EnvelopeError.Reason
    ENVELOPE_ERROR_REPLAY_DETECTED: EnvelopeError.Reason
    ENVELOPE_ERROR_EXPIRED: EnvelopeError.Reason
    ENVELOPE_ERROR_MALFORMED: EnvelopeError.Reason
    ENVELOPE_ERROR_UNKNOWN_PERFORMATIVE: EnvelopeError.Reason
    ENVELOPE_ERROR_RECIPIENT_UNKNOWN: EnvelopeError.Reason
    ENVELOPE_ERROR_CAPABILITY_DENIED: EnvelopeError.Reason
    REASON_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    ENVELOPE_ID_FIELD_NUMBER: _ClassVar[int]
    reason: EnvelopeError.Reason
    detail: str
    envelope_id: bytes
    def __init__(self, reason: _Optional[_Union[EnvelopeError.Reason, str]] = ..., detail: _Optional[str] = ..., envelope_id: _Optional[bytes] = ...) -> None: ...

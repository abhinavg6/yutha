from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class HashAlgorithm(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HASH_ALGORITHM_UNKNOWN: _ClassVar[HashAlgorithm]
    HASH_ALGORITHM_SHA256: _ClassVar[HashAlgorithm]
    HASH_ALGORITHM_BLAKE3: _ClassVar[HashAlgorithm]

class SignatureAlgorithm(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SIGNATURE_ALGORITHM_UNKNOWN: _ClassVar[SignatureAlgorithm]
    SIGNATURE_ALGORITHM_ED25519: _ClassVar[SignatureAlgorithm]
    SIGNATURE_ALGORITHM_RESERVED_PQ: _ClassVar[SignatureAlgorithm]
HASH_ALGORITHM_UNKNOWN: HashAlgorithm
HASH_ALGORITHM_SHA256: HashAlgorithm
HASH_ALGORITHM_BLAKE3: HashAlgorithm
SIGNATURE_ALGORITHM_UNKNOWN: SignatureAlgorithm
SIGNATURE_ALGORITHM_ED25519: SignatureAlgorithm
SIGNATURE_ALGORITHM_RESERVED_PQ: SignatureAlgorithm

class AgentId(_message.Message):
    __slots__ = ("value",)
    VALUE_FIELD_NUMBER: _ClassVar[int]
    value: bytes
    def __init__(self, value: _Optional[bytes] = ...) -> None: ...

class SwarmId(_message.Message):
    __slots__ = ("value",)
    VALUE_FIELD_NUMBER: _ClassVar[int]
    value: bytes
    def __init__(self, value: _Optional[bytes] = ...) -> None: ...

class ReceiptId(_message.Message):
    __slots__ = ("hash",)
    HASH_FIELD_NUMBER: _ClassVar[int]
    hash: Hash
    def __init__(self, hash: _Optional[_Union[Hash, _Mapping]] = ...) -> None: ...

class Hash(_message.Message):
    __slots__ = ("algorithm", "digest")
    ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    DIGEST_FIELD_NUMBER: _ClassVar[int]
    algorithm: HashAlgorithm
    digest: bytes
    def __init__(self, algorithm: _Optional[_Union[HashAlgorithm, str]] = ..., digest: _Optional[bytes] = ...) -> None: ...

class Signature(_message.Message):
    __slots__ = ("algorithm", "value", "key_fingerprint")
    ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    KEY_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    algorithm: SignatureAlgorithm
    value: bytes
    key_fingerprint: bytes
    def __init__(self, algorithm: _Optional[_Union[SignatureAlgorithm, str]] = ..., value: _Optional[bytes] = ..., key_fingerprint: _Optional[bytes] = ...) -> None: ...

class PublicKey(_message.Message):
    __slots__ = ("algorithm", "value")
    ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    algorithm: SignatureAlgorithm
    value: bytes
    def __init__(self, algorithm: _Optional[_Union[SignatureAlgorithm, str]] = ..., value: _Optional[bytes] = ...) -> None: ...

class Timestamp(_message.Message):
    __slots__ = ("wall_clock", "monotonic_ns")
    WALL_CLOCK_FIELD_NUMBER: _ClassVar[int]
    MONOTONIC_NS_FIELD_NUMBER: _ClassVar[int]
    wall_clock: str
    monotonic_ns: int
    def __init__(self, wall_clock: _Optional[str] = ..., monotonic_ns: _Optional[int] = ...) -> None: ...

class CausalRef(_message.Message):
    __slots__ = ("predecessors",)
    PREDECESSORS_FIELD_NUMBER: _ClassVar[int]
    predecessors: _containers.RepeatedCompositeFieldContainer[Hash]
    def __init__(self, predecessors: _Optional[_Iterable[_Union[Hash, _Mapping]]] = ...) -> None: ...

class Version(_message.Message):
    __slots__ = ("value",)
    VALUE_FIELD_NUMBER: _ClassVar[int]
    value: str
    def __init__(self, value: _Optional[str] = ...) -> None: ...

class Extensions(_message.Message):
    __slots__ = ("entries",)
    class EntriesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: Any
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[Any, _Mapping]] = ...) -> None: ...
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    entries: _containers.MessageMap[str, Any]
    def __init__(self, entries: _Optional[_Mapping[str, Any]] = ...) -> None: ...

class Any(_message.Message):
    __slots__ = ("type_url", "value")
    TYPE_URL_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    type_url: str
    value: bytes
    def __init__(self, type_url: _Optional[str] = ..., value: _Optional[bytes] = ...) -> None: ...

class CostAnnotation(_message.Message):
    __slots__ = ("input_tokens", "output_tokens", "tool_call_count", "wall_time_ms", "usd_cents_estimate", "model_provider", "model_name", "model_version")
    INPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    TOOL_CALL_COUNT_FIELD_NUMBER: _ClassVar[int]
    WALL_TIME_MS_FIELD_NUMBER: _ClassVar[int]
    USD_CENTS_ESTIMATE_FIELD_NUMBER: _ClassVar[int]
    MODEL_PROVIDER_FIELD_NUMBER: _ClassVar[int]
    MODEL_NAME_FIELD_NUMBER: _ClassVar[int]
    MODEL_VERSION_FIELD_NUMBER: _ClassVar[int]
    input_tokens: int
    output_tokens: int
    tool_call_count: int
    wall_time_ms: int
    usd_cents_estimate: str
    model_provider: str
    model_name: str
    model_version: str
    def __init__(self, input_tokens: _Optional[int] = ..., output_tokens: _Optional[int] = ..., tool_call_count: _Optional[int] = ..., wall_time_ms: _Optional[int] = ..., usd_cents_estimate: _Optional[str] = ..., model_provider: _Optional[str] = ..., model_name: _Optional[str] = ..., model_version: _Optional[str] = ...) -> None: ...

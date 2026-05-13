"""Identifier and crypto-primitive Pydantic models — Python mirrors of the
Rust ``yutha-core`` types in
[`crates/yutha-core`](../../../../crates/yutha-core/src).

Every type here is a thin Pydantic v2 model wrapping the bytes / strings
the proto layer transmits. The ergonomic API matches the Rust side as
closely as Python idiom allows:

  - ``AgentId.new()`` / ``SwarmId.new()`` mint a fresh UUID v7.
  - ``.to_proto()`` / ``.from_proto(proto_obj)`` convert against the
    generated ``yutha._proto`` messages.
  - Display methods produce the same algorithm-prefixed hex form the
    Rust ``Hash::to_hex()`` produces (``"sha256:abcd..."``).

Validation is strict at construction time — wrong-length AgentId, an
unknown hash algorithm, or a non-RFC-3339 timestamp all raise rather
than silently coerce.
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from enum import IntEnum
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from yutha._proto import common_pb2

# =============================================================================
# UUID v7
# =============================================================================
#
# Python's stdlib `uuid` module gets v7 support in 3.14. Until then we
# emit it inline — the algorithm is small and self-contained per
# RFC 9562 §5.7. Wire format:
#
#   - 48 bits: Unix timestamp in milliseconds, big-endian
#   - 4 bits:  version = 0111
#   - 12 bits: rand_a (CSPRNG)
#   - 2 bits:  variant = 10
#   - 62 bits: rand_b (CSPRNG)


def _new_uuid_v7_bytes() -> bytes:
    """Mint a fresh UUID v7 as 16 raw bytes."""
    unix_ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand_a = int.from_bytes(os.urandom(2), "big") & 0x0FFF  # 12 bits
    rand_b = int.from_bytes(os.urandom(8), "big") & ((1 << 62) - 1)  # 62 bits

    out = bytearray(16)
    # Bytes 0–5: timestamp (48-bit big-endian).
    out[0] = (unix_ts_ms >> 40) & 0xFF
    out[1] = (unix_ts_ms >> 32) & 0xFF
    out[2] = (unix_ts_ms >> 24) & 0xFF
    out[3] = (unix_ts_ms >> 16) & 0xFF
    out[4] = (unix_ts_ms >> 8) & 0xFF
    out[5] = unix_ts_ms & 0xFF
    # Bytes 6–7: 4-bit version (0111) | 12-bit rand_a.
    out[6] = 0x70 | ((rand_a >> 8) & 0x0F)
    out[7] = rand_a & 0xFF
    # Bytes 8–15: 2-bit variant (10) | 62-bit rand_b.
    out[8] = 0x80 | ((rand_b >> 56) & 0x3F)
    for i in range(9, 16):
        shift = (15 - i) * 8
        out[i] = (rand_b >> shift) & 0xFF
    return bytes(out)


# =============================================================================
# Enums (wire-pinned)
# =============================================================================


class HashAlgorithm(IntEnum):
    """SHA-256 only in v1.0; BLAKE3 reserved for v1.x. Wire numbers match
    the proto enum directly."""

    SHA256 = 1
    BLAKE3 = 2


class SignatureAlgorithm(IntEnum):
    """Ed25519 in v1.0; ReservedPq is the future-PQ migration hatch and
    is rejected at construction in v1."""

    ED25519 = 1
    RESERVED_PQ = 2


# =============================================================================
# Identifier wrappers
# =============================================================================


class AgentId(BaseModel):
    """Stable 16-byte agent identifier (UUID v7)."""

    model_config = ConfigDict(frozen=True)

    value: bytes = Field(..., description="16 raw UUID v7 bytes.")

    LENGTH: ClassVar[int] = 16

    @field_validator("value")
    @classmethod
    def _validate_length(cls, v: bytes) -> bytes:
        if len(v) != cls.LENGTH:
            raise ValueError(f"AgentId must be exactly {cls.LENGTH} bytes, got {len(v)}")
        return v

    @classmethod
    def new(cls) -> AgentId:
        """Mint a fresh AgentId (UUID v7)."""
        return cls(value=_new_uuid_v7_bytes())

    @classmethod
    def from_bytes(cls, b: bytes) -> AgentId:
        return cls(value=bytes(b))

    @classmethod
    def from_proto(cls, p: common_pb2.AgentId) -> AgentId:
        return cls(value=p.value)

    def to_proto(self) -> common_pb2.AgentId:
        return common_pb2.AgentId(value=self.value)

    def __str__(self) -> str:
        # Matches Rust `AgentId::Display`: hyphenated UUID form.
        v = self.value
        return f"{v[0:4].hex()}-{v[4:6].hex()}-{v[6:8].hex()}-{v[8:10].hex()}-{v[10:16].hex()}"


class SwarmId(BaseModel):
    """Stable 16-byte swarm identifier (UUID v7)."""

    model_config = ConfigDict(frozen=True)

    value: bytes = Field(..., description="16 raw UUID v7 bytes.")

    LENGTH: ClassVar[int] = 16

    @field_validator("value")
    @classmethod
    def _validate_length(cls, v: bytes) -> bytes:
        if len(v) != cls.LENGTH:
            raise ValueError(f"SwarmId must be exactly {cls.LENGTH} bytes, got {len(v)}")
        return v

    @classmethod
    def new(cls) -> SwarmId:
        return cls(value=_new_uuid_v7_bytes())

    @classmethod
    def from_bytes(cls, b: bytes) -> SwarmId:
        return cls(value=bytes(b))

    @classmethod
    def from_proto(cls, p: common_pb2.SwarmId) -> SwarmId:
        return cls(value=p.value)

    def to_proto(self) -> common_pb2.SwarmId:
        return common_pb2.SwarmId(value=self.value)

    def __str__(self) -> str:
        v = self.value
        return f"{v[0:4].hex()}-{v[4:6].hex()}-{v[6:8].hex()}-{v[8:10].hex()}-{v[10:16].hex()}"


# =============================================================================
# Crypto primitives
# =============================================================================


class Hash(BaseModel):
    """Content-address. ``digest`` length is fixed by ``algorithm`` —
    32 bytes for SHA-256."""

    model_config = ConfigDict(frozen=True)

    algorithm: HashAlgorithm
    digest: bytes

    @field_validator("digest")
    @classmethod
    def _validate_digest(cls, v: bytes, info: ValidationInfo) -> bytes:
        alg = info.data.get("algorithm")
        if alg == HashAlgorithm.SHA256 and len(v) != 32:
            raise ValueError(f"SHA-256 digest must be 32 bytes, got {len(v)}")
        if alg == HashAlgorithm.BLAKE3 and len(v) != 32:
            raise ValueError(f"BLAKE3 digest must be 32 bytes, got {len(v)}")
        return v

    @classmethod
    def from_proto(cls, p: common_pb2.Hash) -> Hash:
        return cls(algorithm=HashAlgorithm(p.algorithm), digest=p.digest)

    def to_proto(self) -> common_pb2.Hash:
        # proto's `common_pb2.Hash.__init__` types `algorithm` as
        # `proto.HashAlgorithm | str | None`. We pass an int extracted
        # from our own `HashAlgorithm` IntEnum — same wire numbers, but
        # mypy treats the two enum classes as nominally distinct. The
        # ignore is local; widening proto stubs is upstream's call.
        return common_pb2.Hash(
            algorithm=self.algorithm.value,  # type: ignore[arg-type]
            digest=self.digest,
        )

    def __str__(self) -> str:
        # Matches Rust `Hash::to_hex()`: "sha256:<hex>".
        prefix = {HashAlgorithm.SHA256: "sha256", HashAlgorithm.BLAKE3: "blake3"}[self.algorithm]
        return f"{prefix}:{self.digest.hex()}"


class Signature(BaseModel):
    """Cryptographic signature carrying algorithm, signature bytes, and
    a fingerprint of the signing public key."""

    model_config = ConfigDict(frozen=True)

    algorithm: SignatureAlgorithm
    value: bytes
    key_fingerprint: bytes

    @field_validator("algorithm")
    @classmethod
    def _validate_algorithm(cls, v: SignatureAlgorithm) -> SignatureAlgorithm:
        if v == SignatureAlgorithm.RESERVED_PQ:
            raise ValueError("SignatureAlgorithm::ReservedPq is reserved for a future PQ migration")
        return v

    @field_validator("value")
    @classmethod
    def _validate_value_length(cls, v: bytes, info: ValidationInfo) -> bytes:
        alg = info.data.get("algorithm")
        if alg == SignatureAlgorithm.ED25519 and len(v) != 64:
            raise ValueError(f"Ed25519 signature must be 64 bytes, got {len(v)}")
        return v

    @field_validator("key_fingerprint")
    @classmethod
    def _validate_fingerprint_length(cls, v: bytes) -> bytes:
        if len(v) != 32:
            raise ValueError(f"key_fingerprint (SHA-256) must be 32 bytes, got {len(v)}")
        return v

    @classmethod
    def from_proto(cls, p: common_pb2.Signature) -> Signature:
        return cls(
            algorithm=SignatureAlgorithm(p.algorithm),
            value=p.value,
            key_fingerprint=p.key_fingerprint,
        )

    def to_proto(self) -> common_pb2.Signature:
        # See note in `Hash.to_proto` re: proto-enum nominal mismatch.
        return common_pb2.Signature(
            algorithm=self.algorithm.value,  # type: ignore[arg-type]
            value=self.value,
            key_fingerprint=self.key_fingerprint,
        )


class PublicKey(BaseModel):
    """Ed25519 (or future-algorithm) public key."""

    model_config = ConfigDict(frozen=True)

    algorithm: SignatureAlgorithm
    value: bytes

    @field_validator("algorithm")
    @classmethod
    def _validate_algorithm(cls, v: SignatureAlgorithm) -> SignatureAlgorithm:
        if v == SignatureAlgorithm.RESERVED_PQ:
            raise ValueError("SignatureAlgorithm::ReservedPq is reserved for a future PQ migration")
        return v

    @field_validator("value")
    @classmethod
    def _validate_value_length(cls, v: bytes, info: ValidationInfo) -> bytes:
        alg = info.data.get("algorithm")
        if alg == SignatureAlgorithm.ED25519 and len(v) != 32:
            raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(v)}")
        return v

    @classmethod
    def from_proto(cls, p: common_pb2.PublicKey) -> PublicKey:
        return cls(algorithm=SignatureAlgorithm(p.algorithm), value=p.value)

    def to_proto(self) -> common_pb2.PublicKey:
        # See note in `Hash.to_proto` re: proto-enum nominal mismatch.
        return common_pb2.PublicKey(
            algorithm=self.algorithm.value,  # type: ignore[arg-type]
            value=self.value,
        )


# =============================================================================
# Timestamp
# =============================================================================


def _now_wall_clock() -> str:
    """RFC 3339 wall-clock with microsecond precision and a literal ``Z``.

    Matches the Rust ``Timestamp::now()`` format closely enough that
    cross-language receipt vectors continue to round-trip. The proto
    `wall_clock` field is just a string preserved verbatim, so subsecond
    precision drift between Rust (ns) and Python (μs) doesn't affect the
    canonical bytes."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Timestamp(BaseModel):
    """Wall-clock RFC 3339 string + monotonic_ns ordering hint."""

    model_config = ConfigDict(frozen=True)

    wall_clock: str
    monotonic_ns: int = Field(..., ge=0, lt=1 << 64)

    @field_validator("wall_clock")
    @classmethod
    def _validate_rfc3339(cls, v: str) -> str:
        # Quick structural parse — proto field is just a string so we
        # don't reject anything the wire would carry, but we surface
        # obvious garbage at construction time.
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError as e:
            raise ValueError(f"wall_clock is not RFC 3339: {e}") from e
        return v

    @classmethod
    def now(cls) -> Timestamp:
        return cls(wall_clock=_now_wall_clock(), monotonic_ns=time.monotonic_ns())

    @classmethod
    def from_proto(cls, p: common_pb2.Timestamp) -> Timestamp:
        return cls(wall_clock=p.wall_clock, monotonic_ns=p.monotonic_ns)

    def to_proto(self) -> common_pb2.Timestamp:
        return common_pb2.Timestamp(wall_clock=self.wall_clock, monotonic_ns=self.monotonic_ns)


# =============================================================================
# CausalRef
# =============================================================================


class CausalRef(BaseModel):
    """Predecessor list. Empty only for the genesis link in any chain."""

    model_config = ConfigDict(frozen=True)

    predecessors: list[Hash] = Field(default_factory=list)

    @classmethod
    def empty(cls) -> CausalRef:
        return cls(predecessors=[])

    @classmethod
    def from_proto(cls, p: common_pb2.CausalRef) -> CausalRef:
        return cls(predecessors=[Hash.from_proto(h) for h in p.predecessors])

    def to_proto(self) -> common_pb2.CausalRef:
        return common_pb2.CausalRef(predecessors=[h.to_proto() for h in self.predecessors])


__all__ = [
    "AgentId",
    "SwarmId",
    "Hash",
    "Signature",
    "PublicKey",
    "Timestamp",
    "CausalRef",
    "HashAlgorithm",
    "SignatureAlgorithm",
]

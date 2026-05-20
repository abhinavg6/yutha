"""Receipt ergonomic model + supporting types.

Mirrors ``/spec/receipt/receipt-v1.proto`` and the Rust ``Receipt``
in ``crates/yutha-receipt/src/receipt.rs``.

Read-only on the SDK side: clients query receipts but don't construct
them — the control plane is the only writer. The ``.from_proto(...)``
conversion is what callers use after a ``ReceiptService.Get`` or
``Query`` response. ``.canonical_bytes()`` is exposed for integrity
checks ("does this receipt's content-address actually match what the
server told me?") but no ``.sign()`` exists.
"""

from __future__ import annotations

from enum import IntEnum

from pydantic import BaseModel, ConfigDict, Field

from yutha._proto import common_pb2
from yutha._proto.receipt import receipt_v1_pb2 as proto
from yutha.canonical import canonical_bytes as _canonical_bytes
from yutha.identity import AgentId, CausalRef, Hash, Signature, SwarmId, Timestamp

# =============================================================================
# Cost annotation (lives in common.proto, modeled here for ergonomics)
# =============================================================================


class CostAnnotation(BaseModel):
    """Resource cost for an action — pure scalars; safe to round-trip."""

    model_config = ConfigDict(frozen=True)

    input_tokens: int = 0
    output_tokens: int = 0
    tool_call_count: int = 0
    wall_time_ms: int = 0
    usd_cents_estimate: str = ""
    model_provider: str = ""
    model_name: str = ""
    model_version: str = ""

    @classmethod
    def from_proto(cls, p: common_pb2.CostAnnotation) -> CostAnnotation:
        return cls(
            input_tokens=p.input_tokens,
            output_tokens=p.output_tokens,
            tool_call_count=p.tool_call_count,
            wall_time_ms=p.wall_time_ms,
            usd_cents_estimate=p.usd_cents_estimate,
            model_provider=p.model_provider,
            model_name=p.model_name,
            model_version=p.model_version,
        )

    def to_proto(self) -> common_pb2.CostAnnotation:
        return common_pb2.CostAnnotation(
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            tool_call_count=self.tool_call_count,
            wall_time_ms=self.wall_time_ms,
            usd_cents_estimate=self.usd_cents_estimate,
            model_provider=self.model_provider,
            model_name=self.model_name,
            model_version=self.model_version,
        )


# =============================================================================
# Evidence + signatures + seal
# =============================================================================


class Evidence(BaseModel):
    """A typed key-value pair recording an input/output of the action."""

    model_config = ConfigDict(frozen=True)

    key: str
    type_url: str
    value: bytes
    sensitive: bool = False

    @classmethod
    def from_proto(cls, p: proto.Evidence) -> Evidence:
        return cls(key=p.key, type_url=p.type_url, value=bytes(p.value), sensitive=p.sensitive)

    def to_proto(self) -> proto.Evidence:
        return proto.Evidence(
            key=self.key, type_url=self.type_url, value=self.value, sensitive=self.sensitive
        )


class SignatureRole(IntEnum):
    """Canonical wire-order signature roles."""

    ACTOR = 1
    CONTROL_PLANE = 2
    SUPERVISOR = 3
    ATTESTATION = 4
    BATCH_ROOT = 5


class SignedBy(BaseModel):
    """A signature carrying its role and timestamp."""

    model_config = ConfigDict(frozen=True)

    role: SignatureRole
    signature: Signature
    signed_at: Timestamp

    @classmethod
    def from_proto(cls, p: proto.SignedBy) -> SignedBy:
        return cls(
            role=SignatureRole(p.role),
            signature=Signature.from_proto(p.signature),
            signed_at=Timestamp.from_proto(p.signed_at),
        )

    def to_proto(self) -> proto.SignedBy:
        # proto.SignedBy's `role` parameter is typed as
        # `proto.SignatureRole | str | None`; we pass an int extracted
        # from our own `SignatureRole` IntEnum. Same wire numbers, but
        # nominally distinct classes at the mypy level.
        return proto.SignedBy(
            role=self.role.value,  # type: ignore[arg-type]
            signature=self.signature.to_proto(),
            signed_at=self.signed_at.to_proto(),
        )


class SealState(IntEnum):
    UNSEALED = 1
    SEALED = 2


class SealStatus(BaseModel):
    """Whether this receipt is sealed into a Merkle batch.

    Fields ``on_chain_tx_digest`` + ``swarm_anchor_object_id`` are populated
    when the seal was committed to an external verifiability backend
    (currently: Sui via the ``receipt_anchor`` Move module — RFC 0014).
    Receipts sealed by the ``LocalSealer`` (in-process, no external
    commitment) leave both fields ``None``.
    """

    model_config = ConfigDict(frozen=True)

    state: SealState = SealState.UNSEALED
    batch_root: Hash | None = None
    merkle_path: list[Hash] = Field(default_factory=list)
    sealed_at: Timestamp | None = None
    # 32-byte Sui tx digest of the commit_batch transaction. None for
    # LocalSealer / unsealed receipts. Raw bytes (NOT hex).
    on_chain_tx_digest: bytes | None = None
    # 32-byte Sui shared-object id of the SwarmAnchor object. Populated
    # together with on_chain_tx_digest. Raw bytes (NOT hex).
    swarm_anchor_object_id: bytes | None = None

    @classmethod
    def from_proto(cls, p: proto.SealStatus) -> SealStatus:
        # Wire 0 = UNKNOWN → treat as UNSEALED (back-compat with old
        # receipts that didn't set the field). Matches Rust reverse impl.
        wire_state = p.state if p.state != 0 else proto.SealStatus.SEAL_STATE_UNSEALED
        # Empty bytes → None (proto's default-empty representation for
        # unset bytes fields). RFC 0014: present together iff SuiSealer.
        on_chain_tx_digest = p.on_chain_tx_digest if p.on_chain_tx_digest else None
        swarm_anchor_object_id = p.swarm_anchor_object_id if p.swarm_anchor_object_id else None
        return cls(
            state=SealState(wire_state),
            batch_root=Hash.from_proto(p.batch_root) if p.HasField("batch_root") else None,
            merkle_path=[Hash.from_proto(h) for h in p.merkle_path],
            sealed_at=Timestamp.from_proto(p.sealed_at) if p.HasField("sealed_at") else None,
            on_chain_tx_digest=on_chain_tx_digest,
            swarm_anchor_object_id=swarm_anchor_object_id,
        )

    def to_proto(self) -> proto.SealStatus:
        # Same proto-enum-nominal-mismatch story as elsewhere.
        out = proto.SealStatus(
            state=self.state.value,  # type: ignore[arg-type]
            merkle_path=[h.to_proto() for h in self.merkle_path],
        )
        if self.batch_root is not None:
            out.batch_root.CopyFrom(self.batch_root.to_proto())
        if self.sealed_at is not None:
            out.sealed_at.CopyFrom(self.sealed_at.to_proto())
        if self.on_chain_tx_digest is not None:
            out.on_chain_tx_digest = self.on_chain_tx_digest
        if self.swarm_anchor_object_id is not None:
            out.swarm_anchor_object_id = self.swarm_anchor_object_id
        return out


# =============================================================================
# Receipt
# =============================================================================


class Receipt(BaseModel):
    """A signed, content-addressed record of a consequential action.

    Read-only on the SDK side. Construct only via ``.from_proto(...)``
    on a response from the control plane; ``.canonical_bytes()`` is
    available for integrity verification."""

    model_config = ConfigDict(frozen=True)

    spec_version: str
    swarm_id: SwarmId
    actor: AgentId
    action_kind: str
    causal: CausalRef = Field(default_factory=CausalRef.empty)
    evidence: list[Evidence] = Field(default_factory=list)
    constitution_version: str
    cost: CostAnnotation | None = None
    occurred_at: Timestamp
    seal: SealStatus = Field(default_factory=SealStatus)
    signatures: list[SignedBy] = Field(default_factory=list)

    @classmethod
    def from_proto(cls, p: proto.Receipt) -> Receipt:
        return cls(
            spec_version=p.spec_version.value,
            swarm_id=SwarmId.from_proto(p.swarm_id),
            actor=AgentId.from_proto(p.actor),
            action_kind=p.action_kind,
            causal=CausalRef.from_proto(p.causal),
            evidence=[Evidence.from_proto(e) for e in p.evidence],
            constitution_version=p.constitution_version,
            cost=CostAnnotation.from_proto(p.cost) if p.HasField("cost") else None,
            occurred_at=Timestamp.from_proto(p.occurred_at),
            seal=SealStatus.from_proto(p.seal),
            signatures=[SignedBy.from_proto(s) for s in p.signatures],
        )

    def to_proto(self) -> proto.Receipt:
        out = proto.Receipt(
            spec_version=common_pb2.Version(value=self.spec_version),
            swarm_id=self.swarm_id.to_proto(),
            actor=self.actor.to_proto(),
            action_kind=self.action_kind,
            causal=self.causal.to_proto(),
            evidence=[e.to_proto() for e in self.evidence],
            constitution_version=self.constitution_version,
            occurred_at=self.occurred_at.to_proto(),
            seal=self.seal.to_proto(),
            signatures=[s.to_proto() for s in self.signatures],
        )
        if self.cost is not None:
            out.cost.CopyFrom(self.cost.to_proto())
        return out

    def canonical_bytes(self) -> bytes:
        """Canonical bytes with signatures, seal, and extensions cleared
        — what the receipt's content-address hashes. Matches the Rust
        ``Receipt::to_canonical_proto`` semantics."""
        p = self.to_proto()
        p.ClearField("signatures")
        p.ClearField("seal")
        p.ClearField("extensions")
        return _canonical_bytes(p)

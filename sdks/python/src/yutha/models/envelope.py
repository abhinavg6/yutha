"""Envelope ergonomic model + supporting types.

Mirrors ``/spec/envelope/envelope-v1.proto`` and the Rust ``Envelope``
in ``crates/yutha-transport/src/envelope.rs``.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from yutha._proto import common_pb2
from yutha._proto.envelope import envelope_v1_pb2 as proto
from yutha.canonical import canonical_bytes as _canonical_bytes
from yutha.crypto import SigningKey, VerificationFailed, verify
from yutha.identity import AgentId, CausalRef, Hash, PublicKey, Signature, SwarmId, Timestamp


class Performative(IntEnum):
    """Speech-act kinds. Wire numbers match the proto enum directly.

    The Rust ``Performative`` enum spells out the same 11 variants in
    the same order. ``UNKNOWN = 0`` is intentionally absent here —
    constructing an envelope with an unknown performative is a
    construction error (per spec rationale §3).
    """

    PROPOSE = 1
    COUNTER = 2
    COMMIT = 3
    ABORT = 4
    RELEASE = 5
    QUERY = 6
    INFORM = 7
    ERROR = 8
    REQUEST_ACTION = 9
    CONFIRM = 10
    DECLINE = 11


# -----------------------------------------------------------------------------
# Recipient (oneof on the wire; tagged-union in Python)
# -----------------------------------------------------------------------------


class SwarmBroadcast(BaseModel):
    """Swarm-wide broadcast recipient with optional tag filter."""

    model_config = ConfigDict(frozen=True)

    filter_tags: list[str] = Field(default_factory=list)


class ExternalEndpoint(BaseModel):
    """External (off-swarm) endpoint recipient."""

    model_config = ConfigDict(frozen=True)

    scheme: str
    authority: str
    path_hint: str = ""


# Recipient is a tagged union. We model it as a Pydantic discriminated
# union so callers can write `Recipient(agent=AgentId(...))` or
# `Recipient(role="supervisor")` without juggling oneof wire shapes.


class Recipient(BaseModel):
    """Tagged union: exactly one of ``agent``, ``role``, ``swarm``,
    ``external`` must be set."""

    model_config = ConfigDict(frozen=True)

    agent: AgentId | None = None
    role: str | None = None
    swarm: SwarmBroadcast | None = None
    external: ExternalEndpoint | None = None

    def _populated_count(self) -> int:
        return sum(x is not None for x in (self.agent, self.role, self.swarm, self.external))

    def model_post_init(self, __context: Any, /) -> None:
        if self._populated_count() != 1:
            raise ValueError(
                "Recipient must have exactly one of agent / role / swarm / external set; "
                f"got {self._populated_count()}"
            )

    @classmethod
    def for_agent(cls, agent_id: AgentId) -> Recipient:
        return cls(agent=agent_id)

    @classmethod
    def for_role(cls, role: str) -> Recipient:
        return cls(role=role)

    @classmethod
    def for_swarm(cls, filter_tags: list[str] | None = None) -> Recipient:
        return cls(swarm=SwarmBroadcast(filter_tags=filter_tags or []))

    @classmethod
    def for_external(cls, scheme: str, authority: str, path_hint: str = "") -> Recipient:
        return cls(
            external=ExternalEndpoint(scheme=scheme, authority=authority, path_hint=path_hint)
        )

    @classmethod
    def from_proto(cls, p: proto.Recipient) -> Recipient:
        which = p.WhichOneof("to")
        if which == "agent":
            return cls(agent=AgentId.from_proto(p.agent))
        if which == "role":
            return cls(role=p.role)
        if which == "swarm":
            return cls(swarm=SwarmBroadcast(filter_tags=list(p.swarm.filter_tags)))
        if which == "external":
            return cls(
                external=ExternalEndpoint(
                    scheme=p.external.scheme,
                    authority=p.external.authority,
                    path_hint=p.external.path_hint,
                )
            )
        raise ValueError("Recipient proto has no `to` variant set")

    def to_proto(self) -> proto.Recipient:
        out = proto.Recipient()
        if self.agent is not None:
            out.agent.CopyFrom(self.agent.to_proto())
        elif self.role is not None:
            out.role = self.role
        elif self.swarm is not None:
            out.swarm.CopyFrom(proto.SwarmBroadcast(filter_tags=list(self.swarm.filter_tags)))
        elif self.external is not None:
            out.external.CopyFrom(
                proto.ExternalEndpoint(
                    scheme=self.external.scheme,
                    authority=self.external.authority,
                    path_hint=self.external.path_hint,
                )
            )
        return out


# -----------------------------------------------------------------------------
# Envelope
# -----------------------------------------------------------------------------


class Envelope(BaseModel):
    """A typed, signed message wrapper. Construct, then ``.sign(key)``
    to attach ``agent_signature``."""

    model_config = ConfigDict(frozen=True)

    spec_version: str
    swarm_id: SwarmId
    envelope_id: bytes
    from_agent: AgentId
    recipient: Recipient
    performative: Performative
    payload: bytes = b""
    payload_schema_id: str = ""
    tags: list[str] = Field(default_factory=list)
    causal: CausalRef = Field(default_factory=CausalRef.empty)
    nonce: bytes
    epoch: int
    sent_at: Timestamp
    expires_at: Timestamp | None = None
    in_reply_to: Hash | None = None
    agent_signature: Signature | None = None

    @classmethod
    def from_proto(cls, p: proto.Envelope) -> Envelope:
        return cls(
            spec_version=p.spec_version.value,
            swarm_id=SwarmId.from_proto(p.swarm_id),
            envelope_id=bytes(p.envelope_id),
            from_agent=AgentId.from_proto(p.from_agent),
            recipient=Recipient.from_proto(p.recipient),
            performative=Performative(p.performative),
            payload=bytes(p.payload),
            payload_schema_id=p.payload_schema_id,
            tags=list(p.tags),
            causal=CausalRef.from_proto(p.causal),
            nonce=bytes(p.nonce),
            epoch=p.epoch,
            sent_at=Timestamp.from_proto(p.sent_at),
            expires_at=Timestamp.from_proto(p.expires_at) if p.HasField("expires_at") else None,
            in_reply_to=Hash.from_proto(p.in_reply_to) if p.HasField("in_reply_to") else None,
            agent_signature=Signature.from_proto(p.agent_signature)
            if p.HasField("agent_signature")
            else None,
        )

    def to_proto(self) -> proto.Envelope:
        # proto.Envelope's `performative` parameter is typed as
        # `proto.Performative | str | None`; we pass an int from our
        # IntEnum. Same wire numbers, nominally distinct types.
        out = proto.Envelope(
            spec_version=common_pb2.Version(value=self.spec_version),
            swarm_id=self.swarm_id.to_proto(),
            envelope_id=self.envelope_id,
            from_agent=self.from_agent.to_proto(),
            recipient=self.recipient.to_proto(),
            performative=self.performative.value,  # type: ignore[arg-type]
            payload=self.payload,
            payload_schema_id=self.payload_schema_id,
            tags=list(self.tags),
            causal=self.causal.to_proto(),
            nonce=self.nonce,
            epoch=self.epoch,
            sent_at=self.sent_at.to_proto(),
        )
        if self.expires_at is not None:
            out.expires_at.CopyFrom(self.expires_at.to_proto())
        if self.in_reply_to is not None:
            out.in_reply_to.CopyFrom(self.in_reply_to.to_proto())
        if self.agent_signature is not None:
            out.agent_signature.CopyFrom(self.agent_signature.to_proto())
        return out

    def canonical_bytes(self) -> bytes:
        p = self.to_proto()
        p.ClearField("agent_signature")
        p.ClearField("extensions")
        return _canonical_bytes(p)

    def sign(self, signing_key: SigningKey, public_key: PublicKey | None = None) -> Envelope:
        """Return a copy with ``agent_signature`` attached.

        Unlike Passport, Envelope doesn't carry the sender's public key
        inline — verification requires resolving ``from_agent`` against
        the passport registry. The optional ``public_key`` argument is
        only used to cross-check that the signing key matches what the
        caller expects.
        """
        if public_key is not None and signing_key.public_key_bytes() != public_key.value:
            raise ValueError("signing key does not match the supplied public_key")
        sig = signing_key.sign_message(self.canonical_bytes())
        return self.model_copy(update={"agent_signature": sig})

    def verify_signature(self, sender_public_key: PublicKey) -> None:
        """Verify the sender's signature against the supplied public
        key + the canonical bytes. Raises on failure."""
        if self.agent_signature is None:
            raise VerificationFailed("envelope has no agent_signature to verify")
        verify(sender_public_key, self.canonical_bytes(), self.agent_signature)

"""Ergonomic Pydantic v2 models for the four signed Yutha message types.

The proto-generated types under ``yutha._proto`` are the wire format —
they're what gets serialized, what protobuf validates at decode time,
and what the gRPC client sends. The models in this package wrap those
types with:

  - Constructor validation (e.g. AgentId length, RFC 3339 timestamps).
  - ``.from_proto(p)`` / ``.to_proto()`` round-trip.
  - ``.canonical_bytes()`` — content-addressable bytes with
    signature / extensions / seal cleared per the Rust
    ``to_canonical_proto()`` convention.
  - ``.sign(signing_key)`` / ``.verify_signature(public_key)`` for the
    three actor-signed types (Passport, Envelope, Capability).

The Receipt model is read-only on the SDK side — clients query receipts,
they don't construct them. (The control plane is the only writer.) It
still has ``.canonical_bytes()`` for integrity checks against the
receipt-id surface that ``ReceiptService.Get`` returns.
"""

from yutha.models.capability import (
    ActionDescriptor,
    Capability,
    Caveat,
    CheckOutcome,
    ConstitutionVersionCaveat,
    ControlPlaneIssuer,
    Issuer,
    NeverIfTaggedCaveat,
    OnlyIfTaggedCaveat,
    RateLimitCaveat,
    Scope,
    SupervisorRequiredCaveat,
    TimeOfDayCaveat,
)
from yutha.models.constitution import Constitution
from yutha.models.envelope import (
    Envelope,
    ExternalEndpoint,
    Performative,
    Recipient,
    SwarmBroadcast,
)
from yutha.models.passport import (
    CapabilityDeclaration,
    Passport,
    PassportTier,
    ResourceDeclaration,
)
from yutha.models.receipt import (
    Evidence,
    Receipt,
    SealState,
    SealStatus,
    SignatureRole,
    SignedBy,
)

__all__ = [
    # Passport.
    "Passport",
    "PassportTier",
    "CapabilityDeclaration",
    "ResourceDeclaration",
    # Envelope.
    "Envelope",
    "Performative",
    "Recipient",
    "SwarmBroadcast",
    "ExternalEndpoint",
    # Capability.
    "Capability",
    "Issuer",
    "ControlPlaneIssuer",
    "Scope",
    "Caveat",
    "TimeOfDayCaveat",
    "ConstitutionVersionCaveat",
    "SupervisorRequiredCaveat",
    "RateLimitCaveat",
    "OnlyIfTaggedCaveat",
    "NeverIfTaggedCaveat",
    "ActionDescriptor",
    "CheckOutcome",
    # Constitution.
    "Constitution",
    # Receipt.
    "Receipt",
    "Evidence",
    "SignedBy",
    "SignatureRole",
    "SealStatus",
    "SealState",
]

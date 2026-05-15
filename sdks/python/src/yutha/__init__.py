"""Yutha Python SDK — async client for the Yutha control plane.

Public surface:

  - :class:`YuthaClient` — async client over the four control-plane
    services, with auto-renewing bearer-token auth.
  - :class:`BearerSession` — the auth layer, available standalone for
    callers that want to wire interceptors into their own channel.
  - Pydantic models for every signed message: :class:`Passport`,
    :class:`Envelope`, :class:`Capability`, :class:`Receipt`, plus all
    their nested types.
  - Crypto + identity primitives: :class:`SigningKey`, :class:`AgentId`,
    :class:`SwarmId`, :class:`Hash`, :class:`Timestamp`, etc.
"""

from __future__ import annotations

__version__ = "0.1.0a1"

# Eager-import the proto package so codegen drift surfaces at
# `import yutha` time rather than at first use.
from yutha import _proto  # noqa: F401
from yutha.auth import BearerSession, make_interceptors, skip_auth_metadata
from yutha.channel import make_channel
from yutha.client import (
    AdmissionAPI,
    CapabilityAPI,
    EnvelopeAPI,
    OperatorRevokeOutcome,
    ReceiptAPI,
    YuthaClient,
)
from yutha.crypto import (
    CryptoError,
    SigningKey,
    VerificationFailed,
    content_address,
    deterministic_signing_key,
    fingerprint_public_key,
    sha256,
    verify,
)
from yutha.identity import (
    AgentId,
    CausalRef,
    Hash,
    HashAlgorithm,
    PublicKey,
    Signature,
    SignatureAlgorithm,
    SwarmId,
    Timestamp,
)
from yutha.models import (
    ActionDescriptor,
    Capability,
    CapabilityDeclaration,
    Caveat,
    CheckOutcome,
    ConstitutionVersionCaveat,
    ControlPlaneIssuer,
    Envelope,
    Evidence,
    ExternalEndpoint,
    Issuer,
    NeverIfTaggedCaveat,
    OnlyIfTaggedCaveat,
    Passport,
    PassportTier,
    Performative,
    RateLimitCaveat,
    Receipt,
    Recipient,
    ResourceDeclaration,
    Scope,
    SealState,
    SealStatus,
    SignatureRole,
    SignedBy,
    SupervisorRequiredCaveat,
    SwarmBroadcast,
    TimeOfDayCaveat,
)

__all__ = [
    "__version__",
    # Client.
    "YuthaClient",
    "AdmissionAPI",
    "CapabilityAPI",
    "EnvelopeAPI",
    "OperatorRevokeOutcome",
    "ReceiptAPI",
    "BearerSession",
    "make_interceptors",
    "make_channel",
    "skip_auth_metadata",
    # Crypto.
    "SigningKey",
    "verify",
    "sha256",
    "content_address",
    "fingerprint_public_key",
    "deterministic_signing_key",
    "CryptoError",
    "VerificationFailed",
    # Identifiers + primitives.
    "AgentId",
    "SwarmId",
    "Hash",
    "HashAlgorithm",
    "Signature",
    "SignatureAlgorithm",
    "PublicKey",
    "Timestamp",
    "CausalRef",
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
    # Receipt.
    "Receipt",
    "Evidence",
    "SignedBy",
    "SignatureRole",
    "SealStatus",
    "SealState",
]

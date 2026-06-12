"""Yutha Python SDK — async client for the Yutha control plane.

Public surface:

  - :class:`YuthaClient` — async client over the four control-plane
    services, with auto-renewing bearer-token auth.
  - :class:`BearerSession` — the auth layer, available standalone for
    callers that want to wire interceptors into their own channel.
  - Pydantic models for every signed message: :class:`Passport`,
    :class:`Envelope`, :class:`Capability`, :class:`Receipt`, plus all
    their nested types.
  - Crypto + identity primitives: :class:`Signer`, :class:`InProcessSigner`,
    :class:`SigningKey`, :class:`AgentId`, :class:`SwarmId`,
    :class:`Hash`, :class:`Timestamp`, etc.
"""

from __future__ import annotations

__version__ = "0.1.0a1"

# Eager-import the proto package so codegen drift surfaces at
# `import yutha` time rather than at first use.
from yutha import _proto  # noqa: F401
from yutha.auth import BearerSession, make_interceptors, skip_auth_metadata
from yutha.channel import make_channel
from yutha.client import (
    ActivatedConstitution,
    ActivatedShadowConstitution,
    ActiveConstitution,
    ActiveShadowConstitution,
    AdmissionAPI,
    CapabilityAPI,
    ConstitutionAPI,
    ConstitutionDenied,
    EnvelopeAPI,
    OperatorRevokeOutcome,
    ReceiptAPI,
    ReplayAPI,
    ReplayMode,
    ReplayProgressEvent,
    ReplaySessionClosed,
    ReplaySessionCreated,
    ReplaySessionInfo,
    ReplaySessionWindow,
    ShadowCleared,
    ShadowPromoted,
    YuthaClient,
)
from yutha.crypto import (
    CryptoError,
    InProcessSigner,
    Signer,
    SigningKey,
    VerificationFailed,
    content_address,
    deterministic_signing_key,
    fingerprint_public_key,
    sha256,
    verify,
)
from yutha.diff import (
    BehaviouralDiff,
    CedarPolicyEntry,
    ChainDivergence,
    ConstitutionDiff,
    DiffError,
    NamedItemChange,
    NamedItemsDiff,
    ReceiptCountDelta,
    diff_constitutions,
    diff_constitutions_against_window,
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
    Constitution,
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
from yutha.sim import (
    PersonaState,
    SimError,
    SimulationOutcome,
    TerminalReason,
    parse_outcome_json,
    run_scenario,
)

__all__ = [
    "__version__",
    # Client.
    "YuthaClient",
    "AdmissionAPI",
    "CapabilityAPI",
    "ConstitutionAPI",
    "ConstitutionDenied",
    "EnvelopeAPI",
    "OperatorRevokeOutcome",
    "ActivatedConstitution",
    "ActiveConstitution",
    "ActivatedShadowConstitution",
    "ShadowCleared",
    "ShadowPromoted",
    "ActiveShadowConstitution",
    "ReplayAPI",
    "ReplayMode",
    "ReplaySessionWindow",
    "ReplaySessionCreated",
    "ReplayProgressEvent",
    "ReplaySessionClosed",
    "ReplaySessionInfo",
    "ReceiptAPI",
    # Constitution diff (Phase 3d).
    "diff_constitutions",
    "diff_constitutions_against_window",
    "ConstitutionDiff",
    "NamedItemsDiff",
    "NamedItemChange",
    "CedarPolicyEntry",
    "BehaviouralDiff",
    "ReceiptCountDelta",
    "ChainDivergence",
    "DiffError",
    # Simulation harness (Phase 3e).
    "run_scenario",
    "parse_outcome_json",
    "SimulationOutcome",
    "PersonaState",
    "TerminalReason",
    "SimError",
    "BearerSession",
    "make_interceptors",
    "make_channel",
    "skip_auth_metadata",
    # Crypto.
    "Signer",
    "InProcessSigner",
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

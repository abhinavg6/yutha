//! [`SignedBy`] and [`SignatureRole`].
//!
//! Mirrors `SignedBy` and `SignatureRole` from
//! [`/spec/receipt/receipt-v1.proto`](../../../spec/receipt/receipt-v1.proto).
//! Receipts are at-least-once-signed (the actor); additional roles cover
//! control-plane countersign, supervisor countersign, attestation, and Merkle
//! batch root.

use yutha_core::{Signature, Timestamp};

/// Signature roles, in canonical wire order.
///
/// Per receipt rationale §3, the canonical order is ACTOR → CONTROL_PLANE →
/// SUPERVISOR → ATTESTATION → BATCH_ROOT. Each later signer signs over the
/// receipt with all prior signatures included; the verifier walks in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SignatureRole {
    /// The agent that performed the action. Required.
    Actor,
    /// Countersign from the control plane that processed the action.
    ControlPlane,
    /// Countersign from a supervisor for two-person-rule actions.
    Supervisor,
    /// Verifiable-tier attestation (Nautilus or equivalent).
    Attestation,
    /// Merkle-batch-root signature; added by the receipt store on seal.
    BatchRoot,
}

impl SignatureRole {
    /// Canonical wire-order rank (lower comes first).
    pub const fn rank(self) -> u8 {
        match self {
            Self::Actor => 0,
            Self::ControlPlane => 1,
            Self::Supervisor => 2,
            Self::Attestation => 3,
            Self::BatchRoot => 4,
        }
    }
}

/// A signature with role and timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedBy {
    /// Which role this signer is acting in.
    pub role: SignatureRole,
    /// The signature itself.
    pub signature: Signature,
    /// When the signing happened.
    pub signed_at: Timestamp,
}

impl SignedBy {
    /// Construct a SignedBy.
    pub fn new(role: SignatureRole, signature: Signature, signed_at: Timestamp) -> Self {
        Self {
            role,
            signature,
            signed_at,
        }
    }
}

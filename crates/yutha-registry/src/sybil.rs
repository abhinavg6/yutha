//! Sybil-resistance requirements.
//!
//! Five mechanisms from the spec. At scaffolding level the
//! [`SybilResistanceRequirement::check`] returns Ok for all variants
//! (trivial-accept). Real implementations land per-mechanism in their own
//! sub-crates; this scaffold defines the surface.

use crate::error::{RegistryError, Result};
use yutha_passport::Passport;

/// Sybil-resistance mechanism. A swarm's open admission policy AND-composes
/// one or more of these.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SybilResistanceRequirement {
    /// Compute-cost barrier. Cheap to verify; commodity-CPU-vulnerable.
    ProofOfWork(ProofOfWorkRequirement),
    /// TEE remote attestation. Strong but not universally available.
    HardwareAttestation(HardwareAttestationRequirement),
    /// Proof of external identity (OIDC / SPIFFE / DID).
    IdpAttestation(IdpAttestationRequirement),
    /// Lockable / slashable stake.
    Stake(StakeRequirement),
    /// One-shot invite token from an existing member.
    Invite(InviteRequirement),
}

impl SybilResistanceRequirement {
    /// Check the requirement against a passport. Scaffolding-level
    /// trivial-accept; production implementations validate against external
    /// state (challenge tokens, attestation reports, IdP responses, stake
    /// records, invite tokens).
    pub fn check(&self, _passport: &Passport) -> Result<()> {
        match self {
            Self::ProofOfWork(_) => {
                // TODO: verify the challenge solution from the passport's
                // extensions or a separate registration message.
                Ok(())
            }
            Self::HardwareAttestation(_) => {
                // TODO: validate the attestation report against the
                // accepted attestation kinds + their respective roots of
                // trust.
                Ok(())
            }
            Self::IdpAttestation(_) => {
                // TODO: validate the IdP token signature against accepted_issuers.
                Ok(())
            }
            Self::Stake(_) => {
                // TODO: confirm a stake record exists with min_stake_amount
                // locked against the registrant's identity.
                Ok(())
            }
            Self::Invite(_) => {
                // TODO: verify a one-shot invite signed by a permitted_inviter.
                Ok(())
            }
        }
    }
}

/// Proof-of-work parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProofOfWorkRequirement {
    /// Leading zero bits required in SHA-256(challenge || nonce).
    pub difficulty_bits: u32,
    /// Challenge prefix; includes swarm_id and a registry-provided nonce.
    pub challenge_prefix: Vec<u8>,
}

/// Hardware attestation parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HardwareAttestationRequirement {
    /// Accepted attestation kinds (Nautilus, SGX, SEV, TPM).
    pub accepted_kinds: Vec<HardwareAttestationKind>,
}

/// Hardware attestation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum HardwareAttestationKind {
    /// Sui Nautilus attestation.
    Nautilus,
    /// Intel SGX.
    IntelSgx,
    /// AMD SEV.
    AmdSev,
    /// TPM-backed.
    Tpm,
}

/// IdP attestation parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IdpAttestationRequirement {
    /// Accepted IdP issuers.
    pub accepted_issuers: Vec<String>,
    /// Accepted attestation formats (`"oidc"`, `"spiffe"`, `"did"`).
    pub accepted_formats: Vec<String>,
}

/// Stake parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StakeRequirement {
    /// Stake resource (`"usd"`, `"reputation_points"`, etc.).
    pub stake_resource: String,
    /// Minimum stake (decimal string).
    pub min_stake_amount: String,
    /// Slashing endpoint URL.
    pub slashing_endpoint: String,
}

/// Invite parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InviteRequirement {
    /// Valid issuers (existing members). Empty = any existing member may invite.
    pub permitted_inviters: Vec<yutha_core::AgentId>,
    /// Maximum invites per inviter per window.
    pub max_invites_per_inviter: u32,
    /// Window length in seconds.
    pub invite_window_seconds: u64,
}

/// Helper that AND-composes multiple requirements.
pub fn check_all(requirements: &[SybilResistanceRequirement], passport: &Passport) -> Result<()> {
    for r in requirements {
        r.check(passport).map_err(|e| match e {
            RegistryError::SybilCheckFailed(_) => e,
            other => RegistryError::SybilCheckFailed(format!("{other}")),
        })?;
    }
    Ok(())
}

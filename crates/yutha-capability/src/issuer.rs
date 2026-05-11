//! [`Issuer`] — who minted a capability.

use yutha_core::AgentId;

/// Source of a capability.
///
/// Three issuance paths from the spec:
/// - **Agent**: attenuating from a held capability (the common in-swarm path).
/// - **Operator**: minting a fresh root capability (the bootstrap path).
/// - **ControlPlane**: platform-issued (e.g., registration-grants).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Issuer {
    /// Attenuating from a held capability.
    Agent(AgentId),
    /// Operator-issued root capability. Value is the operator-key fingerprint.
    Operator(Vec<u8>),
    /// Control-plane-issued capability.
    ControlPlane(ControlPlaneIssuer),
}

/// Control-plane issuer identity. Distinct kind because audits care: a
/// control-plane-issued capability is *platform-policy*; an operator-issued
/// one is *human-policy*.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ControlPlaneIssuer {
    /// SHA-256 of the control-plane's signing key. 32 bytes.
    pub control_plane_key_fingerprint: Vec<u8>,
    /// Control-plane-instance identifier; observability hint.
    pub instance_id: String,
}

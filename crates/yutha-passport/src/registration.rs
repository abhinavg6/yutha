//! [`RegistrationOutcome`] — what the store returns from `register`.

use yutha_core::{AgentId, Hash};

/// Coarse registration status. Mirrors the proto `RegistrationResult.Status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RegistrationStatus {
    /// Registration accepted; passport is live in the swarm.
    Accepted,
    /// Registration rejected (e.g., admission policy denial).
    Rejected,
    /// Hybrid-mode periphery may pend for operator review.
    PendingReview,
}

/// What a register call returns.
#[derive(Debug, Clone)]
pub struct RegistrationOutcome {
    /// Coarse status.
    pub status: RegistrationStatus,
    /// The agent id (echoed back; equals the passport's).
    pub agent_id: AgentId,
    /// Pointer to the registration receipt in the receipt store. Empty
    /// when status is Rejected (no receipt was produced).
    pub registration_receipt: Option<Hash>,
    /// Human-readable rejection reason when status is Rejected.
    pub rejection_reason: String,
}

impl RegistrationOutcome {
    /// Was the registration accepted?
    pub fn is_accepted(&self) -> bool {
        matches!(self.status, RegistrationStatus::Accepted)
    }
}

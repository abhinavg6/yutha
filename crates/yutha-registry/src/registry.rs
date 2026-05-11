//! [`Registry`] — membership controller trait.

use crate::error::Result;
use async_trait::async_trait;
use yutha_core::AgentId;
use yutha_passport::{Passport, RegistrationOutcome};

/// Membership controller.
///
/// Owns the swarm's topology and gates admission. Wraps a `PassportStore`
/// internally; produces `agent.register` receipts via the receipt store
/// (wired at the control-plane layer).
#[async_trait]
pub trait Registry: Send + Sync {
    /// Attempt to register an agent.
    ///
    /// Implementations MUST:
    /// - Verify the passport's self-signature.
    /// - Check the passport's `swarm_id` matches this registry's swarm.
    /// - Apply the topology's admission policy:
    ///   - **Closed**: allowlist match by agent_id or owner-key fingerprint;
    ///     unknown → REJECTED or PENDING_REVIEW per policy.
    ///   - **Open**: AND-compose all sybil-resistance requirements; check
    ///     min passport tier; check lifetime.
    ///   - **Hybrid**: closed_core then open_periphery; apply
    ///     periphery_capability_constraint when issuing the initial
    ///     capability.
    /// - Persist the passport via the passport store.
    /// - Return a [`RegistrationOutcome`] with status + receipt pointer
    ///   (when the receipt-store side is wired).
    async fn register(&self, passport: Passport) -> Result<RegistrationOutcome>;

    /// Revoke an agent's membership. Produces an `agent.revoke` receipt
    /// signed by the control plane.
    async fn revoke(&self, agent_id: &AgentId, reason: &str) -> Result<()>;

    /// Rotate an agent's signing key. The new passport carries the new
    /// public key, signed with the new key. Continuity (proof that the
    /// old key holder consented) is enforced at the application layer; the
    /// registry produces an `agent.rotate_key` receipt on success.
    async fn rotate_key(&self, new_passport: Passport) -> Result<RegistrationOutcome>;
}

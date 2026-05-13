//! [`Registry`] — membership controller trait.

use crate::error::Result;
use crate::topology::Topology;
use async_trait::async_trait;
use yutha_core::{AgentId, Hash};
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
    /// signed by the control plane. Returns the receipt's content-address
    /// so callers (gRPC handlers, scenarios) can echo it back without
    /// re-querying the receipt store.
    async fn revoke(&self, agent_id: &AgentId, reason: &str) -> Result<Hash>;

    /// Rotate an agent's signing key. The new passport carries the new
    /// public key, signed with the new key. Continuity (proof that the
    /// old key holder consented) is enforced at the application layer; the
    /// registry produces an `agent.rotate_key` receipt on success.
    async fn rotate_key(&self, new_passport: Passport) -> Result<RegistrationOutcome>;

    /// Borrow the swarm's topology.
    ///
    /// Topology is immutable for the swarm's lifetime (per spec rationale),
    /// so callers can rely on the borrow remaining valid as long as the
    /// registry is alive. Used by the control-plane gRPC handler for
    /// `AdmissionService.GetTopology` and by the bearer-token interceptor
    /// for swarm_id binding checks.
    fn topology(&self) -> &Topology;
}

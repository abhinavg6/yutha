//! [`PassportStore`] — the trait every passport backend implements.

use crate::error::Result;
use crate::passport::Passport;
use crate::registration::RegistrationOutcome;
use async_trait::async_trait;
use yutha_core::AgentId;

/// Storage trait for passports.
///
/// In production this is backed by a persistent store (alongside the receipt
/// store, typically Postgres). For tests, use [`crate::MemoryPassportStore`].
#[async_trait]
pub trait PassportStore: Send + Sync {
    /// Persist a freshly self-signed passport. Implementations MUST:
    /// - Verify the passport's self-signature ([`Passport::verify_self_signature`]).
    /// - Reject duplicate agent IDs unless the call is a key rotation
    ///   (handled via [`rotate_key`] for clarity).
    /// - Return a [`RegistrationOutcome`] with the registration receipt's
    ///   content-address. (Producing the receipt itself is the caller's
    ///   responsibility — typically the registry, which integrates this
    ///   crate with `yutha-receipt`. The store may persist receipt-hash
    ///   pointers it's handed.)
    async fn register(&self, passport: Passport) -> Result<RegistrationOutcome>;

    /// Look up a passport by agent id. Returns None if not registered or if
    /// revoked.
    async fn lookup(&self, agent_id: &AgentId) -> Result<Option<Passport>>;

    /// Revoke an agent's passport. Subsequent lookups return None.
    async fn revoke(&self, agent_id: &AgentId, reason: &str) -> Result<()>;

    /// Rotate to a new public key. The new passport is signed with the new
    /// key; continuity comes from a separate signature with the old key
    /// (carried via the caller's flow; not enforced by the store at this
    /// scaffolding level).
    async fn rotate_key(&self, new_passport: Passport) -> Result<RegistrationOutcome>;

    /// Total registered passports (cheap on in-memory; backend-dependent).
    async fn count(&self) -> Result<u64>;
}

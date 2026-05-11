//! [`CapabilityStore`] — issue / attenuate / revoke / check.

use crate::capability::Capability;
use crate::check::{ActionDescriptor, CheckOutcome};
use crate::error::Result;
use async_trait::async_trait;
use yutha_core::Hash;

/// Storage and operations on capabilities.
#[async_trait]
pub trait CapabilityStore: Send + Sync {
    /// Persist a freshly-issued (root) capability. Returns its content-address.
    async fn issue(&self, capability: Capability) -> Result<Hash>;

    /// Persist an attenuated child of `parent`. Implementations MUST verify
    /// that `child.parent == Some(parent_hash)` and refuse if the child
    /// broadens the parent's scope along any dimension (intersection check).
    async fn attenuate(&self, child: Capability) -> Result<Hash>;

    /// Revoke a capability. Subsequent checks against it deny within the
    /// spec'd propagation bound.
    async fn revoke(&self, capability_id: &Hash, reason: &str) -> Result<()>;

    /// Look up a capability by content-address. Returns None if unknown or
    /// revoked.
    async fn lookup(&self, capability_id: &Hash) -> Result<Option<Capability>>;

    /// Check whether `descriptor` is permitted by the capability identified
    /// by `capability_id`, walking the parent chain.
    ///
    /// Implementations MUST:
    /// - Walk the chain up to [`crate::DEFAULT_MAX_CHAIN_DEPTH`] (refuse
    ///   deeper).
    /// - Refuse if any link is revoked or out of validity window.
    /// - Intersect scopes along the chain.
    /// - Evaluate caveats at each link.
    /// - Return a [`CheckOutcome`] with the deny reason on failure.
    async fn check(
        &self,
        capability_id: &Hash,
        descriptor: &ActionDescriptor,
    ) -> Result<CheckOutcome>;
}

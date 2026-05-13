//! [`CapabilityStore`] — issue / attenuate / revoke / check.

use crate::capability::Capability;
use crate::check::{ActionDescriptor, CheckOutcome};
use crate::error::Result;
use async_trait::async_trait;
use yutha_core::Hash;

/// Outcome of an [`CapabilityStore::issue`] or
/// [`CapabilityStore::attenuate`] call.
///
/// Carries both the capability's content-address and the content-address of
/// the substrate receipt that records the issuance / attenuation. Both are
/// needed at the gRPC layer (see `IssueResponse` and `AttenuateResponse` in
/// `/spec/control-plane/v1.proto`).
#[derive(Debug, Clone)]
pub struct IssuanceOutcome {
    /// Content-address of the issued capability.
    pub capability_id: Hash,
    /// Content-address of the `capability.issue` or `capability.attenuate`
    /// receipt that records this operation.
    pub issuance_receipt: Hash,
}

/// Outcome of a [`CapabilityStore::check`] call: the policy outcome plus
/// the content-address of the receipt that records the check.
#[derive(Debug, Clone)]
pub struct CheckEvaluation {
    /// Policy outcome — pass / deny + reasons + matched/unmet caveats.
    pub outcome: CheckOutcome,
    /// Content-address of the `capability.check.pass` or
    /// `capability.check.deny` receipt.
    pub check_receipt: Hash,
}

/// Storage and operations on capabilities.
#[async_trait]
pub trait CapabilityStore: Send + Sync {
    /// Persist a freshly-issued (root) capability and record a
    /// `capability.issue` receipt. Returns both content-addresses.
    async fn issue(&self, capability: Capability) -> Result<IssuanceOutcome>;

    /// Persist an attenuated child of `parent` and record a
    /// `capability.attenuate` receipt. Implementations MUST verify that
    /// `child.parent == Some(parent_hash)` and refuse if the child
    /// broadens the parent's scope along any dimension (intersection
    /// check).
    async fn attenuate(&self, child: Capability) -> Result<IssuanceOutcome>;

    /// Revoke a capability. Subsequent checks against it deny within the
    /// spec'd propagation bound. Records a `capability.revoke` receipt
    /// and returns its content-address.
    async fn revoke(&self, capability_id: &Hash, reason: &str) -> Result<Hash>;

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
    /// - Return a [`CheckEvaluation`] carrying the policy outcome and
    ///   the `capability.check.{pass,deny}` receipt id.
    async fn check(
        &self,
        capability_id: &Hash,
        descriptor: &ActionDescriptor,
    ) -> Result<CheckEvaluation>;
}

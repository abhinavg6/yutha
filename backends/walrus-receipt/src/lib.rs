//! Walrus + Seal + Nautilus reference implementation of the verifiable-tier
//! [`yutha_receipt::ReceiptStore`].
//!
//! **Status: skeleton.** Implementation pending. Per build-plan.md §6, this
//! backend must pass the **same** conformance suite as the default Postgres
//! backend at Phase 1 exit, and additionally pass the Verifiable-tier tests.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

use async_trait::async_trait;
use yutha_core::Hash;
use yutha_receipt::{
    AppendOptions, AppendOutcome, Page, PassportResolver, Query, Receipt, ReceiptStore, Result,
};

/// Verifiable-tier receipt store backed by Walrus storage, Seal encryption,
/// and Nautilus attestation.
#[derive(Debug, Clone)]
pub struct WalrusStore {
    // TODO: walrus_client, seal_client, nautilus_attester
}

impl WalrusStore {
    /// Build a Walrus-backed store. Configuration parameters TBD as the
    /// downstream client APIs mature.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for WalrusStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ReceiptStore for WalrusStore {
    async fn append(
        &self,
        _receipt: Receipt,
        _options: AppendOptions,
        _resolver: &dyn PassportResolver,
    ) -> Result<AppendOutcome> {
        // TODO: resolver.resolve_actor → verify signatures via
        // yutha_receipt::verify_receipt_signatures BEFORE persisting; reject
        // on ActorNotResolvable / SignatureFailed / SignatureOrderInvalid.
        // Then: canonicalize → write canonical bytes to Walrus keyed by
        // content-address; if any evidence has sensitive=true, encrypt via
        // Seal first; produce Nautilus attestation as
        // SignatureRole::Attestation; periodic Merkle-batch seal.
        todo!("walrus append")
    }

    async fn get(&self, _id: &Hash) -> Result<Option<Receipt>> {
        // TODO: read from Walrus by content-address; verify Nautilus
        // attestation; return.
        todo!("walrus get")
    }

    async fn query(&self, _query: Query, _page_token: Option<Vec<u8>>) -> Result<Page> {
        // TODO: Walrus does not natively index by predecessor/agent/action;
        // we maintain side-indices (probably in Postgres or local KV) for
        // these queries. The receipt content stays in Walrus.
        todo!("walrus query")
    }

    async fn count(&self) -> Result<u64> {
        todo!("walrus count")
    }
}

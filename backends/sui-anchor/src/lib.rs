//! Sui-anchor backend for the Yutha [`yutha_receipt::Sealer`] trait.
//!
//! Implements verifiability Layer 1 per
//! [`/spec/verifiability/sui-anchoring.md`](../../../spec/verifiability/sui-anchoring.md):
//! batched receipts → Merkle root → canonical preimage → Ed25519
//! signature → `commit_batch` PTB → on-chain `AnchorCommitted` event +
//! `SealedBatch.commitment_id` populated with the Sui tx digest.
//!
//! ## Layout
//!
//! - [`client`] — `SuiAnchorClient` trait + types. The trait abstracts
//!   the parts of the Sui Rust SDK this crate needs (read a shared
//!   object, submit a transaction). Tests mock the trait; production
//!   code uses [`rpc::RpcAnchorClient`].
//! - [`rpc`] — production impl of `SuiAnchorClient` using
//!   `sui-rpc` + `sui-transaction-builder` + `sui-crypto` +
//!   `sui-sdk-types`.
//! - [`keystore`] — parsing the `suiprivkey1…` canonical Sui keystore
//!   format into an `Ed25519PrivateKey`.
//! - [`sealer`] — [`SuiSealer`], an impl of `yutha_receipt::Sealer` that
//!   wraps a `SuiAnchorClient` and translates `SealedBatch` (no
//!   commitment yet) → `commit_batch` PTB → `SealedBatch` with
//!   commitment_id populated.
//! - [`driver`] — `AnchorDriver`, the background task implementing the
//!   hybrid cadence loop. Public so the control plane can
//!   `tokio::spawn(driver.run())`.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod client;
pub mod driver;
pub mod error;
pub mod keystore;
pub mod rpc;
pub mod sealer;

pub use client::{AnchorState, CommitBatchArgs, SuiAnchorClient};
pub use driver::{AnchorDriver, AnchorDriverConfig};
pub use error::{AnchorBackendError, Result};
pub use keystore::load_sealer_key_from_file;
pub use rpc::RpcAnchorClient;
pub use sealer::SuiSealer;

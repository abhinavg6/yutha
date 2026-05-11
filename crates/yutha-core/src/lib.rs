//! Shared types for Yutha.
//!
//! This crate mirrors [`/spec/common.proto`](https://github.com/yutha/yutha/blob/main/spec/common.proto)
//! in Rust ergonomics. It is intentionally small — anything that smells like
//! business logic belongs in a different crate. Cryptographic operations
//! (sign / verify / hash) live in [`yutha-crypto`](../yutha_crypto/index.html).

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod causal;
pub mod cost;
pub mod error;
pub mod hash;
pub mod identity;
pub mod proto_conv;
pub mod signature;
pub mod time;
pub mod version;

pub use causal::CausalRef;
pub use cost::CostAnnotation;
pub use error::{CoreError, Result};
pub use hash::{Hash, HashAlgorithm};
pub use identity::{AgentId, ReceiptId, SwarmId};
pub use signature::{PublicKey, Signature, SignatureAlgorithm};
pub use time::Timestamp;
pub use version::SpecVersion;

/// Maximum size of any single byte payload in a Yutha-managed structure.
///
/// This is a defensive default applied at deserialization boundaries to bound
/// memory under a hostile input. Operators can tighten via topology; loosening
/// requires an ADR and is generally a bad idea.
pub const MAX_BYTE_PAYLOAD: usize = 16 * 1024 * 1024; // 16 MiB

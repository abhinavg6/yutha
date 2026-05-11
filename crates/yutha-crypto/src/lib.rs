//! Cryptographic primitives for Yutha.
//!
//! Wraps audited Rust libraries (`ed25519-dalek`, `sha2`) behind APIs that
//! produce the value types in [`yutha-core`](../yutha_core/index.html).
//!
//! This crate is the cryptographic substrate; per CODEOWNERS, every change
//! requires Workstream L (security) review.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod canonical;
pub mod error;
pub mod hash;
pub mod sign;

pub use error::{CryptoError, Result};
pub use hash::{fingerprint_public_key, sha256};
pub use sign::{generate_keypair, sign, verify, SigningKey, VerifyingKey};

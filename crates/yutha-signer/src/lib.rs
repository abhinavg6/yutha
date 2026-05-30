//! Pluggable signing-key custody for Yutha.
//!
//! Implements [RFC 0015 — Signer interface](../../../spec/rfcs/0015-signer-interface.md).
//!
//! # Quick orientation
//!
//! Every Ed25519 signing operation in the Yutha substrate flows through the
//! [`Signer`] trait. Implementations may hold the key in process memory
//! ([`InProcessSigner`], the zero-dependency default), or hold only a handle
//! to an external custody backend (cloud KMS, Vault transit — those live in
//! separate optional crates, not here).
//!
//! ```no_run
//! use yutha_signer::{InProcessSigner, Signer};
//!
//! # async fn example() {
//! let seed = [0u8; 32];
//! let signer = InProcessSigner::from_bytes(&seed);
//! let public_key = signer.public_key();
//! let signature = signer.sign_message(b"hello world").await.unwrap();
//! # }
//! ```
//!
//! # Two invariants the trait enforces
//!
//! 1. **No raw-key export.** The trait exposes `public_key` and `sign_message`;
//!    nothing else. Implementations may not return private bytes for any
//!    reason. This is structural — the KMS-backed implementations *cannot*
//!    expose private bytes because they don't have them; the in-process
//!    implementation *will not* expose private bytes because the trait shape
//!    forbids it.
//! 2. **Algorithm pinned to Ed25519.** The returned signature MUST verify
//!    under [`Signer::public_key`] per [RFC 8032]. Implementations wrapping
//!    KMS keys MUST wrap Ed25519 keys.
//!
//! [RFC 8032]: https://datatracker.ietf.org/doc/html/rfc8032

mod error;
mod inprocess;
mod traits;

pub use error::SignerError;
pub use inprocess::InProcessSigner;
pub use traits::Signer;

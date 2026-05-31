//! SPIFFE/SPIRE backend for the Yutha [`Attestor`] trait.
//!
//! Implements [`/spec/identity-keys/attestor-spiffe.md`](../../../spec/identity-keys/attestor-spiffe.md),
//! the byte-exact verification contract that the umbrella
//! [RFC 0016 §3.5](../../../spec/rfcs/0016-attestor-interface.md#35-reference-impl-sketch--spiffespire-phase-e)
//! defers to. The Phase E reference enterprise Attestor.
//!
//! # Quick orientation
//!
//! ```no_run
//! use yutha_attestor::{Attestor, AttestationContext};
//! use yutha_attestor_spiffe::{SpiffeAttestor, SpiffeConfig, TrustBundleSource};
//! use std::path::PathBuf;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Static-bundle flavour — fits air-gapped / edge / dev where no
//! // SPIRE agent socket is reachable.
//! let attestor = SpiffeAttestor::connect(SpiffeConfig {
//!     source: TrustBundleSource::StaticFile {
//!         path: PathBuf::from("/etc/yutha/trust-bundle.json"),
//!     },
//!     expected_audience: "yutha-orders-prod".to_string(),
//!     max_staleness: None,    // static path: no staleness check by default
//!     clock_skew_tolerance_secs: 60,
//!     connect_timeout_secs: 10,
//! })
//! .await?;
//!
//! // Workload API flavour — production SPIRE; bundle hot-rotates as
//! // the SPIRE agent streams updates.
//! let attestor = SpiffeAttestor::connect(SpiffeConfig {
//!     source: TrustBundleSource::WorkloadApi {
//!         socket: "/run/spire/sockets/agent.sock".into(),
//!     },
//!     expected_audience: "yutha-orders-prod".to_string(),
//!     max_staleness: None,    // None → derive from spiffe_refresh_hint × 2
//!     clock_skew_tolerance_secs: 60,
//!     connect_timeout_secs: 10,
//! })
//! .await?;
//! # Ok(()) }
//! ```
//!
//! # Two invariants
//!
//! 1. **Trust-bundle reads are atomic-swap-safe.** The cached bundle is
//!    held behind a structure that lets [`SpiffeAttestor::verify`] see
//!    either the old bundle or the new one, never a torn intermediate.
//!    This crate uses `tokio::sync::watch` (Phase E3) for that swap.
//! 2. **No PII in errors.** Per [RFC 0016 §3.1] and the spec's §9.1,
//!    error messages MUST NOT include credential bytes, decoded payload
//!    fields, or subject identifiers. The crate's `map_spiffe_error`
//!    helper centralises the conversions.
//!
//! [RFC 0016 §3.1]: ../../../spec/rfcs/0016-attestor-interface.md#31-the-attestor-trait-rust
//!
//! # Crate layout
//!
//! - [`SpiffeConfig`] — construction-time configuration (which source,
//!   what audience, staleness window, clock-skew tolerance).
//! - [`TrustBundleSource`] — `StaticFile` vs. `WorkloadApi` enum
//!   discriminator. The impl details + the streaming swap land in
//!   Phase E3.
//! - [`SpiffeAttestor`] — the [`Attestor`] impl. Construction
//!   (`connect`) builds the trust-bundle cache; `verify` runs the
//!   9-step algorithm pinned in the spec (delegating signature +
//!   audience + expiry to [`spiffe::JwtSvid::parse_and_validate`]
//!   and adding the spec's clock-skew-tolerant `nbf`/`iat` checks
//!   plus the [`map_spiffe_error`] translation).
//!
//! [`Attestor`]: yutha_attestor::Attestor

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod attestor;
mod config;
mod error;
mod payload;
mod source;

pub use attestor::SpiffeAttestor;
pub use config::SpiffeConfig;
pub use error::map_spiffe_error;
pub use source::TrustBundleSource;

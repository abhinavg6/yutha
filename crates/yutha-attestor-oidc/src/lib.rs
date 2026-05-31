//! OpenID Connect backend for the Yutha [`Attestor`] trait.
//!
//! Implements [`/spec/identity-keys/attestor-oidc.md`](../../../spec/identity-keys/attestor-oidc.md),
//! the byte-exact verification contract that the umbrella
//! [RFC 0016 §3.6](../../../spec/rfcs/0016-attestor-interface.md#36-reference-impl-sketch--oidc-phase-f)
//! defers to. The Phase F broad-compatibility enterprise Attestor.
//!
//! # Quick orientation
//!
//! ```no_run
//! use yutha_attestor::{Attestor, AttestationContext};
//! use yutha_attestor_oidc::{OidcAttestor, OidcConfig, JwksSource};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Discovery mode — the default. Operator points the Attestor at the
//! // IdP's issuer URL; the Attestor fetches /.well-known/openid-configuration
//! // and the linked JWKS at construction.
//! let attestor = OidcAttestor::connect(OidcConfig {
//!     source: JwksSource::Discovery {
//!         issuer_url: "https://login.example.com".to_string(),
//!     },
//!     expected_issuer: "https://login.example.com".to_string(),
//!     expected_audience: "yutha-orders-prod".to_string(),
//!     allowed_algs: vec!["RS256".into(), "ES256".into(), "EdDSA".into()],
//!     project_claims: vec!["groups".into(), "email".into()],
//!     cache_ttl_secs: 3600,
//!     max_staleness_secs: Some(86400),
//!     clock_skew_tolerance_secs: 60,
//!     connect_timeout_secs: 10,
//!     allow_insecure_http: false,
//! })
//! .await?;
//! # Ok(()) }
//! ```
//!
//! # Phase F status
//!
//! This crate ships across F1 (spec) → F10 (verification gate). As of
//! **F2 (this scaffold)**, the type surface is declared and the crate
//! compiles, but [`OidcAttestor::connect`] returns
//! `AttestorError::Internal("Phase F in progress; ...")` until F3
//! ([`JwksCache`]) + F4 (verify body) land. Operators today should run
//! `--attestor spiffe` (Phase E reference) or `--attestor native`
//! (zero-dep default).
//!
//! # Two invariants
//!
//! 1. **JWKS reads are atomic-swap-safe.** The cached JWKS is held
//!    behind a structure that lets [`OidcAttestor::verify`] see either
//!    the old JWKS or the new one, never a torn intermediate. F3 picks
//!    the concrete sync primitive.
//! 2. **No PII in errors.** Per [RFC 0016 §3.1] and the spec's §9.1,
//!    error messages MUST NOT include credential bytes, decoded payload
//!    fields, or subject identifiers. The crate's [`map_oidc_error`]
//!    helper centralises the conversions.
//!
//! [RFC 0016 §3.1]: ../../../spec/rfcs/0016-attestor-interface.md#31-the-attestor-trait-rust
//!
//! # Crate layout
//!
//! - [`OidcConfig`] — construction-time configuration (which source,
//!   what issuer + audience, allowed algorithms, claims to project,
//!   cache TTL, staleness window, clock-skew tolerance).
//! - [`JwksSource`] — three-way enum: live OIDC discovery, direct
//!   JWKS-URI override, static JWKS file. Mutually exclusive at
//!   construction (CLI validates).
//! - [`JwksCache`] — in-memory JWKS cache with TTL refresh + kid-miss
//!   async refresh (deduplicated). F3 ships the impl.
//! - [`OidcAttestor`] — the [`Attestor`] impl. F4 ships `verify`.
//! - [`map_oidc_error`] — centralised mapping from internal error
//!   sources (`jsonwebtoken::Error`, `jwks::JwksError`, HTTP failures)
//!   to `AttestorError` per spec §9. F5 fills it in.
//!
//! [`Attestor`]: yutha_attestor::Attestor

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod attestor;
mod config;
mod error;
mod jwks_cache;
mod payload;
mod source;

pub use attestor::OidcAttestor;
pub use config::OidcConfig;
pub use error::map_oidc_error;
pub use jwks_cache::JwksCache;
pub use source::JwksSource;

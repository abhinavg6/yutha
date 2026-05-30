//! Pluggable external-identity verification for Yutha admission.
//!
//! Implements [RFC 0016 — Attestor interface](../../../spec/rfcs/0016-attestor-interface.md).
//!
//! # Quick orientation
//!
//! Today's admission flow has one trust step: the passport must
//! self-verify under its embedded public key. With this crate plugged
//! in, the admission handler also calls a pluggable [`Attestor`] to
//! verify an external credential (a SPIFFE SVID, an OIDC ID token, …)
//! and records the verified external identity in the registration
//! receipt's evidence.
//!
//! ```no_run
//! use yutha_attestor::{Attestor, AttestationContext, NativeAttestor};
//! use yutha_core::{AgentId, PublicKey, SignatureAlgorithm, SwarmId};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let attestor = NativeAttestor::default();
//!
//! let context = AttestationContext {
//!     swarm_id: SwarmId::new(),
//!     claimed_agent_id: AgentId::new(),
//!     agent_public_key: PublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 32])?,
//! };
//!
//! // Native accepts an empty credential and returns a verified-identity
//! // record naming the agent's own passport as the attestation source.
//! let identity = attestor.verify(&context, &[]).await?;
//! assert!(identity.external_identity.starts_with("yutha:native:"));
//! # Ok(()) }
//! ```
//!
//! # Two invariants the trait enforces
//!
//! 1. **`Attestor::verify` is concurrent-safe.** The `Send + Sync` bound
//!    is part of the contract — implementations holding mutable state
//!    (JWKS cache, trust-bundle handle) MUST gate access through an
//!    internal lock or `Arc<Mutex>`.
//! 2. **No PII in errors.** Implementations MUST NOT include the raw
//!    credential bytes or claim contents in `AttestorError` messages.
//!    The operator can correlate via the IdP's audit log if needed; the
//!    Yutha-side error stays redaction-safe.
//!
//! # Crate layout
//!
//! - [`Attestor`] trait — the single verify call.
//! - [`AttestationContext`] — what the admission handler passes in
//!   (swarm_id, claimed agent_id, agent public key). Designed as a
//!   struct so future fields (tenant_id, request metadata) can land as
//!   field-additions without trait-signature breaks.
//! - [`AttestedIdentity`] — the success return value (external IdP
//!   identifier, credential expiry, free-form attributes).
//! - [`AttestorError`] — failure variants split into `Malformed` /
//!   `Rejected` / `TrustRootUnavailable` / `Internal`. The
//!   `TrustRootUnavailable` distinction lets the admission handler
//!   surface a retryable code instead of a permanent reject.
//! - [`NativeAttestor`] — the zero-dependency default. Accepts the
//!   empty credential, returns `yutha:native:<hex>` as the external
//!   identifier. Hobby + dev path runs this.
//!
//! Reference enterprise implementations ship as separate optional
//! crates in Phases E + F:
//!
//! - **`yutha-attestor-spiffe`** *(Phase E)* — SPIFFE JWT-SVID
//!   verification against a SPIRE trust bundle.
//! - **`yutha-attestor-oidc`** *(Phase F)* — OpenID Connect ID-token
//!   verification against a discovery URL's JWKS.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod error;
mod native;
mod traits;
mod types;

pub use error::AttestorError;
pub use native::NativeAttestor;
pub use traits::Attestor;
pub use types::{AttestationContext, AttestedIdentity};

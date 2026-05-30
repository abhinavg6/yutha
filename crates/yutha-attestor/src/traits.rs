//! The [`Attestor`] trait — the single external-identity verification
//! abstraction in Yutha admission.

use crate::error::AttestorError;
use crate::types::{AttestationContext, AttestedIdentity};
use async_trait::async_trait;
use std::fmt::Debug;

/// Verifies an external identity credential at registration time.
///
/// Every Yutha registration's external-credential check flows through
/// this trait. Implementations may hold whatever state their
/// credential flavor requires (SPIFFE trust bundle, OIDC JWKS cache,
/// static config for native).
///
/// # Invariants implementations MUST uphold
///
/// 1. **Concurrent-safe.** The `Send + Sync` bound is part of the
///    contract. Implementations holding mutable state (JWKS cache,
///    refresh handle, internal connection pool) MUST gate access
///    through an internal lock or other concurrency primitive — the
///    admission handler will call into this trait from multiple async
///    tasks.
///
/// 2. **No PII in errors.** Implementations MUST NOT include the raw
///    credential bytes, claim contents, or subject identifiers in the
///    returned [`AttestorError`] messages. The operator can correlate
///    Yutha-side rejections with the IdP's audit log via timestamp +
///    `claimed_agent_id` (which is on the deny-receipt evidence).
///
/// 3. **No mutation of context.** Implementations MUST NOT modify
///    `context`. The Rust borrow checker already enforces this (`&self`
///    + `&AttestationContext`), but worth restating: the context
///    arrives from the admission handler and is logged unchanged into
///    the deny-path receipt if verification fails.
///
/// 4. **Key-binding check.** Implementations MUST verify that the
///    credential's subject controls `context.agent_public_key`. The
///    specifics depend on the Attestor flavor — for SPIFFE that's via
///    the SVID's audience + the passport's already-verified
///    self-signature; for OIDC it's the same with the JWT's `aud`
///    claim. The native Attestor relies on the passport's
///    self-signature alone (because the agent's passport IS the
///    attestation).
///
/// # Forward-compatibility
///
/// The trait shape is designed to be wrappable — a future multi-tenant
/// resolver wraps an `Arc<dyn Attestor>` without changing this trait's
/// signature. The wrapper resolves `context` to the right per-tenant
/// Attestor and delegates. See RFC 0016 §5.4 for the precise extension
/// plan.
///
/// # Example
///
/// ```no_run
/// use yutha_attestor::{Attestor, AttestationContext, NativeAttestor};
/// use yutha_core::{AgentId, PublicKey, SignatureAlgorithm, SwarmId};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let attestor: Box<dyn Attestor> = Box::new(NativeAttestor::default());
/// let ctx = AttestationContext {
///     swarm_id: SwarmId::new(),
///     claimed_agent_id: AgentId::new(),
///     agent_public_key: PublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 32])?,
/// };
/// let identity = attestor.verify(&ctx, &[]).await?;
/// assert_eq!(attestor.id(), "native");
/// assert!(identity.external_identity.starts_with("yutha:native:"));
/// # Ok(()) }
/// ```
#[async_trait]
pub trait Attestor: Send + Sync + Debug {
    /// A short identifier for this Attestor flavor, recorded in the
    /// `agent.register` receipt's `attestor_id` evidence key.
    ///
    /// Convention: lowercase, hyphen-separated, optionally
    /// instance-qualified. Examples: `"native"`, `"spiffe"`,
    /// `"oidc:okta-prod"`. Used purely for audit-log filtering; NOT
    /// policy-load-bearing. (Admission policy must not key on
    /// `attestor_id`; it would create a covert channel for a
    /// malicious operator to swap Attestors and have the substrate
    /// admit different sets of agents.)
    fn id(&self) -> &str;

    /// Verify the presented credential.
    ///
    /// Returns `Ok(AttestedIdentity)` iff:
    ///   - the credential is well-formed for this Attestor's flavor;
    ///   - the credential validates against the Attestor's trust root
    ///     (SPIFFE bundle, OIDC JWKS, native: passport self-signature);
    ///   - the credential is not expired (if it carries an expiry);
    ///   - the credential's subject is consistent with
    ///     `context.agent_public_key` (specifics are flavor-dependent;
    ///     see RFC 0016 §3.5 and §3.6 for SPIFFE / OIDC details).
    ///
    /// Returns `Err(AttestorError)` otherwise. See [`AttestorError`]
    /// for the variant-to-admission-outcome mapping.
    ///
    /// [`AttestorError`]: crate::AttestorError
    async fn verify(
        &self,
        context: &AttestationContext,
        credential: &[u8],
    ) -> Result<AttestedIdentity, AttestorError>;
}

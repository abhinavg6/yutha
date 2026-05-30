//! [`AttestationContext`] and [`AttestedIdentity`] — value types for the
//! [`Attestor`](crate::Attestor) trait.

use std::collections::BTreeMap;
use yutha_core::{AgentId, PublicKey, SwarmId, Timestamp};

/// Context the admission handler passes to [`Attestor::verify`].
///
/// Designed as a struct rather than a flat argument list so future
/// fields (tenant_id, request metadata) can land as field-additions
/// without breaking the trait signature. RFC 0016 §3.1 documents the
/// extension shape.
///
/// All fields are required and non-optional in v1.
///
/// [`Attestor::verify`]: crate::Attestor::verify
#[derive(Debug, Clone)]
pub struct AttestationContext {
    /// The swarm this registration targets.
    pub swarm_id: SwarmId,

    /// The agent_id from the registration request's passport. An
    /// [`Attestor`](crate::Attestor) implementation MAY reject if the
    /// claimed id is inconsistent with the credential's subject — e.g.
    /// a SPIFFE Attestor that enforces "agent_id MUST be derived from
    /// the SVID's SPIFFE ID."
    pub claimed_agent_id: AgentId,

    /// The Ed25519 public key the registration is binding. The
    /// [`Attestor`](crate::Attestor) implementation MUST verify (per
    /// its credential flavor) that the credential's subject controls
    /// this key. For SPIFFE that's via the SVID's audience + the
    /// passport's already-verified self-signature; for OIDC it's the
    /// same, with the JWT's `aud` claim matching a Yutha-known value.
    pub agent_public_key: PublicKey,
    // FUTURE EXTENSION HOOKS — documented in RFC 0016 §5.4. Not in v1.
    //
    //   pub tenant_id: Option<TenantId>,
    //   pub request_metadata: BTreeMap<String, String>,
}

/// Result of a successful [`Attestor::verify`] call.
///
/// Forms the basis of the `attested_external_identity` and
/// `attestor_id` evidence keys on the `agent.register` receipt (and
/// the future lifecycle layer hooks on `credential_expires_at`).
///
/// [`Attestor::verify`]: crate::Attestor::verify
#[derive(Debug, Clone)]
pub struct AttestedIdentity {
    /// The IdP-side identifier for the principal.
    ///
    /// Convention by Attestor flavor:
    /// - SPIFFE: the SVID's SPIFFE ID, e.g.
    ///   `spiffe://prod.example.com/workload/yutha-agent`.
    /// - OIDC: the JWT's `sub` claim, optionally issuer-prefixed,
    ///   e.g. `okta:user@example.com`.
    /// - Native: `yutha:native:<agent_id_hex>` (the agent's own
    ///   passport is the attestation source).
    pub external_identity: String,

    /// Wall-clock instant the *external* credential expires.
    ///
    /// `None` ONLY for the native case (no external credential exists,
    /// so nothing to expire). External-credential Attestors MUST
    /// populate this — the future lifecycle layer hooks here to
    /// trigger passport revocation when the IdP-side credential
    /// expires.
    pub credential_expires_at: Option<Timestamp>,

    /// Free-form verified attributes from the credential.
    ///
    /// SPIFFE Attestor populates workload selectors (`k8s_sa`,
    /// `k8s_ns`, …). OIDC Attestor populates selected ID-token
    /// claims (`groups`, `department`, …). Native Attestor returns
    /// an empty map.
    ///
    /// Attributes land in the `agent.register` receipt evidence under
    /// `attributes.<key>: <value>` keys. They do NOT change the
    /// passport's wire format.
    pub attributes: BTreeMap<String, String>,
}

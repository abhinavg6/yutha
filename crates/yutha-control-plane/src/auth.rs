//! Bearer-token authentication for the control-plane gRPC server.
//!
//! ## Wire format
//!
//! Every authenticated RPC carries an `authorization` gRPC metadata header
//! of the form:
//!
//! ```text
//! authorization: bearer <hex>
//! ```
//!
//! where `<hex>` is the prost-encoded
//! [`AgentBearerToken`](yutha_proto::control_plane::v1::AgentBearerToken)
//! with the agent's signature included. The canonical bytes that the
//! signature covers are the same encoding with the `signature` (and
//! `extensions`) fields cleared — the standard Yutha
//! "canonical-with-signature-cleared" pattern that receipts, passports,
//! envelopes, and capabilities all use.
//!
//! ## Per-method policy
//!
//! Per `/spec/control-plane/v1.proto`, `AdmissionService.Register` is the
//! only RPC that does NOT require a bearer token — the passport itself
//! IS the credential. Every other RPC requires a valid token, and
//! [`require_bearer_auth`] is the verification entry point.
//!
//! ## Why this is a free function, not a tonic `Interceptor`
//!
//! tonic 0.11's `Interceptor` trait is synchronous (`fn call(&mut self,
//! Request<()>) -> Result<...>`), but bearer-token verification needs to
//! call `PassportResolver::resolve_actor(&AgentId) -> Future<...>` to
//! look up the agent's public key, then `crypto::sign::verify` against
//! the canonical bytes. We could shoehorn that into a Tower middleware,
//! but the per-handler call site is simpler and keeps the auth context
//! local to the handler that depends on it. The
//! [`BearerInterceptor`] struct below is kept as a sync passthrough so
//! the gRPC server's interceptor wiring stays in place (and gives a
//! single place to emit observability events if we want them); it does
//! not enforce auth.

use std::sync::Arc;

use tonic::{service::Interceptor, Request, Status};
use tracing::trace;

use yutha_core::{AgentId, Signature, SwarmId, Timestamp};
use yutha_proto::control_plane::v1 as cp_proto;
use yutha_proto::Message;
use yutha_receipt::PassportResolver;

use crate::grpc::ControlPlaneState;

/// Metadata header key. Lowercase per HTTP/2 / gRPC convention; tonic
/// internally normalizes, but we use the canonical form here for clarity.
const AUTHORIZATION_HEADER: &str = "authorization";
const BEARER_PREFIX: &str = "bearer ";

/// Which bearer-token variant the wire header carries (RFC 0009 §3.1).
///
/// Header forms (the variant prefix is required):
///   `bearer agent <hex>`     → [`BearerVariant::Agent`]
///   `bearer operator <hex>`  → [`BearerVariant::Operator`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BearerVariant {
    Agent,
    Operator,
}

/// Parse the `authorization` header value into its (variant, hex-body)
/// pair. Returns `Status::unauthenticated` for any malformed header so
/// callers can early-exit uniformly.
///
/// The variant prefix (`agent` / `operator`) is REQUIRED. Pre-RFC-0009
/// drafts admitted `bearer <hex>` without an explicit variant as agent;
/// that compat shim is removed pre-public-release — every SDK we ship
/// emits the explicit variant.
//
// clippy::result_large_err: returns `Result<(BearerVariant, &str), Status>`
// where Status is ~176 bytes. Boxing Status would force the entire gRPC
// handler layer to un-box (Status is tonic's canonical Err); accept the
// imbalance locally, same as the other auth.rs / handler call sites.
#[allow(clippy::result_large_err)]
fn parse_bearer_header(header: &str) -> Result<(BearerVariant, &str), Status> {
    let rest = header
        .strip_prefix(BEARER_PREFIX)
        .or_else(|| header.strip_prefix("Bearer "))
        .ok_or_else(|| Status::unauthenticated("authorization must start with 'bearer '"))?
        .trim();
    if let Some(hex) = rest.strip_prefix("agent ") {
        Ok((BearerVariant::Agent, hex.trim()))
    } else if let Some(hex) = rest.strip_prefix("operator ") {
        Ok((BearerVariant::Operator, hex.trim()))
    } else {
        Err(Status::unauthenticated(
            "authorization must specify variant: 'bearer agent <hex>' or 'bearer operator <hex>'",
        ))
    }
}

/// What the auth layer hands to handlers after successful verification.
///
/// - `agent_id` is the bearer's verified identity. Read by every
///   authenticated handler that needs to gate on who's calling —
///   `AdmissionHandler::revoke`, `EnvelopeHandler::send` (anti-spoofing
///   check), `EnvelopeHandler::subscribe` (no-eavesdropping check).
/// - `swarm_id` and `expires_at` are populated for handler use but no
///   wired handler currently reads them. They're kept on the struct
///   (rather than discarded after validation) so future handlers can
///   surface a "this work would run past your token" rejection without
///   re-parsing the metadata. `#[allow(dead_code)]` is per-field with
///   the rationale local; remove once a consumer lands.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// The authenticated agent.
    pub agent_id: AgentId,
    /// The swarm the token was minted in. Verified inside
    /// [`require_bearer_auth`] to equal this control plane's swarm;
    /// echoed back here so handlers don't need to re-fetch the
    /// topology to know which swarm the caller speaks for.
    #[allow(dead_code)]
    pub swarm_id: SwarmId,
    /// When the token expires. Handlers MAY refuse work that would
    /// run past this — none currently do.
    #[allow(dead_code)]
    pub expires_at: Timestamp,
}

/// Sync passthrough interceptor.
///
/// Wired into every gRPC service so the auth wiring point exists; real
/// verification is async and lives in [`require_bearer_auth`]. The
/// interceptor emits a trace event noting whether an authorization
/// header is present — useful for debugging without enforcing.
#[derive(Clone, Default)]
pub struct BearerInterceptor;

impl BearerInterceptor {
    /// Construct.
    pub fn new() -> Self {
        Self
    }
}

impl Interceptor for BearerInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        let has_auth = request.metadata().contains_key(AUTHORIZATION_HEADER);
        trace!(has_auth, "BearerInterceptor passthrough");
        Ok(request)
    }
}

/// Verify a request's bearer token. Returns the authenticated
/// [`AuthContext`] on success; a `tonic::Status` with code
/// `UNAUTHENTICATED` on any failure.
///
/// Caller is expected to be the handler for an RPC that requires auth
/// (everything except `AdmissionService.Register`).
///
/// ## Verification steps
///
/// 1. Read `authorization: bearer <hex>` from request metadata.
/// 2. Hex-decode and prost-decode into an `AgentBearerToken`.
/// 3. Pull `agent_id`, `swarm_id`, `expires_at`, `signature` from the
///    token (all required; missing → `UNAUTHENTICATED`).
/// 4. Reject if `swarm_id` does not match `expected_swarm` — prevents
///    a token minted for swarm A from being replayed against swarm B.
/// 5. Reject if `expires_at` is in the past (monotonic_ns comparison
///    against `Timestamp::now()`).
/// 6. Resolve the claimed `agent_id`'s public key via the passport
///    resolver; missing → `UNAUTHENTICATED` ("agent not registered").
/// 7. Re-encode the token with `signature` cleared (the same operation
///    the SDK does to compute canonical bytes for signing) and verify
///    the signature against the resolved public key.
///
/// All failure paths return `UNAUTHENTICATED` with a descriptive message;
/// callers should NOT distinguish between them at the policy layer —
/// "the token is no good" is the only actionable distinction.
pub async fn require_bearer_auth<T>(
    request: &Request<T>,
    resolver: &Arc<dyn PassportResolver>,
    expected_swarm: SwarmId,
) -> Result<AuthContext, Status> {
    // -- Parse the header. ---------------------------------------------------
    let header_value = request
        .metadata()
        .get(AUTHORIZATION_HEADER)
        .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?;
    let header_str = header_value
        .to_str()
        .map_err(|_| Status::unauthenticated("authorization metadata is not valid ASCII"))?;
    let (variant, hex_part) = parse_bearer_header(header_str)?;
    if variant != BearerVariant::Agent {
        // This entry point is for AgentBearerToken. OperatorBearerToken
        // goes through `require_operator_bearer_auth`.
        return Err(Status::unauthenticated(
            "this RPC requires an agent bearer; got operator variant",
        ));
    }
    let token_bytes = hex::decode(hex_part)
        .map_err(|e| Status::unauthenticated(format!("authorization hex decode failed: {e}")))?;

    // -- Decode the proto. ---------------------------------------------------
    let token = cp_proto::AgentBearerToken::decode(token_bytes.as_slice())
        .map_err(|e| Status::unauthenticated(format!("bearer token decode failed: {e}")))?;

    let agent_id_proto = token
        .agent_id
        .as_ref()
        .ok_or_else(|| Status::unauthenticated("bearer token missing agent_id"))?;
    let agent_id = AgentId::try_from(agent_id_proto)
        .map_err(|e| Status::unauthenticated(format!("bearer token agent_id invalid: {e}")))?;
    let swarm_id_proto = token
        .swarm_id
        .as_ref()
        .ok_or_else(|| Status::unauthenticated("bearer token missing swarm_id"))?;
    let swarm_id = SwarmId::try_from(swarm_id_proto)
        .map_err(|e| Status::unauthenticated(format!("bearer token swarm_id invalid: {e}")))?;
    let expires_at_proto = token
        .expires_at
        .as_ref()
        .ok_or_else(|| Status::unauthenticated("bearer token missing expires_at"))?;
    let expires_at = Timestamp::try_from(expires_at_proto)
        .map_err(|e| Status::unauthenticated(format!("bearer token expires_at invalid: {e}")))?;
    let signature_proto = token
        .signature
        .as_ref()
        .ok_or_else(|| Status::unauthenticated("bearer token missing signature"))?;
    let signature = Signature::try_from(signature_proto)
        .map_err(|e| Status::unauthenticated(format!("bearer token signature invalid: {e}")))?;

    // -- Swarm binding. ------------------------------------------------------
    // Tokens are scoped to a single swarm; replay across swarms is rejected
    // even if the signature would otherwise verify (the agent might be
    // registered in both swarms with the same key for some reason).
    if swarm_id != expected_swarm {
        return Err(Status::unauthenticated(
            "bearer token swarm_id does not match this control plane",
        ));
    }

    // -- Expiry. -------------------------------------------------------------
    // Tokens are recommended ≤ 5 minutes (per /spec/control-plane/v1.proto).
    // Compare on wall_clock per RFC 0008 — SDK-minted expires_at and
    // CP-checked "now" come from different processes whose monotonic
    // clocks have unrelated origins. Default-fail-closed on malformed
    // wall_clock in either timestamp: an unparseable token expiry
    // counts as expired.
    let now = Timestamp::now();
    let expired = now.wall_at_or_after(&expires_at)
        || now.parsed_wall_clock().is_none()
        || expires_at.parsed_wall_clock().is_none();
    if expired {
        return Err(Status::unauthenticated("bearer token expired"));
    }

    // -- Resolve the agent's public key. -------------------------------------
    let public_key = resolver
        .resolve_actor(&agent_id)
        .await
        // PassportResolver errors are I/O / backend conditions, not policy
        // — surface as INTERNAL so the caller can distinguish "your token
        // is bad" from "we couldn't check it".
        .map_err(|e| Status::internal(format!("passport resolver error: {e}")))?
        .ok_or_else(|| {
            Status::unauthenticated(format!(
                "bearer token claims agent {agent_id} but agent is not registered"
            ))
        })?;

    // -- Verify the signature. -----------------------------------------------
    // Canonical bytes = encoding of the token with `signature` and
    // `extensions` cleared. This is the same pattern receipts, passports,
    // and capabilities use.
    let mut canonical = token.clone();
    canonical.signature = None;
    canonical.extensions = None;
    let canonical_bytes = canonical.encode_to_vec();
    yutha_crypto::sign::verify(&public_key, &canonical_bytes, &signature).map_err(|e| {
        Status::unauthenticated(format!("bearer token signature verification failed: {e}"))
    })?;

    Ok(AuthContext {
        agent_id,
        swarm_id,
        expires_at,
    })
}

/// What the operator-auth layer hands back. Distinct from
/// [`AuthContext`] because operator bearer tokens carry an
/// `operator_id` (free-form audit string) rather than an `agent_id`.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct OperatorAuthContext {
    /// The operator identifier from the token. Free-form; used for
    /// audit-trail clarity. Trust is rooted in the signature
    /// verifying against a configured operator public key.
    pub operator_id: String,
    /// Swarm the token was minted for. Verified to equal this
    /// control plane's swarm before the context is returned.
    pub swarm_id: SwarmId,
    /// When the token expires.
    pub expires_at: Timestamp,
}

/// Best-effort extraction of the `agent_id` from an agent bearer
/// header WITHOUT verifying its signature, decoding swarm/expiry, or
/// touching the registry.
///
/// Returns `None` whenever any step fails — the caller will hit the
/// same failure under full verification and produce a more specific
/// `UNAUTHENTICATED` message there. The only purpose of peeking is
/// to give [`require_active_bearer_auth`] a chance to consult the
/// revoked-set BEFORE the registry-resolver lookup; without this,
/// an evicted agent whose passport has already been deregistered
/// would always surface as "agent is not registered" and the
/// revoked-set check at the bottom of `require_active_bearer_auth`
/// would be dead code on the post-eviction path (RFC 0009 §3.3
/// expects the revoked-set to be the authoritative signal).
///
/// **Safety:** the returned `agent_id` is untrusted. We only use it
/// as a key into a hash set — no policy decision is made beyond
/// "reject with `revoked` instead of `not registered`", and a forged
/// token claiming to be a revoked agent gets rejected either way.
/// Operator bearers are silently ignored (the variant check returns
/// `None`); the dedicated operator path runs through
/// [`require_operator_bearer_auth`].
fn peek_agent_bearer_agent_id<T>(request: &Request<T>) -> Option<AgentId> {
    let header_value = request.metadata().get(AUTHORIZATION_HEADER)?;
    let header_str = header_value.to_str().ok()?;
    let (variant, hex_part) = parse_bearer_header(header_str).ok()?;
    if variant != BearerVariant::Agent {
        return None;
    }
    let token_bytes = hex::decode(hex_part).ok()?;
    let token = cp_proto::AgentBearerToken::decode(token_bytes.as_slice()).ok()?;
    let agent_id_proto = token.agent_id.as_ref()?;
    AgentId::try_from(agent_id_proto).ok()
}

/// Wrapper around [`require_bearer_auth`] that additionally consults
/// the in-process revoked-agents set (RFC 0009 §3.3).
///
/// Use this from any handler whose auth check should reject agents
/// that have been revoked during this process's lifetime — which is
/// every authenticated handler under the v1.2 spec. The bare
/// [`require_bearer_auth`] is kept for callers that don't need the
/// revoked-set check (and to keep existing unit tests stable).
///
/// ## Ordering: revoked-set BEFORE resolver lookup
///
/// `AdmissionService.OperatorRevoke` not only stamps the target into
/// the revoked-set, it also deregisters the target's passport (so
/// future Send-path resolves can't accept the agent as a recipient).
/// That deregistration races AHEAD of any post-eviction bearer-auth
/// check on the fresh-RPC path — without a pre-resolver consult of
/// the revoked-set, every such check would surface "agent is not
/// registered" and the revoked-set would have no observable effect
/// at the gRPC error-message layer. RFC 0009 §3.3 specifies the
/// revoked-set IS the post-eviction rejection signal, so we peek
/// the token's claimed agent_id (without signature verification)
/// and check the set first.
pub async fn require_active_bearer_auth<T>(
    request: &Request<T>,
    state: &ControlPlaneState,
) -> Result<AuthContext, Status> {
    if let Some(claimed_id) = peek_agent_bearer_agent_id(request) {
        if state.is_revoked(&claimed_id).await {
            // Pre-resolver short-circuit — see the doc-comment on
            // this function for why we trust an unverified agent_id
            // here. Full bearer-auth (signature + swarm + expiry)
            // is bypassed because we have an authoritative reason
            // to reject already; a forged-token attacker only gets
            // a different rejection message, not access.
            return Err(Status::unauthenticated("agent revoked"));
        }
    }
    let topology = state.registry.topology();
    let auth = require_bearer_auth(request, &state.resolver, topology.swarm_id).await?;
    // Belt-and-braces re-check: a revoke that lands between the
    // peek above and the resolver lookup completing would otherwise
    // slip through. Keeps the invariant "no authenticated handler
    // ever sees a revoked agent" tight.
    if state.is_revoked(&auth.agent_id).await {
        return Err(Status::unauthenticated("agent revoked"));
    }
    Ok(auth)
}

/// Verify an operator bearer token (RFC 0009 §3.1). Returns
/// [`OperatorAuthContext`] on success; `Status::unauthenticated`
/// otherwise.
///
/// Verification steps:
/// 1. Header parses to the `operator` variant (`bearer operator <hex>`).
/// 2. Server has an operator public key configured (otherwise
///    `FAILED_PRECONDITION` — operator credentials disabled).
/// 3. Hex-decode + prost-decode the body into `OperatorBearerToken`.
/// 4. Swarm binding: token's `swarm_id` matches this control plane's.
/// 5. Wall-clock expiry not in the past (RFC 0008).
/// 6. Ed25519 signature over canonical bytes verifies against the
///    configured operator public key.
pub async fn require_operator_bearer_auth<T>(
    request: &Request<T>,
    state: &ControlPlaneState,
) -> Result<OperatorAuthContext, Status> {
    let operator_pk = state
        .operator_public_key
        .as_ref()
        .ok_or_else(|| Status::failed_precondition("operator credentials not enabled"))?;

    // -- Header parsing. -----------------------------------------------------
    let header_value = request
        .metadata()
        .get(AUTHORIZATION_HEADER)
        .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?;
    let header_str = header_value
        .to_str()
        .map_err(|_| Status::unauthenticated("authorization metadata is not valid ASCII"))?;
    let (variant, hex_part) = parse_bearer_header(header_str)?;
    if variant != BearerVariant::Operator {
        return Err(Status::unauthenticated(
            "this RPC requires an operator bearer; got agent variant",
        ));
    }
    let token_bytes = hex::decode(hex_part)
        .map_err(|e| Status::unauthenticated(format!("authorization hex decode failed: {e}")))?;

    // -- Proto decode. -------------------------------------------------------
    let token = cp_proto::OperatorBearerToken::decode(token_bytes.as_slice())
        .map_err(|e| Status::unauthenticated(format!("operator token decode failed: {e}")))?;
    let swarm_id_proto = token
        .swarm_id
        .as_ref()
        .ok_or_else(|| Status::unauthenticated("operator token missing swarm_id"))?;
    let swarm_id = SwarmId::try_from(swarm_id_proto)
        .map_err(|e| Status::unauthenticated(format!("operator token swarm_id invalid: {e}")))?;
    let expires_at_proto = token
        .expires_at
        .as_ref()
        .ok_or_else(|| Status::unauthenticated("operator token missing expires_at"))?;
    let expires_at = Timestamp::try_from(expires_at_proto)
        .map_err(|e| Status::unauthenticated(format!("operator token expires_at invalid: {e}")))?;
    let signature_proto = token
        .signature
        .as_ref()
        .ok_or_else(|| Status::unauthenticated("operator token missing signature"))?;
    let signature = Signature::try_from(signature_proto)
        .map_err(|e| Status::unauthenticated(format!("operator token signature invalid: {e}")))?;

    // -- Swarm binding. ------------------------------------------------------
    let expected_swarm = state.registry.topology().swarm_id;
    if swarm_id != expected_swarm {
        return Err(Status::unauthenticated(
            "operator token swarm_id does not match this control plane",
        ));
    }

    // -- Expiry (wall-clock per RFC 0008). -----------------------------------
    let now = Timestamp::now();
    let expired = now.wall_at_or_after(&expires_at)
        || now.parsed_wall_clock().is_none()
        || expires_at.parsed_wall_clock().is_none();
    if expired {
        return Err(Status::unauthenticated("operator token expired"));
    }

    // -- Signature. ----------------------------------------------------------
    let mut canonical = token.clone();
    canonical.signature = None;
    canonical.extensions = None;
    let canonical_bytes = canonical.encode_to_vec();
    yutha_crypto::sign::verify(operator_pk, &canonical_bytes, &signature).map_err(|e| {
        Status::unauthenticated(format!("operator token signature verification failed: {e}"))
    })?;

    Ok(OperatorAuthContext {
        operator_id: token.operator_id,
        swarm_id,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use yutha_core::SpecVersion;
    use yutha_passport::{
        MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore, PassportTier,
    };
    use yutha_signer::{InProcessSigner, Signer};

    /// Build a token, sign it, and hex-encode it for the wire.
    async fn mint_token(
        agent_id: AgentId,
        swarm_id: SwarmId,
        signer: &InProcessSigner,
        expires_at: Timestamp,
    ) -> String {
        let mut token = cp_proto::AgentBearerToken {
            agent_id: Some((&agent_id).into()),
            swarm_id: Some((&swarm_id).into()),
            issued_at: Some((&Timestamp::now()).into()),
            expires_at: Some((&expires_at).into()),
            nonce: vec![0xab; 16],
            extensions: None,
            signature: None,
        };
        let canonical = token.encode_to_vec();
        let sig = signer.sign_message(&canonical).await.unwrap();
        token.signature = Some((&sig).into());
        let bytes = token.encode_to_vec();
        hex::encode(bytes)
    }

    /// Build a passport for an agent, register it in the passport store,
    /// and return the resolver plus the signer.
    async fn register_agent(
        swarm_id: SwarmId,
    ) -> (Arc<dyn PassportResolver>, AgentId, InProcessSigner) {
        let store: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
        let signer = InProcessSigner::generate();
        let agent_id = AgentId::new();
        let passport = Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(agent_id)
            .swarm_id(swarm_id)
            .agent_public_key(signer.public_key())
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(&signer)
            .await
            .unwrap();
        store.register(passport).await.unwrap();
        let resolver: Arc<dyn PassportResolver> = Arc::new(PassportResolverAdapter::new(store));
        (resolver, agent_id, signer)
    }

    fn request_with_auth(value: &str) -> Request<()> {
        let mut req = Request::new(());
        req.metadata_mut()
            .insert(AUTHORIZATION_HEADER, value.parse().unwrap());
        req
    }

    fn future_timestamp() -> Timestamp {
        // Wall-clock anchored well into the future. The previous
        // monotonic-only construction (incrementing monotonic_ns
        // alone) stopped working under RFC 0008's wall-clock
        // semantics — the expiry check parses wall_clock and
        // ignores monotonic_ns. Picking a far-future RFC 3339
        // string keeps the test intent ("token is not expired
        // yet") regardless of when this test runs.
        Timestamp::new("2099-01-01T00:00:00Z".into(), u64::MAX / 2).unwrap()
    }

    #[tokio::test]
    async fn valid_token_authenticates() {
        let swarm = SwarmId::new();
        let (resolver, agent_id, signer) = register_agent(swarm).await;
        let hex_token = mint_token(agent_id, swarm, &signer, future_timestamp()).await;
        let req = request_with_auth(&format!("bearer agent {hex_token}"));
        let ctx = require_bearer_auth(&req, &resolver, swarm).await.unwrap();
        assert_eq!(ctx.agent_id, agent_id);
        assert_eq!(ctx.swarm_id, swarm);
    }

    #[tokio::test]
    async fn missing_auth_header_rejected() {
        let swarm = SwarmId::new();
        let (resolver, _, _) = register_agent(swarm).await;
        let req = Request::new(());
        let err = require_bearer_auth(&req, &resolver, swarm)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("missing"));
    }

    #[tokio::test]
    async fn wrong_scheme_rejected() {
        let swarm = SwarmId::new();
        let (resolver, _, _) = register_agent(swarm).await;
        let req = request_with_auth("basic abc123");
        let err = require_bearer_auth(&req, &resolver, swarm)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn wrong_swarm_rejected() {
        let issuer_swarm = SwarmId::new();
        let cp_swarm = SwarmId::new();
        let (resolver, agent_id, signer) = register_agent(issuer_swarm).await;
        let hex_token = mint_token(agent_id, issuer_swarm, &signer, future_timestamp()).await;
        let req = request_with_auth(&format!("bearer agent {hex_token}"));
        let err = require_bearer_auth(&req, &resolver, cp_swarm)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("swarm_id"));
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let swarm = SwarmId::new();
        let (resolver, agent_id, signer) = register_agent(swarm).await;
        // Mint with expiry strictly before now.
        let past = Timestamp::new("2020-01-01T00:00:00Z".into(), 1).unwrap();
        let hex_token = mint_token(agent_id, swarm, &signer, past).await;
        let req = request_with_auth(&format!("bearer agent {hex_token}"));
        let err = require_bearer_auth(&req, &resolver, swarm)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("expired"));
    }

    #[tokio::test]
    async fn unknown_agent_rejected() {
        let swarm = SwarmId::new();
        let (resolver, _registered_agent, _registered_signer) = register_agent(swarm).await;
        let other_signer = InProcessSigner::generate();
        let stranger = AgentId::new();
        let hex_token = mint_token(stranger, swarm, &other_signer, future_timestamp()).await;
        let req = request_with_auth(&format!("bearer agent {hex_token}"));
        let err = require_bearer_auth(&req, &resolver, swarm)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("not registered"));
    }

    #[tokio::test]
    async fn tampered_signature_rejected() {
        // Why we don't just flip the last byte of the wire encoding:
        // prost-encodes AgentBearerToken in tag order, and the signature
        // message's final inner field is `key_fingerprint`. Flipping a
        // byte there leaves `signature.value` (and the message body the
        // signature actually covers) untouched, so Ed25519 verification
        // still succeeds. We instead mint a structurally-valid signature
        // over the wrong bytes — that's the exact failure mode this test
        // is trying to assert.
        let swarm = SwarmId::new();
        let (resolver, agent_id, signer) = register_agent(swarm).await;

        let mut token = cp_proto::AgentBearerToken {
            agent_id: Some((&agent_id).into()),
            swarm_id: Some((&swarm).into()),
            issued_at: Some((&Timestamp::now()).into()),
            expires_at: Some((&future_timestamp()).into()),
            nonce: vec![0xab; 16],
            extensions: None,
            signature: None,
        };
        // Sign DIFFERENT bytes — same key, but a message that has nothing
        // to do with this token's canonical bytes.
        let bogus_sig = signer
            .sign_message(b"definitely not the canonical bytes of this token")
            .await
            .unwrap();
        token.signature = Some((&bogus_sig).into());
        let hex_token = hex::encode(token.encode_to_vec());

        let req = request_with_auth(&format!("bearer agent {hex_token}"));
        let err = require_bearer_auth(&req, &resolver, swarm)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(
            err.message().contains("signature"),
            "expected signature-verification error, got: {}",
            err.message()
        );
    }
}

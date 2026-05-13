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

/// Metadata header key. Lowercase per HTTP/2 / gRPC convention; tonic
/// internally normalizes, but we use the canonical form here for clarity.
const AUTHORIZATION_HEADER: &str = "authorization";
const BEARER_PREFIX: &str = "bearer ";

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
    let hex_part = header_str
        .strip_prefix(BEARER_PREFIX)
        .or_else(|| header_str.strip_prefix("Bearer "))
        .ok_or_else(|| Status::unauthenticated("authorization must start with 'bearer '"))?
        .trim();
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
    // We compare monotonic_ns against the local process's monotonic clock —
    // this is exact for SDK/CP loopback; for remote deployments the SDK and
    // CP necessarily share the wall_clock timeline which is what mints set
    // expires_at against in practice. Operators concerned about clock skew
    // should add an mTLS layer on top.
    let now = Timestamp::now();
    if expires_at.monotonic_ns <= now.monotonic_ns {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use yutha_core::SpecVersion;
    use yutha_crypto::sign::generate_keypair;
    use yutha_passport::{
        MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore, PassportTier,
    };

    /// Build a token, sign it, and hex-encode it for the wire.
    fn mint_token(
        agent_id: AgentId,
        swarm_id: SwarmId,
        signing_key: &yutha_crypto::SigningKey,
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
        let sig = signing_key.sign_message(&canonical);
        token.signature = Some((&sig).into());
        let bytes = token.encode_to_vec();
        hex::encode(bytes)
    }

    /// Build a passport for an agent, register it in the passport store,
    /// and return the resolver plus the signing key.
    async fn register_agent(
        swarm_id: SwarmId,
    ) -> (Arc<dyn PassportResolver>, AgentId, yutha_crypto::SigningKey) {
        let store: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
        let key = generate_keypair();
        let agent_id = AgentId::new();
        let passport = Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(agent_id)
            .swarm_id(swarm_id)
            .agent_public_key(key.public())
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(&key)
            .unwrap();
        store.register(passport).await.unwrap();
        let resolver: Arc<dyn PassportResolver> = Arc::new(PassportResolverAdapter::new(store));
        (resolver, agent_id, key)
    }

    fn request_with_auth(value: &str) -> Request<()> {
        let mut req = Request::new(());
        req.metadata_mut()
            .insert(AUTHORIZATION_HEADER, value.parse().unwrap());
        req
    }

    fn future_timestamp() -> Timestamp {
        let now = Timestamp::now();
        Timestamp::new(now.wall_clock, now.monotonic_ns + 60_000_000_000).unwrap()
    }

    #[tokio::test]
    async fn valid_token_authenticates() {
        let swarm = SwarmId::new();
        let (resolver, agent_id, key) = register_agent(swarm).await;
        let hex_token = mint_token(agent_id, swarm, &key, future_timestamp());
        let req = request_with_auth(&format!("bearer {hex_token}"));
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
        let (resolver, agent_id, key) = register_agent(issuer_swarm).await;
        let hex_token = mint_token(agent_id, issuer_swarm, &key, future_timestamp());
        let req = request_with_auth(&format!("bearer {hex_token}"));
        let err = require_bearer_auth(&req, &resolver, cp_swarm)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("swarm_id"));
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let swarm = SwarmId::new();
        let (resolver, agent_id, key) = register_agent(swarm).await;
        // Mint with expiry strictly before now.
        let past = Timestamp::new("2020-01-01T00:00:00Z".into(), 1).unwrap();
        let hex_token = mint_token(agent_id, swarm, &key, past);
        let req = request_with_auth(&format!("bearer {hex_token}"));
        let err = require_bearer_auth(&req, &resolver, swarm)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("expired"));
    }

    #[tokio::test]
    async fn unknown_agent_rejected() {
        let swarm = SwarmId::new();
        let (resolver, _registered_agent, _registered_key) = register_agent(swarm).await;
        let other_key = generate_keypair();
        let stranger = AgentId::new();
        let hex_token = mint_token(stranger, swarm, &other_key, future_timestamp());
        let req = request_with_auth(&format!("bearer {hex_token}"));
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
        let (resolver, agent_id, key) = register_agent(swarm).await;

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
        let bogus_sig = key.sign_message(b"definitely not the canonical bytes of this token");
        token.signature = Some((&bogus_sig).into());
        let hex_token = hex::encode(token.encode_to_vec());

        let req = request_with_auth(&format!("bearer {hex_token}"));
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

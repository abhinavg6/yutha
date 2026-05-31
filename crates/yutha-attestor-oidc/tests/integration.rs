//! F7 — in-process mock OIDC server integration tests per
//! [spec §11.1](../../../../spec/identity-keys/attestor-oidc.md#111-in-process-mock-oidc-server-for-the-integration-test-not-for-vectors).
//!
//! Unlike the SPIFFE crate's docker-spire integration test (which is
//! `#[ignore]`-gated because docker isn't available in CI), the OIDC
//! mock server is a small axum app inside the test process. No
//! `#[ignore]` — runs in CI on every PR. Validates the Discovery +
//! JWKS-URI-override paths AND the kid-rotation refresh path
//! end-to-end against a real HTTP server.

mod common;

use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
use common::{dummy_context, happy_claims, SigningFixture};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use yutha_attestor::Attestor;
use yutha_attestor_oidc::{JwksSource, OidcAttestor, OidcConfig};

// =====================================================================
// MockOidcServer: tiny axum-based OIDC IdP simulator.
//
// Wraps an axum app that serves /.well-known/openid-configuration +
// /jwks. The JWKS body lives behind an `Arc<RwLock<String>>` so tests
// can swap it mid-run (kid-rotation case). The server task aborts
// when the `MockOidcServer` is dropped — RAII cleanup, no leaked
// listeners across tests.
// =====================================================================

#[derive(Clone)]
struct AppState {
    /// What the discovery doc reports as `issuer`. Equals the bound
    /// `http://127.0.0.1:<port>`. Spec §6.3 requires the operator's
    /// `expected_issuer` to exact-match this.
    issuer: String,
    /// Current JWKS body served from `/jwks`. Behind `RwLock` so
    /// `MockOidcServer::set_jwks` can mutate mid-test.
    jwks_body: Arc<RwLock<String>>,
}

struct MockOidcServer {
    issuer: String,
    jwks_body: Arc<RwLock<String>>,
    _abort: AbortOnDrop,
}

impl MockOidcServer {
    async fn start(initial_jwks_body: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock OIDC server");
        let addr = listener.local_addr().expect("local_addr");
        let issuer = format!("http://{addr}");
        let jwks_body = Arc::new(RwLock::new(initial_jwks_body));

        let state = AppState {
            issuer: issuer.clone(),
            jwks_body: jwks_body.clone(),
        };

        let app = Router::new()
            .route("/.well-known/openid-configuration", get(handle_discovery))
            .route("/jwks", get(handle_jwks))
            .with_state(state);

        let handle = tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app).await {
                eprintln!("mock OIDC server exited: {err}");
            }
        });

        Self {
            issuer,
            jwks_body,
            _abort: AbortOnDrop(handle.abort_handle()),
        }
    }

    fn url(&self) -> &str {
        &self.issuer
    }

    /// Swap the JWKS body the mock serves. Used by the kid-rotation
    /// test to simulate an IdP rotating its signing key mid-session.
    async fn set_jwks(&self, new_body: String) {
        *self.jwks_body.write().await = new_body;
    }
}

async fn handle_discovery(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "issuer": state.issuer,
        "jwks_uri": format!("{}/jwks", state.issuer),
        // Discovery doc fields the Attestor ignores but real IdPs
        // emit; include them so the mock looks like a plausible IdP
        // to anything else that might peek.
        "authorization_endpoint": format!("{}/authorize", state.issuer),
        "token_endpoint": format!("{}/token", state.issuer),
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256", "EdDSA"],
    }))
}

async fn handle_jwks(State(state): State<AppState>) -> impl IntoResponse {
    let body = state.jwks_body.read().await.clone();
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
}

/// RAII wrapper around the server task. Aborts the task when the
/// test function returns, regardless of pass/fail.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// =====================================================================
// Tests
// =====================================================================

#[tokio::test(flavor = "multi_thread")]
async fn discovery_mode_round_trips_against_mock_oidc() {
    let fx = SigningFixture::new_rs256();
    let mock = MockOidcServer::start(fx.jwks_body.clone()).await;

    let attestor = OidcAttestor::connect(OidcConfig {
        source: JwksSource::Discovery {
            issuer_url: mock.url().to_string(),
        },
        expected_issuer: mock.url().to_string(),
        expected_audience: common::EXPECTED_AUDIENCE.into(),
        allowed_algs: vec!["RS256".into(), "ES256".into()],
        project_claims: vec![],
        cache_ttl_secs: 60,
        max_staleness_secs: None,
        clock_skew_tolerance_secs: 60,
        connect_timeout_secs: 5,
        allow_insecure_http: true, // mock OIDC uses HTTP — spec §6.4 escape hatch
    })
    .await
    .expect("Discovery-mode connect against mock OIDC must succeed");

    let mut claims = happy_claims("disco-user");
    claims
        .as_object_mut()
        .unwrap()
        .insert("iss".into(), Value::String(mock.url().to_string()));

    let token = fx.mint_token(&claims);
    let identity = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect("happy-path verify after Discovery warm");

    assert_eq!(
        identity.external_identity,
        format!("oidc:{}:disco-user", mock.url()),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn jwks_uri_override_mode_round_trips_against_mock_oidc() {
    let fx = SigningFixture::new_rs256();
    let mock = MockOidcServer::start(fx.jwks_body.clone()).await;

    let attestor = OidcAttestor::connect(OidcConfig {
        source: JwksSource::JwksUri {
            url: format!("{}/jwks", mock.url()),
        },
        expected_issuer: mock.url().to_string(),
        expected_audience: common::EXPECTED_AUDIENCE.into(),
        allowed_algs: vec!["RS256".into()],
        project_claims: vec![],
        cache_ttl_secs: 60,
        max_staleness_secs: None,
        clock_skew_tolerance_secs: 60,
        connect_timeout_secs: 5,
        allow_insecure_http: true,
    })
    .await
    .expect("JwksUri-override connect against mock OIDC must succeed");

    let mut claims = happy_claims("override-user");
    claims
        .as_object_mut()
        .unwrap()
        .insert("iss".into(), Value::String(mock.url().to_string()));

    let token = fx.mint_token(&claims);
    let identity = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect("happy-path verify after JwksUri warm");

    assert!(identity.external_identity.starts_with("oidc:"));
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_issuer_mismatch_rejects_at_construction() {
    // The mock server reports `issuer = http://127.0.0.1:<port>` in
    // its discovery doc. Configuring the Attestor with a DIFFERENT
    // expected_issuer must fail at construction per spec §6.3
    // (RFC 8414 §3.3 exact-match requirement).
    let fx = SigningFixture::new_rs256();
    let mock = MockOidcServer::start(fx.jwks_body.clone()).await;

    let res = OidcAttestor::connect(OidcConfig {
        source: JwksSource::Discovery {
            issuer_url: mock.url().to_string(),
        },
        expected_issuer: "http://attacker.example.com".to_string(),
        expected_audience: common::EXPECTED_AUDIENCE.into(),
        allowed_algs: vec!["RS256".into()],
        project_claims: vec![],
        cache_ttl_secs: 60,
        max_staleness_secs: None,
        clock_skew_tolerance_secs: 60,
        connect_timeout_secs: 5,
        allow_insecure_http: true,
    })
    .await;

    let err = res.expect_err("discovery-doc issuer mismatch must reject at construct");
    let msg = err.to_string();
    assert!(
        msg.contains("discovery") || msg.contains("issuer"),
        "expected discovery-issuer-mismatch error, got: {msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn kid_rotation_triggers_refresh_and_verify_succeeds() {
    // Scenario: simulate an IdP that rotates its signing key
    // (publishes a new JWKS) after the Attestor has warmed its cache.
    // Spec §5.2 requires the Attestor to refetch JWKS on kid-miss
    // and retry the lookup once.
    //
    // Setup:
    //   - Two RSA keypairs, fx_v1 (initial) and fx_v2 (post-rotation).
    //   - Mock server starts serving JWKS_v1.
    //   - Attestor connects via JwksUri mode (simpler than Discovery
    //     for this test — same code path through `lookup` either way).
    //   - Verify a token signed by v1 → cache hit, succeeds.
    //   - Rotate mock server to serve JWKS_v2.
    //   - Verify a token signed by v2 → cache miss on new kid →
    //     triggers blocking refresh → retry succeeds.
    //
    // Regression guard: an earlier F3 implementation had a wrong
    // dedup heuristic (`elapsed() < 100ms` → skip refresh) that
    // silently broke this case when the rotation happened shortly
    // after the initial warm. F7's bug-fix replaced it with a
    // before/after `last_refresh_at` snapshot comparison. This test
    // would fail under the old code.

    let fx_v1 = SigningFixture::new_rs256();
    let fx_v2 = SigningFixture::new_rs256();
    let mock = MockOidcServer::start(fx_v1.jwks_body.clone()).await;

    let attestor = OidcAttestor::connect(OidcConfig {
        source: JwksSource::JwksUri {
            url: format!("{}/jwks", mock.url()),
        },
        expected_issuer: mock.url().to_string(),
        expected_audience: common::EXPECTED_AUDIENCE.into(),
        allowed_algs: vec!["RS256".into()],
        project_claims: vec![],
        cache_ttl_secs: 3600, // long TTL — refresh MUST be kid-miss-driven, not TTL-driven
        max_staleness_secs: None,
        clock_skew_tolerance_secs: 60,
        connect_timeout_secs: 5,
        allow_insecure_http: true,
    })
    .await
    .expect("warm Attestor against JWKS_v1");

    // Sanity: token signed by v1 verifies against the initial cache.
    let mut claims_v1 = happy_claims("u1");
    claims_v1
        .as_object_mut()
        .unwrap()
        .insert("iss".into(), Value::String(mock.url().to_string()));
    let token_v1 = fx_v1.mint_token(&claims_v1);
    attestor
        .verify(&dummy_context(), token_v1.as_bytes())
        .await
        .expect("v1 token verifies against initial JWKS_v1 cache");

    // ROTATION: server starts serving JWKS_v2. Cache still holds
    // JWKS_v1 — the next verify must trigger a kid-miss refresh.
    mock.set_jwks(fx_v2.jwks_body.clone()).await;

    let mut claims_v2 = happy_claims("u2");
    claims_v2
        .as_object_mut()
        .unwrap()
        .insert("iss".into(), Value::String(mock.url().to_string()));
    let token_v2 = fx_v2.mint_token(&claims_v2);

    let identity = attestor
        .verify(&dummy_context(), token_v2.as_bytes())
        .await
        .expect(
            "v2 token MUST verify after kid-miss-triggered JWKS refresh — \
             if this fails, the `refresh_now` dedup heuristic regressed",
        );

    assert_eq!(
        identity.external_identity,
        format!("oidc:{}:u2", mock.url()),
    );

    // After rotation, a v1 token should still verify (JWKS_v2 doesn't
    // contain v1's kid — kid-miss refresh fetches JWKS_v2 again, still
    // no kid-v1 → Rejected("kid not found in JWKS")). This is the
    // correct semantics: rotated-out keys no longer attest.
    let err = attestor
        .verify(&dummy_context(), token_v1.as_bytes())
        .await
        .expect_err("post-rotation v1 token must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("kid not found"),
        "expected kid-not-found rejection for rotated-out key; got: {msg}"
    );
}

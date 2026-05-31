//! E7 — forged JWT-SVID coverage of the
//! [`SpiffeAttestor`](yutha_attestor_spiffe::SpiffeAttestor) verify
//! path.
//!
//! Each test in this file:
//!   1. Generates a fresh EC P-256 keypair.
//!   2. Builds a static trust-bundle JSON whose JWKS holds the
//!      public key.
//!   3. Constructs the [`SpiffeAttestor`] pointing at the bundle file.
//!   4. Forges a JWT-SVID with specific claims, signs with the private
//!      key.
//!   5. Calls `verify` and asserts the expected outcome.
//!
//! This is the integration-test coverage that proves the verify path
//! correctly delegates to `spiffe::JwtSvid::parse_and_validate`,
//! correctly applies the spec's clock-skew-tolerant `nbf`/`iat`
//! checks, and correctly projects the `selectors` claim per spec §8.
//!
//! See `tests/integration.rs` for the docker-spire path that exercises
//! the Workload-API source against a live SPIRE agent.

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::EncodePrivateKey;
use p256::{EncodedPoint, PublicKey, SecretKey};
use rand_core::OsRng;
use serde::Serialize;
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use yutha_attestor::{AttestationContext, Attestor, AttestorError};
use yutha_attestor_spiffe::{SpiffeAttestor, SpiffeConfig, TrustBundleSource};
use yutha_core::{AgentId, PublicKey as CorePublicKey, SignatureAlgorithm, SwarmId};

const AUDIENCE: &str = "yutha-test-audience";
const TRUST_DOMAIN: &str = "example.org";
const KID: &str = "test-key-1";

/// Test fixture: an EC P-256 keypair + a trust-bundle file containing
/// its public key, plus an `EncodingKey` for the JWT signer.
struct Fixture {
    signing_key: EncodingKey,
    bundle_path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let secret = SecretKey::random(&mut OsRng);
        let public = secret.public_key();

        // jsonwebtoken's ES256 signer takes a PKCS8 PEM. p256 emits
        // that directly.
        let pkcs8_pem = secret
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("encode pkcs8 pem");
        let signing_key = EncodingKey::from_ec_pem(pkcs8_pem.as_bytes())
            .expect("EncodingKey::from_ec_pem accepts our pkcs8");

        let bundle_path = write_temp_bundle(&public);

        Self {
            signing_key,
            bundle_path,
        }
    }

    fn config(&self) -> SpiffeConfig {
        SpiffeConfig {
            source: TrustBundleSource::StaticFile {
                path: self.bundle_path.clone(),
            },
            expected_audience: AUDIENCE.to_string(),
            max_staleness: None,
            clock_skew_tolerance_secs: 60,
            connect_timeout_secs: 10,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.bundle_path);
    }
}

/// Build the SPIFFE trust-bundle JSON our static-file path expects,
/// containing the given EC P-256 public key as a JWKS entry.
fn write_temp_bundle(public: &PublicKey) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);

    let (x_b64, y_b64) = jwk_xy(public);
    let body = json!({
        "trust_domain": TRUST_DOMAIN,
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "kid": KID,
            "use": "jwt-svid",
            "x": x_b64,
            "y": y_b64,
        }],
    });

    let path = std::env::temp_dir().join(format!(
        "yutha-attestor-spiffe-forged-{}-{}.json",
        std::process::id(),
        unique,
    ));
    let mut f = std::fs::File::create(&path).expect("temp create");
    f.write_all(serde_json::to_vec(&body).expect("ser").as_slice())
        .expect("write");
    path
}

/// Extract the raw `x`/`y` coordinates of an uncompressed EC P-256
/// point and base64url-encode each (no padding) per the JWK spec.
fn jwk_xy(public: &PublicKey) -> (String, String) {
    use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let encoded: EncodedPoint = public.to_encoded_point(false);
    let x = encoded.x().expect("uncompressed point has x");
    let y = encoded.y().expect("uncompressed point has y");
    (URL_SAFE_NO_PAD.encode(x), URL_SAFE_NO_PAD.encode(y))
}

fn dummy_context() -> AttestationContext {
    AttestationContext {
        swarm_id: SwarmId::new(),
        claimed_agent_id: AgentId::new(),
        agent_public_key: CorePublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 32])
            .expect("32-byte pk"),
    }
}

/// Standard claim shape for a SPIFFE JWT-SVID. Custom values per test.
#[derive(Serialize)]
struct Claims {
    sub: String,
    aud: Vec<String>,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selectors: Option<Value>,
}

impl Claims {
    fn standard() -> Self {
        let now = now_unix_secs();
        Self {
            sub: format!("spiffe://{TRUST_DOMAIN}/test/workload"),
            aud: vec![AUDIENCE.to_string()],
            exp: now + 3600,
            iat: Some(now),
            nbf: None,
            selectors: None,
        }
    }
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn sign(claims: &Claims, key: &EncodingKey) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(KID.to_string());
    jsonwebtoken::encode(&header, claims, key).expect("encode JWT")
}

// ────────────────────────── Happy path ──────────────────────────

#[tokio::test]
async fn verify_accepts_well_formed_jwt_svid() {
    let fx = Fixture::new();
    let attestor = SpiffeAttestor::connect(fx.config()).await.expect("connect");

    let claims = Claims::standard();
    let token = sign(&claims, &fx.signing_key);

    let identity = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect("happy-path verify must succeed");

    assert_eq!(
        identity.external_identity,
        format!("spiffe://{TRUST_DOMAIN}/test/workload")
    );
    assert!(identity.credential_expires_at.is_some());
    assert!(identity.attributes.is_empty());
}

#[tokio::test]
async fn verify_projects_selectors_into_attributes() {
    let fx = Fixture::new();
    let attestor = SpiffeAttestor::connect(fx.config()).await.expect("connect");

    let mut claims = Claims::standard();
    claims.selectors = Some(json!({
        "k8s_ns": "billing",
        "k8s_sa": "processor",
    }));
    let token = sign(&claims, &fx.signing_key);

    let identity = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect("verify with selectors must succeed");

    assert_eq!(identity.attributes.len(), 2);
    assert_eq!(
        identity.attributes.get("k8s_ns").map(String::as_str),
        Some("billing")
    );
    assert_eq!(
        identity.attributes.get("k8s_sa").map(String::as_str),
        Some("processor")
    );
}

#[tokio::test]
async fn verify_skips_selectors_when_any_value_is_non_string() {
    let fx = Fixture::new();
    let attestor = SpiffeAttestor::connect(fx.config()).await.expect("connect");

    // Per spec §8.1: any non-string value → skip the WHOLE claim,
    // not partial projection.
    let mut claims = Claims::standard();
    claims.selectors = Some(json!({
        "k8s_ns": "billing",
        "unix_uid": 1000,
    }));
    let token = sign(&claims, &fx.signing_key);

    let identity = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect("verify still succeeds; non-string just skips selectors");

    assert!(identity.attributes.is_empty());
}

// ────────────────────────── Rejected ──────────────────────────

#[tokio::test]
async fn verify_rejects_wrong_audience() {
    let fx = Fixture::new();
    let attestor = SpiffeAttestor::connect(fx.config()).await.expect("connect");

    let mut claims = Claims::standard();
    claims.aud = vec!["some-other-audience".to_string()];
    let token = sign(&claims, &fx.signing_key);

    let err = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect_err("audience mismatch must reject");
    match err {
        AttestorError::Rejected(msg) => {
            assert!(msg.contains("audience mismatch"), "got: {msg}");
            // PII rule: error must not echo either audience value.
            assert!(!msg.contains("some-other-audience"));
            assert!(!msg.contains(AUDIENCE));
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn verify_rejects_expired_credential() {
    let fx = Fixture::new();
    let attestor = SpiffeAttestor::connect(fx.config()).await.expect("connect");

    let mut claims = Claims::standard();
    claims.exp = now_unix_secs() - 60; // 1 minute in the past
    let token = sign(&claims, &fx.signing_key);

    let err = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect_err("expired credential must reject");
    match err {
        AttestorError::Rejected(msg) => {
            assert!(msg.contains("credential expired"), "got: {msg}")
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn verify_rejects_signature_mismatch() {
    let fx = Fixture::new();
    let attestor = SpiffeAttestor::connect(fx.config()).await.expect("connect");

    let token = sign(&Claims::standard(), &fx.signing_key);

    // Flip the last byte of the signature segment. The token is
    // header.payload.sig; tamper with sig.
    let mut parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let tampered_sig = tamper_last_b64_char(parts[2]);
    parts[2] = &tampered_sig;
    let tampered_token = parts.join(".");

    let err = attestor
        .verify(&dummy_context(), tampered_token.as_bytes())
        .await
        .expect_err("bit-flipped signature must reject");
    match err {
        AttestorError::Rejected(msg) => {
            assert!(msg.contains("signature verification failed"), "got: {msg}")
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn verify_rejects_unknown_kid() {
    let fx = Fixture::new();
    let attestor = SpiffeAttestor::connect(fx.config()).await.expect("connect");

    // Sign with a *different* kid than the bundle published.
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("bogus-unknown-kid".to_string());
    let token =
        jsonwebtoken::encode(&header, &Claims::standard(), &fx.signing_key).expect("encode");

    let err = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect_err("unknown kid must reject");
    match err {
        AttestorError::Rejected(msg) => {
            assert!(msg.contains("kid not found in trust bundle"), "got: {msg}")
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn verify_rejects_trust_domain_mismatch() {
    let fx = Fixture::new();
    let attestor = SpiffeAttestor::connect(fx.config()).await.expect("connect");

    // The bundle declares trust_domain=example.org but the SVID's
    // sub names a different domain.
    let mut claims = Claims::standard();
    claims.sub = "spiffe://other.example.org/test/workload".to_string();
    let token = sign(&claims, &fx.signing_key);

    let err = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect_err("trust-domain mismatch must reject");
    match err {
        AttestorError::Rejected(msg) => {
            assert!(msg.contains("trust domain not in bundle"), "got: {msg}")
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn verify_rejects_nbf_in_the_future_past_tolerance() {
    let fx = Fixture::new();
    // Tighten clock-skew tolerance so the test isn't flaky.
    let mut config = fx.config();
    config.clock_skew_tolerance_secs = 5;
    let attestor = SpiffeAttestor::connect(config).await.expect("connect");

    let mut claims = Claims::standard();
    claims.nbf = Some(now_unix_secs() + 600); // 10 minutes in the future
    let token = sign(&claims, &fx.signing_key);

    let err = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect_err("future-dated nbf must reject");
    match err {
        AttestorError::Rejected(msg) => {
            assert!(msg.contains("nbf in the future"), "got: {msg}")
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn verify_accepts_nbf_within_clock_skew_tolerance() {
    let fx = Fixture::new();
    let mut config = fx.config();
    config.clock_skew_tolerance_secs = 120;
    let attestor = SpiffeAttestor::connect(config).await.expect("connect");

    let mut claims = Claims::standard();
    // 30 seconds ahead — within the 120 s tolerance.
    claims.nbf = Some(now_unix_secs() + 30);
    let token = sign(&claims, &fx.signing_key);

    attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect("nbf within tolerance must accept");
}

// ──────────────────── Bundle-cache staleness ──────────────────────

#[tokio::test]
async fn verify_surfaces_trust_root_unavailable_when_bundle_stale() {
    let fx = Fixture::new();
    let mut config = fx.config();
    // Zero-duration staleness window → anything past `loaded_at` is
    // stale. The static-file path uses `loaded_at` (construction
    // time); sleeping briefly past `loaded_at` ensures the check
    // fires.
    config.max_staleness = Some(Duration::from_secs(0));
    let attestor = SpiffeAttestor::connect(config).await.expect("connect");

    tokio::time::sleep(Duration::from_millis(5)).await;

    let token = sign(&Claims::standard(), &fx.signing_key);
    let err = attestor
        .verify(&dummy_context(), token.as_bytes())
        .await
        .expect_err("zero-window staleness must reject");
    assert!(matches!(err, AttestorError::TrustRootUnavailable(_)));
}

// ─────────────────────────── Helpers ───────────────────────────

/// Flip the last base64url character to something deterministic but
/// different, producing a syntactically-valid-but-wrong signature.
fn tamper_last_b64_char(s: &str) -> String {
    let mut chars: Vec<char> = s.chars().collect();
    if let Some(last) = chars.last_mut() {
        *last = if *last == 'A' { 'B' } else { 'A' };
    }
    chars.into_iter().collect()
}

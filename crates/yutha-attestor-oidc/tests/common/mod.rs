//! Shared test helpers for the F7 forged-JWT + integration-test
//! suites. Cargo treats `tests/common/mod.rs` as a non-test file
//! (subdirectories don't become test targets), so this module is
//! pulled into sibling `tests/*.rs` files via `mod common;`.

#![allow(dead_code)] // helpers shared across multiple test files;
                     // not every file uses every helper.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
// ed25519-dalek 2.x exposes `SigningKey::to_pkcs8_der()` as an
// inherent method when its `pkcs8` feature is on (no separate trait
// import needed — confirmed at the F7 build gate). We go through DER
// instead of PEM to avoid the `pkcs8::LineEnding` re-export-path
// churn; `EncodingKey::from_ed_der` accepts the raw PKCS#8 bytes.
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::EncodePrivateKey;
use p256::SecretKey as P256SecretKey;
use rand_core::OsRng;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use yutha_attestor::AttestationContext;
use yutha_attestor_oidc::{JwksSource, OidcConfig};
use yutha_core::{AgentId, PublicKey as CorePublicKey, SignatureAlgorithm, SwarmId};

pub const EXPECTED_ISSUER: &str = "https://login.test.example.com";
pub const EXPECTED_AUDIENCE: &str = "yutha-test-audience";

/// Unique kid per test so accidentally-leaked fixture state shows up
/// as a kid-not-found rather than a silent crossover.
pub fn next_kid() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!("test-kid-{}", COUNTER.fetch_add(1, Ordering::SeqCst))
}

/// Wall-clock now as Unix seconds. Used to drive the manual
/// `iat`-future / `nbf`-future / `exp`-past constructions in tests.
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A real-signing test keypair + the JWKS body that the verify path
/// can use to find its public key. The `signing_key` is what
/// `jsonwebtoken::encode` accepts; `algorithm` is the matching
/// JWS alg; `jwks_body` is the JSON-serialised one-key JWKS.
pub struct SigningFixture {
    pub kid: String,
    pub algorithm: Algorithm,
    pub signing_key: EncodingKey,
    pub jwks_body: String,
}

impl SigningFixture {
    /// RSA-2048 / RS256. Slowest keygen (~100-500 ms) but most
    /// representative of real-world OIDC IdPs.
    pub fn new_rs256() -> Self {
        let kid = next_kid();
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA-2048 keygen");
        let public_key = private_key.to_public_key();

        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let jwks = json!({
            "keys": [{
                "use": "sig",
                "kty": "RSA",
                "alg": "RS256",
                "kid": kid,
                "n": n,
                "e": e,
            }]
        });

        let pkcs1_der = private_key.to_pkcs1_der().expect("RSA pkcs1 der encode");
        let signing_key = EncodingKey::from_rsa_der(pkcs1_der.as_bytes());

        Self {
            kid,
            algorithm: Algorithm::RS256,
            signing_key,
            jwks_body: jwks.to_string(),
        }
    }

    /// ECDSA P-256 / ES256. Fast keygen, smaller JWKS, common in
    /// modern IdPs (Auth0, Okta).
    pub fn new_es256() -> Self {
        let kid = next_kid();
        let secret = P256SecretKey::random(&mut OsRng);
        let public = secret.public_key();

        // JWK EC-coordinate encoding: take the uncompressed SEC1
        // point and split into (x, y). Both are 32-byte big-endian
        // field elements.
        let encoded = public.to_encoded_point(false);
        let x_bytes = encoded.x().expect("uncompressed EC point has x");
        let y_bytes = encoded.y().expect("uncompressed EC point has y");
        let x = URL_SAFE_NO_PAD.encode(x_bytes);
        let y = URL_SAFE_NO_PAD.encode(y_bytes);

        let jwks = json!({
            "keys": [{
                "use": "sig",
                "kty": "EC",
                "alg": "ES256",
                "crv": "P-256",
                "kid": kid,
                "x": x,
                "y": y,
            }]
        });

        let pkcs8_pem = secret
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("p256 pkcs8 pem encode");
        let signing_key = EncodingKey::from_ec_pem(pkcs8_pem.as_bytes())
            .expect("jsonwebtoken EncodingKey::from_ec_pem");

        Self {
            kid,
            algorithm: Algorithm::ES256,
            signing_key,
            jwks_body: jwks.to_string(),
        }
    }

    /// Ed25519 / EdDSA. Fast keygen; the JWK encoding is the
    /// shortest of the three families (single `x` field with the
    /// 32-byte raw public key). Common in modern identity stacks
    /// that prefer EdDSA's smaller signatures over RSA.
    pub fn new_eddsa() -> Self {
        let kid = next_kid();
        let mut rng = OsRng;
        let signing = Ed25519SigningKey::generate(&mut rng);
        let verifying = signing.verifying_key();
        let x = URL_SAFE_NO_PAD.encode(verifying.to_bytes());

        let jwks = json!({
            "keys": [{
                "use": "sig",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "kid": kid,
                "x": x,
            }]
        });

        let pkcs8_der = signing
            .to_pkcs8_der()
            .expect("ed25519-dalek pkcs8 der encode");
        let signing_key = EncodingKey::from_ed_der(pkcs8_der.as_bytes());

        Self {
            kid,
            algorithm: Algorithm::EdDSA,
            signing_key,
            jwks_body: jwks.to_string(),
        }
    }

    /// Materialise the JWKS body as a temp file. Returned NamedTempFile
    /// auto-deletes on drop.
    pub fn to_temp_jwks(&self) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(self.jwks_body.as_bytes()).unwrap();
        f
    }

    /// Mint a JWT from `claims` JSON, signed with this fixture's key
    /// and with `kid` in the header.
    pub fn mint_token(&self, claims: &Value) -> String {
        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.kid.clone());
        header.typ = Some("JWT".to_string());
        jsonwebtoken::encode(&header, claims, &self.signing_key).expect("jsonwebtoken::encode")
    }
}

/// A well-formed claim set for the configured (issuer, audience).
/// Tests can `.as_object_mut()` and mutate before passing to
/// `SigningFixture::mint_token`.
pub fn happy_claims(sub: &str) -> Value {
    let now = now_secs();
    json!({
        "iss": EXPECTED_ISSUER,
        "aud": EXPECTED_AUDIENCE,
        "sub": sub,
        "exp": now + 3600,
        "iat": now,
    })
}

/// OidcConfig pinned at the test fixture's JWKS file. Static-file
/// source so no live HTTP; matches what we test by default.
pub fn config_with_static_file(jwks_path: &std::path::Path) -> OidcConfig {
    OidcConfig {
        source: JwksSource::StaticFile {
            path: jwks_path.to_path_buf(),
        },
        expected_issuer: EXPECTED_ISSUER.to_string(),
        expected_audience: EXPECTED_AUDIENCE.to_string(),
        allowed_algs: vec!["RS256".into(), "ES256".into(), "EdDSA".into()],
        project_claims: vec![],
        cache_ttl_secs: 3600,
        max_staleness_secs: None,
        clock_skew_tolerance_secs: 60,
        connect_timeout_secs: 10,
        allow_insecure_http: false,
    }
}

/// Dummy AttestationContext — the verify body doesn't inspect
/// `context.agent_public_key` directly (per spec §3.1 layered-binding
/// rationale), so a zero-byte placeholder PK is fine for these tests.
pub fn dummy_context() -> AttestationContext {
    AttestationContext {
        swarm_id: SwarmId::new(),
        claimed_agent_id: AgentId::new(),
        agent_public_key: CorePublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 32]).unwrap(),
    }
}

/// Tiny helper to write a JWKS body string to a fresh temp file path.
pub fn write_jwks_file(body: &str) -> PathBuf {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(body.as_bytes()).unwrap();
    let path = f.path().to_path_buf();
    // Persist past the test fn return — keep the NamedTempFile alive
    // by forgetting it (file gets cleaned up on process exit).
    std::mem::forget(f);
    path
}

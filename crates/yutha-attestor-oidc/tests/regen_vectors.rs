//! Regenerate the OIDC Attestor conformance vectors at
//! `/spec/vectors/attestor/oidc/`.
//!
//! Implemented as an `#[ignore]`-gated test (not a `main()` binary
//! or example) because cargo's `[[example]]` targets do not reliably
//! get access to `[dev-dependencies]`. The regen needs `p256`,
//! `jsonwebtoken`, and `rand_chacha` — all dev-deps. Tests see
//! dev-deps unconditionally, so this is the cleanest landing spot.
//! Same pattern as the Phase E spiffe crate's `regen_vectors.rs`.
//!
//! Run with:
//! ```bash
//! cd /Users/abhinavgarg/Documents/Claude/Yutha
//! cargo test -p yutha-attestor-oidc --test regen_vectors \
//!     -- --ignored --nocapture
//! ```
//!
//! Produces deterministic JSON fixtures from a documented seed
//! ([`REGEN_SEED`]). Re-running with the same seed produces
//! byte-identical output; changing the seed (or the case manifest in
//! this file) drifts every fixture in lockstep.
//!
//! See [`spec/vectors/attestor/oidc/README.md`](../../../../spec/vectors/attestor/oidc/README.md)
//! for the fixture format + the case-count deviation from spec §11.

use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::EncodePrivateKey;
use p256::{PublicKey, SecretKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

/// Deterministic seed for the regen RNG. Bumping this rotates every
/// fixture; intentional drift only.
const REGEN_SEED: [u8; 32] = *b"yutha-attestor-oidc-vectors-v1!!";

/// Fixed pseudo-`now()` used to compute exp/iat/nbf claims in the
/// fixtures. 2099-01-01T00:00:00Z. See README for the regen-by-2098
/// caveat.
const PSEUDO_NOW_UNIX_SECS: i64 = 4_070_908_800;

const ISSUER: &str = "https://login.test.example.com";
const AUDIENCE: &str = "yutha-test-audience";
const KID: &str = "test-key-1";

/// Regenerate every fixture under `/spec/vectors/attestor/oidc/`.
/// Gated `#[ignore]` so `cargo test` doesn't rewrite committed
/// fixtures on every run; opt-in with `-- --ignored`.
#[test]
#[ignore]
fn regen() {
    let out_dir = repo_root().join("spec/vectors/attestor/oidc");
    fs::create_dir_all(&out_dir).expect("mkdir spec dir");

    let mut rng = ChaCha20Rng::from_seed(REGEN_SEED);
    let secret = SecretKey::random(&mut rng);
    let public = secret.public_key();

    let pkcs8_pem = secret
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("encode pkcs8 pem");
    let signing_key = EncodingKey::from_ec_pem(pkcs8_pem.as_bytes()).expect("EncodingKey");

    let jwks_value = jwks_json(&public);

    // Wipe + rewrite the fixture tree so removed cases don't linger.
    for sub in [
        "accept-es256",
        "reject-issuer",
        "reject-audience",
        "reject-expired",
        "reject-signature",
        "reject-empty",
    ] {
        let p = out_dir.join(sub);
        if p.exists() {
            fs::remove_dir_all(&p).expect("rm old fixture dir");
        }
    }

    let cases = build_cases(&signing_key, &jwks_value);

    let mut count = 0;
    for (sub, slug, fixture) in cases {
        let sub_dir = out_dir.join(&sub);
        fs::create_dir_all(&sub_dir).expect("mkdir sub");
        let path = sub_dir.join(format!("{slug}.json"));
        let pretty = serde_json::to_string_pretty(&fixture).expect("ser fixture");
        fs::write(&path, pretty + "\n").expect("write fixture");
        eprintln!("emitted {sub}/{slug}.json");
        count += 1;
    }

    eprintln!(
        "\nregen complete: {} fixtures under {}",
        count,
        out_dir.display()
    );
}

/// Compute the workspace root by walking up from CARGO_MANIFEST_DIR.
fn repo_root() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .expect("crates/")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

/// Build the standalone JWKS shape the static-file source path
/// accepts. No `trust_domain` wrapper (that's the SPIFFE-specific
/// shape); just `{ "keys": [...] }`.
fn jwks_json(public: &PublicKey) -> Value {
    let (x_b64, y_b64) = jwk_xy(public);
    json!({
        "keys": [{
            "use": "sig",
            "kty": "EC",
            "alg": "ES256",
            "crv": "P-256",
            "kid": KID,
            "x": x_b64,
            "y": y_b64,
        }]
    })
}

fn jwk_xy(public: &PublicKey) -> (String, String) {
    let encoded = public.to_encoded_point(false);
    let x = encoded.x().expect("uncompressed point has x");
    let y = encoded.y().expect("uncompressed point has y");
    (URL_SAFE_NO_PAD.encode(x), URL_SAFE_NO_PAD.encode(y))
}

#[derive(Serialize, Clone)]
struct Claims {
    iss: String,
    sub: String,
    aud: Vec<String>,
    exp: i64,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

impl Claims {
    fn standard(sub: &str) -> Self {
        // The verify path requires `iat` per spec §2.2. We need it
        // present + not-future-relative-to-verify-time. Setting iat
        // to PSEUDO_NOW would make it 75 years in the future at
        // verify time → rejected. Set iat to a fixed early-2020s
        // timestamp instead; it's past-relative for any reasonable
        // verify time and the verify path doesn't require iat to be
        // recent (only "not in the future").
        Self {
            iss: ISSUER.to_string(),
            sub: sub.to_string(),
            aud: vec![AUDIENCE.to_string()],
            exp: PSEUDO_NOW_UNIX_SECS,
            iat: 1_700_000_000, // 2023-11-14T22:13:20Z — safely past
            nbf: None,
            groups: None,
            email: None,
        }
    }
}

fn sign(claims: &Claims, key: &EncodingKey, kid: &str) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(&header, claims, key).expect("encode JWT")
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Build the entire case manifest. Each tuple is
/// (sub-directory, slug, full fixture JSON).
fn build_cases(signing_key: &EncodingKey, jwks: &Value) -> Vec<(String, String, Value)> {
    let mut cases = Vec::new();

    let default_attestor_config = json!({
        "jwks": jwks,
        "expected_issuer": ISSUER,
        "expected_audience": AUDIENCE,
        "allowed_algs": ["RS256", "ES256", "EdDSA"],
        "project_claims": [],
        "clock_skew_tolerance_secs": 60,
    });

    // Fixed bytes so the JSON is byte-stable across regens.
    let context = json!({
        "swarm_id_hex": "00000000000000000000000000000001",
        "claimed_agent_id_hex": "00000000000000000000000000000002",
        "agent_public_key": {
            "algorithm": "ed25519",
            "value_b64": URL_SAFE_NO_PAD.encode([0u8; 32]),
        },
    });

    // ── accept-es256/happy_path ─────────────────────────────────────
    {
        let claims = Claims::standard("user-1");
        let token = sign(&claims, signing_key, KID);
        let fixture = json!({
            "name": "happy_path",
            "description": "Well-formed ES256-signed ID token; all required claims present, exp far in future. Asserts the §3 happy-path: signature verifies, claims pass, AttestedIdentity.external_identity = oidc:<iss>:<sub>.",
            "kind": "attestor-oidc-verify",
            "inputs": {
                "credential_b64": b64(token.as_bytes()),
                "context": context,
                "attestor_config": default_attestor_config,
            },
            "expected_outcome": "accept",
            "expected_identity": {
                "external_identity": format!("oidc:{ISSUER}:user-1"),
                "credential_expires_at_unix_secs": claims.exp,
                "attributes": {},
            },
        });
        cases.push((
            "accept-es256".to_string(),
            "happy_path".to_string(),
            fixture,
        ));
    }

    // ── accept-es256/projected_claims ──────────────────────────────
    {
        let mut claims = Claims::standard("alice");
        claims.groups = Some(json!(["admin", "auditor"]));
        claims.email = Some("alice@example.com".to_string());
        let token = sign(&claims, signing_key, KID);

        let mut config = default_attestor_config.clone();
        config["project_claims"] = json!(["groups", "email"]);

        let fixture = json!({
            "name": "projected_claims",
            "description": "Operator allowlists `groups` + `email`; token includes both; projection lands in AttestedIdentity.attributes per spec §8.1 (array → comma-joined, string → verbatim).",
            "kind": "attestor-oidc-verify",
            "inputs": {
                "credential_b64": b64(token.as_bytes()),
                "context": context,
                "attestor_config": config,
            },
            "expected_outcome": "accept",
            "expected_identity": {
                "external_identity": format!("oidc:{ISSUER}:alice"),
                "credential_expires_at_unix_secs": claims.exp,
                "attributes": {
                    "groups": "admin,auditor",
                    "email": "alice@example.com",
                },
            },
        });
        cases.push((
            "accept-es256".to_string(),
            "projected_claims".to_string(),
            fixture,
        ));
    }

    // ── reject-issuer/iss_mismatch ─────────────────────────────────
    {
        let mut claims = Claims::standard("u");
        claims.iss = "https://attacker.example.com".to_string();
        let token = sign(&claims, signing_key, KID);
        let fixture = json!({
            "name": "iss_mismatch",
            "description": "Token `iss` claim does not equal operator's expected_issuer. Spec §9 maps to Rejected('issuer mismatch').",
            "kind": "attestor-oidc-verify",
            "inputs": {
                "credential_b64": b64(token.as_bytes()),
                "context": context,
                "attestor_config": default_attestor_config,
            },
            "expected_outcome": "reject",
            "expected_error_variant": "Rejected",
            "expected_error_message_substring": "issuer mismatch",
        });
        cases.push((
            "reject-issuer".to_string(),
            "iss_mismatch".to_string(),
            fixture,
        ));
    }

    // ── reject-audience/aud_mismatch ───────────────────────────────
    {
        let mut claims = Claims::standard("u");
        claims.aud = vec!["some-other-rp".to_string()];
        let token = sign(&claims, signing_key, KID);
        let fixture = json!({
            "name": "aud_mismatch",
            "description": "Token `aud` claim does not contain operator's expected_audience. Spec §9 maps to Rejected('audience mismatch').",
            "kind": "attestor-oidc-verify",
            "inputs": {
                "credential_b64": b64(token.as_bytes()),
                "context": context,
                "attestor_config": default_attestor_config,
            },
            "expected_outcome": "reject",
            "expected_error_variant": "Rejected",
            "expected_error_message_substring": "audience mismatch",
        });
        cases.push((
            "reject-audience".to_string(),
            "aud_mismatch".to_string(),
            fixture,
        ));
    }

    // ── reject-expired/exp_past ────────────────────────────────────
    {
        let mut claims = Claims::standard("u");
        // Hardcoded 2001 Unix time. Per the time-relative-fixtures
        // lesson, "expired" must be hardcoded past — not
        // PSEUDO_NOW-minus-offset (that's still future for the verify
        // path's wall-clock now()).
        claims.exp = 1_000_000_000;
        let token = sign(&claims, signing_key, KID);
        let fixture = json!({
            "name": "exp_past",
            "description": "Token `exp` is in the past (hardcoded 2001 Unix time). Spec §9 maps to Rejected('credential expired').",
            "kind": "attestor-oidc-verify",
            "inputs": {
                "credential_b64": b64(token.as_bytes()),
                "context": context,
                "attestor_config": default_attestor_config,
            },
            "expected_outcome": "reject",
            "expected_error_variant": "Rejected",
            "expected_error_message_substring": "credential expired",
        });
        cases.push((
            "reject-expired".to_string(),
            "exp_past".to_string(),
            fixture,
        ));
    }

    // ── reject-signature/bit_flipped ───────────────────────────────
    {
        let claims = Claims::standard("u");
        let token = sign(&claims, signing_key, KID);

        // Flip a single bit of the DECODED signature bytes — keeps
        // the signature segment structurally valid (same length, R/S
        // still in-range for ES256) but mathematically wrong, so
        // jsonwebtoken's verify returns `InvalidSignature` (mapped
        // to Rejected) rather than a parse-level error.
        //
        // Mutating the base64-encoded segment directly turned out to
        // produce decoded bytes that jsonwebtoken's ECDSA backend
        // rejected at the signature-parse layer (some ErrorKind
        // variant our error.rs doesn't name explicitly → catch-all
        // → Malformed), defeating the spec-row this case is meant
        // to exercise.
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "jwt has three segments");
        let mut sig_bytes = URL_SAFE_NO_PAD
            .decode(parts[2])
            .expect("decode sig segment");
        let last_idx = sig_bytes.len() - 1;
        sig_bytes[last_idx] ^= 0x01;
        let mutated_sig = URL_SAFE_NO_PAD.encode(&sig_bytes);
        let mutated_token = format!("{}.{}.{}", parts[0], parts[1], mutated_sig);

        let fixture = json!({
            "name": "bit_flipped",
            "description": "Otherwise-valid ES256 ID token with one bit of the decoded signature bytes flipped. Structurally valid (correct length, in-range R/S) but mathematically invalid. Spec §9 maps to Rejected('signature verification failed').",
            "kind": "attestor-oidc-verify",
            "inputs": {
                "credential_b64": b64(mutated_token.as_bytes()),
                "context": context,
                "attestor_config": default_attestor_config,
            },
            "expected_outcome": "reject",
            "expected_error_variant": "Rejected",
            "expected_error_message_substring": "signature verification failed",
        });
        cases.push((
            "reject-signature".to_string(),
            "bit_flipped".to_string(),
            fixture,
        ));
    }

    // ── reject-empty/empty ─────────────────────────────────────────
    {
        let fixture = json!({
            "name": "empty",
            "description": "Empty credential bytes. Spec §9 first row → Rejected('empty credential; OIDC Attestor requires an ID token').",
            "kind": "attestor-oidc-verify",
            "inputs": {
                "credential_b64": "",
                "context": context,
                "attestor_config": default_attestor_config,
            },
            "expected_outcome": "reject",
            "expected_error_variant": "Rejected",
            "expected_error_message_substring": "empty credential",
        });
        cases.push(("reject-empty".to_string(), "empty".to_string(), fixture));
    }

    cases
}

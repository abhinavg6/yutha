//! Regenerate the SPIFFE Attestor conformance vectors at
//! `/spec/vectors/attestor/spiffe/`.
//!
//! Implemented as an `#[ignore]`-gated test (not a `main()` binary
//! or example) because cargo's `[[example]]` targets do not reliably
//! get access to `[dev-dependencies]`. The regen needs `p256`,
//! `jsonwebtoken`, and `rand_chacha` — all dev-deps. Tests see
//! dev-deps unconditionally, so this is the cleanest landing spot.
//!
//! Run with:
//! ```bash
//! cd /Users/abhinavgarg/Documents/Claude/Yutha
//! cargo test -p yutha-attestor-spiffe --test regen_vectors \
//!     -- --ignored --nocapture
//! ```
//!
//! Produces deterministic JSON fixtures from a documented seed
//! ([`REGEN_SEED`]). Re-running with the same seed produces
//! byte-identical output; changing the seed (or the case manifest in
//! this file) drifts every fixture in lockstep.
//!
//! Per [`attestor-spiffe.md` §11](../../../spec/identity-keys/attestor-spiffe.md#11-conformance-vectors)
//! the cases exercise every spec §11 row with at least one fixture.
//! The committed v1 set is intentionally smaller than the §11
//! per-directory case counts (which were aspirational); see the
//! vectors README for the deviation rationale.

use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::EncodePrivateKey;
use p256::{EncodedPoint, PublicKey, SecretKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

/// Deterministic seed for the regen RNG. Bumping this rotates every
/// fixture; intentional drift only.
const REGEN_SEED: [u8; 32] = *b"yutha-attestor-spiffe-vectors-v1";

/// Fixed pseudo-`now()` used to compute exp/iat/nbf claims in the
/// fixtures. Picked far enough in the future that the fixtures stay
/// valid for years without regen. Year 2099, near the i32-second
/// boundary but inside i64 range comfortably.
///
/// Verify-side note: at test time, real `now()` MUST be less than
/// `PSEUDO_NOW + 3600` for "accept" cases to pass. That's ~75 years
/// from when this constant lands; the fixtures expire in 2099 at the
/// earliest. Regen if you're reading this in 2098.
const PSEUDO_NOW_UNIX_SECS: i64 = 4_070_908_800; // 2099-01-01T00:00:00Z

const TRUST_DOMAIN: &str = "example.org";
const AUDIENCE: &str = "yutha-test-audience";
const KID: &str = "test-key-1";
const ALT_KID: &str = "unknown-key-id";

/// Regenerate every fixture under `/spec/vectors/attestor/spiffe/`.
/// Gated `#[ignore]` so `cargo test` doesn't rewrite committed
/// fixtures on every run; opt-in with `-- --ignored`.
#[test]
#[ignore]
fn regen() {
    let out_dir = repo_root().join("spec/vectors/attestor/spiffe");
    fs::create_dir_all(&out_dir).expect("mkdir spec dir");

    let mut rng = ChaCha20Rng::from_seed(REGEN_SEED);
    let secret = SecretKey::random(&mut rng);
    let public = secret.public_key();

    let pkcs8_pem = secret
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("encode pkcs8 pem");
    let signing_key = EncodingKey::from_ec_pem(pkcs8_pem.as_bytes()).expect("EncodingKey");

    let bundle_value = bundle_json(&public);

    // Wipe + rewrite the fixture tree so removed cases don't linger.
    for sub in [
        "accept-ed25519", // not used in v1; SPIFFE SDK accepts EdDSA but
        //  jsonwebtoken needs ed25519-dalek + extra wiring
        //  — covered by an in-tree note rather than a
        //  fixture in this regen pass.
        "accept-ecdsa-p256",
        "accept-rsa", // similarly: not emitted in v1 (avoid pulling
        //   an RSA keypair dep just for fixture sugar).
        "reject-audience",
        "reject-expired",
        "reject-signature",
        "reject-malformed",
        "reject-trust-domain",
        "reject-empty",
        "selectors",
    ] {
        let p = out_dir.join(sub);
        if p.exists() {
            fs::remove_dir_all(&p).expect("rm old fixture dir");
        }
    }

    // Emit each case. Returns ((sub-directory, slug, fixture-JSON), ...).
    let cases = build_cases(&signing_key, &bundle_value);

    let mut count = 0;
    for (sub, slug, fixture) in cases {
        let sub_dir = out_dir.join(&sub);
        fs::create_dir_all(&sub_dir).expect("mkdir sub");
        let path = sub_dir.join(format!("{slug}.json"));
        let pretty = serde_json::to_string_pretty(&fixture).expect("ser fixture");
        fs::write(&path, pretty + "\n").expect("write fixture");
        eprintln!("emitted {}/{}.json", sub, slug);
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
    // CARGO_MANIFEST_DIR is the crate dir
    // (.../crates/yutha-attestor-spiffe); two parents up is the repo root.
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .expect("crates/")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

/// Build the trust-bundle JSON our static-file source path accepts.
fn bundle_json(public: &PublicKey) -> Value {
    let (x_b64, y_b64) = jwk_xy(public);
    json!({
        "trust_domain": TRUST_DOMAIN,
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "kid": KID,
            "use": "jwt-svid",
            "x": x_b64,
            "y": y_b64,
        }],
    })
}

fn jwk_xy(public: &PublicKey) -> (String, String) {
    let encoded: EncodedPoint = public.to_encoded_point(false);
    let x = encoded.x().expect("uncompressed point has x");
    let y = encoded.y().expect("uncompressed point has y");
    (URL_SAFE_NO_PAD.encode(x), URL_SAFE_NO_PAD.encode(y))
}

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
        // NOTE: `iat` and `nbf` are deliberately omitted from the
        // standard claim shape. The fixtures' `exp` is in 2099 so they
        // stay valid for decades; if we ALSO set `iat = 2099`, our
        // verify path (rightly) rejects it as future-dated relative
        // to current wall-clock. Per spec §3 step 7e–f, missing
        // `iat`/`nbf` is fine; absent claims aren't checked. Cases
        // that specifically exercise iat/nbf set them explicitly.
        Self {
            sub: format!("spiffe://{TRUST_DOMAIN}/test/workload"),
            aud: vec![AUDIENCE.to_string()],
            exp: PSEUDO_NOW_UNIX_SECS + 3600,
            iat: None,
            nbf: None,
            selectors: None,
        }
    }
}

fn sign(claims: &Claims, key: &EncodingKey, kid: &str) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(&header, claims, key).expect("encode JWT")
}

/// Build the entire case manifest. Each tuple is
/// (sub-directory, slug, full fixture JSON).
fn build_cases(signing_key: &EncodingKey, bundle: &Value) -> Vec<(String, String, Value)> {
    let mut cases = Vec::new();

    let attestor_config = json!({
        "trust_bundle": bundle,
        "expected_audience": AUDIENCE,
        "clock_skew_tolerance_secs": 60,
    });

    // Default verify-context — fixed bytes so the JSON is byte-stable
    // across regens.
    let context = json!({
        "swarm_id_hex": "00000000000000000000000000000001",
        "claimed_agent_id_hex": "00000000000000000000000000000002",
        "agent_public_key": {
            "algorithm": "ed25519",
            "value_b64": URL_SAFE_NO_PAD.encode([0u8; 32]),
        },
    });

    // ── accept-ecdsa-p256/ — happy path ────────────────────────────
    {
        let claims = Claims::standard();
        let token = sign(&claims, signing_key, KID);
        let fixture = json!({
            "name": "es256_happy_path",
            "description": "Well-formed ES256-signed JWT-SVID; sub spiffe://example.org/test/workload, aud matches, exp far in future. Asserts the §3 happy-path: signature verifies, claims pass, AttestedIdentity carries the SPIFFE ID + exp.",
            "kind": "attestor-spiffe-verify",
            "inputs": {
                "credential_b64": b64(token.as_bytes()),
                "context": context,
                "attestor_config": attestor_config,
            },
            "expected_outcome": "accept",
            "expected_identity": {
                "external_identity": format!("spiffe://{TRUST_DOMAIN}/test/workload"),
                "credential_expires_at_unix_secs": claims.exp,
                "attributes": {},
            },
        });
        cases.push((
            "accept-ecdsa-p256".to_string(),
            "es256_happy_path".to_string(),
            fixture,
        ));
    }

    // ── selectors/ — projection of well-formed string-map selectors ─
    {
        let mut claims = Claims::standard();
        claims.selectors = Some(json!({
            "k8s_ns": "billing",
            "k8s_sa": "processor",
        }));
        let token = sign(&claims, signing_key, KID);
        let fixture = json!({
            "name": "selectors_string_map_projection",
            "description": "Selectors claim with all-string values projects 1:1 into AttestedIdentity.attributes per spec §8.",
            "kind": "attestor-spiffe-verify",
            "inputs": {
                "credential_b64": b64(token.as_bytes()),
                "context": context,
                "attestor_config": attestor_config,
            },
            "expected_outcome": "accept",
            "expected_identity": {
                "external_identity": format!("spiffe://{TRUST_DOMAIN}/test/workload"),
                "credential_expires_at_unix_secs": claims.exp,
                "attributes": {
                    "k8s_ns": "billing",
                    "k8s_sa": "processor",
                },
            },
        });
        cases.push((
            "selectors".to_string(),
            "selectors_string_map_projection".to_string(),
            fixture,
        ));
    }

    // ── selectors/ — mixed-type selectors skip the whole claim ──────
    {
        let mut claims = Claims::standard();
        claims.selectors = Some(json!({
            "k8s_ns": "billing",
            "unix_uid": 1000,  // non-string → spec §8.1 says skip entire claim
        }));
        let token = sign(&claims, signing_key, KID);
        let fixture = json!({
            "name": "selectors_mixed_type_skipped",
            "description": "Selectors claim with any non-string value: per spec §8.1, the entire claim is skipped (NOT partial). attributes ends up empty.",
            "kind": "attestor-spiffe-verify",
            "inputs": {
                "credential_b64": b64(token.as_bytes()),
                "context": context,
                "attestor_config": attestor_config,
            },
            "expected_outcome": "accept",
            "expected_identity": {
                "external_identity": format!("spiffe://{TRUST_DOMAIN}/test/workload"),
                "credential_expires_at_unix_secs": claims.exp,
                "attributes": {},
            },
        });
        cases.push((
            "selectors".to_string(),
            "selectors_mixed_type_skipped".to_string(),
            fixture,
        ));
    }

    // ── reject-audience/ — aud claim doesn't contain expected ──────
    {
        let mut claims = Claims::standard();
        claims.aud = vec!["some-other-audience".to_string()];
        let token = sign(&claims, signing_key, KID);
        let fixture = json!({
            "name": "audience_mismatch",
            "description": "SVID's aud claim does not contain the operator-configured expected_audience. Spec §9 maps to Rejected('audience mismatch').",
            "kind": "attestor-spiffe-verify",
            "inputs": {
                "credential_b64": b64(token.as_bytes()),
                "context": context,
                "attestor_config": attestor_config,
            },
            "expected_outcome": "reject",
            "expected_error_variant": "Rejected",
            "expected_error_message_substring": "audience mismatch",
        });
        cases.push((
            "reject-audience".to_string(),
            "audience_mismatch".to_string(),
            fixture,
        ));
    }

    // ── reject-expired/ — exp <= now() ─────────────────────────────
    {
        let mut claims = Claims::standard();
        // Deep-past exp: 2001-09-09T01:46:40Z. "Expired" is relative
        // to verify-time wall-clock, NOT to PSEUDO_NOW. If we used
        // PSEUDO_NOW - 3600 = year 2099, the fixture would actually
        // be in the FUTURE from any 2026-era verifier's perspective
        // and accept rather than reject.
        claims.exp = 1_000_000_000;
        let token = sign(&claims, signing_key, KID);
        let fixture = json!({
            "name": "credential_expired",
            "description": "exp claim is in the deep past (2001-09-09T01:46:40Z). Spec §9 maps to Rejected('credential expired'). The hard-coded past timestamp is intentional: 'expired' is relative to verify-time wall-clock, not to PSEUDO_NOW. PSEUDO_NOW-relative offsets would still be in the future for any reasonable verifier and would incorrectly accept.",
            "kind": "attestor-spiffe-verify",
            "inputs": {
                "credential_b64": b64(token.as_bytes()),
                "context": context,
                "attestor_config": attestor_config,
            },
            "expected_outcome": "reject",
            "expected_error_variant": "Rejected",
            "expected_error_message_substring": "credential expired",
        });
        cases.push((
            "reject-expired".to_string(),
            "credential_expired".to_string(),
            fixture,
        ));
    }

    // ── reject-signature/ — bit-flipped sig segment ────────────────
    {
        let token = sign(&Claims::standard(), signing_key, KID);
        // Flip the last base64 char of the sig segment.
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        assert_eq!(parts.len(), 3);
        let tampered_sig = tamper_last_b64_char(&parts[2]);
        parts[2] = tampered_sig;
        let tampered_token = parts.join(".");

        let fixture = json!({
            "name": "signature_mismatch",
            "description": "Token's signature segment has been bit-flipped; the JWS signature verification step fails. Spec §9 maps to Rejected('signature verification failed').",
            "kind": "attestor-spiffe-verify",
            "inputs": {
                "credential_b64": b64(tampered_token.as_bytes()),
                "context": context,
                "attestor_config": attestor_config,
            },
            "expected_outcome": "reject",
            "expected_error_variant": "Rejected",
            "expected_error_message_substring": "signature verification failed",
        });
        cases.push((
            "reject-signature".to_string(),
            "signature_mismatch".to_string(),
            fixture,
        ));
    }

    // ── reject-malformed/ — garbled token, not 3-part JWS ──────────
    {
        let garbled = "this.is.not.a.real.jwt".as_bytes();
        let fixture = json!({
            "name": "not_a_jws_compact_serialization",
            "description": "Credential is valid UTF-8 but has more than 3 dot-separated segments → JWS parse fails. Spec §9 maps to Malformed('not a JWS compact serialization').",
            "kind": "attestor-spiffe-verify",
            "inputs": {
                "credential_b64": b64(garbled),
                "context": context,
                "attestor_config": attestor_config,
            },
            "expected_outcome": "reject",
            "expected_error_variant": "Malformed",
            "expected_error_message_substring": "not a JWS compact serialization",
        });
        cases.push((
            "reject-malformed".to_string(),
            "not_a_jws_compact_serialization".to_string(),
            fixture,
        ));
    }

    // ── reject-trust-domain/ — sub names an unknown trust domain ───
    {
        let mut claims = Claims::standard();
        claims.sub = "spiffe://other.example.org/test/workload".to_string();
        let token = sign(&claims, signing_key, KID);
        let fixture = json!({
            "name": "trust_domain_not_in_bundle",
            "description": "SVID's sub names a trust domain (other.example.org) that is not in the configured bundle (example.org). Spec §9 maps to Rejected('trust domain not in bundle').",
            "kind": "attestor-spiffe-verify",
            "inputs": {
                "credential_b64": b64(token.as_bytes()),
                "context": context,
                "attestor_config": attestor_config,
            },
            "expected_outcome": "reject",
            "expected_error_variant": "Rejected",
            "expected_error_message_substring": "trust domain not in bundle",
        });
        cases.push((
            "reject-trust-domain".to_string(),
            "trust_domain_not_in_bundle".to_string(),
            fixture,
        ));
    }

    // ── reject-empty/ — empty credential ───────────────────────────
    {
        let fixture = json!({
            "name": "empty_credential",
            "description": "Empty credential bytes. SPIFFE Attestor requires a JWT-SVID; spec §9 step 0 maps empty to Rejected('empty credential; SPIFFE Attestor requires a JWT-SVID').",
            "kind": "attestor-spiffe-verify",
            "inputs": {
                "credential_b64": "",
                "context": context,
                "attestor_config": attestor_config,
            },
            "expected_outcome": "reject",
            "expected_error_variant": "Rejected",
            "expected_error_message_substring": "empty credential",
        });
        cases.push((
            "reject-empty".to_string(),
            "empty_credential".to_string(),
            fixture,
        ));
    }

    // ── reject-malformed/ — kid header doesn't match any bundle entry ─
    {
        let token = sign(&Claims::standard(), signing_key, ALT_KID);
        let fixture = json!({
            "name": "unknown_kid",
            "description": "SVID's header.kid does not match any entry in the trust bundle JWKS. Spec §9 maps to Rejected('kid not found in trust bundle').",
            "kind": "attestor-spiffe-verify",
            "inputs": {
                "credential_b64": b64(token.as_bytes()),
                "context": context,
                "attestor_config": attestor_config,
            },
            "expected_outcome": "reject",
            "expected_error_variant": "Rejected",
            "expected_error_message_substring": "kid not found in trust bundle",
        });
        cases.push((
            "reject-malformed".to_string(),
            "unknown_kid".to_string(),
            fixture,
        ));
    }

    cases
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn tamper_last_b64_char(s: &str) -> String {
    let mut chars: Vec<char> = s.chars().collect();
    if let Some(last) = chars.last_mut() {
        *last = if *last == 'A' { 'B' } else { 'A' };
    }
    chars.into_iter().collect()
}

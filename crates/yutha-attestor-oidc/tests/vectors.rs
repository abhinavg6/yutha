//! F8 conformance vectors — loader test.
//!
//! Iterates every `*.json` file under `/spec/vectors/attestor/oidc/`,
//! parses the per-fixture shape pinned in
//! [`spec/vectors/attestor/oidc/README.md`](../../../spec/vectors/attestor/oidc/README.md),
//! constructs an [`OidcAttestor`] in static-file mode against the
//! fixture's inline JWKS, calls `verify()` against the fixture's
//! credential bytes, and asserts the outcome matches.
//!
//! Run with:
//! ```bash
//! cargo test -p yutha-attestor-oidc --test vectors
//! ```
//!
//! Failure modes worth distinguishing:
//! - **Loader bug** (deserialize fails): the fixture JSON shape
//!   doesn't match the expected struct. Update either the regen
//!   (`tests/regen_vectors.rs`) or the structs below.
//! - **Verify outcome mismatch** (test assertion fails): the
//!   Attestor disagrees with the fixture. Either a regression in
//!   `OidcAttestor::verify` OR the fixture is stale; check
//!   `tests/regen_vectors.rs` for the case definition.

use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use yutha_attestor::{AttestationContext, Attestor, AttestorError};
use yutha_attestor_oidc::{JwksSource, OidcAttestor, OidcConfig};
use yutha_core::{AgentId, PublicKey, SignatureAlgorithm, SwarmId};

#[derive(Deserialize)]
struct Fixture {
    // `name`, `description`, `kind` are diagnostic-only — present in
    // every fixture for human readability but the loader doesn't
    // assert on them. clippy: dead-code-allowed since the deserializer
    // populates them.
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    kind: String,
    inputs: Inputs,
    expected_outcome: String,
    #[serde(default)]
    expected_identity: Option<ExpectedIdentity>,
    #[serde(default)]
    expected_error_variant: Option<String>,
    #[serde(default)]
    expected_error_message_substring: Option<String>,
}

#[derive(Deserialize)]
struct Inputs {
    credential_b64: String,
    context: FixtureContext,
    attestor_config: FixtureConfig,
}

#[derive(Deserialize)]
struct FixtureContext {
    swarm_id_hex: String,
    claimed_agent_id_hex: String,
    agent_public_key: FixturePubkey,
}

#[derive(Deserialize)]
struct FixturePubkey {
    algorithm: String,
    value_b64: String,
}

#[derive(Deserialize)]
struct FixtureConfig {
    jwks: Value,
    expected_issuer: String,
    expected_audience: String,
    allowed_algs: Vec<String>,
    project_claims: Vec<String>,
    clock_skew_tolerance_secs: u64,
}

#[derive(Deserialize)]
struct ExpectedIdentity {
    external_identity: String,
    credential_expires_at_unix_secs: i64,
    attributes: BTreeMap<String, String>,
}

#[tokio::test(flavor = "multi_thread")]
async fn all_fixtures_match_attestor_verify_outcome() {
    let vectors_dir = repo_root().join("spec/vectors/attestor/oidc");
    assert!(
        vectors_dir.is_dir(),
        "vectors directory missing: {}. Run \
         `cargo test -p yutha-attestor-oidc --test regen_vectors -- --ignored`",
        vectors_dir.display()
    );

    let fixture_paths = collect_fixture_paths(&vectors_dir);
    assert!(
        !fixture_paths.is_empty(),
        "no fixtures found under {}",
        vectors_dir.display()
    );

    let mut failures: Vec<String> = Vec::new();
    let mut count = 0;

    for path in fixture_paths {
        count += 1;
        let body =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let fixture: Fixture =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));

        if let Err(why) = run_fixture(&fixture).await {
            failures.push(format!(
                "FAIL {}: {why}",
                path.strip_prefix(&vectors_dir).unwrap_or(&path).display()
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} of {count} fixtures failed:\n{}",
            failures.len(),
            failures.join("\n"),
        );
    }
    eprintln!("\nall {count} OIDC conformance vectors pass");
}

async fn run_fixture(fixture: &Fixture) -> Result<(), String> {
    // Materialise the fixture's inline JWKS as a temp file so the
    // Attestor's static-file source can read it. NamedTempFile
    // cleans up on drop at end of this fn.
    let mut jwks_file = NamedTempFile::new().map_err(|e| format!("tempfile: {e}"))?;
    let jwks_pretty = serde_json::to_string(&fixture.inputs.attestor_config.jwks)
        .map_err(|e| format!("serialize jwks: {e}"))?;
    jwks_file
        .write_all(jwks_pretty.as_bytes())
        .map_err(|e| format!("write jwks: {e}"))?;

    let cfg = OidcConfig {
        source: JwksSource::StaticFile {
            path: jwks_file.path().to_path_buf(),
        },
        expected_issuer: fixture.inputs.attestor_config.expected_issuer.clone(),
        expected_audience: fixture.inputs.attestor_config.expected_audience.clone(),
        allowed_algs: fixture.inputs.attestor_config.allowed_algs.clone(),
        project_claims: fixture.inputs.attestor_config.project_claims.clone(),
        cache_ttl_secs: 3600,
        max_staleness_secs: None,
        clock_skew_tolerance_secs: fixture.inputs.attestor_config.clock_skew_tolerance_secs,
        connect_timeout_secs: 10,
        // The fixture's expected_issuer might be `https://login.test.example.com`
        // (no live server). Static-file source doesn't fetch anything, so
        // allow_insecure_http is irrelevant; we set it true defensively for
        // any future regen that picks an `http://` value.
        allow_insecure_http: true,
    };

    let attestor = OidcAttestor::connect(cfg)
        .await
        .map_err(|e| format!("connect: {e}"))?;

    let credential = URL_SAFE_NO_PAD
        .decode(&fixture.inputs.credential_b64)
        .map_err(|e| format!("decode credential_b64: {e}"))?;

    let context = decode_context(&fixture.inputs.context)?;

    let result = attestor.verify(&context, &credential).await;

    match (fixture.expected_outcome.as_str(), result) {
        ("accept", Ok(identity)) => {
            let expected = fixture
                .expected_identity
                .as_ref()
                .ok_or_else(|| "missing expected_identity".to_string())?;
            if identity.external_identity != expected.external_identity {
                return Err(format!(
                    "external_identity mismatch (got {:?}, want {:?})",
                    identity.external_identity, expected.external_identity,
                ));
            }
            let got_exp = identity
                .credential_expires_at
                .as_ref()
                .and_then(|ts| ts.parsed_wall_clock())
                .map(|dt| dt.unix_timestamp())
                .ok_or_else(|| "credential_expires_at missing or unparseable".to_string())?;
            if got_exp != expected.credential_expires_at_unix_secs {
                return Err(format!(
                    "credential_expires_at mismatch (got {got_exp}, want {})",
                    expected.credential_expires_at_unix_secs,
                ));
            }
            let got_attrs: BTreeMap<String, String> = identity.attributes.into_iter().collect();
            if got_attrs != expected.attributes {
                return Err(format!(
                    "attributes mismatch (got {got_attrs:?}, want {:?})",
                    expected.attributes,
                ));
            }
            Ok(())
        }
        ("accept", Err(err)) => Err(format!("expected accept, got reject: {err}")),
        ("reject", Ok(identity)) => Err(format!(
            "expected reject, got accept (external_identity={})",
            identity.external_identity,
        )),
        ("reject", Err(err)) => {
            let want_variant = fixture
                .expected_error_variant
                .as_deref()
                .unwrap_or("Rejected");
            let got_variant = error_variant_tag(&err);
            if got_variant != want_variant {
                return Err(format!(
                    "error-variant mismatch (got {got_variant}, want {want_variant}): {err}"
                ));
            }
            if let Some(needle) = fixture.expected_error_message_substring.as_deref() {
                let msg = err.to_string();
                if !msg.contains(needle) {
                    return Err(format!(
                        "error-message substring missing (want {needle:?}, got {msg:?})"
                    ));
                }
            }
            Ok(())
        }
        (other, _) => Err(format!("unknown expected_outcome {other:?}")),
    }
}

fn error_variant_tag(err: &AttestorError) -> &'static str {
    match err {
        AttestorError::Malformed(_) => "Malformed",
        AttestorError::Rejected(_) => "Rejected",
        AttestorError::TrustRootUnavailable(_) => "TrustRootUnavailable",
        AttestorError::Internal(_) => "Internal",
    }
}

fn decode_context(ctx: &FixtureContext) -> Result<AttestationContext, String> {
    let swarm_bytes = hex::decode(&ctx.swarm_id_hex).map_err(|e| format!("swarm_id_hex: {e}"))?;
    let agent_bytes =
        hex::decode(&ctx.claimed_agent_id_hex).map_err(|e| format!("claimed_agent_id_hex: {e}"))?;
    let pk_bytes = URL_SAFE_NO_PAD
        .decode(&ctx.agent_public_key.value_b64)
        .map_err(|e| format!("agent_public_key.value_b64: {e}"))?;

    let alg = match ctx.agent_public_key.algorithm.as_str() {
        "ed25519" => SignatureAlgorithm::Ed25519,
        other => return Err(format!("unknown pubkey algorithm: {other}")),
    };

    Ok(AttestationContext {
        swarm_id: SwarmId::from_bytes(&swarm_bytes).map_err(|e| format!("swarm_id: {e}"))?,
        claimed_agent_id: AgentId::from_bytes(&agent_bytes)
            .map_err(|e| format!("agent_id: {e}"))?,
        agent_public_key: PublicKey::new(alg, pk_bytes)
            .map_err(|e| format!("pubkey construct: {e}"))?,
    })
}

fn collect_fixture_paths(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(root, &mut out);
    out.sort();
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
            out.push(path);
        }
    }
}

fn repo_root() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .expect("crates/")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

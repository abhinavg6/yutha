//! Conformance-vectors loader. Iterates every JSON fixture under
//! `/spec/vectors/attestor/spiffe/` and asserts our `SpiffeAttestor`
//! produces the `expected_outcome` documented in the file.
//!
//! Runs as part of the regular `cargo test -p yutha-attestor-spiffe`
//! suite — no `--ignored` gate. If the spec dir is empty (no
//! fixtures committed yet), the test no-ops with a friendly message
//! pointing at the regen test in `tests/regen_vectors.rs`.
//!
//! See [`/spec/vectors/attestor/spiffe/README.md`](../../../spec/vectors/attestor/spiffe/README.md)
//! for the JSON fixture shape this loader consumes.

use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use yutha_attestor::{AttestationContext, Attestor, AttestorError};
use yutha_attestor_spiffe::{SpiffeAttestor, SpiffeConfig, TrustBundleSource};
use yutha_core::{AgentId, PublicKey, SignatureAlgorithm, SwarmId};

const VECTORS_REL: &str = "spec/vectors/attestor/spiffe";

#[tokio::test]
async fn every_fixture_matches_expected_outcome() {
    let root = repo_root();
    let dir = root.join(VECTORS_REL);

    if !dir.exists() {
        eprintln!(
            "skipping: {} does not exist yet. Run `cargo test \
             -p yutha-attestor-spiffe --test regen_vectors -- \
             --ignored --nocapture` to materialise the fixtures.",
            dir.display()
        );
        return;
    }

    let fixtures = collect_fixtures(&dir);
    if fixtures.is_empty() {
        eprintln!(
            "skipping: no *.json fixtures under {}. See \
             `tests/regen_vectors.rs` to materialise them.",
            dir.display()
        );
        return;
    }

    eprintln!("loading {} SPIFFE conformance fixtures…", fixtures.len());
    for path in fixtures {
        let case = load_case(&path);
        run_case(&path, &case).await;
    }
}

/// Walk `dir` recursively, collecting every `*.json` that isn't a
/// README. Sorted for deterministic test ordering.
fn collect_fixtures(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk(&p, out);
            continue;
        }
        if p.extension().and_then(|s| s.to_str()) == Some("json") {
            out.push(p);
        }
    }
}

/// Read + parse a single fixture file.
fn load_case(path: &Path) -> Value {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Run one fixture: build the Attestor from its config, call verify,
/// assert the outcome matches `expected_*`.
async fn run_case(path: &Path, case: &Value) {
    let display = path
        .strip_prefix(repo_root())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.display().to_string());

    let name = case
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>");
    let kind = case.get("kind").and_then(Value::as_str).unwrap_or("");
    assert_eq!(
        kind, "attestor-spiffe-verify",
        "{display}: kind must be 'attestor-spiffe-verify'"
    );

    let inputs = case.get("inputs").expect("inputs");
    let credential = decode_credential(inputs);
    let context = decode_context(inputs);
    let config = decode_config(inputs, &display);

    // Write the trust bundle to a temp file the static-file source
    // can consume.
    let bundle_path = write_temp_bundle(config, &display);
    let cfg = SpiffeConfig {
        source: TrustBundleSource::StaticFile {
            path: bundle_path.clone(),
        },
        expected_audience: config
            .get("expected_audience")
            .and_then(Value::as_str)
            .unwrap_or("yutha-test-audience")
            .to_string(),
        max_staleness: None,
        clock_skew_tolerance_secs: config
            .get("clock_skew_tolerance_secs")
            .and_then(Value::as_u64)
            .unwrap_or(60),
        connect_timeout_secs: 10,
    };

    let attestor = SpiffeAttestor::connect(cfg)
        .await
        .unwrap_or_else(|e| panic!("{display}: connect failed: {e}"));

    let outcome = case
        .get("expected_outcome")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{display}: missing expected_outcome"));

    let result = attestor.verify(&context, &credential).await;

    let _ = fs::remove_file(&bundle_path);

    match outcome {
        "accept" => assert_accept(&display, name, case, result),
        "reject" => assert_reject(&display, name, case, result),
        other => panic!("{display}: unknown expected_outcome '{other}'"),
    }
}

fn assert_accept(
    display: &str,
    name: &str,
    case: &Value,
    result: Result<yutha_attestor::AttestedIdentity, AttestorError>,
) {
    let identity =
        result.unwrap_or_else(|e| panic!("{display} ({name}): expected accept, got reject: {e:?}"));

    let expected = case
        .get("expected_identity")
        .unwrap_or_else(|| panic!("{display}: accept fixture must carry expected_identity"));

    if let Some(ext) = expected.get("external_identity").and_then(Value::as_str) {
        assert_eq!(
            identity.external_identity, ext,
            "{display} ({name}): external_identity mismatch"
        );
    }
    if let Some(exp_secs) = expected
        .get("credential_expires_at_unix_secs")
        .and_then(Value::as_i64)
    {
        let got = identity
            .credential_expires_at
            .as_ref()
            .expect("accept must carry expiry")
            .clone();
        let got_secs = parse_rfc3339_unix(&got.wall_clock)
            .unwrap_or_else(|| panic!("{display} ({name}): could not parse expiry wall_clock"));
        assert_eq!(
            got_secs, exp_secs,
            "{display} ({name}): credential_expires_at_unix_secs mismatch"
        );
    }
    if let Some(attrs) = expected.get("attributes").and_then(Value::as_object) {
        assert_eq!(
            identity.attributes.len(),
            attrs.len(),
            "{display} ({name}): attribute count mismatch \
             (got: {:?}, expected: {:?})",
            identity.attributes,
            attrs
        );
        for (k, v) in attrs {
            let v_str = v.as_str().unwrap_or_else(|| {
                panic!(
                    "{display} ({name}): expected_identity.attributes \
                     values must be strings; got {v:?}"
                )
            });
            assert_eq!(
                identity.attributes.get(k).map(String::as_str),
                Some(v_str),
                "{display} ({name}): attribute '{k}' mismatch"
            );
        }
    }
}

fn assert_reject(
    display: &str,
    name: &str,
    case: &Value,
    result: Result<yutha_attestor::AttestedIdentity, AttestorError>,
) {
    let err = result
        .err()
        .unwrap_or_else(|| panic!("{display} ({name}): expected reject, got accept"));

    let expected_variant = case
        .get("expected_error_variant")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{display}: reject fixture must carry expected_error_variant"));
    let expected_substr = case
        .get("expected_error_message_substring")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!("{display}: reject fixture must carry expected_error_message_substring")
        });

    let (got_variant, got_msg) = match &err {
        AttestorError::Malformed(m) => ("Malformed", m.as_str()),
        AttestorError::Rejected(m) => ("Rejected", m.as_str()),
        AttestorError::TrustRootUnavailable(m) => ("TrustRootUnavailable", m.as_str()),
        AttestorError::Internal(m) => ("Internal", m.as_str()),
    };

    assert_eq!(
        got_variant, expected_variant,
        "{display} ({name}): variant mismatch (msg: {got_msg})"
    );
    assert!(
        got_msg.contains(expected_substr),
        "{display} ({name}): expected substring '{expected_substr}' \
         not found in actual message '{got_msg}'"
    );
}

// ───────────────────────────── Helpers ─────────────────────────────

fn decode_credential(inputs: &Value) -> Vec<u8> {
    let b64 = inputs
        .get("credential_b64")
        .and_then(Value::as_str)
        .expect("inputs.credential_b64");
    if b64.is_empty() {
        Vec::new()
    } else {
        URL_SAFE_NO_PAD
            .decode(b64)
            .expect("credential_b64 must be base64url-no-pad")
    }
}

fn decode_context(inputs: &Value) -> AttestationContext {
    let ctx = inputs.get("context").expect("inputs.context");
    let swarm_id_hex = ctx
        .get("swarm_id_hex")
        .and_then(Value::as_str)
        .expect("context.swarm_id_hex");
    let claimed_id_hex = ctx
        .get("claimed_agent_id_hex")
        .and_then(Value::as_str)
        .expect("context.claimed_agent_id_hex");
    let pk_obj = ctx
        .get("agent_public_key")
        .expect("context.agent_public_key");
    let pk_b64 = pk_obj
        .get("value_b64")
        .and_then(Value::as_str)
        .expect("agent_public_key.value_b64");
    let pk_bytes = URL_SAFE_NO_PAD
        .decode(pk_b64)
        .expect("agent_public_key.value_b64 must be base64url-no-pad");

    AttestationContext {
        swarm_id: parse_swarm_id(swarm_id_hex),
        claimed_agent_id: parse_agent_id(claimed_id_hex),
        agent_public_key: PublicKey::new(SignatureAlgorithm::Ed25519, pk_bytes)
            .expect("32-byte Ed25519 public key"),
    }
}

fn decode_config<'a>(inputs: &'a Value, display: &str) -> &'a Value {
    inputs
        .get("attestor_config")
        .unwrap_or_else(|| panic!("{display}: inputs.attestor_config missing"))
}

fn write_temp_bundle(config: &Value, display: &str) -> PathBuf {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let bundle = config
        .get("trust_bundle")
        .unwrap_or_else(|| panic!("{display}: attestor_config.trust_bundle missing"));
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "yutha-attestor-spiffe-vectors-{}-{}.json",
        std::process::id(),
        unique,
    ));
    let mut f = fs::File::create(&path).expect("temp create");
    f.write_all(serde_json::to_vec(bundle).expect("ser bundle").as_slice())
        .expect("write bundle");
    path
}

fn parse_swarm_id(hex: &str) -> SwarmId {
    let bytes = hex_to_bytes(hex);
    assert_eq!(bytes.len(), 16, "swarm_id_hex must decode to 16 bytes");
    SwarmId::from_bytes(&bytes).expect("16-byte swarm id")
}

fn parse_agent_id(hex: &str) -> AgentId {
    let bytes = hex_to_bytes(hex);
    assert_eq!(
        bytes.len(),
        16,
        "claimed_agent_id_hex must decode to 16 bytes"
    );
    AgentId::from_bytes(&bytes).expect("16-byte agent id")
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i + 1 < chars.len() {
        let hi = chars[i].to_digit(16).unwrap_or_else(|| panic!("hex: {s}"));
        let lo = chars[i + 1]
            .to_digit(16)
            .unwrap_or_else(|| panic!("hex: {s}"));
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    out
}

fn parse_rfc3339_unix(wall_clock: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    let dt = OffsetDateTime::parse(wall_clock, &Rfc3339).ok()?;
    Some(dt.unix_timestamp())
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

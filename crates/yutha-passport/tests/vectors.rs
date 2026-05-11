//! Passport wire-format vectors test.
//!
//! Mirrors `crates/yutha-receipt/tests/vectors.rs` exactly in shape — reads
//! every JSON fixture under `/spec/vectors/passport/`, builds a [`Passport`]
//! from the declared fields, computes canonical bytes, asserts hex match.
//!
//! Set `YUTHA_REGENERATE_VECTORS=1` to rewrite each fixture's
//! `expected_canonical_hex` instead of asserting on it (use only when a
//! legitimate spec change shifts the wire format).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use yutha_core::{AgentId, PublicKey, SignatureAlgorithm, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_passport::{CapabilityDeclaration, Passport, PassportTier, ResourceDeclaration};

// -----------------------------------------------------------------------------
// Fixture schema
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
struct Vector {
    name: String,
    description: String,
    kind: String,
    fields: PassportFields,
    expected_canonical_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct PassportFields {
    spec_version: String,
    agent_id_hex: String,
    swarm_id_hex: String,
    agent_public_key: PublicKeyFields,
    owner: String,
    framework: String,
    framework_version: String,
    capabilities: Vec<CapabilityDeclarationFields>,
    accepted_constitution_version: String,
    tier: String,
    resources: ResourceDeclarationFields,
    issued_at: TimestampFields,
    expires_at: Option<TimestampFields>,
    default_model_provider: String,
    default_model_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct PublicKeyFields {
    algorithm: String,
    value_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct CapabilityDeclarationFields {
    kind: String,
    resource_tags: Vec<String>,
    bounds: BTreeMap<String, String>,
    description: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ResourceDeclarationFields {
    max_concurrent_actions: u64,
    max_messages_per_minute: u64,
    max_tool_calls_per_hour: u64,
    max_usd_per_day_cents: String,
    max_memory_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct TimestampFields {
    wall_clock: String,
    monotonic_ns: u64,
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string has odd length: {s:?}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn parse_algorithm(s: &str) -> SignatureAlgorithm {
    match s {
        "ed25519" => SignatureAlgorithm::Ed25519,
        "reserved_pq" => SignatureAlgorithm::ReservedPq,
        other => panic!("unknown signature algorithm: {other}"),
    }
}

fn parse_tier(s: &str) -> PassportTier {
    match s {
        "minimal" => PassportTier::Minimal,
        "standard" => PassportTier::Standard,
        "verifiable" => PassportTier::Verifiable,
        other => panic!("unknown passport tier: {other}"),
    }
}

fn parse_timestamp(t: &TimestampFields) -> Timestamp {
    Timestamp::new(t.wall_clock.clone(), t.monotonic_ns).expect("valid timestamp")
}

// -----------------------------------------------------------------------------
// Fixture → Passport
// -----------------------------------------------------------------------------

fn build_passport(name: &str, f: &PassportFields) -> Passport {
    let agent_id = AgentId::from_bytes(&hex_decode(&f.agent_id_hex))
        .unwrap_or_else(|e| panic!("[{name}] agent_id: {e}"));
    let swarm_id = SwarmId::from_bytes(&hex_decode(&f.swarm_id_hex))
        .unwrap_or_else(|e| panic!("[{name}] swarm_id: {e}"));
    let pk = PublicKey::new(
        parse_algorithm(&f.agent_public_key.algorithm),
        hex_decode(&f.agent_public_key.value_hex),
    )
    .unwrap_or_else(|e| panic!("[{name}] agent_public_key: {e}"));

    let mut builder = Passport::builder()
        .spec_version(
            SpecVersion::parse(&f.spec_version)
                .unwrap_or_else(|e| panic!("[{name}] spec_version: {e}")),
        )
        .agent_id(agent_id)
        .swarm_id(swarm_id)
        .agent_public_key(pk)
        .owner(f.owner.clone())
        .framework(f.framework.clone(), f.framework_version.clone())
        .accepted_constitution_version(f.accepted_constitution_version.clone())
        .tier(parse_tier(&f.tier))
        .resources(ResourceDeclaration {
            max_concurrent_actions: f.resources.max_concurrent_actions,
            max_messages_per_minute: f.resources.max_messages_per_minute,
            max_tool_calls_per_hour: f.resources.max_tool_calls_per_hour,
            max_usd_per_day_cents: f.resources.max_usd_per_day_cents.clone(),
            max_memory_bytes: f.resources.max_memory_bytes,
        })
        .issued_at(parse_timestamp(&f.issued_at))
        .default_model(
            f.default_model_provider.clone(),
            f.default_model_name.clone(),
        );

    if let Some(e) = &f.expires_at {
        builder = builder.expires_at(parse_timestamp(e));
    }

    for cap in &f.capabilities {
        let mut decl = CapabilityDeclaration::of_kind(cap.kind.clone())
            .with_description(cap.description.clone());
        for tag in &cap.resource_tags {
            decl = decl.with_tag(tag.clone());
        }
        // BTreeMap iteration is sorted; insertion order in the JSON doesn't
        // affect what build sees. Both BTreeMap (Rust) and Deterministic
        // marshal (Go) sort on encode — that's the wire contract.
        for (k, v) in &cap.bounds {
            decl = decl.with_bound(k.clone(), v.clone());
        }
        builder = builder.declares(decl);
    }

    // build_unsigned (not sign) — canonical bytes are signature-cleared
    // anyway, but build_unsigned avoids needing a real keypair.
    builder
        .build_unsigned()
        .unwrap_or_else(|e| panic!("[{name}] build_unsigned: {e}"))
}

// -----------------------------------------------------------------------------
// Test driver
// -----------------------------------------------------------------------------

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/passport")
}

fn regenerate_requested() -> bool {
    matches!(
        std::env::var("YUTHA_REGENERATE_VECTORS").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn process_vector(path: &Path, regenerate: bool) -> Result<(), String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {path:?}: {e}"))?;
    let mut vector: Vector =
        serde_json::from_str(&raw).map_err(|e| format!("parse {path:?}: {e}"))?;
    if vector.kind != "passport" {
        return Ok(());
    }

    let passport = build_passport(&vector.name, &vector.fields);
    let canonical = passport
        .canonical_bytes()
        .map_err(|e| format!("[{}] canonical_bytes: {e}", vector.name))?;
    let actual_hex = hex_encode(&canonical);

    if regenerate {
        vector.expected_canonical_hex = actual_hex;
        let updated = serde_json::to_string_pretty(&vector)
            .map_err(|e| format!("[{}] serialize: {e}", vector.name))?;
        fs::write(path, format!("{updated}\n"))
            .map_err(|e| format!("[{}] write: {e}", vector.name))?;
        return Ok(());
    }

    if vector.expected_canonical_hex == actual_hex {
        Ok(())
    } else {
        Err(format!(
            "[{}] canonical bytes diverged from fixture\n  expected: {}\n  actual:   {}\n  hint:    re-run with YUTHA_REGENERATE_VECTORS=1 if this change is intentional",
            vector.name, vector.expected_canonical_hex, actual_hex,
        ))
    }
}

#[test]
fn passport_vectors_match() {
    let dir = vectors_dir();
    let entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"))
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .collect();

    assert!(!entries.is_empty(), "no passport vectors in {dir:?}");

    let regenerate = regenerate_requested();
    let mut failures = Vec::new();
    let mut count = 0usize;
    for entry in entries {
        count += 1;
        if let Err(e) = process_vector(&entry.path(), regenerate) {
            failures.push(e);
        }
    }

    if !failures.is_empty() {
        panic!(
            "{n} passport vector(s) failed:\n\n{joined}",
            n = failures.len(),
            joined = failures.join("\n\n"),
        );
    }
    if regenerate {
        eprintln!("regenerated {count} passport vector(s)");
    }
}

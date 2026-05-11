//! Wire-format vectors test.
//!
//! Reads every JSON fixture under `/spec/vectors/receipt/`, builds a
//! [`Receipt`] from the declared fields, computes its canonical bytes via
//! the spec-mandated path (`to_canonical_proto().encode_to_vec()`), and
//! asserts that the result matches the fixture's `expected_canonical_hex`.
//!
//! This test is the *frozen wire format* gate: any change to the canonical
//! encoding for any input fires it. Cross-language conformance (a Go or
//! other-language implementation hitting the same vectors) layers on top
//! by running the equivalent assertion against the same fixture set.
//!
//! ## Regenerating expected hex
//!
//! When a legitimate spec change shifts the wire format, set
//! `YUTHA_REGENERATE_VECTORS=1` and re-run:
//!
//! ```bash
//! YUTHA_REGENERATE_VECTORS=1 cargo test -p yutha-receipt --test vectors
//! git diff spec/vectors/
//! ```
//!
//! The test will rewrite each fixture's `expected_canonical_hex` in place
//! instead of asserting. Commit the diff, then re-run normally to verify.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use yutha_core::{
    AgentId, CausalRef, CostAnnotation, Hash, HashAlgorithm, SpecVersion, SwarmId, Timestamp,
};
use yutha_crypto::canonical::Canonical;
use yutha_receipt::{Evidence, Receipt};

// -----------------------------------------------------------------------------
// Fixture schema
// -----------------------------------------------------------------------------

/// Top-level vector file shape. Mirrors the format documented in
/// [`/spec/vectors/README.md`](../../../../spec/vectors/README.md).
#[derive(Debug, Deserialize, Serialize)]
struct Vector {
    name: String,
    description: String,
    kind: String,
    fields: ReceiptFields,
    expected_canonical_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReceiptFields {
    spec_version: String,
    swarm_id_hex: String,
    actor_hex: String,
    action_kind: String,
    constitution_version: String,
    occurred_at: TimestampFields,
    predecessors_hex: Vec<String>,
    evidence: Vec<EvidenceFields>,
    cost: Option<CostFields>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TimestampFields {
    wall_clock: String,
    monotonic_ns: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct EvidenceFields {
    key: String,
    type_url: String,
    value_hex: String,
    sensitive: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct CostFields {
    input_tokens: u64,
    output_tokens: u64,
    tool_call_count: u64,
    wall_time_ms: u64,
    usd_cents_estimate: String,
    model_provider: String,
    model_name: String,
    model_version: String,
}

// -----------------------------------------------------------------------------
// Fixture → Receipt
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

fn build_receipt(name: &str, f: &ReceiptFields) -> Receipt {
    let swarm = SwarmId::from_bytes(&hex_decode(&f.swarm_id_hex))
        .unwrap_or_else(|e| panic!("[{name}] swarm_id: {e}"));
    let actor = AgentId::from_bytes(&hex_decode(&f.actor_hex))
        .unwrap_or_else(|e| panic!("[{name}] actor: {e}"));

    let predecessors: Vec<Hash> = f
        .predecessors_hex
        .iter()
        .map(|h| {
            Hash::new(HashAlgorithm::Sha256, hex_decode(h))
                .unwrap_or_else(|e| panic!("[{name}] predecessor: {e}"))
        })
        .collect();

    let mut builder = Receipt::builder()
        .spec_version(
            SpecVersion::parse(&f.spec_version)
                .unwrap_or_else(|e| panic!("[{name}] spec_version: {e}")),
        )
        .swarm_id(swarm)
        .actor(actor)
        .action_kind(f.action_kind.clone())
        .constitution_version(f.constitution_version.clone())
        .occurred_at(
            Timestamp::new(f.occurred_at.wall_clock.clone(), f.occurred_at.monotonic_ns)
                .unwrap_or_else(|e| panic!("[{name}] occurred_at: {e}")),
        )
        .causal(CausalRef::from_iter(predecessors));

    for e in &f.evidence {
        let value = hex_decode(&e.value_hex);
        let ev = if e.sensitive {
            Evidence::sensitive(e.key.clone(), e.type_url.clone(), value)
        } else {
            Evidence::new(e.key.clone(), e.type_url.clone(), value)
        };
        builder = builder.evidence(ev);
    }

    if let Some(c) = &f.cost {
        builder = builder.cost(CostAnnotation {
            input_tokens: c.input_tokens,
            output_tokens: c.output_tokens,
            tool_call_count: c.tool_call_count,
            wall_time_ms: c.wall_time_ms,
            usd_cents_estimate: c.usd_cents_estimate.clone(),
            model_provider: c.model_provider.clone(),
            model_name: c.model_name.clone(),
            model_version: c.model_version.clone(),
        });
    }

    builder
        .build()
        .unwrap_or_else(|e| panic!("[{name}] build: {e}"))
}

// -----------------------------------------------------------------------------
// Test driver
// -----------------------------------------------------------------------------

/// Locate `/spec/vectors/receipt/` from this test's working directory. The
/// test runs from the crate root (`/crates/yutha-receipt/`), so `../../`
/// hops back to the repo root.
fn vectors_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../spec/vectors/receipt")
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

    if vector.kind != "receipt" {
        // Other types will be added later (passport, envelope, capability).
        // For now, the receipt vectors directory is the only thing we
        // process; ignore other kinds defensively.
        return Ok(());
    }

    let receipt = build_receipt(&vector.name, &vector.fields);
    let canonical = receipt
        .canonical_bytes()
        .map_err(|e| format!("[{}] canonical_bytes: {e}", vector.name))?;
    let actual_hex = hex_encode(&canonical);

    if regenerate {
        vector.expected_canonical_hex = actual_hex;
        let updated = serde_json::to_string_pretty(&vector)
            .map_err(|e| format!("[{}] serialize: {e}", vector.name))?;
        // Preserve trailing newline matching the original file convention.
        let with_newline = format!("{updated}\n");
        fs::write(path, with_newline).map_err(|e| format!("[{}] write: {e}", vector.name))?;
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
fn receipt_vectors_match() {
    let dir = vectors_dir();
    let entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"))
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .collect();

    assert!(
        !entries.is_empty(),
        "no receipt vectors found in {dir:?} — did the directory get moved?"
    );

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
            "{n} receipt vector(s) failed:\n\n{joined}",
            n = failures.len(),
            joined = failures.join("\n\n"),
        );
    }

    if regenerate {
        eprintln!("regenerated {count} receipt vector(s); review with `git diff spec/vectors/`");
    }
}

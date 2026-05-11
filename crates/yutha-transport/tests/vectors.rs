//! Envelope wire-format vectors test.
//!
//! Reads every JSON fixture under `/spec/vectors/envelope/`, builds an
//! [`Envelope`] from the declared fields, computes canonical bytes,
//! asserts hex match. Same regeneration env-var as the other vectors
//! tests (`YUTHA_REGENERATE_VECTORS=1`).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use yutha_core::{AgentId, CausalRef, Hash, HashAlgorithm, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_transport::{Envelope, Performative, Recipient, SwarmBroadcast};

// -----------------------------------------------------------------------------
// Fixture schema
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
struct Vector {
    name: String,
    description: String,
    kind: String,
    fields: EnvelopeFields,
    expected_canonical_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct EnvelopeFields {
    spec_version: String,
    swarm_id_hex: String,
    envelope_id_hex: String,
    from_agent_hex: String,
    recipient: RecipientFields,
    performative: String,
    payload_hex: String,
    payload_schema_id: String,
    tags: Vec<String>,
    predecessors_hex: Vec<String>,
    nonce_hex: String,
    epoch: u64,
    sent_at: TimestampFields,
    expires_at: Option<TimestampFields>,
    in_reply_to_hex: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind")]
#[serde(rename_all = "snake_case")]
enum RecipientFields {
    Agent { agent_hex: String },
    Role { role: String },
    Swarm { filter_tags: Vec<String> },
    External(ExternalEndpointFields),
}

#[derive(Debug, Deserialize, Serialize)]
struct ExternalEndpointFields {
    scheme: String,
    authority: String,
    path_hint: String,
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

fn parse_timestamp(t: &TimestampFields) -> Timestamp {
    Timestamp::new(t.wall_clock.clone(), t.monotonic_ns).expect("valid timestamp")
}

fn parse_performative(s: &str) -> Performative {
    match s {
        "propose" => Performative::Propose,
        "counter" => Performative::Counter,
        "commit" => Performative::Commit,
        "abort" => Performative::Abort,
        "release" => Performative::Release,
        "query" => Performative::Query,
        "inform" => Performative::Inform,
        "error" => Performative::Error,
        "request_action" => Performative::RequestAction,
        "confirm" => Performative::Confirm,
        "decline" => Performative::Decline,
        other => panic!("unknown performative: {other}"),
    }
}

fn parse_recipient(name: &str, r: &RecipientFields) -> Recipient {
    match r {
        RecipientFields::Agent { agent_hex } => Recipient::Agent(
            AgentId::from_bytes(&hex_decode(agent_hex))
                .unwrap_or_else(|e| panic!("[{name}] recipient.agent: {e}")),
        ),
        RecipientFields::Role { role } => Recipient::Role(role.clone()),
        RecipientFields::Swarm { filter_tags } => Recipient::Swarm(SwarmBroadcast {
            filter_tags: filter_tags.clone(),
        }),
        RecipientFields::External(e) => {
            Recipient::External(yutha_transport::ExternalEndpoint {
                scheme: e.scheme.clone(),
                authority: e.authority.clone(),
                path_hint: e.path_hint.clone(),
            })
        }
    }
}

// -----------------------------------------------------------------------------
// Fixture → Envelope
// -----------------------------------------------------------------------------

fn build_envelope(name: &str, f: &EnvelopeFields) -> Envelope {
    let from_agent = AgentId::from_bytes(&hex_decode(&f.from_agent_hex))
        .unwrap_or_else(|e| panic!("[{name}] from_agent: {e}"));
    let swarm_id = SwarmId::from_bytes(&hex_decode(&f.swarm_id_hex))
        .unwrap_or_else(|e| panic!("[{name}] swarm_id: {e}"));

    let predecessors: Vec<Hash> = f
        .predecessors_hex
        .iter()
        .map(|h| {
            Hash::new(HashAlgorithm::Sha256, hex_decode(h))
                .unwrap_or_else(|e| panic!("[{name}] predecessor: {e}"))
        })
        .collect();

    let mut builder = Envelope::builder()
        .spec_version(
            SpecVersion::parse(&f.spec_version)
                .unwrap_or_else(|e| panic!("[{name}] spec_version: {e}")),
        )
        .swarm_id(swarm_id)
        .envelope_id(hex_decode(&f.envelope_id_hex))
        .from_agent(from_agent)
        .recipient(parse_recipient(name, &f.recipient))
        .performative(parse_performative(&f.performative))
        .payload(hex_decode(&f.payload_hex))
        .payload_schema_id(f.payload_schema_id.clone())
        .causal(CausalRef::from_iter(predecessors))
        .nonce(hex_decode(&f.nonce_hex))
        .epoch(f.epoch)
        .sent_at(parse_timestamp(&f.sent_at));

    for tag in &f.tags {
        builder = builder.tag(tag.clone());
    }
    if let Some(e) = &f.expires_at {
        builder = builder.expires_at(parse_timestamp(e));
    }
    if let Some(reply_hex) = &f.in_reply_to_hex {
        let h = Hash::new(HashAlgorithm::Sha256, hex_decode(reply_hex))
            .unwrap_or_else(|e| panic!("[{name}] in_reply_to: {e}"));
        builder = builder.in_reply_to(h);
    }

    builder
        .build()
        .unwrap_or_else(|e| panic!("[{name}] build: {e}"))
}

// -----------------------------------------------------------------------------
// Test driver
// -----------------------------------------------------------------------------

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/envelope")
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
    if vector.kind != "envelope" {
        return Ok(());
    }

    let envelope = build_envelope(&vector.name, &vector.fields);
    let canonical = envelope
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
fn envelope_vectors_match() {
    let dir = vectors_dir();
    let entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"))
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .collect();

    assert!(!entries.is_empty(), "no envelope vectors in {dir:?}");

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
            "{n} envelope vector(s) failed:\n\n{joined}",
            n = failures.len(),
            joined = failures.join("\n\n"),
        );
    }
    if regenerate {
        eprintln!("regenerated {count} envelope vector(s)");
    }
}

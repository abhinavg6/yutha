//! Capability wire-format vectors test.
//!
//! Reads every JSON fixture under `/spec/vectors/capability/`, builds a
//! [`Capability`] from the declared fields, computes canonical bytes,
//! asserts hex match. Two oneofs here — `Issuer` (3 variants) and
//! `Caveat` (6 variants); the fixtures collectively exercise the
//! variants we actually encode in practice.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use yutha_capability::{
    Capability, Caveat, ControlPlaneIssuer, Issuer, RateLimit, Scope, TimeOfDay,
};
use yutha_core::{AgentId, Hash, HashAlgorithm, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::Canonical;

// -----------------------------------------------------------------------------
// Fixture schema
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
struct Vector {
    name: String,
    description: String,
    kind: String,
    fields: CapabilityFields,
    expected_canonical_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct CapabilityFields {
    spec_version: String,
    capability_id_hex: String,
    swarm_id_hex: String,
    issuer: IssuerFields,
    subject_hex: String,
    scope: ScopeFields,
    parent_hex: Option<String>,
    valid_from: TimestampFields,
    valid_until: TimestampFields,
    caveats: Vec<CaveatFields>,
    revocation_endpoint: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind")]
#[serde(rename_all = "snake_case")]
enum IssuerFields {
    Agent {
        agent_hex: String,
    },
    Operator {
        key_fingerprint_hex: String,
    },
    ControlPlane {
        control_plane_key_fingerprint_hex: String,
        instance_id: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
struct ScopeFields {
    permitted_actions: Vec<String>,
    resource_tags: Vec<String>,
    bounds: BTreeMap<String, String>,
    permitted_recipients: Vec<String>,
    memory_scopes: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind")]
#[serde(rename_all = "snake_case")]
enum CaveatFields {
    TimeOfDay {
        from_utc: String,
        to_utc: String,
    },
    ConstitutionVersion {
        min_version: String,
        max_version: Option<String>,
    },
    SupervisorRequired {
        supervisor_role: String,
    },
    RateLimit {
        max_actions: u32,
        window_seconds: u64,
    },
    OnlyIfTagged {
        required_tags: Vec<String>,
    },
    NeverIfTagged {
        forbidden_tags: Vec<String>,
    },
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

fn parse_issuer(name: &str, i: &IssuerFields) -> Issuer {
    match i {
        IssuerFields::Agent { agent_hex } => Issuer::Agent(
            AgentId::from_bytes(&hex_decode(agent_hex))
                .unwrap_or_else(|e| panic!("[{name}] issuer.agent: {e}")),
        ),
        IssuerFields::Operator {
            key_fingerprint_hex,
        } => Issuer::Operator(hex_decode(key_fingerprint_hex)),
        IssuerFields::ControlPlane {
            control_plane_key_fingerprint_hex,
            instance_id,
        } => Issuer::ControlPlane(ControlPlaneIssuer {
            control_plane_key_fingerprint: hex_decode(control_plane_key_fingerprint_hex),
            instance_id: instance_id.clone(),
        }),
    }
}

fn parse_scope(s: &ScopeFields) -> Scope {
    let mut scope = Scope {
        permitted_actions: s.permitted_actions.clone(),
        resource_tags: s.resource_tags.clone(),
        bounds: BTreeMap::new(),
        permitted_recipients: s.permitted_recipients.clone(),
        memory_scopes: s.memory_scopes.clone(),
    };
    // BTreeMap insertion is sorted by construction.
    for (k, v) in &s.bounds {
        scope.bounds.insert(k.clone(), v.clone());
    }
    scope
}

fn parse_caveat(c: &CaveatFields) -> Caveat {
    match c {
        CaveatFields::TimeOfDay { from_utc, to_utc } => Caveat::TimeOfDay(TimeOfDay {
            from_utc: from_utc.clone(),
            to_utc: to_utc.clone(),
        }),
        CaveatFields::ConstitutionVersion {
            min_version,
            max_version,
        } => Caveat::ConstitutionVersion {
            min_version: min_version.clone(),
            max_version: max_version.clone(),
        },
        CaveatFields::SupervisorRequired { supervisor_role } => Caveat::SupervisorRequired {
            supervisor_role: supervisor_role.clone(),
        },
        CaveatFields::RateLimit {
            max_actions,
            window_seconds,
        } => Caveat::RateLimit(RateLimit {
            max_actions: *max_actions,
            window_seconds: *window_seconds,
        }),
        CaveatFields::OnlyIfTagged { required_tags } => Caveat::OnlyIfTagged {
            required_tags: required_tags.clone(),
        },
        CaveatFields::NeverIfTagged { forbidden_tags } => Caveat::NeverIfTagged {
            forbidden_tags: forbidden_tags.clone(),
        },
    }
}

// -----------------------------------------------------------------------------
// Fixture → Capability
// -----------------------------------------------------------------------------

fn build_capability(name: &str, f: &CapabilityFields) -> Capability {
    let subject = AgentId::from_bytes(&hex_decode(&f.subject_hex))
        .unwrap_or_else(|e| panic!("[{name}] subject: {e}"));
    let swarm_id = SwarmId::from_bytes(&hex_decode(&f.swarm_id_hex))
        .unwrap_or_else(|e| panic!("[{name}] swarm_id: {e}"));

    let mut builder = Capability::builder()
        .spec_version(
            SpecVersion::parse(&f.spec_version)
                .unwrap_or_else(|e| panic!("[{name}] spec_version: {e}")),
        )
        .capability_id(hex_decode(&f.capability_id_hex))
        .swarm_id(swarm_id)
        .issuer(parse_issuer(name, &f.issuer))
        .subject(subject)
        .scope(parse_scope(&f.scope))
        .valid_from(parse_timestamp(&f.valid_from))
        .valid_until(parse_timestamp(&f.valid_until))
        .revocation_endpoint(f.revocation_endpoint.clone());

    if let Some(parent_hex) = &f.parent_hex {
        let h = Hash::new(HashAlgorithm::Sha256, hex_decode(parent_hex))
            .unwrap_or_else(|e| panic!("[{name}] parent: {e}"));
        builder = builder.parent(h);
    }

    for caveat in &f.caveats {
        builder = builder.caveat(parse_caveat(caveat));
    }

    // build() is the unsigned path — canonical bytes are signature-cleared
    // anyway, and we don't need to invoke a real keypair just to encode.
    builder
        .build()
        .unwrap_or_else(|e| panic!("[{name}] build: {e}"))
}

// -----------------------------------------------------------------------------
// Test driver
// -----------------------------------------------------------------------------

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/capability")
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
    if vector.kind != "capability" {
        return Ok(());
    }

    let capability = build_capability(&vector.name, &vector.fields);
    let canonical = capability
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
fn capability_vectors_match() {
    let dir = vectors_dir();
    let entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"))
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .collect();

    assert!(!entries.is_empty(), "no capability vectors in {dir:?}");

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
            "{n} capability vector(s) failed:\n\n{joined}",
            n = failures.len(),
            joined = failures.join("\n\n"),
        );
    }
    if regenerate {
        eprintln!("regenerated {count} capability vector(s)");
    }
}

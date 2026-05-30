//! Signer wire-format + behavioral conformance vectors.
//!
//! Reads every JSON fixture under
//! `/spec/vectors/signer/sign-and-verify/`, derives the
//! `(public_key, key_fingerprint, signature)` triple via both the
//! [`InProcessSigner`] trait surface AND the underlying raw
//! [`yutha_crypto::SigningKey`], and asserts:
//!
//! 1. The two paths produce **byte-identical** output. This is the
//!    "RFC 0015 §3.1 invariant 1" gate — the wrapper MUST NOT change
//!    the math.
//! 2. The produced signature **verifies** under the reported public
//!    key. This is the RFC 8032 round-trip.
//! 3. The output matches the committed `expected_*_hex` fields in the
//!    fixture. This is the cross-implementation byte-equivalence gate
//!    — any future implementation (Python `InProcessSigner`, Go SDK,
//!    Vault transit adapter) that fails a vector is non-conformant.
//!
//! ## Regenerating expected hex
//!
//! When the spec legitimately changes the wire format (a new RFC
//! repins the seed→key derivation; Ed25519 itself would have to move,
//! which it won't), set `YUTHA_REGENERATE_VECTORS=1` and re-run:
//!
//! ```bash
//! YUTHA_REGENERATE_VECTORS=1 cargo test -p yutha-signer --test vectors
//! git diff spec/vectors/signer/    # review every change
//! ```
//!
//! The test rewrites each fixture's `expected_*_hex` in place instead
//! of asserting. Commit the diff, then re-run normally to verify the
//! committed values pass assertion mode.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use yutha_crypto::{verify, SigningKey};
use yutha_signer::{InProcessSigner, Signer};

// -----------------------------------------------------------------------------
// Fixture schema
// -----------------------------------------------------------------------------

/// Top-level vector file shape. Mirrors the format documented in
/// [`/spec/vectors/signer/sign-and-verify/README.md`](../../../../spec/vectors/signer/sign-and-verify/README.md).
///
/// `serde_json::Value`-typed `inputs` keeps round-trip serialisation
/// stable across the optional `_comment_*` keys some fixtures carry
/// (used to document hash-derived seeds without forcing a schema bump).
#[derive(Debug, Deserialize, Serialize)]
struct Vector {
    name: String,
    description: String,
    kind: String,
    inputs: serde_json::Map<String, serde_json::Value>,
    expected_public_key_hex: String,
    expected_key_fingerprint_hex: String,
    expected_signature_hex: String,
}

// -----------------------------------------------------------------------------
// Hex helpers — same shape as the receipt vectors test
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

fn inputs_str(inputs: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    inputs
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("vector inputs missing string key {key:?}"))
        .to_string()
}

// -----------------------------------------------------------------------------
// Per-vector assertion
// -----------------------------------------------------------------------------

/// Process one fixture. Returns Ok(()) on success, Err(msg) on
/// failure (with vector name + diff embedded in the message).
async fn process_vector(path: &Path, regenerate: bool) -> Result<(), String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {path:?}: {e}"))?;
    let mut vector: Vector =
        serde_json::from_str(&raw).map_err(|e| format!("parse {path:?}: {e}"))?;

    if vector.kind != "signer-sign-and-verify" {
        // Defensive: future vector kinds in the same directory should
        // not be processed by this loader.
        return Ok(());
    }

    let seed_hex = inputs_str(&vector.inputs, "seed_hex");
    let message_hex = inputs_str(&vector.inputs, "message_hex");

    let seed_vec = hex_decode(&seed_hex);
    if seed_vec.len() != 32 {
        return Err(format!(
            "[{}] seed must be 32 bytes; got {}",
            vector.name,
            seed_vec.len()
        ));
    }
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed_vec);
    let message = hex_decode(&message_hex);

    // Build via the raw SigningKey path.
    let raw_key = SigningKey::from_bytes(&seed_arr);
    let raw_pubkey = raw_key.public();
    let raw_sig = raw_key.sign_message(&message);

    // Build via the InProcessSigner trait surface.
    let signer = InProcessSigner::from_bytes(&seed_arr);
    let trait_pubkey = Signer::public_key(&signer);
    let trait_sig = signer
        .sign_message(&message)
        .await
        .map_err(|e| format!("[{}] InProcessSigner.sign_message: {e}", vector.name))?;

    // Invariant 1 (RFC 0015 §3.1): wrapper doesn't change the math.
    if raw_pubkey != trait_pubkey {
        return Err(format!(
            "[{}] InProcessSigner.public_key differs from raw SigningKey.public",
            vector.name,
        ));
    }
    if raw_sig.value != trait_sig.value {
        return Err(format!(
            "[{}] InProcessSigner signature bytes differ from raw SigningKey output",
            vector.name,
        ));
    }
    if raw_sig.key_fingerprint != trait_sig.key_fingerprint {
        return Err(format!(
            "[{}] InProcessSigner key_fingerprint differs from raw SigningKey output",
            vector.name,
        ));
    }

    // Invariant 2 (RFC 8032): signature verifies under reported public key.
    verify(&trait_pubkey, &message, &trait_sig)
        .map_err(|e| format!("[{}] verify under reported public_key: {e}", vector.name))?;

    let actual_public_key_hex = hex_encode(&trait_pubkey.value);
    let actual_key_fingerprint_hex = hex_encode(&trait_sig.key_fingerprint);
    let actual_signature_hex = hex_encode(&trait_sig.value);

    if regenerate {
        vector.expected_public_key_hex = actual_public_key_hex;
        vector.expected_key_fingerprint_hex = actual_key_fingerprint_hex;
        vector.expected_signature_hex = actual_signature_hex;
        let updated = serde_json::to_string_pretty(&vector)
            .map_err(|e| format!("[{}] serialize: {e}", vector.name))?;
        let with_newline = format!("{updated}\n");
        fs::write(path, with_newline).map_err(|e| format!("[{}] write: {e}", vector.name))?;
        return Ok(());
    }

    // Invariant 3: matches the committed fixture.
    let mismatches: Vec<String> = [
        (
            "expected_public_key_hex",
            &vector.expected_public_key_hex,
            &actual_public_key_hex,
        ),
        (
            "expected_key_fingerprint_hex",
            &vector.expected_key_fingerprint_hex,
            &actual_key_fingerprint_hex,
        ),
        (
            "expected_signature_hex",
            &vector.expected_signature_hex,
            &actual_signature_hex,
        ),
    ]
    .iter()
    .filter_map(|(field, expected, actual)| {
        if expected == actual {
            None
        } else {
            Some(format!(
                "    {field}:\n      expected: {expected}\n      actual:   {actual}"
            ))
        }
    })
    .collect();

    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "[{}] vector diverged from fixture:\n{}\n  hint: re-run with YUTHA_REGENERATE_VECTORS=1 if this change is intentional",
            vector.name,
            mismatches.join("\n"),
        ))
    }
}

// -----------------------------------------------------------------------------
// Test driver
// -----------------------------------------------------------------------------

/// Locate `/spec/vectors/signer/sign-and-verify/` from this test's
/// working directory. The test runs from the crate root
/// (`/crates/yutha-signer/`), so `../../` hops back to the repo root.
fn vectors_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../spec/vectors/signer/sign-and-verify")
}

fn regenerate_requested() -> bool {
    matches!(
        std::env::var("YUTHA_REGENERATE_VECTORS").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

#[tokio::test]
async fn signer_vectors_match() {
    let dir = vectors_dir();
    let entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"))
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .collect();

    assert!(
        !entries.is_empty(),
        "no signer vectors found in {dir:?} — did the directory get moved?"
    );

    let regenerate = regenerate_requested();
    let mut failures = Vec::new();
    let mut count = 0usize;
    for entry in entries {
        count += 1;
        if let Err(e) = process_vector(&entry.path(), regenerate).await {
            failures.push(e);
        }
    }

    if !failures.is_empty() {
        panic!(
            "{n} signer vector(s) failed:\n\n{joined}",
            n = failures.len(),
            joined = failures.join("\n\n"),
        );
    }

    if regenerate {
        eprintln!(
            "regenerated {count} signer vector(s); review with `git diff spec/vectors/signer/`"
        );
    }
}

//! Sui keystore loading.
//!
//! Parses Sui's canonical `suiprivkey1…` Bech32 encoding into an
//! [`sui_crypto::ed25519::Ed25519PrivateKey`]. Delegates the actual
//! Bech32 + flag-byte handling to
//! [`Ed25519PrivateKey::from_suiprivkey`] from sui-crypto's `bech32`
//! feature so we stay in lockstep with whatever the Sui Rust SDK
//! treats as canonical.
//!
//! ## File format
//!
//! Single-line text file containing a `suiprivkey1…` string. Operators
//! generate via:
//!
//! ```bash
//! sui keytool generate ed25519 --json
//! # The output's `suiPrivateKey` field is what we want; extract it.
//! ```
//!
//! Then write that string to a file with `chmod 600` and point
//! `--anchor-sealer-key-file` at it.

use std::path::Path;

use sui_crypto::ed25519::Ed25519PrivateKey;

use crate::error::{AnchorBackendError, Result};

/// Load an Ed25519 sealer key from a file containing a `suiprivkey1…`
/// canonical Sui keystore string. Strips leading/trailing whitespace
/// (newlines, trailing spaces from text editors).
///
/// File-not-found, malformed Bech32, wrong key-scheme prefix, or
/// truncated keys all map to [`AnchorBackendError::SealerKey`].
pub fn load_sealer_key_from_file<P: AsRef<Path>>(path: P) -> Result<Ed25519PrivateKey> {
    let raw = std::fs::read_to_string(path.as_ref()).map_err(|e| {
        AnchorBackendError::SealerKey(format!("read keystore file {:?}: {e}", path.as_ref()))
    })?;
    parse_suiprivkey(raw.trim())
}

/// Parse a `suiprivkey1…` string into an Ed25519 private key.
///
/// Thin wrapper around [`Ed25519PrivateKey::from_suiprivkey`] that
/// maps `sui_crypto::SignatureError` into our [`AnchorBackendError`]
/// hierarchy. The underlying parser handles HRP validation, Bech32
/// checksum, scheme-flag check, and length check — all the failure
/// modes my earlier hand-rolled parser covered, but tied to whatever
/// is canonical in the upstream SDK.
pub fn parse_suiprivkey(s: &str) -> Result<Ed25519PrivateKey> {
    Ed25519PrivateKey::from_suiprivkey(s)
        .map_err(|e| AnchorBackendError::SealerKey(format!("suiprivkey parse: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a known key through the SDK's encoder + our decoder
    /// to verify the wire-format agreement. Generates a fixed
    /// keypair, encodes it as `suiprivkey…`, then re-decodes — the
    /// resulting private key MUST equal the original.
    #[test]
    fn round_trips_through_sdk_encoder() {
        let original = Ed25519PrivateKey::new([0x01u8; 32]);
        let encoded = original
            .to_suiprivkey()
            .expect("to_suiprivkey should succeed for a valid Ed25519 key");
        let decoded = parse_suiprivkey(&encoded).expect("parse_suiprivkey should round-trip");
        assert_eq!(original, decoded);
    }

    #[test]
    fn rejects_garbage() {
        let err = parse_suiprivkey("not a bech32 string").unwrap_err();
        match err {
            AnchorBackendError::SealerKey(msg) => assert!(msg.contains("suiprivkey parse:")),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn load_from_file_strips_trailing_newline() {
        // The Sui CLI writes the key followed by a newline; our reader
        // must tolerate that.
        use std::io::Write;
        let original = Ed25519PrivateKey::new([0x02u8; 32]);
        let encoded = original.to_suiprivkey().unwrap();

        let tmp =
            std::env::temp_dir().join(format!("yutha-anchor-sui-test-{}.key", std::process::id()));
        {
            let mut f = std::fs::File::create(&tmp).unwrap();
            writeln!(f, "{encoded}").unwrap();
        }

        let loaded = load_sealer_key_from_file(&tmp).expect("load_sealer_key_from_file");
        assert_eq!(loaded, original);

        std::fs::remove_file(&tmp).ok();
    }
}

//! Receipt verification helpers.
//!
//! Two checks make a receipt valid:
//!
//! 1. **Content-address check.** Re-canonicalize the receipt and compare its
//!    SHA-256 to the claimed `receipt_id`. Any mismatch is structural tamper
//!    detection.
//! 2. **Signature check.** The actor signature MUST verify against the
//!    `actor`'s public key (resolved out of band; passport store). Optional
//!    role signatures (control plane, supervisor, attestation) are verified
//!    if present, in canonical wire order.

use crate::error::{ReceiptError, Result};
use crate::receipt::Receipt;
use crate::signing::{SignatureRole, SignedBy};
use yutha_core::PublicKey;
use yutha_crypto::canonical::{content_address, verify_content_address};

/// Outcome of receipt verification.
#[derive(Debug, Clone)]
pub struct VerificationOutcome {
    /// The recomputed content-address of the receipt.
    pub content_address: yutha_core::Hash,
    /// The signature roles whose signatures were verified.
    pub verified_roles: Vec<SignatureRole>,
}

/// Verify a receipt's signatures.
///
/// `actor_public_key` is the actor's verifying key (resolved from the
/// passport store by the caller). `additional_keys` is a callback that maps
/// `(role, key_fingerprint)` to the verifying key for non-actor signatures —
/// callers may return `None` to skip optional roles, or return an error to
/// reject.
///
/// This function does NOT check the content-address against any externally
/// claimed value; it computes and returns the recomputed address. The caller
/// (typically the receipt store on append) is responsible for comparing the
/// returned address against any claimed receipt_id.
pub fn verify_receipt_signatures<F>(
    receipt: &Receipt,
    actor_public_key: &PublicKey,
    mut additional_keys: F,
) -> Result<VerificationOutcome>
where
    F: FnMut(SignatureRole, &[u8]) -> Option<PublicKey>,
{
    // Canonicalize once — every signature verifies against the same bytes.
    let canonical = content_address(receipt).map_err(ReceiptError::Crypto)?;
    let canonical_bytes = canonical.digest.clone(); // hash bytes used as message? No — see below.

    // The message-being-signed is the canonical-bytes themselves, NOT the
    // hash. We re-derive the canonical bytes for verification.
    let message_bytes = {
        use yutha_crypto::canonical::Canonical;
        receipt.canonical_bytes().map_err(ReceiptError::Crypto)?
    };
    let _ = canonical_bytes; // silence unused-binding lint without affecting semantics

    // Order check.
    enforce_canonical_order(&receipt.signatures)?;

    // Actor signature is required.
    let actor_sig = receipt
        .signatures
        .iter()
        .find(|s| s.role == SignatureRole::Actor)
        .ok_or(ReceiptError::MissingSignatureRole {
            role: SignatureRole::Actor,
        })?;

    let mut verified = Vec::new();

    yutha_crypto::sign::verify(actor_public_key, &message_bytes, &actor_sig.signature).map_err(
        |e| ReceiptError::SignatureFailed {
            detail: format!("actor: {e}"),
        },
    )?;
    verified.push(SignatureRole::Actor);

    // Verify any present optional roles.
    for sig in receipt
        .signatures
        .iter()
        .filter(|s| s.role != SignatureRole::Actor)
    {
        if let Some(pk) = additional_keys(sig.role, &sig.signature.key_fingerprint) {
            yutha_crypto::sign::verify(&pk, &message_bytes, &sig.signature).map_err(|e| {
                ReceiptError::SignatureFailed {
                    detail: format!("{:?}: {e}", sig.role),
                }
            })?;
            verified.push(sig.role);
        }
        // Roles whose key the caller declines to supply are skipped (caller
        // policy decides whether that's OK; conformance suite may enforce
        // stricter rules per tier).
    }

    Ok(VerificationOutcome {
        content_address: canonical,
        verified_roles: verified,
    })
}

/// Confirm signatures appear in canonical wire order:
/// Actor → ControlPlane → Supervisor → Attestation → BatchRoot.
fn enforce_canonical_order(sigs: &[SignedBy]) -> Result<()> {
    let mut last = None;
    for s in sigs {
        if let Some(prev) = last {
            if s.role.rank() < prev {
                return Err(ReceiptError::SignatureOrderInvalid {
                    detail: format!(
                        "{:?} (rank {}) appears after rank {}",
                        s.role,
                        s.role.rank(),
                        prev
                    ),
                });
            }
        }
        last = Some(s.role.rank());
    }
    Ok(())
}

/// Re-validate a claimed content-address against a receipt's recomputed hash.
/// Returns Ok if they match, [`ReceiptError::ContentAddressMismatch`]
/// otherwise. Wraps [`yutha_crypto::canonical::verify_content_address`] with
/// a typed error.
pub fn verify_address(receipt: &Receipt, claimed: &yutha_core::Hash) -> Result<()> {
    verify_content_address(receipt, claimed).map_err(|e| match e {
        yutha_crypto::CryptoError::VerificationFailed => {
            // Recompute to surface the mismatch detail.
            let recomputed = content_address(receipt).expect("content_address infallible here");
            ReceiptError::ContentAddressMismatch {
                claimed: claimed.clone(),
                recomputed,
            }
        }
        other => ReceiptError::Crypto(other),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Evidence;
    use yutha_core::{AgentId, CausalRef, SpecVersion, SwarmId, Timestamp};
    use yutha_crypto::sign::generate_keypair;

    fn signed_fixture() -> (Receipt, PublicKey) {
        let key = generate_keypair();
        let pk = key.public();

        let mut r = Receipt::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(SwarmId::new())
            .actor(AgentId::new())
            .action_kind("envelope.send")
            .constitution_version("1.0.0")
            .occurred_at(Timestamp::now())
            .causal(CausalRef::empty())
            .evidence(Evidence::new(
                "k",
                "type.yutha.dev/v1/Bytes",
                b"hello".to_vec(),
            ))
            .build()
            .unwrap();

        // Sign over canonical bytes.
        use yutha_crypto::canonical::Canonical;
        let canonical_bytes = r.canonical_bytes().unwrap();
        let sig = key.sign_message(&canonical_bytes);
        r.signatures
            .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

        (r, pk)
    }

    #[test]
    fn verify_passes_on_well_signed_receipt() {
        let (r, pk) = signed_fixture();
        let outcome = verify_receipt_signatures(&r, &pk, |_, _| None).unwrap();
        assert!(outcome.verified_roles.contains(&SignatureRole::Actor));
    }

    #[test]
    fn verify_fails_on_missing_actor_signature() {
        let (mut r, pk) = signed_fixture();
        r.signatures.clear();
        assert!(matches!(
            verify_receipt_signatures(&r, &pk, |_, _| None),
            Err(ReceiptError::MissingSignatureRole {
                role: SignatureRole::Actor
            })
        ));
    }

    #[test]
    fn verify_fails_on_tampered_action_kind() {
        let (mut r, pk) = signed_fixture();
        r.action_kind = "tampered".into();
        let result = verify_receipt_signatures(&r, &pk, |_, _| None);
        assert!(matches!(result, Err(ReceiptError::SignatureFailed { .. })));
    }

    #[test]
    fn verify_fails_on_out_of_order_signatures() {
        let (mut r, pk) = signed_fixture();
        // Inject a Supervisor signature before the Actor signature.
        let key = generate_keypair();
        let canonical_bytes = {
            use yutha_crypto::canonical::Canonical;
            r.canonical_bytes().unwrap()
        };
        let sig = key.sign_message(&canonical_bytes);
        let supervisor = SignedBy::new(SignatureRole::Supervisor, sig, Timestamp::now());
        r.signatures.insert(0, supervisor);
        let result = verify_receipt_signatures(&r, &pk, |_, _| None);
        assert!(matches!(
            result,
            Err(ReceiptError::SignatureOrderInvalid { .. })
        ));
    }
}

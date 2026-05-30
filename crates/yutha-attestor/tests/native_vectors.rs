//! Conformance vectors for [`NativeAttestor`] per
//! [RFC 0016 §3.8](../../../spec/rfcs/0016-attestor-interface.md#38-conformance-contract)
//! and [`/spec/vectors/attestor/README.md`](../../../spec/vectors/attestor/README.md).
//!
//! Three contracts, exercised against the canonical 16 / 8 / 8 case
//! shape pinned in the RFC:
//!
//! 1. **accept-empty**: `NativeAttestor.verify(ctx, &[])` returns `Ok`
//!    with `external_identity == "yutha:native:<agent_id_hex>"`,
//!    `credential_expires_at == None`, empty `attributes`.
//! 2. **reject-nonempty**: `NativeAttestor.verify(ctx, &[any non-empty])`
//!    returns `Err(AttestorError::Rejected(_))`.
//! 3. **context-passthrough**: the `claimed_agent_id` from the context
//!    flows unchanged into `external_identity`; `agent_public_key`
//!    and `swarm_id` are not silently mutated by the call.
//!
//! These cases ARE the v1 attestor conformance spec — Phase E / F's
//! SPIFFE + OIDC Attestors will additionally ship JSON-fixture
//! vectors under `/spec/vectors/attestor/{spiffe,oidc}/`.

use yutha_attestor::{AttestationContext, Attestor, AttestorError, NativeAttestor};
use yutha_core::{AgentId, PublicKey, SignatureAlgorithm, SwarmId};

// ---------------------------------------------------------------------------
// Case-shape helpers
// ---------------------------------------------------------------------------

fn agent_from_bytes(seed: [u8; 16]) -> AgentId {
    AgentId::from_bytes(&seed).expect("16 bytes is the AgentId length")
}

fn public_key_from(byte: u8) -> PublicKey {
    PublicKey::new(SignatureAlgorithm::Ed25519, vec![byte; 32]).unwrap()
}

fn ctx_from(agent_seed: [u8; 16], pk_byte: u8) -> AttestationContext {
    AttestationContext {
        swarm_id: SwarmId::new(),
        claimed_agent_id: agent_from_bytes(agent_seed),
        agent_public_key: public_key_from(pk_byte),
    }
}

/// The 16 accept-empty agent-id shapes. Boundary + deterministic.
fn accept_empty_cases() -> Vec<(&'static str, [u8; 16])> {
    vec![
        ("all_zero", [0u8; 16]),
        ("all_ff", [0xFFu8; 16]),
        (
            "ascending",
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        ),
        (
            "descending",
            [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
        ),
        (
            "alternating_55_aa",
            [
                0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA,
                0x55, 0xAA,
            ],
        ),
        (
            "alternating_aa_55",
            [
                0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55,
                0xAA, 0x55,
            ],
        ),
        (
            "one_high_bit",
            [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        (
            "one_low_bit",
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        ),
        (
            "uuid_v7_like_a",
            [
                0x01, 0x8F, 0x3A, 0x4B, 0x5C, 0x6D, 0x70, 0x12, 0x80, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5,
                0xF6, 0x07,
            ],
        ),
        (
            "uuid_v7_like_b",
            [
                0x01, 0x8F, 0x3A, 0x4B, 0x5C, 0x6D, 0x70, 0x34, 0x80, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5,
                0xF6, 0x08,
            ],
        ),
        (
            "uuid_v7_like_c",
            [
                0x01, 0x8F, 0x3A, 0x4B, 0x5C, 0x6D, 0x70, 0x56, 0x80, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5,
                0xF6, 0x09,
            ],
        ),
        (
            "uuid_v7_like_d",
            [
                0x01, 0x8F, 0x3A, 0x4B, 0x5C, 0x6D, 0x70, 0x78, 0x80, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5,
                0xF6, 0x0A,
            ],
        ),
        (
            "uuid_v7_like_e",
            [
                0x01, 0x8F, 0x3A, 0x4B, 0x5C, 0x6D, 0x70, 0x9A, 0x80, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5,
                0xF6, 0x0B,
            ],
        ),
        (
            "uuid_v7_like_f",
            [
                0x01, 0x8F, 0x3A, 0x4B, 0x5C, 0x6D, 0x70, 0xBC, 0x80, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5,
                0xF6, 0x0C,
            ],
        ),
        (
            "uuid_v7_like_g",
            [
                0x01, 0x8F, 0x3A, 0x4B, 0x5C, 0x6D, 0x70, 0xDE, 0x80, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5,
                0xF6, 0x0D,
            ],
        ),
        (
            "uuid_v7_like_h",
            [
                0x01, 0x8F, 0x3A, 0x4B, 0x5C, 0x6D, 0x70, 0xF0, 0x80, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5,
                0xF6, 0x0E,
            ],
        ),
    ]
}

/// The 8 reject-nonempty credential shapes.
fn reject_nonempty_cases() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("one_zero_byte", vec![0u8]),
        ("one_high_byte", vec![0xFFu8]),
        ("thirty_two_zeros", vec![0u8; 32]),
        ("thirty_two_high", vec![0xFFu8; 32]),
        ("sixty_four_bytes", (0u8..64).collect()),
        ("two_fifty_six_bytes", (0u8..=255).collect()),
        ("kib_zeros", vec![0u8; 1024]),
        ("kib_pattern", (0..1024).map(|i| (i % 256) as u8).collect()),
    ]
}

/// The 8 context-passthrough cases. Vary agent_id + public_key + swarm,
/// then verify the result encodes the *claimed_agent_id* and not some
/// other field.
fn context_passthrough_cases() -> Vec<(&'static str, [u8; 16], u8)> {
    vec![
        ("zero_zero", [0u8; 16], 0u8),
        ("zero_high", [0u8; 16], 0xFFu8),
        ("high_zero", [0xFFu8; 16], 0u8),
        ("high_high", [0xFFu8; 16], 0xFFu8),
        (
            "ascending_zero",
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            0u8,
        ),
        (
            "ascending_42",
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            0x42u8,
        ),
        (
            "uuid_v7_like_x",
            [
                0x01, 0x8F, 0x3A, 0x4B, 0x5C, 0x6D, 0x70, 0x12, 0x80, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5,
                0xF6, 0xAA,
            ],
            0x7Fu8,
        ),
        (
            "uuid_v7_like_y",
            [
                0x01, 0x8F, 0x3A, 0x4B, 0x5C, 0x6D, 0x70, 0x34, 0x80, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5,
                0xF6, 0xBB,
            ],
            0x80u8,
        ),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Contract 1: NativeAttestor accepts the empty credential and emits
/// the canonical `yutha:native:<hex>` identity. 16 cases per RFC 0016
/// §3.8.
#[tokio::test]
async fn native_accept_empty_16_cases() {
    let attestor = NativeAttestor;
    for (name, seed) in accept_empty_cases() {
        let ctx = ctx_from(seed, 0x00);
        let identity = attestor
            .verify(&ctx, &[])
            .await
            .unwrap_or_else(|e| panic!("case `{name}` rejected: {e}"));

        let expected_id = format!("yutha:native:{}", hex::encode(seed));
        assert_eq!(
            identity.external_identity, expected_id,
            "case `{name}`: external_identity must be yutha:native:<hex(agent_id)>"
        );
        assert!(
            identity.credential_expires_at.is_none(),
            "case `{name}`: native has no external credential, expiry must be None"
        );
        assert!(
            identity.attributes.is_empty(),
            "case `{name}`: native emits no attributes"
        );
    }
    assert_eq!(attestor.id(), "native");
}

/// Contract 2: NativeAttestor rejects any non-empty credential. 8
/// cases per RFC 0016 §3.8.
#[tokio::test]
async fn native_reject_nonempty_8_cases() {
    let attestor = NativeAttestor;
    let ctx = ctx_from([0u8; 16], 0x00);

    for (name, credential) in reject_nonempty_cases() {
        let err = attestor
            .verify(&ctx, &credential)
            .await
            .expect_err(&format!("case `{name}` should have rejected"));

        match err {
            AttestorError::Rejected(msg) => {
                assert!(
                    msg.contains("NativeAttestor"),
                    "case `{name}`: error must mention NativeAttestor for operator clarity; got: {msg}"
                );
            }
            other => panic!("case `{name}`: expected Rejected, got {other:?}"),
        }
    }
}

/// Contract 3: AttestationContext fields flow unchanged through the
/// call. 8 cases per RFC 0016 §3.8.
#[tokio::test]
async fn native_context_passthrough_8_cases() {
    let attestor = NativeAttestor;
    for (name, agent_seed, pk_byte) in context_passthrough_cases() {
        let agent_id = agent_from_bytes(agent_seed);
        let pk = public_key_from(pk_byte);
        let swarm_id = SwarmId::new();
        let ctx = AttestationContext {
            swarm_id,
            claimed_agent_id: agent_id,
            agent_public_key: pk.clone(),
        };

        let identity = attestor.verify(&ctx, &[]).await.unwrap();

        // The external_identity encodes claimed_agent_id, NOT
        // public_key or swarm_id. This is the load-bearing assertion
        // for context-passthrough: NativeAttestor MUST NOT silently
        // swap fields.
        let expected_id = format!("yutha:native:{}", hex::encode(agent_seed));
        assert_eq!(
            identity.external_identity, expected_id,
            "case `{name}`: external_identity must encode claimed_agent_id"
        );

        // Pseudo-mutation check: pass a DIFFERENT context and confirm
        // we get a DIFFERENT identity. Catches an implementation that
        // ignores the context entirely.
        let other_seed = [0xEE; 16];
        let other_ctx = AttestationContext {
            swarm_id,
            claimed_agent_id: agent_from_bytes(other_seed),
            agent_public_key: pk,
        };
        let other_identity = attestor.verify(&other_ctx, &[]).await.unwrap();
        assert_ne!(
            identity.external_identity, other_identity.external_identity,
            "case `{name}`: distinct claimed_agent_ids must produce distinct external_identities"
        );
    }
}

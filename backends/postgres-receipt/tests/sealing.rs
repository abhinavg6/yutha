//! SealStore conformance against the Postgres receipt store.
//!
//! Skipped by default; runs when `YUTHA_PG_TEST_URL` is set. Same per-run
//! schema isolation pattern as `conformance.rs`: a UUID-suffixed schema
//! pinned via the libpq `options` parameter, with `TRUNCATE ... CASCADE`
//! between tests.
//!
//! Exercises the H3 surface end-to-end: append receipts, run them through
//! `LocalSealer`, record the resulting batch in Postgres, query the seal
//! status back, and verify the merkle path against the stored root.

use sqlx::postgres::PgPoolOptions;
use sqlx::Executor;
use std::sync::Arc;
use uuid::Uuid;
use yutha_backend_postgres_receipt::PostgresStore;
use yutha_core::{AgentId, CausalRef, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_crypto::sign::generate_keypair;
use yutha_receipt::{
    AppendOptions, Evidence, LocalSealer, Receipt, ReceiptStore, SealState, SealStore, Sealer,
    SignatureRole, SignedBy, StaticPassportResolver,
};

fn pg_url_or_skip(test_name: &str) -> Option<String> {
    match std::env::var("YUTHA_PG_TEST_URL") {
        Ok(s) if !s.is_empty() => Some(s),
        _ => {
            eprintln!("[{test_name}] YUTHA_PG_TEST_URL not set; skipping postgres sealing run");
            None
        }
    }
}

fn url_with_search_path(base: &str, schema: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    let opt = format!("-c%20search_path%3D{schema}");
    format!("{base}{separator}options={opt}")
}

/// Build + sign a fresh receipt under a randomly-generated keypair.
/// Returns (signed receipt, resolver for that actor).
fn signed_fixture(action: &str) -> (Receipt, StaticPassportResolver) {
    let key = generate_keypair();
    let actor = AgentId::new();
    let mut r = Receipt::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .swarm_id(SwarmId::new())
        .actor(actor)
        .action_kind(action)
        .constitution_version("1.0.0")
        .occurred_at(Timestamp::now())
        .causal(CausalRef::default())
        .evidence(Evidence::new("k", "type.yutha.dev/v1/Bytes", b"v".to_vec()))
        .build()
        .unwrap();
    let bytes = r.canonical_bytes().unwrap();
    let sig = key.sign_message(&bytes);
    r.signatures
        .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));
    let resolver = StaticPassportResolver::new().with_actor(actor, key.public());
    (r, resolver)
}

/// Per-test reset: clear all domain tables. Conformance.rs uses the same
/// pattern; duplicated here to keep the sealing tests self-contained.
async fn truncate_all(pool: &sqlx::PgPool) {
    pool.execute(
        "TRUNCATE TABLE receipts, receipt_predecessors, receipt_signatures, \
         receipt_evidence, receipt_cost, receipt_seal CASCADE",
    )
    .await
    .expect("TRUNCATE between tests");
}

#[tokio::test]
async fn postgres_seals_a_batch_and_round_trips_status() {
    let Some(url) = pg_url_or_skip("postgres_seals_a_batch_and_round_trips_status") else {
        return;
    };

    let schema = format!("yutha_seal_{}", Uuid::now_v7().simple());
    let bootstrap_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect (bootstrap)");
    bootstrap_pool
        .execute(format!("CREATE SCHEMA IF NOT EXISTS {schema}").as_str())
        .await
        .expect("CREATE SCHEMA");
    bootstrap_pool.close().await;

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url_with_search_path(&url, &schema))
        .await
        .expect("connect (pinned schema)");

    let store = Arc::new(PostgresStore::new(pool.clone()));
    store.migrate().await.expect("migrate");

    truncate_all(&pool).await;

    // Append three receipts; collect their receipt objects for sealing.
    let mut receipts = Vec::new();
    let mut ids = Vec::new();
    for action in ["envelope.send", "envelope.deliver", "envelope.send"] {
        let (receipt, resolver) = signed_fixture(action);
        let receipt_clone = receipt.clone();
        let out = store
            .append(receipt, AppendOptions::default(), &resolver)
            .await
            .expect("append");
        receipts.push(receipt_clone);
        ids.push(out.receipt_id);
    }

    // Seal locally — no on-chain anchor.
    let batch = LocalSealer::new()
        .seal_batch(&receipts)
        .await
        .expect("seal_batch");

    // Record the seal in Postgres.
    store
        .record_sealed_batch(&batch)
        .await
        .expect("record_sealed_batch");

    // Round-trip every receipt's status.
    for id in &ids {
        let status = store.seal_status(id).await.expect("seal_status");
        assert_eq!(
            status.state,
            SealState::Sealed,
            "receipt {:02x?} should be sealed",
            &id.digest[..8]
        );
        assert_eq!(status.batch_root.as_ref(), Some(&batch.batch_root));
        assert!(
            status.on_chain_tx_digest.is_none(),
            "LocalSealer must not stamp an on-chain anchor"
        );
        // Merkle path lets a verifier reconstruct the root.
        assert!(
            yutha_receipt::verify_path(id, &status.merkle_path, &batch.batch_root),
            "merkle path must verify against the stored batch_root"
        );
    }
}

#[tokio::test]
async fn postgres_seal_with_anchor_persists_tx_digest() {
    let Some(url) = pg_url_or_skip("postgres_seal_with_anchor_persists_tx_digest") else {
        return;
    };

    let schema = format!("yutha_seal_{}", Uuid::now_v7().simple());
    let bootstrap_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect (bootstrap)");
    bootstrap_pool
        .execute(format!("CREATE SCHEMA IF NOT EXISTS {schema}").as_str())
        .await
        .expect("CREATE SCHEMA");
    bootstrap_pool.close().await;

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url_with_search_path(&url, &schema))
        .await
        .expect("connect (pinned schema)");

    let store = Arc::new(PostgresStore::new(pool.clone()));
    store.migrate().await.expect("migrate");
    truncate_all(&pool).await;

    // Append + seal as in the LocalSealer test.
    let mut receipts = Vec::new();
    let mut ids = Vec::new();
    for action in ["envelope.send", "envelope.deliver"] {
        let (receipt, resolver) = signed_fixture(action);
        let receipt_clone = receipt.clone();
        let out = store
            .append(receipt, AppendOptions::default(), &resolver)
            .await
            .expect("append");
        receipts.push(receipt_clone);
        ids.push(out.receipt_id);
    }

    let mut batch = LocalSealer::new()
        .seal_batch(&receipts)
        .await
        .expect("seal_batch");
    // Simulate a SuiSealer commitment — stamp a 32-byte tx digest.
    let fake_tx_digest = vec![0xCDu8; 32];
    batch.commitment_id = fake_tx_digest.clone();

    store
        .record_sealed_batch(&batch)
        .await
        .expect("record_sealed_batch with anchor");

    for id in &ids {
        let status = store.seal_status(id).await.expect("seal_status");
        assert_eq!(
            status.on_chain_tx_digest.as_deref(),
            Some(fake_tx_digest.as_slice()),
            "on-chain tx digest must survive the round trip"
        );
    }
}

#[tokio::test]
async fn postgres_seal_is_idempotent_with_same_root() {
    let Some(url) = pg_url_or_skip("postgres_seal_is_idempotent_with_same_root") else {
        return;
    };

    let schema = format!("yutha_seal_{}", Uuid::now_v7().simple());
    let bootstrap_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect (bootstrap)");
    bootstrap_pool
        .execute(format!("CREATE SCHEMA IF NOT EXISTS {schema}").as_str())
        .await
        .expect("CREATE SCHEMA");
    bootstrap_pool.close().await;

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url_with_search_path(&url, &schema))
        .await
        .expect("connect (pinned schema)");

    let store = Arc::new(PostgresStore::new(pool.clone()));
    store.migrate().await.expect("migrate");
    truncate_all(&pool).await;

    let mut receipts = Vec::new();
    for _ in 0..2 {
        let (receipt, resolver) = signed_fixture("envelope.send");
        let receipt_clone = receipt.clone();
        store
            .append(receipt, AppendOptions::default(), &resolver)
            .await
            .expect("append");
        receipts.push(receipt_clone);
    }

    let batch = LocalSealer::new().seal_batch(&receipts).await.unwrap();
    store.record_sealed_batch(&batch).await.expect("first seal");
    // Re-seal with the same batch_root — must be a no-op, not an error.
    store
        .record_sealed_batch(&batch)
        .await
        .expect("idempotent re-seal");
}

#[tokio::test]
async fn postgres_seal_rejects_conflicting_root() {
    let Some(url) = pg_url_or_skip("postgres_seal_rejects_conflicting_root") else {
        return;
    };

    let schema = format!("yutha_seal_{}", Uuid::now_v7().simple());
    let bootstrap_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect (bootstrap)");
    bootstrap_pool
        .execute(format!("CREATE SCHEMA IF NOT EXISTS {schema}").as_str())
        .await
        .expect("CREATE SCHEMA");
    bootstrap_pool.close().await;

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url_with_search_path(&url, &schema))
        .await
        .expect("connect (pinned schema)");

    let store = Arc::new(PostgresStore::new(pool.clone()));
    store.migrate().await.expect("migrate");
    truncate_all(&pool).await;

    let mut receipts = Vec::new();
    for _ in 0..2 {
        let (receipt, resolver) = signed_fixture("envelope.send");
        let receipt_clone = receipt.clone();
        store
            .append(receipt, AppendOptions::default(), &resolver)
            .await
            .expect("append");
        receipts.push(receipt_clone);
    }

    let batch1 = LocalSealer::new().seal_batch(&receipts).await.unwrap();
    store
        .record_sealed_batch(&batch1)
        .await
        .expect("first seal");

    // Fabricate a conflicting batch — same leaves, different root.
    let mut batch2 = batch1.clone();
    batch2.batch_root =
        yutha_core::Hash::new(yutha_core::HashAlgorithm::Sha256, vec![0xFFu8; 32]).unwrap();

    let err = store
        .record_sealed_batch(&batch2)
        .await
        .expect_err("conflicting root must error");
    assert!(
        err.to_string().contains("different batch"),
        "expected BatchInvalid(different batch), got {err}"
    );
}

#[tokio::test]
async fn postgres_seal_status_unsealed_for_unknown_receipt() {
    let Some(url) = pg_url_or_skip("postgres_seal_status_unsealed_for_unknown_receipt") else {
        return;
    };

    let schema = format!("yutha_seal_{}", Uuid::now_v7().simple());
    let bootstrap_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect (bootstrap)");
    bootstrap_pool
        .execute(format!("CREATE SCHEMA IF NOT EXISTS {schema}").as_str())
        .await
        .expect("CREATE SCHEMA");
    bootstrap_pool.close().await;

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url_with_search_path(&url, &schema))
        .await
        .expect("connect (pinned schema)");

    let store = Arc::new(PostgresStore::new(pool.clone()));
    store.migrate().await.expect("migrate");
    truncate_all(&pool).await;

    // Any 32-byte SHA-256 hash with no underlying receipt → unsealed.
    let fake = yutha_crypto::sha256(b"not a real receipt");
    let status = store.seal_status(&fake).await.expect("seal_status");
    assert_eq!(status.state, SealState::Unsealed);
    assert!(status.batch_root.is_none());
}

//! Integration tests for [`PostgresReplayStore`] (Phase 3c follow-on,
//! RFC 0018 §4).
//!
//! Skipped by default; runs when `YUTHA_PG_TEST_URL` is set. Per-run
//! schema isolation via `?options=-c%20search_path=<schema>` mirrors
//! the production-receipts conformance test setup.
//!
//! Coverage:
//!
//! - Session lifecycle: create → list → get → touch → delete.
//! - Duplicate `create_session` errors.
//! - Per-session append + get round-trip.
//! - Cross-session isolation: A's receipts invisible to B; production
//!   `receipts` query unaffected by replay writes.
//! - Counter accumulation via `touch_session`.

use sqlx::postgres::PgPoolOptions;
use sqlx::Executor;
use uuid::Uuid;
use yutha_backend_postgres_receipt::{PostgresReplayStore, PostgresStore};
use yutha_core::{AgentId, Hash, HashAlgorithm, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_crypto::sign::generate_keypair;
use yutha_receipt::{
    AppendOptions, Evidence, ReceiptBuilder, ReceiptStore, ReplayMode, ReplaySessionId,
    ReplaySessionMetadata, ReplaySessionWindow, ReplayStore, SignatureRole, SignedBy,
    StaticPassportResolver,
};

fn pg_url_or_skip(test_name: &str) -> Option<String> {
    match std::env::var("YUTHA_PG_TEST_URL") {
        Ok(s) if !s.is_empty() => Some(s),
        _ => {
            eprintln!("[{test_name}] YUTHA_PG_TEST_URL not set; skipping postgres replay test");
            None
        }
    }
}

fn url_with_search_path(base: &str, schema: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    let opt = format!("-c%20search_path%3D{schema}");
    format!("{base}{separator}options={opt}")
}

async fn fresh_pool(test_name: &str) -> Option<(sqlx::PgPool, String)> {
    let url = pg_url_or_skip(test_name)?;
    let schema = format!("yutha_test_{}", Uuid::now_v7().simple());

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
        .max_connections(8)
        .connect(&url_with_search_path(&url, &schema))
        .await
        .expect("connect (pinned schema)");

    let store = PostgresStore::new(pool.clone());
    store.migrate().await.expect("migrate");

    Some((pool, schema))
}

async fn drop_schema(pool: &sqlx::PgPool, schema: &str) {
    let _ = pool
        .execute(format!("DROP SCHEMA IF EXISTS {schema} CASCADE").as_str())
        .await;
    pool.close().await;
}

fn fresh_metadata() -> ReplaySessionMetadata {
    ReplaySessionMetadata {
        session_id: ReplaySessionId::new(),
        candidate_constitution_hash: Hash::new(HashAlgorithm::Sha256, vec![0xC0u8; 32]).unwrap(),
        candidate_constitution_version: "1.1.0-rc".into(),
        window: ReplaySessionWindow {
            from_unix_ns: 1_000,
            to_unix_ns: 10_000,
            action_kind_filter: vec!["envelope.send".into()],
        },
        mode: ReplayMode::Cold,
        warm_lookback_hours: 0,
        created_at: Timestamp::now(),
        last_active_at: Timestamp::now(),
        receipts_replayed: 0,
    }
}

async fn signed_receipt(
    actor: AgentId,
    swarm_id: SwarmId,
) -> (yutha_receipt::Receipt, AgentId, yutha_core::PublicKey) {
    let key = generate_keypair();
    let mut r = ReceiptBuilder::new()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .swarm_id(swarm_id)
        .actor(actor)
        .action_kind("envelope.send")
        .evidence(Evidence::new("k", "type.yutha.dev/v1/Bytes", vec![1]))
        .constitution_version("1.0.0")
        .occurred_at(Timestamp::now())
        .build()
        .unwrap();
    let bytes = r.canonical_bytes().unwrap();
    let sig = key.sign_message(&bytes);
    r.signatures
        .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));
    (r, actor, key.public())
}

#[tokio::test]
async fn postgres_replay_session_lifecycle() {
    let Some((pool, schema)) = fresh_pool("postgres_replay_session_lifecycle").await else {
        return;
    };

    let store = PostgresReplayStore::new(pool.clone());

    let meta = fresh_metadata();
    let id = meta.session_id;
    store
        .create_session(meta.clone())
        .await
        .expect("create_session");

    let listed = store.list_sessions().await.expect("list_sessions");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].session_id, id);
    assert_eq!(
        listed[0].candidate_constitution_version,
        meta.candidate_constitution_version
    );

    let got = store
        .get_session(&id)
        .await
        .expect("get_session")
        .expect("session present");
    assert_eq!(got.session_id, id);
    assert_eq!(got.receipts_replayed, 0);
    assert_eq!(got.mode, ReplayMode::Cold);
    assert_eq!(got.window.action_kind_filter, vec!["envelope.send"]);

    // Touch updates counters monotonically.
    let now1 = Timestamp::now();
    store.touch_session(&id, 5, &now1).await.expect("touch 1");
    let now2 = Timestamp::now();
    store.touch_session(&id, 3, &now2).await.expect("touch 2");
    let touched = store.get_session(&id).await.unwrap().unwrap();
    assert_eq!(touched.receipts_replayed, 8);
    assert_eq!(touched.last_active_at, now2);

    // Duplicate create errors.
    let mut second = meta;
    second.session_id = id;
    let err = store.create_session(second).await.unwrap_err();
    assert!(matches!(err, yutha_receipt::ReceiptError::Backend(_)));

    // Delete drops everything; subsequent get returns None; idempotent.
    store.delete_session(&id).await.expect("delete");
    assert!(store.get_session(&id).await.unwrap().is_none());
    store.delete_session(&id).await.expect("delete idempotent");
    assert!(store.list_sessions().await.unwrap().is_empty());

    drop_schema(&pool, &schema).await;
}

#[tokio::test]
async fn postgres_replay_session_store_isolates_appends() {
    let Some((pool, schema)) = fresh_pool("postgres_replay_session_store_isolates_appends").await
    else {
        return;
    };

    let production = PostgresStore::new(pool.clone());
    let replay = PostgresReplayStore::new(pool.clone());

    // Two sessions.
    let a_meta = fresh_metadata();
    let b_meta = fresh_metadata();
    let a_id = a_meta.session_id;
    let b_id = b_meta.session_id;
    replay.create_session(a_meta).await.unwrap();
    replay.create_session(b_meta).await.unwrap();

    let a_store = replay.session_store(&a_id);
    let b_store = replay.session_store(&b_id);

    let swarm_id = SwarmId::new();
    let actor = AgentId::new();
    let (receipt, _, pk) = signed_receipt(actor, swarm_id).await;
    let resolver = StaticPassportResolver::new().with_actor(actor, pk);

    // Append to A only.
    let outcome = a_store
        .append(receipt.clone(), AppendOptions::default(), &resolver)
        .await
        .expect("append into A");

    // A sees the receipt; B does not.
    assert!(a_store.get(&outcome.receipt_id).await.unwrap().is_some());
    assert!(
        b_store.get(&outcome.receipt_id).await.unwrap().is_none(),
        "RFC 0018 §4.1 cross-session isolation: B MUST NOT see A's receipts"
    );
    assert_eq!(a_store.count().await.unwrap(), 1);
    assert_eq!(b_store.count().await.unwrap(), 0);

    // The production store sees zero receipts — replay writes never
    // touch the `receipts` table.
    assert_eq!(
        production.count().await.unwrap(),
        0,
        "RFC 0018 §4.1 production isolation: production store MUST stay empty across replay writes"
    );

    // Round-trip through query() too: ByActionKind against A returns
    // the receipt, against B returns nothing.
    let a_page = a_store
        .query(
            yutha_receipt::Query::ByActionKind(yutha_receipt::ActionKindQuery {
                action_kind: "envelope.send".into(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(a_page.receipts.len(), 1);
    let b_page = b_store
        .query(
            yutha_receipt::Query::ByActionKind(yutha_receipt::ActionKindQuery {
                action_kind: "envelope.send".into(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(b_page.receipts.len(), 0);

    drop_schema(&pool, &schema).await;
}

#[tokio::test]
async fn postgres_replay_delete_session_cascades_receipts() {
    let Some((pool, schema)) = fresh_pool("postgres_replay_delete_session_cascades_receipts").await
    else {
        return;
    };

    let replay = PostgresReplayStore::new(pool.clone());

    let meta = fresh_metadata();
    let id = meta.session_id;
    replay.create_session(meta).await.unwrap();

    let store = replay.session_store(&id);
    let swarm_id = SwarmId::new();
    let actor = AgentId::new();
    let (receipt, _, pk) = signed_receipt(actor, swarm_id).await;
    let resolver = StaticPassportResolver::new().with_actor(actor, pk);
    store
        .append(receipt, AppendOptions::default(), &resolver)
        .await
        .unwrap();
    assert_eq!(store.count().await.unwrap(), 1);

    // delete_session SHOULD cascade-drop the per-session receipt rows
    // via the schema's ON DELETE CASCADE.
    replay.delete_session(&id).await.unwrap();

    // Re-create the session with the same id; the new session_store
    // sees an empty store (cascade dropped the old rows).
    let mut meta2 = fresh_metadata();
    meta2.session_id = id;
    replay.create_session(meta2).await.unwrap();
    let store2 = replay.session_store(&id);
    assert_eq!(
        store2.count().await.unwrap(),
        0,
        "ON DELETE CASCADE MUST drop the receipts when a session is deleted"
    );

    drop_schema(&pool, &schema).await;
}

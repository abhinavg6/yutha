//! Pagination test against the Postgres backend.
//!
//! Skipped by default; runs when `YUTHA_PG_TEST_URL` is set. Same isolation
//! pattern as `tests/conformance.rs` (per-run schema namespace via libpq
//! `-c search_path`).
//!
//! The test appends 7 receipts, paginates with a `page_limit` of 3, and
//! verifies:
//!  - first page returns 3 receipts + a non-None token,
//!  - second page returns 3 receipts + a non-None token,
//!  - third page returns the remaining 1 receipt + a None token,
//!  - the full walk produces every original receipt exactly once.

use sqlx::postgres::PgPoolOptions;
use sqlx::Executor;
use std::collections::HashSet;
use uuid::Uuid;
use yutha_backend_postgres_receipt::PostgresStore;
use yutha_core::{AgentId, CausalRef, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_crypto::sign::generate_keypair;
use yutha_receipt::{
    AppendOptions, Evidence, Query, Receipt, ReceiptStore, SignatureRole, SignedBy,
    StaticPassportResolver,
};

fn pg_url_or_skip(test_name: &str) -> Option<String> {
    match std::env::var("YUTHA_PG_TEST_URL") {
        Ok(s) if !s.is_empty() => Some(s),
        _ => {
            eprintln!(
                "[{test_name}] YUTHA_PG_TEST_URL not set; skipping postgres pagination run"
            );
            None
        }
    }
}

fn url_with_search_path(base: &str, schema: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    let opt = format!("-c%20search_path%3D{schema}");
    format!("{base}{separator}options={opt}")
}

#[tokio::test]
async fn postgres_paginates_consistently() {
    let Some(url) = pg_url_or_skip("postgres_paginates_consistently") else {
        return;
    };

    let schema = format!("yutha_test_{}", Uuid::now_v7().simple());

    let bootstrap = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("bootstrap connect");
    bootstrap
        .execute(format!("CREATE SCHEMA IF NOT EXISTS {schema}").as_str())
        .await
        .expect("CREATE SCHEMA");
    bootstrap.close().await;

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url_with_search_path(&url, &schema))
        .await
        .expect("connect (pinned schema)");

    // page_limit = 3 → 7 receipts walk in three pages of [3, 3, 1].
    let store = PostgresStore::new(pool.clone()).with_page_limit(3);
    store.migrate().await.expect("migrate");

    // Build 7 distinct receipts, all under the same action_kind so the
    // ByActionKind query enumerates them all. Each gets a fresh keypair so
    // signatures verify; bind every keypair in a single resolver.
    let action = "envelope.send";
    let mut resolver = StaticPassportResolver::new();
    let mut expected_ids: HashSet<Vec<u8>> = HashSet::new();
    for _ in 0..7 {
        let actor = AgentId::new();
        let key = generate_keypair();
        resolver = resolver.with_actor(actor, key.public());

        let mut r = Receipt::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(SwarmId::new())
            .actor(actor)
            .action_kind(action)
            .constitution_version("1.0.0")
            .occurred_at(Timestamp::now())
            .causal(CausalRef::empty())
            .evidence(Evidence::new("k", "type.yutha.dev/v1/Bytes", b"v".to_vec()))
            .build()
            .unwrap();
        let bytes = r.canonical_bytes().unwrap();
        let sig = key.sign_message(&bytes);
        r.signatures
            .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

        let id = store
            .append(r, AppendOptions::default(), &resolver)
            .await
            .expect("append")
            .receipt_id;
        expected_ids.insert(id.digest);

        // Force monotonic_ns separation so the cursor's tie-break on
        // receipt_id is never the deciding factor in this test. Without
        // this, very fast appends can land at the same monotonic_ns and
        // the test still passes via the (ns, receipt_id) tie-break — but
        // making the time dimension load-bearing keeps the test honest
        // about what's being exercised.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    assert_eq!(expected_ids.len(), 7, "fixture should produce 7 unique ids");

    // Walk pages.
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut token: Option<Vec<u8>> = None;
    let mut page_no = 0;
    loop {
        page_no += 1;
        let query = Query::ByActionKind(yutha_receipt::ActionKindQuery {
            action_kind: action.into(),
        });
        let page = store.query(query, token.clone()).await.expect("query");
        let got = page.receipts.len();

        match page_no {
            1 | 2 => assert_eq!(
                got, 3,
                "page {page_no} expected to have 3 receipts, got {got}"
            ),
            3 => assert_eq!(got, 1, "page 3 expected to have 1 receipt, got {got}"),
            _ => panic!("walked more than 3 pages: extra page {page_no} with {got} receipts"),
        }

        for r in page.receipts {
            let id_digest =
                yutha_crypto::canonical::content_address(&r).expect("content_address").digest;
            assert!(
                seen.insert(id_digest),
                "page walk emitted the same receipt twice"
            );
        }

        match (page_no, &page.next_page_token) {
            (1, Some(_)) | (2, Some(_)) => { /* expected: more pages */ }
            (3, None) => break,
            (pn, t) => panic!(
                "unexpected token state at page {pn}: token.is_some() = {}",
                t.is_some()
            ),
        }
        token = page.next_page_token;
    }

    assert_eq!(seen, expected_ids, "page walk missed or duplicated receipts");

    let _ = pool
        .execute(format!("DROP SCHEMA IF EXISTS {schema} CASCADE").as_str())
        .await;
    pool.close().await;
}

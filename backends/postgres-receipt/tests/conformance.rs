//! Conformance suite run against the Postgres receipt store.
//!
//! Skipped by default; runs when `YUTHA_PG_TEST_URL` is set to a usable
//! Postgres connection string. The reason for an explicit env var (rather
//! than the standard `DATABASE_URL`) is that `DATABASE_URL` is overloaded
//! by sqlx tooling — operators may have a `DATABASE_URL` pointed at a
//! production read-replica they emphatically don't want a test suite to
//! talk to.
//!
//! Isolation strategy: a per-run schema namespace pinned via the libpq
//! `options` connection parameter (`-c search_path=<schema>`). That option
//! is honored on every connection the pool opens, so concurrent test runs
//! against the same database don't collide. Within a single run, the
//! per-test reset is a `TRUNCATE ... CASCADE` of the domain tables; the
//! migrations table is left alone.

use sqlx::postgres::PgPoolOptions;
use sqlx::Executor;
use std::sync::Arc;
use uuid::Uuid;
use yutha_backend_postgres_receipt::PostgresStore;
use yutha_conformance::receipt::{ReceiptStoreSuite, StoreFactory, StoreReloader};
use yutha_receipt::ReceiptStore;

fn pg_url_or_skip(test_name: &str) -> Option<String> {
    match std::env::var("YUTHA_PG_TEST_URL") {
        Ok(s) if !s.is_empty() => Some(s),
        _ => {
            eprintln!("[{test_name}] YUTHA_PG_TEST_URL not set; skipping postgres conformance run");
            None
        }
    }
}

/// Append `?options=-c%20search_path%3D<schema>` (or `&options=...` if a
/// query string is already present) to the URL. libpq honors this option
/// on every connection the pool opens.
fn url_with_search_path(base: &str, schema: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    // Manual percent-encoding for the two characters that need it (space
    // and `=`): no extra dep, no surprises.
    let opt = format!("-c%20search_path%3D{schema}");
    format!("{base}{separator}options={opt}")
}

#[tokio::test]
async fn postgres_passes_core_suite() {
    let Some(url) = pg_url_or_skip("postgres_passes_core_suite") else {
        return;
    };

    // UUID v7 — the only feature the workspace dep enables, and equally
    // serviceable here since we just need a collision-free identifier.
    let schema = format!("yutha_test_{}", Uuid::now_v7().simple());

    // Step 1: connect to the *base* URL (no search_path pinning) just long
    // enough to CREATE SCHEMA. We need the schema to exist before any
    // connection that pins its search_path to it tries to run DDL.
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

    // Step 2: real pool with the per-run schema pinned via libpq options.
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url_with_search_path(&url, &schema))
        .await
        .expect("connect (pinned schema)");

    let store = PostgresStore::new(pool.clone());
    store.migrate().await.expect("migrate");

    // Per-test reset: TRUNCATE every domain table. CASCADE drops dependent
    // rows in the right FK order without us needing to spell it out.
    let pool_for_factory = pool.clone();
    let factory: StoreFactory = Box::new(move || {
        let pool = pool_for_factory.clone();
        Box::pin(async move {
            pool.execute(
                "TRUNCATE TABLE receipts, receipt_predecessors, receipt_signatures, \
                 receipt_evidence, receipt_cost, receipt_seal CASCADE",
            )
            .await
            .expect("TRUNCATE between tests");
            Arc::new(PostgresStore::new(pool.clone())) as Arc<dyn ReceiptStore>
        })
    });

    // Reloader: simulates a process restart by discarding the existing
    // store handle and constructing a new one against the same pool. The
    // pool *is* the persistence boundary in our test setup — same schema,
    // same connection options — so re-handling it is faithful to what a
    // real restart would observe. Crucially, the reloader does NOT
    // truncate; the durability test's whole point is that data survives.
    let pool_for_reloader = pool.clone();
    let reloader: StoreReloader = Box::new(move |_old_store| {
        let pool = pool_for_reloader.clone();
        Box::pin(async move { Arc::new(PostgresStore::new(pool)) as Arc<dyn ReceiptStore> })
    });

    let suite = ReceiptStoreSuite::new(factory).with_reloader(reloader);
    let outcome = suite.run().await;

    // Best-effort cleanup; runs whether the suite passed or failed (the
    // assert below comes after).
    let _ = pool
        .execute(format!("DROP SCHEMA IF EXISTS {schema} CASCADE").as_str())
        .await;
    pool.close().await;

    assert!(
        outcome.passed(),
        "postgres failed Core conformance ({} failures):\n{:#?}",
        outcome.failures(),
        outcome.failed().collect::<Vec<_>>()
    );
}

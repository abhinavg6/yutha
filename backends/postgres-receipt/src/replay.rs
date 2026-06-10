//! Postgres impl of [`yutha_receipt::ReplayStore`] (Phase 3c follow-on,
//! RFC 0018 §4).
//!
//! Layered on top of the production-receipts schema in
//! [`crate`] but writing to a distinct `replay_*` table family —
//! production reads of `receipts` are blind to replay rows by schema
//! design. Per-session isolation is enforced by composite
//! `(session_id, receipt_id)` primary keys + `WHERE session_id = $1`
//! filters on every read path.
//!
//! ## Layering
//!
//! - [`PostgresReplayStore`] impls [`ReplayStore`] — owns the session
//!   metadata table and hands out per-session handles via
//!   `session_store(id)`.
//! - [`PostgresSessionScopedStore`] impls [`ReceiptStore`] (and **not**
//!   `SealStore` — type-system enforcement of the RFC 0018 §4.4
//!   never-anchors invariant). Every method carries the session_id
//!   into the SQL.
//!
//! ## Migration
//!
//! Schema lives in `migrations/20260610130000_replay_store.sql`.
//! `PostgresStore::migrate()` runs both the production-receipts
//! migrations and the replay-store migration in chronological order
//! via the standard `sqlx::migrate!` macro — operators don't need a
//! separate migrate call for the replay tables.

use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row, Transaction};
use std::sync::Arc;
use uuid::Uuid;

use yutha_core::{
    AgentId, CausalRef, Hash, HashAlgorithm, Signature, SignatureAlgorithm, SpecVersion, SwarmId,
    Timestamp,
};
use yutha_crypto::canonical::{content_address, Canonical};
use yutha_receipt::{
    AppendKind, AppendOptions, AppendOutcome, Evidence, Page, PassportResolver, Query, Receipt,
    ReceiptError, ReceiptStore, ReplayMode, ReplaySessionId, ReplaySessionMetadata,
    ReplaySessionWindow, ReplayStore, Result, SealStatus, SignedBy,
};

use crate::{
    decode_cursor, encode_cursor, i64_to_u64, require_sha256, role_from_rank, u64_to_i64,
    verify_pre_append, Cursor,
};

/// Default page size for per-session queries. Same tuning as the
/// production store — see `crate::DEFAULT_PAGE_LIMIT`.
const DEFAULT_PAGE_LIMIT: usize = 256;

/// Postgres-backed [`ReplayStore`].
#[derive(Debug, Clone)]
pub struct PostgresReplayStore {
    pool: PgPool,
    page_limit: usize,
}

impl PostgresReplayStore {
    /// Construct a replay store against `pool`. Migrations are applied
    /// via [`crate::PostgresStore::migrate`] — both crates share the
    /// same `migrations/` directory.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            page_limit: DEFAULT_PAGE_LIMIT,
        }
    }

    /// Override the default per-session page size. Values ≤ 0 are
    /// clamped to 1.
    pub fn with_page_limit(mut self, limit: usize) -> Self {
        self.page_limit = limit.max(1);
        self
    }
}

#[async_trait]
impl ReplayStore for PostgresReplayStore {
    fn session_store(&self, session_id: &ReplaySessionId) -> Arc<dyn ReceiptStore> {
        Arc::new(PostgresSessionScopedStore {
            pool: self.pool.clone(),
            session_id: *session_id,
            page_limit: self.page_limit,
        }) as Arc<dyn ReceiptStore>
    }

    async fn create_session(&self, metadata: ReplaySessionMetadata) -> Result<()> {
        let mode_str = mode_to_text(metadata.mode);
        let result = sqlx::query(
            "INSERT INTO replay_sessions \
                (session_id, candidate_constitution_hash, candidate_constitution_version, \
                 window_from_unix_ns, window_to_unix_ns, action_kind_filter, mode, \
                 warm_lookback_hours, created_at_ns, created_at_wall, \
                 last_active_at_ns, last_active_at_wall, receipts_replayed) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
             ON CONFLICT (session_id) DO NOTHING",
        )
        .bind(Uuid::from_bytes(*metadata.session_id.as_bytes()))
        .bind(require_sha256(&metadata.candidate_constitution_hash)?)
        .bind(&metadata.candidate_constitution_version)
        .bind(u64_to_i64(metadata.window.from_unix_ns))
        .bind(u64_to_i64(metadata.window.to_unix_ns))
        .bind(&metadata.window.action_kind_filter)
        .bind(mode_str)
        .bind(metadata.warm_lookback_hours as i32)
        .bind(u64_to_i64(metadata.created_at.monotonic_ns))
        .bind(&metadata.created_at.wall_clock)
        .bind(u64_to_i64(metadata.last_active_at.monotonic_ns))
        .bind(&metadata.last_active_at.wall_clock)
        .bind(u64_to_i64(metadata.receipts_replayed))
        .execute(&self.pool)
        .await
        .map_err(|e| ReceiptError::Backend(format!("create_session: {e}")))?;

        if result.rows_affected() == 0 {
            // ON CONFLICT DO NOTHING swallowed an existing-row collision.
            // Mirrors `MemoryReplayStore::create_session`'s posture:
            // creating the same session twice is a Backend error.
            return Err(ReceiptError::Backend(format!(
                "replay session {} already exists",
                metadata.session_id
            )));
        }
        Ok(())
    }

    async fn delete_session(&self, session_id: &ReplaySessionId) -> Result<()> {
        // ON DELETE CASCADE drops the per-session receipts + their
        // join-table rows in one statement. Idempotent — deleting a
        // missing session is a no-op (zero rows affected).
        sqlx::query("DELETE FROM replay_sessions WHERE session_id = $1")
            .bind(Uuid::from_bytes(*session_id.as_bytes()))
            .execute(&self.pool)
            .await
            .map_err(|e| ReceiptError::Backend(format!("delete_session: {e}")))?;
        Ok(())
    }

    async fn list_sessions(&self) -> Result<Vec<ReplaySessionMetadata>> {
        // UUIDv7 sort order is creation order — mirrors
        // `MemoryReplayStore::list_sessions`'s sort-by-id posture.
        let rows = sqlx::query(
            "SELECT session_id, candidate_constitution_hash, candidate_constitution_version, \
                    window_from_unix_ns, window_to_unix_ns, action_kind_filter, mode, \
                    warm_lookback_hours, created_at_ns, created_at_wall, \
                    last_active_at_ns, last_active_at_wall, receipts_replayed \
             FROM replay_sessions ORDER BY session_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ReceiptError::Backend(format!("list_sessions: {e}")))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(row_to_metadata(row)?);
        }
        Ok(out)
    }

    async fn get_session(
        &self,
        session_id: &ReplaySessionId,
    ) -> Result<Option<ReplaySessionMetadata>> {
        let row = sqlx::query(
            "SELECT session_id, candidate_constitution_hash, candidate_constitution_version, \
                    window_from_unix_ns, window_to_unix_ns, action_kind_filter, mode, \
                    warm_lookback_hours, created_at_ns, created_at_wall, \
                    last_active_at_ns, last_active_at_wall, receipts_replayed \
             FROM replay_sessions WHERE session_id = $1",
        )
        .bind(Uuid::from_bytes(*session_id.as_bytes()))
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ReceiptError::Backend(format!("get_session: {e}")))?;

        Ok(match row {
            Some(r) => Some(row_to_metadata(r)?),
            None => None,
        })
    }

    async fn touch_session(
        &self,
        session_id: &ReplaySessionId,
        receipts_replayed_delta: u64,
        now: &Timestamp,
    ) -> Result<()> {
        // UPDATE filtered by session_id; if the session doesn't exist,
        // zero rows update — silent no-op mirroring MemoryReplayStore.
        sqlx::query(
            "UPDATE replay_sessions \
             SET last_active_at_ns = $1, \
                 last_active_at_wall = $2, \
                 receipts_replayed = LEAST(receipts_replayed + $3, $4) \
             WHERE session_id = $5",
        )
        .bind(u64_to_i64(now.monotonic_ns))
        .bind(&now.wall_clock)
        .bind(u64_to_i64(receipts_replayed_delta))
        .bind(i64::MAX)
        .bind(Uuid::from_bytes(*session_id.as_bytes()))
        .execute(&self.pool)
        .await
        .map_err(|e| ReceiptError::Backend(format!("touch_session: {e}")))?;
        Ok(())
    }
}

// =============================================================================
// PostgresSessionScopedStore — impls ReceiptStore only (NOT SealStore)
// =============================================================================

/// A session-scoped [`ReceiptStore`] handle. Every read filters by
/// `session_id = $1`; every write inserts with `session_id` set on
/// `replay_receipts`. Constructed via
/// [`PostgresReplayStore::session_store`].
///
/// **Does not implement [`yutha_receipt::SealStore`]** — Type-system
/// enforcement of RFC 0018 §4.4: the anchor driver requires
/// `Arc<dyn SealStore>`, so a session-scoped handle structurally
/// cannot be plumbed into the anchoring path.
#[derive(Debug, Clone)]
pub struct PostgresSessionScopedStore {
    pool: PgPool,
    session_id: ReplaySessionId,
    page_limit: usize,
}

impl PostgresSessionScopedStore {
    fn session_uuid(&self) -> Uuid {
        Uuid::from_bytes(*self.session_id.as_bytes())
    }
}

#[async_trait]
impl ReceiptStore for PostgresSessionScopedStore {
    async fn append(
        &self,
        receipt: Receipt,
        _options: AppendOptions,
        resolver: &dyn PassportResolver,
    ) -> Result<AppendOutcome> {
        // Same pre-append verification as production. A failed
        // verify short-circuits before any DB writes.
        verify_pre_append(&receipt, resolver).await?;

        let receipt_id = content_address(&receipt).map_err(ReceiptError::Crypto)?;
        let canonical = receipt.canonical_bytes().map_err(ReceiptError::Crypto)?;
        let session_uuid = self.session_uuid();

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ReceiptError::Backend(format!("replay append: begin tx: {e}")))?;

        let inserted =
            replay_insert_receipt(&mut tx, session_uuid, &receipt, &receipt_id, &canonical).await?;

        let kind = if inserted {
            replay_insert_predecessors(&mut tx, session_uuid, &receipt_id, &receipt.causal).await?;
            replay_insert_signatures(&mut tx, session_uuid, &receipt_id, &receipt.signatures)
                .await?;
            replay_insert_evidence(&mut tx, session_uuid, &receipt_id, &receipt.evidence).await?;
            // Note: no per-receipt cost insert. Phase 3c-shipped replay
            // emissions are `enforcement.*` shapes that don't carry
            // `CostAnnotation`. If a future replay path produces
            // cost-bearing receipts, parallel `replay_receipt_cost`
            // table + insert lands here.
            AppendKind::Inserted
        } else {
            AppendKind::AlreadyPresent
        };

        tx.commit()
            .await
            .map_err(|e| ReceiptError::Backend(format!("replay append: commit tx: {e}")))?;

        Ok(AppendOutcome {
            receipt_id,
            kind,
            // Session-scoped receipts are unsealed by construction —
            // see the never-anchors invariant note on the struct.
            seal: SealStatus::unsealed(),
        })
    }

    async fn get(&self, id: &Hash) -> Result<Option<Receipt>> {
        let digest = require_sha256(id)?;
        let row = sqlx::query(
            "SELECT receipt_id, swarm_id, actor, action_kind, constitution_version, \
                    occurred_at_ns, occurred_at_wall \
             FROM replay_receipts WHERE session_id = $1 AND receipt_id = $2",
        )
        .bind(self.session_uuid())
        .bind(digest)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ReceiptError::Backend(format!("replay get: {e}")))?;

        let Some(row) = row else { return Ok(None) };
        let receipt = replay_rehydrate_receipt(&self.pool, self.session_uuid(), row).await?;
        Ok(Some(receipt))
    }

    async fn query(&self, query: Query, page_token: Option<Vec<u8>>) -> Result<Page> {
        // ByReceiptId is 0-or-1 — same shortcut as production.
        if let Query::ByReceiptId(id) = &query {
            let one = self.get(id).await?;
            return Ok(Page {
                receipts: one.into_iter().collect(),
                next_page_token: None,
            });
        }

        let cursor = page_token.as_deref().map(decode_cursor).transpose()?;
        let page_limit = self.page_limit;
        let fetch_limit = (page_limit as i64) + 1;
        let session_uuid = self.session_uuid();

        // Keyset cursor pattern mirrors production's exactly, but with
        // the session_id filter as the first WHERE term so the
        // (session_id, occurred_at_ns, receipt_id) compound index
        // serves the query index-only.
        let mut rows = match &query {
            Query::ByReceiptId(_) => unreachable!("ByReceiptId handled above"),
            Query::ByPredecessor(q) => {
                let digest = require_sha256(&q.predecessor)?;
                let sql = match &cursor {
                    None => {
                        "SELECT r.receipt_id, r.swarm_id, r.actor, r.action_kind, \
                                r.constitution_version, r.occurred_at_ns, r.occurred_at_wall \
                         FROM replay_receipts r \
                         JOIN replay_receipt_predecessors rp \
                              ON rp.session_id = r.session_id AND rp.receipt_id = r.receipt_id \
                         WHERE r.session_id = $1 AND rp.predecessor = $2 \
                         ORDER BY r.occurred_at_ns, r.receipt_id \
                         LIMIT $3"
                    }
                    Some(_) => {
                        "SELECT r.receipt_id, r.swarm_id, r.actor, r.action_kind, \
                                r.constitution_version, r.occurred_at_ns, r.occurred_at_wall \
                         FROM replay_receipts r \
                         JOIN replay_receipt_predecessors rp \
                              ON rp.session_id = r.session_id AND rp.receipt_id = r.receipt_id \
                         WHERE r.session_id = $1 AND rp.predecessor = $2 \
                           AND (r.occurred_at_ns, r.receipt_id) > ($4, $5) \
                         ORDER BY r.occurred_at_ns, r.receipt_id \
                         LIMIT $3"
                    }
                };
                let mut q = sqlx::query(sql)
                    .bind(session_uuid)
                    .bind(digest)
                    .bind(fetch_limit);
                if let Some(c) = &cursor {
                    q = q.bind(c.occurred_at_ns).bind(c.receipt_id_digest.clone());
                }
                q.fetch_all(&self.pool)
                    .await
                    .map_err(|e| ReceiptError::Backend(format!("replay query(pred): {e}")))?
            }
            Query::ByAgent(q) => {
                let actor_uuid = Uuid::from_bytes(q.agent_id.as_bytes());
                let sql = match &cursor {
                    None => {
                        "SELECT receipt_id, swarm_id, actor, action_kind, constitution_version, \
                                occurred_at_ns, occurred_at_wall \
                         FROM replay_receipts \
                         WHERE session_id = $1 AND actor = $2 \
                         ORDER BY occurred_at_ns, receipt_id \
                         LIMIT $3"
                    }
                    Some(_) => {
                        "SELECT receipt_id, swarm_id, actor, action_kind, constitution_version, \
                                occurred_at_ns, occurred_at_wall \
                         FROM replay_receipts \
                         WHERE session_id = $1 AND actor = $2 \
                           AND (occurred_at_ns, receipt_id) > ($4, $5) \
                         ORDER BY occurred_at_ns, receipt_id \
                         LIMIT $3"
                    }
                };
                let mut q = sqlx::query(sql)
                    .bind(session_uuid)
                    .bind(actor_uuid)
                    .bind(fetch_limit);
                if let Some(c) = &cursor {
                    q = q.bind(c.occurred_at_ns).bind(c.receipt_id_digest.clone());
                }
                q.fetch_all(&self.pool)
                    .await
                    .map_err(|e| ReceiptError::Backend(format!("replay query(agent): {e}")))?
            }
            Query::ByActionKind(q) => {
                let kind = q.action_kind.clone();
                let sql = match &cursor {
                    None => {
                        "SELECT receipt_id, swarm_id, actor, action_kind, constitution_version, \
                                occurred_at_ns, occurred_at_wall \
                         FROM replay_receipts \
                         WHERE session_id = $1 AND action_kind = $2 \
                         ORDER BY occurred_at_ns, receipt_id \
                         LIMIT $3"
                    }
                    Some(_) => {
                        "SELECT receipt_id, swarm_id, actor, action_kind, constitution_version, \
                                occurred_at_ns, occurred_at_wall \
                         FROM replay_receipts \
                         WHERE session_id = $1 AND action_kind = $2 \
                           AND (occurred_at_ns, receipt_id) > ($4, $5) \
                         ORDER BY occurred_at_ns, receipt_id \
                         LIMIT $3"
                    }
                };
                let mut q = sqlx::query(sql)
                    .bind(session_uuid)
                    .bind(kind)
                    .bind(fetch_limit);
                if let Some(c) = &cursor {
                    q = q.bind(c.occurred_at_ns).bind(c.receipt_id_digest.clone());
                }
                q.fetch_all(&self.pool)
                    .await
                    .map_err(|e| ReceiptError::Backend(format!("replay query(kind): {e}")))?
            }
            Query::ByTimeRange(q) => {
                let from = u64_to_i64(q.from.monotonic_ns);
                let to = u64_to_i64(q.to.monotonic_ns);
                let sql = match &cursor {
                    None => {
                        "SELECT receipt_id, swarm_id, actor, action_kind, constitution_version, \
                                occurred_at_ns, occurred_at_wall \
                         FROM replay_receipts \
                         WHERE session_id = $1 AND occurred_at_ns BETWEEN $2 AND $3 \
                         ORDER BY occurred_at_ns, receipt_id \
                         LIMIT $4"
                    }
                    Some(_) => {
                        "SELECT receipt_id, swarm_id, actor, action_kind, constitution_version, \
                                occurred_at_ns, occurred_at_wall \
                         FROM replay_receipts \
                         WHERE session_id = $1 AND occurred_at_ns BETWEEN $2 AND $3 \
                           AND (occurred_at_ns, receipt_id) > ($5, $6) \
                         ORDER BY occurred_at_ns, receipt_id \
                         LIMIT $4"
                    }
                };
                let mut q = sqlx::query(sql)
                    .bind(session_uuid)
                    .bind(from)
                    .bind(to)
                    .bind(fetch_limit);
                if let Some(c) = &cursor {
                    q = q.bind(c.occurred_at_ns).bind(c.receipt_id_digest.clone());
                }
                q.fetch_all(&self.pool)
                    .await
                    .map_err(|e| ReceiptError::Backend(format!("replay query(time): {e}")))?
            }
        };

        let has_more = rows.len() > page_limit;
        if has_more {
            rows.truncate(page_limit);
        }

        let mut receipts = Vec::with_capacity(rows.len());
        let mut last_cursor: Option<Cursor> = None;
        for row in rows {
            let occurred_at_ns: i64 = row.try_get("occurred_at_ns").map_err(|e| {
                ReceiptError::Backend(format!("replay cursor decode occurred_at_ns: {e}"))
            })?;
            let receipt_id: Vec<u8> = row
                .try_get("receipt_id")
                .map_err(|e| ReceiptError::Backend(format!("replay cursor decode receipt_id: {e}")))?;
            last_cursor = Some(Cursor {
                occurred_at_ns,
                receipt_id_digest: receipt_id,
            });
            receipts.push(replay_rehydrate_receipt(&self.pool, session_uuid, row).await?);
        }

        let next_page_token = if has_more {
            last_cursor.as_ref().map(encode_cursor)
        } else {
            None
        };

        Ok(Page {
            receipts,
            next_page_token,
        })
    }

    async fn count(&self) -> Result<u64> {
        let row = sqlx::query("SELECT COUNT(*) AS c FROM replay_receipts WHERE session_id = $1")
            .bind(self.session_uuid())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| ReceiptError::Backend(format!("replay count: {e}")))?;
        let c: i64 = row
            .try_get("c")
            .map_err(|e| ReceiptError::Backend(format!("replay count decode: {e}")))?;
        Ok(c.max(0) as u64)
    }
}

// =============================================================================
// Helpers (session-scoped INSERT / SELECT)
// =============================================================================

fn mode_to_text(mode: ReplayMode) -> &'static str {
    match mode {
        ReplayMode::Cold => "cold",
        ReplayMode::Warm => "warm",
    }
}

fn text_to_mode(s: &str) -> Result<ReplayMode> {
    match s {
        "cold" => Ok(ReplayMode::Cold),
        "warm" => Ok(ReplayMode::Warm),
        other => Err(ReceiptError::Backend(format!(
            "unknown replay mode in db: {other:?}"
        ))),
    }
}

fn row_to_metadata(row: PgRow) -> Result<ReplaySessionMetadata> {
    let session_uuid: Uuid = row
        .try_get("session_id")
        .map_err(|e| ReceiptError::Backend(format!("decode session_id: {e}")))?;
    let session_id: ReplaySessionId = session_uuid
        .to_string()
        .parse()
        .map_err(|e| ReceiptError::Backend(format!("parse session_id: {e}")))?;

    let candidate_constitution_hash: Vec<u8> = row
        .try_get("candidate_constitution_hash")
        .map_err(|e| ReceiptError::Backend(format!("decode candidate hash: {e}")))?;
    let candidate_constitution_hash = Hash::new(HashAlgorithm::Sha256, candidate_constitution_hash)
        .map_err(|e| ReceiptError::Backend(format!("candidate hash not 32 bytes: {e}")))?;

    let candidate_constitution_version: String = row
        .try_get("candidate_constitution_version")
        .map_err(|e| ReceiptError::Backend(format!("decode candidate version: {e}")))?;

    let from_unix_ns: i64 = row
        .try_get("window_from_unix_ns")
        .map_err(|e| ReceiptError::Backend(format!("decode window_from: {e}")))?;
    let to_unix_ns: i64 = row
        .try_get("window_to_unix_ns")
        .map_err(|e| ReceiptError::Backend(format!("decode window_to: {e}")))?;
    let action_kind_filter: Vec<String> = row
        .try_get("action_kind_filter")
        .map_err(|e| ReceiptError::Backend(format!("decode action_kind_filter: {e}")))?;
    let mode_str: String = row
        .try_get("mode")
        .map_err(|e| ReceiptError::Backend(format!("decode mode: {e}")))?;
    let warm_lookback_hours: i32 = row
        .try_get("warm_lookback_hours")
        .map_err(|e| ReceiptError::Backend(format!("decode warm_lookback_hours: {e}")))?;

    let created_at_ns: i64 = row
        .try_get("created_at_ns")
        .map_err(|e| ReceiptError::Backend(format!("decode created_at_ns: {e}")))?;
    let created_at_wall: String = row
        .try_get("created_at_wall")
        .map_err(|e| ReceiptError::Backend(format!("decode created_at_wall: {e}")))?;
    let last_active_at_ns: i64 = row
        .try_get("last_active_at_ns")
        .map_err(|e| ReceiptError::Backend(format!("decode last_active_at_ns: {e}")))?;
    let last_active_at_wall: String = row
        .try_get("last_active_at_wall")
        .map_err(|e| ReceiptError::Backend(format!("decode last_active_at_wall: {e}")))?;
    let receipts_replayed: i64 = row
        .try_get("receipts_replayed")
        .map_err(|e| ReceiptError::Backend(format!("decode receipts_replayed: {e}")))?;

    Ok(ReplaySessionMetadata {
        session_id,
        candidate_constitution_hash,
        candidate_constitution_version,
        window: ReplaySessionWindow {
            from_unix_ns: i64_to_u64(from_unix_ns),
            to_unix_ns: i64_to_u64(to_unix_ns),
            action_kind_filter,
        },
        mode: text_to_mode(&mode_str)?,
        warm_lookback_hours: warm_lookback_hours.max(0) as u32,
        created_at: Timestamp::new(created_at_wall, i64_to_u64(created_at_ns))
            .map_err(ReceiptError::Core)?,
        last_active_at: Timestamp::new(last_active_at_wall, i64_to_u64(last_active_at_ns))
            .map_err(ReceiptError::Core)?,
        receipts_replayed: i64_to_u64(receipts_replayed),
    })
}

async fn replay_insert_receipt(
    tx: &mut Transaction<'_, Postgres>,
    session_uuid: Uuid,
    r: &Receipt,
    receipt_id: &Hash,
    canonical: &[u8],
) -> Result<bool> {
    let digest = require_sha256(receipt_id)?;
    let result = sqlx::query(
        "INSERT INTO replay_receipts \
            (session_id, receipt_id, swarm_id, actor, action_kind, constitution_version, \
             occurred_at_ns, occurred_at_wall, canonical_bytes) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (session_id, receipt_id) DO NOTHING",
    )
    .bind(session_uuid)
    .bind(digest)
    .bind(Uuid::from_bytes(r.swarm_id.as_bytes()))
    .bind(Uuid::from_bytes(r.actor.as_bytes()))
    .bind(&r.action_kind)
    .bind(&r.constitution_version)
    .bind(u64_to_i64(r.occurred_at.monotonic_ns))
    .bind(&r.occurred_at.wall_clock)
    .bind(canonical)
    .execute(&mut **tx)
    .await
    .map_err(|e| ReceiptError::Backend(format!("replay insert receipts: {e}")))?;

    Ok(result.rows_affected() > 0)
}

async fn replay_insert_predecessors(
    tx: &mut Transaction<'_, Postgres>,
    session_uuid: Uuid,
    receipt_id: &Hash,
    causal: &CausalRef,
) -> Result<()> {
    let digest = require_sha256(receipt_id)?;
    for p in &causal.predecessors {
        let pdig = require_sha256(p)?;
        sqlx::query(
            "INSERT INTO replay_receipt_predecessors (session_id, receipt_id, predecessor) \
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(session_uuid)
        .bind(digest.to_vec())
        .bind(pdig)
        .execute(&mut **tx)
        .await
        .map_err(|e| ReceiptError::Backend(format!("replay insert predecessors: {e}")))?;
    }
    Ok(())
}

async fn replay_insert_signatures(
    tx: &mut Transaction<'_, Postgres>,
    session_uuid: Uuid,
    receipt_id: &Hash,
    signatures: &[SignedBy],
) -> Result<()> {
    let digest = require_sha256(receipt_id)?;
    for s in signatures {
        sqlx::query(
            "INSERT INTO replay_receipt_signatures \
                (session_id, receipt_id, role, algorithm, signature, key_fingerprint, \
                 signed_at_ns, signed_at_wall) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(session_uuid)
        .bind(digest.to_vec())
        .bind(i32::from(s.role.rank()))
        .bind(s.signature.algorithm.to_wire())
        .bind(&s.signature.value)
        .bind(&s.signature.key_fingerprint)
        .bind(u64_to_i64(s.signed_at.monotonic_ns))
        .bind(&s.signed_at.wall_clock)
        .execute(&mut **tx)
        .await
        .map_err(|e| ReceiptError::Backend(format!("replay insert signatures: {e}")))?;
    }
    Ok(())
}

async fn replay_insert_evidence(
    tx: &mut Transaction<'_, Postgres>,
    session_uuid: Uuid,
    receipt_id: &Hash,
    evidence: &[Evidence],
) -> Result<()> {
    let digest = require_sha256(receipt_id)?;
    for (ord, e) in evidence.iter().enumerate() {
        sqlx::query(
            "INSERT INTO replay_receipt_evidence \
                (session_id, receipt_id, ord, key, type_url, value, sensitive) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(session_uuid)
        .bind(digest.to_vec())
        .bind(ord as i32)
        .bind(&e.key)
        .bind(&e.type_url)
        .bind(&e.value)
        .bind(e.sensitive)
        .execute(&mut **tx)
        .await
        .map_err(|e| ReceiptError::Backend(format!("replay insert evidence: {e}")))?;
    }
    Ok(())
}

async fn replay_rehydrate_receipt(
    pool: &PgPool,
    session_uuid: Uuid,
    row: PgRow,
) -> Result<Receipt> {
    let receipt_id_bytes: Vec<u8> = row
        .try_get("receipt_id")
        .map_err(|e| ReceiptError::Backend(format!("decode receipt_id: {e}")))?;
    let receipt_id =
        Hash::new(HashAlgorithm::Sha256, receipt_id_bytes.clone()).map_err(ReceiptError::Core)?;

    let swarm_uuid: Uuid = row
        .try_get("swarm_id")
        .map_err(|e| ReceiptError::Backend(format!("decode swarm_id: {e}")))?;
    let actor_uuid: Uuid = row
        .try_get("actor")
        .map_err(|e| ReceiptError::Backend(format!("decode actor: {e}")))?;
    let action_kind: String = row
        .try_get("action_kind")
        .map_err(|e| ReceiptError::Backend(format!("decode action_kind: {e}")))?;
    let constitution_version: String = row
        .try_get("constitution_version")
        .map_err(|e| ReceiptError::Backend(format!("decode constitution_version: {e}")))?;
    let occurred_at_ns: i64 = row
        .try_get("occurred_at_ns")
        .map_err(|e| ReceiptError::Backend(format!("decode occurred_at_ns: {e}")))?;
    let occurred_at_wall: String = row
        .try_get("occurred_at_wall")
        .map_err(|e| ReceiptError::Backend(format!("decode occurred_at_wall: {e}")))?;

    let occurred_at =
        Timestamp::new(occurred_at_wall, i64_to_u64(occurred_at_ns)).map_err(ReceiptError::Core)?;

    let causal = replay_fetch_predecessors(pool, session_uuid, &receipt_id).await?;
    let signatures = replay_fetch_signatures(pool, session_uuid, &receipt_id).await?;
    let evidence = replay_fetch_evidence(pool, session_uuid, &receipt_id).await?;

    let mut receipt = Receipt::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .swarm_id(SwarmId::from_bytes(swarm_uuid.as_bytes()).map_err(ReceiptError::Core)?)
        .actor(AgentId::from_bytes(actor_uuid.as_bytes()).map_err(ReceiptError::Core)?)
        .action_kind(action_kind)
        .causal(causal)
        .constitution_version(constitution_version)
        .occurred_at(occurred_at);

    for e in evidence {
        receipt = receipt.evidence(e);
    }
    let mut receipt = receipt.build().map_err(|e| {
        ReceiptError::Backend(format!(
            "replay rehydrate: builder rejected required field: {e}"
        ))
    })?;
    receipt.signatures = signatures;

    Ok(receipt)
}

async fn replay_fetch_predecessors(
    pool: &PgPool,
    session_uuid: Uuid,
    id: &Hash,
) -> Result<CausalRef> {
    let digest = require_sha256(id)?;
    let rows = sqlx::query(
        "SELECT predecessor FROM replay_receipt_predecessors \
         WHERE session_id = $1 AND receipt_id = $2",
    )
    .bind(session_uuid)
    .bind(digest)
    .fetch_all(pool)
    .await
    .map_err(|e| ReceiptError::Backend(format!("replay fetch predecessors: {e}")))?;
    let mut hashes = Vec::with_capacity(rows.len());
    for row in rows {
        let p: Vec<u8> = row
            .try_get("predecessor")
            .map_err(|e| ReceiptError::Backend(format!("decode predecessor: {e}")))?;
        hashes.push(Hash::new(HashAlgorithm::Sha256, p).map_err(ReceiptError::Core)?);
    }
    Ok(CausalRef::from_iter(hashes))
}

async fn replay_fetch_signatures(
    pool: &PgPool,
    session_uuid: Uuid,
    id: &Hash,
) -> Result<Vec<SignedBy>> {
    let digest = require_sha256(id)?;
    let rows = sqlx::query(
        "SELECT role, algorithm, signature, key_fingerprint, signed_at_ns, signed_at_wall \
         FROM replay_receipt_signatures \
         WHERE session_id = $1 AND receipt_id = $2 ORDER BY role",
    )
    .bind(session_uuid)
    .bind(digest)
    .fetch_all(pool)
    .await
    .map_err(|e| ReceiptError::Backend(format!("replay fetch signatures: {e}")))?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let role_rank: i32 = row
            .try_get("role")
            .map_err(|e| ReceiptError::Backend(format!("decode role: {e}")))?;
        let role = role_from_rank(role_rank)?;
        let algorithm_wire: i32 = row
            .try_get("algorithm")
            .map_err(|e| ReceiptError::Backend(format!("decode algorithm: {e}")))?;
        let algorithm =
            SignatureAlgorithm::from_wire(algorithm_wire).map_err(ReceiptError::Core)?;
        let value: Vec<u8> = row
            .try_get("signature")
            .map_err(|e| ReceiptError::Backend(format!("decode signature: {e}")))?;
        let fingerprint: Vec<u8> = row
            .try_get("key_fingerprint")
            .map_err(|e| ReceiptError::Backend(format!("decode key_fingerprint: {e}")))?;
        let signed_at_ns: i64 = row
            .try_get("signed_at_ns")
            .map_err(|e| ReceiptError::Backend(format!("decode signed_at_ns: {e}")))?;
        let signed_at_wall: String = row
            .try_get("signed_at_wall")
            .map_err(|e| ReceiptError::Backend(format!("decode signed_at_wall: {e}")))?;

        let signature =
            Signature::new(algorithm, value, fingerprint).map_err(ReceiptError::Core)?;
        let signed_at =
            Timestamp::new(signed_at_wall, i64_to_u64(signed_at_ns)).map_err(ReceiptError::Core)?;
        out.push(SignedBy::new(role, signature, signed_at));
    }
    Ok(out)
}

async fn replay_fetch_evidence(
    pool: &PgPool,
    session_uuid: Uuid,
    id: &Hash,
) -> Result<Vec<Evidence>> {
    let digest = require_sha256(id)?;
    let rows = sqlx::query(
        "SELECT key, type_url, value, sensitive \
         FROM replay_receipt_evidence \
         WHERE session_id = $1 AND receipt_id = $2 ORDER BY ord",
    )
    .bind(session_uuid)
    .bind(digest)
    .fetch_all(pool)
    .await
    .map_err(|e| ReceiptError::Backend(format!("replay fetch evidence: {e}")))?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let key: String = row
            .try_get("key")
            .map_err(|e| ReceiptError::Backend(format!("decode key: {e}")))?;
        let type_url: String = row
            .try_get("type_url")
            .map_err(|e| ReceiptError::Backend(format!("decode type_url: {e}")))?;
        let value: Vec<u8> = row
            .try_get("value")
            .map_err(|e| ReceiptError::Backend(format!("decode value: {e}")))?;
        let sensitive: bool = row
            .try_get("sensitive")
            .map_err(|e| ReceiptError::Backend(format!("decode sensitive: {e}")))?;
        out.push(Evidence {
            key,
            type_url,
            value,
            sensitive,
        });
    }
    Ok(out)
}

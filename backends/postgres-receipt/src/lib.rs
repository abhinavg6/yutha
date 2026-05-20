//! Postgres backend for the Yutha [`yutha_receipt::ReceiptStore`].
//!
//! Default backend for self-hosted deployments. Targets Core + Full
//! conformance per [`/docs/conformance/conformance-suite.md`](../../docs/conformance/conformance-suite.md)
//! §3.3; Verifiable-tier sealing is left to the Walrus backend.
//!
//! ## Schema
//!
//! See [`migrations/`](../migrations/). The `receipts` table holds the parsed
//! columns plus the canonical bytes (stored for re-verification and bulk
//! export); related rows live in `receipt_predecessors`, `receipt_signatures`,
//! `receipt_evidence`, `receipt_cost`, and `receipt_seal`. The application
//! database role SHOULD be granted INSERT only on these tables — append-only
//! enforcement at the trait surface is belt; the role grant is suspenders.
//!
//! ## Hash storage
//!
//! `receipt_id` is stored as `BYTEA` carrying only the 32-byte SHA-256
//! digest. The algorithm tag is *implicit* — v1.0 requires SHA-256 and
//! nothing else. When BLAKE3 (or anything else) becomes a normative option,
//! a schema migration adds an `algorithm INTEGER` column and the read path
//! starts honoring it.
//!
//! ## SQL strategy
//!
//! Queries use runtime-built `sqlx::query` / `sqlx::query_as` rather than
//! the compile-time `sqlx::query!` macros. The runtime path costs us
//! compile-time validation; in exchange, the crate compiles without a
//! running Postgres or a checked-in `.sqlx/` cache. When CI grows a
//! reliable Postgres dependency we can switch the hot queries to macros
//! and ship the offline cache.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row, Transaction};
use std::collections::HashMap;
use uuid::Uuid;
use yutha_core::{
    AgentId, CausalRef, CostAnnotation, Hash, HashAlgorithm, PublicKey, Signature,
    SignatureAlgorithm, SpecVersion, SwarmId, Timestamp,
};
use yutha_crypto::canonical::{content_address, Canonical};
use yutha_receipt::{
    AppendKind, AppendOptions, AppendOutcome, Evidence, Page, PassportResolver, Query, Receipt,
    ReceiptError, ReceiptStore, Result, SealStatus, SealStore, SealedBatch, SignatureRole,
    SignedBy,
};

/// Postgres-backed receipt store.
#[derive(Debug, Clone)]
pub struct PostgresStore {
    pool: PgPool,
    /// Page size for multi-row query results. See [`DEFAULT_PAGE_LIMIT`].
    page_limit: usize,
}

impl PostgresStore {
    /// Construct a store against the supplied pool with the default page
    /// size. Migrations are applied elsewhere (see `migrations/` and your
    /// deployment runbook).
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            page_limit: DEFAULT_PAGE_LIMIT,
        }
    }

    /// Override the default page size. Useful for tests and for operators
    /// who want a different tuning point. Values ≤ 0 are clamped to 1.
    pub fn with_page_limit(mut self, limit: usize) -> Self {
        self.page_limit = limit.max(1);
        self
    }

    /// Run schema migrations. Wraps `sqlx::migrate!`. Should be called once
    /// at process start, ideally with a leader-election guard in HA
    /// deployments.
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|e| ReceiptError::Backend(format!("migration failed: {e}")))?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// ReceiptStore impl
// -----------------------------------------------------------------------------

#[async_trait]
impl ReceiptStore for PostgresStore {
    async fn append(
        &self,
        receipt: Receipt,
        _options: AppendOptions,
        resolver: &dyn PassportResolver,
    ) -> Result<AppendOutcome> {
        // 1) Verify signatures (same policy as MemoryStore). Failures here
        //    short-circuit before any DB writes.
        verify_pre_append(&receipt, resolver).await?;

        // 2) Compute content-address. This also exercises the canonical
        //    bytes path; if it errors, the receipt would have been
        //    unrepresentable anyway.
        let receipt_id = content_address(&receipt).map_err(ReceiptError::Crypto)?;
        let canonical = receipt.canonical_bytes().map_err(ReceiptError::Crypto)?;

        // 3) Persist in a single transaction. ON CONFLICT (receipt_id) DO
        //    NOTHING gives us idempotency: the same canonical bytes always
        //    yield the same receipt_id, and second-and-later inserts collapse
        //    into a no-op. We detect that case via the RETURNING-from-INSERT
        //    sentinel.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ReceiptError::Backend(format!("begin tx: {e}")))?;

        let inserted = insert_receipt(&mut tx, &receipt, &receipt_id, &canonical).await?;

        let kind = if inserted {
            // Fresh insert — write the related rows.
            insert_predecessors(&mut tx, &receipt_id, &receipt.causal).await?;
            insert_signatures(&mut tx, &receipt_id, &receipt.signatures).await?;
            insert_evidence(&mut tx, &receipt_id, &receipt.evidence).await?;
            if let Some(cost) = &receipt.cost {
                insert_cost(&mut tx, &receipt_id, cost).await?;
            }
            AppendKind::Inserted
        } else {
            AppendKind::AlreadyPresent
        };

        tx.commit()
            .await
            .map_err(|e| ReceiptError::Backend(format!("commit tx: {e}")))?;

        Ok(AppendOutcome {
            receipt_id,
            kind,
            seal: SealStatus::unsealed(),
        })
    }

    async fn get(&self, id: &Hash) -> Result<Option<Receipt>> {
        let digest = require_sha256(id)?;
        let row = sqlx::query(
            "SELECT receipt_id, swarm_id, actor, action_kind, constitution_version, \
                    occurred_at_ns, occurred_at_wall \
             FROM receipts WHERE receipt_id = $1",
        )
        .bind(digest)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ReceiptError::Backend(format!("get(receipts): {e}")))?;

        let Some(row) = row else { return Ok(None) };

        let receipt = rehydrate_receipt(&self.pool, row).await?;
        Ok(Some(receipt))
    }

    async fn query(&self, query: Query, page_token: Option<Vec<u8>>) -> Result<Page> {
        // ByReceiptId is 0-or-1; pagination doesn't apply.
        if let Query::ByReceiptId(id) = &query {
            let one = self.get(id).await?;
            return Ok(Page {
                receipts: one.into_iter().collect(),
                next_page_token: None,
            });
        }

        let cursor = page_token.as_deref().map(decode_cursor).transpose()?;
        // Fetch one extra row to detect whether a next page exists. If
        // exactly `page_limit + 1` rows come back, there's more; drop the
        // peeked row before rehydrating.
        let page_limit = self.page_limit;
        let fetch_limit = (page_limit as i64) + 1;

        // Each multi-row variant builds its own SQL string. The keyset is
        // `(occurred_at_ns, receipt_id)` ascending — `occurred_at_ns` is
        // indexed and `receipt_id` is the PK, so the cursor predicate
        // resolves with an index-only scan.
        let mut rows = match &query {
            Query::ByReceiptId(_) => unreachable!("ByReceiptId handled above"),
            Query::ByPredecessor(q) => {
                let digest = require_sha256(&q.predecessor)?;
                let sql = match &cursor {
                    None => {
                        "SELECT r.receipt_id, r.swarm_id, r.actor, r.action_kind, \
                                r.constitution_version, r.occurred_at_ns, r.occurred_at_wall \
                         FROM receipts r \
                         JOIN receipt_predecessors rp ON rp.receipt_id = r.receipt_id \
                         WHERE rp.predecessor = $1 \
                         ORDER BY r.occurred_at_ns, r.receipt_id \
                         LIMIT $2"
                    }
                    Some(_) => {
                        "SELECT r.receipt_id, r.swarm_id, r.actor, r.action_kind, \
                                r.constitution_version, r.occurred_at_ns, r.occurred_at_wall \
                         FROM receipts r \
                         JOIN receipt_predecessors rp ON rp.receipt_id = r.receipt_id \
                         WHERE rp.predecessor = $1 \
                           AND (r.occurred_at_ns, r.receipt_id) > ($3, $4) \
                         ORDER BY r.occurred_at_ns, r.receipt_id \
                         LIMIT $2"
                    }
                };
                let mut q = sqlx::query(sql).bind(digest).bind(fetch_limit);
                if let Some(c) = &cursor {
                    q = q.bind(c.occurred_at_ns).bind(c.receipt_id_digest.clone());
                }
                q.fetch_all(&self.pool)
                    .await
                    .map_err(|e| ReceiptError::Backend(format!("query(predecessor): {e}")))?
            }
            Query::ByAgent(q) => {
                let actor_uuid = Uuid::from_bytes(q.agent_id.as_bytes());
                let sql = match &cursor {
                    None => {
                        "SELECT receipt_id, swarm_id, actor, action_kind, constitution_version, \
                                occurred_at_ns, occurred_at_wall \
                         FROM receipts \
                         WHERE actor = $1 \
                         ORDER BY occurred_at_ns, receipt_id \
                         LIMIT $2"
                    }
                    Some(_) => {
                        "SELECT receipt_id, swarm_id, actor, action_kind, constitution_version, \
                                occurred_at_ns, occurred_at_wall \
                         FROM receipts \
                         WHERE actor = $1 \
                           AND (occurred_at_ns, receipt_id) > ($3, $4) \
                         ORDER BY occurred_at_ns, receipt_id \
                         LIMIT $2"
                    }
                };
                let mut q = sqlx::query(sql).bind(actor_uuid).bind(fetch_limit);
                if let Some(c) = &cursor {
                    q = q.bind(c.occurred_at_ns).bind(c.receipt_id_digest.clone());
                }
                q.fetch_all(&self.pool)
                    .await
                    .map_err(|e| ReceiptError::Backend(format!("query(agent): {e}")))?
            }
            Query::ByActionKind(q) => {
                let kind = q.action_kind.clone();
                let sql = match &cursor {
                    None => {
                        "SELECT receipt_id, swarm_id, actor, action_kind, constitution_version, \
                                occurred_at_ns, occurred_at_wall \
                         FROM receipts \
                         WHERE action_kind = $1 \
                         ORDER BY occurred_at_ns, receipt_id \
                         LIMIT $2"
                    }
                    Some(_) => {
                        "SELECT receipt_id, swarm_id, actor, action_kind, constitution_version, \
                                occurred_at_ns, occurred_at_wall \
                         FROM receipts \
                         WHERE action_kind = $1 \
                           AND (occurred_at_ns, receipt_id) > ($3, $4) \
                         ORDER BY occurred_at_ns, receipt_id \
                         LIMIT $2"
                    }
                };
                let mut q = sqlx::query(sql).bind(kind).bind(fetch_limit);
                if let Some(c) = &cursor {
                    q = q.bind(c.occurred_at_ns).bind(c.receipt_id_digest.clone());
                }
                q.fetch_all(&self.pool)
                    .await
                    .map_err(|e| ReceiptError::Backend(format!("query(action_kind): {e}")))?
            }
            Query::ByTimeRange(q) => {
                // Spec says monotonic_ns is authoritative for ordering;
                // we filter on it here. Wall-clock filtering across a
                // process restart is a Full-tier wrinkle covered by a
                // separate path once we tie monotonic restarts to a
                // stable epoch.
                let from = u64_to_i64(q.from.monotonic_ns);
                let to = u64_to_i64(q.to.monotonic_ns);
                let sql = match &cursor {
                    None => {
                        "SELECT receipt_id, swarm_id, actor, action_kind, constitution_version, \
                                occurred_at_ns, occurred_at_wall \
                         FROM receipts \
                         WHERE occurred_at_ns BETWEEN $1 AND $2 \
                         ORDER BY occurred_at_ns, receipt_id \
                         LIMIT $3"
                    }
                    Some(_) => {
                        "SELECT receipt_id, swarm_id, actor, action_kind, constitution_version, \
                                occurred_at_ns, occurred_at_wall \
                         FROM receipts \
                         WHERE occurred_at_ns BETWEEN $1 AND $2 \
                           AND (occurred_at_ns, receipt_id) > ($4, $5) \
                         ORDER BY occurred_at_ns, receipt_id \
                         LIMIT $3"
                    }
                };
                let mut q = sqlx::query(sql).bind(from).bind(to).bind(fetch_limit);
                if let Some(c) = &cursor {
                    q = q.bind(c.occurred_at_ns).bind(c.receipt_id_digest.clone());
                }
                q.fetch_all(&self.pool)
                    .await
                    .map_err(|e| ReceiptError::Backend(format!("query(time): {e}")))?
            }
        };

        // Peek-trim: if we got the +1 row, there's more; drop it.
        let has_more = rows.len() > page_limit;
        if has_more {
            rows.truncate(page_limit);
        }

        // Rehydrate, capture the last (ns, id) for the next-page cursor.
        let mut receipts = Vec::with_capacity(rows.len());
        let mut last_cursor: Option<Cursor> = None;
        for row in rows {
            let occurred_at_ns: i64 = row
                .try_get("occurred_at_ns")
                .map_err(|e| ReceiptError::Backend(format!("cursor decode occurred_at_ns: {e}")))?;
            let receipt_id: Vec<u8> = row
                .try_get("receipt_id")
                .map_err(|e| ReceiptError::Backend(format!("cursor decode receipt_id: {e}")))?;
            last_cursor = Some(Cursor {
                occurred_at_ns,
                receipt_id_digest: receipt_id,
            });
            receipts.push(rehydrate_receipt(&self.pool, row).await?);
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
        let row = sqlx::query("SELECT COUNT(*) AS c FROM receipts")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| ReceiptError::Backend(format!("count: {e}")))?;
        let c: i64 = row
            .try_get("c")
            .map_err(|e| ReceiptError::Backend(format!("count decode: {e}")))?;
        Ok(c.max(0) as u64)
    }
}

// -----------------------------------------------------------------------------
// SealStore impl (RFC 0014, /spec/verifiability/sui-anchoring.md §7)
// -----------------------------------------------------------------------------

#[async_trait]
impl SealStore for PostgresStore {
    async fn record_sealed_batch(&self, batch: &SealedBatch) -> Result<()> {
        if batch.leaves.is_empty() {
            return Err(ReceiptError::BatchInvalid(
                "sealed batch must contain at least one leaf".into(),
            ));
        }

        let root_digest = require_sha256(&batch.batch_root)?;
        let sealed_at_ns = u64_to_i64(batch.sealed_at.monotonic_ns);
        let sealed_at_wall = batch.sealed_at.wall_clock.clone();
        let on_chain_anchor: Option<Vec<u8>> = if batch.commitment_id.is_empty() {
            None
        } else {
            Some(batch.commitment_id.clone())
        };

        // All N row inserts go into a single transaction (atomicity is
        // the load-bearing property here per the spec doc §7.2). An
        // INSERT ... ON CONFLICT path handles the idempotent-reseal
        // case; conflicts where the existing row has a different
        // batch_root surface as BatchInvalid.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ReceiptError::Backend(format!("seal: begin tx: {e}")))?;

        for leaf in &batch.leaves {
            let receipt_digest = require_sha256(&leaf.leaf)?;
            let path_digests: Vec<Vec<u8>> = leaf
                .path
                .iter()
                .map(require_sha256)
                .collect::<Result<Vec<_>>>()?;

            // Step 1: detect a pre-existing seal with a conflicting root.
            // If the row exists with a different batch_root, abort — the
            // sealer-cadence loop should never produce this, so an error
            // indicates either a sealer bug or Postgres tampering. Either
            // way, refuse silently overwriting.
            let existing: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT batch_root FROM receipt_seal WHERE receipt_id = $1 FOR UPDATE",
            )
            .bind(&receipt_digest)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| ReceiptError::Backend(format!("seal: lookup existing: {e}")))?;

            if let Some(existing_root) = existing {
                if existing_root != root_digest {
                    return Err(ReceiptError::BatchInvalid(format!(
                        "receipt {} already sealed in a different batch",
                        hex_short(&receipt_digest)
                    )));
                }
                // Same batch_root → idempotent re-seal, skip insert.
                continue;
            }

            // Step 2: insert the new row.
            sqlx::query(
                "INSERT INTO receipt_seal \
                    (receipt_id, batch_root, merkle_path, sealed_at_ns, \
                     sealed_at_wall, on_chain_anchor_tx_digest) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&receipt_digest)
            .bind(&root_digest)
            .bind(&path_digests)
            .bind(sealed_at_ns)
            .bind(&sealed_at_wall)
            .bind(on_chain_anchor.as_deref())
            .execute(&mut *tx)
            .await
            .map_err(|e| ReceiptError::Backend(format!("seal: insert: {e}")))?;
        }

        tx.commit()
            .await
            .map_err(|e| ReceiptError::Backend(format!("seal: commit: {e}")))?;

        Ok(())
    }

    async fn seal_status(&self, receipt_id: &Hash) -> Result<SealStatus> {
        let digest = require_sha256(receipt_id)?;
        let row = sqlx::query(
            "SELECT batch_root, merkle_path, sealed_at_ns, sealed_at_wall, \
                    on_chain_anchor_tx_digest \
             FROM receipt_seal WHERE receipt_id = $1",
        )
        .bind(&digest)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ReceiptError::Backend(format!("seal_status: {e}")))?;

        let Some(row) = row else {
            // No seal row → unsealed (the spec's "neither in this map
            // nor anywhere else" case).
            return Ok(SealStatus::unsealed());
        };

        let root_digest: Vec<u8> = row
            .try_get("batch_root")
            .map_err(|e| ReceiptError::Backend(format!("seal_status decode root: {e}")))?;
        let batch_root = Hash::new(HashAlgorithm::Sha256, root_digest)
            .map_err(|e| ReceiptError::Backend(format!("seal_status: root not 32 bytes: {e}")))?;

        let path_digests: Vec<Vec<u8>> = row
            .try_get("merkle_path")
            .map_err(|e| ReceiptError::Backend(format!("seal_status decode path: {e}")))?;
        let merkle_path: Vec<Hash> = path_digests
            .into_iter()
            .map(|d| Hash::new(HashAlgorithm::Sha256, d))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                ReceiptError::Backend(format!("seal_status: path entry not 32 bytes: {e}"))
            })?;

        let sealed_at_ns_i64: i64 = row
            .try_get("sealed_at_ns")
            .map_err(|e| ReceiptError::Backend(format!("seal_status decode ns: {e}")))?;
        let sealed_at_wall: String = row
            .try_get("sealed_at_wall")
            .map_err(|e| ReceiptError::Backend(format!("seal_status decode wall: {e}")))?;
        let sealed_at = Timestamp::new(sealed_at_wall, i64_to_u64(sealed_at_ns_i64))
            .map_err(ReceiptError::Core)?;

        let on_chain: Option<Vec<u8>> = row
            .try_get("on_chain_anchor_tx_digest")
            .map_err(|e| ReceiptError::Backend(format!("seal_status decode anchor: {e}")))?;

        Ok(match on_chain {
            Some(tx_digest) => SealStatus::sealed_with_anchor(
                batch_root,
                merkle_path,
                sealed_at,
                tx_digest,
                Vec::new(), // swarm_anchor_object_id lives in runtime config, not Postgres
            ),
            None => SealStatus::sealed(batch_root, merkle_path, sealed_at),
        })
    }
}

/// Short hex for error messages.
fn hex_short(bytes: &[u8]) -> String {
    let take = bytes.len().min(8);
    let mut s = String::with_capacity(take * 2 + 3);
    for b in &bytes[..take] {
        s.push_str(&format!("{b:02x}"));
    }
    if bytes.len() > take {
        s.push_str("...");
    }
    s
}

// -----------------------------------------------------------------------------
// Pre-append verification (mirrors MemoryStore policy)
// -----------------------------------------------------------------------------

async fn verify_pre_append(receipt: &Receipt, resolver: &dyn PassportResolver) -> Result<()> {
    let actor_pk = resolver
        .resolve_actor(&receipt.actor)
        .await?
        .ok_or(ReceiptError::ActorNotResolvable(receipt.actor))?;

    let mut role_keys: HashMap<(SignatureRole, Vec<u8>), PublicKey> = HashMap::new();
    for sig in &receipt.signatures {
        if sig.role == SignatureRole::Actor {
            continue;
        }
        if let Some(pk) = resolver
            .resolve_role(sig.role, &sig.signature.key_fingerprint)
            .await?
        {
            role_keys.insert((sig.role, sig.signature.key_fingerprint.clone()), pk);
        }
    }

    yutha_receipt::verify_receipt_signatures(receipt, &actor_pk, |role, fingerprint| {
        role_keys.get(&(role, fingerprint.to_vec())).cloned()
    })?;

    Ok(())
}

// -----------------------------------------------------------------------------
// Insert helpers (within a single transaction)
// -----------------------------------------------------------------------------

/// Insert the row in `receipts`. Returns true iff a fresh row was inserted
/// (false on idempotent collision).
async fn insert_receipt(
    tx: &mut Transaction<'_, Postgres>,
    r: &Receipt,
    receipt_id: &Hash,
    canonical: &[u8],
) -> Result<bool> {
    let digest = require_sha256(receipt_id)?;
    let result = sqlx::query(
        "INSERT INTO receipts \
            (receipt_id, swarm_id, actor, action_kind, constitution_version, \
             occurred_at_ns, occurred_at_wall, canonical_bytes) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (receipt_id) DO NOTHING",
    )
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
    .map_err(|e| ReceiptError::Backend(format!("insert receipts: {e}")))?;

    Ok(result.rows_affected() > 0)
}

async fn insert_predecessors(
    tx: &mut Transaction<'_, Postgres>,
    receipt_id: &Hash,
    causal: &CausalRef,
) -> Result<()> {
    let digest = require_sha256(receipt_id)?;
    for p in &causal.predecessors {
        let pdig = require_sha256(p)?;
        sqlx::query(
            "INSERT INTO receipt_predecessors (receipt_id, predecessor) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind(digest.to_vec())
        .bind(pdig)
        .execute(&mut **tx)
        .await
        .map_err(|e| ReceiptError::Backend(format!("insert predecessors: {e}")))?;
    }
    Ok(())
}

async fn insert_signatures(
    tx: &mut Transaction<'_, Postgres>,
    receipt_id: &Hash,
    signatures: &[SignedBy],
) -> Result<()> {
    let digest = require_sha256(receipt_id)?;
    for s in signatures {
        sqlx::query(
            "INSERT INTO receipt_signatures \
                (receipt_id, role, algorithm, signature, key_fingerprint, signed_at_ns, signed_at_wall) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(digest.to_vec())
        .bind(i32::from(s.role.rank()))
        .bind(s.signature.algorithm.to_wire())
        .bind(&s.signature.value)
        .bind(&s.signature.key_fingerprint)
        .bind(u64_to_i64(s.signed_at.monotonic_ns))
        .bind(&s.signed_at.wall_clock)
        .execute(&mut **tx)
        .await
        .map_err(|e| ReceiptError::Backend(format!("insert signatures: {e}")))?;
    }
    Ok(())
}

async fn insert_evidence(
    tx: &mut Transaction<'_, Postgres>,
    receipt_id: &Hash,
    evidence: &[Evidence],
) -> Result<()> {
    let digest = require_sha256(receipt_id)?;
    for (ord, e) in evidence.iter().enumerate() {
        sqlx::query(
            "INSERT INTO receipt_evidence (receipt_id, ord, key, type_url, value, sensitive) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(digest.to_vec())
        .bind(ord as i32)
        .bind(&e.key)
        .bind(&e.type_url)
        .bind(&e.value)
        .bind(e.sensitive)
        .execute(&mut **tx)
        .await
        .map_err(|e| ReceiptError::Backend(format!("insert evidence: {e}")))?;
    }
    Ok(())
}

async fn insert_cost(
    tx: &mut Transaction<'_, Postgres>,
    receipt_id: &Hash,
    cost: &CostAnnotation,
) -> Result<()> {
    let digest = require_sha256(receipt_id)?;
    sqlx::query(
        "INSERT INTO receipt_cost \
            (receipt_id, input_tokens, output_tokens, tool_call_count, wall_time_ms, \
             usd_cents_estimate, model_provider, model_name, model_version) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(digest)
    .bind(u64_to_i64(cost.input_tokens))
    .bind(u64_to_i64(cost.output_tokens))
    .bind(u64_to_i64(cost.tool_call_count))
    .bind(u64_to_i64(cost.wall_time_ms))
    .bind(&cost.usd_cents_estimate)
    .bind(&cost.model_provider)
    .bind(&cost.model_name)
    .bind(&cost.model_version)
    .execute(&mut **tx)
    .await
    .map_err(|e| ReceiptError::Backend(format!("insert cost: {e}")))?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Read-side rehydration
// -----------------------------------------------------------------------------

/// Rebuild a `Receipt` from a row plus the related-row lookups.
async fn rehydrate_receipt(pool: &PgPool, row: PgRow) -> Result<Receipt> {
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

    // Related rows. These are 3-5 small queries; the receipt store isn't a
    // latency-hot path. If profiling later flags this, denormalize or use
    // an aggregate JSON query.
    let causal = fetch_predecessors(pool, &receipt_id).await?;
    let signatures = fetch_signatures(pool, &receipt_id).await?;
    let evidence = fetch_evidence(pool, &receipt_id).await?;
    let cost = fetch_cost(pool, &receipt_id).await?;

    let mut receipt = Receipt::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap()) // see note below
        .swarm_id(SwarmId::from_bytes(swarm_uuid.as_bytes()).map_err(ReceiptError::Core)?)
        .actor(AgentId::from_bytes(actor_uuid.as_bytes()).map_err(ReceiptError::Core)?)
        .action_kind(action_kind)
        .causal(causal)
        .constitution_version(constitution_version)
        .occurred_at(occurred_at);

    if let Some(c) = cost {
        receipt = receipt.cost(c);
    }
    for e in evidence {
        receipt = receipt.evidence(e);
    }
    let mut receipt = receipt.build().map_err(|e| {
        ReceiptError::Backend(format!("rehydrate: builder rejected required field: {e}"))
    })?;
    receipt.signatures = signatures;
    // NOTE on spec_version: the receipts table doesn't currently store it
    // (every receipt at this stage is v1.0). A future spec-version
    // migration adds a column and the read path pulls it through.

    Ok(receipt)
}

async fn fetch_predecessors(pool: &PgPool, id: &Hash) -> Result<CausalRef> {
    let digest = require_sha256(id)?;
    let rows = sqlx::query("SELECT predecessor FROM receipt_predecessors WHERE receipt_id = $1")
        .bind(digest)
        .fetch_all(pool)
        .await
        .map_err(|e| ReceiptError::Backend(format!("fetch predecessors: {e}")))?;
    let mut hashes = Vec::with_capacity(rows.len());
    for row in rows {
        let p: Vec<u8> = row
            .try_get("predecessor")
            .map_err(|e| ReceiptError::Backend(format!("decode predecessor: {e}")))?;
        hashes.push(Hash::new(HashAlgorithm::Sha256, p).map_err(ReceiptError::Core)?);
    }
    Ok(CausalRef::from_iter(hashes))
}

async fn fetch_signatures(pool: &PgPool, id: &Hash) -> Result<Vec<SignedBy>> {
    let digest = require_sha256(id)?;
    let rows = sqlx::query(
        "SELECT role, algorithm, signature, key_fingerprint, signed_at_ns, signed_at_wall \
         FROM receipt_signatures WHERE receipt_id = $1 ORDER BY role",
    )
    .bind(digest)
    .fetch_all(pool)
    .await
    .map_err(|e| ReceiptError::Backend(format!("fetch signatures: {e}")))?;

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

async fn fetch_evidence(pool: &PgPool, id: &Hash) -> Result<Vec<Evidence>> {
    let digest = require_sha256(id)?;
    let rows = sqlx::query(
        "SELECT key, type_url, value, sensitive \
         FROM receipt_evidence WHERE receipt_id = $1 ORDER BY ord",
    )
    .bind(digest)
    .fetch_all(pool)
    .await
    .map_err(|e| ReceiptError::Backend(format!("fetch evidence: {e}")))?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let key: String = row.try_get("key").map_err(|e| dec("key", e))?;
        let type_url: String = row.try_get("type_url").map_err(|e| dec("type_url", e))?;
        let value: Vec<u8> = row.try_get("value").map_err(|e| dec("value", e))?;
        let sensitive: bool = row.try_get("sensitive").map_err(|e| dec("sensitive", e))?;
        out.push(Evidence {
            key,
            type_url,
            value,
            sensitive,
        });
    }
    Ok(out)
}

async fn fetch_cost(pool: &PgPool, id: &Hash) -> Result<Option<CostAnnotation>> {
    let digest = require_sha256(id)?;
    let row = sqlx::query(
        "SELECT input_tokens, output_tokens, tool_call_count, wall_time_ms, \
                usd_cents_estimate, model_provider, model_name, model_version \
         FROM receipt_cost WHERE receipt_id = $1",
    )
    .bind(digest)
    .fetch_optional(pool)
    .await
    .map_err(|e| ReceiptError::Backend(format!("fetch cost: {e}")))?;

    let Some(row) = row else { return Ok(None) };

    let input_tokens: i64 = row
        .try_get("input_tokens")
        .map_err(|e| dec("input_tokens", e))?;
    let output_tokens: i64 = row
        .try_get("output_tokens")
        .map_err(|e| dec("output_tokens", e))?;
    let tool_call_count: i64 = row
        .try_get("tool_call_count")
        .map_err(|e| dec("tool_call_count", e))?;
    let wall_time_ms: i64 = row
        .try_get("wall_time_ms")
        .map_err(|e| dec("wall_time_ms", e))?;
    let usd_cents_estimate: String = row
        .try_get("usd_cents_estimate")
        .map_err(|e| dec("usd_cents_estimate", e))?;
    let model_provider: String = row
        .try_get("model_provider")
        .map_err(|e| dec("model_provider", e))?;
    let model_name: String = row
        .try_get("model_name")
        .map_err(|e| dec("model_name", e))?;
    let model_version: String = row
        .try_get("model_version")
        .map_err(|e| dec("model_version", e))?;

    Ok(Some(CostAnnotation {
        input_tokens: i64_to_u64(input_tokens),
        output_tokens: i64_to_u64(output_tokens),
        tool_call_count: i64_to_u64(tool_call_count),
        wall_time_ms: i64_to_u64(wall_time_ms),
        usd_cents_estimate,
        model_provider,
        model_name,
        model_version,
    }))
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Extract the 32-byte SHA-256 digest from a [`Hash`]; reject other
/// algorithms because the schema only stores SHA-256 digests at v1.0.
fn require_sha256(h: &Hash) -> Result<Vec<u8>> {
    match h.algorithm {
        HashAlgorithm::Sha256 => Ok(h.digest.clone()),
        other => Err(ReceiptError::Backend(format!(
            "postgres backend stores SHA-256 only at v1.0 (got {other:?})"
        ))),
    }
}

fn role_from_rank(rank: i32) -> Result<SignatureRole> {
    Ok(match rank {
        0 => SignatureRole::Actor,
        1 => SignatureRole::ControlPlane,
        2 => SignatureRole::Supervisor,
        3 => SignatureRole::Attestation,
        4 => SignatureRole::BatchRoot,
        other => {
            return Err(ReceiptError::Backend(format!(
                "unknown signature role rank: {other}"
            )))
        }
    })
}

/// Translate Rust `u64` (monotonic_ns / token counts) to Postgres `BIGINT`
/// (`i64`). Values above `i64::MAX` are saturated; for monotonic_ns this is
/// well outside any realistic process lifetime.
fn u64_to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn i64_to_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn dec(field: &'static str, e: sqlx::Error) -> ReceiptError {
    ReceiptError::Backend(format!("decode {field}: {e}"))
}

// -----------------------------------------------------------------------------
// Pagination
// -----------------------------------------------------------------------------

/// Default page size for multi-row queries. Tuned for a v0.1 alpha: large
/// enough that single-page responses are common, small enough that
/// rehydration latency stays bounded. Operators who need a different
/// number wait for the spec to grow a `QueryOptions.limit` field
/// (`AppendOptions.page_limit` is misnamed — pagination is a query
/// concept; that field lives on the wrong struct).
const DEFAULT_PAGE_LIMIT: usize = 256;

/// Keyset cursor for pagination.
///
/// Encodes the position "the last row returned was `(occurred_at_ns,
/// receipt_id_digest)`". The next page starts strictly after this position
/// in `(occurred_at_ns, receipt_id)` lex order.
#[derive(Debug, Clone)]
struct Cursor {
    occurred_at_ns: i64,
    receipt_id_digest: Vec<u8>,
}

/// Cursor token format: 40 raw bytes.
///
/// ```text
/// offset | len | content
/// -------|-----|--------------------------
///   0    |  8  | occurred_at_ns, BE i64
///   8    | 32  | receipt_id (SHA-256 digest)
/// ```
///
/// The token is opaque to callers — they pass back whatever
/// `Page::next_page_token` returned and the next call decodes it. The
/// format is deliberately compact and version-free; if we need to evolve
/// it, we'll add a leading version byte and bump.
const CURSOR_LEN: usize = 8 + 32;

fn encode_cursor(c: &Cursor) -> Vec<u8> {
    let mut out = Vec::with_capacity(CURSOR_LEN);
    out.extend_from_slice(&c.occurred_at_ns.to_be_bytes());
    // Defensive: pad/truncate to 32 bytes. The schema enforces 32-byte
    // SHA-256 digests, so this should always be exact; the clamp guards
    // against a future schema change that doesn't update the cursor
    // format.
    let mut id = c.receipt_id_digest.clone();
    id.resize(32, 0);
    out.extend_from_slice(&id);
    out
}

fn decode_cursor(bytes: &[u8]) -> Result<Cursor> {
    if bytes.len() != CURSOR_LEN {
        return Err(ReceiptError::InvalidQuery(format!(
            "page token has wrong length: expected {CURSOR_LEN}, got {}",
            bytes.len()
        )));
    }
    let mut ns_buf = [0u8; 8];
    ns_buf.copy_from_slice(&bytes[..8]);
    let occurred_at_ns = i64::from_be_bytes(ns_buf);
    let receipt_id_digest = bytes[8..].to_vec();
    Ok(Cursor {
        occurred_at_ns,
        receipt_id_digest,
    })
}

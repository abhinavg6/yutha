//! [`ReplayStore`] — Phase 3c (RFC 0018 §4) replay-session storage.
//!
//! Sibling trait to [`ReceiptStore`]. A `ReplayStore` carries
//! per-session receipt stores: every replay session lives in its own
//! isolated [`ReceiptStore`] handle obtained via [`ReplayStore::session_store`].
//! Within-session receipts are partitioned from production and from
//! each other; the existing in-process code that takes
//! `Arc<dyn ReceiptStore>` (`build_eval_request_for_send`, eval-receipt
//! emitters, etc.) operates unchanged on the session-scoped handle.
//!
//! ## Isolation invariants (RFC 0018 §4.3 / §4.4)
//!
//! - **Session isolation.** A receipt appended via
//!   `session_store(A)` MUST NOT appear in queries against
//!   `session_store(B)` or against the production store. Memory
//!   backend enforces this by giving every session its own
//!   [`MemoryStore`] instance.
//! - **Never-anchors.** The [`crate::ReceiptStore`] handles returned
//!   from `session_store` are NOT wrapped in a publishing decorator,
//!   so replay receipts never enter the production enforcement-engine
//!   forwarder. The `AnchorDriver`'s `ReceiptStoreCandidateSource`
//!   is bound to the production store only — replay handles are
//!   distinct `Arc`s and the anchor driver provably can't see them.
//!
//! ## Backends
//!
//! - **Memory backend (this file).** [`MemoryReplayStore`] is the
//!   reference implementation; used by tests, by the conformance
//!   harness, and by `yutha-control-plane --receipt-backend memory`.
//!   Each session gets its own [`MemoryStore`] instance for
//!   isolation. Not for production: no durability, no
//!   cross-process visibility.
//! - **Postgres backend** lives in
//!   [`yutha-backend-postgres-receipt`'s `replay` module] —
//!   `PostgresReplayStore` shares the same pool as `PostgresStore`
//!   (the production receipt store), and the replay schema is
//!   provisioned by the same `PostgresStore::migrate()` call. RFC
//!   0018 §4.1 isolation is enforced at the schema level: per-session
//!   receipts live in a distinct `replay_*` table family with
//!   composite `(session_id, receipt_id)` primary keys, and the
//!   session-scoped handle does NOT implement [`crate::SealStore`]
//!   (type-system enforcement of the never-anchors invariant).
//!
//! [`yutha-backend-postgres-receipt`'s `replay` module]: https://github.com/abhinavg6/yutha/blob/main/backends/postgres-receipt/src/replay.rs

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::{ReceiptError, Result};
use crate::memory::MemoryStore;
use crate::store::ReceiptStore;
use yutha_core::Timestamp;

/// Identifier for a replay session. UUIDv7 — time-ordered so listing
/// sessions surfaces them by creation order without an explicit sort.
/// Mirrors the [`yutha_core::AgentId`] / [`yutha_core::SwarmId`]
/// convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReplaySessionId(pub Uuid);

impl ReplaySessionId {
    /// Construct a new session id with a fresh UUIDv7 value.
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// The 16-byte big-endian representation.
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Default for ReplaySessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl FromStr for ReplaySessionId {
    type Err = uuid::Error;

    /// Parse a session id from its canonical UUID string form
    /// (`urn:uuid:...` or hyphenated). Callers can use the `&str ->
    /// ReplaySessionId` conversion via `s.parse::<ReplaySessionId>()`.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Uuid::parse_str(s).map(Self)
    }
}

impl std::fmt::Display for ReplaySessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hyphenated UUID form — what surfaces in receipts'
        // `replay_session_id` evidence and in `yutha-ops replay
        // list` output.
        self.0.fmt(f)
    }
}

/// Engine state-init mode for a replay session (RFC 0018 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ReplayMode {
    /// Engine starts at defaults. Per RFC 0018 §4.2.
    Cold,
    /// Engine state rebuilt from receipts preceding
    /// `window.from_unix_ns` for `warm_lookback_hours`. Per RFC 0018
    /// §4.2.
    Warm,
}

/// Receipt-window selection for a replay session (RFC 0018 §4.1).
/// Strict triple per the locked spec — no arbitrary-predicate
/// flexibility today (additive RFC if a more flexible surface
/// becomes necessary).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReplaySessionWindow {
    /// Inclusive lower bound, monotonic_ns. The window includes
    /// receipts with `occurred_at.monotonic_ns >= from_unix_ns`.
    pub from_unix_ns: u64,
    /// Inclusive upper bound, monotonic_ns.
    pub to_unix_ns: u64,
    /// Whitelist of action-kinds to replay. Empty = replay every
    /// receipt in the window. Non-empty = replay only listed kinds.
    pub action_kind_filter: Vec<String>,
}

/// Metadata describing one replay session. Returned from
/// [`ReplayStore::list_sessions`]; passed by value into
/// [`ReplayStore::create_session`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReplaySessionMetadata {
    /// The session id.
    pub session_id: ReplaySessionId,
    /// Content-address of the candidate constitution this session
    /// previews. Surfaces in operator listings as the join key back
    /// to the audit `replay.session.create` receipt's evidence.
    pub candidate_constitution_hash: yutha_core::Hash,
    /// Convenience: candidate constitution version string.
    pub candidate_constitution_version: String,
    /// Receipt window this session replays against.
    pub window: ReplaySessionWindow,
    /// Cold or warm engine-init mode.
    pub mode: ReplayMode,
    /// Warm-mode lookback hours. Ignored when `mode == Cold`.
    pub warm_lookback_hours: u32,
    /// When the session was created (server wall_clock + monotonic).
    pub created_at: Timestamp,
    /// Last `RunSession` activity timestamp. Used by the TTL
    /// auto-close path.
    pub last_active_at: Timestamp,
    /// Cumulative replay receipts emitted by this session so far.
    pub receipts_replayed: u64,
}

/// A store of per-session replay receipt stores.
///
/// Implementations partition receipts by session: a receipt appended
/// via `session_store(A)` MUST NOT be visible via `session_store(B)`
/// or via the production store.
///
/// Conformance per RFC 0018 §4.1: implementations MUST support
/// `create_session` / `delete_session` / `list_sessions` and MUST
/// return a `ReceiptStore` handle from `session_store` that satisfies
/// the same Append / Lookup / Query contracts as production
/// [`ReceiptStore`] implementations, but scoped to the session.
#[async_trait]
pub trait ReplayStore: Send + Sync {
    /// Returns a [`ReceiptStore`] handle scoped to the session.
    ///
    /// Calling `session_store(id)` for a session that has not been
    /// created via `create_session` MAY return a usable handle
    /// (memory backend) or MAY return an empty/error handle
    /// (Postgres backend); behaviour is implementation-defined.
    /// Callers should always `create_session` first.
    fn session_store(&self, session_id: &ReplaySessionId) -> Arc<dyn ReceiptStore>;

    /// Create a new session. Initialises any backing state (in-memory
    /// inner store or Postgres schema) and records the metadata.
    /// Returns [`ReceiptError::AppendOnly`] when called with a
    /// `session_id` that already exists — sessions are unique and
    /// session ids are not reusable.
    async fn create_session(&self, metadata: ReplaySessionMetadata) -> Result<()>;

    /// Delete a session. Drops every within-session receipt and
    /// releases the backing state. Idempotent — deleting a session
    /// that doesn't exist is a no-op (the caller's intent — "this
    /// session is gone" — is satisfied).
    async fn delete_session(&self, session_id: &ReplaySessionId) -> Result<()>;

    /// List all sessions in creation order. UUIDv7 ordering is the
    /// natural sort key.
    async fn list_sessions(&self) -> Result<Vec<ReplaySessionMetadata>>;

    /// Look up metadata for one session. Returns `None` when the
    /// session has been deleted or never existed.
    async fn get_session(
        &self,
        session_id: &ReplaySessionId,
    ) -> Result<Option<ReplaySessionMetadata>>;

    /// Update the `last_active_at` + `receipts_replayed` counters on
    /// a session. Called by the orchestrator after each
    /// `play_receipt` and at TTL-check intervals. Returns
    /// `ReceiptError::ActorNotResolvable` analogue — we don't have a
    /// session-not-found error variant today, so we reuse the
    /// existing taxonomy by returning Ok even when the session is
    /// gone (the orchestrator will discover the mismatch on the next
    /// `get_session`).
    async fn touch_session(
        &self,
        session_id: &ReplaySessionId,
        receipts_replayed_delta: u64,
        now: &Timestamp,
    ) -> Result<()>;
}

// =============================================================================
// MemoryReplayStore
// =============================================================================

/// In-memory reference implementation of [`ReplayStore`].
///
/// Used by tests, by the conformance harness, and by
/// `yutha-control-plane --receipt-backend memory`. Not for
/// production: no durability, no cross-process visibility. Each
/// session gets its own [`MemoryStore`] instance for isolation —
/// drop a session and its receipts disappear with it.
///
/// Thread-safe via `tokio::sync::RwLock`; cloneable handles share
/// state via the inner `Arc`.
#[derive(Debug, Clone, Default)]
pub struct MemoryReplayStore {
    inner: Arc<RwLock<MemoryReplayStoreInner>>,
}

#[derive(Debug, Default)]
struct MemoryReplayStoreInner {
    /// Per-session state. Each value owns its own MemoryStore
    /// instance — no shared HashMap key namespacing, full isolation.
    sessions: HashMap<ReplaySessionId, SessionSlot>,
}

#[derive(Debug)]
struct SessionSlot {
    store: Arc<MemoryStore>,
    metadata: ReplaySessionMetadata,
}

impl MemoryReplayStore {
    /// New empty replay store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ReplayStore for MemoryReplayStore {
    fn session_store(&self, session_id: &ReplaySessionId) -> Arc<dyn ReceiptStore> {
        // Synchronous read of the session map. We block_in_place the
        // tokio RwLock here by going through try_read; if it fails
        // (writer in flight) we fall back to a fresh empty
        // MemoryStore — the caller will discover the session is
        // unknown via list_sessions or get_session.
        //
        // Practical note: `session_store` is called from the
        // orchestrator AFTER `create_session` succeeds, so the slot
        // is always present. The fallback is a defensive default
        // that satisfies the trait's "returns a usable handle"
        // contract; behaviour is implementation-defined per the
        // doc-comment on the trait.
        //
        // We use try_read instead of blocking_read here because the
        // method is sync and `blocking_read` on a tokio runtime
        // would panic. try_read returning None means a writer holds
        // the lock — that's racy with create_session itself, so the
        // caller's "always create first" discipline protects us.
        if let Ok(guard) = self.inner.try_read() {
            if let Some(slot) = guard.sessions.get(session_id) {
                return Arc::clone(&slot.store) as Arc<dyn ReceiptStore>;
            }
        }
        // Fallback: empty store. The session is either unknown or
        // racing creation; subsequent get_session calls will
        // surface the truth.
        Arc::new(MemoryStore::new()) as Arc<dyn ReceiptStore>
    }

    async fn create_session(&self, metadata: ReplaySessionMetadata) -> Result<()> {
        let mut guard = self.inner.write().await;
        if guard.sessions.contains_key(&metadata.session_id) {
            // ReceiptError::Backend is the closest existing variant
            // for "this store rejected the call due to a state
            // conflict". A dedicated SessionConflict variant could
            // be added if the orchestrator needs to distinguish
            // session conflicts from generic backend errors.
            return Err(ReceiptError::Backend(format!(
                "replay session {} already exists",
                metadata.session_id
            )));
        }
        let store = Arc::new(MemoryStore::new());
        guard
            .sessions
            .insert(metadata.session_id, SessionSlot { store, metadata });
        Ok(())
    }

    async fn delete_session(&self, session_id: &ReplaySessionId) -> Result<()> {
        let mut guard = self.inner.write().await;
        guard.sessions.remove(session_id);
        Ok(())
    }

    async fn list_sessions(&self) -> Result<Vec<ReplaySessionMetadata>> {
        let guard = self.inner.read().await;
        // UUIDv7 ordering gives natural creation-time order — the
        // BTreeMap-like sort by key works because ReplaySessionId
        // is Ord.
        let mut metadata: Vec<ReplaySessionMetadata> = guard
            .sessions
            .values()
            .map(|s| s.metadata.clone())
            .collect();
        metadata.sort_by_key(|a| a.session_id);
        Ok(metadata)
    }

    async fn get_session(
        &self,
        session_id: &ReplaySessionId,
    ) -> Result<Option<ReplaySessionMetadata>> {
        let guard = self.inner.read().await;
        Ok(guard.sessions.get(session_id).map(|s| s.metadata.clone()))
    }

    async fn touch_session(
        &self,
        session_id: &ReplaySessionId,
        receipts_replayed_delta: u64,
        now: &Timestamp,
    ) -> Result<()> {
        let mut guard = self.inner.write().await;
        if let Some(slot) = guard.sessions.get_mut(session_id) {
            slot.metadata.last_active_at = now.clone();
            slot.metadata.receipts_replayed = slot
                .metadata
                .receipts_replayed
                .saturating_add(receipts_replayed_delta);
        }
        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::AppendOptions;
    use crate::receipt::ReceiptBuilder;
    use crate::signing::{SignatureRole, SignedBy};
    use crate::Evidence;
    use yutha_core::{AgentId, HashAlgorithm, PublicKey, SpecVersion, SwarmId};
    use yutha_crypto::canonical::Canonical;
    use yutha_crypto::sign::generate_keypair;

    fn fresh_metadata() -> ReplaySessionMetadata {
        ReplaySessionMetadata {
            session_id: ReplaySessionId::new(),
            candidate_constitution_hash: yutha_core::Hash::new(
                HashAlgorithm::Sha256,
                vec![0xC0u8; 32],
            )
            .unwrap(),
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

    fn signed_receipt(actor: AgentId) -> (crate::Receipt, AgentId, PublicKey) {
        let key = generate_keypair();
        let mut r = ReceiptBuilder::new()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(SwarmId::from_bytes(&[0x42; 16]).unwrap())
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
    async fn create_then_list_sees_session() {
        let store = MemoryReplayStore::new();
        let meta = fresh_metadata();
        let id = meta.session_id;
        store.create_session(meta).await.unwrap();
        let sessions = store.list_sessions().await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, id);
    }

    #[tokio::test]
    async fn create_twice_with_same_id_errors() {
        let store = MemoryReplayStore::new();
        let meta = fresh_metadata();
        let id = meta.session_id;
        store.create_session(meta.clone()).await.unwrap();
        let mut second = meta;
        second.session_id = id; // same id
        let err = store.create_session(second).await.unwrap_err();
        assert!(matches!(err, ReceiptError::Backend(_)));
    }

    #[tokio::test]
    async fn delete_removes_session() {
        let store = MemoryReplayStore::new();
        let meta = fresh_metadata();
        let id = meta.session_id;
        store.create_session(meta).await.unwrap();
        store.delete_session(&id).await.unwrap();
        assert!(store.get_session(&id).await.unwrap().is_none());
        assert!(store.list_sessions().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_nonexistent_is_idempotent() {
        let store = MemoryReplayStore::new();
        store
            .delete_session(&ReplaySessionId::new())
            .await
            .expect("idempotent");
    }

    #[tokio::test]
    async fn session_store_isolates_appends_between_sessions() {
        let store = MemoryReplayStore::new();
        let a_meta = fresh_metadata();
        let b_meta = fresh_metadata();
        let a_id = a_meta.session_id;
        let b_id = b_meta.session_id;
        store.create_session(a_meta).await.unwrap();
        store.create_session(b_meta).await.unwrap();

        let a_store = store.session_store(&a_id);
        let b_store = store.session_store(&b_id);

        // Append to A's store.
        let (receipt, actor, pk) = signed_receipt(AgentId::new());
        let resolver = crate::passport::StaticPassportResolver::new().with_actor(actor, pk);
        let outcome = a_store
            .append(receipt.clone(), AppendOptions::default(), &resolver)
            .await
            .unwrap();

        // A sees it; B does not.
        assert!(a_store.get(&outcome.receipt_id).await.unwrap().is_some());
        assert!(
            b_store.get(&outcome.receipt_id).await.unwrap().is_none(),
            "session B MUST NOT see receipts appended to session A — RFC 0018 §4.1 isolation invariant"
        );
        assert_eq!(a_store.count().await.unwrap(), 1);
        assert_eq!(b_store.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn touch_session_updates_counters() {
        let store = MemoryReplayStore::new();
        let meta = fresh_metadata();
        let id = meta.session_id;
        store.create_session(meta).await.unwrap();

        let now = Timestamp::now();
        store.touch_session(&id, 7, &now).await.unwrap();
        let after = store.get_session(&id).await.unwrap().unwrap();
        assert_eq!(after.receipts_replayed, 7);
        assert_eq!(after.last_active_at, now);

        // Subsequent touches accumulate.
        store.touch_session(&id, 3, &now).await.unwrap();
        let after2 = store.get_session(&id).await.unwrap().unwrap();
        assert_eq!(after2.receipts_replayed, 10);
    }

    #[tokio::test]
    async fn touch_nonexistent_is_silent_noop() {
        let store = MemoryReplayStore::new();
        let id = ReplaySessionId::new();
        // No create_session — touch should not panic or error.
        store
            .touch_session(&id, 1, &Timestamp::now())
            .await
            .expect("silent no-op");
        assert!(store.get_session(&id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn replay_session_id_string_round_trip() {
        let id = ReplaySessionId::new();
        let s = id.to_string();
        let parsed: ReplaySessionId = s.parse().expect("parses");
        assert_eq!(id, parsed);
    }
}

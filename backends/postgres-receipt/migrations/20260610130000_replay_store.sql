-- Phase 3c follow-on: PostgresReplayStore schema (RFC 0018 §4).
--
-- Adds the per-session replay tables. Replay receipts live in a
-- distinct table family from production receipts; queries against
-- `receipts` never see replay rows, queries against
-- `replay_receipts` always carry a `session_id = $1` filter. The
-- isolation invariant from RFC 0018 §4.1 holds at the schema level:
-- a row in `replay_receipts` for session A is not joinable to any
-- production-store query path.
--
-- Cascade semantics: `replay_sessions` is the parent; every per-
-- receipt row has `ON DELETE CASCADE` on `session_id` so
-- `delete_session(id)` removes the session metadata plus all its
-- receipts in a single statement.

-- Per-session metadata. Mirrors `ReplaySessionMetadata` field-for-
-- field. `mode` is stored as TEXT ('cold' | 'warm') for readability
-- in `psql` over a tighter-fitting smallint.
CREATE TABLE replay_sessions (
    session_id                       UUID        PRIMARY KEY,
    candidate_constitution_hash      BYTEA       NOT NULL,
    candidate_constitution_version   TEXT        NOT NULL,
    window_from_unix_ns              BIGINT      NOT NULL,
    window_to_unix_ns                BIGINT      NOT NULL,
    action_kind_filter               TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
    mode                             TEXT        NOT NULL CHECK (mode IN ('cold','warm')),
    warm_lookback_hours              INTEGER     NOT NULL DEFAULT 0,
    created_at_ns                    BIGINT      NOT NULL,
    created_at_wall                  TEXT        NOT NULL,
    last_active_at_ns                BIGINT      NOT NULL,
    last_active_at_wall              TEXT        NOT NULL,
    receipts_replayed                BIGINT      NOT NULL DEFAULT 0,
    inserted_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Per-session receipts. Composite PK `(session_id, receipt_id)`
-- means the same content-address can appear in multiple sessions
-- (each is a physically-distinct row), but is unique within one
-- session — idempotent re-append collapses via ON CONFLICT DO
-- NOTHING.
CREATE TABLE replay_receipts (
    session_id           UUID        NOT NULL REFERENCES replay_sessions(session_id) ON DELETE CASCADE,
    receipt_id           BYTEA       NOT NULL,                 -- SHA-256 content-address
    swarm_id             UUID        NOT NULL,
    actor                UUID        NOT NULL,
    action_kind          TEXT        NOT NULL,
    constitution_version TEXT        NOT NULL,
    occurred_at_ns       BIGINT      NOT NULL,                 -- monotonic ns
    occurred_at_wall     TEXT        NOT NULL,                 -- RFC 3339
    canonical_bytes      BYTEA       NOT NULL,
    inserted_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (session_id, receipt_id)
);

-- "All replay receipts for one session at a given action_kind" is
-- the `yutha-ops replay-query` access path. The (session_id,
-- action_kind) compound index makes it index-only.
CREATE INDEX replay_receipts_by_session_action_kind
    ON replay_receipts (session_id, action_kind);

-- Per-session time-range scans — the cursor predicate in `query()`
-- uses (occurred_at_ns, receipt_id) keyset pagination per session.
CREATE INDEX replay_receipts_by_session_occurred_at
    ON replay_receipts (session_id, occurred_at_ns, receipt_id);

-- Predecessor edges. Composite PK plus the session_id include is
-- necessary to keep session A's chain isolated from session B's
-- chain even when receipts content-collide.
CREATE TABLE replay_receipt_predecessors (
    session_id   UUID  NOT NULL,
    receipt_id   BYTEA NOT NULL,
    predecessor  BYTEA NOT NULL,
    PRIMARY KEY (session_id, receipt_id, predecessor),
    FOREIGN KEY (session_id, receipt_id) REFERENCES replay_receipts(session_id, receipt_id) ON DELETE CASCADE
);

-- "What depends on X?" within one session.
CREATE INDEX replay_receipt_predecessors_by_session_predecessor
    ON replay_receipt_predecessors (session_id, predecessor);

CREATE TABLE replay_receipt_signatures (
    session_id      UUID    NOT NULL,
    receipt_id      BYTEA   NOT NULL,
    role            INTEGER NOT NULL,
    algorithm       INTEGER NOT NULL,
    signature       BYTEA   NOT NULL,
    key_fingerprint BYTEA   NOT NULL,
    signed_at_ns    BIGINT  NOT NULL,
    signed_at_wall  TEXT    NOT NULL,
    PRIMARY KEY (session_id, receipt_id, role),
    FOREIGN KEY (session_id, receipt_id) REFERENCES replay_receipts(session_id, receipt_id) ON DELETE CASCADE
);

CREATE TABLE replay_receipt_evidence (
    session_id UUID    NOT NULL,
    receipt_id BYTEA   NOT NULL,
    ord        INTEGER NOT NULL,
    key        TEXT    NOT NULL,
    type_url   TEXT    NOT NULL,
    value      BYTEA   NOT NULL,
    sensitive  BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (session_id, receipt_id, ord),
    FOREIGN KEY (session_id, receipt_id) REFERENCES replay_receipts(session_id, receipt_id) ON DELETE CASCADE
);

-- NOTE: no `replay_receipt_cost` table. Replay-emitted receipts are
-- canonical `enforcement.*` shapes per RFC 0018 §4.3; they don't
-- carry `CostAnnotation`. If a future replay path produces
-- cost-bearing receipts, add the parallel table here.
--
-- NOTE: no `replay_receipt_seal` table. The AnchorDriver is bound
-- to the production store only (RFC 0018 §4.4); replay receipts
-- never seal. The PostgresSessionScopedStore impl does NOT
-- implement `SealStore`, which is the type-system enforcement of
-- this invariant.

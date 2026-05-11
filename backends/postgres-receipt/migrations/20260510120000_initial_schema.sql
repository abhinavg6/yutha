-- Initial schema for the Postgres receipt store.
--
-- Per /spec/receipt/receipt-v1.proto and the receipt rationale:
--   * receipt_id is the SHA-256 content-address of the canonical receipt
--     bytes (32 bytes, BYTEA).
--   * append-only: the application enforces this via the ReceiptStore trait
--     surface (no update or delete methods). Production deployments SHOULD
--     additionally restrict the application's database role to
--     INSERT-only (no UPDATE/DELETE grants on these tables) for defense in
--     depth.
--   * canonical_bytes is stored alongside the parsed columns to support
--     bytewise re-verification and bulk-export manifests; this is a small
--     storage tax for a large audit benefit.

CREATE TABLE receipts (
    receipt_id           BYTEA       PRIMARY KEY,             -- SHA-256 content-address (32 bytes)
    swarm_id             UUID        NOT NULL,
    actor                UUID        NOT NULL,
    action_kind          TEXT        NOT NULL,
    constitution_version TEXT        NOT NULL,
    occurred_at_ns       BIGINT      NOT NULL,                 -- monotonic ns
    occurred_at_wall     TEXT        NOT NULL,                 -- RFC 3339
    canonical_bytes      BYTEA       NOT NULL,                 -- stored for re-verification
    inserted_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for "all receipts for a given actor" queries (Full conformance §3.3).
CREATE INDEX receipts_by_actor
    ON receipts (actor);

-- Index for "all receipts of a given action kind" queries.
CREATE INDEX receipts_by_action_kind
    ON receipts (action_kind);

-- Index for time-range queries; uses monotonic_ns per spec.
CREATE INDEX receipts_by_occurred_at
    ON receipts (occurred_at_ns);

-- Predecessor edges. Two-column primary key dedupes the (receipt, predecessor)
-- pair; the by-predecessor index serves "what depends on X?" queries (Core
-- conformance §3.3).
CREATE TABLE receipt_predecessors (
    receipt_id  BYTEA NOT NULL REFERENCES receipts(receipt_id),
    predecessor BYTEA NOT NULL,
    PRIMARY KEY (receipt_id, predecessor)
);

CREATE INDEX receipt_predecessors_by_predecessor
    ON receipt_predecessors (predecessor);

-- Signatures, in canonical wire order. The role column stores the
-- SignatureRole::rank() integer (Actor=0, ControlPlane=1, Supervisor=2,
-- Attestation=3, BatchRoot=4); the (receipt_id, role) primary key enforces
-- "at most one signature per role per receipt."
CREATE TABLE receipt_signatures (
    receipt_id      BYTEA   NOT NULL REFERENCES receipts(receipt_id),
    role            INTEGER NOT NULL,
    algorithm       INTEGER NOT NULL,
    signature       BYTEA   NOT NULL,
    key_fingerprint BYTEA   NOT NULL,
    signed_at_ns    BIGINT  NOT NULL,
    signed_at_wall  TEXT    NOT NULL,
    PRIMARY KEY (receipt_id, role)
);

-- Evidence entries. Stored separately to keep the receipts table narrow and
-- to support cheap "list evidence by key" queries during audit / replay.
CREATE TABLE receipt_evidence (
    receipt_id BYTEA   NOT NULL REFERENCES receipts(receipt_id),
    ord        INTEGER NOT NULL,                                -- preserves order from the receipt
    key        TEXT    NOT NULL,
    type_url   TEXT    NOT NULL,
    value      BYTEA   NOT NULL,
    sensitive  BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (receipt_id, ord)
);

-- Cost annotations. One row per receipt that carries a CostAnnotation; null
-- if the receipt did not record one. Decimal as TEXT because Postgres NUMERIC
-- and Rust f64 disagree on edge cases and we want exact aggregation.
CREATE TABLE receipt_cost (
    receipt_id         BYTEA  PRIMARY KEY REFERENCES receipts(receipt_id),
    input_tokens       BIGINT NOT NULL,
    output_tokens      BIGINT NOT NULL,
    tool_call_count    BIGINT NOT NULL,
    wall_time_ms       BIGINT NOT NULL,
    usd_cents_estimate TEXT   NOT NULL,
    model_provider     TEXT   NOT NULL,
    model_name         TEXT   NOT NULL,
    model_version      TEXT   NOT NULL
);

-- Sealing state. Receipts in this table have been Merkle-batched. Receipts
-- not in this table are unsealed.
CREATE TABLE receipt_seal (
    receipt_id     BYTEA   PRIMARY KEY REFERENCES receipts(receipt_id),
    batch_root     BYTEA   NOT NULL,
    merkle_path    BYTEA[] NOT NULL,
    sealed_at_ns   BIGINT  NOT NULL,
    sealed_at_wall TEXT    NOT NULL
);

# yutha-backend-postgres-receipt

Postgres backend implementation of the Yutha `ReceiptStore`. The default backend for self-hosted deployments.

## Status

**Skeleton.** Cargo.toml and the trait `impl` shell are in place; method bodies are `todo!()` pending implementation. The conformance suite is wired in as a dev-dep and will run against a live Postgres in CI once the bodies land.

## Schema

Schema migrations live in `./migrations/`. The `sqlx` build-time SQL check uses a Postgres at `$DATABASE_URL` for compile-time query validation; CI provides one (see `.github/workflows/ci.yml`).

Tables (planned):

```sql
CREATE TABLE receipts (
    receipt_id      BYTEA PRIMARY KEY,         -- content-address (32 bytes)
    swarm_id        UUID  NOT NULL,
    actor           UUID  NOT NULL,
    action_kind     TEXT  NOT NULL,
    constitution_version TEXT NOT NULL,
    occurred_at_ns  BIGINT NOT NULL,           -- monotonic
    occurred_at_wall TEXT NOT NULL,            -- RFC 3339
    -- canonical_bytes stored for audit; not strictly required
    canonical_bytes BYTEA NOT NULL,
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX receipts_by_actor ON receipts (actor);
CREATE INDEX receipts_by_action_kind ON receipts (action_kind);
CREATE INDEX receipts_by_occurred_at ON receipts (occurred_at_ns);

CREATE TABLE receipt_predecessors (
    receipt_id    BYTEA NOT NULL REFERENCES receipts(receipt_id),
    predecessor   BYTEA NOT NULL,
    PRIMARY KEY (receipt_id, predecessor)
);

CREATE INDEX receipt_predecessors_by_predecessor
    ON receipt_predecessors (predecessor);

CREATE TABLE receipt_signatures (
    receipt_id    BYTEA NOT NULL REFERENCES receipts(receipt_id),
    role          INTEGER NOT NULL,            -- SignatureRole::rank()
    algorithm     INTEGER NOT NULL,
    signature     BYTEA   NOT NULL,
    key_fingerprint BYTEA NOT NULL,
    signed_at_ns  BIGINT  NOT NULL,
    signed_at_wall TEXT   NOT NULL,
    PRIMARY KEY (receipt_id, role)
);
```

Append-only enforcement uses Postgres role permissions (the application role gets INSERT but not UPDATE / DELETE on these tables) plus an explicit guard in the implementation.

## Conformance

Targets Core + Full per [`/docs/conformance/conformance-suite.md`](../../docs/conformance/conformance-suite.md) §3.3. Verifiable tier lives in `walrus-receipt`.

## Reference

- [`/spec/receipt/`](../../spec/receipt/)
- [`/crates/yutha-receipt/`](../../crates/yutha-receipt/) — trait being implemented.

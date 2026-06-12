# Sui Receipt Anchoring — Specification (v1)

> **RFC:** [0014](../rfcs/0014-sui-receipt-anchoring.md)
> **Predecessors:** [RFC 0004](../rfcs/0004-receipt-v1.md) (defines `SealStatus`, the `BatchRoot` signature role, the `receipt_seal` table)
> **Phase:** Phase 3 (pre-public-release v1)
> **Status:** Draft, design-frozen
> **Out of scope:** Walrus cold-storage of sealed batches (Layer 2); on-chain constitution objects (Layer 3)

## 0. Scope

This document specifies the wire-level, byte-exact, and operational contract for receipt anchoring against the Sui blockchain. It is the detail spec the RFC defers to; conformant implementations MUST honor everything pinned here.

What this document does NOT specify: the *implementation* of the sealer (a background subsystem of the control plane). What it specifies is the contract every conformant implementation honors — same receipts in, same Merkle root + same signing preimage + same Move-call PTB out.

The companion RFC ([0014](../rfcs/0014-sui-receipt-anchoring.md)) is the document of record for the high-level design decisions.

---

## 1. The anchoring contract

A single anchor flow is a four-step progression:

```
              ┌──────────────────────────────────────────────────────────┐
              │ Receipt store (Postgres)                                 │
              │   ↓ unanchored receipts (watermark < occurred_at_ns)     │
              │                                                          │
              │   Sealer — batches, builds Merkle tree, signs preimage   │
              │                                                          │
              │   ┌───────────┐    ┌───────────────┐    ┌──────────────┐ │
              │   │ collect   │ →  │ Merkle root + │ →  │ Move call:    │ │
              │   │ batch     │    │ canonical sig │    │ commit_batch  │ │
              │   └───────────┘    └───────────────┘    └──────────────┘ │
              │       ↑                                       ↓          │
              │       │                                       │          │
              │   hybrid time/count                  Sui tx digest +     │
              │   cadence trigger                    block timestamp     │
              │                                               │          │
              │       ┌───────────────────────────────────────┘          │
              │       ↓                                                  │
              │   Postgres receipt_seal rows + anchor.commit receipt     │
              └──────────────────────────────────────────────────────────┘
```

Five concrete properties:

1. **Anchoring is opt-in.** The substrate works without it. Deployments not opting in use the `LocalSealer` no-op or have no sealer wired in at all. The Postgres write path is untouched.

2. **Postgres is primary, Sui is best-effort.** Sui RPC unavailability MUST NOT block writes. Unanchored receipts accumulate; the sealer catches up when Sui recovers. The control plane's send-path latency is unaffected by anchoring health.

3. **Operator-owned everything.** Each operator deploys their own copy of the Move package to whichever Sui network they target (mainnet / testnet / localnet / custom). The operator holds the package's `UpgradeCap`. There is no Yutha-operated canonical deployment, no shared registry, no Yutha-held upgrade authority.

4. **Network-agnostic at runtime.** The control plane's anchor flags do not encode network identity — only `--anchor-sui-rpc-url <url>`. The same binary anchors to mainnet, testnet, or a self-hosted full-node by changing the URL + the package id + the swarm-anchor id.

5. **Single-key trust model in v1.** One Ed25519 sealer keypair per swarm. The on-chain Move module enforces that anchors come from the registered key. Multi-key / supervisor-multisig is deferred to Phase 4.

---

## 2. The `Sealer` trait

The trait surface in `yutha-receipt`:

```rust
use async_trait::async_trait;
use std::collections::BTreeMap;
use thiserror::Error;
use yutha_core::{Hash, Timestamp};

#[async_trait]
pub trait Sealer: Send + Sync + std::fmt::Debug {
    /// Seal a batch of receipts. Implementations MUST:
    ///   1. Compute the Merkle root over the receipts' canonical bytes,
    ///      ordered by `occurred_at_ns` ascending, ties broken by
    ///      `receipt_id` lex-ascending.
    ///   2. Compute per-receipt Merkle paths (siblings from leaf to root,
    ///      in leaf→root order).
    ///   3. Submit the commitment to the verifiability backend
    ///      (Sui transaction, no-op log, etc.).
    ///   4. Return a `SealedBatch` describing the batch + backend
    ///      commitment id.
    ///
    /// The control plane runs this in a background task; failures here
    /// MUST NOT block receipt appends. Implementations SHOULD retry
    /// transient backend failures (configurable bound) before surfacing
    /// the error.
    async fn seal_batch(
        &self,
        receipts: &[Receipt],
    ) -> Result<SealedBatch, SealError>;
}

#[derive(Debug, Clone)]
pub struct SealedBatch {
    /// SHA-256 Merkle root over the batch's receipt canonical bytes.
    pub batch_root: Hash,
    /// Per-receipt Merkle paths. `merkle_paths[i]` is the path from the
    /// i-th receipt (in the input order, AFTER sorting by occurred_at_ns)
    /// to `batch_root`. Each path entry is a sibling hash; verifier walks
    /// leaf→root.
    pub merkle_paths: Vec<Vec<Hash>>,
    /// Wall-clock + monotonic timestamp the sealer recorded at commit time.
    pub sealed_at: Timestamp,
    /// Per-action-kind count over the batch. Keys are canonical
    /// action_kind strings ("envelope.send" etc.); values are the number
    /// of receipts in the batch with that action_kind. Sum of values
    /// equals receipts.len().
    pub action_kind_histogram: BTreeMap<String, u64>,
    /// Backend-specific commitment id. For SuiSealer: 32-byte Sui tx digest
    /// of the commit_batch transaction. For LocalSealer: empty bytes.
    pub commitment_id: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum SealError {
    #[error("empty batch: at least one receipt required")]
    EmptyBatch,
    #[error("merkle construction failed: {0}")]
    MerkleError(String),
    #[error("backend transient failure (retryable): {0}")]
    Transient(String),
    #[error("backend permanent failure: {0}")]
    Permanent(String),
    #[error("signing failed: {0}")]
    SigningError(String),
}
```

The trait is intentionally backend-agnostic. The control plane holds an `Arc<dyn Sealer>` and calls it from the sealer background task; nothing in the trait surface is Sui-specific.

### 2.1 `LocalSealer` — the default no-op

```rust
pub struct LocalSealer;

#[async_trait]
impl Sealer for LocalSealer {
    async fn seal_batch(&self, receipts: &[Receipt]) -> Result<SealedBatch, SealError> {
        // Compute root + paths exactly like SuiSealer, but skip the
        // backend submit step. Useful for local development and tests:
        // sealing is observable through the receipt_seal Postgres rows
        // without any external dependency.
        let root_and_paths = compute_merkle(receipts)?;
        let histogram = compute_histogram(receipts);
        Ok(SealedBatch {
            batch_root: root_and_paths.root,
            merkle_paths: root_and_paths.paths,
            sealed_at: Timestamp::now(),
            action_kind_histogram: histogram,
            commitment_id: Vec::new(),
        })
    }
}
```

`LocalSealer` is what the control plane wires in when `--anchor-backend` is unset or set to `local`. Deployments not opting into Sui anchoring still get a populated `receipt_seal` table (useful for "is this receipt sealed?" queries) without any external commitment.

---

## 3. Merkle tree construction

### 3.1 Leaf canonicalization

The leaf bytes for a receipt are the **canonical receipt bytes with all signatures cleared** — exactly the same byte representation that produces the `receipt_id`. This means: the Merkle leaf is the receipt's content-address preimage, and the receipt_id IS the leaf hash (saves a hash round per receipt).

Formally, `leaf_hash[i] = receipt[i].receipt_id` after sorting.

### 3.2 Sort order

Receipts in a batch MUST be ordered by `(occurred_at_ns ASC, receipt_id ASC)`. The receipt_id tiebreaker exists because two receipts can share an `occurred_at_ns` (the substrate's monotonic counter is per-actor; cross-actor ties are real). Lexicographic byte-ordering on the receipt_id is deterministic and well-defined.

Implementations MUST refuse to seal a batch with duplicate receipt_ids; that's an upstream bug worth surfacing.

### 3.3 Tree construction (sorted-pair hashing)

Binary Merkle tree, SHA-256 throughout. Internal-node hashing uses the **sorted-pair convention**: at each level, the two child hashes are sorted lex-ascending before concatenation. Formally:

```
parent(a, b) = sha256(min(a.digest, b.digest) || max(a.digest, b.digest))
```

For an odd-count level, the last leaf is duplicated (the Bitcoin / CT convention) before pairing — this means a 2-leaf batch produces a depth-1 tree, a 3-leaf batch produces a depth-2 tree with the third leaf duplicated at the bottom, and so on. With sorted-pair hashing, `parent(a, a) = sha256(a.digest || a.digest)`, which is well-defined.

The 1-receipt edge case: root = the receipt's id itself, no parent hashing.

**Why sorted-pair rather than positional.** Sorted-pair removes the need to track left/right direction info in the wire-format path. A verifier reconstructs the root with:

```
verify_path(leaf, path, expected_root):
    current = leaf
    for sibling in path:
        current = parent(current, sibling)
    return current == expected_root
```

No direction bits, no per-entry left/right tracking, no auxiliary fields on `SealStatus`. The standard alternative (positional with explicit direction bits) is also correct but requires either a parallel `directions: bytes` field on `SealStatus` or encoding direction info into the path entries themselves — both more complex than sorted-pair for our use case.

The security tradeoff: with sorted-pair, only the SET of leaves at each level matters, not their positions. An attacker would need to find two distinct leaf-orderings producing the same root to mount a 2nd-preimage attack — infeasible under SHA-256 collision resistance, and the canonical leaf ordering (§3.2) prevents this anyway.

### 3.4 Merkle path construction

For each leaf `i` in the sorted order, the path is the list of sibling hashes encountered walking from the leaf to the root:

```
path[i] = [sibling(level=0, leaf=i),
           sibling(level=1, parent_of(i, 0)),
           ...
           sibling(level=depth-1, ...)]
```

Length of `path[i]` equals the tree depth (= `ceil(log2(N))` for N leaves). For the 1-leaf degenerate case, `path[0] = []` (empty; the leaf is itself the root).

### 3.5 Wire encoding of `merkle_path`

`SealStatus.merkle_path` is a `repeated Hash` field on the wire — just the list of sibling hashes, in leaf→root order. No direction bits needed. A verifier reconstructs the root via the sorted-pair recurrence above; the only wire-level requirement is that consumers iterate `merkle_path` in order and hash each sibling against the accumulating `current` value using the sorted-pair function.

Implementations MUST document the sorted-pair convention in their `SealStatus` decoder.

### 3.6 Determinism vectors

Conformance vectors land at `/spec/vectors/sui-anchoring/merkle/`:
- `merkle_1.json` — 1-receipt batch (degenerate; root == leaf)
- `merkle_2.json` — 2-receipt batch
- `merkle_3.json` — 3-receipt batch (odd, last leaf duplicated)
- `merkle_8.json` — 8-receipt batch (balanced)
- `merkle_100.json` — typical batch size
- `merkle_1000.json` — max-batch-size boundary case

Each vector is a `{receipts: [...], expected_root: "<hex>", expected_paths: [["<hex>", ...], ...]}` JSON document. The Rust unit tests in `yutha-receipt` consume these directly.

---

## 4. Canonical preimage encoding

The sealer signs a deterministic preimage that the on-chain Move function reconstructs byte-for-byte before calling `ed25519_verify`. The byte layout:

```
preimage =
    swarm_id (16 bytes)              ‖
    batch_root (32 bytes)            ‖
    count (u64 big-endian, 8 bytes)  ‖
    ns_range_start (u64 BE, 8 bytes) ‖
    ns_range_end (u64 BE, 8 bytes)   ‖
    canonical_histogram_bytes
```

Total fixed-part size: `16 + 32 + 8 + 8 + 8 = 72 bytes`. Histogram size is variable; see §4.1.

### 4.1 Canonical histogram bytes

The histogram is a `Map<String, u64>`. The canonical byte form:

```
canonical_histogram_bytes =
    entry_count (u32 BE, 4 bytes) ‖
    entries (entry_count of them, in lex-ascending order by action_kind):
        each entry =
            action_kind_len (u8, 1 byte) ‖
            action_kind (UTF-8 bytes, length = action_kind_len) ‖
            count (u64 BE, 8 bytes)
```

Constraints:
- `entry_count` MUST equal the number of distinct action_kinds in the batch.
- Entries MUST be sorted lex-ascending by `action_kind` (UTF-8 byte ordering).
- `action_kind_len` MUST be between 1 and 255 (inclusive). The wire format (u8) self-enforces the upper bound. The canonical action_kinds are all well within this; workload-extension action_kinds inherit the same bound — see §10 cardinality bound. Implementations rejecting overlong keys before the wire-encode step is recommended for clearer error reporting.
- `count` MUST be non-zero (action_kinds with zero occurrences are NOT serialized).
- Sum of all `count` values MUST equal the batch's receipt count.

The encoding is round-trip lossless: an external verifier given the canonical histogram bytes can fully reconstruct the `Map<String, u64>` without ambiguity.

### 4.2 Signature

The sealer's Ed25519 signature over the preimage is the standard 64-byte form. Computed as `ed25519_sign(sealer_private_key, preimage)`.

### 4.3 Preimage determinism vectors

`/spec/vectors/sui-anchoring/preimage/`:
- `preimage_empty_histogram.json` — degenerate single-receipt batch
- `preimage_single_kind.json` — all receipts same action_kind
- `preimage_multi_kind.json` — 5 distinct kinds, varying counts
- `preimage_workload_kinds.json` — includes workload-extension action_kinds (e.g. `Yutha::SupportQueue::Action::IssueRefund`)
- `preimage_unicode_action_kind.json` — non-ASCII characters in an action_kind name (edge case for UTF-8 byte ordering)

Each vector pins the `(inputs, expected_preimage_hex, expected_signature_hex)` triple, using a fixed Ed25519 keypair so the signature is reproducible.

---

## 5. Sui Move module

The reference Move source lives at `/contracts/sui/receipt_anchor/`. Operators MUST publish their own copy of this package; Yutha does not maintain a canonical mainnet deployment.

### 5.1 Module layout

```
/contracts/sui/receipt_anchor/
    Move.toml
    sources/
        receipt_anchor.move
    tests/
        receipt_anchor_tests.move
```

### 5.2 The `SwarmAnchor` shared object

```move
public struct SwarmAnchor has key {
    id: UID,
    swarm_id: vector<u8>,            // 16 bytes
    sealer_pubkey: vector<u8>,        // 32 bytes, raw Ed25519
    batch_count: u64,                 // monotonic; serves as batch_index
    last_ns_range_end: u64,           // for ordering invariants
    created_at_ms: u64,
}
```

One per swarm. Shared object (so anyone can call `commit_batch` on it — the signature check is the gate, not Move's ownership semantics).

### 5.3 The `AnchorCommitted` event

```move
public struct AnchorCommitted has copy, drop {
    swarm_id: vector<u8>,
    batch_index: u64,
    batch_root: vector<u8>,                                // 32 bytes
    count: u64,
    ns_range_start: u64,
    ns_range_end: u64,
    action_kind_histogram: VecMap<vector<u8>, u64>,        // keys are UTF-8 bytes
    anchored_at_ms: u64,
}
```

Emitted once per successful `commit_batch` call. Sui indexers (Suiscan, Suivision, self-hosted) consume this stream.

### 5.4 Entry functions

```move
public entry fun create_swarm_anchor(
    swarm_id: vector<u8>,
    sealer_pubkey: vector<u8>,
    clock: &sui::clock::Clock,
    ctx: &mut TxContext,
) { /* validate lengths, create + share */ }

public entry fun commit_batch(
    anchor: &mut SwarmAnchor,
    batch_root: vector<u8>,
    count: u64,
    ns_range_start: u64,
    ns_range_end: u64,
    action_kind_histogram: VecMap<vector<u8>, u64>,
    sealer_signature: vector<u8>,
    clock: &sui::clock::Clock,
    ctx: &mut TxContext,
) {
    // 1. Length checks: batch_root == 32, sealer_signature == 64,
    //    swarm_id == 16, etc.
    // 2. Monotonic check: ns_range_start >= anchor.last_ns_range_end.
    // 3. Reconstruct the canonical preimage (§4) byte-for-byte.
    // 4. ed25519_verify(sealer_signature, anchor.sealer_pubkey, preimage)
    //    — abort with ESealerKeyMismatch on failure.
    // 5. anchor.batch_count = anchor.batch_count + 1.
    // 6. anchor.last_ns_range_end = ns_range_end.
    // 7. emit AnchorCommitted event with the current clock time.
}
```

### 5.5 Move abort codes

| Code | Constant | Meaning |
|------|----------|---------|
| 1 | `EBatchRootLength` | `batch_root` is not 32 bytes |
| 2 | `ESignatureLength` | `sealer_signature` is not 64 bytes |
| 3 | `EPubkeyLength` | `sealer_pubkey` is not 32 bytes |
| 4 | `ESwarmIdLength` | `swarm_id` is not 16 bytes |
| 5 | `ENsRangeNotMonotonic` | `ns_range_start < anchor.last_ns_range_end` |
| 6 | `ENsRangeInvalid` | `ns_range_end < ns_range_start` |
| 7 | `EHistogramSumMismatch` | sum of histogram values ≠ `count` |
| 8 | `EHistogramKeyTooLong` | a histogram key exceeds 255 bytes |
| 9 | `ESealerKeyMismatch` | `ed25519_verify` returned false |
| 10 | `EHistogramNotSorted` | histogram entries arrived out of lex-ascending key order |

The `EHistogramNotSorted` code surfaces the most common Rust-side bug cleanly: if the sealer somehow constructs the VecMap with out-of-order keys, the Move-reconstructed canonical preimage won't match the sealer's signed bytes, and signature verification would fail with `ESealerKeyMismatch` — leaving the operator with no clear hint about which side went wrong. The explicit sort-order check makes the actual cause unambiguous.

### 5.6 Upgrade model

The operator who publishes the package holds the `UpgradeCap` returned by `sui client publish`. Upgrades are at the operator's discretion. Operators MUST preserve the canonical preimage construction (§4) and the abort-code semantics (§5.5) across upgrades, or third-party verifiers using off-chain preimage reconstruction will diverge from the on-chain check. Major-version changes that alter the preimage or abort-code semantics MUST be a new package id with a fresh `SwarmAnchor` per swarm.

### 5.7 Move tests

`tests/receipt_anchor_tests.move` MUST cover:
- Happy path: valid signature → tx accepted, event emitted, batch_count incremented.
- Wrong signer: signature over preimage by a different key → aborts with `ESealerKeyMismatch`.
- Tampered preimage: signature valid for original preimage, but a mutated field on-chain → aborts (signature won't match reconstructed preimage).
- Monotonic violation: second `commit_batch` with `ns_range_start < prev.ns_range_end` → aborts with `ENsRangeNotMonotonic`.
- Histogram sum mismatch: `count=10` but histogram values sum to 9 → aborts with `EHistogramSumMismatch`.
- Length validations: all five length-check abort codes hit by malformed input.

---

## 6. The sealer cadence loop

### 6.1 Configuration surface

The control plane exposes these flags (CLI + env-var pairs):

| Flag | Env var | Default | Meaning |
|------|---------|---------|---------|
| `--anchor-backend` | `YUTHA_ANCHOR_BACKEND` | `none` | One of `none`, `local`, `sui`. Default `none` disables sealing entirely. `local` uses `LocalSealer` (Postgres-only). `sui` activates `SuiSealer` and requires the flags below. |
| `--anchor-sui-rpc-url` | `YUTHA_ANCHOR_SUI_RPC_URL` | — | Sui JSON-RPC endpoint. Mainnet / testnet / localnet / custom all supported. |
| `--anchor-sui-package-id` | `YUTHA_ANCHOR_SUI_PACKAGE_ID` | — | The published `receipt_anchor` package id (hex with `0x` prefix). |
| `--anchor-swarm-anchor-id` | `YUTHA_ANCHOR_SWARM_ANCHOR_ID` | — | The per-swarm `SwarmAnchor` shared-object id (hex with `0x` prefix). |
| `--anchor-sealer-key-file` | `YUTHA_ANCHOR_SEALER_KEY_FILE` | — | Path to a Sui-format keystore file containing the sealer Ed25519 keypair. |
| `--anchor-batch-count-threshold` | `YUTHA_ANCHOR_BATCH_COUNT` | `100` | Maximum receipts per batch. Sealer triggers when this is reached. |
| `--anchor-batch-time-threshold` | `YUTHA_ANCHOR_BATCH_TIME` | `10s` | Maximum age (since last sealed batch) before a new batch fires regardless of count. Parsed as humantime (e.g. `5s`, `1m`, `2h`). |
| `--anchor-max-batch-size` | `YUTHA_ANCHOR_MAX_BATCH_SIZE` | `1000` | Hard ceiling on a single batch's size (protects against backlog blowouts after RPC downtime). |
| `--anchor-retry-attempts` | `YUTHA_ANCHOR_RETRY_ATTEMPTS` | `5` | Max retries per batch on transient Sui RPC failure before giving up and retrying on the next cadence tick. |

If `--anchor-backend sui` is set, all of the `sui-*` flags except the optional sizing knobs MUST be provided. The control plane fails fast at startup if any required flag is missing.

### 6.2 Watermark

The sealer tracks one piece of state: the highest `monotonic_ns` it has already sealed (the **watermark**). On startup:

1. Query Sui for the `SwarmAnchor` shared object → read `last_ns_range_end`.
2. Set the in-memory watermark to that value.

On every successful `seal_batch`:

3. Advance the watermark to the batch's `ns_range_end`.

Failure mid-batch (Sui tx submitted but no confirmation received) leaves the watermark unchanged; the next iteration re-discovers the receipts and retries. The Move-side monotonic check rejects duplicate batches automatically, so retry-safety is on-chain-enforced.

### 6.3 Cadence loop pseudocode

```
loop {
    candidates = postgres.query_receipts_with_ns_gt(watermark)
                         .limit(max_batch_size)
                         .order_by(monotonic_ns ASC, receipt_id ASC)

    seconds_since_last_seal = now - last_seal_at

    if len(candidates) >= batch_count_threshold
       OR (len(candidates) > 0 AND seconds_since_last_seal >= batch_time_threshold):
        try:
            batch = sealer.seal_batch(candidates)
            postgres.update_receipt_seal(candidates, batch.merkle_paths, batch.batch_root,
                                          batch.commitment_id)
            control_plane.emit_anchor_commit_receipt(batch)
            watermark = candidates.last().occurred_at_ns
            last_seal_at = now
        except SealError::Transient(_):
            sleep(retry_backoff)
            continue
        except SealError::Permanent(_):
            alert_operator("sealer permanent failure; investigate")
            sleep(long_backoff)

    sleep(min(batch_time_threshold - seconds_since_last_seal, poll_interval))
}
```

### 6.4 Hybrid cadence semantics

The "or" in the trigger condition gives the hybrid behavior:

- **High-throughput swarm:** `len(candidates) >= 100` fires first; batches arrive on the count cadence; time threshold is irrelevant.
- **Quiet swarm:** `len(candidates) < 100` indefinitely, but eventually `seconds_since_last_seal >= 10` fires; batches arrive on the time cadence. Important: this means a swarm with only a handful of receipts/minute still gets sub-minute anchoring latency.
- **Zero-traffic swarm:** `len(candidates) == 0` keeps the loop idle; no anchor is created until traffic resumes. This is correct — there's nothing to anchor.

### 6.5 First-batch corner case

On a fresh swarm with `batch_count = 0` and `last_ns_range_end = 0`, the first batch is normal (no monotonic check to satisfy). The first batch's `ns_range_start` is whatever the first receipt's `occurred_at_ns` is, which is fine.

### 6.6 Sealer crash recovery

After a sealer process crash, restart:
1. Query Sui for `SwarmAnchor.last_ns_range_end` → set watermark.
2. Begin the cadence loop.

If the crashed sealer had submitted a Sui tx that wasn't confirmed before the crash, the new sealer's first `commit_batch` call will fail on the Move-side monotonic check (the tx eventually confirms and bumps `last_ns_range_end`; the new sealer re-reads on a subsequent loop iteration and aligns). Alternatively, the failed tx never confirms and the new sealer re-attempts with the same `ns_range_start` and the Move-side check accepts (since `last_ns_range_end` was never advanced).

---

## 7. Postgres integration

### 7.1 `receipt_seal` table

Existing schema (per `/backends/postgres-receipt/migrations/20260510120000_initial_schema.sql`):

```sql
CREATE TABLE receipt_seal (
    receipt_id     BYTEA   PRIMARY KEY REFERENCES receipts(receipt_id),
    batch_root     BYTEA   NOT NULL,
    merkle_path    BYTEA[] NOT NULL,
    sealed_at_ns   BIGINT  NOT NULL,
    sealed_at_wall TEXT    NOT NULL
);
```

This RFC adds one nullable column:

```sql
ALTER TABLE receipt_seal
    ADD COLUMN on_chain_anchor_tx_digest BYTEA;
```

A row populated by `LocalSealer` leaves this column NULL. A row populated by `SuiSealer` sets it to the 32-byte Sui tx digest. Conformant readers MUST treat NULL as "sealed locally only" and a non-NULL value as "anchored to the verifiability backend identified by `commitment_id` shape."

### 7.2 Atomic update

For each batch, the sealer MUST update Postgres atomically (single transaction): all N `receipt_seal` rows insert together, or none do. Implementations MUST NOT leave a partial batch in `receipt_seal` — a partial state would let a verifier reconstruct a different (wrong) Merkle root.

The recommended SQL pattern:

```sql
BEGIN;
INSERT INTO receipt_seal (receipt_id, batch_root, merkle_path,
                          sealed_at_ns, sealed_at_wall, on_chain_anchor_tx_digest)
VALUES (...), (...), (...), ...;
COMMIT;
```

If Postgres rejects the transaction (constraint violation, etc.), the sealer MUST NOT consider the batch sealed — the Sui tx, if it landed, becomes a "phantom anchor" that points at no Postgres rows. Implementations MUST emit an operator-alert in this case (detection: `commit_batch` succeeded on Sui but the Postgres INSERT failed).

---

## 8. Receipt evidence: `anchor.commit`

Each successful Sui anchor produces an `anchor.commit` receipt. Evidence shape:

```
action_kind: anchor.commit
actor:       Control plane (the sealer's signing identity is the control plane's identity for receipt-actor purposes)
evidence: {
    batch_root: <32-byte hex>,
    batch_index: <u64, the value of SwarmAnchor.batch_count BEFORE this commit>,
    count: <u64, number of receipts in the batch>,
    ns_range_start: <u64>,
    ns_range_end: <u64>,
    on_chain_tx_digest: <32-byte hex, the Sui tx digest>,
    swarm_anchor_object_id: <32-byte hex, the shared-object id>,
    action_kind_histogram: <canonical histogram bytes from §4.1, hex>,
    anchored_at_wall_clock: <RFC 3339, from the Sui block clock or local wall-clock fallback>,
}
```

Note: the `anchor.commit` receipt is itself eligible for inclusion in a later batch. The sealer MUST NOT exclude it from candidate lookups. This is intentional — the audit trail of "when we anchored" is part of the audit trail.

A receipt with `action_kind = "anchor.commit"` is signed by the control plane only (no Actor signature — the anchor is a substrate operation, not an agent action).

---

## 9. Failure modes

### 9.1 Sui RPC unavailable

The sealer logs a `WARN` line with the RPC error, sleeps for the retry backoff, and tries again. The cadence loop continues; unanchored receipts accumulate beyond the time threshold; the next successful tx commits a larger-than-usual batch (capped at `max_batch_size`). Send-path latency is unaffected.

### 9.2 Sealer key mismatch

A `commit_batch` PTB that fails with `ESealerKeyMismatch` indicates one of:
- Sealer key file rotated without `SwarmAnchor.sealer_pubkey` update.
- Wrong `--anchor-swarm-anchor-id` (pointing at a different swarm's anchor).
- Sui RPC compromise — but the on-chain `ed25519_verify` rejects so the attack fails closed.

In all cases the sealer surfaces a permanent failure (`SealError::Permanent`) and the operator must intervene. The cadence loop sleeps on a long backoff and continues retrying — if the operator fixes the misconfiguration, the next tick recovers.

### 9.3 Monotonic violation

A `commit_batch` PTB that fails with `ENsRangeNotMonotonic` indicates the sealer's view of the watermark disagrees with `SwarmAnchor.last_ns_range_end`. The recovery path is to re-read `last_ns_range_end` from Sui and advance the in-memory watermark. The next cadence tick should succeed.

### 9.4 Postgres tampering detected

If the sealer fetches receipts for `monotonic_ns > watermark` and the receipt content has been mutated such that the computed Merkle root for a previously-known set of receipt_ids differs from a prior anchor, the sealer's own Merkle reconstruction (during the next batch) will produce a root that — when committed — doesn't match what a verifier reconstructs from the same Postgres state. Detection of this state is by an **external verifier**, not by the sealer itself; the sealer commits whatever Postgres shows it. This is the intended threat model: Postgres tampering becomes externally verifiable; it does not become locally self-detected.

### 9.5 Sui network partition

Long partition (hours):
- Anchoring stops; Postgres remains write-available.
- Operator MUST be alerted; the alert is a metrics signal, NOT an automatic shutdown.
- When the network recovers, the sealer drains the backlog (possibly many small batches if the time threshold dominated during the outage).

The sealer SHOULD log a structured event every N failed retries so operator monitoring picks up the anchoring outage.

---

## 10. Conformance hooks

A conformant implementation:

1. **Inclusion-proof verifiability.** Given a sealed receipt + its merkle path + the on-chain commitment, an independent verifier MUST be able to reconstruct the batch root and confirm the on-chain anchor without trusting the operator's Postgres. Concrete test: pull a receipt from Postgres, recompute the root via §3.4, fetch the `AnchorCommitted` event from Sui by `batch_index`, assert event's `batch_root == reconstructed_root`.

2. **Sort-order stability.** Two sealers seeing the same receipt set MUST produce identical Merkle roots. Validated against the §3.6 vectors.

3. **Canonical preimage determinism.** Two sealers seeing the same `(swarm_id, batch_root, count, ns_range_start, ns_range_end, histogram)` MUST produce byte-identical signing preimages. Validated against the §4.3 vectors.

4. **Histogram completeness.** For every batch: `sum(histogram.values()) == count`. The Move-side check (`EHistogramSumMismatch`, §5.5) enforces this on-chain; the sealer MUST also enforce it before submission.

5. **Hybrid-cadence triggering.** Implementations MUST trigger a seal when either threshold fires. Test: at low throughput, batches arrive on the time cadence; at high throughput, batches arrive on the count cadence. Verification: count `AnchorCommitted` events per minute under controlled receipt-emission rates.

6. **Postgres independence.** Sui RPC unavailability MUST NOT block receipt appends or any substrate operation. Test: simulate RPC down for 60s; verify send-path latency unchanged.

7. **Histogram cardinality bound.** A batch MUST NOT contain more than 256 distinct action_kinds (defense against histogram blowup from misconfigured workload extensions; canonical set is ≈ 30-50 kinds, leaving generous headroom). Sealers SHOULD refuse to seal a batch exceeding this and SHOULD log a structured warning.

8. **Action-kind length bound.** Per §4.1, `action_kind_len` is u16-encoded but MUST NOT exceed 255 bytes. The canonical action-kind names are all well within this; workload extensions inheriting the same convention is a soft requirement enforced at schema-load time (out of this RFC).

Test cases land at `/conformance/verifiability/sui-anchoring/` during H5-H6.

---

## 11. Observability

The on-chain `AnchorCommitted` event stream is the foundation for any operator-facing observability:

- **Direct Sui RPC queries.** `sui client events --module receipt_anchor --event AnchorCommitted` (or the equivalent JSON-RPC call) returns every commit for a package. Filtering by `swarm_id` field gives the per-swarm view.
- **Sui ecosystem indexers** (Suiscan, Suivision, Sui Mainnet's official indexer) can index the events without any Yutha-specific configuration. Operators wanting their dashboard inside an existing Sui observability stack get this for free.
- **Self-hosted indexer.** Operators wanting a customized indexer (joining `AnchorCommitted` events against per-swarm metadata) can use the standard Sui indexer toolkit; the event shape is stable.

Yutha does not ship a reference observability dashboard in v1 — see RFC 0014 §9 for the open question.

---

## 12. Operator-upgradeable Move package

The operator who publishes the `receipt_anchor` package holds the `UpgradeCap`. Upgrades are operator-discretion:

- **Bug-fix upgrades** that preserve the canonical preimage (§4) and abort-code semantics (§5.5) MAY be applied in-place; existing `SwarmAnchor` shared objects continue to work.
- **Semantic-changing upgrades** (preimage layout changes, additional fields in the histogram, new event fields with different ordering) MUST be a fresh package publish. Operators migrate by:
  1. Publishing the new package version → fresh `package_id`.
  2. Creating new `SwarmAnchor` shared objects under the new package for each swarm.
  3. Reconfiguring control planes with the new package id + new SwarmAnchor id.
  4. Old anchors remain valid for historical receipts; new receipts anchor to the new objects.

Operators MAY also burn the `UpgradeCap` (Sui's `freeze_object` or transfer-to-zero pattern) to declare the package immutable. This is a strict tightening of the trust model and is recommended for production deployments.

Yutha's reference Move source defaults to **operator-keeps-UpgradeCap**; operators wanting the immutability story add a single `sui client call` to freeze it post-publish.

---

## 13. References

- RFC: [`/spec/rfcs/0014-sui-receipt-anchoring.md`](../rfcs/0014-sui-receipt-anchoring.md)
- Receipt spec: [`/spec/receipt/receipt-v1.proto`](../receipt/receipt-v1.proto), [`/spec/receipt/canonical-actions.md`](../receipt/canonical-actions.md), [`/spec/receipt/rationale.md`](../receipt/rationale.md)
- Existing seal scaffolding: [`/crates/yutha-receipt/src/seal.rs`](../../crates/yutha-receipt/src/seal.rs)
- Postgres receipt store: [`/backends/postgres-receipt/`](../../backends/postgres-receipt/)
- Move reference source (after H4): `/contracts/sui/receipt_anchor/`
- Sui Move language: <https://docs.sui.io/concepts/sui-move-concepts>
- Sui Ed25519 cryptography primitives: <https://docs.sui.io/standards/cryptography>
- Build-plan: [`/docs/internal/build-plan.md`](../../docs/internal/build-plan.md)

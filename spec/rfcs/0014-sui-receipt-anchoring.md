# RFC 0014: Sui Receipt Anchoring (Verifiability Layer 1)

> **Status:** Draft
> **Authors:** Workstream A (Specs) + Workstream H (Verifiability)
> **Filed:** 2026-05-19
> **Targets spec:** `/spec/verifiability/sui-anchoring.md` (new),
>                   `/spec/receipt/canonical-actions.md` (one new `anchor.commit` entry),
>                   `/spec/receipt/receipt-v1.proto` (optional `SealStatus.on_chain_anchor` field)
> **Targets phase:** Phase 3 (pre-public-release v1)
> **Discussion:** TBD
> **Predecessors:** [RFC 0004](./0004-receipt-v1.md) (receipt spec — defines `SealStatus`, the `BatchRoot` signature role, and the `receipt_seal` table)
> **Substrate dependency:** Postgres receipt backend (`/backends/postgres-receipt/`)
> **Out of scope:** Walrus cold-storage of sealed batches (Layer 2 — future RFC); on-chain constitution objects (Layer 3 — future RFC).

## 1. Summary

Adds a public-verifiability layer on top of the existing Postgres receipt store: a sealer batches receipts at a hybrid time/count cadence, computes a Merkle root, and posts a single Sui transaction anchoring the root + a per-action-kind histogram for that batch. Anyone with read access to Postgres (or, later, a Walrus blob) plus an internet connection to a Sui RPC node can independently verify that any individual receipt was anchored at a specific time. A Postgres operator that silently deletes or alters a sealed receipt is detectable.

**Anchoring is fully opt-in.** The substrate works without it; existing deployments require zero changes. Operators who do enable it choose their own Sui network (mainnet, testnet, localnet, or any custom RPC endpoint) and deploy their own copy of the Move package — Yutha publishes reference Move source under `/contracts/sui/` but does NOT operate any canonical on-chain registry. The result: each operator's anchoring trust boundary is theirs alone, with no shared on-chain state, no upgrade-authority dependency on Yutha, and no forced network choice.

Concretely pinned in this RFC:

1. **A sealer trait** in `yutha-receipt`, mirroring the existing `ReceiptStore` shape. One method (`seal_batch`) plus a `SealedBatch` value type. Default impl is a no-op `LocalSealer`; the Sui impl ships as a separate crate that operators wire in by flag.
2. **A Sui Move module** (`yutha::receipt_anchor`) — reference source under `/contracts/sui/`, deployed by each operator to whichever Sui network they target. No Yutha-operated canonical deployment. One shared `SwarmAnchor` object per swarm holds the rolling list of batch commitments.
3. **The on-chain commitment shape:** `(swarm_id, batch_root, count, ns_range_start, ns_range_end, action_kind_histogram, sealer_signature)`. The histogram is a `VecMap<String, u64>` of action_kind counts.
4. **Hybrid cadence:** the sealer triggers a new batch on whichever fires first — N receipts accumulated, or T seconds since the last batch sealed. Defaults `N=100`, `T=10s`; both operator-configurable.
5. **Single-key trust model:** one Ed25519 keypair per swarm signs every anchor transaction. The on-chain Move module enforces that anchors come from the registered key. Multi-key / supervisor-tier-multisig deferred (Phase 4).
6. **Postgres remains primary.** Sui RPC failure does not block writes. Unanchored receipts accumulate; sealer catches up when Sui RPC recovers.
7. **Network-agnostic.** Selection is by `--anchor-sui-rpc-url <url>`. Mainnet, testnet, custom devnet, self-hosted full-node — all equally supported. The control plane has no preferred network and no hard-coded URL.

Filled into the existing schema:

- `receipt_seal` table (`/backends/postgres-receipt/migrations/...sql`) populates as batches seal. Adds one column: `on_chain_anchor_tx_digest` (32 bytes, nullable until Sui tx confirms).
- `SealStatus` proto (`/spec/receipt/receipt-v1.proto`) optionally carries `on_chain_anchor` — the Sui tx digest + the shared-object id holding the swarm's anchor history. Receipts re-emitted post-seal carry these fields so consumers don't need to re-query.

## 2. Motivation

Phase 2's audit trail is exhaustive — every send, deliver, capability check, constitution evaluation, and enforcement transition produces a signed receipt. But the *integrity* of that trail today depends entirely on trusting the operator running Postgres. A malicious or compromised operator can silently delete a receipt, retroactively edit `occurred_at_ns`, or splice a fabricated receipt into the log. There is no external check.

Three concrete adversarial scenarios this RFC unblocks:

1. **Selective deletion.** A compromised operator removes a single `constitution.evaluate.deny` receipt and the downstream `enforcement.detect` that pattern-matched on it. The agent that violated policy gets erased from the record. Today: undetectable. After this RFC: the Merkle root committed on-chain no longer matches the receipts in Postgres → external verifier flags the inconsistency.

2. **Backdated insertion.** An operator inserts a receipt with `occurred_at_ns` predating a known incident, fabricating evidence that "we already knew about this." Today: undetectable. After: the receipt's anchor batch must postdate its `occurred_at_ns`, and the anchor's wall-clock is on a public chain with independent timestamps — tampering becomes provable.

3. **Operator denial of governance changes.** A `constitution.activate` receipt records an amendment the operator now wants to disclaim. Today: the operator can delete the receipt and reactivate the prior constitution silently. After: the anchor on Sui preserves the activate's content-address, making the historical activation cryptographically verifiable to anyone.

Beyond adversarial cases, this RFC unlocks a class of monitoring use cases that don't require Postgres read-access at all — the on-chain histogram makes "is this swarm seeing weird enforcement.evict volume?" queryable directly from Sui RPC.

This RFC is the **first verifiability-layer spec**. After it lands, Layer 2 (Walrus cold-store of sealed batches, RFC 0015 if it ships) and Layer 3 (constitutions as on-chain Move objects, RFC 0016 if it ships) become natural follow-ons.

## 3. Detailed design

The full spec lives in [`/spec/verifiability/sui-anchoring.md`](../verifiability/sui-anchoring.md). This RFC summarizes the load-bearing decisions.

### 3.1 The `Sealer` trait (yutha-receipt)

New trait in `yutha-receipt`, parallel in shape to `ReceiptStore`:

```rust
#[async_trait]
pub trait Sealer: Send + Sync + std::fmt::Debug {
    /// Seal a batch of receipts. Implementations:
    ///   1. compute the Merkle root over the receipts' canonical bytes
    ///      in `monotonic_ns` order;
    ///   2. compute per-receipt Merkle paths;
    ///   3. submit the commitment to the verifiability backend;
    ///   4. return a `SealedBatch` describing the batch + commitment.
    ///
    /// The control plane runs this in a background task; failures here
    /// MUST NOT block receipt appends. Implementations SHOULD retry
    /// transient backend failures with exponential backoff before
    /// surfacing the error.
    async fn seal_batch(
        &self,
        receipts: &[Receipt],
    ) -> Result<SealedBatch, SealError>;
}

pub struct SealedBatch {
    pub batch_root: Hash,
    pub merkle_paths: Vec<Vec<Hash>>,   // path per receipt, same index as input
    pub sealed_at: Timestamp,
    pub action_kind_histogram: BTreeMap<String, u64>,
    /// Backend-specific commitment id (Sui tx digest, Walrus blob id, etc.).
    pub commitment_id: Vec<u8>,
}
```

The trait is intentionally backend-agnostic. The default impl is a no-op `LocalSealer` that stamps the Postgres `receipt_seal` table without any external commitment (useful for local development and tests). The `SuiSealer` (this RFC's reference impl) lives in a new `yutha-anchor-sui` crate.

### 3.2 The Sui Move module

A single Move module `yutha::receipt_anchor` deployed once per operator (or shared by trust-co-located swarms — the swarm_id field on each commitment provides isolation):

```move
module yutha::receipt_anchor {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::vec_map::{Self, VecMap};

    /// One shared object per swarm. Holds the rolling commitment history.
    public struct SwarmAnchor has key {
        id: UID,
        swarm_id: vector<u8>,            // 16 bytes
        sealer_pubkey: vector<u8>,        // 32 bytes, Ed25519 raw
        batch_count: u64,                 // monotonic; serves as batch_index
        last_ns_range_end: u64,           // for ordering invariants
    }

    /// Emitted once per anchor commitment. Indexers consume these.
    public struct AnchorCommitted has copy, drop {
        swarm_id: vector<u8>,
        batch_index: u64,
        batch_root: vector<u8>,           // 32 bytes
        count: u64,
        ns_range_start: u64,
        ns_range_end: u64,
        action_kind_histogram: VecMap<vector<u8>, u64>,
        anchored_at_ms: u64,              // Sui clock at commit time
    }

    /// Create a fresh SwarmAnchor (typically called once per swarm).
    public entry fun create_swarm_anchor(
        swarm_id: vector<u8>,
        sealer_pubkey: vector<u8>,
        ctx: &mut TxContext,
    ) { /* ... */ }

    /// Commit a batch. The sealer_signature must be a valid Ed25519
    /// signature by `anchor.sealer_pubkey` over the canonical batch bytes.
    /// `ns_range_start` MUST be >= `anchor.last_ns_range_end` (monotonic).
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
    ) { /* signature verify, monotonic check, increment, emit event */ }
}
```

Two design constraints worth pinning explicitly:

- **Signature verification on-chain.** Sui has native `ed25519_verify`. The Move function refuses to land an anchor that wasn't signed by the registered sealer key. A compromised Sui RPC node or a malicious tx submitter cannot forge anchors.
- **Monotonic ns-range invariant.** Each batch's `ns_range_start` must be `>= prev.ns_range_end`. Catches sealer bugs that would otherwise create overlapping batches whose Merkle proofs become ambiguous.

**Deployment model — operator-owned.** Each operator who enables anchoring deploys their own copy of this package to whichever Sui network they target. Yutha publishes the reference Move source (canonical filename, canonical structure, conformance vectors) under `/contracts/sui/` in the OSS repo; an operator copies it, optionally audits it, runs `sui client publish`, and feeds the resulting `package_id` to the control plane. There is no Yutha-operated mainnet deployment, no shared registry object, no Yutha-held upgrade authority. The same source compiled on testnet vs. mainnet produces different `package_id`s and different `SwarmAnchor` shared-object ids; both are fully isolated, both are equally valid targets. The control plane's flags don't know or care which Sui network is on the other end of `--anchor-sui-rpc-url` — only that it speaks the Sui RPC protocol.

### 3.3 The on-chain commitment shape

The minimum payload posted per batch:

| Field | Type | Source | Why on-chain |
|-------|------|--------|--------------|
| `swarm_id` | 16-byte UUID | derived from bootstrap seed | distinguishes commitments from co-tenant swarms |
| `batch_index` | u64 | `anchor.batch_count` (incremented in Move) | enables monotonic indexing; serves as the "batch N" reference for proofs |
| `batch_root` | 32-byte SHA-256 | Merkle root of receipt canonical bytes | the inclusion-proof anchor |
| `count` | u64 | `receipts.len()` | enables sanity-check "we expected N receipts in this batch" |
| `ns_range_start`, `ns_range_end` | u64 each | min/max `occurred_at_ns` in batch | enables time-window queries against the anchor history |
| `action_kind_histogram` | `VecMap<String, u64>` | counted from the receipts | enables monitoring queries without Postgres |
| `sealer_signature` | 64-byte Ed25519 sig | sealer key, over the canonical preimage | the on-chain authenticity check |
| `anchored_at_ms` | u64 | Sui Clock | the chain's view of when the batch landed |

The `action_kind_histogram` covers every kind present in the batch. For the canonical receipt set (≈ 30-50 action_kinds), this is at most a few hundred bytes per batch — negligible against the inclusion-proof value. See `/spec/receipt/canonical-actions.md` for the full set.

Canonical preimage that the sealer signs (matches the Move function's reconstructed bytes for the on-chain verify):

```
swarm_id (16 bytes) ‖
batch_root (32 bytes) ‖
count (8 bytes, big-endian) ‖
ns_range_start (8 bytes, big-endian) ‖
ns_range_end (8 bytes, big-endian) ‖
canonical_histogram_bytes(action_kind_histogram)
```

`canonical_histogram_bytes` sorts entries by action_kind lex-ascending, encodes each as `(action_kind_len: u16, action_kind_utf8, count: u64)`. Determinism is required so the on-chain verify reproduces the off-chain signing bytes byte-for-byte.

### 3.4 Hybrid cadence + watermark

The sealer maintains a watermark: the highest `monotonic_ns` it has already sealed. On each tick:

1. Query Postgres for receipts with `occurred_at_ns > watermark` (cap at `--anchor-max-batch-size`, default 1000 — protects against single-batch blowouts on backlog).
2. If `count >= --anchor-batch-count-threshold` (default 100) OR seconds-since-last-seal `>= --anchor-batch-time-threshold` (default 10s) → seal this batch.
3. Otherwise, sleep until the time threshold is hit or the count threshold is reached (whichever fires first).
4. After a successful seal, advance the watermark.

The first-fires-first hybrid handles both load patterns:

- **Bursty / high-throughput swarms** never wait long for the time threshold — the count threshold fires first and anchors keep up.
- **Quiet swarms** still anchor every 10s, ensuring there's no indefinitely-unsealed window where an attacker has time to tamper undetected.

The thresholds are flag-configurable per deployment. Operators tuning for cost can raise both (anchor less often, save Sui gas); operators tuning for latency-to-verifiability can lower both.

### 3.5 Single-key trust model

The sealer holds one Ed25519 keypair per swarm. The public counterpart is registered once on-chain (at `create_swarm_anchor` time) and never rotated in v1. Compromise model:

- **Sealer key compromise:** the attacker can post fraudulent anchors (anchors whose Merkle root doesn't correspond to any real receipts in Postgres, or anchors over a swapped-in fake batch). Detection: comparing on-chain commitments against Postgres-derived roots, any third-party verifier sees the divergence. Mitigation v1.x: rotate the key + emit a `sealer.rotate` receipt that itself gets anchored under the new key. Multi-key + supervisor multisig is the proper fix (deferred — Phase 4).
- **Sui RPC compromise:** the on-chain `ed25519_verify` makes the Sui RPC node untrusted. A malicious RPC can refuse to forward a tx (denial of service, recoverable on retry) but cannot land an unsigned or differently-signed anchor.
- **Postgres compromise alone (no sealer compromise):** the attack this RFC primarily defends against. Detection is automatic — anchors no longer match Postgres state.
- **Postgres + sealer compromise:** both must be coordinated to forge a tampering-undetectable history. This is harder than Postgres-alone but not impossible; multisig is the structural defense and is the v1.x follow-up.

The sealer key is stored separately from the bootstrap seed — operators MUST NOT reuse the bootstrap-derived operator key for sealing. Reasons: rotation policy differs, exposure surface differs, and accidentally exposing the sealer key shouldn't grant operator-revoke authority.

### 3.6 Failure-mode behavior

Categorical statement: **Postgres remains primary; Sui anchoring is best-effort.**

| Failure | Behavior |
|---------|----------|
| Anchoring not enabled (no `--anchor-backend` flag) | Postgres write-path operates exactly as today; the `Sealer` slot is filled by `LocalSealer` (no-op) or left empty. No Sui dependency at runtime, no Sui RPC connection attempts, no startup checks. This is the default. |
| Sui RPC down (anchoring enabled) | Sealer logs warning; unanchored receipts continue to accumulate; sealer retries on cadence; backlog drains when RPC recovers. Send-path latency unaffected. |
| Sealer key invalid / on-chain pubkey mismatch | `commit_batch` aborts on-chain with `ESealerKeyMismatch`; sealer logs the failure; operator must investigate (key rotation, package reinstall, etc.). |
| Sealer process crash | New sealer instance reads `anchor.batch_count` from Sui to learn the last sealed batch_index, then queries Postgres to find the corresponding `monotonic_ns` watermark. Backlog drains. |
| Postgres receipt mismatch (sealer + Postgres disagree on what's in a batch) | Sealer aborts the batch; emits a loud operator-alert. This indicates either Postgres tampering or sealer bugs — both worth human investigation, neither worth silent overwrite. |
| Sui network partition lasting > 1 hour | Configured-cadence anchoring stops; Postgres remains write-available; operator-alertable. Service degraded but functional. Applies symmetrically to mainnet, testnet, and self-hosted full-nodes. |
| Switching networks (testnet → mainnet, or vice versa) | Treat as a fresh setup: deploy the Move package to the new network, create a new `SwarmAnchor` shared object, start anchoring forward from the current watermark. Existing receipts anchored on the old network keep their proofs valid against that network; no cross-network bridging. |

The asymmetry is deliberate: receipts-without-anchors is a degraded-but-recoverable state; anchors-without-correct-receipts is an integrity violation that demands operator attention.

## 4. Receipt-evidence schemas

This RFC adds one new entry to `/spec/receipt/canonical-actions.md`:

| `action_kind` | Producer | Actor | Notes |
|---------------|----------|-------|-------|
| `anchor.commit` | Sealer | Control plane | One per Sui anchor transaction successfully confirmed on-chain. Evidence: `batch_root`, `batch_index`, `count`, `ns_range_start`, `ns_range_end`, `on_chain_tx_digest` (Sui tx digest, 32 bytes), `swarm_anchor_object_id` (the shared object, 32 bytes), `action_kind_histogram` (BTreeMap canonicalized to bytes), `anchored_at_wall_clock` (RFC 3339). Receipt itself is signed by the control plane only (no Actor signature — the anchor is a substrate operation, not an agent action). |

Note: the `anchor.commit` receipt is itself anchorable in a subsequent batch. This is intentional — the audit trail of "when we anchored" is part of the audit trail.

The existing `SealStatus` proto gains optional fields (additive — old consumers ignore them):

```protobuf
message SealStatus {
    SealState state = 1;
    optional Hash batch_root = 2;
    repeated Hash merkle_path = 3;
    optional Timestamp sealed_at = 4;

    // Added per RFC 0014. Present when sealed via SuiSealer.
    optional bytes on_chain_tx_digest = 5;       // 32 bytes
    optional bytes swarm_anchor_object_id = 6;   // 32 bytes
}
```

The Postgres `receipt_seal` table gets one new column:

```sql
ALTER TABLE receipt_seal
    ADD COLUMN on_chain_anchor_tx_digest BYTEA;
```

Nullable so the `LocalSealer` (no on-chain commitment) and historical batches still satisfy the column.

## 5. Conformance hooks

A conformant anchoring implementation:

- **Inclusion-proof verifiability.** Given a sealed receipt + its merkle path + the on-chain commitment, an external verifier MUST be able to reconstruct the batch root and confirm the on-chain anchor without trusting the operator's Postgres.
- **Monotonic batch ordering.** Successive batches MUST have non-overlapping ns-ranges. The Move module's `ns_range_start >= prev.ns_range_end` check enforces this on-chain; sealer implementations MUST not submit out-of-order batches.
- **Histogram completeness.** Every receipt in a batch MUST be reflected in the histogram. Test: `sum(histogram.values()) == count`.
- **Canonical preimage determinism.** Two sealers seeing the same `(swarm_id, batch_root, count, ns_range_start, ns_range_end, histogram)` MUST produce byte-identical signing preimages. Test vectors land under `/spec/vectors/sui-anchoring/`.
- **Hybrid-cadence triggering.** Implementations MUST trigger a seal when either threshold fires. Test: at low throughput, batches arrive on the time cadence; at high throughput, batches arrive on the count cadence.
- **Postgres independence.** Sui RPC unavailability MUST NOT block receipt appends or any other substrate operation. Test: simulate RPC down for 60s; verify send-path latency unchanged.

Test cases land under `/conformance/verifiability/sui-anchoring/` during H-code stages.

## 6. Threat-model linkage

This RFC is the primary defense against:

- **A8 (malicious operator).** Postgres tampering becomes externally detectable. Selective deletion, backdated insertion, governance-history forgery all leave on-chain evidence of inconsistency.
- **A11 (post-incident audit-log denial).** An operator denying a documented event finds the historical receipt's content-address committed on a public chain; the receipt's existence at a specific wall-clock is independently verifiable.

Secondary contribution to:

- **A1 (hostile agent).** Doesn't directly defend, but the anchor of `enforcement.detect` / `enforcement.quarantine` / `enforcement.evict` events for the agent makes the enforcement history tamper-evident — a compromised operator can't retroactively remove the agent's punishment record.
- **A7 (norm drift).** The on-chain histogram surfaces enforcement-event volume directly; norm drift becomes operator-observable from a public dashboard, not just from inside Postgres.

Does **not** defend against:

- **A12 (sealer + operator collusion).** Both keys + Postgres write access lets an attacker forge a coherent fraudulent history. Multisig is the structural mitigation, deferred to v1.x.
- **A13 (Sui chain itself reorgs/forks).** Sui's finality + ecosystem maturity is the trust assumption here; if Sui itself produces conflicting state, that's outside this RFC's threat model. Anchor-on-multiple-chains is a future RFC if appetite emerges.

## 7. Backwards compatibility

This RFC is purely additive:

- New crate (`yutha-anchor-sui`) — not a runtime dep of any existing crate.
- New trait (`Sealer`) — has a default no-op `LocalSealer` impl; existing deployments behave as today.
- New SQL column (`on_chain_anchor_tx_digest`) — nullable.
- New proto fields (`SealStatus.on_chain_*`) — optional, scalar additions; old consumers ignore.
- New action_kind (`anchor.commit`) — receipt consumers that don't recognize it pass through.

Existing receipts retain their `SealState::Unsealed` status. Operators opting into anchoring start sealing forward; old receipts remain unsealed unless an operator runs an opt-in backfill pass (allowed but not specified — implementations MAY support it).

## 8. Migration path

Operators adopting Sui anchoring (entirely optional — skip this section if you don't want it):

1. **Pick a Sui network.** Mainnet is the production choice; testnet is right for everything pre-production; localnet works for dev. The control plane treats these identically — only the RPC URL changes.
2. **Generate a fresh sealer keypair.** Distinct from the bootstrap seed. Persist the private key in operator-tier secret storage.
3. **Publish the Move package on your chosen network.** From the OSS repo:
   ```
   cd contracts/sui/receipt_anchor
   sui client switch --env <testnet|mainnet|your-env>
   sui client publish --gas-budget 100000000
   ```
   Record the printed `package_id`. The same Move source published on a different network gives a different package_id; that's expected and correct.
4. **Create the per-swarm `SwarmAnchor` shared object** by calling the package's `create_swarm_anchor` entry function with `(swarm_id, sealer_pubkey)`. Record the returned shared-object id.
5. **Start the control plane with anchor flags:**
   ```
   --anchor-backend sui
   --anchor-sui-rpc-url <your network's RPC URL>
   --anchor-sui-package-id 0x...        # from step 3
   --anchor-swarm-anchor-id 0x...        # from step 4
   --anchor-sealer-key-file /path/to/sealer.key
   --anchor-batch-count-threshold 100
   --anchor-batch-time-threshold 10s
   ```
   For reference, the RPC URLs Sui Foundation operates: `https://fullnode.mainnet.sui.io:443` (mainnet), `https://fullnode.testnet.sui.io:443` (testnet). Self-hosted full-nodes or third-party RPC providers work identically.
6. **Verify.** After the first batch lands, query the `SwarmAnchor` shared object's `AnchorCommitted` event stream — a tx digest appears. The control plane logs the corresponding `anchor.commit` receipt.

There is no in-place migration of pre-existing receipts. Operators who want historical receipts anchored can opt into a backfill pass (run the sealer over historical batches in chronological order); the resulting `anchor.commit` receipts carry the historical ns-ranges. This is opt-in because it reveals historical receipt counts on a public chain — an operator may have privacy reasons to prefer forward-only anchoring.

## 9. Open questions for review

- **Indexer + dashboarding story.** The on-chain `AnchorCommitted` events are the foundation for any "this swarm has had N anchors in the last 24h, with these histograms" dashboard. Whether Yutha ships a reference indexer or relies on Sui's ecosystem indexers (Suiscan, Suivision) is a v1.x decision. Out of this RFC. (Note: because each operator deploys their own package per §3.2, ecosystem indexers won't automatically aggregate across operators — that's a feature, not a bug, since each operator's anchoring trust boundary is independent.)
- **Watermark consistency model.** The sealer's "what's already sealed" watermark is derived from Postgres + Sui state. Edge cases: sealer crashes mid-batch (uncommitted Sui tx + Postgres rows already linked). Probably resolvable by re-deriving the watermark from `anchor.batch_count` on every start; needs care.
- **Histogram cardinality bound.** A constitution that defines many workload-specific action_kinds could theoretically blow up the histogram. The canonical set is bounded by `/spec/receipt/canonical-actions.md`; workload extensions could add more. Worth specifying a maximum-distinct-kinds-per-batch (e.g. 128) to bound the on-chain size?
- **Anchor for fail-safe operations.** Should `agent.operator_revoke` and `enforcement.evict` receipts be anchored synchronously (a small dedicated batch per high-severity event) rather than waiting for the next cadence-triggered batch? Tighter audit window but more on-chain cost. Plausible to make this rule-configurable; out of v1.
- **Multi-region / multi-RPC redundancy.** A single Sui RPC node is a denial-of-service surface for anchoring. Hedging across multiple RPCs improves availability; complicates duplicate-tx detection (two RPCs accept the same tx). Likely worth doing; not load-bearing for v1.
- **Receipt-evidence carrying the merkle path.** Currently `SealStatus.merkle_path` is the path *within* the batch's Merkle tree. Does it need to also carry the on-chain object_id + batch_index so a consumer with just a receipt can fully verify without external state? Probably yes — already implied by §4's `SealStatus` additions. Worth pinning explicitly during /spec/verifiability/sui-anchoring.md drafting.

## 10. References

- Receipt spec: [`/spec/receipt/rationale.md`](../receipt/rationale.md), [`/spec/receipt/canonical-actions.md`](../receipt/canonical-actions.md), [`/spec/receipt/receipt-v1.proto`](../receipt/receipt-v1.proto)
- Postgres backend: [`/backends/postgres-receipt/`](../../backends/postgres-receipt/)
- Existing seal scaffolding: [`/crates/yutha-receipt/src/seal.rs`](../../crates/yutha-receipt/src/seal.rs)
- Existing `BatchRoot` signature role: [`/crates/yutha-receipt/src/proto_conv.rs`](../../crates/yutha-receipt/src/proto_conv.rs)
- Existing `receipt_seal` table migration: [`/backends/postgres-receipt/migrations/20260510120000_initial_schema.sql`](../../backends/postgres-receipt/migrations/20260510120000_initial_schema.sql)
- Sui Move language reference: <https://docs.sui.io/concepts/sui-move-concepts>
- Sui native crypto (`ed25519_verify`): <https://docs.sui.io/standards/cryptography>
- Build-plan §verifiability: [`/docs/internal/build-plan.md`](../../docs/internal/build-plan.md)
- Threat model: `/docs/internal/threat-model.md`

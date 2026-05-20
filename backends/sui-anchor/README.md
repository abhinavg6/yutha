# yutha-backend-sui-anchor

Sui-anchor backend for the Yutha [`Sealer`] trait. Commits batched
receipt Merkle roots to a per-swarm `SwarmAnchor` shared object via
the `receipt_anchor` Move package (RFC 0014).

## What it does

Given a `SealedBatch` from `yutha-receipt`, this crate:

1. Constructs the canonical preimage per
   `/spec/verifiability/sui-anchoring.md` §4.
2. Signs it with the sealer's Ed25519 key.
3. Builds a PTB calling `receipt_anchor::receipt_anchor::commit_batch`
   on the operator's deployed copy of the Move package.
4. Submits the PTB through `sui-rpc`.
5. Waits for confirmation and returns the Sui transaction digest as
   the `SealedBatch.commitment_id`.

It also exposes an `AnchorDriver` — a background-task driver that
implements the hybrid cadence loop (RFC 0014 §3.4) over a
`SealStore`-backed receipt queue.

## What it doesn't do

- Sealing pre-conditions (Merkle construction, canonical preimage
  bytes, histogram aggregation) — those live in `yutha-receipt`'s
  `merkle`, `preimage`, and `sealer` modules. This crate composes
  with `LocalSealer`'s computation logic but adds the on-chain
  commitment step.
- Publishing the Move package — operators run `sui client publish`
  on their own copy of `/contracts/sui/receipt_anchor/`. This crate
  consumes the resulting package id + `SwarmAnchor` object id via
  configuration.
- Key management beyond loading. The sealer key is loaded from a
  file path; operator-tier secret storage (HSM, KMS, etc.) is out
  of scope for v1.

## SDK choice

This crate uses the new modular Sui Rust SDK at
<https://github.com/MystenLabs/sui-rust-sdk> — `sui-sdk-types`,
`sui-crypto`, `sui-rpc`, `sui-transaction-builder`. An internal
`SuiAnchorClient` trait abstracts the SDK touch points so future
swaps stay narrow.

## Configuration

The `AnchorDriverConfig` mirrors the CLI flag surface from
`/spec/verifiability/sui-anchoring.md` §6.1:

| Field | CLI flag | Default |
|-------|----------|---------|
| `rpc_url` | `--anchor-sui-rpc-url` | — |
| `package_id` | `--anchor-sui-package-id` | — |
| `swarm_anchor_id` | `--anchor-swarm-anchor-id` | — |
| `sealer_key_file` | `--anchor-sealer-key-file` | — |
| `batch_count_threshold` | `--anchor-batch-count-threshold` | 100 |
| `batch_time_threshold` | `--anchor-batch-time-threshold` | 10s |
| `max_batch_size` | `--anchor-max-batch-size` | 1000 |
| `retry_attempts` | `--anchor-retry-attempts` | 5 |

# yutha-core

Shared types for Yutha. Mirrors the Rust ergonomics of [`/spec/common.proto`](../../spec/common.proto).

This crate is the dependency root for everything else. Keep it small. Anything that smells like business logic belongs in another crate.

## What's here

- **Identifiers**: `AgentId`, `SwarmId`, `ReceiptId` (UUID v7 wrappers).
- **Crypto value types**: `Hash`, `Signature`, `PublicKey` (algorithm-tagged byte containers — actual crypto work lives in `yutha-crypto`).
- **Time**: `Timestamp` (wall-clock + monotonic).
- **Causality**: `CausalRef` (predecessor pointers).
- **Cost**: `CostAnnotation` (PRD §13.2 cost transparency).
- **Versioning**: `SpecVersion`.
- **Errors**: `CoreError`.

## What's NOT here

- Cryptographic operations (sign / verify / hash) — those are in `yutha-crypto`.
- Wire-format encoding/decoding — those will land via `prost` once the proto build pipeline is wired in (feature-gated under `proto`).
- Anything stateful.

## Reference

- [`/spec/common.proto`](../../spec/common.proto) — the wire-format definition this crate mirrors.
- [`/spec/README.md`](../../spec/README.md) — versioning policy, crypto baseline, content-addressing.

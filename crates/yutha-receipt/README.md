# yutha-receipt

The load-bearing wall. Append-only, content-addressed, signed records of consequential actions in a Yutha swarm.

Per build-plan.md §4.1, this crate is built before everything else that emits receipts (which is everything). Per the receipt RFC ([RFC 0004](../../spec/rfcs/0004-receipt-v1.md)), this crate's behavior is normative — backends conform to its trait, and the conformance suite verifies them.

## What's here

- **`Receipt`** struct mirroring [`/spec/receipt/receipt-v1.proto`](../../spec/receipt/receipt-v1.proto), plus `Evidence`, `SignedBy`, `SignatureRole`, `SealStatus`.
- **`ReceiptStore` trait** — the interface every storage backend implements. Async, errors via `ReceiptError`.
- **In-memory reference implementation** (`MemoryStore`) — useful for tests, conformance harness fixtures, and the embedded-quickstart path.
- **Content-address verification** — the `verify_content_address` helper that re-canonicalizes a receipt and checks its hash against a claimed ID.
- **Signature verification** — checks the actor signature; ordering rules for control-plane / supervisor / attestation signatures.

## What's NOT here

- Persistent storage (Postgres + S3) — that's `backends/postgres-receipt` + `backends/s3-blob`.
- Verifiable-tier sealing logic — partially here as trait surface, fully implemented in `backends/walrus-receipt`.
- The constitution evaluator's evidence shapes — those land in Phase 2.
- Cross-store replication — Phase 1.x.

## Threat-model linkage

A8 (malicious operator) is the primary adversary this crate defends against — append-only + content-addressed + signed defeats silent tampering. Per CODEOWNERS, every change requires Workstream L (security) review.

## Reference

- [`/spec/receipt/receipt-v1.proto`](../../spec/receipt/receipt-v1.proto)
- [`/spec/receipt/rationale.md`](../../spec/receipt/rationale.md)
- [`/docs/internal/conformance-suite.md`](../../docs/internal/conformance-suite.md) §3.3
- [RFC 0004](../../spec/rfcs/0004-receipt-v1.md)

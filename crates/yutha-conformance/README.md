# yutha-conformance

The conformance harness. Backends register themselves and run the same test set; the harness verifies they meet the spec'd behaviors at their declared conformance level.

Per build-plan.md §10, the conformance suite is a build-time forcing function — components that don't pass don't merge. Per Workstream A's charter, this crate's runner is co-owned with B/C/D/E (each owns the test contents for their interface).

## What's here

- **`receipt::ReceiptStoreSuite`** — Core-tier test suite for any `ReceiptStore` implementation. Pluggable: pass in a factory, the suite runs.
- **`Outcome`** — structured pass/fail with detail.

## What's NOT here

- Per-spec wire-format conformance (will land alongside the prost-bindings work).
- Performance benchmarks (separate harness).
- Differential conformance against the reference stack (separate runner; consumes this).
- Security adversary scenarios A1–A9 (Workstream L; lands as A2 conformance work begins).

## How to run

In CI:

```bash
cargo test --package yutha-conformance --features in-memory-receipt-suite
```

For a custom backend:

```rust
use yutha_conformance::receipt::ReceiptStoreSuite;
use yutha_receipt::ReceiptStore;
use std::sync::Arc;

let factory = || async { Arc::new(MyBackend::new().await) as Arc<dyn ReceiptStore> };
let suite = ReceiptStoreSuite::new(factory).await;
let outcome = suite.run().await;
assert!(outcome.passed(), "{outcome:#?}");
```

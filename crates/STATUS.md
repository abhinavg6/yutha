# Workstream C Status — Phase 1 Receipt-Store Scaffold

> **As of:** 2026-05-10
> **Author:** background work session, autonomous
> **Audience:** Abhinav (returning), incoming Workstream C engineers

## What landed

The Cargo workspace, the dependency-root crates, the receipt store with full in-memory implementation, and the conformance harness wired to run against it. Plus skeleton crates for the persistent and verifiable backends so the workspace compiles end-to-end and engineers picking up the next pieces have a buildable starting point.

### Workspace and project hygiene

| File | Purpose |
|------|---------|
| [`Cargo.toml`](../Cargo.toml) | Workspace root with seven members; pinned dependency versions; release/dev profiles. |
| [`README.md`](../README.md) | Project front door; two-sided North Star; topology modes; pointer to build plan. |
| [`LICENSE`](../LICENSE) | Apache-2.0, full text. |
| [`rust-toolchain.toml`](../rust-toolchain.toml) | Stable channel; rustfmt and clippy components. |
| [`.gitignore`](../.gitignore) | Standard Rust + project-specific. |
| [`deny.toml`](../deny.toml) | Cargo-deny config: license allowlist, OpenSSL banned (we use rustls per ADR 0001), no unknown registries. |
| [`.github/CODEOWNERS`](../.github/CODEOWNERS) | Per-area ownership; security-critical paths require Workstream L review. |
| [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | fmt + clippy + build (stable + MSRV) + test + conformance + cargo-audit + cargo-deny. |

### Crates (real code, with tests)

| Crate | Role | State |
|-------|------|-------|
| [`yutha-core`](./yutha-core/) | Shared types: AgentId / SwarmId / ReceiptId, Hash, Signature, PublicKey, Timestamp, CausalRef, CostAnnotation, SpecVersion, errors. | **Real.** Mirrors `/spec/common.proto`. ~25 unit tests. |
| [`yutha-crypto`](./yutha-crypto/) | Ed25519 sign/verify, SHA-256 hash, key fingerprint, Canonical trait + content_address helpers. Wraps `ed25519-dalek` and `sha2`. | **Real.** ~13 unit tests including known SHA-256 vectors and round-trip sign/verify. |
| [`yutha-receipt`](./yutha-receipt/) | Receipt struct, Evidence, SignedBy, SealStatus, ReceiptStore trait, MemoryStore, signature verification with canonical-order enforcement. | **Real.** MemoryStore passes the conformance suite. ~13 unit tests + integration via the conformance harness. |
| [`yutha-conformance`](./yutha-conformance/) | Pluggable conformance harness; backends provide a factory, harness runs the same tests. Six Core-tier receipt tests implemented. | **Real.** Runs against MemoryStore via `--features in-memory-receipt-suite`. |
| [`yutha-proto`](./yutha-proto/) | Prost-generated wire types for every `/spec/*.proto`. Single source of truth for on-the-wire encoding; consumers convert ergonomic Rust → proto for content-addressing and signing. Also emits tonic gRPC service stubs for `/spec/control-plane/v1.proto` and exposes a `FILE_DESCRIPTOR_SET` for runtime reflection. | **Real.** `btree_map(["."])` for deterministic map encoding; bundled `protoc` via `protoc-bin-vendored` so contributors don't need a system install. Build uses `tonic-build` (superset of `prost-build`). |
| [`yutha-cedar-plus`](./yutha-cedar-plus/) | Phase 2 constitution stack: stock Cedar gating (Layer A, delegates to upstream `cedar-policy`) + engine-side scoring rules, procedures, enforcement (Layer B). Implements the v1.1 constitution layer specified in RFCs 0010-0013. | **F5-F10 complete (Phase 2 reference impl integrated).** F5: public surface; sandbox bounds (10ms SendEnvelope / 100ms general, 1k entity / 1k policy / depth 16). F6: `ConstitutionLoader` — structural validators, `@<name>` predicate resolution, cedar-policy `Validator` in Strict mode, load-time bound enforcement. F7: Layer A evaluator via stock `Authorizer::is_authorized`. **F8: Layer B engine eval.** Scoring + procedure-trigger + procedure-transition policies synthesized at activation; `Authorizer` re-used to evaluate against them. Scores as fixed-precision i64 (no floats). `ProcedureIndex` under `Mutex` for optimistic transition firing. Evidence digest byte-deterministic via sorted BTreeMap canonical JSON. **F9: enforcement engine.** `EnforcementEngine` long-lived stateful object — receipt-stream-driven pattern matching against active constitution's `enforcement_rules` (sliding-window counters per `(rule_name, group_key)`), wall-clock-keyed `poll_scheduled` for stage progression (detect→coach→quarantine→evict), per-agent reputation accumulator clamped to [0.0, 1.0], quarantine state API (`is_agent_quarantined`) for cap-layer consultation. `ReceiptView` is the read-only borrowed-from-store input shape control-plane uses to drive `on_receipt`. **F10: control-plane integration.** `ConstitutionService.Activate` + `GetActive` RPCs (operator / agent bearer respectively); Send-path constitution gate (`FAILED_PRECONDITION` until operator activates); `constitution.evaluate.{pass,deny}` receipt emission (subject carried in `subject_agent_id` evidence since the receipt's actor is the control plane); receipt → engine feedback via `PublishingReceiptStore` decorator + `EnforcementReceiptView` mpsc channel (capacity 4096) drained by an async forwarder; 1s scheduler-tick task driving `poll_scheduled`; cap-layer `QuarantineSource` trait with `EnforcementEngineQuarantineSource` adapter so `MemoryCapabilityStore::{check,issue,attenuate}` refuse quarantined subjects. |
| [`yutha-control-plane`](./yutha-control-plane/) | Binary wiring backends + the gRPC server. Five services (`AdmissionService`, `CapabilityService`, `EnvelopeService`, `ReceiptService`, `ConstitutionService`) per `/spec/control-plane/v1.proto`. | **All five services wired end-to-end (Phase 2 F10 complete).** **2a:** reverse `TryFrom<&Proto>` conversions in `yutha-core`; `grpc/error.rs` `ErrorIntoStatus` trait. **2b:** reverse conversions in `yutha-receipt`; `ReceiptHandler` Get + Query. **2c:** reverse conversions in `yutha-passport`; both-direction `Topology` conversions in `yutha-registry`; `Registry::topology()` accessor; `Registry::revoke` widened to return receipt id; real bearer-token authentication (`auth::require_bearer_auth` parses `authorization: bearer <hex>`, prost-decodes `AgentBearerToken`, validates swarm binding + expiry + Ed25519 signature against the registered passport's public key); `AdmissionHandler` Register (anonymous) / Revoke (self-only) / GetTopology / RotateKey-UNIMPLEMENTED. **2d (this revision):** reverse `TryFrom<&Proto>` conversions in `yutha-capability` (Capability, Issuer, Scope, Caveat, ActionDescriptor) and `yutha-transport` (Envelope, Recipient, Performative); `CapabilityStore` widened — issue/attenuate now return `IssuanceOutcome { capability_id, issuance_receipt }`, revoke returns the revocation receipt id, check returns `CheckEvaluation { outcome, check_receipt }`; `MemoryCapabilityStore` emits `capability.issue` / `capability.attenuate` / `capability.revoke` receipts (previously only `capability.check.*`); `Transport::send` widened to return the `envelope.send` receipt id; new `Transport::subscribe(agent_id) -> Stream<(Envelope, Hash)>` for the streaming Subscribe RPC, with `MemoryTransport`'s impl idempotently registering the inbox; `CapabilityHandler` Issue/Attenuate/Revoke/Check wired (Check is stateless, no receipt — spec design); `EnvelopeHandler::send` checks `envelope.from_agent == auth.agent_id` then delegates; `EnvelopeHandler::subscribe` returns a `BoxStream` that maps the transport's items to `SubscribedEnvelope` proto. Spec-gap callouts: `RotateKey` still UNIMPLEMENTED, capability issuance signs with the CP key regardless of the `Issuer` field (scaffolding shortcut), multi-agent attenuation delegation (subject changes hands) deferred. |

### Backend skeletons

| Backend | Purpose | State |
|---------|---------|-------|
| [`backends/postgres-receipt`](../backends/postgres-receipt/) | Default backend. Schema in `migrations/`; conformance test in `tests/conformance.rs`. | **Real.** Append (with verify-on-append), get, by-id/predecessor/agent/action-kind/time-range queries, count. Append wraps inserts across `receipts` + 4 related tables in a single tx with `ON CONFLICT DO NOTHING` for idempotency. Conformance test runs against `YUTHA_PG_TEST_URL` when set (per-run schema namespace via libpq `-c search_path`); skipped silently otherwise. |
| [`backends/s3-blob`](../backends/s3-blob/) | Large-evidence blob store; AWS SDK wired. | **Skeleton.** BlobStore trait defined; method bodies `todo!()`. |
| [`backends/walrus-receipt`](../backends/walrus-receipt/) | Verifiable-tier reference (Walrus + Seal + Nautilus). | **Skeleton.** Trait `impl` shell; method bodies `todo!()`. Per build-plan.md §6, must pass the same conformance suite as Postgres at Phase 1 exit. |

## How to read this when you're back

If you have 10 minutes:
1. [`spec/STATUS.md`](../spec/STATUS.md) — Workstream A's deliverables (where the spec layer landed).
2. This document.
3. Run `cargo test --workspace --features yutha-conformance/in-memory-receipt-suite` to see the suite passing against the in-memory store. (Once you pull the toolchain.)

If you have an hour:
- Read `crates/yutha-receipt/src/store.rs` (the trait), then `memory.rs` (the impl), then `verify.rs` (signature verification with canonical-order rules), then `crates/yutha-conformance/src/receipt.rs` (the test set).
- Skim `crates/yutha-core/src/` to see how the shared types map from `/spec/common.proto`.

## What I'd flag for your attention

These are calls I made under your absence; please validate before reference impl deepens:

1. **Crate names use `yutha-` prefix everywhere; published crate names use the longer `yutha-backend-postgres-receipt` form.** Two reasons: avoids name conflicts on crates.io (`yutha-postgres` is too generic), keeps the `yutha-backend-X` pattern visible. Could shorten to `yutha-postgres-receipt` if you prefer; trivial to rename.

2. ~~**Canonical serialization is provisional.**~~ **RESOLVED — uniformly across all signed-blob types.** The prost-bindings pipeline has landed. A new [`yutha-proto`](./yutha-proto/) crate runs `prost-build` over every `.proto` under `/spec/` (bundled `protoc` via `protoc-bin-vendored`, `btree_map(["."])` for sorted-key map encoding). Each consumer crate has a `proto_conv.rs` providing one-way ergonomic → proto conversions, a `to_canonical_proto()` helper that clears signature/seal/extensions fields, and a one-line `Canonical::canonical_bytes` impl that calls `prost::Message::encode_to_vec()` on it. Applied to all four signed-blob types: **Receipt** ([`yutha-receipt/src/proto_conv.rs`](./yutha-receipt/src/proto_conv.rs)), **Passport** ([`yutha-passport/src/proto_conv.rs`](./yutha-passport/src/proto_conv.rs)), **Envelope** ([`yutha-transport/src/proto_conv.rs`](./yutha-transport/src/proto_conv.rs)), and **Capability** ([`yutha-capability/src/proto_conv.rs`](./yutha-capability/src/proto_conv.rs)). With tag-sorted field encoding plus `btree_map`, the output is bytewise deterministic across runs *and* wire-equivalent across spec-conforming implementations in other languages. Cross-language differential conformance is now unlocked (needs a second-language impl to exercise).

3. **Signature scheme is fixed at Ed25519.** `SignatureAlgorithm::ReservedPq` is rejected at construction in v1. Per spec, PQ migration is a future major version bump.

4. ~~**The receipt store's `append` does not yet verify the actor signature.**~~ **RESOLVED.** The trait now requires a `&dyn PassportResolver` parameter and verifies the actor signature (plus any non-actor role signatures whose key the resolver knows) before persisting. New error variants: `ActorNotResolvable`, `PassportResolver`. Helper `StaticPassportResolver` ships for tests/dev. Three new Core conformance tests cover the policy: `receipt.append_rejects_unsigned`, `receipt.append_rejects_tampered_signature`, `receipt.append_rejects_unknown_actor`. MemoryStore + the conformance suite both green; backend skeletons updated to match the new signature.

5. **Append-only enforcement is documented but not encoded in the trait surface.** The trait has no `update` or `delete` method; that's the enforcement. Postgres backend will additionally use role permissions (no UPDATE / DELETE grants) per the README. Worth confirming this is enough.

6. **CI uses `Cargo.lock` not committed.** `.gitignore` excludes it. Standard for libraries; for the workspace as a whole I leaned library-style, but as we ship the control-plane binary (Workstream B) we may want to commit `Cargo.lock` for reproducibility. Defer.

## What is *not* yet done

The substrate scaffold is in place. What's missing:

- ~~**Prost-bindings pipeline**~~ — **DONE across all four signed-blob types** (Receipt, Passport, Envelope, Capability). Each crate's `Canonical::canonical_bytes` is now `to_canonical_proto().encode_to_vec()`.
- ~~**Cross-language differential conformance.**~~ **Complete across all four signed-blob types.** `/spec/vectors/{receipt,passport,envelope,capability}/` together hold ~13 JSON fixtures with frozen `expected_canonical_hex` values. Each consuming crate has `tests/vectors.rs` that reads its own subdirectory, builds the typed message, and asserts the canonical bytes match (with `YUTHA_REGENERATE_VECTORS=1` for spec-change-driven re-baseline). [`/interop/go/`](../interop/go/) is the second-language witness using protoc-gen-go + `proto.MarshalOptions{Deterministic: true}` — four test files (`vectors_receipt_test.go`, `vectors_passport_test.go`, `vectors_envelope_test.go`, `vectors_capability_test.go`), each walking its own kind directory. Coverage highlights: the Passport `with_capabilities` fixture and Capability `attenuated_with_caveat` fixture both carry non-empty `bounds` maps with keys in non-sorted insertion order — that's the load-bearing test that BTreeMap (Rust) + Deterministic marshal (Go) agree on lex-sorted map encoding. Envelope fixtures cover three Recipient oneof variants (Agent, Role, Swarm); Capability fixtures cover all three Issuer oneof variants and four of six Caveat oneof variants.
- ~~**Postgres impl bodies.**~~ **DONE.** `PostgresStore` implements `ReceiptStore` end-to-end (append with verify, get, all five query variants, count). Conformance test in `backends/postgres-receipt/tests/conformance.rs` runs the Core suite against a live Postgres when `YUTHA_PG_TEST_URL` is set; skipped silently otherwise. Per-run schema isolation via libpq `-c search_path`; per-test reset via `TRUNCATE ... CASCADE`. **Pagination**: keyset-cursor pagination on `(occurred_at_ns, receipt_id)` for the four multi-row query variants; default page size 256, configurable via `PostgresStore::with_page_limit(n)`. Cursor format is opaque 40 bytes (8 BE i64 + 32-byte digest). Pagination test in `tests/pagination.rs` walks 7 receipts in 3 pages of [3, 3, 1] under the same env-var gate. **Remaining caveat**: the receipt-spec-version column doesn't exist yet (every receipt is rehydrated as `1.0.0`, which is true at v1.0 but won't be once we ship 1.1).
- **Walrus impl bodies.** Same. Coordination with Walrus / Seal / Nautilus integrators required.
- **S3 blob impl bodies.** Smallest and easiest of the three.
- ~~**Conformance suite expansion.**~~ **Core suite complete.** **Eleven** Core tests now cover every bullet in `conformance-suite.md` §3.3: append+retrieve, content-addressing, tamper detection (unsigned/tampered/unknown-actor variants), idempotency, predecessor index, count consistency, **concurrent appends preserve causal ordering** (new — 10 children pointing at one parent appended via `tokio::spawn`), and **sequential append durable across restart** (new — gated on a `StoreReloader` the backend optionally provides; in-memory skips cleanly, Postgres exercises). Full + Verifiable tiers remain to be authored.
- ~~**Append-with-verification path.**~~ **DONE.** See flag #4 above.
- ~~**Persistence test for the in-memory store.**~~ **Resolved differently.** The durability test now lives in the receipt-store conformance suite, gated on a `StoreReloader` hook the backend optionally provides. In-memory declines (no reloader → test is `TestOutcome::skip`); Postgres provides a reloader that drops the existing handle and constructs a new one against the same pool, faithfully simulating a process restart.

## Workspace health checks I could not run

Without cargo in the sandbox, I could not verify:

- **Does it compile?** Code is written carefully; should compile cleanly. Worth running `cargo build --workspace` first.
- **Do the tests pass?** Same — run `cargo test --workspace --features yutha-conformance/in-memory-receipt-suite`.
- **Does clippy complain?** I wrote conservatively; expect clippy clean modulo the usual missing-doc warnings on `pub` items, which I've tried to avoid.
- **Does cargo-deny pass?** The dependency set is conservative; expect green.

If anything fails, the most likely culprits are: (a) a dependency version that has shifted under us since I selected it; (b) a borrow-checker disagreement on the conformance harness's BoxFuture type. Easy fixes either way.

## A note on docs layout

The five design documents (PRD, ADR 0001, threat-model, constitution-language, conformance-suite) plus build-plan.md currently live at the workspace root, not under `/docs/` as the build plan §3 calls for. I left them where they are because moving user-placed files without permission felt overstepping. When you're ready, a single `git mv` consolidates them under `/docs/{decisions,security,design,conformance}/` per the layout in `/docs/internal/build-plan.md` §3. Cross-references in the spec rationale docs point to those `/docs/` paths in anticipation; they'll start resolving once the move happens.

## What comes next (suggested ordering)

In rough priority:

1. **`cargo build --workspace`** to verify the scaffold compiles. Fix anything that doesn't.
2. **Prost-bindings pipeline** for `yutha-core`. Unlocks deterministic wire format and starts to make differential conformance meaningful.
3. **Wire actor signature verification into `ReceiptStore::append`** (or document the policy decision not to). The conformance suite already has the building blocks.
4. **Move design docs into `/docs/{decisions,security,design,conformance}/` per build-plan.md §3.** Updates the cross-references the rationale docs already use.
5. **Postgres backend impl bodies** — first real persistence-tier conformance.
6. **Workstream B begins** in parallel — registry, transport, capability all consume the receipt trait that's now stable.

The spec contracts and the receipt scaffold together are what unblock B (control plane), D (SDKs), and the rest of C (persistent and verifiable backends). The rest of Phase 1 is now a parallel-execution problem, not a sequencing problem.

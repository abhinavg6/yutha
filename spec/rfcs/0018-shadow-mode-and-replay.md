# RFC 0018: Shadow-mode evaluator and replay engine — the constitution-preview contract

> **Status:** Draft
> **Authors:** Abhinav Garg
> **Filed:** 2026-06-09
> **Targets spec:** `/spec/constitution/evaluation.md` (cross-link from §1.3 once the evaluator surface lands); `/spec/receipt/canonical-actions.md` (five new entries under the Constitution domain — see §5)
> **Targets phase:** Phase 3 (simulation + observability) — specifically Phase 3b (shadow mode, implemented) and Phase 3c (replay engine, design-open)
> **Companion RFCs:** [0010 — Constitution Language v1.0](./0010-constitution-language-v1.md), [0012 — Evaluation model + sandbox](./0012-evaluation-model-and-sandbox.md), [0013 — Four-stage enforcement loop](./0013-four-stage-enforcement-loop.md)
> **Substrate dependency:** `yutha-cedar-plus`'s `CedarPlusEvaluator` + `EnforcementEngine` + `ActivatedConstitution`; `yutha-receipt`'s `ReceiptStore` trait; `yutha-control-plane`'s `ConstitutionService`, `EnvelopeHandler::send` eval path, and `PublishingReceiptStore` fan-out
> **Out of scope:** Multi-shadow (1+N concurrent shadow constitutions); full forensic / audit replay (replaying historical bursts to investigate past incidents); time-travel debugging; cross-swarm shadow promotion; shadow-mode SLAs for the candidate's evaluation latency

## 1. Summary

Phase 2 shipped one slot for the active constitution: operators publish via `ConstitutionService.Activate`, the slot swaps atomically, and every subsequent envelope is evaluated against the new policy. There is no way to **preview** a constitution against live traffic before it gates production. RFC 0018 pins the paired contract for two surfaces that together close that gap:

1. **Shadow-mode evaluator** (Phase 3b, implemented). A second slot — the **candidate** — alongside the active. Every envelope evaluates against both. Only the active gates (the cap layer, the deny short-circuit, the enforcement engine). The shadow emits `constitution.evaluate.shadow.{pass,deny}` receipts whose only consumer is the operator's audit-trail tooling. Operators promote shadow → active when they're convinced the divergence is intentional.

2. **Replay engine** (Phase 3c, design-open in this RFC; as-shipped notes amended at 3c close). An **isolated** evaluator instance plus an **isolated** receipt store that, given a constitution candidate and a receipt window, reproduces the receipts the candidate WOULD have emitted against the window's envelopes. Replay produces no production-side effect — its receipts go into a sibling store keyed by `replay_session_id`, and it never anchors to Sui.

Concretely pinned in this RFC:

1. **One+one shadow slot today, design-open for one+N.** The shadow slot is `Option<Arc<ActivatedConstitution>>`; the public API is shaped so a future RFC can grow it to `Vec<NamedShadow>` without breaking the existing surface.
2. **Shadow lifecycle is operator-driven.** Four operator-bearer-authenticated RPCs: `ActivateShadow`, `ClearShadow`, `PromoteShadow`, `GetActiveShadow`. Promotion is **atomic** — a single RPC that swaps the slot and rebinds the enforcement engine in one transaction.
3. **Shadow is observation-only.** The enforcement engine is bound only to the active constitution. Shadow `constitution.evaluate.shadow.{pass,deny}` receipts MUST NOT flow into `EnforcementEngine::on_receipt`. The fan-out filter at the receipt-publisher forwarder enforces this.
4. **Shadow shares one entity snapshot per envelope with the active eval.** Two evaluations, one snapshot, one `EvaluationRequest` (with the constitution_hash field rewritten internally for the shadow call) — the substrate doesn't pay the resolver cost twice.
5. **Active-eval receipts gain `shadow_constitution_hash` evidence when a shadow is configured.** Auditors correlating active and shadow decisions for the same envelope have an explicit hash to join on.
6. **Replay is engine-rebuild-from-receipts.** The replay engine spins up a fresh `EnforcementEngine` instance per session and feeds it the receipt window in order. This matches the locked architecture decision that engine-authoritative state and receipt-derived state must produce the same answer for the same receipt window (per [`/spec/constitution/evaluation.md`](../constitution/evaluation.md) §6).
7. **Replay isolation is per-store-implementation.** Postgres uses a separate schema; memory backend uses a sibling in-memory `ReplayStore` keyed under a `replay/` namespace. Replay never writes into the production store.
8. **Replay receipts never anchor to Sui.** The `AnchorDriver` per RFC 0014 filters replay receipts by their store membership, not by their action-kind.

## 2. Motivation

Phase 2 made constitutions versionable and amendable but left a gap operators noticed within days of trying to roll Yutha into production: there is **no safe way to preview a constitution against real traffic**. The available options before this RFC, all bad:

1. **Test in a staging swarm.** Staging traffic doesn't resemble production traffic; the constitution may pass staging and deny something in production no one anticipated.
2. **Activate the new constitution in production and watch for denies.** This is what operators end up doing. Denies block real work; rolling back via `Activate` of the previous version is a second outage. The audit trail records both as legitimate constitutional choices, which makes post-incident analysis murkier than it has to be.
3. **Read the diff and reason about it.** Constitutions span many Cedar rules + the engine config (RFC 0013 enforcement rules, RFC 0011 scoring + procedures). Reasoning is necessary but never sufficient; the actual traffic surfaces emergent denies that any local reasoning misses.

Shadow mode replaces option (2) with a fourth path: **activate the candidate as a shadow, watch the divergence between its receipts and the active's, then promote when satisfied.** No production-side effect from the shadow's denies. No audit-trail contamination. The cost is one extra Cedar evaluation per envelope, which is on the same order of magnitude as the existing active evaluation.

Replay is the shadow's natural companion: shadow tells you what the candidate WOULD have decided on **future** traffic; replay tells you what the candidate WOULD have decided on a **past** receipt window. Either is enough to catch problems that local reasoning misses; the two together cover both forward-looking and backward-looking diligence.

The architectural decisions were locked before this RFC went into draft (per [memory: `project-phase-3-simulation-observability`](#) — engine-authoritative reads, receipt-derived replay reconstruction, replay isolation per-store, shadow-mode 1+1 with extension path to 1+N, OTLP push not Prometheus pull). RFC 0018 pins the contracts those decisions imply.

## 3. Detailed design — shadow mode (Phase 3b)

### 3.1 Two-slot evaluator

`CedarPlusEvaluator` gains a parallel slot:

```rust
pub struct CedarPlusEvaluator {
    loader: ConstitutionLoader,
    sandbox: SandboxConfig,
    current: RwLock<Option<Arc<ActivatedConstitution>>>,
    current_shadow: RwLock<Option<Arc<ActivatedConstitution>>>,  // NEW in Phase 3b
    procedure_index: Mutex<ProcedureIndex>,
}
```

Both slots are loaded via the same `ConstitutionLoader`. The loader runs the full validation pass (RFC 0012 §3.3 structural checks, named-predicate resolution, Cedar Validator in Strict mode, load-time bound enforcement) on the candidate at activate-shadow time. A constitution that fails loader validation cannot enter the shadow slot — operators see a `FAILED_PRECONDITION` mapped from `CedarPlusError::LoadBoundExceeded` exactly as they would for `Activate`.

The shadow slot's `ActivatedConstitution` shares the same `Arc<cedar_policy::Schema>` only when its `schema_version` field is identical to the active's. A shadow constitution authored against a different schema version is permitted (operators preview schema bumps too) — the loader builds an independent `Arc<Schema>` in that case.

**Procedure-state isolation.** The single `procedure_index: Mutex<ProcedureIndex>` is reserved for the **active** constitution. Shadow evals MUST NOT mutate it. The shadow path either (a) runs Layer A only (cedar gating + receipt evidence) and skips Layer B procedure transitions, or (b) runs Layer B against a separate, in-memory shadow-side `ProcedureIndex` that lives for the shadow slot's lifetime. Phase 3b ships option (a) — shadow eval emits only `evaluate.shadow.{pass,deny}` receipts, no `procedure.enter` / `procedure.transition` / `procedure.timeout` from the shadow path. The shadow's `score_contributions` and `total_score` are computed and surfaced on the receipt (scoring is stateless); procedure effects are not. A future RFC can flip to option (b) when 1+N or full procedure-preview becomes a goal.

### 3.2 Lifecycle — activate, clear, promote

Four operator-bearer-authenticated RPCs on `ConstitutionService`:

```protobuf
service ConstitutionService {
  rpc Activate(ActivateConstitutionRequest) returns (ActivateConstitutionResponse);  // unchanged
  rpc GetActive(GetActiveConstitutionRequest) returns (GetActiveConstitutionResponse);  // unchanged

  // NEW in Phase 3b — RFC 0018 §3.2
  rpc ActivateShadow(ActivateShadowConstitutionRequest) returns (ActivateShadowConstitutionResponse);
  rpc ClearShadow(ClearShadowConstitutionRequest) returns (ClearShadowConstitutionResponse);
  rpc PromoteShadow(PromoteShadowConstitutionRequest) returns (PromoteShadowConstitutionResponse);
  rpc GetActiveShadow(GetActiveShadowConstitutionRequest) returns (GetActiveShadowConstitutionResponse);
}
```

- **`ActivateShadow`** — operator auth → `constitution_from_proto` (full loader validation runs against the candidate) → `cedar_plus.activate_shadow(constitution)` → emit `constitution.shadow_activate` receipt. **Does not call `enforcement.activate`.** Replacing an existing shadow with a new one is permitted; the previously-shadowed slot is discarded with no separate clear receipt. Returns `(shadow_constitution_hash, shadow_activate_receipt)`.

- **`ClearShadow`** — operator auth → `cedar_plus.clear_shadow()` → emit `constitution.shadow_clear` receipt if a shadow was present; if the slot was already empty, return `OK` with the receipt id empty. Idempotent.

- **`PromoteShadow`** — operator auth → `cedar_plus.promote_shadow()` (atomic: shadow slot becomes new active, shadow slot empties). Then `enforcement.activate(promoted_constitution)` rebinds the engine onto the new active. Then emit `constitution.shadow_promote` receipt. Returns `(to_active_constitution_hash, shadow_promote_receipt)`. Returns `FAILED_PRECONDITION` when the shadow slot is empty at the moment of call.

- **`GetActiveShadow`** — agent-bearer-authenticated (any registered agent may read what's loaded; symmetric with `GetActive`). Returns the shadow `Constitution` and its hash, or unset if no shadow is loaded.

**Promote semantics in detail.**

1. Shadow slot's `ActivatedConstitution` is taken from `current_shadow` and placed into `current` under the same write lock.
2. The previous active is discarded (no per-promote `constitution.deactivate` receipt — discarding is part of the standard activate transition, just as a direct `Activate` discards the previous active).
3. `enforcement.activate(new_active)` is called. The engine's per-agent reputation and quarantine state are **preserved** (they're agent-keyed, not constitution-keyed). Sliding-window counters **reset** to match the existing `EnforcementEngine::activate` behaviour — the new constitution's `enforcement_rules` may differ in their windowing, so prior counters are no longer meaningful.
4. The `constitution.shadow_promote` receipt is distinct from `constitution.activate`. The distinction matters for audit: an operator reviewing the constitution chain wants to know whether a constitution arrived via direct `Activate` or via shadow-preview-then-promote. Same audit-clarity argument as `agent.operator_revoke` vs `agent.revoke` (RFC 0009).

### 3.3 Hot-path eval pair semantics

`EnvelopeHandler::send` consults both slots in one read:

```rust
let (active, shadow_opt) = cedar_plus.current_pair().await;
let eval_request = build_eval_request_for_send(active.constitution_hash, ..., &resolver_inputs).await;
let (active_outcome, shadow_outcome_opt) = cedar_plus.evaluate_pair(eval_request).await?;
```

`evaluate_pair` runs the active eval per the existing `evaluate` path, then — when the shadow slot was non-empty at `current_pair` read time — clones the request, rewrites `constitution_hash` to the shadow's, and runs a second eval against the shadow's policy set + schema + scoring rules. The entity snapshot is built once and reused.

**Critical invariant on snapshot reuse.** The snapshot must be valid against BOTH constitutions' schemas. When active and shadow share a `schema_version` this is trivially true. When they differ, the shadow's eval may fail with `CedarPlusError::RequestShapeInvalid` (Cedar's strict-mode validator rejecting an entity attribute the shadow's schema declares with a different type). Phase 3b treats such a shadow-eval failure as a **shadow deny** with `deny_reason = "shadow_schema_incompatible"` and emits the `constitution.evaluate.shadow.deny` receipt with that reason. The active eval is unaffected. Operators see exactly the failure they need to see: "this shadow constitution can't be promoted against current entity shapes without a coordinated schema migration."

**Cost.** Shadow eval doubles the per-send Cedar work plus the per-send scoring evaluation. Procedure evaluation is skipped on the shadow path per §3.1, so the cost is bounded. The substrate's sandbox bounds (`SandboxConfig::max_entity_count`, `max_policy_count`, `max_policy_depth`) apply per-eval; a shadow constitution whose policy set exceeds them is rejected by the loader at activate-shadow time, not at evaluate time.

### 3.4 Receipt emission

The hot path emits **up to two** evaluation receipts per envelope:

- **Active receipt** — `constitution.evaluate.{pass,deny}` as today. **Evidence shape gains one field when a shadow is configured:**
  - `shadow_constitution_hash` (type `type.yutha.dev/v1/Hash`) — content-address of the shadow's constitution.
  
  Auditors join active and shadow receipts for the same envelope by matching `subject_agent_id` + `input_attribute_digest` + this new field. When no shadow is configured, the field is absent (proto-additive, breaking-change-free on the audit-tooling side).

- **Shadow receipt** — `constitution.evaluate.shadow.{pass,deny}`. Emitted iff the shadow eval was attempted (i.e., shadow slot was non-empty when `current_pair()` returned). Evidence shape:
  - `shadow_constitution_hash` (type `type.yutha.dev/v1/Hash`) — content-address of the shadow constitution (NOT `constitution_hash`, to make audit queries unambiguous).
  - `action_kind` — the substrate action being evaluated (`"SendEnvelope"`).
  - `matched_rule_ids` — Cedar policy ids from the shadow's policy set.
  - `input_attribute_digest` — same canonical bytes hash as the active receipt for this envelope (the snapshot was shared); auditors use it to correlate.
  - `subject_agent_id` — same agent the active receipt names.
  - `deny_reason` (deny variant only) — Cedar mapping per existing semantics, plus the special `"shadow_schema_incompatible"` for the cross-schema failure path from §3.3.
  - `total_score` (pass variant only, when shadow `prefer` rules contributed) — same shape as active eval.

Receipt order on the wire is **deterministic**: the active receipt appends first, then the shadow receipt. Replay-time reconstruction depends on this order for the receipt-window iteration to be reproducible.

### 3.5 Engine state invariant

The `EnforcementEngine` MUST NOT react to shadow receipts. The filter lives at the receipt-publisher forwarder task (`crates/yutha-control-plane/src/main.rs`, the receiver loop that drains the channel and calls `on_receipt`):

```rust
while let Some(view) = rx.recv().await {
    if view.action_kind.starts_with("constitution.evaluate.shadow.") {
        continue;  // Shadow receipts are observation-only per RFC 0018 §3.5.
    }
    if let Err(e) = enforcement.on_receipt(&view.as_receipt_view()) {
        tracing::warn!(error = %e, "engine on_receipt rejected; engine will rebuild from log");
    }
}
```

This is the **only** filter point. `PublishingReceiptStore::append` continues to fan every receipt onto the channel (the receipt log is authoritative; the engine being one consumer doesn't change the substrate's responsibility). The `build_view` extractor stays pure. The engine stays ignorant of shadow semantics — if a future change wants to expose shadow receipts to a different downstream consumer (e.g., an OTel exporter that surfaces shadow divergence as a metric), the additional consumer subscribes to a separate channel or filters by the same prefix.

**Why not filter at `build_view` or inside `on_receipt`?** Filter-at-build forces `build_view` to know about shadow semantics; the receipt-publisher module exists precisely to extract substrate-agnostic match-relevant fields. Filter-inside-`on_receipt` couples the cedar-plus crate to the action-kind string convention that lives in the canonical-actions registry; the engine should stay unaware. The forwarder is the natural seam: it already knows which downstream consumer it's calling.

### 3.6 Operator workflow

The end-to-end flow operators run when previewing a new constitution:

1. **Author the candidate constitution.** Cedar source + engine config (YAML). Same authoring loop as `Activate`.
2. **Activate as shadow.** `yutha-ops activate-shadow constitution.cedar --engine-config engine.yaml`. The CLI prints the `shadow_constitution_hash` and the `constitution.shadow_activate` receipt id.
3. **Let traffic flow.** Production envelopes continue under the active constitution. Each envelope produces an active receipt and a shadow receipt; the active gates, the shadow only observes.
4. **Watch divergence.** `yutha-ops grep constitution.evaluate.shadow.deny --since 10m` shows shadow denies the active permitted. `yutha-ops grep constitution.evaluate.shadow.pass --since 10m | yutha-ops grep constitution.evaluate.deny --joined-by input_attribute_digest` shows the inverse — envelopes the active denied but the shadow would have permitted. Either signal is interesting.
5. **Iterate.** When the divergence is wrong, the operator either clears the shadow (`yutha-ops clear-shadow`) and re-authors the candidate, or amends the candidate in place by calling `activate-shadow` again (replaces the prior shadow).
6. **Promote.** `yutha-ops promote-shadow` flips the shadow into the active slot atomically. The CLI prints the `to_active_constitution_hash` and the `constitution.shadow_promote` receipt id.

A constitution that has been promoted has the same content-address as it did while it was a shadow — content-addressing is over the constitution's canonical bytes, not over its slot history. Replay sessions that reference the constitution by hash continue to work after promotion.

## 4. Detailed design — replay engine (Phase 3c)

### 4.1 Replay sessions and isolation

A **replay session** is an isolated container for one preview run. Each session carries:

- A `replay_session_id` — UUIDv7, generated server-side at `CreateSession`. Surfaces as evidence on every receipt the session produces.
- A `candidate_constitution` — passed by value at session creation, NOT by reference to a loaded slot. This lets operators preview a constitution that has never been activated (or shadowed) on the production substrate, and lets them preview many candidates in parallel without thrashing the shadow slot.
- A `receipt_window` — strict tuple `(from_unix_ns: u64, to_unix_ns: u64, action_kind_filter: repeated string)`. The filter is whitelist semantics: when empty, every action-kind is replayed; when non-empty, only listed kinds are. Typical usage: `["envelope.send"]` to replay only Send events.
- A `replay_mode` — `cold` or `warm` (see §4.2).
- An `engine: EnforcementEngine` instance, instantiated fresh per session. Activated with the candidate. Sliding-window counters start at zero in cold mode; rebuilt in warm mode from a lookback window.
- A `receipt_store: Arc<dyn ReceiptStore>` handle, scoped to the session. Within-session appends and queries are isolated; production queries cannot reach session receipts.
- A `control_plane_identity: Arc<ControlPlaneIdentity>` — the same identity production uses, so receipts within the session are signed identically.

The session-scoped receipt-store handle is obtained from a new `ReplayStore` trait:

```rust
#[async_trait]
pub trait ReplayStore: Send + Sync {
    /// Returns a ReceiptStore handle isolated to this session.
    /// All append + query through the returned handle is partitioned
    /// from production receipts and from other replay sessions.
    fn session_store(&self, session_id: &ReplaySessionId) -> Arc<dyn ReceiptStore>;

    async fn create_session(&self, session_id: &ReplaySessionId, metadata: ReplaySessionMetadata) -> Result<()>;
    async fn delete_session(&self, session_id: &ReplaySessionId) -> Result<()>;
    async fn list_sessions(&self) -> Result<Vec<ReplaySessionMetadata>>;
}
```

The returned `session_store` is a `ReceiptStore`-shaped surface — the existing in-process code that takes `Arc<dyn ReceiptStore>` (`build_eval_request_for_send`, emit functions, etc.) operates unchanged on it. The Postgres backend uses a dedicated schema (`replay_<session_id>` table prefix in the proof-of-concept impl; future impls may consolidate to a single table partitioned by session_id). The memory backend uses a sibling `MemoryReplayStore` keyed under the session id with the same `HashMap` shape as `MemoryStore`.

### 4.2 Cold vs warm engine init

- **`cold`** — engine starts at defaults. Every agent has reputation `1.0`, no quarantine, no procedure instances, sliding-window counters at zero. Answers: "what would this candidate do on this window, starting from a clean slate?"
- **`warm`** — engine state is rebuilt from receipts preceding `from_unix_ns` for a configurable lookback (default **24 hours**, configurable per session at creation time). The rebuild calls `engine.on_receipt(view)` for each predecessor receipt in monotonic order, then activates the candidate. The window's evaluations start with engine state that approximates what production engine state was at `from_unix_ns`. Answers: "what would this candidate have done on this window, in the engine state that actually existed at the start of it?"

Warm mode's lookback is bounded by design — exhaustive rebuild from swarm genesis is the forensic-audit use-case explicitly deferred to a follow-on RFC (§6).

### 4.3 Within-session receipt semantics

Replay receipts share canonical contracts with production receipts; what distinguishes them is **store membership** plus **evidence markers**.

- **Action-kinds**: replay receipts use the SAME canonical `action_kind` strings as production (`constitution.evaluate.pass`, `envelope.send`, `enforcement.detect`, etc.). No `replay.*` namespace explosion on the evaluation path. Operators get a uniform mental model: a `constitution.evaluate.deny` receipt is a constitution-evaluate-deny regardless of which store it lives in.
- **`replay_session_id` evidence marker**: every receipt produced within a session carries an evidence entry `{"key": "replay_session_id", "value_type": "type.yutha.dev/v1/String", "value": <session_uuid>}`. This is the belt-and-suspenders distinguishability layer — even if a receipt is exported from the session store and surfaced elsewhere, the marker prevents it being mistaken for production.
- **Causal predecessors**: replay-emitted receipts form a session-internal causal chain. Each replay step's emitted receipts reference the previous step's emitted receipts as predecessors (not the originals from production). This keeps within-session graph walks self-contained — an operator graph-walking from a `enforcement.quarantine` replay receipt traverses through `enforcement.detect` replay receipts back to the session's first step, all within the session store. Cross-references to production receipts would break under store isolation since the session store doesn't know about production content-addresses.
- **Signatures**: replay receipts within a session ARE signed by `ControlPlaneIdentity` with `SignatureRole::Actor`. Same provenance contract as production substrate receipts. Within-session audit holds; unsigned replay would introduce a "trust the session orchestrator" assumption that contradicts the rest of the substrate.
- **Sealing**: replay receipts are NEVER sealed — `AppendOptions::wait_for_seal` is forced false on the session-store path. The `AnchorDriver` operates over the production store only (§4.4).

### 4.4 Never-anchors invariant — by construction

Replay receipts are **never** anchored to Sui per RFC 0014. The substrate enforces this by construction at two layers:

1. **`AnchorDriver`'s `ReceiptStoreCandidateSource`** is constructed at startup with the production `Arc<dyn ReceiptStore>` (`crates/yutha-control-plane/src/main.rs` wiring). Session-scoped replay stores are distinct `Arc<dyn ReceiptStore>` instances obtained from `ReplayStore::session_store(...)`. The anchor driver provably can't see receipts in a store it doesn't hold a handle to.
2. **`PublishingReceiptStore`** (the production-side decorator that fans every appended receipt onto the enforcement engine's mpsc channel) wraps ONLY the production store. The replay session orchestrator obtains the raw `Arc<dyn ReceiptStore>` from `ReplayStore::session_store(...)` — no `PublishingReceiptStore` wrapper. Replay receipts therefore never enter the production engine's forwarder channel; the session's isolated `EnforcementEngine` instance handles `on_receipt` inline (single-threaded per session, no async channel needed).

This is the substrate's enforcement of the locked architectural decision that replay is for **operator decision-making**, not for the swarm's truth-preserving audit log. The Phase 3c-F conformance test makes the by-construction invariants explicit. A future RFC may relax this if a forensic-replay-with-anchored-attestation use-case emerges; that's out of scope here.

### 4.5 ReplayService gRPC

The control plane exposes session lifecycle and query operations via a new operator-bearer-authenticated service:

```protobuf
service ReplayService {
  // Operator-bearer-authenticated. Lifecycle:
  rpc CreateSession(CreateReplaySessionRequest) returns (CreateReplaySessionResponse);
  rpc RunSession(RunReplaySessionRequest) returns (stream ReplayProgress);
  rpc CloseSession(CloseReplaySessionRequest) returns (CloseReplaySessionResponse);
  rpc ListSessions(ListReplaySessionsRequest) returns (ListReplaySessionsResponse);

  // Query the session's isolated receipt store. Operator-bearer-
  // authenticated; takes the same Query variants as
  // ReceiptService.Query but scoped to the session.
  rpc QueryReplayReceipts(QueryReplayReceiptsRequest) returns (QueryReplayReceiptsResponse);
}
```

**`CreateSession`** creates the session in the `ReplayStore`, instantiates the per-session `EnforcementEngine` + `CedarPlusEvaluator`, and (when `replay_mode == warm`) performs the lookback rebuild. Returns the `replay_session_id` and the content-address of the `replay.session.create` audit receipt that landed in the production store.

**`RunSession`** is server-streaming — it iterates the production receipt window matching the session's filter and `play_receipt`s each one, emitting `ReplayProgress` items as it advances. The progress shape carries `(progress_unix_ns, receipts_replayed, latest_replay_receipt_id)` so operators monitoring long-running replays see throughput in real time. Cancellation by the operator (closing the stream) leaves the session in a quiescent state — the operator can `QueryReplayReceipts` against whatever has been replayed so far, or `CloseSession` to release resources.

**`CloseSession`** deletes the session from the `ReplayStore` (which drops the session-scoped store + every receipt within it), shuts down the per-session engine instance, and lands a `replay.session.close` audit receipt in the production store. Sessions also auto-close after a configurable TTL (default **24 hours after last RunSession activity**) — the operator's quiescent-but-not-closed window is bounded.

**`ListSessions`** returns active sessions for the swarm, scoped by the operator's bearer. Useful for cleanup of forgotten sessions and for the `yutha-ops` CLI's listing command.

**`QueryReplayReceipts`** takes the same `Query` variants as `ReceiptService.Query` (ByReceiptId / ByPredecessor / ByAgent / ByActionKind / ByTimeRange) but evaluates them against the session's store. The session id is part of the request, not derivable from the query; operators must pass it explicitly.

### 4.6 Audit-trail anchor in the production store

Session lifecycle events DO land in the production receipt store as audit records — they are operator actions that consumed substrate resources, and the production audit trail captures who created/closed what session, even though the within-session evaluation receipts live in the isolated store. Two new canonical action-kinds (`replay.session.create`, `replay.session.close`) cover this; their evidence shape is documented in §5.

## 5. Canonical action-kinds

Five new entries land in [`/spec/receipt/canonical-actions.md`](../receipt/canonical-actions.md) under the Constitution domain. Reproduced here for the RFC's reading-without-the-registry case; the registry is authoritative.

| `action_kind` | Producer | Actor | Notes |
|---------------|----------|-------|-------|
| `constitution.evaluate.shadow.pass` | Constitution engine | Subject agent | One per successful shadow-constitution evaluation when a shadow slot is configured (RFC 0018 §3.4). Evidence: `shadow_constitution_hash`, `action_kind`, `matched_rule_ids`, `input_attribute_digest`, `subject_agent_id`, `total_score` (Decimal — only when shadow `prefer` rules contributed). Emitted in the same Send path as the active `constitution.evaluate.pass` receipt; ordering is active-then-shadow. **Engine MUST NOT react to this receipt.** |
| `constitution.evaluate.shadow.deny` | Constitution engine | Subject agent | One per denied shadow-constitution evaluation. Same evidence as the pass variant plus `deny_reason`. `deny_reason` shape mirrors `constitution.evaluate.deny` and additionally includes the special value `"shadow_schema_incompatible"` for cases where the shadow's schema-version differs from the active's and the shared entity snapshot violates the shadow's strict-mode validation (RFC 0018 §3.3). **Engine MUST NOT react to this receipt.** |
| `constitution.shadow_activate` | Constitution engine | Operator | A new shadow constitution has been activated. Evidence: `shadow_constitution_hash`, `shadow_constitution_version`, `parent_active_constitution_hash` (the active at the moment of shadow activation — operators correlating shadow runs back to the production active they were measured against), `schema_version`. Operator-bearer-authenticated, same auth model as `constitution.activate`. |
| `constitution.shadow_clear` | Constitution engine | Operator | The shadow slot has been cleared. Evidence: `previously_shadowed_constitution_hash` (absent when the slot was already empty at the time of call — the RPC is idempotent and the receipt records the operator's intent regardless). |
| `constitution.shadow_promote` | Constitution engine | Operator | A shadow constitution has been promoted to active atomically (RFC 0018 §3.2). Evidence: `from_active_constitution_hash`, `to_active_constitution_hash` (this is the shadow's hash, which now addresses the new active), `to_constitution_version`, `schema_version`. Distinct from `constitution.activate` for audit clarity — auditors want to know whether a constitution arrived via direct activation or via shadow-preview-then-promote. |
| `replay.session.create` | Replay engine | Operator | An operator created a replay session (RFC 0018 §4.5). Lands in the **production** receipt store (audit trail of who created what session). Evidence: `replay_session_id` (UUIDv7), `candidate_constitution_hash`, `candidate_constitution_version`, `receipt_window_from_unix_ns`, `receipt_window_to_unix_ns`, `action_kind_filter` (comma-joined string; empty = wildcard), `replay_mode` (`"cold"` \| `"warm"`), `warm_lookback_hours` (only present when `replay_mode == "warm"`). |
| `replay.session.close` | Replay engine | Operator | A replay session has been closed — either explicitly via `ReplayService.CloseSession` or automatically after the inactivity TTL. Lands in the **production** receipt store. Evidence: `replay_session_id`, `receipts_replayed_total` (u64), `close_reason` (`"explicit"` \| `"ttl"`), `session_create_receipt_id` (content-address of the corresponding `replay.session.create` receipt for direct join). |

Within-session evaluation receipts (`constitution.evaluate.{pass,deny}`, `procedure.{enter,transition,timeout}`, `enforcement.{detect,coach,quarantine,evict,reverse}`, etc.) use the SAME action-kind strings as production but land in the session's isolated store and carry an additional `replay_session_id` evidence entry. See §4.3 for the full semantics.

## 6. What's NOT in scope (this RFC)

- **Multi-shadow (1+N).** Only one shadow slot is supported in Phase 3b. The public API is shaped so a follow-on RFC can extend the slot to `Vec<NamedShadow>` (each with an operator-assigned name) without breaking the existing surface — but the extension itself is a separate RFC.
- **Full forensic / audit replay.** Phase 3c's replay is for constitution-change preview. Replaying historical bursts to investigate past incidents (where the **same** constitution as production is replayed and operators compare against what the production engine actually did) is a meaningful but different surface; deferred.
- **Time-travel debugging.** Stepping through individual receipts in a replay session with introspection of intermediate engine state. Useful but Phase-TBD.
- **Cross-swarm shadow promotion.** Activating one swarm's candidate as a shadow on another swarm; deferred to the federation workstream.
- **Shadow-mode SLAs.** The shadow eval is best-effort; if the cedar evaluator returns an internal error on the shadow path, the active eval succeeds and the shadow emits a deny-with-`evaluator_internal_error`-reason receipt. No retries, no fallback, no metric guarantees on shadow eval latency.

## 7. Migration and compatibility

This RFC introduces additive surfaces:

- **Proto.** Four new RPCs on `ConstitutionService` (Phase 3b) and a new `ReplayService` with five RPCs (Phase 3c); existing RPCs are byte-identical. Existing SDKs continue working.
- **Receipts.** Seven new action-kinds (five shadow-related, two replay-session-lifecycle); existing action-kinds are unchanged. The `constitution.evaluate.{pass,deny}` evidence list gains an optional `shadow_constitution_hash` field that is absent when no shadow is configured. Within-replay-session evaluation receipts gain a `replay_session_id` evidence entry — production-side audit tooling that hasn't been updated for replay treats these receipts identically to production ones unless it opts in to filter on the new key. Tools that asserted exhaustive evidence-key sets need a one-line update.
- **Stores.** New `ReplayStore` trait in `yutha-receipt`. New `yutha-replay` crate hosts the `ReplaySession` orchestrator. Existing `ReceiptStore` callers are unchanged.
- **CLI.** `yutha-ops` gains `activate-shadow`, `clear-shadow`, `promote-shadow` (Phase 3b) and `replay` subcommands (Phase 3c). Existing subcommands unchanged.
- **Python SDK.** `ConstitutionAPI` gains the four shadow methods (Phase 3b). New `ReplayAPI` carries `create_session`, `run_session` (async iterator over progress), `query_replay_receipts`, `close_session`, `list_sessions` (Phase 3c). Existing methods unchanged.

Per [memory: `feedback-no-backcompat-pre-phase2`](#), the repo is pre-Phase-2-public, so breaking changes would be acceptable here — they just aren't necessary because the design is naturally additive.

## 8. Open questions for follow-on phases

1. **OTel-side shadow signal.** When RFC 0019 (Phase 3f, OTel semantic conventions) lands, what's the right OTel signal shape for shadow divergence? A metric counting `evaluate.shadow.deny` rate over `evaluate.deny` rate? A trace attribute on the active eval span pointing at the shadow's receipt? Deferred to RFC 0019.
2. **Replay-side OTel.** Should replay-session receipts produce OTel spans tagged with the `replay_session_id`? RFC 0019.
3. **Shadow eval and workload extensions.** When the shadow constitution declares workload extensions different from the active (RFC 0011 §4), does the substrate refuse the activate-shadow or treat it as a forced schema-incompatibility? Phase 3b ships the latter (the loader runs at activate-shadow time and refuses; the workload registration surface is shared). Open question for whether a workload-extension-shadow surface is meaningful as a follow-on.
4. **Promote with engine-state reset opt-in.** Phase 3b ships engine reputation + quarantine preserved across promote, sliding windows reset. An operator who wants a clean-slate promote (e.g., to genuinely start from scratch after a constitutional crisis) has no direct path today. Phase TBD.
5. **Shadow-of-shadow.** A future operator workflow might want to compare two candidate constitutions against each other AND against the active. The 1+N extension already discussed addresses this; sketched here for awareness.

## 9. As-shipped notes

### 9.1 Phase 3b as-shipped notes

Committed locally 2026-06-09 (push held for Phase 3 workstream close at Phase 3h). Per-sub-phase summary lives in the auto-memory's `project-phase-3-simulation-observability` "Phase 3b as-shipped state" section. Notable substrate-level decisions made during implementation:

- The shadow path skips procedure-state mutation (§3.1) — implementation introduces an `EvaluationMode { Active, Shadow }` enum threaded through a private `evaluate_against(request, activated, mode)` helper in `CedarPlusEvaluator`. Trait `ConstitutionEvaluator::evaluate` is now a thin delegate; `evaluate_pair` calls the helper twice.
- Cross-schema shadow eval failures (§3.3) surface as a synthesized `Decision::Deny` with `deny_reason = "shadow_schema_incompatible"` via a `schema_incompatible_deny(request)` helper. Caught at all three Cedar shape-construction failure points: entity build, context build, Cedar `Request::new`.
- The engine fan-out filter (§3.5) lives at `crates/yutha-control-plane/src/main.rs::spawn_enforcement_forwarder` — a single `view.action_kind.starts_with("constitution.evaluate.shadow.")` check skips shadow receipts before they reach `EnforcementEngine::on_receipt`. `PublishingReceiptStore::build_view` stays pure; `EnforcementEngine` stays shadow-agnostic.
- The atomic promote semantic (§3.2) is enforced by `CedarPlusEvaluator::promote_shadow()`'s lock ordering — shadow write lock first, then active write lock, then receipt emission. The `enforcement.activate(promoted)` rebind happens at the gRPC handler level (`ConstitutionHandler::promote_shadow`) AFTER the substrate-side swap completes.
- Conformance regression guard: scenario S10 (`crates/yutha-conformance/src/scenarios/s10_shadow_mode.rs`) covers slot independence + receipt action-kind partitioning + RFC 0018 §3.4 evidence shape against the persisted receipts.

### 9.2 Phase 3c as-shipped notes

Committed locally 2026-06-10 (push held for Phase 3 workstream close at Phase 3h). Per-sub-phase summary lives in the auto-memory's `project-phase-3-simulation-observability` "Phase 3c as-shipped state" section. Notable substrate-level decisions made during implementation:

- **Production-store isolation is by construction, not by filter** (§4.1). The session's `Arc<dyn ReceiptStore>` is distinct from the production handle the gRPC services hold; `ReplaySession::run_window` only ever calls `append` against the session-scoped handle. The `AnchorDriver` is wired against the production handle only, so replay emissions never even appear on the anchoring candidate path. The invariant has two regression guards: `crates/yutha-anchor-sui/src/candidate_source.rs::replay_receipts_never_appear_in_candidates` (anchoring side) and conformance scenario S11 (session-scoped emissions land only in the session store, production count unchanged across the run).
- **Session-internal causal chain via `last_step_emissions`** (§4.3). Implemented as a `tokio::sync::Mutex<Vec<Hash>>` on `ReplaySession`; `play_receipt` captures it at the top of the call, uses the snapshot as `CausalRef::predecessors` on every emission of that step, then unconditionally writes the step's emitted-receipt-ids back at the end. The unconditional reset means the chain only carries across *consecutive* emitting steps — a no-effect step resets the head to `[]`. Conformance scenario S11 uses `count_threshold: 1` so every replayed receipt emits, exercising the chain across all four steps.
- **`replay_session_id` evidence marker on every within-session enforcement receipt** (§4.3). `ReplaySession::emit_session_enforcement_receipt` prepends the marker via `Evidence::new("replay_session_id", "type.yutha.dev/v1/String", session_id.to_string().into_bytes())` before any effect-specific evidence. Same canonical action-kinds as production (`enforcement.detect` / `coach` / `quarantine` / `evict` / `reverse`) — the marker is the only distinguisher.
- **Cold + warm init share `create_cold` as the substrate** (§4.2). `create_warm` calls `create_cold` to land the engine + activated constitution, then iterates the lookback window through `engine.on_receipt` + `engine.poll_scheduled` with `let _effects = ...` to discard the lookback's effects — only the post-`from_unix_ns` window produces session-scoped emissions. Lookback hours capped at `u32`; the wall-clock for the synthetic timestamps uses `1970-01-01T00:00:00Z` / `9999-12-31T23:59:59Z` since `MemoryReceiptStore::query` by time-range gates on `monotonic_ns`, not the RFC 3339 string.
- **Replay-session lifecycle audit lands in the production store, not the session store** (§4.6). `ReplayHandler::create_session` and `close_session` emit `replay.session.create` / `replay.session.close` receipts against `state.receipt_store` (production), bracketing the session for downstream auditors. Within-session enforcement emissions are otherwise the only writes to the session-scoped store.
- **`ReplaySessionId` is UUIDv7 with `FromStr`** matching `AgentId` / `SwarmId`'s convention; this corrected an earlier 3c-B spec draft that called for UUIDv4. The `FromStr` impl (instead of an inherent `from_str`) was a clippy-driven cleanup during 3c-C — callers use idiomatic `s.parse::<ReplaySessionId>()`.
- **`MemoryReplayStore` is the Phase 3c-shipped backend.** Per-session state is `HashMap<ReplaySessionId, Arc<MemoryStore>>` plus a `HashMap<ReplaySessionId, ReplaySessionMetadata>` slot for the `touch_session` lifecycle counters. `PostgresReplayStore` ships as a follow-on (tracked separately in the auto-memory `project-phase-3-simulation-observability` follow-on list); the operator-facing surface (gRPC + Python SDK + `yutha-ops`) is backend-agnostic so the swap is contained to the registry wiring in `main.rs`.
- **Operator surface across all three layers.** `ReplayService` gRPC (Create / Run server-stream / Query / Close / List) in `crates/yutha-control-plane/src/grpc/replay.rs` (~450 lines); `yutha.ReplayAPI` on the Python SDK client with `_wrap_run_session_stream` async generator + 5 dataclasses + `ReplayMode` enum; `yutha-ops` CLI subcommands `replay-create` / `replay-run` / `replay-query` / `replay-close` / `replay-list` mirroring the Python surface. The CLI's `replay-create` defaults to `--mode cold` and `--warm-lookback-hours 24` to match the substrate defaults.
- **Operator-facing operational story.** `docs/operator/replay.md` is the operator's runbook; covers cold vs warm, same-control-plane semantic isolation (different `Arc`s) vs real compute/Postgres load (shared), the two-process-against-shared-Postgres mitigation when load matters, session TTL + auto-close emission with `close_reason = "ttl"`, the never-anchors invariant, and the explicit no-rate-limit-today caveat. The shadow-mode page's "replay not yet shipped" caveat was retired and now cross-links to the replay page as the backward-looking diligence pair.

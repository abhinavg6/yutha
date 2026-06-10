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

## 4. Detailed design — replay engine (Phase 3c, design-open)

This section pins the **contracts** the replay engine satisfies. Implementation details (the exact gRPC surface, the exact replay-store schema in Postgres) firm up in Phase 3c and the as-shipped notes amend this section at 3c close.

### 4.1 Replay sessions and isolation

A **replay session** is an isolated container for one preview run. Each session has:

- A `replay_session_id` (UUID, generated server-side at session creation).
- A `candidate_constitution` (the constitution being previewed — passed by value, NOT by reference to an activated slot, so the replay can preview a constitution that was never activated).
- A `receipt_window` (a `[from_ns, to_ns]` time range PLUS a `receipt_action_kind_filter` listing the action-kinds that should be replayed — typically `["SendEnvelope"]` or all-envelopes).
- An isolated `EnforcementEngine` instance (constructed fresh, with state seeded from the receipt-window's prefix if the operator wants the engine state to reflect production at the start of the window).
- A sibling `ReceiptStore` keyed under the session id. Replay-emitted receipts land in this store; they MUST NOT appear in production queries.

### 4.2 Receipt-derived replay vs engine state preservation

Two state-init modes for the per-session engine:

- **`replay_mode = "cold"`** — engine starts empty. Every agent has default reputation, no quarantine, no procedure instances. Used when the operator wants to know "what would this constitution decide on this window, starting from scratch?"
- **`replay_mode = "warm"`** — engine is rebuilt from the receipt-window's predecessor receipts (per [`/spec/constitution/evaluation.md`](../constitution/evaluation.md) §6 receipt-derived reconstruction). The window's evals start with engine state that matches production at `from_ns`. Used when the operator wants to know "what would this constitution have done on this window, in the engine state that actually existed at the start?"

Both modes produce replay receipts identical in shape to production receipts (same action-kinds, same evidence, same canonical bytes contract) except the receipts are addressed under the session's isolated store.

### 4.3 Never-anchors invariant

Replay receipts are **never** anchored to Sui per RFC 0014. The `AnchorDriver`'s candidate source (`ReceiptStoreCandidateSource`) is bound to the production receipt store, not to any replay session's store. Replay sessions whose receipts are never read by the anchor driver are invisible to the on-chain audit trail by construction.

This is the substrate's enforcement of the locked architectural decision that replay is for **operator decision-making**, not for the swarm's truth-preserving audit log. A future RFC may relax this if a forensic-replay-with-anchored-attestation use-case emerges; that's explicitly out of scope here.

### 4.4 RPC surface (sketch)

A new `ReplayService` is sketched but not finalized in this RFC — 3c will firm it up. Provisional shape:

```protobuf
service ReplayService {
  rpc CreateSession(CreateReplaySessionRequest) returns (CreateReplaySessionResponse);
  rpc RunSession(RunReplaySessionRequest) returns (stream ReplayProgress);
  rpc QueryReceipts(QueryReplayReceiptsRequest) returns (QueryReplayReceiptsResponse);
  rpc CloseSession(CloseReplaySessionRequest) returns (CloseReplaySessionResponse);
}
```

`CreateSession` returns a `replay_session_id`. `RunSession` is server-streaming — it emits `ReplayProgress` items as the engine works through the window so long-running replays can be monitored. `QueryReceipts` is the replay-store analogue of `ReceiptService.Query`. `CloseSession` releases the session's store + engine resources; sessions also auto-close after a configurable TTL.

**This shape is non-binding for 3c.** The as-shipped notes at 3c close amend §4.4 with the final surface.

## 5. Canonical action-kinds

Five new entries land in [`/spec/receipt/canonical-actions.md`](../receipt/canonical-actions.md) under the Constitution domain. Reproduced here for the RFC's reading-without-the-registry case; the registry is authoritative.

| `action_kind` | Producer | Actor | Notes |
|---------------|----------|-------|-------|
| `constitution.evaluate.shadow.pass` | Constitution engine | Subject agent | One per successful shadow-constitution evaluation when a shadow slot is configured (RFC 0018 §3.4). Evidence: `shadow_constitution_hash`, `action_kind`, `matched_rule_ids`, `input_attribute_digest`, `subject_agent_id`, `total_score` (Decimal — only when shadow `prefer` rules contributed). Emitted in the same Send path as the active `constitution.evaluate.pass` receipt; ordering is active-then-shadow. **Engine MUST NOT react to this receipt.** |
| `constitution.evaluate.shadow.deny` | Constitution engine | Subject agent | One per denied shadow-constitution evaluation. Same evidence as the pass variant plus `deny_reason`. `deny_reason` shape mirrors `constitution.evaluate.deny` and additionally includes the special value `"shadow_schema_incompatible"` for cases where the shadow's schema-version differs from the active's and the shared entity snapshot violates the shadow's strict-mode validation (RFC 0018 §3.3). **Engine MUST NOT react to this receipt.** |
| `constitution.shadow_activate` | Constitution engine | Operator | A new shadow constitution has been activated. Evidence: `shadow_constitution_hash`, `shadow_constitution_version`, `parent_active_constitution_hash` (the active at the moment of shadow activation — operators correlating shadow runs back to the production active they were measured against), `schema_version`. Operator-bearer-authenticated, same auth model as `constitution.activate`. |
| `constitution.shadow_clear` | Constitution engine | Operator | The shadow slot has been cleared. Evidence: `previously_shadowed_constitution_hash` (absent when the slot was already empty at the time of call — the RPC is idempotent and the receipt records the operator's intent regardless). |
| `constitution.shadow_promote` | Constitution engine | Operator | A shadow constitution has been promoted to active atomically (RFC 0018 §3.2). Evidence: `from_active_constitution_hash`, `to_active_constitution_hash` (this is the shadow's hash, which now addresses the new active), `to_constitution_version`, `schema_version`. Distinct from `constitution.activate` for audit clarity — auditors want to know whether a constitution arrived via direct activation or via shadow-preview-then-promote. |

## 6. What's NOT in scope (this RFC)

- **Multi-shadow (1+N).** Only one shadow slot is supported in Phase 3b. The public API is shaped so a follow-on RFC can extend the slot to `Vec<NamedShadow>` (each with an operator-assigned name) without breaking the existing surface — but the extension itself is a separate RFC.
- **Full forensic / audit replay.** Phase 3c's replay is for constitution-change preview. Replaying historical bursts to investigate past incidents (where the **same** constitution as production is replayed and operators compare against what the production engine actually did) is a meaningful but different surface; deferred.
- **Time-travel debugging.** Stepping through individual receipts in a replay session with introspection of intermediate engine state. Useful but Phase-TBD.
- **Cross-swarm shadow promotion.** Activating one swarm's candidate as a shadow on another swarm; deferred to the federation workstream.
- **Shadow-mode SLAs.** The shadow eval is best-effort; if the cedar evaluator returns an internal error on the shadow path, the active eval succeeds and the shadow emits a deny-with-`evaluator_internal_error`-reason receipt. No retries, no fallback, no metric guarantees on shadow eval latency.

## 7. Migration and compatibility

This RFC introduces additive surfaces:

- **Proto.** Four new RPCs on `ConstitutionService`; existing RPCs are byte-identical. Existing SDKs continue working.
- **Receipts.** Five new action-kinds; existing action-kinds are unchanged. The `constitution.evaluate.{pass,deny}` evidence list gains an optional `shadow_constitution_hash` field that is absent when no shadow is configured — auditing tools that walked evidence by key continue to work; tools that asserted exhaustive evidence-key sets need a one-line update.
- **CLI.** `yutha-ops` gains `activate-shadow`, `clear-shadow`, `promote-shadow` subcommands. Existing subcommands unchanged.
- **Python SDK.** `ConstitutionAPI` gains `activate_shadow`, `clear_shadow`, `promote_shadow`, `get_active_shadow` methods. Existing methods unchanged.

Per [memory: `feedback-no-backcompat-pre-phase2`](#), the repo is pre-Phase-2-public, so breaking changes would be acceptable here — they just aren't necessary because the design is naturally additive.

## 8. Open questions for follow-on phases

1. **OTel-side shadow signal.** When RFC 0019 (Phase 3f, OTel semantic conventions) lands, what's the right OTel signal shape for shadow divergence? A metric counting `evaluate.shadow.deny` rate over `evaluate.deny` rate? A trace attribute on the active eval span pointing at the shadow's receipt? Deferred to RFC 0019.
2. **Replay-side OTel.** Should replay-session receipts produce OTel spans tagged with the `replay_session_id`? RFC 0019.
3. **Shadow eval and workload extensions.** When the shadow constitution declares workload extensions different from the active (RFC 0011 §4), does the substrate refuse the activate-shadow or treat it as a forced schema-incompatibility? Phase 3b ships the latter (the loader runs at activate-shadow time and refuses; the workload registration surface is shared). Open question for whether a workload-extension-shadow surface is meaningful as a follow-on.
4. **Promote with engine-state reset opt-in.** Phase 3b ships engine reputation + quarantine preserved across promote, sliding windows reset. An operator who wants a clean-slate promote (e.g., to genuinely start from scratch after a constitutional crisis) has no direct path today. Phase TBD.
5. **Shadow-of-shadow.** A future operator workflow might want to compare two candidate constitutions against each other AND against the active. The 1+N extension already discussed addresses this; sketched here for awareness.

## 9. As-shipped notes

*(To be filled in at Phase 3c close. Phase 3b ships the shadow-mode half; Phase 3c ships the replay half and amends §4 with the final RPC surface, the final session-state semantics, and any divergence from this RFC.)*

### 9.1 Phase 3b as-shipped notes

*(To be filled in at Phase 3b close, after sub-phases 3b-C through 3b-G ship.)*

### 9.2 Phase 3c as-shipped notes

*(To be filled in at Phase 3c close.)*

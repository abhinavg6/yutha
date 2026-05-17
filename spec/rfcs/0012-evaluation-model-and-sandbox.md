# RFC 0012: Constitution Evaluation Model + Sandbox Contract

> **Status:** Draft
> **Authors:** Workstream A (Specs) + Workstream E (Constitution engine)
> **Filed:** 2026-05-15
> **Targets spec:** `/spec/constitution/evaluation.md` (new),
>                   `/spec/receipt/canonical-actions.md` (extends `constitution.evaluate.deny` reason set with sandbox-bound reasons)
> **Targets phase:** Phase 2 (Coordination & Norms)
> **Discussion:** TBD
> **Predecessor:** [RFC 0010](./0010-constitution-language-v1.md), [RFC 0011](./0011-cedar-plus-extensions.md)
> **Follow-on:** RFC 0013 (Four-stage enforcement loop)

## 1. Summary

Specifies how Yutha's constitution evaluator actually runs at request time. Pins three things:

1. **The layered evaluation contract.** Stock `cedar-policy` gates first; if it permits, the constitution engine runs scoring rules (RFC 0011 §2) and procedure logic (RFC 0011 §3) on top. The two layers compose into a single decision plus evidence plus a small set of causally-linked receipts.

2. **The determinism guarantees.** Same inputs MUST produce the same decision, the same evidence, and the same receipt content-addresses across implementations and across runs. The wall-clock is read once per evaluation; iteration order is declaration order; expression errors count as `false`; no floating-point arithmetic anywhere.

3. **The sandbox contract.** Per-evaluation bounds (max wall-clock time, entity-store size, scoring-rule count, procedure-instance count, Cedar policy count, evaluation depth) with explicit bound-exceeded deny reasons. v1.1 runs the evaluator in-process with bounded resources; process/WASM isolation is documented as a future-RFC option if the threat model justifies.

The detailed specification lives in [`/spec/constitution/evaluation.md`](../constitution/evaluation.md). This RFC summarizes the load-bearing decisions and pins the new `deny_reason` entries that get added to the receipt canonical-actions vocabulary.

## 2. Motivation

RFC 0010 (base schema) and RFC 0011 (capabilities) together specified *what* a constitution can express. Neither specified *how* an evaluation runs — what call order, with what bounds, with what determinism guarantees, with what receipt-emission semantics.

Without this RFC, two questions are unanswered:

- **Determinism.** Multiple Yutha implementations (or even multiple runs of the same implementation) could produce different scoring orders, different evidence digests, and therefore different receipt content-addresses for the same input. That breaks the cross-implementation interop story `/spec/README.md` §5 promises and makes receipt-fabric audit untrustworthy.

- **Sandbox / DoS posture.** A malicious or accidentally-pathological constitution could OOM the control plane via a million-entity entity-store or stall request handling via deep nested scoring rules. The constitution language design doc flags "sandbox escape is a critical vulnerability class" but doesn't say what the sandbox actually is.

Three concrete cases this RFC unblocks:

1. **Cross-implementation conformance.** Two implementations (e.g. the Rust reference and a future Go port) can be tested against the same constitution + input set and verified to produce byte-identical receipts.
2. **Performance budgeting.** Operators can predict worst-case evaluation latency from the sandbox bounds; the SDK can set request timeouts accordingly.
3. **Threat-model defense.** The bounds catalog is the surface against A1 (hostile agent) DoS attempts via crafted requests, and A4 (deceptive norm authorship) DoS attempts via crafted constitutions.

## 3. Detailed design

The full spec lives in [`/spec/constitution/evaluation.md`](../constitution/evaluation.md). This RFC walks the load-bearing decisions inline.

### 3.1 The two-layer contract (evaluation.md §1)

Every constitution evaluation runs synchronously through:

- **Layer A:** stock `cedar-policy::Authorizer::is_authorized` for gating. Yutha pins our *usage* of cedar-policy (request construction, entity store, decision/error mapping) but delegates everything substantive to upstream.
- **Layer B:** the constitution engine. Only runs if Layer A returned Allow. Iterates scoring rules from the engine config, matches procedure triggers, fires procedure transitions, schedules timeouts.

The composite decision plus evidence plus 0..N procedure-lifecycle receipts come out of the call. The receipt emission order is fixed (eval receipt first, then `procedure.enter`, `procedure.transition`, `procedure.escalate`) and the receipts' `causal_predecessors` thread back to the eval receipt.

### 3.2 Determinism guarantees (evaluation.md §4)

The hard guarantee: identical `(constitution_hash, schema_version, request, entity_snapshot, current_wall_clock, current_time_unix_ns)` → identical decision + evidence + receipt content-addresses. To achieve this the spec pins:

- **Wall-clock read once per evaluation.** Re-reading the clock for each scoring rule or each procedure transition would produce different scores or different transition orderings for evaluations that happen to span a clock tick.
- **Scoring iteration in declaration order.** The engine config's `scoring_rules` array order is the canonical order. Different orderings produce different `score_contributions` arrays and different evidence digests.
- **Expression evaluation errors → false.** A rule whose `when` errors does not contribute to scoring. The alternative (errors → exception → abort evaluation) creates a non-determinism surface where the order of errored rules matters.
- **No floating-point arithmetic.** Scoring uses Cedar's `Decimal` (fixed-precision rational). Floating-point summation is associative-but-not-commutative in IEEE 754 and would surface as cross-implementation receipt drift.
- **Structural rejection of transition ambiguity** at constitution-load time (RFC 0011 §3.5). If somehow ambiguity arrives at runtime (corrupted index, RFC 0011 violation), the canonical behavior is default-deny the request with `procedure_transition_ambiguous`.

A determinism conformance test (cross-implementation, byte-equivalent receipts) is part of the language conformance sub-suite.

### 3.3 Sandbox bounds (evaluation.md §5)

Per-evaluation bounds (plus one load-time bound):

| Bound | Default | Configurable |
|-------|---------|--------------|
| Max evaluation wall-clock time — `SendEnvelope` (hot path) | 10 ms | Yes, via topology |
| Max evaluation wall-clock time — all other actions | 100 ms | Yes, via topology |
| Max entity-store entity count | 1,000 | Yes |
| Max scoring rules per constitution | 1,000 | Yes |
| Max procedure declarations per constitution | 100 | Yes |
| Max open procedure instances examined per request | 100 | Yes |
| Max Cedar policy count | 1,000 | Yes |
| Max Cedar policy depth at constitution load (Yutha-side) | 16 | Yes |
| Cedar's internal evaluation depth limit | 64 | No (Cedar internal) |

The `SendEnvelope` hot-path bound is tighter because envelope sends are the highest-frequency gated action — every agent-to-agent message gates here. 10 ms is generous against real constitutions (Cedar evaluates simple policies in microseconds) while keeping send-path latency under operator control. Other actions get the looser 100 ms.

The max-policy-depth bound applies at constitution **load time** (`constitution.activate`); the loader runs Cedar's `Validator` over the policy set and refuses constitutions whose analyzer-reported max depth exceeds the bound. Most real policies are depth 3-5; 16 catches "this policy is doing something unusual" without rejecting reasonable work. Cedar's internal 64-limit stays as the language ceiling we can't reach into.

When a bound is exceeded at evaluation time, the evaluator emits `constitution.evaluate.deny` with the specific reason and stops. Reasons added in this RFC:

- `evaluation_time_exceeded`
- `entity_store_size_exceeded`
- `scoring_rule_count_exceeded`
- `procedure_count_exceeded`
- `open_procedure_instance_count_exceeded`
- `policy_count_exceeded`
- `policy_depth_exceeded`

These join the existing reasons (`forbid_rule_matched`, `no_permit_rule`, `evaluation_depth_exceeded`, `schema_version_unsupported`, `evaluator_internal_error`) defined in RFC 0010.

Load-time bound violations (`scoring_rule_count_exceeded`, `procedure_count_exceeded`, `policy_count_exceeded`, `policy_depth_exceeded`) refuse `constitution.activate` rather than landing as evaluate-deny receipts. The operator must amend the constitution or raise the bound.

### 3.4 Isolation posture (evaluation.md §5.3-5.4)

v1.1 runs the evaluator in-process with the rest of the control plane. Cedar-policy is pure Rust with no I/O; the engine code is also pure Rust. Per-evaluation isolation comes from:

- Read-only entity snapshots constructed by the control plane *before* the evaluation call. The evaluator never reaches back to the registry, capability store, or memory layer mid-evaluation.
- Independent `Authorizer`, `Request`, `Entities` per evaluation; no shared mutable state across concurrent evaluations.
- Bounded resource consumption per §3.3.

**Future evolution.** Process or WASM isolation (Wasmtime with strict resource caps) MAY be introduced in a follow-on RFC if the threat model demands. v1.1 ships in-process because (a) cedar-policy's design already prevents the side-channel classes WASM would protect against (no clock-skew leaks, no syscall surface) and (b) in-process is the simpler conformance target; cross-implementation byte-equivalent receipts are easier to verify when both implementations use the same upstream library.

### 3.5 Procedure-state reconstruction (evaluation.md §6)

The engine's procedure-state index is a **materialized view** over the receipt log — advisory, not authoritative. The receipt log is the source of truth.

Cold-start rebuild: read all `procedure.{enter,transition,timeout,escalate}` receipts in chronological order, replay state transitions, populate the index. O(N) in receipt count; runs only on cold start or after a disagreement triggers rebuild.

At evaluation time, before staging any procedure effect, the engine MUST verify the index entry for the relevant `instance_id` matches the most recent receipt for that instance. If they disagree, the index is stale — rebuild before deciding the transition.

This makes the engine effectively stateless: a restart means "clear index, replay receipts, resume" with no risk of state divergence. It also means a corrupted index never corrupts a decision — at worst it costs a rebuild.

### 3.6 Timeout firing (evaluation.md §7)

The engine maintains a wall-clock-keyed scheduler. When a procedure instance enters a state with an outgoing timeout transition, schedule `fire_at = entry_wall_clock + timeout_duration`. When the scheduler fires:

1. Re-read the index. If the instance is no longer in the timeout's source state, drop silently (an explicit transition won the race).
2. Otherwise, emit `procedure.timeout` and transition the instance to the timeout's target state. If the target state has an `on_timeout_escalate` mapping, also emit `procedure.escalate` and open a fresh instance of the escalation target.

**Jitter bound.** Timeouts fire within `[fire_at, fire_at + scheduler_jitter]`. Default `scheduler_jitter` is 1 second. Timeout values shorter than `2 * scheduler_jitter` are rejected at constitution load time — meaningless under the scheduler's worst-case observation interval.

Per RFC 0008, scheduling uses `Timestamp.wall_clock` (RFC 3339). `current_time_unix_ns` is admitted only for in-eval arithmetic, never for scheduling.

## 4. New `deny_reason` entries

Added to the `constitution.evaluate.deny` receipt's `deny_reason` enum (in `/spec/receipt/canonical-actions.md`):

| Reason | Producer | When |
|--------|----------|------|
| `evaluation_time_exceeded` | Sandbox bound | The 100 ms (or configured) wall-clock safety-net fired. |
| `entity_store_size_exceeded` | Sandbox bound | Entity snapshot exceeded the configured max entity count. |
| `scoring_rule_count_exceeded` | Sandbox bound | Constitution declares more scoring rules than the bound permits. Normally caught at load time; runtime check is belt-and-braces. |
| `procedure_count_exceeded` | Sandbox bound | Constitution declares more procedures than the bound permits. Same belt-and-braces story. |
| `open_procedure_instance_count_exceeded` | Sandbox bound | The set of currently-open procedure instances exceeds the per-request examination cap. |
| `policy_count_exceeded` | Sandbox bound (load-time, runtime fallback) | Cedar source declares more policy rules than the bound permits. |
| `policy_depth_exceeded` | Sandbox bound (load-time, Yutha-side) | Cedar's `Validator` reports a max policy depth exceeding the Yutha-side cap. Refused at `constitution.activate`; runtime occurrence means an activation slipped past the loader. |
| `procedure_transition_ambiguous` | Determinism | Two transitions match the request `(from_state, action_kind)` simultaneously. Should be unreachable per RFC 0011 §3.5 load-time validation; canonical-action allows the runtime fail-closed. |
| `request_shape_invalid` | Layer A error | Cedar reports the request shape doesn't match the schema (e.g. missing context field). |
| `entity_unresolved` | Layer A error | Request references an entity not in the snapshot. |
| `constitution_unresolved` | Layer A error | `constitution_hash` doesn't resolve to a loaded constitution. |

`evaluator_internal_error` (existing) is now narrowed: implementations SHOULD prefer one of the more-specific reasons above when applicable. `evaluator_internal_error` is the catch-all for genuinely unanticipated failures.

## 5. Conformance hooks

Summarized; full list in evaluation.md §10:

- **Layer A delegation.** Implementations MUST use stock cedar-policy for gating.
- **Determinism harness.** Cross-implementation suite asserts byte-equivalent receipts for the same inputs.
- **Bound enforcement.** Each sandbox bound has a test case that crafts a constitution-or-request hitting the bound and verifies the correct `deny_reason`.
- **Procedure reconstruction.** Test: corrupt the index; replay from receipts; verify identical state.
- **Timeout jitter.** Test: schedule a 5-second timeout; verify firing within `[5s, 6s]`.

Test cases land under `/conformance/interface/language/evaluation/` during F-code stages.

## 6. Threat-model linkage

The sandbox contract is the primary defense against:

- **A1 (hostile agent) DoS.** A compromised agent crafting requests with oversize entity stores or pathological scoring contexts. Bounds catch these immediately with a deny + receipt.
- **A4 (deceptive norm authorship) DoS.** A constitution that passes the analyzer but explodes at eval time (e.g. a thousand scoring rules each with a deep entity-traversal predicate). Bounds catch these regardless of how they got past the analyzer.
- **A1/A4 side-channel.** In-process v1.1 already prevents most side-channels (cedar-policy is pure Rust). The future-RFC escalation path is documented but not yet triggered.

## 7. Backwards compatibility

This RFC adds a new spec document and extends the `deny_reason` vocabulary. No existing wire format changes. v1.0 implementations that don't yet honor the new bounds continue to evaluate v1.0 constitutions correctly (the bounds default to "unbounded" if not configured — which is the v1.0 behavior). v1.1-aware implementations honor the bounds.

The new `deny_reason` strings are additive to the enum; receipt consumers that don't recognize them treat them as `UNKNOWN` per the default-unknown rule.

## 8. Migration path

Implementations adopting v1.1 evaluation semantics:

1. Upgrade the constitution engine to a version that delegates Layer A to stock cedar-policy.
2. Implement the §3.3 bound enforcement at the evaluation entry point.
3. Implement the §3.5 receipt-driven procedure-state reconstruction.
4. Implement the §3.6 wall-clock scheduler with the §3.6 jitter bound.
5. Pass the determinism conformance harness.

Implementations that don't upgrade continue to work for v1.0 constitutions — the bounds and determinism guarantees are spec floor for v1.1, not retroactive requirements on v1.0.

## 9. Open questions for review

- **Concrete bound values for non-hot-path actions.** §3.3's tightened defaults (10 ms hot-path / 100 ms general; 1,000 entities; 1,000 policies; max-depth 16) are educated estimates. Design partners pushing on real workloads may still want adjustments. Worth a public-review pass with usage data.
- **Persistent vs in-memory scheduler.** evaluation.md §7.1 admits both; should production deployments be required to use persistent? Likely yes via a follow-on once crash-recovery requirements are quantified.
- **Sandbox escalation criteria.** What threshold of threat-model evidence triggers the move to WASM/process isolation? evaluation.md §5.3 leaves this open.
- **Cross-implementation suite mechanics.** The determinism harness needs a corpus of `(constitution, request)` pairs with expected receipts. Where does the corpus live? Lean: `/spec/vectors/constitution-eval/`, mirroring the existing vectors directories.

## 10. References

- Evaluation spec: [`/spec/constitution/evaluation.md`](../constitution/evaluation.md)
- Predecessor: [RFC 0010](./0010-constitution-language-v1.md), [RFC 0011](./0011-cedar-plus-extensions.md)
- Wall-clock semantics: [RFC 0008](./0008-wall-clock-bound-checks.md)
- Default-deny posture: PRD §13.2
- Cedar reference: <https://docs.cedarpolicy.com/>
- Threat model: `/docs/security/threat-model.md`

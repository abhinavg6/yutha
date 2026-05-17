# Constitution Evaluation Model + Sandbox Contract (v1.1)

> **Spec:** [`schema.cedarschema`](./schema.cedarschema), [`extensions.md`](./extensions.md)
> **RFC:** [0012](../rfcs/0012-evaluation-model-and-sandbox.md)
> **Predecessor:** [RFC 0010](../rfcs/0010-constitution-language-v1.md) (base schema), [RFC 0011](../rfcs/0011-cedar-plus-extensions.md) (engine constructs + schema patterns)
> **Phase:** 2

## 0. Scope

This document specifies how a Yutha constitution actually *evaluates* a request at runtime. It pins the layered evaluation contract (stock Cedar for gating + the engine for scoring/procedures), the sandbox bounds within which evaluation runs, the determinism guarantees implementations must preserve, and the procedure-state reconstruction protocol that lets the engine survive crashes / index resets / cold starts without losing audit fidelity.

What this document does NOT specify: the *implementation* of the constitution engine (that's the forthcoming `yutha-cedar-plus` crate). What it specifies is the contract every conformant implementation honors — same inputs produce same decisions, same evidence, same receipt content-addresses.

The companion RFC ([0012](../rfcs/0012-evaluation-model-and-sandbox.md)) is the document of record for these decisions.

---

## 1. The layered evaluation contract

A single constitution evaluation is a two-layer call:

```
                       ┌─────────────────────────────────────────────┐
                       │   Yutha constitution evaluator              │
                       │                                             │
   request →           │   Layer A: cedar-policy::Authorizer          │
   { principal,        │     ─ stock Cedar gating (permit/forbid)    │
     action,           │     ─ deterministic, bounded                │
     resource,         │                                             │
     context,          │   ──────── gate decision (permit?) ────────  │
     entities }        │                                             │
                       │   Layer B: constitution engine               │
                       │     ─ scoring-rule iteration (if permit)     │
                       │     ─ procedure trigger matching            │
                       │     ─ procedure transition firing           │
                       │     ─ timeout scheduling                    │
                       │                                             │
                       │   → composite decision + evidence + receipt │
                       └─────────────────────────────────────────────┘
```

Both layers run synchronously inside a single evaluation call. Layer A's decision gates whether Layer B runs at all: if Cedar denies (explicit forbid, no matching permit, or evaluation error), Layer B is skipped and a `constitution.evaluate.deny` receipt lands immediately. If Cedar permits, Layer B layers on the engine-side work and emits `constitution.evaluate.pass` plus any procedure-lifecycle receipts the request triggered.

### 1.1 Request shape

The evaluator receives a request carrying:

| Field | Type | Source |
|-------|------|--------|
| `constitution_hash` | Hash | Pinned by the swarm's currently-active constitution. |
| `schema_version` | semver string | Pinned by the constitution. Determines which schema to load. |
| `action_kind` | String | The Cedar action being attempted (e.g. `SendEnvelope`). |
| `principal_id` | EntityUid (`Yutha::Agent::"<agent-id>"`) | From the bearer auth context. |
| `resource_id` | EntityUid | Synthesized per action by the calling handler (e.g. `EnvelopeHandler::send` constructs the target Agent or Envelope entity reference). |
| `context_attrs` | Record | Per-action context fields per `schema.cedarschema` (e.g. `performative`, `payload_schema_id`, `tags`, `estimated_cost_*`). Always includes `current_wall_clock` and `current_time_unix_ns`. |
| `entity_snapshot` | EntityStore | A read-only snapshot of the entities the evaluation may reference: the principal Agent, the Swarm, any Capability entities the principal holds, any Memory entities involved, etc. |

The `entity_snapshot` is synthesized by the control plane *before* the call — the evaluator never reaches back to the registry, capability store, or memory layer during evaluation. This is what makes evaluation pure (no I/O, no race conditions) and deterministic.

### 1.2 Response shape

```
EvaluationOutcome {
    decision: Permit | Deny,
    deny_reason: Option<DenyReason>,         // Some when decision == Deny
    matched_rule_ids: Vec<RuleId>,            // Cedar rules that contributed
    score_contributions: Vec<(RuleId, Decimal)>,    // empty when no scoring fired
    total_score: Option<Decimal>,             // Some iff score_contributions non-empty
    procedure_effects: Vec<ProcedureEffect>,  // empty when no procedure triggered/transitioned
    evidence_digest: Hash,                    // hash over the matched rules + input attrs
}
```

`ProcedureEffect` carries the `(action_kind, instance_id)` of every `procedure.enter` / `procedure.transition` / `procedure.escalate` receipt emitted in the same handler. The caller uses this to thread `causal_predecessors` correctly on subsequent receipts.

### 1.3 Call order

Per request, in order:

1. **Schema load.** Resolve `schema_version` to the canonical schema file (or canonical + signed delta). Failure → `Deny` with `schema_version_unsupported`.
2. **Constitution load.** Resolve `constitution_hash` to the Cedar policy file + engine config. Failure → `Deny` with `constitution_unresolved`.
3. **Sandbox bounds check.** Verify the request fits within the sandbox limits (§5). Failure → `Deny` with the specific bound-exceeded reason.
4. **Layer A.** Construct a `cedar_policy::Request` and `cedar_policy::Entities` from the request. Call `Authorizer::is_authorized`. Cedar returns Allow/Deny + diagnostics.
5. **Layer B (only if Cedar returned Allow).**
   - **Scoring.** Iterate `scoring_rules` in declaration order; for each whose head matches and `when` evaluates true, add `score` to the running total.
   - **Procedure trigger matching.** For each declared procedure, if `trigger.action == request.action_kind` AND `trigger.when` evaluates true AND no open instance already exists for this triggering action descriptor, open a new instance and stage a `procedure.enter` effect.
   - **Procedure transition matching.** For each open procedure instance whose `procedure_name` is one whose transitions reference the current `request.action_kind`, find the transition whose `from` matches the instance's current state and whose `actor_when` evaluates true. If found, stage a `procedure.transition` effect.
   - **Timeout scheduling.** For each newly-entered instance and each transition into a state with an outgoing timeout, schedule the timeout firing per §7.
6. **Receipt emission.** Emit `constitution.evaluate.{pass,deny}` first, then any `procedure.{enter,transition,escalate}` effects (with `causal_predecessors` referencing the eval receipt's content-address). Receipts emit in a single causal batch; the receipt store is the authoritative ordering source.
7. **Return composite outcome to the caller.**

---

## 2. Layer A — Cedar evaluation semantics

Yutha delegates gating to stock `cedar-policy`. This section pins our *usage* of the library — not the library's behavior, which is specified at <https://docs.cedarpolicy.com/>.

### 2.1 Construction

For each evaluation:

```rust
let request = cedar_policy::Request::new(
    Some(principal_euid),
    Some(action_euid),
    Some(resource_euid),
    cedar_policy::Context::from_pairs(context_attrs, Some(&schema))?,
    Some(&schema),
)?;
let response = Authorizer::new().is_authorized(&request, &policy_set, &entity_store);
```

The schema MUST be loaded at the constitution's pinned `schema_version`. The policy set is the parsed Cedar source file (no engine-config artifacts mixed in). The entity store is the read-only snapshot from §1.1.

### 2.2 Decision mapping

Stock Cedar's `Response::decision()` returns `Decision::Allow` or `Decision::Deny`. The Yutha layer maps:

- `Allow` → proceed to Layer B.
- `Deny` → emit `constitution.evaluate.deny` with `deny_reason` derived from the diagnostics:
  - The diagnostics carry the matched forbid rule id (if any) → `forbid_rule_matched` with `forbid_rule_id` in evidence.
  - No matching permit and no forbid → `no_permit_rule`.
  - Cedar reports evaluation errors (e.g. attribute missing from entity) → `evaluator_internal_error` with the Cedar error string in evidence.

### 2.3 Error treatment

Any error from cedar-policy that isn't a clean decision counts as Deny. Specifically:

- Type errors (request shape doesn't match schema) → Deny, `request_shape_invalid`.
- Entity lookup failures (request references an entity not in the snapshot) → Deny, `entity_unresolved`.
- Expression evaluation errors during policy eval → Deny, `evaluator_internal_error`.

The default-deny posture from PRD §13.2 is preserved at every error class. Implementations MAY add finer-grained reasons via RFC; the existing reasons are the spec floor.

### 2.4 What we explicitly do NOT pin

- Cedar's internal evaluation algorithm. As long as `Authorizer::is_authorized` returns the same decision for the same inputs (which it MUST per Cedar's published semantics), implementations are free to use whatever Cedar version is current.
- The Cedar policy file's textual format. Cedar 3.x supports both standard policy syntax and JSON; conformant constitutions ship the standard syntax form, but the policy file MAY be re-rendered in either.

---

## 3. Layer B — Engine evaluation semantics

The constitution engine runs the scoring and procedure logic on top of the Cedar permit. This section is where v1.1's new behavior actually lives.

### 3.1 Scoring rule evaluation

Pseudocode (the canonical Rust implementation in `yutha-cedar-plus` MUST behave identically):

```
total = Decimal::ZERO
contributions = []
for rule in constitution.scoring_rules.iter():
    if !head_matches(rule.head, request): continue
    when_value = cedar_evaluate_expression(rule.when, request_context)
    if when_value is Err or when_value is Bool(false): continue
    total += rule.score
    contributions.push((rule.id, rule.score))
emit total + contributions in evidence
```

Key invariants:

- **Iteration order is declaration order** in the engine config. Different orderings would produce different `score_contributions` arrays and different receipt content-addresses — a determinism bug.
- **Expression evaluation errors count as `false`.** A rule whose `when` errors does not contribute. The error is logged but not surfaced in the receipt (the receipt records what passed, not what errored — adding errored rules to evidence would surface implementation noise).
- **`head_matches`** is a simple structural check: if the head's `action` field is present, it must equal `request.action_kind`; same for `principal` (matches EntityUid) and `resource` (matches EntityUid). Absent fields are wildcards.
- **`current_wall_clock` is captured once per evaluation** at the very beginning and used by every rule's `when` evaluation. Re-reading the clock per rule would make the score depend on inter-rule timing — a non-determinism source.

### 3.2 Procedure trigger matching

For each procedure declaration whose `trigger.action == request.action_kind`:

1. Evaluate `trigger.when` against the request context.
2. If true, compute the would-be `instance_id`:
   ```
   instance_id = sha256(procedure_name || triggering_action_descriptor_digest || swarm_id || current_wall_clock)
   ```
3. If an open instance with this `instance_id` already exists (consultable via the procedure-state index), skip — entry is idempotent. This handles the retry case (same request reprocessed; we don't want two enters).
4. Otherwise, stage a `procedure.enter` effect for this instance with `initial_state = procedure.initial_state`.

A single request CAN trigger entries into multiple procedures simultaneously. The engine iterates procedures in declaration order; multiple matching triggers all fire.

### 3.3 Procedure transition matching

For each open procedure instance (consultable via the index):

1. Check whether the procedure's transition list contains any transition with `from == instance.current_state` and `action == request.action_kind`.
2. For each such candidate transition, evaluate `actor_when` against the request (the actor is the request's principal).
3. If `actor_when` is true, the transition fires:
   - Stage a `procedure.transition` effect with `from_state`, `to_state`, `transition_actor`, `transition_action_descriptor_digest`.
   - Update the index to reflect the new state.
   - If the new state is in `terminal_states`, mark the instance closed.
   - If the new state has an outgoing timeout transition, schedule it per §7.

### 3.4 Transition ambiguity

Per extensions.md §3.5 the loader rejects procedures with ambiguous transitions (two transitions sharing `(from, action)`). Therefore at runtime at most one transition per instance fires per request. The check is belt-and-braces; if an implementation somehow encounters ambiguity at runtime (e.g., a corrupted index), the canonical behavior is **default-deny the whole request** with `procedure_transition_ambiguous` — the receipt records the conflicting transition ids.

### 3.5 Cross-instance independence

A transition predicate (`actor_when`) cannot see other procedure instances' state. The Cedar expression has access only to the request entity store; instance state is not modeled as a Cedar entity. This is a deliberate decoupling — extensions.md §3.6 — and is the structural reason scoring outputs cannot leak into transition predicates either.

---

## 4. Determinism guarantees

The evaluator MUST be deterministic in the strict sense: given identical `(constitution_hash, schema_version, request, entity_snapshot, current_wall_clock, current_time_unix_ns)`, two invocations on two different implementations or two different runs of the same implementation MUST produce:

- Identical `decision`, `deny_reason`, and `matched_rule_ids`.
- Identical `score_contributions` (same ordering, same scores) and `total_score`.
- Identical sequence of `procedure_effects`.
- Identical content-address on the resulting `constitution.evaluate.{pass,deny}` receipt and any procedure-lifecycle receipts.

What this rules out:

- Reading the wall-clock more than once per evaluation.
- Random tie-breaking when multiple matching rules or transitions exist (the spec specifies deterministic ordering via declaration order in §3.1 and a structural prohibition on ambiguity in §3.4).
- Implementation-defined hashmap iteration order leaking into receipt evidence.
- Floating-point arithmetic. Scoring uses Cedar's `Decimal` type (fixed-precision rational); summation is deterministic.

What the evaluator MAY do non-deterministically (because it doesn't affect the receipt content):

- Cache evaluation results across requests (an LRU on `(constitution_hash, request_hash)` is fine).
- Run scoring rules concurrently (commutative under summation; final total is the same as serial summation).
- Materialize entity attributes lazily.

Conformance test §10's determinism harness reruns the same evaluation across multiple implementations and asserts byte-equivalent receipts.

---

## 5. Sandbox contract

Cedar's evaluator is pure Rust with no I/O — it cannot, by construction, reach back into the host process or out to the network. The Yutha sandbox concern is *resource exhaustion*: a malicious constitution (slipped past the analyzer) or a degenerate request (oversize entity store) must not be able to OOM the control plane or block other requests.

### 5.1 Bounds enforced per evaluation (and per constitution load)

| Bound | Default | Configurable per-swarm |
|-------|---------|------------------------|
| Max evaluation wall-clock time — `SendEnvelope` (hot path) | 10 ms | Yes, via topology |
| Max evaluation wall-clock time — all other actions | 100 ms | Yes, via topology |
| Max entity-store entity count | 1,000 | Yes |
| Max scoring rules per constitution | 1,000 | Yes |
| Max procedure declarations per constitution | 100 | Yes |
| Max open procedure instances examined per request | 100 | Yes |
| Max Cedar policy count | 1,000 | Yes |
| Max Cedar policy depth at constitution load (Yutha-side) | 16 | Yes |
| Cedar's internal evaluation depth limit | 64 | No (Cedar's internal limit) |

The `SendEnvelope` hot-path bound is tighter because envelope sends are the highest-frequency gated action in a busy swarm — every agent-to-agent message gates here. The 10 ms ceiling is generous against real constitutions (Cedar evaluates simple policies in microseconds) while keeping send-path latency under the operator's control. Other actions (capability issuance, memory operations, procedure transitions) are lower-frequency and get the looser 100 ms safety net.

The wall-clock bounds are the runtime safety-net. Cedar's analyzer already proves bounded depth statically, so a well-formed constitution shouldn't approach the limit; the bounds exist to defend against pathological entity stores (e.g. an entity with thousands of attribute set members) that pass the analyzer but explode at eval time.

The max-policy-depth bound is enforced at constitution **load time**, not per evaluation: at `constitution.activate`, the loader runs Cedar's `Validator` over the policy set and refuses constitutions whose analyzer-reported max depth exceeds the bound. This is a Yutha-side cap on top of Cedar's internal 64-limit; most real policies are depth 3-5, so 16 catches "this policy is doing something unusual" without rejecting reasonable work. Operators MAY raise the bound via topology config.

### 5.2 Bound-exceeded handling

Each bound has a corresponding `deny_reason`:

- `evaluation_time_exceeded` (the wall-clock safety-net fired; the action-specific cap from §5.1 applies)
- `entity_store_size_exceeded`
- `scoring_rule_count_exceeded` (load-time check, runtime resort if bypassed)
- `procedure_count_exceeded` (load-time check, runtime resort if bypassed)
- `open_procedure_instance_count_exceeded`
- `policy_count_exceeded` (load-time check, runtime resort if bypassed)
- `policy_depth_exceeded` (Yutha-side load-time check; if it surfaces at evaluation time, the constitution was activated under a stale loader)
- `evaluation_depth_exceeded` (Cedar's internal limit; should be unreachable for well-formed constitutions)

When a bound is hit at evaluation time, the evaluator immediately produces `constitution.evaluate.deny` with the appropriate reason. No partial results are surfaced; no scoring or procedure work happens. The caller's request fails-closed.

When a bound is hit at constitution-load time (the load-time checks above), the activation is refused — `constitution.activate` does NOT land. The operator must amend the constitution to bring it within bounds (or raise the bound via topology config).

### 5.3 Isolation posture

v1.1 evaluator runs **in-process** with the rest of the control plane. The cedar-policy crate is pure Rust; the engine code is also pure Rust. Isolation is per-evaluation: each request constructs its own `Authorizer`, `Request`, `Entities`, and timeout-bound async task. Concurrent evaluations don't share mutable state.

**Future evolution.** If the threat model justifies (specifically: an adversary class that can author constitutions the analyzer accepts but whose evaluation footprint can side-channel against other requests), v1.2+ MAY introduce process isolation (a separate evaluator process per swarm) or WASM isolation (compile the evaluator to WASM and run in Wasmtime with strict resource caps). Both are RFC-gated; v1.1 ships in-process with bounded resources.

### 5.4 What "sandbox escape" means in v1.1

Stock cedar-policy cannot perform I/O, allocate unbounded memory, or escape its Rust process. A "sandbox escape" in v1.1 means: an evaluation reads memory or invokes code outside the evaluator's intended scope. The defenses:

- The evaluator is given a read-only entity snapshot at request time. It cannot write back. The registry and capability store APIs are not in the evaluator's call graph at all.
- The cedar-policy crate is the only library that evaluates Cedar expressions. We do not embed alternative evaluators.
- The evaluator does not spawn threads, perform syscalls, or invoke external commands.

A bug in cedar-policy that violates these properties would be a CVE-class issue in upstream Cedar; we treat it as a security-incident class. The Yutha threat model assumes cedar-policy's published guarantees hold.

---

## 6. Procedure-state reconstruction

The engine maintains a procedure-state index — a materialized view over the receipt log keyed on `instance_id`, recording each instance's `current_state`, `entry_wall_clock`, `entry_descriptor_digest`, and any scheduled timeouts. The index is **advisory**: the receipt log is the authoritative source of truth.

### 6.1 Build from receipts

On constitution-engine startup (or whenever the index needs rebuilding):

```
for receipt in receipts.query(action_kind in {procedure.enter, procedure.transition, procedure.timeout, procedure.escalate}).order_by(occurred_at_unix_ns):
    case procedure.enter:
        index[instance_id] = OpenInstance { state: initial_state, ... }
        schedule_timeout_if_applicable(...)
    case procedure.transition:
        index[instance_id].state = to_state
        if to_state in terminal_states: index[instance_id].closed = true
        schedule_timeout_if_applicable(...)
    case procedure.timeout:
        index[instance_id].state = state_at_timeout's target_via_timeout_transition
        ... possibly escalate
    case procedure.escalate:
        index[to_instance_id] = OpenInstance { state: initial_state of to_procedure, ... }
        index[from_instance_id].closed = true
```

This is a linear pass over receipts; it's O(N) in receipt count but only run on cold start or after a disagreement triggers a rebuild.

### 6.2 Index validation

At evaluation time, before staging any procedure effect, the engine MUST verify the index entry for the relevant `instance_id` matches the most recent receipt for that instance. If they disagree, the index is stale — the engine MUST rebuild from receipts before deciding the transition. This is a slow path but bounds the worst case.

### 6.3 No mutable engine state survives a restart

There is no on-disk engine state beyond the index, and the index is reconstructable. Restarting the constitution engine means: clear the index, replay receipts, resume. This makes the engine effectively stateless — a property the receipt fabric inherits to.

---

## 7. Timeout firing

### 7.1 Scheduler

The engine maintains a wall-clock scheduler. When a procedure instance enters a state with an outgoing timeout transition, the engine computes `fire_at = entry_wall_clock + timeout_duration` and schedules a callback.

Implementations have two options:

- **In-memory scheduler.** A min-heap of `(fire_at, instance_id, state)` tuples; a polling task scans for `fire_at <= now`. On restart, the scheduler rebuilds from the receipt-derived index.
- **Persistent scheduler.** Same but with a backing store (e.g. a Postgres `scheduled_timeouts` table). Survives restart without rebuild.

v1.1 spec does NOT mandate one or the other; the conformance test verifies that timeouts fire within the spec'd jitter window (§7.3) regardless of scheduler design.

### 7.2 Firing semantics

When `fire_at <= now`:

1. The engine re-reads the index for the instance. If the instance is no longer in the timeout's source state (i.e. an explicit transition already fired), the timeout is dropped silently — no receipt, no effect. This is the "transition won the race" case.
2. Otherwise, fire the timeout: emit `procedure.timeout` with the spec'd evidence; transition the instance to the timeout's target state; if the target state has an `on_timeout_escalate` mapping, also emit `procedure.escalate` and open a fresh instance of the escalation target.
3. If the new state has an outgoing timeout, schedule it.

### 7.3 Jitter bound

Timeouts fire at-most-once within `[fire_at, fire_at + scheduler_jitter]`. The default `scheduler_jitter` is 1 second; configurable per-swarm. The bound is necessary because no scheduler fires perfectly on schedule; it's the spec floor implementations must meet.

Timeout values shorter than `2 * scheduler_jitter` (i.e. 2 seconds by default) are rejected at constitution-load time per extensions.md §3.5 — a timeout shorter than the scheduler's worst-case observation interval is meaningless.

### 7.4 Wall-clock semantics

Per RFC 0008, scheduling and firing both use `Timestamp.wall_clock` (RFC 3339). `current_time_unix_ns` is admitted only for in-eval arithmetic, never for scheduling. This bounds the cross-process clock skew exposure: timeouts are minutes-to-hours on the spec'd workloads, while wall-clock skew across reasonable NTP-synced hosts is sub-second.

---

## 8. Receipt-emission order and causality

A single evaluation can produce multiple receipts: the eval receipt itself plus 0..N procedure-lifecycle receipts. The emission order MUST be:

1. `constitution.evaluate.{pass,deny}` first.
2. Any `procedure.enter` next, in declaration order of the procedures that triggered.
3. Any `procedure.transition` next, in declaration order of the procedures that transitioned.
4. Any `procedure.escalate` last.

Subsequent receipts' `causal_predecessors` MUST include the eval receipt's content-address. The first procedure-lifecycle receipt of each kind references the eval; subsequent receipts of the same evaluation can reference each other or the eval.

This ordering ensures the receipt fabric's causal DAG accurately reflects the evaluation's dependency structure: a procedure entry depends on the gating eval; an escalation depends on the timeout that triggered it; etc.

---

## 9. Evidence digests

The `evidence_digest` field in the evaluation outcome is `sha256` over the canonical serialization of:

```
(matched_rule_ids, score_contributions, procedure_effects, input_attribute_digest)
```

Canonical serialization rules:

- `matched_rule_ids` sorted lexicographically.
- `score_contributions` in declaration order (per §3.1).
- `procedure_effects` in the §8 emission order.
- `input_attribute_digest` is `sha256` over the entity snapshot's canonical bytes plus the context attrs, canonicalized via the same rules used elsewhere in the spec (per `/spec/README.md` §5).

The evidence_digest goes into the eval receipt's `evidence` field. Two implementations that disagree on `evidence_digest` for the same inputs are non-conformant.

---

## 10. Conformance hooks

A conformant constitution implementation:

- **Layer A delegation.** Use stock cedar-policy `Authorizer::is_authorized` for gating. Reject any implementation that re-implements Cedar evaluation in Yutha code.
- **Layer B determinism.** Score iteration in declaration order; clock read once per eval; expression errors → false; identical evidence digests across runs.
- **Sandbox bounds.** Enforce per-evaluation bounds per §5; emit the correct `deny_reason` per bound type.
- **Procedure reconstruction.** Index MUST be reconstructable from receipts; index MUST be checked against most-recent receipt at transition firing time; receipt-vs-index disagreement triggers rebuild.
- **Timeout firing.** Fire within `[fire_at, fire_at + scheduler_jitter]`; reject load-time timeouts shorter than `2 * scheduler_jitter`.
- **Receipt emission.** Order per §8; causal_predecessors per §8.
- **Determinism harness.** Pass a cross-implementation determinism suite that asserts byte-equivalent receipts for the same inputs.

Conformance test cases live under `/conformance/interface/language/evaluation/` (added during F-code stages).

---

## 11. Open questions

- **Concrete bound values for non-hot-path actions.** §5.1's 100 ms, 1,000 entities, 1,000 policies, and 16 max-depth are tightened-from-initial-draft values; design partners pushing on real workloads may still want some larger and some smaller. Worth a public-review pass with usage data. The `SendEnvelope` hot-path bound (10 ms) and the `policy_depth_exceeded` load-time cap (16) were chosen explicitly during this RFC's drafting.
- **Persistent vs in-memory scheduler.** §7.1 admits both; should we mandate persistent for production deployments? Likely yes via a follow-on RFC once we have crash-recovery requirements quantified.
- **Sandbox escalation path.** When (not if) the threat model demands process/WASM isolation, the design lands in a follow-on RFC. v1.1 documents in-process is sufficient; v1.2 may revisit.
- **Cross-swarm evaluation.** v1.1 evaluators are single-swarm. Federation (Phase 4) needs cross-swarm evaluation semantics; out of scope here.
- **Concurrent evaluations sharing entity snapshots.** Multiple concurrent requests against the same constitution may share a read-only entity snapshot for efficiency. v1.1 admits this as an implementation choice; conformance test verifies determinism regardless of sharing.

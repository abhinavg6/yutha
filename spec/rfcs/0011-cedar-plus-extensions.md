# RFC 0011: Cedar+ Extensions — Engine Constructs and Schema Patterns

> **Status:** Draft
> **Authors:** Workstream A (Specs) + Workstream E (Constitution engine)
> **Filed:** 2026-05-15
> **Targets spec:** `/spec/constitution/schema.cedarschema` (v1.0 → v1.1),
>                   `/spec/constitution/extensions.md` (new),
>                   `/spec/receipt/canonical-actions.md` (adds `procedure.*` action-kinds)
> **Targets phase:** Phase 2 (Coordination & Norms)
> **Discussion:** TBD
> **Predecessor:** [RFC 0010](./0010-constitution-language-v1.md) (base schema at v1.0)
> **Follow-on:** RFC 0012 (Evaluation model + sandbox), RFC 0013 (Four-stage enforcement)

## 1. Summary

Adds four constitution-layer capabilities at v1.1, **none of which extend Cedar's language**. The four split cleanly into two categories:

| # | Capability | Category | Surface |
|---|------------|----------|---------|
| 1 | `prefer` (soft-preference scoring) | **Engine construct** | Stock Cedar policy file + separate engine config carrying scoring rules. Engine consumes both; ranking happens after Cedar's gating decision. Scores never override forbid. |
| 2 | `procedure` (bounded state machines) | **Engine construct** | Stock Cedar policy file + separate engine config carrying procedure definitions. Engine runs the state machine, calls back into Cedar by name for transition predicates. State is reconstructable from the receipt log. |
| 3 | Resource budgets | **Schema-pattern** | Stock Cedar + new schema vocabulary. v1.1 adds `budget_remaining_*` attributes on `Agent` and `estimated_cost_*` context fields on relevant actions; canonical idiom uses stock Cedar `<` comparisons. |
| 4 | Memory norms | **Schema-pattern** | Stock Cedar + new entity/action types. v1.1 adds the `Memory` entity and `ReadMemory` / `WriteMemory` / `ShareMemory` actions; canonical idioms use stock Cedar `permit` / `forbid` over them. |

**No new Cedar+ keywords. No Cedar parser/compiler/analyzer extensions. Cedar's decidability proofs are untouched.** Earlier drafts of this RFC proposed `prefer` and `procedure` as syntactic extensions to Cedar; we reversed that decision in favor of the engine-construct path for three reasons:

1. **Maintenance.** Engine constructs let us use stock `cedar-policy` (the open-source Rust crate) unmodified. As Cedar evolves upstream, we get every improvement for free; we maintain no fork-equivalent code.
2. **Decidability surface.** Engine constructs have their own small, conventional validators (YAML/protobuf shape + Cedar expression parsing + textbook graph algorithms for state machines). Cedar's existing analyzer is the security boundary for everything *inside* Cedar; the engine-side validators are the security boundary for everything outside. Neither boundary expands.
3. **Future evolution.** Multi-step coordination constructs Yutha hasn't designed yet (voting, amendment ratification, federation handshakes) become engine-side schemas rather than language extensions. Cheap to add later.

The cost — authors write two artifacts (`.cedar` policy + `.engine.yaml` config) instead of one — is real but manageable, and offset by the architectural cleanliness of the split.

Bumps `schema.cedarschema` to v1.1.0 (additive, per RFC 0010 §3.5 minor-bump semantics). Adds four new action-kinds to `/spec/receipt/canonical-actions.md` for the procedure lifecycle.

## 2. Motivation

RFC 0010 established the Cedar+ surface at the minimum necessary to gate substrate operations. What it didn't yet provide:

- **Ranking signals.** Many real swarm policies aren't boolean. "Prefer routing high-value cases to senior agents" is a ranking, not a gate. We need a clean way to encode scores without weakening Cedar's decidability.
- **Multi-step workflows.** Refund-above-threshold approvals, supervisor escalations, constitution-amendment ratification — these are state machines, not single-shot decisions. Stock Cedar evaluates one quadruple per call; multi-step gating requires either external state (footgun) or a structured construct.
- **Budget gating.** Agents have bounded dollar/compute/tool-call budgets. The constitution layer needs to refuse over-budget actions without itself maintaining budget state.
- **Memory norms.** Memory operations are first-class actions per `/spec/receipt/canonical-actions.md`. The constitution layer needs to gate them with familiar permit/forbid rules and the requisite schema vocabulary.

The four capabilities in this RFC together address these gaps while keeping Cedar's analyzer guarantees intact.

## 3. Detailed design

The full spec lives in [`/spec/constitution/extensions.md`](../constitution/extensions.md). This RFC summarizes the load-bearing decisions and adds the receipt-layer touches.

### 3.1 The engine-construct vs schema-pattern split

Two questions decide where each capability lands:

1. **Does the capability need new runtime state or scheduling that Cedar deliberately doesn't model?** If yes → engine construct. (Cedar refuses to model time-as-a-resource, mutable state, or workflows — that's its design.)
2. **If no, does the capability fit cleanly as new schema vocabulary?** If yes → schema-pattern.

Applied to the four:

- **`prefer`.** No runtime state, but scoring rules have their own head/body structure conceptually distinct from gating rules. Engine construct — fits more naturally as a separate config artifact than as schema vocabulary.
- **`procedure`.** Has runtime state (state machine instances), scheduling (timeouts), and lifecycle. Engine construct.
- **Budgets.** No runtime state inside the constitution layer (the control plane already maintains agent budgets and injects current values into each request). Schema-pattern.
- **Memory norms.** No runtime state. Schema-pattern.

### 3.2 `prefer` as engine construct (extensions.md §2)

Scoring rules live in an engine-config artifact alongside the Cedar policy file:

```yaml
# constitution.engine.yaml
schema_version: "1.1.0"

predicates:
  - name: senior_for_sensitive
    expr: 'principal.reputation > 0.8 && resource.tags.contains("sensitive")'

scoring_rules:
  - name: senior_for_sensitive_score
    score: 2.0
    head: { action: AssignCase }
    when: '@senior_for_sensitive'
```

The Cedar policy file stays pure stock Cedar (`permit` / `forbid` rules only). The engine reads both files at constitution-load time, parses each scoring rule's `when` expression with `cedar_policy::Expr::from_str`, validates against the v1.1 schema, and binds the rule.

At evaluation time: stock Cedar gates first. If permit, the engine iterates scoring rules, evaluates each rule's `when` over the same request context Cedar saw, and sums scores. Total attaches to the decision and lands in `constitution.evaluate.pass` receipt evidence as `score_contributions` + `total_score`.

**Scores never override forbid.** Receipt evidence makes this auditable.

The `@<name>` form in scoring rules and procedure predicates is a load-time substitution for reuse — see extensions.md §2.4.

### 3.3 `procedure` as engine construct (extensions.md §3)

Procedure definitions live in the same engine-config artifact:

```yaml
procedures:
  - name: refund_above_threshold
    initial_state: pending_supervisor_approval
    states: [pending_supervisor_approval, approved, rejected, timed_out]
    terminal_states: [approved, rejected, timed_out]
    trigger:
      action: IssueRefund
      when: '@is_high_value_refund'
    transitions:
      - { from: pending_supervisor_approval, to: approved,
          action: ApproveRefund, actor_when: '@is_supervisor' }
      - { from: pending_supervisor_approval, to: rejected,
          action: RejectRefund, actor_when: '@is_supervisor' }
      - { from: pending_supervisor_approval, to: timed_out, on_timeout: 1h }
    on_timeout_escalate:
      pending_supervisor_approval: manual_review
```

**Instance state is reconstructable from the receipt log.** Each entry into a procedure emits `procedure.enter`, each transition emits `procedure.transition`, timeout firing emits `procedure.timeout`, escalation emits `procedure.escalate`. The engine MAY maintain a procedure-state index for performance, but tearing it down and rebuilding from receipts MUST produce identical state. This matches Yutha's receipt-as-source-of-truth posture and makes procedures auditable end-to-end.

The engine's loader validates procedure shape (reachability, determinism, escalation acyclicity) using textbook graph algorithms; expression bodies validate against the v1.1 schema via `cedar_policy::Validator`. No new analyzer extensions.

### 3.4 Resource budgets as schema-pattern (extensions.md §4)

v1.1 schema adds three attributes to `Agent`:

```
Agent.budget_remaining_usd_cents: Long
Agent.budget_remaining_tool_calls: Long
Agent.budget_remaining_compute_ms: Long
```

And matching context fields on `SendEnvelope` and `IssueCapability`:

```
context.estimated_cost_usd_cents: Long
context.estimated_cost_tool_calls: Long
context.estimated_cost_compute_ms: Long
```

The SDK populates `estimated_cost_*` per call; the control plane synthesizes `budget_remaining_*` from its own state. Canonical idiom is stock Cedar:

```cedar
forbid (principal, action == Action::"SendEnvelope", resource)
when { principal.budget_remaining_usd_cents < context.estimated_cost_usd_cents };
```

No new compilation, no new analyzer rules — pure schema augmentation.

### 3.5 Memory norms as schema-pattern (extensions.md §5)

v1.1 schema adds:

- New entity type `Memory` (attributes: `memory_id`, `owner: Agent`, `scope: String`, `tags: Set<String>`, `payload_schema_id: String`, `created_at_unix_ns: Long`).
- Three new actions: `ReadMemory`, `WriteMemory`, `ShareMemory`, each `appliesTo principal: [Agent], resource: [Memory]` with appropriate context fields.

Canonical idioms are stock Cedar `permit` / `forbid` over the new types — full set in extensions.md §5.3. The constitution evaluation lands as a `constitution.evaluate.{pass,deny}` receipt alongside the memory layer's own `memory.read` / `memory.write` / `memory.share` receipts; both lifecycle and policy decisions are auditable.

### 3.6 Cross-capability composition

The structural properties that make composition trivial:

1. The Cedar source file knows only Cedar primitives and schema-declared types. It cannot reference engine-construct outputs (scoring totals, procedure state) because the schema simply doesn't declare them.
2. The engine config can reference Cedar via expression strings, but its own declarations are invisible to Cedar — Cedar's analyzer never sees the YAML.
3. The engine orchestrates the call order: Cedar gates first; scoring rules and procedure transitions evaluate after, never the reverse.

Cycles can't form because the data flow is one-directional. The composition rule from earlier drafts ("`prefer` scores can't gate `procedure` transitions") is achieved structurally — there's no syntactic surface where a cycle could be introduced.

The only composition rule the loader actively enforces is acyclic procedure escalation (a textbook graph cycle detection).

## 4. Schema bump

The base schema bumps from v1.0.0 to v1.1.0 — minor bump per RFC 0010 §3.5. Additions:

- Three new attributes on `Agent`: `budget_remaining_usd_cents`, `_tool_calls`, `_compute_ms`.
- Three new context fields on `SendEnvelope`: `estimated_cost_usd_cents`, `_tool_calls`, `_compute_ms`.
- Same three on `IssueCapability`.
- New entity type `Memory`.
- Three new actions: `ReadMemory`, `WriteMemory`, `ShareMemory`.

Existing v1.0-pinned constitutions continue to evaluate under their pinned version per RFC 0010 §3.5.

Per RFC 0010 §3.4 (schema authoring posture), operators MAY further extend v1.1 via signed schema delta. The delta-only restriction is enforced at constitution load time.

**Note:** the engine-config schema is a separate artifact specced in extensions.md §2 and §3. It is not a Cedar schema. Versioning is independent of the Cedar schema's version, though for v1.1 they align at "1.1.0."

## 5. New receipt action-kinds

Four new entries in the `Constitution` domain of `/spec/receipt/canonical-actions.md`:

| `action_kind` | Producer | Actor | Notes |
|---------------|----------|-------|-------|
| `procedure.enter` | Constitution engine | Subject agent | A request matched a procedure's trigger; new instance spawned. Evidence: `procedure_name`, `instance_id`, `triggering_action_descriptor_digest`, `initial_state`. |
| `procedure.transition` | Constitution engine | Transition-actor agent | A procedure transition fired. Evidence: `instance_id`, `from_state`, `to_state`, `transition_actor`, `transition_action_descriptor_digest`. |
| `procedure.timeout` | Constitution engine | Control plane | A procedure timeout fired before any explicit transition. Evidence: `instance_id`, `state_at_timeout`, `timeout_wall_clock`, `timeout_value`. |
| `procedure.escalate` | Constitution engine | Control plane | A timeout-escalate fired. Evidence: `from_procedure_name`, `from_instance_id`, `to_procedure_name`, `to_instance_id`. |

`constitution.evaluate.pass` evidence is extended to carry `score_contributions: list<(rule_id, score: Decimal)>` and `total_score: Decimal` when scoring rules fired. Both absent when no scoring rule applied.

## 6. Conformance hooks

A conformant constitution implementation:

- **Cedar policy.** Parse with stock `cedar-policy`; validate against v1.1 schema; reject unschema'd references.
- **Engine config shape.** Validate YAML/protobuf shape against the v1.1 engine-config schema.
- **Cedar expressions in engine configs.** Parse and validate each `when` / `actor_when` / `trigger.when` against the v1.1 schema using `cedar_policy::Validator`.
- **Procedure state from receipts.** Maintain a procedure-state index over the receipt log; tolerate index reset (rebuild from receipts deterministically).
- **Score emission.** Emit `score_contributions` + `total_score` in `constitution.evaluate.pass` evidence when scoring rules fired.
- **Timeout firing.** Honor procedure timeouts against `Timestamp.wall_clock` per RFC 0008. Default-deny when wall-clock parsing fails.
- **Loader validation.** Reject configs that violate extensions.md §2.6 (scoring) or §3.5 (procedures).
- **Determinism.** Same inputs (Cedar policy + engine config + request + entity store) produce identical decision + evidence + receipt content-address across implementations.

Conformance test cases live under `/conformance/interface/language/` (added during F-code stages alongside the implementation crate).

## 7. Threat-model linkage

The capabilities extend the constitution layer's defense against A4 (deceptive norm authorship) and A7 (norm drift):

- **`prefer`** makes ranking-as-policy auditable. Operators previously embedded ranking in application code; now they express it in the engine config, the loader validates it, and runtime scores land in receipts. A4 mitigation: no out-of-band ranking code; the analyzer + loader is the security boundary.
- **`procedure`** makes multi-step workflows auditable. Every transition emits a receipt; state is reconstructable; the receipt fabric records the full workflow history. A7 mitigation: drift in multi-step processes is now detectable as receipt sequences that diverge from current procedure definitions.
- **Resource budgets** bound A1 (hostile agent) blast radius. A compromised agent cannot exceed its budget; the constitution layer enforces independently of capability caveats.
- **Memory norms** are the primary policy surface for A3 (prompt injection) at the memory layer. A prompt-injected agent attempting to leak memory hits constitution-layer forbid rules; combined with capability caveats, this is defense in depth.

## 8. Migration path

Implementations on v1.0 schema (RFC 0010 only) that want to opt into v1.1:

1. Upgrade the constitution engine to a version supporting v1.1 schema and the engine-config artifact (forthcoming `yutha-cedar-plus` crate).
2. Amend the swarm's constitution: pin `schema_version: "1.1.0"`; add scoring rules and procedures to the engine config; add memory/budget policies to the Cedar source if desired.
3. The amendment lands as a `constitution.amend.commit` receipt; the schema-version transition is recorded in its evidence.
4. Subsequent gated actions invoke the v1.1-aware evaluator.

Implementations that *don't* upgrade continue to evaluate v1.0 constitutions correctly — the schema bump is additive and the engine config is opt-in.

## 9. Open questions for review

Captured in [`extensions.md`](../constitution/extensions.md) §8. Most relevant for review:

- **Engine-config serialization format.** YAML, JSON, or TOML for the human-facing form? Protobuf is the machine-readable canonical. Lean YAML.
- **Single vs split engine-config files.** One file with `predicates` + `scoring_rules` + `procedures` blocks, or three files? Currently single; trivial to split.
- **Two-artifact author UX.** Authors now write `.cedar` + `.engine.yaml` in lockstep. Plain-English authoring CLI (Phase 2 deliverable) needs to emit both coherently.
- **Decimal precision for `prefer` scores.** Cedar's Decimal is 4 fractional digits. Sufficient?
- **Procedure instance pruning.** Indefinite accumulation; out of scope for v1.1.
- **Budget refresh actions.** Out of scope for v1.1.
- **"Cedar+" naming.** Now that the language layer is stock Cedar unchanged, the "+" might mislead. Defer to a separate naming review; this RFC retains "Cedar+" as the stack-level brand.

## 10. Backwards compatibility

- Schema v1.0 → v1.1 is an additive minor bump per RFC 0010 §3.5.
- v1.0-pinned constitutions continue to evaluate under v1.0; the engine transparently loads the right schema version.
- The engine config is a new artifact at v1.1. v1.0 constitutions have no engine config; v1.1 constitutions MAY have one. An empty engine config (no predicates, no scoring rules, no procedures) is valid and behaves identically to no config.
- v1.0-aware engines receiving a v1.1 constitution refuse with `constitution.evaluate.deny: schema_version_unsupported`.
- v1.1-aware engines handle both v1.0 and v1.1 constitutions correctly.
- New receipt action-kinds (`procedure.*`) are additive; receipt consumers that don't recognize them treat them as `UNKNOWN` and surface to the operator per `/spec/README.md` §3.

## 11. References

- Spec extensions: [`/spec/constitution/extensions.md`](../constitution/extensions.md)
- Rationale: [`/spec/constitution/rationale.md`](../constitution/rationale.md)
- Schema at v1.1: [`/spec/constitution/schema.cedarschema`](../constitution/schema.cedarschema)
- Predecessor: [RFC 0010](./0010-constitution-language-v1.md)
- Design partner doc: [`/docs/internal/constitution-language.md`](../../docs/internal/constitution-language.md)
- Cedar reference: <https://docs.cedarpolicy.com/>
- Build-plan §7 (Phase 2): [`/docs/internal/build-plan.md`](../../docs/internal/build-plan.md)

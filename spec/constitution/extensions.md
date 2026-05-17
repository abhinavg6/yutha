# Cedar+ Extensions — Specification (v1.1)

> **Spec:** [`schema.cedarschema`](./schema.cedarschema) at v1.1.0
> **RFC:** [0011](../rfcs/0011-cedar-plus-extensions.md)
> **Predecessor:** [RFC 0010](../rfcs/0010-constitution-language-v1.md) (base schema at v1.0)
> **Phase:** 2

## 0. Scope

This document specifies the four constitution-layer capabilities that ship with v1.1 beyond what the stock Cedar gating layer (RFC 0010) covers. None of them extends Cedar's *language*. Two add new vocabulary to the schema; two add new engine-side artifacts the constitution engine consumes alongside the Cedar policy file.

| Category | Capabilities | What it means |
|----------|--------------|---------------|
| **Schema-pattern** — stock Cedar, new schema vocabulary | resource budgets, memory norms | The policy author writes ordinary Cedar `permit`/`forbid` rules. v1.1 adds the entity types, action types, and attributes those rules reference. No new parser, no new analyzer rules. |
| **Engine-construct** — stock Cedar plus separate engine config | `prefer` (scoring), `procedure` (state machines) | Authors write *two* artifacts: a Cedar policy file (stock Cedar) and an engine config (YAML/protobuf) declaring scoring rules or procedures. The engine loads both; runtime evaluation calls back into Cedar for individual predicates referenced by name from the engine config. Cedar's parser, analyzer, and proofs are untouched. |

**Why no syntactic extensions.** Earlier drafts of this RFC introduced `prefer` and `procedure` as new Cedar+ keywords with their own parser/compiler/analyzer extensions. We reversed that decision in favor of the engine-construct path for three reasons: it lets us depend on stock `cedar-policy` unmodified (no fork-equivalent maintenance surface as Cedar evolves); it leaves Cedar's decidability proofs intact (engine constructs have their own validators on a smaller, more conventional surface); and it keeps future workflow constructs cheap to add as engine-side schemas rather than forcing every multi-step concern into the policy language. The trade-off — authors now manage two artifacts instead of one — is real but manageable, and is offset by the architectural cleanliness of the split.

**A note on the "Cedar+" name.** With this RFC, "Cedar+" no longer means "Cedar with new keywords." It means the *Yutha constitution stack*: stock Cedar for gating, plus the v1.1 schema additions, plus the two engine-construct configs. The name is retained as a brand for the layered system; the layering is clearer than it was in earlier drafts.

---

## 1. The split, and why each capability lands where it does

Stock Cedar's strong property is **bounded, decidable evaluation** — every Cedar policy terminates in static depth, and the cedar-policy analyzer can prove correctness properties (equivalence, satisfiability, type-checking against a schema). The constitution layer's job is to extend what Yutha can express without weakening that property.

Two questions decide where each capability lands:

1. **Does the capability need new runtime state or scheduling that Cedar deliberately doesn't model?** If yes → engine construct. (Cedar refuses to model time-as-a-resource, mutable state, or workflows — that's the language's design.)
2. **If no, does the capability fit cleanly as new schema vocabulary?** If yes → schema-pattern. The capability is just new types and actions; Cedar gates them with `permit`/`forbid` like anything else.

Applied to the four:

- **`prefer`** (scoring). Has no runtime state — every score is computed in one pass over the same `(principal, action, resource, context)` Cedar already sees. *Could* be schema-pattern (just add a `score` attribute to action context and compute it client-side), but scoring rules want their own head/body structure separate from gating rules. Engine construct fits more naturally — scoring rules are conceptually a different kind of artifact from permit/forbid rules, even if they reuse Cedar predicates for the body.

- **`procedure`** (state machines). Has runtime state (state machine instances), scheduling (timeouts), and lifecycle (enter / transition / terminate / escalate) — all things Cedar doesn't model. Engine construct.

- **Resource budgets.** No runtime state — the control plane synthesizes "current budget remaining" into the action context per call. Pure schema-pattern: add `budget_remaining_*` attributes on `Agent` and `estimated_cost_*` context fields on the actions that consume budget. Policy authors write stock Cedar `forbid when ...` rules.

- **Memory norms.** No runtime state. Memory operations need new entity types (`Memory`) and new action types (`ReadMemory` / `WriteMemory` / `ShareMemory`). Schema-pattern: declare the vocabulary; authors write stock Cedar `permit`/`forbid` rules over it.

---

## 2. Engine-construct capability: `prefer` (soft preferences)

### 2.1 Motivation

Stock Cedar emits permit / forbid — boolean decisions. Many real swarm policies are not boolean: "prefer routing high-value cases to senior agents," "prefer agents with high reputation when assigning sensitive tasks." These are *ranking* signals, not gating signals. Encoding them as permit/forbid loses the ranking; encoding them as scores buried in application code loses the audit trail.

`prefer` is the audited surface for ranking-as-policy.

### 2.2 The artifact

The constitution carries a `scoring_rules` block in its engine-config artifact (alongside the Cedar policy file). Wire format is YAML in the design here; protobuf is the canonical machine-readable form (the YAML is a human-friendly serialization of the same shape).

```yaml
# constitution.engine.yaml (excerpt)
schema_version: "1.1.0"

scoring_rules:
  - name: senior_for_sensitive
    score: 2.0
    head:
      action: "AssignCase"
      # principal and resource left unbound — applies to any principal/resource pair
    when: 'principal.reputation > 0.8 && resource.tags.contains("sensitive")'
```

Each scoring rule has:

- **`name`** — string identifier, unique within the constitution; appears in receipt evidence.
- **`score`** — Decimal weight. May be negative ("prefer not"). May not be zero (the loader rejects). Range is operator-defined; the constitution's metadata documents the score range and units.
- **`head`** — restricts which `(principal, action, resource)` tuples this rule applies to. Any of `principal`, `action`, `resource` may be omitted, meaning "any value." The most common shape gates on `action` only.
- **`when`** — a Cedar expression string. The engine parses this with `cedar_policy::Expr::from_str` and evaluates it against the same `(principal, action, resource, context, entities)` Cedar's evaluator sees. Same syntax, same type-checking against the schema, same analyzer guarantees on the expression body.

There is no `unless` field; the same effect is expressed by negating the `when` expression. Keeping the surface minimal here lets future versions add an `unless` field cleanly if usage demands.

### 2.3 Evaluation semantics

For each gated action:

1. Stock Cedar evaluates `permit` / `forbid` against the request. If `forbid` (explicit or default-deny), the request is denied and **scoring rules do not execute**.
2. If `permit`, the engine iterates `scoring_rules`. For each rule whose `head` matches the request:
   1. Evaluate the `when` expression against the request context. If false (or evaluation errors out, which counts as false), skip the rule.
   2. If true, add the rule's `score` to the running total.
3. The total score is attached to the decision and emitted in the `constitution.evaluate.pass` receipt evidence.
4. Downstream consumers (the dispatcher, the supervisor layer, ranking heuristics) read the score from the receipt or the live decision and use it as a tie-breaker among permitted actions.

**Scores never override forbid.** The dispatcher cannot rank a forbidden action above a permitted one; the receipt evidence makes this property auditable.

### 2.4 Named-predicate convenience

Scoring rules and procedures (§3) often reference the same predicate. A `predicates` block in the engine config lets authors give a predicate a name and reuse it:

```yaml
predicates:
  - name: is_supervisor
    expr: 'principal.passport_tier == "supervisor"'
  - name: prefers_senior_for_sensitive
    expr: 'principal.reputation > 0.8 && resource.tags.contains("sensitive")'

scoring_rules:
  - name: senior_for_sensitive
    score: 2.0
    head: { action: AssignCase }
    when: '@prefers_senior_for_sensitive'   # reference by name
```

The `@<name>` form is a shorthand the engine resolves at constitution-load time by substituting the named expression. After resolution, the rule is identical to one with the expression inlined. Inlining is always permitted; naming is a reuse convenience.

### 2.5 Receipt emission

When scoring rules contribute to a decision, the `constitution.evaluate.pass` receipt's evidence carries:

```
evidence: {
    constitution_hash: <hash>,
    action_kind: "AssignCase",
    action_descriptor_digest: <hash>,
    matched_rule_ids: ["permit-001", "permit-003"],       // stock Cedar
    score_contributions: [                                  // present only when scoring fired
        { rule_id: "senior_for_sensitive", score: 2.0 },
        { rule_id: "weekend_deprioritize", score: -0.5 }
    ],
    total_score: 1.5,
    input_attribute_digest: <hash>
}
```

`score_contributions` and `total_score` are absent when no scoring rule matched (or when the constitution declares no scoring rules at all).

### 2.6 Validation

The constitution loader rejects the engine config when:

- A rule's `score` is zero, or non-finite, or violates a Decimal precision bound (Cedar's Decimal is 4 fractional digits; the loader enforces this).
- A rule's `when` expression doesn't parse as Cedar, or references attributes the v1.1 schema doesn't declare.
- A `@<name>` reference points at an undefined predicate.
- Two scoring rules share the same `name`.

Validation is conventional structural checking plus Cedar expression parsing — no new analyzer extensions. The cedar-policy crate's `Validator::validate_expression` handles the schema-conformance check; everything else is a small YAML/protobuf validator.

---

## 3. Engine-construct capability: `procedure` (bounded state machines)

### 3.1 Motivation

Some norms are inherently multi-step — escalation, voting, amendment ratification. Stock Cedar evaluates one `(principal, action, resource, context)` quadruple per call; it deliberately doesn't model "this action is part of a larger workflow with N more steps before it completes."

`procedure` is the engine-side surface for multi-step gated workflows. Each procedure is a bounded state machine; transitions are gated by Cedar+ predicates; instance state is reconstructable from the receipt log.

### 3.2 The artifact

The engine config carries a `procedures` block listing procedure definitions:

```yaml
# constitution.engine.yaml (excerpt)
predicates:
  - name: is_supervisor
    expr: 'principal.passport_tier == "supervisor"'
  - name: is_high_value_refund
    expr: 'context.amount_usd_cents > 50000'

procedures:
  - name: refund_above_threshold
    initial_state: pending_supervisor_approval
    states: [pending_supervisor_approval, approved, rejected, timed_out]
    terminal_states: [approved, rejected, timed_out]
    trigger:
      action: IssueRefund
      when: '@is_high_value_refund'
    transitions:
      - from: pending_supervisor_approval
        to: approved
        action: ApproveRefund
        actor_when: '@is_supervisor'
      - from: pending_supervisor_approval
        to: rejected
        action: RejectRefund
        actor_when: '@is_supervisor'
      - from: pending_supervisor_approval
        to: timed_out
        on_timeout: 1h
    on_timeout_escalate:
      pending_supervisor_approval: manual_review

  - name: manual_review
    initial_state: pending_human_review
    states: [pending_human_review, resolved]
    terminal_states: [resolved]
    # ...
```

Per procedure:

- **`name`** — unique within the constitution.
- **`initial_state`** — the state every fresh instance begins in.
- **`states`** — the complete set of named states. Finite and statically declared.
- **`terminal_states`** — subset of `states` that have no outgoing transitions; instances landing here are closed.
- **`trigger`** — the request shape that opens a new procedure instance. Has `action` (the Cedar action name) and `when` (a Cedar expression over the request context).
- **`transitions`** — each is `{ from, to, action, actor_when, on_timeout }`. A transition fires when its `action` is invoked against the open instance AND `actor_when` evaluates true on the request's principal AND the instance is in the `from` state. `on_timeout` is mutually exclusive with `action` — a timeout transition fires automatically when wall-clock advances past `entry_wall_clock + on_timeout`.
- **`on_timeout_escalate`** — a map from state to another procedure name. When the timeout fires in the indexed state, the engine opens a fresh instance of the named procedure (the escalation target) with the original triggering action carried forward as context.

### 3.3 Instance lifecycle

When a request matches a procedure's trigger, the engine spawns an *instance*:

- **`instance_id`** — content-addressed over `(procedure_name, triggering_action_descriptor_digest, swarm_id, entry_wall_clock)`. Two concurrent attempts to trigger the same procedure with the same triggering action produce two distinct instances (different `entry_wall_clock`).
- **Current state** — the most recent transition receipt for this instance. If no transitions have fired, the state is `initial_state`.
- **Open vs closed** — an instance is closed when its state is in `terminal_states` or when a timeout escalation has fired.

Instance state is **reconstructable from the receipt log** — no engine-side mutable state is authoritative. The engine MAY maintain a procedure-state index for performance (materialized view over the relevant receipts) but the index is advisory; tearing it down and rebuilding from receipts MUST produce identical state. This makes procedures auditable end-to-end and matches Yutha's receipt-as-source-of-truth posture.

### 3.4 Receipt emission

| `action_kind` | Producer | When | Evidence |
|---------------|----------|------|----------|
| `procedure.enter` | Constitution engine | A request matched a procedure's trigger; new instance spawned. | `procedure_name`, `instance_id`, `triggering_action_descriptor_digest`, `initial_state`. |
| `procedure.transition` | Constitution engine | A transition fired. | `instance_id`, `from_state`, `to_state`, `transition_actor` (AgentId), `transition_action_descriptor_digest`. |
| `procedure.timeout` | Constitution engine | A timeout fired before any explicit transition. | `instance_id`, `state_at_timeout`, `timeout_wall_clock` (RFC 3339), `timeout_value` (e.g. `"1h"`). |
| `procedure.escalate` | Constitution engine | A timeout-escalate fired. | `from_procedure_name`, `from_instance_id`, `to_procedure_name`, `to_instance_id`. |

These action-kinds are added to `/spec/receipt/canonical-actions.md` in this RFC.

### 3.5 Validation

The constitution loader rejects a procedure when:

- The `initial_state` isn't in `states`.
- Any `from` or `to` in `transitions` isn't in `states`.
- A non-terminal state has no outgoing transitions (unreachable termination — instance gets stuck).
- A terminal state has outgoing transitions (terminal contradiction).
- The transition graph has unreachable states (the analyzer flags but doesn't reject — it's an operator warning).
- Two transitions share the same `(from, action)` or `(from, on_timeout)` (non-determinism).
- The `actor_when` or `trigger.when` expression doesn't parse as Cedar or references unschema'd attributes.
- The escalation graph across all procedures contains a cycle (procedure A escalates to procedure B which escalates back to A).
- Two procedures share the same `name`.

The reachability + acyclicity checks are textbook graph algorithms. The expression checks reuse Cedar's `Validator::validate_expression`. No new analyzer extensions.

### 3.6 Why no `prefer` referenced from procedure predicates

A procedure transition's `actor_when` is a Cedar expression. It CAN reference any attribute the schema declares, including the budget/memory attributes from the schema-pattern extensions. It CANNOT reference scoring outputs (`total_score` or individual rule scores) — those don't exist as attributes on any entity or context field. The schema simply doesn't have them; the analyzer's schema check would reject any expression that tried.

This is the architectural cycle-prevention rule from earlier drafts, now achieved structurally: scoring outputs are receipt evidence, not entity attributes, and procedure predicates are constrained to entity attributes. There's no syntactic surface where a cycle could be introduced.

---

## 4. Schema-pattern capability: Resource budgets

### 4.1 Motivation

Agents have bounded budgets — tool-call quotas, dollar amounts, compute time. The constitution layer needs to gate actions on remaining budget without itself maintaining budget state (state in the policy layer is a footgun and breaks decidability).

The pattern: the control plane synthesizes the agent's *current* budget into the action context; Cedar policies gate the action on the budget threshold.

### 4.2 Schema additions

Three new attributes on `Agent`:

```cedar
entity Agent in [Swarm] = {
    // ... existing fields ...
    budget_remaining_usd_cents: Long,
    budget_remaining_tool_calls: Long,
    budget_remaining_compute_ms: Long,
};
```

Three new context fields on relevant actions (`SendEnvelope`, `IssueCapability` at v1.1; future RFCs add more actions to the budget surface):

```
context: {
    // ... existing fields ...
    estimated_cost_usd_cents: Long,
    estimated_cost_tool_calls: Long,
    estimated_cost_compute_ms: Long,
}
```

The estimated-cost fields are populated by the SDK (the framework adapter knows the cost of the operation it's about to invoke). The control plane forwards them into the Cedar evaluator's context.

### 4.3 Canonical idiom

```cedar
forbid (principal, action == Action::"SendEnvelope", resource)
when {
    principal.budget_remaining_usd_cents < context.estimated_cost_usd_cents
};
```

Equivalent for tool calls and compute time. Multiple budget dimensions are AND-composed (every dimension must individually be above its cost).

### 4.4 Why this isn't an engine construct

Budgets need no runtime state inside the constitution layer. The control plane already maintains agent budgets (it's the source of truth for "how much has agent X spent today"); it injects current values into each request. Cedar gates with stock comparison operators. No engine-side artifact is needed; the schema additions are sufficient.

A future extension could add a `budget(name, current) >= cost(name)` macro for ergonomic sugar; v1.1 deliberately ships the verbose form to keep the surface minimal.

### 4.5 Validation

No new validation — Cedar's analyzer handles attribute lookup and type-checking. The control plane is responsible for populating `budget_remaining_*` and `estimated_cost_*` correctly; misalignment surfaces as `constitution.evaluate.deny` with `deny_reason: evaluator_internal_error`.

---

## 5. Schema-pattern capability: Memory norms

### 5.1 Motivation

Memory operations (read, write, share) are first-class actions in Yutha — `/spec/receipt/canonical-actions.md` already enumerates `memory.read`, `memory.write`, `memory.share`. The constitution layer needs to gate them with familiar permit/forbid rules.

### 5.2 Schema additions

New entity type `Memory`:

```cedar
entity Memory = {
    memory_id: String,
    owner: Agent,
    scope: String,                   // "private" | "shared" | "swarm" | "external" | <operator-defined>
    tags: Set<String>,               // {"pii"}, {"financial"}, {"customer-x"}, etc.
    payload_schema_id: String,
    created_at_unix_ns: Long,
};
```

The `owner` attribute is an `Agent` reference. Policies can write `resource.owner == principal` for the canonical "is this my memory?" predicate.

Three new actions:

```cedar
action ReadMemory appliesTo {
    principal: [Agent],
    resource: [Memory],
    context: { current_time_unix_ns: Long, current_wall_clock: String }
};

action WriteMemory appliesTo {
    principal: [Agent],
    resource: [Memory],
    context: {
        write_kind: String,          // "create" | "update" | "delete"
        current_time_unix_ns: Long,
        current_wall_clock: String,
    }
};

action ShareMemory appliesTo {
    principal: [Agent],
    resource: [Memory],
    context: {
        from_scope: String,
        to_scope: String,
        current_time_unix_ns: Long,
        current_wall_clock: String,
    }
};
```

### 5.3 Canonical idioms

```cedar
// Default: an agent may read its own memory.
permit (principal, action == Action::"ReadMemory", resource)
when { resource.owner == principal };

// Default: an agent may read swarm-scoped memory.
permit (principal, action == Action::"ReadMemory", resource)
when { resource.scope == "swarm" };

// Forbid writing PII to external scope, ever.
forbid (principal, action == Action::"WriteMemory", resource)
when { resource.tags.contains("pii") && resource.scope == "external" };

// Forbid sharing PII out of swarm scope unless principal is compliance.
forbid (principal, action == Action::"ShareMemory", resource)
when { resource.tags.contains("pii") && context.to_scope == "external" }
unless { principal.passport_tier == "compliance" };
```

The canonical schemas (F8) bundle a baseline memory-norms policy block matching these idioms.

### 5.4 Receipt action-kinds

The `memory.*` action-kinds (`memory.read`, `memory.write`, `memory.share`) already exist in `/spec/receipt/canonical-actions.md` (pre-allocated Phase 2 entries). RFC 0011 doesn't add new memory-layer action-kinds; the constitution evaluation lands as a `constitution.evaluate.{pass,deny}` receipt alongside the memory-layer's own receipt.

### 5.5 Validation

No new validation — stock Cedar.

---

## 6. Cross-capability composition

The architectural cleanliness of the engine-construct split makes most composition concerns trivial. The cases worth enumerating:

| Combination | Allowed? | Notes |
|-------------|----------|-------|
| `prefer` referenced inside `procedure` predicates | **No, structurally** — scoring outputs are not entity attributes; the schema doesn't declare them; the analyzer rejects expressions trying to read them. |
| `prefer` head referencing schema-pattern attributes (budgets, memory) | Yes — same as any Cedar predicate. |
| `procedure` transition predicates referencing budgets/memory | Yes — same as any Cedar predicate. |
| Procedure escalating to another procedure | Yes, **non-circular** — loader rejects cyclic escalation graphs. |
| Stock Cedar gating (`permit`/`forbid`) over budgets/memory | Yes — that's exactly what they're for. |

Three structural properties make this work:

1. The Cedar source file knows only Cedar primitives and schema-declared types. It cannot reference anything the engine constructs produce because none of that lives in the schema.
2. The engine config (scoring rules and procedures) can reference Cedar via expression strings, but its declarations are not visible to Cedar — Cedar's analyzer never sees the YAML.
3. The engine itself orchestrates the call order: stock Cedar gates first, scoring rules and procedure transitions fire after, never the reverse.

Cycles can't form because the data flow is one-directional.

---

## 7. Conformance hooks

A conformant constitution implementation:

- **Cedar policy.** Parse and validate against the v1.1 schema using stock `cedar-policy`; reject policies that reference undeclared attributes.
- **Engine config schema.** Validate YAML/protobuf shape against the v1.1 engine-config schema. Reject malformed configs.
- **Cedar expressions inside engine configs.** Parse each `when` / `actor_when` / `trigger.when` expression with `cedar_policy::Expr::from_str`; validate against the v1.1 schema; reject expressions that reference undeclared attributes.
- **Procedure state from receipts.** Maintain the engine's procedure-state index over the receipt log; tolerate index reset (rebuild from receipts deterministically).
- **Score emission.** Emit `score_contributions` and `total_score` in `constitution.evaluate.pass` receipt evidence when scoring rules fired.
- **Timeout firing.** Honor procedure timeouts against `Timestamp.wall_clock` per RFC 0008. Default-deny when wall-clock parsing fails.
- **Engine-config validation.** Reject configs that violate §2.6 (scoring) or §3.5 (procedures).
- **Determinism.** Same inputs (Cedar policy + engine config + request + entity store) produce identical decision + evidence + receipt content-address across implementations.

Conformance test cases live under `/conformance/interface/language/` (added during F-code stages alongside the `yutha-cedar-plus` implementation crate).

---

## 8. Open questions for review

- **Engine-config serialization format.** YAML throughout this doc; protobuf is the canonical form for content-addressing. Should the human-facing form be YAML, JSON, or TOML? Lean YAML (matches common Kubernetes/SRE muscle memory); flag for design partners.
- **Single file vs separate files.** Should `predicates`, `scoring_rules`, and `procedures` live in one engine-config file or be split across `predicates.yaml` / `scoring.yaml` / `procedures.yaml`? Currently designed as a single document; splitting is trivial if reviewers prefer.
- **Author UX for two-artifact constitutions.** Authors now write a `.cedar` file *and* a `.engine.yaml` file. Tooling has to keep them coordinated (renaming a predicate breaks references; renaming an action breaks scoring/procedure heads). The plain-English authoring CLI (Phase 2 deliverable) needs to emit both in lockstep.
- **Decimal precision for `prefer` scores.** Cedar's Decimal type has 4 fractional digits. Sufficient for v1.1; revisit if design partners hit ceilings.
- **Procedure instance pruning.** Procedure instances in terminal states accumulate in the receipt log indefinitely. Should we add a `procedure.gc` action-kind that compacts old instances? Out of scope for v1.1.
- **Budget refresh actions.** Operators currently reset budgets via direct receipt emission. A clean API would help; defer to a follow-up RFC.
- **"Cedar+" naming.** Now that the language layer is stock Cedar, the "+" marketing might mislead. Defer to a separate naming review; this RFC retains "Cedar+" as the stack-level brand.

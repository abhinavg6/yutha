# Constitution Language Design

> **Repo location:** `/docs/design/constitution-language.md`
> **Version:** v0.1 (working draft)
> **Status:** Initial design; design-partner input required before Phase 2 scope freeze
> **Owners:** Workstream G (Constitution Engine), Workstream A (Specs), Workstream L (Security)

## Purpose

This document specifies the language used to author swarm constitutions: the declarative norm specs that govern agent behavior. It is the technical companion to **PRD Section 9** (Coordination & Norms) and a prerequisite for Phase 2.

The language is the load-bearing artifact of the entire enforcement story. If it is too weak, real norms cannot be expressed and operators write predicates by hand. If it is too strong (Turing-complete, side-effecting), it becomes an attack surface — policy engines have a long history of becoming RCE vectors. Getting this design right is non-optional.

## Goals

1. **Plain-English authorship is the front door.** A norm author writes English; an LLM-assisted compiler emits a reviewable predicate plus generated test cases.
2. **The compiled form is the source of truth.** The English is documentation; the predicate is what runs.
3. **Predicates are non-Turing-complete by construction.** No loops, no recursion, no general computation. Decidable evaluation is structural, not by convention.
4. **No side effects during evaluation.** Predicates read inputs and return decisions. They cannot mutate, call external services, or alter state.
5. **Versioned and signed.** Every constitution has an explicit version, a signed manifest, and a diff-friendly representation.
6. **Reviewable as policy.** A compliance lead must be able to read the compiled form and understand what it means, without LLM mediation.
7. **Norms can express the dimensions Concord cares about:** agent actions, message content, memory access, resource budgets, escalation procedures, amendment rules.

## Anti-goals

- General-purpose programming (loops, recursion, arbitrary I/O).
- Stateful evaluation. The evaluator is pure.
- External lookups during evaluation. All inputs to a predicate are passed in by the caller.
- Compile-time-only checks that don't apply at runtime. Every guarantee is a runtime guarantee.

## Design space and prior art

Four candidates considered for the canonical compiled form:

### Bespoke DSL

A language designed entirely for Concord's needs.

- **Pros:** complete control over semantics; can be made non-Turing-complete by construction; can integrate native types for agent passports, memory items, capabilities.
- **Cons:** more design work upfront; ecosystem of tools (parsers, formatters, IDE support) must be built from scratch; users must learn a new language.

### Rego (OPA)

The Open Policy Agent project's language. Mature and widely deployed for Kubernetes and infrastructure policy.

- **Pros:** mature ecosystem, broad familiarity, real production deployment at scale.
- **Cons:** Rego allows constructs that compile to Turing-complete or semi-Turing-complete evaluation under some conditions. Decidability properties are not as strong as we want for a security-critical language. The OPA team has acknowledged design tensions here.

### Cedar (AWS / Open Source)

A policy language explicitly designed for non-Turing-completeness, formal verification, and authorization use cases.

- **Pros:** designed for exactly the property profile we need. Formal verification of policy properties (like "this policy never permits action X") is feasible. Mature implementation. Open source. Active community. Implemented in Rust, aligning with our language choice.
- **Cons:** smaller ecosystem than Rego. Designed primarily for authorization (permit / forbid decisions), so extending to soft preferences and procedures requires layering. Less name recognition.

### Datalog

The classical declarative logic-programming language. Decidable, well-understood.

- **Pros:** mathematically clean; decidability is a textbook property; expressible.
- **Cons:** harder for non-experts to author. Authoring tooling thinner than Cedar's. Datalog as a policy language has more academic than industrial deployment.

## Decision

**Adopt Cedar as the canonical compiled form.** Author a Concord-specific extension layer ("Cedar+") that adds the dimensions Cedar doesn't natively cover (soft preferences, procedures, resource budgets, memory norms).

Plain-English authorship compiles to Cedar+. Cedar+ is what evaluates; Cedar+ is what reviewers read.

**Why Cedar over the alternatives:**

- The non-Turing-complete property is by construction, not by convention.
- Formal verification of policy properties is feasible — important for a security-critical system.
- The authorization shape of Cedar (permit / forbid + conditions) maps directly to Concord's hard constraints. Soft preferences and procedures layer cleanly above.
- Active open community; not a single-vendor language.
- Mature implementation in Rust, which aligns with ADR 0001.

We considered building a bespoke DSL and reject that for v1 specifically because Cedar gets us to a defensible v1 faster, with stronger formal properties, while still allowing evolution. If Cedar proves limiting in a way that warrants forking or replacing, that decision is documented in a future ADR.

## Architecture: three-layer authoring

```
┌──────────────────────────────────────────┐
│ Layer 1: Plain-English (input)           │
│ "Agents must never share customer email  │
│  addresses with external services."      │
└────────────────┬─────────────────────────┘
                 │ LLM-assisted compilation
                 │ (authoring time only)
                 ▼
┌──────────────────────────────────────────┐
│ Layer 2: Cedar+ (canonical)              │
│ forbid (principal, action ==             │
│   Action::"share_external", resource)    │
│ when { resource.tags.contains("email") } │
└────────────────┬─────────────────────────┘
                 │ Static analysis,
                 │ test generation,
                 │ human review
                 ▼
┌──────────────────────────────────────────┐
│ Layer 3: Compiled predicate (runtime)    │
│ Deterministic decision tree;             │
│ bounded evaluation depth                 │
└──────────────────────────────────────────┘
```

Layer 1 is the front door. Layer 2 is the source of truth. Layer 3 is what the engine evaluates.

The LLM is involved only at authoring time. It translates English to Cedar+, and it generates test cases for the human to review. Once the constitution is saved, **the LLM is no longer in the path**; runtime evaluation is pure Cedar+.

## What the language can express

### Hard constraints

```cedar
forbid (principal, action == Action::"share_pii", resource)
when { resource.scope == "external" };

permit (principal, action, resource)
when { principal.role == "supervisor" }
unless { action == Action::"self_elevate" };
```

Every action is denied unless permitted. Every permit can have `unless` clauses. Forbid clauses are absolute and override permits.

### Soft preferences

Soft preferences are an extension. Cedar emits permit / forbid; Cedar+ layers a `prefer` keyword that compiles to a scoring function:

```cedar
prefer score(2.0) (principal, action == Action::"handle_task", resource)
when { principal.reputation > 0.8 && resource.category == "sensitive" };
```

The dispatcher consumes `prefer` scores when ranking candidates; they never override `forbid`.

### Memory norms

Memory operations are first-class actions in Concord. Memory norms are constraints on those actions:

```cedar
forbid (principal, action == Action::"write_shared_memory", resource)
when { resource.tags.contains("pii") }
unless { principal.role == "compliance_handler" };

permit (principal, action == Action::"read_shared_memory", resource)
when { resource.scope == "swarm" || principal.id == resource.owner };
```

### Resource budgets

```cedar
forbid (principal, action == Action::"call_tool", resource)
when { principal.budget_remaining < resource.estimated_cost };
```

Budgets are evaluated as inputs to the predicate; the engine does not maintain budget state itself. The control plane passes current state in.

### Procedures

Procedures (escalation, voting, amendment) are a Cedar+ extension. They are encoded as state machines whose transitions are gated by Cedar+ predicates:

```
procedure refund_above_threshold {
  on action == Action::"issue_refund"
  when amount > 500
  require approval from principal where principal.role == "supervisor"
  with timeout 1 hour
  on timeout escalate to procedure manual_review
}
```

This compiles to a small state machine plus a set of Cedar+ predicates that gate transitions. The state machine is itself bounded and deterministic.

### Temporal constraints

Limited temporal expression: comparisons against a clock value passed in by the caller (the engine does not read the clock itself).

```cedar
forbid (principal, action, resource)
when { principal.quarantined_until > context.current_time };
```

No general temporal logic, no event histories beyond what the caller passes in.

## What the language explicitly cannot express

- Loops or recursion.
- Calls to external services during evaluation.
- Mutation of any state, including its own inputs.
- Unbounded computation. Every predicate has a bounded evaluation depth, statically checked.
- Reflection or meta-evaluation of policies.
- I/O of any kind.

These restrictions are structural. The Cedar+ compiler rejects programs that violate them; there is no flag to enable them.

## Evaluation model

- Predicates compile to a decision tree with bounded depth.
- Evaluation is deterministic: given the same inputs, the same decision is produced.
- Evaluation is bounded: a depth limit is statically enforced; a time limit is enforced at runtime as a safety net.
- Each decision produces evidence: a list of the rules that matched and the input fields they read. This evidence is recorded in the receipt for the action.
- No partial evaluation. A predicate either evaluates to a decision or fails closed (default-deny) with the failure recorded.

## LLM-assisted authoring

The authoring tool runs only at constitution editing time.

**Inputs:**

- The English text the author wrote.
- The Cedar+ schema for this swarm (entity types, action types, attributes).
- (Optionally) example scenarios the author wants the constitution to handle correctly.

**Outputs:**

- One or more candidate Cedar+ rules.
- Generated test cases that exercise the rules. Each test case is a (input, expected decision) pair.
- A diagnostic report identifying ambiguities, missing edge cases, or English statements that could not be cleanly compiled.

The author reviews. They can edit the Cedar+ directly or refine the English and recompile. Once they save, the LLM is no longer in the path.

**The LLM is not trusted to produce safe predicates by itself.** The static analyzer rejects programs that violate the structural constraints (no loops, no I/O, etc.) regardless of LLM intent. Test cases are reviewed before save. **The LLM is an authoring convenience, not a security boundary.**

## Versioning, signing, and amendment

A constitution is a signed artifact:

```yaml
constitution_version: "1.4.2"
swarm_id: "swarm-abc123"
parent_version: "1.4.1"           # null for genesis
signed_by: "operator-key-fingerprint"
signed_at: "2026-03-15T10:00:00Z"
content:
  cedar_plus_source: "..."
  english_source: "..."
  test_cases: [...]
  schema_version: "concord-cedar-plus-v1"
```

Versions are immutable. An amendment produces a new version with `parent_version` pointing back. The full chain is a tamper-evident history.

Amendment requires the procedures defined in the constitution itself. By default:

- **Minor amendments** (clarifications, new soft preferences): single operator signature; effective on the next swarm tick.
- **Major amendments** (changes to hard constraints, new procedures): defined quorum (e.g., supervisor + operator); time-locked for a defined period before activation.
- **Sensitive amendments** (changes to the amendment procedure itself, changes to enforcement procedures, changes to memory access norms): higher quorum and longer time-lock.

The bootstrap version of the constitution defines the amendment procedure; thereafter the procedure can amend itself, subject to its own rules.

## Open design questions

- **Schema authoring.** Cedar+ requires a schema (entity types, action types). Who authors the schema? Default proposal: Concord ships canonical schemas for common workloads (queue-mode support swarm, campaign-mode incident response, etc.); operators extend.
- **Test-case generation quality.** LLM-generated test cases need empirical evaluation before they can be relied on. Phase 2 includes a study.
- **Backwards compatibility on schema evolution.** When the canonical schema evolves, existing constitutions must still evaluate. We need explicit migration semantics. Defer to Phase 2 design work.
- **Authoring UI.** The plain-English authoring tool is a CLI in v1, a web UI in Phase 3 (visual composer). The transition needs to preserve the same compilation pipeline.
- **Fallback when LLM authoring fails.** Some norms cannot be cleanly compiled from English. The fallback is hand-authored Cedar+. Authoring tools must make this transition smooth.
- **Internationalization.** The plain-English layer is English-first in v1. Multilingual authoring is a Phase 3 commitment, but the schema layer should not assume English even in v1.
- **Rego compatibility shim?** Some teams have existing Rego policy. Question: ship a one-way Rego-to-Cedar+ converter as a migration aid? Defer.

## Security considerations

Recapped from PRD Section 18.1:

- The Cedar+ evaluator runs in a sandbox with bounded memory and CPU. Sandbox escape is a critical vulnerability class.
- Cryptographic verification of constitution signatures uses the same audited libraries as the rest of the platform.
- LLM authoring is not a trust boundary. The structural analyzer is. Any rule that gets through analysis must be safe regardless of how it was produced.
- Test cases are not a substitute for analysis. A constitution that passes its tests but contains a logic bug is still a logic bug.
- **Schema attacks:** a malicious schema could allow unsafe entity-type or action-type definitions. Schemas are themselves signed and reviewed; canonical schemas are vetted by the foundation.

## How this document evolves

Major design changes follow the RFC process. Minor refinements (clarifications, examples) are committed normally. Test cases for the language semantics live in the constitution-engine repository and are part of the conformance suite.

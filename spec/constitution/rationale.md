# Constitution Spec — Design Rationale

> **Spec:** [`schema.cedarschema`](./schema.cedarschema)
> **Version:** v1.0 draft
> **RFC:** 0010
> **Phase:** 2 (Coordination & Norms)
> **Design partner doc:** [`/constitution-language.md`](../../constitution-language.md) — held at workspace root until coordinated rename pass; `rationale.md` is the spec-layer summary.
> **Threat-model linkage:** A1 (hostile agent — bounded), A3 (prompt injection — secondary defense), A4 (deceptive norm authorship — primary defense), A6 (sybil — partial), A7 (norm drift — primary defense), A9 (compromised supervisor — partial)

## 1. What is a constitution, in one paragraph

A constitution is a signed, versioned, declarative policy document that defines a swarm's norms — what actions are permitted, forbidden, or preferred, by which principals, under which conditions. Constitutions are authored in plain English at Layer 1, compiled to Cedar+ at Layer 2 (the canonical form reviewers read and the static analyzer verifies), and evaluated at Layer 3 as deterministic decision trees with bounded resource consumption. Every consequential action in a Yutha swarm is gated by a constitution evaluation; every evaluation produces a `constitution.evaluate.{pass,deny}` receipt; every constitution version is content-addressed and signature-chained back to the swarm's genesis. The constitution is to swarm norms what the capability is to per-agent authority: an explicit, auditable, structurally-bounded contract. The two compose — a capability says "the holder MAY do X"; a constitution says "the swarm permits X to be done right now, by this principal, under these conditions." Both must pass for an action to proceed.

## 2. Why this shape

Four decisions structure the design:

- **Cedar over Rego/Datalog/bespoke DSL.** Cedar has a published formal semantics, a sound static analyzer that proves termination, and a permit/forbid + conditions shape that maps directly onto agent gating. We build on top of stock Cedar (the open-source `cedar-policy` Rust crate) — we do not fork. Extensions arrive in v1.1+ via RFC 0011 as a layered "Cedar+" surface that compiles down to stock Cedar plus auxiliary state machines, never widening Cedar's decidability properties. Alternatives considered (and rejected for v1) at [`/constitution-language.md`](../../constitution-language.md) §"Design space and prior art".

- **Three-layer authoring with the LLM at build-time only.** Layer 1 (plain English) is the front door for non-engineers. Layer 2 (Cedar+) is canonical; reviewers read Cedar+, the static analyzer verifies Cedar+. Layer 3 (compiled decision tree) is what the engine evaluates. The LLM only translates Layer 1 to Layer 2 at authoring time. Runtime evaluation is pure Cedar+ — the LLM is never on the request path. This invariant is build-time enforced (CI tests verify no LLM dependency is reachable from the evaluator) and is the structural reason A4 (deceptive norm authorship) is bounded: a malicious LLM cannot produce policies the static analyzer accepts.

- **Composes with capabilities, does not replace them.** A constitution may *require* a capability for an action (the policy can name `principal.capabilities` in its `when` clause), but the capability itself is not a Cedar+ predicate. This keeps both layers decidable in isolation. Capabilities answer "who has authority"; constitutions answer "what authority is permitted to be exercised right now under our norms." A wire-level `EnvelopeService.Send` invocation runs the capability check (RFC 0007) AND the constitution evaluation; both must pass. Either failure surfaces as the appropriate deny receipt.

- **Default-deny, surfaced denials.** Every denied evaluation produces a `constitution.evaluate.deny` receipt with the deny reason, the matched forbid rule (if any), and the input attributes the evaluator read. There is no silent failure and no implicit permit. PRD §13.2: "Default-deny on ambiguity. When norms are silent, the system errs toward inaction and surfaces the decision."

## 3. The schema, section by section

### 3.1 Entity types

Five entity types at v1.0: `Agent`, `Swarm`, `Capability`, `Envelope`, `Resource`. Each mirrors a substrate concept and exposes only the attributes the v1.0 evaluator needs the control plane to marshal.

**`Agent in [Swarm]`.** The `in` relation makes `principal in Yutha::Swarm::"<swarm-id>"` work as a policy predicate, which is the canonical way to gate on swarm membership without naming agents individually. Attributes: `agent_id`, `passport_tier`, `framework`, `passport_hash`, `reputation`. The reputation scalar is admitted in v1.0 even though the supervisor layer that computes it lands in F4 (RFC 0013 four-stage enforcement) — admitting the attribute in the schema now means F2's `prefer` extension (RFC 0011) can write `prefer score(2.0) when principal.reputation > 0.8` without a schema migration.

**`Swarm`.** Topology mode + active constitution version. The mode field is what makes topology-aware policies expressible — closed-mode constitutions can be permissive about who registers; open-mode constitutions need sybil-aware predicates by default.

**`Capability in [Agent]`.** The `in` relation lets policies enumerate `principal.capabilities` and reason over them. Critically, `scope_action_kinds: Set<String>` is exposed (not the full caveat tree) — the constitution layer reasons about *what capabilities authorize* (e.g. "does this agent already hold a cap for `envelope.send`?"), not the per-caveat caveat semantics (those are the cap layer's responsibility per `/spec/capability/rationale.md` §2).

**`Envelope`.** Exposed as a first-class entity, not just a context bag, so policies that index multiple envelopes (a supervisor reviewing a batch, an auditor reasoning over a recent window) can do so without ad-hoc marshalling. The `recipient_kind` + `recipient_value` pair is the Cedar-expressible flattening of the protobuf oneof in `/spec/envelope/v1.proto`.

**`Resource`.** A generic catch-all with `resource_kind`, `scope`, `tags`. Admitted in v1.0 to forward-compatible types ahead of RFC 0011's memory norms (`memory.read`/`memory.write` actions target a memory resource) and the tool-call extension (the resource is the tool being invoked). v1.0 has no actions that take `Resource` as a target; the type is reserved.

### 3.2 Action types

Four actions at v1.0: `SendEnvelope`, `IssueCapability`, `AttenuateCapability`, `RevokeCapability`. Each gates a substrate RPC 1:1. Each carries a `context` record the control plane synthesizes per invocation.

The synthesizer for each action is bound at the gRPC handler:

- `SendEnvelope` synthesized inside `EnvelopeHandler::send`, after the capability check passes. Context fields are pulled from the envelope plus the validated bearer.
- `IssueCapability` / `AttenuateCapability` / `RevokeCapability` synthesized inside `CapabilityHandler` per RPC. The capability artifact's own fields populate `resource`.

The synthesizer adds two universal context fields: `current_time_unix_ns: Long` and `current_wall_clock: String`. The wall-clock string is RFC 3339 per RFC 0008's wall-clock convention; the unix_ns is admitted for policies that need monotonic ordering within a process (rare, but expressible). Policies that compare against the clock use `context.current_wall_clock`; policies that compute deltas can use `context.current_time_unix_ns`.

Memory operations, tool calls, and the enforcement-stage transitions (detect/coach/quarantine/evict) arrive as additional action types in subsequent RFCs:

| RFC | Adds |
|-----|------|
| **0011** (Cedar+ extensions) | New keywords (`prefer`, `procedure`, resource budgets, memory norm sugar) |
| **0012** (Evaluation model + sandbox) | No new actions — refines the per-action evaluator contract |
| **0013** (Four-stage enforcement) | `DetectViolation`, `CoachAgent`, `QuarantineAgent`, `EvictAgent` action types |

### 3.3 What is intentionally NOT in v1.0

- **Memory action types.** `memory.read` / `memory.write` / `memory.share` are in `/spec/receipt/canonical-actions.md` already, but the constitution-side action types and corresponding entity attributes (memory scope, owner, tags) arrive in RFC 0011 alongside the memory-norm Cedar+ extension that lets operators write the relevant policies cleanly.
- **Tool-call action type.** Same reasoning — the action-kind exists in the receipt vocabulary; the Cedar+ entity surface for it arrives with the budgets/tool extension in RFC 0011.
- **Cross-swarm references.** Cedar lets us name foreign entities (`Yutha::Swarm::"other-swarm-id"`), but v1.0 policies SHOULD NOT do so. Federation (RFC 00XX, Phase 4) is the spec layer that turns cross-swarm references into a first-class thing; v1.0 evaluators MAY refuse policies that name swarms other than the one they're evaluating against.

## 4. Schema authoring posture (closes Open Q from design doc)

The `constitution-language.md` design doc flagged "schema authoring" as an open question. RFC 0010 closes it:

- **Yutha ships canonical schemas under `/spec/constitution/canonical-schemas/`** (added in F2/F8 — sub-stages F1g and F8 of the build-plan §7 deliverables). v1.0 will ship at minimum `support-queue.cedarschema` (workload S1), `incident-response.cedarschema` (workload S3), plus baseline schemas for closed/open/hybrid topology modes (RFC 0011 forward-references these).
- **Operators MAY extend a canonical schema by authoring a signed schema delta.** A delta references the canonical schema's content-address, adds (never modifies, never removes) entity types and attributes, and is itself content-addressed and signed by the operator. The combined effective schema (canonical + delta) is what the evaluator loads at policy evaluation time.
- **Operators MAY NOT author a fully bespoke schema in v1.0.** This is a deliberate v1.0 restriction — the schema is the contract between Cedar+ policy and the substrate's marshalling code, and a fully bespoke schema means the substrate has no way to know which attributes it must populate. v1.1+ may relax this once `yutha-cedar-plus` exposes a schema-discovery interface the marshaller can consult.

The delta-only constraint is enforced at constitution validation time (the static analyzer rejects constitutions whose schema cannot be expressed as `canonical + delta`).

## 5. Schema evolution semantics (closes Open Q from design doc)

The second F1-blocking open question: how do constitutions survive schema bumps?

The rule: **constitutions pin a schema version at bootstrap and evaluate under that pinned version forever**, unless explicitly amended to a newer version. This is the canonical Cedar+ invariant for schema-policy compatibility.

Concrete semantics:

1. Every constitution artifact carries a `schema_version` field (semver string, e.g. `"1.0.0"`). The genesis constitution sets this to the canonical schema version it was authored against.
2. An evaluator MUST load schemas at the constitution's pinned version. If the constitution pins `1.0.0` and the canonical schema has since advanced to `1.1.0`, the evaluator loads `1.0.0` from `/spec/constitution/canonical-schemas/v1.0.0/` (the canonical-schemas directory is version-namespaced).
3. Schema **minor bumps** (`1.0` → `1.1`) add new entity types or new optional attributes. Existing constitutions pinned at `1.0` continue to evaluate; their evaluator simply doesn't see the new attributes. New constitutions pinned at `1.1` can use them.
4. Schema **major bumps** (`1.x` → `2.0`) may rename or remove attributes. Existing constitutions pinned at `1.x` continue to evaluate under v1 (the v1 schemas are kept available for the 12-month deprecation window per `/spec/README.md` §3). After the window, constitutions still pinned at deprecated versions MAY be refused by the evaluator with `constitution.evaluate.deny` carrying a `schema_version_unsupported` reason — the safe default.
5. Amending a constitution MAY also amend its `schema_version`. Schema-version transitions are themselves auditable as `constitution.amend.commit` receipts; the transition's diff is recorded in the receipt's evidence.

The split between schema versioning and constitution versioning matters: the constitution version reflects the *swarm's policy history*; the schema version reflects the *substrate's vocabulary*. A swarm may amend its constitution dozens of times without ever changing its schema version.

## 6. Threat-model linkage

| Adversary | How this spec contributes to mitigation |
|-----------|------------------------------------------|
| A1 Hostile agent (bounded) | Constitution `forbid` rules express "this principal MAY NOT do X" at swarm-policy level, independent of whether the agent holds a capability for X. A compromised agent with valid caps still has the constitution layer to clear. |
| A3 Prompt injection (secondary defense) | The capability layer is the primary defense per `/spec/capability/rationale.md` §4. The constitution layer adds a second check: even if a prompt-injected agent somehow has the requisite capability, the constitution policy may still refuse. Defense in depth. |
| A4 Deceptive norm authorship | THE primary defense. The static analyzer is the security boundary — it rejects programs that violate decidability constraints (loops, I/O, mutation, unbounded computation) regardless of whether they came from an LLM or a human. The LLM is an authoring convenience; its output runs through analysis like any other input. Build-time invariant tests verify the LLM is unreachable from the runtime evaluator. |
| A6 Sybil (partial) | Open-mode swarms can author constitutions that gate registration on sybil-resistance proofs (`Action::"RegisterAgent"` will arrive in RFC 0013 as an enforcement-stage action). v1.0 admits the topology_mode attribute on Swarm so policies can discriminate by mode. |
| A7 Norm drift | THE primary defense. Constitutions are signed, content-addressed, and version-chained back to genesis. Every amendment produces a receipt. Drift becomes detectable as receipts whose decision wouldn't match the current constitution — an audit query the operator runs against the receipt fabric. |
| A9 Compromised supervisor (partial) | The constitution can encode supervisor-required gates as `forbid ... unless principal.role == "supervisor"` predicates. Combined with the capability layer's `SupervisorRequiredCaveat`, this is the two-person-rule surface. A compromised supervisor alone cannot bypass both layers. |

## 7. Conformance hooks

A conformant constitution implementation:

- **Load.** Accepts a signed constitution artifact; verifies the signer's signature against the swarm's operator-key set; verifies the `parent_version` chain back to genesis (or genesis itself); verifies the static analyzer accepts the Cedar+ source under the pinned `schema_version`.
- **Activate.** Persists the loaded constitution; emits a `constitution.activate` receipt; transitions the swarm's `Swarm.constitution_version` attribute.
- **Evaluate.** Accepts a `(principal, action, resource, context)` quadruple per the schema; runs the compiled decision tree; produces a permit/forbid decision plus matched-rule evidence; emits a `constitution.evaluate.pass` or `constitution.evaluate.deny` receipt with the evidence inline.
- **Default-deny.** Empty policy sets, ambiguous matches, or evaluator errors deny rather than permit. Every deny carries an explicit reason.
- **Bounded evaluation.** Refuses to evaluate beyond the statically-proven depth bound from the analyzer. Runtime depth-exceeded is a deny with reason `evaluation_depth_exceeded`.
- **Static analyzer integration.** The compiler MUST refuse Cedar+ source that violates the structural constraints (no loops, no I/O, no mutation, bounded depth). The analyzer's reject set is part of the conformance suite.
- **Schema version honored.** Evaluator loads schema at the constitution's pinned version per §5.
- **Receipt determinism.** Same inputs (constitution + action + context) MUST produce identical decision + evidence + receipt content-address across implementations.

`/conformance/interface/language/` will house the test cases (added in F2-F4 alongside the extension specs); the analyzer sub-suite tests the structural-constraint rejection set with adversarial Cedar+ programs (Workstream L red-team activity per build-plan §7.4).

## 8. Open questions for RFC review

The following are open at F1; closure is expected during the public review window for RFC 0010, or deferred to the indicated downstream RFC:

- **Test-case generation quality.** LLM-generated test cases (Layer 1 → Cedar+) need empirical evaluation before they can be relied upon for safety claims. Phase 2 includes a study; design partners contribute corpus.
- **Canonical schema scope at v1.0 launch.** Minimum proposed: `support-queue` (S1), `incident-response` (S3), plus three topology-mode baselines (closed/open/hybrid). Is this the right initial set, or should `campaign-mode` and one more workload land in v1.0? Decision lands in F8 (canonical-schema authoring sub-stage).
- **Cross-swarm policy references.** v1.0 evaluators MAY refuse such policies; should v1.0 evaluators MUST refuse? Decision deferred to RFC 0012 (evaluation model).
- **Internationalization of Layer 1.** English-first at v1; multilingual authoring is a Phase 3 commitment. The schema layer is language-neutral and not affected.
- **Rego compatibility shim.** A one-way Rego-to-Cedar+ converter as a migration aid for teams with existing OPA policy. Deferred — out of v1.0 scope.

## 9. Future evolution

- **v1.1 — landed in RFC 0011.** Two engine-construct capabilities (scoring rules and procedures, both as separate engine-config artifacts — NOT Cedar language extensions) plus two schema-pattern capabilities (resource budgets and memory norms — stock Cedar over new schema vocabulary). The base schema bumped to v1.1.0 with the `Memory` entity, budget attributes on `Agent`, and three memory action types. The `Tool` entity remains reserved (no actions take it as a target at v1.1).
- **v1.x** adds the four-stage enforcement loop (RFC 0013) — `DetectViolation`, `CoachAgent`, `QuarantineAgent`, `EvictAgent` actions; integration with capability revocation; supervisor-tree integration.
- **v1.x** adds the LLM authoring CLI's Cedar+ output contract (the CLI is a build-time tool, but its output must satisfy the schema, so the contract belongs in the spec layer).
- **v2.0** likely revisits the schema-authoring restriction if operator demand for fully-bespoke schemas materializes and `yutha-cedar-plus` exposes a marshaller-discovery interface that makes them safe to honor.

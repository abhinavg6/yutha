# Constitution and enforcement

A **constitution** is the swarm's norms — written down, signed, content-addressed, and evaluated on every consequential action. It says, declaratively and uniformly, what the swarm permits, forbids, and prefers; under what conditions; by which principals. The control plane runs an evaluation against the active constitution before any envelope leaves the wire. Denials produce signed receipts; patterns of denials walk a four-stage enforcement loop.

The constitution sits next to — not inside — each agent's prompt, model, or framework, which is the whole point. Norms enforced from the substrate apply identically to a LangGraph agent, a CrewAI crew, an OpenAI Agents handoff, or anything else you bring through the adapter layer. Frameworks change; the constitution doesn't. And because it's an artifact and not a piece of code, it's reviewable by people who don't write Rust or Python — a compliance officer, a security lead, an engineering manager. They read the same Cedar+ source the analyzer reads and the evaluator runs.

## Cedar+ — the language

Constitutions are written in **Cedar+**, which is [AWS's Cedar policy language](https://github.com/cedar-policy) plus a small set of Yutha-specific additions. Cedar was the right starting point for two reasons that matter more than they sound.

It has a published formal semantics — every policy provably terminates within a static depth bound, and Cedar's analyzer can prove correctness properties (equivalence, satisfiability, type-checking against a schema) without running the policy. And its `permit` / `forbid` plus `when` shape maps cleanly onto the question we actually want answered at every gated action: *should this principal be allowed to do this thing right now, in this context?*

Rolling our own DSL was considered and rejected. A bespoke language means a bespoke analyzer, bespoke decidability proofs, bespoke tooling, and a bespoke security audit — all of which exist for Cedar already, and none of which Yutha as a project is qualified to do better. We depend on the unmodified `cedar-policy` Rust crate; we do not fork. That's the load-bearing decision.

Authoring is three-layered.

A plain-English DSL sits at the front door for non-engineers — it compiles to Cedar+ at build time, never at evaluation time. The Cedar+ source itself is canonical; reviewers read it, the static analyzer verifies it. The compiled decision tree is what the engine actually runs at request time.

The LLM that helps translate from plain English to Cedar+ is a build-time convenience only; it is never on the request path. A build-time invariant test verifies the LLM is structurally unreachable from the evaluator. This matters for the threat model — a deceptive policy author (or a deceptive LLM) cannot produce a constitution that defeats the analyzer's checks, because the analyzer is the security boundary and runs on every artifact regardless of who or what wrote it.

The "+" is four capabilities that sit on top of stock Cedar without weakening any of its properties:

- **Scoring rules.** Soft preferences — *prefer* high-reputation agents for sensitive cases, *prefer* certain routing on weekdays, *prefer not* a particular pattern without forbidding it outright. Each rule contributes a decimal weight to a permitted decision; downstream consumers (dispatchers, schedulers, ranking heuristics) use the total as a tie-breaker. Scores never override a `forbid` — the dispatcher can't rank a forbidden action above a permitted one — and the contributions land in the receipt's evidence so the ranking is auditable. A support-queue swarm uses scoring to route a high-value case to a senior agent without making it an outright requirement: *prefer score 2.0 when principal.reputation > 0.8 and resource.tags.contains("sensitive").*

- **Procedures.** Declarative state machines for multi-step approvals: refund over a threshold enters `pending_supervisor_approval`, transitions to `approved` on the supervisor's countersign or `timed_out` after one hour, escalates to a `manual_review` procedure if it times out. Each transition is its own receipt; the entire approval chain — who triggered, who approved, when, under which constitution version — is reconstructable end-to-end from the audit log alone. Procedures are an engine construct, not a Cedar language extension; the underlying expressions stay stock Cedar.

- **Resource budgets.** Wall-clock, quota, and dollar-bounded permissions. The control plane synthesizes each agent's remaining budget into the action context; a Cedar `forbid when principal.budget_remaining_usd_cents < context.estimated_cost_usd_cents` does the rest. Budgets are a schema pattern, not a runtime extension — no engine-side state, no risk to decidability. An AP/invoice swarm uses this to cap the auto-approver's daily payment authority without baking the number into agent code.

- **Memory norms.** Guards on what an agent may read, write, or share from swarm memory. The schema declares a `Memory` entity type with `owner`, `scope`, and `tags`; policies write idioms like *forbid writing PII to external scope, ever* or *forbid sharing PII out of swarm scope unless principal is compliance* in straight Cedar. Memory operations get their own evaluation alongside envelope sends — same evaluator, same receipt shape, same audit trail.

Scoring rules and procedures are *engine constructs* — authors write a stock Cedar policy file plus an engine-config artifact (YAML or protobuf) that the engine loads alongside the policy. Budgets and memory norms are *schema patterns* — authors write only Cedar, against new vocabulary the v1.1 schema declares.

Either way, Cedar's parser, analyzer, and proofs stay untouched. "Cedar+" is the Yutha stack as a whole; it is not a fork of Cedar. That distinction matters when Cedar evolves — we pick up new versions without rebasing a fork, and our additions never block on an upstream language change.

For the spec, see [`/spec/constitution/extensions.md`](https://github.com/abhinavg6/yutha/blob/main/spec/constitution/extensions.md) and [RFC 0011](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0011-cedar-plus-extensions.md).

## How evaluation works

Every `EnvelopeService.Send` runs a constitution evaluation server-side, before the envelope is signed and shipped. Capability and memory operations get evaluated the same way. The evaluator is a pure function of its inputs — no I/O, no network calls, no race conditions — so two runs against the same inputs produce byte-identical receipts. This is the property that makes the audit trail meaningful: same constitution + same request → same decision + same evidence + same content-addressed receipt, on any implementation.

Per request, the control plane synthesizes a snapshot of the entities the evaluator will be allowed to see. That includes the sending agent's passport (id, tier, framework, reputation, remaining budgets); the swarm entity (topology mode, active constitution version); any capability the sender presented; the envelope's recipient, performative, payload schema, and tags.

That snapshot plus the action's context attributes is what the evaluator sees. It cannot reach back into the registry, the capability store, or the memory layer mid-evaluation — those were all consulted up front. The closed-over-its-inputs property is what makes evaluation auditable: anything the policy reasoned about is captured in the receipt's evidence digest.

Evaluation runs in two layers, in order.

**Layer A** is stock `cedar-policy`: it runs `permit` and `forbid` rules and returns `Allow` or `Deny`. If Layer A denies, the request fails closed with a `constitution.evaluate.deny` receipt carrying the matched forbid rule id (or `no_permit_rule` if no rule matched at all).

**Layer B** is the engine — it only runs when Layer A allowed — and iterates scoring rules in declaration order, matches procedure triggers, fires procedure transitions, and schedules timeouts.

A permit lands as `constitution.evaluate.pass` with score contributions and procedure effects in the evidence. Procedure lifecycle events emit their own receipts — `procedure.enter`, `procedure.transition`, `procedure.timeout`, `procedure.escalate` — each causally linked to the evaluation that produced it.

Procedure instance state is reconstructable from this stream alone. The engine maintains an index for performance, but tearing the index down and rebuilding it from receipts produces an identical state. There is no authoritative state outside the receipt log.

Both layers run inside a sandbox. The hot-path (`SendEnvelope`) gets a 10ms wall-clock cap; everything else gets 100ms. Entity stores cap at 1,000 entities, policy depth at 16, open procedure instances at 100. Bound-exceeded fails closed with a specific `deny_reason`.

The bounds are runtime safety nets — Cedar's analyzer already proves bounded depth statically, so a well-formed constitution shouldn't approach them. The limits exist to defend against pathological inputs (huge entity sets, malformed contexts) that pass the analyzer but blow up at eval time, and to give operators a knob if a particular workload demands tighter or looser ceilings.

Default-deny is the bias on every error path. Empty policy sets, ambiguous matches, type errors, missing entities, evaluator panics — all deny, all surface an explicit reason in the receipt. There is no silent failure and no implicit permit, because either of those would weaken the audit trail's primary claim: *everything consequential that happened is in the log, with its decision visible*.

Spec: [`/spec/constitution/evaluation.md`](https://github.com/abhinavg6/yutha/blob/main/spec/constitution/evaluation.md) and [RFC 0012](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0012-evaluation-model-and-sandbox.md).

## The four-stage enforcement loop

A single denied action might be a bug, a confused prompt, or a perfectly reasonable speculative attempt. A pattern of denied actions is a different signal entirely.

The constitution layer responds to single denials with `constitution.evaluate.deny`. The **enforcement loop** is what responds, mechanically and progressively, when a pattern develops.

The enforcement engine is itself receipt-driven. It subscribes to the receipt stream, pattern-matches against the rules declared in the constitution's engine-config (*N denies of forbid rule X within window W, grouped by principal*, or *single critical-severity event*, or *cross-receipt sequence*), and fires stage transitions when a pattern completes. Each stage transition is itself a signed receipt that the capability layer, registry, and supervisor layer observe and apply.

It has four stages:

- **Detect.** A pattern fires — for instance, three denies of the same forbid rule within ten minutes, grouped by principal. Mechanically almost nothing changes. The `enforcement.detect` receipt lands, the agent's reputation moves slightly, the operator dashboard surfaces the signal. The agent under detection observes nothing different yet; this is a cooldown window during which the operator can intervene before the agent sees feedback.

- **Coach.** After a cooldown — defaults to 30 seconds — the engine emits an `ADVISE` envelope to the agent's inbox: *your action was denied because of rule X; here's the relevant guidance.* The envelope is a normal envelope that produces its own send/deliver receipts; the coaching is part of the audit trail. Coach is non-punitive by default — reputation barely moves — and is the operator's chance to teach an agent that's just confused before any consequential effect lands.

- **Quarantine.** If the pattern persists past coach, the engine emits `enforcement.quarantine`. The agent's existing capabilities are *not* revoked — that would be operationally noisy and would force re-issuance on reverse — but the capability layer's check pathway now consults quarantine state and denies the agent's actions with `subject_quarantined`. New capability issuance to the agent is also refused. The agent's subscribe streams stay open; they receive envelopes but can't act on them. The intent is reversibility: a quarantined agent is paused, not removed.

- **Evict.** If quarantine doesn't restore compliance, `enforcement.evict` fires. This is the terminal, irreversible stage. The engine internally calls `AdmissionService.OperatorRevoke` with `cascade_capabilities=true`, which lands an `agent.operator_revoke` receipt, revokes every capability the agent held, tears down their subscribe streams within tens of milliseconds, and adds them to the deregistration list. Eviction by default requires a supervisor-tier countersign — a hard structural requirement, not a soft policy check. The receipt is malformed without the second signature and the registry refuses to apply it. To re-admit an evicted agent, an operator registers them with a fresh passport (new agent_id; the old one is gone) and starts over.

Why four stages and not a binary allow/deny? Because the alternative — straight to eviction on any pattern — is operationally untenable. Real swarms have agents that misfire, prompts that need adjusting, and operators who'd rather coach than evict.

Detect-and-coach gives the operator a window to intervene before any consequential effect lands on the agent. Quarantine gives a reversible operational state that doesn't force capability re-issuance on the reverse path. Eviction is the floor when nothing else worked. Each stage corresponds to a different operational posture, and each is appropriate to a different signal.

The loop is **reversible** at every non-terminal stage. An `enforcement.reverse` receipt — manual via operator RPC, or automatic via a rule-defined condition like quarantine expiry or reputation recovery above threshold — winds the agent back a stage and partially restores reputation.

Reversal is intentionally not fully symmetric: a small residue remains on the agent's reputation after every reverse, so that rapid trigger-and-reverse cycles don't game the system. The intermediate stages also remain in the audit trail — the receipt fabric never rewrites, so a coached-then-reversed agent's history shows both the coach and the reverse.

**Reputation** is a decimal scalar per agent that the supervisor layer computes from the enforcement receipts themselves — there's no separate store. Each `enforcement.*` receipt carries a `reputation_delta` field; cold-start reconstruction sums them.

Reputation feeds back into constitution evaluation — Cedar can read `principal.reputation` and forbid sensitive actions for low-reputation agents, scoring rules can prefer high-reputation ones for high-stakes routing. The same receipt fabric that holds the audit trail is what the policy reasons over. That symmetry is the structural reason the audit log and the policy engine can't drift out of sync.

**Topology shapes the defaults.** Closed swarms — operator-vetted agents only — favor slow escalation with supervisor countersign at every stage, indefinite quarantine until explicit reverse, eviction rare. Open swarms — public participation gated by sybil-resistance — favor fast escalation, short cooldowns, auto-expiring quarantine, eviction as the common terminal outcome.

Hybrid swarms apply closed defaults to trusted-core agents and open defaults to periphery. The concrete numbers ship in canonical schemas under `/spec/constitution/canonical-schemas/`, so operators tune by amending the schema reference rather than rewriting policy.

**Operators can intervene at any non-terminal stage.** A manually-fired `enforcement.reverse` carries an operator signature in the receipt evidence; the audit trail records who overrode what and why (the `reason` field is free-form).

The structural guarantee is that intervention is *visible* — there's no hidden override path. Eviction itself can be manually triggered before the rule's normal escalation timer fires, but the supervisor countersign requirement still holds.

Spec: [`/spec/constitution/enforcement.md`](https://github.com/abhinavg6/yutha/blob/main/spec/constitution/enforcement.md) and [RFC 0013](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0013-four-stage-enforcement-loop.md).

## A worked example

The [code-review crew demo](../examples/code-review.md) ships a constitution that forbids any envelope tagged with *both* `patch_applied` and `security_sensitive` — i.e. *"the auto-fix agent must not claim to have patched a security-sensitive file."* The Cedar policy, from [`sdks/python/examples/code_review.py`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/examples/code_review.py):

```cedar
@id("no-security-patches-from-auto-fix")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
) when {
    context.tags.contains("security_sensitive") &&
    context.tags.contains("patch_applied")
};

permit (principal, action, resource);
```

The matching enforcement rule says: two `constitution.evaluate.deny` receipts within sixty seconds, grouped by principal, fire `enforcement.detect`. Coach lands one second later, quarantine one second after that, evict one second after that. The 1-second cooldowns are demo-tight — real swarms set them to minutes or hours so operators have time to intervene — but the chain is the same shape.

The demo plays this out end-to-end. The reviewer fans out one happy-path PR (README typo, no sensitive tag — auto-fix processes it normally) and one sensitive PR (crypto file — routes to the human approver, never reaches auto-fix). Then the auto-fix agent attempts the forbidden combination twice.

The first attempt lands a `constitution.evaluate.deny` with `deny_reason: forbid_rule_matched` and the matched rule id. The second attempt lands a second deny — and crosses the enforcement threshold.

Within a few seconds the demo polls and sees `enforcement.detect`, `enforcement.coach`, and `enforcement.quarantine` land in order. A subsequent capability check confirms the agent's still-valid send cap now denies with `subject_quarantined` — the cap layer is consulting the quarantine state, exactly the spec'd behavior. Then `enforcement.evict` lands, the agent's streams tear down, and the audit trail shows the full chain.

The demo's expected audit delta is precisely defined: 3 register receipts, 1 constitution activate, 3 successful sends + deliveries, 3 constitution passes, 2 denies, 1 capability issue, 3 cap checks that pass, 1 cap check that denies (the post-quarantine one), and 1 each of detect, coach, quarantine, evict.

Every consequential action leaves a receipt; every receipt is signed and content-addressed; the whole trace is replayable. If you re-run the demo against a clean control plane, you get an identical delta — that's the determinism guarantee in practice. And the same enforcement chain shape appears in the other demos: the AP/invoice demo's over-cap payment attempts walk the same stages, the DevOps demo's missing-countersign attempts walk the same stages. One mechanism, applied to each swarm's specific norms.

## What constitutions don't do

A few things the constitution layer is deliberately not.

It is **not a substitute for typed validation in agent code.** If your agent computes a refund amount, the type system and your business logic catch overflow and negative values. The constitution gates whether the refund *send* is permitted, not whether the math is correct. These are complementary concerns and should stay in separate layers.

It is **not a place to encode business logic.** "Compute the discount" or "categorize this ticket" are framework-side concerns; the constitution lives at the substrate, where the question is always *should this action proceed, by this principal, under these conditions?* Pushing business logic into Cedar makes the policy unreviewable and the substrate brittle.

It is **not a circuit breaker for prompt injection.** A prompt-injected agent may still attempt forbidden actions; the constitution's job is to make sure those attempts are caught at the wire, surfaced as receipts, and walked through enforcement if the pattern persists. The constitution governs what the substrate lets through, not what the model decides to try.

And it is **not the only line of defense.** Capabilities answer *does this principal have authority?* and constitutions answer *given the principal has authority, do the swarm's norms permit this exercise of it right now?* Both layers run on every consequential action; either failure denies. The capability layer's caveats (rate limits, time windows, supervisor-required gates) are a separate decidable surface that the constitution layer can read but not modify. Defense in depth is structural, not a slogan.

## Where to go next

- [`/spec/constitution/`](https://github.com/abhinavg6/yutha/tree/main/spec/constitution) — the schema, rationale, extensions, evaluation model, and enforcement contract as specs.
- [RFCs 0010 through 0013](../reference/rfcs.md) — the design decisions behind the constitution language, the Cedar+ extensions, the evaluation model, and the four-stage enforcement loop.
- [Operator → Authoring constitutions](../operator/authoring-constitutions.md) — the plain-English DSL that compiles to Cedar+, plus testing and rollout guidance.
- [Examples](../examples/index.md) — five runnable end-to-end demos. The [code-review](../examples/code-review.md), [AP & invoice](../examples/ap-invoice.md), [research crew](../examples/research-crew.md), and [DevOps incident](../examples/devops-incident.md) walkthroughs each exercise a real Cedar+ constitution.

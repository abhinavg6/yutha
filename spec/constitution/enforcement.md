# Constitution Enforcement — Four-Stage Loop Specification (v1.1)

> **Spec:** [`schema.cedarschema`](./schema.cedarschema), [`extensions.md`](./extensions.md), [`evaluation.md`](./evaluation.md)
> **RFC:** [0013](../rfcs/0013-four-stage-enforcement-loop.md)
> **Predecessors:** [RFC 0010](../rfcs/0010-constitution-language-v1.md), [RFC 0011](../rfcs/0011-cedar-plus-extensions.md), [RFC 0012](../rfcs/0012-evaluation-model-and-sandbox.md), [RFC 0009](../rfcs/0009-operator-credentials.md) (substrate primitive eviction calls into)
> **Phase:** 2

## 0. Scope

This document specifies how a Yutha swarm enforces its constitution beyond simple per-request deny. Single-shot deny (`constitution.evaluate.deny`) tells an agent "this specific action was refused"; the **enforcement loop** is what tells the swarm "this agent has a pattern of denied actions worth responding to" — and what mechanically responds at four escalating levels: detect, coach, quarantine, evict.

What this document does NOT specify: the *implementation* of the enforcement watcher (a subsystem of the constitution engine that subscribes to the receipt stream and fires enforcement actions). What it specifies is the contract every conformant implementation honors — same constitution + same receipt history → same enforcement actions and same audit trail.

The companion RFC ([0013](../rfcs/0013-four-stage-enforcement-loop.md)) is the document of record for these decisions.

---

## 1. The enforcement contract

A single enforcement loop is a four-stage progression:

```
              ┌─────────────────────────────────────────────────────┐
              │ Receipt stream                                      │
              │   ↓ constitution.evaluate.deny receipts             │
              │   ↓ (and other receipt-kind triggers)               │
              │                                                     │
              │   Enforcement engine — pattern-matches per rule     │
              │                                                     │
              │   ┌───────┐    ┌───────┐    ┌────────────┐  ┌─────┐ │
              │   │ detect│ →  │ coach │ →  │ quarantine │ →│evict│ │
              │   └───────┘    └───────┘    └────────────┘  └─────┘ │
              │       ↑            ↑             ↑              ↓   │
              │       └────────────┴─── reverse ─┘              │   │
              │                                                 │   │
              │   each stage emits a receipt; cap layer +       │   │
              │   registry observe and apply the mechanical     │   │
              │   effect; reputation moves per stage delta      │   │
              └─────────────────────────────────────────────────┴───┘
```

Five concrete properties:

1. **Receipt-driven.** The enforcement engine doesn't poll agents or query mutable state. It subscribes to the receipt stream, pattern-matches on receipt content, and fires enforcement actions. The stream is its only input.

2. **Stage receipts are first-class.** Every stage transition emits a signed receipt (`enforcement.detect`, `enforcement.coach`, `enforcement.quarantine`, `enforcement.evict`, `enforcement.reverse`). The cap layer, the registry, and the supervisor layer all subscribe to these and apply their mechanical effects.

3. **Stages are advance-only by default; reversal is explicit.** An agent can move detect → coach → quarantine → evict (or skip stages if the constitution says to), but reverting requires an explicit `enforcement.reverse` receipt — itself constitution-gated. There is no implicit "the agent has been good for a while, drop them back" path in v1.1; that's a future refinement.

4. **Composes with substrate primitives.** Quarantine layers on top of the capability system (the cap layer denies quarantined agents). Eviction layers on top of operator-revoke (RFC 0009; calls `AdmissionService.OperatorRevoke` with `cascade=true`). The enforcement engine is a coordinator that drives existing primitives — it does NOT introduce a parallel revocation system.

5. **Topology-aware defaults.** Closed swarms favor slow escalation with supervisor countersign at every stage transition; open swarms favor faster escalation with less ceremony; hybrid swarms mix. Specific numbers ship in F8 canonical-schemas (`/spec/constitution/canonical-schemas/`); this document specifies the hook points.

---

## 2. Stage 1: Detect

### 2.1 Trigger

The enforcement engine subscribes to the receipt stream. For each receipt landing, it checks every `enforcement_rules:` entry in the active constitution's engine config to see if the receipt completes a pattern that should fire a `detect`. Typical patterns:

- **N denies of a specific forbid rule, within window W.** "3 denies of `no_pii_to_external` within 10 minutes, grouped by principal."
- **N denies of a deny-reason class, within window W.** "5 `evaluation_time_exceeded` denies within 1 minute" (signals an agent attempting DoS).
- **Single high-severity event.** "Any `capability.check.deny` with a `forbid_rule_id` flagged `severity: critical` in the rule's metadata."
- **Cross-receipt sequences.** "An `envelope.send` followed by `capability.check.deny` for the same envelope within 100ms" (signals an agent racing the capability layer).

### 2.2 What "detect" actually does

Mechanically, almost nothing. The `enforcement.detect` receipt lands; the cap layer, registry, and other subsystems take no action *yet*. Detection is a signal to:

- The enforcement engine itself — start the cooldown timer before escalating to coach.
- The supervisor layer — increment the per-agent detection counter for the reputation scalar.
- The receipt-driven audit pipeline — surface the detection in operator dashboards.

The agent under detection observes nothing different until coach lands.

### 2.3 Receipt evidence

```
action_kind: enforcement.detect
actor:       Control plane (the enforcement engine)
evidence: {
    enforcement_rule_id: <rule name>,
    target_agent_id: <agent under enforcement>,
    matched_receipt_ids: [<receipt hashes that completed the pattern>],
    pattern_summary: <human-readable, e.g. "3 denies of forbid_pii in 10m">,
    constitution_hash: <hash>,
    reputation_delta: <Decimal, typically small negative>,
}
```

### 2.4 What can NOT trigger detect

- A single `constitution.evaluate.deny` does NOT auto-detect. Single denies are normal and expected (e.g., an agent attempting an action they don't have authority for, getting denied, then taking an authorized path). Detection requires a pattern.
- A receipt that pre-dates the current constitution version does NOT trigger detect rules added in a newer constitution version. Patterns are evaluated against receipts emitted under the constitution version the rule was authored in (or, for explicit cross-version detection, the rule MUST opt in via a `historical: true` flag — out of v1.1 scope).

---

## 3. Stage 2: Coach

### 3.1 Trigger

Coach fires after a `detect` lands and a cooldown elapses without a `reverse`. Cooldown is rule-defined; default is 30 seconds. The cooldown gives the operator a chance to intervene (cancel the detect via reverse) before the agent sees feedback.

### 3.2 What "coach" actually does

The enforcement engine emits an envelope of performative `ADVISE` to the offending agent's inbox. The envelope's payload carries:

- A human-readable explanation: "Your action X was denied because Y."
- The matched receipt evidence digest (so the agent can audit).
- Operator-defined remediation guidance, if the rule provides a `coach.guidance_template`.

The envelope is a normal envelope routed through `EnvelopeService` — it carries an `envelope.send` + `envelope.deliver` receipt pair like any other message. Its `from_agent` is the control plane's own AgentId (per `/spec/passport/rationale.md` §4 — the control plane has a registered agent identity for the receipts it produces).

### 3.3 Reversal of coach

Coach is fully reversible by `enforcement.reverse` at any time. The agent's reputation is restored. The coaching envelope they received remains in the audit trail; the receipt fabric never rewrites.

### 3.4 Receipt evidence

```
action_kind: enforcement.coach
actor:       Control plane
evidence: {
    enforcement_rule_id: <rule name>,
    target_agent_id: <agent>,
    detect_receipt_id: <hash of the predecessor enforcement.detect>,
    coaching_envelope_id: <envelope.send receipt id for the ADVISE envelope>,
    constitution_hash: <hash>,
    reputation_delta: <Decimal, often 0.0 — coach itself is non-punitive>,
}
```

The `coaching_envelope_id` lets downstream auditors trace from "this agent received coaching" back to "here's exactly what was said."

---

## 4. Stage 3: Quarantine

### 4.1 Trigger

Quarantine fires after a `coach` lands and a longer cooldown elapses without compliance. Compliance is rule-defined; typical specifications:

- "No more `forbid_pii_to_external` denies for 5 minutes after coach."
- "Reputation scalar recovers above threshold T."
- "Operator explicitly clears the detect."

The rule's `escalate_after` field defines the cooldown if compliance isn't observed. Default: 5 minutes.

### 4.2 What "quarantine" actually does

Two mechanical effects:

1. **The agent's existing capabilities are NOT revoked.** Quarantine is reversible by design; revoking caps would force re-issuance on reverse, which is operationally noisy. Instead, the cap layer's check pathway consults the agent's quarantine state (read from the most recent `enforcement.quarantine` / `enforcement.reverse` receipt for the agent) and denies if the agent is currently quarantined. Quarantined agents fail capability checks; their sends, memory operations, and other gated actions deny with `agent_quarantined`.

2. **New capability issuance to the quarantined agent is refused.** `CapabilityService.Issue` and `CapabilityService.Attenuate` consult the same state and refuse to mint new caps where the subject is quarantined.

What quarantine does NOT block:

- The agent's existing subscribe streams stay open. They continue to receive envelopes addressed to them. (They just can't act on them.)
- They can self-revoke via `AdmissionService.Revoke` — useful if they want to leave the swarm cleanly.
- The supervisor can countersign a reversal at any time.

The intent is reversibility: a quarantined agent is paused, not removed. If the quarantine was a false positive, the operator reverses and the agent resumes.

### 4.3 Reversal of quarantine

`enforcement.reverse` lifts the quarantine. The agent's `is_quarantined` state flips back; the cap layer resumes accepting their checks; new issuances are permitted again. Reputation is partially restored per rule-defined delta.

### 4.4 Receipt evidence

```
action_kind: enforcement.quarantine
actor:       Control plane
evidence: {
    enforcement_rule_id: <rule name>,
    target_agent_id: <agent>,
    coach_receipt_id: <hash of predecessor enforcement.coach, if any — may be absent if rule allows skip>,
    expires_at_wall_clock: <RFC 3339 — optional; absent means indefinite>,
    constitution_hash: <hash>,
    reputation_delta: <Decimal, larger negative>,
}
```

The optional `expires_at_wall_clock` enables auto-reversal: when wall-clock advances past it, the engine emits an `enforcement.reverse` automatically. Absent → quarantine is indefinite until explicit reverse.

---

## 5. Stage 4: Evict

### 5.1 Trigger

Eviction is the irreversible terminal stage. It fires when:

- A constitution rule explicitly escalates from quarantine after a defined window without compliance.
- An operator manually escalates (via a control-plane RPC that emits the enforcement.evict + the substrate operator_revoke; see §5.3).
- A rule with severity flag `auto_evict: true` matches (rare; reserved for blatant violations like attempting to forge another agent's signature).

### 5.2 Required countersign

`enforcement.evict` requires a **supervisor countersign** by default (per `/spec/receipt/canonical-actions.md` note: "Highest-stakes; supervisor countersign required."). Mechanically: the receipt carries a second signature from a supervisor-tier agent (passport tier `supervisor` or higher). Without the countersign, the receipt is malformed and the registry refuses to apply the eviction.

The constitution MAY relax the countersign requirement for specific rules (e.g., `auto_evict: true` rules may waive countersign), but the relaxation must be opt-in per rule, not a global default.

### 5.3 What "evict" actually does

The enforcement engine internally calls `AdmissionService.OperatorRevoke` with `cascade_capabilities=true` (RFC 0009 §3.2). This:

- Lands an `agent.operator_revoke` receipt for the target.
- Lands per-capability `capability.revoke` receipts for every cap the target held.
- Marks the agent in the revoked-set (RFC 0009 §3.3); active subscribe streams tear down within tens of milliseconds.
- Adds the target to the registry's deregistration list.

The `enforcement.evict` receipt is a meta-receipt that wraps these substrate effects. Its `causal_predecessors` field includes the resulting `agent.operator_revoke` receipt id, making the audit trail traceable.

### 5.4 Irreversibility

Eviction is not reversible by `enforcement.reverse`. The substrate operations (revoke, cascade) are themselves irreversible per RFC 0009. To re-admit an evicted agent, an operator must:

1. Have the agent register a fresh passport (new agent_id; the old one is deregistered).
2. Pass the swarm's admission policy.
3. Be re-issued capabilities from scratch.

This is the "evicted agent comes back" path; it's not strictly reversal — it's re-admission of what is, by identifier, a new agent.

### 5.5 Receipt evidence

```
action_kind: enforcement.evict
actor:       Control plane
evidence: {
    enforcement_rule_id: <rule name>,
    target_agent_id: <agent>,
    quarantine_receipt_id: <hash of predecessor enforcement.quarantine, if any>,
    substrate_revoke_receipt_id: <hash of the agent.operator_revoke receipt this evict drove>,
    cascade_revoke_receipt_ids: [<hashes of cap-revoke receipts>],
    constitution_hash: <hash>,
    reputation_delta: <Decimal, very large negative or sentinel reset value>,
    supervisor_countersign: <signature by a supervisor-tier agent on this receipt's canonical bytes>,
}
```

---

## 6. Reversal semantics

`enforcement.reverse` undoes a non-terminal enforcement stage. Constraints:

- Reverse MAY undo `detect`, `coach`, or `quarantine`. Reverse MAY NOT undo `evict` — see §5.4.
- A reverse SHOULD reference its target receipt (the stage it's reversing) via `causal_predecessors`.
- A reverse landed during cooldown short-circuits the escalation: the next stage does not fire.
- A reverse landed AFTER escalation has already fired only undoes the most recent stage; intermediate stages remain in the audit trail.
- Reverse can be triggered manually (operator action via RPC) or automatically (rule-defined `auto_reverse_when` condition; default conditions: quarantine expiry, reputation recovery above threshold).

Reversal MAY be partial: the constitution can specify `reputation_delta_on_reverse` separate from the original stage delta, so a reversed enforcement leaves some "this happened" residue on the agent's reputation. This is important for repeat-offender detection — a fully-symmetric reverse (undo all reputation impact) would let agents game the system by triggering then reversing rapidly.

### 6.1 Receipt evidence

```
action_kind: enforcement.reverse
actor:       Control plane (or operator-bearer agent for manual reversals)
evidence: {
    enforcement_rule_id: <rule name>,
    target_agent_id: <agent>,
    reversed_receipt_id: <hash of the stage being reversed>,
    reversed_stage: "detect" | "coach" | "quarantine",
    reason: <free-form string; e.g. "false positive — operator override">,
    constitution_hash: <hash>,
    reputation_delta: <Decimal, typically positive (partial restoration)>,
    operator_signature: <when manually triggered by an operator-bearer agent>,
}
```

---

## 7. Reputation scalar dynamics

`Agent.reputation: Decimal` was admitted in the v1.0 schema (RFC 0010 §3.1) specifically so this section could exist without a schema bump.

### 7.1 Computation model

The supervisor layer maintains the running reputation scalar per agent. The scalar is computed entirely from the receipt log — there is no parallel state store. Each enforcement receipt carries a `reputation_delta` field; the supervisor sums them.

Pseudocode for cold-start reconstruction:

```
reputation = INITIAL_REPUTATION  // typically 1.0
for receipt in receipts.query(action_kind in {enforcement.*}, target_agent_id == agent).order_by(occurred_at_unix_ns):
    reputation += receipt.evidence.reputation_delta
    reputation = clamp(reputation, MIN_REPUTATION, MAX_REPUTATION)
```

Common bounds: `MIN_REPUTATION = 0.0`, `MAX_REPUTATION = 1.0`, `INITIAL_REPUTATION = 1.0` (newly-admitted agents start with full reputation).

### 7.2 Default deltas

Per-stage defaults; rules MAY override per-rule:

| Stage | Default delta | Rationale |
|-------|---------------|-----------|
| detect | -0.05 | Small flag; multiple detects accumulate. |
| coach | 0.0 | Coaching is non-punitive — it's feedback, not penalty. |
| quarantine | -0.25 | Larger penalty; quarantine is a real operational consequence. |
| evict | -1.0 (or set to 0.0 directly) | Terminal. Implementations MAY clamp to 0 rather than apply the delta. |
| reverse (post-detect) | +0.05 | Full restoration. |
| reverse (post-coach) | +0.0 | Nothing to restore. |
| reverse (post-quarantine) | +0.15 | Partial — 0.10 residue remains for repeat-offender detection. |

These are spec defaults. Constitution rules pin specific deltas inline; canonical-schemas (F8) ship workload-appropriate values.

### 7.3 Reputation as a policy input

Once Cedar evaluates with `principal.reputation`, the constitution can gate behavior on reputation directly:

```cedar
// Forbid sensitive actions for low-reputation agents.
forbid (principal, action == Action::"SendEnvelope", resource)
when { principal.reputation < 0.3 && resource.tags.contains("sensitive") };
```

And scoring rules can rank by reputation:

```yaml
scoring_rules:
  - name: prefer_high_reputation
    score: 1.0
    head: { action: AssignCase }
    when: 'principal.reputation > 0.8'
```

The control plane synthesizes `principal.reputation` into the action entity at evaluation time from the supervisor layer's cached value (which is itself a materialized view over the enforcement receipts).

---

## 8. Supervisor tree integration

### 8.1 What is the supervisor tree

In v1.1 the "supervisor tree" is a simple two-tier structure: every agent has a passport `tier` (per `/spec/passport/`); some tiers can supervise others. The default tier ordering, lowest to highest: `minimal`, `standard`, `supervisor`, `compliance`. Operators MAY define additional tiers via signed schema delta per RFC 0010 §3.4.

A `supervisor`-tier (or higher) agent can:

- Countersign enforcement receipts that require it (eviction by default).
- Issue capabilities to lower-tier agents (subject to constitution rules).
- Trigger manual `enforcement.reverse` for agents they supervise.

There is no explicit "this supervisor supervises that agent" linkage in v1.1 — the tree is flat (any supervisor-tier agent can countersign for any agent in the swarm). Per-agent supervisor pairing is a future refinement.

### 8.2 Countersign mechanics

Per `/spec/receipt/rationale.md` §3, receipts can carry multiple signatures from different signing roles. The eviction countersign uses this:

1. The enforcement engine produces an `enforcement.evict` receipt; signs it with the control plane's key (the "Actor" role per receipt spec).
2. The receipt remains in a pending state — not yet appended to the receipt log.
3. The engine requests a countersign from a supervisor-tier agent. The supervisor agent reviews and signs the receipt's canonical bytes (the "Supervisor" role).
4. With both signatures, the receipt is appended. The cap layer + registry honor the eviction.
5. If no supervisor countersigns within a timeout (default 1 hour), the pending receipt is abandoned with an `enforcement.evict_timeout` event in the audit trail. Eviction does not happen.

This makes supervisor countersign a hard structural requirement, not a soft policy check.

### 8.3 Future evolution

v1.x may add:

- Per-agent supervisor designation (Alice supervises Bob; Carol cannot countersign Bob's eviction).
- Hierarchical trees (multi-level supervision).
- Quorum requirements (M-of-N supervisor signatures, not just 1).

These are out of v1.1 scope; the receipt format already supports multiple signatures, so future RFCs can add the policy layer without changing wire format.

---

## 9. Topology-aware enforcement defaults

The three topology modes (closed / open / hybrid) suggest different enforcement defaults. Specific numbers ship in the F8 canonical-schemas under `/spec/constitution/canonical-schemas/v1.1.0/<mode>-baseline.cedarschema`; this section pins the policy posture.

### 9.1 Closed swarms

Closed swarms admit only trusted agents from a known allowlist. Trust is high; enforcement defaults to slow, supervisor-mediated:

- **Detect thresholds: high.** Single denies don't escalate; patterns of 5-10 denies do.
- **Coach cooldown: long.** 5 minutes between coach and quarantine.
- **Supervisor countersign at every stage transition** (not just evict).
- **Indefinite quarantine until explicit operator reverse.** No auto-expiry.
- **Eviction rare.** Typically reserved for verified compromise, not procedural drift.

### 9.2 Open swarms

Open swarms admit any agent passing the (typically sybil-resistant) admission policy. Trust is low; enforcement defaults to fast:

- **Detect thresholds: low.** 2-3 denies trigger detect; some severity-classes auto-detect on a single occurrence.
- **Coach cooldown: short.** 10-30 seconds.
- **No supervisor countersign on detect/coach/quarantine** — the volume would overwhelm supervisors.
- **Quarantine auto-expires** after a defined window unless re-triggered.
- **Eviction is the common outcome** for repeat offenders; supervisor countersign still required for evict (RFC 0009 §3.3 is the substrate floor).

### 9.3 Hybrid swarms

Hybrid swarms have a trusted core + open periphery. Enforcement applies the closed-mode defaults to core agents (those passing the operator allowlist) and open-mode defaults to periphery agents. The constitution distinguishes by `principal.passport_tier` or a custom attribute via schema delta.

### 9.4 Where the actual numbers live

The defaults above are *postures*, not numbers. Concrete `count_threshold`, `time_window`, `escalate_after`, `auto_expire_after` values per topology mode ship in F8 canonical schemas. The advantage of putting them there rather than here: operators amending their canonical schema reference can tune without re-spec'ing.

---

## 10. The engine-config surface for enforcement rules

The constitution's engine-config artifact carries an `enforcement_rules:` block alongside `scoring_rules:` and `procedures:` (extensions.md §2 + §3). Shape:

```yaml
# constitution.engine.yaml (excerpt)
enforcement_rules:
  - name: repeat_pii_violation
    detect:
      trigger:
        receipt_kind: constitution.evaluate.deny
        deny_reason: forbid_rule_matched
        forbid_rule_id: forbid_pii_to_external
      count_threshold: 3
      time_window: 10m
      group_by: principal      # one running counter per principal
      historical: false        # ignore receipts from prior constitution versions
    coach:
      cooldown: 30s
      guidance_template: |
        Your attempt to write PII to external scope was denied. Per swarm policy
        (constitution version {constitution_version}), PII may only be written
        to private or swarm scopes. If you need external scope, request a
        compliance-tier capability through your supervisor.
    quarantine:
      escalate_after: 5m
      expires_after: 1h        # absent → indefinite
      compliance_check:
        no_more_of: forbid_pii_to_external
        for: 5m
    evict:
      escalate_after: 24h
      require_countersign: true
      severity: critical
    reputation_delta:
      detect: -0.10            # overrides global default; harsher for PII
      coach: 0.0
      quarantine: -0.40
      evict: -1.0
      reverse_detect: +0.10
      reverse_coach: +0.0
      reverse_quarantine: +0.20
    reverse:
      auto_when:
        - quarantine_expired
        - reputation_above_threshold: 0.8

  - name: high_send_rate_dos
    detect:
      trigger:
        receipt_kind: capability.check.deny
        deny_reason: rate_limit_caveat_failed
      count_threshold: 10
      time_window: 1m
      group_by: principal
    # No coach; go straight to quarantine (severity flag)
    coach: null
    quarantine:
      escalate_after: 0s
      expires_after: 15m
    evict:
      escalate_after: 1h
    severity: medium
```

### 10.1 Field semantics

- **`name`** — unique within the constitution; appears in every enforcement receipt's evidence.
- **`detect.trigger`** — receipt-stream pattern. `receipt_kind` is required; other fields filter further. `group_by` defaults to `none` (single global counter); `principal` is the common case.
- **`detect.count_threshold`** and **`detect.time_window`** — pattern parameters. `count_threshold: 1` means "any matching receipt triggers detect."
- **`coach: null`** — explicit skip. The rule progresses from detect directly to quarantine after `quarantine.escalate_after`.
- **`compliance_check`** — used by quarantine and reverse to define when the agent has demonstrated compliance.
- **`reputation_delta`** — per-stage overrides of the global defaults from §7.2.
- **`reverse.auto_when`** — list of conditions; reverse fires when ANY condition holds.
- **`severity`** — operator-facing hint for dashboards and alerting; not consumed by the enforcement engine itself.

### 10.2 Loader validation

The constitution loader rejects an enforcement rule when:

- Two rules share the same `name`.
- A trigger's `receipt_kind` isn't a known action-kind from canonical-actions.md.
- A `forbid_rule_id` references a Cedar rule not present in the constitution's Cedar source.
- `count_threshold` is zero or negative; `time_window` is zero or negative.
- `reputation_delta` values are non-finite, exceed Decimal precision, or violate the reputation clamp range.
- A stage references another that wasn't declared (e.g. `coach.cooldown` but no `coach:` block).
- The rule's `escalate_after` durations chain to a cycle (impossible with linear stages, but belt-and-braces).

### 10.3 Validation is structural

The loader does NOT verify that a rule "makes sense" — that's an operator-judgment call. A rule that triggers detect on a `receipt_kind` no Cedar policy ever produces will simply never fire; it's not malformed.

---

## 11. Conformance hooks

A conformant constitution implementation:

- **Receipt-stream subscription.** Enforcement engine MUST subscribe to the receipt log; missed receipts are NOT permitted to cause missed enforcement.
- **Pattern matching.** Enforcement triggers fire within `[match_time, match_time + 1s]` for in-process implementations; persistent-scheduler implementations MAY have higher jitter.
- **Stage receipts.** Each stage transition produces the corresponding `enforcement.*` receipt with the spec'd evidence shape.
- **Quarantine enforcement.** Cap-layer and registry MUST consult the quarantine state; quarantined agents fail capability checks and cap issuance refuses.
- **Eviction integration.** `enforcement.evict` MUST drive `AdmissionService.OperatorRevoke` with `cascade_capabilities=true`; the cascade receipts MUST appear in the evict receipt's `cascade_revoke_receipt_ids` field.
- **Countersign enforcement.** Receipts requiring countersign MUST NOT be appended to the receipt log until the second signature is present.
- **Reversal determinism.** Same constitution + same receipt history → same enforcement state per agent (the running reputation scalar, the current stage, the active rule instances).
- **Reputation reconstruction.** Cold-start reputation rebuild from receipts produces the same scalar as the running supervisor cache.

Conformance test cases live under `/conformance/interface/language/enforcement/` (added during F-code stages).

---

## 12. Open questions

- **Per-agent supervisor designation.** v1.1 has flat supervisor tier; v1.2 may add per-agent supervisor links.
- **Quorum countersign.** M-of-N supervisor signatures for high-stakes evictions (e.g., evicting a supervisor-tier agent requires 2-of-3 supervisor signatures). Out of v1.1.
- **Re-admission policy.** When an evicted agent re-registers with a fresh passport, should the swarm have a "this is a reincarnation of a previous eviction" detection? Possible via passport metadata (operator-signed delta), but enforcement-side has no opinion in v1.1.
- **Reputation decay over time.** A small negative delta from a year-old detect feels less load-bearing than the same delta yesterday. Some swarms might want time-decay. Out of v1.1.
- **Cross-agent enforcement amplification.** "If agent A is detected, downgrade trust in agents A supervised." Interesting but introduces cascade complexity. Out of v1.1.
- **Operator override audit shape.** When an operator manually triggers reverse (overriding an automatic detection), the receipt carries an `operator_signature`. Should there be a stronger "audit-only" enforcement state where operators have to justify the override in a free-form field? Implementations MAY add this in the `reason` field; v1.1 doesn't require it.
- **Enforcement engine cold-start gap.** Receipts that land during enforcement-engine downtime are processed on restart — but the latency is implementation-defined. Worth specifying a maximum cold-start lag?

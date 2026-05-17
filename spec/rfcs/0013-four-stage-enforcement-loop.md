# RFC 0013: Four-Stage Constitution Enforcement Loop

> **Status:** Draft
> **Authors:** Workstream A (Specs) + Workstream E (Constitution engine)
> **Filed:** 2026-05-15
> **Targets spec:** `/spec/constitution/enforcement.md` (new),
>                   `/spec/receipt/canonical-actions.md` (fills out evidence shapes for the pre-allocated `enforcement.*` entries)
> **Targets phase:** Phase 2 (Coordination & Norms)
> **Discussion:** TBD
> **Predecessors:** [RFC 0010](./0010-constitution-language-v1.md), [RFC 0011](./0011-cedar-plus-extensions.md), [RFC 0012](./0012-evaluation-model-and-sandbox.md)
> **Substrate dependency:** [RFC 0009](./0009-operator-credentials.md) (eviction calls into `AdmissionService.OperatorRevoke`)

## 1. Summary

Specifies the four-stage enforcement loop that responds to constitution violations beyond single-shot deny: **detect → coach → quarantine → evict**, with explicit `reverse` semantics for non-terminal stages. Receipt-driven (the enforcement engine subscribes to the receipt stream, pattern-matches on receipt content, fires staged enforcement actions). Receipt-stage transitions are first-class audit events; the cap layer, registry, and supervisor layer subscribe to them and apply mechanical effects (quarantine scopes down cap-checks; evict drives the RFC 0009 operator-revoke + cascade).

Pinned in this RFC:

1. **The four-stage flow.** Each stage's trigger, mechanical effect, receipt evidence, and reversal semantics.
2. **The engine-config surface.** A new `enforcement_rules:` block in the constitution's engine config — same artifact `scoring_rules` and `procedures` live in (RFC 0011). YAML/protobuf shape; pattern-matching over the receipt stream; per-rule reputation deltas.
3. **Reputation scalar dynamics.** How the `Agent.reputation: Decimal` field (admitted in v1.0 schema) moves per enforcement stage; how the supervisor layer computes the running value from receipts.
4. **Supervisor tree integration.** v1.1 ships flat supervisor-tier countersign — any agent at `supervisor` tier or higher may countersign. Eviction requires countersign by default; constitutions MAY waive per rule.
5. **Topology-aware defaults.** Closed swarms favor slow escalation with supervisor countersign at every stage; open swarms favor fast escalation with less ceremony; hybrid mixes per-agent.

Fills out the evidence shapes for the pre-allocated `enforcement.*` action-kinds in `/spec/receipt/canonical-actions.md` (the entries existed since the receipt spec landed; this RFC defines what their evidence carries).

## 2. Motivation

Phase 1 substrate (RFCs 0002-0009) gave agents authority (capabilities) and the swarm visibility (receipts). Phase 2 base spec (RFCs 0010-0012) gave the swarm policy (constitution evaluation) and an audit-grade trail of per-evaluation decisions. What it didn't yet provide: **a response mechanism**.

Single-shot deny is not enough. An agent attempting a forbidden action and getting `constitution.evaluate.deny` learns that this specific attempt failed; the swarm learns nothing more than that. Three concrete cases this RFC unblocks:

1. **Repeat offenders.** An agent attempting the same forbidden action 10 times in a minute is either compromised, broken, or actively probing. Today, each attempt produces a deny receipt and nothing else. With this RFC, the third attempt triggers detect, the next coaches the agent, and continued attempts escalate to quarantine and (with supervisor signoff) eviction.

2. **Graduated remediation.** PRD §13 (the social contract) is explicit that response should be graduated — coaching before quarantine, quarantine before eviction. Without an enforcement loop, every response collapses to "operator manually intervenes" or "leave it alone."

3. **Reputation as policy input.** RFC 0010 admitted the `Agent.reputation` attribute specifically so policies could gate on it (`prefer score(2.0) when principal.reputation > 0.8`). But the attribute moves only through enforcement events. Without this RFC, reputation never changes and the attribute is decorative.

Beyond the operator-facing motivation, this RFC is the **last spec stage of Phase 2**. After F4 lands, Phase 2 spec work is complete and Phase 2 code (the F-code stages: `yutha-cedar-plus` crate scaffold, extension impls, evaluator, enforcement engine, authoring CLI, canonical schemas, conformance scenarios S2/S3) begins.

## 3. Detailed design

The full spec lives in [`/spec/constitution/enforcement.md`](../constitution/enforcement.md). This RFC summarizes the load-bearing decisions.

### 3.1 The four stages (enforcement.md §§2-5)

**Detect.** Pattern-matches on the receipt stream (`constitution.evaluate.deny` is the typical trigger, but other receipt kinds are admitted — e.g., capability check denies, send failures). Fires an `enforcement.detect` receipt; agents see nothing different yet. Mechanically a signal to escalation timers and the reputation scalar.

**Coach.** Fires after a detect plus cooldown (default 30s). The enforcement engine sends an `ADVISE` envelope to the agent's inbox with operator-defined guidance. Non-punitive; reputation delta typically 0.0. Fully reversible.

**Quarantine.** Fires after coach plus a longer cooldown (default 5m) without compliance. Mechanical effect: the cap layer's check pathway treats the agent as quarantined and denies; new capability issuance refuses. **Existing capabilities are not revoked** — quarantine is reversible by design. Reputation drops materially.

**Evict.** Terminal. Drives `AdmissionService.OperatorRevoke` (RFC 0009) with `cascade_capabilities=true`. Requires supervisor countersign by default (waivable per rule for severity-flagged auto-evict cases). Irreversible — the agent must re-register a fresh passport to return.

### 3.2 Reversal (enforcement.md §6)

`enforcement.reverse` undoes detect / coach / quarantine. Cannot undo evict (the substrate operations are themselves irreversible per RFC 0009).

Reversal can be triggered manually (operator action, recorded as `operator_signature` on the receipt) or automatically (rule-defined `auto_when` conditions: quarantine expiry, reputation recovery, compliance window). Reputation restoration on reverse is **partial by default** — some residue remains for repeat-offender detection. A fully-symmetric reverse would let agents game the loop by triggering and immediately reversing.

### 3.3 Reputation scalar (enforcement.md §7)

The `Agent.reputation: Decimal` field (v1.0 schema, RFC 0010) is computed by the supervisor layer as a sum of enforcement-receipt deltas, clamped to `[MIN_REPUTATION, MAX_REPUTATION]` (default `[0.0, 1.0]`). The supervisor layer maintains a running cache; cold-start rebuild walks the relevant `enforcement.*` receipts in chronological order. There is no parallel state store — the receipt log is authoritative.

Reputation is then available as a Cedar attribute for policies to gate on (`forbid when principal.reputation < 0.3`) and as a scoring-rule input (`prefer score(1.0) when principal.reputation > 0.8`).

### 3.4 Supervisor tree (enforcement.md §8)

v1.1 ships flat supervisor-tier countersign: any agent at passport `tier: supervisor` (or higher) may countersign any enforcement receipt requiring it. The countersign mechanically is a second signature on the receipt's canonical bytes, recorded in the receipt's existing multi-signature field per `/spec/receipt/rationale.md` §3.

Pending receipts that require countersign do NOT land in the receipt log until the second signature arrives. A 1-hour default timeout abandons the pending receipt with an `enforcement.evict_timeout` audit event.

Per-agent supervisor pairing, hierarchical trees, and M-of-N quorum countersign are explicitly deferred — v1.1 ships the simplest correct shape that the receipt format already supports.

### 3.5 Engine-config surface (enforcement.md §10)

`enforcement_rules:` block in the constitution's engine config artifact (alongside `scoring_rules` and `procedures` from RFC 0011). YAML/protobuf shape; pattern-matching over receipt streams; per-rule reputation deltas.

The full shape is in enforcement.md §10. A representative rule:

```yaml
enforcement_rules:
  - name: repeat_pii_violation
    detect:
      trigger: { receipt_kind: constitution.evaluate.deny, forbid_rule_id: forbid_pii_to_external }
      count_threshold: 3
      time_window: 10m
      group_by: principal
    coach:
      cooldown: 30s
      guidance_template: "Your attempt to write PII to external scope..."
    quarantine:
      escalate_after: 5m
      expires_after: 1h
    evict:
      escalate_after: 24h
      require_countersign: true
    reputation_delta:
      detect: -0.10
      quarantine: -0.40
      evict: -1.0
```

Loader validation: rule names unique, trigger references valid action-kinds, forbid_rule_id references actual Cedar rules in the constitution, reputation deltas finite + within clamp range, stage references consistent. Per the engine-construct pattern established in F2, validation is conventional structural checking — no Cedar analyzer extension.

### 3.6 Topology defaults (enforcement.md §9)

Three default postures (concrete numbers in F8 canonical schemas):

- **Closed:** high detect thresholds, long cooldowns, supervisor countersign at every stage transition, indefinite quarantine.
- **Open:** low detect thresholds, short cooldowns, no countersign on non-eviction stages, auto-expiring quarantine.
- **Hybrid:** closed-mode for allowlisted core, open-mode for periphery; the constitution distinguishes via `principal.passport_tier` or operator-defined attributes.

## 4. Receipt-evidence schemas

Fills out the `enforcement.*` entries in `/spec/receipt/canonical-actions.md`. Each entry's evidence shape:

| `action_kind` | Evidence fields |
|---------------|-----------------|
| `enforcement.detect` | `enforcement_rule_id`, `target_agent_id`, `matched_receipt_ids[]`, `pattern_summary`, `constitution_hash`, `reputation_delta` |
| `enforcement.coach` | `enforcement_rule_id`, `target_agent_id`, `detect_receipt_id`, `coaching_envelope_id`, `constitution_hash`, `reputation_delta` |
| `enforcement.quarantine` | `enforcement_rule_id`, `target_agent_id`, `coach_receipt_id` (optional), `expires_at_wall_clock` (optional), `constitution_hash`, `reputation_delta` |
| `enforcement.evict` | `enforcement_rule_id`, `target_agent_id`, `quarantine_receipt_id` (optional), `substrate_revoke_receipt_id`, `cascade_revoke_receipt_ids[]`, `constitution_hash`, `reputation_delta`, `supervisor_countersign` |
| `enforcement.reverse` | `enforcement_rule_id`, `target_agent_id`, `reversed_receipt_id`, `reversed_stage`, `reason`, `constitution_hash`, `reputation_delta`, `operator_signature` (when manual) |

The `evict` receipt's `substrate_revoke_receipt_id` is the load-bearing audit link — it points at the `agent.operator_revoke` receipt RFC 0009 produces. Auditors trace evictions through this link without ambiguity.

## 5. Conformance hooks

A conformant constitution implementation:

- **Receipt subscription.** Enforcement engine MUST subscribe to the receipt log; missed receipts MUST NOT cause missed enforcement.
- **Pattern jitter bound.** Stage transitions fire within `[match_time, match_time + 1s]` for in-process implementations; persistent-scheduler implementations may have higher documented jitter.
- **Stage receipts.** Each transition emits the corresponding receipt with the §4 evidence shape.
- **Quarantine enforcement at cap layer.** Cap-check and cap-issue MUST consult the agent's quarantine state; quarantined agents fail with `agent_quarantined`.
- **Eviction integration.** `enforcement.evict` MUST drive `AdmissionService.OperatorRevoke` (RFC 0009) with `cascade_capabilities=true`; the cascade receipts appear in the evict's `cascade_revoke_receipt_ids`.
- **Countersign enforcement.** Receipts requiring countersign MUST NOT append to the log until the second signature is present.
- **Reputation reconstruction determinism.** Cold-start rebuild over the same receipt history MUST produce the same scalar as the running supervisor cache.
- **Reversal determinism.** Same constitution + same receipt history → same enforcement state per agent.

Test cases land under `/conformance/interface/language/enforcement/` during F-code stages.

## 6. Threat-model linkage

The enforcement loop is the primary defense against:

- **A7 (norm drift).** Repeat offenders are detected automatically; the receipt fabric records every detection. Drift becomes operationally surfaced (dashboard alerts) rather than buried in per-eval-deny noise.
- **A1 (hostile agent).** A compromised agent is quarantined within minutes of detection; cap-issuance refusal prevents the compromise from spreading via attenuation; eviction terminates the threat with full audit trail.

Secondary contribution to:

- **A3 (prompt injection).** Agents repeatedly tripped by prompt injection produce detect-able patterns; coaching surfaces the issue to operators before the next attempt escalates.
- **A8 (malicious operator).** Operator manual reversals are signed (`operator_signature` on the receipt). An operator abusing the reverse mechanism is auditable; pattern detection on operator reverse activity is itself a future enforcement target.
- **A9 (compromised supervisor).** Supervisor countersign on evict is structural; a single compromised supervisor cannot evict an entire swarm. Quorum countersign (deferred to v1.x) hardens this further.

## 7. Backwards compatibility

This RFC adds the enforcement.md spec document, the `enforcement_rules:` engine-config block, and the evidence shapes for pre-allocated `enforcement.*` action-kinds. No existing wire format changes. Implementations on v1.0 / v1.1 constitutions that haven't yet adopted enforcement continue to work — they simply don't emit `enforcement.*` receipts and reputation stays at its initial value.

When a swarm opts into enforcement:

- Existing v1.0 / v1.1 Cedar policy files require no changes.
- The engine config artifact gains an `enforcement_rules:` block.
- The amendment lands as `constitution.amend.commit`; the new enforcement rules take effect for receipts landing AFTER the amendment receipt (per enforcement.md §2.4 — patterns don't trigger on pre-rule receipts unless `historical: true` is set).

## 8. Migration path

Operators adopting enforcement in an existing swarm:

1. Author `enforcement_rules:` in the engine config. Start narrow — one or two rules for the most-visible violation patterns.
2. Amend the constitution with the new engine config. The amendment receipt records the schema_version and rule additions in evidence.
3. Wait for the rules to fire in production; observe the receipts; tune thresholds.
4. Add more rules as the operator's understanding of the swarm's threat surface deepens.

Reputation starts at the spec default (typically 1.0) for agents already in the swarm. Implementations MAY choose to seed reputation from a backfill pass over historical receipts (run the new rules against the historical receipt log and emit detect receipts retroactively), but this is opt-in and produces a `historical_backfill: true` marker on every emitted receipt.

## 9. Open questions for review

- **Per-agent supervisor designation.** v1.1 has flat supervisor tier; v1.2 may add per-agent supervisor links and hierarchical trees.
- **Quorum countersign.** M-of-N supervisor signatures for high-stakes evictions. Receipt format already supports multiple signatures; the policy layer doesn't yet.
- **Re-admission policy.** When an evicted agent re-registers with a fresh passport, should there be detection of "this is a reincarnation"? Possible via passport metadata (operator-signed delta); enforcement-side has no opinion in v1.1.
- **Reputation decay over time.** A year-old detect feels less load-bearing than yesterday's. Time-decay is plausible but introduces clock dependencies that the receipt-rebuild model would have to honor. Out of v1.1.
- **Cross-agent enforcement amplification.** "If A is detected, downgrade trust in agents A supervised." Cascade complexity; out of v1.1.
- **Operator override audit shape.** A manual reverse carries `operator_signature`. Should free-form `reason` text be mandatory rather than optional?
- **Enforcement engine cold-start lag.** Receipts that land during engine downtime are processed on restart; what's the maximum acceptable lag? In-process: seconds. Persistent: minutes. Worth specifying a ceiling?

## 10. References

- Enforcement spec: [`/spec/constitution/enforcement.md`](../constitution/enforcement.md)
- Predecessors: [RFC 0010](./0010-constitution-language-v1.md), [RFC 0011](./0011-cedar-plus-extensions.md), [RFC 0012](./0012-evaluation-model-and-sandbox.md)
- Substrate dependency: [RFC 0009](./0009-operator-credentials.md) (operator-revoke + cascade)
- Receipt spec: [`/spec/receipt/rationale.md`](../receipt/rationale.md), [`/spec/receipt/canonical-actions.md`](../receipt/canonical-actions.md)
- Build-plan §7 (Phase 2 exit criteria): [`/build-plan.md`](../../build-plan.md)
- Threat model: `/docs/security/threat-model.md`

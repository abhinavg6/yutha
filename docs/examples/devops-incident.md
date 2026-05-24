# DevOps incident-response with SRE countersign

A worked example for a production-incident-response swarm built
on Microsoft Agent Framework (MAF) — an alerting agent ingests
the pager event, a triage agent classifies it, a remediation
agent performs the production actions (capability-gated), a
post-mortem agent writes the incident summary, and a human SRE
agent stands in as the human-in-the-loop countersign. The
substrate point is **policy-bounded production access**:
remediation may execute safe rollbacks freely, but schema-
changing actions are constitutionally forbidden unless the
envelope carries an `sre_countersigned` tag.

The runnable demo lives at
[`sdks/python/examples/devops_incident.py`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/examples/devops_incident.py).
It runs end-to-end against a real control plane in about
fifteen to twenty seconds.

This is the **Microsoft Agent Framework** companion to the
[code-review](code-review.md) (LangGraph),
[AP/invoice](ap-invoice.md) (CrewAI), and
[research-crew](research-crew.md) (OpenAI Agents) examples.
Same substrate machinery — different framework idioms,
different business framing.

For the framework adapter's full surface — `YuthaChatAgent`
lifecycle, the dispatch loop, `@capability_required` on async
tool callables, audit-log patterns, plus the honest v1 scope vs
`WorkflowBuilder` / `RequestInfoExecutor` / `FunctionMiddleware`
follow-ons — see the
[Microsoft Agent Framework developer guide](../developer/maf.md).
This page is the applied walkthrough that exercises that surface
end-to-end with a real constitution.

---

## What this example shows

The four previous examples covered identity, capability gating,
constitution-based forbid rules, and the four-stage enforcement
loop. This one demonstrates the same substrate machinery
through MAF's `Agent` surface, with a deliberately enterprise-
flavored use case (devops incident response is one of MAF's
canonical positioning fits).

- Five MAF `Agent` instances register as Yutha agents with
  distinct `framework` labels.
- An operator activates a custom devops-incident constitution
  that gates production-write actions on the presence of an
  `sre_countersigned` tag when the action is a `schema_change`.
- A single `alerting.run(incident)` LLM exploration in Phase 5
  exercises the MAF Agent surface end-to-end.
- The orchestrator then drives the deterministic substrate
  path: a safe rollback (Phase 6), two bypass attempts (Phases
  7-8), the four-stage enforcement chain (Phases 9 + 11),
  and a post-quarantine cap-check (Phase 10).
- The audit-trail assertion uses the same split-window pattern
  as the research-crew example — pre→mid is informational
  (LLM-driven counts vary), mid→after is strict-asserted.

---

## v1 scope vs. future

The v1 adapter and example are deliberately scoped to ship
quickly while exercising the substrate-correct integration
end-to-end. Three MAF-distinctive capabilities are tracked as
documented follow-ons rather than v1 features:

- **`WorkflowBuilder` integration.** v1 drives agents
  individually (`await alerting.run(incident)`). The natural
  next step is composing the runbook as a MAF graph workflow
  (`alerting → triage → remediation → post_mortem`) where
  each edge emits a Yutha envelope. The adapter primitives
  already support this; the demo would just swap the
  orchestrator path for `workflow.run(...)`.
- **`RequestInfoExecutor` for HITL.** v1 has the `human_sre`
  agent passively registered. The next revision would wire
  it through MAF's HITL primitive so the request +
  countersign cycle produces `approval_required` and
  `countersigned` Yutha receipts.
- **`FunctionMiddleware`-based cap-gating.** v1 reuses the
  contextvar-decorator pattern from the other three adapters
  (which works because MAF's tool invocation is async-native).
  Moving the cap-context into a `FunctionMiddleware` would be
  tighter integration with MAF's middleware pipeline but
  doesn't affect substrate correctness.

The walkthrough below covers what v1 actually delivers; the
follow-ons get separate scope when they land.

---

## The cast

Five MAF agents register into a clean swarm. Each carries a
passport with a distinct `framework` label.

| Agent | `framework` | Role |
|---|---|---|
| `alerting` | `maf-devops-alerting` | Receives a pager event; orchestrator drives its `Agent.run` in Phase 5. |
| `triage` | `maf-devops-triage` | Classifies incident severity; passively registered in v1. |
| `remediation` | `maf-devops-remediation` | Performs production actions via a cap-gated `apply_action` callable. **Subject of bypass attempts.** |
| `post_mortem` | `maf-devops-post-mortem` | Receives audit envelopes of every executed action; passively registered. |
| `human_sre` | `maf-devops-human-sre` | The human countersign agent. Passively registered in v1; HITL wiring is a follow-on. |

---

## The constitution

```cedar
@id("no-schema-change-without-sre-countersign")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
) when {
    context.tags.contains("production_action") &&
    context.tags.contains("schema_change") &&
    !context.tags.contains("sre_countersigned")
};

permit (principal, action, resource);
```

The rule reads as *"no agent may send a `production_action`
tagged `schema_change` without also carrying
`sre_countersigned`."* The remediation's `apply_action` helper
builds the tag set parametrically:

- **Happy rollback**: `[production_action]` only — no
  `schema_change`, the forbid rule doesn't apply.
- **Authorized schema change**: `[production_action,
  schema_change, sre_countersigned]` — all three forbid
  conditions exist but the negation fails the match (the
  `sre_countersigned` tag IS present); the policy permits.
- **Bypass attempt**: `[production_action, schema_change]`
  without `sre_countersigned` — exactly the combination the
  forbid rule catches.

The engine config attaches the same 4-stage enforcement rule
shape used by the other examples (`count_threshold: 2`, 1s
cooldowns, `require_countersign: false` on evict for the
self-contained demo).

---

## The cap-gated apply_action

Same pattern as the other examples — the remediation's
outbound production-action send is wrapped with
`@capability_required`:

```python
@capability_required(remediation_cap, action_kind="envelope.send")
async def apply_action(
    action_description: str,
    schema_change: bool,
    countersigned: bool,
) -> yutha.Hash:
    tags = [DEMO_TAG, "production_action"]
    if schema_change:
        tags.append("schema_change")
    if countersigned:
        tags.append("sre_countersigned")
    return await remediation_wrapper.send(
        recipient=yutha.Recipient.for_agent(audit_recipient_id),
        performative=yutha.Performative.INFORM,
        payload=action_description.encode("utf-8"),
        payload_schema_id="type.yutha.dev/v1/Text",
        tags=tags,
    )
```

The orchestrator drives this directly for Phases 6-8 with
explicit `schema_change` / `countersigned` arguments. The LLM
in Phase 5 doesn't invoke it (the `alerting` agent doesn't
have it as a tool — that's a deliberate scoping decision to
keep Phase 5 LLM-only and Phases 6-8 substrate-deterministic).

---

## The bypass and the chain

Each bypass attempt is one async call expected to raise
`ConstitutionDenied`:

```python
try:
    await remediation_apply_action(
        "Apply schema migration without supervisor approval.",
        schema_change=True,
        countersigned=False,
    )
except yutha.ConstitutionDenied as e:
    assert e.deny_reason == "forbid_rule_matched"
```

After the second attempt, the enforcement engine fires
`enforcement.detect`. The chain progresses through coach,
quarantine, and evict at 1-second intervals plus the
scheduler tick. The demo polls the first three stages, runs
the post-quarantine cap-check, then polls evict — same pattern
as the other examples.

---

## The audit-trail delta — split into two windows

The split-assertion pattern from research_crew.py applies here
identically. MAF's `Agent.run` in Phase 5 is LLM-driven and
non-deterministic; the orchestrator-driven Phases 6-11 are
substrate-deterministic.

```python
EXPECTED_PRE_TO_MID_DELTA = {
    "agent.register": 5,
    "constitution.activate": 1,
    "capability.issue": 1,
}

LLM_INFORMATIONAL_KINDS = frozenset({
    "envelope.send",
    "envelope.deliver",
    "constitution.evaluate.pass",
    "capability.check.pass",
})

EXPECTED_MID_TO_AFTER_DELTA = {
    "envelope.send": 1,
    "envelope.deliver": 1,
    "constitution.evaluate.pass": 1,
    "constitution.evaluate.deny": 2,
    "capability.check.pass": 3,
    "capability.check.deny": 1,
    "enforcement.detect": 1,
    "enforcement.coach": 1,
    "enforcement.quarantine": 1,
    "enforcement.evict": 1,
}
```

The mid→after window is strict-asserted; a `✗` in that block
is a substrate regression. The pre→mid window's LLM-driven
counts (`·` markers) can vary run-to-run depending on what
the alerting agent does with the incident description.

---

## Running it

```bash
# Mint a seed (once per run).
export YUTHA_BOOTSTRAP_SEED=$(python -c \
    'import secrets; print(secrets.token_hex(32))')

# MAF needs an LLM credential. Default in this demo is OpenAI;
# swap for FoundryChatClient / AzureOpenAIChatClient / etc. if
# preferred (edit the import in the demo file).
export OPENAI_API_KEY=...

# Start the control plane with the seed-derived operator pubkey.
cargo run -p yutha-control-plane -- \
    --admission-mode open \
    --operator-public-key $(python sdks/python/examples/devops_incident.py --print-operator-pubkey)

# Run the demo in a second shell with the same seed exported.
pip install 'yutha[maf]'    # or editable install during dev
python sdks/python/examples/devops_incident.py
```

A clean run prints two delta blocks. The pre→mid block reports
what the LLM did in Phase 5 (deterministic kinds asserted with
`✓`/`✗`, LLM-driven kinds marked with `·` for "varies, not
asserted"). The mid→after block is the strict assertion:

```text
# Pre → Mid delta (LLM exploration may have produced extra receipts)
  ✓ agent.register                +5  (expected +5)
  ✓ constitution.activate         +1  (expected +1)
  ✓ capability.issue              +1  (expected +1)
  · envelope.send                 +0  (LLM-driven; varies, not asserted)
  · envelope.deliver              +0  (LLM-driven; varies, not asserted)
  · constitution.evaluate.pass    +0  (LLM-driven; varies, not asserted)
  · capability.check.pass         +0  (LLM-driven; varies, not asserted)

# (Phases 6-11 then run the deterministic substrate path.)

# Phase 12 — Mid → After delta (strict assertion)
  ✓ envelope.send                 +1  (expected +1)
  ✓ envelope.deliver              +1  (expected +1)
  ✓ constitution.evaluate.pass    +1  (expected +1)
  ✓ constitution.evaluate.deny    +2  (expected +2)
  ✓ capability.check.pass         +3  (expected +3)
  ✓ capability.check.deny         +1  (expected +1)
  ✓ enforcement.detect            +1  (expected +1)
  ✓ enforcement.coach             +1  (expected +1)
  ✓ enforcement.quarantine        +1  (expected +1)
  ✓ enforcement.evict             +1  (expected +1)

✓ Mid → After delta matches; substrate behavior verified
```

Total wall-clock is ~15-20 seconds. The script exits with
status 1 only if mid→after shows any mismatch.

---

## What to try next

A few directions to extend the example:

- **Wire the full hybrid (Option C in the design)** — replace
  the orchestrator-driven Phase 5 with a real MAF
  `WorkflowBuilder` graph (alerting → triage → remediation →
  post_mortem), then add `RequestInfoExecutor`-driven HITL so
  the human_sre agent actually countersigns. The adapter
  primitives are already in place; this is mostly demo and
  walkthrough work.
- **Lift `FunctionMiddleware` cap-gating** — replace the
  contextvar decorator with a MAF middleware. Both approaches
  produce identical substrate behavior; the middleware version
  is tighter integration with MAF's pipeline.
- **Multi-environment topologies** — model staging vs.
  production as two distinct Yutha swarms with a shared
  constitution. Schema changes are permitted in staging
  freely; in production they require countersign. Federation
  primitives ship in a later substrate cut.
- **OpenTelemetry bridge** — wire MAF's OTel spans into Yutha
  telemetry receipts (or vice versa via a Yutha OTel
  exporter). Useful when an operator already runs an OTel
  stack and wants the substrate to participate in it.

---

## See also

- [Research crew with citation enforcement](research-crew.md)
  — the OpenAI Agents example with the same split-assertion
  pattern.
- [Code review crew with security boundaries](code-review.md)
  — the LangGraph example.
- [AP & invoice processing with payment caps](ap-invoice.md)
  — the CrewAI example.
- [Customer support with a refund cap](customer-support.md) —
  the simplest primitives-only example.
- [Microsoft Agent Framework](https://github.com/microsoft/agent-framework)
  — the upstream framework.
- [RFC 0013 — four-stage enforcement loop](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0013-four-stage-enforcement-loop.md)
  — the design behind detect / coach / quarantine / evict.

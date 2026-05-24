# Research crew with citation enforcement

A worked example for a research swarm — a researcher that gathers
raw material, a fact-checker that verifies citations, and an
editor that publishes the final brief. The substrate point is
**citation verification as a constitutional requirement**: the
editor agent may only publish envelopes that carry the
`verified_citations` tag, and the four-stage enforcement loop
trips on any agent that tries to bypass that boundary.

The runnable demo lives at
[`sdks/python/examples/research_crew.py`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/examples/research_crew.py).
It runs end-to-end against a real control plane in about fifteen
to twenty seconds, depending on LLM latency.

This is the **OpenAI Agents** companion to the
[code-review](code-review.md) (LangGraph) and
[AP/invoice](ap-invoice.md) (CrewAI) examples. Same substrate
machinery; first example to use OpenAI Agents' **handoff**
primitive as a first-class substrate hook.

---

## What this example shows

The previous constitution-bearing examples used in-graph routing
(LangGraph) or per-envelope task factories (CrewAI). OpenAI
Agents' multi-agent model is built around **handoffs** — one
agent explicitly transferring control to another inside a single
`Runner.run`. This example demonstrates how Yutha bridges those
handoffs to the substrate:

- Every `researcher → fact_checker → editor` transition fires
  `RunHooks.on_handoff`. The
  [`yutha.openai_agents.YuthaRunHooks`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/src/yutha/openai_agents/hooks.py)
  bridge emits a Yutha envelope from the source agent to the
  target agent's inbox, tagged with the handoff source/destination.
  The substrate audit log captures the full agent collaboration
  chain.
- The editor's `publish_brief` function tool is wrapped with
  `@capability_required` — server-side capability checks fire
  before each envelope is signed.
- Two bypass attempts (the demo orchestrator calls the editor's
  publish helper directly with `cited=False`) produce
  `constitution.evaluate.deny` receipts and cross the enforcement
  rule's threshold. The four-stage chain (detect → coach →
  quarantine → evict) progresses on the server's wall-clock
  scheduler.
- A post-quarantine `capability.check` returns deny with reason
  `subject_quarantined` — the cap layer honors the engine's
  quarantine state regardless of the cap's own validity.
- The audit-trail delta is computed against a pre-flow snapshot
  and asserted — every consequential action leaves a receipt.

---

## The cast

Three OpenAI Agents agents register into a clean swarm. Each
carries a passport with a distinct `framework` label.

| Agent | `framework` | Role |
|---|---|---|
| `researcher` | `openai-research-crew-researcher` | Receives a topic prompt, drafts a research brief, hands off to `fact_checker`. |
| `fact_checker` | `openai-research-crew-fact-checker` | Reviews the draft, acknowledges consistency, hands off to `editor`. |
| `editor` | `openai-research-crew-editor` | Composes the final brief, calls the cap-gated `publish_brief` tool. **Subject of bypass attempts.** |

Each LLM-driven agent uses tightly-constrained `instructions`
so the handoff chain is deterministic — researcher always hands
off to fact_checker; fact_checker always hands off to editor;
editor always calls `publish_brief` with `cited=True`. The
substrate-side bypass attempts run *outside* the Runner.run by
invoking the editor's publish helper directly.

---

## The constitution

```cedar
@id("no-publish-without-verified-citations")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
) when {
    context.tags.contains("claim_published") &&
    !context.tags.contains("verified_citations")
};

permit (principal, action, resource);
```

The rule reads as *"no agent may send a `claim_published`
envelope without the `verified_citations` tag."* The editor's
`publish_brief` tool adds `verified_citations` iff its `cited`
parameter is true:

```python
@capability_required(editor_cap, action_kind="envelope.send")
async def publish_brief(content: str, cited: bool) -> yutha.Hash:
    tags = [DEMO_TAG, "claim_published"]
    if cited:
        tags.append("verified_citations")
    return await editor_wrapper.send(
        recipient=yutha.Recipient.for_agent(publisher_id),
        performative=yutha.Performative.INFORM,
        payload=content.encode("utf-8"),
        payload_schema_id="type.yutha.dev/v1/Text",
        tags=tags,
    )
```

The happy-path `Runner.run` causes the editor's LLM to call
`publish_brief(content, cited=True)` — the constitution permits.
Bypass attempts (orchestrator calls `publish_brief(content,
cited=False)` directly) emit `claim_published` alone and trip
the forbid rule.

The engine config attaches a single enforcement rule with 1-
second cooldowns:

```yaml
enforcement_rules:
  - name: unverified_publish_chain
    detect:
      trigger:
        receipt_kind: constitution.evaluate.deny
      count_threshold: 2
      time_window: 60s
      group_by: principal
    coach:
      cooldown: 1s
      guidance_template: "Editor must not publish without verified citations"
    quarantine:
      escalate_after: 1s
    evict:
      escalate_after: 1s
      require_countersign: false
    severity: high
```

Two denies within the 60-second window for the same principal
fire `enforcement.detect`. The chain progresses on the server's
wall-clock scheduler — same shape as code-review and ap-invoice.

---

## The handoff bridge

The most interesting integration in this example is the handoff
bridge — OpenAI Agents' `RunHooks` system gives us a clean
event whenever the Runner transitions between agents, and the
`YuthaRunHooks` factory turns each transition into a Yutha
envelope:

```python
# Inside YuthaRunHooks (yutha/openai_agents/hooks.py):
async def on_handoff(self, context, from_agent, to_agent):
    from_name = getattr(from_agent, "name", "?")
    to_name = getattr(to_agent, "name", "?")
    peer = registry.get(to_name)
    recipient = (
        yutha.Recipient.for_agent(peer.agent_id)
        if peer is not None
        else yutha.Recipient.for_agent(wrapper.agent_id)
    )
    await wrapper.send(
        recipient=recipient,
        performative=yutha.Performative.INFORM,
        payload=f"handoff: {from_name} -> {to_name}".encode("utf-8"),
        payload_schema_id="type.yutha.dev/v1/HandoffAudit",
        tags=[
            "openai_agents_handoff",
            f"handoff_from:{from_name}",
            f"handoff_to:{to_name}",
        ],
    )
```

The `peer_registry` maps OpenAI Agents `Agent.name` to the
corresponding `YuthaOpenAIAgent` wrapper. When a handoff target
is registered, the envelope is addressed to that peer's inbox —
the substrate audit trail records the transition with a real
sender + recipient pair. When no peer is registered (e.g.
in-process handoffs to anonymous helper agents), the envelope is
a self-loop — still produces audit receipts; just doesn't
deliver to any external inbox.

The demo wires the full registry up front:

```python
peer_registry = {
    "ResearchFactChecker": wrappers["fact_checker"],
    "ResearchEditor": wrappers["editor"],
    "ResearchResearcher": wrappers["researcher"],
}
for wrapper in wrappers.values():
    wrapper._get_hooks().register_peers(peer_registry)
```

Now every handoff in the `Runner.run(researcher, …)` happy-path
produces a real signed envelope between two distinct registered
Yutha agents.

---

## The cap-gated publish tool

Same pattern as the other examples — the editor's outbound
publish is wrapped with `@capability_required`:

```python
@capability_required(editor_cap, action_kind="envelope.send")
async def publish_brief(content: str, cited: bool) -> yutha.Hash:
    ...
```

For the LLM-driven happy path, the demo wraps `publish_brief`
with `function_tool` and attaches it to the editor agent:

```python
editor_agent.tools = [function_tool(publish_brief)]
```

The editor's instructions tell the LLM to call `publish_brief`
exactly once with `cited=True`. The Runner invokes the tool,
the cap-context is set, the envelope's tags include
`verified_citations`, and the constitution permits.

For bypass attempts, the demo orchestrator invokes the
underlying `publish_brief` callable directly (bypassing the
LLM and the function_tool wrapper). The `cited=False` argument
produces an envelope with `claim_published` but no
`verified_citations`. The constitution denies; the cap-context
fires; the substrate raises `ConstitutionDenied`.

---

## The bypass and the chain

Each bypass is one async call that's expected to raise
`ConstitutionDenied`:

```python
try:
    await publish_brief("Unverified draft of a research claim.", False)
except yutha.ConstitutionDenied as e:
    assert e.deny_reason == "forbid_rule_matched"
```

After the second attempt, the enforcement engine sees two
`constitution.evaluate.deny` receipts for the same principal in
the 60-second window and fires `enforcement.detect`. The chain
then progresses through coach, quarantine, and evict at 1-second
intervals plus the scheduler tick.

The demo polls the receipt store for the first three stages,
runs the post-quarantine cap-check, then polls for evict. Same
pattern as the previous examples.

---

## The audit-trail delta — split into two windows

OpenAI Agents' handoff invocation is ultimately the LLM's
choice. Sometimes the model traverses the full
`researcher → fact_checker → editor → publish_brief` chain;
sometimes it stops short or narrates a handoff in prose
without actually issuing the `transfer_to_<name>` tool call.
That nondeterminism is real and tighter prompting only reduces
it, never eliminates it.

To keep the demo's audit-delta assertion meaningful, the run is
structured around a **mid-flow audit snapshot** that separates
the LLM-driven phase from the substrate-driven phases:

```python
# Deterministic counts that fire BEFORE the LLM-driven phase
# (Phases 1-4 — register / activate / cap.issue).
EXPECTED_PRE_TO_MID_DELTA = {
    "agent.register": 3,
    "constitution.activate": 1,
    "capability.issue": 1,
}

# LLM-driven counts that vary between runs. Reported as
# informational under the pre→mid block; NOT asserted.
LLM_INFORMATIONAL_KINDS = frozenset({
    "envelope.send",
    "envelope.deliver",
    "constitution.evaluate.pass",
    "capability.check.pass",
})

# Deterministic counts that fire AFTER the LLM-driven phase
# (Phases 6-11 — deterministic happy publish + bypasses +
# enforcement chain). Strict equality is asserted on this dict.
EXPECTED_MID_TO_AFTER_DELTA = {
    "envelope.send": 1,            # Phase 6 deterministic publish
    "envelope.deliver": 1,
    "constitution.evaluate.pass": 1,
    "constitution.evaluate.deny": 2,  # 2 bypass attempts
    "capability.check.pass": 3,    # happy publish + 2 bypasses
    "capability.check.deny": 1,    # post-quarantine cap-check
    "enforcement.detect": 1,
    "enforcement.coach": 1,
    "enforcement.quarantine": 1,
    "enforcement.evict": 1,
}
```

The substrate-correctness signal lives in the mid→after window.
If a run prints `✗` markers in that block, that's a real
substrate regression. If the pre→mid block shows
varying-but-plausible LLM-driven counts (anywhere from 0 to 3
extra `envelope.send` etc.), that's expected LLM behavior, not
a bug.

Things worth noticing:

- **The mid→after `envelope.send: 1`** is the
  orchestrator-driven Phase 6 publish — a direct call to the
  editor's publish helper with `cited=True`. It's the
  guaranteed substrate baseline regardless of whether the
  LLM-driven Phase 5 produced anything at all.
- **The bypass attempts contribute to `capability.check.pass`,
  not `capability.check.deny`.** Cap-check runs first
  server-side; the cap is still valid (no quarantine yet); only
  the constitution denies. The single `capability.check.deny`
  in mid→after comes from the explicit post-quarantine
  cap-check in Phase 10.
- **`constitution.evaluate.pass` in mid→after = 1** because
  only Phase 6's deterministic publish fires it. If the LLM in
  Phase 5 also reached the editor and called `publish_brief`,
  that would add to the pre→mid block — visible there but not
  counted here.

---

## LLM nondeterminism caveat

OpenAI Agents has no deterministic-runner mode — Phase 5's
`Runner.run` always hits a real LLM. Common things that vary
between runs:

- **0, 1, or 2 handoffs** depending on whether the model
  invokes the configured `transfer_to_<name>` tools or just
  produces final output at each agent.
- **Whether `publish_brief` gets called** during Phase 5
  depends on whether the model reaches the editor agent at all.
- **Brief content** varies, but the substrate doesn't care
  about content — only tag combinations matter.

All of this is captured in the pre→mid block as informational.
The mid→after block is unaffected because Phases 6-11 run
entirely on orchestrator-driven code paths that don't depend on
the LLM. If you ever see a mismatch in mid→after, treat it as a
real bug.

---

## Running it

OpenAI Agents requires an LLM credential at construction time
even though the substrate path doesn't depend on the LLM for the
bypass phases:

```bash
# Mint a seed (once per run).
export YUTHA_BOOTSTRAP_SEED=$(python -c \
    'import secrets; print(secrets.token_hex(32))')

# OpenAI Agents needs an LLM credential. Default is OpenAI;
# other providers work via LiteLLM.
export OPENAI_API_KEY=...

# Start the control plane with the seed-derived operator pubkey.
cargo run -p yutha-control-plane -- \
    --admission-mode open \
    --operator-public-key $(python sdks/python/examples/research_crew.py --print-operator-pubkey)

# Run the demo in a second shell with the same seed exported.
python sdks/python/examples/research_crew.py
```

A clean run prints two delta blocks. The pre→mid block reports
what the LLM did in Phase 5 (deterministic kinds asserted with
`✓`/`✗`, LLM-driven kinds marked with `·` for "varies, not
asserted"). The mid→after block is the strict assertion:

```text
# Pre → Mid delta (LLM exploration may have produced extra receipts)
  ✓ agent.register                +3  (expected +3)
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

The pre→mid `·`-marked counts can be anywhere from `+0` (LLM
produced final output at the researcher with no handoffs) to
`+3` (LLM completed the full chain through to the editor's
publish_brief call). Either is fine; the substrate captured
whatever happened.

Total wall-clock is ~15-20 seconds (LLM exploration +
deterministic publish + bypasses + enforcement chain). The
script exits with status 1 only if the mid→after block shows
any mismatch.

---

## What to try next

A few directions to extend the example:

- **Add input guardrails.** OpenAI Agents' `InputGuardrail`
  primitive lets you reject inputs before the agent loop runs.
  Add a researcher-side guardrail that rejects topics containing
  PII; turn the guardrail trip into a Yutha receipt for the audit
  trail.
- **Swap to Sandbox Agents.** Use OpenAI Agents v0.14's
  `SandboxAgent` for the researcher so it can inspect real files
  inside a sandboxed workspace. The constitution can gate which
  directories the researcher writes to; every file touched
  produces a Yutha receipt.
- **Multi-source verification.** Instead of one fact_checker,
  fan out to N parallel verifiers (one per citation domain — e.g.
  arXiv-checker, news-checker, primary-source-checker). The
  constitution requires all N to sign off via tags before the
  editor can publish.
- **Cross-framework collaboration.** Wire this OpenAI Agents
  research crew alongside the LangGraph code-review crew or the
  CrewAI AP-invoice crew under a single Yutha swarm. The
  substrate doesn't care which framework an agent ships under;
  every envelope and receipt is just envelope and receipt.

---

## See also

- [Code review crew with security boundaries](code-review.md) —
  the LangGraph example; same constitution + enforcement
  machinery, different framework idioms.
- [AP & invoice processing with payment caps](ap-invoice.md) —
  the CrewAI example with role-boundary enforcement.
- [Customer support with a refund cap](customer-support.md) —
  the simpler primitives-only example.
- [OpenAI Agents SDK](https://github.com/openai/openai-agents-python)
  — the upstream framework documentation.
- [RFC 0013 — four-stage enforcement loop](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0013-four-stage-enforcement-loop.md)
  — the design behind detect / coach / quarantine / evict.

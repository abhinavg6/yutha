# Building a Microsoft Agent Framework agent on Yutha

A walkthrough for developers and AI engineers who want to put
Microsoft Agent Framework (MAF) agents on top of Yutha's
coordination substrate. Companion to the
[LangGraph guide](langgraph.md) and the
[CrewAI guide](crewai.md) — same substrate, different framework
idioms.

By the end you'll have:

- A signed, registered MAF `ChatAgent` talking to a real Yutha
  control plane.
- A MAF agent whose `Agent.run(...)` is driven by inbound Yutha
  envelopes, with each run producing its own audit-log trail.
- A MAF async tool callable wrapped with `@capability_required`
  so server-side capability gates fire when the callable emits
  a Yutha envelope.
- A query against the audit log showing exactly which MAF agent
  did what.

**What you get for free.** Every message is Ed25519-signed by
its sender's MAF agent. Every send, every delivery, every
capability check, every admission/revocation produces a content-
addressed receipt. The 1:1 mapping between MAF `Agent` instances
and Yutha agents means the audit log records the actual
decision-making agent for each action, not a workflow-level
aggregate.

**What you write.** Three things: per-agent passports, the MAF
`Agent` instances themselves, and optional `@capability_required`
wrappers on sensitive async tool callables. Everything else —
bearer-token minting, signature verification, stream
multiplexing, receipt emission — happens below the SDK surface.

If you haven't built an agent on top of Yutha before, the
[LangGraph guide](langgraph.md) is a gentler starting point (its
handler is a synchronous state graph with no LLM dependency).
This walkthrough assumes you're already comfortable with MAF's
`Agent` / `ChatAgent` / `agent.run(...)` surface and its async-
native tool callable model.

---

## Prerequisites

You need four things on hand before any of the snippets work.

**1. A running control plane** in open admission mode:

```bash
export YUTHA_BOOTSTRAP_SEED=$(python -c \
    'import secrets; print(secrets.token_hex(32))')

cargo run -p yutha-control-plane -- --admission-mode open
```

**2. The Python SDK installed with the `maf` extra:**

```bash
pip install 'yutha[maf]'   # core SDK + MAF adapter
```

The `maf` extra pulls in `agent-framework-core` and
`agent-framework-openai` — the two narrowed packages the adapter
actually needs — rather than the umbrella `agent-framework`
distribution. The reason is concrete: the umbrella package
carries a pre-release `azure-search-documents>=11.7.0b2`
dependency, which would force every installer to add
`--prerelease=allow` to `pip` (or `--prerelease=if-necessary` to
`uv`) just to satisfy resolution. Narrowing to the two packages
the adapter exercises avoids that footgun. If you want MAF's
other chat clients (Foundry, Azure OpenAI, Anthropic, …) install
them alongside as needed: `pip install 'yutha[maf]'
agent-framework-foundry`.

Working from a repo clone instead of PyPI? Use an editable
install: `cd sdks/python && uv pip install -e '.[dev,maf]'`.

A **package-name note** that catches people once and then never
again: the PyPI distribution is `agent-framework` (hyphen) but
the importable Python module is `agent_framework` (underscore).
The Yutha adapter is named `yutha.maf` rather than
`yutha.agent_framework` to keep imports short and to avoid any
confusion with the upstream framework's own packaging. So your
imports look like:

```python
from agent_framework import Agent
from agent_framework.openai import OpenAIChatClient
from yutha.maf import YuthaChatAgent, capability_required
```

**3. The same `YUTHA_BOOTSTRAP_SEED` exported in your dev shell**
so derived swarm_ids match.

**4. An LLM credential.** MAF's `Agent` constructor requires a
chat client. The simplest default is OpenAI via
`OpenAIChatClient`, which takes a `model=` kwarg (e.g.
`"gpt-4o-mini"`) and reads `OPENAI_API_KEY` from the environment:

```bash
export OPENAI_API_KEY=...
```

MAF also supports Foundry, Azure OpenAI, Anthropic, and several
other backends via dedicated chat-client classes — see MAF's docs
for switching providers. The Yutha adapter is provider-agnostic;
the choice only affects how each MAF agent reasons.

---

## Step 1 — Your first MAF agent on Yutha

The smallest useful pattern: mint a passport, connect, register a
MAF `Agent` under a Yutha identity, send a message to yourself,
receive it on the dispatch loop.

```python
import asyncio
import hashlib
import os
import secrets

from agent_framework import Agent
from agent_framework.openai import OpenAIChatClient

import yutha
from yutha.maf import YuthaChatAgent


async def main():
    # Derive swarm_id from the bootstrap seed.
    seed = bytes.fromhex(os.environ["YUTHA_BOOTSTRAP_SEED"])
    swarm_id = yutha.SwarmId(value=hashlib.sha256(seed + b"\x02").digest()[:16])

    # Mint a fresh identity for this MAF agent.
    signer = yutha.InProcessSigner.generate()
    agent_id = yutha.AgentId(value=secrets.token_bytes(16))

    passport = await yutha.Passport(
        spec_version="1.0.0",
        agent_id=agent_id,
        swarm_id=swarm_id,
        agent_public_key=signer.public_key(),
        owner="hello-yutha-maf",
        framework="maf",
        framework_version="1.0.0",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
        expires_at=yutha.Timestamp(
            wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62
        ),
    ).sign(signer)

    # Construct a MAF Agent. The chat client + instructions drive
    # the LLM reasoning; for the substrate-level integration these
    # are informational — what matters is that the wrapper gets a
    # real Agent instance to invoke run() against.
    maf_agent = Agent(
        client=OpenAIChatClient(model="gpt-4o-mini"),
        name="Greeter",
        instructions="Acknowledge inbound messages in one short sentence.",
    )

    # Wrap and connect. The wrapper's lifecycle mirrors
    # yutha.langgraph.YuthaAgent and yutha.crewai.YuthaCrewAgent —
    # register, async-context start + stop, send to emit envelopes.
    async with YuthaChatAgent.connect(
        "127.0.0.1:50051",
        passport=passport,
        signer=signer,
        maf_agent=maf_agent,
    ) as agent:
        await agent.register()
        await asyncio.sleep(0.1)  # let subscription settle

        # Send a message to ourselves. Returns the envelope.send
        # receipt id.
        receipt = await agent.send(
            recipient=yutha.Recipient.for_agent(agent_id),
            performative=yutha.Performative.INFORM,
            payload=b"hello from a MAF agent",
            payload_schema_id="type.yutha.dev/v1/Text",
        )
        print(f"sent; receipt = {receipt.digest.hex()[:16]}...")

        # The dispatch loop receives the envelope and, by default,
        # decodes the payload as UTF-8 and passes it as the input
        # argument to maf_agent.run(...). Wait a moment so the
        # async run has time to fire.
        await asyncio.sleep(0.5)


asyncio.run(main())
```

A few things to note:

- **The passport's `framework` field is `"maf"`.** Useful for
  audit-log filtering and analytics later on; doesn't affect any
  wire semantics. Demos that register multiple distinct MAF
  agents tend to use more specific labels (e.g.
  `"maf-devops-alerting"`, `"maf-devops-triage"`) so the audit
  trail attributes work by role.
- **The signing key never leaves your process.** The Yutha
  control plane verifies every envelope's signature against the
  public key on the passport.
- **`YuthaChatAgent` is *not* itself a MAF Agent.** It wraps
  one. The wrapping is deliberate: the wrapper owns the gRPC
  channel, the registration, the subscribe stream, and the
  signing key — none of which MAF cares about.

---

## Step 2 — The dispatch loop: envelope → agent.run

When `YuthaChatAgent.start()` runs, it opens a subscribe stream
and for each inbound envelope it:

1. Asks the **input factory** to convert the envelope into the
   `input` argument for the next `Agent.run(...)` call. The
   default factory decodes `envelope.payload` as UTF-8 and uses
   that string directly.
2. Invokes `await maf_agent.run(input)`. Tool calls inside that
   run that go through `@capability_required`-wrapped callables
   thread the held cap_id into outbound sends.
3. Hands the result to your optional **on_output** callback,
   which can inspect what `Agent.run` returned and emit a follow-
   on envelope via `agent.send(...)`.

A typical input factory looks like this:

```python
def my_input_factory(agent, envelope, deliver_receipt):
    # Parse the inbound payload. Branch on payload_schema_id if
    # you support multiple kinds of inbound messages.
    if envelope.payload_schema_id == "type.yutha.dev/v1/Ticket":
        return (
            f"Process this ticket and produce a short customer-"
            f"facing acknowledgment:\n{envelope.payload.decode()}"
        )
    # Skip envelopes we don't know how to handle.
    return None


async def on_output(agent, envelope, result):
    # `result` is whatever Agent.run returned. Extract the
    # customer-facing text and emit it as a follow-on envelope.
    await agent.send(
        recipient=envelope.recipient,
        performative=yutha.Performative.INFORM,
        payload=str(result).encode("utf-8"),
        in_reply_to=...,  # the inbound envelope id
    )
```

Returning `None` from the input factory **skips** the inbound
envelope. Use that for filtering — for example, the devops
incident demo's orchestrator drives every `Agent.run` directly
and passes `input_factory=lambda a, e, d: None` to make the
dispatch loop a no-op for every wrapped agent (avoids cascade
behavior when the orchestrator is the one driving turns).

A concrete contrast with CrewAI worth calling out: CrewAI tool
bodies are synchronous, so the CrewAI adapter has to bridge sync
→ async via `asyncio.run_coroutine_threadsafe` whenever a tool
wants to emit a Yutha envelope. MAF's `Agent.run` and its tool
callables are async-native end-to-end, which means there's no
thread-bridge boilerplate inside the dispatch loop or inside
your tool bodies. Contextvars propagate cleanly inside the same
event loop, which is also what makes the cap-gating decorator in
Step 3 work as-is.

---

## Step 3 — Gating async tool callables with capabilities

When a MAF tool callable performs something sensitive (issuing a
refund, applying a production schema change, sending PII), you
want a server-side gate rather than a client-side check the
agent could remove. That's what capabilities are for.

A capability is a signed grant scoped to a specific action. The
`yutha.maf.capability_required` decorator wraps an async tool
callable so that, during its execution:

1. The held cap's scope is validated against the declared
   `action_kind` (a mismatch raises `CapabilityDenied` at
   decoration time, before the tool can run).
2. The cap's content-address is threaded into a context-local
   variable that `YuthaChatAgent.send` reads, so any send made
   *during the tool's execution* picks up the cap_id
   automatically. On a server-side cap-check deny (revoked,
   expired, out-of-scope) the send call raises
   `CapabilityDenied`.

```python
from yutha.maf import capability_required


# Issue the capability server-side first.
remediation_cap = yutha.Capability(
    spec_version="1.0.0",
    capability_id=secrets.token_bytes(16),
    swarm_id=swarm_id,
    issuer=yutha.Issuer.for_agent(remediation.agent_id),
    subject=remediation.agent_id,
    scope=yutha.Scope.for_action("envelope.send"),
    valid_from=yutha.Timestamp.now(),
    valid_until=yutha.Timestamp(
        wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62
    ),
)
cap_id, _ = await remediation.client.capability.issue(remediation_cap)


# Wrap the async tool callable.
@capability_required(remediation_cap, action_kind="envelope.send")
async def apply_action(action_description: str, schema_change: bool) -> yutha.Hash:
    tags = ["production_action"]
    if schema_change:
        tags.append("schema_change")
    return await remediation.send(
        recipient=yutha.Recipient.for_agent(audit_recipient_id),
        performative=yutha.Performative.INFORM,
        payload=action_description.encode("utf-8"),
        tags=tags,
    )


# Pass the wrapped callable to a MAF Agent's tools list.
remediation_maf = Agent(
    client=OpenAIChatClient(model="gpt-4o-mini"),
    name="Remediation",
    instructions="Apply production rollbacks when requested.",
    tools=[apply_action],
)
```

When the LLM decides to call `apply_action`, MAF invokes the
async callable. The decorator sets the contextvar; the body
calls `remediation.send(...)`; the send's gRPC call carries the
cap_id; the server runs the RFC 0007 cap-check and emits the
load-bearing `capability.check.{pass,deny}` receipt.

The contextvar threading is identical to the LangGraph, CrewAI,
and OpenAI Agents adapters. The win here is that MAF's async-
native tool surface means **no thread-bridge boilerplate** — the
wrapped callable just `await`s `remediation.send(...)` directly,
the dispatch loop's event loop owns the gRPC channel, and the
contextvar propagates inside the same task tree without any
extra glue.

---

## Step 4 — Reading the audit log

The Yutha control plane writes a signed receipt for every
substrate-level action. To query them from a MAF agent:

```python
async with YuthaChatAgent.connect(...) as agent:
    # Most recent 20 capability.check.pass receipts.
    receipts, _next_page = await agent.client.receipt.query_by_action_kind(
        "capability.check.pass", limit=20
    )
    for receipt in receipts:
        print(receipt.action_kind, receipt.actor)
```

The same query works against any of the canonical action_kinds —
see [`/spec/receipt/canonical-actions.md`](https://github.com/abhinavg6/yutha/blob/main/spec/receipt/canonical-actions.md)
for the full list. Useful kinds for a MAF integration:

- `envelope.send` / `envelope.deliver` — every signed send.
- `capability.check.{pass,deny}` — every cap gate fired by the
  RFC 0007 server-side check.
- `constitution.evaluate.{pass,deny}` — every Cedar+ evaluation.
- `agent.register` / `agent.revoke` — admission lifecycle.

---

## Step 5 — The worked example

[`examples/devops_incident.py`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/examples/devops_incident.py)
ties everything together: five MAF agents
(`alerting` / `triage` / `remediation` / `post_mortem` /
`human_sre`) registering into a fresh swarm, a custom
constitution that forbids production `schema_change` actions
without an `sre_countersigned` tag, a cap-gated `apply_action`
callable on the remediation agent, an LLM-driven exploration
phase, and a fully deterministic substrate phase that exercises
the four-stage detect/coach/quarantine/evict enforcement chain.

For a step-by-step walkthrough of what each phase does and how
the audit-trail assertion is structured, see the applied
[devops incident-response example](../examples/devops-incident.md).
That page is the place for *narrative*; this page is the place
for *adapter mechanics*.

Run it:

```bash
export OPENAI_API_KEY=...
export YUTHA_BOOTSTRAP_SEED=$(python -c \
    'import secrets; print(secrets.token_hex(32))')

# Terminal A — the control plane needs the operator pubkey
# derived from the same seed.
cargo run -p yutha-control-plane -- \
    --admission-mode open \
    --operator-public-key $(python sdks/python/examples/devops_incident.py --print-operator-pubkey)

# Terminal B (with the same seed exported)
python sdks/python/examples/devops_incident.py
```

---

## Step 6 — v1 scope vs documented follow-ons

The v1 adapter is deliberately the smallest substrate-correct
integration that exercises MAF's `Agent` surface, and several
MAF-distinctive capabilities are tracked as follow-ons rather
than v1 features. Setting expectations here matters more than
for the other adapters because MAF's value proposition leans
heavily on its workflow and middleware primitives, and the v1
adapter doesn't yet wire those into the substrate. The source
of truth for this list is the
[`yutha.maf` package docstring](https://github.com/abhinavg6/yutha/blob/main/sdks/python/src/yutha/maf/__init__.py);
this section reproduces it in walk-through form.

**`WorkflowBuilder` integration.** v1 drives agents directly —
the orchestrator calls `await alerting.run(incident)` and so on.
MAF's graph-based `WorkflowBuilder` is the natural next step:
compose the runbook as a workflow
(`alerting → triage → remediation → post_mortem`), where each
workflow edge emits a Yutha envelope so the graph's execution
trace shows up in the audit log alongside the substrate's own
receipts. The adapter primitives already support this; the
demo's orchestrator path would just swap to `workflow.run(...)`.

**`RequestInfoExecutor` and HITL.** v1 has a `human_sre` agent
that gets registered but isn't driven through MAF's formal
human-in-the-loop primitive. Wiring `RequestInfoExecutor` so the
request + countersign cycle produces `approval_required` and
`countersigned` Yutha receipts is the natural HITL upgrade. The
substrate's receipt vocabulary already has slots for these; the
v1 demo just doesn't exercise them because the cap-gating +
constitution-deny path covers the substrate behavior we wanted
to verify first.

**`AgentMiddleware` / `FunctionMiddleware` as the cap-gating
hook.** v1 reuses the contextvar-based `@capability_required`
decorator the other three adapters use, which works because
MAF's tool invocation is async-native and contextvars propagate
cleanly across `await` boundaries inside the same event loop. A
future revision could move cap-gating into a
`YuthaFunctionMiddleware` for tighter MAF middleware-pipeline
integration — both approaches produce identical substrate
behavior, so this is stylistic rather than corrective.

**Checkpoint receipts.** MAF's checkpoint primitive is distinct
from Yutha's receipt log — checkpoints capture workflow state
for replay, receipts attest to substrate-level actions. Bridging
them would let workflow checkpoint events surface in the audit
trail (and conversely, let receipt queries serve as a coarse
checkpoint timeline for workflows that don't need full state
capture).

**OpenTelemetry bridge.** MAF emits OTel spans for agent runs,
workflow execution, and tool invocations. Bridging those to
Yutha telemetry receipts (or in the other direction, building a
Yutha OTel exporter so the substrate participates in an
operator's existing OTel stack) is useful when an operator
already has the observability plumbing and wants the substrate
to slot into it.

Frame these as deliberate v1 scoping decisions. The substrate-
correct integration is here today; the MAF-distinctive features
layer on top of the same core `YuthaChatAgent` wrapper without
requiring it to change shape. The v1 surface is sufficient for
the end-to-end demos that the substrate's audit-trail assertions
care about.

---

## Where to go from here

- **Layer a constitution.** Use the
  [operator quickstart](../operator/quickstart.md) to author and
  activate a Cedar+ constitution; every send through a MAF
  agent will then be evaluated against it, with denies
  surfacing as `yutha.ConstitutionDenied`.
- **Provider switching.** MAF supports Foundry, Azure OpenAI,
  Anthropic, and others via dedicated chat clients. Install
  alongside the `[maf]` extra as needed — e.g.
  `pip install 'yutha[maf]' agent-framework-foundry` — and swap
  the `OpenAIChatClient` argument on each `Agent` for the
  appropriate alternative. Yutha is provider-agnostic.
- **Hybrid swarms.** Nothing prevents a MAF agent from sharing
  a swarm with LangGraph, CrewAI, or OpenAI Agents agents. They
  register the same way, sign with the same Ed25519 algorithm,
  and produce the same receipts. The audit log records the
  `framework` field per passport, so you can attribute behavior
  to the right framework after the fact. The devops example
  already uses distinct `framework` labels per agent
  (`maf-devops-alerting`, etc.) which is the pattern to copy.
- **Spec reference.** The
  [substrate spec](https://github.com/abhinavg6/yutha/tree/main/spec/)
  is the authoritative description of the wire format —
  passport, envelope, receipt, capability, topology. The MAF
  adapter implements the same wire contract as every other
  adapter, so anything you read in `/spec/` applies directly.

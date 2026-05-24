# Building an OpenAI Agents agent on Yutha

A walkthrough for developers and AI engineers who want to put
OpenAI Agents agents on top of Yutha's coordination substrate.
Companion to the [LangGraph guide](langgraph.md) and the
[CrewAI guide](crewai.md) — same substrate, different framework
idioms. The distinctive piece here is OpenAI Agents' **handoff**
primitive: every inter-agent transition the LLM performs becomes
a signed Yutha envelope on the audit log.

By the end you'll have:

- A signed, registered OpenAI Agents agent talking to a real
  Yutha control plane.
- Two `agents.Agent` instances exchanging control via handoffs,
  with each handoff producing a signed envelope between distinct
  Yutha identities.
- A `function_tool` callable wrapped with `@capability_required`
  so server-side capability gates fire when the tool emits a
  Yutha envelope.
- A query against the audit log showing the full handoff chain
  plus every cap-check that gated it.

**What you get for free.** Every message — including each
handoff-audit envelope the bridge emits — is Ed25519-signed by
its sender. Every send, every delivery, every capability check,
every admission/revocation produces a content-addressed receipt.
The 1:1 mapping between OpenAI Agents `Agent` instances and
Yutha agents means the audit log records which agent handed off
to which, when, and with what conversation state — not a
Runner-level aggregate.

**What you write.** Three things: per-agent passports, the
`agents.Agent` instances themselves (with their `instructions`,
`tools`, and `handoffs` lists), and optional
`@capability_required` wrappers on sensitive `function_tool`
callables. Everything else — bearer-token minting, signature
verification, the handoff bridge, stream multiplexing, receipt
emission — happens below the SDK surface.

If you haven't built an agent on top of Yutha before, the
[LangGraph guide](langgraph.md) is a gentler starting point (its
handler is a synchronous state graph with no LLM dependency).
This walkthrough assumes you're already comfortable with OpenAI
Agents' `Agent` / `Runner` / `function_tool` / `handoffs` model.

---

## Prerequisites

You need four things on hand before any of the snippets work.

**1. A running control plane** in open admission mode:

```bash
export YUTHA_BOOTSTRAP_SEED=$(python -c \
    'import secrets; print(secrets.token_hex(32))')

cargo run -p yutha-control-plane -- --admission-mode open
```

**2. The Python SDK installed with the `openai-agents` extra:**

```bash
pip install 'yutha[openai-agents]'   # core SDK + OpenAI Agents adapter
```

The `openai-agents` extra pulls the upstream OpenAI Agents SDK
in (which itself brings the OpenAI Python SDK, `litellm` for
cross-provider model support, and tracing/MCP transitive
dependencies). The base `yutha` install doesn't carry any of
that — see the rationale in
[`pyproject.toml`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/pyproject.toml).

Working from a repo clone instead of PyPI? Use an editable
install:
`cd sdks/python && uv pip install -e '.[dev,openai-agents]'`.

A note on import paths: the PyPI package is `openai-agents`,
but the importable Python module is `agents`. So it's
`from agents import Agent, Runner, function_tool` — not
`from openai_agents import ...`. The Yutha adapter follows the
same convention internally.

**3. The same `YUTHA_BOOTSTRAP_SEED` exported in your dev shell**
so derived swarm_ids match.

**4. An OpenAI Agents LLM credential.** Unlike the LangGraph
adapter (whose handler can be a deterministic state graph), the
OpenAI Agents Runner *always* invokes an LLM on each turn. The
simplest default is OpenAI:

```bash
export OPENAI_API_KEY=...
```

Other providers work via the framework's LiteLLM integration —
see the upstream
[OpenAI Agents docs](https://github.com/openai/openai-agents-python)
for switching defaults. The Yutha adapter is LLM-agnostic; the
choice only affects how each Agent reasons.

---

## Step 1 — Your first OpenAI Agents agent on Yutha

The smallest useful pattern: mint a passport, connect, register
an `agents.Agent` under a Yutha identity, send a message to
yourself, and have the dispatch loop convert it into a
`Runner.run` call.

```python
import asyncio
import hashlib
import os
import secrets

from agents import Agent

import yutha
from yutha.openai_agents import YuthaOpenAIAgent


async def main():
    # Derive swarm_id from the bootstrap seed.
    seed = bytes.fromhex(os.environ["YUTHA_BOOTSTRAP_SEED"])
    swarm_id = yutha.SwarmId(value=hashlib.sha256(seed + b"\x02").digest()[:16])

    # Mint a fresh identity for this OpenAI Agents agent.
    signing_key = yutha.SigningKey.generate()
    agent_id = yutha.AgentId(value=secrets.token_bytes(16))

    passport = yutha.Passport(
        spec_version="1.0.0",
        agent_id=agent_id,
        swarm_id=swarm_id,
        agent_public_key=signing_key.public_key(),
        owner="hello-yutha-openai-agents",
        framework="openai-agents",
        framework_version="0.x",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
        expires_at=yutha.Timestamp(
            wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62
        ),
    ).sign(signing_key)

    # Construct an OpenAI Agents Agent. instructions/tools/handoffs
    # drive the LLM reasoning; for the substrate-level integration
    # these are informational — what matters is that the wrapper
    # gets a real Agent instance to invoke Runner.run against.
    oai_agent = Agent(
        name="Greeter",
        instructions=(
            "You receive a short greeting and reply with a single "
            "short sentence acknowledging it."
        ),
    )

    # Wrap and connect. Lifecycle mirrors yutha.crewai.YuthaCrewAgent
    # and yutha.langgraph.YuthaAgent — register, async-context
    # start + stop, send to emit envelopes.
    async with YuthaOpenAIAgent.connect(
        "127.0.0.1:50051",
        passport=passport,
        signing_key=signing_key,
        oai_agent=oai_agent,
    ) as agent:
        await agent.register()
        await asyncio.sleep(0.1)  # let subscription settle

        # Send a message to ourselves. Returns the envelope.send
        # receipt id.
        receipt = await agent.send(
            recipient=yutha.Recipient.for_agent(agent_id),
            performative=yutha.Performative.INFORM,
            payload=b"hello from an OpenAI Agents agent",
            payload_schema_id="type.yutha.dev/v1/Text",
        )
        print(f"sent; receipt = {receipt.digest.hex()[:16]}...")

        # The dispatch loop receives the envelope and, by default,
        # converts its payload to a UTF-8 string and passes it to
        # Runner.run on the wrapped Agent. Wait a moment so the
        # LLM round-trip has time to complete.
        await asyncio.sleep(5.0)


asyncio.run(main())
```

A few things to note:

- **The passport's `framework` field is `"openai-agents"`.**
  Useful for audit-log filtering and analytics later on; doesn't
  affect any wire semantics.
- **The signing key never leaves your process.** The Yutha
  control plane verifies every envelope's signature against the
  public key on the passport.
- **`YuthaOpenAIAgent` is *not* itself an `agents.Agent`.** It
  wraps one. The wrapping is deliberate: the wrapper owns the
  gRPC channel, the registration, the subscribe stream, the
  `RunHooks` instance, and the signing key — none of which
  OpenAI Agents cares about.
- **No sync/async bridge.** OpenAI Agents' `Runner.run` is fully
  async, so the dispatch loop just `await`s it directly. No
  thread-offload, no `run_coroutine_threadsafe` — contrast the
  CrewAI guide where sync `kickoff()` forces a worker thread.

---

## Step 2 — The dispatch loop and the `RunHooks` handoff bridge

This is the part that's distinctively OpenAI Agents. When
`YuthaOpenAIAgent.start()` runs, it opens a subscribe stream and
for each inbound envelope it:

1. Asks the **input factory** to convert the envelope into the
   `input` argument for the next `Runner.run` call. The default
   factory decodes `envelope.payload` as UTF-8 and returns it as
   a single-turn user message — and explicitly skips
   handoff-audit envelopes (more on those below) so the bridge
   doesn't cascade into spurious extra runs.
2. Invokes `Runner.run(self._oai_agent, input, hooks=...)` with
   a lazily-constructed `YuthaRunHooks` attached. The hooks
   subclass `agents.lifecycle.RunHooksBase` and ride along
   through the entire turn — including any handoffs.
3. Hands the resulting `RunResult` to your optional `on_output`
   callback if you supplied one, which can emit follow-on
   envelopes via `agent.send(...)`.

The bridge does *not* emit substrate receipts on tool
boundaries or agent start/end. OpenAI Agents ships its own
tracing for those, and adding parallel substrate receipts would
just multiply audit noise without adding signal. The
substrate-relevant tool event is the `Send` a cap-gated tool
makes, which produces its own `capability.check.*` receipt
naturally.

### How handoffs cross the wire

OpenAI Agents represents multi-agent flows as a graph of
`Agent` instances joined by `handoffs=[other_agent, ...]`
lists. When the Runner decides (LLM-driven) to transfer control
from agent A to agent B, it invokes
`on_handoff(context, from_agent, to_agent)` on every attached
hooks instance. The Yutha bridge's `on_handoff` implementation
turns each transition into a signed Yutha envelope:

```python
# Inside YuthaRunHooks (yutha/openai_agents/hooks.py):
async def on_handoff(self, context, from_agent, to_agent):
    from_name = getattr(from_agent, "name", "?")
    to_name = getattr(to_agent, "name", "?")

    # Look up the source wrapper so the audit envelope is
    # attributed to the actual source agent, not always to the
    # wrapper that owns the hooks. Falls back to the owning
    # wrapper when the source isn't registered.
    source_wrapper = registry.get(from_name, wrapper)
    peer = registry.get(to_name)
    recipient = (
        Recipient.for_agent(peer.agent_id)
        if peer is not None
        else Recipient.for_agent(source_wrapper.agent_id)
    )
    await source_wrapper.send(
        recipient=recipient,
        performative=Performative.INFORM,
        payload=f"handoff: {from_name} -> {to_name}".encode(),
        payload_schema_id="type.yutha.dev/v1/HandoffAudit",
        tags=[
            "openai_agents_handoff",
            f"handoff_from:{from_name}",
            f"handoff_to:{to_name}",
        ],
    )
```

Two details worth internalizing.

**The peer registry is what makes attribution real.** Each
`YuthaOpenAIAgent` constructs its hooks lazily on first run; you
register the rest of the swarm against those hooks before
kicking off a `Runner.run`. The registry maps
`agents.Agent.name` (a string) to a `YuthaOpenAIAgent` wrapper:

```python
peer_registry = {
    "ResearchFactChecker": wrappers["fact_checker"],
    "ResearchEditor": wrappers["editor"],
    "ResearchResearcher": wrappers["researcher"],
}
for wrapper in wrappers.values():
    wrapper._get_hooks().register_peers(peer_registry)
```

With the registry populated, every handoff `A → B` produces an
envelope signed by A's key, addressed to B's inbox, tagged with
both names. Without it, the bridge falls back to a self-loop —
still produces `envelope.send` + `envelope.deliver` receipts,
but they go from and to the owning wrapper, which is less
useful for reconstructing the actual collaboration chain.

**Source-wrapper lookup is what makes multi-hop chains correct.**
A `Runner.run` started on agent A that transitions A → B → C
calls `on_handoff` twice — once with `from_agent=A` and once
with `from_agent=B`. Without the `registry.get(from_name, ...)`
lookup, both envelopes would be attributed to whichever wrapper
owns the hooks (A), which is wrong for the second hop. With the
lookup, the second envelope is correctly emitted from B's
identity. This is what the `hooks.py` comment calls out
explicitly when it says "the substrate audit log captures every
inter-agent transfer the LLM-driven Runner performs" — without
the source-wrapper lookup, attribution would silently degrade
on every chain longer than a single hop.

### The contract: 1:1 Agent ↔ Yutha identity

Each `agents.Agent` in a multi-agent flow gets its own Yutha
passport, signing key, `agent.register` receipt, and dispatch
loop. Handoffs cross the Yutha wire as signed envelopes between
two distinct `agent_id` values. Compared to running an OpenAI
Agents flow under a single Yutha identity, this trades a small
amount of setup for substantially better forensics — the audit
log answers "which agent handed off to which, when, and what
prompted it" without you instrumenting anything yourself.

You can opt out per-wrapper by passing
`emit_handoff_envelopes=False`, which keeps the hooks attached
but reduces them to a stdout log. Useful for unit tests that
shouldn't have substrate side effects.

---

## Step 3 — Gating `function_tool` callables with capabilities

When a tool performs something sensitive (publishing a brief,
issuing a refund, calling a payment API, sending PII), you want
a server-side gate rather than a client-side check the LLM
could bypass by editing the function body. That's what
capabilities are for.

A capability is a signed grant scoped to a specific action. The
`yutha.openai_agents.capability_required` wrapper modifies a
callable so that, during its execution:

1. The held cap's scope is validated against the declared
   `action_kind` (a mismatch raises `CapabilityDenied`
   immediately at decoration time — catches the "I wrapped this
   tool with the wrong action_kind for the cap I hold" error
   before the tool runs once).
2. The cap's content-address is threaded into a context-local
   variable that `YuthaOpenAIAgent.send` reads, so any send made
   *during the tool's execution* picks up the `cap_id`
   automatically. On a server-side cap-check deny (revoked,
   expired, out-of-scope, subject quarantined) the send call
   raises `CapabilityDenied`.

The contextvar is the same `ACTIVE_CAPABILITY_ID` the LangGraph
and CrewAI adapters use — all three share a single mechanism so
a downstream that mixes frameworks needs only one `except`
clause for `CapabilityDenied`.

A typical wrap-and-issue pattern, lifted from the research-crew
example:

```python
from agents import function_tool

from yutha.openai_agents import capability_required


# Issue the cap server-side first.
editor_cap = yutha.Capability(
    spec_version="1.0.0",
    capability_id=secrets.token_bytes(16),
    swarm_id=swarm_id,
    issuer=yutha.Issuer.for_agent(editor_id),
    subject=editor_id,
    scope=yutha.Scope.for_action("envelope.send"),
    valid_from=yutha.Timestamp.now(),
    valid_until=yutha.Timestamp(
        wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62
    ),
)
cap_id, _ = await editor_wrapper.client.capability.issue(editor_cap)


# Wrap the callable. capability_required sets the contextvar
# for the duration of every invocation; function_tool exposes
# it to the LLM as a callable tool with a JSON schema.
@capability_required(editor_cap, action_kind="envelope.send")
async def publish_brief(content: str, cited: bool) -> yutha.Hash:
    tags = ["claim_published"]
    if cited:
        tags.append("verified_citations")
    return await editor_wrapper.send(
        recipient=yutha.Recipient.for_agent(publisher_id),
        performative=yutha.Performative.INFORM,
        payload=content.encode("utf-8"),
        payload_schema_id="type.yutha.dev/v1/Text",
        tags=tags,
    )


# Attach to the agent's tools list — the LLM can now call it.
editor_agent.tools = [function_tool(publish_brief)]
```

When the LLM decides to call `publish_brief`, OpenAI Agents
invokes the wrapped callable. `capability_required` sets the
contextvar; the body's `await editor_wrapper.send(...)` reads
it; the resulting gRPC `Send` request carries the cap_id; the
server runs the RFC 0007 cap-check and emits the load-bearing
`capability.check.{pass,deny}` receipt.

**Composition order is flexible.** Both
`@function_tool` / `@capability_required` (function_tool
outermost) and `@capability_required` / `@function_tool`
(capability_required outermost) work; the wrapper detects which
kind of target it received and patches the right hook. The
research-crew demo uses the canonical form — decorate the plain
async function with `capability_required`, then pass it through
`function_tool` at attach time — because the gate is the first
thing the reader sees on the source line.

**No sync/async bridging hassle.** Because OpenAI Agents'
`function_tool` callables are async-native, there's no
worker-thread bridging like the CrewAI adapter requires for
sync tool bodies. The contextvar set by `capability_required`
propagates naturally through `await editor_wrapper.send(...)`
inside the same event loop.

---

## Step 4 — Reading the audit log

The Yutha control plane writes a signed receipt for every
substrate-level action. To query them from an OpenAI Agents
agent:

```python
async with YuthaOpenAIAgent.connect(...) as agent:
    # Most recent 20 capability.check.pass receipts.
    page = await agent.client.receipt.query_by_action_kind(
        "capability.check.pass", limit=20
    )
    for receipt in page.receipts:
        print(receipt.action_kind, receipt.actor)
```

The same query works against any of the canonical action_kinds
— see [`/spec/receipt/canonical-actions.md`](https://github.com/abhinavg6/yutha/blob/main/spec/receipt/canonical-actions.md)
for the full list. Useful kinds for an OpenAI Agents
integration:

- `envelope.send` / `envelope.deliver` — every signed send,
  including **the handoff-audit envelopes the bridge emits**.
  Filter those by `tags` (every handoff envelope carries
  `openai_agents_handoff` plus `handoff_from:<name>` and
  `handoff_to:<name>`) to reconstruct the full agent
  collaboration chain that a given `Runner.run` traversed.
- `capability.check.{pass,deny}` — every cap gate fired by the
  RFC 0007 server-side check. One per `function_tool` invocation
  whose body emits a send.
- `constitution.evaluate.{pass,deny}` — every Cedar+ evaluation
  that ran against an envelope (if you've activated a
  constitution; see the operator guide).
- `agent.register` / `agent.revoke` — admission lifecycle.

The handoff-audit tag scheme is the load-bearing piece for
OpenAI Agents specifically. Filter on `openai_agents_handoff`
and you've got every inter-agent transition the swarm has ever
performed, with full sender + recipient attribution and
content-addressed signatures. The audit log is the source of
truth for "what did the multi-agent flow actually do" without
you instrumenting the framework yourself.

---

## Step 5 — The worked example

[`examples/research_crew.py`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/examples/research_crew.py)
ties everything together: three OpenAI Agents agents
(researcher → fact_checker → editor) registering into a fresh
swarm, an editor whose `publish_brief` function tool is
cap-gated, a citation-enforcing constitution that forbids
`claim_published` envelopes lacking the `verified_citations`
tag, two bypass attempts that trip the four-stage enforcement
chain (detect → coach → quarantine → evict), and a split
audit-delta assertion to keep the substrate-correctness signal
crisp despite LLM nondeterminism in the handoff phase.

The applied walkthrough at
[Research crew with citation enforcement](../examples/research-crew.md)
covers the example end-to-end — the cast, the constitution, the
bridge wiring, the bypass-and-chain pattern, and why the
pre→mid / mid→after split exists. Read it after this page if
you want to see all the pieces work together against a real
control plane.

---

## Where to go from here

- **Layer a constitution.** Use the
  [operator quickstart](../operator/quickstart.md) to author and
  activate a Cedar+ constitution; every send through an OpenAI
  Agents agent will then be evaluated against it, with denies
  surfacing as `yutha.ConstitutionDenied`. The research-crew
  example is the reference for what an enforcement-active
  OpenAI Agents flow looks like end-to-end.
- **Custom LLMs.** OpenAI Agents supports model switching via
  its `model=` parameter on each `Agent` (and via LiteLLM for
  cross-provider configs). Yutha is LLM-agnostic — switch
  models freely; the substrate semantics don't change.
- **Hybrid swarms.** Nothing prevents an OpenAI Agents agent, a
  LangGraph agent, a CrewAI agent, and a Microsoft Agent
  Framework agent from sharing the same swarm. They register
  the same way, sign with the same Ed25519 algorithm, and
  produce the same receipts. The audit log records the
  `framework` field per passport, so you can attribute
  behavior to the right framework after the fact. A
  mixed-framework swarm demo is on the roadmap as a later
  capstone.
- **Spec reference.** The OpenAI Agents adapter is a thin
  wrapper around primitives defined in
  [`/spec/`](https://github.com/abhinavg6/yutha/tree/main/spec/) —
  passports, envelopes, capabilities, receipts. If you want to
  understand exactly what the bridge puts on the wire when it
  emits a handoff-audit envelope, that's where to look.

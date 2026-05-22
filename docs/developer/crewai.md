# Building a CrewAI agent on Yutha

A walkthrough for developers and AI engineers who want to put CrewAI
agents on top of Yutha's coordination substrate. Companion to the
[LangGraph guide](langgraph.md) — same substrate, different framework
idioms.

By the end you'll have:

- A signed, registered CrewAI agent talking to a real Yutha control
  plane.
- Two CrewAI agents exchanging envelopes, each with its own
  cryptographic identity on every send.
- A CrewAI tool wrapped with `@capability_required` so server-side
  capability gates fire when the tool emits a Yutha envelope.
- A query against the audit log showing exactly which CrewAI agent
  did what.

**What you get for free.** Every message is Ed25519-signed by its
sender's CrewAI agent. Every send, every delivery, every capability
check, every admission/revocation produces a content-addressed
receipt. The 1:1 mapping between CrewAI Agents and Yutha agents
means the audit log records the actual decision-making agent for
each action, not a Crew-level aggregate.

**What you write.** Three things: per-agent passports, the CrewAI
``Agent`` instances themselves, and optional ``@capability_required``
wrappers on sensitive tools. Everything else — bearer-token minting,
signature verification, stream multiplexing, receipt emission —
happens below the SDK surface.

If you haven't built an agent on top of Yutha before, the
[LangGraph guide](langgraph.md) is a gentler starting point (its handler is a synchronous state graph
with no LLM dependency). This walkthrough assumes you're already
comfortable with CrewAI's ``Agent`` / ``Task`` / ``Crew`` model.

---

## Prerequisites

You need four things on hand before any of the snippets work.

**1. A running control plane** in open admission mode:

```bash
export YUTHA_BOOTSTRAP_SEED=$(python -c \
    'import secrets; print(secrets.token_hex(32))')

cargo run -p yutha-control-plane -- --admission-mode open
```

**2. The Python SDK installed with the `crewai` extra:**

```bash
pip install 'yutha[crewai]'   # core SDK + CrewAI adapter
```

The `crewai` extra pulls CrewAI 0.70+ in (LangChain core + a few
transitive dependencies). The base `yutha` install doesn't carry
any of that — see the rationale in
[`pyproject.toml`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/pyproject.toml).

Working from a repo clone instead of PyPI? Use an editable install:
`cd sdks/python && uv pip install -e '.[dev,crewai]'`.

**3. The same `YUTHA_BOOTSTRAP_SEED` exported in your dev shell**
so derived swarm_ids match.

**4. A CrewAI-compatible LLM credential.** CrewAI's ``Agent``
constructor requires an LLM. The simplest default is OpenAI:

```bash
export OPENAI_API_KEY=...
```

CrewAI also supports Anthropic, Ollama, and several other backends
via its ``LLM`` class — see CrewAI's docs for switching defaults.
The Yutha adapter is LLM-agnostic; the choice only affects how each
CrewAI Agent reasons.

---

## Step 1 — Your first CrewAI agent on Yutha

The smallest useful pattern: mint a passport, connect, register a
CrewAI Agent under a Yutha identity, send a message to yourself,
receive it on the dispatch loop.

```python
import asyncio
import hashlib
import os
import secrets

from crewai import Agent

import yutha
from yutha.crewai import YuthaCrewAgent


async def main():
    # Derive swarm_id from the bootstrap seed.
    seed = bytes.fromhex(os.environ["YUTHA_BOOTSTRAP_SEED"])
    swarm_id = yutha.SwarmId(value=hashlib.sha256(seed + b"\x02").digest()[:16])

    # Mint a fresh identity for this CrewAI agent.
    signing_key = yutha.SigningKey.generate()
    agent_id = yutha.AgentId(value=secrets.token_bytes(16))

    passport = yutha.Passport(
        spec_version="1.0.0",
        agent_id=agent_id,
        swarm_id=swarm_id,
        agent_public_key=signing_key.public_key(),
        owner="hello-yutha-crewai",
        framework="crewai",
        framework_version="0.x",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
        expires_at=yutha.Timestamp(
            wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62
        ),
    ).sign(signing_key)

    # Construct a CrewAI Agent. Role/goal/backstory drive the LLM
    # reasoning; for the substrate-level integration these are
    # informational — what matters is that the wrapper gets a real
    # Agent instance to bind tasks to.
    crew_agent = Agent(
        role="Greeter",
        goal="Acknowledge inbound messages.",
        backstory="A simple agent that says hello.",
        allow_delegation=False,
    )

    # Wrap and connect. The wrapper's lifecycle mirrors
    # yutha.langgraph.YuthaAgent — register, async-context start +
    # stop, send to emit envelopes.
    async with YuthaCrewAgent.connect(
        "127.0.0.1:50051",
        passport=passport,
        signing_key=signing_key,
        crew_agent=crew_agent,
    ) as agent:
        await agent.register()
        await asyncio.sleep(0.1)  # let subscription settle

        # Send a message to ourselves. Returns the envelope.send
        # receipt id.
        receipt = await agent.send(
            recipient=yutha.Recipient.for_agent(agent_id),
            performative=yutha.Performative.INFORM,
            payload=b"hello from a CrewAI agent",
            payload_schema_id="type.yutha.dev/v1/Text",
        )
        print(f"sent; receipt = {receipt.digest.hex()[:16]}...")

        # The dispatch loop receives the envelope and, by default,
        # constructs a single-task Crew that asks crew_agent to
        # respond. Wait a moment so it has time to fire.
        await asyncio.sleep(0.5)


asyncio.run(main())
```

A few things to note:

- **The passport's `framework` field is `"crewai"`.** Useful for
  audit-log filtering and for analytics later on; doesn't affect
  any wire semantics.
- **The signing key never leaves your process.** The Yutha control
  plane verifies every envelope's signature against the public key
  on the passport.
- **`YuthaCrewAgent` is *not* itself a CrewAI Agent.** It wraps
  one. The wrapping is deliberate: the wrapper owns the gRPC
  channel, the registration, the subscribe stream, and the
  signing-key — none of which CrewAI cares about.

---

## Step 2 — The dispatch loop: envelope → Crew

When `YuthaCrewAgent.start()` runs, it opens a subscribe stream and
for each inbound envelope it:

1. Asks the **task factory** to convert the envelope into a CrewAI
   ``Task``. The default factory uses the payload (UTF-8) as the
   task description.
2. Wraps the task in a single-task, single-agent ``Crew`` and runs
   ``Crew.kickoff()``. CrewAI's kickoff is synchronous; the dispatch
   loop offloads it to a worker thread so the gRPC stream stays
   responsive.
3. Hands the crew's output to your optional **on_output** callback,
   which can inspect the result and emit a follow-on envelope via
   ``agent.send(...)``.

A real task factory typically looks like this:

```python
from crewai import Task


def my_task_factory(agent, envelope, deliver_receipt):
    # Parse the inbound payload. Branch on payload_schema_id if you
    # support multiple kinds of inbound messages.
    if envelope.payload_schema_id == "type.yutha.dev/v1/Ticket":
        return Task(
            description=f"Process this ticket:\n{envelope.payload.decode()}",
            expected_output="A short customer-facing acknowledgment.",
            agent=agent.crew_agent,
        )
    # Skip envelopes we don't know how to handle.
    return None


async def on_output(agent, envelope, output):
    # `output` is whatever Crew.kickoff returned (a CrewOutput
    # in modern CrewAI versions). Extract the customer-facing
    # text and emit it as a follow-on envelope.
    await agent.send(
        recipient=envelope.recipient,
        performative=yutha.Performative.INFORM,
        payload=str(output).encode("utf-8"),
        in_reply_to=...,  # the inbound envelope id
    )
```

Returning `None` from the task factory **skips** the inbound
envelope. Use that for filtering — for example, the demo's refund
clerk handles refund tickets and skips shipping tickets entirely.

---

## Step 3 — Gating tools with capabilities

When a CrewAI tool performs something sensitive (issuing a refund,
calling a payment API, sending PII), you want a server-side gate
rather than a client-side check the agent could remove. That's
what capabilities are for.

A capability is a signed grant scoped to a specific action. The
``yutha.crewai.capability_required`` wrapper modifies a CrewAI
``BaseTool`` instance so that, during its execution:

1. The held cap's scope is validated against the declared
   ``action_kind`` (a mismatch raises ``CapabilityDenied``
   immediately — caught at wire time, before the tool can run).
2. The cap's content-address is threaded into a context-local
   variable that ``YuthaCrewAgent.send`` reads, so any send made
   *during the tool's execution* picks up the cap_id automatically.
   On a server-side cap-check deny (revoked, expired, out-of-scope)
   the send call raises ``CapabilityDenied``.

```python
from crewai.tools import BaseTool

from yutha.crewai import capability_required


class IssueRefundTool(BaseTool):
    name: str = "issue_refund"
    description: str = "Issue a refund to a customer."

    def _run(self, customer_id: str, amount_cents: int) -> str:
        # Tool body — emits a Yutha envelope to the payments service.
        # The send is sync because CrewAI 0.x tool bodies are sync;
        # bridge to the dispatch-loop's event loop via
        # asyncio.run_coroutine_threadsafe (or asyncio.run for a
        # one-shot test).
        ...
        return "refund issued"


# Issue the capability server-side, then wrap the tool.
cap = yutha.Capability(
    spec_version="1.0.0",
    capability_id=secrets.token_bytes(16),
    swarm_id=swarm_id,
    issuer=yutha.Issuer.for_agent(my_agent.agent_id),
    subject=my_agent.agent_id,
    scope=yutha.Scope.for_action("envelope.send"),
    valid_from=yutha.Timestamp.now(),
    valid_until=yutha.Timestamp(
        wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62
    ),
)
cap_id, _ = await my_agent.client.capability.issue(cap)

# Wrap the tool. Mutation-in-place: the returned tool is the same
# instance, with its `_run` method patched to set the contextvar.
tool = capability_required(cap, action_kind="envelope.send")(IssueRefundTool())

crew_agent = Agent(
    role="Refunds clerk",
    goal="Issue refunds when the policy permits.",
    backstory="...",
    tools=[tool],
)
```

When the LLM decides to call ``issue_refund``, CrewAI invokes the
tool's ``_run``. The wrapper sets the contextvar; the body emits
its Yutha envelope; the send's gRPC call carries the cap_id; the
server runs the RFC 0007 cap-check and emits the load-bearing
``capability.check.{pass,deny}`` receipt.

**Bridging sync → async inside a tool.** CrewAI's tool bodies are
synchronous; ``YuthaCrewAgent.send`` is async. The cleanest pattern
is to bridge via the dispatch loop:

```python
loop = my_agent._dispatch_task.get_loop()
fut = asyncio.run_coroutine_threadsafe(
    my_agent.send(recipient=..., performative=..., payload=...),
    loop,
)
receipt = fut.result(timeout=5.0)
```

The dispatch loop owns the gRPC channel, so scheduling the send on
its loop avoids the cross-thread-channel issue.

---

## Step 4 — Reading the audit log

The Yutha control plane writes a signed receipt for every
substrate-level action. To query them from a CrewAI agent:

```python
async with YuthaCrewAgent.connect(...) as agent:
    # Most recent 20 capability.check.pass receipts.
    page = await agent.client.receipt.query_by_action_kind(
        "capability.check.pass", limit=20
    )
    for receipt in page.receipts:
        print(receipt.action_kind, receipt.actor)
```

The same query works against any of the canonical action_kinds —
see [`/spec/receipt/canonical-actions.md`](https://github.com/abhinavg6/yutha/blob/main/spec/receipt/canonical-actions.md)
for the full list. Useful kinds for a CrewAI integration:

- ``envelope.send`` / ``envelope.deliver`` — every signed send.
- ``capability.check.{pass,deny}`` — every cap gate fired by the
  RFC 0007 server-side check.
- ``constitution.evaluate.{pass,deny}`` — every Cedar+ evaluation.
- ``agent.register`` / ``agent.revoke`` — admission lifecycle.

---

## Step 5 — The worked example

[`examples/s1_support_queue_crewai.py`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/examples/s1_support_queue_crewai.py)
ties everything together: three CrewAI agents (router,
refund_clerk, supervisor) registering into a fresh swarm, a
capability-gated dispatch tool, three inbound tickets, an
escalation pattern, a cap revocation, and an end-of-run audit
delta query.

It's a focused companion to
[`examples/s1_support_queue.py`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/examples/s1_support_queue.py)
(the LangGraph port of the same Rust conformance scenario). The
LangGraph version uses deterministic state-graph nodes; the CrewAI
version exercises the LLM-driven path while keeping the routing
logic deterministic (a keyword classifier inside the tool body),
so the audit-trail delta stays predictable.

Run it:

```bash
export OPENAI_API_KEY=...
export YUTHA_BOOTSTRAP_SEED=$(python -c \
    'import secrets; print(secrets.token_hex(32))')

# Terminal A
cargo run -p yutha-control-plane -- --admission-mode open

# Terminal B (with the same seed exported)
python sdks/python/examples/s1_support_queue_crewai.py
```

---

## Where to go from here

- **Layer a constitution.** Use the
  [operator quickstart](../operator/quickstart.md) to author and
  activate a Cedar+ constitution; every send through a CrewAI
  agent will then be evaluated against it, with denies surfacing
  as ``yutha.ConstitutionDenied``.
- **Custom LLMs.** CrewAI's ``LLM`` class supports Anthropic,
  Ollama, custom endpoints, and more. Switch yours via the
  ``llm`` parameter on each ``Agent`` — Yutha is LLM-agnostic.
- **Hybrid swarms.** Nothing prevents a CrewAI agent and a
  LangGraph agent from sharing the same swarm. They register the
  same way, sign with the same Ed25519 algorithm, and produce
  the same receipts. The audit log records the ``framework``
  field per passport, so you can attribute behavior to the right
  framework after the fact.

# Building a LangGraph agent on Yutha

A 15-minute walkthrough for developers and AI engineers who want to put
LangGraph workflows on top of Yutha's coordination substrate. By the
end you'll have:

- A signed, registered agent talking to a real Yutha control plane.
- Two agents passing messages, with full cryptographic identity on
  every envelope.
- A LangGraph node that acts on inbound envelopes and emits new ones.
- Server-side capability gates wrapping the actions you care about.
- A query against the audit log showing every action the swarm took.

**What you get for free.** Every message is Ed25519-signed by its
sender. Every send, every delivery, every capability check, every
admission/revocation produces a content-addressed receipt that any
authenticated agent can query. You don't write any of that — the
substrate emits it automatically as long as you go through the
`YuthaClient` API.

**What you write.** Five things: passports (identity manifests), the
agent's envelope handler (typically a compiled LangGraph graph),
optional `@capability_required` decorators on sensitive nodes, and the
small bit of bootstrap code that wires it all together. Everything
else — bearer-token minting, signature verification, stream
multiplexing, receipt emission — happens below the SDK surface.

---

## Prerequisites

You need three things on hand before any of the snippets work.

**1. A running control plane.** From the repo root:

```bash
# Mint a fresh 32-byte seed once per session.
export YUTHA_BOOTSTRAP_SEED=$(python -c \
    'import secrets; print(secrets.token_hex(32))')

# Start the server in open admission mode so fresh agents can self-register.
# (Default is closed mode — production posture, where only allowlisted
#  agents can join. Open mode is the demo / dev knob.)
cargo run -p yutha-control-plane -- --admission-mode open
```

You should see a `WARN admission mode: OPEN ...` line in the startup
log. Leave this terminal running.

**2. The Python SDK installed.** In a separate terminal:

```bash
cd sdks/python
uv pip install -e '.[dev,langgraph]'   # langgraph extra pulls in LangGraph
```

**3. The same `YUTHA_BOOTSTRAP_SEED` in this terminal too** — it tells
your client which `swarm_id` to bind passports to. Without that, the
registry will reject every passport with "wrong swarm". Export it
again here:

```bash
export YUTHA_BOOTSTRAP_SEED=<paste the same hex from terminal A>
```

---

## Step 1 — Your first agent

The smallest useful agent: mints a passport, connects, registers,
sends a message to itself, receives it on the subscribe stream, and
shuts down cleanly.

```python
import asyncio
import hashlib
import os
import secrets

import yutha

async def main():
    # Derive swarm_id from the bootstrap seed — same hash the server uses,
    # so our passport binds to the registry's swarm.
    seed = bytes.fromhex(os.environ["YUTHA_BOOTSTRAP_SEED"])
    swarm_id = yutha.SwarmId(value=hashlib.sha256(seed + b"\x02").digest()[:16])

    # Mint an identity. The signing_key's public counterpart goes on the
    # passport; the substrate uses it to verify every envelope you sign.
    signing_key = yutha.SigningKey.generate()
    agent_id = yutha.AgentId(value=secrets.token_bytes(16))

    passport = yutha.Passport(
        spec_version="1.0.0",
        agent_id=agent_id,
        swarm_id=swarm_id,
        agent_public_key=signing_key.public_key(),
        owner="hello-yutha",
        framework="langgraph",
        framework_version="1.0.0",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
        # Open admission requires expires_at; far-future is fine for a demo.
        expires_at=yutha.Timestamp(
            wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62
        ),
    ).sign(signing_key)

    async with yutha.YuthaClient.connect(
        "127.0.0.1:50051",
        agent_id=agent_id,
        swarm_id=swarm_id,
        signing_key=signing_key,
    ) as client:
        # Register — anonymous RPC; passport IS the credential.
        await client.admission.register(passport)

        # Open the subscribe stream BEFORE sending so the server has the
        # inbox registered by the time the send arrives.
        async def collect():
            async for envelope, _deliver_id in client.envelope.subscribe():
                return envelope
        receive_task = asyncio.create_task(collect())
        await asyncio.sleep(0.1)

        # Build, sign, and send an envelope to ourselves.
        env = yutha.Envelope(
            spec_version="1.0.0",
            swarm_id=swarm_id,
            envelope_id=secrets.token_bytes(16),
            from_agent=agent_id,
            recipient=yutha.Recipient.for_agent(agent_id),
            performative=yutha.Performative.INFORM,
            payload=b"hello from yutha",
            payload_schema_id="type.yutha.dev/v1/Text",
            nonce=secrets.token_bytes(16),
            epoch=1,
            sent_at=yutha.Timestamp.now(),
        ).sign(signing_key)
        await client.envelope.send(env)

        delivered = await asyncio.wait_for(receive_task, timeout=3.0)
        print(f"received: {delivered.payload.decode()}")

asyncio.run(main())
```

Run it. You'll see `received: hello from yutha`. The server stored
three receipts in the audit log: `agent.register`, `envelope.send`,
and `envelope.deliver`. You can query for them at any time — see
the audit-log section below.

A few things to internalize about that snippet:

- **The signing key never leaves your process.** The server has
  the public counterpart on the registered passport and verifies
  every envelope's signature against it.
- **`secrets.token_bytes(16)` for `envelope_id` and `nonce`.** Both
  must be unique per send; the server's replay protection rejects
  duplicates within the configured window.
- **`epoch`** is a monotonic counter you maintain per-agent. The
  high-level `YuthaAgent` wrapper (next section) does this for you
  automatically.

---

## Step 2 — `YuthaAgent`: the high-level wrapper

Writing the subscribe/dispatch loop manually for every agent gets
old. `yutha.langgraph.YuthaAgent` packages it up — give it a handler
callback, enter its async context manager, and incoming envelopes
fire your handler automatically. The wrapper also tracks the epoch
counter and provides a one-line `agent.send(...)`.

```python
from yutha.langgraph import YuthaAgent

async def handler(agent, envelope, deliver_id):
    print(f"[{agent.agent_id}] got {len(envelope.payload)}B from {envelope.from_agent}")

agent = YuthaAgent.connect(
    "127.0.0.1:50051",
    passport=passport,
    signing_key=signing_key,
    handler=handler,
)
await agent.register()

async with agent:                        # starts the dispatch loop
    await agent.send(
        recipient=yutha.Recipient.for_agent(agent.agent_id),
        performative=yutha.Performative.INFORM,
        payload=b"hello from a YuthaAgent",
    )
    await asyncio.sleep(0.5)              # give the handler time to fire
```

The handler signature is fixed: `(agent: YuthaAgent, envelope: Envelope,
deliver_id: Hash) -> Awaitable[None]`. The first argument lets the
handler reach back into the agent to send replies, query receipts,
issue capabilities — whatever's appropriate.

---

## Step 3 — A LangGraph workflow as the handler

This is where Yutha + LangGraph actually clicks. Make your handler
invoke a compiled `StateGraph`. Each inbound envelope becomes a
graph invocation; nodes inside the graph can call `agent.send(...)`
to emit downstream envelopes, producing fan-out, escalation, or
reply patterns.

The five-agent demo bundled with the SDK
([`s1_support_queue.py`](../sdks/python/examples/s1_support_queue.py))
looks like this:

<p align="center">
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 720 460" width="720" role="img" aria-labelledby="diagram-title diagram-desc">
  <title id="diagram-title">S1 customer-support queue — agent message flow</title>
  <desc id="diagram-desc">Router at top fans three tickets out to billing, shipping, and returns. Returns then escalates to supervisor. Every send and delivery produces a signed receipt in the audit log.</desc>
  <defs>
    <marker id="arrow-dia" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor"/>
    </marker>
  </defs>
  <style>
    .box  { fill: none; stroke: currentColor; stroke-width: 1.5; }
    .box2 { fill: none; stroke: currentColor; stroke-width: 1.5; stroke-dasharray: 4 3; }
    .h    { font: 600 15px sans-serif; fill: currentColor; }
    .sub  { font: 12px sans-serif; fill: currentColor; opacity: 0.65; }
    .name { font: 600 13px sans-serif; fill: currentColor; text-anchor: middle; }
    .role { font: 11px sans-serif; fill: currentColor; opacity: 0.65; text-anchor: middle; }
    .edge { stroke: currentColor; stroke-width: 1.4; fill: none; }
    .lbl  { font: 11px ui-monospace, Menlo, Consolas, monospace; fill: currentColor; opacity: 0.75; text-anchor: middle; }
    .leg  { font: 11px sans-serif; fill: currentColor; opacity: 0.65; }
    .foot { font: 11px sans-serif; fill: currentColor; opacity: 0.65; text-anchor: middle; }
  </style>

  <text x="360" y="26" class="h" text-anchor="middle">S1 — customer-support queue</text>
  <text x="360" y="44" class="sub" text-anchor="middle">five agents · four envelopes · one capability check · one revocation</text>

  <rect x="295" y="78" width="130" height="55" rx="8" class="box"/>
  <text x="360" y="103" class="name">router</text>
  <text x="360" y="121" class="role">classifies + dispatches</text>

  <rect x="60" y="220" width="130" height="55" rx="8" class="box"/>
  <text x="125" y="245" class="name">billing</text>
  <text x="125" y="263" class="role">handles charges</text>

  <rect x="295" y="220" width="130" height="55" rx="8" class="box"/>
  <text x="360" y="245" class="name">shipping</text>
  <text x="360" y="263" class="role">order tracking</text>

  <rect x="530" y="220" width="130" height="55" rx="8" class="box2"/>
  <text x="595" y="245" class="name">returns</text>
  <text x="595" y="263" class="role">refunds + escalation</text>

  <rect x="530" y="345" width="130" height="55" rx="8" class="box2"/>
  <text x="595" y="370" class="name">supervisor</text>
  <text x="595" y="388" class="role">human-in-the-loop</text>

  <path d="M 340 133 Q 230 175 165 220" class="edge" marker-end="url(#arrow-dia)"/>
  <text x="218" y="178" class="lbl">① ticket-0</text>

  <path d="M 360 133 L 360 220" class="edge" marker-end="url(#arrow-dia)"/>
  <text x="380" y="180" class="lbl">② ticket-1</text>

  <path d="M 380 133 Q 490 175 555 220" class="edge" marker-end="url(#arrow-dia)"/>
  <text x="505" y="178" class="lbl">③ ticket-2</text>

  <path d="M 595 275 L 595 345" class="edge" marker-end="url(#arrow-dia)"/>
  <text x="660" y="313" class="lbl">④ escalation</text>

  <line x1="60" y1="425" x2="80" y2="425" class="edge"/>
  <text x="86" y="429" class="leg">framework_a (router · billing · shipping)</text>
  <line x1="370" y1="425" x2="390" y2="425" class="edge" stroke-dasharray="4 3"/>
  <text x="396" y="429" class="leg">framework_b (returns · supervisor)</text>

  <text x="360" y="450" class="foot">every send + deliver → signed receipt · 16 entries land in the audit log</text>
</svg>
</p>

The router has a two-node classifier-then-send graph; returns has a
two-node inspect-then-conditional-escalate graph; the three
specialist handlers are single-node loggers. Four envelopes cross
the wire in total — three router fan-outs plus one returns →
supervisor escalation. The escalation step (④) is the interesting
one: a LangGraph node *receiving* an envelope and *emitting* a
downstream one in response, which is the core pattern for chaining
agents through the substrate.

A returns-handling agent with a two-node graph — inspect, then
conditionally escalate:

```python
from typing import TypedDict
from langgraph.graph import END, START, StateGraph
from yutha.langgraph import YuthaAgent

class ReturnsState(TypedDict, total=False):
    payload: bytes
    needs_escalation: bool

def inspect(state: ReturnsState) -> ReturnsState:
    # Real logic would look at refund amount, customer tier, etc.
    # The point is: this is a LangGraph node that can branch.
    return {"needs_escalation": b"defective" in state["payload"]}

def build_returns_graph(returns_agent: YuthaAgent, supervisor_id: yutha.AgentId):
    async def escalate(state: ReturnsState) -> ReturnsState:
        await returns_agent.send(
            recipient=yutha.Recipient.for_agent(supervisor_id),
            performative=yutha.Performative.INFORM,
            payload=b"ESCALATED: " + state["payload"],
        )
        return state

    def route(state: ReturnsState) -> str:
        return "escalate" if state.get("needs_escalation") else END

    g = StateGraph(ReturnsState)
    g.add_node("inspect", inspect)
    g.add_node("escalate", escalate)
    g.add_edge(START, "inspect")
    g.add_conditional_edges("inspect", route, {"escalate": "escalate", END: END})
    g.add_edge("escalate", END)
    return g.compile()
```

Wire the compiled graph into your handler:

```python
graph_cache = {}

async def returns_handler(agent, envelope, _deliver_id):
    # Compile lazily on first envelope so the graph can close over the
    # actual YuthaAgent reference the dispatch loop hands us.
    if "compiled" not in graph_cache:
        graph_cache["compiled"] = build_returns_graph(agent, supervisor_id)
    await graph_cache["compiled"].ainvoke({"payload": envelope.payload})
```

That's the whole pattern. Any LangGraph topology works the same way
— ReAct loops, multi-tool calls, structured-output extraction — as
long as one of the nodes calls `agent.send(...)` when it wants to
emit a downstream envelope.

---

## Step 4 — Gating actions with capabilities

When a graph node performs something sensitive (issuing a refund,
hitting an external API, sending PII), you want a server-side gate
rather than a client-side check the agent could just remove. That's
what capabilities are for.

A capability is a signed grant scoped to a specific action (and
optionally constrained by caveats — recipient, resource tags, numeric
bounds). The `@capability_required` decorator from `yutha.langgraph`
wraps an async function with two pieces of glue:

1. **Local sanity check** — confirms the cap's scope permits the
   declared `action_kind` and fails fast with `CapabilityDenied`
   before the wrapped fn runs if there's a mismatch (catches
   "I decorated this node with the wrong action_kind for the cap"
   coding errors).
2. **Context-local cap_id** — sets a contextvar so any
   `agent.send(...)` inside the wrapped fn picks up the cap_id
   automatically. The substrate-level capability check runs
   server-side at Send (RFC 0007); a deny — because the cap was
   revoked, expired, or has unmet caveats — surfaces as
   `CapabilityDenied` raised from the send call.

```python
from yutha.langgraph import CapabilityDenied, capability_required

# 1. Issue a capability scoped to "envelope.send". The router holds it.
router_cap = yutha.Capability(
    spec_version="1.0.0",
    capability_id=secrets.token_bytes(16),
    swarm_id=swarm_id,
    issuer=yutha.Issuer.for_agent(router.agent_id),
    subject=router.agent_id,
    scope=yutha.Scope.for_action("envelope.send"),
    valid_from=yutha.Timestamp.now(),
    valid_until=yutha.Timestamp(
        wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62
    ),
)
cap_id, _ = await router.client.capability.issue(router_cap)

# 2. Decorate the node that does the sensitive thing.
@capability_required(router.client, router_cap, action_kind="envelope.send")
async def send_to_handler(state):
    await router.send(
        recipient=yutha.Recipient.for_agent(destinations[state["category"]]),
        performative=yutha.Performative.REQUEST_ACTION,
        payload=state["ticket_text"].encode("utf-8"),
    )
    return state

# 3. Wire the decorated function into your StateGraph as usual.
# Every invocation goes through a server-side check + emits a
# capability.check.pass receipt.

# 4. To demonstrate the gate is load-bearing, revoke the cap and
#    try again — the decorator raises CapabilityDenied:
await router.client.capability.revoke(cap_id, "demo")
try:
    await send_to_handler({"category": "billing", "ticket_text": "blocked"})
except CapabilityDenied as e:
    print(f"blocked: {e}")        # 'blocked: capability revoked in chain'
```

The check is **stateful**: the server walks the cap's parent chain,
honors revocation, enforces the validity window, intersects scopes
across the chain, and evaluates caveats. Every check emits a
`capability.check.pass` or `capability.check.deny` receipt — your
audit log records not just what happened but every authorization
decision that gated it.

For more on capability semantics — attenuation, caveat evaluation,
delegation chains — see [`/spec/capability/`](../spec/capability/).

---

## Step 5 — Querying the audit log

Every action above produces a content-addressed receipt that any
authenticated agent can query.

```python
# All agent.register receipts on this server:
receipts, _next_page = await client.receipt.query_by_action_kind("agent.register")
for r in receipts:
    print(r.action_kind, r.actor)

# All receipts authored by a specific actor (control plane signs send
# and deliver receipts, agents sign their own actions):
receipts, _ = await client.receipt.query_by_agent(some_agent_id)

# Fetch a single receipt by content-address:
single = await client.receipt.get(receipt_hash)
```

The canonical action kinds you'll see in a typical workflow:

| Kind | When |
|---|---|
| `agent.register` | A passport joins the registry |
| `agent.revoke` | A passport is decommissioned |
| `envelope.send` | An agent sends a message |
| `envelope.deliver` | The transport delivers it to a recipient |
| `capability.issue` | A new capability is minted |
| `capability.attenuate` | A child cap is derived from a parent |
| `capability.revoke` | A capability is invalidated |
| `capability.check.pass` | An authorization decision permitted an action |
| `capability.check.deny` | An authorization decision refused an action |

Every receipt is signed by the actor it attributes (or the control
plane, for substrate-emitted receipts like `envelope.send`/`deliver`).
The audit log is the source of truth for "what actually happened in
the swarm" — you don't need to instrument your own observability for
the substrate's behavior; it's all here.

---

## Step 6 — Operator-level eviction

Sometimes you need an out-of-band way to forcibly remove an agent
from the swarm — a compromised key, a misbehaving worker, a policy
violation surfaced from outside the substrate. Self-revoke
(`agent.client.admission.revoke(my_own_id, …)`) covers the case
where the agent itself decides to leave. Operator-revoke is the
sibling RPC for everything else.

The operator credential is structurally separate from agent
credentials — a different bearer-token variant signed by an
"operator key" the control plane is configured with at startup.
The operator's private key stays in operator tooling (a separate
binary, a sealed secret, an HSM); the server only ever sees its
public counterpart.

```python
from yutha import YuthaClient

# The operator's signing key. In production this stays in an
# operator-side secret store. For the demo we derive it from the
# bootstrap seed (see the S1 demo's derive_operator_identity).
operator_signing_key = ...

async with YuthaClient.connect_as_operator(
    "127.0.0.1:50051",
    operator_id="ops-team-1",
    swarm_id=swarm_id,
    operator_signing_key=operator_signing_key,
) as op_client:
    receipt = await op_client.admission.operator_revoke(
        target_agent_id,
        "compromised credential — rotating",
    )
    print(f"revoked, receipt={receipt}")
```

Three properties worth knowing:

- **Immediate tear-down.** The server adds the target to its
  revoked-set and fires a per-agent revocation signal. Any active
  `Subscribe` stream the target holds closes within tens of
  milliseconds with an `UNAUTHENTICATED: agent revoked` frame. The
  next bearer-auth call from any of the target's remaining tokens
  rejects with the same code, regardless of how much wall-clock
  time the token has left. This is RFC 0009 §3.3.
- **Distinct receipt kind.** Operator-revoke produces an
  `agent.operator_revoke` receipt with `operator_id` on its
  evidence — different from `agent.revoke` (self-revoke) so audit
  queries can filter by actor type without parsing reason strings.
- **Server config gate.** Operator credentials are opt-in. If the
  control plane was started without `--operator-public-key`,
  `operator_revoke` returns `FAILED_PRECONDITION: operator
  credentials not enabled`. This keeps the operator surface
  disabled by default; operators opt in explicitly at binary launch.

The S1 demo's Phase 7.5 exercises this end-to-end: derives an
operator keypair from the bootstrap seed, connects as operator,
evicts the `billing` agent, and the audit shape gains
`agent.operator_revoke: +1`.

**What this RPC does NOT do** in v1: cascade-revoke the target's
capabilities (still on the roadmap), rotate the operator's own
key at runtime (stop + restart with a new key), or support
multiple operator keys (single key per server today). See
RFC 0009 §9 for the explicit punts.

---

## Putting it together: the full demo

For a complete five-agent workflow that exercises everything above
— LangGraph classifier, conditional escalation, capability gating
with a negative path, audit-shape assertions — see:

- **Source**: [`sdks/python/examples/s1_support_queue.py`](../sdks/python/examples/s1_support_queue.py)
- **Integration test**: [`sdks/python/tests/test_s1_support_queue_demo.py`](../sdks/python/tests/test_s1_support_queue_demo.py)

The demo is fully runnable; it produces exactly 20 audit-log receipts
on a clean run and asserts on the shape. It's the reference for
"what a production-ish Yutha + LangGraph workflow looks like."

To run it:

```bash
# Terminal A — server (in any directory):
YUTHA_BOOTSTRAP_SEED=$(python -c 'import secrets; print(secrets.token_hex(32))') \
    cargo run -p yutha-control-plane -- --admission-mode open

# Terminal B — demo (in sdks/python/):
export YUTHA_BOOTSTRAP_SEED=<same hex>
uv run python examples/s1_support_queue.py
```

---

## Common gotchas

These come up enough that they're worth knowing upfront.

**Closed vs. open admission.** The control plane defaults to closed
mode, which only admits passports in its allowlist (production
posture). For demos and local dev where you want fresh agents to
self-register, start the server with `--admission-mode open`.
**Never use open mode in production** — it imposes no sybil
resistance beyond the basic passport-shape check.

**Swarm-ID derivation.** The server's registry serves exactly one
`swarm_id`. Your passports must bind to that same `swarm_id` or
registration fails with "wrong swarm". The simplest way to coordinate
client and server is to share `YUTHA_BOOTSTRAP_SEED` between them
and derive `swarm_id = sha256(seed || 0x02)[:16]` on both sides
(this walkthrough's snippet shows the Python side; the Rust server
does it the same way internally).

**Revocation is self-revoke only today.** Any agent can call
`client.admission.revoke(its_own_id, reason)` to decommission its
own passport. Operator-revoke (the swarm operator forcibly evicting
an agent) and constitution-driven revoke (automated eviction after
norm violations) are planned but not built yet.

**Bearer tokens auto-renew.** You don't manage them — the
`YuthaClient` mints them lazily and re-mints them as their expiry
approaches. Default lifetime is 5 minutes; you can override with
the `token_lifetime_seconds=` and `refresh_lead_seconds=` kwargs on
`YuthaClient.connect(...)`.

---

## Where to go next

- [`/spec/`](../spec/) — the substrate spec. Read passport,
  envelope, receipt, capability, and topology if you want to know
  what's actually on the wire.
- [`sdks/python/src/yutha/langgraph/`](../sdks/python/src/yutha/langgraph/)
  — the adapter source. Read it if you want to understand how
  `YuthaAgent` and `@capability_required` are implemented (~200
  lines, very approachable).
- [`crates/yutha-conformance/`](../crates/yutha-conformance/) —
  the Rust reference scenarios. The Python S1 demo mirrors
  `s1_queue_mode.rs`; future scenarios will get Python ports too.
- File an issue or RFC at the project repo if you hit a wart that
  isn't in the "common gotchas" list above.

The LangGraph adapter is intentionally light — it doesn't try to be
opinionated about LangGraph's state model or replace its
checkpointing. It just makes the Yutha control plane available to
LangGraph nodes as inbound/outbound mailboxes with cryptographic
identity and an audit trail. Build whatever workflow shape you
want; the substrate stays out of your way.

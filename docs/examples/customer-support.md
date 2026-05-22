# Customer support with a refund cap

A worked example for a customer-support swarm — a router that
classifies inbound tickets, three specialists that handle
refunds, shipping, and returns, and a supervisor that picks up
escalations. The substrate point is **the foundational
primitives**: per-agent cryptographic identity, capability-gated
sends, capability revocation as a live control, and the two
flavours of agent removal (self-revoke and operator-driven
eviction).

This is the simplest of the three example demos. It does not
activate a constitution or exercise the four-stage enforcement
loop — those layer on top in the [code-review](code-review.md)
and [AP/invoice](ap-invoice.md) examples. Treat this one as the
walkthrough that establishes the substrate vocabulary; the other
two build the policy story on top of it.

The runnable demo lives at
[`sdks/python/examples/s1_support_queue.py`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/examples/s1_support_queue.py).
A CrewAI port — same audit-trail shape, narrower three-agent
cast — lives at
[`s1_support_queue_crewai.py`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/examples/s1_support_queue_crewai.py).
Each runs end-to-end against a real control plane in a few
seconds.

---

## What this example shows

- Five fresh agents register themselves into a clean swarm,
  carrying distinct `framework` labels so audit queries can
  filter by role.
- The router's two-node LangGraph classifies each ticket via
  keyword rules and dispatches to the right specialist.
- Every outbound router send runs through a server-side
  capability check via `@capability_required` — the same gate
  pattern reused by the other two examples.
- The returns agent's LangGraph has a conditional edge that
  escalates inbound tickets to the supervisor — a node that
  *acts* by emitting another envelope, not just consuming one.
- The negative path is exercised live: the router's capability
  is revoked, one more send is attempted, and
  `CapabilityDenied` raises with a `capability.check.deny`
  receipt landing in the audit log.
- Self-revoke and operator-revoke are demonstrated side by side
  — the returns agent self-revokes its passport; an operator
  client evicts the billing agent via the operator-bearer RPC.
  Two distinct receipt kinds (`agent.revoke` vs.
  `agent.operator_revoke`) make the audit trail
  legally-distinguishable.
- The audit-trail delta is queried at the end and compared
  exactly to the expected shape — every consequential action
  the demo took left a receipt.

---

## The cast

Five LangGraph agents register into a clean swarm. The two
`framework` labels (`framework_a` and `framework_b`) mirror the
Rust S1 conformance scenario's mixed-framework setup, which
exists to prove that the substrate doesn't care which
framework an agent ships under.

| Agent | `framework` | Role |
|---|---|---|
| `router` | `framework_a` | Receives the demo's three inbound tickets, classifies each, dispatches via a cap-gated send to the right specialist. |
| `billing` | `framework_a` | Receives refund/billing tickets. Acknowledges receipt. Later evicted by the operator to demonstrate the operator-revoke path. |
| `shipping` | `framework_a` | Receives shipping/tracking tickets. Acknowledges receipt. |
| `returns` | `framework_b` | Receives return/defective-item tickets. Always escalates to the supervisor via a conditional LangGraph edge. Later self-revokes its passport. |
| `supervisor` | `framework_b` | Receives escalations from the returns agent. Passive observer in the demo. |

A real implementation would have the specialists actually
respond to tickets and would route a fraction (rather than
all) of the returns flow through the supervisor. For the demo
the orchestration is kept tight enough that the audit-trail
delta is deterministic.

---

## The classifier graph

The router's LangGraph workflow is two nodes — classify then
send:

```python
def classify_ticket(state: ClassifierState) -> ClassifierState:
    """Keyword-rules classifier. No LLM dependency on purpose —
    the demo is about the substrate (signed identity, audit
    trail, capability gating), not the classifier's
    intelligence."""
    text = state["ticket_text"].lower()
    if any(k in text for k in ("refund", "return", "replace", "defective")):
        category = "returns"
    elif any(k in text for k in ("delivery", "package", "tracking", "shipped", "where is")):
        category = "shipping"
    else:
        category = "billing"
    return {"category": category}
```

The send node is wrapped with `@capability_required` so every
outbound ticket triggers a real server-side capability check
before the envelope is signed:

```python
@capability_required(router_agent.client, router_cap, action_kind="envelope.send")
async def send_to_handler(state: ClassifierState) -> ClassifierState:
    dest = destinations[state["category"]]
    receipt = await router_agent.send(
        recipient=yutha.Recipient.for_agent(dest),
        performative=yutha.Performative.REQUEST_ACTION,
        payload=state["ticket_text"].encode("utf-8"),
        payload_schema_id="type.yutha.dev/v1/Text",
        tags=["s1-demo", f"category:{state['category']}"],
    )
    return {"destination_agent_id": dest, "send_receipt_id": receipt}
```

The decorator threads `capability_id` through to the Send RPC.
The server runs the cap check; a deny would raise
`CapabilityDenied` from inside this node. The
[code-review example](code-review.md) reuses this exact pattern
and layers a constitution check on top.

---

## The returns escalation

The returns agent's handler does something subtler: when an
envelope arrives, it invokes its own LangGraph to decide
whether to escalate, and the escalation branch *acts* by
sending another envelope:

```python
def build_returns_graph(returns_agent, supervisor_id):
    async def escalate(state):
        receipt = await returns_agent.send(
            recipient=yutha.Recipient.for_agent(supervisor_id),
            performative=yutha.Performative.INFORM,
            payload=b"ESCALATED: " + state["payload"],
            payload_schema_id="type.yutha.dev/v1/Text",
            tags=["s1-demo", "escalation"],
        )
        return {"escalation_receipt_id": receipt}

    def route(state):
        return "escalate" if state.get("needs_escalation") else END

    graph = StateGraph(ReturnsState)
    graph.add_node("inspect_priority", inspect_priority)
    graph.add_node("escalate", escalate)
    graph.add_edge(START, "inspect_priority")
    graph.add_conditional_edges("inspect_priority", route, {"escalate": "escalate", END: END})
    graph.add_edge("escalate", END)
    return graph.compile()
```

The returns agent's send is NOT cap-gated — it doesn't present
a `capability_id` on the Send call. That's a deliberate
choice: the demo wants to show what the substrate looks like
when *some* sends use capabilities and others don't, mixed in
a single swarm. Open-mode topology permits this; closed mode
would require every send to present a cap.

---

## The negative path

After three tickets have been routed, the demo revokes the
router's capability and attempts one more send:

```python
await router.client.capability.revoke(cap_id, "demo: showing the gate is load-bearing")

denied = False
try:
    await router_graph.ainvoke({"ticket_text": "another billing question after revocation"})
except CapabilityDenied as e:
    denied = True
    print(f"  ✓ post-revoke send blocked: {e}")
```

The revoke RPC produces a `capability.revoke` receipt. The
subsequent send attempt produces a `capability.check.deny`
receipt with the reason embedded in evidence. The Python
`CapabilityDenied` exception carries the server's denial
reason for programmatic inspection.

---

## Self-revoke vs operator-revoke

Two flavours of agent removal:

```python
# Self-revoke — the agent removes itself.
revoke_receipt = await returns.client.admission.revoke(
    returns_id, "s1 scenario cleanup"
)
# → emits `agent.revoke` (NOT `agent.operator_revoke`)
```

```python
# Operator-revoke — an operator-bearer client evicts an agent.
async with yutha.YuthaClient.connect_as_operator(
    server_addr,
    operator_id="s1-demo-operator",
    swarm_id=swarm_id,
    operator_signing_key=op_signing_key,
) as op_client:
    op_outcome = await op_client.admission.operator_revoke(
        billing_id,
        "s1 demo: operator-driven eviction",
    )
# → emits `agent.operator_revoke` (NOT `agent.revoke`)
```

The two paths use different bearer-token variants (agent-bearer
vs operator-bearer), call different gRPC methods, and write
distinct receipt kinds. An auditor reconstructing what happened
to billing vs returns can tell from the audit log alone who
took the action — the returns agent removed itself, the
operator evicted billing.

The operator's keypair in this demo is derived from the same
bootstrap seed as the agents, using a domain-separated SHA-256
chain so the leak of one derivation can't pivot to another.
See `derive_operator_identity()` in the demo source.

---

## The audit-trail delta

The demo asserts the exact shape of the audit trail it produced.
Pre-snapshot before any work; post-snapshot after the eviction
lands; delta is the receipts attributable to this run:

```python
EXPECTED_AUDIT_DELTA = {
    "agent.register": 5,         # five fresh registrations
    "envelope.send": 4,          # 3 ticket dispatches + 1 escalation
    "envelope.deliver": 4,
    "capability.issue": 1,       # router's send cap
    "capability.check.pass": 3,  # one per successful router dispatch
    "capability.check.deny": 1,  # post-revoke attempt
    "capability.revoke": 1,
    "agent.revoke": 1,           # returns self-revokes
    "agent.operator_revoke": 1,  # operator evicts billing
}
```

Things worth noticing:

- `envelope.send` and `envelope.deliver` agree because every
  send the demo issues has exactly one recipient and all
  recipients are live (no broadcasts, no dead inboxes).
- `capability.check.pass` ticks only on the router's three
  ticket dispatches. The returns→supervisor escalation isn't
  cap-gated (the returns agent's send doesn't present a
  `capability_id`) so no cap-check fires.
- `agent.revoke` and `agent.operator_revoke` are different
  receipt kinds and produced by different RPCs. Code that
  needs to detect "an agent left the swarm" should query for
  both kinds.

---

## Running it

The demo and the server agree on the swarm ID via a 32-byte
bootstrap seed — same handshake shape as the other two
examples.

```bash
# Mint a seed (once per run).
export YUTHA_BOOTSTRAP_SEED=$(python -c \
    'import secrets; print(secrets.token_hex(32))')

# Start the control plane in open admission mode. The demo's
# operator-driven eviction step requires --operator-public-key;
# the demo's helper subcommand derives the pubkey from the seed.
cargo run -p yutha-control-plane -- \
    --admission-mode open \
    --operator-public-key $(python -c "
import hashlib, os, sys
sys.path.insert(0, 'sdks/python/src')
import yutha
seed = bytes.fromhex(os.environ['YUTHA_BOOTSTRAP_SEED'].strip())
op_seed = hashlib.sha256(seed + b'\\x03').digest()
print(yutha.SigningKey.from_seed_bytes(op_seed).public_key().value.hex())
")

# Run the demo in a second shell with the same seed exported.
python sdks/python/examples/s1_support_queue.py
```

A clean run prints each phase's progress and finishes with the
audit-delta block:

```text
# Phase 8 — audit-trail delta
  ✓ agent.register              +5  (expected +5)
  ✓ envelope.send               +4  (expected +4)
  ✓ envelope.deliver            +4  (expected +4)
  ✓ capability.issue            +1  (expected +1)
  ✓ capability.check.pass       +3  (expected +3)
  ✓ capability.check.deny       +1  (expected +1)
  ✓ capability.revoke           +1  (expected +1)
  ✓ agent.revoke                +1  (expected +1)
  ✓ agent.operator_revoke       +1  (expected +1)

✓ audit-trail shape matches expectations
```

Total wall-clock is a few seconds; the script exits with status
1 if any delta doesn't match.

For the CrewAI port, replace `s1_support_queue.py` with
`s1_support_queue_crewai.py` in the run command and export
`OPENAI_API_KEY=...` first — CrewAI's `Agent` constructor
requires an LLM credential even when the substrate path
bypasses the LLM (the dispatch tool is invoked directly
rather than via an LLM-driven Crew).

---

## What to try next

A few directions to extend the example:

- **Layer a refund-cap constitution.** Activate a Cedar policy
  that forbids the billing agent's send when the envelope
  carries `refund_amount_cents > N`. The Rust conformance
  scenario at
  [`crates/yutha-conformance/src/scenarios/s5_support_queue_refunds.rs`](https://github.com/abhinavg6/yutha/blob/main/crates/yutha-conformance/src/scenarios/s5_support_queue_refunds.rs)
  shows exactly that shape. Once added to the Python demo, you
  pick up `constitution.evaluate.pass` / `deny` receipts in
  the audit trail. The [code-review](code-review.md) and
  [AP/invoice](ap-invoice.md) examples already show the
  Python-side activation pattern.
- **Wire the four-stage enforcement loop.** With the
  refund-cap constitution active, add an enforcement rule
  whose `detect.trigger.receipt_kind` is
  `constitution.evaluate.deny` and whose `count_threshold`
  trips after, say, two over-cap attempts inside an hour. The
  billing agent gets coached, quarantined, then evicted —
  same chain the code-review demo runs.
- **Anchor the audit trail.** Enable
  [Sui anchoring](../operator/sui-anchoring.md) and re-run
  the demo. The receipt log becomes verifiable to a third
  party who has only the constitution and the on-chain
  commitment — no trust in your control plane required.
- **Add a duplicate-ticket detector.** A receipt-stream
  pattern that fires when the same `customer_id` filed two
  refund requests within a minute — the substrate-side
  equivalent of fraud-detection rules.

---

## See also

- [Code review crew with security boundaries](code-review.md)
  — adds a constitution + four-stage enforcement on top of
  the substrate primitives this example demonstrates.
- [AP & invoice processing with payment caps](ap-invoice.md)
  — same constitution machinery, framed around role
  boundaries instead of file tags.
- [LangGraph developer guide](../developer/langgraph.md) —
  the long-form treatment of the `YuthaAgent` wrapper, the
  `@capability_required` decorator, and the SDK surface this
  demo builds on.
- [Operator credentials reference](../operator/operator-credentials.md)
  — how the operator-bearer client used by the
  `operator_revoke` step is constructed and authenticated.

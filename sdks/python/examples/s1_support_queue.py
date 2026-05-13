"""S1 customer-support queue — Python + LangGraph end-to-end demo.

Mirrors the Rust conformance scenario at
``crates/yutha-conformance/src/scenarios/s1_queue_mode.rs`` but goes
end-to-end through the gRPC control plane, drives each agent's
incoming-envelope handling via a small compiled LangGraph workflow,
and gates the router's outbound sends via the
:func:`yutha.langgraph.capability_required` decorator from Stage-4b.

Running locally
---------------

The demo and the server must agree on the swarm_id (registry rejects
cross-swarm passports). The simplest way to make them agree without
adding a discovery RPC is the same bootstrap-seed handshake that
``tests/test_integration.py`` uses — both sides derive the swarm_id
from a shared 32-byte seed.

1. Mint a seed once per run and start the control plane in OPEN
   admission mode (default is CLOSED, which rejects passports outside
   its allowlist — fine for production tests, incompatible with five
   fresh agents self-registering). ::

       export YUTHA_BOOTSTRAP_SEED=$(python -c \\
           'import secrets; print(secrets.token_hex(32))')

       cargo run -p yutha-control-plane -- --admission-mode open

2. With the same seed exported in this shell, run this script ::

       python sdks/python/examples/s1_support_queue.py

What the demo exercises
-----------------------

* Five fresh agents register themselves into a clean swarm
  (two of them tagged ``framework_b`` to mirror the Rust scenario's
  mixed-framework setup).
* The router's two-node LangGraph classifies each ticket via keyword
  rules and dispatches to the right specialist.
* The returns agent's LangGraph has a conditional edge that
  escalates received tickets to the supervisor — a node that *acts*
  by emitting another envelope, not just consuming one.
* Every outbound router send runs through a server-side capability
  check before the envelope hits the wire.
* Negative path: revoke the router's capability, attempt one more
  send, confirm :class:`yutha.langgraph.CapabilityDenied` raises.
* The returns agent self-revokes its passport at the end.
* The audit-trail delta is queried and compared to the expected
  shape — same receipt kinds the Rust scenario produces, plus the
  cap-revoke + cap-deny entries the negative path adds.

The ``run_s1()`` coroutine returns the delta dict so the pytest
wrapper in ``tests/test_s1_support_queue_demo.py`` can re-use it
without forking the body.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

import yutha
from yutha.langgraph import CapabilityDenied, YuthaAgent, capability_required

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

SERVER_ADDR = os.environ.get("YUTHA_GRPC_ADDR", "127.0.0.1:50051")

# Far-future expires_at sentinel. Open-mode admission rejects passports
# without expires_at; we set one that obviously outlasts the demo run.
FAR_FUTURE = yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62)

# Past-anchor for capability windows. The substrate's
# ``Capability::is_within_window`` compares ``monotonic_ns`` numerically,
# but Python's ``time.monotonic_ns()`` and Rust's monotonic clock have
# process-local origins — a cap built client-side with ``valid_from =
# Timestamp.now()`` lands in the *future* relative to the server's
# monotonic clock and fails the window check. Until the spec/substrate
# moves window semantics to wall-clock (tracked in memory), the
# cross-process workaround is to anchor ``valid_from`` at zero. The
# wall_clock field is informational and unused by the check; we set it
# to the Unix epoch for readability.
EPOCH_ZERO = yutha.Timestamp(wall_clock="1970-01-01T00:00:00Z", monotonic_ns=0)


def derive_bootstrap_identity(
    seed: bytes,
) -> tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId]:
    """Reproduce the Rust ``BootstrapIdentity::from_seed_hex``
    derivation: the seed itself is the Ed25519 private key,
    ``sha256(seed || 0x01)[:16]`` is the agent_id, and
    ``sha256(seed || 0x02)[:16]`` is the swarm_id.

    Returning all three lets the demo (a) bind its own passports to
    the right swarm_id and (b) authenticate as the bootstrap agent
    for the pre-snapshot audit query — taken *before* any demo agent
    registers, so the ``agent.register`` delta actually counts the
    five demo registrations rather than zero."""
    if len(seed) != 32:
        raise ValueError(f"seed must be exactly 32 bytes, got {len(seed)}")
    signing_key = yutha.SigningKey.from_seed_bytes(seed)
    agent_id = yutha.AgentId(value=hashlib.sha256(seed + b"\x01").digest()[:16])
    swarm_id = yutha.SwarmId(value=hashlib.sha256(seed + b"\x02").digest()[:16])
    return signing_key, agent_id, swarm_id


def load_bootstrap_identity_from_env() -> tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId]:
    """Read ``YUTHA_BOOTSTRAP_SEED`` and derive the full bootstrap
    identity from it. Raises a clear error if the env var is missing
    or malformed — cleaner than hitting an ``AioRpcError`` deep in
    Phase 1."""
    seed_hex = os.environ.get("YUTHA_BOOTSTRAP_SEED")
    if not seed_hex:
        raise RuntimeError(
            "YUTHA_BOOTSTRAP_SEED is not set. The demo needs the same "
            "32-byte hex seed the control plane was started with so it "
            "can (a) derive the swarm_id its passports must bind to "
            "and (b) authenticate as the bootstrap agent for the "
            "pre-flow audit snapshot. Run:\n"
            "    YUTHA_BOOTSTRAP_SEED=$(python -c "
            "'import secrets; print(secrets.token_hex(32))') \\\n"
            "    cargo run -p yutha-control-plane -- --admission-mode open\n"
            "    YUTHA_BOOTSTRAP_SEED=<same hex> \\\n"
            "    python examples/s1_support_queue.py"
        )
    try:
        seed = bytes.fromhex(seed_hex.strip())
    except ValueError as e:
        raise RuntimeError(f"YUTHA_BOOTSTRAP_SEED is not valid hex: {e}") from e
    if len(seed) != 32:
        raise RuntimeError(
            f"YUTHA_BOOTSTRAP_SEED must be exactly 64 hex chars (32 bytes); got {len(seed)} bytes"
        )
    return derive_bootstrap_identity(seed)


# Expected receipt-count delta for one demo run. The test wrapper
# asserts exactly this dict — change here and there in lockstep.
EXPECTED_AUDIT_DELTA: dict[str, int] = {
    "agent.register": 5,
    "envelope.send": 4,
    "envelope.deliver": 4,
    "capability.issue": 1,
    "capability.check.pass": 3,
    "capability.check.deny": 1,
    "capability.revoke": 1,
    "agent.revoke": 1,
}

# The five-agent cast and their framework tags. Two frameworks mirrors
# the Rust S1 scenario's "multi-framework swarm" setup.
CAST: list[tuple[str, str]] = [
    ("router", "framework_a"),
    ("billing", "framework_a"),
    ("shipping", "framework_a"),
    ("returns", "framework_b"),
    ("supervisor", "framework_b"),
]

# Three tickets the router fans out. Wording is chosen so the keyword
# classifier picks each ticket's intended destination unambiguously.
TICKETS: list[str] = [
    "I was charged twice for my order; the duplicate should be reversed.",
    "Where is my package? It was supposed to arrive Monday.",
    "I want to return this defective item.",
]


# -----------------------------------------------------------------------------
# Passport helpers
# -----------------------------------------------------------------------------


def make_passport(
    name: str,
    framework: str,
    swarm_id: yutha.SwarmId,
    signing_key: yutha.SigningKey,
    agent_id: yutha.AgentId,
) -> yutha.Passport:
    """Build a signed passport for one demo agent.

    Open-mode admission requires ``expires_at`` and ``tier ≥ Minimal``.
    We set both unconditionally so the same passport shape would also
    pass a closed-mode allowlist check if the operator chose to
    pre-register these IDs."""
    return yutha.Passport(
        spec_version="1.0.0",
        agent_id=agent_id,
        swarm_id=swarm_id,
        agent_public_key=signing_key.public_key(),
        owner=f"yutha-demo:s1:{name}",
        framework=framework,
        framework_version="1.0.0",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
        expires_at=FAR_FUTURE,
    ).sign(signing_key)


# -----------------------------------------------------------------------------
# Router classifier graph (LangGraph)
# -----------------------------------------------------------------------------


class ClassifierState(TypedDict, total=False):
    """State threaded through the router's classify → send graph.

    Marked ``total=False`` so nodes can return only the keys they
    populate; LangGraph merges each node's return into the running
    state."""

    ticket_text: str
    category: str
    destination_agent_id: yutha.AgentId
    send_receipt_id: yutha.Hash


def classify_ticket(state: ClassifierState) -> ClassifierState:
    """Keyword-rules classifier. No LLM dependency on purpose — the
    demo is about the substrate (signed identity, audit trail,
    capability gating), not the classifier's intelligence."""
    text = state["ticket_text"].lower()
    if any(k in text for k in ("refund", "return", "replace", "defective")):
        category = "returns"
    elif any(k in text for k in ("delivery", "package", "tracking", "shipped", "where is")):
        category = "shipping"
    else:
        category = "billing"
    return {"category": category}


def build_router_graph(
    router_agent: YuthaAgent,
    router_cap: yutha.Capability,
    destinations: dict[str, yutha.AgentId],
) -> Any:
    """Compile the router's classify → send graph.

    The send node is wrapped with
    :func:`yutha.langgraph.capability_required` so every outbound
    ticket runs a real server-side capability check before the
    envelope is signed and shipped. Revoking ``router_cap`` after
    compilation causes subsequent invocations to raise
    :class:`CapabilityDenied` at the gated node — see Phase 6 in
    :func:`run_s1`."""

    @capability_required(router_agent.client, router_cap, action_kind="send_message")
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

    graph: StateGraph = StateGraph(ClassifierState)
    graph.add_node("classify_ticket", classify_ticket)
    graph.add_node("send_to_handler", send_to_handler)
    graph.add_edge(START, "classify_ticket")
    graph.add_edge("classify_ticket", "send_to_handler")
    graph.add_edge("send_to_handler", END)
    return graph.compile()


# -----------------------------------------------------------------------------
# Returns escalation graph (LangGraph)
# -----------------------------------------------------------------------------


class ReturnsState(TypedDict, total=False):
    """State for the returns agent's inspect → escalate graph."""

    payload: bytes
    needs_escalation: bool
    escalation_receipt_id: yutha.Hash


def inspect_priority(state: ReturnsState) -> ReturnsState:
    """Stub priority check. For the demo every returns ticket
    escalates; in a real workflow this would inspect payload
    contents, customer tier, refund amount, etc."""
    return {"needs_escalation": True}


def build_returns_graph(returns_agent: YuthaAgent, supervisor_id: yutha.AgentId) -> Any:
    """Compile the returns agent's inspect → conditional-escalate
    graph. Demonstrates LangGraph's branching machinery on a node
    that produces a real side effect (sends an envelope)."""

    async def escalate(state: ReturnsState) -> ReturnsState:
        receipt = await returns_agent.send(
            recipient=yutha.Recipient.for_agent(supervisor_id),
            performative=yutha.Performative.INFORM,
            payload=b"ESCALATED: " + state["payload"],
            payload_schema_id="type.yutha.dev/v1/Text",
            tags=["s1-demo", "escalation"],
        )
        return {"escalation_receipt_id": receipt}

    def route(state: ReturnsState) -> str:
        return "escalate" if state.get("needs_escalation") else END

    graph: StateGraph = StateGraph(ReturnsState)
    graph.add_node("inspect_priority", inspect_priority)
    graph.add_node("escalate", escalate)
    graph.add_edge(START, "inspect_priority")
    graph.add_conditional_edges("inspect_priority", route, {"escalate": "escalate", END: END})
    graph.add_edge("escalate", END)
    return graph.compile()


# -----------------------------------------------------------------------------
# Audit-trail snapshot
# -----------------------------------------------------------------------------


async def query_audit(client: yutha.YuthaClient, kinds: list[str]) -> dict[str, int]:
    """Snapshot receipt counts for each action_kind. Used to compute
    the delta attributable to this run — works whether the server is
    freshly started or hosting receipts from prior demos."""
    counts: dict[str, int] = {}
    for kind in kinds:
        receipts, _ = await client.receipt.query_by_action_kind(kind)
        counts[kind] = len(receipts)
    return counts


# -----------------------------------------------------------------------------
# Main flow
# -----------------------------------------------------------------------------

EnvelopeHandler = Callable[[YuthaAgent, yutha.Envelope, yutha.Hash], Awaitable[None]]


async def run_s1(server_addr: str = SERVER_ADDR) -> dict[str, int]:
    """Run the S1 scenario end-to-end against ``server_addr``.

    Returns the audit-trail delta: receipt-count change attributable
    to this run, keyed by action_kind."""
    print(f"# S1 customer-support queue demo · server={server_addr}")

    # --- bootstrap identity (used for swarm_id binding + pre-snapshot) ---
    bootstrap_key, bootstrap_agent_id, swarm_id = load_bootstrap_identity_from_env()
    print(f"# swarm_id={swarm_id.value.hex()} (from YUTHA_BOOTSTRAP_SEED)")

    # --- Phase 0: pre-flow audit snapshot ---
    # Taken BEFORE the five demo agents register, using the bootstrap
    # identity the server already knows about. Without this, the
    # `agent.register` delta would be zero — the five register receipts
    # would already exist by the time any demo agent could query.
    kinds = list(EXPECTED_AUDIT_DELTA.keys())
    async with yutha.YuthaClient.connect(
        server_addr,
        agent_id=bootstrap_agent_id,
        swarm_id=swarm_id,
        signing_key=bootstrap_key,
    ) as bootstrap_client:
        before = await query_audit(bootstrap_client, kinds)
    print(f"# pre-flow snapshot taken via bootstrap agent {bootstrap_agent_id.value.hex()[:16]}…")

    # --- identities ----------------------------------------------------
    identities: dict[str, tuple[yutha.SigningKey, yutha.AgentId, yutha.Passport]] = {}
    for name, framework in CAST:
        key = yutha.SigningKey.generate()
        agent_id = yutha.AgentId(value=secrets.token_bytes(16))
        passport = make_passport(name, framework, swarm_id, key, agent_id)
        identities[name] = (key, agent_id, passport)

    # --- handlers ------------------------------------------------------
    received: dict[str, list[yutha.Envelope]] = {n: [] for n in identities}
    supervisor_id = identities["supervisor"][1]
    returns_graph_holder: dict[str, Any] = {}

    def logger_handler(name: str) -> EnvelopeHandler:
        async def handler(
            _agent: YuthaAgent,
            envelope: yutha.Envelope,
            _deliver_id: yutha.Hash,
        ) -> None:
            received[name].append(envelope)
            print(f"  [{name}] recv {len(envelope.payload)}B")

        return handler

    async def returns_handler(
        agent: YuthaAgent,
        envelope: yutha.Envelope,
        _deliver_id: yutha.Hash,
    ) -> None:
        received["returns"].append(envelope)
        print(f"  [returns] recv {len(envelope.payload)}B → escalation graph")
        # Compile the graph lazily on first envelope so it can close over
        # the actual YuthaAgent reference passed in by the dispatch loop.
        if "graph" not in returns_graph_holder:
            returns_graph_holder["graph"] = build_returns_graph(agent, supervisor_id)
        await returns_graph_holder["graph"].ainvoke({"payload": envelope.payload})

    async def router_handler(_agent: YuthaAgent, envelope: yutha.Envelope, _id: yutha.Hash) -> None:
        # Router doesn't expect inbound envelopes in S1; log defensively.
        received["router"].append(envelope)
        print(f"  [router] unexpected inbound from {envelope.from_agent}")

    handlers: dict[str, EnvelopeHandler] = {
        "router": router_handler,
        "billing": logger_handler("billing"),
        "shipping": logger_handler("shipping"),
        "returns": returns_handler,
        "supervisor": logger_handler("supervisor"),
    }

    # --- connect + register (anonymous; no dispatch yet) ---------------
    agent_handles: dict[str, YuthaAgent] = {}
    try:
        print("\n# Phase 1 — connect + register")
        for name, (key, _agent_id, passport) in identities.items():
            ag = YuthaAgent.connect(
                server_addr,
                passport=passport,
                signing_key=key,
                handler=handlers[name],
            )
            agent_handles[name] = ag
            receipt = await ag.register()
            short = receipt.digest.hex()[:16] + "…" if receipt else "already-present"
            print(f"  registered {name:<11} receipt={short}")

        router = agent_handles["router"]
        router_id = identities["router"][1]
        # `before` and `kinds` were captured in the Phase-0 pre-snapshot
        # block above (via the bootstrap identity, before any demo
        # registrations); router.client is only used for the final
        # snapshot in Phase 8.

        # --- start dispatch loops --------------------------------------
        print("\n# Phase 2 — start dispatch loops")
        async with AsyncExitStack() as stack:
            for ag in agent_handles.values():
                await stack.enter_async_context(ag)
            print("  all five agents subscribed")

            # --- Phase 3: issue router's send_message capability -------
            print("\n# Phase 3 — issue capability")
            router_cap = yutha.Capability(
                spec_version="1.0.0",
                capability_id=secrets.token_bytes(16),
                swarm_id=swarm_id,
                issuer=yutha.Issuer.for_agent(router_id),
                subject=router_id,
                scope=yutha.Scope.for_action("send_message"),
                # See EPOCH_ZERO docstring: cross-process monotonic
                # clocks can't agree on "now", so anchor in the past.
                valid_from=EPOCH_ZERO,
                valid_until=FAR_FUTURE,
            )
            cap_id, issue_receipt = await router.client.capability.issue(router_cap)
            print(
                f"  router cap id={cap_id.digest.hex()[:16]}… "
                f"issuance receipt={issue_receipt.digest.hex()[:16]}…"
            )

            destinations: dict[str, yutha.AgentId] = {
                "billing": identities["billing"][1],
                "shipping": identities["shipping"][1],
                "returns": identities["returns"][1],
            }
            router_graph = build_router_graph(router, router_cap, destinations)

            # --- Phase 4: fan out tickets via the router's graph -------
            print("\n# Phase 4 — fan out tickets (classified + cap-gated)")
            for t in TICKETS:
                result = await router_graph.ainvoke({"ticket_text": t})
                print(f"  '{t[:50]}…' → {result['category']}")

            # --- Phase 5: wait for the escalation to land --------------
            print("\n# Phase 5 — wait for returns→supervisor escalation")
            for _ in range(50):
                if received["supervisor"]:
                    break
                await asyncio.sleep(0.1)
            assert received["supervisor"], (
                "supervisor never received the returns→supervisor escalation"
            )
            print(f"  supervisor received {len(received['supervisor'])} escalation(s)")

            # --- Phase 6: negative path — revoke + denied attempt ------
            print("\n# Phase 6 — revoke cap, attempt blocked send")
            await router.client.capability.revoke(cap_id, "demo: showing the gate is load-bearing")
            print("  router cap revoked")

            denied = False
            try:
                await router_graph.ainvoke(
                    {"ticket_text": "another billing question after revocation"}
                )
            except CapabilityDenied as e:
                denied = True
                print(f"  ✓ post-revoke send blocked: {e}")
            assert denied, (
                "router_graph.ainvoke after capability.revoke should have raised CapabilityDenied"
            )

            # --- Phase 7: returns self-revokes -------------------------
            print("\n# Phase 7 — returns self-revokes passport")
            returns = agent_handles["returns"]
            returns_id = identities["returns"][1]
            revoke_receipt = await returns.client.admission.revoke(
                returns_id, "s1 scenario cleanup"
            )
            print(f"  returns revoke receipt={revoke_receipt.digest.hex()[:16]}…")

            # --- Phase 8: snapshot delta and report --------------------
            print("\n# Phase 8 — audit-trail delta")
            after = await query_audit(router.client, kinds)
            delta = {k: after[k] - before[k] for k in kinds}
            for k in kinds:
                marker = "✓" if delta[k] == EXPECTED_AUDIT_DELTA[k] else "✗"
                print(f"  {marker} {k:<25} +{delta[k]:<2} (expected +{EXPECTED_AUDIT_DELTA[k]})")
            return delta
    finally:
        # Belt-and-braces channel close even on exceptions before the
        # AsyncExitStack opens (e.g. a register failure mid-loop).
        # YuthaClient.close is documented as idempotent.
        for ag in agent_handles.values():
            try:
                await ag.client.close()
            except Exception:
                pass


# -----------------------------------------------------------------------------
# CLI entry point
# -----------------------------------------------------------------------------


def main() -> None:
    delta = asyncio.run(run_s1())
    mismatches = {
        k: (delta[k], EXPECTED_AUDIT_DELTA[k])
        for k in EXPECTED_AUDIT_DELTA
        if delta[k] != EXPECTED_AUDIT_DELTA[k]
    }
    if mismatches:
        print(f"\n✗ audit-shape mismatch: got vs expected = {mismatches}")
        raise SystemExit(1)
    print("\n✓ audit-trail shape matches expectations")


if __name__ == "__main__":
    main()

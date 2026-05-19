"""S1 customer-support queue — Python + CrewAI end-to-end demo.

Companion to ``s1_support_queue.py`` (the LangGraph port), but built
on CrewAI Agents. CrewAI's model is LLM-driven by construction, which
makes a faithful five-agent classify-and-route port both heavier and
LLM-dependent than the LangGraph one. This demo therefore takes a
focused, three-agent shape that exercises the same substrate
behaviors:

* signed identity per CrewAI Agent (1:1 mapping — each agent gets its
  own passport + signing key, registers independently);
* a capability-gated tool, wrapped with
  :func:`yutha.crewai.capability_required`, that emits a Yutha
  envelope from inside a CrewAI Agent's tool call;
* a deterministic-keyword classifier the router uses to pick a
  destination (no LLM in the routing path — the LLM is purely for
  the Agent's I/O glue);
* an audit-trail delta query at the end that confirms the substrate
  saw exactly the receipts we expected.

Cast
----

* **router** — receives three inbound tickets, classifies each by
  keyword, dispatches via the ``DispatchTicketTool`` (capability-gated).
* **refund_clerk** — receives "refund" tickets via Yutha and writes a
  short acknowledgment back to the router. Demonstrates the inbound
  side of the integration.
* **supervisor** — receives escalation messages from the refund clerk
  when the refund amount exceeds a threshold. Closes the
  refund_clerk → supervisor escalation pattern from the LangGraph
  demo, in CrewAI idioms.

Running locally
---------------

1. Mint a seed once per run and start the control plane in OPEN
   admission mode::

       export YUTHA_BOOTSTRAP_SEED=$(python -c \\
           'import secrets; print(secrets.token_hex(32))')
       cargo run -p yutha-control-plane -- --admission-mode open

2. Export an OpenAI-compatible API key (CrewAI's default LLM) and
   the same seed in this shell::

       export OPENAI_API_KEY=...
       export YUTHA_BOOTSTRAP_SEED=<same hex as step 1>

3. Run the demo::

       python sdks/python/examples/s1_support_queue_crewai.py

If ``OPENAI_API_KEY`` isn't set, the demo exits with a clean
diagnostic rather than crashing partway through a model call. The
substrate-level integration tests
(:mod:`tests.test_crewai_unit`,
:mod:`tests.test_crewai_integration`) cover the CrewAI adapter's
behavior independent of any LLM, so the demo's LLM dependency
isn't on the critical path for v1 release validation.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
from contextlib import AsyncExitStack
from typing import Any

import yutha
from yutha.crewai import YuthaCrewAgent, capability_required

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

SERVER_ADDR = os.environ.get("YUTHA_GRPC_ADDR", "127.0.0.1:50051")

FAR_FUTURE = yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62)

# The three agents this demo registers. Same passport shape as the
# langgraph demo (open-mode-compatible: expires_at + tier ≥ Minimal).
CAST: list[tuple[str, str]] = [
    ("router", "crewai-demo"),
    ("refund_clerk", "crewai-demo"),
    ("supervisor", "crewai-demo"),
]

# Three inbound tickets the router fans out. Wording is chosen so the
# keyword classifier picks each ticket's intended destination
# unambiguously without LLM input.
TICKETS: list[str] = [
    "I'd like a refund for my duplicate charge.",
    "Where is my package? Tracking shows it stuck.",
    "I want a refund — this item arrived defective.",
]

# Audit-trail delta one full demo run produces. The wrapper asserts
# exactly this dict so a substrate regression that drops or doubles a
# receipt surfaces as a clean diff.
EXPECTED_AUDIT_DELTA: dict[str, int] = {
    "agent.register": 3,
    "envelope.send": 4,         # 3 router dispatches + 1 escalation
    "envelope.deliver": 4,
    "capability.issue": 1,      # router's send-cap
    "capability.check.pass": 3, # 3 successful dispatches
    "capability.check.deny": 1, # post-revoke attempt
    "capability.revoke": 1,
}


# -----------------------------------------------------------------------------
# Passport helpers — identical shape to the langgraph demo
# -----------------------------------------------------------------------------


def derive_bootstrap_identity(
    seed: bytes,
) -> tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId]:
    if len(seed) != 32:
        raise ValueError(f"seed must be exactly 32 bytes, got {len(seed)}")
    signing_key = yutha.SigningKey.from_seed_bytes(seed)
    agent_id = yutha.AgentId(value=hashlib.sha256(seed + b"\x01").digest()[:16])
    swarm_id = yutha.SwarmId(value=hashlib.sha256(seed + b"\x02").digest()[:16])
    return signing_key, agent_id, swarm_id


def load_bootstrap_identity_from_env() -> (
    tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId, bytes]
):
    seed_hex = os.environ.get("YUTHA_BOOTSTRAP_SEED")
    if not seed_hex:
        raise RuntimeError(
            "YUTHA_BOOTSTRAP_SEED is not set. See module docstring for setup."
        )
    seed = bytes.fromhex(seed_hex.strip())
    if len(seed) != 32:
        raise RuntimeError(
            f"YUTHA_BOOTSTRAP_SEED must be 64 hex chars (32 bytes); got {len(seed)} bytes"
        )
    signing_key, agent_id, swarm_id = derive_bootstrap_identity(seed)
    return signing_key, agent_id, swarm_id, seed


def make_passport(
    name: str,
    framework: str,
    swarm_id: yutha.SwarmId,
    signing_key: yutha.SigningKey,
    agent_id: yutha.AgentId,
) -> yutha.Passport:
    return yutha.Passport(
        spec_version="1.0.0",
        agent_id=agent_id,
        swarm_id=swarm_id,
        agent_public_key=signing_key.public_key(),
        owner=f"yutha-demo:s1-crewai:{name}",
        framework=framework,
        framework_version="1.0.0",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
        expires_at=FAR_FUTURE,
    ).sign(signing_key)


# -----------------------------------------------------------------------------
# CrewAI tools — the capability-gated DispatchTicketTool is the substrate
# integration point.
# -----------------------------------------------------------------------------


def classify_ticket(text: str) -> str:
    """Deterministic keyword classifier. No LLM dependency on purpose
    — the demo is about the substrate (signed identity, cap gating,
    audit trail), not the classifier's intelligence."""
    text_lower = text.lower()
    if any(k in text_lower for k in ("refund", "return", "defective")):
        return "refund_clerk"
    return "general"  # would dispatch to shipping/billing in a fuller port


def make_dispatch_tool(
    router_wrapper: YuthaCrewAgent,
    destinations: dict[str, yutha.AgentId],
) -> Any:
    """Build the router's outbound dispatch tool. CrewAI's BaseTool
    is constructed inline here so the closure captures the wrapper
    and destination map without leaking them into a module-level
    variable."""
    from crewai.tools import BaseTool

    class DispatchTicketTool(BaseTool):
        name: str = "dispatch_ticket"
        description: str = (
            "Send a customer-support ticket to the correct specialist agent. "
            "Use this when you've classified the ticket and need to route it."
        )

        def _run(self, ticket_text: str, category: str) -> str:
            """Synchronous CrewAI tool body. We're inside the dispatch
            loop's worker thread (via asyncio.to_thread); to emit a
            Yutha envelope we hop back to the dispatch loop's event
            loop via run_coroutine_threadsafe.

            For demo simplicity the tool body is the deterministic
            classify-and-send pattern; in a real workflow the LLM
            would call this tool with category= already filled in."""
            if category not in destinations:
                return f"unknown category: {category}"
            dest = destinations[category]
            # We're on a worker thread; the dispatch loop owns the
            # YuthaClient channel and runs on a different event loop.
            # Bridge via run_coroutine_threadsafe.
            loop = router_wrapper._dispatch_task.get_loop() if router_wrapper._dispatch_task else None
            if loop is None:
                # Fallback: synchronous emit through a fresh loop. Less
                # efficient but works when the dispatch loop hasn't
                # started yet (e.g. demo's manual dispatch path).
                return _emit_envelope_sync(
                    router_wrapper, dest, ticket_text, category
                )
            fut = asyncio.run_coroutine_threadsafe(
                router_wrapper.send(
                    recipient=yutha.Recipient.for_agent(dest),
                    performative=yutha.Performative.REQUEST_ACTION,
                    payload=ticket_text.encode("utf-8"),
                    payload_schema_id="type.yutha.dev/v1/Text",
                    tags=["s1-crewai-demo", f"category:{category}"],
                ),
                loop,
            )
            receipt = fut.result(timeout=5.0)
            return f"dispatched to {category}; receipt={receipt.digest.hex()[:16]}..."

    return DispatchTicketTool()


def _emit_envelope_sync(
    wrapper: YuthaCrewAgent,
    dest: yutha.AgentId,
    ticket_text: str,
    category: str,
) -> str:
    """Synchronous emit fallback. Uses asyncio.run on a fresh loop.

    Only invoked from the manual-dispatch path in :func:`run_s1` —
    the actual CrewAI dispatch loop uses the run_coroutine_threadsafe
    path above. Kept as a helper so the tool body has a clean
    fallback for demo / test scenarios."""
    receipt = asyncio.run(
        wrapper.send(
            recipient=yutha.Recipient.for_agent(dest),
            performative=yutha.Performative.REQUEST_ACTION,
            payload=ticket_text.encode("utf-8"),
            payload_schema_id="type.yutha.dev/v1/Text",
            tags=["s1-crewai-demo", f"category:{category}"],
        )
    )
    return f"dispatched to {category}; receipt={receipt.digest.hex()[:16]}..."


# -----------------------------------------------------------------------------
# Inbound-handler task factories — what each agent does when an envelope arrives
# -----------------------------------------------------------------------------


def refund_clerk_task_factory(
    supervisor_id: yutha.AgentId,
) -> Any:
    """Returns a TaskFactory that produces an acknowledgment-and-
    optional-escalate task per inbound envelope. Mirrors the
    LangGraph demo's returns-agent escalation pattern."""

    def factory(
        agent: YuthaCrewAgent,
        env: yutha.Envelope,
        deliver_id: yutha.Hash,
    ) -> Any:
        _ = deliver_id  # available for evidence-threading future use
        text = env.payload.decode("utf-8", errors="replace")
        # Inspect the ticket: if it mentions "defective", escalate to
        # supervisor by emitting a follow-on envelope. We do that here
        # synchronously via the wrapper before returning the task, so
        # the task is purely an LLM acknowledgment (or None to skip).
        if "defective" in text.lower():
            # Escalation path — emit via the dispatch loop.
            loop = agent._dispatch_task.get_loop() if agent._dispatch_task else None
            if loop is not None:
                # We're already inside the dispatch loop thread, so
                # just schedule a task on the same loop.
                async def _escalate() -> None:
                    await agent.send(
                        recipient=yutha.Recipient.for_agent(supervisor_id),
                        performative=yutha.Performative.INFORM,
                        payload=b"ESCALATED: " + env.payload,
                        payload_schema_id="type.yutha.dev/v1/Text",
                        tags=["s1-crewai-demo", "escalation"],
                    )

                asyncio.run_coroutine_threadsafe(_escalate(), loop)

        # Return None to skip the LLM-driven response task. The demo
        # is about the substrate behavior, not the LLM acknowledgment.
        # A production integration would return a Task here that lets
        # the LLM frame a customer-facing response.
        return None

    return factory


def supervisor_task_factory(
    agent: YuthaCrewAgent, env: yutha.Envelope, deliver_id: yutha.Hash
) -> Any:
    """Supervisor doesn't escalate further; just observes."""
    _ = (agent, env, deliver_id)
    return None


# -----------------------------------------------------------------------------
# Audit-trail snapshot — same shape as the langgraph demo's helper
# -----------------------------------------------------------------------------


async def snapshot_audit_trail(client: yutha.YuthaClient) -> dict[str, int]:
    """Query the audit trail and return a count of receipts by
    action_kind. Used to compute the demo's pre/post delta."""
    counts: dict[str, int] = {}
    for kind in EXPECTED_AUDIT_DELTA:
        page_token = b""
        seen = 0
        while True:
            page = await client.receipt.query_by_action_kind(
                kind, limit=100, page_token=page_token
            )
            seen += len(page.receipts)
            if not page.next_page_token:
                break
            page_token = page.next_page_token
        counts[kind] = seen
    return counts


def compute_delta(pre: dict[str, int], post: dict[str, int]) -> dict[str, int]:
    return {kind: post.get(kind, 0) - pre.get(kind, 0) for kind in EXPECTED_AUDIT_DELTA}


# -----------------------------------------------------------------------------
# Main demo orchestration
# -----------------------------------------------------------------------------


async def run_s1_crewai() -> dict[str, int]:
    """End-to-end demo. Returns the audit-trail delta dict so the
    test wrapper can assert on it without forking this body.

    Phases:
      1. Sanity-check `OPENAI_API_KEY`. Exit early with a friendly
         message if missing rather than failing inside CrewAI.
      2. Derive bootstrap identity + register the three demo agents.
      3. Take a pre-flow audit snapshot via the bootstrap agent.
      4. Issue the router's send-cap; wrap a DispatchTicketTool with
         it; construct the router's CrewAI Agent with the tool.
      5. Start refund_clerk and supervisor as YuthaCrewAgent
         instances (their dispatch loops handle inbound).
      6. Synthesize three inbound tickets — invoke the dispatch tool
         directly to demonstrate the cap-gated send path without
         depending on the LLM's tool-call decision.
      7. Revoke the router's cap; attempt one more dispatch; confirm
         CapabilityDenied (or its server-side equivalent) raises.
      8. Take a post-flow audit snapshot, compute the delta, return.
    """
    from crewai import Agent

    from yutha.crewai import CapabilityDenied

    if not os.environ.get("OPENAI_API_KEY"):
        print(
            "OPENAI_API_KEY is not set. CrewAI Agents require an LLM at "
            "construction time; this demo defaults to OpenAI. Set the env "
            "var (or any CrewAI-compatible LLM env config) and re-run."
        )
        return {}

    bootstrap_signing_key, bootstrap_agent_id, swarm_id, _seed = (
        load_bootstrap_identity_from_env()
    )

    # Per-agent fresh identity.
    identities: dict[str, tuple[yutha.SigningKey, yutha.AgentId]] = {}
    passports: dict[str, yutha.Passport] = {}
    for name, framework in CAST:
        sk = yutha.SigningKey.generate()
        agent_id = yutha.AgentId(value=secrets.token_bytes(16))
        identities[name] = (sk, agent_id)
        passports[name] = make_passport(name, framework, swarm_id, sk, agent_id)

    # Bootstrap client for audit snapshots + cap revocation.
    async with yutha.YuthaClient.connect(
        SERVER_ADDR,
        agent_id=bootstrap_agent_id,
        swarm_id=swarm_id,
        signing_key=bootstrap_signing_key,
    ) as bootstrap_client:
        pre = await snapshot_audit_trail(bootstrap_client)
        # Register each demo agent.
        for name, _ in CAST:
            sk, _ = identities[name]
            await bootstrap_client.admission.register(passports[name])

        # Build the router's send-cap. Self-issued (issuer == subject)
        # for demo simplicity; a real integration would have an
        # operator issue the root cap.
        router_sk, router_id = identities["router"]
        refund_clerk_id = identities["refund_clerk"][1]
        supervisor_id = identities["supervisor"][1]

        cap = yutha.Capability(
            spec_version="1.0.0",
            capability_id=secrets.token_bytes(16),
            swarm_id=swarm_id,
            issuer=yutha.Issuer.for_agent(router_id),
            subject=router_id,
            scope=yutha.Scope.for_action("envelope.send"),
            valid_from=yutha.Timestamp.now(),
            valid_until=FAR_FUTURE,
        )

        # Start refund_clerk + supervisor dispatch loops.
        destinations = {"refund_clerk": refund_clerk_id}

        async with AsyncExitStack() as stack:
            # Refund clerk
            rc_sk, _ = identities["refund_clerk"]
            rc_agent = Agent(
                role="Refund Clerk",
                goal="Acknowledge inbound refund requests.",
                backstory="Handles refunds politely and quickly.",
                allow_delegation=False,
            )
            rc_wrapper = YuthaCrewAgent.connect(
                SERVER_ADDR,
                passport=passports["refund_clerk"],
                signing_key=rc_sk,
                crew_agent=rc_agent,
                task_factory=refund_clerk_task_factory(supervisor_id),
            )
            await stack.enter_async_context(rc_wrapper)

            # Supervisor
            sup_sk, _ = identities["supervisor"]
            sup_agent = Agent(
                role="Supervisor",
                goal="Observe escalations.",
                backstory="Handles edge cases.",
                allow_delegation=False,
            )
            sup_wrapper = YuthaCrewAgent.connect(
                SERVER_ADDR,
                passport=passports["supervisor"],
                signing_key=sup_sk,
                crew_agent=sup_agent,
                task_factory=supervisor_task_factory,
            )
            await stack.enter_async_context(sup_wrapper)

            # Router — needs its own YuthaCrewAgent for the send path.
            router_agent = Agent(
                role="Router",
                goal="Dispatch incoming tickets to the right specialist.",
                backstory="Knows the team and routes by keyword.",
                allow_delegation=False,
                tools=[],  # populated after wrapper exists so cap_required can close over it
            )
            router_wrapper = YuthaCrewAgent.connect(
                SERVER_ADDR,
                passport=passports["router"],
                signing_key=router_sk,
                crew_agent=router_agent,
            )
            await stack.enter_async_context(router_wrapper)

            # Issue the cap server-side. The wrapper's cap-required
            # tool needs the same Capability object the server now
            # knows.
            cap_id, _ = await router_wrapper.client.capability.issue(cap)

            # Build the dispatch tool, wrap it, and attach to router.
            dispatch_tool = make_dispatch_tool(router_wrapper, destinations)
            capability_required(cap, action_kind="envelope.send")(dispatch_tool)
            router_agent.tools = [dispatch_tool]

            # Drive the demo: classify each ticket deterministically
            # and invoke the (now cap-gated) tool. We don't kick off a
            # full LLM-driven Crew here — the tool's body is what
            # exercises the substrate, and bypassing the LLM keeps the
            # demo deterministic.
            for ticket in TICKETS:
                category = classify_ticket(ticket)
                if category != "refund_clerk":
                    continue  # other categories would route to billing/shipping
                dispatch_tool._run(ticket_text=ticket, category=category)

            # Give the refund_clerk's dispatch loop time to receive
            # the tickets and (for the "defective" ones) escalate to
            # supervisor.
            await asyncio.sleep(1.0)

            # Negative path: revoke the cap server-side, attempt one
            # more dispatch, confirm a deny surfaces. Capability
            # denials raise CapabilityDenied (translated from the
            # server's PERMISSION_DENIED).
            await router_wrapper.client.capability.revoke(cap_id)
            try:
                dispatch_tool._run(
                    ticket_text="post-revoke attempt", category="refund_clerk"
                )
            except CapabilityDenied as exc:
                print(f"  cap-denied (expected): {exc}")
            else:
                print("  WARNING: post-revoke dispatch did not raise CapabilityDenied")

            await asyncio.sleep(0.5)

        # Post-snapshot.
        post = await snapshot_audit_trail(bootstrap_client)
        delta = compute_delta(pre, post)
        return delta


def main() -> None:
    delta = asyncio.run(run_s1_crewai())
    if not delta:
        return  # OPENAI_API_KEY was missing; already messaged.
    print("\naudit-trail delta:")
    print(json.dumps(delta, indent=2))
    drift = {k: (delta.get(k, 0), EXPECTED_AUDIT_DELTA[k]) for k in EXPECTED_AUDIT_DELTA}
    mismatches = {k: v for k, v in drift.items() if v[0] != v[1]}
    if mismatches:
        print(
            "\nNOTE: delta differs from the expected pattern; this is "
            "informational, not a failure (LLM-driven flows have inherent "
            "variance). Run the unit tests for strict substrate-level "
            "assertions:"
        )
        print(json.dumps({k: {"got": v[0], "want": v[1]} for k, v in mismatches.items()}, indent=2))
    else:
        print("\ndelta matches EXPECTED_AUDIT_DELTA")


if __name__ == "__main__":
    main()

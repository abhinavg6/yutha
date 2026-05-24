"""Research crew with citation enforcement — Python + OpenAI Agents
end-to-end demo.

Three OpenAI Agents agents collaborating on a research brief:
a researcher that gathers raw material, a fact-checker that
verifies the citations, and an editor that publishes the final
brief. The substrate point is **citation verification as a
constitutional requirement**: the editor agent may only publish
envelopes that carry the ``verified_citations`` tag, and the
four-stage enforcement loop trips on any agent that tries to
bypass that boundary.

Companion to ``code_review.py`` (LangGraph) and
``ap_invoice.py`` (CrewAI). Same substrate machinery — different
framework idioms, different business framing. This example is the
first to use OpenAI Agents' **handoff** primitive: every
researcher → fact_checker → editor transition fires a
``RunHooks.on_handoff`` event, which the
:class:`yutha.openai_agents.YuthaRunHooks` bridge turns into a
Yutha envelope. The substrate audit log captures the full agent
collaboration chain.

Cast
----

* **researcher** (``framework: openai-research-crew-researcher``) —
  receives a topic prompt, "researches" via tightly-constrained
  instructions, hands off to ``fact_checker``.
* **fact_checker** (``framework: openai-research-crew-fact-checker``) —
  reviews the researcher's draft, hands off to ``editor``.
* **editor** (``framework: openai-research-crew-editor``) —
  composes the final brief, calls a cap-gated ``publish_brief``
  function tool. Subject of bypass attempts.

Constitution
------------

The active constitution forbids ``SendEnvelope`` when an envelope
is tagged ``claim_published`` but NOT ``verified_citations``. The
editor's ``publish_brief`` tool adds the ``verified_citations``
tag iff its ``cited`` parameter is true — happy-path runs go
through with both tags; bypass attempts (the demo orchestrator
calls the tool's underlying impl directly with ``cited=False``)
emit ``claim_published`` alone and trip the constitution.

The engine config attaches a single enforcement rule covering
all four stages (detect → coach → quarantine → evict) with 1-
second cooldowns, identical in shape to the code-review and
ap-invoice demos. ``count_threshold: 2`` means two denies within
a 60-second window for the same principal fire detect; the
chain then progresses on the server's wall-clock scheduler.

Running locally
---------------

OpenAI Agents requires an LLM credential at construction time;
the substrate path bypasses the LLM for the bypass-attempt
phases but uses it for the happy-path Runner.run. Set
``OPENAI_API_KEY`` (or any other OpenAI-Agents-compatible LLM
config) plus the bootstrap seed and the operator pubkey:

::

    export YUTHA_BOOTSTRAP_SEED=$(python -c \\
        'import secrets; print(secrets.token_hex(32))')
    export OPENAI_API_KEY=...

    cargo run -p yutha-control-plane -- \\
        --admission-mode open \\
        --operator-public-key $(python sdks/python/examples/research_crew.py --print-operator-pubkey)

    python sdks/python/examples/research_crew.py

What the demo exercises
-----------------------

The flow is structured around a **mid-flow audit snapshot** that
splits LLM-driven and substrate-driven receipt counts, so the
strict-equality assertion only covers the deterministic
substrate path:

* Phases 1-4: Three OpenAI Agents agents register with distinct
  ``framework`` labels; the operator activates a custom
  research-crew constitution; the editor is issued a send cap.
* Phase 5 — **LLM exploration (informational only)**: the
  orchestrator invokes ``Runner.run(researcher, "topic X")``.
  Tight instructions try to steer the LLM through the
  ``researcher → fact_checker → editor → publish_brief(cited=True)``
  chain, but handoff invocations are ultimately LLM-driven and
  non-deterministic. Whatever happens, the substrate captures
  it: handoffs that the LLM actually invokes fire the
  :class:`yutha.openai_agents.YuthaRunHooks` bridge and emit
  audit envelopes; a successful publish at the editor produces
  ``claim_published + verified_citations``. **None of these
  counts are strict-asserted** — they're reported as
  informational in the pre→mid block.
* Mid-flow snapshot.
* Phase 6 — **deterministic happy publish**: the orchestrator
  calls the editor's publish helper directly with ``cited=True``.
  Always produces exactly one ``claim_published +
  verified_citations`` envelope that the constitution permits.
* Phases 7-8 — **bypass attempts**: orchestrator calls the
  editor's publish helper with ``cited=False``. Both raise
  ``ConstitutionDenied`` with ``deny_reason =
  "forbid_rule_matched"`` and trip the enforcement chain on the
  second attempt.
* Phases 9-11 — **enforcement chain**: detect → coach →
  quarantine, then a cap-check that returns ``subject_quarantined``,
  then evict.
* Phase 12 — **Mid → After delta**: strict equality on every
  deterministic substrate count.

The substrate-correctness signal lives in the mid→after window.
The pre→mid window reports whatever the LLM did and asserts only
on the three counts that fire from substrate code (register,
constitution.activate, capability.issue) — those are
deterministic regardless of LLM behavior.

The ``run_research_crew()`` coroutine returns the mid→after
delta dict for the test wrapper / ``main()`` to assert against.

LLM caveat
----------

OpenAI Agents has no deterministic-runner mode — the Phase 5
``Runner.run`` hits a real LLM. The model may not always invoke
the configured handoffs in the expected order (sometimes it
narrates a handoff in prose instead of issuing the
``transfer_to_<name>`` tool call, sometimes it stops at the
researcher's draft, etc.). That nondeterminism is captured in
the pre→mid block but **does not affect** the mid→after strict
assertion, because Phases 6-11 don't run any LLM-driven code.
If you see ``✗`` markers in the mid→after block, that's a real
substrate regression — investigate. If you see varying counts
in the pre→mid block across runs, that's expected LLM behavior.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import sys
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack
from typing import Any

import yutha
from yutha.langgraph.tools import CapabilityDenied
from yutha.models.constitution import Constitution
from yutha.openai_agents import YuthaOpenAIAgent, capability_required

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

SERVER_ADDR = os.environ.get("YUTHA_GRPC_ADDR", "127.0.0.1:50051")

FAR_FUTURE = yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62)

# Per-stage wall-clock budget for the enforcement chain.
ENFORCEMENT_STAGE_TIMEOUT_SECONDS = 15.0
ENFORCEMENT_POLL_INTERVAL_SECONDS = 0.25

# Tag conventions. Constitution keys on these.
TAG_CLAIM_PUBLISHED = "claim_published"
TAG_VERIFIED_CITATIONS = "verified_citations"
DEMO_TAG = "research-crew-demo"

# -----------------------------------------------------------------------------
# Constitution (Cedar source + engine config)
# -----------------------------------------------------------------------------
#
# Forbid `claim_published` envelopes that lack the
# `verified_citations` tag. The editor's publish tool adds
# `verified_citations` iff its `cited` parameter is true. The
# happy-path Runner.run causes the LLM to call publish_brief
# with cited=True. The bypass paths invoke the tool's underlying
# impl directly with cited=False, producing the forbidden combo.

_RESEARCH_CREW_CEDAR_SOURCE = """\
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
"""

_RESEARCH_CREW_ENGINE_CONFIG_YAML = """\
schema_version: "1.1.0"
predicates: []
scoring_rules: []
procedures: []
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
"""


def build_research_crew_constitution(swarm_id: yutha.SwarmId) -> Constitution:
    """Build the research-crew demo's constitution. Inlined so the
    file is self-describing — the rule governing the swarm sits
    next to the agents it governs."""
    return Constitution(
        spec_version="1.0.0",
        schema_version="1.1.0",
        constitution_version="1.0.0",
        parent_version=None,
        swarm_id=swarm_id,
        cedar_source=_RESEARCH_CREW_CEDAR_SOURCE,
        engine_config_yaml=_RESEARCH_CREW_ENGINE_CONFIG_YAML,
        issued_at=yutha.Timestamp.now(),
    )


# -----------------------------------------------------------------------------
# Cast
# -----------------------------------------------------------------------------

CAST: list[tuple[str, str]] = [
    ("researcher", "openai-research-crew-researcher"),
    ("fact_checker", "openai-research-crew-fact-checker"),
    ("editor", "openai-research-crew-editor"),
]

# Topic the demo asks the researcher to write a brief on. Picked
# to be deterministic-friendly — the LLM has nothing controversial
# to deliberate over, just a quick handoff chain to traverse.
DEMO_TOPIC = (
    "the history of the Sanskrit word 'yutha' (group, herd) in vedic and post-vedic literature"
)


# -----------------------------------------------------------------------------
# Expected audit-trail delta
# -----------------------------------------------------------------------------

# The demo's audit-delta assertion is split into TWO windows around
# a mid-flow snapshot, because OpenAI Agents' handoff invocation is
# LLM-driven and non-deterministic — a given Runner.run might
# perform 0, 1, or 2 handoffs depending on how the model interprets
# the agent's instructions, and might or might not reach the
# editor's publish_brief tool. Asserting strict equality on those
# counts would make the demo flaky.
#
# The split:
#
#   * **Pre → Mid** covers Phases 1-5 (register + activate + cap
#     issue + LLM-driven exploration). The substrate-side counts
#     fire deterministically; the LLM-driven counts go into
#     :data:`LLM_INFORMATIONAL_KINDS` and are reported but not
#     asserted.
#   * **Mid → After** covers Phases 6-12 (deterministic happy
#     publish + 2 bypass attempts + enforcement chain + final
#     cap-check). Every receipt here fires from substrate-driven
#     code paths the orchestrator controls, so strict equality
#     holds run-to-run regardless of LLM behavior.

# Deterministic counts that fire BEFORE the LLM-driven phase.
EXPECTED_PRE_TO_MID_DELTA: dict[str, int] = {
    # 3 agents register.
    "agent.register": 3,
    # Operator activates the constitution.
    "constitution.activate": 1,
    # Editor gets its send capability.
    "capability.issue": 1,
}

# LLM-driven counts that VARY between runs. Reported as
# informational under the pre→mid block; not asserted.
#
# Maximum possible per-run contribution to each (when the LLM does
# the full chain — 2 handoffs + 1 editor publish_brief): +3 for
# the first three, +1 for capability.check.pass.
LLM_INFORMATIONAL_KINDS: frozenset[str] = frozenset(
    {
        "envelope.send",
        "envelope.deliver",
        "constitution.evaluate.pass",
        "capability.check.pass",
    }
)

# Deterministic counts that fire AFTER the LLM-driven phase
# (Phase 6 onward). Strict equality is asserted on this dict.
EXPECTED_MID_TO_AFTER_DELTA: dict[str, int] = {
    # Phase 6 — orchestrator calls editor_publish(cited=True)
    # directly: 1 envelope.send + envelope.deliver +
    # constitution.evaluate.pass + capability.check.pass.
    "envelope.send": 1,
    "envelope.deliver": 1,
    "constitution.evaluate.pass": 1,
    # Phases 7-8 — 2 bypass attempts deny at constitution layer
    # (after passing cap-check).
    "constitution.evaluate.deny": 2,
    # Phase 6 + Phases 7-8 — 1 happy + 2 bypasses pass cap-check
    # (cap-check fires before constitution-check; cap is still
    # valid for all three since quarantine hasn't fired yet).
    "capability.check.pass": 3,
    # Phase 10 — explicit post-quarantine cap-check denies.
    "capability.check.deny": 1,
    # Phases 9 + 11 — four stages of the enforcement loop.
    "enforcement.detect": 1,
    "enforcement.coach": 1,
    "enforcement.quarantine": 1,
    "enforcement.evict": 1,
}

# Union of all kinds we snapshot. Used by the query helpers below.
ALL_KINDS: list[str] = sorted(
    set(EXPECTED_PRE_TO_MID_DELTA) | set(EXPECTED_MID_TO_AFTER_DELTA) | LLM_INFORMATIONAL_KINDS
)


# -----------------------------------------------------------------------------
# Bootstrap identity (mirrors S1 / code_review / ap_invoice)
# -----------------------------------------------------------------------------


def derive_bootstrap_identity(
    seed: bytes,
) -> tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId]:
    """Reproduce ``BootstrapIdentity::from_seed_hex``."""
    if len(seed) != 32:
        raise ValueError(f"seed must be exactly 32 bytes, got {len(seed)}")
    signing_key = yutha.SigningKey.from_seed_bytes(seed)
    agent_id = yutha.AgentId(value=hashlib.sha256(seed + b"\x01").digest()[:16])
    swarm_id = yutha.SwarmId(value=hashlib.sha256(seed + b"\x02").digest()[:16])
    return signing_key, agent_id, swarm_id


def derive_operator_identity(seed: bytes) -> tuple[yutha.SigningKey, yutha.PublicKey]:
    """Domain-separated derivation of the operator keypair."""
    if len(seed) != 32:
        raise ValueError(f"seed must be exactly 32 bytes, got {len(seed)}")
    op_seed = hashlib.sha256(seed + b"\x03").digest()
    op_signing = yutha.SigningKey.from_seed_bytes(op_seed)
    return op_signing, op_signing.public_key()


def load_bootstrap_identity_from_env() -> tuple[
    yutha.SigningKey, yutha.AgentId, yutha.SwarmId, bytes
]:
    """Read ``YUTHA_BOOTSTRAP_SEED`` and derive the full identity."""
    seed_hex = os.environ.get("YUTHA_BOOTSTRAP_SEED")
    if not seed_hex:
        raise RuntimeError(
            "YUTHA_BOOTSTRAP_SEED is not set. See the module docstring for the full setup."
        )
    try:
        seed = bytes.fromhex(seed_hex.strip())
    except ValueError as e:
        raise RuntimeError(f"YUTHA_BOOTSTRAP_SEED is not valid hex: {e}") from e
    if len(seed) != 32:
        raise RuntimeError(
            f"YUTHA_BOOTSTRAP_SEED must be exactly 64 hex chars (32 bytes); got {len(seed)} bytes"
        )
    signing_key, agent_id, swarm_id = derive_bootstrap_identity(seed)
    return signing_key, agent_id, swarm_id, seed


# -----------------------------------------------------------------------------
# Passport helper
# -----------------------------------------------------------------------------


def make_passport(
    name: str,
    framework: str,
    swarm_id: yutha.SwarmId,
    signing_key: yutha.SigningKey,
    agent_id: yutha.AgentId,
) -> yutha.Passport:
    """Build a signed passport."""
    return yutha.Passport(
        spec_version="1.0.0",
        agent_id=agent_id,
        swarm_id=swarm_id,
        agent_public_key=signing_key.public_key(),
        owner=f"yutha-demo:research-crew:{name}",
        framework=framework,
        framework_version="1.0.0",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
        expires_at=FAR_FUTURE,
    ).sign(signing_key)


# -----------------------------------------------------------------------------
# Editor publish helper
# -----------------------------------------------------------------------------


def build_editor_publish(
    editor_wrapper: YuthaOpenAIAgent,
    editor_cap: yutha.Capability,
    publisher_id: yutha.AgentId,
) -> Callable[[str, bool], Awaitable[yutha.Hash]]:
    """Return an async function that sends a ``claim_published``
    envelope from the editor to a publisher (the researcher in
    this demo, used as a passive observer).

    Wrapped with ``@capability_required`` so every send hits a
    server-side cap check before the envelope is signed. The
    ``cited`` parameter controls whether the
    ``verified_citations`` tag is added — happy-path runs pass
    ``True``; bypass attempts pass ``False``.
    """

    @capability_required(editor_cap, action_kind="envelope.send")
    async def publish_brief(content: str, cited: bool) -> yutha.Hash:
        tags = [DEMO_TAG, TAG_CLAIM_PUBLISHED]
        if cited:
            tags.append(TAG_VERIFIED_CITATIONS)
        return await editor_wrapper.send(
            recipient=yutha.Recipient.for_agent(publisher_id),
            performative=yutha.Performative.INFORM,
            payload=content.encode("utf-8"),
            payload_schema_id="type.yutha.dev/v1/Text",
            tags=tags,
        )

    return publish_brief


# -----------------------------------------------------------------------------
# Audit helpers
# -----------------------------------------------------------------------------


async def query_audit(client: yutha.YuthaClient, kinds: list[str]) -> dict[str, int]:
    """Snapshot receipt counts for each action_kind."""
    counts: dict[str, int] = {}
    for kind in kinds:
        receipts, _ = await client.receipt.query_by_action_kind(kind)
        counts[kind] = len(receipts)
    return counts


async def wait_for_kind_delta(
    client: yutha.YuthaClient,
    kind: str,
    before_count: int,
    expected_delta: int,
    *,
    timeout_seconds: float = ENFORCEMENT_STAGE_TIMEOUT_SECONDS,
    poll_interval_seconds: float = ENFORCEMENT_POLL_INTERVAL_SECONDS,
) -> None:
    """Poll until the count of ``kind`` has grown by
    ``expected_delta`` since ``before_count``."""
    deadline = asyncio.get_event_loop().time() + timeout_seconds
    while asyncio.get_event_loop().time() < deadline:
        receipts, _ = await client.receipt.query_by_action_kind(kind)
        if len(receipts) - before_count >= expected_delta:
            return
        await asyncio.sleep(poll_interval_seconds)
    receipts, _ = await client.receipt.query_by_action_kind(kind)
    raise AssertionError(
        f"timed out after {timeout_seconds}s waiting for delta>={expected_delta} "
        f"on {kind!r}; before={before_count} now={len(receipts)}"
    )


# -----------------------------------------------------------------------------
# Main flow
# -----------------------------------------------------------------------------


async def run_research_crew(server_addr: str = SERVER_ADDR) -> dict[str, int]:
    """Run the research-crew demo end-to-end against ``server_addr``.

    Returns the audit-trail delta keyed by action_kind."""
    print(f"# research crew demo · server={server_addr}")

    # Lazy openai-agents import — heavy transitive deps.
    try:
        from agents import Agent, function_tool
    except ImportError as e:
        raise RuntimeError(
            "openai-agents is not installed. Run:\n"
            "    cd sdks/python && uv pip install -e '.[dev,openai-agents]'\n"
            "and re-run this demo."
        ) from e

    if not os.environ.get("OPENAI_API_KEY"):
        print(
            "OPENAI_API_KEY is not set. OpenAI Agents' Runner.run requires "
            "an LLM credential. Set the env var (or any other openai-agents-"
            "compatible model config) and re-run."
        )
        return {}

    # --- bootstrap identity ------------------------------------------------
    bootstrap_key, bootstrap_agent_id, swarm_id, seed = load_bootstrap_identity_from_env()
    print(f"# swarm_id={swarm_id.value.hex()} (from YUTHA_BOOTSTRAP_SEED)")

    op_signing_key, op_public_key = derive_operator_identity(seed)
    print(f"# operator pubkey: {op_public_key.value.hex()}")

    # --- Phase 0: pre-flow audit snapshot ---------------------------------
    kinds = list(ALL_KINDS)
    async with yutha.YuthaClient.connect(
        server_addr,
        agent_id=bootstrap_agent_id,
        swarm_id=swarm_id,
        signing_key=bootstrap_key,
    ) as bootstrap_client:
        before = await query_audit(bootstrap_client, kinds)
    print(f"# pre-flow snapshot taken via bootstrap agent {bootstrap_agent_id.value.hex()[:16]}…")

    # --- identities + passports -------------------------------------------
    identities: dict[str, tuple[yutha.SigningKey, yutha.AgentId, yutha.Passport]] = {}
    for name, framework in CAST:
        key = yutha.SigningKey.generate()
        agent_id = yutha.AgentId(value=secrets.token_bytes(16))
        passport = make_passport(name, framework, swarm_id, key, agent_id)
        identities[name] = (key, agent_id, passport)

    # --- OpenAI Agents Agent instances (constructed up front) -------------
    # Tight instructions: each handoff is an explicit step the
    # LLM should take immediately. The publish step adds the
    # verified_citations tag iff the brief was fact-checked.
    researcher_agent: Any  # forward-declared so handoffs can reference
    fact_checker_agent: Any
    editor_agent: Any

    # We build the chain inside-out: editor first (no further
    # handoff), then fact_checker (handoffs to editor), then
    # researcher (handoffs to fact_checker).
    # publish_brief is bound after the editor wrapper exists +
    # the cap is issued, so we attach the editor's tools list
    # after the fact.
    editor_agent = Agent(
        name="ResearchEditor",
        instructions=(
            "You are the editor on a 3-person research team. "
            "You will receive a fact-checked research brief on a "
            "Sanskrit-etymology topic. Your job: immediately call "
            "the `publish_brief` tool exactly once, passing "
            "`content` = your final brief (one paragraph, max 80 words) "
            "and `cited=True` (the brief came pre-verified from the "
            "fact-checker, so citations are confirmed). Do NOT do "
            "any extra research, do NOT critique the brief, do NOT "
            "ask clarifying questions. Just publish."
        ),
        tools=[],  # publish_brief gets attached after the cap is issued
    )
    fact_checker_agent = Agent(
        name="ResearchFactChecker",
        instructions=(
            "You are the fact-checker on a 3-person research team. "
            "You will receive a draft research brief on a Sanskrit-"
            "etymology topic. Your job: in ONE sentence acknowledge "
            "the brief is consistent with known sources, then "
            "immediately hand off to the `ResearchEditor` agent. "
            "Do NOT rewrite the brief, do NOT add commentary, do "
            "NOT ask questions."
        ),
        handoffs=[editor_agent],
    )
    researcher_agent = Agent(
        name="ResearchResearcher",
        instructions=(
            "You are the researcher on a 3-person research team. "
            "Given a topic, write a ONE-paragraph (max 60 word) draft "
            "research brief on it. Then immediately hand off to the "
            "`ResearchFactChecker` agent. Do NOT publish, do NOT call "
            "any tools, do NOT ask clarifying questions."
        ),
        handoffs=[fact_checker_agent],
    )

    oai_agents = {
        "researcher": researcher_agent,
        "fact_checker": fact_checker_agent,
        "editor": editor_agent,
    }

    # --- Phase 1: connect + register --------------------------------------
    print("\n# Phase 1 — connect + register")
    wrappers: dict[str, YuthaOpenAIAgent] = {}
    try:
        for name, (key, _agent_id, passport) in identities.items():
            wrapper = YuthaOpenAIAgent.connect(
                server_addr,
                passport=passport,
                signing_key=key,
                oai_agent=oai_agents[name],
                # Dispatch loops are no-ops in this demo — the
                # orchestrator drives every Runner.run directly
                # (Phase 5 happy path + Phases 6-7 bypass attempts).
                # Without this lambda, inbound envelopes (the
                # handoff-audit envelopes the bridge emits, plus
                # the editor's published-brief envelope landing on
                # the researcher's inbox) would each trigger a
                # fresh Runner.run on the receiving agent — the
                # cascading LLM runs produce unpredictable extra
                # sends and shift the audit delta. Returning None
                # tells the dispatch loop to skip every envelope.
                input_factory=lambda _agent, _env, _deliver: None,
            )
            wrappers[name] = wrapper
            receipt = await wrapper.register()
            short = receipt.digest.hex()[:16] + "…" if receipt else "already-present"
            print(f"  registered {name:<13} receipt={short}")

        researcher_id = identities["researcher"][1]
        editor_id = identities["editor"][1]
        _ = researcher_id  # kept for symmetry / future use

        async with AsyncExitStack() as stack:
            print("\n# Phase 2 — start dispatch loops")
            for wrapper in wrappers.values():
                await stack.enter_async_context(wrapper)
            print("  all three agents subscribed")

            # Peer registry: lets the YuthaRunHooks address each
            # handoff envelope to the actual target agent's inbox
            # (rather than a self-loop). The Agent names here MUST
            # match the framework Agent.name fields above.
            peer_registry = {
                "ResearchFactChecker": wrappers["fact_checker"],
                "ResearchEditor": wrappers["editor"],
                "ResearchResearcher": wrappers["researcher"],
            }
            for wrapper in wrappers.values():
                wrapper._get_hooks().register_peers(peer_registry)

            # --- Phase 3: operator activates the constitution -------------
            print("\n# Phase 3 — operator activates research-crew constitution")
            constitution = build_research_crew_constitution(swarm_id)
            async with yutha.YuthaClient.connect_as_operator(
                server_addr,
                operator_id="yutha-demo:research-crew:operator",
                swarm_id=swarm_id,
                operator_signing_key=op_signing_key,
            ) as op_client:
                activated = await op_client.constitution.activate(constitution)
            print(
                f"  constitution_hash={activated.constitution_hash.digest.hex()[:16]}… "
                f"activate_receipt={activated.activate_receipt.digest.hex()[:16]}…"
            )

            # --- Phase 4: issue editor's send cap ------------------------
            print("\n# Phase 4 — issue editor send capability")
            editor_cap = yutha.Capability(
                spec_version="1.0.0",
                capability_id=secrets.token_bytes(16),
                swarm_id=swarm_id,
                issuer=yutha.Issuer.for_agent(editor_id),
                subject=editor_id,
                scope=yutha.Scope.for_action("envelope.send"),
                valid_from=yutha.Timestamp.now(),
                valid_until=FAR_FUTURE,
            )
            cap_id, issue_receipt = await wrappers["editor"].client.capability.issue(editor_cap)
            print(
                f"  editor cap id={cap_id.digest.hex()[:16]}… "
                f"issuance receipt={issue_receipt.digest.hex()[:16]}…"
            )

            # Bind the publish helper + attach to editor agent.
            # The "publisher" recipient is the researcher (used
            # as a passive observer for the published brief).
            editor_publish = build_editor_publish(wrappers["editor"], editor_cap, researcher_id)
            editor_agent.tools = [function_tool(editor_publish)]

            # --- Phase 5: LLM-driven exploration (informational) ---------
            #
            # researcher.run drives the OpenAI Agents handoff
            # primitive. The LLM MAY traverse the full handoff
            # chain (researcher → fact_checker → editor → call
            # publish_brief), or it may stop short — handoffs are
            # ultimately the LLM's choice. The substrate captures
            # whatever happens via the YuthaRunHooks bridge, but
            # we don't assert on the receipt counts here because
            # they vary by LLM behavior. The deterministic
            # substrate enforcement (constitution + cap-gating +
            # four-stage chain) is exercised by Phases 6-11 below
            # under strict equality.
            print(f"\n# Phase 5 — LLM exploration (topic: '{DEMO_TOPIC[:50]}…')")
            try:
                result = await wrappers["researcher"].run(DEMO_TOPIC)
                final_text = str(getattr(result, "final_output", "")) or "<empty>"
                print(f"  LLM final output: {final_text[:80]}{'…' if len(final_text) > 80 else ''}")
            except Exception as e:
                print(
                    f"  LLM run raised {type(e).__name__}: {e} "
                    "(informational; continuing to deterministic phases)"
                )

            # --- Mid-flow snapshot ----------------------------------------
            #
            # Splits the audit-delta assertion. Counts before this
            # snapshot are part of the pre→mid reporting block
            # below — deterministic kinds asserted, LLM-driven
            # kinds informational. Counts after this snapshot are
            # the strict-equality mid→after block at the end.
            mid = await query_audit(wrappers["editor"].client, kinds)
            print("\n# Pre → Mid delta (LLM exploration may have produced extra receipts)")
            for k in kinds:
                v = mid[k] - before[k]
                if k in EXPECTED_PRE_TO_MID_DELTA:
                    expected = EXPECTED_PRE_TO_MID_DELTA[k]
                    marker = "✓" if v == expected else "✗"
                    print(f"  {marker} {k:<28} +{v:<2} (expected +{expected})")
                elif k in LLM_INFORMATIONAL_KINDS:
                    print(f"  · {k:<28} +{v:<2} (LLM-driven; varies, not asserted)")
                elif v != 0:
                    print(f"  ! {k:<28} +{v:<2} (unexpected — should be 0 in pre→mid)")

            # --- Phase 6: deterministic happy publish --------------------
            #
            # Orchestrator calls editor_publish directly with
            # cited=True. This is the substrate-deterministic
            # equivalent of "editor publishes a verified brief" —
            # no LLM involved, guaranteed to produce exactly 1
            # envelope.send + 1 envelope.deliver + 1
            # constitution.evaluate.pass + 1 capability.check.pass.
            print("\n# Phase 6 — deterministic happy publish (cited=True)")
            happy_receipt = await editor_publish(
                "Verified research brief on Yutha etymology.", True
            )
            print(f"  ✓ published; envelope.send receipt={happy_receipt.digest.hex()[:16]}…")

            # --- Phase 7: bypass attempt #1 ------------------------------
            #
            # Editor calls its own publish helper with cited=False.
            # The constitution forbids `claim_published` without
            # `verified_citations`. The Send RPC raises
            # ConstitutionDenied with the structured deny_reason.
            print("\n# Phase 7 — editor bypass attempt #1 (cited=False)")
            denied_1 = await _attempt_bypass(editor_publish)
            assert denied_1.deny_reason == "forbid_rule_matched", (
                f"expected forbid_rule_matched, got {denied_1.deny_reason!r}"
            )
            print(f"  ✓ denied: {denied_1}")

            # --- Phase 8: bypass attempt #2 → enforcement.detect ---------
            print("\n# Phase 8 — editor bypass attempt #2 (trips enforcement.detect)")
            denied_2 = await _attempt_bypass(editor_publish)
            assert denied_2.deny_reason == "forbid_rule_matched"
            print(f"  ✓ denied: {denied_2}")

            # --- Phase 9: poll for detect → coach → quarantine ----------
            print("\n# Phase 9 — poll for detect → coach → quarantine")
            for stage in (
                "enforcement.detect",
                "enforcement.coach",
                "enforcement.quarantine",
            ):
                await wait_for_kind_delta(
                    wrappers["editor"].client, stage, mid[stage], expected_delta=1
                )
                print(f"  ✓ {stage} landed")

            # --- Phase 10: cap-check denies WHILE quarantined ------------
            print("\n# Phase 10 — verify quarantine denies editor cap-check")
            check_outcome = await wrappers["editor"].client.capability.check(
                editor_cap,
                yutha.ActionDescriptor(action_kind="envelope.send"),
            )
            assert not check_outcome.permitted, (
                "quarantined editor should be denied even on a still-valid cap"
            )
            assert check_outcome.deny_reason == "subject_quarantined", (
                f"expected subject_quarantined, got {check_outcome.deny_reason!r}"
            )
            print(f"  ✓ cap-check denied with reason={check_outcome.deny_reason}")

            # --- Phase 11: wait for evict --------------------------------
            print("\n# Phase 11 — wait for enforcement.evict")
            await wait_for_kind_delta(
                wrappers["editor"].client,
                "enforcement.evict",
                mid["enforcement.evict"],
                expected_delta=1,
            )
            print("  ✓ enforcement.evict landed")

            # --- Phase 12: mid→after audit delta (strict-asserted) -------
            print("\n# Phase 12 — Mid → After delta (strict assertion)")
            after = await query_audit(wrappers["editor"].client, kinds)
            delta = {k: after[k] - mid[k] for k in kinds}
            for k in kinds:
                if k in EXPECTED_MID_TO_AFTER_DELTA:
                    expected = EXPECTED_MID_TO_AFTER_DELTA[k]
                    marker = "✓" if delta[k] == expected else "✗"
                    print(f"  {marker} {k:<28} +{delta[k]:<2} (expected +{expected})")
                elif delta[k] != 0:
                    print(f"  ! {k:<28} +{delta[k]:<2} (unexpected — should be 0 in mid→after)")
            return delta
    finally:
        for wrapper in wrappers.values():
            try:
                await wrapper.client.close()
            except Exception:
                pass


async def _attempt_bypass(
    publish: Callable[[str, bool], Awaitable[yutha.Hash]],
) -> yutha.ConstitutionDenied:
    """Drive one editor bypass attempt and return the structured deny."""
    try:
        await publish("Unverified draft of a research claim.", False)
    except yutha.ConstitutionDenied as e:
        return e
    except CapabilityDenied as e:
        raise AssertionError(
            f"bypass attempt should have raised ConstitutionDenied, not CapabilityDenied: {e}"
        ) from None
    raise AssertionError("bypass attempt should have raised ConstitutionDenied")


# -----------------------------------------------------------------------------
# CLI entry points
# -----------------------------------------------------------------------------


def _print_operator_pubkey() -> None:
    """Derive + print the operator pubkey from the bootstrap seed."""
    _, _, _, seed = load_bootstrap_identity_from_env()
    _, op_public_key = derive_operator_identity(seed)
    print(op_public_key.value.hex())


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--print-operator-pubkey":
        _print_operator_pubkey()
        return
    delta = asyncio.run(run_research_crew())
    if not delta:
        return  # OPENAI_API_KEY missing; the run printed a diagnostic.
    # Only the mid→after window is strict-asserted; the pre→mid
    # block has already been printed inline as informational
    # (deterministic substrate counts asserted, LLM-driven counts
    # reported).
    mismatches = {
        k: (delta[k], EXPECTED_MID_TO_AFTER_DELTA[k])
        for k in EXPECTED_MID_TO_AFTER_DELTA
        if delta[k] != EXPECTED_MID_TO_AFTER_DELTA[k]
    }
    if mismatches:
        print(f"\n✗ Mid → After mismatch: got vs expected = {mismatches}")
        print(
            "The Mid → After window is the deterministic substrate path "
            "(Phase 6 happy publish + Phases 7-8 bypasses + Phases 9-11 "
            "enforcement chain). Mismatches here indicate a substrate "
            "regression, not LLM nondeterminism — investigate."
        )
        raise SystemExit(1)
    print("\n✓ Mid → After delta matches; substrate behavior verified")


if __name__ == "__main__":
    main()

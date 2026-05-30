"""DevOps incident-response runbook — Python + Microsoft Agent
Framework end-to-end demo.

Five MAF agents collaborating on an incident-response workflow:
``alerting`` ingests a pager event, ``triage`` classifies the
incident, ``remediation`` performs production-write actions
(cap-gated), ``post_mortem`` writes the incident summary, and
``human_sre`` is registered as the human-in-the-loop observer.
The substrate point is **policy-bounded production access**:
the remediation agent may perform safe rollbacks freely, but
schema-changing actions are constitutionally forbidden unless
the envelope carries an ``sre_countersigned`` tag.

Companion to ``code_review.py`` (LangGraph), ``ap_invoice.py``
(CrewAI), and ``research_crew.py`` (OpenAI Agents). Same
substrate machinery — different framework idioms, different
business framing.

Cast
----

* **alerting** (``framework: maf-devops-alerting``) — ingests a
  pager event; in v1 the orchestrator calls its
  :meth:`Agent.run` directly with the incident description.
* **triage** (``framework: maf-devops-triage``) — classifies
  the incident; passively registered in v1.
* **remediation** (``framework: maf-devops-remediation``) —
  performs production actions via a cap-gated ``apply_action``
  callable. Subject of bypass attempts.
* **post_mortem** (``framework: maf-devops-post-mortem``) —
  writes the incident summary; passively registered in v1.
* **human_sre** (``framework: maf-devops-human-sre``) — the
  human countersign agent. Passively registered in v1; full
  ``RequestInfoExecutor``-driven HITL is a tracked follow-on.

Constitution
------------

The active constitution forbids ``SendEnvelope`` when an
envelope is tagged ``production_action`` AND ``schema_change``
but NOT ``sre_countersigned``. The remediation's apply_action
helper builds the tag set based on the action's parameters —
happy-path rollbacks add ``production_action`` alone (no
``schema_change``, no need for countersign); supervisor-approved
schema changes add all three; bypass attempts omit
``sre_countersigned``.

The engine config attaches a single enforcement rule covering
all four stages (detect → coach → quarantine → evict) with 1-
second cooldowns, identical in shape to the other three demos.

Running locally
---------------

MAF requires an LLM credential. Set ``OPENAI_API_KEY`` (or any
other MAF-compatible chat-client config) plus the bootstrap
seed and the operator pubkey:

::

    export YUTHA_BOOTSTRAP_SEED=$(python -c \\
        'import secrets; print(secrets.token_hex(32))')
    export OPENAI_API_KEY=...

    cargo run -p yutha-control-plane -- \\
        --admission-mode open \\
        --operator-public-key $(python sdks/python/examples/devops_incident.py --print-operator-pubkey)

    python sdks/python/examples/devops_incident.py

Audit-delta assertion (same split as research_crew.py)
------------------------------------------------------

The demo takes two snapshots — pre-flow and mid-flow — and
splits the audit-delta assertion into:

* **Pre → Mid** (deterministic substrate counts asserted;
  LLM-driven counts reported but not asserted) — covers the
  agent registrations + constitution activation + cap issuance
  + a single ``alerting.run`` LLM exploration in Phase 5.
* **Mid → After** (strict equality on every count) — covers
  the deterministic substrate path: orchestrator-driven happy
  publish + 2 bypass attempts + the four-stage enforcement
  chain + the post-quarantine cap-check + evict.

This split lets the strict assertion meaningfully fire on
substrate regressions while tolerating the inherent variance
of LLM-driven phases.

v1 scope vs future
------------------

v1 demonstrates the core integration: MAF Agents wrapped 1:1
as Yutha agents, with cap-gating on outbound tool sends via
the contextvar-based ``@capability_required`` decorator. The
following are tracked follow-ons (see ``yutha.maf.__init__``):

* **WorkflowBuilder integration** — instead of orchestrator-
  driven ``Agent.run`` calls in Phase 5, the workflow would be
  composed via MAF's graph-based ``WorkflowBuilder``. Each
  workflow edge would emit a Yutha envelope for audit.
* **RequestInfoExecutor / HITL** — the human_sre agent would
  be wired through MAF's HITL primitive so the request +
  response cycle produces ``approval_required`` and
  ``countersigned`` receipts.
* **AgentMiddleware / FunctionMiddleware cap-gating** — the
  cap-context could move from the decorator into a
  ``FunctionMiddleware`` for tighter integration with MAF's
  middleware pipeline.

These don't affect substrate correctness in v1; the
``yutha.maf`` adapter primitives are already sufficient.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import sys
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack

import yutha
from yutha.langgraph.tools import CapabilityDenied
from yutha.maf import YuthaChatAgent, capability_required
from yutha.models.constitution import Constitution

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

SERVER_ADDR = os.environ.get("YUTHA_GRPC_ADDR", "127.0.0.1:50051")

FAR_FUTURE = yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62)

ENFORCEMENT_STAGE_TIMEOUT_SECONDS = 15.0
ENFORCEMENT_POLL_INTERVAL_SECONDS = 0.25

# Tag conventions. Constitution keys on these.
TAG_PRODUCTION_ACTION = "production_action"
TAG_SCHEMA_CHANGE = "schema_change"
TAG_SRE_COUNTERSIGNED = "sre_countersigned"
DEMO_TAG = "devops-incident-demo"

# -----------------------------------------------------------------------------
# Constitution (Cedar source + engine config)
# -----------------------------------------------------------------------------

_DEVOPS_CEDAR_SOURCE = """\
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
"""

_DEVOPS_ENGINE_CONFIG_YAML = """\
schema_version: "1.1.0"
predicates: []
scoring_rules: []
procedures: []
enforcement_rules:
  - name: unauthorized_schema_change_chain
    detect:
      trigger:
        receipt_kind: constitution.evaluate.deny
      count_threshold: 2
      time_window: 60s
      group_by: principal
    coach:
      cooldown: 1s
      guidance_template: "Remediation must not perform schema_change without SRE countersign"
    quarantine:
      escalate_after: 1s
    evict:
      escalate_after: 1s
      require_countersign: false
    severity: high
"""


def build_devops_constitution(swarm_id: yutha.SwarmId) -> Constitution:
    """Build the DevOps incident-response demo's constitution."""
    return Constitution(
        spec_version="1.0.0",
        schema_version="1.1.0",
        constitution_version="1.0.0",
        parent_version=None,
        swarm_id=swarm_id,
        cedar_source=_DEVOPS_CEDAR_SOURCE,
        engine_config_yaml=_DEVOPS_ENGINE_CONFIG_YAML,
        issued_at=yutha.Timestamp.now(),
    )


# -----------------------------------------------------------------------------
# Cast
# -----------------------------------------------------------------------------

CAST: list[tuple[str, str]] = [
    ("alerting", "maf-devops-alerting"),
    ("triage", "maf-devops-triage"),
    ("remediation", "maf-devops-remediation"),
    ("post_mortem", "maf-devops-post-mortem"),
    ("human_sre", "maf-devops-human-sre"),
]

# Incident description the demo asks the alerting agent to
# process in the LLM-driven Phase 5. Picked to be
# deterministic-friendly: a single short sentence, nothing the
# LLM needs to over-think.
DEMO_INCIDENT = (
    "PAGER-DB-0042: production-db cluster reporting elevated "
    "p99 query latency after the 14:00 UTC deploy."
)


# -----------------------------------------------------------------------------
# Expected audit-trail deltas (split into pre→mid and mid→after)
# -----------------------------------------------------------------------------
#
# Same shape as research_crew.py — MAF's Agent.run is LLM-driven,
# so the pre→mid block is informational; the mid→after block is
# strict-asserted.

EXPECTED_PRE_TO_MID_DELTA: dict[str, int] = {
    "agent.register": 5,
    "constitution.activate": 1,
    "capability.issue": 1,
}

LLM_INFORMATIONAL_KINDS: frozenset[str] = frozenset(
    {
        "envelope.send",
        "envelope.deliver",
        "constitution.evaluate.pass",
        "capability.check.pass",
    }
)

EXPECTED_MID_TO_AFTER_DELTA: dict[str, int] = {
    # Phase 6 — orchestrator calls remediation_apply_action
    # with a safe rollback (production_action only, no
    # schema_change): 1 envelope.send + deliver + pass +
    # cap.check.pass.
    "envelope.send": 1,
    "envelope.deliver": 1,
    "constitution.evaluate.pass": 1,
    # Phases 7-8 — 2 bypass attempts deny at constitution layer.
    "constitution.evaluate.deny": 2,
    # Phase 6 + Phases 7-8 — 1 happy + 2 bypasses pass cap-check
    # (cap-check fires before constitution-check; cap still
    # valid for all three).
    "capability.check.pass": 3,
    # Phase 10 — explicit post-quarantine cap-check denies.
    "capability.check.deny": 1,
    # Phases 9 + 11 — four stages of the enforcement loop.
    "enforcement.detect": 1,
    "enforcement.coach": 1,
    "enforcement.quarantine": 1,
    "enforcement.evict": 1,
}

ALL_KINDS: list[str] = sorted(
    set(EXPECTED_PRE_TO_MID_DELTA) | set(EXPECTED_MID_TO_AFTER_DELTA) | LLM_INFORMATIONAL_KINDS
)


# -----------------------------------------------------------------------------
# Bootstrap identity (mirrors the other demos)
# -----------------------------------------------------------------------------


def derive_bootstrap_identity(
    seed: bytes,
) -> tuple[yutha.InProcessSigner, yutha.AgentId, yutha.SwarmId]:
    if len(seed) != 32:
        raise ValueError(f"seed must be exactly 32 bytes, got {len(seed)}")
    signer = yutha.InProcessSigner.from_seed_bytes(seed)
    agent_id = yutha.AgentId(value=hashlib.sha256(seed + b"\x01").digest()[:16])
    swarm_id = yutha.SwarmId(value=hashlib.sha256(seed + b"\x02").digest()[:16])
    return signer, agent_id, swarm_id


def derive_operator_identity(seed: bytes) -> tuple[yutha.InProcessSigner, yutha.PublicKey]:
    if len(seed) != 32:
        raise ValueError(f"seed must be exactly 32 bytes, got {len(seed)}")
    op_seed = hashlib.sha256(seed + b"\x03").digest()
    op_signer = yutha.InProcessSigner.from_seed_bytes(op_seed)
    return op_signer, op_signer.public_key()


def load_bootstrap_identity_from_env() -> tuple[
    yutha.InProcessSigner, yutha.AgentId, yutha.SwarmId, bytes
]:
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
    signer, agent_id, swarm_id = derive_bootstrap_identity(seed)
    return signer, agent_id, swarm_id, seed


# -----------------------------------------------------------------------------
# Passport helper
# -----------------------------------------------------------------------------


async def make_passport(
    name: str,
    framework: str,
    swarm_id: yutha.SwarmId,
    signer: yutha.Signer,
    agent_id: yutha.AgentId,
) -> yutha.Passport:
    return await yutha.Passport(
        spec_version="1.0.0",
        agent_id=agent_id,
        swarm_id=swarm_id,
        agent_public_key=signer.public_key(),
        owner=f"yutha-demo:devops-incident:{name}",
        framework=framework,
        framework_version="1.0.0",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
        expires_at=FAR_FUTURE,
    ).sign(signer)


# -----------------------------------------------------------------------------
# Remediation apply-action helper
# -----------------------------------------------------------------------------


def build_remediation_apply_action(
    remediation_wrapper: YuthaChatAgent,
    remediation_cap: yutha.Capability,
    audit_recipient_id: yutha.AgentId,
) -> Callable[[str, bool, bool], Awaitable[yutha.Hash]]:
    """Return an async function that sends a ``production_action``
    envelope from remediation to the post_mortem agent (used as
    a passive observer of remediation events).

    The ``schema_change`` parameter controls whether the
    ``schema_change`` tag is added; the ``countersigned``
    parameter controls whether ``sre_countersigned`` is added.
    Happy-path rollbacks set ``schema_change=False``; legitimate
    supervisor-approved schema changes set both True; bypass
    attempts set ``schema_change=True`` and
    ``countersigned=False``.
    """

    @capability_required(remediation_cap, action_kind="envelope.send")
    async def apply_action(
        action_description: str,
        schema_change: bool,
        countersigned: bool,
    ) -> yutha.Hash:
        tags = [DEMO_TAG, TAG_PRODUCTION_ACTION]
        if schema_change:
            tags.append(TAG_SCHEMA_CHANGE)
        if countersigned:
            tags.append(TAG_SRE_COUNTERSIGNED)
        return await remediation_wrapper.send(
            recipient=yutha.Recipient.for_agent(audit_recipient_id),
            performative=yutha.Performative.INFORM,
            payload=action_description.encode("utf-8"),
            payload_schema_id="type.yutha.dev/v1/Text",
            tags=tags,
        )

    return apply_action


# -----------------------------------------------------------------------------
# Audit helpers
# -----------------------------------------------------------------------------


async def query_audit(client: yutha.YuthaClient, kinds: list[str]) -> dict[str, int]:
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


async def run_devops_incident(server_addr: str = SERVER_ADDR) -> dict[str, int]:
    """Run the DevOps incident-response demo end-to-end.

    Returns the mid→after audit-trail delta keyed by action_kind
    for the strict-equality assertion in ``main()``. The pre→mid
    block is reported inline as informational."""
    print(f"# devops incident-response demo · server={server_addr}")

    # Lazy MAF imports — heavy transitive deps.
    try:
        from agent_framework import Agent
    except ImportError as e:
        raise RuntimeError(
            "agent-framework is not installed. Run:\n"
            "    cd sdks/python && uv pip install -e '.[dev,maf]'\n"
            "and re-run this demo."
        ) from e
    try:
        # MAF's OpenAI chat client. Path is best-guessed against
        # MAF's current 1.x layout; if this import fails, see
        # MAF's docs for the current chat-client module path.
        from agent_framework.openai import OpenAIChatClient
    except ImportError as e:
        raise RuntimeError(
            "Could not import agent_framework.openai.OpenAIChatClient. "
            "Check MAF's current chat-client module layout; you may "
            "need a different provider (FoundryChatClient, "
            "AzureOpenAIChatClient, etc.). Edit this demo to import "
            "the right client."
        ) from e

    if not os.environ.get("OPENAI_API_KEY"):
        print(
            "OPENAI_API_KEY is not set. MAF's OpenAI chat client requires "
            "an LLM credential. Set the env var (or wire a different MAF "
            "chat client) and re-run."
        )
        return {}

    # --- bootstrap identity ------------------------------------------------
    bootstrap_signer, bootstrap_agent_id, swarm_id, seed = load_bootstrap_identity_from_env()
    print(f"# swarm_id={swarm_id.value.hex()} (from YUTHA_BOOTSTRAP_SEED)")

    op_signer, op_public_key = derive_operator_identity(seed)
    print(f"# operator pubkey: {op_public_key.value.hex()}")

    # --- Phase 0: pre-flow audit snapshot ---------------------------------
    kinds = list(ALL_KINDS)
    async with yutha.YuthaClient.connect(
        server_addr,
        agent_id=bootstrap_agent_id,
        swarm_id=swarm_id,
        signer=bootstrap_signer,
    ) as bootstrap_client:
        before = await query_audit(bootstrap_client, kinds)
    print(f"# pre-flow snapshot taken via bootstrap agent {bootstrap_agent_id.value.hex()[:16]}…")

    # --- identities + passports -------------------------------------------
    identities: dict[str, tuple[yutha.InProcessSigner, yutha.AgentId, yutha.Passport]] = {}
    for name, framework in CAST:
        agent_signer = yutha.InProcessSigner.generate()
        agent_id = yutha.AgentId(value=secrets.token_bytes(16))
        passport = await make_passport(name, framework, swarm_id, agent_signer, agent_id)
        identities[name] = (agent_signer, agent_id, passport)

    # --- MAF Agent instances ----------------------------------------------
    # Each agent shares an OpenAI chat client. Instructions are
    # tightly-constrained so the LLM phase produces predictable
    # output. The agents are passive in v1 — they exist for
    # registration and to exercise Agent.run; the substrate-
    # critical work happens in the deterministic Phase 6+.
    #
    # OpenAIChatClient requires the model name explicitly (or via
    # the OPENAI_CHAT_MODEL / OPENAI_MODEL env var). Hardcoding
    # gpt-4o-mini keeps the demo self-contained and cheap.
    shared_client = OpenAIChatClient(model="gpt-4o-mini")

    def _make_agent(name: str, role: str, goal: str) -> Agent:
        return Agent(
            client=shared_client,
            name=name,
            instructions=(
                f"You are the {role} in a DevOps incident-response runbook. "
                f"{goal} Be concise — one or two sentences."
            ),
        )

    maf_agents: dict[str, Agent] = {
        "alerting": _make_agent(
            "DevOpsAlerting",
            "alerting agent",
            "When given an incident description, summarize the alert in plain English.",
        ),
        "triage": _make_agent(
            "DevOpsTriage",
            "triage agent",
            "Classify incident severity and suggest a remediation category.",
        ),
        "remediation": _make_agent(
            "DevOpsRemediation",
            "remediation agent",
            "Describe the production action you would take.",
        ),
        "post_mortem": _make_agent(
            "DevOpsPostMortem",
            "post-mortem agent",
            "Summarize the incident for the post-mortem record.",
        ),
        "human_sre": _make_agent(
            "DevOpsHumanSRE",
            "human-in-the-loop SRE agent",
            "Acknowledge requests for human countersign.",
        ),
    }

    # --- Phase 1: connect + register --------------------------------------
    print("\n# Phase 1 — connect + register")
    wrappers: dict[str, YuthaChatAgent] = {}
    try:
        for name, (agent_signer, _agent_id, passport) in identities.items():
            wrapper = YuthaChatAgent.connect(
                server_addr,
                passport=passport,
                signer=agent_signer,
                maf_agent=maf_agents[name],
                # Dispatch loops are no-ops — the orchestrator
                # drives every Agent.run directly. Same defensive
                # pattern as research_crew.py.
                input_factory=lambda _agent, _env, _deliver: None,
            )
            wrappers[name] = wrapper
            receipt = await wrapper.register()
            short = receipt.digest.hex()[:16] + "…" if receipt else "already-present"
            print(f"  registered {name:<13} receipt={short}")

        remediation_id = identities["remediation"][1]
        post_mortem_id = identities["post_mortem"][1]

        async with AsyncExitStack() as stack:
            print("\n# Phase 2 — start dispatch loops")
            for wrapper in wrappers.values():
                await stack.enter_async_context(wrapper)
            print("  all five agents subscribed")

            # --- Phase 3: operator activates the constitution -------------
            print("\n# Phase 3 — operator activates devops-incident constitution")
            constitution = build_devops_constitution(swarm_id)
            async with yutha.YuthaClient.connect_as_operator(
                server_addr,
                operator_id="yutha-demo:devops-incident:operator",
                swarm_id=swarm_id,
                operator_signer=op_signer,
            ) as op_client:
                activated = await op_client.constitution.activate(constitution)
            print(
                f"  constitution_hash={activated.constitution_hash.digest.hex()[:16]}… "
                f"activate_receipt={activated.activate_receipt.digest.hex()[:16]}…"
            )

            # --- Phase 4: issue remediation's send cap -------------------
            print("\n# Phase 4 — issue remediation send capability")
            remediation_cap = yutha.Capability(
                spec_version="1.0.0",
                capability_id=secrets.token_bytes(16),
                swarm_id=swarm_id,
                issuer=yutha.Issuer.for_agent(remediation_id),
                subject=remediation_id,
                scope=yutha.Scope.for_action("envelope.send"),
                valid_from=yutha.Timestamp.now(),
                valid_until=FAR_FUTURE,
            )
            cap_id, issue_receipt = await wrappers["remediation"].client.capability.issue(
                remediation_cap
            )
            print(
                f"  remediation cap id={cap_id.digest.hex()[:16]}… "
                f"issuance receipt={issue_receipt.digest.hex()[:16]}…"
            )

            # Production actions audit to the post_mortem agent
            # (passive observer of remediation events).
            remediation_apply_action = build_remediation_apply_action(
                wrappers["remediation"], remediation_cap, post_mortem_id
            )

            # --- Phase 5: LLM-driven exploration (informational) ---------
            print(
                f"\n# Phase 5 — LLM exploration (alerting agent processes: '{DEMO_INCIDENT[:60]}…')"
            )
            try:
                result = await wrappers["alerting"].run(DEMO_INCIDENT)
                final_text = str(result) if result is not None else "<empty>"
                print(f"  LLM final output: {final_text[:80]}{'…' if len(final_text) > 80 else ''}")
            except Exception as e:
                print(
                    f"  LLM run raised {type(e).__name__}: {e} "
                    "(informational; continuing to deterministic phases)"
                )

            # --- Mid-flow snapshot ----------------------------------------
            mid = await query_audit(wrappers["remediation"].client, kinds)
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
            # Orchestrator calls remediation.apply_action directly
            # with a safe rollback (no schema_change tag). The
            # constitution permits; produces exactly 1 envelope.send
            # + envelope.deliver + constitution.evaluate.pass +
            # capability.check.pass.
            print("\n# Phase 6 — deterministic happy publish (rollback, no schema_change)")
            happy_receipt = await remediation_apply_action(
                "Rollback deploy 14:00 UTC; restore last-known-good config.",
                False,  # schema_change
                False,  # countersigned
            )
            print(f"  ✓ rollback applied; envelope.send receipt={happy_receipt.digest.hex()[:16]}…")

            # --- Phase 7: bypass attempt #1 ------------------------------
            print("\n# Phase 7 — remediation bypass attempt #1 (schema_change w/o countersign)")
            denied_1 = await _attempt_bypass(remediation_apply_action)
            assert denied_1.deny_reason == "forbid_rule_matched", (
                f"expected forbid_rule_matched, got {denied_1.deny_reason!r}"
            )
            print(f"  ✓ denied: {denied_1}")

            # --- Phase 8: bypass attempt #2 → enforcement.detect ---------
            print("\n# Phase 8 — remediation bypass attempt #2 (trips enforcement.detect)")
            denied_2 = await _attempt_bypass(remediation_apply_action)
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
                    wrappers["remediation"].client, stage, mid[stage], expected_delta=1
                )
                print(f"  ✓ {stage} landed")

            # --- Phase 10: cap-check denies WHILE quarantined ------------
            print("\n# Phase 10 — verify quarantine denies remediation cap-check")
            check_outcome = await wrappers["remediation"].client.capability.check(
                remediation_cap,
                yutha.ActionDescriptor(action_kind="envelope.send"),
            )
            assert not check_outcome.permitted, (
                "quarantined remediation should be denied even on a still-valid cap"
            )
            assert check_outcome.deny_reason == "subject_quarantined", (
                f"expected subject_quarantined, got {check_outcome.deny_reason!r}"
            )
            print(f"  ✓ cap-check denied with reason={check_outcome.deny_reason}")

            # --- Phase 11: wait for evict --------------------------------
            print("\n# Phase 11 — wait for enforcement.evict")
            await wait_for_kind_delta(
                wrappers["remediation"].client,
                "enforcement.evict",
                mid["enforcement.evict"],
                expected_delta=1,
            )
            print("  ✓ enforcement.evict landed")

            # --- Phase 12: mid→after audit delta (strict-asserted) -------
            print("\n# Phase 12 — Mid → After delta (strict assertion)")
            after = await query_audit(wrappers["remediation"].client, kinds)
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
    apply_action: Callable[[str, bool, bool], Awaitable[yutha.Hash]],
) -> yutha.ConstitutionDenied:
    """Drive one remediation bypass attempt and return the
    structured deny."""
    try:
        await apply_action(
            "Apply schema migration without supervisor approval.",
            True,  # schema_change
            False,  # countersigned
        )
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
    _, _, _, seed = load_bootstrap_identity_from_env()
    _, op_public_key = derive_operator_identity(seed)
    print(op_public_key.value.hex())


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--print-operator-pubkey":
        _print_operator_pubkey()
        return
    delta = asyncio.run(run_devops_incident())
    if not delta:
        return
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

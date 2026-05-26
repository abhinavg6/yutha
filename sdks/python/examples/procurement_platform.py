"""Procurement platform — Python + LangGraph (buyer) + CrewAI (vendors) demo.

A mid-to-large enterprise's internal procurement platform: the buyer
posts RFPs, approved vendors submit proposals against them. Each
side runs its agents in whichever framework its team picked — the
buyer's intake agent on LangGraph, each vendor agent on CrewAI —
and they coordinate through one Yutha control plane. Nobody had to
agree on a framework; nobody can see another vendor's submissions.

This is the first runnable Python demo that exercises a
**heterogeneous-framework swarm** end-to-end: distinct passports
per agent regardless of framework, bounded capabilities that
enforce a multi-party confidentiality wall between vendors, a
queue-mode buyer intake that routes each submission to the right
RFP's evaluation, and a Cedar+ constitution whose forbid rule trips
the four-stage enforcement loop on a bad-acting vendor.

Cast
----

Buyer side (LangGraph):

* **buyer_intake** (``framework: langgraph``) — single intake +
  scorer agent. Receives every vendor submission, classifies by
  the envelope's ``rfp:<id>`` tag, scores against the RFP's
  in-memory criteria, and escalates high-value submissions to
  the human approver. The "receive → score → maybe-escalate"
  flow is a three-node LangGraph workflow triggered on each
  inbound envelope. Sends to the human approver are not
  capability-gated; the constitution still gates them.
* **human_approver** (``framework: langgraph``) — passive
  observer for escalated submissions. A real implementation
  would reply with an approval or rejection envelope; for the
  demo it just logs receipt so the audit trail carries the
  full "who was asked to approve what" chain.

Vendor side (CrewAI):

* **vendor_alpha** (``framework: crewai``) — invited to RFP-101
  only. Carries one Yutha capability whose ``OnlyIfTagged``
  caveat requires the envelope to be tagged ``rfp:RFP-101``.
  The bad-acting vendor in this demo: tries to submit to
  RFP-202 (cap denies) and tries twice to leak other vendors'
  data via the constitution-forbidden tag combination
  (constitution denies; the second deny crosses the enforcement
  rule's threshold).
* **vendor_beta** (``framework: crewai``) — invited to BOTH
  RFP-101 and RFP-202. Carries two capabilities, one per RFP,
  each with the matching ``OnlyIfTagged`` caveat. Submits well-
  behaved proposals to both RFPs.
* **vendor_gamma** (``framework: crewai``) — invited to RFP-202
  only. Symmetric to vendor_alpha but on the other RFP.

Five agents, three different framework labels, one swarm, one
audit log.

What the substrate enforces — and what it doesn't
-------------------------------------------------

The point of the example is the *vendor isolation wall*, and
each layer of the substrate enforces one slice of it:

* **Bounded capabilities (centerpiece).** Each vendor's send
  capability is scoped to ``envelope.send`` with an
  ``OnlyIfTagged`` caveat that pins it to one specific RFP.
  An envelope tagged for the wrong RFP fails ``capability.check``
  at the cap layer — no constitution evaluation needed, no
  envelope ever lands. This is how a vendor agent is *structurally*
  prevented from submitting to RFPs it wasn't invited to, even
  if its prompt or its code tries to.
* **Constitution-level isolation.** A Cedar forbid rule denies
  any envelope tagged ``submission`` together with
  ``leak_other_vendor_data`` — the demo's stand-in for "this
  vendor is trying to exfiltrate insight about another vendor's
  bid." A cap-passing-but-constitution-failing send produces a
  ``constitution.evaluate.deny`` receipt; two such denies inside
  a 60-second window for the same principal fire
  ``enforcement.detect``, and the four-stage chain (detect →
  coach → quarantine → evict) plays out on the substrate's
  scheduler.
* **Queue-mode intake.** Every vendor submission lands at the
  same ``buyer_intake`` inbox; the intake's LangGraph workflow
  uses the envelope's ``rfp:<id>`` tag to route to the right
  per-RFP scoring path. Receivers are not addressed by RFP —
  the platform is a single intake queue, the routing is
  done in-agent. Demonstrates the queue topology the
  ``customer-support`` example introduced, applied to a
  multi-tenant flow.
* **Receipt log as neutral record.** Every consequential action
  — submission send, intake delivery, scoring escalation,
  isolation deny, enforcement progression — leaves a signed,
  content-addressed receipt. Two parties in a dispute can
  reconstruct who did what, when, and under which constitution
  version, without trusting each other or the operator.

What this demo does *not* exercise:

* **Federation across orgs.** The platform is buyer-operated;
  every agent (intake, human, all three vendors) registers into
  one swarm and one control plane. The platform framing
  upgrades cleanly post-Phase-4 — each vendor running its own
  swarm in its own infrastructure, federating with the buyer's
  — but the cross-swarm primitives don't exist yet. The example
  is built so that future upgrade is natural; nothing here
  assumes single-swarm permanence.
* **LLM-driven dispatch.** Both the buyer_intake's LangGraph
  workflow and the vendor agents' CrewAI tools are
  deterministic for demo determinism. The substrate's audit
  trail shape doesn't depend on which classifier picked which
  destination; only the resulting tags matter.

Running locally
---------------

CrewAI requires an LLM credential at ``Agent`` construction time
even though the substrate path bypasses the LLM. Set
``OPENAI_API_KEY`` (or any CrewAI-compatible credential) plus the
bootstrap seed and the operator pubkey:

::

    export YUTHA_BOOTSTRAP_SEED=$(python -c \\
        'import secrets; print(secrets.token_hex(32))')
    export OPENAI_API_KEY=...

    cargo run -p yutha-control-plane -- \\
        --admission-mode open \\
        --operator-public-key $(python sdks/python/examples/procurement_platform.py --print-operator-pubkey)

    python sdks/python/examples/procurement_platform.py

What you'll see
---------------

* Five fresh agents register, three framework labels among them.
* An operator-bearer client activates a custom procurement
  constitution.
* Four capabilities issued — one per (vendor, invited-RFP) pair.
* One cross-RFP attempt (vendor_alpha to RFP-202) denied at the
  cap layer.
* Four well-behaved submissions land at buyer_intake; one of them
  (vendor_beta's RFP-202 bid) is high-value and gets escalated to
  the human approver.
* Two leakage bypass attempts from vendor_alpha denied at the
  constitution layer; the second one trips enforcement.detect.
* The four-stage enforcement chain progresses on the server's
  scheduler; the demo polls each stage to land.
* A post-quarantine cap-check returns ``subject_quarantined`` —
  vendor_alpha's still-valid capability is now consulting the
  quarantine state.
* The audit-trail delta is computed against a pre-flow snapshot
  and asserted exactly.

The ``run_procurement()`` coroutine returns the audit delta so an
optional pytest wrapper could re-use the body without forking it.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import sys
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

import yutha
from yutha.crewai import CapabilityDenied, YuthaCrewAgent
from yutha.langgraph import YuthaAgent

# The async-function flavour of `capability_required` lives in
# `yutha.langgraph.tools`; the CrewAI flavour wraps a ``BaseTool``
# instance and is unnecessary here because we drive the vendor
# tool bodies directly (deterministic demo path). Both flavours
# route through the same ``ACTIVE_CAPABILITY_ID`` contextvar.
from yutha.langgraph.tools import capability_required
from yutha.models.constitution import Constitution

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

SERVER_ADDR = os.environ.get("YUTHA_GRPC_ADDR", "127.0.0.1:50051")

FAR_FUTURE = yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62)

# Per-stage wall-clock budget for the enforcement chain. 1s scheduler
# tick + 1s cooldowns × 3 stages = ~5s real chain time; 15s leaves
# generous slack for slow CI machines. Same constants as
# ``code_review.py`` / ``ap_invoice.py``.
ENFORCEMENT_STAGE_TIMEOUT_SECONDS = 15.0
ENFORCEMENT_POLL_INTERVAL_SECONDS = 0.25

# The bid threshold (cents) above which a submission escalates to
# the human approver. Below this, buyer_intake auto-clears the
# submission and logs it. The constitution does NOT see this
# number directly — only the resulting ``human_review`` tag — so
# the threshold is interpreted in one place (here) and auditors
# can verify the boundary without trusting the intake agent.
HIGH_VALUE_THRESHOLD_CENTS = 100_000_00  # $100,000


# -----------------------------------------------------------------------------
# RFP fixtures (in-memory; in a real deployment these come from a
# constitutionally-governed memory entity or an external system of record)
# -----------------------------------------------------------------------------

RFP_101 = {
    "rfp_id": "RFP-101",
    "title": "Internal collaboration suite — annual licensing",
    "category": "software",
    "deadline": FAR_FUTURE,
}
RFP_202 = {
    "rfp_id": "RFP-202",
    "title": "Datacenter networking refresh — switches + optics",
    "category": "equipment",
    "deadline": FAR_FUTURE,
}


# -----------------------------------------------------------------------------
# Constitution (Cedar source + engine config)
# -----------------------------------------------------------------------------
#
# Two forbid rules + a permit-all fallback. The first rule is the
# load-bearing one for the demo's enforcement chain; the second is
# a belt-and-braces sanity check that mirrors a real procurement
# platform's "no post-deadline submissions" requirement.
#
# Rule 1: forbid any envelope tagged BOTH ``submission`` and
# ``leak_other_vendor_data``. This is the stand-in for "vendor is
# trying to exfiltrate insight about another vendor's bid." The
# demo's bypass attempts deliberately add the leakage tag to the
# envelope; the rule fires; ``ConstitutionDenied`` is raised to
# the caller and a ``constitution.evaluate.deny`` receipt lands.
#
# Rule 2 (informational here; doesn't fire in the demo's clean
# run): forbid any envelope tagged ``submission`` together with
# ``past_deadline``. The buyer_intake tags late submissions
# at receive time; a vendor sending after the RFP's deadline
# would trip this rule before its envelope reached scoring. The
# demo's fixture deadlines are far-future so the rule sits idle —
# but the policy is wired so an operator running the demo against
# a real RFP timeline would see it activate.
#
# Trailing ``permit (principal, action, resource)`` is required:
# Cedar's validator rejects policy sets that lack a permit, and
# every non-forbidden send (vendor happy-path submissions,
# buyer_intake → human escalations) needs the permit-all fallback
# so it passes the constitution gate.

_PROCUREMENT_CEDAR_SOURCE = """\
@id("no-cross-vendor-data-leakage")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
) when {
    context.tags.contains("submission") &&
    context.tags.contains("leak_other_vendor_data")
};

@id("no-post-deadline-submissions")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
) when {
    context.tags.contains("submission") &&
    context.tags.contains("past_deadline")
};

permit (principal, action, resource);
"""

# Single enforcement rule covering all four stages with 1s
# cooldowns so the full chain runs in seconds rather than minutes.
# Shape matches ``forbid_constitution`` in ``yutha.testing`` and
# the analogous fixtures in ``code_review.py`` / ``ap_invoice.py``.
#
# ``count_threshold: 2`` means two denies within ``time_window: 60s``
# fire ``enforcement.detect``. ``require_countersign: false`` waives
# the supervisor-tier countersign that the canonical-actions spec
# requires by default on ``enforcement.evict`` — this demo doesn't
# stand up a supervisor agent.
_PROCUREMENT_ENGINE_CONFIG_YAML = """\
schema_version: "1.1.0"
predicates: []
scoring_rules: []
procedures: []
enforcement_rules:
  - name: vendor_leakage_bypass_chain
    detect:
      trigger:
        receipt_kind: constitution.evaluate.deny
      count_threshold: 2
      time_window: 60s
      group_by: principal
    coach:
      cooldown: 1s
      guidance_template: "Vendor agents may not exfiltrate cross-vendor data"
    quarantine:
      escalate_after: 1s
    evict:
      escalate_after: 1s
      require_countersign: false
    severity: high
"""


def build_procurement_constitution(swarm_id: yutha.SwarmId) -> Constitution:
    """Build the procurement demo's constitution. Inlined here so
    the demo file is self-describing — the rule that governs the
    swarm sits next to the agents it governs."""
    return Constitution(
        spec_version="1.0.0",
        schema_version="1.1.0",
        constitution_version="1.0.0",
        parent_version=None,
        swarm_id=swarm_id,
        cedar_source=_PROCUREMENT_CEDAR_SOURCE,
        engine_config_yaml=_PROCUREMENT_ENGINE_CONFIG_YAML,
        issued_at=yutha.Timestamp.now(),
    )


# -----------------------------------------------------------------------------
# Bootstrap identity (mirrors code_review / ap_invoice)
# -----------------------------------------------------------------------------


def derive_bootstrap_identity(
    seed: bytes,
) -> tuple[yutha.SigningKey, yutha.AgentId, yutha.SwarmId]:
    """Reproduce ``BootstrapIdentity::from_seed_hex``: seed is the
    Ed25519 private key, ``sha256(seed || 0x01)[:16]`` is the
    agent_id, ``sha256(seed || 0x02)[:16]`` is the swarm_id."""
    if len(seed) != 32:
        raise ValueError(f"seed must be exactly 32 bytes, got {len(seed)}")
    signing_key = yutha.SigningKey.from_seed_bytes(seed)
    agent_id = yutha.AgentId(value=hashlib.sha256(seed + b"\x01").digest()[:16])
    swarm_id = yutha.SwarmId(value=hashlib.sha256(seed + b"\x02").digest()[:16])
    return signing_key, agent_id, swarm_id


def derive_operator_identity(seed: bytes) -> tuple[yutha.SigningKey, yutha.PublicKey]:
    """Domain-separated derivation of the Ed25519 operator keypair.
    Uses ``sha256(seed || 0x03)[:32]`` so a leak of one derivation
    can't pivot to another."""
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
            "YUTHA_BOOTSTRAP_SEED is not set. The demo needs the same "
            "32-byte hex seed the control plane was started with. See "
            "the module docstring for the full setup."
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
# Expected audit-trail delta for one clean demo run
# -----------------------------------------------------------------------------

EXPECTED_AUDIT_DELTA: dict[str, int] = {
    # 5 fresh agents register: buyer_intake, human_approver, 3 vendors.
    "agent.register": 5,
    # Operator activates the procurement constitution once.
    "constitution.activate": 1,
    # 5 successful sends:
    #   vendor_alpha → buyer_intake (RFP-101 submission)
    #   vendor_beta  → buyer_intake (RFP-101 submission)
    #   vendor_beta  → buyer_intake (RFP-202 submission, high value)
    #   vendor_gamma → buyer_intake (RFP-202 submission)
    #   buyer_intake → human_approver (escalation for the high-value bid)
    "envelope.send": 5,
    "envelope.deliver": 5,
    # Constitution-check runs on every Send that makes it past cap-check.
    # 5 successful sends pass; 2 bypass attempts (submission +
    # leak_other_vendor_data, both passing cap-check) are denied.
    "constitution.evaluate.pass": 5,
    "constitution.evaluate.deny": 2,
    # Caps issued, one per (vendor, invited-RFP) pair:
    #   vendor_alpha → RFP-101
    #   vendor_beta  → RFP-101
    #   vendor_beta  → RFP-202
    #   vendor_gamma → RFP-202
    "capability.issue": 4,
    # Cap-checks that pass:
    #   4 happy vendor submissions (caveat satisfied)
    #   2 bypass attempts (cap caveat still satisfied; constitution is
    #     what denies — cap-check runs first, then constitution)
    # = 6 cap-pass receipts. The buyer_intake's escalation is NOT
    # cap-gated; no cap receipt for that send.
    "capability.check.pass": 6,
    # Cap-checks that deny:
    #   1× cross-RFP attempt (vendor_alpha sends tagged rfp:RFP-202
    #     using its only cap, which requires rfp:RFP-101; caveat unmet)
    #   1× post-quarantine explicit check on vendor_alpha (cap layer
    #     consults the engine's quarantine state)
    "capability.check.deny": 2,
    # Four stages of the enforcement loop, fired by the 2 leakage
    # denies above crossing the count_threshold.
    "enforcement.detect": 1,
    "enforcement.coach": 1,
    "enforcement.quarantine": 1,
    "enforcement.evict": 1,
}


# -----------------------------------------------------------------------------
# Cast + tag conventions
# -----------------------------------------------------------------------------
#
# Buyer-side agents carry ``framework: langgraph``; vendor agents
# carry ``framework: crewai``. Constitutions can policy-key on this
# field in principle, but the rule above keys on tags only — this
# demo's framework labels are descriptive, not load-bearing.

BUYER_CAST: list[tuple[str, str]] = [
    ("buyer_intake", "langgraph"),
    ("human_approver", "langgraph"),
]

VENDOR_CAST: list[tuple[str, str]] = [
    ("vendor_alpha", "crewai"),
    ("vendor_beta", "crewai"),
    ("vendor_gamma", "crewai"),
]

# Which RFPs each vendor was invited to. The cap layout below
# mirrors this exactly — one cap per (vendor, invited-RFP) pair.
VENDOR_INVITATIONS: dict[str, list[str]] = {
    "vendor_alpha": ["RFP-101"],
    "vendor_beta": ["RFP-101", "RFP-202"],
    "vendor_gamma": ["RFP-202"],
}

# Tag conventions. Constitution and cap caveats key on these.
TAG_SUBMISSION = "submission"
TAG_LEAK_OTHER_VENDOR_DATA = "leak_other_vendor_data"
TAG_PAST_DEADLINE = "past_deadline"
TAG_HUMAN_REVIEW = "human_review"
TAG_ESCALATION = "escalation"
DEMO_TAG = "procurement-demo"


def rfp_tag(rfp_id: str) -> str:
    """Construct the tag the cap caveats key on."""
    return f"rfp:{rfp_id}"


# -----------------------------------------------------------------------------
# Submission fixtures
# -----------------------------------------------------------------------------
#
# Three well-behaved submissions plus one over-threshold submission
# that escalates to the human approver. Amounts are in cents so the
# threshold comparison is integer-only.

VENDOR_ALPHA_RFP_101 = {
    "submission_id": "SUB-2026-A101",
    "vendor": "vendor_alpha",
    "rfp_id": "RFP-101",
    "bid_amount_cents": 45_000_00,  # $45,000 — under threshold
    "proposal_summary": "Annual licensing for 500 seats with priority support.",
}
VENDOR_BETA_RFP_101 = {
    "submission_id": "SUB-2026-B101",
    "vendor": "vendor_beta",
    "rfp_id": "RFP-101",
    "bid_amount_cents": 62_000_00,  # $62,000 — under threshold
    "proposal_summary": "Hybrid licensing with extended training credits.",
}
VENDOR_BETA_RFP_202 = {
    "submission_id": "SUB-2026-B202",
    "vendor": "vendor_beta",
    "rfp_id": "RFP-202",
    "bid_amount_cents": 425_000_00,  # $425,000 — over threshold, escalates
    "proposal_summary": "Full chassis refresh with five-year warranty.",
}
VENDOR_GAMMA_RFP_202 = {
    "submission_id": "SUB-2026-G202",
    "vendor": "vendor_gamma",
    "rfp_id": "RFP-202",
    "bid_amount_cents": 88_000_00,  # $88,000 — under threshold
    "proposal_summary": "Pluggable optics + spares kit; switches BYO.",
}


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
    """Build a signed passport for one demo agent. Open-mode
    admission requires ``expires_at`` and ``tier >= Minimal``."""
    return yutha.Passport(
        spec_version="1.0.0",
        agent_id=agent_id,
        swarm_id=swarm_id,
        agent_public_key=signing_key.public_key(),
        owner=f"yutha-demo:procurement:{name}",
        framework=framework,
        framework_version="1.0.0",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
        expires_at=FAR_FUTURE,
    ).sign(signing_key)


# -----------------------------------------------------------------------------
# Capability helpers — one per (vendor, invited-RFP) pair
# -----------------------------------------------------------------------------


def build_vendor_capability(
    vendor_id: yutha.AgentId,
    rfp_id: str,
    swarm_id: yutha.SwarmId,
) -> yutha.Capability:
    """Build a vendor's send capability for ONE specific RFP.

    The cap's ``OnlyIfTagged`` caveat requires the envelope's tags
    to contain ``rfp:<RFP id>``. The Send-path cap-check on the
    server bridges ``envelope.tags`` into the
    :class:`ActionDescriptor`'s ``resource_tags``, so an envelope
    tagged for a different RFP — or no RFP at all — fails the
    caveat and the cap denies.

    This is what gives each vendor a *bounded* send authority: the
    capability is self-issued, signed, content-addressed, and
    structurally tied to a single RFP. Adding the second RFP is a
    second capability, not a wider scope on the existing one.
    """
    return yutha.Capability(
        spec_version="1.0.0",
        capability_id=secrets.token_bytes(16),
        swarm_id=swarm_id,
        issuer=yutha.Issuer.for_agent(vendor_id),
        subject=vendor_id,
        scope=yutha.Scope.for_action("envelope.send"),
        valid_from=yutha.Timestamp.now(),
        valid_until=FAR_FUTURE,
        caveats=[
            yutha.Caveat(
                only_if_tagged=yutha.OnlyIfTaggedCaveat(
                    required_tags=[rfp_tag(rfp_id)],
                )
            )
        ],
    )


# -----------------------------------------------------------------------------
# Vendor send helpers (CrewAI side) — cap-gated submission + bypass attempts
# -----------------------------------------------------------------------------


def build_vendor_submit(
    vendor_wrapper: YuthaCrewAgent,
    vendor_cap: yutha.Capability,
    buyer_intake_id: yutha.AgentId,
) -> Callable[[dict[str, Any], list[str]], Awaitable[yutha.Hash]]:
    """Return an async function that sends a ``submission`` envelope
    from the vendor to the buyer's intake. Wrapped with
    ``@capability_required`` so every outbound send hits a server-
    side cap check before the envelope is signed and shipped.

    ``extra_tags`` lets the orchestrator drive the bypass attempts
    deterministically — passing ``[TAG_LEAK_OTHER_VENDOR_DATA]``
    produces the exact tag combination the constitution forbids,
    while still satisfying the cap caveat (because the rfp:<id>
    tag is added unconditionally below).

    Note that the cap-required decorator is the LangGraph flavour
    even though the vendor is a CrewAI agent. Both flavours route
    through the same ``ACTIVE_CAPABILITY_ID`` contextvar; the
    decorator's job is to set the contextvar around the wrapped
    coroutine, and ``YuthaCrewAgent.send`` reads it the same way
    ``YuthaAgent.send`` does. The CrewAI-specific flavour is for
    wrapping a ``BaseTool`` instance; here we're wrapping a plain
    async function so the LangGraph flavour is the right tool.
    """
    # The rfp_id is derived from the cap's caveat at decoration time
    # so the helper's ergonomics match the cap's structural binding.
    # A vendor with two caps gets two helpers — one per RFP — which
    # is exactly the shape vendor_beta uses.
    required_tags = []
    for caveat in vendor_cap.caveats:
        if caveat.only_if_tagged is not None:
            required_tags = list(caveat.only_if_tagged.required_tags)
            break
    if not required_tags:
        raise ValueError(
            "vendor capability must have an OnlyIfTagged caveat; "
            f"got caveats={vendor_cap.caveats!r}"
        )

    @capability_required(
        vendor_wrapper.client,
        vendor_cap,
        action_kind="envelope.send",
    )
    async def submit(submission: dict[str, Any], extra_tags: list[str]) -> yutha.Hash:
        payload = json.dumps(submission).encode("utf-8")
        tags = [DEMO_TAG, TAG_SUBMISSION, *required_tags, *extra_tags]
        return await vendor_wrapper.send(
            recipient=yutha.Recipient.for_agent(buyer_intake_id),
            performative=yutha.Performative.REQUEST_ACTION,
            payload=payload,
            payload_schema_id="type.yutha.dev/v1/Json",
            tags=tags,
        )

    return submit


def build_vendor_cross_rfp_attempt(
    vendor_wrapper: YuthaCrewAgent,
    vendor_cap: yutha.Capability,
    buyer_intake_id: yutha.AgentId,
    target_rfp_id: str,
) -> Callable[[dict[str, Any]], Awaitable[yutha.Hash]]:
    """Return an async function that attempts to submit to a SPECIFIC
    RFP using a cap that's pinned to a DIFFERENT RFP. The cap's
    ``OnlyIfTagged`` caveat will be unmet because the envelope is
    tagged with the target RFP, not the cap's RFP — so the cap-
    check denies before the envelope reaches the constitution
    layer.

    This is the demo's bounded-capabilities-as-isolation
    demonstration: even if the vendor's code or prompt tries to
    leak across RFPs, the substrate refuses to forward the
    envelope. The vendor never sees another vendor's data because
    the substrate never lets it ask for it under its bounded cap.
    """

    @capability_required(
        vendor_wrapper.client,
        vendor_cap,
        action_kind="envelope.send",
    )
    async def attempt(submission: dict[str, Any]) -> yutha.Hash:
        payload = json.dumps(submission).encode("utf-8")
        # Crucially we tag with ``target_rfp_id`` — the WRONG RFP
        # for the cap we're presenting. Cap-check sees the
        # OnlyIfTagged caveat's required_tags absent from
        # resource_tags and denies.
        tags = [DEMO_TAG, TAG_SUBMISSION, rfp_tag(target_rfp_id)]
        return await vendor_wrapper.send(
            recipient=yutha.Recipient.for_agent(buyer_intake_id),
            performative=yutha.Performative.REQUEST_ACTION,
            payload=payload,
            payload_schema_id="type.yutha.dev/v1/Json",
            tags=tags,
        )

    return attempt


# -----------------------------------------------------------------------------
# Buyer-side LangGraph workflow (intake → score → maybe-escalate)
# -----------------------------------------------------------------------------
#
# State threaded through the three-node graph. Marked ``total=False``
# so each node returns only the keys it populates; LangGraph merges
# each node's return into the running state.


class IntakeState(TypedDict, total=False):
    """State for the buyer_intake graph."""

    envelope_tags: list[str]
    envelope_payload: bytes
    rfp_id: str
    submission: dict[str, Any]
    is_high_value: bool
    escalation_receipt_id: yutha.Hash


def _extract_rfp_id(tags: list[str]) -> str | None:
    """Pull the ``rfp:<id>`` tag from an envelope's tag set, if any.

    The first ``rfp:<id>`` tag wins. The demo's well-behaved sends
    only have one such tag; if a misbehaving vendor stuffed two
    in one envelope, picking the first is a deterministic fallback
    (and the constitution would deny the send on a different rule
    in any case)."""
    for t in tags:
        if t.startswith("rfp:"):
            return t.removeprefix("rfp:")
    return None


def classify_rfp(state: IntakeState) -> IntakeState:
    """First node — read the envelope tags and pin which RFP this
    submission is for. Errors fail loud rather than silently
    routing to a default RFP: a submission without an rfp tag is
    not a valid submission under this platform's contract."""
    rfp_id = _extract_rfp_id(state["envelope_tags"])
    if rfp_id is None:
        raise ValueError(
            f"submission envelope has no rfp:<id> tag; tags={state['envelope_tags']!r}"
        )
    return {"rfp_id": rfp_id}


def score_submission(state: IntakeState) -> IntakeState:
    """Second node — decode the payload and decide if the bid is
    high-value enough to escalate. A real implementation would
    score against a per-RFP rubric (price, vendor track record,
    proposal quality); for the demo a single threshold keeps the
    audit shape deterministic. The same boundary logic appears in
    ``ap_invoice.py`` — interpret the number in one place, tag the
    envelope, and let the constitution see the tag rather than the
    raw value."""
    submission = json.loads(state["envelope_payload"].decode("utf-8"))
    is_high_value = submission.get("bid_amount_cents", 0) > HIGH_VALUE_THRESHOLD_CENTS
    return {"submission": submission, "is_high_value": is_high_value}


def build_intake_graph(
    intake_agent: YuthaAgent,
    human_approver_id: yutha.AgentId,
) -> Any:
    """Compile the buyer_intake three-node graph: classify → score →
    maybe-escalate. The maybe-escalate branch is the only one that
    produces an outbound envelope; the under-threshold branch logs
    and ends.

    The escalation send is NOT capability-gated. The constitution
    still gates it — the permit-all fallback fires because the
    envelope is tagged ``escalation`` not ``submission``."""

    async def maybe_escalate(state: IntakeState) -> IntakeState:
        if not state["is_high_value"]:
            return {}
        submission = state["submission"]
        rfp_id = state["rfp_id"]
        # The escalation envelope carries enough context that the
        # human approver can act on it directly. We deliberately
        # don't include other vendors' submission ids — the
        # confidentiality wall extends to the human-review side of
        # the buyer's organization too.
        payload = json.dumps(
            {
                "rfp_id": rfp_id,
                "submission_id": submission["submission_id"],
                "vendor": submission["vendor"],
                "bid_amount_cents": submission["bid_amount_cents"],
                "reason_for_escalation": (
                    f"bid_amount > ${HIGH_VALUE_THRESHOLD_CENTS / 100:,.0f} threshold"
                ),
            }
        ).encode("utf-8")
        receipt = await intake_agent.send(
            recipient=yutha.Recipient.for_agent(human_approver_id),
            performative=yutha.Performative.REQUEST_ACTION,
            payload=payload,
            payload_schema_id="type.yutha.dev/v1/Json",
            tags=[DEMO_TAG, TAG_ESCALATION, rfp_tag(rfp_id), TAG_HUMAN_REVIEW],
        )
        return {"escalation_receipt_id": receipt}

    def route(state: IntakeState) -> str:
        return "maybe_escalate" if state.get("is_high_value") else END

    graph: StateGraph = StateGraph(IntakeState)
    graph.add_node("classify_rfp", classify_rfp)
    graph.add_node("score_submission", score_submission)
    graph.add_node("maybe_escalate", maybe_escalate)
    graph.add_edge(START, "classify_rfp")
    graph.add_edge("classify_rfp", "score_submission")
    graph.add_conditional_edges(
        "score_submission",
        route,
        {"maybe_escalate": "maybe_escalate", END: END},
    )
    graph.add_edge("maybe_escalate", END)
    return graph.compile()


# -----------------------------------------------------------------------------
# Audit helpers (same shape as code_review.py / ap_invoice.py)
# -----------------------------------------------------------------------------


async def query_audit(client: yutha.YuthaClient, kinds: list[str]) -> dict[str, int]:
    """Snapshot receipt counts for each action_kind. Used to compute
    the delta attributable to this run — works whether the server
    is freshly started or hosting receipts from prior demos."""
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
    """Poll the receipt store until the count of ``kind`` has grown
    by ``expected_delta``."""
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

EnvelopeHandler = Callable[[YuthaAgent, yutha.Envelope, yutha.Hash], Awaitable[None]]


async def run_procurement(server_addr: str = SERVER_ADDR) -> dict[str, int]:
    """Run the procurement-platform demo end-to-end. Returns the
    audit-trail delta keyed by action_kind."""
    print(f"# procurement-platform demo · server={server_addr}")

    # Lazy CrewAI import — keeps the ``--print-operator-pubkey``
    # invocation fast and gives a clean diagnostic if the extra
    # isn't installed.
    try:
        from crewai import Agent
    except ImportError as e:
        raise RuntimeError(
            "CrewAI is not installed. Run:\n"
            "    cd sdks/python && uv pip install -e '.[dev,crewai]'\n"
            "and re-run this demo."
        ) from e

    if not os.environ.get("OPENAI_API_KEY"):
        print(
            "OPENAI_API_KEY is not set. CrewAI Agents require an LLM "
            "credential at construction time, even when the substrate "
            "path bypasses the LLM. Set the env var (or any other "
            "CrewAI-compatible LLM config) and re-run."
        )
        return {}

    # --- bootstrap identity -------------------------------------------------
    bootstrap_key, bootstrap_agent_id, swarm_id, seed = load_bootstrap_identity_from_env()
    print(f"# swarm_id={swarm_id.value.hex()} (from YUTHA_BOOTSTRAP_SEED)")

    op_signing_key, op_public_key = derive_operator_identity(seed)
    print(f"# operator pubkey (pass as --operator-public-key): {op_public_key.value.hex()}")

    # --- Phase 0: pre-flow audit snapshot ----------------------------------
    kinds = list(EXPECTED_AUDIT_DELTA.keys())
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
    for name, framework in [*BUYER_CAST, *VENDOR_CAST]:
        key = yutha.SigningKey.generate()
        agent_id = yutha.AgentId(value=secrets.token_bytes(16))
        passport = make_passport(name, framework, swarm_id, key, agent_id)
        identities[name] = (key, agent_id, passport)

    # --- CrewAI Agent instances (LLM is constructed at this point) --------
    crew_agents: dict[str, Any] = {
        "vendor_alpha": Agent(
            role="Vendor Alpha proposal agent",
            goal="Submit a competitive proposal to invited RFPs.",
            backstory="Acts on behalf of Vendor Alpha — invited to RFP-101 only.",
            allow_delegation=False,
        ),
        "vendor_beta": Agent(
            role="Vendor Beta proposal agent",
            goal="Submit competitive proposals to invited RFPs.",
            backstory="Acts on behalf of Vendor Beta — invited to RFP-101 and RFP-202.",
            allow_delegation=False,
        ),
        "vendor_gamma": Agent(
            role="Vendor Gamma proposal agent",
            goal="Submit a competitive proposal to invited RFPs.",
            backstory="Acts on behalf of Vendor Gamma — invited to RFP-202 only.",
            allow_delegation=False,
        ),
    }

    # --- received-envelope ledger (used for log-only handlers) -------------
    received: dict[str, list[yutha.Envelope]] = {n: [] for n in identities}
    intake_graph_holder: dict[str, Any] = {}

    # --- buyer-side inbound handlers (LangGraph) ---------------------------
    def buyer_intake_handler(human_approver_id: yutha.AgentId) -> EnvelopeHandler:
        """Buyer-intake handler: drives the three-node LangGraph
        workflow on each inbound submission. We compile the graph
        lazily on first envelope so the closure captures the actual
        ``YuthaAgent`` reference passed in by the dispatch loop."""

        async def handler(
            agent: YuthaAgent,
            envelope: yutha.Envelope,
            _deliver_id: yutha.Hash,
        ) -> None:
            received["buyer_intake"].append(envelope)
            if "graph" not in intake_graph_holder:
                intake_graph_holder["graph"] = build_intake_graph(agent, human_approver_id)
            rfp = _extract_rfp_id(list(envelope.tags))
            print(
                f"  [buyer_intake] recv {len(envelope.payload)}B "
                f"rfp={rfp} tags={list(envelope.tags)}"
            )
            await intake_graph_holder["graph"].ainvoke(
                {
                    "envelope_tags": list(envelope.tags),
                    "envelope_payload": envelope.payload,
                }
            )

        return handler

    def passive_handler(name: str) -> EnvelopeHandler:
        async def handler(
            _agent: YuthaAgent,
            envelope: yutha.Envelope,
            _deliver_id: yutha.Hash,
        ) -> None:
            received[name].append(envelope)
            print(f"  [{name}] recv {len(envelope.payload)}B tags={list(envelope.tags)}")

        return handler

    # --- vendor-side inbound handlers (CrewAI task_factory shape) ----------
    def vendor_task_factory(name: str) -> Callable[..., Any]:
        """Vendors only initiate submissions in this demo; they
        don't react to inbound envelopes. The task_factory logs
        receipt and returns None (no LLM call). A production
        integration would have the vendor agent reply to
        clarification requests through this factory."""

        def factory(
            _agent: YuthaCrewAgent,
            envelope: yutha.Envelope,
            _deliver_id: yutha.Hash,
        ) -> Any:
            received[name].append(envelope)
            print(f"  [{name}] recv {len(envelope.payload)}B tags={list(envelope.tags)}")
            return None

        return factory

    print("\n# Phase 1 — connect + register (5 agents)")
    buyer_handles: dict[str, YuthaAgent] = {}
    vendor_wrappers: dict[str, YuthaCrewAgent] = {}
    try:
        human_approver_id = identities["human_approver"][1]

        # buyer-side agents — YuthaAgent (LangGraph flavour)
        for name, _ in BUYER_CAST:
            key, _agent_id, passport = identities[name]
            handler: EnvelopeHandler
            if name == "buyer_intake":
                handler = buyer_intake_handler(human_approver_id)
            else:
                handler = passive_handler(name)
            ag = YuthaAgent.connect(
                server_addr,
                passport=passport,
                signing_key=key,
                handler=handler,
            )
            buyer_handles[name] = ag
            receipt = await ag.register()
            short = receipt.digest.hex()[:16] + "…" if receipt else "already-present"
            print(f"  registered {name:<15} (langgraph)   receipt={short}")

        # vendor-side agents — YuthaCrewAgent
        for name, _ in VENDOR_CAST:
            key, _agent_id, passport = identities[name]
            wrapper = YuthaCrewAgent.connect(
                server_addr,
                passport=passport,
                signing_key=key,
                crew_agent=crew_agents[name],
                task_factory=vendor_task_factory(name),
            )
            vendor_wrappers[name] = wrapper
            receipt = await wrapper.register()
            short = receipt.digest.hex()[:16] + "…" if receipt else "already-present"
            print(f"  registered {name:<15} (crewai)      receipt={short}")

        buyer_intake_id = identities["buyer_intake"][1]
        vendor_alpha_id = identities["vendor_alpha"][1]
        vendor_beta_id = identities["vendor_beta"][1]
        vendor_gamma_id = identities["vendor_gamma"][1]
        _ = (vendor_alpha_id, vendor_beta_id, vendor_gamma_id)

        # --- start dispatch loops ---------------------------------------
        async with AsyncExitStack() as stack:
            print("\n# Phase 2 — start dispatch loops")
            for ag in buyer_handles.values():
                await stack.enter_async_context(ag)
            for wrapper in vendor_wrappers.values():
                await stack.enter_async_context(wrapper)
            print("  all five agents subscribed (2 langgraph + 3 crewai)")

            # --- Phase 3: operator activates the constitution ------------
            print("\n# Phase 3 — operator activates procurement constitution")
            constitution = build_procurement_constitution(swarm_id)
            async with yutha.YuthaClient.connect_as_operator(
                server_addr,
                operator_id="yutha-demo:procurement:operator",
                swarm_id=swarm_id,
                operator_signing_key=op_signing_key,
            ) as op_client:
                activated = await op_client.constitution.activate(constitution)
            print(
                f"  constitution_hash={activated.constitution_hash.digest.hex()[:16]}… "
                f"version={constitution.constitution_version} "
                f"activate_receipt={activated.activate_receipt.digest.hex()[:16]}…"
            )

            # --- Phase 4: issue one cap per (vendor, invited-RFP) -------
            #
            # vendor_alpha → 1 cap (RFP-101)
            # vendor_beta  → 2 caps (RFP-101 + RFP-202)
            # vendor_gamma → 1 cap (RFP-202)
            print("\n# Phase 4 — issue vendor send caps (one per invited RFP)")
            vendor_caps: dict[tuple[str, str], yutha.Capability] = {}
            for vendor_name, rfps in VENDOR_INVITATIONS.items():
                _, vendor_id, _ = identities[vendor_name]
                wrapper = vendor_wrappers[vendor_name]
                for rfp_id in rfps:
                    cap = build_vendor_capability(vendor_id, rfp_id, swarm_id)
                    cap_id, issue_receipt = await wrapper.client.capability.issue(cap)
                    vendor_caps[(vendor_name, rfp_id)] = cap
                    print(
                        f"  {vendor_name} → {rfp_id} cap id={cap_id.digest.hex()[:16]}… "
                        f"issuance={issue_receipt.digest.hex()[:16]}…"
                    )

            # Build the cap-gated submit helpers now that the caps
            # exist. Each helper is bound to one specific cap.
            submit_alpha_101 = build_vendor_submit(
                vendor_wrappers["vendor_alpha"],
                vendor_caps[("vendor_alpha", "RFP-101")],
                buyer_intake_id,
            )
            submit_beta_101 = build_vendor_submit(
                vendor_wrappers["vendor_beta"],
                vendor_caps[("vendor_beta", "RFP-101")],
                buyer_intake_id,
            )
            submit_beta_202 = build_vendor_submit(
                vendor_wrappers["vendor_beta"],
                vendor_caps[("vendor_beta", "RFP-202")],
                buyer_intake_id,
            )
            submit_gamma_202 = build_vendor_submit(
                vendor_wrappers["vendor_gamma"],
                vendor_caps[("vendor_gamma", "RFP-202")],
                buyer_intake_id,
            )

            # --- Phase 5: cross-RFP attempt — cap-layer denies ----------
            #
            # vendor_alpha tries to submit to RFP-202 using its only
            # cap (which requires rfp:RFP-101). The cap caveat is
            # unmet; cap-check denies; ``CapabilityDenied`` raises
            # in the wrapped function before the envelope hits the
            # wire. This is the demo's bounded-capabilities-as-
            # isolation demonstration: the substrate refuses to
            # forward the envelope at all.
            print("\n# Phase 5 — cross-RFP attempt (cap-layer denies)")
            cross_rfp_attempt = build_vendor_cross_rfp_attempt(
                vendor_wrappers["vendor_alpha"],
                vendor_caps[("vendor_alpha", "RFP-101")],
                buyer_intake_id,
                target_rfp_id="RFP-202",
            )
            cap_denied = False
            try:
                await cross_rfp_attempt(
                    {
                        "submission_id": "SUB-2026-A202-INVALID",
                        "vendor": "vendor_alpha",
                        "rfp_id": "RFP-202",
                        "bid_amount_cents": 50_000_00,
                        "proposal_summary": "Attempting to submit to an uninvited RFP.",
                    }
                )
            except CapabilityDenied as e:
                cap_denied = True
                print(f"  ✓ cap denied as expected: {e}")
            except yutha.ConstitutionDenied as e:
                raise AssertionError(
                    "cross-RFP attempt should have hit the cap layer first; "
                    f"got constitution deny instead: {e}"
                ) from None
            assert cap_denied, "cross-RFP attempt should have raised CapabilityDenied"

            # --- Phase 6: happy submissions (4 vendor sends) ------------
            print("\n# Phase 6 — happy submissions")
            await submit_alpha_101(VENDOR_ALPHA_RFP_101, [])
            print("  ✓ vendor_alpha → buyer_intake (RFP-101)")
            await submit_beta_101(VENDOR_BETA_RFP_101, [])
            print("  ✓ vendor_beta  → buyer_intake (RFP-101)")
            await submit_beta_202(VENDOR_BETA_RFP_202, [])
            print("  ✓ vendor_beta  → buyer_intake (RFP-202, high value)")
            await submit_gamma_202(VENDOR_GAMMA_RFP_202, [])
            print("  ✓ vendor_gamma → buyer_intake (RFP-202)")

            # --- Phase 7: wait for the escalation to land at human ------
            #
            # buyer_intake's LangGraph workflow runs in the dispatch-
            # loop's task. For the high-value submission it produces
            # an outbound escalation envelope; we wait for the human
            # approver's handler to log receipt of exactly one.
            print("\n# Phase 7 — wait for high-value escalation to land")
            await _wait_for_envelope(received, "human_approver", expected=1)
            print(f"  ✓ human_approver received {len(received['human_approver'])} escalation(s)")

            # --- Phase 8: bypass attempt #1 -----------------------------
            #
            # vendor_alpha tries to send a submission tagged with the
            # leakage sentinel. The cap caveat IS satisfied (the
            # required rfp:RFP-101 tag is added by ``build_vendor_submit``
            # unconditionally) — cap-check passes. The constitution's
            # leakage forbid rule matches; ``ConstitutionDenied``
            # raises with reason ``forbid_rule_matched``.
            print("\n# Phase 8 — vendor_alpha leakage attempt #1")
            denied_1 = await _attempt_leakage(submit_alpha_101)
            assert denied_1.deny_reason == "forbid_rule_matched", (
                f"expected forbid_rule_matched, got {denied_1.deny_reason!r}"
            )
            print(f"  ✓ denied: {denied_1}")

            # --- Phase 9: bypass attempt #2 → trips enforcement.detect --
            print("\n# Phase 9 — vendor_alpha leakage attempt #2 (trips enforcement.detect)")
            denied_2 = await _attempt_leakage(submit_alpha_101)
            assert denied_2.deny_reason == "forbid_rule_matched"
            print(f"  ✓ denied: {denied_2}")

            # --- Phase 10: poll for detect → coach → quarantine --------
            print("\n# Phase 10 — poll for detect → coach → quarantine")
            for stage in (
                "enforcement.detect",
                "enforcement.coach",
                "enforcement.quarantine",
            ):
                await wait_for_kind_delta(
                    vendor_wrappers["vendor_alpha"].client,
                    stage,
                    before[stage],
                    expected_delta=1,
                )
                print(f"  ✓ {stage} landed")

            # --- Phase 11: cap-check denies WHILE quarantined ----------
            #
            # vendor_alpha's RFP-101 cap was never revoked. It's
            # still cryptographically valid, still in the cap store,
            # still within its validity window. The cap layer's
            # QuarantineSource consults the engine on every check
            # and denies with reason ``subject_quarantined``. F10g's
            # spec reason; same shape as ``code_review.py`` /
            # ``ap_invoice.py``.
            print("\n# Phase 11 — verify quarantine denies vendor_alpha cap-check")
            check_outcome = await vendor_wrappers["vendor_alpha"].client.capability.check(
                vendor_caps[("vendor_alpha", "RFP-101")],
                yutha.ActionDescriptor(action_kind="envelope.send"),
            )
            assert not check_outcome.permitted, (
                "quarantined vendor_alpha should be denied even on a still-valid cap"
            )
            assert check_outcome.deny_reason == "subject_quarantined", (
                f"expected subject_quarantined, got {check_outcome.deny_reason!r}"
            )
            print(f"  ✓ cap-check denied with reason={check_outcome.deny_reason}")

            # --- Phase 12: wait for evict -------------------------------
            print("\n# Phase 12 — wait for enforcement.evict")
            await wait_for_kind_delta(
                vendor_wrappers["vendor_alpha"].client,
                "enforcement.evict",
                before["enforcement.evict"],
                expected_delta=1,
            )
            print("  ✓ enforcement.evict landed")

            # --- Phase 13: snapshot delta + report ---------------------
            print("\n# Phase 13 — audit-trail delta")
            after = await query_audit(vendor_wrappers["vendor_alpha"].client, kinds)
            delta = {k: after[k] - before[k] for k in kinds}
            for k in kinds:
                marker = "✓" if delta[k] == EXPECTED_AUDIT_DELTA[k] else "✗"
                print(f"  {marker} {k:<28} +{delta[k]:<2} (expected +{EXPECTED_AUDIT_DELTA[k]})")
            return delta
    finally:
        # Belt-and-braces channel close — YuthaClient.close is
        # documented as idempotent on both flavours.
        for ag in buyer_handles.values():
            try:
                await ag.client.close()
            except Exception:
                pass
        for wrapper in vendor_wrappers.values():
            try:
                await wrapper.client.close()
            except Exception:
                pass


async def _wait_for_envelope(
    received: dict[str, list[yutha.Envelope]],
    name: str,
    *,
    expected: int,
    timeout_seconds: float = 5.0,
) -> None:
    """Block until ``received[name]`` has at least ``expected``
    entries. Used between phases to keep the demo deterministic —
    each phase finishes only after the envelope it produced has
    been observed by the receiving agent's handler."""
    deadline = asyncio.get_event_loop().time() + timeout_seconds
    while asyncio.get_event_loop().time() < deadline:
        if len(received[name]) >= expected:
            return
        await asyncio.sleep(0.05)
    raise AssertionError(
        f"timed out waiting for {expected} envelope(s) at {name!r}; got {len(received[name])}"
    )


async def _attempt_leakage(
    submit: Callable[[dict[str, Any], list[str]], Awaitable[yutha.Hash]],
) -> yutha.ConstitutionDenied:
    """Drive one leakage bypass attempt and return the structured
    deny. Wraps the assertion that ``ConstitutionDenied`` raises
    rather than ``CapabilityDenied`` — cap-check runs first
    server-side, and on the bypass attempts the cap is still
    valid (the RFP-101 tag satisfies the caveat), so the deny we
    expect comes from the constitution layer."""
    leak_payload = {
        "submission_id": "SUB-2026-A101-LEAK",
        "vendor": "vendor_alpha",
        "rfp_id": "RFP-101",
        "bid_amount_cents": 49_000_00,
        "proposal_summary": (
            "Demo: this envelope tags itself with leak_other_vendor_data "
            "to exercise the constitution's forbid rule."
        ),
    }
    try:
        await submit(leak_payload, [TAG_LEAK_OTHER_VENDOR_DATA])
    except yutha.ConstitutionDenied as e:
        return e
    except CapabilityDenied as e:
        raise AssertionError(
            f"leakage attempt should have raised ConstitutionDenied, not CapabilityDenied: {e}"
        ) from None
    raise AssertionError("leakage attempt should have raised ConstitutionDenied")


# -----------------------------------------------------------------------------
# CLI entry points
# -----------------------------------------------------------------------------


def _print_operator_pubkey() -> None:
    """Convenience subcommand: derive + print the operator pubkey
    from ``YUTHA_BOOTSTRAP_SEED`` so callers can pipe it straight
    into the control-plane invocation."""
    _, _, _, seed = load_bootstrap_identity_from_env()
    _, op_public_key = derive_operator_identity(seed)
    print(op_public_key.value.hex())


def main() -> None:
    # ``--print-operator-pubkey`` is the only flag the demo accepts;
    # everything else is env-driven (YUTHA_BOOTSTRAP_SEED,
    # YUTHA_GRPC_ADDR, OPENAI_API_KEY).
    if len(sys.argv) == 2 and sys.argv[1] == "--print-operator-pubkey":
        _print_operator_pubkey()
        return
    delta = asyncio.run(run_procurement())
    if not delta:
        return  # OPENAI_API_KEY missing; the run printed a diagnostic.
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

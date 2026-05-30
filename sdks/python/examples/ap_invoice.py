"""AP / invoice processing — Python + CrewAI end-to-end demo.

Four CrewAI agents collaborating on an accounts-payable pipeline:
a classifier that buckets invoices by amount, an auto-approver
that authorizes small payments, a supervisor that authorizes
large payments after human review, and a treasury observer that
receives every authorized payment. The substrate point is **role
boundaries enforced by the constitution**: only the supervisor
may authorize over-cap payments, and the four-stage enforcement
loop trips on any agent that tries to bypass that boundary.

Companion to ``code_review.py`` (the LangGraph constitution demo).
Same substrate machinery — different framework idioms, different
business framing.

Cast
----

* **classifier** (``framework: ap-invoice-classifier``) — receives
  an inbound invoice envelope and routes it to either the
  approver (amount-within-cap) or the supervisor (amount-over-cap).
  Sends are not cap-gated; classification is keyed off a
  deterministic threshold in the invoice payload.
* **approver** (``framework: ap-invoice-approver``) — auto-approves
  small invoices by sending an ``authorize_payment`` envelope to
  the treasury. Its outbound send is wrapped with
  ``@capability_required``. This is the agent whose bypass attempts
  trip the enforcement loop.
* **supervisor** (``framework: ap-invoice-supervisor``) — approves
  large invoices, tagging its outbound send with
  ``supervisor_approved`` so the constitution permits the
  authorization. Sends are not cap-gated.
* **treasury** (``framework: ap-invoice-treasury``) — passive
  observer; receives every ``authorize_payment`` envelope so the
  audit log carries the full "who authorized what" trail.

Constitution
------------

The active constitution forbids ``SendEnvelope`` when all three
hold simultaneously:

  1. envelope is tagged ``authorize_payment``;
  2. envelope is tagged ``amount_over_cap``;
  3. envelope is NOT tagged ``supervisor_approved``.

The supervisor's authorize-payment helper unconditionally adds
``supervisor_approved`` alongside its tag set; the approver's
helper never does. The bypass attempt sends ``amount_over_cap``
without the ``supervisor_approved`` tag, the forbid rule
matches, and the substrate raises ``ConstitutionDenied``.

Substrate caveat: the more honest version of this rule would
gate on the principal's passport-trusted ``framework`` attribute
(so the approver couldn't bypass by adding the supervisor tag
itself). That requires the gRPC EnvelopeHandler to enrich the
principal's Cedar Agent entity from the PassportStore — until
that pass lands the handler still passes placeholder values
(empty framework, minimal tier, all-zero passport_hash) and a
``principal.framework == "..."`` policy never matches. See the
walkthrough's "what to try next" for the tracking item.

The engine config attaches a single enforcement rule covering
all four stages (detect → coach → quarantine → evict) with 1-
second cooldowns, identical in shape to ``forbid_constitution``
in ``yutha.testing``. ``count_threshold: 2`` means two denies
within a 60-second window for the same principal fire detect;
the chain then progresses on the server's wall-clock scheduler.

Running locally
---------------

CrewAI's Agent constructor requires an LLM credential even when
the demo never reaches an LLM-driven step (the substrate path
bypasses the LLM by invoking tools directly). Set
``OPENAI_API_KEY`` (or any CrewAI-compatible LLM credential) plus
the bootstrap seed and the operator pubkey:

::

    export YUTHA_BOOTSTRAP_SEED=$(python -c \\
        'import secrets; print(secrets.token_hex(32))')
    export OPENAI_API_KEY=...

    cargo run -p yutha-control-plane -- \\
        --admission-mode open \\
        --operator-public-key $(python sdks/python/examples/ap_invoice.py --print-operator-pubkey)

    python sdks/python/examples/ap_invoice.py

What the demo exercises
-----------------------

* Four CrewAI agents register with distinct ``framework`` labels
  that the constitution gates on.
* An operator-bearer client activates a custom AP-invoice
  constitution carrying the four-stage enforcement rule.
* The classifier routes a $250 invoice to the approver and a
  $50,000 invoice to the supervisor; both end up at the
  treasury with permitted ``authorize_payment`` envelopes.
* The approver makes two bypass attempts (over-cap authorize
  without the supervisor-approved tag); both raise
  ``ConstitutionDenied`` with reason ``forbid_rule_matched``.
* The enforcement loop progresses through all four stages; the
  demo polls the receipt store for each one.
* A post-quarantine ``capability.check`` returns deny with
  reason ``subject_quarantined`` — quarantine state is consulted
  on every cap-check regardless of the cap's own validity.
* The audit-trail delta is computed against a pre-flow snapshot
  and asserted exactly.

The runnable ``run_ap_invoice()`` coroutine returns the audit
delta so an optional pytest wrapper could re-use the body.
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
from typing import Any, cast

import yutha
from yutha.crewai import CapabilityDenied, YuthaCrewAgent

# The async-function flavour of `capability_required` lives in
# `yutha.langgraph.tools` — its sibling in `yutha.crewai.tools` is
# designed to wrap a CrewAI ``BaseTool`` instance rather than a
# plain coroutine. Both flavours route through the same
# ``ACTIVE_CAPABILITY_ID`` contextvar (see ``yutha._capability_context``),
# so this demo's gate fires equivalently whether the agent ships
# under a CrewAI or LangGraph adapter; the choice here is purely
# about which callable shape we want to decorate.
from yutha.langgraph.tools import capability_required
from yutha.models.constitution import Constitution

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

SERVER_ADDR = os.environ.get("YUTHA_GRPC_ADDR", "127.0.0.1:50051")

FAR_FUTURE = yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62)

# Per-stage wall-clock budget for the enforcement chain. 1s scheduler
# tick + 1s cooldowns × 3 stages = ~5s real chain time; 15s leaves
# generous slack for slow CI machines.
ENFORCEMENT_STAGE_TIMEOUT_SECONDS = 15.0
ENFORCEMENT_POLL_INTERVAL_SECONDS = 0.25

# The amount threshold (cents) above which authorization requires
# the supervisor. The classifier buckets invoices into the
# ``amount_within_cap`` / ``amount_over_cap`` tags off this value.
# The constitution does NOT see this number directly — only the
# resulting tag — because Cedar can't see into payload bytes and
# `estimated_cost_usd_cents` is not yet plumbed end-to-end.
PAYMENT_CAP_CENTS = 10_000_00  # $10,000

# -----------------------------------------------------------------------------
# Constitution (Cedar source + engine config)
# -----------------------------------------------------------------------------
#
# Forbid `authorize_payment` envelopes tagged `amount_over_cap` UNLESS
# they also carry the `supervisor_approved` tag. The supervisor's
# authorize-payment helper unconditionally adds `supervisor_approved`
# alongside `amount_over_cap`; the approver's helper never does. The
# bypass attempt sends `amount_over_cap` without `supervisor_approved`
# and trips the forbid.
#
# Design note: the more substrate-honest version of this rule would
# gate on the principal's passport-trusted `framework` attribute
# (so the approver can't lie about which role it is). That requires
# the gRPC EnvelopeHandler to enrich the principal's Agent entity
# with real attributes from the PassportStore — at the time of writing
# the handler still passes placeholder values (empty `framework`,
# minimal tier, all-zero passport_hash). Until that enrichment pass
# lands, gating on a tag the supervisor's helper applies is the
# practical path. The "What to try next" section of the walkthrough
# tracks this as a substrate follow-on.
#
# Trailing `permit (principal, action, resource)` is required: Cedar
# Validator rejects policy sets that lack a permit, and every
# non-authorize-payment send (e.g. the classifier dispatching an
# invoice) needs the permit-all fallback so it passes the
# constitution gate.

_AP_CEDAR_SOURCE = """\
@id("no-over-cap-without-supervisor-approval")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
) when {
    context.tags.contains("authorize_payment") &&
    context.tags.contains("amount_over_cap") &&
    !context.tags.contains("supervisor_approved")
};

permit (principal, action, resource);
"""

# Same four-stage chain as `forbid_constitution`: 1s cooldowns,
# count_threshold 2, require_countersign false on evict (we don't
# stand up a supervisor-tier agent that countersigns).
_AP_ENGINE_CONFIG_YAML = """\
schema_version: "1.1.0"
predicates: []
scoring_rules: []
procedures: []
enforcement_rules:
  - name: over_cap_bypass_chain
    detect:
      trigger:
        receipt_kind: constitution.evaluate.deny
      count_threshold: 2
      time_window: 60s
      group_by: principal
    coach:
      cooldown: 1s
      guidance_template: "Auto-approver may not authorize over-cap payments"
    quarantine:
      escalate_after: 1s
    evict:
      escalate_after: 1s
      require_countersign: false
    severity: high
"""


def build_ap_constitution(swarm_id: yutha.SwarmId) -> Constitution:
    """Build the AP-invoice demo's constitution. Inlined here so
    the demo file is self-describing."""
    return Constitution(
        spec_version="1.0.0",
        schema_version="1.1.0",
        constitution_version="1.0.0",
        parent_version=None,
        swarm_id=swarm_id,
        cedar_source=_AP_CEDAR_SOURCE,
        engine_config_yaml=_AP_ENGINE_CONFIG_YAML,
        issued_at=yutha.Timestamp.now(),
    )


# -----------------------------------------------------------------------------
# Cast + invoice fixtures
# -----------------------------------------------------------------------------

# Framework labels matter — the constitution gates on
# `principal.framework == "ap-invoice-approver"`. Don't change these
# without updating the Cedar source above.
CAST: list[tuple[str, str]] = [
    ("classifier", "ap-invoice-classifier"),
    ("approver", "ap-invoice-approver"),
    ("supervisor", "ap-invoice-supervisor"),
    ("treasury", "ap-invoice-treasury"),
]

# The two invoices the demo classifies + routes. Amounts are in
# cents to match PAYMENT_CAP_CENTS.
HAPPY_INVOICE = {
    "invoice_id": "INV-2026-00417",
    "vendor": "Acme Office Supplies",
    "amount_cents": 25_000,  # $250
    "description": "Quarterly office supply restock.",
}
LARGE_INVOICE = {
    "invoice_id": "INV-2026-00418",
    "vendor": "Acme Cloud Services",
    "amount_cents": 50_000_00,  # $50,000
    "description": "Annual cloud hosting renewal.",
}

# Tag conventions. Constitution keys on these.
TAG_AUTHORIZE_PAYMENT = "authorize_payment"
TAG_AMOUNT_WITHIN_CAP = "amount_within_cap"
TAG_AMOUNT_OVER_CAP = "amount_over_cap"
TAG_SUPERVISOR_APPROVED = "supervisor_approved"
TAG_INVOICE = "invoice"
DEMO_TAG = "ap-invoice-demo"


# -----------------------------------------------------------------------------
# Expected audit-trail delta for one clean demo run
# -----------------------------------------------------------------------------

EXPECTED_AUDIT_DELTA: dict[str, int] = {
    # 4 fresh agents register themselves.
    "agent.register": 4,
    # Operator activates the AP constitution.
    "constitution.activate": 1,
    # 4 successful sends:
    #   classifier → approver (HAPPY invoice)
    #   approver → treasury (authorize_payment, within_cap)
    #   classifier → supervisor (LARGE invoice)
    #   supervisor → treasury (authorize_payment, over_cap, supervisor_approved)
    "envelope.send": 4,
    "envelope.deliver": 4,
    # Constitution-check runs on every Send. 4 successful sends pass;
    # 2 bypass attempts (approver's over_cap authorize without the
    # supervisor_approved tag) are denied.
    "constitution.evaluate.pass": 4,
    "constitution.evaluate.deny": 2,
    # Approver gets a send capability.
    "capability.issue": 1,
    # Three of approver's sends are cap-gated: 1 happy + 2 bypass
    # attempts. Cap-check runs BEFORE constitution-check; the cap is
    # valid (no quarantine yet) so all three pass cap-check. The
    # constitution layer is what denies the bypasses.
    "capability.check.pass": 3,
    # After quarantine fires, the demo explicitly re-checks the
    # approver's cap; the cap layer's QuarantineSource consults the
    # engine and denies with `subject_quarantined`.
    "capability.check.deny": 1,
    # Four stages of the enforcement loop.
    "enforcement.detect": 1,
    "enforcement.coach": 1,
    "enforcement.quarantine": 1,
    "enforcement.evict": 1,
}


# -----------------------------------------------------------------------------
# Bootstrap identity (mirrors S1 / code_review)
# -----------------------------------------------------------------------------


def derive_bootstrap_identity(
    seed: bytes,
) -> tuple[yutha.InProcessSigner, yutha.AgentId, yutha.SwarmId]:
    """Reproduce ``BootstrapIdentity::from_seed_hex``: seed is the
    Ed25519 private key, ``sha256(seed || 0x01)[:16]`` is the
    agent_id, ``sha256(seed || 0x02)[:16]`` is the swarm_id."""
    if len(seed) != 32:
        raise ValueError(f"seed must be exactly 32 bytes, got {len(seed)}")
    signer = yutha.InProcessSigner.from_seed_bytes(seed)
    agent_id = yutha.AgentId(value=hashlib.sha256(seed + b"\x01").digest()[:16])
    swarm_id = yutha.SwarmId(value=hashlib.sha256(seed + b"\x02").digest()[:16])
    return signer, agent_id, swarm_id


def derive_operator_identity(seed: bytes) -> tuple[yutha.InProcessSigner, yutha.PublicKey]:
    """Domain-separated derivation of an Ed25519 operator keypair.
    See the analogous helper in ``code_review.py`` for the
    domain-separation rationale."""
    if len(seed) != 32:
        raise ValueError(f"seed must be exactly 32 bytes, got {len(seed)}")
    op_seed = hashlib.sha256(seed + b"\x03").digest()
    op_signer = yutha.InProcessSigner.from_seed_bytes(op_seed)
    return op_signer, op_signer.public_key()


def load_bootstrap_identity_from_env() -> tuple[
    yutha.InProcessSigner, yutha.AgentId, yutha.SwarmId, bytes
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
    """Build a signed passport. The ``framework`` field is the
    constitution's hook — it's how the policy distinguishes the
    approver from the supervisor without trusting self-applied
    tags."""
    return await yutha.Passport(
        spec_version="1.0.0",
        agent_id=agent_id,
        swarm_id=swarm_id,
        agent_public_key=signer.public_key(),
        owner=f"yutha-demo:ap-invoice:{name}",
        framework=framework,
        framework_version="1.0.0",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
        expires_at=FAR_FUTURE,
    ).sign(signer)


# -----------------------------------------------------------------------------
# Classification + send helpers
# -----------------------------------------------------------------------------


def classify_amount(amount_cents: int) -> str:
    """Bucket an invoice's amount into a constitution-visible tag.
    The constitution doesn't see the raw number — only the tag —
    so this is the single point where the threshold is interpreted.
    Auditors who want to verify the boundary inspect this function
    + the constitution; the agents themselves don't need to be
    trusted on the boundary."""
    return TAG_AMOUNT_WITHIN_CAP if amount_cents <= PAYMENT_CAP_CENTS else TAG_AMOUNT_OVER_CAP


def build_classifier_dispatch(
    classifier_wrapper: YuthaCrewAgent,
    approver_id: yutha.AgentId,
    supervisor_id: yutha.AgentId,
) -> Callable[[dict[str, Any]], Awaitable[yutha.Hash]]:
    """Return an async function that takes an invoice dict and
    routes it. The classifier's send is NOT cap-gated — only the
    approver's outbound authorize is. Mirrors the ``reviewer``
    pattern in ``code_review.py``."""

    async def dispatch_invoice(invoice: dict[str, Any]) -> yutha.Hash:
        bucket = classify_amount(invoice["amount_cents"])
        dest = approver_id if bucket == TAG_AMOUNT_WITHIN_CAP else supervisor_id
        payload = json.dumps(invoice).encode("utf-8")
        return await classifier_wrapper.send(
            recipient=yutha.Recipient.for_agent(dest),
            performative=yutha.Performative.REQUEST_ACTION,
            payload=payload,
            payload_schema_id="type.yutha.dev/v1/Json",
            tags=[DEMO_TAG, TAG_INVOICE, bucket],
        )

    return dispatch_invoice


def build_approver_authorize(
    approver_wrapper: YuthaCrewAgent,
    approver_cap: yutha.Capability,
    treasury_id: yutha.AgentId,
) -> Callable[[dict[str, Any], list[str]], Awaitable[yutha.Hash]]:
    """Return an async function that sends an ``authorize_payment``
    envelope from the approver to the treasury. Wrapped with
    ``@capability_required`` so every send hits a server-side cap
    check before the envelope is signed.

    The ``extra_tags`` parameter lets the demo orchestrator drive
    bypass attempts — passing ``[TAG_AMOUNT_OVER_CAP]`` produces
    the exact tag combination the constitution forbids for an
    approver-framework principal."""

    @capability_required(
        approver_wrapper.client,
        approver_cap,
        action_kind="envelope.send",
    )
    async def authorize_payment(invoice: dict[str, Any], extra_tags: list[str]) -> yutha.Hash:
        payload = json.dumps({"authorized": invoice}).encode("utf-8")
        tags = [DEMO_TAG, TAG_AUTHORIZE_PAYMENT, *extra_tags]
        return await approver_wrapper.send(
            recipient=yutha.Recipient.for_agent(treasury_id),
            performative=yutha.Performative.INFORM,
            payload=payload,
            payload_schema_id="type.yutha.dev/v1/Json",
            tags=tags,
        )

    return authorize_payment


def build_supervisor_authorize(
    supervisor_wrapper: YuthaCrewAgent,
    treasury_id: yutha.AgentId,
) -> Callable[[dict[str, Any]], Awaitable[yutha.Hash]]:
    """Supervisor's authorize-payment send. Not cap-gated for the
    demo. The constitution permits the over-cap authorize because
    the supervisor's framework is not ``ap-invoice-approver`` AND
    its envelope carries the ``supervisor_approved`` tag — both
    independently sufficient under the forbid rule."""

    async def authorize_payment(invoice: dict[str, Any]) -> yutha.Hash:
        payload = json.dumps({"authorized": invoice, "by": "supervisor"}).encode("utf-8")
        tags = [
            DEMO_TAG,
            TAG_AUTHORIZE_PAYMENT,
            TAG_AMOUNT_OVER_CAP,
            TAG_SUPERVISOR_APPROVED,
        ]
        return await supervisor_wrapper.send(
            recipient=yutha.Recipient.for_agent(treasury_id),
            performative=yutha.Performative.INFORM,
            payload=payload,
            payload_schema_id="type.yutha.dev/v1/Json",
            tags=tags,
        )

    return authorize_payment


# -----------------------------------------------------------------------------
# Inbound task factories
# -----------------------------------------------------------------------------
#
# Each YuthaCrewAgent is constructed with a task_factory that fires on
# every inbound envelope. The factory can return a CrewAI Task (LLM
# call) or None (no LLM). For this demo every factory returns None —
# the substrate path doesn't depend on the LLM, and we want the audit
# trail to be deterministic.


def approver_task_factory(
    approver_holder: dict[str, Any],
) -> Callable[[YuthaCrewAgent, yutha.Envelope, yutha.Hash], Any]:
    """Approver's task factory. When an invoice arrives, schedule
    the ``authorize_payment`` send on the dispatch loop's event
    loop via ``run_coroutine_threadsafe`` — same bridging pattern
    as the s1 CrewAI demo.

    The ``approver_holder`` dict carries the lazily-bound
    ``authorize_payment`` callable; we can't pass it at factory-
    construction time because the cap-gated tool depends on the
    cap, which depends on the issuance, which happens after the
    wrappers are connected. The holder is populated in run_ap_invoice
    once the cap is issued."""

    def factory(
        agent: YuthaCrewAgent,
        env: yutha.Envelope,
        _deliver_id: yutha.Hash,
    ) -> Any:
        if "authorize" not in approver_holder:
            return None
        # We're on the dispatch loop's thread. Schedule the send via
        # the same loop (no thread bridging needed at this layer).
        loop = agent._dispatch_task.get_loop() if agent._dispatch_task else None
        if loop is None:
            return None
        invoice = json.loads(env.payload.decode("utf-8"))
        authorize: Callable[[dict[str, Any], list[str]], Awaitable[yutha.Hash]] = approver_holder[
            "authorize"
        ]

        async def _authorize() -> None:
            try:
                await authorize(invoice, [TAG_AMOUNT_WITHIN_CAP])
            except (CapabilityDenied, yutha.ConstitutionDenied) as e:
                print(f"  [approver] authorize denied: {e}")

        asyncio.run_coroutine_threadsafe(_authorize(), loop)
        return None

    return factory


def supervisor_task_factory(
    supervisor_holder: dict[str, Any],
) -> Callable[[YuthaCrewAgent, yutha.Envelope, yutha.Hash], Any]:
    """Supervisor's task factory. Mirrors the approver's — when an
    invoice arrives, schedule an authorize-payment send."""

    def factory(
        agent: YuthaCrewAgent,
        env: yutha.Envelope,
        _deliver_id: yutha.Hash,
    ) -> Any:
        if "authorize" not in supervisor_holder:
            return None
        loop = agent._dispatch_task.get_loop() if agent._dispatch_task else None
        if loop is None:
            return None
        invoice = json.loads(env.payload.decode("utf-8"))
        authorize: Callable[[dict[str, Any]], Awaitable[yutha.Hash]] = supervisor_holder[
            "authorize"
        ]

        async def _authorize() -> None:
            try:
                await authorize(invoice)
            except yutha.ConstitutionDenied as e:
                print(f"  [supervisor] authorize denied (unexpected): {e}")

        asyncio.run_coroutine_threadsafe(_authorize(), loop)
        return None

    return factory


def passive_task_factory(
    agent: YuthaCrewAgent,
    env: yutha.Envelope,
    _deliver_id: yutha.Hash,
) -> Any:
    """Treasury and classifier task factory — log only. The
    classifier doesn't react to inbound envelopes (the demo
    invokes its dispatch tool directly); the treasury is a passive
    receiver."""
    _ = (agent, env)
    return None


# -----------------------------------------------------------------------------
# Audit helpers
# -----------------------------------------------------------------------------


async def query_audit(client: yutha.YuthaClient, kinds: list[str]) -> dict[str, int]:
    """Snapshot receipt counts for each action_kind, paging through
    larger result sets if the server's per-page cap is hit."""
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
    by ``expected_delta``. Used for the four enforcement-stage
    receipts whose timing depends on the server scheduler tick."""
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


async def _wait_until(
    predicate: Callable[[], bool],
    *,
    description: str,
    timeout_seconds: float = 5.0,
    poll_interval_seconds: float = 0.05,
) -> None:
    """Block until ``predicate()`` returns True. Used between phases
    to keep the demo deterministic when an envelope must land
    before the next phase can proceed."""
    deadline = asyncio.get_event_loop().time() + timeout_seconds
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return
        await asyncio.sleep(poll_interval_seconds)
    raise AssertionError(f"timed out waiting for: {description}")


# -----------------------------------------------------------------------------
# Main flow
# -----------------------------------------------------------------------------


async def run_ap_invoice(server_addr: str = SERVER_ADDR) -> dict[str, int]:
    """Run the AP / invoice demo end-to-end against ``server_addr``.

    Returns the audit-trail delta keyed by action_kind, suitable
    for the ``main()`` wrapper or an optional pytest harness to
    diff against ``EXPECTED_AUDIT_DELTA``."""
    print(f"# AP / invoice demo · server={server_addr}")

    # Lazy CrewAI import — CrewAI pulls in LangChain core + assorted
    # transitives; deferring until we know the demo can actually run
    # keeps `--print-operator-pubkey` invocation fast.
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

    # --- bootstrap identity ------------------------------------------------
    bootstrap_signer, bootstrap_agent_id, swarm_id, seed = load_bootstrap_identity_from_env()
    print(f"# swarm_id={swarm_id.value.hex()} (from YUTHA_BOOTSTRAP_SEED)")

    op_signer, op_public_key = derive_operator_identity(seed)
    print(f"# operator pubkey (pass as --operator-public-key): {op_public_key.value.hex()}")

    # --- Phase 0: pre-flow audit snapshot ---------------------------------
    kinds = list(EXPECTED_AUDIT_DELTA.keys())
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

    # --- CrewAI Agent instances (LLM is constructed at this point) --------
    # We pre-build the CrewAI Agent objects here so the YuthaCrewAgent
    # wrappers can take them at connect-time. The Agent's role/goal/
    # backstory are read by CrewAI when it builds Tasks; since our
    # task_factory mostly returns None (no LLM calls), these are
    # mostly cosmetic.
    crew_agents: dict[str, Any] = {
        "classifier": Agent(
            role="AP Classifier",
            goal="Route inbound invoices to the right approver based on amount.",
            backstory="Reads invoice metadata and decides who should authorize.",
            allow_delegation=False,
        ),
        "approver": Agent(
            role="AP Auto-Approver",
            goal="Authorize small invoices for payment.",
            backstory="Approves invoices under the configured cap.",
            allow_delegation=False,
        ),
        "supervisor": Agent(
            role="AP Supervisor",
            goal="Approve high-value invoices after human-equivalent review.",
            backstory="Reviews and approves invoices above the auto-approval cap.",
            allow_delegation=False,
        ),
        "treasury": Agent(
            role="AP Treasury",
            goal="Observe authorized payments for downstream settlement.",
            backstory="Receives every authorize_payment envelope.",
            allow_delegation=False,
        ),
    }

    # --- holders used by task factories to lazily bind sender helpers ----
    approver_holder: dict[str, Any] = {}
    supervisor_holder: dict[str, Any] = {}

    # --- task factories ---------------------------------------------------
    factories: dict[str, Callable[[YuthaCrewAgent, yutha.Envelope, yutha.Hash], Any]] = {
        "classifier": passive_task_factory,
        "approver": approver_task_factory(approver_holder),
        "supervisor": supervisor_task_factory(supervisor_holder),
        "treasury": passive_task_factory,
    }

    print("\n# Phase 1 — connect + register")
    wrappers: dict[str, YuthaCrewAgent] = {}
    try:
        for name, (agent_signer, _agent_id, passport) in identities.items():
            wrapper = YuthaCrewAgent.connect(
                server_addr,
                passport=passport,
                signer=agent_signer,
                crew_agent=crew_agents[name],
                task_factory=factories[name],
            )
            wrappers[name] = wrapper
            receipt = await wrapper.register()
            short = receipt.digest.hex()[:16] + "…" if receipt else "already-present"
            print(f"  registered {name:<12} receipt={short}")

        classifier_id = identities["classifier"][1]
        approver_id = identities["approver"][1]
        supervisor_id = identities["supervisor"][1]
        treasury_id = identities["treasury"][1]
        _ = (classifier_id,)  # local name kept for symmetry; unused below

        async with AsyncExitStack() as stack:
            print("\n# Phase 2 — start dispatch loops")
            for wrapper in wrappers.values():
                await stack.enter_async_context(wrapper)
            print("  all four agents subscribed")

            # --- Phase 3: operator activates the constitution -------------
            print("\n# Phase 3 — operator activates AP constitution")
            constitution = build_ap_constitution(swarm_id)
            async with yutha.YuthaClient.connect_as_operator(
                server_addr,
                operator_id="yutha-demo:ap-invoice:operator",
                swarm_id=swarm_id,
                operator_signer=op_signer,
            ) as op_client:
                activated = await op_client.constitution.activate(constitution)
            print(
                f"  constitution_hash={activated.constitution_hash.digest.hex()[:16]}… "
                f"version={constitution.constitution_version} "
                f"activate_receipt={activated.activate_receipt.digest.hex()[:16]}…"
            )

            # --- Phase 4: issue approver's send cap ----------------------
            print("\n# Phase 4 — issue approver send capability")
            approver_cap = yutha.Capability(
                spec_version="1.0.0",
                capability_id=secrets.token_bytes(16),
                swarm_id=swarm_id,
                issuer=yutha.Issuer.for_agent(approver_id),
                subject=approver_id,
                scope=yutha.Scope.for_action("envelope.send"),
                valid_from=yutha.Timestamp.now(),
                valid_until=FAR_FUTURE,
            )
            cap_id, issue_receipt = await wrappers["approver"].client.capability.issue(approver_cap)
            print(
                f"  approver cap id={cap_id.digest.hex()[:16]}… "
                f"issuance receipt={issue_receipt.digest.hex()[:16]}…"
            )

            # Bind the sender helpers now that the cap exists.
            approver_authorize = build_approver_authorize(
                wrappers["approver"], approver_cap, treasury_id
            )
            approver_holder["authorize"] = approver_authorize
            supervisor_authorize = build_supervisor_authorize(wrappers["supervisor"], treasury_id)
            supervisor_holder["authorize"] = supervisor_authorize

            classifier_dispatch = build_classifier_dispatch(
                wrappers["classifier"], approver_id, supervisor_id
            )

            # --- Phase 5: happy path ($250 invoice) ----------------------
            #
            # classifier → approver → treasury. The approver's
            # task_factory schedules the authorize-payment send on the
            # dispatch loop; we then wait for treasury to log receipt.
            print(
                f"\n# Phase 5 — happy path (${cast(int, HAPPY_INVOICE['amount_cents']) / 100:,.2f})"
            )
            await classifier_dispatch(HAPPY_INVOICE)
            await wait_for_kind_delta(
                wrappers["classifier"].client,
                "envelope.deliver",
                before["envelope.deliver"],
                expected_delta=2,  # classifier→approver + approver→treasury
                timeout_seconds=5.0,
            )
            print("  ✓ approver authorized; treasury observed payment")

            # --- Phase 6: escalation path ($50,000 invoice) --------------
            #
            # classifier → supervisor → treasury. The supervisor's
            # task_factory schedules the authorize_payment send tagged
            # with supervisor_approved. The constitution permits the
            # over_cap send because the supervisor's framework is not
            # the gated one.
            print(
                f"\n# Phase 6 — escalation (${cast(int, LARGE_INVOICE['amount_cents']) / 100:,.2f})"
            )
            await classifier_dispatch(LARGE_INVOICE)
            await wait_for_kind_delta(
                wrappers["classifier"].client,
                "envelope.deliver",
                before["envelope.deliver"],
                expected_delta=4,  # 2 more (classifier→supervisor + supervisor→treasury)
                timeout_seconds=5.0,
            )
            print("  ✓ supervisor authorized; treasury observed payment")

            # --- Phase 7: bypass attempt #1 ------------------------------
            #
            # Approver calls its own authorize tool with
            # TAG_AMOUNT_OVER_CAP — i.e. the exact combination the
            # constitution forbids. The Send RPC raises
            # ConstitutionDenied with the deny_reason from the Cedar
            # forbid rule.
            print("\n# Phase 7 — approver bypass attempt #1")
            denied_1 = await _attempt_bypass(approver_authorize, LARGE_INVOICE)
            assert denied_1.deny_reason == "forbid_rule_matched", (
                f"expected forbid_rule_matched, got {denied_1.deny_reason!r}"
            )
            print(f"  ✓ denied: {denied_1}")

            # --- Phase 8: bypass attempt #2 → enforcement.detect ---------
            print("\n# Phase 8 — approver bypass attempt #2 (trips enforcement.detect)")
            denied_2 = await _attempt_bypass(approver_authorize, LARGE_INVOICE)
            assert denied_2.deny_reason == "forbid_rule_matched"
            print(f"  ✓ denied: {denied_2}")

            # --- Phase 9: poll for detect → coach → quarantine ----------
            #
            # See the analogous Phase 9 in code_review.py for the
            # rationale on polling the first three stages now and
            # evict separately after the post-quarantine cap-check.
            print("\n# Phase 9 — poll for detect → coach → quarantine")
            for stage in (
                "enforcement.detect",
                "enforcement.coach",
                "enforcement.quarantine",
            ):
                await wait_for_kind_delta(
                    wrappers["approver"].client, stage, before[stage], expected_delta=1
                )
                print(f"  ✓ {stage} landed")

            # --- Phase 10: cap-check denies WHILE quarantined -----------
            print("\n# Phase 10 — verify quarantine denies approver cap-check")
            check_outcome = await wrappers["approver"].client.capability.check(
                approver_cap,
                yutha.ActionDescriptor(action_kind="envelope.send"),
            )
            assert not check_outcome.permitted, (
                "quarantined approver should be denied even on a still-valid cap"
            )
            assert check_outcome.deny_reason == "subject_quarantined", (
                f"expected subject_quarantined, got {check_outcome.deny_reason!r}"
            )
            print(f"  ✓ cap-check denied with reason={check_outcome.deny_reason}")

            # --- Phase 11: wait for evict --------------------------------
            print("\n# Phase 11 — wait for enforcement.evict")
            await wait_for_kind_delta(
                wrappers["approver"].client,
                "enforcement.evict",
                before["enforcement.evict"],
                expected_delta=1,
            )
            print("  ✓ enforcement.evict landed")

            # --- Phase 12: snapshot delta + report ----------------------
            print("\n# Phase 12 — audit-trail delta")
            after = await query_audit(wrappers["approver"].client, kinds)
            delta = {k: after[k] - before[k] for k in kinds}
            for k in kinds:
                marker = "✓" if delta[k] == EXPECTED_AUDIT_DELTA[k] else "✗"
                print(f"  {marker} {k:<28} +{delta[k]:<2} (expected +{EXPECTED_AUDIT_DELTA[k]})")
            return delta
    finally:
        for wrapper in wrappers.values():
            try:
                await wrapper.client.close()
            except Exception:
                pass


async def _attempt_bypass(
    authorize: Callable[[dict[str, Any], list[str]], Awaitable[yutha.Hash]],
    invoice: dict[str, Any],
) -> yutha.ConstitutionDenied:
    """Drive one approver bypass attempt and return the structured
    deny. Catches ``CapabilityDenied`` separately so a misconfigured
    cap surfaces as a clear test failure rather than masking as a
    constitution deny."""
    try:
        await authorize(invoice, [TAG_AMOUNT_OVER_CAP])
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
    """Convenience: derive + print the operator pubkey from the
    bootstrap seed. Used to pipe into ``--operator-public-key`` on
    the control plane invocation."""
    _, _, _, seed = load_bootstrap_identity_from_env()
    _, op_public_key = derive_operator_identity(seed)
    print(op_public_key.value.hex())


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--print-operator-pubkey":
        _print_operator_pubkey()
        return
    delta = asyncio.run(run_ap_invoice())
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

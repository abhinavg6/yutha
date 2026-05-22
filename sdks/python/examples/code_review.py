"""Code-review crew — Python + LangGraph end-to-end demo.

A reviewer agent classifies pull-request review requests by file
path; non-sensitive PRs route to an auto-fix agent that applies the
patch; security-sensitive PRs route to a human-approver agent.

The active constitution forbids any envelope tagged with BOTH
``patch_applied`` and ``security_sensitive`` — i.e. *"auto-fix must
not claim to have patched a security-sensitive file."* Two bypass
attempts cross the enforcement rule's threshold and trip the
four-stage enforcement loop (detect → coach → quarantine → evict).
After quarantine fires, the auto-fix agent's send capability
denies with ``subject_quarantined``, even though the capability
itself was never revoked.

This is the first runnable Python demo that exercises the
constitution + enforcement layer end-to-end over gRPC, in the same
shape as the Rust S4 conformance scenario but framed for a
developer audience (PRs and security-tagged paths rather than
sentinel payload schemas).

Running locally
---------------

The demo and the server must agree on the swarm_id and on the
operator's public key. The bootstrap-seed handshake from S1 is
reused — both sides derive everything from a shared 32-byte seed.

1. Mint a seed once per run and start the control plane in OPEN
   admission mode with the matching operator public key. ::

       export YUTHA_BOOTSTRAP_SEED=$(python -c \\
           'import secrets; print(secrets.token_hex(32))')

       cargo run -p yutha-control-plane -- \\
           --admission-mode open \\
           --operator-public-key $(python sdks/python/examples/code_review.py --print-operator-pubkey)

   (The ``--print-operator-pubkey`` subcommand below derives the
   pubkey from ``YUTHA_BOOTSTRAP_SEED`` without running the full
   demo — handy for plugging into the server invocation.)

2. With the same seed exported in this shell, run this script ::

       python sdks/python/examples/code_review.py

What the demo exercises
-----------------------

* Three fresh agents register themselves into a clean swarm
  (``reviewer``, ``auto_fix``, ``human_approver``).
* An operator client activates a custom code-review constitution
  carrying the four-stage enforcement rule.
* The reviewer's two-node LangGraph classifies each incoming PR by
  file path and dispatches to the right downstream agent.
* The auto-fix agent's outbound send is gated by a server-side
  capability check via the ``@capability_required`` decorator —
  identical pattern to S1.
* Two bypass attempts (``patch_applied + security_sensitive``)
  produce ``constitution.evaluate.deny`` receipts and trip the
  enforcement loop. The script polls the audit log for the four
  stage receipts to land.
* A post-quarantine ``capability.check`` confirms that the cap
  layer is consulting the engine's quarantine state — auto-fix's
  still-valid send cap returns ``deny`` with reason
  ``subject_quarantined``.
* The audit-trail delta is queried and compared to the expected
  shape — every consequential action in the demo leaves a receipt.

The ``run_code_review()`` coroutine returns the delta dict so an
optional pytest wrapper could re-use it without forking the body.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import sys
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

import yutha
from yutha.langgraph import CapabilityDenied, YuthaAgent, capability_required
from yutha.models.constitution import Constitution

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

SERVER_ADDR = os.environ.get("YUTHA_GRPC_ADDR", "127.0.0.1:50051")

# Far-future expires_at sentinel. Open-mode admission rejects passports
# without expires_at; we set one that obviously outlasts the demo run.
FAR_FUTURE = yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62)

# Per-stage wall-clock budget for the enforcement chain. The active
# constitution's rule schedules coach 1s after detect, quarantine 1s
# after coach, evict 1s after quarantine — with the scheduler's
# ~1s tick on top. 15s is generous and leaves headroom for slow CI.
ENFORCEMENT_STAGE_TIMEOUT_SECONDS = 15.0
ENFORCEMENT_POLL_INTERVAL_SECONDS = 0.25

# -----------------------------------------------------------------------------
# Constitution (Cedar source + engine config)
# -----------------------------------------------------------------------------
#
# The Cedar policy keys on `context.tags` — a `Set<String>` carried on
# every SendEnvelope evaluation. The forbid rule fires when an envelope
# is tagged BOTH `security_sensitive` AND `patch_applied`:
#
#   * reviewer sends `review_request` tagged `security_sensitive` to
#     the human approver — forbid rule does NOT match (no
#     `patch_applied` tag); the permit-all fallback fires.
#   * auto-fix sends `patch_applied` to the reviewer for a README
#     typo (no `security_sensitive` tag) — forbid rule does NOT
#     match; permits.
#   * auto-fix sends `patch_applied` AND `security_sensitive` — the
#     bypass we're guarding against — forbid rule matches; denies.
#
# Annotating the policy with `@id(...)` pins its identity in the
# `constitution.evaluate.deny` receipt's evidence so an operator
# auditing the log can trace each deny to a named rule.
_CODE_REVIEW_CEDAR_SOURCE = """\
@id("no-security-patches-from-auto-fix")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
) when {
    context.tags.contains("security_sensitive") &&
    context.tags.contains("patch_applied")
};

permit (principal, action, resource);
"""

# Single enforcement rule covering all four stages with 1s cooldowns
# so the full chain runs in seconds rather than minutes. Shape
# matches `forbid_constitution` in `yutha.testing` and the Rust
# S4 fixture in `scenarios/s4_enforcement_loop.rs`.
#
# `count_threshold: 2` means two denies within `time_window: 60s`
# fire `enforcement.detect`. `require_countersign: false` waives
# the supervisor-tier countersign that the canonical-actions spec
# requires by default on `enforcement.evict` — this demo doesn't
# stand up a supervisor agent, and the waiver keeps the chain
# self-contained.
_CODE_REVIEW_ENGINE_CONFIG_YAML = """\
schema_version: "1.1.0"
predicates: []
scoring_rules: []
procedures: []
enforcement_rules:
  - name: security_tag_bypass_chain
    detect:
      trigger:
        receipt_kind: constitution.evaluate.deny
      count_threshold: 2
      time_window: 60s
      group_by: principal
    coach:
      cooldown: 1s
      guidance_template: "Auto-fix may not patch security-sensitive files"
    quarantine:
      escalate_after: 1s
    evict:
      escalate_after: 1s
      require_countersign: false
    severity: high
"""


def build_code_review_constitution(swarm_id: yutha.SwarmId) -> Constitution:
    """Build the code-review demo's constitution.

    Inlined here (rather than tucked behind a ``yutha.testing``
    helper) so the demo file is self-describing — the rule that
    governs the swarm sits next to the agents it governs."""
    return Constitution(
        spec_version="1.0.0",
        schema_version="1.1.0",
        constitution_version="1.0.0",
        parent_version=None,
        swarm_id=swarm_id,
        cedar_source=_CODE_REVIEW_CEDAR_SOURCE,
        engine_config_yaml=_CODE_REVIEW_ENGINE_CONFIG_YAML,
        issued_at=yutha.Timestamp.now(),
    )


# -----------------------------------------------------------------------------
# Bootstrap identity (mirrors S1)
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

    Uses ``sha256(seed || 0x03)[:32]`` as the operator's private-key
    seed — the ``0x03`` byte separates this stream from the
    bootstrap-identity ones (``0x01`` agent_id, ``0x02`` swarm_id)
    so a leak of one derivation can't pivot to another."""
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
            "32-byte hex seed the control plane was started with. Run:\n"
            "    export YUTHA_BOOTSTRAP_SEED=$(python -c "
            "'import secrets; print(secrets.token_hex(32))')\n"
            "    cargo run -p yutha-control-plane -- --admission-mode open "
            "--operator-public-key <derived-pubkey>\n"
            "    python sdks/python/examples/code_review.py"
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
    # 3 fresh agents register themselves.
    "agent.register": 3,
    # The operator activates the code-review constitution once.
    "constitution.activate": 1,
    # 3 successful sends: reviewer→auto_fix, auto_fix→reviewer
    # (patch_applied), reviewer→human_approver.
    "envelope.send": 3,
    "envelope.deliver": 3,
    # Constitution-check runs on every Send. 3 successful sends pass;
    # 2 bypass attempts (auto_fix's patch_applied + security_sensitive)
    # are denied.
    "constitution.evaluate.pass": 3,
    "constitution.evaluate.deny": 2,
    # Auto-fix is issued an envelope.send capability.
    "capability.issue": 1,
    # Three of auto_fix's sends are cap-gated: the happy-path
    # patch_applied + the two bypass attempts. The cap is valid on
    # all three (cap-check runs BEFORE constitution-check); the
    # constitution layer is what denies the bypasses.
    "capability.check.pass": 3,
    # After quarantine fires, the demo explicitly re-checks
    # auto_fix's cap; the cap layer's QuarantineSource consults the
    # engine and denies with `subject_quarantined`.
    "capability.check.deny": 1,
    # The four stages of the enforcement loop.
    "enforcement.detect": 1,
    "enforcement.coach": 1,
    "enforcement.quarantine": 1,
    "enforcement.evict": 1,
}

# The cast — 1:1 with what registers in Phase 1. Framework labels
# describe the agent's role; the constitution policy is keyed on
# envelope tags, not framework, so these are free-form.
CAST: list[tuple[str, str]] = [
    ("reviewer", "code-review-reviewer"),
    ("auto_fix", "code-review-auto-fix"),
    ("human_approver", "code-review-human-approver"),
]

# Two PRs the reviewer fans out + one bypass file the auto-fix
# agent will try to "patch" against the constitution's wishes.
HAPPY_PR = ("Fix a typo in the README header.", "README.md")
SENSITIVE_PR = ("Rotate the bootstrap signing key.", "crates/yutha-crypto/keys.rs")
BYPASS_FILE_PATH = "crates/yutha-crypto/keys.rs"

# Tag the reviewer puts on every classified PR to signal sensitivity.
SECURITY_SENSITIVE_TAG = "security_sensitive"
# Tag the auto-fix agent puts on every "I applied a patch" envelope.
PATCH_APPLIED_TAG = "patch_applied"
# Demo-wide tag so audit queries can filter for this run.
DEMO_TAG = "code-review-demo"


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
        owner=f"yutha-demo:code-review:{name}",
        framework=framework,
        framework_version="1.0.0",
        accepted_constitution_version="1.0.0",
        tier=yutha.PassportTier.MINIMAL,
        issued_at=yutha.Timestamp.now(),
        expires_at=FAR_FUTURE,
    ).sign(signing_key)


# -----------------------------------------------------------------------------
# Reviewer classifier graph (LangGraph)
# -----------------------------------------------------------------------------


class ReviewerState(TypedDict, total=False):
    """State threaded through the reviewer's classify → dispatch graph.

    Marked ``total=False`` so each node returns only the keys it
    populates; LangGraph merges each node's return into the running
    state."""

    pr_text: str
    file_path: str
    is_sensitive: bool
    destination_agent_id: yutha.AgentId
    send_receipt_id: yutha.Hash


# Hard-coded directory prefixes the reviewer treats as
# security-sensitive. A real implementation would lift this from
# CODEOWNERS / a policy file; for the demo a fixed tuple keeps the
# classifier deterministic (matches s1's keyword-rules approach).
SECURITY_SENSITIVE_PREFIXES: tuple[str, ...] = (
    "crates/yutha-crypto/",
    "crates/yutha-capability/",
    "spec/",
    "contracts/",
)


def classify_pr(state: ReviewerState) -> ReviewerState:
    """Tag a PR as sensitive if its file path lives under any of
    the configured security-sensitive prefixes."""
    path = state["file_path"]
    is_sensitive = any(path.startswith(p) for p in SECURITY_SENSITIVE_PREFIXES)
    return {"is_sensitive": is_sensitive}


def build_reviewer_graph(
    reviewer_agent: YuthaAgent,
    auto_fix_id: yutha.AgentId,
    human_approver_id: yutha.AgentId,
) -> Any:
    """Compile the reviewer's classify → dispatch graph.

    The reviewer's sends are NOT cap-gated in this demo (no
    ``capability_id`` is presented). Only auto-fix's outbound
    sends are cap-gated — see :func:`build_auto_fix_send`."""

    async def dispatch(state: ReviewerState) -> ReviewerState:
        is_sensitive = state["is_sensitive"]
        dest = human_approver_id if is_sensitive else auto_fix_id
        tags = [DEMO_TAG, "review_request"]
        if is_sensitive:
            tags.append(SECURITY_SENSITIVE_TAG)
        payload = f"FILE: {state['file_path']}\n\n{state['pr_text']}".encode()
        receipt = await reviewer_agent.send(
            recipient=yutha.Recipient.for_agent(dest),
            performative=yutha.Performative.REQUEST_ACTION,
            payload=payload,
            payload_schema_id="type.yutha.dev/v1/Text",
            tags=tags,
        )
        return {"destination_agent_id": dest, "send_receipt_id": receipt}

    graph: StateGraph = StateGraph(ReviewerState)
    graph.add_node("classify_pr", classify_pr)
    graph.add_node("dispatch", dispatch)
    graph.add_edge(START, "classify_pr")
    graph.add_edge("classify_pr", "dispatch")
    graph.add_edge("dispatch", END)
    return graph.compile()


# -----------------------------------------------------------------------------
# Auto-fix send helpers (LangGraph node, cap-gated)
# -----------------------------------------------------------------------------


def build_auto_fix_send(
    auto_fix_agent: YuthaAgent,
    auto_fix_cap: yutha.Capability,
    reviewer_id: yutha.AgentId,
) -> Callable[[bytes, list[str]], Awaitable[yutha.Hash]]:
    """Return an async function that sends a ``patch_applied``
    envelope from auto-fix to the reviewer.

    The send is wrapped with ``@capability_required`` so every
    outbound send hits a server-side capability check before the
    envelope is signed and shipped. Constitution-check runs
    server-side AFTER cap-check, so a valid cap + a forbidden tag
    combination still produces a ``constitution.evaluate.deny``."""

    @capability_required(
        auto_fix_agent.client,
        auto_fix_cap,
        action_kind="envelope.send",
    )
    async def send_patch_applied(payload: bytes, extra_tags: list[str]) -> yutha.Hash:
        tags = [DEMO_TAG, PATCH_APPLIED_TAG, *extra_tags]
        return await auto_fix_agent.send(
            recipient=yutha.Recipient.for_agent(reviewer_id),
            performative=yutha.Performative.INFORM,
            payload=payload,
            payload_schema_id="type.yutha.dev/v1/Text",
            tags=tags,
        )

    return send_patch_applied


# -----------------------------------------------------------------------------
# Audit-trail helpers
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
    """Poll the receipt store until the count of ``kind`` receipts
    has grown by at least ``expected_delta``. Used for the four
    enforcement-stage receipts whose timing depends on the
    server-side scheduler tick + the configured cooldowns."""
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


async def run_code_review(server_addr: str = SERVER_ADDR) -> dict[str, int]:
    """Run the code-review demo end-to-end against ``server_addr``.

    Returns the audit-trail delta keyed by action_kind."""
    print(f"# code-review crew demo · server={server_addr}")

    # --- bootstrap identity (used for swarm_id binding + pre-snapshot) ---
    bootstrap_key, bootstrap_agent_id, swarm_id, seed = load_bootstrap_identity_from_env()
    print(f"# swarm_id={swarm_id.value.hex()} (from YUTHA_BOOTSTRAP_SEED)")

    op_signing_key, op_public_key = derive_operator_identity(seed)
    print(f"# operator pubkey (pass as --operator-public-key): {op_public_key.value.hex()}")

    # --- Phase 0: pre-flow audit snapshot ---
    # Taken BEFORE any demo state lands so the delta calculation
    # works against a server that already hosts receipts from prior
    # runs of S1, S4, or this demo itself.
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

    def logger_handler(name: str) -> EnvelopeHandler:
        async def handler(
            _agent: YuthaAgent,
            envelope: yutha.Envelope,
            _deliver_id: yutha.Hash,
        ) -> None:
            received[name].append(envelope)
            print(f"  [{name}] recv {len(envelope.payload)}B tags={list(envelope.tags)}")

        return handler

    handlers: dict[str, EnvelopeHandler] = {
        "reviewer": logger_handler("reviewer"),
        "auto_fix": logger_handler("auto_fix"),
        "human_approver": logger_handler("human_approver"),
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
            print(f"  registered {name:<15} receipt={short}")

        reviewer = agent_handles["reviewer"]
        auto_fix = agent_handles["auto_fix"]
        auto_fix_id = identities["auto_fix"][1]
        human_approver_id = identities["human_approver"][1]
        reviewer_id = identities["reviewer"][1]

        # --- start dispatch loops --------------------------------------
        print("\n# Phase 2 — start dispatch loops")
        async with AsyncExitStack() as stack:
            for ag in agent_handles.values():
                await stack.enter_async_context(ag)
            print("  all three agents subscribed")

            # --- Phase 3: operator activates the constitution ---------
            #
            # The operator client uses a separate bearer-token variant
            # tied to the operator's Ed25519 key. ConstitutionService.
            # Activate is an operator-only RPC; agent bearers can't
            # call it.
            print("\n# Phase 3 — operator activates code-review constitution")
            constitution = build_code_review_constitution(swarm_id)
            async with yutha.YuthaClient.connect_as_operator(
                server_addr,
                operator_id="yutha-demo:code-review:operator",
                swarm_id=swarm_id,
                operator_signing_key=op_signing_key,
            ) as op_client:
                activated = await op_client.constitution.activate(constitution)
            # `ActivatedConstitution` carries the content-address + the
            # activate-receipt hash; the version field lives on the
            # `Constitution` artifact we just sent up.
            print(
                f"  constitution_hash={activated.constitution_hash.digest.hex()[:16]}… "
                f"version={constitution.constitution_version} "
                f"activate_receipt={activated.activate_receipt.digest.hex()[:16]}…"
            )

            # --- Phase 4: issue auto-fix's send capability ------------
            print("\n# Phase 4 — issue auto-fix send capability")
            auto_fix_cap = yutha.Capability(
                spec_version="1.0.0",
                capability_id=secrets.token_bytes(16),
                swarm_id=swarm_id,
                issuer=yutha.Issuer.for_agent(auto_fix_id),
                subject=auto_fix_id,
                scope=yutha.Scope.for_action("envelope.send"),
                valid_from=yutha.Timestamp.now(),
                valid_until=FAR_FUTURE,
            )
            cap_id, issue_receipt = await auto_fix.client.capability.issue(auto_fix_cap)
            print(
                f"  auto-fix cap id={cap_id.digest.hex()[:16]}… "
                f"issuance receipt={issue_receipt.digest.hex()[:16]}…"
            )

            # Build the cap-gated send helper now that we have the cap.
            send_patch_applied = build_auto_fix_send(auto_fix, auto_fix_cap, reviewer_id)

            # Reviewer's graph doesn't depend on the cap (its sends
            # aren't cap-gated), but constructing it after Phase 4
            # keeps the demo's narrative tidy.
            reviewer_graph = build_reviewer_graph(reviewer, auto_fix_id, human_approver_id)

            # --- Phase 5: happy-path PR (README typo) ----------------
            #
            # Reviewer classifies HAPPY_PR as non-sensitive, dispatches
            # to auto_fix. Auto_fix's handler logs receipt; we then
            # explicitly drive auto_fix's send-patch-applied back to
            # the reviewer to close the loop.
            print("\n# Phase 5 — happy path (README typo)")
            await reviewer_graph.ainvoke({"pr_text": HAPPY_PR[0], "file_path": HAPPY_PR[1]})
            # Wait for auto_fix to actually receive the dispatch.
            await _wait_for_envelope(received, "auto_fix", expected=1)
            patch_receipt = await send_patch_applied(
                f"PATCH_APPLIED: {HAPPY_PR[1]}".encode(),
                extra_tags=[],
            )
            print(f"  auto-fix → reviewer patch_applied receipt={patch_receipt.digest.hex()[:16]}…")
            await _wait_for_envelope(received, "reviewer", expected=1)

            # --- Phase 6: sensitive PR routes to human approver ------
            print("\n# Phase 6 — sensitive PR (crypto file) routes to human")
            await reviewer_graph.ainvoke({"pr_text": SENSITIVE_PR[0], "file_path": SENSITIVE_PR[1]})
            await _wait_for_envelope(received, "human_approver", expected=1)
            # Auto-fix MUST NOT have been hit — the reviewer's classifier
            # routes sensitive PRs straight to the human approver.
            assert len(received["auto_fix"]) == 1, (
                "sensitive PR should not have been routed to auto-fix; "
                f"auto_fix received {len(received['auto_fix'])} envelopes total"
            )

            # --- Phase 7: bypass attempt #1 --------------------------
            #
            # Auto-fix decides to send `patch_applied + security_sensitive`
            # anyway — the exact combination the constitution forbids.
            # The Send RPC raises ConstitutionDenied with the structured
            # deny_reason from the Cedar forbid rule.
            print("\n# Phase 7 — bypass attempt #1 (patch_applied + security_sensitive)")
            denied_1 = await _attempt_bypass(send_patch_applied, BYPASS_FILE_PATH)
            assert denied_1.deny_reason == "forbid_rule_matched", (
                f"expected forbid_rule_matched, got {denied_1.deny_reason!r}"
            )
            print(f"  ✓ denied: {denied_1}")

            # --- Phase 8: bypass attempt #2 → enforcement.detect fires
            print("\n# Phase 8 — bypass attempt #2 (threshold trips enforcement.detect)")
            denied_2 = await _attempt_bypass(send_patch_applied, BYPASS_FILE_PATH)
            assert denied_2.deny_reason == "forbid_rule_matched"
            print(f"  ✓ denied: {denied_2}")

            # --- Phase 9: poll for detect → coach → quarantine ------
            #
            # detect fires on the 2nd deny; coach 1s later; quarantine
            # 1s after coach. Add the scheduler tick (~1s) + slow-CI
            # slack — hence the 15s per-stage budget. We poll only the
            # first three stages here so the cap-check in Phase 10
            # lands while auto-fix is still in quarantine (not yet
            # evicted). The S4 Python integration test follows the
            # same intra-quarantine order; matches the spec's
            # "quarantine state lingers post-evict" semantic but
            # avoids depending on it.
            print("\n# Phase 9 — poll for detect → coach → quarantine")
            for stage in (
                "enforcement.detect",
                "enforcement.coach",
                "enforcement.quarantine",
            ):
                await wait_for_kind_delta(auto_fix.client, stage, before[stage], expected_delta=1)
                print(f"  ✓ {stage} landed")

            # --- Phase 10: cap-check denies WHILE quarantined --------
            #
            # The cap itself was never revoked; the cap layer's
            # QuarantineSource consults the engine on every check and
            # denies while the agent is quarantined. F10g's spec
            # reason is `subject_quarantined`. Quarantine state
            # lingers post-evict per RFC 0013 §4.2, so this would
            # also pass after evict — landing the check here is the
            # conservative choice.
            print("\n# Phase 10 — verify quarantine denies cap-check")
            check_outcome = await auto_fix.client.capability.check(
                auto_fix_cap,
                yutha.ActionDescriptor(action_kind="envelope.send"),
            )
            assert not check_outcome.permitted, (
                "quarantined auto-fix should be denied even on a still-valid cap"
            )
            assert check_outcome.deny_reason == "subject_quarantined", (
                f"expected subject_quarantined, got {check_outcome.deny_reason!r}"
            )
            print(f"  ✓ cap-check denied with reason={check_outcome.deny_reason}")

            # --- Phase 11: wait for evict to land --------------------
            #
            # Evict is scheduled 1s after quarantine fires. Polling
            # for it last keeps the demo's narrative linear: detect →
            # coach → quarantine → (check while quarantined) → evict.
            print("\n# Phase 11 — wait for enforcement.evict")
            await wait_for_kind_delta(
                auto_fix.client,
                "enforcement.evict",
                before["enforcement.evict"],
                expected_delta=1,
            )
            print("  ✓ enforcement.evict landed")

            # --- Phase 12: snapshot delta and report -----------------
            print("\n# Phase 12 — audit-trail delta")
            after = await query_audit(auto_fix.client, kinds)
            delta = {k: after[k] - before[k] for k in kinds}
            for k in kinds:
                marker = "✓" if delta[k] == EXPECTED_AUDIT_DELTA[k] else "✗"
                print(f"  {marker} {k:<28} +{delta[k]:<2} (expected +{EXPECTED_AUDIT_DELTA[k]})")
            return delta
    finally:
        # Belt-and-braces channel close — YuthaClient.close is
        # documented as idempotent.
        for ag in agent_handles.values():
            try:
                await ag.client.close()
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


async def _attempt_bypass(
    send_patch_applied: Callable[[bytes, list[str]], Awaitable[yutha.Hash]],
    file_path: str,
) -> yutha.ConstitutionDenied:
    """Drive one bypass attempt and return the structured deny.

    Wraps the assertion that ``ConstitutionDenied`` raises rather
    than ``CapabilityDenied`` — cap-check runs first server-side,
    and on the bypass attempts the cap is still valid, so the deny
    we expect comes from the constitution layer."""
    try:
        await send_patch_applied(
            f"PATCH_APPLIED: {file_path}".encode(),
            extra_tags=[SECURITY_SENSITIVE_TAG],
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
    """Convenience subcommand: derive + print the operator pubkey
    from ``YUTHA_BOOTSTRAP_SEED`` so callers can pipe it straight
    into the control-plane invocation:

        cargo run -p yutha-control-plane -- --admission-mode open \\
            --operator-public-key \\
            $(python sdks/python/examples/code_review.py --print-operator-pubkey)
    """
    _, _, _, seed = load_bootstrap_identity_from_env()
    _, op_public_key = derive_operator_identity(seed)
    print(op_public_key.value.hex())


def main() -> None:
    # `--print-operator-pubkey` is the only flag the demo accepts;
    # everything else is env-driven (YUTHA_BOOTSTRAP_SEED,
    # YUTHA_GRPC_ADDR).
    if len(sys.argv) == 2 and sys.argv[1] == "--print-operator-pubkey":
        _print_operator_pubkey()
        return
    delta = asyncio.run(run_code_review())
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

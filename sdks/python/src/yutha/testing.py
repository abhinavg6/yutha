"""Test scaffolding for downstream users of the Yutha SDK.

Anything in this module is intended for use from test code — the SDK's
own tests and any consumer's integration suites. Production code paths
should NOT import from here.

What's here today:

  * :func:`permissive_constitution` — build a minimal but valid
    constitution that lets every action through. Useful for tests that
    need the constitution gate to be open (RFC 0010 §3.6 / F10's
    SendEnvelope gate) without exercising any specific policy.

Why a public submodule. The constitution layer (RFCs 0010-0013) makes
``ConstitutionService.Activate`` a *required* step for any swarm that
wants ``EnvelopeService.Send`` to work. Test authors hitting a fresh
control plane all need the same "any-policy-will-do" artifact; baking
it into the SDK avoids every downstream re-deriving it from the
canonical schema.
"""

from __future__ import annotations

from yutha.identity import SwarmId, Timestamp
from yutha.models.constitution import Constitution

# The smallest Cedar policy the F6 loader accepts: one permit rule with
# no `when` clause and unconstrained principal / action / resource. Cedar
# requires at least one policy in a policy set, and Strict-mode
# validation against ``/spec/constitution/schema.cedarschema`` passes
# this form (it matches every action declared in the namespace).
#
# Keep this in lockstep with the Rust-side smallest-fixture in
# ``crates/yutha-cedar-plus/src/loader.rs::tests::empty_constitution_loads``.
_PERMISSIVE_CEDAR_SOURCE = "permit (principal, action, resource);"

# Engine config with every list explicitly empty. Equivalent to
# ``EngineConfig::default()`` on the Rust side — emitted verbatim
# (rather than via ``yaml.dump``) so:
#
#   1. The form is stable across pyyaml versions.
#   2. The shape matches what the Rust loader's serde derives expect
#      (``#[serde(default)]`` on every field would also accept ``{}``,
#      but the explicit form documents intent for readers of failing
#      diff output).
_PERMISSIVE_ENGINE_CONFIG_YAML = """\
schema_version: "1.1.0"
predicates: []
scoring_rules: []
procedures: []
enforcement_rules: []
"""


def permissive_constitution(
    swarm_id: SwarmId,
    *,
    constitution_version: str = "1.0.0",
    spec_version: str = "1.0.0",
    schema_version: str = "1.1.0",
) -> Constitution:
    """Build a minimal "permit everything" constitution for ``swarm_id``.

    The resulting artifact:

      * passes the F6 load-time validator (structural checks,
        ``@<name>`` predicate resolution, Cedar Validator in Strict
        mode, load-time bound enforcement per RFC 0012 §3.3);
      * authorizes every Cedar action declared in the canonical
        schema, so the post-F10 SendEnvelope gate stops returning
        ``FAILED_PRECONDITION`` once it's been activated;
      * carries no scoring rules, procedures, or enforcement rules —
        the enforcement loop has nothing to fire on, which is exactly
        what test fixtures generally want.

    Parameters
    ----------
    swarm_id
        Bind the constitution to this swarm. Must match the swarm the
        control plane is running.
    constitution_version
        Semver for the constitution artifact itself. Defaults to
        ``"1.0.0"`` (genesis). Override when authoring amendment
        scenarios.
    spec_version
        Spec version of the constitution wire format. Defaults to
        ``"1.0.0"``.
    schema_version
        Cedar+ schema version the policy was authored against. The
        v1.1 canonical schema is what the F6 loader pins to by
        default; tests authored against a different schema version
        will need to pass it explicitly here.

    Returns
    -------
    Constitution
        Ready to hand to
        :meth:`yutha.ConstitutionAPI.activate`.
    """
    return Constitution(
        spec_version=spec_version,
        schema_version=schema_version,
        constitution_version=constitution_version,
        parent_version=None,  # Genesis — operators amending pass a real parent.
        swarm_id=swarm_id,
        cedar_source=_PERMISSIVE_CEDAR_SOURCE,
        engine_config_yaml=_PERMISSIVE_ENGINE_CONFIG_YAML,
        issued_at=Timestamp.now(),
    )


_FORBID_CEDAR_SOURCE = """\
@id("no-forbidden-payloads")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
) when {
    context.payload_schema_id == "type.yutha.dev/v1/Forbidden"
};

permit (principal, action, resource);
"""

# Same shape as the Rust S4 scenario's engine config in
# crates/yutha-conformance/src/scenarios/s4_enforcement_loop.rs. Short
# cooldowns so the chain runs in seconds, not minutes; tests should
# poll with bounded retries rather than fixed sleeps to absorb the
# scheduler-tick (1s) jitter.
_FORBID_ENGINE_CONFIG_YAML = """\
schema_version: "1.1.0"
predicates: []
scoring_rules: []
procedures: []
enforcement_rules:
  - name: forbidden_payload_chain
    detect:
      trigger:
        receipt_kind: constitution.evaluate.deny
      count_threshold: 2
      time_window: 60s
      group_by: principal
    coach:
      cooldown: 1s
      guidance_template: "Stop sending forbidden payloads"
    quarantine:
      escalate_after: 1s
    evict:
      escalate_after: 1s
      require_countersign: false
    severity: high
"""


def forbid_constitution(
    swarm_id: SwarmId,
    *,
    constitution_version: str = "1.0.0",
    spec_version: str = "1.0.0",
    schema_version: str = "1.1.0",
) -> Constitution:
    """Build a constitution that denies forbidden payloads + permits
    everything else + drives the four-stage enforcement chain on
    forbidden-payload denies.

    Used by the Python S4 integration test (and any downstream test
    that wants to exercise the constitution + enforcement layer
    end-to-end via gRPC). Distinct from
    :func:`permissive_constitution` in two ways:

      * The Cedar source carries a `forbid` rule on
        ``payload_schema_id == "type.yutha.dev/v1/Forbidden"``. Sends
        with that sentinel deny; everything else hits the trailing
        ``permit (principal, action, resource)`` and passes.
      * The engine config carries a single
        ``enforcement_rules`` entry covering all four stages
        (detect → coach → quarantine → evict) with 1s cooldowns —
        short enough that an integration test can drive the full
        chain in a handful of seconds.

    Because the permit-all fallback still fires for non-forbidden
    payloads, activating this constitution doesn't break tests that
    only send permitted traffic. Quarantine state is keyed per agent
    so the forbidden-sender getting quarantined doesn't affect other
    agents on the same swarm.
    """
    return Constitution(
        spec_version=spec_version,
        schema_version=schema_version,
        constitution_version=constitution_version,
        parent_version=None,
        swarm_id=swarm_id,
        cedar_source=_FORBID_CEDAR_SOURCE,
        engine_config_yaml=_FORBID_ENGINE_CONFIG_YAML,
        issued_at=Timestamp.now(),
    )


# Support-queue refund-cap constitution. Mirrors the Rust S5 fixture
# at /spec/constitution/canonical-schemas/v1.1.0/examples/
# support-queue-refund-cap.{cedar,yaml}.
#
# The Cedar source references `Yutha::SupportQueue::Action::"IssueRefund"`
# — the server MUST be running with the matching workload extension
# loaded (`yutha-control-plane --workload support-queue`), otherwise
# Activate rejects the constitution at the Cedar Validator step.
_SUPPORT_QUEUE_REFUND_CAP_CEDAR = """\
@id("refund-cap-requires-supervisor")
forbid (
    principal,
    action == Yutha::SupportQueue::Action::"IssueRefund",
    resource
) when {
    context.refund_amount_cents > 10000 &&
    principal.passport_tier != "verifiable"
};

permit (principal, action, resource);
"""

_SUPPORT_QUEUE_REFUND_CAP_ENGINE_CONFIG_YAML = """\
schema_version: "1.1.0"
predicates: []
scoring_rules: []
procedures: []
enforcement_rules: []
"""


def support_queue_refund_cap_constitution(
    swarm_id: SwarmId,
    *,
    constitution_version: str = "1.0.0",
    spec_version: str = "1.0.0",
    schema_version: str = "1.1.0",
) -> Constitution:
    """Build the F14/S5 worked-example constitution for the Python
    side.

    Cedar policy forbids ``IssueRefund`` over 10000 cents unless the
    principal is verifiable-tier; everything else passes the trailing
    permit-all rule. Engine config is empty.

    Requires the control plane to have been started with
    ``--workload support-queue`` so the Cedar Validator recognizes
    the ``Yutha::SupportQueue`` namespace at activation time. Without
    that, ``ConstitutionAPI.activate`` returns ``INVALID_ARGUMENT``.
    """
    return Constitution(
        spec_version=spec_version,
        schema_version=schema_version,
        constitution_version=constitution_version,
        parent_version=None,
        swarm_id=swarm_id,
        cedar_source=_SUPPORT_QUEUE_REFUND_CAP_CEDAR,
        engine_config_yaml=_SUPPORT_QUEUE_REFUND_CAP_ENGINE_CONFIG_YAML,
        issued_at=Timestamp.now(),
    )


__all__ = [
    "forbid_constitution",
    "permissive_constitution",
    "support_queue_refund_cap_constitution",
]

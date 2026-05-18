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


__all__ = ["permissive_constitution"]

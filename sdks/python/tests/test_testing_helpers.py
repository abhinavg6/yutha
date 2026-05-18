"""Tests for the public ``yutha.testing`` submodule.

These run cold (no live server) — they only assert that
:func:`yutha.testing.permissive_constitution` produces a structurally
sound :class:`yutha.Constitution`. Whether the server's load-time
validator actually accepts it is exercised by the F11d integration
fixture against a running control plane.
"""

from __future__ import annotations

import yutha
from yutha.testing import permissive_constitution


def test_permissive_constitution_defaults() -> None:
    """Default invocation yields a genesis constitution bound to the
    swarm, with versions matching the v1.1 canonical schema."""
    swarm_id = yutha.SwarmId.new()
    c = permissive_constitution(swarm_id)

    assert isinstance(c, yutha.Constitution)
    assert c.swarm_id == swarm_id
    assert c.parent_version is None  # Genesis.
    assert c.spec_version == "1.0.0"
    assert c.schema_version == "1.1.0"
    assert c.constitution_version == "1.0.0"
    # Cedar source must be non-empty and contain a ``permit`` rule —
    # the F6 loader rejects empty policy sets.
    assert "permit" in c.cedar_source
    # Engine config YAML carries the matching schema_version pin and
    # explicit-empty lists per the helper's docstring contract.
    assert 'schema_version: "1.1.0"' in c.engine_config_yaml
    assert "scoring_rules: []" in c.engine_config_yaml
    assert "enforcement_rules: []" in c.engine_config_yaml


def test_permissive_constitution_round_trips_through_proto() -> None:
    """The helper's output must survive the proto round-trip — anything
    else means the fixture can't be sent over the wire to Activate."""
    c = permissive_constitution(yutha.SwarmId.new())
    back = yutha.Constitution.from_proto(c.to_proto())
    assert back == c


def test_permissive_constitution_overrides_version() -> None:
    """Callers building amendment-test scenarios can override the
    constitution_version. The other defaults stay put."""
    swarm_id = yutha.SwarmId.new()
    c = permissive_constitution(swarm_id, constitution_version="2.0.0")
    assert c.constitution_version == "2.0.0"
    assert c.spec_version == "1.0.0"  # Unchanged.
    assert c.schema_version == "1.1.0"


def test_permissive_constitution_distinct_swarms_distinct_constitutions() -> None:
    """Two calls with different swarm_ids produce constitutions that
    differ in both ``swarm_id`` and (by proto-content addressing
    semantics) their canonical bytes."""
    a = permissive_constitution(yutha.SwarmId.new())
    b = permissive_constitution(yutha.SwarmId.new())
    assert a.swarm_id != b.swarm_id
    assert a.to_proto().SerializeToString() != b.to_proto().SerializeToString()

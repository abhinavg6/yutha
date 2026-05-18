"""Constitution ergonomic model.

Mirrors ``/spec/control-plane/v1.proto`` ``Constitution`` and the Rust
``yutha_cedar_plus::Constitution`` in
``crates/yutha-cedar-plus/src/constitution.rs``.

A constitution artifact carries:

  * The Cedar+ schema version it was authored against (pinned at load
    time per RFC 0010 §3.5).
  * The constitution's own semver, bumped on each amendment.
  * The Cedar policy source (stock Cedar ``permit`` / ``forbid`` rules
    plus named predicates per extensions.md §2.4).
  * The engine-config YAML — scoring rules, procedures, enforcement
    rules per extensions.md §2.2 / §3.2 / enforcement.md §10.
  * Lineage (parent-version content-address, swarm binding, issued-at
    timestamp).

The control plane content-addresses the deterministically-serialized
proto bytes (per ``/spec/README.md`` §5); the wire shape *is* the
canonical shape. Unlike Passport / Envelope / Capability, the
constitution is not actor-signed — the operator's bearer token on the
``Activate`` RPC is the authority proof. There is consequently no
``sign()`` / ``verify_signature()`` on this model.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from yutha._proto import common_pb2
from yutha._proto.control_plane import v1_pb2 as cp_pb2
from yutha.identity import Hash, SwarmId, Timestamp


class Constitution(BaseModel):
    """A constitution artifact, ready to hand to ``ConstitutionService.Activate``.

    Construct directly when you have the four authored fields
    (``cedar_source``, ``engine_config_yaml``, ``schema_version``,
    ``constitution_version``) and the binding ``swarm_id`` plus
    ``issued_at``. For test scaffolding, see
    :func:`yutha.testing.permissive_constitution`.

    ``parent_version`` is unset on the swarm's genesis constitution and
    populated with the prior constitution's content-address on every
    subsequent amendment.
    """

    model_config = ConfigDict(frozen=True)

    # Yutha spec version of the artifact format itself (e.g. "1.0.0").
    # The wire field is ``common.Version`` (a versioned semver string);
    # we surface it as a plain ``str`` to match the other models'
    # convention.
    spec_version: str

    # Canonical Cedar+ schema version this constitution was authored
    # against (e.g. "1.1.0"). The evaluator pins schema loading to this
    # version per RFC 0010 §3.5.
    schema_version: str

    # Constitution semver. Bumped on each amendment (RFC 0013 §7).
    constitution_version: str

    # Content-address of the parent constitution, if any. ``None`` for
    # the swarm's genesis constitution.
    parent_version: Hash | None = None

    # The swarm this constitution governs.
    swarm_id: SwarmId

    # Cedar policy source — stock Cedar ``permit`` / ``forbid`` rules
    # plus ``@predicate name(...)`` named predicates from extensions.md
    # §2.4. Stored as canonical text; the evaluator parses on load.
    cedar_source: str

    # Engine-side config (scoring rules, procedures, enforcement
    # rules), YAML-serialized per extensions.md / enforcement.md §10.
    # YAML over wire is v1.1's authoring-ergonomics choice; protobuf
    # is the long-term canonical machine-readable form.
    engine_config_yaml: str

    # When the constitution was authored. The
    # ``constitution.activate`` receipt's ``occurred_at`` is recorded
    # separately by the control plane.
    issued_at: Timestamp = Field(default_factory=Timestamp.now)

    @classmethod
    def from_proto(cls, p: cp_pb2.Constitution) -> Constitution:
        """Inverse of :meth:`to_proto`. ``parent_version`` resolves to
        ``None`` when the proto's field is unset (proto3 default is the
        zero-value Hash, which a sender either explicitly omits or
        fills with zeros; we treat both as "no parent" — genesis
        constitutions hit this path).
        """
        parent: Hash | None
        if p.HasField("parent_version"):
            parent = Hash.from_proto(p.parent_version)
        else:
            parent = None
        return cls(
            spec_version=p.spec_version.value,
            schema_version=p.schema_version,
            constitution_version=p.constitution_version,
            parent_version=parent,
            swarm_id=SwarmId.from_proto(p.swarm_id),
            cedar_source=p.cedar_source,
            engine_config_yaml=p.engine_config_yaml,
            issued_at=Timestamp.from_proto(p.issued_at),
        )

    def to_proto(self) -> cp_pb2.Constitution:
        out = cp_pb2.Constitution(
            spec_version=common_pb2.Version(value=self.spec_version),
            schema_version=self.schema_version,
            constitution_version=self.constitution_version,
            swarm_id=self.swarm_id.to_proto(),
            cedar_source=self.cedar_source,
            engine_config_yaml=self.engine_config_yaml,
            issued_at=self.issued_at.to_proto(),
        )
        if self.parent_version is not None:
            out.parent_version.CopyFrom(self.parent_version.to_proto())
        return out


__all__ = ["Constitution"]

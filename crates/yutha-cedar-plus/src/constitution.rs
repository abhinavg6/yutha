//! The `Constitution` artifact — Cedar policy file + engine config bundle.
//!
//! A constitution carries everything the evaluator needs to make decisions
//! for a swarm: the Cedar policy text (stock Cedar `permit` / `forbid`
//! rules), the engine config (named predicates, scoring rules, procedures,
//! enforcement rules per [`engine_config`](crate::engine_config)), plus
//! metadata (schema version, constitution version, signing chain back to
//! genesis).
//!
//! The artifact is content-addressed (`Hash`) and signature-chained — see
//! [`/spec/constitution/rationale.md`](../../../spec/constitution/rationale.md)
//! §5 for the schema-evolution semantics. v1.1 evaluators load constitutions
//! at the pinned `schema_version` and refuse policies referencing attributes
//! not declared at that version.

use yutha_core::{Hash, SpecVersion, SwarmId, Timestamp};

use crate::engine_config::EngineConfig;

/// A signed, versioned constitution artifact.
///
/// Currently a stub — F5 scaffolds the type; F6 fills in load-from-bytes,
/// signature verification, schema-version pinning, and the validation
/// pass that runs Cedar's `Validator` against the policy set.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Constitution {
    /// Content-address of this constitution. Set when loading from
    /// canonical bytes.
    pub constitution_hash: Hash,

    /// Yutha spec version of the constitution artifact format. This is
    /// separate from `schema_version`; the artifact format and the
    /// canonical Cedar+ schema evolve independently.
    pub spec_version: SpecVersion,

    /// The canonical Cedar+ schema version this constitution was
    /// authored against (e.g. `"1.1.0"`). The evaluator MUST load
    /// schemas at this pinned version per RFC 0010 §3.5.
    pub schema_version: String,

    /// Constitution version (semver string). Bumped at each amendment.
    pub constitution_version: String,

    /// Content-address of the parent constitution, or `None` for the
    /// swarm's genesis constitution.
    pub parent_version: Option<Hash>,

    /// The swarm this constitution governs. Constitutions are
    /// single-swarm in v1.1 — federation (Phase 4) is a separate spec.
    pub swarm_id: SwarmId,

    /// The Cedar policy source — `permit` / `forbid` rules, named
    /// predicates (`@predicate name(args) { body }` convention from
    /// extensions.md §2.4). Stored as the canonical text; the
    /// evaluator parses on load.
    pub cedar_source: String,

    /// The engine-side config (scoring rules, procedures, enforcement
    /// rules). MAY be empty — a constitution with only Cedar gating
    /// and no engine-side features is valid.
    pub engine_config: EngineConfig,

    /// When this constitution was authored.
    pub issued_at: Timestamp,
}

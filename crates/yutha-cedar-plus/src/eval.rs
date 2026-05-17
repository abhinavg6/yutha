//! Evaluation request / response shapes and the `ConstitutionEvaluator`
//! trait — the entry point for runtime evaluation.
//!
//! See [`/spec/constitution/evaluation.md`](../../../spec/constitution/evaluation.md)
//! §1.1-§1.2 for the request/response contract this implements.

use std::collections::HashMap;

use async_trait::async_trait;
use yutha_core::{AgentId, Hash, Timestamp};

use crate::constitution::Constitution;
use crate::error::Result;

/// A single evaluation request, synthesized by the control plane before
/// invoking the evaluator.
///
/// Per evaluation.md §1.1, the control plane is responsible for building
/// `entity_snapshot` upfront — the evaluator never reaches back to the
/// registry, capability store, or memory layer mid-evaluation. This is
/// what makes evaluation pure and deterministic.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct EvaluationRequest {
    /// The constitution this request evaluates against. Pinned by the
    /// swarm's active constitution at evaluation time.
    pub constitution_hash: Hash,

    /// Canonical schema version the constitution pinned at bootstrap.
    pub schema_version: String,

    /// The Cedar action being attempted (e.g. `"SendEnvelope"`). The
    /// evaluator wraps this as `Action::"<kind>"` per Cedar's
    /// convention for action entities.
    pub action_kind: String,

    /// The acting agent. Evaluator wraps as `Yutha::Agent::"<id>"` —
    /// v1.1 only admits Agent as a principal type.
    pub principal_id: AgentId,

    /// The resource the action targets. Structured because resource
    /// type varies per action (e.g. `SendEnvelope`'s resource is an
    /// Agent or Envelope; `ReadMemory`'s is a Memory). The caller
    /// builds the appropriate `EntityUid` per the schema's
    /// `appliesTo.resource` declaration for the action.
    pub resource_uid: EntityUid,

    /// Per-action context attributes per the schema's action `context`
    /// shape. Always includes `current_wall_clock` and
    /// `current_time_unix_ns` per evaluation.md §1.1.
    pub context_attrs: HashMap<String, serde_json::Value>,

    /// The read-only entity snapshot the evaluator may reference. The
    /// concrete type lives in the Layer A integration (F7) where we
    /// build a `cedar_policy::Entities` from it; F5 leaves it opaque.
    pub entity_snapshot: EntitySnapshot,

    /// Wall-clock at evaluation time (RFC 3339). Read once per
    /// evaluation per evaluation.md §3.1.
    pub current_wall_clock: String,

    /// Monotonic-since-epoch nanoseconds. Admitted for in-eval
    /// arithmetic; never used for scheduling.
    pub current_time_unix_ns: u64,
}

/// The read-only entity store the evaluator may reference.
///
/// Per evaluation.md §1.1, the control plane synthesizes this BEFORE
/// the evaluation call — the evaluator never reaches back to the
/// registry, capability store, or memory layer mid-evaluation. The
/// snapshot is plain data; F7's evaluator serializes it to Cedar's
/// JSON entity format and parses it through `cedar_policy::Entities`.
///
/// The public surface deliberately doesn't expose `cedar_policy`
/// types so callers can construct snapshots without taking a direct
/// dependency on Cedar.
#[derive(Debug, Clone, Default)]
pub struct EntitySnapshot {
    /// Every entity the policy may reference. Each carries its UID,
    /// attribute map, and parent-entity references for Cedar's `in`
    /// hierarchy.
    pub entities: Vec<EntityRecord>,
}

impl EntitySnapshot {
    /// The entity count — what the sandbox bound checks against.
    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }
}

/// One entity in the [`EntitySnapshot`].
#[derive(Debug, Clone)]
pub struct EntityRecord {
    /// The entity's UID (type + id).
    pub uid: EntityUid,
    /// Attribute map. Values use `serde_json::Value` for forward-
    /// compatibility with Cedar's evolving wire format; the evaluator
    /// converts to Cedar's internal value types at parse time.
    pub attrs: std::collections::HashMap<String, serde_json::Value>,
    /// Parent UIDs for Cedar's `entity in [Parent]` hierarchy (e.g. an
    /// Agent's Swarm membership).
    pub parents: Vec<EntityUid>,
}

/// A Cedar entity identifier: type name + opaque id.
///
/// Equivalent to `cedar_policy::EntityUid` but expressed in plain
/// Rust types so [`EvaluationRequest`] / [`EntityRecord`] don't leak
/// the cedar dependency to callers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntityUid {
    /// Cedar type name, e.g. `"Yutha::Agent"` or `"Action"`.
    pub entity_type: String,
    /// Opaque id, e.g. the UUIDv7 string form of an `AgentId`.
    pub entity_id: String,
}

impl EntityUid {
    /// Construct a UID from type + id parts.
    pub fn new(entity_type: impl Into<String>, entity_id: impl Into<String>) -> Self {
        Self {
            entity_type: entity_type.into(),
            entity_id: entity_id.into(),
        }
    }
}

/// Composite evaluation outcome — the decision, evidence, and any
/// procedure effects fired in the same handler.
///
/// Per evaluation.md §1.2.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct EvaluationOutcome {
    /// The decision.
    pub decision: Decision,

    /// Present iff `decision == Deny`. RFC 0012 §3.3 enum.
    pub deny_reason: Option<String>,

    /// Cedar rule ids that contributed to the decision. Empty for
    /// default-deny.
    pub matched_rule_ids: Vec<String>,

    /// Scoring contributions from `prefer`-style scoring rules. Empty
    /// when no scoring rule applied (or scoring is not declared).
    pub score_contributions: Vec<ScoreContribution>,

    /// Sum of `score_contributions`. `Some` iff `score_contributions`
    /// is non-empty.
    pub total_score: Option<Score>,

    /// Procedure-lifecycle effects fired in the same evaluation
    /// (procedure.enter, procedure.transition, procedure.escalate).
    pub procedure_effects: Vec<ProcedureEffect>,

    /// SHA-256 over the canonical serialization of `(matched_rule_ids,
    /// score_contributions, procedure_effects, input_attribute_digest)`
    /// — see evaluation.md §9.
    pub evidence_digest: Hash,

    /// When the evaluation completed. Used by the receipt emitter.
    pub decided_at: Timestamp,
}

/// Final decision from a constitution evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request is permitted to proceed.
    Permit,
    /// The request is refused.
    Deny,
}

/// One scoring rule's contribution to the total score.
#[derive(Debug, Clone)]
pub struct ScoreContribution {
    /// The scoring rule's `name`.
    pub rule_id: String,
    /// The rule's `score` field — fixed-precision Decimal so the sum
    /// across rules is deterministic.
    pub score: Score,
}

/// Stub Decimal newtype. F5 leaves this as a string-wrapped placeholder
/// so the public API can compile; F7 replaces it with whatever
/// `cedar-policy` exposes for its fixed-precision Decimal type (Cedar
/// 3.x has a Decimal extension; the exact public re-export shape
/// varies by minor version).
///
/// **Determinism note.** Whatever this becomes in F7 MUST be fixed-
/// precision (no floating point) — see evaluation.md §4. The string
/// representation here is for the canonical bytes of receipt evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Score(pub String);

/// A procedure-lifecycle effect fired during the same evaluation. The
/// receipt emitter uses these to wire `causal_predecessors` between
/// the eval receipt and the procedure receipts.
#[derive(Debug, Clone)]
pub struct ProcedureEffect {
    /// One of: `"procedure.enter"`, `"procedure.transition"`,
    /// `"procedure.escalate"`.
    pub action_kind: String,
    /// The instance id this effect targets — see RFC 0011 §3.3 for
    /// how instance ids are content-addressed.
    pub instance_id: String,
}

/// The evaluator surface. Implementations load a constitution once,
/// then field many requests against it.
///
/// F5 defines the trait; F7 (Layer A delegation to cedar-policy) and
/// F8 (engine-side scoring + procedure logic) supply the implementation.
#[async_trait]
pub trait ConstitutionEvaluator: Send + Sync {
    /// Evaluate a single request against the currently-loaded
    /// constitution. Per evaluation.md §1.3 the call order is
    /// schema-load → sandbox-bounds-check → Layer A → Layer B →
    /// receipt-emission; this trait method covers Layer A + Layer B.
    /// Receipt emission lives in the calling control-plane handler so
    /// the receipt store integration stays single-sourced.
    async fn evaluate(&self, request: EvaluationRequest) -> Result<EvaluationOutcome>;

    /// Activate a new constitution. Replaces the currently-loaded
    /// constitution (if any). Implementations MUST run the load-time
    /// validations from RFC 0012 §3.3 and RFC 0011 §3.5 before the
    /// activation lands.
    async fn activate(&self, constitution: Constitution) -> Result<Hash>;
}

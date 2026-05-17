//! The engine-config artifact: scoring rules, procedures, enforcement
//! rules + named predicates.
//!
//! Per the RFC 0011 §3 engine-construct decision, none of these constructs
//! are Cedar+ syntax — they're declared in a separate artifact alongside
//! the Cedar policy file, parsed as YAML/protobuf, and consumed by the
//! constitution engine. The engine calls back into Cedar by name to
//! evaluate the predicate bodies (which ARE stock Cedar expressions).
//!
//! Wire format: YAML for human authoring (this module is serde-driven),
//! protobuf for content-addressing and machine-readable canonical bytes
//! (added when the wire-format vector pass lands).
//!
//! Schemas mirrored from:
//! - [`/spec/constitution/extensions.md`](../../../spec/constitution/extensions.md)
//!   §2 (scoring) and §3 (procedures)
//! - [`/spec/constitution/enforcement.md`](../../../spec/constitution/enforcement.md)
//!   §10 (enforcement rules)

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::eval::Score;

/// The full engine config — everything that lives outside the Cedar
/// policy file.
///
/// MAY be empty (a constitution with only Cedar gating and no engine-
/// side features is valid). Loaded from YAML/protobuf alongside the
/// Cedar source.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct EngineConfig {
    /// Schema version pin — same value as `Constitution.schema_version`
    /// duplicated here so the engine config is self-describing when
    /// distributed independently of its sibling Cedar file. The loader
    /// MUST verify the two pins agree.
    #[serde(default)]
    pub schema_version: String,

    /// Named predicate expressions (extensions.md §2.4). Each `expr` is
    /// a stock Cedar `when`-clause body. Referenced from scoring rules,
    /// procedures, and enforcement rules via the `@<name>` shorthand —
    /// resolved at constitution-load time by substitution.
    #[serde(default)]
    pub predicates: Vec<NamedPredicate>,

    /// Soft-preference scoring rules (RFC 0011 §2; extensions.md §2.2).
    #[serde(default)]
    pub scoring_rules: Vec<ScoringRule>,

    /// Bounded state-machine procedures (RFC 0011 §3; extensions.md §3.2).
    #[serde(default)]
    pub procedures: Vec<Procedure>,

    /// Receipt-stream pattern-matching enforcement rules (RFC 0013;
    /// enforcement.md §10).
    #[serde(default)]
    pub enforcement_rules: Vec<EnforcementRule>,
}

// =============================================================================
// Named predicates
// =============================================================================

/// A named Cedar expression that scoring rules, procedures, and
/// enforcement rules can reference by `@<name>` shorthand.
///
/// Per extensions.md §2.4: the `expr` is parsed by the engine at
/// constitution-load time using `cedar_policy::Expr::from_str` and
/// validated against the v1.1 schema. Resolution is by load-time
/// substitution — after the loader runs, a `@<name>` reference is
/// indistinguishable from an inlined expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedPredicate {
    /// Unique within the engine config.
    pub name: String,
    /// Stock Cedar expression body — same syntax as a `when` clause.
    pub expr: String,
}

// =============================================================================
// Scoring rules — RFC 0011 §2 / extensions.md §2.2
// =============================================================================

/// A scoring rule contributing a fixed-precision score to permitted
/// requests matching its head.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringRule {
    /// Unique within the engine config.
    pub name: String,
    /// Decimal weight. May be negative ("prefer not"); must not be zero.
    pub score: Score,
    /// Restricts which `(principal, action, resource)` tuples this
    /// rule applies to. Absent fields are wildcards (most rules gate
    /// on `action` only).
    #[serde(default)]
    pub head: ScoringHead,
    /// Cedar `when`-clause body. May reference named predicates via
    /// `@<name>` shorthand.
    pub when: String,
}

/// Head pattern for [`ScoringRule`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScoringHead {
    /// If present, the rule only applies when `request.principal_id`
    /// matches this entity UID. Cedar `EntityUid::Display` format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// If present, the rule only applies when `request.action_kind`
    /// matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// If present, the rule only applies when `request.resource_id`
    /// matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

// =============================================================================
// Procedures — RFC 0011 §3 / extensions.md §3.2
// =============================================================================

/// A bounded state machine. Transitions are gated by Cedar predicates;
/// timeouts fire on wall-clock advance. Instance state is reconstructable
/// from the receipt log (evaluation.md §6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Procedure {
    /// Unique within the engine config.
    pub name: String,
    /// Every fresh instance begins in this state.
    pub initial_state: String,
    /// Complete set of named states. Finite and statically declared.
    pub states: Vec<String>,
    /// Subset of `states` that have no outgoing transitions.
    pub terminal_states: Vec<String>,
    /// The request shape that opens a new procedure instance.
    pub trigger: ProcedureTrigger,
    /// State transitions.
    pub transitions: Vec<ProcedureTransition>,
    /// Map from state-name to escalation-target-procedure-name. When
    /// a timeout fires in the indexed state and no other transition
    /// has resolved the instance, the engine opens a fresh instance
    /// of the named procedure.
    #[serde(default)]
    pub on_timeout_escalate: HashMap<String, String>,
}

/// The pattern that triggers a procedure entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcedureTrigger {
    /// The Cedar action name (e.g. `"IssueRefund"`).
    pub action: String,
    /// A Cedar expression evaluated against the request context. May
    /// reference named predicates via `@<name>`. Absent → always-fire
    /// on matching action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
}

/// A single transition definition within a procedure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcedureTransition {
    /// Source state.
    pub from: String,
    /// Destination state.
    pub to: String,
    /// The Cedar action that fires this transition. Mutually exclusive
    /// with `on_timeout`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Cedar expression gating on the request's principal (the
    /// transition actor). Absent → any actor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_when: Option<String>,
    /// Duration string (e.g. `"1h"`, `"30s"`). Mutually exclusive with
    /// `action`. When set, the transition fires automatically when
    /// wall-clock advances past `entry_wall_clock + on_timeout`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_timeout: Option<String>,
}

// =============================================================================
// Enforcement rules — RFC 0013 / enforcement.md §10
// =============================================================================

/// A receipt-stream pattern that drives the four-stage enforcement loop
/// (detect → coach → quarantine → evict) plus reversal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementRule {
    /// Unique within the engine config.
    pub name: String,
    /// Stage 1: receipt-stream pattern that lands a `detect`.
    pub detect: DetectConfig,
    /// Stage 2: coaching feedback. `None` means skip directly from
    /// detect to quarantine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coach: Option<CoachConfig>,
    /// Stage 3: cap-check denial + new-issuance refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine: Option<QuarantineConfig>,
    /// Stage 4: drives `AdmissionService.OperatorRevoke` with cascade.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evict: Option<EvictConfig>,
    /// Per-stage reputation deltas. Overrides global defaults from
    /// enforcement.md §7.2.
    #[serde(default)]
    pub reputation_delta: HashMap<String, Score>,
    /// Reversal triggers.
    #[serde(default)]
    pub reverse: ReverseConfig,
    /// Operator-facing severity hint. Not consumed by the engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

/// Detect-stage config — the receipt-pattern trigger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectConfig {
    /// The receipt-stream pattern.
    pub trigger: DetectTrigger,
    /// Number of matching receipts within `time_window` that fire
    /// `detect`. Must be ≥ 1.
    pub count_threshold: u32,
    /// Window duration. Format: standard duration strings (`"10m"`,
    /// `"1h"`, etc.).
    pub time_window: String,
    /// Grouping. `"principal"` for per-agent counters; `"none"` for a
    /// single global counter.
    #[serde(default = "default_group_by")]
    pub group_by: String,
    /// If true, the engine considers receipts emitted under earlier
    /// constitution versions. Default false (rules don't fire on
    /// historical data).
    #[serde(default)]
    pub historical: bool,
}

fn default_group_by() -> String {
    "principal".to_string()
}

/// The receipt-pattern trigger for detect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectTrigger {
    /// Required. The `action_kind` of receipts to match.
    pub receipt_kind: String,
    /// Optional filter on `deny_reason` (for `constitution.evaluate.deny`
    /// receipts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    /// Optional filter on `forbid_rule_id` (which Cedar forbid rule
    /// matched).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forbid_rule_id: Option<String>,
}

/// Coach-stage config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoachConfig {
    /// Cooldown after `detect` lands before `coach` fires. Format:
    /// duration string (`"30s"`).
    pub cooldown: String,
    /// Operator-defined guidance template included in the coaching
    /// envelope's payload. May reference receipt-evidence fields
    /// via `{name}` placeholders.
    pub guidance_template: String,
}

/// Quarantine-stage config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    /// Cooldown after `coach` lands before `quarantine` fires.
    pub escalate_after: String,
    /// Optional auto-expiry. Absent → indefinite until explicit
    /// `enforcement.reverse`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_after: Option<String>,
    /// Optional compliance check that reverses the quarantine before
    /// expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_check: Option<ComplianceCheck>,
}

/// Compliance check for [`QuarantineConfig::compliance_check`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheck {
    /// "No more of this `forbid_rule_id` for the configured window."
    pub no_more_of: String,
    /// Window duration.
    #[serde(rename = "for")]
    pub for_duration: String,
}

/// Evict-stage config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvictConfig {
    /// Cooldown after `quarantine` before `evict` fires.
    pub escalate_after: String,
    /// Whether a supervisor countersign is required. Default true per
    /// enforcement.md §5.2. Constitutions MAY waive per rule for
    /// `severity: critical` cases.
    #[serde(default = "default_require_countersign")]
    pub require_countersign: bool,
}

fn default_require_countersign() -> bool {
    true
}

/// Reverse-stage config — conditions under which a non-terminal stage
/// auto-reverses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReverseConfig {
    /// Conditions; reverse fires when ANY hold.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auto_when: Vec<String>,
}

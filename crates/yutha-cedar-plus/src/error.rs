//! Error type for the constitution stack.
//!
//! Every fallible call in `yutha-cedar-plus` returns
//! [`Result<T, CedarPlusError>`](Result). Errors are grouped by which layer
//! produced them (loader, Cedar Layer A, engine Layer B, sandbox), with
//! the exact `deny_reason` from RFC 0012 §5.2 / RFC 0010 §3.6 attached as
//! the leaf variant where applicable.

use thiserror::Error;

/// All error variants surfaced by the constitution stack.
///
/// The `Evaluation*` variants map 1:1 onto `constitution.evaluate.deny`
/// receipt `deny_reason` values; the `Load*` variants map onto the
/// `constitution.activate` refusal reasons.
#[derive(Debug, Error)]
pub enum CedarPlusError {
    // --- Loader errors -------------------------------------------------------
    /// The constitution artifact failed to parse as YAML / Cedar.
    #[error("constitution parse error: {0}")]
    Parse(String),

    /// The constitution's pinned schema version is not supported by this
    /// evaluator build.
    #[error("schema version {0} not supported")]
    SchemaVersionUnsupported(String),

    /// A `scoring_rules` entry's `when` expression failed Cedar schema
    /// validation.
    #[error("scoring rule {rule} invalid: {detail}")]
    InvalidScoringRule {
        /// The offending rule's `name`.
        rule: String,
        /// Underlying detail (Cedar validator message, etc.).
        detail: String,
    },

    /// A `procedures` entry has an unreachable state, ambiguous transition,
    /// or other structural defect caught at load time.
    #[error("procedure {procedure} invalid: {detail}")]
    InvalidProcedure {
        /// The offending procedure's `name`.
        procedure: String,
        /// Underlying detail.
        detail: String,
    },

    /// An `enforcement_rules` entry references an unknown receipt kind or
    /// a `forbid_rule_id` not present in the Cedar source.
    #[error("enforcement rule {rule} invalid: {detail}")]
    InvalidEnforcementRule {
        /// The offending rule's `name`.
        rule: String,
        /// Underlying detail.
        detail: String,
    },

    /// The Cedar policy set or engine config exceeded a Yutha-side
    /// load-time bound (policy count, policy depth, scoring rule count,
    /// procedure count).
    #[error("load-time bound exceeded: {0}")]
    LoadBoundExceeded(LoadBoundReason),

    // --- Evaluation errors (Layer A — stock cedar-policy) -------------------
    /// The request's shape doesn't match the schema (e.g. missing
    /// context field).
    #[error("request shape invalid: {0}")]
    RequestShapeInvalid(String),

    /// The request references an entity not present in the snapshot.
    #[error("entity unresolved: {0}")]
    EntityUnresolved(String),

    /// The constitution hash didn't resolve to a loaded constitution.
    #[error("constitution unresolved: {0}")]
    ConstitutionUnresolved(String),

    /// Layer A reported an evaluation error (attribute lookup failure,
    /// type mismatch, etc.) that's not categorized as a more specific
    /// variant above.
    #[error("evaluator internal error: {0}")]
    EvaluatorInternalError(String),

    // --- Evaluation errors (Layer B — engine sandbox bounds) ----------------
    /// A per-evaluation sandbox bound was exceeded at runtime (RFC 0012
    /// §5).
    #[error("evaluation bound exceeded: {0}")]
    EvaluationBoundExceeded(EvalBoundReason),

    // --- Engine internals ---------------------------------------------------
    /// Two procedure transitions matched the same `(from_state,
    /// action_kind)` at runtime — should be unreachable per the load-
    /// time validation in RFC 0011 §3.5.
    #[error("procedure transition ambiguous: instance {instance}, candidates {candidates:?}")]
    ProcedureTransitionAmbiguous {
        /// The open instance whose transitions conflicted.
        instance: String,
        /// The conflicting transition ids.
        candidates: Vec<String>,
    },

    /// IO or other infrastructural failure (file read, channel send, etc.).
    #[error("infrastructure error: {0}")]
    Infrastructure(String),
}

/// Reason kinds for [`CedarPlusError::LoadBoundExceeded`].
///
/// Map 1:1 onto the load-time `deny_reason` values from RFC 0012 §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBoundReason {
    /// Scoring rule count > configured cap.
    ScoringRuleCount,
    /// Procedure count > configured cap.
    ProcedureCount,
    /// Cedar policy count > configured cap.
    PolicyCount,
    /// Cedar policy max depth (per Cedar `Validator`) > Yutha-side cap.
    PolicyDepth,
}

impl std::fmt::Display for LoadBoundReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::ScoringRuleCount => "scoring_rule_count_exceeded",
            Self::ProcedureCount => "procedure_count_exceeded",
            Self::PolicyCount => "policy_count_exceeded",
            Self::PolicyDepth => "policy_depth_exceeded",
        };
        write!(f, "{s}")
    }
}

/// Reason kinds for [`CedarPlusError::EvaluationBoundExceeded`].
///
/// Map 1:1 onto the evaluation-time `deny_reason` values from RFC 0012
/// §5.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalBoundReason {
    /// Wall-clock evaluation time exceeded the per-action cap (10 ms for
    /// `SendEnvelope`, 100 ms for other actions per RFC 0012 §3.3 default).
    EvaluationTime,
    /// Entity snapshot exceeded the cap (default 1,000).
    EntityStoreSize,
    /// Open procedure instances examined per request exceeded the cap
    /// (default 100).
    OpenProcedureInstanceCount,
    /// Cedar's internal evaluation depth limit (64) was hit; should be
    /// unreachable for well-formed constitutions.
    EvaluationDepth,
}

impl std::fmt::Display for EvalBoundReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::EvaluationTime => "evaluation_time_exceeded",
            Self::EntityStoreSize => "entity_store_size_exceeded",
            Self::OpenProcedureInstanceCount => "open_procedure_instance_count_exceeded",
            Self::EvaluationDepth => "evaluation_depth_exceeded",
        };
        write!(f, "{s}")
    }
}

/// Convenience alias for the crate's primary `Result`.
pub type Result<T> = std::result::Result<T, CedarPlusError>;

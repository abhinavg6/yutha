//! Yutha constitution stack — Phase 2 substrate.
//!
//! This crate is the reference implementation of the constitution layer
//! specified in RFCs 0010–0013:
//!
//! - [RFC 0010](../../../spec/rfcs/0010-constitution-language-v1.md):
//!   base Cedar+ schema and constitution artifact shape.
//! - [RFC 0011](../../../spec/rfcs/0011-cedar-plus-extensions.md):
//!   engine-construct + schema-pattern capabilities (`prefer` scoring,
//!   `procedure` state machines, resource budgets, memory norms).
//! - [RFC 0012](../../../spec/rfcs/0012-evaluation-model-and-sandbox.md):
//!   two-layer evaluation contract (stock Cedar + engine), determinism
//!   guarantees, per-evaluation sandbox bounds.
//! - [RFC 0013](../../../spec/rfcs/0013-four-stage-enforcement-loop.md):
//!   detect → coach → quarantine → evict enforcement loop with reverse
//!   semantics, reputation dynamics, supervisor-tier countersign.
//!
//! # Architecture
//!
//! Constitution evaluation is two layers:
//!
//! 1. **Layer A** — stock [`cedar-policy`](https://crates.io/crates/cedar-policy)
//!    gating. Permit / forbid decisions over the Cedar policy file.
//!    We delegate to upstream; we do NOT extend Cedar's language.
//! 2. **Layer B** — the constitution engine (this crate). Runs after
//!    Layer A returns Permit. Evaluates scoring rules, fires procedure
//!    transitions, drives the enforcement loop.
//!
//! The engine reads from a separate **engine config** artifact
//! (YAML / protobuf) declaring scoring rules, procedures, and
//! enforcement rules. Cedar source stays pure stock Cedar; engine
//! configs reference Cedar predicates by name via the `@<name>`
//! convention (see [`engine_config`] and the named-predicate
//! description in [extensions.md §2.4](../../../spec/constitution/extensions.md)).
//!
//! # Layout
//!
//! - [`constitution`] — the signed, versioned constitution artifact.
//! - [`engine_config`] — scoring rules, procedures, enforcement rules,
//!   named predicates.
//! - [`eval`] — request/response types + the [`ConstitutionEvaluator`]
//!   trait surface.
//! - [`sandbox`] — per-evaluation resource bounds + bound-exceeded
//!   reasons.
//! - [`scoring`], [`procedure`], [`enforcement`] — engine subsystems
//!   (stub at F5; filled in by F7-F9).
//! - [`error`] — the crate's `Result` and error type.
//!
//! # Status
//!
//! **F5 scaffold.** The public surface and module skeleton compile. The
//! Layer A delegate, the engine eval logic, the procedure state machine
//! impl, and the enforcement-engine receipt subscriber are all `todo!()`
//! / stubbed and land in subsequent F-code stages.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod constitution;
pub mod enforcement;
pub mod engine_config;
pub mod error;
pub mod eval;
pub mod evaluator;
pub mod layer_b;
pub mod loader;
pub mod procedure;
pub mod sandbox;
pub mod scoring;
pub(crate) mod validate;

pub use constitution::Constitution;
pub use enforcement::{
    AgentSnapshot, AgentStage, BudgetSnapshot, EnforcementEffect, EnforcementEngine, ReceiptView,
};
pub use engine_config::{
    CoachConfig, ComplianceCheck, DetectConfig, DetectTrigger, EnforcementRule, EngineConfig,
    EvictConfig, NamedPredicate, Procedure, ProcedureTransition, ProcedureTrigger,
    QuarantineConfig, ReverseConfig, ScoringHead, ScoringRule,
};
pub use error::{CedarPlusError, EvalBoundReason, LoadBoundReason, Result};
pub use eval::{
    ConstitutionEvaluator, Decision, EntityRecord, EntitySnapshot, EntityUid, EvaluationOutcome,
    EvaluationRequest, ProcedureEffect, Score, ScoreContribution,
};
pub use evaluator::{CedarPlusEvaluator, PromoteShadowOutcome};
pub use loader::{
    canonical_schema_v1_1, canonical_schema_v1_1_with_extensions, parse_engine_config_yaml,
    workload_extension_by_name, ActivatedConstitution, ConstitutionLoader,
    WORKLOAD_CODE_REVIEW_V1_1, WORKLOAD_SUPPORT_QUEUE_V1_1,
};
pub use sandbox::SandboxConfig;

#[cfg(test)]
mod tests {
    use super::*;

    /// The crate's public surface compiles and the most-used types are
    /// constructible. Sentinel test — F7 / F8 / F9 add real coverage as
    /// the subsystems land.
    #[test]
    fn public_surface_compiles() {
        let _cfg = SandboxConfig::default();
        let _score = Score("1.5".into());
        let _engine_config = EngineConfig::default();
    }

    /// The engine config round-trips through YAML — covers the
    /// serde-driven loader's wire surface.
    #[test]
    fn engine_config_roundtrips_yaml() {
        let yaml = r#"
schema_version: "1.1.0"
predicates:
  - name: is_supervisor
    expr: 'principal.passport_tier == "supervisor"'
scoring_rules:
  - name: senior_for_sensitive
    score: "2.0"
    head:
      action: AssignCase
    when: '@is_supervisor'
"#;
        let parsed: EngineConfig = serde_yaml::from_str(yaml).expect("yaml parses");
        assert_eq!(parsed.schema_version, "1.1.0");
        assert_eq!(parsed.predicates.len(), 1);
        assert_eq!(parsed.predicates[0].name, "is_supervisor");
        assert_eq!(parsed.scoring_rules.len(), 1);
        assert_eq!(parsed.scoring_rules[0].name, "senior_for_sensitive");
        assert_eq!(parsed.scoring_rules[0].score, Score("2.0".into()));

        // Re-emit and parse again — basic determinism shape.
        let re_emitted = serde_yaml::to_string(&parsed).unwrap();
        let _: EngineConfig = serde_yaml::from_str(&re_emitted).expect("re-emitted yaml parses");
    }
}

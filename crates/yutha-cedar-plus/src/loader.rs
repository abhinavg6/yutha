//! Public loader API — turns raw constitution artifacts into validated,
//! ready-to-evaluate [`ActivatedConstitution`]s.
//!
//! Per [evaluation.md §1.3](../../../spec/constitution/evaluation.md)
//! steps 1-2: schema load + constitution load. The loader runs the
//! structural validators from [`crate::validate`] in fixed order, then
//! parses + validates the Cedar source with `cedar-policy`'s
//! `Validator`, then enforces the load-time bounds from RFC 0012 §3.3.
//!
//! Failure at any step short-circuits with the appropriate
//! [`CedarPlusError`] variant. On success, the returned
//! [`ActivatedConstitution`] is what the F7 evaluator runs against.

use std::sync::Arc;

use crate::constitution::Constitution;
use crate::engine_config::EngineConfig;
use crate::error::{CedarPlusError, Result};
use crate::sandbox::SandboxConfig;
use crate::validate;

/// A constitution that has passed all load-time validation and is ready
/// for runtime evaluation.
///
/// Holds the parsed `cedar_policy::PolicySet` (no re-parsing per
/// evaluation) plus the engine config in its resolved form
/// (`@<predicate>` references substituted; all Cedar expressions
/// parse-verified against the schema) plus a reference to the schema
/// the constitution was activated under (so the evaluator can build
/// requests + entities against it without re-loading per call) plus
/// the F8 [`LayerBArtifacts`] — synthesized stock-Cedar policy sets
/// that let the constitution engine reuse cedar-policy's `Authorizer`
/// to evaluate scoring rules, procedure triggers, and procedure
/// transitions.
#[derive(Debug)]
pub struct ActivatedConstitution {
    /// The constitution artifact this was activated from.
    pub constitution: Constitution,
    /// The parsed Cedar policy set, ready for `Authorizer::is_authorized`
    /// calls in F7.
    pub policy_set: cedar_policy::PolicySet,
    /// The Cedar schema the constitution was validated against. Shared
    /// via `Arc` so multiple concurrent evaluations can reference it
    /// without per-activation cloning.
    pub schema: Arc<cedar_policy::Schema>,
    /// The engine config with named-predicate references resolved.
    /// Distinct from `constitution.engine_config` (which carries the
    /// pre-resolution form for audit clarity).
    pub resolved_engine_config: EngineConfig,
    /// Synthesized stock-Cedar policy sets backing Layer B (scoring +
    /// procedures). Built at load time; the evaluator reuses
    /// `Authorizer` against them per request.
    pub layer_b: crate::layer_b::LayerBArtifacts,
    /// Count of Cedar policies (statement count). Recorded for
    /// observability and to support runtime fallback checks if the
    /// constitution somehow drifts past the load-time bound.
    pub policy_count: usize,
    /// The Yutha-side max policy depth, computed by [`crate::validate`]
    /// from the source. Compared against [`SandboxConfig::max_policy_depth_at_load`]
    /// at load time; recorded here for traceability.
    pub cedar_max_policy_depth: u32,
}

/// The constitution loader. Construct once with a Cedar schema + bound
/// configuration; reuse across many constitution loads.
///
/// Schema and bounds are immutable per-loader; swarms that change
/// either need a fresh loader. Operators reconfiguring bounds at
/// runtime should construct a new loader and use it for the next
/// activation.
pub struct ConstitutionLoader {
    schema: Arc<cedar_policy::Schema>,
    bounds: SandboxConfig,
}

impl ConstitutionLoader {
    /// Construct a loader with an explicit schema + bound configuration.
    pub fn new(schema: cedar_policy::Schema, bounds: SandboxConfig) -> Self {
        Self {
            schema: Arc::new(schema),
            bounds,
        }
    }

    /// Construct a loader with the given schema and the default bounds
    /// from [`SandboxConfig::default`] (per RFC 0012 §3.3, post-F3-
    /// tightening defaults).
    pub fn with_default_bounds(schema: cedar_policy::Schema) -> Self {
        Self::new(schema, SandboxConfig::default())
    }

    /// Access the underlying schema. Used by the evaluator to thread
    /// the schema into request/entity construction without re-loading.
    pub fn schema(&self) -> &Arc<cedar_policy::Schema> {
        &self.schema
    }

    /// Load and validate a constitution artifact. Returns an
    /// [`ActivatedConstitution`] ready for runtime evaluation.
    ///
    /// Validation order — failure at any step short-circuits:
    ///
    /// 1. Structural: name uniqueness across scoring/procedure/
    ///    enforcement/predicate; scoring-rule shape sanity; procedure
    ///    state-machine well-formedness; enforcement-rule receipt-kind
    ///    + threshold + duration sanity; escalation graph acyclicity.
    /// 2. Resolution: `@<predicate>` references substituted.
    /// 3. Load-time count bounds: scoring/procedure/policy counts
    ///    within the loader's [`SandboxConfig`].
    /// 4. Cedar parse + validate: PolicySet parses; Validator passes
    ///    in Strict mode.
    /// 5. Load-time policy-depth bound.
    /// 6. Cedar expressions in engine config: each `when` / `actor_when`
    ///    / `trigger.when` parses (and, future, validates against the
    ///    schema).
    pub fn load(&self, constitution: Constitution) -> Result<ActivatedConstitution> {
        // Stage 1: structural validators.
        validate::check_unique_names(&constitution.engine_config)?;
        validate::check_scoring_rules(&constitution.engine_config)?;
        validate::check_procedures(&constitution.engine_config)?;
        validate::check_enforcement_rules(&constitution.engine_config)?;

        // Stage 2: resolve `@<name>` references. After this pass, all
        // engine-config expressions are in their fully-inlined form.
        // We resolve in a clone so the original `constitution.engine_config`
        // retains the human-authored form for audit.
        let mut resolved_engine_config = constitution.engine_config.clone();
        validate::resolve_named_predicates(&mut resolved_engine_config)?;

        // Stage 3: load-time count bounds.
        validate::check_load_time_counts(&resolved_engine_config, &self.bounds)?;

        // Stage 4-5: cedar parse + validate + depth bound (rolled
        // together in [`validate::parse_and_validate_cedar`]).
        let parsed = validate::parse_and_validate_cedar(
            &self.schema,
            &constitution.cedar_source,
            &self.bounds,
        )?;

        // Stage 6: parse each engine-config Cedar expression against
        // the schema. F6 only verifies it parses; F7 wires the
        // schema-validation pass for these standalone expressions.
        for rule in &resolved_engine_config.scoring_rules {
            validate::parse_cedar_expression(&self.schema, &rule.when).map_err(|e| {
                CedarPlusError::InvalidScoringRule {
                    rule: rule.name.clone(),
                    detail: format!("when expression rejected: {e}"),
                }
            })?;
        }
        for proc in &resolved_engine_config.procedures {
            if let Some(w) = &proc.trigger.when {
                validate::parse_cedar_expression(&self.schema, w).map_err(|e| {
                    CedarPlusError::InvalidProcedure {
                        procedure: proc.name.clone(),
                        detail: format!("trigger.when rejected: {e}"),
                    }
                })?;
            }
            for t in &proc.transitions {
                if let Some(aw) = &t.actor_when {
                    validate::parse_cedar_expression(&self.schema, aw).map_err(|e| {
                        CedarPlusError::InvalidProcedure {
                            procedure: proc.name.clone(),
                            detail: format!(
                                "transition {:?}->{:?} actor_when rejected: {e}",
                                t.from, t.to
                            ),
                        }
                    })?;
                }
            }
        }

        // Stage 7: synthesize Layer B artifacts. Each scoring rule /
        // procedure trigger / procedure transition becomes a stock
        // Cedar `permit` policy in its own PolicySet, ready for the
        // F8 evaluator to call `Authorizer::is_authorized` against.
        // Pre-parsed at load time so per-evaluation work is bounded
        // (no per-call policy compilation).
        let layer_b = crate::layer_b::synthesize(&self.schema, &resolved_engine_config)?;

        // The original constitution moves into the result so callers
        // have both the raw artifact (for re-emit / audit) and the
        // activated form (for evaluation) without holding two copies
        // of the metadata.
        Ok(ActivatedConstitution {
            constitution,
            policy_set: parsed.policy_set,
            schema: Arc::clone(&self.schema),
            resolved_engine_config,
            layer_b,
            policy_count: parsed.policy_count,
            cedar_max_policy_depth: parsed.cedar_max_policy_depth,
        })
    }
}

/// Parse an engine config from a YAML string. Convenience around
/// `serde_yaml::from_str`; surfaces parse errors as
/// [`CedarPlusError::Parse`].
pub fn parse_engine_config_yaml(yaml: &str) -> Result<EngineConfig> {
    serde_yaml::from_str(yaml)
        .map_err(|e| CedarPlusError::Parse(format!("engine config YAML: {e}")))
}

/// Load the v1.1 canonical schema embedded at compile time.
///
/// The schema text is taken from `/spec/constitution/schema.cedarschema`
/// via `include_str!`. Callers that need a different schema version
/// (e.g. activating a constitution pinned at a future v1.2) construct
/// a `cedar_policy::Schema` themselves and pass it to the loader.
pub fn canonical_schema_v1_1() -> Result<cedar_policy::Schema> {
    canonical_schema_v1_1_with_extensions(&[])
}

/// Load the v1.1 canonical schema plus zero or more workload
/// extensions. Cedar 3.x supports multiple namespaces in a single
/// schema string, so the loader simply concatenates the base schema
/// with each extension (separated by newlines) and hands the result
/// to `Schema::from_cedarschema_str`.
///
/// Use the [`WORKLOAD_SUPPORT_QUEUE_V1_1`] / [`WORKLOAD_CODE_REVIEW_V1_1`]
/// constants for the workloads Yutha ships, or pass a custom Cedar
/// source string to load an operator-authored extension.
///
/// See `/spec/constitution/canonical-schemas/v1.1.0/README.md` for
/// the extension pattern + constraints.
pub fn canonical_schema_v1_1_with_extensions(extensions: &[&str]) -> Result<cedar_policy::Schema> {
    let base = include_str!("../../../spec/constitution/schema.cedarschema");
    let combined = if extensions.is_empty() {
        // Common case (the activation path most production swarms hit
        // when they're not yet using workload extensions). Avoid the
        // String allocation in the empty-extensions case.
        std::borrow::Cow::Borrowed(base)
    } else {
        let mut owned = String::with_capacity(
            base.len() + extensions.iter().map(|e| e.len() + 1).sum::<usize>(),
        );
        owned.push_str(base);
        for ext in extensions {
            owned.push('\n');
            owned.push_str(ext);
        }
        std::borrow::Cow::Owned(owned)
    };
    let (schema, _warnings) = cedar_policy::Schema::from_cedarschema_str(combined.as_ref())
        .map_err(|e| {
            CedarPlusError::Parse(format!(
                "v1.1 canonical schema + {} extension(s) failed to parse: {e}",
                extensions.len()
            ))
        })?;
    Ok(schema)
}

/// Embedded source of the `Yutha::SupportQueue` workload extension
/// shipped under
/// `/spec/constitution/canonical-schemas/v1.1.0/support-queue.cedarschema`.
/// Pass to [`canonical_schema_v1_1_with_extensions`] to load it.
pub const WORKLOAD_SUPPORT_QUEUE_V1_1: &str =
    include_str!("../../../spec/constitution/canonical-schemas/v1.1.0/support-queue.cedarschema");

/// Embedded source of the `Yutha::CodeReview` workload extension
/// shipped under
/// `/spec/constitution/canonical-schemas/v1.1.0/code-review.cedarschema`.
/// Pass to [`canonical_schema_v1_1_with_extensions`] to load it.
pub const WORKLOAD_CODE_REVIEW_V1_1: &str =
    include_str!("../../../spec/constitution/canonical-schemas/v1.1.0/code-review.cedarschema");

/// Resolve a workload-name string (`"support-queue"` / `"code-review"`)
/// to its embedded schema source. Returns `None` for unknown names —
/// the control plane uses this to translate operator-supplied
/// `--workload <name>` CLI args into schema sources without
/// hard-coding the mapping at the call site.
///
/// The accepted names match the file stems under
/// `/spec/constitution/canonical-schemas/v1.1.0/`; future workloads
/// shipped under that directory should land here too.
pub fn workload_extension_by_name(name: &str) -> Option<&'static str> {
    match name {
        "support-queue" => Some(WORKLOAD_SUPPORT_QUEUE_V1_1),
        "code-review" => Some(WORKLOAD_CODE_REVIEW_V1_1),
        _ => None,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_config::{EngineConfig, NamedPredicate, ScoringHead, ScoringRule};
    use crate::eval::Score;
    use yutha_core::{Hash, HashAlgorithm, SpecVersion, SwarmId, Timestamp};

    fn placeholder_hash() -> Hash {
        // 32-byte zero digest — a Hash that's well-formed but obviously
        // placeholder. F7 / control-plane integration computes real
        // content-addresses; F6 tests don't depend on the value.
        Hash::new(HashAlgorithm::Sha256, vec![0u8; 32]).expect("placeholder hash")
    }

    /// Synthesize a Constitution carrying the given cedar source +
    /// engine config. Other fields are filled with placeholder values
    /// — F7 / control-plane integration will set them properly.
    fn make_constitution(cedar_source: &str, engine_config: EngineConfig) -> Constitution {
        Constitution {
            constitution_hash: placeholder_hash(),
            spec_version: SpecVersion::parse("1.0.0").unwrap(),
            schema_version: "1.1.0".into(),
            constitution_version: "1.0.0".into(),
            parent_version: None,
            swarm_id: SwarmId::new(),
            cedar_source: cedar_source.into(),
            engine_config,
            issued_at: Timestamp::now(),
        }
    }

    /// Load with a forgiving stub schema (declares the entities the
    /// canonical v1.1 schema does). Re-uses the embedded canonical
    /// schema so tests exercise the same loader path the production
    /// code uses.
    fn loader() -> ConstitutionLoader {
        let schema = canonical_schema_v1_1().expect("canonical schema loads");
        ConstitutionLoader::with_default_bounds(schema)
    }

    #[test]
    fn canonical_schema_loads() {
        let _schema = canonical_schema_v1_1().expect("embedded v1.1 schema parses");
    }

    #[test]
    fn empty_constitution_loads() {
        // The smallest valid constitution: a single `permit (principal,
        // action, resource);` rule (cedar requires at least one) and
        // an empty engine config.
        let cedar = "permit (principal, action, resource);";
        let cfg = EngineConfig::default();
        let constitution = make_constitution(cedar, cfg);
        let activated = loader()
            .load(constitution)
            .expect("empty constitution loads");
        assert_eq!(activated.policy_count, 1);
        assert!(activated.resolved_engine_config.scoring_rules.is_empty());
    }

    #[test]
    fn load_resolves_named_predicates() {
        let cedar = "permit (principal, action, resource);";
        let mut cfg = EngineConfig::default();
        cfg.predicates.push(NamedPredicate {
            name: "is_super".into(),
            expr: r#"principal == User::"alice""#.into(),
        });
        cfg.scoring_rules.push(ScoringRule {
            name: "s".into(),
            score: Score("1.0".into()),
            head: ScoringHead::default(),
            when: "@is_super".into(),
        });
        let activated = loader()
            .load(make_constitution(cedar, cfg))
            .expect("resolves cleanly");
        assert_eq!(
            activated.resolved_engine_config.scoring_rules[0].when,
            r#"(principal == User::"alice")"#
        );
    }

    #[test]
    fn load_rejects_unresolved_predicate() {
        let cedar = "permit (principal, action, resource);";
        let mut cfg = EngineConfig::default();
        cfg.scoring_rules.push(ScoringRule {
            name: "s".into(),
            score: Score("1.0".into()),
            head: ScoringHead::default(),
            when: "@undefined".into(),
        });
        let err = loader().load(make_constitution(cedar, cfg)).unwrap_err();
        assert!(matches!(err, CedarPlusError::InvalidScoringRule { .. }));
    }

    #[test]
    fn load_rejects_malformed_cedar() {
        let cedar = "this is not cedar policy syntax";
        let cfg = EngineConfig::default();
        let err = loader().load(make_constitution(cedar, cfg)).unwrap_err();
        assert!(matches!(err, CedarPlusError::Parse(_)));
    }

    /// F14: canonical schema + workload extension load together and
    /// a constitution gating one of the extension's actions activates
    /// cleanly. Validates the multi-namespace concatenation pattern.
    #[test]
    fn canonical_plus_support_queue_extension_loads() {
        let schema = canonical_schema_v1_1_with_extensions(&[WORKLOAD_SUPPORT_QUEUE_V1_1])
            .expect("canonical + support-queue extension parses");
        let loader = ConstitutionLoader::with_default_bounds(schema);

        // Policy that gates the workload's IssueRefund action.
        // Permits everything else (so the policy set is non-empty for
        // the base namespace too — Cedar requires every appliesTo to
        // have at least one applicable policy in Strict mode).
        let cedar = r#"
            @id("refund-cap")
            forbid (
                principal,
                action == Yutha::SupportQueue::Action::"IssueRefund",
                resource
            ) when {
                context.refund_amount_cents > 10000
            };
            permit (principal, action, resource);
        "#;
        let activated = loader
            .load(make_constitution(cedar, EngineConfig::default()))
            .expect("constitution using SupportQueue action activates");
        assert_eq!(activated.policy_count, 2);
    }

    /// F14: loading both shipped workloads together also works — the
    /// two namespaces don't conflict.
    #[test]
    fn canonical_plus_both_workload_extensions_load() {
        let _schema = canonical_schema_v1_1_with_extensions(&[
            WORKLOAD_SUPPORT_QUEUE_V1_1,
            WORKLOAD_CODE_REVIEW_V1_1,
        ])
        .expect("canonical + both workload extensions parses");
    }

    #[test]
    fn parse_engine_config_yaml_smoke() {
        let yaml = r#"
schema_version: "1.1.0"
predicates:
  - name: foo
    expr: "true"
"#;
        let cfg = parse_engine_config_yaml(yaml).expect("parses");
        assert_eq!(cfg.predicates.len(), 1);
        assert_eq!(cfg.predicates[0].name, "foo");
    }
}

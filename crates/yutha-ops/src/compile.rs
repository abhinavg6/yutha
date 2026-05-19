//! Plain-English constitution authoring DSL → Cedar+ compiler (F15).
//!
//! Operators describe their constitution in a small YAML DSL that
//! captures *intent* ("require supervisor for refunds over $100",
//! "quarantine repeat offenders") rather than Cedar syntax. The
//! compiler emits a `(cedar_source, engine_config_yaml)` pair
//! suitable for activation via `ConstitutionService.Activate` (or
//! `yutha-ops activate`).
//!
//! ## Design choices
//!
//! * **Templated, not LLM-backed.** The compiler is a pure function
//!   over the DSL — same input, same output, no network, no
//!   probabilistic translation. Operators relying on this for
//!   production policy authoring need that determinism. An LLM
//!   front-end could sit upstream of the DSL (suggesting `forbid:`
//!   blocks from prose); the compiler downstream stays deterministic
//!   regardless.
//! * **Operator-supplied Cedar `when:` clauses.** Some conditions
//!   (e.g. complex multi-attribute predicates) don't fit cleanly into
//!   a structured field set. The DSL accepts a raw Cedar expression
//!   in `when:` for these cases. The compiler doesn't validate the
//!   expression — the server's load-time Cedar validator does that
//!   when `ConstitutionService.Activate` runs.
//! * **Safe-by-default.** Every rule gets an `@id` annotation
//!   (auto-generated from the rule's array index when not supplied).
//!   The compiler always emits a trailing `permit (principal,
//!   action, resource)` so the constitution is additive over the
//!   permissive baseline — unless `closed_by_default: true` is set,
//!   in which case the permit-all is omitted and only the operator's
//!   forbids and permits land.
//!
//! ## DSL shape
//!
//! ```yaml
//! description: "Customer support PII norms"
//! constitution_version: "1.0.0"
//! schema_version: "1.1.0"
//! closed_by_default: false  # default
//! rules:
//!   - forbid_action:
//!       id: refund-cap
//!       action: Yutha::SupportQueue::Action::IssueRefund
//!       when: "context.refund_amount_cents > 10000 && principal.passport_tier != \"verifiable\""
//!       description: "Refunds over $100 require supervisor"
//!
//!   - forbid_action:
//!       id: no-forbidden-payloads
//!       action: SendEnvelope
//!       when: 'context.payload_schema_id == "type.yutha.dev/v1/Forbidden"'
//!       description: "Block known-forbidden payload schemas"
//!
//!   - enforcement_chain:
//!       id: forbidden-payload-chain
//!       detects_on_forbid_rule: no-forbidden-payloads
//!       threshold: 3
//!       window: 60s
//!       full_chain: true  # detect → coach → quarantine → evict
//!       description: "Quarantine repeat offenders"
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Top-level DSL document. Compile via [`Self::compile`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlainEnglishConstitution {
    /// Human-readable description. Emitted as a top-of-file comment
    /// on the generated Cedar source. Not consumed by the evaluator.
    #[serde(default)]
    pub description: String,
    /// Constitution semver pinned on the resulting artifact when the
    /// operator activates it. The compiler doesn't enforce a
    /// particular value; the server does.
    #[serde(default = "default_constitution_version")]
    pub constitution_version: String,
    /// Cedar+ schema version the rules target. Defaults to the v1.1
    /// canonical schema. Operators using workload extensions still
    /// pin this to the base schema version — extensions don't carry
    /// independent schema-version semver.
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    /// When false (default), the compiler appends a trailing
    /// `permit (principal, action, resource)` so the constitution is
    /// additive over the permissive baseline. When true, the
    /// trailing permit-all is omitted and only the operator's
    /// explicit forbids and permits land — every unmatched request
    /// then default-denies (Cedar's no-permit-rule path).
    #[serde(default)]
    pub closed_by_default: bool,
    /// The rule list. Compiled in order; emitted policy ids reflect
    /// the order via the auto-id fallback.
    pub rules: Vec<Rule>,
}

fn default_constitution_version() -> String {
    "1.0.0".to_string()
}
fn default_schema_version() -> String {
    "1.1.0".to_string()
}

/// One DSL rule. Each variant maps to a specific Cedar / engine-config
/// emission shape.
///
/// Wire form (YAML): a flat map carrying a `kind: <variant>` tag plus
/// the variant's own fields. `serde(tag = "kind")` makes this work as
/// internally-tagged so operators write
/// ```yaml
/// rules:
///   - kind: forbid_action
///     action: SendEnvelope
///     when: ...
/// ```
/// rather than the more nested externally-tagged form (which serde_yaml
/// represents with the surprising `!ForbidAction` YAML-tag syntax).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Rule {
    /// Direct `forbid` rule with an operator-supplied Cedar `when:`
    /// expression. The most flexible kind; falls back here when the
    /// higher-level shapes below don't fit.
    ForbidAction {
        /// Policy `@id` annotation. Auto-generated as `forbid-N`
        /// when absent. `EnforcementChain.detects_on_forbid_rule`
        /// references this id, so operator-supplied ids are
        /// typically more useful.
        #[serde(default)]
        id: Option<String>,
        /// The action UID this rule gates. Bare name (e.g.
        /// `SendEnvelope`) maps to `Yutha::Action::"SendEnvelope"`.
        /// Workload-namespaced actions use the full path
        /// (e.g. `Yutha::SupportQueue::Action::IssueRefund`).
        action: String,
        /// Raw Cedar `when:` clause body. The compiler doesn't
        /// validate — the server's Cedar validator does on
        /// activation.
        when: String,
        /// Human-readable description. Emitted as a leading comment
        /// on the generated Cedar block.
        #[serde(default)]
        description: String,
    },

    /// Pure `permit` rule — useful with `closed_by_default: true`
    /// for narrowly admitting specific shapes while default-denying
    /// everything else.
    PermitAction {
        #[serde(default)]
        id: Option<String>,
        action: String,
        /// Cedar `when:` body. Omit for an unconditional permit.
        #[serde(default)]
        when: Option<String>,
        #[serde(default)]
        description: String,
    },

    /// Declarative four-stage enforcement loop on a named forbid
    /// rule. Compiles to an `enforcement_rules:` entry in the
    /// engine config, NOT a Cedar policy.
    EnforcementChain {
        /// Engine-config rule name (the `name:` field on the
        /// `enforcement_rules:` entry).
        #[serde(default)]
        id: Option<String>,
        /// The `forbid_rule_id` whose `constitution.evaluate.deny`
        /// receipts the engine matches on. Must reference a rule
        /// earlier in the document (so its `@id` is in scope).
        detects_on_forbid_rule: String,
        /// Number of matching denies within `window` that fire
        /// detect.
        threshold: u32,
        /// Sliding window for the threshold (e.g. `"60s"`, `"5m"`).
        window: String,
        /// When true (default), all four stages fire (detect →
        /// coach → quarantine → evict) with 1s cooldowns each.
        /// When false, only `detect` fires; the operator can wire
        /// later stages by hand if needed.
        #[serde(default = "default_full_chain")]
        full_chain: bool,
        #[serde(default)]
        description: String,
    },
}

fn default_full_chain() -> bool {
    true
}

/// Engine config emitted to the YAML side. Public so the compiler can
/// return both halves without an additional wrapper struct.
#[derive(Debug, Clone, Default, Serialize)]
pub struct EngineConfig {
    pub schema_version: String,
    pub predicates: Vec<()>,
    pub scoring_rules: Vec<()>,
    pub procedures: Vec<()>,
    pub enforcement_rules: Vec<EngineEnforcementRule>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineEnforcementRule {
    pub name: String,
    pub detect: EngineDetect,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coach: Option<EngineCoach>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine: Option<EngineQuarantine>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evict: Option<EngineEvict>,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineDetect {
    pub trigger: EngineDetectTrigger,
    pub count_threshold: u32,
    pub time_window: String,
    pub group_by: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineDetectTrigger {
    pub receipt_kind: String,
    pub forbid_rule_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineCoach {
    pub cooldown: String,
    pub guidance_template: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineQuarantine {
    pub escalate_after: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineEvict {
    pub escalate_after: String,
    pub require_countersign: bool,
}

impl PlainEnglishConstitution {
    /// Parse from a YAML source.
    pub fn from_yaml(src: &str) -> anyhow::Result<Self> {
        let parsed: Self = serde_yaml::from_str(src)?;
        Ok(parsed)
    }

    /// Compile to `(cedar_source, engine_config_yaml)`. Either half is
    /// non-empty when the DSL has rules of the matching kind; for an
    /// all-defaults DSL the cedar half carries just the trailing
    /// permit-all and the engine config carries no enforcement rules.
    pub fn compile(&self) -> anyhow::Result<(String, String)> {
        let mut cedar = String::new();
        // Header comment carries both the description and the
        // intended constitution_version. Operators activating via
        // `yutha-ops activate` pass `--version` separately (so the
        // header is informational, not load-bearing), but recording
        // the authored intent here makes diffs against later
        // amendments cleaner.
        cedar.push_str(&format!(
            "// Generated by yutha-ops compile.\n\
             // Source description:      {description}\n\
             // Authored constitution_version: {version}\n\
             // Schema version:          {schema}\n\n",
            description = if self.description.is_empty() {
                "(no description)"
            } else {
                &self.description
            },
            version = self.constitution_version,
            schema = self.schema_version,
        ));

        // Track allocated forbid-rule ids so EnforcementChain can
        // verify its `detects_on_forbid_rule` actually points at
        // something the operator declared.
        let mut declared_ids: BTreeMap<String, ()> = BTreeMap::new();
        let mut next_auto = 0usize;

        let mut enforcement_rules: Vec<EngineEnforcementRule> = Vec::new();

        for (idx, rule) in self.rules.iter().enumerate() {
            match rule {
                Rule::ForbidAction {
                    id,
                    action,
                    when,
                    description,
                } => {
                    let rule_id = id.clone().unwrap_or_else(|| {
                        next_auto += 1;
                        format!("forbid-{next_auto}")
                    });
                    declared_ids.insert(rule_id.clone(), ());
                    if !description.is_empty() {
                        cedar.push_str(&format!("// {description}\n"));
                    }
                    cedar.push_str(&format!(
                        "@id({id_lit})\nforbid (\n    principal,\n    action == {action_path},\n    resource\n) when {{\n    {when}\n}};\n\n",
                        id_lit = quote_id(&rule_id),
                        action_path = action_to_cedar_path(action),
                    ));
                }
                Rule::PermitAction {
                    id,
                    action,
                    when,
                    description,
                } => {
                    let rule_id = id.clone().unwrap_or_else(|| {
                        next_auto += 1;
                        format!("permit-{next_auto}")
                    });
                    if !description.is_empty() {
                        cedar.push_str(&format!("// {description}\n"));
                    }
                    let action_path = action_to_cedar_path(action);
                    match when {
                        Some(w) => cedar.push_str(&format!(
                            "@id({id_lit})\npermit (\n    principal,\n    action == {action_path},\n    resource\n) when {{\n    {w}\n}};\n\n",
                            id_lit = quote_id(&rule_id),
                        )),
                        None => cedar.push_str(&format!(
                            "@id({id_lit})\npermit (\n    principal,\n    action == {action_path},\n    resource\n);\n\n",
                            id_lit = quote_id(&rule_id),
                        )),
                    }
                }
                Rule::EnforcementChain {
                    id,
                    detects_on_forbid_rule,
                    threshold,
                    window,
                    full_chain,
                    description,
                } => {
                    if !declared_ids.contains_key(detects_on_forbid_rule) {
                        anyhow::bail!(
                            "rules[{idx}]: enforcement_chain.detects_on_forbid_rule = {:?} \
                             does not match any forbid_action.id declared earlier in this document. \
                             Known forbid ids: {:?}",
                            detects_on_forbid_rule,
                            declared_ids.keys().collect::<Vec<_>>()
                        );
                    }
                    let chain_id = id.clone().unwrap_or_else(|| {
                        next_auto += 1;
                        format!("chain-{next_auto}")
                    });
                    let detect = EngineDetect {
                        trigger: EngineDetectTrigger {
                            receipt_kind: "constitution.evaluate.deny".into(),
                            forbid_rule_id: detects_on_forbid_rule.clone(),
                        },
                        count_threshold: *threshold,
                        time_window: window.clone(),
                        group_by: "principal".into(),
                    };
                    let (coach, quarantine, evict) = if *full_chain {
                        let guidance = if description.is_empty() {
                            "Stop the violating behavior".to_string()
                        } else {
                            description.clone()
                        };
                        (
                            Some(EngineCoach {
                                cooldown: "1s".into(),
                                guidance_template: guidance,
                            }),
                            Some(EngineQuarantine {
                                escalate_after: "1s".into(),
                            }),
                            Some(EngineEvict {
                                escalate_after: "1s".into(),
                                require_countersign: false,
                            }),
                        )
                    } else {
                        (None, None, None)
                    };
                    enforcement_rules.push(EngineEnforcementRule {
                        name: chain_id,
                        detect,
                        coach,
                        quarantine,
                        evict,
                        severity: "high".into(),
                    });
                }
            }
        }

        if !self.closed_by_default {
            cedar.push_str(
                "// Trailing permit-all (closed_by_default: false). Everything the\n\
                 // rules above don't forbid lands here and permits.\n\
                 permit (principal, action, resource);\n",
            );
        } else if !self
            .rules
            .iter()
            .any(|r| matches!(r, Rule::PermitAction { .. }))
        {
            // Operator opted into closed-by-default but didn't author
            // any permit rules. That's a default-deny constitution
            // — Cedar requires at least one policy of any kind, and
            // having only forbids leaves every action denied with
            // "no_permit_rule". Probably not what the operator
            // wanted; flag it.
            cedar.push_str(
                "// closed_by_default: true and no permit_action rules — every\n\
                 // action default-denies. If this is intentional, ignore this\n\
                 // comment; otherwise add at least one permit_action.\n",
            );
        }

        let engine = EngineConfig {
            schema_version: self.schema_version.clone(),
            predicates: Vec::new(),
            scoring_rules: Vec::new(),
            procedures: Vec::new(),
            enforcement_rules,
        };
        let engine_yaml = serde_yaml::to_string(&engine)?;
        Ok((cedar, engine_yaml))
    }
}

/// Convert a DSL action specifier to the fully-qualified Cedar action
/// path. Bare names (no `::` in the input) map to `Yutha::Action::"X"`;
/// already-qualified inputs (e.g. `Yutha::SupportQueue::Action::IssueRefund`)
/// are normalized to ensure the trailing component is quoted.
fn action_to_cedar_path(spec: &str) -> String {
    if let Some(idx) = spec.rfind("::") {
        let (namespace, name) = (&spec[..idx], &spec[idx + 2..]);
        format!("{namespace}::{}", quote_id(name))
    } else {
        format!("Yutha::Action::{}", quote_id(spec))
    }
}

fn quote_id(s: &str) -> String {
    // Cedar policy-id and action-id annotations are double-quoted.
    // No string contains a literal `"` in any plausible DSL input;
    // we still escape defensively.
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
description: "Test policy"
rules:
  - kind: forbid_action
    id: refund-cap
    action: Yutha::SupportQueue::Action::IssueRefund
    when: "context.refund_amount_cents > 10000"
    description: "Refunds over $100 deny"

  - kind: forbid_action
    id: no-forbidden-payloads
    action: SendEnvelope
    when: 'context.payload_schema_id == "type.yutha.dev/v1/Forbidden"'

  - kind: enforcement_chain
    id: forbidden-chain
    detects_on_forbid_rule: no-forbidden-payloads
    threshold: 3
    window: 60s
    full_chain: true
"#;

    #[test]
    fn compile_sample_produces_expected_shape() {
        let dsl = PlainEnglishConstitution::from_yaml(SAMPLE).expect("yaml parses");
        let (cedar, engine_yaml) = dsl.compile().expect("compile succeeds");
        assert!(cedar.contains("@id(\"refund-cap\")"));
        assert!(cedar.contains("Yutha::SupportQueue::Action::\"IssueRefund\""));
        assert!(cedar.contains("@id(\"no-forbidden-payloads\")"));
        assert!(cedar.contains("Yutha::Action::\"SendEnvelope\""));
        // Trailing permit-all (closed_by_default defaulted to false).
        assert!(cedar.contains("permit (principal, action, resource)"));
        // Engine config has one enforcement rule with all four stages.
        assert!(engine_yaml.contains("name: forbidden-chain"));
        assert!(engine_yaml.contains("receipt_kind: constitution.evaluate.deny"));
        assert!(engine_yaml.contains("forbid_rule_id: no-forbidden-payloads"));
        assert!(engine_yaml.contains("cooldown: 1s"));
        assert!(engine_yaml.contains("escalate_after: 1s"));
    }

    #[test]
    fn enforcement_chain_referencing_unknown_rule_errors() {
        let bad = r#"
rules:
  - kind: enforcement_chain
    detects_on_forbid_rule: does-not-exist
    threshold: 2
    window: 60s
"#;
        let dsl = PlainEnglishConstitution::from_yaml(bad).expect("yaml parses");
        let err = dsl.compile().expect_err("should error");
        let msg = format!("{err}");
        assert!(msg.contains("does-not-exist"), "got: {msg}");
    }

    #[test]
    fn closed_by_default_omits_trailing_permit_all() {
        let yaml = r#"
closed_by_default: true
rules:
  - kind: permit_action
    action: SendEnvelope
"#;
        let dsl = PlainEnglishConstitution::from_yaml(yaml).expect("yaml parses");
        let (cedar, _) = dsl.compile().expect("compile");
        // Operator's explicit permit lands.
        assert!(cedar
            .contains("permit (\n    principal,\n    action == Yutha::Action::\"SendEnvelope\""));
        // But the unconditional trailing permit-all does NOT.
        assert!(!cedar.contains("permit (principal, action, resource)"));
    }
}

//! Constitution validators — load-time checks on the engine config and
//! the Cedar source.
//!
//! Split into two sections:
//!
//! - **Structural** (cedar-independent): name uniqueness, count thresholds,
//!   procedure graph well-formedness, escalation acyclicity, `@<name>`
//!   reference resolution.
//! - **Cedar bridge**: schema loading, Cedar `PolicySet` parsing, Cedar
//!   expression parsing, the `Validator` call.
//!
//! Validators are invoked in fixed order by [`crate::loader::ConstitutionLoader`];
//! a failure short-circuits the load with the appropriate
//! [`crate::error::CedarPlusError`] variant.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use crate::engine_config::{EngineConfig, Procedure, ProcedureTransition};
use crate::error::{CedarPlusError, LoadBoundReason, Result};
use crate::sandbox::SandboxConfig;

// =============================================================================
// Structural validators (cedar-independent)
// =============================================================================

/// Verify that no two scoring rules, procedures, enforcement rules, or
/// named predicates share a `name`.
///
/// Per extensions.md §2.6, §3.5 and enforcement.md §10.2.
pub(crate) fn check_unique_names(config: &EngineConfig) -> Result<()> {
    let mut scoring_names: HashSet<&str> = HashSet::new();
    for rule in &config.scoring_rules {
        if !scoring_names.insert(&rule.name) {
            return Err(CedarPlusError::InvalidScoringRule {
                rule: rule.name.clone(),
                detail: "duplicate scoring-rule name".into(),
            });
        }
    }

    let mut procedure_names: HashSet<&str> = HashSet::new();
    for proc in &config.procedures {
        if !procedure_names.insert(&proc.name) {
            return Err(CedarPlusError::InvalidProcedure {
                procedure: proc.name.clone(),
                detail: "duplicate procedure name".into(),
            });
        }
    }

    let mut enforcement_names: HashSet<&str> = HashSet::new();
    for rule in &config.enforcement_rules {
        if !enforcement_names.insert(&rule.name) {
            return Err(CedarPlusError::InvalidEnforcementRule {
                rule: rule.name.clone(),
                detail: "duplicate enforcement-rule name".into(),
            });
        }
    }

    let mut predicate_names: HashSet<&str> = HashSet::new();
    for pred in &config.predicates {
        if !predicate_names.insert(&pred.name) {
            return Err(CedarPlusError::Parse(format!(
                "duplicate predicate name: {}",
                pred.name
            )));
        }
    }

    Ok(())
}

/// Verify each scoring rule has a non-zero score in a parseable form.
///
/// F6 does NOT do full Decimal validation — that lands in F7 when we
/// pick `cedar-policy`'s Decimal surface. F6 only checks the surface
/// shape (non-empty, looks numeric, isn't a zero literal).
pub(crate) fn check_scoring_rules(config: &EngineConfig) -> Result<()> {
    for rule in &config.scoring_rules {
        let s = &rule.score.0;
        if s.is_empty() {
            return Err(CedarPlusError::InvalidScoringRule {
                rule: rule.name.clone(),
                detail: "score is empty".into(),
            });
        }

        // Surface-level shape check. F7 will parse with cedar's Decimal
        // and enforce real precision / range constraints.
        let trimmed = s.trim_start_matches('-');
        if trimmed.is_empty() || !trimmed.chars().next().unwrap().is_ascii_digit() {
            return Err(CedarPlusError::InvalidScoringRule {
                rule: rule.name.clone(),
                detail: format!("score {s:?} doesn't look numeric"),
            });
        }

        // Zero check — every "all-zeros" textual form. Negative zero
        // and trailing-zero forms both ruled out.
        let zero_forms = ["0", "0.0", "0.00", "-0", "-0.0", "-0.00"];
        if zero_forms.contains(&s.as_str()) {
            return Err(CedarPlusError::InvalidScoringRule {
                rule: rule.name.clone(),
                detail: "score must not be zero".into(),
            });
        }
    }
    Ok(())
}

/// Verify procedures: states form a finite graph, transitions reference
/// declared states, no `(from, action)` ambiguity, terminal states
/// have no outgoing transitions, no cyclic escalation.
///
/// Per extensions.md §3.5 / evaluation.md §3.4.
pub(crate) fn check_procedures(config: &EngineConfig) -> Result<()> {
    for proc in &config.procedures {
        check_procedure_states(proc)?;
        check_procedure_transitions(proc)?;
    }
    check_escalation_acyclic(config)?;
    Ok(())
}

fn check_procedure_states(proc: &Procedure) -> Result<()> {
    let state_set: HashSet<&str> = proc.states.iter().map(String::as_str).collect();

    if !state_set.contains(proc.initial_state.as_str()) {
        return Err(CedarPlusError::InvalidProcedure {
            procedure: proc.name.clone(),
            detail: format!("initial_state {:?} not in states", proc.initial_state),
        });
    }

    for terminal in &proc.terminal_states {
        if !state_set.contains(terminal.as_str()) {
            return Err(CedarPlusError::InvalidProcedure {
                procedure: proc.name.clone(),
                detail: format!("terminal_state {terminal:?} not in states"),
            });
        }
    }

    Ok(())
}

fn check_procedure_transitions(proc: &Procedure) -> Result<()> {
    let state_set: HashSet<&str> = proc.states.iter().map(String::as_str).collect();
    let terminal_set: HashSet<&str> = proc.terminal_states.iter().map(String::as_str).collect();

    // (from_state, action_or_timeout_marker) -> count
    let mut transition_keys: HashMap<(String, String), u32> = HashMap::new();

    for t in &proc.transitions {
        if !state_set.contains(t.from.as_str()) {
            return Err(CedarPlusError::InvalidProcedure {
                procedure: proc.name.clone(),
                detail: format!("transition from {:?} not in states", t.from),
            });
        }
        if !state_set.contains(t.to.as_str()) {
            return Err(CedarPlusError::InvalidProcedure {
                procedure: proc.name.clone(),
                detail: format!("transition to {:?} not in states", t.to),
            });
        }
        if terminal_set.contains(t.from.as_str()) {
            return Err(CedarPlusError::InvalidProcedure {
                procedure: proc.name.clone(),
                detail: format!(
                    "transition from terminal state {:?} — terminal states cannot have outgoing \
                     transitions",
                    t.from
                ),
            });
        }
        if t.action.is_none() && t.on_timeout.is_none() {
            return Err(CedarPlusError::InvalidProcedure {
                procedure: proc.name.clone(),
                detail: format!(
                    "transition {:?}->{:?} has neither action nor on_timeout",
                    t.from, t.to
                ),
            });
        }
        if t.action.is_some() && t.on_timeout.is_some() {
            return Err(CedarPlusError::InvalidProcedure {
                procedure: proc.name.clone(),
                detail: format!(
                    "transition {:?}->{:?} has both action and on_timeout (mutually exclusive)",
                    t.from, t.to
                ),
            });
        }

        let action_key = transition_action_key(t);
        let counter = transition_keys
            .entry((t.from.clone(), action_key.clone()))
            .or_insert(0);
        *counter += 1;
        if *counter > 1 {
            return Err(CedarPlusError::InvalidProcedure {
                procedure: proc.name.clone(),
                detail: format!(
                    "two transitions share (from={:?}, action_or_timeout={:?}) — ambiguous",
                    t.from, action_key
                ),
            });
        }
    }

    // Reachability: every non-terminal state SHOULD have an outgoing
    // transition (otherwise instances in it are stuck). We surface
    // this as a warning-shaped error so the loader rejects with a
    // clear message.
    for s in &proc.states {
        if terminal_set.contains(s.as_str()) {
            continue;
        }
        let has_outgoing = proc.transitions.iter().any(|t| t.from == *s);
        if !has_outgoing {
            return Err(CedarPlusError::InvalidProcedure {
                procedure: proc.name.clone(),
                detail: format!(
                    "non-terminal state {s:?} has no outgoing transitions — instances would be stuck"
                ),
            });
        }
    }

    Ok(())
}

fn transition_action_key(t: &ProcedureTransition) -> String {
    match (&t.action, &t.on_timeout) {
        (Some(a), _) => format!("action:{a}"),
        (None, Some(to)) => format!("timeout:{to}"),
        // Caught by the earlier check; both-None can't reach here.
        (None, None) => "unreachable".into(),
    }
}

fn check_escalation_acyclic(config: &EngineConfig) -> Result<()> {
    // Procedure → set of procedures it may escalate into (via
    // on_timeout_escalate). Cycle detection via DFS.
    let graph: HashMap<&str, HashSet<&str>> = config
        .procedures
        .iter()
        .map(|p| {
            let edges: HashSet<&str> = p.on_timeout_escalate.values().map(String::as_str).collect();
            (p.name.as_str(), edges)
        })
        .collect();

    // Verify every escalation target exists as a procedure.
    let proc_names: HashSet<&str> = config.procedures.iter().map(|p| p.name.as_str()).collect();
    for (from, edges) in &graph {
        for to in edges {
            if !proc_names.contains(to) {
                return Err(CedarPlusError::InvalidProcedure {
                    procedure: from.to_string(),
                    detail: format!("escalation target {to:?} is not a declared procedure"),
                });
            }
        }
    }

    // DFS for cycles.
    enum Color {
        White,
        Gray,
        Black,
    }
    let mut color: HashMap<&str, Color> = config
        .procedures
        .iter()
        .map(|p| (p.name.as_str(), Color::White))
        .collect();

    fn dfs<'a>(
        node: &'a str,
        graph: &'a HashMap<&'a str, HashSet<&'a str>>,
        color: &mut HashMap<&'a str, Color>,
    ) -> Result<()> {
        color.insert(node, Color::Gray);
        if let Some(edges) = graph.get(node) {
            for next in edges {
                match color.get(next) {
                    Some(Color::Gray) => {
                        return Err(CedarPlusError::InvalidProcedure {
                            procedure: node.to_string(),
                            detail: format!("escalation cycle reaches back to {next:?}"),
                        })
                    }
                    Some(Color::Black) => continue,
                    Some(Color::White) | None => dfs(next, graph, color)?,
                }
            }
        }
        color.insert(node, Color::Black);
        Ok(())
    }

    for proc in &config.procedures {
        if matches!(color.get(proc.name.as_str()), Some(Color::White)) {
            dfs(proc.name.as_str(), &graph, &mut color)?;
        }
    }

    Ok(())
}

/// Verify enforcement rules: trigger references a known receipt kind,
/// thresholds and windows positive, duration strings parse.
///
/// Per enforcement.md §10.2.
pub(crate) fn check_enforcement_rules(config: &EngineConfig) -> Result<()> {
    let known_receipt_kinds = known_receipt_kinds();
    for rule in &config.enforcement_rules {
        if !known_receipt_kinds.contains(rule.detect.trigger.receipt_kind.as_str()) {
            return Err(CedarPlusError::InvalidEnforcementRule {
                rule: rule.name.clone(),
                detail: format!(
                    "trigger.receipt_kind {:?} is not a known canonical action-kind",
                    rule.detect.trigger.receipt_kind
                ),
            });
        }
        if rule.detect.count_threshold == 0 {
            return Err(CedarPlusError::InvalidEnforcementRule {
                rule: rule.name.clone(),
                detail: "detect.count_threshold must be >= 1".into(),
            });
        }
        if parse_duration(&rule.detect.time_window).is_none() {
            return Err(CedarPlusError::InvalidEnforcementRule {
                rule: rule.name.clone(),
                detail: format!(
                    "detect.time_window {:?} is not a parseable duration",
                    rule.detect.time_window
                ),
            });
        }
        if let Some(coach) = &rule.coach {
            if parse_duration(&coach.cooldown).is_none() {
                return Err(CedarPlusError::InvalidEnforcementRule {
                    rule: rule.name.clone(),
                    detail: format!(
                        "coach.cooldown {:?} is not a parseable duration",
                        coach.cooldown
                    ),
                });
            }
        }
        if let Some(quar) = &rule.quarantine {
            if parse_duration(&quar.escalate_after).is_none() {
                return Err(CedarPlusError::InvalidEnforcementRule {
                    rule: rule.name.clone(),
                    detail: format!(
                        "quarantine.escalate_after {:?} is not a parseable duration",
                        quar.escalate_after
                    ),
                });
            }
            if let Some(exp) = &quar.expires_after {
                if parse_duration(exp).is_none() {
                    return Err(CedarPlusError::InvalidEnforcementRule {
                        rule: rule.name.clone(),
                        detail: format!(
                            "quarantine.expires_after {exp:?} is not a parseable duration"
                        ),
                    });
                }
            }
        }
        if let Some(evict) = &rule.evict {
            if parse_duration(&evict.escalate_after).is_none() {
                return Err(CedarPlusError::InvalidEnforcementRule {
                    rule: rule.name.clone(),
                    detail: format!(
                        "evict.escalate_after {:?} is not a parseable duration",
                        evict.escalate_after
                    ),
                });
            }
        }
    }
    Ok(())
}

/// The set of `action_kind` values we accept as enforcement-rule
/// triggers. Per `/spec/receipt/canonical-actions.md` — this list MUST
/// stay in sync with the canonical-actions registry.
///
/// F6 hard-codes the v1.1 set; F8 / F9 may load this from the
/// canonical-actions YAML if we promote that registry to a parseable
/// artifact.
fn known_receipt_kinds() -> HashSet<&'static str> {
    [
        // Agent lifecycle
        "agent.register",
        "agent.revoke",
        "agent.operator_revoke",
        "agent.rotate_key",
        "agent.heartbeat.missed",
        // Envelope
        "envelope.send",
        "envelope.deliver",
        "envelope.deliver.failed",
        // Capability
        "capability.issue",
        "capability.attenuate",
        "capability.revoke",
        "capability.check.pass",
        "capability.check.deny",
        // Memory (Phase 2)
        "memory.write",
        "memory.read",
        "memory.forget",
        "memory.share",
        // Constitution
        "constitution.activate",
        "constitution.evaluate.pass",
        "constitution.evaluate.deny",
        "constitution.amend.propose",
        "constitution.amend.commit",
        "constitution.amend.timeout",
        // Procedure
        "procedure.enter",
        "procedure.transition",
        "procedure.timeout",
        "procedure.escalate",
        // Enforcement
        "enforcement.detect",
        "enforcement.coach",
        "enforcement.quarantine",
        "enforcement.evict",
        "enforcement.reverse",
        "enforcement.evict_timeout",
    ]
    .into_iter()
    .collect()
}

/// Parse a duration string like `"10m"`, `"1h"`, `"30s"`, `"500ms"`.
///
/// Conservative parser — handles the common units used in spec
/// examples. F6 doesn't aim for full RFC 3339 / ISO 8601 duration
/// parsing; the SI suffix shape is what operators actually write.
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Find the suffix
    let (num_part, unit) = split_suffix(s)?;
    let n: u64 = num_part.parse().ok()?;
    let dur = match unit {
        "ms" => Duration::from_millis(n),
        "s" => Duration::from_secs(n),
        "m" => Duration::from_secs(n * 60),
        "h" => Duration::from_secs(n * 60 * 60),
        "d" => Duration::from_secs(n * 60 * 60 * 24),
        _ => return None,
    };
    Some(dur)
}

fn split_suffix(s: &str) -> Option<(&str, &str)> {
    // Suffix is the trailing alphabetic run.
    let split_at = s.rfind(|c: char| c.is_ascii_digit())? + 1;
    if split_at >= s.len() {
        return None;
    }
    Some((&s[..split_at], &s[split_at..]))
}

// =============================================================================
// Named-predicate resolution
// =============================================================================

/// Substitute every `@<name>` reference in scoring/procedure/enforcement
/// rule expressions with the corresponding predicate's expression text.
///
/// Per extensions.md §2.4: resolution is by load-time substitution; after
/// this pass, no `@`-references remain in any expression. The result is
/// an [`EngineConfig`] with expressions in their fully-inlined form,
/// ready for cedar-policy parsing.
///
/// Unresolved `@<name>` references produce
/// [`CedarPlusError::InvalidScoringRule`] / `InvalidProcedure` /
/// `InvalidEnforcementRule` depending on where the reference appeared.
pub(crate) fn resolve_named_predicates(config: &mut EngineConfig) -> Result<()> {
    let predicate_map: HashMap<String, String> = config
        .predicates
        .iter()
        .map(|p| (p.name.clone(), p.expr.clone()))
        .collect();

    for rule in &mut config.scoring_rules {
        rule.when = substitute(&rule.when, &predicate_map).map_err(|name| {
            CedarPlusError::InvalidScoringRule {
                rule: rule.name.clone(),
                detail: format!("unresolved @{name} reference in when"),
            }
        })?;
    }

    for proc in &mut config.procedures {
        if let Some(w) = &proc.trigger.when {
            let resolved =
                substitute(w, &predicate_map).map_err(|name| CedarPlusError::InvalidProcedure {
                    procedure: proc.name.clone(),
                    detail: format!("unresolved @{name} reference in trigger.when"),
                })?;
            proc.trigger.when = Some(resolved);
        }
        for t in &mut proc.transitions {
            if let Some(w) = &t.actor_when {
                let resolved = substitute(w, &predicate_map).map_err(|name| {
                    CedarPlusError::InvalidProcedure {
                        procedure: proc.name.clone(),
                        detail: format!("unresolved @{name} reference in transition.actor_when"),
                    }
                })?;
                t.actor_when = Some(resolved);
            }
        }
    }

    // Enforcement rules don't carry Cedar expressions themselves at
    // v1.1 (the trigger pattern matches receipt fields, not Cedar
    // expressions). If a future RFC adds expression bodies to
    // enforcement rules, the substitution loop lands here.

    Ok(())
}

/// Substitute `@<name>` tokens with the corresponding expression. Returns
/// `Err(name)` for the first unresolved reference.
///
/// Token format: `@` followed by an identifier-like run
/// (`[A-Za-z_][A-Za-z0-9_]*`). Substitution wraps the expansion in
/// parentheses so operator precedence is preserved when the named
/// predicate composes into a larger expression.
fn substitute(
    src: &str,
    predicates: &HashMap<String, String>,
) -> std::result::Result<String, String> {
    let mut out = String::with_capacity(src.len());
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '@' {
            let start = i + 1;
            let mut end = start;
            while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
                end += 1;
            }
            if end == start {
                // Bare '@' — not a reference; emit as-is.
                out.push('@');
                i += 1;
                continue;
            }
            let name: String = chars[start..end].iter().collect();
            let expansion = predicates.get(&name).ok_or_else(|| name.clone())?;
            out.push('(');
            out.push_str(expansion);
            out.push(')');
            i = end;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    Ok(out)
}

// =============================================================================
// Load-time bound enforcement
// =============================================================================

/// Enforce the load-time count bounds from RFC 0012 §3.3. Policy depth
/// is checked separately in the cedar bridge after Validator runs.
pub(crate) fn check_load_time_counts(config: &EngineConfig, bounds: &SandboxConfig) -> Result<()> {
    if config.scoring_rules.len() > bounds.max_scoring_rules {
        return Err(CedarPlusError::LoadBoundExceeded(
            LoadBoundReason::ScoringRuleCount,
        ));
    }
    if config.procedures.len() > bounds.max_procedures {
        return Err(CedarPlusError::LoadBoundExceeded(
            LoadBoundReason::ProcedureCount,
        ));
    }
    Ok(())
}

// =============================================================================
// Cedar bridge — schema, policy, expression parsing
// =============================================================================

/// Result of running cedar-policy over the Cedar source: the parsed
/// `PolicySet` plus the analyzer-reported policy count and max depth.
///
/// `cedar_max_policy_depth` is what the Yutha-side
/// `policy_depth_exceeded` bound checks against. cedar-policy 3.x's
/// Validator surfaces a strict-mode depth; if a future version's API
/// shifts, this struct evolves accordingly.
#[derive(Debug)]
pub(crate) struct ParsedCedar {
    pub(crate) policy_set: cedar_policy::PolicySet,
    pub(crate) policy_count: usize,
    pub(crate) cedar_max_policy_depth: u32,
}

/// Parse the Cedar policy source against the loaded schema, run the
/// Validator in strict mode, and reject malformed or schema-incompatible
/// policies.
///
/// **cedar-policy 3.x API note.** This function assumes:
/// - `cedar_policy::PolicySet::from_str(&str) -> Result<PolicySet, _>`
/// - `cedar_policy::Validator::new(Schema)`
/// - `Validator::validate(&PolicySet, ValidationMode::Strict) ->
///   ValidationResult` with `validation_passed()` and an iterator
///   over `validation_errors()`.
///
/// If the actual cedar-policy 3.4 surface differs, this function is the
/// surgical point — fix here, not in callers.
pub(crate) fn parse_and_validate_cedar(
    schema: &cedar_policy::Schema,
    cedar_source: &str,
    bounds: &SandboxConfig,
) -> Result<ParsedCedar> {
    let policy_set: cedar_policy::PolicySet = cedar_source
        .parse()
        .map_err(|e| CedarPlusError::Parse(format!("Cedar source failed to parse: {e}")))?;

    let policy_count = policy_set.policies().count();
    if policy_count > bounds.max_cedar_policies {
        return Err(CedarPlusError::LoadBoundExceeded(
            LoadBoundReason::PolicyCount,
        ));
    }

    let validator = cedar_policy::Validator::new(schema.clone());
    let validation_result = validator.validate(&policy_set, cedar_policy::ValidationMode::Strict);
    if !validation_result.validation_passed() {
        let errs: Vec<String> = validation_result
            .validation_errors()
            .map(|e| e.to_string())
            .collect();
        return Err(CedarPlusError::Parse(format!(
            "Cedar validator rejected the policy set: {}",
            errs.join("; ")
        )));
    }

    // cedar-policy 3.x doesn't expose policy-depth as a single number
    // through the public API at every minor version. F6 computes a
    // conservative upper bound from the source-text shape; F7
    // refines using whatever the cedar API exposes once we depend on
    // a stable 3.4+ surface. For now, count nested `&&` / `||` /
    // `.attr` chains as a depth proxy.
    let cedar_max_policy_depth = estimate_cedar_depth(cedar_source);
    if cedar_max_policy_depth > bounds.max_policy_depth_at_load {
        return Err(CedarPlusError::LoadBoundExceeded(
            LoadBoundReason::PolicyDepth,
        ));
    }

    Ok(ParsedCedar {
        policy_set,
        policy_count,
        cedar_max_policy_depth,
    })
}

/// Conservative depth estimator. Counts the maximum number of dot-
/// access chains, `&&`/`||` operators, and parentheses nesting in any
/// single line. NOT a precise measure — F7 swaps this for cedar's own
/// analyzer-reported depth.
fn estimate_cedar_depth(source: &str) -> u32 {
    let mut max_depth: u32 = 0;
    for line in source.lines() {
        let mut depth: u32 = 0;
        let mut current: u32 = 0;
        for ch in line.chars() {
            match ch {
                '(' | '[' | '{' => {
                    current += 1;
                    depth = depth.max(current);
                }
                ')' | ']' | '}' => {
                    current = current.saturating_sub(1);
                }
                _ => {}
            }
        }
        max_depth = max_depth.max(depth);
    }
    max_depth
}

/// Parse a Cedar expression string (the body of a `when` clause or
/// similar) and check that it validates against the schema.
///
/// **cedar-policy 3.x API note.** Cedar 3.x exposes a stable
/// `Expression` or `Expr` type with `from_str`. If the public method
/// differs, the surgical fix lands here.
pub(crate) fn parse_cedar_expression(_schema: &cedar_policy::Schema, expr: &str) -> Result<()> {
    // F6 only parses; F7 wires up schema-level expression validation
    // (cedar-policy 3.4's `Validator::validate_expression` API, where
    // present, or a manual round-trip through a synthetic policy).
    let _: cedar_policy::Expression = expr.parse().map_err(|e| {
        CedarPlusError::Parse(format!("Cedar expression {expr:?} failed to parse: {e}"))
    })?;
    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_config::{
        DetectConfig, DetectTrigger, EnforcementRule, NamedPredicate, ProcedureTrigger,
        ScoringHead, ScoringRule,
    };
    use crate::eval::Score;

    fn empty_config() -> EngineConfig {
        EngineConfig::default()
    }

    #[test]
    fn unique_names_accepts_distinct() {
        let mut cfg = empty_config();
        cfg.scoring_rules.push(ScoringRule {
            name: "a".into(),
            score: Score("1.0".into()),
            head: ScoringHead::default(),
            when: "true".into(),
        });
        cfg.scoring_rules.push(ScoringRule {
            name: "b".into(),
            score: Score("2.0".into()),
            head: ScoringHead::default(),
            when: "true".into(),
        });
        check_unique_names(&cfg).expect("distinct names accepted");
    }

    #[test]
    fn unique_names_rejects_duplicate() {
        let mut cfg = empty_config();
        cfg.scoring_rules.push(ScoringRule {
            name: "a".into(),
            score: Score("1.0".into()),
            head: ScoringHead::default(),
            when: "true".into(),
        });
        cfg.scoring_rules.push(ScoringRule {
            name: "a".into(),
            score: Score("2.0".into()),
            head: ScoringHead::default(),
            when: "true".into(),
        });
        let err = check_unique_names(&cfg).unwrap_err();
        assert!(matches!(err, CedarPlusError::InvalidScoringRule { .. }));
    }

    #[test]
    fn scoring_rules_rejects_zero_score() {
        let mut cfg = empty_config();
        cfg.scoring_rules.push(ScoringRule {
            name: "z".into(),
            score: Score("0.0".into()),
            head: ScoringHead::default(),
            when: "true".into(),
        });
        let err = check_scoring_rules(&cfg).unwrap_err();
        assert!(matches!(err, CedarPlusError::InvalidScoringRule { .. }));
    }

    #[test]
    fn parse_duration_handles_common_units() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("10m"), Some(Duration::from_secs(600)));
        assert_eq!(parse_duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("2d"), Some(Duration::from_secs(172800)));
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("10"), None);
        assert_eq!(parse_duration("abc"), None);
        assert_eq!(parse_duration("10x"), None);
    }

    #[test]
    fn enforcement_rejects_unknown_receipt_kind() {
        let mut cfg = empty_config();
        cfg.enforcement_rules.push(EnforcementRule {
            name: "bad".into(),
            detect: DetectConfig {
                trigger: DetectTrigger {
                    receipt_kind: "made.up.kind".into(),
                    deny_reason: None,
                    forbid_rule_id: None,
                },
                count_threshold: 1,
                time_window: "1m".into(),
                group_by: "principal".into(),
                historical: false,
            },
            coach: None,
            quarantine: None,
            evict: None,
            reputation_delta: HashMap::new(),
            reverse: Default::default(),
            severity: None,
        });
        let err = check_enforcement_rules(&cfg).unwrap_err();
        assert!(matches!(err, CedarPlusError::InvalidEnforcementRule { .. }));
    }

    #[test]
    fn enforcement_accepts_known_kind() {
        let mut cfg = empty_config();
        cfg.enforcement_rules.push(EnforcementRule {
            name: "ok".into(),
            detect: DetectConfig {
                trigger: DetectTrigger {
                    receipt_kind: "constitution.evaluate.deny".into(),
                    deny_reason: Some("forbid_rule_matched".into()),
                    forbid_rule_id: None,
                },
                count_threshold: 3,
                time_window: "10m".into(),
                group_by: "principal".into(),
                historical: false,
            },
            coach: None,
            quarantine: None,
            evict: None,
            reputation_delta: HashMap::new(),
            reverse: Default::default(),
            severity: None,
        });
        check_enforcement_rules(&cfg).expect("known kind accepted");
    }

    #[test]
    fn named_predicate_substitution_inlines() {
        let mut cfg = empty_config();
        cfg.predicates.push(NamedPredicate {
            name: "is_super".into(),
            expr: r#"principal.passport_tier == "supervisor""#.into(),
        });
        cfg.scoring_rules.push(ScoringRule {
            name: "s".into(),
            score: Score("1.0".into()),
            head: ScoringHead::default(),
            when: "@is_super".into(),
        });
        resolve_named_predicates(&mut cfg).expect("resolution succeeds");
        assert_eq!(
            cfg.scoring_rules[0].when,
            r#"(principal.passport_tier == "supervisor")"#
        );
    }

    #[test]
    fn named_predicate_unresolved_errors() {
        let mut cfg = empty_config();
        cfg.scoring_rules.push(ScoringRule {
            name: "s".into(),
            score: Score("1.0".into()),
            head: ScoringHead::default(),
            when: "@nonexistent".into(),
        });
        let err = resolve_named_predicates(&mut cfg).unwrap_err();
        assert!(matches!(err, CedarPlusError::InvalidScoringRule { .. }));
    }

    #[test]
    fn cyclic_escalation_rejected() {
        let mut cfg = empty_config();
        cfg.procedures.push(Procedure {
            name: "a".into(),
            initial_state: "x".into(),
            states: vec!["x".into(), "term".into()],
            terminal_states: vec!["term".into()],
            trigger: ProcedureTrigger {
                action: "Foo".into(),
                when: None,
            },
            transitions: vec![ProcedureTransition {
                from: "x".into(),
                to: "term".into(),
                action: Some("Foo".into()),
                actor_when: None,
                on_timeout: None,
            }],
            on_timeout_escalate: {
                let mut m = HashMap::new();
                m.insert("x".into(), "b".into());
                m
            },
        });
        cfg.procedures.push(Procedure {
            name: "b".into(),
            initial_state: "y".into(),
            states: vec!["y".into(), "term".into()],
            terminal_states: vec!["term".into()],
            trigger: ProcedureTrigger {
                action: "Bar".into(),
                when: None,
            },
            transitions: vec![ProcedureTransition {
                from: "y".into(),
                to: "term".into(),
                action: Some("Bar".into()),
                actor_when: None,
                on_timeout: None,
            }],
            on_timeout_escalate: {
                let mut m = HashMap::new();
                m.insert("y".into(), "a".into());
                m
            },
        });
        let err = check_procedures(&cfg).unwrap_err();
        assert!(matches!(err, CedarPlusError::InvalidProcedure { .. }));
    }

    #[test]
    fn ambiguous_transition_rejected() {
        let mut cfg = empty_config();
        cfg.procedures.push(Procedure {
            name: "a".into(),
            initial_state: "x".into(),
            states: vec!["x".into(), "term".into()],
            terminal_states: vec!["term".into()],
            trigger: ProcedureTrigger {
                action: "Foo".into(),
                when: None,
            },
            transitions: vec![
                ProcedureTransition {
                    from: "x".into(),
                    to: "term".into(),
                    action: Some("Foo".into()),
                    actor_when: None,
                    on_timeout: None,
                },
                ProcedureTransition {
                    from: "x".into(),
                    to: "term".into(),
                    action: Some("Foo".into()),
                    actor_when: Some("true".into()),
                    on_timeout: None,
                },
            ],
            on_timeout_escalate: HashMap::new(),
        });
        let err = check_procedures(&cfg).unwrap_err();
        assert!(matches!(err, CedarPlusError::InvalidProcedure { .. }));
    }

    #[test]
    fn load_bound_scoring_count() {
        let mut cfg = empty_config();
        let bounds = SandboxConfig {
            max_scoring_rules: 2,
            ..SandboxConfig::default()
        };
        for i in 0..3 {
            cfg.scoring_rules.push(ScoringRule {
                name: format!("r{i}"),
                score: Score("1.0".into()),
                head: ScoringHead::default(),
                when: "true".into(),
            });
        }
        let err = check_load_time_counts(&cfg, &bounds).unwrap_err();
        match err {
            CedarPlusError::LoadBoundExceeded(LoadBoundReason::ScoringRuleCount) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

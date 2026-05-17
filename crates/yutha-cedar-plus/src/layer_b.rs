//! Layer B artifacts — synthesized stock-Cedar policy sets that back
//! scoring rules, procedure triggers, and procedure transitions.
//!
//! ## Design
//!
//! Cedar's `Authorizer::is_authorized` evaluates a `PolicySet` against a
//! `Request` + `Entities` and returns which policies matched. We exploit
//! this by **synthesizing one stock Cedar policy per engine-config rule**
//! at constitution-activation time:
//!
//! - A scoring rule with `head: { action: AssignCase }` and
//!   `when: 'principal.reputation > 0.8'` becomes a stock Cedar
//!   `permit (principal, action == Yutha::Action::"AssignCase",
//!   resource) when { principal.reputation > 0.8 };`.
//! - A procedure trigger similarly becomes a `permit (...)` filtered
//!   by the trigger's action.
//! - Each procedure transition becomes a `permit (...)` filtered by
//!   the transition's `action`.
//!
//! At runtime, the evaluator runs `Authorizer` against each synthesized
//! `PolicySet`. The matched policy ids tell us which scoring rules
//! contributed / which procedures triggered / which transitions fired.
//! Cedar handles head matching, when-clause evaluation, and the schema
//! check; the Layer B engine only does the bookkeeping.
//!
//! This reuses cedar-policy's well-tested infrastructure (no parallel
//! expression evaluator), preserves decidability (every Layer B
//! evaluation is a stock Cedar pass), and stays decoupled from the
//! receipt fabric (the engine only needs the same Request/Entities
//! Layer A already has).
//!
//! ## Policy id encoding
//!
//! Synthesized policy ids carry the source-rule name plus a domain
//! prefix to disambiguate across the three policy sets. Format:
//!
//! - `scoring__<rule_name>` — scoring rule.
//! - `proc_trigger__<procedure_name>` — procedure trigger.
//! - `proc_trans__<procedure_name>__<from_state>__<to_state>` —
//!   procedure transition.
//!
//! Cedar policy ids are case-sensitive arbitrary strings, so the
//! double-underscore separator is safe — operators authoring rule
//! names that contain `__` will see Cedar reject the synthesized
//! policy at load time. Load-time validation catches this case.

use std::collections::BTreeMap;
use std::str::FromStr;

use crate::engine_config::{
    EngineConfig, NamedPredicate, Procedure, ProcedureTransition, ScoringRule,
};
use crate::error::{CedarPlusError, Result};
use crate::eval::Score;

/// Synthesized stock-Cedar policy sets backing Layer B evaluation.
///
/// Built once per `constitution.activate`; reused for every evaluation
/// against this constitution.
#[derive(Debug)]
pub struct LayerBArtifacts {
    /// One Cedar `permit` policy per scoring rule.
    pub scoring_policy_set: cedar_policy::PolicySet,
    /// Map from synthesized scoring policy id → (rule_name, score).
    /// Lookup is O(log N) — N is small (≤ 1,000 per sandbox bound).
    pub scoring_by_policy_id: BTreeMap<String, ScoringRuleHandle>,

    /// One Cedar `permit` policy per procedure trigger.
    pub procedure_trigger_policy_set: cedar_policy::PolicySet,
    /// Map from synthesized trigger policy id → procedure name.
    pub trigger_by_policy_id: BTreeMap<String, String>,

    /// One Cedar `permit` policy per procedure transition's
    /// `actor_when` predicate. (Timeout transitions don't have an
    /// `actor_when` to evaluate — they're scheduled and fired by F9.)
    pub procedure_transition_policy_set: cedar_policy::PolicySet,
    /// Map from synthesized transition policy id → transition handle
    /// (procedure name, from state, to state, action).
    pub transition_by_policy_id: BTreeMap<String, TransitionHandle>,
}

/// Per-scoring-rule metadata recovered when a synthesized policy fires.
#[derive(Debug, Clone)]
pub struct ScoringRuleHandle {
    /// Operator-authored rule name (the value in `engine_config.scoring_rules[i].name`).
    pub rule_name: String,
    /// Operator-authored score. Stored as the original [`Score`]
    /// representation; evaluator accumulates as fixed-precision i64
    /// (4 fractional digits per Cedar's Decimal precision).
    pub score: Score,
    /// Pre-parsed numeric value for accumulation. Pre-computed at
    /// load time so each evaluation does integer-only arithmetic.
    /// Encoded as `score * 10_000` (i.e. "2.5" → 25_000).
    pub score_scaled: i64,
}

/// Per-transition metadata recovered when a synthesized transition
/// policy fires.
#[derive(Debug, Clone)]
pub struct TransitionHandle {
    /// The procedure this transition belongs to.
    pub procedure_name: String,
    /// Source state.
    pub from_state: String,
    /// Destination state.
    pub to_state: String,
    /// The action that fires this transition (Cedar action kind).
    pub action: String,
}

// =============================================================================
// Synthesis
// =============================================================================

/// Build [`LayerBArtifacts`] from a constitution's engine config, after
/// named-predicate resolution. Called by `ConstitutionLoader::load`.
pub(crate) fn synthesize(
    schema: &cedar_policy::Schema,
    resolved: &EngineConfig,
) -> Result<LayerBArtifacts> {
    let scoring = synthesize_scoring(schema, &resolved.scoring_rules)?;
    let triggers = synthesize_triggers(schema, &resolved.procedures)?;
    let transitions = synthesize_transitions(schema, &resolved.procedures)?;
    Ok(LayerBArtifacts {
        scoring_policy_set: scoring.policy_set,
        scoring_by_policy_id: scoring.by_id,
        procedure_trigger_policy_set: triggers.policy_set,
        trigger_by_policy_id: triggers.by_id,
        procedure_transition_policy_set: transitions.policy_set,
        transition_by_policy_id: transitions.by_id,
    })
}

struct ScoringSyn {
    policy_set: cedar_policy::PolicySet,
    by_id: BTreeMap<String, ScoringRuleHandle>,
}

fn synthesize_scoring(schema: &cedar_policy::Schema, rules: &[ScoringRule]) -> Result<ScoringSyn> {
    let mut by_id = BTreeMap::new();
    let mut policy_texts: Vec<String> = Vec::new();
    for rule in rules {
        let policy_id = format!("scoring__{}", rule.name);
        let action_constraint = match &rule.head.action {
            Some(a) => format!("action == Yutha::Action::\"{a}\""),
            None => "action".to_string(),
        };
        // F8 v1 doesn't synthesize principal / resource head
        // constraints — the dominant case in extensions.md §2.2 is
        // action-only filtering. Future RFCs may add principal /
        // resource wildcards; this synthesizer extends naturally.
        let policy_text = format!(
            "@id(\"{policy_id}\")\npermit (principal, {action_constraint}, resource)\nwhen {{ {when} }};",
            when = rule.when
        );
        policy_texts.push(policy_text);
        let score_scaled = parse_score_scaled(&rule.score).map_err(|detail| {
            CedarPlusError::InvalidScoringRule {
                rule: rule.name.clone(),
                detail,
            }
        })?;
        by_id.insert(
            policy_id,
            ScoringRuleHandle {
                rule_name: rule.name.clone(),
                score: rule.score.clone(),
                score_scaled,
            },
        );
    }

    let policy_set = parse_synthesized_set(schema, &policy_texts, "scoring")?;
    Ok(ScoringSyn { policy_set, by_id })
}

struct TriggerSyn {
    policy_set: cedar_policy::PolicySet,
    by_id: BTreeMap<String, String>,
}

fn synthesize_triggers(
    schema: &cedar_policy::Schema,
    procedures: &[Procedure],
) -> Result<TriggerSyn> {
    let mut by_id = BTreeMap::new();
    let mut policy_texts: Vec<String> = Vec::new();
    for proc in procedures {
        let policy_id = format!("proc_trigger__{}", proc.name);
        let when_clause = proc.trigger.when.as_deref().unwrap_or("true");
        let policy_text = format!(
            "@id(\"{policy_id}\")\npermit (principal, action == Yutha::Action::\"{action}\", resource)\nwhen {{ {when_clause} }};",
            action = proc.trigger.action,
        );
        policy_texts.push(policy_text);
        by_id.insert(policy_id, proc.name.clone());
    }

    let policy_set = parse_synthesized_set(schema, &policy_texts, "procedure trigger")?;
    Ok(TriggerSyn { policy_set, by_id })
}

struct TransitionSyn {
    policy_set: cedar_policy::PolicySet,
    by_id: BTreeMap<String, TransitionHandle>,
}

fn synthesize_transitions(
    schema: &cedar_policy::Schema,
    procedures: &[Procedure],
) -> Result<TransitionSyn> {
    let mut by_id = BTreeMap::new();
    let mut policy_texts: Vec<String> = Vec::new();
    for proc in procedures {
        for t in &proc.transitions {
            // Timeout transitions are scheduler-driven (F9); we only
            // synthesize policies for action-driven transitions.
            let action_kind = match &t.action {
                Some(a) => a.clone(),
                None => continue,
            };
            let policy_id = format!("proc_trans__{}__{}__{}", proc.name, t.from, t.to);
            let when_clause = t.actor_when.as_deref().unwrap_or("true");
            let policy_text = format!(
                "@id(\"{policy_id}\")\npermit (principal, action == Yutha::Action::\"{action_kind}\", resource)\nwhen {{ {when_clause} }};"
            );
            policy_texts.push(policy_text);
            by_id.insert(
                policy_id,
                TransitionHandle {
                    procedure_name: proc.name.clone(),
                    from_state: t.from.clone(),
                    to_state: t.to.clone(),
                    action: action_kind,
                },
            );
        }
    }

    let policy_set = parse_synthesized_set(schema, &policy_texts, "procedure transition")?;
    Ok(TransitionSyn { policy_set, by_id })
}

/// Parse a list of policy texts into a single `PolicySet`. Used by
/// each of the three synthesizers. Concatenates the texts (Cedar's
/// policy file parser accepts multiple `permit` statements separated
/// by blank lines).
fn parse_synthesized_set(
    _schema: &cedar_policy::Schema,
    texts: &[String],
    domain: &str,
) -> Result<cedar_policy::PolicySet> {
    if texts.is_empty() {
        return Ok(cedar_policy::PolicySet::new());
    }
    let combined = texts.join("\n\n");
    cedar_policy::PolicySet::from_str(&combined).map_err(|e| {
        CedarPlusError::Parse(format!(
            "synthesized {domain} policy set failed to parse: {e}"
        ))
    })
}

// =============================================================================
// Score parsing
// =============================================================================

/// Parse a `Score` string into a fixed-precision i64. Encoding:
/// `score * 10_000` so the four fractional digits Cedar's Decimal
/// admits all preserve. Returns `Err(detail)` on parse failure.
///
/// Examples: `"2.0"` → 20_000; `"-0.25"` → -2_500; `"1.2345"` →
/// 12_345. Longer fractional parts round-truncate (any digits past
/// the 4th are discarded — matches Cedar's Decimal posture).
pub(crate) fn parse_score_scaled(score: &Score) -> std::result::Result<i64, String> {
    let s = score.0.trim();
    if s.is_empty() {
        return Err("empty score string".into());
    }
    let (sign, rest) = if let Some(s) = s.strip_prefix('-') {
        (-1i64, s)
    } else {
        (1i64, s)
    };
    let (int_part, frac_part) = match rest.find('.') {
        Some(idx) => (&rest[..idx], &rest[idx + 1..]),
        None => (rest, ""),
    };
    let int_val: i64 = int_part
        .parse()
        .map_err(|e| format!("integer part {int_part:?} not parseable: {e}"))?;
    let mut frac_padded = String::with_capacity(4);
    for c in frac_part.chars().take(4) {
        if !c.is_ascii_digit() {
            return Err(format!("fractional part contains non-digit: {c}"));
        }
        frac_padded.push(c);
    }
    while frac_padded.len() < 4 {
        frac_padded.push('0');
    }
    let frac_val: i64 = frac_padded
        .parse()
        .map_err(|e| format!("fractional part {frac_padded:?} not parseable: {e}"))?;
    let scaled = int_val * 10_000 + frac_val;
    Ok(sign * scaled)
}

/// Render a fixed-precision i64 score back to a string with at most
/// four fractional digits. Strips trailing zeros but keeps at least
/// one digit after the decimal so `0` is rendered as `"0.0"` rather
/// than `"0"`.
///
/// Inverse of [`parse_score_scaled`] up to canonicalization.
pub(crate) fn render_score_scaled(scaled: i64) -> Score {
    let sign = if scaled < 0 { "-" } else { "" };
    let abs = scaled.unsigned_abs();
    let int_part = abs / 10_000;
    let frac_part = abs % 10_000;
    if frac_part == 0 {
        Score(format!("{sign}{int_part}.0"))
    } else {
        let mut frac = format!("{frac_part:04}");
        // Trim trailing zeros while keeping at least one digit.
        while frac.ends_with('0') && frac.len() > 1 {
            frac.pop();
        }
        Score(format!("{sign}{int_part}.{frac}"))
    }
}

// =============================================================================
// Named-predicate accessors used by tests (kept here so the layer_b
// synthesis module is self-contained from the engine_config types)
// =============================================================================

#[allow(dead_code)]
fn _doc_link_named_predicate(_p: NamedPredicate) {
    // Doc-only: forces the NamedPredicate import to be exercised so
    // the module compiles cleanly even when nothing else uses it.
}

// Same for ProcedureTransition (used in TransitionHandle construction
// loop but the compiler may not always see the reference).
#[allow(dead_code)]
fn _doc_link_procedure_transition(_t: ProcedureTransition) {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_score_scaled_simple_cases() {
        assert_eq!(parse_score_scaled(&Score("2.0".into())).unwrap(), 20_000);
        assert_eq!(parse_score_scaled(&Score("0.5".into())).unwrap(), 5_000);
        assert_eq!(parse_score_scaled(&Score("-0.25".into())).unwrap(), -2_500);
        assert_eq!(parse_score_scaled(&Score("1.2345".into())).unwrap(), 12_345);
        assert_eq!(parse_score_scaled(&Score("1".into())).unwrap(), 10_000);
        assert_eq!(parse_score_scaled(&Score("-1".into())).unwrap(), -10_000);
    }

    #[test]
    fn parse_score_scaled_truncates_extra_digits() {
        // Cedar's Decimal is 4 fractional digits; anything past
        // truncates rather than rounds.
        assert_eq!(
            parse_score_scaled(&Score("1.99999".into())).unwrap(),
            19_999
        );
    }

    #[test]
    fn parse_score_scaled_rejects_garbage() {
        assert!(parse_score_scaled(&Score("".into())).is_err());
        assert!(parse_score_scaled(&Score("abc".into())).is_err());
        assert!(parse_score_scaled(&Score("1.x".into())).is_err());
    }

    #[test]
    fn render_score_scaled_round_trip() {
        for raw in &["2.0", "0.5", "-0.25", "1.2345", "100.0", "-1000.5"] {
            let scaled = parse_score_scaled(&Score((*raw).into())).unwrap();
            let rendered = render_score_scaled(scaled);
            let re_scaled = parse_score_scaled(&rendered).unwrap();
            assert_eq!(scaled, re_scaled, "round-trip failed for {raw}");
        }
    }
}

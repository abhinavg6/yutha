//! Engine-side scoring rule evaluator (RFC 0011 §2 / extensions.md §2.2).
//!
//! Fires only after stock Cedar permits the request. Reuses cedar-policy's
//! `Authorizer::is_authorized` against the synthesized scoring
//! [`PolicySet`](cedar_policy::PolicySet) on
//! [`crate::loader::ActivatedConstitution`]; each matched synthesized
//! policy maps back to its source scoring rule (via the activated
//! constitution's `scoring_by_policy_id` table) and contributes its
//! score to the running total.
//!
//! Determinism guarantees per evaluation.md §3.1 + §4:
//!
//! - Score iteration follows declaration order. cedar-policy's
//!   `Response::diagnostics().reason()` returns matched policy ids in
//!   an order Cedar doesn't promise to be deterministic, so we sort
//!   the contributions by policy id (which encodes declaration order
//!   via `scoring__<name>`) before emission.
//! - Cedar expression errors → that rule contributes nothing (per
//!   evaluation.md §3.1's "expression evaluation errors count as
//!   false"). Cedar's Authorizer reports errored policies in
//!   `diagnostics().errored()`; we ignore them rather than failing
//!   the whole evaluation.
//! - Total score is integer arithmetic over the pre-scaled i64
//!   representation from [`crate::layer_b`] — no floating point.

use crate::eval::ScoreContribution;
use crate::layer_b::{render_score_scaled, LayerBArtifacts};
use crate::loader::ActivatedConstitution;

/// Result of a Layer B scoring pass.
#[derive(Debug, Clone, Default)]
pub(crate) struct ScoringOutcome {
    /// Per-rule contributions, in declaration order.
    pub(crate) contributions: Vec<ScoreContribution>,
    /// Sum of all contributions' scores, rendered back from the
    /// fixed-precision accumulator.
    pub(crate) total_scaled: i64,
}

impl ScoringOutcome {
    /// `Some(rendered_total)` when at least one contribution fired,
    /// `None` otherwise. The renderer converts the scaled i64 back
    /// to a `Score` string with 4-fractional-digit precision.
    pub(crate) fn total_score(&self) -> Option<crate::eval::Score> {
        if self.contributions.is_empty() {
            None
        } else {
            Some(render_score_scaled(self.total_scaled))
        }
    }
}

/// Run the scoring evaluator: Authorizer against the synthesized
/// scoring policy set, then map matched policy ids back to their
/// source scoring rules and accumulate.
pub(crate) fn evaluate_scoring(
    request: &cedar_policy::Request,
    entities: &cedar_policy::Entities,
    activated: &ActivatedConstitution,
) -> ScoringOutcome {
    let LayerBArtifacts {
        scoring_policy_set,
        scoring_by_policy_id,
        ..
    } = &activated.layer_b;

    if scoring_policy_set.policies().count() == 0 {
        return ScoringOutcome::default();
    }

    let authorizer = cedar_policy::Authorizer::new();
    let response = authorizer.is_authorized(request, scoring_policy_set, entities);

    // Cedar's `reason()` returns the policy ids that contributed to
    // the Allow decision. For scoring, only Allow is meaningful — a
    // scoring policy that errored or didn't match simply doesn't
    // contribute.
    let mut matched: Vec<String> = response
        .diagnostics()
        .reason()
        .map(|pid| pid.to_string())
        .collect();
    matched.sort(); // Declaration order via "scoring__<name>" id prefix.

    let mut total_scaled: i64 = 0;
    let mut contributions = Vec::with_capacity(matched.len());
    for policy_id in &matched {
        let Some(handle) = scoring_by_policy_id.get(policy_id) else {
            // Unknown policy id — defensive, shouldn't happen.
            // Skip silently; the scoring pass stays deterministic.
            continue;
        };
        // Saturating arithmetic so a pathological score sum doesn't
        // overflow into evaluator_internal_error. Real swarms won't
        // hit this; the saturating bound protects against bugs.
        total_scaled = total_scaled.saturating_add(handle.score_scaled);
        contributions.push(ScoreContribution {
            rule_id: handle.rule_name.clone(),
            score: handle.score.clone(),
        });
    }

    ScoringOutcome {
        contributions,
        total_scaled,
    }
}

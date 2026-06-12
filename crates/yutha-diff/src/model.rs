//! Top-level data model: [`ConstitutionDiff`] + [`NamedItemsDiff`].
//!
//! All shapes here are pure data — no compute, no I/O. Both sides of
//! the diff are kept by value in the `modified` arms so renderers
//! have the full pre/post available for field-level rendering.

use serde::{Deserialize, Serialize};
use yutha_cedar_plus::engine_config::{EnforcementRule, NamedPredicate, Procedure, ScoringRule};

use crate::behavioural::BehaviouralDiff;
use crate::cedar::CedarPolicyEntry;

/// The top-level diff value.
///
/// Sections render in this order in all output formats:
///
/// 1. Schema-version change (if any) — always first because it
///    contextualises every subsequent diff.
/// 2. Cedar policies — the load-bearing surface for gating
///    decisions.
/// 3. Named predicates — referenced by everything else, so changes
///    here ripple into scoring / procedures / enforcement.
/// 4. Scoring rules.
/// 5. Procedures.
/// 6. Enforcement rules.
/// 7. Behavioural diff (when populated by 3d-G `--against-window`).
///
/// Empty sections are preserved (`added`/`removed`/`modified` all
/// empty) so consumers can detect "no change" vs "section not in
/// scope" unambiguously.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstitutionDiff {
    /// Stable schema marker for the diff format. Bumped if the JSON
    /// shape ever evolves; consumers SHOULD check it before parsing.
    /// Current value: `"yutha-diff/v1"`.
    pub diff_schema_version: String,

    /// Left-side constitution version string. Convenience for
    /// renderers; not load-bearing.
    pub left_constitution_version: String,
    /// Right-side constitution version string.
    pub right_constitution_version: String,

    /// `Some((from, to))` when the two constitutions pin different
    /// Cedar+ schema versions. `None` when they match.
    pub schema_version_change: Option<(String, String)>,

    /// Cedar policy diff, keyed by `PolicyId` (the `@id` annotation
    /// when present; structural fallback otherwise — see
    /// [`crate::cedar`] for the matching policy).
    pub cedar_policies: NamedItemsDiff<CedarPolicyEntry>,

    /// Named-predicate diff, keyed by `.name`.
    pub named_predicates: NamedItemsDiff<NamedPredicate>,

    /// Scoring-rule diff, keyed by `.name`.
    pub scoring_rules: NamedItemsDiff<ScoringRule>,

    /// Procedure diff, keyed by `.name`.
    pub procedures: NamedItemsDiff<Procedure>,

    /// Enforcement-rule diff, keyed by `.name`.
    pub enforcement_rules: NamedItemsDiff<EnforcementRule>,

    /// Behavioural diff populated by `yutha-ops diff
    /// --against-window`. `None` for static-only diffs.
    pub behavioural: Option<BehaviouralDiff>,
}

impl ConstitutionDiff {
    /// `true` when no structural section reports any change. The
    /// behavioural diff (if populated) is intentionally excluded —
    /// `is_empty_structurally` is the right predicate for "should
    /// this diff gate a PR?".
    pub fn is_empty_structurally(&self) -> bool {
        self.schema_version_change.is_none()
            && self.cedar_policies.is_empty()
            && self.named_predicates.is_empty()
            && self.scoring_rules.is_empty()
            && self.procedures.is_empty()
            && self.enforcement_rules.is_empty()
    }
}

/// Add/remove/modify triple for a named-item collection. Generic
/// over the item type; same shape used for all five section types
/// (cedar policies + the four engine-config item types).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedItemsDiff<T> {
    /// Items present in the right-side constitution but not the left.
    pub added: Vec<T>,
    /// Items present in the left-side constitution but not the right.
    pub removed: Vec<T>,
    /// Items present on both sides but with different
    /// canonical-byte representations.
    pub modified: Vec<NamedItemChange<T>>,
}

impl<T> NamedItemsDiff<T> {
    /// `true` when none of `added` / `removed` / `modified` has any
    /// entries.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }
}

impl<T> Default for NamedItemsDiff<T> {
    fn default() -> Self {
        Self {
            added: Vec::new(),
            removed: Vec::new(),
            modified: Vec::new(),
        }
    }
}

/// One modified-item entry: same name on both sides, different
/// canonical bytes. Both pre and post are retained for field-level
/// rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedItemChange<T> {
    /// The name (or `PolicyId`) shared by both sides.
    pub name: String,
    /// Left-side value.
    pub left: T,
    /// Right-side value.
    pub right: T,
}

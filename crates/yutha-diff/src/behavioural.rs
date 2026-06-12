//! Behavioural-diff data model (RFC 0018 §4 replay composition).
//!
//! Phase 3d-B ships the data shape only — populating it requires
//! running a replay session via the gRPC ReplayService and is the
//! call site's responsibility (3d-G in `yutha-ops`). The data model
//! is here so renderers (3d-C / 3d-D / 3d-E) can format it without
//! depending on the gRPC layer.
//!
//! Per the 3d-A scope-lock, behavioural-diff surfaces two sections:
//!
//! 1. Side-by-side receipt counts by `action_kind` + `subject_agent_id`.
//!    Production-store counts vs candidate-session-store counts over
//!    the same time window.
//! 2. Enforcement chain divergences. New `enforcement.{detect, coach,
//!    quarantine, evict, reverse}` receipts the candidate would have
//!    emitted that production didn't, keyed by
//!    `target_agent_id` + `enforcement_rule_id`.
//!
//! Per-envelope deny/permit join (where production permitted but
//! candidate would deny) was explicitly deferred at 3d-A scope-lock.

use serde::{Deserialize, Serialize};

/// Behavioural diff: receipt counts + enforcement chain divergences
/// over a replay window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviouralDiff {
    /// Inclusive lower bound of the replay window (`monotonic_ns`).
    pub window_from_unix_ns: u64,
    /// Inclusive upper bound of the replay window (`monotonic_ns`).
    pub window_to_unix_ns: u64,
    /// The replay session id that produced these numbers. Carries
    /// through to renderers as a join key back into the audit
    /// `replay.session.create` receipt.
    pub replay_session_id: String,
    /// Side-by-side receipt counts. One entry per (`action_kind`,
    /// `subject_agent_id`) pair observed in either store. Empty when
    /// neither store had matching receipts in the window.
    pub receipt_count_deltas: Vec<ReceiptCountDelta>,
    /// Enforcement chain divergences — `enforcement.*` receipts the
    /// candidate would have emitted that production didn't (or
    /// production-only emissions, when the candidate is more
    /// permissive). Keyed by (target_agent_id, enforcement_rule_id,
    /// stage).
    pub chain_divergences: Vec<ChainDivergence>,
}

/// One side-by-side receipt-count row.
///
/// Both counts are present even when zero on a side — renderers use
/// the deltas to highlight rows where the candidate diverges from
/// production.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptCountDelta {
    /// `action_kind` of the matched receipts (e.g.
    /// `"constitution.evaluate.deny"`, `"enforcement.detect"`).
    pub action_kind: String,
    /// Subject agent id surfaced via the `subject_agent_id`
    /// evidence key. Empty string when the receipt lacks one
    /// (e.g. global system receipts).
    pub subject_agent_id: String,
    /// Count from the production receipt store.
    pub production_count: u64,
    /// Count from the candidate session's receipt store.
    pub candidate_count: u64,
}

impl ReceiptCountDelta {
    /// Convenience: `candidate_count - production_count` as an
    /// `i64`. Positive when the candidate would emit MORE receipts
    /// than production; negative when fewer.
    pub fn delta(&self) -> i64 {
        self.candidate_count as i64 - self.production_count as i64
    }

    /// Convenience: `true` when production and candidate counts
    /// match. Renderers may skip such rows in summary tables.
    pub fn is_unchanged(&self) -> bool {
        self.production_count == self.candidate_count
    }
}

/// One enforcement-chain divergence row.
///
/// The chain produces `enforcement.{detect, coach, quarantine, evict,
/// reverse}` receipts; this struct surfaces a single stage emission
/// that differs between production and candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainDivergence {
    /// Target agent the enforcement chain fired against (via the
    /// `target_agent_id` evidence on the receipt).
    pub target_agent_id: String,
    /// `enforcement_rule_id` the firing rule was named with (the
    /// `name` field on the candidate constitution's
    /// `enforcement_rules` entry).
    pub enforcement_rule_id: String,
    /// Stage that diverged: one of `"detect"`, `"coach"`,
    /// `"quarantine"`, `"evict"`, `"reverse"`. Maps 1:1 to the
    /// canonical action-kind suffix in `enforcement.*`.
    pub stage: String,
    /// How many of this stage's receipts production emitted in the
    /// window.
    pub production_count: u64,
    /// How many the candidate's session emitted.
    pub candidate_count: u64,
}

impl ChainDivergence {
    /// `candidate_count - production_count`. Positive = candidate
    /// would emit additional stage receipts (the rule-tightening
    /// case operators usually preview); negative = candidate would
    /// emit fewer (rule-loosening case).
    pub fn delta(&self) -> i64 {
        self.candidate_count as i64 - self.production_count as i64
    }
}

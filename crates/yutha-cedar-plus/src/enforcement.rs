//! Enforcement engine — receipt-stream-driven four-stage loop
//! (RFC 0013 / enforcement.md).
//!
//! # Architecture
//!
//! The engine is a long-lived stateful object held by the control
//! plane. It maintains three pieces of state:
//!
//! 1. **Per-rule sliding-window counters** — for each
//!    `enforcement_rules` entry, a (group_key → recent matching
//!    receipts) map. Used to fire `enforcement.detect` when
//!    `count_threshold` is met within `time_window`.
//! 2. **Per-agent enforcement stage + reputation** — the agent's
//!    current stage in the loop (`Detect` / `Coach` / `Quarantine`
//!    / `Evict`) plus reputation scalar accumulated from prior
//!    `enforcement.*` receipts. Cap-layer consults
//!    [`Self::is_agent_quarantined`]; scoring rules read
//!    [`Self::agent_reputation`].
//! 3. **Scheduled stage transitions** — a min-heap of
//!    `(fire_at_wall_clock, ScheduledAction)`. Poll-driven (F10
//!    integration drives the polling); not persistent in v1.1.
//!
//! # Interfaces
//!
//! [`EnforcementEngine::on_receipt`] is called by the control plane
//! once per landing receipt. Returns 0..N [`EnforcementEffect`]s —
//! the caller emits them as new receipts (which then feed back into
//! `on_receipt` on the next call, producing reputation updates and
//! quarantine state changes).
//!
//! [`EnforcementEngine::poll_scheduled`] is called periodically (or
//! after wall-clock advance) to fire stage transitions whose
//! scheduled time has passed.
//!
//! [`EnforcementEngine::is_agent_quarantined`] and
//! [`EnforcementEngine::agent_reputation`] are the synchronous-read
//! queries the cap layer + scoring layer use to consult enforcement
//! state during evaluation.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::RwLock;

use crate::engine_config::EnforcementRule;
use crate::eval::Score;
use crate::layer_b::{parse_score_scaled, render_score_scaled};
use crate::loader::ActivatedConstitution;

// =============================================================================
// Public types
// =============================================================================

/// Read-only view of a receipt the control plane just emitted (or
/// just landed from an external source). Carries only the fields
/// the enforcement engine pattern-matches on; the full receipt
/// remains in the receipt store.
#[derive(Debug, Clone)]
pub struct ReceiptView<'a> {
    /// The receipt's action kind (e.g. `"constitution.evaluate.deny"`).
    pub action_kind: &'a str,
    /// The principal the receipt is about, if applicable. For
    /// `constitution.evaluate.deny` this is the request's principal.
    pub principal_id: Option<&'a str>,
    /// Optional `deny_reason` filter target (for
    /// `constitution.evaluate.deny` receipts).
    pub deny_reason: Option<&'a str>,
    /// Optional `forbid_rule_id` filter target.
    pub forbid_rule_id: Option<&'a str>,
    /// Receipt's monotonic timestamp (nanoseconds since epoch). Used
    /// for sliding-window pruning.
    pub occurred_at_unix_ns: u64,
    /// Receipt's wall-clock timestamp (RFC 3339). Used as the
    /// reference time for stage-progression scheduling — fresh
    /// detects schedule coaching at `occurred_at + cooldown`.
    pub occurred_at_wall_clock: &'a str,
    /// Reputation delta carried by the receipt (for
    /// `enforcement.*` receipts that the engine itself produced
    /// in a previous call). Used by the reputation accumulator.
    pub reputation_delta: Option<Score>,
}

/// An enforcement action the engine staged. The caller is
/// responsible for emitting the corresponding receipt.
#[derive(Debug, Clone)]
pub struct EnforcementEffect {
    /// One of: `enforcement.detect` / `.coach` / `.quarantine` /
    /// `.evict` / `.reverse` / `.evict_timeout`.
    pub action_kind: String,
    /// The agent the enforcement targets.
    pub target_agent_id: String,
    /// The originating enforcement-rule name.
    pub enforcement_rule_id: String,
    /// Reputation delta this stage applies (per-rule deltas in
    /// `EnforcementRule.reputation_delta`, falling back to spec
    /// defaults from enforcement.md §7.2).
    pub reputation_delta: Score,
    /// Additional evidence the engine surfaces for the caller to
    /// embed in the receipt. Keys + values mirror the
    /// canonical-actions evidence shape (e.g. `matched_receipt_ids`,
    /// `detect_receipt_id`, `coach_receipt_id`).
    pub additional_evidence: BTreeMap<String, Value>,
}

// =============================================================================
// Internal state
// =============================================================================

/// Default initial reputation for a freshly-seen agent. Per
/// enforcement.md §7.1.
const INITIAL_REPUTATION_SCALED: i64 = 10_000; // = 1.0 at 4-decimal scale
/// Reputation clamp range (scaled). Default `[0.0, 1.0]`.
const MIN_REPUTATION_SCALED: i64 = 0;
const MAX_REPUTATION_SCALED: i64 = 10_000;

/// Per-agent enforcement state.
#[derive(Debug, Clone, Default)]
struct AgentState {
    /// Reputation scalar as fixed-precision i64 × 10_000 (same
    /// encoding as [`crate::layer_b::ScoringRuleHandle::score_scaled`]).
    reputation_scaled: i64,
    /// Most recently observed stage for this agent. `None` means
    /// the agent has never tripped a rule.
    current_stage: Option<Stage>,
    /// Whether the agent is currently quarantined.
    quarantined: bool,
}

impl AgentState {
    fn initial() -> Self {
        Self {
            reputation_scaled: INITIAL_REPUTATION_SCALED,
            current_stage: None,
            quarantined: false,
        }
    }
}

/// The four enforcement stages.
///
/// `Quarantine` and `Evict` only land on the scheduled queue once F10
/// wires the receipt-emission feedback loop — when coach fires and
/// the control plane emits an `enforcement.coach` receipt that feeds
/// back into `on_receipt`, the engine schedules the next stage.
/// Until that loop closes, the variants are reachable via
/// [`Stage::action_kind`] and [`build_stage_effect`] but never
/// constructed at runtime, hence the dead-code allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum Stage {
    Detect,
    Coach,
    Quarantine,
    Evict,
}

impl Stage {
    fn action_kind(&self) -> &'static str {
        match self {
            Stage::Detect => "enforcement.detect",
            Stage::Coach => "enforcement.coach",
            Stage::Quarantine => "enforcement.quarantine",
            Stage::Evict => "enforcement.evict",
        }
    }
}

/// Sliding-window counter entry for a single (rule_name, group_key)
/// bucket.
#[derive(Debug, Clone, Default)]
struct CounterBucket {
    /// Monotonic timestamps (nanoseconds) of recent matching
    /// receipts within the window. Newest first.
    timestamps_ns: Vec<u64>,
}

impl CounterBucket {
    fn prune(&mut self, now_ns: u64, window_ns: u64) {
        if now_ns < window_ns {
            // Underflow guard — clock skew at the very start.
            return;
        }
        let cutoff = now_ns - window_ns;
        self.timestamps_ns.retain(|t| *t >= cutoff);
    }
}

/// A scheduled stage transition that will fire when wall-clock
/// reaches `fire_at_wall_clock`.
#[derive(Debug, Clone)]
struct ScheduledAction {
    fire_at_wall_clock: String,
    target_agent_id: String,
    enforcement_rule_id: String,
    stage: Stage,
}

// =============================================================================
// The engine
// =============================================================================

/// The enforcement engine. Construct one per swarm (or one shared
/// across swarms with separate state if/when multi-swarm support
/// arrives in Phase 4).
///
/// All state is held behind a single `RwLock` for simplicity at
/// v1.1; F10 integration may break this up into finer-grained locks
/// once contention is measurable.
pub struct EnforcementEngine {
    inner: RwLock<EngineState>,
}

struct EngineState {
    /// The currently-active constitution. Changes on
    /// [`EnforcementEngine::activate`]; rule counters reset on each
    /// activation (per enforcement.md §2.4 — patterns don't trigger
    /// on receipts from prior constitution versions unless the rule
    /// opts into `historical: true`).
    active: Option<Arc<ActivatedConstitution>>,
    /// Per-agent reputation + stage + quarantine state.
    agents: HashMap<String, AgentState>,
    /// Sliding-window counters keyed on (rule_name, group_key).
    counters: HashMap<(String, String), CounterBucket>,
    /// Stage transitions scheduled for future wall-clock instants.
    /// Sorted by fire_at_wall_clock so `poll_scheduled` can early-
    /// out once the earliest scheduled entry is in the future.
    scheduled: Vec<ScheduledAction>,
}

impl EngineState {
    fn fresh() -> Self {
        Self {
            active: None,
            agents: HashMap::new(),
            counters: HashMap::new(),
            scheduled: Vec::new(),
        }
    }
}

impl Default for EnforcementEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl EnforcementEngine {
    /// Construct a fresh engine. No active constitution; agents map
    /// empty; counters empty.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(EngineState::fresh()),
        }
    }

    /// Bind a freshly-activated constitution to the engine. Resets
    /// rule counters (per enforcement.md §2.4); preserves reputation,
    /// agent stages, quarantine state, and any in-flight scheduled
    /// transitions per RFC 0013 §7 (amendment doesn't clear in-flight
    /// enforcement).
    pub async fn activate(&self, constitution: Arc<ActivatedConstitution>) {
        let mut state = self.inner.write().await;
        state.active = Some(constitution);
        state.counters.clear();
    }

    /// Process a freshly-landed receipt. Returns any enforcement
    /// effects the receipt triggered. The caller is responsible
    /// for emitting them as new receipts.
    pub async fn on_receipt(&self, receipt: ReceiptView<'_>) -> Vec<EnforcementEffect> {
        let mut state = self.inner.write().await;

        // First: reputation accumulation. enforcement.* receipts
        // we previously emitted come back here and shift the target
        // agent's reputation.
        if receipt.action_kind.starts_with("enforcement.") {
            if let Some(principal) = receipt.principal_id {
                if let Some(delta) = &receipt.reputation_delta {
                    apply_reputation_delta(&mut state, principal, delta);
                }
                // Quarantine state transitions follow the receipt
                // kind. enforcement.quarantine sets quarantined =
                // true; enforcement.reverse + enforcement.evict
                // clear it (evict because the agent is gone; reverse
                // because the quarantine is lifted).
                match receipt.action_kind {
                    "enforcement.quarantine" => set_quarantine(&mut state, principal, true),
                    "enforcement.reverse" | "enforcement.evict" => {
                        set_quarantine(&mut state, principal, false)
                    }
                    _ => {}
                }
            }
            // enforcement.* receipts don't themselves trigger more
            // enforcement (no second-order rules in v1.1).
            return Vec::new();
        }

        // Second: pattern-match the receipt against every active
        // enforcement_rules entry.
        let Some(active) = state.active.clone() else {
            return Vec::new();
        };
        let mut effects = Vec::new();
        for rule in &active.resolved_engine_config.enforcement_rules {
            if let Some(effect) = check_detect(&mut state, rule, &receipt) {
                effects.push(effect);
            }
        }

        effects
    }

    /// True iff the agent is currently quarantined. Cap-layer
    /// consults this on every check.
    pub async fn is_agent_quarantined(&self, agent_id: &str) -> bool {
        let state = self.inner.read().await;
        state.agents.get(agent_id).is_some_and(|a| a.quarantined)
    }

    /// Current reputation scalar for the agent, rendered as a
    /// Decimal string. Agents the engine has never seen return the
    /// default initial reputation (`"1.0"`).
    pub async fn agent_reputation(&self, agent_id: &str) -> Score {
        let state = self.inner.read().await;
        let scaled = state
            .agents
            .get(agent_id)
            .map(|a| a.reputation_scaled)
            .unwrap_or(INITIAL_REPUTATION_SCALED);
        render_score_scaled(scaled)
    }

    /// Poll the scheduled-transitions queue. Any transitions whose
    /// `fire_at_wall_clock` is ≤ `now` fire and their effects are
    /// returned. The control plane drives this after wall-clock
    /// advance (typically once per second).
    pub async fn poll_scheduled(&self, now: &str) -> Vec<EnforcementEffect> {
        let mut state = self.inner.write().await;
        let mut effects = Vec::new();
        let mut still_pending = Vec::new();
        for entry in std::mem::take(&mut state.scheduled) {
            if entry.fire_at_wall_clock.as_str() <= now {
                if let Some(effect) = build_stage_effect(&entry, &state) {
                    effects.push(effect);
                }
            } else {
                still_pending.push(entry);
            }
        }
        state.scheduled = still_pending;
        effects
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn apply_reputation_delta(state: &mut EngineState, agent_id: &str, delta: &Score) {
    let agent = state
        .agents
        .entry(agent_id.to_string())
        .or_insert_with(AgentState::initial);
    if let Ok(delta_scaled) = parse_score_scaled(delta) {
        agent.reputation_scaled = (agent.reputation_scaled.saturating_add(delta_scaled))
            .clamp(MIN_REPUTATION_SCALED, MAX_REPUTATION_SCALED);
    }
}

fn set_quarantine(state: &mut EngineState, agent_id: &str, quarantined: bool) {
    let agent = state
        .agents
        .entry(agent_id.to_string())
        .or_insert_with(AgentState::initial);
    agent.quarantined = quarantined;
}

/// Match a single enforcement rule against a single receipt and
/// either bump the rule's counter or fire a detect effect.
fn check_detect(
    state: &mut EngineState,
    rule: &EnforcementRule,
    receipt: &ReceiptView<'_>,
) -> Option<EnforcementEffect> {
    // Trigger filters.
    if receipt.action_kind != rule.detect.trigger.receipt_kind {
        return None;
    }
    if let Some(want) = &rule.detect.trigger.deny_reason {
        if receipt.deny_reason != Some(want.as_str()) {
            return None;
        }
    }
    if let Some(want) = &rule.detect.trigger.forbid_rule_id {
        if receipt.forbid_rule_id != Some(want.as_str()) {
            return None;
        }
    }

    // Determine the group key per `detect.group_by`.
    let group_key = match rule.detect.group_by.as_str() {
        "principal" => receipt.principal_id.unwrap_or("").to_string(),
        "none" => String::new(),
        _ => receipt.principal_id.unwrap_or("").to_string(), // default to principal
    };

    let window_ns = parse_window_ns(&rule.detect.time_window).unwrap_or(60_000_000_000);
    let counter = state
        .counters
        .entry((rule.name.clone(), group_key.clone()))
        .or_default();
    counter.prune(receipt.occurred_at_unix_ns, window_ns);
    counter.timestamps_ns.push(receipt.occurred_at_unix_ns);
    if (counter.timestamps_ns.len() as u32) < rule.detect.count_threshold {
        return None;
    }

    // Threshold met → fire detect.
    let matched_timestamps: Vec<Value> = counter
        .timestamps_ns
        .iter()
        .map(|ts| Value::String(ts.to_string()))
        .collect();
    let mut evidence: BTreeMap<String, Value> = BTreeMap::new();
    evidence.insert(
        "matched_timestamps_ns".into(),
        Value::Array(matched_timestamps),
    );
    evidence.insert("group_key".into(), Value::String(group_key.clone()));
    evidence.insert(
        "pattern_summary".into(),
        Value::String(format!(
            "{}+ matches of {} in {}",
            rule.detect.count_threshold, rule.detect.trigger.receipt_kind, rule.detect.time_window
        )),
    );

    // Reset the counter — once detect fires, we re-arm.
    counter.timestamps_ns.clear();

    // Default detect reputation delta is -0.05 per enforcement.md
    // §7.2 unless the rule overrides.
    let delta = rule
        .reputation_delta
        .get("detect")
        .cloned()
        .unwrap_or_else(|| Score("-0.05".into()));

    let target = group_key.clone();
    // Track stage on the agent.
    if !target.is_empty() {
        let agent = state
            .agents
            .entry(target.clone())
            .or_insert_with(AgentState::initial);
        agent.current_stage = Some(Stage::Detect);
    }

    // Schedule the coach transition if the rule declares one.
    if let Some(coach) = &rule.coach {
        if let Some(fire_at) = compute_fire_at(receipt.occurred_at_wall_clock, &coach.cooldown) {
            state.scheduled.push(ScheduledAction {
                fire_at_wall_clock: fire_at,
                target_agent_id: target.clone(),
                enforcement_rule_id: rule.name.clone(),
                stage: Stage::Coach,
            });
        }
    }
    // F10 schedules quarantine + evict from the coach/quarantine
    // fire-paths once stage-emission becomes a feedback loop via the
    // control-plane receipt subscriber.

    Some(EnforcementEffect {
        action_kind: Stage::Detect.action_kind().into(),
        target_agent_id: target,
        enforcement_rule_id: rule.name.clone(),
        reputation_delta: delta,
        additional_evidence: evidence,
    })
}

/// Build the effect for a scheduled stage transition that just
/// fired. Currently keeps the same effect shape across all four
/// stages; refinements (specific evidence per stage) land in F10.
fn build_stage_effect(action: &ScheduledAction, _state: &EngineState) -> Option<EnforcementEffect> {
    Some(EnforcementEffect {
        action_kind: action.stage.action_kind().into(),
        target_agent_id: action.target_agent_id.clone(),
        enforcement_rule_id: action.enforcement_rule_id.clone(),
        // Default per-stage deltas from enforcement.md §7.2.
        reputation_delta: Score(
            match action.stage {
                Stage::Detect => "-0.05",
                Stage::Coach => "0.0",
                Stage::Quarantine => "-0.25",
                Stage::Evict => "-1.0",
            }
            .into(),
        ),
        additional_evidence: BTreeMap::new(),
    })
}

/// Parse a duration string (`"30s"`, `"5m"`, `"1h"`) into ns. Returns
/// `None` on malformed input — the loader already validated these
/// at constitution-activate time, so a runtime failure is genuinely
/// surprising and we conservatively skip the rule rather than panic.
fn parse_window_ns(s: &str) -> Option<u64> {
    let s = s.trim();
    let split_at = s.rfind(|c: char| c.is_ascii_digit())? + 1;
    if split_at >= s.len() {
        return None;
    }
    let num: u64 = s[..split_at].parse().ok()?;
    let unit = &s[split_at..];
    let secs = match unit {
        "ms" => return num.checked_mul(1_000_000),
        "s" => num,
        "m" => num.checked_mul(60)?,
        "h" => num.checked_mul(60 * 60)?,
        "d" => num.checked_mul(60 * 60 * 24)?,
        _ => return None,
    };
    secs.checked_mul(1_000_000_000)
}

/// Compute `now_wall_clock + duration` as an RFC 3339 string. Used
/// to schedule stage transitions. F9 uses a conservative
/// approximation that depends on the wall-clock string being
/// lexically comparable (which RFC 3339 in UTC is) — the actual
/// time math happens by adding to a parsed instant.
///
/// Returns `None` if the wall-clock can't be parsed; the caller
/// skips scheduling in that case.
fn compute_fire_at(now_wall_clock: &str, duration_str: &str) -> Option<String> {
    let dur_ns = parse_window_ns(duration_str)?;
    let dur = Duration::from_nanos(dur_ns);
    // Use the `time` crate (already a workspace dep) for RFC 3339
    // arithmetic.
    let parsed = time::OffsetDateTime::parse(
        now_wall_clock,
        &time::format_description::well_known::Rfc3339,
    )
    .ok()?;
    let fire_at = parsed.checked_add(time::Duration::nanoseconds(dur.as_nanos() as i64))?;
    fire_at
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_config::{DetectConfig, DetectTrigger, EnforcementRule};

    fn rule_for_pii_pattern() -> EnforcementRule {
        EnforcementRule {
            name: "repeat_pii".into(),
            detect: DetectConfig {
                trigger: DetectTrigger {
                    receipt_kind: "constitution.evaluate.deny".into(),
                    deny_reason: Some("forbid_rule_matched".into()),
                    forbid_rule_id: Some("forbid_pii".into()),
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
        }
    }

    fn make_receipt<'a>(
        action_kind: &'a str,
        principal: &'a str,
        deny_reason: Option<&'a str>,
        forbid_rule_id: Option<&'a str>,
        now_ns: u64,
    ) -> ReceiptView<'a> {
        ReceiptView {
            action_kind,
            principal_id: Some(principal),
            deny_reason,
            forbid_rule_id,
            occurred_at_unix_ns: now_ns,
            occurred_at_wall_clock: "2026-05-15T00:00:00Z",
            reputation_delta: None,
        }
    }

    fn state_with_rule(_rule: EnforcementRule) -> EngineState {
        // Tests bypass on_receipt's activation requirement by
        // driving check_detect against the rule directly — building
        // a real ActivatedConstitution requires a parsed Cedar
        // schema + PolicySet, which is overkill for the rule-
        // matching tests. Activation-driven coverage lives in F10's
        // integration suite where the control plane assembles the
        // full constitution.
        EngineState::fresh()
    }

    #[test]
    fn below_threshold_doesnt_fire() {
        let rule = rule_for_pii_pattern();
        let mut state = state_with_rule(rule.clone());
        let r1 = make_receipt(
            "constitution.evaluate.deny",
            "alice",
            Some("forbid_rule_matched"),
            Some("forbid_pii"),
            1_000_000_000,
        );
        let r2 = make_receipt(
            "constitution.evaluate.deny",
            "alice",
            Some("forbid_rule_matched"),
            Some("forbid_pii"),
            2_000_000_000,
        );
        assert!(check_detect(&mut state, &rule, &r1).is_none());
        assert!(check_detect(&mut state, &rule, &r2).is_none());
    }

    #[test]
    fn threshold_fires_detect() {
        let rule = rule_for_pii_pattern();
        let mut state = state_with_rule(rule.clone());
        for i in 1..=3 {
            let r = make_receipt(
                "constitution.evaluate.deny",
                "alice",
                Some("forbid_rule_matched"),
                Some("forbid_pii"),
                (i as u64) * 1_000_000_000,
            );
            let res = check_detect(&mut state, &rule, &r);
            if i == 3 {
                let effect = res.expect("threshold met");
                assert_eq!(effect.action_kind, "enforcement.detect");
                assert_eq!(effect.target_agent_id, "alice");
                assert_eq!(effect.enforcement_rule_id, "repeat_pii");
            } else {
                assert!(res.is_none());
            }
        }
    }

    #[test]
    fn per_principal_isolation() {
        let rule = rule_for_pii_pattern();
        let mut state = state_with_rule(rule.clone());
        // Alice and Bob each get 2 hits — neither should fire.
        for (i, who) in [(1, "alice"), (2, "bob"), (3, "alice"), (4, "bob")] {
            let r = make_receipt(
                "constitution.evaluate.deny",
                who,
                Some("forbid_rule_matched"),
                Some("forbid_pii"),
                (i as u64) * 1_000_000_000,
            );
            assert!(check_detect(&mut state, &rule, &r).is_none());
        }
    }

    #[test]
    fn non_matching_action_kind_doesnt_count() {
        let rule = rule_for_pii_pattern();
        let mut state = state_with_rule(rule.clone());
        for i in 1..=5 {
            let r = make_receipt(
                "envelope.send", // doesn't match rule trigger
                "alice",
                None,
                None,
                (i as u64) * 1_000_000_000,
            );
            assert!(check_detect(&mut state, &rule, &r).is_none());
        }
    }

    #[test]
    fn window_pruning_resets_counter() {
        let rule = rule_for_pii_pattern();
        let mut state = state_with_rule(rule.clone());
        // Two hits at t=0, then a hit at t = 11 minutes (window
        // is 10 min) — the new hit should be alone in the bucket.
        let r1 = make_receipt(
            "constitution.evaluate.deny",
            "alice",
            Some("forbid_rule_matched"),
            Some("forbid_pii"),
            0,
        );
        let r2 = make_receipt(
            "constitution.evaluate.deny",
            "alice",
            Some("forbid_rule_matched"),
            Some("forbid_pii"),
            1_000_000_000,
        );
        let r3 = make_receipt(
            "constitution.evaluate.deny",
            "alice",
            Some("forbid_rule_matched"),
            Some("forbid_pii"),
            11 * 60 * 1_000_000_000, // 11 minutes
        );
        assert!(check_detect(&mut state, &rule, &r1).is_none());
        assert!(check_detect(&mut state, &rule, &r2).is_none());
        assert!(check_detect(&mut state, &rule, &r3).is_none()); // counter pruned, only r3 remains
    }

    #[test]
    fn parse_window_ns_handles_units() {
        assert_eq!(parse_window_ns("30s"), Some(30 * 1_000_000_000));
        assert_eq!(parse_window_ns("5m"), Some(5 * 60 * 1_000_000_000));
        assert_eq!(parse_window_ns("1h"), Some(3600 * 1_000_000_000));
        assert_eq!(parse_window_ns("100ms"), Some(100 * 1_000_000));
        assert_eq!(parse_window_ns("garbage"), None);
    }

    #[test]
    fn compute_fire_at_adds_duration() {
        let result = compute_fire_at("2026-05-15T00:00:00Z", "30s");
        let result = result.expect("parses");
        assert!(result.starts_with("2026-05-15T00:00:30"));
    }

    #[tokio::test]
    async fn reputation_default_is_full() {
        let engine = EnforcementEngine::new();
        assert_eq!(engine.agent_reputation("alice").await, Score("1.0".into()));
    }

    #[tokio::test]
    async fn quarantine_default_false() {
        let engine = EnforcementEngine::new();
        assert!(!engine.is_agent_quarantined("alice").await);
    }
}

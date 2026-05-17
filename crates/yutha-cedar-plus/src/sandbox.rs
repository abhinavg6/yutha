//! Sandbox bounds and bound-exceeded handling (RFC 0012 §5).
//!
//! Per-evaluation resource limits the constitution evaluator enforces:
//! wall-clock time (action-specific), entity-snapshot size, scoring rule
//! count, procedure count, open-procedure-instance examination cap, Cedar
//! policy count + max policy depth (load-time, Yutha-side).
//!
//! Bound-exceeded outcomes map 1:1 onto the `deny_reason` enum entries
//! from evaluation.md §5.2 and the [`crate::error::EvalBoundReason`] /
//! [`crate::error::LoadBoundReason`] enums.
//!
//! F5 scaffold. F7 (evaluator integration) wires the bound checks into
//! the eval entry point.

use std::time::Duration;

/// Per-swarm sandbox configuration. Defaults match the values in
/// evaluation.md §5.1; operators override via topology config.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SandboxConfig {
    /// Default 10 ms per RFC 0012 §3.3 after the F3 tightening pass.
    pub send_envelope_max_time: Duration,
    /// Default 100 ms.
    pub other_action_max_time: Duration,
    /// Default 1,000.
    pub max_entity_count: usize,
    /// Default 1,000.
    pub max_scoring_rules: usize,
    /// Default 100.
    pub max_procedures: usize,
    /// Default 100.
    pub max_open_procedure_instances_examined: usize,
    /// Default 1,000.
    pub max_cedar_policies: usize,
    /// Default 16 (Yutha-side load-time check). Cedar's internal 64
    /// is the substrate ceiling we can't reach into.
    pub max_policy_depth_at_load: u32,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            send_envelope_max_time: Duration::from_millis(10),
            other_action_max_time: Duration::from_millis(100),
            max_entity_count: 1_000,
            max_scoring_rules: 1_000,
            max_procedures: 100,
            max_open_procedure_instances_examined: 100,
            max_cedar_policies: 1_000,
            max_policy_depth_at_load: 16,
        }
    }
}

impl SandboxConfig {
    /// Pick the wall-clock cap for an evaluation based on its action
    /// kind. Hot-path actions (currently `SendEnvelope` only) get the
    /// tighter bound; everything else gets the looser bound.
    #[allow(dead_code)]
    pub fn max_time_for(&self, action_kind: &str) -> Duration {
        if action_kind == "SendEnvelope" {
            self.send_envelope_max_time
        } else {
            self.other_action_max_time
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bounds_match_spec() {
        // RFC 0012 §3.3 — these are the post-F3-tightening defaults.
        // If you change them here, update evaluation.md §5.1 and the
        // RFC, and notify Workstream A (the spec is the contract).
        let cfg = SandboxConfig::default();
        assert_eq!(cfg.send_envelope_max_time, Duration::from_millis(10));
        assert_eq!(cfg.other_action_max_time, Duration::from_millis(100));
        assert_eq!(cfg.max_entity_count, 1_000);
        assert_eq!(cfg.max_scoring_rules, 1_000);
        assert_eq!(cfg.max_procedures, 100);
        assert_eq!(cfg.max_open_procedure_instances_examined, 100);
        assert_eq!(cfg.max_cedar_policies, 1_000);
        assert_eq!(cfg.max_policy_depth_at_load, 16);
    }

    #[test]
    fn hot_path_bound_routing() {
        let cfg = SandboxConfig::default();
        assert_eq!(cfg.max_time_for("SendEnvelope"), Duration::from_millis(10));
        assert_eq!(
            cfg.max_time_for("IssueCapability"),
            Duration::from_millis(100)
        );
        assert_eq!(cfg.max_time_for("ReadMemory"), Duration::from_millis(100));
        // Unknown / future action kinds get the looser bound by
        // default. F7 will refine if a future action joins the hot path.
        assert_eq!(
            cfg.max_time_for("FutureUnknown"),
            Duration::from_millis(100)
        );
    }
}

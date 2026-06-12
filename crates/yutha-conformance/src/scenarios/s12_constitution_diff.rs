//! Behavioral scenario **S12: Constitution diff engine end-to-end
//! (Phase 3d regression guard).**
//!
//! Phase 3d shipped the `yutha-diff` crate: a pure-compute engine
//! that takes two [`yutha_cedar_plus::Constitution`] artifacts and
//! returns a [`yutha_diff::ConstitutionDiff`] naming every
//! section-level change between them. The crate is operator-facing
//! tooling rather than substrate, but the diff shape is load-bearing
//! for the `yutha-ops diff` CLI's three output formats + the
//! upcoming OpenTelemetry exporter, and for any CI gate that pins
//! constitution evolution to a review process.
//!
//! S12 locks **five** load-bearing properties:
//!
//! 1. **Identity diff is empty.** Diffing a constitution against
//!    itself reports `is_empty_structurally()` and every section's
//!    `added` / `removed` / `modified` arrays empty.
//! 2. **Cedar policy add detected by `@id`.** A new annotated
//!    `forbid` rule on the right side surfaces in
//!    `cedar_policies.added` exactly once, keyed by the operator-
//!    supplied `@id` (not by the Cedar auto-generated `policy<n>`).
//! 3. **Cedar policy modify retains both sides.** Same `@id` on both
//!    sides with a different `when {}` body surfaces in
//!    `cedar_policies.modified` exactly once, with `left.source` !=
//!    `right.source` so renderers can produce a Before/After diff.
//! 4. **Engine-config item modify is field-level.** Changing a
//!    single nested field on an [`yutha_cedar_plus::engine_config::EnforcementRule`]
//!    surfaces as exactly one `modified` entry with both sides
//!    intact. Operators reading the diff see the exact field
//!    delta — not "rule X changed somehow".
//! 5. **Schema version pin change surfaces independently.**
//!    Different `schema_version` strings produce a
//!    `Some((from, to))` even when every other section is empty.
//!
//! ## Scenario shape
//!
//! Three back-to-back diff invocations with hand-crafted
//! [`yutha_cedar_plus::Constitution`] values:
//!
//! | Case | Left → Right                                     | Asserts                                            |
//! |------|--------------------------------------------------|----------------------------------------------------|
//! | A    | baseline vs baseline                             | identity diff is empty                             |
//! | B    | baseline vs tightened                            | Cedar add + enforcement-rule add + identity-other  |
//! | C    | tightened vs tightened-evolved                   | Cedar modify + enforcement-rule modify + schema-pin change |
//!
//! No control-plane stack, no signing, no async — `yutha-diff` is
//! pure compute over already-constructed Constitution values.

use std::collections::HashMap;

use yutha_cedar_plus::engine_config::{
    CoachConfig, DetectConfig, DetectTrigger, EnforcementRule, EngineConfig, EvictConfig,
    QuarantineConfig, ReverseConfig,
};
use yutha_cedar_plus::Constitution;
use yutha_core::{Hash, HashAlgorithm, SpecVersion, SwarmId, Timestamp};
use yutha_diff::diff_constitutions;

/// Constitution-diff section-count snapshot for the test at the bottom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S12Outcome {
    /// Case A — identity diff was empty.
    pub case_a_empty: bool,
    /// Case B — Cedar policies `added` count (expect 1:
    /// `forbid-large-refunds`).
    pub case_b_cedar_added: u64,
    /// Case B — enforcement rules `added` count (expect 1:
    /// `large_refund_detector`).
    pub case_b_enforcement_added: u64,
    /// Case C — Cedar policies `modified` count (expect 1:
    /// `forbid-large-refunds` body tightened).
    pub case_c_cedar_modified: u64,
    /// Case C — enforcement rules `modified` count (expect 1:
    /// `large_refund_detector` threshold tightened).
    pub case_c_enforcement_modified: u64,
    /// Case C — schema-version pin change present.
    pub case_c_schema_version_changed: bool,
}

/// The baseline (permit-all) constitution. Mirrors the
/// `crates/yutha-diff/tests/fixtures/baseline.{cedar,engine.yaml}`
/// pair but inline so this scenario doesn't depend on fixture
/// files.
const BASELINE_CEDAR: &str = r#"
@id("permit-routine-actions")
permit (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
);
"#;

/// The tightened constitution — baseline plus
/// `forbid-large-refunds` Cedar rule + `large_refund_detector`
/// enforcement chain.
const TIGHTENED_CEDAR: &str = r#"
@id("permit-routine-actions")
permit (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
);

@id("forbid-large-refunds")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
)
when {
    context.payload_schema_id == "type.yutha.dev/v1/Refund" &&
    context.estimated_cost_usd_cents > 50000
};
"#;

/// The tightened-evolved constitution. Same shape as `tightened`,
/// but the refund threshold drops from 50000 to 25000 (modified
/// Cedar body) AND the detect count_threshold drops from 3 to 2
/// (modified enforcement rule) AND the schema version pin advances.
const TIGHTENED_EVOLVED_CEDAR: &str = r#"
@id("permit-routine-actions")
permit (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
);

@id("forbid-large-refunds")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
)
when {
    context.payload_schema_id == "type.yutha.dev/v1/Refund" &&
    context.estimated_cost_usd_cents > 25000
};
"#;

/// Build the baseline engine config — empty rule set.
fn baseline_engine_config() -> EngineConfig {
    EngineConfig {
        schema_version: "1.1.0".into(),
        predicates: Vec::new(),
        scoring_rules: Vec::new(),
        procedures: Vec::new(),
        enforcement_rules: Vec::new(),
    }
}

/// Build the tightened engine config — adds the
/// `large_refund_detector` enforcement chain.
fn tightened_engine_config() -> EngineConfig {
    EngineConfig {
        schema_version: "1.1.0".into(),
        predicates: Vec::new(),
        scoring_rules: Vec::new(),
        procedures: Vec::new(),
        enforcement_rules: vec![large_refund_rule(3)],
    }
}

/// Build the tightened-evolved engine config — drops the detect
/// threshold from 3 to 2.
fn tightened_evolved_engine_config() -> EngineConfig {
    EngineConfig {
        schema_version: "1.2.0".into(),
        predicates: Vec::new(),
        scoring_rules: Vec::new(),
        procedures: Vec::new(),
        enforcement_rules: vec![large_refund_rule(2)],
    }
}

/// Hand-rolled `large_refund_detector` rule with parameterised
/// detect `count_threshold` so the modify-detection case can vary
/// just one field.
fn large_refund_rule(detect_count_threshold: u32) -> EnforcementRule {
    EnforcementRule {
        name: "large_refund_detector".into(),
        detect: DetectConfig {
            trigger: DetectTrigger {
                receipt_kind: "constitution.evaluate.deny".into(),
                deny_reason: None,
                forbid_rule_id: Some("forbid-large-refunds".into()),
            },
            count_threshold: detect_count_threshold,
            time_window: "60m".into(),
            group_by: "principal".into(),
            historical: false,
        },
        coach: Some(CoachConfig {
            cooldown: "5m".into(),
            guidance_template: "Refunds over $500 require supervisor approval.".into(),
        }),
        quarantine: Some(QuarantineConfig {
            escalate_after: "1h".into(),
            expires_after: None,
            compliance_check: None,
        }),
        evict: Some(EvictConfig {
            escalate_after: "24h".into(),
            require_countersign: true,
        }),
        reputation_delta: HashMap::new(),
        reverse: ReverseConfig::default(),
        severity: Some("high".into()),
    }
}

/// Assemble a Constitution value from cedar source + engine config.
/// `constitution_hash` and `swarm_id` are placeholder zeros — the
/// structural diff doesn't read them.
fn constitution(cedar_source: &str, engine_config: EngineConfig, version: &str) -> Constitution {
    Constitution {
        constitution_hash: Hash::new(HashAlgorithm::Sha256, vec![0u8; 32]).unwrap(),
        spec_version: SpecVersion::parse("1.0.0").unwrap(),
        schema_version: engine_config.schema_version.clone(),
        constitution_version: version.into(),
        parent_version: None,
        swarm_id: SwarmId::from_bytes(&[0u8; 16]).unwrap(),
        cedar_source: cedar_source.into(),
        engine_config,
        issued_at: Timestamp::now(),
    }
}

/// Run S12 end-to-end. Returns the section-count snapshot for the
/// `#[tokio::test]` at the bottom of this module to assert against.
pub fn run_s12() -> S12Outcome {
    let baseline = constitution(BASELINE_CEDAR, baseline_engine_config(), "baseline");
    let tightened = constitution(TIGHTENED_CEDAR, tightened_engine_config(), "tightened");
    let tightened_evolved = constitution(
        TIGHTENED_EVOLVED_CEDAR,
        tightened_evolved_engine_config(),
        "tightened-evolved",
    );

    // ---- Case A: identity diff is empty ----
    let a = diff_constitutions(&baseline, &baseline).expect("diff A computes");
    let case_a_empty = a.is_empty_structurally();
    assert!(case_a_empty, "identity diff MUST be empty");

    // ---- Case B: baseline → tightened ----
    let b = diff_constitutions(&baseline, &tightened).expect("diff B computes");
    // Cedar: 1 added (`forbid-large-refunds`), keyed by the operator
    // `@id`, not by the auto-generated Cedar PolicyId.
    assert_eq!(b.cedar_policies.added.len(), 1);
    assert_eq!(b.cedar_policies.added[0].name, "forbid-large-refunds");
    assert!(
        b.cedar_policies.added[0].annotated,
        "added Cedar policy MUST surface as annotated when @id was supplied"
    );
    assert_eq!(b.cedar_policies.removed.len(), 0);
    assert_eq!(b.cedar_policies.modified.len(), 0);
    // Enforcement: 1 added (`large_refund_detector`).
    assert_eq!(b.enforcement_rules.added.len(), 1);
    assert_eq!(b.enforcement_rules.added[0].name, "large_refund_detector");
    // Identity-other: no changes in the unmoved sections.
    assert!(b.named_predicates.is_empty());
    assert!(b.scoring_rules.is_empty());
    assert!(b.procedures.is_empty());
    // Schema version pin matched on this hop.
    assert_eq!(b.schema_version_change, None);

    // ---- Case C: tightened → tightened-evolved ----
    let c = diff_constitutions(&tightened, &tightened_evolved).expect("diff C computes");
    // Cedar: 1 modified — same `@id`, body differs. Both sides
    // retained for renderer use.
    assert_eq!(c.cedar_policies.added.len(), 0);
    assert_eq!(c.cedar_policies.removed.len(), 0);
    assert_eq!(c.cedar_policies.modified.len(), 1);
    let cedar_change = &c.cedar_policies.modified[0];
    assert_eq!(cedar_change.name, "forbid-large-refunds");
    assert_ne!(
        cedar_change.left.source, cedar_change.right.source,
        "modified Cedar entry MUST retain both sides' sources so renderers can show a Before/After"
    );
    assert!(
        cedar_change.left.source.contains("50000"),
        "left side carries the 50000 threshold"
    );
    assert!(
        cedar_change.right.source.contains("25000"),
        "right side carries the 25000 threshold"
    );
    // Enforcement: 1 modified — same name, different
    // detect.count_threshold field.
    assert_eq!(c.enforcement_rules.added.len(), 0);
    assert_eq!(c.enforcement_rules.removed.len(), 0);
    assert_eq!(c.enforcement_rules.modified.len(), 1);
    let enf_change = &c.enforcement_rules.modified[0];
    assert_eq!(enf_change.name, "large_refund_detector");
    assert_eq!(
        enf_change.left.detect.count_threshold, 3,
        "left side carries the original detect count_threshold (3)"
    );
    assert_eq!(
        enf_change.right.detect.count_threshold, 2,
        "right side carries the tightened detect count_threshold (2)"
    );
    // Schema version pin change surfaces independently.
    assert_eq!(
        c.schema_version_change,
        Some(("1.1.0".to_string(), "1.2.0".to_string())),
        "schema_version pin change MUST surface as Some((from, to))"
    );

    S12Outcome {
        case_a_empty,
        case_b_cedar_added: b.cedar_policies.added.len() as u64,
        case_b_enforcement_added: b.enforcement_rules.added.len() as u64,
        case_c_cedar_modified: c.cedar_policies.modified.len() as u64,
        case_c_enforcement_modified: c.enforcement_rules.modified.len() as u64,
        case_c_schema_version_changed: c.schema_version_change.is_some(),
    }
}

// =============================================================================
// Test
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s12_constitution_diff_round_trip() {
        let outcome = run_s12();
        assert_eq!(
            outcome,
            S12Outcome {
                case_a_empty: true,
                case_b_cedar_added: 1,
                case_b_enforcement_added: 1,
                case_c_cedar_modified: 1,
                case_c_enforcement_modified: 1,
                case_c_schema_version_changed: true,
            }
        );
    }
}

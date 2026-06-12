//! Integration test: load the checked-in fixture pairs, run
//! `diff_constitutions` against them, and pin the expected deltas.
//!
//! Lives here (rather than inline in `src/`) so the fixture files can
//! be reused by ad-hoc `yutha-ops diff` smoke testing. If you edit
//! either side of the fixture pair, the assertions below will need
//! to be updated to match.

use std::path::PathBuf;

use yutha_cedar_plus::{parse_engine_config_yaml, Constitution};
use yutha_core::{Hash, HashAlgorithm, SpecVersion, SwarmId, Timestamp};
use yutha_diff::diff_constitutions;

fn fixture_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p
}

fn load_fixture(version_label: &str, cedar_filename: &str, engine_filename: &str) -> Constitution {
    let cedar_path = fixture_dir().join(cedar_filename);
    let engine_path = fixture_dir().join(engine_filename);
    let cedar_source =
        std::fs::read_to_string(&cedar_path).unwrap_or_else(|e| panic!("read {cedar_path:?}: {e}"));
    let engine_yaml = std::fs::read_to_string(&engine_path)
        .unwrap_or_else(|e| panic!("read {engine_path:?}: {e}"));
    let engine_config = parse_engine_config_yaml(&engine_yaml)
        .unwrap_or_else(|e| panic!("parse engine config {engine_path:?}: {e}"));

    Constitution {
        constitution_hash: Hash::new(HashAlgorithm::Sha256, vec![0u8; 32]).unwrap(),
        spec_version: SpecVersion::parse("1.0.0").unwrap(),
        schema_version: engine_config.schema_version.clone(),
        constitution_version: version_label.into(),
        parent_version: None,
        swarm_id: SwarmId::from_bytes(&[0u8; 16]).unwrap(),
        cedar_source,
        engine_config,
        issued_at: Timestamp::now(),
    }
}

#[test]
fn baseline_to_tightened_adds_one_cedar_rule_and_one_enforcement_rule() {
    let baseline = load_fixture("baseline", "baseline.cedar", "baseline.engine.yaml");
    let tightened = load_fixture("tightened", "tightened.cedar", "tightened.engine.yaml");

    let diff = diff_constitutions(&baseline, &tightened).expect("diff computes");

    // Schema version pin unchanged across the pair.
    assert_eq!(diff.schema_version_change, None);

    // One added Cedar policy: `forbid-large-refunds`.
    assert_eq!(diff.cedar_policies.added.len(), 1);
    assert_eq!(diff.cedar_policies.added[0].name, "forbid-large-refunds");
    assert!(diff.cedar_policies.added[0].annotated);
    assert_eq!(diff.cedar_policies.removed.len(), 0);
    assert_eq!(diff.cedar_policies.modified.len(), 0);

    // No-change engine-config sections (predicates, scoring,
    // procedures).
    assert!(diff.named_predicates.is_empty());
    assert!(diff.scoring_rules.is_empty());
    assert!(diff.procedures.is_empty());

    // One added enforcement rule: `large_refund_detector`.
    assert_eq!(diff.enforcement_rules.added.len(), 1);
    assert_eq!(
        diff.enforcement_rules.added[0].name,
        "large_refund_detector"
    );
    assert_eq!(diff.enforcement_rules.removed.len(), 0);
    assert_eq!(diff.enforcement_rules.modified.len(), 0);

    // Static-only — behavioural is populated by 3d-G (`--against-window`).
    assert!(diff.behavioural.is_none());

    // Constitution version labels surface for the renderer titles.
    assert_eq!(diff.left_constitution_version, "baseline");
    assert_eq!(diff.right_constitution_version, "tightened");
}

#[test]
fn tightened_to_baseline_surfaces_symmetric_removals() {
    let baseline = load_fixture("baseline", "baseline.cedar", "baseline.engine.yaml");
    let tightened = load_fixture("tightened", "tightened.cedar", "tightened.engine.yaml");

    // Reverse direction — the same delta surfaces as removals.
    let diff = diff_constitutions(&tightened, &baseline).expect("diff computes");

    assert_eq!(diff.cedar_policies.added.len(), 0);
    assert_eq!(diff.cedar_policies.removed.len(), 1);
    assert_eq!(diff.cedar_policies.removed[0].name, "forbid-large-refunds");

    assert_eq!(diff.enforcement_rules.added.len(), 0);
    assert_eq!(diff.enforcement_rules.removed.len(), 1);
    assert_eq!(
        diff.enforcement_rules.removed[0].name,
        "large_refund_detector"
    );
}

#[test]
fn identity_diff_is_empty() {
    let baseline = load_fixture("baseline", "baseline.cedar", "baseline.engine.yaml");
    let baseline2 = load_fixture("baseline", "baseline.cedar", "baseline.engine.yaml");
    let diff = diff_constitutions(&baseline, &baseline2).expect("diff computes");
    assert!(
        diff.is_empty_structurally(),
        "a constitution diffed against itself MUST report no structural changes"
    );
}

#[test]
fn fixtures_render_in_all_three_formats() {
    use yutha_diff::{render_to_string, OutputFormat};
    let baseline = load_fixture("baseline", "baseline.cedar", "baseline.engine.yaml");
    let tightened = load_fixture("tightened", "tightened.cedar", "tightened.engine.yaml");
    let diff = diff_constitutions(&baseline, &tightened).expect("diff computes");

    // All three renderers MUST produce non-empty output that
    // contains a recognisable marker.
    let json = render_to_string(&diff, OutputFormat::Json).expect("render json");
    assert!(json.contains("yutha-diff/v1"), "JSON missing schema marker");
    assert!(json.contains("forbid-large-refunds"));
    assert!(json.contains("large_refund_detector"));

    let md = render_to_string(&diff, OutputFormat::Markdown).expect("render markdown");
    assert!(md.contains("# Constitution diff"));
    assert!(md.contains("forbid-large-refunds"));
    assert!(md.contains("large_refund_detector"));

    let html = render_to_string(&diff, OutputFormat::Html).expect("render html");
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("forbid-large-refunds"));
    assert!(html.contains("large_refund_detector"));
}

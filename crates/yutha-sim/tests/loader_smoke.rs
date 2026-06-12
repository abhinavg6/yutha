//! 3e-G integration smoke: load the checked-in example scenario
//! fixture and confirm it parses into a [`ScenarioConfig`] matching
//! the expectations baked into the example binary
//! (`examples/refund_attacker_meets_cap.rs`).
//!
//! Lives here so a drift between the YAML and either
//! [`ScenarioConfig`] or the persona configs surfaces as a test
//! failure rather than a runtime panic in the example binary.

use std::path::PathBuf;

use yutha_sim::load_scenario_yaml;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/scenarios/refund_attacker_meets_cap")
}

#[tokio::test]
async fn example_scenario_yaml_loads_into_expected_shape() {
    let cfg = load_scenario_yaml(fixture_root().join("scenario.yaml"))
        .await
        .expect("load_scenario_yaml");

    // Pin the load-time shape so an accidental edit to the
    // fixture YAML doesn't silently change the example output.
    assert_eq!(cfg.steps, 20);
    assert_eq!(cfg.tick_ms, 1000);
    assert_eq!(cfg.agents.len(), 2);
    assert_eq!(cfg.agents[0].persona, "support_agent");
    assert_eq!(cfg.agents[1].persona, "refund_attacker");

    // Paths must resolve to existing files under the fixture root.
    assert!(
        cfg.constitution.cedar_path.is_file(),
        "expected cedar at {:?}",
        cfg.constitution.cedar_path
    );
    assert!(
        cfg.constitution.engine_config_path.is_file(),
        "expected engine config at {:?}",
        cfg.constitution.engine_config_path
    );
}

#[tokio::test]
async fn example_scenario_fixture_files_are_well_formed() {
    use yutha_cedar_plus::parse_engine_config_yaml;
    let root = fixture_root();
    // Cedar file must parse as UTF-8 and contain the @id annotation
    // the engine config keys off semantically. Full Cedar parse is
    // exercised by the harness; this guards the syntactic shape.
    let cedar = std::fs::read_to_string(root.join("refund-cap.cedar")).expect("read cedar");
    assert!(
        cedar.contains("@id(\"refund-cap\")"),
        "cedar fixture lost the refund-cap @id annotation"
    );
    assert!(
        cedar.contains("context.estimated_cost_usd_cents"),
        "cedar fixture lost the cost-threshold gate"
    );

    // Engine config must round-trip through the same parser the
    // harness uses.
    let engine_yaml =
        std::fs::read_to_string(root.join("refund-cap.engine.yaml")).expect("read engine yaml");
    let engine_config = parse_engine_config_yaml(&engine_yaml).expect("parse engine config");
    assert_eq!(engine_config.schema_version, "1.1.0");
    assert_eq!(
        engine_config.enforcement_rules.len(),
        1,
        "fixture should have exactly one enforcement rule"
    );
    assert_eq!(engine_config.enforcement_rules[0].name, "refund_cap_chain");
}

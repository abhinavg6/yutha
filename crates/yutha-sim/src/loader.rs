//! YAML scenario loader.
//!
//! Reads a YAML file into [`ScenarioConfig`] and resolves the
//! constitution paths relative to the YAML file's parent directory.
//!
//! The shape is documented at the [`ScenarioConfig`] type — this
//! module just handles I/O + relative-path resolution.

use std::path::{Path, PathBuf};

use crate::error::{Result, SimError};
use crate::scenario::ScenarioConfig;

/// Load a scenario from a YAML file on disk.
///
/// `cedar_path` and `engine_config_path` in the loaded YAML are
/// resolved against the YAML file's parent directory (or, when the
/// YAML lives at the filesystem root, against the current working
/// directory). Absolute paths in the YAML are left as-is.
///
/// ## Errors
///
/// - [`SimError::Io`] when the YAML file can't be read.
/// - [`SimError::ScenarioParse`] when the YAML is malformed or
///   doesn't match the [`ScenarioConfig`] shape.
pub async fn load_scenario_yaml(path: impl AsRef<Path>) -> Result<ScenarioConfig> {
    let path = path.as_ref();
    let body = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| SimError::Io(std::io::Error::new(e.kind(), format!("read {path:?}: {e}"))))?;
    let mut cfg: ScenarioConfig = serde_yaml::from_str(&body)
        .map_err(|e| SimError::ScenarioParse(format!("{path:?}: {e}")))?;
    let base_dir = path.parent().map(Path::to_path_buf).unwrap_or_else(|| {
        // YAML at the filesystem root → resolve against cwd. Very
        // unusual in practice; included for completeness.
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });
    cfg.constitution.cedar_path = resolve(&base_dir, &cfg.constitution.cedar_path);
    cfg.constitution.engine_config_path = resolve(&base_dir, &cfg.constitution.engine_config_path);
    Ok(cfg)
}

/// Parse a scenario from a YAML string without touching the
/// filesystem. Constitution paths are NOT rewritten — the caller is
/// responsible for setting absolute paths or running the result
/// through [`set_constitution_base_dir`] before handing it to
/// [`crate::SimulationHarness::new`].
pub fn parse_scenario_yaml(yaml: &str) -> Result<ScenarioConfig> {
    serde_yaml::from_str(yaml).map_err(|e| SimError::ScenarioParse(e.to_string()))
}

/// Rewrite the constitution's `cedar_path` and
/// `engine_config_path` as if `base_dir` were the YAML file's
/// parent directory. Idempotent on absolute paths.
pub fn set_constitution_base_dir(cfg: &mut ScenarioConfig, base_dir: impl AsRef<Path>) {
    let base = base_dir.as_ref();
    cfg.constitution.cedar_path = resolve(base, &cfg.constitution.cedar_path);
    cfg.constitution.engine_config_path = resolve(base, &cfg.constitution.engine_config_path);
}

fn resolve(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
constitution:
  cedar_path: ./refund-cap.cedar
  engine_config_path: ./refund-cap.engine.yaml

agents:
  - persona: support_agent
    config:
      message_text: "ping"
  - persona: refund_attacker
    config:
      initial_amount_cents: 50
      step_multiplier: 2.0

steps: 12
tick_ms: 1000
"#;

    #[test]
    fn parse_scenario_yaml_round_trips_full_shape() {
        let cfg = parse_scenario_yaml(SAMPLE).expect("parse");
        assert_eq!(cfg.steps, 12);
        assert_eq!(cfg.tick_ms, 1000);
        assert_eq!(cfg.agents.len(), 2);
        assert_eq!(cfg.agents[0].persona, "support_agent");
        assert_eq!(cfg.agents[1].persona, "refund_attacker");
        // Paths are kept as-written when going through the
        // string-only parser.
        assert_eq!(
            cfg.constitution.cedar_path,
            PathBuf::from("./refund-cap.cedar")
        );
    }

    #[test]
    fn set_constitution_base_dir_resolves_relative_paths() {
        let mut cfg = parse_scenario_yaml(SAMPLE).expect("parse");
        set_constitution_base_dir(&mut cfg, "/tmp/scenarios");
        assert_eq!(
            cfg.constitution.cedar_path,
            PathBuf::from("/tmp/scenarios/./refund-cap.cedar")
        );
        assert_eq!(
            cfg.constitution.engine_config_path,
            PathBuf::from("/tmp/scenarios/./refund-cap.engine.yaml")
        );
    }

    #[test]
    fn set_constitution_base_dir_leaves_absolute_paths_alone() {
        let yaml = r#"
constitution:
  cedar_path: /opt/yutha/refund-cap.cedar
  engine_config_path: /opt/yutha/refund-cap.engine.yaml
agents: []
steps: 1
tick_ms: 100
"#;
        let mut cfg = parse_scenario_yaml(yaml).expect("parse");
        set_constitution_base_dir(&mut cfg, "/anywhere/else");
        assert_eq!(
            cfg.constitution.cedar_path,
            PathBuf::from("/opt/yutha/refund-cap.cedar")
        );
    }

    #[test]
    fn parse_rejects_garbage_yaml() {
        match parse_scenario_yaml("not: a: scenario:") {
            Ok(_) => panic!("expected parse error"),
            Err(SimError::ScenarioParse(_)) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
}

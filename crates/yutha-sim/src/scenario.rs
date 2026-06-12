//! Scenario configuration — the data shape the YAML loader
//! (3e-G), the CLI subcommand (3e-H), and the Python wrapper (3e-I)
//! all share.
//!
//! 3e-B locks the **shape** of these types. The 3e-G YAML format is
//! a direct serde deserialisation; 3e-H's CLI hands the deserialised
//! value to the harness without further translation; 3e-I's Python
//! wrapper round-trips via the same serde shape.
//!
//! No driver logic, no file I/O — pure data.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// A full simulation scenario.
///
/// ## YAML shape (3e-G preview)
///
/// ```yaml
/// constitution:
///   cedar_path: ./constitution.cedar
///   engine_config_path: ./constitution.engine.yaml
///
/// agents:
///   - persona: support_agent
///     config:
///       name_suffix: alice
///   - persona: refund_attacker
///     config:
///       name_suffix: mallory
///       initial_amount_cents: 100
///
/// steps: 50
/// tick_ms: 100
/// ```
///
/// The `persona` discriminator is resolved by the harness against
/// its persona registry. The `config` blob is handed to the matched
/// persona's deserializer; the unknown-persona path produces
/// [`crate::SimError::UnknownPersona`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioConfig {
    /// Which constitution to activate before running the scenario.
    pub constitution: ConstitutionConfig,

    /// Personas + their per-persona configs. Order is preserved —
    /// the harness invokes `step()` in the order agents appear
    /// here, which fixes the receipt emission order for
    /// reproducibility.
    pub agents: Vec<AgentConfig>,

    /// Maximum number of simulation steps. The harness may exit
    /// earlier when every persona returns `None` in a single step
    /// (see [`crate::TerminalReason::AllPersonasIdle`]).
    pub steps: u32,

    /// Wall-clock advance between successive steps, in
    /// milliseconds. Also the basis for the monotonic_ns the
    /// harness stamps on each emitted envelope.
    pub tick_ms: u32,
}

/// Constitution to activate at the start of the simulation.
///
/// The 3e-C harness reads both files at setup time, runs them
/// through `yutha_cedar_plus::ConstitutionLoader`, and surfaces any
/// load failure as [`crate::SimError::ConstitutionLoad`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstitutionConfig {
    /// Path to the Cedar policy source file. Resolved relative to
    /// the scenario YAML's directory when loaded via the YAML
    /// loader.
    pub cedar_path: PathBuf,

    /// Path to the engine-config YAML (named predicates, scoring
    /// rules, procedures, enforcement rules). Same relative
    /// resolution rule as `cedar_path`.
    pub engine_config_path: PathBuf,
}

/// One persona entry in the agents list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Persona discriminator. The harness's registry maps this to
    /// a persona constructor. Built-in values
    /// (post-3e-F): `support_agent` /
    /// `refund_attacker` / `broken_tool`. Operators implementing
    /// custom personas in Rust register them at harness
    /// construction time and supply their own discriminator.
    pub persona: String,

    /// Persona-specific config blob. Each persona declares its own
    /// expected shape; the harness deserialises this `Value` into
    /// the persona's config type at construction time. Empty
    /// `{}` is acceptable for personas with no per-instance config.
    #[serde(default)]
    pub config: serde_json::Value,
}

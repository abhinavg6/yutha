//! Error type for `yutha-sim`.
//!
//! The 3e-B substrate types don't error on their own — they're pure
//! data shapes. The variants here are forward-declared for the
//! harness driver (3e-C), YAML loader (3e-G), and persona
//! configuration parsers (3e-D/E/F).

use thiserror::Error;

/// Errors that can occur during simulation setup or execution.
#[derive(Debug, Error)]
pub enum SimError {
    /// A scenario YAML file failed to parse.
    #[error("scenario parse failed: {0}")]
    ScenarioParse(String),

    /// A constitution file (Cedar source or engine-config YAML)
    /// couldn't be read or parsed.
    #[error("constitution load failed: {0}")]
    ConstitutionLoad(String),

    /// A persona's config (the persona-specific JSON value the YAML
    /// surfaces) couldn't be deserialized into the persona's
    /// expected shape.
    #[error("persona config invalid for {persona}: {source}")]
    PersonaConfig {
        /// The persona discriminator from the YAML
        /// (`support_agent` / `refund_attacker` / `broken_tool`).
        persona: String,
        /// The underlying serde error.
        #[source]
        source: serde_json::Error,
    },

    /// The YAML referenced an unknown persona discriminator.
    /// Operators implementing custom personas should plug them in
    /// at the harness construction site rather than going through
    /// the YAML registry.
    #[error("unknown persona discriminator: {0}. Built-in: support_agent / refund_attacker / broken_tool")]
    UnknownPersona(String),

    /// The harness failed to set up the in-memory stack — usually a
    /// substrate error from yutha-passport / yutha-receipt /
    /// yutha-cedar-plus surfaced as a string.
    #[error("simulation setup failed: {0}")]
    Setup(String),

    /// The harness encountered a substrate error during the persona
    /// loop. Wraps any error from the Send path, Cedar evaluation,
    /// or receipt append.
    #[error("simulation step failed: {0}")]
    Step(String),

    /// I/O error reading a scenario file or writing an outcome
    /// payload.
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Crate-level `Result` alias.
pub type Result<T> = std::result::Result<T, SimError>;

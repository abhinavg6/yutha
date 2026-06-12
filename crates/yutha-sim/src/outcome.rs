//! [`SimulationOutcome`] — everything a finished simulation surfaces.
//!
//! The harness fills this in by reading the in-memory receipt store
//! after the persona loop exits. The shape round-trips through
//! serde so 3e-H (CLI rendering) and 3e-I (Python wrapper) can both
//! consume it without a separate translation layer.

use serde::{Deserialize, Serialize};
use yutha_core::AgentId;
use yutha_receipt::Receipt;

/// The full set of artifacts a finished simulation produces.
///
/// `receipts` is the audit-trail substrate every downstream pipeline
/// builds on: count receipts by action_kind to assert behavioural
/// gates; filter on `subject_agent_id` to attribute behaviour to
/// individual personas; pair adjacent
/// `constitution.evaluate.deny` + `enforcement.detect` entries to
/// validate the four-stage chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationOutcome {
    /// Every receipt emitted across the simulation, in monotonic_ns
    /// order. Covers constitution.evaluate.{pass,deny},
    /// envelope.{send,deliver}, capability.check.{permit,deny},
    /// enforcement.* — anything the in-memory substrate generates.
    pub receipts: Vec<Receipt>,

    /// Per-persona terminal state.
    pub persona_states: Vec<PersonaState>,

    /// Total steps executed. May be less than the configured
    /// `ScenarioConfig::steps` when every persona went idle in a
    /// single step.
    pub total_steps: u32,

    /// Why the simulation ended.
    pub terminal_reason: TerminalReason,
}

/// Per-persona terminal summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonaState {
    /// The persona's [`crate::Persona::name`] at construction.
    pub name: String,

    /// The persona's agent id assigned at harness setup.
    pub agent_id: AgentId,

    /// Number of times `step()` returned `Some(intent)` across the
    /// simulation. Idle steps don't increment.
    pub intents_emitted: u32,

    /// Optional free-form note set by
    /// [`crate::Persona::finalize`]. Personas use it to surface
    /// internal counters or theory-of-mind state into the rendered
    /// outcome.
    #[serde(default)]
    pub final_note: Option<String>,
}

/// Why the harness exited the persona loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalReason {
    /// The configured `steps` budget was exhausted.
    BudgetExhausted,
    /// Every persona returned `None` in a single step, so the
    /// harness exited early.
    AllPersonasIdle,
}

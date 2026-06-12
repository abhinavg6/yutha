//! Simulation harness + canonical personas for Yutha constitutions.
//!
//! Phase 3e / Pillar 1 (simulation + observability). Drive a
//! candidate constitution against synthetic agent traffic in a fully
//! in-memory stack: no control plane, no network, no async runtime
//! plumbing past the trait surface. The harness is deterministic by
//! construction — sequential per-step persona execution, fixed
//! `tick_ms` between steps.
//!
//! ## Layered shape
//!
//! - [`Persona`] — async trait every persona implements. One
//!   `step()` call per simulation step, returning an optional
//!   [`EnvelopeIntent`] that the harness materialises into a signed
//!   Envelope and pushes through the in-memory Send path.
//! - [`SimContext`] — read-only view the harness hands every
//!   persona at the top of each step: recent receipts, current
//!   wall-clock, this persona's quarantine state, the active
//!   constitution hash.
//! - [`EnvelopeIntent`] — the persona's output. A neutral
//!   description of an envelope that the harness fills in with the
//!   missing bits (signer, swarm_id, monotonic_ns) before driving
//!   the Send path.
//! - [`ScenarioConfig`] — the scenario the simulation runs.
//!   Constitution paths + agent setup + step budget + tick. Locked
//!   shape across the Rust library, the YAML scenario format
//!   (3e-G), the CLI subcommand (3e-H), and the Python wrapper
//!   (3e-I).
//! - [`SimulationOutcome`] — what the harness returns. Every
//!   emitted receipt + per-persona terminal state + why the
//!   simulation ended.
//!
//! ## What this crate is NOT
//!
//! - Not a network-backed simulator. The harness stands up the
//!   in-memory stack (receipt store, passport store, capability
//!   store, Cedar+ evaluator, enforcement engine) in-process.
//!   Operators wanting to drive real network traffic should use the
//!   existing Python SDK adapters.
//! - Not a sprawling persona library. Ships three canonical
//!   personas + their YAML config schemas; operators who need
//!   custom personas implement the trait directly.
//! - Not concurrent. Personas run sequentially per step in
//!   declaration order. Deterministic; debuggable; no async
//!   ordering surprises.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod error;
pub mod harness;
pub mod loader;
pub mod outcome;
pub mod persona;
pub mod personas;
pub mod registry;
pub mod scenario;

pub use error::{Result, SimError};
pub use harness::SimulationHarness;
pub use loader::{load_scenario_yaml, parse_scenario_yaml, set_constitution_base_dir};
pub use outcome::{PersonaState, SimulationOutcome, TerminalReason};
pub use persona::{EnvelopeIntent, Persona, SimContext};
pub use personas::register_canonical_personas;
pub use registry::{PersonaConstructor, PersonaRegistry};
pub use scenario::{AgentConfig, ConstitutionConfig, ScenarioConfig};

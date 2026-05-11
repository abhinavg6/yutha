//! Behavioral conformance scenarios.
//!
//! Mirrors [`/docs/conformance/conformance-suite.md`](../../../docs/conformance/conformance-suite.md) §4 reference scenarios.
//! These scenarios stand up the full in-memory stack (all five Workstream B
//! crates plus the receipt store) and verify swarm-level invariants.
//!
//! At this Phase 1 maturity, only S1 (customer-support queue mode) is
//! authored, and it tests the substrate properties achievable without the
//! constitution engine: registration, audit-trail production, envelope
//! round-trip, signature verification. Norm-enforcement properties land in
//! Phase 2 once the constitution evaluator ships.

pub mod s1_queue_mode;

pub use s1_queue_mode::{run_s1, S1Outcome};

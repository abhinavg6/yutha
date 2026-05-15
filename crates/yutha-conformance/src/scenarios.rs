//! Behavioral conformance scenarios.
//!
//! Mirrors [`/docs/conformance/conformance-suite.md`](../../../docs/conformance/conformance-suite.md) §4 reference scenarios.
//! These scenarios stand up the full in-memory stack (all five Workstream B
//! crates plus the receipt store) and verify swarm-level invariants.
//!
//! Authored scenarios:
//! - **S1: customer-support queue mode.** Substrate properties achievable
//!   without the constitution engine: registration, audit-trail
//!   production, envelope round-trip, signature verification.
//! - **S2: Send-path capability enforcement (RFC 0007).** Locks the
//!   substrate semantics behind the gRPC Send handler's cap-check branch
//!   — permit, revoke-deny, and out-of-scope-deny paths, with the same
//!   `ActionDescriptor` synthesis the handler uses.
//!
//! Norm-enforcement properties (S3+) land in Phase 2 once the
//! constitution evaluator ships.

pub mod s1_queue_mode;
pub mod s2_send_path_cap_check;

pub use s1_queue_mode::{run_s1, S1Outcome};
pub use s2_send_path_cap_check::{run_s2, S2Outcome};

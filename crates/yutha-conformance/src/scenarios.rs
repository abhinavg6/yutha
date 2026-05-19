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
//! - **S4: Four-stage enforcement loop (RFC 0013).** Activates a real
//!   constitution with a Cedar forbid rule + an `enforcement_rules`
//!   entry covering all four stages. Drives the chain end-to-end via
//!   synthetic time advance and verifies the audit-trail delta plus
//!   the cap-layer's post-quarantine denial.
//! - **S5: Support-queue refund cap (F14).** Activates a constitution
//!   authored against the `Yutha::SupportQueue` workload extension
//!   with a Cedar `forbid` rule gating refunds over a threshold by
//!   non-supervisor agents. Validates the schema-extension pattern
//!   + cross-namespace-policy authoring.
//! - **S6: Memory privacy gate.** Activates a constitution whose
//!   Cedar policy uses `ReadMemory` (v1.1 memory norms) to deny
//!   cross-agent reads of `private`-scoped memories. Validates that
//!   the memory entity + memory actions evaluate end-to-end.
//! - **S7: Enforcement reverse path.** Companion to S4. Exercises the
//!   alternate quarantine outcome: an auto-reverse triggered by
//!   `quarantine.expires_after` elapsing without an explicit operator
//!   reverse. Verifies the engine's `Stage::Reverse` plumbing + the
//!   cap layer flipping back to "permitted" after reverse.

pub mod s1_queue_mode;
pub mod s2_send_path_cap_check;
pub mod s4_enforcement_loop;
pub mod s5_support_queue_refunds;
pub mod s6_memory_privacy;
pub mod s7_reverse_path;

pub use s1_queue_mode::{run_s1, S1Outcome};
pub use s2_send_path_cap_check::{run_s2, S2Outcome};
pub use s4_enforcement_loop::{run_s4, S4Outcome};
pub use s5_support_queue_refunds::{run_s5, S5Outcome};
pub use s6_memory_privacy::{run_s6, S6Outcome};
pub use s7_reverse_path::{run_s7, S7Outcome};

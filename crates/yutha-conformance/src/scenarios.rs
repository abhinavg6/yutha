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
//! - **S9: Principal-attribute Cedar rules fire honestly (Phase 3a
//!   regression guard).** Three SendEnvelope evaluations against a
//!   constitution with two forbid rules — one keying on
//!   `principal.framework`, one on `principal.reputation`. Locks the
//!   post-Phase-3a behaviour in: pre-3a these placeholder attrs caused
//!   policies to silently degrade to permit-all.
//! - **S10: Shadow-mode evaluator end-to-end (Phase 3b regression
//!   guard).** Permissive active + restrictive shadow; three
//!   SendEnvelope evaluations through `evaluate_pair`. Locks the
//!   three load-bearing properties from RFC 0018: slot
//!   independence (shadow deny doesn't influence active decision),
//!   receipt action-kind partitioning
//!   (`constitution.evaluate.{pass,deny}` vs
//!   `constitution.evaluate.shadow.{pass,deny}` never cross-pollute),
//!   and evidence shape (active receipts gain
//!   `shadow_constitution_hash` when shadow is configured; shadow
//!   receipts carry `shadow_constitution_hash` and NOT
//!   `constitution_hash`).
//! - **S11: Replay session end-to-end (Phase 3c regression guard).**
//!   Production source store with 4 `constitution.evaluate.deny`
//!   receipts for the same subject; cold-init replay session against
//!   a candidate whose `enforcement_rules` fire `detect` at
//!   threshold 2. Locks the four load-bearing properties from RFC
//!   0018 §4: production store untouched after the run, session
//!   store receives the emissions, within-session enforcement
//!   receipts use the same canonical `enforcement.detect`
//!   action-kind as production with a `replay_session_id` evidence
//!   marker, and step N+1's predecessors point at step N's emissions
//!   (session-internal causal chain — never the original receipt's
//!   predecessors).

pub mod s10_shadow_mode;
pub mod s11_replay_session;
pub mod s1_queue_mode;
pub mod s2_send_path_cap_check;
pub mod s4_enforcement_loop;
pub mod s5_support_queue_refunds;
pub mod s6_memory_privacy;
pub mod s7_reverse_path;
pub mod s8_attestation_deny;
pub mod s9_principal_attrs;

pub use s10_shadow_mode::{run_s10, S10Outcome};
pub use s11_replay_session::{run_s11, S11Outcome};
pub use s1_queue_mode::{run_s1, S1Outcome};
pub use s2_send_path_cap_check::{run_s2, S2Outcome};
pub use s4_enforcement_loop::{run_s4, S4Outcome};
pub use s5_support_queue_refunds::{run_s5, S5Outcome};
pub use s6_memory_privacy::{run_s6, S6Outcome};
pub use s7_reverse_path::{run_s7, S7Outcome};
pub use s8_attestation_deny::{run_s8, S8Outcome};
pub use s9_principal_attrs::{run_s9, S9Outcome};

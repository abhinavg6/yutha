//! Canonical persona library.
//!
//! Three personas ship with `yutha-sim`:
//!
//! - [`support_agent::SupportAgent`] — well-formed support-queue
//!   envelopes. Never trips enforcement. Baseline traffic.
//! - [`refund_attacker::RefundAttacker`] — escalating refund
//!   probes. Adaptive observation on Cedar deny. Respects
//!   quarantine.
//! - [`broken_tool::BrokenTool`] — emits out-of-scope schema sends
//!   without a capability. Drives `constitution.evaluate.deny` and
//!   the four-stage enforcement chain when paired with a
//!   constitution forbid rule on the sentinel schema id.
//!
//! Operators implementing custom personas register them on
//! [`crate::PersonaRegistry`] directly. The canonical bundle is
//! available through [`register_canonical_personas`].

pub mod broken_tool;
pub mod refund_attacker;
pub mod support_agent;

use crate::registry::PersonaRegistry;

/// Register all three built-in canonical personas on `registry`.
/// Operators who want only a subset register them individually via
/// each persona module's `register` function.
pub fn register_canonical_personas(registry: &mut PersonaRegistry) {
    support_agent::SupportAgent::register(registry);
    refund_attacker::RefundAttacker::register(registry);
    broken_tool::BrokenTool::register(registry);
}

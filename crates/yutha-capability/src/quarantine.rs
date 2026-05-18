//! [`QuarantineSource`] — pluggable state that tells the cap layer
//! which agents are currently quarantined.
//!
//! ## Why a trait rather than a state field
//!
//! Quarantine state lives in the constitution layer's enforcement
//! engine (RFC 0013 §4.2), not in the cap layer itself. The cap
//! layer needs a one-way read of that state on every check / issue /
//! attenuate (per enforcement.md §4.2: "the cap layer denies
//! quarantined agents" and "CapabilityService.Issue and
//! CapabilityService.Attenuate consult the same state and refuse to
//! mint new caps where the subject is quarantined"). A trait keeps
//! the dependency arrow pointing the right way — the cap crate stays
//! independent of `yutha-cedar-plus`; the control plane wires the
//! engine in via an adapter that implements this trait.
//!
//! ## Default behaviour
//!
//! [`AlwaysAllowed`] is a zero-state implementation that reports
//! every agent as un-quarantined. Tests and demo binaries that don't
//! exercise the enforcement layer plug it in; production binaries
//! wire an adapter backed by `EnforcementEngine`.

use async_trait::async_trait;
use yutha_core::AgentId;

/// One-way read of whether the agent identified by `agent_id` is
/// currently quarantined.
///
/// Called on the hot path of every cap-check, so implementations
/// MUST be fast and non-blocking. The control-plane adapter holds an
/// `Arc<EnforcementEngine>` and resolves the query against an
/// in-memory `RwLock` — a single read-lock acquire per call.
#[async_trait]
pub trait QuarantineSource: Send + Sync + std::fmt::Debug {
    /// Returns true iff `agent_id` is currently quarantined.
    ///
    /// Quarantine is a *current* state — both setting it
    /// (`enforcement.quarantine` receipt) and clearing it
    /// (`enforcement.reverse` or `enforcement.evict` receipt) are
    /// reflected here as soon as the enforcement engine processes
    /// the receipt.
    async fn is_agent_quarantined(&self, agent_id: &AgentId) -> bool;
}

/// No-quarantine implementation. Every agent is reported as
/// un-quarantined. Used by tests, demo binaries, and any code path
/// where the constitution layer isn't wired in.
///
/// This is NOT a back-compat shim — callers that don't construct a
/// quarantine source explicitly must opt into this no-op variant.
/// The default-deny posture is preserved because the cap layer's
/// scope + caveat checks still run; `AlwaysAllowed` only short-
/// circuits the enforcement-engine consultation.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysAllowed;

#[async_trait]
impl QuarantineSource for AlwaysAllowed {
    async fn is_agent_quarantined(&self, _agent_id: &AgentId) -> bool {
        false
    }
}

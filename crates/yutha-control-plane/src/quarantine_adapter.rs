//! Adapter that lets [`yutha_capability::CapabilityStore`] consult
//! the constitution layer's [`yutha_cedar_plus::EnforcementEngine`]
//! as its [`yutha_capability::QuarantineSource`].
//!
//! ## Why this lives in the control plane
//!
//! `yutha-capability` deliberately does NOT depend on
//! `yutha-cedar-plus` — the dependency arrow goes the other way (the
//! enforcement engine is downstream of the cap layer in the layering
//! diagram from `/spec/constitution/enforcement.md` §3). The control
//! plane is the only crate that sees both, so the adapter that
//! bridges them lives here.
//!
//! ## Behaviour
//!
//! Delegates `is_agent_quarantined` to
//! [`EnforcementEngine::is_agent_quarantined`], converting the cap
//! layer's strongly-typed [`AgentId`] into the stringified form the
//! engine indexes by (per RFC 0013 §4.2's serialization of
//! `target_agent_id` evidence).

use async_trait::async_trait;
use std::sync::Arc;

use yutha_capability::QuarantineSource;
use yutha_cedar_plus::EnforcementEngine;
use yutha_core::AgentId;

/// Cap-layer-facing wrapper over a shared `EnforcementEngine`.
///
/// Holds the engine by `Arc` so the control-plane state and the cap
/// store both observe the same enforcement decisions — there is
/// exactly one engine instance per running control plane.
#[derive(Clone)]
pub struct EnforcementEngineQuarantineSource {
    engine: Arc<EnforcementEngine>,
}

// `EnforcementEngine` doesn't currently impl Debug (its internal
// state is behind a tokio RwLock that doesn't itself impl Debug for
// the held value). The `QuarantineSource` trait bound requires
// Debug, so we provide a hand-written impl that names the adapter
// without trying to render the engine.
impl std::fmt::Debug for EnforcementEngineQuarantineSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnforcementEngineQuarantineSource")
            .finish_non_exhaustive()
    }
}

impl EnforcementEngineQuarantineSource {
    /// Wrap the given engine. The returned adapter is cheap to
    /// `Arc::new`-and-share into a `MemoryCapabilityStore`.
    pub fn new(engine: Arc<EnforcementEngine>) -> Self {
        Self { engine }
    }
}

#[async_trait]
impl QuarantineSource for EnforcementEngineQuarantineSource {
    async fn is_agent_quarantined(&self, agent_id: &AgentId) -> bool {
        // The engine indexes quarantine state by the same string form
        // we use everywhere else for AgentId (UUID v7 in canonical
        // hex-with-dashes via Display). Keep this in lockstep with
        // how `subject_agent_id` evidence is serialized in
        // envelope.rs::emit_constitution_eval_receipt.
        self.engine
            .is_agent_quarantined(&agent_id.to_string())
            .await
    }
}

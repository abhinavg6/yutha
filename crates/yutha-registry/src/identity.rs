//! `ControlPlaneIdentity` is defined in [`yutha-passport`](../../yutha_passport/index.html)
//! so that transport, capability, and registry can all consume it without
//! creating a dependency cycle (registry already depends on capability and
//! transport on its own path doesn't, but capability is harder).
//!
//! This module re-exports for callers that used `yutha_registry::ControlPlaneIdentity`
//! historically.

pub use yutha_passport::ControlPlaneIdentity;

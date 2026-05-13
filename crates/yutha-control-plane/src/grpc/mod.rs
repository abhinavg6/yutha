//! gRPC service handlers for the Yutha control plane.
//!
//! Each submodule implements one of the four services declared in
//! [`/spec/control-plane/v1.proto`](../../../../spec/control-plane/v1.proto):
//!
//! - [`admission`] — register, revoke, rotate_key, get_topology *(wired; rotate_key is UNIMPLEMENTED pending a spec RFC)*
//! - [`capability`] — issue, attenuate, revoke, check *(wired)*
//! - [`envelope`] — send (unary), subscribe (server-streaming) *(wired)*
//! - [`receipt`] — get, query *(wired)*
//!
//! Every authenticated handler calls
//! [`crate::auth::require_bearer_auth`] at the top of its body — the only
//! anonymous RPC is `AdmissionService.Register`, where the passport is the
//! credential.
//!
//! ## Shared state
//!
//! Each handler struct holds an `Arc<ControlPlaneState>` carrying the
//! in-process backends. That state is built by [`crate::main`] and shared
//! across all four handler structs — the gRPC handlers are *thin* wrappers
//! around the same library types the binary already used in Phase 1.

use std::sync::Arc;

use yutha_capability::CapabilityStore;
use yutha_passport::{ControlPlaneIdentity, PassportStore};
use yutha_receipt::{PassportResolver, ReceiptStore};
use yutha_registry::Registry;
use yutha_transport::Transport;

pub mod admission;
pub mod capability;
pub mod envelope;
pub mod error;
pub mod receipt;

/// Shared in-process state plumbed into every gRPC handler.
///
/// Handlers hold an `Arc<ControlPlaneState>` and delegate to the
/// appropriate trait-object backend. This keeps the gRPC layer thin —
/// it's a request decoder + an auth check + a delegation, nothing more.
///
/// `#[allow(dead_code)]` covers fields no wired handler yet reads
/// (`passport_store` is one — the resolver adapter is what the auth
/// path uses; `passport_store` is exposed for forward-compat with
/// future operator endpoints).
#[allow(dead_code)]
#[derive(Clone)]
pub struct ControlPlaneState {
    pub registry: Arc<dyn Registry>,
    pub passport_store: Arc<dyn PassportStore>,
    pub capability_store: Arc<dyn CapabilityStore>,
    pub transport: Arc<dyn Transport>,
    pub receipt_store: Arc<dyn ReceiptStore>,
    pub resolver: Arc<dyn PassportResolver>,
    pub control_plane_identity: Arc<ControlPlaneIdentity>,
}

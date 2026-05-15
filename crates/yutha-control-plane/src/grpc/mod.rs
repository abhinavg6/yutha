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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::{Notify, RwLock};
use yutha_capability::CapabilityStore;
use yutha_core::{AgentId, PublicKey};
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

    /// Operator public key the server trusts for `OperatorBearerToken`
    /// verification (RFC 0009 §3.4). When `None`, `OperatorRevoke`
    /// returns `FAILED_PRECONDITION: operator credentials not enabled`.
    /// Set at startup via the `--operator-public-key` CLI flag.
    pub operator_public_key: Option<PublicKey>,

    /// Agent ids that have been revoked (self or operator) during this
    /// process's lifetime. Consulted by every bearer-auth check —
    /// revoked agents are rejected with `UNAUTHENTICATED: agent
    /// revoked` regardless of remaining token-window time
    /// (RFC 0009 §3.3 active tear-down).
    ///
    /// In a multi-process / restart-replay deployment the
    /// `PassportStore` is the authoritative source (it carries the
    /// `is_revoked` flag); this in-memory set is the fast path so
    /// hot bearer-auth doesn't have to round-trip to passport storage
    /// on every call. State is rebuilt from receipts at startup —
    /// for the Phase-1 in-memory backend, the set is trivially
    /// rebuilt by replaying `agent.revoke` + `agent.operator_revoke`
    /// receipts, but the path isn't load-bearing because the same
    /// `MemoryReceiptStore` instance is used in-process across the
    /// server's lifetime.
    pub revoked_agents: Arc<RwLock<HashSet<AgentId>>>,

    /// Per-agent revocation notifier. Subscribe-stream forwarders
    /// hold a clone of the relevant `Arc<Notify>` and `tokio::select!`
    /// on it; when a revoke lands, we call `notify_waiters()` on the
    /// target's entry, which fires the active-stream tear-down
    /// (RFC 0009 §3.3) — the forwarder exits within tens of
    /// milliseconds and the gRPC stream closes from the client's
    /// perspective.
    pub revocation_signals: Arc<RwLock<HashMap<AgentId, Arc<Notify>>>>,
}

impl ControlPlaneState {
    /// Returns the `Notify` for an agent's stream-revocation signal,
    /// creating one if absent. Subscribers store the returned `Arc`
    /// and listen on it; revokers look it up and fire `notify_waiters()`.
    pub async fn revocation_signal_for(&self, agent_id: AgentId) -> Arc<Notify> {
        // Fast path: read lock + lookup.
        {
            let read = self.revocation_signals.read().await;
            if let Some(n) = read.get(&agent_id) {
                return Arc::clone(n);
            }
        }
        // Slow path: write lock + recheck + insert.
        let mut write = self.revocation_signals.write().await;
        Arc::clone(
            write
                .entry(agent_id)
                .or_insert_with(|| Arc::new(Notify::new())),
        )
    }

    /// Mark `agent_id` revoked and fire the active-stream tear-down.
    /// Called by both the self-revoke and operator-revoke handlers
    /// after the registry produces the corresponding receipt.
    pub async fn mark_revoked(&self, agent_id: AgentId) {
        self.revoked_agents.write().await.insert(agent_id);
        // Signal any active subscribe stream for this agent. If none
        // exist, this is a no-op — `notify_waiters` doesn't queue.
        if let Some(notify) = self.revocation_signals.read().await.get(&agent_id) {
            notify.notify_waiters();
        }
    }

    /// True if the given agent has been revoked during this process's
    /// lifetime. Bearer auth (`require_active_bearer_auth`) consults
    /// this BEFORE the passport-resolver lookup so that an evicted
    /// agent whose passport was deregistered as part of the revoke
    /// still surfaces as "agent revoked" rather than "agent is not
    /// registered" — RFC 0009 §3.3.
    pub async fn is_revoked(&self, agent_id: &AgentId) -> bool {
        self.revoked_agents.read().await.contains(agent_id)
    }
}

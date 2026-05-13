//! `AdmissionService` gRPC handler.
//!
//! Maps the four RPCs from
//! [`/spec/control-plane/v1.proto`](../../../../spec/control-plane/v1.proto):
//!
//! - [`AdmissionHandler::register`] — passport as credential (no bearer
//!   token; the only RPC in the entire control-plane surface that's
//!   anonymous, per spec).
//! - [`AdmissionHandler::revoke`] — bearer-authenticated; caller may
//!   self-revoke or an operator may revoke any agent (operator policy is
//!   currently scaffolding — see TODOs).
//! - [`AdmissionHandler::rotate_key`] — bearer-authenticated; the new
//!   passport's `agent_signature` proves the new-key holder consents,
//!   and the registry enforces continuity with the previously-registered
//!   passport.
//! - [`AdmissionHandler::get_topology`] — bearer-authenticated; returns
//!   the swarm's immutable topology document. Clients cache after first
//!   call.
//!
//! All non-Register handlers call [`crate::auth::require_bearer_auth`]
//! before doing any work; the helper validates the bearer token end-to-end
//! against the registered passport public key.

use std::sync::Arc;

use tonic::{Request, Response, Status};
use yutha_passport::Passport;
use yutha_proto::control_plane::v1::{
    admission_service_server::AdmissionService, GetTopologyRequest, GetTopologyResponse,
    RegisterRequest, RegisterResponse, RevokeRequest, RevokeResponse, RotateKeyRequest,
    RotateKeyResponse,
};

use crate::auth::require_bearer_auth;

use super::error::{missing_field, ErrorIntoStatus};
use super::ControlPlaneState;

/// Concrete `AdmissionService` implementation. Holds an
/// `Arc<ControlPlaneState>` and delegates to the registry backend.
pub struct AdmissionHandler {
    state: Arc<ControlPlaneState>,
}

impl AdmissionHandler {
    pub fn new(state: Arc<ControlPlaneState>) -> Self {
        Self { state }
    }

    /// Convenience: borrow the swarm id this control plane is bound to.
    /// Used by the auth helper for bearer-token swarm binding.
    fn swarm_id(&self) -> yutha_core::SwarmId {
        self.state.registry.topology().swarm_id
    }
}

#[tonic::async_trait]
impl AdmissionService for AdmissionHandler {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        // NOTE: Register is intentionally unauthenticated. The passport is
        // itself the credential being presented — there's no prior identity
        // to authenticate against. The registry verifies the passport's
        // self-signature and applies the swarm's admission policy.
        let req = request.into_inner();
        let passport_proto = req
            .passport
            .as_ref()
            .ok_or_else(|| missing_field("passport"))?;
        let passport = Passport::try_from(passport_proto).map_err(|e| e.to_status())?;

        // The registry handles: self-signature verification, swarm_id
        // check, admission policy, persistence, and registration-receipt
        // emission. We just translate the outcome to the wire shape.
        let outcome = self
            .state
            .registry
            .register(passport)
            .await
            .map_err(|e| e.to_status())?;

        Ok(Response::new(RegisterResponse {
            result: Some((&outcome).into()),
        }))
    }

    async fn revoke(
        &self,
        request: Request<RevokeRequest>,
    ) -> Result<Response<RevokeResponse>, Status> {
        let auth = require_bearer_auth(&request, &self.state.resolver, self.swarm_id()).await?;
        let req = request.into_inner();

        let target_proto = req
            .agent_id
            .as_ref()
            .ok_or_else(|| missing_field("agent_id"))?;
        let target = yutha_core::AgentId::try_from(target_proto).map_err(|e| e.to_status())?;

        // Self-revoke is always allowed. Operator-level revoke (caller !=
        // target) is a TODO — needs an operator-identity concept that the
        // current scaffolding doesn't yet model. Reject for now so the
        // surface is explicit about what it does and doesn't enforce.
        if auth.agent_id != target {
            return Err(Status::permission_denied(
                "cross-agent revoke not yet permitted; operator identity TODO",
            ));
        }

        let receipt_id = self
            .state
            .registry
            .revoke(&target, &req.reason)
            .await
            .map_err(|e| e.to_status())?;

        Ok(Response::new(RevokeResponse {
            revocation_receipt: Some((&receipt_id).into()),
        }))
    }

    async fn rotate_key(
        &self,
        request: Request<RotateKeyRequest>,
    ) -> Result<Response<RotateKeyResponse>, Status> {
        // Auth check still happens — even a not-yet-implemented endpoint
        // must reject unauthenticated callers so the failure mode is
        // honest about which layer rejected.
        let auth = require_bearer_auth(&request, &self.state.resolver, self.swarm_id()).await?;
        let _ = auth;
        let _ = request.into_inner();

        // SPEC GAP: `RotateKeyRequest` carries only `new_public_key` plus
        // an `authorization_signature` from the OLD key. But the
        // ergonomic `Registry::rotate_key` takes a *Passport* — and the
        // new passport's self-signature must be made with the new
        // *private* key, which only the agent holds. The control plane
        // can't construct it server-side.
        //
        // Two ways to close this gap, both spec-level:
        //   (a) Widen `RotateKeyRequest` to carry a full new `Passport`
        //       (signed with new key), keeping `authorization_signature`
        //       as the proof-of-consent from the old key.
        //   (b) Keep the current shape but redefine "rotation" as
        //       producing a registry-side stub passport with no self-sig
        //       — adds a new state machine and breaks the "every
        //       passport is self-signed" invariant.
        //
        // (a) is the cleaner path; landing it is an RFC, not Stage 2c
        // work. Until that lands the endpoint returns UNIMPLEMENTED so
        // SDK authors get a clear signal.
        Err(Status::unimplemented(
            "rotate_key blocked on spec gap (RotateKeyRequest cannot carry a self-signed new passport); see /spec/control-plane/v1.proto and RFC tracker",
        ))
    }

    async fn get_topology(
        &self,
        request: Request<GetTopologyRequest>,
    ) -> Result<Response<GetTopologyResponse>, Status> {
        let _auth = require_bearer_auth(&request, &self.state.resolver, self.swarm_id()).await?;
        let topology = self.state.registry.topology();
        Ok(Response::new(GetTopologyResponse {
            topology: Some(topology.into()),
        }))
    }
}

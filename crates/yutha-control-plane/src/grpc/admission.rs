//! `AdmissionService` gRPC handler.
//!
//! Maps the four RPCs from
//! [`/spec/control-plane/v1.proto`](../../../../spec/control-plane/v1.proto):
//!
//! - [`AdmissionHandler::register`] — passport as credential (no bearer
//!   token; the only RPC in the entire control-plane surface that's
//!   anonymous, per spec).
//! - [`AdmissionHandler::revoke`] — agent-bearer-authenticated;
//!   self-revoke only. Cross-agent revocation goes through
//!   [`AdmissionHandler::operator_revoke`] under an
//!   `OperatorBearerToken`.
//! - [`AdmissionHandler::operator_revoke`] — operator-bearer-
//!   authenticated (RFC 0009). Returns `FAILED_PRECONDITION` when the
//!   server was launched without `--operator-public-key`. On success
//!   emits `agent.operator_revoke` and triggers active-stream
//!   tear-down on the target.
//! - [`AdmissionHandler::rotate_key`] — agent-bearer-authenticated;
//!   currently `UNIMPLEMENTED` pending a wire-format RFC.
//! - [`AdmissionHandler::get_topology`] — agent-bearer-authenticated;
//!   returns the swarm's immutable topology document. Clients cache
//!   after first call.
//!
//! All authenticated handlers call either
//! [`crate::auth::require_active_bearer_auth`] (agent path; consults
//! the revoked-set per RFC 0009 §3.3) or
//! [`crate::auth::require_operator_bearer_auth`] (operator path).

use std::sync::Arc;

use tonic::{Request, Response, Status};
use yutha_passport::Passport;
use yutha_proto::control_plane::v1::{
    admission_service_server::AdmissionService, GetTopologyRequest, GetTopologyResponse,
    OperatorRevokeRequest, OperatorRevokeResponse, RegisterRequest, RegisterResponse,
    RevokeRequest, RevokeResponse, RotateKeyRequest, RotateKeyResponse,
};

use crate::auth::{require_active_bearer_auth, require_operator_bearer_auth};

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
        let auth = require_active_bearer_auth(&request, &self.state).await?;
        let req = request.into_inner();

        let target_proto = req
            .agent_id
            .as_ref()
            .ok_or_else(|| missing_field("agent_id"))?;
        let target = yutha_core::AgentId::try_from(target_proto).map_err(|e| e.to_status())?;

        // `Revoke` is self-revoke only. Operator-level eviction lives
        // on `OperatorRevoke` (RFC 0009) and uses a distinct bearer
        // variant. A caller presenting an agent bearer with a target
        // other than themselves is asking for the wrong RPC.
        if auth.agent_id != target {
            return Err(Status::permission_denied(
                "cross-agent revoke uses AdmissionService.OperatorRevoke; \
                 this RPC is self-revoke only",
            ));
        }

        let receipt_id = self
            .state
            .registry
            .revoke(&target, &req.reason)
            .await
            .map_err(|e| e.to_status())?;

        // RFC 0009 §3.3 active-stream tear-down: mark the agent in
        // the in-process revoked-set (every future bearer-auth check
        // rejects them) and fire the per-agent revocation Notify so
        // any open subscribe stream tears down within
        // tens-of-milliseconds rather than waiting for token expiry.
        self.state.mark_revoked(target).await;

        Ok(Response::new(RevokeResponse {
            revocation_receipt: Some((&receipt_id).into()),
        }))
    }

    async fn operator_revoke(
        &self,
        request: Request<OperatorRevokeRequest>,
    ) -> Result<Response<OperatorRevokeResponse>, Status> {
        // Verify the operator bearer. Returns FAILED_PRECONDITION when
        // the server has no operator-public-key configured (RFC 0009
        // §3.4 — "operator credentials not enabled" is the spec error
        // string).
        let op_auth = require_operator_bearer_auth(&request, &self.state).await?;
        let req = request.into_inner();

        let target_proto = req.target.as_ref().ok_or_else(|| missing_field("target"))?;
        let target = yutha_core::AgentId::try_from(target_proto).map_err(|e| e.to_status())?;

        // Land the agent-eviction receipt FIRST via the registry's
        // operator-revoke path. This emits `agent.operator_revoke`
        // (distinct from `agent.revoke` for audit clarity).
        let receipt_id = self
            .state
            .registry
            .operator_revoke(&target, &op_auth.operator_id, &req.reason)
            .await
            .map_err(|e| e.to_status())?;

        // RFC 0009 §3.2 cascade: when the operator opts in, enumerate
        // every capability the target currently holds (`subject ==
        // target`) and revoke each with a `capability.revoke` receipt.
        // Ordering: receipts land in the order `list_for_subject`
        // returns ids; the operator's audit query can reconstruct the
        // sequence from receipt monotonic_ns.
        //
        // Errors mid-cascade: if one cap-revoke fails, surface as
        // INTERNAL. The agent-revoke receipt has already landed by
        // this point, so the eviction itself stands — only the
        // cascade is partial. Operators can re-invoke
        // `OperatorRevoke` (idempotent: re-revoke of an already-
        // revoked agent is a noop receipt-wise, and the cascade will
        // skip already-revoked caps via `list_for_subject`'s filter).
        let cascade_receipts: Vec<yutha_proto::common::v1::Hash> = if req.cascade_capabilities {
            let cap_ids = self
                .state
                .capability_store
                .list_for_subject(&target)
                .await
                .map_err(|e| e.to_status())?;
            let mut out = Vec::with_capacity(cap_ids.len());
            let reason = format!("cascade from operator-revoke of {target}");
            for cap_id in cap_ids {
                let rid = self
                    .state
                    .capability_store
                    .revoke(&cap_id, &reason)
                    .await
                    .map_err(|e| e.to_status())?;
                out.push((&rid).into());
            }
            out
        } else {
            Vec::new()
        };

        // Same tear-down as self-revoke: add to revoked-set + fire
        // the per-agent Notify so active subscribe streams close.
        self.state.mark_revoked(target).await;

        Ok(Response::new(OperatorRevokeResponse {
            revocation_receipt: Some((&receipt_id).into()),
            cascade_receipts,
        }))
    }

    async fn rotate_key(
        &self,
        request: Request<RotateKeyRequest>,
    ) -> Result<Response<RotateKeyResponse>, Status> {
        // Auth check still happens — even a not-yet-implemented endpoint
        // must reject unauthenticated callers so the failure mode is
        // honest about which layer rejected.
        let auth = require_active_bearer_auth(&request, &self.state).await?;
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
        let _auth = require_active_bearer_auth(&request, &self.state).await?;
        let topology = self.state.registry.topology();
        Ok(Response::new(GetTopologyResponse {
            topology: Some(topology.into()),
        }))
    }
}

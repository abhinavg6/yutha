//! `CapabilityService` gRPC handler.
//!
//! Bridges the four RPCs from
//! [`/spec/control-plane/v1.proto`](../../../../spec/control-plane/v1.proto)
//! to the in-process [`CapabilityStore`](yutha_capability::CapabilityStore).
//!
//! All four RPCs require bearer auth (per
//! [`crate::auth::require_bearer_auth`]); the passport itself is NOT the
//! credential here (that's `AdmissionService.Register`'s special case).
//!
//! ## Issuance signing (scaffolding)
//!
//! The spec says `IssueCapabilityRequest.capability` arrives unsigned and
//! "the control plane signs and persists in one transaction." In a
//! production setup, the signing key depends on the capability's `issuer`
//! field — `Issuer::Agent(_)` would be signed by the agent (server-side
//! signing would be wrong), `Issuer::Operator(_)` by an operator-supplied
//! key, `Issuer::ControlPlane(_)` by the CP. The current scaffolding takes
//! a shortcut: if the request arrives without a signature, sign with the
//! CP's key regardless of what `issuer` declares. This is good enough for
//! local-dev and SDK development; a future RFC will pin down the
//! per-issuer signing path.
//!
//! ## Check semantics
//!
//! `Check` routes through [`yutha_capability::CapabilityStore::check`].
//! The store's check is the load-bearing one: it walks the parent
//! chain, enforces revocation + validity-window, intersects scopes,
//! evaluates caveats, AND emits a `capability.check.pass` or
//! `capability.check.deny` receipt as a substrate observation.
//!
//! The handler derives the capability's content-address (cap_id) from
//! the proto on the wire and calls `store.check(&cap_id, descriptor)`.
//! Capabilities the server has never seen — i.e. never issued or
//! attenuated through the gRPC surface — will fail the lookup with a
//! "missing chain link" error rather than silently passing. That's
//! intentional: stateless evaluation is available locally via
//! `Capability::check(&descriptor)` for callers who want it, but the
//! gRPC surface is the auditable, revocation-aware path.

use std::sync::Arc;

use tonic::{Request, Response, Status};
use yutha_capability::{ActionDescriptor, Capability, CapabilityBuilder, Caveat, Scope};
use yutha_core::{Hash, Timestamp};
use yutha_crypto::canonical::{content_address, Canonical};
use yutha_proto::capability::v1 as cap_proto;
use yutha_proto::control_plane::v1::{
    capability_service_server::CapabilityService, AttenuateRequest, AttenuateResponse,
    CheckRequest, CheckResponse, IssueCapabilityRequest, IssueCapabilityResponse,
    RevokeCapabilityRequest, RevokeCapabilityResponse,
};

use crate::auth::require_active_bearer_auth;

use super::error::{missing_field, ErrorIntoStatus};
use super::ControlPlaneState;

pub struct CapabilityHandler {
    state: Arc<ControlPlaneState>,
}

impl CapabilityHandler {
    pub fn new(state: Arc<ControlPlaneState>) -> Self {
        Self { state }
    }

    /// Scaffolding shortcut: if the capability arrives unsigned, sign it
    /// with the control plane's key in place. See module-level note for
    /// why this is a simplification, not the production signing path.
    //
    // clippy::result_large_err: this returns Result<(), Status> where ()
    // is zero-sized and Status is ~176 bytes, which trips the lint.
    // Boxing Status here would force the whole gRPC handler layer to
    // un-box (Status is the canonical Err type for tonic), so we accept
    // the imbalance locally.
    #[allow(clippy::result_large_err)]
    fn sign_with_cp(&self, cap: &mut Capability) -> Result<(), Status> {
        if cap.issuer_signature.is_some() {
            return Ok(());
        }
        let bytes = cap
            .canonical_bytes()
            .map_err(|e| Status::internal(format!("canonical bytes: {e}")))?;
        let sig = self.state.control_plane_identity.sign(&bytes);
        cap.issuer_signature = Some(sig);
        Ok(())
    }
}

#[tonic::async_trait]
impl CapabilityService for CapabilityHandler {
    async fn issue(
        &self,
        request: Request<IssueCapabilityRequest>,
    ) -> Result<Response<IssueCapabilityResponse>, Status> {
        let _auth = require_active_bearer_auth(&request, &self.state).await?;
        let req = request.into_inner();

        let cap_proto = req
            .capability
            .as_ref()
            .ok_or_else(|| missing_field("capability"))?;
        let mut cap = Capability::try_from(cap_proto).map_err(|e| e.to_status())?;
        self.sign_with_cp(&mut cap)?;

        let outcome = self
            .state
            .capability_store
            .issue(cap)
            .await
            .map_err(|e| e.to_status())?;

        Ok(Response::new(IssueCapabilityResponse {
            capability_id: Some((&outcome.capability_id).into()),
            issuance_receipt: Some((&outcome.issuance_receipt).into()),
        }))
    }

    async fn attenuate(
        &self,
        request: Request<AttenuateRequest>,
    ) -> Result<Response<AttenuateResponse>, Status> {
        let _auth = require_active_bearer_auth(&request, &self.state).await?;
        let req = request.into_inner();

        // Unwrap the wire shape: control_plane.v1.AttenuateRequest wraps
        // capability.v1.AttenuateRequest.
        let inner = req
            .request
            .as_ref()
            .ok_or_else(|| missing_field("request"))?;
        let parent_hash = Hash::try_from(
            inner
                .parent
                .as_ref()
                .ok_or_else(|| missing_field("parent"))?,
        )
        .map_err(|e| e.to_status())?;
        let additional_scope = inner
            .additional_constraints
            .as_ref()
            .map(Scope::from)
            .unwrap_or_else(Scope::empty);
        let additional_caveats = inner
            .additional_caveats
            .iter()
            .map(Caveat::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_status())?;
        let valid_until = match inner.valid_until.as_ref() {
            Some(t) => Timestamp::try_from(t).map_err(|e| e.to_status())?,
            // Attenuation must carry an expiry per spec ("valid_until
            // cannot exceed the parent's"). If missing, reject up front.
            None => return Err(missing_field("valid_until")),
        };

        // Look up parent and intersect scope.
        let parent = self
            .state
            .capability_store
            .lookup(&parent_hash)
            .await
            .map_err(|e| e.to_status())?
            .ok_or_else(|| {
                Status::not_found(format!("parent capability not found: {parent_hash}"))
            })?;

        // Spec: "valid_until cannot exceed the parent's." Enforce here so
        // the store doesn't have to re-derive the rule.
        if valid_until.monotonic_ns > parent.valid_until.monotonic_ns {
            return Err(Status::failed_precondition(
                "attenuated valid_until exceeds parent's",
            ));
        }

        // Build the child as an intersection of parent + additional
        // constraints; caveats are additive. Subject stays the same;
        // multi-agent delegation (subject changes hands) is a future RFC.
        let child_scope = parent.scope.intersect(&additional_scope);
        let mut all_caveats = parent.caveats.clone();
        all_caveats.extend(additional_caveats);

        let mut builder: CapabilityBuilder = Capability::builder()
            .spec_version(parent.spec_version.clone())
            // Child gets its own capability_id; use a fresh UUID v7.
            .capability_id(yutha_core::AgentId::new().as_bytes().to_vec())
            .swarm_id(parent.swarm_id)
            .issuer(parent.issuer.clone())
            .subject(parent.subject)
            .scope(child_scope)
            .parent(parent_hash.clone())
            .valid_from(Timestamp::now())
            .valid_until(valid_until);
        for c in all_caveats {
            builder = builder.caveat(c);
        }
        let mut child = builder
            .build()
            .map_err(|e| Status::internal(format!("build child capability: {e}")))?;
        self.sign_with_cp(&mut child)?;

        let outcome = self
            .state
            .capability_store
            .attenuate(child.clone())
            .await
            .map_err(|e| e.to_status())?;

        Ok(Response::new(AttenuateResponse {
            response: Some(cap_proto::AttenuateResponse {
                child: Some((&child).into()),
                attenuation_receipt: Some((&outcome.issuance_receipt).into()),
            }),
        }))
    }

    async fn revoke(
        &self,
        request: Request<RevokeCapabilityRequest>,
    ) -> Result<Response<RevokeCapabilityResponse>, Status> {
        // SCAFFOLDING: any bearer-authenticated caller can revoke any
        // capability. Production hardening: only the cap's subject, its
        // issuer, or an operator should be allowed. Gating that requires
        // an operator-identity concept the current scaffolding doesn't
        // yet model — same TODO as `AdmissionService.Revoke`'s
        // cross-agent path.
        let _auth = require_active_bearer_auth(&request, &self.state).await?;
        let req = request.into_inner();

        let inner = req
            .request
            .as_ref()
            .ok_or_else(|| missing_field("request"))?;
        let cap_id = Hash::try_from(
            inner
                .capability
                .as_ref()
                .ok_or_else(|| missing_field("capability"))?,
        )
        .map_err(|e| e.to_status())?;

        let revocation_receipt = self
            .state
            .capability_store
            .revoke(&cap_id, &inner.reason)
            .await
            .map_err(|e| e.to_status())?;

        Ok(Response::new(RevokeCapabilityResponse {
            response: Some(cap_proto::RevokeResponse {
                revocation_receipt: Some((&revocation_receipt).into()),
                effective_at: Some((&Timestamp::now()).into()),
            }),
        }))
    }

    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let _auth = require_active_bearer_auth(&request, &self.state).await?;
        let req = request.into_inner();

        let inner = req
            .request
            .as_ref()
            .ok_or_else(|| missing_field("request"))?;
        let cap_proto = inner
            .capability
            .as_ref()
            .ok_or_else(|| missing_field("capability"))?;
        let action_proto = inner
            .action
            .as_ref()
            .ok_or_else(|| missing_field("action"))?;

        let cap = Capability::try_from(cap_proto).map_err(|e| e.to_status())?;
        let descriptor: ActionDescriptor = action_proto.into();

        // Stateful path through the store: walks the parent chain,
        // honors revocation + validity window, intersects scopes,
        // evaluates caveats, and emits a check.pass / check.deny
        // receipt. The cap_id is derived from the proto's canonical
        // bytes (same derivation `issue` and `revoke` use) so a cap
        // a client previously issued through this server resolves to
        // the persisted record. Stateless local eval is still
        // available via `Capability::check(&descriptor)` for callers
        // that want it; the gRPC surface is the auditable,
        // revocation-aware path.
        let cap_id = content_address(&cap)
            .map_err(|e| Status::internal(format!("content-address capability: {e}")))?;
        let evaluation = self
            .state
            .capability_store
            .check(&cap_id, &descriptor)
            .await
            .map_err(|e| e.to_status())?;

        Ok(Response::new(CheckResponse {
            response: Some(
                evaluation
                    .outcome
                    .to_proto_with_receipt(Some(&evaluation.check_receipt)),
            ),
        }))
    }
}

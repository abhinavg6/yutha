//! `ConstitutionService` gRPC handler.
//!
//! Implements the two RPCs from
//! [`/spec/control-plane/v1.proto`](../../../../spec/control-plane/v1.proto):
//!
//! - [`ConstitutionHandler::activate`] — operator-bearer-authenticated.
//!   Publishes a new constitution. Runs the full load-time validation
//!   pass from RFC 0012 §3.3 via `yutha-cedar-plus`'s
//!   `ConstitutionLoader`, then activates both the evaluator and the
//!   enforcement engine, and emits a `constitution.activate` receipt.
//! - [`ConstitutionHandler::get_active`] — agent-bearer-authenticated.
//!   Returns the currently-active constitution.
//!
//! This is the F10 control-plane surface for Phase 2's constitution
//! layer. Once activated, `EnvelopeHandler::send` and the
//! `CapabilityHandler` RPCs evaluate against it (F10d-g, follow-on).

use std::sync::Arc;

use tonic::{Request, Response, Status};
use yutha_cedar_plus::{parse_engine_config_yaml, Constitution, ConstitutionEvaluator};
use yutha_core::{Hash, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_proto::control_plane::v1::{
    constitution_service_server::ConstitutionService, ActivateConstitutionRequest,
    ActivateConstitutionResponse, ActivateShadowConstitutionRequest,
    ActivateShadowConstitutionResponse, ClearShadowConstitutionRequest,
    ClearShadowConstitutionResponse, Constitution as ConstitutionProto,
    GetActiveConstitutionRequest, GetActiveConstitutionResponse,
    GetActiveShadowConstitutionRequest, GetActiveShadowConstitutionResponse,
    PromoteShadowConstitutionRequest, PromoteShadowConstitutionResponse,
};
use yutha_receipt::{AppendOptions, Evidence, Receipt, SignatureRole, SignedBy};

use crate::auth::{require_active_bearer_auth, require_operator_bearer_auth};

use super::error::{missing_field, ErrorIntoStatus};
use super::ControlPlaneState;

/// Concrete `ConstitutionService` implementation. Holds an
/// `Arc<ControlPlaneState>` and delegates to the cedar-plus evaluator.
pub struct ConstitutionHandler {
    state: Arc<ControlPlaneState>,
}

impl ConstitutionHandler {
    pub fn new(state: Arc<ControlPlaneState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl ConstitutionService for ConstitutionHandler {
    async fn activate(
        &self,
        request: Request<ActivateConstitutionRequest>,
    ) -> Result<Response<ActivateConstitutionResponse>, Status> {
        // Operator-only per RFC 0010 §3.6 — constitutions reshape the
        // swarm's policy surface, so the same trust-root that mints
        // bearer credentials authors them.
        let op_auth = require_operator_bearer_auth(&request, &self.state).await?;

        let req = request.into_inner();
        let constitution_proto = req
            .constitution
            .as_ref()
            .ok_or_else(|| missing_field("constitution"))?;

        let constitution = constitution_from_proto(constitution_proto)?;
        let constitution_hash = constitution.constitution_hash.clone();

        // Activate the cedar-plus evaluator. This runs the full
        // load-time validation pass — structural validators,
        // named-predicate resolution, Cedar Validator in Strict mode,
        // load-time bound enforcement, Layer B synthesis. Any failure
        // here means the constitution doesn't activate; the operator
        // sees a specific CedarPlusError mapped to a tonic Status.
        let _activated_hash = self
            .state
            .cedar_plus
            .activate(constitution)
            .await
            .map_err(|e| cedar_plus_to_status(&e))?;

        // Bind the freshly-activated constitution onto the enforcement
        // engine too. The engine needs the active constitution to
        // match incoming receipts against `enforcement_rules`. Re-fetch
        // the activated constitution to read its constitution_version
        // for the receipt below.
        let constitution_version = if let Some(active) = self.state.cedar_plus.current().await {
            self.state.enforcement.activate(active.clone()).await;
            active.constitution.constitution_version.clone()
        } else {
            // Defensive — `activate` above succeeded, so current()
            // should always return Some here. If it somehow doesn't,
            // we still emit the receipt against the constitution
            // version we just read from the wire.
            constitution_proto.constitution_version.clone()
        };

        // Emit the `constitution.activate` receipt. Audit-trail anchor
        // for every subsequent `constitution.evaluate.*` receipt run
        // under this constitution (per /spec/receipt/canonical-actions.md).
        let activate_receipt = emit_constitution_activate_receipt(
            &self.state,
            &constitution_hash,
            &constitution_version,
            &op_auth.swarm_id,
        )
        .await?;

        Ok(Response::new(ActivateConstitutionResponse {
            constitution_hash: Some((&constitution_hash).into()),
            activate_receipt: Some((&activate_receipt).into()),
        }))
    }

    async fn get_active(
        &self,
        request: Request<GetActiveConstitutionRequest>,
    ) -> Result<Response<GetActiveConstitutionResponse>, Status> {
        let _auth = require_active_bearer_auth(&request, &self.state).await?;

        let Some(active) = self.state.cedar_plus.current().await else {
            return Err(Status::not_found("no active constitution"));
        };

        let constitution_hash = active.constitution.constitution_hash.clone();
        let proto = constitution_to_proto(&active.constitution);

        Ok(Response::new(GetActiveConstitutionResponse {
            constitution: Some(proto),
            constitution_hash: Some((&constitution_hash).into()),
        }))
    }

    // ---- Phase 3b shadow-mode handlers (RFC 0018 §3.2) ----

    async fn activate_shadow(
        &self,
        request: Request<ActivateShadowConstitutionRequest>,
    ) -> Result<Response<ActivateShadowConstitutionResponse>, Status> {
        // Operator-only per RFC 0018 §3.2 — shadow activation reshapes
        // the operator's preview surface and produces a receipt
        // attributed to the operator. Same auth posture as `activate`.
        let op_auth = require_operator_bearer_auth(&request, &self.state).await?;

        let req = request.into_inner();
        let constitution_proto = req
            .constitution
            .as_ref()
            .ok_or_else(|| missing_field("constitution"))?;
        let constitution = constitution_from_proto(constitution_proto)?;

        // Capture the parent-active hash BEFORE the activate_shadow
        // write — the receipt's `parent_active_constitution_hash`
        // evidence reflects what was active at the moment the shadow
        // got loaded. A concurrent direct `Activate` between this
        // read and the activate_shadow write would race for the
        // recorded parent; the race is benign (audit clarity holds at
        // single-operator cadence; concurrent operator activates are
        // rare and the parent_active is best-effort context).
        let parent_active_hash = self
            .state
            .cedar_plus
            .current()
            .await
            .map(|a| a.constitution.constitution_hash.clone());

        let shadow_constitution_hash = self
            .state
            .cedar_plus
            .activate_shadow(constitution)
            .await
            .map_err(|e| cedar_plus_to_status(&e))?;

        // Re-read the shadow slot to capture `constitution_version` +
        // `schema_version` for the receipt. Defensive — activate_shadow
        // just wrote the slot, so current_shadow() should always
        // return Some. If a concurrent `clear_shadow` / `promote_shadow`
        // races between our write and this read, fall back to the
        // shapes pulled from the wire proto.
        let (shadow_constitution_version, schema_version) =
            if let Some(shadow_active) = self.state.cedar_plus.current_shadow().await {
                (
                    shadow_active.constitution.constitution_version.clone(),
                    shadow_active.constitution.schema_version.clone(),
                )
            } else {
                (
                    constitution_proto.constitution_version.clone(),
                    constitution_proto.schema_version.clone(),
                )
            };

        let activate_receipt = emit_constitution_shadow_activate_receipt(
            &self.state,
            &shadow_constitution_hash,
            &shadow_constitution_version,
            parent_active_hash.as_ref(),
            &schema_version,
            &op_auth.swarm_id,
        )
        .await?;

        Ok(Response::new(ActivateShadowConstitutionResponse {
            shadow_constitution_hash: Some((&shadow_constitution_hash).into()),
            shadow_activate_receipt: Some((&activate_receipt).into()),
        }))
    }

    async fn clear_shadow(
        &self,
        request: Request<ClearShadowConstitutionRequest>,
    ) -> Result<Response<ClearShadowConstitutionResponse>, Status> {
        let op_auth = require_operator_bearer_auth(&request, &self.state).await?;

        // Capture the constitution_version of whatever shadow we're
        // about to evict — used for the receipt's
        // `constitution_version` builder field. Read BEFORE
        // clear_shadow drops the slot.
        let shadow_constitution_version = self
            .state
            .cedar_plus
            .current_shadow()
            .await
            .map(|a| a.constitution.constitution_version.clone());

        let previously_shadowed = self.state.cedar_plus.clear_shadow().await;

        let clear_receipt = emit_constitution_shadow_clear_receipt(
            &self.state,
            previously_shadowed.as_ref(),
            shadow_constitution_version.as_deref(),
            &op_auth.swarm_id,
        )
        .await?;

        Ok(Response::new(ClearShadowConstitutionResponse {
            shadow_clear_receipt: Some((&clear_receipt).into()),
            previously_shadowed_constitution_hash: previously_shadowed.as_ref().map(|h| h.into()),
        }))
    }

    async fn promote_shadow(
        &self,
        request: Request<PromoteShadowConstitutionRequest>,
    ) -> Result<Response<PromoteShadowConstitutionResponse>, Status> {
        let op_auth = require_operator_bearer_auth(&request, &self.state).await?;

        let outcome = self
            .state
            .cedar_plus
            .promote_shadow()
            .await
            .ok_or_else(|| {
                Status::failed_precondition(
                    "no shadow constitution to promote; call ActivateShadow first",
                )
            })?;

        // Rebind the enforcement engine onto the new active
        // constitution. Per RFC 0018 §3.2: per-agent reputation +
        // quarantine state is preserved across promote (it's
        // agent-keyed, not constitution-keyed); sliding-window
        // counters reset to match the existing
        // `EnforcementEngine::activate` posture (the new constitution's
        // enforcement_rules may differ in their windowing, so prior
        // counters are no longer meaningful).
        self.state
            .enforcement
            .activate(outcome.promoted.clone())
            .await;

        let promote_receipt = emit_constitution_shadow_promote_receipt(
            &self.state,
            outcome.from_active_constitution_hash.as_ref(),
            &outcome.to_active_constitution_hash,
            &outcome.to_constitution_version,
            &outcome.schema_version,
            &op_auth.swarm_id,
        )
        .await?;

        Ok(Response::new(PromoteShadowConstitutionResponse {
            to_active_constitution_hash: Some((&outcome.to_active_constitution_hash).into()),
            shadow_promote_receipt: Some((&promote_receipt).into()),
            from_active_constitution_hash: outcome
                .from_active_constitution_hash
                .as_ref()
                .map(|h| h.into()),
        }))
    }

    async fn get_active_shadow(
        &self,
        request: Request<GetActiveShadowConstitutionRequest>,
    ) -> Result<Response<GetActiveShadowConstitutionResponse>, Status> {
        // Agent-bearer-authenticated for read symmetry with GetActive
        // — any registered agent may inspect what shadow (if any) is
        // loaded.
        let _auth = require_active_bearer_auth(&request, &self.state).await?;

        let Some(shadow_active) = self.state.cedar_plus.current_shadow().await else {
            // Empty shadow slot is not an error — it's the default
            // posture. Return an empty response per the proto's
            // optional-field semantics. Symmetric with how GetActive
            // returns NOT_FOUND when nothing is active; we return OK
            // with absent fields here because "no shadow" is a stable
            // operator state, not an error.
            return Ok(Response::new(GetActiveShadowConstitutionResponse {
                constitution: None,
                shadow_constitution_hash: None,
            }));
        };

        let shadow_constitution_hash = shadow_active.constitution.constitution_hash.clone();
        let proto = constitution_to_proto(&shadow_active.constitution);

        Ok(Response::new(GetActiveShadowConstitutionResponse {
            constitution: Some(proto),
            shadow_constitution_hash: Some((&shadow_constitution_hash).into()),
        }))
    }
}

/// Build a `yutha_cedar_plus::Constitution` from the wire proto. The
/// content-address (`constitution_hash`) is computed from the
/// canonical bytes of the proto — sha256 over the encoded message
/// with no signature field (the field doesn't exist in v1.1 wire
/// format).
///
/// `clippy::result_large_err`: `tonic::Status` is ~176 bytes and
/// dwarfs the `Constitution` Ok variant. Same trade-off
/// `auth::parse_bearer_header` makes — boxing the error here would
/// force callers to `Box<Status>` propagation that loses ergonomic
/// `?` use against the trait-bound `Result<Response<T>, Status>`
/// of every RPC entry point.
/// Public re-export of [`constitution_from_proto`] so sibling handlers
/// (e.g. the Phase 3c `ReplayService` handler) can reuse the same
/// loader-validation surface as `ConstitutionService.Activate`.
#[allow(clippy::result_large_err)]
pub fn constitution_from_proto_pub(p: &ConstitutionProto) -> Result<Constitution, Status> {
    constitution_from_proto(p)
}

#[allow(clippy::result_large_err)]
fn constitution_from_proto(p: &ConstitutionProto) -> Result<Constitution, Status> {
    let spec_version_proto = p
        .spec_version
        .as_ref()
        .ok_or_else(|| missing_field("constitution.spec_version"))?;
    let spec_version = SpecVersion::try_from(spec_version_proto).map_err(|e| e.to_status())?;

    let swarm_id_proto = p
        .swarm_id
        .as_ref()
        .ok_or_else(|| missing_field("constitution.swarm_id"))?;
    let swarm_id = SwarmId::try_from(swarm_id_proto).map_err(|e| e.to_status())?;

    let issued_at_proto = p
        .issued_at
        .as_ref()
        .ok_or_else(|| missing_field("constitution.issued_at"))?;
    let issued_at = Timestamp::try_from(issued_at_proto).map_err(|e| e.to_status())?;

    let parent_version = match &p.parent_version {
        Some(h) => Some(yutha_core::Hash::try_from(h).map_err(|e| e.to_status())?),
        None => None,
    };

    // Pre-load YAML into the engine config so any parse errors surface
    // here (before the cedar-plus loader is invoked). The loader will
    // re-receive the parsed config alongside the cedar_source.
    let _engine_config =
        parse_engine_config_yaml(&p.engine_config_yaml).map_err(|e| cedar_plus_to_status(&e))?;

    // Content-address the constitution. For v1.1 this is sha256 over
    // the prost-encoded proto (deterministic per `/spec/README.md` §5
    // canonical-serialization rules). Future RFC may evolve to a
    // signature chain.
    let canonical = prost_encode(p);
    let constitution_hash = yutha_crypto::sha256(&canonical);

    // Build the cedar-plus Constitution. We re-parse the engine
    // config inside the loader; pre-parse above is just for early
    // error-mapping.
    Ok(Constitution {
        constitution_hash,
        spec_version,
        schema_version: p.schema_version.clone(),
        constitution_version: p.constitution_version.clone(),
        parent_version,
        swarm_id,
        cedar_source: p.cedar_source.clone(),
        engine_config: parse_engine_config_yaml(&p.engine_config_yaml)
            .map_err(|e| cedar_plus_to_status(&e))?,
        issued_at,
    })
}

/// Encode a `Constitution` back to its wire proto. Used by GetActive.
fn constitution_to_proto(c: &Constitution) -> ConstitutionProto {
    ConstitutionProto {
        spec_version: Some((&c.spec_version).into()),
        schema_version: c.schema_version.clone(),
        constitution_version: c.constitution_version.clone(),
        parent_version: c.parent_version.as_ref().map(|h| h.into()),
        swarm_id: Some((&c.swarm_id).into()),
        cedar_source: c.cedar_source.clone(),
        // We re-emit YAML for the engine config. For F10 this is the
        // round-trip-safe path; F11+ may switch to protobuf for the
        // wire form once the engine-config proto schema lands.
        engine_config_yaml: serde_yaml::to_string(&c.engine_config).unwrap_or_default(),
        issued_at: Some((&c.issued_at).into()),
    }
}

fn prost_encode<M: yutha_proto::Message>(m: &M) -> Vec<u8> {
    let mut buf = Vec::with_capacity(m.encoded_len());
    m.encode(&mut buf).expect("encoding into Vec never fails");
    buf
}

/// Emit a `constitution.activate` receipt. The audit-trail anchor for
/// every subsequent `constitution.evaluate.*` receipt run under this
/// constitution (per /spec/receipt/canonical-actions.md).
///
/// Mirrors the receipt-emission pattern in
/// `envelope::emit_constitution_eval_receipt`: build → canonical sign
/// → append. Actor is the control plane (operator authority lives in
/// the bearer-token signature on the RPC, not on the receipt itself —
/// per RFC 0010 §3.6, the receipt records the *event*, not the
/// authorization chain).
async fn emit_constitution_activate_receipt(
    state: &ControlPlaneState,
    constitution_hash: &Hash,
    constitution_version: &str,
    swarm_id: &SwarmId,
) -> Result<Hash, Status> {
    let spec_version = SpecVersion::parse("1.0.0").map_err(|e| {
        Status::internal(format!("constitution.activate receipt spec_version: {e}"))
    })?;

    let evidence = vec![
        Evidence::new(
            "constitution_hash",
            "type.yutha.dev/v1/Hash",
            constitution_hash.digest.clone(),
        ),
        Evidence::new(
            "constitution_version",
            "type.yutha.dev/v1/String",
            constitution_version.as_bytes().to_vec(),
        ),
    ];

    let mut builder = Receipt::builder()
        .spec_version(spec_version)
        .swarm_id(*swarm_id)
        .actor(state.control_plane_identity.agent_id)
        .action_kind("constitution.activate")
        .constitution_version(constitution_version)
        .occurred_at(Timestamp::now());
    for e in evidence {
        builder = builder.evidence(e);
    }
    let mut receipt = builder
        .build()
        .map_err(|e| Status::internal(format!("constitution.activate receipt build: {e}")))?;

    let bytes = receipt
        .canonical_bytes()
        .map_err(|e| Status::internal(format!("constitution.activate canonical: {e}")))?;
    let sig = state
        .control_plane_identity
        .sign(&bytes)
        .await
        .map_err(|e| Status::internal(format!("constitution.activate signer: {e}")))?;
    receipt
        .signatures
        .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

    let outcome = state
        .receipt_store
        .append(receipt, AppendOptions::default(), state.resolver.as_ref())
        .await
        .map_err(|e| Status::internal(format!("constitution.activate append: {e}")))?;
    Ok(outcome.receipt_id)
}

/// Emit a `constitution.shadow_activate` receipt (RFC 0018 §3.2).
/// Audit-trail anchor for shadow-mode previews. Same emission pattern
/// as `emit_constitution_activate_receipt`; evidence shape per
/// `/spec/receipt/canonical-actions.md`:
///
/// - `shadow_constitution_hash` — content-address of the loaded shadow.
/// - `shadow_constitution_version` — version string of the loaded
///   shadow.
/// - `parent_active_constitution_hash` — content-address of the
///   constitution that was active at the moment of shadow load.
///   Omitted when no active was loaded (fresh-swarm case).
/// - `schema_version` — schema version the shadow was authored
///   against.
async fn emit_constitution_shadow_activate_receipt(
    state: &ControlPlaneState,
    shadow_constitution_hash: &Hash,
    shadow_constitution_version: &str,
    parent_active_hash: Option<&Hash>,
    schema_version: &str,
    swarm_id: &SwarmId,
) -> Result<Hash, Status> {
    let spec_version = SpecVersion::parse("1.0.0").map_err(|e| {
        Status::internal(format!(
            "constitution.shadow_activate receipt spec_version: {e}"
        ))
    })?;

    let mut evidence: Vec<Evidence> = vec![
        Evidence::new(
            "shadow_constitution_hash",
            "type.yutha.dev/v1/Hash",
            shadow_constitution_hash.digest.clone(),
        ),
        Evidence::new(
            "shadow_constitution_version",
            "type.yutha.dev/v1/String",
            shadow_constitution_version.as_bytes().to_vec(),
        ),
        Evidence::new(
            "schema_version",
            "type.yutha.dev/v1/String",
            schema_version.as_bytes().to_vec(),
        ),
    ];
    if let Some(parent) = parent_active_hash {
        evidence.push(Evidence::new(
            "parent_active_constitution_hash",
            "type.yutha.dev/v1/Hash",
            parent.digest.clone(),
        ));
    }

    let mut builder = Receipt::builder()
        .spec_version(spec_version)
        .swarm_id(*swarm_id)
        .actor(state.control_plane_identity.agent_id)
        .action_kind("constitution.shadow_activate")
        .constitution_version(shadow_constitution_version)
        .occurred_at(Timestamp::now());
    for e in evidence {
        builder = builder.evidence(e);
    }
    let mut receipt = builder.build().map_err(|e| {
        Status::internal(format!("constitution.shadow_activate receipt build: {e}"))
    })?;

    let bytes = receipt
        .canonical_bytes()
        .map_err(|e| Status::internal(format!("constitution.shadow_activate canonical: {e}")))?;
    let sig = state
        .control_plane_identity
        .sign(&bytes)
        .await
        .map_err(|e| Status::internal(format!("constitution.shadow_activate signer: {e}")))?;
    receipt
        .signatures
        .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

    let outcome = state
        .receipt_store
        .append(receipt, AppendOptions::default(), state.resolver.as_ref())
        .await
        .map_err(|e| Status::internal(format!("constitution.shadow_activate append: {e}")))?;
    Ok(outcome.receipt_id)
}

/// Emit a `constitution.shadow_clear` receipt (RFC 0018 §3.2).
/// Idempotent: emitted even when the slot was already empty at the
/// time of the call (the receipt records the operator's intent). When
/// the slot was empty, `previously_shadowed_constitution_hash`
/// evidence is omitted; the `constitution_version` builder field
/// falls back to the swarm's active constitution version if known, or
/// `"0.0.0"` if the swarm has no active either.
async fn emit_constitution_shadow_clear_receipt(
    state: &ControlPlaneState,
    previously_shadowed: Option<&Hash>,
    previously_shadowed_constitution_version: Option<&str>,
    swarm_id: &SwarmId,
) -> Result<Hash, Status> {
    let spec_version = SpecVersion::parse("1.0.0").map_err(|e| {
        Status::internal(format!(
            "constitution.shadow_clear receipt spec_version: {e}"
        ))
    })?;

    // For the builder's constitution_version field: prefer the
    // shadow's version (it's the most accurate marker of which
    // constitution this clear receipt is about); fall back to the
    // active constitution's version; fall back to "0.0.0" for the
    // pre-genesis swarm case. The Receipt::builder requires a
    // non-empty constitution_version regardless of receipt content.
    let constitution_version_for_builder: String =
        if let Some(v) = previously_shadowed_constitution_version {
            v.to_string()
        } else if let Some(active) = state.cedar_plus.current().await {
            active.constitution.constitution_version.clone()
        } else {
            "0.0.0".to_string()
        };

    let mut evidence: Vec<Evidence> = Vec::new();
    if let Some(prev) = previously_shadowed {
        evidence.push(Evidence::new(
            "previously_shadowed_constitution_hash",
            "type.yutha.dev/v1/Hash",
            prev.digest.clone(),
        ));
    }

    let mut builder = Receipt::builder()
        .spec_version(spec_version)
        .swarm_id(*swarm_id)
        .actor(state.control_plane_identity.agent_id)
        .action_kind("constitution.shadow_clear")
        .constitution_version(&constitution_version_for_builder)
        .occurred_at(Timestamp::now());
    for e in evidence {
        builder = builder.evidence(e);
    }
    let mut receipt = builder
        .build()
        .map_err(|e| Status::internal(format!("constitution.shadow_clear receipt build: {e}")))?;

    let bytes = receipt
        .canonical_bytes()
        .map_err(|e| Status::internal(format!("constitution.shadow_clear canonical: {e}")))?;
    let sig = state
        .control_plane_identity
        .sign(&bytes)
        .await
        .map_err(|e| Status::internal(format!("constitution.shadow_clear signer: {e}")))?;
    receipt
        .signatures
        .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

    let outcome = state
        .receipt_store
        .append(receipt, AppendOptions::default(), state.resolver.as_ref())
        .await
        .map_err(|e| Status::internal(format!("constitution.shadow_clear append: {e}")))?;
    Ok(outcome.receipt_id)
}

/// Emit a `constitution.shadow_promote` receipt (RFC 0018 §3.2).
/// Distinct from `constitution.activate` for audit clarity — auditors
/// reviewing the constitution chain can distinguish "arrived via
/// direct activation" from "arrived via shadow-preview-then-promote"
/// (mirrors the `agent.operator_revoke` vs `agent.revoke` precedent
/// per RFC 0009).
///
/// Evidence:
///
/// - `to_active_constitution_hash` — content-address of the new
///   active (the formerly-shadowed constitution).
/// - `to_constitution_version` — version of the new active.
/// - `schema_version` — schema the new active was authored against.
/// - `from_active_constitution_hash` — content-address of the
///   previous active. Omitted when no active was loaded at the time
///   of promote (fresh-swarm case).
async fn emit_constitution_shadow_promote_receipt(
    state: &ControlPlaneState,
    from_active_hash: Option<&Hash>,
    to_active_hash: &Hash,
    to_constitution_version: &str,
    schema_version: &str,
    swarm_id: &SwarmId,
) -> Result<Hash, Status> {
    let spec_version = SpecVersion::parse("1.0.0").map_err(|e| {
        Status::internal(format!(
            "constitution.shadow_promote receipt spec_version: {e}"
        ))
    })?;

    let mut evidence: Vec<Evidence> = vec![
        Evidence::new(
            "to_active_constitution_hash",
            "type.yutha.dev/v1/Hash",
            to_active_hash.digest.clone(),
        ),
        Evidence::new(
            "to_constitution_version",
            "type.yutha.dev/v1/String",
            to_constitution_version.as_bytes().to_vec(),
        ),
        Evidence::new(
            "schema_version",
            "type.yutha.dev/v1/String",
            schema_version.as_bytes().to_vec(),
        ),
    ];
    if let Some(from) = from_active_hash {
        evidence.push(Evidence::new(
            "from_active_constitution_hash",
            "type.yutha.dev/v1/Hash",
            from.digest.clone(),
        ));
    }

    let mut builder = Receipt::builder()
        .spec_version(spec_version)
        .swarm_id(*swarm_id)
        .actor(state.control_plane_identity.agent_id)
        .action_kind("constitution.shadow_promote")
        .constitution_version(to_constitution_version)
        .occurred_at(Timestamp::now());
    for e in evidence {
        builder = builder.evidence(e);
    }
    let mut receipt = builder
        .build()
        .map_err(|e| Status::internal(format!("constitution.shadow_promote receipt build: {e}")))?;

    let bytes = receipt
        .canonical_bytes()
        .map_err(|e| Status::internal(format!("constitution.shadow_promote canonical: {e}")))?;
    let sig = state
        .control_plane_identity
        .sign(&bytes)
        .await
        .map_err(|e| Status::internal(format!("constitution.shadow_promote signer: {e}")))?;
    receipt
        .signatures
        .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

    let outcome = state
        .receipt_store
        .append(receipt, AppendOptions::default(), state.resolver.as_ref())
        .await
        .map_err(|e| Status::internal(format!("constitution.shadow_promote append: {e}")))?;
    Ok(outcome.receipt_id)
}

/// Map a `CedarPlusError` to a tonic `Status`. The mapping mirrors
/// RFC 0010 §3.6 and RFC 0012 §5.2 — load-time failures surface as
/// `FAILED_PRECONDITION`, structural / shape failures as
/// `INVALID_ARGUMENT`, internal failures as `INTERNAL`.
fn cedar_plus_to_status(e: &yutha_cedar_plus::CedarPlusError) -> Status {
    use yutha_cedar_plus::CedarPlusError;
    match e {
        CedarPlusError::Parse(msg) => {
            Status::invalid_argument(format!("constitution parse: {msg}"))
        }
        CedarPlusError::SchemaVersionUnsupported(v) => {
            Status::failed_precondition(format!("schema_version {v} not supported"))
        }
        CedarPlusError::InvalidScoringRule { rule, detail } => {
            Status::invalid_argument(format!("scoring rule {rule}: {detail}"))
        }
        CedarPlusError::InvalidProcedure { procedure, detail } => {
            Status::invalid_argument(format!("procedure {procedure}: {detail}"))
        }
        CedarPlusError::InvalidEnforcementRule { rule, detail } => {
            Status::invalid_argument(format!("enforcement rule {rule}: {detail}"))
        }
        CedarPlusError::LoadBoundExceeded(reason) => {
            Status::failed_precondition(format!("load-time bound exceeded: {reason}"))
        }
        CedarPlusError::RequestShapeInvalid(msg) => Status::invalid_argument(msg.clone()),
        CedarPlusError::EntityUnresolved(msg) => Status::invalid_argument(msg.clone()),
        CedarPlusError::ConstitutionUnresolved(msg) => Status::failed_precondition(msg.clone()),
        CedarPlusError::EvaluatorInternalError(msg) => Status::internal(msg.clone()),
        CedarPlusError::EvaluationBoundExceeded(reason) => {
            Status::resource_exhausted(format!("evaluation bound exceeded: {reason}"))
        }
        CedarPlusError::ProcedureTransitionAmbiguous { instance, .. } => Status::internal(format!(
            "procedure transition ambiguous on instance {instance}"
        )),
        CedarPlusError::Infrastructure(msg) => Status::internal(msg.clone()),
    }
}

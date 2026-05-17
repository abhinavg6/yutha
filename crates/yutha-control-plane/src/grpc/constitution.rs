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
use yutha_core::{SpecVersion, SwarmId, Timestamp};
use yutha_proto::control_plane::v1::{
    constitution_service_server::ConstitutionService, ActivateConstitutionRequest,
    ActivateConstitutionResponse, Constitution as ConstitutionProto, GetActiveConstitutionRequest,
    GetActiveConstitutionResponse,
};

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
        let _op_auth = require_operator_bearer_auth(&request, &self.state).await?;

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
        let activate_hash = self
            .state
            .cedar_plus
            .activate(constitution)
            .await
            .map_err(|e| cedar_plus_to_status(&e))?;

        // Bind the freshly-activated constitution onto the enforcement
        // engine too. The engine needs the active constitution to
        // match incoming receipts against `enforcement_rules`.
        if let Some(active) = self.state.cedar_plus.current().await {
            self.state.enforcement.activate(active).await;
        }

        // F10e: emit a `constitution.activate` receipt. The receipt
        // emission machinery isn't yet wired through ControlPlaneState
        // for the constitution layer — that lands in the F10
        // follow-on alongside the receipt-subscription channel. For
        // now, return the activate_hash as a stand-in for the
        // receipt id; the receipt itself will land once the
        // subscription path is built.
        Ok(Response::new(ActivateConstitutionResponse {
            constitution_hash: Some((&constitution_hash).into()),
            activate_receipt: Some((&activate_hash).into()),
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

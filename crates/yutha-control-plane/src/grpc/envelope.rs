//! `EnvelopeService` gRPC handler.
//!
//! Bridges the two RPCs from
//! [`/spec/control-plane/v1.proto`](../../../../spec/control-plane/v1.proto)
//! to the in-process [`Transport`](yutha_transport::Transport):
//!
//! - [`EnvelopeHandler::send`] — unary. Validates the bearer (and that
//!   the envelope's `from_agent` matches the bearer's `agent_id` to
//!   prevent spoofing), then delegates to `Transport::send`. Returns the
//!   `envelope.send` receipt's content-address.
//! - [`EnvelopeHandler::subscribe`] — server-streaming. Opens a
//!   long-lived subscription on the transport and forwards every
//!   delivered envelope + its `envelope.deliver` receipt id back to the
//!   client. Cancelling the stream cleanly ends the subscription.
//!
//! ## Auth and routing rules
//!
//! - `Send` checks that `envelope.from_agent == auth.agent_id`. Cross-
//!   agent sending is not currently permitted; the spec leaves room for
//!   future delegate-style flows, but until they're defined we reject.
//! - `Subscribe` requires the request's `agent_id` (if set) to equal the
//!   bearer's `agent_id`. An empty `agent_id` defaults to the bearer's —
//!   prevents an authenticated caller from eavesdropping on a different
//!   agent's inbox.
//!
//! ## Stream lifecycle
//!
//! The transport's `subscribe` returns a `Stream<(Envelope, Hash)>`.
//! This handler maps each item to a `SubscribedEnvelope` proto + maps
//! `TransportError` to `tonic::Status` via the existing
//! `ErrorIntoStatus` trait. When the client cancels the gRPC stream,
//! tonic drops the response stream → the forwarder task inside
//! `MemoryTransport::subscribe` notices `tx.send` errored and shuts
//! itself down.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use futures::StreamExt;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::debug;
use yutha_capability::ActionDescriptor;
use yutha_cedar_plus::{
    ConstitutionEvaluator, Decision, EntityRecord, EntitySnapshot, EntityUid, EvaluationOutcome,
    EvaluationRequest,
};
use yutha_core::{AgentId, Hash, SpecVersion, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_proto::control_plane::v1::{
    envelope_service_server::EnvelopeService, SendEnvelopeRequest, SendEnvelopeResponse,
    SubscribeRequest, SubscribedEnvelope,
};
use yutha_receipt::{AppendOptions, Evidence, Receipt, SignatureRole, SignedBy};
use yutha_transport::{Envelope, Recipient};

use crate::auth::require_active_bearer_auth;

use super::error::{missing_field, ErrorIntoStatus};
use super::ControlPlaneState;

pub struct EnvelopeHandler {
    state: Arc<ControlPlaneState>,
}

impl EnvelopeHandler {
    pub fn new(state: Arc<ControlPlaneState>) -> Self {
        Self { state }
    }
}

/// Render a [`Recipient`] as the string form used in an
/// [`ActionDescriptor`]'s `recipient` field.
///
/// The format is stable and lets caveats (e.g. `OnlyIfTaggedCaveat`
/// targeting `agent:<id>`) match deterministically across runs. Not
/// part of any wire protocol — purely the substrate's internal
/// descriptor representation.
fn recipient_descriptor_string(r: &Recipient) -> String {
    match r {
        Recipient::Agent(id) => format!("agent:{id}"),
        Recipient::Role(role) => format!("role:{role}"),
        Recipient::Swarm(b) if b.filter_tags.is_empty() => "swarm:*".to_string(),
        Recipient::Swarm(b) => format!("swarm:{}", b.filter_tags.join(",")),
        Recipient::External(e) => {
            format!("external:{}://{}{}", e.scheme, e.authority, e.path_hint)
        }
    }
}

/// Construct an [`EvaluationRequest`] for a SendEnvelope action, plus a
/// minimal [`EntitySnapshot`] containing the sender Agent + Swarm.
///
/// F10d intentionally keeps the snapshot lean — sender Agent (with the
/// Swarm as parent for Cedar's `in [Swarm]` relation) and the Swarm
/// itself. Cedar policies that only check action/principal identity
/// work out of the box; policies that reference rich Agent attributes
/// (`passport_tier`, `framework`, `reputation`, budget fields) need
/// the F11/F12 enrichment pass that walks the passport store + the
/// enforcement engine. Until that lands, such expressions will see
/// `null` for unprovided attrs and Cedar will deny on the attribute
/// lookup — which is the fail-closed default per evaluation.md §2.3.
fn build_eval_request_for_send(
    constitution_hash: Hash,
    principal_id: &AgentId,
    envelope: &Envelope,
    cap_id: Option<&Hash>,
    swarm_id: &yutha_core::SwarmId,
    constitution_version: &str,
    topology_mode: &str,
) -> EvaluationRequest {
    let principal_uid_str = principal_id.to_string();
    let swarm_uid_str = swarm_id.to_string();

    // Resource UID depends on the recipient variant. For Agent
    // recipients we hand Cedar a Yutha::Agent; for Role / Swarm /
    // External we hand Cedar a Yutha::Resource carrying the
    // recipient's kind + identifier in its `resource_kind` / `scope`
    // attrs. The schema's SendEnvelope.appliesTo accepts all three
    // (Agent / Envelope / Resource) per v1.1.x.
    //
    // `resource_snapshot` is `Some(...)` exactly when we need to add
    // a Resource entity to the entity snapshot below; for Agent
    // recipients the snapshot already contains the agent entity and
    // there's nothing extra to add.
    let (resource_uid, resource_snapshot) = match &envelope.recipient {
        Recipient::Agent(id) => (EntityUid::new("Yutha::Agent", id.to_string()), None),
        Recipient::Role(role) => {
            let uid = format!("role:{role}");
            let entity = resource_entity(&uid, "role", role, &[]);
            (EntityUid::new("Yutha::Resource", uid), Some(entity))
        }
        Recipient::Swarm(b) => {
            let scope = if b.filter_tags.is_empty() {
                "*".to_string()
            } else {
                b.filter_tags.join(",")
            };
            let uid = format!("swarm:{scope}");
            let entity = resource_entity(&uid, "swarm", &scope, &b.filter_tags);
            (EntityUid::new("Yutha::Resource", uid), Some(entity))
        }
        Recipient::External(e) => {
            let scope = format!("{}://{}{}", e.scheme, e.authority, e.path_hint);
            let uid = format!("external:{scope}");
            let entity = resource_entity(&uid, "external", &scope, &[]);
            (EntityUid::new("Yutha::Resource", uid), Some(entity))
        }
    };

    // Entity snapshot — sender Agent (parented under Swarm) + the
    // Swarm + (optionally) the recipient Agent. Every entity carries
    // the FULL attribute surface the v1.1 canonical schema declares,
    // because Cedar's Strict-mode entity validation rejects partial
    // entities even when no policy reads the missing attrs. The
    // values here are stand-ins: the control plane hasn't yet wired
    // the resolvers that would pull real passport_tier / framework /
    // reputation / budgets for the principal (those land alongside
    // the supervisor-layer + budget-substrate work). The permissive
    // permit-all policy doesn't read them; rule-authoring operators
    // who need real values will need the resolver wiring before
    // those rules evaluate correctly.
    let now = Timestamp::now();
    let mut entities = vec![
        agent_entity(&principal_uid_str, &swarm_uid_str),
        swarm_entity(&swarm_uid_str, topology_mode, constitution_version),
    ];
    // Only add the recipient when it's a *different* agent — Cedar
    // rejects duplicate entity entries, which self-sends would
    // otherwise produce (the sender entity is already in the list).
    if let Recipient::Agent(rid) = &envelope.recipient {
        if rid != principal_id {
            entities.push(agent_entity(&rid.to_string(), &swarm_uid_str));
        }
    }
    // Non-Agent recipients (Role / Swarm / External) need their
    // synthesized Yutha::Resource entity in the snapshot too — Cedar
    // resolves attribute accesses on `resource` against the snapshot,
    // so a missing entity here would surface as "resource has no
    // attr X" during eval rather than a clean policy decision.
    if let Some(entity) = resource_snapshot {
        entities.push(entity);
    }
    let entity_snapshot = EntitySnapshot { entities };

    // Action-context fields the schema's SendEnvelope expects per
    // schema.cedarschema. Zeros for the budget/cost dimensions
    // (F11+ wires real values from the SDK). The capability_id
    // field tells policies which cap the sender presented.
    let mut context_attrs: HashMap<String, serde_json::Value> = HashMap::new();
    context_attrs.insert(
        "performative".into(),
        serde_json::Value::String(format!("{:?}", envelope.performative)),
    );
    context_attrs.insert(
        "payload_schema_id".into(),
        serde_json::Value::String(envelope.payload_schema_id.clone()),
    );
    context_attrs.insert(
        "tags".into(),
        serde_json::Value::Array(
            envelope
                .tags
                .iter()
                .map(|t| serde_json::Value::String(t.clone()))
                .collect(),
        ),
    );
    context_attrs.insert(
        "capability_id".into(),
        serde_json::Value::String(cap_id.map(|h| hex::encode(&h.digest)).unwrap_or_default()),
    );
    for k in [
        "estimated_cost_usd_cents",
        "estimated_cost_tool_calls",
        "estimated_cost_compute_ms",
    ] {
        context_attrs.insert(k.into(), serde_json::Value::Number(0.into()));
    }
    context_attrs.insert(
        "current_wall_clock".into(),
        serde_json::Value::String(now.wall_clock.clone()),
    );
    context_attrs.insert(
        "current_time_unix_ns".into(),
        serde_json::Value::Number(now.monotonic_ns.into()),
    );

    EvaluationRequest {
        constitution_hash,
        schema_version: "1.1.0".into(),
        action_kind: "SendEnvelope".into(),
        principal_id: *principal_id,
        resource_uid,
        context_attrs,
        entity_snapshot,
        current_wall_clock: now.wall_clock.clone(),
        current_time_unix_ns: now.monotonic_ns,
    }
}

/// Build a `Yutha::Agent` entity record populated with all attributes
/// the canonical v1.1 schema declares. Values are scaffolding-tier
/// placeholders — minimal tier, empty framework, all-zero passport
/// hash, reputation 1.0, generous budgets. Replaced with real values
/// (wired from the passport store and supervisor layer) when those
/// resolvers land. Cedar 3.x decimal extension values use the
/// implicit string form, which the JSON entity parser accepts.
fn agent_entity(agent_uid: &str, swarm_uid: &str) -> EntityRecord {
    let mut attrs: HashMap<String, serde_json::Value> = HashMap::new();
    attrs.insert(
        "agent_id".into(),
        serde_json::Value::String(agent_uid.to_string()),
    );
    attrs.insert(
        "passport_tier".into(),
        serde_json::Value::String("minimal".into()),
    );
    attrs.insert("framework".into(), serde_json::Value::String(String::new()));
    attrs.insert(
        "passport_hash".into(),
        // 64-char hex stand-in. Real value lands once the passport
        // resolver is wired into this path.
        serde_json::Value::String("0".repeat(64)),
    );
    // Cedar 3.x: extension types use the explicit __extn shape with
    // "fn" + "arg". The implicit short-form ("1.0") also works in
    // Cedar 3.x JSON entity format, but explicit is unambiguous.
    attrs.insert(
        "reputation".into(),
        serde_json::json!({
            "__extn": { "fn": "decimal", "arg": "1.0" }
        }),
    );
    attrs.insert(
        "budget_remaining_usd_cents".into(),
        serde_json::Value::Number(i64::MAX.into()),
    );
    attrs.insert(
        "budget_remaining_tool_calls".into(),
        serde_json::Value::Number(i64::MAX.into()),
    );
    attrs.insert(
        "budget_remaining_compute_ms".into(),
        serde_json::Value::Number(i64::MAX.into()),
    );
    EntityRecord {
        uid: EntityUid::new("Yutha::Agent", agent_uid.to_string()),
        attrs,
        parents: vec![EntityUid::new("Yutha::Swarm", swarm_uid.to_string())],
    }
}

/// Build a `Yutha::Swarm` entity record with all schema-required
/// attributes populated. `topology_mode` is the lowercased string
/// form of `yutha_registry::TopologyMode` (closed / open / hybrid);
/// `constitution_version` is the version of the currently-active
/// constitution at evaluation time.
/// Build a `Yutha::Resource` entity record for non-Agent recipients
/// of SendEnvelope. The schema declares Resource with three required
/// attrs (`resource_kind`, `scope`, `tags`); we populate from the
/// Recipient variant. Policies that gate on these read them via
/// `resource.resource_kind == "role"` etc.
fn resource_entity(uid: &str, kind: &str, scope: &str, tags: &[String]) -> EntityRecord {
    let mut attrs: HashMap<String, serde_json::Value> = HashMap::new();
    attrs.insert(
        "resource_kind".into(),
        serde_json::Value::String(kind.to_string()),
    );
    attrs.insert("scope".into(), serde_json::Value::String(scope.to_string()));
    attrs.insert(
        "tags".into(),
        serde_json::Value::Array(
            tags.iter()
                .map(|t| serde_json::Value::String(t.clone()))
                .collect(),
        ),
    );
    EntityRecord {
        uid: EntityUid::new("Yutha::Resource", uid.to_string()),
        attrs,
        parents: Vec::new(),
    }
}

fn swarm_entity(swarm_uid: &str, topology_mode: &str, constitution_version: &str) -> EntityRecord {
    let mut attrs: HashMap<String, serde_json::Value> = HashMap::new();
    attrs.insert(
        "swarm_id".into(),
        serde_json::Value::String(swarm_uid.to_string()),
    );
    attrs.insert(
        "topology_mode".into(),
        serde_json::Value::String(topology_mode.to_string()),
    );
    attrs.insert(
        "constitution_version".into(),
        serde_json::Value::String(constitution_version.to_string()),
    );
    EntityRecord {
        uid: EntityUid::new("Yutha::Swarm", swarm_uid.to_string()),
        attrs,
        parents: Vec::new(),
    }
}

/// Build + sign + append a `constitution.evaluate.{pass,deny}` receipt
/// for the given eval outcome.
///
/// Evidence shape mirrors `/spec/receipt/canonical-actions.md`:
///
/// - `constitution_hash` — content-address of the active constitution.
/// - `action_kind` — the action being evaluated (e.g. `"SendEnvelope"`).
/// - `matched_rule_ids` — comma-joined list of cedar policy ids that
///   contributed to the decision.
/// - `input_attribute_digest` — sha256 over the eval request's
///   canonical bytes (already computed by the evaluator as
///   `EvaluationOutcome.evidence_digest`).
/// - `deny_reason` — only on deny.
/// - `total_score` — only on pass when scoring rules contributed.
///
/// The control plane signs the receipt with its own identity
/// (`Actor` role); on a successful append the receipt's content-
/// address is returned.
async fn emit_constitution_eval_receipt(
    state: &ControlPlaneState,
    outcome: &EvaluationOutcome,
    constitution_hash: &Hash,
    constitution_version: &str,
    swarm_id: yutha_core::SwarmId,
    subject_agent_id: &AgentId,
) -> Result<Hash, Status> {
    let action_kind = match outcome.decision {
        yutha_cedar_plus::Decision::Permit => "constitution.evaluate.pass",
        yutha_cedar_plus::Decision::Deny => "constitution.evaluate.deny",
    };

    let mut evidence: Vec<Evidence> = vec![
        Evidence::new(
            "constitution_hash",
            "type.yutha.dev/v1/Hash",
            constitution_hash.digest.clone(),
        ),
        Evidence::new(
            "action_kind",
            "type.yutha.dev/v1/String",
            "SendEnvelope".as_bytes().to_vec(),
        ),
        Evidence::new(
            "matched_rule_ids",
            "type.yutha.dev/v1/String",
            outcome.matched_rule_ids.join(",").into_bytes(),
        ),
        Evidence::new(
            "input_attribute_digest",
            "type.yutha.dev/v1/Hash",
            outcome.evidence_digest.digest.clone(),
        ),
        // The subject is the agent whose action was evaluated. The
        // receipt's `actor` is the control plane (it emits the
        // signed audit record), so the subject has to ride in
        // evidence — the enforcement engine downstream (F10f
        // PublishingReceiptStore + F9 on_receipt) matches on this
        // field to attribute denies to the right agent.
        Evidence::new(
            "subject_agent_id",
            "type.yutha.dev/v1/AgentId",
            subject_agent_id.to_string().into_bytes(),
        ),
    ];
    if let Some(reason) = &outcome.deny_reason {
        evidence.push(Evidence::new(
            "deny_reason",
            "type.yutha.dev/v1/String",
            reason.as_bytes().to_vec(),
        ));
    }
    if let Some(total) = &outcome.total_score {
        evidence.push(Evidence::new(
            "total_score",
            "type.yutha.dev/v1/String",
            total.0.as_bytes().to_vec(),
        ));
    }

    let spec_version = SpecVersion::parse("1.0.0").map_err(|e| {
        Status::internal(format!("constitution.evaluate receipt spec_version: {e}"))
    })?;
    let mut builder = Receipt::builder()
        .spec_version(spec_version)
        .swarm_id(swarm_id)
        .actor(state.control_plane_identity.agent_id)
        .action_kind(action_kind)
        .constitution_version(constitution_version)
        .occurred_at(Timestamp::now());
    for e in evidence {
        builder = builder.evidence(e);
    }
    let mut receipt = builder
        .build()
        .map_err(|e| Status::internal(format!("constitution.evaluate receipt build: {e}")))?;

    let bytes = receipt
        .canonical_bytes()
        .map_err(|e| Status::internal(format!("constitution.evaluate canonical: {e}")))?;
    let sig = state
        .control_plane_identity
        .sign(&bytes)
        .await
        .map_err(|e| Status::internal(format!("constitution.evaluate signer: {e}")))?;
    receipt
        .signatures
        .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

    let outcome = state
        .receipt_store
        .append(receipt, AppendOptions::default(), state.resolver.as_ref())
        .await
        .map_err(|e| Status::internal(format!("constitution.evaluate append: {e}")))?;
    Ok(outcome.receipt_id)
}

/// Type alias for the server-streaming Subscribe response — a boxed
/// stream of `SubscribedEnvelope` items.
pub type SubscribeStream =
    Pin<Box<dyn Stream<Item = Result<SubscribedEnvelope, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl EnvelopeService for EnvelopeHandler {
    async fn send(
        &self,
        request: Request<SendEnvelopeRequest>,
    ) -> Result<Response<SendEnvelopeResponse>, Status> {
        let auth = require_active_bearer_auth(&request, &self.state).await?;
        let req = request.into_inner();

        let envelope_proto = req
            .envelope
            .as_ref()
            .ok_or_else(|| missing_field("envelope"))?;
        let envelope = Envelope::try_from(envelope_proto).map_err(|e| e.to_status())?;
        debug!(
            target: "yutha::envelope::trace",
            from_agent = %envelope.from_agent,
            recipient = ?envelope.recipient,
            envelope_id = ?envelope.envelope_id,
            epoch = envelope.epoch,
            cap_id_present = req.capability_id.is_some(),
            "Send: envelope received"
        );

        // Anti-spoofing: the bearer claims an identity, the envelope
        // claims a sender — they MUST be the same agent. Cross-agent
        // proxying is not part of v1.0; future work might add a
        // delegate-send shape.
        if envelope.from_agent != auth.agent_id {
            return Err(Status::permission_denied(
                "envelope.from_agent must match the bearer-token agent_id",
            ));
        }

        // RFC 0007: Send-path capability enforcement.
        //
        // Behavior matrix:
        //   - require_capability_for_send = true,  cap_id absent  → INVALID_ARGUMENT
        //   - require_capability_for_send = true,  cap_id present → check; deny → PERMISSION_DENIED
        //   - require_capability_for_send = false, cap_id absent  → skip check (legacy)
        //   - require_capability_for_send = false, cap_id present → check anyway (audit
        //                                                            value); deny still rejects
        //
        // The store's `check` walks the parent chain, honors revocation
        // + validity window, intersects scopes, evaluates caveats, and
        // emits the `capability.check.{pass,deny}` receipt as a
        // substrate observation regardless of which branch is taken.
        let topology = self.state.registry.topology();
        let cap_id_opt: Option<Hash> = req
            .capability_id
            .as_ref()
            .map(Hash::try_from)
            .transpose()
            .map_err(|e| e.to_status())?;

        if topology.require_capability_for_send && cap_id_opt.is_none() {
            return Err(Status::invalid_argument(
                "topology.require_capability_for_send is true: \
                 SendEnvelopeRequest.capability_id is required",
            ));
        }

        if let Some(cap_id) = cap_id_opt.clone() {
            let descriptor = ActionDescriptor {
                action_kind: "envelope.send".to_string(),
                resource_tags: envelope.tags.clone(),
                recipient: Some(recipient_descriptor_string(&envelope.recipient)),
                ..Default::default()
            };
            let evaluation = self
                .state
                .capability_store
                .check(&cap_id, &descriptor)
                .await
                .map_err(|e| e.to_status())?;
            if !evaluation.outcome.permitted {
                return Err(Status::permission_denied(format!(
                    "capability check denied: {}",
                    evaluation.outcome.deny_reason
                )));
            }
        }

        // RFC 0010-0013: constitution evaluation (F10d).
        //
        // Layered on top of E1's cap check: the cap layer answers "does
        // this agent have authority"; the constitution layer answers
        // "do the swarm's norms permit this authority to be exercised
        // right now." Both must pass.
        //
        // A swarm MUST have an active constitution before any send
        // succeeds. The operator publishes one via
        // `ConstitutionService.Activate` as part of bringing the swarm
        // online; a Send arriving before that activation is a
        // misconfiguration and surfaces as `FAILED_PRECONDITION`.
        let active = self.state.cedar_plus.current().await.ok_or_else(|| {
            Status::failed_precondition(
                "no active constitution; operator must call ConstitutionService.Activate before \
                 envelope sends are permitted",
            )
        })?;
        let constitution_hash = active.constitution.constitution_hash.clone();
        let constitution_version = active.constitution.constitution_version.clone();
        drop(active);
        let topology_mode_str = match topology.mode {
            yutha_registry::TopologyMode::Closed => "closed",
            yutha_registry::TopologyMode::Open => "open",
            yutha_registry::TopologyMode::Hybrid => "hybrid",
        };
        let eval_request = build_eval_request_for_send(
            constitution_hash.clone(),
            &auth.agent_id,
            &envelope,
            cap_id_opt.as_ref(),
            &topology.swarm_id,
            &constitution_version,
            topology_mode_str,
        );
        let outcome = self
            .state
            .cedar_plus
            .evaluate(eval_request)
            .await
            .map_err(|e| Status::internal(format!("constitution eval: {e}")))?;

        // F10e: emit constitution.evaluate.{pass,deny} receipt with
        // the eval outcome's evidence digest + matched-rule ids +
        // (when present) score contributions. Emission happens
        // BEFORE the deny short-circuit below so the audit trail
        // records both permits and denies symmetrically — per
        // /spec/receipt/canonical-actions.md.
        emit_constitution_eval_receipt(
            &self.state,
            &outcome,
            &constitution_hash,
            &constitution_version,
            topology.swarm_id,
            &auth.agent_id,
        )
        .await?;

        if outcome.decision == Decision::Deny {
            let reason = outcome.deny_reason.as_deref().unwrap_or("unknown");
            return Err(Status::permission_denied(format!(
                "constitution check denied: {reason}"
            )));
        }

        let send_receipt = self
            .state
            .transport
            .send(envelope)
            .await
            .map_err(|e| e.to_status())?;
        debug!(
            target: "yutha::envelope::trace",
            from_agent = %auth.agent_id,
            send_receipt = %send_receipt,
            "Send: transport.send returned"
        );

        Ok(Response::new(SendEnvelopeResponse {
            send_receipt: Some((&send_receipt).into()),
        }))
    }

    type SubscribeStream = SubscribeStream;

    // clippy::result_large_err: the .map() closure below produces
    // Result<SubscribedEnvelope, Status>, where SubscribedEnvelope is
    // small but Status is ~176 bytes — that imbalance trips the lint.
    // Status is tonic's canonical error and isn't going to change shape
    // crate-side; accept the imbalance locally.
    #[allow(clippy::result_large_err)]
    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let auth = require_active_bearer_auth(&request, &self.state).await?;
        let req = request.into_inner();

        // Resolve the target agent: explicit value (must equal the
        // bearer's agent) or default to the bearer's. Forbids
        // cross-agent eavesdropping.
        let target = match req.agent_id.as_ref() {
            Some(id_proto) => {
                let claimed = AgentId::try_from(id_proto).map_err(|e| e.to_status())?;
                if claimed != auth.agent_id {
                    return Err(Status::permission_denied(
                        "Subscribe.agent_id must match the bearer-token agent_id",
                    ));
                }
                claimed
            }
            None => auth.agent_id,
        };

        debug!(
            target: "yutha::envelope::trace",
            target_agent = %target,
            "Subscribe: handler entered"
        );

        // Open the transport-level stream. MemoryTransport's impl
        // idempotently registers the inbox if needed, so the first
        // subscription from a fresh agent works without prior setup.
        let envelope_stream = self
            .state
            .transport
            .subscribe(target)
            .await
            .map_err(|e| e.to_status())?;

        // Map each `(Envelope, Hash)` pair to the wire `SubscribedEnvelope`,
        // and any TransportError to `tonic::Status`. The cancellation
        // path is handled by the underlying transport: when this stream
        // is dropped, its tx half closes and the forwarder task inside
        // MemoryTransport::subscribe terminates.
        let mapped = envelope_stream.map(|item| match item {
            Ok((envelope, deliver_receipt)) => Ok(SubscribedEnvelope {
                envelope: Some((&envelope).into()),
                deliver_receipt: Some((&deliver_receipt).into()),
            }),
            Err(e) => Err(e.to_status()),
        });

        // RFC 0009 §3.3 active-stream tear-down: race the envelope
        // stream against the target's revocation Notify. When a
        // revoke (self or operator) lands, the Notify fires; this
        // forwarder emits one terminating UNAUTHENTICATED frame and
        // ends the stream within tens-of-milliseconds rather than
        // making the client wait for token expiry.
        //
        // Uses the same `tokio::spawn` + `mpsc` + `ReceiverStream`
        // pattern `MemoryTransport`'s subscribe forwarder uses so we
        // don't pull in an async-stream dep just for this combinator.
        let revocation_signal = self.state.revocation_signal_for(target).await;
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<SubscribedEnvelope, Status>>(8);
        let target_for_log = target;
        tokio::spawn(async move {
            tokio::pin!(mapped);
            let mut items_forwarded: u64 = 0;
            loop {
                tokio::select! {
                    biased;
                    // Client dropped the stream → exit immediately so we
                    // don't sit parked on `mapped.next()` and consume an
                    // envelope into a closed downstream. Same pattern as
                    // the zombie-forwarder fix in
                    // `MemoryTransport::subscribe` (4b): without this,
                    // back-to-back subscribe-then-drop test runs leave
                    // wrappers that eat the next subscriber's envelopes.
                    _ = tx.closed() => {
                        debug!(
                            target: "yutha::envelope::trace",
                            target_agent = %target_for_log,
                            items_forwarded,
                            "Subscribe: outer forwarder exit via tx.closed"
                        );
                        break;
                    }
                    _ = revocation_signal.notified() => {
                        debug!(
                            target: "yutha::envelope::trace",
                            target_agent = %target_for_log,
                            items_forwarded,
                            "Subscribe: outer forwarder exit via revocation"
                        );
                        let _ = tx
                            .send(Err(Status::unauthenticated("agent revoked")))
                            .await;
                        break;
                    }
                    next = mapped.next() => match next {
                        Some(item) => {
                            let item_ok = item.is_ok();
                            if tx.send(item).await.is_err() {
                                // Same root cause; same exit. This branch
                                // handles the race where the receiver
                                // drops between the `tx.closed()` poll
                                // and the next `tx.send`.
                                debug!(
                                    target: "yutha::envelope::trace",
                                    target_agent = %target_for_log,
                                    items_forwarded,
                                    "Subscribe: outer forwarder exit via tx.send error (consumed item dropped)"
                                );
                                break;
                            }
                            if item_ok {
                                items_forwarded += 1;
                            }
                        }
                        None => {
                            debug!(
                                target: "yutha::envelope::trace",
                                target_agent = %target_for_log,
                                items_forwarded,
                                "Subscribe: outer forwarder exit via inner stream end"
                            );
                            break;
                        }
                    }
                }
            }
        });

        Ok(Response::new(
            Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx))
                as Pin<Box<dyn Stream<Item = _> + Send + 'static>>,
        ))
    }
}

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
use yutha_capability::ActionDescriptor;
use yutha_cedar_plus::{
    ConstitutionEvaluator, Decision, EntityRecord, EntitySnapshot, EntityUid, EvaluationRequest,
};
use yutha_core::{AgentId, Hash, Timestamp};
use yutha_proto::control_plane::v1::{
    envelope_service_server::EnvelopeService, SendEnvelopeRequest, SendEnvelopeResponse,
    SubscribeRequest, SubscribedEnvelope,
};
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
) -> EvaluationRequest {
    let principal_uid_str = principal_id.to_string();
    let swarm_uid_str = swarm_id.to_string();

    // Resource UID depends on the recipient variant. For Agent
    // recipients we hand Cedar a Yutha::Agent; for Role / Swarm /
    // External we use a generic Resource identifier so the policy
    // can still gate by `recipient_kind` from context.
    let resource_uid = match &envelope.recipient {
        Recipient::Agent(id) => EntityUid::new("Yutha::Agent", id.to_string()),
        Recipient::Role(role) => EntityUid::new("Yutha::Resource", format!("role:{role}")),
        Recipient::Swarm(_) => EntityUid::new("Yutha::Resource", "swarm:*".to_string()),
        Recipient::External(e) => EntityUid::new(
            "Yutha::Resource",
            format!("external:{}://{}{}", e.scheme, e.authority, e.path_hint),
        ),
    };

    // Minimal entity snapshot — sender Agent (parented under Swarm)
    // + the Swarm itself. Policies that reach for richer attrs will
    // see missing keys and default-deny per RFC 0012 §2.3.
    let now = Timestamp::now();
    let mut entities = vec![
        EntityRecord {
            uid: EntityUid::new("Yutha::Agent", principal_uid_str.clone()),
            attrs: HashMap::new(),
            parents: vec![EntityUid::new("Yutha::Swarm", swarm_uid_str.clone())],
        },
        EntityRecord {
            uid: EntityUid::new("Yutha::Swarm", swarm_uid_str.clone()),
            attrs: HashMap::new(),
            parents: Vec::new(),
        },
    ];
    if let Recipient::Agent(rid) = &envelope.recipient {
        entities.push(EntityRecord {
            uid: EntityUid::new("Yutha::Agent", rid.to_string()),
            attrs: HashMap::new(),
            parents: vec![EntityUid::new("Yutha::Swarm", swarm_uid_str.clone())],
        });
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
        drop(active);
        let eval_request = build_eval_request_for_send(
            constitution_hash,
            &auth.agent_id,
            &envelope,
            cap_id_opt.as_ref(),
            &topology.swarm_id,
        );
        let outcome = self
            .state
            .cedar_plus
            .evaluate(eval_request)
            .await
            .map_err(|e| Status::internal(format!("constitution eval: {e}")))?;
        if outcome.decision == Decision::Deny {
            let reason = outcome.deny_reason.as_deref().unwrap_or("unknown");
            return Err(Status::permission_denied(format!(
                "constitution check denied: {reason}"
            )));
        }
        // F10e (receipt emission for constitution.evaluate.{pass,deny})
        // is the follow-on — landing it requires the receipt-store
        // emission helper plus a sign-with-control-plane-identity
        // pass that's still under construction.
        let _ = outcome;

        let send_receipt = self
            .state
            .transport
            .send(envelope)
            .await
            .map_err(|e| e.to_status())?;

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
        tokio::spawn(async move {
            tokio::pin!(mapped);
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
                    _ = tx.closed() => break,
                    _ = revocation_signal.notified() => {
                        let _ = tx
                            .send(Err(Status::unauthenticated("agent revoked")))
                            .await;
                        break;
                    }
                    next = mapped.next() => match next {
                        Some(item) => {
                            if tx.send(item).await.is_err() {
                                // Same root cause; same exit. This branch
                                // handles the race where the receiver
                                // drops between the `tx.closed()` poll
                                // and the next `tx.send`.
                                break;
                            }
                        }
                        None => break,
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

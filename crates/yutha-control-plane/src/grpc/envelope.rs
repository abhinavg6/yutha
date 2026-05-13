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

use std::pin::Pin;
use std::sync::Arc;

use futures::StreamExt;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use yutha_core::AgentId;
use yutha_proto::control_plane::v1::{
    envelope_service_server::EnvelopeService, SendEnvelopeRequest, SendEnvelopeResponse,
    SubscribeRequest, SubscribedEnvelope,
};
use yutha_transport::Envelope;

use crate::auth::require_bearer_auth;

use super::error::{missing_field, ErrorIntoStatus};
use super::ControlPlaneState;

pub struct EnvelopeHandler {
    state: Arc<ControlPlaneState>,
}

impl EnvelopeHandler {
    pub fn new(state: Arc<ControlPlaneState>) -> Self {
        Self { state }
    }

    fn swarm_id(&self) -> yutha_core::SwarmId {
        self.state.registry.topology().swarm_id
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
        let auth = require_bearer_auth(&request, &self.state.resolver, self.swarm_id()).await?;
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
        let auth = require_bearer_auth(&request, &self.state.resolver, self.swarm_id()).await?;
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

        Ok(Response::new(
            Box::pin(mapped) as Pin<Box<dyn Stream<Item = _> + Send + 'static>>
        ))
    }
}

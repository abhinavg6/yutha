//! `ReplayService` gRPC handler (Phase 3c, RFC 0018 §4).
//!
//! Five RPCs: `CreateSession`, `RunSession` (server-streaming),
//! `QueryReplayReceipts`, `CloseSession`, `ListSessions`. All
//! operator-bearer-authenticated.
//!
//! Session lifecycle audit receipts (`replay.session.create`,
//! `replay.session.close`) land in the PRODUCTION receipt store so
//! the audit trail captures who created/closed what session.
//! Within-session evaluation receipts (`enforcement.*` emitted by
//! the candidate's engine during replay) land in the session's
//! isolated store per `ReplayStore::session_store`.
//!
//! Per the project memory `phase-3c-replay-operational-concerns`:
//! the substrate provides semantic isolation by construction
//! (replay receipts never enter the production engine fan-out and
//! never anchor to Sui), but operators should be aware that
//! long-running sessions share CPU + Postgres I/O with the
//! envelope-serving path on this control plane. Run heavy replay
//! workloads via a sibling control-plane process pointed at the
//! same Postgres when latency-sensitive.

use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, Stream};
use tonic::{Request, Response, Status};
use yutha_core::{Hash, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_proto::control_plane::v1::{
    replay_service_server::ReplayService, CloseReplaySessionRequest, CloseReplaySessionResponse,
    CreateReplaySessionRequest, CreateReplaySessionResponse, ListReplaySessionsRequest,
    ListReplaySessionsResponse, QueryReplayReceiptsRequest, QueryReplayReceiptsResponse,
    ReplayMode as ProtoReplayMode, ReplayProgress, ReplaySessionDescriptor,
    RunReplaySessionRequest,
};
use yutha_receipt::{
    AppendOptions, Evidence, Receipt, ReplayMode, ReplaySessionId, ReplaySessionMetadata,
    ReplaySessionWindow, SignatureRole, SignedBy,
};
use yutha_replay::ReplaySession;

use crate::auth::require_operator_bearer_auth;

use super::error::missing_field;
use super::ControlPlaneState;

/// Concrete `ReplayService` implementation. Holds an
/// `Arc<ControlPlaneState>` for shared backends + session map.
pub struct ReplayHandler {
    state: Arc<ControlPlaneState>,
}

impl ReplayHandler {
    pub fn new(state: Arc<ControlPlaneState>) -> Self {
        Self { state }
    }
}

/// Type alias for the server-streaming `RunSession` response — a
/// boxed stream of `ReplayProgress` items.
pub type RunSessionStream =
    Pin<Box<dyn Stream<Item = Result<ReplayProgress, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl ReplayService for ReplayHandler {
    async fn create_session(
        &self,
        request: Request<CreateReplaySessionRequest>,
    ) -> Result<Response<CreateReplaySessionResponse>, Status> {
        let op_auth = require_operator_bearer_auth(&request, &self.state).await?;
        let req = request.into_inner();

        let candidate_proto = req
            .candidate
            .as_ref()
            .ok_or_else(|| missing_field("candidate"))?;
        let window_proto = req.window.as_ref().ok_or_else(|| missing_field("window"))?;

        // Convert the candidate via the constitution handler's
        // proto-conversion helper so the loader's validation surface
        // is identical to `ConstitutionService.Activate`.
        let candidate = super::constitution::constitution_from_proto_pub(candidate_proto)?;
        let candidate_constitution_hash = candidate.constitution_hash.clone();
        let candidate_constitution_version = candidate.constitution_version.clone();

        let window = ReplaySessionWindow {
            from_unix_ns: window_proto.from_unix_ns,
            to_unix_ns: window_proto.to_unix_ns,
            action_kind_filter: window_proto.action_kind_filter.clone(),
        };

        let mode = match ProtoReplayMode::try_from(req.mode).unwrap_or(ProtoReplayMode::Cold) {
            ProtoReplayMode::Cold => ReplayMode::Cold,
            ProtoReplayMode::Warm => ReplayMode::Warm,
        };
        // Default 24h warm lookback per RFC 0018 §4.2; ignored on Cold.
        let warm_lookback_hours = if req.warm_lookback_hours == 0 {
            24
        } else {
            req.warm_lookback_hours
        };

        let session_id = ReplaySessionId::new();
        let now = Timestamp::now();
        let metadata = ReplaySessionMetadata {
            session_id,
            candidate_constitution_hash: candidate_constitution_hash.clone(),
            candidate_constitution_version: candidate_constitution_version.clone(),
            window: window.clone(),
            mode,
            warm_lookback_hours,
            created_at: now.clone(),
            last_active_at: now.clone(),
            receipts_replayed: 0,
        };

        // Reserve the slot in the replay store.
        self.state
            .replay_store
            .create_session(metadata)
            .await
            .map_err(|e| Status::internal(format!("replay_store.create_session: {e}")))?;
        let session_store = self.state.replay_store.session_store(&session_id);

        // Build the per-session ReplaySession. For warm mode, use
        // the production receipt store as the lookback source.
        let session = match mode {
            ReplayMode::Cold => ReplaySession::create_cold(
                session_id,
                op_auth.swarm_id,
                candidate,
                self.state.cedar_plus.as_ref(),
                session_store,
                Arc::clone(&self.state.resolver),
                Arc::clone(&self.state.control_plane_identity),
            )
            .await
            .map_err(|e| Status::internal(format!("ReplaySession::create_cold: {e}")))?,
            ReplayMode::Warm => ReplaySession::create_warm(
                session_id,
                op_auth.swarm_id,
                candidate,
                self.state.cedar_plus.as_ref(),
                session_store,
                Arc::clone(&self.state.resolver),
                Arc::clone(&self.state.control_plane_identity),
                self.state.receipt_store.as_ref(),
                window.from_unix_ns,
                warm_lookback_hours,
            )
            .await
            .map_err(|e| Status::internal(format!("ReplaySession::create_warm: {e}")))?,
        };

        // Stash in the session map.
        let session_arc = Arc::new(session);
        self.state
            .replay_sessions
            .write()
            .await
            .insert(session_id, Arc::clone(&session_arc));

        // Audit-trail receipt in the production store.
        let create_receipt = emit_replay_session_create_receipt(
            &self.state,
            &session_id,
            &candidate_constitution_hash,
            &candidate_constitution_version,
            &window,
            mode,
            warm_lookback_hours,
            &op_auth.swarm_id,
        )
        .await?;

        Ok(Response::new(CreateReplaySessionResponse {
            replay_session_id: session_id.to_string(),
            session_create_receipt: Some((&create_receipt).into()),
        }))
    }

    type RunSessionStream = RunSessionStream;

    async fn run_session(
        &self,
        request: Request<RunReplaySessionRequest>,
    ) -> Result<Response<Self::RunSessionStream>, Status> {
        let _op_auth = require_operator_bearer_auth(&request, &self.state).await?;
        let req = request.into_inner();

        let session_id: ReplaySessionId = req
            .replay_session_id
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid replay_session_id: {e}")))?;

        let session = {
            let sessions = self.state.replay_sessions.read().await;
            sessions.get(&session_id).cloned().ok_or_else(|| {
                Status::not_found(format!("replay session {session_id} not found"))
            })?
        };

        // Fetch the window from the session's metadata.
        let metadata = self
            .state
            .replay_store
            .get_session(&session_id)
            .await
            .map_err(|e| Status::internal(format!("replay_store.get_session: {e}")))?
            .ok_or_else(|| Status::not_found(format!("replay session {session_id} not found")))?;

        let (tx, rx) = mpsc::channel::<Result<ReplayProgress, Status>>(64);
        let state = Arc::clone(&self.state);

        // Spawn the replay loop. The handler returns the receiver
        // stream immediately; the operator sees progress messages as
        // the loop advances. Cancellation (client closes the gRPC
        // stream) drops the sender, which the loop detects via
        // `tx.send` returning Err — it bails on the next step.
        tokio::spawn(async move {
            run_window_streaming(state, session, session_id, metadata.window, tx).await;
        });

        Ok(Response::new(
            Box::pin(ReceiverStream::new(rx)) as Self::RunSessionStream
        ))
    }

    async fn query_replay_receipts(
        &self,
        request: Request<QueryReplayReceiptsRequest>,
    ) -> Result<Response<QueryReplayReceiptsResponse>, Status> {
        let _op_auth = require_operator_bearer_auth(&request, &self.state).await?;
        let req = request.into_inner();

        let session_id: ReplaySessionId = req
            .replay_session_id
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid replay_session_id: {e}")))?;

        let query_proto = req.query.ok_or_else(|| missing_field("query"))?;
        let query = yutha_receipt::Query::try_from(&query_proto)
            .map_err(|e| Status::invalid_argument(format!("invalid query: {e}")))?;

        let session_store = self.state.replay_store.session_store(&session_id);
        let page = session_store
            .query(query, None)
            .await
            .map_err(|e| Status::internal(format!("session_store.query: {e}")))?;

        Ok(Response::new(QueryReplayReceiptsResponse {
            receipts: page.receipts.iter().map(|r| r.into()).collect(),
            next_page_token: page.next_page_token.unwrap_or_default(),
        }))
    }

    async fn close_session(
        &self,
        request: Request<CloseReplaySessionRequest>,
    ) -> Result<Response<CloseReplaySessionResponse>, Status> {
        let op_auth = require_operator_bearer_auth(&request, &self.state).await?;
        let req = request.into_inner();

        let session_id: ReplaySessionId = req
            .replay_session_id
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid replay_session_id: {e}")))?;

        // Read the cumulative replay-count BEFORE delete so the
        // close receipt's evidence carries it. The metadata in the
        // replay store is the source of truth.
        let metadata = self
            .state
            .replay_store
            .get_session(&session_id)
            .await
            .map_err(|e| Status::internal(format!("replay_store.get_session: {e}")))?
            .ok_or_else(|| Status::not_found(format!("replay session {session_id} not found")))?;
        let receipts_replayed_total = metadata.receipts_replayed;

        // Drop from the in-memory map, then delete from the replay
        // store. Order matters: drop the in-memory ReplaySession
        // first so the per-session engine is released before the
        // store deletes its receipts.
        self.state.replay_sessions.write().await.remove(&session_id);
        self.state
            .replay_store
            .delete_session(&session_id)
            .await
            .map_err(|e| Status::internal(format!("replay_store.delete_session: {e}")))?;

        let close_receipt = emit_replay_session_close_receipt(
            &self.state,
            &session_id,
            receipts_replayed_total,
            "explicit",
            &op_auth.swarm_id,
        )
        .await?;

        Ok(Response::new(CloseReplaySessionResponse {
            session_close_receipt: Some((&close_receipt).into()),
            receipts_replayed_total,
        }))
    }

    async fn list_sessions(
        &self,
        request: Request<ListReplaySessionsRequest>,
    ) -> Result<Response<ListReplaySessionsResponse>, Status> {
        let _op_auth = require_operator_bearer_auth(&request, &self.state).await?;

        let metadata = self
            .state
            .replay_store
            .list_sessions()
            .await
            .map_err(|e| Status::internal(format!("replay_store.list_sessions: {e}")))?;

        let sessions: Vec<ReplaySessionDescriptor> = metadata
            .into_iter()
            .map(|m| ReplaySessionDescriptor {
                replay_session_id: m.session_id.to_string(),
                candidate_constitution_hash: Some((&m.candidate_constitution_hash).into()),
                candidate_constitution_version: m.candidate_constitution_version,
                window: Some(yutha_proto::control_plane::v1::ReplaySessionWindow {
                    from_unix_ns: m.window.from_unix_ns,
                    to_unix_ns: m.window.to_unix_ns,
                    action_kind_filter: m.window.action_kind_filter,
                }),
                mode: match m.mode {
                    ReplayMode::Cold => ProtoReplayMode::Cold as i32,
                    ReplayMode::Warm => ProtoReplayMode::Warm as i32,
                },
                created_at: Some((&m.created_at).into()),
                last_active_at: Some((&m.last_active_at).into()),
                receipts_replayed: m.receipts_replayed,
            })
            .collect();

        Ok(Response::new(ListReplaySessionsResponse { sessions }))
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Drive the session through its window, sending `ReplayProgress`
/// messages over `tx` as it advances. Mirrors
/// `yutha_replay::ReplaySession::run_window` but emits per-receipt
/// progress instead of returning the totals at the end.
///
/// Cancellation: when the receiver is dropped (client closes the
/// stream), `tx.send` returns Err and the loop bails out.
async fn run_window_streaming(
    state: Arc<ControlPlaneState>,
    session: Arc<ReplaySession>,
    session_id: ReplaySessionId,
    window: ReplaySessionWindow,
    tx: mpsc::Sender<Result<ReplayProgress, Status>>,
) {
    use yutha_receipt::{Query, TimeRangeQuery};

    let from_ts = match Timestamp::new("1970-01-01T00:00:00Z".to_string(), window.from_unix_ns) {
        Ok(t) => t,
        Err(e) => {
            let _ = tx
                .send(Err(Status::internal(format!("from-timestamp: {e}"))))
                .await;
            return;
        }
    };
    let to_ts = match Timestamp::new("9999-12-31T23:59:59Z".to_string(), window.to_unix_ns) {
        Ok(t) => t,
        Err(e) => {
            let _ = tx
                .send(Err(Status::internal(format!("to-timestamp: {e}"))))
                .await;
            return;
        }
    };

    let page = match state
        .receipt_store
        .query(
            Query::ByTimeRange(TimeRangeQuery {
                from: from_ts,
                to: to_ts,
            }),
            None,
        )
        .await
    {
        Ok(p) => p,
        Err(e) => {
            let _ = tx
                .send(Err(Status::internal(format!("source query: {e}"))))
                .await;
            return;
        }
    };

    let mut receipts = page.receipts;
    receipts.sort_by_key(|r| r.occurred_at.monotonic_ns);
    if !window.action_kind_filter.is_empty() {
        receipts.retain(|r| window.action_kind_filter.contains(&r.action_kind));
    }

    let mut cumulative_replayed: u64 = 0;
    for r in &receipts {
        let outcome = match session.play_receipt(r).await {
            Ok(o) => o,
            Err(e) => {
                let _ = tx
                    .send(Err(Status::internal(format!("play_receipt: {e}"))))
                    .await;
                return;
            }
        };
        cumulative_replayed = cumulative_replayed.saturating_add(1);

        // Touch the session metadata so list/get reflect progress.
        let now = Timestamp::now();
        let _ = state.replay_store.touch_session(&session_id, 1, &now).await;

        let progress = ReplayProgress {
            replay_session_id: session_id.to_string(),
            progress_unix_ns: r.occurred_at.monotonic_ns,
            receipts_replayed: cumulative_replayed,
            latest_replay_receipt_id: outcome.emitted_receipt_ids.last().map(|h| h.into()),
            window_complete: false,
        };
        if tx.send(Ok(progress)).await.is_err() {
            // Client cancelled. Bail.
            return;
        }
    }

    // Terminal message — window_complete=true.
    let now = Timestamp::now();
    let _ = state.replay_store.touch_session(&session_id, 0, &now).await;
    let _ = tx
        .send(Ok(ReplayProgress {
            replay_session_id: session_id.to_string(),
            progress_unix_ns: window.to_unix_ns,
            receipts_replayed: cumulative_replayed,
            latest_replay_receipt_id: None,
            window_complete: true,
        }))
        .await;
}

/// Emit a `replay.session.create` receipt into the PRODUCTION store
/// (RFC 0018 §4.6 — session lifecycle is audit-trail-anchored to
/// production, even though within-session receipts live in the
/// isolated store).
#[allow(clippy::too_many_arguments)]
async fn emit_replay_session_create_receipt(
    state: &ControlPlaneState,
    session_id: &ReplaySessionId,
    candidate_hash: &Hash,
    candidate_version: &str,
    window: &ReplaySessionWindow,
    mode: ReplayMode,
    warm_lookback_hours: u32,
    swarm_id: &SwarmId,
) -> Result<Hash, Status> {
    let spec_version = SpecVersion::parse("1.0.0").map_err(|e| {
        Status::internal(format!("replay.session.create receipt spec_version: {e}"))
    })?;

    let mode_str = match mode {
        ReplayMode::Cold => "cold",
        ReplayMode::Warm => "warm",
    };

    let mut evidence: Vec<Evidence> = vec![
        Evidence::new(
            "replay_session_id",
            "type.yutha.dev/v1/String",
            session_id.to_string().into_bytes(),
        ),
        Evidence::new(
            "candidate_constitution_hash",
            "type.yutha.dev/v1/Hash",
            candidate_hash.digest.clone(),
        ),
        Evidence::new(
            "candidate_constitution_version",
            "type.yutha.dev/v1/String",
            candidate_version.as_bytes().to_vec(),
        ),
        Evidence::new(
            "receipt_window_from_unix_ns",
            "type.yutha.dev/v1/String",
            window.from_unix_ns.to_string().into_bytes(),
        ),
        Evidence::new(
            "receipt_window_to_unix_ns",
            "type.yutha.dev/v1/String",
            window.to_unix_ns.to_string().into_bytes(),
        ),
        Evidence::new(
            "action_kind_filter",
            "type.yutha.dev/v1/String",
            window.action_kind_filter.join(",").into_bytes(),
        ),
        Evidence::new(
            "replay_mode",
            "type.yutha.dev/v1/String",
            mode_str.as_bytes().to_vec(),
        ),
    ];
    if matches!(mode, ReplayMode::Warm) {
        evidence.push(Evidence::new(
            "warm_lookback_hours",
            "type.yutha.dev/v1/String",
            warm_lookback_hours.to_string().into_bytes(),
        ));
    }

    let mut builder = Receipt::builder()
        .spec_version(spec_version)
        .swarm_id(*swarm_id)
        .actor(state.control_plane_identity.agent_id)
        .action_kind("replay.session.create")
        .constitution_version(candidate_version)
        .occurred_at(Timestamp::now());
    for e in evidence {
        builder = builder.evidence(e);
    }
    let mut receipt = builder
        .build()
        .map_err(|e| Status::internal(format!("replay.session.create build: {e}")))?;
    let bytes = receipt
        .canonical_bytes()
        .map_err(|e| Status::internal(format!("replay.session.create canonical: {e}")))?;
    let sig = state
        .control_plane_identity
        .sign(&bytes)
        .await
        .map_err(|e| Status::internal(format!("replay.session.create signer: {e}")))?;
    receipt
        .signatures
        .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

    let outcome = state
        .receipt_store
        .append(receipt, AppendOptions::default(), state.resolver.as_ref())
        .await
        .map_err(|e| Status::internal(format!("replay.session.create append: {e}")))?;
    Ok(outcome.receipt_id)
}

/// Emit a `replay.session.close` receipt into the production store.
async fn emit_replay_session_close_receipt(
    state: &ControlPlaneState,
    session_id: &ReplaySessionId,
    receipts_replayed_total: u64,
    close_reason: &str,
    swarm_id: &SwarmId,
) -> Result<Hash, Status> {
    let spec_version = SpecVersion::parse("1.0.0")
        .map_err(|e| Status::internal(format!("replay.session.close receipt spec_version: {e}")))?;

    let evidence: Vec<Evidence> = vec![
        Evidence::new(
            "replay_session_id",
            "type.yutha.dev/v1/String",
            session_id.to_string().into_bytes(),
        ),
        Evidence::new(
            "receipts_replayed_total",
            "type.yutha.dev/v1/String",
            receipts_replayed_total.to_string().into_bytes(),
        ),
        Evidence::new(
            "close_reason",
            "type.yutha.dev/v1/String",
            close_reason.as_bytes().to_vec(),
        ),
    ];

    let mut builder = Receipt::builder()
        .spec_version(spec_version)
        .swarm_id(*swarm_id)
        .actor(state.control_plane_identity.agent_id)
        .action_kind("replay.session.close")
        // No constitution version is intrinsic to the close event
        // itself — the create receipt carries the candidate version.
        // Use a sentinel.
        .constitution_version("0.0.0")
        .occurred_at(Timestamp::now());
    for e in evidence {
        builder = builder.evidence(e);
    }
    let mut receipt = builder
        .build()
        .map_err(|e| Status::internal(format!("replay.session.close build: {e}")))?;
    let bytes = receipt
        .canonical_bytes()
        .map_err(|e| Status::internal(format!("replay.session.close canonical: {e}")))?;
    let sig = state
        .control_plane_identity
        .sign(&bytes)
        .await
        .map_err(|e| Status::internal(format!("replay.session.close signer: {e}")))?;
    receipt
        .signatures
        .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

    let outcome = state
        .receipt_store
        .append(receipt, AppendOptions::default(), state.resolver.as_ref())
        .await
        .map_err(|e| Status::internal(format!("replay.session.close append: {e}")))?;
    Ok(outcome.receipt_id)
}

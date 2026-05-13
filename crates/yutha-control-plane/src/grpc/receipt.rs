//! `ReceiptService` gRPC handler.
//!
//! Bridges the gRPC surface from
//! [`/spec/control-plane/v1.proto`](../../../../spec/control-plane/v1.proto)
//! to the in-process [`ReceiptStore`](yutha_receipt::ReceiptStore).
//!
//! Two RPCs:
//!
//! - `Get(receipt_id)` — single-receipt lookup by content-address. Returns
//!   `NOT_FOUND` if absent, `INVALID_ARGUMENT` if the hash bytes don't decode.
//! - `Query(QueryRequest)` — structured query with keyset pagination via an
//!   opaque page token. Decodes the `oneof by` selector into the ergonomic
//!   [`Query`](yutha_receipt::Query) enum and delegates.
//!
//! ## Conversion strategy
//!
//! Requests are proto; we hand-decode the small set of fields we need with
//! `TryFrom<&proto::X>` impls from `yutha-core` / `yutha-receipt`. Responses
//! convert via the existing `From<&Ergonomic> for proto::Proto` impls. This
//! keeps the handler thin — it's request decode + delegate + response encode.

use std::sync::Arc;

use tonic::{Request, Response, Status};
use yutha_core::Hash;
use yutha_proto::control_plane::v1::{
    receipt_service_server::ReceiptService, GetReceiptRequest, GetReceiptResponse,
    QueryReceiptsRequest, QueryReceiptsResponse,
};
use yutha_receipt::Query;

use super::error::{missing_field, ErrorIntoStatus};
use super::ControlPlaneState;

pub struct ReceiptHandler {
    state: Arc<ControlPlaneState>,
}

impl ReceiptHandler {
    pub fn new(state: Arc<ControlPlaneState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl ReceiptService for ReceiptHandler {
    async fn get(
        &self,
        request: Request<GetReceiptRequest>,
    ) -> Result<Response<GetReceiptResponse>, Status> {
        let req = request.into_inner();
        // proto3 nested-message fields are Option<T>; the ergonomic types
        // treat them as required and the handler is the right layer to
        // enforce that.
        let id_proto = req
            .receipt_id
            .as_ref()
            .ok_or_else(|| missing_field("receipt_id"))?;
        let id = Hash::try_from(id_proto)
            // CoreError → InvalidArgument: the caller gave us bytes we
            // can't decode into a Hash (wrong length, unknown algorithm).
            .map_err(|e| e.to_status())?;

        let receipt = self
            .state
            .receipt_store
            .get(&id)
            .await
            .map_err(|e| e.to_status())?
            .ok_or_else(|| Status::not_found(format!("receipt not found: {id}")))?;

        Ok(Response::new(GetReceiptResponse {
            receipt: Some((&receipt).into()),
        }))
    }

    async fn query(
        &self,
        request: Request<QueryReceiptsRequest>,
    ) -> Result<Response<QueryReceiptsResponse>, Status> {
        let req = request.into_inner();
        let query_proto = req.query.as_ref().ok_or_else(|| missing_field("query"))?;

        // Decode the oneof selector into the ergonomic Query enum. The
        // proto QueryRequest also carries `limit` and `page_token`; the
        // ReceiptStore trait threads page_token separately and treats
        // limit as a backend hint (in-memory ignores; postgres honors).
        let query = Query::try_from(query_proto).map_err(|e| e.to_status())?;
        let page_token = if query_proto.page_token.is_empty() {
            None
        } else {
            Some(query_proto.page_token.clone())
        };

        let page = self
            .state
            .receipt_store
            .query(query, page_token)
            .await
            .map_err(|e| e.to_status())?;

        Ok(Response::new(QueryReceiptsResponse {
            receipts: page.receipts.iter().map(Into::into).collect(),
            // Empty Vec on the wire encodes the same as absent — SDKs
            // interpret a zero-length token as "end of stream".
            next_page_token: page.next_page_token.unwrap_or_default(),
        }))
    }
}

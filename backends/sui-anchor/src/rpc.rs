//! Production [`SuiAnchorClient`] using the modular Sui Rust SDK
//! (`sui-sdk-types` + `sui-crypto` + `sui-rpc` + `sui-transaction-builder`,
//! v0.3.x — pinned by path to the local checkout while bech32 lands
//! upstream).
//!
//! ## How it works
//!
//! 1. **Connect.** [`RpcAnchorClient::connect`] resolves the RPC URL
//!    into a `sui_rpc::Client` (lazy connection; the underlying
//!    `tonic::transport::Channel` is `Clone`-cheap). The sealer
//!    private key + the operator-deployed package id + the per-swarm
//!    `SwarmAnchor` shared-object id are bound at construction time.
//!
//! 2. **Read anchor state.** A `GetObjectRequest` against the
//!    `SwarmAnchor` shared-object id, with the BCS contents in the
//!    read mask. We decode the BCS into [`crate::client::AnchorState`]
//!    via a minimal local shape.
//!
//! 3. **Submit commit_batch.** Build a PTB:
//!    - Add `SwarmAnchor` as a mutable shared input
//!      ([`sui_transaction_builder::ObjectInput::as_shared`]).
//!    - Add `0x6` (the system clock) as a read-only shared input.
//!    - Add `batch_root`, `count`, `ns_range_start`, `ns_range_end`,
//!      `histogram`, `sealer_signature` as BCS pure inputs
//!      ([`sui_transaction_builder::TransactionBuilder::pure`]).
//!    - One [`sui_transaction_builder::TransactionBuilder::move_call`]
//!      to `<package>::receipt_anchor::commit_batch` with those 8 args.
//!    - [`sui_transaction_builder::TransactionBuilder::build`] (async)
//!      to resolve gas + finalize the transaction.
//!    - Sign with `SuiSigner::sign_transaction`.
//!    - Submit + wait via
//!      [`sui_rpc::Client::execute_transaction_and_wait_for_checkpoint`].
//!    - Compute the tx digest locally (`Transaction::digest()`) for
//!      the returned `commitment_id`.
//!
//! ## SDK-version footnote
//!
//! Pinned at sui-rust-sdk 0.3.x (local checkout — see workspace
//! Cargo.toml). The proto-types surface
//! (`GetObjectRequest`, `ExecuteTransactionRequest`) is generated
//! from `.proto` files; the builder pattern (`Default + with_*`)
//! is what other call sites in the SDK use. If a future SDK bump
//! renames or restructures these, fixes are localized here.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_crypto::SuiSigner;
use sui_sdk_types::{Address, Identifier};
use sui_transaction_builder::{Function, ObjectInput, TransactionBuilder};
use tokio::sync::Mutex;

use crate::client::{AnchorState, CommitBatchArgs, SuiAnchorClient};
use crate::error::{AnchorBackendError, Result};

/// Canonical Sui system-clock shared-object id (`0x6`). Stable across
/// mainnet / testnet / localnet. Required as the `&Clock` parameter to
/// `commit_batch`.
const SUI_CLOCK_OBJECT_ID: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000006";

/// Default execute-and-wait-for-checkpoint timeout. Sui mainnet
/// finality is sub-second under normal conditions; localnet is faster
/// still. 30 seconds is a generous bound for "something is very wrong".
const DEFAULT_EXECUTE_TIMEOUT: Duration = Duration::from_secs(30);

/// Production [`SuiAnchorClient`] impl backed by the Sui Rust SDK.
///
/// Cloneable (internal `Arc<Mutex<_>>`); spawn it once at startup and
/// hand `Box<dyn SuiAnchorClient>` clones to the sealer + driver.
#[derive(Clone)]
pub struct RpcAnchorClient {
    inner: Arc<RpcInner>,
}

struct RpcInner {
    /// gRPC client. Behind a Mutex because `sui_rpc::Client` exposes
    /// sub-clients via `&mut self` methods (`ledger_client()`,
    /// `execution_client()`, `execute_transaction_and_wait_for_checkpoint`).
    /// The lock is uncontended on the sealer-cadence path (one batch
    /// at a time) so contention is not a concern.
    rpc: Mutex<sui_rpc::Client>,
    /// Sealer private key. Signs both the canonical preimage embedded
    /// in `commit_batch` AND the outer Sui transaction. In v1 these
    /// are the same key; multi-key (separate sealer vs. gas payer) is
    /// a Phase-4 follow-on.
    sealer_key: Ed25519PrivateKey,
    /// Operator-deployed `receipt_anchor` package id.
    package_id: Address,
    /// Per-swarm `SwarmAnchor` shared-object id.
    swarm_anchor_id: Address,
    /// Sender = sealer key's derived address. Used as the PTB sender
    /// and gas owner.
    sender_address: Address,
}

impl std::fmt::Debug for RpcAnchorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcAnchorClient")
            .field("package_id", &self.inner.package_id)
            .field("swarm_anchor_id", &self.inner.swarm_anchor_id)
            .field("sender_address", &self.inner.sender_address)
            .field("sealer_key", &"<redacted>")
            .field("rpc", &"<sui_rpc::Client>")
            .finish()
    }
}

impl RpcAnchorClient {
    /// Connect to a Sui fullnode and bind the sealer identity.
    ///
    /// `rpc_url`: any Sui RPC endpoint — mainnet, testnet, localnet,
    /// custom. Use the constants on [`sui_rpc::Client`] (e.g.
    /// `Client::MAINNET_FULLNODE`) for the Sui-Foundation defaults.
    /// `sealer_key`: parsed via
    /// [`crate::keystore::load_sealer_key_from_file`].
    /// `package_id_hex`: 0x-prefixed hex string from `sui client publish`.
    /// `swarm_anchor_id_hex`: 0x-prefixed hex string returned by
    /// `create_swarm_anchor`.
    pub fn connect(
        rpc_url: &str,
        sealer_key: Ed25519PrivateKey,
        package_id_hex: &str,
        swarm_anchor_id_hex: &str,
    ) -> Result<Self> {
        let rpc = sui_rpc::Client::new(rpc_url).map_err(|e| {
            AnchorBackendError::Config(format!("sui-rpc Client::new({rpc_url}): {e}"))
        })?;

        let package_id = Address::from_hex(package_id_hex)
            .map_err(|e| AnchorBackendError::Config(format!("package_id: {e}")))?;
        let swarm_anchor_id = Address::from_hex(swarm_anchor_id_hex)
            .map_err(|e| AnchorBackendError::Config(format!("swarm_anchor_id: {e}")))?;

        // Derive the sender address from the sealer public key. Sui's
        // address-derivation = Blake2b256(scheme_flag || pubkey_bytes);
        // sui_sdk_types' Ed25519PublicKey exposes `derive_address()`
        // that handles this (requires the `hash` feature on sui-sdk-types).
        let sender_address = sealer_key.public_key().derive_address();

        Ok(Self {
            inner: Arc::new(RpcInner {
                rpc: Mutex::new(rpc),
                sealer_key,
                package_id,
                swarm_anchor_id,
                sender_address,
            }),
        })
    }
}

#[async_trait]
impl SuiAnchorClient for RpcAnchorClient {
    async fn read_anchor_state(&self) -> Result<AnchorState> {
        use sui_rpc::field::{FieldMask, FieldMaskUtil};
        use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;

        let object_id_hex = self.inner.swarm_anchor_id.to_hex();
        // `contents` (not `bcs`!) is the BCS of *just* the Move struct
        // fields. `Object.bcs` would be the entire Object wrapper —
        // version, owner, type, plus contents — which is NOT what
        // `decode_anchor_state` expects.
        let request = GetObjectRequest::default()
            .with_object_id(&object_id_hex)
            .with_read_mask(FieldMask::from_paths(["contents"]));

        let response = {
            let mut rpc = self.inner.rpc.lock().await;
            rpc.ledger_client()
                .get_object(request)
                .await
                .map_err(|e| classify_rpc_error(e, "get_object(SwarmAnchor)"))?
        };

        // `Object.contents` is a `Bcs { name, value }` wrapper; the
        // actual Move-struct BCS bytes live in `.value`. Extract via
        // the `From<&Bcs> for Vec<u8>` impl in sui-rpc.
        let bcs_bytes: Vec<u8> = response.get_ref().object().contents().into();
        if bcs_bytes.is_empty() {
            return Err(AnchorBackendError::SwarmAnchorRead(
                "object response missing Move contents (wrong object id, \
                 or fullnode doesn't expose object_contents on this version?)"
                    .into(),
            ));
        }

        decode_anchor_state(&bcs_bytes)
    }

    async fn submit_commit_batch(&self, args: CommitBatchArgs) -> Result<Vec<u8>> {
        use sui_rpc::proto::sui::rpc::v2::{Bcs as BcsProto, ExecuteTransactionRequest};

        let clock_id = Address::from_hex(SUI_CLOCK_OBJECT_ID)
            .map_err(|e| AnchorBackendError::Config(format!("hardcoded clock id parse: {e}")))?;

        // 1. Build the PTB.
        let mut tx = TransactionBuilder::new();
        tx.set_sender(self.inner.sender_address);

        // Shared-object inputs. The SwarmAnchor is mutable (we
        // increment batch_count + last_ns_range_end); the Clock is
        // immutable-ref. Versions are not specified here; the async
        // build path resolves them from chain state.
        let anchor_input = tx.object(
            ObjectInput::new(self.inner.swarm_anchor_id)
                .as_shared()
                .with_mutable(true),
        );
        let clock_input = tx.object(ObjectInput::new(clock_id).as_shared().with_mutable(false));

        // BCS pure inputs. `pure()` returns Argument directly — no
        // Result, since serialization of these types can't fail.
        let batch_root_arg = tx.pure(&args.batch_root);
        let count_arg = tx.pure(&args.count);
        let ns_start_arg = tx.pure(&args.ns_range_start);
        let ns_end_arg = tx.pure(&args.ns_range_end);
        // Histogram crosses the PTB boundary as two parallel pure
        // vectors (`vector<vector<u8>>` keys + `vector<u64>` values);
        // Sui PTBs forbid arbitrary Move structs (including
        // `VecMap<K, V>`) as pure args. The on-chain
        // `commit_batch_from_arrays` wrapper rebuilds the VecMap in
        // input order, which must equal the lex-ascending order the
        // Rust sealer already produces (via BTreeMap iteration).
        let histogram_keys: Vec<Vec<u8>> = args.histogram.iter().map(|(k, _)| k.clone()).collect();
        let histogram_values: Vec<u64> = args.histogram.iter().map(|(_, v)| *v).collect();
        let histogram_keys_arg = tx.pure(&histogram_keys);
        let histogram_values_arg = tx.pure(&histogram_values);
        let signature_arg = tx.pure(&args.sealer_signature);

        // 2. The Move call: <package>::receipt_anchor::commit_batch_from_arrays.
        let function = Function::new(
            self.inner.package_id,
            Identifier::from_static("receipt_anchor"),
            Identifier::from_static("commit_batch_from_arrays"),
        );
        tx.move_call(
            function,
            vec![
                anchor_input,
                batch_root_arg,
                count_arg,
                ns_start_arg,
                ns_end_arg,
                histogram_keys_arg,
                histogram_values_arg,
                signature_arg,
                clock_input,
            ],
        );

        // 3. Resolve gas + finalize. The async `build()` path uses
        // the RPC client for gas selection + transaction simulation;
        // requires the `intents` feature on sui-transaction-builder
        // (on by default).
        let transaction = {
            let mut rpc = self.inner.rpc.lock().await;
            tx.build(&mut rpc)
                .await
                .map_err(|e| AnchorBackendError::Config(format!("transaction build: {e}")))?
        };

        // Compute the digest locally — Transaction::digest() is the
        // same value the chain will see, so we can return it as the
        // commitment_id without parsing the execute response.
        let tx_digest_bytes = transaction.digest().inner().to_vec();

        // 4. Sign the Sui tx (separate from the preimage signature
        // already embedded as `signature_arg`).
        let user_sig = self
            .inner
            .sealer_key
            .sign_transaction(&transaction)
            .map_err(|e| AnchorBackendError::SealerKey(format!("sign_transaction: {e}")))?;

        // 5. Encode tx + signature for the wire.
        //
        // The proto `Transaction` and `UserSignature` messages each
        // carry a BCS-serialized body. `Bcs::serialize` does the
        // bcs::to_bytes call and wraps it in the proto Bcs message in
        // one step.
        let tx_bcs = BcsProto::serialize(&transaction)
            .map_err(|e| AnchorBackendError::Config(format!("BCS encode transaction: {e}")))?;
        let sig_bcs = BcsProto::serialize(&user_sig)
            .map_err(|e| AnchorBackendError::Config(format!("BCS encode UserSignature: {e}")))?;

        let mut tx_proto = sui_rpc::proto::sui::rpc::v2::Transaction::default();
        tx_proto.set_bcs(tx_bcs);
        let mut sig_proto = sui_rpc::proto::sui::rpc::v2::UserSignature::default();
        sig_proto.set_bcs(sig_bcs);

        let request = ExecuteTransactionRequest::default()
            .with_transaction(tx_proto)
            .with_signatures(vec![sig_proto]);

        let response = {
            let mut rpc = self.inner.rpc.lock().await;
            rpc.execute_transaction_and_wait_for_checkpoint(request, DEFAULT_EXECUTE_TIMEOUT)
                .await
                .map_err(classify_execute_error)?
        };

        // 6. Sanity-check the execution status. Move aborts surface
        // here as a non-success effect status; we map them to
        // AnchorBackendError::OnChainAbort with the abort code parsed
        // out when present. The abort code lives at
        // `effects.status.error.abort.abort_code` (a `MoveAbort` inside
        // the `error_details` oneof of `ExecutionError`).
        let inner = response.into_inner();
        let effects = inner.transaction().effects();
        let status = effects.status();
        if !status.success_opt().unwrap_or(false) {
            let err = status.error_opt();
            let abort_code = err
                .and_then(|e| e.abort_opt())
                .and_then(|a| a.abort_code_opt());
            let detail = err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "transaction failed without an ExecutionError".into());
            return Err(AnchorBackendError::OnChainAbort {
                code: abort_code,
                detail,
            });
        }

        Ok(tx_digest_bytes)
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// BCS-decode the `SwarmAnchor` shared-object content into our
/// off-chain view of its mutable state. We don't need the full
/// struct here — just `batch_count` and `last_ns_range_end`. The
/// `id` UID prefix and `created_at_ms` suffix are read and discarded.
///
/// Field order MUST match `receipt_anchor.move`:
///   id: UID, swarm_id: vector<u8>, sealer_pubkey: vector<u8>,
///   batch_count: u64, last_ns_range_end: u64, created_at_ms: u64.
fn decode_anchor_state(object_bcs: &[u8]) -> Result<AnchorState> {
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct SwarmAnchorOnChain {
        // UID has the layout `id: ID(address)` which BCS-serializes as
        // 32 bytes. Treat as opaque.
        id: [u8; 32],
        swarm_id: Vec<u8>,
        sealer_pubkey: Vec<u8>,
        batch_count: u64,
        last_ns_range_end: u64,
        created_at_ms: u64,
    }

    let parsed: SwarmAnchorOnChain = bcs::from_bytes(object_bcs).map_err(|e| {
        AnchorBackendError::SwarmAnchorRead(format!(
            "BCS decode SwarmAnchor (object content shape may have changed): {e}"
        ))
    })?;

    Ok(AnchorState {
        batch_count: parsed.batch_count,
        last_ns_range_end: parsed.last_ns_range_end,
    })
}

/// Map a tonic::Status from a Sui RPC call into our error hierarchy.
/// Everything network-shaped is transient; specific permanent failures
/// (object not found, package not deployed) propagate as
/// `SwarmAnchorRead` / `Config`.
fn classify_rpc_error(status: tonic::Status, op: &str) -> AnchorBackendError {
    use tonic::Code;
    match status.code() {
        Code::NotFound => AnchorBackendError::SwarmAnchorRead(format!("{op}: not found: {status}")),
        Code::InvalidArgument => {
            AnchorBackendError::Config(format!("{op}: invalid argument: {status}"))
        }
        _ => AnchorBackendError::RpcTransient(format!("{op}: {status}")),
    }
}

/// Same shape as `classify_rpc_error` but for the wrapped
/// `ExecuteAndWaitError`. Unwraps RpcError into the same classification;
/// surfaces checkpoint timeouts as transient (the tx may still be
/// landing; the next cadence tick re-attempts).
fn classify_execute_error(err: sui_rpc::client::ExecuteAndWaitError) -> AnchorBackendError {
    use sui_rpc::client::ExecuteAndWaitError as E;
    // `ExecuteAndWaitError` is `#[non_exhaustive]` — upstream can add
    // variants in a minor bump, so we cover the known set explicitly
    // and treat anything new as transient (safe default: the cadence
    // loop will retry; the operator will see it in logs).
    match err {
        E::RpcError(status) => classify_rpc_error(status, "execute_transaction"),
        E::MissingTransaction => {
            AnchorBackendError::Config("execute: missing transaction (caller bug)".into())
        }
        E::ProtoConversionError(e) => {
            AnchorBackendError::Config(format!("execute: proto conversion: {e}"))
        }
        E::CheckpointTimeout(_) => AnchorBackendError::RpcTransient(
            "execute_and_wait: checkpoint timeout — tx may still confirm".into(),
        ),
        E::CheckpointStreamError { error, .. } => AnchorBackendError::RpcTransient(format!(
            "execute_and_wait: checkpoint stream: {error}"
        )),
        other => AnchorBackendError::RpcTransient(format!(
            "execute_and_wait: unrecognized SDK error variant: {other:?}"
        )),
    }
}

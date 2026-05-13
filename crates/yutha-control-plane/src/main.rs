//! Yutha control-plane binary.
//!
//! Brings the in-memory backends up, registers a bootstrap agent end-to-end,
//! and exposes a gRPC server on `--grpc-addr` (default `127.0.0.1:50051`)
//! across four services from
//! [`/spec/control-plane/v1.proto`](../../../../spec/control-plane/v1.proto).
//!
//! Implementation status (all four services wired):
//!   - `ReceiptService` (Get, Query) — wired through to the
//!     [`ReceiptStore`](yutha_receipt::ReceiptStore).
//!   - `AdmissionService` (Register, Revoke, GetTopology) — wired through
//!     to the [`Registry`](yutha_registry::Registry). `RotateKey` returns
//!     `UNIMPLEMENTED` pending a spec RFC (the wire shape can't carry a
//!     self-signed continuation passport).
//!   - `CapabilityService` (Issue, Attenuate, Revoke, Check) — wired
//!     through to the [`CapabilityStore`](yutha_capability::CapabilityStore).
//!     Issuance signs with the control-plane's key as a scaffolding
//!     shortcut; a future RFC pins down per-issuer signing.
//!   - `EnvelopeService.Send` — wired through to
//!     [`Transport::send`](yutha_transport::Transport).
//!   - `EnvelopeService.Subscribe` — server-streaming. Idempotently
//!     registers the bearer's inbox on first call and forwards every
//!     delivered envelope + its `envelope.deliver` receipt id.
//!
//! Always-on infrastructure:
//!   - bearer-token verification ([`crate::auth::require_bearer_auth`]) —
//!     called by every handler that requires auth. Validates an
//!     `authorization: bearer <hex>` metadata header end-to-end against
//!     the registered passport's public key.
//!   - gRPC reflection (so `grpcurl <addr> list` works without proto files)
//!   - optional TLS (server cert; presence of --client-ca opts into mTLS)

#![forbid(unsafe_code)]

mod auth;
mod grpc;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tracing::{info, warn};
use yutha_capability::{CapabilityStore, MemoryCapabilityStore};
use yutha_core::{AgentId, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::hash::sha256;
use yutha_crypto::sign::{generate_keypair, SigningKey};
use yutha_passport::{
    ControlPlaneIdentity, MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore,
    PassportTier,
};
use yutha_proto::control_plane::v1::{
    admission_service_server::AdmissionServiceServer,
    capability_service_server::CapabilityServiceServer,
    envelope_service_server::EnvelopeServiceServer, receipt_service_server::ReceiptServiceServer,
};
use yutha_proto::FILE_DESCRIPTOR_SET;
use yutha_receipt::{
    ActionKindQuery, MemoryStore as MemoryReceiptStore, PassportResolver, Query, ReceiptStore,
};
use yutha_registry::{
    AdmissionPolicy, ClosedPolicy, MemoryRegistry, OpenPolicy, Registry, Topology, TopologyMode,
};
use yutha_transport::{MemoryTransport, Transport};

use auth::BearerInterceptor;
use grpc::{
    admission::AdmissionHandler, capability::CapabilityHandler, envelope::EnvelopeHandler,
    receipt::ReceiptHandler, ControlPlaneState,
};

/// Yutha control plane.
#[derive(Debug, Parser)]
#[command(name = "yutha", version, about, long_about = None)]
struct Cli {
    /// gRPC listen address. Default is loopback-only; bind to 0.0.0.0
    /// for non-local access (and consider TLS).
    #[arg(long, env = "YUTHA_GRPC_ADDR", default_value = "127.0.0.1:50051")]
    grpc_addr: SocketAddr,

    /// TLS server certificate (PEM). When set, the gRPC server requires
    /// TLS. Pair with --tls-key.
    #[arg(long, env = "YUTHA_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// TLS server private key (PEM). Required when --tls-cert is set.
    #[arg(long, env = "YUTHA_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// Client CA bundle (PEM). When set, the gRPC server requires
    /// client certs (mTLS). Layered on top of bearer-token auth.
    #[arg(long, env = "YUTHA_CLIENT_CA")]
    client_ca: Option<PathBuf>,

    /// Admission policy for the registry.
    ///
    /// - `closed` (default) — only the bootstrap agent is allowlisted.
    ///   Matches production posture: no agent can join without
    ///   pre-registration. Used by the existing
    ///   `test_integration.py` smoke tests.
    /// - `open` — any well-formed passport with `expires_at` set and
    ///   tier ≥ Minimal is admitted. Intended for demos and local
    ///   development (the Stage-4c LangGraph customer-support demo
    ///   uses this mode so its five agents can self-register).
    ///   **Never enable in production**: open mode imposes no Sybil
    ///   resistance beyond the default `OpenPolicy` requirements.
    #[arg(long, env = "YUTHA_ADMISSION_MODE", value_enum, default_value_t = AdmissionModeArg::Closed)]
    admission_mode: AdmissionModeArg,

    /// Deterministic 32-byte hex seed for the bootstrap agent's
    /// identity (signing key + AgentId + SwarmId).
    ///
    /// When unset, all three are generated randomly at startup
    /// (production behavior; the bootstrap key stays in-process and
    /// is never exposed). When set, the seed is fed into:
    ///
    ///   - the Ed25519 signing key directly (32 raw seed bytes)
    ///   - `sha256(seed || 0x01)[:16]` → bootstrap AgentId
    ///   - `sha256(seed || 0x02)[:16]` → SwarmId
    ///
    /// so an external client that knows the seed can derive the same
    /// identity and act as the bootstrap agent.
    ///
    /// Use case: end-to-end integration tests (the Python SDK's
    /// `test_integration.py`) that need to authenticate as a known
    /// agent already in the swarm's allowlist. The seed travels
    /// through the same channel as any production secret (env var or
    /// file) and never widens the server's auth surface — the closed
    /// admission policy is unchanged.
    ///
    /// **WARNING:** logged at startup. Pass via env var
    /// (`YUTHA_BOOTSTRAP_SEED`) rather than `--bootstrap-seed` on the
    /// command line so it doesn't appear in `ps aux`. Do NOT enable
    /// in production unless you've explicitly chosen the seed from a
    /// KMS-backed source.
    #[arg(long, env = "YUTHA_BOOTSTRAP_SEED")]
    bootstrap_seed: Option<String>,
}

/// CLI shadow of [`yutha_registry::AdmissionPolicy`]'s variants we expose.
/// `Hybrid` is intentionally not surfaced yet — its policy fields don't
/// map cleanly to a single flag, and there's no demand for it from the
/// command line. When a workload needs it, add it explicitly.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum AdmissionModeArg {
    Closed,
    Open,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();
    info!("yutha control-plane starting up");

    let bootstrap_identity = match cli.bootstrap_seed.as_deref() {
        Some(seed_hex) => Some(BootstrapIdentity::from_seed_hex(seed_hex)?),
        None => None,
    };
    let state = bootstrap_backends(bootstrap_identity, cli.admission_mode).await?;
    serve_grpc(&cli, state).await?;
    Ok(())
}

/// Deterministically-derived bootstrap-agent identity, optionally
/// supplied by the operator via `--bootstrap-seed` /
/// `YUTHA_BOOTSTRAP_SEED`.
///
/// All three fields are derived from the same 32-byte seed so a
/// client that holds the seed can reconstruct them without any
/// out-of-band coordination with the running server.
struct BootstrapIdentity {
    signing_key: SigningKey,
    agent_id: AgentId,
    swarm_id: SwarmId,
}

impl BootstrapIdentity {
    fn from_seed_hex(seed_hex: &str) -> anyhow::Result<Self> {
        let seed_bytes =
            hex::decode(seed_hex.trim()).context("bootstrap-seed: hex decode failed")?;
        let seed: [u8; 32] = seed_bytes.try_into().map_err(|v: Vec<u8>| {
            anyhow::anyhow!(
                "bootstrap-seed: expected 32 raw bytes (64 hex chars), got {} bytes",
                v.len()
            )
        })?;
        // Ed25519 takes the seed directly.
        let signing_key = SigningKey::from_bytes(&seed);
        // Domain-separated derivations: a one-byte tag distinguishes
        // the two identifier streams so they can't ever collide.
        let mut agent_input = Vec::with_capacity(33);
        agent_input.extend_from_slice(&seed);
        agent_input.push(0x01);
        let agent_id = AgentId::from_bytes(&sha256(&agent_input).digest[..16])
            .context("bootstrap-seed: derive agent_id")?;

        let mut swarm_input = Vec::with_capacity(33);
        swarm_input.extend_from_slice(&seed);
        swarm_input.push(0x02);
        let swarm_id = SwarmId::from_bytes(&sha256(&swarm_input).digest[..16])
            .context("bootstrap-seed: derive swarm_id")?;

        warn!(
            agent_id = %agent_id,
            swarm_id = %swarm_id,
            "bootstrap-seed in use — bootstrap identity is deterministically derivable by anyone with the seed. Intended for integration tests; never enable in production unless the seed comes from a KMS-backed source."
        );

        Ok(Self {
            signing_key,
            agent_id,
            swarm_id,
        })
    }
}

/// Bring up the in-memory backends and register a bootstrap agent.
///
/// This is the Phase-1 substrate exercise: every backend gets constructed
/// in the right order, the cp identity is wired in, the bootstrap agent
/// is admitted, and the audit trail is sanity-checked. Same logic as the
/// pre-gRPC binary; we just return the assembled state at the end so the
/// gRPC handlers can share it.
async fn bootstrap_backends(
    bootstrap_identity: Option<BootstrapIdentity>,
    admission_mode: AdmissionModeArg,
) -> anyhow::Result<Arc<ControlPlaneState>> {
    // If the operator supplied a deterministic bootstrap seed, the
    // resulting (signing_key, agent_id, swarm_id) triplet replaces the
    // random defaults below. Everything downstream — the CLOSED
    // admission policy with this agent in the allowlist, the receipt
    // emission path, the resolver — works identically whether the
    // identity is random or seed-derived.
    //
    // (Match rather than `unwrap_or_else(SwarmId::new)` because
    // clippy's `unwrap_or_default` suggestion is wrong here:
    // `SwarmId::new()` produces a fresh UUID v7, whereas
    // `SwarmId::default()` would be all zeros — very different
    // semantics.)
    let swarm_id = match bootstrap_identity.as_ref() {
        Some(b) => b.swarm_id,
        None => SwarmId::new(),
    };

    let receipt_store: Arc<dyn ReceiptStore> = Arc::new(MemoryReceiptStore::new());
    let passport_store: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
    let resolver: Arc<dyn PassportResolver> =
        Arc::new(PassportResolverAdapter::new(Arc::clone(&passport_store)));
    info!("resolver adapter wired (passport → receipt)");

    let cp_key = generate_keypair();
    let cp_agent_id = AgentId::new();
    let cp_passport = Passport::builder()
        .spec_version(SpecVersion::parse("1.0.0").context("parse spec version")?)
        .agent_id(cp_agent_id)
        .swarm_id(swarm_id)
        .agent_public_key(cp_key.public())
        .owner("yutha control plane")
        .accepted_constitution_version("1.0.0")
        .tier(PassportTier::Minimal)
        .issued_at(Timestamp::now())
        .sign(&cp_key)
        .map_err(|e| anyhow::anyhow!("build cp passport: {e}"))?;
    passport_store
        .register(cp_passport)
        .await
        .context("register control-plane passport")?;
    info!(
        cp_agent_id = %cp_agent_id,
        "control-plane identity registered (genesis; no receipt)"
    );
    let cp = Arc::new(ControlPlaneIdentity::new(cp_agent_id, cp_key));

    let capability_store: Arc<dyn CapabilityStore> = Arc::new(MemoryCapabilityStore::new(
        Arc::clone(&receipt_store),
        Arc::clone(&resolver),
        Arc::clone(&cp),
    ));
    let transport: Arc<dyn Transport> = Arc::new(MemoryTransport::new(
        Arc::clone(&receipt_store),
        Arc::clone(&resolver),
        Arc::clone(&cp),
    ));

    let (bootstrap_key, bootstrap_agent_id) = match bootstrap_identity {
        Some(b) => (b.signing_key, b.agent_id),
        None => (generate_keypair(), AgentId::new()),
    };
    // expires_at is required by open-mode admission and ignored by
    // closed-mode, so we set it unconditionally. Use a far-future
    // sentinel: the bootstrap identity is server-managed and not
    // expected to rotate within this process's lifetime.
    let bootstrap_expires_at = Timestamp::new("2099-01-01T00:00:00Z".into(), u64::MAX / 2)
        .map_err(|e| anyhow::anyhow!("build bootstrap expires_at: {e}"))?;
    let bootstrap_passport = Passport::builder()
        .spec_version(SpecVersion::parse("1.0.0").context("parse spec version")?)
        .agent_id(bootstrap_agent_id)
        .swarm_id(swarm_id)
        .agent_public_key(bootstrap_key.public())
        .owner("yutha-control-plane bootstrap")
        .framework("none", "n/a")
        .accepted_constitution_version("1.0.0")
        .tier(PassportTier::Minimal)
        .issued_at(Timestamp::now())
        .expires_at(bootstrap_expires_at)
        .sign(&bootstrap_key)
        .map_err(|e| anyhow::anyhow!("build bootstrap passport: {e}"))?;

    let (admission, topology_mode) = match admission_mode {
        AdmissionModeArg::Closed => (
            AdmissionPolicy::Closed(ClosedPolicy {
                allowlisted_agents: vec![bootstrap_agent_id],
                ..Default::default()
            }),
            TopologyMode::Closed,
        ),
        AdmissionModeArg::Open => (
            // OpenPolicy::default() requires tier ≥ Standard, which
            // would reject every Minimal-tier demo passport (including
            // this binary's own bootstrap agent). Relax to Minimal
            // here — open mode is already an explicit "demo only" knob
            // (see the WARN below), so the tier floor doesn't add
            // production safety it can't already get from staying in
            // closed mode.
            AdmissionPolicy::Open(OpenPolicy {
                min_passport_tier: PassportTier::Minimal,
                ..Default::default()
            }),
            TopologyMode::Open,
        ),
    };
    if matches!(admission_mode, AdmissionModeArg::Open) {
        warn!(
            "admission mode: OPEN — any well-formed passport is admitted. \
             Intended for demos and local development only."
        );
    }
    let topology = Topology {
        spec_version: SpecVersion::parse("1.0.0").context("parse spec version")?,
        swarm_id,
        mode: topology_mode,
        admission,
        max_capability_lifetime_seconds: 90 * 24 * 60 * 60,
        max_capability_chain_depth: 8,
        default_envelope_ttl_seconds: 300,
        max_epoch_skew: 256,
        external_sends_permitted: false,
        // E1b will set this based on `admission_mode` (CLOSED→true,
        // OPEN→false). E1a only adds the field so the workspace
        // compiles; behavior is unchanged until E1b ships the
        // Send-path handler that consults it.
        require_capability_for_send: false,
        initial_constitution_version: "1.0.0".into(),
        operator_key_fingerprint: vec![0u8; 32],
        operator_signature: None,
    };
    let registry: Arc<dyn Registry> = Arc::new(MemoryRegistry::new(
        topology,
        Arc::clone(&passport_store),
        Arc::clone(&receipt_store),
        Arc::clone(&resolver),
        Arc::clone(&cp),
    )?);
    let mode_str = match admission_mode {
        AdmissionModeArg::Closed => "CLOSED",
        AdmissionModeArg::Open => "OPEN",
    };
    info!(swarm_id = %swarm_id, mode = mode_str, "registry constructed");

    let outcome = registry.register(bootstrap_passport).await?;
    info!(
        status = ?outcome.status,
        agent_id = %outcome.agent_id,
        receipt = ?outcome.registration_receipt.as_ref().map(|h| h.to_hex()),
        "bootstrap agent registered with receipt"
    );

    match resolver.resolve_actor(&bootstrap_agent_id).await {
        Ok(Some(_pk)) => info!("resolver sees bootstrap agent ✓"),
        Ok(None) => warn!("resolver could not see bootstrap agent (unexpected)"),
        Err(e) => warn!(error = %e, "resolver error (unexpected)"),
    }

    let receipt_count = receipt_store.count().await.unwrap_or(0);
    let register_receipts = receipt_store
        .query(
            Query::ByActionKind(ActionKindQuery {
                action_kind: "agent.register".into(),
            }),
            None,
        )
        .await
        .map(|p| p.receipts.len())
        .unwrap_or(0);
    info!(
        receipt_count,
        register_receipts, "receipt store reachable; audit trail populated"
    );

    Ok(Arc::new(ControlPlaneState {
        registry,
        passport_store,
        capability_store,
        transport,
        receipt_store,
        resolver,
        control_plane_identity: cp,
    }))
}

/// Build and run the gRPC server. Handles graceful Ctrl-C shutdown.
async fn serve_grpc(cli: &Cli, state: Arc<ControlPlaneState>) -> anyhow::Result<()> {
    // Bearer-token interceptor is a sync passthrough that just emits a
    // trace event noting whether an authorization header is present.
    // Real verification is async (it calls into the passport resolver
    // and runs Ed25519 verify) and lives in `crate::auth::require_bearer_auth`,
    // which handlers call directly. tonic 0.11's interceptor trait is
    // sync, which is why we don't enforce here. Each service gets a
    // fresh clone of the interceptor (tonic's `with_interceptor` takes
    // the interceptor by value).
    let interceptor = BearerInterceptor::new();
    let admission = AdmissionServiceServer::with_interceptor(
        AdmissionHandler::new(Arc::clone(&state)),
        interceptor.clone(),
    );
    let capability = CapabilityServiceServer::with_interceptor(
        CapabilityHandler::new(Arc::clone(&state)),
        interceptor.clone(),
    );
    let envelope = EnvelopeServiceServer::with_interceptor(
        EnvelopeHandler::new(Arc::clone(&state)),
        interceptor.clone(),
    );
    let receipt = ReceiptServiceServer::with_interceptor(
        ReceiptHandler::new(Arc::clone(&state)),
        interceptor,
    );

    // gRPC reflection from the compiled FileDescriptorSet — lets
    // `grpcurl <addr> list` work without shipping proto files separately.
    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build()
        .context("build reflection service")?;

    let mut builder = Server::builder();

    // Optional TLS / mTLS. Three states:
    //   - no --tls-cert: plaintext (loopback local-dev default).
    //   - --tls-cert + --tls-key: server TLS.
    //   - --tls-cert + --tls-key + --client-ca: mTLS (server still
    //     verifies bearer token; cert is an additional layer).
    match (
        cli.tls_cert.as_ref(),
        cli.tls_key.as_ref(),
        cli.client_ca.as_ref(),
    ) {
        (None, None, None) => {
            info!(addr = %cli.grpc_addr, "gRPC: plaintext (no TLS configured)");
        }
        (Some(cert_path), Some(key_path), client_ca) => {
            let cert_pem =
                std::fs::read(cert_path).with_context(|| format!("read TLS cert {cert_path:?}"))?;
            let key_pem =
                std::fs::read(key_path).with_context(|| format!("read TLS key {key_path:?}"))?;
            let identity = Identity::from_pem(cert_pem, key_pem);
            let mut tls = ServerTlsConfig::new().identity(identity);
            if let Some(ca_path) = client_ca {
                let ca_pem = std::fs::read(ca_path)
                    .with_context(|| format!("read client CA {ca_path:?}"))?;
                tls = tls.client_ca_root(tonic::transport::Certificate::from_pem(ca_pem));
                info!(addr = %cli.grpc_addr, "gRPC: mTLS (server cert + client CA)");
            } else {
                info!(addr = %cli.grpc_addr, "gRPC: server TLS");
            }
            builder = builder.tls_config(tls).context("apply TLS configuration")?;
        }
        (cert, key, _) => {
            anyhow::bail!(
                "TLS misconfiguration: --tls-cert and --tls-key must be set together \
                 (cert = {:?}, key = {:?})",
                cert.is_some(),
                key.is_some(),
            );
        }
    }

    let router = builder
        .add_service(admission)
        .add_service(capability)
        .add_service(envelope)
        .add_service(receipt)
        .add_service(reflection);

    info!(
        addr = %cli.grpc_addr,
        "yutha control-plane gRPC server listening (all four services wired)"
    );

    router
        .serve_with_shutdown(cli.grpc_addr, async {
            // Graceful shutdown on Ctrl-C. tokio's signal handler is
            // installed once and resolves on SIGINT.
            if let Err(e) = tokio::signal::ctrl_c().await {
                warn!(error = %e, "ctrl-c handler errored; shutting down anyway");
            }
            info!("Ctrl-C received; shutting down gRPC server");
        })
        .await
        .context("gRPC server failed")?;

    info!("shutdown complete");
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, FmtSubscriber};
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,yutha=debug"));
    let subscriber = FmtSubscriber::builder().with_env_filter(filter).finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

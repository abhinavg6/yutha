//! `yutha-ops` — operator CLI for the Yutha control plane.
//!
//! Subcommands, all over plain-text gRPC by default (use the
//! Python SDK or a custom client for TLS):
//!
//!   * `activate <cedar-file> [--engine-config <yaml-file>]` —
//!     publish a constitution via `ConstitutionService.Activate`
//!     (operator-bearer auth).
//!   * `grep <action_kind>` — query receipts by action_kind via
//!     `ReceiptService.Query` (agent-bearer auth).
//!   * `revoke <agent_id> --reason <text> [--cascade]` —
//!     operator-revoke an agent via
//!     `AdmissionService.OperatorRevoke` (operator-bearer auth).
//!   * `print-operator-pubkey` — derive the operator public key
//!     from the seed and print it as hex. Pipe straight into the
//!     server's `--operator-public-key` flag at startup. No server
//!     connection needed; uses the seed only.
//!   * `compile <yaml-file>` — compile a plain-English YAML DSL
//!     document into Cedar + engine-config files. No server
//!     connection, no seed needed.
//!
//! Auth is driven by a single 32-byte `--seed` hex value (or
//! `YUTHA_BOOTSTRAP_SEED`). The CLI derives every identity from it
//! using the same hashing scheme the control-plane binary uses for
//! its bootstrap agent (`sha256(seed || 0x01)` → AgentId,
//! `sha256(seed || 0x02)` → SwarmId, `sha256(seed || 0x03)` →
//! operator signing key). That means the same seed the operator
//! handed to the server can be re-used here without copying
//! additional keys around.
//!
//! Bearer-token wire shape mirrors the Python SDK: prost-encode the
//! token proto with the signature field cleared, sign over those
//! canonical bytes, attach the signature to the proto, then
//! hex-encode the full re-serialized message. Attach as
//! `authorization: bearer agent <hex>` or `bearer operator <hex>`
//! depending on the call.

mod compile;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use prost::Message;
use sha2::{Digest, Sha256};
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::Request;

use yutha_core::{AgentId, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::sign::SigningKey;
use yutha_proto::common::v1 as common;
use yutha_proto::control_plane::v1::{
    admission_service_client::AdmissionServiceClient,
    constitution_service_client::ConstitutionServiceClient,
    receipt_service_client::ReceiptServiceClient, replay_service_client::ReplayServiceClient,
    ActivateConstitutionRequest, ActivateShadowConstitutionRequest, AgentBearerToken,
    ClearShadowConstitutionRequest, CloseReplaySessionRequest, Constitution,
    CreateReplaySessionRequest, ListReplaySessionsRequest, OperatorBearerToken,
    OperatorRevokeRequest, PromoteShadowConstitutionRequest, QueryReceiptsRequest,
    QueryReplayReceiptsRequest, ReplayMode as ProtoReplayMode, ReplaySessionWindow,
    RunReplaySessionRequest,
};
use yutha_proto::receipt::v1::{ActionKindQuery, QueryRequest};

#[derive(Debug, Parser)]
#[command(
    name = "yutha-ops",
    version,
    about = "Operator CLI for the Yutha control plane.",
    long_about = None
)]
struct Cli {
    /// gRPC address of the control plane.
    #[arg(long, env = "YUTHA_GRPC_ADDR", default_value = "127.0.0.1:50051")]
    addr: String,

    /// 32-byte hex seed. Used to derive both the agent (for `grep`)
    /// and the operator (for `activate` / `revoke`). Same seed the
    /// control plane was started with — see
    /// `crates/yutha-control-plane/src/main.rs` for the derivation
    /// scheme.
    ///
    /// Optional only when invoking `compile` (a pure-local file → file
    /// transformation that doesn't talk to the server and doesn't use
    /// the seed at all). Required for every other subcommand —
    /// including `print-operator-pubkey`, which uses the seed locally
    /// without a server connection.
    #[arg(long, env = "YUTHA_BOOTSTRAP_SEED")]
    seed: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Publish a constitution via ConstitutionService.Activate.
    Activate {
        /// Path to the Cedar policy source file.
        cedar_file: PathBuf,
        /// Path to the engine-config YAML file. Defaults to an empty
        /// (schema_version-only) config; pass a real file to attach
        /// scoring / procedure / enforcement rules.
        #[arg(long)]
        engine_config: Option<PathBuf>,
        /// Constitution version (semver). Bumped on each amendment.
        #[arg(long, default_value = "1.0.0")]
        version: String,
        /// Cedar+ schema_version the policy is authored against.
        #[arg(long, default_value = "1.1.0")]
        schema_version: String,
    },

    /// Load a candidate constitution into the shadow slot via
    /// ConstitutionService.ActivateShadow (Phase 3b, RFC 0018 §3.2).
    ///
    /// Once loaded, every envelope evaluates against both the active
    /// and the shadow; the active gates the cap layer + enforcement
    /// engine, the shadow only emits
    /// `constitution.evaluate.shadow.{pass,deny}` receipts.
    ///
    /// Operator workflow: activate-shadow → watch divergence (e.g.
    /// `yutha-ops grep constitution.evaluate.shadow.deny`) →
    /// promote-shadow when satisfied, or clear-shadow + re-activate
    /// to iterate.
    ActivateShadow {
        /// Path to the Cedar policy source file for the shadow.
        cedar_file: PathBuf,
        /// Path to the engine-config YAML file for the shadow. Same
        /// semantics as `activate --engine-config`.
        #[arg(long)]
        engine_config: Option<PathBuf>,
        /// Shadow constitution version (semver). May differ from the
        /// active's — operators previewing an amendment typically bump
        /// the version here ahead of the eventual promote.
        #[arg(long, default_value = "1.0.0")]
        version: String,
        /// Cedar+ schema_version the shadow is authored against.
        #[arg(long, default_value = "1.1.0")]
        schema_version: String,
    },

    /// Clear the shadow slot via ConstitutionService.ClearShadow.
    /// Idempotent — emits a `constitution.shadow_clear` receipt even
    /// if the slot was already empty (the receipt records the
    /// operator's intent regardless).
    ClearShadow,

    /// Atomically promote the shadow slot to active via
    /// ConstitutionService.PromoteShadow (Phase 3b, RFC 0018 §3.2).
    /// The shadow slot is left empty. Per-agent reputation +
    /// quarantine state is preserved; sliding-window counters reset.
    ///
    /// Fails with FAILED_PRECONDITION if the shadow slot is empty.
    PromoteShadow,

    /// Create a replay session against a candidate constitution
    /// (Phase 3c, RFC 0018 §4). The candidate is previewed against
    /// receipts in [--from, --to]; the session's emissions land in
    /// an isolated session-scoped receipt store (production stays
    /// untouched). Print the new session id; subsequent commands
    /// take it via `--session-id`.
    ReplayCreate {
        /// Path to the candidate Cedar policy source file.
        cedar_file: PathBuf,
        /// Path to the candidate engine-config YAML (optional —
        /// defaults to an empty config; without enforcement_rules
        /// the candidate replay produces no emissions).
        #[arg(long)]
        engine_config: Option<PathBuf>,
        /// Candidate version (semver).
        #[arg(long, default_value = "1.0.0")]
        version: String,
        /// Cedar+ schema version the candidate is authored against.
        #[arg(long, default_value = "1.1.0")]
        schema_version: String,
        /// Lower bound of the receipt window (monotonic_ns, inclusive).
        #[arg(long)]
        from: u64,
        /// Upper bound of the receipt window (monotonic_ns, inclusive).
        #[arg(long)]
        to: u64,
        /// Whitelist of action-kinds to replay. Repeatable. Empty
        /// = wildcard. Typical: `--filter envelope.send`.
        #[arg(long = "filter")]
        action_kind_filter: Vec<String>,
        /// Engine state-init mode. `cold` starts from defaults;
        /// `warm` rebuilds the engine state from receipts preceding
        /// `--from` for `--warm-lookback-hours` (default 24).
        #[arg(long, default_value = "cold")]
        mode: String,
        /// Warm-mode lookback hours. Ignored when mode != warm.
        #[arg(long, default_value = "24")]
        warm_lookback_hours: u32,
    },

    /// Stream the replay session's progress via
    /// ReplayService.RunSession. Prints one line per progress event
    /// + a terminal "window complete" line.
    ReplayRun {
        /// The session id returned by `replay-create`.
        #[arg(long)]
        session_id: String,
    },

    /// Query the session's isolated receipt store by action_kind via
    /// ReplayService.QueryReplayReceipts. Same shape as `grep` but
    /// scoped to one session.
    ReplayQuery {
        /// The session id.
        #[arg(long)]
        session_id: String,
        /// Action kind to match within the session's store.
        action_kind: String,
        /// Maximum receipts to print.
        #[arg(long, default_value = "20")]
        limit: u32,
    },

    /// Close a replay session via ReplayService.CloseSession.
    /// Releases the per-session engine + receipt store on the server
    /// and emits the `replay.session.close` audit receipt into the
    /// production store.
    ReplayClose {
        /// The session id.
        #[arg(long)]
        session_id: String,
    },

    /// List active replay sessions via ReplayService.ListSessions.
    ReplayList,

    /// Query receipts by action_kind via ReceiptService.Query.
    Grep {
        /// Action kind to match (e.g. "envelope.send",
        /// "constitution.evaluate.deny").
        action_kind: String,
        /// Maximum receipts to print. 0 means server default.
        #[arg(long, default_value = "20")]
        limit: u32,
    },

    /// Operator-revoke an agent via AdmissionService.OperatorRevoke.
    Revoke {
        /// Target agent's UUIDv7 (hyphenated form).
        agent_id: String,
        /// Free-form reason recorded on the revocation receipt.
        #[arg(long)]
        reason: String,
        /// Cascade-revoke every capability the agent holds (RFC 0009
        /// §3.2). Default: false.
        #[arg(long)]
        cascade: bool,
    },

    /// Derive the operator public key from `--seed` and print it as
    /// 64-character hex on stdout. Designed to be piped straight into
    /// the control plane's `--operator-public-key` flag at startup
    /// (the server only ever needs the public counterpart; the
    /// private operator key stays here, derived on demand from the
    /// seed via `sha256(seed || 0x03)`).
    PrintOperatorPubkey,

    /// Compile a plain-English YAML DSL document to Cedar + engine
    /// config. The compile path does NOT require a connection to the
    /// server (and the `--seed` argument is unused) — emit the two
    /// files locally, then pass them to `activate`.
    Compile {
        /// Path to the YAML DSL document. See
        /// `/spec/constitution/canonical-schemas/v1.1.0/examples/`
        /// for sample shapes.
        input: PathBuf,
        /// Where to write the generated Cedar policy source. Defaults
        /// to the input path with the extension replaced by `.cedar`.
        #[arg(long)]
        out_cedar: Option<PathBuf>,
        /// Where to write the generated engine-config YAML. Defaults
        /// to the input path with the extension replaced by
        /// `.engine.yaml`.
        #[arg(long)]
        out_engine_config: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();

    // `compile` is a pure-local file → file transformation. It does
    // NOT need the seed or a server connection, so dispatch it
    // before paying the cost of either.
    if let Cmd::Compile {
        input,
        out_cedar,
        out_engine_config,
    } = cli.cmd
    {
        return cmd_compile(input, out_cedar, out_engine_config);
    }

    let seed_hex = cli.seed.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "--seed / YUTHA_BOOTSTRAP_SEED is required for activate / grep / \
             revoke / print-operator-pubkey. (Only `compile` runs purely \
             locally without it.)"
        )
    })?;
    let seed = decode_seed(seed_hex)?;
    let identity = SeedIdentity::derive(&seed);

    // `print-operator-pubkey` needs the seed but no server connection.
    // Dispatch it before paying the channel-connect cost so it works
    // offline (the operator runs this before the server is up to feed
    // the result into `--operator-public-key`).
    if matches!(cli.cmd, Cmd::PrintOperatorPubkey) {
        return cmd_print_operator_pubkey(&identity);
    }

    let channel = Channel::from_shared(format!("http://{}", cli.addr))?
        .connect()
        .await
        .with_context(|| format!("connect to {}", cli.addr))?;

    match cli.cmd {
        Cmd::Activate {
            cedar_file,
            engine_config,
            version,
            schema_version,
        } => {
            cmd_activate(
                channel,
                &identity,
                cedar_file,
                engine_config,
                version,
                schema_version,
            )
            .await
        }
        Cmd::ActivateShadow {
            cedar_file,
            engine_config,
            version,
            schema_version,
        } => {
            cmd_activate_shadow(
                channel,
                &identity,
                cedar_file,
                engine_config,
                version,
                schema_version,
            )
            .await
        }
        Cmd::ClearShadow => cmd_clear_shadow(channel, &identity).await,
        Cmd::PromoteShadow => cmd_promote_shadow(channel, &identity).await,
        Cmd::ReplayCreate {
            cedar_file,
            engine_config,
            version,
            schema_version,
            from,
            to,
            action_kind_filter,
            mode,
            warm_lookback_hours,
        } => {
            cmd_replay_create(
                channel,
                &identity,
                cedar_file,
                engine_config,
                version,
                schema_version,
                from,
                to,
                action_kind_filter,
                mode,
                warm_lookback_hours,
            )
            .await
        }
        Cmd::ReplayRun { session_id } => cmd_replay_run(channel, &identity, session_id).await,
        Cmd::ReplayQuery {
            session_id,
            action_kind,
            limit,
        } => cmd_replay_query(channel, &identity, session_id, action_kind, limit).await,
        Cmd::ReplayClose { session_id } => cmd_replay_close(channel, &identity, session_id).await,
        Cmd::ReplayList => cmd_replay_list(channel, &identity).await,
        Cmd::Grep { action_kind, limit } => cmd_grep(channel, &identity, action_kind, limit).await,
        Cmd::Revoke {
            agent_id,
            reason,
            cascade,
        } => cmd_revoke(channel, &identity, agent_id, reason, cascade).await,
        Cmd::Compile { .. } | Cmd::PrintOperatorPubkey => {
            unreachable!("dispatched above")
        }
    }
}

/// Dump the operator public key (raw 32-byte Ed25519, hex-encoded) on
/// stdout. Suitable for `$(yutha-ops print-operator-pubkey)` substitution
/// inline with the server's `--operator-public-key` flag.
fn cmd_print_operator_pubkey(identity: &SeedIdentity) -> anyhow::Result<()> {
    let public_key = identity.operator_key.public();
    println!("{}", hex::encode(&public_key.value));
    Ok(())
}

fn cmd_compile(
    input: PathBuf,
    out_cedar: Option<PathBuf>,
    out_engine_config: Option<PathBuf>,
) -> anyhow::Result<()> {
    let src =
        std::fs::read_to_string(&input).with_context(|| format!("read DSL document {input:?}"))?;
    let dsl = compile::PlainEnglishConstitution::from_yaml(&src)
        .with_context(|| format!("parse DSL {input:?}"))?;
    let (cedar, engine_yaml) = dsl.compile()?;

    let cedar_path = out_cedar.unwrap_or_else(|| input.with_extension("cedar"));
    let engine_path = out_engine_config.unwrap_or_else(|| input.with_extension("engine.yaml"));
    std::fs::write(&cedar_path, &cedar)
        .with_context(|| format!("write cedar source {cedar_path:?}"))?;
    std::fs::write(&engine_path, &engine_yaml)
        .with_context(|| format!("write engine config {engine_path:?}"))?;

    println!("compiled:");
    println!("  cedar:         {}", cedar_path.display());
    println!("  engine config: {}", engine_path.display());
    println!(
        "\nNext: activate with the workload extension if your rules reference one, e.g.\n  \
         yutha-ops activate {cedar} --engine-config {engine}",
        cedar = cedar_path.display(),
        engine = engine_path.display(),
    );
    Ok(())
}

// =============================================================================
// Subcommand bodies
// =============================================================================

async fn cmd_activate(
    channel: Channel,
    identity: &SeedIdentity,
    cedar_file: PathBuf,
    engine_config: Option<PathBuf>,
    version: String,
    schema_version: String,
) -> anyhow::Result<()> {
    let cedar_source = std::fs::read_to_string(&cedar_file)
        .with_context(|| format!("read cedar source {cedar_file:?}"))?;
    let engine_config_yaml = match engine_config {
        Some(path) => std::fs::read_to_string(&path)
            .with_context(|| format!("read engine config {path:?}"))?,
        None => DEFAULT_EMPTY_ENGINE_CONFIG_YAML.to_string(),
    };

    let now = Timestamp::now();
    let constitution = Constitution {
        spec_version: Some((&SpecVersion::parse("1.0.0")?).into()),
        schema_version,
        constitution_version: version,
        parent_version: None, // CLI v1: genesis only; amendments come later.
        swarm_id: Some((&identity.swarm_id).into()),
        cedar_source,
        engine_config_yaml,
        issued_at: Some((&now).into()),
    };

    let token_hex = mint_operator_token(identity)?;
    let mut client = ConstitutionServiceClient::new(channel);
    let mut request = Request::new(ActivateConstitutionRequest {
        constitution: Some(constitution),
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("bearer operator {token_hex}"))?,
    );
    let response = client.activate(request).await?.into_inner();

    let constitution_hash = response
        .constitution_hash
        .as_ref()
        .map(|h| hex::encode(&h.digest))
        .unwrap_or_default();
    let activate_receipt = response
        .activate_receipt
        .as_ref()
        .map(|h| hex::encode(&h.digest))
        .unwrap_or_default();
    println!("activated:");
    println!("  constitution_hash: {constitution_hash}");
    println!("  activate_receipt:  {activate_receipt}");
    Ok(())
}

// ---- Phase 3b shadow-mode subcommand bodies (RFC 0018 §3.2) ----

async fn cmd_activate_shadow(
    channel: Channel,
    identity: &SeedIdentity,
    cedar_file: PathBuf,
    engine_config: Option<PathBuf>,
    version: String,
    schema_version: String,
) -> anyhow::Result<()> {
    let cedar_source = std::fs::read_to_string(&cedar_file)
        .with_context(|| format!("read cedar source {cedar_file:?}"))?;
    let engine_config_yaml = match engine_config {
        Some(path) => std::fs::read_to_string(&path)
            .with_context(|| format!("read engine config {path:?}"))?,
        None => DEFAULT_EMPTY_ENGINE_CONFIG_YAML.to_string(),
    };

    let now = Timestamp::now();
    let constitution = Constitution {
        spec_version: Some((&SpecVersion::parse("1.0.0")?).into()),
        schema_version,
        constitution_version: version,
        parent_version: None,
        swarm_id: Some((&identity.swarm_id).into()),
        cedar_source,
        engine_config_yaml,
        issued_at: Some((&now).into()),
    };

    let token_hex = mint_operator_token(identity)?;
    let mut client = ConstitutionServiceClient::new(channel);
    let mut request = Request::new(ActivateShadowConstitutionRequest {
        constitution: Some(constitution),
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("bearer operator {token_hex}"))?,
    );
    let response = client.activate_shadow(request).await?.into_inner();

    let shadow_constitution_hash = response
        .shadow_constitution_hash
        .as_ref()
        .map(|h| hex::encode(&h.digest))
        .unwrap_or_default();
    let shadow_activate_receipt = response
        .shadow_activate_receipt
        .as_ref()
        .map(|h| hex::encode(&h.digest))
        .unwrap_or_default();
    println!("shadow activated:");
    println!("  shadow_constitution_hash: {shadow_constitution_hash}");
    println!("  shadow_activate_receipt:  {shadow_activate_receipt}");
    println!();
    println!("Watch divergence with:");
    println!("  yutha-ops grep constitution.evaluate.shadow.deny");
    println!("  yutha-ops grep constitution.evaluate.shadow.pass");
    println!("Promote when satisfied:");
    println!("  yutha-ops promote-shadow");
    Ok(())
}

async fn cmd_clear_shadow(channel: Channel, identity: &SeedIdentity) -> anyhow::Result<()> {
    let token_hex = mint_operator_token(identity)?;
    let mut client = ConstitutionServiceClient::new(channel);
    let mut request = Request::new(ClearShadowConstitutionRequest {});
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("bearer operator {token_hex}"))?,
    );
    let response = client.clear_shadow(request).await?.into_inner();

    let shadow_clear_receipt = response
        .shadow_clear_receipt
        .as_ref()
        .map(|h| hex::encode(&h.digest))
        .unwrap_or_default();
    let previously_shadowed = response
        .previously_shadowed_constitution_hash
        .as_ref()
        .map(|h| hex::encode(&h.digest));
    println!("shadow cleared:");
    println!("  shadow_clear_receipt: {shadow_clear_receipt}");
    match previously_shadowed {
        Some(hash) => println!("  previously_shadowed:  {hash}"),
        None => println!("  previously_shadowed:  (slot was empty)"),
    }
    Ok(())
}

async fn cmd_promote_shadow(channel: Channel, identity: &SeedIdentity) -> anyhow::Result<()> {
    let token_hex = mint_operator_token(identity)?;
    let mut client = ConstitutionServiceClient::new(channel);
    let mut request = Request::new(PromoteShadowConstitutionRequest {});
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("bearer operator {token_hex}"))?,
    );
    // FAILED_PRECONDITION surfaces as a tonic Status error here — the
    // `?` propagation gives the operator a clear server-side message
    // ("no shadow constitution to promote; call ActivateShadow
    // first") without any client-side translation.
    let response = client.promote_shadow(request).await?.into_inner();

    let to_active = response
        .to_active_constitution_hash
        .as_ref()
        .map(|h| hex::encode(&h.digest))
        .unwrap_or_default();
    let shadow_promote_receipt = response
        .shadow_promote_receipt
        .as_ref()
        .map(|h| hex::encode(&h.digest))
        .unwrap_or_default();
    let from_active = response
        .from_active_constitution_hash
        .as_ref()
        .map(|h| hex::encode(&h.digest));
    println!("shadow promoted:");
    println!("  to_active_constitution_hash: {to_active}");
    println!("  shadow_promote_receipt:      {shadow_promote_receipt}");
    match from_active {
        Some(hash) => println!("  from_active_constitution_hash: {hash}"),
        None => println!("  from_active_constitution_hash: (no active was loaded)"),
    }
    Ok(())
}

// ---- Phase 3c replay subcommand bodies (RFC 0018 §4) ----

#[allow(clippy::too_many_arguments)]
async fn cmd_replay_create(
    channel: Channel,
    identity: &SeedIdentity,
    cedar_file: PathBuf,
    engine_config: Option<PathBuf>,
    version: String,
    schema_version: String,
    from: u64,
    to: u64,
    action_kind_filter: Vec<String>,
    mode: String,
    warm_lookback_hours: u32,
) -> anyhow::Result<()> {
    let cedar_source = std::fs::read_to_string(&cedar_file)
        .with_context(|| format!("read cedar source {cedar_file:?}"))?;
    let engine_config_yaml = match engine_config {
        Some(path) => std::fs::read_to_string(&path)
            .with_context(|| format!("read engine config {path:?}"))?,
        None => DEFAULT_EMPTY_ENGINE_CONFIG_YAML.to_string(),
    };

    let now = Timestamp::now();
    let candidate = Constitution {
        spec_version: Some((&SpecVersion::parse("1.0.0")?).into()),
        schema_version,
        constitution_version: version,
        parent_version: None,
        swarm_id: Some((&identity.swarm_id).into()),
        cedar_source,
        engine_config_yaml,
        issued_at: Some((&now).into()),
    };

    let mode_enum = match mode.as_str() {
        "cold" => ProtoReplayMode::Cold,
        "warm" => ProtoReplayMode::Warm,
        other => anyhow::bail!("--mode must be `cold` or `warm` (got `{other}`)"),
    };

    let token_hex = mint_operator_token(identity)?;
    let mut client = ReplayServiceClient::new(channel);
    let mut request = Request::new(CreateReplaySessionRequest {
        candidate: Some(candidate),
        window: Some(ReplaySessionWindow {
            from_unix_ns: from,
            to_unix_ns: to,
            action_kind_filter,
        }),
        mode: mode_enum.into(),
        warm_lookback_hours,
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("bearer operator {token_hex}"))?,
    );
    let response = client.create_session(request).await?.into_inner();

    let session_create_receipt = response
        .session_create_receipt
        .as_ref()
        .map(|h| hex::encode(&h.digest))
        .unwrap_or_default();
    println!("replay session created:");
    println!("  replay_session_id:      {}", response.replay_session_id);
    println!("  session_create_receipt: {session_create_receipt}");
    println!();
    println!("Next:");
    println!(
        "  yutha-ops replay-run --session-id {}",
        response.replay_session_id
    );
    Ok(())
}

async fn cmd_replay_run(
    channel: Channel,
    identity: &SeedIdentity,
    session_id: String,
) -> anyhow::Result<()> {
    let token_hex = mint_operator_token(identity)?;
    let mut client = ReplayServiceClient::new(channel);
    let mut request = Request::new(RunReplaySessionRequest {
        replay_session_id: session_id.clone(),
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("bearer operator {token_hex}"))?,
    );
    let mut stream = client.run_session(request).await?.into_inner();

    println!("streaming replay progress (session {session_id}):");
    while let Some(progress) = stream.message().await? {
        let latest = progress
            .latest_replay_receipt_id
            .as_ref()
            .map(|h| hex::encode(&h.digest))
            .unwrap_or_else(|| "-".to_string());
        if progress.window_complete {
            println!(
                "  [DONE] replayed={} progress_unix_ns={} (window complete)",
                progress.receipts_replayed, progress.progress_unix_ns
            );
        } else {
            println!(
                "  replayed={} progress_unix_ns={} latest_receipt={}",
                progress.receipts_replayed, progress.progress_unix_ns, latest
            );
        }
    }
    Ok(())
}

async fn cmd_replay_query(
    channel: Channel,
    identity: &SeedIdentity,
    session_id: String,
    action_kind: String,
    limit: u32,
) -> anyhow::Result<()> {
    let token_hex = mint_operator_token(identity)?;
    let mut client = ReplayServiceClient::new(channel);
    let inner = QueryRequest {
        by: Some(yutha_proto::receipt::v1::query_request::By::ByActionKind(
            ActionKindQuery {
                action_kind: action_kind.clone(),
            },
        )),
        limit,
        page_token: Vec::new(),
    };
    let mut request = Request::new(QueryReplayReceiptsRequest {
        replay_session_id: session_id.clone(),
        query: Some(inner),
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("bearer operator {token_hex}"))?,
    );
    let response = client.query_replay_receipts(request).await?.into_inner();

    if response.receipts.is_empty() {
        println!("no replay receipts in session {session_id} matching action_kind {action_kind:?}");
        return Ok(());
    }
    for r in &response.receipts {
        let occurred_at = r
            .occurred_at
            .as_ref()
            .map(|t| t.wall_clock.as_str())
            .unwrap_or("?");
        let actor = r
            .actor
            .as_ref()
            .map(|a| format_agent_id(&a.value))
            .unwrap_or_else(|| "?".into());
        println!(
            "[{occurred_at}] {action_kind} actor={actor} evidence={evidence_count}",
            evidence_count = r.evidence.len()
        );
    }
    println!(
        "---\n{} session-scoped receipt(s) shown.",
        response.receipts.len()
    );
    Ok(())
}

async fn cmd_replay_close(
    channel: Channel,
    identity: &SeedIdentity,
    session_id: String,
) -> anyhow::Result<()> {
    let token_hex = mint_operator_token(identity)?;
    let mut client = ReplayServiceClient::new(channel);
    let mut request = Request::new(CloseReplaySessionRequest {
        replay_session_id: session_id.clone(),
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("bearer operator {token_hex}"))?,
    );
    let response = client.close_session(request).await?.into_inner();

    let session_close_receipt = response
        .session_close_receipt
        .as_ref()
        .map(|h| hex::encode(&h.digest))
        .unwrap_or_default();
    println!("replay session closed:");
    println!("  session_close_receipt:   {session_close_receipt}");
    println!(
        "  receipts_replayed_total: {}",
        response.receipts_replayed_total
    );
    Ok(())
}

async fn cmd_replay_list(channel: Channel, identity: &SeedIdentity) -> anyhow::Result<()> {
    let token_hex = mint_operator_token(identity)?;
    let mut client = ReplayServiceClient::new(channel);
    let mut request = Request::new(ListReplaySessionsRequest {});
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("bearer operator {token_hex}"))?,
    );
    let response = client.list_sessions(request).await?.into_inner();

    if response.sessions.is_empty() {
        println!("no active replay sessions.");
        return Ok(());
    }
    for s in &response.sessions {
        let mode_str = match ProtoReplayMode::try_from(s.mode).unwrap_or(ProtoReplayMode::Cold) {
            ProtoReplayMode::Cold => "cold",
            ProtoReplayMode::Warm => "warm",
        };
        let candidate_hash = s
            .candidate_constitution_hash
            .as_ref()
            .map(|h| hex::encode(&h.digest))
            .unwrap_or_default();
        let window = s.window.as_ref();
        let from = window.map(|w| w.from_unix_ns).unwrap_or(0);
        let to = window.map(|w| w.to_unix_ns).unwrap_or(0);
        let filter = window
            .map(|w| w.action_kind_filter.join(","))
            .unwrap_or_default();
        println!("session {}", s.replay_session_id);
        println!(
            "  candidate: {} (v{})",
            candidate_hash, s.candidate_constitution_version
        );
        println!("  window:    [{from}, {to}] mode={mode_str} filter=[{filter}]");
        println!("  replayed:  {}", s.receipts_replayed);
    }
    println!("---\n{} active replay session(s).", response.sessions.len());
    Ok(())
}

async fn cmd_grep(
    channel: Channel,
    identity: &SeedIdentity,
    action_kind: String,
    limit: u32,
) -> anyhow::Result<()> {
    let token_hex = mint_agent_token(identity)?;
    let mut client = ReceiptServiceClient::new(channel);
    let inner = QueryRequest {
        // The proto declares `oneof by { ... ByActionKind by_action_kind = 4; ... }`
        // — prost names the oneof enum `By` (capitalized from the
        // oneof name) and the field `by`.
        by: Some(yutha_proto::receipt::v1::query_request::By::ByActionKind(
            ActionKindQuery {
                action_kind: action_kind.clone(),
            },
        )),
        limit,
        page_token: Vec::new(),
    };
    let mut request = Request::new(QueryReceiptsRequest { query: Some(inner) });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("bearer agent {token_hex}"))?,
    );
    let response = client.query(request).await?.into_inner();

    if response.receipts.is_empty() {
        println!("no receipts matching action_kind {action_kind:?}");
        return Ok(());
    }
    for r in &response.receipts {
        let occurred_at = r
            .occurred_at
            .as_ref()
            .map(|t| t.wall_clock.as_str())
            .unwrap_or("?");
        let actor = r
            .actor
            .as_ref()
            .map(|a| format_agent_id(&a.value))
            .unwrap_or_else(|| "?".into());
        println!(
            "[{occurred_at}] {action_kind} actor={actor} evidence={evidence_count}",
            evidence_count = r.evidence.len()
        );
    }
    println!("---\n{} receipt(s) shown.", response.receipts.len());
    Ok(())
}

async fn cmd_revoke(
    channel: Channel,
    identity: &SeedIdentity,
    agent_id_str: String,
    reason: String,
    cascade: bool,
) -> anyhow::Result<()> {
    let target = parse_agent_id(&agent_id_str)
        .with_context(|| format!("--agent-id {agent_id_str:?} is not a UUID v7"))?;
    let token_hex = mint_operator_token(identity)?;
    let mut client = AdmissionServiceClient::new(channel);
    let mut request = Request::new(OperatorRevokeRequest {
        target: Some((&target).into()),
        reason,
        cascade_capabilities: cascade,
    });
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("bearer operator {token_hex}"))?,
    );
    let response = client.operator_revoke(request).await?.into_inner();

    let revocation_receipt = response
        .revocation_receipt
        .as_ref()
        .map(|h| hex::encode(&h.digest))
        .unwrap_or_default();
    println!("revoked {target}:");
    println!("  revocation_receipt: {revocation_receipt}");
    if cascade {
        println!("  cascade_receipts:   {}", response.cascade_receipts.len());
        for h in &response.cascade_receipts {
            println!("    - {}", hex::encode(&h.digest));
        }
    }
    Ok(())
}

// =============================================================================
// Seed-based identity derivation. Mirrors the control-plane binary's
// `BootstrapIdentity::from_seed_hex` so the same seed used to start
// the server lights up here too.
// =============================================================================

struct SeedIdentity {
    agent_id: AgentId,
    swarm_id: SwarmId,
    agent_key: SigningKey,
    operator_key: SigningKey,
}

impl SeedIdentity {
    fn derive(seed: &[u8; 32]) -> Self {
        let agent_id_bytes = sha256_with_tag(seed, 0x01);
        let swarm_id_bytes = sha256_with_tag(seed, 0x02);
        let operator_seed = sha256_with_tag(seed, 0x03);
        SeedIdentity {
            agent_id: AgentId::from_bytes(&agent_id_bytes[..16]).expect("16-byte agent id"),
            swarm_id: SwarmId::from_bytes(&swarm_id_bytes[..16]).expect("16-byte swarm id"),
            agent_key: SigningKey::from_bytes(seed),
            operator_key: SigningKey::from_bytes(&operator_seed),
        }
    }
}

fn sha256_with_tag(seed: &[u8; 32], tag: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update([tag]);
    hasher.finalize().into()
}

fn decode_seed(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).context("--seed: hex decode")?;
    if bytes.len() != 32 {
        bail!(
            "--seed: expected 32 raw bytes (64 hex chars), got {}",
            bytes.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// =============================================================================
// Bearer-token minting. Builds the proto, prost-encodes with signature
// cleared (canonical bytes), signs, re-encodes with signature attached,
// hex-encodes for the wire.
// =============================================================================

fn mint_agent_token(identity: &SeedIdentity) -> anyhow::Result<String> {
    let now = Timestamp::now();
    let expires = expire_after(&now, 300);
    let mut token = AgentBearerToken {
        agent_id: Some((&identity.agent_id).into()),
        swarm_id: Some((&identity.swarm_id).into()),
        issued_at: Some((&now).into()),
        expires_at: Some((&expires).into()),
        nonce: random_nonce(),
        extensions: None,
        signature: None,
    };
    let canonical = token.encode_to_vec();
    let sig = identity.agent_key.sign_message(&canonical);
    token.signature = Some((&sig).into());
    Ok(hex::encode(token.encode_to_vec()))
}

fn mint_operator_token(identity: &SeedIdentity) -> anyhow::Result<String> {
    let now = Timestamp::now();
    let expires = expire_after(&now, 300);
    let mut token = OperatorBearerToken {
        operator_id: "yutha-ops".into(),
        swarm_id: Some((&identity.swarm_id).into()),
        issued_at: Some((&now).into()),
        expires_at: Some((&expires).into()),
        nonce: random_nonce(),
        extensions: None,
        signature: None,
    };
    let canonical = token.encode_to_vec();
    let sig = identity.operator_key.sign_message(&canonical);
    token.signature = Some((&sig).into());
    Ok(hex::encode(token.encode_to_vec()))
}

fn expire_after(now: &Timestamp, seconds: u64) -> Timestamp {
    // Wall-clock: parse + add seconds + re-render with the Z suffix
    // the rest of the substrate expects. Falls back to a hardcoded
    // future string if parsing somehow fails — defensive, the
    // server tolerates non-standard wall_clock as long as
    // monotonic_ns advances.
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    let advanced_wall = OffsetDateTime::parse(&now.wall_clock, &Rfc3339)
        .ok()
        .map(|t| t + time::Duration::seconds(seconds as i64))
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_else(|| "2099-01-01T00:00:00Z".to_string());
    Timestamp::new(advanced_wall, now.monotonic_ns + seconds * 1_000_000_000)
        .expect("valid RFC 3339")
}

fn random_nonce() -> Vec<u8> {
    // 16 bytes of unique-ish entropy. We use SystemTime + a counter
    // because the CLI does one token per invocation; no need for
    // a CSPRNG.
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut out = vec![0u8; 16];
    out[..16].copy_from_slice(&now_ns.to_le_bytes()[..16]);
    out
}

// =============================================================================
// AgentId formatting / parsing — mirrors the substrate's Display impl
// (UUIDv7 with hyphens).
// =============================================================================

fn format_agent_id(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return hex::encode(bytes);
    }
    format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&bytes[0..4]),
        hex::encode(&bytes[4..6]),
        hex::encode(&bytes[6..8]),
        hex::encode(&bytes[8..10]),
        hex::encode(&bytes[10..16]),
    )
}

fn parse_agent_id(s: &str) -> anyhow::Result<AgentId> {
    let cleaned: String = s.chars().filter(|c| *c != '-').collect();
    let bytes = hex::decode(cleaned).context("agent_id hex")?;
    AgentId::from_bytes(&bytes).context("agent_id must be 16 bytes")
}

// =============================================================================
// Defaults / helpers
// =============================================================================

const DEFAULT_EMPTY_ENGINE_CONFIG_YAML: &str = "schema_version: \"1.1.0\"\n\
predicates: []\n\
scoring_rules: []\n\
procedures: []\n\
enforcement_rules: []\n";

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, FmtSubscriber};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let subscriber = FmtSubscriber::builder().with_env_filter(filter).finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

// Trait impl glue: tonic's Channel needs a stringified address;
// AgentId / Timestamp / etc. need to land in their proto forms via the
// existing `From<&T>` impls in yutha-core / yutha-proto's conv layer.
// All of those impls live elsewhere; this file just composes them.

// Suppress an unused-import warning when the `From<&Timestamp>` for
// common::Timestamp impl isn't directly referenced (it's used
// implicitly via .into() on the token-build call sites).
#[allow(dead_code)]
fn _force_common_use(_: common::AgentId) {}

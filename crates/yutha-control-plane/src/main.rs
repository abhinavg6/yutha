//! Yutha control-plane binary. Skeleton wire-up of in-memory backends.
//!
//! What this binary proves: the substrate types compose. Receipt store +
//! passport store + capability store + transport + registry can be brought
//! up together, the resolver adapter bridges passport into receipt, the
//! closed-mode admission policy admits a known agent end-to-end, and the
//! admission produces an `agent.register` receipt signed by the control
//! plane and verified through the resolver.
//!
//! What it does NOT do yet: open a network port, parse a config file, or
//! run any constitution-engine work. Those land as their respective
//! workstreams mature.

#![forbid(unsafe_code)]

use std::sync::Arc;

use anyhow::Context;
use tracing::{info, warn};
use yutha_capability::{CapabilityStore, MemoryCapabilityStore};
use yutha_core::{AgentId, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::sign::generate_keypair;
use yutha_passport::{
    MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore, PassportTier,
};
use yutha_receipt::{
    ActionKindQuery, MemoryStore as MemoryReceiptStore, PassportResolver, Query, ReceiptStore,
};
use yutha_registry::{
    AdmissionPolicy, ClosedPolicy, ControlPlaneIdentity, MemoryRegistry, Registry, Topology,
    TopologyMode,
};
use yutha_transport::{MemoryTransport, Transport};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    info!("yutha control-plane starting up");

    let swarm_id = SwarmId::new();

    // -------------------------------------------------------------------
    // Receipt store, passport store, resolver. These three are wired
    // first because the cp identity needs to be persistable into the
    // passport store, and transport / capability stores need all three
    // plus the cp identity at construction time.
    // -------------------------------------------------------------------
    let receipt_store: Arc<dyn ReceiptStore> = Arc::new(MemoryReceiptStore::new());
    let passport_store: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
    let resolver: Arc<dyn PassportResolver> =
        Arc::new(PassportResolverAdapter::new(Arc::clone(&passport_store)));
    info!("resolver adapter wired (passport → receipt)");

    // -------------------------------------------------------------------
    // Control-plane identity: fresh keypair, register its own passport so
    // the resolver knows the cp's key when verifying admission receipts.
    // -------------------------------------------------------------------
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

    // Now build transport + capability store with the cp identity.
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

    // -------------------------------------------------------------------
    // Bootstrap agent (a regular swarm participant) — what the rest of the
    // demo admits.
    // -------------------------------------------------------------------
    let bootstrap_key = generate_keypair();
    let bootstrap_agent_id = AgentId::new();
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
        .sign(&bootstrap_key)
        .map_err(|e| anyhow::anyhow!("build bootstrap passport: {e}"))?;
    info!(
        bootstrap_agent_id = %bootstrap_agent_id,
        "constructed bootstrap passport"
    );

    // -------------------------------------------------------------------
    // Topology + registry. Closed mode with the bootstrap agent allowlisted.
    // -------------------------------------------------------------------
    let admission = AdmissionPolicy::Closed(ClosedPolicy {
        allowlisted_agents: vec![bootstrap_agent_id],
        ..Default::default()
    });
    let topology = Topology {
        spec_version: SpecVersion::parse("1.0.0").context("parse spec version")?,
        swarm_id,
        mode: TopologyMode::Closed,
        admission,
        max_capability_lifetime_seconds: 90 * 24 * 60 * 60,
        max_capability_chain_depth: 8,
        default_envelope_ttl_seconds: 300,
        max_epoch_skew: 256,
        external_sends_permitted: false,
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
    info!(swarm_id = %swarm_id, "registry constructed in CLOSED mode");

    // -------------------------------------------------------------------
    // Register the bootstrap agent end-to-end. Exercise admission +
    // admission receipt.
    // -------------------------------------------------------------------
    let outcome = registry.register(bootstrap_passport).await?;
    info!(
        status = ?outcome.status,
        agent_id = %outcome.agent_id,
        receipt = ?outcome.registration_receipt.as_ref().map(|h| h.to_hex()),
        "bootstrap agent registered with receipt"
    );

    // Cross-check: the resolver sees the registered agent.
    match resolver.resolve_actor(&bootstrap_agent_id).await {
        Ok(Some(_pk)) => info!("resolver sees bootstrap agent ✓"),
        Ok(None) => warn!("resolver could not see bootstrap agent (unexpected)"),
        Err(e) => warn!(error = %e, "resolver error (unexpected)"),
    }

    // Show the audit trail.
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

    let _ = capability_store; // exercised by tests; held for future wire-up.
    let _ = transport;

    info!(
        "yutha control-plane is up. Press Ctrl-C to exit. \
         No network listener yet; transport is in-memory."
    );

    tokio::signal::ctrl_c()
        .await
        .context("install Ctrl-C handler")?;
    info!("shutting down");
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, FmtSubscriber};
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,yutha=debug"));
    let subscriber = FmtSubscriber::builder().with_env_filter(filter).finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

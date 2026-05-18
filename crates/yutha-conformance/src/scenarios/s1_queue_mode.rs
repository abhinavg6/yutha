//! Behavioral scenario **S1: customer-support queue mode** (Phase 1 anchor).
//!
//! Per [`/docs/conformance/conformance-suite.md`](../../../../docs/conformance/conformance-suite.md) §4 S1
//! and [PRD §8.5](../../../../docs/Concord_PRD.docx).
//!
//! What this Phase 1 implementation covers:
//! - 5 agents registered, sourced from 2 different framework strings.
//! - Each registration produces an `agent.register` receipt.
//! - 4 envelopes round-trip via the in-memory transport. Each one produces
//!   an `envelope.send` + `envelope.deliver` pair.
//! - One capability is issued; one `check.pass` receipt is produced.
//! - One agent is revoked; an `agent.revoke` receipt is produced.
//! - Every receipt is signed by the control plane and verified through the
//!   resolver. The audit trail is queryable end-to-end.
//!
//! What it does **not** cover yet (lands when the relevant workstreams ship):
//! - Constitution norms over PII (Phase 2).
//! - Four-stage enforcement (Phase 2).
//! - Supervisor-approval receipts via two-person rule (Phase 2).

use std::sync::Arc;
use yutha_capability::{
    ActionDescriptor, AlwaysAllowed, Capability, CapabilityStore, Issuer, MemoryCapabilityStore,
    Scope,
};
use yutha_core::{AgentId, CausalRef, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::sign::generate_keypair;
use yutha_passport::{
    ControlPlaneIdentity, MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore,
    PassportTier,
};
use yutha_receipt::{
    ActionKindQuery, MemoryStore as MemoryReceiptStore, PassportResolver, Query, ReceiptStore,
};
use yutha_registry::{
    AdmissionPolicy, ClosedPolicy, MemoryRegistry, Registry, Topology, TopologyMode,
};
use yutha_transport::{Envelope, MemoryTransport, Performative, Recipient, Transport};

/// What a successful S1 run reports. Counts in this struct align to what
/// the test assertion checks.
#[derive(Debug, Clone)]
pub struct S1Outcome {
    /// Agents successfully registered.
    pub agents_registered: u64,
    /// `agent.register` receipts.
    pub register_receipts: u64,
    /// Envelopes round-tripped.
    pub envelopes_delivered: u64,
    /// `envelope.send` receipts.
    pub envelope_send_receipts: u64,
    /// `envelope.deliver` receipts.
    pub envelope_deliver_receipts: u64,
    /// `capability.check.pass` receipts.
    pub check_pass_receipts: u64,
    /// `agent.revoke` receipts.
    pub revoke_receipts: u64,
    /// All receipts in the audit store.
    pub total_receipts: u64,
}

struct SupportAgent {
    name: &'static str,
    framework: &'static str,
    agent_id: AgentId,
    key: yutha_crypto::SigningKey,
}

/// Run the S1 scenario end-to-end.
pub async fn run_s1() -> S1Outcome {
    let swarm_id = SwarmId::new();
    let receipts: Arc<dyn ReceiptStore> = Arc::new(MemoryReceiptStore::new());
    let passports: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
    let resolver: Arc<dyn PassportResolver> =
        Arc::new(PassportResolverAdapter::new(Arc::clone(&passports)));

    // Control plane bootstrap.
    let cp_key = generate_keypair();
    let cp_agent_id = AgentId::new();
    let cp_passport = signed_passport(
        swarm_id,
        cp_agent_id,
        &cp_key,
        "framework_a",
        "control plane",
    );
    passports.register(cp_passport).await.unwrap();
    let cp = Arc::new(ControlPlaneIdentity::new(cp_agent_id, cp_key));

    // Wire the substrate stack with the cp identity.
    let transport = Arc::new(MemoryTransport::new(
        Arc::clone(&receipts),
        Arc::clone(&resolver),
        Arc::clone(&cp),
    ));
    let capability_store = Arc::new(MemoryCapabilityStore::new(
        Arc::clone(&receipts),
        Arc::clone(&resolver),
        Arc::clone(&cp),
        // S1 doesn't exercise the enforcement loop — every agent is
        // assumed in good standing for the duration of the scenario.
        // S4 (Phase 2) will add the enforcement-driven variant.
        Arc::new(AlwaysAllowed),
    ));

    // Five support-swarm agents.
    let agents: Vec<SupportAgent> = vec![
        ("router", "framework_a"),
        ("billing", "framework_a"),
        ("shipping", "framework_a"),
        ("returns", "framework_b"),
        ("supervisor", "framework_b"),
    ]
    .into_iter()
    .map(|(name, framework)| {
        let key = generate_keypair();
        SupportAgent {
            name,
            framework,
            agent_id: AgentId::new(),
            key,
        }
    })
    .collect();

    let topology = Topology {
        spec_version: SpecVersion::parse("1.0.0").unwrap(),
        swarm_id,
        mode: TopologyMode::Closed,
        admission: AdmissionPolicy::Closed(ClosedPolicy {
            allowlisted_agents: agents.iter().map(|a| a.agent_id).collect(),
            ..Default::default()
        }),
        max_capability_lifetime_seconds: 90 * 24 * 60 * 60,
        max_capability_chain_depth: 8,
        default_envelope_ttl_seconds: 300,
        max_epoch_skew: 256,
        external_sends_permitted: false,
        // S1 is in-process — the gRPC Send-path cap-check (RFC 0007)
        // doesn't apply to MemoryTransport calls. Keep false so the
        // scenario's audit shape doesn't change.
        require_capability_for_send: false,
        initial_constitution_version: "1.0.0".into(),
        operator_key_fingerprint: vec![0u8; 32],
        operator_signature: None,
    };
    let registry: Arc<dyn Registry> = Arc::new(
        MemoryRegistry::new(
            topology,
            Arc::clone(&passports),
            Arc::clone(&receipts),
            Arc::clone(&resolver),
            Arc::clone(&cp),
        )
        .expect("registry construction"),
    );

    // Register each agent.
    let mut agents_registered = 0u64;
    for agent in &agents {
        let passport = signed_passport(
            swarm_id,
            agent.agent_id,
            &agent.key,
            agent.framework,
            agent.name,
        );
        let outcome = registry
            .register(passport)
            .await
            .unwrap_or_else(|e| panic!("registration failed for {}: {e}", agent.name));
        assert!(outcome.is_accepted(), "{} not accepted", agent.name);
        assert!(
            outcome.registration_receipt.is_some(),
            "{} produced no registration receipt",
            agent.name
        );
        transport.register_recipient(agent.agent_id).await;
        agents_registered += 1;
    }

    // Send 4 envelopes: router → 3 handlers, returns → supervisor.
    let router = &agents[0];
    let supervisor = &agents[4];
    let mut envelopes_delivered = 0u64;
    let mut nonce_seed: u8 = 1;

    for (i, handler) in agents[1..4].iter().enumerate() {
        let env = build_envelope(
            swarm_id,
            router,
            Recipient::Agent(handler.agent_id),
            Performative::RequestAction,
            &format!("ticket-{i}"),
            CausalRef::empty(),
            &mut nonce_seed,
            (i as u64) + 1,
        );
        transport.send(env).await.expect("send to handler");
        let delivered = transport
            .receive(&handler.agent_id)
            .await
            .expect("receive at handler");
        delivered
            .verify_signature(&router.key.public())
            .expect("envelope signature verifies");
        envelopes_delivered += 1;
    }
    {
        let returns = &agents[3];
        let env = build_envelope(
            swarm_id,
            returns,
            Recipient::Agent(supervisor.agent_id),
            Performative::RequestAction,
            "escalation",
            CausalRef::empty(),
            &mut nonce_seed,
            10,
        );
        transport.send(env).await.expect("send escalation");
        let _ = transport
            .receive(&supervisor.agent_id)
            .await
            .expect("supervisor receives escalation");
        envelopes_delivered += 1;
    }

    // Issue a capability to the router and exercise check.pass.
    let key = generate_keypair();
    let capability = Capability::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .capability_id(vec![1u8; 16])
        .swarm_id(swarm_id)
        .issuer(Issuer::Operator(vec![0u8; 32]))
        .subject(router.agent_id)
        .scope(Scope::for_action("send_message"))
        .valid_from(Timestamp::now())
        .valid_until(Timestamp::new("2099-01-01T00:00:00Z".into(), u64::MAX / 2).unwrap())
        .sign(&key)
        .unwrap();
    let issued = capability_store.issue(capability).await.unwrap();
    let evaluation = capability_store
        .check(
            &issued.capability_id,
            &ActionDescriptor {
                action_kind: "send_message".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(evaluation.outcome.permitted);

    // Revoke one agent (the returns role).
    let returns_id = agents[3].agent_id;
    registry
        .revoke(&returns_id, "scenario cleanup")
        .await
        .unwrap();

    // Audit.
    let register_receipts = count_action(&receipts, "agent.register").await;
    let envelope_send_receipts = count_action(&receipts, "envelope.send").await;
    let envelope_deliver_receipts = count_action(&receipts, "envelope.deliver").await;
    let check_pass_receipts = count_action(&receipts, "capability.check.pass").await;
    let revoke_receipts = count_action(&receipts, "agent.revoke").await;
    let total_receipts = receipts.count().await.unwrap();

    S1Outcome {
        agents_registered,
        register_receipts,
        envelopes_delivered,
        envelope_send_receipts,
        envelope_deliver_receipts,
        check_pass_receipts,
        revoke_receipts,
        total_receipts,
    }
}

async fn count_action(receipts: &Arc<dyn ReceiptStore>, kind: &str) -> u64 {
    let page = receipts
        .query(
            Query::ByActionKind(ActionKindQuery {
                action_kind: kind.into(),
            }),
            None,
        )
        .await
        .expect("query");
    page.receipts.len() as u64
}

fn signed_passport(
    swarm_id: SwarmId,
    agent_id: AgentId,
    key: &yutha_crypto::SigningKey,
    framework: &str,
    owner: &str,
) -> Passport {
    Passport::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .agent_id(agent_id)
        .swarm_id(swarm_id)
        .agent_public_key(key.public())
        .owner(owner)
        .framework(framework, "1.0.0")
        .accepted_constitution_version("1.0.0")
        .tier(PassportTier::Minimal)
        .issued_at(Timestamp::now())
        .sign(key)
        .expect("sign passport")
}

#[allow(clippy::too_many_arguments)]
fn build_envelope(
    swarm_id: SwarmId,
    sender: &SupportAgent,
    recipient: Recipient,
    performative: Performative,
    payload_text: &str,
    causal: CausalRef,
    nonce_seed: &mut u8,
    epoch: u64,
) -> Envelope {
    *nonce_seed = nonce_seed.wrapping_add(1);
    let nonce = vec![*nonce_seed; 16];
    Envelope::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .swarm_id(swarm_id)
        .envelope_id(vec![*nonce_seed; 16])
        .from_agent(sender.agent_id)
        .recipient(recipient)
        .performative(performative)
        .payload(payload_text.as_bytes().to_vec())
        .payload_schema_id("type.yutha.dev/v1/Text")
        .causal(causal)
        .nonce(nonce)
        .epoch(epoch)
        .sent_at(Timestamp::now())
        .sign(&sender.key)
        .expect("sign envelope")
}

#[cfg(test)]
#[cfg(feature = "in-memory-scenarios")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn s1_queue_mode_runs_end_to_end() {
        let outcome = run_s1().await;
        // 5 registrations, 4 envelope round-trips, 1 capability issuance
        // + 1 capability check, 1 revocation.
        assert_eq!(outcome.agents_registered, 5);
        assert_eq!(outcome.register_receipts, 5);
        assert_eq!(outcome.envelopes_delivered, 4);
        assert_eq!(outcome.envelope_send_receipts, 4);
        assert_eq!(outcome.envelope_deliver_receipts, 4);
        assert_eq!(outcome.check_pass_receipts, 1);
        assert_eq!(outcome.revoke_receipts, 1);
        // 5 register + 4 send + 4 deliver + 1 capability.issue (D-2d) +
        // 1 check.pass + 1 revoke = 16.
        assert_eq!(outcome.total_receipts, 16);
    }
}

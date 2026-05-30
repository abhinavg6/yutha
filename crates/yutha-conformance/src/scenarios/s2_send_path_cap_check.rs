//! Behavioral scenario **S2: Send-path capability enforcement** (RFC 0007).
//!
//! Locks in the substrate semantics that back the gRPC
//! [`EnvelopeService.Send`](../../../../crates/yutha-control-plane/src/grpc/envelope.rs)
//! handler's cap-check branch: a Send presenting a `capability_id`
//! resolves through [`CapabilityStore::check`], the resulting
//! `capability.check.{pass,deny}` receipt lands in the audit log, and
//! deny suppresses the send. The scenario is purely in-process — the
//! gRPC layer is exercised by the Python integration tests at
//! `sdks/python/tests/test_*` — but the descriptor it builds is
//! byte-equivalent to what the gRPC handler synthesizes from the
//! envelope (`action_kind = "envelope.send"`, `recipient` rendered to
//! the stable string form, `resource_tags = envelope.tags`).
//!
//! Coverage:
//! 1. **Positive.** Cap with scope permitting `envelope.send` is
//!    issued; check passes; envelope.send + deliver receipts land.
//! 2. **Revocation.** The cap is revoked; the same descriptor is
//!    re-checked; check denies with reason "capability revoked in
//!    chain"; no envelope round-trip happens in the gated branch.
//! 3. **Out-of-scope.** A second cap with scope permitting a
//!    different action is issued; checking it against
//!    `envelope.send` denies on scope intersection.

use std::sync::Arc;
use yutha_capability::{
    ActionDescriptor, AlwaysAllowed, Capability, CapabilityStore, Issuer, MemoryCapabilityStore,
    Scope,
};
use yutha_core::{AgentId, CausalRef, SpecVersion, SwarmId, Timestamp};
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
use yutha_signer::{InProcessSigner, Signer};
use yutha_transport::{Envelope, MemoryTransport, Performative, Recipient, Transport};

/// Receipt-count shape produced by a clean S2 run. The conformance
/// test below asserts equality against fixed expectations.
#[derive(Debug, Clone)]
pub struct S2Outcome {
    /// Agents successfully registered (alice + bob; expect 2).
    pub agents_registered: u64,
    /// `agent.register` receipts in the audit log.
    pub register_receipts: u64,
    /// `capability.issue` receipts (one per cap minted; expect 2 —
    /// the send-permitting cap and the out-of-scope one).
    pub capability_issue_receipts: u64,
    /// `capability.check.pass` receipts (positive path; expect 1).
    pub check_pass_receipts: u64,
    /// `capability.check.deny` receipts (revoke + out-of-scope;
    /// expect 2).
    pub check_deny_receipts: u64,
    /// `capability.revoke` receipts (expect 1).
    pub capability_revoke_receipts: u64,
    /// `envelope.send` receipts (only the permitted send; expect 1).
    pub envelope_send_receipts: u64,
    /// `envelope.deliver` receipts (mirrors send; expect 1).
    pub envelope_deliver_receipts: u64,
    /// All receipts in the audit log (expect 10 = 2+2+1+2+1+1+1).
    pub total_receipts: u64,
}

/// Build the descriptor the gRPC Send handler would synthesize from
/// this envelope. Kept here as a free function so the scenario and
/// the handler can stay byte-equivalent; if either drifts, this is
/// the single place to update.
fn descriptor_for_send(envelope: &Envelope) -> ActionDescriptor {
    ActionDescriptor {
        action_kind: "envelope.send".into(),
        resource_tags: envelope.tags.clone(),
        recipient: Some(recipient_descriptor_string(&envelope.recipient)),
        ..Default::default()
    }
}

/// Mirror of `recipient_descriptor_string` in
/// `crates/yutha-control-plane/src/grpc/envelope.rs`. Kept duplicated
/// (rather than re-exported) so this conformance scenario doesn't
/// take a runtime dep on `yutha-control-plane`; any drift between the
/// two is what S2 is meant to catch.
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

/// Run S2 end-to-end. Returns the receipt-count snapshot for the
/// `#[tokio::test]` at the bottom of this module (and any future
/// callers) to assert against.
pub async fn run_s2() -> S2Outcome {
    let swarm_id = SwarmId::new();
    let receipts: Arc<dyn ReceiptStore> = Arc::new(MemoryReceiptStore::new());
    let passports: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
    let resolver: Arc<dyn PassportResolver> =
        Arc::new(PassportResolverAdapter::new(Arc::clone(&passports)));

    // Control-plane bootstrap.
    let cp_signer = InProcessSigner::generate();
    let cp_agent_id = AgentId::new();
    let cp_passport = signed_passport(swarm_id, cp_agent_id, &cp_signer, "control plane").await;
    passports.register(cp_passport).await.unwrap();
    let cp = Arc::new(ControlPlaneIdentity::new(
        cp_agent_id,
        Arc::new(cp_signer) as Arc<dyn Signer>,
    ));

    let transport = Arc::new(MemoryTransport::new(
        Arc::clone(&receipts),
        Arc::clone(&resolver),
        Arc::clone(&cp),
    ));
    let capability_store = Arc::new(MemoryCapabilityStore::new(
        Arc::clone(&receipts),
        Arc::clone(&resolver),
        Arc::clone(&cp),
        // S2 focuses on RFC 0007 (Send-path cap enforcement) and does
        // not exercise the constitution-layer enforcement loop. A
        // future S4 variant will swap in an EnforcementEngine-backed
        // quarantine source.
        Arc::new(AlwaysAllowed),
    ));

    // Two demo agents — alice (sender) and bob (recipient).
    let alice_signer = InProcessSigner::generate();
    let alice_id = AgentId::new();
    let bob_signer = InProcessSigner::generate();
    let bob_id = AgentId::new();

    let topology = Topology {
        spec_version: SpecVersion::parse("1.0.0").unwrap(),
        swarm_id,
        mode: TopologyMode::Closed,
        admission: AdmissionPolicy::Closed(ClosedPolicy {
            allowlisted_agents: vec![alice_id, bob_id],
            ..Default::default()
        }),
        max_capability_lifetime_seconds: 90 * 24 * 60 * 60,
        max_capability_chain_depth: 8,
        default_envelope_ttl_seconds: 300,
        max_epoch_skew: 256,
        external_sends_permitted: false,
        // The handler-level flag (RFC 0007) is a gRPC-layer concern;
        // in-process this scenario explicitly calls capability_store
        // .check() to match the handler's logic, regardless of the
        // topology flag's value.
        require_capability_for_send: true,
        initial_constitution_version: "1.0.0".into(),
        operator_key_fingerprint: vec![0u8; 32],
        operator_signature: None,
    };
    let attestor: Arc<dyn yutha_attestor::Attestor> = Arc::new(yutha_attestor::NativeAttestor);
    let registry: Arc<dyn Registry> = Arc::new(
        MemoryRegistry::new(
            topology,
            Arc::clone(&passports),
            Arc::clone(&receipts),
            Arc::clone(&resolver),
            Arc::clone(&cp),
            attestor,
        )
        .expect("registry construction"),
    );

    // Register both agents.
    let mut agents_registered = 0u64;
    for (signer, agent_id, owner) in [
        (&alice_signer, alice_id, "alice"),
        (&bob_signer, bob_id, "bob"),
    ] {
        let passport = signed_passport(swarm_id, agent_id, signer, owner).await;
        let outcome = registry.register(passport, Vec::new()).await.unwrap();
        assert!(outcome.is_accepted(), "{owner} not admitted");
        transport.register_recipient(agent_id).await;
        agents_registered += 1;
    }

    // ---- 1. Positive path: cap permits envelope.send ----
    let alice_send_cap = Capability::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .capability_id(vec![1u8; 16])
        .swarm_id(swarm_id)
        .issuer(Issuer::Operator(vec![0u8; 32]))
        .subject(alice_id)
        .scope(Scope::for_action("envelope.send"))
        .valid_from(Timestamp::now())
        .valid_until(Timestamp::new("2099-01-01T00:00:00Z".into(), u64::MAX / 2).unwrap())
        .sign(&alice_signer)
        .await
        .unwrap();
    let issued = capability_store.issue(alice_send_cap).await.unwrap();

    let envelope = Envelope::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .swarm_id(swarm_id)
        .envelope_id(vec![1u8; 16])
        .from_agent(alice_id)
        .recipient(Recipient::Agent(bob_id))
        .performative(Performative::Inform)
        .payload(b"s2 positive".to_vec())
        .payload_schema_id("type.yutha.dev/v1/Text")
        .causal(CausalRef::empty())
        .nonce(vec![2u8; 16])
        .epoch(1)
        .sent_at(Timestamp::now())
        .sign(&alice_signer)
        .await
        .expect("sign envelope");

    let descriptor = descriptor_for_send(&envelope);
    let eval = capability_store
        .check(&issued.capability_id, &descriptor)
        .await
        .unwrap();
    assert!(eval.outcome.permitted, "positive-path check should permit");

    // Permit → proceed with the send. Mirrors the gRPC handler's flow.
    transport.send(envelope).await.expect("permitted send");
    let _delivered = transport
        .receive(&bob_id)
        .await
        .expect("bob receives the envelope");

    // ---- 2. Revoke + re-check denies ----
    capability_store
        .revoke(&issued.capability_id, "s2 revocation step")
        .await
        .unwrap();

    let eval = capability_store
        .check(&issued.capability_id, &descriptor)
        .await
        .unwrap();
    assert!(!eval.outcome.permitted, "revoked cap should deny");
    assert!(
        eval.outcome.deny_reason.contains("revoked"),
        "deny reason should mention revocation, got {:?}",
        eval.outcome.deny_reason,
    );

    // ---- 3. Out-of-scope cap ----
    let alice_other_cap = Capability::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .capability_id(vec![3u8; 16])
        .swarm_id(swarm_id)
        .issuer(Issuer::Operator(vec![0u8; 32]))
        .subject(alice_id)
        // Scope permits a different action; the descriptor asks for
        // envelope.send, so intersection denies.
        .scope(Scope::for_action("issue_refund"))
        .valid_from(Timestamp::now())
        .valid_until(Timestamp::new("2099-01-01T00:00:00Z".into(), u64::MAX / 2).unwrap())
        .sign(&alice_signer)
        .await
        .unwrap();
    let other_issued = capability_store.issue(alice_other_cap).await.unwrap();

    let eval = capability_store
        .check(&other_issued.capability_id, &descriptor)
        .await
        .unwrap();
    assert!(
        !eval.outcome.permitted,
        "out-of-scope cap should deny against envelope.send descriptor"
    );

    // ---- Audit shape ----
    S2Outcome {
        agents_registered,
        register_receipts: count_action(&receipts, "agent.register").await,
        capability_issue_receipts: count_action(&receipts, "capability.issue").await,
        check_pass_receipts: count_action(&receipts, "capability.check.pass").await,
        check_deny_receipts: count_action(&receipts, "capability.check.deny").await,
        capability_revoke_receipts: count_action(&receipts, "capability.revoke").await,
        envelope_send_receipts: count_action(&receipts, "envelope.send").await,
        envelope_deliver_receipts: count_action(&receipts, "envelope.deliver").await,
        total_receipts: receipts.count().await.unwrap(),
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

async fn signed_passport(
    swarm_id: SwarmId,
    agent_id: AgentId,
    signer: &dyn Signer,
    owner: &str,
) -> Passport {
    Passport::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .agent_id(agent_id)
        .swarm_id(swarm_id)
        .agent_public_key(signer.public_key())
        .owner(owner)
        .framework("conformance-s2", "1.0.0")
        .accepted_constitution_version("1.0.0")
        .tier(PassportTier::Minimal)
        .issued_at(Timestamp::now())
        .sign(signer)
        .await
        .expect("sign passport")
}

#[cfg(test)]
#[cfg(feature = "in-memory-scenarios")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn s2_send_path_cap_check_runs_end_to_end() {
        let o = run_s2().await;
        // 2 register + 2 issue + 1 check.pass + 2 check.deny + 1 revoke
        // + 1 send + 1 deliver = 10 receipts.
        assert_eq!(o.agents_registered, 2);
        assert_eq!(o.register_receipts, 2);
        assert_eq!(o.capability_issue_receipts, 2);
        assert_eq!(o.check_pass_receipts, 1);
        assert_eq!(o.check_deny_receipts, 2);
        assert_eq!(o.capability_revoke_receipts, 1);
        assert_eq!(o.envelope_send_receipts, 1);
        assert_eq!(o.envelope_deliver_receipts, 1);
        assert_eq!(o.total_receipts, 10);
    }
}

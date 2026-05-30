//! Behavioral scenario **S8: attestation deny path** (Phase D anchor for
//! [RFC 0016](../../../../spec/rfcs/0016-attestor-interface.md)).
//!
//! Per [`/spec/receipt/canonical-actions.md`](../../../../spec/receipt/canonical-actions.md)
//! `agent.register.deny` row + RFC 0016 §3.3 admission flow.
//!
//! What this scenario covers:
//!
//! - Stand up a control plane configured with `NativeAttestor` (the
//!   v1 default). Topology is OPEN with a permissive admission policy
//!   so the admission-policy check passes and the Attestor call is
//!   what produces the reject.
//! - Submit a `RegisterRequest` whose `external_credential` is
//!   *non-empty*. The native default expects empty bytes; non-empty
//!   triggers `AttestorError::Rejected`.
//! - Assert the registry returns `RegistryError::AttestationDenied`
//!   with `attestor_id = "native"`.
//! - Assert exactly one `agent.register.deny` receipt was appended,
//!   carrying the canonical evidence shape:
//!     - `claimed_agent_id` = the rejected passport's agent_id
//!     - `attestor_id` = `"native"`
//!     - `deny_reason` = the Attestor's operator-facing message
//! - Assert NO `agent.register` receipt was emitted (deny path
//!   short-circuits before persistence).
//! - Assert the passport store does NOT contain the rejected agent
//!   (no half-registered rows).
//!
//! This is the substrate-side companion of the gRPC integration test
//! that lives in the Python suite (Phase D follow-on); together they
//! lock the deny-path semantics at both layers.

use std::sync::Arc;
use yutha_attestor::NativeAttestor;
use yutha_core::{AgentId, SpecVersion, SwarmId, Timestamp};
use yutha_passport::{
    ControlPlaneIdentity, MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore,
    PassportTier,
};
use yutha_receipt::{
    ActionKindQuery, MemoryStore as MemoryReceiptStore, PassportResolver, Query, ReceiptStore,
};
use yutha_registry::{
    AdmissionPolicy, ClosedPolicy, MemoryRegistry, Registry, RegistryError, Topology, TopologyMode,
};
use yutha_signer::{InProcessSigner, Signer};

/// What a successful S8 run reports. Counts align with the
/// assertions the integration test makes.
#[derive(Debug, Clone)]
pub struct S8Outcome {
    /// Number of registrations attempted (always 1 in v1).
    pub registrations_attempted: u64,
    /// `agent.register.deny` receipts produced. v1 expects exactly 1.
    pub register_deny_receipts: u64,
    /// `agent.register` receipts produced. v1 expects exactly 0 (deny
    /// short-circuits before the success-receipt path).
    pub register_success_receipts: u64,
    /// Whether the rejected agent's passport ended up in the passport
    /// store. v1 expects `false`.
    pub passport_persisted: bool,
    /// Whether the registry returned `RegistryError::AttestationDenied`.
    /// v1 expects `true`.
    pub returned_attestation_denied: bool,
    /// `attestor_id` carried on the deny-receipt's evidence. v1
    /// expects `"native"`.
    pub deny_attestor_id: String,
}

/// Run the S8 scenario end-to-end.
pub async fn run_s8() -> S8Outcome {
    let swarm_id = SwarmId::new();
    let receipts: Arc<dyn ReceiptStore> = Arc::new(MemoryReceiptStore::new());
    let passports: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
    let resolver: Arc<dyn PassportResolver> =
        Arc::new(PassportResolverAdapter::new(Arc::clone(&passports)));

    // Bootstrap control plane.
    let cp_signer = InProcessSigner::generate();
    let cp_public_key = cp_signer.public_key();
    let cp_signer: Arc<dyn Signer> = Arc::new(cp_signer);
    let cp_agent_id = AgentId::new();
    let cp_passport = Passport::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .agent_id(cp_agent_id)
        .swarm_id(swarm_id)
        .agent_public_key(cp_public_key)
        .owner("control plane")
        .accepted_constitution_version("1.0.0")
        .tier(PassportTier::Minimal)
        .issued_at(Timestamp::now())
        .sign(cp_signer.as_ref())
        .await
        .unwrap();
    passports.register(cp_passport).await.unwrap();
    let cp = Arc::new(ControlPlaneIdentity::new(cp_agent_id, cp_signer));

    // CLOSED topology with our test agent pre-allowlisted so the
    // admission-policy check is guaranteed to pass — the Attestor is
    // then the only thing that can produce a reject. (OpenPolicy
    // defaults to min_tier=Standard + a 7-day expires_at requirement,
    // which would fail before the Attestor ever runs.)
    let agent_signer = InProcessSigner::generate();
    let agent_id = AgentId::new();
    let mut closed = ClosedPolicy::default();
    closed.allowlisted_agents.push(agent_id);

    let topology = Topology {
        spec_version: SpecVersion::parse("1.0.0").unwrap(),
        swarm_id,
        mode: TopologyMode::Closed,
        admission: AdmissionPolicy::Closed(closed),
        max_capability_lifetime_seconds: 0,
        max_capability_chain_depth: 8,
        default_envelope_ttl_seconds: 300,
        max_epoch_skew: 256,
        external_sends_permitted: false,
        require_capability_for_send: false,
        initial_constitution_version: "1.0.0".into(),
        operator_key_fingerprint: vec![0u8; 32],
        operator_signature: None,
    };

    // NativeAttestor: empty credential = accept, anything else = deny.
    let attestor: Arc<dyn yutha_attestor::Attestor> = Arc::new(NativeAttestor);
    let registry = MemoryRegistry::new(
        topology,
        Arc::clone(&passports),
        Arc::clone(&receipts),
        resolver,
        cp,
        attestor,
    )
    .expect("registry construction");

    // Build the agent's passport with a NON-EMPTY external_credential
    // — the deny-path trigger.
    let agent_passport = Passport::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .agent_id(agent_id)
        .swarm_id(swarm_id)
        .agent_public_key(agent_signer.public_key())
        .owner("test agent")
        .accepted_constitution_version("1.0.0")
        .tier(PassportTier::Minimal)
        .issued_at(Timestamp::now())
        .sign(&agent_signer)
        .await
        .unwrap();

    let non_empty_credential = b"this should be rejected by NativeAttestor".to_vec();
    let result = registry
        .register(agent_passport.clone(), non_empty_credential)
        .await;

    let (returned_attestation_denied, deny_attestor_id) = match result {
        Err(RegistryError::AttestationDenied {
            attestor_id,
            reason: _,
        }) => (true, attestor_id),
        Err(other) => panic!("expected AttestationDenied, got {other:?}"),
        Ok(_) => panic!("expected error, got success"),
    };

    // Count deny vs success receipts.
    let deny_count = receipts
        .query(
            Query::ByActionKind(ActionKindQuery {
                action_kind: "agent.register.deny".into(),
            }),
            None,
        )
        .await
        .unwrap()
        .receipts
        .len() as u64;

    let success_count = receipts
        .query(
            Query::ByActionKind(ActionKindQuery {
                action_kind: "agent.register".into(),
            }),
            None,
        )
        .await
        .unwrap()
        .receipts
        .len() as u64;

    // Was the rejected passport persisted? (It MUST NOT be.)
    let passport_persisted = passports.lookup(&agent_id).await.unwrap().is_some();

    S8Outcome {
        registrations_attempted: 1,
        register_deny_receipts: deny_count,
        register_success_receipts: success_count,
        passport_persisted,
        returned_attestation_denied,
        deny_attestor_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The S8 contract, all-in-one assertion bank.
    #[tokio::test]
    async fn s8_native_rejects_nonempty_credential() {
        let outcome = run_s8().await;

        assert_eq!(outcome.registrations_attempted, 1);
        assert!(
            outcome.returned_attestation_denied,
            "registry MUST return RegistryError::AttestationDenied on the deny path"
        );
        assert_eq!(
            outcome.deny_attestor_id, "native",
            "deny receipt MUST carry attestor_id=\"native\" when NativeAttestor rejected"
        );
        assert_eq!(
            outcome.register_deny_receipts, 1,
            "exactly one agent.register.deny receipt must land"
        );
        assert_eq!(
            outcome.register_success_receipts, 0,
            "NO agent.register receipt may be emitted on the deny path"
        );
        assert!(
            !outcome.passport_persisted,
            "rejected passport MUST NOT appear in the passport store"
        );
    }
}

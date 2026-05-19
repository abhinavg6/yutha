//! Behavioral scenario **S5: support-queue refund cap.**
//!
//! Activates a constitution authored against the
//! `Yutha::SupportQueue` workload extension (F14) and a single Cedar
//! `forbid` rule that gates `IssueRefund` on (a) amount > 10000 minor
//! units and (b) principal tier != "verifiable". Validates that the
//! schema-extension + cross-namespace-policy pattern actually
//! evaluates as the README promises.
//!
//! Three eval cases run, mirroring how real swarms would invoke the
//! constitution layer for an `IssueRefund` request:
//!
//! | Case | Refund amount | Agent tier   | Expected decision |
//! |------|---------------|--------------|-------------------|
//! | A    | 5,000         | minimal      | Permit (under cap)|
//! | B    | 15,000        | minimal      | Deny  (over cap)  |
//! | C    | 15,000        | verifiable   | Permit (supervisor) |
//!
//! Each case produces a `constitution.evaluate.{pass,deny}` receipt;
//! the scenario asserts the counts.
//!
//! Pairs with the worked-example files under
//! [`/spec/constitution/canonical-schemas/v1.1.0/examples/`].

use std::collections::HashMap;
use std::sync::Arc;

use yutha_cedar_plus::{
    canonical_schema_v1_1_with_extensions, parse_engine_config_yaml, CedarPlusEvaluator,
    Constitution, ConstitutionEvaluator, ConstitutionLoader, Decision, EntityRecord,
    EntitySnapshot, EntityUid, EvaluationRequest, WORKLOAD_SUPPORT_QUEUE_V1_1,
};
use yutha_core::{AgentId, Hash, HashAlgorithm, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_crypto::sign::generate_keypair;
use yutha_passport::{
    ControlPlaneIdentity, MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore,
    PassportTier,
};
use yutha_receipt::{
    ActionKindQuery, AppendOptions, Evidence, MemoryStore as MemoryReceiptStore, PassportResolver,
    Query, Receipt, ReceiptStore, SignatureRole, SignedBy,
};

const REFUND_CAP_CEDAR: &str =
    include_str!("../../../../spec/constitution/canonical-schemas/v1.1.0/examples/support-queue-refund-cap.cedar");
const REFUND_CAP_ENGINE_CONFIG_YAML: &str = include_str!(
    "../../../../spec/constitution/canonical-schemas/v1.1.0/examples/support-queue-refund-cap.yaml"
);

/// Receipt-count snapshot from a clean S5 run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S5Outcome {
    /// `constitution.evaluate.pass` receipts. Expect 2 (cases A + C).
    pub eval_pass_receipts: u64,
    /// `constitution.evaluate.deny` receipts. Expect 1 (case B).
    pub eval_deny_receipts: u64,
}

/// Run S5 end-to-end. Returns the receipt-count snapshot for the
/// `#[tokio::test]` at the bottom of this module to assert against.
pub async fn run_s5() -> S5Outcome {
    let swarm_id = SwarmId::new();
    let receipts: Arc<dyn ReceiptStore> = Arc::new(MemoryReceiptStore::new());
    let passports: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
    let resolver: Arc<dyn PassportResolver> =
        Arc::new(PassportResolverAdapter::new(Arc::clone(&passports)));

    let cp_key = generate_keypair();
    let cp_agent_id = AgentId::new();
    let cp_passport = signed_passport(swarm_id, cp_agent_id, &cp_key, "control plane");
    passports.register(cp_passport).await.unwrap();
    let cp = Arc::new(ControlPlaneIdentity::new(cp_agent_id, cp_key));

    // Constitution layer with the SupportQueue extension loaded.
    let schema = canonical_schema_v1_1_with_extensions(&[WORKLOAD_SUPPORT_QUEUE_V1_1])
        .expect("canonical + support-queue extension parses");
    let loader = ConstitutionLoader::with_default_bounds(schema);
    let evaluator = CedarPlusEvaluator::with_default_bounds(loader);

    let engine_config = parse_engine_config_yaml(REFUND_CAP_ENGINE_CONFIG_YAML)
        .expect("example engine_config parses");
    let constitution = Constitution {
        constitution_hash: Hash {
            algorithm: HashAlgorithm::Sha256,
            digest: vec![0xCC; 32],
        },
        spec_version: SpecVersion::parse("1.0.0").unwrap(),
        schema_version: "1.1.0".into(),
        constitution_version: "1.0.0".into(),
        parent_version: None,
        swarm_id,
        cedar_source: REFUND_CAP_CEDAR.into(),
        engine_config,
        issued_at: Timestamp::now(),
    };
    evaluator
        .activate(constitution)
        .await
        .expect("constitution activates");
    let active = evaluator.current().await.expect("active set");
    let constitution_hash = active.constitution.constitution_hash.clone();
    let constitution_version = active.constitution.constitution_version.clone();
    drop(active);

    // Three eval cases. Ticket entity is reused across them — the
    // refund amount + principal tier are what vary.
    let ticket_uid = "T-9001";
    let agent_minimal = AgentId::new();
    let agent_supervisor = AgentId::new();

    let cases = [
        ("A", agent_minimal, "minimal", 5_000_i64, Decision::Permit),
        ("B", agent_minimal, "minimal", 15_000_i64, Decision::Deny),
        (
            "C",
            agent_supervisor,
            "verifiable",
            15_000_i64,
            Decision::Permit,
        ),
    ];

    let mut eval_pass_receipts = 0u64;
    let mut eval_deny_receipts = 0u64;
    for (label, principal_id, tier, amount, expected) in cases {
        let request = issue_refund_request(
            &constitution_hash,
            principal_id,
            tier,
            ticket_uid,
            amount,
            swarm_id,
        );
        let outcome = evaluator
            .evaluate(request)
            .await
            .expect("eval runs cleanly");
        assert_eq!(
            outcome.decision, expected,
            "case {label}: expected {expected:?}, got {:?} (deny_reason={:?})",
            outcome.decision, outcome.deny_reason
        );

        let action_kind = match outcome.decision {
            Decision::Permit => "constitution.evaluate.pass",
            Decision::Deny => "constitution.evaluate.deny",
        };
        append_eval_receipt(
            &*receipts,
            &*resolver,
            &cp,
            swarm_id,
            action_kind,
            &constitution_version,
            &constitution_hash,
            principal_id,
        )
        .await;
        match outcome.decision {
            Decision::Permit => eval_pass_receipts += 1,
            Decision::Deny => eval_deny_receipts += 1,
        }
    }

    // Sanity: the receipt store accumulated exactly the expected
    // shape. Filter by action_kind so the assertion mirrors what an
    // operator would query in production.
    let pass_page = receipts
        .query(
            Query::ByActionKind(ActionKindQuery {
                action_kind: "constitution.evaluate.pass".into(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(pass_page.receipts.len() as u64, eval_pass_receipts);
    let deny_page = receipts
        .query(
            Query::ByActionKind(ActionKindQuery {
                action_kind: "constitution.evaluate.deny".into(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(deny_page.receipts.len() as u64, eval_deny_receipts);

    S5Outcome {
        eval_pass_receipts,
        eval_deny_receipts,
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn signed_passport(
    swarm_id: SwarmId,
    agent_id: AgentId,
    key: &yutha_crypto::sign::SigningKey,
    owner: &str,
) -> Passport {
    Passport::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .agent_id(agent_id)
        .swarm_id(swarm_id)
        .agent_public_key(key.public())
        .owner(owner)
        .accepted_constitution_version("1.0.0")
        .tier(PassportTier::Minimal)
        .issued_at(Timestamp::now())
        .sign(key)
        .expect("sign passport")
}

/// Build an [`EvaluationRequest`] for the SupportQueue `IssueRefund`
/// action. Populates every schema-required attribute on Agent /
/// Swarm / Ticket so Cedar's Strict-mode entity validation accepts
/// the snapshot.
fn issue_refund_request(
    constitution_hash: &Hash,
    principal_id: AgentId,
    tier: &str,
    ticket_uid: &str,
    refund_amount_cents: i64,
    swarm_id: SwarmId,
) -> EvaluationRequest {
    let principal_str = principal_id.to_string();
    let swarm_str = swarm_id.to_string();
    let now = Timestamp::now();

    let mut context_attrs: HashMap<String, serde_json::Value> = HashMap::new();
    context_attrs.insert(
        "refund_amount_cents".into(),
        serde_json::Value::Number(refund_amount_cents.into()),
    );
    context_attrs.insert(
        "reason".into(),
        serde_json::Value::String("customer requested refund".into()),
    );
    context_attrs.insert(
        "current_wall_clock".into(),
        serde_json::Value::String(now.wall_clock.clone()),
    );

    let entities = vec![
        agent_entity(&principal_str, &swarm_str, tier),
        swarm_entity(&swarm_str, "closed", "1.0.0"),
        ticket_entity(ticket_uid),
    ];

    EvaluationRequest {
        constitution_hash: constitution_hash.clone(),
        schema_version: "1.1.0".into(),
        // Action UID convention (post-F14 evaluator generalization):
        // last `::` separates the entity-type-name from the
        // entity-id. So this resolves to type
        // `Yutha::SupportQueue::Action` + id `"IssueRefund"`, which
        // matches the workload schema's action declaration.
        action_kind: "Yutha::SupportQueue::Action::IssueRefund".into(),
        principal_id,
        resource_uid: EntityUid::new("Yutha::SupportQueue::Ticket", ticket_uid.to_string()),
        context_attrs,
        entity_snapshot: EntitySnapshot { entities },
        current_wall_clock: now.wall_clock.clone(),
        current_time_unix_ns: now.monotonic_ns,
    }
}

fn agent_entity(agent_uid: &str, swarm_uid: &str, tier: &str) -> EntityRecord {
    // Mirrors crates/yutha-control-plane/src/grpc/envelope.rs::agent_entity
    // but with the passport_tier overridable for the test cases.
    let mut attrs: HashMap<String, serde_json::Value> = HashMap::new();
    attrs.insert(
        "agent_id".into(),
        serde_json::Value::String(agent_uid.to_string()),
    );
    attrs.insert(
        "passport_tier".into(),
        serde_json::Value::String(tier.to_string()),
    );
    attrs.insert("framework".into(), serde_json::Value::String(String::new()));
    attrs.insert(
        "passport_hash".into(),
        serde_json::Value::String("0".repeat(64)),
    );
    attrs.insert(
        "reputation".into(),
        serde_json::json!({ "__extn": { "fn": "decimal", "arg": "1.0" } }),
    );
    attrs.insert(
        "budget_remaining_usd_cents".into(),
        serde_json::Value::Number(i64::MAX.into()),
    );
    attrs.insert(
        "budget_remaining_tool_calls".into(),
        serde_json::Value::Number(i64::MAX.into()),
    );
    attrs.insert(
        "budget_remaining_compute_ms".into(),
        serde_json::Value::Number(i64::MAX.into()),
    );
    EntityRecord {
        uid: EntityUid::new("Yutha::Agent", agent_uid.to_string()),
        attrs,
        parents: vec![EntityUid::new("Yutha::Swarm", swarm_uid.to_string())],
    }
}

fn swarm_entity(swarm_uid: &str, topology_mode: &str, constitution_version: &str) -> EntityRecord {
    let mut attrs: HashMap<String, serde_json::Value> = HashMap::new();
    attrs.insert(
        "swarm_id".into(),
        serde_json::Value::String(swarm_uid.to_string()),
    );
    attrs.insert(
        "topology_mode".into(),
        serde_json::Value::String(topology_mode.to_string()),
    );
    attrs.insert(
        "constitution_version".into(),
        serde_json::Value::String(constitution_version.to_string()),
    );
    EntityRecord {
        uid: EntityUid::new("Yutha::Swarm", swarm_uid.to_string()),
        attrs,
        parents: Vec::new(),
    }
}

fn ticket_entity(ticket_id: &str) -> EntityRecord {
    let mut attrs: HashMap<String, serde_json::Value> = HashMap::new();
    attrs.insert(
        "ticket_id".into(),
        serde_json::Value::String(ticket_id.to_string()),
    );
    attrs.insert(
        "customer_id".into(),
        serde_json::Value::String("cust-42".into()),
    );
    attrs.insert("tier".into(), serde_json::Value::String("pro".into()));
    attrs.insert("status".into(), serde_json::Value::String("open".into()));
    EntityRecord {
        uid: EntityUid::new("Yutha::SupportQueue::Ticket", ticket_id.to_string()),
        attrs,
        parents: Vec::new(),
    }
}

/// Build + sign + append a `constitution.evaluate.{pass,deny}`
/// receipt. The gRPC handler does the same via
/// `envelope::emit_constitution_eval_receipt`; this is the in-process
/// twin.
#[allow(clippy::too_many_arguments)]
async fn append_eval_receipt(
    receipts: &dyn ReceiptStore,
    resolver: &dyn PassportResolver,
    cp: &ControlPlaneIdentity,
    swarm_id: SwarmId,
    action_kind: &str,
    constitution_version: &str,
    constitution_hash: &Hash,
    subject_agent_id: AgentId,
) {
    let evidence = vec![
        Evidence::new(
            "constitution_hash",
            "type.yutha.dev/v1/Hash",
            constitution_hash.digest.clone(),
        ),
        Evidence::new(
            "subject_agent_id",
            "type.yutha.dev/v1/AgentId",
            subject_agent_id.to_string().into_bytes(),
        ),
    ];
    let mut builder = Receipt::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .swarm_id(swarm_id)
        .actor(cp.agent_id)
        .action_kind(action_kind)
        .constitution_version(constitution_version)
        .occurred_at(Timestamp::now());
    for e in evidence {
        builder = builder.evidence(e);
    }
    let mut receipt = builder.build().expect("build receipt");
    let bytes = receipt.canonical_bytes().expect("canonical");
    let sig = cp.sign(&bytes);
    receipt
        .signatures
        .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));
    receipts
        .append(receipt, AppendOptions::default(), resolver)
        .await
        .expect("append receipt");
}

// =============================================================================
// Test
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn s5_refund_cap_evaluates_three_cases() {
        let outcome = run_s5().await;
        assert_eq!(
            outcome,
            S5Outcome {
                eval_pass_receipts: 2,
                eval_deny_receipts: 1,
            }
        );
    }
}

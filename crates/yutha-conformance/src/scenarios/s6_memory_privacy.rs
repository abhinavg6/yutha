//! Behavioral scenario **S6: memory privacy gate.**
//!
//! Activates a constitution whose Cedar policy uses one of the v1.1
//! memory-norm actions (`ReadMemory`) to gate cross-agent reads of
//! `private`-scoped memories. Validates that the schema's memory
//! entity + memory actions actually evaluate end-to-end — the F2
//! schema work declared them, but no scenario exercised them until
//! now.
//!
//! Three eval cases:
//!
//! | Case | Reader        | Memory scope | Memory owner   | Expected |
//! |------|---------------|--------------|----------------|----------|
//! | A    | owner-agent   | "private"    | owner-agent    | Permit   |
//! | B    | other-agent   | "private"    | owner-agent    | **Deny** |
//! | C    | other-agent   | "shared"     | owner-agent    | Permit   |
//!
//! Each case produces a `constitution.evaluate.{pass,deny}` receipt.
//!
//! Pairs with the worked-example files under
//! `/spec/constitution/canonical-schemas/v1.1.0/examples/`.

use std::collections::HashMap;
use std::sync::Arc;

use yutha_cedar_plus::{
    canonical_schema_v1_1, parse_engine_config_yaml, CedarPlusEvaluator, Constitution,
    ConstitutionEvaluator, ConstitutionLoader, Decision, EntityRecord, EntitySnapshot, EntityUid,
    EvaluationRequest,
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

const PRIVACY_CEDAR: &str = include_str!(
    "../../../../spec/constitution/canonical-schemas/v1.1.0/examples/memory-privacy-gate.cedar"
);
const PRIVACY_ENGINE_CONFIG_YAML: &str = include_str!(
    "../../../../spec/constitution/canonical-schemas/v1.1.0/examples/memory-privacy-gate.yaml"
);

/// Receipt-count snapshot from a clean S6 run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S6Outcome {
    /// `constitution.evaluate.pass` receipts. Expect 2 (cases A + C).
    pub eval_pass_receipts: u64,
    /// `constitution.evaluate.deny` receipts. Expect 1 (case B).
    pub eval_deny_receipts: u64,
}

/// Run S6 end-to-end.
pub async fn run_s6() -> S6Outcome {
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

    let schema = canonical_schema_v1_1().expect("canonical v1.1 schema parses");
    let loader = ConstitutionLoader::with_default_bounds(schema);
    let evaluator = CedarPlusEvaluator::with_default_bounds(loader);

    let engine_config =
        parse_engine_config_yaml(PRIVACY_ENGINE_CONFIG_YAML).expect("example engine_config parses");
    let constitution = Constitution {
        constitution_hash: Hash {
            algorithm: HashAlgorithm::Sha256,
            digest: vec![0xDD; 32],
        },
        spec_version: SpecVersion::parse("1.0.0").unwrap(),
        schema_version: "1.1.0".into(),
        constitution_version: "1.0.0".into(),
        parent_version: None,
        swarm_id,
        cedar_source: PRIVACY_CEDAR.into(),
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

    // Two agents: an owner (who creates the memory) and an unrelated
    // "other" agent who attempts to read it. The schema declares
    // `Memory.owner: Agent`, so the owner reference inside the Memory
    // entity is a Cedar EntityUid pointing at this agent.
    let owner_id = AgentId::new();
    let other_id = AgentId::new();
    let private_memory_uid = "mem-001";
    let shared_memory_uid = "mem-002";

    let cases = [
        (
            "A",
            owner_id,
            "private",
            private_memory_uid,
            owner_id,
            Decision::Permit,
        ),
        (
            "B",
            other_id,
            "private",
            private_memory_uid,
            owner_id,
            Decision::Deny,
        ),
        (
            "C",
            other_id,
            "shared",
            shared_memory_uid,
            owner_id,
            Decision::Permit,
        ),
    ];

    let mut eval_pass_receipts = 0u64;
    let mut eval_deny_receipts = 0u64;
    for (label, reader_id, scope, memory_uid, memory_owner, expected) in cases {
        let request = read_memory_request(
            &constitution_hash,
            reader_id,
            memory_uid,
            scope,
            memory_owner,
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
            reader_id,
        )
        .await;
        match outcome.decision {
            Decision::Permit => eval_pass_receipts += 1,
            Decision::Deny => eval_deny_receipts += 1,
        }
    }

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

    S6Outcome {
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

/// Build an [`EvaluationRequest`] for a `ReadMemory` call. The
/// Memory entity is included in the snapshot with the configured
/// scope + owner; the owner Agent entity is also in the snapshot
/// so Cedar can resolve `principal != resource.owner` to an Agent
/// reference rather than an unknown id.
fn read_memory_request(
    constitution_hash: &Hash,
    reader_id: AgentId,
    memory_uid: &str,
    memory_scope: &str,
    memory_owner: AgentId,
    swarm_id: SwarmId,
) -> EvaluationRequest {
    let reader_str = reader_id.to_string();
    let owner_str = memory_owner.to_string();
    let swarm_str = swarm_id.to_string();
    let now = Timestamp::now();

    let mut context_attrs: HashMap<String, serde_json::Value> = HashMap::new();
    context_attrs.insert(
        "current_wall_clock".into(),
        serde_json::Value::String(now.wall_clock.clone()),
    );
    context_attrs.insert(
        "current_time_unix_ns".into(),
        serde_json::Value::Number(now.monotonic_ns.into()),
    );

    let mut entities = vec![
        agent_entity(&reader_str, &swarm_str),
        swarm_entity(&swarm_str, "closed", "1.0.0"),
        memory_entity(memory_uid, memory_scope, &owner_str),
    ];
    // The owner Agent must be in the snapshot too — Cedar resolves
    // `resource.owner` (an Agent reference) against the entity set.
    // Skip when the reader IS the owner (case A) to avoid Cedar's
    // duplicate-entity error.
    if reader_id != memory_owner {
        entities.push(agent_entity(&owner_str, &swarm_str));
    }

    EvaluationRequest {
        constitution_hash: constitution_hash.clone(),
        schema_version: "1.1.0".into(),
        action_kind: "ReadMemory".into(),
        principal_id: reader_id,
        resource_uid: EntityUid::new("Yutha::Memory", memory_uid.to_string()),
        context_attrs,
        entity_snapshot: EntitySnapshot { entities },
        current_wall_clock: now.wall_clock.clone(),
        current_time_unix_ns: now.monotonic_ns,
    }
}

fn agent_entity(agent_uid: &str, swarm_uid: &str) -> EntityRecord {
    let mut attrs: HashMap<String, serde_json::Value> = HashMap::new();
    attrs.insert(
        "agent_id".into(),
        serde_json::Value::String(agent_uid.to_string()),
    );
    attrs.insert(
        "passport_tier".into(),
        serde_json::Value::String("minimal".into()),
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

fn memory_entity(memory_uid: &str, scope: &str, owner_uid: &str) -> EntityRecord {
    let mut attrs: HashMap<String, serde_json::Value> = HashMap::new();
    attrs.insert(
        "memory_id".into(),
        serde_json::Value::String(memory_uid.to_string()),
    );
    // Owner is an Agent reference. Cedar's JSON entity format uses
    // an `__entity` wrapper to denote entity references in attribute
    // values.
    attrs.insert(
        "owner".into(),
        serde_json::json!({
            "__entity": { "type": "Yutha::Agent", "id": owner_uid }
        }),
    );
    attrs.insert("scope".into(), serde_json::Value::String(scope.to_string()));
    attrs.insert("tags".into(), serde_json::Value::Array(Vec::new()));
    attrs.insert(
        "payload_schema_id".into(),
        serde_json::Value::String("type.yutha.dev/v1/Text".into()),
    );
    attrs.insert(
        "created_at_unix_ns".into(),
        serde_json::Value::Number(0.into()),
    );
    EntityRecord {
        uid: EntityUid::new("Yutha::Memory", memory_uid.to_string()),
        attrs,
        parents: Vec::new(),
    }
}

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
    async fn s6_memory_privacy_gate_evaluates_three_cases() {
        let outcome = run_s6().await;
        assert_eq!(
            outcome,
            S6Outcome {
                eval_pass_receipts: 2,
                eval_deny_receipts: 1,
            }
        );
    }
}

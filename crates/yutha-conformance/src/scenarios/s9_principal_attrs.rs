//! Behavioral scenario **S9: Principal-attribute Cedar rules fire honestly
//! (Phase 3a regression guard).**
//!
//! Phase 3a wired real `framework` / `passport_tier` / `passport_hash` /
//! `reputation` values into the gRPC `EvaluateEnvelope` path's `Yutha::Agent`
//! entity attrs (3a-2 + 3a-3). Pre-Phase-3a these were placeholders, which
//! meant Cedar policies keying on those attrs silently degraded to
//! permit-all — written, never fired. S9 is the regression guard that
//! locks the post-3a-3 behaviour in.
//!
//! Three cases against a constitution with two forbid rules — one keying
//! on `principal.framework`, one on `principal.reputation` — driven at the
//! evaluator level (same shape as S5). Real reputation lives in the
//! enforcement engine and budget lives in the substrate's eventual
//! budget-norms work; for the evaluator-level guard we synthesize entities
//! with the attrs set directly (the gRPC resolver wiring 3a-2/3 produced
//! is unit-tested adjacent to the call site; this scenario locks the
//! *Cedar* side).
//!
//! | Case | Framework  | Reputation | Expected decision         |
//! |------|------------|------------|---------------------------|
//! | A    | `primary`  | `1.0`      | Permit (baseline)         |
//! | B    | `rogue`    | `1.0`      | Deny (framework forbid)   |
//! | C    | `primary`  | `0.3`      | Deny (reputation forbid)  |
//!
//! Each case produces a `constitution.evaluate.{pass,deny}` receipt;
//! the scenario asserts the counts (1 pass, 2 denies).
//!
//! The deliberate test of *real* substrate behaviour (resolver + engine +
//! Cedar end-to-end through the gRPC handler) lives at the control-plane
//! integration-test layer. S9's role is the Cedar-side property the
//! resolver wiring relies on: "if the entity attrs are populated, the
//! Cedar forbid rules keying on them fire."
//!
//! Pairs with the `reference_principal_attrs_unwired` memory entry, which
//! S9's existence formally retires.

use std::collections::HashMap;
use std::sync::Arc;

use yutha_cedar_plus::{
    canonical_schema_v1_1, parse_engine_config_yaml, CedarPlusEvaluator, Constitution,
    ConstitutionEvaluator, ConstitutionLoader, Decision, EntityRecord, EntitySnapshot, EntityUid,
    EvaluationRequest,
};
use yutha_core::{AgentId, Hash, HashAlgorithm, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_passport::{
    ControlPlaneIdentity, MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore,
    PassportTier,
};
use yutha_receipt::{
    ActionKindQuery, AppendOptions, Evidence, MemoryStore as MemoryReceiptStore, PassportResolver,
    Query, Receipt, ReceiptStore, SignatureRole, SignedBy,
};
use yutha_signer::{InProcessSigner, Signer};

/// One forbid rule per principal attr the Phase 3a wiring now populates
/// honestly. The two `@id` annotations make each rule individually
/// identifiable; the trailing permit makes the constitution open-by-default
/// so only the forbid rules drive the deny outcomes.
const S9_CEDAR_SOURCE: &str = r#"
@id("forbid-rogue-framework")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
) when {
    principal.framework == "rogue"
};

@id("forbid-low-reputation")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
) when {
    principal.reputation.lessThan(decimal("0.5"))
};

permit (principal, action, resource);
"#;

/// Minimal engine config — no scoring rules, no procedures, no
/// enforcement rules. S9 only exercises Cedar Layer A; the Layer B
/// constructs S4/S7 exercise are out-of-scope.
const S9_ENGINE_CONFIG_YAML: &str = r#"
schema_version: "1.1.0"
predicates: []
scoring_rules: []
procedures: []
enforcement_rules: []
"#;

/// Receipt-count snapshot from a clean S9 run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S9Outcome {
    /// `constitution.evaluate.pass` receipts. Expect 1 (case A).
    pub eval_pass_receipts: u64,
    /// `constitution.evaluate.deny` receipts. Expect 2 (cases B + C).
    pub eval_deny_receipts: u64,
}

/// Run S9 end-to-end. Returns the receipt-count snapshot for the
/// `#[tokio::test]` at the bottom of this module to assert against.
pub async fn run_s9() -> S9Outcome {
    let swarm_id = SwarmId::new();
    let receipts: Arc<dyn ReceiptStore> = Arc::new(MemoryReceiptStore::new());
    let passports: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
    let resolver: Arc<dyn PassportResolver> =
        Arc::new(PassportResolverAdapter::new(Arc::clone(&passports)));

    let cp_signer = InProcessSigner::generate();
    let cp_agent_id = AgentId::new();
    let cp_passport = signed_passport(swarm_id, cp_agent_id, &cp_signer, "control plane").await;
    passports.register(cp_passport).await.unwrap();
    let cp = Arc::new(ControlPlaneIdentity::new(
        cp_agent_id,
        Arc::new(cp_signer) as Arc<dyn Signer>,
    ));

    let schema = canonical_schema_v1_1().expect("canonical schema loads");
    let loader = ConstitutionLoader::with_default_bounds(schema);
    let evaluator = CedarPlusEvaluator::with_default_bounds(loader);

    let engine_config =
        parse_engine_config_yaml(S9_ENGINE_CONFIG_YAML).expect("S9 engine_config parses");
    let constitution = Constitution {
        constitution_hash: Hash {
            algorithm: HashAlgorithm::Sha256,
            digest: vec![0x99; 32],
        },
        spec_version: SpecVersion::parse("1.0.0").unwrap(),
        schema_version: "1.1.0".into(),
        constitution_version: "1.0.0".into(),
        parent_version: None,
        swarm_id,
        cedar_source: S9_CEDAR_SOURCE.into(),
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

    // Three eval cases. The agent_id stays the same across cases —
    // what varies is the entity-attr values we synthesize for the
    // sender agent. Real-deployment usage runs through the resolver
    // which would pull the values from passport_store + enforcement
    // engine; here we set them directly to lock the Cedar side.
    let alice_id = AgentId::new();
    let resource_scope = "support-queue";

    let cases = [
        ("A", "primary", "1.0", Decision::Permit),
        ("B", "rogue", "1.0", Decision::Deny),
        ("C", "primary", "0.3", Decision::Deny),
    ];

    let mut eval_pass_receipts = 0u64;
    let mut eval_deny_receipts = 0u64;
    for (label, framework, reputation, expected) in cases {
        let request = send_envelope_request(
            &constitution_hash,
            alice_id,
            framework,
            reputation,
            resource_scope,
            swarm_id,
        );
        let outcome = evaluator
            .evaluate(request)
            .await
            .expect("eval runs cleanly");
        assert_eq!(
            outcome.decision, expected,
            "case {label} (framework={framework}, reputation={reputation}): \
             expected {expected:?}, got {:?} (deny_reason={:?})",
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
            alice_id,
        )
        .await;
        match outcome.decision {
            Decision::Permit => eval_pass_receipts += 1,
            Decision::Deny => eval_deny_receipts += 1,
        }
    }

    // Receipt-store sanity — same counts surface via by-action-kind
    // query (mirrors the operator's `yutha-ops grep` view).
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

    S9Outcome {
        eval_pass_receipts,
        eval_deny_receipts,
    }
}

// =============================================================================
// Helpers
// =============================================================================

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
        .accepted_constitution_version("1.0.0")
        .tier(PassportTier::Minimal)
        .issued_at(Timestamp::now())
        .sign(signer)
        .await
        .expect("sign passport")
}

/// Build an [`EvaluationRequest`] for `SendEnvelope` against a
/// `Yutha::Resource` recipient (cleanest minimal shape — no second
/// Agent entity needed in the snapshot).
fn send_envelope_request(
    constitution_hash: &Hash,
    principal_id: AgentId,
    framework: &str,
    reputation: &str,
    resource_scope: &str,
    swarm_id: SwarmId,
) -> EvaluationRequest {
    let principal_str = principal_id.to_string();
    let swarm_str = swarm_id.to_string();
    let resource_uid_str = format!("role:{resource_scope}");
    let now = Timestamp::now();

    let mut context_attrs: HashMap<String, serde_json::Value> = HashMap::new();
    context_attrs.insert(
        "performative".into(),
        serde_json::Value::String("INFORM".into()),
    );
    context_attrs.insert(
        "payload_schema_id".into(),
        serde_json::Value::String("type.yutha.dev/v1/Text".into()),
    );
    context_attrs.insert("tags".into(), serde_json::Value::Array(Vec::new()));
    context_attrs.insert(
        "capability_id".into(),
        serde_json::Value::String(String::new()),
    );
    for k in [
        "estimated_cost_usd_cents",
        "estimated_cost_tool_calls",
        "estimated_cost_compute_ms",
    ] {
        context_attrs.insert(k.into(), serde_json::Value::Number(0.into()));
    }
    context_attrs.insert(
        "current_wall_clock".into(),
        serde_json::Value::String(now.wall_clock.clone()),
    );
    context_attrs.insert(
        "current_time_unix_ns".into(),
        serde_json::Value::Number(now.monotonic_ns.into()),
    );

    let entities = vec![
        agent_entity_with(&principal_str, &swarm_str, framework, reputation),
        swarm_entity(&swarm_str, "closed", "1.0.0"),
        role_resource_entity(&resource_uid_str, resource_scope),
    ];

    EvaluationRequest {
        constitution_hash: constitution_hash.clone(),
        schema_version: "1.1.0".into(),
        action_kind: "Yutha::Action::SendEnvelope".into(),
        principal_id,
        resource_uid: EntityUid::new("Yutha::Resource", resource_uid_str),
        context_attrs,
        entity_snapshot: EntitySnapshot { entities },
        current_wall_clock: now.wall_clock.clone(),
        current_time_unix_ns: now.monotonic_ns,
    }
}

/// Build a `Yutha::Agent` entity with the framework + reputation
/// attrs caller-controlled — the rest at canonical defaults. Mirrors
/// the gRPC handler's `agent_entity` shape so what S9 hands the
/// evaluator looks byte-equivalent to what the resolver wiring
/// produces post-3a-3.
fn agent_entity_with(
    agent_uid: &str,
    swarm_uid: &str,
    framework: &str,
    reputation: &str,
) -> EntityRecord {
    let mut attrs: HashMap<String, serde_json::Value> = HashMap::new();
    attrs.insert(
        "agent_id".into(),
        serde_json::Value::String(agent_uid.to_string()),
    );
    attrs.insert(
        "passport_tier".into(),
        serde_json::Value::String("minimal".into()),
    );
    attrs.insert(
        "framework".into(),
        serde_json::Value::String(framework.to_string()),
    );
    attrs.insert(
        "passport_hash".into(),
        serde_json::Value::String("0".repeat(64)),
    );
    attrs.insert(
        "reputation".into(),
        serde_json::json!({ "__extn": { "fn": "decimal", "arg": reputation } }),
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

fn role_resource_entity(resource_uid: &str, scope: &str) -> EntityRecord {
    let mut attrs: HashMap<String, serde_json::Value> = HashMap::new();
    attrs.insert(
        "resource_kind".into(),
        serde_json::Value::String("role".into()),
    );
    attrs.insert("scope".into(), serde_json::Value::String(scope.to_string()));
    attrs.insert("tags".into(), serde_json::Value::Array(Vec::new()));
    EntityRecord {
        uid: EntityUid::new("Yutha::Resource", resource_uid.to_string()),
        attrs,
        parents: Vec::new(),
    }
}

/// Build + sign + append a `constitution.evaluate.{pass,deny}` receipt.
/// Mirrors the in-process twin from S5 (and the gRPC handler's
/// `emit_constitution_eval_receipt`).
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
    let sig = cp.sign(&bytes).await.expect("cp signer");
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
    async fn s9_principal_attrs_fire_honestly() {
        let outcome = run_s9().await;
        assert_eq!(
            outcome,
            S9Outcome {
                eval_pass_receipts: 1,
                eval_deny_receipts: 2,
            }
        );
    }
}

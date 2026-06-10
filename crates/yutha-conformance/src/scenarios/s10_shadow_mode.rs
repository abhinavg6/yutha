//! Behavioral scenario **S10: Shadow-mode evaluator end-to-end
//! (Phase 3b regression guard).**
//!
//! Phase 3b shipped the shadow-mode evaluator per RFC 0018: a
//! candidate constitution slot alongside the active. Every envelope
//! evaluates against both via [`CedarPlusEvaluator::evaluate_pair`];
//! the active gates the cap layer + enforcement engine, the shadow
//! only emits `constitution.evaluate.shadow.{pass,deny}` receipts.
//!
//! S10 locks the three load-bearing properties from RFC 0018 in:
//!
//! 1. **Slot independence.** `evaluate_pair` returns
//!    `(active_outcome, Option<shadow_outcome>)` for one shared
//!    [`EvaluationRequest`]. The two outcomes are independent — a
//!    shadow deny does NOT influence the active decision.
//! 2. **Receipt action-kind partitioning.** Active denies emit
//!    `constitution.evaluate.deny`; shadow denies emit
//!    `constitution.evaluate.shadow.deny`. The two streams never
//!    cross-pollute (the engine fan-out filter at the receipt-
//!    publisher forwarder lives outside this scenario, but the
//!    receipt-store-level partitioning we assert here is what makes
//!    that filter possible).
//! 3. **Evidence shape per RFC 0018 §3.4.** Active receipts gain a
//!    `shadow_constitution_hash` evidence entry when a shadow is
//!    configured at evaluation time (absent when not). Shadow
//!    receipts carry `shadow_constitution_hash` and NOT
//!    `constitution_hash` — auditors join active+shadow receipts for
//!    the same envelope on the `shadow_constitution_hash` evidence
//!    plus the shared `input_attribute_digest`.
//!
//! ## Three cases
//!
//! | Case | `tags`          | Active   | Shadow   |
//! |------|-----------------|----------|----------|
//! | A    | `["routine"]`   | Permit   | Permit   |
//! | B    | `["sensitive"]` | Permit   | Deny     |
//! | C    | `["broadcast"]` | Permit   | Permit   |
//!
//! Active is permit-all. Shadow forbids when
//! `context.tags.contains("sensitive")`. Case B is the
//! shadow-divergence-without-gating outcome operators rely on for
//! preview workflows.
//!
//! Expected receipt counts after 3 envelopes:
//!
//! - 3 `constitution.evaluate.pass` (active is permissive, all three
//!   pass)
//! - 0 `constitution.evaluate.deny`
//! - 2 `constitution.evaluate.shadow.pass` (cases A + C)
//! - 1 `constitution.evaluate.shadow.deny` (case B)

use std::collections::HashMap;
use std::sync::Arc;

use yutha_cedar_plus::{
    canonical_schema_v1_1, parse_engine_config_yaml, CedarPlusEvaluator, Constitution,
    ConstitutionEvaluator, ConstitutionLoader, Decision, EntityRecord, EntitySnapshot, EntityUid,
    EvaluationOutcome, EvaluationRequest,
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

/// Permissive active constitution — every SendEnvelope passes.
const S10_ACTIVE_CEDAR_SOURCE: &str = r#"
permit (principal, action, resource);
"#;

/// Restrictive shadow constitution — forbids any SendEnvelope whose
/// `context.tags` includes `"sensitive"`. The trailing permit makes
/// the constitution open-by-default so only the forbid rule drives
/// the deny outcome.
const S10_SHADOW_CEDAR_SOURCE: &str = r#"
@id("forbid-sensitive-tag")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
) when {
    context.tags.contains("sensitive")
};

permit (principal, action, resource);
"#;

/// Minimal engine config — no scoring, no procedures, no enforcement
/// rules. S10 only exercises Layer A + the slot-level mechanics.
const S10_ENGINE_CONFIG_YAML: &str = r#"
schema_version: "1.1.0"
predicates: []
scoring_rules: []
procedures: []
enforcement_rules: []
"#;

/// Receipt-count snapshot from a clean S10 run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S10Outcome {
    /// `constitution.evaluate.pass` receipts. Expect 3 (active is
    /// permissive; every case passes).
    pub eval_pass_receipts: u64,
    /// `constitution.evaluate.deny` receipts. Expect 0.
    pub eval_deny_receipts: u64,
    /// `constitution.evaluate.shadow.pass` receipts. Expect 2 (cases
    /// A, C).
    pub shadow_pass_receipts: u64,
    /// `constitution.evaluate.shadow.deny` receipts. Expect 1 (case
    /// B).
    pub shadow_deny_receipts: u64,
}

/// Run S10 end-to-end. Returns the receipt-count snapshot for the
/// `#[tokio::test]` at the bottom of this module to assert against.
pub async fn run_s10() -> S10Outcome {
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

    let engine_config_active =
        parse_engine_config_yaml(S10_ENGINE_CONFIG_YAML).expect("active engine_config parses");
    let active_constitution = Constitution {
        constitution_hash: Hash {
            algorithm: HashAlgorithm::Sha256,
            digest: vec![0xA0; 32],
        },
        spec_version: SpecVersion::parse("1.0.0").unwrap(),
        schema_version: "1.1.0".into(),
        constitution_version: "1.0.0".into(),
        parent_version: None,
        swarm_id,
        cedar_source: S10_ACTIVE_CEDAR_SOURCE.into(),
        engine_config: engine_config_active,
        issued_at: Timestamp::now(),
    };
    evaluator
        .activate(active_constitution)
        .await
        .expect("active constitution activates");

    let engine_config_shadow =
        parse_engine_config_yaml(S10_ENGINE_CONFIG_YAML).expect("shadow engine_config parses");
    let shadow_constitution = Constitution {
        constitution_hash: Hash {
            algorithm: HashAlgorithm::Sha256,
            // Distinct hash from active so receipt evidence can be
            // unambiguously checked across slots.
            digest: vec![0xB0; 32],
        },
        spec_version: SpecVersion::parse("1.0.0").unwrap(),
        schema_version: "1.1.0".into(),
        constitution_version: "1.1.0-rc".into(),
        parent_version: None,
        swarm_id,
        cedar_source: S10_SHADOW_CEDAR_SOURCE.into(),
        engine_config: engine_config_shadow,
        issued_at: Timestamp::now(),
    };
    evaluator
        .activate_shadow(shadow_constitution)
        .await
        .expect("shadow constitution activates");

    // Snapshot both slots before sending — same posture as the gRPC
    // handler. RFC 0018 §3.4 receipt evidence depends on both hashes
    // being in scope when each emit fires.
    let (active_opt, shadow_opt) = evaluator.current_pair().await;
    let active = active_opt.expect("active set");
    let shadow = shadow_opt.expect("shadow set");
    let active_hash = active.constitution.constitution_hash.clone();
    let active_version = active.constitution.constitution_version.clone();
    let shadow_hash = shadow.constitution.constitution_hash.clone();
    let shadow_version = shadow.constitution.constitution_version.clone();
    drop(active);
    drop(shadow);

    let alice_id = AgentId::new();
    let resource_scope = "support-queue";

    let cases = [
        ("A", &["routine"][..], Decision::Permit, Decision::Permit),
        ("B", &["sensitive"][..], Decision::Permit, Decision::Deny),
        ("C", &["broadcast"][..], Decision::Permit, Decision::Permit),
    ];

    let mut eval_pass_receipts = 0u64;
    let mut eval_deny_receipts = 0u64;
    let mut shadow_pass_receipts = 0u64;
    let mut shadow_deny_receipts = 0u64;

    for (label, tags, expected_active, expected_shadow) in cases {
        let request = send_envelope_request(&active_hash, alice_id, tags, resource_scope, swarm_id);

        let (active_outcome, shadow_outcome_opt) = evaluator
            .evaluate_pair(request)
            .await
            .expect("evaluate_pair runs cleanly");

        // RFC 0018 §3.1 slot-independence guard: the active outcome
        // is whatever the active constitution decided, regardless of
        // what the shadow saw.
        assert_eq!(
            active_outcome.decision, expected_active,
            "case {label}: active expected {expected_active:?}, got {:?}",
            active_outcome.decision
        );
        let shadow_outcome =
            shadow_outcome_opt.expect("shadow loaded → evaluate_pair returns Some shadow outcome");
        assert_eq!(
            shadow_outcome.decision, expected_shadow,
            "case {label}: shadow expected {expected_shadow:?}, got {:?} (reason={:?})",
            shadow_outcome.decision, shadow_outcome.deny_reason
        );

        // Emit the active receipt (with shadow_constitution_hash
        // evidence per RFC 0018 §3.4 since a shadow is configured).
        let active_action_kind = match active_outcome.decision {
            Decision::Permit => "constitution.evaluate.pass",
            Decision::Deny => "constitution.evaluate.deny",
        };
        append_active_eval_receipt(
            &*receipts,
            &*resolver,
            &cp,
            swarm_id,
            active_action_kind,
            &active_version,
            &active_hash,
            Some(&shadow_hash),
            alice_id,
            &active_outcome,
        )
        .await;
        match active_outcome.decision {
            Decision::Permit => eval_pass_receipts += 1,
            Decision::Deny => eval_deny_receipts += 1,
        }

        // Emit the shadow receipt. Action-kind partitioning per
        // RFC 0018 §3.4: shadow receipts NEVER use the active
        // `constitution.evaluate.{pass,deny}` action-kinds.
        let shadow_action_kind = match shadow_outcome.decision {
            Decision::Permit => "constitution.evaluate.shadow.pass",
            Decision::Deny => "constitution.evaluate.shadow.deny",
        };
        append_shadow_eval_receipt(
            &*receipts,
            &*resolver,
            &cp,
            swarm_id,
            shadow_action_kind,
            &shadow_version,
            &shadow_hash,
            alice_id,
            &shadow_outcome,
        )
        .await;
        match shadow_outcome.decision {
            Decision::Permit => shadow_pass_receipts += 1,
            Decision::Deny => shadow_deny_receipts += 1,
        }
    }

    // Receipt-store sanity — same counts surface via by-action-kind
    // query (mirrors the operator's `yutha-ops grep` view).
    assert_count(&*receipts, "constitution.evaluate.pass", eval_pass_receipts).await;
    assert_count(&*receipts, "constitution.evaluate.deny", eval_deny_receipts).await;
    assert_count(
        &*receipts,
        "constitution.evaluate.shadow.pass",
        shadow_pass_receipts,
    )
    .await;
    assert_count(
        &*receipts,
        "constitution.evaluate.shadow.deny",
        shadow_deny_receipts,
    )
    .await;

    // RFC 0018 §3.4 evidence-shape guard, run against the actual
    // receipts persisted to the store:
    //
    // 1. Every active receipt carries `shadow_constitution_hash`
    //    evidence when a shadow is configured at eval time.
    // 2. Every shadow receipt carries `shadow_constitution_hash`
    //    evidence and does NOT carry the active's `constitution_hash`
    //    key (auditors keying on either field need them unambiguous).
    let pass_page = receipts
        .query(
            Query::ByActionKind(ActionKindQuery {
                action_kind: "constitution.evaluate.pass".into(),
            }),
            None,
        )
        .await
        .unwrap();
    for r in &pass_page.receipts {
        assert!(
            r.evidence
                .iter()
                .any(|e| e.key == "shadow_constitution_hash"),
            "active receipt MUST carry shadow_constitution_hash evidence when a shadow is \
             configured (RFC 0018 §3.4)"
        );
        assert!(
            r.evidence.iter().any(|e| e.key == "constitution_hash"),
            "active receipt MUST carry the active constitution_hash evidence"
        );
    }
    let shadow_deny_page = receipts
        .query(
            Query::ByActionKind(ActionKindQuery {
                action_kind: "constitution.evaluate.shadow.deny".into(),
            }),
            None,
        )
        .await
        .unwrap();
    for r in &shadow_deny_page.receipts {
        assert!(
            r.evidence
                .iter()
                .any(|e| e.key == "shadow_constitution_hash"),
            "shadow receipt MUST carry shadow_constitution_hash evidence (RFC 0018 §3.4)"
        );
        assert!(
            !r.evidence.iter().any(|e| e.key == "constitution_hash"),
            "shadow receipts MUST use shadow_constitution_hash, NOT constitution_hash \
             (RFC 0018 §3.4) — auditors join active+shadow receipts on the \
             shadow_constitution_hash key; mixing would make the join ambiguous"
        );
    }

    S10Outcome {
        eval_pass_receipts,
        eval_deny_receipts,
        shadow_pass_receipts,
        shadow_deny_receipts,
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

/// Build an [`EvaluationRequest`] for `SendEnvelope` with
/// caller-controlled tags. Mirrors `send_envelope_request` from S9 —
/// the only knob S10 varies across cases is `tags`.
fn send_envelope_request(
    constitution_hash: &Hash,
    principal_id: AgentId,
    tags: &[&str],
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
    context_attrs.insert(
        "tags".into(),
        serde_json::Value::Array(
            tags.iter()
                .map(|t| serde_json::Value::String((*t).to_string()))
                .collect(),
        ),
    );
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
        agent_entity(&principal_str, &swarm_str),
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

/// `Yutha::Agent` entity at canonical defaults — S10 doesn't gate on
/// principal attrs, those have their own regression guard in S9.
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
    attrs.insert(
        "framework".into(),
        serde_json::Value::String("primary".into()),
    );
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

/// Build + sign + append a `constitution.evaluate.{pass,deny}`
/// receipt with the same evidence shape as the gRPC handler's
/// `emit_constitution_eval_receipt`. When `shadow_constitution_hash`
/// is `Some`, that evidence entry rides on the active receipt
/// per RFC 0018 §3.4.
#[allow(clippy::too_many_arguments)]
async fn append_active_eval_receipt(
    receipts: &dyn ReceiptStore,
    resolver: &dyn PassportResolver,
    cp: &ControlPlaneIdentity,
    swarm_id: SwarmId,
    action_kind: &str,
    constitution_version: &str,
    constitution_hash: &Hash,
    shadow_constitution_hash: Option<&Hash>,
    subject_agent_id: AgentId,
    outcome: &EvaluationOutcome,
) {
    let mut evidence = vec![
        Evidence::new(
            "constitution_hash",
            "type.yutha.dev/v1/Hash",
            constitution_hash.digest.clone(),
        ),
        Evidence::new(
            "action_kind",
            "type.yutha.dev/v1/String",
            "SendEnvelope".as_bytes().to_vec(),
        ),
        Evidence::new(
            "matched_rule_ids",
            "type.yutha.dev/v1/String",
            outcome.matched_rule_ids.join(",").into_bytes(),
        ),
        Evidence::new(
            "input_attribute_digest",
            "type.yutha.dev/v1/Hash",
            outcome.evidence_digest.digest.clone(),
        ),
        Evidence::new(
            "subject_agent_id",
            "type.yutha.dev/v1/AgentId",
            subject_agent_id.to_string().into_bytes(),
        ),
    ];
    if let Some(reason) = &outcome.deny_reason {
        evidence.push(Evidence::new(
            "deny_reason",
            "type.yutha.dev/v1/String",
            reason.as_bytes().to_vec(),
        ));
    }
    if let Some(shadow_hash) = shadow_constitution_hash {
        evidence.push(Evidence::new(
            "shadow_constitution_hash",
            "type.yutha.dev/v1/Hash",
            shadow_hash.digest.clone(),
        ));
    }
    sign_and_append(
        receipts,
        resolver,
        cp,
        swarm_id,
        action_kind,
        constitution_version,
        evidence,
    )
    .await;
}

/// Build + sign + append a `constitution.evaluate.shadow.{pass,deny}`
/// receipt mirroring the gRPC handler's
/// `emit_constitution_shadow_eval_receipt`. Evidence shape per
/// RFC 0018 §3.4: `shadow_constitution_hash` (NOT
/// `constitution_hash`), `action_kind`, `matched_rule_ids`,
/// `input_attribute_digest`, `subject_agent_id`, optional
/// `deny_reason`.
#[allow(clippy::too_many_arguments)]
async fn append_shadow_eval_receipt(
    receipts: &dyn ReceiptStore,
    resolver: &dyn PassportResolver,
    cp: &ControlPlaneIdentity,
    swarm_id: SwarmId,
    action_kind: &str,
    shadow_constitution_version: &str,
    shadow_constitution_hash: &Hash,
    subject_agent_id: AgentId,
    outcome: &EvaluationOutcome,
) {
    let mut evidence = vec![
        Evidence::new(
            "shadow_constitution_hash",
            "type.yutha.dev/v1/Hash",
            shadow_constitution_hash.digest.clone(),
        ),
        Evidence::new(
            "action_kind",
            "type.yutha.dev/v1/String",
            "SendEnvelope".as_bytes().to_vec(),
        ),
        Evidence::new(
            "matched_rule_ids",
            "type.yutha.dev/v1/String",
            outcome.matched_rule_ids.join(",").into_bytes(),
        ),
        Evidence::new(
            "input_attribute_digest",
            "type.yutha.dev/v1/Hash",
            outcome.evidence_digest.digest.clone(),
        ),
        Evidence::new(
            "subject_agent_id",
            "type.yutha.dev/v1/AgentId",
            subject_agent_id.to_string().into_bytes(),
        ),
    ];
    if let Some(reason) = &outcome.deny_reason {
        evidence.push(Evidence::new(
            "deny_reason",
            "type.yutha.dev/v1/String",
            reason.as_bytes().to_vec(),
        ));
    }
    sign_and_append(
        receipts,
        resolver,
        cp,
        swarm_id,
        action_kind,
        shadow_constitution_version,
        evidence,
    )
    .await;
}

/// Shared build+sign+append shape across the two emitters. Mirrors
/// the gRPC handler's pattern: builder → canonical_bytes → cp.sign →
/// push signature → store.append.
async fn sign_and_append(
    receipts: &dyn ReceiptStore,
    resolver: &dyn PassportResolver,
    cp: &ControlPlaneIdentity,
    swarm_id: SwarmId,
    action_kind: &str,
    constitution_version: &str,
    evidence: Vec<Evidence>,
) {
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

/// Assert the store holds exactly `expected` receipts with the given
/// `action_kind`. Operator-facing `yutha-ops grep <kind>` query.
async fn assert_count(receipts: &dyn ReceiptStore, action_kind: &str, expected: u64) {
    let page = receipts
        .query(
            Query::ByActionKind(ActionKindQuery {
                action_kind: action_kind.into(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        page.receipts.len() as u64,
        expected,
        "expected {expected} receipts with action_kind {action_kind:?}, found {}",
        page.receipts.len()
    );
}

// =============================================================================
// Test
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn s10_shadow_mode_round_trip() {
        let outcome = run_s10().await;
        assert_eq!(
            outcome,
            S10Outcome {
                eval_pass_receipts: 3,
                eval_deny_receipts: 0,
                shadow_pass_receipts: 2,
                shadow_deny_receipts: 1,
            }
        );
    }
}

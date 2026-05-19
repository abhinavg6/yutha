//! Behavioral scenario **S7: enforcement reverse path.**
//!
//! Companion to S4 (which exercises detect → coach → quarantine →
//! evict). S7 covers the alternate quarantine outcome: an
//! auto-reverse triggered by `quarantine.expires_after` elapsing
//! without an explicit operator reverse. Verifies the engine's
//! Stage::Reverse plumbing + the cap layer's quarantine consultation
//! flipping back to "permitted" after the reverse fires.
//!
//! Flow:
//!
//! 1. Activate a constitution with an enforcement rule that has
//!    detect (count_threshold=2) + coach (1s) + quarantine
//!    (escalate_after=1s, expires_after=2s) + NO evict.
//! 2. Issue alice a pre-quarantine send-cap (verified later).
//! 3. Two forbidden-payload evaluations land 2 deny receipts and
//!    fire `enforcement.detect`.
//! 4. Advance time → `enforcement.coach` fires.
//! 5. Advance time → `enforcement.quarantine` fires; engine
//!    schedules the auto-reverse at `now + expires_after`.
//! 6. Cap.check on alice's cap denies with `subject_quarantined`.
//! 7. Advance time past expires_after → `enforcement.reverse` fires;
//!    engine clears quarantine state.
//! 8. Cap.check on the same cap now permits (alice is unquarantined).
//!
//! Pairs the F4 reverse-stage spec with a runnable proof: each
//! transition emits a receipt, the cap layer's behavior flips at
//! exactly the quarantine boundaries, and the audit-log delta is a
//! stable count the conformance harness asserts on.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use yutha_capability::{
    ActionDescriptor, Capability, CapabilityStore, Issuer, MemoryCapabilityStore, QuarantineSource,
    Scope,
};
use yutha_cedar_plus::{
    canonical_schema_v1_1, parse_engine_config_yaml, CedarPlusEvaluator, Constitution,
    ConstitutionEvaluator, ConstitutionLoader, Decision, EnforcementEffect, EnforcementEngine,
    EntityRecord, EntitySnapshot, EntityUid, EvaluationRequest, ReceiptView,
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

const S7_CEDAR_SOURCE: &str = r#"
@id("no-forbidden-payloads")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
) when {
    context.payload_schema_id == "type.yutha.dev/v1/Forbidden"
};

permit (principal, action, resource);
"#;

/// `expires_after: 2s` is the load-bearing field for S7 — the engine
/// uses it to schedule the auto-reverse off the quarantine fire.
/// `evict` is intentionally absent so the Reverse path is the only
/// follow-on from quarantine (the F13 chain dispatcher schedules
/// both when both are configured; S4 covers the evict half).
const S7_ENGINE_CONFIG_YAML: &str = r#"
schema_version: "1.1.0"
predicates: []
scoring_rules: []
procedures: []
enforcement_rules:
  - name: forbidden_payload_with_reverse
    detect:
      trigger:
        receipt_kind: constitution.evaluate.deny
      count_threshold: 2
      time_window: 60s
      group_by: principal
    coach:
      cooldown: 1s
      guidance_template: "Stop sending forbidden payloads"
    quarantine:
      escalate_after: 1s
      expires_after: 2s
    severity: medium
"#;

/// Receipt-count + state-flag snapshot from a clean S7 run. The
/// `#[tokio::test]` at the bottom asserts an exact-match against
/// this shape; any drift in stage emission or engine quarantine
/// transitions surfaces immediately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S7Outcome {
    /// `constitution.evaluate.deny` receipts. Expect 2 (one per
    /// forbidden eval).
    pub eval_deny_receipts: u64,
    /// `enforcement.detect` receipts. Expect 1.
    pub detect_receipts: u64,
    /// `enforcement.coach` receipts. Expect 1.
    pub coach_receipts: u64,
    /// `enforcement.quarantine` receipts. Expect 1.
    pub quarantine_receipts: u64,
    /// `enforcement.reverse` receipts. Expect 1 (the auto-reverse
    /// triggered by `quarantine.expires_after`).
    pub reverse_receipts: u64,
    /// True iff the engine reported alice quarantined between the
    /// quarantine and reverse stages.
    pub quarantined_mid_chain: bool,
    /// True iff the engine reported alice un-quarantined after the
    /// reverse fired.
    pub unquarantined_post_reverse: bool,
}

struct EngineQuarantineSource {
    engine: Arc<EnforcementEngine>,
}

impl std::fmt::Debug for EngineQuarantineSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineQuarantineSource").finish_non_exhaustive()
    }
}

#[async_trait]
impl QuarantineSource for EngineQuarantineSource {
    async fn is_agent_quarantined(&self, agent_id: &AgentId) -> bool {
        self.engine
            .is_agent_quarantined(&agent_id.to_string())
            .await
    }
}

/// Run S7 end-to-end. Returns the [`S7Outcome`] snapshot for the
/// `#[tokio::test]` at the bottom of this module to assert against.
pub async fn run_s7() -> S7Outcome {
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

    let alice_key = generate_keypair();
    let alice_id = AgentId::new();
    passports
        .register(signed_passport(swarm_id, alice_id, &alice_key, "alice"))
        .await
        .unwrap();

    let schema = canonical_schema_v1_1().expect("canonical schema loads");
    let loader = ConstitutionLoader::with_default_bounds(schema);
    let evaluator = Arc::new(CedarPlusEvaluator::with_default_bounds(loader));
    let engine = Arc::new(EnforcementEngine::new());

    let constitution = build_s7_constitution(swarm_id);
    evaluator
        .activate(constitution)
        .await
        .expect("constitution activates");
    let active = evaluator.current().await.expect("active set");
    engine.activate(active.clone()).await;
    let constitution_hash = active.constitution.constitution_hash.clone();
    let constitution_version = active.constitution.constitution_version.clone();
    drop(active);

    let cap_store = MemoryCapabilityStore::new(
        Arc::clone(&receipts),
        Arc::clone(&resolver),
        Arc::clone(&cp),
        Arc::new(EngineQuarantineSource {
            engine: Arc::clone(&engine),
        }),
    );
    let issued = cap_store
        .issue(build_alice_cap(swarm_id, alice_id, &alice_key))
        .await
        .expect("pre-quarantine cap issues");

    // ---- Two forbidden evaluations → detect fires ----
    let mut eval_deny_receipts = 0u64;
    let mut detect_effects: Vec<EnforcementEffect> = Vec::new();
    for _ in 0..2 {
        let outcome = evaluator
            .evaluate(forbidden_eval_request(
                &constitution_hash,
                alice_id,
                swarm_id,
            ))
            .await
            .expect("eval runs");
        assert_eq!(outcome.decision, Decision::Deny);

        let receipt_id = append_receipt(
            &*receipts,
            &*resolver,
            &cp,
            swarm_id,
            "constitution.evaluate.deny",
            &constitution_version,
            vec![
                Evidence::new(
                    "constitution_hash",
                    "type.yutha.dev/v1/Hash",
                    constitution_hash.digest.clone(),
                ),
                Evidence::new(
                    "subject_agent_id",
                    "type.yutha.dev/v1/AgentId",
                    alice_id.to_string().into_bytes(),
                ),
                Evidence::new(
                    "deny_reason",
                    "type.yutha.dev/v1/String",
                    outcome
                        .deny_reason
                        .as_deref()
                        .unwrap_or("forbid_rule_matched")
                        .as_bytes()
                        .to_vec(),
                ),
            ],
            Timestamp::now(),
        )
        .await;
        eval_deny_receipts += 1;
        let persisted = receipts.get(&receipt_id).await.unwrap().unwrap();
        detect_effects = engine.on_receipt(view_from(&persisted, alice_id)).await;
    }
    assert_eq!(detect_effects.len(), 1);
    assert_eq!(detect_effects[0].action_kind, "enforcement.detect");
    let detect_receipts = emit_effect_with_loopback(
        &*receipts,
        &*resolver,
        &cp,
        &engine,
        swarm_id,
        &constitution_version,
        &constitution_hash,
        &detect_effects[0],
        alice_id,
    )
    .await;

    // ---- Advance past coach.cooldown → coach fires ----
    let coach_effects = engine.poll_scheduled(&advance_seconds(60)).await;
    assert_eq!(coach_effects.len(), 1);
    assert_eq!(coach_effects[0].action_kind, "enforcement.coach");
    let coach_receipts = emit_effect_with_loopback(
        &*receipts,
        &*resolver,
        &cp,
        &engine,
        swarm_id,
        &constitution_version,
        &constitution_hash,
        &coach_effects[0],
        alice_id,
    )
    .await;

    // ---- Advance past quarantine.escalate_after → quarantine fires.
    // The engine simultaneously schedules the auto-reverse at
    // (poll-time) + expires_after — observable on the next poll.
    let q_effects = engine.poll_scheduled(&advance_seconds(120)).await;
    assert_eq!(q_effects.len(), 1);
    assert_eq!(q_effects[0].action_kind, "enforcement.quarantine");
    let quarantine_receipts = emit_effect_with_loopback(
        &*receipts,
        &*resolver,
        &cp,
        &engine,
        swarm_id,
        &constitution_version,
        &constitution_hash,
        &q_effects[0],
        alice_id,
    )
    .await;

    // Cap layer denies while alice is quarantined.
    let quarantined_mid_chain = engine.is_agent_quarantined(&alice_id.to_string()).await;
    assert!(quarantined_mid_chain);
    let cap_eval_during = cap_store
        .check(
            &issued.capability_id,
            &ActionDescriptor {
                action_kind: "envelope.send".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(!cap_eval_during.outcome.permitted);
    assert_eq!(cap_eval_during.outcome.deny_reason, "subject_quarantined");

    // ---- Advance past quarantine.expires_after → reverse fires.
    // Note: expires_after was scheduled with `now=120s-base`, so
    // the reverse fires at 120s + 2s. Advance to 240s for headroom.
    let r_effects = engine.poll_scheduled(&advance_seconds(240)).await;
    assert_eq!(r_effects.len(), 1, "expected one auto-reverse effect");
    assert_eq!(r_effects[0].action_kind, "enforcement.reverse");
    let reverse_receipts = emit_effect_with_loopback(
        &*receipts,
        &*resolver,
        &cp,
        &engine,
        swarm_id,
        &constitution_version,
        &constitution_hash,
        &r_effects[0],
        alice_id,
    )
    .await;

    // Cap layer permits again post-reverse.
    let unquarantined_post_reverse = !engine.is_agent_quarantined(&alice_id.to_string()).await;
    assert!(unquarantined_post_reverse);
    let cap_eval_after = cap_store
        .check(
            &issued.capability_id,
            &ActionDescriptor {
                action_kind: "envelope.send".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(
        cap_eval_after.outcome.permitted,
        "post-reverse cap.check should permit, got deny_reason={:?}",
        cap_eval_after.outcome.deny_reason
    );

    S7Outcome {
        eval_deny_receipts,
        detect_receipts,
        coach_receipts,
        quarantine_receipts,
        reverse_receipts,
        quarantined_mid_chain,
        unquarantined_post_reverse,
    }
}

// =============================================================================
// Helpers — most are copies of the S4 versions. Duplicated rather than
// extracted because the scenarios are independent of each other.
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

fn build_s7_constitution(swarm_id: SwarmId) -> Constitution {
    let engine_config =
        parse_engine_config_yaml(S7_ENGINE_CONFIG_YAML).expect("S7 engine_config parses");
    Constitution {
        constitution_hash: Hash {
            algorithm: HashAlgorithm::Sha256,
            digest: vec![0xEE; 32],
        },
        spec_version: SpecVersion::parse("1.0.0").unwrap(),
        schema_version: "1.1.0".into(),
        constitution_version: "1.0.0".into(),
        parent_version: None,
        swarm_id,
        cedar_source: S7_CEDAR_SOURCE.into(),
        engine_config,
        issued_at: Timestamp::now(),
    }
}

fn forbidden_eval_request(
    constitution_hash: &Hash,
    principal_id: AgentId,
    swarm_id: SwarmId,
) -> EvaluationRequest {
    let principal_str = principal_id.to_string();
    let swarm_str = swarm_id.to_string();
    let mut context_attrs: HashMap<String, serde_json::Value> = HashMap::new();
    context_attrs.insert(
        "performative".into(),
        serde_json::Value::String("Inform".into()),
    );
    context_attrs.insert(
        "payload_schema_id".into(),
        serde_json::Value::String("type.yutha.dev/v1/Forbidden".into()),
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
    let now = Timestamp::now();
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
    ];
    EvaluationRequest {
        constitution_hash: constitution_hash.clone(),
        schema_version: "1.1.0".into(),
        action_kind: "SendEnvelope".into(),
        principal_id,
        resource_uid: EntityUid::new("Yutha::Agent", principal_str.clone()),
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

#[allow(clippy::too_many_arguments)]
async fn append_receipt(
    receipts: &dyn ReceiptStore,
    resolver: &dyn PassportResolver,
    cp: &ControlPlaneIdentity,
    swarm_id: SwarmId,
    action_kind: &str,
    constitution_version: &str,
    evidence: Vec<Evidence>,
    occurred_at: Timestamp,
) -> Hash {
    let mut builder = Receipt::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .swarm_id(swarm_id)
        .actor(cp.agent_id)
        .action_kind(action_kind)
        .constitution_version(constitution_version)
        .occurred_at(occurred_at);
    for e in evidence {
        builder = builder.evidence(e);
    }
    let mut receipt = builder.build().expect("build receipt");
    let bytes = receipt.canonical_bytes().expect("canonical bytes");
    let sig = cp.sign(&bytes);
    receipt
        .signatures
        .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));
    let outcome = receipts
        .append(receipt, AppendOptions::default(), resolver)
        .await
        .expect("append receipt");
    outcome.receipt_id
}

#[allow(clippy::too_many_arguments)]
async fn emit_effect_with_loopback(
    receipts: &dyn ReceiptStore,
    resolver: &dyn PassportResolver,
    cp: &ControlPlaneIdentity,
    engine: &EnforcementEngine,
    swarm_id: SwarmId,
    constitution_version: &str,
    constitution_hash: &Hash,
    effect: &EnforcementEffect,
    target: AgentId,
) -> u64 {
    let mut evidence = vec![
        Evidence::new(
            "target_agent_id",
            "type.yutha.dev/v1/AgentId",
            effect.target_agent_id.as_bytes().to_vec(),
        ),
        Evidence::new(
            "enforcement_rule_id",
            "type.yutha.dev/v1/String",
            effect.enforcement_rule_id.as_bytes().to_vec(),
        ),
        Evidence::new(
            "reputation_delta",
            "type.yutha.dev/v1/String",
            effect.reputation_delta.0.as_bytes().to_vec(),
        ),
        Evidence::new(
            "constitution_hash",
            "type.yutha.dev/v1/Hash",
            constitution_hash.digest.clone(),
        ),
    ];
    let _: BTreeMap<String, serde_json::Value> = effect.additional_evidence.clone();
    for (k, v) in &effect.additional_evidence {
        evidence.push(Evidence::new(
            k.as_str(),
            "type.yutha.dev/v1/Json",
            serde_json::to_vec(v).expect("encode additional evidence"),
        ));
    }
    let receipt_id = append_receipt(
        receipts,
        resolver,
        cp,
        swarm_id,
        &effect.action_kind,
        constitution_version,
        evidence,
        Timestamp::now(),
    )
    .await;
    let persisted = receipts.get(&receipt_id).await.unwrap().unwrap();
    let _ = engine.on_receipt(view_from(&persisted, target)).await;
    1
}

fn view_from(receipt: &Receipt, target: AgentId) -> ReceiptView<'_> {
    let mut principal_id_owned: Option<String> = None;
    let mut deny_reason_owned: Option<String> = None;
    let mut forbid_rule_id_owned: Option<String> = None;
    let mut reputation_delta_owned: Option<yutha_cedar_plus::Score> = None;
    for ev in &receipt.evidence {
        match ev.key.as_str() {
            "subject_agent_id" | "target_agent_id" if principal_id_owned.is_none() => {
                principal_id_owned = String::from_utf8(ev.value.clone()).ok();
            }
            "deny_reason" => deny_reason_owned = String::from_utf8(ev.value.clone()).ok(),
            "forbid_rule_id" => forbid_rule_id_owned = String::from_utf8(ev.value.clone()).ok(),
            "reputation_delta" => {
                if let Ok(s) = String::from_utf8(ev.value.clone()) {
                    reputation_delta_owned = Some(yutha_cedar_plus::Score(s));
                }
            }
            _ => {}
        }
    }
    if principal_id_owned.is_none() {
        principal_id_owned = Some(target.to_string());
    }
    let principal_id_static: Option<&'static str> = principal_id_owned
        .map(|s| &*Box::leak(s.into_boxed_str()));
    let deny_reason_static: Option<&'static str> = deny_reason_owned
        .map(|s| &*Box::leak(s.into_boxed_str()));
    let forbid_rule_id_static: Option<&'static str> = forbid_rule_id_owned
        .map(|s| &*Box::leak(s.into_boxed_str()));
    ReceiptView {
        action_kind: Box::leak(receipt.action_kind.clone().into_boxed_str()),
        principal_id: principal_id_static,
        deny_reason: deny_reason_static,
        forbid_rule_id: forbid_rule_id_static,
        occurred_at_unix_ns: receipt.occurred_at.monotonic_ns,
        occurred_at_wall_clock: Box::leak(
            receipt.occurred_at.wall_clock.clone().into_boxed_str(),
        ),
        reputation_delta: reputation_delta_owned,
    }
}

fn build_alice_cap(
    swarm_id: SwarmId,
    alice_id: AgentId,
    alice_key: &yutha_crypto::sign::SigningKey,
) -> Capability {
    Capability::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .capability_id(vec![1u8; 16])
        .swarm_id(swarm_id)
        .issuer(Issuer::Operator(vec![0u8; 32]))
        .subject(alice_id)
        .scope(Scope::for_action("envelope.send"))
        .valid_from(Timestamp::now())
        .valid_until(Timestamp::new("2099-01-01T00:00:00Z".into(), u64::MAX / 2).unwrap())
        .sign(alice_key)
        .expect("sign cap")
}

fn advance_seconds(seconds_offset: u64) -> String {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    let base = OffsetDateTime::parse("2100-01-01T00:00:00Z", &Rfc3339).expect("parse base");
    let advanced = base + time::Duration::seconds(seconds_offset as i64);
    advanced.format(&Rfc3339).expect("format")
}

#[allow(dead_code)]
async fn count_receipts(receipts: &dyn ReceiptStore, action_kind: &str) -> u64 {
    let page = receipts
        .query(
            Query::ByActionKind(ActionKindQuery {
                action_kind: action_kind.into(),
            }),
            None,
        )
        .await
        .expect("query");
    page.receipts.len() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn s7_reverse_path_runs_end_to_end() {
        let outcome = run_s7().await;
        assert_eq!(
            outcome,
            S7Outcome {
                eval_deny_receipts: 2,
                detect_receipts: 1,
                coach_receipts: 1,
                quarantine_receipts: 1,
                reverse_receipts: 1,
                quarantined_mid_chain: true,
                unquarantined_post_reverse: true,
            }
        );
    }
}

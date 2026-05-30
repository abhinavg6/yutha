//! Behavioral scenario **S4: Four-stage enforcement loop (RFC 0013).**
//!
//! Activates a constitution with one Cedar `forbid` rule plus an
//! `enforcement_rules` entry covering all four stages
//! (detect → coach → quarantine → evict). Drives the chain
//! end-to-end against an in-process [`EnforcementEngine`] and
//! verifies:
//!
//! 1. The Cedar evaluator denies forbidden sends and produces
//!    `constitution.evaluate.deny` receipts.
//! 2. After `count_threshold` denies, the engine fires
//!    `enforcement.detect`.
//! 3. Driving the wall-clock forward via [`EnforcementEngine::poll_scheduled`]
//!    fires `enforcement.coach`, then `enforcement.quarantine`, then
//!    `enforcement.evict` in order (the F13 stage-chaining fix).
//! 4. Between the quarantine and the evict, the cap layer denies
//!    fresh issuances + checks for the quarantined agent with
//!    `deny_reason = "subject_quarantined"` (RFC 0013 §4.2).
//!
//! The scenario drives time directly with synthetic RFC 3339 strings
//! rather than `tokio::time` so the test runs in milliseconds and
//! never flakes on wall-clock cooldowns. The engine's
//! `poll_scheduled(now)` takes the wall-clock string as a parameter
//! exactly to make this kind of harness possible.
//!
//! Coverage gap callout: the scenario does NOT exercise the gRPC
//! handler's `build_eval_request_for_send` path; it constructs
//! [`EvaluationRequest`]s directly against the in-process
//! [`CedarPlusEvaluator`]. Drift between handler and scenario is
//! intentional — the gRPC path adds context shape (entity attrs,
//! topology mode) that's out-of-scope for the enforcement chain test.

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
use yutha_passport::{
    ControlPlaneIdentity, MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore,
    PassportTier,
};
use yutha_receipt::{
    ActionKindQuery, AppendOptions, Evidence, MemoryStore as MemoryReceiptStore, PassportResolver,
    Query, Receipt, ReceiptStore, SignatureRole, SignedBy,
};
use yutha_signer::{InProcessSigner, Signer};

/// Receipt-count snapshot a clean S4 run produces. The conformance
/// test below asserts against these expectations exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S4Outcome {
    /// `constitution.evaluate.deny` receipts emitted. Equals
    /// `count_threshold` for this scenario (2).
    pub eval_deny_receipts: u64,
    /// `enforcement.detect` receipts (expect 1).
    pub detect_receipts: u64,
    /// `enforcement.coach` receipts (expect 1).
    pub coach_receipts: u64,
    /// `enforcement.quarantine` receipts (expect 1).
    pub quarantine_receipts: u64,
    /// `enforcement.evict` receipts (expect 1).
    pub evict_receipts: u64,
    /// `capability.check.deny` receipts produced between the
    /// quarantine and the evict, with `deny_reason =
    /// "subject_quarantined"` (expect 1).
    pub quarantined_cap_denies: u64,
    /// Whether [`EnforcementEngine::is_agent_quarantined`] returned
    /// `true` between the quarantine and the evict (expect `true`).
    pub agent_was_quarantined: bool,
}

// =============================================================================
// Constitution fixture
// =============================================================================

/// The Cedar policy: one `forbid` rule on `SendEnvelope` when the
/// payload's schema id matches a sentinel, plus an open `permit` so
/// every other action evaluates to allow. The `@id` annotation pins
/// the policy's id so the enforcement detect rule can pattern-match
/// on it via `forbid_rule_id` if needed (the scenario itself doesn't
/// filter on it, since the receipt-emit path below doesn't currently
/// surface that field on `constitution.evaluate.deny` evidence).
const S4_CEDAR_SOURCE: &str = r#"
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

/// The engine config: a single enforcement rule covering all four
/// stages with 1-second cooldowns so the harness can drive the chain
/// via synthetic time advance.
///
/// `count_threshold: 2` means two denies fire detect; that's the
/// smallest non-trivial threshold the F9 sliding-window matcher
/// exercises. All four stage configs are present so the F13 chain
/// fully runs.
const S4_ENGINE_CONFIG_YAML: &str = r#"
schema_version: "1.1.0"
predicates: []
scoring_rules: []
procedures: []
enforcement_rules:
  - name: forbidden_payload_chain
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
    evict:
      escalate_after: 1s
      require_countersign: false
    severity: high
"#;

/// Cap-layer quarantine adapter for the scenario. Mirrors the
/// production `EnforcementEngineQuarantineSource` in
/// `yutha-control-plane` — duplicated rather than re-exported so the
/// conformance crate doesn't depend on the control-plane binary.
///
/// `EnforcementEngine` doesn't impl Debug (its inner state is behind a
/// tokio RwLock); hand-roll the impl so the QuarantineSource trait
/// bound is satisfied.
struct EngineQuarantineSource {
    engine: Arc<EnforcementEngine>,
}

impl std::fmt::Debug for EngineQuarantineSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineQuarantineSource")
            .finish_non_exhaustive()
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

// =============================================================================
// Scenario body
// =============================================================================

/// Run S4 end-to-end. Returns the receipt-count snapshot for the
/// `#[tokio::test]` at the bottom of this module to assert against.
pub async fn run_s4() -> S4Outcome {
    let swarm_id = SwarmId::new();
    let receipts: Arc<dyn ReceiptStore> = Arc::new(MemoryReceiptStore::new());
    let passports: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
    let resolver: Arc<dyn PassportResolver> =
        Arc::new(PassportResolverAdapter::new(Arc::clone(&passports)));

    // Control-plane identity. Signs every receipt the scenario
    // emits (Cedar evals + enforcement-stage transitions).
    let cp_signer = InProcessSigner::generate();
    let cp_agent_id = AgentId::new();
    let cp_passport = signed_passport(swarm_id, cp_agent_id, &cp_signer, "control plane").await;
    passports.register(cp_passport).await.unwrap();
    let cp = Arc::new(ControlPlaneIdentity::new(
        cp_agent_id,
        Arc::new(cp_signer) as Arc<dyn Signer>,
    ));

    // The target agent — the one whose forbidden sends trigger the
    // enforcement loop. Registered + passport stored so the
    // quarantine-state semantics behave normally; subsequent
    // cap-checks would fail anyway for an unregistered subject.
    let alice_signer = InProcessSigner::generate();
    let alice_id = AgentId::new();
    passports
        .register(signed_passport(swarm_id, alice_id, &alice_signer, "alice").await)
        .await
        .unwrap();

    // Constitution layer.
    let schema = canonical_schema_v1_1().expect("canonical schema loads");
    let loader = ConstitutionLoader::with_default_bounds(schema);
    let evaluator = Arc::new(CedarPlusEvaluator::with_default_bounds(loader));
    let engine = Arc::new(EnforcementEngine::new());

    let constitution = build_s4_constitution(swarm_id);
    evaluator
        .activate(constitution)
        .await
        .expect("constitution activates");
    let active = evaluator.current().await.expect("active set");
    engine.activate(active.clone()).await;
    let constitution_hash = active.constitution.constitution_hash.clone();
    let constitution_version = active.constitution.constitution_version.clone();
    drop(active);

    // Cap-layer store wired to consult the engine for quarantine
    // state. Issue alice a send-cap NOW, before any enforcement
    // fires, so the cap exists in the store when we re-check it
    // post-quarantine. Issuing post-quarantine would itself fail
    // with `SubjectQuarantined` (which is the right semantic; F10g
    // tests cover it separately).
    let cap_store = MemoryCapabilityStore::new(
        Arc::clone(&receipts),
        Arc::clone(&resolver),
        Arc::clone(&cp),
        Arc::new(EngineQuarantineSource {
            engine: Arc::clone(&engine),
        }),
    );
    let issued = cap_store
        .issue(build_alice_cap(swarm_id, alice_id, &alice_signer).await)
        .await
        .expect("issue pre-quarantine cap");

    // ---- Step 1: two forbidden Cedar evals → two deny receipts ----
    //
    // For the threshold-2 detect rule, the first deny just bumps a
    // counter; the second crosses the threshold and produces an
    // enforcement effect.
    let mut effects_from_deny_2: Vec<EnforcementEffect> = Vec::new();
    let mut eval_deny_receipts = 0u64;
    for _ in 0..2 {
        let outcome = evaluator
            .evaluate(forbidden_eval_request(
                &constitution_hash,
                alice_id,
                swarm_id,
            ))
            .await
            .expect("eval runs");
        assert_eq!(
            outcome.decision,
            Decision::Deny,
            "forbid rule should deny the payload"
        );

        // Emit the constitution.evaluate.deny receipt that the gRPC
        // handler would. Feed the corresponding view into the
        // engine; on the second deny, we'll get an effect back.
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
        // Pull the persisted receipt back out so we can build a
        // ReceiptView against its exact occurred_at — the engine's
        // counter prune uses occurred_at_unix_ns.
        let persisted = receipts.get(&receipt_id).await.unwrap().unwrap();
        effects_from_deny_2 = engine.on_receipt(view_from(&persisted, alice_id)).await;
    }
    // The second deny crossed the threshold.
    assert_eq!(effects_from_deny_2.len(), 1);
    assert_eq!(effects_from_deny_2[0].action_kind, "enforcement.detect");

    // Persist the detect receipt + close the loop into the engine.
    // The engine's enforcement.* special-case applies the reputation
    // delta and returns no further effects.
    let detect_receipts = emit_effect_with_loopback(
        &*receipts,
        &*resolver,
        &cp,
        &engine,
        swarm_id,
        &constitution_version,
        &constitution_hash,
        &effects_from_deny_2[0],
        alice_id,
    )
    .await;
    assert_eq!(detect_receipts, 1);

    // ---- Step 2: advance past coach.cooldown → enforcement.coach ----
    //
    // The engine scheduled coach 1 second after the detect's
    // occurred_at_wall_clock. We use a deliberately-large advance so
    // the cooldown is comfortably past regardless of how fast or slow
    // the harness clock ticked between Step 1 and now.
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
    assert_eq!(coach_receipts, 1);

    // ---- Step 3: advance past quarantine.escalate_after ----
    //
    // F13's stage-chaining fix scheduled quarantine when coach fired
    // above; this poll surfaces it.
    let q_effects = engine.poll_scheduled(&advance_seconds(120)).await;
    assert_eq!(
        q_effects.len(),
        1,
        "F13 chain: coach should schedule quarantine"
    );
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
    assert_eq!(quarantine_receipts, 1);

    // ---- Step 4: cap-layer denies alice while quarantined ----
    //
    // The cap was issued at the top of the scenario (pre-quarantine),
    // so it lives in the same `cap_store` we're now checking against.
    // The engine's quarantine state is consulted on every check; alice
    // is currently quarantined, so this denies with the reason F10g
    // surfaces in `MemoryCapabilityStore::check_inner`.
    let agent_was_quarantined = engine.is_agent_quarantined(&alice_id.to_string()).await;
    assert!(
        agent_was_quarantined,
        "engine should report alice quarantined"
    );
    let eval = cap_store
        .check(
            &issued.capability_id,
            &ActionDescriptor {
                action_kind: "envelope.send".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(!eval.outcome.permitted, "quarantined alice must be denied");
    assert_eq!(eval.outcome.deny_reason, "subject_quarantined");

    // ---- Step 5: advance past evict.escalate_after ----
    let e_effects = engine.poll_scheduled(&advance_seconds(240)).await;
    assert_eq!(
        e_effects.len(),
        1,
        "F13 chain: quarantine should schedule evict"
    );
    assert_eq!(e_effects[0].action_kind, "enforcement.evict");
    let evict_receipts = emit_effect_with_loopback(
        &*receipts,
        &*resolver,
        &cp,
        &engine,
        swarm_id,
        &constitution_version,
        &constitution_hash,
        &e_effects[0],
        alice_id,
    )
    .await;
    assert_eq!(evict_receipts, 1);

    // Count quarantine-driven cap-check denies. The pre-quarantine
    // issuance produced a capability.issue receipt; the post-
    // quarantine check produced a capability.check.deny.
    let quarantined_cap_denies = count_receipts_with_kind_and_reason(
        &*receipts,
        "capability.check.deny",
        "subject_quarantined",
    )
    .await;

    S4Outcome {
        eval_deny_receipts,
        detect_receipts,
        coach_receipts,
        quarantine_receipts,
        evict_receipts,
        quarantined_cap_denies,
        agent_was_quarantined,
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

fn build_s4_constitution(swarm_id: SwarmId) -> Constitution {
    let engine_config =
        parse_engine_config_yaml(S4_ENGINE_CONFIG_YAML).expect("S4 engine_config parses");
    // The constitution_hash here is a placeholder — receipts embed
    // it as evidence but the scenario doesn't verify it against a
    // canonical-bytes derivation (the loader doesn't recompute the
    // hash; it trusts what's set). Real wire-shape activation does
    // recompute, but for in-process scenarios this is fine.
    let constitution_hash = Hash {
        algorithm: HashAlgorithm::Sha256,
        digest: vec![0xAB; 32],
    };
    Constitution {
        constitution_hash,
        spec_version: SpecVersion::parse("1.0.0").unwrap(),
        schema_version: "1.1.0".into(),
        constitution_version: "1.0.0".into(),
        parent_version: None,
        swarm_id,
        cedar_source: S4_CEDAR_SOURCE.into(),
        engine_config,
        issued_at: Timestamp::now(),
    }
}

/// Build an [`EvaluationRequest`] for a "send envelope with forbidden
/// payload schema" — the only call shape the scenario evaluates.
/// Matches the gRPC handler's entity-snapshot surface closely enough
/// for the forbid rule to evaluate against the same context.
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

    // Self-send shape: the resource_uid is the same Agent as the
    // principal. The schema declares SendEnvelope.resource: [Agent,
    // Envelope]; Yutha::Agent satisfies that. The gRPC handler
    // dedups recipient==sender so the snapshot has exactly one
    // Agent entity even on self-sends.
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
    // Mirrors crates/yutha-control-plane/src/grpc/envelope.rs::agent_entity
    // (scaffolding-tier placeholders for every required attr).
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

/// Build + sign + append a substrate receipt the control plane would
/// otherwise emit. Used for the `constitution.evaluate.deny` and
/// `enforcement.*` receipts the scenario produces.
///
/// The 8-argument shape mirrors the wire-receipt-construction surface
/// the control plane goes through (every field is structurally
/// required). Bundling into a struct just to satisfy
/// `clippy::too_many_arguments` would obscure rather than clarify —
/// callers in the scenario read top-to-bottom against the spec's
/// receipt schema.
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
    use yutha_crypto::canonical::Canonical;
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
    let sig = cp.sign(&bytes).await.expect("cp signer");
    receipt
        .signatures
        .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));
    let outcome = receipts
        .append(receipt, AppendOptions::default(), resolver)
        .await
        .expect("append receipt");
    outcome.receipt_id
}

/// Persist an `enforcement.*` receipt corresponding to the given
/// effect and feed the same view back into the engine to close the
/// loop (so reputation deltas land and quarantine state flips). The
/// engine's pattern matcher special-cases `enforcement.*` kinds and
/// returns no further effects, terminating the cycle.
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
    // Feed back into the engine — this is where reputation deltas
    // apply and where enforcement.quarantine flips the agent's state.
    let _ = engine.on_receipt(view_from(&persisted, target)).await;
    1
}

/// Build a [`ReceiptView`] borrowing from `receipt`. The view's
/// `principal_id` comes from a `subject_agent_id` or `target_agent_id`
/// evidence entry; if neither is present, fall back to the explicit
/// `target` parameter (the actor on every receipt the scenario
/// emits is the control plane, so that's never the right
/// principal_id for the engine).
fn view_from(receipt: &Receipt, target: AgentId) -> ReceiptView<'_> {
    // Reuse the same evidence-extraction logic as
    // crates/yutha-control-plane/src/receipt_publisher.rs::build_view,
    // but cap-layer adapter — local since we're not pulling in the
    // PublishingReceiptStore decorator for this in-process scenario.
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

    // Leak owned strings into 'static via Box::leak — ugly, but the
    // engine's ReceiptView<'a> takes &str refs and the scenario
    // doesn't need to free them. A real control plane uses a longer-
    // lived owned struct (`EnforcementReceiptView`) that converts
    // through a borrowed view for the engine call.
    let principal_id_static: Option<&'static str> =
        principal_id_owned.map(|s| &*Box::leak(s.into_boxed_str()));
    let deny_reason_static: Option<&'static str> =
        deny_reason_owned.map(|s| &*Box::leak(s.into_boxed_str()));
    let forbid_rule_id_static: Option<&'static str> =
        forbid_rule_id_owned.map(|s| &*Box::leak(s.into_boxed_str()));

    ReceiptView {
        action_kind: Box::leak(receipt.action_kind.clone().into_boxed_str()),
        principal_id: principal_id_static,
        deny_reason: deny_reason_static,
        forbid_rule_id: forbid_rule_id_static,
        occurred_at_unix_ns: receipt.occurred_at.monotonic_ns,
        occurred_at_wall_clock: Box::leak(receipt.occurred_at.wall_clock.clone().into_boxed_str()),
        reputation_delta: reputation_delta_owned,
    }
}

async fn build_alice_cap(
    swarm_id: SwarmId,
    alice_id: AgentId,
    alice_signer: &dyn Signer,
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
        .sign(alice_signer)
        .await
        .expect("sign cap")
}

/// Synthetic wall-clock advance — returns an RFC 3339 string in the
/// future. Drives [`EnforcementEngine::poll_scheduled`] without
/// touching `tokio::time`. Each call returns a strictly later
/// timestamp by adding `seconds_offset` to a fixed base far enough
/// past any timestamp `Timestamp::now()` might mint during the run.
fn advance_seconds(seconds_offset: u64) -> String {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    // Base year 2100 ensures we're past anything `Timestamp::now()`
    // produces during the scenario.
    let base = OffsetDateTime::parse("2100-01-01T00:00:00Z", &Rfc3339).expect("parse base");
    let advanced = base + time::Duration::seconds(seconds_offset as i64);
    advanced.format(&Rfc3339).expect("format")
}

async fn count_receipts_with_kind_and_reason(
    receipts: &dyn ReceiptStore,
    action_kind: &str,
    deny_reason: &str,
) -> u64 {
    let page = receipts
        .query(
            Query::ByActionKind(ActionKindQuery {
                action_kind: action_kind.into(),
            }),
            None,
        )
        .await
        .expect("query receipts");
    page.receipts
        .iter()
        .filter(|r| {
            r.evidence
                .iter()
                .any(|e| e.key == "deny_reason" && e.value == deny_reason.as_bytes())
        })
        .count() as u64
}

// =============================================================================
// Test
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn s4_enforcement_chain_runs_end_to_end() {
        let outcome = run_s4().await;
        assert_eq!(
            outcome,
            S4Outcome {
                eval_deny_receipts: 2,
                detect_receipts: 1,
                coach_receipts: 1,
                quarantine_receipts: 1,
                evict_receipts: 1,
                quarantined_cap_denies: 1,
                agent_was_quarantined: true,
            }
        );
    }
}

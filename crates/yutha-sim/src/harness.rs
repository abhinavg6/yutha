//! [`SimulationHarness`] — orchestrates the in-memory stack +
//! persona loop.
//!
//! ## Lifecycle
//!
//! 1. [`SimulationHarness::new`] reads + activates the constitution,
//!    stands up the in-memory substrate (receipt store, passport
//!    store, capability store, Cedar+ evaluator, enforcement
//!    engine), registers each agent's passport, and constructs every
//!    persona via the supplied [`PersonaRegistry`].
//! 2. [`SimulationHarness::run`] drives the persona loop for up to
//!    [`crate::ScenarioConfig::steps`] steps, advancing wall-clock by
//!    [`crate::ScenarioConfig::tick_ms`] between steps. On exit it
//!    returns a fully-populated [`crate::SimulationOutcome`].
//!
//! ## Per-step loop semantics
//!
//! For each step `s`:
//!
//! - Build a [`crate::SimContext`] for each persona populated with
//!   the receipts emitted during step `s-1` and the persona's
//!   `i_am_quarantined` flag read from
//!   [`yutha_cedar_plus::EnforcementEngine::is_agent_quarantined`].
//! - Sequentially call each persona's
//!   [`crate::Persona::step`]. Personas returning `Some(intent)`
//!   have the intent materialised into a
//!   [`yutha_cedar_plus::EvaluationRequest`] against
//!   `Yutha::Action::SendEnvelope` and fed through the evaluator.
//!   Pass and deny both emit a
//!   `constitution.evaluate.{pass,deny}` receipt; deny receipts
//!   loopback through
//!   [`yutha_cedar_plus::EnforcementEngine::on_receipt`] which may
//!   surface enforcement effects.
//! - Each surfaced effect emits the appropriate
//!   `enforcement.{detect,coach,quarantine,evict,reverse}` receipt
//!   and loopbacks through the engine (which special-cases
//!   `enforcement.*` to apply reputation deltas without triggering
//!   further effects).
//! - At the end of the step the harness advances wall-clock and
//!   calls
//!   [`yutha_cedar_plus::EnforcementEngine::poll_scheduled`] to
//!   surface any scheduler-driven stage transitions; those follow
//!   the same emit + loopback path.
//! - If every persona returned `None` during this step the harness
//!   exits the loop with [`crate::TerminalReason::AllPersonasIdle`].
//!
//! ## What the harness does NOT do
//!
//! - **No network.** Substrate is fully in-memory.
//! - **No anchoring.** No [`yutha_receipt::SealStore`] is wired in —
//!   replay-store-equivalent invariant: simulation receipts MUST NOT
//!   be anchored to a live ledger.
//! - **No capability layer enforcement.** The simulation harness
//!   does NOT run Send-path cap-checks. Personas reason about cap
//!   scope by setting `EnvelopeIntent::capability_id` for evidence
//!   propagation, but the harness doesn't emit
//!   `capability.check.*` receipts. That's a 3e follow-on if
//!   personas start needing it; the three canonical personas
//!   (support / refund_attacker / broken_tool) don't.

use std::collections::HashMap;
use std::sync::Arc;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use yutha_cedar_plus::{
    canonical_schema_v1_1, parse_engine_config_yaml, CedarPlusEvaluator, Constitution,
    ConstitutionEvaluator, ConstitutionLoader, Decision, EnforcementEffect, EnforcementEngine,
    EntityRecord, EntitySnapshot, EntityUid, EvaluationOutcome, EvaluationRequest, ReceiptView,
};
use yutha_core::{AgentId, Hash, HashAlgorithm, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_passport::{
    ControlPlaneIdentity, MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore,
    PassportTier,
};
use yutha_receipt::{
    AppendOptions, Evidence, MemoryStore as MemoryReceiptStore, PassportResolver, Receipt,
    ReceiptStore, SignatureRole, SignedBy,
};
use yutha_signer::{InProcessSigner, Signer};

use crate::error::{Result, SimError};
use crate::outcome::{PersonaState, SimulationOutcome, TerminalReason};
use crate::persona::{EnvelopeIntent, Persona, SimContext};
use crate::registry::PersonaRegistry;
use crate::scenario::ScenarioConfig;

/// In-process simulation harness. Constructed once via
/// [`SimulationHarness::new`], run via
/// [`SimulationHarness::run`]. Not re-runnable — drop after use.
pub struct SimulationHarness {
    /// Scenario config (kept for budget + tick_ms access).
    scenario: ScenarioConfig,
    /// In-memory substrate.
    swarm_id: SwarmId,
    receipts: Arc<dyn ReceiptStore>,
    /// Kept alive so registered passports survive the simulation
    /// even though we don't query the store post-setup.
    #[allow(dead_code)]
    passports: Arc<dyn PassportStore>,
    /// Threaded into every `ReceiptStore::append` so the memory
    /// backend can verify actor signatures.
    resolver: Arc<dyn PassportResolver>,
    cp: Arc<ControlPlaneIdentity>,
    evaluator: Arc<CedarPlusEvaluator>,
    engine: Arc<EnforcementEngine>,
    constitution_hash: Hash,
    constitution_version: String,
    /// Per-persona state: persona, agent_id, intents_emitted counter.
    agents: Vec<HarnessAgent>,
    /// Synthetic wall-clock base used by [`advance_wall_clock`].
    wall_clock_base: OffsetDateTime,
}

/// One persona's runtime state inside the harness.
struct HarnessAgent {
    persona: Box<dyn Persona>,
    agent_id: AgentId,
    name: String,
    intents_emitted: u32,
}

impl SimulationHarness {
    /// Stand up the in-memory stack, activate the constitution, and
    /// instantiate every persona. The harness is ready to
    /// [`run`](Self::run) after this returns.
    ///
    /// ## Errors
    ///
    /// - [`SimError::Io`] / [`SimError::ConstitutionLoad`] on
    ///   missing or malformed constitution files.
    /// - [`SimError::Setup`] on substrate construction failures
    ///   (passport register, constitution activate).
    /// - [`SimError::UnknownPersona`] when a YAML agent's
    ///   discriminator isn't in `registry`.
    /// - [`SimError::PersonaConfig`] when a persona constructor
    ///   refuses its config blob.
    pub async fn new(scenario: ScenarioConfig, registry: &PersonaRegistry) -> Result<Self> {
        let swarm_id = SwarmId::new();
        let receipts: Arc<dyn ReceiptStore> = Arc::new(MemoryReceiptStore::new());
        let passports: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
        let resolver: Arc<dyn PassportResolver> =
            Arc::new(PassportResolverAdapter::new(Arc::clone(&passports)));

        // Control-plane identity — signs every receipt the harness
        // emits.
        let cp_signer = InProcessSigner::generate();
        let cp_agent_id = AgentId::new();
        let cp_passport = signed_passport(swarm_id, cp_agent_id, &cp_signer, "control plane")
            .await
            .map_err(|e| SimError::Setup(format!("sign cp passport: {e}")))?;
        passports
            .register(cp_passport)
            .await
            .map_err(|e| SimError::Setup(format!("register cp passport: {e}")))?;
        let cp = Arc::new(ControlPlaneIdentity::new(
            cp_agent_id,
            Arc::new(cp_signer) as Arc<dyn Signer>,
        ));

        // Constitution layer.
        let schema = canonical_schema_v1_1()
            .map_err(|e| SimError::Setup(format!("canonical schema v1.1: {e}")))?;
        let loader = ConstitutionLoader::with_default_bounds(schema);
        let evaluator = Arc::new(CedarPlusEvaluator::with_default_bounds(loader));
        let engine = Arc::new(EnforcementEngine::new());

        let constitution = build_constitution_from_paths(swarm_id, &scenario).await?;
        evaluator
            .activate(constitution)
            .await
            .map_err(|e| SimError::ConstitutionLoad(format!("activate: {e}")))?;
        let active = evaluator
            .current()
            .await
            .ok_or_else(|| SimError::Setup("constitution not active after activate".into()))?;
        engine.activate(active.clone()).await;
        let constitution_hash = active.constitution.constitution_hash.clone();
        let constitution_version = active.constitution.constitution_version.clone();
        drop(active);

        // Materialise each persona — register a passport, mint an
        // agent_id, hand off to the registry-supplied constructor.
        let mut agents: Vec<HarnessAgent> = Vec::with_capacity(scenario.agents.len());
        for (idx, agent_cfg) in scenario.agents.iter().enumerate() {
            let signer = InProcessSigner::generate();
            let agent_id = AgentId::new();
            let owner = format!("{}#{idx}", agent_cfg.persona);
            let passport = signed_passport(swarm_id, agent_id, &signer, &owner)
                .await
                .map_err(|e| SimError::Setup(format!("sign passport for {owner}: {e}")))?;
            passports
                .register(passport)
                .await
                .map_err(|e| SimError::Setup(format!("register passport for {owner}: {e}")))?;

            let persona = registry.build(
                &agent_cfg.persona,
                owner.clone(),
                agent_id,
                agent_cfg.config.clone(),
            )?;
            agents.push(HarnessAgent {
                persona,
                agent_id,
                name: owner,
                intents_emitted: 0,
            });
        }

        // Synthetic wall-clock base. Same pattern as the S4 helper:
        // start in 2100 so `Timestamp::now()` calls scattered through
        // the substrate never race the synthetic clock.
        let wall_clock_base = OffsetDateTime::parse("2100-01-01T00:00:00Z", &Rfc3339)
            .map_err(|e| SimError::Setup(format!("parse base wall-clock: {e}")))?;

        Ok(Self {
            scenario,
            swarm_id,
            receipts,
            passports,
            resolver,
            cp,
            evaluator,
            engine,
            constitution_hash,
            constitution_version,
            agents,
            wall_clock_base,
        })
    }

    /// Run the persona loop. Consumes `self`; returns
    /// [`SimulationOutcome`] with the full receipt log and
    /// per-persona terminal state.
    pub async fn run(mut self) -> Result<SimulationOutcome> {
        let mut all_receipts: Vec<Receipt> = Vec::new();
        let mut last_step_receipts: Vec<Receipt> = Vec::new();
        let mut total_steps: u32 = 0;
        let mut terminal_reason = TerminalReason::BudgetExhausted;

        for step in 0..self.scenario.steps {
            total_steps = step + 1;
            let step_wall_clock =
                advance_wall_clock(self.wall_clock_base, step, self.scenario.tick_ms);
            let step_now = Timestamp::new(
                step_wall_clock.clone(),
                monotonic_for_step(step, self.scenario.tick_ms),
            )
            .map_err(|e| SimError::Step(format!("mint step timestamp: {e}")))?;
            let mut emissions_this_step = 0u32;
            let mut receipts_this_step: Vec<Receipt> = Vec::new();

            for idx in 0..self.agents.len() {
                let agent_id = self.agents[idx].agent_id;
                let i_am_quarantined = self
                    .engine
                    .is_agent_quarantined(&agent_id.to_string())
                    .await;

                let ctx = SimContext {
                    self_id: agent_id,
                    now: step_now.clone(),
                    step,
                    recent_receipts: last_step_receipts.clone(),
                    i_am_quarantined,
                    constitution_hash: self.constitution_hash.clone(),
                    swarm_id: self.swarm_id,
                };

                let intent_opt = self.agents[idx].persona.step(&ctx).await;
                let Some(intent) = intent_opt else { continue };
                emissions_this_step += 1;
                self.agents[idx].intents_emitted += 1;

                // Materialise into eval request + evaluate.
                let request = build_eval_request(
                    &self.constitution_hash,
                    self.swarm_id,
                    agent_id,
                    &intent,
                    &step_now,
                );
                let outcome = self
                    .evaluator
                    .evaluate(request)
                    .await
                    .map_err(|e| SimError::Step(format!("evaluate intent: {e}")))?;

                // Emit constitution.evaluate.{pass,deny} receipt +
                // feed back through the engine.
                let receipt = self
                    .emit_constitution_eval_receipt(agent_id, &outcome, &step_now)
                    .await?;
                receipts_this_step.push(receipt.clone());
                let effects = self.engine.on_receipt(view_from(&receipt, agent_id)).await;

                // Cascade any returned enforcement effects.
                for effect in effects {
                    let emitted = self
                        .emit_effect_with_loopback(&effect, agent_id, &step_now)
                        .await?;
                    receipts_this_step.push(emitted);
                }
            }

            // Drain any time-triggered stage transitions.
            let scheduler_effects = self.engine.poll_scheduled(&step_wall_clock).await;
            for effect in scheduler_effects {
                // The effect's target_agent_id string is the source
                // of truth — find the matching agent for the
                // loopback view.
                let target_agent = self
                    .agents
                    .iter()
                    .find(|a| a.agent_id.to_string() == effect.target_agent_id)
                    .map(|a| a.agent_id)
                    .unwrap_or(self.cp.agent_id);
                let emitted = self
                    .emit_effect_with_loopback(&effect, target_agent, &step_now)
                    .await?;
                receipts_this_step.push(emitted);
            }

            all_receipts.extend(receipts_this_step.iter().cloned());

            if emissions_this_step == 0 {
                terminal_reason = TerminalReason::AllPersonasIdle;
                break;
            }

            last_step_receipts = receipts_this_step;
        }

        // Finalise every persona.
        let finalize_ctx_base = SimContext {
            self_id: AgentId::new(), // placeholder, replaced per-agent
            now: Timestamp::now(),
            step: total_steps,
            recent_receipts: last_step_receipts.clone(),
            i_am_quarantined: false,
            constitution_hash: self.constitution_hash.clone(),
            swarm_id: self.swarm_id,
        };
        for agent in self.agents.iter_mut() {
            let mut ctx = finalize_ctx_base.clone();
            ctx.self_id = agent.agent_id;
            ctx.i_am_quarantined = self
                .engine
                .is_agent_quarantined(&agent.agent_id.to_string())
                .await;
            agent.persona.finalize(&ctx).await;
        }

        let persona_states = self
            .agents
            .iter()
            .map(|a| PersonaState {
                name: a.name.clone(),
                agent_id: a.agent_id,
                intents_emitted: a.intents_emitted,
                final_note: None, // finalize() hook can't set this in 3e-C; reserved for a follow-on
            })
            .collect();

        Ok(SimulationOutcome {
            receipts: all_receipts,
            persona_states,
            total_steps,
            terminal_reason,
        })
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    async fn emit_constitution_eval_receipt(
        &self,
        subject: AgentId,
        outcome: &EvaluationOutcome,
        now: &Timestamp,
    ) -> Result<Receipt> {
        let action_kind = match outcome.decision {
            Decision::Permit => "constitution.evaluate.pass",
            Decision::Deny => "constitution.evaluate.deny",
        };
        let mut evidence = vec![
            Evidence::new(
                "constitution_hash",
                "type.yutha.dev/v1/Hash",
                self.constitution_hash.digest.clone(),
            ),
            Evidence::new(
                "subject_agent_id",
                "type.yutha.dev/v1/AgentId",
                subject.to_string().into_bytes(),
            ),
        ];
        if matches!(outcome.decision, Decision::Deny) {
            evidence.push(Evidence::new(
                "deny_reason",
                "type.yutha.dev/v1/String",
                outcome
                    .deny_reason
                    .as_deref()
                    .unwrap_or("forbid_rule_matched")
                    .as_bytes()
                    .to_vec(),
            ));
        }
        append_receipt(
            &*self.receipts,
            &*self.resolver,
            &self.cp,
            self.swarm_id,
            action_kind,
            &self.constitution_version,
            evidence,
            now.clone(),
        )
        .await
    }

    async fn emit_effect_with_loopback(
        &self,
        effect: &EnforcementEffect,
        target: AgentId,
        now: &Timestamp,
    ) -> Result<Receipt> {
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
                self.constitution_hash.digest.clone(),
            ),
        ];
        for (k, v) in &effect.additional_evidence {
            evidence.push(Evidence::new(
                k.as_str(),
                "type.yutha.dev/v1/Json",
                serde_json::to_vec(v)
                    .map_err(|e| SimError::Step(format!("encode additional evidence: {e}")))?,
            ));
        }
        let receipt = append_receipt(
            &*self.receipts,
            &*self.resolver,
            &self.cp,
            self.swarm_id,
            &effect.action_kind,
            &self.constitution_version,
            evidence,
            now.clone(),
        )
        .await?;
        // Loopback — engine special-cases enforcement.* kinds, applies
        // reputation deltas, returns no further effects.
        let _ = self.engine.on_receipt(view_from(&receipt, target)).await;
        Ok(receipt)
    }
}

// =============================================================================
// Free helpers
// =============================================================================

/// Read + parse the scenario's constitution files and bundle them
/// into a [`Constitution`] ready for activation.
async fn build_constitution_from_paths(
    swarm_id: SwarmId,
    scenario: &ScenarioConfig,
) -> Result<Constitution> {
    let cedar_source = tokio::fs::read_to_string(&scenario.constitution.cedar_path)
        .await
        .map_err(|e| {
            SimError::ConstitutionLoad(format!(
                "read cedar {:?}: {e}",
                scenario.constitution.cedar_path
            ))
        })?;
    let engine_yaml = tokio::fs::read_to_string(&scenario.constitution.engine_config_path)
        .await
        .map_err(|e| {
            SimError::ConstitutionLoad(format!(
                "read engine config {:?}: {e}",
                scenario.constitution.engine_config_path
            ))
        })?;
    let engine_config = parse_engine_config_yaml(&engine_yaml)
        .map_err(|e| SimError::ConstitutionLoad(format!("parse engine config: {e}")))?;
    Ok(Constitution {
        constitution_hash: Hash::new(HashAlgorithm::Sha256, vec![0xCCu8; 32])
            .map_err(|e| SimError::Setup(format!("synth hash: {e}")))?,
        spec_version: SpecVersion::parse("1.0.0")
            .map_err(|e| SimError::Setup(format!("spec version: {e}")))?,
        schema_version: engine_config.schema_version.clone(),
        constitution_version: "simulation".into(),
        parent_version: None,
        swarm_id,
        cedar_source,
        engine_config,
        issued_at: Timestamp::now(),
    })
}

async fn signed_passport(
    swarm_id: SwarmId,
    agent_id: AgentId,
    signer: &dyn Signer,
    owner: &str,
) -> std::result::Result<Passport, String> {
    Passport::builder()
        .spec_version(SpecVersion::parse("1.0.0").map_err(|e| format!("spec version: {e}"))?)
        .agent_id(agent_id)
        .swarm_id(swarm_id)
        .agent_public_key(signer.public_key())
        .owner(owner)
        .accepted_constitution_version("1.0.0")
        .tier(PassportTier::Minimal)
        .issued_at(Timestamp::now())
        .sign(signer)
        .await
        .map_err(|e| format!("sign passport: {e}"))
}

/// Build an [`EvaluationRequest`] for an [`EnvelopeIntent`].
///
/// Targets the canonical `Yutha::Action::SendEnvelope` action. The
/// persona's payload_schema_id + tags + cost estimates surface into
/// the Cedar context so policy `when` clauses can gate on them.
fn build_eval_request(
    constitution_hash: &Hash,
    swarm_id: SwarmId,
    principal_id: AgentId,
    intent: &EnvelopeIntent,
    now: &Timestamp,
) -> EvaluationRequest {
    let principal_str = principal_id.to_string();
    let swarm_str = swarm_id.to_string();
    let recipient_str = intent.recipient.to_string();

    let mut context_attrs: HashMap<String, serde_json::Value> = HashMap::new();
    context_attrs.insert(
        "payload_schema_id".into(),
        serde_json::Value::String(intent.payload_schema_id.clone()),
    );
    context_attrs.insert(
        "performative".into(),
        serde_json::Value::String(intent.performative.clone()),
    );
    context_attrs.insert(
        "tags".into(),
        serde_json::Value::Array(
            intent
                .tags
                .iter()
                .map(|t| serde_json::Value::String(t.clone()))
                .collect(),
        ),
    );
    context_attrs.insert(
        "estimated_cost_usd_cents".into(),
        serde_json::Value::Number(intent.estimated_cost_usd_cents.into()),
    );
    context_attrs.insert(
        "estimated_cost_tool_calls".into(),
        serde_json::Value::Number(intent.estimated_cost_tool_calls.into()),
    );
    context_attrs.insert(
        "estimated_cost_compute_ms".into(),
        serde_json::Value::Number(intent.estimated_cost_compute_ms.into()),
    );
    context_attrs.insert(
        "current_wall_clock".into(),
        serde_json::Value::String(now.wall_clock.clone()),
    );
    // The canonical schema v1.1 declares `current_time_unix_ns:
    // Long` on every action's context — strict validation rejects
    // requests that omit it, even when no policy references it.
    // See `spec/constitution/schema.cedarschema`.
    context_attrs.insert(
        "current_time_unix_ns".into(),
        serde_json::Value::Number(now.monotonic_ns.into()),
    );
    // The schema declares `capability_id: String` as required; the
    // empty string is the convention for "no cap presented" (per
    // `crates/yutha-conformance/src/scenarios/s4_enforcement_loop.rs`).
    context_attrs.insert(
        "capability_id".into(),
        serde_json::Value::String(intent.capability_id.clone().unwrap_or_default()),
    );

    let entities = vec![
        agent_entity(&principal_str, &swarm_str),
        agent_entity(&recipient_str, &swarm_str),
        swarm_entity(&swarm_str, "closed", "simulation"),
    ];

    EvaluationRequest {
        constitution_hash: constitution_hash.clone(),
        schema_version: "1.1.0".into(),
        action_kind: "Yutha::Action::SendEnvelope".into(),
        principal_id,
        resource_uid: EntityUid::new("Yutha::Agent", recipient_str),
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

/// Build + sign + append a receipt. Mirrors
/// [`crates/yutha-conformance/src/scenarios/s4_enforcement_loop.rs::append_receipt`].
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
) -> Result<Receipt> {
    let mut builder = Receipt::builder()
        .spec_version(
            SpecVersion::parse("1.0.0")
                .map_err(|e| SimError::Step(format!("spec version: {e}")))?,
        )
        .swarm_id(swarm_id)
        .actor(cp.agent_id)
        .action_kind(action_kind)
        .constitution_version(constitution_version)
        .occurred_at(occurred_at);
    for e in evidence {
        builder = builder.evidence(e);
    }
    let mut receipt = builder
        .build()
        .map_err(|e| SimError::Step(format!("build receipt: {e}")))?;
    let bytes = receipt
        .canonical_bytes()
        .map_err(|e| SimError::Step(format!("canonical bytes: {e}")))?;
    let sig = cp
        .sign(&bytes)
        .await
        .map_err(|e| SimError::Step(format!("cp sign: {e}")))?;
    receipt
        .signatures
        .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));
    receipts
        .append(receipt.clone(), AppendOptions::default(), resolver)
        .await
        .map_err(|e| SimError::Step(format!("append receipt: {e}")))?;
    Ok(receipt)
}

/// Build a [`ReceiptView`] borrowing from `receipt`. Same Box::leak
/// trick the S4 scenario uses — fine for short-lived simulation
/// runs, but a real production reader uses a longer-lived owned
/// struct (`EnforcementReceiptView` in the control plane).
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

/// Synthetic wall-clock for step `step` given `tick_ms` between
/// steps. Base is 2100-01-01 so we never collide with
/// `Timestamp::now()` calls inside the substrate.
fn advance_wall_clock(base: OffsetDateTime, step: u32, tick_ms: u32) -> String {
    let offset_ms = (step as i64) * (tick_ms as i64);
    let advanced = base + time::Duration::milliseconds(offset_ms);
    advanced.format(&Rfc3339).expect("format step wall-clock")
}

/// Synthetic monotonic_ns counter matching `advance_wall_clock`. The
/// 2100-base offset is large enough that the engine's counter prune
/// (which uses occurred_at_unix_ns) sees the simulation steps as
/// strictly increasing.
fn monotonic_for_step(step: u32, tick_ms: u32) -> u64 {
    // Offset by ~10^18 to stay above any monotonic_ns Timestamp::now
    // could produce.
    const BASE: u64 = 4_102_444_800_000_000_000; // ns at 2100-01-01
    BASE + (step as u64) * (tick_ms as u64) * 1_000_000
}

//! 3e-B substrate smoke test.
//!
//! Pure compile-and-construct exercise. Confirms that:
//!
//! - The [`Persona`] trait surface is async-trait–dispatchable.
//! - The [`SimContext`], [`EnvelopeIntent`], [`ScenarioConfig`],
//!   [`SimulationOutcome`] types construct without trait-bound
//!   surprises.
//! - The serde-derived round-trip on
//!   [`SimulationOutcome`], [`ScenarioConfig`], and
//!   [`TerminalReason`] survives the `yutha-receipt[serde]` +
//!   `yutha-core[serde]` feature gates.
//!
//! No driver logic — that lands in 3e-C.

use async_trait::async_trait;
use yutha_core::{AgentId, Hash, HashAlgorithm, SwarmId, Timestamp};
use yutha_sim::{
    AgentConfig, ConstitutionConfig, EnvelopeIntent, Persona, PersonaState, ScenarioConfig,
    SimContext, SimulationOutcome, TerminalReason,
};

/// Minimal persona impl — proves the async-trait wiring closes
/// over `dyn Persona`.
struct EchoPersona {
    name: String,
}

#[async_trait]
impl Persona for EchoPersona {
    fn name(&self) -> &str {
        &self.name
    }

    async fn step(&mut self, ctx: &SimContext) -> Option<EnvelopeIntent> {
        // Only emit on step 0 — proves SimContext.step is readable.
        if ctx.step == 0 {
            Some(EnvelopeIntent::request_to(
                AgentId::new(),
                "type.yutha.dev/v1/Text",
            ))
        } else {
            None
        }
    }
}

#[tokio::test]
async fn persona_trait_is_object_safe_and_callable() {
    let mut persona: Box<dyn Persona> = Box::new(EchoPersona {
        name: "echo#alpha".into(),
    });

    let ctx = SimContext {
        self_id: AgentId::new(),
        now: Timestamp::now(),
        step: 0,
        recent_receipts: Vec::new(),
        i_am_quarantined: false,
        constitution_hash: Hash::new(HashAlgorithm::Sha256, vec![0u8; 32]).unwrap(),
        swarm_id: SwarmId::new(),
    };

    let out = persona.step(&ctx).await;
    assert!(out.is_some(), "EchoPersona must emit on step 0");
    let intent = out.unwrap();
    assert_eq!(intent.performative, "REQUEST");
    assert_eq!(intent.payload_schema_id, "type.yutha.dev/v1/Text");
}

#[test]
fn scenario_config_round_trips_through_serde_json() {
    let cfg = ScenarioConfig {
        constitution: ConstitutionConfig {
            cedar_path: "./constitution.cedar".into(),
            engine_config_path: "./constitution.engine.yaml".into(),
        },
        agents: vec![
            AgentConfig {
                persona: "support_agent".into(),
                config: serde_json::json!({ "name_suffix": "alice" }),
            },
            AgentConfig {
                persona: "refund_attacker".into(),
                config: serde_json::Value::Null,
            },
        ],
        steps: 50,
        tick_ms: 100,
    };

    let bytes = serde_json::to_vec(&cfg).expect("serialize");
    let back: ScenarioConfig = serde_json::from_slice(&bytes).expect("deserialize");
    assert_eq!(back.steps, 50);
    assert_eq!(back.tick_ms, 100);
    assert_eq!(back.agents.len(), 2);
    assert_eq!(back.agents[0].persona, "support_agent");
}

#[test]
fn simulation_outcome_round_trips_through_serde_json() {
    let outcome = SimulationOutcome {
        receipts: Vec::new(),
        persona_states: vec![PersonaState {
            name: "support_agent#alice".into(),
            agent_id: AgentId::new(),
            intents_emitted: 7,
            final_note: Some("idle on quarantine".into()),
        }],
        total_steps: 30,
        terminal_reason: TerminalReason::AllPersonasIdle,
    };

    let bytes = serde_json::to_vec(&outcome).expect("serialize");
    let back: SimulationOutcome = serde_json::from_slice(&bytes).expect("deserialize");
    assert_eq!(back.total_steps, 30);
    assert_eq!(back.terminal_reason, TerminalReason::AllPersonasIdle);
    assert_eq!(back.persona_states.len(), 1);
    assert_eq!(back.persona_states[0].intents_emitted, 7);
    assert_eq!(
        back.persona_states[0].final_note.as_deref(),
        Some("idle on quarantine")
    );
}

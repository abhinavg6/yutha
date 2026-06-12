//! Persona 1: well-behaved support agent.
//!
//! Generates a steady stream of well-formed support-queue envelopes.
//! Designed never to trip a Cedar `forbid` rule under a baseline
//! constitution, and to **stop emitting** the moment it's
//! quarantined — proving the persona is policy-respecting rather
//! than only behaviour-driven.
//!
//! Useful as:
//!
//! - **Baseline noise** alongside an adversarial persona, so that
//!   receipt-count assertions can distinguish "denied" from "didn't
//!   send".
//! - **Smoke check** that a candidate constitution doesn't
//!   accidentally deny well-formed support traffic — if SupportAgent
//!   gets denied, the constitution is wrong.
//!
//! ## YAML config (deserialised from
//! [`crate::AgentConfig::config`])
//!
//! Every field is optional. The defaults produce a low-cost
//! `REQUEST` envelope with a `support` tag, no capability, and
//! `"type.yutha.dev/v1/Text"` payload — well within any reasonable
//! Cedar policy's permit set.
//!
//! ```yaml
//! agents:
//!   - persona: support_agent
//!     config:
//!       # Deterministic recipient. Omit → persona mints a fresh
//!       # UUID v7 at construction time and reuses it.
//!       recipient_agent_id: "01923456-789a-7000-8000-000000000001"
//!       # Default: "type.yutha.dev/v1/Text".
//!       payload_schema_id: "type.yutha.dev/v1/Text"
//!       # Default: "support: please look at this ticket".
//!       message_text: "support: please look at ticket T-9001"
//!       # Default: ["support"].
//!       tags: ["support", "low-priority"]
//!       # Default: None. Surfaces into Cedar context only;
//!       # harness does not run Send-path cap-check.
//!       capability_id: "support-send"
//!       # Default: 5 cents per envelope (typical small message).
//!       estimated_cost_usd_cents: 5
//! ```

use async_trait::async_trait;
use serde::Deserialize;
use yutha_core::AgentId;

use crate::error::{Result, SimError};
use crate::persona::{EnvelopeIntent, Persona, SimContext};
use crate::registry::PersonaRegistry;

/// Per-instance YAML config for a [`SupportAgent`].
#[derive(Debug, Clone, Deserialize)]
pub struct SupportAgentConfig {
    /// Deterministic recipient. UUID v7 string. `None` → mint a
    /// fresh id at construction time.
    #[serde(default)]
    pub recipient_agent_id: Option<String>,

    /// Cedar `context.payload_schema_id`. Default
    /// `"type.yutha.dev/v1/Text"`.
    #[serde(default = "default_payload_schema_id")]
    pub payload_schema_id: String,

    /// Body of the envelope. Serialised verbatim into
    /// `EnvelopeIntent.payload_bytes`.
    #[serde(default = "default_message_text")]
    pub message_text: String,

    /// Free-form tags surfaced into Cedar `context.tags`. Default
    /// `["support"]`.
    #[serde(default = "default_tags")]
    pub tags: Vec<String>,

    /// Optional capability id. Surfaces into Cedar context only —
    /// the harness does not run Send-path cap-check.
    #[serde(default)]
    pub capability_id: Option<String>,

    /// USD-cents estimate carried into Cedar `context.cost_*`
    /// attrs + the [`EnvelopeIntent`]. Default `5`.
    #[serde(default = "default_cost_usd_cents")]
    pub estimated_cost_usd_cents: u64,
}

impl Default for SupportAgentConfig {
    fn default() -> Self {
        Self {
            recipient_agent_id: None,
            payload_schema_id: default_payload_schema_id(),
            message_text: default_message_text(),
            tags: default_tags(),
            capability_id: None,
            estimated_cost_usd_cents: default_cost_usd_cents(),
        }
    }
}

fn default_payload_schema_id() -> String {
    "type.yutha.dev/v1/Text".into()
}

fn default_message_text() -> String {
    "support: please look at this ticket".into()
}

fn default_tags() -> Vec<String> {
    vec!["support".into()]
}

fn default_cost_usd_cents() -> u64 {
    5
}

/// Well-behaved support persona. Emits a steady REQUEST stream to a
/// fixed recipient until quarantined.
pub struct SupportAgent {
    name: String,
    #[allow(dead_code)] // surfaced via Persona::name; kept for future debug logging
    agent_id: AgentId,
    config: SupportAgentConfig,
    recipient: AgentId,
    emissions: u32,
}

impl SupportAgent {
    /// Persona discriminator surfaced in YAML scenarios.
    pub const DISCRIMINATOR: &'static str = "support_agent";

    /// Constructor used by the [`PersonaRegistry`]. Deserialises
    /// `raw_config` into a [`SupportAgentConfig`] and resolves the
    /// recipient.
    pub fn build(
        name: String,
        agent_id: AgentId,
        raw_config: serde_json::Value,
    ) -> Result<Box<dyn Persona>> {
        let config: SupportAgentConfig = if raw_config.is_null() {
            SupportAgentConfig::default()
        } else {
            serde_json::from_value(raw_config).map_err(|source| SimError::PersonaConfig {
                persona: Self::DISCRIMINATOR.into(),
                source,
            })?
        };
        let recipient = match &config.recipient_agent_id {
            Some(s) => parse_agent_id(s)?,
            None => AgentId::new(),
        };
        Ok(Box::new(Self {
            name,
            agent_id,
            config,
            recipient,
            emissions: 0,
        }))
    }

    /// Register this persona on `registry` under
    /// [`Self::DISCRIMINATOR`].
    pub fn register(registry: &mut PersonaRegistry) {
        registry.register(Self::DISCRIMINATOR, Self::build);
    }
}

#[async_trait]
impl Persona for SupportAgent {
    fn name(&self) -> &str {
        &self.name
    }

    async fn step(&mut self, ctx: &SimContext) -> Option<EnvelopeIntent> {
        // Well-behaved persona — if the engine has quarantined us,
        // stop sending. (A baseline constitution should never
        // quarantine SupportAgent; this branch is defence in depth.)
        if ctx.i_am_quarantined {
            return None;
        }
        self.emissions += 1;
        Some(EnvelopeIntent {
            performative: "REQUEST".into(),
            recipient: self.recipient,
            payload_schema_id: self.config.payload_schema_id.clone(),
            payload_bytes: self.config.message_text.clone().into_bytes(),
            tags: self.config.tags.clone(),
            capability_id: self.config.capability_id.clone(),
            estimated_cost_usd_cents: self.config.estimated_cost_usd_cents,
            estimated_cost_tool_calls: 0,
            estimated_cost_compute_ms: 0,
        })
    }

    async fn finalize(&mut self, _ctx: &SimContext) {
        // Reserved for the 3e-J PersonaState.final_note wire-up.
    }
}

/// Parse an [`AgentId`] from a UUID string. Maps the parse error
/// through [`SimError::PersonaConfig`] so config-time failures look
/// identical to other persona config failures.
fn parse_agent_id(s: &str) -> Result<AgentId> {
    use serde::de::Error;
    let uuid = uuid::Uuid::parse_str(s).map_err(|e| SimError::PersonaConfig {
        persona: SupportAgent::DISCRIMINATOR.into(),
        source: serde_json::Error::custom(format!("invalid recipient_agent_id {s:?}: {e}")),
    })?;
    Ok(AgentId(uuid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_with_null_config_uses_defaults() {
        let p = SupportAgent::build(
            "support#alice".into(),
            AgentId::new(),
            serde_json::Value::Null,
        )
        .expect("build");
        assert_eq!(p.name(), "support#alice");
    }

    #[test]
    fn build_with_explicit_config_parses() {
        let cfg = serde_json::json!({
            "recipient_agent_id": "01923456-789a-7000-8000-000000000001",
            "payload_schema_id": "type.example.com/v1/Echo",
            "message_text": "hi",
            "tags": ["echo"],
            "capability_id": "support-send",
            "estimated_cost_usd_cents": 7
        });
        let p = SupportAgent::build("support#bob".into(), AgentId::new(), cfg).expect("build");
        assert_eq!(p.name(), "support#bob");
    }

    #[test]
    fn build_with_invalid_recipient_uuid_errors() {
        let cfg = serde_json::json!({ "recipient_agent_id": "not-a-uuid" });
        // Can't use `unwrap_err` — Box<dyn Persona> isn't Debug.
        match SupportAgent::build("x".into(), AgentId::new(), cfg) {
            Ok(_) => panic!("expected error, got Ok"),
            Err(SimError::PersonaConfig { persona, .. }) => assert_eq!(persona, "support_agent"),
            Err(other) => panic!("expected PersonaConfig, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn step_emits_intent_when_not_quarantined() {
        use yutha_core::{Hash, HashAlgorithm, SwarmId, Timestamp};
        let mut p = SupportAgent::build(
            "support#alpha".into(),
            AgentId::new(),
            serde_json::Value::Null,
        )
        .expect("build");
        let ctx = SimContext {
            self_id: AgentId::new(),
            now: Timestamp::now(),
            step: 0,
            recent_receipts: Vec::new(),
            i_am_quarantined: false,
            constitution_hash: Hash::new(HashAlgorithm::Sha256, vec![0u8; 32]).unwrap(),
            swarm_id: SwarmId::new(),
        };
        let intent = p.step(&ctx).await.expect("emits");
        assert_eq!(intent.performative, "REQUEST");
        assert_eq!(intent.payload_schema_id, "type.yutha.dev/v1/Text");
        assert_eq!(intent.tags, vec!["support".to_string()]);
        assert_eq!(intent.estimated_cost_usd_cents, 5);
    }

    #[tokio::test]
    async fn step_goes_idle_when_quarantined() {
        use yutha_core::{Hash, HashAlgorithm, SwarmId, Timestamp};
        let mut p = SupportAgent::build(
            "support#alpha".into(),
            AgentId::new(),
            serde_json::Value::Null,
        )
        .expect("build");
        let ctx = SimContext {
            self_id: AgentId::new(),
            now: Timestamp::now(),
            step: 0,
            recent_receipts: Vec::new(),
            i_am_quarantined: true,
            constitution_hash: Hash::new(HashAlgorithm::Sha256, vec![0u8; 32]).unwrap(),
            swarm_id: SwarmId::new(),
        };
        assert!(p.step(&ctx).await.is_none());
    }
}

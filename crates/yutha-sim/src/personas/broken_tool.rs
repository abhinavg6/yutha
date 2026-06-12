//! Persona 3: broken-tool agent.
//!
//! Simulates the most common "tool-misuse" failure mode: an agent
//! that emits envelopes without attaching the right capability_id
//! and with an out-of-scope `payload_schema_id`. A well-written
//! constitution will deny these via a Cedar `forbid` rule on the
//! sentinel schema id, and the resulting
//! `constitution.evaluate.deny` receipts loopback through the
//! enforcement engine to fire the four-stage chain.
//!
//! ## What's "broken" about it
//!
//! The persona is stateless and unaware of its own
//! misbehaviour. Every step it emits the same shape:
//!
//! - `capability_id: None` (default) — no cap attached
//! - `payload_schema_id` — operator-configurable sentinel
//!   (default `"type.yutha.dev/v1/UnscopedAction"`)
//! - `tags` includes `"broken-tool"` for receipt-side filtering
//!
//! This is intentionally narrower than a sprawling fuzzer. The
//! goal is to drive a deterministic deny + enforcement chain, not
//! to characterise every possible misuse.
//!
//! ## Pairing constitution
//!
//! For BrokenTool to actually trip the enforcement chain, the
//! constitution must include a Cedar `forbid` rule matching the
//! sentinel `payload_schema_id`, plus an `enforcement_rules` entry
//! whose detect trigger fires on
//! `constitution.evaluate.deny`. Without those, BrokenTool emits
//! harmless envelopes that pass Cedar's default permit.
//!
//! Reference Cedar fragment (illustrative — the 3e-J scenario
//! ships a full constitution fixture):
//!
//! ```cedar
//! @id("no-unscoped-actions")
//! forbid (
//!     principal,
//!     action == Yutha::Action::"SendEnvelope",
//!     resource
//! ) when {
//!     context.payload_schema_id == "type.yutha.dev/v1/UnscopedAction"
//! };
//! ```
//!
//! ## YAML config
//!
//! ```yaml
//! agents:
//!   - persona: broken_tool
//!     config:
//!       # Optional. UUID v7 string for the recipient.
//!       recipient_agent_id: "01923456-789a-7000-8000-000000000003"
//!       # The sentinel schema id the constitution forbids.
//!       # Default: "type.yutha.dev/v1/UnscopedAction".
//!       payload_schema_id: "type.yutha.dev/v1/UnscopedAction"
//!       # Free-form tags. "broken-tool" is always prepended.
//!       # Default: [].
//!       tags: ["debug"]
//!       # Optional capability_id. Default None mimics the most
//!       # common broken-tool failure (forgot to attach the cap).
//!       capability_id: null
//!       # Cost estimates carried into Cedar context. Default 0.
//!       estimated_cost_usd_cents: 0
//! ```

use async_trait::async_trait;
use serde::Deserialize;
use yutha_core::AgentId;

use crate::error::{Result, SimError};
use crate::persona::{EnvelopeIntent, Persona, SimContext};
use crate::registry::PersonaRegistry;

/// Per-instance YAML config for a [`BrokenTool`].
#[derive(Debug, Clone, Deserialize)]
pub struct BrokenToolConfig {
    /// Deterministic recipient UUID v7 string. `None` → mint fresh
    /// at construction.
    #[serde(default)]
    pub recipient_agent_id: Option<String>,

    /// Sentinel schema id the constitution forbids. Default
    /// `"type.yutha.dev/v1/UnscopedAction"`.
    #[serde(default = "default_payload_schema_id")]
    pub payload_schema_id: String,

    /// Extra tags. The persona always prepends `"broken-tool"`
    /// regardless of this list. Default empty.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Optional capability id. Default `None` — the most common
    /// broken-tool failure shape.
    #[serde(default)]
    pub capability_id: Option<String>,

    /// USD cents surfaced into Cedar context. Default 0.
    #[serde(default)]
    pub estimated_cost_usd_cents: u64,
}

impl Default for BrokenToolConfig {
    fn default() -> Self {
        Self {
            recipient_agent_id: None,
            payload_schema_id: default_payload_schema_id(),
            tags: Vec::new(),
            capability_id: None,
            estimated_cost_usd_cents: 0,
        }
    }
}

fn default_payload_schema_id() -> String {
    "type.yutha.dev/v1/UnscopedAction".into()
}

/// Stateless tool-misuse persona.
pub struct BrokenTool {
    name: String,
    #[allow(dead_code)] // Surfaced via Persona::name; kept for debug logging.
    agent_id: AgentId,
    config: BrokenToolConfig,
    recipient: AgentId,
    emissions: u32,
}

impl BrokenTool {
    /// Persona discriminator surfaced in YAML scenarios.
    pub const DISCRIMINATOR: &'static str = "broken_tool";

    /// Tag the persona always prepends so downstream receipt
    /// queries can filter by it.
    pub const TAG: &'static str = "broken-tool";

    /// Registry constructor.
    pub fn build(
        name: String,
        agent_id: AgentId,
        raw_config: serde_json::Value,
    ) -> Result<Box<dyn Persona>> {
        let config: BrokenToolConfig = if raw_config.is_null() {
            BrokenToolConfig::default()
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

    /// Register on `registry`.
    pub fn register(registry: &mut PersonaRegistry) {
        registry.register(Self::DISCRIMINATOR, Self::build);
    }

    /// Build the tag list (the persona always prepends
    /// [`Self::TAG`]).
    fn emit_tags(&self) -> Vec<String> {
        let mut t = Vec::with_capacity(self.config.tags.len() + 1);
        t.push(Self::TAG.to_string());
        t.extend(self.config.tags.iter().cloned());
        t
    }
}

#[async_trait]
impl Persona for BrokenTool {
    fn name(&self) -> &str {
        &self.name
    }

    async fn step(&mut self, ctx: &SimContext) -> Option<EnvelopeIntent> {
        // Quarantine respect — same as the other canonical personas.
        if ctx.i_am_quarantined {
            return None;
        }
        self.emissions += 1;
        Some(EnvelopeIntent {
            performative: "REQUEST".into(),
            recipient: self.recipient,
            payload_schema_id: self.config.payload_schema_id.clone(),
            payload_bytes: b"{}".to_vec(),
            tags: self.emit_tags(),
            capability_id: self.config.capability_id.clone(),
            estimated_cost_usd_cents: self.config.estimated_cost_usd_cents,
            estimated_cost_tool_calls: 1,
            estimated_cost_compute_ms: 10,
        })
    }
}

fn parse_agent_id(s: &str) -> Result<AgentId> {
    use serde::de::Error;
    let uuid = uuid::Uuid::parse_str(s).map_err(|e| SimError::PersonaConfig {
        persona: BrokenTool::DISCRIMINATOR.into(),
        source: serde_json::Error::custom(format!("invalid recipient_agent_id {s:?}: {e}")),
    })?;
    Ok(AgentId(uuid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use yutha_core::{Hash, HashAlgorithm, SwarmId, Timestamp};

    fn fresh_ctx(quarantined: bool) -> SimContext {
        SimContext {
            self_id: AgentId::new(),
            now: Timestamp::now(),
            step: 0,
            recent_receipts: Vec::new(),
            i_am_quarantined: quarantined,
            constitution_hash: Hash::new(HashAlgorithm::Sha256, vec![0u8; 32]).unwrap(),
            swarm_id: SwarmId::new(),
        }
    }

    #[test]
    fn build_with_null_config_uses_defaults() {
        let p = BrokenTool::build(
            "broken#alpha".into(),
            AgentId::new(),
            serde_json::Value::Null,
        )
        .expect("build");
        assert_eq!(p.name(), "broken#alpha");
    }

    #[test]
    fn build_with_invalid_recipient_uuid_errors() {
        let cfg = serde_json::json!({ "recipient_agent_id": "not-a-uuid" });
        match BrokenTool::build("x".into(), AgentId::new(), cfg) {
            Ok(_) => panic!("expected error"),
            Err(SimError::PersonaConfig { persona, .. }) => assert_eq!(persona, "broken_tool"),
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn step_emits_sentinel_schema_with_no_cap_by_default() {
        let mut p = BrokenTool::build(
            "broken#alpha".into(),
            AgentId::new(),
            serde_json::Value::Null,
        )
        .expect("build");
        let ctx = fresh_ctx(false);
        let intent = p.step(&ctx).await.expect("emits");
        assert_eq!(intent.payload_schema_id, "type.yutha.dev/v1/UnscopedAction");
        assert!(intent.capability_id.is_none());
        // Tag is always prepended.
        assert_eq!(intent.tags[0], "broken-tool");
    }

    #[tokio::test]
    async fn step_prepends_broken_tool_tag_even_with_extra_tags() {
        let cfg = serde_json::json!({ "tags": ["debug", "scratch"] });
        let mut p = BrokenTool::build("broken#alpha".into(), AgentId::new(), cfg).expect("build");
        let intent = p.step(&fresh_ctx(false)).await.expect("emits");
        assert_eq!(
            intent.tags,
            vec![
                "broken-tool".to_string(),
                "debug".to_string(),
                "scratch".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn step_honours_explicit_capability_id() {
        let cfg = serde_json::json!({ "capability_id": "stale-cap-xyz" });
        let mut p = BrokenTool::build("broken#alpha".into(), AgentId::new(), cfg).expect("build");
        let intent = p.step(&fresh_ctx(false)).await.expect("emits");
        assert_eq!(intent.capability_id.as_deref(), Some("stale-cap-xyz"));
    }

    #[tokio::test]
    async fn step_goes_idle_when_quarantined() {
        let mut p = BrokenTool::build(
            "broken#alpha".into(),
            AgentId::new(),
            serde_json::Value::Null,
        )
        .expect("build");
        assert!(p.step(&fresh_ctx(true)).await.is_none());
    }
}

//! Persona 2: adversarial refund attacker.
//!
//! Generates an escalating stream of refund-request envelopes that
//! probe the constitution's refund-cap forbid rule. The probe
//! amount climbs geometrically every step (default: ×2 per tick),
//! starting at `initial_amount_cents`. The persona surfaces the
//! current probe amount through `EnvelopeIntent.estimated_cost_usd_cents`,
//! which the harness threads into Cedar's `context.estimated_cost_usd_cents` —
//! the same attribute the canonical Cedar+ refund-cap policies key
//! off.
//!
//! ## Adaptive behaviour
//!
//! The persona reads `ctx.recent_receipts` and counts
//! `constitution.evaluate.deny` receipts where the
//! `subject_agent_id` evidence matches its own agent id. The deny
//! counter surfaces into [`Persona::finalize`] as an internal
//! summary; the persona does NOT slow down or back off on
//! deny — the goal is to characterise the deny threshold, not to
//! evade it. The persona DOES go fully idle when
//! `ctx.i_am_quarantined`: it recognises the supervisor signal and
//! stops sending. (Operators wanting an attacker that ignores
//! quarantine should implement a custom persona.)
//!
//! Useful as:
//!
//! - **Threshold characterisation.** Pair against a constitution
//!   with a `refund_amount_cents > THRESHOLD` forbid rule; the
//!   simulation outcome shows exactly how many probes land before
//!   the chain quarantines the persona.
//! - **Constitution-tightening preview.** Run the persona against
//!   the candidate constitution from a diff, count denies/quarantine
//!   step, compare against the same persona's behaviour against
//!   production. This is the regression-test path 3e-J's S13
//!   formalises.
//!
//! ## YAML config
//!
//! ```yaml
//! agents:
//!   - persona: refund_attacker
//!     config:
//!       # Optional. UUID string. Omit → fresh UUID at construct.
//!       recipient_agent_id: "01923456-789a-7000-8000-000000000002"
//!       # Default: "type.yutha.dev/v1/RefundRequest".
//!       payload_schema_id: "type.yutha.dev/v1/RefundRequest"
//!       # Default: 100 cents ($1).
//!       initial_amount_cents: 100
//!       # Default: 2.0. amount *= step_multiplier each step.
//!       # Use 1.0 for linear constant probing.
//!       step_multiplier: 2.0
//!       # Default: ["refund"].
//!       tags: ["refund", "attacker"]
//!       # Default: None. Surfaces into Cedar context only.
//!       capability_id: "refund-attempt"
//! ```

use async_trait::async_trait;
use serde::Deserialize;
use yutha_core::AgentId;

use crate::error::{Result, SimError};
use crate::persona::{EnvelopeIntent, Persona, SimContext};
use crate::registry::PersonaRegistry;

/// Per-instance YAML config for a [`RefundAttacker`].
#[derive(Debug, Clone, Deserialize)]
pub struct RefundAttackerConfig {
    /// Deterministic recipient UUID v7 string. `None` → mint fresh
    /// at construction.
    #[serde(default)]
    pub recipient_agent_id: Option<String>,

    /// Cedar `context.payload_schema_id`. Default
    /// `"type.yutha.dev/v1/RefundRequest"`.
    #[serde(default = "default_payload_schema_id")]
    pub payload_schema_id: String,

    /// Starting probe amount in USD cents. Surfaces into
    /// `EnvelopeIntent.estimated_cost_usd_cents` on step 0. Default
    /// 100 ($1).
    #[serde(default = "default_initial_amount_cents")]
    pub initial_amount_cents: u64,

    /// Geometric escalation factor applied after every emit.
    /// Default 2.0 (probe doubles each step). Use 1.0 for a
    /// linear, constant-amount probe.
    #[serde(default = "default_step_multiplier")]
    pub step_multiplier: f64,

    /// Free-form tags surfaced into Cedar `context.tags`. Default
    /// `["refund"]`.
    #[serde(default = "default_tags")]
    pub tags: Vec<String>,

    /// Optional capability id. Surfaces into Cedar context only.
    #[serde(default)]
    pub capability_id: Option<String>,
}

impl Default for RefundAttackerConfig {
    fn default() -> Self {
        Self {
            recipient_agent_id: None,
            payload_schema_id: default_payload_schema_id(),
            initial_amount_cents: default_initial_amount_cents(),
            step_multiplier: default_step_multiplier(),
            tags: default_tags(),
            capability_id: None,
        }
    }
}

fn default_payload_schema_id() -> String {
    "type.yutha.dev/v1/RefundRequest".into()
}

fn default_initial_amount_cents() -> u64 {
    100
}

fn default_step_multiplier() -> f64 {
    2.0
}

fn default_tags() -> Vec<String> {
    vec!["refund".into()]
}

/// Escalating adversarial refund probe.
pub struct RefundAttacker {
    name: String,
    agent_id: AgentId,
    config: RefundAttackerConfig,
    recipient: AgentId,
    /// Current probe amount in USD cents. Updated after each emit.
    current_amount_cents: u64,
    /// Total emits across the simulation.
    probes_emitted: u32,
    /// Number of `constitution.evaluate.deny` receipts attributed
    /// to this persona during the simulation. Surfaces in
    /// [`Persona::finalize`].
    denies_observed: u32,
    /// Amount on the LAST emit. Useful to surface the threshold the
    /// persona was probing when it got quarantined.
    last_probe_amount_cents: u64,
}

impl RefundAttacker {
    /// Persona discriminator surfaced in YAML scenarios.
    pub const DISCRIMINATOR: &'static str = "refund_attacker";

    /// Registry constructor.
    pub fn build(
        name: String,
        agent_id: AgentId,
        raw_config: serde_json::Value,
    ) -> Result<Box<dyn Persona>> {
        let config: RefundAttackerConfig = if raw_config.is_null() {
            RefundAttackerConfig::default()
        } else {
            serde_json::from_value(raw_config).map_err(|source| SimError::PersonaConfig {
                persona: Self::DISCRIMINATOR.into(),
                source,
            })?
        };
        if !config.step_multiplier.is_finite() || config.step_multiplier <= 0.0 {
            return Err(invalid_config(format!(
                "step_multiplier must be > 0 and finite; got {}",
                config.step_multiplier
            )));
        }
        let recipient = match &config.recipient_agent_id {
            Some(s) => parse_agent_id(s)?,
            None => AgentId::new(),
        };
        let current_amount_cents = config.initial_amount_cents;
        Ok(Box::new(Self {
            name,
            agent_id,
            config,
            recipient,
            current_amount_cents,
            probes_emitted: 0,
            denies_observed: 0,
            last_probe_amount_cents: 0,
        }))
    }

    /// Register on `registry`.
    pub fn register(registry: &mut PersonaRegistry) {
        registry.register(Self::DISCRIMINATOR, Self::build);
    }

    /// Count receipts in `recent_receipts` that are
    /// `constitution.evaluate.deny` and attribute (via
    /// `subject_agent_id` evidence) to this persona's agent.
    fn count_denies_in_recent(&self, ctx: &SimContext) -> u32 {
        let self_id_str = self.agent_id.to_string();
        let mut count = 0u32;
        for receipt in &ctx.recent_receipts {
            if receipt.action_kind != "constitution.evaluate.deny" {
                continue;
            }
            for ev in &receipt.evidence {
                if ev.key == "subject_agent_id" {
                    if let Ok(s) = std::str::from_utf8(&ev.value) {
                        if s == self_id_str {
                            count += 1;
                            break;
                        }
                    }
                }
            }
        }
        count
    }

    /// Advance the probe amount according to `step_multiplier`.
    /// Saturates on overflow. The f64 math accepts the usual
    /// precision loss for u64s past 2^53 — the probe amounts we
    /// realistically care about ($1 to $1B) are well inside that
    /// range, and operators chasing strict-integer probe arithmetic
    /// should implement a custom persona.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]
    fn escalate(&mut self) {
        let scaled = (self.current_amount_cents as f64) * self.config.step_multiplier;
        // Cap at u64::MAX to avoid panic on overflow when the
        // operator picks an exuberant multiplier.
        self.current_amount_cents = if scaled.is_finite() && scaled < (u64::MAX as f64) {
            scaled as u64
        } else {
            u64::MAX
        };
    }
}

#[async_trait]
impl Persona for RefundAttacker {
    fn name(&self) -> &str {
        &self.name
    }

    async fn step(&mut self, ctx: &SimContext) -> Option<EnvelopeIntent> {
        // Record any denies that landed on the previous step
        // attributable to us. Used in finalize note.
        self.denies_observed += self.count_denies_in_recent(ctx);

        // Quarantine respect: recognise the supervisor signal, go
        // idle. (Removing this branch would let the persona keep
        // emitting even after quarantine — but the harness's
        // engine will continue denying so it'd be noise without
        // signal.)
        if ctx.i_am_quarantined {
            return None;
        }

        let amount = self.current_amount_cents;
        self.last_probe_amount_cents = amount;
        self.probes_emitted += 1;
        let intent = EnvelopeIntent {
            performative: "REQUEST".into(),
            recipient: self.recipient,
            payload_schema_id: self.config.payload_schema_id.clone(),
            // The payload bytes carry the amount as a JSON literal
            // so an evaluator that wants to inspect the raw payload
            // (vs. context.estimated_cost_usd_cents) has a place to
            // look.
            payload_bytes: format!("{{\"refund_amount_cents\":{amount}}}").into_bytes(),
            tags: self.config.tags.clone(),
            capability_id: self.config.capability_id.clone(),
            estimated_cost_usd_cents: amount,
            estimated_cost_tool_calls: 1,
            estimated_cost_compute_ms: 50,
        };
        self.escalate();
        Some(intent)
    }

    async fn finalize(&mut self, _ctx: &SimContext) {
        // Final-note surfacing is wired in 3e-J. For now we just
        // freeze internal counters — they're available via the
        // 3e-C PersonaState path once the harness pulls
        // persona-private state into the rendered outcome.
    }
}

/// Parse an [`AgentId`] from a UUID string.
fn parse_agent_id(s: &str) -> Result<AgentId> {
    let uuid = uuid::Uuid::parse_str(s)
        .map_err(|e| invalid_config(format!("invalid recipient_agent_id {s:?}: {e}")))?;
    Ok(AgentId(uuid))
}

fn invalid_config(msg: String) -> SimError {
    use serde::de::Error;
    SimError::PersonaConfig {
        persona: RefundAttacker::DISCRIMINATOR.into(),
        source: serde_json::Error::custom(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yutha_core::{Hash, HashAlgorithm, SwarmId, Timestamp};

    fn fresh_ctx(quarantined: bool, recent: Vec<yutha_receipt::Receipt>) -> SimContext {
        SimContext {
            self_id: AgentId::new(),
            now: Timestamp::now(),
            step: 0,
            recent_receipts: recent,
            i_am_quarantined: quarantined,
            constitution_hash: Hash::new(HashAlgorithm::Sha256, vec![0u8; 32]).unwrap(),
            swarm_id: SwarmId::new(),
        }
    }

    #[test]
    fn build_with_null_config_uses_defaults() {
        let p = RefundAttacker::build("ra#m".into(), AgentId::new(), serde_json::Value::Null)
            .expect("build");
        assert_eq!(p.name(), "ra#m");
    }

    #[test]
    fn build_rejects_non_finite_multiplier() {
        let cfg = serde_json::json!({ "step_multiplier": "not a number" });
        // serde_json deserialization error first.
        match RefundAttacker::build("x".into(), AgentId::new(), cfg) {
            Ok(_) => panic!("expected error"),
            Err(SimError::PersonaConfig { persona, .. }) => assert_eq!(persona, "refund_attacker"),
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn build_rejects_zero_multiplier() {
        let cfg = serde_json::json!({ "step_multiplier": 0.0 });
        match RefundAttacker::build("x".into(), AgentId::new(), cfg) {
            Ok(_) => panic!("expected error"),
            Err(SimError::PersonaConfig { persona, source }) => {
                assert_eq!(persona, "refund_attacker");
                assert!(source.to_string().contains("step_multiplier"));
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn first_step_emits_initial_amount() {
        let mut p = RefundAttacker::build(
            "ra#m".into(),
            AgentId::new(),
            serde_json::json!({ "initial_amount_cents": 250 }),
        )
        .expect("build");
        let ctx = fresh_ctx(false, Vec::new());
        let intent = p.step(&ctx).await.expect("emits");
        assert_eq!(intent.estimated_cost_usd_cents, 250);
        assert_eq!(intent.performative, "REQUEST");
        // Payload bytes encode the same amount.
        let body = std::str::from_utf8(&intent.payload_bytes).unwrap();
        assert!(body.contains("\"refund_amount_cents\":250"));
    }

    #[tokio::test]
    async fn subsequent_steps_escalate_geometrically() {
        let mut p = RefundAttacker::build(
            "ra#m".into(),
            AgentId::new(),
            serde_json::json!({
                "initial_amount_cents": 100,
                "step_multiplier": 3.0,
            }),
        )
        .expect("build");
        let ctx = fresh_ctx(false, Vec::new());
        let first = p.step(&ctx).await.expect("emit 0");
        assert_eq!(first.estimated_cost_usd_cents, 100);
        let second = p.step(&ctx).await.expect("emit 1");
        assert_eq!(second.estimated_cost_usd_cents, 300);
        let third = p.step(&ctx).await.expect("emit 2");
        assert_eq!(third.estimated_cost_usd_cents, 900);
    }

    #[tokio::test]
    async fn step_goes_idle_when_quarantined() {
        let mut p = RefundAttacker::build("ra#m".into(), AgentId::new(), serde_json::Value::Null)
            .expect("build");
        let ctx = fresh_ctx(true, Vec::new());
        assert!(p.step(&ctx).await.is_none());
    }
}

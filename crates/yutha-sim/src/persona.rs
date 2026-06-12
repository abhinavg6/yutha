//! [`Persona`] trait + the values it sees and emits.
//!
//! These three types are the surface a persona author works against.
//! The 3e-C harness wires them into the in-memory stack; the YAML
//! loader (3e-G) materialises persona implementations from a string
//! discriminator; the CLI subcommand (3e-H) and Python wrapper
//! (3e-I) consume the trait output without re-implementing any of
//! it.

use async_trait::async_trait;
use yutha_core::{AgentId, Hash, SwarmId, Timestamp};
use yutha_receipt::Receipt;

/// A simulation participant. One `Persona` impl per behavioural
/// archetype (well-behaved, adversarial, broken, …).
///
/// The harness calls `step()` once per simulation step in declaration
/// order. Personas are NOT concurrent — sequential execution keeps
/// the receipt stream deterministic and the resulting outcome
/// reproducible.
///
/// ## Reactive behaviour
///
/// Personas observe the previous step's emissions through
/// [`SimContext::recent_receipts`]. This is enough to express
/// adversarial back-off ("on Cedar deny, escalate amount"), graceful
/// surrender ("on quarantine, go idle"), and probe-and-retry
/// loops. The harness intentionally does NOT hand personas the full
/// receipt log — keeping context narrow forces personas to be
/// behaviour-driven rather than oracle-driven.
///
/// ## Lifecycle
///
/// 1. Harness constructs the persona once.
/// 2. `step()` runs up to `ScenarioConfig::steps` times.
/// 3. `finalize()` runs once at the end. Personas use it to surface
///    internal state (probe counters, theory-of-mind notes) into
///    [`crate::PersonaState::final_note`].
#[async_trait]
pub trait Persona: Send + Sync {
    /// Human-readable name, surfaced in the rendered simulation
    /// outcome. Convention: `archetype#instance` (e.g.
    /// `support_agent#alice`, `refund_attacker#mallory`).
    fn name(&self) -> &str;

    /// Called once per simulation step.
    ///
    /// Return `Some(intent)` to emit an envelope this step. Return
    /// `None` to skip — the persona is idle for this tick. When
    /// EVERY persona returns `None` in a single step, the harness
    /// considers the simulation complete and exits with
    /// [`crate::TerminalReason::AllPersonasIdle`] regardless of the
    /// remaining step budget.
    async fn step(&mut self, ctx: &SimContext) -> Option<EnvelopeIntent>;

    /// Optional finalize hook. Called once after the last step.
    /// Default impl is a no-op.
    async fn finalize(&mut self, _ctx: &SimContext) {}
}

/// Read-only view of the simulation state the harness hands each
/// persona at the top of every step.
///
/// Fields are intentionally narrow — see [`Persona`] docs for why.
#[derive(Debug, Clone)]
pub struct SimContext {
    /// This persona's agent id.
    pub self_id: AgentId,

    /// Current simulated wall-clock. Advances by
    /// [`crate::ScenarioConfig::tick_ms`] between steps.
    pub now: Timestamp,

    /// 0-based step index. `0` on the first call to `step()`.
    pub step: u32,

    /// Receipts emitted during the PREVIOUS step, in emission
    /// order. Empty on step `0`. The harness fills this from the
    /// in-memory receipt store after each step's Send-path completes
    /// + the enforcement engine has drained its scheduler.
    ///
    /// Personas use this to react: see a `constitution.evaluate.deny`
    /// addressed to `self_id`, change strategy on the next step.
    pub recent_receipts: Vec<Receipt>,

    /// `true` iff the EnforcementEngine has the persona's agent
    /// marked quarantined as of the previous step's settlement. A
    /// well-behaved persona returns `None` while quarantined; an
    /// adversarial persona may probe to verify the quarantine
    /// actually denies its sends.
    pub i_am_quarantined: bool,

    /// Content-address of the active constitution. Useful for
    /// personas that compare their own theory of the rules against
    /// the activated rule set across sub-scenarios.
    pub constitution_hash: Hash,

    /// Swarm the simulation runs against. Personas wanting to send
    /// to roles or topic addresses use this to construct the
    /// recipient.
    pub swarm_id: SwarmId,
}

/// A persona's emission. A neutral description of an envelope the
/// harness fills in with signer + monotonic_ns + swarm_id before
/// materialising into a signed [`yutha_passport::Envelope`] and
/// driving the in-memory Send path.
///
/// ## Why not just emit an [`yutha_passport::Envelope`] directly?
///
/// Personas would have to know about the signer-handle the harness
/// owns, generate their own monotonic_ns, set `from_swarm` etc. —
/// boilerplate the harness already has the answer to. `EnvelopeIntent`
/// is the "what the persona wants to say" half; the harness owns
/// the "how the envelope is shaped" half.
///
/// ## Performative
///
/// String for portability with the YAML format. The harness maps it
/// to the canonical [`yutha_core::Performative`] enum at materialise
/// time and returns [`crate::SimError::Step`] if the string is
/// unrecognised.
#[derive(Debug, Clone)]
pub struct EnvelopeIntent {
    /// Performative name — `"REQUEST"`, `"INFORM"`, `"PROPOSE"`,
    /// etc. Case-insensitive on the way in; the harness mapper does
    /// the lookup.
    pub performative: String,

    /// Recipient. Construct via [`AgentId::role`] for role-addressed
    /// envelopes; the harness sets the right
    /// [`yutha_passport::Recipient`] shape downstream.
    pub recipient: AgentId,

    /// Payload schema id — the canonical type URI for the payload
    /// bytes (e.g. `"type.yutha.dev/v1/Text"`).
    pub payload_schema_id: String,

    /// Payload bytes — the persona's choice of serialisation.
    /// Cedar+ sees the SHA-256 fingerprint of these bytes in
    /// `context.payload_digest`, not the raw bytes themselves.
    pub payload_bytes: Vec<u8>,

    /// Free-form tags surfaced into Cedar's
    /// `context.tags`. Personas use this to declare topic shape
    /// (e.g. `["refund", "high-value"]`).
    pub tags: Vec<String>,

    /// Optional capability id to attach. When `None`, the Send path
    /// runs the cap-check with no capability — usually denied
    /// unless the constitution explicitly permits no-cap sends from
    /// the persona's principal class.
    pub capability_id: Option<String>,

    /// Estimated USD cents for the work this envelope would
    /// require. Surfaces into Cedar+ scoring rules + budget
    /// procedures.
    pub estimated_cost_usd_cents: u64,

    /// Estimated tool-call count for this envelope.
    pub estimated_cost_tool_calls: u64,

    /// Estimated compute-ms for this envelope.
    pub estimated_cost_compute_ms: u64,
}

impl EnvelopeIntent {
    /// Convenience constructor for the common case — REQUEST
    /// performative, no cap, zero-cost. Personas tweak the
    /// individual fields afterwards.
    pub fn request_to(recipient: AgentId, payload_schema_id: impl Into<String>) -> Self {
        Self {
            performative: "REQUEST".into(),
            recipient,
            payload_schema_id: payload_schema_id.into(),
            payload_bytes: Vec::new(),
            tags: Vec::new(),
            capability_id: None,
            estimated_cost_usd_cents: 0,
            estimated_cost_tool_calls: 0,
            estimated_cost_compute_ms: 0,
        }
    }
}

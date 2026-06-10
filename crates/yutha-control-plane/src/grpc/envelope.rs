//! `EnvelopeService` gRPC handler.
//!
//! Bridges the two RPCs from
//! [`/spec/control-plane/v1.proto`](../../../../spec/control-plane/v1.proto)
//! to the in-process [`Transport`](yutha_transport::Transport):
//!
//! - [`EnvelopeHandler::send`] — unary. Validates the bearer (and that
//!   the envelope's `from_agent` matches the bearer's `agent_id` to
//!   prevent spoofing), then delegates to `Transport::send`. Returns the
//!   `envelope.send` receipt's content-address.
//! - [`EnvelopeHandler::subscribe`] — server-streaming. Opens a
//!   long-lived subscription on the transport and forwards every
//!   delivered envelope + its `envelope.deliver` receipt id back to the
//!   client. Cancelling the stream cleanly ends the subscription.
//!
//! ## Auth and routing rules
//!
//! - `Send` checks that `envelope.from_agent == auth.agent_id`. Cross-
//!   agent sending is not currently permitted; the spec leaves room for
//!   future delegate-style flows, but until they're defined we reject.
//! - `Subscribe` requires the request's `agent_id` (if set) to equal the
//!   bearer's `agent_id`. An empty `agent_id` defaults to the bearer's —
//!   prevents an authenticated caller from eavesdropping on a different
//!   agent's inbox.
//!
//! ## Stream lifecycle
//!
//! The transport's `subscribe` returns a `Stream<(Envelope, Hash)>`.
//! This handler maps each item to a `SubscribedEnvelope` proto + maps
//! `TransportError` to `tonic::Status` via the existing
//! `ErrorIntoStatus` trait. When the client cancels the gRPC stream,
//! tonic drops the response stream → the forwarder task inside
//! `MemoryTransport::subscribe` notices `tx.send` errored and shuts
//! itself down.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use futures::StreamExt;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::debug;
use yutha_capability::ActionDescriptor;
use yutha_cedar_plus::{
    Decision, EnforcementEngine, EntityRecord, EntitySnapshot, EntityUid, EvaluationOutcome,
    EvaluationRequest,
};
use yutha_core::{AgentId, Hash, SpecVersion, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_crypto::hash::sha256;
use yutha_passport::{PassportStore, PassportTier};
use yutha_proto::control_plane::v1::{
    envelope_service_server::EnvelopeService, SendEnvelopeRequest, SendEnvelopeResponse,
    SubscribeRequest, SubscribedEnvelope,
};
use yutha_receipt::{AppendOptions, Evidence, Receipt, SignatureRole, SignedBy};
use yutha_transport::{Envelope, Recipient};

use crate::auth::require_active_bearer_auth;

use super::error::{missing_field, ErrorIntoStatus};
use super::ControlPlaneState;

pub struct EnvelopeHandler {
    state: Arc<ControlPlaneState>,
}

impl EnvelopeHandler {
    pub fn new(state: Arc<ControlPlaneState>) -> Self {
        Self { state }
    }
}

/// Render a [`Recipient`] as the string form used in an
/// [`ActionDescriptor`]'s `recipient` field.
///
/// The format is stable and lets caveats (e.g. `OnlyIfTaggedCaveat`
/// targeting `agent:<id>`) match deterministically across runs. Not
/// part of any wire protocol — purely the substrate's internal
/// descriptor representation.
fn recipient_descriptor_string(r: &Recipient) -> String {
    match r {
        Recipient::Agent(id) => format!("agent:{id}"),
        Recipient::Role(role) => format!("role:{role}"),
        Recipient::Swarm(b) if b.filter_tags.is_empty() => "swarm:*".to_string(),
        Recipient::Swarm(b) => format!("swarm:{}", b.filter_tags.join(",")),
        Recipient::External(e) => {
            format!("external:{}://{}{}", e.scheme, e.authority, e.path_hint)
        }
    }
}

/// Construct an [`EvaluationRequest`] for a SendEnvelope action, plus a
/// minimal [`EntitySnapshot`] containing the sender Agent + Swarm.
///
/// Phase 3a (post-3a-3): the snapshot's `Yutha::Agent` entities carry
/// real `framework` / `passport_tier` / `passport_hash` from the
/// passport store and real `reputation` from the enforcement engine
/// snapshot via [`resolve_agent_attrs`]. Cedar policies keying on
/// those four attrs now fire honestly — previously they silently
/// degraded to permit-all because every entity had placeholder
/// values. Budgets stay at `i64::MAX` until budget norms
/// (RFC 0011 §4) ship in the engine.
///
/// Originally F10d kept the snapshot lean and intentionally
/// placeholder-populated; this fn is the unblock for task #282 that
/// the simulation + observability pillars (Phases 3b–3g) both depend
/// on.
// 9 params (was 7 pre-Phase-3a; passport_store + enforcement joined
// for the resolver wiring). Same posture as `bootstrap_backends` in
// main.rs and the s1/s4–s7 conformance scenarios — bundling these
// into a config struct would obscure the parameter origins (cli/
// state-derived vs evaluation-derived) without buying call-site
// clarity, since the only call site is `EnvelopeHandler::send`.
#[allow(clippy::too_many_arguments)]
async fn build_eval_request_for_send(
    constitution_hash: Hash,
    principal_id: &AgentId,
    envelope: &Envelope,
    cap_id: Option<&Hash>,
    swarm_id: &yutha_core::SwarmId,
    constitution_version: &str,
    topology_mode: &str,
    passport_store: &dyn PassportStore,
    enforcement: &EnforcementEngine,
) -> EvaluationRequest {
    let principal_uid_str = principal_id.to_string();
    let swarm_uid_str = swarm_id.to_string();

    // Resource UID depends on the recipient variant. For Agent
    // recipients we hand Cedar a Yutha::Agent; for Role / Swarm /
    // External we hand Cedar a Yutha::Resource carrying the
    // recipient's kind + identifier in its `resource_kind` / `scope`
    // attrs. The schema's SendEnvelope.appliesTo accepts all three
    // (Agent / Envelope / Resource) per v1.1.x.
    //
    // `resource_snapshot` is `Some(...)` exactly when we need to add
    // a Resource entity to the entity snapshot below; for Agent
    // recipients the snapshot already contains the agent entity and
    // there's nothing extra to add.
    let (resource_uid, resource_snapshot) = match &envelope.recipient {
        Recipient::Agent(id) => (EntityUid::new("Yutha::Agent", id.to_string()), None),
        Recipient::Role(role) => {
            let uid = format!("role:{role}");
            let entity = resource_entity(&uid, "role", role, &[]);
            (EntityUid::new("Yutha::Resource", uid), Some(entity))
        }
        Recipient::Swarm(b) => {
            let scope = if b.filter_tags.is_empty() {
                "*".to_string()
            } else {
                b.filter_tags.join(",")
            };
            let uid = format!("swarm:{scope}");
            let entity = resource_entity(&uid, "swarm", &scope, &b.filter_tags);
            (EntityUid::new("Yutha::Resource", uid), Some(entity))
        }
        Recipient::External(e) => {
            let scope = format!("{}://{}{}", e.scheme, e.authority, e.path_hint);
            let uid = format!("external:{scope}");
            let entity = resource_entity(&uid, "external", &scope, &[]);
            (EntityUid::new("Yutha::Resource", uid), Some(entity))
        }
    };

    // Entity snapshot — sender Agent (parented under Swarm) + the
    // Swarm + (optionally) the recipient Agent. Every entity carries
    // the FULL attribute surface the v1.1 canonical schema declares,
    // because Cedar's Strict-mode entity validation rejects partial
    // entities even when no policy reads the missing attrs.
    //
    // `resolve_agent_attrs` populates `framework` / `passport_tier` /
    // `passport_hash` from the passport store (Phase 3a-2) and
    // `reputation` from the enforcement engine snapshot (Phase 3a-3)
    // for both sender and (if different) recipient. `budget_remaining_*`
    // stays at `i64::MAX` until budget norms (RFC 0011 §4) ship in the
    // engine — Cedar policies that gate on budgets silently permit-all
    // until then. Honest signal; not a wiring bug.
    let now = Timestamp::now();
    let sender_attrs = resolve_agent_attrs(principal_id, passport_store, enforcement).await;
    let mut entities = vec![
        agent_entity(&principal_uid_str, &swarm_uid_str, &sender_attrs),
        swarm_entity(&swarm_uid_str, topology_mode, constitution_version),
    ];
    // Only add the recipient when it's a *different* agent — Cedar
    // rejects duplicate entity entries, which self-sends would
    // otherwise produce (the sender entity is already in the list).
    if let Recipient::Agent(rid) = &envelope.recipient {
        if rid != principal_id {
            let recipient_attrs = resolve_agent_attrs(rid, passport_store, enforcement).await;
            entities.push(agent_entity(
                &rid.to_string(),
                &swarm_uid_str,
                &recipient_attrs,
            ));
        }
    }
    // Non-Agent recipients (Role / Swarm / External) need their
    // synthesized Yutha::Resource entity in the snapshot too — Cedar
    // resolves attribute accesses on `resource` against the snapshot,
    // so a missing entity here would surface as "resource has no
    // attr X" during eval rather than a clean policy decision.
    if let Some(entity) = resource_snapshot {
        entities.push(entity);
    }
    let entity_snapshot = EntitySnapshot { entities };

    // Action-context fields the schema's SendEnvelope expects per
    // schema.cedarschema. Zeros for the budget/cost dimensions
    // (F11+ wires real values from the SDK). The capability_id
    // field tells policies which cap the sender presented.
    let mut context_attrs: HashMap<String, serde_json::Value> = HashMap::new();
    context_attrs.insert(
        "performative".into(),
        serde_json::Value::String(format!("{:?}", envelope.performative)),
    );
    context_attrs.insert(
        "payload_schema_id".into(),
        serde_json::Value::String(envelope.payload_schema_id.clone()),
    );
    context_attrs.insert(
        "tags".into(),
        serde_json::Value::Array(
            envelope
                .tags
                .iter()
                .map(|t| serde_json::Value::String(t.clone()))
                .collect(),
        ),
    );
    context_attrs.insert(
        "capability_id".into(),
        serde_json::Value::String(cap_id.map(|h| hex::encode(&h.digest)).unwrap_or_default()),
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

    EvaluationRequest {
        constitution_hash,
        schema_version: "1.1.0".into(),
        action_kind: "SendEnvelope".into(),
        principal_id: *principal_id,
        resource_uid,
        context_attrs,
        entity_snapshot,
        current_wall_clock: now.wall_clock.clone(),
        current_time_unix_ns: now.monotonic_ns,
    }
}

/// Pre-resolved Cedar `Yutha::Agent` entity attrs for the gRPC
/// constitution-evaluation path. Decouples I/O (passport store +
/// enforcement engine lookups) from data shaping (entity record
/// construction) so [`agent_entity`] stays sync and trivially
/// testable.
///
/// **Phase 3a posture:**
///
/// - `framework`, `passport_tier`, `passport_hash` — real values from
///   the passport store (Phase 3a-2).
/// - `reputation` — real current scalar from the enforcement engine
///   (Phase 3a-3). Never-seen agents get the engine default `"1.0"`,
///   which equals the placeholder.
/// - `budget_remaining_*` — placeholder `i64::MAX`. Budget norms
///   (RFC 0011 §4) are not yet tracked in the engine; until they
///   are, Cedar policies that gate on `principal.budget_remaining_*`
///   silently permit-all because every check compares against
///   `MAX`. Honest signal; not a wiring bug.
struct ResolvedAgentAttrs {
    framework: String,
    passport_tier: String,
    /// Hex SHA256 over canonical Passport bytes (64 hex chars).
    passport_hash: String,
    /// Cedar decimal-form string.
    reputation: String,
    budget_remaining_usd_cents: i64,
    budget_remaining_tool_calls: i64,
    budget_remaining_compute_ms: i64,
}

impl ResolvedAgentAttrs {
    /// Defaults used for agents the passport store doesn't know
    /// about, or as the starting shape that [`resolve_agent_attrs`]
    /// overwrites field-by-field with real values.
    ///
    /// Today the sender path always has a passport (bearer auth
    /// verified it before send); the only case this fires is a
    /// cross-agent envelope to a recipient that hasn't registered.
    fn placeholder() -> Self {
        Self {
            framework: String::new(),
            passport_tier: "minimal".into(),
            passport_hash: "0".repeat(64),
            reputation: "1.0".into(),
            budget_remaining_usd_cents: i64::MAX,
            budget_remaining_tool_calls: i64::MAX,
            budget_remaining_compute_ms: i64::MAX,
        }
    }
}

/// Render a [`PassportTier`] as the lowercase Cedar string form the
/// v1.1 canonical schema expects (`"minimal" / "standard" /
/// "verifiable"`).
fn passport_tier_str(t: PassportTier) -> &'static str {
    match t {
        PassportTier::Minimal => "minimal",
        PassportTier::Standard => "standard",
        PassportTier::Verifiable => "verifiable",
    }
}

/// Resolve the per-agent Cedar attrs for the gRPC `EvaluateEnvelope`
/// path against the v1.1 canonical schema.
///
/// Two independent reads — a [`PassportStore`] lookup for the
/// passport-derived attrs and an [`EnforcementEngine::get_agent_state`]
/// snapshot for reputation — composed into a single
/// [`ResolvedAgentAttrs`] before [`agent_entity`] consumes it.
///
/// **Honest fields (Phase 3a-2 + 3a-3):**
///
/// - `framework`, `passport_tier`, `passport_hash` — real passport
///   values for registered agents; placeholders on miss (see
///   below). `passport_hash` is SHA256 over canonical Passport bytes,
///   hex-encoded.
/// - `reputation` — real current reputation from the enforcement
///   engine. Never-seen agents get `"1.0"` (matches both the engine
///   default and the placeholder), so the call is safe to make
///   unconditionally before the passport lookup.
///
/// **Still placeholder:** `budget_remaining_*` stays at `i64::MAX`
/// because budget norms (RFC 0011 §4) aren't yet tracked in the
/// engine. When they ship, `AgentSnapshot::budgets` becomes `Some(_)`
/// and this resolver will read from it directly.
///
/// **Passport-lookup failure handling.** Three paths fall back to the
/// passport-store half of [`ResolvedAgentAttrs::placeholder`] with a
/// `tracing::warn!`:
///
/// 1. Passport not in the store (an unregistered cross-agent
///    recipient; the sender path is always present because bearer
///    auth verified it).
/// 2. Passport store lookup errored (transport / backend failure).
/// 3. Canonical-bytes serialization errored (substrate bug — shouldn't
///    happen, but we'd rather permit-all-degradation than a 500).
///
/// All three keep the gRPC call alive; Cedar policies keying on the
/// real passport-derived attrs degrade to permit-all for that one
/// entity. Reputation is still honest in every fallback path because
/// it's read independently.
async fn resolve_agent_attrs(
    agent_id: &AgentId,
    passport_store: &dyn PassportStore,
    enforcement: &EnforcementEngine,
) -> ResolvedAgentAttrs {
    let mut attrs = ResolvedAgentAttrs::placeholder();

    // Reputation read is independent of the passport lookup and
    // always honest: `get_agent_state` returns `"1.0"` for agents
    // the engine has never seen, matching the placeholder default.
    // Budgets stay at `i64::MAX` until budget norms (RFC 0011 §4)
    // are tracked in the engine — `snapshot.budgets` is `None`
    // today by design.
    let snapshot = enforcement.get_agent_state(&agent_id.to_string()).await;
    attrs.reputation = snapshot.reputation.0.clone();

    // Passport-derived attrs. Failures fall through with a warn;
    // reputation we set above is preserved regardless.
    match passport_store.lookup(agent_id).await {
        Ok(Some(passport)) => {
            attrs.framework = passport.framework.clone();
            attrs.passport_tier = passport_tier_str(passport.tier).to_string();
            attrs.passport_hash = match passport.canonical_bytes() {
                Ok(bytes) => hex::encode(&sha256(&bytes).digest),
                Err(e) => {
                    tracing::warn!(
                        agent_id = %agent_id,
                        error = %e,
                        "passport canonical_bytes failed; falling back to all-zero passport_hash"
                    );
                    "0".repeat(64)
                }
            };
        }
        Ok(None) => {
            tracing::warn!(
                agent_id = %agent_id,
                "agent passport not in store; passport-derived Cedar attrs using placeholders"
            );
        }
        Err(e) => {
            tracing::warn!(
                agent_id = %agent_id,
                error = %e,
                "passport_store lookup failed; passport-derived Cedar attrs using placeholders"
            );
        }
    }

    attrs
}

/// Build a `Yutha::Agent` entity record populated with all attributes
/// the canonical v1.1 schema declares.
///
/// Phase 3a (post-3a-2): `framework` / `passport_tier` / `passport_hash`
/// come from the resolved attrs (real passport-store values for known
/// agents, placeholder fallbacks for unknown). Reputation lands real
/// in Phase 3a-3; budgets stay at the `i64::MAX` placeholder until a
/// future phase implements RFC 0011 §4 budget tracking in the engine.
///
/// Cedar 3.x: extension types use the explicit `__extn` shape with
/// `fn` + `arg`. The implicit short-form (`"1.0"`) also works in the
/// Cedar 3.x JSON entity format, but explicit is unambiguous and
/// trivially diffable.
fn agent_entity(
    agent_uid: &str,
    swarm_uid: &str,
    attrs_resolved: &ResolvedAgentAttrs,
) -> EntityRecord {
    let mut attrs: HashMap<String, serde_json::Value> = HashMap::new();
    attrs.insert(
        "agent_id".into(),
        serde_json::Value::String(agent_uid.to_string()),
    );
    attrs.insert(
        "passport_tier".into(),
        serde_json::Value::String(attrs_resolved.passport_tier.clone()),
    );
    attrs.insert(
        "framework".into(),
        serde_json::Value::String(attrs_resolved.framework.clone()),
    );
    attrs.insert(
        "passport_hash".into(),
        serde_json::Value::String(attrs_resolved.passport_hash.clone()),
    );
    attrs.insert(
        "reputation".into(),
        serde_json::json!({
            "__extn": { "fn": "decimal", "arg": attrs_resolved.reputation }
        }),
    );
    attrs.insert(
        "budget_remaining_usd_cents".into(),
        serde_json::Value::Number(attrs_resolved.budget_remaining_usd_cents.into()),
    );
    attrs.insert(
        "budget_remaining_tool_calls".into(),
        serde_json::Value::Number(attrs_resolved.budget_remaining_tool_calls.into()),
    );
    attrs.insert(
        "budget_remaining_compute_ms".into(),
        serde_json::Value::Number(attrs_resolved.budget_remaining_compute_ms.into()),
    );
    EntityRecord {
        uid: EntityUid::new("Yutha::Agent", agent_uid.to_string()),
        attrs,
        parents: vec![EntityUid::new("Yutha::Swarm", swarm_uid.to_string())],
    }
}

/// Build a `Yutha::Swarm` entity record with all schema-required
/// attributes populated. `topology_mode` is the lowercased string
/// form of `yutha_registry::TopologyMode` (closed / open / hybrid);
/// `constitution_version` is the version of the currently-active
/// constitution at evaluation time.
/// Build a `Yutha::Resource` entity record for non-Agent recipients
/// of SendEnvelope. The schema declares Resource with three required
/// attrs (`resource_kind`, `scope`, `tags`); we populate from the
/// Recipient variant. Policies that gate on these read them via
/// `resource.resource_kind == "role"` etc.
fn resource_entity(uid: &str, kind: &str, scope: &str, tags: &[String]) -> EntityRecord {
    let mut attrs: HashMap<String, serde_json::Value> = HashMap::new();
    attrs.insert(
        "resource_kind".into(),
        serde_json::Value::String(kind.to_string()),
    );
    attrs.insert("scope".into(), serde_json::Value::String(scope.to_string()));
    attrs.insert(
        "tags".into(),
        serde_json::Value::Array(
            tags.iter()
                .map(|t| serde_json::Value::String(t.clone()))
                .collect(),
        ),
    );
    EntityRecord {
        uid: EntityUid::new("Yutha::Resource", uid.to_string()),
        attrs,
        parents: Vec::new(),
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

/// Build + sign + append a `constitution.evaluate.{pass,deny}` receipt
/// for the given eval outcome.
///
/// Evidence shape mirrors `/spec/receipt/canonical-actions.md`:
///
/// - `constitution_hash` — content-address of the active constitution.
/// - `action_kind` — the action being evaluated (e.g. `"SendEnvelope"`).
/// - `matched_rule_ids` — comma-joined list of cedar policy ids that
///   contributed to the decision.
/// - `input_attribute_digest` — sha256 over the eval request's
///   canonical bytes (already computed by the evaluator as
///   `EvaluationOutcome.evidence_digest`).
/// - `deny_reason` — only on deny.
/// - `total_score` — only on pass when scoring rules contributed.
/// - `shadow_constitution_hash` — Phase 3b (RFC 0018 §3.4): content-
///   address of the shadow constitution when one was configured at
///   the moment of evaluation. Auditors join active + shadow
///   receipts for the same envelope by matching this field plus
///   `subject_agent_id` + `input_attribute_digest`. Absent when no
///   shadow is loaded.
///
/// The control plane signs the receipt with its own identity
/// (`Actor` role); on a successful append the receipt's content-
/// address is returned.
async fn emit_constitution_eval_receipt(
    state: &ControlPlaneState,
    outcome: &EvaluationOutcome,
    constitution_hash: &Hash,
    constitution_version: &str,
    swarm_id: yutha_core::SwarmId,
    subject_agent_id: &AgentId,
    shadow_constitution_hash: Option<&Hash>,
) -> Result<Hash, Status> {
    let action_kind = match outcome.decision {
        yutha_cedar_plus::Decision::Permit => "constitution.evaluate.pass",
        yutha_cedar_plus::Decision::Deny => "constitution.evaluate.deny",
    };

    let mut evidence: Vec<Evidence> = vec![
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
        // The subject is the agent whose action was evaluated. The
        // receipt's `actor` is the control plane (it emits the
        // signed audit record), so the subject has to ride in
        // evidence — the enforcement engine downstream (F10f
        // PublishingReceiptStore + F9 on_receipt) matches on this
        // field to attribute denies to the right agent.
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
    if let Some(total) = &outcome.total_score {
        evidence.push(Evidence::new(
            "total_score",
            "type.yutha.dev/v1/String",
            total.0.as_bytes().to_vec(),
        ));
    }
    // Phase 3b (RFC 0018 §3.4): record shadow correlation context on
    // the active receipt when a shadow was configured at eval time.
    if let Some(shadow_hash) = shadow_constitution_hash {
        evidence.push(Evidence::new(
            "shadow_constitution_hash",
            "type.yutha.dev/v1/Hash",
            shadow_hash.digest.clone(),
        ));
    }

    let spec_version = SpecVersion::parse("1.0.0").map_err(|e| {
        Status::internal(format!("constitution.evaluate receipt spec_version: {e}"))
    })?;
    let mut builder = Receipt::builder()
        .spec_version(spec_version)
        .swarm_id(swarm_id)
        .actor(state.control_plane_identity.agent_id)
        .action_kind(action_kind)
        .constitution_version(constitution_version)
        .occurred_at(Timestamp::now());
    for e in evidence {
        builder = builder.evidence(e);
    }
    let mut receipt = builder
        .build()
        .map_err(|e| Status::internal(format!("constitution.evaluate receipt build: {e}")))?;

    let bytes = receipt
        .canonical_bytes()
        .map_err(|e| Status::internal(format!("constitution.evaluate canonical: {e}")))?;
    let sig = state
        .control_plane_identity
        .sign(&bytes)
        .await
        .map_err(|e| Status::internal(format!("constitution.evaluate signer: {e}")))?;
    receipt
        .signatures
        .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

    let outcome = state
        .receipt_store
        .append(receipt, AppendOptions::default(), state.resolver.as_ref())
        .await
        .map_err(|e| Status::internal(format!("constitution.evaluate append: {e}")))?;
    Ok(outcome.receipt_id)
}

/// Build + sign + append a `constitution.evaluate.shadow.{pass,deny}`
/// receipt for a shadow-mode evaluation outcome (Phase 3b, RFC 0018
/// §3.4). Only called when the evaluator returned a shadow outcome
/// (i.e., a shadow constitution was loaded at the moment of
/// `evaluate_pair`).
///
/// Evidence shape per `/spec/receipt/canonical-actions.md`:
///
/// - `shadow_constitution_hash` — content-address of the shadow
///   constitution. NOT `constitution_hash`, to make audit queries
///   unambiguous.
/// - `action_kind` — the action being evaluated (`"SendEnvelope"`
///   today).
/// - `matched_rule_ids` — Cedar policy ids from the shadow's policy
///   set that contributed to the decision.
/// - `input_attribute_digest` — same canonical bytes hash as the
///   active eval receipt for this envelope; auditors use it to
///   correlate active + shadow decisions.
/// - `subject_agent_id` — same agent the active receipt names. (The
///   enforcement-engine forwarder filters shadow receipts out of the
///   fan-out per RFC 0018 §3.5, so this field is purely audit
///   context.)
/// - `deny_reason` — only on deny. Mirrors the active eval's
///   `deny_reason` shape and additionally accepts the special value
///   `"shadow_schema_incompatible"` for the cross-schema failure
///   path (RFC 0018 §3.3).
/// - `total_score` — only on pass when shadow `prefer` rules
///   contributed.
///
/// Receipt ordering on the wire is deterministic — the active eval
/// receipt appends first (caller's responsibility), this one
/// second. Replay-time reconstruction (Phase 3c) depends on this
/// ordering.
async fn emit_constitution_shadow_eval_receipt(
    state: &ControlPlaneState,
    outcome: &EvaluationOutcome,
    shadow_constitution_hash: &Hash,
    shadow_constitution_version: &str,
    swarm_id: yutha_core::SwarmId,
    subject_agent_id: &AgentId,
) -> Result<Hash, Status> {
    let action_kind = match outcome.decision {
        yutha_cedar_plus::Decision::Permit => "constitution.evaluate.shadow.pass",
        yutha_cedar_plus::Decision::Deny => "constitution.evaluate.shadow.deny",
    };

    let mut evidence: Vec<Evidence> = vec![
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
    if let Some(total) = &outcome.total_score {
        evidence.push(Evidence::new(
            "total_score",
            "type.yutha.dev/v1/String",
            total.0.as_bytes().to_vec(),
        ));
    }

    let spec_version = SpecVersion::parse("1.0.0").map_err(|e| {
        Status::internal(format!(
            "constitution.evaluate.shadow receipt spec_version: {e}"
        ))
    })?;
    let mut builder = Receipt::builder()
        .spec_version(spec_version)
        .swarm_id(swarm_id)
        .actor(state.control_plane_identity.agent_id)
        .action_kind(action_kind)
        .constitution_version(shadow_constitution_version)
        .occurred_at(Timestamp::now());
    for e in evidence {
        builder = builder.evidence(e);
    }
    let mut receipt = builder.build().map_err(|e| {
        Status::internal(format!("constitution.evaluate.shadow receipt build: {e}"))
    })?;

    let bytes = receipt
        .canonical_bytes()
        .map_err(|e| Status::internal(format!("constitution.evaluate.shadow canonical: {e}")))?;
    let sig = state
        .control_plane_identity
        .sign(&bytes)
        .await
        .map_err(|e| Status::internal(format!("constitution.evaluate.shadow signer: {e}")))?;
    receipt
        .signatures
        .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

    let outcome = state
        .receipt_store
        .append(receipt, AppendOptions::default(), state.resolver.as_ref())
        .await
        .map_err(|e| Status::internal(format!("constitution.evaluate.shadow append: {e}")))?;
    Ok(outcome.receipt_id)
}

/// Type alias for the server-streaming Subscribe response — a boxed
/// stream of `SubscribedEnvelope` items.
pub type SubscribeStream =
    Pin<Box<dyn Stream<Item = Result<SubscribedEnvelope, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl EnvelopeService for EnvelopeHandler {
    async fn send(
        &self,
        request: Request<SendEnvelopeRequest>,
    ) -> Result<Response<SendEnvelopeResponse>, Status> {
        let auth = require_active_bearer_auth(&request, &self.state).await?;
        let req = request.into_inner();

        let envelope_proto = req
            .envelope
            .as_ref()
            .ok_or_else(|| missing_field("envelope"))?;
        let envelope = Envelope::try_from(envelope_proto).map_err(|e| e.to_status())?;
        debug!(
            target: "yutha::envelope::trace",
            from_agent = %envelope.from_agent,
            recipient = ?envelope.recipient,
            envelope_id = ?envelope.envelope_id,
            epoch = envelope.epoch,
            cap_id_present = req.capability_id.is_some(),
            "Send: envelope received"
        );

        // Anti-spoofing: the bearer claims an identity, the envelope
        // claims a sender — they MUST be the same agent. Cross-agent
        // proxying is not part of v1.0; future work might add a
        // delegate-send shape.
        if envelope.from_agent != auth.agent_id {
            return Err(Status::permission_denied(
                "envelope.from_agent must match the bearer-token agent_id",
            ));
        }

        // RFC 0007: Send-path capability enforcement.
        //
        // Behavior matrix:
        //   - require_capability_for_send = true,  cap_id absent  → INVALID_ARGUMENT
        //   - require_capability_for_send = true,  cap_id present → check; deny → PERMISSION_DENIED
        //   - require_capability_for_send = false, cap_id absent  → skip check (legacy)
        //   - require_capability_for_send = false, cap_id present → check anyway (audit
        //                                                            value); deny still rejects
        //
        // The store's `check` walks the parent chain, honors revocation
        // + validity window, intersects scopes, evaluates caveats, and
        // emits the `capability.check.{pass,deny}` receipt as a
        // substrate observation regardless of which branch is taken.
        let topology = self.state.registry.topology();
        let cap_id_opt: Option<Hash> = req
            .capability_id
            .as_ref()
            .map(Hash::try_from)
            .transpose()
            .map_err(|e| e.to_status())?;

        if topology.require_capability_for_send && cap_id_opt.is_none() {
            return Err(Status::invalid_argument(
                "topology.require_capability_for_send is true: \
                 SendEnvelopeRequest.capability_id is required",
            ));
        }

        if let Some(cap_id) = cap_id_opt.clone() {
            let descriptor = ActionDescriptor {
                action_kind: "envelope.send".to_string(),
                resource_tags: envelope.tags.clone(),
                recipient: Some(recipient_descriptor_string(&envelope.recipient)),
                ..Default::default()
            };
            let evaluation = self
                .state
                .capability_store
                .check(&cap_id, &descriptor)
                .await
                .map_err(|e| e.to_status())?;
            if !evaluation.outcome.permitted {
                return Err(Status::permission_denied(format!(
                    "capability check denied: {}",
                    evaluation.outcome.deny_reason
                )));
            }
        }

        // RFC 0010-0013: constitution evaluation (F10d).
        //
        // Layered on top of E1's cap check: the cap layer answers "does
        // this agent have authority"; the constitution layer answers
        // "do the swarm's norms permit this authority to be exercised
        // right now." Both must pass.
        //
        // A swarm MUST have an active constitution before any send
        // succeeds. The operator publishes one via
        // `ConstitutionService.Activate` as part of bringing the swarm
        // online; a Send arriving before that activation is a
        // misconfiguration and surfaces as `FAILED_PRECONDITION`.
        // Phase 3b (RFC 0018 §3.3): read both slots — active +
        // shadow — in a single call so the envelope is evaluated
        // against both with a consistent snapshot. The shadow slot
        // is observation-only; only the active slot gates the cap
        // layer + the enforcement engine.
        let (active_opt, shadow_opt) = self.state.cedar_plus.current_pair().await;
        let active = active_opt.ok_or_else(|| {
            Status::failed_precondition(
                "no active constitution; operator must call ConstitutionService.Activate before \
                 envelope sends are permitted",
            )
        })?;
        let constitution_hash = active.constitution.constitution_hash.clone();
        let constitution_version = active.constitution.constitution_version.clone();
        // Capture the shadow's hash + version before dropping the
        // Arc, since we need them on the active receipt's evidence
        // (per RFC 0018 §3.4) and to label the shadow receipt that
        // follows.
        let shadow_meta: Option<(Hash, String)> = shadow_opt.as_ref().map(|s| {
            (
                s.constitution.constitution_hash.clone(),
                s.constitution.constitution_version.clone(),
            )
        });
        drop(active);
        drop(shadow_opt);

        let topology_mode_str = match topology.mode {
            yutha_registry::TopologyMode::Closed => "closed",
            yutha_registry::TopologyMode::Open => "open",
            yutha_registry::TopologyMode::Hybrid => "hybrid",
        };
        let eval_request = build_eval_request_for_send(
            constitution_hash.clone(),
            &auth.agent_id,
            &envelope,
            cap_id_opt.as_ref(),
            &topology.swarm_id,
            &constitution_version,
            topology_mode_str,
            self.state.passport_store.as_ref(),
            self.state.enforcement.as_ref(),
        )
        .await;
        // evaluate_pair runs the active eval (full Layer A + B,
        // procedure-state mutation) then — if a shadow is loaded —
        // clones the request, rewrites its constitution_hash to the
        // shadow's, and runs Layer A + scoring against the shadow
        // policy set. Shadow-side schema incompatibilities surface
        // as a synthesized Deny with deny_reason =
        // "shadow_schema_incompatible" per RFC 0018 §3.3.
        let (active_outcome, shadow_outcome_opt) = self
            .state
            .cedar_plus
            .evaluate_pair(eval_request)
            .await
            .map_err(|e| Status::internal(format!("constitution eval: {e}")))?;

        // F10e + Phase 3b (RFC 0018 §3.4): emit the active eval
        // receipt with shadow_constitution_hash evidence when a
        // shadow was configured. Emission happens BEFORE the deny
        // short-circuit so the audit trail records permits and
        // denies symmetrically — per
        // /spec/receipt/canonical-actions.md.
        emit_constitution_eval_receipt(
            &self.state,
            &active_outcome,
            &constitution_hash,
            &constitution_version,
            topology.swarm_id,
            &auth.agent_id,
            shadow_meta.as_ref().map(|(h, _)| h),
        )
        .await?;

        // Phase 3b (RFC 0018 §3.4): emit the shadow eval receipt
        // when the shadow path ran. Ordering is deterministic —
        // active first, shadow second — which Phase 3c replay
        // reconstruction depends on. Engine fan-out filters these
        // shadow action-kinds out at the forwarder per RFC 0018
        // §3.5; nothing here gates on the shadow outcome.
        if let Some(shadow_outcome) = shadow_outcome_opt {
            let (shadow_hash, shadow_version) = shadow_meta
                .as_ref()
                .expect("shadow_outcome_opt is Some implies shadow_meta is Some");
            emit_constitution_shadow_eval_receipt(
                &self.state,
                &shadow_outcome,
                shadow_hash,
                shadow_version,
                topology.swarm_id,
                &auth.agent_id,
            )
            .await?;
        }

        if active_outcome.decision == Decision::Deny {
            let reason = active_outcome.deny_reason.as_deref().unwrap_or("unknown");
            return Err(Status::permission_denied(format!(
                "constitution check denied: {reason}"
            )));
        }

        let send_receipt = self
            .state
            .transport
            .send(envelope)
            .await
            .map_err(|e| e.to_status())?;
        debug!(
            target: "yutha::envelope::trace",
            from_agent = %auth.agent_id,
            send_receipt = %send_receipt,
            "Send: transport.send returned"
        );

        Ok(Response::new(SendEnvelopeResponse {
            send_receipt: Some((&send_receipt).into()),
        }))
    }

    type SubscribeStream = SubscribeStream;

    // clippy::result_large_err: the .map() closure below produces
    // Result<SubscribedEnvelope, Status>, where SubscribedEnvelope is
    // small but Status is ~176 bytes — that imbalance trips the lint.
    // Status is tonic's canonical error and isn't going to change shape
    // crate-side; accept the imbalance locally.
    #[allow(clippy::result_large_err)]
    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let auth = require_active_bearer_auth(&request, &self.state).await?;
        let req = request.into_inner();

        // Resolve the target agent: explicit value (must equal the
        // bearer's agent) or default to the bearer's. Forbids
        // cross-agent eavesdropping.
        let target = match req.agent_id.as_ref() {
            Some(id_proto) => {
                let claimed = AgentId::try_from(id_proto).map_err(|e| e.to_status())?;
                if claimed != auth.agent_id {
                    return Err(Status::permission_denied(
                        "Subscribe.agent_id must match the bearer-token agent_id",
                    ));
                }
                claimed
            }
            None => auth.agent_id,
        };

        debug!(
            target: "yutha::envelope::trace",
            target_agent = %target,
            "Subscribe: handler entered"
        );

        // Open the transport-level stream. MemoryTransport's impl
        // idempotently registers the inbox if needed, so the first
        // subscription from a fresh agent works without prior setup.
        let envelope_stream = self
            .state
            .transport
            .subscribe(target)
            .await
            .map_err(|e| e.to_status())?;

        // Map each `(Envelope, Hash)` pair to the wire `SubscribedEnvelope`,
        // and any TransportError to `tonic::Status`. The cancellation
        // path is handled by the underlying transport: when this stream
        // is dropped, its tx half closes and the forwarder task inside
        // MemoryTransport::subscribe terminates.
        let mapped = envelope_stream.map(|item| match item {
            Ok((envelope, deliver_receipt)) => Ok(SubscribedEnvelope {
                envelope: Some((&envelope).into()),
                deliver_receipt: Some((&deliver_receipt).into()),
            }),
            Err(e) => Err(e.to_status()),
        });

        // RFC 0009 §3.3 active-stream tear-down: race the envelope
        // stream against the target's revocation Notify. When a
        // revoke (self or operator) lands, the Notify fires; this
        // forwarder emits one terminating UNAUTHENTICATED frame and
        // ends the stream within tens-of-milliseconds rather than
        // making the client wait for token expiry.
        //
        // Uses the same `tokio::spawn` + `mpsc` + `ReceiverStream`
        // pattern `MemoryTransport`'s subscribe forwarder uses so we
        // don't pull in an async-stream dep just for this combinator.
        let revocation_signal = self.state.revocation_signal_for(target).await;
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<SubscribedEnvelope, Status>>(8);
        let target_for_log = target;
        tokio::spawn(async move {
            tokio::pin!(mapped);
            let mut items_forwarded: u64 = 0;
            loop {
                tokio::select! {
                    biased;
                    // Client dropped the stream → exit immediately so we
                    // don't sit parked on `mapped.next()` and consume an
                    // envelope into a closed downstream. Same pattern as
                    // the zombie-forwarder fix in
                    // `MemoryTransport::subscribe` (4b): without this,
                    // back-to-back subscribe-then-drop test runs leave
                    // wrappers that eat the next subscriber's envelopes.
                    _ = tx.closed() => {
                        debug!(
                            target: "yutha::envelope::trace",
                            target_agent = %target_for_log,
                            items_forwarded,
                            "Subscribe: outer forwarder exit via tx.closed"
                        );
                        break;
                    }
                    _ = revocation_signal.notified() => {
                        debug!(
                            target: "yutha::envelope::trace",
                            target_agent = %target_for_log,
                            items_forwarded,
                            "Subscribe: outer forwarder exit via revocation"
                        );
                        let _ = tx
                            .send(Err(Status::unauthenticated("agent revoked")))
                            .await;
                        break;
                    }
                    next = mapped.next() => match next {
                        Some(item) => {
                            let item_ok = item.is_ok();
                            if tx.send(item).await.is_err() {
                                // Same root cause; same exit. This branch
                                // handles the race where the receiver
                                // drops between the `tx.closed()` poll
                                // and the next `tx.send`.
                                debug!(
                                    target: "yutha::envelope::trace",
                                    target_agent = %target_for_log,
                                    items_forwarded,
                                    "Subscribe: outer forwarder exit via tx.send error (consumed item dropped)"
                                );
                                break;
                            }
                            if item_ok {
                                items_forwarded += 1;
                            }
                        }
                        None => {
                            debug!(
                                target: "yutha::envelope::trace",
                                target_agent = %target_for_log,
                                items_forwarded,
                                "Subscribe: outer forwarder exit via inner stream end"
                            );
                            break;
                        }
                    }
                }
            }
        });

        Ok(Response::new(
            Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx))
                as Pin<Box<dyn Stream<Item = _> + Send + 'static>>,
        ))
    }
}

//! [`ReplaySession`] — orchestrates one replay run.
//!
//! Per RFC 0018 §4.1, a session owns:
//!
//! - An isolated [`EnforcementEngine`] activated with the candidate.
//! - A session-scoped [`ReceiptStore`] handle from
//!   [`yutha_receipt::ReplayStore::session_store`].
//! - The same [`ControlPlaneIdentity`] production uses, so within-
//!   session receipts are signed identically.
//!
//! The session orchestrator drives:
//!
//! - **Cold init** — engine at defaults, candidate activated, ready
//!   to receive `play_receipt` calls.
//! - **Warm init** — additionally feeds receipts preceding
//!   `from_unix_ns` for `warm_lookback_hours` through `on_receipt` to
//!   approximate production engine state at the window's start.
//! - **`play_receipt(original)`** — builds a `ReceiptView` from the
//!   original, calls `engine.on_receipt` + `engine.poll_scheduled`
//!   against the original's wall-clock, and emits any
//!   `enforcement.*` effects as session-scoped receipts.
//! - **`run_window(source_store)`** — iterates the receipt window
//!   matching the session's action-kind filter, sorts ascending by
//!   monotonic_ns, calls `play_receipt` for each.

use std::collections::BTreeMap;
use std::sync::Arc;

use yutha_cedar_plus::{EnforcementEffect, EnforcementEngine, ReceiptView, Score};
use yutha_core::{CausalRef, Hash, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::Canonical;
use yutha_passport::ControlPlaneIdentity;
use yutha_receipt::{
    AppendOptions, Evidence, PassportResolver, Query, Receipt, ReceiptStore, ReplaySessionId,
    ReplaySessionWindow, SignatureRole, SignedBy, TimeRangeQuery,
};

use crate::error::{ReplayError, Result};

/// One ReplaySession previews a candidate constitution against a
/// past receipt window. Drop the session to release its engine
/// state (the receipt store handle stays alive as long as the
/// parent `ReplayStore` does, but receipts within it are tied to
/// the session's lifetime via `ReplayStore::delete_session`).
pub struct ReplaySession {
    session_id: ReplaySessionId,
    swarm_id: SwarmId,
    constitution_hash: Hash,
    constitution_version: String,
    engine: Arc<EnforcementEngine>,
    receipt_store: Arc<dyn ReceiptStore>,
    resolver: Arc<dyn PassportResolver>,
    cp_identity: Arc<ControlPlaneIdentity>,
    /// Session-internal causal chain head — the previous step's
    /// emitted replay receipts. The next step's emissions use these
    /// as predecessors. Per RFC 0018 §4.3 — graph walks stay
    /// self-contained.
    last_step_emissions: tokio::sync::Mutex<Vec<Hash>>,
}

/// Outcome of one `play_receipt` step.
#[derive(Debug, Clone)]
pub struct ReplayStepOutcome {
    /// The original receipt that triggered this step (content-address).
    pub original_receipt_id: Hash,
    /// Number of `EnforcementEffect`s the engine emitted on this step.
    pub effects_count: usize,
    /// Content-addresses of the receipts written into the session's
    /// store as a result of this step. May be empty (no effects)
    /// or contain N receipts (one per effect).
    pub emitted_receipt_ids: Vec<Hash>,
}

/// Outcome of `run_window`.
#[derive(Debug, Clone)]
pub struct ReplayWindowOutcome {
    /// Total receipts from the source store that were replayed.
    pub receipts_replayed: u64,
    /// Cumulative count of session-scoped receipts emitted across
    /// all steps.
    pub session_receipts_emitted: u64,
}

impl ReplaySession {
    /// Construct a cold-init session. Engine starts at defaults.
    ///
    /// `receipt_store` is the session-scoped store from
    /// `ReplayStore::session_store(session_id)`. `resolver` is the
    /// passport resolver — the session signs its own receipts so the
    /// resolver mainly serves the receipt-store's signature
    /// verification path on append.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_cold(
        session_id: ReplaySessionId,
        swarm_id: SwarmId,
        candidate: yutha_cedar_plus::Constitution,
        evaluator: &yutha_cedar_plus::CedarPlusEvaluator,
        receipt_store: Arc<dyn ReceiptStore>,
        resolver: Arc<dyn PassportResolver>,
        cp_identity: Arc<ControlPlaneIdentity>,
    ) -> Result<Self> {
        // Activate the candidate on a private evaluator-side slot so
        // the activator's load-time validation runs. The evaluator
        // is shared with the production active path; we don't
        // mutate its active slot here — we just need the loader's
        // validation pass + a borrowed `Arc<ActivatedConstitution>`.
        //
        // Phase 3c MVP scoping: we don't actually use the evaluator
        // for replay-side Cedar evaluation (the entity snapshot
        // isn't preserved on production receipts). We use it as the
        // loader path so we get the same validation rejection
        // surface as `ConstitutionService.Activate`.
        let _ = evaluator;
        let constitution_hash = candidate.constitution_hash.clone();
        let constitution_version = candidate.constitution_version.clone();

        // Build the per-session engine and activate it directly via
        // the loader. The control-plane production engine wraps the
        // same loader path; we mirror it here to keep error surfaces
        // identical.
        let loader = yutha_cedar_plus::ConstitutionLoader::with_default_bounds(
            yutha_cedar_plus::canonical_schema_v1_1()
                .map_err(|e| ReplayError::CedarPlus(e.to_string()))?,
        );
        let activated = loader
            .load(candidate)
            .map_err(|e| ReplayError::CedarPlus(e.to_string()))?;
        let activated_arc = Arc::new(activated);

        let engine = Arc::new(EnforcementEngine::new());
        engine.activate(Arc::clone(&activated_arc)).await;

        Ok(Self {
            session_id,
            swarm_id,
            constitution_hash,
            constitution_version,
            engine,
            receipt_store,
            resolver,
            cp_identity,
            last_step_emissions: tokio::sync::Mutex::new(Vec::new()),
        })
    }

    /// Construct a warm-init session. Engine is rebuilt from
    /// receipts preceding `from_unix_ns` for `lookback_hours` via
    /// `on_receipt` calls. The lookback receipts are NOT replayed
    /// (no session-scoped emissions); they're consumed purely to
    /// approximate production engine state at `from_unix_ns`.
    ///
    /// Per RFC 0018 §4.2: the rebuild is bounded — exhaustive
    /// rebuild from swarm genesis is the forensic-audit use case
    /// deferred to a follow-on RFC.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_warm(
        session_id: ReplaySessionId,
        swarm_id: SwarmId,
        candidate: yutha_cedar_plus::Constitution,
        evaluator: &yutha_cedar_plus::CedarPlusEvaluator,
        receipt_store: Arc<dyn ReceiptStore>,
        resolver: Arc<dyn PassportResolver>,
        cp_identity: Arc<ControlPlaneIdentity>,
        source_store: &dyn ReceiptStore,
        from_unix_ns: u64,
        lookback_hours: u32,
    ) -> Result<Self> {
        let session = Self::create_cold(
            session_id,
            swarm_id,
            candidate,
            evaluator,
            receipt_store,
            resolver,
            cp_identity,
        )
        .await?;

        // Lookback window: [from_unix_ns - lookback_ns, from_unix_ns).
        let lookback_ns = (lookback_hours as u64)
            .saturating_mul(3_600)
            .saturating_mul(1_000_000_000);
        let lookback_from = from_unix_ns.saturating_sub(lookback_ns);
        let lookback_to = from_unix_ns.saturating_sub(1);

        let from_ts = Timestamp::new("1970-01-01T00:00:00Z".to_string(), lookback_from)
            .map_err(|e| ReplayError::Backend(format!("lookback from-timestamp: {e}")))?;
        let to_ts = Timestamp::new("9999-12-31T23:59:59Z".to_string(), lookback_to)
            .map_err(|e| ReplayError::Backend(format!("lookback to-timestamp: {e}")))?;

        let page = source_store
            .query(
                Query::ByTimeRange(TimeRangeQuery {
                    from: from_ts,
                    to: to_ts,
                }),
                None,
            )
            .await?;

        // Sort ascending — the engine's sliding-window counters
        // depend on monotonic ordering for correct pruning.
        let mut receipts = page.receipts;
        receipts.sort_by_key(|r| r.occurred_at.monotonic_ns);

        // Feed each through the engine. No session-scoped emission
        // for lookback receipts — they're pure state-rebuild.
        for r in &receipts {
            let view = build_view(r);
            let _effects = session.engine.on_receipt(view).await;
            // Note: we discard the effects rather than emitting
            // them. The effects represent what the candidate's
            // engine WOULD have flagged in the lookback window, but
            // the operator's interest is in the actual replay
            // window (post-from_unix_ns).
            let _ = session
                .engine
                .poll_scheduled(&r.occurred_at.wall_clock)
                .await;
        }

        Ok(session)
    }

    /// The session id.
    pub fn session_id(&self) -> &ReplaySessionId {
        &self.session_id
    }

    /// The candidate's constitution_hash.
    pub fn constitution_hash(&self) -> &Hash {
        &self.constitution_hash
    }

    /// Replay one original receipt against the candidate's engine.
    /// Per RFC 0018 §4.3 the emitted receipts:
    ///
    /// - Use the same canonical action-kinds as production.
    /// - Carry `replay_session_id` evidence.
    /// - Reference the previous step's emissions as causal
    ///   predecessors (session-internal chain).
    /// - Are signed by `ControlPlaneIdentity`.
    /// - Land in the session-scoped receipt store.
    pub async fn play_receipt(&self, original: &Receipt) -> Result<ReplayStepOutcome> {
        let original_receipt_id = yutha_crypto::canonical::content_address(original)
            .map_err(|e| ReplayError::Backend(format!("compute original receipt id: {e}")))?;

        // Feed into the candidate's engine.
        let view = build_view(original);
        let effects = self.engine.on_receipt(view).await;

        // Advance synthetic time. The engine's scheduled-transitions
        // queue fires anything whose `fire_at_wall_clock` <=
        // `original.occurred_at.wall_clock`.
        let scheduled_effects = self
            .engine
            .poll_scheduled(&original.occurred_at.wall_clock)
            .await;

        // Emit one session-scoped receipt per effect. Causal
        // predecessors point at the previous step's emissions.
        let mut emitted_receipt_ids = Vec::new();
        let predecessors = {
            let last = self.last_step_emissions.lock().await;
            last.clone()
        };

        let all_effects: Vec<EnforcementEffect> =
            effects.into_iter().chain(scheduled_effects).collect();
        let effects_count = all_effects.len();

        for effect in &all_effects {
            let id = self
                .emit_session_enforcement_receipt(effect, &predecessors)
                .await?;
            emitted_receipt_ids.push(id);
        }

        // Update the chain head — next step's emissions reference
        // this step's emissions.
        {
            let mut last = self.last_step_emissions.lock().await;
            *last = emitted_receipt_ids.clone();
        }

        Ok(ReplayStepOutcome {
            original_receipt_id,
            effects_count,
            emitted_receipt_ids,
        })
    }

    /// Iterate the source store's receipts within `window`, sort
    /// ascending by monotonic_ns, replay each through
    /// [`play_receipt`].
    pub async fn run_window(
        &self,
        source_store: &dyn ReceiptStore,
        window: &ReplaySessionWindow,
    ) -> Result<ReplayWindowOutcome> {
        let from_ts = Timestamp::new("1970-01-01T00:00:00Z".to_string(), window.from_unix_ns)
            .map_err(|e| ReplayError::Backend(format!("window from-timestamp: {e}")))?;
        let to_ts = Timestamp::new("9999-12-31T23:59:59Z".to_string(), window.to_unix_ns)
            .map_err(|e| ReplayError::Backend(format!("window to-timestamp: {e}")))?;

        let page = source_store
            .query(
                Query::ByTimeRange(TimeRangeQuery {
                    from: from_ts,
                    to: to_ts,
                }),
                None,
            )
            .await?;

        let mut receipts = page.receipts;
        receipts.sort_by_key(|r| r.occurred_at.monotonic_ns);

        // Action-kind filter — whitelist semantics. Empty = wildcard.
        if !window.action_kind_filter.is_empty() {
            receipts.retain(|r| {
                window
                    .action_kind_filter
                    .iter()
                    .any(|k| k == &r.action_kind)
            });
        }

        let mut total_emissions: u64 = 0;
        let mut total_replayed: u64 = 0;
        for r in &receipts {
            let outcome = self.play_receipt(r).await?;
            total_emissions =
                total_emissions.saturating_add(outcome.emitted_receipt_ids.len() as u64);
            total_replayed = total_replayed.saturating_add(1);
        }

        Ok(ReplayWindowOutcome {
            receipts_replayed: total_replayed,
            session_receipts_emitted: total_emissions,
        })
    }

    /// Build + sign + append a session-scoped `enforcement.*`
    /// receipt for one effect. Same evidence shape as the production
    /// emitter (`crates/yutha-control-plane/src/receipt_publisher.rs`)
    /// plus a `replay_session_id` evidence entry.
    async fn emit_session_enforcement_receipt(
        &self,
        effect: &EnforcementEffect,
        predecessors: &[Hash],
    ) -> Result<Hash> {
        let spec_version = SpecVersion::parse("1.0.0")
            .map_err(|e| ReplayError::Backend(format!("spec version: {e}")))?;

        let mut evidence: Vec<Evidence> = vec![
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
            // RFC 0018 §4.3 distinguishability marker.
            Evidence::new(
                "replay_session_id",
                "type.yutha.dev/v1/String",
                self.session_id.to_string().into_bytes(),
            ),
        ];

        // Effect-specific evidence — same shape as the production
        // emitter; engine populates a BTreeMap for deterministic
        // canonical bytes.
        let additional: BTreeMap<&String, &serde_json::Value> =
            effect.additional_evidence.iter().collect();
        for (key, value) in additional {
            let bytes = serde_json::to_vec(value).map_err(|e| {
                ReplayError::Backend(format!("encode additional_evidence[{key}]: {e}"))
            })?;
            evidence.push(Evidence::new(key.as_str(), "type.yutha.dev/v1/Json", bytes));
        }

        let causal = CausalRef {
            predecessors: predecessors.to_vec(),
        };

        let mut builder = yutha_receipt::ReceiptBuilder::new()
            .spec_version(spec_version)
            .swarm_id(self.swarm_id)
            .actor(self.cp_identity.agent_id)
            .action_kind(effect.action_kind.as_str())
            .constitution_version(&self.constitution_version)
            .causal(causal)
            .occurred_at(Timestamp::now());
        for e in evidence {
            builder = builder.evidence(e);
        }
        let mut receipt = builder
            .build()
            .map_err(|e| ReplayError::Backend(format!("build receipt: {e}")))?;

        let bytes = receipt
            .canonical_bytes()
            .map_err(|e| ReplayError::Backend(format!("canonical bytes: {e}")))?;
        let sig = self
            .cp_identity
            .sign(&bytes)
            .await
            .map_err(|e| ReplayError::Signer(e.to_string()))?;
        receipt
            .signatures
            .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

        let outcome = self
            .receipt_store
            .append(receipt, AppendOptions::default(), self.resolver.as_ref())
            .await?;
        Ok(outcome.receipt_id)
    }

    /// Underlying engine handle — exposed so the gRPC handler (3c-E)
    /// can read per-agent state for the operator's
    /// `QueryReplayReceipts` view.
    pub fn engine(&self) -> &EnforcementEngine {
        self.engine.as_ref()
    }
}

/// Build a [`ReceiptView`] from a [`Receipt`]. Mirrors the production
/// pattern in `crates/yutha-control-plane/src/receipt_publisher.rs::build_view`.
///
/// The view borrows from the receipt for the duration of the
/// `on_receipt` call. Caller MUST keep the receipt alive across
/// `on_receipt`.
fn build_view(receipt: &Receipt) -> ReceiptView<'_> {
    // Extract principal from evidence: prefer `subject_agent_id`
    // (set by control-plane-emitted receipts like
    // `constitution.evaluate.*`), fall back to `target_agent_id`
    // (set by `enforcement.*`), fall back to the actor.
    let mut principal_id: Option<&str> = None;
    let mut deny_reason: Option<&str> = None;
    let mut forbid_rule_id: Option<&str> = None;
    let mut reputation_delta: Option<Score> = None;

    for ev in &receipt.evidence {
        match ev.key.as_str() {
            "subject_agent_id" | "target_agent_id" if principal_id.is_none() => {
                if let Ok(s) = std::str::from_utf8(&ev.value) {
                    principal_id = Some(s);
                }
            }
            "deny_reason" => {
                if let Ok(s) = std::str::from_utf8(&ev.value) {
                    deny_reason = Some(s);
                }
            }
            "forbid_rule_id" => {
                if let Ok(s) = std::str::from_utf8(&ev.value) {
                    forbid_rule_id = Some(s);
                }
            }
            "reputation_delta" => {
                if let Ok(s) = std::str::from_utf8(&ev.value) {
                    reputation_delta = Some(Score(s.to_string()));
                }
            }
            _ => {}
        }
    }

    // No actor fallback in Phase 3c MVP — the primary replay
    // targets (`envelope.send`, `enforcement.*`) all carry an
    // explicit principal in evidence (`subject_agent_id` or
    // `target_agent_id`), so a None here means the receipt has no
    // agent-attributable principal, which the engine treats as a
    // no-op. A future enhancement could borrow the actor's string
    // form from a per-receipt cache, but that's not load-bearing
    // for engine-state replay.

    ReceiptView {
        action_kind: receipt.action_kind.as_str(),
        principal_id,
        deny_reason,
        forbid_rule_id,
        occurred_at_unix_ns: receipt.occurred_at.monotonic_ns,
        occurred_at_wall_clock: receipt.occurred_at.wall_clock.as_str(),
        reputation_delta,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use yutha_cedar_plus::{
        parse_engine_config_yaml, CedarPlusEvaluator, Constitution, ConstitutionLoader,
    };
    use yutha_core::{AgentId, HashAlgorithm};
    use yutha_passport::{
        MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore, PassportTier,
    };
    use yutha_receipt::{
        Evidence as ReceiptEvidence, MemoryReplayStore, MemoryStore, ReceiptBuilder, ReplayMode,
        ReplaySessionMetadata, ReplaySessionWindow, ReplayStore,
    };
    use yutha_signer::{InProcessSigner, Signer};

    fn permissive_cedar() -> &'static str {
        "permit (principal, action, resource);"
    }
    fn empty_engine_config() -> &'static str {
        r#"
schema_version: "1.1.0"
predicates: []
scoring_rules: []
procedures: []
enforcement_rules: []
"#
    }

    async fn build_session_fixtures() -> (
        ReplaySession,
        Arc<MemoryStore>,
        Arc<MemoryReplayStore>,
        ReplaySessionId,
        AgentId,
        Arc<dyn PassportResolver>,
    ) {
        let swarm_id = SwarmId::new();
        let replay_store = Arc::new(MemoryReplayStore::new());
        let session_id = ReplaySessionId::new();
        let candidate_hash = Hash::new(HashAlgorithm::Sha256, vec![0xC0; 32]).unwrap();

        let metadata = ReplaySessionMetadata {
            session_id,
            candidate_constitution_hash: candidate_hash.clone(),
            candidate_constitution_version: "1.1.0-rc".into(),
            window: ReplaySessionWindow {
                from_unix_ns: 0,
                to_unix_ns: u64::MAX,
                action_kind_filter: Vec::new(),
            },
            mode: ReplayMode::Cold,
            warm_lookback_hours: 0,
            created_at: Timestamp::now(),
            last_active_at: Timestamp::now(),
            receipts_replayed: 0,
        };
        replay_store.create_session(metadata).await.unwrap();
        let session_store = replay_store.session_store(&session_id);

        // Production source store. Tests append to this then run the
        // session against it.
        let source_store = Arc::new(MemoryStore::new());

        // Passports + resolver.
        let passports: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
        let cp_signer = InProcessSigner::generate();
        let cp_agent_id = AgentId::new();
        let cp_passport = Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(cp_agent_id)
            .swarm_id(swarm_id)
            .agent_public_key(cp_signer.public_key())
            .owner("test control plane")
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(&cp_signer)
            .await
            .unwrap();
        passports.register(cp_passport).await.unwrap();
        let resolver: Arc<dyn PassportResolver> =
            Arc::new(PassportResolverAdapter::new(Arc::clone(&passports)));
        let cp_identity = Arc::new(ControlPlaneIdentity::new(
            cp_agent_id,
            Arc::new(cp_signer) as Arc<dyn Signer>,
        ));

        // Evaluator stub — only used for the loader's validation
        // path through create_cold.
        let schema = yutha_cedar_plus::canonical_schema_v1_1().unwrap();
        let loader = ConstitutionLoader::with_default_bounds(schema);
        let evaluator = CedarPlusEvaluator::with_default_bounds(loader);

        let candidate = Constitution {
            constitution_hash: candidate_hash,
            spec_version: SpecVersion::parse("1.0.0").unwrap(),
            schema_version: "1.1.0".into(),
            constitution_version: "1.1.0-rc".into(),
            parent_version: None,
            swarm_id,
            cedar_source: permissive_cedar().into(),
            engine_config: parse_engine_config_yaml(empty_engine_config()).unwrap(),
            issued_at: Timestamp::now(),
        };

        let session = ReplaySession::create_cold(
            session_id,
            swarm_id,
            candidate,
            &evaluator,
            session_store,
            Arc::clone(&resolver),
            cp_identity,
        )
        .await
        .unwrap();

        (
            session,
            source_store,
            replay_store,
            session_id,
            cp_agent_id,
            resolver,
        )
    }

    #[tokio::test]
    async fn cold_init_creates_session_with_engine_at_defaults() {
        let (session, _src, _replay, session_id, _cp, _resolver) = build_session_fixtures().await;
        assert_eq!(session.session_id(), &session_id);
        // Engine is fresh — never-seen agent renders the engine's
        // default reputation. The exact string ("1.0") is what
        // `EnforcementEngine::get_agent_state` produces for an
        // unknown agent — see render_score_scaled in
        // crates/yutha-cedar-plus/src/enforcement.rs.
        let unknown_agent_state = session.engine().get_agent_state("unknown-agent").await;
        assert_eq!(unknown_agent_state.reputation.0, "1.0");
        // Sanity that the snapshot's other defaults match what a
        // never-seen agent should look like.
        assert!(!unknown_agent_state.quarantined);
        assert!(unknown_agent_state.current_stage.is_none());
    }

    /// Build a signed envelope.send receipt at a specific monotonic_ns.
    async fn signed_envelope_send_receipt(
        actor: AgentId,
        swarm_id: SwarmId,
        monotonic_ns: u64,
        signer: &dyn Signer,
    ) -> Receipt {
        let mut r = ReceiptBuilder::new()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .swarm_id(swarm_id)
            .actor(actor)
            .action_kind("envelope.send")
            .evidence(ReceiptEvidence::new(
                "envelope_hash",
                "type.yutha.dev/v1/Hash",
                vec![0xEE; 32],
            ))
            .constitution_version("1.0.0")
            .occurred_at(Timestamp::new("2026-06-09T00:00:00Z".into(), monotonic_ns).unwrap())
            .build()
            .unwrap();
        let bytes = r.canonical_bytes().unwrap();
        let sig = signer.sign_message(&bytes).await.unwrap();
        r.signatures
            .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));
        r
    }

    #[tokio::test]
    async fn run_window_replays_filtered_receipts_into_session_store() {
        let (session, source, replay_store, session_id, _cp, source_resolver) =
            build_session_fixtures().await;

        // Append a couple of envelope.send receipts into the source.
        // Register a passport for the actor so the source's append
        // verification passes.
        let actor_signer = InProcessSigner::generate();
        let actor_id = AgentId::new();
        let actor_passport = Passport::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .agent_id(actor_id)
            .swarm_id(SwarmId::new())
            .agent_public_key(actor_signer.public_key())
            .owner("actor")
            .accepted_constitution_version("1.0.0")
            .tier(PassportTier::Minimal)
            .issued_at(Timestamp::now())
            .sign(&actor_signer)
            .await
            .unwrap();
        // Re-derive the swarm_id from the session (we passed a
        // fresh one above; reuse it).
        let swarm_id = actor_passport.swarm_id;
        let passports: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
        passports.register(actor_passport).await.unwrap();
        let resolver: Arc<dyn PassportResolver> = Arc::new(PassportResolverAdapter::new(passports));

        let r1 = signed_envelope_send_receipt(actor_id, swarm_id, 100, &actor_signer).await;
        let r2 = signed_envelope_send_receipt(actor_id, swarm_id, 200, &actor_signer).await;
        source
            .append(r1, AppendOptions::default(), resolver.as_ref())
            .await
            .unwrap();
        source
            .append(r2, AppendOptions::default(), resolver.as_ref())
            .await
            .unwrap();

        // Permissive candidate has no enforcement rules — so the
        // engine produces zero effects per receipt. run_window
        // returns `receipts_replayed: 2, session_receipts_emitted: 0`.
        let window = ReplaySessionWindow {
            from_unix_ns: 50,
            to_unix_ns: 300,
            action_kind_filter: vec!["envelope.send".into()],
        };
        let outcome = session
            .run_window(source.as_ref() as &dyn ReceiptStore, &window)
            .await
            .unwrap();
        assert_eq!(outcome.receipts_replayed, 2);
        assert_eq!(outcome.session_receipts_emitted, 0);

        // Session-scoped store should be empty (no enforcement
        // effects emitted), production store untouched.
        let session_store = replay_store.session_store(&session_id);
        assert_eq!(session_store.count().await.unwrap(), 0);
        assert_eq!(source.count().await.unwrap(), 2);

        // Drop the unused source_resolver to silence warnings.
        let _ = source_resolver;
    }

    #[tokio::test]
    async fn play_receipt_with_no_effects_emits_no_session_receipts() {
        let (session, _src, _replay, _session_id, _cp, _resolver) = build_session_fixtures().await;
        let actor_signer = InProcessSigner::generate();
        let actor_id = AgentId::new();
        let r = signed_envelope_send_receipt(actor_id, SwarmId::new(), 100, &actor_signer).await;
        let outcome = session.play_receipt(&r).await.unwrap();
        assert_eq!(outcome.effects_count, 0);
        assert!(outcome.emitted_receipt_ids.is_empty());
    }
}

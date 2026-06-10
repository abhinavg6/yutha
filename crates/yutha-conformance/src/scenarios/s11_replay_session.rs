//! Behavioral scenario **S11: Replay session end-to-end (Phase 3c
//! regression guard).**
//!
//! Phase 3c shipped the `yutha-replay` orchestration layer per RFC
//! 0018 §4: a candidate constitution previewed against a past
//! receipt window, with all session-scoped emissions isolated to a
//! per-session [`ReceiptStore`] handle from
//! [`yutha_receipt::ReplayStore::session_store`]. The session signs
//! receipts identically to production but lands them in the isolated
//! store — production stays untouched.
//!
//! S11 locks the four load-bearing properties from RFC 0018 §4 in:
//!
//! 1. **Production store isolation.** The source/production receipt
//!    store ends the run with exactly the receipts the test
//!    appended — `run_window` never writes to it.
//! 2. **Session store receives the emissions.** The session-scoped
//!    store ends the run with exactly the per-step enforcement
//!    receipts the candidate's engine emitted. The `MemoryReplayStore`
//!    is the substrate; Phase 3c follow-on swaps in
//!    `PostgresReplayStore` without changing this invariant.
//! 3. **Canonical action-kind parity.** Within-session enforcement
//!    receipts use the same canonical `enforcement.detect` /
//!    `enforcement.coach` / `enforcement.quarantine` /
//!    `enforcement.evict` / `enforcement.reverse` action-kinds as
//!    production (RFC 0018 §4.3). Auditors run the same
//!    `yutha-ops grep <kind>` query; the `replay_session_id` evidence
//!    marker is what distinguishes them.
//! 4. **Session-internal causal chain.** Step N+1's session-scoped
//!    emissions reference step N's emissions (within the same
//!    session) as predecessors — NOT the original receipt's
//!    predecessors. Graph walks across replay receipts stay
//!    self-contained per RFC 0018 §4.3.
//!
//! ## Scenario shape
//!
//! - Production source store with **4** `constitution.evaluate.deny`
//!   receipts for the same subject agent at monotonic_ns 100, 200,
//!   300, 400 (all signed by the control-plane identity).
//! - Candidate constitution: permissive Cedar plus one
//!   `enforcement_rule` with `detect.trigger.receipt_kind =
//!   constitution.evaluate.deny`, `count_threshold: 1`,
//!   `group_by: principal`. Threshold 1 means every replayed deny
//!   fires `detect` — keeps the chain check below clean (every
//!   `play_receipt` call emits, so `last_step_emissions` never
//!   resets to empty between firing steps). Coach / quarantine /
//!   evict are declared with multi-hour cooldowns so only `detect`
//!   fires inside the replay window (the four input receipts share
//!   a wall_clock string so `poll_scheduled` never escalates the
//!   chain past detect).
//! - Cold-init replay session against window [50, 450], filter
//!   `["constitution.evaluate.deny"]`.
//!
//! Expected:
//!
//! - 4 receipts replayed.
//! - 4 session-scoped emissions (detect fires on every deny because
//!   threshold is 1).
//! - Session store holds 4 `enforcement.detect` receipts, each
//!   carrying `replay_session_id` evidence equal to the session id.
//! - Detect #1's predecessors are empty (genesis of the
//!   session-internal chain). Detect #N's predecessors (N > 1)
//!   contain exactly `[content_address(detect #N-1)]` — the
//!   self-contained chain RFC 0018 §4.3 requires so replay-receipt
//!   graph walks never leak into the production DAG.
//! - Production store holds exactly 4 receipts (the deniers we
//!   appended); `count == 4` before and after the run.

use std::sync::Arc;

use yutha_cedar_plus::{
    canonical_schema_v1_1, parse_engine_config_yaml, CedarPlusEvaluator, Constitution,
    ConstitutionLoader,
};
use yutha_core::{AgentId, Hash, HashAlgorithm, SpecVersion, SwarmId, Timestamp};
use yutha_crypto::canonical::{content_address, Canonical};
use yutha_passport::{
    ControlPlaneIdentity, MemoryPassportStore, Passport, PassportResolverAdapter, PassportStore,
    PassportTier,
};
use yutha_receipt::{
    ActionKindQuery, AppendOptions, Evidence, MemoryReplayStore, MemoryStore as MemoryReceiptStore,
    PassportResolver, Query, Receipt, ReceiptStore, ReplayMode, ReplaySessionId,
    ReplaySessionMetadata, ReplaySessionWindow, ReplayStore, SignatureRole, SignedBy,
};
use yutha_replay::ReplaySession;
use yutha_signer::{InProcessSigner, Signer};

/// Permissive Cedar — the active-policy decision in the replay loop
/// is irrelevant for S11. The detect rule fires on the action-kind
/// pattern of the *original* receipts (not on candidate-side
/// re-evaluation), which is what the candidate's engine consumes.
const S11_CANDIDATE_CEDAR_SOURCE: &str = "permit (principal, action, resource);";

/// One enforcement rule: detect on `constitution.evaluate.deny`,
/// threshold 1, grouped by principal. Threshold 1 keeps the
/// session-internal causal chain unbroken — every replayed deny
/// fires a detect, so `last_step_emissions` carries a non-empty
/// chain head across every step.
///
/// Multi-hour cooldowns on the downstream stages keep coach /
/// quarantine / evict out of the replay window — `poll_scheduled`
/// runs against each original receipt's wall_clock, and S11 pins
/// every original receipt to the same wall_clock string so nothing
/// schedules forward.
const S11_CANDIDATE_ENGINE_CONFIG_YAML: &str = r#"
schema_version: "1.1.0"
predicates: []
scoring_rules: []
procedures: []
enforcement_rules:
  - name: deny_streak_detector
    detect:
      trigger:
        receipt_kind: constitution.evaluate.deny
      count_threshold: 1
      time_window: 60s
      group_by: principal
    coach:
      cooldown: 24h
      guidance_template: "Stop the streak"
    quarantine:
      escalate_after: 24h
    evict:
      escalate_after: 24h
      require_countersign: false
    severity: high
"#;

/// Receipt-count snapshot a clean S11 run produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S11Outcome {
    /// Total receipts replayed through `run_window` (expect 4 — every
    /// receipt in the window matches the action-kind filter).
    pub receipts_replayed: u64,
    /// Total session-scoped receipts emitted across `run_window`
    /// (expect 4 — threshold 1 fires detect on every replayed deny).
    pub session_receipts_emitted: u64,
    /// `constitution.evaluate.deny` count in the **production** store
    /// after the run (expect 4 — production untouched per RFC 0018
    /// §4.1).
    pub production_deny_count: u64,
    /// `enforcement.detect` count in the **session-scoped** store
    /// after the run (expect 4 — one per replayed deny).
    pub session_detect_count: u64,
}

/// Run S11 end-to-end. Returns the receipt-count snapshot for the
/// `#[tokio::test]` at the bottom of this module to assert against.
pub async fn run_s11() -> S11Outcome {
    let swarm_id = SwarmId::new();

    // -----------------------------------------------------------------
    // Passports + control-plane identity.
    // -----------------------------------------------------------------
    let passports: Arc<dyn PassportStore> = Arc::new(MemoryPassportStore::new());
    let resolver: Arc<dyn PassportResolver> =
        Arc::new(PassportResolverAdapter::new(Arc::clone(&passports)));

    let cp_signer = InProcessSigner::generate();
    let cp_agent_id = AgentId::new();
    let cp_passport = signed_passport(swarm_id, cp_agent_id, &cp_signer, "control plane").await;
    passports.register(cp_passport).await.unwrap();
    let cp = Arc::new(ControlPlaneIdentity::new(
        cp_agent_id,
        Arc::new(cp_signer) as Arc<dyn Signer>,
    ));

    // The subject agent — Alice — whose `constitution.evaluate.deny`
    // receipts the candidate's engine groups on.
    let alice_signer = InProcessSigner::generate();
    let alice_id = AgentId::new();
    passports
        .register(signed_passport(swarm_id, alice_id, &alice_signer, "alice").await)
        .await
        .unwrap();

    // -----------------------------------------------------------------
    // Production (source) receipt store. Mirrors the live
    // control-plane's primary store.
    // -----------------------------------------------------------------
    let production_store: Arc<dyn ReceiptStore> = Arc::new(MemoryReceiptStore::new());

    // Append 4 `constitution.evaluate.deny` receipts at known
    // monotonic_ns. Same wall_clock string across all four so
    // `poll_scheduled` inside the replay loop never escalates past
    // detect.
    let constitution_hash = Hash::new(HashAlgorithm::Sha256, vec![0xA0; 32]).unwrap();
    for monotonic_ns in [100u64, 200, 300, 400] {
        let r =
            signed_deny_receipt(&cp, swarm_id, alice_id, &constitution_hash, monotonic_ns).await;
        production_store
            .append(r, AppendOptions::default(), &*resolver)
            .await
            .unwrap();
    }

    let production_count_before = production_store.count().await.unwrap();
    assert_eq!(production_count_before, 4, "fixture invariant");

    // -----------------------------------------------------------------
    // Replay store + session.
    // -----------------------------------------------------------------
    let replay_store = Arc::new(MemoryReplayStore::new());
    let session_id = ReplaySessionId::new();
    let candidate_hash = Hash::new(HashAlgorithm::Sha256, vec![0xC0; 32]).unwrap();
    let window = ReplaySessionWindow {
        from_unix_ns: 50,
        to_unix_ns: 450,
        action_kind_filter: vec!["constitution.evaluate.deny".into()],
    };

    let metadata = ReplaySessionMetadata {
        session_id,
        candidate_constitution_hash: candidate_hash.clone(),
        candidate_constitution_version: "1.1.0-rc".into(),
        window: window.clone(),
        mode: ReplayMode::Cold,
        warm_lookback_hours: 0,
        created_at: Timestamp::now(),
        last_active_at: Timestamp::now(),
        receipts_replayed: 0,
    };
    replay_store.create_session(metadata).await.unwrap();
    let session_store = replay_store.session_store(&session_id);

    // Candidate constitution — used by the session's private engine.
    let candidate = Constitution {
        constitution_hash: candidate_hash.clone(),
        spec_version: SpecVersion::parse("1.0.0").unwrap(),
        schema_version: "1.1.0".into(),
        constitution_version: "1.1.0-rc".into(),
        parent_version: None,
        swarm_id,
        cedar_source: S11_CANDIDATE_CEDAR_SOURCE.into(),
        engine_config: parse_engine_config_yaml(S11_CANDIDATE_ENGINE_CONFIG_YAML).unwrap(),
        issued_at: Timestamp::now(),
    };

    // Evaluator stub — only used for `create_cold`'s loader path.
    let schema = canonical_schema_v1_1().unwrap();
    let loader = ConstitutionLoader::with_default_bounds(schema);
    let evaluator = CedarPlusEvaluator::with_default_bounds(loader);

    let session = ReplaySession::create_cold(
        session_id,
        swarm_id,
        candidate,
        &evaluator,
        Arc::clone(&session_store),
        Arc::clone(&resolver),
        Arc::clone(&cp),
    )
    .await
    .expect("cold-init session activates");

    // -----------------------------------------------------------------
    // Run the replay window.
    // -----------------------------------------------------------------
    let outcome = session
        .run_window(production_store.as_ref(), &window)
        .await
        .expect("run_window completes");

    // -----------------------------------------------------------------
    // Property 1 — Production store isolation. (RFC 0018 §4.1)
    // -----------------------------------------------------------------
    let production_count_after = production_store.count().await.unwrap();
    assert_eq!(
        production_count_after, 4,
        "production store MUST be untouched after replay; expected 4 receipts (the 4 \
         denies appended pre-replay), got {production_count_after}"
    );

    // -----------------------------------------------------------------
    // Property 2 — Session store receives the emissions.
    // -----------------------------------------------------------------
    let session_total = session_store.count().await.unwrap();
    assert_eq!(
        session_total, 4,
        "session store MUST contain exactly the session-scoped emissions \
         (4 detect fires from a 4-deny stream at threshold 1), got {session_total}"
    );

    // -----------------------------------------------------------------
    // Property 3 — Canonical action-kind parity. (RFC 0018 §4.3)
    // -----------------------------------------------------------------
    let detect_page = session_store
        .query(
            Query::ByActionKind(ActionKindQuery {
                action_kind: "enforcement.detect".into(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        detect_page.receipts.len(),
        4,
        "session-scoped `enforcement.detect` receipts MUST match production canonical \
         action-kind so `yutha-ops grep enforcement.detect` against the session store \
         surfaces them (RFC 0018 §4.3); got {} matches",
        detect_page.receipts.len()
    );

    // -----------------------------------------------------------------
    // Property 4 — `replay_session_id` evidence marker. (RFC 0018 §4.3)
    // -----------------------------------------------------------------
    let expected_marker = session_id.to_string().into_bytes();
    for r in &detect_page.receipts {
        let marker = r
            .evidence
            .iter()
            .find(|e| e.key == "replay_session_id")
            .expect(
                "every session-scoped enforcement receipt MUST carry a \
                 `replay_session_id` evidence entry (RFC 0018 §4.3)",
            );
        assert_eq!(
            marker.value, expected_marker,
            "`replay_session_id` evidence MUST equal the session id"
        );
    }

    // -----------------------------------------------------------------
    // Property 5 — Session-internal causal chain. (RFC 0018 §4.3)
    //
    // Threshold 1 means every `play_receipt` call emits one detect,
    // so `last_step_emissions` carries a non-empty chain head across
    // all four steps. Detect #1 has empty predecessors (the genesis
    // of the session-internal chain); each subsequent detect #N has
    // predecessors == [content_address(detect #N-1)].
    //
    // Crucially, predecessors point at the previous session-scoped
    // detect — NOT at the original receipt's predecessors in the
    // production store. Replay receipts form a self-contained chain
    // so a graph walk across them never leaks into the production
    // DAG.
    // -----------------------------------------------------------------
    let mut detects_sorted = detect_page.receipts.clone();
    detects_sorted.sort_by_key(|r| r.occurred_at.monotonic_ns);

    assert!(
        detects_sorted[0].causal.predecessors.is_empty(),
        "first detect's predecessors MUST be empty — it's the genesis of the \
         session-internal chain (RFC 0018 §4.3)"
    );

    for i in 1..detects_sorted.len() {
        let prev_id =
            content_address(&detects_sorted[i - 1]).expect("content-address previous detect");
        assert_eq!(
            detects_sorted[i].causal.predecessors,
            vec![prev_id],
            "detect #{n}'s predecessors MUST point at detect #{prev}'s content-address \
             (session-internal chain, RFC 0018 §4.3); predecessors MUST NOT mirror the \
             original receipt's predecessors — without this, a graph walk across replay \
             receipts would leak into the production DAG.",
            n = i + 1,
            prev = i,
        );
    }

    S11Outcome {
        receipts_replayed: outcome.receipts_replayed,
        session_receipts_emitted: outcome.session_receipts_emitted,
        production_deny_count: production_count_after,
        session_detect_count: detect_page.receipts.len() as u64,
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

/// Build + sign + return a `constitution.evaluate.deny` receipt at
/// `monotonic_ns` whose evidence carries the load-bearing fields the
/// candidate's engine needs to thread through `build_view`:
///
/// - `subject_agent_id` → `principal_id` (group_by key)
/// - `constitution_hash`, `action_kind`, `matched_rule_ids`,
///   `input_attribute_digest`, `deny_reason` → mirror the production
///   emitter's shape (matches `s10_shadow_mode.rs::append_active_eval_receipt`).
///
/// Caller appends the result into the production store.
async fn signed_deny_receipt(
    cp: &ControlPlaneIdentity,
    swarm_id: SwarmId,
    subject_agent_id: AgentId,
    constitution_hash: &Hash,
    monotonic_ns: u64,
) -> Receipt {
    let evidence = vec![
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
            "no-forbidden".as_bytes().to_vec(),
        ),
        Evidence::new(
            "input_attribute_digest",
            "type.yutha.dev/v1/Hash",
            vec![0x77; 32],
        ),
        Evidence::new(
            "subject_agent_id",
            "type.yutha.dev/v1/AgentId",
            subject_agent_id.to_string().into_bytes(),
        ),
        Evidence::new(
            "deny_reason",
            "type.yutha.dev/v1/String",
            "policy_forbid_match".as_bytes().to_vec(),
        ),
    ];

    let mut builder = Receipt::builder()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .swarm_id(swarm_id)
        .actor(cp.agent_id)
        .action_kind("constitution.evaluate.deny")
        .constitution_version("1.0.0")
        .occurred_at(Timestamp::new("2026-06-09T00:00:00Z".into(), monotonic_ns).unwrap());
    for e in evidence {
        builder = builder.evidence(e);
    }
    let mut receipt = builder.build().expect("build deny receipt");
    let bytes = receipt.canonical_bytes().expect("canonical bytes");
    let sig = cp.sign(&bytes).await.expect("cp signs deny receipt");
    receipt
        .signatures
        .push(SignedBy::new(SignatureRole::Actor, sig, Timestamp::now()));

    receipt
}

// =============================================================================
// Test
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn s11_replay_session_round_trip() {
        let outcome = run_s11().await;
        assert_eq!(
            outcome,
            S11Outcome {
                receipts_replayed: 4,
                session_receipts_emitted: 4,
                production_deny_count: 4,
                session_detect_count: 4,
            }
        );
    }
}

//! Behavioral scenario **S13: simulation harness end-to-end.**
//!
//! Drives the `yutha-sim` harness over a self-contained refund-cap
//! constitution and the canonical persona bundle. Validates the
//! Phase 3e contract holistically: the YAML loader → persona
//! registry → in-memory stack → eval loop → receipt emission →
//! enforcement chain all compose into the expected receipt-count
//! shape.
//!
//! Five load-bearing properties:
//!
//! 1. The simulation terminates with `BudgetExhausted` at the
//!    configured step count (no runaway, no early-exit surprise).
//! 2. Every well-behaved SupportAgent emit produces a
//!    `constitution.evaluate.pass`. None produce a deny — the
//!    constitution must not regress on baseline traffic.
//! 3. The RefundAttacker's escalating probe trips the cap forbid
//!    rule at the threshold step, producing
//!    `constitution.evaluate.deny` receipts attributed to the
//!    attacker's agent id.
//! 4. The four-stage enforcement chain fires at least once
//!    (`enforcement.detect` >= 1) — the engine's pattern matcher
//!    and scheduler both work end-to-end through the harness.
//! 5. SupportAgent's intent count equals the step budget — the
//!    persona is never quarantined by the same constitution that
//!    quarantines the attacker.
//!
//! Pairs with `crates/yutha-sim/examples/scenarios/refund_attacker_meets_cap/`,
//! the operator-facing fixture. The constitution sources here are
//! deliberately inlined as `const &str` so S13 has no
//! filesystem-path dependency on the operator-facing example
//! directory.

use std::collections::HashMap;

use yutha_sim::{
    register_canonical_personas, ConstitutionConfig, PersonaRegistry, ScenarioConfig,
    SimulationHarness, SimulationOutcome, TerminalReason,
};

/// Receipt-count snapshot from a clean S13 run. Pinned by the
/// `#[tokio::test]` at the bottom of the module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S13Outcome {
    /// Total steps executed (should equal the scenario budget).
    pub total_steps: u32,
    /// `BudgetExhausted` for a healthy run; `AllPersonasIdle` if
    /// the chain enforces eviction so hard that personas go quiet.
    pub terminal_reason: TerminalReason,
    /// `constitution.evaluate.pass` receipts.
    pub eval_pass_receipts: u64,
    /// `constitution.evaluate.deny` receipts.
    pub eval_deny_receipts: u64,
    /// `enforcement.detect` receipts.
    pub detect_receipts: u64,
    /// `enforcement.quarantine` receipts.
    pub quarantine_receipts: u64,
    /// SupportAgent's reported intents_emitted.
    pub support_intents: u32,
    /// RefundAttacker's reported intents_emitted.
    pub attacker_intents: u32,
}

/// Cedar source for the S13 fixture.
const S13_CEDAR_SOURCE: &str = r#"
@id("refund-cap")
forbid (
    principal,
    action == Yutha::Action::"SendEnvelope",
    resource
) when {
    context.estimated_cost_usd_cents >= 1000
};

permit (principal, action, resource);
"#;

/// Engine config for the S13 fixture. Same shape as the
/// operator-facing example — one enforcement rule covering all
/// four stages with 1-second cooldowns.
const S13_ENGINE_CONFIG_YAML: &str = r#"
schema_version: "1.1.0"
predicates: []
scoring_rules: []
procedures: []
enforcement_rules:
  - name: refund_cap_chain
    detect:
      trigger:
        receipt_kind: constitution.evaluate.deny
      count_threshold: 2
      time_window: 60s
      group_by: principal
    coach:
      cooldown: 1s
      guidance_template: "Refund amount exceeds the cap."
    quarantine:
      escalate_after: 1s
    evict:
      escalate_after: 1s
      require_countersign: false
    severity: high
"#;

/// Run S13 end-to-end. Writes the Cedar + engine config to a
/// temporary directory, builds the [`ScenarioConfig`] in memory,
/// runs the harness with the canonical persona bundle, and
/// returns the receipt-count snapshot.
pub async fn run_s13() -> S13Outcome {
    // Materialise the constitution fixtures into a temp dir the
    // harness can read. We don't reuse the operator-facing example
    // directory so this scenario stays self-contained.
    let tmp = tempfile::tempdir().expect("tempdir");
    let cedar_path = tmp.path().join("refund-cap.cedar");
    let engine_path = tmp.path().join("refund-cap.engine.yaml");
    std::fs::write(&cedar_path, S13_CEDAR_SOURCE).expect("write cedar");
    std::fs::write(&engine_path, S13_ENGINE_CONFIG_YAML).expect("write engine yaml");

    // Build the scenario config in memory. Two agents (one of
    // each canonical type), 20 steps, 1s tick — same shape as the
    // operator-facing fixture so the receipt-count expectations
    // transfer.
    let scenario = ScenarioConfig {
        constitution: ConstitutionConfig {
            cedar_path,
            engine_config_path: engine_path,
        },
        agents: vec![
            yutha_sim::AgentConfig {
                persona: "support_agent".into(),
                config: serde_json::json!({
                    "message_text": "support",
                    "tags": ["support"],
                    "estimated_cost_usd_cents": 5,
                }),
            },
            yutha_sim::AgentConfig {
                persona: "refund_attacker".into(),
                config: serde_json::json!({
                    "initial_amount_cents": 100,
                    "step_multiplier": 2.0,
                    "tags": ["refund"],
                }),
            },
        ],
        steps: 20,
        tick_ms: 1000,
    };

    let mut registry = PersonaRegistry::new();
    register_canonical_personas(&mut registry);

    let harness = SimulationHarness::new(scenario, &registry)
        .await
        .expect("harness new");
    let outcome = harness.run().await.expect("harness run");
    let snapshot = snapshot(&outcome);

    // Pin the five load-bearing properties.
    assert_eq!(
        snapshot.terminal_reason,
        TerminalReason::BudgetExhausted,
        "S13: expected BudgetExhausted, got {:?}",
        snapshot.terminal_reason
    );
    assert_eq!(
        snapshot.total_steps, 20,
        "S13: expected 20 steps, got {}",
        snapshot.total_steps
    );

    // SupportAgent never gets denied — the constitution must
    // permit baseline traffic with cost 5.
    let support_denies = denies_attributable_to(&outcome, &support_agent_id(&outcome));
    assert_eq!(
        support_denies, 0,
        "S13: support_agent received {support_denies} denies, expected 0"
    );

    // RefundAttacker's geometric probe (100, 200, 400, 800, 1600,
    // 3200, ...) crosses the 1000-cent threshold at step 4. The
    // chain emits >= 1 deny attributable to the attacker.
    let attacker_denies = denies_attributable_to(&outcome, &attacker_agent_id(&outcome));
    assert!(
        attacker_denies >= 1,
        "S13: refund_attacker received {attacker_denies} denies, expected >= 1"
    );

    // The four-stage chain fires at least once.
    assert!(
        snapshot.detect_receipts >= 1,
        "S13: expected >= 1 enforcement.detect receipts, got {}",
        snapshot.detect_receipts
    );

    // SupportAgent is never quarantined by the same constitution
    // that quarantines the attacker.
    assert_eq!(
        snapshot.support_intents, 20,
        "S13: support_agent emitted {} intents, expected 20 (one per step — never quarantined)",
        snapshot.support_intents
    );

    snapshot
}

fn snapshot(outcome: &SimulationOutcome) -> S13Outcome {
    let mut counts: HashMap<&str, u64> = HashMap::new();
    for r in &outcome.receipts {
        *counts.entry(r.action_kind.as_str()).or_insert(0) += 1;
    }
    let support_intents = outcome
        .persona_states
        .iter()
        .find(|p| p.name.starts_with("support_agent"))
        .map(|p| p.intents_emitted)
        .unwrap_or(0);
    let attacker_intents = outcome
        .persona_states
        .iter()
        .find(|p| p.name.starts_with("refund_attacker"))
        .map(|p| p.intents_emitted)
        .unwrap_or(0);
    S13Outcome {
        total_steps: outcome.total_steps,
        terminal_reason: outcome.terminal_reason,
        eval_pass_receipts: counts
            .get("constitution.evaluate.pass")
            .copied()
            .unwrap_or(0),
        eval_deny_receipts: counts
            .get("constitution.evaluate.deny")
            .copied()
            .unwrap_or(0),
        detect_receipts: counts.get("enforcement.detect").copied().unwrap_or(0),
        quarantine_receipts: counts.get("enforcement.quarantine").copied().unwrap_or(0),
        support_intents,
        attacker_intents,
    }
}

fn support_agent_id(outcome: &SimulationOutcome) -> String {
    outcome
        .persona_states
        .iter()
        .find(|p| p.name.starts_with("support_agent"))
        .map(|p| p.agent_id.to_string())
        .expect("support_agent in persona_states")
}

fn attacker_agent_id(outcome: &SimulationOutcome) -> String {
    outcome
        .persona_states
        .iter()
        .find(|p| p.name.starts_with("refund_attacker"))
        .map(|p| p.agent_id.to_string())
        .expect("refund_attacker in persona_states")
}

/// Count `constitution.evaluate.deny` receipts whose
/// `subject_agent_id` evidence matches `target`.
fn denies_attributable_to(outcome: &SimulationOutcome, target: &str) -> u64 {
    let mut count = 0u64;
    for r in &outcome.receipts {
        if r.action_kind != "constitution.evaluate.deny" {
            continue;
        }
        for ev in &r.evidence {
            if ev.key == "subject_agent_id" {
                if let Ok(s) = std::str::from_utf8(&ev.value) {
                    if s == target {
                        count += 1;
                        break;
                    }
                }
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn s13_simulation_harness_chain_fires() {
        let outcome = run_s13().await;
        // Loose post-condition pins beyond the inline assertions in
        // run_s13. The exact deny / chain numbers shift slightly
        // when the engine's matching algorithm evolves; keep these
        // ranges generous enough to survive harmless drift.
        assert!(
            outcome.eval_pass_receipts >= 20,
            "expected >= 20 passes (SupportAgent baseline), got {}",
            outcome.eval_pass_receipts
        );
        assert!(
            outcome.eval_deny_receipts >= 1,
            "expected >= 1 deny (refund cap crossed), got {}",
            outcome.eval_deny_receipts
        );
    }
}

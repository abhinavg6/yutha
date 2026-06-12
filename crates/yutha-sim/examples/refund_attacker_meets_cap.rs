//! Run the `refund_attacker_meets_cap` scenario from disk and
//! render a human summary of the resulting receipt log.
//!
//! ```ignore
//! cargo run -p yutha-sim --example refund_attacker_meets_cap
//! ```
//!
//! The scenario YAML, Cedar policy, and engine-config fixture live
//! next to this file at `examples/scenarios/refund_attacker_meets_cap/`.
//! The example shows the standard wiring for a one-shot simulation:
//!
//! 1. Resolve the scenario YAML path relative to
//!    `CARGO_MANIFEST_DIR` so the example runs from any working
//!    directory.
//! 2. Load the scenario via [`yutha_sim::load_scenario_yaml`].
//! 3. Construct a [`PersonaRegistry`] with the canonical bundle.
//! 4. Build + run a [`SimulationHarness`].
//! 5. Render the resulting [`SimulationOutcome`].

use std::collections::BTreeMap;
use std::path::PathBuf;

use yutha_sim::{
    load_scenario_yaml, register_canonical_personas, PersonaRegistry, SimulationHarness,
    SimulationOutcome, TerminalReason,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Locate the scenario YAML relative to this crate.
    let scenario_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples/scenarios/refund_attacker_meets_cap/scenario.yaml");
    println!("loading scenario from {}", scenario_path.display());
    let scenario = load_scenario_yaml(&scenario_path).await?;
    println!(
        "scenario loaded: {} agents, {} steps, tick_ms={}",
        scenario.agents.len(),
        scenario.steps,
        scenario.tick_ms,
    );

    // 2. Build a persona registry with all three canonical personas
    //    (`support_agent`, `refund_attacker`, `broken_tool`). Custom
    //    persona impls register on the same registry before the
    //    harness consumes it.
    let mut registry = PersonaRegistry::new();
    register_canonical_personas(&mut registry);

    // 3. Stand up the harness + run.
    let harness = SimulationHarness::new(scenario, &registry).await?;
    let outcome = harness.run().await?;

    // 4. Render the outcome.
    render(&outcome);
    Ok(())
}

fn render(outcome: &SimulationOutcome) {
    println!();
    println!("=== Simulation outcome ===");
    println!("total_steps:     {}", outcome.total_steps);
    println!(
        "terminal_reason: {}",
        match outcome.terminal_reason {
            TerminalReason::BudgetExhausted => "budget_exhausted",
            TerminalReason::AllPersonasIdle => "all_personas_idle",
        }
    );
    println!("total_receipts:  {}", outcome.receipts.len());

    let mut by_kind: BTreeMap<&str, u32> = BTreeMap::new();
    for r in &outcome.receipts {
        *by_kind.entry(r.action_kind.as_str()).or_insert(0) += 1;
    }
    println!();
    println!("Receipts by action_kind:");
    for (kind, count) in by_kind {
        println!("  {kind:<40} {count}");
    }

    println!();
    println!("Persona summary:");
    for p in &outcome.persona_states {
        println!(
            "  {:<32} agent={}  intents_emitted={}",
            p.name, p.agent_id, p.intents_emitted,
        );
    }
}

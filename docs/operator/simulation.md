# Simulation (synthetic traffic)

`yutha-ops sim` runs a candidate constitution against scripted agent behaviour in a self-contained sandbox — no live agents, no network, no production data. It lets you confirm a new rule actually catches what you want it to catch, before you turn the rule on.

Think of it as a unit test for your rule set: write a small YAML scenario describing who's sending what to whom, point `sim` at the candidate rule files, and watch the receipts that come out.

This is the right preview to reach for when the behaviour you want to catch isn't yet in your live traffic. The other three preview tools — [shadow mode](shadow-mode.md), [replay](replay.md), and [diff](constitution-diff.md) — all evaluate against actual traffic, past or present. Simulation evaluates against traffic you script directly.

## When to simulate

Three workflows make simulation worth the setup:

- **Pre-promote dry-run.** You've tightened a refund cap from $50 to $10. Before activating the new rule, run a scenario with a refund attacker that probes at $5, $20, $80, $320, $1280. Confirm the new $10 threshold catches the third probe and triggers the four-stage enforcement chain. If the chain doesn't fire, the rule isn't doing what you thought.
- **Constitution regression test.** A pull request modifies a Cedar policy. A CI step runs the same scenario against `main` and against the PR branch, compares the receipt counts. The PR fails review if the canonical refund-attacker stops getting denied — the new policy quietly loosened a rule.
- **Operator documentation.** You want to show a stakeholder "this is what happens when an agent goes off the rails." Run the broken-tool scenario, paste the markdown output into a runbook. The output shows the detect → coach → quarantine sequence with timestamps.

## What sim does and doesn't run

| Surface | What sim does |
|---|---|
| In-memory stack | Spins up the same receipt store, identity store, policy evaluator, and enforcement engine the live control plane uses — all in one process. |
| Rule activation | Reads your Cedar source + engine config from disk and activates them, same code path as production. |
| Agent loop | Walks through your scripted agents one at a time per simulation tick, deterministic ordering. |
| Reactive agents | Each scripted agent sees the receipts produced in the previous tick and learns its own quarantine status. |
| Emitted receipts | The same `constitution.evaluate.*` and `enforcement.*` receipts the live control plane emits, in the same shape. |
| Capability checks | **Not exercised.** If you want to test cap-discipline rules, write the rule against `context.capability_id == ""` and let the agent script omit the cap. |
| Eviction | **Symbolic.** The `enforcement.evict` receipt fires but the agent isn't actually removed from the scenario — the chain cycles. |
| Sui anchoring | **Off.** Simulation receipts never reach the chain. |
| Server contact | None. Pure local. |
| Authentication | Not needed. |

Three properties to keep in mind:

- **Sequential, not concurrent.** Scripted agents run one at a time per tick, in the order you list them. This is deliberate — running them concurrently would make the receipt order non-deterministic, defeating the use case as a regression test.
- **Synthetic clock.** The simulation advances time by a configurable `tick_ms` per step using an internal clock based far in the future (year 2100), so the enforcement engine's scheduler sees clean ordering. Set `tick_ms` to match or exceed your enforcement rule cooldowns — for a 1-second cooldown rule, use `tick_ms: 1000`.
- **Early exit on idle.** If every scripted agent goes idle in the same tick, the simulation exits early. A well-formed scenario with a baseline agent + an adversarial agent should never trip this; if it does, the baseline is broken or the rule is denying it.

## Three scripted agents you can use

The library ships **infrastructure + three opinionated examples** — not a sprawling library of personas to choose from. The three cover the common preview shapes; operators with more exotic needs implement their own in Rust (the trait is small).

| Name | What it does | Useful for |
|---|---|---|
| `support_agent` | Sends well-formed, low-cost support requests. Respects quarantine signal. Never trips a baseline rule. | Background noise. Confirms your rule doesn't accidentally deny good traffic. |
| `refund_attacker` | Sends refund requests with escalating amounts (default: doubles every tick). The amount surfaces into the same Cedar context field your refund-cap rules check. Counts the denies it receives. Respects quarantine. | Characterising a refund cap. Confirming the cap fires at the right threshold. |
| `broken_tool` | Sends envelopes without a capability and with a placeholder schema id (default: `type.yutha.dev/v1/UnscopedAction`). Always tags with `broken-tool`. | Driving the enforcement chain. Confirming an unscoped-send rule actually denies. |

For the `broken_tool` to actually trip your enforcement chain, your constitution needs a forbid rule that matches its sentinel schema id. The simulation docs link to a worked example.

## Scenario YAML

A scenario is a YAML file that lists the constitution to use, the scripted agents, and the simulation length:

```yaml
constitution:
  cedar_path: ./refund-cap.cedar
  engine_config_path: ./refund-cap.engine.yaml

agents:
  - persona: support_agent
    config:
      message_text: "support: please look at ticket T-9001"
      tags: ["support"]
      estimated_cost_usd_cents: 5
  - persona: refund_attacker
    config:
      initial_amount_cents: 100
      step_multiplier: 2.0

steps: 20
tick_ms: 1000
```

The constitution paths resolve relative to the YAML file's directory. The `config` block under each agent gets passed to that agent's deserializer; the configurable fields are documented next to each agent's source:

- [`SupportAgentConfig`](https://github.com/abhinavg6/yutha/blob/main/crates/yutha-sim/src/personas/support_agent.rs)
- [`RefundAttackerConfig`](https://github.com/abhinavg6/yutha/blob/main/crates/yutha-sim/src/personas/refund_attacker.rs)
- [`BrokenToolConfig`](https://github.com/abhinavg6/yutha/blob/main/crates/yutha-sim/src/personas/broken_tool.rs)

A complete worked example lives at [`crates/yutha-sim/examples/scenarios/refund_attacker_meets_cap/`](https://github.com/abhinavg6/yutha/tree/main/crates/yutha-sim/examples/scenarios/refund_attacker_meets_cap) — copy it to start.

## Running a scenario

```sh
# Human-readable summary on the terminal.
yutha-ops sim path/to/scenario.yaml

# JSON output for piping into jq / CI gates.
yutha-ops sim path/to/scenario.yaml --format json | jq '.persona_states'

# Markdown digest for a runbook or PR comment.
yutha-ops sim path/to/scenario.yaml --format markdown --output-file outcome.md
```

The rendered output goes to standard output; progress messages and "wrote N bytes" notes go to standard error. So you can safely pipe `--format json | jq` without filtering.

## Calling sim from Python

The Python SDK wraps the same CLI in `yutha.sim`. The wrapper shells out to `yutha-ops sim --format json` and parses the result into typed dataclasses, so you don't lose type information when you write assertions:

```python
from yutha import run_scenario, TerminalReason

outcome = run_scenario("scenario.yaml")
counts = outcome.count_by_action_kind()

assert outcome.terminal_reason == TerminalReason.BUDGET_EXHAUSTED
assert counts.get("constitution.evaluate.deny", 0) >= 1, "cap rule didn't fire"
assert counts.get("enforcement.detect", 0) >= 1, "enforcement chain didn't trigger"
```

Two helpers on the outcome are worth knowing about:

- `outcome.count_by_action_kind()` returns a `{kind: count}` dictionary. Useful for CI threshold assertions.
- `outcome.receipts_for_agent(agent_id)` returns the receipts attributed to a specific agent — answers "what happened to my refund attacker?" without writing the evidence-walk yourself.

## CI integration recipes

**Confirm a forbid rule fires under a tightened policy:**

```sh
yutha-ops sim ./tightened.yaml --format json > outcome.json
jq -e '
  (.receipts | map(select(.action_kind == "constitution.evaluate.deny")) | length) >= 1
' outcome.json
```

**Confirm baseline traffic isn't accidentally denied:**

```sh
yutha-ops sim ./baseline.yaml --format json > outcome.json
jq -e '
  (.persona_states[] | select(.name | startswith("support_agent")) | .intents_emitted) ==
  (.total_steps)
' outcome.json
```

**Pin quarantine behaviour.** A scripted agent's `intents_emitted` count is lower than `total_steps` if it was quarantined and went idle for at least one tick. Tighten or loosen the assertion based on what you want to enforce.

## Caveats

- **Eviction is symbolic.** When the chain reaches `enforcement.evict`, the receipt is emitted but the scripted agent stays in the scenario. The chain cycles on the next deny window. If you're measuring "how long does it take to evict?" instead of "does the chain fire at all?", use a shorter step budget that doesn't let the chain re-trigger.
- **Capability layer is bypassed.** Scripted agents can attach a `capability_id` for evidence purposes, but the simulation doesn't run a cap-check. Test cap-discipline rules via Cedar `forbid when context.capability_id == ""` clauses instead.
- **Synthetic timestamps.** Receipts emitted during a simulation carry the year-2100 synthetic clock, not your production wall-clock. Don't pipe a simulation log into a tool that expects current time without converting.
- **Three agents, no more.** Custom scripted agents are a Rust trait-impl exercise (see the [crate README](https://github.com/abhinavg6/yutha/blob/main/crates/yutha-sim/README.md)). The deliberate three-agents-only ship keeps the surface focused.

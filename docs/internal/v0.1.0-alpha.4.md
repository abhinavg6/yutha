# v0.1.0-alpha.4 — Preview rule changes before promoting them

This release adds the **four tools every operator needs to confidently change their rule set** without putting live agents at risk. Together they form a clean "preview before promote" loop: pick the preview that matches the question you're asking, run it, read the receipts, and only then activate the new rule set.

It also tightens the documentation around the substrate it builds on, so a new engineer landing on the docs site can answer "what is this and how do I use it" without having to ask an LLM to explain the jargon first.

This is a **pre-1.0 alpha** — solid enough to play with end-to-end, but wire formats and API surfaces may shift before 1.0. Pin tightly if you build on it.

---

## What's new

### Four ways to preview a rule change

A rule set in Yutha is called a **constitution** — a Cedar policy file plus a small YAML config. Changing it used to mean "edit, activate, hope." Now you have four ways to find out what the change will do before you commit:

- **[Shadow mode](https://yutha.ai/operator/shadow-mode/)** — load the candidate next to the active rule set on a live system. Every envelope evaluates against both. The active continues to gate live agents; the shadow quietly emits observation-only `constitution.evaluate.shadow.*` receipts you can query. Promote when satisfied. The most realistic preview.
- **[Replay](https://yutha.ai/operator/replay/)** — run the candidate against a past time window in your receipt log. Get an answer right now instead of waiting for a day of live traffic. Useful for "if I'd promoted last Tuesday, what would have been different?"
- **[Diff](https://yutha.ai/operator/constitution-diff/)** — structural comparison of two rule sets, with an optional behavioural delta if you also pass a time window. Use when the change is structural (adding a forbid rule, tightening a threshold) and you want a PR-friendly summary. The behavioural path composes the replay engine automatically.
- **[Simulation](https://yutha.ai/operator/simulation/)** — script synthetic adversarial traffic against the candidate in a self-contained sandbox. No live agents, no network. Use when the behaviour you want to catch (a refund attacker probing limits, a broken tool sending unscoped envelopes) doesn't exist yet in your live logs.

All four are **read-only against your production data**, never modify it, and never publish their evaluations to the agents — so a candidate denying something doesn't actually block the live agent. They're CI-friendly: each ships a JSON output format you can pipe into `jq` for pipeline gates.

The new [Previewing rule changes overview](https://yutha.ai/operator/previewing-changes/) walks the common author → diff → simulate → shadow → promote workflow and helps you pick the right preview for the question you're asking.

### Three canonical scripted agents for simulation

Simulation ships infrastructure + three opinionated scripted agents:

- `support_agent` — well-formed support-queue envelopes. Never trips a baseline rule. Use as background noise to confirm your rule doesn't accidentally deny good traffic.
- `refund_attacker` — escalating refund probes (geometric, default ×2 per tick). Surfaces probe amount through the same Cedar context attribute your refund-cap rules check. Use to characterise where the cap actually fires.
- `broken_tool` — out-of-scope sends without a capability. Pair with a Cedar `forbid` rule on the sentinel schema id to drive the four-stage enforcement chain (detect → coach → quarantine → evict).

Operators with more exotic needs implement custom scripted agents in Rust against a small `Persona` trait. The deliberate three-agents-only ship keeps the surface focused.

### Python SDK additions

```python
from yutha import run_scenario, diff_constitutions, TerminalReason

# Simulation
outcome = run_scenario("scenario.yaml")
assert outcome.count_by_action_kind()["enforcement.detect"] >= 1

# Structural diff
diff = diff_constitutions(
    left_cedar="./baseline.cedar",
    left_engine_config="./baseline.engine.yaml",
    right_cedar="./tightened.cedar",
    right_engine_config="./tightened.engine.yaml",
)
assert not diff.is_empty_structurally()
```

- `yutha.sim` module — `run_scenario`, `parse_outcome_json`, `SimulationOutcome` with `count_by_action_kind()` + `receipts_for_agent()` helpers.
- `yutha.diff` module — `diff_constitutions`, `diff_constitutions_against_window`, full `ConstitutionDiff` dataclass tree.
- `YuthaClient.replay` — async wrapper for the in-band replay-mode preview path.

### `yutha-ops` CLI additions

- `yutha-ops sim <scenario.yaml> [--format human|json|markdown]` — run a simulation scenario against the canonical persona bundle.
- `yutha-ops diff --left-cedar … --right-cedar … [--format json|markdown|html] [--window-from … --window-to …]` — structural diff with optional behavioural delta.
- `yutha-ops replay-{create,run,query,close,list}` — drive a replay session against a candidate constitution.
- `yutha-ops {activate,clear,promote}-shadow` — manage the shadow slot.

All preview-tool subcommands are pure-local where possible (`sim`, `diff` static path) — no seed, no server connection required.

### Substrate fixes folded in

- Passport-derived attributes (`framework`, `passport_tier`, `passport_hash`) and engine-tracked `reputation` now populate on every Cedar evaluation. Previously these were placeholder zeros; Cedar policies keying on them silently degraded to permit-all.
- Receipt-evidence digest now canonicalises the full entity snapshot per spec (fix for a latent determinism bug that pre-3a was hashing only `entity_count`).
- Strict-Cedar schema compliance fix on `Yutha::Action::SendEnvelope` context attrs — `current_time_unix_ns` and an always-present `capability_id` string are now correctly threaded through every eval request.

### Documentation overhaul

The docs site was reorganised and rewritten for accessibility:

- Operator guide reorganised into four buckets: **Quickstart + Authoring**, **Previewing rule changes**, **Identity & credentials**, **Running in production**.
- Concepts pages rewritten to lead with the question each primitive answers before naming the primitive.
- Home page surfaces preview tooling and reframes the verifiability layer in plain language.
- Phase/Pillar internal vocabulary scrubbed from user-facing docs — they're for operators, not for the internal roadmap.

---

## Conformance

Phase 3 ships five new behavioural scenarios in the conformance suite:

- **S9** — principal-attribute Cedar rules fire honestly (passport enrichment regression guard).
- **S10** — shadow-mode evaluator end-to-end (RFC 0018 invariants).
- **S11** — replay session end-to-end (RFC 0018 §4 invariants).
- **S12** — constitution diff engine end-to-end (five load-bearing properties).
- **S13** — simulation harness end-to-end (five load-bearing properties).

All pass; behavioural pins are explicit in the test files so a regression is visible in the failing assertion line.

---

## What's next

The observability pillar — OpenTelemetry exporter for receipts, causality CLI, state-query RPCs — is in design and targeted for the next release. Until then, receipt logs are queryable through `yutha-ops grep` and the receipt-store API. The PRD has the full roadmap.

---

## Install

**Python SDK:**

```sh
pip install yutha==0.1.0a4
# or with a framework adapter
pip install 'yutha[langgraph]==0.1.0a4'
pip install 'yutha[crewai]==0.1.0a4'
pip install 'yutha[openai-agents]==0.1.0a4'
pip install 'yutha[maf]==0.1.0a4'
```

**Rust workspace** (from a clone):

```sh
git checkout v0.1.0-alpha.4
cargo build --release
```

The `yutha-ops` and `yutha-control-plane` binaries land in `target/release/`.

**Docs:** [https://yutha.ai](https://yutha.ai)

---

## Acknowledgements

Yutha is open-source under Apache 2.0, stewarded by a single maintainer. Issues, design discussion, and PRs welcome at [github.com/abhinavg6/yutha](https://github.com/abhinavg6/yutha).

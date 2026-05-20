# Reversible long-running actions

!!! info "Page in progress"
    Full content is being written. The conformance scenario (S7) is in [`crates/yutha-conformance/`](https://github.com/abhinavg6/yutha/tree/main/crates/yutha-conformance/src) and exercises the engine's reverse path end-to-end.

What this example will cover:

- The agents: an autonomous operator agent making state-changing calls
- The constitution: pattern detection for misbehavior, four-stage progression
- Stage 1: flag — receipt records, agent continues
- Stage 2: restrict — capabilities narrowed
- Stage 3: quarantine — consequential sends blocked, receipts retained
- The reversal: the engine emits compensating actions for the offending steps
- Why this is the right model for long-running workflows that can't simply be killed

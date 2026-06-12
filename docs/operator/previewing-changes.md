# Previewing rule changes

When you change the rules that govern your agents — what they're allowed to do, what triggers a coach-then-quarantine response, what counts as a budget breach — you want to know what *will* happen before the change goes live. Yutha gives you four ways to find out, each suited to a different question.

A rule set in Yutha is called a **constitution**: a Cedar policy file (the `permit` / `forbid` rules) plus a small YAML config (scoring rules, enforcement-chain stages, named predicates). When you "preview a rule change," you're previewing how a candidate constitution would behave compared to the one running today.

## Which preview tool to use

| You want to know… | Use |
|---|---|
| How would my new rules behave against the actual traffic my agents are sending **right now**? | [Shadow mode](shadow-mode.md) |
| How would my new rules have behaved against the traffic my agents sent **last week**? | [Replay](replay.md) |
| What changed between **rule set A** and **rule set B**, both as a structural diff and as a behaviour delta? | [Diff](constitution-diff.md) |
| How would my new rules respond to traffic shapes that **don't exist yet** in my logs — a refund attacker probing limits, a broken tool sending bad envelopes? | [Simulation](simulation.md) |

All four are read-only against your production data, never modify it, and never publish their evaluations to the agents (so a candidate rule denying something doesn't actually block the live agent). They're CI-friendly: every one has a JSON output format you can pipe into `jq` for pipeline gates.

## A common workflow

1. **Author** the candidate constitution. Edit Cedar source + engine config locally.
2. **Diff** it against the live one. `yutha-ops diff` shows you the structural change in plain English (what rules were added, removed, modified). If you also pass a past-window flag, you get a behaviour delta — how many more denies, how many extra enforcement chain firings.
3. **Simulate** the candidate against synthetic adversarial traffic. Confirms the new rule actually catches what you intended it to catch, and doesn't accidentally deny baseline traffic.
4. **Shadow** the candidate on live traffic for a day or a week. Every envelope evaluates against both the active and the candidate; only the active enforces. Watch the `constitution.evaluate.shadow.deny` receipt stream — those are the envelopes the candidate would have denied if it had been active. Decide if that matches intent.
5. **Promote** the shadow to active when you're satisfied. `yutha-ops promote-shadow` atomically swaps; running agents see the new rules on their next evaluation.

Replay is the alternative path to step 4 when you'd rather not wait for a day of live traffic — it lets you ask "what would the candidate have done to last Tuesday's traffic?" without leaving the candidate active.

## What each tool guarantees

- **Production-store isolation.** Shadow, replay, diff (behavioural), and simulation never write to your live receipt log or trigger your live enforcement engine. Shadow emits its own separate receipt stream (`constitution.evaluate.shadow.*`); replay writes to a per-session isolated store; diff queries both stores read-only; simulation runs entirely in memory.
- **No live-agent side effect.** A preview can show that the candidate would deny envelope X — but envelope X still goes through the active constitution. Your agents don't see the candidate at all until you promote it.
- **No on-chain pollution.** Preview receipts (shadow, replay, simulation) are never anchored to the Sui ledger. Only production constitution emissions reach the chain.

## Picking the right preview

If you have ongoing live traffic you trust to represent normal behaviour, **shadow mode** is the most realistic preview. It runs the candidate against the same envelopes your agents are actually producing, in real time.

If you want a snapshot answer right now without waiting for traffic, **replay** is the fastest path — it walks a past time window through the candidate. Useful for "what would have happened last Tuesday?" questions.

If your change is *structural* — adding a forbid rule, tightening a scoring threshold, renaming a procedure — **diff** is the right starting point. It shows you exactly what changed before you commit to running a behavioural preview. Diff's optional behavioural path then composes replay automatically.

If your change is *adversarial* — you're tightening a rule specifically to catch a behaviour pattern that hasn't appeared in production yet — **simulation** lets you script that behaviour directly. The canonical refund-attacker persona, for instance, deliberately probes a refund cap to confirm the cap fires; production logs rarely contain that pattern in isolation.

Use them together: diff for the structural picture, simulation for the adversarial probe, then either replay (fast, retrospective) or shadow (slow, live) for the behavioural confirmation before promoting.

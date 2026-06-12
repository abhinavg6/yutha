# Replay (against past traffic)

Replay lets you preview a candidate rule set against a past window of traffic — what the candidate would have decided on envelopes that already came through. It's the answer to "if I'd promoted this rule change last Tuesday, what would have been different?" without having to actually wait a day for live data to accumulate, the way [shadow mode](shadow-mode.md) requires.

You point the candidate at a window (a start and end time). The control plane spins up an isolated copy of the enforcement engine with the candidate rule set loaded, walks the receipts in that window through it, and writes any new emissions (the four-stage enforcement chain receipts the candidate would have produced) into a per-session, isolated store. Your production receipt log is never touched — replay is observation-only by construction.

When the session finishes, you query the per-session store the same way you query production (`yutha-ops grep`, `client.receipt.query`, etc.), compare against the production tally for the same window, and decide whether to promote.

It's the right preview to reach for when you want a fast retrospective answer and you have a representative past window in your receipt log. The other three preview tools cover the cases this one doesn't: [shadow mode](shadow-mode.md) for live traffic, [diff](constitution-diff.md) for a structural comparison of two rule sets, [simulation](simulation.md) for synthetic traffic shapes that don't exist yet in your logs.

This page is the operator runbook. The substrate side lives at
[RFC 0018 §4](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0018-shadow-mode-and-replay.md).

---

## What replay is for

Shadow mode is the right answer when you want to preview a candidate
against the **next** ten thousand envelopes. Replay is the right
answer when the question is one of these:

- **"This new enforcement rule would have caught those three incidents
  from last quarter, right?"** Author the rule into a candidate,
  replay against the receipt window the incidents lived in, check
  that `enforcement.detect` / `quarantine` fires on the agents you
  expect.
- **"How often would tightening this Cedar `forbid` have triggered
  the four-stage chain on real agents over the past month?"** Replay
  the same window with the candidate; count session-scoped
  `enforcement.detect` receipts grouped by `principal`.
- **"My active constitution has a coach threshold of 5. Should it
  have been 3?"** Author a candidate at threshold 3, replay the same
  window, count divergences against the production
  `enforcement.coach` stream.

Replay only addresses changes that change **what the engine emits**
(Cedar gating, scoring deltas, enforcement-rule firing). It does not
replay the production engine's previous emissions — it produces a
**candidate** engine's emissions on the same input window. If the
two diverge, you've found the answer to "would my rule change have
mattered?"

---

## What replay does and does not do

| Surface | Production active | Replay session |
|---------|-------------------|----------------|
| Production receipt store writes | unchanged | **never written to** |
| Session-scoped receipt store | n/a | candidate's emissions land here |
| `EnvelopeService.Send` cap-layer gate | gates on this | not involved |
| `EnforcementEngine` reputation / quarantine | reacts to production | private engine, dies with session |
| `Sui` anchoring driver | anchors production receipts | **never** anchors replay receipts |
| `constitution.evaluate.*` receipts | emits from active eval | not re-emitted; engine consumes them |
| `enforcement.*` receipts | emits into production store | emits into session store (same `action_kind`) |
| `replay.session.{create,close}` | n/a | emits into production store (audit trail) |

Three properties worth knowing before you author a candidate:

- **Production isolation is by construction.** The session's receipt
  store is a different `Arc<dyn ReceiptStore>` than production — not
  a filter, not an opt-in. Even a buggy replay session can't write
  to production. Same property for the anchoring driver: it consults
  the production store only, never any session store.
- **Replay receipts live in the session store, and die with it.**
  When you `replay-close` (or the session TTL elapses), the
  session's receipts are released. Audit-grade replay output is on
  you: query the session, persist what you care about, then close.
- **The session's emissions are tagged.** Every replay-emitted
  `enforcement.*` receipt carries a `replay_session_id` evidence
  entry equal to the session id, plus the candidate's
  `constitution_hash`. They use the **same canonical
  action-kinds** as production (no `enforcement.replay.detect`
  variant) so `yutha-ops grep enforcement.detect` against the
  session store works exactly as it does against production.

---

## Cold vs warm sessions

A replay session needs an `EnforcementEngine` somewhere in its
lifecycle. The two `mode` options differ only in what state the
engine starts in:

- **`--mode cold` (default).** The engine starts at defaults — every
  agent unknown, every reputation at 1.0, no quarantines, no
  sliding-window counters. The window plays through against that
  blank slate. This is the right mode when the rule change you're
  previewing should fire from scratch — e.g., "does this new detect
  rule trigger on the first burst of denies in the window?"
- **`--mode warm` (`--warm-lookback-hours N`, default 24).** Before
  the window plays, the engine consumes receipts from `[from −
  Nh, from)` purely to rebuild approximate engine state — no
  session-scoped emissions for the lookback receipts. Then the
  window plays against the rebuilt engine. This is the right mode
  when the rule change interacts with **accumulated state** —
  reputation drift, sliding-window counters, quarantine schedules
  — that wouldn't be exercised by a cold-init session.

Warm is bounded by design. Exhaustive rebuild from swarm genesis is
the forensic-audit use case deferred to a follow-on RFC. For
day-to-day diligence, 24h of lookback usually approximates
production engine state closely enough; bump the flag if your
sliding windows are longer.

---

## The end-to-end workflow

### Step 1 — Author the candidate

A constitution is a Cedar policy source file plus an engine-config
YAML, the same artifacts described in
[Authoring constitutions](authoring-constitutions.md). For replay,
you author it identically — there's no separate "replay format".

### Step 2 — Create the session

```bash
yutha-ops replay-create path/to/candidate.cedar \
    --engine-config path/to/candidate.engine.yaml \
    --version 1.1.0-rc \
    --schema-version 1.1.0 \
    --from   1748736000000000000 \
    --to     1751328000000000000 \
    --filter constitution.evaluate.deny \
    --filter enforcement.detect \
    --mode cold
```

`--from` and `--to` are `monotonic_ns` bounds — the same field the
receipt-store time-range query uses. The control plane:

1. Loads the candidate through the same loader/validator path as
   `activate` (structural checks, `@<name>` predicate resolution,
   Cedar Validator in Strict mode, load-time bound enforcement). A
   bad candidate is refused with `FAILED_PRECONDITION` at session-
   create time, not later mid-replay.
2. Provisions the session-scoped receipt store
   (`MemoryReplayStore` today; `PostgresReplayStore` is a follow-on).
3. Emits a `replay.session.create` receipt into the **production**
   store — the audit-trail entry that says "operator X created
   replay session Y against candidate Z at time T".
4. Returns the new `replay_session_id` (UUIDv7).

Python SDK equivalent:

```python
from yutha import YuthaClient, Constitution, ReplayMode, ReplaySessionWindow

client = await YuthaClient.connect_as_operator(...)
candidate = Constitution(...)
created = await client.replay.create_session(
    candidate=candidate,
    window=ReplaySessionWindow(
        from_unix_ns=1_748_736_000_000_000_000,
        to_unix_ns=1_751_328_000_000_000_000,
        action_kind_filter=["constitution.evaluate.deny", "enforcement.detect"],
    ),
    mode=ReplayMode.COLD,
)
print(created.replay_session_id, created.session_create_receipt)
```

### Step 3 — Run the window

```bash
yutha-ops replay-run --session-id <replay_session_id>
```

The CLI streams `ReplayService.RunSession` progress events, one per
batch, plus a terminal `window complete` line. Behind the scenes:

- The control plane queries the production store for receipts in
  `[from, to]` matching the action-kind filter.
- It sorts ascending by `monotonic_ns` (engine's sliding-window
  pruning depends on monotonic ordering).
- For each receipt, it calls the session engine's `on_receipt` +
  `poll_scheduled(receipt.wall_clock)` — the same path the
  production receipt forwarder uses, just against the per-session
  engine instead of the production one.
- Any emitted `EnforcementEffect`s become signed receipts in the
  session-scoped store, with `replay_session_id` evidence and
  session-internal causal-chain predecessors (next step's
  predecessors point at this step's emissions, not at the original
  receipt's predecessors — graph walks across replay receipts stay
  self-contained).

Run is idempotent — calling `replay-run` twice on the same session
replays the same window twice (you'll see double emissions).
Closing and re-creating against the same window is the right way to
re-run cleanly.

### Step 4 — Inspect the session

Query the session-scoped store via the operator CLI:

```bash
yutha-ops replay-query --session-id <id> enforcement.detect --limit 50
yutha-ops replay-query --session-id <id> enforcement.quarantine --limit 50
```

Or programmatically:

```python
page = await client.replay.query_replay_receipts(
    replay_session_id=created.replay_session_id,
    action_kind="enforcement.detect",
    limit=50,
)
for r in page.receipts:
    print(r.action_kind, r.actor, r.evidence)
```

The same `yutha-ops grep` queries you use against production work
against the session — same `action_kind`s, same evidence keys.
What's distinguishable is the `replay_session_id` evidence entry on
every session-scoped enforcement receipt.

A typical diligence loop:

- **"Did my candidate's detect rule fire on the right agents?"** —
  `replay-query enforcement.detect`, group by `target_agent_id`
  evidence, compare against the production `enforcement.detect`
  stream for the same window.
- **"How many extra quarantines would I have produced?"** —
  `(session enforcement.quarantine count) − (production
  enforcement.quarantine count in window)`. Production count is the
  baseline — a regular `yutha-ops grep` query, no session id.
- **"Which specific receipts triggered the divergence?"** — pull
  the candidate's detect receipts, walk `matched_timestamps_ns`
  evidence keys back into the production store, see which original
  receipts the candidate's engine grouped together.

### Step 5 — Close the session

```bash
yutha-ops replay-close --session-id <replay_session_id>
```

The control plane:

- Releases the per-session engine state + receipt store. Any
  receipts not persisted out before close are gone.
- Emits a `replay.session.close` receipt into the **production**
  store — the audit-trail closer for `replay.session.create`,
  carrying `receipts_replayed_total`.

Sessions that aren't explicitly closed eventually time out and the
control plane closes them automatically (see [Limits and
caveats](#limits-and-caveats)).

---

## Same control plane, isolated by construction

The single most common question about replay is "where does this
*run*?" The answer:

> Replay runs inside the same control-plane process as production
> traffic, against the same Postgres receipt store. Isolation between
> production and replay is **semantic** (different `Arc`s), not
> physical (separate process or database).

That's deliberately the simplest defensible design. The receipt store
trait is shared between production and replay — but each session
holds its own `Arc<dyn ReceiptStore>` from
`ReplayStore::session_store(session_id)`, distinct from the production
`Arc<dyn ReceiptStore>` the gRPC handlers hold. Production writes
never reach a session store; session writes never reach production.
The anchoring driver is wired only to the production store handle, so
replay emissions never get queued for Sui anchoring either. These
properties are unit-tested in `crates/yutha-conformance`'s S11 scenario
and in
`crates/yutha-anchor-sui/src/candidate_source.rs::replay_receipts_never_appear_in_candidates`.

What this means in practice — three things the operator should care
about:

- **Semantically, you can't corrupt production with a replay
  session.** Even a buggy replay-side bug can't write to the
  production store; the type system enforces it. Same for the
  anchoring driver.
- **Operationally, replay shares compute and database connections
  with production.** Replay walks a Postgres time-range and feeds
  every match through an `EnforcementEngine`. On a large window
  (millions of receipts), that's real CPU and real Postgres
  connection-pool load on the same process that's serving live
  envelope traffic.
- **There are no rate limits or read-budget caps on
  `ReplayService.RunSession` today.** An operator who runs replay
  against a six-month window during peak load can degrade live
  traffic. Until the rate-limit follow-on lands, replay-during-peak
  is an operator-discipline problem.

The mitigation that's been validated, when replay load matters: run
**two control-plane processes** against the same Postgres database.
The "production" process serves live `EnvelopeService.Send` traffic
and owns the anchoring driver. The "replay" process is otherwise
identical but is reachable only by operators on a separate endpoint.
Same database, separate compute. The semantic isolation properties
hold either way — this is purely a compute-isolation play.

---

## The audit trail

Replay is fully receipt-traceable. Two new production-store
action-kinds bracket every session:

| `action_kind` | Producer |
|---|---|
| `replay.session.create` | When you create a session. Evidence: `replay_session_id`, `candidate_constitution_hash`, `candidate_constitution_version`, `window_from_unix_ns`, `window_to_unix_ns`, `action_kind_filter` (comma-joined), `mode` (`cold`/`warm`), `warm_lookback_hours`. Lands in the **production** store so the operator action is part of the production audit chain. |
| `replay.session.close` | When you close a session. Evidence: `replay_session_id`, `receipts_replayed_total`. Lands in the **production** store. Closes the audit bracket. |

Inside the session store, the candidate's emissions match production
canonically:

| `action_kind` | Producer |
|---|---|
| `enforcement.detect` / `coach` / `quarantine` / `evict` / `reverse` | The candidate's engine, fired by the session's `play_receipt` walk. Same evidence-shape as production plus a `replay_session_id` evidence entry equal to the session id. Lands in the **session-scoped** store. |

The canonical registry of `action_kind` strings lives at
[`/spec/receipt/canonical-actions.md`](https://github.com/abhinavg6/yutha/blob/main/spec/receipt/canonical-actions.md);
the two replay-session entries plus the per-stage `enforcement.*`
entries are documented in full there.

---

## Limits and caveats

- **Replay does not write to production.** Said three times in this
  doc on purpose. If you ever see an `enforcement.*` receipt in
  production with a `replay_session_id` evidence entry, file a bug —
  that's a contract violation.
- **Replay does not anchor to Sui.** The anchoring driver consults
  the production store only. Session-scoped receipts are
  unanchored by design and stay unanchored even after promotion.
- **Sessions are TTL'd.** The default session TTL is operator-tunable
  (see the control-plane `--replay-session-ttl-hours` flag, default
  24h). An idle session past TTL is closed automatically and emits
  a `replay.session.close` receipt with reason
  `auto_closed_idle_ttl`. Persist what you care about before walking
  away.
- **Backing store follows `--receipt-backend`.** When the control
  plane runs with `--receipt-backend memory`, sessions and their
  per-session receipts live in process memory and are lost on
  restart. When it runs with `--receipt-backend postgres`,
  `PostgresReplayStore` shares the same pool as the production
  receipt store and survives restarts. The `replay_*` table family
  is provisioned automatically by the standard
  `PostgresStore::migrate()` call at startup; no separate migrate
  step needed.
- **No rate-limit / read-budget on `RunSession` today.** See [Same
  control plane, isolated by construction](#same-control-plane-isolated-by-construction).
  Discipline-only mitigation: run replay during off-peak windows,
  or deploy a separate replay process against shared Postgres.
- **Replay does not re-emit `constitution.evaluate.*` receipts.** The
  session's engine consumes the production `constitution.evaluate.*`
  stream as input — it doesn't re-evaluate Cedar against the
  candidate per envelope (the production entity-snapshot isn't
  preserved on the receipt-store side). What replay produces is the
  **enforcement** delta: would the candidate's enforcement rules
  have fired differently given the same production Cedar denies?
  Forward-looking Cedar-policy preview is shadow mode's job.
- **Warm-mode lookback is bounded.** The control plane caps the
  lookback at a defensible window (24h default). Exhaustive
  rebuild from swarm genesis is a forensic-audit use case deferred
  to a follow-on RFC.
- **Concurrent sessions share the same control plane.** Today the
  control plane will happily accept multiple concurrent
  `ReplayService.CreateSession` calls; resource isolation between
  them is process-wide (each session gets a private engine, but
  they share Postgres connections and CPU). High concurrency is an
  operator-discipline problem same as the single-session case.

---

## Cross-references

- [Shadow mode](shadow-mode.md) — the forward-looking preview
  (next envelopes); replay is the backward-looking preview (past
  receipts).
- [Authoring constitutions](authoring-constitutions.md) — the
  authoring loop replay builds on.
- [Monitoring & receipts](monitoring.md) — `yutha-ops grep` and
  the broader receipt-query patterns; replay queries are
  scoped variants of the same.
- [Sui anchoring](sui-anchoring.md) — the anchoring driver consults
  the production store only; this is the doc that says why.
- [RFC 0018](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0018-shadow-mode-and-replay.md)
  — the substrate-level contract for shadow mode and the replay
  engine.
- [canonical-actions.md](https://github.com/abhinavg6/yutha/blob/main/spec/receipt/canonical-actions.md)
  — full evidence-shape catalog for `replay.session.{create,close}`
  and the per-stage `enforcement.*` action-kinds.

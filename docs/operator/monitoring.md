# Monitoring and receipts

The receipt log is where every consequential thing that happens in
your swarm lands as an evidentiary record. This page is the
operator's guide to using it — querying it, reconstructing what
happened, alerting on patterns that matter, and getting the data
into whatever observability stack you already run. Step 5 of the
[operator quickstart](quickstart.md) covers the basic `yutha-ops
grep` shape; this page builds on that.

---

## What the receipt log is

A receipt is an append-only, content-addressed, signed record of
one consequential action. Every send, every capability check, every
constitution evaluation, every enforcement-stage transition, every
operator credential action — each lands as a receipt with the
actor's signature, the inputs and outputs ("evidence"), the causal
predecessors, and a wall-clock plus monotonic timestamp. The store
guarantees you can append and read; nothing can rewrite or delete.

Two consequences shape this whole page:

- **The catalog of "consequential" is fixed.** The full list of
  canonical `action_kind` strings lives in
  [`/spec/receipt/canonical-actions.md`](https://github.com/abhinavg6/yutha/blob/main/spec/receipt/canonical-actions.md);
  adding a new kind requires an RFC. So when you alert on
  `enforcement.evict`, you know exactly what produces one and no
  future version will silently start producing them under a
  different name.
- **The log is the source of truth.** Logs and traces are
  diagnostic — they help you ask questions. Receipts are
  evidentiary — they are the answer. If something happened in your
  swarm and there's no receipt for it, the substrate didn't do it.

Receipts are served via `ReceiptService.Query` over gRPC with
agent-bearer auth. The Python SDK's `client.receipt.query` hits
the same RPC; `yutha-ops grep` is a thin wrapper around it.

---

## Primary query tool today: `yutha-ops grep`

`yutha-ops grep` is the operator's main hand-on-keyboard surface
into the receipt log. It takes an `action_kind` and an optional
`--limit`, and prints one line per matching receipt with the
timestamp, actor, and evidence count.

```bash
# Recent envelope traffic — high-volume, useful for confirming the
# substrate is alive.
yutha-ops grep envelope.send --limit 50

# Constitution denies — these are the policy edges agents are
# hitting. A sudden spike usually means a workload changed.
yutha-ops grep constitution.evaluate.deny --limit 20

# Recent detection patterns — informational by themselves; cluster
# them by target agent to see who's repeatedly tripping rules.
yutha-ops grep enforcement.detect --limit 10

# Recent evictions. Should be near-empty on a healthy swarm; every
# entry deserves a look.
yutha-ops grep enforcement.evict --limit 5
```

Output shape:

```
[2026-05-22T14:03:17.451Z] enforcement.detect actor=019e3ce9-8d7d-70ec-9209-e34415ca9477 evidence=5
```

The evidence count is the most useful signal in that line — it
tells you how much context the producer attached. For a
`constitution.evaluate.pass` that's the matched Cedar policy IDs
(one per `permit` rule that fired) plus the input-attribute digest;
for `enforcement.detect` it's the rule ID, target agent, matched
receipt IDs, and reputation delta; for a `prefer`-rule-driven pass,
evidence also carries per-rule score contributions and the total
score. Fetch the full receipt via the SDK's `receipt.get` by
content address to inspect each evidence field's typed value.

What `grep` doesn't do today: query by agent, by predecessor, by
time range, or by combinations. The store supports all four on the
wire (`Query::ByAgent`, `Query::ByPredecessor`, `Query::ByActionKind`,
`Query::ByTimeRange`), but the CLI only exposes by-action-kind. For
everything else drop into the SDK —
`await client.receipt.query(yutha.AgentQuery(agent_id=...))` and
friends. An `--agent`, `--since`, and `--predecessor` flag set is
on the list.

---

## Common audit patterns

Four reconstruction scenarios that come up often.

**"Why was agent X quarantined?"** Start at the
`enforcement.quarantine` receipt. Its evidence carries the
`coach_receipt_id` (when present) and `enforcement_rule_id`; the
coach receipt points at `detect_receipt_id`; the detect receipt's
evidence lists `matched_receipt_ids` — the underlying receipts
(usually `constitution.evaluate.deny` entries) that completed the
trigger pattern. Walking quarantine → coach → detect → matched
gives you the rule that fired, the behavior that tripped it, the
cooldown, the coach, and the capability decision that followed.

**"What did agent X do today?"** Drop into the SDK with
`Query::ByAgent` — every receipt the agent acted on comes back.
`yutha-ops grep` is action-kind-only today.

**"Did we evaluate the constitution on every send?"** Compare
`envelope.send` counts against `constitution.evaluate.pass + .deny`
over the same window. Mismatches beyond window-boundary slop mean
something is bypassing the evaluator gate — a substrate invariant,
not a tuning question, so file a bug.

**"What did the operator do?"** Query receipts whose actor is the
control plane's identity (operator-driven actions land as
control-plane-actor receipts via the bearer interceptor). The
catalog: `constitution.activate`, `agent.operator_revoke`,
`capability.revoke` with an operator-revoke cause, `anchor.commit`.

---

## The canonical action-kinds you'll see most

A short orientation. The
[full catalog](https://github.com/abhinavg6/yutha/blob/main/spec/receipt/canonical-actions.md)
covers every domain, payload shape, and evidence schema.

**Agent lifecycle** — `agent.register`, `agent.revoke` (self),
`agent.operator_revoke` (operator eviction, with optional
`cascade_receipt_ids` for capabilities revoked in the same
operation), `agent.rotate_key`, `agent.heartbeat.missed`.

**Capability** — `capability.issue`, `capability.attenuate`,
`capability.revoke`, `capability.check.pass` / `.deny`. The check
receipts are highest-volume; graph them, don't alert on them.

**Envelope** — `envelope.send`, `envelope.deliver`,
`envelope.deliver.failed` (replay, expired, signature failure,
recipient unknown). Failed-deliver is your first signal of network
or admission misconfiguration.

**Constitution** — `constitution.activate` (genesis + amendments),
`constitution.evaluate.pass` / `.deny`. The pass-vs-deny ratio is
one of the most useful health signals — see dashboards below.

**Enforcement** — `enforcement.detect`, `.coach`, `.quarantine`,
`.evict`, `.reverse`, plus `.evict_timeout` when an evict is
abandoned because no supervisor countersign arrived. The alarm
cluster — next section covers it in detail.

**Verifiability** — `anchor.commit` per successful Sui anchor
transaction. Control-plane-signed only; carries the batch root,
count, ns-range, action-kind histogram, and on-chain tx digest.
Useful for confirming the [anchoring loop](sui-anchoring.md) is
keeping up.

---

## Enforcement event tracking

The four enforcement stages map to four alerting tiers.

**`enforcement.detect`** lands every time a sliding-window pattern
completes. Informational on its own; clusters are the signal — many
detects against one agent in a short window, or detects spreading
across many agents in lockstep (usually a config change that just
rolled out).

**`enforcement.coach`** is the first agent-visible signal — the
engine sent an `ADVISE` envelope to the offending agent. One per
recovery cycle is normal; repeats inside the cooldown window mean
behavior didn't change in response.

**`enforcement.quarantine`** is the first capability-affecting
signal. From this moment the cap layer denies every `Issue` and
`Check` for the target agent with `SubjectQuarantined`. Page-worthy
if the agent sits in a business-critical path. Evidence carries
`expires_at_wall_clock` when the rule sets a finite window;
absent means indefinite.

**`enforcement.evict`** is terminal and always page-worthy. Agent
gone, every held capability revoked, any active subscribe streams
torn down. Evidence includes `substrate_revoke_receipt_id` (the
`agent.operator_revoke` it drove) and `cascade_revoke_receipt_ids`.
Supervisor countersign is required by default, so the receipt's
existence itself proves two-person rule was honored.

A starting-point alerting recipe: five `enforcement.detect` in five
minutes against the same `target_agent_id` is the "something is up
with this agent" signal; a single `enforcement.quarantine` against
a business-critical role pages a human; every `enforcement.evict`
pages a human. Tune from there.

---

## Structured logs and tracing today

The control plane uses [`tracing`](https://docs.rs/tracing/) with
`tracing-subscriber`'s `FmtSubscriber` for output. The default
filter is `warn`; turn it up via `RUST_LOG`:

```bash
# Production posture — info from yutha itself, warns from
# everything else.
RUST_LOG=yutha=info cargo run -p yutha-control-plane -- ...

# Debugging a specific concern — capability layer at debug.
RUST_LOG=yutha=info,yutha_capability=debug cargo run -p yutha-control-plane -- ...
```

Every consequential path is instrumented. Startup logs one line
per backend chosen, workload loaded, anchoring status, gRPC bind.
The enforcement scheduler logs each emitted effect with
action_kind, target, rule ID, reputation delta, and receipt ID.
The anchor driver logs each sealed batch with count and watermark.
Authentication failures and constitution denies log at `warn` with
enough context to trace back to the originating request.

For aggregation, swap `FmtSubscriber` for a JSON layer
(`tracing-subscriber::fmt::json`); the control-plane binary doesn't
ship that configuration but it's a one-call change in a fork. Any
pipeline that consumes stdout JSON works.

**What's not yet wired:** there's no OpenTelemetry exporter today.
All the `tracing` instrumentation an OTLP bridge would consume is
in place; the dependency itself isn't in the binary. Operators who
want spans and metrics in an existing OTel stack either parse the
JSON logs in their aggregator (Datadog, Splunk, Loki) and derive
metrics from the structured fields, or build the same metrics from
the receipt log directly. An OTLP exporter is a worthwhile future
enhancement; not blocking anything material today.

---

## Recommended dashboards

A handful of derived metrics worth graphing — all computable from
the receipt log, most also derivable from JSON logs.

- **Receipts/sec by `action_kind`.** Volume plus composition; a
  sudden mix shift is usually the first sign a workload changed.
- **Constitution deny rate.** `count(.deny) / (count(.pass) +
  count(.deny))` over a rolling window. A step up means agents are
  hitting policy edges they weren't before — workload change or a
  constitution amendment that tightened a rule.
- **Enforcement-stage breakdown by agent.** Per-`target_agent_id`
  table of latest stage reached and time since. Sort by latest
  stage to surface agents in or near quarantine.
- **Capability issue-to-check ratio per agent.** A runaway agent
  delegating downstream shows up as a rising issue rate without a
  matching check rate from recipients.
- **Anchor lag (if running Sui anchoring).** Time between the
  newest unsealed receipt's `occurred_at` and the latest
  `anchor.commit.anchored_at_wall_clock`. Stays bounded by the
  cadence knobs in normal operation; a sustained climb means the
  driver isn't keeping up — usually a chain-side gas or RPC issue.

---

## Backup, replay, and disaster recovery

Receipts are append-only and content-addressed, so backup is
whatever your Postgres backup strategy is — see
[Deployment](deployment.md) for backend choices. Restore is a
plain Postgres restore; the receipt store adds no reconstruction
logic. Downstream subscribers re-process the tail naturally on
restart: the enforcement engine rebuilds its sliding-window
counters from the log, and the anchor driver resumes at the
on-chain `last_ns_range_end` watermark. The receipt API isn't
mutating, so re-appending the same receipt is idempotent at the
store layer (content-address collision).

One note: restoring a snapshot older than the on-chain anchor
watermark leaves the driver seeing on-chain state ahead of the
restored log. It catches up on the next batch — just be aware of
the brief divergence window.

---

## Pointers

- Full action-kind catalog with payload + evidence schemas:
  [`/spec/receipt/canonical-actions.md`](https://github.com/abhinavg6/yutha/blob/main/spec/receipt/canonical-actions.md).
- Receipt wire format and rationale:
  [`/spec/receipt/`](https://github.com/abhinavg6/yutha/tree/main/spec/receipt).
- Operator-attributed receipts and the revoke/cascade story:
  [Operator credentials](operator-credentials.md).
- On-chain verifiability for the receipt log:
  [Sui anchoring](sui-anchoring.md).
- Storage backends and the Postgres backup story:
  [Deployment](deployment.md).

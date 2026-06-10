# Shadow-mode constitution preview

The shadow slot lets you preview a constitution against real
traffic before it gates anything. You activate the candidate as a
shadow; every envelope evaluates against both the active slot and
the shadow slot; the active continues to gate the cap layer and
enforcement engine, the shadow only emits observation-only receipts
you can query. When you're satisfied the candidate is what you
want, you promote the shadow into the active slot atomically.

This page is the operator's guide to that workflow. It complements
[Authoring constitutions](authoring-constitutions.md), which covers
authoring and activating in the active slot — shadow mode is the
preview layer on top of the same authoring loop.

The substrate side lives at
[RFC 0018](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0018-shadow-mode-and-replay.md);
this page is the operator-facing translation.

---

## What shadow mode is for

Whether you're standing up a brand-new swarm or amending an
existing constitution, you want to know what your constitution
will actually do against real traffic before any envelope is
gated on it. Shadow mode is that "actually do" preview:

- **For a fresh swarm**, you can load a candidate as a shadow,
  point a small slice of agents at the control plane, watch the
  shadow's decisions on real envelopes, and promote when you're
  confident. The promote brings the constitution into the active
  slot atomically — no separate "activate" call.
- **For a swarm that already has an active constitution**, you
  load the amended candidate as a shadow alongside the current
  active. Both evaluate every envelope; the active continues to
  gate, the shadow only observes. When the shadow's behaviour
  matches what you wanted, you promote — atomic swap, no second
  activation window where things could break.

Either way, the property you get is that the candidate runs against
real traffic before it has the power to deny anything.

---

## What shadow mode does and does not do

Shadow mode runs both slots against every envelope and emits two
evaluation receipts per envelope when a shadow is loaded. The
shadow is fully read-only: nothing gates on what it decides.

| Surface | Active slot | Shadow slot |
|---------|-------------|-------------|
| `EnvelopeService.Send` cap-layer gate | gates on this | not consulted |
| `EnforcementEngine` reputation / quarantine | reacts to this | NEVER reacts |
| `constitution.evaluate.{pass,deny}` receipts | emits these | not emitted |
| `constitution.evaluate.shadow.{pass,deny}` receipts | not emitted | emits these |
| `procedure.{enter,transition,timeout}` receipts | emits these | NOT emitted |
| Scoring (`prefer` rules) | full | full (preview only) |

Two consequences worth knowing before you author a candidate:

- **Procedure transitions are skipped on the shadow path.** If your
  candidate adds or changes a procedure (RFC 0011 §3), shadow mode
  won't tell you whether the procedure machine works — it'll show
  you the Cedar gating delta and the scoring delta, nothing else.
  Procedures need to live in the active slot to be exercised.
- **Shadow denies don't affect the agent.** No reputation drop, no
  quarantine schedule, no sliding-window counter movement. A
  candidate that would tank an agent's reputation if it were active
  produces zero engine-state change while it's a shadow. That's
  the whole point.

---

## The end-to-end workflow

### Step 1 — Author the candidate

A constitution is a Cedar policy source file plus an engine-config
YAML, the same artifacts described in
[Authoring constitutions](authoring-constitutions.md). For shadow
use, you author it identically — there's no separate "shadow
format". The `constitution_version` field is a free-form semver
string; pick whatever makes sense for your situation (e.g.,
`1.0.0` for a first constitution, `1.1.0-rc` if you're previewing
an amendment to a `1.0.0` active).

### Step 2 — Activate as shadow

```bash
yutha-ops activate-shadow path/to/candidate.cedar \
    --engine-config path/to/candidate.engine.yaml \
    --version 1.0.0 \
    --schema-version 1.1.0
```

The CLI prints the shadow constitution's hash and the
`constitution.shadow_activate` receipt id. Both are queryable for
audit reconstruction.

The same validation pass that runs on `activate` runs here —
structural checks, `@<name>` predicate resolution, Cedar Validator
in Strict mode, load-time bound enforcement (RFC 0012 §3.3). A
candidate that fails any of those is refused with
`FAILED_PRECONDITION` at shadow-activate time, not later during
traffic. That's deliberate: catch authoring mistakes before they
quietly produce zero shadow receipts because every eval errored
out.

Loading a shadow does NOT bind the candidate onto the enforcement
engine. The engine only ever reacts to receipts from the active
slot.

If you call `activate-shadow` a second time while a shadow is
already loaded, the new candidate replaces the previous one. No
separate `clear-shadow` is needed first; the
`constitution.shadow_activate` receipt covers the new activation
regardless of prior slot state.

Python SDK equivalent:

```python
from yutha import YuthaClient, Constitution

client = await YuthaClient.connect_as_operator(...)
candidate = Constitution(
    spec_version=...,
    schema_version="1.1.0",
    constitution_version="1.0.0",
    parent_version=None,
    swarm_id=...,
    cedar_source=open("candidate.cedar").read(),
    engine_config_yaml=open("candidate.engine.yaml").read(),
    issued_at=...,
)
result = await client.constitution.activate_shadow(candidate)
print(result.shadow_constitution_hash, result.shadow_activate_receipt)
```

### Step 3 — Let traffic flow and watch the receipts

With a shadow loaded, every envelope that goes through
`EnvelopeService.Send` produces two evaluation receipts now: the
existing `constitution.evaluate.{pass,deny}` from the active eval
(or none, if no active is loaded), plus a
`constitution.evaluate.shadow.{pass,deny}` from the shadow eval.

The two streams partition cleanly by action-kind, so `yutha-ops
grep` against either stream returns only that slot's decisions:

```bash
# What the shadow would have denied.
yutha-ops grep constitution.evaluate.shadow.deny --limit 50

# What the shadow would have permitted (the boring case — useful
# for confirming the shadow is actually evaluating, not just
# silently failing).
yutha-ops grep constitution.evaluate.shadow.pass --limit 50

# Active-side decisions, for comparison. When an active is loaded
# alongside the shadow, every envelope produces one of these too.
yutha-ops grep constitution.evaluate.deny --limit 50
yutha-ops grep constitution.evaluate.pass --limit 50
```

When both slots are loaded, the active receipt's evidence carries
a `shadow_constitution_hash` entry — that field is the join key
between active and shadow receipts that observed the same envelope.
Pair them up by `(subject_agent_id, input_attribute_digest,
shadow_constitution_hash)` and you have a complete divergence
record per envelope.

What to look for:

- **Shadow denies in cases the active permitted.** The candidate
  is stricter than the current active (or, if no active is
  loaded, the candidate would block this traffic). Decide whether
  that's what you intended.
- **Shadow permits in cases the active denied.** The candidate is
  more permissive than the current active in some way. Same
  question — intended or not.
- **`shadow_schema_incompatible` deny reasons.** The candidate
  was authored against a schema version that doesn't match the
  active's, and the shared entity snapshot can't satisfy the
  candidate's strict-mode validation. Two options: coordinate a
  schema migration before promoting, or clear the shadow and
  re-author against a compatible schema.
- **Zero shadow receipts at all.** Either you haven't loaded a
  shadow, or every shadow eval is hitting an internal error —
  check the control plane logs.

### Step 4 — Iterate or promote

Two paths from a divergence review:

- **Iterate.** Either clear the shadow:

  ```bash
  yutha-ops clear-shadow
  ```

  Or just call `activate-shadow` again with the revised candidate
  — the new shadow replaces the previous one without a separate
  clear receipt. `clear-shadow` is what you reach for when you
  want the slot empty for a while (e.g., to stop emitting shadow
  receipts entirely while you reconsider).

- **Promote.** When you're satisfied the candidate is what you
  want active:

  ```bash
  yutha-ops promote-shadow
  ```

  This atomically swaps shadow → active. The CLI prints the
  newly-active constitution's hash (same as the shadow's hash
  immediately beforehand — content-addressing is over the
  constitution's bytes, not over slot history) and the
  `constitution.shadow_promote` receipt id.

  The enforcement engine is bound onto the new active. If there
  was a previous active, per-agent reputation and quarantine
  state is preserved across the promote (state is agent-keyed,
  not constitution-keyed). Sliding-window counters reset — the
  new constitution's `enforcement_rules` may have different
  windowing, so prior counters are no longer meaningful.

  The shadow slot is left empty. You can load a new candidate for
  the next round whenever.

---

## The audit trail

Shadow mode is fully receipt-traceable. Every operator action and
every eval produces a receipt:

| `action_kind` | Producer |
|---|---|
| `constitution.shadow_activate` | When you load a candidate. Evidence: `shadow_constitution_hash`, `shadow_constitution_version`, `parent_active_constitution_hash` (the active at the moment of shadow load — for correlating shadow runs back to their baseline; absent if no active is loaded), `schema_version`. |
| `constitution.shadow_clear` | When you clear the slot. Idempotent — emitted even when the slot was already empty (the previously-shadowed evidence is omitted in that case). |
| `constitution.shadow_promote` | When you promote shadow → active. Evidence: `from_active_constitution_hash` (absent for the case where no active was loaded — i.e., shadow-first-then-promote), `to_active_constitution_hash`, `to_constitution_version`, `schema_version`. **Distinct from `constitution.activate`** — auditors reviewing the constitution chain can tell whether a constitution arrived via direct activation or via shadow-preview-then-promote (same audit-clarity argument as `agent.operator_revoke` vs `agent.revoke`). |
| `constitution.evaluate.shadow.pass` | Per envelope, when a shadow is loaded. Evidence: `shadow_constitution_hash`, `action_kind`, `matched_rule_ids`, `input_attribute_digest`, `subject_agent_id`, optional `total_score` when scoring rules contributed. **Note** the evidence uses `shadow_constitution_hash`, NOT `constitution_hash` — the active receipt's `constitution_hash` always refers to the active slot. |
| `constitution.evaluate.shadow.deny` | Same shape plus `deny_reason`. Recognized `deny_reason` values match the active eval's set, plus the special value `"shadow_schema_incompatible"` for the cross-schema validation failure path. |

The canonical registry of `action_kind` strings lives at
[`/spec/receipt/canonical-actions.md`](https://github.com/abhinavg6/yutha/blob/main/spec/receipt/canonical-actions.md);
the five shadow-related entries are documented in full there.

Cross-grepping the receipts via `yutha-ops grep` is the operator's
day-to-day access pattern; for programmatic access, every shadow
receipt is also queryable via `client.receipt.query` from the
Python SDK and via `ReceiptService.Query` directly.

---

## Limitations to know about

- **One shadow at a time today.** RFC 0018 §6 documents the
  extension path to multiple concurrent shadows, but the current
  release supports one+one. To compare two candidates against each
  other, you serialize: activate-shadow the first, observe,
  clear-shadow, activate-shadow the second.
- **Replay is the backward-looking diligence pair.** Shadow tells
  you what the candidate would decide on **future** traffic; the
  [replay engine](replay.md) tells you what the candidate would
  have decided on a **past** receipt window. The two are designed
  to be used together — shadow for live preview, replay for
  historical regression analysis.
- **Procedure changes can't be previewed.** Shadow mode skips
  procedure-state mutation on the shadow path. A candidate that
  changes procedure behaviour won't be previewable through shadow
  — it has to be activated to be exercised.
- **No SLA on shadow eval latency.** Shadow eval is best-effort.
  If the cedar evaluator returns an internal error on the shadow
  path, the active eval still succeeds and the shadow emits a deny
  receipt with `evaluator_internal_error` reason. No retries, no
  fallback.

---

## Cross-references

- [Authoring constitutions](authoring-constitutions.md) — the
  authoring workflow shadow mode builds on.
- [Monitoring & receipts](monitoring.md) — `yutha-ops grep` and
  the broader receipt-query patterns.
- [RFC 0018](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0018-shadow-mode-and-replay.md)
  — the substrate-level contract for shadow mode and the future
  replay engine.
- [canonical-actions.md](https://github.com/abhinavg6/yutha/blob/main/spec/receipt/canonical-actions.md)
  — full evidence-shape catalog for every shadow-related
  action-kind.

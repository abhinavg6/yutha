# Constitution diff (Phase 3d)

`yutha-ops diff` is the operator's CI-ready inspection tool for
constitution changes. Give it two `(cedar source, engine-config
YAML)` pairs and it tells you exactly what changed — at the rule
level, with both `Before:` and `After:` retained for renderer use.
Optionally, point it at a window of past traffic and it composes
the replay engine to also tell you how the candidate would have
*behaved* differently than the active constitution did over that
window.

It's the third leg of the Phase 3 / Pillar 1 diligence triad —
alongside [shadow mode](shadow-mode.md) (forward-looking preview
against incoming traffic) and [replay mode](replay.md) (backward-
looking preview against a past window). Diff is what you reach for
when you have *two* candidate constitutions in hand and want a
structured PR-friendly summary of how they differ + (optionally)
what their behavioural delta would have been on real traffic.

This page is the operator runbook. The substrate side lives in
[`crates/yutha-diff/`](https://github.com/abhinavg6/yutha/tree/main/crates/yutha-diff)
and [`crates/yutha-ops/`](https://github.com/abhinavg6/yutha/tree/main/crates/yutha-ops);
this page is the operator-facing translation.

---

## When to diff

Three workflows make diff load-bearing:

- **Constitution PR review.** A reviewer wants to see "did this PR
  change anything about *gating*, *scoring*, *procedures*, or
  *enforcement*?" in a structured form they can scan in 30 seconds.
  Use `--format markdown` and paste into the PR thread.
- **CI gate on constitution evolution.** A pipeline wants to fail
  PRs that modify the constitution without an attached audit
  ticket. Use `--format json` and walk the response to compute a
  policy-hygiene + magnitude score.
- **Pre-promotion behavioural check.** Before promoting a shadow or
  activating a replay candidate, run the diff with `--window-from`/
  `--window-to` over the past N days and review the receipt-count
  deltas + enforcement chain divergences. If the candidate would
  have produced N% more quarantines than production did, decide if
  that's the intent.

---

## What diff does and does not do

| Surface | Static path (`yutha-ops diff`) | Behavioural path (`+ --window-from/--window-to`) |
|---------|------------------------------|--------------------------------------------------|
| Cedar policy add/remove/modify | Surfaced by `@id` annotation | Same |
| Engine-config item add/remove/modify | Surfaced by `.name` key | Same |
| Schema version pin change | Surfaced as `Some((from, to))` | Same |
| Replay engine composition | n/a | Creates session, runs window, queries both stores, closes session |
| Production receipt store mutation | None — pure local | None — same isolation guarantee as replay mode |
| Receipt-count deltas | n/a | Side-by-side production vs candidate-session counts |
| Enforcement chain divergences | n/a | New `enforcement.*` receipts the candidate would have emitted |
| `--filter` whitelist | Ignored | Narrows the tally to listed `action_kind`s |
| Output format | `json`, `markdown`, `html` | Same |
| Auth | None (no server contact) | Operator-bearer for replay + agent-bearer for production query |

Three properties worth knowing:

- **Production store is never touched.** Behavioural diff uses the
  same RFC 0018 §4 isolation as the replay engine — the candidate's
  emissions land in the session-scoped store; production stays
  exactly as it was. The only writes to production are the audit
  `replay.session.{create,close}` receipts that bracket the diff.
- **Cedar policies match by `@id` annotation.** Operators SHOULD
  `@id("name")` every policy by Yutha convention. Un-annotated
  policies match by a structural fingerprint (effect + scope shape
  + body hash); the diff still works, but reorderings are best
  diff'd against annotated policies. Renderers surface a soft
  "consider annotating with `@id`" hint when un-annotated policies
  are present.
- **Empty sections show as `(no changes)` — never elided.** All
  five structural sections (cedar policies, named predicates,
  scoring rules, procedures, enforcement rules) render shape-stably.
  CI tooling can rely on the JSON having the same top-level keys
  on every run.

---

## Static-only diff (no server needed)

The most common operator workflow:

```bash
yutha-ops diff \
    --left-cedar  path/to/baseline.cedar \
    --left-engine-config  path/to/baseline.engine.yaml \
    --right-cedar path/to/candidate.cedar \
    --right-engine-config path/to/candidate.engine.yaml \
    --left-version  baseline \
    --right-version candidate \
    --format markdown
```

Flags:

- `--left-cedar` / `--left-engine-config` — the **baseline** side.
- `--right-cedar` / `--right-engine-config` — the **candidate**
  side. Added items are present in the right but not the left;
  removed items are present in the left but not the right.
- `--left-version` / `--right-version` — free-form labels surfaced
  in the rendered title. Defaults to literal `"left"` and `"right"`.
- `--format {json,markdown,md,html}` — pick the output format.
  Default `markdown`.
- `--output-file <path>` — write to a file instead of stdout. Useful
  for HTML output (open the file in a browser) or for piping JSON
  into a CI tooling chain that wants on-disk artifacts.

No `--seed` needed, no gRPC channel, no server. The command is
pure-local file → file → stdout.

### What the output looks like

The fixture pair under
[`crates/yutha-diff/tests/fixtures/`](https://github.com/abhinavg6/yutha/tree/main/crates/yutha-diff/tests/fixtures)
gives you a worked example: `baseline` (minimal permit-all) →
`tightened` (adds a `forbid-large-refunds` Cedar rule + a
`large_refund_detector` enforcement chain). The Markdown rendering
opens with a 6-line summary block, then expands per-section with
the new entries shown inline in `cedar` and `json` code fences. The
HTML rendering is the same shape with color-coded sections + a
`<details>` collapse on every long code block.

### Three output formats, when to use which

| Format | Use it for |
|--------|------------|
| `--format markdown` (default) | PR review threads, ad-hoc CLI inspection, READMEs |
| `--format json` | CI gates, OpenTelemetry attribute emission, audit pipelines |
| `--format html --output-file diff.html` | Stakeholder review pages, sharing with non-technical reviewers |

The JSON shape carries a `diff_schema_version: "yutha-diff/v1"`
marker on every output. CI consumers SHOULD check it before
parsing — future format evolution will bump the marker.

---

## Behavioural diff via the replay engine

Add `--window-from <unix_ns>` and `--window-to <unix_ns>` to switch
the same command into behavioural mode:

```bash
yutha-ops diff \
    --left-cedar  path/to/baseline.cedar \
    --left-engine-config  path/to/baseline.engine.yaml \
    --right-cedar path/to/candidate.cedar \
    --right-engine-config path/to/candidate.engine.yaml \
    --left-version baseline --right-version candidate \
    --window-from 1748736000000000000 \
    --window-to   1751328000000000000 \
    [--filter <action_kind>]... \
    --format markdown
```

Both window flags are required when either is set. The window is
`monotonic_ns` (matches every other Yutha API's time bound). For an
"every receipt since the server started" window, use
`--window-from 0 --window-to 9223372036854775807`.

`--filter <action_kind>` is repeatable and whitelists the
action-kinds counted in the receipt-count tally. Empty (the
default) tallies the canonical set: `envelope.send` +
`constitution.evaluate.{pass,deny}` + `enforcement.{detect,coach,
quarantine,evict,reverse}`. Narrowing the filter reduces server
load when the window is large.

### What the behavioural diff surfaces

Two tables under a `## Behavioural diff` heading:

- **Receipt count deltas.** One row per `(action_kind,
  subject_agent_id)` pair observed in either store, with side-by-
  side `production` and `candidate` columns and a signed `delta`.
  Positive delta = the candidate would emit MORE receipts than
  production did; negative = fewer.
- **Enforcement chain divergences.** A subset of the above
  restricted to `enforcement.*` action-kinds, additionally keyed by
  `enforcement_rule_id` + `stage`. Only entries where production
  and candidate disagree appear — agreements are noise on this
  panel.

The renderer also reports the session id at the top of the
behavioural section so an auditor can join back to the
`replay.session.create` / `replay.session.close` receipts in the
production store for the full audit chain.

### Behavioural-diff caveats

- **It IS a server call.** Behavioural mode spawns a real replay
  session on the control plane — same compute + Postgres
  characteristics as documented in
  [the replay operator doc](replay.md#same-control-plane-isolated-by-construction).
  For very large windows, consider narrowing with `--filter` or
  running against the operator's two-process deployment if you
  have one.
- **Receipt query pagination is NOT implemented.** Each per-
  `action_kind` query uses `limit: 10_000`. If your window contains
  more receipts of a single kind than that, the tally is
  incomplete. Workaround: narrow `--window-from`/`--window-to` or
  use `--filter` to reduce per-kind volume. Pagination is a Phase 3
  follow-on.
- **The candidate's Cedar policies are NOT re-evaluated against the
  production envelopes.** The replay engine consumes the production
  `constitution.evaluate.*` receipts as input and computes the
  candidate's *enforcement chain* delta — it doesn't re-render
  Cedar evaluations. That's a deliberate Phase 3c MVP scoping
  decision (the production entity-snapshot isn't preserved on
  receipts). Per-envelope Cedar divergence is the natural follow-
  on; until then, the receipt-count delta is the closest signal.

---

## Audit trail

Diff itself does not emit any receipts — it's a pure inspection
tool. The behavioural-diff path DOES emit two receipts as part of
the embedded replay session:

| `action_kind` | When | Notes |
|---------------|------|-------|
| `replay.session.create` | When the diff session is created. | Evidence carries `replay_session_id`, `candidate_constitution_hash`, `window_from_unix_ns`, `window_to_unix_ns`, `mode: "cold"`. Lands in **production** store. |
| `replay.session.close` | When the diff session closes (immediately after the diff renders). | Evidence carries `replay_session_id` + `receipts_replayed_total`. Lands in **production** store. |

These bracket every behavioural diff in the audit chain so an
auditor reviewing the production receipt log can see "an operator
ran a behavioural diff over window X against candidate Y at time T".

---

## CI integration recipes

### Mandatory PR comment on constitution changes (GitHub Actions)

```yaml
- name: Run constitution diff
  run: |
    yutha-ops diff \
      --left-cedar  spec/constitution/main.cedar \
      --left-engine-config  spec/constitution/main.engine.yaml \
      --right-cedar PR/${{ github.event.pull_request.head.ref }}/main.cedar \
      --right-engine-config PR/${{ github.event.pull_request.head.ref }}/main.engine.yaml \
      --left-version main --right-version pr-${{ github.event.pull_request.number }} \
      --format markdown > diff.md

- name: Post diff as PR comment
  uses: actions/github-script@v7
  with:
    script: |
      const fs = require('fs');
      const body = fs.readFileSync('diff.md', 'utf8');
      await github.rest.issues.createComment({
        owner: context.repo.owner, repo: context.repo.repo,
        issue_number: context.issue.number, body
      });
```

### Fail CI on un-annotated Cedar policies (Python)

```python
import json
import subprocess
import sys

result = subprocess.run([
    "yutha-ops", "diff",
    "--left-cedar", "spec/main.cedar",
    "--left-engine-config", "spec/main.engine.yaml",
    "--right-cedar", "candidate.cedar",
    "--right-engine-config", "candidate.engine.yaml",
    "--format", "json",
], capture_output=True, text=True, check=True)

diff = json.loads(result.stdout)
unannotated = [
    e for section in [
        diff["cedar_policies"]["added"],
        diff["cedar_policies"]["removed"],
    ]
    for e in section
    if not e["annotated"]
]
if unannotated:
    print(f"FAIL: {len(unannotated)} un-annotated Cedar policies in diff")
    for e in unannotated:
        print(f"  - {e['effect']} {e['name']}")
    sys.exit(1)
```

The Python SDK also exposes `yutha.diff_constitutions` /
`yutha.diff_constitutions_against_window` as typed dataclass
wrappers around the same subprocess. See
[the Python SDK guide](../developer/python-sdk.md) for the full surface.

### OpenTelemetry attribute emission (operator's choice)

The JSON output's `diff_schema_version` field plus the per-section
counts make a natural set of OTel span attributes for an "operator
ran a diff" trace event. Phase 3f's RFC 0019 will codify the
semantic conventions; until then, operator choice.

---

## Limits and caveats

- **Static diff is structural, not semantic.** Two Cedar policies
  with different sources but identical evaluation behaviour will
  show as `modified`. The diff says what *changed*, not whether the
  change *matters semantically*. Use shadow + replay for the
  semantic question.
- **Modified detection uses canonical-bytes equality on engine-
  config items.** Two items with the same `.name` but different
  YAML field order will show as `modified` if the underlying
  `serde_json::to_value` representation differs. In practice this
  doesn't fire because serde_json preserves struct field order
  consistently.
- **No diff between active + shadow slots.** Diff is between two
  authored constitutions, not between the active slot and the
  shadow slot of a running server. To preview a shadow against the
  active, use [shadow mode](shadow-mode.md) directly.
- **Schema-version pin change is not a Cedar+ migration tool.**
  When the diff reports `schema_version: 1.1.0 → 1.2.0`, that's a
  pin change; it does NOT validate that the candidate's policies
  parse under the new schema. Activate against a server with the
  new schema bound to confirm.
- **The session created during behavioural diff IS subject to the
  control plane's replay-session TTL.** A behavioural diff that
  takes longer than the TTL (default 24h) to complete will close
  out-of-band. Practical implication: none — diff sessions close
  in seconds, not hours.

---

## Cross-references

- [Shadow mode](shadow-mode.md) — forward-looking preview against
  incoming traffic; pair with diff when comparing two candidates.
- [Replay mode](replay.md) — backward-looking preview against a
  past window; the behavioural-diff substrate.
- [Authoring constitutions](authoring-constitutions.md) — the
  upstream authoring loop diff operates on.
- [Monitoring & receipts](monitoring.md) — the receipt-query
  patterns the behavioural-diff query layer composes.
- [RFC 0018 §4](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0018-shadow-mode-and-replay.md)
  — the substrate-level contract for the replay engine the
  behavioural-diff path composes.

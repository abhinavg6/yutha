# Authoring constitutions

A constitution is the rule set your swarm runs under. Authoring one is the operator's job — you decide what agents may do, what they must not do, what trade-offs you prefer, and what should happen when an agent crosses the line. This page is the practical reference for *how* you write one.

If you're new to the idea, the [Concepts page](../concepts/constitution.md) covers what a constitution *is* and why it's shaped the way it is; the [Operator quickstart](quickstart.md) walks one end-to-end author → compile → activate → enforce loop. This page sits in between — a hands-on reference for the rule kinds the authoring DSL exposes, what each compiles to, and how to iterate without painting yourself into a corner.

You'll come away knowing the six rule kinds the DSL exposes, how each lands as Cedar source or engine-config YAML, what `yutha-ops compile` and `yutha-ops activate` validate at each step, how to roll forward and back, and which workload schemas you need to load at server startup for your rules to typecheck.

---

## The authoring pipeline at a glance

A constitution travels through three layers between you and the
evaluator. Each layer is a separate artifact you can read, diff,
and version-control.

**Layer 1 — the plain-English YAML DSL** (`*.yutha`). What you
author. Captures intent in a small structured vocabulary — forbid
this action, prefer that ranking, run this multi-step approval —
without making you write Cedar syntax. Reviewable by people who
don't write code; structurally validated by `yutha-ops compile`.

**Layer 2 — Cedar+ artifacts** (`*.cedar` + `*.engine.yaml`). What
the server consumes. The Cedar file is canonical policy source
the unmodified `cedar-policy` crate parses; the engine-config
YAML carries the Layer-B constructs Cedar doesn't model
(scoring, procedures, enforcement chains). Reviewers who need to
audit byte-for-byte what the evaluator runs read these.

**Layer 3 — the activated constitution.** What the running swarm
evaluates against. A content-addressed proto carrying both
artifacts plus version, swarm id, and issuance timestamp. Lives
in the receipt log forever once activated; the active one is
whichever `ConstitutionService.Activate` call most recently
landed.

The compiler is a pure, deterministic function — no LLM in the
loop. An LLM may sit *upstream* of the DSL (suggesting rule
blocks from prose); the compiler downstream stays repeatable
regardless. This matters for the threat model: a deceptive
authoring assistant cannot produce a constitution that defeats
the Cedar analyzer's checks, because the analyzer runs on every
compiled artifact regardless of who or what produced the YAML.

---

## Rule kinds you can write in the DSL

The DSL exposes six rule kinds. The first two are Cedar gating
rules; the rest map to engine-config constructs.

### `forbid_action`

The workhorse. Emits a Cedar `forbid` rule on a specific action
UID with an operator-supplied `when` clause. Any envelope or
operation matching the action UID is evaluated against the
clause; if it evaluates true, the request denies with
`forbid_rule_matched` and the rule's `@id` appears in the receipt
evidence.

```yaml
- kind: forbid_action
  id: no-merge-without-review
  action: Yutha::CodeReview::Action::ApproveMerge
  when: 'context.approval_method == "self-merge" && resource.author == principal.agent_id'
  description: "Self-merges are forbidden; require a second reviewer"
```

The `when` body is a raw Cedar expression — `principal`, `action`,
`resource`, `context` are bound exactly as Cedar expects them.
The compiler doesn't validate the expression; Cedar's analyzer
does at activation time, against the schema plus any workload
extensions you loaded.

### `permit_action`

The companion to `forbid_action`. Useful with
`closed_by_default: true` to narrowly admit specific shapes
while letting everything else default-deny. With the default
(`closed_by_default: false`), explicit permits are rarely needed
— the compiler appends a trailing `permit (principal, action,
resource)` so every action not explicitly forbidden permits.

```yaml
- kind: permit_action
  id: small-prs-auto-approve
  action: Yutha::CodeReview::Action::ApproveMerge
  when: 'resource.files_changed <= 3 && resource.lines_added <= 50'
```

### `scoring_rule` — soft preferences

Stock Cedar emits boolean decisions; many real policies are about
*ranking* — prefer the senior reviewer for sensitive PRs, prefer
high-reputation agents for high-stakes routing. Scoring rules
contribute decimal weights to a permitted decision; downstream
consumers (dispatchers, schedulers) use the total as a
tie-breaker. Scores never override a `forbid` — the dispatcher
can't rank a forbidden action above a permitted one — and every
contribution lands in the `constitution.evaluate.pass` receipt
evidence so the ranking is auditable.

The DSL surface for scoring is one of the spots where you'll
hand-author the `engine.yaml` directly today — the
plain-English compiler doesn't yet emit `scoring_rules` blocks.
Once compiled, you'd append something like:

```yaml
scoring_rules:
  - name: prefer_senior_reviewer
    score: 2.0
    head: { action: ApproveMerge }
    when: 'principal.reputation > 0.8 && resource.files_changed > 20'
```

Score must be non-zero, may be negative ("prefer not"), and
follows Cedar's `Decimal` precision (4 fractional digits).

### `procedure` — multi-step state machines

Some norms are inherently multi-step: a merge requires sign-off
from two reviewers; a refund over a threshold needs supervisor
countersign or auto-rejects after an hour. Procedures encode
these as bounded state machines — declarative `states`,
`transitions`, `on_timeout` clauses. Each instance is
content-addressed; each transition emits its own
`procedure.transition` receipt, so the full approval chain
reconstructs end-to-end from the audit log alone.

Procedures, like scoring, sit in the engine config. Sketch:

```yaml
procedures:
  - name: large_pr_two_reviewer_rule
    initial_state: awaiting_first_approval
    states: [awaiting_first_approval, awaiting_second_approval, merged, timed_out]
    terminal_states: [merged, timed_out]
    trigger:
      action: ApproveMerge
      when: 'resource.files_changed > 20'
    transitions:
      - from: awaiting_first_approval
        to:   awaiting_second_approval
        action: ApproveMerge
      - from: awaiting_second_approval
        to:   merged
        action: ApproveMerge
      - from: awaiting_first_approval
        to:   timed_out
        on_timeout: 24h
```

Procedure instances are reconstructable from the receipt log
alone — the engine maintains a perf index, but tearing it down
and rebuilding produces identical state. Author them when the
rule genuinely needs durable state across requests; if a single
predicate would do, `forbid_action` is simpler.

### `enforcement_chain` — the four-stage loop trigger

`forbid_action` responds to single denied attempts. An
`enforcement_chain` responds to a *pattern* of denies — three
forbidden sends in a minute, ten rate-limit denies in a minute,
two security-sensitive auto-fix attempts in sixty seconds. When
the pattern fires, the engine walks the agent through the
spec'd four stages: **detect** (signal-only; operator window to
intervene), **coach** (`ADVISE` envelope explaining the rule),
**quarantine** (cap layer denies the agent's actions, existing
caps stay live so reversal doesn't force re-issuance), **evict**
(terminal; calls `AdmissionService.OperatorRevoke` with
cascade).

```yaml
- kind: enforcement_chain
  id: repeat-self-merge-chain
  detects_on_forbid_rule: no-merge-without-review
  threshold: 2
  window: 60s
  full_chain: true
  description: "Two self-merge attempts in a minute → quarantine"
```

`full_chain: true` runs all four stages with the demo-tight 1s
cooldowns the compiler hardcodes today; for production rules,
hand-edit the resulting `engine.yaml` to set per-stage
`escalate_after` durations measured in minutes or hours so
operators have time to intervene. `full_chain: false` fires
only the detect — useful when you want the audit signal without
the automatic escalation.

The chain references its trigger rule by id, so the
`detects_on_forbid_rule` value must match a `forbid_action.id`
declared earlier in the same document. The compiler enforces
this structurally.

### `memory_norm` — guards on swarm memory

Memory operations (`ReadMemory`, `WriteMemory`, `ShareMemory`)
are first-class Cedar+ actions; the canonical schema declares
the `Memory` entity with `owner`, `scope`, and `tags`
attributes. Memory norms are stock Cedar over that vocabulary —
no DSL sugar yet, but the pattern is straightforward. The
shipped example at
`/spec/constitution/canonical-schemas/v1.1.0/examples/memory-privacy-gate.cedar`
is a representative starting point:

```cedar
@id("private-memory-read-gate")
forbid (
    principal,
    action == Yutha::Action::"ReadMemory",
    resource
) when {
    resource.scope == "private" && principal != resource.owner
};
permit (principal, action, resource);
```

Compose with `tags.contains("pii")`, `scope == "external"`, or
custom operator-defined attributes for richer privacy and
sharing rules.

### `resource_budget` — wall-clock and quota bounds

Budgets are also a schema pattern — no engine-side state.
`Agent` carries `budget_remaining_usd_cents`,
`budget_remaining_tool_calls`, and `budget_remaining_compute_ms`;
actions that consume budget carry matching `estimated_cost_*`
context fields. The canonical idiom is a stock
`forbid_action`:

```yaml
- kind: forbid_action
  id: budget-cap
  action: SendEnvelope
  when: 'principal.budget_remaining_usd_cents < context.estimated_cost_usd_cents'
  description: "Cap sends on remaining USD budget"
```

The control plane synthesizes current budget into the action
context per request — agents don't maintain budget state; the
constitution simply gates on it. Misalignment (the SDK forgot
to populate `estimated_cost_*`) surfaces as
`evaluator_internal_error` in the deny receipt.

!!! note "Budget tracking is still placeholder substrate today"

    Real passport-derived attributes (`framework`,
    `passport_tier`, `passport_hash`) and engine-tracked
    `reputation` are now populated on every evaluation. **Budget
    remaining is still placeholder** — the enforcement engine
    doesn't yet track per-agent budget consumption, so
    `principal.budget_remaining_*` evaluates to `i64::MAX` for
    every request. Forbid rules keying on it silently permit-all
    until budget-norms (RFC 0011 §4) ship in the engine. Author
    your budget rules now — they'll start firing the moment that
    phase lands — but don't expect them to enforce anything
    today.

### Cedar gotchas worth knowing up front

A few rough edges that catch first-time constitution authors:

- **`decimal` doesn't dispatch to infix operators.** A rule like
  `principal.reputation < decimal("0.5")` fails Cedar's validator
  with `expected Long but saw decimal`. Use the extension method
  instead: `principal.reputation.lessThan(decimal("0.5"))`. The
  same applies to `.greaterThan()`, `.lessThanOrEqual()`,
  `.greaterThanOrEqual()`.
- **`Set` membership is `.contains()`, not `in`.** The `in` operator
  is reserved for entity-hierarchy traversal (`principal in
  Yutha::Swarm::"<id>"`). For `Set<String>` membership use
  `context.tags.contains("approved")`.

---

## A worked example — code-review approvals

Putting four of the rule kinds together. Save as
`code-review.yutha`:

```yaml
description: "Code-review approval norms"
constitution_version: "1.0.0"
schema_version: "1.1.0"
closed_by_default: false

rules:
  # Forbid self-merges outright.
  - kind: forbid_action
    id: no-self-merge
    action: Yutha::CodeReview::Action::ApproveMerge
    when: 'context.approval_method == "self-merge" && resource.author == principal.agent_id'
    description: "Self-merges require a second reviewer"

  # Repeat self-merge attempts trip the enforcement chain.
  - kind: enforcement_chain
    id: repeat-self-merge-chain
    detects_on_forbid_rule: no-self-merge
    threshold: 2
    window: 60s
    full_chain: true
    description: "Two self-merge attempts in a minute → quarantine"
```

Two rule kinds, two intents: a hard gate on self-merge, plus a
pattern detector that escalates repeat offenders through the
four-stage loop. Once compiled, you'd likely hand-append a
`scoring_rules` block preferring senior reviewers on large PRs,
and maybe a `procedures` block requiring two-reviewer sign-off
on PRs touching more than twenty files. The Cedar half stays
small; the engine config grows as the norms get richer.

Note the absence of permit rules. With `closed_by_default:
false` the compiler appends `permit (principal, action,
resource)` to the bottom of the Cedar source — every `ApproveMerge`
that isn't a self-merge passes through, every other action
passes through, and only the explicit forbid bites.

---

## Compile

```bash
yutha-ops compile code-review.yutha
```

Two artifacts land alongside the input:

```
compiled:
  cedar:         code-review.cedar
  engine config: code-review.engine.yaml
```

**`code-review.cedar`** carries one `@id("no-self-merge")` Cedar
`forbid` rule plus the trailing permit-all. The header
comment records the authored description, version, and schema
version for diff context — informational only, the
`--version` flag on `activate` is what actually pins the
constitution version.

**`code-review.engine.yaml`** carries the
`schema_version` and one `enforcement_rules` entry mirroring
the chain — `trigger.receipt_kind:
constitution.evaluate.deny`, `forbid_rule_id: no-self-merge`,
`count_threshold: 2`, the four stage blocks with 1s
cooldowns.

The compile path is pure-local; it never touches the server, and
the `--seed` env var is irrelevant for it. Re-run after every
edit — there's no caching layer to fight, and any drift between
the YAML and the compiled artifacts is a footgun (you'd activate
a stale Cedar file with new YAML intent).

---

## Review before activate

Three things to eyeball in the compiled artifacts before pushing
them at a live server.

**The Cedar forbid carries the `when` clause you intended.**
Compile silently substitutes your `when:` string into the
generated `forbid` body; a missing quote or stray paren lands as
a Cedar parse error at activation, but a semantically-wrong but
syntactically-valid clause activates and quietly mis-gates. Read
the generated `.cedar` and confirm the rule does what you meant.

**The enforcement rule references the right forbid id.** The
compiler enforces this structurally — an unknown
`detects_on_forbid_rule` fails compile with a clear error
listing the known ids — but it's still worth a sanity glance at
the generated `forbid_rule_id` field in the engine YAML.

**Per-stage cooldowns are appropriate.** The compiler hardcodes
1-second cooldowns for `full_chain: true` because the test
demos want fast feedback. Production rules want minutes-to-hours
between stages so operators can intervene. Edit the
`coach.cooldown` and `*.escalate_after` values in the
`.engine.yaml` directly before activating.

Compile validates the DSL structurally — duplicate rule ids,
references to undeclared forbids, malformed rule kinds. Cedar's
analyzer runs at activation time, after the gRPC call lands.
Even a structurally-valid DSL can fail activation if its Cedar
half doesn't typecheck against the schema plus the workload
extensions the server loaded. The typical activation failure is
"unknown action `Yutha::SupportQueue::Action::IssueRefund`" —
fix by adding `--workload support-queue` to the server's
startup args, then retry.

---

## Activate

```bash
yutha-ops activate code-review.cedar \
    --engine-config code-review.engine.yaml \
    --version 1.0.0 \
    --schema-version 1.1.0
```

This call is operator-bearer authenticated — `yutha-ops` mints a
fresh `OperatorBearerToken` signed with the operator key derived
from `YUTHA_BOOTSTRAP_SEED`, attaches it as `authorization:
bearer operator <hex>`. The server verifies against the public
key you passed at startup with `--operator-public-key`.

Success looks like:

```
activated:
  constitution_hash: 7e3a...   (32-byte content-address of the full Constitution proto)
  activate_receipt:  9f12...   (32-byte content-address of the constitution.activate receipt)
```

Activation is atomic. The new constitution is in effect for the
next request — no read-your-writes window, no half-applied
state, and crucially no "active alongside" mode under v1. The
previous constitution stops being evaluated against the moment
the new one lands; its `constitution.activate` receipt stays in
the audit log forever, but no live evaluation references it.

If the activation fails — Cedar typecheck failure, unknown
workload action, malformed engine config — the call returns
`INVALID_ARGUMENT` with the validator's specific complaint and
nothing changes server-side. The currently-active constitution
keeps evaluating; you fix the YAML, recompile, and retry.

---

## Iteration loop

Constitutions amend. The CLI ships a v1 path: edit YAML,
recompile, activate with a bumped semver.

```bash
# Tighten the chain threshold from 2 to 3 self-merge attempts.
$EDITOR code-review.yutha
yutha-ops compile code-review.yutha
yutha-ops activate code-review.cedar \
    --engine-config code-review.engine.yaml \
    --version 1.0.1
```

`--version` is a free-form semver — the server doesn't enforce
monotonic ordering or parent-version linkage (those land with
the full amendment plumbing in Phase 4). What you bump it for is
the audit log: every `constitution.evaluate.{pass,deny}` receipt
carries the active constitution's hash and version, so denies
attributed to version `1.0.1` are unambiguously distinguishable
from denies under `1.0.0`. Bump on every amendment, no matter
how small.

Watch the result by greping the receipt log for the action
kinds your new rule should produce — `constitution.evaluate.deny`
with the new `forbid_rule_id`, or `enforcement.detect` when a
new chain trips. The Operator Quickstart covers the grep flow in
depth.

---

## Rollback

There's no `yutha-ops revert` command. To roll back, re-activate
the older Cedar plus engine config. The constitution hash gives
you content-addressed proof of which version is live, and the
audit log carries every prior activation receipt, so the rollback
is itself a normal `constitution.activate` event with its own
content-address.

```bash
# Reactivate the prior version.
yutha-ops activate code-review.cedar.v1.0.0 \
    --engine-config code-review.engine.yaml.v1.0.0 \
    --version 1.0.2
```

Two things follow from this. First, **save your compiled
artifacts** — the only way to re-activate a prior version is to
have its `.cedar` and `.engine.yaml` on hand. Treat them like
schema migrations and commit them alongside the source `.yutha`
in version control. Second, the rollback version still bumps
forward — you're not "going back to 1.0.0," you're activating
1.0.2 which happens to carry the same rule text as 1.0.0. The
receipt log shows the activation, not a revert.

---

## Testing before activation

What's available today: structural compile-time validation
(duplicate ids, malformed shapes, unknown forbid references),
Cedar's full analyzer at activation (typecheck, schema
conformance, depth bounds), and the runtime sandbox bounds
(`evaluation_time_exceeded`, `entity_store_size_exceeded`,
etc., per `/spec/constitution/evaluation.md` §5).

What's not yet shipped: a dedicated `yutha-ops compile --check`
or `yutha-ops constitution test` subcommand that runs the
loader's Cedar validation locally without activating. The
loader code lives in
[`crates/yutha-cedar-plus/src/loader.rs`](https://github.com/abhinavg6/yutha/tree/main/crates/yutha-cedar-plus/src/loader.rs)
and could be wrapped as a CLI subcommand cheaply, but until
that lands the honest workflow is: **activate against a dev
control plane first**. Run a second `yutha-control-plane` on
`127.0.0.1:50052` with the same workload extensions as
production, activate your new constitution there, drive a few
representative requests through it, watch the receipts, then
promote the same artifacts to production with a fresh
`activate` call.

A dev control plane with `--receipt-backend memory` boots in
under a second and discards state on shutdown, so the iteration
loop is fast.

---

## Workload extensions

Rules that reference workload-specific actions or entities —
`Yutha::SupportQueue::Action::IssueRefund`, the
`PullRequest.files_changed` attribute — require the matching
workload extension to be loaded at server startup. Pass
`--workload <name>` (repeatable, or use
`YUTHA_WORKLOADS=name1,name2`) on the `yutha-control-plane`
invocation.

```bash
yutha-control-plane \
    --workload code-review \
    --workload support-queue \
    --operator-public-key "$YUTHA_OPERATOR_PUBLIC_KEY" \
    # ... other flags
```

If a constitution references
`Yutha::CodeReview::Action::ApproveMerge` and the server wasn't
started with `--workload code-review`, activation fails at parse
time with `Cedar validation failed: unknown action`. The shipped
workload catalog lives at
[`/spec/constitution/canonical-schemas/v1.1.0/`](https://github.com/abhinavg6/yutha/tree/main/spec/constitution/canonical-schemas/v1.1.0)
— the README there walks the extension model and lists what's
currently shipped (`support-queue`, `code-review`, with more to
follow under the same pattern).

Authoring a new workload extension is a Cedar `entity` + `action`
schema fragment plus a registration entry in
`yutha-cedar-plus`'s `loader.rs`. Operators who need a
domain-specific vocabulary (AP/invoice, incident-response,
research) can either contribute the schema upstream or carry it
locally as a private extension.

---

## Pointers

- [`/spec/constitution/`](https://github.com/abhinavg6/yutha/tree/main/spec/constitution)
  — the schema, rationale, extensions, evaluation model, and
  enforcement contract as specs. The README orients the
  directory; `schema.cedarschema` is the canonical v1.1.0
  schema every constitution conforms to.
- RFCs [0010](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0010-constitution-language-v1.md),
  [0011](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0011-cedar-plus-extensions.md),
  [0012](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0012-evaluation-model-and-sandbox.md),
  and [0013](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0013-four-stage-enforcement-loop.md)
  — the design decisions behind the language, the Cedar+
  extensions, the evaluation model, and the four-stage
  enforcement loop. Read 0013 before tuning chain cooldowns in
  production.
- [Concepts → Constitution & enforcement](../concepts/constitution.md)
  — what the constitution is and why; the conceptual companion
  to this page.
- [Operator Quickstart](quickstart.md) — the 20-minute
  walkthrough that exercises author → compile → activate →
  enforce end-to-end with the support-queue refund-cap example.
- [Monitoring & receipts](monitoring.md) — how to observe the
  receipts your constitution produces once it's running.

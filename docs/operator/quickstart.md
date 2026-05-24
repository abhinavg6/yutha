# Operating a Yutha swarm under a constitution

A 20-minute walkthrough for operators — the human running the control
plane and authoring the rules every agent has to live within. By the
end you'll have:

- A control plane running with a workload-schema extension loaded
  and operator credentials wired up.
- A plain-English YAML document compiled into Cedar policies plus an
  engine-config file, then activated against the swarm.
- A live constitution evaluating every `EnvelopeService.Send` and
  emitting `constitution.evaluate.{pass,deny}` receipts.
- A four-stage enforcement chain (detect → coach → quarantine →
  reverse) firing end-to-end, visible in the audit log.
- A revoked agent, gone from the swarm, with the eviction recorded.

**What you get for free.** Cedar+ is the constitution language; the
`yutha-cedar-plus` crate evaluates every send server-side. The
enforcement engine watches the receipt stream and fires the chain
automatically when an `enforcement_rules` pattern hits. The cap
layer consults the quarantine state on every issue and every check.
You don't write any of that — wire up a constitution and the
substrate does the rest.

**What you write.** Three things: an intent-level YAML document
(`*.yutha`), the choice of which workload schemas to load at server
startup, and the seed that derives both the operator credential and
the bootstrap agent. Everything else — Cedar compilation, engine
config emission, bearer-token minting, receipt emission — happens
below the CLI surface.

If you haven't built an agent on top of Yutha before, read the
[LangGraph guide](../developer/langgraph.md) first. That one's
developer-facing; this one's operator-facing, and the two compose.

---

## Prerequisites

You need four things on hand before any of the commands work.

**1. The `yutha-ops` and `yutha-control-plane` binaries.** From the
repo root, one cargo invocation builds both:

```bash
cargo build --release -p yutha-control-plane -p yutha-ops
```

Bin paths land at `target/release/yutha` (the control-plane binary)
and `target/release/yutha-ops`. The examples below assume both are on
your `PATH` or invoked through `cargo run -p ...`.

**2. The Python SDK installed in a virtualenv.** We use it for one
shell helper (deriving the operator public key from the seed) and
for the section that drives synthetic traffic:

```bash
pip install yutha
```

Working from a repo clone (tracking `main` rather than the released
PyPI version)? Use an editable install instead:
`cd sdks/python && uv pip install -e '.[dev]'`.

**3. A 32-byte bootstrap seed.** Yutha derives three things from
this single hex value:

- the bootstrap **agent**'s signing key (raw seed bytes),
- the **swarm id** (`sha256(seed || 0x02)`),
- the **operator** signing key (`sha256(seed || 0x03)`).

So the same seed the operator hands to the server is also what
`yutha-ops` uses to mint operator-bearer tokens. Mint one:

```bash
export YUTHA_BOOTSTRAP_SEED=$(python -c \
    'import secrets; print(secrets.token_hex(32))')
```

**4. The operator public key, derived from the seed.** The server
needs the *public* counterpart so it can verify operator-bearer
tokens. `yutha-ops print-operator-pubkey` does the derivation
locally (no server connection needed — it's the seed-only
`sha256(seed || 0x03)` derivation that the CLI also uses to mint
operator-bearer tokens):

```bash
export YUTHA_OPERATOR_PUBLIC_KEY=$(yutha-ops print-operator-pubkey)
```

You'll see a 64-character hex string in `$YUTHA_OPERATOR_PUBLIC_KEY`.
Keep this terminal — every following command needs both env vars.

---

## Step 1 — Start the control plane

A production-shaped startup line. Five flags carry the load. For
the full production deployment surface — TLS, mTLS, the Postgres
backend, scaling posture, what's not yet supported — read
[Deployment](deployment.md) before standing one up for real.

```bash
cargo run --release -p yutha-control-plane -- \
    --admission-mode closed \
    --workload support-queue \
    --operator-public-key "$YUTHA_OPERATOR_PUBLIC_KEY" \
    --receipt-backend memory \
    --grpc-addr 127.0.0.1:50051
```

A few notes on each:

- **`--admission-mode closed`.** Production posture. Only the
  bootstrap agent is allowlisted; everything else has to be
  registered through `AdmissionService.Register` with the operator's
  blessing. Flip to `open` for local demos where you want agents to
  self-register (the LangGraph walkthrough uses that).
- **`--workload support-queue`.** Loads the support-queue
  workload-schema extension under the `Yutha::SupportQueue`
  namespace. Repeat the flag (or use
  `YUTHA_WORKLOADS=support-queue,code-review`) to load more than
  one. If the constitution you're about to activate references an
  action or entity in a workload namespace and you forget this
  flag, the activate call returns `INVALID_ARGUMENT: Cedar
  validation failed: unknown action`. Available workloads live
  under `/spec/constitution/canonical-schemas/v1.1.0/`.
- **`--operator-public-key`.** Without this, the server treats
  every operator-bearer call as `FAILED_PRECONDITION: operator
  credentials not enabled` — so `yutha-ops activate` and `yutha-ops
  revoke` would both fail. Setting it is the one-time
  bootstrap that turns the swarm from un-governed to operator-
  managed.
- **`--receipt-backend memory`.** Non-persistent storage; fine
  for a walkthrough. Production posture is `--receipt-backend
  postgres --postgres-url postgresql://...`. The schema migrates
  automatically on startup.
- **`--grpc-addr 127.0.0.1:50051`.** Default. Listed for
  completeness; bind to `0.0.0.0` only behind TLS termination.

You'll see a few startup lines: receipt backend chosen, workload
extensions loaded, operator credentials enabled, gRPC listening.
Leave this terminal running.

> **Why not pass `--bootstrap-seed` here?** You can — and you'd
> want to for integration tests where an external client needs to
> authenticate as the bootstrap agent. For a real operator
> deployment, omit it: the server generates a random bootstrap
> identity in-process and never exposes the private material.
> `yutha-ops` doesn't need the bootstrap-agent key, just the
> operator key — and that's derived from the seed independently.

---

## Step 2 — Author intent in plain-English YAML

The constitution language is Cedar+. The Cedar half is exact policy
syntax — useful for reviewers but tedious for authors. The intent
language is a YAML DSL that compiles down to Cedar plus an engine-
config file. You author the YAML; the compiler does the syntactic
heavy lift.

The example below is intentionally compact — one forbid rule and one
enforcement chain. For the full rule-kind catalog (scoring rules,
procedures, memory norms, resource budgets), the compile-vs-Cedar
validation boundary, and the iteration / rollback patterns, see
[Authoring constitutions](authoring-constitutions.md).

A running example: a customer-support refund cap. The rule is
"refunds over $100 require supervisor approval, and three
forbidden-payload sends in a minute trip the enforcement chain."

Save this as `refund-cap.yutha` (or copy the canonical version from
`/spec/constitution/canonical-schemas/v1.1.0/examples/support-queue-refund-cap.yutha`):

```yaml
description: "Customer-support refund cap — supervisors only for >$100"
constitution_version: "1.0.0"
schema_version: "1.1.0"
closed_by_default: false

rules:
  # Cap large refunds to verifiable-tier (supervisor) agents.
  - kind: forbid_action
    id: refund-cap-requires-supervisor
    action: Yutha::SupportQueue::Action::IssueRefund
    when: 'context.refund_amount_cents > 10000 && principal.passport_tier != "verifiable"'
    description: "Refunds over $100 require supervisor approval"

  # Block payloads tagged as known-forbidden — a forbid rule with
  # a downstream enforcement chain attached.
  - kind: forbid_action
    id: no-forbidden-payloads
    action: SendEnvelope
    when: 'context.payload_schema_id == "type.yutha.dev/v1/Forbidden"'
    description: "Block payloads tagged as known-forbidden"

  - kind: enforcement_chain
    id: forbidden-payload-chain
    detects_on_forbid_rule: no-forbidden-payloads
    threshold: 3
    window: 60s
    full_chain: true
    description: "Three forbidden sends in a minute → escalate"
```

Three things to internalize about that document:

- **`forbid_action`** maps directly to a Cedar `forbid` rule on a
  specific `action` UID. The `when` clause is a Cedar expression —
  you reference `principal`, `action`, `resource`, and `context`
  attributes exactly the way Cedar expects.
- **`Yutha::SupportQueue::Action::IssueRefund`** is namespaced
  under the workload extension you loaded at startup. If the
  server isn't run with `--workload support-queue`, this rule
  fails to validate at `activate` time, before it can ever fire.
- **`enforcement_chain`** is a Layer B construct — it doesn't
  exist in stock Cedar. It tells the enforcement engine: when N
  receipts matching the trigger pattern land in `window`, run the
  detect → coach → quarantine → evict (or auto-reverse) chain
  defined in RFC 0013. `full_chain: true` runs all four stages
  with default cadence; per-stage `escalate_after` lets you slow
  the chain down for less-severe rules.

Pick `closed_by_default: false` for the running thread (everything
not explicitly forbidden permits) or `true` for production-grade
posture (everything not explicitly permitted forbids). The latter
is harder to author against — you'll typically want it once you
have a complete catalog of intended actions.

---

## Step 3 — Compile

Turn intent into the two files the server actually consumes:

```bash
yutha-ops compile refund-cap.yutha
```

You'll see:

```
compiled:
  cedar:         refund-cap.cedar
  engine config: refund-cap.engine.yaml
```

The compile path is pure-local — it never touches the server, and
the `--seed` env var is irrelevant here. Inspect the two artifacts:

- **`refund-cap.cedar`** — Cedar policy source. The two `forbid_action`
  rules became Cedar `forbid` statements with the same `@id`
  annotations. A trailing `permit (principal, action, resource);`
  is appended because `closed_by_default: false`. This file is what
  the loader hands stock `cedar-policy` 3.4 to parse, validate
  against the canonical schema (+ workload extensions), and
  evaluate.
- **`refund-cap.engine.yaml`** — engine-config YAML carrying the
  Layer B constructs Cedar doesn't model: scoring rules, named
  predicates, procedures, and the `enforcement_rules` list. For
  the refund-cap example the engine config has one
  enforcement rule covering the forbidden-payload chain.

Both files are human-readable; you should be able to diff them
against the YAML and recognize every line. Re-run the compile any
time you edit the YAML — there's no caching layer to fight.

---

## Step 4 — Activate

Publish the constitution to the running server:

```bash
yutha-ops activate \
    refund-cap.cedar \
    --engine-config refund-cap.engine.yaml \
    --version 1.0.0 \
    --schema-version 1.1.0
```

This call is operator-bearer authenticated. `yutha-ops` mints a
fresh `OperatorBearerToken`, signs it with the operator key derived
from `YUTHA_BOOTSTRAP_SEED`, and attaches it as
`authorization: bearer operator <hex>`. The server verifies against
the public key you passed with `--operator-public-key` at startup.

You'll see:

```
activated:
  constitution_hash: 7e3a...   (32-byte content-address of the full Constitution proto)
  activate_receipt:  9f12...   (32-byte content-address of the constitution.activate receipt)
```

Both are content-addresses against the canonical receipt-wire form,
so they're reproducible — re-activating the same constitution with
the same `issued_at` will land the same hash. The
`constitution.activate` receipt is in the audit log; from this
point on, every `EnvelopeService.Send` runs through Cedar+
evaluation against this constitution.

> **What does it mean for two constitutions to coexist?**
> They don't. Each `Activate` call atomically replaces the active
> constitution. The previous one is no longer evaluated against,
> but its `constitution.activate` receipt is permanent in the audit
> log — you have an unbroken history of every governance change
> the swarm ever made.

---

## Step 5 — Watch enforcement fire

Now drive enough traffic to trip the chain. The Python SDK is the
quickest path; this snippet registers two agents, has them send
three forbidden-payload envelopes in a row (matching the
`no-forbidden-payloads` rule), and waits for the enforcement
chain to land in the audit log.

The `yutha-ops grep` invocations below are the minimum operator
query surface. For the wider monitoring surface — audit-trail
reconstruction patterns, the canonical action-kind catalog,
alerting thresholds for the four enforcement stages, structured
logs and tracing — see [Monitoring & receipts](monitoring.md).

```python
# scripts/operator_walkthrough_traffic.py
import asyncio, hashlib, os, secrets
import yutha

async def main():
    seed = bytes.fromhex(os.environ["YUTHA_BOOTSTRAP_SEED"])
    swarm_id = yutha.SwarmId(value=hashlib.sha256(seed + b"\x02").digest()[:16])

    # Closed admission mode → we need operator-blessed registration.
    # The simplest path is: spin up two agents whose passports the
    # bootstrap operator countersigns. The SDK's BearerSession +
    # AdmissionAPI.register handle that for you — see the LangGraph
    # walkthrough for the full registration flow.
    #
    # Here we assume two agents already registered named "sender"
    # and "recipient", with their signing keys + agent ids loaded.
    sender_key, sender_id = load_agent("sender")
    recipient_key, recipient_id = load_agent("recipient")

    async with yutha.YuthaClient.connect(
        "127.0.0.1:50051",
        agent_id=sender_id,
        swarm_id=swarm_id,
        signing_key=sender_key,
    ) as client:
        for i in range(3):
            env = yutha.Envelope(
                spec_version="1.0.0",
                swarm_id=swarm_id,
                envelope_id=secrets.token_bytes(16),
                from_agent=sender_id,
                recipient=yutha.Recipient.for_agent(recipient_id),
                performative=yutha.Performative.INFORM,
                payload=b"this should be blocked",
                # The schema id that the forbid rule's `when` clause
                # matches against. Send three of these in a minute.
                payload_schema_id="type.yutha.dev/v1/Forbidden",
                nonce=secrets.token_bytes(16),
                epoch=i + 1,
                sent_at=yutha.Timestamp.now(),
            ).sign(sender_key)

            # The SDK translates the server-side
            # `PERMISSION_DENIED: constitution check denied: ...`
            # into a structured `ConstitutionDenied` carrying the
            # evaluator's `deny_reason` as an attribute. For this
            # rule the reason is `"forbid_rule_matched"` (a Cedar
            # forbid rule fired) — RFC 0010 §6 enumerates the full
            # set of possible deny_reason values.
            try:
                await client.envelope.send(env)
            except yutha.ConstitutionDenied as exc:
                print(f"send {i}: denied — {exc.deny_reason}")
            else:
                print(f"send {i}: permitted")

asyncio.run(main())
```

Each forbidden send lands a `constitution.evaluate.deny` receipt
with `forbid_rule_id = "no-forbidden-payloads"`. When the third
one lands within 60s, the engine's pattern-matcher fires
`enforcement.detect`, schedules `enforcement.coach` (which sends
an `ADVISE` envelope to the offending agent), and then schedules
`enforcement.quarantine`. The cap layer immediately flips: from
that point on, every `CapabilityService.Issue` and
`CapabilityService.Check` for the quarantined agent denies with
`SubjectQuarantined`.

From a fresh terminal (with `YUTHA_BOOTSTRAP_SEED` exported):

```bash
# All the denies the constitution emitted.
yutha-ops grep constitution.evaluate.deny --limit 20

# The detect that closed the pattern.
yutha-ops grep enforcement.detect

# The coach ADVISE that the engine sent in response.
yutha-ops grep enforcement.coach

# The quarantine that flipped the cap layer.
yutha-ops grep enforcement.quarantine
```

Each receipt is signed by the control plane and content-addressed.
The evidence fields under each kind tell you which rule fired,
which receipts the pattern matched, the reputation delta applied,
and the wall-clock the stage transitioned at. The
canonical-actions table in
[`/spec/receipt/canonical-actions.md`](https://github.com/abhinavg6/yutha/blob/main/spec/receipt/canonical-actions.md)
is the source of truth for what evidence each `action_kind`
carries.

---

## Step 6 — Reverse or revoke

Two ways out of a quarantine.

**Auto-reverse** is what fires when the chain's
`quarantine.expires_after` window elapses without an operator
intervention. The engine emits an `enforcement.reverse` receipt
referencing the quarantine; the cap layer flips back to permitted;
the agent is functional again. This is the default path for a
chain like the refund-cap example, where the `quarantine` stage
sets a short `escalate_after` and the next entry in
`next_stage_schedule` is a reverse.

**Manual revoke** is the operator-driven escape hatch. When you've
seen enough — a real attack, a runaway agent, a misconfigured
workload — you evict directly. For the full credential lifecycle
behind the `yutha-ops revoke` command (what the operator credential
authorizes, the active-stream tear-down semantics, the cascade
contract, what's deferred per RFC 0009), see
[Operator credentials](operator-credentials.md):

```bash
yutha-ops revoke 019e3ce9-8d7d-70ec-9209-e34415ca9477 \
    --reason "scope-creep on PII access" --cascade
```

`--cascade` tells the substrate to revoke every capability the
agent currently holds in addition to ending its admission (RFC
0009 §3.2). The eviction lands as an `agent.operator_revoke`
receipt, every cap revocation lands as a `capability.revoke`
receipt with the operator-revoke as the cause, and any active
subscribe streams the agent had open are torn down.

Eviction is irreversible. The audit-log entry is permanent;
re-registering the same agent id would need a fresh passport and
operator countersign, and the history is forever visible.

---

## Step 7 — Iterate

Constitutions amend. The current CLI ships a v1 path: edit the
YAML, recompile, and re-activate with a bumped version:

```bash
# Edit refund-cap.yutha — say, drop the refund cap from $100 to $50.
yutha-ops compile refund-cap.yutha
yutha-ops activate \
    refund-cap.cedar \
    --engine-config refund-cap.engine.yaml \
    --version 1.0.1
```

The new constitution takes effect immediately for every subsequent
`Send` — the evaluator swap is atomic, so concurrent evaluations
see either the old constitution or the new one, never a partial
mix. The previous `constitution.activate` receipt stays in the
audit log forever; the new one would reference it as
`parent_version` once full amendment plumbing lands (the CLI v1
path leaves `parent_version` empty — quorum, supervisor
countersign, and proper amendment receipts are a Phase 4 follow-on).

Re-running `yutha-ops grep constitution.activate` after a few
iterations shows you the full history.

---

## Where to go from here

You now have the full operator surface in muscle memory: author in
YAML, compile, activate, grep, revoke. The rest of the Operator
Guide goes deeper on each piece:

- **[Authoring constitutions](authoring-constitutions.md)** — the
  full rule-kind catalog (scoring rules, procedures, memory norms,
  resource budgets in addition to the forbid/permit/enforcement
  shapes shown here), compile-vs-Cedar validation boundary,
  iteration loop, rollback.
- **[Operator credentials](operator-credentials.md)** — what the
  credential authorizes, generating/storing/rotating, the revoke +
  cascade + active-stream tear-down semantics in depth, and the
  multi-operator/threshold/rate-limit follow-ons RFC 0009 defers.
- **[Monitoring & receipts](monitoring.md)** — `yutha-ops grep`
  patterns beyond the one-liner above, audit-trail reconstruction
  recipes, alerting thresholds for the four enforcement stages,
  structured logs and tracing, dashboard suggestions.
- **[Deployment](deployment.md)** — production-grade startup, TLS
  + mTLS, the Postgres backend and its backup story, scaling
  posture (single-tenant by design today), what is and is not yet
  supported.
- **[Sui anchoring](sui-anchoring.md)** — the optional
  verifiability layer, when a third party needs to verify the log
  without trusting you. Walks publishing the Move package,
  creating the per-swarm `SwarmAnchor`, and wiring the anchor
  driver into a running control plane.

A few specific follow-on tracks worth calling out:

- **Custom workloads.** The two shipped workload schemas
  (`support-queue`, `code-review`) live under
  `/spec/constitution/canonical-schemas/v1.1.0/`. Authoring a new
  one is a Cedar `entity` + `action` schema fragment plus a
  registration entry in `yutha-cedar-plus`'s `loader.rs`. The
  README under that directory walks the pattern.
- **The four-stage loop in depth.** [RFC 0013](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0013-four-stage-enforcement-loop.md)
  is the source of truth for stage cadence, reputation deltas,
  and the reversal contract. Read it before tuning
  `escalate_after` values in production.
- **Programmatic driving.** If you want to run the same workflow
  from CI (GitOps-style amendment workflow, automated
  revocations), the Python SDK's `ConstitutionAPI` exposes
  the same `ConstitutionService.Activate` and
  `AdmissionService.OperatorRevoke` RPCs `yutha-ops` wraps.

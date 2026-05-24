# Topology

Topology is a swarm-level setting — chosen once, at swarm creation — that
decides who can join the swarm, under what conditions, and with what default
authority. It is first-class because the answer shapes everything downstream:
the registry's admission flow, the capability layer's default lifetime
ceilings, the constitution's enforcement posture, even whether agents are
allowed to send envelopes to endpoints outside the swarm. The three options
Yutha ships are **closed** (allowlist of vetted agents only), **open** (anyone
meeting sybil-resistance criteria), and **hybrid** (a trusted closed core with
an open periphery around it). Why three and not a continuous knob? Because each
one carries a coherent bundle of defaults — admission flow, scope ceilings,
enforcement cadence, external-send policy — and operators reason about the
bundle, not the individual sliders. Mixing-and-matching at the slider level
invited combinations that didn't add up. The three modes are the points on the
spectrum that real deployments actually land on, made explicit.

A topology is set at swarm creation and is immutable for the swarm's lifetime.
Changing it requires creating a new swarm and migrating — a deliberate cost,
paid once, in exchange for the security property that no operator can silently
widen participation or loosen capability ceilings after agents have joined. The
full design rationale lives in
[`/spec/topology/rationale.md`](https://github.com/abhinavg6/yutha/blob/main/spec/topology/rationale.md)
and [RFC 0006](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0006-topology-v1.md);
this page is the plain-English version for someone choosing a mode for their
first deployment.

## Closed

In a closed swarm, every agent is on an allowlist the operator maintains. The
allowlist can enumerate specific AgentIds, or it can list owner-key
fingerprints — the latter lets an operator say "any agent registered under org
X's signing key" without naming each one in advance. Registration of any
AgentId that doesn't match is either rejected outright or, if the operator has
set `pending_review_on_unknown=true`, parked in a queue for manual approval via
an `agent.register.approve` receipt.

Operationally this is the simplest case. Sybil defense is structural — the
allowlist *is* the defense — so there's no proof-of-work, no attestation, no
IdP plumbing. Capability lifetimes default generously because the operator
has already vetted everyone holding a passport. Enforcement defaults toward
patient, supervisor-mediated escalation: a single denied envelope doesn't
trip a quarantine, because the prior on trust is high. External sends
default off (the operator can enable them).

Closed is the right starting posture for production. Regulated workflows
(financial, healthcare, anything with named-actor obligations) almost always
want closed; so do internal company swarms where every agent is owned by a
known team. Anywhere the reputational or compliance cost of a misbehaving
agent is concentrated on the operator, closed is the safe answer. The
trade-off is reach: it's a poor fit for anything resembling a community.
Closed also concentrates trust in the operator more than the other modes —
full latitude to mint passports, issue capabilities, and revoke agents —
with the receipt fabric as the primary check on that latitude.

One subtlety: closed swarms default `require_capability_for_send` to true
(open defaults to false to preserve the v1.0 demo posture; hybrid expects
the operator to set it). Every `EnvelopeService.Send` has to carry an
explicit `capability_id` resolving to a held capability whose scope permits
the send, and the server-side check is unbypassable from the client side.
[RFC 0007](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0007-send-path-cap-check.md)
has the rationale.

## Open

In an open swarm, registration is gated by sybil-resistance instead of a
vetted list. A fresh agent presents proof — one of, or any combination of,
five mechanisms — and the registry admits it if every requirement passes:

- **Proof-of-work** — a hash collision against an operator-tuned difficulty
  parameter. Cheap to verify, expensive to produce. Difficulty 22 is a few
  seconds of CPU; 26 is closer to a minute. A noise filter, not a serious
  adversary defense.
- **Hardware attestation** — a TEE-backed attestation report (Nautilus, SGX,
  SEV, TPM). Strong defense, but rules out agents that don't run on attested
  hardware.
- **IdP attestation** — proof of identity via OIDC, SPIFFE, or a DID. The
  right fit when admission is "any agent operated by a known organization in
  this list."
- **Stake** — a locked resource (financial, reputational, computational)
  recoverable on good behavior, slashable on misbehavior. Strongest defense;
  opt-in per deployment because of the policy weight it carries.
- **Invite** — a one-shot token signed by an existing member. The bootstrap
  pattern for invite-only public swarms.

Combinations are AND. A common production combo is IdP attestation plus a
small proof-of-work — known-org agents that also pay the registration cost.

Open swarms tighten defaults relative to closed in three places. Passport
lifetimes are shorter — a 90-day passport in a closed swarm is fine; in an
open swarm it lets attackers register, dwell, and strike late. Capability
scopes start narrower — `default_initial_scope` caps what a newly-admitted
agent can do; growth happens through reputation, supervisor approval, or
operator grant, never automatically. And enforcement defaults aggressive —
two or three denied envelopes trip a detect; coach cadence is short;
quarantine auto-expires. The volume of agents in an open swarm makes
per-incident supervisor countersign infeasible early on. Eviction still
requires the substrate floor of supervisor countersign per RFC 0009 §3.3.

The bootstrap-seed pattern every demo and quickstart uses binds a fresh
agent and control plane to the same `swarm_id` without an out-of-band
handshake — a single hex string deterministically derives the agent signing
key, the swarm id, and the operator key. It works for either closed or open
admission (see [Operator → Quickstart](../operator/quickstart.md)).

Open fits tutorials, public demos, crowd-sourced workflows, and community
swarms whose constitution is restrictive enough that lower-trust admission
doesn't matter much. Recommended starting points: a public hobbyist swarm
tends to land on PoW difficulty 22 plus invite-required, minimal passport
tier, 7-day lifetime. A research consortium lands on IdP attestation against
an accepted-issuers list, standard tier, 30-day lifetime. A verifiable-tier
swarm — anything anchoring receipts for downstream third parties — typically
requires hardware attestation and verifiable tier. The full set is in
[`/spec/topology/rationale.md`](https://github.com/abhinavg6/yutha/blob/main/spec/topology/rationale.md)
§8.

## Hybrid

Hybrid is a closed core plus an open periphery in one swarm. The core is an
allowlist of trusted operators or operator-owned agents; the periphery is open
registration under whatever sybil-resistance the operator configures. The two
halves coexist under one constitution and one receipt fabric.

What makes hybrid more than "open with privileged agents" is the structural
cap on periphery authority. The `periphery_capability_constraint` is a scope
ceiling every periphery agent's capabilities are intersected against —
independent of issuer, enforced at check time. The constraint can't be
silently waived by an operator who later decides to be generous; it's part of
the topology document, which is immutable. A `periphery_may_delegate` knob
(default false, periphery is leaf-only) decides whether periphery agents can
sub-delegate attenuated capabilities to other periphery agents.

The mental model: the trust gradient lives in the topology, not in ad-hoc
checks scattered across the constitution and agent code. Core has full
authority because the topology says so; periphery has bounded authority
because the topology says so; promotion requires explicit operator action or
a constitution-mediated reputation path. Operators don't write per-agent
privilege exceptions — the topology does the structural work, the
constitution does the behavioral work.

Hybrid fits many real deployments the closed-vs-open binary forces into
uncomfortable choices. A disaster-response coalition with a trusted core of
UN agencies and named NGOs plus an open periphery of volunteer
organizations. A multi-tenant developer platform with a trusted control core
(the platform team) and open user agents. An open-source maintenance bot
swarm where the project maintainers are core and outside contributors run
periphery agents with capped authority over the same PRs.

The promotion path — periphery agents earning their way into the core —
runs through reputation, not topology mutation. An agent accumulates good
behavior; the constitution evaluates that signal; the operator extends an
explicit grant or upgrades the agent's `passport_tier`. The topology
document doesn't change; what changes is whether a given agent is on the
core allowlist, via a normal operator-signed allowlist-update receipt.
Reputation is never the *sole* basis for the decision — it informs;
capabilities and the constitution decide.

## How topology colors enforcement

The same constitution behaves differently across topologies, by design. The
Cedar+ policy text doesn't change — the same `forbid` rule with the same
`when` clause runs everywhere. What changes is the bundle of defaults the
enforcement engine applies on top of the policy decisions.

In a closed swarm, enforcement defaults are slow and supervisor-mediated:
detect thresholds are high (a pattern of 5–10 denies, not 2–3), coach
cooldowns are long (5 minutes between coach and quarantine), supervisor
countersign is required at every stage transition rather than just at evict,
and a quarantine stays in place until an operator explicitly reverses it.
Eviction is rare and reserved for verified compromise.

In an open swarm, the defaults invert. Detect thresholds are low (2–3
denies, sometimes one for severe categories), coach cooldowns are short (tens
of seconds), supervisor countersign is skipped on detect/coach/quarantine
because the volume would overwhelm any supervisor, and quarantines auto-expire
after a defined window unless re-triggered. Eviction is a common outcome for
repeat offenders.

In a hybrid swarm, the engine applies closed-mode defaults to core agents and
open-mode defaults to periphery agents, distinguishing them via
`principal.passport_tier` or a custom attribute in the schema. One
constitution, two enforcement cadences, no per-agent special-casing.

Capability defaults shift too. Lifetime ceilings, chain-depth caps, and
`default_initial_scope` are tighter in open and hybrid than in closed —
declared in the topology document and enforced as ceilings at capability
issue time. `external_sends_permitted` defaults differ: false in closed,
true in open (periphery scopes are assumed constrained anyway), operator-set
in hybrid. Concrete numbers per mode ship in the F8 canonical schemas under
`/spec/constitution/canonical-schemas/v1.1.0/`; postures are pinned in
[`/spec/constitution/enforcement.md`](https://github.com/abhinavg6/yutha/blob/main/spec/constitution/enforcement.md)
§9.

## Choosing one

Default to closed for first deployments. The operational simplicity, the
high trust prior, the patient enforcement defaults, the structural sybil
defense all compound to make a closed swarm the easiest to reason about
while you're still discovering what your agents do. Most production
deployments stay closed.

Move to hybrid when you have external participants whose trust grows over
time and you don't want to choose between admitting them with full authority
or not admitting them at all. The structural cap on periphery authority is
the load-bearing property — a misbehaving periphery agent can't escalate
beyond a known ceiling, regardless of how generous a momentary lapse from
an operator might be.

Use open for tutorials, public demos, and community swarms where the
constitution is restrictive enough that low-trust admission isn't a hole —
including developer-quickstart-style workflows where the seed-based
bootstrap is the whole point.

If you find yourself wishing you could change topology in place, the
migration path (new swarm, fresh `swarm_id`, fresh genesis receipt chain,
fresh operator signature) is the answer. The cost is real for large swarms;
the security property is that the cost cannot be avoided by an operator
alone. Phase 4 federation provides a partial workaround: admit new
participants via a federated peer swarm whose topology fits them.

## A worked example

The topology selection happens at control-plane startup. From the operator
quickstart, a production-shaped invocation:

```bash
cargo run --release -p yutha-control-plane -- \
    --admission-mode closed \
    --workload support-queue \
    --operator-public-key "$YUTHA_OPERATOR_PUBLIC_KEY" \
    --receipt-backend memory \
    --grpc-addr 127.0.0.1:50051
```

`--admission-mode` takes `closed`, `open`, or `hybrid`. Full semantics —
bootstrap-seed pattern, operator-key wiring, why production deployments omit
`--bootstrap-seed` from the server side — are at
[Operator → Quickstart, Step 1](../operator/quickstart.md#step-1-start-the-control-plane).

## Where to go next

- [`/spec/topology/`](https://github.com/abhinavg6/yutha/blob/main/spec/topology/)
  — the canonical proto definition and design rationale.
- [RFC 0006 — Topology v1.0](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0006-topology-v1.md)
  and [RFC 0009 — Operator credentials](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0009-operator-credentials.md)
  — admission and operator-side mechanics topology depends on.
- [Operator → Quickstart](../operator/quickstart.md) — the 20-minute
  walkthrough that picks a topology and stands a swarm up around it.
- [Constitution & enforcement](constitution.md) — how the topology you choose
  shapes the enforcement defaults the constitution runs on top of.

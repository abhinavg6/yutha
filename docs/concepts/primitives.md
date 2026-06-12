# Primitives

When an agent does something consequential — sends a message to another agent, calls an external API, spends a budget, escalates to a human — four questions need answers afterwards: *who did it*, *were they allowed to*, *what actually happened*, and *what speech act was it*. Yutha builds the whole substrate from exactly four primitives, each answering one of those questions: a **passport** identifies the agent, a **capability** grants bounded authority, a **receipt** records what occurred, and an **envelope** carries the message that triggered it all.

Four isn't a coincidence. Three would force one of identity, authority, or evidence to piggy-back on the others — always a leaky abstraction. Seven would mean the substrate is reasoning about things the application should own. Four is the smallest set that lets you talk honestly about each question without collapsing them. Everything else in Yutha — the rules engine (the constitution), the four-stage response to violations, the verifiable audit trail, the framework adapters — composes over these four. If you load this page, the rest of the system follows.

This page is the conceptual tour: what each primitive is, why it exists, what mental model to keep when you reach for it, and how the four compose into a working flow. The formal wire format, field-by-field rationale, and conformance hooks live under `/spec/` and are linked at the end of each section. The threat model that shaped the primitives — hostile agent, compromised model, prompt injection, network adversary, sybil, malicious operator, compromised supervisor — is what each design choice is defending against; when a constraint looks unnecessarily strict, one of those adversaries is usually the reason.

!!! note "One invariant to load up front"

    **Declaration is not authority.** A passport's `capabilities` list is what the agent *says* it can do. A capability token is what actually *lets* it do something. An envelope's `performative` is what kind of speech act the sender is making. A receipt's `action_kind` is what the substrate observed after the fact. None of those four fields ever stand in for one of the others. The split is structural, and it is what makes prompt injection containable: an LLM convinced to *declare* an authority it does not hold still gets denied at the capability check, because the declaration was never authorization.

## Passport

A passport is the signed identity manifest an agent presents when it asks to join a swarm. Think of it as the agent's resume plus its signature: this is who I am, this is the key I will sign every future action with, this is the swarm I want into, this is the framework I'm built on, this is the constitution version I commit to obey, and this is the resource budget I expect to need. The agent self-signs the passport with its private Ed25519 key; the registry validates it against the swarm's admission policy and writes a registration receipt. From that point on, every signature the agent produces is verifiable against the passport's public key, and every receipt that names the agent ties back to the passport that authorized it.

Two pieces of the design are worth lingering on. **First, the agent signs its own passport** — not the operator. The operator's role is to *accept or reject* the registration, not to forge the identity. This means a malicious operator cannot silently swap one agent's identity for another, because the operator does not hold the agent's private key. It also means the passport is non-repudiable: an agent cannot later claim "that wasn't me" about a passport signed by its own key. **Second, declaration is not authority.** A passport carries a `capabilities` list — what the agent *says* it can do — but that list confers no permission. Permission lives in capability tokens, issued separately and gated at the control plane. This split is structural, and it is what makes prompt injection containable: an LLM that is talked into believing it can issue refunds still gets denied at the capability check, because the passport never granted refund authority in the first place.

A passport is also single-swarm. An agent that wants to be in two swarms holds two passports. The constraint sounds annoying until you consider the alternative: a capability issued in swarm A leaking into swarm B because the underlying identity straddles both. Federation, when it lands, will handle cross-swarm operations through explicit handshakes — never by re-using a passport.

What the registry does with the passport depends on the swarm's [topology mode](topology.md). A closed swarm checks the passport against an allowlist; an open swarm requires it to pass a registration-cost mechanism and to declare an `expires_at`; a hybrid swarm has both a closed core and an open periphery and applies different admission tiers to each. The passport carries the same shape in all three modes — only the admission policy on the operator's side changes.

The fields you'll care about most:

- `agent_id` — UUID v7, stable across key rotations. Deliberately *not* a hash of the public key, which would tie identity to keying material and break rotation.
- `agent_public_key` — Ed25519. v1.0 locks the algorithm; PQ migration is a future major-version bump.
- `framework` / `framework_version` — free-form strings, used for compromised-model attribution and adapter routing. Never used as a permission input.
- `accepted_constitution_version` — the constitution the agent commits to obey. Amendments require fresh consent (a new passport, signed).
- `tier` — `MINIMAL` / `STANDARD` / `VERIFIABLE`. Admission policy keys on this; verifiable backends require the top tier.
- `resources` — declared budget caps (concurrent actions, messages per minute, USD-cents per day). The control plane enforces these as quotas; the constitution can additionally tighten them.
- `expires_at` — required in open and hybrid swarms (sybil mitigation); optional in closed.

Three operations change a passport's effective authority, each with a distinct receipt action-kind so audit can disambiguate them. **Self-revoke** (`agent.revoke`) is the agent saying "I'm done." **Operator-revoke** (`agent.operator_revoke`) is the operator evicting the agent — optionally with a cascade that revokes every capability the agent ever issued. **Key rotation** (`agent.rotate_key`) preserves the `agent_id` while swapping the public key, signed by the old private key to prove continuity. On any revocation, the control plane proactively tears down active subscriptions and rejects subsequent bearer tokens; revocations are immediate, not waiting for token expiry. The full field list and rationale live in [`/spec/passport/`](https://github.com/abhinavg6/yutha/tree/main/spec/passport).

## Envelope

An envelope is the typed wrapper around every agent-to-agent message. The application's content — LLM output, customer text, a tool result, a structured payload — sits inside `payload` as opaque bytes. Everything around the payload — sender, recipient, performative, swarm, causal predecessors, nonce, signature, tags — is typed and signed, and that is what the control plane reasons about. The substrate never introspects the payload. This split is the structural defense against prompt injection: even if an LLM is convinced to embed instructions in the payload, those instructions cannot synthesize a valid envelope of a forbidden performative, because they cannot produce the agent's signature.

The **recipient** is a oneof, not a string. An envelope is addressed to one of: a specific agent (unicast), a role (`"supervisor"`, `"billing"`, `"router"` — fanned out to all agents claiming that role), a swarm-wide broadcast with optional filter tags, or an external endpoint (gated by capability). Role-based dispatch is first-class because that is how real swarms are wired — the router doesn't know the billing agent's ID, it knows there's a billing role. Putting that dispatch in the substrate means the audit trail captures the role binding, not just the resolved endpoint.

The **performative** is a small, closed enumeration borrowed from speech-act theory and pruned hard. Eleven values cover the negotiation patterns the platform needs — `PROPOSE`, `COUNTER`, `COMMIT`, `ABORT`, `RELEASE`, `QUERY`, `INFORM`, `ERROR`, `REQUEST_ACTION`, `CONFIRM`, `DECLINE`. We resisted shipping forty performatives because every additional one is a thing the constitution has to know about and the control plane has to dispatch on. Domain actions like "issue_refund" or "fetch_document" are *not* performatives; they are payload kinds inside a `REQUEST_ACTION` envelope. The performative is the *kind of speech act*; the payload says *what specifically*.

The **payload_schema_id** lets the SDK adapter deserialize on the receiver side and lets the constitution match without parsing bytes. The **tags** field carries operator-defined classification labels — `"pii"`, `"external"`, `"high_risk"`, `"customer_data"` — that constitution norms and capability caveats can key on. Tags are part of the signed surface, so they cannot be retroactively altered; a downstream auditor slicing by tag is slicing by what the sender attested at send time, not by some later annotation.

The `Recipient.external` variant deserves a special note. Envelopes can target external endpoints (webhooks, third-party APIs, mail systems) but only when an explicit capability authorizes the destination, and only when the swarm's topology mode permits external sends at all. The substrate carries the scheme, authority, and a coarse path hint — never the full URL — so the capability is the deciding factor, not a string the agent constructed locally. Without external-send authority, every attempt produces a deny receipt and stops at the substrate.

**Causal predecessors** are a first-class field on every envelope. The DAG of dependencies is emitted by the sender, not reconstructed by a downstream tracer. This means counterfactual replay is tractable — perturbing an upstream evidence value and re-running the deterministic decision tree finds exactly which downstream receipts are invalidated, without log archaeology. It also means audit can walk the chain that led to any decision without trusting timestamp ordering.

Concretely, a router envelope from the [S1 customer-support demo](https://github.com/abhinavg6/yutha/blob/main/sdks/python/examples/s1_support_queue.py) looks like this in the SDK:

```python
await router_agent.send(
    recipient=yutha.Recipient.for_agent(returns_agent_id),
    performative=yutha.Performative.REQUEST_ACTION,
    payload=ticket_text.encode("utf-8"),
    payload_schema_id="type.yutha.dev/v1/Text",
    tags=["s1-demo", "category:returns"],
)
```

The SDK fills in the nonce, epoch, timestamps, causal predecessors, and signature. The control plane verifies the signature, gates the send against the active capability and constitution, and writes an `envelope.send` receipt before the message hits the wire.

Two operational details worth flagging. **Replay protection is layered**: a per-sender nonce defeats same-window replay, a monotonically-increasing `epoch` defeats stale replay after nonce state ages out, and an `expires_at` TTL defeats long-delayed adversarial replay where both have aged out. **Unknown performatives are never silently ignored.** A receiver that doesn't recognize a performative surfaces it as `ENVELOPE_ERROR_UNKNOWN_PERFORMATIVE` — that surfacing is the difference between an audit trail and a leak.

## Receipt

A receipt is the canonical record of a consequential action — every envelope sent, every capability checked, every memory write, every enforcement decision, every constitution amendment. Receipts are append-only (you can add, you cannot rewrite or delete), content-addressed (a receipt's identifier is the SHA-256 of its canonical serialization), and cryptographically signed (the actor at minimum; the control plane, supervisor, or attestation backend countersign where the action requires it). The receipt store is the single place an auditor goes to reconstruct what happened. It is the load-bearing wall of Yutha — every later capability, including enforcement, observability, federation, dispute resolution, and regulatory audit, reduces to "what do the receipts say?"

A useful mental model is git, but for agent actions. Content addressing means two implementations that observe the same action produce bit-identical receipt IDs — that is the property the differential conformance suite verifies nightly against the reference stack. Causal predecessors mean the dependency graph is *emitted*, not reconstructed: an enforcement engine doing a counterfactual replay doesn't have to guess which receipts a perturbation would invalidate, because the predecessors are right there. And immutability means a malicious operator cannot silently rewrite history — the rewrite would change the content-address and break every receipt that referenced it. The optional [Sui anchoring](verifiability.md) extends this to cryptographic detectability across organizational boundaries.

One conceptual point worth surfacing: the **control plane itself produces receipts as an agent**. The control plane has its own passport, its own signing key, and shows up as the `actor` on receipts for actions it performed — registrations it accepted, enforcement decisions it made, capabilities it minted on platform policy. The control plane is not magic; it is an agent with extra capabilities, and its actions are receipted exactly like any other agent's. This is what makes the audit trail honest about *who* did what, including the platform itself.

What counts as "consequential" is defined by the [canonical action-kinds registry](../reference/canonical-actions.md). The list grows as the substrate matures, but the shape is stable: domain-prefixed strings like

- `envelope.send`, `envelope.deliver`, `envelope.deliver.failed` (transport),
- `capability.issue`, `capability.attenuate`, `capability.revoke`, `capability.check.pass`, `capability.check.deny` (authority),
- `agent.register`, `agent.revoke`, `agent.operator_revoke`, `agent.rotate_key` (identity lifecycle),
- `constitution.evaluate.pass`, `constitution.evaluate.deny`, `enforcement.detect`, `enforcement.coach`, `enforcement.quarantine`, `enforcement.evict`, `enforcement.reverse` (policy and enforcement),
- `anchor.commit` (verifiable-tier sealing).

Conformant implementations must use these strings; inventing new ones requires an RFC. The registry is the contract between implementations — two stacks that agree on action-kinds and canonical serialization will produce bit-identical receipts for the same observed action, which is what differential conformance checks.

Each receipt also pins the **constitution version active at decision time**. A receipt from six months ago must remain interpretable under the rules that were active then, not under whatever rules are active now. The version pin is what makes that work. Receipts also carry an optional `CostAnnotation` (tokens, wall-time, USD-cent estimate, model provider and name) so cost-per-task analytics and compromised-model correlation come for free from the audit trail.

The signature surface deserves a brief callout because it generalizes cleanly. A receipt carries an ordered list of signatures, each with a role: `ACTOR` (required — the agent that performed the action), `CONTROL_PLANE` (the platform observed and accepted this), `SUPERVISOR` (two-person-rule countersign on high-stakes actions), `ATTESTATION` (verifiable-tier hardware/enclave binding), and `BATCH_ROOT` (a sealed-batch Merkle-root countersign for cryptographic-tier inclusion proofs). Each later signer signs over the receipt-with-previous-signatures-included, so the chain is verifiable in order without relitigating prior signatures. Adding new signer roles in the future — federation peers, dispute mediators — is additive: same shape, new role enum, no wire break.

Content-addressing has one more property worth surfacing. Because the receipt's identifier is the hash of its canonical serialization with signatures *cleared*, the identifier is stable regardless of who eventually signs. The actor can compute and reference the receipt's content-address before the control plane countersigns; later signers don't change the address; the supervisor and attestation backends can sign asynchronously without invalidating any pointer that already exists. This is the substrate that makes ordered multi-sig and selective disclosure (in the verifiable tier) work without coordination dance.

Receipts also have a **seal status** that distinguishes plain durable persistence from cryptographic anchoring. An unsealed receipt is fully valid for everyday audit; a sealed receipt has additionally been folded into a Merkle batch whose root is signed and (optionally) anchored to a public chain. The cost is one extra signature per batch and one short Merkle path stored per receipt; the benefit is that an external verifier can prove a single receipt's inclusion with O(log N) bytes, verify a million-receipt batch with one signature, and selectively disclose a single receipt without exposing the rest of the batch. The optional Sui anchor adds a transaction-digest pointer so a third party can independently verify the seal — see [Verifiability](verifiability.md) for the layer above.

## Capability

A capability is an authority token: a signed, attenuable, expiring credential that says "the holder is permitted to perform actions matching this scope, under these caveats, in this swarm, until this time." There is no ambient authority in Yutha. Every consequential action requires an explicit capability check, performed at the control plane, not in agent code. If an agent is convinced via prompt injection to attempt an action it does not have a capability for, the check fails and the action does not happen. The receipt log records the denial with its reason and any unmet caveats; nothing is silent.

The mental model closest to capabilities is an OAuth bearer token — but with three differences that matter. Capabilities are **attenuable** in the macaroon style: a holder can mint a child capability that *narrows* its scope (never broadens), give the child to a delegate, and the delegate can attenuate further. The verifier walks the parent chain to a root and intersects scopes at each step, so the child can never exceed the parent. This makes safe delegation a local operation — the holder doesn't need to contact the issuer. Capabilities are **content-addressed**, so the parent pointer is a hash; an attempt to rewrite a parent after the fact dangles every child that descended from it, which gives delegation chains the same integrity property as the receipt chain. And capability checks are **verified by the control plane**, not by the calling agent's own code, which means a compromised or prompt-injected agent cannot just decide to skip the check.

Scope is multi-dimensional: permitted action kinds, resource tags, numeric bounds (`"usd_max": "500.00"`), permitted recipients, permitted memory scopes. Empty fields default-deny — you cannot accidentally grant unrestricted authority by leaving a field blank; you have to set an explicit `unrestricted_actions` extension. Attenuation intersects each dimension at every step, which means scope can only narrow as a chain deepens, never broaden.

Caveats are a small, closed vocabulary that further constrain when the capability is valid:

- **`TimeOfDayCaveat`** — only between specified UTC hours. Business-hours-only authority, on-call windows.
- **`ConstitutionVersionCaveat`** — valid only under a specified constitution semver range. Pinning authority to policy.
- **`SupervisorRequiredCaveat`** — forces a two-person rule. The resulting receipt requires a supervisor countersign before it lands.
- **`RateLimitCaveat`** — at most N actions per window. The quota lives on the capability itself, not in agent code.
- **`OnlyIfTaggedCaveat`** / **`NeverIfTaggedCaveat`** — conditional on resource tags. "Only on resources tagged `internal`," "never on resources tagged `pii`."

The set is closed because each caveat type is something the control plane evaluates at every check, and arbitrary caveat predicates would put a Turing-complete language on the security boundary. Richer conditions — anything resembling a Boolean expression over agent attributes, receipt history, or workflow state — belong one layer up, in the Cedar+ [constitution](constitution.md), where the analyzer can prove them safe.

Issuers come in three flavors and the audit cares which: an **agent** (attenuating a capability it already holds), an **operator** (minting a fresh root capability with an operator-fingerprinted key — the bootstrap path), or the **control plane** itself (minting platform-policy capabilities like "you've just registered, here is the basic-membership capability"). Validity windows are required — `valid_until` cannot be unset — and the spec defaults to a 90-day maximum, with production deployments encouraged to use hours-to-days. Short lifetimes shrink the compromise window and naturally bound the cost of revocation propagation; the canonical pattern for long-running authority is a short-lived capability refreshed on a heartbeat.

Revocation produces a `capability.revoke` receipt that the control plane consults on every subsequent check; propagation is immediate, not waiting for token expiry. When an operator revokes an agent's passport with cascade enabled, every capability that descends from the agent's issuance chain is revoked in the same operation, and the receipts for the cascade are linked from the operator-revoke receipt — so a single audit query reproduces both the eviction and its blast radius.

A few implementation details that matter when you're reasoning about authority. The control plane walks the parent chain to a root on every check; the chain length is bounded (default max depth 8, configurable in topology) to prevent attack-via-deep-chain. Default capability lifetime is 90 days as a hard ceiling; the spec strongly discourages anything near that. Empty-list root capabilities require an explicit `unrestricted_actions` extension flag so they cannot be created accidentally. Every denied check produces an explicit `capability.check.deny` receipt with the deny reason and the unmet caveats — there is no silent failure, ever.

## How the four compose

In practice, the four primitives compose along a single throughline. An agent generates an Ed25519 keypair, builds and signs a passport, and presents it at `AdmissionService.Register`. The registry validates against the swarm's topology mode, writes an `agent.register` receipt, and returns a bearer token that authenticates subsequent RPCs. With the bearer token in hand, the agent (or an operator on its behalf) requests a capability via `CapabilityService.Issue` for the action it's about to perform — sending an envelope to a particular recipient, writing memory in a particular scope, calling a particular tool. The issuer signs the capability, the store persists it, and a `capability.issue` receipt lands.

In code, the bootstrap looks roughly like this — adapted from the [S1 customer-support demo](https://github.com/abhinavg6/yutha/blob/main/sdks/python/examples/s1_support_queue.py):

```python
signer = yutha.InProcessSigner.generate()
passport = await yutha.Passport(...).sign(signer)    # primitive 1
agent = YuthaAgent.connect(server, passport=passport, signer=signer)
await agent.register()                               # writes agent.register receipt
cap = yutha.Capability(scope=yutha.Scope.for_action("envelope.send"), ...)
cap_id, _ = await agent.client.capability.issue(cap) # primitive 4 + capability.issue receipt
await agent.send(recipient=..., performative=..., payload=...)  # primitive 2 + check.pass / send / deliver receipts (primitive 3)
```

Three primitives are visible in the call sites; the fourth — the receipt — is what every one of those calls writes into the durable log on the way past.

One mechanism that sits between the primitives and the gRPC surface is worth naming: the **bearer token**. After registration, the server returns a bearer token bound to the agent's passport that authenticates every subsequent RPC over the gRPC channel. The bearer is a transport-layer convenience — it saves re-signing every call — but it is *not* authority. Authority still flows from capabilities. The bearer says "you are who you say you are"; the capability says "you may do what you are about to do." Two different questions, two different mechanisms, two different layers. Operator-tier bearer tokens (used by `yutha-ops` and operator-driven flows) are a separate variant with their own RPC subset and their own receipt kinds.

The four primitives have stayed stable through every Phase of the project so far, and the conformance suite is what keeps them honest across implementations. Every change to a primitive's wire shape is RFC-gated; every change to the canonical action-kind taxonomy is RFC-gated; every change to the canonical serialization rules requires regenerating the wire vectors and re-running differential conformance across the Rust, Go, and Move stacks. The cost of getting these four right up front is exactly what lets the layers above them (constitution, enforcement, anchoring, adapters) move quickly without dragging the substrate behind them.

When the agent then sends an envelope, the SDK attaches the capability's content-address to the request. The control plane synthesizes an `ActionDescriptor` from the envelope (action kind, recipient, tags, payload schema), walks the capability's parent chain, evaluates every caveat, and either passes or denies. A `capability.check.pass` receipt unlocks the send; the transport delivers the envelope and writes an `envelope.send` receipt referencing both. On the receiver side, an `envelope.deliver` receipt lands when the envelope clears signature verification and replay checks. Every step is a separate, signed, content-addressed receipt with causal predecessors pointing back to the receipts it depends on. The DAG of dependencies is the audit trail; the audit trail is the source of truth.

The four primitives also reinforce one another. The passport is what the envelope's signature is verified against. The capability is what the control plane authorizes the envelope's send against. The receipt is what every check, every issuance, every send, and every revocation writes into the durable log. And the capability's parent chain and the receipt's causal DAG share a structural property — both are content-addressed and tamper-evident, so rewriting either later is detectable. The constitution, the four-stage enforcement loop, the verifiable anchor, and the framework adapters all build on top without introducing additional primitives: they read receipts, mint capabilities, and emit more receipts.

Layered on top of all this, the [constitution](constitution.md) evaluates each action against declarative norms before the capability check and writes its own `constitution.evaluate.{pass,deny}` receipts; the [enforcement engine](constitution.md) pattern-matches over the receipt stream and progresses violations through the four stages. None of those layers invent new primitives — they read receipts, mint capabilities, and emit more receipts.

A useful way to internalize the four is by what they defend against. **Prompt injection (A3)** is contained by the structural split between envelope (typed, signed, control-plane-readable) and payload (opaque application bytes), and by the no-ambient-authority property of capabilities. **Malicious operators (A8)** are contained by self-signed passports the operator cannot forge, by append-only content-addressed receipts the operator cannot silently rewrite, and (in the verifiable tier) by Sui-anchored Merkle roots external auditors can check without trusting the operator's storage. **Compromised models (A2)** are made detectable by the framework + model-provider fields the passport and the receipt's `CostAnnotation` both carry. **Hostile or buggy agents (A1)** are bounded by capability scopes and resource declarations, and made accountable by the agent-signature requirement on every action. Each primitive is doing more than one job; the four together are doing all of them at once.

## Where to go next

- The formal wire formats and full field-by-field rationale live under [`/spec/passport/`](https://github.com/abhinavg6/yutha/tree/main/spec/passport), [`/spec/envelope/`](https://github.com/abhinavg6/yutha/tree/main/spec/envelope), [`/spec/receipt/`](https://github.com/abhinavg6/yutha/tree/main/spec/receipt), and [`/spec/capability/`](https://github.com/abhinavg6/yutha/tree/main/spec/capability). Each has a `.proto` file and a `rationale.md` that goes deeper than this page.
- Shared types — `AgentId`, `SwarmId`, `Hash`, `Timestamp`, `Signature`, `CausalRef`, `CostAnnotation` — are at [`/spec/common.proto`](https://github.com/abhinavg6/yutha/blob/main/spec/common.proto). The wire-determinism conformance vectors live under [`/spec/vectors/`](https://github.com/abhinavg6/yutha/tree/main/spec/vectors).
- The canonical action-kind taxonomy — the strings every conformant implementation must use for receipts — is at [Reference → Canonical actions](../reference/canonical-actions.md).
- The [RFC archive](../reference/rfcs.md) carries the design history. RFC 0002 (passport), 0003 (envelope), 0004 (receipt), and 0005 (capability) are the primitive specs; RFCs 0007–0009 cover send-path enforcement, wall-clock bound checks, and operator credentials; RFC 0014 covers the verifiable-tier Sui anchor.
- For a runnable end-to-end of these primitives in fifteen minutes, work through the [Developer quickstart](../developer/quickstart.md).
- For the policy layer on top, see [Constitution & enforcement](constitution.md). For the topology that determines admission policy, see [Topology](topology.md). For the cryptographic-proof layer, see [Verifiability](verifiability.md).

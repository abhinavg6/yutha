# Topology Spec — Design Rationale

> **Spec:** [`topology-v1.proto`](./topology-v1.proto)
> **Version:** v1.0 draft
> **RFC:** 0006
> **Threat-model linkage:** A1 (hostile agent — admission gating), A6 (sybil — primary defense), A8 (malicious operator — periphery constraint)

## 1. What is a topology, in one paragraph

A topology declares the participation mode and admission policy of a swarm: who can join, under what conditions, with what default authority, and with what defaults around capability lifetime, envelope TTL, and replay-protection windows. Yutha supports three modes — closed (allowlist, trusted-only), open (anyone meeting sybil-resistance criteria), and hybrid (trusted core + open periphery). The mode is an immutable property set at swarm creation; changing it requires creating a new swarm with migration. This restriction is intentional, because the topology shapes capability defaults, registration costs, and constitution amendment quorums; allowing in-place mutation would create privilege-escalation paths.

## 2. Why this exists as a separate spec

Topology could plausibly live inside the constitution. We separated it for three reasons:

- **Topology is established at creation, before there is a constitution to evaluate.** The constitution is evaluated against entities and actions; the topology decides which entities are even admitted. The bootstrap order matters.
- **Topology binds the registry and the capability layer, not the policy layer.** A registry implementation has to consult topology to decide admission; a capability issuer has to consult topology for default lifetime ceilings; the constitution evaluator does not directly read topology fields.
- **Topology is operator-policy, not norm-policy.** "We are a closed swarm of trusted internal agents" is a deployment decision, not a community-debated norm. The constitution evolves; the topology does not.

The three modes are first-class to the build plan (PRD §8.3 plus build-plan.md §4.9). The PRD alludes to "fixed/open/dynamic topologies"; v1.0 instantiates that as the closed/open/hybrid trio with explicit semantics for each.

## 3. Field-by-field rationale

**`spec_version`.** First.

**`swarm_id`.** Pinning topology to a swarm is the primary integrity property. A topology document is meaningful only in conjunction with the swarm it declares.

**`mode` (TopologyMode).** Three values: CLOSED, OPEN, HYBRID. Each requires a corresponding admission policy variant; consistency is enforced at validation time (a closed mode with an open admission policy is rejected).

**`admission` (AdmissionPolicy).** A oneof matching the mode. The split into three policy types (rather than a single union of fields) makes it impossible to express incoherent combinations like "closed + sybil resistance" or "open + allowlist."

**Default knobs** (`max_capability_lifetime_seconds`, `max_capability_chain_depth`, `default_envelope_ttl_seconds`, `max_epoch_skew`). These tighten or accept the platform defaults. Topology can tighten; cannot loosen below absolute floors enforced by the spec. For instance, you can require capabilities live no more than 24 hours in your swarm, but you cannot extend lifetime beyond the platform-wide max.

**`external_sends_permitted`.** Whether agents in this swarm may send envelopes to ExternalEndpoint recipients (subject still requires capability check). Defaults vary: closed mode false unless explicitly enabled; open mode true with the assumption that periphery agents have constrained scopes; hybrid mode true with periphery generally restricted by capability scope from sending external.

**`initial_constitution_version`.** The genesis constitution. Constitution amendments evolve from here per the constitution's own amendment procedure (Phase 2 + 4).

**`operator_key_fingerprint`.** The trust root of the swarm. Operator-issued capabilities are verified against this key. Multi-operator swarms (federation, Phase 4) handle multi-root via the federation handshake.

**`extensions`.** Forward-compatibility hatch.

**`operator_signature`.** The topology document is signed by the operator. Re-signing (e.g., on operator key rotation) is itself a controlled operation that produces a `topology.operator_rotate` receipt; the topology fields themselves do not change.

## 4. The three modes in detail

### Closed

ClosedPolicy enumerates allowed agents. Two granularities: by AgentId (specific agents) and by owner-key fingerprint (any agent registered under a known operator). The owner-key path is what makes operator-class allowlists possible — "any agent whose owner key is org X" without enumerating every agent.

`pending_review_on_unknown` controls behavior for unknown registrations:
- `false` (default): unknown AgentId is REJECTED outright.
- `true`: unknown AgentId is PENDING_REVIEW and held in a queue; an operator-issued `agent.register.approve` receipt admits, an `agent.register.deny` receipt rejects.

Closed swarms are the simplest case for sybil defense (the allowlist is the sybil defense), the simplest case for capability defaults (operators decide), and the simplest case for amendment (operator decides). They are also the most operator-trust-dependent — a malicious operator in a closed swarm has the most latitude. A8 mitigations rely heavily on receipt fabric integrity here.

### Open

OpenPolicy supports five sybil-resistance mechanisms (one or more, AND-composed):

- **Proof-of-work**: simple, universal, cheap to verify. Difficulty parameter is operator-tunable. A few seconds at difficulty 22; about a minute at 26. Real cost: a determined attacker with many cores can outpace defense; useful as a noise filter, not a real attack defense.
- **Hardware attestation**: strong defense via TEE attestation (Nautilus, SGX, SEV, TPM). Not universally available; rules out many legitimate participants. Best for verifiable-tier swarms.
- **IdP attestation**: registrant proves identity via OIDC, SPIFFE, or DID. Useful when admission is "any agent operated by a known org" (university consortium, partner network).
- **Stake**: register by locking some resource (financial, reputational, computational) recoverable on good behavior, slashable on misbehavior. Strongest defense; opt-in per deployment because of policy implications.
- **Invite**: existing-member-issued one-shot invite tokens. Bootstraps invite-only public swarms.

Combinations are AND. "Open swarm requiring proof-of-work AND IdP attestation" is "you have to be a known org's agent AND pay the registration cost." The most common production combination is expected to be IdP + small proof-of-work (or invite + small proof-of-work) for swarms that want to admit broadly but raise the cost of mass registration.

`min_passport_tier` and `max_passport_lifetime_seconds` further constrain. Open swarms typically tighten passport lifetime relative to closed swarms — a 90-day passport in a closed swarm is fine, but in an open swarm it lets attackers register, dwell, and strike late.

`default_initial_scope` is the capability ceiling for newly-admitted agents. Open swarms generally start agents with minimal capabilities and grow scope through reputation, supervisor approval, or operator grant. The constitution decides growth policy; the topology decides the starting point.

### Hybrid

HybridPolicy combines a closed core (trusted operators) with an open periphery (broader participation). Three additional knobs:

- `core` and `periphery`: the closed and open policies for each segment.
- `periphery_capability_constraint`: a scope ceiling that further constrains every periphery agent's capabilities, regardless of the open policy's `default_initial_scope`. The intersection rules from the capability spec apply.
- `periphery_may_delegate`: whether periphery agents can attenuate their capabilities to other periphery agents. Default false (periphery is leaf-only). When true, a periphery agent can sub-delegate; the chain is bounded by `max_capability_chain_depth`.

Hybrid is the right mode for many real deployments. Disaster-response coalitions often have a trusted operator core (UN agencies, named NGOs) plus an open periphery (volunteer organizations, individual responders). Multi-tenant developer platforms have a trusted control core (the platform team) plus open user agents (customer deployments).

## 5. Threat-model linkage

| Adversary | How this spec contributes to mitigation |
|-----------|------------------------------------------|
| A1 Hostile agent | Admission policy gates entry; default scope ceilings limit blast radius of admitted hostiles. |
| A6 Sybil | The primary defense surface. Closed mode trivially defeats sybil via allowlist. Open mode raises cost via proof-of-work, attestation, IdP, stake, or invite. Hybrid mode offers fine-grained "trusted core gets full authority, periphery gets bounded authority" model. |
| A8 Malicious operator (partial) | The hybrid mode's `periphery_capability_constraint` is a structural cap on what the operator can grant to periphery agents, even by capability issuance — the constraint is enforced at check time independent of issuer. Operator cannot silently "promote" periphery to core authority without amending topology, which (since topology is immutable) requires a fresh swarm and visible migration. |

## 6. Why topology is immutable

A swarm's topology shapes:

- Capability lifetime ceilings (cannot extend beyond what topology permits).
- Default initial scopes (a new agent's authority).
- Constitution amendment quorums (per topology defaults; constitution may further constrain).
- Sybil-resistance requirements at registration.
- Whether external sends are even permitted.

If topology were mutable, an operator could:

- Loosen periphery constraints in hybrid mode to grant unintended authority.
- Lower sybil-resistance to admit attackers.
- Extend capability lifetime to make compromised tokens valid longer.
- Toggle external_sends_permitted to enable exfiltration paths.

Each of these is a privilege escalation. Modeling topology change as "create a new swarm and migrate" makes the change visible (a new swarm_id, a new genesis receipt chain, a new operator signature) and forces operator-side discipline. The migration is observable to every participant; no one wakes up tomorrow under a different topology than they consented to.

The cost is real: large swarms migrating between modes is expensive. We accept the cost for the security property. Phase 4 federation provides a partial workaround for some use cases (e.g., admit new participants via a federated peer swarm rather than expanding the host swarm).

## 7. Conformance hooks

A conformant registry implementation:

- **Validates topology consistency** (mode matches admission variant) at swarm creation. Rejects inconsistent topologies.
- **Enforces admission policy** at every register call. Closed: allowlist match (by AgentId or owner key). Open: ALL sybil-resistance requirements pass and min_passport_tier met. Hybrid: closed_core OR open_periphery succeeds; periphery agents receive constrained capabilities.
- **Enforces topology defaults** as ceilings (capability lifetime, envelope TTL, chain depth).
- **Refuses to start** if its admission policy and the swarm's declared topology disagree (the immutability check).
- **Produces `topology.activate` receipt** on swarm creation; this is the genesis receipt.
- **Refuses topology mutation** in place; returns a clear error directing operator to the migration flow.

Conformance tests in `/conformance/interface/registry/` exercise each mode independently plus the cross-mode rejection cases.

## 8. Default sybil-resistance combinations

Recommended starting points (operators tune from here):

- **Internal SOC swarm** (closed): allowlist of agents owned by the SOC team; pending_review_on_unknown=false.
- **Public hobbyist swarm** (open): proof-of-work difficulty 22 + invite required; min_passport_tier=MINIMAL; passport lifetime 7 days.
- **Research consortium** (open): IdP attestation against accepted-issuers list of consortium members; min_passport_tier=STANDARD; passport lifetime 30 days.
- **Disaster-response coalition** (hybrid): closed_core of UN-agency operator-key fingerprints; open_periphery requiring IdP attestation against pre-approved NGO list; periphery scope limited to logistics-coordination actions only; periphery_may_delegate=false.
- **Verifiable-tier swarm**: hardware attestation required (Nautilus or equivalent); min_passport_tier=VERIFIABLE.

Each comes with a starter Cedar+ schema in Phase 2.

## 9. Alternatives considered

**Two modes (closed and open).** Rejected: hybrid covers a meaningful fraction of real deployments cleanly; collapsing it into "open with allowlisted privileged agents" via constitution norms produces messier configurations.

**Mutable topology with versioning.** Rejected: the privilege-escalation surface is too large. The migration path is the right safety property.

**Per-agent admission policy stored in the registry rather than declared topology-wide.** Rejected: makes the swarm's identity and reasoning opaque to participants. Topology is operator policy that participants consent to by joining; it must be visible and stable.

**Topology as part of constitution.** Rejected, see §2.

**A single AdmissionPolicy struct with all fields optional.** Rejected: invites incoherent combinations. Oneof + variant types is more verbose but structurally guarantees consistency.

## 10. Open questions for RFC review

- Default proof-of-work difficulty: 22 is a reasonable noise filter; should we ship higher (26+) to make small-scale sybil meaningfully expensive? Tradeoff is barrier to legitimate hobbyist participation.
- IdP attestation accepted_formats: should the spec enumerate (OIDC, SPIFFE, DID) or remain free-form strings? Currently free-form for extensibility.
- StakeRequirement: should slashing be platform-defined (with a standard slashing-receipt action_kind) or operator-defined (with a slashing endpoint)? Currently the latter; revisit if multiple stake-using deployments converge on common patterns.
- Hybrid `periphery_may_delegate=true` — should chain depth be globally bounded or separately bounded for periphery? Currently global; may need separate-bound if periphery-delegation patterns warrant.
- Topology migration receipts: what's the canonical "topology.migrate_from_v1" / "topology.migrate_to_v2" pattern? Need spec'ing before any production deployment migrates.

## 11. Future evolution

- v1.1 may add a federation-aware mode (TOPOLOGY_MODE_FEDERATED) once Phase 4 federation lands.
- v1.x may add platform-standard slashing semantics if stake-based deployments converge.
- v2.0 may revisit whether topology can have a controlled mutation path (e.g., loosening periphery constraints, but never tightening core authority) — only if real operational demand justifies the security review.

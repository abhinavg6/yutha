# Capability Spec — Design Rationale

> **Spec:** [`capability-v1.proto`](./capability-v1.proto)
> **Version:** v1.0 draft
> **RFC:** 0005
> **Threat-model linkage:** A1 (hostile agent), A3 (prompt injection — primary defense), A6 (sybil), A8 (malicious operator partial), A9 (compromised supervisor)

## 1. What is a capability, in one paragraph

A capability is an authority token: a signed, attenuable, expiring credential that says "the holder is permitted to perform actions matching this scope, under these caveats, in this swarm." Capabilities are minted by issuers (operators, the control plane on registration, supervisors, or other capability holders via attenuation). Every action in Yutha — sending an envelope to a particular recipient, writing memory in a particular scope, calling a particular tool — is gated by a capability check. There is no ambient authority. If an agent is convinced via prompt injection to attempt an action it does not have a capability for, the check fails and the action does not happen. This is the structural defense against A3 that the rest of the system relies on.

## 2. Why this shape

Three decisions structure the design:

- **Macaroon-style attenuation, not OAuth-style scopes.** A held capability can be attenuated — narrowed, never broadened — into a child capability that the holder gives to a delegate. The child references the parent by content-address; the verifier walks the chain to a root. This makes delegation safe by construction: the child cannot exceed the parent. Delegating is a local operation that does not require contacting the issuer.

- **Caveats over policy languages.** Capabilities are decidable on their own — a check is a finite walk over scope and caveats. Constitution norms (Cedar+) live one layer up; a constitution may *require* a capability for an action, but the capability itself is not a Cedar+ predicate. Keeping these layers separate keeps both decidable and keeps the security boundary small.

- **Default-deny, surfaced denials.** Every denied check produces a `capability.check.deny` receipt with the deny reason and the unmet caveats. There is no silent failure. PRD §13.2: "Default-deny on ambiguity. When norms are silent, the system errs toward inaction and surfaces the decision."

## 3. Field-by-field rationale

**`spec_version`.** First.

**`capability_id` vs. content-address.** Two identifiers, same pattern as envelope/passport. capability_id (UUID v7) is for revocation lookup — the revocation list keys on it. Content-address is for parent pointers and tamper detection.

**`swarm_id`.** Single-swarm, like every other Phase 1 artifact. Cross-swarm capabilities are Phase 4 federation constructs.

**`issuer` (oneof).** Three issuance paths:
- **Agent**: an existing capability holder attenuates and delegates. The most common path for in-swarm delegation.
- **Operator**: an operator key mints a fresh root capability. The bootstrap path; operators are the trust roots.
- **Control plane**: the platform itself mints capabilities for things like "agent X has just registered, here is the basic-membership capability." Distinct issuer kind because audits care: a control-plane-issued capability is platform-policy; an operator-issued one is human-policy.

**`subject` (AgentId).** Tightly bound. The agent presenting the capability MUST sign their action envelope with the key whose fingerprint matches the subject's passport. Capability + envelope-signature together establish authority.

**`scope`.** Multi-dimensional: action kinds, resource tags, numeric bounds, recipient constraints, memory scopes. Empty list means "all" for that dimension, but operators are strongly discouraged from leaving dimensions unbounded — every empty list is a deny-by-default escape hatch the operator opens deliberately. Conformance tests verify that empty-list root capabilities require an explicit `unrestricted_actions` extension flag, so they cannot be created accidentally.

Attenuation semantics: a child's effective scope is `parent.scope ∩ child.scope`. The intersection is computed dimension by dimension. The child can only narrow, never broaden. The conformance suite tests this property exhaustively (you cannot escalate via attenuation).

**`parent`.** Content-address of the parent capability for attenuated children. Empty for root capabilities. Verifiers walk this chain to a root; the chain length is bounded (default max depth 8, configurable via topology) to prevent attack-via-deep-chain.

**`valid_from`, `valid_until`.** Both required. valid_until MUST be set; the spec does not permit non-expiring capabilities. Long-lived capabilities are revoked-then-reissued, not held indefinitely. Default maximum lifetime is 90 days, configurable in topology, with shorter defaults strongly recommended for production.

**`caveats`.** Typed, closed vocabulary at v1.0. Six caveat kinds:
- TimeOfDayCaveat: business-hours-only, on-call-only, etc.
- ConstitutionVersionCaveat: the capability is valid only under specific constitution versions.
- SupervisorRequiredCaveat: the action requires a supervisor countersign on the resulting receipt (two-person rule).
- RateLimitCaveat: bounded number of actions per window.
- OnlyIfTaggedCaveat / NeverIfTaggedCaveat: conditional on resource tags.

The set is closed because each caveat type is something the control plane has to evaluate at every check; new caveat kinds are an attack surface and require RFC consideration. Constitution-defined arbitrary conditions live in the Cedar+ layer, not as caveats.

**`revocation_endpoint`.** Optional. A URL (or other resolver) where verifiers can check revocation status. The authoritative source of truth is `capability.revoke` receipts in the receipt store; the endpoint is an optimization for backends that want to publish a CRL-like resource. Implementations MUST treat the receipt store as authoritative even when the endpoint disagrees.

**`extensions`.** Forward-compatibility hatch.

**`signatures`.** ISSUER required. ATTESTATION optional for verifiable tier.

## 4. Threat-model linkage

| Adversary | How this spec contributes to mitigation |
|-----------|------------------------------------------|
| A1 Hostile agent | Per-agent quotas via RateLimitCaveat; resource-bound capabilities cap blast radius; revocation provides quick removal of authority without removing the agent. |
| A3 Prompt injection | The structural defense. No ambient authority means every prompt-injected action attempt encounters a capability check; the check denies anything the agent's capabilities don't already permit. Combined with envelope's typed performatives, prompt-injected escalation is contained at the substrate. |
| A6 Sybil | Open-mode swarms can require capabilities issued only after costly registration; reduces leverage of mass-registered identities. Hybrid mode periphery agents get reduced capabilities by default (topology spec). |
| A8 Malicious operator (partial) | Operator can mint and revoke capabilities, but every mint and revoke produces a receipt; the receipt fabric makes operator-side authority changes auditable. The operator cannot silently delegate authority. |
| A9 Compromised supervisor | SupervisorRequiredCaveat on high-stakes capabilities forces two-person rule; the supervisor's countersign produces a receipt that envelope detection can monitor. |

## 5. Conformance hooks

A conformant capability implementation:

- **Issue.** Accepts IssueRequest; verifies issuer signature; persists to the capability store; produces `capability.issue` receipt; returns content-address.
- **Attenuate.** Accepts AttenuateRequest; verifies parent exists and is held by requester; computes intersected scope; refuses any attempt to broaden; produces `capability.attenuate` receipt.
- **Revoke.** Accepts RevokeRequest; produces `capability.revoke` receipt; subsequent checks against the revoked capability MUST deny within the spec'd revocation propagation window.
- **Check.** Accepts CheckRequest; walks the parent chain; computes effective scope; evaluates all caveats; produces `capability.check.pass` or `capability.check.deny` receipt with explicit deny_reason and matched/unmet caveats.
- **Send-path enforcement.** When the swarm's `Topology.require_capability_for_send` is true, `EnvelopeService.Send` invokes the same `Check` pathway with an `ActionDescriptor` synthesized from the envelope (action_kind `envelope.send`; evidence carrying recipient, performative, payload_schema_id, tags). A deny rejects the send with `PERMISSION_DENIED`; a pass proceeds to delivery. Either way a check receipt lands in the audit trail. See RFC 0007.
- **Default-deny.** Empty fields and ambiguous match conditions deny rather than permit.
- **Bounded chain depth.** Refuses to walk parent chains beyond the configured maximum (default 8).
- **Tamper detection.** Capabilities whose content-address (after re-canonicalization) does not match the recomputed hash are rejected.

`/conformance/interface/access-control/` contains the test cases; the Verifiable tier additionally tests cross-org capability mutual-recognition (Phase 4).

## 6. Why content-addressed parent pointers

Alternatives considered: capability_id pointer (the macaroon model), nested-bytes inclusion (the JWT chained-token model), URN identifiers.

Content-address won because it makes attenuation auditable and tamper-evident. The parent's hash is in the child; if the parent is altered after attenuation, every child's parent pointer dangles and the chain breaks. This means attenuation chains have the same integrity property as receipt chains — you cannot retroactively rewrite an authorization without invalidating every delegation that descended from it.

## 7. Why caveats are typed and closed

Caveats look superficially like "predicates" (small Boolean expressions). The temptation to allow arbitrary predicates is real. We resist it for the same reason the constitution language uses Cedar instead of Lua: the security boundary is the static analyzer's ability to prove things about the policy, and a Turing-complete caveat language destroys that property.

Six caveat types covers the canonical use cases. New caveats go through RFC. Operators that need richer conditions move them up into the Cedar+ constitution, where the analyzer can prove them safe.

## 8. Capability lifetime and rotation

Default maximum lifetime is 90 days. Production deployments are encouraged to use much shorter lifetimes (hours to days) for capabilities granting consequential authority. Two reasons:

- **Compromise window.** A leaked capability is valid until expiry. Short lifetimes shrink the window.
- **Revocation propagation cost.** Revocation receipts must propagate to verifiers; short lifetimes naturally bound the consistency requirement.

For long-running capabilities (e.g., "this agent is a member of this swarm"), the pattern is to issue a short-lived authority and refresh it on a heartbeat — refresh produces an `agent.heartbeat.missed` receipt if the agent goes silent and a fresh capability when it returns.

The spec does not enforce these patterns; it provides the primitives that make them implementable.

## 9. Alternatives considered

**OAuth 2.0 scopes.** Rejected: server-side trust required for every check; no attenuation; not suited for in-swarm delegation between agents.

**JWTs with embedded claims.** Considered. JWTs lack attenuation natively; chained-JWT proposals (e.g., JWT-Chain) exist but ergonomics are poor. Macaroon model is cleaner.

**Pure macaroons.** Considered closely. Macaroons use cryptographic chaining with HMAC; we use signature-chained content-addressed messages because (a) signatures are publicly verifiable without shared secrets, which matters for federation; (b) content-addressing integrates naturally with the receipt fabric; (c) the conformance suite can verify chain properties bytewise.

**Capability tokens stored entirely in-database with database-keyed identifiers.** Rejected: breaks federation portability, requires trusting the database operator for authority decisions, and makes cross-store mutual recognition impossible.

**Bidirectional capabilities (subject can also revoke their own).** Considered. Allows agent to "drop" an authority they no longer need. Currently not in v1.0 — modeled as agent-initiated `capability.revoke` issued by the subject's own attenuator chain. May add as a v1.1 helper if usage warrants.

## 10. Open questions for RFC review

- Default maximum chain depth: 8 chosen somewhat arbitrarily. Need to validate against real attenuation patterns from design partners.
- Default capability lifetime: 90 days as a maximum is chosen to be permissive enough not to surprise operators; should we tighten to 30 days as a hard ceiling?
- ControlPlaneIssuer: is the instance_id useful or noise? It helps observability but adds a non-cryptographic field to the trust surface.
- Caveat composition: caveats are AND-composed (all must pass). Should we add an explicit OR construct? Probably no — operators that need OR can issue multiple capabilities.
- Cross-issuer capabilities (multi-issuer signatures, e.g., "requires both operator A and operator B to sign"): should this be in v1.0? Currently no; deferred to a later RFC.

## 11. Future evolution

- v1.1 likely adds a `capability.transfer` operation (subject changes from A to B) for delegated identity scenarios.
- v1.x adds attestation integration for verifiable-tier capability issuance (Nautilus binding).
- v2.0 may revisit the issuer model if Phase 4 federation requires multi-org joint issuance.

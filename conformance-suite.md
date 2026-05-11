# Concord Conformance Suite

> **Repo location:** `/docs/conformance/conformance-suite.md`
> **Version:** v0.1 (working draft)
> **Status:** Initial design; finalized scope required before Phase 1 freeze
> **Owners:** Workstream A (Specs), with co-ownership across Workstreams B, C, D, E (each responsible for their interface's sub-suite)

## Purpose

The conformance suite is the artifact that lets multiple implementations of Concord — different backends, different transports, different attestation layers, eventually different control planes — coexist as part of one ecosystem.

It exists because **pluggable backends without a conformance suite is just marketing.** With a conformance suite, the equal-access goal (PRD Section 3.2) becomes structural: anyone can ship a backend that passes the suite, and operators can swap backends without changing observable behavior.

It also exists to make the platform-vendor-capture defense (PRD Section 21.1) credible. A vendor-hosted version of Concord that doesn't pass the same conformance suite as the open-source reference is, definitionally, not Concord. The suite is what gives that statement teeth.

## What conformance means

A backend or component is **conformant** at a stated level if it:

- Implements every required operation in the relevant spec
- Produces the specified behavior for every test case at that level
- Meets the performance and security SLAs declared at that level
- Documents which optional capabilities it does and does not implement

**Conformance is observable equivalence, not implementation equivalence.** Two memory backends can use entirely different storage technology and conform if they produce the same observable behavior to the swarm.

## Audiences

| Audience | Question they're answering |
|----------|----------------------------|
| Backend implementers | "What do I need to test to claim compliance?" |
| Operators choosing backends | "Which backend stacks are guaranteed to work together?" |
| Security reviewers | "What's actually verified about this implementation?" |
| The foundation | "Is this implementation eligible for the conformance mark?" |

## Conformance levels

Each pluggable interface has tiered conformance. A backend declares which level(s) it claims; the suite verifies the claim.

| Level | What it covers |
|-------|----------------|
| **Core** | Minimum viable. Required operations, basic correctness, default failure modes. The floor for any backend that wants to call itself Concord-compliant. |
| **Full** | Core + all optional operations + concurrency + full failure-mode coverage. The level expected of production-grade backends. |
| **Verifiable** | Full + cryptographic verifiability properties. Required for backends claiming the verifiable stack. |
| **Constrained-transport** | Full + intermittent-connectivity properties. Required for transports claiming field-deployment support. |

A backend can claim any combination consistent with what it implements. A registry might claim Core + Verifiable; a transport might claim Full + Constrained-transport; a memory backend might claim Full only.

## Suite structure

The suite is organized into five top-level categories:

```
/conformance
├── /interface              # Per-interface sub-suites (isolation tests)
│   ├── registry/
│   ├── memory/
│   ├── receipts/
│   ├── transport/
│   ├── access-control/
│   └── attestation/
├── /language               # Constitution language conformance
│   ├── cedar-plus-semantics/
│   ├── static-analyzer/
│   └── authoring-pipeline/
├── /behavioral             # Cross-component integration scenarios
│   ├── queue-mode/
│   ├── campaign-mode/
│   ├── federation/
│   └── constrained-network/
├── /performance            # SLA tests
└── /security               # Threat-model adversary tests
```

Each category is described below.

---

## Interface conformance

Each pluggable interface has an isolated sub-suite. Tests run against the candidate implementation with mocked peers and a controlled environment, so failures unambiguously attribute to the implementation under test.

### Registry conformance

**Core (required for any registry implementation):**

- Register agent with valid passport → succeeds, returns agent ID and registration receipt
- Register with invalid signature → fails closed; no partial state
- Register duplicate agent ID → fails per spec (no silent overwrites)
- Lookup by ID returns the registered passport with cryptographic integrity preserved
- Lookup of non-existent ID returns null per spec (not an exception)
- Capability assertion returns true for declared capabilities, false for undeclared
- Revocation of an agent → subsequent lookups reflect the revocation atomically
- Concurrent registrations of distinct agents all succeed
- Simultaneous registration of the same ID → exactly one succeeds; the other receives the spec'd error

**Full (additional):**

- Bulk operations are transactional (all-or-nothing)
- Listing supports pagination, filtering, ordering per spec
- Capability updates produce receipts and are observable in subscribers
- Heartbeat and liveness semantics work end-to-end

**Verifiable (additional):**

- Passport signatures are verifiable against published public keys without trusting the registry operator
- Registration produces a verifiable claim retrievable by third parties
- Revocation is mutually recognizable across federation peers
- Registry state is auditable end-to-end without operator cooperation
- Cryptographic chain allows external reconstruction of registration history

### Memory conformance

For both per-agent and shared tiers:

**Core:**

- `put(key, value, scope, ttl, tags)` followed by `get(key)` returns the value with metadata intact
- `put` with TTL → `get` after TTL returns null
- `put` with scope tag → access from outside scope is denied at the backend, not just the wrapper
- `search(query, filter, limit)` returns items matching filter, respecting access control
- `forget(key)` → subsequent `get` returns null; the deletion is durable
- `export(scope)` returns all items in scope with manifest

**Concurrency:**

- N parallel puts of distinct keys all succeed
- Last-writer-wins on conflicting puts (default consistency model)
- Subscribers receive notifications for matching writes within the spec's latency bound
- No torn reads under concurrent put + get on the same key

**Privacy:**

- Per-agent memory of agent A is not visible to agent B
- Shared memory respects scope tags from the active constitution version
- `forget` cascades to subscribers and updates indices atomically

**Vector/semantic capabilities (optional, claimed separately):**

- Semantic search returns items in score order
- Filter combined with semantic search applies both correctly
- Embedding model identification is recorded in receipts so retrieval is reproducible

**Verifiable (additional):**

- All writes produce attestable claims with cryptographic provenance
- `forget` on immutable backends produces a redaction event with selective-disclosure semantics (the platform is honest about what is and is not deletable)
- Cross-org memory federation respects declared export scope and revocation

### Receipt store conformance

**Core:**

- Append a receipt → it's retrievable by ID and by causal predecessor
- Receipts are content-addressed (identical content → identical ID)
- Tamper detection: any modified receipt fails signature check
- Sequential append is durable across process restart
- Concurrent appends preserve causal ordering where causal metadata is present
- Query by causal predecessor returns the consistent set of children

**Full (additional):**

- Range queries by time, agent, swarm work per spec
- Bulk export produces a verifiable manifest
- Retention policies are enforced (with configurability per deployment)

**Verifiable (additional):**

- Receipts are mutually recognizable across organizations using only public keys
- Cryptographic chain enables cross-store verification without trusting either operator
- Receipt batches can be sealed (Merkle-rooted) for efficient verification at scale
- Selective-disclosure proofs allow revealing a single receipt without revealing the rest of the chain

### Transport conformance

Per profile (datacenter, WAN, constrained), in addition to common requirements.

**Common (all profiles):**

- `send(message)` → `receive(message)` at recipient with envelope intact
- Causal metadata preserved through transport
- Encryption applied per profile spec; channels are identity-bound where the registry supports it
- Replay attempts are detected and rejected
- Dropped messages are detected (at-least-once delivery semantics by default)
- Backpressure is signaled, not silently dropped

**Datacenter profile:**

- p99 routing latency under 100ms in-region for swarms of up to 100 agents
- Throughput supports the spec'd ops-per-second floor
- TLS configuration meets the platform crypto baseline

**WAN profile:**

- Retry / backoff under variable latency converges
- Behavior under brief partitions (< 30s) is graceful
- p99 routing latency under 500ms across regions

**Constrained-transport (additional, claimed separately):**

The hardest sub-suite, because the failure modes are subtle.

- 50% packet loss sustained for 5 minutes → all writes eventually sync; no permanent loss
- 80% partition windows → bounded local autonomy is respected (agents act only within declared scope)
- 10 kbps sustained bandwidth cap → no operation starves; cost-aware routing prevents pathological behavior
- One-hour partition → reconvergence produces deterministic, consistent state
- Conflicting writes during partition → conflict-free merge produces a deterministic, observable outcome
- No silent receipt loss under any failure pattern in the test set
- Sync failures are surfaced to operators within the spec'd time bound

### Access control conformance

**Core:**

- Capability tokens are unforgeable (signature verification rejects modifications)
- Token expiry is enforced
- Token attenuation (delegation with reduced scope) is enforced
- Revocation is observable within the spec'd propagation bound
- No ambient authority; every operation requires an explicit capability check

**Verifiable (additional):**

- Capability chains are auditable end-to-end
- Cross-org delegation produces verifiable attestation
- Revocation is cryptographically detectable across federation peers

### Attestation conformance (optional layer)

For backends claiming attestation support:

- Attestations bind a decision to the inputs and the agent making it
- Attestation verification is possible without trusting the producer
- Attestation chains support reconstruction of decision provenance
- Attestation forgery is cryptographically detectable

---

## Constitution language conformance

The Cedar+ evaluator and authoring pipeline have their own conformance sub-suite. This is large because policy semantics is where logic bugs hide.

### Cedar+ semantic tests

Hundreds to thousands of test cases, organized by feature:

- **Hard constraints (forbid).** Empty constitutions; single forbid; conflicting forbids; nested unless; principal-action-resource matrix coverage.
- **Permits.** Basic permit; permit with conditions; permit with unless; default-deny when no permit matches.
- **Soft preferences (prefer).** Single prefer; multiple prefers ordered by score; prefer interaction with permit / forbid.
- **Memory norms.** Per-tier access; scope enforcement; tag-based norms; cascade on forget.
- **Resource budgets.** Budget-conditional permits; budget exhaustion; budget restoration semantics.
- **Procedures.** State machine transitions; timeout handling; escalation paths; nested procedures.
- **Temporal expressions.** Comparisons against passed-in clock; quarantine windows; TTL-conditional rules.
- **Edge cases.** Empty constitution; circular references rejected; self-modifying rules rejected; deeply nested unless.

### Static analyzer tests

The analyzer is the security boundary; its conformance matters more than most.

- Rejects programs with loops or recursion
- Rejects programs with side effects
- Rejects programs exceeding statically-bounded depth
- Rejects programs with unbounded data structures
- Accepts every valid program in the canonical examples library
- Identifies ambiguity (multiple valid interpretations) and surfaces it

### Authoring pipeline tests

For the LLM-assisted plain-English layer:

- Plain English → Cedar+ produces structurally valid output for the canonical example set
- Generated test cases cover the scenarios claimed in the English source
- Diagnostic mode correctly flags ambiguous English
- Round-trip: hand-edited Cedar+ → re-display in English layer is consistent
- Failure mode: when English cannot be cleanly compiled, the tool fails loud rather than producing an unsafe predicate

The LLM authoring layer is **not a security boundary** (the static analyzer is), so its conformance is about UX consistency, not safety. A backend that ships a worse LLM authoring tool can still be conformant; it just has worse DX.

---

## Behavioral conformance

Cross-component integration tests. These prove that a particular backend stack produces the right swarm-level behavior, not just that each component passes its interface suite.

This is the most expensive part of the suite to run, but the most important for proving observable equivalence across stacks.

### Reference scenarios

Each scenario runs a complete swarm against the candidate backend combination and verifies swarm-level invariants.

**S1. Customer-support queue mode (Phase 1 anchor scenario).** Five agents from two frameworks; queue of 1,000 tickets; supervisor; full memory access; norms over PII. Pass criteria: all tickets resolved or escalated correctly; all consequential actions produced verifiable receipts; no unauthorized memory access; behavior identical (within tolerance) to the reference stack.

**S2. Insurance due-diligence pipeline (Phase 2 queue-mode anchor).** Ten agents; 500 claims; affinity rules; peer consultation; role-scoped memory; SLA tracking. Pass criteria: SLA met or accurately reported as missed; affinity rules respected; medical-info access norms enforced.

**S3. Security incident response (Phase 2 campaign-mode anchor).** Eight investigator agents; injected adversary scenarios from the threat model; supervisor approvals required for production actions. Pass criteria: hard-rule violations detected within one tick; coaching reduces repeat violations; no production action without supervisor approval.

**S4. Disaster response with constrained transport (Phase 3 anchor).** Twenty-five agents (mix of software and drone-mounted); simulated network with packet loss and partition windows; federated across two organizations. Pass criteria: bounded local autonomy respected; reconvergence produces consistent state; no receipt loss; cross-org receipts mutually recognized.

**S5. Federated multi-org delivery network (Phase 4 anchor).** Three swarms with different constitutions; shared subset of norms; bad-actor agent in one swarm. Pass criteria: federation handshake succeeds; bad-actor agent is detected and quarantined; clean detachment after the joint operation.

### Differential conformance

A particularly important pattern: run S1–S5 on both the candidate stack and the reference stack with identical inputs, and verify that **observable swarm behavior is equivalent** within stated tolerances. This is the single strongest test that a candidate implementation is genuinely substitutable.

Tolerances must be specified explicitly. Some are exact (every receipt must exist, every signature must verify); some are bounded (latency within X percent of reference); some are statistical (decision distribution within Y standard deviations).

---

## Performance conformance

SLA tests with stated load profiles. These are not the place to set ambitious performance goals; they are the floor below which a backend cannot fall.

| Operation | p99 target | Notes |
|-----------|-----------|-------|
| Message routing (datacenter) | < 100 ms | Up to 100 agents, in-region |
| Message routing (WAN) | < 500 ms | Cross-region |
| Receipt write | < 250 ms | Default backend; verifiable backends may have a separate target |
| Memory get / put (KV) | < 50 ms | Default backend |
| Memory search (semantic) | < 200 ms | Vector-capable backend |
| Constitution evaluation | < 10 ms | Per decision; bounded by static depth |

Targets are revisited as the suite matures and real backends generate benchmark data. Phase 1 ships with placeholder targets; Phase 2 fixes them.

## Security conformance

Targeted tests per adversary in the threat model (`/docs/security/threat-model.md`).

For each of A1 through A9:

- A scripted attack exercising the adversary's claimed capabilities
- Verification that the documented mitigations fire
- Verification that residual risk is no worse than claimed
- A red-team test where the adversary attempts to escape the documented capability bounds

These tests are co-developed with Workstream L. Results are reviewed by the foundation's security working group before any conformance mark is issued.

## How conformance is run

- **Reference test runner.** A canonical runner ships in the project repo. Backends declare claimed levels; runner executes the appropriate subsets; produces a signed report.
- **Self-attestation.** Vendors may run the suite and publish results themselves. Self-attested results carry a different visual treatment than foundation-verified results.
- **Foundation verification.** For the conformance mark, the foundation runs the suite against the vendor's submitted artifact in a controlled environment. Results are published in a public registry.
- **Continuous conformance.** Conformant backends commit to running the latest suite against every release. Falling out of conformance triggers loss of the mark.

## The conformance mark

The conformance mark is what users see. It indicates:

- The level(s) at which the backend is conformant
- The suite version it was last tested against
- The date of last verification
- Whether verification was self-attested or foundation-verified

The mark is revocable. Misrepresentation of conformance is grounds for revocation and (for foundation-verified marks) public advisory.

## How the suite evolves

- **Test additions** follow the RFC process. New tests must be backwards-compatible with existing claims at older spec versions; a backend conformant at suite v1.0 must remain conformant at v1.1 unless the v1.1 changes were explicitly breaking and version-bumped accordingly.
- **Test deprecation** requires explicit replacement. No test is removed without a successor that covers the same property.
- **Suite versioning** follows semver: major version bumps signal breaking changes; minor versions add tests; patch versions fix bugs in existing tests.
- **Backwards compatibility window.** Backends have at least 12 months to retest against a new major suite version before the older suite version is retired.

## Open design questions

These are resolved during Phase 1, before the suite is published as a stable artifact.

- **Test runner language.** Rust (matches core) vs. polyglot (lower contributor barrier). Leaning Rust for the runner core with adapters for vendor-provided backends in any language.
- **How are vendor backends submitted?** Container images, source builds, or running endpoints? Probably all three with different verification depth per submission type.
- **Tolerance specification language.** How are statistical-equivalence tolerances declared? Bespoke vs. existing property-test framework. Defer.
- **Performance test environment normalization.** Different hardware produces different results. Either we standardize the test environment (cloud instance type), provide a normalization model, or report results per-environment. Probably a hybrid.
- **Cost.** Running the full behavioral suite is expensive (long-running, requires multiple agents, network simulation). The foundation needs a sustainable funding model for verification-as-a-service.
- **Conformance for the control plane itself.** This document covers backends and language. A separate sub-suite for alternative control-plane implementations (if any ever emerge) is a Phase 4 question.

## How this document evolves

Major changes to suite design follow the RFC process. The suite itself is a living artifact in `/conformance/`; this document explains *why* it is structured the way it is, and is updated when that rationale changes.

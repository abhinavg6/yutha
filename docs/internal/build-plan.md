# Yutha Build Plan

> **Repo location:** `/docs/internal/build-plan.md`
> **Version:** v0.2 (working draft)
> **Status:** Synthesizes the PRD v0.1, ADR 0001 (language choice), threat model v0.1, Cedar+ design v0.1, and conformance suite v0.1. Reflects the Concord → Yutha rename and the deferred-foundation governance posture.
> **Naming note:** the project is being renamed from **Concord** to **Yutha** (Sanskrit *यूथ*, "a coordinated swarm or flock"). This document uses the new name throughout. The cross-document rename across the PRD, threat model, ADR 0001, the constitution-language design doc, and the conformance suite is held until trademark clearance returns; asset namespaces (domains, GitHub org, package registries, social handles) are being locked immediately.
> **Owners:** Cross-workstream; primary maintainer Workstream A (Specs)

---

## 1. Purpose and how to read this document

This document is the synthesis layer between the strategic intent in the PRD and the four foundational design artifacts (`0001-language-choice.md`, `threat-model.md`, `constitution-language.md`, `conformance-suite.md`). It is not a replacement for any of them. It is the plan-of-record for *how Yutha gets built* — what is constructed in what order, by which workstream, gated by which conformance level, and defending against which adversaries.

If the PRD answers "what are we building and for whom?", this plan answers "how do we ship it without losing the load-bearing properties?"

A reader's path:

- A workstream lead reads §4 (architectural commitments), §5 (workstream blueprint), §6–§9 (their phase chapters), and §10 (conformance gating).
- A community contributor reads §2 (north star), §3 (artifact layout), §10 (conformance as credibility), and §13 (governance posture).
- A new contributor reads §3 and §5, then jumps to the design doc relevant to their workstream.

---

## 2. North Star

Yutha serves two first-class user journeys, not one. Both must be approachable; both must be possible without distributed-systems expertise.

**Joining a swarm.** A non-engineer or technical builder can take an agent built in any popular framework and bring it into a working, governed, observable swarm in under fifteen minutes.

**Initiating a swarm.** A small technical team can stand up a new swarm — with their own initial agents, their own constitution, and the topology of their choice — in under thirty minutes, end to end, on infrastructure they own.

**Topology is the operator's choice.** Every swarm declares one of three participation modes at creation, and the registry, capability, and constitution layers honor that choice as a first-class property:

- **Closed (trusted-only).** Membership is restricted to a known list of agents or a known set of operator-vetted credentials. Internal SOC swarms, single-org support swarms, regulated-domain swarms. Registration is operator-gated; no agent joins without explicit approval.
- **Open (public participation).** Any agent meeting registration criteria — passport schema, capability declarations, constitution acceptance — can join. Public coalitions, research consortia, hobbyist swarms. The constitution and the conformance bar replace operator gatekeeping.
- **Hybrid (trusted core, open periphery).** A trusted core of operator-approved agents, plus an open periphery whose members have reduced capabilities or scoped memory access by default. Disaster-response coalitions, multi-tenant developer platforms.

**The shared invariant across all three modes:** every swarm produces a complete, signed, verifiable record of what it did, on backends the operator chose. That sentence is the entirety of the success condition. Every architectural decision that does not serve it — for either user journey, in any topology mode — is suspect.

Three corollaries shape every build choice:

- **Specs are the product.** The reference implementation proves the specs run. Other implementations adopting the spec is a win, not a threat. The conformance suite is what makes "implementing the spec" a verifiable claim rather than a marketing one.
- **The load-bearing wall is receipts.** Phase 1 ships the trace and receipt system before anything else, because every later capability — enforcement, observability, federation, audit — depends on it. If the receipt fabric is wrong, nothing on top of it is salvageable.
- **Trust boundaries are language boundaries.** The components inside the trust boundary are written in Rust. Components that hold no privileged state (SDK adapters, the visual composer, some adapters and tooling) are written in the language of the runtime they live in. ADR 0001 is the policy; this plan is its operational consequences.

---

## 3. Repository and artifact layout

A single mono-repo with a clear public surface, plus one separately-tracked spec/RFC repo so that spec evolution is auditable on its own timeline. The proposed layout:

```
yutha/
├── /spec                  # Versioned wire & artifact specs (separately versioned)
│   ├── passport/
│   ├── envelope/          # Typed message envelope + performatives
│   ├── receipt/
│   ├── capability/
│   ├── topology/          # Closed / open / hybrid swarm-mode declarations
│   └── constitution/      # Cedar+ schema + canonical schemas
├── /docs
│   ├── /decisions         # ADRs (0001-language-choice.md, …)
│   ├── /design            # constitution-language.md, …
│   ├── /security          # threat-model.md, sub-models per subsystem
│   ├── /conformance       # conformance-suite.md
│   ├── /community         # CONTRIBUTING.md, RFC process, code of conduct
│   └── build-plan.md      # this document
├── /crates                # Rust workspace — the trust-boundary code
│   ├── yutha-core/        # shared types, errors, causal metadata
│   ├── yutha-crypto/      # signing, hashing, content addressing (wraps `ring`)
│   ├── yutha-receipt/     # store, append, query, content-address
│   ├── yutha-passport/    # identity & capability declarations
│   ├── yutha-transport/   # wire framing, gRPC, NATS adapter
│   ├── yutha-registry/    # membership controller (closed / open / hybrid modes)
│   ├── yutha-capability/  # token mint, attenuate, revoke, verify
│   ├── yutha-memory/      # per-agent + shared memory core
│   ├── yutha-cedar-plus/  # Cedar+ compiler, static analyzer, evaluator
│   ├── yutha-enforcement/ # detect → coach → quarantine → evict loop
│   ├── yutha-supervision/ # supervision trees
│   ├── yutha-control-plane/ # binary that wires the above
│   └── yutha-conformance/ # runner core
├── /backends              # Pluggable backend reference impls
│   ├── postgres-receipt/
│   ├── s3-blob/
│   ├── nats-transport/
│   ├── redis-streams-transport/
│   ├── walrus-receipt/    # verifiable-tier reference
│   ├── seal-encrypt/      # verifiable-tier reference (encrypted memory)
│   └── nautilus-attest/   # verifiable-tier reference (attestation)
├── /sdk
│   ├── python/            # adapters for LangGraph, AutoGen, CrewAI, Agent SDK
│   └── typescript/
├── /sim                   # Phase 3
│   ├── runtime/           # Rust; deterministic clock; same control plane
│   └── adversaries/       # one per A1–A9
├── /composer              # Phase 3 web UI (TypeScript)
├── /conformance           # The suite proper (test cases, scenarios)
│   ├── interface/
│   ├── language/
│   ├── behavioral/
│   ├── performance/
│   └── security/
└── /examples              # Quickstart, fifteen-minute path, reference swarms
```

The spec directory is *separately versioned*. A spec change can ship before the reference implementation catches up; backwards compatibility windows are governed by §13 of the PRD.

---

## 4. Architectural commitments that shape everything

Eight commitments are load-bearing across every workstream. They are not negotiable inside a phase; changing one requires an ADR and supersession.

**4.1 Receipts before everything else.** No component in any phase ships without producing receipts for its consequential actions. Workstream C builds the receipt crate first, in Phase 1, and every other crate consumes it. Tests gate on receipt completeness.

**4.2 Specs first, code second.** Every public surface ships a spec doc *before* the reference implementation merges. Passport, envelope, receipt, capability, topology, and constitution schemas live in `/spec` and are versioned independently of crate code. This is what makes the framework-neutrality and pluggable-backend goals enforceable.

**4.3 Pluggable backends behind stable interfaces, conformance-gated.** Every backend interface has a Rust trait, a default implementation, and a conformance sub-suite. Backends are interchangeable; conformance is the substitutability proof. The verifiable tier (Walrus + Seal + Nautilus) lives behind the same interfaces as the default tier — flipping config, not changing API.

**4.4 Rust core, polyglot edges.** Per ADR 0001: the crates listed under `/crates` are Rust. SDKs are the runtime's native language. Backends are Rust or Go (Rust preferred for security-critical paths). The composer is TypeScript. The boundary is clear and is enforced at code-review time.

**4.5 Cedar+ is canonical; LLM authoring is not a security boundary.** The Cedar+ static analyzer is the security boundary — it rejects programs with loops, side effects, or unbounded computation regardless of whether they came from an LLM or a human. The LLM authoring tool is a UX convenience; its output is reviewed by the analyzer like any other input. Runtime evaluation never invokes the LLM.

**4.6 Default-deny, fail-safe, reversible-before-irreversible.** Ambiguous capability evaluation denies. Every enforcement step has a reverse path until the last (eviction). Every escalation produces a receipt. Quarantine before eviction; coaching before quarantine; detection before coaching. Build-time test cases prove this for each enforcement transition.

**4.7 No proprietary protocols, no telemetry phone-home, no required SaaS.** Everything on the wire is gRPC + protobuf with public schemas. The open-source path runs entirely self-hosted with embedded Postgres + NATS + S3-compatible blob. Build infrastructure has no third-party scripts in CI (per threat-model A7 mitigations).

**4.8 Causal metadata on every message from message zero.** The DAG is emitted, not reconstructed. Every envelope carries causal predecessors. Every receipt links by content-address. This is what makes counterfactual replay (Phase 3) possible without retrofitting; retrofitting it later is the kind of decision that destroys the whole audit story.

**4.9 Topology mode is a property of the swarm, not a separate product.** Closed, open, and hybrid swarms run the same control plane and the same conformance suite. The differences live in the registry's admission policy, the constitution's amendment quorums, and the capability tier defaults. Building one well means building all three well.

---

## 5. Workstream blueprint

Eight workstreams, mapped from PRD §18, plus a security workstream (L) called out throughout the threat model and Cedar+ design doc. Each is a charter, not a team-shape — staffing is in §14.

### Workstream A — Specs

**Charter:** authors and maintains the launch specs (passport, envelope, receipt, capability, topology) plus the Cedar+ schema spec. Owns the public RFC repo and process. Owns the conformance runner core (because the runner *is* the spec, executable).

**Phase 1:** passport, envelope, receipt, capability, topology specs at v1.0. Conformance runner at v1.0 with Core-level checks for registry, receipts, transport, capability.
**Phase 2:** constitution schema spec; language conformance sub-suite; behavioral scenario S1 codified.
**Phase 3:** OpenTelemetry semantic conventions for agent operations (proposed upstream); behavioral S2/S3/S4.
**Phase 4:** federation handshake spec; cross-org receipt mutual-recognition spec; behavioral S5.

**Conformance ownership:** the runner. Per-interface sub-suites are co-owned with B/C/D/E.

**Threat model linkage:** A7 (supply chain) — specs are reviewed in the open; A8 (malicious operator) — spec defines the audit surface that resists operator capture.

### Workstream B — Control plane

**Charter:** the trust-boundary Rust code that mints identity, routes messages, evaluates capabilities, and enforces norms. Owns `yutha-core`, `yutha-crypto`, `yutha-passport`, `yutha-transport`, `yutha-registry`, `yutha-capability`, `yutha-control-plane`.

**Phase 1:** crypto primitives, passport, transport, registry, capability — all to Core conformance. Registry supports the three topology modes (closed, open, hybrid) via a pluggable admission-policy trait; reference implementations of all three ship in Phase 1.
**Phase 2:** integration with the constitution evaluator (Workstream E) and enforcement loop. Capability checks become constitution-driven. Topology-mode-aware registration costs (open swarms get sybil-resistance proofs by default; closed swarms skip them).
**Phase 3:** integration with envelope detection feeding back into enforcement.
**Phase 4:** federation transport profile; cross-org capability attestation.

**Conformance ownership:** registry, transport, capability sub-suites.

**Threat model linkage:** A3 (prompt injection) — typed envelopes; A5 (network adversary) — TLS, identity-bound channels, replay protection; A6 (sybil) — registry verification (especially in open and hybrid modes); A8 (operator) — receipts cannot be silently modified at the control-plane layer.

### Workstream C — Receipt store and observability fabric

**Charter:** the load-bearing wall. Append-only, content-addressed, signed receipts. Owns `yutha-receipt`, the Postgres + S3 default backend, the Walrus + Seal + Nautilus reference verifiable backend, and the OpenTelemetry export path.

**Phase 1:** receipt crate at Core + Full. Default backend in production. Verifiable backend reaches Core (it must pass the same conformance suite — PRD §8.4).
**Phase 2:** retention policies, range queries, bulk export with verifiable manifest.
**Phase 3:** OTEL semantic conventions; meta-fleet observability; behavioral envelope detection (signal source, not enforcement target — that lives in E).
**Phase 4:** receipt mutual-recognition across federation; selective-disclosure proofs.

**Conformance ownership:** receipt sub-suite (all levels), memory sub-suite (co-owned with B), attestation sub-suite.

**Threat model linkage:** A8 (operator) — append-only + content-addressed + signed defeats silent tampering; A7 (supply chain) — reproducible builds, signed releases; A5 (network) — replay detection via content-addressing.

### Workstream D — Framework adapters (SDKs)

**Charter:** Python and TypeScript SDKs for the launch frameworks. Wire-protocol-only by default (no FFI, per PRD constraint and ADR 0001 default). One adapter per supported framework, sharing a common SDK core.

**Phase 1:** Python SDK with adapters for LangGraph, AutoGen, CrewAI, Agent SDK. TypeScript SDK with the same set or a subset (final scope locked at Phase 1 entry). Quickstart and the fifteen-minute path validated with five non-engineering testers. Initiator path (the thirty-minute "stand up a new swarm" experience) validated with at least three small technical teams across the closed, open, and hybrid topologies.
**Phase 2:** SDK-side support for negotiation primitives (typed state machines). Constitution-aware error surfaces.
**Phase 3:** SDK hooks into the simulator (sim-and-prod symmetry).
**Phase 4:** SDK-side federation hints; passport extension for cross-org delegation.

**Conformance ownership:** none directly (SDKs are below the trust boundary). Co-owns DX validation with G.

**Threat model linkage:** A3 (prompt injection) — the SDK presents only typed surfaces, never lets agent output synthesize a control-plane operation.

### Workstream E — Constitution engine and enforcement loop

**Charter:** Cedar+ compiler, static analyzer, evaluator, and the four-stage enforcement loop. Owns `yutha-cedar-plus`, `yutha-enforcement`, `yutha-supervision`. Owns the LLM-assisted authoring CLI for Phase 2 and hands the visual layer off to G in Phase 3.

**Phase 1:** Cedar+ design partner work in parallel with Phase 1 substrate. Schema spec drafted. Cedar+ compiler is *not* required to ship in Phase 1 — Phase 1 ships substrate only — but the design must be far enough along that Phase 2 can start day one.
**Phase 2:** Cedar+ compiler, analyzer, evaluator at language conformance. Plain-English authoring CLI. Detect/coach/quarantine/evict loop. Reputation scalar. Supervision trees. Canonical schemas for queue-mode, campaign-mode, plus baseline schemas for closed / open / hybrid topologies (open and hybrid require sybil-aware predicates and quorum-by-capability for amendments by default).
**Phase 3:** behavioral envelope detection promoted from advisory (Phase 2) to gating once field data justifies it; envelope models live alongside Cedar+ predicates.
**Phase 4:** constitution amendment machinery (quorum, time-locks, rollback); apoptosis predicates.

**Conformance ownership:** language sub-suite (Cedar+ semantics, static analyzer, authoring pipeline).

**Threat model linkage:** A1 (hostile agent) — every mitigation; A2 (compromised model) — per-role envelopes; A6 (sybil) — quorum-by-capability for amendments, especially in open swarms; A9 (compromised supervisor) — watchers are watched, supervisors subject to envelope monitoring.

### Workstream F — Simulator and adversary library

**Charter:** the same control plane against synthetic environments, deterministically. Owns `/sim`. The single most important property of the simulator is that sim and prod traces are interchangeable artifacts.

**Phase 3 (entry):** deterministic clock; recorded-or-synthetic environments; replay; adversary library with one drop-in agent per A1–A9; property-based assertions; counterfactual replay engine.
**Phase 4:** federation-aware sim; multi-org adversary scenarios.

**Conformance ownership:** none directly; provides the harness for behavioral conformance scenarios S1–S5.

**Threat model linkage:** all of A1–A9, expressed as adversary agents that the rest of the system must defend against in scripted scenarios.

### Workstream G — DX, docs, quickstart, visual composer

**Charter:** the success criterion in §2 lives or dies here. Owns both the joiner path (fifteen minutes) and the initiator path (thirty minutes). Owns the quickstart, the docs site, the error-message conventions, and the visual composer (Phase 3).

The PRD calls this "the most underrated workstream." This plan agrees — it is staffed seriously from Phase 1 day one, not deferred.

**Phase 1:** quickstart, hello-world, fifteen-minute joiner path, thirty-minute initiator path. Three-layer docs (get-started / how-to / reference). Errors-that-respect-the-user conventions, enforced in code review. External-tester program (five non-engineers per phase plus three small technical teams for the initiator flow).
**Phase 2:** plain-English authoring tool front-end (CLI, then improved); diff/version UI for constitutions; topology-aware swarm templates (closed / open / hybrid starters).
**Phase 3:** visual swarm composer (web UI, TypeScript). Composer talks to the same control plane as the CLI.
**Phase 4:** federation UX; multi-org composer flows.

**Conformance ownership:** none directly; co-owns DX validation; owns the documentation NPS and quickstart-completion-rate metrics.

**Threat model linkage:** indirect — bad UX is how operators get into misconfigured states (cross-cutting "configuration drift" concern from threat-model §6). Good defaults and clear errors are mitigations.

### Workstream H — Community, open-source operations, and contributor experience

**Charter:** makes the open-source project credible, navigable, and welcoming to outside contribution from day one — without committing to a foundation, council, or formal governance body until adoption justifies one. Owns the public RFC process (with A); owns CONTRIBUTING.md, the code of conduct, and the security-disclosure process; owns the conformance mark policy in its initial *project-stewarded* form.

The deliberate posture: **defer the foundation question.** Yutha is an OSS project, not yet an institution. We commit to transparency, public RFCs, reproducible decisions, and equal-access conformance. Whether the project graduates to a foundation, a fiscal-host arrangement (NumFOCUS, Software Freedom Conservancy, etc.), or some lighter steward is a question revisited at Phase 3 entry — and only if adoption and contributor-base shape make it the right answer. Until then, governance is "BDFL-style with radical transparency" plus an explicit pre-commitment that no strategic decision is made off-list.

**Phase 1:** RFC process live before any spec is committed (RFCs in `/spec/rfcs/`, public discussion in the project forum). CONTRIBUTING.md, code of conduct, security-disclosure process (security@<project domain>, GPG key published). Public roadmap. Design-partner intake playbook. Conformance mark policy v0.1: self-attested only; result format and visual treatment specified.
**Phase 2:** Conformance mark policy v1.0: project-stewarded verification path (a small rotating reviewer pool from existing maintainers, not a separate body). Lightweight contributor council *if* the active-maintainer set has grown enough that decisions need broader input — judgment call, not a calendar item.
**Phase 3:** **Reassess governance.** Document decision criteria explicitly: how many active contributors, how many independent backend implementations, what fraction of commits come from outside the founding team. Foundation-track is one option among several; staying as-is is also a valid outcome.
**Phase 4:** whatever governance shape the project has at this point — informal stewardship, formal foundation, fiscal-host arrangement — federation policy and cross-org RFC norms live here.

**Conformance ownership:** the *mark* — who issues, how, what revocation looks like. The technical sub-suites belong to A/B/C/D/E.

**Threat model linkage:** A8 (malicious operator) — whistleblower channel and dissent semantics work because of *credible* governance; in early phases credibility comes from radical transparency and reproducibility, not from a governing body.

### Workstream L — Security (cross-cutting)

Not in PRD §18's enumeration but called out throughout the threat model and Cedar+ doc; staffed as a peer workstream from day one.

**Charter:** owns the threat model, the security conformance sub-suite, the supply-chain controls, and red-team work. Co-owns every interface that touches the trust boundary.

**Phase 1:** supply-chain controls live (signed releases, pinned deps, two-person review on security-critical paths, no third-party CI scripts); security conformance sub-suite for A3, A5, A7 in scope; red-team test of the substrate before phase exit.
**Phase 2:** security suite for A1, A6, A9; red-team Cedar+ analyzer; sandbox the evaluator. Sybil-resistance review specifically targeted at open and hybrid topologies.
**Phase 3:** security suite for A2; envelope-detection adversarial robustness.
**Phase 4:** security suite for A4, A8; cross-org delegation review.

**Conformance ownership:** security sub-suite (all adversaries).

**Threat model linkage:** all of it.

---

## 6. Phase 1 — Substrate (months 0–6)

**Pre-Phase-1 hygiene** (in motion now, prerequisite to a public release):

- Lock asset namespaces: `yutha.ai`, `yutha.io`, `yutha.dev`, `yutha.xyz` (acquired); GitHub org `yutha`; PyPI, npm, crates.io, Docker Hub namespaces; `@yutha` on X, Bluesky, LinkedIn.
- Trademark clearance in US (USPTO classes 9 and 42), EU (EUIPO), and India. Until clearance returns, the name in source documents (PRD, threat model, ADR, Cedar+ design, conformance suite) holds at "Concord"; this build plan and net-new artifacts use "Yutha." On clearance, a single coordinated rename pass updates the held documents.

**Phase exit condition (from PRD §8.4 plus this plan's gates):**

1. Ten-agent, two-framework swarm runs from a single YAML file with 100% receipt coverage.
2. p99 message routing under 100 ms in-region for swarms up to 100 agents.
3. **Both user paths validated:** five non-engineering testers complete the fifteen-minute joiner path; three small technical teams complete the thirty-minute initiator path covering all three topology modes.
4. Public spec docs published for passport, envelope, receipt, capability, topology.
5. Verifiable-backend reference (Walrus + Seal + Nautilus) passes the *same* conformance suite as the default backend at Core level.
6. **Conformance gates:** registry/Core (with admission-policy variants for closed, open, hybrid), receipts/Core, transport/Common+Datacenter, capability/Core, memory/Core (per-agent + shared), attestation/Core for the verifiable reference backend.
7. **Threat-model gates:** A3, A5, A7 mitigations have build-time tests in the security sub-suite. A1/A6/A8 partial coverage (full coverage requires Phase 2 enforcement; A6 in particular needs constitution-level quorum work for open swarms).
8. **Differential conformance:** the canonical S1 scenario passes with identical observable behavior on the default backend stack and on the Walrus + Seal + Nautilus reference stack within stated tolerances.

**Build sequence (the order is itself a constraint):**

1. **Specs frozen at v1.0.** Workstream A authors `passport.proto`, `envelope.proto`, `receipt.proto`, `capability.proto`, `topology.proto`. Public RFC window opens immediately. Frozen at month 2.
2. **Crypto + content-addressing.** `yutha-core` and `yutha-crypto` in Workstream B/C — wraps `ring` (audited), defines hash function, content-address scheme, signature primitives. No business logic depends on a non-audited crypto library.
3. **Receipt store core.** `yutha-receipt` plus the Postgres + S3 backend. Built first because everything else writes to it. Conformance: Core + Full.
4. **Passport and capability.** `yutha-passport`, `yutha-capability`. SPIFFE-compatible default; OIDC adapter. Capability tokens are content-addressed signed bearer tokens with attenuation.
5. **Transport.** `yutha-transport` over gRPC + NATS. Causal metadata propagated automatically; the SDK side cannot opt out.
6. **Registry with admission policies.** `yutha-registry`. Membership controller, reconciliation loop, declarative swarm spec, heartbeat. Three reference admission policies: `closed` (allowlist), `open` (sybil-resistant registration with optional proof-of-work or attestation), `hybrid` (allowlist for the core, open for the periphery with reduced-capability defaults).
7. **Control plane binary.** `yutha-control-plane` wires the above. `yutha up` from the quickstart spins this up against embedded Postgres + NATS.
8. **SDKs.** Python first (broader builder population), TypeScript second. One adapter per launch framework. Wire-protocol-only.
9. **Quickstart, joiner path, initiator path, docs.** Workstream G drives this in parallel from month 1; final polish months 5–6.
10. **Security sub-suite for A3/A5/A7.** Workstream L; gates phase exit.
11. **Verifiable-backend reference.** Walrus + Seal + Nautilus adapters under `/backends`. Must pass the conformance suite alongside the default — this is the existence proof for backend neutrality and the credibility floor for Phase 4 federation.
12. **Community and OSS hygiene.** RFC process live, CONTRIBUTING.md and code of conduct in place, security disclosure inbox monitored, public roadmap published. Workstream H.

**Phase 1 explicit non-goals (resist scope creep — this is the top-listed risk in PRD §18):**

- No constitution evaluator. No norm enforcement. No coaching, quarantine, eviction.
- No simulator.
- No visual composer.
- No federation primitives.
- No envelope detection.
- **No foundation, no council, no governing body.** Open-source project hygiene only. The foundation question is explicitly deferred (see §13).

If a Phase 1 ticket has the word "norm" or "policy" in it and is not about *capability* tokens, it is Phase 2.

**Open questions to resolve before scope freezes (from source docs and the synthesis):**

- Final adapter list (PRD §17.1).
- SPIFFE-first vs. OIDC-first default (PRD §17.1) — leaning SPIFFE per the PRD; confirm before month 2.
- NATS vs. Redis Streams (PRD §17.1) — leaning NATS; benchmark in month 2.
- Async runtime (ADR 0001) — confirm tokio.
- HTTP framework for control-plane admin surfaces (ADR 0001) — choose axum or actix-web before any admin endpoint ships.
- DB driver pattern (ADR 0001) — sqlx, diesel, or sea-orm.
- MSRV policy (ADR 0001) — proposed: stable minus three releases.
- Open-swarm sybil-resistance default — proof-of-work, hardware attestation, third-party identity attestation, or per-deployment operator choice.
- Trademark clearance on "Yutha" (in motion).

---

## 7. Phase 2 — Coordination & Norms (months 6–12)

**Phase entry condition:** Phase 1 is in production at three or more pilot organizations (ideally covering at least two of the three topology modes); constitution language design is accepted by at least two design partners; negotiation protocol selection is final (Contract Net, English/Dutch/sealed-bid auctions, deadline negotiation, divisible-resource split, mediated dispute — anything else is Phase 3).

**Phase exit condition:**

1. 95%+ detection rate on injected hard-rule violations within one tick.
2. Coaching reduces repeat violations by 50% over a 100-turn horizon.
3. Swarm survives the loss of any single agent (including a supervisor) with no task interruption visible to end users.
4. Riya can author, deploy, amend a constitution end-to-end without code; validated with external testers.
5. Sam reviews a constitution as a policy document, signs off, and rolls back.
6. **Conformance gates:** language/Cedar+ semantics, language/static-analyzer, language/authoring; receipts/Full; memory/Core+Concurrency+Privacy; access-control/Core; behavioral S1 + S2 + S3.
7. **Threat-model gates:** A1, A6, A9, partial A2 covered by security sub-suite. A3 capability-check mitigations exercised end-to-end. A6 sybil resistance exercised specifically in open and hybrid topologies.

**Build sequence:**

1. **Cedar+ compiler.** `yutha-cedar-plus` built on top of the open-source `cedar-policy` Rust crate. The Cedar+ extensions (`prefer`, procedures, resource budgets, memory norms) are layered above stock Cedar; we do not fork Cedar.
2. **Static analyzer.** The security boundary. Rejects loops, recursion, side effects, unbounded depth. Built before the evaluator is wired into the control plane — the analyzer must reject every program-class the threat model cares about before any predicate reaches production.
3. **Evaluator + sandbox.** Bounded depth statically checked, runtime time limit as safety net. Wasm sandbox path is a near-term option for evaluating user-provided procedure code; default is in-process Rust.
4. **Canonical schemas.** Workstream A ships entity-type and action-type schemas for queue-mode (customer support), campaign-mode (security incident response), and topology-mode baselines (closed / open / hybrid). Operators can extend; canonical schemas ship pre-vetted and signed.
5. **Plain-English authoring CLI.** LLM-assisted compile: English in, Cedar+ out, generated test cases for human review. **The LLM is not in the runtime path; this is a build-time invariant tested in CI.**
6. **Negotiation protocol library.** Each pattern is a typed state machine on top of Phase 1 messaging. SDK exposes them as primitives.
7. **Four-stage enforcement loop.** `yutha-enforcement`: detect (predicate match + envelope hint), coach (typed feedback message), quarantine (reversible isolation), evict (irreversible, receipt-bearing). Every transition produces a receipt with cited evidence.
8. **Reputation scalar.** Per-agent score derived from receipts and enforcement events. Pluggable storage. Advisory; never the sole basis for decisions. Especially load-bearing in open swarms where reputation does some of the gatekeeping work that operators do in closed swarms.
9. **Supervision trees.** `yutha-supervision`. Erlang-style restart/escalate/terminate. Default strategies for common patterns. Watcher-of-watchers semantics so supervisors are themselves under envelope monitoring (A9 mitigation).
10. **Behavioral scenarios S1 (queue mode), S2 (insurance due-diligence), and S3 (security incident response)** wired into the conformance runner. S3 is the canonical Phase 2 use-case validation per PRD §9.5.

**Phase 2 explicit non-goals:**

- No simulator (no shadow swarm, no adversary library).
- No visual composer.
- No federation.
- No constitution amendment mechanisms beyond the basic versioning + signing in v1.

**Cedar+ specific risks and mitigations:**

- **LLM authoring producing unsafe predicates.** Mitigated: the static analyzer is the security boundary, not the LLM. Tested by red-teaming the analyzer in Workstream L with adversarial Cedar+ programs.
- **Cedar+ extensions making the language Turing-complete.** Mitigated: every extension must come with a structural decidability proof at design review. Procedures are state machines, not arbitrary code; soft preferences are scoring functions, not loops.
- **Schema attacks.** Mitigated: canonical schemas are signed by the project maintainers; operator-extended schemas are reviewed at deployment.

---

## 8. Phase 3 — Simulation & Observability (months 12–18)

**Phase entry condition:** Phase 2 in production at two pilot orgs; receipt volume sufficient to seed envelope models; OTEL semantic conventions for agents agreed and proposed upstream. **Governance reassessment** is also a Phase 3 entry activity (Workstream H), informed by the size and shape of the contributor base.

**Phase exit condition:**

1. Pre-prod simulation predicts production behavior on cost, completion rate, and norm-violation rate within stated tolerance.
2. Counterfactual replay reproduces real prod traces deterministically when no perturbation is applied.
3. Meta-fleet dashboards expose ten committed metrics with drill-down to causal traces.
4. A non-engineer builds, deploys, and operates a swarm in the visual composer for two weeks without engineering escalation.
5. **Conformance gates:** performance suite at all targets in `conformance-suite.md` §6; behavioral S4 (constrained transport).
6. **Threat-model gates:** A2 (compromised model) coverage via per-role envelopes; residual A1 (sophisticated drift) substantially reduced; envelope detection robustness tested adversarially.

**Build sequence:**

1. **Deterministic clock + replay infrastructure.** Workstream F. The simulator and the production control plane share the same Rust crate; the difference is the clock and the I/O surface.
2. **Adversary library.** One drop-in agent per A1–A9. Each adversary's capability profile matches the threat-model entry; each ships with reference scenarios that exercise its claimed capabilities.
3. **Property-based assertions.** Quickcheck-for-swarms. Plain-English claims compiled to runnable assertions (uses the same Cedar+ pipeline at compile time, but assertions evaluate over traces, not single decisions).
4. **Counterfactual replay.** Take a real trace; perturb one agent's output or one tool's response; replay deterministically. Critical for incident review and for behavioral envelope validation.
5. **OTEL semantic conventions.** Workstream A leads upstream contribution. Internal default is to ship our conventions before upstream acceptance, with a migration when upstream lands.
6. **Meta-fleet observability.** Dashboards across swarms. Cost-per-task, plan churn, consensus latency, blast-radius, drift indicators. Drill-down to causal traces. Built on the receipt fabric — no new data source.
7. **Behavioral envelope detection.** Statistical models per agent and per role, learned from receipts. Phase 2 ships envelope detection as advisory; Phase 3 promotes it to gating only after sufficient field data validates false-positive rates.
8. **Visual swarm composer.** Web UI, TypeScript, Workstream G. Talks to the same control plane as the CLI. Constitution authoring layer migrates from Phase 2 CLI to the composer; the compilation pipeline does not change. Supports composing closed, open, and hybrid swarms with mode-appropriate templates.
9. **Behavioral scenario S4** (disaster response with constrained transport) is the Phase 3 anchor.
10. **Governance reassessment write-up.** Workstream H publishes the criteria evaluation: contributor count, independent implementations, off-team commit fraction. Outcome: explicit decision to keep current stewardship, move to a fiscal host, or begin a foundation track.

**Behavioral envelope cautions (PRD §16.2):**

- False-positive cost can be high; envelope detection is advisory through Phase 2 and gating only after Phase 3 validates rates.
- Privacy implications of pretrained vs. per-deployment models are unresolved (PRD §17.3); default is per-deployment with optional shared-pretrained as opt-in.

---

## 9. Phase 4 — Federation & Governance (months 18+)

**Phase entry condition:** Phase 3 broadly adopted; two organizations independently asking for federation; verifiable-backend track record sufficient for cross-org receipt mutual-recognition; a governance shape adequate to handle cross-org policy disputes (this may be informal stewardship if the project remains small and trusted, a fiscal host, or a formal foundation — the Phase 3 reassessment determines which).

**Phase exit condition:**

1. Two swarms with different constitutions complete a real joint task with mutual-recognition and bounded delegation.
2. A constitution amendment is proposed, voted, and applied live without downtime.
3. At least one apoptosis case fires in a real deployment and prevents an incident the external loop missed.
4. A regulator or auditor signs off on a Yutha-deployed swarm using only Yutha-produced artifacts.
5. **Conformance gates:** registry/Verifiable, receipts/Verifiable, memory/Verifiable, access-control/Verifiable; behavioral S5.
6. **Threat-model gates:** A4 (hostile peer swarm), A8 (malicious operator) covered; cross-org receipt mutual-recognition cryptographically detectable (verifiable tier).

**Build sequence:**

1. **Federation handshake protocol.** Capability advertisement; norm reconciliation (common-subset); bounded mutual delegation. Spec'd in `/spec/federation/`; the spec ships before any code merges.
2. **Cross-swarm receipt mutual-recognition.** Verifiable-tier receipts mutually recognizable across organizations using only public keys. Selective-disclosure proofs.
3. **Constitution amendment machinery.** Quorums (by capability or role, not just count); supermajorities for sensitive clauses; time-locks; rollback. Pluggable governance backends.
4. **Apoptosis primitives.** Self-introspection predicates and clean self-termination with receipt. Default library of common self-checks. Opt-in vs. required for high-stakes deployments is a Workstream H call (PRD §17.4).
5. **Dialect and translation layer.** Subgroup compression with explicit registration. Maintains interpretability to outsiders and regulators.
6. **Verifiable-tier defaults for high-stakes.** Same code; one config flip. The verifiable backend has been carrying the same conformance burden since Phase 1, so this is configuration work, not new implementation.
7. **Whistleblower channel** (cross-cutting, but matures in Phase 4 as federation amplifies operator-vs-agent power asymmetry).
8. **Behavioral scenario S5** (federated multi-org delivery network) is the anchor.

---

## 10. Conformance as a build-time forcing function

The conformance suite is not a QA artifact added at the end. It is a build-time forcing function that gates phase exits.

**Operational policy:**

- A component that does not pass its declared conformance level is not merged for that phase. Period.
- Every PR that touches a conformance-relevant interface runs the relevant sub-suite in CI.
- The runner ships in Rust (matches core) with adapters for backends in any language. (Resolves an open question in `conformance-suite.md` §10.)
- Differential conformance against the reference stack runs nightly from Phase 1 onward, even for components not yet at "Full" — early signal on observable-equivalence drift is much cheaper than late signal.
- Self-attested results carry different visual treatment than project-stewarded verification (per `conformance-suite.md` §8). Phase 1 ships only self-attested. Project-stewarded verification — a small rotating reviewer pool from existing maintainers — stands up in Phase 2. Whether that ever graduates to a foundation-issued mark depends on the Phase 3 governance reassessment.
- Performance targets in `conformance-suite.md` §6 ship as placeholders in Phase 1; real benchmark-derived targets land before Phase 2 freezes (per the conformance doc).
- The conformance mark is revocable. Misrepresentation is grounds for revocation and (under any future governance arrangement) public advisory.

**Why this matters:** the entire credibility argument for backend neutrality, framework neutrality, and platform-vendor-capture defense (PRD §3.2 and §16.1) depends on conformance being structural rather than performative. Treating it as a QA gate that gets cut when behind schedule destroys the strategic position. Until the project has a foundation or steward of any formal kind, the conformance suite *is* the institution.

---

## 11. Threat-model coverage map

Every adversary in the threat model has at least one design-time mitigation and at least one build-phase owner. This table is the audit:

| Adversary | Primary phase of coverage | Lead workstream | Key mitigations |
|-----------|---------------------------|-----------------|-----------------|
| A1 Hostile agent | Phase 2 | E (with B, L) | Constitution norms; envelope detection; four-stage enforcement; per-agent quotas; causal attribution |
| A2 Compromised model | Phase 3 | E, C | Per-role envelopes; receipts capture model+version; norms can require model diversity; verifiable model attestation |
| A3 Prompt injection | Phase 1 (containment) → Phase 2 (capability check) | B, D | Typed envelopes; capability enforcement; default-deny; SDK presents only typed surfaces |
| A4 Hostile peer swarm | Phase 4 | E, B, H | Federation handshake limits scope; revocable federated memory; cross-swarm receipts; clean detach |
| A5 Network adversary | Phase 1 | B, L | TLS; identity-bound channels; signing; replay protection via causal metadata + nonces; content-addressed receipts |
| A6 Sybil | Phase 1 (registry foundations) → Phase 2 (constitution-level quorums) | B, E | Registry verification cost (especially in open / hybrid swarms); reputation advisory only; cold-start protection; quorum-by-capability for amendments |
| A7 Supply chain | Phase 1 (continuous) | L | Two-person review on critical paths; reproducible builds + Sigstore; pinned deps; no third-party CI scripts; vendoring small deps |
| A8 Malicious operator | Phase 1 (substrate) → Phase 4 (federation) | C, H | Append-only signed receipts; whistleblower channel; right to dissent; verifiable tier makes tampering cryptographically detectable; transparent governance from Phase 1 |
| A9 Compromised supervisor | Phase 2 → Phase 4 (apoptosis) | E | Watchers-watched envelope monitoring; two-person rule for some supervisor actions; supervisor receipts; constitution can forbid self-elevation |

Configuration drift (cross-cutting) is mitigated by safe defaults + warnings on unsafe configurations + the conformance suite verifying configuration; this is Workstream G's responsibility for defaults and Workstream A's for the suite. Topology-mode misconfiguration (e.g., declaring `closed` and accidentally running an open admission policy) is prevented by the registry refusing to start if its admission policy and the swarm's declared mode disagree.

---

## 12. Critical path and dependencies

Reading this as a build DAG:

```
[A: Specs v1] ──► [C: Receipt core] ──► [B: Crypto+Passport+Capability] ──► [B: Transport]
                                                                         ──► [B: Registry + 3 admission policies] ──► [B: Control plane bin]
                                                                                                                  ──► [D: SDKs] ──► [G: Quickstart + initiator path]
                                                                                                                  ──► [Backends: Postgres/S3/NATS, Walrus/Seal/Nautilus]
                                                                                                                  ──► [L: Security sub-suite A3/A5/A7]
                                                                                                                  ──► [Conformance: Core for all interfaces]
   │
   └─────► [A: Constitution schema spec] ──► [E: Cedar+ design with partners]
                                               │
                                          (parallel during Phase 1)
                                               │
                                               ▼
                                       [Phase 2 entry]
```

Hard sequencing constraints:

1. **Specs before code, always.** No reference implementation merges before the spec it implements is at v1.0.
2. **Receipt core before everything that emits receipts.** Which is everything. So receipt core is the first non-spec artifact built.
3. **Crypto + content-addressing before passport, before capability, before transport.**
4. **Transport before registry** (registry uses transport for heartbeats).
5. **Control-plane binary before SDKs** (SDKs need something to talk to).
6. **Conformance runner before any conformance level can be claimed** — runner ships at month 2–3 of Phase 1 alongside the first specs.

Soft sequencing:

- Cedar+ design partner work runs in parallel with all of Phase 1 — it is the longest-lead-time intellectual workstream and starting it at month 6 means Phase 2 slips.
- Workstream G (DX) runs in parallel from month 1; deferring it to "after the substrate works" is the historical pattern that produces Kubernetes-style DX. We are explicitly counter-positioning against that. The initiator path (thirty-minute swarm bring-up) is as important as the joiner path and gets equal attention.
- Workstream H (community) runs in parallel from month 1 — but with a deliberately scoped charter (RFC process, contributor experience, OSS hygiene). The foundation question is *not* on the Phase 1 critical path.
- Workstream L (security) runs in parallel from month 1; supply-chain controls (A7) shipping after Phase 1 is too late.

---

## 13. Governance posture (and what we are deliberately not doing yet)

Yutha is being released as an open-source project, not as an institution. The posture for the foreseeable future:

- **Public RFC process from day one.** All spec changes, all major architectural decisions, all conformance-mark policy changes happen on-list. No private decisions about public artifacts.
- **Maintainer-stewarded, BDFL-flavored.** Decision authority sits with the active maintainers. The original author is the tiebreaker until the contributor base says otherwise.
- **Radical transparency in lieu of formal governance.** Roadmaps, design discussions, conformance results, security disclosures, and rationale documents are all public. The project earns trust by being legible, not by appointing a body to vouch for it.
- **Explicit pre-commitments.** No surprise relicensing. No telemetry phone-home (architectural commitment 4.7). No proprietary protocol path that bypasses the spec. These commitments live in `/docs/community/` and are themselves under RFC governance.
- **Foundation question explicitly deferred.** Whether Yutha eventually graduates to a foundation, a fiscal-host arrangement, or some other formal structure is reassessed at Phase 3 entry. Decision criteria: contributor count, independent implementations, off-team commit fraction, regulator/enterprise demand for a neutral steward. Until that reassessment, foundation-creation is not on the work plan.
- **What "neutrality" looks like before there is a foundation.** Equal-access conformance suite. Default backend stack that has no commercial dependency on any single vendor. Verifiable backend stack that ships from day one, alongside the default, passing the same suite. SDK adapters that treat all supported frameworks symmetrically. Decisions documented in ADRs that anyone can read and challenge.

This posture trades some institutional credibility for execution speed. It is the right trade for a project that needs to prove itself before asking the OSS world to invest infrastructure in it. The commitment is that we revisit the trade openly when conditions change.

---

## 14. Cross-cutting language, runtime, and dependency decisions

Resolves the open ADR questions and pins the major dependency choices for build-time predictability.

| Decision | Choice | Notes |
|----------|--------|-------|
| Async runtime | tokio | The default. Confirmed; alternatives carry no upside for our profile. |
| HTTP framework | axum | Lower complexity than actix-web; good tokio integration; smaller surface to audit. |
| Database driver | sqlx | Compile-time-checked queries; async-native; Postgres-first. |
| gRPC | tonic | The de-facto Rust gRPC; mature; integrates with prost. |
| Protobuf | prost | Standard Rust protobuf. |
| Serialization (non-wire) | serde | Standard. |
| Crypto baseline | ring + rustls + ed25519-dalek + age | All audited; widely deployed; covers signing, hashing, TLS, encryption-at-rest. |
| Cedar base | cedar-policy crate | Cedar+ extensions layer above; we do not fork Cedar. |
| Logging | tracing | Span-based; integrates with OTEL. |
| Telemetry export | OpenTelemetry | Conventions for agent ops contributed upstream in Phase 3. |
| Build orchestration | cargo workspace + sccache + mold | Mitigates Rust compile-time concern (ADR 0001). |
| Reproducibility | Sigstore for signing + locked deps + vendored small deps | A7 supply-chain mitigation. |
| MSRV | latest stable minus 3 releases | Per ADR 0001 proposal. |
| Python SDK FFI | wire-protocol-only by default | FFI (PyO3) is special-case escape hatch with explicit benchmark justification. |
| TypeScript SDK FFI | wire-protocol-only | Same. |
| Visual composer | TypeScript + React | Web-native; no first-class status. |

---

## 15. Staffing shape

A *shape* — not a hiring plan. The hiring plan is Cowork's first action item per PRD §18.

**Phase 1 ramp (month 0–6):**

- Workstream A — 2 senior engineers, RFC-process literacy, protocol-design background.
- Workstream B — 4–6 Rust engineers; async + distributed-systems experience required.
- Workstream C — 2–3 engineers; storage + crypto; one OTEL upstream contributor desirable for Phase 3.
- Workstream D — 1 Python lead + 1 TypeScript lead; framework-integration experience.
- Workstream E — 2 engineers; PL / Cedar / formal-methods adjacent. Starts Cedar+ design partner work in parallel with Phase 1 substrate; does not deliver runtime code in Phase 1.
- Workstream G — 2–4 (writer + designer + DX engineer + composer engineer ramping). Owns both joiner and initiator paths.
- Workstream H — 1 community lead, part-time. Scope is OSS hygiene, RFC process, contributor experience — not foundation creation. Adding part-time legal counsel for trademark and license review only.
- Workstream L — 2 engineers; co-owns threat model and security conformance.

Approximately 18–22 at Phase 1 ramp — slightly leaner than the v0.1 plan because Workstream H has a smaller initial scope.

**Phase 3 plateau:** approximately 28, with F (sim) standing up at month 12 and G expanding for the visual composer.

Cross-workstream resourcing:

- Two-person review on security-critical paths (A7 mitigation) is enforced via CODEOWNERS; the second reviewer is always Workstream L for `yutha-cedar-plus`, `yutha-crypto`, `yutha-passport`, `yutha-capability`, `yutha-receipt`.
- Every workstream has a documented on-call rotation by Phase 2; this is practice for the operational pattern Yutha is selling and produces the muscle memory pilots ask about.

---

## 16. Risks and how this plan absorbs them

The PRD enumerates strategic, technical, and ethical risks. Plan-level mitigations:

**Phase 1 absorbs Phase 2 features (highest risk per PRD §18).**
*Absorbed by:* explicit non-goals list in §6; weekly check-ins to surface scope creep; the four-stage enforcement loop is *not* in any Phase 1 ticket; Cedar+ design partner work is firewalled from Phase 1 substrate work.

**Cedar+ proves limiting.**
*Absorbed by:* Cedar is the canonical compiled form, not the user-facing form; replacing Cedar with a future bespoke DSL is a documented evolution path (constitution-language.md §6); the LLM authoring layer abstracts Cedar's surface from the author.

**Behavioral envelope false-positives.**
*Absorbed by:* envelope detection ships as advisory in Phase 2; gates promotion to enforcing in Phase 3 only after field data validates rates; quarantine is reversible always.

**SDK adapter quadratic burden.**
*Absorbed by:* shared SDK core; wire-protocol-only by default keeps adapters thin; conformance suite for SDK behavior keeps community adapters honest.

**Project perceived as a vendor product (PRD §16.1 risk variant).**
*Absorbed by:* radical transparency from day one — public RFCs, public roadmap, on-list decisions; equal-access conformance suite that any backend can pass; verifiable backend stack ships from day one alongside the default and passes the same suite; default deployment uses Postgres + NATS, not Walrus; spec is the product, code is the proof. The deferred-foundation posture means we do not paper over with institutional structure what we have not yet earned with practice — but we also commit to revisiting governance when conditions warrant.

**Supply-chain attack (A7).**
*Absorbed by:* two-person review on critical paths from PR #1; pinned deps; no third-party CI scripts; reproducible builds; Sigstore signing; vendoring of small deps; pre-merge security review on every dependency upgrade.

**Norm specification harms broader communities.**
*Absorbed by:* dissent channels first-class; multilingual-ready schemas in v1; non-Western design partners on the recruit list for Phase 1; constitution language explicitly refuses to pretend norms are neutral.

**Receipt store becomes the bottleneck.**
*Absorbed by:* append-only + content-addressed + sharded from Phase 1; explicit per-phase benchmarks; verifiable backend has stricter latency targets so the default backend cannot regress unnoticed.

**Phase 1 ships a beautiful substrate that nobody adopts.**
*Absorbed by:* the fifteen-minute joiner path and thirty-minute initiator path are both phase-exit gates, not marketing lines; three pilot orgs are a Phase 2 entry condition; Workstream G owns adoption metrics from Phase 1.

**Open-swarm sybil resistance is harder than expected.**
*New risk surfaced by topology-mode work. Absorbed by:* Phase 1 ships closed and hybrid first-class; open mode ships with a configurable sybil-resistance proof (proof-of-work, attestation, or third-party identity) and operators choose; Phase 2 hardens with constitution-level quorum-by-capability.

**Trademark clearance fails on "Yutha."**
*Absorbed by:* asset namespaces locked early but in-document rename held until clearance; if clearance fails, fallback name selection process documented in the rename memo; cost of a second rename is bounded because the build plan and code haven't yet shipped publicly.

---

## 17. What this plan deliberately does not do

- It does not replace per-subsystem RFCs. Each major component (registry, transport, receipt store, Cedar+, federation handshake) gets its own RFC with deeper design rationale.
- It is not a project schedule. Cowork breaks each phase's exit criteria into a milestone list with owners and target dates (PRD §18, first action item).
- It does not commit to specific calendar dates. The phase durations in the PRD (0–6, 6–12, 12–18, 18+ months) are scope-shaped, not date-shaped. Date commitments come out of the milestone list, not this plan.
- It does not commit to a foundation, council, or formal governance body. The Phase 3 reassessment is when that question is reopened.
- It does not name people or teams. Charters, not assignments.

---

## 18. Open questions surfaced by the synthesis

These are not open in any single source doc but become open when the docs are read together. They want resolution before Phase 1 freezes:

- **Conformance runner vs. control plane code sharing.** The runner instantiates control-plane components in a controlled environment. How much of `yutha-control-plane` is a library that the runner can embed vs. a binary the runner exec's? Leaning library-first; confirm in month 2.
- **Schema authoring authority.** Cedar+ schemas can be canonical (maintainer-vetted) or operator-extended. Where does the operator-extended schema live? Inside the constitution YAML, in a separate signed artifact, or in a registry? The constitution-language doc defers; this needs to land before Phase 2.
- **OTEL upstream timing.** Phase 3 commits to upstreaming agent semantic conventions. If upstream rejects or delays, what's the fallback? Default is to ship our conventions and live with an upstream migration later; document that explicitly.
- **Federation handshake spec timeline.** Phase 4 is months 18+, but spec authoring can begin earlier. Suggest spec-only work in late Phase 3.
- **Verifiable backend in Phase 1.** PRD §8.4 requires verifiable backend at Phase 1 exit. This is aggressive given the rest of Phase 1 substrate. Confirm both that this is achievable and that the Walrus + Seal + Nautilus integrators have the bandwidth at the right moment.
- **Open-swarm default sybil-resistance mechanism.** Proof-of-work is uncomplicated but environmentally questionable; hardware attestation is rigorous but not universally available; third-party identity attestation introduces an external dependency. Default likely needs to be operator-choice with sane templates.
- **Trademark clearance on "Yutha."** Pending. If clearance returns negative, the rename memo's fallback process activates and this build plan needs another rename pass.
- **Project hosting after the first non-trivial outside contribution.** Today: maintainer-stewarded. If the first significant outside contributor wants commit access, what's the process? Workstream H drafts a maintainer-promotion policy in Phase 1.

---

## 19. Index of source documents

- `/docs/Concord_PRD.docx` — Product requirements (Abhinav Garg, v0.1). Filename retained until coordinated rename pass.
- `/docs/internal/0001-language-choice.md` — ADR: Rust core + polyglot edges.
- `/docs/internal/threat-model.md` — Adversaries A1–A9; assets and trust boundaries.
- `/docs/internal/constitution-language.md` — Cedar+ design; LLM authoring; static analyzer as security boundary.
- `/docs/internal/conformance-suite.md` — Conformance levels, sub-suites, behavioral scenarios S1–S5, performance SLAs.
- *Project rename memo (Concord → Yutha)* — naming rationale, sequencing, hold-until-clearance instruction.

---

## 20. How this document evolves

Major changes follow the same RFC process as the source documents. This plan is reviewed:

- At every phase entry (does the plan still match what we committed to?).
- At every phase exit (did the plan match what we shipped? where did it not, and why?).
- Whenever a source document (PRD, ADR, threat model, language doc, conformance suite) bumps a major version.
- Whenever the governance posture in §13 is reassessed — at minimum, at Phase 3 entry.

The plan is the synthesis. When the source documents disagree with the plan, the source documents win, and the plan is updated to reflect the new ground truth.

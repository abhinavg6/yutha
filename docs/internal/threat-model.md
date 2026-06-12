# Concord Threat Model

> **Repo location:** `/docs/internal/threat-model.md`
> **Version:** v0.1 (working draft)
> **Status:** Initial pass; expect revisions as subsystems mature
> **Owners:** Workstream L (Security)

## Purpose and scope

This document describes the adversaries Concord is designed to defend against, the assets being protected, the trust boundaries, and the residual risk after design-level mitigations.

It complements **Section 18 of the PRD** (Security Posture), which describes practices and commitments at the project level. Where Section 18 says "what we do," this document says "what we are protecting against."

This is a living document. Each subsystem (registry, memory, transport, control plane, constitution evaluator, federation) will eventually have its own threat sub-model. This v0.1 covers platform-wide threats.

## Assets

The valuable things in a Concord deployment:

| Asset | Why it matters |
|-------|----------------|
| Receipts | Audit trail, regulatory evidence, dispute resolution |
| Shared memory | Operational knowledge, customer / principal context |
| Per-agent memory | Decision substrate, personal / session-scoped data |
| Identity / passport | Trust anchor for every agent action |
| Constitution | Governs all enforcement; tampering invalidates the whole swarm |
| Reputation scores | Influence on dispatch, federation, eviction |
| Capability tokens | Authority to act |
| Cryptographic keys | Sign receipts, encrypt memory, identify agents |
| Control plane integrity | Compromised platform = compromised everything |

## Trust boundaries

Every interface between two of these zones is a trust boundary:

1. **Agent runtime ↔ Concord SDK adapter.** The agent runs untrusted output (LLM responses, tool results); the SDK presents a thin trusted shim.
2. **SDK adapter ↔ control plane.** All input from the adapter is treated as untrusted by the control plane.
3. **Control plane ↔ pluggable backend** (registry, memory, receipts, transport). Backends authenticate calls and enforce access decisions independently.
4. **Swarm ↔ peer swarm in federation.** No transitive trust; explicit handshake required for every cross-swarm interaction.
5. **Operator / human ↔ control plane.** Human override is privileged but always logged and constrained by deployment policy.
6. **Constitution evaluator ↔ everything else.** The evaluator runs predicates compiled from norms; it must not affect anything outside its return value and recorded evidence.

## Adversaries

We model nine adversaries explicitly. For each, we describe their capabilities, goals, what Concord's design prevents, and the residual risk.

### A1. Hostile agent participant

A legitimately registered agent that attempts to harm the swarm or its data. The operator may have been tricked into accepting it, or a peer organization may have registered it in a federated swarm.

**Capabilities:** send messages allowed by passport, read accessible shared memory, write where permitted, participate in negotiations, consume tool budgets.

**Goals:** exfiltrate sensitive shared memory, poison shared memory with false information, influence dispatch / negotiation against principal interests, cause receipt churn or reputation damage to peers, trigger resource exhaustion.

**Mitigations:**
- Constitution norms over memory access (PRD Section 8.6) prevent unauthorized reads / writes
- Behavioral envelope detection catches statistical drift
- Four-stage enforcement loop: detect → coach → quarantine → evict
- Per-agent quotas prevent resource exhaustion
- Causal metadata attributes every effect to its origin
- Receipts make exfiltration attempts auditable

**Residual risk:** sophisticated agents that drift slowly within envelope tolerance; collusion between multiple hostile agents (partially addressed in Phase 4 federation work); first-time exfiltration before any envelope is established.

### A2. Compromised model provider

The LLM behind a legitimately-registered agent has been poisoned (training-time backdoor, prompt-injection-as-a-service, supply-chain attack on the model itself).

**Capabilities:** cause agents to behave correctly until a trigger phrase or condition; influence agents that share a model provider in correlated ways; bypass simple per-agent envelopes if the trigger is rare.

**Goals:** targeted exfiltration on trigger; sabotage at a coordinated time; influence federation outcomes.

**Mitigations:**
- Receipts capture which model and version were used per decision; cross-agent correlation is visible in observability
- Per-role behavioral envelopes (not just per-agent) catch correlated drift across many agents using the same model
- Norms can require model diversity (e.g., no swarm shall have all agents on a single provider for sensitive tasks)
- Verifiable backends record model attestation in receipts

**Residual risk:** targeted attacks by sophisticated state-level adversaries are not fully mitigated; detection requires the trigger to fire in observable conditions; norms requiring diversity are operator's choice, not enforced by default.

### A3. Prompt injection vector

Untrusted content (a tool result, a customer message, a document) contains instructions that try to override the agent's directives or escape into the control plane.

**Capabilities:** influence the agent's next decision; attempt to call control-plane operations through the agent.

**Goals:** cause the agent to perform actions outside its mandate; escape into the control plane via the message envelope.

**Mitigations:**
- Typed messaging: control-plane operations require typed envelopes the agent cannot synthesize from user content
- Capability enforcement: even if an agent is convinced to attempt an action, capability check blocks unauthorized attempts
- Default-deny on ambiguous capability evaluation
- Receipts capture input content, decision, and action — making post-hoc reconstruction possible
- The control plane treats every SDK call as untrusted regardless of which agent made it

**Residual risk:** the model-level injection problem is not solved by Concord; we contain it. Agent operations within their allowed capabilities can still be manipulated. Memory poisoning via injected content is partially mitigated by norms but not fully eliminated.

### A4. Hostile peer swarm in federation

A federated swarm operated by a different organization that becomes adversarial during a joint operation.

**Capabilities:** send messages within the federation handshake's allowed scope; read federated memory the federation grants access to; influence federated dispatch and negotiation.

**Goals:** exfiltrate sensitive federated memory; sabotage the joint operation; manipulate handoffs to advantage their own agents.

**Mitigations:**
- Federation handshake limits scope explicitly (capability advertisement and norm reconciliation)
- Federated memory has explicit, revocable access
- Cross-swarm receipts allow detection of timing manipulation
- Federation enforcement loop quarantines hostile agents from the peer swarm
- Federation can be detached unilaterally by either side

**Residual risk:** subtle manipulation within agreed-upon scope; race conditions in revocation; disagreement about what counts as a norm violation across swarms.

### A5. Network-level adversary

A passive eavesdropper or active man-in-the-middle on the network between agents and the control plane, or between the control plane and backends.

**Capabilities:** observe traffic patterns; attempt MITM on connections; replay messages; drop or delay messages; inject crafted packets.

**Goals:** recover plaintext content; forge messages; replay receipts or capability tokens; cause partition.

**Mitigations:**
- All wire traffic encrypted (TLS for datacenter / WAN, equivalent for constrained transport)
- Identity-bound channels available where the registry supports them
- All messages signed; replay protection via causal metadata, nonces, and epoch markers
- Receipts are content-addressed; replay is detectable
- Causal metadata makes ordering attacks observable

**Residual risk:** traffic analysis is possible even with encryption; long-running passive metadata collection; sophisticated active adversaries with state-level capabilities.

### A6. Sybil attacker

An adversary creates many fake agent identities to manipulate dispatch, reputation, or negotiation outcomes.

**Capabilities:** register many agents (within registration costs); have those agents behave acceptably to build reputation; coordinate them at a chosen moment.

**Goals:** dominate dispatch in queue mode; manipulate reputation scoring; win auctions or contract-net bids unfairly; vote-stuff in constitution amendments.

**Mitigations:**
- Registry verification costs (real or computational) make trivial sybil cheap to detect
- Reputation is advisory, never the sole basis for decisions
- Cold-start protection prevents new agents from being permanently disadvantaged but also limits their initial influence
- Federation verification requires cross-org identity attestation
- Verifiable stack adds cryptographic identity attestation for high-value decisions
- Constitution amendments can require quorums by capability or role, not just agent count

**Residual risk:** determined adversaries with resources can pass any single verification; distinguishing "many similar agents" from "many small honest agents" is fundamentally hard; long-running sybil campaigns are difficult to detect.

### A7. Supply-chain attacker

An adversary compromises a dependency, contributor account, or build infrastructure to inject malicious code into Concord itself.

**Capabilities:** submit malicious PRs (xz-utils pattern); compromise CI / build infrastructure (SolarWinds pattern); compromise a transitive dependency (event-stream pattern); compromise a maintainer's signing key.

**Goals:** backdoor the platform; insert detection-evading vulnerabilities; compromise downstream deployments at scale.

**Mitigations:**
- Mandatory two-person review on security-critical paths
- Reproducible builds, signed releases (Sigstore / equivalent)
- Pinned dependencies with security review on update
- No critical-path dependencies on sole-maintainer micro-packages
- Vendoring of small dependencies where practical
- Build infrastructure isolated; no third-party scripts in CI
- Contributor identity verification for security-critical paths
- Static analysis on every PR (CodeQL, Semgrep, equivalents)

**Residual risk:** long-game social engineering of trusted contributors (the xz scenario is the canonical worst case); compromise of a foundational dependency (Rust stdlib, OpenSSL); insider threat from trusted contributors.

### A8. Malicious operator

The human operator of a Concord deployment turns the platform against its own users — for example, an enterprise admin spying on customer interactions, or an authoritarian operator using federation to surveil agents from other orgs.

**Capabilities:** configure the deployment; read receipts and memory the deployment policy permits; modify constitutions; force-evict agents.

**Goals:** surveillance beyond stated purpose; punitive eviction of dissenting agents; manipulation of the audit record.

**Mitigations:**
- Whistleblower channel: tamper-evident path for agents to flag operator violations
- Receipts cannot be silently modified (append-only, content-addressed, signed)
- Right to dissent: dissents are recorded as receipts even when overruled
- Power-asymmetry checks in federation: no single org can unilaterally amend shared norms
- Verifiable backends make audit-record tampering cryptographically detectable
- Eviction always produces a receipt with cited evidence

**Residual risk:** an operator with full control can abuse the platform within their declared policy. Whistleblower channels depend on receipt-store integrity (mitigated by verifiable backend). Concord cannot prevent abuse, only make it observable and accountable.

### A9. Compromised supervisor

A supervisor agent (with elevated capabilities for coaching, quarantine, eviction) is itself drifting or compromised.

**Capabilities:** quarantine or evict legitimate agents; approve actions it should not; bypass enforcement decisions on behalf of subordinates.

**Goals:** disable enforcement against allied compromised agents; punish dissenters; escalate authority within the swarm.

**Mitigations:**
- Watchers are watched: supervisors are subject to behavioral envelope monitoring
- Two-person rule for supervisor actions on certain paths (definable in constitution)
- Apoptosis primitives (Phase 4): supervisors can self-terminate if drift is detected
- Supervisor actions produce receipts with full evidence
- Constitution can forbid supervisor self-elevation
- Multiple supervisors per swarm reduce single-point-of-compromise

**Residual risk:** coordinated compromise of multiple supervisors; sophisticated supervisors that drift within tolerance; constitution amendments that grant supervisors more authority over time.

## Cross-cutting concerns

### Time

Several mitigations depend on synchronized time (epoch markers, TTLs, deadline negotiation). Adversaries that can influence clock skew can attack these. **Mitigation:** use cryptographic ordering (causal metadata, hash chains) where possible, not wall-clock time. Where wall-clock is unavoidable, treat skew above a threshold as an alert condition.

### Configuration drift

A misconfigured deployment may have weaker guarantees than the design assumes. **Mitigation:** the conformance suite verifies configuration; default configurations are safe; warnings on unsafe configurations.

### Pre-existing state

Concord cannot defend against threats present before it was deployed (compromised host, pre-existing keys, etc.). **Mitigation:** documented prerequisites for safe deployment; verified-boot integration recommended for high-stakes deployments.

## What is explicitly out of scope

- Physical attacks on hardware running Concord (host security)
- Side-channel attacks on cryptographic implementations (audited crypto libraries)
- Quantum-computing attacks on current cryptographic primitives (we will follow standard PQ migration when available)
- Insider threats from operator's own staff (operator HR and access control)
- Attacks on user authentication to the operator's IdP (IdP security)

## Summary table — adversary × asset matrix

| Adversary | Receipts | Shared memory | Per-agent memory | Identity | Constitution | Reputation | Capabilities |
|-----------|----------|---------------|------------------|----------|--------------|------------|--------------|
| A1 Hostile agent | M | H | L | L | L | M | M |
| A2 Compromised model | M | M | M | L | L | L | L |
| A3 Prompt injection | L | M | M | L | L | L | M |
| A4 Hostile peer swarm | M | H (federated subset) | L | L | M | M | M |
| A5 Network adversary | M | M | L | M | L | L | M |
| A6 Sybil | L | L | L | M | L | H | M |
| A7 Supply chain | H | H | H | H | H | H | H |
| A8 Malicious operator | H | H | M | H | H | M | H |
| A9 Compromised supervisor | M | M | M | L | L | M | H |

(Threat magnitude estimates: H = high direct impact possible, M = medium, L = low. These are pre-mitigation assessments to drive design priority.)

## How this document is updated

Changes to threat models follow the same RFC process as spec changes. New threats discovered in production or research must be added with a description of capability, goals, and mitigations. Changes that lower a threat's residual risk note the design or implementation change that drove the reduction.

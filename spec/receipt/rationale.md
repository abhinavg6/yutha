# Receipt Spec — Design Rationale

> **Spec:** [`receipt-v1.proto`](./receipt-v1.proto)
> **Version:** v1.0 draft
> **RFC:** 0004
> **Threat-model linkage:** A1 (hostile agent attribution), A2 (compromised model attribution), A5 (network adversary), A7 (supply chain via reproducibility), A8 (malicious operator — primary defense), A9 (compromised supervisor)

## 1. What is a receipt, in one paragraph

A receipt is the canonical record of a consequential action — every envelope sent, every capability checked, every memory write, every enforcement decision, every constitution amendment. Receipts are append-only (you can add, you cannot rewrite or delete), content-addressed (the receipt's identifier is the hash of its content), and cryptographically signed (the actor signs at minimum; supervisors and the control plane countersign where the action requires it). The receipt store is the single place an auditor goes to reconstruct what happened in a swarm. It is the load-bearing wall of Yutha — every later capability (enforcement, observability, federation, dispute resolution, regulatory audit) reduces to "what do the receipts say?"

## 2. Why this shape

Three design pressures shape the receipt:

- **Append-only is the operator-defense property.** Per threat model A8, a malicious operator must not be able to silently rewrite history. Append-only + content-addressing + signing means rewriting requires either forging signatures (hard) or producing a different chain that the world has not yet seen (detectable via Merkle batching and external mirrors). The verifiable tier (Walrus + Seal + Nautilus) extends this to cryptographic detectability across organizational boundaries.

- **Content-addressing is the consistency property.** Two implementations that observe the same action produce the same receipt bytes (assuming canonical serialization, which the spec mandates). Two stores that have the same receipts are bit-identical at the receipt level. Differential conformance (build plan §10) compares receipt content-addresses across reference and candidate stacks; equality is the proof of observable equivalence.

- **Causal predecessors are the reasoning property.** The DAG of dependencies is in the receipts themselves. A counterfactual replay can trace which receipts a perturbation would invalidate. An audit can reconstruct the full causal chain leading to any decision. None of this requires log-archaeology or out-of-band metadata.

The receipt is deliberately not a "log entry" or a "trace span." It is a signed, content-addressed, durably-persisted artifact with explicit causal structure. Logs are best-effort; receipts are evidentiary.

## 3. Field-by-field rationale

**`spec_version`.** First.

**`swarm_id`.** Receipts are single-swarm. Cross-swarm receipt mutual-recognition is a Phase 4 federation construct that operates over receipts, not at the receipt-level field.

**`actor` (AgentId).** Who did the thing. For platform-internal receipts (registration, control-plane decisions), this is the control plane's own identity — yes, the control plane has a passport, and yes, that passport is signed. The control plane is not magic; it is an agent-with-extra-capabilities, and its actions are receipted exactly like any other.

**`action_kind` (string).** Canonical taxonomy of what happened. Free-form string at the wire level; the canonical taxonomy lives in `/spec/receipt/canonical-actions.md` (forthcoming alongside RFC 0004's first amendment). Initial taxonomy (non-exhaustive):

| Domain | Action kinds |
|--------|-------------|
| Envelope | `envelope.send`, `envelope.deliver`, `envelope.deliver.failed` |
| Agent | `agent.register`, `agent.rotate_key`, `agent.revoke`, `agent.heartbeat.missed` |
| Capability | `capability.issue`, `capability.attenuate`, `capability.revoke`, `capability.check.pass`, `capability.check.deny` |
| Memory | `memory.write`, `memory.read`, `memory.forget`, `memory.share` |
| Enforcement | `enforcement.detect`, `enforcement.coach`, `enforcement.quarantine`, `enforcement.evict`, `enforcement.reverse` |
| Constitution | `constitution.activate`, `constitution.amend.propose`, `constitution.amend.commit`, `constitution.amend.timeout` |
| Governance | `agent.dissent`, `operator.whistleblow`, `supervisor.override` |
| Federation (Phase 4) | `federation.handshake`, `federation.delegate`, `federation.detach` |

Free-form on the wire keeps the spec from version-bumping every time a new action kind is needed; the canonical list is maintained by the foundation/maintainers and conformance tests are written against it.

**`causal` (CausalRef).** Predecessors. Empty only for genesis. Same DAG semantics as envelope's causal field; the conformance suite verifies the DAG is preserved across registry, transport, and store.

**`evidence`.** Typed key-value pairs recording inputs/outputs of the action. The constitution evaluator's "decision evidence" (per `constitution-language.md` §13) is recorded here. Counterfactual replay (Phase 3) uses this — a replay perturbs evidence values and re-runs the deterministic decision tree.

The `sensitive` flag on Evidence is what makes selective-disclosure work in the verifiable tier. A receipt's `evidence` may contain customer PII; the receipt itself is durable and signed; selective disclosure proves the receipt exists without revealing the sensitive fields. PRD §13.3 ("Privacy by design") is implemented partly here.

**`constitution_version`.** Pinning the constitution version at decision time means a receipt remains interpretable even after the constitution is amended. This is critical for audit: a receipt from six months ago must be re-evaluable under the rules that were active then, not under whatever rules are active now.

**`cost` (CostAnnotation).** Cost transparency (PRD §13.2). Optional but encouraged. Aggregated over the swarm, this is what the meta-fleet observability (Phase 3) consumes for cost-per-task dashboards.

**`occurred_at`.** Wall-clock + monotonic. Comparison logic uses monotonic; observability uses wall-clock.

**`seal` (SealStatus).** Whether the receipt has been Merkle-batched. UNSEALED receipts are fully valid; SEALED receipts add the ability to prove inclusion via a short Merkle path. The seal is added by the receipt store, not by the producer, so producers do not need to be aware of batching policy.

**`extensions`.** Forward-compatibility hatch.

**`signatures` (SignedBy[]).** AT LEAST ONE signature is required — the actor's. The schema permits multiple signatures with different roles:

- `ACTOR`: required, the agent that performed the action.
- `CONTROL_PLANE`: countersign from the control plane that processed the action. Provides "the platform observed and accepted this" attestation; required for some action kinds (registration, enforcement) and optional otherwise.
- `SUPERVISOR`: countersign from a supervisor when the action requires two-person rule (constitution-defined; common for high-stakes actions like production deployments).
- `ATTESTATION`: verifiable-tier attestation from Nautilus or equivalent; binds the action to the hardware/enclave that produced it. Required for VERIFIABLE-tier receipts.
- `BATCH_ROOT`: when sealed, the signature over the Merkle batch root; lets external verifiers check inclusion without trusting the store operator.

The signature ordering convention in the wire encoding is ACTOR first, then CONTROL_PLANE, then SUPERVISOR (if any), then ATTESTATION (if any), then BATCH_ROOT (if sealed). Conformance tests verify this canonical order.

## 4. Threat-model linkage

| Adversary | How this spec contributes to mitigation |
|-----------|------------------------------------------|
| A1 Hostile agent | Every consequential action is attributable to its `actor`; the causal DAG makes blast-radius reconstructable; evidence makes review of specific decisions possible. |
| A2 Compromised model | `cost.model_provider`, `cost.model_name`, `cost.model_version` per receipt make cross-agent correlation by model possible; per-role envelope detection consumes this. |
| A5 Network adversary | Content-addressing means replayed receipts have identical IDs and are dedup-detectable; signatures make tampering structurally impossible without key compromise. |
| A7 Supply chain | Receipts produced by a backdoored implementation that diverges from canonical serialization will produce different content-addresses than the reference; differential conformance catches this nightly. |
| A8 Malicious operator | The single most important spec for A8. Append-only + content-addressed + signed + verifiable-tier-Merkle-rooted. Operator-side tampering is structurally detectable; whistleblower channel uses receipt semantics that the operator cannot silently disable. |
| A9 Compromised supervisor | Supervisor actions produce receipts with `SIGNATURE_ROLE_SUPERVISOR`; two-person-rule constitution clauses require those receipts; supervisor envelope detection (Phase 3) reads supervisor-action receipts as a primary signal. |

## 5. Conformance hooks

A conformant receipt-store implementation:

- **Append.** Accepts AppendRequest; produces AppendResponse with the content-address of the persisted receipt. Verifies all signatures before persistence. Rejects receipts whose content-address (after re-canonicalization) does not match a recomputed hash.
- **Persist durably.** Sequential append is durable across process restart (Core).
- **Content-address consistency.** Two appends of receipts that canonically serialize to identical bytes produce the same receipt_id and the second is idempotent (no duplicate, returns the existing ID).
- **Tamper detection.** Receipt mutation is structurally impossible (append-only API); attempts to update return spec'd errors.
- **Causal queries.** by_receipt_id (Core), by_predecessor (Core+), by_agent + by_action_kind + by_time (Full).
- **Bulk export with verifiable manifest** (Full).
- **Sealing** (optional in Full; required in Verifiable). Periodic Merkle-batching with batch-root signing.
- **Selective disclosure** (Verifiable). Reveal a single receipt with proof of inclusion without revealing the rest of the chain.

`/conformance/interface/receipts/` covers each level. The Verifiable tier (cross-org mutual-recognition) is exercised in the federation behavioral scenario S5.

## 6. Why content-addressing is non-negotiable

Several alternatives were considered: monotonic sequence numbers per actor (simpler but require trust in sequence assignment), database-generated UUIDs (no integrity binding), wall-clock timestamps (clock-skew-fragile). All were rejected because they break two properties we need:

- **Cross-store equality.** Two stores with the same actions must produce the same receipts. Sequence numbers and database UUIDs differ by store. Content-addressing is naturally identical.
- **Causal references that survive store replication.** A receipt that names predecessors by content-address can be replicated, mirrored, federated, and exported without the predecessor pointers becoming dangling. Sequence-number-based references break the moment you change stores.

Content-addressing also gives us "two implementations that produce identical actions produce identical receipts" for free, which is what differential conformance needs.

## 7. Sealing and the verifiable tier

Sealing is a write-time operation that batches recent receipts into a Merkle tree, signs the root, and stores the path from each receipt to the root. The cost is one extra signature per batch and one Merkle path stored per receipt; the benefit is that an external verifier can:

- Check inclusion of a single receipt with O(log N) bytes.
- Verify the integrity of a million-receipt batch by checking one signature.
- Selectively disclose one receipt without revealing the others (the path doesn't expose siblings' contents — only their hashes).

Sealing is optional at Core/Full and required at Verifiable. Phase 4 federation requires Verifiable for cross-org mutual recognition — that is what makes "regulator signs off on a Yutha-deployed swarm using only Yutha-produced artifacts" achievable (PRD §11.4).

## 8. Why receipts are at-least-once-signed and ordered-multi-sig

Some receipts have only the actor's signature: routine envelope sends, normal capability passes, reads. Others require multiple signatures: enforcement decisions need control-plane countersign; two-person-rule actions need supervisor countersign; verifiable-tier receipts need attestation. Rather than have a separate message kind per countersign pattern, we have one receipt with an ordered repeated SignedBy field.

Ordering matters for verification: the canonical signature order is ACTOR → CONTROL_PLANE → SUPERVISOR → ATTESTATION → BATCH_ROOT. Each later signer signs over the receipt-with-previous-signatures-included, which means the chain is verifiable in order without relitigating prior signatures.

This pattern is general enough that future signature roles (federation-peer countersign, dispute-mediator countersign) can be added without breaking the wire format.

## 9. Alternatives considered

**Hash chain (each receipt links to the previous).** Rejected: enforces a total order that does not exist in a multi-actor swarm. Causal DAG is the right structure.

**Receipts as OpenTelemetry spans.** Rejected for the receipt layer; OTEL is the *observability* path (Phase 3) and consumes receipts as a data source. Receipts are evidentiary; spans are diagnostic.

**Embedding the previous receipt's content fully (rather than hash).** Rejected: storage explosion. Hashes plus a working store give the same property at a fraction of the cost.

**Receipt format that allows mutability with version history.** Rejected categorically: the operator-defense property requires immutability. Mutability is modeled as append-of-correction-receipt, never as in-place update.

**Receipts written by the agent itself rather than by the control plane.** Rejected for v1: the control plane is the integrity boundary. Future ADR may revisit for fully-decentralized peer-to-peer swarms (Phase 4+ research).

## 10. Open questions for RFC review

- Canonical action-kind taxonomy — should it be a closed enum (rejected currently) or maintained as a separate registry document? Currently the latter; need to publish the registry as v1.0 ships.
- Evidence schemas — should we ship canonical Evidence shapes (e.g. CapabilityCheckEvidence, EnforcementEvidence) inline in this spec or as separate spec docs? Leaning separate docs.
- Per-receipt encryption — should `evidence.value` support encrypted bytes natively (with key reference) or always be plaintext at the receipt layer with encryption at the store layer? Currently always plaintext; encrypted-at-rest is store-layer.
- Sealing latency budget — what is the spec'd maximum delay between receipt acknowledgement and seal? Currently no spec; needs setting before Phase 2.
- Cross-store replication — should the spec define a wire format for replicating receipts between stores (for HA, geo-redundancy)? Probably yes for v1.x; out of v1.0 scope.

## 11. Future evolution

- v1.1 likely standardizes selective-disclosure proof format for Verifiable tier.
- v1.x adds canonical Evidence shapes for the most common action kinds.
- v2.0 may revisit the actor-required-signature model if peer-to-peer swarms (no control plane) become a target use case.

# Canonical Action Kinds

> **Repo location:** `/spec/receipt/canonical-actions.md`
> **Status:** Living registry; entries added as the substrate produces them.
> **Owners:** Workstream A (Specs)

This document is the canonical list of `action_kind` strings that conformant Yutha receipts use. The receipt spec ([`/spec/receipt/receipt-v1.proto`](./receipt-v1.proto), [rationale §3](./rationale.md)) defines `action_kind` as a free-form string at the wire level; this registry is the maintained vocabulary that the conformance suite tests against and the canonical schemas in Phase 2 build on.

Conformant implementations **MUST** use these strings when they produce receipts for the listed actions, and **MUST NOT** invent new action kinds without an RFC.

---

## Domain: Agent lifecycle

| `action_kind` | Producer | Actor | Notes |
|---------------|----------|-------|-------|
| `agent.register` | Registry (control plane) | Control plane | Produced when an agent's passport is admitted into a swarm. Evidence includes `passport_agent_id` and `passport_hash` (the content-address of the registered passport). |
| `agent.revoke` | Registry (control plane) | Control plane | Produced when an agent's membership is terminated. Evidence: `agent_id`, `reason`. |
| `agent.rotate_key` | Registry (control plane) | Control plane | Produced when an agent rotates its signing key. Evidence: `agent_id`, `old_key_fingerprint`, `new_key_fingerprint`, continuity signature. |
| `agent.heartbeat.missed` | Registry | Control plane | Optional. Produced when an agent fails to heartbeat within the policy window. |

## Domain: Envelope

| `action_kind` | Producer | Actor | Notes |
|---------------|----------|-------|-------|
| `envelope.send` | Transport | Sender agent | One per successful envelope send. Evidence: `envelope_hash`. |
| `envelope.deliver` | Transport | Recipient agent | One per successful envelope delivery. Evidence: `envelope_hash`, optionally `delivery_latency_ms`. |
| `envelope.deliver.failed` | Transport | Recipient agent | One per delivery failure (replay, expired, signature failure, recipient unknown). Evidence: `envelope_hash`, `failure_reason`. |

## Domain: Capability

| `action_kind` | Producer | Actor | Notes |
|---------------|----------|-------|-------|
| `capability.issue` | Capability store | Issuer (operator / agent / control plane) | One per fresh capability mint. Evidence: `capability_hash`, `subject`, `scope_digest`. |
| `capability.attenuate` | Capability store | Attenuating holder (agent) | One per attenuated child. Evidence: `parent_hash`, `child_hash`. |
| `capability.revoke` | Capability store | Issuer or operator | Evidence: `capability_hash`, `reason`. |
| `capability.check.pass` | Control plane | Subject agent | One per successful capability check at an action point. Evidence: `capability_hash`, `action_descriptor_digest`. |
| `capability.check.deny` | Control plane | Subject agent | One per denied check. Evidence includes the deny_reason and unmet caveats. |

## Domain: Memory (Phase 2)

| `action_kind` | Producer | Actor | Notes |
|---------------|----------|-------|-------|
| `memory.write` | Memory layer | Writing agent | Evidence: `memory_key`, `scope_digest`. |
| `memory.read` | Memory layer | Reading agent | Evidence: `memory_key`, `scope_digest`. |
| `memory.forget` | Memory layer | Writing agent or operator | Evidence: `memory_key`. |
| `memory.share` | Memory layer | Writing agent | Cross-scope share. Evidence: `memory_key`, `from_scope`, `to_scope`. |

## Domain: Enforcement (Phase 2)

| `action_kind` | Producer | Actor | Notes |
|---------------|----------|-------|-------|
| `enforcement.detect` | Constitution engine | Control plane | A norm violation was detected. Evidence: violation type, evidence digest. |
| `enforcement.coach` | Constitution engine | Control plane | Coaching feedback sent to a drifting agent. |
| `enforcement.quarantine` | Constitution engine | Control plane | An agent has been quarantined (reversible). |
| `enforcement.evict` | Constitution engine | Control plane | An agent has been evicted (irreversible). Highest-stakes; supervisor countersign required. |
| `enforcement.reverse` | Constitution engine | Control plane | An enforcement decision was reversed. |

## Domain: Constitution (Phase 2 + Phase 4)

| `action_kind` | Producer | Actor | Notes |
|---------------|----------|-------|-------|
| `constitution.activate` | Constitution engine | Operator | A new constitution version is now active. |
| `constitution.amend.propose` | Constitution engine | Proposer | An amendment has been proposed. |
| `constitution.amend.commit` | Constitution engine | Control plane | A proposed amendment passed quorum and is now active. |
| `constitution.amend.timeout` | Constitution engine | Control plane | A proposed amendment timed out without quorum. |

## Domain: Governance

| `action_kind` | Producer | Actor | Notes |
|---------------|----------|-------|-------|
| `agent.dissent` | Any agent | Dissenting agent | An agent has flagged disagreement with an enforcement decision. PRD §13.3 right to dissent. |
| `operator.whistleblow` | Any agent | Whistleblowing agent | An agent has flagged operator misconduct. PRD §13.3 whistleblower channel. |
| `supervisor.override` | Supervisor agent | Supervisor | A supervisor has overridden a decision. Two-person rule may apply. |

## Domain: Federation (Phase 4)

| `action_kind` | Producer | Actor | Notes |
|---------------|----------|-------|-------|
| `federation.handshake` | Federation handshake | Federating control plane | A federation handshake completed. |
| `federation.delegate` | Federation handshake | Federating control plane | Bounded delegation issued. |
| `federation.detach` | Federation handshake | Federating control plane | Clean federation detachment. |

---

## How this registry evolves

- **Adding a new action kind** requires an RFC (per [RFC 0001](../rfcs/0001-rfc-process.md)) — minor change to the receipt spec; backward-compatible.
- **Removing an action kind** requires a major-version bump on the receipt spec, with a 12-month deprecation window.
- **Renaming** is treated as add-new + deprecate-old.
- **Evidence-shape changes** for an existing action kind are typically minor — the receipt spec's `Evidence` field is open by construction. Document the evidence shape in this file when you add one.

## Phase mapping

The Phase 1 substrate produces receipts in the Agent lifecycle, Envelope, and Capability domains only. The other domains land as their respective workstreams ship (Phase 2 enforcement + constitution + memory; Phase 4 federation; governance receipts begin in Phase 2 and mature through Phase 4).

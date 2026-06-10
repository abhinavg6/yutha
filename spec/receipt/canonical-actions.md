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
| `agent.register` | Registry (control plane) | Control plane | Produced when an agent's passport is admitted into a swarm. Evidence: `passport_agent_id`, `passport_hash` (content-address of the registered passport). Since RFC 0016 also: `attested_external_identity` (the IdP-side identifier the configured Attestor verified — `yutha:native:<hex>` on the native path, `spiffe://…` on SPIRE, `okta:user@…` on OIDC), `attestor_id` (the short identifier from `Attestor::id()` — `"native"`, `"spiffe"`, `"oidc:<instance>"`), plus optional `attributes.<key>` entries copied from `AttestedIdentity.attributes` (workload selectors on SPIFFE, selected ID-token claims on OIDC; empty on native). |
| `agent.register.deny` | Registry (control plane) | Control plane | Produced when a registration is rejected by the configured Attestor (RFC 0016 §3.4) or by swarm_id binding. Evidence: `claimed_agent_id` (bytes — the agent_id from the rejected request), `attestor_id` (string — the Attestor that ran, or `"unattested"` if the rejection was substrate-side before the Attestor was called), `deny_reason` (string — short reason). Mirrors `capability.check.deny`'s pattern; operators monitor for both debugging integration issues and noticing attack attempts. |
| `agent.revoke` | Registry (control plane) | Control plane | Produced when an agent **self-revokes** via `AdmissionService.Revoke`. Evidence: `agent_id`, `reason`. Operator-driven evictions land as `agent.operator_revoke` (see RFC 0009). |
| `agent.operator_revoke` | Registry (control plane) | Control plane | Produced when an operator evicts an agent via `AdmissionService.OperatorRevoke` (RFC 0009). Evidence: `target_agent_id`, `operator_id`, `reason`, optional `cascade_receipt_ids` for capabilities revoked in the same operation. |
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
| `enforcement.detect` | Constitution engine | Control plane | A receipt-stream pattern matched the trigger of an active `enforcement_rules` entry (RFC 0013 §2). Evidence: `enforcement_rule_id`, `target_agent_id`, `matched_receipt_ids[]` (the receipts that completed the pattern), `pattern_summary` (human-readable), `constitution_hash`, `reputation_delta` (Decimal). |
| `enforcement.coach` | Constitution engine | Control plane | After a detect plus rule-defined cooldown, the engine sent an `ADVISE` envelope to the offending agent (RFC 0013 §3). Evidence: `enforcement_rule_id`, `target_agent_id`, `detect_receipt_id` (predecessor), `coaching_envelope_id` (the `envelope.send` receipt for the ADVISE), `constitution_hash`, `reputation_delta`. |
| `enforcement.quarantine` | Constitution engine | Control plane | An agent has been quarantined (reversible) (RFC 0013 §4). Evidence: `enforcement_rule_id`, `target_agent_id`, `coach_receipt_id` (optional — absent when rule allows skip), `expires_at_wall_clock` (optional — RFC 3339; absent means indefinite), `constitution_hash`, `reputation_delta`. Cap-check and cap-issuance MUST consult this state and deny if quarantined. |
| `enforcement.evict` | Constitution engine | Control plane | An agent has been evicted (irreversible) (RFC 0013 §5). Drives `AdmissionService.OperatorRevoke` with `cascade_capabilities=true` per RFC 0009. Evidence: `enforcement_rule_id`, `target_agent_id`, `quarantine_receipt_id` (optional), `substrate_revoke_receipt_id` (the `agent.operator_revoke` receipt this drove), `cascade_revoke_receipt_ids[]`, `constitution_hash`, `reputation_delta`, `supervisor_countersign` (a second signature from a supervisor-tier agent — REQUIRED by default; constitutions MAY waive per rule). Receipt MUST NOT land until the countersign is present. |
| `enforcement.reverse` | Constitution engine (auto) or operator-bearer agent (manual) | Control plane or operator | A non-terminal enforcement stage (detect / coach / quarantine) was reversed (RFC 0013 §6). Eviction is NOT reversible. Evidence: `enforcement_rule_id`, `target_agent_id`, `reversed_receipt_id`, `reversed_stage` (`"detect"` \| `"coach"` \| `"quarantine"`), `reason` (free-form string), `constitution_hash`, `reputation_delta` (typically positive — partial restoration), `operator_signature` (present when manually triggered by an operator-bearer agent). |
| `enforcement.evict_timeout` | Constitution engine | Control plane | A pending `enforcement.evict` was abandoned because no supervisor countersign arrived within the timeout (default 1 hour). Evidence: `enforcement_rule_id`, `target_agent_id`, `pending_evict_canonical_hash` (the would-be evict receipt's content-address), `timeout_wall_clock` (RFC 3339). |

## Domain: Constitution (Phase 2 + Phase 4)

| `action_kind` | Producer | Actor | Notes |
|---------------|----------|-------|-------|
| `constitution.activate` | Constitution engine | Operator | A new constitution version is now active. Used both for genesis activation (bootstrap of a swarm's first constitution) and for amend-driven transitions. Evidence: `constitution_hash`, `constitution_version`, `parent_version` (empty for genesis), `schema_version`. |
| `constitution.evaluate.pass` | Constitution engine | Subject agent | One per successful Cedar+ evaluation at an action gate (RFC 0010). Evidence: `constitution_hash`, `action_kind`, `action_descriptor_digest`, `matched_rule_ids` (the Cedar policy ids that contributed to the permit), `input_attribute_digest`. **When `prefer` rules contributed (RFC 0011)**, evidence additionally carries `score_contributions: list<(rule_id, score: Decimal)>` and `total_score: Decimal`; both fields are absent when no `prefer` rule applied. |
| `constitution.evaluate.deny` | Constitution engine | Subject agent | One per denied evaluation. Evidence includes `deny_reason`, the offending `forbid_rule_id` if applicable, and the `input_attribute_digest`. `deny_reason` is one of: `forbid_rule_matched`, `no_permit_rule`, `evaluation_depth_exceeded`, `schema_version_unsupported`, `evaluator_internal_error` (RFC 0010); plus the sandbox-bound reasons `evaluation_time_exceeded`, `entity_store_size_exceeded`, `scoring_rule_count_exceeded`, `procedure_count_exceeded`, `open_procedure_instance_count_exceeded`, `policy_count_exceeded`, `policy_depth_exceeded`, `procedure_transition_ambiguous`, `request_shape_invalid`, `entity_unresolved`, `constitution_unresolved` (RFC 0012). Load-time bounds (`scoring_rule_count_exceeded`, `procedure_count_exceeded`, `policy_count_exceeded`, `policy_depth_exceeded`) primarily refuse `constitution.activate` rather than landing as evaluate-deny; the evaluate-deny path is the runtime fallback for activations that bypassed loader validation. **Since RFC 0018 (Phase 3b shadow-mode):** when a shadow constitution is configured at the moment of evaluation, this receipt's evidence additionally carries `shadow_constitution_hash` — the content-address of the shadow slot's constitution, for joining active + shadow receipts that observed the same envelope. Absent when no shadow is configured. |
| `constitution.evaluate.shadow.pass` | Constitution engine | Subject agent | One per successful shadow-constitution evaluation when a shadow slot is configured (RFC 0018 §3.4). Evidence: `shadow_constitution_hash`, `action_kind`, `matched_rule_ids`, `input_attribute_digest`, `subject_agent_id`, `total_score` (Decimal — only when shadow `prefer` rules contributed). Emitted in the same Send path as the active `constitution.evaluate.pass` receipt; ordering is active-then-shadow. **Engine MUST NOT react to this receipt** — shadow is observation-only per RFC 0018 §3.5. |
| `constitution.evaluate.shadow.deny` | Constitution engine | Subject agent | One per denied shadow-constitution evaluation. Same evidence as the pass variant plus `deny_reason`. `deny_reason` shape mirrors `constitution.evaluate.deny` and additionally includes the special value `"shadow_schema_incompatible"` for cases where the shadow's schema-version differs from the active's and the shared entity snapshot violates the shadow's strict-mode validation (RFC 0018 §3.3). **Engine MUST NOT react to this receipt.** |
| `constitution.shadow_activate` | Constitution engine | Operator | A new shadow constitution has been activated (RFC 0018 §3.2). Evidence: `shadow_constitution_hash`, `shadow_constitution_version`, `parent_active_constitution_hash` (the active at the moment of shadow activation), `schema_version`. Operator-bearer-authenticated, same auth model as `constitution.activate`. Replacing an existing shadow with a new one emits one shadow_activate receipt (the prior shadow is discarded without a separate clear receipt). |
| `constitution.shadow_clear` | Constitution engine | Operator | The shadow slot has been cleared (RFC 0018 §3.2). Evidence: `previously_shadowed_constitution_hash` (absent when the slot was already empty at the time of call — the RPC is idempotent and the receipt records the operator's intent regardless). |
| `constitution.shadow_promote` | Constitution engine | Operator | A shadow constitution has been promoted to active atomically (RFC 0018 §3.2). Evidence: `from_active_constitution_hash`, `to_active_constitution_hash` (the previous shadow's hash, which now addresses the new active), `to_constitution_version`, `schema_version`. Distinct from `constitution.activate` for audit clarity — auditors want to know whether a constitution arrived via direct activation or via shadow-preview-then-promote (mirrors `agent.operator_revoke` vs `agent.revoke` precedent). On promote: engine reputation + quarantine state preserved across agents; sliding-window counters reset (matches `EnforcementEngine::activate` posture). |
| `constitution.amend.propose` | Constitution engine | Proposer | An amendment has been proposed. |
| `constitution.amend.commit` | Constitution engine | Control plane | A proposed amendment passed quorum and is now active. Evidence includes the diff (`from_constitution_hash` → `to_constitution_hash`) and, when the amendment also bumps the schema, `from_schema_version` → `to_schema_version`. |
| `constitution.amend.timeout` | Constitution engine | Control plane | A proposed amendment timed out without quorum. |
| `procedure.enter` | Constitution engine | Subject agent | A request matched a procedure's trigger; new instance spawned (RFC 0011 §3). Evidence: `procedure_name`, `instance_id` (content-addressed over `(procedure_name, triggering_action_descriptor_digest, swarm_id, current_wall_clock)`), `triggering_action_descriptor_digest`, `initial_state`. |
| `procedure.transition` | Constitution engine | Transition-actor agent | A procedure transition fired (RFC 0011 §3). Evidence: `instance_id`, `from_state`, `to_state`, `transition_actor` (AgentId), `transition_action_descriptor_digest`. |
| `procedure.timeout` | Constitution engine | Control plane | A procedure timeout fired before any other transition (RFC 0011 §3). Evidence: `instance_id`, `state_at_timeout`, `timeout_wall_clock` (RFC 3339), `timeout_value` (e.g. `"1.hour"`). |
| `procedure.escalate` | Constitution engine | Control plane | A terminal state's `escalate to` clause fired (RFC 0011 §3). Evidence: `from_procedure_name`, `from_instance_id`, `to_procedure_name`, `to_instance_id`. |

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

## Domain: Verifiability (Phase 3)

| `action_kind` | Producer | Actor | Notes |
|---------------|----------|-------|-------|
| `anchor.commit` | Sealer | Control plane | One per successfully-confirmed Sui anchor transaction (RFC 0014). Evidence: `batch_root` (32-byte hex), `batch_index` (u64; the value of `SwarmAnchor.batch_count` BEFORE this commit), `count` (u64), `ns_range_start`, `ns_range_end`, `on_chain_tx_digest` (32-byte Sui tx digest), `swarm_anchor_object_id` (32-byte Sui shared-object id), `action_kind_histogram` (canonical histogram bytes per `/spec/verifiability/sui-anchoring.md` §4.1, hex-encoded), `anchored_at_wall_clock` (RFC 3339). Signed by the control plane only — no Actor signature, since the anchor is a substrate operation, not an agent action. The `anchor.commit` receipt is itself anchorable in a later batch (the audit trail of "when we anchored" is part of the audit trail). |

---

## How this registry evolves

- **Adding a new action kind** requires an RFC (per [RFC 0001](../rfcs/0001-rfc-process.md)) — minor change to the receipt spec; backward-compatible.
- **Removing an action kind** requires a major-version bump on the receipt spec, with a 12-month deprecation window.
- **Renaming** is treated as add-new + deprecate-old.
- **Evidence-shape changes** for an existing action kind are typically minor — the receipt spec's `Evidence` field is open by construction. Document the evidence shape in this file when you add one.

## Phase mapping

The Phase 1 substrate produces receipts in the Agent lifecycle, Envelope, and Capability domains only. The other domains land as their respective workstreams ship (Phase 2 enforcement + constitution + memory; Phase 4 federation; governance receipts begin in Phase 2 and mature through Phase 4).

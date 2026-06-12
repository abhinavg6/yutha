# RFC 0010: Constitution Language v1.0 — Cedar+ Schema Spec

> **Status:** Draft
> **Authors:** Workstream A (Specs) + Workstream E (Constitution engine)
> **Filed:** 2026-05-15
> **Targets spec:** `/spec/constitution/` (new directory at v1.0)
>                   `/spec/receipt/canonical-actions.md` (adds `constitution.evaluate.{pass,deny}`)
> **Targets phase:** Phase 2 (Coordination & Norms)
> **Discussion:** TBD
> **Companion RFCs (follow-on):** 0011 (Cedar+ extensions), 0012 (Evaluation model + sandbox), 0013 (Four-stage enforcement loop)

## 1. Summary

Introduces `/spec/constitution/` to the Yutha spec surface. The directory ships the **canonical Cedar+ schema** at v1.0 — five entity types (`Agent`, `Swarm`, `Capability`, `Envelope`, `Resource`) and four action types (`SendEnvelope`, `IssueCapability`, `AttenuateCapability`, `RevokeCapability`) — plus the design rationale, the policy-evaluation receipt action-kinds, and the directory README pointing forward to RFCs 0011-0013.

This is the first of four spec-stage RFCs that build out Phase 2. RFC 0010 establishes the Cedar+ surface and the schema-stability contract. Subsequent RFCs add language extensions (0011), evaluation semantics + sandbox (0012), and the four-stage enforcement loop (0013). Code lands after the spec quartet closes.

RFC 0010 also closes the two schema-side open questions flagged in `/docs/internal/constitution-language.md`: schema authoring posture (operators extend canonical schemas by signed delta; bespoke schemas are a v1.1+ relaxation), and schema evolution semantics (constitutions pin a schema version at bootstrap and evaluate under that version forever, unless an amendment also bumps the version).

## 2. Motivation

Phase 1 substrate is complete: identity (passport), typed messaging (envelope), capability-based authority (with send-path enforcement, wall-clock validity, operator credentials), and the receipt fabric. What the substrate does NOT yet provide is the **norm layer** — the swarm-level policy that says "this agent MAY hold a `envelope.send` capability, but the swarm's norms forbid sending to recipient X under condition Y." Capabilities answer who has authority; constitutions answer what the swarm permits authority to be exercised on.

Three concrete cases unblocked by this layer:

1. **Topology-aware admission.** An open-mode swarm needs to gate registration on sybil-resistance proofs that vary with current pressure (e.g. proof-of-compute when registration rate exceeds N/hour). Capabilities can encode "the agent passed the proof"; constitutions decide what proof is currently required.
2. **Workload-shape policies.** A customer-support swarm in queue-mode has norms ("escalate after the third unresolved exchange", "supervisors must countersign refunds above $500") that aren't naturally expressible as capability caveats — they're conditional logic over the action descriptor and current state.
3. **Auditable norm changes.** PRD §13.3's "right to dissent" and "whistleblower channel" require that operators changing norms produce an audit trail. Constitution amendments are content-addressed and receipt-emitting; an operator cannot silently reshape the swarm's policy.

The capability rationale already calls out the split: `/spec/capability/rationale.md` §2 says "Caveats over policy languages. Capabilities are decidable on their own... Constitution norms (Cedar+) live one layer up." This RFC stands up that one-layer-up surface.

## 3. Detailed design

### 3.1 Directory layout

```
spec/constitution/
├── README.md             # added by this RFC
├── schema.cedarschema    # added by this RFC — canonical schema
├── rationale.md          # added by this RFC
├── extensions.md         # added by RFC 0011
├── evaluation.md         # added by RFC 0012
├── enforcement.md        # added by RFC 0013
└── canonical-schemas/    # added by F8 sub-stage of build-plan §7
    ├── v1.0.0/
    │   ├── support-queue.cedarschema
    │   ├── incident-response.cedarschema
    │   ├── closed-baseline.cedarschema
    │   ├── open-baseline.cedarschema
    │   └── hybrid-baseline.cedarschema
    └── ...
```

This RFC delivers the first three files. The `canonical-schemas/` subdirectory is version-namespaced (`v1.0.0/`, `v1.1.0/`, ...) per §3.4 below.

### 3.2 The schema at v1.0

The full `schema.cedarschema` is in this RFC's companion artifact at [`/spec/constitution/schema.cedarschema`](../constitution/schema.cedarschema). The shape:

**Entity types:**

| Type | Parent relation | Purpose |
|------|-----------------|---------|
| `Agent` | `in [Swarm]` | A registered agent. Attributes: `agent_id`, `passport_tier`, `framework`, `passport_hash`, `reputation: Decimal`. The `in` relation lets policies write `principal in Yutha::Swarm::"..."`. |
| `Swarm` | (none) | The swarm itself. Attributes: `swarm_id`, `topology_mode`, `constitution_version`. |
| `Capability` | `in [Agent]` | An authority token. Attributes: `capability_id`, `capability_hash`, `subject`, `scope_action_kinds: Set<String>`. |
| `Envelope` | (none) | A typed message. Attributes: `envelope_id`, `envelope_hash`, `from_agent`, `recipient_kind`, `recipient_value`, `performative`, `payload_schema_id`, `tags: Set<String>`, `epoch: Long`. |
| `Resource` | (none) | Generic resource (memory, tool, external endpoint). Attributes: `resource_kind`, `scope`, `tags: Set<String>`. v1.0 admits the type but no v1.0 action takes it as a target. |

**Action types** (each gates a single control-plane RPC 1:1):

| Action | Principal | Resource | Context fields |
|--------|-----------|----------|----------------|
| `SendEnvelope` | `Agent` | `Agent` or `Envelope` | `performative`, `payload_schema_id`, `tags`, `capability_id`, time fields |
| `IssueCapability` | `Agent` | `Agent` | `issuer_kind`, `scope_action_kinds`, time fields |
| `AttenuateCapability` | `Agent` | `Capability` | `child_scope_action_kinds`, time fields |
| `RevokeCapability` | `Agent` | `Capability` | `revoker_kind`, `reason`, time fields |

Every action context carries `current_time_unix_ns: Long` and `current_wall_clock: String` so policies that depend on time can resolve it without the evaluator reading the clock itself. RFC 0008's wall-clock convention applies: time-comparison policies use `current_wall_clock`.

The synthesizer for each action is bound at the gRPC handler in `yutha-control-plane`: `EnvelopeHandler::send` synthesizes the `SendEnvelope` context after the capability check passes; the three capability actions are synthesized inside the respective `CapabilityHandler` RPCs. The evaluator is invoked AFTER the capability layer succeeds and BEFORE the action is allowed to land — both checks must pass.

### 3.3 What's intentionally absent at v1.0

This RFC freezes the surface area at the minimum that maps 1:1 to the existing substrate RPCs. Memory operations (`memory.read` / `memory.write` action types and the `Memory` entity), tool calls (the `ExternalEndpoint` entity), and the enforcement-stage transitions (`Detect` / `Coach` / `Quarantine` / `Evict`) arrive in subsequent RFCs:

| Subsequent RFC | Adds |
|----------------|------|
| **0011** Cedar+ extensions | Memory + tool entities/actions; `prefer`, `procedure`, resource-budgets, memory-norm keywords; decidability proofs per extension |
| **0012** Evaluation model + sandbox | No new actions; refines the evaluator contract, deterministic semantics, bounded resources |
| **0013** Four-stage enforcement loop | `DetectViolation`, `CoachAgent`, `QuarantineAgent`, `EvictAgent` action types; integration with capability revocation and operator-revoke from RFC 0009 |

This staging means RFC 0010 alone is **not enough for a working evaluator** — the language is too narrow to express interesting policies until 0011 lands the extensions, and the evaluator contract isn't yet rigorous until 0012. RFC 0010 deliberately stops at the schema-and-conformance-hooks layer because that's the load-bearing contract everything else depends on.

### 3.4 Schema authoring posture

**Yutha ships canonical schemas; operators extend by signed delta. Fully bespoke schemas are deferred to v1.1+.** Three rules:

1. The base schema (this RFC) is the only schema that defines entity *types* and action *types*. Operators may not add new types in v1.0.
2. Workload-extending canonical schemas (added in F8 sub-stage) MAY add type-level extensions and constrain attributes. They live under `/spec/constitution/canonical-schemas/v<spec-version>/<workload>.cedarschema` and are themselves part of the public spec.
3. Operators MAY author a **schema delta** that adds attributes to existing types (never modifies, never removes). The delta references a canonical schema by content-address, is itself content-addressed and signed, and the effective schema seen by the evaluator is `canonical ∪ delta`.

The delta-only restriction means: the substrate's marshalling code only needs to populate attributes the canonical schemas declare; it can't be surprised by an operator demanding attributes it has no source for. v1.1+ may relax this once `yutha-cedar-plus` exposes a marshaller-discovery interface — see §6 below.

The static analyzer (RFC 0012) is the enforcement point. Constitutions whose effective schema cannot be expressed as `canonical ∪ delta` are refused at validation time.

### 3.5 Schema evolution semantics

**Constitutions pin a schema version at bootstrap; the evaluator loads that pinned version.** Concrete rules:

1. Every constitution artifact carries `schema_version: String` (semver, e.g. `"1.0.0"`). The genesis constitution sets this to the version it was authored against.
2. The evaluator MUST load schemas at the constitution's pinned version. Schema files are version-namespaced under `canonical-schemas/v<version>/`.
3. **Minor schema bump** (`1.0` → `1.1`): adds new entity types, new actions, or new optional attributes. Existing constitutions pinned at `1.0` continue to evaluate under their schema; new constitutions can pin `1.1` to use the new vocabulary.
4. **Major schema bump** (`1.x` → `2.0`): MAY rename or remove attributes. Constitutions still pinned at `1.x` continue to evaluate during the 12-month deprecation window (per `/spec/README.md` §3); after the window, the evaluator MAY refuse with `constitution.evaluate.deny: schema_version_unsupported`.
5. Amending a constitution MAY also amend its `schema_version`. The transition is recorded in the `constitution.amend.commit` receipt's evidence (`from_schema_version` → `to_schema_version`).

The split between schema versioning and constitution versioning is deliberate: constitution version reflects swarm policy history; schema version reflects substrate vocabulary. A swarm may amend its constitution dozens of times without ever bumping schema.

### 3.6 Receipt action-kinds (added to `/spec/receipt/canonical-actions.md`)

Two new action-kinds in the `Constitution` domain:

- **`constitution.evaluate.pass`** — One per successful Cedar+ evaluation at an action gate. Evidence: `constitution_hash`, `action_kind`, `action_descriptor_digest`, `matched_rule_ids`, `input_attribute_digest`.
- **`constitution.evaluate.deny`** — One per denied evaluation. Evidence: `constitution_hash`, `action_kind`, `action_descriptor_digest`, `deny_reason` (`forbid_rule_matched` | `no_permit_rule` | `evaluation_depth_exceeded` | `schema_version_unsupported` | `evaluator_internal_error`), `forbid_rule_id` (optional, present when reason is `forbid_rule_matched`), `input_attribute_digest`.

The existing pre-allocated `constitution.activate` kind is also clarified in this RFC: it's used for BOTH genesis activation (the swarm's first constitution coming into force) AND amend-driven transitions. Evidence extended to include `parent_version` (empty for genesis), `constitution_version`, and `schema_version`. The amend-driven case additionally produces a `constitution.amend.commit` receipt; both land in the same logical transaction.

The full updated table is in `/spec/receipt/canonical-actions.md` under the `Constitution` domain.

## 4. Conformance hooks

This RFC introduces hooks that the language conformance sub-suite (added at F2-F4) will test. Summarized inline; full set in [`rationale.md`](../constitution/rationale.md) §7.

- **Load.** Verify signature, verify parent-version chain, verify static analyzer accepts under pinned schema.
- **Activate.** Persist; emit `constitution.activate` receipt; transition `Swarm.constitution_version`.
- **Evaluate.** Compile Cedar+ to decision tree; evaluate against `(principal, action, resource, context)`; produce permit/forbid + matched-rule evidence; emit `constitution.evaluate.{pass,deny}` receipt.
- **Default-deny + bounded evaluation.** Empty policies, ambiguous matches, depth-exceeded all deny with explicit reason.
- **Schema version honored.** Per §3.5.
- **Receipt determinism.** Same inputs → identical decision + evidence + receipt content-address across implementations.

## 5. Threat-model linkage

Recapped from [`rationale.md`](../constitution/rationale.md) §6. The constitution layer is the primary defense against:

- **A4 (deceptive norm authorship)** — static analyzer rejects unsafe predicates regardless of authoring source; LLM is build-time-only and unreachable from the evaluator (CI-enforced invariant).
- **A7 (norm drift)** — every amendment is signed, content-addressed, receipt-emitting; drift becomes auditable.

And contributes to the bounded defense of A1, A3 (secondary to capabilities), A6, A9. See `/docs/internal/threat-model.md` for the full adversary set.

## 6. Open questions for review

- **Canonical schema launch set at v1.0.** Currently proposed: `support-queue`, `incident-response`, plus three topology-mode baselines. Should `campaign-mode` also land at v1.0? Decision can be made in F8.
- **Cross-swarm policy references.** v1.0 evaluators MAY refuse policies that name foreign swarms. Should "MAY" be tightened to "MUST"? Deferred to RFC 0012.
- **Operator marshaller-discovery interface for bespoke schemas.** Mentioned in §3.4 as a v1.1+ relaxation. Should the interface be sketched (informatively) in RFC 0010 or wait until concrete operator demand? Currently deferred.
- **Reputation scalar admission.** v1.0 admits `Agent.reputation: Decimal` even though the supervisor layer computing the scalar lands in F4 (RFC 0013). Pre-admitting is a forward-compat win for `prefer` policies in RFC 0011 but introduces a schema field with no producer until F4 — acceptable trade?
- **Schema-delta authoring tooling.** The delta-only constraint at §3.4 is enforced by the analyzer, but operators need tooling to AUTHOR a delta. Tooling is out of spec but needs a design-partner conversation in F8.

## 7. Backwards compatibility

This RFC adds a new directory and two new action-kinds. No existing wire format changes. Existing implementations that don't yet support constitutions continue to work — they simply don't emit `constitution.evaluate.*` receipts. The `Topology` spec is not modified by this RFC; constitution enforcement is opt-in via `Swarm.constitution_version` being non-empty.

When constitution enforcement is opted in, the gating order is:

```
Bearer auth  →  Capability check (RFC 0007)  →  Constitution eval (RFC 0010)  →  Action lands
```

All four gates run. Either failure denies. Three receipts emitted (cap-check + constitution-eval + action receipt) on the happy path; deny short-circuits at the failing gate.

## 8. Migration path

For implementations on substrate (E1/E2/E3 complete) that want to opt into constitution enforcement:

1. Author a constitution against `schema.cedarschema` v1.0.
2. Sign it with the swarm's operator key.
3. Land an `constitution.activate` receipt via the (forthcoming, RFC 0012) `ConstitutionService.Activate` RPC.
4. Subsequent gated actions invoke the evaluator and emit `constitution.evaluate.{pass,deny}` receipts.

Step 3 + 4 require the `yutha-cedar-plus` crate, which is workstream-F code work landing after RFCs 0010-0013 close.

## 9. References

- Design partner doc: [`/docs/internal/constitution-language.md`](../../docs/internal/constitution-language.md)
- Spec rationale: [`/spec/constitution/rationale.md`](../constitution/rationale.md)
- Build-plan §7 (Phase 2): [`/docs/internal/build-plan.md`](../../docs/internal/build-plan.md)
- Cedar 3.x reference: <https://docs.cedarpolicy.com/>
- ADR 0001 (Language choice — Cedar over alternatives): [`/docs/internal/0001-language-choice.md`](../../docs/internal/0001-language-choice.md)
- Companion RFCs (forthcoming): 0011 (extensions), 0012 (evaluation), 0013 (enforcement)

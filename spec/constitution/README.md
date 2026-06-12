# `/spec/constitution/` — Cedar+ Schema and Canonical Schemas (Phase 2)

> **Status:** v1.0 draft (F1 — RFC 0010 introduces this directory).
> **Owners:** Workstream A (Specs) + Workstream E (Constitution engine).

This directory holds the Yutha constitution-language spec — the schema-of-schemas every Cedar+ constitution conforms to, plus the canonical workload/topology schemas that ship with Yutha out of the box.

The design partner doc lives at [`/docs/internal/constitution-language.md`](../../docs/internal/constitution-language.md). Read that for the strategic intent; read [`rationale.md`](./rationale.md) for the spec-layer decisions and threat-model linkage.

---

## Files in this directory

| File | Purpose |
|------|---------|
| [`schema.cedarschema`](./schema.cedarschema) | The canonical Cedar+ schema (v1.1.0) — entity types and action types that every constitution authored against this version may reference. Cedar 3.x human-readable schema syntax. v1.0 → v1.1 history captured in the file header. |
| [`rationale.md`](./rationale.md) | Why the schema is shaped this way; threat-model linkage; conformance hooks; closure of the open design questions from `constitution-language.md` (schema authoring posture + schema evolution semantics). |
| [`extensions.md`](./extensions.md) | The four v1.1 constitution capabilities (RFC 0011). Two are **schema-pattern** (resource budgets, memory norms — stock Cedar over new schema vocabulary). Two are **engine-construct** (`prefer` scoring rules, `procedure` state machines — declared in a separate engine-config artifact, never in Cedar syntax). No Cedar language extensions in v1.1. |
| [`evaluation.md`](./evaluation.md) | Evaluation model + sandbox contract (RFC 0012). Two-layer evaluation (stock cedar-policy for gating + the engine for scoring/procedures), determinism guarantees (same inputs → same receipts byte-for-byte), per-evaluation sandbox bounds with explicit deny-reason mapping, procedure-state reconstruction from the receipt log, wall-clock scheduler for timeouts. |
| [`enforcement.md`](./enforcement.md) | Four-stage enforcement loop (RFC 0013): detect → coach → quarantine → evict, with explicit reverse semantics for non-terminal stages. Receipt-driven (the engine subscribes to the receipt stream); quarantine layers on top of the capability layer; eviction drives `AdmissionService.OperatorRevoke` (RFC 0009). Reputation scalar dynamics; supervisor-tier countersign for evict; topology-aware defaults. |
| `canonical-schemas/` *(F8 — pending)* | Workload-specific schemas extending the base. v1.0 launch set: `support-queue` (S1), `incident-response` (S3), plus topology-mode baselines (`closed`, `open`, `hybrid`). |

---

## How this directory evolves

This is a Phase 2 directory and `/spec/STATUS.md` tracks the spec-stage progress. Adding to or modifying the schema requires an RFC (per [RFC 0001](../rfcs/0001-rfc-process.md)). Workload schemas under `canonical-schemas/` evolve under the same RFC process — they're part of the public spec surface because constitutions reference them by content-address.

The constitution layer and the substrate (passport, envelope, receipt, capability, topology) compose intentionally:

- A capability says "the holder MAY do X" (per-agent authority, content-addressed, attenuable).
- A constitution says "the swarm permits X to be done right now, by this principal, under these conditions" (per-swarm policy, content-addressed, version-chained).

Every consequential action runs BOTH checks. Either failure denies. Both layers emit receipts. See [`rationale.md`](./rationale.md) §2 for the composition argument and §6 for the threat-model split.

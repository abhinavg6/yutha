# RFC 0004: Receipt v1.0

> **Status:** Draft
> **Authors:** Workstream A, Workstream C (receipt store), Workstream L (security)
> **Filed:** 2026-05-10
> **Targets spec:** `/spec/receipt/` v1.0 (new)
> **Targets phase:** Phase 1

## 1. Summary

Introduces the Receipt spec — append-only, content-addressed, signed records of consequential actions. Receipts are the load-bearing wall of Yutha; every later capability depends on them. Includes ordered multi-signature semantics (actor / control plane / supervisor / attestation / batch root), Merkle-batch sealing for the verifiable tier, and canonical evidence format.

## 2. Motivation

Build-plan §4.1: "Receipts before everything else." Every consequential action must produce a receipt; without the receipt fabric, no enforcement, observability, federation, or audit story works. PRD §3.3 names receipts as a strategic goal; PRD §8.3 makes them a Phase 1 deliverable.

A8 (malicious operator) is the primary adversary this spec defends against — append-only + content-addressed + signed receipts, sealed via Merkle batching for the verifiable tier, are the structural defense.

## 3. Detailed design

See [`/spec/receipt/receipt-v1.proto`](../receipt/receipt-v1.proto) and [`/spec/receipt/rationale.md`](../receipt/rationale.md).

Highlights:

- Content-addressable; receipt_id is hash of canonical serialization with signatures cleared.
- AT LEAST ONE signature required (actor); ordered multi-sig allows control-plane countersign, supervisor countersign, attestation, batch-root signature.
- Causal predecessors required.
- Constitution version pinned at decision time so receipts remain interpretable across amendments.
- Append + query operations in spec; bulk export with verifiable manifest at Full+; selective disclosure at Verifiable.
- Canonical action-kind taxonomy in rationale §3 (envelope.send, agent.register, capability.check.deny, enforcement.coach, …); maintained as a separate registry document.

## 4. Drawbacks

- Append-only means no in-place correction; corrections are append-of-correction-receipt, which feels heavyweight to operators used to mutable logs.
- Content-addressing requires canonical serialization discipline; cross-language implementations need careful test vectors.
- Multi-sig wire format is more complex than single-sig; conformance suite has to test each ordering case.

Mitigations: append-of-correction is the right abstraction for evidentiary logs; canonical serialization is testable bytewise (we have the test-vector mechanism); the multi-sig complexity is the cost of separating actor / supervisor / attestation roles cleanly.

## 5. Alternatives considered

See rationale §9. Rejected: hash chain (totally orders what isn't totally ordered), receipts as OTEL spans (different layer), embedded previous-receipt-fully (storage explosion), mutability with version history (defeats A8 mitigation), agent-written receipts (control plane is the integrity boundary).

## 6. Threat-model impact

| Adversary | Effect |
|-----------|--------|
| A1 | Strengthens. Per-action attribution. |
| A2 | Strengthens. Cost.model_provider per receipt enables correlation. |
| A5 | Strengthens. Content-address + signature defeats replay and tampering. |
| A7 | Strengthens. Backdoored implementation that diverges from canonical serialization produces different content-addresses; differential conformance catches. |
| A8 | Strengthens (primary). Append-only + content-addressed + signed + sealed. |
| A9 | Strengthens. Supervisor signatures recorded; envelope detection can monitor. |

No new attack surface.

## 7. Conformance impact

Adds the receipt sub-suite at `/conformance/interface/receipts/`. Core: append, query by ID, content-address consistency, tamper detection. Full: range queries by time/agent/action; bulk export. Verifiable: cross-org mutual recognition, selective disclosure, sealing.

## 8. Migration

Greenfield. The action-kind taxonomy is maintained separately so additions don't require a spec version bump (just the taxonomy document update).

## 9. Open questions

See rationale §10.

## 10. Adoption checklist

- [x] Spec committed
- [x] Rationale committed
- [ ] Action-kind taxonomy registry created (`/spec/receipt/canonical-actions.md`)
- [ ] Canonical evidence shapes documented (`/spec/receipt/canonical-evidence.md`)
- [ ] Conformance tests committed (Workstream C + A)
- [ ] Reference Postgres+S3 implementation drafted
- [ ] Reference Walrus+Seal+Nautilus implementation drafted (must pass same suite)
- [ ] At least two reviewers approved
- [ ] 60-day window expired (sensitive: changes to A8 defense)

## 11. References

- [`/spec/receipt/`](../receipt/)
- [`/docs/internal/threat-model.md`](../../docs/internal/threat-model.md) — A8 primarily
- [`/docs/internal/conformance-suite.md`](../../docs/internal/conformance-suite.md) §3.3
- PRD §3.3, §8.3, §13.3 (privacy/selective disclosure)
- Build plan §4.1 (the load-bearing wall)

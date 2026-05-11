# RFC 0003: Envelope v1.0

> **Status:** Draft
> **Authors:** Workstream A, Workstream B (transport), Workstream L (security)
> **Filed:** 2026-05-10
> **Targets spec:** `/spec/envelope/` v1.0 (new)
> **Targets phase:** Phase 1

## 1. Summary

Introduces the Envelope spec — the typed wrapper around every agent-to-agent message. Untrusted payload bytes are signed-but-opaque; envelope fields (performative, recipient, swarm, causal predecessors, nonce, epoch, signature, tags) are typed and authoritative. The split is the structural defense against A3 (prompt injection).

## 2. Motivation

The substrate cannot reason about agent communication without a typed message format. Reading raw bytes is not enough; the substrate needs to know who sent what to whom, of what speech-act kind, depending on what predecessors. The envelope is that.

Second motivation: PRD §13.2 ("Causal metadata in every message") and PRD §8.3 ("Performative-typed message envelopes") are non-negotiable substrate properties; this spec instantiates them.

## 3. Detailed design

See [`/spec/envelope/envelope-v1.proto`](../envelope/envelope-v1.proto) and [`/spec/envelope/rationale.md`](../envelope/rationale.md).

Eleven performatives. Recipient oneof (agent / role / swarm / external). Causal predecessors required (empty only for genesis). Nonce + epoch + TTL layered replay protection. Tags as bare strings (matched by constitution as set membership). Single agent_signature over canonical serialization with signature cleared.

## 4. Drawbacks

- Eleven performatives may not cover every speech-act pattern. Mitigation: RFC process for additions; minor-version bump.
- Causal predecessors required adds wire bytes. Mitigation: typically small (2–5 hashes); the audit/replay value is much larger than the cost.
- Tags as bare strings mean operator/SDK has to coordinate vocabulary. Mitigation: canonical schemas in Phase 2 ship conventional vocabularies.

## 5. Alternatives considered

See rationale §8. Rejected: JSON envelopes, embedded recipient public key, implicit causal ordering, per-recipient signatures, per-recipient sequence numbers.

## 6. Threat-model impact

| Adversary | Effect |
|-----------|--------|
| A3 | Strengthens (primary). Typed performatives + recipient oneof + signed surface = injected payloads cannot synthesize forbidden envelopes. |
| A5 | Strengthens. Layered replay protection (nonce + epoch + TTL + signature). |
| A8 | Partial strengthen. Receipts reference envelopes by content-address; rewriting changes the address. |

No new attack surface.

## 7. Conformance impact

Adds the transport sub-suite at `/conformance/interface/transport/` covering common requirements (signature, replay, causal, recipient routing) plus per-profile (datacenter, WAN, constrained) tests. No existing tests change.

## 8. Migration

Greenfield. v1.x adds performatives via minor version bumps.

## 9. Open questions

See rationale §9.

## 10. Adoption checklist

- [x] Spec committed
- [x] Rationale committed
- [ ] Conformance tests committed (Workstream B)
- [ ] Reference transport implementation drafted (NATS adapter first)
- [ ] At least two reviewers approved
- [ ] 30-day window expired

## 11. References

- [`/spec/envelope/`](../envelope/)
- [`/docs/security/threat-model.md`](../../docs/security/threat-model.md) — A3, A5
- PRD §8.3
- Speech-act theory: Searle (1969), FIPA-ACL (cautionary tale on overshooting)

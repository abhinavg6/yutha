# RFC 0006: Topology v1.0

> **Status:** Draft
> **Authors:** Workstream A, Workstream B (registry), Workstream L (security)
> **Filed:** 2026-05-10
> **Targets spec:** `/spec/topology/` v1.0 (new)
> **Targets phase:** Phase 1

## 1. Summary

Introduces the Topology spec — closed/open/hybrid swarm-mode declaration with admission policy, sybil-resistance configuration, and default-knob ceilings (capability lifetime, envelope TTL, replay windows). Topology is immutable for the swarm's lifetime; changing it requires creating a new swarm with migration.

## 2. Motivation

Build-plan.md North Star (§2) elevates topology mode to a first-class user choice. The PRD §8.3 alludes to "fixed/open/dynamic topologies"; this spec instantiates the trio with explicit semantics. Without it, Phase 1's registry has no policy basis for admission, and open / hybrid deployments are not buildable.

A6 (sybil) is the headline adversary; admission policy is the primary defense. A8 (malicious operator) is partially mitigated via the immutability constraint, which prevents in-place privilege escalation.

## 3. Detailed design

See [`/spec/topology/topology-v1.proto`](../topology/topology-v1.proto) and [`/spec/topology/rationale.md`](../topology/rationale.md).

Three modes (CLOSED, OPEN, HYBRID), each with a corresponding admission policy variant. Five sybil-resistance mechanisms for open mode (proof-of-work, hardware attestation, IdP attestation, stake, invite); combinations are AND. Default knobs (capability lifetime, envelope TTL, chain depth) tighten platform defaults. Operator signature required.

## 4. Drawbacks

- Immutable topology means operators have to migrate (new swarm) to change participation mode. Real cost for large swarms; the security property is worth it.
- Five sybil-resistance mechanisms is a lot of optionality; operators may pick poorly. Mitigation: documented starting points in rationale §8.
- Cross-spec dependency on capability spec creates a parsing order; topology requires capability v1 be available when validating defaults.

## 5. Alternatives considered

See rationale §9. Rejected: two-mode (no hybrid), mutable topology with versioning, per-agent admission policy, topology-inside-constitution.

## 6. Threat-model impact

| Adversary | Effect |
|-----------|--------|
| A1 | Strengthens. Admission gating + default scope ceilings. |
| A6 | Strengthens (primary). Five mechanisms cover the spectrum from cheap (PoW) to strong (TEE). |
| A8 | Partial strengthen. Immutability prevents silent privilege escalation; periphery_capability_constraint structurally caps periphery authority. |

No new attack surface. The five sybil-resistance mechanisms each have known tradeoffs documented in rationale.

## 7. Conformance impact

Adds topology validation to the registry sub-suite — three admission-policy variants, five sybil-resistance kinds, default-knob enforcement, immutability rejection.

## 8. Migration

Greenfield. Topology migration between swarms (Phase 2 effort) requires a separate spec for migration receipts.

## 9. Open questions

See rationale §10.

## 10. Adoption checklist

- [x] Spec committed
- [x] Rationale committed
- [ ] Conformance tests committed
- [ ] Reference admission-policy implementations (closed, open, hybrid) drafted
- [ ] Starter Cedar+ schemas for each mode (Phase 2 dependency)
- [ ] At least two reviewers approved
- [ ] 30-day window expired

## 11. References

- [`/spec/topology/`](../topology/)
- [`/spec/capability/`](../capability/) — depended-on
- [`/docs/internal/threat-model.md`](../../docs/internal/threat-model.md) — A6 primarily
- PRD §8.3 (fixed/open/dynamic topologies)
- Build plan §2 (two-sided North Star), §4.9 (topology as first-class)

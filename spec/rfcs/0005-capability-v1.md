# RFC 0005: Capability v1.0

> **Status:** Draft
> **Authors:** Workstream A, Workstream B (control plane), Workstream L (security)
> **Filed:** 2026-05-10
> **Targets spec:** `/spec/capability/` v1.0 (new)
> **Targets phase:** Phase 1

## 1. Summary

Introduces the Capability spec — macaroon-style attenuable authority tokens. Capabilities are minted by issuers (operators, control plane, supervisors, or attenuating holders), signed, scoped, time-bounded, caveat-constrained, and required for every action. No ambient authority. Default-deny. Denials produce receipts.

## 2. Motivation

A3 (prompt injection) is the headline adversary. The structural defense is: every action requires a capability check, and capability authority cannot be synthesized from agent payload content because it requires the issuer's signature. Combined with envelope's typed performatives, this contains prompt injection at the substrate.

A1, A6, A8, A9 also depend on capability semantics: bounded blast radius (A1), bounded periphery authority (A6 in hybrid topologies), auditable issuance/revocation (A8), two-person rule via SupervisorRequiredCaveat (A9).

## 3. Detailed design

See [`/spec/capability/capability-v1.proto`](../capability/capability-v1.proto) and [`/spec/capability/rationale.md`](../capability/rationale.md).

Highlights:

- Macaroon-style attenuation: child references parent by content-address; effective scope is intersection.
- Six caveat types (TimeOfDay, ConstitutionVersion, SupervisorRequired, RateLimit, OnlyIfTagged, NeverIfTagged); closed vocabulary.
- Validity window required (no non-expiring capabilities); default max 90 days; topology can tighten.
- Bounded chain depth (default 8); refuses deeper.
- Default-deny with deny_reason and unmet_caveats in CheckResponse; produces receipt.

## 4. Drawbacks

- Attenuation chain depth requires walk for every check; cost grows linearly in depth. Mitigation: bounded depth (default 8); caching at the verifier.
- Six caveat types may not cover every operator need. Mitigation: constitution layer (Cedar+) handles arbitrary conditions one layer up.
- Expiring capabilities require refresh patterns operators must build; not a drop-in replacement for OAuth bearer tokens. Mitigation: documented patterns; SDK helpers for refresh-on-heartbeat.

## 5. Alternatives considered

See rationale §9. Rejected: OAuth scopes (no attenuation), JWTs (chained-JWT ergonomics poor), pure macaroons (no public verifiability), DB-keyed capabilities (breaks federation).

## 6. Threat-model impact

| Adversary | Effect |
|-----------|--------|
| A1 | Strengthens. Quotas + scope bounds limit hostile action. |
| A3 | Strengthens (primary). Default-deny defeats prompt-injected unauthorized action attempts. |
| A6 | Strengthens. Open/hybrid swarm periphery scope ceilings limit sybil leverage. |
| A8 | Partial strengthen. Operator can mint and revoke, but every operation receipted. |
| A9 | Strengthens. SupervisorRequiredCaveat forces two-person rule on high-stakes capabilities. |

## 7. Conformance impact

Adds access-control sub-suite at `/conformance/interface/access-control/`. Core: issue, attenuate, revoke, check, default-deny semantics, bounded chain depth, tamper detection. Verifiable: cross-org capability mutual recognition (Phase 4).

## 8. Migration

Greenfield. v1.x adds caveat types via minor version bumps (each addition is itself an RFC).

## 9. Open questions

See rationale §10.

## 10. Adoption checklist

- [x] Spec committed
- [x] Rationale committed
- [ ] Conformance tests committed
- [ ] Reference implementation drafted
- [ ] At least two reviewers approved
- [ ] 30-day window expired

## 11. References

- [`/spec/capability/`](../capability/)
- [`/docs/internal/threat-model.md`](../../docs/internal/threat-model.md) — A3 primarily
- PRD §13.2 (default-deny)
- Macaroons: Birgisson et al. (2014)
- Build plan §4.6 (default-deny / fail-safe / reversible-before-irreversible)

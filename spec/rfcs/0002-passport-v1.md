# RFC 0002: Passport v1.0

> **Status:** Draft
> **Authors:** Workstream A (Specs), with Workstream B (control plane), Workstream L (security)
> **Filed:** 2026-05-10
> **Targets spec:** `/spec/passport/` v1.0 (new)
> **Targets phase:** Phase 1

## 1. Summary

Introduces the Passport spec — the signed identity manifest an agent presents at swarm join. Covers identity, capabilities (declared, not authorized), framework attribution for A2 (compromised model) detection, resource declarations, conformance tier, and the agent self-signature plus registry countersignature pattern.

## 2. Motivation

Phase 1 substrate (build-plan.md §6) cannot ship without an identity primitive. Per the PRD §8.3, every agent presents a signed manifest at join. The passport is that manifest.

Threat-model adversaries A1, A3, A6, and A8 all require a stable, verifiable identity primitive that binds capability declarations to a cryptographic key. This spec is that primitive.

## 3. Detailed design

See [`/spec/passport/passport-v1.proto`](../passport/passport-v1.proto) and [`/spec/passport/rationale.md`](../passport/rationale.md).

Key choices:

- AgentId is UUID v7 (time-orderable, non-secret).
- Passport is single-swarm. Multi-swarm agents hold multiple passports.
- Capability list in the passport is a *declaration*, not authority. Authority is granted via the separate Capability spec (RFC 0005).
- Self-signed by the agent; registration produces a separate countersigned receipt.
- Tier (MINIMAL / STANDARD / VERIFIABLE) mirrors conformance tiers.

## 4. Drawbacks

- Inline public key adds bytes to every passport (about 100 bytes of overhead). Mitigation: passports are infrequent.
- Single-swarm restriction means cross-swarm agents need multiple passports. Mitigation: federation handshake (Phase 4) handles cross-swarm without re-using passports.
- Capability declarations in the passport are advisory and could mislead operators into thinking they confer authority. Mitigation: explicit and bold-faced in rationale doc; capability check is the actual gate.

## 5. Alternatives considered

See `rationale.md` §7. Rejected: SPIFFE-native AgentId, multi-swarm passports, mutable passports, X.509 client certs as agent identity.

## 6. Threat-model impact

| Adversary | Effect |
|-----------|--------|
| A1 | Strengthens. Stable AgentId + signing-key binding gives attribution. |
| A2 | Strengthens. framework + default_model_provider fields enable cross-agent correlation. |
| A3 | Strengthens. Capability *declaration* split from capability *authority* is the structural defense. |
| A6 | Strengthens. expires_at required in open/hybrid swarms forces re-registration cost. |
| A8 | Partial strengthen. Operator cannot forge passport without agent's private key. |

No new attack surface introduced.

## 7. Conformance impact

Adds the registry/Core conformance sub-suite under `/conformance/interface/registry/`. See `rationale.md` §5 for the required behaviors. No existing tests change (this is the first passport spec).

## 8. Migration

Greenfield; no migration. v1.x backwards-compatible additions can extend within the existing wire format.

## 9. Open questions

See rationale §8.

## 10. Adoption checklist

- [x] Spec doc committed (`passport-v1.proto`)
- [x] Rationale committed
- [ ] Conformance tests committed (Workstream B + A; tracked in subsequent PR)
- [ ] Reference implementation drafted
- [ ] At least two reviewers approved
- [ ] Public review window expired (30 days; major change as new spec)

## 11. References

- [`/spec/passport/`](../passport/)
- [`/docs/internal/threat-model.md`](../../docs/internal/threat-model.md) — A1, A2, A3, A6, A8
- PRD §8.3 (passport)
- ADR 0001 (language choice; informs crypto baseline)

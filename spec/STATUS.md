# Workstream A Status — Phase 1 Spec Drafts

> **As of:** 2026-05-10
> **Author:** background work session, autonomous
> **Audience:** Abhinav (returning to the project), incoming Workstream A reviewers

## What landed

Six spec artifacts and supporting infrastructure for the Phase 1 substrate, all in v1.0 *draft* state — meaning ready to enter the public RFC review window, not frozen.

### Specs

| Spec | Files | RFC |
|------|-------|-----|
| Common types (shared) | [`common.proto`](./common.proto) | (no RFC; foundational types) |
| Passport | [`passport/passport-v1.proto`](./passport/passport-v1.proto), [`rationale.md`](./passport/rationale.md) | [0002](./rfcs/0002-passport-v1.md) |
| Envelope | [`envelope/envelope-v1.proto`](./envelope/envelope-v1.proto), [`rationale.md`](./envelope/rationale.md) | [0003](./rfcs/0003-envelope-v1.md) |
| Receipt | [`receipt/receipt-v1.proto`](./receipt/receipt-v1.proto), [`rationale.md`](./receipt/rationale.md) | [0004](./rfcs/0004-receipt-v1.md) |
| Capability | [`capability/capability-v1.proto`](./capability/capability-v1.proto), [`rationale.md`](./capability/rationale.md) | [0005](./rfcs/0005-capability-v1.md) |
| Topology | [`topology/topology-v1.proto`](./topology/topology-v1.proto), [`rationale.md`](./topology/rationale.md) | [0006](./rfcs/0006-topology-v1.md) |

### RFC infrastructure

- [`rfcs/template.md`](./rfcs/template.md) — RFC template
- [`rfcs/0001-rfc-process.md`](./rfcs/0001-rfc-process.md) — meta-RFC defining the RFC process
- RFCs 0002–0006 — one per launch spec

### Community / OSS docs (Workstream H minimum scope per build plan)

- [`/docs/community/CONTRIBUTING.md`](../docs/community/CONTRIBUTING.md)
- [`/docs/community/CODE_OF_CONDUCT.md`](../docs/community/CODE_OF_CONDUCT.md) — Contributor Covenant v2.1
- [`/docs/community/SECURITY.md`](../docs/community/SECURITY.md) — vuln disclosure policy
- [`/docs/community/RFC_PROCESS.md`](../docs/community/RFC_PROCESS.md) — operator-facing how-to

### Spec README

[`/spec/README.md`](./README.md) — orientation document covering versioning policy (semver per spec, 12-month deprecation window for major bumps), crypto baseline (Ed25519, SHA-256, ChaCha20-Poly1305, all from audited libs), content-addressing semantics, identity-time-causality conventions, and conformance linkage.

## How to read this when you're back

If you have 15 minutes, in this order:

1. [`/spec/README.md`](./README.md) — orient on what's here and how it's structured.
2. [`/spec/STATUS.md`](./STATUS.md) — this document.
3. One spec rationale that interests you most — I'd suggest [receipt rationale](./receipt/rationale.md) since it's the load-bearing wall.

If you have an hour, read all five rationales in this order: passport → envelope → receipt → capability → topology. They build on each other.

If you have a half-day, read everything plus the launch RFCs. Then form opinions.

## What I'd flag for your attention first

These are the calls I made under your absence that I want you to specifically validate or push back on:

1. **AgentId is UUID v7, not SPIFFE.** The PRD §17.1 leans SPIFFE. I shipped UUID v7 with SPIFFE-as-extension because UUID v7 is more compact and language-neutral. Worth confirming before this freezes.
2. **Eleven performatives, not more.** I resisted shipping a larger speech-act vocabulary. If your design partners need more, this gets bigger fast. RFC 0003 §9 surfaces this.
3. **Six caveat types, closed vocabulary.** Capability caveats are deliberately narrow; richer conditions live in the constitution layer (Cedar+). This is the right architectural boundary IMO but worth your sanity check.
4. **Topology is immutable.** Strong claim. The reasoning (rationale §6) is the security property of preventing in-place privilege escalation. The cost is real (large swarms migrating between modes is expensive). Validate.
5. **Action-kind taxonomy as a separate registry document, not enum.** I went with free-form-string-plus-canonical-registry-document instead of a closed enum. This avoids spec version bumps for every new action kind but creates a maintenance burden on the registry. Prefer A or B?
6. **No CLA in CONTRIBUTING.md.** I called this out as "may revisit" rather than committing. If your trademark counsel raises CLA-flavored questions, this is the file to update.

## What is *not* yet done (and is intentionally next)

The specs are drafts; they need:

- **Conformance test cases.** Workstream B/C/A jointly. The conformance runner skeleton at `/conformance/` is the next directory to scaffold.
- **Test vectors.** Bytewise canonical-serialization vectors so cross-language implementations can verify they produce identical bytes. One per message type, ideally.
- **Canonical action-kind registry.** `/spec/receipt/canonical-actions.md` referenced from receipt rationale §3 — needs to be authored.
- **Canonical Evidence shapes.** `/spec/receipt/canonical-evidence.md` similarly.
- **Reference implementation.** Workstream B/C — not Workstream A's job, but Workstream A reviews their conformance.
- **Cedar+ schema spec.** Phase 2; design partner work begins now in parallel.

## What is *not* started (Phase-2-or-later by design)

Per build-plan §6 explicit non-goals for Phase 1:

- Constitution evaluator
- Norm enforcement (no coaching/quarantine/eviction)
- Simulator
- Visual composer
- Federation primitives
- Envelope detection
- Foundation/council/governing body

Resist the pull. The substrate is the substrate.

## Open RFC review windows

If we adopt the windows in RFC 0001 (14d minor / 30d major / 60d sensitive), the launch RFCs would have these earliest-decision dates assuming opening today (2026-05-10):

| RFC | Window | Earliest decision |
|-----|--------|-------------------|
| 0001 RFC process | 60d (sensitive — meta) | 2026-07-09 |
| 0002 Passport v1.0 | 30d (new spec) | 2026-06-09 |
| 0003 Envelope v1.0 | 30d | 2026-06-09 |
| 0004 Receipt v1.0 | 60d (sensitive — A8 defense) | 2026-07-09 |
| 0005 Capability v1.0 | 30d | 2026-06-09 |
| 0006 Topology v1.0 | 30d | 2026-06-09 |

That tracks the build-plan §6 commitment to "specs frozen at month 2" assuming Phase 1 month 0 = 2026-05-10.

## Summary

Six specs at v1.0 draft. Six RFCs ready to open for review. Community/OSS scaffolding in place to invite outside contribution from PR #1. Cross-spec consistency verified. The substrate spec layer is ready for the reference implementation work to begin (Workstream B + C, in parallel where possible per build-plan §12).

What's missing is implementation; what's ready is contract. Per `build-plan.md` §4.2, that's the right ordering.

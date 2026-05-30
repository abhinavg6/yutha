# Workstream A Status — Spec Drafts

> **As of:** 2026-05-27 (Phase A — identity-keys workstream — entry; prior entries below)
> **Author:** background work session, autonomous
> **Audience:** Abhinav (returning to the project), incoming Workstream A reviewers

## Phase A — identity-keys (RFCs 0015 + 0016), in flight 2026-05-27

Enterprise-readiness workstream opened. Paper-only Phase A drafts the two pluggable interfaces that need to land before Yutha is adoptable inside large enterprises or by SaaS platforms building on it: `Signer` (key custody — where signing keys live, who may use them) and `Attestor` (identity verification — chaining Yutha agent_ids back to enterprise IdPs).

| Artifact | Status |
|----------|--------|
| [`/spec/identity-keys/README.md`](./identity-keys/README.md) | Draft. Shared design memo both RFCs refer back to. Frames the two-seams decomposition, native-default + reference-enterprise pattern, explicit deferrals (authorization seam, lifecycle seam, multi-tenancy), phasing A–G. |
| [`/spec/rfcs/0015-signer-interface.md`](./rfcs/0015-signer-interface.md) | Draft. Async `Signer` trait in new `yutha-signer` crate. Breaking change at five sign call sites (passport / envelope / capability / bearer-token-mint / control-plane self-signed receipts) — all become async, all accept `&dyn Signer`. `InProcessSigner` is the zero-dependency default. Phase C ships three production-grade implementations: `yutha-signer-gcp-kms`, `yutha-signer-azure-kv`, and `yutha-signer-vault-transit` (the AWS-friendly path, since AWS KMS doesn't yet support Ed25519). Native AWS KMS deferred until AWS adds Ed25519. |
| [`/spec/rfcs/0016-attestor-interface.md`](./rfcs/0016-attestor-interface.md) | Draft. Async `Attestor` trait in new `yutha-attestor` crate. `RegisterRequest` proto gains optional `external_credential` bytes field; admission handler calls `Attestor.verify` between policy check and registry insert. `NativeAttestor` is the zero-dependency default. SPIFFE/SPIRE (Phase E) and OIDC (Phase F) are the reference enterprise implementations. New canonical action-kind `agent.register.deny`; `agent.register` evidence gains `attested_external_identity` + `attestor_id` keys. Multi-tenancy deliberately deferred; §5.4 documents the extension shape that keeps it easy to add later. |

Five design decisions locked before drafting:

1. **Multi-tenancy deferred.** Single global Attestor per control plane in v1. Trait shape (context struct, not bare credential) keeps the door open for `(swarm_id, tenant_id) → Attestor` resolver later without trait-signature change.
2. **Signer goes async-all-the-way.** Phase B fold-in refactors `Passport::sign` / `Envelope::sign` / `Capability::sign` / `BearerSession::_mint_token` / control-plane receipt signing to async. Estimated 1–2 weeks of mechanical refactor + test-suite chase for a solo dev working full-time.
3. **Separate `yutha-signer` and `yutha-attestor` crates** in core workspace. Cloud KMS / SPIRE / OIDC impls live in feature-gated workspace crates — matches `yutha-anchor-sui` shape from RFC 0014.
4. **Two RFCs.** Filed as a pair, landing together. Shared framing memo above them. Detail specs (`/spec/identity-keys/signer.md` byte-exact, `attestor-spiffe.md`, `attestor-oidc.md`) land alongside each implementation phase, not in Phase A.
5. **No backcompat.** Pre-public; breaking change in place. Demos / tests / examples update once at Phase B and again at Phase D.

Phasing checkpoint: Phase A ends at "drafts reviewed + reviewer-approved." Phase B (Signer trait + async refactor) is the next consequential step; do not roll into Phase B without explicit go-ahead.

---

## Phase 2 in flight (added 2026-05-15)

## Phase 2 in flight (added 2026-05-15)

Phase 1 substrate hardening closed cleanly — RFCs 0007, 0008, 0009 landed across spec, reference impl (Rust control plane), Python SDK + LangGraph adapter, and conformance scenarios S1/S2/S3. See the project root commit history for details.

**RFC 0010 — Constitution Language v1.0 (Cedar+ schema spec)** filed today:

| Artifact | Status |
|----------|--------|
| [`/spec/constitution/schema.cedarschema`](./constitution/schema.cedarschema) | Draft, **at v1.1.0 after F2**. Six entity types, seven action types, six budget-related schema additions. Cedar 3.x human-readable schema syntax. |
| [`/spec/constitution/rationale.md`](./constitution/rationale.md) | Draft. Closes the two F1-blocking open Qs from `constitution-language.md` (schema authoring posture + schema evolution semantics). |
| [`/spec/constitution/extensions.md`](./constitution/extensions.md) | Draft (RFC 0011). Four Cedar+ extensions: `prefer`, `procedure`, resource budgets, memory norms. Per-extension decidability arguments. |
| [`/spec/constitution/README.md`](./constitution/README.md) | Draft. Directory overview. |
| [`/spec/receipt/canonical-actions.md`](./receipt/canonical-actions.md) | Updated. Added `constitution.evaluate.{pass,deny}`, four `procedure.*` action-kinds, and extended evidence on existing `constitution.activate` / `constitution.amend.commit` / `constitution.evaluate.pass` (the last for `prefer` scoring). |
| [`/spec/rfcs/0010-constitution-language-v1.md`](./rfcs/0010-constitution-language-v1.md) | Draft. The RFC for the base schema. |
| [`/spec/rfcs/0011-cedar-plus-extensions.md`](./rfcs/0011-cedar-plus-extensions.md) | Draft. The RFC for the four v1.1 capabilities (two engine-construct, two schema-pattern). |
| [`/spec/constitution/evaluation.md`](./constitution/evaluation.md) | Draft (RFC 0012). Two-layer evaluation contract, determinism guarantees, sandbox bounds, procedure-state reconstruction, timeout firing. |
| [`/spec/rfcs/0012-evaluation-model-and-sandbox.md`](./rfcs/0012-evaluation-model-and-sandbox.md) | Draft. The RFC for the evaluation model and sandbox. |
| [`/spec/constitution/enforcement.md`](./constitution/enforcement.md) | Draft (RFC 0013). Four-stage loop, reversal, reputation, supervisor countersign, topology defaults, `enforcement_rules:` config surface. |
| [`/spec/rfcs/0013-four-stage-enforcement-loop.md`](./rfcs/0013-four-stage-enforcement-loop.md) | Draft. The RFC for the four-stage enforcement loop. |

**F10 (control-plane integration, complete 2026-05-18)** wired `ConstitutionService.Activate` + the F10d send-path constitution gate. Per the no-back-compat-pre-public guidance, `EnvelopeService.Send` now hard-requires an active constitution (returns `FAILED_PRECONDITION` otherwise) and the bearer-header variant prefix is mandatory (`bearer agent <hex>` / `bearer operator <hex>` — bare `bearer <hex>` rejected). F10e emits `constitution.evaluate.{pass,deny}` receipts from the send path. F10f closed the receipt → enforcement-engine feedback loop via a `PublishingReceiptStore` decorator that wraps the in-memory backend: every successful `append` non-blockingly fans an owned `EnforcementReceiptView` onto an mpsc channel (capacity 4096), drained by a background `spawn_enforcement_forwarder` task that forwards into `EnforcementEngine::on_receipt`. A second 1s-cadence `spawn_scheduler_tick` task drives `poll_scheduled` for stage progression. *(F10f shipped with effects logged only; persistence wired in F12 below.)* F10g closed the cap-layer side of the same loop per RFC 0013 §4.2: `yutha-capability` gained a `QuarantineSource` trait (with an `AlwaysAllowed` no-op impl for tests / demos), and `MemoryCapabilityStore` now consults it on every `check`, `issue`, and `attenuate`. A control-plane-side `EnforcementEngineQuarantineSource` adapter bridges the cap layer to `EnforcementEngine::is_agent_quarantined` so the cap and constitution layers share a single quarantine-state view without `yutha-capability` taking a dep on `yutha-cedar-plus`. Quarantined `check` calls deny with reason `subject_quarantined` and emit a `capability.check.deny` receipt; quarantined `issue` / `attenuate` calls return `CapabilityError::SubjectQuarantined`.

**F11 (Python SDK constitution surface, complete 2026-05-18)** added the Python side of the constitution layer. F11a-c shipped the public surface: a Pydantic `Constitution` model under `yutha.models.constitution`, a `ConstitutionAPI` on `YuthaClient` with `activate` (operator-bearer) + `get_active` (agent-bearer, `NOT_FOUND` → `None` per SDK convention), and a public `yutha.testing.permissive_constitution(swarm_id)` helper that builds the smallest constitution the F6 loader accepts (Cedar `permit (principal, action, resource);` + explicit-empty engine config). F11d added a session-scoped `activated_permissive_constitution` conftest fixture that derives the operator key from `YUTHA_BOOTSTRAP_SEED` (same `sha256(seed || 0x03)` formula as the operator-revoke tests), connects via `connect_as_operator`, and activates the permissive constitution; it skips cleanly with actionable messages on the two operator-confusing failure modes (server unreachable; `--operator-public-key` not configured). F11e un-skipped the four send-using integration tests (`test_integration::test_full_lifecycle`, the two `test_langgraph_agent` send-path tests, `test_s1_support_queue_demo::test_s1_demo_audit_shape`) and threaded the fixture through each. Three follow-on fixes landed under F11 to make those tests pass: (i) `constitution.rs::activate` now emits a real `constitution.activate` receipt via `emit_constitution_activate_receipt` rather than returning the constitution hash as a stand-in (F10c gap); (ii) `envelope.rs::build_eval_request_for_send` now populates the full schema-required attribute surface on every `Yutha::Agent` (passport_tier, framework, passport_hash, reputation decimal, three budget Longs — scaffolding-tier placeholders until the resolver wiring lands) and `Yutha::Swarm` (swarm_id, topology_mode, constitution_version); (iii) self-sends no longer push a duplicate recipient entity. Also fixed two stale `test_auth.py` parsing tests that still expected the pre-F10 bare `bearer <hex>` header form.

**F13 (S4 conformance scenario, complete 2026-05-18)** closes the four-stage enforcement loop behaviorally. Engine-side: extended `EnforcementEngine::poll_scheduled` to chain stages — when a `Coach` effect fires, look up the rule and schedule `Quarantine` at `now + quarantine.escalate_after`; when `Quarantine` fires, schedule `Evict` (the F9-shipped engine only scheduled detect → coach inline in `check_detect`, leaving the rest of the chain dormant). A new helper `next_stage_schedule(rule, fired, now)` does the lookup + conditional scheduling. Scenario-side: new `s4_enforcement_loop.rs` under `yutha-conformance/src/scenarios/`. Activates a constitution with a Cedar `forbid` rule on `SendEnvelope` (gated by `payload_schema_id == "type.yutha.dev/v1/Forbidden"`) plus a single `enforcement_rules` entry covering all four stages with 1s cooldowns. Drives the chain: two forbidden evals → 2 `constitution.evaluate.deny` receipts → engine fires `Detect`; `poll_scheduled` with a synthetic future timestamp fires `Coach`; F13 chain schedules `Quarantine`, next poll fires it, engine flips `is_agent_quarantined` to true; a cap-check against a pre-quarantine-issued capability denies with `deny_reason = "subject_quarantined"` (validating F10g); final poll fires `Evict`. Wall-clock is driven directly via RFC 3339 strings rather than `tokio::time`, so the scenario runs in milliseconds and never flakes. `Stage::Quarantine` and `Stage::Evict` lose their `#[allow(dead_code)]` — they're constructed at runtime now.

**F12 (enforcement.* receipt emission, complete 2026-05-18)** closes the F10f deferred work. A new `emit_enforcement_receipt` helper in `receipt_publisher.rs` builds + signs + appends `enforcement.{detect,coach,quarantine,evict,reverse,evict_timeout}` receipts from an `EnforcementEffect`: universal evidence (`target_agent_id`, `enforcement_rule_id`, `reputation_delta`, `constitution_hash`) plus variant-specific keys from the effect's `additional_evidence` BTreeMap (e.g. `matched_receipt_ids[]` on detect, `detect_receipt_id` on coach, `expires_at_wall_clock` on quarantine), encoded as canonical JSON. The forwarder + scheduler tick tasks call a shared `emit_effects` helper instead of logging; appended receipts flow back through `PublishingReceiptStore` → forwarder → `EnforcementEngine::on_receipt`, which the F9 pattern matcher special-cases (`enforcement.*` receipts apply reputation deltas and flip quarantine state without scheduling further effects, so the loop terminates after one round-trip). Behavioral coverage of the closed loop — an actual enforcement rule firing end-to-end — lands in F13's S4 conformance scenario; F12 itself ships the plumbing.

Phase 2 spec staging (workstream F-spec):

| Stage | Deliverable | Status |
|-------|-------------|--------|
| F1 | RFC 0010 + `/spec/constitution/` scaffold | **Drafted 2026-05-15** |
| F2 | RFC 0011 — Cedar+ v1.1 capabilities: two engine-construct (`prefer` scoring + `procedure` state machines, both as engine-config artifacts, NOT Cedar language extensions) + two schema-pattern (resource budgets, memory norms). Schema bump to v1.1.0; `procedure.*` action-kinds added to canonical-actions registry. **Revised 2026-05-15** from an earlier draft that proposed `prefer` and `procedure` as syntactic Cedar extensions — engine-construct is the better architectural fit (stock cedar-policy unmodified, Cedar's analyzer untouched, smaller maintenance surface). | **Drafted 2026-05-15** |
| F3 | RFC 0012 — Evaluation model + sandbox contract: two-layer evaluation (Cedar gating + engine scoring/procedures), determinism guarantees, per-evaluation sandbox bounds, procedure-state reconstruction from receipts, wall-clock scheduler. New `deny_reason` entries added to canonical-actions. | **Drafted 2026-05-15** |
| F4 | RFC 0013 — Four-stage enforcement loop (detect → coach → quarantine → evict + reverse). Receipt-driven engine subscribing to the receipt stream; quarantine via cap-check denial; eviction via `AdmissionService.OperatorRevoke` (RFC 0009) with `cascade_capabilities=true`. Reputation scalar dynamics from per-stage deltas. Flat supervisor-tier countersign for evict. Topology-aware defaults. Engine-config `enforcement_rules:` block alongside `scoring_rules` + `procedures` (RFC 0011). Evidence shapes for `enforcement.*` action-kinds filled out. New: `enforcement.evict_timeout` kind for abandoned pending evictions. | **Drafted 2026-05-15** |

Phase 2 code stages (workstream F-code) follow the spec quartet — `yutha-cedar-plus` crate scaffold on top of `cedar-policy`, then extension impls, static analyzer, evaluator + sandbox, control-plane integration, plain-English authoring CLI, canonical schemas under `/spec/constitution/canonical-schemas/`, and S2/S3 behavioral scenarios wired into the conformance runner. Sub-staging firms up after F1-F4 close.

Working pattern is the substrate pattern: strict-order sub-stages, explicit go-ahead between stages, cross-spec consistency sweep at each stage boundary.

---

## Phase 1 entry (original, dated 2026-05-10)

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

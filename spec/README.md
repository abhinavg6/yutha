# Yutha Specifications

> **Status:** Phase 1 launch specs in v1.0 draft. Open for RFC review.
> **Owners:** Workstream A (Specs).
> **Versioning:** see §3 below.

This directory holds the Yutha public surface — every wire format, every signed artifact, and every protocol that other implementations must follow to interoperate. The reference implementation in `/crates/` proves the specs run; the specs are what other implementations adopt.

This is the load-bearing claim of the project: **specs are the product, code is the proof.** Every architectural decision in `/docs/build-plan.md` reduces to "do the specs lock this down, and does the conformance suite verify it?"

---

## 1. What is in here

The Phase 1 launch specs:

| Spec | Status | Purpose |
|------|--------|---------|
| [`common/`](./common.proto) | v1.0 draft | Shared types used by every other spec (Hash, Signature, AgentId, Timestamp, etc.) |
| [`passport/`](./passport/) | v1.0 draft | Signed identity manifest an agent presents at swarm join |
| [`envelope/`](./envelope/) | v1.0 draft | Typed message wrapper with performatives and causal metadata |
| [`receipt/`](./receipt/) | v1.0 draft | Append-only, content-addressed, signed record of consequential actions |
| [`capability/`](./capability/) | v1.0 draft | Macaroon-style attenuable authority tokens |
| [`topology/`](./topology/) | v1.0 draft | Closed / open / hybrid swarm-mode declaration and admission policy |
| [`constitution/`](./constitution/) | v1.0 draft (RFC 0010, schema-only) | Cedar+ canonical schema; entity and action types every constitution conforms to. Extensions, evaluation, enforcement land in RFCs 0011-0013. |

Phase 2 will further extend `constitution/` with:

- `extensions.md` — `prefer`, procedures, resource budgets, memory norms (RFC 0011)
- `evaluation.md` — evaluation model + sandbox contract (RFC 0012)
- `enforcement.md` — four-stage enforcement loop (RFC 0013)
- `canonical-schemas/` — workload-specific schemas (queue-mode, campaign-mode, topology baselines)

Phase 4 will add:

- `federation/` — handshake, norm reconciliation, cross-org receipt mutual-recognition

Each spec lives in its own subdirectory containing:

- `<spec>-v<N>.proto` — the wire format (protobuf 3)
- `rationale.md` — why the spec is shaped this way; threat-model linkage; conformance hooks; alternatives considered
- `test-vectors.md` (added in subsequent drafts) — canonical inputs/outputs for the conformance suite

The RFC subdirectory ([`rfcs/`](./rfcs/)) contains the formal proposals that introduce or amend specs. Every change to a v1.0+ spec goes through an RFC.

---

## 2. How to read a spec

Each spec is self-contained and answers four questions in the same order:

1. **What is it?** A one-paragraph statement of the artifact's purpose.
2. **What is the wire format?** The `.proto` definition.
3. **Why is it shaped this way?** Design rationale, threat-model linkage, alternatives rejected.
4. **What must a conformant implementation do?** Conformance hooks consumed by `/conformance/interface/`.

A reviewer reading a spec from cold should be able to answer "what would an implementation of this need to do, and what would I check to verify it?" by the end of `rationale.md`.

---

## 3. Versioning policy

Every spec has its own semver-style version. Spec versions evolve independently — a passport v1.1 release does not require an envelope v1.1 release.

**Version semantics:**

- **Major (`v1` → `v2`):** breaking change. Existing artifacts produced under the old version may not validate under the new version. Requires an RFC, a one-year deprecation window for the previous major version, and a migration story.
- **Minor (`v1.0` → `v1.1`):** backwards-compatible additions. New optional fields, new enum values with `_UNKNOWN` fallback semantics, new performatives. Existing v1.0 artifacts still validate. Requires an RFC.
- **Patch (`v1.0.0` → `v1.0.1`):** clarifications, doc fixes, test-vector corrections. No wire-format change. Does not require an RFC; a normal PR is sufficient.

**Default-unknown handling.** Every enum has an `_UNKNOWN = 0` member. Receivers that encounter an unknown enum value MUST treat it as the conservative default (deny, ignore, fail-closed) and surface the unknown to the operator rather than silently dropping or interpreting.

**Field number reservations.** Field numbers `1`–`15` are reserved for v1.x core fields (one byte on the wire); `16`–`200` for v2+ additions; `201`–`8192` for vendor extensions in `extensions` maps where present; `8193+` reserved for future protocol use.

**Spec deprecation window.** When a major version is bumped, the previous major version remains a supported on-the-wire format for at least 12 months from the new version's release. During this window:

- All conformant implementations accept artifacts in either version.
- New artifacts are produced in the new version by default; the old version is opt-in for compatibility.
- The conformance suite tests both versions.

After the window, the old version becomes deprecated; one further release continues to accept it; the release after that may reject it.

**Specs and code versions are independent.** A reference implementation at `yutha-receipt v0.4.2` may implement `receipt-spec v1.0`. The crate version moves with implementation maturity; the spec version moves with wire-format evolution.

---

## 4. Crypto baseline

These choices are part of every spec by reference. Changing any of them is a major-version bump.

| Primitive | Choice | Notes |
|-----------|--------|-------|
| Hash function | SHA-256 | Multihash-style algorithm prefix in `Hash` allows future migration without breaking content addresses retroactively. BLAKE3 anticipated as a `v1.x` addition. |
| Signature | Ed25519 | Fast, small, standardized. Algorithm prefix in `Signature` allows future PQ migration. |
| Asymmetric key wrapping | X25519 | For encrypted memory and key exchange. |
| Symmetric encryption | ChaCha20-Poly1305 | Default for memory at rest where the deployment selects encryption. |
| Key derivation | HKDF-SHA-256 | For derivation chains. |
| Random | OS CSPRNG | No userspace PRNG paths in spec-mandated flows. |

All cryptographic operations in the reference implementation come from audited Rust libraries — `ring`, `ed25519-dalek`, `rustls`. ADR 0001 is the policy.

---

## 5. Content addressing

The hash of a message is computed over its **canonical serialization**:

1. The message's `signature` field (if any) is unset.
2. All fields are encoded using protobuf 3 deterministic serialization (field order ascending by tag, no field tag with default-value-only payload, no `unknown` fields preserved).
3. The hash is computed over the resulting byte sequence.
4. The signature is then computed over that hash and reattached.

This guarantees that two implementations producing the same logical message produce the same content-address regardless of language, library, or platform endianness. The conformance suite tests this property explicitly with cross-implementation byte-equivalence vectors.

When `Hash` is used to reference another message (a `causal_predecessor`, a parent capability), it always refers to this canonical hash.

---

## 6. Identity, time, and causality

**Identity** is referenced via `AgentId` (UUID v7) and `SwarmId` (UUID v7). UUID v7 is chosen for time-orderable, monotonic identifiers with sufficient entropy to prevent collision and discourage guessing. Identifiers are not meant to be secret; they are stable references whose authority comes from cryptographic signature, not from secrecy.

**Time** is recorded as both an RFC 3339 wall-clock string and a monotonic-since-epoch nanosecond counter. Wall-clock is for operators; monotonic is for ordering decisions where clock skew matters (per threat-model §6 cross-cutting). Implementations MUST emit both. Comparison logic in spec-mandated paths uses monotonic; observability uses wall-clock.

**Causality** is recorded by `CausalRef` — a list of receipt hashes that an action depends on. This is what makes the causal DAG emitted-not-reconstructed. Every envelope and every receipt carries causal predecessors; the registry, transport, and receipt-store conformance suites verify they are preserved end-to-end.

---

## 7. Conformance linkage

Every spec defines what a conformant implementation must produce or accept. The conformance suite at `/conformance/interface/` contains the executable test cases. The relationship is deliberate: **the spec is the contract; the suite is how we verify it.**

When you draft an RFC that changes a spec, you are also implicitly changing the conformance test set. A spec change without a conformance-test change is an RFC that is not yet ready for review.

---

## 8. RFC process (short version)

The full process lives in [`rfcs/0001-rfc-process.md`](./rfcs/0001-rfc-process.md). The short version:

1. File an RFC at `/spec/rfcs/<NNNN>-<short-name>.md` using [`template.md`](./rfcs/template.md).
2. Open it for public discussion. Minimum public review window: 14 days for a minor change, 30 days for a major change.
3. Reach **lazy consensus** among the active maintainers — silence is approval, but a sustained objection blocks merge until addressed or overruled by the project lead.
4. Merge the RFC. Update the relevant spec to a new version. Update the conformance suite.
5. Tag a release.

The RFC repository is public from PR #1. No spec change happens off-list.

---

## 9. What is *not* spec'd here (deliberately)

- **Authoring tooling.** The plain-English constitution authoring layer is a UX surface, not a wire format. It does not appear in `/spec`.
- **Backend implementations.** Postgres receipt schemas, NATS subject naming, Redis key formats — all implementation details. Backends conform to the receipt/transport spec; they don't need to be specced themselves.
- **Operator policy.** What constitution to author, what topology to choose, what reputation threshold to set — operator decisions, not spec decisions.
- **Specific framework integrations.** SDK adapters use these specs but don't constrain them. New frameworks can be added without changing `/spec`.

---

## 10. Index of related documents

- [`/docs/build-plan.md`](../docs/build-plan.md) — synthesis of how Yutha gets built across phases. Workstream A's deliverables are in §5.
- [`/docs/decisions/0001-language-choice.md`](../docs/decisions/0001-language-choice.md) — Rust-core ADR; the crypto baseline above is partially derived from this.
- [`/docs/security/threat-model.md`](../docs/security/threat-model.md) — adversaries A1–A9. Each spec's `rationale.md` cites which adversaries the spec mitigates.
- [`/docs/conformance/conformance-suite.md`](../docs/conformance/conformance-suite.md) — conformance levels and sub-suites.
- [`/docs/design/constitution-language.md`](../docs/design/constitution-language.md) — Cedar+ design (Phase 2 spec target).

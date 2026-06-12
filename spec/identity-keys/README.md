# Identity & key management — design memo

> **Status:** Draft (Phase A — paper only)
> **Filed:** 2026-05-27
> **Companion RFCs:** [0015 — Signer interface](../rfcs/0015-signer-interface.md), [0016 — Attestor interface](../rfcs/0016-attestor-interface.md)
> **Targets phase:** Phase 3+ (enterprise readiness)
> **Out of scope for this memo:** authorization seam (external RBAC/ABAC), lifecycle seam (upstream-revocation propagation), multi-tenant substrate. See §5 for the deferred items.

## 0. Why this document exists

This memo is the shared framing that RFCs 0015 and 0016 both refer back to. Read it first; the two RFCs each cover one of the two interfaces the memo introduces and assume the framing is shared context.

It is paper-only. No code lands from it. The implementation comes in later phases (B–G in the plan at §6), each gated on review of the previous one.

## 1. The problem

Yutha's substrate today is self-contained: every agent generates an Ed25519 keypair in process, mints a passport that embeds the public key, signs it with the matching private key, and presents it at admission. The control plane accepts the passport if the self-signature verifies. Bearer tokens are minted the same way — agent's private key signs a short-lived token; the server's `PassportResolver` looks up the public key and verifies. The same private key signs envelopes, capabilities, and bearer tokens.

For independent builders and development swarms, that is exactly the right surface — zero external dependencies, no operator burden, no IdP integration. The hobby story works because the substrate is the trust root.

For large enterprises and SaaS platforms building on Yutha, the same surface is the blocker. Two reasons:

- **Identity does not start at Yutha.** A bank already has SPIRE, an Okta tenant, and a workload-identity story for everything that runs in production. Agent identity must be a *derived projection* of one of those, not a parallel island. If Yutha asks the security team to provision and rotate a separate identity for each agent, the answer is no.
- **Keys do not belong in process memory.** A security review that ends with "the agent reads its Ed25519 private key from disk and signs in user space" does not proceed. Production-grade key handling means HSM, cloud KMS, or Vault. The agent holds a *handle* to a signing capability; it never sees the bytes.

These are not two facets of one problem. They are two separate concerns, and an enterprise will routinely want a different vendor for each — SPIRE for identity, AWS KMS for keys, all on the same agent. The design must therefore decompose into **narrow, independent interfaces**, each with a zero-dependency native default and a reference enterprise implementation. The hobby path stays trivial; the enterprise path plugs in.

## 2. The two seams

This memo introduces two interfaces. Each is the subject of one RFC; this memo states the shape of the decomposition.

### 2.1 Signer (key custody)

**RFC:** [0015](../rfcs/0015-signer-interface.md).

A `Signer` is a handle to a signing capability. The contract is one method: given canonical bytes, return an Ed25519 signature that verifies under a known public key. The signer never exposes the raw key material — even the in-process default goes through the same interface as a cloud-KMS-backed one.

Native default: `InProcessSigner` wraps the existing `SigningKey` byte-for-byte. Zero dependencies; what hobby swarms run today.

Reference enterprise implementations (Phase C — three v1 deliverables, all following the shared pattern in [RFC 0017](../rfcs/0017-external-signer-backends.md)):

- **HashiCorp Vault transit** — supports Ed25519; the recommended path for enterprises on AWS, where KMS doesn't yet ship Ed25519 (see [RFC 0015 §9.1](../rfcs/0015-signer-interface.md#91-aws-kms-ed25519-support--decided)). Ships first in Phase C-B as the OSS-friendly reference.
- **GCP Cloud KMS** — Ed25519 keys supported natively (`EC_SIGN_ED25519`). Ships in Phase C-C.
- **Azure Key Vault** — Managed HSM tier (Premium) supports Ed25519. Ships in Phase C-D.

Natural follow-ons (deferred until requested):

- AWS KMS native (blocked on AWS adding Ed25519 support)
- PKCS#11 / FIPS HSM (vendor-specific)

### 2.2 Attestor (identity verification)

**RFC:** [0016](../rfcs/0016-attestor-interface.md).

An `Attestor` answers the question "who is this principal, in terms an external identity provider already knows about?" Given a presented credential plus a context, it verifies the credential against external infrastructure and returns a verified-identity record that the admission handler binds into a Yutha passport.

Native default: `NativeAttestor` — today's self-signed-passport flow, unchanged. Zero dependencies; what hobby swarms run today.

Reference enterprise implementations (Phases E and F):

- **SPIFFE/SPIRE** — chosen deliberately as the *primary* enterprise reference. SPIFFE is a CNCF standard (building to it means building to a standard, not to one IdP); it is workload-identity-first, which is what an agent actually is; and SPIFFE trust domains federate across organizations, which maps directly onto Yutha's planned cross-swarm federation.
- **OIDC** — chosen as the broad-compatibility on-ramp. Many enterprises can do OIDC even if they don't run SPIRE.

### 2.3 The token-vs-key bridge

The two seams meet at one design tension that's worth naming explicitly.

A Yutha passport binds an *identity* to a *keypair*. The signature on the passport is the proof of that binding.

Most enterprise IdPs do not work this way. SPIFFE SVIDs and OIDC tokens are short-lived bearer artifacts: presenting one proves identity for the duration of the token, but the token itself is not a key. The agent needs *both* — a keypair (for signing envelopes, etc.) and an external token (for proving who it is to the IdP).

The Attestor's job is to verify the external credential and confirm that the keypair the agent is registering belongs to the same logical principal as the external token's subject. That binding becomes the basis of the Yutha passport. The result is a passport that an external auditor can chain back to the IdP's records: "this agent_id corresponds to that SPIFFE ID corresponds to that workload selector."

RFC 0016 §3 specifies how this binding works for each external credential type.

## 3. The pattern: native default + reference enterprise

Every interface in this work follows the same pattern:

1. A native implementation is the zero-dependency default. The hobby/development path works without ever touching enterprise infrastructure. The native implementation is part of the core crate, not behind a feature flag, not opt-in.
2. Reference enterprise implementations ship as separate, optional crates feature-gated off the umbrella. AWS KMS, SPIRE, OIDC each live in their own crate; nothing else in the core depends on them.
3. The trait surface is the contract; conformance vectors prove implementations behave equivalently for the same logical input.

This is the same pattern the verifiability work (`yutha-anchor-sui`) uses, and it's the right one — the substrate stays small, integrators pull in only what they need, and an audit by a paranoid security team can verify that the core crate does not transitively depend on any cloud SDK.

## 4. What this work is *not*

Two scope guardrails worth restating, because the temptation to expand them will be real.

### 4.1 Not authentication-vs-authorization

A `Signer` and an `Attestor` are both about *establishing* identity and proving control of keys. They do not decide what an established identity is *allowed* to do — that is the authorization layer's job. Yutha today has two authorization mechanisms — capabilities and the Cedar+ constitution — and both stay exactly as they are. An `Attestor` produces a verified-identity record; the same passport-tier-based rules and capability scopes apply to it as to a natively-attested passport.

### 4.2 Not lifecycle propagation

If an Okta tenant deprovisions a human, the human's derived agent identities should eventually lapse. That is *real*, it is *important*, and it is *not what this work delivers*. Building it now would entangle the Signer + Attestor traits with revocation propagation semantics that we don't yet have a clean shape for. We instead design the trait surfaces so a lifecycle layer can be added later without breaking them — see §5.

## 5. What's deferred — and how the traits stay open for it

Three concerns are deliberately deferred. Each is anticipated in the trait shapes so a future RFC can add it without breaking 0015/0016.

### 5.1 Authorization seam

External RBAC/ABAC / policy-decision-point integration for capability granting. Today Cedar+ runs in-process; an enterprise might want the constitution evaluator to consult Open Policy Agent or a corporate PDP. Yutha's existing capabilities + Cedar+ is sufficient for v1. Future RFC 0018+ when demand surfaces.

### 5.2 Lifecycle propagation

Automatic upstream-revocation handling. When the Attestor receives a credential whose validity period has expired or whose IdP-side principal has been deprovisioned, the derived Yutha authority should lapse. The Attestor RFC notes a `credential_expires_at` field on the verified-identity record that future lifecycle work can hook into; the operator-revoke RPC (RFC 0009) is the obvious enforcement point.

### 5.3 Multi-tenancy

A SaaS company building on Yutha will eventually want one control-plane process serving many customer tenants, each with its own IdP configuration. This memo and the two RFCs deliberately scope to **one Attestor per control plane** — single global config, no tenant routing. The shape that keeps multi-tenancy easy to add later is straightforward:

- The `Attestor::verify(context, credential)` signature takes a context struct, not a bare credential. Adding `context.tenant_id` later is field-addition, not a breaking trait change.
- Today's single-Attestor config becomes a resolver lookup later: `(swarm_id) → Attestor` becomes `(swarm_id, tenant_id) → Attestor`.
- The `Passport` shape does not gain a tenant field in 0016. When multi-tenancy ships, the verified-identity record can carry a `tenant_id`, and the passport's `owner` field (already free-form) is the place to embed it. Or a future passport version bump can add a dedicated field.

Concretely: if you draft a future "RFC 00NN — within-swarm tenancy" three months from now, the deltas to 0015/0016 should be additive — new field on the context struct, new resolver layer above the Attestor. No trait-signature breaks.

## 6. Phasing

The plan agreed before Phase A starts. Each phase ends in a checkpoint; do not roll into the next phase without explicit go-ahead.

| Phase | Scope | Output |
|---|---|---|
| A — *paper* | This memo + RFC 0015 + RFC 0016 | Spec only; no code; **done 2026-05-27** |
| B — *Signer trait + async refactor* | Land the `Signer` trait, refactor all five sign call sites to async, ship `InProcessSigner` as the default | One PR-stack, breaking change; **done 2026-05-30** |
| C — *external Signer impls* | RFC 0017 umbrella + three new crates: Vault transit (first), GCP KMS, Azure Key Vault Managed HSM. AWS KMS punted (RFC 0015 §9.1; no Ed25519 today). **Done 2026-05-30** — all three backends scaffolded, connect+sign+verify integration-tested. | RFC 0017 + three feature-gated crates |
| D — *Attestor trait + admission refactor* | Land the `Attestor` trait, wire into the admission handler, ship `NativeAttestor` as the default | One PR-stack, breaking change; **done 2026-05-30** — `yutha-attestor` crate scaffolded; `RegisterRequest.external_credential` proto field added; registry takes `Arc<dyn Attestor>` at construction; `agent.register.deny` action-kind + evidence keys pinned; `--attestor` CLI flag scaffolded (native today; spiffe/oidc reserved). |
| E — *SPIFFE/SPIRE Attestor* | The reference enterprise Attestor. **Done 2026-05-31** — `yutha-attestor-spiffe` crate ships JWT-SVID verification against either a static trust-bundle file or the SPIRE Workload API socket; `--attestor spiffe` CLI flag plus 6 `--attestor-spiffe-*` config flags wired into the control plane; 11 in-tree forged-JWT tests + 9 JSON conformance fixtures + `#[ignore]`-gated docker-spire integration test; operator runbook at [`docs/operator/spiffe-attestor.md`](../../docs/operator/spiffe-attestor.md). | [`attestor-spiffe.md`](./attestor-spiffe.md) + `yutha-attestor-spiffe` crate + `docs/operator/spiffe-attestor.md` |
| F — *OIDC Attestor* | The broad-compatibility Attestor. **Done 2026-05-31** — `yutha-attestor-oidc` crate ships offline ID-token verification (RS256/RS384/RS512/ES256/ES384/EdDSA via `jsonwebtoken ^10`) against three JWKS sources (OIDC Discovery / `jwks_uri` override / static file) with bounded-staleness TTL refresh + kid-miss deduplicated async refresh; `--attestor oidc` CLI flag plus 11 `--attestor-oidc-*` config flags wired into the control plane; 10 forged-JWT unit tests + 4 in-process axum-mock-OIDC integration tests (incl. kid-rotation) + 7 JSON conformance fixtures at `/spec/vectors/attestor/oidc/`; operator runbook at [`docs/operator/oidc-attestor.md`](../../docs/operator/oidc-attestor.md). | [`attestor-oidc.md`](./attestor-oidc.md) + `yutha-attestor-oidc` crate + `docs/operator/oidc-attestor.md` |
| G — *enterprise-identity walkthrough* | `docs/operator/enterprise-identity.md` — end-to-end docs covering a SPIRE + Vault-transit deployment (the OSS-friendly reference path), plus the control-plane CLI wiring that lets operators select an external Signer backend (`--signer {vault,gcp-kms,azure-kv}`) without editing source. **Done 2026-05-31** — `docs/operator/enterprise-identity.md` + 12 new `--signer*` CLI flags on `yutha-control-plane` + the per-backend operator runbooks updated to lead with the CLI flags + the integrated nav grouping (Signer sub-section, Attestor sub-section). | One doc page + control-plane CLI wiring; matches sui-anchoring's walkthrough shape |

## 7. Anti-patterns

Six things this work explicitly will not do, restated so they remain visible during review.

- **No shadow-IT identity.** Yutha does not invent agent identity that admins must separately provision. Agent identity is a derived, revocable projection of the identity store the org already runs.
- **No mandatory external dependency on the standalone path.** The native passport + in-process signer remain the default and the always-available zero-dependency way to run Yutha.
- **No raw key material across the Signer interface.** Signing is always a call into the backend. Implementations may not return private bytes for any reason.
- **No reinvention of SPIFFE or OIDC.** These are the standards. Implement them; do not redesign them.
- **No coupling of the two seams.** `Signer` and `Attestor` are independent. An enterprise running NativeAttestor + Vault-transit Signer is a real configuration; so is SPIFFE Attestor + InProcessSigner.
- **No backcompat to maintain.** Per [the no-backcompat-pre-Phase-2-public guidance](../../AGENTS.md), the repo is private with no production users. `Passport::sign(&SigningKey)` becomes `Passport::sign(&dyn Signer).await` directly. Demos and tests update once.

## 8. References

- The scoping doc — direction agreed for this work; tracked in project notes.
- [Threat model](../../docs/internal/threat-model.md) — A1 (hostile agent), A6 (Sybil), A7 (supply-chain), A8 (malicious operator) are the load-bearing adversaries for this work.
- [RFC 0002 — Passport v1](../rfcs/0002-passport-v1.md) — the artifact `Attestor` produces verified-identity records for and `Signer` signs.
- [RFC 0007 — send-path capability check](../rfcs/0007-send-path-cap-check.md) — the call site `Signer` replaces in the agent's bearer-token mint path.
- [RFC 0009 — operator credentials](../rfcs/0009-operator-credentials.md) — operator-revoke is the enforcement hook for the deferred lifecycle work.
- [SPIFFE specification](https://github.com/spiffe/spiffe) — external standard the Attestor implements against.
- [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html) — external standard the OIDC Attestor implements against.

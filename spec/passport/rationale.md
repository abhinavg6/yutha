# Passport Spec — Design Rationale

> **Spec:** [`passport-v1.proto`](./passport-v1.proto)
> **Version:** v1.0 draft
> **RFC:** 0002
> **Threat-model linkage:** A1 (hostile agent), A2 (compromised model), A3 (prompt injection), A6 (sybil), A8 (malicious operator)

## 1. What is a passport, in one paragraph

A passport is the signed identity manifest an agent presents when it asks to join a swarm. It says: this is who I am (a stable AgentId), this is the swarm I want to join, this is the public key I will sign all future actions with, this is the framework I'm built on, this is what I claim I can do, this is the constitution I commit to obey, this is the resource budget I expect to need. The agent self-signs the passport; the registry validates it against admission policy and counter-signs the result as a registration receipt. From that point on, every signature the agent produces is verifiable against the passport's public key, and every action it takes can be tied back to the passport that authorized it.

## 2. Why this shape

The PRD calls passports "a signed manifest with identity, capabilities, owner, norm-set version, declared resources" (§8.3). This spec is the wire-format expression of that statement. The shape is constrained by three forces:

- **Authority must be cryptographic, not declarative.** An agent that says "I can issue refunds" is not authorized to issue refunds. The capability declaration is a request; the actual authority is a capability token issued separately (see [`/spec/capability/`](../capability/capability-v1.proto)). This is what makes prompt injection (A3) containable — even if an agent is convinced to attempt an action, the capability check blocks unauthorized attempts.
- **Identity must be stable across key rotations.** AgentId persists; the public key may rotate. A passport re-issued with a new key but the same AgentId is a valid key rotation, and the rotation itself produces a receipt.
- **A passport is single-swarm.** An agent that wants to be in two swarms holds two passports. This avoids cross-swarm capability leakage — a capability token issued for swarm X cannot accidentally apply in swarm Y because the passport it descends from was for X only. Federation (Phase 4) handles cross-swarm operations through explicit handshakes, not by re-using passports.

## 3. Field-by-field rationale

**`spec_version`.** Required first because version negotiation has to happen before any other interpretation. A passport authored at v1.5 sent to a registry that only knows v1.0 is rejected with a clear error before any other validation runs.

**`agent_id` (UUID v7).** Time-orderable identifiers help observability (you can roughly sort by ID without consulting timestamps), and v7 has enough entropy to discourage guessing while remaining non-secret. AgentId is intentionally not a hash of the public key — that would tie identity to keying material and break key rotation.

**`swarm_id`.** Pinning the passport to a single swarm is a containment property. It also makes the registration receipt's content-address depend on swarm_id, which means a passport leaked from swarm A cannot be replayed against swarm B even if the agent's private key were compromised.

**`agent_public_key`.** Inline rather than by reference. A passport is self-contained; a verifier with no other context can validate the signature. Some bandwidth cost on the wire, but passports are infrequent (one per swarm-join) and the operational simplicity is worth it.

**`owner`.** Free-form string for the human-meaningful owner. Operators and auditors care; the control plane does not enforce against this field. It exists for accountability — when a receipt links to an agent, the audit trail shows who is responsible.

**`framework` and `framework_version`.** The PRD's framework neutrality goal means we do *not* discriminate on framework, but we *do* record it. Recording it is what makes A2 (compromised model) detectable — if a model provider is poisoned and many agents using that provider drift in correlated ways, the receipt fabric needs framework attribution to surface the correlation.

**`capabilities` (CapabilityDeclaration).** Critical to read this carefully: **declaration is not authority.** This list is what the agent says it can do. The registry decides whether to honor any of it; the constitution constrains what's even askable; the capability token (separate spec) is what actually grants authority. Putting declarations in the passport is helpful for admission decisions ("does this agent's claimed capability set match what this swarm needs?") but the passport itself never carries authorization.

**`accepted_constitution_version`.** The agent commits to a specific version. If the constitution amends, agents must explicitly re-consent (PRD §13.3 — "Consent on participation"). This field plus the constitution's amendment procedure is what implements that.

**`tier`.** PassportTier mirrors conformance tiers. The mapping is intentional:
- MINIMAL: closed swarms only; self-attested; no extra checks.
- STANDARD: open and hybrid swarms; operator-vetted credentials; the default for most production deployments.
- VERIFIABLE: required for verifiable backends; cryptographic attestation via Nautilus or equivalent.

**`resources` (ResourceDeclaration).** Budget caps the agent expects. The control plane uses these for quotas; the constitution's `forbid` rules can further constrain. Both are inputs to PRD §13.4's "blast-radius bounds" guarantee.

**`issued_at` and `expires_at`.** Wall-clock + monotonic, per the common Timestamp shape. expires_at is optional in closed swarms (long-lived internal agents) but required in open/hybrid (sybil mitigation — attackers that register, behave, and wait must keep paying registration cost). The expiry check uses `Timestamp.wall_clock` (RFC 3339) because the passport is minted by the SDK and evaluated by the control plane — see [RFC 0008](../rfcs/0008-wall-clock-bound-checks.md) for why cross-process bound checks can't rely on `monotonic_ns`.

**`default_model_provider`, `default_model_name`.** A2 attribution. Receipts override these per-action; the passport carries the default for cases where the receipt elides them.

**`extensions`.** Forward-compatibility. Vendors and future minor versions add typed entries here without breaking older readers.

**`agent_signature`.** Last because it signs everything before it. Computed over canonical serialization with this field cleared.

## 4. Threat-model linkage

| Adversary | How this spec contributes to mitigation |
|-----------|------------------------------------------|
| A1 Hostile agent | Stable AgentId + signing-key binding makes attribution to the offending agent unambiguous; resource declarations cap blast radius even if the agent is hostile; tier and constitution-version fields make admission policy enforceable. |
| A2 Compromised model | Framework + model-provider fields per passport (and per-action override in receipts) make correlated drift across agents on the same provider observable. |
| A3 Prompt injection | Critical: capability **declaration** in the passport is not capability **authority**. Even if an agent is prompt-injected into claiming or attempting a capability, the registry-issued capability token is what gates action. The split is structural. |
| A6 Sybil | expires_at required in open/hybrid swarms forces re-registration cost; tier requirements (STANDARD or VERIFIABLE) raise the cost of mass registration; admission policy in `/spec/topology` consumes passport fields to set the cost knob. |
| A8 Malicious operator | Owner field plus signed-by-agent self-attestation means a malicious operator cannot silently substitute one agent's identity for another — the operator can refuse to register, but cannot forge a passport for an agent without that agent's private key. |

## 5. What an implementation must do (conformance hooks)

A conformant registry implementation:

- **Validates the spec_version** is supported before any other interpretation.
- **Verifies agent_signature** against canonical serialization with `agent_signature` cleared. Rejects on mismatch.
- **Checks expires_at** against wall-clock time (RFC 0008). Rejects expired passports.
- **Applies admission policy** per the swarm's topology declaration. Closed: allowlist match. Open: registration-cost mechanism passes. Hybrid: closed_core allowlist or open_periphery cost mechanism passes.
- **Persists the passport** by content-address in the registry's pluggable store; produces a registration receipt with the passport's content-address as evidence.
- **Rejects duplicate AgentId** registration unless the new passport is a key rotation (same AgentId, different key, signed by an `agent.rotate_key` capability or operator override).
- **Returns RegistrationResult** with the registration receipt's hash on accept; with rejection_reason on reject.

Conformance tests in `/conformance/interface/registry/` exercise each of these explicitly. See the registry sub-suite Core level (per `/docs/conformance/conformance-suite.md` §3.1) for the full required matrix.

## 6. Key rotation, revocation, and reissue

Three operations that change a passport's effective authority:

- **Key rotation.** Same AgentId, new public key. Implemented as a Register call with the new passport, signed by the old private key (proving continuity), and tagged with `kind = "agent.rotate_key"`. Registry verifies, persists, and issues a rotation receipt. The old key is marked superseded; signatures it produced before rotation remain valid for historical receipts but cannot authorize new actions.

- **Revocation.** AgentId is marked invalid. Three pathways, each with a distinct receipt action_kind: **self-revoke** by the agent itself (`agent.revoke` via `AdmissionService.Revoke`); **operator-revoke** by a swarm operator presenting an `OperatorBearerToken` (`agent.operator_revoke` via `AdmissionService.OperatorRevoke`, RFC 0009); **constitution-revoke** driven by the norm-enforcement pipeline (Phase 2; receipt kind TBD with the constitution work). On any revocation, the control plane proactively tears down the target's active subscribe streams and rejects subsequent bearer tokens — revocations are immediate, not waiting for token expiry (RFC 0009 §3.3). Signatures the agent attempts after revocation are recorded for audit completeness but produce no new authoritative actions.

- **Reissue.** A fresh AgentId for the same logical agent. Used when continuity is undesirable (post-incident clean restart, end-of-life of a previous identity). This is a new registration, not a rotation; receipts under the old AgentId are not transferred.

These operations are deliberately distinct in receipt action_kind so audit is unambiguous: `agent.rotate_key`, `agent.revoke`, `agent.operator_revoke`, `agent.register`.

## 7. Alternatives considered

**Embedding capability tokens in the passport.** Rejected: it conflates declaration with authority and makes capability rotation harder than passport rotation. Kept separate.

**SPIFFE IDs as the AgentId format.** Considered. SPIFFE IDs are URI-shaped; UUID v7 is more compact and language-neutral, and SPIFFE-compatible identity can be carried as an extension or in `owner`. Phase 1 ADR pending — leaning UUID with a SPIFFE adapter rather than SPIFFE-native.

**Multi-swarm passports.** Rejected: cross-swarm leakage risk; federation handles the cross-swarm case explicitly in Phase 4.

**Mutable passports.** Rejected: a mutable passport breaks content-addressing and makes audit harder. Mutation is modeled as a new passport plus a key-rotation or capability-update receipt.

**X.509 / TLS client certs as the identity primitive.** Rejected for the agent layer. X.509 carries operational baggage (CRL, OCSP, PKI infrastructure) that doesn't map cleanly to short-lived agent identity. The transport layer uses TLS for channel encryption with separate identity binding — that's the appropriate place for X.509-style PKI.

## 8. Open questions for RFC review

- Should `framework` be a free-form string or an enumerated registry? Free-form is more open; an enum gates community-blessed adapters. Leaning free-form with a maintained list in /docs/community/.
- `default_model_provider` granularity: should it be (provider, model, version) tuple or free-form? Currently free-form. Pro: future-proof. Con: less normalized for cross-correlation.
- Resource declarations: should `max_usd_per_day_cents` be in the passport or only in the constitution? Currently both — the passport declares; the constitution can override down. Need to validate this isn't redundant.
- Signature scheme: lock at Ed25519 for v1.0 or allow algorithm negotiation now? Currently locked; PQ migration is an explicit future major-version bump.

## 9. Future evolution

- v1.1 likely adds optional `delegate_to_id` for supervisor-style delegation chains.
- v1.x adds BLAKE3 hash and key-fingerprint variants behind algorithm flags.
- v2.0 may revisit AgentId format if SPIFFE-native or DID-native identity becomes the right substrate.

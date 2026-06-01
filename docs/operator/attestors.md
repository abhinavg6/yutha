# Attestor backends — overview

An **Attestor** is the seam that decides *who is allowed to register
as an agent*. Every call to `AdmissionService.Register` is routed
through the configured Attestor before any passport is stored — so
the control plane can verify that the calling workload is who it
claims to be against the identity system your organization already
runs, rather than accepting any well-formed passport that arrives.

The default Attestor accepts every well-formed passport (matching
the pre-Phase-D behaviour — no extra infrastructure required).
External backends bind admission to a SPIRE workload-identity
deployment or to an OpenID Connect IdP your security team already
operates, so an agent can't join the swarm unless an external
identity system has already attested its workload.

This page explains what the Attestor seam does in plain language,
when you'd switch to an external backend, and how to pick between
the two shipped today. The per-backend pages cover provisioning
specifics.

---

## What an Attestor does

When an agent tries to join the swarm via `AdmissionService.Register`,
it presents a self-signed passport plus an optional
`external_credential` (a SPIFFE JWT-SVID, an OIDC ID-token, or empty
for the native flow). The configured Attestor:

1. **Verifies the credential** against external trust roots — the
   SPIRE trust bundle for SPIFFE, the IdP's JWKS for OIDC — or
   accepts the empty credential for the native default.
2. **Extracts an attested identity** — `spiffe://example.org/yutha/...`,
   `oidc:https://issuer/:subject`, or
   `yutha:native:<passport_pubkey_hex>` — that the audit log binds to
   the agent's `agent_id`.
3. **Projects allowlisted claims into receipt evidence** so auditors
   can chain a Yutha `agent_id` all the way back to the workload
   selectors (SPIRE) or token claims (OIDC) the identity system
   already records.

On rejection the call fails with `PERMISSION_DENIED` and an
`agent.register.deny` receipt lands in the audit log — no passport
is stored, no agent joins the swarm. The deny receipt's evidence
names *which* Attestor rejected and *why* (audience mismatch, expired
token, signature invalid, etc.) without leaking the credential bytes
themselves.

The Attestor never replaces the constitution layer — what an agent
is *allowed to do* once admitted stays with capabilities and the
Cedar+ constitution. The Attestor only decides *who gets in the
door*.

---

## When to use which

**`native` (the default)** — accepts any well-formed passport with a
future `expires_at`; records `yutha:native:<pubkey-hex>` as the
attested external identity. Zero infrastructure. The right choice
for local development, integration tests, demos, and any deployment
where the topology layer (open / closed / hybrid admission) gives
enough control over who joins.

**External Attestor backends** — when one or more of these applies:

- **No shadow IT identity.** Your organization already runs SPIRE,
  Okta, Auth0, Azure AD, or another workload-identity system. Agents
  shouldn't get a Yutha-only identity that bypasses what your
  security team already operates.
- **Compliance.** Audit requires every admission to be traceable to
  an externally-attested workload identity, not just a self-signed
  passport.
- **Sybil resistance.** In open-admission swarms, you want to prove
  that every joining agent corresponds to a real workload your
  identity system already vouched for — not an arbitrary
  passport-minter.
- **Cross-organization workflows.** SPIFFE trust-domain federation
  lets workloads from a partner organization join your swarm under
  a federated identity, without provisioning per-agent credentials
  on your side.

For local development, demos, and the examples shipped with the
repo, the default `native` Attestor is correct. None of them needs
SPIRE or an OIDC IdP.

---

## Backends shipped today

| Backend | Selector flag | Credential format | Operator runbook |
|---|---|---|---|
| **Native** (default) | `--attestor native` | none (accepts empty `external_credential`) | n/a — zero-config |
| **SPIFFE / SPIRE** | `--attestor spiffe` | JWT-SVID minted by the SPIRE workload API | [SPIFFE/SPIRE Attestor](spiffe-attestor.md) |
| **OpenID Connect** | `--attestor oidc` | OIDC ID-token minted by any OIDC IdP | [OIDC Attestor](oidc-attestor.md) |

Both external backends:

- Verify credentials offline against a cached trust bundle (SPIRE
  trust bundle, OIDC JWKS) — no per-admission round-trip to the
  identity system once steady state is reached.
- Hot-rotate the trust bundle (SPIFFE via the Workload API stream,
  OIDC via JWKS TTL refresh + kid-miss async refetch) so signing-key
  rotations at the identity system don't require a control-plane
  restart.
- Fail closed on any verification failure — the agent doesn't join
  and the audit log records the rejection with operator-actionable
  evidence.
- Never leak credential bytes into error messages or receipts (per
  RFC 0016 §3.1).

**Which to pick:**

- **SPIFFE / SPIRE** when you already run SPIRE or you want CNCF-
  standard workload identity. Strongest fit for Kubernetes deployments
  with SPIRE agents on every node, and for cross-organization
  federation via SPIFFE trust domains.
- **OIDC** when you don't run SPIRE but you do run an OIDC IdP
  (Okta, Auth0, Azure AD, Google Workspace, Keycloak). Broad-
  compatibility on-ramp — most enterprises can do this even if they
  can't do SPIFFE today.

Some operators run both at different layers (SPIRE for in-cluster
agents, OIDC for human-facing tool agents); v1 supports one Attestor
per control plane, so multi-Attestor deployments today run one
control plane per identity domain.

---

## How operators select a backend

Pick the backend at startup with one flag, then pass the per-backend
configuration with that backend's flag set:

```bash
# SPIFFE/SPIRE — Workload API socket (hot bundle rotation)
./yutha \
  --attestor spiffe \
  --attestor-spiffe-socket /run/spire/sockets/agent.sock \
  --attestor-spiffe-audience yutha-prod-payroll \
  [other startup flags]

# OIDC — Discovery against the IdP's issuer URL
./yutha \
  --attestor oidc \
  --attestor-oidc-issuer https://login.example.okta.com \
  --attestor-oidc-audience yutha-prod-payroll \
  [other startup flags]
```

Every `--attestor-*` flag has a matching `YUTHA_ATTESTOR_*` env var
if you prefer env-driven config. The **audience** value MUST be
swarm-specific — a generic value invites cross-swarm credential
replay; see each per-backend runbook §6.

Agents on the *other* side of the call need to fetch a matching
credential before they call `register()`. The developer-side
documentation lives at
[developer quickstart → joining a swarm with workload attestation](../developer/quickstart.md);
the gist is one extra keyword argument: `await
client.admission.register(passport, external_credential=svid_bytes)`.

---

## Where to go from here

- **[SPIFFE/SPIRE Attestor](spiffe-attestor.md)** — SPIRE
  registration entries + selectors, trust-bundle rotation, static-
  bundle (air-gapped) mode.
- **[OIDC Attestor](oidc-attestor.md)** — JWKS source choice
  (Discovery / `jwks_uri` override / static file), per-IdP recipes
  for Auth0 / Okta / Azure AD / Keycloak / Google Workspace.
- **[Enterprise identity end-to-end](enterprise-identity.md)** — the
  integrated walkthrough showing an Attestor paired with a Signer in
  one production deployment.
- **[Signer backends — overview](signers.md)** — the other
  enterprise-identity seam (custody of the control plane's signing
  key, vs the Attestor's external-identity verification).

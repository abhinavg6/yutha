# Signer backends — overview

A **Signer** is the seam that decides *where the Yutha control plane's
signing key lives*. Every passport, envelope, capability, bearer
token, and receipt the substrate produces is signed through this one
interface — but the key bytes themselves can sit in process memory,
in HashiCorp Vault, in GCP Cloud KMS, or in Azure Managed HSM,
depending on which backend the operator selects at startup.

The default backend keeps the key in process memory (no extra
infrastructure to stand up). External-custody backends move the key
into a KMS / HSM your security team already runs, so the bytes never
appear on disk or in a process dump and every signature is auditable
in the KMS's own log.

This page explains what the Signer seam does in plain language, when
you'd switch to an external backend, and how to pick between the
three shipped today. The per-backend pages cover provisioning and
operational specifics.

---

## What a Signer does

Every consequential action in Yutha leaves a signed artifact:

- **Passports** are signed when an agent registers (proof the agent
  controls the keypair the passport embeds).
- **Envelopes** are signed when sent (proof of who sent what).
- **Capabilities** are signed when issued or attenuated (proof of
  delegation chain).
- **Bearer tokens** are signed when minted (gRPC auth).
- **Receipts** are signed by the control plane (the audit log's
  integrity guarantee).

The `Signer` trait is a one-method interface — *give me canonical
bytes, return an Ed25519 signature that verifies under a known public
key* — and every call site in the substrate goes through it. Swapping
the implementation doesn't change any wire format, any receipt's
content-address, or any verification path. Same signatures, same
audit log; only the storage of the private key moves.

---

## When to use which

**`in-process` (the default)** — keys generated at startup, held in
process memory, never persisted. Zero infrastructure. The right
choice for local development, integration tests, demos, and any
deployment where the existing operator-key-via-bootstrap-seed
posture is acceptable.

**External KMS / HSM backends** — when one or more of these applies:

- **Compliance.** SOC 2, PCI-DSS, FedRAMP, or internal policy
  requires private keys to live in a FIPS-validated KMS / HSM, not
  in application memory.
- **Existing custody infrastructure.** Your security team already
  runs Vault / GCP KMS / Azure Managed HSM for other services, and
  this is one more workload that uses it.
- **Separation of duties.** The team operating the control plane
  shouldn't have direct access to the signing key; KMS access
  policies enforce that separately.
- **Audit visibility.** You want one log entry per Yutha signature
  in your KMS audit stream — useful for tying every receipt back to
  a specific KMS call from a specific service principal.
- **Key sharing.** Multiple control-plane instances (e.g., for
  active-passive failover) need to share an identity without
  copying private bytes between them.

For local development and the demos shipped with the repo, the
default in-process backend is correct. None of the examples need an
external KMS.

---

## Backends shipped today

| Backend | Selector flag | Custody type | Operator runbook |
|---|---|---|---|
| **In-process** (default) | `--signer in-process` | Ed25519 keypair in process memory | n/a — zero-config |
| **HashiCorp Vault** | `--signer vault` | Vault transit secrets engine, Ed25519 key | [Vault Signer](vault-signer.md) |
| **GCP Cloud KMS** | `--signer gcp-kms` | Cloud KMS asymmetric key, algorithm `EC_SIGN_ED25519` | [GCP KMS Signer](gcp-kms-signer.md) |
| **Azure Managed HSM** | `--signer azure-kv` | Managed HSM key, `kty=OKP-HSM`, `crv=Ed25519` | [Azure KV Signer](azure-kv-signer.md) |

All three external backends:

- Sign Ed25519 only (RFC 8032 deterministic signatures, matching the
  in-process default byte-for-byte).
- Cache the public key at startup so verification stays fast; every
  *sign* is a network round-trip, every *verify* stays in-process.
- Fail closed at startup if the configured key can't be loaded or
  has the wrong algorithm — the control plane never starts in a
  half-working state.

**AWS KMS** is not shipped because AWS KMS does not support Ed25519
natively. The recommended AWS-friendly path is `--signer vault`
against a Vault deployment colocated in AWS (the same `vaultrs`
client speaks to OSS, HCP, and self-hosted Enterprise Vault).

---

## How operators select a backend

Pick the backend at startup with one flag, then pass the per-backend
configuration with that backend's flag set:

```bash
# Vault (Token auth)
./yutha \
  --signer vault \
  --signer-vault-addr "$VAULT_ADDR" \
  --signer-vault-key yutha-bootstrap \
  --signer-vault-token-file ~/.yutha/vault-token \
  [other startup flags]

# GCP KMS (ADC handles auth — no Yutha-side credential flag)
./yutha \
  --signer gcp-kms \
  --signer-gcp-kms-key-version "projects/.../cryptoKeyVersions/1" \
  [other startup flags]

# Azure Managed HSM (DefaultAzureCredential handles auth)
./yutha \
  --signer azure-kv \
  --signer-azure-kv-vault-url https://yutha-hsm.managedhsm.azure.net \
  --signer-azure-kv-key-name bootstrap \
  --signer-azure-kv-key-version <hex-version> \
  [other startup flags]
```

Every `--signer-*` flag has a matching `YUTHA_SIGNER_*` env var if
you prefer env-driven config. Secret material is always passed by
*file path* (`--signer-vault-token-file`,
`--signer-vault-approle-secret-id-file`), never as a raw flag value —
so secrets never appear in `ps aux`, shell history, or
process-listing scrapes.

---

## One caveat to call out

`--signer` governs the *control plane's* signing identity — the key
that signs receipts, passports the control plane registers,
capabilities it issues, and bearer tokens it mints. Two related
identities are deliberately NOT (yet) governed by this flag:

- **The bootstrap agent's signing key.** Still derived from the
  bootstrap seed in-process. This is the first agent in the swarm,
  used for the admission bootstrap flow; operators don't typically
  externalise it because it's seed-derivable for testability.
- **The operator credential key** used by `yutha-ops` to mint
  operator-bearer tokens. Still in-process; extending `yutha-ops`
  with the same `--signer` flag set is a tracked follow-on. See
  [operator credentials — What's deferred](operator-credentials.md#whats-deferred).

The control plane's own identity is the load-bearing one — every
receipt's signature traces back to it — so externalising that is the
big win an enterprise gets from Phase G.

---

## Where to go from here

- **[Vault Signer](vault-signer.md)** — provisioning a transit key,
  Token vs AppRole auth, least-privilege policy.
- **[GCP KMS Signer](gcp-kms-signer.md)** — creating an
  `EC_SIGN_ED25519` key, ADC / Workload Identity setup,
  `cloudkms.signerVerifier` role binding.
- **[Azure KV Signer](azure-kv-signer.md)** — Managed HSM activation,
  `OKP-HSM` / `Ed25519` key, `DefaultAzureCredential` auth chain.
- **[Enterprise identity end-to-end](enterprise-identity.md)** — the
  integrated walkthrough showing a Signer paired with an Attestor in
  one production deployment.
- **[Attestor backends — overview](attestors.md)** — the other
  enterprise-identity seam (verifying *who* a principal is, vs the
  Signer's *what key signed this*).

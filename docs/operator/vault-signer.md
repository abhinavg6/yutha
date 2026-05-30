# Holding the bootstrap key in HashiCorp Vault

A 30-minute walkthrough for the operator who wants to move Yutha's
bootstrap signing key out of process memory and into
[HashiCorp Vault](https://developer.hashicorp.com/vault)'s transit
secrets engine. By the end you'll have:

- A Vault transit Ed25519 key the substrate signs against on every
  passport / envelope / capability / bearer mint / receipt operation.
- A Vault policy that grants the control-plane process exactly the
  two capabilities it needs (`read` on the key, `update` on `sign`).
- An auth path (Token or AppRole) the control plane uses to acquire
  its Vault client token.
- A `VaultSigner` wired through the control plane, with the in-process
  signer no longer present.

**What you get for free.** Every signing call site in the substrate
already flows through the [`Signer`](../concepts/primitives.md) trait
since RFC 0015's async refactor; swapping `InProcessSigner` for
`VaultSigner` is a single construction-site change. No call paths
move. No receipt formats change. Signatures stay byte-for-byte the
same — Ed25519 is deterministic, and Vault implements RFC 8032 just
like the in-process path does.

**What you write.** The Vault address, the policy, the auth method
choice, and the env-var configuration that points the control plane
at this backend.

If you haven't operated a Yutha swarm before, read the
[operator quickstart](quickstart.md) first — it covers the bootstrap
seed model and the gRPC server flags this doc assumes you're
comfortable with.

This walkthrough implements the Vault-transit backend pinned by
[RFC 0017 §4.1](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0017-external-signer-backends.md#41-hashicorp-vault-transit-yutha-signer-vault),
which itself is the AWS-friendly enterprise custody path nominated by
[RFC 0015 §9.1](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0015-signer-interface.md#91-aws-kms-ed25519-support--decided)
(since AWS KMS does not support Ed25519 today).

---

## Prerequisites

- Vault 1.13 or later. Vault OSS, HCP Vault, or self-hosted
  Enterprise all work. The free `vault server -dev` mode is fine for
  this walkthrough.
- The `vault` CLI v1.13+ available on your shell path.
- A Yutha control-plane checkout at `crates/yutha-control-plane` (this
  walkthrough exercises the binary).
- About 10–20 ms of additional sign latency budget per envelope —
  Vault transit is network-bound, vs. `InProcessSigner`'s in-memory
  Ed25519 of well under 100 µs.

You do **not** need any cloud account, KMS provisioning, or PKCS#11
hardware. The whole walkthrough runs against a local Vault dev
container.

---

## 1. Stand up a Vault dev server

A one-off container is enough for this walkthrough. In production
you'd point at your existing Vault cluster instead.

```bash
docker run --rm -d \
  --name yutha-vault \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=dev-root \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  hashicorp/vault:1.17

export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=dev-root
vault status
```

`vault status` should print `Initialized true / Sealed false`. The
dev-server token (`dev-root`) is over-privileged on purpose — we'll
provision a least-privilege token below before pointing Yutha at
this Vault.

> **Production note.** Plain HTTP is only OK for a dev container.
> `VaultSigner::connect` will warn but proceed if you point it at
> `http://...`. Production deployments MUST use HTTPS — Vault transit
> signs over the wire, and an attacker on the network can otherwise
> tamper with sign requests/responses.

---

## 2. Enable transit + create the Ed25519 key

The transit engine is what gives Vault its sign / verify / encrypt
RPCs. We only need sign.

```bash
vault secrets enable transit

vault write -f transit/keys/yutha-bootstrap type=ed25519

vault read transit/keys/yutha-bootstrap
```

The `read` output should show `type=ed25519` and a `keys` map with
version `1` and a base64-encoded `public_key`. That's the Ed25519
public key your Yutha swarm will sign against — it's safe to copy
into your monitoring / runbooks / out-of-band attestation channels.

You created the key without a derivation context (`derived=false`),
which is what we want — Yutha signs canonical bytes directly, no
per-request derivation.

---

## 3. Write the least-privilege policy

Yutha needs exactly two capabilities:

- `read` on `transit/keys/yutha-bootstrap` — to discover the public
  key at `connect()` time.
- `update` on `transit/sign/yutha-bootstrap` — to sign messages.

Nothing else. No `delete`, no `rotate`, no second key path. The
policy doc:

```bash
cat > /tmp/yutha-signer-policy.hcl <<'EOF'
path "transit/keys/yutha-bootstrap" {
  capabilities = ["read"]
}
path "transit/sign/yutha-bootstrap" {
  capabilities = ["update"]
}
EOF

vault policy write yutha-signer /tmp/yutha-signer-policy.hcl
```

The principle here is the same one as Yutha's capability layer: hand
out exactly the rights the consumer needs, and no more.

---

## 4. Pick an auth method

`yutha-signer-vault` supports **Token** and **AppRole** end-to-end.
Pick one:

### Option A — Token auth (simplest)

Mint a periodic token scoped to the `yutha-signer` policy:

```bash
vault token create \
  -policy=yutha-signer \
  -period=24h \
  -display-name="yutha-control-plane" \
  -format=json | jq -r '.auth.client_token'
```

Save that token into the env var the control plane reads:

```bash
export YUTHA_SIGNER_VAULT_TOKEN='<paste the token here>'
```

A periodic token renews itself on every read up to its `period`, so
as long as the control plane calls `lookup-self` / `renew-self`
periodically (or you run a Vault Agent sidecar that does this for
you), the token doesn't expire.

### Option B — AppRole auth (recommended for cloud VMs)

AppRole gives the control plane a `role_id` (durable, may be baked
into config) + a `secret_id` (rotated, typically delivered via some
out-of-band trust path). The Vault Signer logs in once at
`connect()`, gets a client token, and uses it for the rest of the
process lifetime.

```bash
vault auth enable approle

vault write auth/approle/role/yutha-control-plane \
  token_policies=yutha-signer \
  token_period=24h \
  bind_secret_id=true

ROLE_ID=$(vault read -field=role_id auth/approle/role/yutha-control-plane/role-id)
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/yutha-control-plane/secret-id)

export YUTHA_SIGNER_VAULT_APPROLE_ROLE_ID=$ROLE_ID
export YUTHA_SIGNER_VAULT_APPROLE_SECRET_ID=$SECRET_ID
```

The `secret_id` is single-use by default — once `VaultSigner::connect`
exchanges it for a client token at process startup, the secret_id is
consumed. To run again you mint a fresh one (or configure
`bind_secret_id=false` if your threat model allows it).

---

## 5. Tell the control plane to use Vault

Three env vars wire `VaultSigner` into the control-plane binary
alongside whichever auth env var you set above:

```bash
export YUTHA_SIGNER_VAULT_ADDR=$VAULT_ADDR        # http://127.0.0.1:8200
export YUTHA_SIGNER_VAULT_KEY=yutha-bootstrap     # the key name from step 2
# Optional: override the mount if you mounted transit somewhere else.
# export YUTHA_SIGNER_VAULT_MOUNT=transit
# Optional: Vault Enterprise namespace.
# export YUTHA_SIGNER_VAULT_NAMESPACE=ns1
```

The full env-var matrix is in the
[crate README](https://github.com/abhinavg6/yutha/blob/main/crates/yutha-signer-vault/README.md).

Then start the control plane normally. The bootstrap-seed flow you
used in the [quickstart](quickstart.md) is no longer needed — the
identity now lives in Vault, not in a seed env var. Remove
`YUTHA_BOOTSTRAP_SEED` from the process environment if it was set.

When the server starts you should see a log line like:

```
INFO yutha_signer_vault: yutha-signer-vault connected
  mount=transit key_name=yutha-bootstrap
  address=http://127.0.0.1:8200
```

That's `VaultSigner::connect` having authenticated, fetched the
public key, and cached it. From this point every passport / envelope
/ capability / bearer-token / receipt signing call is a network
round-trip to Vault.

---

## 6. Verify end-to-end

Run any existing Yutha integration test against this control plane.
The `test_integration::test_full_lifecycle` Python test (from the
`sdks/python/` directory) is a good end-to-end smoke:

```bash
cd sdks/python
YUTHA_CONTROL_PLANE_ADDR=http://127.0.0.1:7000 \
  pytest tests/test_integration.py::test_full_lifecycle -v
```

If you watch the Vault audit log in another shell during the run,
you'll see one `transit/sign/yutha-bootstrap` line per sign event:
the bootstrap passport, the operator passport, every envelope and
capability the test mints. Yutha's logs are unchanged — the only
thing that moved is where the key bytes live.

To turn the audit log on:

```bash
vault audit enable file file_path=stdout
docker logs -f yutha-vault | grep transit/sign
```

---

## 7. Failure modes you'll hit in practice

| Symptom (operator-visible) | Likely cause | Where to look |
|---|---|---|
| `SignerError::BackendRejected` mentioning HTTP 403 at startup | Token or AppRole credentials don't have the `yutha-signer` policy attached. | `vault token lookup <token>` — check `policies`. |
| `SignerError::BackendRejected` mentioning HTTP 404 at startup | Key name wrong, mount path wrong, or the key was never created. | `vault read transit/keys/<key>` should succeed under the token in use. |
| `SignerError::UnsupportedAlgorithm` at startup | The transit key isn't `type=ed25519`. | `vault read transit/keys/<key>` — `type` field. Delete the wrong-type key and recreate. |
| `SignerError::BackendUnavailable` during a sign | Vault sealed, network blip, or the cluster is down. | `vault status`; check the audit log + Vault server logs. The substrate's caller (passport mint, envelope send, etc.) returns a transient error; retry policy is the caller's. |
| Sign latency jumps from ms to seconds | Vault is in a different region than your control plane. | Co-locate. The expected steady-state is 5–20 ms intra-region, 50–150 ms cross-region. |
| The control plane starts but every gRPC call fails with `FAILED_PRECONDITION` | A constitution has not been activated. Vault has nothing to do with this — see [operator credentials](operator-credentials.md). | The constitution layer runs in-process; the Signer doesn't touch it. |

---

## 8. Rotating the Vault key

Yutha v1 does not yet support live key rotation — the public key is
cached at `connect()` and held until process restart. To rotate:

1. `vault write -f transit/keys/yutha-bootstrap/rotate` (creates
   version 2).
2. Either:
   - Restart the control plane to pick up the new version (simplest
     for closed swarms), or
   - Use the operator-revoke RPC and `rotate_key` admission flow to
     redirect agents at a new key path (see
     [operator credentials](operator-credentials.md)).

Real rotation hooks are tracked under the operator-credentials
follow-ons memo and will land before the public 0.2 release. For now,
plan for a restart at rotation time.

---

## 9. What this does NOT change

The Vault Signer is a *custody* swap, not a *protocol* swap. None of
these change when you adopt it:

- Receipt canonical bytes. Same wire format, same Merkle tree, same
  conformance vectors. The [Phase B sign-and-verify
  vectors](https://github.com/abhinavg6/yutha/tree/main/spec/vectors/signer)
  test the byte-equivalence of `InProcessSigner` against raw
  `SigningKey::sign_message`; the per-backend integration test under
  `crates/yutha-signer-vault/tests/integration.rs` asserts the
  same RFC 8032 verify-roundtrip property holds for Vault.
- Topology semantics. Closed / open / hybrid behave the same.
- Constitution evaluator + enforcement loop. All in-process; Vault
  has nothing to do with them.
- Operator credentials (RFC 0009). The operator's signing key is the
  same `Signer` trait — if you point both at the same Vault, both go
  through Vault. The operator-credential workflow is unchanged.

The only difference an observer would see externally: a signature
takes ~10–20 ms longer to mint, and a Vault audit-log entry exists
for every signing event.

---

## What's next

- **GCP KMS or Azure Key Vault**: the sibling crates
  `yutha-signer-gcp-kms` and `yutha-signer-azure-kv` ship in
  Phase C-C / C-D and follow the same connect-and-sign pattern.
  Each has its own walkthrough under `/docs/operator/`.
- **AWS KMS**: not supported in v1; AWS KMS does not have native
  Ed25519. The Vault path documented here is the recommended
  AWS-friendly approach. See [RFC 0015 §9.1](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0015-signer-interface.md#91-aws-kms-ed25519-support--decided).
- **Attestor**: signing custody (what this doc covers) is one of
  two enterprise-identity seams. The other is identity verification
  via SPIFFE/SPIRE or OIDC, which lands in Phase E / F. See
  [`/spec/identity-keys/README.md`](https://github.com/abhinavg6/yutha/blob/main/spec/identity-keys/README.md).

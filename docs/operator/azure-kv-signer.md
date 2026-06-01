# Holding the bootstrap key in Azure Key Vault Managed HSM

A 30–45 minute walkthrough for the operator who wants to move Yutha's
bootstrap signing key out of process memory and into an Azure
[Managed HSM](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/).
By the end you'll have:

- An activated Managed HSM with an Ed25519 key (`kty=OKP-HSM`,
  `crv=Ed25519`).
- A least-privilege RBAC binding (**Managed HSM Crypto User**) on
  exactly that key.
- A `DefaultAzureCredential`-based auth path (managed identity for
  AKS / Container Apps; env-var SP for VMs; `az login` for local dev).
- An `AzureKvSigner` wired through the control plane, with the
  in-process signer no longer holding the bootstrap seed.

**What you get for free.** Every signing call site in the substrate
already flows through the [`Signer`](../concepts/primitives.md) trait
since RFC 0015's async refactor; swapping `InProcessSigner` for
`AzureKvSigner` is a single construction-site change. No call paths
move. No receipt formats change.

**What you write.** The Managed HSM, the key, the RBAC binding, the
auth path, and the env-var wiring.

## The hard prerequisite

**You need a Managed HSM, not a standard Key Vault.** The standard
Azure Key Vault tier (`*.vault.azure.net`) does NOT support Ed25519
keys. Trying to point this signer at one will fail at startup with
`SignerError::UnsupportedAlgorithm`.

Managed HSM is a separate Azure resource SKU (~$3/hour per HSM
instance + per-operation fees as of 2026). If your platform team
already runs one, skip §1. If not, you'll need a privileged role to
create one (Owner or Contributor on the resource group); this isn't
something the Yutha control plane's service principal should be doing
ad-hoc.

If you haven't operated a Yutha swarm before, read the
[operator quickstart](quickstart.md) first.

If you're on AWS, see the [Vault Signer walkthrough](vault-signer.md);
if you're on GCP, see [GCP KMS Signer](gcp-kms-signer.md).

This walkthrough implements the Azure backend pinned by
[RFC 0017 §4.3](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0017-external-signer-backends.md#43-azure-key-vault-managed-hsm-yutha-signer-azure-kv).

---

## Prerequisites

- Azure subscription with the **Managed HSM** SKU available
  (most public regions).
- `az` CLI v2.50+ authenticated (`az login`) and pointed at the right
  subscription (`az account set --subscription <id>`).
- A resource group where you'll create the HSM.
- About 50–150 ms of additional signing latency budget per envelope —
  Managed HSM signing is slower than software KMS by design.

---

## 1. Create + activate the Managed HSM

> Skip this section if your platform team has already provisioned a
> Managed HSM you can use. Go straight to §2.

Managed HSM creation is a two-step process: **provision** (Azure brings
the hardware online) and **activate** (you download the security
domain — three RSA key shares that encrypt the HSM's root key).

```bash
HSM_NAME=yutha-hsm                    # globally unique
RG=yutha-rg
LOCATION=eastus

# Designate three administrators (by object ID).
# Use `az ad signed-in-user show --query id -o tsv` for your own ID.
ADMIN1_OID=...
ADMIN2_OID=...
ADMIN3_OID=...

az keyvault create \
  --hsm-name $HSM_NAME \
  --resource-group $RG \
  --location $LOCATION \
  --administrators $ADMIN1_OID $ADMIN2_OID $ADMIN3_OID \
  --retention-days 28
```

After ~10 minutes the HSM is provisioned but **not yet usable** — every
data-plane operation (including key creation) returns
`HsmNotActivated`. To activate, generate 3 RSA key pairs and download
the security domain:

```bash
mkdir certs
for i in 0 1 2; do
  openssl req -newkey rsa:4096 -nodes \
    -keyout certs/cert_$i.key \
    -x509 -days 365 \
    -subj "/CN=yutha-hsm-admin-$i" \
    -out certs/cert_$i.cer
done

az keyvault security-domain download \
  --hsm-name $HSM_NAME \
  --sd-wrapping-keys certs/cert_0.cer certs/cert_1.cer certs/cert_2.cer \
  --sd-quorum 2 \
  --security-domain-file ${HSM_NAME}-SD.json
```

> **Store the `.key` files + the `-SD.json` file like you'd store
> nuclear codes.** Losing them means losing the ability to recover
> the HSM if anything goes wrong with the Azure-side keys. Production
> deployments typically keep these in three different physical safes
> with separation of access; for testing, an encrypted USB drive
> stored offline is the minimum-viable hygiene.

---

## 2. Create the Ed25519 key

`OKP-HSM` is the key type and `Ed25519` is the curve. Yutha uses the
key for sign + verify operations.

```bash
KEY_NAME=bootstrap

az keyvault key create \
  --hsm-name $HSM_NAME \
  --name $KEY_NAME \
  --kty OKP-HSM \
  --curve Ed25519 \
  --ops sign verify \
  --query "key.kid" -o tsv
```

The output is the full key ID, e.g.
`https://yutha-hsm.managedhsm.azure.net/keys/bootstrap/a1b2c3d4...`.
The hex tail is the **key version** — save it; you'll pin it in §5.

To confirm the algorithm matches what Yutha expects:

```bash
az keyvault key show \
  --hsm-name $HSM_NAME \
  --name $KEY_NAME \
  --query "key.{kty: kty, crv: crv}"
```

Should print `{"kty": "OKP-HSM", "crv": "Ed25519"}`. If `kty` is
anything else, the Yutha signer will reject the key at startup.

---

## 3. Create the Yutha service principal (or reuse one)

This is the identity the control-plane process authenticates as.
Skip ahead if you already have one.

```bash
SP_NAME=yutha-control-plane

# Create an SP, capture appId + objectId.
SP_JSON=$(az ad sp create-for-rbac --name $SP_NAME --skip-assignment)
APP_ID=$(echo $SP_JSON | jq -r .appId)
TENANT_ID=$(echo $SP_JSON | jq -r .tenant)
CLIENT_SECRET=$(echo $SP_JSON | jq -r .password)
SP_OID=$(az ad sp show --id $APP_ID --query id -o tsv)

echo "AZURE_CLIENT_ID=$APP_ID"
echo "AZURE_TENANT_ID=$TENANT_ID"
echo "AZURE_CLIENT_SECRET=$CLIENT_SECRET   # store as a secret"
echo "SP_OID=$SP_OID   # used in the next step"
```

> **Production note.** SP client secrets are long-lived; prefer
> federated credentials (Workload Identity / OIDC) or managed identity
> where the runtime supports it. The env-var SP path is the lowest
> common denominator.

---

## 4. Grant least-privilege RBAC

The role is **Managed HSM Crypto User** (predefined; covers
`sign`, `verify`, `get`, `list`, `update`, `import` on keys). Scope it
to the *specific key*, not the whole HSM.

```bash
az role assignment create \
  --hsm-name $HSM_NAME \
  --assignee-object-id $SP_OID \
  --assignee-principal-type ServicePrincipal \
  --role "Managed HSM Crypto User" \
  --scope "/keys/$KEY_NAME"
```

If you scoped at `/` instead of `/keys/$KEY_NAME`, the SP would have
crypto-user rights on every key in the HSM — that's only appropriate
for an HSM dedicated to Yutha.

---

## 5. Pick an auth path

`AzureKvSigner` uses `DefaultAzureCredential`. Three paths, pick
whichever fits your deployment:

### Option A — Local dev (your laptop)

```bash
az login   # interactive browser flow
```

`DefaultAzureCredential` will pick up the cached `az` token and use
*your* identity. Make sure your user account has the
**Managed HSM Crypto User** role on the key, or impersonate the SP:

```bash
az login --service-principal \
  --username $AZURE_CLIENT_ID \
  --password $AZURE_CLIENT_SECRET \
  --tenant $AZURE_TENANT_ID
```

### Option B — Service-principal env vars (any VM / CI)

```bash
export AZURE_CLIENT_ID=$APP_ID
export AZURE_TENANT_ID=$TENANT_ID
export AZURE_CLIENT_SECRET=$CLIENT_SECRET
```

`DefaultAzureCredential` picks these up automatically. Use a secrets
manager (HashiCorp Vault, Kubernetes Secrets, Azure Key Vault — yes,
ironically) to deliver `AZURE_CLIENT_SECRET`; don't bake it into
process startup scripts.

### Option C — Managed Identity (AKS / Container Apps / VM Scale Sets)

Easiest and most secure. The runtime injects an identity that Yutha
never sees credentials for.

AKS via Workload Identity:

```bash
# Bind the K8s ServiceAccount to the Azure-side SP.
az identity federated-credential create \
  --name yutha-fed \
  --identity-name $SP_NAME \
  --resource-group $RG \
  --issuer $(az aks show -n <cluster> -g $RG --query oidcIssuerProfile.issuerUrl -o tsv) \
  --subject "system:serviceaccount:$NAMESPACE:$KSA_NAME"

# Annotate the K8s SA.
kubectl annotate sa $KSA_NAME -n $NAMESPACE \
  azure.workload.identity/client-id=$APP_ID
```

No env vars needed on the pod. `DefaultAzureCredential` detects the
projected service account token automatically.

---

## 6. Tell the control plane to use Azure Key Vault

`--signer azure-kv` plus two required flags wires `AzureKvSigner`
into the control-plane binary. Auth is via `DefaultAzureCredential`
(configured in §5) — no Yutha-side credential flag.

```bash
./yutha \
  --signer azure-kv \
  --signer-azure-kv-vault-url "https://$HSM_NAME.managedhsm.azure.net" \
  --signer-azure-kv-key-name $KEY_NAME \
  --signer-azure-kv-key-version "<32-char-hex from §2>" \
  [other flags from the quickstart]
```

`--signer-azure-kv-key-version` is technically optional (without it
the signer takes the latest version) but **strongly recommended in
production** — leaving it unset means Azure can auto-rotate the
underlying key behind your back and invalidate signatures from the
perspective of any verifier that cached the old public key. Pin per
[RFC 0017 §3.6](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0017-external-signer-backends.md#36-rotation-and-key-versions).

Every flag has a matching `YUTHA_SIGNER_AZURE_KV_*` env var
(`YUTHA_SIGNER_AZURE_KV_VAULT_URL`, `YUTHA_SIGNER_AZURE_KV_KEY_NAME`,
`YUTHA_SIGNER_AZURE_KV_KEY_VERSION`) if you prefer env-driven config.

The bootstrap-seed flow from the [quickstart](quickstart.md) is no
longer needed for the *control plane's* identity — that identity now
lives in the Managed HSM. The bootstrap *agent* is unaffected (still
in-process, seedable via `YUTHA_BOOTSTRAP_SEED` if set) — see the
[enterprise identity walkthrough](enterprise-identity.md) for the
two-identity distinction.

When the server starts you should see:

```
INFO yutha_signer_azure_kv: yutha-signer-azure-kv connected
  vault_url=https://yutha-hsm.managedhsm.azure.net
  key_name=bootstrap
  key_version=a1b2c3d4...
```

If `vault_url` doesn't end in `.managedhsm.azure.net`, you'll see a
`WARN` line above the connect message — that's the tier-mismatch
guardrail firing (see §10 below).

---

## 7. Verify end-to-end

Run any existing Yutha integration test against this control plane:

```bash
cd sdks/python
YUTHA_CONTROL_PLANE_ADDR=http://127.0.0.1:7000 \
  pytest tests/test_integration.py::test_full_lifecycle -v
```

If you tail Managed HSM audit logs during the run (assuming you've
enabled them via `az monitor diagnostic-settings`), you'll see one
`Sign` operation entry per Yutha signing event.

---

## 8. Failure modes you'll hit in practice

| Symptom (operator-visible) | Likely cause | Where to look |
|---|---|---|
| `SignerError::BackendRejected` mentioning 403 / `Forbidden` at startup | The SP doesn't have the **Managed HSM Crypto User** role on this key. | `az role assignment list --hsm-name <hsm> --query "[?principalId=='$SP_OID']"`. |
| `SignerError::BackendRejected` mentioning 401 / `Unauthorized` | `DefaultAzureCredential` couldn't resolve. Env vars unset, `az login` expired, no managed identity attached. | `az account show` (CLI path); pod logs for managed-identity probes. |
| `SignerError::BackendRejected` mentioning 404 | Wrong vault URL, wrong key name, or `KEY_VERSION` pointing at a destroyed version. | `az keyvault key list --hsm-name <hsm>`; verify `vault_url` exactly matches. |
| `SignerError::UnsupportedAlgorithm` at startup | The key isn't `OKP-HSM`/`Ed25519` (you accidentally created an RSA or EC key, or you're pointed at a standard Key Vault). | `az keyvault key show --hsm-name <hsm> --name <key> --query "key.{kty,crv}"`. |
| `SignerError::BackendUnavailable` during signing | Azure transient, throttle (429), or DNS / TLS hiccup. | [Azure status](https://azure.status.microsoft); check `kubectl logs` for retry behaviour. |
| `WARN yutha-signer-azure-kv: vault URL does not look like a Managed HSM` at startup | URL is `*.vault.azure.net` instead of `*.managedhsm.azure.net`. | Standard Key Vault doesn't support Ed25519 — create or use a Managed HSM. |
| Sign latency higher than 50–150 ms | Cross-region traffic, or HSM partition contention. | Co-locate the control plane with the HSM region. |

---

## 9. Rotating the key

Yutha v1 does not support live version-following — the public key is
cached at `connect()` and held until process restart. To rotate:

```bash
# Create a new version.
az keyvault key create \
  --hsm-name $HSM_NAME \
  --name $KEY_NAME \
  --kty OKP-HSM \
  --curve Ed25519 \
  --ops sign verify \
  --query "key.kid" -o tsv

# Update YUTHA_SIGNER_AZURE_KV_KEY_VERSION to the new hex + restart.
```

Plan for a restart at rotation time. Real live-rotation hooks are
tracked under the operator-credentials follow-ons memo.

> **Don't destroy the old version immediately.** Receipts signed under
> it are still verifiable against its public key for the lifetime of
> any external verifier that cached it. Use `az keyvault key set-attributes`
> to disable rather than destroy when you're done.

---

## 10. What this does NOT change

The Azure Key Vault Signer is a *custody* swap, not a *protocol* swap.
None of these change when you adopt it:

- Receipt canonical bytes, topology semantics, constitution evaluator,
  enforcement loop, operator credentials.
- Yutha's logs — only thing that moves is where the key bytes live.

The only differences an observer would see externally: ~50–150 ms
extra signing latency, and one Managed HSM audit entry per signing
event.

---

## What's next

- **GCP KMS or HashiCorp Vault**: the sibling crates
  `yutha-signer-gcp-kms` and `yutha-signer-vault` follow the same
  connect-and-sign pattern with their own walkthroughs.
- **AWS KMS**: not supported in v1; AWS KMS does not have native
  Ed25519. Use the [Vault Signer walkthrough](vault-signer.md) on AWS.
- **Attestor**: signing custody (this doc) is one of two
  enterprise-identity seams. The other is identity verification via
  SPIFFE/SPIRE or OIDC, landing in Phase E / F.

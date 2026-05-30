# yutha-signer-azure-kv

Azure Key Vault Managed HSM backend for the Yutha [`Signer`](../yutha-signer) trait.

The Ed25519 signing key lives inside an Azure Managed HSM (FIPS 140-2
Level 3); every Yutha sign call is an HTTPS RPC to `keys/<name>/sign`
with `alg=EdDSA`. The substrate never sees private bytes.

See [RFC 0017 §4.3](../../spec/rfcs/0017-external-signer-backends.md#43-azure-key-vault-managed-hsm-yutha-signer-azure-kv)
for the design pin.

## Tier requirement (read this first)

Ed25519 / EdDSA is only available on **Azure Key Vault Managed HSM**
(`*.managedhsm.azure.net`). The standard Key Vault tier
(`*.vault.azure.net`) **does NOT support Ed25519**. If you point this
crate at a standard Key Vault, `connect()` will return
`SignerError::UnsupportedAlgorithm` after observing the wrong key type.

Managed HSM is a separate, paid Azure resource — typically pre-purchased
by your platform team. If you don't have one, see the operator
walkthrough at `docs/operator/azure-kv-signer.md` for the one-time
`az keyvault create-hsm` activation flow.

## When to reach for this

- You're deploying Yutha into an Azure-native stack (AKS, Container
  Apps, Azure VMs) and your platform team already runs a Managed HSM.
- You need FIPS 140-2 Level 3 backing for the bootstrap signing key.
- You want signing audit events to land in Azure Monitor alongside
  the rest of your platform telemetry.

If you're on GCP, use [`yutha-signer-gcp-kms`](../yutha-signer-gcp-kms).
If you're on AWS, use [`yutha-signer-vault`](../yutha-signer-vault) —
AWS KMS doesn't support Ed25519 today.

## Operator prerequisites

- A Managed HSM resource that's been *activated* (security domain
  downloaded — see the walkthrough).
- An Ed25519 key inside it.
- An RBAC binding granting the Yutha process's identity the
  **Managed HSM Crypto User** role on the specific key.
- `DefaultAzureCredential` configured (managed identity for AKS /
  Container Apps; env-var SP for plain VMs; `az login` for local dev).

The smallest viable setup once you have an activated Managed HSM:

```bash
az keyvault key create \
  --hsm-name yutha-hsm \
  --name bootstrap \
  --kty OKP-HSM \
  --curve Ed25519 \
  --ops sign verify

az role assignment create \
  --hsm-name yutha-hsm \
  --assignee-object-id $YUTHA_SA_OBJECT_ID \
  --assignee-principal-type ServicePrincipal \
  --role "Managed HSM Crypto User" \
  --scope "/keys/bootstrap"
```

## Env-var convention

Per [RFC 0017 §3.2](../../spec/rfcs/0017-external-signer-backends.md#32-construction-and-config):

| Variable                                | Required | Default | Notes                                              |
|-----------------------------------------|----------|---------|----------------------------------------------------|
| `YUTHA_SIGNER_AZURE_KV_VAULT_URL`       | yes      | —       | Full Managed HSM URL (`https://<name>.managedhsm.azure.net`). |
| `YUTHA_SIGNER_AZURE_KV_KEY_NAME`        | yes      | —       | Name of the Ed25519 key inside the HSM.            |
| `YUTHA_SIGNER_AZURE_KV_KEY_VERSION`     | no       | latest  | Explicit version hex string. **Pin in production** — see RFC 0017 §3.6. |
| `AZURE_CLIENT_ID` / `_TENANT_ID` / `_CLIENT_SECRET` | one of   | —       | Service-principal env vars (one path of `DefaultAzureCredential`). |
| (managed identity / `az login`)         | one of   | —       | Auto-discovered by `DefaultAzureCredential`.       |

## Quick usage

```rust,no_run
use yutha_signer::Signer;
use yutha_signer_azure_kv::{AzureKvConfig, AzureKvSigner};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let config = AzureKvConfig::from_env()?;
let signer = AzureKvSigner::connect(config).await?;

// public_key is sync after connect; sign_message round-trips to Azure.
let pk = signer.public_key();
let sig = signer.sign_message(b"hello azure").await?;
# Ok(()) }
```

## Error mapping

`azure_core::Error` → [`SignerError`](../yutha-signer/src/error.rs), per
[RFC 0017 §3.4](../../spec/rfcs/0017-external-signer-backends.md#34-standardised-error-mapping):

| Azure response                                  | `SignerError` variant   | Retryable? |
|-------------------------------------------------|-------------------------|------------|
| 401 / 403 (auth / RBAC)                         | `BackendRejected`       | No         |
| 404 (key / version missing)                     | `BackendRejected`       | No         |
| 400 (bad request — wrong tier, wrong alg)       | `BackendRejected`       | No         |
| 429 (throttled) / 503 / 504 / transport         | `BackendUnavailable`    | Yes        |
| Non-`OKP`/`Ed25519` key (detected client-side)  | `UnsupportedAlgorithm`  | No         |
| URL parse / credential build / config invalid   | `Internal`              | No         |

## Integration test

`tests/integration.rs` runs the [RFC 0017 §3.7 conformance pattern](../../spec/rfcs/0017-external-signer-backends.md#37-conformance-pattern-for-non-seed-derivable-keys)
against a real Managed HSM key. Skipped by default; runs when
`YUTHA_SIGNER_AZURE_KV_VAULT_URL` + `YUTHA_SIGNER_AZURE_KV_KEY_NAME`
are set and `DefaultAzureCredential` can resolve.

```bash
# Local-dev auth.
az login

export YUTHA_SIGNER_AZURE_KV_VAULT_URL="https://yutha-hsm.managedhsm.azure.net"
export YUTHA_SIGNER_AZURE_KV_KEY_NAME=bootstrap
# Optional — recommended in production:
# export YUTHA_SIGNER_AZURE_KV_KEY_VERSION=<32-char-hex>

cargo test -p yutha-signer-azure-kv --test integration -- --ignored
```

The test stays `#[ignore]`-gated so `cargo test --workspace` still
passes on a developer laptop without Azure creds.

## SDK choice

Per RFC 0017 §4.3, this crate uses
[`azure_security_keyvault_keys`](https://crates.io/crates/azure_security_keyvault_keys)
+ [`azure_identity`](https://crates.io/crates/azure_identity) from
Microsoft's official
[`Azure/azure-sdk-for-rust`](https://github.com/Azure/azure-sdk-for-rust).
The crates are still on a 0.x line as of 2026; we pin a specific minor
in the workspace and bump on minor releases.

## License

Apache-2.0. See the repository [`LICENSE`](../../LICENSE).

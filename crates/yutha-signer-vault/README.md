# yutha-signer-vault

HashiCorp Vault transit-engine backend for the Yutha [`Signer`](../yutha-signer) trait.

The Ed25519 signing key lives inside Vault; every Yutha sign call is an HTTP
RPC to `transit/sign/<key>`. The substrate never sees private bytes. This is
the recommended enterprise-on-AWS custody path until AWS KMS adds native
Ed25519 support — see [RFC 0015 §9.1](../../spec/rfcs/0015-signer-interface.md#91-aws-kms-ed25519-support--decided)
and [RFC 0017 §4.1](../../spec/rfcs/0017-external-signer-backends.md#41-hashicorp-vault-transit-yutha-signer-vault).

## When to reach for this

- You're deploying Yutha into an environment that already runs Vault (most
  enterprises do; HCP Vault and Vault OSS both work).
- You want signing keys behind a network boundary but don't want to commit
  to a single cloud's KMS.
- You're on AWS and need Ed25519 — AWS KMS doesn't ship it natively today.

If you're hobby-scale or you're fine with the private key living in process
memory, stay with [`InProcessSigner`](../yutha-signer/src/inprocess.rs).
If you're on GCP or Azure, the sibling crates `yutha-signer-gcp-kms` and
`yutha-signer-azure-kv` will land in Phase C-C / C-D.

## Operator prerequisites

Vault 1.13+ with the transit secrets engine enabled and an Ed25519 key
provisioned. The smallest viable setup:

```bash
vault secrets enable transit
vault write -f transit/keys/yutha-bootstrap type=ed25519
```

Then grant the Yutha process a Vault token (or AppRole credentials) with a
policy that allows `read` on `transit/keys/yutha-bootstrap` and `update` on
`transit/sign/yutha-bootstrap`:

```hcl
path "transit/keys/yutha-bootstrap" {
  capabilities = ["read"]
}
path "transit/sign/yutha-bootstrap" {
  capabilities = ["update"]
}
```

## Env-var convention

Per [RFC 0017 §3.2](../../spec/rfcs/0017-external-signer-backends.md#32-construction-and-config),
the env-var prefix is `YUTHA_SIGNER_VAULT_*`:

| Variable                                 | Required | Default     | Notes                                          |
|------------------------------------------|----------|-------------|------------------------------------------------|
| `YUTHA_SIGNER_VAULT_ADDR`                | yes      | —           | Vault HTTPS URL.                               |
| `YUTHA_SIGNER_VAULT_KEY`                 | yes      | —           | Transit key name (just the name, not the path).|
| `YUTHA_SIGNER_VAULT_MOUNT`               | no       | `transit`   | Override if your transit engine is mounted elsewhere. |
| `YUTHA_SIGNER_VAULT_NAMESPACE`           | no       | —           | Vault Enterprise namespace (OSS Vault: leave unset). |
| `YUTHA_SIGNER_VAULT_TOKEN`               | one of   | —           | Pre-acquired client token (root, periodic, Agent-renewed). |
| `YUTHA_SIGNER_VAULT_APPROLE_ROLE_ID`     | one of   | —           | AppRole role_id.                               |
| `YUTHA_SIGNER_VAULT_APPROLE_SECRET_ID`   | one of   | —           | AppRole secret_id.                             |
| `YUTHA_SIGNER_VAULT_APPROLE_MOUNT`       | no       | `approle`   | Override if AppRole is mounted elsewhere.      |

`Token` always wins over `AppRole` when both sets are present, so operators
can override the auth method temporarily without unsetting the AppRole env
vars.

## Quick usage

```rust,no_run
use yutha_signer::Signer;
use yutha_signer_vault::{VaultConfig, VaultSigner};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let config = VaultConfig::from_env()?;
let signer = VaultSigner::connect(config).await?;

// public_key is sync after connect; sign_message round-trips to Vault.
let pk = signer.public_key();
let sig = signer.sign_message(b"hello vault").await?;
# Ok(()) }
```

## Auth methods supported in v1

| Method     | Variant                 | Status                           |
|------------|-------------------------|----------------------------------|
| Token      | `VaultAuth::Token`      | Supported.                       |
| AppRole    | `VaultAuth::AppRole`    | Supported.                       |
| Kubernetes | `VaultAuth::Kubernetes` | Reserved — `connect()` returns `SignerError::UnsupportedAlgorithm` in v1. Lands in a follow-on PR with integration coverage. |
| AWS IAM    | `VaultAuth::AwsIam`     | Reserved — same posture as above. |

## Error mapping

`vaultrs::ClientError` → [`SignerError`](../yutha-signer/src/error.rs), per
[RFC 0017 §3.4](../../spec/rfcs/0017-external-signer-backends.md#34-standardised-error-mapping):

| Vault response                | `SignerError` variant   | Retryable? |
|-------------------------------|-------------------------|------------|
| 401 / 403 (auth)              | `BackendRejected`       | No         |
| 404 (key missing)             | `BackendRejected`       | No         |
| 5xx                           | `BackendUnavailable`    | Yes        |
| Network / TLS / timeout       | `BackendUnavailable`    | Yes        |
| Non-Ed25519 transit key       | `UnsupportedAlgorithm`  | No         |
| URL parse / config invalid    | `Internal`              | No         |

Callers (the substrate's `Passport`/`Envelope`/`Capability`/bearer-mint
paths) only need to distinguish "back off and retry" (Unavailable) from
"alert an operator" (everything else); the rest is detail in the error
message.

## Integration test

`tests/integration.rs` runs the [RFC 0017 §3.7 conformance pattern](../../spec/rfcs/0017-external-signer-backends.md#37-conformance-pattern-for-non-seed-derivable-keys)
against a real Vault: connect → public_key matches expected → sign → verify
roundtrip + a couple of adversarial cases. Skipped by default; runs when
`YUTHA_SIGNER_VAULT_ADDR` + `YUTHA_SIGNER_VAULT_KEY` + an auth env var are
set.

To run it locally against a docker-vault dev server:

```bash
docker run --rm -d --name yutha-vault-it \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=dev-root \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  hashicorp/vault:1.17

# Provision the key + policy.
VAULT_ADDR=http://127.0.0.1:8200 \
VAULT_TOKEN=dev-root \
  vault secrets enable transit
VAULT_ADDR=http://127.0.0.1:8200 \
VAULT_TOKEN=dev-root \
  vault write -f transit/keys/yutha-integration type=ed25519

# Run the test.
YUTHA_SIGNER_VAULT_ADDR=http://127.0.0.1:8200 \
YUTHA_SIGNER_VAULT_TOKEN=dev-root \
YUTHA_SIGNER_VAULT_KEY=yutha-integration \
  cargo test -p yutha-signer-vault --test integration -- --ignored

docker stop yutha-vault-it
```

The test stays `#[ignore]`-gated so `cargo test --workspace` still passes
on a developer laptop without Vault running.

## SDK choice

Per RFC 0017 §4.1, this crate uses the community-maintained
[`vaultrs`](https://crates.io/crates/vaultrs) crate. There is no first-party
Rust Vault SDK from HashiCorp.

If you have a hard requirement to vendor instead of pulling `vaultrs`, the
public Vault transit HTTP API is two endpoints — `GET /v1/<mount>/keys/<name>`
and `POST /v1/<mount>/sign/<name>` — and a direct `reqwest` reimplementation
of this crate's `VaultSigner` is roughly 150 lines. The wire shapes are
documented at [transit secrets engine HTTP API](https://developer.hashicorp.com/vault/api-docs/secret/transit).

## License

Apache-2.0. See the repository [`LICENSE`](../../LICENSE).

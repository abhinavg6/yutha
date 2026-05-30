# yutha-signer-gcp-kms

Google Cloud KMS backend for the Yutha [`Signer`](../yutha-signer) trait.

The Ed25519 signing key lives inside GCP KMS (algorithm `EC_SIGN_ED25519`,
PureEdDSA over Curve25519); every Yutha sign call is a gRPC RPC to
`cryptoKeyVersions.asymmetricSign`. The substrate never sees private bytes.

See [RFC 0017 §4.2](../../spec/rfcs/0017-external-signer-backends.md#42-gcp-kms-yutha-signer-gcp-kms)
for the design pin.

## When to reach for this

- You're deploying Yutha into a GCP-native stack (GKE, Cloud Run, GCE)
  with Workload Identity already in place.
- You want hardware-backed key custody and your protection level of
  choice (SOFTWARE, HSM, HSM_SINGLE_TENANT, EXTERNAL).
- You're standardising on the official Google Cloud Rust SDK across
  your services and don't want a community Vault HTTP client in the
  dep tree.

If you're on AWS, use [`yutha-signer-vault`](../yutha-signer-vault) —
AWS KMS does not support Ed25519 today; see
[RFC 0015 §9.1](../../spec/rfcs/0015-signer-interface.md#91-aws-kms-ed25519-support--decided).
If you're on Azure, the sibling crate `yutha-signer-azure-kv` lands in
Phase C-D.

## Operator prerequisites

A GCP project with the Cloud KMS API enabled, a key ring + crypto key
of purpose `asymmetric-signing` and algorithm `ec-sign-ed25519`, and
ADC configured for the Yutha process. The smallest viable setup:

```bash
# One-time enable.
gcloud services enable cloudkms.googleapis.com

# Key ring + key.
gcloud kms keyrings create yutha --location=us-central1
gcloud kms keys create bootstrap \
  --location=us-central1 \
  --keyring=yutha \
  --purpose=asymmetric-signing \
  --default-algorithm=ec-sign-ed25519

# IAM — least privilege. Bind the signer/verifier role to the SA
# the Yutha process runs as.
gcloud kms keys add-iam-policy-binding bootstrap \
  --location=us-central1 \
  --keyring=yutha \
  --member="serviceAccount:yutha-control-plane@PROJECT_ID.iam.gserviceaccount.com" \
  --role=roles/cloudkms.signerVerifier
```

`roles/cloudkms.signerVerifier` is the predefined least-privilege role
for this crate's needs — it covers `getPublicKey` + `asymmetricSign`
on the specific key and nothing else.

## Env-var convention

Per [RFC 0017 §3.2](../../spec/rfcs/0017-external-signer-backends.md#32-construction-and-config):

| Variable                              | Required | Default | Notes                                                       |
|---------------------------------------|----------|---------|-------------------------------------------------------------|
| `YUTHA_SIGNER_GCP_KMS_KEY_VERSION`    | yes      | —       | Full path: `projects/.../cryptoKeyVersions/<n>`. Pin the explicit version. |
| `YUTHA_SIGNER_GCP_KMS_ENDPOINT`       | no       | global  | Override for regional endpoints / VPC SC perimeter proxies. |
| `GOOGLE_APPLICATION_CREDENTIALS`      | one of   | —       | Path to service-account JSON for local / VM dev.            |
| (Workload Identity attachment)        | one of   | —       | Auto-discovered by the SDK on GKE / Cloud Run / GCE.        |

## Quick usage

```rust,no_run
use yutha_signer::Signer;
use yutha_signer_gcp_kms::{GcpKmsConfig, GcpKmsSigner};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let config = GcpKmsConfig::from_env()?;
let signer = GcpKmsSigner::connect(config).await?;

// public_key is sync after connect; sign_message round-trips to GCP.
let pk = signer.public_key();
let sig = signer.sign_message(b"hello gcp").await?;
# Ok(()) }
```

## Error mapping

`google_cloud_kms_v1::Error` → [`SignerError`](../yutha-signer/src/error.rs),
per [RFC 0017 §3.4](../../spec/rfcs/0017-external-signer-backends.md#34-standardised-error-mapping):

| GCP response                              | `SignerError` variant   | Retryable? |
|-------------------------------------------|-------------------------|------------|
| `PERMISSION_DENIED` / `UNAUTHENTICATED`   | `BackendRejected`       | No         |
| `NOT_FOUND` (key version missing)         | `BackendRejected`       | No         |
| `FAILED_PRECONDITION` (key disabled, etc.)| `BackendRejected`       | No         |
| `UNAVAILABLE` / `DEADLINE_EXCEEDED`       | `BackendUnavailable`    | Yes        |
| Other 5xx / transport                     | `BackendUnavailable`    | Yes        |
| Non-`EC_SIGN_ED25519` key                 | `UnsupportedAlgorithm`  | No         |
| URL parse / config invalid                | `Internal`              | No         |

## Integration test

`tests/integration.rs` runs the [RFC 0017 §3.7 conformance pattern](../../spec/rfcs/0017-external-signer-backends.md#37-conformance-pattern-for-non-seed-derivable-keys)
against a real KMS key. Skipped by default; runs when
`YUTHA_SIGNER_GCP_KMS_KEY_VERSION` is set and ADC is configured.

```bash
# Local-dev ADC (browser flow).
gcloud auth application-default login

# Or, with a service-account key:
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json

export YUTHA_SIGNER_GCP_KMS_KEY_VERSION=\
"projects/$PROJECT_ID/locations/us-central1/keyRings/yutha/cryptoKeys/bootstrap/cryptoKeyVersions/1"

cargo test -p yutha-signer-gcp-kms --test integration -- --ignored
```

The test stays `#[ignore]`-gated so `cargo test --workspace` still
passes on a developer laptop without GCP creds.

## SDK choice

Per RFC 0017 §4.2, this crate uses
[`google-cloud-kms-v1`](https://crates.io/crates/google-cloud-kms-v1)
from Google's official
[`googleapis/google-cloud-rust`](https://github.com/googleapis/google-cloud-rust)
SDK. Pinned to `^1` in the workspace; the 1.x line is marked stable by
Google. ADC + Workload Identity are handled by the shared
`google-cloud-gax` runtime — no Yutha-side credential code.

The earlier community `google-cloud-kms` crate (yoshidan/google-cloud-rust)
is the documented fallback for operators who need to vendor without
Google's runtime crates.

## License

Apache-2.0. See the repository [`LICENSE`](../../LICENSE).

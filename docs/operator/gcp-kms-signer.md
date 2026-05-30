# Holding the bootstrap key in Google Cloud KMS

A 30-minute walkthrough for the operator who wants to move Yutha's
bootstrap signing key out of process memory and into
[Google Cloud KMS](https://cloud.google.com/kms). By the end you'll
have:

- A GCP KMS asymmetric key of algorithm `EC_SIGN_ED25519` (PureEdDSA
  over Curve25519, RFC 8032).
- A least-privilege IAM binding (`roles/cloudkms.signerVerifier`) on
  exactly that key.
- An ADC-based auth path (`gcloud auth application-default login` for
  local dev; Workload Identity for GKE / Cloud Run).
- A `GcpKmsSigner` wired through the control plane, with the in-process
  signer no longer holding the bootstrap seed.

**What you get for free.** Every signing call site in the substrate
already flows through the [`Signer`](../concepts/primitives.md) trait
since RFC 0015's async refactor; swapping `InProcessSigner` for
`GcpKmsSigner` is a single construction-site change. No call paths
move. No receipt formats change. Signatures stay byte-for-byte the
same — Ed25519 is deterministic and GCP KMS implements RFC 8032 just
like the in-process path does.

**What you write.** The GCP project + key ring + key, the IAM binding,
the ADC path, and the env-var wiring that points the control plane at
this backend.

If you haven't operated a Yutha swarm before, read the
[operator quickstart](quickstart.md) first.

If you're on AWS, see the [Vault Signer walkthrough](vault-signer.md)
instead — AWS KMS doesn't ship Ed25519 today
([RFC 0015 §9.1](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0015-signer-interface.md#91-aws-kms-ed25519-support--decided)).

This walkthrough implements the GCP backend pinned by
[RFC 0017 §4.2](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0017-external-signer-backends.md#42-gcp-kms-yutha-signer-gcp-kms).

---

## Prerequisites

- A GCP project where you can enable APIs and create KMS resources
  (the per-resource cost is ~$0.06/key-version/month for SOFTWARE keys
  plus ~$0.03 per 10,000 sign operations as of 2026).
- `gcloud` CLI authenticated (`gcloud auth login`) and pointed at the
  right project (`gcloud config set project PROJECT_ID`).
- A Yutha control-plane checkout at `crates/yutha-control-plane`.
- About 30–80 ms of additional sign latency budget per envelope —
  in-region. Cross-region adds the usual GCP RTT.

---

## 1. Enable Cloud KMS

```bash
gcloud services enable cloudkms.googleapis.com
```

---

## 2. Create the key ring + Ed25519 key

A key ring is a region-scoped container; the key inside it carries
the algorithm and protection level.

```bash
LOCATION=us-central1
KEYRING=yutha
KEYNAME=bootstrap

gcloud kms keyrings create $KEYRING --location=$LOCATION

gcloud kms keys create $KEYNAME \
  --location=$LOCATION \
  --keyring=$KEYRING \
  --purpose=asymmetric-signing \
  --default-algorithm=ec-sign-ed25519
```

Optional: pick a protection level. `--protection-level=software` is
the default (fine for non-regulated workloads); `--protection-level=hsm`
(adds ~$2.50/key-version/month) gives FIPS 140-2 Level 3 backing if
your compliance posture requires it.

Confirm the algorithm:

```bash
gcloud kms keys describe $KEYNAME \
  --location=$LOCATION \
  --keyring=$KEYRING

# Look for:
#   primary:
#     algorithm: EC_SIGN_ED25519
#     state: ENABLED
```

> **Wrong algorithm?** `GcpKmsSigner::connect` returns
> `SignerError::UnsupportedAlgorithm` at startup, naming the algorithm
> it found. The fix is to delete the wrong-algorithm key and recreate
> with `--default-algorithm=ec-sign-ed25519`.

---

## 3. Compute the full key-version resource path

Yutha names the *exact version*, not the key. This is the path you'll
plug into `YUTHA_SIGNER_GCP_KMS_KEY_VERSION`:

```bash
PROJECT_ID=$(gcloud config get-value project)
VERSION=1   # use the version your key is on; new keys start at 1.

KEY_VERSION_NAME="projects/$PROJECT_ID/locations/$LOCATION/keyRings/$KEYRING/cryptoKeys/$KEYNAME/cryptoKeyVersions/$VERSION"
echo $KEY_VERSION_NAME
```

Pinning the version is deliberate per
[RFC 0017 §3.6](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0017-external-signer-backends.md#36-rotation-and-key-versions):
rotation is operator-controlled. Letting Yutha auto-follow `primary`
would mean signing keys could change behind your back without a
control-plane restart.

---

## 4. Bind least-privilege IAM

Create a service account for the control plane (or reuse an existing
one) and grant `roles/cloudkms.signerVerifier` on this specific key.
That predefined role covers `getPublicKey` + `asymmetricSign` and
nothing else.

```bash
# Skip the create step if the SA already exists.
gcloud iam service-accounts create yutha-control-plane \
  --display-name="Yutha control plane"

SA="yutha-control-plane@$PROJECT_ID.iam.gserviceaccount.com"

gcloud kms keys add-iam-policy-binding $KEYNAME \
  --location=$LOCATION \
  --keyring=$KEYRING \
  --member="serviceAccount:$SA" \
  --role=roles/cloudkms.signerVerifier
```

The binding is scoped to the *key*, not the key ring — other keys in
the same ring stay invisible to this SA.

---

## 5. Pick an auth path

`GcpKmsSigner` uses Application Default Credentials. Three paths,
pick whichever fits your deployment:

### Option A — Local dev (your laptop)

```bash
gcloud auth application-default login
```

The browser flow drops a JSON credential under
`~/.config/gcloud/application_default_credentials.json`. The SDK
auto-finds it. No `GOOGLE_APPLICATION_CREDENTIALS` env var needed.

If you want the SA's permissions (not yours):

```bash
gcloud auth application-default login \
  --impersonate-service-account=$SA
```

### Option B — Service-account JSON file (CI / VM)

```bash
gcloud iam service-accounts keys create /etc/yutha/sa-key.json \
  --iam-account=$SA

export GOOGLE_APPLICATION_CREDENTIALS=/etc/yutha/sa-key.json
```

> **Production note.** Long-lived JSON keys are an audit liability.
> Prefer Workload Identity (Option C) on Kubernetes; or short-lived
> credential exchange via `gcloud iam service-accounts sign-jwt` if
> you're on a non-GCP VM with no workload-identity story.

### Option C — Workload Identity (GKE / Cloud Run / GCE)

GKE: bind a Kubernetes ServiceAccount to the Google ServiceAccount:

```bash
gcloud iam service-accounts add-iam-policy-binding $SA \
  --role=roles/iam.workloadIdentityUser \
  --member="serviceAccount:$PROJECT_ID.svc.id.goog[NAMESPACE/KSA_NAME]"

kubectl annotate serviceaccount KSA_NAME \
  -n NAMESPACE \
  iam.gke.io/gcp-service-account=$SA
```

No env vars needed on the pod — the SDK detects the metadata server
and exchanges automatically.

Cloud Run: set the service account at deploy time
(`gcloud run deploy --service-account=$SA`). Same story — the metadata
server handles the exchange.

---

## 6. Tell the control plane to use GCP KMS

```bash
export YUTHA_SIGNER_GCP_KMS_KEY_VERSION="$KEY_VERSION_NAME"
# Optional regional endpoint (lower latency, VPC SC compatibility):
# export YUTHA_SIGNER_GCP_KMS_ENDPOINT="https://us-central1-cloudkms.googleapis.com"
```

Then start the control plane normally. Remove `YUTHA_BOOTSTRAP_SEED`
from the environment — the identity now lives in GCP KMS, not in a
seed.

When the server starts you should see:

```
INFO yutha_signer_gcp_kms: yutha-signer-gcp-kms connected
  key_version=projects/.../cryptoKeyVersions/1
```

That's `GcpKmsSigner::connect` having authenticated, fetched the
public key, validated the algorithm is `EC_SIGN_ED25519`, and cached
the 32 raw bytes.

---

## 7. Verify end-to-end

Run any existing Yutha integration test against this control plane:

```bash
cd sdks/python
YUTHA_CONTROL_PLANE_ADDR=http://127.0.0.1:7000 \
  pytest tests/test_integration.py::test_full_lifecycle -v
```

If you tail the [Cloud Audit Logs](https://cloud.google.com/kms/docs/audit-logging)
during the run, you'll see one `AsymmetricSign` admin-activity entry
per Yutha signing event:

```bash
gcloud logging read \
  'resource.type="cloudkms_cryptokey"
   AND protoPayload.methodName="AsymmetricSign"
   AND resource.labels.crypto_key_id="bootstrap"' \
  --limit=10 \
  --format=json
```

Yutha's logs are unchanged — the only thing that moved is where the
key bytes live.

---

## 8. Failure modes you'll hit in practice

| Symptom (operator-visible) | Likely cause | Where to look |
|---|---|---|
| `SignerError::BackendRejected` mentioning 403 / `PERMISSION_DENIED` at startup | The SA hasn't been granted `cloudkms.signerVerifier` on this key. | `gcloud kms keys get-iam-policy <key> --keyring=… --location=…`. |
| `SignerError::BackendRejected` mentioning 401 / `UNAUTHENTICATED` | ADC isn't configured for the process. | `GOOGLE_APPLICATION_CREDENTIALS` unset and no Workload Identity attached, or the JSON file is stale. |
| `SignerError::BackendRejected` mentioning 404 / `NOT_FOUND` at startup | Wrong key path (typo in project/location/keyring/key), or `cryptoKeyVersions/N` points at a version that was destroyed. | `gcloud kms keys versions list --location=… --keyring=… --key=…`. |
| `SignerError::UnsupportedAlgorithm` at startup | Key isn't `EC_SIGN_ED25519`. | `gcloud kms keys describe …`; recreate with `--default-algorithm=ec-sign-ed25519`. |
| `SignerError::BackendUnavailable` during signing | Transient GCP outage, deadline exceeded, or network blip. | [GCP status dashboard](https://status.cloud.google.com); check egress firewall to `cloudkms.googleapis.com`. The caller will retry per its policy. |
| Sign latency much higher than the 30–80 ms baseline | Cross-region traffic, or SOFTWARE protection level under heavy load. | Set `YUTHA_SIGNER_GCP_KMS_ENDPOINT` to the regional endpoint matching your VM region; consider HSM if you need consistent latency under load. |

---

## 9. Rotating the key

Yutha v1 does not support live key-version following — the public key
is cached at `connect()` and held until process restart. To rotate:

```bash
# Create version 2.
gcloud kms keys versions create \
  --location=$LOCATION \
  --keyring=$KEYRING \
  --key=$KEYNAME

# Update the env var to point at the new version + restart the control plane.
export YUTHA_SIGNER_GCP_KMS_KEY_VERSION="projects/.../cryptoKeyVersions/2"
```

Plan for a restart at rotation time. Real live-rotation hooks are
tracked under the operator-credentials follow-ons memo.

> **Don't destroy version 1 immediately.** Receipts signed under it
> are still verifiable against the version-1 public key for the
> lifetime of any external verifier that cached it. Disable rather
> than destroy when you're done.

---

## 10. What this does NOT change

The GCP KMS Signer is a *custody* swap, not a *protocol* swap. None
of these change when you adopt it:

- Receipt canonical bytes. Same wire format, same Merkle tree, same
  conformance vectors.
- Topology semantics. Closed / open / hybrid behave the same.
- Constitution evaluator + enforcement loop. All in-process; GCP KMS
  has nothing to do with them.
- Operator credentials (RFC 0009). The operator's signing key is the
  same `Signer` trait — if you point both at GCP, both go through GCP.
  The operator-credential workflow is unchanged.

The only differences an observer would see externally: ~30–80 ms of
extra signing latency, and one Cloud Audit Logs entry per signing
event.

---

## What's next

- **Azure Key Vault Managed HSM**: the sibling crate
  `yutha-signer-azure-kv` ships in Phase C-D and follows the same
  connect-and-sign pattern.
- **AWS KMS**: not supported in v1; AWS KMS does not have native
  Ed25519. The [Vault Signer walkthrough](vault-signer.md) is the
  recommended AWS-friendly approach.
- **Attestor**: signing custody (this doc) is one of two
  enterprise-identity seams. The other is identity verification via
  SPIFFE/SPIRE or OIDC, landing in Phase E / F.

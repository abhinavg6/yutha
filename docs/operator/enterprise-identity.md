# Enterprise identity end-to-end

A 60-minute walkthrough that puts both halves of Yutha's enterprise-
identity story into one running deployment. By the end you'll have:

- The control plane's bootstrap signing identity held in **HashiCorp
  Vault transit** instead of process memory — every passport, envelope,
  capability, and bearer-token signature now goes to Vault.
- The control plane verifying every `AdmissionService.Register` call
  against a **SPIRE-issued JWT-SVID** — workloads that aren't attested
  by SPIRE cannot join the swarm at all.
- A first agent registered using its SPIRE SVID as the
  `external_credential`, with the resulting `agent.register` receipt
  recording the SPIFFE ID + selectors as evidence so auditors can chain
  Yutha identities back to attested workloads.
- A clear deny path: any registration without a valid SVID, or signed
  by a non-Vault key, fails closed at startup or first call with
  operator-actionable receipts.

**What this walkthrough is, and isn't.** This page is the *integration
story* — how the [Signer](signers.md) and [Attestor](attestors.md)
seams compose into one production-grade deployment. It deliberately
defers the per-backend specifics (Vault policy authoring, SPIRE
selector design, key creation, IAM) to the dedicated runbooks. Treat
each per-backend page as the deep reference; this page as the
recipe that stitches them together.

If you haven't operated a Yutha swarm before, read the
[operator quickstart](quickstart.md) first — it covers the
bootstrap-seed model, gRPC server flags, and the operator credential
this walkthrough assumes you're comfortable with.

This walkthrough implements the deployment pattern pinned by
[RFC 0015](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0015-signer-interface.md)
(Signer interface),
[RFC 0016](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0016-attestor-interface.md)
(Attestor interface), and
[RFC 0017](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0017-external-signer-backends.md)
(External Signer backends).

---

## Why these two seams travel together

The two halves answer two different questions:

| | Signer (RFC 0015 / 0017) | Attestor (RFC 0016) |
|---|---|---|
| **Question** | *Whose key just signed this artifact?* | *Is the caller actually the workload it claims to be?* |
| **Hot path** | Every passport / envelope / capability / bearer / receipt **mint** | Every `AdmissionService.Register` **call** |
| **Custody** | Keys live in Vault / GCP KMS / Azure HSM, never on disk | SVIDs are issued by SPIRE / OIDC IdP, verified by Yutha |
| **What ships in v1** | `yutha-signer-{vault,gcp-kms,azure-kv}` | `yutha-attestor-{spiffe,oidc}` |

You can adopt either independently — and many operators will. But the
two together give you the property an enterprise audit usually
requires: **every signed artifact in the swarm traces back to a
workload identity that an external system has attested**, and the
operator's bootstrap key never sits on disk. That's the deployment
this walkthrough delivers.

---

## Prerequisites

Five things on hand before any commands run:

**1. A running SPIRE deployment** (server + agent), 1.10 or later.
   Either a production deployment or the local-testing recipe at
   [`crates/yutha-attestor-spiffe/tests/SPIRE_LOCAL_TESTING.md`](https://github.com/abhinavg6/yutha/blob/main/crates/yutha-attestor-spiffe/tests/SPIRE_LOCAL_TESTING.md).

**2. A reachable HashiCorp Vault**, 1.13 or later. For evaluation
   `vault server -dev` is fine; for production point at your existing
   Vault cluster.

**3. Yutha control plane built**:

```bash
cargo build -p yutha-control-plane --release
```

**4. The two backend overview pages open in another tab** for
   reference if you want to compare backends or hit something
   this page doesn't cover:

- [Signer backends — overview](signers.md) — what a Signer is, when
  to use which backend, links to the Vault / GCP KMS / Azure HSM
  runbooks.
- [Attestor backends — overview](attestors.md) — what an Attestor
  is, when to use which backend, links to the SPIFFE/SPIRE / OIDC
  runbooks.

**5. About 30–60 ms of additional admission/sign latency budget per
   call.** Vault transit adds 5–20 ms per sign (network round-trip);
   SPIFFE verify is offline JWS, CPU-bound at single-digit ms. Steady
   state remains well inside any reasonable SLA.

You do **not** need any cloud account for this walkthrough — both
backends run locally. Cloud-KMS variants (GCP, Azure) are noted at the
end under [alternative backends](#alternative-backends).

---

## 1 — Provision the SPIRE workload entry

You're going to point the control plane at SPIRE for SVID
verification, and you'll want at least one registered workload (the
first agent) so the end-to-end path has something to verify against.

**Choose the audience string up front.** Pick a swarm-specific,
non-generic value — for example `yutha-prod-payroll` or
`yutha-${SWARM_NAME}-${ENV}`. Generic values like `yutha-prod` invite
cross-system SVID replay; per `attestor-spiffe.md` §6.1, audience
narrowness is the operator's single best defense against confused-
deputy attacks across SPIRE workloads.

```bash
export YUTHA_AUDIENCE=yutha-walkthrough
```

**Register one workload entry** in SPIRE for the agent process you'll
register first. The selector set depends on where your agent runs —
the SPIRE quickstart covers `unix:uid:<id>`, `k8s:ns:<namespace>`, and
`docker:label:<key>:<value>` as the common ones. Example for a Linux
service running under uid 1000:

```bash
spire-server entry create \
  -spiffeID  spiffe://example.org/yutha/agent-alpha \
  -parentID  spiffe://example.org/spire/agent/x509pop/<agent-sha> \
  -selector  unix:uid:1000
```

The full SPIRE selector and registration-entry catalogue is in the
[Vault Signer runbook](vault-signer.md) (linked from
`spiffe-attestor.md` §4) — this page doesn't try to re-explain SPIRE.

**Verify a workload can mint an SVID** for the chosen audience:

```bash
spire-agent api fetch jwt -audience "$YUTHA_AUDIENCE" -socketPath /tmp/agent.sock
```

You should get a JWT-SVID printed to stdout. Stash it for §5:

```bash
export YUTHA_FIRST_AGENT_SVID="$(spire-agent api fetch jwt \
  -audience "$YUTHA_AUDIENCE" \
  -socketPath /tmp/agent.sock \
  | sed -n 's/^token(spiffe[^)]*):\s*//p' | head -n1)"
```

---

## 2 — Provision the Vault transit key

You're going to hold the control plane's bootstrap signing key here.
Three steps; the deep walkthrough in [vault-signer.md](vault-signer.md)
covers each in detail — only what's needed for the integrated path
appears below.

**Start Vault dev (skip if pointing at existing cluster):**

```bash
docker run --rm -d --name yutha-vault \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=dev-root \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  hashicorp/vault:1.17

export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=dev-root
vault status
```

**Create the transit Ed25519 key + least-privilege policy:**

```bash
vault secrets enable transit
vault write -f transit/keys/yutha-bootstrap type=ed25519

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

**Mint an AppRole role + secret_id for the control plane** (recommended
production posture; Token auth is fine for dev — see vault-signer.md
§4 for the trade-off):

```bash
vault auth enable approle 2>/dev/null || true

vault write auth/approle/role/yutha-control-plane \
  token_policies=yutha-signer \
  token_period=24h \
  bind_secret_id=true

ROLE_ID=$(vault read -field=role_id auth/approle/role/yutha-control-plane/role-id)
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/yutha-control-plane/secret-id)

# Write the secret_id to a file — Yutha reads it via a file path, not
# a raw flag value, so the secret never appears in `ps aux`.
mkdir -p ~/.yutha
echo -n "$SECRET_ID" > ~/.yutha/vault-secret-id
chmod 600 ~/.yutha/vault-secret-id

echo "ROLE_ID: $ROLE_ID"
echo "secret_id file: ~/.yutha/vault-secret-id"
```

**Sanity check** the policy is right by simulating a sign with that
role:

```bash
# Log in with the secret-id you just minted (consumed on first use
# by the AppRole backend; the control plane will mint its own at
# startup).
TEST_SECRET=$(vault write -f -field=secret_id auth/approle/role/yutha-control-plane/secret-id)
TEST_TOKEN=$(vault write -field=token auth/approle/login \
  role_id="$ROLE_ID" secret_id="$TEST_SECRET")

VAULT_TOKEN="$TEST_TOKEN" \
  vault write transit/sign/yutha-bootstrap \
  input="$(echo -n 'walkthrough sanity check' | base64)" \
  | grep '^signature'
```

You should see a single `signature  vault:v1:…` line. If you get HTTP
403, the policy isn't attached correctly — re-check `vault token
lookup "$TEST_TOKEN"` and confirm `policies` contains `yutha-signer`.

---

## 3 — Configure the control plane

This is the integration step — both backends arrive on the command
line together. The default for both flags is the zero-config in-process
backend, so adding the eight `--signer-vault-*` / `--attestor-spiffe-*`
flags is the entire diff from a dev-mode startup.

```bash
export YUTHA_OPERATOR_PUBLIC_KEY=<your operator public key — see operator-credentials.md>

cargo run --release -p yutha-control-plane -- \
  --grpc-addr 0.0.0.0:50051 \
  --admission-mode closed \
  --operator-public-key "$YUTHA_OPERATOR_PUBLIC_KEY" \
  \
  --signer vault \
  --signer-vault-addr "$VAULT_ADDR" \
  --signer-vault-key yutha-bootstrap \
  --signer-vault-approle-role-id "$ROLE_ID" \
  --signer-vault-approle-secret-id-file ~/.yutha/vault-secret-id \
  \
  --attestor spiffe \
  --attestor-spiffe-socket /tmp/agent.sock \
  --attestor-spiffe-audience "$YUTHA_AUDIENCE"
```

Expected startup log lines (interleaved with the usual gRPC server
boot lines):

```
INFO yutha_signer_vault: yutha-signer-vault connected
  mount=transit key_name=yutha-bootstrap address=http://127.0.0.1:8200
INFO yutha_attestor_spiffe: SPIFFE Attestor connected
  source=WorkloadApi socket=/tmp/agent.sock audience=yutha-walkthrough
INFO yutha: yutha gRPC server listening on 0.0.0.0:50051
```

**Why these flags compose cleanly.** Every signing call site in the
substrate already flows through the `Signer` trait, and every
admission call flows through the `Attestor` trait. The CLI just
selects the implementation; no call paths move and no receipt
formats change. From an external observer's point of view, every
artifact's signature is still Ed25519, every receipt still verifies
against a registered passport, and every conformance vector still
passes byte-for-byte.

**Defaults you didn't have to change:** TLS, mTLS, receipt-backend,
admission-mode, workloads, anchoring — all orthogonal. The
[Deployment](deployment.md) page covers the production posture for
each; the enterprise-identity flags layer on top of whatever you
already deploy.

---

## 4 — Register the first agent with its SVID

With both backends wired, every `AdmissionService.Register` call now
requires a valid SVID in the request's `external_credential` field.
The Python SDK call shape:

```python
from yutha import YuthaClient, InProcessSigner
import os

svid = os.environ["YUTHA_FIRST_AGENT_SVID"]  # captured in §1

signer = InProcessSigner.generate()
client = await YuthaClient.connect(
    "http://localhost:50051",
    agent_id="agent-alpha",
    signer=signer,
    external_credential=svid.encode("utf-8"),
)
```

The control plane calls `SpiffeAttestor::verify(svid)` before any
passport gets stored. On success, the resulting `agent.register`
receipt's `evidence` map carries the SPIFFE ID and SPIRE selectors so
the audit trail chains the Yutha `agent_id` back to the attested
workload:

```json
{
  "kind": "agent.register",
  "evidence": {
    "external_identity": "spiffe://example.org/yutha/agent-alpha",
    "attestor": "spiffe",
    "attestor.attributes.audience": "yutha-walkthrough"
  },
  "...": "..."
}
```

The control plane's *own* passport (registered at startup, before any
agent connects) is signed by Vault. Pull it from the receipt store
and verify against the Vault-held public key:

```bash
# The CP's pubkey is what vault read returned in §2.
vault read transit/keys/yutha-bootstrap \
  | grep public_key
```

Compare the base64-decoded last 32 bytes against the
`agent_public_key` field on the control plane's own passport (visible
in the first `agent.register` receipt or via the Admission RPC).
They must match exactly — if they don't, you've configured the
control plane against the wrong Vault key.

---

## 5 — Watch the deny paths fire

Both backends should fail closed when something's wrong. Confirm.

**SVID rejection.** Send a `Register` with an empty or invalid
external_credential — the call returns `PERMISSION_DENIED` and the
control plane writes an `agent.register.deny` receipt:

```python
try:
    await YuthaClient.connect(
        "http://localhost:50051",
        agent_id="agent-evil",
        signer=InProcessSigner.generate(),
        external_credential=b"not-a-real-svid",
    )
except grpc.aio.AioRpcError as e:
    assert e.code() == grpc.StatusCode.PERMISSION_DENIED
```

Pull the resulting deny receipt — the `evidence` map will name the
Attestor and the rejection reason without leaking the offending
credential bytes (per RFC 0016 §3.1 — no PII in Attestor errors).

**Signer outage.** Stop Vault (`docker stop yutha-vault`). The next
`Register` attempt returns `INTERNAL: signer backend unavailable`
because the control plane can't sign the response passport. Restart
Vault and registration recovers — Yutha does not cache signatures
across restarts, so there's no consistency window to worry about.

**Wrong audience.** Re-mint an SVID with a different audience and try
to register with it:

```bash
WRONG_SVID=$(spire-agent api fetch jwt -audience other-audience -socketPath /tmp/agent.sock | ...)
```

`PERMISSION_DENIED` again, deny receipt evidence names "audience
mismatch" — exactly the cross-swarm replay attack the
swarm-specific-audience guideline in §1 prevents.

---

## Alternative backends

The two `--signer …` / `--attestor …` enums are the only knobs the
control plane needs to swap each backend; every other CLI flag is
backend-specific and well-documented in the per-backend runbooks.

**Signer alternatives:**

| Flag | Backend | Runbook |
|---|---|---|
| `--signer vault` | HashiCorp Vault transit | [vault-signer.md](vault-signer.md) |
| `--signer gcp-kms` | GCP Cloud KMS (Ed25519 crypto key) | [gcp-kms-signer.md](gcp-kms-signer.md) |
| `--signer azure-kv` | Azure Managed HSM | [azure-kv-signer.md](azure-kv-signer.md) |
| `--signer in-process` | Default; keys in process memory | n/a |

**Attestor alternatives:**

| Flag | Backend | Runbook |
|---|---|---|
| `--attestor spiffe` | SPIFFE/SPIRE JWT-SVIDs | [spiffe-attestor.md](spiffe-attestor.md) |
| `--attestor oidc` | OpenID Connect ID tokens | [oidc-attestor.md](oidc-attestor.md) |
| `--attestor native` | Default; accepts empty credential | n/a |

**The four 2×2 combinations operators most often pick:**

- **Vault + SPIFFE/SPIRE** — this walkthrough; the typical on-prem or
  Kubernetes-with-SPIRE deployment.
- **GCP KMS + OIDC (Google identity)** — GKE workloads attesting via
  GCP's OIDC issuer for the workload identity pool.
- **Azure Managed HSM + OIDC (Azure AD)** — AKS workloads attesting
  via Azure AD's OIDC issuer.
- **Vault + OIDC** — Vault for custody when the org already runs
  Vault, OIDC for attestation when the workload identities live in
  an existing Okta / Auth0 / IdP.

Whichever pair you pick, the CLI shape is identical: pick the
`--signer …` flag and provide its per-backend flags, pick the
`--attestor …` flag and provide its per-backend flags, restart.

---

## What this does NOT change

The Signer + Attestor swaps are *custody* and *attestation* changes,
not *protocol* changes. None of these move when you adopt them:

- **Receipt canonical bytes.** Same wire format, same Merkle tree,
  same [conformance vectors](https://github.com/abhinavg6/yutha/tree/main/spec/vectors).
  The Phase B sign-and-verify vectors test the byte-equivalence of
  `InProcessSigner` against raw `SigningKey::sign_message`; the
  per-backend integration tests under each
  `crates/yutha-signer-*/tests/integration.rs` assert the same
  RFC 8032 verify-roundtrip property holds for every backend.
- **Topology semantics.** Closed / open / hybrid behave the same.
  Admission mode is orthogonal to which Attestor is wired in.
- **Constitution evaluator + four-stage enforcement.** All in-process;
  Signer and Attestor never run inside `EnvelopeService.Send`'s hot
  path.
- **Operator credentials** (RFC 0009). The operator-credential
  workflow is unchanged. The operator key still derives from the
  bootstrap seed in `yutha-ops` and signs in-process; extending
  `yutha-ops` with the same `--signer` flag set as the control
  plane (so the operator key can also live in Vault / GCP KMS /
  Azure Managed HSM) is a natural follow-on, not in v1. See the
  "KMS-backed custody for the operator key" bullet under
  [operator credentials → What's deferred](operator-credentials.md#whats-deferred).
- **Sui anchoring** (if you've enabled it). The sealer key is a
  separate Signer instance (RFC 0014); it's currently held in a file
  but the same trait surface means it can move into a separate Vault
  transit key when operator-key-rotation hooks land (tracked under
  the operator-credentials follow-ons memo).

The only difference an outside observer sees externally: an extra
~10–20 ms per sign (Vault round-trip), an extra ~2–10 ms per
register (offline SVID verify), and an external audit trail in Vault
+ SPIRE that ties every Yutha artifact back to an attested workload
identity.

---

## Failure modes you'll hit in practice

The deny paths in §5 are the happy-path-style failures (the system
working as designed). The list below is what's actually surprising
the first few times.

| Symptom | Likely cause | Where to look |
|---|---|---|
| Server fails to start with `--signer vault: invalid configuration: missing field` | One of `--signer-vault-{addr,key}` is unset, or the AppRole pair is incomplete (need both `role-id` AND `secret-id-file`) | The error message names the missing flag |
| Server fails to start with `Vault Signer construction failed: HTTP 403` | The AppRole secret_id has already been consumed (single-use by default), or the role's policies don't include `yutha-signer` | Re-mint the secret_id; or set `bind_secret_id=false` on the role for repeatable boot (weaker security) |
| Server starts but every `Register` fails with `PERMISSION_DENIED: audience mismatch` | The SVID's `aud` claim doesn't equal `--attestor-spiffe-audience` exactly | `spire-server entry list` — the audience MUST be the one the workload's SVID is minted with |
| Sign latency jumps to seconds | Vault is in a different region than the control plane, or under load | Co-locate Vault and the control plane; expected steady state is 5–20 ms intra-region |
| `Register` fails with `INTERNAL: signer backend unavailable` *after* a period of working fine | Vault sealed, TLS cert expired, AppRole token expired (no auto-renewal in v1) | `vault status`; restart the control plane to re-login |
| The CP starts but the public key on the bootstrap passport doesn't match what `vault read transit/keys/yutha-bootstrap` returns | Probably the wrong key name — `--signer-vault-key` is the *name* (e.g. `yutha-bootstrap`), not the full path | Compare exactly; recreate the key if you typo'd the name in §2 |
| SPIRE Workload API socket isn't readable | The control-plane process isn't in the right group / UID / namespace to read SPIRE's socket | `ls -la /tmp/agent.sock`; the SPIRE quickstart explains the agent socket's default permissions |

For backend-specific deeper failure paths, each per-backend runbook
has its own troubleshooting table.

---

## What's deferred

A handful of capabilities are nominated but not yet wired:

- **Live Signer rotation.** The public key is cached at `connect()`
  and held until process restart. To rotate the Vault transit key,
  rotate it in Vault (`vault write -f transit/keys/yutha-bootstrap/rotate`)
  and restart the control plane. RFC 0017 §3.6 sketches the runtime
  rotation protocol.
- **Vault Agent token renewal.** Periodic tokens renew via Vault Agent
  sidecar today; native renewal in `yutha-signer-vault` is a follow-
  on.
- **Multi-key / multi-cluster.** One control plane = one Signer
  instance + one Attestor instance. Operators running multiple swarms
  with per-swarm Vault namespaces today run one control plane per
  swarm.
- **Threshold signing.** Vault transit supports it; the
  `yutha-signer-vault` adapter exposes single-signer transit signing
  only in v1.

Each is a known gap with a tracked follow-on memo, not an oversight.

---

## Where to go from here

- [Signer backends — overview](signers.md) — when to use which
  Signer backend, with links to the Vault / GCP KMS / Azure HSM
  per-backend runbooks.
- [Attestor backends — overview](attestors.md) — when to use which
  Attestor backend, with links to the SPIFFE/SPIRE / OIDC per-backend
  runbooks.
- [Monitoring & receipts](monitoring.md) — which receipts and metrics
  to alert on, including the new `agent.register.deny` evidence
  fields the Attestor adds to the audit trail.
- [Operator credentials](operator-credentials.md) — operator-key
  lifecycle, including the open question of when the operator key
  itself should move to KMS custody.

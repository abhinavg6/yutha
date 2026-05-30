# RFC 0017: External Signer backends — the cross-backend contract

> **Status:** Draft
> **Authors:** Abhinav Garg
> **Filed:** 2026-05-30
> **Targets spec:** `/spec/identity-keys/README.md` (cross-link from §3 Phase C); no wire-format changes
> **Targets phase:** Phase 3+ (enterprise readiness); Phase C of the enterprise-identity workstream
> **Companion RFCs:** [0015 — Signer interface](./0015-signer-interface.md) (which this builds on), [0016 — Attestor interface](./0016-attestor-interface.md) (parallel surface; same workstream)
> **Predecessors:** [RFC 0015](./0015-signer-interface.md) (defines the trait this RFC builds backends against)
> **Substrate dependency:** `yutha-signer`'s `Signer` trait + `SignerError` (no changes to either); per-backend crates live in `/crates/yutha-signer-*` under the same workspace as the H-series anchor crates
> **Out of scope:** AWS KMS (no Ed25519 today — see RFC 0015 §9.1); HSM / PKCS#11 (deferred follow-on); multi-tenant key infrastructure (deferred to the lifecycle-seam workstream); algorithm-agnostic signing (a separate, much larger RFC if ever undertaken)

## 1. Summary

RFC 0015 pinned the `Signer` trait surface and shipped `InProcessSigner` as the zero-dependency default. This RFC pins the *shared pattern* that the three v1 external-backend implementations — HashiCorp Vault transit, GCP KMS, Azure Key Vault Managed HSM — follow, so they share one operator mental model and one conformance-test pattern rather than three independently-evolved shapes.

Concretely pinned in this RFC:

1. **Crate-shape convention.** Each backend ships as its own workspace crate (`yutha-signer-vault`, `yutha-signer-gcp-kms`, `yutha-signer-azure-kv`), feature-gated off an umbrella; nothing in the core depends on any cloud SDK. Matches the `yutha-anchor-sui` shape from RFC 0014.
2. **Async `connect()` construction pattern.** Every external-backend `Signer` is constructed via an async `connect(config) -> Result<Self, SignerError>` that performs exactly one network call — fetch the public key — and caches it. Subsequent `public_key()` calls are sync and infallible per the RFC 0015 §3.1 invariant. Subsequent `sign_message(...)` calls do hit the network.
3. **Configuration surface.** Rust constructor args are the source of truth. A documented env-var convention (`YUTHA_SIGNER_VAULT_*`, `YUTHA_SIGNER_GCP_KMS_*`, etc.) provides a friction-free path for `yutha-control-plane` invocations. A YAML config-registry pattern is documented but not implemented in this RFC; landing it is its own future work.
4. **Authentication is per-backend.** Each backend documents its accepted auth methods in its crate README. Vault offers token / AppRole / Kubernetes / AWS IAM auth; GCP uses Application Default Credentials including Workload Identity; Azure uses `DefaultAzureCredential`. The umbrella RFC does NOT mandate which to use — operators pick per their existing posture.
5. **Error mapping is standardized.** Cloud-API errors map onto the four `SignerError` variants already pinned in RFC 0015 §3.1. The umbrella RFC pins which class of cloud-side condition maps to which variant; each backend's crate has the per-API translation table.
6. **Conformance pattern for non-seed-derivable keys.** The Phase B vectors (`/spec/vectors/signer/sign-and-verify/`) assume seed-derivable keys. External-backend keys are externally provisioned and have no seed. The new pattern is documented in §3.7 — each backend ships an integration test that, given a pre-provisioned key plus a known message, asserts (a) the reported public key matches the key the operator provisioned, (b) the produced signature verifies under that reported public key, and (c) RFC 0015's `SignerError` mapping behaves correctly on adversarial input (key revoked, IAM denied, wrong region).
7. **RFC 0015 open questions §9.2 and §9.4 are pinned here.** Public-key-fetch failures at construction time surface as `SignerError::BackendUnavailable` (transient — retryable by the caller) or `BackendRejected` (permanent — key not found, IAM denied). Concurrent-sign rate limiting is the backend's responsibility; each crate documents its rate-limit posture; the umbrella crate provides an opt-in `yutha-signer::throttle::TokioThrottle` helper for callers who want to enforce a ceiling without per-backend custom code.

The Python SDK does **not** gain external backends in this RFC. The Python `Signer` Protocol stays exactly as-is; if a Python user needs a KMS-backed signer they wrap the Rust impl behind an out-of-process daemon or call gRPC. A dedicated Python-side Phase C-Python is plausible later; this RFC is Rust-side-only.

## 2. Motivation

Phase B left the substrate ready to plug in external signers but shipped only one implementation (`InProcessSigner`). Phase C must produce three new ones; without a shared contract those three will drift in:

1. **Construction shape.** Without a convention, one backend might use a builder pattern, another might use a factory function, a third might use direct struct construction. Operators using more than one backend (or evaluating between them) hit cognitive friction.
2. **Configuration surface.** The three cloud SDKs all have their own client-config conventions (`gcloud auth`, `az login`, Vault tokens). Without standardization, each Yutha-side wrapper might invent its own env-var scheme, YAML shape, or CLI flag convention — every cross-backend doc would need three copies.
3. **Error handling.** Cloud APIs return wildly different error shapes. Without explicit mapping, the same operator-facing failure (key not found, IAM denied, region unreachable) might surface as three different `SignerError` variants depending on which backend is in use.
4. **Conformance testing.** Phase B's vector test is byte-equivalence against a seed-derived key — directly inapplicable to externally-provisioned keys. Each backend would otherwise invent its own test pattern, fragmenting cross-impl conformance.

The umbrella also surfaces decisions RFC 0015 deferred (§9.2 and §9.4) at the point where they actually matter — when backends are being implemented. Pushing those deeper into per-backend RFCs would force the same three decisions to be re-litigated three times.

## 3. Detailed design

### 3.1 Crate shape

Per-backend crates live in `/crates/yutha-signer-{vault,gcp-kms,azure-kv}/`. Each:

- Depends on `yutha-signer` (the trait + `SignerError` + the optional `throttle` helper).
- Depends on `yutha-crypto` only for the `PublicKey` + `Signature` types — never for `SigningKey` (the backend never sees private bytes).
- Depends on its cloud SDK (or HTTP client for Vault) directly. No abstraction layer between Yutha and the SDK.
- Exposes exactly one public type (`VaultSigner`, `GcpKmsSigner`, `AzureKvSigner`) plus its config struct (`VaultSignerConfig`, etc.) and any backend-specific error type that maps into `SignerError`.
- Ships a `README.md` covering: supported auth methods, env-var convention, latency expectations, rate-limit posture, integration-test setup.

The umbrella workspace `Cargo.toml` adds each backend as an optional dependency under a feature flag:

```toml
[features]
default = []
vault = ["yutha-signer-vault"]
gcp-kms = ["yutha-signer-gcp-kms"]
azure-kv = ["yutha-signer-azure-kv"]
all-external-signers = ["vault", "gcp-kms", "azure-kv"]
```

Nothing in `yutha-control-plane`, `yutha-passport`, `yutha-transport`, `yutha-capability`, or `yutha-registry` depends on any backend crate. Operators wire a backend in their `main.rs` (or via a future config-driven path; see §3.3) before constructing `ControlPlaneIdentity`.

### 3.2 Construction pattern — async `connect()`

Every external-backend `Signer` is constructed via:

```rust
let config = {Backend}SignerConfig::from_env()?;     // or from_args(), or struct-literal
let signer = {Backend}Signer::connect(config).await?;
let signer: Arc<dyn Signer> = Arc::new(signer);
```

`connect()` MUST:

1. Establish credentials (token, ADC, DefaultAzureCredential) using the backend's idiomatic SDK path. Credential acquisition failure surfaces as `SignerError::BackendUnavailable` (transient — likely cred refresh) or `SignerError::BackendRejected` (permanent — wrong principal).
2. Issue exactly one backend call to fetch the public key for the configured key reference. Failure surfaces per §3.5.
3. Verify the fetched public key is Ed25519. If not, return `SignerError::UnsupportedAlgorithm` with a backend-specific descriptor (e.g., GCP's `EC_SIGN_P256_SHA256`).
4. Cache the public key on the struct so the trait's sync `public_key()` is infallible after construction.

`connect()` MUST NOT:

- Perform any sign-test or "warm up" calls.
- Discover the key by listing or searching — the operator names exactly one key reference.
- Fall back silently if the configured key is missing or inaccessible.

After `connect()` returns, the signer is `Arc`-cloneable and shareable across many concurrent sign calls per the RFC 0015 §3.1 `Send + Sync` requirement.

### 3.3 Configuration surface

The source of truth is the Rust constructor: `{Backend}SignerConfig` is a plain struct with `Debug` derived (with credential fields redacted) and `serde::Deserialize` derived so it round-trips through any deserializer the operator wants to use.

Each backend's config struct ships with three helper constructors:

- `from_args(...)` — explicit struct-literal-equivalent; for libraries embedding Yutha.
- `from_env() -> Result<Self, ConfigError>` — reads the `YUTHA_SIGNER_{BACKEND}_*` env-var convention (table per backend in §4). The control-plane binary uses this.
- `from_deserializer(D) -> Result<Self, D::Error>` — `serde`-generic; lets a future config-loader hand it a TOML / YAML / JSON value without coupling this RFC to a specific format.

**The `YUTHA_SIGNER_{BACKEND}_*` env-var convention** is the standardized surface operators interact with most often:

```
YUTHA_SIGNER_VAULT_ADDR=https://vault.internal:8200
YUTHA_SIGNER_VAULT_KEY=yutha/control-plane
YUTHA_SIGNER_VAULT_TOKEN=hvs.…       # one of {TOKEN, APPROLE_ROLE_ID+SECRET_ID, K8S_ROLE, AWS_ROLE}

YUTHA_SIGNER_GCP_KMS_KEY=projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/v
# GCP creds come from Application Default Credentials — no explicit env var here.

YUTHA_SIGNER_AZURE_KV_URL=https://my-hsm.managedhsm.azure.net
YUTHA_SIGNER_AZURE_KV_KEY=control-plane-ed25519
# Azure creds come from DefaultAzureCredential — no explicit env var here.
```

A YAML config-registry pattern (one config file naming several signers by label, the control-plane resolves names to signers at startup) is **documented as a future direction in §3.3.1 but not implemented in this RFC**. The friction it adds to the v1 commit is not worth the saved configuration boilerplate when most operators run with a single signer.

#### 3.3.1 Future YAML config registry (sketch — NOT in v1)

```yaml
signers:
  control-plane:
    backend: vault
    addr: https://vault.internal:8200
    key: yutha/control-plane
    auth: { kind: approle, role_id_env: VAULT_ROLE_ID, secret_id_env: VAULT_SECRET_ID }
  operator:
    backend: gcp-kms
    key: projects/p/.../cryptoKeyVersions/v
control_plane_signer: control-plane
operator_signer: operator
```

When implemented: one parser crate (`yutha-signer-config`) that knows the schema; control-plane gains a `--signer-config` flag; integration tests cover the YAML round-trip. Not on this RFC's critical path.

### 3.4 Authentication is per-backend

The umbrella RFC does NOT mandate which auth method any given backend prefers. Operators choose per their existing security posture:

- **Vault**: token (development; static); AppRole (CI / non-cloud); Kubernetes (in-cluster); AWS IAM (instance role on EC2/ECS/EKS).
- **GCP KMS**: Application Default Credentials — gcloud user creds (dev), service-account JSON file (CI), Workload Identity (in-cluster), VM metadata server (GCE/GKE/Cloud Run).
- **Azure Key Vault**: `DefaultAzureCredential` — env-var-based service principal (CI), managed identity (in-VM), Azure CLI creds (dev), Visual Studio creds (Windows).

What the umbrella DOES mandate:

1. Each crate's `README.md` ships a complete auth matrix: which methods are supported, which env vars / files they consume, which Yutha-side config fields they require.
2. Auth-acquisition failure MUST surface as `SignerError::BackendUnavailable` (network / refresh-token-expired conditions, where retrying may help) or `SignerError::BackendRejected` (wrong principal, missing IAM grant — where retrying won't).
3. Credential rotation is the backend's problem. The signer instance MUST remain valid across credential refreshes (Vault token renewal, GCP token refresh, Azure managed-identity rotation) without operator intervention — the underlying SDK or HTTP client handles refresh transparently. Where this isn't possible (e.g., a Vault token expires and the auth method doesn't support renewal), the backend MUST surface a clear `BackendUnavailable` and document the operator runbook for re-construction.

### 3.5 Error mapping

The four `SignerError` variants from RFC 0015 §3.1 are sufficient; this RFC pins which cloud-side condition maps to which variant.

| Condition | `SignerError` | Notes |
|---|---|---|
| Network failure / DNS / connection refused | `BackendUnavailable` | Retryable; caller decides whether to retry vs fail fast. |
| Auth token expired but refresh succeeded → call succeeded | (no error) | SDK / HTTP client refresh transparently. |
| Auth token expired and refresh failed | `BackendUnavailable` | Likely transient (network blip on refresh endpoint). |
| Principal lacks IAM grant on the key | `BackendRejected` | Permanent; surface clear message naming the key + the missing permission. |
| Key not found / disabled / scheduled-deletion | `BackendRejected` | Permanent. |
| Key exists but algorithm ≠ Ed25519 | `UnsupportedAlgorithm` | Surfaced at `connect()` time only — never per sign call. |
| Backend rate-limit / quota exceeded | `BackendUnavailable` | Retryable; the backend's throttle implementation (§3.6) is encouraged. |
| Wire-malformed response | `Internal` | Indicates an SDK bug or a backend regression; should be rare. |
| Anything else | `Internal` | Catch-all per RFC 0015. |

Per-backend crates ship a `*ErrorContext` helper (e.g., `VaultErrorContext::map`) that takes the SDK's error type and produces the right `SignerError` per this table. The intent is that any future contributor adding a fourth backend can crib from any existing one without inventing a fresh translation.

### 3.6 Caching + concurrent-sign posture (RFC 0015 §9.2 + §9.4 pinned)

**Public-key caching** is mandatory per RFC 0015 §3.1. This RFC adds: `connect()` is the *only* place the public key is fetched. If a backend somehow rotates the public key under a stable key reference (Vault `transit/keys/{name}/rotate` does this on demand; GCP's `cryptoKeyVersions/v` pins a specific version so it doesn't; Azure key versions are similarly pinned), the `Signer` instance becomes stale — it'll continue to report the *old* public key but receive signatures against the *new* one. The cure is `Signer` re-construction at the next operator-driven restart. This RFC does NOT add a refresh path; key rotation requires explicit operator action.

**Concurrent-sign rate limiting** is the backend's responsibility (RFC 0015 §9.4). Implementations SHOULD document:

- The backend's per-key rate limit (Vault's depends on the storage backend; GCP KMS is 6000 QPM per key by default; Azure HSM is ~1000 transactions/second per HSM instance).
- Whether the implementation provides internal throttling or expects the caller to handle pushback.

The umbrella `yutha-signer` crate ships an opt-in helper:

```rust
use yutha_signer::throttle::TokioThrottle;
let signer = TokioThrottle::wrap(inner_signer, ThrottleConfig { qps: 100, burst: 200 });
```

This is a wrapper that implements `Signer` and uses a tokio semaphore + leaky bucket. Operators who want a cross-backend throttle without invoking each backend's specific knob use this. Throughput-sensitive deployments may want to skip it and tune the backend directly.

### 3.7 Conformance pattern for non-seed-derivable keys

The Phase B `/spec/vectors/signer/sign-and-verify/` vectors don't apply: the seed isn't knowable for an externally-provisioned key.

The replacement pattern, mandatory for every external-backend impl:

1. **Per-backend integration test under `crates/yutha-signer-{backend}/tests/integration.rs`.** Skipped by default; runs when the backend's env-var convention is satisfied (mirrors the postgres / sui-anchor pattern).
2. **Step 1 — ground-truth provisioning.** The test reads a known key reference from env (e.g., `YUTHA_SIGNER_VAULT_KEY`) and a known *expected* public key hex from env (e.g., `YUTHA_SIGNER_VAULT_EXPECTED_PUBLIC_KEY_HEX`). The operator running the test is responsible for provisioning that key out-of-band (Vault CLI, gcloud CLI, az CLI) and pasting the public key into the env var. This is the equivalent of "the operator provisions the seed for `InProcessSigner`" — but the seed is in the backend, not in the env.
3. **Step 2 — `connect()` round-trip.** Construct the signer. Assert `signer.public_key().value.hex() == expected_public_key_hex`.
4. **Step 3 — sign + verify.** Sign a known message (the test hardcodes `b"yutha-conformance-vector-1"`). Verify the produced signature using stock `yutha_crypto::verify(&signer.public_key(), message, &sig)`. This is the RFC 8032 round-trip.
5. **Step 4 — adversarial cases** (each as a separate `#[test]`):
   - Wrong key reference → `SignerError::BackendRejected`.
   - Revoked / disabled key → `SignerError::BackendRejected`.
   - Network partition simulation → `SignerError::BackendUnavailable` (uses a wrong port or unreachable host).
   - IAM denied (a key the principal can't access) → `SignerError::BackendRejected`.

Each crate's `README.md` documents the env-var matrix and the recommended provisioning script (`scripts/provision-vault-key.sh`, etc.). Operators running the integration suite for the first time follow the script; subsequent runs reuse the same key.

**What this gives up vs Phase B's pattern**: byte-equivalence. We can't assert the backend produces *the same* signature any future re-impl would produce (Ed25519 is deterministic but the test can't know the key bytes). What we keep: every backend produces *some* signature that verifies under the reported public key, and surfaces failures via the standardized `SignerError` mapping. That's the operationally-load-bearing property.

## 4. Per-backend specifics

Concise pins; per-crate READMEs are the deep dive.

### 4.1 HashiCorp Vault transit (`yutha-signer-vault`)

- **SDK choice.** No first-party Rust SDK for Vault exists. We use the `vaultrs` crate (community-maintained, MIT, ~100k downloads/month at filing) for the HTTP shape. Direct `reqwest`-based fallback is documented in the README for paranoid operators.
- **Key path convention.** `transit/sign/{key_name}` and `transit/keys/{key_name}` — Yutha names the *key*, not the full path; the prefix is fixed.
- **Auth.** All four Vault auth methods supported per §3.4. AppRole is the recommended path for cloud-VM deployments without a workload-identity story (this is the "AWS-friendly" path RFC 0015 §9.1 nominated).
- **Multi-tenancy hook.** Vault transit keys are naturally per-path; a future multi-tenant story can use `transit-tenant-{id}/sign/{key_name}`. This RFC doesn't implement it but the trait shape doesn't preclude it.
- **Latency.** ~5–20 ms per sign call against a local Vault, ~50–150 ms against a regional Vault cluster.

### 4.2 GCP KMS (`yutha-signer-gcp-kms`)

- **SDK choice.** The `google-cloud-kms-v1` crate from Google's official `googleapis/google-cloud-rust` SDK (pin to `^1` in `Cargo.toml`; first stable 1.x line GA as of 2026-05). Built-in ADC + Workload Identity via the shared `google-cloud-gax` runtime; rustls/aws-lc-rs TLS matches our existing `sqlx` and `sui-rpc` stack. The earlier community `google-cloud-kms` crate (from yoshidan/google-cloud-rust) is the documented fallback for operators who need to vendor without Google's runtime crates — the umbrella RFC originally pinned that crate, but the official SDK reached 1.x stability before Phase C-C started, so we use it as the v1 default.
- **Key reference format.** Full resource path including the version: `projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}/cryptoKeyVersions/{v}`. The version is required — pinning to `cryptoKeyVersions/v1` (or any explicit version) means rotation is operator-controlled.
- **Algorithm.** Key must be created with `purpose=ASYMMETRIC_SIGN` and `algorithm=EC_SIGN_ED25519`. The integration test asserts the algorithm at `connect()` time and surfaces `SignerError::UnsupportedAlgorithm` if mismatched.
- **Auth.** Application Default Credentials. The `gcloud auth application-default login` flow covers local dev; Workload Identity covers GKE / Cloud Run.
- **Latency.** ~30–80 ms per sign in-region; cross-region adds the usual GCP RTT.

### 4.3 Azure Key Vault Managed HSM (`yutha-signer-azure-kv`)

- **SDK choice.** The `azure_security_keyvault_keys` crate from the official Microsoft `azure-sdk-for-rust` (currently in active development; pin a specific minor version in `Cargo.toml`).
- **Tier requirement.** **Managed HSM** specifically — the standard Key Vault tier does not support Ed25519. Documented prominently in the README; `connect()` surfaces `SignerError::UnsupportedAlgorithm` if the key turns out to be on the wrong tier.
- **Key reference.** Vault URL (`https://my-hsm.managedhsm.azure.net`) + key name. The HSM uses key versioning; the Yutha config can pin a specific version or use `latest` (with the same staleness caveat as §3.6).
- **Auth.** `DefaultAzureCredential` — covers the full Azure auth ladder (managed identity, env-var SP, CLI creds).
- **Latency.** ~50–150 ms per sign — Managed HSM signing is slower than software KMS by design (the HSM does the math).

## 5. Drawbacks

- **Three integrations instead of one cross-backend abstraction layer.** We could try to write a single "cloud KMS Rust wrapper" that all three plug into. We don't — the SDKs differ enough that the wrapper would be more code than the integrations it abstracts. Each crate is straightforward; the duplication is bounded.
- **No first-party Vault SDK in Rust.** Using a community crate (`vaultrs`) introduces a small supply-chain risk. We mitigate by pinning a specific version, reviewing the crate's release notes on bump, and providing a documented `reqwest`-direct fallback for operators who want to vendor.
- **The env-var convention is opinionated.** Operators with existing tooling that uses different env-var names will need a small wrapper script or have to invoke the Rust constructor directly. The convention is documented; deviating from it is supported.
- **Integration tests need real backend access.** Phase B's vector tests are fully self-contained; the §3.7 pattern requires a running Vault / a GCP project / an Azure HSM. We mitigate by making the tests skip cleanly when env vars are absent (postgres-test pattern), and by shipping `scripts/provision-*-key.sh` so first-time setup is one command.
- **AWS-on-Vault is the documented enterprise-on-AWS path.** Operators expecting "AWS KMS Just Works" will be surprised; we mitigate by documenting the rationale (RFC 0015 §9.1) prominently in both the umbrella RFC and in `docs/operator/`.

## 6. Alternatives considered

### 6.1 Three independent RFCs (one per backend)

Reject. The three backends share more than they differ — the construction pattern, the auth-method-is-per-backend convention, the error mapping table, the conformance-test pattern. Pulling those out into three RFCs would either duplicate the content (and risk drift) or under-specify some of the three. Single umbrella RFC + per-crate README is the right granularity.

### 6.2 No RFC — implementation memos in each crate

Reject. Phase B explicitly used the RFC-first pattern (RFC 0015 → impl). Skipping that for Phase C would create an inconsistency in the workstream and lose the "cross-backend decisions are explicit" benefit. The umbrella RFC is small (~12-15 pages on the page count of RFC 0009 — well under what Phase B's RFC was) precisely because the per-backend specifics are deferred to the crate-level docs.

### 6.3 Implement first, RFC after

Reject. The user choice in the C-A kickoff explicitly picked "RFC umbrella, then per-backend impls" — and the precedent from RFCs 0010–0013 (constitution + enforcement) is that paper-first work catches design issues before implementation drift. The recon-first path would risk three backends diverging before the umbrella locked them down.

### 6.4 Algorithm-agnostic Signer trait (revisit RFC 0015's Ed25519 pin)

Reject for v1. Out of scope per RFC 0015 §9.1. A separate, much larger RFC could pursue this in the future if AWS KMS support becomes a forcing function. Not on this workstream's critical path.

## 7. Threat-model impact

Same as RFC 0015 §6 — external Signer implementations are the mechanism RFC 0015 promised when arguing the trait surface improves the threat model. Each backend implementation:

- **Strengthens A7 (supply-chain attacker)** further than `InProcessSigner` does: a compromised dependency can no longer steal seed bytes because there are no seed bytes in the process.
- **Strengthens A8 (malicious operator)** to the extent the operator does not retain IAM-on-the-KMS. An operator who is also the cloud-platform admin retains full access; that's a known limitation of cloud-KMS-based custody and is documented per backend.

No new attack surface is introduced by the umbrella RFC itself — the surface is the per-backend crates, and each is feature-gated off by default. Workstream L review is required per-crate, not per-RFC.

## 8. Conformance impact

A new test-discipline pattern at `/spec/vectors/signer/` — a `README.md` addendum documenting the §3.7 conformance pattern, with a pointer from each per-backend crate's `tests/integration.rs`. No JSON fixtures (the inputs aren't seed-derivable). The Phase B `sign-and-verify/` vectors remain authoritative for `InProcessSigner` and any future seed-derivable signer.

## 9. Migration

None. This RFC is purely additive. Existing `InProcessSigner` code paths and the Phase B refactor are unchanged. Operators opt into a backend by adding the relevant feature flag and wiring `connect()` in their `main.rs`.

## 10. Open questions

### 10.1 Should there be a per-signer "audit" hook?

Some operators may want a hook fired on every `sign_message` call (for SIEM forwarding, for billing per-sign, for anomaly detection). Today: nothing. We could add a `Signer::on_sign(impl Fn(&Signature))` hook, or a separate `AuditedSigner<S>` wrapper.

Working assumption: skip for v1. The backend's own audit (CloudTrail / Cloud Audit Logs / Vault audit device) is the source of truth. A Yutha-side hook duplicates that for marginal benefit. Revisit if an enterprise asks.

### 10.2 Per-backend benchmark numbers

The latency ranges in §4 are estimates from public docs. Phase C-B/C/D should each include a `cargo bench` micro-benchmark over `sign_message` to lock real numbers in each crate's README.

Working assumption: bench in each backend's PR, not in this RFC.

### 10.3 Should the `throttle` helper move to its own crate?

`yutha-signer::throttle::TokioThrottle` pulls in `tokio` (already a transitive dep) and a small leaky-bucket impl. Could grow into a `yutha-signer-throttle` crate if the surface expands; for v1 it lives in the umbrella.

Working assumption: in-umbrella for v1; split later if/when a third throttle strategy emerges.

## 11. Adoption checklist

- [x] This RFC reviewed and lands *(2026-05-30, Phase C-A)*
- [x] `/spec/identity-keys/README.md` updated to link this RFC from §3 Phase C *(C-A4)*
- [x] RFC 0015 §9.1 amended with a pointer to this RFC *(C-A4)*
- [x] `/spec/vectors/signer/README.md` gains a "Per-backend integration tests" section linking §3.7 *(C-A4)*
- [x] Phase C-B: `yutha-signer-vault` crate scaffolded, `connect()` + sign + integration test land *(2026-05-30; Token + AppRole auth, k8s/AWS reserved variants, docker-vault integration test verified)*
- [x] Phase C-C: `yutha-signer-gcp-kms` crate scaffolded, `connect()` + sign + integration test land *(2026-05-30; `google-cloud-kms-v1 ^1` — official Google Rust SDK, swapped from yoshidan crate originally pinned in §4.2; ADC + Workload Identity)*
- [x] Phase C-D: `yutha-signer-azure-kv` crate scaffolded, `connect()` + sign + integration test land *(2026-05-30; `azure_security_keyvault_keys 0.14` + `azure_identity 0.35` + `azure_core 0.35`; `DeveloperToolsCredential` default with `connect_with_credential` escape hatch for production; `UnknownValue` strings used until SDK regenerates Ed25519/OKP enum variants)*
- [x] `docs/operator/` gains one walkthrough per backend (`vault-signer.md`, `gcp-kms-signer.md`, `azure-kv-signer.md`) *(operator-friendly filenames; mkdocs nav + llms.txt wired)*
- [ ] `yutha-signer::throttle::TokioThrottle` lands with unit tests *(deferred — no operator demand surfaced in v1; ship when first backend needs rate-limit headroom)*
- [ ] Workstream L (security review) sign-off on each backend before merge *(per-backend, gating commits)*

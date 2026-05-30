# RFC 0015: Signer interface — pluggable key custody

> **Status:** Draft
> **Authors:** Abhinav Garg
> **Filed:** 2026-05-27
> **Targets spec:** `/spec/identity-keys/` (new directory),
>                   `/spec/passport/passport-v1.proto` (no wire change; `.sign()` method signature changes in the impl),
>                   `/spec/envelope/envelope-v1.proto` (same),
>                   `/spec/capability/capability-v1.proto` (same)
> **Targets phase:** Phase 3+ (enterprise readiness)
> **Companion RFC:** [0016 — Attestor interface](./0016-attestor-interface.md)
> **Predecessors:** [RFC 0002](./0002-passport-v1.md), [RFC 0003](./0003-envelope-v1.md), [RFC 0005](./0005-capability-v1.md), [RFC 0009](./0009-operator-credentials.md)
> **Substrate dependency:** `yutha-crypto`'s `Ed25519` types; no new wire-format changes
> **Out of scope:** Specific KMS implementations (Phase C, separate work); HSM / PKCS#11 / Vault transit (deferred follow-ons); signature algorithms other than Ed25519 (not a v1 goal — see §9.1)

## 1. Summary

Introduces a `Signer` trait that mediates *every* call site where Yutha today calls `SigningKey::sign_message` directly. The trait surface is one method (`sign_message`) plus one accessor (`public_key`); implementations may hold the private key in process memory (the `InProcessSigner` default, what hobby swarms run today), or hold only a handle to an external custody backend like AWS KMS, GCP KMS, Azure Key Vault, or HashiCorp Vault.

Concretely pinned in this RFC:

1. **An async trait** `Signer` in a new `yutha-signer` crate. `sign_message(&self, &[u8]) -> Result<Signature, SignerError>` is async because cloud-KMS implementations are network-bound; `public_key(&self) -> PublicKey` is sync because implementations cache the public key at construction.
2. **A breaking signature change** on `Passport::sign`, `Envelope::sign`, `Capability::sign`, the bearer-token mint path, and the control-plane's own self-signed receipts: all five become async and accept `&dyn Signer` instead of `&SigningKey`. There is no backcompat path — the repo is pre-public, the cost of compatibility shims outweighs the savings (see §8).
3. **`InProcessSigner` as the zero-dependency default.** Wraps the existing `SigningKey` byte-for-byte. No external crate, no async runtime overhead beyond what the rest of the SDK already requires. The hobby path is unchanged in behavior, only in call-shape.
4. **No raw-key export across the trait.** `Signer` exposes `public_key()` and `sign_message()` and nothing else. The KMS-backed implementations *cannot* expose private bytes because they don't have them; the in-process implementation *will not* expose private bytes because the trait shape forbids it.
5. **Algorithm pinned to Ed25519.** The signature returned by `sign_message` MUST verify under `public_key()` per [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032). Implementations wrapping KMS keys MUST wrap Ed25519 keys; this constrains which KMS providers are usable in v1 (see §9.1).
6. **Async-all-the-way.** The decision to make sign call sites async cascades into every demo, every test, and every example. This is the largest call-site change of the workstream; it lands as a single PR-stack at Phase B.

The Python SDK mirrors the shape: a `Signer` Protocol with the same two methods, an `InProcessSigner` default, and identical async semantics.

## 2. Motivation

A security review of any production agent deployment will ask the same two questions before any other: "where do the signing keys live, and who has access to them?" Today Yutha's answer is "in the agent's process memory; whoever owns the process owns the keys." That answer doesn't pass.

Five concrete things the current shape makes structurally impossible:

1. **HSM-backed agent keys.** A regulated deployment (financial, healthcare, government) may be legally required to keep all signing keys in a FIPS-certified HSM. Yutha today reads raw bytes from disk or env into `SigningKey::from_seed_bytes` — that is the disqualifying pattern.
2. **Cloud-KMS-managed rotation.** AWS KMS, GCP KMS, and Azure Key Vault all support automatic key rotation managed centrally by the cloud team. With private keys living in agent process memory, rotation requires every agent process to be told about the new key — there's no place to plug rotation in.
3. **Centralized audit of key use.** AWS CloudTrail, GCP Audit Logs, and Azure Diagnostic Logs record every signing operation against a managed key. With keys in process, signing operations are visible only to the host's local logging.
4. **Separation of duties.** A platform team can grant an agent the ability to *use* a signing key without ever letting it *see* the key. With in-process keys, "can use" and "can read" are the same permission.
5. **Post-compromise recovery.** When a host is compromised, an in-process key must be considered burned and the corresponding passport revoked. A KMS-held key can be unbound from the compromised agent's IAM role atomically — the key is uncompromised; only the access path is.

The `Signer` trait is the smallest change that turns those five from "impossible" into "configurable." It does not make Yutha enterprise-only; the native default stays exactly as fast and as dependency-free as today.

## 3. Detailed design

### 3.1 The `Signer` trait (Rust)

New crate `yutha-signer` in the core workspace. Trait definition:

```rust
use async_trait::async_trait;
use std::fmt::Debug;
use thiserror::Error;
use yutha_crypto::{PublicKey, Signature};

/// A handle to an Ed25519 signing capability.
///
/// Implementations:
///   - hold a reference to a key (in-process bytes, KMS key ARN, Vault path, etc.);
///   - cache the corresponding public key at construction so `public_key()` is
///     sync and infallible after that point;
///   - perform the actual signing operation when `sign_message` is called.
///
/// Implementations MUST NOT expose the raw private key bytes via any method,
/// trait, or downcast. The `Signer` trait is intentionally the only path.
#[async_trait]
pub trait Signer: Send + Sync + Debug {
    /// Return the Ed25519 public key this signer signs for.
    ///
    /// Implementations MUST cache this value at construction. This method MUST
    /// NOT make network calls or block.
    fn public_key(&self) -> PublicKey;

    /// Sign the given canonical bytes.
    ///
    /// Implementations MUST return a signature that verifies under
    /// `self.public_key()` per RFC 8032. Implementations MAY:
    ///   - cache nothing (every call hits the backend);
    ///   - retry transient backend failures internally;
    ///   - emit telemetry / audit-log entries to their backend;
    ///   - rate-limit calls to protect the backend.
    ///
    /// Implementations MUST NOT:
    ///   - return a signature produced by a different key than `public_key()`
    ///     reports;
    ///   - mutate the input bytes;
    ///   - return until the signing operation has either succeeded or failed
    ///     (no fire-and-forget).
    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError>;
}

/// Errors a `Signer` implementation may return.
#[derive(Debug, Error)]
pub enum SignerError {
    /// The backend was reachable but rejected the signing request (auth, key
    /// disabled, key not found, quota exceeded, …). Retrying without
    /// intervention will not help.
    #[error("signer backend rejected: {0}")]
    BackendRejected(String),

    /// The backend was unreachable or returned a transient error. Retrying
    /// MAY help. Implementations SHOULD retry transient errors internally
    /// before surfacing this.
    #[error("signer backend unavailable: {0}")]
    BackendUnavailable(String),

    /// The wrapped key uses an algorithm Yutha does not support. Surfaced at
    /// construction time, not per-call. Included in the error enum so
    /// construction errors and call errors share a type.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Anything else.
    #[error("internal signer error: {0}")]
    Internal(String),
}
```

### 3.2 The `InProcessSigner` default

Ships in `yutha-signer` itself. Wraps `yutha_crypto::SigningKey` byte-for-byte.

```rust
#[derive(Debug, Clone)]
pub struct InProcessSigner {
    signing_key: yutha_crypto::SigningKey,
    public_key: PublicKey,  // cached at construction
}

impl InProcessSigner {
    /// Construct from a 32-byte Ed25519 seed.
    pub fn from_seed_bytes(seed: &[u8; 32]) -> Self {
        let signing_key = yutha_crypto::SigningKey::from_seed_bytes(seed);
        let public_key = signing_key.public_key();
        Self { signing_key, public_key }
    }

    /// Construct by generating a fresh keypair from OS RNG. Test / demo use.
    pub fn generate() -> Self {
        let signing_key = yutha_crypto::SigningKey::generate();
        let public_key = signing_key.public_key();
        Self { signing_key, public_key }
    }
}

#[async_trait]
impl Signer for InProcessSigner {
    fn public_key(&self) -> PublicKey {
        self.public_key
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        // ed25519-dalek's sign is sync and CPU-bound. We don't spawn_blocking
        // because Ed25519 over a small canonical-bytes input is fast enough
        // that the spawn overhead would dominate. Benchmarked at < 100 µs
        // per call on commodity hardware; well below the rest of the gRPC
        // critical path.
        Ok(self.signing_key.sign_message(message))
    }
}
```

The `async` qualifier on `sign_message` does *not* impose a runtime overhead for `InProcessSigner` — the function body is synchronous code wrapped in an `async fn`. Callers' `.await` returns immediately. The async surface exists for cloud-KMS implementations, which need it.

### 3.3 Call-site refactor — five places

The breaking change touches five Rust call sites, mirrored in Python:

| # | Today (Rust) | After RFC 0015 |
|---|---|---|
| 1 | `Passport::sign(&SigningKey) -> Result<Passport, _>` | `Passport::sign(&dyn Signer) -> Result<Passport, _>` (async) |
| 2 | `Envelope::sign(&SigningKey) -> Envelope` | `Envelope::sign(&dyn Signer) -> Result<Envelope, _>` (async) |
| 3 | `Capability::sign(&SigningKey) -> Result<Capability, _>` | `Capability::sign(&dyn Signer) -> Result<Capability, _>` (async) |
| 4 | `BearerSession::_mint_token(&SigningKey, ...)` (Python) | `BearerSession::_mint_token(&Signer, ...)` (already async; trait change only) |
| 5 | `ControlPlaneState::sign_receipt(&SigningKey, ...)` (Rust) | `ControlPlaneState::sign_receipt(&dyn Signer, ...)` (async) |

Each call site flows through every caller; tests, demos, examples, and walkthroughs in the docs all update. The change is mechanical but wide. Phase B's PR-stack lands this in one go to avoid an unshippable half-state.

Call shape, before:

```rust
let passport = Passport::builder()
    .agent_id(agent_id)
    .agent_public_key(signing_key.public_key())
    // ...
    .sign(&signing_key)?;
```

Call shape, after:

```rust
let signer: Arc<dyn Signer> = Arc::new(InProcessSigner::from_seed_bytes(&seed));
let passport = Passport::builder()
    .agent_id(agent_id)
    .agent_public_key(signer.public_key())
    // ...
    .sign(&*signer).await?;
```

The `agent_public_key` is now sourced from `signer.public_key()` rather than `signing_key.public_key()` — the agent code never holds a `SigningKey`. That's the load-bearing semantic change.

### 3.4 Cloud KMS implementations (sketches; full design is Phase C)

The trait surface is algorithm-agnostic in shape but algorithm-specific in conformance — every signature must verify under an Ed25519 public key. This constrains which KMS providers can host Yutha keys in v1:

| Provider | Ed25519 sign/verify support | v1 viable |
|---|---|---|
| GCP Cloud KMS | Yes (key version `EC_SIGN_ED25519`) | Yes |
| Azure Key Vault Managed HSM | Yes (EdDSA, Premium tier required) | Yes (HSM tier only) |
| HashiCorp Vault transit | Yes | **Yes** — the AWS-friendly path; ships in Phase C |
| AWS KMS | No (ECC NIST P-256/384/521 only) | **No** in v1 — AWS users use Vault transit on AWS; see §9.1 |
| PKCS#11 / FIPS HSMs | Vendor-dependent; many support Ed25519 | Deferred follow-on |

For each viable provider, a separate crate ships in Phase C:

- `yutha-signer-gcp-kms` — wraps `google-cloud-kms` Rust SDK. Constructor `GcpKmsSigner::connect(client, resource_name)` makes one async call to `getPublicKey`, caches the result, returns the signer.
- `yutha-signer-azure-kv` — wraps `azure_security_keyvault` Rust SDK. Same shape; Premium tier (Managed HSM) only.
- `yutha-signer-vault-transit` — wraps a Vault HTTP client against the [Vault transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit). The recommended path for enterprises on AWS (since AWS KMS doesn't yet ship Ed25519) — Vault runs anywhere, including on AWS infrastructure, and its transit engine supports Ed25519 sign/verify natively. Constructor `VaultTransitSigner::connect(vault_addr, key_name, token)` fetches the public key once at startup, caches it, returns the signer.
- `yutha-signer-aws-kms` — *deferred until either AWS KMS adds Ed25519 support, or this RFC is amended to allow algorithm-agnostic signing.* (See §9.1.)

Each crate is feature-gated; nothing in the core depends on cloud SDKs or on Vault.

### 3.5 Python SDK surface

`yutha.crypto.Signer` is a `Protocol` (PEP 544 structural type):

```python
from typing import Protocol
from yutha.identity import PublicKey, Signature

class Signer(Protocol):
    def public_key(self) -> PublicKey: ...
    async def sign_message(self, message: bytes) -> Signature: ...
```

`yutha.crypto.InProcessSigner` is the default impl:

```python
class InProcessSigner:
    def __init__(self, signing_key: SigningKey) -> None:
        self._signing_key = signing_key
        self._public_key = signing_key.public_key()

    @classmethod
    def from_seed_bytes(cls, seed: bytes) -> "InProcessSigner":
        return cls(SigningKey.from_seed_bytes(seed))

    @classmethod
    def generate(cls) -> "InProcessSigner":
        return cls(SigningKey.generate())

    def public_key(self) -> PublicKey:
        return self._public_key

    async def sign_message(self, message: bytes) -> Signature:
        return self._signing_key.sign_message(message)
```

`Passport.sign`, `Envelope.sign`, `Capability.sign` become async methods accepting any object that satisfies the `Signer` protocol. The existing `SigningKey` class loses its public `sign_message` / `.sign(...)` integration with the artifact types — it stays as a key-material container but is no longer the path callers use to sign things. Internally it's the body of `InProcessSigner.sign_message`.

### 3.6 Construction and lifecycle

Construction of a `Signer` may be async or sync depending on the implementation:

- `InProcessSigner::from_seed_bytes(&seed)` — sync, no I/O.
- `InProcessSigner::generate()` — sync, OS RNG only.
- `GcpKmsSigner::connect(client, resource).await` — one async call to fetch the public key, then cached.
- `AzureKvSigner::connect(vault_url, key_name).await` — same pattern.

After construction, the `Signer` is shared via `Arc<dyn Signer>` (Rust) or just a regular shared reference (Python). The signer's lifetime spans the agent's lifetime; constructing once per RPC is wasteful.

Agents construct their signer once at startup, before connecting. The `YuthaClient` and `YuthaAgent` constructors (both Rust and Python) accept a `&dyn Signer` instead of a `SigningKey`. The agent's bearer-token mint path reads its signer from the client; envelope sends thread it through; passport-mint helpers take it explicitly.

### 3.7 Conformance contract

The conformance suite (`/spec/vectors/`) gets new vectors under `signer/`:

- **`signer/inprocess-equivalence/`** — 16 fixed-seed signing operations. Asserts that `InProcessSigner::from_seed_bytes(seed).sign_message(message).await` produces byte-identical output to `SigningKey::from_seed_bytes(seed).sign_message(message)`. This is the "the trait doesn't change the math" gate.
- **`signer/verify-under-public-key/`** — 16 operations where the test only knows the wrapped signer's `public_key()` and the message. Asserts the produced signature verifies under that public key. This is the "any conformant impl produces verifiable signatures" gate; KMS implementations pass this without exposing private bytes.
- **`signer/concurrent-sign-safety/`** — 64 concurrent `sign_message` calls on a single signer instance from multiple tasks. Asserts no signature is duplicated or corrupted. Tests the `Send + Sync` bound is honored.

For non-`InProcessSigner` implementations, only the latter two gates apply — there is no byte-equivalence assertion possible (we don't know the KMS's private key). This is the right trade-off; the verifiability gate is what matters operationally.

### 3.8 Bearer-token-mint specifics

The Python `BearerSession` in `sdks/python/src/yutha/auth.py` mints fresh `AgentBearerToken` artifacts on each RPC (with caching until expiry minus a refresh lead). Today it holds a `SigningKey`. After this RFC:

- `BearerSession(agent_id, swarm_id, signer: Signer, ...)` — accepts the signer directly.
- `_mint_token` becomes `async def _mint_token(self) -> bytes` and `await self._signer.sign_message(canonical_bytes)` instead of `self._signing_key.sign_message(canonical_bytes)`.
- The token cache stays — fetching a token on every gRPC call is a performance regression even for `InProcessSigner`, and is a real cost for KMS-backed signers (1+ network round trip per sign).

The cache is per-session, indexed by `(agent_id, swarm_id)`. The cache strategy does not change; only the signing path inside the cache-miss branch does.

## 4. Drawbacks

- **Async-all-the-way blast radius.** Every test fixture that mints a passport, every demo that signs an envelope, every walkthrough that constructs a capability — all of it touches `.await`. Phase B's PR-stack will be large and mechanical. Realistic estimate: 1–2 weeks of refactor + test-suite chasing for a solo developer working full-time on this.
- **Async cost on the in-process path.** Wrapping a 100-µs sync operation in `async fn` and awaiting it adds a small amount of overhead (the future construction + the immediate `Poll::Ready` return). For high-throughput envelope signing this is measurable in microbenchmarks. We accept this trade — the alternative (sync trait + runtime-bridge for cloud impls) is uglier and more error-prone.
- **No raw-key access for legacy code paths.** Any future use case that legitimately needs the raw `SigningKey` (e.g., importing a key into a different cryptosystem) has to dance around the `Signer` trait, since the trait doesn't expose it. We bet this is rare enough to not matter; if it isn't, we add a downcast escape hatch later (and document why).
- **AWS KMS not viable in v1.** This is the single largest adoption gap. AWS is the most common enterprise cloud; an enterprise running on AWS today cannot use KMS-backed Yutha keys until either AWS adds Ed25519 (out of our control) or we change the signature algorithm (a much larger RFC). See §9.1.
- **Signer construction failure modes are new.** `InProcessSigner::from_seed_bytes` can't fail today; cloud-KMS `connect()` can fail in a hundred ways (network, IAM, key not found, key disabled, wrong region…). The agent's startup path gains a new class of error to handle gracefully. Existing fixtures that assume "signer construction is infallible" need updating.
- **Trait-object overhead.** `&dyn Signer` calls go through a vtable rather than monomorphizing. For sign-heavy paths (e.g., envelope.send under high throughput) this is a small but real perf cost vs the current direct call. Not a deal-breaker; mention for completeness.

## 5. Alternatives considered

### 5.1 Sync trait with runtime bridge

Keep `Signer::sign_message` sync; have cloud-KMS impls block on a tokio handle internally. This was the working assumption in the earlier scoping pass.

Rejected because:

- The sync wrapper has to either reach for a tokio handle (forcing every caller to be inside a tokio runtime, which test code and CLI tools often aren't) or spawn its own runtime (heavy, and prone to "blocking-the-only-runtime-thread" bugs).
- The pattern leaks: any caller that wants to retry transient errors with backoff needs to do that around a sync call, which is a fiddly do-while loop, vs. a clean async retry using `tokio::time::sleep`.
- Cloud-KMS calls *are* network I/O. Forcing the rest of the codebase to pretend they aren't is the wrong direction; the rest of the codebase is async-first anyway (gRPC client, dispatcher loops, receipt store).

The async-all-the-way refactor is bigger, but the result is structurally cleaner.

### 5.2 Sync trait + separate `AsyncSigner` trait

Two traits: `Signer` (sync) for the in-process case, `AsyncSigner` (async) for KMS. Callers parameterize on whichever they need.

Rejected: it splits the call sites in half. `Passport::sign` now needs two versions, one for each trait. The cognitive burden on integrators picking which signer fits which call site is significant. One unified trait is simpler.

### 5.3 Leave `SigningKey` as-is; add KMS keys as a separate orthogonal feature

Continue using `SigningKey` everywhere; add a `KmsBackedSigningKey` type that *looks like* a `SigningKey` but proxies sign calls. This is a less-invasive change but breaks the security model:

- It would force `KmsBackedSigningKey` to implement methods that return raw bytes (`to_bytes`, etc.), which it can't.
- The polymorphism is at the type level, not behind a trait, so call sites have to pick one. No way to switch implementations without recompile.

Rejected.

### 5.4 Do nothing

Keep `SigningKey` as the only signing surface; ship a docs page that says "users who need KMS should fork."

Rejected. Forking is not a viable path for enterprise adoption. The point of this work is to make Yutha adoptable in places it currently isn't.

## 6. Threat-model impact

This RFC strengthens defenses against [A7 (supply-chain attacker)](../../threat-model.md#a7-supply-chain-attacker) and [A8 (malicious operator)](../../threat-model.md#a8-malicious-operator), and slightly improves [A1 (hostile agent participant)](../../threat-model.md#a1-hostile-agent-participant).

- **A7 — supply chain.** Today, any code path that gets `SigningKey::from_seed_bytes(&seed)` can sign anything the agent could sign. A malicious dependency (LangChain, CrewAI, OpenAI Agents, …) that exfiltrates the bytes wins. With `Signer`, the dependency would need to either steal the seed bytes *before* `InProcessSigner` consumes them, or coopt the running `Signer` to sign attacker-chosen bytes. The latter is harder to do silently (signing operations against a KMS leave audit-log entries).
- **A8 — malicious operator.** A cloud-KMS-backed signer raises the bar: the operator can no longer simply read agent keys from disk and forge envelopes after the fact. They'd need to retain IAM access to the KMS key. (Note: an operator who *currently* has IAM still wins; this isn't a defense against an operator-as-attacker, but it raises the cost from "scrape a file" to "leave audit entries.")
- **A1 — hostile agent.** No first-order change. The hostile agent's own signing key was always its own; what changes is that *other* agents whose hosts the hostile agent might compromise can now keep their keys in KMS.

No new attack surface is introduced. The trait surface itself is small (two methods); KMS implementations live behind feature flags and are not part of the core. Workstream L review required on Phase B before merge.

## 7. Conformance impact

Three new vector directories under `/spec/vectors/signer/` — see §3.7 above. The existing receipt / passport / envelope / capability vectors do not change (canonical bytes are unaffected; only the call shape that produces signatures changes).

The Phase B implementation must produce identical signatures for fixed-seed `InProcessSigner` runs against the new `signer/inprocess-equivalence/` vectors. Backends that pass the current suite continue to pass after the refactor — the wire output is the same.

The Python interop test gains a `Signer` round-trip case: Python `InProcessSigner.sign_message(canonical_bytes)` must produce the same signature as Rust `InProcessSigner::sign_message(canonical_bytes).await` for identical seeds and messages. This is already implicit (same Ed25519 library family), but worth pinning explicitly.

## 8. Migration

There is no migration. The repo is pre-public; there are no production users to preserve compatibility for. Per the [no-backcompat-pre-Phase-2-public guidance](../../AGENTS.md), we land the breaking change in place. Demos, tests, examples, and walkthroughs all update once as part of Phase B.

Specifically:

- `Passport::sign(&SigningKey)` → `Passport::sign(&dyn Signer).await` — every call site updates.
- `Envelope::sign(&SigningKey)` → `Envelope::sign(&dyn Signer).await` — every call site updates.
- `Capability::sign(&SigningKey)` → `Capability::sign(&dyn Signer).await` — every call site updates.
- `BearerSession(signing_key, ...)` → `BearerSession(signer, ...)` — every call site updates.
- Control-plane signing path in receipt emission becomes async.
- All demos, all walkthroughs, all integration tests, all the example pages in `/docs/examples/` update.

mkdocs `--strict` must remain clean throughout; ruff + mypy + cargo + cargo clippy all clean at end of Phase B.

## 9. Open questions

### 9.1 AWS KMS Ed25519 support — DECIDED

AWS KMS today does not support Ed25519 signing, which would otherwise forecloses the most common enterprise cloud as a key custodian in v1. **Decided 2026-05-27:** ship `yutha-signer-vault-transit` as the AWS-friendly path in Phase C. HashiCorp Vault transit supports Ed25519 natively, runs on AWS infrastructure (EC2, ECS, EKS — wherever the enterprise's existing Vault deployment lives), and integrates cleanly with AWS IAM via the [AWS auth backend](https://developer.hashicorp.com/vault/docs/auth/aws) for agent authentication.

This puts three Phase-C deliverables in v1: GCP KMS, Azure Key Vault (Managed HSM tier), and Vault transit. AWS-native KMS support remains a longer-term possibility down two paths, neither blocking this RFC:

- **Wait for AWS.** AWS has been adding key algorithms over time; Ed25519 may land at some point. When it does, `yutha-signer-aws-kms` becomes a small, mechanical follow-on crate.
- **Algorithm-agnostic sibling track.** A larger future RFC could allow Yutha to negotiate between Ed25519 and ECDSA P-256 (which AWS KMS does support today). Touches every spec that pins Ed25519; out of scope for this RFC; would need its own.

For v1 Phase C, AWS-on-Vault is the documented path.

### 9.2 Public-key fetching errors at construction

`GcpKmsSigner::connect()` fetches the public key once. If that fetch fails, construction fails — but the agent has already been told (by config / env / CLI) which KMS key to use. What's the right error to surface?

Working assumption: surface as `SignerError::BackendUnavailable` and let the calling code retry construction or fail fast. Worth confirming the shape during Phase B.

### 9.3 Should `Signer` also encrypt?

`yutha-crypto` includes ChaCha20-Poly1305 for memory-entity encryption. Some KMS providers can also do envelope encryption. Should `Signer` extend to a more general `KeyHandle` that does both?

Working assumption: no. Signing and encryption are different operations with different threat models; conflating them in one trait creates more confusion than it saves. Future RFC for a separate `Cipher` trait if needed.

### 9.4 Concurrent-sign safety for KMS implementations

KMS providers have rate limits per key. A swarm with many agents signing under one KMS key (unusual but possible) might hit them. Should the `Signer` trait expose a hint about expected throughput, or is rate-limiting the implementation's problem alone?

Working assumption: implementation's problem. The trait is intentionally narrow. Per-impl docs note their rate-limit posture.

## 10. Adoption checklist

- [ ] `/spec/identity-keys/README.md` reviewed and lands
- [ ] This RFC reviewed and lands
- [ ] Companion RFC 0016 reviewed and lands
- [ ] Phase B work tracked: `yutha-signer` crate scaffolded; trait defined; `InProcessSigner` implemented
- [ ] Phase B work tracked: five call sites refactored (Passport, Envelope, Capability, BearerSession, control-plane receipt signing)
- [ ] Phase B work tracked: every demo + walkthrough + example doc updated to the new call shape
- [ ] Conformance vectors authored under `/spec/vectors/signer/` (inprocess-equivalence, verify-under-public-key, concurrent-sign-safety)
- [ ] Phase C work tracked: `yutha-signer-gcp-kms`, `yutha-signer-azure-kv`, `yutha-signer-vault-transit` (three v1 deliverables per §9.1)
- [ ] mkdocs `--strict`, ruff check, mypy strict, cargo build, cargo clippy all clean
- [ ] At least one reviewer approves (per RFC 0001 process)
- [ ] Public review window expired

## 11. References

- [`/spec/identity-keys/README.md`](../identity-keys/README.md) — shared framing memo
- [RFC 0016 — Attestor interface](./0016-attestor-interface.md) — companion RFC; the other seam
- [RFC 0002 — Passport v1](./0002-passport-v1.md) — passport canonical form; `sign` call site #1
- [RFC 0003 — Envelope v1](./0003-envelope-v1.md) — envelope canonical form; `sign` call site #2
- [RFC 0005 — Capability v1](./0005-capability-v1.md) — capability canonical form; `sign` call site #3
- [RFC 0009 — Operator credentials](./0009-operator-credentials.md) — bearer-token / operator-revoke flow; `sign` call site #4
- [RFC 0014 — Sui receipt anchoring](./0014-sui-receipt-anchoring.md) — separate `Sealer` trait shaped similarly; the trait-plus-impl-crates pattern this RFC follows
- [RFC 8032 — Edwards-Curve Digital Signature Algorithm (Ed25519)](https://datatracker.ietf.org/doc/html/rfc8032)
- [Threat model](../../threat-model.md) — A1, A7, A8 are the load-bearing adversaries

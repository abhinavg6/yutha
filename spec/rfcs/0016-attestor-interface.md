# RFC 0016: Attestor interface — pluggable identity verification

> **Status:** Draft
> **Authors:** Abhinav Garg
> **Filed:** 2026-05-27
> **Targets spec:** `/spec/identity-keys/` (new directory; see [README](../identity-keys/README.md)),
>                   `/spec/control-plane/v1.proto` (`RegisterRequest` gains an optional `external_credential` field),
>                   `/spec/receipt/canonical-actions.md` (`agent.register` evidence gains `attested_external_identity` + `attestor_id` keys)
> **Targets phase:** Phase 3+ (enterprise readiness)
> **Companion RFC:** [0015 — Signer interface](./0015-signer-interface.md)
> **Predecessors:** [RFC 0002](./0002-passport-v1.md) (passport — the artifact the attested identity is bound into), [RFC 0006](./0006-topology-v1.md) (admission modes — what this RFC layers on top of), [RFC 0009](./0009-operator-credentials.md) (operator-revoke — future lifecycle hook)
> **Substrate dependency:** none; the trait + native default ship in `yutha-attestor` (new crate)
> **Out of scope:** Specific Attestor implementations (Phases E + F); multi-tenant resolver (deliberately deferred — see §5.4 for the shape that keeps it easy to add later); the lifecycle seam (upstream-revocation propagation)

## 1. Summary

Introduces an `Attestor` trait that mediates *external identity verification* at registration time. Today the Yutha admission handler accepts a passport whose self-signature is the only proof of identity. With this RFC, the admission handler also calls a pluggable `Attestor` to verify a presented external credential — a SPIFFE SVID, an OIDC ID token, or other — and records the verified external identity in the registration receipt's evidence. The result is a passport whose `agent_id` can be chained back to the enterprise's existing identity provider by anyone reading the audit log.

Concretely pinned in this RFC:

1. **An async trait** `Attestor` in a new `yutha-attestor` crate. One method (`verify`), taking an `AttestationContext` (swarm_id, claimed agent_id, agent public key) and a credential blob, returning an `AttestedIdentity` (external IdP identifier, credential expiry, free-form attributes).
2. **A breaking change to `AdmissionService.Register`.** `RegisterRequest` gains an optional `external_credential: bytes` field. The admission handler calls the configured `Attestor` for every registration regardless of whether the field is set — the native default handles the empty-credential case.
3. **`NativeAttestor` as the zero-dependency default.** Accepts an empty credential, returns a verified-identity record naming the agent's own self-signed passport as the attestation source. The hobby path is unchanged in behavior — only one extra in-process call along the admission flow.
4. **The trait shape is forward-compatible with multi-tenancy.** `AttestationContext` is a struct, not a bare argument; the future tenant-resolver layer wraps the Attestor rather than changing its trait. The Passport wire format does not gain a `tenant_id` field in this RFC. See §5.4 for the precise extension plan.
5. **Two reference enterprise impls planned.** SPIFFE/SPIRE in Phase E (the workload-identity-first standard, the primary enterprise reference) and OIDC in Phase F (the broad on-ramp). Sketches in §3.5 and §3.6; full design lands with each impl phase.
6. **Receipt evidence change.** `agent.register` receipts gain `attested_external_identity` (the IdP's identifier for the principal) and `attestor_id` (a short identifier for which Attestor verified the credential) keys in the canonical evidence. An auditor reading the receipt log can chain Yutha agent_ids back to enterprise principals.

The `Attestor` trait is server-side only. The Python SDK gains one new parameter (`external_credential: bytes | None`) on `YuthaClient.connect(...)` to pass through to the registration RPC; it does not host the Attestor itself.

## 2. Motivation

Today's admission flow is one trust step: the passport must self-verify under its embedded public key. The agent_id is whatever the agent generated. The passport's `owner` field is a free-form string the agent chose. Nothing in the protocol forces it to match anything an enterprise security team knows about.

For hobby and development swarms this is correct — the substrate is the trust root, and nothing outside it should be required. For enterprise deployments it is the disqualifying gap. Three concrete reasons:

1. **No chain back to a human / workload identity.** An auditor sees `agent_id = e3f7c1...`. Who is this? The audit log has the passport's `owner` field — which the agent itself wrote. There's no cryptographic chain from the agent_id back to a payroll record, an LDAP entry, a Kubernetes workload, an IAM role. With `Attestor`, the receipt log records the SPIFFE ID or OIDC subject the agent attested with; the agent_id is now anchored.

2. **No way to enforce "only our SPIRE agents may register."** Closed admission today allows operators to allowlist `agent_id` values or owner-key fingerprints, but those are values the agent picks. An enterprise wants the substrate to enforce "the only agents that can register are workloads SPIRE has issued SVIDs for." With `Attestor`, that becomes the configured policy: `SpiffeAttestor` rejects any registration without a valid SVID; the operator runs in closed mode with a SPIFFE-Attestor-only allow rule.

3. **No automatic Sybil resistance for open swarms.** Open admission today requires an `expires_at` on every passport as a sybil mitigation. With OIDC `Attestor`, "open" can mean "any registration that presents a valid token from this IdP." Sybil cost rises from "generate a keypair" to "obtain an IdP-issued credential" — orders of magnitude more friction for the attacker.

The `Attestor` trait is the smallest change that turns those three from "operator-can't-do-this" into "operator-configures-this."

## 3. Detailed design

### 3.1 The `Attestor` trait (Rust)

New crate `yutha-attestor` in the core workspace.

```rust
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::fmt::Debug;
use thiserror::Error;
use yutha_core::{AgentId, PublicKey, SwarmId, Timestamp};

/// Verifies an external identity credential at registration time.
///
/// Implementations:
///   - hold whatever configuration is needed to verify their credential
///     flavor (SPIFFE trust bundle, OIDC discovery URL + JWKS cache,
///     static config for native);
///   - perform verification on each call;
///   - return an `AttestedIdentity` carrying the verified external
///     identifier and any attributes the admission policy may want to act
///     on.
///
/// Implementations MUST be safe to call concurrently. The trait shape is
/// designed to be wrappable — a future multi-tenant resolver wraps an
/// `Attestor` without changing the trait signature.
#[async_trait]
pub trait Attestor: Send + Sync + Debug {
    /// A short identifier the registration-receipt evidence will carry.
    /// E.g., "native", "spiffe", "oidc:okta-prod". Used purely for
    /// audit-log filtering; not policy-load-bearing.
    fn id(&self) -> &str;

    /// Verify the presented credential.
    ///
    /// Returns Ok(AttestedIdentity) iff:
    ///   - the credential is well-formed for this Attestor's flavor;
    ///   - the credential validates against the Attestor's trust root
    ///     (SPIFFE bundle, OIDC JWKS, …);
    ///   - the credential is not expired;
    ///   - the credential's subject is consistent with `context.agent_public_key`
    ///     (the specifics of "consistent" are Attestor-flavor-dependent; see
    ///     §3.5 and §3.6 for SPIFFE and OIDC details).
    ///
    /// Returns Err(AttestorError) otherwise. The error carries no PII.
    async fn verify(
        &self,
        context: &AttestationContext,
        credential: &[u8],
    ) -> Result<AttestedIdentity, AttestorError>;
}

/// Context the admission handler passes to the Attestor.
///
/// Designed to be additive — new fields land as field-additions, never
/// as struct-replacement. The trait signature stays stable across
/// future extensions (multi-tenancy, request metadata, etc.).
#[derive(Debug, Clone)]
pub struct AttestationContext {
    /// The swarm this registration targets.
    pub swarm_id: SwarmId,

    /// The agent_id the registration request carries. The Attestor MAY
    /// reject if it doesn't like this (e.g., a SPIFFE Attestor that
    /// enforces "agent_id MUST be derived from the SVID's SPIFFE ID").
    pub claimed_agent_id: AgentId,

    /// The Ed25519 public key the registration is binding. The Attestor
    /// MUST verify that the credential's subject controls this key — for
    /// SPIFFE that's via the SVID's audience + the passport's
    /// self-signature; for OIDC it's the same, with the JWT's `aud`
    /// claim matching a Yutha-known value.
    pub agent_public_key: PublicKey,

    // FUTURE EXTENSION HOOKS — not present in v1; documented here so
    // implementations leave room.
    //
    // pub tenant_id: Option<TenantId>,
    // pub request_metadata: BTreeMap<String, String>,
}

/// Result of a successful `Attestor::verify` call.
///
/// Forms the basis of the `attested_external_identity` and `attestor_id`
/// fields in the `agent.register` receipt evidence.
#[derive(Debug, Clone)]
pub struct AttestedIdentity {
    /// The IdP-side identifier for the principal. SPIFFE Attestor returns
    /// the SVID's SPIFFE ID ("spiffe://<trust-domain>/..."); OIDC Attestor
    /// returns the JWT's `sub` claim, optionally prefixed with the
    /// issuer ("okta:user@example.com"); native Attestor returns
    /// "yutha:native:<agent_id_hex>".
    pub external_identity: String,

    /// Wall-clock instant the *external* credential expires. May be far
    /// in the future for long-lived credentials (X.509 SVIDs typically
    /// hours; OIDC tokens typically minutes). The future lifecycle layer
    /// hooks here — a credential past expiry triggers passport revocation.
    /// None ONLY for the native Attestor case (no external credential to
    /// expire).
    pub credential_expires_at: Option<Timestamp>,

    /// Free-form verified attributes from the credential. SPIFFE Attestor
    /// returns workload selectors here ("k8s_sa", "k8s_ns", ...). OIDC
    /// Attestor returns selected ID-token claims (e.g., "groups",
    /// "department"). Native Attestor returns an empty map.
    ///
    /// Attributes are landed in the `agent.register` receipt's evidence
    /// (under `attributes.<key>: <value>` keys). They do NOT change the
    /// passport's wire format.
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Error)]
pub enum AttestorError {
    /// Credential was structurally malformed (wrong format, bad signature
    /// algorithm, etc.). Implementations MUST NOT include the credential
    /// itself in the error message.
    #[error("credential malformed: {0}")]
    Malformed(String),

    /// Credential was structurally OK but failed validation (bad
    /// signature, expired, wrong audience, …).
    #[error("credential rejected: {0}")]
    Rejected(String),

    /// The IdP-side trust root was unreachable (SPIRE socket down, OIDC
    /// JWKS endpoint timed out). Distinct from `Rejected` because the
    /// admission handler MAY choose to retry, queue, or fail with a
    /// retryable error code.
    #[error("trust root unavailable: {0}")]
    TrustRootUnavailable(String),

    /// Anything else.
    #[error("internal attestor error: {0}")]
    Internal(String),
}
```

### 3.2 The `NativeAttestor` default

Ships in `yutha-attestor` itself. Verifies nothing about an external credential; the credential MUST be empty.

```rust
#[derive(Debug, Default)]
pub struct NativeAttestor;

#[async_trait]
impl Attestor for NativeAttestor {
    fn id(&self) -> &str { "native" }

    async fn verify(
        &self,
        context: &AttestationContext,
        credential: &[u8],
    ) -> Result<AttestedIdentity, AttestorError> {
        if !credential.is_empty() {
            return Err(AttestorError::Rejected(
                "NativeAttestor configured but external_credential was \
                 provided; reconfigure with a non-native Attestor or omit \
                 the credential".to_string(),
            ));
        }
        Ok(AttestedIdentity {
            external_identity: format!(
                "yutha:native:{}",
                hex::encode(context.claimed_agent_id.value)
            ),
            credential_expires_at: None,
            attributes: BTreeMap::new(),
        })
    }
}
```

The native flow is unchanged. The passport's self-signature is still the proof of key possession; admission's existing checks (allowlist, expiry, tier) still run; `NativeAttestor` just augments the receipt evidence with `attested_external_identity = "yutha:native:<hex>"` and `attestor_id = "native"`.

### 3.3 Admission integration

The admission handler's flow becomes:

```text
1. Receive RegisterRequest with (passport, external_credential).
2. Verify passport self-signature.                       [existing]
3. Verify swarm_id binding.                              [existing]
4. Verify admission policy (open/closed/hybrid).         [existing]
5. Call attestor.verify(context, external_credential).   [NEW]
   - context = AttestationContext { swarm_id,
                                    claimed_agent_id = passport.agent_id,
                                    agent_public_key = passport.agent_public_key }
   - on error → return PERMISSION_DENIED to client;
                emit agent.register.deny receipt (new kind — see §3.4)
6. Insert passport into registry.                        [existing]
7. Emit agent.register receipt with attested-identity    [evidence change]
   evidence keys populated from the AttestedIdentity.
```

The Attestor call happens AFTER admission-policy check, BEFORE registry insert. The ordering matters:

- *Before* admission-policy check means an attacker with no valid credential can probe the policy by submitting requests and seeing the failure code. Bad.
- *After* registry insert means an admission failure leaves stale rows in the registry. Bad.
- *Between* keeps both invariants: only requests that already pass policy are worth verifying externally; only successful Attestor verifications produce registry rows.

The Attestor is configured at control-plane startup (see §3.7). A control plane has exactly one Attestor in v1; multi-tenant resolver shape is §5.4.

### 3.4 Wire-format change — `RegisterRequest` + receipts

**`RegisterRequest` proto.** One new optional field:

```proto
message RegisterRequest {
    Passport passport = 1;

    // External credential to attest the registering principal against an
    // enterprise IdP. Format is Attestor-dependent: SPIFFE JWT-SVID is the
    // raw JWT bytes; OIDC is the raw ID-token JWT bytes; native expects
    // empty.
    //
    // The configured Attestor on the control plane decides how to parse
    // this. Clients that don't know what Attestor the control plane runs
    // can omit the field; a NativeAttestor control plane will accept.
    bytes external_credential = 2;  // NEW

    // Future: optional tenant_id, request metadata, etc. See RFC 0016 §5.4
    // for the multi-tenancy extension plan.
}
```

This is a proto3-additive change. Existing clients that don't set the field still work against a control plane running `NativeAttestor` (the empty credential is what NativeAttestor expects). A control plane running `SpiffeAttestor` or `OidcAttestor` rejects empty credentials with `AttestorError::Rejected`.

**`agent.register` receipt evidence.** Two new keys in the canonical evidence:

| Key | Type | Value |
|---|---|---|
| `attested_external_identity` | string | The `AttestedIdentity.external_identity` returned by the Attestor. |
| `attestor_id` | string | The `Attestor.id()` of the Attestor that verified the credential. |
| `attributes.<key>` | string | Optionally, each entry from `AttestedIdentity.attributes`. Native Attestor emits no `attributes.*` keys. |

`/spec/receipt/canonical-actions.md` is updated to add these as recognized evidence keys for `agent.register`.

**New receipt kind: `agent.register.deny`.** Emitted when the Attestor rejects (or when admission-policy rejects, or when swarm_id binding fails). Mirrors the existing pattern of `capability.check.deny`. Carries:

| Key | Type | Value |
|---|---|---|
| `claimed_agent_id` | bytes (hex) | The agent_id from the rejected request. |
| `attestor_id` | string | The Attestor that ran (or `"unattested"` if the rejection was admission-policy). |
| `deny_reason` | string | A short reason string. Specific to the failure type. |

Adding `agent.register.deny` lets operators monitor failed registration attempts — a useful surface for both debugging integration issues and noticing attack attempts.

### 3.5 Reference impl sketch — SPIFFE/SPIRE (Phase E)

A separate crate, `yutha-attestor-spiffe`, ships in Phase E. Verifies SPIFFE JWT-SVIDs. (The X.509-SVID + mTLS pattern is also valid but punts on the question of "where does the mTLS terminate" — JWT-SVID is bearer-token-shaped, fits in the existing `external_credential` field, and works regardless of whether the gRPC connection is direct or proxied.)

```rust
pub struct SpiffeAttestor {
    /// SPIFFE trust bundle — the SPIRE server's signing keys, fetched at
    /// construction via the Workload API (Unix socket) or supplied
    /// statically via config for environments without the agent socket.
    trust_bundle: TrustBundle,

    /// The audience value Yutha is expected to be addressed as in the
    /// SVID. SPIRE workloads request SVIDs with a target audience; this
    /// Attestor only accepts SVIDs whose `aud` claim contains this value.
    expected_audience: String,
}

impl SpiffeAttestor {
    pub async fn connect(workload_api_socket: &Path, audience: &str) -> Result<Self, _>;
    pub fn from_static_bundle(bundle: TrustBundle, audience: &str) -> Self;
}

#[async_trait]
impl Attestor for SpiffeAttestor {
    fn id(&self) -> &str { "spiffe" }

    async fn verify(&self, ctx: &AttestationContext, cred: &[u8])
        -> Result<AttestedIdentity, AttestorError>
    {
        // 1. Parse the credential as a JWT-SVID.
        // 2. Verify signature against trust_bundle.
        // 3. Check `aud` includes expected_audience.
        // 4. Check `exp` is in the future.
        // 5. Extract `sub` as the SPIFFE ID.
        // 6. Optional: extract workload selectors from custom claims.
        //
        // The proof of key-possession is the passport's self-signature
        // (verified before Attestor.verify is called) PLUS the SVID's
        // audience binding (which proves SPIRE attested the workload
        // for *this* swarm). The Attestor does not need to verify the
        // key-binding directly.
        // ...
    }
}
```

Full design lands in Phase E with a [`/spec/identity-keys/attestor-spiffe.md`](../identity-keys/attestor-spiffe.md) byte-exact spec alongside the impl. This RFC pins the trait surface; the SPIFFE-specific details (Workload API integration, trust-bundle refresh cadence, selectors-to-attributes mapping) are Phase E's deliverables.

### 3.6 Reference impl sketch — OIDC (Phase F)

A separate crate, `yutha-attestor-oidc`, ships in Phase F. Verifies OpenID Connect ID tokens.

```rust
pub struct OidcAttestor {
    /// Issuer's discovery URL — e.g., "https://login.example.com".
    issuer_url: Url,

    /// JWKS cache, refreshed on a configurable cadence (default 1 hour)
    /// or on cache-miss for an unrecognized `kid`.
    jwks_cache: Arc<JwksCache>,

    /// The audience value Yutha is registered as in the IdP.
    expected_audience: String,
}

impl OidcAttestor {
    pub async fn connect(issuer_url: Url, audience: &str) -> Result<Self, _>;
}

#[async_trait]
impl Attestor for OidcAttestor {
    fn id(&self) -> &str { "oidc" }

    async fn verify(&self, ctx: &AttestationContext, cred: &[u8])
        -> Result<AttestedIdentity, AttestorError>
    {
        // 1. Parse as JWT.
        // 2. Verify signature against JWKS (refresh on cache-miss kid).
        // 3. Verify `iss` matches issuer_url.
        // 4. Verify `aud` includes expected_audience.
        // 5. Verify `exp` is in the future, `iat` is reasonable.
        // 6. Optional: verify a `nonce` claim if Yutha included one.
        // 7. Extract `sub` as the external identity.
        // 8. Extract selected claims (groups, department, ...) as
        //    attributes.
        // ...
    }
}
```

Full design lands in Phase F with `/spec/identity-keys/attestor-oidc.md`. Same pattern as the SPIFFE Attestor.

### 3.7 Control-plane configuration

The control plane is configured with exactly one Attestor at startup. CLI flags:

```bash
# default: NativeAttestor, no external dependencies
yutha-control-plane ...

# SPIFFE: requires a path to a SPIRE Workload API socket
yutha-control-plane --attestor spiffe \
    --attestor-spiffe-socket /run/spire/sockets/agent.sock \
    --attestor-spiffe-audience yutha-prod \
    ...

# OIDC: requires an issuer URL
yutha-control-plane --attestor oidc \
    --attestor-oidc-issuer https://login.example.com \
    --attestor-oidc-audience yutha-prod \
    ...
```

The configured Attestor is constructed once at startup and held as an `Arc<dyn Attestor>` in `ControlPlaneState`. Same lifecycle pattern as `Arc<dyn ReceiptStore>` and `Arc<dyn Sealer>`.

### 3.8 Conformance contract

Three new vector directories under `/spec/vectors/attestor/`:

- **`attestor/native-accept-empty/`** — 16 cases. `NativeAttestor.verify(ctx, &[])` returns Ok with `external_identity = "yutha:native:<hex>"` and empty attributes. Asserts the native happy path.
- **`attestor/native-reject-nonempty/`** — 8 cases. `NativeAttestor.verify(ctx, &[some bytes])` returns Err. Asserts native rejects credentials when none was expected.
- **`attestor/context-passthrough/`** — 8 cases. The Attestor receives the context's `claimed_agent_id` and `agent_public_key` and the resulting `AttestedIdentity` is consistent. Asserts no context-mangling in the call.

SPIFFE and OIDC Attestors will add their own vector directories in Phases E and F, with credentials forged against a test trust bundle / JWKS.

The `agent.register` evidence changes also gain conformance assertions — the new keys MUST be present, in canonical order, in any conformant implementation.

### 3.9 Python SDK surface

One new parameter on `YuthaClient.connect`:

```python
client = YuthaClient.connect(
    server_addr,
    agent_id=agent_id,
    swarm_id=swarm_id,
    signing_key=signing_key,
    external_credential=spiffe_svid_bytes,  # NEW; optional, defaults to None
)
```

The client passes `external_credential` through to the `Register` RPC. The Python SDK does not host the Attestor itself — that's server-side. There's no client-side verification step.

The `YuthaAgent` wrapper (LangGraph / CrewAI / OpenAI Agents / MAF flavors) gets the same passthrough parameter. Demos and walkthroughs all gain an explicit `external_credential=None` for clarity, with one new example doc (Phase G) covering the SPIRE + KMS path end-to-end.

## 4. Drawbacks

- **Admission-flow latency.** Every registration now makes one extra call. NativeAttestor is in-process and ~microseconds; SPIFFE/OIDC are network-bound and add real latency (10–100 ms typical for cached cases, 100–500 ms for cold-cache JWKS refresh). For high-churn fleets this matters; for stable swarms it doesn't. Worth measuring in Phase D.
- **New failure mode at registration.** "IdP down" becomes a registration failure cause. SPIRE socket down or OIDC issuer unavailable means new agents cannot register until the IdP recovers. This is the right semantic (we don't admit unattested workloads) but it's a new failure surface for ops to monitor.
- **Wire-format change.** `RegisterRequest.external_credential` is additive but its semantics change: a control plane running `SpiffeAttestor` will reject what previously-working hobby clients submit. The breaking change is in the *behavior*, not the *wire shape*. Migration is per-deployment: clients running against a NativeAttestor server keep working; clients running against a SpiffeAttestor server must present an SVID.
- **`agent.register.deny` receipt volume.** A noisy environment (misconfigured client looping on retries, attacker probing) could fill the receipt store with deny receipts. Same shape as `capability.check.deny`; operators apply the same monitoring + rate-limiting patterns.
- **No multi-tenancy in v1.** A SaaS company that wants to onboard multiple enterprises onto one control plane will need either one process per tenant (which is fine but expensive) or to wait for the multi-tenant resolver layer (deliberately deferred — see §5.4). This is a real customer ask we're choosing to punt on, to keep this RFC shippable.
- **Attestor is server-side only.** An agent has no way to ask "what Attestor does this control plane run?" before submitting a registration. Operators document this out-of-band; misconfiguration produces `AttestorError::Rejected` rather than a structured handshake failure. Worth thinking about a `/v1/server-info` informational endpoint in a future RFC.

## 5. Alternatives considered

### 5.1 Attestor as a `PassportResolver` extension

The existing `PassportResolver` trait already does external lookup (it's how bearer-token verification finds the right public key). One option was to extend that trait with a new method for external attestation.

Rejected. `PassportResolver` is about *reading* passports from a backend store; `Attestor` is about *verifying* an inbound credential at registration time. Coupling them complicates both. Separate traits, separate concerns.

### 5.2 Push attestation logic into closed-mode admission policy

Today's closed-mode admission accepts an allowlist of agent_ids / owner-key fingerprints. One option was to expand that into "accept anything that SPIRE has attested." Keeps the trait count down.

Rejected. The admission allowlist is a static data structure; SPIFFE attestation is a dynamic call into an external service. Conflating them obscures both. The Attestor sits *next to* admission policy, not inside it.

### 5.3 Make every operation re-verify the external credential

This RFC has the Attestor run only at registration. An alternative is to have the agent present a fresh credential on every RPC, with the bearer-interceptor consulting the Attestor.

Rejected for v1. SPIFFE JWT-SVIDs are short-lived (minutes to hours); OIDC tokens are similar. The agent's Yutha bearer token (the AgentBearerToken from RFC 0007) is already short-lived and signed by the agent's private key, which the Attestor verified at registration. Re-attesting on every call doubles the network cost and adds little. The future lifecycle layer is the right place to add periodic re-attestation, NOT every-call re-attestation.

### 5.4 Per-tenant Attestor resolution in this RFC

Originally scoped to include `tenant_id` on `AttestationContext` and on `RegisterRequest`, with a resolver table mapping `(swarm_id, tenant_id) → Attestor`.

Rejected for v1, per the scoping discussion. Multi-tenancy is a separate concern that affects far more than just the Attestor (receipt isolation, constitution scoping, capability isolation). Building it half-way in this RFC is worse than not building it.

The trait shape preserves the option:

- `AttestationContext` is a struct, so a future `tenant_id: Option<TenantId>` field is field-addition, not signature change.
- The configured Attestor on the control plane is a single `Arc<dyn Attestor>`. The future multi-tenant version replaces that with an `Arc<dyn AttestorResolver>` where `AttestorResolver::resolve(&AttestationContext) -> Arc<dyn Attestor>` — and `StaticAttestor(Arc<dyn Attestor>)` is the trivial impl for the single-tenant case.
- `RegisterRequest` is proto3-additive; adding `tenant_id: string` later is non-breaking.
- The `AttestedIdentity.attributes` BTreeMap already accepts tenant-related claims; a future multi-tenant Attestor populates `"tenant_id"` in attributes.

The path from v1 to multi-tenancy is: add three optional fields, write the resolver layer, write the tenant-resolution policy. No trait-signature breaks. Concretely, a future "RFC 00NN — within-swarm tenancy" can land without amending 0016.

### 5.5 Do nothing — operators run separate control planes per tenant

Run one Yutha process per enterprise customer; identity boundary is the process boundary, not a within-swarm tenant boundary. This is the *current* state and is a real shippable option for many use cases.

Rejected as the only path. For small SaaS use cases (hundreds of tenants), process-per-tenant is operationally reasonable. For larger fleets the per-process overhead matters, and the multi-tenant resolver becomes the better answer. The point of this RFC is to leave the door open.

## 6. Threat-model impact

This RFC strengthens defenses against [A1 (hostile agent participant)](../../docs/internal/threat-model.md#a1-hostile-agent-participant), [A6 (Sybil attacker)](../../docs/internal/threat-model.md#a6-sybil-attacker), and slightly against [A8 (malicious operator)](../../docs/internal/threat-model.md#a8-malicious-operator).

- **A1 — hostile agent.** Today, a malicious actor in possession of the swarm's bootstrap seed can register an arbitrary agent in open mode. With a SPIFFE Attestor, they additionally need a valid SVID — which SPIRE issues only to attested workloads. Cost rises from "have the seed" to "compromise the SPIRE agent or attest as a valid workload."
- **A6 — Sybil.** Open admission's sole sybil defense today is "passports must have an `expires_at`." With an OIDC Attestor, sybil cost becomes "one IdP-issued token per fake agent" — orders of magnitude more friction than "one keypair generation per fake agent."
- **A8 — malicious operator.** Marginal effect. An operator who controls the Attestor's configuration can still admit whoever they want. The added value is *audit-side*: the receipt log records which Attestor verified each registration, so a post-hoc audit can detect "the operator switched the Attestor to one that admits everything for an hour."

No new attack surface is introduced beyond the IdP itself (which the operator already relies on for non-Yutha workload identity). Workstream L review required on Phase D before merge.

## 7. Conformance impact

Three new vector directories under `/spec/vectors/attestor/` (see §3.8). The existing admission/registration vectors continue to pass — a control plane running `NativeAttestor` with an empty `external_credential` produces identical receipts to today's behavior, modulo the two new evidence keys.

The Python `test_integration` suite gains:

- Tests for `external_credential` round-tripping through the registration RPC.
- An assertion that `agent.register` receipts now carry `attested_external_identity` and `attestor_id` evidence keys.

The Rust conformance suite gains:

- A scenario asserting that `RegisterRequest` with non-empty `external_credential` against a `NativeAttestor`-configured control plane returns `PERMISSION_DENIED` with the expected `agent.register.deny` receipt shape.

SPIFFE and OIDC scenarios are Phase E + F deliverables.

## 8. Migration

No migration. Pre-public; no production users to preserve compatibility for. Per [no-backcompat-pre-Phase-2-public](../../AGENTS.md):

- `RegisterRequest` proto adds the optional `external_credential` field — non-breaking on the wire.
- The admission handler always calls `Attestor.verify`; default `NativeAttestor` accepts empty credentials so the existing hobby flow continues to work behaviorally.
- All demos / walkthroughs / examples that construct `YuthaClient` gain `external_credential=None` for clarity.
- The Python SDK constructor signature gains the optional parameter; client code that doesn't set it works unchanged.

mkdocs `--strict`, ruff check, mypy strict, cargo build, cargo clippy all clean at end of Phase D.

## 9. Open questions

### 9.1 Should `agent.register.deny` carry the credential hash?

The proposed evidence omits any reference to the rejected credential. An auditor investigating "why was this registration rejected" only sees `claimed_agent_id` and `deny_reason`. Including a hash of the rejected credential (NOT the credential itself) would let the auditor correlate with IdP-side logs.

Working assumption: don't include. Keeps the deny path simple and avoids any chance of credential leakage. Worth confirming during Phase D.

### 9.2 Trust-bundle / JWKS refresh cadence

Both SPIFFE and OIDC Attestors need to refresh their trust roots. Common pattern is on-cache-miss (`kid` not in JWKS → fetch + retry) plus a TTL (default 1h).

If the IdP is briefly unavailable, what's the right behavior? Three options:

- Hard fail until refresh succeeds (strictest; rejects all registrations).
- Continue with stale trust root past TTL (most available; accepts trust-bundle staleness).
- Hard fail past TTL + N (e.g., 2× TTL) — bounded staleness window.

Working assumption: bounded staleness (option 3). Configurable; default 2× TTL. To revisit during Phase E.

### 9.3 Where should configured Attestor identity be published?

If an agent doesn't know which Attestor the control plane runs, it submits a registration and gets a `Rejected` error. That's the failure-driven path. Should the control plane expose a `/v1/server-info` (or similar) endpoint with `attestor_id`, `attestor_version`, etc.?

Working assumption: future RFC. Out of scope for this one; the failure-driven path is acceptable for v1.

### 9.4 Should client-side know whether to refresh its credential?

OIDC tokens expire in minutes. SPIFFE SVIDs expire in hours. If the Yutha agent runs for longer than its credential's lifetime, the credential at registration is the *only* one ever presented — the substrate doesn't check it again.

That's correct behavior for v1 (per §5.3 above), but it's a real gap for long-running agents. The lifecycle layer (deferred) is where this gets addressed — the Attestor result's `credential_expires_at` is the hook.

For v1: document that the agent is responsible for re-registering with a fresh credential before its current Yutha passport expires. Future lifecycle layer formalizes this.

## 10. Adoption checklist

- [x] `/spec/identity-keys/README.md` reviewed and lands (shared with RFC 0015) *(Phase A, 2026-05-27)*
- [x] Companion RFC 0015 reviewed and lands *(Phase A, 2026-05-27)*
- [x] This RFC reviewed and lands *(Phase A, 2026-05-27)*
- [x] Phase D work tracked: `yutha-attestor` crate scaffolded; trait defined; `NativeAttestor` implemented *(2026-05-30, D1)*
- [x] Phase D work tracked: `RegisterRequest` proto gains `external_credential` field; codegen regenerated *(D2)*
- [x] Phase D work tracked: admission handler refactored to call `Attestor.verify` between policy check and registry insert *(D4 — actually landed in the registry layer per the registry-holds-attestor design, not the handler; orchestration semantics are identical, and the handler stays thin)*
- [x] Phase D work tracked: `/spec/receipt/canonical-actions.md` updated with new `agent.register` evidence keys + new `agent.register.deny` action-kind *(D3)*
- [x] Phase D work tracked: Python SDK `YuthaClient.connect(...)` gains `external_credential` parameter *(D7 — actually landed on `AdmissionAPI.register()` + each adapter's `register()` rather than on `YuthaClient.connect`, because `connect` doesn't currently call Register. Semantically equivalent: caller passes the credential at the same logical "register the agent" step.)*
- [x] Phase D work tracked: every demo + walkthrough + example doc updated *(no source changes needed — `external_credential` defaults to `b""` which the native path expects; existing examples keep working unchanged)*
- [~] Conformance vectors authored under `/spec/vectors/attestor/` (native-accept-empty, native-reject-nonempty, context-passthrough) *(D8 — `/spec/vectors/attestor/README.md` shipped + 16/8/8 Rust test cases at `crates/yutha-attestor/tests/native_vectors.rs`. **Deviation:** JSON fixtures NOT shipped in v1 because NativeAttestor has no cross-impl to validate against; the Rust test IS the spec. Phase E/F SPIFFE + OIDC vectors land as JSON because their credential formats have multiple reference impls.)*
- [x] Phase E work tracked: `yutha-attestor-spiffe` crate + `/spec/identity-keys/attestor-spiffe.md` *(2026-05-31, E1–E10)*
  - [x] E1 spec — `/spec/identity-keys/attestor-spiffe.md` byte-exact contract
  - [x] E2 crate scaffold — `crates/yutha-attestor-spiffe/`, deps + module skeleton
  - [x] E3 `TrustBundleSource` — static-file + Workload-API streaming via `spiffe::JwtSource`
  - [x] E4 `SpiffeAttestor::verify` — 9-step algorithm per spec §3, `nbf`/`iat` clock-skew checks
  - [x] E5 error mapping per spec §9 — full `JwtSvidError` → `AttestorError` table with PII rule
  - [x] E6 CLI wiring — `--attestor spiffe` + 6 `--attestor-spiffe-*` flags, mutex source-flavour validation
  - [x] E7 tests — 11 forged-JWT integration tests + docker-spire end-to-end test (env-gated)
  - [x] E8 conformance vectors — 9 JSON fixtures under `/spec/vectors/attestor/spiffe/` + deterministic regen + loader test *(deliberate v1 deviation from spec §11's 45-case target: see vectors README)*
  - [x] E9 operator runbook — `docs/operator/spiffe-attestor.md` wired into mkdocs nav
  - [x] E10 verification gate — workspace cargo build/test/clippy clean, mkdocs strict clean, cross-spec sweep
- [x] Phase F work tracked: `yutha-attestor-oidc` crate + `/spec/identity-keys/attestor-oidc.md`
  - [x] F0 recon — JWKS-library survey (`jwks` chenhunghan + handwritten cache selected; `jwks_client_rs` rejected for opaque verify API + heavier dep graph)
  - [x] F1 spec — [`/spec/identity-keys/attestor-oidc.md`](../identity-keys/attestor-oidc.md) v1 draft, design-frozen
  - [x] F2 scaffold `yutha-attestor-oidc` crate — config + source + attestor + payload + jwks_cache + error modules; workspace member wired
  - [x] F3 `JwksSource` — Discovery + `jwks_uri` override + static file; `JwksCache` with TTL refresh + kid-miss async refresh (deduplicated via before/after `last_refresh_at` snapshot — F7 kid-rotation test guards against the F3-original elapsed-ms heuristic bug)
  - [x] F4 `OidcAttestor::verify` — full 9-step algorithm per spec §3 (`decode_header` → kid+typ+alg pre-check → cache.assert_fresh → cache.lookup → `jsonwebtoken::decode<Value>` for sig+iss+aud+exp+nbf → manual iat → AttestedIdentity construction with `oidc:<iss>:<sub>` + claim projection)
  - [x] F5 error mapping per spec §9 — `map_oidc_error(jsonwebtoken::Error)` covers verified ErrorKind variants (InvalidSignature/InvalidToken/InvalidIssuer/InvalidAudience/ExpiredSignature/ImmatureSignature/MissingRequiredClaim) + catch-all → Malformed for unknown variants. PII-leak spot-check test in `src/error.rs::tests`.
  - [x] F6 CLI wiring — `--attestor oidc` + 11 `--attestor-oidc-*` flags wired into `yutha-control-plane`; mutex validation for jwks-uri vs jwks-file; HS*/none rejected at config-validate time
  - [x] F7 tests — 10 forged-JWT round-trip tests (RS256 + ES256 + EdDSA happy paths + 5 claim-failure rows that need a valid signature + projection + aud-array) + 4 in-process axum-mock-OIDC integration tests including kid-rotation (no `#[ignore]`; runs in CI)
  - [x] F8 conformance vectors — 7 JSON fixtures under `/spec/vectors/attestor/oidc/` + deterministic regen + loader test *(deliberate v1 deviation from spec §11's 25-case target: see vectors README)*
  - [x] F9 operator runbook — `docs/operator/oidc-attestor.md` wired into mkdocs nav (Discovery / JWKS-URI / static-file source-decision table, per-IdP recipes for Auth0/Okta/Keycloak/Azure AD/Google, failure-mode → diagnosis table, docker-keycloak local-test recipe)
  - [x] F10 verification gate — workspace cargo build/test/clippy clean, mkdocs strict clean, cross-spec sweep
- [x] Phase G work tracked: `docs/operator/enterprise-identity.md` end-to-end walkthrough — shipped 2026-05-31. Combines SPIRE Attestor + Vault transit Signer into one integrated deployment narrative; per-backend runbooks (Vault / GCP KMS / Azure KV / SPIFFE / OIDC) updated to lead with `--signer …` / `--attestor …` CLI flags; the bootstrap-CP-identity vs bootstrap-agent-identity distinction explained; alternative-backends 2×2 table for the four pairings operators most often pick. Plus the Phase G Signer CLI wiring on the control plane (12 new `--signer*` flags; `SignerArg::build` mirrors the `AttestorArg::build` pattern from Phase E/F).
- [ ] mkdocs `--strict`, ruff check, mypy strict, cargo build, cargo clippy all clean *(D11 — verification gate; Phase E re-affirmed at E10)*
- [ ] At least one reviewer approves (per RFC 0001 process)
- [ ] Public review window expired

## 11. References

- [`/spec/identity-keys/README.md`](../identity-keys/README.md) — shared framing memo
- [RFC 0015 — Signer interface](./0015-signer-interface.md) — companion RFC; the other seam
- [RFC 0002 — Passport v1](./0002-passport-v1.md) — passport canonical form
- [RFC 0006 — Topology v1](./0006-topology-v1.md) — admission modes; what this RFC layers on top of
- [RFC 0009 — Operator credentials](./0009-operator-credentials.md) — operator-revoke; future lifecycle hook for credential expiry
- [SPIFFE specification](https://github.com/spiffe/spiffe) — the standard the SPIFFE Attestor implements against
- [SPIFFE JWT-SVID](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md) — the credential format the SPIFFE Attestor verifies
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) — the standard the OIDC Attestor implements against
- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519) — the wire format both reference Attestors verify
- [Threat model](../../docs/internal/threat-model.md) — A1, A6, A8 are the load-bearing adversaries

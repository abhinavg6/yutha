# yutha-attestor

Pluggable external-identity verification for Yutha admission.

The `Attestor` trait mediates the registration-time check that binds a
Yutha agent_id to an enterprise identity provider's notion of the
principal — a SPIFFE ID, an OIDC subject, or other.
`NativeAttestor` is the zero-dependency default: it accepts an empty
credential and records the agent's own self-signed passport as the
attestation source. Reference enterprise implementations
(SPIFFE/SPIRE, OIDC) ship as separate optional crates in Phases E + F
of the enterprise-identity workstream.

Implements [RFC 0016 — Attestor interface](../../spec/rfcs/0016-attestor-interface.md).

## Quick usage

```rust
use yutha_attestor::{Attestor, AttestationContext, NativeAttestor};
use yutha_core::{AgentId, PublicKey, SignatureAlgorithm, SwarmId};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let attestor = NativeAttestor::default();

let context = AttestationContext {
    swarm_id: SwarmId::new(),
    claimed_agent_id: AgentId::new(),
    agent_public_key: PublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 32])?,
};

// Native accepts an empty credential.
let identity = attestor.verify(&context, &[]).await?;
assert!(identity.external_identity.starts_with("yutha:native:"));
# Ok(()) }
```

## Why it exists

Today's admission flow is one trust step: the passport must self-verify
under its embedded public key. For hobby and development swarms this is
correct — the substrate is the trust root. For enterprise deployments
it's the disqualifying gap: there's no cryptographic chain from a Yutha
`agent_id` back to a SPIFFE ID, an LDAP entry, a Kubernetes workload, an
IAM role.

The `Attestor` trait is the smallest change that turns "no IdP binding
possible" into "IdP binding configurable." The native default keeps the
hobby path unchanged in behavior; reference enterprise implementations
plug in without touching the substrate.

See [RFC 0016 §2 (Motivation)](../../spec/rfcs/0016-attestor-interface.md#2-motivation)
for the three concrete enterprise-blocking gaps this addresses.

## What's in the trait

The trait surface is intentionally small — one method:

| Method | Purpose |
|---|---|
| `id() -> &str` | Short identifier for the `agent.register` receipt's `attestor_id` evidence key. Audit-log filtering only; not policy-load-bearing. |
| `verify(context, credential) -> Result<AttestedIdentity, AttestorError>` | The actual check. Returns the verified IdP identifier + credential expiry + free-form attributes. |

`AttestationContext` is a struct (not a flat argument list) so future
fields (`tenant_id`, request metadata) can land as field-additions
without breaking the trait signature. See
[RFC 0016 §5.4](../../spec/rfcs/0016-attestor-interface.md#54-per-tenant-attestor-resolution-in-this-rfc)
for the multi-tenancy extension plan.

`AttestorError` distinguishes three failure modes:

| Variant | Admission-handler treatment |
|---|---|
| `Malformed` / `Rejected` | Permanent rejection → `PERMISSION_DENIED` + `agent.register.deny` receipt. |
| `TrustRootUnavailable` | Transient → `UNAVAILABLE` (client MAY retry); no deny receipt (no verdict). |
| `Internal` | Yutha-side bug → `INTERNAL` + deny receipt (verdict was "deny" even if cause was internal). |

## Implementations

- **`NativeAttestor`** — the zero-dependency default. Accepts the empty
  credential; returns `yutha:native:<agent_id_hex>` as the external
  identifier. What hobby and dev swarms run. Lives in this crate.
- **`yutha-attestor-spiffe`** *(separate crate, Phase E)* — SPIFFE
  JWT-SVID verification against a SPIRE trust bundle.
- **`yutha-attestor-oidc`** *(separate crate, Phase F)* — OpenID
  Connect ID-token verification against a discovery URL's JWKS.

## When to reach for this

- **Always**, in v1 — the substrate's admission handler always calls
  the configured Attestor, even on the native path. Wiring is at the
  control-plane construction site, not at every call site.

## Invariants implementations MUST uphold

See the trait doc-comment for the full list. Short version:

1. `verify` is `Send + Sync` — concurrent admission requests share one
   `Arc<dyn Attestor>`.
2. No PII in `AttestorError` messages — operators correlate with the
   IdP's audit log via timestamp + `claimed_agent_id`.
3. `verify` does not mutate `context` (Rust enforces; restated for
   reviewer attention).
4. The credential's subject MUST be tied to `context.agent_public_key`
   in a flavor-appropriate way (SPIFFE: audience binding; OIDC:
   `aud` claim; native: passport self-signature).

## License

Apache-2.0. See the repository [`LICENSE`](../../LICENSE).

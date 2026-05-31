# yutha-attestor-oidc

OpenID Connect backend for the Yutha `Attestor` trait. Verifies OIDC ID tokens against a configured JWKS — fetched live via OIDC discovery, fetched live via a direct JWKS URL, or loaded from a static file — and returns `oidc:<iss>:<sub>` as the attested external identity for binding into a Yutha agent passport.

The companion spec is [`/spec/identity-keys/attestor-oidc.md`](../../spec/identity-keys/attestor-oidc.md). Conformant implementations in other languages MUST honor everything pinned there.

## Status

**Phase F in progress.** This crate ships across:

- [x] **F1** — spec drafted ([attestor-oidc.md](../../spec/identity-keys/attestor-oidc.md))
- [x] **F2** — crate scaffold + types + workspace wiring *(you're here)*
- [ ] **F3** — `JwksSource` impl (Discovery + JWKS-URI override + static file) + cache with TTL refresh + kid-miss async refresh (deduplicated)
- [ ] **F4** — `OidcAttestor::verify` body (9-step algorithm per spec §3)
- [ ] **F5** — full error mapping per spec §9
- [ ] **F6** — CLI wiring into `yutha-control-plane` (replace the Phase-F bail, add `--attestor-oidc-*` flags)
- [ ] **F7** — forged-JWT unit tests + in-process mock OIDC integration test
- [ ] **F8** — JSON conformance vectors under `/spec/vectors/attestor/oidc/`
- [ ] **F9** — operator runbook `docs/operator/oidc-attestor.md`
- [ ] **F10** — verification gate + commit

Until F4 lands, `OidcAttestor::connect` and `OidcAttestor::verify` both return `AttestorError::Internal` with a "Phase F in progress" message. Operators today should use `--attestor spiffe` (Phase E) or `--attestor native` (default).

## What this crate does

OIDC turns "anyone who can mint an Ed25519 keypair can register an agent" into "registration requires an ID token from the configured corporate IdP, signed by a key in that IdP's JWKS, with the right audience claim". Adoption inside large enterprises (Okta, Auth0, Azure AD, Keycloak, Google Workspace) usually starts here — it's the broadest-compatibility Attestor.

The Attestor is server-side only. Clients present an ID token in the `RegisterRequest.external_credential` bytes field; the Yutha SDK does not parse or verify the token client-side.

## What this crate does NOT do

- **Mint ID tokens.** That's the IdP's job; we verify.
- **Run OAuth flows.** No authorization-code / PKCE / refresh-token handling. The agent obtains an ID token via the IdP's normal flow before calling Yutha; the substrate only does offline JWS verify against the JWKS.
- **HMAC-signed ID tokens.** HS256/HS384/HS512 require a shared secret between issuer and verifier, which breaks JWKS distribution and the OIDC trust posture. Operators wanting an HMAC-shaped admission flow should use the native Attestor with a swarm-wide shared seed.
- **Userinfo enrichment.** Optional OIDC userinfo-endpoint queries are deferred (see attestor-oidc.md §13.1).

## Quick orientation

```rust,no_run
use yutha_attestor::{Attestor, AttestationContext};
use yutha_attestor_oidc::{OidcAttestor, OidcConfig, JwksSource};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let attestor = OidcAttestor::connect(OidcConfig {
    source: JwksSource::Discovery {
        issuer_url: "https://login.example.com".to_string(),
    },
    expected_issuer: "https://login.example.com".to_string(),
    expected_audience: "yutha-orders-prod".to_string(),
    allowed_algs: vec!["RS256".into(), "ES256".into(), "EdDSA".into()],
    project_claims: vec!["groups".into(), "email".into()],
    cache_ttl_secs: 3600,
    max_staleness_secs: Some(86400),
    clock_skew_tolerance_secs: 60,
    connect_timeout_secs: 10,
    allow_insecure_http: false,
})
.await?;

// (verify body lands in F4)
# Ok(()) }
```

## Two invariants

1. **JWKS reads are atomic-swap-safe.** The cached JWKS is held behind a structure that lets `OidcAttestor::verify` see either the old JWKS or the new one, never a torn intermediate.
2. **No PII in errors.** Per [RFC 0016 §3.1] and the spec's §9.1, error messages MUST NOT include credential bytes, decoded payload fields, or subject identifiers. The crate's `map_oidc_error` helper centralises the conversions.

[RFC 0016 §3.1]: ../../spec/rfcs/0016-attestor-interface.md#31-the-attestor-trait-rust

## See also

- [`yutha-attestor`](../yutha-attestor/) — the trait + native default this crate plugs into
- [`yutha-attestor-spiffe`](../yutha-attestor-spiffe/) — the sister Phase E backend; same shape, different IdP
- [`/spec/identity-keys/README.md`](../../spec/identity-keys/README.md) — workstream framing for Signer + Attestor

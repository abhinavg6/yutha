# OIDC Attestor — Specification (v1)

> **RFC:** [0016 — Attestor interface](../rfcs/0016-attestor-interface.md) (the umbrella; §3.6 defers byte-exact details here)
> **Predecessors:** [RFC 0002](../rfcs/0002-passport-v1.md) (passport — the artifact the attested identity is bound into), [identity-keys README](./README.md) (shared framing for Signer + Attestor), [attestor-spiffe spec](./attestor-spiffe.md) (sibling Attestor; structural template for this doc)
> **Phase:** Phase 3 (enterprise readiness)
> **Status:** Draft, design-frozen
> **Companion crate:** `yutha-attestor-oidc` (Phase F)
> **External standards:** [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html), [RFC 7519 — JWT](https://datatracker.ietf.org/doc/html/rfc7519), [RFC 7517 — JWK](https://datatracker.ietf.org/doc/html/rfc7517), [RFC 7518 — JWA](https://datatracker.ietf.org/doc/html/rfc7518), [RFC 8414 — OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
> **Out of scope:** authorization-code / PKCE / refresh-token flows (Yutha admission is a server-side verify; the agent comes pre-equipped with an ID token); userinfo-endpoint enrichment (deferred — see §13.1); per-issuer `attestor_id` disambiguation (deferred — see §13.2); HMAC-signed ID tokens (architecturally disallowed — see §2.1)

## 0. Scope

This document specifies the byte-exact verification contract for the OIDC Attestor — Yutha's broad-compatibility enterprise Attestor that mediates OpenID-Connect-issued workload identity into Yutha agent passports. It is the detail spec [RFC 0016 §3.6](../rfcs/0016-attestor-interface.md#36-reference-impl-sketch--oidc-phase-f) defers to; conformant implementations MUST honor everything pinned here.

What this document does NOT specify: the *implementation* of the verifier (a server-side component of the control plane). What it specifies is the contract every conformant implementation honors — same ID token + same JWKS + same operator config in, same `AttestedIdentity` (or same `AttestorError`) out.

The Phase F crate (`yutha-attestor-oidc`) is the in-tree reference implementation; it builds on [`jwks ^0.5`](https://crates.io/crates/jwks) (for JWKS parse + OIDC discovery) and [`jsonwebtoken ^10`](https://crates.io/crates/jsonwebtoken) (for JWT verify), with the cache + verify state machine in-tree. Third-party implementations in other languages (Go, Java, Python, …) are equally welcome as long as they pass the §11 conformance vectors.

---

## 1. The OIDC Attestor contract

The OIDC Attestor is an `Attestor` trait implementation that verifies OpenID Connect ID tokens against a configured JWKS. The contract is:

1. **Input.** The admission handler passes (a) an `AttestationContext` (swarm_id, claimed_agent_id, agent_public_key) and (b) an opaque credential blob.
2. **Pre-verification.** The credential MUST be parsed as a JWT per [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) §3 (JWS compact serialization).
3. **Verification.** The Attestor MUST run every check in §3 in order. Any check failing terminates with the mapped `AttestorError` variant (see §9).
4. **Output on success.** An `AttestedIdentity` with `external_identity` = `oidc:<iss>:<sub>` (see §7), `credential_expires_at` = the ID token's `exp` claim, and `attributes` = the operator-configurable claim projection (see §8).
5. **Output on failure.** An `AttestorError` chosen per §9. The error message MUST NOT contain any credential bytes, any decoded header/payload field other than the algorithm name, or any subject identifier.

The Attestor is server-side only. Clients present an ID token in `RegisterRequest.external_credential`; the Yutha SDK does not parse or verify it client-side.

### 1.1 Why ID tokens, not access tokens

OAuth 2.0 / OIDC ecosystems mint two token types: **access tokens** (for calling protected APIs; opaque by spec, often JWT in practice) and **ID tokens** (for proving *who* a principal is to a relying party; always JWT, with a documented claim set). The Attestor accepts only ID tokens. Three reasons:

- **Claim shape is standardized.** ID tokens MUST contain `iss`, `sub`, `aud`, `exp`, `iat` per OpenID Connect Core §2. Access tokens have no spec-mandated claim shape — different providers ship wildly different formats. The Attestor needs a fixed contract to verify against.
- **Signature is mandatory.** ID tokens MUST be signed (Core §2). Access tokens are commonly opaque/encrypted-only at the IdP; offline verification against a JWKS is not always possible.
- **Audience semantics match.** An ID token's `aud` is the relying party — exactly Yutha's role here. An access token's `aud` is the resource server — a different abstraction that complicates the model.

Operators presenting access tokens get `Malformed("payload: missing iss")` (or similar) — the contract is "ID token in" and that's what fails first on most access tokens.

---

## 2. ID-token format pinning

The Attestor accepts ID tokens per [OpenID Connect Core 1.0 §2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken). This section pins what that means in byte-exact terms for this Attestor:

### 2.1 Header

Standard JWS compact serialization (`base64url(header) || '.' || base64url(payload) || '.' || base64url(signature)`). The decoded header MUST be a JSON object with at least:

| Claim | Type | Constraint |
|---|---|---|
| `alg` | string | MUST be in the operator-configured allow-list (default: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `EdDSA`). **`none` MUST be rejected with `Malformed`** regardless of operator config. **`HS256`/`HS384`/`HS512` MUST be rejected with `Malformed`** regardless of operator config — see below. |
| `typ` | string | If present, MUST be `JWT` or `JOSE`. Other values are `Malformed`. |
| `kid` | string | Required. Lookup key into the JWKS. Absence is `Malformed` even if the JWKS has exactly one key — see §2.1.1. |

Any other header claim is ignored (not load-bearing for verification).

**Why HMAC is architecturally disallowed.** HS256/HS384/HS512 sign the JWT with a *shared symmetric secret*. Verifying an HS-signed token means the verifier holds the same key the issuer used to sign — at which point the verifier *is* the issuer for trust purposes. JWKS distribution doesn't fit symmetric secrets (they don't go in a public discovery doc), and the trust posture ("we mint, you verify") of OIDC depends on asymmetric signing. The Attestor refuses HS* algorithms not because the operator might allow them, but because they break the OIDC threat model. Operators wanting an HMAC-shaped admission posture should use the native Attestor with a swarm-wide shared secret instead.

#### 2.1.1 Why `kid` is required even for single-key JWKS

Some IdPs ship a one-key JWKS and omit `kid` from issued tokens. The OIDC spec doesn't require `kid` in the token header (only in the JWK). Two policies were considered:

- **Loose:** if `kid` is missing in the header AND the JWKS has exactly one key, use that key.
- **Strict:** require `kid` always, reject on absence.

This Attestor implements **strict**. Reasons: (a) operationally, JWKS frequently grow from one key to two during a rotation window; a `kid`-less token will silently start failing at that moment instead of at the obviously-correct config-time. (b) Audit-side, the `kid` is the only header field that's meaningful in receipts (if we ever started recording header diagnostics — we don't today, but the principle stands). (c) Every modern IdP (Auth0, Okta, Google, Azure AD, Keycloak, dex) ships `kid` by default; the strict policy rejects only misconfigured IdPs.

If a future operator surfaces a specific IdP that cannot be configured to issue `kid`-bearing tokens, §13.3 documents the loose-mode escape hatch.

### 2.2 Payload

The decoded payload MUST be a JSON object. Required claims:

| Claim | Type | Constraint |
|---|---|---|
| `iss` | string | MUST exactly equal the operator-configured `expected_issuer` (string-equal, no normalisation — see §6). |
| `sub` | string | The subject identifier within the issuer's namespace. Non-empty UTF-8. No further shape constraint (OIDC permits any string up to 255 chars; the Attestor only checks non-empty). |
| `aud` | string OR array-of-string | MUST contain the operator-configured `expected_audience` (see §6). Otherwise `Rejected`. |
| `exp` | integer | Unix epoch seconds. MUST be strictly greater than verification-time wall-clock. Otherwise `Rejected`. |
| `iat` | integer | Unix epoch seconds. MUST be ≤ verification-time wall-clock plus the configured clock-skew tolerance. Default tolerance: 60 seconds. |

Optional claims the Attestor recognises:

| Claim | Type | Treatment |
|---|---|---|
| `nbf` | integer | If present and > verification-time wall-clock plus tolerance, `Rejected`. |
| `azp` | string | Ignored. Authorized-party semantics are RP-flow-specific; Yutha's admission is server-side. |
| `nonce` | string | Ignored. Yutha does not issue a nonce challenge at admission. |
| `auth_time` | integer | Ignored. |
| `acr`, `amr` | varies | Ignored. |
| Operator-allowlisted claims (e.g., `groups`, `email`, `roles`) | string OR array-of-string | Projected into `attributes` per §8. |

Any other payload claim is ignored. Implementations MUST NOT fail on unknown claims (forward compatibility with IdP-specific extensions).

### 2.3 Signature

The signature is verified per JWS rules for the `alg` header claim, against the public key in the JWKS entry matching `kid`. The Attestor delegates this step to `jsonwebtoken::decode` (or its non-Rust equivalent); the requirement is that the algorithm enforcement (§2.1) matches what the library actually verifies — the Attestor MUST pass the header `alg` into the library's allow-list parameter, not trust the library's default.

---

## 3. Verification algorithm

Given `(context: AttestationContext, credential: &[u8])`, the Attestor MUST execute the following steps in order. Each step's failure maps to a specific `AttestorError` per §9.

```text
 0. If credential.is_empty():
      → Rejected("empty credential; OIDC Attestor requires an ID token")
 1. Parse `credential` as a JWS compact serialization (three base64url
    segments joined by '.').
      → On parse failure: Malformed("not a JWS compact serialization")
 2. Decode the header. Reject `alg = none`. Reject HS*. Reject any alg
    not on the operator-configured allow-list. Require `kid`.
      → On any header issue: Malformed("header: <reason>")
 3. Snapshot the current JWKS (§4, §5). If the cache is past the
    bounded-staleness deadline (§5):
      → TrustRootUnavailable("JWKS stale: last refresh was N seconds ago;
                              max staleness window is M seconds")
 4. Look up the JWKS entry whose `kid` matches the header `kid`.
    On miss, kick off an out-of-band JWKS refresh (deduplicated; see §5.2)
    and retry the lookup once against the refreshed JWKS.
      → On second miss: Rejected("kid not found in JWKS")
      → On refresh failure during the retry: TrustRootUnavailable(
          "JWKS refresh failed: <reason>")
 5. Verify the JWS signature against that public key using the header
    `alg`. The library's verify call MUST be constant-time-safe.
      → On signature failure: Rejected("signature verification failed")
 6. Decode the payload as JSON.
      → On JSON parse failure: Malformed("payload not JSON")
 7. Validate required payload claims (§2.2):
    - `iss` MUST be present and equal `expected_issuer`.
      → On miss/empty: Malformed("payload: missing iss")
      → On mismatch: Rejected("issuer mismatch")
    - `sub` MUST be present, a non-empty string.
      → On miss/empty: Malformed("payload: missing sub")
    - `aud` MUST be present and contain `expected_audience`.
      → On miss: Malformed("payload: missing aud")
      → On no overlap: Rejected("audience mismatch")
    - `exp` MUST be present, an integer, strictly greater than now().
      → On miss/non-integer: Malformed("payload: missing/invalid exp")
      → On expiry: Rejected("credential expired")
    - `iat` MUST be present and ≤ now() + clock_skew_tolerance.
      → On miss/non-integer: Malformed("payload: missing/invalid iat")
      → On future-dated: Rejected("iat in the future")
    - `nbf` (if present) MUST be ≤ now() + clock_skew_tolerance.
      → On future-dated: Rejected("nbf in the future")
 8. Project payload to AttestedIdentity (§7, §8):
    - external_identity = format!("oidc:{}:{}", iss, sub)
    - credential_expires_at = Some(Timestamp::from_unix_seconds(exp))
    - attributes = §8 projection of operator-allowlisted claims
                   (empty if no claims allowlisted)
 9. Return Ok(AttestedIdentity).
```

The ordering is load-bearing, and parallels the SPIFFE Attestor's §3 with one OIDC-specific twist:

- **Step 0 (empty check) first** is faster than parse and gives a clearer error for the most common misconfiguration ("forgot to pass a credential").
- **Step 3 (JWKS snapshot) before signature verify** because the JWKS snapshot is the slower path on cold-cache cases; failing fast on `TrustRootUnavailable` avoids spending CPU on a JWS verify that will be discarded.
- **Step 4 (kid lookup with refresh-on-miss)** is the OIDC-specific addition. JWKS rotation is a normal IdP behavior — an unrecognized `kid` is often "the IdP rotated keys since our last fetch", not "this is a forgery". A single deduplicated refresh + retry handles the rotation case without making every verify call wait on a stale-TTL-trigger refresh. If the second lookup still misses, the credential is genuinely unknown and rejected.
- **Step 5 (signature verify) before payload claim checks** because an attacker submitting forged claims wants to know which check rejected them; doing signature verify first means a forged ID token always reports `signature verification failed` regardless of payload contents — no information leak about which claims would have passed.
- **Step 7 (claim checks) in the order listed**: identity-binding claims (`iss`, `sub`) before liveness claims (`aud`, `exp`, `nbf`, `iat`). This means an expired-but-otherwise-good token reports "credential expired" rather than "audience mismatch", which is the more useful operator diagnostic.

The whole algorithm MUST be constant-time-safe with respect to the signature verify in step 5. Steps 0–4 and 6–8 may short-circuit on the first failure; step 5 MUST use the implementation library's constant-time JWS verify path.

### 3.1 Key-binding to `context.agent_public_key`

RFC 0016 §3.1 documents that the Attestor's `verify()` is called with the agent's claimed public key in the `AttestationContext`, and that "the Attestor MUST verify that the credential's subject controls this key". The OIDC Attestor handles this through the same *layered* binding as the SPIFFE Attestor (see [attestor-spiffe §3.1](./attestor-spiffe.md#31-key-binding-to-contextagent_public_key)):

1. **The passport's self-signature** is verified by the admission handler BEFORE `Attestor.verify` is called (RFC 0016 §3.3 step 2). That proves the agent holds the private key matching `context.agent_public_key`.
2. **The ID token's `aud` claim** matches the operator-configured `expected_audience`. That proves the IdP issued the token *for* this Yutha swarm specifically.
3. **The ID token's `sub` claim** is the subject identifier the IdP assigned to the calling principal.

Composing the three: the principal is an IdP-attested subject `sub`, holds an Ed25519 keypair whose public key it bound into the passport, and obtained an ID token that targets this Yutha swarm by audience. The OIDC Attestor does NOT inspect `context.agent_public_key` directly — it relies on the admission handler having done the self-signature check before calling `verify`.

This composition is sound as long as the swarm's `expected_audience` value is not shared with any other system that might mint ID tokens with the same audience for principals who do not also hold a Yutha-bound keypair. Operators MUST choose audience values that are Yutha-swarm-specific — see §6.1.

---

## 4. JWKS sources

The OIDC Attestor obtains its JWKS from exactly one source at construction. Three source types are supported.

### 4.1 OIDC Discovery

The standard path. Operator configures `--attestor-oidc-issuer <url>`. At construction the Attestor:

1. Fetches `<issuer>/.well-known/openid-configuration` per [OpenID Connect Discovery 1.0 §4](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig).
2. Validates the response per §6.3 below (`issuer` exact-match, `jwks_uri` HTTPS, etc.).
3. Fetches the JWKS from the discovery doc's `jwks_uri`.
4. Holds the JWKS in the cache (§5) for the configured TTL.

Discovery is the default mode and the path operators should choose unless they have a specific reason not to. It self-heals across IdP infrastructure changes that move the JWKS endpoint within the same issuer.

### 4.2 JWKS URI override

For IdPs whose discovery doc is misconfigured, missing, or hidden behind an authenticated endpoint, operators may bypass discovery by providing the JWKS URL directly: `--attestor-oidc-jwks-uri <url>`.

When this flag is set, the Attestor:

1. Does NOT fetch the discovery doc.
2. Fetches the JWKS directly from the provided URL.
3. Skips the discovery-doc `issuer` exact-match check (the operator-configured `--attestor-oidc-issuer` is still used for the §3 step 7 `iss`-claim check).

Use sparingly. The discovery-doc check exists for a reason — without it, a man-in-the-middle who can swap the operator's `--attestor-oidc-issuer` config still has to forge the discovery doc; with the override, only the JWKS endpoint needs to be controlled. The override is for cases where the IdP truly doesn't run discovery (rare; some self-hosted dev IdPs); not for skipping config burden.

### 4.3 Static JWKS file

For air-gapped deployments where the control plane cannot reach the IdP at all (or where operators want JWKS rotation to be a deliberate file-replace + restart rather than a live HTTP fetch): `--attestor-oidc-jwks-file /etc/yutha/oidc-jwks.json`.

The file MUST contain a JSON document of the shape:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "abc123",
      "alg": "RS256",
      "n": "...base64url...",
      "e": "AQAB"
    },
    {
      "kty": "EC",
      "use": "sig",
      "kid": "def456",
      "alg": "ES256",
      "crv": "P-256",
      "x": "...base64url...",
      "y": "...base64url..."
    }
  ]
}
```

The Attestor reads the file once at construction and holds it for the process lifetime. Operators rotate the JWKS by writing a new file and restarting the control plane.

Validation at construction:

- File parses as JSON.
- `keys` is a non-empty array.
- Each entry has `kid`, `kty`, and the public-key bytes required by its `kty`.
- Each entry's `alg` (if present) is on the operator-configured allow-list.

Validation failure at construction is a fatal startup error. At verify-time, file rot is not detected — operators are responsible for rotating-then-restarting.

The static-file path skips both the discovery-doc check AND the live JWKS fetch. The operator-configured `--attestor-oidc-issuer` is still used for the §3 step 7 `iss`-claim check.

### 4.4 Exactly one source

The CLI surface (§10) enforces that exactly one of `--attestor-oidc-jwks-uri` or `--attestor-oidc-jwks-file` may be set when `--attestor oidc` is selected, with absence of both meaning "use Discovery". Setting both is a fatal startup error. The constructor signature in the crate reflects this — there is no `Both` variant.

---

## 5. JWKS cache + bounded staleness

This section resolves [RFC 0016 §9.2](../rfcs/0016-attestor-interface.md#92-trust-bundle--jwks-refresh-cadence) for the OIDC Attestor.

### 5.1 TTL refresh policy

The Attestor MUST maintain a `last_refresh_at: Timestamp` value, updated on every successful JWKS fetch. The TTL refresh policy:

- **Within TTL:** serve verification from the cached JWKS.
- **Past TTL but within `max_staleness_window`:** kick off a background refresh; continue serving from the cached JWKS until the refresh completes.
- **Past `max_staleness_window`:** every subsequent `verify()` call returns `TrustRootUnavailable("JWKS stale: last refresh was N seconds ago; max staleness window is M seconds")` until a fresh JWKS arrives.

The default TTL is 1 hour. The default `max_staleness_window` is 24 hours. Operators MAY override via `--attestor-oidc-cache-ttl-secs` and `--attestor-oidc-max-staleness-secs`.

For the static-file source, `last_refresh_at` is set at construction and never updated; `max_staleness_window` defaults to `Duration::MAX` (no staleness check). Operators using the static-file path who want a hard expiry MAY set `--attestor-oidc-max-staleness-secs` to a finite value.

The Attestor does NOT consult HTTP `Cache-Control` / `Expires` headers from the JWKS response. The operator-configured TTL is authoritative — rationale: IdPs vary wildly in their cache-header hygiene; pinning a substrate-side TTL makes the substrate's behavior predictable across IdPs.

### 5.2 Kid-miss refresh

When a verify call encounters a `kid` not in the cached JWKS, the Attestor MUST attempt a single out-of-band JWKS refetch and retry the lookup once:

- The refetch is **deduplicated** per Attestor instance — concurrent verify calls that miss on the same kid (or any kid) MUST share a single in-flight refetch, not spawn N parallel HTTP requests against the IdP. A `tokio::sync::Mutex`-guarded "refresh-in-progress" flag is sufficient; `Notify` or `Watch` variants also work.
- If the refetch returns the kid, the verify call proceeds normally.
- If the refetch returns a JWKS that still lacks the kid, the verify call rejects with `Rejected("kid not found in JWKS")`.
- If the refetch fails (network error, non-200, malformed JSON), the verify call returns `TrustRootUnavailable("JWKS refresh failed: <reason>")`. The cache is NOT invalidated — subsequent calls continue serving from the still-cached JWKS until the next TTL boundary triggers another refresh.

For the static-file source, kid-miss refresh is a no-op — there is no remote source to refresh from. A missing kid is `Rejected("kid not found in JWKS")` immediately.

Rationale: JWKS rotation is normal IdP behavior. A naive cache that only refreshes on TTL expiry would reject every legitimate token signed with a freshly-rotated key for up to one TTL. Kid-miss refresh keeps p99 latency reasonable across rotations without flooding the IdP under attack scenarios (because of deduplication).

### 5.3 JWKS size cap

The Attestor MUST cap the total JWKS payload size at 64 KiB at fetch time. Larger payloads are treated as a fetch failure (`TrustRootUnavailable("JWKS payload exceeds 64 KiB cap")`). The cap prevents a misconfigured or malicious JWKS endpoint from blowing the substrate's memory or attestation latency.

64 KiB allows comfortable headroom for normal JWKS sizes (typically 1–4 KiB for one-to-three RSA-2048 keys). IdPs hitting this cap have either a runaway key-rotation bug or are trying to be a vector — both warrant a substrate refusal.

---

## 6. Issuer + audience binding

The operator MUST configure both `expected_issuer` (`--attestor-oidc-issuer`) and `expected_audience` (`--attestor-oidc-audience`) at startup. The Attestor MUST reject any ID token whose `iss` claim does not exactly equal `expected_issuer`, OR whose `aud` claim does not contain `expected_audience`.

### 6.1 Choosing values

- **`expected_issuer`** is the IdP's issuer URL — the exact value the IdP places in the `iss` claim. For Auth0: `https://<tenant>.auth0.com/`. For Okta: `https://<org>.okta.com`. For Google: `https://accounts.google.com`. For Keycloak: `https://<host>/realms/<realm>`. For Azure AD: `https://login.microsoftonline.com/<tenant-id>/v2.0`. Trailing slashes matter — copy from the IdP's discovery doc, do not normalize.
- **`expected_audience`** is the IdP-side identifier registered for the Yutha control plane. Concrete guidance mirrors [attestor-spiffe §6.1](./attestor-spiffe.md#61-choosing-an-audience-value): production should be `yutha-<swarm-name>-<env>` shape (e.g., `yutha-orders-prod`), unique per (swarm, environment). Generic values like `yutha-prod` invite cross-system replay if the same IdP serves other Yutha-shaped consumers.

### 6.2 Why both bindings are required

The issuer check ensures the token was minted by an IdP we trust. The audience check ensures the token was minted *for us*. Without audience, a token that principal P obtained for some unrelated audience X (also minted by the same IdP) could be replayed against the Yutha control plane. Audience binding is the ID token's "you, specifically" claim; the Attestor MUST enforce it.

### 6.3 Discovery-doc `issuer` exact-match (Discovery mode only)

When the Attestor is in Discovery mode (§4.1), the discovery-doc response MUST contain an `issuer` field that EXACTLY equals `expected_issuer` per [RFC 8414 §3.3](https://datatracker.ietf.org/doc/html/rfc8414#section-3.3). On mismatch the Attestor MUST refuse to start (fatal at construction, not at verify-time).

This is a load-bearing check: it prevents an attacker who controls DNS for the `<issuer>/.well-known/...` path from serving a malicious discovery doc that points the Attestor at an attacker-controlled JWKS endpoint. The `issuer` field in the discovery doc is the IdP's self-declaration; it MUST match the operator's expectation.

The check does NOT apply in JWKS-URI-override or static-file modes (there's no discovery doc to check), but the §3 step 7 `iss`-claim check still applies to every ID token in all three modes.

### 6.4 HTTPS requirement

In Discovery mode and JWKS-URI-override mode, the issuer URL and JWKS URI MUST use HTTPS. The Attestor MUST reject HTTP URLs at construction.

The escape hatch: `--attestor-oidc-allow-insecure-http`. This flag exists for the F7 in-process mock-OIDC test server and for local Keycloak/dex setups during development. The flag emits a startup warning log; operators running production with this flag set are violating the OpenID Connect spec (Core §2: "Communication ... MUST utilize TLS"). The flag is documented as test-only in the operator runbook.

---

## 7. iss/sub → external_identity mapping

`AttestedIdentity.external_identity` MUST equal `format!("oidc:{}:{}", iss, sub)`, where `iss` is the validated `iss` claim and `sub` is the validated `sub` claim, both verbatim from the ID token.

The `agent.register` receipt's `attested_external_identity` evidence key will then carry strings like:

```
oidc:https://accounts.google.com:114857192384756192834
oidc:https://example.okta.com:00uId4nfFnZHmqCBp4x7
oidc:https://login.example.com:user@example.com
oidc:https://my-keycloak/realms/yutha:bot-12345
```

Auditors querying the receipt log for "all agents attested under a specific issuer" can substring-match on `oidc:<issuer>:`; for a specific principal, on `:<sub>`.

### 7.1 Why the `oidc:` prefix + issuer

The OIDC spec guarantees `sub` is unique only within an issuer (Core §2: "the Subject Identifier ... MUST be locally unique and never reassigned within the Issuer"). Two principals at two different IdPs can have the same `sub`. The receipt evidence column is global across all attestors, so identifiers MUST be globally unique:

- The `oidc:` prefix distinguishes OIDC attestations from native (`yutha:native:<hex>`) and SPIFFE (`spiffe://<trust-domain>/...`) ones, matching the [attestor-spiffe §7.1](./attestor-spiffe.md#71-why-not-strip-the-scheme) disambiguator pattern.
- The `<iss>:` component makes the identifier globally unique by namespacing on the issuer URL.
- The `<sub>` is verbatim — no normalization, no truncation, no URI encoding.

A future enhancement that hashes `<iss>:<sub>` for fixed-length identifiers is deferable to RFC time when it's needed; for now, the readable form is more useful for operator debugging and audit.

---

## 8. Claims → attributes projection

If the operator configures `--attestor-oidc-project-claims <claim1>,<claim2>,...`, the Attestor MUST project the listed claims from the ID token payload into `AttestedIdentity.attributes`. The receipt evidence then carries `attributes.<claim-name>: <value>` keys per RFC 0016 §3.4.

Default: empty list — no claims projected. Operators opt in to projection.

Example: configuring `--attestor-oidc-project-claims groups,email,department` against a token whose payload includes `"groups": ["admin", "auditor"], "email": "ops@example.com", "department": "platform"` results in `agent.register` receipt evidence:

```
attributes.groups: admin,auditor
attributes.email: ops@example.com
attributes.department: platform
```

### 8.1 Value handling

The Attestor MUST handle the following value shapes:

- **String values:** projected verbatim as `attributes.<key>: <string>`.
- **Array-of-string values:** joined with `,` (comma, no surrounding whitespace) into a single string. Empty arrays project as `attributes.<key>: <empty-string>`.
- **Numeric / boolean / null / object / mixed-array values:** the entire claim is skipped (not projected) with a `tracing::warn!` log naming the claim. The verification still succeeds.

The "comma-joined for arrays" choice is operationally common (matches how SAML, Keycloak's `roles` claim, and most IdPs ship multi-valued attributes in places that expect strings). The "skip non-string-shaped" rule matches the SPIFFE Attestor's selector handling — receipt evidence's `attributes.<key>: <value>` is `string → string`, and converting numbers/bools risks lossy formatting.

### 8.2 Size caps

The Attestor MUST cap the total claims-to-attributes projection at:

- **64 entries** across all projected claims (counting each entry from a key's array value as one entry's worth of bytes, but the total entry count is bounded by the number of allowlisted claim *names*).
- **4 KiB** total bytes of `key + value` for the projected set.

Beyond either cap, the projection truncates with a warning log naming the dropped claims. Rationale matches [attestor-spiffe §8.1](./attestor-spiffe.md#81-constraints): receipt evidence is canonical-encoded into receipt bytes; an unbounded claims projection can balloon individual receipts.

### 8.3 Non-allowlisted claims

The Attestor MUST NOT project any claim not on the operator-configured allow-list. In particular: `iss`, `sub`, `aud`, `iat`, `exp`, `nbf`, `nonce`, `azp`, `auth_time`, `acr`, `amr`, `jti`, and IdP-specific extension claims (`https://example.com/roles`, etc.) are all ignored unless explicitly allowlisted.

Rationale: canonicality. The audit log's `attributes.<key>` keys must come from operator-declared sources; loose projection of "everything in the JWT" makes the evidence schema unpredictable across IdPs and across token issuance. Operators wanting custom claims declare them explicitly.

---

## 9. Error mapping

The mapping from internal verification failures to `AttestorError` variants. Every failure mode the Attestor surfaces MUST land on exactly one row in this table.

| Failure | `AttestorError` variant | Message shape |
|---|---|---|
| Empty `credential` | `Rejected` | `"empty credential; OIDC Attestor requires an ID token"` |
| JWS compact-serialisation parse failure | `Malformed` | `"not a JWS compact serialization"` |
| Header missing `kid` | `Malformed` | `"header: missing kid"` |
| Header `alg = none` | `Malformed` | `"header: alg none is not permitted"` |
| Header `alg` is HS* family | `Malformed` | `"header: HMAC algorithms not permitted for OIDC"` |
| Header `alg` not on operator allow-list | `Malformed` | `"header: unsupported alg"` |
| Header `typ` present and not `JWT` or `JOSE` | `Malformed` | `"header: unsupported typ"` |
| JWKS source unavailable at construction | (fatal; control plane refuses to start) | n/a |
| JWKS stale past `max_staleness_window` | `TrustRootUnavailable` | `"JWKS stale: last refresh was N seconds ago; max staleness window is M seconds"` |
| JWKS refresh on kid-miss failed | `TrustRootUnavailable` | `"JWKS refresh failed: <reason>"` |
| JWKS payload exceeds 64 KiB cap | `TrustRootUnavailable` | `"JWKS payload exceeds 64 KiB cap"` |
| `kid` not found in JWKS after refresh | `Rejected` | `"kid not found in JWKS"` |
| JWS signature verification failure | `Rejected` | `"signature verification failed"` |
| Payload not JSON | `Malformed` | `"payload not JSON"` |
| Missing `iss` claim | `Malformed` | `"payload: missing iss"` |
| `iss` not a string | `Malformed` | `"payload: iss not a string"` |
| `iss` does not equal `expected_issuer` | `Rejected` | `"issuer mismatch"` |
| Missing `sub` claim | `Malformed` | `"payload: missing sub"` |
| `sub` not a non-empty string | `Malformed` | `"payload: sub empty or not a string"` |
| Missing `aud` claim | `Malformed` | `"payload: missing aud"` |
| `aud` does not contain `expected_audience` | `Rejected` | `"audience mismatch"` |
| Missing `exp` claim | `Malformed` | `"payload: missing/invalid exp"` |
| `exp` not an integer | `Malformed` | `"payload: missing/invalid exp"` |
| `exp ≤ now()` | `Rejected` | `"credential expired"` |
| Missing `iat` claim | `Malformed` | `"payload: missing/invalid iat"` |
| `iat` not an integer | `Malformed` | `"payload: missing/invalid iat"` |
| `iat > now() + clock_skew_tolerance` | `Rejected` | `"iat in the future"` |
| `nbf > now() + clock_skew_tolerance` | `Rejected` | `"nbf in the future"` |
| Implementation bug / unreachable | `Internal` | `"unexpected: <short tag>"` |

### 9.1 PII rule restated

No error message MAY contain:

- Any byte of the original `credential` argument.
- The decoded payload, in whole or in part — no `iss` URL, no `sub`, no `aud`, no custom claims, no allowlisted-claim values.
- The decoded header beyond the algorithm name (the algorithm being part of the `unsupported alg` message is permitted because it's a low-entropy enum value, not a subject identifier).

The audit log captures `attested_external_identity` only on *successful* attestations (the `agent.register` receipt). Failed attestations land in `agent.register.deny` receipts whose evidence is `claimed_agent_id` + `attestor_id` + `deny_reason` — and `deny_reason` comes from the error-message table above, which carries no claim contents.

This is a SOC2/HIPAA-defensible posture: an operator investigating a failed registration sees enough to debug (which check failed) but not enough to derive identifying information about the would-be principal.

---

## 10. CLI flag surface

The control-plane binary (`yutha-control-plane`) is the only consumer of the Attestor today. The Phase F flag additions:

```bash
# Discovery mode (default)
yutha-control-plane \
    --attestor oidc \
    --attestor-oidc-issuer https://login.example.com \
    --attestor-oidc-audience yutha-orders-prod \
    [--attestor-oidc-project-claims groups,email,roles] \
    [--attestor-oidc-allowed-algs RS256,ES256,EdDSA] \
    [--attestor-oidc-cache-ttl-secs 3600] \
    [--attestor-oidc-max-staleness-secs 86400] \
    [--attestor-oidc-clock-skew-secs 60] \
    [--attestor-oidc-connect-timeout-secs 10]
```

```bash
# JWKS URI override mode
yutha-control-plane \
    --attestor oidc \
    --attestor-oidc-issuer https://login.example.com \
    --attestor-oidc-jwks-uri https://login.example.com/custom-jwks \
    --attestor-oidc-audience yutha-orders-prod \
    [other flags as above]
```

```bash
# Static file mode
yutha-control-plane \
    --attestor oidc \
    --attestor-oidc-issuer https://login.example.com \
    --attestor-oidc-jwks-file /etc/yutha/oidc-jwks.json \
    --attestor-oidc-audience yutha-orders-prod \
    [other flags as above; cache-ttl is no-op]
```

Validation at startup:

- `--attestor-oidc-issuer` is REQUIRED when `--attestor oidc`. Must be HTTPS unless `--attestor-oidc-allow-insecure-http` is set. Empty string is fatal.
- `--attestor-oidc-audience` is REQUIRED. Empty string is fatal.
- At most one of `--attestor-oidc-jwks-uri` or `--attestor-oidc-jwks-file` may be set. Both → fatal. Neither → Discovery mode.
- `--attestor-oidc-project-claims` is a comma-separated list; default empty (no projection).
- `--attestor-oidc-allowed-algs` is a comma-separated list; default `RS256,RS384,RS512,ES256,ES384,EdDSA`. `none` and HS* are silently filtered (operator config cannot enable them; an explicit attempt fatals at startup).
- `--attestor-oidc-cache-ttl-secs` defaults to `3600` (1 hour). Must be ≥ 60.
- `--attestor-oidc-max-staleness-secs` defaults to `86400` (24 h) for Discovery / JWKS-URI; defaults to `0` (no check) for static-file. Explicit `0` selects "hard fail on TTL expiry".
- `--attestor-oidc-clock-skew-secs` defaults to `60`. Must be non-negative.
- `--attestor-oidc-connect-timeout-secs` defaults to `10` (Discovery + JWKS-URI modes; ignored for static).
- `--attestor-oidc-allow-insecure-http` is a bool flag, default false. Emits a warning when set.

All flags accept their corresponding `YUTHA_ATTESTOR_OIDC_*` env vars (clap `env=` attribute), matching the convention from the [Signer backends](../rfcs/0017-external-signer-backends.md) and the SPIFFE Attestor flags.

### 10.1 Selecting `oidc` without the required flags

If an operator runs `--attestor oidc` without `--attestor-oidc-issuer` or `--attestor-oidc-audience`, or with both source-override flags set simultaneously, the control plane MUST exit at startup with a clear message naming the missing/conflicting flags. Same posture as the Phase D scaffold's `--attestor oidc` placeholder.

---

## 11. Conformance vectors

Per RFC 0016 §3.8 the OIDC vectors land in Phase F. Directory layout under `/spec/vectors/attestor/oidc/`:

```
accept-rs256/           # 3 cases: happy path, RS256-signed ID tokens
accept-es256/           # 3 cases: happy path, ES256-signed ID tokens
accept-eddsa/           # 2 cases: happy path, EdDSA-signed ID tokens
accept-projected-claims/  # 2 cases: groups/email projection
reject-issuer/          # 2 cases: iss mismatch
reject-audience/        # 2 cases: aud mismatch (string + array forms)
reject-expired/         # 2 cases: exp in the past
reject-signature/       # 2 cases: bit-flipped signature
reject-kid-unknown/     # 1 case: header kid not in JWKS
reject-alg-none/        # 1 case: header alg = none
reject-alg-hmac/        # 1 case: header alg = HS256
reject-malformed/       # 2 cases: garbled JWS, missing kid
reject-not-yet-valid/   # 1 case: nbf > now + skew
reject-empty/           # 1 case: credential = []
```

Each case file is a JSON document of the shape:

```json
{
  "description": "human-readable summary",
  "context": {
    "swarm_id_hex": "...",
    "claimed_agent_id_hex": "...",
    "agent_public_key": { "algorithm": "ed25519", "value_b64": "..." }
  },
  "attestor_config": {
    "jwks": { "...": "JWKS object served as if from jwks_uri" },
    "expected_issuer": "https://login.example.com",
    "expected_audience": "yutha-test",
    "allowed_algs": ["RS256", "ES256", "EdDSA"],
    "project_claims": ["groups", "email"],
    "clock_skew_secs": 60
  },
  "credential_b64": "...",
  "expected_result": {
    "kind": "ok" | "err",
    "external_identity": "oidc:https://login.example.com:user@example.com",  // present iff kind=ok
    "credential_expires_at_unix_secs": 1234567,                              // present iff kind=ok
    "attributes": { "groups": "admin,auditor", "email": "ops@example.com" }, // present iff kind=ok
    "error_variant": "Malformed" | "Rejected" | "TrustRootUnavailable" | "Internal",  // present iff kind=err
    "error_message_substring": "audience mismatch"                            // present iff kind=err; substring-match on AttestorError display
  }
}
```

The vectors test (`crates/yutha-attestor-oidc/tests/vectors.rs`) iterates every JSON file, constructs an `OidcAttestor` in **static-file mode** seeded with the vector's `jwks` (this avoids any live HTTP dep in the vectors path), calls `verify(context, credential)`, and asserts the result matches `expected_result`.

The cases MUST be regenerable from a documented seed; the vectors directory ships a `regen.rs` (Rust `#[test] #[ignore]`) that takes a `REGEN_SEED` env var and produces every fixture deterministically (keypairs derived; clock-dependent claims use a fixed `PSEUDO_NOW`). Same pattern as Phase E. Time-relative claims follow [the time-relative-fixtures rule](../../crates/yutha-attestor-spiffe/tests/regen_vectors.rs) (happy-path pins `exp` far-future, omits `iat`/`nbf` unless testing them; "expired" hardcodes an early-2000s Unix time).

### 11.1 In-process mock OIDC server (for the integration test, NOT for vectors)

Beyond the JSON vectors, the Phase F crate ships a small in-process mock OIDC server (axum-based, ~200 LOC) used by `tests/integration.rs`. The mock contract is:

- Serves `/.well-known/openid-configuration` returning a minimal valid discovery doc whose `issuer` matches the operator-configured value and whose `jwks_uri` is the mock's own `/jwks` path.
- Serves `/jwks` returning a JWKS with a known signing keypair.
- Exposes a Rust test helper `mock.mint_token(claims: serde_json::Value) -> String` that produces a signed ID token using the mock's keypair.

This integration test runs IN CI (no `#[ignore]`) — it exercises the Discovery + JWKS-URI-override paths end-to-end against a real HTTP server in the same test process. The static-file path is covered by the JSON vectors.

A separate `#[ignore]`-gated `docker-keycloak` test path is described in the operator runbook (Phase F9) for operators who want real-IdP fidelity. Not part of CI.

---

## 12. Threat-model impact

This Attestor implements [RFC 0016 §6](../rfcs/0016-attestor-interface.md#6-threat-model-impact)'s A1 / A6 / A8 mitigations against [the threat model](../../docs/internal/threat-model.md):

### 12.1 A1 — hostile agent participant

**Mitigation.** An OIDC-Attestor-configured control plane refuses to admit any agent that cannot present an ID token for the configured (issuer, audience) pair. An attacker who steals the swarm's bootstrap seed (RFC 0007's standalone scenario) still cannot register an arbitrary agent — they additionally need an IdP-issued ID token, which the IdP issues only to authenticated principals.

**Residual.** An attacker who compromises a principal that the IdP has already authenticated (e.g., RCE into a service that holds a long-lived ID token, or OAuth-flow phishing) inherits its identity and can register a malicious agent under that principal's name. This is the irreducible "if the principal is compromised, its identity is compromised" property of any attestation system — the IdP's job is to bound which principals can be impersonated; the substrate cannot strengthen this beyond what the IdP provides.

### 12.2 A6 — Sybil attacker

**Mitigation.** With OIDC attestation enforced, Sybil cost rises from "generate an Ed25519 keypair" to "convince the IdP to authenticate a new principal and mint an ID token with the right audience". Self-service IdPs (e.g., a public Google sign-in) lower this cost; corporate IdPs (Okta, Azure AD with conditional access) raise it substantially.

**Residual.** A self-service IdP that grants ID tokens to any new account (e.g., Google OAuth, GitHub OAuth) gives an internal attacker many sources of valid tokens. The audience-binding (§6) helps — the attacker also needs an ID token specifically minted for the Yutha audience — but the right substrate posture in those cases is "use a corporate IdP for the Attestor" rather than "the Attestor will catch sloppy IdP config".

### 12.3 A8 — malicious operator

**Mitigation, marginal.** A malicious operator who controls the Attestor's configuration can still admit whoever they want — by swapping `--attestor oidc` for `--attestor native`, or by configuring an IdP they control. What this Attestor adds is *audit-side*: the `agent.register` receipts record `attestor_id = "oidc"` and `attested_external_identity = oidc:<issuer>:<sub>`. A post-hoc audit can detect that the operator swapped attestors (the `attestor_id` field changes), or that registrations came from an unexpected issuer (the `oidc:<issuer>:` prefix is auditable).

### 12.4 New attack surfaces

- **The IdP itself.** The substrate's trust is now transitively dependent on the IdP. A compromised IdP issuing arbitrary ID tokens grants arbitrary attestation. Operators MUST follow the IdP's own deployment guidance; this is outside Yutha's substrate scope.
- **ID-token replay.** OIDC ID tokens have lifetimes (typically 5 minutes – 1 hour). A captured ID token within its lifetime can be replayed by anyone with network access to the admission RPC. The lifecycle of the resulting Yutha passport is independent — once registered, the agent's authority depends on its own bearer tokens, not the ID token. This is consistent with RFC 0016 §5.3 (no per-call re-attestation in v1).
- **DNS/MITM against discovery.** In Discovery mode, an attacker who controls DNS for the issuer's `/.well-known/openid-configuration` path can serve a forged discovery doc pointing the Attestor at an attacker-controlled JWKS endpoint. The §6.3 `issuer`-field exact-match check is the substrate's defense — a forged doc whose `issuer` claim doesn't match the operator's `--attestor-oidc-issuer` config is rejected at construction. HTTPS validation (cert pinning at the OS or organization level) is the operator's complementary defense.
- **JWKS-endpoint compromise.** An attacker who compromises just the JWKS endpoint (but not the IdP's signing keys) can serve forged public keys, allowing them to forge ID tokens that the Attestor accepts as valid. Mitigations: TLS to the JWKS endpoint, IdP-side JWKS-publishing-side hardening, and (if available at the IdP) public-key-pinning out of band. The substrate cannot detect this kind of compromise; it relies on the IdP's operational posture.

---

## 13. Open items

### 13.1 Userinfo endpoint enrichment

The OIDC userinfo endpoint (`<issuer>/userinfo` typically) can return additional claims about the principal that aren't in the ID token. A future enhancement could:

- Optionally fetch userinfo at attest-time using the ID token as a bearer.
- Merge userinfo claims into the projected `attributes`.
- Cache userinfo response per principal with its own TTL.

Not in v1. Reasons: (a) userinfo is per-principal and per-call, blowing up admission latency; (b) it's an additional network dep for the substrate; (c) the same data is often available as an `id_token`-claim if the IdP is configured well. Deferred until an operator surfaces a specific need.

### 13.2 Per-issuer `attestor_id`

The receipt evidence's `attestor_id = "oidc"` is constant across all OIDC-attested registrations. Operators running multi-tenant deployments with multiple OIDC issuers (rare in v1, since the Attestor is single-issuer per control plane, but plausible for the future multi-tenant work) might want `attestor_id = "oidc:<issuer-short-name>"` for sub-Attestor granularity. The current `Attestor::id() -> &str` trait returns a static string; adding a per-call dynamic id would be a trait change. Deferred to a future RFC if needed. Parallels [attestor-spiffe §13.3](./attestor-spiffe.md#133-per-attestor-audit-log-filtering).

### 13.3 Loose-`kid` mode

§2.1.1 documents why the Attestor requires `kid` in the token header even for single-key JWKS. If a future operator surfaces an IdP that genuinely cannot issue `kid`-bearing tokens, a `--attestor-oidc-allow-missing-kid` escape hatch could be added (only valid when the JWKS has exactly one entry; rejects with a clear error when the JWKS grows past one key). Deferred until concrete demand surfaces.

### 13.4 Multi-issuer mode

The Attestor accepts ID tokens from exactly one issuer (`--attestor-oidc-issuer`). Operators wanting to federate across multiple IdPs (e.g., accept both Google-issued and corporate-Okta-issued tokens) would need either: (a) one Attestor per issuer composed by an outer dispatcher, or (b) a multi-issuer Attestor variant. Today's substrate supports neither — the control plane has a single `Arc<dyn Attestor>`. The multi-attestor dispatcher is a substrate-level enhancement, not OIDC-specific; deferred to a future RFC.

### 13.5 Token-exchange / refresh

OAuth 2.0 / OIDC define token-exchange (RFC 8693) and refresh tokens for long-running clients. Yutha does not consume either — agents present a single ID token at admission and the resulting passport carries its own lifecycle. The future lifecycle work (RFC 0016 §5.2-deferred) is where token-refresh integration would land if needed. Not part of v1.

---

## 14. References

- [RFC 0016 — Attestor interface](../rfcs/0016-attestor-interface.md) — the umbrella RFC this spec extends
- [attestor-spiffe spec](./attestor-spiffe.md) — sibling Attestor; structural template
- [identity-keys README](./README.md) — shared framing memo for Signer + Attestor
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) — the standard this Attestor implements
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) — the discovery-doc protocol Discovery mode uses
- [RFC 8414 — OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414) — discovery-doc `issuer` exact-match requirement
- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519) — JWT format
- [RFC 7517 — JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517) — JWKS format
- [RFC 7518 — JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518) — `alg` enumeration
- [`jwks` crate](https://crates.io/crates/jwks) — the Rust crate the reference impl uses for JWKS parse + discovery
- [`jsonwebtoken` crate](https://crates.io/crates/jsonwebtoken) — the Rust crate the reference impl uses for JWT verify
- [Threat model](../../docs/internal/threat-model.md) — A1, A6, A8 are the load-bearing adversaries

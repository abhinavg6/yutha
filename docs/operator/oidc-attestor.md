# Verifying agents against OpenID Connect (OIDC)

A 30-minute walkthrough for the operator who wants to bind Yutha
agent registrations to an existing OpenID Connect identity provider
(Auth0, Okta, Azure AD, Keycloak, Google Workspace, dex, or similar).
By the end you'll have:

- The control plane configured with `--attestor oidc`, pointed at the
  IdP's issuer URL via OIDC Discovery (the default), an explicit
  `jwks_uri` override, or a static JWKS file (air-gapped).
- Every successful agent registration recording the calling
  principal's `oidc:<iss>:<sub>` external identity + any operator-
  allowlisted ID-token claims as receipt evidence — auditors can
  chain Yutha `agent_id`s back to IdP-authenticated principals.
- A clear deny path: any registration without a valid ID token (or
  with the wrong issuer, audience, signature, or expired credential)
  hits `PERMISSION_DENIED` at the gRPC layer plus an
  `agent.register.deny` receipt with operator-actionable evidence.

**What you get for free.** RFC 0016's `Attestor` trait is consulted
on every registration regardless of which flavour the operator
selected. Swapping `--attestor native` for `--attestor oidc` changes
the verification step; everything downstream of registration
(bearer-token auth, capability checks, constitution evaluation,
receipt anchoring) is unchanged.

**What you write.** A Yutha-specific OIDC application registration in
your IdP (the source of the `audience` value the Attestor will pin to),
plus the `--attestor-oidc-*` CLI flags that pin issuer + audience +
optional claim projection.

If you haven't operated a Yutha swarm before, read the
[operator quickstart](quickstart.md) first — it covers the bootstrap
seed model and the gRPC server flags this doc assumes you're
comfortable with.

This walkthrough implements the OIDC Attestor pinned by
[RFC 0016 §3.6](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0016-attestor-interface.md#36-reference-impl-sketch--oidc-phase-f)
and detailed in
[`/spec/identity-keys/attestor-oidc.md`](https://github.com/abhinavg6/yutha/blob/main/spec/identity-keys/attestor-oidc.md).

---

## Prerequisites

- An OpenID Connect IdP you control, with the ability to register a
  new application and obtain ID tokens for it. Any of these work:
  - **Auth0** — Applications → Create Application → Machine to Machine
  - **Okta** — Applications → Create App Integration → API Services
  - **Azure AD / Entra ID** — App Registrations → New
  - **Keycloak** — Clients → Create
  - **Google Workspace** — Cloud Console → APIs & Services → Credentials
  - **dex** (or any OIDC-spec-compliant IdP)
- A Yutha control-plane binary built with default features
  (`yutha-attestor-oidc` is wired in unconditionally; no compile-time
  gate).
- About 5–50 ms of additional admission latency budget per `Register`
  RPC for the OIDC verify path. Offline JWS verification is CPU-bound;
  the JWKS cache fronts the per-call latency in steady state. First-
  registration latency adds the discovery + JWKS fetch (one-time at
  Attestor warm-up); kid-rotation cases add one extra fetch.
- Agent runtime that can obtain an ID token from your IdP. Typically
  the agent runs alongside or inside a workload that already
  authenticates to the IdP (workload identity, service account
  credential, OAuth2 client credentials flow, etc.); the agent picks
  up the token from the workload's identity machinery and presents
  it to Yutha. See [§7](#7-wire-the-client-side) for the SDK call shape.

You do **not** need any IdP-side capability beyond standard OIDC
ID-token issuance + JWKS publication. Yutha never calls the userinfo
endpoint, never starts an OAuth flow, never holds an IdP client
secret. It's purely a verifying relying party.

---

## 1. Decide: Discovery, JWKS-URI override, or static file?

The OIDC Attestor reads its JWKS from exactly one of three sources.
Pick before configuring.

| | OIDC Discovery (default) | JWKS-URI override | Static JWKS file |
|---|---|---|---|
| **CLI flags** | (just `--attestor-oidc-issuer <url>`) | `--attestor-oidc-jwks-uri <url>` | `--attestor-oidc-jwks-file <path>` |
| **Discovery doc fetched at startup** | Yes — validates `issuer` field exact-matches operator config (spec §6.3) | No | No |
| **Live JWKS fetch** | Yes — from discovery doc's `jwks_uri` | Yes — direct | No |
| **Kid-miss async refresh** | Yes (deduplicated; spec §5.2) | Yes | No (kid-miss → immediate reject) |
| **TTL refresh** | Yes (default 1 h) | Yes | n/a |
| **Network dependency on IdP at runtime** | Yes | Yes | No |
| **Rotation** | Automatic (kid-miss-triggered refresh) | Automatic | Operator replaces file + restarts |
| **Best for** | Standard production deployments — most IdPs | IdPs with broken/missing discovery docs | Air-gapped, edge, dev environments |

**Discovery is the recommended default.** It self-heals across IdP
infrastructure changes that move the JWKS endpoint within the same
issuer. The `issuer` exact-match check at construction is a load-
bearing security control — without it, an attacker who controls DNS
for the issuer's `/.well-known/...` could serve a forged discovery
doc pointing at an attacker-controlled JWKS endpoint.

**Use the JWKS-URI override sparingly.** Reserved for IdPs whose
discovery doc is misconfigured, missing, or hidden behind an
authenticated endpoint. The override skips the discovery-doc
`issuer` integrity check; only the per-ID-token `iss` claim check
remains.

**Static-file mode** is appropriate for air-gapped deployments where
the control plane cannot reach the IdP at all, or for "rotate by
deliberate file-replace + restart" deployments preferring a more
controlled rotation cadence. Trade-off: no automatic kid-rotation
recovery — a freshly-issued token signed by a rotated key will reject
with `Rejected("kid not found in JWKS")` until you update the file
and restart.

---

## 2. Pick an audience value

The `aud` claim is the ID token's "you, specifically" assertion —
it MUST match the operator-configured `--attestor-oidc-audience`
exactly. Operators choose a value when they register Yutha as an
application in the IdP.

**Recommended shape**: `yutha-<swarm-name>-<env>`

```
yutha-orders-prod
yutha-payments-staging
yutha-platform-dev
```

Unique per (swarm, environment). Generic values like `yutha-prod`
invite cross-system replay if the same IdP serves other Yutha-shaped
consumers.

**Multi-region**: include region in the audience.

```
yutha-orders-prod-us-east
yutha-orders-prod-eu-west
```

Each region's control plane configures only its region's audience.

**Why audience binding is required even with the issuer check** —
the issuer check ensures the token was minted by an IdP you trust.
The audience check ensures the token was minted *for Yutha*, not for
some other service the same IdP also fronts. Without audience, a
token a principal obtained for an unrelated service (same IdP, same
issuer) could be replayed against Yutha. Audience binding is the
substrate's defense against this; the Attestor MUST enforce it.

---

## 3. Register Yutha in your IdP

The exact path varies per IdP. Some representative recipes:

### Auth0

1. **Applications** → **Create Application** → "Machine to Machine".
2. Authorize it for an **API** whose identifier (audience) is your
   chosen value, e.g. `yutha-orders-prod`.
3. Note the **issuer URL** (your tenant's `https://<tenant>.auth0.com/`
   — trailing slash matters).
4. Workloads obtain ID tokens via the Auth0 client-credentials flow:

   ```bash
   curl -X POST https://<tenant>.auth0.com/oauth/token \
       -H 'content-type: application/json' \
       -d '{"client_id":"...","client_secret":"...","audience":"yutha-orders-prod","grant_type":"client_credentials"}'
   # → { "access_token": "...", "id_token": "..." }
   ```

   (The agent uses the `id_token` field, not `access_token` — see
   spec §1.1 for why.)

### Okta

1. **Applications** → **Create App Integration** → "API Services".
2. **API → Authorization Servers** → choose your auth server →
   **Audiences** → add `yutha-orders-prod`.
3. **Scopes** → grant the application a scope that includes
   `openid`.
4. Note the **issuer URL** — usually
   `https://<org>.okta.com/oauth2/<auth-server-id>`.
5. Same client-credentials flow as Auth0; the response includes an
   `id_token`.

### Keycloak

1. **Clients** → **Create** → Client ID = `yutha-orders-prod`,
   client authentication enabled.
2. **Client Scopes** → assign `openid`.
3. **Authentication** → confirm the realm publishes a JWKS at
   `<host>/realms/<realm>/protocol/openid-connect/certs`.
4. Issuer URL = `https://<host>/realms/<realm>`.

### Azure AD / Entra ID

1. **App Registrations** → **New**.
2. **Expose an API** → add scope; the Application ID URI becomes the
   audience.
3. Use the `v2.0` issuer:
   `https://login.microsoftonline.com/<tenant-id>/v2.0`.

### Google Workspace

1. **Cloud Console** → **APIs & Services** → **Credentials** →
   create an OAuth 2.0 Client ID.
2. The audience is your service-account email or a custom value
   depending on the auth flow.
3. Issuer URL = `https://accounts.google.com`.

In all cases: **copy the issuer URL exactly** as the IdP publishes
it (trailing slashes, scheme casing, port). Don't normalize. The
Attestor compares with byte-exact equality.

---

## 4. Configure the control plane

### Discovery mode (production)

The simplest and recommended path. Add to your control-plane
invocation:

```bash
yutha-control-plane \
    --attestor oidc \
    --attestor-oidc-issuer https://login.example.com \
    --attestor-oidc-audience yutha-orders-prod \
    [other flags ...]
```

At startup the Attestor:

1. GETs `https://login.example.com/.well-known/openid-configuration`.
2. Validates the doc's `issuer` field equals `--attestor-oidc-issuer`
   exactly (spec §6.3 / RFC 8414 §3.3). Mismatch → fatal startup
   error.
3. GETs the discovery doc's `jwks_uri`.
4. Holds the JWKS in cache.

If any step fails, the control plane exits at startup with an
operator-actionable error — before any agent registers.

### JWKS-URI override

For non-standard IdPs:

```bash
yutha-control-plane \
    --attestor oidc \
    --attestor-oidc-issuer https://login.example.com \
    --attestor-oidc-jwks-uri https://login.example.com/custom-jwks \
    --attestor-oidc-audience yutha-orders-prod \
    [other flags ...]
```

The Attestor skips the discovery doc and fetches the JWKS directly
from `--attestor-oidc-jwks-uri`. The per-ID-token `iss` check still
uses `--attestor-oidc-issuer`, but the discovery-doc integrity check
(spec §6.3) is bypassed — use sparingly.

### Static-file mode (air-gapped)

```bash
yutha-control-plane \
    --attestor oidc \
    --attestor-oidc-issuer https://login.example.com \
    --attestor-oidc-jwks-file /etc/yutha/oidc-jwks.json \
    --attestor-oidc-audience yutha-orders-prod \
    [other flags ...]
```

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
    }
  ]
}
```

Fetch the current JWKS from your IdP's `jwks_uri` and save it to disk.
Rotation = write new file + restart the control plane. No live IdP
dependency.

### Mutually exclusive

You may set **at most one** of `--attestor-oidc-jwks-uri` and
`--attestor-oidc-jwks-file`. Setting both fails at startup with a
clear error naming both flags. Setting neither selects Discovery
mode (the default).

`--attestor-oidc-issuer` + `--attestor-oidc-audience` are **required**
when `--attestor oidc`; empty values are fatal.

---

## 5. Tune freshness + skew (optional)

The defaults are operationally sensible — start there. Override only
if you have a specific reason.

| Flag | Default | Spec | When to override |
|---|---|---|---|
| `--attestor-oidc-cache-ttl-secs` | `3600` (1 h) | §5.1 | Shorter for IdPs with very chatty key rotation; minimum 60 (the validator rejects shorter to avoid hammering the IdP). |
| `--attestor-oidc-max-staleness-secs` | discovery / JWKS-URI: `86400` (24 h); static-file: no check | §5.1 | `0` selects "hard fail on TTL expiry" — strict policy for high-assurance deployments where you'd rather reject all admissions than serve from a maybe-stale JWKS during an IdP outage. |
| `--attestor-oidc-clock-skew-secs` | `60` | §3 step 7 | Tighter (e.g., `10`) if you trust NTP precision; looser if you have known clock-drift issues. |
| `--attestor-oidc-connect-timeout-secs` | `10` | n/a | Lower for fail-fast startup posture; higher for slow IdPs. Ignored for static-file. |
| `--attestor-oidc-allowed-algs` | `RS256,RS384,RS512,ES256,ES384,EdDSA` | §2.1 | Narrow if your IdP only uses one alg (defense in depth: an attacker who somehow swapped your JWKS for an HS-shaped one can't downgrade you). `none` and `HS*` are rejected at startup regardless of operator config. |
| `--attestor-oidc-project-claims` | empty | §8 | Comma-separated list of claims to project into receipt evidence as `attributes.<claim>: <value>`. Common: `groups,email,roles,department`. See [§11](#11-security-posture) for the wire-time PII rules — projected claims land in receipts that may flow to audit pipelines. |

Read [`/spec/identity-keys/attestor-oidc.md` §5](https://github.com/abhinavg6/yutha/blob/main/spec/identity-keys/attestor-oidc.md#5-jwks-cache--bounded-staleness)
for the full semantics: TTL refresh fires a background fetch
(deduplicated); kid-miss fires a blocking refresh + retry (also
deduplicated, regression-guarded by the
`kid_rotation_triggers_refresh_and_verify_succeeds` integration
test); past `max_staleness_secs`, every verify call returns
`TrustRootUnavailable`.

---

## 6. Disable HTTPS only for tests

The default rejects HTTP issuer + JWKS URLs at startup. This is
deliberate — OpenID Connect Core §2 mandates TLS, and an HTTP
endpoint exposes you to trivial MITM key substitution.

The escape hatch:

```bash
--attestor-oidc-allow-insecure-http
```

Setting this emits a startup warning. Only use it for:

- The Yutha-internal mock-OIDC integration test
  (`crates/yutha-attestor-oidc/tests/integration.rs`).
- Local development against a Keycloak or dex running on
  `http://localhost`.

**Never set in production.** Operators who run with this flag set
have a known security gap; document it as a deviation in your runbook.

---

## 7. Wire the client side

Agents present ID tokens in `RegisterRequest.external_credential`.
The Python SDK threads this through as a keyword argument:

```python
import yutha

# Obtain an ID token from your IdP. In production this comes from
# the workload's identity machinery (workload identity federation,
# service-account-token-volume mount, OAuth2 client-credentials
# flow, etc.). For demo purposes:
id_token = obtain_id_token_for_audience("yutha-orders-prod")

client = await yutha.YuthaClient.connect(
    server_addr="https://control-plane.example.com:7071",
    agent_id=agent_id,
    swarm_id=swarm_id,
    signer=yutha.crypto.InProcessSigner(signing_key),
    external_credential=id_token.encode(),  # bytes, not str
)
```

If the token verifies:

- The agent's passport gets recorded with `attestor_id = "oidc"` and
  `attested_external_identity = "oidc:<iss>:<sub>"` in the
  `agent.register` receipt evidence.
- Any operator-allowlisted claims appear under
  `attributes.<claim>` keys.

If verification fails:

- `client.connect()` raises `RpcError` with status
  `PERMISSION_DENIED` and a message naming the failing check
  (e.g., `"credential rejected: audience mismatch"`).
- The server emits an `agent.register.deny` receipt whose evidence
  carries the deny reason + the operator-configured `attestor_id`.
  The receipt body MUST NOT include any decoded payload field — see
  [§11](#11-security-posture).

The same `external_credential=` parameter exists on the framework
adapter wrappers (`yutha.langgraph.YuthaAgent.connect`,
`yutha.crewai.YuthaCrewAgent.connect`, etc.). Pass it through; the
agent doesn't parse or verify the token client-side — that's purely
server work.

---

## 8. Verify the wire-up

```bash
# 1. Start the control plane with `--attestor oidc` configured.
yutha-control-plane --attestor oidc \
    --attestor-oidc-issuer https://login.example.com \
    --attestor-oidc-audience yutha-orders-prod \
    [other flags ...]

# 2. Tail the structured logs. You should see:
#    INFO yutha_attestor_oidc::attestor: Attestor warmed, source=Discovery
#    INFO yutha_control_plane: server listening, attestor=oidc

# 3. Run a Python smoke test that registers ONE agent with a real
#    ID token.
python -c "
import asyncio, os, yutha
async def main():
    sk = yutha.crypto.SigningKey.generate()
    cli = await yutha.YuthaClient.connect(
        'https://localhost:7071',
        agent_id=yutha.AgentId.new(),
        swarm_id=yutha.SwarmId.from_seed(os.environ['YUTHA_BOOTSTRAP_SEED']),
        signer=yutha.crypto.InProcessSigner(sk),
        external_credential=os.environb[b'OIDC_ID_TOKEN'],
    )
    print('registered:', await cli.agent_id())
asyncio.run(main())
"

# 4. Query the receipts. The `agent.register` receipt should have:
#    - attestor_id = 'oidc'
#    - attested_external_identity = 'oidc:https://login.example.com:<sub>'
#    - any allowlisted claims under attributes.<key>
yutha-ops receipt-tail | grep -i agent.register
```

If step 3 fails with `PERMISSION_DENIED`, jump to [§9](#9-failure-modes-monitoring).

---

## 9. Failure modes + monitoring

Operator-facing failure modes the OIDC Attestor surfaces, and how to
diagnose:

| Operator-visible symptom | What's wrong | Where to look |
|---|---|---|
| Control plane exits at startup with `"OidcConfig: expected_issuer must not be empty"` | `--attestor oidc` set without `--attestor-oidc-issuer` | CLI flags |
| Startup error: `"discovery-doc issuer field does not exact-match operator-configured expected_issuer"` | Discovery mode + the IdP's discovery doc reports a different `issuer` than your config (trailing slash mismatch, scheme casing, etc.) | Copy the discovery doc's `issuer` field byte-exact: `curl https://login.example.com/.well-known/openid-configuration \| jq -r .issuer` |
| Startup error: `"expected_issuer must be HTTPS unless allow_insecure_http is set"` | Operator config has an `http://` issuer | Use HTTPS, or set `--attestor-oidc-allow-insecure-http` (test only) |
| Registration `PERMISSION_DENIED` with `"issuer mismatch"` | Token's `iss` claim differs from `--attestor-oidc-issuer` | Decode the token at jwt.io and confirm the `iss` claim — operator config and IdP issuer must match exactly |
| Registration `PERMISSION_DENIED` with `"audience mismatch"` | Token's `aud` claim doesn't contain `--attestor-oidc-audience` | Confirm the agent's IdP request asks for the right audience (most IdPs require an explicit `audience` parameter in the token request) |
| Registration `PERMISSION_DENIED` with `"credential expired"` | Token's `exp` claim is in the past | Re-mint the token; check the IdP's default token lifetime |
| Registration `PERMISSION_DENIED` with `"signature verification failed"` | Token signature doesn't verify against the cached JWKS | (a) Verify the JWKS the Attestor cached matches the IdP's current JWKS — `curl <jwks_uri>` and diff. (b) If the IdP recently rotated, wait for kid-miss refresh (~one verify call's latency); if still failing, restart the control plane. (c) If using static-file mode, replace the JWKS file. |
| Registration `PERMISSION_DENIED` with `"kid not found in JWKS"` AND non-static source | Token's `kid` isn't in the cached JWKS AND the kid-miss refresh also didn't find it | The IdP no longer publishes that key — likely a rotated-out, expired-still-cached token. Token-side fix. |
| Registration `PERMISSION_DENIED` with `"kid not found in JWKS"` AND static-file source | Token signed by a rotated key the file doesn't contain | Update the static JWKS file + restart |
| Registration `UNAVAILABLE` with `"JWKS stale"` | Cache is past `max_staleness_secs` and refresh attempts haven't succeeded | IdP is down or unreachable. Check connectivity to the issuer host; verify the `--attestor-oidc-max-staleness-secs` setting matches your incident-tolerance |

Structured-log fields worth alerting on:

- `level=WARN, target=yutha_attestor_oidc::jwks_cache, message="background JWKS refresh failed"` — IdP unreachable mid-session; the cache is still serving stale entries within the staleness window.
- `level=WARN, target=yutha_attestor_oidc::payload, message="OIDC claim projection: claim is not string-or-array-of-string"` — IdP-side claim shape is unexpected (e.g., a numeric `groups` claim). Doesn't fail the verify; review your `--attestor-oidc-project-claims` config.
- `level=WARN, target=yutha_attestor_oidc::attestor, message="--attestor-oidc-allow-insecure-http is set"` — startup warning emitted every time the insecure-HTTP escape hatch is enabled. SHOULD NOT appear in any production log.

---

## 10. Local-developer testing against real Keycloak

Spec §11.1 notes that the OIDC Attestor ships an in-process axum
mock used by the CI integration test (`tests/integration.rs`,
runs without `#[ignore]` on every PR). That covers the wire-up;
operators who want real-IdP fidelity can use Keycloak via docker:

```bash
# 1. Run Keycloak (one-liner; ephemeral data — adjust for persistence).
docker run -p 8080:8080 \
    -e KEYCLOAK_ADMIN=admin \
    -e KEYCLOAK_ADMIN_PASSWORD=admin \
    quay.io/keycloak/keycloak:latest \
    start-dev

# 2. In Keycloak admin UI (http://localhost:8080):
#    - Create a realm "yutha-test"
#    - Create a client "yutha-orders-prod" (client authentication on)
#    - Note the client's secret
#    - Confirm JWKS at:
#      http://localhost:8080/realms/yutha-test/protocol/openid-connect/certs

# 3. Run the control plane against it.
yutha-control-plane \
    --attestor oidc \
    --attestor-oidc-issuer http://localhost:8080/realms/yutha-test \
    --attestor-oidc-audience yutha-orders-prod \
    --attestor-oidc-allow-insecure-http \
    [other flags ...]

# 4. Get an ID token via the client-credentials flow.
TOKEN=$(curl -X POST \
    http://localhost:8080/realms/yutha-test/protocol/openid-connect/token \
    -d "grant_type=client_credentials&client_id=yutha-orders-prod&client_secret=<SECRET>&scope=openid" \
    | jq -r .id_token)

# 5. Use the token in a Python smoke test:
OIDC_ID_TOKEN=$TOKEN python register_smoke_test.py
```

Same recipe works for `dex`. Keep `--attestor-oidc-allow-insecure-http`
out of any non-local invocation.

---

## 11. Security posture

The OIDC Attestor doesn't strengthen the IdP — it depends on it. The
substrate's trust posture under OIDC is:

- **Issuer integrity**: discovery-doc `issuer` exact-match (spec
  §6.3) plus the per-token `iss` claim check prevents an attacker
  with DNS control from pointing the Attestor at a forged JWKS.
- **Audience binding**: `aud` claim check prevents cross-system replay
  of tokens issued for other services by the same IdP.
- **Signature verification**: every token is verified against the
  JWKS at admission time. JWKS rotation is automatic for
  Discovery / JWKS-URI sources.
- **Asymmetric crypto only**: `none` and `HS*` algorithms are
  architecturally rejected — see spec §2.1 for why HMAC breaks the
  OIDC trust model.
- **No PII in errors** (spec §9.1): failed-registration receipt
  evidence contains the deny reason (a low-entropy enum-like string
  per spec §9) but NOT decoded payload fields, claim values, or
  credential bytes. Operators investigating a failure see enough to
  diagnose but not enough to derive identifying information about
  the would-be principal.

Things this Attestor does **not** defend against:

- **A compromised IdP.** If the IdP issues bogus ID tokens, the
  Attestor accepts them (they verify). Operator response: trust your
  IdP's security posture; rotate IdP keys after a known compromise;
  use IdP-side audit logging to detect anomalous token issuance.
- **A self-service IdP admitting arbitrary principals.** A public
  Google sign-in OIDC IdP gives the attacker many sources of valid
  tokens. Use a corporate IdP with explicit principal-provisioning if
  Sybil-resistance matters.
- **JWKS-endpoint compromise without IdP-signing-key compromise.** If
  the attacker can swap the JWKS bytes mid-flight but doesn't have
  the IdP's signing key, they can serve their own pubkeys → forge
  tokens that the Attestor accepts. Mitigations: TLS to the JWKS
  endpoint (Discovery + JWKS-URI modes; the substrate enforces HTTPS
  unless `allow_insecure_http`), IdP-side JWKS-publishing hardening.
- **ID-token replay within token lifetime.** A captured token can be
  replayed by any party with network access to the Yutha admission
  RPC, until the token expires. Mitigation: short IdP-side token
  lifetimes (5–15 minutes is typical).

---

## See also

- [`/spec/identity-keys/attestor-oidc.md`](https://github.com/abhinavg6/yutha/blob/main/spec/identity-keys/attestor-oidc.md) — byte-exact OIDC Attestor verify contract
- [`/spec/rfcs/0016-attestor-interface.md`](https://github.com/abhinavg6/yutha/blob/main/spec/rfcs/0016-attestor-interface.md) — Attestor trait + admission flow
- [`/spec/vectors/attestor/oidc/`](https://github.com/abhinavg6/yutha/blob/main/spec/vectors/attestor/oidc/) — cross-implementation conformance vectors
- [SPIFFE Attestor operator runbook](spiffe-attestor.md) — sibling Phase E reference for SPIRE-shop operators
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) — the standard this Attestor implements
- [Operator quickstart](quickstart.md) — bootstrap-seed model + general server-flag context

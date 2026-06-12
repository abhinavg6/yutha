# SPIFFE Attestor — Specification (v1)

> **RFC:** [0016 — Attestor interface](../rfcs/0016-attestor-interface.md) (the umbrella; §3.5 defers byte-exact details here)
> **Predecessors:** [RFC 0002](../rfcs/0002-passport-v1.md) (passport — the artifact the attested identity is bound into), [identity-keys README](./README.md) (shared framing for Signer + Attestor)
> **Phase:** Phase 3 (enterprise readiness)
> **Status:** Draft, design-frozen
> **Companion crate:** `yutha-attestor-spiffe` (Phase E)
> **External standards:** [SPIFFE](https://github.com/spiffe/spiffe), [SPIFFE JWT-SVID](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md), [RFC 7519 — JWT](https://datatracker.ietf.org/doc/html/rfc7519), [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md)
> **Out of scope:** X.509-SVIDs (deferred — see §13.1); per-tenant SPIRE federation (deferred to multi-tenant work)

## 0. Scope

This document specifies the byte-exact verification contract for the SPIFFE Attestor — Yutha's reference enterprise Attestor that mediates SPIFFE workload identity into Yutha agent passports. It is the detail spec [RFC 0016](../rfcs/0016-attestor-interface.md) defers to; conformant implementations MUST honor everything pinned here.

What this document does NOT specify: the *implementation* of the verifier (a server-side component of the control plane). What it specifies is the contract every conformant implementation honors — same JWT-SVID + same trust bundle in, same `AttestedIdentity` (or same `AttestorError`) out.

The Phase E crate (`yutha-attestor-spiffe`) is the in-tree reference implementation; it builds on `spiffe ^0.11` from [maxlambrecht/rust-spiffe](https://github.com/maxlambrecht/rust-spiffe). Third-party implementations in other languages (Go, Java, …) are equally welcome as long as they pass the §11 conformance vectors.

---

## 1. The SPIFFE Attestor contract

The SPIFFE Attestor is an `Attestor` trait implementation that verifies SPIFFE JWT-SVIDs against a configured trust bundle. The contract is:

1. **Input.** The admission handler passes (a) an `AttestationContext` (swarm_id, claimed_agent_id, agent_public_key) and (b) an opaque credential blob.
2. **Pre-verification.** The credential MUST be parsed as a JWT-SVID per [SPIFFE JWT-SVID v1](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md) §2.
3. **Verification.** The Attestor MUST run every check in §4 in order. Any check failing terminates with the mapped `AttestorError` variant (see §9).
4. **Output on success.** An `AttestedIdentity` with `external_identity` = the SVID's SPIFFE ID, `credential_expires_at` = the SVID's `exp` claim, and `attributes` = the projected workload selectors (see §8).
5. **Output on failure.** An `AttestorError` chosen per §9. The error message MUST NOT contain any credential bytes, any decoded JWT header/payload field other than the algorithm name, or any subject identifier.

The Attestor is server-side only. Clients present a JWT-SVID in `RegisterRequest.external_credential`; the Yutha SDK does not parse or verify it client-side.

### 1.1 Why JWT-SVID, not X.509-SVID

X.509-SVIDs and mTLS are the SPIFFE-native shape for service-to-service identity, but they couple identity to the transport — the SVID is presented during the TLS handshake, not as an application payload. Yutha's admission RPC accepts an opaque `bytes` field; binding the Attestor to mTLS would (a) force a decision on whether and where TLS terminates (load balancer? sidecar? gRPC?), (b) preclude proxy/relay topologies the substrate already supports, and (c) prevent operators from running mixed-credential fleets where some agents present SPIFFE and others present (Phase F) OIDC.

JWT-SVIDs are bearer-token shaped, fit in the existing `external_credential` field, work regardless of where the gRPC connection is terminated, and verify with the same offline algorithm in every language. The §13.1 deferred-X.509 path remains available if a specific deployment needs it; v1 ships JWT only.

---

## 2. JWT-SVID format pinning

The Attestor accepts JWT-SVIDs that satisfy [SPIFFE JWT-SVID v1](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md). This section pins what that means in byte-exact terms for this Attestor:

### 2.1 Header

Standard JWS compact serialization (`base64url(header) || '.' || base64url(payload) || '.' || base64url(signature)`). The decoded header MUST be a JSON object with at least:

| Claim | Type | Constraint |
|---|---|---|
| `alg` | string | One of: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512`. SPIFFE JWT-SVID §3.1 also lists `EdDSA`; the Attestor MUST accept it. **`none` MUST be rejected with `Malformed`.** |
| `typ` | string | If present, MUST be `JWT` or `JOSE`. Other values are `Malformed`. |
| `kid` | string | Required. Lookup key into the trust bundle's JWKS. Absence is `Malformed`. |

Any other header claim is ignored (not load-bearing for verification, not relayed to evidence).

### 2.2 Payload

The decoded payload MUST be a JSON object. Required claims:

| Claim | Type | Constraint |
|---|---|---|
| `sub` | string | The SPIFFE ID. MUST satisfy `spiffe://<trust-domain>/<workload-path>` per [SPIFFE ID §2](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md). Trust domain MUST match one in the configured trust bundle. |
| `aud` | string OR array-of-string | MUST contain the operator-configured `expected_audience` value (see §6). Otherwise `Rejected`. |
| `exp` | integer | Unix epoch seconds. MUST be strictly greater than verification-time wall-clock. Otherwise `Rejected`. |
| `iat` | integer | Optional. If present and greater than verification-time wall-clock plus the configured clock-skew tolerance, `Rejected`. Default tolerance: 60 seconds. |

Optional claims the Attestor recognises:

| Claim | Type | Treatment |
|---|---|---|
| `selectors` | object (string → string) | Workload selectors as projected by SPIRE. If present, every key-value pair lands in `AttestedIdentity.attributes` as `<key>: <value>`. Non-string values cause the entire claim to be ignored with a `tracing::warn!` log; the verification still succeeds. See §8. |
| `nbf` | integer | If present and greater than verification-time wall-clock plus tolerance, `Rejected`. |

Any other payload claim is ignored. Implementations MUST NOT fail on unknown claims (forward compatibility with SPIRE custom extensions).

### 2.3 Signature

The signature is verified per JWS rules for the `alg` header claim, against the public key in the trust bundle JWKS entry matching `kid`. The Attestor delegates this step to the implementation's JWS library; the requirement is that the algorithm enforcement (§2.1) matches what the library actually verifies.

---

## 3. Verification algorithm

Given `(context: AttestationContext, credential: &[u8])`, the Attestor MUST execute the following steps in order. Each step's failure maps to a specific `AttestorError` per §9.

```text
0. If credential.is_empty():
     → Rejected("empty credential; SPIFFE Attestor requires a JWT-SVID")
1. Parse `credential` as a JWS compact serialization.
   → On parse failure: Malformed("not a JWS compact serialization")
2. Decode the header. Reject `alg = none`. Require `kid`.
   → On any header issue: Malformed("header: <reason>")
3. Snapshot the current trust bundle (§5). If the bundle is unavailable
   or past the bounded-staleness deadline (§6):
   → TrustRootUnavailable("trust bundle unavailable (<source-tag>): <reason>")
4. Look up the JWKS entry whose `kid` matches the header `kid`.
   → On lookup miss: Rejected("kid not found in trust bundle")
5. Verify the JWS signature against that public key using the header `alg`.
   → On signature failure: Rejected("signature verification failed")
6. Decode the payload as JSON.
   → On JSON parse failure: Malformed("payload not JSON")
7. Validate required payload claims (§2.2):
   - `sub` MUST be a well-formed SPIFFE ID.
     → On bad shape: Malformed("sub is not a SPIFFE ID")
   - The SPIFFE ID's trust domain MUST equal a trust domain in the bundle.
     → On mismatch: Rejected("trust domain not in bundle")
   - `aud` MUST contain `expected_audience` (string or array).
     → On miss: Rejected("audience mismatch")
   - `exp` MUST be strictly greater than `now()`.
     → On expiry: Rejected("credential expired")
   - `nbf` (if present) MUST be ≤ `now() + clock_skew_tolerance`.
     → On future-dated: Rejected("nbf in the future")
   - `iat` (if present) MUST be ≤ `now() + clock_skew_tolerance`.
     → On future-dated: Rejected("iat in the future")
8. Project payload to AttestedIdentity (§7, §8):
   - external_identity = payload.sub                       (the SPIFFE ID string)
   - credential_expires_at = Some(Timestamp::from_unix_seconds(payload.exp))
   - attributes = §8 projection of `selectors` (empty if claim absent)
9. Return Ok(AttestedIdentity).
```

The ordering is load-bearing:

- **Step 0 (empty check) first** is faster than parse and gives a clearer error for the most common misconfiguration ("forgot to pass a credential").
- **Step 3 (trust bundle snapshot) before signature verify** because the bundle snapshot is the slower path on cold-cache cases; failing fast on `TrustRootUnavailable` avoids spending CPU on a JWS verify that will be discarded.
- **Step 5 (signature verify) before payload claim checks** because an attacker submitting forged claims to a SPIFFE Attestor wants to know which check rejected them; doing signature verify first means a forged JWT always reports `signature verification failed` regardless of payload contents — no information leak about which claims would have passed.
- **Step 7 (claim checks) in the order listed**: shape checks (`sub` well-formed, trust domain match) before liveness checks (`aud`, `exp`, `nbf`). This means an expired-but-otherwise-good JWT reports "credential expired" rather than "audience mismatch", which is the more useful operator diagnostic.

The whole algorithm MUST be constant-time-safe with respect to the signature verify in step 5. Steps 0–4 and 6–8 may short-circuit on the first failure; step 5 MUST use the implementation library's constant-time JWS verify path.

### 3.1 Key-binding to `context.agent_public_key`

RFC 0016 §3.1 documents that the Attestor's `verify()` is called with the agent's claimed public key in the `AttestationContext`, and that "the Attestor MUST verify that the credential's subject controls this key". The SPIFFE Attestor handles this through the *layered* binding:

1. **The passport's self-signature** is verified by the admission handler BEFORE `Attestor.verify` is called (RFC 0016 §3.3 step 2). That proves the agent holds the private key matching `context.agent_public_key`.
2. **The SVID's `aud` claim** matches the operator-configured `expected_audience`. That proves SPIRE attested the workload for *this* swarm specifically (a SPIRE registration with the right audience).
3. **The SVID's `sub` claim** is the SPIFFE ID SPIRE assigned to the calling workload at attest time.

Composing the three: the workload is a SPIRE-attested principal with SPIFFE ID `sub`, holds an Ed25519 keypair whose public key it bound into the passport, and obtained a JWT-SVID that targets this Yutha swarm by audience. The SPIFFE Attestor does NOT inspect `context.agent_public_key` directly — it relies on the admission handler having done the self-signature check before calling `verify`.

This composition is sound as long as the swarm's `expected_audience` value is not shared with any other system that might mint JWT-SVIDs with the same audience for principals who do not also hold a Yutha-bound keypair. Operators MUST choose audience values that are Yutha-swarm-specific (a UUID or `yutha-<swarm-name>-<env>` shape works; raw hostnames or generic strings like `yutha-prod` do not).

---

## 4. Trust-bundle sources

The SPIFFE Attestor obtains its trust bundle from exactly one source at construction. Two source types are supported:

### 4.1 Static bundle file

A JSON file containing a [SPIFFE Trust Bundle](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format). Format:

```json
{
  "spiffe_sequence": 0,
  "spiffe_refresh_hint": 600,
  "trust_domain": "prod.example.com",
  "keys": [
    {
      "use": "jwt-svid",
      "kty": "EC",
      "crv": "P-256",
      "kid": "abc123",
      "x": "...base64url...",
      "y": "...base64url..."
    }
  ]
}
```

The Attestor reads the file once at construction and holds it for the process lifetime. Operators rotate the bundle by writing a new file and restarting the control plane. The static path is appropriate for air-gapped environments, edge deployments, and any case where running a SPIRE agent sidecar next to the control plane is not feasible.

The Attestor MUST validate the file at construction:

- File parses as JSON.
- `trust_domain` is a valid SPIFFE trust domain (DNS-name shape, no path).
- `keys` is a non-empty array of JWKS entries with `use = "jwt-svid"`.
- Each entry has `kid`, `kty`, and the public-key bytes required by its `kty`.

Validation failure at construction is a `SignerError`-equivalent fatal (the control plane refuses to start). At verify-time, file rot is not detected — operators are responsible for rotating-then-restarting.

### 4.2 Workload API stream

A long-lived gRPC stream to a SPIRE agent's Workload API socket. The Attestor calls `JwtBundlesClient::stream_jwt_bundles` at construction, receives the initial bundle on the first stream message, and replaces its cached bundle atomically on every subsequent message.

The Attestor MUST handle:

- **Cold start.** If the initial stream message hasn't arrived within `connect_timeout` (default 10 s, configurable), construction fails — the control plane refuses to start. There is no "start now, get a bundle later" mode; an Attestor without a bundle cannot verify.
- **Mid-stream disconnects.** Reconnect with exponential backoff (initial 1 s, max 60 s, infinite retries). While disconnected, continue serving from the last-known bundle until §6's bounded-staleness deadline is hit.
- **Bundle replacement.** Atomic swap via `Arc::swap` (or equivalent). Verify-time readers see either the old bundle or the new one, never a torn intermediate.
- **Multiple trust domains.** A SPIRE agent serving a federation will stream a `JwtBundleSet` containing multiple trust domains; the Attestor MUST accept any SVID whose `sub` trust domain is present in the set.

The Workload API socket path is OS-dependent (`unix://...` on Linux/macOS, `\\.\pipe\...` on Windows). The Attestor MUST accept whatever form the `spiffe` crate's `WorkloadApiClient::new_from_path` accepts.

### 4.3 Exactly one source

The CLI surface (§10) enforces that exactly one of `--attestor-spiffe-socket` or `--attestor-spiffe-bundle-file` is set when `--attestor spiffe` is selected. Setting both, or neither, is a fatal startup error. The constructor signature in the crate reflects this — there is no `Both` variant.

---

## 5. Bounded staleness policy

This section resolves [RFC 0016 §9.2](../rfcs/0016-attestor-interface.md#92-trust-bundle--jwks-refresh-cadence) — what to do when the trust-bundle source is briefly unavailable.

The Attestor MUST maintain a `last_refresh_at: Timestamp` value, updated on every successful bundle fetch. At verify-time, the Attestor compares `now() - last_refresh_at` against a configured `max_staleness_window`:

- **Within window:** serve verification from the cached bundle.
- **Past window:** every subsequent `verify()` call returns `TrustRootUnavailable("trust bundle stale: last refresh was N seconds ago; max staleness window is M seconds")` until a fresh bundle arrives.

The default `max_staleness_window` is `2 × spiffe_refresh_hint` from the most recent bundle, with a floor of 60 seconds and a ceiling of 24 hours. Operators MAY override via `--attestor-spiffe-max-staleness-secs`. Setting to `0` selects "hard fail on TTL expiry" (the strictest policy); the substrate refuses to admit anything past the source's own refresh hint.

For the static-bundle source, `last_refresh_at` is set at construction and never updated; `max_staleness_window` defaults to `Duration::MAX` (no staleness check). Operators using the static path who want a hard expiry MAY set `--attestor-spiffe-max-staleness-secs` to a finite value, which will cause the substrate to start rejecting registrations after that many seconds since process start — a useful trigger for "restart-the-control-plane to rotate the bundle" cron patterns.

Rationale: bounded staleness is the median-correct choice for production SPIRE deployments. Short SPIRE-agent outages (sub-minute) are common and should not block agent registrations; multi-hour outages indicate something serious is wrong and the right substrate behaviour is to refuse new registrations until operators investigate. The 2× multiplier mirrors common bearer-token grace-period patterns.

---

## 6. Audience binding

The operator MUST configure `expected_audience` at startup via `--attestor-spiffe-audience`. The Attestor MUST reject any SVID whose `aud` claim does not contain this exact value (string-equal, no normalisation, no wildcards).

### 6.1 Choosing an audience value

The audience value is the *Yutha-side identifier* that SPIRE workloads request when they obtain a JWT-SVID for talking to Yutha. SPIRE workloads call something analogous to `WorkloadApiClient::fetch_jwt_svid(audiences=[audience])`; only audience values registered for that workload are honored.

Concrete guidance:

- **Production:** `yutha-<swarm-name>-<env>` shape, e.g., `yutha-orders-prod`. Unique per (swarm, environment). Audience is the proof that "this SVID was obtained specifically to talk to this Yutha swarm" — generic values like `yutha-prod` invite cross-system replay if the same SPIRE trust domain serves other Yutha-shaped consumers.
- **Multi-region:** include region in the audience, e.g., `yutha-orders-prod-us-east`. Each region's control plane configures only its region's audience.
- **Federated:** when SPIRE-federation is in play (workloads in trust domain A presenting SVIDs to a Yutha control plane configured for trust domain B), the audience MUST be the Yutha-side value, not a domain identifier. The SPIRE federation policy at the issuing side decides whether the workload is allowed to mint SVIDs for that audience.

### 6.2 Why audience binding is required even with trust-domain check

The trust-domain check (§3 step 7) ensures the SVID was minted by a SPIRE we trust. The audience check ensures the SVID was minted *for us*. Without audience, a SVID that workload W obtained to talk to some unrelated SPIRE-protected service S could be replayed against the Yutha control plane — same trust domain, same valid SVID, wrong intent. Audience binding is the SVID's "you, specifically" claim; the Attestor MUST enforce it.

---

## 7. SPIFFE-ID → external_identity mapping

`AttestedIdentity.external_identity` MUST equal the SVID's `sub` claim verbatim. That string is:

- The full canonical SPIFFE ID: `spiffe://<trust-domain>/<workload-path>`.
- Whatever the trust domain and workload path SPIRE issued. No normalisation. No truncation. No URI encoding/decoding beyond what's required to be valid UTF-8.

Concretely, the `agent.register` receipt's `attested_external_identity` evidence key will carry strings like:

```
spiffe://prod.example.com/payments-api/v2
spiffe://staging.example.com/workload/k8s-ns/billing/k8s-sa/processor
spiffe://example.org/ci/runner-42
```

Auditors querying the receipt log for "all agents attested under workload-path matching `/payments-api/*`" can do so with a substring filter; the canonical form is the searchable form.

### 7.1 Why not strip the scheme

It is tempting to drop `spiffe://` and just record the path. Don't:

- The scheme distinguishes SPIFFE attestations from native (`yutha:native:<hex>`) and OIDC (`oidc:<issuer>:<sub>`) ones. Mixing them in one evidence column without a scheme makes the audit log ambiguous.
- SPIFFE's [URI shape](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md) is the canonical wire form. Tools that read SPIFFE IDs expect the scheme.

---

## 8. Selectors → attributes projection

If the SVID payload contains a `selectors` claim that is a JSON object whose values are all strings, the Attestor MUST project each entry into `AttestedIdentity.attributes` as `<key>: <value>`. The receipt evidence then carries `attributes.<key>: <value>` keys per RFC 0016 §3.4.

Example: a SPIRE-attested Kubernetes workload's selectors might look like:

```json
"selectors": {
  "k8s_ns": "billing",
  "k8s_sa": "processor",
  "k8s_pod_label_app": "billing-processor",
  "unix_uid": "1000"
}
```

The `agent.register` receipt evidence then includes:

```
attributes.k8s_ns: billing
attributes.k8s_sa: processor
attributes.k8s_pod_label_app: billing-processor
attributes.unix_uid: 1000
```

These attributes are auditor-visible and admin-policy-consumable. A future admission-policy extension could read them (e.g., "only admit workloads with `k8s_ns = billing`"); v1 does not — they go to the audit log only.

### 8.1 Constraints

- **Strings only.** If any value in `selectors` is not a string (number, bool, array, object, null), the Attestor MUST log a warning and skip the entire claim — `attributes` ends up empty. The reason is wire-shape stability: the receipt evidence's `attributes.<key>: <value>` shape is `string → string`, and converting numbers/bools risks lossy formatting (123 vs "123"). Skipping is safer than guessing.
- **Key namespace.** SPIRE's selector keys are typically `<type>_<name>` (`k8s_ns`, `unix_uid`, `k8s_pod_label_<labelname>`). The Attestor does NOT prefix or namespace them further; the SPIRE convention IS the convention. Two SPIRE selector types with the same key (rare in practice, possible in principle) get a "last one wins" outcome — operators relying on selectors should use unambiguous keys.
- **Size cap.** The Attestor MUST cap the total selectors-to-attributes projection at 64 entries and at 4 KiB of total key+value bytes. Beyond either cap, the projection truncates with a warning log. Rationale: receipt evidence is canonical-encoded into receipt bytes; an unbounded selectors blob can balloon individual receipts and the receipt store's row size.

### 8.2 Non-`selectors` claims

The Attestor MUST NOT project any other payload claim into `attributes`. In particular: `iss`, `aud`, `iat`, `exp`, `nbf`, `jti`, custom non-selector claims SPIRE may add — all ignored. The reason is canonicality: the audit log's `attributes.<key>` keys must come from a documented source, and `selectors` is the only documented source. Loose projection of "everything in the JWT" makes the evidence schema unpredictable across SPIRE versions.

---

## 9. Error mapping

The mapping from internal verification failures to `AttestorError` variants. Every failure mode the Attestor surfaces MUST land on exactly one row in this table.

| Failure | `AttestorError` variant | Message shape |
|---|---|---|
| Empty `credential` | `Rejected` | `"empty credential; SPIFFE Attestor requires a JWT-SVID"` |
| JWS compact-serialisation parse failure | `Malformed` | `"not a JWS compact serialization"` |
| Header missing `kid` | `Malformed` | `"header: missing kid"` |
| Header `alg = none` | `Malformed` | `"header: alg none is not permitted"` |
| Header `alg` not on the allowlist | `Malformed` | `"header: unsupported alg"` |
| Header `typ` present and not `JWT` or `JOSE` | `Malformed` | `"header: unsupported typ"` |
| Trust bundle source unavailable (cold start past `connect_timeout`) | `TrustRootUnavailable` | `"trust bundle unavailable (<source-tag>): <reason>"` |
| Trust bundle stale past `max_staleness_window` | `TrustRootUnavailable` | `"trust bundle stale: last refresh was N seconds ago; max staleness window is M seconds"` |
| `kid` not found in trust bundle JWKS | `Rejected` | `"kid not found in trust bundle"` |
| JWS signature verification failure | `Rejected` | `"signature verification failed"` |
| Payload not JSON | `Malformed` | `"payload not JSON"` |
| Missing `sub` claim | `Malformed` | `"payload: missing sub"` |
| `sub` not a SPIFFE ID | `Malformed` | `"sub is not a SPIFFE ID"` |
| SPIFFE-ID trust domain not in bundle | `Rejected` | `"trust domain not in bundle"` |
| Missing `aud` claim | `Malformed` | `"payload: missing aud"` |
| `aud` does not contain `expected_audience` | `Rejected` | `"audience mismatch"` |
| Missing `exp` claim | `Malformed` | `"payload: missing exp"` |
| `exp` not a number | `Malformed` | `"payload: exp not a number"` |
| `exp ≤ now()` | `Rejected` | `"credential expired"` |
| `nbf > now() + clock_skew_tolerance` | `Rejected` | `"nbf in the future"` |
| `iat > now() + clock_skew_tolerance` | `Rejected` | `"iat in the future"` |
| Implementation bug / unreachable | `Internal` | `"unexpected: <short tag>"` |

### 9.1 PII rule restated

No error message MAY contain:

- Any byte of the original `credential` argument.
- The decoded payload, in whole or in part — no `sub`, `aud`, `iss`, custom claims, selectors, JWT IDs.
- The decoded header beyond the algorithm name (the algorithm being part of the `unsupported alg` message is permitted because it's a low-entropy enum value, not a subject identifier).

The audit log captures `attested_external_identity` only on *successful* attestations (the `agent.register` receipt). Failed attestations land in `agent.register.deny` receipts whose evidence is `claimed_agent_id` + `attestor_id` + `deny_reason` — and `deny_reason` comes from the error-message table above, which carries no claim contents.

This is a SOC2/HIPAA-defensible posture: an operator investigating a failed registration sees enough to debug (which check failed) but not enough to derive identifying information about the would-be principal.

---

## 10. CLI flag surface

The control-plane binary (`yutha-control-plane`) is the only consumer of the Attestor today. The Phase E flag additions:

```bash
yutha-control-plane \
    --attestor spiffe \
    --attestor-spiffe-socket /run/spire/sockets/agent.sock \
    --attestor-spiffe-audience yutha-orders-prod \
    [--attestor-spiffe-max-staleness-secs 3600] \
    [--attestor-spiffe-clock-skew-secs 60] \
    [--attestor-spiffe-connect-timeout-secs 10]
```

or, for the static-bundle path:

```bash
yutha-control-plane \
    --attestor spiffe \
    --attestor-spiffe-bundle-file /etc/yutha/trust-bundle.json \
    --attestor-spiffe-audience yutha-orders-prod \
    [--attestor-spiffe-max-staleness-secs 0] \   # 0 = no staleness check
    [--attestor-spiffe-clock-skew-secs 60]
```

Validation at startup:

- `--attestor-spiffe-audience` is REQUIRED when `--attestor spiffe`. Empty string is fatal.
- Exactly one of `--attestor-spiffe-socket` or `--attestor-spiffe-bundle-file` MUST be set. Both → fatal; neither → fatal.
- `--attestor-spiffe-max-staleness-secs` defaults to `2 × spiffe_refresh_hint` (Workload API) or `0` (static); explicit `0` selects "hard fail on TTL expiry" for Workload API.
- `--attestor-spiffe-clock-skew-secs` defaults to `60`. Must be non-negative.
- `--attestor-spiffe-connect-timeout-secs` defaults to `10` (Workload API path only; ignored for static).

All flags accept their corresponding `YUTHA_ATTESTOR_SPIFFE_*` env vars (clap `env=` attribute), matching the convention from the [Signer backends](../rfcs/0017-external-signer-backends.md) flags.

### 10.1 Selecting `spiffe` without the required flags

If an operator runs `--attestor spiffe` without `--attestor-spiffe-audience`, or with neither/both source flags, the control plane MUST exit at startup with a clear message naming the missing/conflicting flags. Same posture as the Phase D scaffold's `--attestor spiffe` placeholder (which exited with "lands in Phase E") — fast, clear, operator-actionable.

---

## 11. Conformance vectors

Per RFC 0016 §3.8 the SPIFFE vectors land in Phase E. Directory layout under `/spec/vectors/attestor/`:

```
spiffe-accept-ed25519/         # 8 cases: happy path, EdDSA-signed SVIDs
spiffe-accept-ecdsa-p256/      # 8 cases: happy path, ES256-signed SVIDs
spiffe-accept-rsa/             # 4 cases: happy path, RS256-signed SVIDs
spiffe-reject-audience/        # 4 cases: aud mismatch
spiffe-reject-expired/         # 4 cases: exp in the past
spiffe-reject-signature/       # 4 cases: bit-flipped signature
spiffe-reject-malformed/       # 4 cases: garbled JWS, missing kid, alg=none
spiffe-reject-trust-domain/    # 4 cases: SPIFFE-ID trust domain not in bundle
spiffe-reject-empty/           # 1 case: credential = []
selector-projection/           # 4 cases: selectors → attributes
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
    "trust_bundle": { "...": "JWKS object" },
    "expected_audience": "yutha-test"
  },
  "credential_b64": "...",
  "expected_result": {
    "kind": "ok" | "err",
    "external_identity": "spiffe://...",        // present iff kind=ok
    "credential_expires_at_unix_secs": 1234567,  // present iff kind=ok
    "attributes": { ... },                       // present iff kind=ok
    "error_variant": "Malformed" | "Rejected" | "TrustRootUnavailable" | "Internal",  // present iff kind=err
    "error_message_substring": "audience mismatch"  // present iff kind=err; substring-match on the AttestorError display
  }
}
```

The vectors test (`crates/yutha-attestor-spiffe/tests/vectors.rs`) iterates every JSON file, constructs a `SpiffeAttestor` with the bundle + audience from `attestor_config`, calls `verify(context, credential)`, and asserts the result matches `expected_result`.

### 11.1 Why JSON fixtures here when Phase D shipped Rust-test-as-spec

Phase D's NativeAttestor has no cross-implementation to validate against — every conformant impl is the Rust impl. The Rust test is the spec.

SPIFFE Attestor has a real cross-implementation surface: Go (`go-spiffe`), Java (`java-spiffe`), Python (`pyspiffe`), and others. The vectors are the inter-language conformance contract — anyone implementing a SPIFFE Attestor in another language can iterate these JSON files and report which pass.

The cases MUST be regenerable from a documented seed; the vectors directory ships a `regen.sh` script that takes a seed and produces every fixture deterministically (trust-bundle keypairs are derived; clock-dependent claims use a fixed pseudo-now). Operators can verify the shipped vectors by running `regen.sh <documented-seed>` and diffing.

---

## 12. Threat-model impact

This Attestor implements [RFC 0016 §6](../rfcs/0016-attestor-interface.md#6-threat-model-impact)'s A1 / A6 / A8 mitigations against [the threat model](../../docs/internal/threat-model.md):

### 12.1 A1 — hostile agent participant

**Mitigation.** A SPIFFE-Attestor-configured control plane refuses to admit any agent that cannot present a SVID for the configured audience. An attacker who steals the swarm's bootstrap seed (RFC 0007's standalone scenario) still cannot register an arbitrary agent — they additionally need a SPIRE-issued SVID, which SPIRE issues only to attested workloads.

**Residual.** An attacker who compromises a workload that SPIRE has already attested (e.g., RCE into a Yutha-eligible pod) inherits its SVID and can register a malicious agent under that workload's identity. This is the irreducible "if the workload is compromised, its identity is compromised" property of any attestation system — SPIRE's job is to bound which workloads can be impersonated; the substrate cannot strengthen this beyond what SPIRE provides.

### 12.2 A6 — Sybil attacker

**Mitigation.** With SPIFFE attestation enforced, Sybil cost rises from "generate an Ed25519 keypair" to "convince SPIRE to attest a workload and mint an SVID with the right audience". SPIRE's workload-attestation policies (selector matching, parent-process attestation, k8s-pod attestation) impose substantial friction.

**Residual.** A SPIRE deployment that admits broad workload classes (e.g., "any pod in any namespace") gives an internal attacker many sources of valid SVIDs. The audience-binding (§6) helps — the attacker also needs an SVID specifically minted for the Yutha audience — but the right substrate posture is "narrow SPIRE registrations" rather than "the Attestor will catch sloppy SPIRE config".

### 12.3 A8 — malicious operator

**Mitigation, marginal.** A malicious operator who controls the Attestor's configuration can still admit whoever they want — by swapping `--attestor spiffe` for `--attestor native`, or by configuring a SPIRE that admits everything. What this Attestor adds is *audit-side*: the `agent.register` receipts record `attestor_id = "spiffe"` and `attested_external_identity = spiffe://...`. A post-hoc audit can detect that the operator swapped attestors (the `attestor_id` field changes), and the timing of any registrations against `attestor_id = "native"` during a SPIFFE-deployment's lifetime is itself anomalous and detectable.

### 12.4 New attack surfaces

- **SPIRE itself.** The substrate's trust is now transitively dependent on SPIRE. A compromised SPIRE issuing arbitrary SVIDs grants arbitrary attestation. Operators MUST follow SPIRE's own deployment guidance; this is outside Yutha's substrate scope.
- **JWT-SVID replay.** SPIFFE JWT-SVIDs have lifetimes (typically 5 minutes – 1 hour). A captured SVID within its lifetime can be replayed by anyone with network access to the admission RPC. The lifecycle of the resulting Yutha passport is independent — once registered, the agent's authority depends on its own bearer tokens, not the SVID. This is consistent with RFC 0016 §5.3 (no per-call re-attestation in v1).

---

## 13. Open items

### 13.1 X.509-SVID support

This v1 does not verify X.509-SVIDs. An operator running an mTLS-everywhere SPIRE deployment may want to terminate mTLS at the Yutha control plane and use the client cert as the attestation credential. The shape of this is reasonably clear:

- New CLI flag `--attestor-spiffe-mode {jwt,x509}` (default `jwt`).
- For `x509`, the credential bytes are the DER-encoded client cert; verification checks chain to the trust bundle's X.509 trust domain, audience against URI SAN (vs. JWT `aud`), and key-binding via the cert's subject public key (which MUST match `context.agent_public_key`).
- Configuration of how mTLS terminates (at the control plane's tonic server vs. at a sidecar that forwards the client cert as a metadata header) is the additional design question this defers.

Worth revisiting if an operator surfaces it; not part of v1.

### 13.2 Custom claim attribute projection

§8.2 explicitly forbids projecting any claim besides `selectors` into `attributes`. A future enhancement could whitelist additional claims via configuration (e.g., `--attestor-spiffe-project-claim spiffe_workload_owner`). Deferred until a concrete need surfaces.

### 13.3 Per-Attestor audit-log filtering

The receipt evidence's `attestor_id = "spiffe"` is constant across all SPIFFE-attested registrations. Operators running federated SPIRE setups (multiple trust domains, possibly multiple SPIRE servers) might want `attestor_id = "spiffe:<trust-domain>"` for sub-Attestor granularity. The current `Attestor::id() -> &str` trait returns a static string; adding a per-call dynamic id would be a trait change. Deferred to a future RFC if needed.

---

## 14. References

- [RFC 0016 — Attestor interface](../rfcs/0016-attestor-interface.md) — the umbrella RFC this spec extends
- [identity-keys README](./README.md) — shared framing memo for Signer + Attestor
- [SPIFFE specification](https://github.com/spiffe/spiffe) — the standard this Attestor implements
- [SPIFFE JWT-SVID v1](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md) — the credential format
- [SPIFFE ID v1](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md) — the identifier format the `sub` claim must satisfy
- [SPIFFE Trust Domain and Bundle](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md) — trust bundle format
- [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md) — Workload API stream protocol
- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519) — JWT format
- [maxlambrecht/rust-spiffe](https://github.com/maxlambrecht/rust-spiffe) — the Rust SDK the reference impl builds on
- [Threat model](../../docs/internal/threat-model.md) — A1, A6, A8 are the load-bearing adversaries

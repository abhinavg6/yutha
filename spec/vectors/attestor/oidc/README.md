# OIDC Attestor — cross-implementation conformance vectors

JSON-fixture vectors for the OIDC Attestor (Phase F,
`yutha-attestor-oidc`). Each fixture pins a (JWKS, ID token,
operator config, expected verify outcome) tuple that any conformant
implementation MUST reproduce.

## Why JSON fixtures

OIDC ID tokens have multiple production-grade implementations
(`jsonwebtoken` Rust, `jose4j` Java, `python-jose` / `PyJWT` Python,
`jose` Node, the IdP-vendor SDKs). The spec memo at
[`/spec/identity-keys/attestor-oidc.md`](../../../identity-keys/attestor-oidc.md)
exists to pin behaviour ALL of those should agree on for the verify
contract. JSON fixtures are the inter-language conformance contract.

Same posture as the [SPIFFE vectors](../spiffe/README.md) — see that
doc for the rationale on JSON-vectors-vs-Rust-test-as-spec.

## Format

Each `*.json` file under one of the subdirectories below has shape:

```jsonc
{
  "name": "<short-slug>",
  "description": "<what this vector exercises and which spec row it pins>",
  "kind": "attestor-oidc-verify",
  "inputs": {
    "credential_b64":   "<base64url-no-pad of the ID-token bytes>",
    "context": {
      "swarm_id_hex":         "<32-char hex = 16 bytes>",
      "claimed_agent_id_hex": "<32-char hex = 16 bytes>",
      "agent_public_key": {
        "algorithm": "ed25519",
        "value_b64": "<base64url-no-pad of the 32-byte public key>"
      }
    },
    "attestor_config": {
      "jwks":                     { "keys": [...] },
      "expected_issuer":          "https://login.test.example.com",
      "expected_audience":        "yutha-test-audience",
      "allowed_algs":             ["RS256", "ES256", "EdDSA"],
      "project_claims":           [],
      "clock_skew_tolerance_secs": 60
    }
  },
  // present iff expected_outcome == "accept":
  "expected_outcome": "accept",
  "expected_identity": {
    "external_identity":              "oidc:https://login.test.example.com:user-1",
    "credential_expires_at_unix_secs": 4070908800,
    "attributes":                      { /* optional projected claims */ }
  },
  // present iff expected_outcome == "reject":
  "expected_outcome": "reject",
  "expected_error_variant":           "Malformed" | "Rejected" | "TrustRootUnavailable" | "Internal",
  "expected_error_message_substring": "audience mismatch"
}
```

### Conventions

- **Base64url** is the JWS-standard URL-safe alphabet WITHOUT padding
  (matches `base64::engine::general_purpose::URL_SAFE_NO_PAD`).
- **Hex** is lowercase, no `0x`.
- **`jwks`** is a standalone JWKS — `{ "keys": [ {kty, kid, alg, ...}, ... ] }`.
  No `trust_domain` wrapper (that's the SPIFFE-specific shape; OIDC
  IdPs publish bare JWKS). The Attestor loads it via
  `JwksSource::StaticFile` for vector tests (no live HTTP).
- **`expected_error_message_substring`** is a substring check (case-
  sensitive), not full-string equality — implementations may add
  prefixes or context. The substring is the spec §9 pinned phrase
  (e.g., `"audience mismatch"`, `"credential expired"`).
- **`external_identity`** has the spec §7 shape `oidc:<iss>:<sub>` —
  the full `iss` URL is verbatim, not normalized; `<sub>` is the
  ID-token `sub` claim verbatim.
- **Timestamps** in fixture claims (`exp`, `iat`, `nbf`) are computed
  off a `PSEUDO_NOW_UNIX_SECS` constant in the regen test
  ([`tests/regen_vectors.rs`](../../../../crates/yutha-attestor-oidc/tests/regen_vectors.rs)).
  The constant is set to 2099-01-01T00:00:00Z so "accept" fixtures
  stay valid for decades. If you're reading this in 2098, bump the
  constant + regen. For "expired" fixtures we hardcode early-2000s
  Unix timestamps (per [the time-relative-fixtures lesson](../../../../crates/yutha-attestor-oidc/tests/regen_vectors.rs)).

## Cases

### `accept-es256/`
- `happy_path.json` — well-formed ES256-signed ID token, all
  required claims, `exp` far-future, no projected claims. Asserts
  the §3 happy-path: signature verifies, claims pass,
  `AttestedIdentity.external_identity = oidc:<iss>:<sub>`.
- `projected_claims.json` — operator allowlists `groups` + `email`;
  token includes both; projection lands in `attributes`. Asserts
  §8 projection semantics (array → comma-joined, string → verbatim).

### `reject-issuer/`
- `iss_mismatch.json` — token `iss` claim differs from
  `expected_issuer`. Spec §9 row "iss does not equal expected_issuer"
  → `Rejected("issuer mismatch")`.

### `reject-audience/`
- `aud_mismatch.json` — token `aud` claim does not contain
  `expected_audience`. Spec §9 row "aud does not contain
  expected_audience" → `Rejected("audience mismatch")`.

### `reject-expired/`
- `exp_past.json` — `exp` hardcoded to a 2001 Unix time. Spec §9
  row "exp ≤ now()" → `Rejected("credential expired")`.

### `reject-signature/`
- `bit_flipped.json` — otherwise-valid ID token with one bit of the
  signature segment flipped. Spec §9 row "JWS signature verification
  failure" → `Rejected("signature verification failed")`.

### `reject-empty/`
- `empty.json` — credential bytes are empty. Spec §9 row "Empty
  credential" → `Rejected("empty credential; OIDC Attestor requires
  an ID token")`.

## Case-count deviation from spec §11

Spec §11 enumerates ~25 case variants across 13 subdirectories
(separate accept-eddsa/, reject-not-yet-valid/, reject-alg-none/,
reject-alg-hmac/, reject-malformed/, reject-kid-unknown/, etc.).

v1 ships **8 cases across 7 subdirectories** — the spec-row coverage
on each side of the parse-pipeline is one representative case rather
than the broader matrix. Matches the [Phase E SPIFFE deviation
posture](../spiffe/README.md#cases) (9 cases vs spec's 45).

Rationale: the missing rows are already exercised by the in-crate
F4 + F7 tests in `crates/yutha-attestor-oidc/tests/` (forged-JWT
unit tests for alg=none, alg=HS256, missing kid, malformed JWS,
not-yet-valid, etc.). The JSON vectors are the
*inter-language* contract — additional rows can land in F10 or a
later RFC-amendment when a third-party impl needs them.

Future implementations can request specific additional cases via
RFC 0016 amendment.

## Regeneration

```bash
# Deterministic: same REGEN_SEED → byte-identical fixtures.
REGEN_SEED=42 cargo test -p yutha-attestor-oidc \
    --test regen_vectors -- --ignored regen_oidc_vectors
```

The regen test:
- Seeds `rand_chacha::ChaCha20Rng` from `REGEN_SEED` (default 42).
- Generates one RSA-2048 keypair + one ECDSA-P256 keypair from the
  seeded RNG. RSA's prime generation is deterministic given the
  seed, so the keys + their JWK encodings are reproducible.
- Pins `PSEUDO_NOW_UNIX_SECS = 4_070_908_800` (2099-01-01Z) as the
  "now" value for `exp` / `iat` / `nbf` claim construction in
  happy-path fixtures.
- Hardcodes early-2000s Unix timestamps in "expired" fixtures (per
  the [time-relative-fixtures memory entry](../../../../crates/yutha-attestor-oidc/tests/regen_vectors.rs)
  documenting that PSEUDO_NOW-relative offsets don't work for
  "past" cases).
- Writes each fixture to `spec/vectors/attestor/oidc/<dir>/<name>.json`.

The fixture loader test (`tests/vectors.rs`) iterates every JSON file
in `spec/vectors/attestor/oidc/`, deserializes per the format above,
constructs an `OidcAttestor` in static-file mode against the
fixture's inline JWKS, calls `verify()`, and asserts the outcome.

Verification command:
```bash
cargo test -p yutha-attestor-oidc --test vectors
```

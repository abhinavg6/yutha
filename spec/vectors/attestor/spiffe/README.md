# SPIFFE Attestor — cross-implementation conformance vectors

JSON-fixture vectors for the SPIFFE Attestor (Phase E,
`yutha-attestor-spiffe`). Each fixture pins a (trust bundle,
JWT-SVID, expected verify outcome) triple that any conformant
implementation MUST reproduce.

## Why JSON fixtures (vs. the Rust-test-as-spec pattern Phase D used)

The Phase D `NativeAttestor` vectors live as Rust test cases inside
`crates/yutha-attestor/tests/native_vectors.rs` — there's only one
implementation, so committed JSON would be redundant
(see [`/spec/vectors/attestor/README.md`](../README.md)).

SPIFFE is different. JWT-SVID has multiple production-grade reference
implementations (`go-spiffe`, `java-spiffe`, `pyspiffe`,
`maxlambrecht/rust-spiffe`), and the spec memo at
[`/spec/identity-keys/attestor-spiffe.md`](../../../identity-keys/attestor-spiffe.md)
exists to pin behaviour ALL of those should agree on. JSON fixtures
are the inter-language conformance contract.

## Format

Each `*.json` file under one of the subdirectories below has shape:

```jsonc
{
  "name": "<short-slug>",
  "description": "<what this vector exercises and which spec row it pins>",
  "kind": "attestor-spiffe-verify",
  "inputs": {
    "credential_b64":   "<base64url-no-pad of the credential bytes>",
    "context": {
      "swarm_id_hex":         "<32-char hex = 16 bytes>",
      "claimed_agent_id_hex": "<32-char hex = 16 bytes>",
      "agent_public_key": {
        "algorithm": "ed25519",
        "value_b64": "<base64url-no-pad of the 32-byte public key>"
      }
    },
    "attestor_config": {
      "trust_bundle":              { "trust_domain": "...", "keys": [...] },
      "expected_audience":         "yutha-test-audience",
      "clock_skew_tolerance_secs": 60
    }
  },
  // present iff expected_outcome == "accept":
  "expected_outcome": "accept",
  "expected_identity": {
    "external_identity":              "spiffe://example.org/test/workload",
    "credential_expires_at_unix_secs": 4070912400,
    "attributes":                      { /* optional projected selectors */ }
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
- **`trust_bundle`** is the static-file JSON shape the Yutha SPIFFE
  Attestor's `TrustBundleSource::StaticFile` path accepts: a
  `trust_domain` string + a `keys` JWKS array. See
  [attestor-spiffe.md §4.1](../../../identity-keys/attestor-spiffe.md#41-static-bundle-file).
- **`expected_error_message_substring`** is a substring check (case-
  sensitive), not full-string equality — implementations may add
  prefixes or context. The substring is the spec §9 pinned phrase
  (e.g., `"audience mismatch"`, `"credential expired"`).
- **Timestamps** in fixture claims (`exp`, `iat`, `nbf`) are computed
  off a `PSEUDO_NOW_UNIX_SECS` constant in the regen test
  ([`tests/regen_vectors.rs`](../../../../crates/yutha-attestor-spiffe/tests/regen_vectors.rs)).
  The constant is set to 2099-01-01T00:00:00Z so "accept" fixtures
  stay valid for decades. If you're reading this in 2098, bump the
  constant + regen.

### What conformance means

For every "accept" fixture, a conformant implementation MUST:

1. Construct an Attestor from `attestor_config` (the static-bundle
   source + the audience).
2. Call `verify(context, credential)` with the inputs.
3. Return `Ok(AttestedIdentity)` whose fields match
   `expected_identity` exactly.

For every "reject" fixture, a conformant implementation MUST:

1. Construct the Attestor likewise.
2. Call `verify(...)`.
3. Return `Err(AttestorError::<expected_error_variant>(msg))` where
   `msg.contains(expected_error_message_substring)`.

The Yutha Rust loader at
[`crates/yutha-attestor-spiffe/tests/vectors.rs`](../../../../crates/yutha-attestor-spiffe/tests/vectors.rs)
iterates every JSON file in this tree and asserts both contracts;
runs as part of `cargo test -p yutha-attestor-spiffe` (no
`--ignored` needed).

## Layout

```
spiffe/
├── README.md                ← you are here
├── accept-ecdsa-p256/       ← ES256 happy-path vectors
├── reject-audience/         ← aud claim doesn't contain expected_audience
├── reject-expired/          ← exp claim in the past
├── reject-malformed/        ← unparseable JWS / bad header / unknown kid
├── reject-signature/        ← bit-flipped signature
├── reject-trust-domain/     ← sub names a trust domain not in the bundle
├── reject-empty/            ← empty credential bytes
└── selectors/               ← selectors → attributes projection
```

### v1 deviation from spec §11 case counts

[attestor-spiffe.md §11](../../../identity-keys/attestor-spiffe.md#11-conformance-vectors)
documents a case-count target of 45 fixtures across 10 directories
(8 ed25519 / 8 ecdsa / 4 rsa / 4 per reject category / 1 empty / 4
selectors). The v1 committed set is **smaller and flatter**: one to two
fixtures per category, ~9 total, exercising every spec §9 row but
not multiplying through trivial variations (e.g., the §11 ed25519 and
rsa accept categories are not emitted in v1 because covering them
would require an Ed25519 + RSA keypair in the regen + dev-deps for
their JWT-libraries' signature paths, with little additional
coverage over the ES256 happy path).

Rationale: the inter-language conformance contract is on the spec
§9 *message-shape* table, not the case count. A Go implementation
that passes the 9 v1 cases is genuinely conformant; expanding to 45
mostly adds repetition. Future regens can grow the set without
breaking the loader (it iterates every `*.json`).

Adding cases:

1. Add a new entry to the `build_cases` function in
   [`tests/regen_vectors.rs`](../../../../crates/yutha-attestor-spiffe/tests/regen_vectors.rs).
2. Re-run the regen (see below).
3. Commit the new JSON.

## Regenerating

The vectors are deterministic from `REGEN_SEED` + `PSEUDO_NOW_UNIX_SECS`
constants in `tests/regen_vectors.rs`. Re-running with both
unchanged produces byte-identical output:

```bash
cd /Users/abhinavgarg/Documents/Claude/Yutha
cargo test -p yutha-attestor-spiffe --test regen_vectors \
    -- --ignored --nocapture
```

The test wipes + rewrites every subdirectory under this README, so
removed cases don't linger. Inspect the diff after running; commit
intentional drift.

## See also

- [`/spec/identity-keys/attestor-spiffe.md`](../../../identity-keys/attestor-spiffe.md) —
  byte-exact spec the fixtures encode.
- [`crates/yutha-attestor-spiffe/tests/vectors.rs`](../../../../crates/yutha-attestor-spiffe/tests/vectors.rs) —
  Rust loader.
- [`crates/yutha-attestor-spiffe/tests/forged_jwts.rs`](../../../../crates/yutha-attestor-spiffe/tests/forged_jwts.rs) —
  the in-tree forged-JWT suite, which covers the same spec rows in
  Rust without committed fixtures. JSON vectors and forged tests are
  complementary, not redundant: forged tests catch Rust regressions
  fast; JSON vectors validate other-language implementations.

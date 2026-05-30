# Attestor — cross-implementation conformance vectors

Behavioral and byte-equivalence vectors for the
[`Attestor` interface (RFC 0016)](../../rfcs/0016-attestor-interface.md)
and its implementations.

## Why this exists

Phase D introduced an async `Attestor` trait in the
`yutha-attestor` crate, plus a zero-dependency `NativeAttestor`
default. RFC 0016 §3.8 pins three conformance contracts every
implementation MUST satisfy:

1. **Native accept-empty.** `NativeAttestor.verify(ctx, &[])` returns
   `Ok` with `external_identity == "yutha:native:<agent_id_hex>"`,
   `credential_expires_at == None`, and empty `attributes`.
2. **Native reject-nonempty.** `NativeAttestor.verify(ctx, &[any non-empty])`
   returns `Err(AttestorError::Rejected(_))`.
3. **Context passthrough.** For any conformant Attestor, the
   `AttestationContext` fields (`swarm_id`, `claimed_agent_id`,
   `agent_public_key`) MUST be carried through unchanged into the
   `AttestedIdentity` derivation (e.g., `external_identity` for native
   encodes `claimed_agent_id`).

The third contract becomes load-bearing in Phase E/F when external
Attestors (SPIFFE, OIDC) extract their `external_identity` from the
credential's subject — but MUST still consult the context to validate
the key-binding invariant from RFC 0016 §3.1.

## Layout

```
/spec/vectors/attestor
├── README.md          ← you are here
├── /native-accept-empty   ← reserved (no JSON fixtures in v1; see below)
├── /native-reject-nonempty ← reserved
├── /context-passthrough   ← reserved
├── /spiffe/                ← Phase E will land JSON fixtures
└── /oidc/                  ← Phase F will land JSON fixtures
```

## Phase D — Rust test as the spec

Unlike the Phase B `signer/sign-and-verify/` vectors (which check in
JSON fixtures because Ed25519 has many cross-language reference impls
to validate against), the v1 Attestor surface has exactly one
implementation: Rust's `NativeAttestor`. Cross-language byte
equivalence is trivially true with one implementation.

For v1, the conformance test at
[`crates/yutha-attestor/tests/native_vectors.rs`](../../../crates/yutha-attestor/tests/native_vectors.rs)
serves as the spec. It runs:

- 16 `accept-empty` cases (boundary agent_id shapes: all-zero, all-FF,
  alternating, deterministic UUID v7s).
- 8 `reject-nonempty` cases (boundary credential shapes: 1 byte, 32
  bytes, 1KiB, …).
- 8 `context-passthrough` cases asserting `claimed_agent_id` flows
  unchanged into `external_identity` and `agent_public_key` /
  `swarm_id` aren't silently mutated.

Run with `cargo test -p yutha-attestor --test native_vectors`. Each
case asserts the RFC 0016 §3.8 contract; failures point at which case
broke.

## Phase E / F — JSON fixtures land alongside

The SPIFFE and OIDC Attestors WILL ship JSON-fixture vectors because:

- Credential formats (JWT-SVID, OIDC ID-token) have multiple
  reference implementations to cross-validate against.
- Test credentials require known signing-key / JWKS material — easier
  to commit as JSON than to regenerate on every test run.

Each will follow the
[Phase B signer-vectors](../signer/sign-and-verify/README.md) JSON
shape:

```json
{
  "name": "...",
  "description": "...",
  "kind": "attestor-spiffe-verify",
  "inputs": { "credential_b64": "...", "context": { ... } },
  "expected_outcome": "accept",
  "expected_identity": { "external_identity": "spiffe://...", "..." }
}
```

When Phase E lands `yutha-attestor-spiffe`, its
`tests/vectors.rs` loader will consume JSON fixtures from
`/spec/vectors/attestor/spiffe/` exactly like
`yutha-signer/tests/vectors.rs` consumes
`/spec/vectors/signer/sign-and-verify/`.

## Receipt-evidence contract

Beyond the trait itself, RFC 0016 also pins the receipt-evidence shape
on `agent.register` (with new keys `attested_external_identity` +
`attestor_id` + optional `attributes.<key>`) and the new
`agent.register.deny` action-kind. Those are specified in
[`/spec/receipt/canonical-actions.md`](../../receipt/canonical-actions.md);
the Rust integration scenario at
`crates/yutha-conformance/src/scenarios/` (Phase D follow-on) asserts
the evidence is populated correctly on the happy path and on the deny
path.

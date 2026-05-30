# Signer — cross-implementation conformance vectors

Byte-equality and behavioral conformance vectors for the
[`Signer` interface (RFC 0015)](../../rfcs/0015-signer-interface.md)
and its `InProcessSigner` default.

## Why this exists

Phase B introduced an async `Signer` trait/Protocol in both the Rust
substrate (`yutha-signer`) and the Python SDK (`yutha.crypto`). The
trait is the only authorised path through which Yutha calls Ed25519
sign — passports, envelopes, capabilities, receipts, and bearer
tokens all flow through it.

Two invariants in RFC 0015 §3.1 make the wire path testable
independently of any specific implementation:

1. **`InProcessSigner` is byte-equivalent to raw `SigningKey::sign_message`.**
   The trait wraps an `Ed25519` keypair; the wrapper MUST NOT change
   the math. This is what makes the trait safe to roll out as a
   refactor — every existing signature stays valid.
2. **Ed25519 is deterministic.** Given a fixed seed and a fixed
   message, `(public_key, signature, key_fingerprint)` is a
   single triple. Any implementation that wraps a different
   Ed25519 library (libsodium, ed25519-zebra, an HSM driver) MUST
   produce the same triple.

These vectors freeze that triple for 16 representative (seed, message)
inputs. Any implementation — current or future, any language, any
custody backend — that fails a vector is by definition non-conformant.

The third category, concurrent-sign safety, is a runtime behavioral
contract; it doesn't have JSON fixtures but is described in
[`concurrent-safety.md`](./concurrent-safety.md) and exercised by
`yutha-signer`'s `concurrent_sign_safety` unit test.

## Layout

```
/spec/vectors/signer
├── README.md                ← you are here
├── concurrent-safety.md     ← runtime concurrent-sign contract
└── /sign-and-verify         ← 16 deterministic (seed, message) fixtures
    ├── README.md            ← format spec
    └── *.json
```

## Regenerating

When the spec legitimately changes (a new RFC repins the seed→key
derivation, or Ed25519 itself moves — which it won't), regenerate the
expected hex fields:

```bash
YUTHA_REGENERATE_VECTORS=1 cargo test -p yutha-signer --test vectors
git diff spec/vectors/signer/    # review every change
```

The test rewrites the `expected_*_hex` fields in each fixture instead
of asserting on them. Commit the rewrites; then re-run normally
(`cargo test -p yutha-signer --test vectors`) to verify the assertion
path passes against the committed values.

If you change vectors *without* a corresponding spec change, you are
by definition breaking cross-implementation byte-equivalence — open
an RFC.

## Cross-language extension

Today the only first-party implementation is Rust's
`yutha-signer::InProcessSigner` plus the Python
`yutha.crypto.InProcessSigner` (which round-trips through the same
`cryptography.hazmat.primitives.asymmetric.ed25519` lib). Future
implementations — a Go SDK, a Rust HSM driver, a Vault transit
backend — must add their own test loaders that consume these JSON
files and assert the same expected hex.

A future cross-language CI step (akin to `/interop/go/` for receipt
canonical bytes) will run all such loaders in lockstep on every PR
that touches the Signer surface.

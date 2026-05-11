# yutha-crypto

Cryptographic primitives for Yutha. Wraps audited Rust libraries — `ed25519-dalek` for signing, `sha2` for hashing — behind APIs that match the value types in `yutha-core`.

## What's here

- **Hashing**: SHA-256, returning `yutha_core::Hash`.
- **Signing**: Ed25519 keygen, sign, verify, returning `yutha_core::Signature` and `yutha_core::PublicKey`.
- **Canonical serialization helpers**: tooling to produce the bytes that get hashed for content-addressing (per [`/spec/README.md`](../../spec/README.md) §5).
- **Key fingerprints**: SHA-256 of public key bytes.

## What's NOT here

- Signature schemes other than Ed25519 (until a future RFC adds one).
- Encryption-at-rest primitives (lives in `backends/seal-encrypt` because it is store-layer).
- Custom protocols. Use the audited primitives or file an RFC.

## Threat-model linkage

This crate is the cryptographic substrate. Per CODEOWNERS, every change requires Workstream L (security) review.

## Reference

- [`/spec/README.md`](../../spec/README.md) §4 — crypto baseline.
- ADR 0001 — language choice (informs why we wrap `ring`/`ed25519-dalek` rather than building custom).

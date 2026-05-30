# yutha-signer

Pluggable signing-key custody for Yutha. Implements [RFC 0015](../../spec/rfcs/0015-signer-interface.md).

## What it is

The `Signer` trait is the single abstraction every Ed25519 signing operation in Yutha flows through:

```rust
#[async_trait]
pub trait Signer: Send + Sync + Debug {
    fn public_key(&self) -> PublicKey;
    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError>;
}
```

Implementations:

- **`InProcessSigner`** — the zero-dependency default. Wraps `yutha_crypto::SigningKey` byte-for-byte. What hobby swarms and development workflows run today.
- **`yutha-signer-gcp-kms`** *(separate crate, Phase C)* — GCP Cloud KMS-backed.
- **`yutha-signer-azure-kv`** *(separate crate, Phase C)* — Azure Key Vault Managed HSM-backed.
- **`yutha-signer-vault-transit`** *(separate crate, Phase C)* — HashiCorp Vault transit engine. The recommended path for enterprises on AWS, since AWS KMS doesn't yet support Ed25519.

## Why it exists

A production agent deployment cannot keep signing keys in process memory. Every security review of every enterprise integration asks the same question first: "where do the signing keys live, and who has access to them?" Today Yutha's answer is "in the agent's process; whoever owns the process owns the keys." That answer doesn't pass.

The `Signer` trait is the smallest change that turns "key custody is enterprise-blocking" into "key custody is configurable." The native default stays exactly as fast and as dependency-free as today; enterprise paths plug in without touching the substrate.

See [RFC 0015](../../spec/rfcs/0015-signer-interface.md) for the full design and [/spec/identity-keys/README.md](../../spec/identity-keys/README.md) for the framing.

## What this crate ships

- `Signer` trait (async).
- `SignerError` enum.
- `InProcessSigner` — the default implementation wrapping `yutha_crypto::SigningKey`.
- Conformance helpers for the three trait gates described in RFC 0015 §3.7 (signature equivalence to raw `SigningKey`, signature verifies under reported public key, concurrent-sign safety).

## What this crate does NOT ship

- Cloud KMS implementations — those live in `yutha-signer-gcp-kms`, `yutha-signer-azure-kv`, `yutha-signer-vault-transit`.
- Raw-key-export pathways. The trait shape forbids it; even `InProcessSigner` does not expose a way to retrieve the wrapped private bytes through the trait.

## Status

Phase B of the identity-keys workstream. The trait is the contract every downstream Yutha crate signs through; substrate refactor to use it lands in Phase B sub-stages B2–B7 (passport, envelope, capability, control-plane, Python SDK).

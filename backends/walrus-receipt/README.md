# yutha-backend-walrus-receipt

Verifiable-tier reference implementation of the Yutha `ReceiptStore`. Uses Walrus for receipt storage, Seal for memory-encryption integration, and Nautilus for attestation.

## Status

**Skeleton.** Cargo.toml and the trait shell are in place; method bodies are `todo!()` pending implementation. PRD §8.4 commits this backend to passing the **same conformance suite** as the default Postgres backend at Phase 1 exit; the existence proof is what makes backend neutrality credible (build-plan.md §10).

## Design

- **Walrus**: append-only storage of canonical receipt bytes with content-address keying. Walrus's data-availability guarantees give us the durability story for verifiable tier.
- **Seal**: encryption-at-rest for sensitive evidence fields (those with `sensitive=true`). Selective disclosure proofs are derived against Seal-encrypted blobs.
- **Nautilus**: attestation. Receipts at this tier carry a `SignatureRole::Attestation` signature produced by the enclave that processed them, binding the action to the hardware/enclave identity.

## Conformance

Targets **Verifiable** tier per [`/docs/internal/conformance-suite.md`](../../docs/internal/conformance-suite.md) §3.3. The same Core + Full tests run against this backend; additionally:

- Receipts are mutually recognizable across organizations using only public keys.
- Cryptographic chain enables cross-store verification without trusting either operator.
- Receipt batches are sealed (Merkle-rooted).
- Selective-disclosure proofs reveal a single receipt without revealing the rest.

## Reference

- [`/spec/receipt/`](../../spec/receipt/)
- [`/docs/internal/build-plan.md`](../../docs/internal/build-plan.md) §6 — Phase 1 verifiable-backend gate.

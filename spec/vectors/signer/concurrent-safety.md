# Signer — concurrent-sign safety contract

A runtime behavioral contract, not a wire-bytes vector. Documented
here for cross-implementation parity; exercised in Rust by the
`concurrent_sign_safety` unit test in
[`crates/yutha-signer/src/inprocess.rs`](../../../crates/yutha-signer/src/inprocess.rs).

## Contract

A conforming `Signer` (or `InProcessSigner` specifically) MUST be
safe to share across many concurrent tasks. Given:

- one `Arc<dyn Signer>` shared across N tasks,
- each task producing M distinct messages,

then:

1. All N × M signatures MUST verify under the signer's public key.
2. For any given message bytes, every signature produced anywhere
   in the test is byte-identical (Ed25519 is deterministic — same
   key + same message ⇒ same signature, regardless of which task
   produced it).
3. The signer's `public_key()` MUST be invariant across all calls
   from any task.
4. No data race may surface — no panic, no torn read, no UB.

## Rust reference test

`crates/yutha-signer/src/inprocess.rs::tests::concurrent_sign_safety`
spawns 32 tasks × 4 signatures each = 128 total signing operations
against a single `Arc<dyn Signer>`. Asserts every signature
verifies, and asserts deterministic-Ed25519 invariance by
re-signing a fixed message twice from a separate signer to confirm
byte-identical output across calls.

## Cross-language implementations

A conforming implementation in another language MUST provide its
own concurrent-safety test along these lines. The exact knobs
(N tasks, M messages, message lengths) may vary; the four
invariants above are what must hold.

The reason this is a contract rather than a JSON vector: the test
exercises runtime properties (no panics under contention, no
data races) that aren't expressible as deterministic byte
equality. JSON fixtures cover the math; this document covers the
threading.

# Signer — sign-and-verify vectors

Sixteen deterministic `(seed, message)` inputs and the
`(public_key, signature, key_fingerprint)` triples they MUST produce
under any conforming Ed25519 signer.

## Format

Each `*.json` file contains:

```jsonc
{
  "name": "<short-slug>",
  "description": "<what this vector exercises>",
  "kind": "signer-sign-and-verify",
  "inputs": {
    "seed_hex": "<64-char hex = 32 bytes>",
    "message_hex": "<2*N-char hex = N bytes>"
  },
  "expected_public_key_hex": "<64-char hex = 32 bytes>",
  "expected_key_fingerprint_hex": "<64-char hex = 32 bytes = SHA-256(public_key)>",
  "expected_signature_hex": "<128-char hex = 64 bytes>"
}
```

### Conventions

- **Hex** is lowercase, no `0x`, no separators.
- **`seed_hex`** is exactly 64 chars (32 bytes), the raw Ed25519 seed
  (NOT the PKCS#8-encoded private key).
- **`message_hex`** may be empty (`""`); the spec doesn't
  pre-hash and Ed25519 signs arbitrary-length byte strings directly.
- **`expected_signature_hex`** is the 64-byte Ed25519 signature in the
  RFC 8032 encoding (R || s, both little-endian, each 32 bytes).
- **`expected_key_fingerprint_hex`** is `SHA-256(public_key_bytes)`,
  matching `yutha_crypto::fingerprint_public_key` on the Rust side and
  `yutha.crypto.fingerprint_public_key` on the Python side.

### What conformance means

For every vector, a conforming implementation MUST:

1. Construct an `InProcessSigner` (or equivalent) from `seed_hex`.
2. Report `public_key()` == `expected_public_key_hex`.
3. Produce `sign_message(message)` whose `.value` ==
   `expected_signature_hex` and whose `.key_fingerprint` ==
   `expected_key_fingerprint_hex`.
4. Verify the produced signature under the reported public key (the
   RFC 8032 round-trip).

The Rust test at `crates/yutha-signer/tests/vectors.rs` exercises all
four checks per fixture against both `InProcessSigner::from_bytes`
and raw `yutha_crypto::SigningKey::from_bytes`, asserting they
produce byte-identical output (the load-bearing "wrapper doesn't
change the math" gate).

## Why 16

Coverage matrix:

| Seed pattern    | Message pattern         | Vector files |
|-----------------|-------------------------|--------------|
| All-zero        | empty / "hello world"   | 2 |
| All-one         | 32-byte / 64-byte       | 2 |
| All-`0xff`      | empty / 1-byte          | 2 |
| All-`0xaa`      | 16-byte / 128-byte      | 2 |
| Ascending       | 1-byte / 32-byte        | 2 |
| Descending      | empty / 256-byte        | 2 |
| Alternating     | 8-byte / 64-byte        | 2 |
| Hash-derived    | spec-version-shaped     | 2 |

8 seed patterns × 2 message lengths each = 16 vectors. Exercises the
edge cases (empty input, all-zero/all-one/all-ff seed clamping, long
messages) without ballooning.

## Adding a vector

1. Pick a `(seed_hex, message_hex)` pair by hand. Don't extract
   it from an existing trace — vectors should be deliberate.
2. Create a new `*.json` with empty `expected_*_hex` fields.
3. Run `YUTHA_REGENERATE_VECTORS=1 cargo test -p yutha-signer --test vectors`
   once to populate the expected hex.
4. Commit the new fixture.
5. Re-run `cargo test -p yutha-signer --test vectors` normally to
   verify the committed values pass assertion mode.

## Vectors

| File | Exercises |
|------|-----------|
| [`seed_zero_empty_msg.json`](seed_zero_empty_msg.json) | All-zero seed, empty message — boundary case. |
| [`seed_zero_hello_world.json`](seed_zero_hello_world.json) | All-zero seed with "hello world". |
| [`seed_one_msg_32.json`](seed_one_msg_32.json) | All-`0x01` seed, 32-byte message. |
| [`seed_one_msg_64.json`](seed_one_msg_64.json) | All-`0x01` seed, 64-byte message. |
| [`seed_ff_empty_msg.json`](seed_ff_empty_msg.json) | All-`0xff` seed, empty message — high-bit clamping case. |
| [`seed_ff_msg_1.json`](seed_ff_msg_1.json) | All-`0xff` seed, single-byte message. |
| [`seed_aa_msg_16.json`](seed_aa_msg_16.json) | All-`0xaa` seed, 16-byte message. |
| [`seed_aa_msg_128.json`](seed_aa_msg_128.json) | All-`0xaa` seed, 128-byte message. |
| [`seed_ascending_msg_1.json`](seed_ascending_msg_1.json) | Seed `00..1f`, single-byte message. |
| [`seed_ascending_msg_32.json`](seed_ascending_msg_32.json) | Seed `00..1f`, 32-byte message. |
| [`seed_descending_empty_msg.json`](seed_descending_empty_msg.json) | Seed `ff..e0`, empty message. |
| [`seed_descending_msg_256.json`](seed_descending_msg_256.json) | Seed `ff..e0`, 256-byte message — long-input case. |
| [`seed_alternating_msg_8.json`](seed_alternating_msg_8.json) | Seed `5a5a..`, 8-byte message. |
| [`seed_alternating_msg_64.json`](seed_alternating_msg_64.json) | Seed `5a5a..`, 64-byte message. |
| [`seed_hash_derived_short.json`](seed_hash_derived_short.json) | Hash-derived seed (sha256("yutha-vector-1")), short message. |
| [`seed_hash_derived_spec.json`](seed_hash_derived_spec.json) | Hash-derived seed (sha256("yutha-vector-2")), `"yutha-spec-v1.0.0"` message. |

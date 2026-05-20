# Sui anchoring — canonical preimage conformance vectors

Byte-equality test vectors for the canonical preimage encoder
specified in [`/spec/verifiability/sui-anchoring.md`](../../../verifiability/sui-anchoring.md) §4.

Two independent encoders must produce identical bytes for these
inputs:

- **Rust** — `yutha_receipt::canonical_preimage` in
  `crates/yutha-receipt/src/preimage.rs`. The off-chain sealer
  signs these bytes.
- **Move** — `build_canonical_preimage` in
  `contracts/sui/receipt_anchor/sources/receipt_anchor.move`. The
  on-chain `commit_batch` reconstructs them before
  `ed25519_verify`.

If the two encoders ever diverge (e.g., a future spec change
applied to one side but not the other), every `commit_batch`
aborts with `ESealerKeyMismatch` (code 9). These vectors catch
that class of drift at test time rather than at production
commit time.

## Format

Each `*.json` file in this directory contains:

```jsonc
{
  "name": "<short-slug>",
  "description": "<what this vector exercises>",
  "inputs": {
    "swarm_id_hex": "<32-char hex = 16 bytes>",
    "batch_root_hex": "<64-char hex = 32 bytes, SHA-256-shaped>",
    "count": <u64>,
    "ns_range_start": <u64>,
    "ns_range_end": <u64>,
    "histogram": [
      ["<action_kind_string>", <u64 count>],
      ...
    ]
  },
  "expected_preimage_hex": "<2*N-char hex>"
}
```

The histogram array's iteration order in the JSON is irrelevant
for the inputs — both encoders normalize to lex-ascending UTF-8
byte order before encoding. The vectors are written in pre-sorted
order purely for human readability.

## Vectors

| File | Exercises |
|------|-----------|
| [`single_kind_minimal.json`](single_kind_minimal.json) | One receipt of one action_kind, 16-byte swarm_id `0x42×16`, equal ns_range bounds. Smallest valid batch. |
| [`multi_kind_lex_sort.json`](multi_kind_lex_sort.json) | Three action_kinds with overlapping prefixes (`envelope.deliver` vs `envelope.send`) that exercise the lex-ascending sort. ns_range spans 1000–2000. |

Adding a vector: pick inputs by hand, compute the expected bytes
following §4 of the spec literally (don't run either encoder to
"generate" the expected — that defeats the cross-implementation
agreement check). Then add it to both the Rust test loader in
`crates/yutha-receipt/tests/preimage_vectors.rs` and the Move
`#[test_only]` function in `receipt_anchor.move`.

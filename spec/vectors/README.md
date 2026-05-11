# Yutha wire vectors

> **Purpose.** These JSON files describe specific, deterministic inputs and the canonical wire bytes they MUST produce. They are how we verify that two implementations of the Yutha spec (e.g., this repo's Rust impl and a Go impl in `/interop/go/`) agree on the bytes at the level of every individual receipt.

## Why this exists

The receipt-store conformance suite (`/crates/yutha-conformance/src/receipt.rs`) verifies *behavior* — appends, queries, idempotency, durability. It does not verify the *wire bytes*. A backend can pass that suite while encoding receipts in a way no other implementation would recognize.

These vectors close that gap. Each vector is a frozen contract: "given exactly these input field values, the canonical bytes are exactly these hex digits." A new implementation, in any language, that fails to produce the same bytes on a vector is by definition non-conformant — regardless of what the rest of its tests say.

## Format

Each vector is a JSON document. The schema is informal but stable; breaking changes require an RFC.

```jsonc
{
  "name": "minimal",                                  // stable id used in test output
  "description": "Receipt with only required fields", // human note
  "kind": "receipt",                                  // which message type this vector is for

  // The receipt fields. All bytes are hex-encoded; all strings are literal.
  "fields": {
    "spec_version": "1.0.0",
    "swarm_id_hex": "0102030405060708090a0b0c0d0e0f10",
    "actor_hex":    "1112131415161718191a1b1c1d1e1f20",
    "action_kind": "envelope.send",
    "constitution_version": "1.0.0",
    "occurred_at": { "wall_clock": "2026-05-10T00:00:00Z", "monotonic_ns": 1000 },
    "predecessors_hex": [],
    "evidence": [],
    "cost": null
  },

  // Canonical bytes after to_canonical_proto() + prost encode, hex-encoded.
  // Populated by running the Rust test with YUTHA_REGENERATE_VECTORS=1 once;
  // committed thereafter as the contract.
  "expected_canonical_hex": "0a05312e302e30..."
}
```

### Conventions

- **Hex** is lowercase, no `0x`, no separators. Identifiers are 16 bytes / 32 hex chars; hashes are 32 bytes / 64 hex chars.
- **Strings** are literal. No interpolation, no `now()`, no `new()`. Deterministic input is the whole point.
- **Optional fields** (`cost`, `seal`, `signatures`, `extensions`) are either absent or explicitly `null` / `[]`. Vectors deliberately do not exercise signature or seal bytes — those are cleared by `to_canonical_proto()` before encoding, so they don't appear in the canonical output. A future vectors directory can cover *signed* receipt bytes if/when a separate "signing fixture" pattern emerges.

### Encoding requirements

The canonical bytes are produced by:

1. Building a `Receipt` (or other typed message) from the declared fields.
2. Calling `to_canonical_proto()` to clear signature / seal / extensions.
3. Encoding the resulting proto message with **deterministic** options:
   - In Rust (prost): tag-sorted field order is the default; map fields use `BTreeMap` per `yutha-proto`'s `build.rs`.
   - In Go (`google.golang.org/protobuf`): `proto.MarshalOptions{Deterministic: true}.Marshal(...)`.
   - In other languages: whatever idiom the runtime exposes for tag-sorted, sorted-map encoding.

Any implementation that meets these requirements MUST produce the bytes listed in `expected_canonical_hex` for every vector here.

## Regenerating

When a spec change legitimately changes the wire format:

```bash
YUTHA_REGENERATE_VECTORS=1 cargo test -p yutha-receipt --test vectors
git diff spec/vectors/  # review the changes
```

The Rust test rewrites `expected_canonical_hex` in each fixture instead of asserting on it. Commit the rewrites, then re-run normally to verify the diff is what you expected.

If you change vectors *without* a spec change, you are by definition breaking wire compatibility — please open an RFC.

## Layout

```
/spec/vectors
├── README.md           ← you are here
└── /receipt
    ├── minimal.json
    ├── with_evidence.json
    ├── with_cost.json
    └── with_predecessors.json
```

Future directories: `/passport`, `/envelope`, `/capability`. Same pattern.

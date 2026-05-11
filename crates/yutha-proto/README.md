# yutha-proto

Prost-generated Rust types from the Yutha protobuf specs in `/spec/`.

## What's here

- Generated Rust code for every `.proto` file in `/spec/`:
  - `yutha_proto::common::v1`
  - `yutha_proto::passport::v1`
  - `yutha_proto::envelope::v1`
  - `yutha_proto::receipt::v1`
  - `yutha_proto::capability::v1`
  - `yutha_proto::topology::v1`
- Re-export of `prost::Message` for ergonomic encoding (`.encode_to_vec()`).

## What's NOT here

- Ergonomic Rust types — those live in the consumer crates (`yutha-receipt`, `yutha-passport`, etc.). The generated types are the wire-format representation; the consumer crates provide builder APIs, type-safe IDs, etc.
- Hand-written validation logic — the consumer crates own validation.

## Determinism

The build is configured to use `BTreeMap` for every map field via `prost_build::Config::btree_map(["."])`. This guarantees deterministic serialization (HashMap iteration order is not stable across runs); maps encode with keys in sorted order. Combined with prost's tag-sorted field encoding, this gives us bytewise-equivalent canonical encoding across Rust runs — and (with care) across implementations in other languages that emit deterministic protobuf.

## Protoc

The `protoc` compiler is required at build time. We use `protoc-bin-vendored` so the binary is bundled with the crate — contributors don't need a system install. CI also installs protoc as a belt-and-suspenders measure.

## Regenerating

`cargo build -p yutha-proto` regenerates whenever any `.proto` file changes (the build script sets `cargo:rerun-if-changed=` for each).

## Reference

- [`/spec/`](../../spec/) — source-of-truth protobuf files
- [RFC 0001](../../spec/rfcs/0001-rfc-process.md) — RFC process for spec changes

# Yutha interop

> **Purpose.** Cross-language proof that the Yutha wire format is portable. Each subdirectory is a minimal implementation of the spec in a different language — just enough to read the JSON fixtures in [`/spec/vectors/`](../spec/vectors/), encode the same logical message, and assert bytewise equivalence with the reference Rust implementation.
>
> A second language implementation that matches every committed `expected_canonical_hex` is what turns "prost emits deterministic bytes" into "the wire contract is real."

## What's here

```
/interop
├── /go     ← Go implementation using protoc-gen-go + google.golang.org/protobuf
└── (more languages welcome — open an RFC if you want to add one)
```

Each subdirectory is self-contained:

- Its own build/test toolchain (no cargo, no Rust). The Rust repo doesn't depend on these directories; they exist purely as conformance witnesses.
- A short README explaining setup specific to that language.
- A test that reads `/spec/vectors/receipt/*.json`, encodes per spec, and asserts hex match.

## What this is NOT

- **Not a production SDK.** The Python / TypeScript / Go SDKs that real applications will use live in `/sdks/` (when they exist) and are a different concern.
- **Not a full spec implementation.** Interop modules implement just enough of the wire types to encode the vectors. They don't implement signing, verification, or storage.

## Adding a new language

A reasonable interop module is:

- 100–300 lines of source.
- Uses a stock proto3 library for the target language (so what we're really proving is "stock library + spec = same bytes").
- Has a single test target that walks every vector and asserts.
- Documents how to install its toolchain.

If you want to add one and the test passes, the next step is an RFC declaring the language a conformant target.

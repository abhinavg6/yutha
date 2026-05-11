# Yutha interop — Go

Go implementation of the Yutha wire format, used as a differential-conformance witness against the Rust reference implementation.

## What it does

`vectors_test.go` reads every JSON fixture under `/spec/vectors/receipt/`, builds the declared `Receipt` using `protoc-gen-go`-generated bindings, encodes deterministically (`proto.MarshalOptions{Deterministic: true}`), and asserts the resulting hex equals the fixture's `expected_canonical_hex`. The expected hex is the same one the Rust test asserts against — so a passing Go test plus a passing Rust test means both implementations produce the *same bytes* for the same logical input.

## Setup (one-time)

You need `protoc` and `protoc-gen-go` on `PATH`:

```bash
# macOS:
brew install protobuf
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
# Make sure $(go env GOPATH)/bin is on your PATH so protoc can find protoc-gen-go.

# Then, from this directory:
make regen      # generate Go bindings from /spec/*.proto into ./gen/
go mod tidy     # populate go.sum
```

`make regen` writes generated Go code to `./gen/yutha/common/v1/` and `./gen/yutha/receipt/v1/`. The generated files are committed so subsequent contributors can run `make test` without protoc; rerun `make regen` whenever a tracked `.proto` file changes.

## Running

```bash
make test       # or: go test ./...
```

Expected output: every vector passes; no diff against `expected_canonical_hex`.

When this test passes alongside the Rust `cargo test -p yutha-receipt --test vectors`, the wire contract is empirically cross-language.

## Failure modes

| Symptom | Likely cause |
|---|---|
| `package github.com/.../gen/... is not in std` | You haven't run `make regen` yet. |
| `protoc: command not found` | Install via `brew install protobuf`. |
| `protoc-gen-go: program not found` | Install the plugin and put `$(go env GOPATH)/bin` on PATH. |
| Hex mismatch on a single vector | The Rust and Go encoders disagree — file an issue with both hex strings and the fixture name. This is the test doing its job. |

## What this is NOT

Not a Go SDK. There's no signing, no transport, no storage. Just enough to encode the wire types and verify the bytes match.

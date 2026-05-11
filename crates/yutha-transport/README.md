# yutha-transport

Typed envelope transport for Yutha. Mirrors [`/spec/envelope/envelope-v1.proto`](../../spec/envelope/envelope-v1.proto).

## What's here

- **`Envelope`** struct with `Canonical` impl; eleven **`Performative`** variants from the spec.
- **`Recipient`** oneof (agent / role / swarm / external).
- **`Transport`** trait with send / receive.
- **`MemoryTransport`**: channel-based in-memory transport for tests and the embedded quickstart.
- **`ReplayProtection`**: per-sender nonce + epoch tracking with TTL pruning. The substrate defense against A5 (network adversary).

## What's NOT here

- NATS / gRPC wire encoding — skeletons only (NATS adapter lands next as a real implementation; gRPC framing follows after prost-bindings are wired in).
- Federation transport profile — Phase 4.
- Constrained-transport profile (intermittent connectivity, partition tolerance) — Phase 3.

## Threat-model linkage

A3 (prompt injection — typed envelopes cannot be synthesized from payload bytes), A5 (network adversary — replay protection, TLS at the wire layer per ADR 0001).

## Reference

- [`/spec/envelope/`](../../spec/envelope/)
- [`/spec/envelope/rationale.md`](../../spec/envelope/rationale.md)
- [RFC 0003](../../spec/rfcs/0003-envelope-v1.md)

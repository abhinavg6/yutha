# yutha-registry

Membership controller for Yutha. Mirrors [`/spec/topology/topology-v1.proto`](../../spec/topology/topology-v1.proto).

## What's here

- **`Topology`** struct: swarm-mode declaration + admission policy + default knobs (cap lifetime, envelope TTL, chain depth, replay window).
- **`TopologyMode`** + **`AdmissionPolicy`** with three variants (closed / open / hybrid).
- **`SybilResistanceRequirement`** with five variants: proof-of-work, hardware attestation, IdP attestation, stake, invite. Skeletons at scaffolding level.
- **`Registry`** trait — `start`, `register`, `revoke`. Consumes passport store + capability store.
- **`MemoryRegistry`** in-memory reference impl. Admits per the topology's policy; produces registration outcomes.

## What's NOT here

- Production sybil-resistance mechanisms (proof-of-work verifier, attestation chain validators, IdP integration). Currently `todo!()` or trivial-accept skeletons.
- Receipt production — when the registry wires into the full control plane it produces `agent.register` receipts; at this scaffolding level the registration outcome carries `registration_receipt: None`.
- Topology migration receipts — open question, deferred.

## Threat-model linkage

A1 (admission gating), A6 (sybil resistance — five mechanism options), A8 (topology immutability prevents in-place privilege escalation).

## Reference

- [`/spec/topology/`](../../spec/topology/)
- [`/spec/topology/rationale.md`](../../spec/topology/rationale.md)
- [RFC 0006](../../spec/rfcs/0006-topology-v1.md)

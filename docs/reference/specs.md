# Specs

The Yutha specs live under [`/spec/`](https://github.com/abhinavg6/yutha/tree/main/spec) in the repo. They are versioned, RFC-governed, and the canonical source of truth for the wire and artifact formats.

- **[Passport](https://github.com/abhinavg6/yutha/tree/main/spec/passport)** — agent identity, key formats, issuance, revocation.
- **[Envelope](https://github.com/abhinavg6/yutha/tree/main/spec/envelope)** — typed messages between agents.
- **[Receipt](https://github.com/abhinavg6/yutha/tree/main/spec/receipt)** — append-only signed records of consequential actions.
- **[Capability](https://github.com/abhinavg6/yutha/tree/main/spec/capability)** — bounded, attenuable authority tokens.
- **[Topology](https://github.com/abhinavg6/yutha/tree/main/spec/topology)** — closed, open, hybrid swarm shapes.
- **[Constitution](https://github.com/abhinavg6/yutha/tree/main/spec/constitution)** — Cedar+ schema, evaluation semantics, enforcement contract.
- **[Verifiability](https://github.com/abhinavg6/yutha/tree/main/spec/verifiability)** — Sui anchoring, canonical preimage encoding.

Wire conformance is enforced via [JSON test vectors](https://github.com/abhinavg6/yutha/tree/main/spec/vectors) that every implementation (Rust, Go, Move) must round-trip identically.

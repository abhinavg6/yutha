# Primitives

!!! info "Page in progress"
    Full content is being written. Until then, the authoritative references are the specs in [`/spec/`](../reference/specs.md) — passport, envelope, receipt, capability, and topology each have a dedicated spec doc with rationale.

A Yutha swarm is built from four primitives:

- **Passport** — a verifiable agent identity. Ed25519-keyed, operator-issued, revocable.
- **Envelope** — a typed message between agents. Has a sender, a recipient (or role, or swarm-wide broadcast), a typed action kind, and a payload.
- **Receipt** — an append-only, signed record of a consequential action. Content-addressed, deterministic, replayable.
- **Capability** — a first-class authority token. Bounded, attenuable, revocable, cascadable. Cap checks happen at the control plane, not in agent code.

Everything else in the system is a composition of these four.

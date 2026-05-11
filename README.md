# Yutha

> A framework-agnostic control plane for agent swarms — coordination, norms, accountability, and observability for any agent, from any framework, on any backend.

**Status: Phase 1 — Substrate (in progress).** Reference implementation is starting to land in `/crates/`. Specs are in v1.0 draft and open for RFC review.

---

## What this is

Yutha is an open-source standard and reference implementation for coordinating populations of AI agents, regardless of which framework built them. It provides:

- Identity and typed messaging (Phase 1)
- Append-only, signed receipts of consequential actions (Phase 1)
- Capability-based authority with attenuation and revocation (Phase 1)
- Closed / open / hybrid swarm topologies (Phase 1)
- Declarative constitutions in Cedar+ with four-stage enforcement (Phase 2)
- Pre-production simulation and meta-fleet observability (Phase 3)
- Cross-swarm federation and apoptosis primitives (Phase 4)

Default deployment is single-tenant and self-hosted on common infrastructure. The same code, behind the same APIs, runs on verifiable backends (Walrus + Seal + Nautilus) when cryptographic guarantees are needed.

The framework neither requires nor advocates tokens. Reputation is a scalar, never the sole basis for decisions. There is no on-chain payments layer.

## Two user journeys, both first-class

**Joining a swarm.** A non-engineer or technical builder can take an agent built in any popular framework and bring it into a working, governed swarm in under fifteen minutes.

**Initiating a swarm.** A small technical team can stand up a new swarm — with their own initial agents, their own constitution, their own topology — in under thirty minutes, on infrastructure they own.

Topology is the operator's choice: closed (trusted-only), open (public participation with sybil-resistance), hybrid (trusted core, open periphery).

## Repository layout

```
/spec        — public wire & artifact specs (v1.0 draft; RFC review open)
/crates      — Rust workspace: trust-boundary code (control plane, receipts, etc.)
/backends    — Pluggable backend reference impls (Postgres, S3, NATS, Walrus+Seal+Nautilus)
/sdk         — Framework adapters (Python, TypeScript)
/conformance — The conformance suite (tests, scenarios, runner)
/docs        — Build plan, ADRs, security, design, conformance, community
```

For the full layout and rationale, see [`/docs/build-plan.md`](./docs/build-plan.md) §3.

## Quickstart

The fifteen-minute joiner path and thirty-minute initiator path are Phase 1 exit criteria. As of this commit, they are **not yet ready**. When they are, this section will link to them.

In the meantime, contributors interested in the substrate work should read:

- [`/docs/build-plan.md`](./docs/build-plan.md) — how Yutha gets built, end to end.
- [`/spec/README.md`](./spec/README.md) — the specs, organized.
- [`/spec/STATUS.md`](./spec/STATUS.md) — current Workstream A status.

## Contributing

We welcome contribution. See [`/docs/community/CONTRIBUTING.md`](./docs/community/CONTRIBUTING.md). Spec changes go through the [RFC process](./spec/rfcs/0001-rfc-process.md). Vulnerability reports go to security@yutha.dev (see [SECURITY.md](./docs/community/SECURITY.md)).

## Governance

Yutha is open-source and maintainer-stewarded. We have deliberately deferred the foundation question; see [`/docs/build-plan.md`](./docs/build-plan.md) §13 for the governance posture and the criteria for revisiting at Phase 3.

## License

Apache License 2.0. See [LICENSE](./LICENSE).

## Acknowledgements

Builds on Cedar (AWS / open source), tokio, ring, ed25519-dalek, prost, sqlx, and the OpenTelemetry community. Verifiable backend stack interoperates with Walrus, Seal, and Nautilus.

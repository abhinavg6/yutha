# Yutha

> **A framework-agnostic control plane for agent swarms.** Identity, capability, accountability, and norms — for agents from any framework, on any backend.

Multi-agent systems work in demos and break in production. The reason is almost always the same: there's no shared substrate for *who an agent is*, *what it's allowed to do*, *what it actually did*, and *which norms govern the swarm it lives in*. Each framework reinvents a fragment of that and stops.

Yutha is the substrate. It runs in front of agents you've already built — in [LangGraph](https://github.com/langchain-ai/langgraph), [CrewAI](https://www.crewai.com/), or anything else you'd like to write an adapter for — and gives them passports, signed receipts, attenuated capabilities, declarative constitutions ([Cedar](https://github.com/cedar-policy)+) with four-stage enforcement, and an optional cryptographic verification layer ([Sui](https://www.sui.io/) anchoring) when you need to prove what happened to a third party.

## Full documentation

**→ [yutha.ai](https://yutha.ai)** — concepts, operator guide, developer guide, and worked examples.

The doc site is the canonical reference. Start at the landing page; pick the operator guide if you're running a swarm, the developer guide if you're building agents that join one.

## What's here

```
/spec        — wire & artifact specs (RFC-governed)
/crates      — Rust workspace: control plane, registry, capability, transport, receipts, cedar+ engine
/backends    — Pluggable backends: Postgres, S3, Sui anchoring, Walrus, Seal, Nautilus
/sdks        — Framework adapters (Python: LangGraph, CrewAI)
/contracts   — Move package for Sui receipt anchoring
/docs        — Source for the doc site at yutha.ai
```

## Quickstart

The fifteen-minute joiner path (developer) and thirty-minute initiator path (operator) live on the doc site under [Developer Guide → Quickstart](https://yutha.ai/developer/quickstart/) and [Operator Guide → Quickstart](https://yutha.ai/operator/quickstart/) respectively.

If you want to poke locally without the doc site:

- **End-to-end LangGraph example.** A customer-support swarm with capability-gated messaging, operator-driven eviction, and a verifiable audit trail. Runnable demo at [`sdks/python/examples/s1_support_queue.py`](./sdks/python/examples/s1_support_queue.py); walkthrough at [`docs/developer/langgraph.md`](./docs/developer/langgraph.md).
- **Conformance suite.** `cargo test -p yutha-conformance` runs the in-process scenarios covering the receipt log, send-path enforcement, operator revocation, and constitution evaluation.

## Contributing

See [CONTRIBUTING.md](./docs/community/CONTRIBUTING.md). The project is stewarded by a single maintainer ([@abhinavg6](https://github.com/abhinavg6)); guidelines are intentionally light.

Spec changes go through the [RFC process](./spec/rfcs/0001-rfc-process.md). Vulnerability reports go to [GitHub private security advisories](https://github.com/abhinavg6/yutha/security/advisories/new) — see [SECURITY.md](./docs/community/SECURITY.md).

## License

Apache License 2.0. See [LICENSE](./LICENSE).

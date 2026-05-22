# Yutha

> **A framework-agnostic control plane for agent swarms.** Identity, capability, accountability, and norms — for agents from any framework, on any backend.

[![Release](https://img.shields.io/github/v/release/abhinavg6/yutha?include_prereleases&label=release&color=orange)](https://github.com/abhinavg6/yutha/releases)
[![PyPI](https://img.shields.io/pypi/v/yutha?label=pypi&color=blue)](https://pypi.org/project/yutha/)
[![License: Apache 2.0](https://img.shields.io/github/license/abhinavg6/yutha)](LICENSE)
[![CI](https://github.com/abhinavg6/yutha/actions/workflows/ci.yml/badge.svg)](https://github.com/abhinavg6/yutha/actions/workflows/ci.yml)
[![Docs](https://github.com/abhinavg6/yutha/actions/workflows/docs.yml/badge.svg)](https://github.com/abhinavg6/yutha/actions/workflows/docs.yml)

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

## Install the Python SDK

```bash
pip install yutha                    # core SDK
pip install 'yutha[langgraph]'       # + LangGraph adapter
pip install 'yutha[crewai]'          # + CrewAI adapter
```

Python 3.11+. The control plane is a Rust binary — clone the repo and `cargo run -p yutha-control-plane` to bring one up, or follow the [operator quickstart](https://yutha.ai/operator/quickstart/) for the longer playbook.

## Quickstart

The fifteen-minute joiner path (developer) and thirty-minute initiator path (operator) live on the doc site under [Developer Guide → Quickstart](https://yutha.ai/developer/quickstart/) and [Operator Guide → Quickstart](https://yutha.ai/operator/quickstart/) respectively.

If you want to poke locally without the doc site:

- **End-to-end LangGraph example.** A customer-support swarm with capability-gated messaging, operator-driven eviction, and a verifiable audit trail. Runnable demo at [`sdks/python/examples/s1_support_queue.py`](./sdks/python/examples/s1_support_queue.py); walkthrough at [`docs/developer/langgraph.md`](./docs/developer/langgraph.md).
- **Constitution + four-stage enforcement.** [`sdks/python/examples/code_review.py`](./sdks/python/examples/code_review.py) (LangGraph) and [`sdks/python/examples/ap_invoice.py`](./sdks/python/examples/ap_invoice.py) (CrewAI) demonstrate the Cedar-based constitution layer plus detect → coach → quarantine → evict.
- **Conformance suite.** `cargo test -p yutha-conformance` runs the in-process scenarios covering the receipt log, send-path enforcement, operator revocation, and constitution evaluation.

## Contributing

See [CONTRIBUTING.md](./docs/community/CONTRIBUTING.md). The project is stewarded by a single maintainer ([@abhinavg6](https://github.com/abhinavg6)); guidelines are intentionally light.

Spec changes go through the [RFC process](./spec/rfcs/0001-rfc-process.md). Vulnerability reports go to [GitHub private security advisories](https://github.com/abhinavg6/yutha/security/advisories/new) — see [SECURITY.md](./docs/community/SECURITY.md).

## License

Apache License 2.0. See [LICENSE](./LICENSE).

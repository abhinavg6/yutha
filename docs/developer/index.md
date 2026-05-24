# Developer guide

You're a **developer** if you're building agents that participate in a Yutha-governed swarm. That includes:

- Wrapping an existing LangGraph, CrewAI, OpenAI Agents, or Microsoft Agent Framework agent so it can join.
- Reading and writing envelopes through the SDK.
- Handling capabilities for tools that take consequential actions.
- Writing a new framework adapter against the spec.

If you're standing up and running the swarm itself, you're an operator — see the [operator guide](../operator/index.md) instead.

## Start here

- **[Quickstart](quickstart.md)** — the 15-minute joiner path. Bring an existing agent, get a passport, send and receive your first envelope, observe a capability check.
- **[Python SDK](python-sdk.md)** — the canonical client surface. Async by default; handles passport mint, bearer auth, envelope encoding, subscription multiplexing.
- **[Writing a new adapter](writing-adapters.md)** — how to add support for a framework Yutha doesn't yet ship for.

## Framework adapters

Four adapters ship today. Each has a full developer walkthrough and a paired worked example under [Examples](../examples/index.md). Pick whichever framework matches what you already build agents in — the substrate is identical under all four.

- **[LangGraph](langgraph.md)** — wrap a LangGraph node as a Yutha agent. The richest hands-on walkthrough; deterministic state-graph handler, no LLM dependency at the dispatch level. Paired example: [customer support with refund cap](../examples/customer-support.md).
- **[CrewAI](crewai.md)** — each `Agent` in a Crew becomes a Yutha agent with its own identity. LLM-driven dispatch via `Crew.kickoff()`. Paired example: [AP & invoice processing](../examples/ap-invoice.md).
- **[OpenAI Agents](openai-agents.md)** — each `agents.Agent` becomes a Yutha agent. Handoff bridging via `RunHooks` so every inter-agent transition produces a signed audit envelope; cap-gating via `@capability_required` on `function_tool` bodies. Paired example: [research crew with citation enforcement](../examples/research-crew.md).
- **[Microsoft Agent Framework](maf.md)** — each `agent_framework.Agent` becomes a Yutha agent. Cap-gating on async-native tool callables (no sync/async bridge); honest documentation of v1 scope vs `WorkflowBuilder` / `RequestInfoExecutor` / `FunctionMiddleware` follow-ons. Paired example: [DevOps incident-response](../examples/devops-incident.md).

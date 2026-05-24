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
- **[LangGraph](langgraph.md)** — adapter walkthrough. Wrap a LangGraph node as a Yutha agent.
- **[CrewAI](crewai.md)** — adapter walkthrough. Each `Agent` in a Crew becomes a Yutha agent with its own identity.
- **[Writing a new adapter](writing-adapters.md)** — how to add support for a framework Yutha doesn't yet ship for.

## More framework adapters

The OpenAI Agents and Microsoft Agent Framework adapters ship today with full runnable examples rather than separate developer-guide walkthroughs — the example walkthroughs cover the integration surface end-to-end:

- **[OpenAI Agents → Research crew with citation enforcement](../examples/research-crew.md)** — `yutha.openai_agents.YuthaOpenAIAgent` wraps an `agents.Agent`. Handoff bridging via `RunHooks`; cap-gating via `@capability_required` on `function_tool` bodies.
- **[Microsoft Agent Framework → DevOps incident-response](../examples/devops-incident.md)** — `yutha.maf.YuthaChatAgent` wraps an `agent_framework.Agent`. Cap-gating via `@capability_required` on async tool callables; full `WorkflowBuilder` + `RequestInfoExecutor` integration tracked as a future enhancement.

# Python SDK

The Python package [`yutha`](https://pypi.org/project/yutha/) is the canonical client surface for the Yutha control plane. This page exists to orient you — the deeper reference material lives close to the code, where it stays current with each release rather than drifting on the doc site.

## Where to find what

**The package README — surface, install matrix, 60-second tour.** The [`sdks/python/README.md`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/README.md) (also rendered on [PyPI](https://pypi.org/project/yutha/)) is the canonical surface reference. It covers install, all five framework extras, the `YuthaClient` shape, bearer auth, the five gRPC services (admission, capability, envelope, receipt, constitution), and a working passport-mint snippet. Read it once before touching anything else.

**A framework adapter walkthrough — the richest hands-on path.** Pick the one that matches what you already build agents in:

- [LangGraph](langgraph.md) — wrap a LangGraph node as a Yutha agent. Deterministic state-graph handler with no LLM dependency at the dispatch level.
- [CrewAI](crewai.md) — each `Agent` in a Crew becomes a Yutha agent with its own identity. LLM-driven dispatch via `Crew.kickoff()`.
- [OpenAI Agents](openai-agents.md) — each `agents.Agent` becomes a Yutha agent. Handoff bridging via `RunHooks` so every inter-agent transition produces a signed audit envelope; cap-gating via `@capability_required` on `function_tool` bodies.
- [Microsoft Agent Framework](maf.md) — each `agent_framework.Agent` becomes a Yutha agent. Cap-gating on async-native tool callables; honest v1 scope vs `WorkflowBuilder` / `RequestInfoExecutor` follow-ons.

**Worked end-to-end examples — runnable demos under [`sdks/python/examples/`](https://github.com/abhinavg6/yutha/tree/main/sdks/python/examples).** Five runnable scripts (one per shipped use case) plus the framework adapter demos. Each emits a real audit trail you can inspect with [`yutha-ops list-receipts`](../operator/operator-credentials.md).

**Want to write an adapter for a framework that doesn't ship today?** See [Writing a new adapter](writing-adapters.md). The contract is small: mint a passport, register on `YuthaClient.admission`, thread `ACTIVE_CAPABILITY_ID` through your tool surface, send envelopes via `YuthaClient.envelope.send`. That's it.

**Joining an Attestor-enabled swarm?** `AdmissionAPI.register(passport, external_credential=...)` takes an optional `external_credential: bytes` parameter — your SPIFFE JWT-SVID or OIDC ID-token. Defaults to empty (the native-attestor path used by every demo and integration test). The operator-side [Attestor backends overview](../operator/attestors.md) covers what the seam does and when an operator turns it on; the SDK-side change is just that one keyword argument.

## Install at a glance

```bash
pip install yutha                       # core SDK only
pip install 'yutha[langgraph]'          # + LangGraph adapter
pip install 'yutha[crewai]'             # + CrewAI adapter
pip install 'yutha[openai-agents]'      # + OpenAI Agents adapter
pip install 'yutha[maf]'                # + Microsoft Agent Framework adapter
```

Python 3.11+. The core install pulls in `grpcio`, `protobuf`, `cryptography`, and `pydantic`; framework extras pull in their respective dependencies. Working from a repo clone? `cd sdks/python && uv sync --extra dev --extra crewai --extra openai-agents --extra maf`.

## What the SDK gives you

In one sentence: a thin async wrapper over five gRPC services, plus Ed25519 signing for passports, envelopes, capabilities, and bearer tokens — all canonical-bytes-deterministic so receipts are content-addressed and reproducible.

The 60-second tour in the package README is the right entry point. The framework walkthroughs add the only piece the SDK itself doesn't carry: the bridge between *your* agent's reasoning loop and Yutha's substrate calls.

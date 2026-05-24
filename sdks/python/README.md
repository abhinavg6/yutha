# yutha

Async Python client for **[Yutha](https://yutha.ai)** — open-source infrastructure
for groups of AI agents. Identity, capability, accountability, and norms — built
once, framework-agnostic.

> **Status — early-stage pre-release.** Currently
> [`v0.1.0-alpha.2`](https://github.com/abhinavg6/yutha/releases).
> Solid enough to play with end-to-end, intentionally pre-1.0. Wire formats and
> API surfaces may shift before 1.0; pin tightly if you build on it.

The Python SDK gives you signed agent identities, capability-gated message
sending, structured envelopes, and access to the append-only receipt log of
the Yutha control plane. Adapters for
[LangGraph](https://github.com/langchain-ai/langgraph),
[CrewAI](https://www.crewai.com/),
[OpenAI Agents](https://github.com/openai/openai-agents-python),
and [Microsoft Agent Framework](https://github.com/microsoft/agent-framework)
ship as optional extras, so the same SDK works regardless of how you build
the agents above it.

---

## Install

```bash
pip install yutha                       # core SDK only
pip install 'yutha[langgraph]'          # + LangGraph adapter
pip install 'yutha[crewai]'             # + CrewAI adapter
pip install 'yutha[openai-agents]'      # + OpenAI Agents adapter
pip install 'yutha[maf]'                # + Microsoft Agent Framework adapter
```

Python 3.11+ required. The core install pulls in `grpcio`, `protobuf`,
`cryptography`, and `pydantic`; the framework extras pull in their
respective dependencies (LangChain core, CrewAI, OpenAI Agents,
Microsoft Agent Framework, etc.).

## Quickstart

A 60-second tour of what the SDK looks like — signing keys, passports,
and the client surface. Full end-to-end with a live control plane is in
the [LangGraph guide](https://yutha.ai/developer/langgraph/).

```python
import yutha

# An agent's cryptographic identity.
signing_key = yutha.SigningKey.generate()

# Its signed passport — the artifact that lets it join a swarm.
passport = yutha.Passport(
    spec_version="1.0.0",
    agent_id=yutha.AgentId.new(),
    swarm_id=yutha.SwarmId.new(),
    agent_public_key=signing_key.public_key(),
    owner="example.com/my-agent",
    framework="langgraph",
    framework_version="0.2.0",
    accepted_constitution_version="1.0.0",
    tier=yutha.PassportTier.MINIMAL,
    issued_at=yutha.Timestamp.now(),
    expires_at=yutha.Timestamp(wall_clock="2099-01-01T00:00:00Z", monotonic_ns=2**62),
).sign(signing_key)

# Connect to a running control plane and register.
async with yutha.YuthaClient.connect(
    "127.0.0.1:50051",
    agent_id=passport.agent_id,
    swarm_id=passport.swarm_id,
    signing_key=signing_key,
) as client:
    await client.admission.register(passport)
    # ... send envelopes, issue capabilities, query receipts ...
```

## What's next

- **[15-minute LangGraph walkthrough](https://yutha.ai/developer/langgraph/)** —
  build a five-agent workflow with capability gating and a full audit trail.
- **[CrewAI walkthrough](https://yutha.ai/developer/crewai/)** —
  the same SDK with CrewAI idioms.
- **[OpenAI Agents research-crew example](https://yutha.ai/examples/research-crew/)** —
  end-to-end OpenAI Agents adapter walkthrough (handoff bridging,
  citation-enforcing constitution, cap-gated `function_tool`s).
- **[Microsoft Agent Framework DevOps example](https://yutha.ai/examples/devops-incident/)** —
  end-to-end MAF adapter walkthrough (SRE countersign, schema-change
  quarantine, `ChatAgent` integration).
- **[Worked examples](https://yutha.ai/examples/)** — runnable end-to-end
  demos covering customer support, code review with security boundaries,
  AP / invoice processing, research-crew citation enforcement, and
  DevOps incident-response.
- **[Concepts](https://yutha.ai/concepts/primitives/)** — passports,
  envelopes, capabilities, receipts, and the Cedar-based constitution
  layer in fifteen minutes.

## How it fits together

```
    ┌──────────────────────────────────────────┐
    │  yutha.YuthaClient                       │
    │  ─────────────────                       │
    │   .admission  →  AdmissionService stub   │
    │   .capability →  CapabilityService stub  │
    │   .envelope   →  EnvelopeService stub    │
    │   .receipt    →  ReceiptService stub     │
    │   .constitution → ConstitutionService    │
    └─────────────────┬────────────────────────┘
                      │
    ┌─────────────────▼─────────────────┐
    │  yutha.auth.BearerSession         │  ← mints + refreshes
    │  (Ed25519 over canonical bytes)   │     AgentBearerToken
    └─────────────────┬─────────────────┘
                      │
    ┌─────────────────▼───────────────┐
    │  yutha._proto.*  (grpcio stubs) │
    └─────────────────────────────────┘
```

The client is a thin async wrapper over five gRPC services. Bearer tokens
are short-lived, Ed25519-signed over the request's canonical bytes; the
session handles minting and refresh transparently.

## License

Apache 2.0. See [LICENSE](https://github.com/abhinavg6/yutha/blob/main/LICENSE).

## Contributing

Contributor setup, codegen, and the integration-test workflow are documented
in the [repository's CONTRIBUTING guide](https://github.com/abhinavg6/yutha/blob/main/docs/community/CONTRIBUTING.md).

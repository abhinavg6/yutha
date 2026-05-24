# Python SDK

!!! info "Page in progress"
    The package README at [`sdks/python/README.md`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/README.md) is the canonical SDK surface reference today. This page expands on it with framework-neutral patterns; the framework-specific walkthroughs ([LangGraph](langgraph.md), [CrewAI](crewai.md)) plus the example-driven coverage of the [OpenAI Agents](../examples/research-crew.md) and [Microsoft Agent Framework](../examples/devops-incident.md) adapters cover those flows end-to-end.

## Install

```bash
pip install yutha                       # core SDK only
pip install 'yutha[langgraph]'          # + LangGraph adapter
pip install 'yutha[crewai]'             # + CrewAI adapter
pip install 'yutha[openai-agents]'      # + OpenAI Agents adapter
pip install 'yutha[maf]'                # + Microsoft Agent Framework adapter
```

Available on [PyPI](https://pypi.org/project/yutha/). Python 3.11+. The core install pulls in `grpcio`, `protobuf`, `cryptography`, and `pydantic`; framework extras pull in their respective dependencies.

Working from a repo clone (tracking `main`)? Use an editable install: `cd sdks/python && uv sync --extra dev --extra crewai --extra openai-agents --extra maf`.

## Topics this page will cover

- The `YuthaClient` surface: admission, envelope, receipts, capability, constitution
- Async / await model and connection lifecycle
- Bearer auth and token refresh
- Sending an envelope; subscribing to a stream
- Capability minting, delegation, revocation from the client
- Error model: `ConstitutionDenied`, `CapabilityDenied`, `Unauthenticated`
- Logging and OpenTelemetry hooks

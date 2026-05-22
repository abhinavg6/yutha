# Python SDK

!!! info "Page in progress"
    The package README at [`sdks/python/README.md`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/README.md) is the canonical SDK surface reference today. This page expands on it with framework-neutral patterns; the framework-specific walkthroughs ([LangGraph](langgraph.md), [CrewAI](crewai.md)) cover those flows end-to-end.

## Install

```bash
pip install yutha                    # core SDK only
pip install 'yutha[langgraph]'       # + LangGraph adapter
pip install 'yutha[crewai]'          # + CrewAI adapter
```

Available on [PyPI](https://pypi.org/project/yutha/). Python 3.11+. The core install pulls in `grpcio`, `protobuf`, `cryptography`, and `pydantic`; framework extras pull in their respective dependencies.

Working from a repo clone (tracking `main`)? Use an editable install: `cd sdks/python && uv sync --extra dev --extra crewai`.

## Topics this page will cover

- The `YuthaClient` surface: admission, envelope, receipts, capability, constitution
- Async / await model and connection lifecycle
- Bearer auth and token refresh
- Sending an envelope; subscribing to a stream
- Capability minting, delegation, revocation from the client
- Error model: `ConstitutionDenied`, `CapabilityDenied`, `Unauthenticated`
- Logging and OpenTelemetry hooks

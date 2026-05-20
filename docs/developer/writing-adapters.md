# Writing a new adapter

!!! info "Page in progress"
    Full content is being written. Until then, the LangGraph adapter at [`sdks/python/src/yutha/langgraph/`](https://github.com/abhinavg6/yutha/tree/main/sdks/python/src/yutha/langgraph) and the CrewAI adapter at [`sdks/python/src/yutha/crewai/`](https://github.com/abhinavg6/yutha/tree/main/sdks/python/src/yutha/crewai) are the reference implementations to study.

Topics this page will cover:

- The adapter contract: what an adapter is responsible for vs. what the SDK does
- Passport lifecycle in your framework's idiom
- Mapping the framework's agent / task / tool concepts to Yutha primitives
- The `@capability_required` decorator (or equivalent) pattern
- Subscription / inbox handling for the framework's event loop
- Testing your adapter against the conformance suite
- Submitting a new adapter via PR (see [contributing](../community/CONTRIBUTING.md))

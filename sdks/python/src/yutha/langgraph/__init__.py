"""LangGraph integration for the Yutha SDK.

Install via the optional extra::

    pip install 'yutha[langgraph]'

What this package provides (lands incrementally across Stage 4):

  - **4a (this revision)**: package scaffolding + optional-dep wiring.
    Importing :mod:`yutha.langgraph` succeeds even without LangGraph
    installed; the actual primitives in 4b will raise a clear
    ``ImportError`` at first use if the extra isn't present.

  - **4b**: adapter primitives — a ``YuthaAgent`` wrapper that
    registers a passport, opens a subscribe stream, and dispatches
    incoming envelopes to a LangGraph workflow; a capability-check
    decorator for LangGraph nodes; an envelope-send helper that
    signs and ships from inside a graph step.

  - **4c**: a runnable five-agent customer-support demo
    (``examples/s1_support_queue.py``) that mirrors the Rust
    conformance scenario :mod:`yutha-conformance::scenarios::s1_queue_mode`.

  - **4d**: walkthrough doc with code snippets.

The adapter is deliberately *light*: it doesn't try to be opinionated
about LangGraph's state model or replace its checkpointing. It just
makes the Yutha control plane available to LangGraph nodes as
inbound/outbound mailboxes with cryptographic identity and an audit
trail. A heavier integration (e.g. a LangGraph ``BaseCheckpointSaver``
backed by the Yutha receipt store) is a future-stage decision.

## Why optional-dep

LangGraph pulls in ``langchain-core`` + ``langsmith`` + assorted
transitive deps. Users who only want to talk to the Yutha control
plane directly (custom workflow, CrewAI later, in-house framework)
shouldn't have to install any of that. Hence
``[project.optional-dependencies] langgraph = [...]`` in
``pyproject.toml`` rather than a runtime dep.
"""

from __future__ import annotations

# 4b adapter primitives. Importing these does NOT require LangGraph
# to be installed — they wrap the Yutha SDK's own types and are
# framework-agnostic by design. The optional extra matters for
# downstream code that imports `langgraph.graph.StateGraph` to build
# real workflows (e.g. the Stage-4c demo).
from yutha.langgraph.agent import EnvelopeHandler, YuthaAgent
from yutha.langgraph.tools import CapabilityDenied, capability_required


def _require_langgraph() -> None:
    """Raise a clear ``ImportError`` if LangGraph isn't installed.

    Adapter primitives that actually consume LangGraph types (none in
    the current 4b surface — :class:`YuthaAgent` and
    :func:`capability_required` are framework-agnostic, on purpose)
    call this on entry. The current 4b primitives are usable without
    LangGraph; this helper is here for the future adapter pieces
    (LangGraph node decorators that introspect ``StateGraph``, etc.).
    """
    try:
        import langgraph  # noqa: F401  # presence-check only
    except ImportError as e:
        raise ImportError(
            "yutha.langgraph requires the optional `langgraph` extra. "
            "Install it with:  pip install 'yutha[langgraph]'"
        ) from e


__all__ = [
    "YuthaAgent",
    "EnvelopeHandler",
    "capability_required",
    "CapabilityDenied",
    "_require_langgraph",
]

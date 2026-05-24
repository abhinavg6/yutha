"""OpenAI Agents integration for the Yutha SDK.

Install via the optional extra::

    pip install 'yutha[openai-agents]'

What this package provides:

  - :class:`YuthaOpenAIAgent` — adapter that wraps an
    :class:`openai_agents.Agent` (or
    :class:`openai_agents.SandboxAgent`) and gives it a Yutha-
    registered identity. Each inbound envelope is converted into
    a single :meth:`openai_agents.Runner.run` call; outbound
    sends from inside function tools go through
    ``yutha_oai_agent.send(...)``.
  - :class:`YuthaRunHooks` — a :class:`openai_agents.RunHooks`
    subclass that turns OpenAI Agents lifecycle events into
    Yutha receipts. Handoffs in particular become Yutha
    envelopes — emitted from the source agent to the target
    agent's inbox — so the substrate audit log captures every
    inter-agent transfer the LLM-driven Runner performs.
  - :func:`capability_required` — decorator/wrapper for
    :func:`openai_agents.function_tool`-decorated callables.
    Sets the same context-local capability_id that
    :mod:`yutha.langgraph` and :mod:`yutha.crewai` use, so when
    a tool calls ``agent.send(...)`` the server's RFC 0007
    cap-check fires with the right cap_id automatically.
  - :class:`CapabilityDenied` — re-exported from
    :mod:`yutha.langgraph.tools`. All three adapters share a
    single exception class so a downstream that mixes
    frameworks (or wants to catch denies uniformly) needs only
    one ``except`` clause.

Audit-log fidelity. The integration model is **1:1 per OpenAI
Agents Agent**: each ``Agent`` in a multi-agent flow gets its
own Yutha passport, signing key, and ``agent.register`` receipt.
Handoffs cross the Yutha wire as signed envelopes between two
distinct ``agent_id`` values — the audit log records which
agent handed off to which, when, and with what conversation
state. Compared to running an OpenAI Agents flow under a
single Yutha identity, this trades a small amount of setup for
substantially better forensics.

## Why optional-dep

``openai-agents`` pulls in the OpenAI Python SDK, ``litellm``
(for cross-provider model support), tracing/MCP dependencies,
and a few other transitive packages. Users who only want to
talk to the Yutha control plane shouldn't have to install any
of that. Hence ``[project.optional-dependencies] openai-agents
= [...]`` in ``pyproject.toml`` rather than a runtime dep —
importing ``yutha.openai_agents`` succeeds even without the
extra installed; the actual adapter primitives raise a clear
``ImportError`` at first use if it's missing.
"""

from __future__ import annotations

from yutha.openai_agents.agent import YuthaOpenAIAgent
from yutha.openai_agents.hooks import YuthaRunHooks
from yutha.openai_agents.tools import CapabilityDenied, capability_required


def _require_openai_agents() -> None:
    """Raise a clear ``ImportError`` if the ``openai-agents`` SDK
    isn't installed.

    Adapter primitives that actually consume OpenAI Agents types
    call this on entry. The bare-Python primitives (the agent's
    lifecycle methods, the cap_id contextvar threading) work
    without it; only the parts that construct a ``Runner`` or
    wrap a ``function_tool`` need the optional extra installed.
    """
    try:
        import agents  # noqa: F401  # presence-check only
    except ImportError as e:
        raise ImportError(
            "yutha.openai_agents requires the optional `openai-agents` extra. "
            "Install it with:  pip install 'yutha[openai-agents]'"
        ) from e


__all__ = [
    "YuthaOpenAIAgent",
    "YuthaRunHooks",
    "capability_required",
    "CapabilityDenied",
    "_require_openai_agents",
]

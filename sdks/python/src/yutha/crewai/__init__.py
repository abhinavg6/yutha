"""CrewAI integration for the Yutha SDK.

Install via the optional extra::

    pip install 'yutha[crewai]'

What this package provides:

  - :class:`YuthaCrewAgent` — adapter that wraps a CrewAI
    ``Agent`` and gives it a Yutha-registered identity. Each
    inbound envelope is converted into a single-task CrewAI
    ``Crew`` invocation; outbound sends from inside CrewAI tools
    go through ``yutha_crew_agent.send(...)``.
  - :func:`capability_required` — decorator/wrapper for CrewAI
    tools (``BaseTool`` subclasses or ``@tool``-decorated
    callables). Sets the same context-local capability_id that
    :mod:`yutha.langgraph` uses, so when a tool calls
    ``agent.send(...)`` the server's RFC 0007 cap-check fires
    with the right cap_id automatically.
  - :class:`CapabilityDenied` — re-exported from
    :mod:`yutha.langgraph.tools`. The two adapters share the
    same exception class so a downstream that toggles between
    frameworks can catch a single type.

Audit-log fidelity. The integration model is **1:1 per CrewAI
Agent**: each Agent in a Crew gets its own Yutha passport,
signing key, and ``agent.register`` receipt. The audit log
records exactly which CrewAI Agent did what — internal CrewAI
delegation (one Agent kicking off a task on another) crosses the
wire as a real signed envelope between two distinct
``agent_id`` values. Compared to running a whole Crew under a
single Yutha identity, this trades a bit of setup for
substantially better forensics.

## Why optional-dep

CrewAI 0.x pulls in LangChain, several embedding-model SDKs, and
a few transitive HTTP clients. Users who only want to talk to
the Yutha control plane shouldn't have to install any of that.
Hence ``[project.optional-dependencies] crewai = [...]`` in
``pyproject.toml`` rather than a runtime dep — importing
``yutha.crewai`` succeeds even without CrewAI installed; the
actual adapter primitives raise a clear ``ImportError`` at first
use if the extra isn't present.
"""

from __future__ import annotations

from yutha.crewai.agent import YuthaCrewAgent
from yutha.crewai.tools import CapabilityDenied, capability_required


def _require_crewai() -> None:
    """Raise a clear ``ImportError`` if CrewAI isn't installed.

    Adapter primitives that actually consume CrewAI types call
    this on entry. The bare-Python primitives (the agent's
    lifecycle methods, the cap_id contextvar threading) work
    without it; only the parts that construct a ``Crew`` /
    ``Task`` need the optional extra installed.
    """
    try:
        import crewai  # noqa: F401  # presence-check only
    except ImportError as e:
        raise ImportError(
            "yutha.crewai requires the optional `crewai` extra. "
            "Install it with:  pip install 'yutha[crewai]'"
        ) from e


__all__ = [
    "YuthaCrewAgent",
    "capability_required",
    "CapabilityDenied",
    "_require_crewai",
]

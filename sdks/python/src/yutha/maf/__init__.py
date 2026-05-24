"""Microsoft Agent Framework (MAF) integration for the Yutha SDK.

Install via the optional extra::

    pip install 'yutha[maf]'

What this package provides:

  - :class:`YuthaChatAgent` — adapter that wraps an
    :class:`agent_framework.Agent` and gives it a Yutha-registered
    identity. Each inbound envelope is converted into a single
    :meth:`Agent.run` call; outbound sends from inside tool
    callables go through ``yutha_maf_agent.send(...)``.
  - :func:`capability_required` — decorator for MAF tool
    callables. Sets the same context-local capability_id that
    :mod:`yutha.langgraph`, :mod:`yutha.crewai`, and
    :mod:`yutha.openai_agents` use, so when a tool calls
    ``agent.send(...)`` the server's RFC 0007 cap-check fires
    with the right cap_id automatically.
  - :class:`CapabilityDenied` — re-exported from
    :mod:`yutha.langgraph.tools`. All four adapters share a
    single exception class so a downstream that mixes frameworks
    needs only one ``except`` clause.

Audit-log fidelity. The integration model is **1:1 per MAF
Agent**: each ``Agent`` gets its own Yutha passport, signing key,
and ``agent.register`` receipt. Inter-agent collaboration (whether
direct envelope-passing or future ``WorkflowBuilder`` integration)
crosses the Yutha wire as signed envelopes between distinct
``agent_id`` values. Compared to running a whole multi-agent flow
under a single Yutha identity, this trades a bit of setup for
substantially better forensics.

## Package-name note

The PyPI package is ``agent-framework`` (hyphen) but the
importable Python module is ``agent_framework`` (underscore).
We name our adapter ``yutha.maf`` rather than
``yutha.agent_framework`` to keep imports short and to avoid
confusion with the upstream framework's own packaging.

## v1 scope vs future

The v1 adapter focuses on **per-agent wrapping with cap-gated
tools** — the smallest substrate-correct integration that
exercises the MAF Agent surface. The following MAF capabilities
are tracked as documented follow-ons, not v1:

  - **WorkflowBuilder integration.** v1 demos drive agents
    directly (orchestrator → ``agent.run(...)``). MAF's
    graph-based ``WorkflowBuilder`` is the natural next step —
    each workflow edge would emit a Yutha envelope for audit.
  - **RequestInfoExecutor / HITL.** v1 has a passive
    ``human_sre`` agent that gets registered but isn't driven
    through the formal HITL primitive. Wiring
    ``RequestInfoExecutor`` so the request + response cycle
    produces ``approval_required`` and ``countersigned`` receipts
    is the natural HITL upgrade.
  - **AgentMiddleware / FunctionMiddleware as the cap-gating
    hook.** v1 reuses the same contextvar-based
    ``@capability_required`` decorator the other adapters use,
    which works because MAF's tool invocation is async-native.
    A future revision could move cap-gating into a
    ``FunctionMiddleware`` for tighter integration with MAF's
    middleware pipeline.
  - **Checkpoint receipts.** MAF's checkpointing primitive is
    distinct from Yutha's receipt log; bridging them would let
    workflow checkpoint events show up in the audit trail.
  - **OpenTelemetry bridge.** MAF's OTel spans → Yutha
    telemetry receipts.

The v1 surface is sufficient for substrate-correct demos; later
revisions layer the MAF-distinctive features on top of the same
core wrapper.

## Why optional-dep

``agent-framework`` pulls in OpenAI / Foundry / Azure SDKs and
several transitive packages. Users who only want to talk to the
Yutha control plane shouldn't have to install any of that. Hence
``[project.optional-dependencies] maf = [...]`` in
``pyproject.toml`` rather than a runtime dep — importing
``yutha.maf`` succeeds even without the extra installed; the
actual adapter primitives raise a clear ``ImportError`` at first
use if it's missing.
"""

from __future__ import annotations

from yutha.maf.agent import YuthaChatAgent
from yutha.maf.tools import CapabilityDenied, capability_required


def _require_maf() -> None:
    """Raise a clear ``ImportError`` if the ``agent-framework`` SDK
    isn't installed.

    Adapter primitives that actually consume MAF types call this
    on entry. Bare-Python primitives (the agent's lifecycle
    methods, the cap_id contextvar threading) work without it;
    only the parts that construct an ``Agent`` or read its
    ``run()`` output need the optional extra installed.
    """
    try:
        import agent_framework  # noqa: F401  # presence-check only
    except ImportError as e:
        raise ImportError(
            "yutha.maf requires the optional `maf` extra. "
            "Install it with:  pip install 'yutha[maf]'"
        ) from e


__all__ = [
    "YuthaChatAgent",
    "capability_required",
    "CapabilityDenied",
    "_require_maf",
]

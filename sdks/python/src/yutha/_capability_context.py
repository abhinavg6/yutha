"""Framework-neutral contextvar for the active capability id.

Both :mod:`yutha.langgraph` and :mod:`yutha.crewai` thread the
content-address of the held capability through the async-local
context so any ``YuthaAgent.send(...)`` or ``YuthaCrewAgent.send(...)``
call made *inside* a capability-gated wrapper picks it up
automatically.

This module is intentionally tiny and dependency-free so neither
framework adapter has to import the other, and the core
:mod:`yutha.client` doesn't have to depend on either adapter.

Usage from inside an adapter's tool/node decorator::

    from yutha._capability_context import ACTIVE_CAPABILITY_ID

    token = ACTIVE_CAPABILITY_ID.set(cap_id)
    try:
        return await fn(*args, **kwargs)
    finally:
        ACTIVE_CAPABILITY_ID.reset(token)

Usage from inside ``YuthaAgent.send`` to read the cap-id default::

    capability_id = ACTIVE_CAPABILITY_ID.get()
"""

from __future__ import annotations

from contextvars import ContextVar

from yutha.identity import Hash

ACTIVE_CAPABILITY_ID: ContextVar[Hash | None] = ContextVar(
    "yutha_active_capability_id", default=None
)

__all__ = ["ACTIVE_CAPABILITY_ID"]

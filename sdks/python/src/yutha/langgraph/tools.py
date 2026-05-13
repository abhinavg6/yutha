"""Helpers callers wire into LangGraph nodes.

``capability_required`` is a decorator that runs a stateless
capability check against a held :class:`yutha.Capability` before
invoking the wrapped function. Use it to gate any LangGraph node that
performs a privileged action — the server still re-checks on every
``EnvelopeService.Send``, so this is a client-side pre-flight, but
it lets the workflow short-circuit early and produce a clean,
auditable rejection.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from yutha.client import YuthaClient
from yutha.models import Capability
from yutha.models.capability import ActionDescriptor, CheckOutcome


class CapabilityDenied(Exception):
    """Raised by :func:`capability_required` when the held capability
    does not permit the requested action.

    Carries the :class:`CheckOutcome` so callers can introspect the
    deny reason, the unmet caveats, and (if attached server-side) the
    receipt id of the deny event. Stage-4b nodes typically let this
    propagate; richer flows can catch it and route to a supervisor.
    """

    def __init__(self, outcome: CheckOutcome) -> None:
        self.outcome = outcome
        msg = outcome.deny_reason or "capability check denied"
        if outcome.unmet_caveats:
            msg = f"{msg} (unmet caveats: {', '.join(outcome.unmet_caveats)})"
        super().__init__(msg)


# Generic type for the decorated function's return value. We keep the
# wrapped fn fully generic so decorators don't lose type info.
R = TypeVar("R")
AsyncFn = Callable[..., Awaitable[R]]


def capability_required(
    client: YuthaClient,
    capability: Capability,
    *,
    action_kind: str | None = None,
    descriptor: ActionDescriptor | None = None,
) -> Callable[[AsyncFn[R]], AsyncFn[R]]:
    """Decorator: gate an async function on a capability check.

    Parameters
    ----------
    client
        The :class:`YuthaClient` to run the check against. Reuse the
        agent's existing client (``agent.client``) to share the
        bearer-session cache.
    capability
        The :class:`yutha.Capability` the caller holds. The decorator
        does not refresh it — if it expires or is revoked, the
        server's ``Check`` will return a deny and we raise
        :class:`CapabilityDenied`.
    action_kind
        Shorthand: when supplied, the descriptor is built as
        ``ActionDescriptor(action_kind=action_kind)``. Sufficient
        when the action's identity is the only dimension you're
        gating on.
    descriptor
        Full descriptor when you need to gate on resource_tags,
        numeric values, recipient, or memory scope. Mutually
        exclusive with ``action_kind``.

    Usage::

        cap = ...  # capability the agent holds
        agent = YuthaAgent.connect(...)

        @capability_required(agent.client, cap, action_kind="issue_refund")
        async def refund_node(state: dict) -> dict:
            ...
    """
    if (action_kind is None) == (descriptor is None):
        raise ValueError(
            "capability_required requires exactly one of `action_kind` or `descriptor`"
        )
    if descriptor is None:
        assert action_kind is not None  # for mypy; checked above
        descriptor = ActionDescriptor(action_kind=action_kind)

    def decorator(fn: AsyncFn[R]) -> AsyncFn[R]:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> R:
            outcome = await client.capability.check(capability, descriptor)
            if not outcome.permitted:
                raise CapabilityDenied(outcome)
            return await fn(*args, **kwargs)

        return wrapper

    return decorator


__all__ = ["capability_required", "CapabilityDenied"]

"""Helpers callers wire into MAF tool callables.

The headline export is :func:`capability_required` — a decorator
that gates an async callable on a held :class:`yutha.Capability`,
intended to be composed with however MAF turns a Python callable
into a tool (typically a decorator like ``@ai_function`` or by
passing the callable in the agent's ``tools=`` list).

Under v1.1 (RFC 0007) capability enforcement is server-side at
Send. The wrapper's job is therefore narrower:

1. **Validate locally** that the held cap's scope action_kind
   matches what the caller declared. A mismatch fails fast
   with :class:`CapabilityDenied` *before* the tool ever runs.
2. **Set a context-local cap_id** for the duration of every
   tool invocation. :meth:`yutha.maf.YuthaChatAgent.send` reads
   it and supplies it to the gRPC ``Send`` request
   automatically. The server's check produces the load-bearing
   ``capability.check.{pass,deny}`` receipt; a deny surfaces as
   :class:`CapabilityDenied` raised from the send call inside
   the tool body.

## Why a decorator (not a FunctionMiddleware) in v1

MAF has a first-class ``FunctionMiddleware`` interface that's
arguably the more idiomatic place to install cap-gating logic.
v1 of this adapter uses the same contextvar-based decorator the
other three adapters use because:

  - It works without depending on MAF's middleware import path
    (which is more sensitive to MAF version skew during the
    framework's active development).
  - It mirrors the pattern callers already know from
    ``yutha.langgraph`` / ``yutha.crewai`` / ``yutha.openai_agents``.
  - MAF's async-native tool invocation propagates contextvars
    cleanly, so the decorator approach is substrate-correct.

A future revision can layer a ``YuthaFunctionMiddleware`` that
hooks into MAF's middleware pipeline directly, with the
decorator pattern preserved as the simpler alternative.

## Why re-export ``CapabilityDenied`` from langgraph

All four adapters share a single exception class so a
downstream that mixes frameworks needs only one ``except``
clause. The class itself lives in :mod:`yutha.langgraph.tools`
because that adapter shipped first; this module re-exports it.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from yutha._capability_context import ACTIVE_CAPABILITY_ID
from yutha.crypto import sha256
from yutha.identity import Hash, HashAlgorithm
from yutha.langgraph.tools import CapabilityDenied
from yutha.models import Capability
from yutha.models.capability import ActionDescriptor

R = TypeVar("R")
AsyncFn = Callable[..., Awaitable[R]]


def _capability_id(capability: Capability) -> Hash:
    """Content-address a capability the same way the server does
    (and the same way the other adapters do). Duplicated rather
    than imported across adapters to keep them independent."""
    return Hash(
        algorithm=HashAlgorithm.SHA256,
        digest=sha256(capability.canonical_bytes()),
    )


def capability_required(
    capability: Capability,
    *,
    action_kind: str | None = None,
    descriptor: ActionDescriptor | None = None,
) -> Callable[[AsyncFn[R]], AsyncFn[R]]:
    """Decorator: gate an async tool callable on a held capability.

    Parameters
    ----------
    capability
        The :class:`yutha.Capability` the caller holds. Its
        content-address becomes the cap_id threaded into
        subsequent sends from within the tool body.
    action_kind
        The action_kind the wrapper expects the cap to permit.
        Validated locally against
        ``capability.scope.permitted_actions``; a mismatch raises
        :class:`CapabilityDenied`. Mutually exclusive with
        ``descriptor``.
    descriptor
        Full :class:`ActionDescriptor` for the same local-
        validation check. Mutually exclusive with ``action_kind``.

    Returns
    -------
    Callable
        A decorator that wraps an async callable. The wrapped
        callable can then be passed to MAF's tool-registration
        mechanism (e.g. ``tools=[my_tool]`` on ``Agent``).

    Deny paths
    ----------
    - Cap scope doesn't match the declared ``action_kind`` →
      :class:`CapabilityDenied` raised at decoration time,
      before the tool is ever invoked.
    - Cap is revoked / expired / has unmet caveats at server-
      side Send time → :class:`CapabilityDenied` raised from
      the ``wrapper.send(...)`` call inside the tool body
      (translated from the server's ``PERMISSION_DENIED``).
    """
    if (action_kind is None) == (descriptor is None):
        raise ValueError(
            "capability_required requires exactly one of `action_kind` or `descriptor`"
        )
    expected_action = (
        action_kind if action_kind is not None else descriptor.action_kind  # type: ignore[union-attr]
    )

    cap_id = _capability_id(capability)

    permitted = list(capability.scope.permitted_actions)
    if permitted and expected_action not in permitted:
        raise CapabilityDenied(
            f"capability scope permits actions {permitted!r}; "
            f"does not include wrapper's expected action_kind "
            f"{expected_action!r}"
        )

    def decorator(fn: AsyncFn[R]) -> AsyncFn[R]:
        @functools.wraps(fn)
        async def wrapped(*args: Any, **kwargs: Any) -> R:
            token = ACTIVE_CAPABILITY_ID.set(cap_id)
            try:
                return await fn(*args, **kwargs)
            finally:
                ACTIVE_CAPABILITY_ID.reset(token)

        return wrapped

    return decorator


__all__ = [
    "capability_required",
    "CapabilityDenied",
]

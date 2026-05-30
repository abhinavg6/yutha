"""Helpers callers wire into openai-agents function tools.

The headline export is :func:`capability_required` — a decorator
that gates an async callable on a held :class:`yutha.Capability`,
intended to be composed with :func:`agents.function_tool`.

Under v1.1 (RFC 0007) capability enforcement is server-side at
Send. The wrapper's job is therefore narrower:

1. **Validate locally** that the held cap's scope action_kind
   matches what the caller declared. A mismatch fails fast with
   :class:`CapabilityDenied` *before* the tool ever runs — no
   preflight RPC, no extra receipt. Catches "I wrapped this
   tool with the wrong action_kind for the cap I hold" coding
   errors.
2. **Set a context-local cap_id** for the duration of every
   tool invocation. :meth:`yutha.openai_agents.YuthaOpenAIAgent.send`
   reads it and supplies it to the gRPC ``Send`` request
   automatically. The server's check produces the load-bearing
   ``capability.check.{pass,deny}`` receipt; a deny surfaces as
   :class:`CapabilityDenied` raised from the send call inside
   the tool body.

## Composing with ``function_tool``

Either order works — the wrapper preserves the underlying
callable's signature so :func:`agents.function_tool` can still
introspect it for the LLM's JSON-schema:

.. code-block:: python

    from agents import function_tool
    from yutha.openai_agents import capability_required

    # Style A — capability_required outermost (recommended for
    # readability: the gate is the first thing the reader sees).
    @function_tool
    @capability_required(cap, action_kind="envelope.send")
    async def publish_brief(content: str, cited: bool) -> str:
        ...
        return await wrapper.send(...)

    # Style B — function_tool outermost (functionally identical).
    @capability_required(cap, action_kind="envelope.send")
    @function_tool
    async def publish_brief(content: str, cited: bool) -> str:
        ...

In Style B, ``capability_required`` mutates the ``FunctionTool``
instance's ``on_invoke_tool`` callback rather than the original
function — same end effect, slightly different mechanism. Style A
is the canonical form used by the example demos.

## Why re-export ``CapabilityDenied`` from langgraph

All three adapters (langgraph, crewai, openai_agents) share a
single exception class so a downstream that mixes frameworks (or
catches denies uniformly across them) needs only one ``except``
clause. The class itself lives in :mod:`yutha.langgraph.tools`
because that adapter shipped first; this module re-exports it.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, TypeVar

from yutha._capability_context import ACTIVE_CAPABILITY_ID
from yutha.crypto import sha256
from yutha.identity import Hash, HashAlgorithm
from yutha.langgraph.tools import CapabilityDenied
from yutha.models import Capability
from yutha.models.capability import ActionDescriptor

if TYPE_CHECKING:
    # Type-only — keeps `yutha.openai_agents.tools` importable
    # without the openai-agents dep installed.
    from agents.tool import FunctionTool


R = TypeVar("R")
AsyncFn = Callable[..., Awaitable[R]]


def _capability_id(capability: Capability) -> Hash:
    """Content-address a capability the same way the server does
    (and the same way :mod:`yutha.langgraph.tools` /
    :mod:`yutha.crewai.tools` do). Duplicated rather than imported
    across adapters to keep them independent."""
    return Hash(
        algorithm=HashAlgorithm.SHA256,
        digest=sha256(capability.canonical_bytes()),
    )


def capability_required(
    capability: Capability,
    *,
    action_kind: str | None = None,
    descriptor: ActionDescriptor | None = None,
) -> Callable[[Any], Any]:
    """Decorator: gate a function-tool body on a held capability.

    Parameters
    ----------
    capability
        The :class:`yutha.Capability` the caller holds. Its
        content-address becomes the cap_id threaded into subsequent
        sends from within the tool body.
    action_kind
        The action_kind the wrapper expects the cap to permit.
        Validated locally against ``capability.scope.permitted_actions``;
        a mismatch raises :class:`CapabilityDenied`. Mutually
        exclusive with ``descriptor``.
    descriptor
        Full :class:`ActionDescriptor` for the same local-validation
        check. Mutually exclusive with ``action_kind``.

    Returns
    -------
    Callable[[Any], Any]
        A decorator that accepts either an async function (Style A)
        or a :class:`agents.tool.FunctionTool` instance (Style B)
        and returns the same kind of object with the cap-context
        wrapping applied.

    Deny paths
    ----------
    - Cap scope doesn't match the declared ``action_kind`` →
      :class:`CapabilityDenied` raised at decoration time, before
      the tool is ever invoked.
    - Cap is revoked / expired / has unmet caveats at server-side
      Send time → :class:`CapabilityDenied` raised from the
      ``wrapper.send(...)`` call inside the tool body (translated
      from the server's ``PERMISSION_DENIED``).
    """
    if (action_kind is None) == (descriptor is None):
        raise ValueError(
            "capability_required requires exactly one of `action_kind` or `descriptor`"
        )
    expected_action = (
        action_kind if action_kind is not None else descriptor.action_kind  # type: ignore[union-attr]
    )

    # Resolve cap_id once at decoration time — deterministic from
    # canonical bytes.
    cap_id = _capability_id(capability)

    # Local validation: the cap's scope must permit the action_kind
    # the wrapper declared. Empty ``permitted_actions`` means "all
    # actions allowed" per :class:`yutha.models.capability.Scope`.
    # Catches structural mismatches without going to the server.
    permitted = list(capability.scope.permitted_actions)
    if permitted and expected_action not in permitted:
        raise CapabilityDenied(
            f"capability scope permits actions {permitted!r}; "
            f"does not include wrapper's expected action_kind "
            f"{expected_action!r}"
        )

    def decorator(target: Any) -> Any:
        # Two shapes the decorator might receive:
        #   1. A plain async callable (Style A from the docstring —
        #      typical when composed as `@function_tool /
        #      @capability_required`).
        #   2. A `FunctionTool` instance (Style B — composed in the
        #      opposite order). FunctionTool has an
        #      `on_invoke_tool` attribute holding the wrapped
        #      callable; we patch that.
        #
        # Detect by attribute presence rather than isinstance to
        # avoid the optional-dep import here.
        on_invoke = getattr(target, "on_invoke_tool", None)

        if callable(on_invoke):
            # FunctionTool instance — wrap its on_invoke_tool.
            return _wrap_function_tool(target, cap_id)

        if not callable(target):
            raise TypeError(
                f"capability_required: target {target!r} is neither an "
                "async callable nor a FunctionTool — cannot wrap"
            )

        # Plain async callable. Wrap it so the contextvar is set
        # during execution; the wrapped callable can then be passed
        # to function_tool (Style A) or used directly.
        @functools.wraps(target)
        async def wrapped(*args: Any, **kwargs: Any) -> Any:
            token = ACTIVE_CAPABILITY_ID.set(cap_id)
            try:
                return await target(*args, **kwargs)
            finally:
                ACTIVE_CAPABILITY_ID.reset(token)

        return wrapped

    return decorator


def _wrap_function_tool(tool: FunctionTool, cap_id: Hash) -> FunctionTool:
    """Mutate a :class:`agents.tool.FunctionTool` instance so its
    ``on_invoke_tool`` callback runs with ``ACTIVE_CAPABILITY_ID``
    set to the held cap.

    Internal helper used by :func:`capability_required` when the
    decorator receives a :class:`FunctionTool` (Style B
    composition order)."""
    original_invoke = tool.on_invoke_tool

    @functools.wraps(original_invoke)
    async def patched_invoke(*args: Any, **kwargs: Any) -> Any:
        token = ACTIVE_CAPABILITY_ID.set(cap_id)
        try:
            return await original_invoke(*args, **kwargs)
        finally:
            ACTIVE_CAPABILITY_ID.reset(token)

    tool.on_invoke_tool = patched_invoke
    return tool


__all__ = [
    "capability_required",
    "CapabilityDenied",
]

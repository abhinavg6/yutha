"""Helpers callers wire into CrewAI tools.

The headline export is :func:`capability_required` — a wrapper that
gates a CrewAI ``BaseTool`` instance on a held :class:`yutha.Capability`.

Under v1.1 (RFC 0007) capability enforcement is server-side at Send.
The wrapper's job is therefore narrower:

1. **Validate locally** that the held cap's scope action_kind matches
   what the caller declared. A mismatch fails fast with
   :class:`CapabilityDenied` *before* the tool ever runs — no
   preflight RPC, no extra receipt. Catches "I wrapped this tool
   with the wrong action_kind for the cap I hold" coding errors.
2. **Set a context-local cap_id** for the duration of every tool
   invocation. :meth:`yutha.crewai.YuthaCrewAgent.send` reads it
   and supplies it to the gRPC ``Send`` request automatically. The
   server's check produces the load-bearing
   ``capability.check.{pass,deny}`` receipt; a deny surfaces as
   :class:`CapabilityDenied` raised from the send call inside the
   tool body.

The wrapper preserves the original tool's ``name``, ``description``,
and ``args_schema`` so CrewAI's introspection (function-calling
schema for the LLM, etc.) keeps working unchanged. It mutates the
tool instance's ``_run`` / ``_arun`` methods rather than
subclass-and-reconstruct — that keeps the API symmetric whether the
user instantiates the tool inline or imports a pre-built one.

## Why re-export ``CapabilityDenied`` from langgraph

Both adapters share a single exception class so a downstream that
toggles between frameworks (or runs both side-by-side) can catch a
single type. The class itself lives in :mod:`yutha.langgraph.tools`
because that adapter shipped first; this module re-exports it as a
sibling.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypeVar

from yutha._capability_context import ACTIVE_CAPABILITY_ID
from yutha.crypto import sha256
from yutha.identity import Hash, HashAlgorithm
from yutha.langgraph.tools import CapabilityDenied
from yutha.models import Capability
from yutha.models.capability import ActionDescriptor

if TYPE_CHECKING:
    # Type-only; the actual import lives inside the wrapper body so
    # `yutha.crewai.tools` is importable without the `crewai` extra.
    from crewai.tools import BaseTool

# Bound for the BaseTool input/output of `capability_required`. The
# wrapper returns the same instance it was handed (after mutation),
# so the type parameter preserves any user-defined BaseTool subclass.
T = TypeVar("T", bound="BaseTool")


def _capability_id(capability: Capability) -> Hash:
    """Content-address a capability the same way the server does (and
    the same way :mod:`yutha.langgraph.tools` does). Kept duplicated
    rather than imported across adapters to avoid binding
    ``yutha.crewai`` to ``yutha.langgraph``'s internal helpers."""
    return Hash(
        algorithm=HashAlgorithm.SHA256,
        digest=sha256(capability.canonical_bytes()),
    )


def capability_required(
    capability: Capability,
    *,
    action_kind: str | None = None,
    descriptor: ActionDescriptor | None = None,
) -> Callable[[T], T]:
    """Wrap a CrewAI ``BaseTool`` so that:

    - the held cap's scope is validated against ``action_kind`` /
      ``descriptor`` at wrap time, and
    - the cap_id is supplied to any
      :meth:`YuthaCrewAgent.send <yutha.crewai.YuthaCrewAgent.send>`
      call made during the tool's execution.

    Parameters
    ----------
    capability
        The :class:`yutha.Capability` the caller holds. Its
        content-address becomes the cap_id threaded into subsequent
        sends from within the tool body.
    action_kind
        The action_kind the wrapper expects the cap to permit.
        Validated locally against ``capability.scope.permitted_actions``;
        a mismatch raises :class:`CapabilityDenied`. Mutually exclusive
        with ``descriptor``.
    descriptor
        Full :class:`ActionDescriptor` for the same local-validation
        check. Mutually exclusive with ``action_kind``.

    Usage::

        from crewai.tools import BaseTool
        from yutha.crewai import capability_required

        class IssueRefundTool(BaseTool):
            name: str = "issue_refund"
            description: str = "Issue a refund to a customer."

            def _run(self, customer_id: str, amount_cents: int) -> str:
                # synchronous body — call sync helper or run an
                # async send via asyncio.run from the worker thread.
                ...

        cap = ...  # capability scoped to "envelope.send" or workload action
        tool = capability_required(cap, action_kind="envelope.send")(IssueRefundTool())

        agent = Agent(
            role="Refunds clerk",
            goal="Issue customer refunds.",
            tools=[tool],
            ...
        )

    Deny paths:

    - Cap scope doesn't match the declared ``action_kind`` →
      :class:`CapabilityDenied` raised at wrap time, before the
      tool is ever invoked.
    - Cap is revoked / expired / has unmet caveats at server-side
      Send time → :class:`CapabilityDenied` raised from the
      ``agent.send(...)`` call inside the tool body (translated
      from the server's ``PERMISSION_DENIED``).
    """
    if (action_kind is None) == (descriptor is None):
        raise ValueError(
            "capability_required requires exactly one of `action_kind` or `descriptor`"
        )
    expected_action = action_kind if action_kind is not None else descriptor.action_kind  # type: ignore[union-attr]

    # Resolve cap_id once at wrap time — deterministic from canonical bytes.
    cap_id = _capability_id(capability)

    # Local validation: the cap's scope must permit the action_kind
    # the wrapper declared. Empty `permitted_actions` means
    # "all actions allowed" per yutha.models.capability.Scope. Catches
    # structural mismatches without going to the server.
    permitted = list(capability.scope.permitted_actions)
    if permitted and expected_action not in permitted:
        raise CapabilityDenied(
            f"capability scope permits actions {permitted!r}; "
            f"does not include wrapper's expected action_kind "
            f"{expected_action!r}"
        )

    def wrap(tool: T) -> T:
        # Mutate `_run` and `_arun` on the instance so the contextvar
        # is set during tool invocation regardless of how CrewAI
        # chooses to dispatch (sync vs async — CrewAI 0.x is mostly
        # sync, but tool authors can define `_arun` and CrewAI will
        # use it when available).
        original_run = getattr(tool, "_run", None)
        original_arun = getattr(tool, "_arun", None)

        if original_run is None and original_arun is None:
            raise TypeError(
                f"capability_required: tool {tool!r} defines neither "
                "_run nor _arun; not a usable CrewAI BaseTool"
            )

        if original_run is not None:
            def patched_run(*args: Any, **kwargs: Any) -> Any:
                token = ACTIVE_CAPABILITY_ID.set(cap_id)
                try:
                    return original_run(*args, **kwargs)
                finally:
                    ACTIVE_CAPABILITY_ID.reset(token)

            # Bind the patched method back; CrewAI's BaseTool stores
            # _run as an unbound (function-shaped) attribute on the
            # instance, so direct assignment is enough.
            tool._run = patched_run

        if original_arun is not None:
            async def patched_arun(*args: Any, **kwargs: Any) -> Any:
                token = ACTIVE_CAPABILITY_ID.set(cap_id)
                try:
                    return await original_arun(*args, **kwargs)
                finally:
                    ACTIVE_CAPABILITY_ID.reset(token)

            tool._arun = patched_arun

        return tool

    return wrap


__all__ = [
    "capability_required",
    "CapabilityDenied",
]

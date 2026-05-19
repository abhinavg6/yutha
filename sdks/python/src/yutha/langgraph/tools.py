"""Helpers callers wire into LangGraph nodes.

The headline export is :func:`capability_required` — a decorator that
gates an async function on a held :class:`yutha.Capability`.

Under v1.1 (RFC 0007), capability enforcement is **server-side at
Send**: the gRPC ``EnvelopeService.Send`` consults the supplied
``capability_id`` against the topology's
``require_capability_for_send`` flag and the cap's chain. The
decorator's job is therefore narrower than in v1.0:

1. **Validate locally** that the held cap's scope action_kind matches
   what the decorator's caller declared. A mismatch fails fast with
   :class:`CapabilityDenied` *before* any server work is done — no
   preflight RPC, no extra receipt. Catches "I decorated this node
   with the wrong action_kind for the cap I hold" coding errors.
2. **Set a context-local cap_id** for the duration of the wrapped
   call. :meth:`yutha.langgraph.YuthaAgent.send` reads it and
   supplies it to the gRPC ``Send`` request automatically. The
   server's check produces the load-bearing
   ``capability.check.{pass,deny}`` receipt; a deny surfaces as
   :class:`CapabilityDenied` raised from the send call inside the
   wrapped fn.

The decorator's surface (parameters, exception shape) is unchanged
from v1.0; the implementation just moved from "preflight Check RPC"
to "context-local cap_id supplied to subsequent sends."
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from yutha._capability_context import ACTIVE_CAPABILITY_ID
from yutha.client import YuthaClient
from yutha.crypto import sha256
from yutha.identity import Hash, HashAlgorithm
from yutha.models import Capability
from yutha.models.capability import ActionDescriptor, CheckOutcome


class CapabilityDenied(Exception):
    """Raised when a capability check refuses an action.

    Two construction shapes:

    - ``CapabilityDenied(reason: str)`` — used when the deny surfaces
      as a server-side ``PERMISSION_DENIED`` on
      :meth:`EnvelopeAPI.send <yutha.client.EnvelopeAPI.send>`. The
      structured :class:`CheckOutcome` isn't available on the wire;
      ``reason`` is whatever string the server attached.
    - ``CapabilityDenied.from_outcome(outcome: CheckOutcome)`` — used
      when a deny is produced client-side or by an explicit
      ``CapabilityService.Check`` call. The full
      :class:`CheckOutcome` is preserved on ``self.outcome`` for
      callers that want to introspect ``unmet_caveats`` etc.

    Both shapes expose ``reason: str`` and a string ``str(exc)``."""

    def __init__(
        self,
        reason: str,
        *,
        outcome: CheckOutcome | None = None,
    ) -> None:
        self.reason = reason
        self.outcome = outcome
        super().__init__(reason)

    @classmethod
    def from_outcome(cls, outcome: CheckOutcome) -> CapabilityDenied:
        """Build a :class:`CapabilityDenied` from a structured
        :class:`CheckOutcome` (e.g. one returned by an explicit
        ``client.capability.check(...)`` call). Adds unmet-caveat info
        to the reason string when present."""
        reason = outcome.deny_reason or "capability check denied"
        if outcome.unmet_caveats:
            reason = f"{reason} (unmet caveats: {', '.join(outcome.unmet_caveats)})"
        return cls(reason, outcome=outcome)


# Generic type for the decorated function's return value. We keep the
# wrapped fn fully generic so the decorator doesn't lose type info.
R = TypeVar("R")
AsyncFn = Callable[..., Awaitable[R]]


def _capability_id(capability: Capability) -> Hash:
    """Content-address a capability the same way the server does (see
    Rust ``content_address(&Capability)`` in ``yutha-capability``).
    Used to derive the ``capability_id`` the decorator threads through
    the context-var.

    ``Capability.canonical_bytes()`` already handles the
    ``ClearField("signatures")`` / ``ClearField("extensions")``
    normalization the server does, so this is byte-for-byte
    interoperable with the Rust derivation."""
    return Hash(
        algorithm=HashAlgorithm.SHA256,
        digest=sha256(capability.canonical_bytes()),
    )


def capability_required(
    client: YuthaClient,
    capability: Capability,
    *,
    action_kind: str | None = None,
    descriptor: ActionDescriptor | None = None,
) -> Callable[[AsyncFn[R]], AsyncFn[R]]:
    """Decorator: gate an async function on a held capability.

    Parameters
    ----------
    client
        The :class:`YuthaClient` (kept for API stability — no longer
        called at decoration time, but reserved for future preflight
        knobs).
    capability
        The :class:`yutha.Capability` the caller holds. Its
        content-address becomes the ``capability_id`` threaded into
        subsequent ``agent.send(...)`` calls inside the wrapped fn.
    action_kind
        The action_kind the decorator expects the cap to permit.
        Validated locally against ``capability.scope.action_kind``;
        a mismatch fails fast with :class:`CapabilityDenied`. Mutually
        exclusive with ``descriptor``.
    descriptor
        Full :class:`ActionDescriptor` for the same local-validation
        check. Mutually exclusive with ``action_kind``.

    Usage::

        cap = ...  # capability the agent holds
        agent = YuthaAgent.connect(...)

        @capability_required(agent.client, cap, action_kind="envelope.send")
        async def gated_node(state: dict) -> dict:
            await agent.send(...)  # cap_id supplied automatically via contextvar
            return state

    Deny paths:

    - Cap scope doesn't match the decorator's ``action_kind`` →
      :class:`CapabilityDenied` raised at the wrapper's first call,
      before the wrapped fn runs.
    - Cap is revoked / expired / has unmet caveats at server-side
      Send time → :class:`CapabilityDenied` raised from the
      ``agent.send(...)`` call inside the wrapped fn (translated from
      the server's ``PERMISSION_DENIED``).
    """
    if (action_kind is None) == (descriptor is None):
        raise ValueError(
            "capability_required requires exactly one of `action_kind` or `descriptor`"
        )
    expected_action = action_kind if action_kind is not None else descriptor.action_kind  # type: ignore[union-attr]

    # Resolve the cap_id once at decoration time — it's deterministic
    # from the cap's canonical bytes.
    cap_id = _capability_id(capability)

    # `client` is reserved for future preflight options; reference it
    # so callers/linters see it's intentional.
    _ = client

    def decorator(fn: AsyncFn[R]) -> AsyncFn[R]:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> R:
            # Local validation: the cap's scope must permit the
            # action_kind the decorator declared. Empty
            # `permitted_actions` means "all actions allowed" per
            # `yutha.models.capability.Scope` semantics. Catches
            # structural mismatches without going to the server.
            permitted = list(capability.scope.permitted_actions)
            if permitted and expected_action not in permitted:
                raise CapabilityDenied(
                    f"capability scope permits actions {permitted!r}; "
                    f"does not include decorator's expected action_kind "
                    f"{expected_action!r}"
                )

            # Thread cap_id into the async-context so any
            # `agent.send(...)` inside the wrapped fn picks it up and
            # supplies it to the server's Send-path check.
            token = ACTIVE_CAPABILITY_ID.set(cap_id)
            try:
                return await fn(*args, **kwargs)
            finally:
                ACTIVE_CAPABILITY_ID.reset(token)

        return wrapper

    return decorator


__all__ = [
    "capability_required",
    "CapabilityDenied",
    "ACTIVE_CAPABILITY_ID",
]

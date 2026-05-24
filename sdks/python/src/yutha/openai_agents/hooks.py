"""YuthaRunHooks — bridges openai-agents lifecycle events to the
Yutha substrate.

OpenAI Agents' :class:`agents.lifecycle.RunHooksBase` exposes
callbacks at every salient point in a ``Runner.run`` invocation:
agent start/end, tool start/end, handoff. This module pairs each
of those callbacks with a Yutha-side handler — the headline being
the handoff bridge that emits a Yutha envelope on every inter-
agent transition.

Tool and agent boundaries are deliberately **not** emitted as
Yutha receipts in v1 — openai-agents already ships with built-in
tracing for those, and adding parallel substrate receipts would
add noise and make audit-delta assertions harder. Cap-gated tools
emit their own ``capability.check.*`` receipts when they fire a
Send, which is the substrate-relevant tool event.

## How handoff bridging works

When ``Runner.run`` performs a handoff, the OpenAI Agents runtime
calls ``on_handoff(ctx, from_agent, to_agent)`` on every attached
hooks instance. The Yutha hook:

* Looks up the target agent in an optional ``peer_registry``
  mapping (``agent.name → YuthaOpenAIAgent``).
* If a peer is found, emits a Yutha envelope from this wrapper's
  agent to the peer's inbox, tagged with the source/destination
  names. The peer's dispatch loop receives it; its
  input-factory decides whether to act on the audit envelope
  (typically: skip).
* If no peer is registered for that name, emits a self-loop
  envelope tagged the same way — still produces audit receipts;
  doesn't deliver to any external inbox.

Either path produces ``envelope.send`` + ``envelope.deliver``
receipts that an auditor can use to reconstruct the agent
collaboration chain.

## Why a factory function (not a static subclass)

``YuthaRunHooks`` must be a ``RunHooksBase`` subclass for the
OpenAI Agents runner to drive it. But ``RunHooksBase`` lives
inside the optional ``openai-agents`` dep — declaring the
subclass statically would force the dep to be present just to
``import yutha.openai_agents.hooks``, which contradicts the
optional-extra model used everywhere else in this SDK. Instead,
the public surface is :func:`make_yutha_run_hooks`, a factory
that lazy-imports ``RunHooksBase`` and returns a fresh
subclass instance bound to the caller's wrapper.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from yutha.models import Performative, Recipient

if TYPE_CHECKING:
    from yutha.openai_agents.agent import YuthaOpenAIAgent


def make_yutha_run_hooks(
    *,
    wrapper: YuthaOpenAIAgent,
    emit_handoff_envelopes: bool = True,
    peer_registry: dict[str, YuthaOpenAIAgent] | None = None,
) -> Any:
    """Build a ``RunHooksBase``-compatible hooks instance bound to
    ``wrapper`` that bridges openai-agents lifecycle events to the
    Yutha substrate.

    Parameters
    ----------
    wrapper
        The :class:`YuthaOpenAIAgent` whose run is being hooked.
        Used to call ``wrapper.send(...)`` from the handoff bridge.
    emit_handoff_envelopes
        When ``True`` (default), the returned hooks instance emits
        a Yutha envelope per handoff. When ``False``, only logs the
        handoff to stdout — useful for unit tests that don't want
        substrate side effects.
    peer_registry
        Optional mapping from openai-agents ``Agent.name`` to the
        :class:`YuthaOpenAIAgent` wrapper for that agent. When a
        handoff target's name is in the registry, the emitted
        envelope is addressed to that peer's agent_id (cross-
        process audit). When the name isn't in the registry, the
        envelope is a self-loop (in-process audit only).

    Returns
    -------
    Any
        A fresh ``RunHooksBase`` subclass instance. Pass to
        ``Runner.run(..., hooks=...)``. The :class:`YuthaOpenAIAgent`
        wrapper invokes this factory once per wrapper and caches
        the result.

    Notes
    -----
    The returned object also carries two extra methods,
    :meth:`register_peer` and :meth:`register_peers`, which update
    the underlying peer registry. Useful when wrappers are
    constructed in dependency-cycle order and the full peer set
    isn't known until after construction.
    """
    from agents.lifecycle import RunHooksBase

    registry: dict[str, YuthaOpenAIAgent] = dict(peer_registry or {})

    class _YuthaRunHooks(RunHooksBase):
        """RunHooksBase subclass that bridges to the substrate.

        Internal: instantiated by :func:`make_yutha_run_hooks`.
        Mutable peer_registry is closed over rather than stored on
        ``self`` so the registration helpers below can update it
        in place after the Runner has already started using the
        hooks.
        """

        def register_peer(self, name: str, peer: YuthaOpenAIAgent) -> None:
            """Add (or replace) a peer mapping at runtime."""
            registry[name] = peer

        def register_peers(self, peers: dict[str, YuthaOpenAIAgent]) -> None:
            """Bulk-register peers."""
            registry.update(peers)

        async def on_handoff(
            self,
            context: Any,
            from_agent: Any,
            to_agent: Any,
        ) -> None:
            """Called by the Runner when a handoff fires. Emits a
            Yutha envelope capturing the transition."""
            _ = context
            from_name = getattr(from_agent, "name", "?")
            to_name = getattr(to_agent, "name", "?")

            if not emit_handoff_envelopes:
                print(
                    f"[yutha.openai_agents] handoff {from_name} → {to_name} (emit disabled)",
                    flush=True,
                )
                return

            # Look up the SOURCE wrapper too, so the audit envelope
            # is emitted FROM the actual source agent rather than
            # always from the wrapper that owns the hooks. Without
            # this lookup, a Runner.run started on agent A that
            # transitions A → B → C would emit both handoff
            # envelopes attributed to A, which is wrong for the
            # second hop. With the lookup, the second envelope is
            # correctly emitted from B (assuming B is in the
            # registry). Falls back to the owning wrapper when
            # the source isn't registered (e.g. anonymous handoff
            # targets) so the substrate audit log still captures
            # the transition with the best available sender.
            source_wrapper = registry.get(from_name, wrapper)
            peer = registry.get(to_name)
            recipient = (
                Recipient.for_agent(peer.agent_id)
                if peer is not None
                else Recipient.for_agent(source_wrapper.agent_id)
            )
            try:
                await source_wrapper.send(
                    recipient=recipient,
                    performative=Performative.INFORM,
                    payload=f"handoff: {from_name} -> {to_name}".encode(),
                    payload_schema_id="type.yutha.dev/v1/HandoffAudit",
                    tags=[
                        "openai_agents_handoff",
                        f"handoff_from:{from_name}",
                        f"handoff_to:{to_name}",
                    ],
                )
            except Exception as e:
                # Audit-only emission failing shouldn't crash the
                # Runner. Log and continue; the actual handoff still
                # happens in-process. Production deployments that
                # want fail-closed semantics on audit-emit failures
                # can subclass and re-raise.
                print(
                    f"[yutha.openai_agents] handoff-audit emit failed "
                    f"({from_name} → {to_name}): {type(e).__name__}: {e}",
                    flush=True,
                )

        # Stubs for the remaining lifecycle hooks — overridden as
        # no-ops with explicit signatures so users who want richer
        # substrate-side telemetry can subclass and add behavior
        # without consulting the openai-agents source.

        async def on_agent_start(self, context: Any, agent: Any) -> None:
            _ = (context, agent)

        async def on_agent_end(self, context: Any, agent: Any, output: Any) -> None:
            _ = (context, agent, output)

        async def on_tool_start(self, context: Any, agent: Any, tool: Any) -> None:
            _ = (context, agent, tool)

        async def on_tool_end(
            self,
            context: Any,
            agent: Any,
            tool: Any,
            result: Any,
        ) -> None:
            _ = (context, agent, tool, result)

        async def on_llm_start(
            self,
            context: Any,
            agent: Any,
            system_prompt: Any,
            input_items: Any,
        ) -> None:
            _ = (context, agent, system_prompt, input_items)

        async def on_llm_end(self, context: Any, agent: Any, response: Any) -> None:
            _ = (context, agent, response)

    return _YuthaRunHooks()


# Backwards-compatible name. Some users may want to import the
# factory by the simpler name; export both. The class itself is
# defined inside :func:`make_yutha_run_hooks` to keep the
# ``RunHooksBase`` import lazy, so there's no public
# ``YuthaRunHooks`` type to export — callers receive a runtime-
# constructed instance.
YuthaRunHooks = make_yutha_run_hooks


__all__ = ["YuthaRunHooks", "make_yutha_run_hooks"]

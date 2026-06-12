"""Python helpers for the Phase 3e simulation harness.

Wraps the ``yutha-ops sim`` CLI subcommand and parses its JSON
output into typed dataclasses suitable for CI gates, audit
pipelines, and regression-test assertions.

The wrapper shells out instead of re-implementing Cedar+ in Python:
the harness needs the full ``yutha_sim`` Rust stack
(``yutha-cedar-plus`` + ``yutha-receipt`` + ``yutha-passport``),
and shipping a Python re-implementation would double the
maintenance surface. Operators who want a richer Python-native
loop (custom personas, custom receipt-store) should call the Rust
library directly via PyO3 in a follow-on — out of scope for 3e-I.

Two ways to use the wrapper:

  - :func:`run_scenario` — load a YAML scenario from disk and run
    it end-to-end. Returns a parsed :class:`SimulationOutcome`.
  - :func:`parse_outcome_json` — parse a JSON blob you obtained
    some other way (e.g. piped from a separately-spawned
    ``yutha-ops sim --format json --output-file …``). Handy in
    tests that pre-generate outcomes.

The Receipt rows on
:attr:`SimulationOutcome.receipts` are NOT modelled as
dataclasses — the Rust :class:`yutha_receipt::Receipt` shape is
rich and Python consumers typically introspect via :class:`dict`
keys (``action_kind``, ``actor``, ``evidence``, etc.). The
per-persona summary IS modelled.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "PersonaState",
    "SimError",
    "SimulationOutcome",
    "TerminalReason",
    "parse_outcome_json",
    "run_scenario",
]


class SimError(RuntimeError):
    """Raised when the underlying ``yutha-ops sim`` subprocess
    failed (non-zero exit, missing binary, malformed JSON)."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class TerminalReason:
    """Stringly-typed reason the simulation exited.

    Two values mirror the Rust enum
    :class:`yutha_sim::TerminalReason`:

    - :attr:`BUDGET_EXHAUSTED` — the step budget ran out before
      every persona went idle.
    - :attr:`ALL_PERSONAS_IDLE` — every persona returned ``None``
      in the same step, so the harness exited early.

    Compare directly: ``outcome.terminal_reason == TerminalReason.ALL_PERSONAS_IDLE``.
    """

    BUDGET_EXHAUSTED = "budget_exhausted"
    ALL_PERSONAS_IDLE = "all_personas_idle"


@dataclass(frozen=True)
class PersonaState:
    """Per-persona terminal summary mirroring
    :class:`yutha_sim::PersonaState`."""

    name: str
    """The persona's instance name, e.g.
    ``support_agent#0``. Format is ``<discriminator>#<index>`` per
    the 3e-C harness's assignment scheme."""

    agent_id: str
    """The persona's assigned AgentId as a UUID string."""

    intents_emitted: int
    """How many times the persona's ``step()`` returned
    ``Some(intent)``. Idle steps don't increment."""

    final_note: str | None = None
    """Optional persona-private summary string. Currently always
    ``None`` (reserved for the 3e-J wire-up that surfaces
    persona-internal counters into the rendered outcome)."""


@dataclass(frozen=True)
class SimulationOutcome:
    """Result of running a scenario end-to-end.

    Same shape as the Rust :class:`yutha_sim::SimulationOutcome`
    JSON. Receipts are kept as plain :class:`dict` rows because
    operator code typically filters them inline rather than
    walking a strongly-typed schema."""

    total_steps: int
    """Steps actually executed. May be less than the configured
    ``ScenarioConfig.steps`` when every persona went idle."""

    terminal_reason: str
    """One of the :class:`TerminalReason` string constants."""

    persona_states: list[PersonaState] = field(default_factory=list)
    """One entry per persona, in declaration order."""

    receipts: list[dict[str, Any]] = field(default_factory=list)
    """Every receipt emitted across the simulation, in
    monotonic_ns order. Each entry is the JSON shape of
    :class:`yutha_receipt::Receipt` — common keys: ``action_kind``,
    ``actor``, ``swarm_id``, ``constitution_version``,
    ``occurred_at``, ``evidence`` (list of {key, type_url, value,
    redactable}), ``signatures``."""

    def count_by_action_kind(self) -> dict[str, int]:
        """Histogram of receipts by action_kind. Useful for CI
        gates like ``outcome.count_by_action_kind()['enforcement.detect'] >= 1``."""
        counts: dict[str, int] = {}
        for r in self.receipts:
            kind = r.get("action_kind", "<unknown>")
            counts[kind] = counts.get(kind, 0) + 1
        return counts

    def receipts_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        """All receipts whose ``subject_agent_id`` or
        ``target_agent_id`` evidence matches `agent_id`. Cheap
        filter for "what happened to this persona"."""
        match: list[dict[str, Any]] = []
        for r in self.receipts:
            for ev in r.get("evidence", []):
                if ev.get("key") not in {"subject_agent_id", "target_agent_id"}:
                    continue
                # Evidence values come back as the canonical Rust
                # JSON shape — `value: <utf-8 string from
                # bytes::to_string>` when the serde feature is on.
                val = ev.get("value")
                if _evidence_value_matches(val, agent_id):
                    match.append(r)
                    break
        return match


def _evidence_value_matches(raw_value: Any, agent_id_str: str) -> bool:
    """Best-effort match against the Rust receipt-evidence value
    shape. ``yutha_receipt::Evidence.value`` is ``Vec<u8>``; serde
    JSON encodes it as a list of integers OR a UTF-8 string
    depending on backend version. We accept both."""
    if isinstance(raw_value, str):
        return raw_value == agent_id_str
    if isinstance(raw_value, list):
        try:
            decoded = bytes(raw_value).decode("utf-8")
            return decoded == agent_id_str
        except (UnicodeDecodeError, ValueError):
            return False
    return False


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def run_scenario(
    scenario: str | Path,
    *,
    yutha_ops_path: str = "yutha-ops",
    extra_env: dict[str, str] | None = None,
) -> SimulationOutcome:
    """Run a scenario via ``yutha-ops sim --format json`` and parse
    the result.

    Pure-local — does NOT require a control plane connection or a
    bootstrap seed.

    :param scenario: Path to the YAML scenario file. The
        ``cedar_path`` / ``engine_config_path`` declarations inside
        the YAML resolve relative to the YAML file's parent
        directory.
    :param yutha_ops_path: Override the binary lookup. Default
        ``"yutha-ops"`` — resolved via ``$PATH`` if no slash present.
    :param extra_env: Optional env-var overrides for the spawned
        process. Merged on top of ``os.environ.copy()``.
    :raises SimError: subprocess failure, binary-not-found,
        non-JSON output, or shape mismatch.
    """
    args = [
        yutha_ops_path,
        "sim",
        str(scenario),
        "--format",
        "json",
    ]
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)

    try:
        proc = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
    except FileNotFoundError as exc:
        raise SimError(
            f"could not invoke {args[0]!r}: binary not found on PATH. "
            "Install yutha-ops or pass yutha_ops_path=..."
        ) from exc

    if proc.returncode != 0:
        raise SimError(
            f"yutha-ops sim exited {proc.returncode}.\nstderr:\n{proc.stderr}"
        )

    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SimError(
            f"yutha-ops sim produced non-JSON output:\n{proc.stdout[:500]}"
        ) from exc

    return parse_outcome_json(raw)


def parse_outcome_json(raw: dict[str, Any]) -> SimulationOutcome:
    """Parse a raw JSON dict into a :class:`SimulationOutcome`.

    Use this when the JSON came from somewhere other than this
    module's subprocess wrapper — e.g. a CI step that ran
    ``yutha-ops sim --format json --output-file outcome.json``
    earlier and now needs to load it.

    :raises SimError: when required top-level fields are missing.
    """
    try:
        total_steps = int(raw["total_steps"])
        terminal_reason = str(raw["terminal_reason"])
        persona_states_raw = raw.get("persona_states", [])
        receipts = list(raw.get("receipts", []))
    except (KeyError, TypeError, ValueError) as exc:
        raise SimError(
            f"SimulationOutcome JSON missing or malformed required fields: {exc}"
        ) from exc

    persona_states = [_parse_persona_state(p) for p in persona_states_raw]
    return SimulationOutcome(
        total_steps=total_steps,
        terminal_reason=terminal_reason,
        persona_states=persona_states,
        receipts=receipts,
    )


def _parse_persona_state(raw: dict[str, Any]) -> PersonaState:
    return PersonaState(
        name=raw["name"],
        agent_id=raw["agent_id"],
        intents_emitted=int(raw["intents_emitted"]),
        final_note=raw.get("final_note"),
    )

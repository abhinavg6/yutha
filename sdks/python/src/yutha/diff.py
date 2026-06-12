"""Python helpers for the Phase 3d constitution-diff engine.

Wraps the `yutha-ops diff` CLI subcommand and parses its JSON output
into typed dataclasses suitable for CI gates, audit pipelines, and
OpenTelemetry attribute emission.

Two entry points mirror the CLI's two modes:

  - :func:`diff_constitutions` — static structural diff.
    Pure-local, no server contact, no seed needed. Takes the four
    file paths (left cedar + left engine YAML + right cedar + right
    engine YAML) and returns a parsed :class:`ConstitutionDiff`.

  - :func:`diff_constitutions_against_window` — behavioural diff.
    Composes the replay engine: creates a session against the right
    candidate, runs the window, queries production + session stores,
    and attaches the receipt-count + chain-divergence delta to the
    returned :class:`ConstitutionDiff` (the ``behavioural`` field).

Both functions shell out to ``yutha-ops diff`` (locating the binary
on ``$PATH`` by default). The JSON shape they parse is documented at
``crates/yutha-diff/src/render/json.rs``; the schema marker
``yutha-diff/v1`` rides on every output as
:attr:`ConstitutionDiff.diff_schema_version`.

The engine-config item types (named predicates, scoring rules,
procedures, enforcement rules) are not modelled as dataclasses — the
JSON shape is rich and Python consumers typically introspect via
:class:`dict`. The Cedar policy and behavioural rows ARE modelled so
operator code can write strongly-typed CI gates.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "BehaviouralDiff",
    "CedarPolicyEntry",
    "ChainDivergence",
    "ConstitutionDiff",
    "DiffError",
    "NamedItemChange",
    "NamedItemsDiff",
    "ReceiptCountDelta",
    "diff_constitutions",
    "diff_constitutions_against_window",
]

DIFF_SCHEMA_VERSION = "yutha-diff/v1"
"""The schema marker the Rust crate stamps on every output. Pin in
the consumer's parser before reading any other field."""


class DiffError(RuntimeError):
    """Raised when the underlying ``yutha-ops diff`` subprocess
    failed (non-zero exit code, missing binary, malformed JSON)."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CedarPolicyEntry:
    """One Cedar policy entry surfaced in the diff. Mirrors the
    Rust :class:`yutha_diff::CedarPolicyEntry` JSON shape."""

    name: str
    """Either the operator's ``@id("...")`` annotation OR a stable
    structural fingerprint when ``@id`` was omitted."""
    annotated: bool
    """``True`` when source carried explicit ``@id``; ``False`` when
    the name is the synthetic fingerprint. Useful for CI gates that
    want to fail on un-annotated policies."""
    effect: str  # "permit" or "forbid"
    """Cedar effect — exactly ``"permit"`` or ``"forbid"``."""
    source: str
    """Rendered Cedar source text for this single policy."""


@dataclass(frozen=True)
class NamedItemChange:
    """One modified-item entry. Same name on both sides, different
    content. ``left`` and ``right`` are :class:`dict` because the
    engine-config types aren't modelled as dataclasses (see module
    docstring)."""

    name: str
    left: Any  # dict for engine-config items, CedarPolicyEntry-shaped dict for cedar
    right: Any


@dataclass(frozen=True)
class NamedItemsDiff:
    """Generic add/remove/modify triple. One section type per diff
    section (cedar policies + the four engine-config families)."""

    added: list[Any] = field(default_factory=list)
    removed: list[Any] = field(default_factory=list)
    modified: list[NamedItemChange] = field(default_factory=list)

    def is_empty(self) -> bool:
        """``True`` when none of the three buckets has any entries."""
        return not (self.added or self.removed or self.modified)


@dataclass(frozen=True)
class ReceiptCountDelta:
    """One side-by-side receipt-count row from the behavioural
    diff."""

    action_kind: str
    subject_agent_id: str
    production_count: int
    candidate_count: int

    @property
    def delta(self) -> int:
        """``candidate_count - production_count``. Positive = the
        candidate would emit MORE receipts than production; negative
        = fewer."""
        return self.candidate_count - self.production_count


@dataclass(frozen=True)
class ChainDivergence:
    """One enforcement-chain divergence row. Surfaces when the
    candidate's enforcement chain would have fired differently than
    production over the same window."""

    target_agent_id: str
    enforcement_rule_id: str
    stage: str  # "detect" | "coach" | "quarantine" | "evict" | "reverse"
    production_count: int
    candidate_count: int

    @property
    def delta(self) -> int:
        """Signed delta; positive = candidate fires MORE on this
        stage (rule-tightening preview), negative = fires fewer."""
        return self.candidate_count - self.production_count


@dataclass(frozen=True)
class BehaviouralDiff:
    """Receipt-count deltas + enforcement chain divergences over a
    replay window. Populated only by
    :func:`diff_constitutions_against_window`."""

    window_from_unix_ns: int
    window_to_unix_ns: int
    replay_session_id: str
    receipt_count_deltas: list[ReceiptCountDelta]
    chain_divergences: list[ChainDivergence]


@dataclass(frozen=True)
class ConstitutionDiff:
    """The top-level diff value. Same shape as the Rust
    :class:`yutha_diff::ConstitutionDiff` JSON."""

    diff_schema_version: str
    left_constitution_version: str
    right_constitution_version: str
    schema_version_change: tuple[str, str] | None
    cedar_policies: NamedItemsDiff  # entries are CedarPolicyEntry
    named_predicates: NamedItemsDiff  # entries are dict
    scoring_rules: NamedItemsDiff
    procedures: NamedItemsDiff
    enforcement_rules: NamedItemsDiff
    behavioural: BehaviouralDiff | None

    def is_empty_structurally(self) -> bool:
        """``True`` when no structural section reports any change.
        The behavioural diff (if populated) is intentionally
        excluded — this predicate answers "should this diff gate a
        PR?"."""
        return (
            self.schema_version_change is None
            and self.cedar_policies.is_empty()
            and self.named_predicates.is_empty()
            and self.scoring_rules.is_empty()
            and self.procedures.is_empty()
            and self.enforcement_rules.is_empty()
        )


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def diff_constitutions(
    *,
    left_cedar: str | Path,
    left_engine_config: str | Path,
    right_cedar: str | Path,
    right_engine_config: str | Path,
    left_version: str = "left",
    right_version: str = "right",
    yutha_ops_path: str = "yutha-ops",
) -> ConstitutionDiff:
    """Static structural diff. Shells out to ``yutha-ops diff
    --format json`` and parses the result.

    Pure-local — does NOT require a control plane connection or a
    bootstrap seed. The four file-path args are resolved by the
    spawned process, so relative paths are interpreted against the
    caller's cwd.

    :param left_cedar: Path to the baseline Cedar policy source.
    :param left_engine_config: Path to the baseline engine-config YAML.
    :param right_cedar: Path to the candidate Cedar source.
    :param right_engine_config: Path to the candidate engine config.
    :param left_version: Human-friendly label for the left side
        (surfaces in the rendered title).
    :param right_version: Human-friendly label for the right side.
    :param yutha_ops_path: Override the binary lookup. Defaults to
        ``yutha-ops`` (resolved via ``$PATH``).
    :raises DiffError: if the subprocess fails or its output isn't
        valid JSON with the expected schema marker.
    """
    args = [
        yutha_ops_path,
        "diff",
        "--left-cedar",
        str(left_cedar),
        "--left-engine-config",
        str(left_engine_config),
        "--right-cedar",
        str(right_cedar),
        "--right-engine-config",
        str(right_engine_config),
        "--left-version",
        left_version,
        "--right-version",
        right_version,
        "--format",
        "json",
    ]
    return _invoke(args)


def diff_constitutions_against_window(
    *,
    left_cedar: str | Path,
    left_engine_config: str | Path,
    right_cedar: str | Path,
    right_engine_config: str | Path,
    window_from_unix_ns: int,
    window_to_unix_ns: int,
    action_kind_filter: list[str] | None = None,
    left_version: str = "left",
    right_version: str = "right",
    bootstrap_seed_hex: str | None = None,
    grpc_addr: str | None = None,
    yutha_ops_path: str = "yutha-ops",
) -> ConstitutionDiff:
    """Behavioural diff. Composes the replay engine and attaches the
    delta as :attr:`ConstitutionDiff.behavioural`.

    Requires a running control plane reachable by the spawned
    ``yutha-ops`` process. Auth uses the same seed-derived operator
    keypair the server's bootstrap was configured with — pass via
    ``bootstrap_seed_hex`` (or set ``YUTHA_BOOTSTRAP_SEED`` in the
    parent env before calling).

    :param window_from_unix_ns: Inclusive lower bound (monotonic_ns).
    :param window_to_unix_ns: Inclusive upper bound (monotonic_ns).
    :param action_kind_filter: Optional whitelist. Empty/None →
        default canonical set (``envelope.send`` +
        ``constitution.evaluate.*`` + ``enforcement.*``).
    :param bootstrap_seed_hex: 32-byte hex seed. If ``None``, the
        spawned process picks up ``YUTHA_BOOTSTRAP_SEED`` from env.
    :param grpc_addr: Override the control-plane endpoint. Default
        is whatever ``YUTHA_GRPC_ADDR`` resolves to in the parent
        env, falling back to ``127.0.0.1:50051``.
    :raises DiffError: on subprocess failure, malformed JSON, or
        schema-marker mismatch.
    """
    args = [
        yutha_ops_path,
        "diff",
        "--left-cedar",
        str(left_cedar),
        "--left-engine-config",
        str(left_engine_config),
        "--right-cedar",
        str(right_cedar),
        "--right-engine-config",
        str(right_engine_config),
        "--left-version",
        left_version,
        "--right-version",
        right_version,
        "--window-from",
        str(window_from_unix_ns),
        "--window-to",
        str(window_to_unix_ns),
        "--format",
        "json",
    ]
    for kind in action_kind_filter or []:
        args.extend(["--filter", kind])

    env = os.environ.copy()
    if bootstrap_seed_hex is not None:
        env["YUTHA_BOOTSTRAP_SEED"] = bootstrap_seed_hex
    if grpc_addr is not None:
        env["YUTHA_GRPC_ADDR"] = grpc_addr
    return _invoke(args, env=env)


# ---------------------------------------------------------------------------
# Subprocess + JSON parsing
# ---------------------------------------------------------------------------


def _invoke(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
) -> ConstitutionDiff:
    try:
        proc = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
    except FileNotFoundError as exc:
        raise DiffError(
            f"could not invoke {args[0]!r}: binary not found on PATH. "
            "Install yutha-ops or pass yutha_ops_path=..."
        ) from exc

    if proc.returncode != 0:
        raise DiffError(f"yutha-ops diff exited {proc.returncode}.\nstderr:\n{proc.stderr}")

    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise DiffError(f"yutha-ops diff produced non-JSON output:\n{proc.stdout[:500]}") from exc

    schema = raw.get("diff_schema_version")
    if schema != DIFF_SCHEMA_VERSION:
        raise DiffError(
            f"diff schema marker {schema!r} does not match expected "
            f"{DIFF_SCHEMA_VERSION!r}. The Python helpers may be out of "
            "sync with the installed yutha-ops version."
        )
    return _parse(raw)


def _parse(raw: dict[str, Any]) -> ConstitutionDiff:
    schema_change = raw.get("schema_version_change")
    schema_tuple: tuple[str, str] | None = (
        (schema_change[0], schema_change[1]) if schema_change is not None else None
    )

    return ConstitutionDiff(
        diff_schema_version=raw["diff_schema_version"],
        left_constitution_version=raw["left_constitution_version"],
        right_constitution_version=raw["right_constitution_version"],
        schema_version_change=schema_tuple,
        cedar_policies=_parse_cedar_section(raw["cedar_policies"]),
        named_predicates=_parse_passthrough_section(raw["named_predicates"]),
        scoring_rules=_parse_passthrough_section(raw["scoring_rules"]),
        procedures=_parse_passthrough_section(raw["procedures"]),
        enforcement_rules=_parse_passthrough_section(raw["enforcement_rules"]),
        behavioural=_parse_behavioural(raw.get("behavioural")),
    )


def _parse_cedar_section(section: dict[str, Any]) -> NamedItemsDiff:
    return NamedItemsDiff(
        added=[_parse_cedar_entry(e) for e in section.get("added", [])],
        removed=[_parse_cedar_entry(e) for e in section.get("removed", [])],
        modified=[
            NamedItemChange(
                name=m["name"],
                left=_parse_cedar_entry(m["left"]),
                right=_parse_cedar_entry(m["right"]),
            )
            for m in section.get("modified", [])
        ],
    )


def _parse_cedar_entry(raw: dict[str, Any]) -> CedarPolicyEntry:
    return CedarPolicyEntry(
        name=raw["name"],
        annotated=raw["annotated"],
        effect=raw["effect"],
        source=raw["source"],
    )


def _parse_passthrough_section(section: dict[str, Any]) -> NamedItemsDiff:
    """Engine-config sections: pass items through as raw dicts.
    Operator code introspects via :class:`dict` access."""
    return NamedItemsDiff(
        added=list(section.get("added", [])),
        removed=list(section.get("removed", [])),
        modified=[
            NamedItemChange(name=m["name"], left=m["left"], right=m["right"])
            for m in section.get("modified", [])
        ],
    )


def _parse_behavioural(raw: dict[str, Any] | None) -> BehaviouralDiff | None:
    if raw is None:
        return None
    return BehaviouralDiff(
        window_from_unix_ns=raw["window_from_unix_ns"],
        window_to_unix_ns=raw["window_to_unix_ns"],
        replay_session_id=raw["replay_session_id"],
        receipt_count_deltas=[
            ReceiptCountDelta(
                action_kind=d["action_kind"],
                subject_agent_id=d["subject_agent_id"],
                production_count=d["production_count"],
                candidate_count=d["candidate_count"],
            )
            for d in raw.get("receipt_count_deltas", [])
        ],
        chain_divergences=[
            ChainDivergence(
                target_agent_id=c["target_agent_id"],
                enforcement_rule_id=c["enforcement_rule_id"],
                stage=c["stage"],
                production_count=c["production_count"],
                candidate_count=c["candidate_count"],
            )
            for c in raw.get("chain_divergences", [])
        ],
    )

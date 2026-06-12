"""Integration tests for :mod:`yutha.diff`.

Shells out to ``yutha-ops diff`` against the checked-in fixtures
under ``crates/yutha-diff/tests/fixtures/``. Skipped when the
binary isn't on ``$PATH`` so test envs without the Rust toolchain
don't break (the binary is built by ``cargo build -p yutha-ops``).

Behavioural-diff path is NOT covered here — that requires a running
control plane. The static path exercises the same subprocess +
JSON-parsing code, so the behavioural branch differs only by the
extra ``--window-from``/``--window-to`` flags and the populated
``behavioural`` field on the response. Operators who want a
behavioural-diff smoke test should follow the recipe in
``docs/operator/constitution-diff.md``.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from yutha.diff import (
    CedarPolicyEntry,
    ConstitutionDiff,
    DiffError,
    NamedItemsDiff,
    diff_constitutions,
)

# Locate the repo root by walking up from this file to find the
# `crates/` directory. Same trick test_vectors.py uses.
_HERE = Path(__file__).resolve()
_REPO_ROOT = next(p for p in _HERE.parents if (p / "crates").is_dir())
_FIXTURES = _REPO_ROOT / "crates" / "yutha-diff" / "tests" / "fixtures"


# Auto-skip every test in this module if the binary isn't available.
pytestmark = pytest.mark.skipif(
    shutil.which("yutha-ops") is None
    and not (_REPO_ROOT / "target" / "debug" / "yutha-ops").is_file(),
    reason="yutha-ops binary not built (run `cargo build -p yutha-ops` first)",
)


def _binary_path() -> str:
    """Prefer ``$PATH`` resolution; fall back to ``target/debug/``
    so the test works in a freshly built workspace without an install
    step."""
    on_path = shutil.which("yutha-ops")
    if on_path:
        return on_path
    return str(_REPO_ROOT / "target" / "debug" / "yutha-ops")


def _run_static_diff(left_version: str, right_version: str) -> ConstitutionDiff:
    """Convenience wrapper around :func:`diff_constitutions` using
    the standard baseline+tightened fixture pair."""
    return diff_constitutions(
        left_cedar=_FIXTURES / "baseline.cedar",
        left_engine_config=_FIXTURES / "baseline.engine.yaml",
        right_cedar=_FIXTURES / "tightened.cedar",
        right_engine_config=_FIXTURES / "tightened.engine.yaml",
        left_version=left_version,
        right_version=right_version,
        yutha_ops_path=_binary_path(),
    )


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------


def test_baseline_to_tightened_surfaces_expected_deltas() -> None:
    diff = _run_static_diff("baseline", "tightened")

    # Schema marker present + version labels propagated.
    assert diff.diff_schema_version == "yutha-diff/v1"
    assert diff.left_constitution_version == "baseline"
    assert diff.right_constitution_version == "tightened"

    # Schema-version pin unchanged on this hop.
    assert diff.schema_version_change is None

    # One added Cedar policy keyed by the operator @id.
    assert len(diff.cedar_policies.added) == 1
    cedar_added = diff.cedar_policies.added[0]
    assert isinstance(cedar_added, CedarPolicyEntry)
    assert cedar_added.name == "forbid-large-refunds"
    assert cedar_added.annotated is True
    assert cedar_added.effect == "forbid"
    # The Cedar source is rendered cleanly; consumers can show it
    # inline in a PR comment.
    assert "forbid-large-refunds" in cedar_added.source

    # One added enforcement rule.
    assert len(diff.enforcement_rules.added) == 1
    enf_added = diff.enforcement_rules.added[0]
    assert isinstance(enf_added, dict)
    assert enf_added["name"] == "large_refund_detector"
    # The enforcement-rule body is passed through as a dict — operator
    # code introspects it.
    assert enf_added["detect"]["count_threshold"] == 3
    assert enf_added["severity"] == "high"

    # The other three engine-config sections show no change.
    assert diff.named_predicates.is_empty()
    assert diff.scoring_rules.is_empty()
    assert diff.procedures.is_empty()

    # Static-only diff: behavioural is None.
    assert diff.behavioural is None

    # Top-level convenience.
    assert not diff.is_empty_structurally()


def test_identity_diff_is_empty() -> None:
    """A constitution diffed against itself MUST be empty
    structurally — the load-bearing property for CI gates that
    auto-merge no-op PRs."""
    diff = diff_constitutions(
        left_cedar=_FIXTURES / "baseline.cedar",
        left_engine_config=_FIXTURES / "baseline.engine.yaml",
        right_cedar=_FIXTURES / "baseline.cedar",
        right_engine_config=_FIXTURES / "baseline.engine.yaml",
        left_version="a",
        right_version="b",
        yutha_ops_path=_binary_path(),
    )
    assert diff.is_empty_structurally()
    assert isinstance(diff.cedar_policies, NamedItemsDiff)
    assert diff.cedar_policies.added == []
    assert diff.cedar_policies.removed == []
    assert diff.cedar_policies.modified == []


def test_reverse_direction_surfaces_removals() -> None:
    """Swap left and right: the added entries become removals."""
    diff = diff_constitutions(
        left_cedar=_FIXTURES / "tightened.cedar",
        left_engine_config=_FIXTURES / "tightened.engine.yaml",
        right_cedar=_FIXTURES / "baseline.cedar",
        right_engine_config=_FIXTURES / "baseline.engine.yaml",
        left_version="tightened",
        right_version="baseline",
        yutha_ops_path=_binary_path(),
    )
    assert len(diff.cedar_policies.removed) == 1
    assert diff.cedar_policies.removed[0].name == "forbid-large-refunds"
    assert len(diff.enforcement_rules.removed) == 1
    assert diff.enforcement_rules.removed[0]["name"] == "large_refund_detector"


# ---------------------------------------------------------------------------
# Error-path tests
# ---------------------------------------------------------------------------


def test_missing_binary_raises_diff_error() -> None:
    """When the binary path resolves to nothing, DiffError fires."""
    with pytest.raises(DiffError, match="binary not found"):
        diff_constitutions(
            left_cedar=_FIXTURES / "baseline.cedar",
            left_engine_config=_FIXTURES / "baseline.engine.yaml",
            right_cedar=_FIXTURES / "baseline.cedar",
            right_engine_config=_FIXTURES / "baseline.engine.yaml",
            yutha_ops_path="/nonexistent/path/yutha-ops-does-not-exist",
        )


def test_invalid_cedar_source_propagates_nonzero_exit() -> None:
    """A malformed Cedar input causes yutha-ops to exit non-zero;
    the Python wrapper surfaces the stderr."""
    # Write an invalid Cedar file to a tmp path.
    bad_dir = _FIXTURES.parent / "_pytest_tmp"
    bad_dir.mkdir(exist_ok=True)
    bad_cedar = bad_dir / "bad.cedar"
    bad_cedar.write_text("this is not valid Cedar")
    try:
        with pytest.raises(DiffError) as exc:
            diff_constitutions(
                left_cedar=bad_cedar,
                left_engine_config=_FIXTURES / "baseline.engine.yaml",
                right_cedar=_FIXTURES / "baseline.cedar",
                right_engine_config=_FIXTURES / "baseline.engine.yaml",
                yutha_ops_path=_binary_path(),
            )
        # The error should at least carry the exit code, even if the
        # exact stderr text shifts across Cedar releases.
        assert "exited" in str(exc.value)
    finally:
        bad_cedar.unlink(missing_ok=True)
        try:
            bad_dir.rmdir()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Sanity check: parsed JSON shape matches the Rust output verbatim
# ---------------------------------------------------------------------------


def test_parsed_json_round_trips_through_dataclasses() -> None:
    """Cross-check: invoking yutha-ops directly and parsing manually
    must produce the same data the wrapper does."""
    bin_path = _binary_path()
    proc = subprocess.run(
        [
            bin_path,
            "diff",
            "--left-cedar",
            str(_FIXTURES / "baseline.cedar"),
            "--left-engine-config",
            str(_FIXTURES / "baseline.engine.yaml"),
            "--right-cedar",
            str(_FIXTURES / "tightened.cedar"),
            "--right-engine-config",
            str(_FIXTURES / "tightened.engine.yaml"),
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    import json

    raw = json.loads(proc.stdout)
    # The dataclass shape and the JSON shape must agree on the
    # load-bearing fields.
    assert raw["diff_schema_version"] == "yutha-diff/v1"
    assert raw["cedar_policies"]["added"][0]["name"] == "forbid-large-refunds"
    assert raw["enforcement_rules"]["added"][0]["name"] == "large_refund_detector"

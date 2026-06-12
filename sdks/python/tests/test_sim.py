"""Phase 3e — Python wrapper tests for ``yutha.sim``.

Auto-skips when the ``yutha-ops`` binary isn't reachable (i.e.
the developer hasn't run ``cargo build -p yutha-ops`` yet).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from yutha.sim import (
    PersonaState,
    SimError,
    SimulationOutcome,
    TerminalReason,
    parse_outcome_json,
    run_scenario,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCENARIO = (
    REPO_ROOT
    / "crates"
    / "yutha-sim"
    / "examples"
    / "scenarios"
    / "refund_attacker_meets_cap"
    / "scenario.yaml"
)


def _yutha_ops() -> str | None:
    """Locate a built ``yutha-ops`` binary. Checks the workspace's
    ``target/debug`` first, then ``target/release``, then ``$PATH``."""
    candidates = [
        REPO_ROOT / "target" / "debug" / "yutha-ops",
        REPO_ROOT / "target" / "release" / "yutha-ops",
    ]
    for p in candidates:
        if p.is_file():
            return str(p)
    found = shutil.which("yutha-ops")
    return found


# ---------------------------------------------------------------------------
# Pure-parser tests (no subprocess)
# ---------------------------------------------------------------------------


def test_parse_outcome_json_empty_succeeds() -> None:
    """Minimal valid shape — all collections empty, no personas."""
    raw = {
        "total_steps": 0,
        "terminal_reason": "all_personas_idle",
        "persona_states": [],
        "receipts": [],
    }
    outcome = parse_outcome_json(raw)
    assert outcome.total_steps == 0
    assert outcome.terminal_reason == TerminalReason.ALL_PERSONAS_IDLE
    assert outcome.persona_states == []
    assert outcome.receipts == []


def test_parse_outcome_json_populated_shape() -> None:
    raw = {
        "total_steps": 12,
        "terminal_reason": "budget_exhausted",
        "persona_states": [
            {
                "name": "support_agent#0",
                "agent_id": "01923456-789a-7000-8000-000000000001",
                "intents_emitted": 12,
                "final_note": None,
            },
            {
                "name": "refund_attacker#1",
                "agent_id": "01923456-789a-7000-8000-000000000002",
                "intents_emitted": 8,
            },
        ],
        "receipts": [
            {"action_kind": "constitution.evaluate.pass", "evidence": []},
            {"action_kind": "constitution.evaluate.deny", "evidence": []},
            {"action_kind": "constitution.evaluate.deny", "evidence": []},
        ],
    }
    outcome = parse_outcome_json(raw)
    assert outcome.total_steps == 12
    assert outcome.terminal_reason == TerminalReason.BUDGET_EXHAUSTED
    assert len(outcome.persona_states) == 2
    assert isinstance(outcome.persona_states[0], PersonaState)
    assert outcome.persona_states[1].intents_emitted == 8
    assert outcome.persona_states[1].final_note is None
    # Histogram helper.
    counts = outcome.count_by_action_kind()
    assert counts == {
        "constitution.evaluate.pass": 1,
        "constitution.evaluate.deny": 2,
    }


def test_parse_outcome_json_missing_fields_raises_simerror() -> None:
    with pytest.raises(SimError):
        parse_outcome_json({"terminal_reason": "budget_exhausted"})


def test_receipts_for_agent_matches_string_evidence() -> None:
    """When yutha-receipt is built with the `serde` feature, evidence
    `value` arrives as a UTF-8 string. The helper accepts that
    shape."""
    target_id = "01923456-789a-7000-8000-000000000002"
    raw = {
        "total_steps": 1,
        "terminal_reason": "budget_exhausted",
        "persona_states": [],
        "receipts": [
            {
                "action_kind": "constitution.evaluate.deny",
                "evidence": [
                    {"key": "subject_agent_id", "value": target_id},
                    {"key": "other", "value": "ignored"},
                ],
            },
            {
                "action_kind": "envelope.send",
                "evidence": [
                    {
                        "key": "subject_agent_id",
                        "value": "01923456-789a-7000-8000-999999999999",
                    },
                ],
            },
        ],
    }
    outcome = parse_outcome_json(raw)
    matches = outcome.receipts_for_agent(target_id)
    assert len(matches) == 1
    assert matches[0]["action_kind"] == "constitution.evaluate.deny"


def test_receipts_for_agent_matches_bytes_array_evidence() -> None:
    """When yutha-receipt's `value` arrives as a list of bytes
    (older serde builds), the helper decodes + matches."""
    target_id = "01923456-789a-7000-8000-000000000002"
    encoded = list(target_id.encode("utf-8"))
    raw = {
        "total_steps": 1,
        "terminal_reason": "budget_exhausted",
        "persona_states": [],
        "receipts": [
            {
                "action_kind": "enforcement.detect",
                "evidence": [{"key": "target_agent_id", "value": encoded}],
            }
        ],
    }
    outcome = parse_outcome_json(raw)
    matches = outcome.receipts_for_agent(target_id)
    assert len(matches) == 1


# ---------------------------------------------------------------------------
# End-to-end subprocess test (auto-skips when yutha-ops not built)
# ---------------------------------------------------------------------------


def test_run_scenario_end_to_end_against_built_binary() -> None:
    binary = _yutha_ops()
    if binary is None:
        pytest.skip("yutha-ops not built — run `cargo build -p yutha-ops` first")
    if not SCENARIO.is_file():
        pytest.skip(f"scenario fixture missing at {SCENARIO}")

    outcome = run_scenario(SCENARIO, yutha_ops_path=binary)

    # Shape sanity: hit the budget (20 steps per the fixture YAML).
    assert isinstance(outcome, SimulationOutcome)
    assert outcome.total_steps == 20
    assert outcome.terminal_reason == TerminalReason.BUDGET_EXHAUSTED
    assert len(outcome.persona_states) == 2

    # The personas should be in declaration order.
    names = [p.name for p in outcome.persona_states]
    assert names[0].startswith("support_agent#")
    assert names[1].startswith("refund_attacker#")

    # Behavioural pin: the cap forbid rule should fire (>= 1 deny)
    # and the enforcement chain should at least surface a detect.
    counts = outcome.count_by_action_kind()
    assert counts.get("constitution.evaluate.deny", 0) >= 1, counts
    assert counts.get("enforcement.detect", 0) >= 1, counts


def test_run_scenario_missing_binary_raises_simerror(tmp_path: Path) -> None:
    fake_scenario = tmp_path / "scenario.yaml"
    fake_scenario.write_text("constitution: {}\nagents: []\nsteps: 1\ntick_ms: 100\n")
    with pytest.raises(SimError) as excinfo:
        run_scenario(fake_scenario, yutha_ops_path="definitely-not-a-real-binary-xyz")
    assert "binary not found" in str(excinfo.value)


def test_run_scenario_propagates_nonzero_exit(tmp_path: Path) -> None:
    """Pass a malformed YAML so yutha-ops fails. Auto-skip when
    the binary isn't built."""
    binary = _yutha_ops()
    if binary is None:
        pytest.skip("yutha-ops not built")
    bad = tmp_path / "bad.yaml"
    bad.write_text("not: a: scenario:")
    with pytest.raises(SimError) as excinfo:
        run_scenario(bad, yutha_ops_path=binary)
    # Should surface stderr.
    assert "yutha-ops sim exited" in str(excinfo.value)


# ---------------------------------------------------------------------------
# JSON round-trip from a separately-spawned yutha-ops sim
# ---------------------------------------------------------------------------


def test_parse_outcome_json_round_trips_from_disk(tmp_path: Path) -> None:
    """Confirm the JSON dump shape matches what parse_outcome_json
    consumes — useful for CI workflows that pipe through a file."""
    raw = {
        "total_steps": 3,
        "terminal_reason": "all_personas_idle",
        "persona_states": [
            {
                "name": "support_agent#0",
                "agent_id": "01923456-789a-7000-8000-000000000003",
                "intents_emitted": 3,
            }
        ],
        "receipts": [],
    }
    p = tmp_path / "out.json"
    p.write_text(json.dumps(raw))
    loaded = parse_outcome_json(json.loads(p.read_text()))
    assert loaded.total_steps == 3
    assert loaded.persona_states[0].intents_emitted == 3

"""Scaffolding checks for `yutha.crewai`.

Mirrors ``test_langgraph_scaffold.py``: the sub-package imports
without the optional extra, and the ``_require_crewai`` helper
behaves correctly for both the "extra installed" and "extra
missing" cases. The full adapter primitives live in
``test_crewai_agent.py`` (unit) and ``test_crewai_integration.py``
(live-server, skip-by-default).
"""

from __future__ import annotations

import importlib
import sys
from unittest import mock

import pytest


def test_namespace_imports_without_crewai() -> None:
    """``import yutha.crewai`` must succeed even when CrewAI isn't
    installed. The package is a namespace; only the helpers that
    touch CrewAI types need the extra."""
    import yutha.crewai

    assert hasattr(yutha.crewai, "_require_crewai")
    assert hasattr(yutha.crewai, "YuthaCrewAgent")
    assert hasattr(yutha.crewai, "capability_required")
    assert hasattr(yutha.crewai, "CapabilityDenied")


def test_require_crewai_passes_when_installed() -> None:
    """When CrewAI is on the import path, the helper is a no-op.
    Skip if the extra isn't installed in the current environment."""
    try:
        import crewai  # noqa: F401
    except ImportError:
        pytest.skip("crewai extra not installed in this environment")

    from yutha.crewai import _require_crewai

    _require_crewai()  # raises on failure


def test_require_crewai_raises_clearly_when_missing() -> None:
    """When CrewAI is missing, the helper raises an ``ImportError``
    with a useful pointer to the extra. Simulate the missing state
    by hiding the import."""
    from yutha.crewai import _require_crewai

    saved = sys.modules.pop("crewai", None)
    try:
        with mock.patch.dict(sys.modules, {"crewai": None}):
            with pytest.raises(ImportError, match=r"pip install 'yutha\[crewai\]'"):
                _require_crewai()
    finally:
        if saved is not None:
            sys.modules["crewai"] = saved


def test_importlib_machinery_finds_yutha_crewai() -> None:
    """Sanity: the package is a real importable module, not a stub."""
    spec = importlib.util.find_spec("yutha.crewai")
    assert spec is not None
    assert spec.origin is not None
    assert spec.origin.endswith("__init__.py")


def test_capability_denied_is_shared_with_langgraph() -> None:
    """``yutha.crewai.CapabilityDenied`` and
    ``yutha.langgraph.CapabilityDenied`` are the same class, so
    downstream code can catch one type regardless of which adapter
    raised it."""
    from yutha.crewai import CapabilityDenied as CrewCapabilityDenied
    from yutha.langgraph import CapabilityDenied as LangCapabilityDenied

    assert CrewCapabilityDenied is LangCapabilityDenied

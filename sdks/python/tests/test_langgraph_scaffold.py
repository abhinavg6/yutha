"""Stage-4a scaffolding checks.

Verifies the ``yutha.langgraph`` sub-package is importable and the
``_require_langgraph`` helper behaves correctly for both the
"extra installed" and "extra missing" cases. The actual adapter
primitives land in 4b and get their own tests.
"""

from __future__ import annotations

import importlib
import sys
from unittest import mock

import pytest


def test_namespace_imports_without_langgraph() -> None:
    """`import yutha.langgraph` must succeed even when LangGraph
    isn't installed. The package is a namespace; only the helpers
    that touch LangGraph actually need the extra."""
    import yutha.langgraph

    assert hasattr(yutha.langgraph, "_require_langgraph")


def test_require_langgraph_passes_when_installed() -> None:
    """When LangGraph is on the import path, the helper is a no-op.
    Skip if the extra isn't installed in the current environment
    (CI without the `langgraph` extra; user with `pip install -e .`
    only)."""
    try:
        import langgraph  # noqa: F401
    except ImportError:
        pytest.skip("langgraph extra not installed in this environment")

    from yutha.langgraph import _require_langgraph

    _require_langgraph()  # raises on failure


def test_require_langgraph_raises_clearly_when_missing() -> None:
    """When LangGraph is missing, the helper raises an ``ImportError``
    with a useful pointer to the extra. Simulate the missing state
    by injecting a mock that fails the import."""
    from yutha.langgraph import _require_langgraph

    # Force the inner `import langgraph` to fail by hiding it from
    # sys.modules and patching the import machinery.
    saved = sys.modules.pop("langgraph", None)
    try:
        with mock.patch.dict(sys.modules, {"langgraph": None}):
            with pytest.raises(ImportError, match=r"pip install 'yutha\[langgraph\]'"):
                _require_langgraph()
    finally:
        if saved is not None:
            sys.modules["langgraph"] = saved


def test_importlib_machinery_finds_yutha_langgraph() -> None:
    """Sanity: the package is a real importable module, not a stub
    re-exported from elsewhere."""
    spec = importlib.util.find_spec("yutha.langgraph")
    assert spec is not None
    assert spec.origin is not None
    assert spec.origin.endswith("__init__.py")

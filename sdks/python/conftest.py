"""pytest configuration shim.

When pytest is invoked from the repo root rather than from
``sdks/python/``, its ``rootdir`` resolves to the repo root and the
``[tool.pytest.ini_options]`` block in ``sdks/python/pyproject.toml``
isn't picked up. That's harmless — tests still run — but it causes a
``PytestUnknownMarkWarning`` for the ``integration`` marker.

This file lives at ``sdks/python/conftest.py`` so pytest discovers it
on the way down from the repo root and registers the marker before
collection.
"""

from __future__ import annotations

import sys
import warnings
from pathlib import Path

# Make example scripts under sdks/python/examples/ importable from
# tests/ so the S1 LangGraph demo can be re-used as an integration
# test without duplicating its body. The directory is a sibling of
# both tests/ and src/.
_EXAMPLES_DIR = Path(__file__).parent / "examples"
if _EXAMPLES_DIR.is_dir() and str(_EXAMPLES_DIR) not in sys.path:
    sys.path.insert(0, str(_EXAMPLES_DIR))

# LangGraph 0.2/0.3 fires a LangChainPendingDeprecationWarning at
# import time inside langgraph.checkpoint.base, regardless of whether
# we use checkpointing. The same suppression lives in
# ``pyproject.toml::[tool.pytest.ini_options].filterwarnings``, but
# pytest's chain applies that filter LATE — after the warning has
# already been recorded. Registering it directly with the warnings
# module at conftest-load time catches the warning at its source.
warnings.filterwarnings(
    "ignore",
    message=r"The default value of `allowed_objects`.*",
    category=PendingDeprecationWarning,
)


def pytest_configure(config) -> None:  # type: ignore[no-untyped-def]
    config.addinivalue_line(
        "markers",
        "integration: tests that require a running yutha control plane "
        "(skipped by default; set YUTHA_BOOTSTRAP_SEED to run)",
    )

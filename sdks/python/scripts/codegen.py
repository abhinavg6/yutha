#!/usr/bin/env python3
"""Regenerate the protobuf + gRPC stubs under ``src/yutha/_proto/``.

This script is the *only* place protoc gets invoked for the Python SDK.
Contributors run it whenever they edit a ``.proto`` file under
``/spec/``; the generated output is committed so that:

  - End-users importing ``yutha`` never need ``grpcio-tools`` installed.
  - CI can verify ``_proto/`` is in sync with ``/spec/`` by re-running
    this script and diffing the working tree.

## Why we post-process imports

``protoc`` generates imports of the form

    import common_pb2 as common__pb2
    from passport import passport_v1_pb2 as ...

which only resolve if the *directory containing the generated file* is
on ``sys.path``. That's a Python-protobuf wart, not a Yutha decision.
Rather than scribbling on ``sys.path`` at runtime, we rewrite the
generated imports in place to use the fully-qualified package path:

    from yutha._proto import common_pb2 as common__pb2
    from yutha._proto.passport import passport_v1_pb2 as ...

This keeps ``yutha._proto`` a normal, importable Python package with no
import-time side effects.

Run with::

    python scripts/codegen.py

from inside ``sdks/python/``. Requires the ``[dev]`` extra
(``grpcio-tools`` + ``mypy-protobuf``).
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SDK_ROOT = SCRIPT_DIR.parent
REPO_ROOT = SDK_ROOT.parent.parent
SPEC_ROOT = REPO_ROOT / "spec"
OUT_DIR = SDK_ROOT / "src" / "yutha" / "_proto"

# Proto files to compile, paths relative to SPEC_ROOT. Order doesn't
# matter to protoc (it resolves imports itself), but we list them in
# dependency order for human readability.
PROTO_FILES = [
    "common.proto",
    "passport/passport-v1.proto",
    "envelope/envelope-v1.proto",
    "receipt/receipt-v1.proto",
    "capability/capability-v1.proto",
    "topology/topology-v1.proto",
    "control-plane/v1.proto",
]

# Sub-packages (relative to OUT_DIR) that need an ``__init__.py`` to be
# importable. Top-level OUT_DIR / "__init__.py" is hand-written and kept
# under version control; this list covers the protoc-emitted directories.
SUBPACKAGE_DIRS = ["passport", "envelope", "receipt", "capability", "topology", "control-plane"]


def main() -> int:
    if not SPEC_ROOT.is_dir():
        sys.stderr.write(f"spec directory not found: {SPEC_ROOT}\n")
        return 2

    # Try the dev import; surface a clear error if grpc_tools is missing.
    try:
        from grpc_tools import protoc  # noqa: F401  # validated for presence
    except ImportError:
        sys.stderr.write(
            "grpc_tools is not installed. Install dev extras:\n"
            "    pip install -e '.[dev]'\n"
        )
        return 2

    # Wipe the previous output so renamed / removed protos don't linger.
    if OUT_DIR.exists():
        for entry in OUT_DIR.iterdir():
            if entry.name == "__init__.py":
                continue  # hand-written; preserved
            if entry.is_dir():
                shutil.rmtree(entry)
            else:
                entry.unlink()
    else:
        OUT_DIR.mkdir(parents=True)

    # Invoke protoc.
    args = [
        "grpc_tools.protoc",
        f"--proto_path={SPEC_ROOT}",
        f"--python_out={OUT_DIR}",
        f"--grpc_python_out={OUT_DIR}",
        f"--pyi_out={OUT_DIR}",
        *[str(SPEC_ROOT / p) for p in PROTO_FILES],
    ]
    print("Running:", " ".join(args))
    from grpc_tools import protoc as _protoc

    rc = _protoc.main(args)
    if rc != 0:
        sys.stderr.write(f"protoc failed with exit code {rc}\n")
        return rc

    # protoc emits subpackage directories named after the proto subdirs.
    # We have one with a hyphen ("control-plane") which Python can't
    # import — rename to "control_plane".
    hyphen_dir = OUT_DIR / "control-plane"
    if hyphen_dir.exists():
        target = OUT_DIR / "control_plane"
        if target.exists():
            shutil.rmtree(target)
        hyphen_dir.rename(target)

    # Add __init__.py to each subpackage directory so Python recognizes
    # them as packages. protoc doesn't emit these.
    for sub in SUBPACKAGE_DIRS:
        # Hyphen → underscore for "control-plane".
        normalized = sub.replace("-", "_")
        d = OUT_DIR / normalized
        if d.is_dir():
            (d / "__init__.py").touch()

    # Post-process imports.
    rewritten = _rewrite_imports(OUT_DIR)
    print(f"Rewrote imports in {rewritten} file(s).")

    # Quick smoke import to surface any leftover import bugs.
    print("Smoke-importing every generated module …")
    failures = _smoke_import(OUT_DIR)
    if failures:
        sys.stderr.write("Some modules failed to import:\n")
        for name, err in failures:
            sys.stderr.write(f"  {name}: {err}\n")
        return 3
    print("All generated modules imported cleanly.")
    return 0


# -----------------------------------------------------------------------------
# Import rewriting
# -----------------------------------------------------------------------------

# Patterns that match protoc's generated imports. The regexes are
# anchored to the start of the line so we don't rewrite imports inside
# string literals or comments.
#
# Examples:
#   import common_pb2 as common__pb2
#   from passport import passport_v1_pb2 as ...
#   from control-plane import v1_pb2 as ...   (but the dir is renamed)
_IMPORT_BARE = re.compile(r"^import (\w+_pb2(?:_grpc)?)\b", re.MULTILINE)
_IMPORT_FROM = re.compile(r"^from ([\w\-]+) import (\w+_pb2(?:_grpc)?)\b", re.MULTILINE)


def _rewrite_imports(root: Path) -> int:
    count = 0
    for py_file in root.rglob("*.py"):
        text = py_file.read_text()
        original = text
        # `import foo_pb2 as foo__pb2` → `from yutha._proto import foo_pb2 as foo__pb2`.
        text = _IMPORT_BARE.sub(r"from yutha._proto import \1", text)
        # `from passport import passport_v1_pb2` →
        # `from yutha._proto.passport import passport_v1_pb2`.
        # Note that `control-plane` (hyphenated on disk per protoc)
        # gets normalized to `control_plane` since the directory is
        # renamed above.
        text = _IMPORT_FROM.sub(
            lambda m: f"from yutha._proto.{m.group(1).replace('-', '_')} import {m.group(2)}",
            text,
        )
        if text != original:
            py_file.write_text(text)
            count += 1
    return count


# -----------------------------------------------------------------------------
# Smoke import
# -----------------------------------------------------------------------------


def _smoke_import(root: Path) -> list[tuple[str, str]]:
    """Try to import every generated module from a fresh interpreter."""
    sdk_src = SDK_ROOT / "src"
    failures: list[tuple[str, str]] = []
    for py_file in sorted(root.rglob("*_pb2.py")) + sorted(root.rglob("*_pb2_grpc.py")):
        rel = py_file.relative_to(sdk_src).with_suffix("")
        module = ".".join(rel.parts)
        result = subprocess.run(
            [sys.executable, "-c", f"import {module}"],
            cwd=sdk_src,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            failures.append((module, result.stderr.strip()))
    return failures


if __name__ == "__main__":
    raise SystemExit(main())

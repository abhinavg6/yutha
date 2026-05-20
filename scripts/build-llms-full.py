#!/usr/bin/env python3
"""Generate docs/llms-full.txt by concatenating all doc pages.

The convention (sibling to https://llmstxt.org/) is: serve a single
file at the site root that contains the full text of every doc page,
in nav order, so an LLM can ingest the documentation in one shot
without crawling. We deploy it at https://yutha.ai/llms-full.txt.

Source of truth for ordering is `mkdocs.yml`'s `nav` block; this
script walks that ordering, reads each referenced markdown file under
`docs/`, and writes the concatenation to `docs/llms-full.txt`. The
output file is itself in `docs/`, so mkdocs copies it to the deployed
site verbatim (along with `docs/llms.txt` and `docs/CNAME`).

Run manually:
    python3 scripts/build-llms-full.py

In CI: invoked by `.github/workflows/docs.yml` before `mkdocs build`.

The output is plain text with HTML-comment-style separators between
sections so an LLM can scan the structure quickly. No frontmatter is
stripped — we leave it in so an LLM that cares about page titles can
see them.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow `from yaml import safe_load`. mkdocs uses PyYAML transitively,
# so it's already in the docs-build venv.
try:
    import yaml
except ImportError:
    print(
        "PyYAML is required (it's a transitive dep of mkdocs). "
        "Install with `pip install pyyaml`.",
        file=sys.stderr,
    )
    sys.exit(1)


REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"
MKDOCS_CONFIG = REPO_ROOT / "mkdocs.yml"
OUTPUT = DOCS_DIR / "llms-full.txt"


def collect_pages(nav: list, pages: list[str]) -> None:
    """Recursively walk mkdocs `nav` and collect markdown file paths.

    mkdocs nav nodes are either:
      - {"Title": "path/to/file.md"}             (leaf)
      - {"Title": [<list of further nodes>]}     (section)
      - "path/to/file.md"                        (rare leaf form)
    """
    for entry in nav:
        if isinstance(entry, str):
            pages.append(entry)
        elif isinstance(entry, dict):
            for _, value in entry.items():
                if isinstance(value, str):
                    pages.append(value)
                elif isinstance(value, list):
                    collect_pages(value, pages)


def load_nav_pages() -> list[str]:
    """Read mkdocs.yml and return doc paths in nav order."""
    # mkdocs.yml uses `!!python/name:...` tags for some markdown
    # extensions. The default SafeLoader rejects those. We don't care
    # about the values — we only need the `nav` block — so build a
    # loader that ignores unknown tags.
    class _LooseLoader(yaml.SafeLoader):
        pass

    def _ignore_unknown(loader, tag_suffix, node):
        return None

    _LooseLoader.add_multi_constructor("", _ignore_unknown)

    with MKDOCS_CONFIG.open("r", encoding="utf-8") as f:
        config = yaml.load(f, Loader=_LooseLoader)

    nav = config.get("nav")
    if not nav:
        print("mkdocs.yml has no `nav` block; nothing to concatenate.", file=sys.stderr)
        sys.exit(1)

    pages: list[str] = []
    collect_pages(nav, pages)
    return pages


def render_page(rel_path: str) -> str:
    """Read a single doc page; emit it with a section separator."""
    full = DOCS_DIR / rel_path
    if not full.exists():
        # Some nav entries (e.g. llms.txt itself isn't markdown) may
        # legitimately be skipped. We don't fail on missing.
        return f"\n<!-- skipped (not found): {rel_path} -->\n"

    body = full.read_text(encoding="utf-8")
    separator = (
        f"\n\n<!--\n"
        f"--- source: docs/{rel_path}\n"
        f"--- url: https://yutha.ai/{rel_path.rsplit('.', 1)[0]}/\n"
        f"-->\n\n"
    )
    return separator + body


def main() -> int:
    pages = load_nav_pages()
    chunks: list[str] = [
        "# Yutha — full documentation\n\n"
        "This file is the concatenation of every page on https://yutha.ai/, "
        "in nav order, generated from `docs/*.md` by "
        "`scripts/build-llms-full.py`. Suited for one-shot ingestion by an "
        "LLM that wants the whole doc set without crawling individual pages.\n"
    ]

    for page in pages:
        chunks.append(render_page(page))

    OUTPUT.write_text("\n".join(chunks), encoding="utf-8")
    size_kb = OUTPUT.stat().st_size / 1024
    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)} ({size_kb:.1f} KB, {len(pages)} pages)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

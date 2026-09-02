from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

PROJECT_ROOT = Path(__file__).parents[2]
MARKDOWN_LINK = re.compile(r"\[[^]]+\]\(([^)]+)\)")


def test_local_markdown_links_resolve() -> None:
    documents = [
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "AGENTS.md",
        PROJECT_ROOT / "CHANGELOG.md",
        *sorted((PROJECT_ROOT / "docs").rglob("*.md")),
    ]
    broken: list[str] = []
    for document in documents:
        for raw_target in MARKDOWN_LINK.findall(document.read_text(encoding="utf-8")):
            target = raw_target.strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or not parsed.path or any(char.isspace() for char in target):
                continue
            resolved = (document.parent / unquote(parsed.path)).resolve()
            if not resolved.exists():
                broken.append(f"{document.relative_to(PROJECT_ROOT)} -> {target}")

    assert not broken, "broken local documentation links:\n" + "\n".join(broken)


def test_design_reference_manifest_sources_resolve() -> None:
    manifest_path = (
        PROJECT_ROOT / "docs" / "design-reference" / "labcourt-ops-ui" / "DESIGN-MANIFEST.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    missing = [
        source
        for source in manifest["sourceFiles"]["all"]
        if not (manifest_path.parent / source).resolve().is_file()
    ]
    assert not missing, f"missing design reference sources: {missing}"

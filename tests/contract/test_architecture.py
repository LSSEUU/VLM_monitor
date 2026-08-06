import ast
import importlib.util
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parents[2]
SOURCE_ROOT = PROJECT_ROOT / "src"


def _module_name(path: Path) -> str:
    relative = path.relative_to(SOURCE_ROOT).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _import_names(source: str, *, module_name: str, is_package: bool = False) -> set[str]:
    tree = ast.parse(source)
    package = module_name if is_package else module_name.rpartition(".")[0]
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                if node.module:
                    names.add(node.module)
                continue

            relative_name = "." * node.level + (node.module or "")
            resolved = importlib.util.resolve_name(relative_name, package)
            if node.module:
                names.add(resolved)
            else:
                names.update(
                    resolved if alias.name == "*" else f"{resolved}.{alias.name}"
                    for alias in node.names
                )
    return names


def _imports(path: Path) -> set[str]:
    return _import_names(
        path.read_text(encoding="utf-8"),
        module_name=_module_name(path),
        is_package=path.name == "__init__.py",
    )


def _is_stdlib(name: str) -> bool:
    return name.split(".", maxsplit=1)[0] in sys.stdlib_module_names


def _assert_import_allowlist(path: Path, *, project_prefixes: tuple[str, ...]) -> None:
    violations = sorted(
        name
        for name in _imports(path)
        if not _is_stdlib(name)
        and not any(name == prefix or name.startswith(f"{prefix}.") for prefix in project_prefixes)
    )
    assert not violations, (
        f"{path.relative_to(PROJECT_ROOT)} imports forbidden modules: {violations}"
    )


@pytest.mark.parametrize(
    ("source", "module_name", "expected"),
    [
        (
            "from .canonical import canonical_json",
            "labcourt.domain.ids",
            {"labcourt.domain.canonical"},
        ),
        ("from ..contracts import FrameRef", "labcourt.domain.ids", {"labcourt.contracts"}),
        ("from .. import domain", "labcourt.contracts.base", {"labcourt.domain"}),
    ],
)
def test_relative_imports_are_resolved_before_policy_checks(
    source: str,
    module_name: str,
    expected: set[str],
) -> None:
    assert _import_names(source, module_name=module_name) == expected


def test_domain_imports_only_stdlib_contracts_and_domain() -> None:
    for path in (SOURCE_ROOT / "labcourt" / "domain").rglob("*.py"):
        _assert_import_allowlist(
            path,
            project_prefixes=("labcourt.contracts", "labcourt.domain"),
        )


def test_application_imports_only_pydantic_and_allowed_project_layers() -> None:
    for path in (SOURCE_ROOT / "labcourt" / "application").rglob("*.py"):
        _assert_import_allowlist(
            path,
            project_prefixes=(
                "pydantic",
                "labcourt.application",
                "labcourt.contracts",
                "labcourt.domain",
                "labcourt.exceptions",
                "labcourt.ports",
            ),
        )


def test_contracts_import_only_stdlib_pydantic_and_contracts() -> None:
    for path in (SOURCE_ROOT / "labcourt" / "contracts").rglob("*.py"):
        _assert_import_allowlist(
            path,
            project_prefixes=("pydantic", "labcourt.contracts"),
        )

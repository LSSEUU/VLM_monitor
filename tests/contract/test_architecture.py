import ast
import importlib.util
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parents[2]
SOURCE_ROOT = PROJECT_ROOT / "src"
APPLICATION_ROOT = SOURCE_ROOT / "labcourt" / "application"

# M8 keeps these executable composition roots in application/ for compatibility.
# Their adapter imports are explicit here so ordinary application modules remain
# constrained to inward-facing layers.
M8_ADAPTER_COMPOSITION_ROOTS = frozenset(
    {
        "m8_feishu_emergency_demo.py",
        "m8_feishu_live_assembly.py",
        "m8_feishu_outbox_authority.py",
        "m8_feishu_outbox_runtime.py",
        "m8_feishu_webhook_authority.py",
        "m8_feishu_webhook_runtime.py",
        "m8_personal_demo_api.py",
        "m8_personal_demo_bootstrap.py",
        "m8_personal_demo_camera.py",
        "m8_personal_demo_knowledge.py",
        "m8_personal_demo_notification.py",
        "m8_personal_demo_ppe_case.py",
        "m8_personal_demo_ppe_notification.py",
        "m8_platform_bootstrap.py",
        "m8_platform_demo_api.py",
    }
)
M8_COMPOSITION_ROOT_EXTRA_IMPORTS = {
    "m8_feishu_webhook_runtime.py": (
        "cryptography.hazmat.primitives",
        "labcourt.m8_feishu_activated_webhook_server",
    ),
    "m8_personal_demo_api.py": ("labcourt.m8_api_server",),
    "m8_platform_demo_api.py": (
        "labcourt.config_loader",
        "labcourt.m8_platform_server",
    ),
}


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
    for path in APPLICATION_ROOT.rglob("*.py"):
        adapter_prefix = ("labcourt.adapters",) if path.name in M8_ADAPTER_COMPOSITION_ROOTS else ()
        composition_root_imports = M8_COMPOSITION_ROOT_EXTRA_IMPORTS.get(path.name, ())
        _assert_import_allowlist(
            path,
            project_prefixes=(
                "pydantic",
                "labcourt.application",
                "labcourt.contracts",
                "labcourt.domain",
                "labcourt.exceptions",
                "labcourt.ports",
                "labcourt.services",
                *adapter_prefix,
                *composition_root_imports,
            ),
        )


def test_contracts_import_only_stdlib_pydantic_and_contracts() -> None:
    for path in (SOURCE_ROOT / "labcourt" / "contracts").rglob("*.py"):
        _assert_import_allowlist(
            path,
            project_prefixes=("pydantic", "labcourt.contracts"),
        )

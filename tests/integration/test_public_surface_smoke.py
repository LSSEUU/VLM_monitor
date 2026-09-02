from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Iterator

from typer.core import TyperCommand, TyperGroup
from typer.main import get_command
from typer.testing import CliRunner

import labcourt
from labcourt.cli import app


def _public_command_paths(
    command: TyperCommand | TyperGroup,
    prefix: tuple[str, ...] = (),
) -> Iterator[tuple[str, ...]]:
    if not isinstance(command, TyperGroup):
        return
    for name, child in sorted(command.commands.items()):
        if child.hidden:
            continue
        path = (*prefix, name)
        yield path
        yield from _public_command_paths(child, path)


def test_every_public_cli_command_has_working_help() -> None:
    runner = CliRunner()
    failures: list[str] = []
    for path in [(), *_public_command_paths(get_command(app))]:
        result = runner.invoke(app, [*path, "--help"])
        if result.exit_code != 0:
            failures.append(f"{' '.join(path) or 'labcourt'}: {result.output}")
    assert not failures, "\n".join(failures)


def test_every_labcourt_module_imports() -> None:
    failures: list[str] = []
    for module in pkgutil.walk_packages(labcourt.__path__, prefix="labcourt."):
        try:
            importlib.import_module(module.name)
        except Exception as error:
            failures.append(f"{module.name}: {type(error).__name__}: {error}")
    assert not failures, "\n".join(failures)

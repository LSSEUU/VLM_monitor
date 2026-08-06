from pathlib import Path

from typer.testing import CliRunner

from labcourt.cli import app

PROJECT_ROOT = Path(__file__).parents[2]
RUNNER = CliRunner()


def test_validate_config_cli_success() -> None:
    result = RUNNER.invoke(
        app,
        [
            "validate-config",
            "-c",
            str(PROJECT_ROOT / "configs" / "demo.yaml"),
            "--json",
        ],
    )
    assert result.exit_code == 0
    assert '"valid": true' in result.stdout


def test_validate_config_cli_contract_error_is_exit_two() -> None:
    result = RUNNER.invoke(
        app,
        [
            "validate-config",
            "-c",
            str(PROJECT_ROOT / "tests" / "fixtures" / "m0" / "config-invalid-evidence-indent.yaml"),
        ],
    )
    assert result.exit_code == 2


def test_schema_cli_export_and_check(tmp_path: Path) -> None:
    export = RUNNER.invoke(app, ["schemas", "export", "--output", str(tmp_path)])
    assert export.exit_code == 0
    check = RUNNER.invoke(
        app,
        ["schemas", "export", "--check", "--output", str(tmp_path)],
    )
    assert check.exit_code == 0

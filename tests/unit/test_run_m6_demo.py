from __future__ import annotations

import importlib.util
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "run_m6_demo.py"


@pytest.fixture(scope="module")
def demo_script() -> ModuleType:
    specification = importlib.util.spec_from_file_location("run_m6_demo_for_test", SCRIPT_PATH)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _write_receipt(
    receipt_path: Path,
    demo_script: ModuleType,
    *,
    names: tuple[str, ...] | None = None,
    outcome: str | None = None,
) -> None:
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite")
    selected_names = names or demo_script._SCENARIO_TEST_NAMES
    for name in selected_names:
        testcase = ET.SubElement(
            suite,
            "testcase",
            {"classname": demo_script._SCENARIO_TEST_CLASSNAME, "name": name},
        )
        if outcome is not None:
            ET.SubElement(testcase, outcome)
    ET.ElementTree(root).write(receipt_path, encoding="utf-8", xml_declaration=True)


def _receipt_path(argv: list[str]) -> Path:
    prefix = "--junitxml="
    return Path(
        next(argument.removeprefix(prefix) for argument in argv if argument.startswith(prefix))
    )


def test_scenario_gate_executes_exact_nodes_with_isolated_environment_and_receipt(
    demo_script: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}
    monkeypatch.setenv("PYTEST_ADDOPTS", "--collect-only")
    monkeypatch.setenv("PYTEST_PLUGINS", "untrusted_plugin")

    def run(
        argv: list[str],
        *,
        cwd: Path,
        check: bool,
        env: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        observed.update(argv=argv, cwd=cwd, check=check, env=env)
        _write_receipt(_receipt_path(argv), demo_script)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(demo_script.subprocess, "run", run)

    assert demo_script._run_scenarios() is True
    argv = observed["argv"]
    assert (
        tuple(
            argument for argument in argv if argument.startswith(f"{demo_script._SCENARIO_FILE}::")
        )
        == demo_script._SCENARIO_NODE_IDS
    )
    assert demo_script._SCENARIO_FILE not in argv
    assert argv[0:3] == [sys.executable, "-m", "pytest"]
    assert argv[3:5] == ["-o", "addopts="]
    assert observed["cwd"] == PROJECT_ROOT
    assert observed["check"] is False
    assert "PYTEST_ADDOPTS" not in observed["env"]
    assert "PYTEST_PLUGINS" not in observed["env"]
    assert observed["env"]["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"


@pytest.mark.parametrize("outcome", ["error", "failure", "skipped"])
def test_scenario_gate_rejects_every_non_passing_junit_outcome(
    demo_script: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
) -> None:
    def run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        _write_receipt(_receipt_path(argv), demo_script, outcome=outcome)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(demo_script.subprocess, "run", run)

    with pytest.raises(demo_script._M6DemoInvariantError):
        demo_script._run_scenarios()


def test_scenario_gate_rejects_a_zero_exit_receipt_missing_one_exact_node(
    demo_script: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        _write_receipt(
            _receipt_path(argv),
            demo_script,
            names=demo_script._SCENARIO_TEST_NAMES[:-1],
        )
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(demo_script.subprocess, "run", run)

    with pytest.raises(demo_script._M6DemoInvariantError):
        demo_script._run_scenarios()


def test_main_converts_scenario_launch_failure_to_payload_free_typed_exit_without_publish(
    demo_script: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    def fail() -> bool:
        raise OSError("sensitive-launch-detail")

    monkeypatch.setattr(demo_script, "_run_scenarios", fail)
    monkeypatch.setattr(
        demo_script,
        "_publish",
        lambda _: pytest.fail("publication must not start after a scenario launch failure"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_m6_demo.py", "--output-root", str(tmp_path)],
    )

    assert demo_script.main() == 2
    output = capsys.readouterr().out
    assert "SCENARIO_GATE_EXECUTION_FAILED" in output
    assert "sensitive-launch-detail" not in output
    assert not (tmp_path / "generations").exists()


def test_main_converts_invalid_receipt_to_typed_exit_without_publish(
    demo_script: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    def fail() -> bool:
        raise demo_script._M6DemoInvariantError("sensitive-receipt-detail")

    monkeypatch.setattr(demo_script, "_run_scenarios", fail)
    monkeypatch.setattr(
        demo_script,
        "_publish",
        lambda _: pytest.fail("publication must not start after an invalid scenario receipt"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_m6_demo.py", "--output-root", str(tmp_path)],
    )

    assert demo_script.main() == 2
    output = capsys.readouterr().out
    assert "SCENARIO_GATE_RECEIPT_INVALID" in output
    assert "sensitive-receipt-detail" not in output
    assert not (tmp_path / "generations").exists()


def test_main_converts_unknown_producer_failure_to_payload_free_typed_exit(
    demo_script: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(demo_script, "_run_scenarios", lambda: True)

    def fail(_: Path) -> Path:
        raise ValueError("sensitive-producer-detail")

    monkeypatch.setattr(demo_script, "_publish", fail)
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_m6_demo.py", "--output-root", str(tmp_path)],
    )

    assert demo_script.main() == 5
    output = capsys.readouterr().out
    assert "DEMO_INVARIANT_FAILURE" in output
    assert "sensitive-producer-detail" not in output


def test_precomputed_publication_rejects_the_wrong_factory_type(
    demo_script: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        demo_script.importlib,
        "import_module",
        lambda _: SimpleNamespace(_publication=lambda: "not-a-publication"),
    )

    with pytest.raises(demo_script._M6DemoInvariantError):
        demo_script._precomputed_closed_publication()

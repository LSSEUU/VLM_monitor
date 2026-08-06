from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pytest
from test_m2_evidence_pipeline import ROOT, _complete_request, _stack
from typer.testing import CliRunner

from labcourt.adapters.storage.json_projector import JsonProjector
from labcourt.adapters.storage.model_response_store import SecureModelResponseStore
from labcourt.adapters.storage.sqlite_m3_repository import SQLiteM3Repository
from labcourt.application.screening_request import prepare_screening_request
from labcourt.cli import app
from labcourt.config_loader import load_config
from labcourt.contracts.artifact_validation import (
    M3ArtifactValidationIssueCode,
    M3ArtifactValidationReport,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.services.m3 import build_screening_prompt_catalog

RUN_ID = "m3-cli-artifacts"
RAW_RESPONSE = b'{"screening":"offline-fixture"}'


@dataclass(frozen=True, slots=True)
class _M3Release:
    root: Path
    workspace: Path
    database: Path
    config: Path
    response_id: str
    raw_response_ref: str


def _fingerprint(root: Path) -> tuple[tuple[str, str, int, int, str], ...]:
    entries: list[tuple[str, str, int, int, str]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        stat = path.stat()
        if path.is_file():
            payload = path.read_bytes()
            entries.append(
                (
                    "FILE",
                    relative,
                    int(stat.st_size),
                    int(stat.st_mtime_ns),
                    hashlib.sha256(payload).hexdigest(),
                )
            )
        elif path.is_dir():
            entries.append(("DIRECTORY", relative, 0, int(stat.st_mtime_ns), ""))
        else:
            entries.append(("OTHER", relative, 0, int(stat.st_mtime_ns), ""))
    return tuple(entries)


def _invoke_json(*options: str) -> tuple[object, M3ArtifactValidationReport]:
    result = CliRunner().invoke(
        app,
        ["artifacts", "validate", "--run-id", RUN_ID, "--json", *options],
    )
    return result, M3ArtifactValidationReport.model_validate_json(result.stdout)


@pytest.fixture(scope="module")
def m3_released_artifacts(tmp_path_factory: pytest.TempPathFactory) -> _M3Release:
    root = tmp_path_factory.mktemp("m3-cli-release")
    config_dir = root / "configs"
    config_dir.mkdir()
    config_path = config_dir / "default.yaml"
    config_path.write_text(
        (ROOT / "configs" / "demo.yaml")
        .read_text(encoding="utf-8")
        .replace('workspace: "runs"', 'workspace: "workspace"'),
        encoding="utf-8",
    )
    config = load_config(config_path)
    with _stack(root, run_id=RUN_ID, config=config) as stack:
        publication = stack.builder.build_and_publish(_complete_request(stack)).publication
        JsonProjector(stack.repository, stack.workspace_root).project_run(RUN_ID)
        prepared = prepare_screening_request(
            publication.pack,
            config,
            stack.manifest,
            build_screening_prompt_catalog(stack.manifest),
        )
        store = SecureModelResponseStore(stack.workspace)
        response = store.publish(
            prepared.request,
            RAW_RESPONSE,
            input_tokens=17,
            output_tokens=11,
            latency_ms=7,
        )
        repository = SQLiteM3Repository(
            stack.database,
            config.storage.busy_timeout_ms,
            raw_response_verifier=store,
        )
        owner_token = "m3-cli-artifact-owner-token-0001"
        claim = repository.claim_model_call(RUN_ID, prepared.request, owner_token)
        assert claim.status.value == "ACQUIRED"
        repository.complete_model_call(
            RUN_ID,
            prepared.request,
            response,
            owner_token,
        )
    return _M3Release(
        root=root,
        workspace=root / "workspace",
        database=root / "workspace" / config.storage.database_filename,
        config=config_path,
        response_id=response.response_id,
        raw_response_ref=response.raw_response_ref,
    )


@pytest.fixture
def m3_release_copy(
    m3_released_artifacts: _M3Release,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> _M3Release:
    shutil.copytree(m3_released_artifacts.workspace, tmp_path / "workspace")
    shutil.copytree(m3_released_artifacts.root / "configs", tmp_path / "configs")
    monkeypatch.chdir(tmp_path)
    return _M3Release(
        root=tmp_path,
        workspace=tmp_path / "workspace",
        database=tmp_path / "workspace" / m3_released_artifacts.database.name,
        config=tmp_path / "configs" / "default.yaml",
        response_id=m3_released_artifacts.response_id,
        raw_response_ref=m3_released_artifacts.raw_response_ref,
    )


def test_artifacts_validate_defaults_to_m3_and_is_canonical_stable_and_read_only(
    m3_release_copy: _M3Release,
) -> None:
    before = _fingerprint(m3_release_copy.workspace)
    runner = CliRunner()
    human = runner.invoke(app, ["artifacts", "validate", "--run-id", RUN_ID])
    first, report = _invoke_json()
    second, repeated = _invoke_json()

    assert human.exit_code == first.exit_code == second.exit_code == 0
    assert "valid artifacts" in human.stdout
    assert "m3_documents=3" in human.stdout
    assert "m3_raw_responses=1" in human.stdout
    assert first.stdout == second.stdout
    assert report == repeated
    assert first.stdout.strip() == canonical_json(report.model_dump(mode="json"))
    assert report.validator_version == "m3-artifacts-v1"
    assert report.m2_report.validator_version == "m2-artifacts-v1"
    assert report.m2_report.passed is True
    assert report.counts.documents == 3
    assert report.counts.model_call_claims == 1
    assert report.counts.model_responses == 1
    assert report.counts.model_cache_entries == 1
    assert report.counts.raw_response_bytes == len(RAW_RESPONSE)
    assert report.issues == ()
    assert _fingerprint(m3_release_copy.workspace) == before


@pytest.mark.parametrize(
    ("damage", "expected_code"),
    [
        pytest.param("missing", M3ArtifactValidationIssueCode.RAW_RESPONSE_MISSING),
        pytest.param("tampered", M3ArtifactValidationIssueCode.RAW_RESPONSE_UNSAFE),
    ],
)
def test_artifacts_validate_detects_physical_raw_damage_without_writes(
    m3_release_copy: _M3Release,
    damage: str,
    expected_code: M3ArtifactValidationIssueCode,
) -> None:
    target = m3_release_copy.workspace / Path(m3_release_copy.raw_response_ref)
    if damage == "missing":
        target.unlink()
    else:
        target.write_bytes(b"x" * len(RAW_RESPONSE))
    before = _fingerprint(m3_release_copy.workspace)

    result, report = _invoke_json()

    assert result.exit_code == 1
    assert expected_code in {issue.code for issue in report.issues}
    assert report.m2_report.passed is True
    assert _fingerprint(m3_release_copy.workspace) == before


@pytest.mark.parametrize(
    ("corruption", "expected_code"),
    [
        pytest.param(
            "canonical",
            M3ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_INVALID,
        ),
        pytest.param(
            "index",
            M3ArtifactValidationIssueCode.AUTHORITY_INDEX_MISMATCH,
        ),
        pytest.param(
            "reference",
            M3ArtifactValidationIssueCode.AUTHORITY_REFERENCE_INVALID,
        ),
    ],
)
def test_artifacts_validate_detects_m3_database_corruption_without_writes(
    m3_release_copy: _M3Release,
    corruption: str,
    expected_code: M3ArtifactValidationIssueCode,
) -> None:
    connection = sqlite3.connect(m3_release_copy.database)
    try:
        if corruption == "canonical":
            connection.execute("DROP TRIGGER model_responses_no_update")
            raw = str(
                connection.execute(
                    "SELECT response_json FROM model_responses WHERE response_id = ?",
                    (m3_release_copy.response_id,),
                ).fetchone()[0]
            )
            connection.execute(
                "UPDATE model_responses SET response_json = ? WHERE response_id = ?",
                (f" {raw}", m3_release_copy.response_id),
            )
        elif corruption == "index":
            connection.execute("DROP TRIGGER model_responses_no_update")
            connection.execute(
                "UPDATE model_responses SET raw_response_ref = ? WHERE response_id = ?",
                (
                    f"{RUN_ID}/model_responses/wrong.json",
                    m3_release_copy.response_id,
                ),
            )
        else:
            connection.execute("DROP TRIGGER model_cache_no_delete")
            connection.execute("DELETE FROM model_cache WHERE run_id = ?", (RUN_ID,))
        connection.commit()
    finally:
        connection.close()
    before = _fingerprint(m3_release_copy.workspace)

    result, report = _invoke_json()

    assert result.exit_code == 1
    assert expected_code in {issue.code for issue in report.issues}
    assert report.m2_report.passed is True
    assert _fingerprint(m3_release_copy.workspace) == before


@pytest.mark.parametrize(
    ("options", "expected_code"),
    [
        pytest.param(
            ("--max-m3-documents", "1"),
            M3ArtifactValidationIssueCode.DOCUMENT_COUNT_BUDGET_EXCEEDED,
        ),
        pytest.param(
            ("--max-m3-document-bytes", "1"),
            M3ArtifactValidationIssueCode.DOCUMENT_BYTES_BUDGET_EXCEEDED,
        ),
        pytest.param(
            ("--max-raw-response-bytes", str(len(RAW_RESPONSE) - 1)),
            M3ArtifactValidationIssueCode.RAW_RESPONSE_BYTES_BUDGET_EXCEEDED,
        ),
        pytest.param(
            ("--max-raw-response-total-bytes", str(len(RAW_RESPONSE) - 1)),
            M3ArtifactValidationIssueCode.RAW_RESPONSE_TOTAL_BYTES_BUDGET_EXCEEDED,
        ),
    ],
)
def test_artifacts_validate_m3_budget_preflight_is_typed_and_read_only(
    m3_release_copy: _M3Release,
    options: tuple[str, str],
    expected_code: M3ArtifactValidationIssueCode,
) -> None:
    before = _fingerprint(m3_release_copy.workspace)

    result, report = _invoke_json(*options)

    assert result.exit_code == 1
    assert {issue.code for issue in report.issues} == {expected_code}
    assert report.m2_report.passed is True
    assert report.counts.documents == 3
    assert report.counts.raw_response_bytes == len(RAW_RESPONSE)
    assert _fingerprint(m3_release_copy.workspace) == before


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--max-m3-documents", "0"),
        ("--max-m3-documents", "10000001"),
        ("--max-m3-document-bytes", "1073741825"),
        ("--max-raw-response-bytes", "1073741825"),
        ("--max-raw-response-total-bytes", "68719476737"),
        ("--max-raw-response-files", "0"),
        ("--max-raw-response-files", "10000001"),
        ("--max-raw-response-name-bytes", "0"),
        ("--max-raw-response-name-bytes", "4097"),
    ],
)
def test_artifacts_validate_m3_cli_limits_match_contract_boundaries(
    m3_release_copy: _M3Release,
    option: str,
    value: str,
) -> None:
    before = _fingerprint(m3_release_copy.workspace)

    result = CliRunner().invoke(
        app,
        ["artifacts", "validate", "--run-id", RUN_ID, "--json", option, value],
    )

    assert result.exit_code == 2
    assert _fingerprint(m3_release_copy.workspace) == before


def test_artifacts_validate_detects_unreferenced_physical_response_without_reading_it(
    m3_release_copy: _M3Release,
) -> None:
    orphan_id = "a" * 64
    orphan = m3_release_copy.workspace / RUN_ID / "model_responses" / f"{orphan_id}.json"
    orphan.write_bytes(b"x" * 4096)
    before = _fingerprint(m3_release_copy.workspace)

    result, report = _invoke_json("--max-raw-response-bytes", "64")

    assert result.exit_code == 1
    assert {
        M3ArtifactValidationIssueCode.RAW_RESPONSE_UNREFERENCED,
        M3ArtifactValidationIssueCode.RAW_RESPONSE_BYTES_BUDGET_EXCEEDED,
    }.issubset({issue.code for issue in report.issues})
    assert report.counts.physical_raw_response_files == 2
    assert report.counts.max_physical_raw_response_bytes == 4096
    assert _fingerprint(m3_release_copy.workspace) == before


def test_artifacts_validate_sanitizes_invalid_and_overlong_physical_names(
    m3_release_copy: _M3Release,
) -> None:
    raw_directory = m3_release_copy.workspace / RUN_ID / "model_responses"
    invalid_name = "provider-secret-invalid-name.txt"
    (raw_directory / invalid_name).write_bytes(b"not-a-response")
    before = _fingerprint(m3_release_copy.workspace)

    first, report = _invoke_json()
    second, repeated = _invoke_json("--max-raw-response-name-bytes", "8")

    assert first.exit_code == second.exit_code == 1
    assert M3ArtifactValidationIssueCode.RAW_RESPONSE_INVENTORY_UNSAFE in {
        issue.code for issue in report.issues
    }
    assert M3ArtifactValidationIssueCode.RAW_RESPONSE_INVENTORY_UNSAFE in {
        issue.code for issue in repeated.issues
    }
    assert invalid_name not in first.stdout
    assert invalid_name not in second.stdout
    assert _fingerprint(m3_release_copy.workspace) == before


def test_artifacts_validate_physical_count_and_total_budgets_are_typed(
    m3_release_copy: _M3Release,
) -> None:
    orphan_id = "b" * 64
    orphan = m3_release_copy.workspace / RUN_ID / "model_responses" / f"{orphan_id}.json"
    orphan.write_bytes(b"orphan")
    before = _fingerprint(m3_release_copy.workspace)

    count_result, count_report = _invoke_json("--max-raw-response-files", "1")
    total_result, total_report = _invoke_json(
        "--max-raw-response-total-bytes",
        str(len(RAW_RESPONSE)),
    )

    assert count_result.exit_code == total_result.exit_code == 1
    assert {issue.code for issue in count_report.issues} == {
        M3ArtifactValidationIssueCode.RAW_RESPONSE_FILE_COUNT_BUDGET_EXCEEDED
    }
    assert M3ArtifactValidationIssueCode.RAW_RESPONSE_TOTAL_BYTES_BUDGET_EXCEEDED in {
        issue.code for issue in total_report.issues
    }
    assert _fingerprint(m3_release_copy.workspace) == before


def test_artifacts_validate_rejects_referenced_hardlink_and_unreferenced_symlink(
    m3_release_copy: _M3Release,
    tmp_path: Path,
) -> None:
    raw_directory = m3_release_copy.workspace / RUN_ID / "model_responses"
    referenced = m3_release_copy.workspace / Path(m3_release_copy.raw_response_ref)
    hardlink_peer = tmp_path / "hardlink-peer.json"
    try:
        os.link(referenced, hardlink_peer)
    except OSError as error:
        pytest.skip(f"hardlink creation unavailable: {error}")
    symlink_id = "c" * 64
    symlink = raw_directory / f"{symlink_id}.json"
    try:
        symlink.symlink_to(hardlink_peer)
    except OSError as error:
        pytest.skip(f"symlink creation unavailable: {error}")
    before = _fingerprint(m3_release_copy.workspace)

    first, report = _invoke_json()
    second, repeated = _invoke_json()

    assert first.exit_code == second.exit_code == 1
    assert first.stdout == second.stdout
    assert report == repeated
    unsafe_reasons = {
        issue.reason_code
        for issue in report.issues
        if issue.code == M3ArtifactValidationIssueCode.RAW_RESPONSE_INVENTORY_UNSAFE
    }
    assert unsafe_reasons & {"HARD_LINK_REJECTED", "UNSAFE_LINK_COUNT"}
    assert unsafe_reasons & {"LINK_OR_NON_DIRECTORY", "REPARSE_POINT_REJECTED"}
    assert _fingerprint(m3_release_copy.workspace) == before


def test_artifacts_validate_rejects_referenced_symlink_and_unreferenced_hardlink(
    m3_release_copy: _M3Release,
    tmp_path: Path,
) -> None:
    raw_directory = m3_release_copy.workspace / RUN_ID / "model_responses"
    referenced = m3_release_copy.workspace / Path(m3_release_copy.raw_response_ref)
    referenced_source = tmp_path / "referenced-source.json"
    referenced_source.write_bytes(referenced.read_bytes())
    referenced.unlink()
    try:
        referenced.symlink_to(referenced_source)
    except OSError as error:
        pytest.skip(f"symlink creation unavailable: {error}")

    orphan_source = tmp_path / "orphan-source.json"
    orphan_source.write_bytes(b"orphan")
    orphan_id = "d" * 64
    orphan = raw_directory / f"{orphan_id}.json"
    try:
        os.link(orphan_source, orphan)
    except OSError as error:
        pytest.skip(f"hardlink creation unavailable: {error}")
    before = _fingerprint(m3_release_copy.workspace)

    result, report = _invoke_json()

    assert result.exit_code == 1
    unsafe_reasons = {
        issue.reason_code
        for issue in report.issues
        if issue.code == M3ArtifactValidationIssueCode.RAW_RESPONSE_INVENTORY_UNSAFE
    }
    assert unsafe_reasons & {"LINK_OR_NON_DIRECTORY", "REPARSE_POINT_REJECTED"}
    assert unsafe_reasons & {"HARD_LINK_REJECTED", "UNSAFE_LINK_COUNT"}
    assert _fingerprint(m3_release_copy.workspace) == before


def test_artifacts_validate_nonempty_db_with_missing_raw_directory_is_incomplete(
    m3_release_copy: _M3Release,
) -> None:
    shutil.rmtree(m3_release_copy.workspace / RUN_ID / "model_responses")
    before = _fingerprint(m3_release_copy.workspace)

    result, report = _invoke_json()

    assert result.exit_code == 1
    assert M3ArtifactValidationIssueCode.RAW_RESPONSE_MISSING in {
        issue.code for issue in report.issues
    }
    assert report.physical_raw_response_inventory_complete is False
    assert _fingerprint(m3_release_copy.workspace) == before


def test_artifacts_validate_empty_db_and_missing_raw_directory_is_zero_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_directory = tmp_path / "configs"
    config_directory.mkdir()
    config_path = config_directory / "default.yaml"
    config_path.write_text(
        (ROOT / "configs" / "demo.yaml")
        .read_text(encoding="utf-8")
        .replace('workspace: "runs"', 'workspace: "workspace"'),
        encoding="utf-8",
    )
    config = load_config(config_path)
    with _stack(tmp_path, run_id=RUN_ID, config=config) as stack:
        stack.builder.build_and_publish(_complete_request(stack))
        JsonProjector(stack.repository, stack.workspace_root).project_run(RUN_ID)
    monkeypatch.chdir(tmp_path)
    workspace = tmp_path / "workspace"
    assert not (workspace / RUN_ID / "model_responses").exists()
    before = _fingerprint(workspace)

    result, report = _invoke_json()

    assert result.exit_code == 0
    assert report.passed is True
    assert report.counts.model_responses == 0
    assert report.counts.physical_raw_response_entries == 0
    assert report.counts.physical_raw_response_files == 0
    assert report.physical_raw_response_inventory_complete is True
    assert _fingerprint(workspace) == before

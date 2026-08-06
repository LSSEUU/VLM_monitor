from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path

import pytest
from typer.testing import CliRunner

from labcourt.application.hearing_backlog_retry import (
    HearingBacklogRetryRecoveryCode,
    HearingBacklogRetryRecoveryRequired,
)
from labcourt.cli import app
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.m4_operations import (
    M4FakeVLMFixtureBundle,
    M4ProcessCaseOutcome,
    M4ProcessCommandReport,
    M4ProcessCounts,
    M4ProcessDisposition,
    M4ProcessReport,
    M4ProjectionDisposition,
    M4ProjectionOutcome,
)
from labcourt.m4_cli import _FixtureInputError, _load_fixture_bundle
from labcourt.services.m4_operations import (
    M4OperationsBoundaryCode,
    M4OperationsBoundaryError,
)

ROOT = Path(__file__).parents[2]
RUN_ID = "run-m4-cli"
CASE_ID = "case-m4-cli"
MANIFEST_ID = "a" * 64
runner = CliRunner()


def _bundle() -> M4FakeVLMFixtureBundle:
    return M4FakeVLMFixtureBundle(
        schema_version="m4-fake-vlm-fixture-bundle-v1",
        fixtures=(),
    )


def _write_bundle(path: Path) -> Path:
    path.write_text(_bundle().model_dump_json(), encoding="utf-8")
    return path


def _report() -> M4ProcessReport:
    outcome = M4ProcessCaseOutcome(
        event_id="event-m4-cli",
        case_id=CASE_ID,
        initial_status=CaseStatus.HUMAN_REVIEW,
        status=CaseStatus.HUMAN_REVIEW,
        revision=3,
        disposition=M4ProcessDisposition.OBSERVED_EXISTING,
        pipeline_invoked=False,
        cache_hit_count=0,
        recovered_response_count=0,
    )
    return M4ProcessReport(
        run_id=RUN_ID,
        manifest_id=MANIFEST_ID,
        perception_mode="SIMULATED PERCEPTION",
        model_mode="FAKE VLM",
        precedent_mode="CONTROLLED FAKE",
        fixture_bundle_id=_bundle().fixture_bundle_id,
        fixture_entry_count=0,
        requested_case_id=CASE_ID,
        selection_limit=1,
        available_case_count=1,
        selection_truncated=False,
        outcomes=(outcome,),
        counts=M4ProcessCounts(
            selected_cases=1,
            pipeline_invocations=0,
            processed_cases=0,
            deferred_to_backlog_cases=0,
            transferred_to_human_cases=0,
            observed_existing_cases=1,
            skipped_not_hearing_ready_cases=0,
            cache_hits=0,
            recovered_responses=0,
        ),
    )


def test_hearing_process_keeps_completed_authority_when_projection_is_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _write_bundle(tmp_path / "bundle.json")

    class _Service:
        def process_case(self, case_id: str) -> M4ProcessReport:
            assert case_id == CASE_ID
            return _report()

    @contextmanager
    def open_service(**_kwargs):
        yield _Service()

    monkeypatch.setattr("labcourt.m4_cli.open_m4_operations_service", open_service)
    monkeypatch.setattr(
        "labcourt.m4_cli._rebuild_projection",
        lambda **_kwargs: M4ProjectionOutcome(
            disposition=M4ProjectionDisposition.PENDING_REBUILD,
            reason_code="PROJECTION_REBUILD_FAILED",
        ),
    )

    result = runner.invoke(
        app,
        [
            "hearing",
            "process",
            "--run-id",
            RUN_ID,
            "--case-id",
            CASE_ID,
            "--fixture-bundle",
            str(fixture),
            "--config",
            str(ROOT / "configs" / "demo.yaml"),
            "--json",
        ],
    )

    assert result.exit_code == 1
    parsed = M4ProcessCommandReport.model_validate_json(result.stdout)
    assert parsed.authority_complete is True
    assert parsed.authority_report == _report()
    assert parsed.projection.disposition == M4ProjectionDisposition.PENDING_REBUILD


def test_hearing_backlog_cli_maps_missing_adapter_to_typed_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _write_bundle(tmp_path / "bundle.json")

    class _Service:
        def backlog_retry_run_once(self, **_kwargs):
            raise M4OperationsBoundaryError(M4OperationsBoundaryCode.BACKLOG_ADAPTER_UNAVAILABLE)

    @contextmanager
    def open_service(**_kwargs):
        yield _Service()

    monkeypatch.setattr("labcourt.m4_cli.open_m4_operations_service", open_service)

    result = runner.invoke(
        app,
        [
            "hearing",
            "backlog",
            "retry",
            "--run-id",
            RUN_ID,
            "--worker-id",
            "worker-m4-cli",
            "--fixture-bundle",
            str(fixture),
            "--config",
            str(ROOT / "configs" / "demo.yaml"),
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload == {
        "authority_complete": False,
        "error": "M4_OPERATION_BOUNDARY_ERROR",
        "model_mode": "FAKE VLM",
        "operation": "HEARING_BACKLOG_RETRY",
        "perception_mode": "SIMULATED PERCEPTION",
        "precedent_mode": "CONTROLLED FAKE",
        "reason_code": "BACKLOG_ADAPTER_UNAVAILABLE",
    }


@pytest.mark.parametrize("recovery_code", tuple(HearingBacklogRetryRecoveryCode))
def test_hearing_backlog_cli_preserves_typed_recovery_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    recovery_code: HearingBacklogRetryRecoveryCode,
) -> None:
    fixture = _write_bundle(tmp_path / "bundle.json")

    class _Service:
        def backlog_retry_run_once(self, **_kwargs):
            raise HearingBacklogRetryRecoveryRequired(
                recovery_code,
                request_id="request-m4-recovery",
            )

    @contextmanager
    def open_service(**_kwargs):
        yield _Service()

    monkeypatch.setattr("labcourt.m4_cli.open_m4_operations_service", open_service)

    result = runner.invoke(
        app,
        [
            "hearing",
            "backlog",
            "retry",
            "--run-id",
            RUN_ID,
            "--worker-id",
            "worker-m4-cli",
            "--fixture-bundle",
            str(fixture),
            "--config",
            str(ROOT / "configs" / "demo.yaml"),
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["authority_complete"] is False
    assert payload["operation"] == "HEARING_BACKLOG_RETRY"
    assert payload["reason_code"] == recovery_code.value


@pytest.mark.parametrize(
    ("payload", "reason"),
    (
        (
            b'{"schema_version":"m4-fake-vlm-fixture-bundle-v1","fixtures":[],"fixtures":[]}',
            "FIXTURE_JSON_INVALID",
        ),
        (b"\xff", "FIXTURE_UTF8_INVALID"),
        (
            b'{"schema_version":"m4-fake-vlm-fixture-bundle-v1",'
            b'"fixtures":[],"fixture_bundle_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
            b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}',
            "FIXTURE_CONTRACT_INVALID",
        ),
    ),
)
def test_fixture_loader_rejects_duplicate_utf8_and_computed_field_tamper(
    tmp_path: Path,
    payload: bytes,
    reason: str,
) -> None:
    path = tmp_path / "invalid.json"
    path.write_bytes(payload)

    with pytest.raises(_FixtureInputError) as raised:
        _load_fixture_bundle(path)

    assert raised.value.reason_code == reason


def test_missing_fixture_fails_before_any_authority_is_claimed(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "hearing",
            "process",
            "--run-id",
            RUN_ID,
            "--case-id",
            CASE_ID,
            "--fixture-bundle",
            str(tmp_path / "missing.json"),
            "--config",
            str(ROOT / "configs" / "demo.yaml"),
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["authority_complete"] is False
    assert payload["reason_code"] == "FIXTURE_FILE_UNAVAILABLE"
    assert payload["perception_mode"] == "SIMULATED PERCEPTION"
    assert payload["model_mode"] == "FAKE VLM"
    assert payload["precedent_mode"] == "CONTROLLED FAKE"


def test_acquisition_fixture_count_is_bounded_before_contract_parsing(
    tmp_path: Path,
) -> None:
    path = tmp_path / "too-many-acquisition-fixtures.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "m4-fake-vlm-fixture-bundle-v1",
                "fixtures": [],
                "acquisition_fixtures": [{}] * 65,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(_FixtureInputError) as raised:
        _load_fixture_bundle(path)

    assert raised.value.reason_code == "FIXTURE_ENTRY_BUDGET_EXCEEDED"

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_m2_evidence_pipeline import ROOT, _complete_request, _stack
from typer.testing import CliRunner

from labcourt.adapters.storage.json_projector import JsonProjector
from labcourt.adapters.storage.model_response_store import SecureModelResponseStore
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_m3_repository import SQLiteM3Repository
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.application.screening_request import prepare_screening_request
from labcourt.cli import app
from labcourt.config_loader import load_config
from labcourt.contracts.artifact_validation import M3ArtifactValidationReport
from labcourt.contracts.backlog import (
    BacklogLeaseIdentity,
    BacklogRetryContext,
    BacklogRetryDisposition,
)
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogStage,
    CaseStatus,
)
from labcourt.contracts.m3_command_reports import (
    M3BacklogRetryCommandReport,
    M3ProcessCommandReport,
    M3ProjectionDisposition,
    M3ProjectionReasonCode,
)
from labcourt.contracts.m3_operations import (
    FakeVLMFailureFixtureInput,
    FakeVLMFixtureBundle,
    FakeVLMFixtureDisposition,
    FakeVLMResponseFixtureInput,
)
from labcourt.contracts.screening import VLMCallRequest
from labcourt.ports.screening_repository import ModelCallClaimStatus
from labcourt.services.m3 import build_screening_prompt_catalog

RUNNER = CliRunner()


class _Release:
    def __init__(
        self,
        *,
        root: Path,
        run_id: str,
        config_path: Path,
        config: object,
        database: Path,
        workspace: Path,
        manifest: object,
        pack: object,
        case_id: str,
        request: VLMCallRequest,
        raw_response: bytes,
    ) -> None:
        self.root = root
        self.run_id = run_id
        self.config_path = config_path
        self.config = config
        self.database = database
        self.workspace = workspace
        self.manifest = manifest
        self.pack = pack
        self.case_id = case_id
        self.request = request
        self.raw_response = raw_response


def _release(tmp_path: Path, run_id: str, *, backlog_max_attempts: int = 3) -> _Release:
    tmp_path.mkdir(parents=True, exist_ok=True)
    config_path = tmp_path / "config.yaml"
    authored = (ROOT / "configs" / "demo.yaml").read_text(encoding="utf-8")
    authored = authored.replace('workspace: "runs"', 'workspace: "workspace"')
    authored = authored.replace(
        "backlog_max_attempts: 3",
        f"backlog_max_attempts: {backlog_max_attempts}",
    )
    config_path.write_text(authored, encoding="utf-8")
    config = load_config(config_path)
    with _stack(tmp_path, run_id=run_id, config=config) as stack:
        publication = stack.builder.build_and_publish(_complete_request(stack)).publication
        pack = publication.pack
        manifest = stack.manifest
        request = prepare_screening_request(
            pack,
            config,
            manifest,
            build_screening_prompt_catalog(manifest),
        ).request
        raw_response = _valid_absence_response(pack)
    return _Release(
        root=tmp_path,
        run_id=run_id,
        config_path=config_path,
        config=config,
        database=tmp_path / "workspace" / config.storage.database_filename,
        workspace=tmp_path / "workspace",
        manifest=manifest,
        pack=pack,
        case_id=pack.case_id,
        request=request,
        raw_response=raw_response,
    )


def _valid_absence_response(pack: object) -> bytes:
    crops = tuple(sorted(pack.temporal_crops, key=lambda crop: crop.crop_id))
    return canonical_bytes(
        {
            "evidence_citations": [
                {
                    "bbox": None,
                    "coordinate_space": None,
                    "evidence_ref": {
                        "artifact_id": crops[0].crop_id,
                        "kind": ArtifactKind.CROP.value,
                    },
                }
            ],
            "evidence_class": pack.event.evidence_class.value,
            "frame_observations": [
                {
                    "crop_id": crop.crop_id,
                    "reason_summary": "Synthetic offline fixture observation.",
                    "wear_status": "NOT_WORN",
                }
                for crop in crops
            ],
            "objective_claims": [],
            "prosecution_summary": "Synthetic structured citations support the test result.",
            "rationale_summary": "Only typed fixture fields drive this offline workflow.",
            "violation_probability": 0.95,
            "violation_type": pack.event.violation_type.value,
        }
    )


def _write_response_bundle(path: Path, request: VLMCallRequest, raw: bytes) -> Path:
    bundle = FakeVLMFixtureBundle(
        schema_version="m3-fake-vlm-fixture-bundle-v1",
        fixtures=(
            FakeVLMResponseFixtureInput(
                disposition=FakeVLMFixtureDisposition.RESPONSE,
                cache_key=request.cache_key,
                raw_response_utf8=raw.decode("utf-8"),
                input_tokens=23,
                output_tokens=11,
                latency_ms=17,
            ),
        ),
    )
    path.write_text(bundle.model_dump_json(), encoding="utf-8")
    return path


def _write_outage_bundle(path: Path, request: VLMCallRequest) -> Path:
    bundle = FakeVLMFixtureBundle(
        schema_version="m3-fake-vlm-fixture-bundle-v1",
        fixtures=(
            FakeVLMFailureFixtureInput(
                disposition=FakeVLMFixtureDisposition.OUTAGE,
                cache_key=request.cache_key,
            ),
        ),
    )
    path.write_text(bundle.model_dump_json(), encoding="utf-8")
    return path


def _process_args(release: _Release, fixture: Path) -> list[str]:
    return [
        "process",
        "--run-id",
        release.run_id,
        "--case-id",
        release.case_id,
        "--fixture-bundle",
        str(fixture),
        "--config",
        str(release.config_path),
        "--json",
    ]


def _fingerprint(root: Path) -> tuple[tuple[str, int, str], ...]:
    return tuple(
        (
            path.relative_to(root).as_posix(),
            path.stat().st_size,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix())
        if path.is_file()
    )


def test_process_success_is_canonical_idempotent_and_artifact_valid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _release(tmp_path, "m3-cli-process-success")
    fixture = _write_response_bundle(
        tmp_path / "response.json",
        release.request,
        release.raw_response,
    )
    monkeypatch.chdir(tmp_path)

    first = RUNNER.invoke(app, _process_args(release, fixture))
    assert first.exit_code == 0, first.output
    first_report = M3ProcessCommandReport.model_validate_json(first.stdout)
    assert first_report.perception_mode == "SIMULATED PERCEPTION"
    assert first_report.model_mode == "FAKE VLM"
    assert first_report.projection.disposition == M3ProjectionDisposition.REBUILT
    assert first_report.authority_report.outcomes[0].status == CaseStatus.READY_FOR_ALERT_POLICY
    assert first.stdout.strip() == canonical_bytes(json.loads(first.stdout)).decode("utf-8")

    validation = RUNNER.invoke(
        app,
        [
            "artifacts",
            "validate",
            "--run-id",
            release.run_id,
            "--config",
            str(release.config_path),
            "--json",
        ],
    )
    assert validation.exit_code == 0, validation.output
    assert M3ArtifactValidationReport.model_validate_json(validation.stdout).passed

    second = RUNNER.invoke(app, _process_args(release, fixture))
    third = RUNNER.invoke(app, _process_args(release, fixture))
    assert second.exit_code == third.exit_code == 0
    assert second.stdout == third.stdout
    observed = M3ProcessCommandReport.model_validate_json(second.stdout)
    assert observed.authority_report.counts.pipeline_invocations == 0
    human_args = [argument for argument in _process_args(release, fixture) if argument != "--json"]
    human = RUNNER.invoke(app, human_args)
    assert human.exit_code == 0
    assert "SIMULATED PERCEPTION / FAKE VLM" in human.stdout


def test_process_outage_is_a_successful_atomic_backlog_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _release(tmp_path, "m3-cli-outage")
    outage = _write_outage_bundle(tmp_path / "outage.json", release.request)
    monkeypatch.chdir(tmp_path)

    result = RUNNER.invoke(app, _process_args(release, outage))
    assert result.exit_code == 0, result.output
    report = M3ProcessCommandReport.model_validate_json(result.stdout)
    assert report.authority_report.counts.deferred_to_backlog_cases == 1
    assert report.authority_report.outcomes[0].status == CaseStatus.BACKLOGGED
    assert report.projection.disposition == M3ProjectionDisposition.REBUILT


def test_invalid_fixture_preflight_writes_no_authority_or_projection_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _release(tmp_path, "m3-cli-invalid-fixture")
    monkeypatch.chdir(tmp_path)
    before = _fingerprint(release.workspace)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (18 * 1024 * 1024))
    oversized_result = RUNNER.invoke(app, _process_args(release, oversized))
    assert oversized_result.exit_code == 2
    oversized_error = json.loads(oversized_result.stdout)
    assert oversized_error["reason_code"] == "FIXTURE_FILE_BYTES_BUDGET_EXCEEDED"
    assert _fingerprint(release.workspace) == before

    surrogate = tmp_path / "surrogate.json"
    surrogate.write_bytes(
        b'{"schema_version":"m3-fake-vlm-fixture-bundle-v1","fixtures":['
        b'{"disposition":"RESPONSE","cache_key":"'
        + (b"1" * 64)
        + b'","raw_response_utf8":"\\ud800","input_tokens":0,'
        b'"output_tokens":0,"latency_ms":0}]}'
    )
    surrogate_result = RUNNER.invoke(app, _process_args(release, surrogate))
    assert surrogate_result.exit_code == 2
    surrogate_error = json.loads(surrogate_result.stdout)
    assert surrogate_error["reason_code"] == "FIXTURE_UTF8_INVALID"
    assert "raw_response_utf8" not in surrogate_result.stdout
    assert _fingerprint(release.workspace) == before

    strict_invalid_payloads = {
        "top-level-duplicate": (
            b'{"schema_version":"m3-fake-vlm-fixture-bundle-v1",'
            b'"schema_version":"must-not-leak-top-level","fixtures":[]}'
        ),
        "nested-duplicate": (
            b'{"schema_version":"m3-fake-vlm-fixture-bundle-v1","fixtures":['
            b'{"disposition":"OUTAGE","cache_key":"'
            + (b"1" * 64)
            + b'","cache_key":"must-not-leak-nested"}]}'
        ),
        "nan": (
            b'{"schema_version":"m3-fake-vlm-fixture-bundle-v1","fixtures":['
            b'{"disposition":"RESPONSE","cache_key":"'
            + (b"1" * 64)
            + b'","raw_response_utf8":"{}","input_tokens":NaN,'
            b'"output_tokens":0,"latency_ms":0}]}'
        ),
        "infinity": (
            b'{"schema_version":"m3-fake-vlm-fixture-bundle-v1","fixtures":['
            b'{"disposition":"RESPONSE","cache_key":"'
            + (b"1" * 64)
            + b'","raw_response_utf8":"{}","input_tokens":Infinity,'
            b'"output_tokens":0,"latency_ms":0}]}'
        ),
        "negative-infinity": (
            b'{"schema_version":"m3-fake-vlm-fixture-bundle-v1","fixtures":['
            b'{"disposition":"RESPONSE","cache_key":"'
            + (b"1" * 64)
            + b'","raw_response_utf8":"{}","input_tokens":-Infinity,'
            b'"output_tokens":0,"latency_ms":0}]}'
        ),
        "bom": (b'\xef\xbb\xbf{"schema_version":"m3-fake-vlm-fixture-bundle-v1","fixtures":[]}'),
        "nul": (b'{"schema_version":"m3-fake-vlm-fixture-bundle-v1\\u0000","fixtures":[]}'),
        "five-thousand-digit-integer": (
            b'{"schema_version":"m3-fake-vlm-fixture-bundle-v1","fixtures":['
            b'{"disposition":"RESPONSE","cache_key":"'
            + (b"1" * 64)
            + b'","raw_response_utf8":"{}","input_tokens":'
            + (b"9" * 5_000)
            + b',"output_tokens":0,"latency_ms":0}]}'
        ),
        "huge-exponent": (
            b'{"schema_version":"m3-fake-vlm-fixture-bundle-v1","fixtures":['
            b'{"disposition":"RESPONSE","cache_key":"'
            + (b"1" * 64)
            + b'","raw_response_utf8":"{}","input_tokens":1e400,'
            b'"output_tokens":0,"latency_ms":0}]}'
        ),
        "overlong-float": (
            b'{"schema_version":"m3-fake-vlm-fixture-bundle-v1","fixtures":['
            b'{"disposition":"RESPONSE","cache_key":"'
            + (b"1" * 64)
            + b'","raw_response_utf8":"{}","input_tokens":0.'
            + (b"7" * 5_000)
            + b',"output_tokens":0,"latency_ms":0}]}'
        ),
        "nested-huge-number": (
            b'{"schema_version":"m3-fake-vlm-fixture-bundle-v1","fixtures":[],'
            b'"must-not-leak-nested-number":{"depth":{"value":1e400}}}'
        ),
    }
    for name, invalid_payload in strict_invalid_payloads.items():
        invalid_fixture = tmp_path / f"strict-invalid-{name}.json"
        invalid_fixture.write_bytes(invalid_payload)
        invalid_result = RUNNER.invoke(app, _process_args(release, invalid_fixture))
        assert invalid_result.exit_code == 2
        assert json.loads(invalid_result.stdout)["reason_code"] == "FIXTURE_JSON_INVALID"
        assert "must-not-leak" not in invalid_result.stdout
        assert "9" * 64 not in invalid_result.stdout
        assert "7" * 64 not in invalid_result.stdout
        assert "1e400" not in invalid_result.stdout
        assert _fingerprint(release.workspace) == before

    too_many = tmp_path / "too-many.json"
    too_many.write_text(
        json.dumps(
            {
                "schema_version": "m3-fake-vlm-fixture-bundle-v1",
                "fixtures": [
                    {
                        "cache_key": f"{index:064x}",
                        "disposition": "OUTAGE",
                    }
                    for index in range(1_001)
                ],
            }
        ),
        encoding="utf-8",
    )
    too_many_result = RUNNER.invoke(app, _process_args(release, too_many))
    assert too_many_result.exit_code == 2
    assert json.loads(too_many_result.stdout)["reason_code"] == ("FIXTURE_ENTRY_BUDGET_EXCEEDED")
    assert _fingerprint(release.workspace) == before


def test_projection_failure_keeps_committed_authority_in_exit_one_envelope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _release(tmp_path, "m3-cli-projection-failure")
    fixture = _write_response_bundle(
        tmp_path / "response.json",
        release.request,
        release.raw_response,
    )
    monkeypatch.chdir(tmp_path)

    def fail_projection(self: JsonProjector, run_id: str, target_directory: object = None) -> None:
        del self, run_id, target_directory
        raise RuntimeError("C:/secret/projection-path")

    monkeypatch.setattr(JsonProjector, "project_run", fail_projection)
    result = RUNNER.invoke(app, _process_args(release, fixture))

    assert result.exit_code == 1, result.output
    report = M3ProcessCommandReport.model_validate_json(result.stdout)
    assert report.authority_report.outcomes[0].status == CaseStatus.READY_FOR_ALERT_POLICY
    assert report.projection.disposition == M3ProjectionDisposition.PENDING_REBUILD
    assert report.projection.reason_code == M3ProjectionReasonCode.PROJECTION_REBUILD_FAILED
    assert "secret" not in result.stdout
    persisted = SQLiteEvidenceRepository(
        release.database,
        release.config.storage.busy_timeout_ms,
    ).load_case(release.run_id, release.case_id)
    assert persisted.case.status == CaseStatus.READY_FOR_ALERT_POLICY


def test_backlog_retry_no_work_fixture_success_and_cache_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    no_work_release = _release(tmp_path / "no-work", "m3-cli-retry-no-work")
    monkeypatch.chdir(no_work_release.root)
    no_work = RUNNER.invoke(
        app,
        [
            "backlog",
            "retry",
            "--run-id",
            no_work_release.run_id,
            "--worker-id",
            "worker-no-work",
            "--config",
            str(no_work_release.config_path),
            "--json",
        ],
    )
    assert no_work.exit_code == 0, no_work.output
    no_work_report = M3BacklogRetryCommandReport.model_validate_json(no_work.stdout)
    assert no_work_report.authority_report.disposition == BacklogRetryDisposition.NO_WORK

    fixture_release = _release(tmp_path / "fixture", "m3-cli-retry-fixture")
    monkeypatch.chdir(fixture_release.root)
    outage = _write_outage_bundle(
        fixture_release.root / "outage.json",
        fixture_release.request,
    )
    backlogged = RUNNER.invoke(app, _process_args(fixture_release, outage))
    process_report = M3ProcessCommandReport.model_validate_json(backlogged.stdout)
    item_ref = process_report.authority_report.outcomes[0].backlog_item_ref
    assert item_ref is not None
    item = SQLiteM3Repository(
        fixture_release.database,
        fixture_release.config.storage.busy_timeout_ms,
    ).load_backlog_item(fixture_release.run_id, item_ref.artifact_id)
    retry_request = prepare_screening_request(
        fixture_release.pack,
        fixture_release.config,
        fixture_release.manifest,
        build_screening_prompt_catalog(fixture_release.manifest),
        backlog_retry_context=BacklogRetryContext(
            backlog_item_id=item.item_id,
            retry_generation=item.retry_generation,
        ),
    ).request
    retry_fixture = _write_response_bundle(
        fixture_release.root / "retry.json",
        retry_request,
        fixture_release.raw_response,
    )
    retried = RUNNER.invoke(
        app,
        [
            "backlog",
            "retry",
            "--run-id",
            fixture_release.run_id,
            "--worker-id",
            "worker-fixture",
            "--fixture-bundle",
            str(retry_fixture),
            "--config",
            str(fixture_release.config_path),
            "--json",
        ],
    )
    assert retried.exit_code == 0, retried.output
    assert (
        M3BacklogRetryCommandReport.model_validate_json(retried.stdout).authority_report.disposition
        == BacklogRetryDisposition.COMPLETED
    )

    cache_release = _release(tmp_path / "cache", "m3-cli-retry-cache")
    monkeypatch.chdir(cache_release.root)
    cache_outage = _write_outage_bundle(cache_release.root / "outage.json", cache_release.request)
    cached_backlog = M3ProcessCommandReport.model_validate_json(
        RUNNER.invoke(app, _process_args(cache_release, cache_outage)).stdout
    )
    cached_ref = cached_backlog.authority_report.outcomes[0].backlog_item_ref
    assert cached_ref is not None
    cache_item = SQLiteM3Repository(
        cache_release.database,
        cache_release.config.storage.busy_timeout_ms,
    ).load_backlog_item(cache_release.run_id, cached_ref.artifact_id)
    cached_request = prepare_screening_request(
        cache_release.pack,
        cache_release.config,
        cache_release.manifest,
        build_screening_prompt_catalog(cache_release.manifest),
        backlog_retry_context=BacklogRetryContext(
            backlog_item_id=cache_item.item_id,
            retry_generation=cache_item.retry_generation,
        ),
    ).request
    cache_clock = datetime(2026, 1, 1, tzinfo=UTC)
    with SecureWorkspace(
        cache_release.workspace,
        cache_release.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        repository = SQLiteM3Repository(
            cache_release.database,
            cache_release.config.storage.busy_timeout_ms,
            clock=lambda: cache_clock,
            raw_response_verifier=store,
        )
        leased = repository.lease_next(
            cache_release.run_id,
            BacklogStage.SCREENING,
            "8" * 64,
            cache_clock + timedelta(minutes=1),
        )
        assert leased is not None
        assert leased.lease_id is not None
        lease = BacklogLeaseIdentity(
            run_id=leased.run_id,
            item_id=leased.item_id,
            lease_id=leased.lease_id,
            attempt_count=leased.attempt_count,
            retry_generation=leased.retry_generation,
        )
        owner = "cached-cli-retry-owner-token-0001"
        claim = repository.claim_model_call(
            cache_release.run_id,
            cached_request,
            owner,
            backlog_lease=lease,
        )
        assert claim.status == ModelCallClaimStatus.ACQUIRED
        response = store.publish(
            cached_request,
            cache_release.raw_response,
            input_tokens=23,
            output_tokens=11,
            latency_ms=17,
        )
        repository.complete_model_call(cache_release.run_id, cached_request, response, owner)
        store.acknowledge(cached_request, response)
    cached_retry = RUNNER.invoke(
        app,
        [
            "backlog",
            "retry",
            "--run-id",
            cache_release.run_id,
            "--worker-id",
            "worker-cache",
            "--config",
            str(cache_release.config_path),
            "--json",
        ],
    )
    assert cached_retry.exit_code == 0, cached_retry.output
    assert (
        M3BacklogRetryCommandReport.model_validate_json(
            cached_retry.stdout
        ).authority_report.disposition
        == BacklogRetryDisposition.COMPLETED
    )


def test_backlog_retry_reports_expired_reclaim_and_exhaustion_field(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _release(tmp_path, "m3-cli-expired", backlog_max_attempts=1)
    monkeypatch.chdir(tmp_path)
    outage = _write_outage_bundle(tmp_path / "outage.json", release.request)
    process_report = M3ProcessCommandReport.model_validate_json(
        RUNNER.invoke(app, _process_args(release, outage)).stdout
    )
    backlog_ref = process_report.authority_report.outcomes[0].backlog_item_ref
    assert backlog_ref is not None
    repository = SQLiteM3Repository(
        release.database,
        release.config.storage.busy_timeout_ms,
    )
    leased = repository.lease_next(
        release.run_id,
        BacklogStage.SCREENING,
        "7" * 64,
        datetime.now(UTC) - timedelta(minutes=1),
    )
    assert leased is not None

    result = RUNNER.invoke(
        app,
        [
            "backlog",
            "retry",
            "--run-id",
            release.run_id,
            "--worker-id",
            "worker-reclaim",
            "--config",
            str(release.config_path),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    report = M3BacklogRetryCommandReport.model_validate_json(result.stdout)
    assert report.authority_report.disposition == BacklogRetryDisposition.NO_WORK
    assert report.authority_report.reclaimed_expired_count == 1
    assert report.authority_report.reclaimed_exhausted_count == 1


def test_m3_operation_help_and_cli_bounds_are_explicit() -> None:
    process_help = RUNNER.invoke(app, ["process", "--help"])
    backlog_help = RUNNER.invoke(app, ["backlog", "retry", "--help"])
    bounded = RUNNER.invoke(
        app,
        ["process", "--run-id", "run-a", "--max-cases", "1001"],
    )
    missing_worker = RUNNER.invoke(app, ["backlog", "retry", "--run-id", "run-a"])

    assert process_help.exit_code == backlog_help.exit_code == 0
    assert "--fixture-bundle" in process_help.stdout
    assert "--worker-id" in backlog_help.stdout
    assert bounded.exit_code == 2
    assert missing_worker.exit_code == 2

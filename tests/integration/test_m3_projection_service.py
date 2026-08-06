from __future__ import annotations

from pathlib import Path

from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.config_loader import load_config
from labcourt.contracts.events import CandidateEvent
from labcourt.contracts.m3_command_reports import (
    M3ProjectionBudget,
    M3ProjectionDisposition,
    M3ProjectionReasonCode,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.services.m3_projection import rebuild_m3_projection

ROOT = Path(__file__).resolve().parents[2]
RUN_ID = "m3-projection-service"


def _release(tmp_path: Path) -> tuple[object, Path, Path]:
    config = load_config(ROOT / "configs" / "demo.yaml")
    workspace = tmp_path / "runs"
    workspace.mkdir()
    database = workspace / config.storage.database_filename
    MigrationRunner(database, config.storage.busy_timeout_ms).apply_all()
    manifest = RunManifest.model_validate_json(
        (ROOT / "tests" / "fixtures" / "m2" / "run-manifest-fake.json").read_text(encoding="utf-8")
    )
    repository = SQLiteEvidenceRepository(database, config.storage.busy_timeout_ms)
    repository.register_run(RUN_ID, manifest)
    event = CandidateEvent.model_validate_json(
        (ROOT / "tests" / "fixtures" / "m2" / "candidate-event-presence.json").read_text(
            encoding="utf-8"
        )
    )
    repository.create_or_get_case(RUN_ID, event)
    return config, workspace, database


def _budget(**changes: int) -> M3ProjectionBudget:
    payload = {
        "max_database_bytes": 64 * 1024 * 1024,
        "max_audit_entries": 100,
        "max_cases": 100,
        "max_packs": 100,
        "max_document_bytes": 1024 * 1024,
        "max_projection_file_bytes": 8 * 1024 * 1024,
        "max_materialization_bytes": 64 * 1024 * 1024,
    }
    payload.update(changes)
    return M3ProjectionBudget.model_validate(payload)


def test_projection_rebuild_uses_bounded_snapshot_and_writes_canonical_release(
    tmp_path: Path,
) -> None:
    config, workspace, database = _release(tmp_path)
    outcome = rebuild_m3_projection(
        config=config,
        run_id=RUN_ID,
        workspace_root=workspace,
        database_path=database,
        budget=_budget(),
    )

    assert outcome.disposition == M3ProjectionDisposition.REBUILT
    assert outcome.reason_code is None
    assert outcome.counts is not None
    assert outcome.counts.cases == 1
    current = workspace / RUN_ID / "projections" / "current.json"
    assert current.is_file()
    assert tuple((workspace / RUN_ID / "projections" / "generations").glob("*"))


def test_projection_budget_and_injected_failure_are_typed_without_paths(
    tmp_path: Path,
) -> None:
    config, workspace, database = _release(tmp_path)
    bounded = rebuild_m3_projection(
        config=config,
        run_id=RUN_ID,
        workspace_root=workspace,
        database_path=database,
        budget=_budget(max_materialization_bytes=1),
    )
    assert bounded.disposition == M3ProjectionDisposition.PENDING_REBUILD
    assert bounded.reason_code == M3ProjectionReasonCode.MATERIALIZATION_BUDGET_EXCEEDED

    def fail_projection(_phase: str) -> None:
        raise RuntimeError("host-secret-path")

    failed = rebuild_m3_projection(
        config=config,
        run_id=RUN_ID,
        workspace_root=workspace,
        database_path=database,
        budget=_budget(),
        fault_injector=fail_projection,
    )
    assert failed.disposition == M3ProjectionDisposition.PENDING_REBUILD
    assert failed.reason_code == M3ProjectionReasonCode.PROJECTION_REBUILD_FAILED
    assert "host-secret-path" not in failed.model_dump_json()


def test_projection_database_document_and_file_preflights_fail_before_projector(
    tmp_path: Path,
) -> None:
    config, workspace, database = _release(tmp_path)
    database_bounded = rebuild_m3_projection(
        config=config,
        run_id=RUN_ID,
        workspace_root=workspace,
        database_path=database,
        budget=_budget(max_database_bytes=1),
    )
    assert database_bounded.reason_code == (M3ProjectionReasonCode.DATABASE_BYTES_BUDGET_EXCEEDED)
    assert database_bounded.counts is None

    document_bounded = rebuild_m3_projection(
        config=config,
        run_id=RUN_ID,
        workspace_root=workspace,
        database_path=database,
        budget=_budget(max_document_bytes=1),
    )
    assert document_bounded.reason_code == (M3ProjectionReasonCode.DOCUMENT_BYTES_BUDGET_EXCEEDED)

    file_bounded = rebuild_m3_projection(
        config=config,
        run_id=RUN_ID,
        workspace_root=workspace,
        database_path=database,
        budget=_budget(max_projection_file_bytes=1),
    )
    assert file_bounded.reason_code == M3ProjectionReasonCode.PROJECTION_FILE_BUDGET_EXCEEDED

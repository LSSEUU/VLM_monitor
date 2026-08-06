import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.contracts.audit import validate_audit_chain
from labcourt.contracts.enums import (
    AuditAction,
    CaseStatus,
    ClosureDefectCode,
    EvidenceFailureCode,
)
from labcourt.contracts.events import CandidateEvent, derive_case_id
from labcourt.contracts.evidence import EvidencePackDraft, TrackSummary
from labcourt.contracts.manifests import RunManifest
from labcourt.exceptions import ConcurrentModification, CreationClosureFailed

FIXTURES = Path(__file__).parents[1] / "fixtures" / "m2"
RUN_ID = "run-01"
BUSY_TIMEOUT_MS = 5_000
RECORDED_AT = datetime(2026, 7, 27, 12, 34, 56, 123456, tzinfo=UTC)


def _clock() -> datetime:
    return RECORDED_AT


def _manifest() -> RunManifest:
    return RunManifest.model_validate_json(
        (FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )


def _event() -> CandidateEvent:
    return CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8")
    )


def _setup_case(tmp_path: Path) -> tuple[Path, SQLiteEvidenceRepository, str]:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    repository = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS, clock=_clock)
    repository.register_run(RUN_ID, _manifest())
    snapshot = repository.create_or_get_case(RUN_ID, _event())
    return database, repository, snapshot.case.case_id


def _database_state(database: Path, case_id: str) -> dict[str, object]:
    connection = sqlite3.connect(database)
    try:
        case_row = connection.execute(
            "SELECT status, current_revision FROM cases WHERE run_id = ? AND case_id = ?",
            (RUN_ID, case_id),
        ).fetchone()
        run_row = connection.execute(
            "SELECT revision, audit_head_sequence, audit_head_hash FROM runs WHERE run_id = ?",
            (RUN_ID,),
        ).fetchone()
        assert case_row is not None
        assert run_row is not None
        return {
            "case": case_row,
            "case_versions": connection.execute(
                "SELECT COUNT(*) FROM case_versions WHERE run_id = ? AND case_id = ?",
                (RUN_ID, case_id),
            ).fetchone()[0],
            "audits": connection.execute(
                "SELECT COUNT(*) FROM audit_entries WHERE run_id = ?",
                (RUN_ID,),
            ).fetchone()[0],
            "run": run_row,
        }
    finally:
        connection.close()


def test_record_evidence_failure_atomically_enters_human_review_with_typed_audit(
    tmp_path: Path,
) -> None:
    database, repository, case_id = _setup_case(tmp_path)

    result = repository.record_evidence_failure(
        RUN_ID,
        1,
        case_id,
        EvidenceFailureCode.EVIDENCE_MISSING,
    )

    assert result.revision == 2
    assert result.case.status == CaseStatus.HUMAN_REVIEW
    assert len(result.case.timeline) == 1
    entry = result.case.timeline[0]
    assert entry.sequence == 0
    assert entry.action == AuditAction.CASE_STATE_CHANGED.value
    assert entry.stage == "EVIDENCE"
    assert entry.object_ref == case_id
    assert dict(entry.details) == {"failure_code": "EVIDENCE_MISSING"}

    connection = sqlite3.connect(database)
    try:
        stored = connection.execute(
            """
            SELECT case_json FROM case_versions
            WHERE run_id = ? AND case_id = ? AND revision = 2
            """,
            (RUN_ID, case_id),
        ).fetchone()
        assert stored is not None
        timeline = json.loads(stored[0])["timeline"]
        assert timeline[-1]["details"] == {"failure_code": "EVIDENCE_MISSING"}
        assert "exception" not in timeline[-1]
        assert "path" not in timeline[-1]
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE case_versions SET status = 'CANDIDATE' WHERE run_id = ?",
                (RUN_ID,),
            )
    finally:
        connection.close()

    audits = repository.list_audit_entries(RUN_ID)
    assert len(audits) == 2
    assert audits[-1].actor == "EVIDENCE"
    assert audits[-1].action == AuditAction.CASE_STATE_CHANGED
    assert audits[-1].object_ref.artifact_id == case_id
    head = repository.get_audit_head(RUN_ID)
    assert validate_audit_chain(
        audits,
        expected_run_id=RUN_ID,
        expected_manifest_id=head.manifest_id,
        expected_head_sequence=head.sequence,
        expected_head_hash=head.entry_hash,
    ).passed
    assert repository.load_case(RUN_ID, case_id) == result


def test_same_latest_failure_is_idempotent_but_different_or_stale_writes_conflict(
    tmp_path: Path,
) -> None:
    database, repository, case_id = _setup_case(tmp_path)
    first = repository.record_evidence_failure(
        RUN_ID,
        1,
        case_id,
        EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE,
    )
    committed = _database_state(database, case_id)

    assert (
        repository.record_evidence_failure(
            RUN_ID,
            1,
            case_id,
            EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE,
        )
        == first
    )
    assert (
        repository.record_evidence_failure(
            RUN_ID,
            2,
            case_id,
            EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE,
        )
        == first
    )
    with pytest.raises(ConcurrentModification, match="different latest"):
        repository.record_evidence_failure(
            RUN_ID,
            2,
            case_id,
            EvidenceFailureCode.PRIVACY_POLICY_UNSATISFIED,
        )
    with pytest.raises(ConcurrentModification, match="revision"):
        repository.record_evidence_failure(
            RUN_ID,
            99,
            case_id,
            EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE,
        )

    assert _database_state(database, case_id) == committed


def test_failure_recording_rejects_open_text_and_isolated_same_case_ids_by_run(
    tmp_path: Path,
) -> None:
    database, repository, case_id = _setup_case(tmp_path)
    before = _database_state(database, case_id)
    with pytest.raises(TypeError, match="EvidenceFailureCode"):
        repository.record_evidence_failure(
            RUN_ID,
            1,
            case_id,
            "C:\\private\\exception.txt",  # type: ignore[arg-type]
        )
    assert _database_state(database, case_id) == before

    repository.register_run("run-02", _manifest())
    second = repository.create_or_get_case("run-02", _event())
    assert second.case.case_id == case_id
    repository.record_evidence_failure(
        RUN_ID,
        1,
        case_id,
        EvidenceFailureCode.EVIDENCE_MISSING,
    )

    assert repository.load_case(RUN_ID, case_id).case.status == CaseStatus.HUMAN_REVIEW
    assert repository.load_case("run-02", case_id).case.status == CaseStatus.CANDIDATE


def test_concurrent_same_failure_coalesces_and_different_failure_has_one_winner(
    tmp_path: Path,
) -> None:
    database, _, case_id = _setup_case(tmp_path)
    repositories = tuple(
        SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS, clock=_clock) for _ in range(2)
    )

    def record_same(index: int) -> int:
        return (
            repositories[index]
            .record_evidence_failure(
                RUN_ID,
                1,
                case_id,
                EvidenceFailureCode.PATH_SECURITY_FAILURE,
            )
            .revision
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert tuple(executor.map(record_same, range(2))) == (2, 2)
    assert _database_state(database, case_id)["audits"] == 2

    second_workspace = tmp_path / "different"
    second_workspace.mkdir()
    second_database = second_workspace / "labcourt.sqlite3"
    MigrationRunner(second_database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    setup = SQLiteEvidenceRepository(second_database, BUSY_TIMEOUT_MS, clock=_clock)
    setup.register_run(RUN_ID, _manifest())
    second_case_id = setup.create_or_get_case(RUN_ID, _event()).case.case_id
    competitors = tuple(
        SQLiteEvidenceRepository(second_database, BUSY_TIMEOUT_MS, clock=_clock) for _ in range(2)
    )
    codes = (
        EvidenceFailureCode.EVIDENCE_MISSING,
        EvidenceFailureCode.EVIDENCE_BUDGET_EXCEEDED,
    )

    def record_different(index: int) -> str:
        try:
            competitors[index].record_evidence_failure(
                RUN_ID,
                1,
                second_case_id,
                codes[index],
            )
        except ConcurrentModification:
            return "conflict"
        return "recorded"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(record_different, range(2)))
    assert sorted(outcomes) == ["conflict", "recorded"]
    assert _database_state(second_database, second_case_id)["audits"] == 2


@pytest.mark.parametrize(
    "fault_phase",
    [
        "record_evidence_failure.after_audit",
        "record_evidence_failure.after_case_version",
        "record_evidence_failure.after_case_update",
        "record_evidence_failure.before_commit",
    ],
)
def test_record_evidence_failure_faults_roll_back_case_version_audit_and_heads(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    database, inspector, case_id = _setup_case(tmp_path)
    before = _database_state(database, case_id)

    def fail_at(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("injected evidence failure write fault")

    repository = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        fault_injector=fail_at,
    )
    with pytest.raises(RuntimeError, match="injected evidence failure"):
        repository.record_evidence_failure(
            RUN_ID,
            1,
            case_id,
            EvidenceFailureCode.CREATION_CLOSURE_FAILED,
        )

    assert _database_state(database, case_id) == before
    snapshot = inspector.load_case(RUN_ID, case_id)
    assert snapshot.revision == 1
    assert snapshot.case.status == CaseStatus.CANDIDATE
    assert snapshot.case.timeline == ()
    assert validate_audit_chain(
        inspector.list_audit_entries(RUN_ID),
        expected_run_id=RUN_ID,
        expected_manifest_id=inspector.get_audit_head(RUN_ID).manifest_id,
        expected_head_sequence=inspector.get_audit_head(RUN_ID).sequence,
        expected_head_hash=inspector.get_audit_head(RUN_ID).entry_hash,
    ).passed


def test_creation_closure_raises_machine_readable_defect_codes(tmp_path: Path) -> None:
    _, repository, case_id = _setup_case(tmp_path)
    event = _event()
    draft = EvidencePackDraft(
        run_id=RUN_ID,
        case_id=derive_case_id(event.event_id),
        version=1,
        complete=False,
        event=event,
        key_frame_ids=("cam-01:demo-ntsc:90",),
        objective_facts=event.objective_facts,
        track_summary=TrackSummary(
            primary_track_ref=event.primary_track_ref,
            start_frame=event.start_frame,
            end_frame_exclusive=event.end_frame_exclusive,
            observed_frame_count=event.end_frame_exclusive - event.start_frame,
        ),
        confirmation_record=event.confirmation,
        manifest_id=event.manifest_id,
    )

    with pytest.raises(CreationClosureFailed) as raised:
        repository.publish_pack(RUN_ID, 1, draft)

    assert raised.value.defect_codes == (ClosureDefectCode.OBJECTIVE_SOURCE_MISSING,)
    assert repository.load_case(RUN_ID, case_id).revision == 1
    assert len(repository.list_audit_entries(RUN_ID)) == 1

from __future__ import annotations

import hashlib
import json
import sqlite3
import traceback
from collections.abc import Callable
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_m6_upgrade_candidate_run_cut import (
    SQLiteM6UpgradeCandidateRunCutRepository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v2 import (
    SQLiteM6UpgradeExecutionLedgerV2Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v3 import (
    SQLiteM6UpgradeExecutionLedgerV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_observation_v3 import (
    SQLiteM6UpgradeExecutionObservationV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_pending_sample_commitment_v3 import (
    SQLiteM6UpgradePendingSampleCommitmentV3Repository,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationReport
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeExecutionScopeAuthority,
)
from labcourt.ports.m6_upgrade_candidate_run_cut import (
    M6UpgradeCandidateRunCutError,
    M6UpgradeCandidateRunCutFailureCode,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Status,
)
from tests.integration.test_m6_upgrade_candidate_run_cut_migration import (
    _run_cut_for_seal,
)
from tests.integration.test_m6_upgrade_execution_ledger_v2_repository import (
    BUSY_TIMEOUT_MS,
    MutableExactSampleArtifactVerifier,
)
from tests.integration.test_m6_upgrade_execution_ledger_v2_repository import (
    _pipeline as _v2_pipeline,
)
from tests.integration.test_m6_upgrade_execution_ledger_v3_repository import (
    _v3_pipeline,
)


class _FixedValidationReportProvider:
    def __init__(
        self,
        report: M5ArtifactValidationReport,
        *,
        fail_if_called: bool = False,
    ) -> None:
        self.report = report
        self.fail_if_called = fail_if_called
        self.calls: list[tuple[str, int, str]] = []

    def load_m6_upgrade_candidate_validation_report(
        self,
        candidate_run_id: str,
        audit_head_sequence: int,
        audit_head_hash: str,
    ) -> M5ArtifactValidationReport:
        self.calls.append((candidate_run_id, audit_head_sequence, audit_head_hash))
        if self.fail_if_called:
            raise AssertionError("durable run-cut replay called the report provider")
        return self.report


def _prepare_v3_state(
    database: Path,
    status: M6UpgradeExecutionLedgerV3Status,
) -> tuple[M6UpgradeExecutionScopeAuthority, M6UpgradeExecutionLedgerSealV2 | None]:
    scope, observations, records, commitments = _v3_pipeline()
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=MutableExactSampleArtifactVerifier(records),
    )
    observation_repository = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    commitment_repository = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    ledger.begin_execution(scope)

    if status == M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT:
        observation_repository.append(observations[0])
    elif status == M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND:
        observation_repository.append(observations[0])
        commitment_repository.append(commitments[0])
    elif status in {
        M6UpgradeExecutionLedgerV3Status.READY_TO_SEAL,
        M6UpgradeExecutionLedgerV3Status.SEALED,
    }:
        for observation, commitment in zip(observations, commitments, strict=True):
            observation_repository.append(observation)
            commitment_repository.append(commitment)
            ledger.append_committed_sample(commitment)
    elif status != M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION:
        raise AssertionError(f"unsupported V3 fixture status: {status.value}")

    seal = None
    if status == M6UpgradeExecutionLedgerV3Status.SEALED:
        seal = ledger.seal(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    resumed = ledger.resume(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    assert resumed.status == status
    assert resumed.seal == seal
    return scope, seal


def _sealed_runtime(
    database: Path,
) -> tuple[
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeExecutionLedgerSealV2,
    M5ArtifactValidationReport,
]:
    scope, seal = _prepare_v3_state(database, M6UpgradeExecutionLedgerV3Status.SEALED)
    assert seal is not None
    report = _run_cut_for_seal(scope, seal).validation_report
    assert report.passed
    assert report.counts.case_roots == seal.candidate_case_count
    predecessor = report.predecessor_report
    assert type(predecessor) is M4ArtifactValidationReport
    assert predecessor.m3_report.m2_report.audit_head_sequence == (seal.source_audit_head_sequence)
    assert predecessor.m3_report.m2_report.audit_head_hash == seal.source_audit_head_hash
    return scope, seal, report


def _repository(
    database: Path,
    provider: _FixedValidationReportProvider,
    *,
    fault_injector: Callable[[str], None] | None = None,
) -> SQLiteM6UpgradeCandidateRunCutRepository:
    return SQLiteM6UpgradeCandidateRunCutRepository(
        database,
        BUSY_TIMEOUT_MS,
        validation_report_provider=provider,
        fault_injector=fault_injector,
    )


def _assert_failure(
    expected: M6UpgradeCandidateRunCutFailureCode,
    repository: SQLiteM6UpgradeCandidateRunCutRepository,
    scope: M6UpgradeExecutionScopeAuthority,
) -> M6UpgradeCandidateRunCutError:
    with pytest.raises(M6UpgradeCandidateRunCutError) as raised:
        repository.build_or_load(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert raised.value.reason_code == expected
    return raised.value


def _canonical_report(
    report: M5ArtifactValidationReport,
    *,
    audit_head_sequence: int | None = None,
    audit_head_hash: str | None = None,
    case_roots: int | None = None,
) -> M5ArtifactValidationReport:
    predecessor = report.predecessor_report
    assert type(predecessor) is M4ArtifactValidationReport
    m3_report = predecessor.m3_report
    m2_report = m3_report.m2_report.model_copy(
        update={
            **(
                {"audit_head_sequence": audit_head_sequence}
                if audit_head_sequence is not None
                else {}
            ),
            **({"audit_head_hash": audit_head_hash} if audit_head_hash is not None else {}),
        }
    )
    changed_m3 = m3_report.model_copy(update={"m2_report": m2_report})
    changed_m4 = predecessor.model_copy(update={"m3_report": changed_m3})
    counts = report.counts.model_copy(
        update=({"case_roots": case_roots} if case_roots is not None else {})
    )
    changed = report.model_copy(update={"predecessor_report": changed_m4, "counts": counts})
    return M5ArtifactValidationReport.model_validate(
        changed.model_dump(mode="json", exclude_computed_fields=True)
    )


def _run_cut_count(database: Path) -> int:
    with sqlite3.connect(database) as connection:
        row = connection.execute("SELECT COUNT(*) FROM m6_upgrade_candidate_run_cuts").fetchone()
    assert row is not None
    return int(row[0])


def test_first_build_persists_and_every_exact_retry_avoids_report_provider(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, seal, report = _sealed_runtime(database)
    provider = _FixedValidationReportProvider(report)
    repository = _repository(database, provider)

    first = repository.build_or_load(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    retry = repository.build_or_load(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )

    assert first == retry == _run_cut_for_seal(scope, seal)
    assert provider.calls == [
        (
            scope.candidate_run_id,
            seal.source_audit_head_sequence,
            seal.source_audit_head_hash,
        )
    ]
    assert _run_cut_count(database) == 1
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT ledger_seal_authority_id, candidate_run_cut_authority_id,
                   run_cut_json, document_sha256, size_bytes
            FROM m6_upgrade_candidate_run_cuts
            """
        ).fetchone()
    assert row is not None
    expected_document = canonical_json(first.model_dump(mode="json"))
    assert row == (
        seal.ledger_seal_authority_id,
        first.candidate_run_cut_authority_id,
        expected_document,
        hashlib.sha256(expected_document.encode("utf-8")).hexdigest(),
        len(expected_document.encode("utf-8")),
    )

    forbidden = _FixedValidationReportProvider(report, fail_if_called=True)
    rebuilt = _repository(database, forbidden)
    assert (
        rebuilt.build_or_load(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
        == first
    )
    assert forbidden.calls == []


@pytest.mark.parametrize(
    "status",
    (
        M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION,
        M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT,
        M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND,
        M6UpgradeExecutionLedgerV3Status.READY_TO_SEAL,
    ),
)
def test_every_unsealed_v3_state_rejects_before_report_provider(
    tmp_path: Path,
    status: M6UpgradeExecutionLedgerV3Status,
) -> None:
    database = tmp_path / status.value / "labcourt.sqlite3"
    database.parent.mkdir()
    scope, seal = _prepare_v3_state(database, status)
    assert seal is None
    report = _run_cut_for_seal(
        scope,
        _v3_pipeline_seal_template(),
    ).validation_report
    provider = _FixedValidationReportProvider(report, fail_if_called=True)

    _assert_failure(
        M6UpgradeCandidateRunCutFailureCode.LEDGER_NOT_SEALED,
        _repository(database, provider),
        scope,
    )
    assert provider.calls == []
    assert _run_cut_count(database) == 0


def _v3_pipeline_seal_template() -> M6UpgradeExecutionLedgerSealV2:
    """Return a canonical report-shaping seal without touching the test database."""

    from tests.contract.test_m6_upgrade_observation_backed_inventory_contracts import (
        _v3_inventory,
    )

    return _v3_inventory().execution_ledger


def test_legacy_ledger_protocol_is_rejected_before_report_provider(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _observations, records, _commitments = _v2_pipeline()
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    SQLiteM6UpgradeExecutionLedgerV2Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=MutableExactSampleArtifactVerifier(records),
    ).begin_execution(scope)
    provider = _FixedValidationReportProvider(
        _v3_pipeline_seal_template_report(),
        fail_if_called=True,
    )

    _assert_failure(
        M6UpgradeCandidateRunCutFailureCode.LEDGER_VERSION_UNSUPPORTED,
        _repository(database, provider),
        scope,
    )
    assert provider.calls == []


def _v3_pipeline_seal_template_report() -> M5ArtifactValidationReport:
    template = _v3_pipeline_seal_template()
    return _run_cut_for_seal(template.execution_scope, template).validation_report


@pytest.mark.parametrize(
    ("drift", "expected"),
    (
        ("audit_head", M6UpgradeCandidateRunCutFailureCode.AUDIT_HEAD_MISMATCH),
        ("case_roots", M6UpgradeCandidateRunCutFailureCode.VALIDATION_REPORT_REJECTED),
    ),
)
def test_validation_report_head_and_case_count_drift_are_rejected_without_insert(
    tmp_path: Path,
    drift: str,
    expected: M6UpgradeCandidateRunCutFailureCode,
) -> None:
    database = tmp_path / drift / "labcourt.sqlite3"
    database.parent.mkdir()
    scope, seal, report = _sealed_runtime(database)
    rejected = (
        _canonical_report(
            report,
            audit_head_sequence=seal.source_audit_head_sequence + 1,
            audit_head_hash="f" * 64,
        )
        if drift == "audit_head"
        else _canonical_report(report, case_roots=seal.candidate_case_count + 1)
    )
    provider = _FixedValidationReportProvider(rejected)

    _assert_failure(expected, _repository(database, provider), scope)
    assert len(provider.calls) == 1
    assert _run_cut_count(database) == 0


def test_after_insert_fault_rolls_back_and_is_retryable(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, seal, report = _sealed_runtime(database)
    provider = _FixedValidationReportProvider(report)
    armed = True
    phases: list[str] = []

    def inject(phase: str) -> None:
        nonlocal armed
        phases.append(phase)
        if armed and phase == "m6_upgrade_candidate_run_cut.after_insert":
            raise RuntimeError("injected run-cut insert fault")

    repository = _repository(database, provider, fault_injector=inject)
    _assert_failure(
        M6UpgradeCandidateRunCutFailureCode.STORAGE_REJECTED,
        repository,
        scope,
    )
    assert _run_cut_count(database) == 0
    assert phases.count("m6_upgrade_candidate_run_cut.after_insert") == 1

    armed = False
    assert repository.build_or_load(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    ) == _run_cut_for_seal(scope, seal)
    assert _run_cut_count(database) == 1
    assert len(provider.calls) == 2


@pytest.mark.parametrize("tamper", ("body", "projection"))
def test_stored_body_and_projection_tampering_fail_closed_before_provider(
    tmp_path: Path,
    tamper: str,
) -> None:
    database = tmp_path / tamper / "labcourt.sqlite3"
    database.parent.mkdir()
    scope, _seal, report = _sealed_runtime(database)
    repository = _repository(database, _FixedValidationReportProvider(report))
    repository.build_or_load(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )

    with sqlite3.connect(database) as connection:
        trigger_row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm6_upgrade_candidate_run_cuts_no_update'
            """
        ).fetchone()
        assert trigger_row is not None and isinstance(trigger_row[0], str)
        no_update_trigger_sql = trigger_row[0]
        connection.execute("DROP TRIGGER m6_upgrade_candidate_run_cuts_no_update")
        if tamper == "projection":
            connection.execute(
                """
                UPDATE m6_upgrade_candidate_run_cuts
                SET validation_report_content_sha256 = ?
                """,
                ("f" * 64,),
            )
        else:
            row = connection.execute(
                "SELECT run_cut_json FROM m6_upgrade_candidate_run_cuts"
            ).fetchone()
            assert row is not None and isinstance(row[0], str)
            payload = json.loads(row[0])
            payload["validation_report"]["authority_root_sha256"] = "e" * 64
            raw = canonical_json(payload)
            connection.execute(
                """
                UPDATE m6_upgrade_candidate_run_cuts
                SET run_cut_json = ?, document_sha256 = ?, size_bytes = ?
                """,
                (
                    raw,
                    hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                    len(raw.encode("utf-8")),
                ),
            )
        connection.execute(no_update_trigger_sql)
        connection.commit()

    forbidden = _FixedValidationReportProvider(report, fail_if_called=True)
    _assert_failure(
        M6UpgradeCandidateRunCutFailureCode.STORED_AUTHORITY_INVALID,
        _repository(database, forbidden),
        scope,
    )
    assert forbidden.calls == []


def test_public_failure_is_payload_free(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _scope, _seal, report = _sealed_runtime(database)
    repository = _repository(database, _FixedValidationReportProvider(report))
    forbidden = "unsafe candidate run id"

    with pytest.raises(M6UpgradeCandidateRunCutError) as raised:
        repository.build_or_load(forbidden, "f" * 64)

    error = raised.value
    assert error.reason_code == M6UpgradeCandidateRunCutFailureCode.INVALID_ARGUMENT
    assert error.args == ("M6 upgrade candidate run cut failed: INVALID_ARGUMENT",)
    assert vars(error) == {"reason_code": error.reason_code}
    assert error.__cause__ is None
    assert error.__context__ is None
    assert forbidden not in "".join(traceback.format_exception(error))
    frames = []
    current = error.__traceback__
    while current is not None:
        if current.tb_frame.f_code.co_filename.endswith("sqlite_m6_upgrade_candidate_run_cut.py"):
            frames.append(current.tb_frame)
        current = current.tb_next
    assert frames
    assert all("self" not in frame.f_locals for frame in frames)

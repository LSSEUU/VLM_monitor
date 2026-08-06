from __future__ import annotations

from dataclasses import dataclass, replace
from typing import cast

import pytest

from labcourt.application import EvidenceIntegrityMonitor as ExportedEvidenceIntegrityMonitor
from labcourt.application.evidence import EvidenceBuilder
from labcourt.application.integrity import (
    EvidenceIntegrityMonitor,
    evidence_failure_code_for_closure,
)
from labcourt.contracts.enums import ArtifactKind, ClosureDefectCode, EvidenceFailureCode
from labcourt.contracts.storage import ArtifactRef, ClosureDefect, ClosureReport
from labcourt.exceptions import ConcurrentModification, ContractViolation, CreationClosureFailed
from labcourt.ports.evidence_repository import EvidenceRepository

RUN_ID = "integrity-run"
CASE_ID = "018f2c10-7995-7f5a-9d08-369b89f86a10"
PACK_ID = "1" * 64
MANIFEST_ID = "2" * 64
INPUT_SHA256 = "3" * 64
CROP_ID = "4" * 64


@dataclass(frozen=True)
class _LoadedPack:
    run_id: str = RUN_ID
    case_id: str = CASE_ID
    pack_id: str = PACK_ID
    version: int = 1
    manifest_id: str = MANIFEST_ID
    closure_input_sha256: str = INPUT_SHA256

    def expected_closure_refs(self) -> tuple[ArtifactRef, ...]:
        return ()


@dataclass(frozen=True)
class _CaseValue:
    run_id: str = RUN_ID
    case_id: str = CASE_ID
    manifest_id: str = MANIFEST_ID
    evidence_packs: tuple[_LoadedPack, ...] = (_LoadedPack(),)


@dataclass(frozen=True)
class _LoadedCase:
    case: _CaseValue = _CaseValue()
    revision: int = 7


class _RepositorySpy:
    def __init__(
        self,
        report: ClosureReport,
        *,
        pack: _LoadedPack | None = None,
        case_snapshot: _LoadedCase | None = None,
        record_error: Exception | None = None,
    ) -> None:
        self.report = report
        self.pack = pack or _LoadedPack()
        self.case_snapshot = case_snapshot or _LoadedCase(
            case=_CaseValue(evidence_packs=(self.pack,))
        )
        self.record_error = record_error
        self.calls: list[tuple[object, ...]] = []

    def load_pack(self, run_id: str, pack_id: str) -> _LoadedPack:
        self.calls.append(("load_pack", run_id, pack_id))
        return self.pack

    def load_case(self, run_id: str, case_id: str) -> _LoadedCase:
        self.calls.append(("load_case", run_id, case_id))
        return self.case_snapshot

    def verify_current_pack(self, run_id: str, pack_id: str) -> ClosureReport:
        self.calls.append(("verify_current_pack", run_id, pack_id))
        return self.report

    def record_evidence_failure(
        self,
        run_id: str,
        expected_revision: int,
        case_id: str,
        failure_code: EvidenceFailureCode,
    ) -> _LoadedCase:
        self.calls.append(
            (
                "record_evidence_failure",
                run_id,
                expected_revision,
                case_id,
                failure_code,
            )
        )
        if self.record_error is not None:
            raise self.record_error
        return _LoadedCase(revision=expected_revision + 1)


def _report(*defects: ClosureDefect) -> ClosureReport:
    root = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=PACK_ID)
    return ClosureReport(
        run_id=RUN_ID,
        root_ref=root,
        manifest_id=MANIFEST_ID,
        input_sha256=INPUT_SHA256,
        checked_refs=(root,),
        defects=tuple(sorted(defects, key=lambda defect: defect.sort_key)),
    )


def _pixel_hash_defect() -> ClosureDefect:
    return ClosureDefect(
        code=ClosureDefectCode.PIXEL_HASH_MISMATCH,
        artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=CROP_ID),
        expected_sha256="5" * 64,
        actual_sha256="6" * 64,
    )


def _retention_defect() -> ClosureDefect:
    return ClosureDefect(
        code=ClosureDefectCode.MEDIA_PURGED_BY_RETENTION,
        artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=CROP_ID),
        reason_code="PURGED_BY_RETENTION",
    )


def _monitor(repository: _RepositorySpy) -> EvidenceIntegrityMonitor:
    return EvidenceIntegrityMonitor(cast(EvidenceRepository, repository))


def test_integrity_monitor_is_exported_from_application_package() -> None:
    assert ExportedEvidenceIntegrityMonitor is EvidenceIntegrityMonitor


def test_passed_current_closure_is_returned_without_state_transition() -> None:
    report = _report()
    repository = _RepositorySpy(report)

    result = _monitor(repository).verify_and_escalate(RUN_ID, PACK_ID)

    assert result is report
    assert repository.calls == [
        ("load_pack", RUN_ID, PACK_ID),
        ("load_case", RUN_ID, CASE_ID),
        ("verify_current_pack", RUN_ID, PACK_ID),
    ]


def test_failed_current_closure_is_mapped_and_delegated_to_atomic_repository_api() -> None:
    report = _report(_pixel_hash_defect())
    repository = _RepositorySpy(report)

    result = _monitor(repository).verify_and_escalate(RUN_ID, PACK_ID)

    assert result is report
    assert repository.calls == [
        ("load_pack", RUN_ID, PACK_ID),
        ("load_case", RUN_ID, CASE_ID),
        ("verify_current_pack", RUN_ID, PACK_ID),
        (
            "record_evidence_failure",
            RUN_ID,
            7,
            CASE_ID,
            EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE,
        ),
    ]


def test_retention_only_current_closure_is_returned_without_case_escalation() -> None:
    report = _report(_retention_defect())
    repository = _RepositorySpy(report)

    result = _monitor(repository).verify_and_escalate(RUN_ID, PACK_ID)

    assert result is report
    assert repository.calls == [
        ("load_pack", RUN_ID, PACK_ID),
        ("load_case", RUN_ID, CASE_ID),
        ("verify_current_pack", RUN_ID, PACK_ID),
    ]


def test_retention_and_abnormal_defects_escalate_using_only_abnormal_codes() -> None:
    report = _report(_retention_defect(), _pixel_hash_defect())
    repository = _RepositorySpy(report)

    result = _monitor(repository).verify_and_escalate(RUN_ID, PACK_ID)

    assert result is report
    assert repository.calls[-1] == (
        "record_evidence_failure",
        RUN_ID,
        7,
        CASE_ID,
        EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE,
    )


def test_integrity_monitor_propagates_repository_concurrency_failure() -> None:
    repository = _RepositorySpy(
        _report(_pixel_hash_defect()),
        record_error=ConcurrentModification("case changed"),
    )

    with pytest.raises(ConcurrentModification, match="case changed"):
        _monitor(repository).verify_and_escalate(RUN_ID, PACK_ID)

    assert repository.calls[-1] == (
        "record_evidence_failure",
        RUN_ID,
        7,
        CASE_ID,
        EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE,
    )


@pytest.mark.parametrize(
    ("defect_codes", "expected"),
    [
        (
            (ClosureDefectCode.PRIVACY_POLICY_VIOLATION,),
            EvidenceFailureCode.PRIVACY_POLICY_UNSATISFIED,
        ),
        (
            (ClosureDefectCode.PATH_BOUNDARY_VIOLATION,),
            EvidenceFailureCode.PATH_SECURITY_FAILURE,
        ),
        ((ClosureDefectCode.UNSAFE_LINK,), EvidenceFailureCode.PATH_SECURITY_FAILURE),
        ((ClosureDefectCode.NOT_REGULAR_FILE,), EvidenceFailureCode.PATH_SECURITY_FAILURE),
        (
            (ClosureDefectCode.SOURCE_HASH_MISMATCH,),
            EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE,
        ),
        (
            (ClosureDefectCode.MEDIA_HASH_MISMATCH,),
            EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE,
        ),
        (
            (ClosureDefectCode.MEDIA_SIZE_MISMATCH,),
            EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE,
        ),
        (
            (ClosureDefectCode.PIXEL_HASH_MISMATCH,),
            EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE,
        ),
        (
            (ClosureDefectCode.MEDIA_DIMENSION_MISMATCH,),
            EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE,
        ),
        (
            (ClosureDefectCode.IDENTITY_MISMATCH,),
            EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE,
        ),
        (
            (ClosureDefectCode.MEDIA_MISSING,),
            EvidenceFailureCode.CREATION_CLOSURE_FAILED,
        ),
        (
            (
                ClosureDefectCode.MEDIA_HASH_MISMATCH,
                ClosureDefectCode.PATH_BOUNDARY_VIOLATION,
            ),
            EvidenceFailureCode.PATH_SECURITY_FAILURE,
        ),
        (
            (
                ClosureDefectCode.PATH_BOUNDARY_VIOLATION,
                ClosureDefectCode.PRIVACY_POLICY_VIOLATION,
            ),
            EvidenceFailureCode.PRIVACY_POLICY_UNSATISFIED,
        ),
    ],
)
def test_typed_closure_mapping_is_shared_with_evidence_builder(
    defect_codes: tuple[ClosureDefectCode, ...],
    expected: EvidenceFailureCode,
) -> None:
    assert evidence_failure_code_for_closure(defect_codes) == expected
    assert EvidenceBuilder._failure_code(CreationClosureFailed(defect_codes)) == expected


def test_closure_mapping_rejects_passed_or_open_text_input() -> None:
    with pytest.raises(ValueError, match="at least one"):
        evidence_failure_code_for_closure(())
    with pytest.raises(TypeError, match="ClosureDefectCode"):
        evidence_failure_code_for_closure(("C:\\private\\image.png",))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="retention-only"):
        evidence_failure_code_for_closure((ClosureDefectCode.MEDIA_PURGED_BY_RETENTION,))


def test_closure_mapping_ignores_retention_when_abnormal_defects_are_present() -> None:
    assert (
        evidence_failure_code_for_closure(
            (
                ClosureDefectCode.MEDIA_PURGED_BY_RETENTION,
                ClosureDefectCode.PIXEL_HASH_MISMATCH,
            )
        )
        == EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE
    )


def test_integrity_monitor_rejects_out_of_scope_pack_before_loading_case() -> None:
    repository = _RepositorySpy(
        _report(),
        pack=replace(_LoadedPack(), run_id="another-run"),
    )

    with pytest.raises(ContractViolation, match="out-of-scope evidence pack"):
        _monitor(repository).verify_and_escalate(RUN_ID, PACK_ID)

    assert repository.calls == [("load_pack", RUN_ID, PACK_ID)]


@pytest.mark.parametrize(
    "case",
    [
        replace(_CaseValue(), run_id="another-run"),
        replace(_CaseValue(), case_id="018f2c10-7995-7f5a-9d08-369b89f86a11"),
        replace(_CaseValue(), manifest_id="9" * 64),
        replace(_CaseValue(), evidence_packs=()),
    ],
)
def test_integrity_monitor_rejects_out_of_scope_case_before_verification(
    case: _CaseValue,
) -> None:
    repository = _RepositorySpy(
        _report(),
        case_snapshot=_LoadedCase(case=case),
    )

    with pytest.raises(ContractViolation, match="out-of-scope case snapshot"):
        _monitor(repository).verify_and_escalate(RUN_ID, PACK_ID)

    assert repository.calls == [
        ("load_pack", RUN_ID, PACK_ID),
        ("load_case", RUN_ID, CASE_ID),
    ]


@pytest.mark.parametrize(
    "report",
    [
        _report().model_copy(update={"run_id": "another-run"}),
        _report().model_copy(
            update={
                "root_ref": ArtifactRef(
                    kind=ArtifactKind.EVIDENCE_PACK,
                    artifact_id="9" * 64,
                ),
                "checked_refs": (
                    ArtifactRef(
                        kind=ArtifactKind.EVIDENCE_PACK,
                        artifact_id="9" * 64,
                    ),
                ),
            }
        ),
        _report().model_copy(update={"manifest_id": "9" * 64}),
        _report().model_copy(update={"input_sha256": "9" * 64}),
        _report().model_copy(
            update={
                "checked_refs": (
                    ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=PACK_ID),
                    ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id="9" * 64),
                )
            }
        ),
    ],
)
def test_integrity_monitor_rejects_out_of_scope_report_without_mutation(
    report: ClosureReport,
) -> None:
    repository = _RepositorySpy(report)

    with pytest.raises(ContractViolation, match="out-of-scope closure report"):
        _monitor(repository).verify_and_escalate(RUN_ID, PACK_ID)

    assert repository.calls == [
        ("load_pack", RUN_ID, PACK_ID),
        ("load_case", RUN_ID, CASE_ID),
        ("verify_current_pack", RUN_ID, PACK_ID),
    ]

"""Current evidence-closure verification and controlled escalation."""

from __future__ import annotations

from collections.abc import Iterable

from labcourt.contracts.enums import ArtifactKind, ClosureDefectCode, EvidenceFailureCode
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.exceptions import ContractViolation
from labcourt.ports.evidence_repository import CaseSnapshot, EvidenceRepository

_MEDIA_INTEGRITY_DEFECTS = frozenset(
    {
        ClosureDefectCode.SOURCE_HASH_MISMATCH,
        ClosureDefectCode.MEDIA_HASH_MISMATCH,
        ClosureDefectCode.MEDIA_SIZE_MISMATCH,
        ClosureDefectCode.PIXEL_HASH_MISMATCH,
        ClosureDefectCode.MEDIA_DIMENSION_MISMATCH,
        ClosureDefectCode.IDENTITY_MISMATCH,
    }
)
_PATH_SECURITY_DEFECTS = frozenset(
    {
        ClosureDefectCode.PATH_BOUNDARY_VIOLATION,
        ClosureDefectCode.UNSAFE_LINK,
        ClosureDefectCode.NOT_REGULAR_FILE,
    }
)
_EXPECTED_RETENTION_DEFECTS = frozenset({ClosureDefectCode.MEDIA_PURGED_BY_RETENTION})


def evidence_failure_code_for_closure(
    defect_codes: Iterable[ClosureDefectCode],
) -> EvidenceFailureCode:
    """Map one or more typed closure defects to a controlled failure category."""

    defects = tuple(defect_codes)
    if not defects:
        raise ValueError("closure failure mapping requires at least one defect code")
    if any(not isinstance(code, ClosureDefectCode) for code in defects):
        raise TypeError("closure defect codes must contain ClosureDefectCode values")
    defect_set = frozenset(defects).difference(_EXPECTED_RETENTION_DEFECTS)
    if not defect_set:
        raise ValueError("retention-only closure defects are not evidence failures")
    if ClosureDefectCode.PRIVACY_POLICY_VIOLATION in defect_set:
        return EvidenceFailureCode.PRIVACY_POLICY_UNSATISFIED
    if defect_set.intersection(_PATH_SECURITY_DEFECTS):
        return EvidenceFailureCode.PATH_SECURITY_FAILURE
    if defect_set.intersection(_MEDIA_INTEGRITY_DEFECTS):
        return EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE
    return EvidenceFailureCode.CREATION_CLOSURE_FAILED


class EvidenceIntegrityMonitor:
    """Verify a published pack before use and escalate controlled defects."""

    __slots__ = ("_repository",)

    def __init__(self, repository: EvidenceRepository) -> None:
        self._repository = repository

    def verify_and_escalate(self, run_id: str, pack_id: str) -> ClosureReport:
        """Return current closure, atomically escalating a failed report's case."""

        pack = self._repository.load_pack(run_id, pack_id)
        self._require_pack_scope(pack, run_id, pack_id)
        case_snapshot = self._repository.load_case(run_id, pack.case_id)
        self._require_case_scope(case_snapshot, pack, run_id)
        report = self._repository.verify_current_pack(run_id, pack_id)
        self._require_report_scope(report, pack, run_id, pack_id)
        if report.passed:
            return report
        actionable_defects = tuple(
            defect.code
            for defect in report.defects
            if defect.code not in _EXPECTED_RETENTION_DEFECTS
        )
        if not actionable_defects:
            return report
        self._repository.record_evidence_failure(
            run_id,
            case_snapshot.revision,
            pack.case_id,
            evidence_failure_code_for_closure(actionable_defects),
        )
        return report

    @staticmethod
    def _require_pack_scope(pack: EvidencePack, run_id: str, pack_id: str) -> None:
        try:
            matches = pack.run_id == run_id and pack.pack_id == pack_id
        except (AttributeError, TypeError, ValueError):
            raise ContractViolation(
                "integrity repository returned an invalid evidence pack"
            ) from None
        if not matches:
            raise ContractViolation("integrity repository returned an out-of-scope evidence pack")

    @staticmethod
    def _require_case_scope(
        snapshot: CaseSnapshot,
        pack: EvidencePack,
        run_id: str,
    ) -> None:
        try:
            case = snapshot.case
            revision = snapshot.revision
            matching_packs = tuple(
                candidate
                for candidate in case.evidence_packs
                if candidate.pack_id == pack.pack_id and candidate.version == pack.version
            )
            matches = (
                isinstance(revision, int)
                and not isinstance(revision, bool)
                and revision >= 1
                and case.run_id == run_id
                and case.case_id == pack.case_id
                and case.manifest_id == pack.manifest_id
                and matching_packs == (pack,)
            )
        except (AttributeError, TypeError, ValueError):
            raise ContractViolation(
                "integrity repository returned an invalid case snapshot"
            ) from None
        if not matches:
            raise ContractViolation("integrity repository returned an out-of-scope case snapshot")

    @staticmethod
    def _require_report_scope(
        report: ClosureReport,
        pack: EvidencePack,
        run_id: str,
        pack_id: str,
    ) -> None:
        if not isinstance(report, ClosureReport):
            raise ContractViolation("integrity repository returned an invalid closure report")
        try:
            root_ref = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=pack_id)
            expected_refs = {ref.sort_key: ref for ref in pack.expected_closure_refs()}
            expected_refs[root_ref.sort_key] = root_ref
            matches = (
                report.run_id == run_id
                and report.root_ref == root_ref
                and report.manifest_id == pack.manifest_id
                and report.input_sha256 == pack.closure_input_sha256
                and report.checked_refs
                == tuple(expected_refs[key] for key in sorted(expected_refs))
            )
        except (AttributeError, TypeError, ValueError):
            raise ContractViolation(
                "integrity repository returned an invalid closure report"
            ) from None
        if not matches:
            raise ContractViolation("integrity repository returned an out-of-scope closure report")


__all__ = ["EvidenceIntegrityMonitor", "evidence_failure_code_for_closure"]

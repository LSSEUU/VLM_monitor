import pytest

from labcourt.contracts.enums import ClosureDefectCode, EvidenceFailureCode
from labcourt.exceptions import CreationClosureFailed, EvidenceMissing


def test_evidence_failure_codes_are_closed_and_stable() -> None:
    assert tuple(EvidenceFailureCode) == (
        EvidenceFailureCode.EVIDENCE_MISSING,
        EvidenceFailureCode.CREATION_CLOSURE_FAILED,
        EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE,
        EvidenceFailureCode.PRIVACY_POLICY_UNSATISFIED,
        EvidenceFailureCode.PATH_SECURITY_FAILURE,
        EvidenceFailureCode.EVIDENCE_BUDGET_EXCEEDED,
    )


def test_creation_closure_failure_exposes_only_controlled_unique_defect_codes() -> None:
    failure = CreationClosureFailed(
        (
            ClosureDefectCode.MEDIA_MISSING,
            ClosureDefectCode.MEDIA_HASH_MISMATCH,
            ClosureDefectCode.MEDIA_MISSING,
        )
    )

    assert isinstance(failure, EvidenceMissing)
    assert failure.defect_codes == (
        ClosureDefectCode.MEDIA_HASH_MISMATCH,
        ClosureDefectCode.MEDIA_MISSING,
    )
    assert str(failure) == "creation closure failed: MEDIA_HASH_MISMATCH, MEDIA_MISSING"


def test_creation_closure_failure_rejects_empty_or_open_text_codes() -> None:
    with pytest.raises(ValueError, match="at least one"):
        CreationClosureFailed(())
    with pytest.raises(TypeError, match="ClosureDefectCode"):
        CreationClosureFailed(("C:\\secret\\frame.png",))  # type: ignore[arg-type]

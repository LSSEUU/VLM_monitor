from __future__ import annotations

import pytest
from pydantic import ValidationError

from labcourt.contracts.enums import CaseStatus, EvidenceFailureCode
from labcourt.contracts.m8_prehearing import (
    M8PreHearingOutcomeCode,
    M8PreHearingPreparationState,
    M8PreHearingPreparationV1,
)


def _pending() -> M8PreHearingPreparationV1:
    return M8PreHearingPreparationV1(
        revision=1,
        run_id="run-01",
        case_id="case-01",
        source_case_revision=3,
        source_screening_id="1" * 64,
        source_screening_version=1,
        source_evidence_pack_id="2" * 64,
        source_evidence_pack_version=1,
        manifest_id="3" * 64,
        candidate_crop_ids=("4" * 64, "5" * 64, "6" * 64),
        clear_crop_ids=("4" * 64,),
        clear_threshold=0.65,
        required_clear_count=2,
        selection_policy_version="prehearing-top-m-observability-v1",
        state=M8PreHearingPreparationState.PENDING,
    )


def test_prehearing_preparation_has_one_stable_identity_and_typed_terminal_revision() -> None:
    pending = _pending()
    completed = pending.complete_no_novel_clear_frame(4)

    assert completed.preparation_id == pending.preparation_id
    assert completed.revision == 2
    assert completed.outcome_code == M8PreHearingOutcomeCode.NO_NOVEL_CLEAR_FRAME
    assert completed.resulting_case_status == CaseStatus.HUMAN_REVIEW
    assert completed.evidence_failure_code == EvidenceFailureCode.EVIDENCE_MISSING
    assert completed.hearing_role_call_count == 0


def test_prehearing_contract_rejects_sufficient_evidence_and_identity_tampering() -> None:
    payload = _pending().model_dump(mode="json")
    payload.pop("preparation_id")
    payload["clear_crop_ids"] = payload["candidate_crop_ids"][:2]
    with pytest.raises(ValidationError, match="insufficient clear evidence"):
        M8PreHearingPreparationV1.model_validate(payload)

    payload = _pending().model_dump(mode="json")
    payload["preparation_id"] = "f" * 64
    with pytest.raises(ValidationError, match="preparation_id"):
        M8PreHearingPreparationV1.model_validate(payload)

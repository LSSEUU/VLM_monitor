from __future__ import annotations

import pytest

from labcourt.application.hearing_history import (
    HearingHistoryBuildError,
    HearingHistoryBuildFailureCode,
    build_hearing_call_history,
    derive_hearing_evidence_grant,
)
from tests.unit.test_m4_hearing_procedural_review import _rig


def test_history_rebuilds_exact_calls_from_unordered_immutable_roots() -> None:
    rig = _rig()
    reversed_calls = tuple(reversed(rig.call_history))

    history = build_hearing_call_history(
        rig.record,
        requests=tuple(call.request for call in reversed_calls),
        responses=tuple(call.response for call in reversed_calls),
        parse_receipts=tuple(call.parse_receipt for call in reversed_calls),
        usage_receipts=tuple(call.usage for call in reversed_calls),
    )

    assert history == rig.call_history
    assert derive_hearing_evidence_grant(rig.record, history) == rig.grant


def test_missing_or_extra_artifact_cannot_form_a_history() -> None:
    rig = _rig()
    calls = rig.call_history

    with pytest.raises(HearingHistoryBuildError) as captured:
        build_hearing_call_history(
            rig.record,
            requests=tuple(call.request for call in calls),
            responses=tuple(call.response for call in calls[:-1]),
            parse_receipts=tuple(call.parse_receipt for call in calls),
            usage_receipts=tuple(call.usage for call in calls),
        )

    assert captured.value.reason_code == HearingHistoryBuildFailureCode.ARTIFACT_SET_MISMATCH


def test_cross_request_usage_binding_fails_closed() -> None:
    rig = _rig()
    calls = rig.call_history
    first_usage = calls[0].usage.model_copy(update={"request_ref": calls[1].usage.request_ref})
    usage = (first_usage, *(call.usage for call in calls[1:]))

    with pytest.raises(HearingHistoryBuildError) as captured:
        build_hearing_call_history(
            rig.record,
            requests=tuple(call.request for call in calls),
            responses=tuple(call.response for call in calls),
            parse_receipts=tuple(call.parse_receipt for call in calls),
            usage_receipts=usage,
        )

    assert captured.value.reason_code in {
        HearingHistoryBuildFailureCode.ARTIFACT_SET_MISMATCH,
        HearingHistoryBuildFailureCode.CALL_BINDING_MISMATCH,
    }


def test_grant_rejects_history_from_another_record_scope() -> None:
    first = _rig()
    second = _rig(crop_count=2)

    with pytest.raises(HearingHistoryBuildError) as captured:
        derive_hearing_evidence_grant(second.record, first.call_history)

    assert captured.value.reason_code == HearingHistoryBuildFailureCode.EVIDENCE_GRANT_INVALID

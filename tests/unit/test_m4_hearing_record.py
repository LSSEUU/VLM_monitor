from __future__ import annotations

import pytest

from labcourt.application.hearing_record import (
    HearingRecordBuildError,
    HearingRecordBuildFailureCode,
    build_hearing_record,
    build_hearing_round,
)
from labcourt.contracts.hearing import HearingCheckpointPhase
from labcourt.domain.hearing_fsm import (
    begin_hearing,
    start_cycle_after_acquisition,
)
from tests.unit.test_m4_hearing_domain import (
    _complete_role_cycle,
    _record,
    _session,
)


def _unchecked_copy(model, **updates):
    return type(model).model_construct(**{**model.__dict__, **updates})


def test_round_projection_matches_contract_fixture_exactly() -> None:
    session = _session()
    checkpoint, expected = _complete_role_cycle(session, begin_hearing(session))
    assert expected is not None

    actual = build_hearing_round(checkpoint)

    assert actual == expected
    assert actual.resulting_evidence_pack_id == checkpoint.current_evidence_pack_id
    assert actual.resulting_evidence_pack_version == (checkpoint.current_evidence_pack_version)


def test_record_aggregates_acquisition_then_terminal_round_and_usage() -> None:
    session = _session()
    first_checkpoint, first_round = _complete_role_cycle(
        session,
        begin_hearing(session),
        acquire=True,
    )
    assert first_round is not None
    second_start = start_cycle_after_acquisition(
        session,
        first_checkpoint,
    ).checkpoint
    second_checkpoint, second_round = _complete_role_cycle(session, second_start)
    assert second_round is not None

    actual = build_hearing_record(
        session,
        (first_checkpoint, second_checkpoint),
    )
    expected = _record(
        session,
        (first_round, second_round),
        (first_checkpoint, second_checkpoint),
    )

    assert actual == expected
    assert actual.version == 2
    assert actual.acquisition_rounds_used == 1
    assert actual.complete
    assert actual.current_evidence_pack_id == (first_checkpoint.current_evidence_pack_id)
    assert len(actual.usage_receipts) == 6
    assert len(actual.model_request_refs) == 6


def test_record_can_persist_incomplete_acquisition_prefix() -> None:
    session = _session()
    checkpoint, _ = _complete_role_cycle(
        session,
        begin_hearing(session),
        acquire=True,
    )

    record = build_hearing_record(session, (checkpoint,))

    assert not record.complete
    assert record.acquisition_rounds_used == 1
    assert record.current_evidence_pack_id == checkpoint.current_evidence_pack_id


def test_nonterminal_or_cross_session_checkpoint_is_rejected() -> None:
    session = _session()
    pending = begin_hearing(session)
    with pytest.raises(HearingRecordBuildError) as captured:
        build_hearing_round(pending)
    assert captured.value.reason_code == HearingRecordBuildFailureCode.CHECKPOINT_NOT_ROUND_COMPLETE

    complete, _ = _complete_role_cycle(session, pending)
    corrupted = _unchecked_copy(
        complete,
        phase=HearingCheckpointPhase.PROSECUTOR_PENDING,
    )
    with pytest.raises(HearingRecordBuildError) as captured:
        build_hearing_record(session, (corrupted,))
    assert captured.value.reason_code == HearingRecordBuildFailureCode.CHECKPOINT_NOT_ROUND_COMPLETE


def test_skipped_cycle_and_duplicate_trace_fail_closed() -> None:
    session = _session()
    first, _ = _complete_role_cycle(
        session,
        begin_hearing(session),
        acquire=True,
    )
    second_start = start_cycle_after_acquisition(session, first).checkpoint
    second, _ = _complete_role_cycle(session, second_start)

    with pytest.raises(HearingRecordBuildError) as captured:
        build_hearing_record(session, (second,))
    assert captured.value.reason_code == HearingRecordBuildFailureCode.CHECKPOINT_SEQUENCE_INVALID

    duplicated = _unchecked_copy(
        second,
        model_request_refs=(
            *second.model_request_refs,
            second.model_request_refs[0],
        ),
    )
    with pytest.raises((HearingRecordBuildError, ValueError)):
        build_hearing_record(session, (first, duplicated))

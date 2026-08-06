from __future__ import annotations

from dataclasses import replace

import pytest

import labcourt.application.hearing_rework as rework_module
from labcourt.application.hearing_rework import (
    HearingReworkPreparationError,
    HearingReworkPreparationFailureCode,
    PreparedHearingRework,
    cycle_scope_from_checkpoint,
    prepare_hearing_rework,
)
from labcourt.contracts.enums import ArtifactKind
from labcourt.contracts.hearing import HearingCheckpointPhase
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.hearing_fsm import (
    begin_hearing,
    record_procedural_review,
    start_rework_cycle,
)
from labcourt.domain.hearing_verdict_builder import HearingReviewClosure
from tests.unit.test_m4_hearing_domain import (
    _complete_role_cycle,
    _record,
    _review_closure,
    _session,
)


def _failed_review_ready():
    session = _session()
    complete, hearing_round = _complete_role_cycle(session, begin_hearing(session))
    assert hearing_round is not None
    closure = _review_closure(
        session,
        (hearing_round,),
        (complete,),
        "rework-preparation",
    )
    ready = record_procedural_review(session, complete, closure)
    return session, ready, closure


def test_rework_preparation_binds_exact_adjacent_cycle_and_failed_review() -> None:
    session, ready, closure = _failed_review_ready()

    prepared = prepare_hearing_rework(session, ready, closure)

    assert prepared.checkpoint.phase == HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING
    assert prepared.checkpoint.judge_cycle == ready.judge_cycle + 1
    assert prepared.checkpoint.prior_rework_rounds == ready.prior_rework_rounds + 1
    assert prepared.checkpoint.previous_checkpoint_id == ready.checkpoint_id
    assert prepared.cycle_scope == cycle_scope_from_checkpoint(prepared.checkpoint)
    assert prepared.receipt.failed_review_id == closure.review.review_id
    assert prepared.receipt.prior_round_id == closure.record.rounds[-1].round_id
    assert prepared.receipt.defect_codes == tuple(
        sorted({defect.code for defect in closure.review.defects}, key=lambda code: code.value)
    )


def test_rework_preparation_rejects_review_or_checkpoint_drift() -> None:
    session, ready, closure = _failed_review_ready()
    wrong_review = type(closure.review).model_construct(
        **{
            **closure.review.__dict__,
            "reviewed_verdict_id": "0" * 64,
        }
    )
    drifted = type(closure)(
        record=closure.record,
        verdict=closure.verdict,
        binding=closure.binding,
        review=wrong_review,
    )

    with pytest.raises(HearingReworkPreparationError) as captured:
        prepare_hearing_rework(session, ready, drifted)

    assert (
        captured.value.reason_code == HearingReworkPreparationFailureCode.REVIEW_AUTHORITY_MISMATCH
    )


def test_cycle_scope_reconstruction_detects_bypassed_scope_corruption() -> None:
    _session_value, ready, _closure = _failed_review_ready()
    corrupted = ready.model_construct(
        **{
            **ready.__dict__,
            "cycle_trigger_review_ref": ArtifactRef(
                kind=ArtifactKind.PROCEDURAL_REVIEW,
                artifact_id="1" * 64,
            ),
        }
    )

    with pytest.raises(HearingReworkPreparationError) as captured:
        cycle_scope_from_checkpoint(corrupted)

    assert (
        captured.value.reason_code
        == HearingReworkPreparationFailureCode.SUCCESSOR_TRANSITION_MISMATCH
    )


def test_rework_limit_is_typed_instead_of_opening_cycle_six() -> None:
    session = _session()
    complete, hearing_round = _complete_role_cycle(session, begin_hearing(session))
    assert hearing_round is not None
    closure = _review_closure(
        session,
        (hearing_round,),
        (complete,),
        "limit-base",
    )
    # A fully realistic two-rework history is covered by the FSM tests.  Here
    # we only bypass construction to prove the application boundary returns
    # the stable exhaustion code rather than fabricating another cycle.
    record = _record(session, (hearing_round,), (complete,))
    assert record == closure.record
    exhausted = record_procedural_review(session, complete, closure).model_construct(
        **{
            **record_procedural_review(session, complete, closure).__dict__,
            "judge_cycle": 3,
            "prior_rework_rounds": 2,
        }
    )

    with pytest.raises(HearingReworkPreparationError):
        prepare_hearing_rework(session, exhausted, closure)


def test_rework_error_requires_a_typed_reason() -> None:
    with pytest.raises(TypeError):
        HearingReworkPreparationError("INVALID_ARGUMENT")  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ("cycle_scope", "checkpoint", "receipt"))
def test_prepared_rework_requires_typed_roots(field: str) -> None:
    session, ready, closure = _failed_review_ready()
    prepared = prepare_hearing_rework(session, ready, closure)
    values = {
        "cycle_scope": prepared.cycle_scope,
        "checkpoint": prepared.checkpoint,
        "receipt": prepared.receipt,
    }
    values[field] = object()

    with pytest.raises(TypeError):
        PreparedHearingRework(**values)  # type: ignore[arg-type]


def test_prepared_rework_rejects_cross_cycle_roots() -> None:
    session, ready, closure = _failed_review_ready()
    prepared = prepare_hearing_rework(session, ready, closure)
    drifted_cycle = prepared.cycle_scope.model_construct(
        **{
            **prepared.cycle_scope.__dict__,
            "cycle_evidence_pack_id": "0" * 64,
        }
    )

    with pytest.raises(ValueError):
        PreparedHearingRework(
            cycle_scope=drifted_cycle,
            checkpoint=prepared.checkpoint,
            receipt=prepared.receipt,
        )


def test_cycle_scope_reconstruction_requires_a_checkpoint() -> None:
    with pytest.raises(TypeError):
        cycle_scope_from_checkpoint(object())  # type: ignore[arg-type]


def test_cycle_scope_reconstruction_maps_invalid_fields_to_typed_failure() -> None:
    _session_value, ready, _closure = _failed_review_ready()
    corrupted = ready.model_construct(
        **{
            **ready.__dict__,
            "cycle_evidence_pack_version": 0,
        }
    )

    with pytest.raises(HearingReworkPreparationError) as raised:
        cycle_scope_from_checkpoint(corrupted)

    assert (
        raised.value.reason_code
        == HearingReworkPreparationFailureCode.SUCCESSOR_TRANSITION_MISMATCH
    )


def test_cycle_scope_reconstruction_rejects_valid_but_drifted_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _session_value, ready, _closure = _failed_review_ready()
    scope = cycle_scope_from_checkpoint(ready)
    drifted_scope = scope.model_construct(
        **{
            **scope.__dict__,
            "cycle_evidence_pack_id": "1" * 64,
        }
    )
    monkeypatch.setattr(
        rework_module,
        "HearingCycleScope",
        lambda **_values: drifted_scope,
    )

    with pytest.raises(HearingReworkPreparationError) as raised:
        cycle_scope_from_checkpoint(ready)

    assert (
        raised.value.reason_code
        == HearingReworkPreparationFailureCode.SUCCESSOR_TRANSITION_MISMATCH
    )


@pytest.mark.parametrize(
    ("session_value", "checkpoint_value", "closure_value"),
    (
        (object(), None, None),
        (None, object(), None),
        (None, None, object()),
    ),
)
def test_rework_preparation_rejects_each_untyped_argument(
    session_value: object | None,
    checkpoint_value: object | None,
    closure_value: object | None,
) -> None:
    session, ready, closure = _failed_review_ready()

    with pytest.raises(HearingReworkPreparationError) as raised:
        prepare_hearing_rework(
            session if session_value is None else session_value,  # type: ignore[arg-type]
            ready if checkpoint_value is None else checkpoint_value,  # type: ignore[arg-type]
            closure if closure_value is None else closure_value,  # type: ignore[arg-type]
        )

    assert raised.value.reason_code == HearingReworkPreparationFailureCode.INVALID_ARGUMENT


def test_rework_preparation_requires_rework_ready_phase() -> None:
    session, _ready, closure = _failed_review_ready()

    with pytest.raises(HearingReworkPreparationError) as raised:
        prepare_hearing_rework(session, begin_hearing(session), closure)

    assert raised.value.reason_code == HearingReworkPreparationFailureCode.REVIEW_AUTHORITY_MISMATCH


def test_rework_transition_failure_is_mapped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, ready, closure = _failed_review_ready()

    def fail_transition(*_args: object) -> None:
        raise ValueError("controlled transition failure")

    monkeypatch.setattr(rework_module, "start_rework_cycle", fail_transition)
    with pytest.raises(HearingReworkPreparationError) as raised:
        prepare_hearing_rework(session, ready, closure)

    assert raised.value.reason_code == HearingReworkPreparationFailureCode.REVIEW_AUTHORITY_MISMATCH


def test_rework_limit_transition_has_exact_typed_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, ready, closure = _failed_review_ready()

    class _ExhaustedTransition:
        human_review_receipt = object()
        checkpoint = ready

    monkeypatch.setattr(
        rework_module,
        "start_rework_cycle",
        lambda *_args: _ExhaustedTransition(),
    )
    with pytest.raises(HearingReworkPreparationError) as raised:
        prepare_hearing_rework(session, ready, closure)

    assert raised.value.reason_code == HearingReworkPreparationFailureCode.REWORK_LIMIT_EXHAUSTED


def test_rework_receipt_construction_failure_is_mapped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, ready, closure = _failed_review_ready()

    def fail_summary(_closure: HearingReviewClosure) -> str:
        raise ValueError("controlled receipt failure")

    monkeypatch.setattr(
        rework_module,
        "_prompt_defect_summary_sha256",
        fail_summary,
    )
    with pytest.raises(HearingReworkPreparationError) as raised:
        prepare_hearing_rework(session, ready, closure)

    assert (
        raised.value.reason_code
        == HearingReworkPreparationFailureCode.SUCCESSOR_TRANSITION_MISMATCH
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("previous_checkpoint_id", "0" * 64),
        ("previous_checkpoint_sha256", "0" * 64),
        ("previous_phase", HearingCheckpointPhase.ROUND_COMPLETE),
    ),
)
def test_rework_successor_history_drift_is_rejected(
    field: str,
    value: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, ready, closure = _failed_review_ready()
    transition = start_rework_cycle(session, ready, closure)
    successor = transition.checkpoint.model_construct(
        **{
            **transition.checkpoint.__dict__,
            field: value,
        }
    )
    monkeypatch.setattr(
        rework_module,
        "start_rework_cycle",
        lambda *_args: replace(transition, checkpoint=successor),
    )

    with pytest.raises(HearingReworkPreparationError) as raised:
        prepare_hearing_rework(session, ready, closure)

    assert (
        raised.value.reason_code
        == HearingReworkPreparationFailureCode.SUCCESSOR_TRANSITION_MISMATCH
    )


@pytest.mark.parametrize("drift", ("round_index", "judge_output"))
def test_rework_terminal_round_drift_is_rejected(
    drift: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, ready, closure = _failed_review_ready()
    transition = start_rework_cycle(session, ready, closure)
    terminal = closure.record.rounds[-1]
    update = (
        {"round_index": terminal.round_index + 1}
        if drift == "round_index"
        else {
            "judge_output": terminal.judge_output.model_construct(
                **{
                    **terminal.judge_output.__dict__,
                    "model_manifest_id": "0" * 64,
                }
            )
        }
    )
    bad_round = terminal.model_construct(**{**terminal.__dict__, **update})
    bad_record = closure.record.model_construct(
        **{
            **closure.record.__dict__,
            "rounds": (bad_round,),
        }
    )
    drifted = HearingReviewClosure(
        bad_record,
        closure.verdict,
        closure.binding,
        closure.review,
    )
    monkeypatch.setattr(
        rework_module,
        "start_rework_cycle",
        lambda *_args: transition,
    )

    with pytest.raises(HearingReworkPreparationError) as raised:
        prepare_hearing_rework(session, ready, drifted)

    assert (
        raised.value.reason_code
        == HearingReworkPreparationFailureCode.SUCCESSOR_TRANSITION_MISMATCH
    )


def test_rework_receipt_index_drift_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, ready, closure = _failed_review_ready()
    original = rework_module.HearingReworkReceipt

    def drifted_receipt(**values: object):
        receipt = original(**values)
        return receipt.model_construct(
            **{
                **receipt.__dict__,
                "rework_index": ready.prior_rework_rounds + 2,
            }
        )

    monkeypatch.setattr(rework_module, "HearingReworkReceipt", drifted_receipt)
    with pytest.raises(HearingReworkPreparationError) as raised:
        prepare_hearing_rework(session, ready, closure)

    assert (
        raised.value.reason_code
        == HearingReworkPreparationFailureCode.SUCCESSOR_TRANSITION_MISMATCH
    )

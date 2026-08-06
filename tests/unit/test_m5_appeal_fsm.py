from __future__ import annotations

from typing import TypeVar, cast

import pytest
from pydantic import BaseModel, ValidationError

from labcourt.contracts.enums import (
    AppealStatus,
    EvidenceClass,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.m5_appeals import (
    AppealResolutionCommand,
    AppealReviewCommand,
    AppealSubmissionCommand,
    AppealVersionAuthority,
    ClosedCaseAppealAuthority,
)
from labcourt.domain.appeal_fsm import (
    AppealTransitionError,
    AppealTransitionFailureCode,
    begin_appeal_review,
    resolve_appeal,
    submit_appeal,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64

ModelT = TypeVar("ModelT", bound=BaseModel)


def _unsafe_copy(model: ModelT, **update: object) -> ModelT:
    """Simulate a corrupted in-memory authority past the contract boundary."""

    return cast(ModelT, BaseModel.model_copy(model, update=update))


def _case(*, effective_appeal_ids: tuple[str, ...] = ()) -> ClosedCaseAppealAuthority:
    return ClosedCaseAppealAuthority(
        run_id="run-1",
        case_id="case-1",
        case_revision=4,
        verdict_id=SHA_A,
        verdict_version=2,
        verdict_sha256=SHA_B,
        final_decision=VerdictDecision.ESTABLISHED,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        effective_appeal_ids=effective_appeal_ids,
        detector_manifest_id=SHA_C,
        text_embedding_manifest_id=SHA_A,
        visual_embedding_manifest_id=SHA_B,
        manifest_id=SHA_D,
        config_sha256=SHA_C,
        rule_version="rules-v1",
    )


def _submit_command(case: ClosedCaseAppealAuthority) -> AppealSubmissionCommand:
    return AppealSubmissionCommand(
        run_id=case.run_id,
        case_id=case.case_id,
        appeal_id="appeal-1",
        expected_case_revision=case.case_revision,
        expected_case_authority_sha256=case.authority_sha256,
        reason="The original finding should be reviewed by a human.",
        submitted_by="subject-1",
    )


def _submitted(case: ClosedCaseAppealAuthority | None = None) -> AppealVersionAuthority:
    authority = case or _case()
    return submit_appeal(authority, _submit_command(authority), None)


def _reviewed() -> AppealVersionAuthority:
    submitted = _submitted()
    return begin_appeal_review(
        submitted,
        AppealReviewCommand(
            run_id=submitted.run_id,
            case_id=submitted.appeal.case_id,
            appeal_id=submitted.appeal.appeal_id,
            expected_appeal_authority_sha256=submitted.authority_sha256,
            reviewer_id="reviewer-1",
        ),
    )


def _resolution_command(
    reviewed: AppealVersionAuthority,
    *,
    status: AppealStatus = AppealStatus.OVERTURNED,
    decision: VerdictDecision = VerdictDecision.NOT_ESTABLISHED,
) -> AppealResolutionCommand:
    return AppealResolutionCommand(
        run_id=reviewed.run_id,
        case_id=reviewed.appeal.case_id,
        appeal_id=reviewed.appeal.appeal_id,
        expected_appeal_authority_sha256=reviewed.authority_sha256,
        status=status,
        reviewer_id="reviewer-1",
        resolution_summary="Human review reached a final appeal decision.",
        resolved_decision=decision,
    )


def test_exact_none_submitted_review_terminal_chain_is_append_only() -> None:
    case = _case()
    submitted = submit_appeal(case, _submit_command(case), None)
    assert submitted.version == 1
    assert submitted.appeal.status == AppealStatus.SUBMITTED
    assert submitted.previous_authority_sha256 is None
    assert submitted.source_case_authority == case

    reviewed = begin_appeal_review(
        submitted,
        AppealReviewCommand(
            run_id="run-1",
            case_id="case-1",
            appeal_id="appeal-1",
            expected_appeal_authority_sha256=submitted.authority_sha256,
            reviewer_id="reviewer-1",
        ),
    )
    assert reviewed.version == 2
    assert reviewed.appeal.status == AppealStatus.UNDER_REVIEW
    assert reviewed.previous_authority_sha256 == submitted.authority_sha256
    assert reviewed.source_case_authority == submitted.source_case_authority

    terminal = resolve_appeal(reviewed, _resolution_command(reviewed))
    assert terminal.version == 3
    assert terminal.appeal.status == AppealStatus.OVERTURNED
    assert terminal.appeal.resolved_decision == VerdictDecision.NOT_ESTABLISHED
    assert terminal.previous_authority_sha256 == reviewed.authority_sha256
    assert terminal.source_case_authority == reviewed.source_case_authority


def test_embedded_submit_time_case_authority_and_its_hash_are_both_immutable() -> None:
    submitted = _submitted()
    assert AppealVersionAuthority.model_validate(submitted.model_dump(mode="json")) == submitted

    hash_tampered = submitted.model_dump(mode="json")
    hash_tampered.pop("authority_sha256")
    hash_tampered["source_case_authority_sha256"] = SHA_C
    with pytest.raises(ValidationError, match="embedded closed Case authority"):
        AppealVersionAuthority.model_validate(hash_tampered)

    document_tampered = submitted.model_dump(mode="json")
    document_tampered["source_case_authority"]["rule_version"] = "rules-v2"
    with pytest.raises(ValidationError):
        AppealVersionAuthority.model_validate(document_tampered)


def test_submission_requires_true_absence_and_zero_prior_effective_appeals() -> None:
    case = _case()
    submitted = _submitted(case)
    with pytest.raises(AppealTransitionError) as existing:
        submit_appeal(case, _submit_command(case), submitted)
    assert existing.value.reason_code == AppealTransitionFailureCode.APPEAL_ALREADY_EXISTS

    prior = _case(effective_appeal_ids=("appeal-old",))
    with pytest.raises(AppealTransitionError) as historical:
        submit_appeal(prior, _submit_command(prior), None)
    assert historical.value.reason_code == AppealTransitionFailureCode.APPEAL_ALREADY_EXISTS


def test_transition_boundaries_reject_untyped_authorities_and_commands() -> None:
    case = _case()
    submit_command = _submit_command(case)
    submitted = _submitted(case)
    review_command = AppealReviewCommand(
        run_id=submitted.run_id,
        case_id=submitted.appeal.case_id,
        appeal_id=submitted.appeal.appeal_id,
        expected_appeal_authority_sha256=submitted.authority_sha256,
        reviewer_id="reviewer-1",
    )
    reviewed = _reviewed()
    resolution_command = _resolution_command(reviewed)

    with pytest.raises(TypeError, match="AppealTransitionFailureCode"):
        AppealTransitionError("AUTHORITY_MISMATCH")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="case_authority"):
        submit_appeal(None, submit_command, None)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="command"):
        submit_appeal(case, None, None)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="current_authority"):
        submit_appeal(case, submit_command, object())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="current_authority"):
        begin_appeal_review(None, review_command)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="command"):
        begin_appeal_review(submitted, None)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="current_authority"):
        resolve_appeal(None, resolution_command)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="command"):
        resolve_appeal(reviewed, None)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "run-other"),
        ("case_id", "case-other"),
        ("expected_case_revision", 3),
        ("expected_case_authority_sha256", SHA_D),
    ],
)
def test_submission_fences_every_closed_case_authority_root(
    field: str,
    value: str | int,
) -> None:
    case = _case()
    command = _unsafe_copy(_submit_command(case), **{field: value})

    with pytest.raises(AppealTransitionError) as failure:
        submit_appeal(case, command, None)
    assert failure.value.reason_code == AppealTransitionFailureCode.AUTHORITY_MISMATCH


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "run-other"),
        ("case_id", "case-other"),
        ("appeal_id", "appeal-other"),
        ("expected_appeal_version", 2),
        ("expected_appeal_authority_sha256", SHA_D),
    ],
)
def test_review_fences_every_submitted_appeal_authority_root(
    field: str,
    value: str | int,
) -> None:
    submitted = _submitted()
    command = _unsafe_copy(
        AppealReviewCommand(
            run_id=submitted.run_id,
            case_id=submitted.appeal.case_id,
            appeal_id=submitted.appeal.appeal_id,
            expected_appeal_authority_sha256=submitted.authority_sha256,
            reviewer_id="reviewer-1",
        ),
        **{field: value},
    )

    with pytest.raises(AppealTransitionError) as failure:
        begin_appeal_review(submitted, command)
    assert failure.value.reason_code == AppealTransitionFailureCode.AUTHORITY_MISMATCH


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "run-other"),
        ("case_id", "case-other"),
        ("appeal_id", "appeal-other"),
        ("expected_appeal_version", 3),
        ("expected_appeal_authority_sha256", SHA_D),
    ],
)
def test_resolution_fences_every_reviewed_appeal_authority_root(
    field: str,
    value: str | int,
) -> None:
    reviewed = _reviewed()
    command = _unsafe_copy(_resolution_command(reviewed), **{field: value})

    with pytest.raises(AppealTransitionError) as failure:
        resolve_appeal(reviewed, command)
    assert failure.value.reason_code == AppealTransitionFailureCode.AUTHORITY_MISMATCH


def test_stale_case_or_appeal_fence_cannot_advance_state() -> None:
    case = _case()
    stale_submit = _submit_command(case).model_copy(update={"expected_case_revision": 3})
    with pytest.raises(AppealTransitionError) as submit_failure:
        submit_appeal(case, stale_submit, None)
    assert submit_failure.value.reason_code == AppealTransitionFailureCode.AUTHORITY_MISMATCH

    submitted = _submitted(case)
    stale_review = AppealReviewCommand(
        run_id=submitted.run_id,
        case_id=submitted.appeal.case_id,
        appeal_id=submitted.appeal.appeal_id,
        expected_appeal_authority_sha256=SHA_D,
        reviewer_id="reviewer-1",
    )
    with pytest.raises(AppealTransitionError) as review_failure:
        begin_appeal_review(submitted, stale_review)
    assert review_failure.value.reason_code == AppealTransitionFailureCode.AUTHORITY_MISMATCH


def test_only_assigned_reviewer_can_resolve() -> None:
    reviewed = _reviewed()
    command = _resolution_command(reviewed).model_copy(update={"reviewer_id": "reviewer-2"})
    with pytest.raises(AppealTransitionError) as failure:
        resolve_appeal(reviewed, command)
    assert failure.value.reason_code == AppealTransitionFailureCode.REVIEWER_MISMATCH


def test_state_and_version_must_both_match_each_transition_boundary() -> None:
    submitted = _submitted()
    wrong_submit_status = _unsafe_copy(
        submitted,
        appeal=_unsafe_copy(submitted.appeal, status=AppealStatus.UNDER_REVIEW),
    )
    review_command = AppealReviewCommand(
        run_id=submitted.run_id,
        case_id=submitted.appeal.case_id,
        appeal_id=submitted.appeal.appeal_id,
        expected_appeal_authority_sha256=submitted.authority_sha256,
        reviewer_id="reviewer-1",
    )
    with pytest.raises(AppealTransitionError) as review_failure:
        begin_appeal_review(wrong_submit_status, review_command)
    assert review_failure.value.reason_code == AppealTransitionFailureCode.TRANSITION_NOT_ALLOWED

    reviewed = _reviewed()
    wrong_review_status = _unsafe_copy(
        reviewed,
        appeal=_unsafe_copy(reviewed.appeal, status=AppealStatus.SUBMITTED),
    )
    with pytest.raises(AppealTransitionError) as resolution_failure:
        resolve_appeal(wrong_review_status, _resolution_command(reviewed))
    assert (
        resolution_failure.value.reason_code == AppealTransitionFailureCode.TRANSITION_NOT_ALLOWED
    )


def test_upheld_resolution_preserves_the_source_decision() -> None:
    reviewed = _reviewed()
    terminal = resolve_appeal(
        reviewed,
        _resolution_command(
            reviewed,
            status=AppealStatus.UPHELD,
            decision=VerdictDecision.ESTABLISHED,
        ),
    )

    assert terminal.appeal.status == AppealStatus.UPHELD
    assert terminal.appeal.resolved_decision == reviewed.source_decision


@pytest.mark.parametrize(
    ("status", "decision"),
    [
        (AppealStatus.UPHELD, VerdictDecision.NOT_ESTABLISHED),
        (AppealStatus.OVERTURNED, VerdictDecision.ESTABLISHED),
    ],
)
def test_upheld_must_preserve_and_overturned_must_change_decision(
    status: AppealStatus,
    decision: VerdictDecision,
) -> None:
    reviewed = _reviewed()
    with pytest.raises(AppealTransitionError) as failure:
        resolve_appeal(
            reviewed,
            _resolution_command(reviewed, status=status, decision=decision),
        )
    assert failure.value.reason_code == AppealTransitionFailureCode.RESOLUTION_DECISION_INVALID


def test_terminal_appeal_cannot_be_reopened_or_resolved_twice() -> None:
    reviewed = _reviewed()
    command = _resolution_command(reviewed)
    terminal = resolve_appeal(reviewed, command)
    with pytest.raises(AppealTransitionError) as resolve_failure:
        resolve_appeal(terminal, command)
    assert resolve_failure.value.reason_code == AppealTransitionFailureCode.TRANSITION_NOT_ALLOWED

    with pytest.raises(AppealTransitionError) as review_failure:
        begin_appeal_review(
            terminal,
            AppealReviewCommand(
                run_id=terminal.run_id,
                case_id=terminal.appeal.case_id,
                appeal_id=terminal.appeal.appeal_id,
                expected_appeal_authority_sha256=terminal.authority_sha256,
                reviewer_id="reviewer-1",
            ),
        )
    assert review_failure.value.reason_code == AppealTransitionFailureCode.TRANSITION_NOT_ALLOWED

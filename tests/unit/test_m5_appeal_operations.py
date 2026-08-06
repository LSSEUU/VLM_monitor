from __future__ import annotations

import pytest

from labcourt.application.m5_appeal_operations import (
    M5AppealOperationsCoordinator,
    M5AppealOperationsError,
    M5AppealOperationsErrorCode,
)
from labcourt.contracts.enums import (
    AppealStatus,
    EvidenceClass,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.m5_appeals import (
    MAX_M5_APPEAL_TRAINING_LABELS,
    AppealResolutionCommand,
    AppealResolutionPrecedentSnapshot,
    AppealResolutionSideEffectIntent,
    AppealReviewCommand,
    AppealSubmissionCommand,
    AppealVersionAuthority,
    ClosedCaseAppealAuthority,
)
from labcourt.domain.appeal_fsm import AppealTransitionError, AppealTransitionFailureCode

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _case() -> ClosedCaseAppealAuthority:
    return ClosedCaseAppealAuthority(
        run_id="run-01",
        case_id="case-01",
        case_revision=8,
        verdict_id=SHA_A,
        verdict_version=2,
        verdict_sha256=SHA_B,
        final_decision=VerdictDecision.ESTABLISHED,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        detector_manifest_id=SHA_C,
        text_embedding_manifest_id=SHA_A,
        visual_embedding_manifest_id=SHA_B,
        manifest_id=SHA_D,
        config_sha256=SHA_C,
        rule_version="rules-v1",
    )


class _Repository:
    def __init__(self, source: ClosedCaseAppealAuthority) -> None:
        self.source = source
        self.current: AppealVersionAuthority | None = None
        self.resolution: AppealResolutionSideEffectIntent | None = None
        self.append_count = 0
        self.snapshot_count = 0
        self.commit_count = 0
        self.case_head_override: AppealVersionAuthority | object | None = _UNSET

    def load_closed_case_authority(
        self,
        run_id: str,
        case_id: str,
    ) -> ClosedCaseAppealAuthority:
        assert (run_id, case_id) == (self.source.run_id, self.source.case_id)
        return self.source

    def load_current_appeal(
        self,
        run_id: str,
        case_id: str,
    ) -> AppealVersionAuthority | None:
        assert (run_id, case_id) == (self.source.run_id, self.source.case_id)
        if self.case_head_override is not _UNSET:
            assert self.case_head_override is None or isinstance(
                self.case_head_override,
                AppealVersionAuthority,
            )
            return self.case_head_override
        return self.current

    def load_appeal_by_id(
        self,
        run_id: str,
        appeal_id: str,
    ) -> AppealVersionAuthority | None:
        if self.current is None:
            return None
        if (run_id, appeal_id) != (
            self.current.run_id,
            self.current.appeal.appeal_id,
        ):
            return None
        return self.current

    def load_resolution_precedent_snapshot(
        self,
        run_id: str,
        case_id: str,
    ) -> AppealResolutionPrecedentSnapshot:
        assert (run_id, case_id) == (self.source.run_id, self.source.case_id)
        self.snapshot_count += 1
        return AppealResolutionPrecedentSnapshot(run_id=run_id, case_id=case_id)

    def load_resolution(
        self,
        run_id: str,
        appeal_id: str,
    ) -> AppealResolutionSideEffectIntent | None:
        if self.resolution is None:
            return None
        assert (run_id, appeal_id) == (
            self.resolution.run_id,
            self.resolution.appeal_authority.appeal.appeal_id,
        )
        return self.resolution

    def append_appeal_version(
        self,
        authority: AppealVersionAuthority,
        expected_previous_authority_sha256: str | None,
    ) -> AppealVersionAuthority:
        assert expected_previous_authority_sha256 == authority.previous_authority_sha256
        self.append_count += 1
        self.current = authority
        return authority

    def commit_resolution(
        self,
        intent: AppealResolutionSideEffectIntent,
    ) -> AppealResolutionSideEffectIntent:
        self.commit_count += 1
        self.current = intent.appeal_authority
        self.resolution = intent
        return intent


_UNSET = object()


def _submit_command(source: ClosedCaseAppealAuthority) -> AppealSubmissionCommand:
    return AppealSubmissionCommand(
        run_id=source.run_id,
        case_id=source.case_id,
        appeal_id="appeal-01",
        expected_case_revision=source.case_revision,
        expected_case_authority_sha256=source.authority_sha256,
        reason="The source decision requires an explicit human review.",
        submitted_by="subject-01",
    )


def test_coordinator_runs_upheld_chain_and_replays_nonterminal_commands() -> None:
    source = _case()
    repository = _Repository(source)
    coordinator = M5AppealOperationsCoordinator(repository)

    submitted = coordinator.submit(_submit_command(source))
    assert submitted.committed_case_revision == source.case_revision + 1
    assert coordinator.submit(_submit_command(source)) == submitted
    assert repository.append_count == 1

    review_command = AppealReviewCommand(
        run_id=source.run_id,
        case_id=source.case_id,
        appeal_id=submitted.appeal_id,
        expected_appeal_authority_sha256=submitted.appeal_authority_sha256,
        reviewer_id="reviewer-01",
    )
    reviewed = coordinator.begin_review(review_command)
    assert reviewed.committed_case_revision == source.case_revision + 2
    assert coordinator.begin_review(review_command) == reviewed
    assert repository.append_count == 2

    resolution_command = AppealResolutionCommand(
        run_id=source.run_id,
        case_id=source.case_id,
        appeal_id=reviewed.appeal_id,
        expected_appeal_authority_sha256=reviewed.appeal_authority_sha256,
        status=AppealStatus.UPHELD,
        reviewer_id="reviewer-01",
        resolution_summary="The assigned human reviewer upheld the decision.",
        resolved_decision=source.final_decision,
    )
    resolved = coordinator.resolve(resolution_command)
    assert resolved.status == AppealStatus.UPHELD
    assert resolved.source_decision == resolved.final_decision
    assert resolved.committed_case_revision == source.case_revision + 3
    assert repository.snapshot_count == 1
    assert repository.commit_count == 1

    assert coordinator.resolve(resolution_command) == resolved
    assert repository.snapshot_count == 1
    assert repository.commit_count == 1

    conflicting = resolution_command.model_copy(
        update={"resolution_summary": "A different terminal human finding."}
    )
    with pytest.raises(M5AppealOperationsError) as terminal_conflict:
        coordinator.resolve(conflicting)
    assert terminal_conflict.value.code == M5AppealOperationsErrorCode.TERMINAL_COMMAND_CONFLICT

    wrong_predecessor = resolution_command.model_copy(
        update={"expected_appeal_authority_sha256": SHA_C}
    )
    with pytest.raises(M5AppealOperationsError) as predecessor_conflict:
        coordinator.resolve(wrong_predecessor)
    assert predecessor_conflict.value.code == M5AppealOperationsErrorCode.TERMINAL_COMMAND_CONFLICT
    assert repository.snapshot_count == 1
    assert repository.commit_count == 1


def test_terminal_replay_requires_its_durable_receipt_and_rejects_unchecked_label_flood() -> None:
    source = _case()
    repository = _Repository(source)
    coordinator = M5AppealOperationsCoordinator(repository)
    submitted = coordinator.submit(_submit_command(source))
    reviewed = coordinator.begin_review(
        AppealReviewCommand(
            run_id=source.run_id,
            case_id=source.case_id,
            appeal_id=submitted.appeal_id,
            expected_appeal_authority_sha256=submitted.appeal_authority_sha256,
            reviewer_id="reviewer-01",
        )
    )
    command = AppealResolutionCommand(
        run_id=source.run_id,
        case_id=source.case_id,
        appeal_id=reviewed.appeal_id,
        expected_appeal_authority_sha256=reviewed.appeal_authority_sha256,
        status=AppealStatus.UPHELD,
        reviewer_id="reviewer-01",
        resolution_summary="The assigned human reviewer upheld the decision.",
        resolved_decision=source.final_decision,
    )
    coordinator.resolve(command)
    repository.resolution = None
    with pytest.raises(M5AppealOperationsError) as missing_receipt:
        coordinator.resolve(command)
    assert missing_receipt.value.code == M5AppealOperationsErrorCode.COMMIT_RESULT_INVALID

    unchecked = AppealResolutionCommand.model_construct(
        **{
            **command.__dict__,
            "training_labels": (object(),) * (MAX_M5_APPEAL_TRAINING_LABELS + 1),
        }
    )
    with pytest.raises(M5AppealOperationsError) as invalid:
        coordinator.resolve(unchecked)
    assert invalid.value.code == M5AppealOperationsErrorCode.RESOLUTION_COMMAND_INVALID


def test_duplicate_or_missing_appeal_fails_closed_with_typed_errors() -> None:
    source = _case()
    repository = _Repository(source)
    coordinator = M5AppealOperationsCoordinator(repository)
    missing = AppealReviewCommand(
        run_id=source.run_id,
        case_id=source.case_id,
        appeal_id="appeal-missing",
        expected_appeal_authority_sha256=SHA_A,
        reviewer_id="reviewer-01",
    )
    with pytest.raises(M5AppealOperationsError) as not_found:
        coordinator.begin_review(missing)
    assert not_found.value.code == M5AppealOperationsErrorCode.APPEAL_NOT_FOUND

    coordinator.submit(_submit_command(source))
    conflicting = _submit_command(source).model_copy(update={"appeal_id": "appeal-02"})
    with pytest.raises(AppealTransitionError) as duplicate:
        coordinator.submit(conflicting)
    assert duplicate.value.reason_code == AppealTransitionFailureCode.APPEAL_ALREADY_EXISTS

    repository.case_head_override = None
    valid_head = repository.current
    assert valid_head is not None
    review = AppealReviewCommand(
        run_id=source.run_id,
        case_id=source.case_id,
        appeal_id=valid_head.appeal.appeal_id,
        expected_appeal_authority_sha256=valid_head.authority_sha256,
        reviewer_id="reviewer-01",
    )
    with pytest.raises(M5AppealOperationsError) as mismatch:
        coordinator.begin_review(review)
    assert mismatch.value.code == M5AppealOperationsErrorCode.CURRENT_AUTHORITY_MISMATCH

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest

from labcourt.application.appeal_resolution import (
    AppealResolutionError,
    AppealResolutionFailureCode,
    build_appeal_resolution_intent,
)
from labcourt.application.m5_human_labels import build_m5_appeal_training_labels
from labcourt.application.m5_precedents import create_m5_precedent_authority
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import (
    AppealStatus,
    EvidenceClass,
    PrecedentSource,
    PrecedentStatus,
    TrainingLabelQuality,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m5_appeals import (
    AffectedPrecedentCitation,
    AppealableAlertAuthority,
    AppealResolutionCommand,
    AppealResolutionPrecedentSnapshot,
    AppealReviewCommand,
    AppealSubmissionCommand,
    AppealVersionAuthority,
    AutomaticPrecedentAppealAuthority,
    ClosedCaseAppealAuthority,
)
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.contracts.m5_precedents import (
    M5EmbeddingChannel,
    M5EmbeddingRequest,
    M5EmbeddingVector,
    M5PrecedentAuthority,
    M5PrecedentPolicy,
)
from labcourt.contracts.training import TrainingLabel
from labcourt.domain.appeal_fsm import begin_appeal_review, submit_appeal

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64


def _case(*, with_automatic: bool = True) -> ClosedCaseAppealAuthority:
    automatic = (
        (
            AutomaticPrecedentAppealAuthority(
                precedent_id="automatic-1",
                precedent_authority_id=SHA_E,
                precedent_revision=3,
                status=PrecedentStatus.ACTIVE,
                decision_direction=VerdictDecision.ESTABLISHED,
                source_case_id="case-1",
                citations=(
                    AffectedPrecedentCitation(
                        source_citation_id=SHA_A,
                        citing_case_id="citing-case-1",
                        precedent_id="automatic-1",
                        similarity_score=0.91,
                    ),
                    AffectedPrecedentCitation(
                        source_citation_id=SHA_B,
                        citing_case_id="citing-case-2",
                        precedent_id="automatic-1",
                        similarity_score=0.72,
                    ),
                ),
            ),
        )
        if with_automatic
        else ()
    )
    return ClosedCaseAppealAuthority(
        run_id="run-1",
        case_id="case-1",
        case_revision=8,
        verdict_id=SHA_A,
        verdict_version=2,
        verdict_sha256=SHA_B,
        final_decision=VerdictDecision.ESTABLISHED,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        alerts=(AppealableAlertAuthority(alert_id="alert-1"),),
        automatic_precedents=automatic,
        detector_manifest_id=SHA_C,
        text_embedding_manifest_id=SHA_A,
        visual_embedding_manifest_id=SHA_B,
        manifest_id=SHA_D,
        config_sha256=SHA_E,
        rule_version="rules-v1",
    )


def _reviewed(case: ClosedCaseAppealAuthority):  # type: ignore[no-untyped-def]
    submitted = submit_appeal(
        case,
        AppealSubmissionCommand(
            run_id=case.run_id,
            case_id=case.case_id,
            appeal_id="appeal-1",
            expected_case_revision=case.case_revision,
            expected_case_authority_sha256=case.authority_sha256,
            reason="The adjudication conflicts with the reviewed evidence.",
            submitted_by="subject-1",
        ),
        None,
    )
    return begin_appeal_review(
        submitted,
        AppealReviewCommand(
            run_id=case.run_id,
            case_id=case.case_id,
            appeal_id="appeal-1",
            expected_appeal_authority_sha256=submitted.authority_sha256,
            reviewer_id="reviewer-1",
        ),
    )


def _snapshot(case: ClosedCaseAppealAuthority) -> AppealResolutionPrecedentSnapshot:
    return AppealResolutionPrecedentSnapshot(
        run_id=case.run_id,
        case_id=case.case_id,
        automatic_precedents=case.automatic_precedents,
    )


def _labels(
    reviewed: AppealVersionAuthority,
    status: AppealStatus,
) -> tuple[TrainingLabel, ...]:
    return build_m5_appeal_training_labels(
        appeal_authority=reviewed,
        terminal_status=status,
        authored_inputs=(
            M5AppealTrainingLabelInput(
                crop_id=SHA_E,
                bbox=BBoxXYXY(x1=10, y1=10, x2=30, y2=30),
                label_name="reagent_container_closed",
                label_value=True,
            ),
        ),
    )


def _replacement(
    *,
    case: ClosedCaseAppealAuthority | None = None,
    decision: VerdictDecision = VerdictDecision.NOT_ESTABLISHED,
) -> M5PrecedentAuthority:
    source = case or _case()
    situation = canonical_json(
        {
            "schema_version": "m5-appeal-overturn-precedent-situation-v1",
            "appeal_id": "appeal-1",
            "case_id": source.case_id,
            "source_case_authority_sha256": source.authority_sha256,
            "source_verdict_sha256": source.verdict_sha256,
            "source_decision": source.final_decision.value,
            "resolved_decision": decision.value,
            "evidence_class": source.evidence_class.value,
            "violation_type": source.violation_type.value,
            "rule_version": source.rule_version,
            "human_authored_situation": (
                "Human appeal found the container was closed in the cited crop."
            ),
        }
    )
    precedent_id = sha256_hex(
        [
            "m5-appeal-overturn-precedent",
            1,
            source.run_id,
            source.case_id,
            "appeal-1",
            source.authority_sha256,
            decision,
            hashlib.sha256(situation.encode("utf-8")).hexdigest(),
        ]
    )
    text_embedding = M5EmbeddingVector(
        request=M5EmbeddingRequest(
            channel=M5EmbeddingChannel.TEXT,
            input_ref=precedent_id,
            input_sha256=SHA_E,
            model_manifest_id=SHA_A,
            dimensions=2,
        ),
        values=(1.0, 0.0),
    )
    policy = M5PrecedentPolicy(
        config_sha256=SHA_E,
        text_weight=0.7,
        visual_weight=0.3,
        source_weights={source: 1.0 for source in PrecedentSource},
        source_priorities={source: index for index, source in enumerate(PrecedentSource)},
        conflict_similarity=0.55,
        automatic_activation_delay_seconds=86_400,
    )
    return create_m5_precedent_authority(
        run_id=source.run_id,
        precedent_id=precedent_id,
        situation_text=situation,
        decision_direction=decision,
        source=PrecedentSource.APPEAL_OVERTURN,
        evidence_class=source.evidence_class,
        violation_type=source.violation_type,
        rule_version=source.rule_version,
        source_case_id=source.case_id,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        policy=policy,
        text_embedding=text_embedding,
    )


def _overturn_command(case: ClosedCaseAppealAuthority):  # type: ignore[no-untyped-def]
    reviewed = _reviewed(case)
    return reviewed, AppealResolutionCommand(
        run_id=case.run_id,
        case_id=case.case_id,
        appeal_id="appeal-1",
        expected_appeal_authority_sha256=reviewed.authority_sha256,
        status=AppealStatus.OVERTURNED,
        reviewer_id="reviewer-1",
        resolution_summary="The human reviewer overturned the original decision.",
        resolved_decision=VerdictDecision.NOT_ESTABLISHED,
        appeal_precedent_authority=_replacement(case=case),
        training_labels=_labels(reviewed, AppealStatus.OVERTURNED),
    )


def test_overturn_builds_complete_preserving_atomic_side_effect_intent() -> None:
    case = _case()
    reviewed, command = _overturn_command(case)
    intent = build_appeal_resolution_intent(
        case_authority=case,
        appeal_authority=reviewed,
        precedent_snapshot=_snapshot(case),
        command=command,
    )
    assert intent.appeal_authority.appeal.status == AppealStatus.OVERTURNED
    assert intent.final_decision == VerdictDecision.NOT_ESTABLISHED
    assert intent.final_decision_changed
    assert intent.verdict_rescission is not None
    assert intent.verdict_rescission.verdict_id == case.verdict_id
    assert tuple(item.alert_id for item in intent.alert_rescissions) == ("alert-1",)
    assert tuple(item.precedent_id for item in intent.precedent_revocations) == ("automatic-1",)
    assert intent.precedent_revocations[0].status == PrecedentStatus.REVOKED
    assert intent.appeal_precedent_authority == command.appeal_precedent_authority
    assert intent.appeal_precedent_authority is not None
    assert intent.appeal_precedent_authority.precedent.status == PrecedentStatus.ACTIVE
    assert intent.appeal_precedent_authority.precedent.source == PrecedentSource.APPEAL_OVERTURN
    assert intent.training_labels[0].quality == TrainingLabelQuality.APPEAL_CONFIRMED
    assert tuple(item.citing_case_id for item in intent.affected_citations.citations) == (
        "citing-case-1",
        "citing-case-2",
    )

    replay = build_appeal_resolution_intent(
        case_authority=case,
        appeal_authority=reviewed,
        precedent_snapshot=_snapshot(case),
        command=command,
    )
    assert replay == intent
    assert replay.intent_id == intent.intent_id


def test_upheld_can_emit_human_confirmation_without_changing_decision() -> None:
    case = _case()
    reviewed = _reviewed(case)
    command = AppealResolutionCommand(
        run_id=case.run_id,
        case_id=case.case_id,
        appeal_id="appeal-1",
        expected_appeal_authority_sha256=reviewed.authority_sha256,
        status=AppealStatus.UPHELD,
        reviewer_id="reviewer-1",
        resolution_summary="The human reviewer upheld the original decision.",
        resolved_decision=VerdictDecision.ESTABLISHED,
        training_labels=_labels(reviewed, AppealStatus.UPHELD),
    )
    intent = build_appeal_resolution_intent(
        case_authority=case,
        appeal_authority=reviewed,
        precedent_snapshot=_snapshot(case),
        command=command,
    )
    assert not intent.final_decision_changed
    assert intent.verdict_rescission is None
    assert intent.alert_rescissions == ()
    assert intent.precedent_revocations == ()
    assert intent.appeal_precedent_authority is None
    assert intent.affected_citations.citations == ()
    assert intent.training_labels[0].quality == TrainingLabelQuality.HUMAN_CONFIRMED


def test_overturn_requires_original_automatic_precedent_to_revoke() -> None:
    case = _case(with_automatic=False)
    reviewed, command = _overturn_command(case)
    with pytest.raises(AppealResolutionError) as failure:
        build_appeal_resolution_intent(
            case_authority=case,
            appeal_authority=reviewed,
            precedent_snapshot=_snapshot(case),
            command=command,
        )
    assert failure.value.reason_code == AppealResolutionFailureCode.AUTOMATIC_PRECEDENT_REQUIRED


def test_overturn_rejects_missing_appeal_confirmation_label() -> None:
    case = _case()
    reviewed, command = _overturn_command(case)
    command = command.model_copy(update={"training_labels": ()})
    with pytest.raises(AppealResolutionError) as failure:
        build_appeal_resolution_intent(
            case_authority=case,
            appeal_authority=reviewed,
            precedent_snapshot=_snapshot(case),
            command=command,
        )
    assert failure.value.reason_code == AppealResolutionFailureCode.TRAINING_LABELS_INVALID


def test_resolution_rejects_caller_forged_training_label_authority_fields() -> None:
    case = _case()
    reviewed, command = _overturn_command(case)
    forged = command.training_labels[0].model_copy(
        update={"source": "caller-asserted-ground-truth"}
    )
    command = command.model_copy(update={"training_labels": (forged,)})

    with pytest.raises(AppealResolutionError) as failure:
        build_appeal_resolution_intent(
            case_authority=case,
            appeal_authority=reviewed,
            precedent_snapshot=_snapshot(case),
            command=command,
        )

    assert failure.value.reason_code == AppealResolutionFailureCode.TRAINING_LABELS_INVALID


def test_replacement_precedent_must_match_case_direction_type_and_rule() -> None:
    case = _case()
    reviewed, command = _overturn_command(case)
    command = command.model_copy(
        update={
            "appeal_precedent_authority": _replacement(
                case=case,
                decision=VerdictDecision.ESTABLISHED,
            )
        }
    )
    with pytest.raises(AppealResolutionError) as failure:
        build_appeal_resolution_intent(
            case_authority=case,
            appeal_authority=reviewed,
            precedent_snapshot=_snapshot(case),
            command=command,
        )
    assert failure.value.reason_code == AppealResolutionFailureCode.REPLACEMENT_PRECEDENT_INVALID


def test_replacement_precedent_must_match_closed_case_config_authority() -> None:
    case = _case()
    reviewed, command = _overturn_command(case)
    foreign = _replacement(case=case).model_copy(update={"config_sha256": SHA_D})
    command = command.model_copy(update={"appeal_precedent_authority": foreign})

    with pytest.raises(AppealResolutionError) as failure:
        build_appeal_resolution_intent(
            case_authority=case,
            appeal_authority=reviewed,
            precedent_snapshot=_snapshot(case),
            command=command,
        )

    assert failure.value.reason_code == AppealResolutionFailureCode.REPLACEMENT_PRECEDENT_INVALID


def test_replacement_precedent_rejects_rehashed_canonical_projection_tamper() -> None:
    case = _case()
    reviewed, command = _overturn_command(case)
    replacement = command.appeal_precedent_authority
    assert replacement is not None
    projection = json.loads(replacement.precedent.situation_text)
    projection["source_verdict_sha256"] = SHA_A
    forged_situation = canonical_json(projection)
    forged_id = sha256_hex(
        [
            "m5-appeal-overturn-precedent",
            1,
            case.run_id,
            case.case_id,
            command.appeal_id,
            case.authority_sha256,
            command.resolved_decision,
            hashlib.sha256(forged_situation.encode("utf-8")).hexdigest(),
        ]
    )
    forged_precedent = replacement.precedent.model_copy(
        update={
            "precedent_id": forged_id,
            "situation_text": forged_situation,
        }
    )
    forged_authority = replacement.model_copy(update={"precedent": forged_precedent})
    forged_command = command.model_copy(update={"appeal_precedent_authority": forged_authority})

    with pytest.raises(AppealResolutionError) as failure:
        build_appeal_resolution_intent(
            case_authority=case,
            appeal_authority=reviewed,
            precedent_snapshot=_snapshot(case),
            command=forged_command,
        )

    assert failure.value.reason_code == AppealResolutionFailureCode.REPLACEMENT_PRECEDENT_INVALID


def test_upheld_rejects_overturn_only_precedent_effect() -> None:
    case = _case()
    reviewed = _reviewed(case)
    command = AppealResolutionCommand(
        run_id=case.run_id,
        case_id=case.case_id,
        appeal_id="appeal-1",
        expected_appeal_authority_sha256=reviewed.authority_sha256,
        status=AppealStatus.UPHELD,
        reviewer_id="reviewer-1",
        resolution_summary="The human reviewer upheld the original decision.",
        resolved_decision=VerdictDecision.ESTABLISHED,
        appeal_precedent_authority=_replacement(
            case=case,
            decision=VerdictDecision.ESTABLISHED,
        ),
    )
    with pytest.raises(AppealResolutionError) as failure:
        build_appeal_resolution_intent(
            case_authority=case,
            appeal_authority=reviewed,
            precedent_snapshot=_snapshot(case),
            command=command,
        )
    assert failure.value.reason_code == AppealResolutionFailureCode.UPHELD_EFFECT_INVALID


def test_resolution_uses_a_fresh_complete_precedent_snapshot_without_rebinding_case() -> None:
    case = _case()
    reviewed, command = _overturn_command(case)
    submitted_precedent = case.automatic_precedents[0]
    fresh_citation = AffectedPrecedentCitation(
        source_citation_id=SHA_C,
        citing_case_id="citing-case-3",
        precedent_id=submitted_precedent.precedent_id,
        similarity_score=2.5,
    )
    current = submitted_precedent.model_copy(
        update={
            "precedent_authority_id": SHA_C,
            "precedent_revision": submitted_precedent.precedent_revision + 1,
            "citations": (*submitted_precedent.citations, fresh_citation),
        }
    )
    snapshot = AppealResolutionPrecedentSnapshot(
        run_id=case.run_id,
        case_id=case.case_id,
        automatic_precedents=(current,),
    )

    intent = build_appeal_resolution_intent(
        case_authority=case,
        appeal_authority=reviewed,
        precedent_snapshot=snapshot,
        command=command,
    )

    assert intent.appeal_authority.source_case_authority_sha256 == case.authority_sha256
    assert intent.precedent_revocations[0].prior_authority_id == SHA_C
    assert intent.precedent_revocations[0].prior_revision == 4
    assert tuple(citation.citing_case_id for citation in intent.affected_citations.citations) == (
        "citing-case-1",
        "citing-case-2",
        "citing-case-3",
    )
    assert intent.precedent_snapshot.snapshot_sha256 == snapshot.snapshot_sha256
    assert any(citation.similarity_score == 2.5 for citation in intent.affected_citations.citations)

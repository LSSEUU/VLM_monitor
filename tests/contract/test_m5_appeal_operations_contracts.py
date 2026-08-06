from __future__ import annotations

import pytest

from labcourt.contracts.enums import AppealStatus, VerdictDecision
from labcourt.contracts.m5_appeal_operations import (
    M5AppealResolutionCommandReport,
    M5AppealReviewCommandReport,
    M5AppealSubmissionCommandReport,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64


def test_submission_and_review_reports_bind_the_append_only_case_revisions() -> None:
    submitted = M5AppealSubmissionCommandReport(
        run_id="run-01",
        case_id="case-01",
        appeal_id="appeal-01",
        source_case_revision=8,
        committed_case_revision=9,
        appeal_authority_sha256=SHA_A,
    )
    reviewed = M5AppealReviewCommandReport(
        run_id=submitted.run_id,
        case_id=submitted.case_id,
        appeal_id=submitted.appeal_id,
        source_case_revision=submitted.source_case_revision,
        committed_case_revision=10,
        reviewer_id="reviewer-01",
        previous_appeal_authority_sha256=submitted.appeal_authority_sha256,
        appeal_authority_sha256=SHA_B,
    )

    assert submitted.status == AppealStatus.SUBMITTED
    assert reviewed.status == AppealStatus.UNDER_REVIEW
    assert (
        M5AppealSubmissionCommandReport.model_validate_json(submitted.model_dump_json())
        == submitted
    )
    assert M5AppealReviewCommandReport.model_validate_json(reviewed.model_dump_json()) == reviewed

    with pytest.raises(ValueError, match="adjacent"):
        submitted.model_copy(update={"committed_case_revision": 10})
    with pytest.raises(ValueError, match="follow submission"):
        reviewed.model_copy(update={"committed_case_revision": 9})
    with pytest.raises(ValueError, match="differ"):
        reviewed.model_copy(update={"appeal_authority_sha256": SHA_A})


def _overturn_report() -> M5AppealResolutionCommandReport:
    return M5AppealResolutionCommandReport(
        run_id="run-01",
        case_id="case-01",
        appeal_id="appeal-01",
        source_case_revision=8,
        committed_case_revision=11,
        status=AppealStatus.OVERTURNED,
        reviewer_id="reviewer-01",
        source_decision=VerdictDecision.ESTABLISHED,
        final_decision=VerdictDecision.NOT_ESTABLISHED,
        previous_appeal_authority_sha256=SHA_A,
        appeal_authority_sha256=SHA_B,
        precedent_snapshot_sha256=SHA_C,
        affected_citation_report_sha256=SHA_D,
        resolution_intent_id=SHA_E,
        rescinded_alert_ids=("alert-01", "alert-02"),
        revoked_precedent_ids=("precedent-01",),
        replacement_precedent_id="precedent-appeal-01",
        training_label_ids=("label-01",),
        affected_citation_case_ids=("case-affected-01", "case-affected-02"),
    )


def test_terminal_report_enforces_status_effect_matrix_and_stable_identities() -> None:
    report = _overturn_report()
    assert M5AppealResolutionCommandReport.model_validate_json(report.model_dump_json()) == report

    with pytest.raises(ValueError, match="stable order"):
        report.model_copy(update={"rescinded_alert_ids": ("alert-02", "alert-01")})
    with pytest.raises(ValueError, match="requires revocation"):
        report.model_copy(update={"revoked_precedent_ids": ()})
    with pytest.raises(ValueError, match="must change"):
        report.model_copy(update={"final_decision": VerdictDecision.ESTABLISHED})

    upheld = report.model_copy(
        update={
            "status": AppealStatus.UPHELD,
            "final_decision": VerdictDecision.ESTABLISHED,
            "rescinded_alert_ids": (),
            "revoked_precedent_ids": (),
            "replacement_precedent_id": None,
            "training_label_ids": ("label-human-confirmed-01",),
            "affected_citation_case_ids": (),
        }
    )
    assert upheld.status == AppealStatus.UPHELD
    assert upheld.training_label_ids == ("label-human-confirmed-01",)
    with pytest.raises(ValueError, match="overturn-only"):
        upheld.model_copy(update={"rescinded_alert_ids": ("alert-01",)})


def test_appeal_command_report_field_sets_are_explicit_and_additive() -> None:
    assert tuple(M5AppealSubmissionCommandReport.model_fields) == (
        "run_id",
        "case_id",
        "appeal_id",
        "source_case_revision",
        "committed_case_revision",
        "appeal_version",
        "status",
        "appeal_authority_sha256",
    )
    assert tuple(M5AppealReviewCommandReport.model_fields) == (
        "run_id",
        "case_id",
        "appeal_id",
        "source_case_revision",
        "committed_case_revision",
        "appeal_version",
        "status",
        "reviewer_id",
        "previous_appeal_authority_sha256",
        "appeal_authority_sha256",
    )
    assert tuple(M5AppealResolutionCommandReport.model_fields)[-5:] == (
        "rescinded_alert_ids",
        "revoked_precedent_ids",
        "replacement_precedent_id",
        "training_label_ids",
        "affected_citation_case_ids",
    )

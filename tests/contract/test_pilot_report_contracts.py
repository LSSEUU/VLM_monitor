from __future__ import annotations

import pytest
from pydantic import ValidationError

from labcourt.contracts.alert_policy import AlertPolicyDisposition
from labcourt.contracts.alerts import AlertDecision
from labcourt.contracts.enums import AlertLevel, AppealStatus, CaseStatus, VerdictDecision
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m5_appeal_operations import M5AppealResolutionCommandReport
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.contracts.m5_operations import (
    M5CloseCaseOutcome,
    M5DispatchCommandReport,
)
from labcourt.contracts.pilot import PilotA4CloseReport
from labcourt.contracts.pilot_report import (
    PILOT_OPERATOR_DISCLAIMER,
    PilotA4CaseView,
    PilotA4MediaView,
    PilotA4Metrics,
    PilotA4ModelVersion,
    PilotA4PublicationReport,
    PilotA4ReviewReport,
    PilotLocalAlertDocument,
)
from labcourt.schema_export import expected_schema_files


def _model(component: str, marker: str) -> PilotA4ModelVersion:
    return PilotA4ModelVersion(
        component=component,
        provider="provider",
        model=f"{component}-model",
        revision="1.0.0",
        model_manifest_id=marker * 64,
    )


def _case_view() -> PilotA4CaseView:
    return PilotA4CaseView(
        run_id="pilot-001",
        case_id="case-001",
        revision=5,
        status=CaseStatus.CLOSED,
        violation_type="PPE_GOGGLES_MISSING",
        start_frame=10,
        end_frame_exclusive=20,
        anonymous_track_ref="cam-01:epoch-01:track-01",
        association_start_frame=10,
        association_end_frame_exclusive=20,
        observed_frame_count=10,
        key_crops=(
            PilotA4MediaView(
                crop_id="1" * 64,
                role="TEMPORAL",
                frame_id="cam-01:stream-01:10",
                integrity="VERIFIED",
                run_relative_path="frames/crop.png",
                media_sha256="2" * 64,
                width=320,
                height=180,
            ),
        ),
        screening_decision="ESTABLISHED",
        screening_probability=0.92,
        screening_router_version="screening-router-v2",
        verdict_decision=VerdictDecision.ESTABLISHED,
        verdict_confidence=0.92,
        procedural_review_passed=True,
        procedural_gate_version="procedural-gate-v1",
        final_decision=VerdictDecision.ESTABLISHED,
        alert_level=AlertLevel.CONFIRMED,
        human_review_required=False,
        detector=_model("detector", "3"),
        screening_model=_model("screening", "4"),
        prompt_bundle_sha256="5" * 64,
        rule_version="laboratory-v1",
        manifest_id="6" * 64,
    )


def _closure() -> PilotA4CloseReport:
    return PilotA4CloseReport(
        run_id="pilot-001",
        manifest_id="6" * 64,
        config_sha256="7" * 64,
        selected_count=1,
        outcomes=(
            M5CloseCaseOutcome(
                case_id="case-001",
                source_revision=4,
                closed_revision=5,
                disposition=AlertPolicyDisposition.ENQUEUE,
                alert_id="8" * 64,
                alert_policy_authority_id="9" * 64,
                automatic_precedent_id="a" * 64,
                automatic_precedent_authority_id="b" * 64,
            ),
        ),
    )


def test_pilot_a4_metrics_and_publication_are_content_bound_and_exported() -> None:
    case = _case_view()
    metrics = PilotA4Metrics(
        run_id="pilot-001",
        manifest_id="6" * 64,
        config_sha256="7" * 64,
        case_count=1,
        closed_count=1,
        human_review_count=0,
        established_count=1,
        not_established_count=0,
        insufficient_evidence_count=0,
        unresolved_count=0,
        verified_local_alert_count=1,
        cases=(case,),
    )
    publication = PilotA4PublicationReport(
        closure=_closure(),
        dispatch=M5DispatchCommandReport(
            run_id="pilot-001",
            selected_count=0,
            succeeded_count=0,
            retryable_failure_count=0,
            unknown_delivery_count=0,
            attention_required_count=0,
            receipts=(),
        ),
        metrics=metrics,
        index_path="runs/pilot-001/report/index.html",
        metrics_path="runs/pilot-001/metrics.json",
        case_paths=("runs/pilot-001/report/cases/case-001.html",),
        local_alert_paths=(f"runs/pilot-001/alerts/{'8' * 64}.json",),
        projection_paths=(
            "runs/pilot-001/projections/current.json",
            "runs/pilot-001/m5-projections/current.json",
        ),
    )

    assert PilotA4Metrics.model_validate_json(metrics.model_dump_json()) == metrics
    assert (
        PilotA4PublicationReport.model_validate_json(publication.model_dump_json()) == publication
    )
    schemas = expected_schema_files()
    for filename in (
        "pilot-a4-case-view.schema.json",
        "pilot-a4-media-view.schema.json",
        "pilot-a4-metrics.schema.json",
        "pilot-a4-model-version.schema.json",
        "pilot-a4-publication-report.schema.json",
        "pilot-a4-review-report.schema.json",
        "pilot-local-alert-document.schema.json",
    ):
        assert filename in schemas

    payload = publication.model_dump(mode="python")
    payload["publication_id"] = "0" * 64
    with pytest.raises(ValidationError, match="publication_id"):
        PilotA4PublicationReport.model_validate(payload)


def test_pilot_a4_review_projects_one_explicit_overturn_label() -> None:
    label = M5AppealTrainingLabelInput(
        crop_id="1" * 64,
        bbox=BBoxXYXY(x1=0, y1=0, x2=320, y2=180),
        label_name="pilot_review:PPE_GOGGLES_MISSING",
        label_value=VerdictDecision.NOT_ESTABLISHED.value,
    )
    resolution = M5AppealResolutionCommandReport(
        run_id="pilot-001",
        case_id="case-001",
        appeal_id="appeal-001",
        source_case_revision=5,
        committed_case_revision=8,
        status=AppealStatus.OVERTURNED,
        reviewer_id="pilot-local-operator",
        source_decision=VerdictDecision.ESTABLISHED,
        final_decision=VerdictDecision.NOT_ESTABLISHED,
        previous_appeal_authority_sha256="2" * 64,
        appeal_authority_sha256="3" * 64,
        precedent_snapshot_sha256="4" * 64,
        affected_citation_report_sha256="5" * 64,
        resolution_intent_id="6" * 64,
        rescinded_alert_ids=("alert-001",),
        revoked_precedent_ids=("precedent-001",),
        replacement_precedent_id="precedent-002",
        training_label_ids=("label-001",),
    )
    report = PilotA4ReviewReport(
        run_id="pilot-001",
        case_id="case-001",
        source_decision=VerdictDecision.ESTABLISHED,
        requested_decision=VerdictDecision.NOT_ESTABLISHED,
        reason_sha256="7" * 64,
        manifest_id="8" * 64,
        resolution=resolution,
        review_label=label,
        publication_id="9" * 64,
        metrics_id="a" * 64,
        index_path="runs/pilot-001/report/index.html",
    )

    assert PilotA4ReviewReport.model_validate_json(report.model_dump_json()) == report
    assert report.production_delivery_count == 0
    payload = report.model_dump(mode="python", exclude_computed_fields=True)
    payload["review_label"] = None
    with pytest.raises(ValidationError, match="requires one appeal label"):
        PilotA4ReviewReport.model_validate(payload)


def test_pilot_a4_insufficient_evidence_remains_visible_for_human_attention() -> None:
    payload = _case_view().model_dump(mode="python", exclude_computed_fields=True)
    payload.update(
        verdict_decision=VerdictDecision.INSUFFICIENT_EVIDENCE,
        final_decision=VerdictDecision.INSUFFICIENT_EVIDENCE,
        alert_level=None,
        human_review_required=True,
    )
    case = PilotA4CaseView.model_validate(payload)

    assert case.human_review_required is True
    payload["human_review_required"] = False
    with pytest.raises(ValidationError, match="human-review flag"):
        PilotA4CaseView.model_validate(payload)


def test_local_alert_document_binds_exact_id_and_prohibits_production_action() -> None:
    alert = AlertDecision(
        alert_id="8" * 64,
        case_id="case-001",
        level=AlertLevel.CONFIRMED,
        recipients=("local-operator",),
        policy_rule_ids=("alert-policy-v1",),
    )
    document = PilotLocalAlertDocument(
        run_id="pilot-001",
        case_id="case-001",
        case_status=CaseStatus.CLOSED,
        final_decision=VerdictDecision.ESTABLISHED,
        alert=alert,
        idempotency_key="8" * 64,
        manifest_id="6" * 64,
        config_sha256="7" * 64,
    )

    assert document.production_action_prohibited is True
    assert document.disclaimer == PILOT_OPERATOR_DISCLAIMER
    assert PilotLocalAlertDocument.model_validate_json(document.model_dump_json()) == document

    payload = document.model_dump(mode="python", exclude_computed_fields=True)
    payload["idempotency_key"] = "0" * 64
    with pytest.raises(ValidationError, match="exact deliverable"):
        PilotLocalAlertDocument.model_validate(payload)

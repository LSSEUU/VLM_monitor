from __future__ import annotations

from pathlib import Path
from typing import TypeVar, cast

import pytest
from pydantic import BaseModel

from labcourt.application.alert_policy_verifier import (
    AlertPolicyVerificationError,
    ConfiguredAlertPolicyVerifier,
)
from labcourt.config_loader import load_config
from labcourt.contracts.alert_policy import AlertPolicyDisposition, AlertPolicyFailureCode
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    AlertLevel,
    ArtifactKind,
    CaseStatus,
    RiskLevel,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.evidence import EvidencePack, EvidencePackDraft
from labcourt.contracts.manifests import (
    RunManifest,
    SoftwareComponentManifest,
    StreamManifest,
)
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.contracts.verdicts import ObservationSufficiency
from labcourt.domain.alert_policy import (
    CONFIDENCE_GATE_RULE,
    EMERGENCY_CAP_RULE,
    FRAME_COOLDOWN_RULE,
    HARD_SIGNAL_MERGE_RULE,
    INSUFFICIENT_RULE,
    AlertPolicyError,
    evaluate_alert_policy,
    plan_case_alert,
)
from tests.contract.test_m3_contracts import (
    _parsed,
    _presence_pack,
    _review,
    _screening,
    _verdict,
)
from tests.contract.test_m5_alert_contracts import (
    _cooldown,
    _emergency_delivery,
    _request,
)

ROOT = Path(__file__).parents[2]

ModelT = TypeVar("ModelT", bound=BaseModel)


def _unsafe_copy(model: ModelT, **update: object) -> ModelT:
    """Simulate a corrupted in-memory authority past the contract boundary."""

    return cast(ModelT, BaseModel.model_copy(model, update=update))


def _manifest_with_stream() -> RunManifest:
    base = RunManifest.model_validate_json(
        (ROOT / "tests/fixtures/m2/run-manifest-fake.json").read_text(encoding="utf-8")
    )
    component = SoftwareComponentManifest(
        component="fixture-decoder",
        package="fixture-decoder",
        version="1.0.0",
        license_id="Proprietary",
    )
    stream = StreamManifest(
        camera_id="cam-01",
        stream_id="demo-ntsc",
        input_file_sha256="1" * 64,
        fps_num=30_000,
        fps_den=1_001,
        timing_mode="CFR",
        timing_authority="TRUSTED_SIDECAR",
        timing_evidence_type="TRUSTED_SIDECAR_JSON",
        timing_evidence_sha256="2" * 64,
        width=1280,
        height=720,
        frame_count=10_000,
        decoder="fixture",
        decoder_version="1.0.0",
        backend="fixture",
        software_component=component.component,
        library=component.package,
        library_version=component.version,
        codec="fake",
        color_conversion="IDENTITY",
        pixel_format="RGB8",
        pixel_hash_algorithm="LCPIX1",
    )
    return base.model_copy(
        update={
            "streams": (stream,),
            "software_components": {component.component: component},
        }
    )


def _ready_case(manifest: RunManifest) -> Case:
    base = _presence_pack()
    event = base.event.model_copy(update={"manifest_id": manifest.manifest_id})
    draft = EvidencePackDraft(
        run_id=base.run_id,
        case_id=base.case_id,
        version=base.version,
        complete=base.complete,
        event=event,
        key_frame_ids=base.key_frame_ids,
        panorama_crops=base.panorama_crops,
        subject_crops=base.subject_crops,
        focus_crops=base.focus_crops,
        temporal_crops=base.temporal_crops,
        objective_facts=base.objective_facts,
        track_summary=base.track_summary,
        confirmation_record=base.confirmation_record,
        observation_sufficiency_input=base.observation_sufficiency_input,
        tool_results=base.tool_results,
        manifest_id=manifest.manifest_id,
    )
    pack = EvidencePack(
        **draft.model_dump(mode="python", exclude={"pack_id"}),
        closure_report=ClosureReport(
            run_id=draft.run_id,
            root_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=draft.case_id),
            manifest_id=draft.manifest_id,
            input_sha256=draft.closure_input_sha256,
            checked_refs=draft.expected_closure_refs(),
        ),
    )
    parsed = _parsed(
        run_id=pack.run_id,
        case_id=pack.case_id,
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        violation_type=pack.event.violation_type,
        evidence_class=pack.event.evidence_class,
        manifest_id=pack.manifest_id,
    )
    screening = _screening(parsed, l1_score=pack.event.l1_score)
    verdict = _verdict(screening)
    review = _review(verdict)
    return Case(
        run_id=pack.run_id,
        status=CaseStatus.READY_FOR_ALERT_POLICY,
        event=pack.event,
        evidence_packs=(pack,),
        screening_results=(screening,),
        verdicts=(verdict,),
        procedural_reviews=(review,),
        manifest_id=pack.manifest_id,
    )


def test_ready_l5_case_builds_exact_atomic_close_and_outbox_intent() -> None:
    manifest = _manifest_with_stream()
    case = _ready_case(manifest)
    authority = plan_case_alert(case, load_config(ROOT / "configs/demo.yaml"), manifest)

    assert authority.disposition == AlertPolicyDisposition.ENQUEUE
    assert authority.target_case_status == CaseStatus.CLOSED
    assert authority.outbox_item is not None
    assert authority.outbox_item.idempotency_key == authority.decision.alert_id  # type: ignore[union-attr]
    assert authority.request.cooldown_frames == 1_799


def test_configured_verifier_rebuilds_only_manifest_pinned_policy() -> None:
    config = load_config(ROOT / "configs/demo.yaml")
    manifest = _manifest_with_stream()
    case = _ready_case(manifest)
    verifier = ConfiguredAlertPolicyVerifier(config)

    assert verifier.rebuild(case, manifest, None, None) == plan_case_alert(
        case,
        config,
        manifest,
    )

    unpinned = manifest.model_copy(update={"config_sha256": "0" * 64})
    with pytest.raises(AlertPolicyVerificationError, match="not pinned"):
        verifier.rebuild(case, unpinned, None, None)


def test_non_ready_case_cannot_bypass_l5_alert_boundary() -> None:
    manifest = _manifest_with_stream()
    ready = _ready_case(manifest)
    screened = ready.model_copy(
        update={
            "status": CaseStatus.SCREENED,
            "verdicts": (),
            "procedural_reviews": (),
        }
    )
    with pytest.raises(AlertPolicyError) as captured:
        plan_case_alert(screened, load_config(ROOT / "configs/demo.yaml"), manifest)
    assert captured.value.reason_code == AlertPolicyFailureCode.INVALID_CASE_STATE


def test_policy_boundaries_reject_untyped_inputs_and_failure_codes() -> None:
    manifest = _manifest_with_stream()
    case = _ready_case(manifest)
    config = load_config(ROOT / "configs/demo.yaml")

    with pytest.raises(TypeError, match="AlertPolicyFailureCode"):
        AlertPolicyError("INVALID_ARGUMENT")  # type: ignore[arg-type]
    with pytest.raises(AlertPolicyError) as request_failure:
        evaluate_alert_policy(None)  # type: ignore[arg-type]
    assert request_failure.value.reason_code == AlertPolicyFailureCode.INVALID_ARGUMENT

    with pytest.raises(AlertPolicyError) as case_failure:
        plan_case_alert(None, config, manifest)  # type: ignore[arg-type]
    assert case_failure.value.reason_code == AlertPolicyFailureCode.INVALID_ARGUMENT
    with pytest.raises(AlertPolicyError) as config_failure:
        plan_case_alert(case, None, manifest)  # type: ignore[arg-type]
    assert config_failure.value.reason_code == AlertPolicyFailureCode.INVALID_ARGUMENT
    with pytest.raises(AlertPolicyError) as manifest_failure:
        plan_case_alert(case, config, None)  # type: ignore[arg-type]
    assert manifest_failure.value.reason_code == AlertPolicyFailureCode.INVALID_ARGUMENT

    with pytest.raises(AlertPolicyError) as cooldown_failure:
        plan_case_alert(case, config, manifest, prior_cooldown=object())  # type: ignore[arg-type]
    assert cooldown_failure.value.reason_code == AlertPolicyFailureCode.INVALID_ARGUMENT
    with pytest.raises(AlertPolicyError) as emergency_failure:
        plan_case_alert(case, config, manifest, prior_emergency_delivery=object())  # type: ignore[arg-type]
    assert emergency_failure.value.reason_code == AlertPolicyFailureCode.INVALID_ARGUMENT


def test_case_plan_fails_closed_for_missing_or_mismatched_review_authority() -> None:
    manifest = _manifest_with_stream()
    case = _ready_case(manifest)
    config = load_config(ROOT / "configs/demo.yaml")
    verdict = case.verdicts[-1]
    review = case.procedural_reviews[-1]

    invalid_cases = [
        _unsafe_copy(case, verdicts=(), procedural_reviews=()),
        _unsafe_copy(case, procedural_reviews=()),
        _unsafe_copy(
            case,
            procedural_reviews=(_unsafe_copy(review, defects=(object(),)),),
        ),
        _unsafe_copy(
            case,
            procedural_reviews=(_unsafe_copy(review, reviewed_verdict_id="0" * 64),),
        ),
        _unsafe_copy(
            case,
            procedural_reviews=(_unsafe_copy(review, reviewed_verdict_version=2),),
        ),
        _unsafe_copy(
            case,
            procedural_reviews=(_unsafe_copy(review, reviewed_verdict_sha256="0" * 64),),
        ),
    ]
    mismatched_verdict = verdict.model_copy(update={"violation_type": ViolationType.OPEN_FLAME})
    invalid_cases.append(
        _unsafe_copy(
            case,
            verdicts=(mismatched_verdict,),
            procedural_reviews=(_review(mismatched_verdict),),
        )
    )

    for invalid_case in invalid_cases:
        with pytest.raises(AlertPolicyError) as failure:
            plan_case_alert(invalid_case, config, manifest)
        assert failure.value.reason_code == AlertPolicyFailureCode.REVIEW_AUTHORITY_MISMATCH


def test_case_plan_fails_closed_for_every_external_authority_root() -> None:
    manifest = _manifest_with_stream()
    case = _ready_case(manifest)
    config = load_config(ROOT / "configs/demo.yaml")

    manifest_mismatch = _unsafe_copy(case, manifest_id="0" * 64)
    with pytest.raises(AlertPolicyError) as manifest_failure:
        plan_case_alert(manifest_mismatch, config, manifest)
    assert manifest_failure.value.reason_code == AlertPolicyFailureCode.MANIFEST_AUTHORITY_MISMATCH

    config_mismatch = _unsafe_copy(config, rule_version="laboratory-v2")
    with pytest.raises(AlertPolicyError) as config_failure:
        plan_case_alert(case, config_mismatch, manifest)
    assert config_failure.value.reason_code == AlertPolicyFailureCode.CONFIG_AUTHORITY_MISMATCH

    rule_mismatch = _unsafe_copy(
        case,
        event=_unsafe_copy(case.event, rule_version="laboratory-v2"),
    )
    with pytest.raises(AlertPolicyError) as rule_failure:
        plan_case_alert(rule_mismatch, config, manifest)
    assert rule_failure.value.reason_code == AlertPolicyFailureCode.CONFIG_AUTHORITY_MISMATCH

    unknown_zone = _unsafe_copy(
        case,
        event=_unsafe_copy(case.event, zone_id="unknown-zone"),
    )
    with pytest.raises(AlertPolicyError) as zone_failure:
        plan_case_alert(unknown_zone, config, manifest)
    assert zone_failure.value.reason_code == AlertPolicyFailureCode.ZONE_AUTHORITY_MISMATCH

    wrong_zone_camera = _unsafe_copy(
        case,
        event=_unsafe_copy(case.event, camera_id="cam-02"),
    )
    with pytest.raises(AlertPolicyError) as camera_failure:
        plan_case_alert(wrong_zone_camera, config, manifest)
    assert camera_failure.value.reason_code == AlertPolicyFailureCode.ZONE_AUTHORITY_MISMATCH

    unknown_stream = _unsafe_copy(
        case,
        event=_unsafe_copy(case.event, stream_id="unknown-stream"),
    )
    with pytest.raises(AlertPolicyError) as stream_failure:
        plan_case_alert(unknown_stream, config, manifest)
    assert stream_failure.value.reason_code == AlertPolicyFailureCode.STREAM_AUTHORITY_MISMATCH


def test_case_plan_binds_nonempty_observation_sufficiency() -> None:
    manifest = _manifest_with_stream()
    case = _ready_case(manifest)
    verdict = case.verdicts[-1].model_copy(
        update={
            "observation_sufficiency": ObservationSufficiency(
                clear_threshold=0.65,
                required_clear_count=2,
            )
        }
    )
    case_with_observation = case.model_copy(
        update={
            "verdicts": (verdict,),
            "procedural_reviews": (_review(verdict),),
        }
    )

    authority = plan_case_alert(
        case_with_observation,
        load_config(ROOT / "configs/demo.yaml"),
        manifest,
    )

    assert authority.request.observation_sufficiency_sha256 is not None


def test_case_plan_maps_contract_reconstruction_errors_to_typed_failures() -> None:
    manifest = _manifest_with_stream()
    case = _ready_case(manifest)
    config = load_config(ROOT / "configs/demo.yaml")

    wrong_track = _unsafe_copy(
        case,
        event=_unsafe_copy(
            case.event,
            primary_track_ref="cam-02:epoch-01:bottle-01",
        ),
    )
    with pytest.raises(AlertPolicyError) as invalid_failure:
        plan_case_alert(wrong_track, config, manifest)
    assert invalid_failure.value.reason_code == AlertPolicyFailureCode.INVALID_ARGUMENT

    with pytest.raises(AlertPolicyError) as emergency_failure:
        plan_case_alert(
            case,
            config,
            manifest,
            prior_emergency_delivery=_emergency_delivery(),
        )
    assert (
        emergency_failure.value.reason_code
        == AlertPolicyFailureCode.EMERGENCY_DELIVERY_AUTHORITY_MISMATCH
    )


def test_insufficient_and_low_confidence_are_capped_before_delivery() -> None:
    insufficient = evaluate_alert_policy(
        _request().model_copy(
            update={
                "verdict_decision": VerdictDecision.INSUFFICIENT_EVIDENCE,
                "recommended_alert_level": AlertLevel.EMERGENCY,
            }
        )
    )
    assert insufficient.decision is not None
    assert insufficient.decision.level == AlertLevel.ADVISORY
    assert insufficient.decision.human_review_required
    assert INSUFFICIENT_RULE in insufficient.policy_rule_ids

    low_confidence = evaluate_alert_policy(
        _request().model_copy(
            update={
                "recommended_alert_level": AlertLevel.CONFIRMED,
                "verdict_confidence": 0.79,
            }
        )
    )
    assert low_confidence.decision is not None
    assert low_confidence.decision.level == AlertLevel.ADVISORY
    assert CONFIDENCE_GATE_RULE in low_confidence.policy_rule_ids


def test_emergency_requires_both_a_hard_rule_and_a_high_risk_zone() -> None:
    non_hard = evaluate_alert_policy(_request().model_copy(update={"hard_rule": False}))
    assert non_hard.decision is not None
    assert non_hard.decision.level == AlertLevel.CONFIRMED
    assert EMERGENCY_CAP_RULE in non_hard.policy_rule_ids

    non_high_risk = evaluate_alert_policy(
        _request().model_copy(update={"zone_risk": RiskLevel.MEDIUM})
    )
    assert non_high_risk.decision is not None
    assert non_high_risk.decision.level == AlertLevel.CONFIRMED
    assert EMERGENCY_CAP_RULE in non_high_risk.policy_rule_ids

    advisory = evaluate_alert_policy(
        _request().model_copy(update={"recommended_alert_level": AlertLevel.ADVISORY})
    )
    assert advisory.decision is not None
    assert advisory.decision.level == AlertLevel.ADVISORY
    assert not advisory.decision.human_review_required


def test_not_established_closes_without_creating_or_suppressing_an_alert() -> None:
    authority = evaluate_alert_policy(
        _request().model_copy(
            update={
                "verdict_decision": VerdictDecision.NOT_ESTABLISHED,
                "recommended_alert_level": AlertLevel.ADVISORY,
            }
        )
    )
    assert authority.disposition == AlertPolicyDisposition.CLOSE_NO_ALERT
    assert authority.decision is None
    assert authority.outbox_item is None


def test_frame_cooldown_merges_only_the_same_complete_tracker_epoch_key() -> None:
    same_epoch = _cooldown().model_copy(
        update={
            "source_trigger_frame": 90,
            "cooldown_until_frame_exclusive": 1_890,
        }
    )
    merged = evaluate_alert_policy(_request(prior_cooldown=same_epoch))
    assert merged.disposition == AlertPolicyDisposition.SUPPRESSED_MERGED
    assert merged.decision is not None
    assert merged.decision.merged_into_alert_id == same_epoch.source_alert_id
    assert FRAME_COOLDOWN_RULE in merged.policy_rule_ids

    other_epoch = evaluate_alert_policy(_request(prior_cooldown=_cooldown(epoch="epoch-02")))
    assert other_epoch.disposition == AlertPolicyDisposition.ENQUEUE
    assert other_epoch.outbox_item is not None


def test_frame_cooldown_rejects_cross_stream_and_frame_regression_authority() -> None:
    wrong_stream = _cooldown().model_copy(update={"stream_id": "stream-02"})
    with pytest.raises(AlertPolicyError) as stream_failure:
        evaluate_alert_policy(_request(prior_cooldown=wrong_stream))
    assert stream_failure.value.reason_code == AlertPolicyFailureCode.STREAM_AUTHORITY_MISMATCH

    future_source = _cooldown().model_copy(
        update={
            "source_trigger_frame": 101,
            "cooldown_until_frame_exclusive": 1_901,
        }
    )
    with pytest.raises(AlertPolicyError) as frame_failure:
        evaluate_alert_policy(_request(prior_cooldown=future_source))
    assert frame_failure.value.reason_code == AlertPolicyFailureCode.COOLDOWN_FRAME_REGRESSION


def test_frame_cooldown_exclusive_boundary_and_untracked_cases_enqueue() -> None:
    expired = _cooldown().model_copy(
        update={
            "source_trigger_frame": 90,
            "cooldown_frames": 10,
            "cooldown_until_frame_exclusive": 100,
        }
    )
    boundary = evaluate_alert_policy(_request(prior_cooldown=expired))
    assert boundary.disposition == AlertPolicyDisposition.ENQUEUE
    assert boundary.cooldown_write is not None

    untracked = evaluate_alert_policy(
        _request(prior_cooldown=_cooldown()).model_copy(update={"primary_track_ref": None})
    )
    assert untracked.disposition == AlertPolicyDisposition.ENQUEUE
    assert untracked.cooldown_write is None
    assert untracked.outbox_item is not None


def test_hard_signal_delivery_is_case_external_and_suppresses_supplement_re_send() -> None:
    authority = evaluate_alert_policy(_request(prior_emergency_delivery=_emergency_delivery()))
    assert authority.disposition == AlertPolicyDisposition.SUPPRESSED_MERGED
    assert authority.outbox_item is None
    assert authority.decision is not None
    assert authority.decision.merged_into_alert_id == "incident-01"
    assert HARD_SIGNAL_MERGE_RULE in authority.policy_rule_ids

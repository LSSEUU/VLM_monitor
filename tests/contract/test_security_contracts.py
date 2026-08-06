import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    AcquisitionAction,
    ArtifactKind,
    CaseStatus,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    ObjectiveFactKind,
    PrivacyPolicy,
    ViolationType,
    VlmRole,
)
from labcourt.contracts.events import CandidateEvent, ObjectiveFact
from labcourt.contracts.evidence import ToolResult
from labcourt.contracts.m3_models import PromptManifest, VlmCallBudget
from labcourt.contracts.screening import VLMMediaRef, VLMRequest
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import ObjectiveClaim
from labcourt.domain.ids import make_event_id
from labcourt.domain.timebase import duration_ms

FIXTURES = Path(__file__).parents[1] / "fixtures" / "m2"
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _presence_event_payload() -> dict[str, object]:
    return json.loads((FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8"))


def _media_ref(
    *,
    crop_id: str = SHA_D,
    source: CropSource = CropSource.SUBJECT,
    media_access: MediaAccess = MediaAccess.LOCAL_ONLY,
    transform_version: str = "privacy-v1",
) -> VLMMediaRef:
    return VLMMediaRef(
        crop_id=crop_id,
        media_sha256=SHA_A,
        local_path=f"run-01/frames/{SHA_A}.png",
        source=source,
        media_access=media_access,
        privacy_policy=PrivacyPolicy.PPE_PRESERVING_REDACTION,
        privacy_transform_version=transform_version,
        width=64,
        height=64,
    )


def _vlm_request(
    *,
    execution_location: ExecutionLocation = ExecutionLocation.LOCAL,
    media: tuple[VLMMediaRef, ...] | None = None,
    case_id: str = "case-01",
    evidence_pack_id: str = SHA_C,
    evidence_pack_version: int = 1,
) -> VLMRequest:
    return VLMRequest(
        run_id="run-01",
        case_id=case_id,
        evidence_pack_id=evidence_pack_id,
        evidence_pack_version=evidence_pack_version,
        provider_profile="screening-profile",
        provider="fixture",
        model="fixture-vlm",
        revision="1.0.0",
        model_manifest_id=SHA_A,
        execution_location=execution_location,
        role=VlmRole.SCREENING,
        prompt_manifest=PromptManifest(
            prompt_id="screening-v1",
            role=VlmRole.SCREENING,
            template_sha256=SHA_B,
            output_schema_sha256=SHA_C,
            prompt_bundle_sha256=SHA_D,
            renderer_version="jinja-3-1",
        ),
        rendered_prompt_sha256=SHA_B,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        evidence_class=EvidenceClass.PRESENCE,
        rule_summary="Check whether the reagent container is open.",
        media=media or (_media_ref(),),
        allowed_evidence_refs=tuple(
            ArtifactRef(kind=ArtifactKind.CROP, artifact_id=item.crop_id)
            for item in (media or (_media_ref(),))
        ),
        objective_summary={"duration_frames": 91},
        temperature=0.0,
        seed=7,
        budget=VlmCallBudget(
            max_images=4,
            max_input_pixels=100_000,
            max_output_tokens=1_024,
            pricing_currency="USD",
            input_cost_per_million_tokens=0.0,
            output_cost_per_million_tokens=0.0,
            max_estimated_cost=0.0,
            max_response_bytes=65_536,
            max_json_depth=8,
            max_json_fields=128,
            max_string_chars=8_192,
            timeout_seconds=15.0,
            claim_completion_grace_seconds=5.0,
        ),
        manifest_id=SHA_D,
    )


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        (ObjectiveFactKind.DURATION_FRAMES, True),
        (ObjectiveFactKind.PERSON_COUNT, -1),
        (ObjectiveFactKind.ZONE_ID, False),
        (ObjectiveFactKind.RISK_LEVEL, "impossible"),
        (ObjectiveFactKind.FRAME_INTERVAL, (2, 2)),
        (ObjectiveFactKind.DETECTION_SCORE, 9),
        (ObjectiveFactKind.OBSERVABILITY, "opaque"),
    ],
)
def test_objective_fact_and_claim_values_follow_their_kind(
    kind: ObjectiveFactKind,
    value: object,
) -> None:
    fact_payload = {
        "fact_id": "fact-01",
        "kind": kind,
        "value": value,
        "source_ref": {"kind": "FRAME", "artifact_id": "cam-01:stream-01:0"},
        "source_manifest_id": SHA_A,
    }
    with pytest.raises(ValidationError):
        ObjectiveFact.model_validate(fact_payload)
    with pytest.raises(ValidationError):
        ObjectiveClaim.model_validate(
            {
                "kind": kind,
                "value": value,
                "evidence_ref": {
                    "kind": ArtifactKind.OBJECTIVE_FACT,
                    "artifact_id": "fact-01",
                },
            }
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("hard_rule", "false"),
        ("l1_score", "0.92"),
        ("start_frame", True),
    ],
)
def test_candidate_event_rejects_wire_type_coercion(field: str, value: object) -> None:
    payload = _presence_event_payload()
    payload[field] = value
    with pytest.raises(ValidationError):
        CandidateEvent.model_validate(payload)


def test_candidate_event_rejects_cross_camera_pii_and_suppressed_records() -> None:
    payload = _presence_event_payload()
    payload["primary_track_ref"] = "other-cam:epoch-01:alice@example.com"
    with pytest.raises(ValidationError):
        CandidateEvent.model_validate(payload)

    payload = _presence_event_payload()
    confirmation = payload["confirmation"]
    assert isinstance(confirmation, dict)
    confirmation.update(
        {
            "suppressed": True,
            "suppression_reason": "counterevidence",
            "examined_frame_ids": ["cam-01:demo-ntsc:90"],
            "counterevidence_frame_ids": ["cam-01:demo-ntsc:90"],
        }
    )
    with pytest.raises(ValidationError, match="must not be emitted"):
        CandidateEvent.model_validate(payload)


def test_case_identity_is_derived_and_claimed_identity_is_verified() -> None:
    event = CandidateEvent.model_validate(_presence_event_payload())
    payload = {
        "case_id": "wrong-case-id",
        "run_id": "run-01",
        "status": CaseStatus.CANDIDATE,
        "event": event.model_dump(mode="json"),
        "manifest_id": event.manifest_id,
    }
    with pytest.raises(ValidationError, match="case_id does not match"):
        Case.model_validate(payload)

    payload.pop("case_id")
    case = Case.model_validate(payload)
    serialized = case.model_dump(mode="json")
    assert serialized["case_id"] == case.case_id


def test_generic_tool_parameters_cannot_reach_an_executor() -> None:
    with pytest.raises(ValidationError):
        ToolResult.model_validate(
            {
                "tool_result_id": "tool-01",
                "action": AcquisitionAction.RECROP,
                "input_refs": [
                    ArtifactRef(
                        kind=ArtifactKind.FRAME,
                        artifact_id="cam-01:stream-01:0",
                    ).model_dump(mode="json")
                ],
                "output_refs": [
                    ArtifactRef(kind=ArtifactKind.CROP, artifact_id=SHA_B).model_dump(mode="json")
                ],
                "validated_parameters": {"command": "dangerous shell text"},
                "execution_manifest_id": SHA_A,
            }
        )


def test_vlm_cache_key_is_derived_and_privacy_transform_sensitive() -> None:
    request = _vlm_request()
    round_trip = VLMRequest.model_validate(request.model_dump(mode="json"))
    assert round_trip.cache_key == request.cache_key
    changed_media = request.media[0].model_copy(update={"privacy_transform_version": "privacy-v2"})
    changed = _vlm_request(media=(changed_media,))
    assert changed.cache_key != request.cache_key
    assert _vlm_request(case_id="case-02").cache_key != request.cache_key
    assert _vlm_request(evidence_pack_id=SHA_B).cache_key != request.cache_key
    assert _vlm_request(evidence_pack_version=2).cache_key != request.cache_key

    tampered = request.model_dump(mode="json")
    tampered["cache_key"] = "0" * 64
    with pytest.raises(ValidationError, match="cache_key"):
        VLMRequest.model_validate(tampered)


def test_external_vlm_request_accepts_only_minimized_cloud_media() -> None:
    cloud_crop = _media_ref(media_access=MediaAccess.CLOUD_ALLOWED)
    external = _vlm_request(
        execution_location=ExecutionLocation.EXTERNAL,
        media=(cloud_crop,),
    )
    assert external.allowed_crop_ids == (SHA_D,)

    with pytest.raises(ValidationError, match="cloud-allowed"):
        _vlm_request(execution_location=ExecutionLocation.EXTERNAL)
    with pytest.raises(ValidationError, match="panorama"):
        _vlm_request(
            execution_location=ExecutionLocation.EXTERNAL,
            media=(
                _media_ref(
                    source=CropSource.PANORAMA,
                    media_access=MediaAccess.CLOUD_ALLOWED,
                ),
            ),
        )


def test_boolean_frame_bounds_never_enter_deterministic_identity_or_time() -> None:
    with pytest.raises(TypeError):
        make_event_id(
            camera_id="cam-01",
            stream_id="stream-01",
            violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
            primary_track_ref="cam-01:epoch-01:object-01",
            start_frame=True,
            rule_version="laboratory-v1",
        )
    with pytest.raises(TypeError):
        duration_ms(False, 2, 30, 1)

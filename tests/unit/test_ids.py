import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from labcourt.contracts.enums import (
    ArtifactKind,
    CropSource,
    MediaAccess,
    MediaAvailability,
    MediaType,
    PrivacyPolicy,
    PrivacyReasonCode,
    ViolationType,
)
from labcourt.contracts.events import CandidateEvent
from labcourt.contracts.evidence import (
    Crop,
    EvidencePack,
    EvidencePackDraft,
    PrivacyReceipt,
    TrackSummary,
)
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.domain.canonical import canonical_json, sha256_hex
from labcourt.domain.ids import (
    make_case_id,
    make_crop_id,
    make_event_id,
    make_manifest_id,
    make_pack_id,
)

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures"
M0_FIXTURES = FIXTURE_ROOT / "m0"
M2_FIXTURES = FIXTURE_ROOT / "m2"
M0_VECTOR = M0_FIXTURES / "canonical-id-vectors.json"
M2_VECTOR = M2_FIXTURES / "canonical-id-vectors.json"


def _vectors(path: Path = M2_VECTOR) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _evidence_pack(
    *,
    local_path: str | None = "frames/bottle.png",
    availability: MediaAvailability = MediaAvailability.AVAILABLE,
    pixel_sha256: str = "b" * 64,
    media_sha256: str = "e" * 64,
) -> EvidencePack:
    event = CandidateEvent.model_validate_json(
        (M2_FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8")
    )
    frame_ref = ArtifactRef(
        kind=ArtifactKind.FRAME,
        artifact_id="cam-01:demo-ntsc:90",
    )
    detection_ref = ArtifactRef(
        kind=ArtifactKind.DETECTION,
        artifact_id="det-bottle-090",
    )
    source_refs = (detection_ref, frame_ref)
    crop = Crop(
        frame_id=frame_ref.artifact_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=500, y1=300, x2=620, y2=650),
        source_refs=source_refs,
        local_path=local_path,
        availability=availability,
        source_media_sha256="a" * 64,
        pixel_sha256=pixel_sha256,
        media_sha256=media_sha256,
        output_width=120,
        output_height=350,
        size_bytes=4096,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.FULL_REDACTION,
            transform_version="ppe-redaction-v1",
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.POLICY_LOCAL_ONLY,
            input_refs=source_refs,
            fill_rgb=(0, 0, 0),
        ),
        primary_track_ref=event.primary_track_ref,
        tags={"zone_id": event.zone_id},
    )
    draft = EvidencePackDraft(
        run_id="run-01",
        case_id=make_case_id(event.event_id),
        version=1,
        event=event,
        key_frame_ids=(frame_ref.artifact_id,),
        focus_crops=(crop,),
        objective_facts=event.objective_facts,
        track_summary=TrackSummary(
            primary_track_ref=event.primary_track_ref,
            start_frame=0,
            end_frame_exclusive=91,
            observed_frame_count=91,
        ),
        confirmation_record=event.confirmation,
        manifest_id=event.manifest_id,
    )
    report = ClosureReport(
        run_id=draft.run_id,
        root_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=draft.case_id),
        manifest_id=draft.manifest_id,
        input_sha256=draft.closure_input_sha256,
        checked_refs=draft.expected_closure_refs(),
    )
    payload = draft.model_dump(mode="json", exclude={"pack_id"})
    payload["closure_report"] = report.model_dump(mode="json")
    return EvidencePack.model_validate(payload)


def test_canonical_golden_vector() -> None:
    vectors = _vectors()
    value = vectors["canonical_input"]
    assert canonical_json(value) == vectors["canonical_json"]
    assert sha256_hex(value) == vectors["canonical_sha256"]


def test_detection_focus_crop_requires_typed_detection_provenance() -> None:
    crop = _evidence_pack().focus_crops[0]
    frame_refs = tuple(ref for ref in crop.source_refs if ref.kind == ArtifactKind.FRAME)
    payload = crop.model_dump(mode="json")
    payload["source_refs"] = [ref.model_dump(mode="json") for ref in frame_refs]
    payload["privacy_receipt"]["input_refs"] = [ref.model_dump(mode="json") for ref in frame_refs]
    payload.pop("crop_id")

    with pytest.raises(ValidationError, match="typed detection source"):
        Crop.model_validate(payload)


def test_event_and_case_golden_vectors() -> None:
    event = _vectors()["event"]
    assert isinstance(event, dict)
    event_id = make_event_id(
        camera_id=str(event["camera_id"]),
        stream_id=str(event["stream_id"]),
        violation_type=ViolationType(str(event["violation_type"])),
        primary_track_ref=str(event["primary_track_ref"]),
        start_frame=int(str(event["start_frame"])),
        rule_version=str(event["rule_version"]),
    )
    assert event_id == event["expected_event_id"]
    assert make_case_id(event_id) == event["expected_case_id"]


def test_output_geometry_is_part_of_crop_identity() -> None:
    base = {
        "frame_id": "cam-01:stream-01:7",
        "bbox": BBoxXYXY(x1=2, y1=3, x2=12, y2=23),
        "crop_source": CropSource.PANORAMA,
        "source_media_sha256": "a" * 64,
        "privacy_policy": PrivacyPolicy.FULL_REDACTION,
        "privacy_transform_version": "ppe-redaction-v1",
        "encoding_version": "png-v1",
    }
    original = make_crop_id(output_width=10, output_height=20, **base)
    resized = make_crop_id(output_width=5, output_height=10, **base)
    assert resized != original


def test_crop_manifest_and_pack_golden_vectors() -> None:
    vectors = _vectors()
    crop = vectors["crop"]
    assert isinstance(crop, dict)
    bbox = crop["bbox"]
    assert isinstance(bbox, list)
    crop_id = make_crop_id(
        frame_id=str(crop["frame_id"]),
        bbox=BBoxXYXY(x1=bbox[0], y1=bbox[1], x2=bbox[2], y2=bbox[3]),
        output_width=int(str(crop["output_width"])),
        output_height=int(str(crop["output_height"])),
        crop_source=CropSource(str(crop["crop_source"])),
        source_media_sha256=str(crop["source_media_sha256"]),
        privacy_policy=PrivacyPolicy(str(crop["privacy_policy"])),
        privacy_transform_version=str(crop["privacy_transform_version"]),
        encoding_version=str(crop["encoding_version"]),
    )
    assert crop_id == crop["expected_crop_id"]
    evidence_pack = _evidence_pack()
    assert evidence_pack.focus_crops[0].crop_id == crop["expected_crop_id"]

    manifest_vector = vectors["manifest"]
    assert isinstance(manifest_vector, dict)
    manifest = RunManifest.model_validate_json(
        (M2_FIXTURES / str(manifest_vector["fixture"])).read_text(encoding="utf-8")
    )
    assert make_manifest_id(manifest) == manifest_vector["expected_manifest_id"]

    pack = vectors["pack"]
    assert isinstance(pack, dict)
    assert make_pack_id(evidence_pack) == pack["expected_pack_id"]
    assert evidence_pack.pack_input_sha256 == pack["expected_pack_input_sha256"]
    assert evidence_pack.closure_input_sha256 == pack["expected_closure_input_sha256"]


def test_m0_identity_vector_remains_an_immutable_legacy_record() -> None:
    legacy = _vectors(M0_VECTOR)
    assert legacy["manifest"] == {
        "fixture": "run-manifest-fake.json",
        "expected_manifest_id": "d8727af23c65e0722ac4754b5aafd2408426c03b2028e6947c6ea774f4ac70db",
    }
    assert isinstance(legacy["crop"], dict)
    assert legacy["crop"]["expected_crop_id"] == (
        "12a545f94d1f8a4788e232f7a125a5eb4fef034def1aa4f9e1df8deb1303ee0f"
    )


def test_semantic_fields_change_event_id() -> None:
    base = {
        "camera_id": "cam-01",
        "stream_id": "stream-01",
        "violation_type": ViolationType.REAGENT_CONTAINER_OPEN,
        "primary_track_ref": "cam-01:epoch-01:object-01",
        "start_frame": 10,
        "rule_version": "v1",
    }
    original = make_event_id(**base)
    changed = dict(base)
    changed["start_frame"] = 11
    assert make_event_id(**changed) != original


def test_hash_payloads_reject_wrong_contract_types() -> None:
    with pytest.raises(TypeError, match="EvidencePack"):
        make_pack_id({"pack_id": "self"})  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="RunManifest"):
        make_manifest_id({"manifest_id": "self"})  # type: ignore[arg-type]


def test_claims_are_verified_and_operational_media_state_is_not_semantic() -> None:
    pack = _evidence_pack()
    serialized_crop = pack.focus_crops[0].model_dump(mode="json")
    serialized_crop["crop_id"] = "0" * 64
    with pytest.raises(ValidationError, match="crop_id"):
        Crop.model_validate(serialized_crop)

    serialized_pack = pack.model_dump(mode="json")
    serialized_pack["pack_id"] = "0" * 64
    with pytest.raises(ValidationError, match="pack_id"):
        EvidencePack.model_validate(serialized_pack)

    relocated = _evidence_pack(local_path="relocated/bottle.png")
    purged = _evidence_pack(
        local_path=None,
        availability=MediaAvailability.PURGED_BY_RETENTION,
    )
    changed_pixels = _evidence_pack(pixel_sha256="c" * 64)
    changed_media = _evidence_pack(media_sha256="f" * 64)

    assert relocated.pack_id == pack.pack_id
    assert purged.pack_id == pack.pack_id
    assert changed_pixels.focus_crops[0].crop_id == pack.focus_crops[0].crop_id
    assert changed_media.focus_crops[0].crop_id == pack.focus_crops[0].crop_id
    assert changed_pixels.pack_id != pack.pack_id
    assert changed_media.pack_id != pack.pack_id


def test_camera_and_stream_tokens_reject_colons() -> None:
    with pytest.raises(ValueError, match="anonymous ASCII"):
        make_event_id(
            camera_id="cam:01",
            stream_id="stream-01",
            violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
            primary_track_ref=None,
            start_frame=0,
            rule_version="v1",
        )

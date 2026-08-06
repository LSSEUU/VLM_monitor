from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import fields
from pathlib import Path
from typing import cast

import pytest

from labcourt.application.evidence import (
    MAX_EVIDENCE_BUILD_FRAMES,
    EvidenceBuilder,
    EvidenceBuildRequest,
    FrameCropContext,
)
from labcourt.config_loader import load_config
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.config import AppConfig
from labcourt.contracts.detections import Detection, FrameBundle, Keypoint
from labcourt.contracts.enums import (
    ArtifactKind,
    AssociationMethod,
    AuditAction,
    CaseStatus,
    EvidenceFailureCode,
    ObservationSource,
    PrivacyPolicy,
)
from labcourt.contracts.events import CandidateEvent
from labcourt.contracts.evidence import (
    Crop,
    CropRequest,
    ObservabilityComponents,
    ObservabilityScore,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.manifests import (
    RunManifest,
    SoftwareComponentManifest,
    StreamManifest,
)
from labcourt.contracts.storage import ArtifactVerification
from labcourt.domain.association import associate_ppe
from labcourt.domain.crop_geometry import plan_absence_focus, plan_subject
from labcourt.domain.evidence_window import KeyFrameSelection
from labcourt.exceptions import BudgetExceeded, EvidenceMissing, PrivacyPolicyViolation
from labcourt.ports.evidence_repository import CaseSnapshot, EvidenceRepository
from labcourt.ports.frame_store import FrameStore

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "m2"
WIDTH = 32
HEIGHT = 24
FRAME_COUNT = 160
TRACK_REF = "cam-01:epoch-01:person-01"
RUN_ID = "adversarial-evidence"
FRAME_STORE_COMPONENT = "adversarial-frame-store"


class _CropCaptured(Exception):
    """Stop a private crop path immediately after observing its request."""


class _CapturingFrameStore:
    def __init__(
        self,
        run_id: str,
        software_component: SoftwareComponentManifest,
    ) -> None:
        self.run_id = run_id
        self.software_component = software_component
        self.requests: list[CropRequest] = []

    def create_crop(self, request: CropRequest) -> Crop:
        self.requests.append(request)
        raise _CropCaptured

    def verify_crop(self, crop: Crop) -> ArtifactVerification:
        del crop
        raise AssertionError("verification must not run in application boundary tests")


class _ForbiddenRepository:
    def __init__(self) -> None:
        self.register_run_called = False
        self.failure_codes: list[EvidenceFailureCode] = []
        self.snapshot: CaseSnapshot | None = None

    def register_run(self, *_args: object, **_kwargs: object) -> None:
        self.register_run_called = True

    def create_or_get_case(
        self,
        run_id: str,
        event: CandidateEvent,
    ) -> CaseSnapshot:
        snapshot = CaseSnapshot(
            case=Case(
                run_id=run_id,
                status=CaseStatus.CANDIDATE,
                event=event,
                manifest_id=event.manifest_id,
            ),
            revision=1,
        )
        self.snapshot = snapshot
        return snapshot

    def record_evidence_failure(
        self,
        run_id: str,
        expected_revision: int,
        case_id: str,
        failure_code: EvidenceFailureCode,
    ) -> CaseSnapshot:
        assert self.snapshot is not None
        assert run_id == self.snapshot.case.run_id
        assert expected_revision == self.snapshot.revision
        assert case_id == self.snapshot.case.case_id
        self.failure_codes.append(failure_code)
        timeline_entry = TimelineEntry(
            sequence=len(self.snapshot.case.timeline),
            action=AuditAction.CASE_STATE_CHANGED.value,
            stage="EVIDENCE",
            object_ref=case_id,
            details={"failure_code": failure_code.value},
        )
        return CaseSnapshot(
            case=self.snapshot.case.model_copy(
                update={
                    "status": CaseStatus.HUMAN_REVIEW,
                    "timeline": (*self.snapshot.case.timeline, timeline_entry),
                }
            ),
            revision=expected_revision + 1,
        )


class _SortingForbiddenBuilder(EvidenceBuilder):
    __slots__ = ()

    def _validate_bundles(
        self,
        bundles: tuple[FrameBundle, ...],
        stream: StreamManifest,
    ) -> tuple[FrameBundle, ...]:
        del bundles, stream
        raise AssertionError("over-budget input reached bundle sorting")


class _IterationCountingBundles(tuple[FrameBundle, ...]):
    iteration_count: int

    def __new__(
        cls,
        values: tuple[FrameBundle, ...],
    ) -> _IterationCountingBundles:
        instance = super().__new__(cls, values)
        instance.iteration_count = 0
        return instance

    def __iter__(self) -> Iterator[FrameBundle]:
        self.iteration_count += 1
        return super().__iter__()


def _config(*, privacy_policy: PrivacyPolicy | None = None) -> AppConfig:
    config = load_config(ROOT / "configs" / "demo.yaml")
    if privacy_policy is None:
        return config
    return config.model_copy(
        update={
            "evidence": config.evidence.model_copy(
                update={"privacy_policy": privacy_policy},
            )
        }
    )


def _manifest(config: AppConfig) -> RunManifest:
    base = RunManifest.model_validate_json(
        (FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )
    component = SoftwareComponentManifest(
        component="synthetic-decoder",
        package="labcourt-test-video",
        version="1.0.0",
        license_id="synthetic-fixture",
    )
    frame_store_component = SoftwareComponentManifest(
        component=FRAME_STORE_COMPONENT,
        package="labcourt-adversarial-test-store",
        version="1.0.0",
        license_id="synthetic-fixture",
    )
    stream = StreamManifest(
        camera_id="cam-01",
        stream_id="demo-absence",
        input_file_sha256="1" * 64,
        fps_num=30,
        fps_den=1,
        timing_mode="CFR",
        timing_authority="CALLER_ATTESTED",
        timing_evidence_type="CALLER_DECLARATION",
        timing_evidence_sha256="2" * 64,
        width=WIDTH,
        height=HEIGHT,
        frame_count=FRAME_COUNT,
        decoder="synthetic-rgb8",
        decoder_version="1.0.0",
        backend="IN_MEMORY_FIXTURE",
        software_component=component.component,
        library=component.package,
        library_version=component.version,
        codec="FAKE",
        color_conversion="NONE_RGB8",
        pixel_format="RGB8",
        pixel_hash_algorithm="LCPIX1",
    )
    return base.model_copy(
        update={
            "config_sha256": config.config_sha256,
            "streams": (stream,),
            "software_components": {
                component.component: component,
                frame_store_component.component: frame_store_component,
            },
        }
    )


def _event(manifest: RunManifest) -> CandidateEvent:
    base = CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-absence-strict.json").read_text(encoding="utf-8")
    )
    return base.model_copy(update={"manifest_id": manifest.manifest_id})


def _frame(frame_index: int) -> FrameRef:
    return FrameRef(
        camera_id="cam-01",
        stream_id="demo-absence",
        frame_index=frame_index,
        fps_num=30,
        fps_den=1,
        width=WIDTH,
        height=HEIGHT,
        content_sha256="a" * 64,
    )


def _bundle(
    frame_index: int,
    *,
    detections: tuple[Detection, ...] = (),
) -> FrameBundle:
    return FrameBundle(frame=_frame(frame_index), detections=detections)


def _person_detection(frame: FrameRef, manifest: RunManifest) -> Detection:
    return Detection(
        detection_id=f"person-{frame.frame_index:03d}",
        frame_id=frame.frame_id,
        label="person",
        bbox=BBoxXYXY(x1=4, y1=2, x2=28, y2=22),
        score=0.9,
        track_ref=TRACK_REF,
        keypoints=(
            Keypoint(name="right_eye", x=20.0, y=7.0, score=0.94),
            Keypoint(name="left_eye", x=10.0, y=7.0, score=0.95),
        ),
        model_manifest_id=manifest.models["detector"].model_manifest_id,
    )


def _observability() -> ObservabilityScore:
    return ObservabilityScore(
        total=0.9,
        components=ObservabilityComponents(
            person_confidence=0.9,
            keypoint_visibility=0.9,
            frontality=0.9,
            sharpness=0.9,
            exposure=0.9,
            non_occlusion=0.9,
        ),
        source=ObservationSource.PRECOMPUTED_FIXTURE,
    )


def _selection(frame_id: str) -> KeyFrameSelection:
    return KeyFrameSelection(
        selection_priority_frame_ids=(frame_id,),
        frame_ids=(frame_id,),
        temporal_top_m_frame_ids=(frame_id,),
    )


def _builder(
    config: AppConfig,
    manifest: RunManifest,
    repository: _ForbiddenRepository,
    *,
    max_window_frames: int = 10_000,
) -> tuple[EvidenceBuilder, _CapturingFrameStore]:
    store = _CapturingFrameStore(
        RUN_ID,
        manifest.software_components[FRAME_STORE_COMPONENT],
    )
    builder = EvidenceBuilder(
        config=config,
        manifest=manifest,
        frame_store=cast(FrameStore, store),
        repository=cast(EvidenceRepository, repository),
        max_window_frames=max_window_frames,
    )
    return builder, store


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("bbox", BBoxXYXY(x1=0, y1=0, x2=1, y2=1)),
        ("keypoints", (Keypoint(name="nose", x=0.0, y=0.0, score=1.0),)),
        ("association_method", AssociationMethod.BODY_FALLBACK),
    ],
)
def test_frame_crop_context_rejects_caller_supplied_geometry(
    field_name: str,
    value: object,
) -> None:
    context_factory = cast(Callable[..., FrameCropContext], FrameCropContext)

    with pytest.raises(TypeError, match="unexpected keyword argument"):
        context_factory(
            frame_id="cam-01:demo-absence:10",
            **{field_name: value},
        )


def test_absence_geometry_and_association_are_derived_from_frame_bundle() -> None:
    context_fields = {field.name for field in fields(FrameCropContext)}
    assert context_fields == {
        "frame_id",
        "observability",
        "presence_focus_detection_id",
    }
    assert {"bbox", "keypoints", "association_method"}.isdisjoint(context_fields)

    config = _config()
    manifest = _manifest(config)
    event = _event(manifest)
    frame = _frame(10)
    person = _person_detection(frame, manifest)
    bundle = FrameBundle(frame=frame, detections=(person,))
    context = FrameCropContext(frame_id=frame.frame_id, observability=_observability())
    builder, store = _builder(config, manifest, _ForbiddenRepository())

    with pytest.raises(_CropCaptured):
        builder._focus_crops(
            event,
            _selection(frame.frame_id),
            {frame.frame_id: bundle},
            {frame.frame_id: context},
        )

    assert len(store.requests) == 1
    request = store.requests[0]
    association = associate_ppe(
        bundle,
        TRACK_REF,
        request.ppe_type,
        score_threshold=config.perception.detector.score_threshold,
        config=config.perception.association,
    )
    expected_plan = plan_absence_focus(
        association.anchor_bbox,
        frame_width=WIDTH,
        frame_height=HEIGHT,
    )
    assert association.method == AssociationMethod.KEYPOINT
    assert request.bbox == expected_plan.bbox
    assert request.anchor_bbox == expected_plan.bbox
    assert request.keypoints == tuple(sorted(person.keypoints, key=lambda item: item.name))
    assert request.association_method == association.method
    assert {(ref.kind, ref.artifact_id) for ref in request.source_refs} == {
        (ArtifactKind.FRAME, frame.frame_id),
        (ArtifactKind.DETECTION, person.detection_id),
    }


def test_presence_subject_uses_the_authoritative_non_person_primary_track() -> None:
    config = _config()
    manifest = _manifest(config)
    event = CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8")
    ).model_copy(update={"manifest_id": manifest.manifest_id})
    frame = FrameRef(
        camera_id=event.camera_id,
        stream_id=event.stream_id,
        frame_index=event.trigger_frame,
        fps_num=30_000,
        fps_den=1_001,
        width=WIDTH,
        height=HEIGHT,
        content_sha256="a" * 64,
    )
    bottle = Detection(
        detection_id="reagent-bottle-090",
        frame_id=frame.frame_id,
        label="reagent_bottle",
        bbox=BBoxXYXY(x1=8, y1=4, x2=24, y2=22),
        score=0.96,
        track_ref=event.primary_track_ref,
        model_manifest_id=manifest.models["detector"].model_manifest_id,
    )
    bundle = FrameBundle(frame=frame, detections=(bottle,))
    builder, store = _builder(config, manifest, _ForbiddenRepository())

    with pytest.raises(_CropCaptured):
        builder._subject_crops(event, {frame.frame_id: bundle})

    request = store.requests[0]
    assert request.primary_track_ref == event.primary_track_ref
    assert (
        request.bbox
        == plan_subject(
            bottle.bbox,
            frame_width=frame.width,
            frame_height=frame.height,
            expand_ratio=config.evidence.subject_expand_ratio,
        ).bbox
    )
    assert {(ref.kind, ref.artifact_id) for ref in request.source_refs} == {
        (ArtifactKind.FRAME, frame.frame_id),
        (ArtifactKind.DETECTION, bottle.detection_id),
    }


def test_full_redaction_rejects_absence_focus_before_media_processing() -> None:
    config = _config(privacy_policy=PrivacyPolicy.FULL_REDACTION)
    manifest = _manifest(config)
    event = _event(manifest)
    frame = _frame(10)
    person = _person_detection(frame, manifest)
    bundle = FrameBundle(frame=frame, detections=(person,))
    context = FrameCropContext(frame_id=frame.frame_id, observability=_observability())
    builder, store = _builder(config, manifest, _ForbiddenRepository())

    with pytest.raises(PrivacyPolicyViolation, match="cannot persist absence-focus"):
        builder._focus_crops(
            event,
            _selection(frame.frame_id),
            {frame.frame_id: bundle},
            {frame.frame_id: context},
        )

    assert store.requests == []


@pytest.mark.parametrize(
    ("scenario", "expected_message"),
    [
        ("gap-before-watermark", "contiguous prefix"),
        ("premature-complete", "completeness conflicts"),
        ("false-incomplete", "completeness conflicts"),
    ],
)
def test_availability_watermark_requires_exact_prefix_and_consistent_completeness(
    scenario: str,
    expected_message: str,
) -> None:
    config = _config()
    manifest = _manifest(config)
    event = _event(manifest)
    if scenario == "gap-before-watermark":
        indices = tuple(index for index in range(152) if index != 73)
        watermark = 152
        complete = False
    elif scenario == "premature-complete":
        indices = tuple(range(152))
        watermark = 152
        complete = True
    else:
        indices = tuple(range(FRAME_COUNT))
        watermark = FRAME_COUNT
        complete = False
    repository = _ForbiddenRepository()
    builder, store = _builder(config, manifest, repository)
    request = EvidenceBuildRequest(
        run_id=RUN_ID,
        event=event,
        bundles=tuple(_bundle(index) for index in indices),
        crop_contexts=(),
        available_end_frame_exclusive=watermark,
        complete=complete,
    )

    with pytest.raises(EvidenceMissing, match=expected_message):
        builder.build_and_publish(request)

    assert store.requests == []
    assert repository.register_run_called is True
    assert repository.failure_codes == [EvidenceFailureCode.EVIDENCE_MISSING]


def test_input_budget_is_rejected_before_bundle_sorting_or_processing() -> None:
    config = _config()
    manifest = _manifest(config)
    event = _event(manifest)
    repository = _ForbiddenRepository()
    store = _CapturingFrameStore(
        RUN_ID,
        manifest.software_components[FRAME_STORE_COMPONENT],
    )
    builder = _SortingForbiddenBuilder(
        config=config,
        manifest=manifest,
        frame_store=cast(FrameStore, store),
        repository=cast(EvidenceRepository, repository),
        max_window_frames=2,
    )
    bundles = _IterationCountingBundles((_bundle(2), _bundle(0), _bundle(1)))
    request = EvidenceBuildRequest(
        run_id=RUN_ID,
        event=event,
        bundles=bundles,
        crop_contexts=(),
        available_end_frame_exclusive=151,
        complete=False,
    )
    # Contract construction validates every element. The application budget gate must
    # reject on O(1) length alone once it receives that validated request.
    bundles.iteration_count = 0

    with pytest.raises(BudgetExceeded, match="artifact budget"):
        builder.build_and_publish(request)

    assert bundles.iteration_count == 0
    assert store.requests == []
    assert repository.register_run_called is True
    assert repository.failure_codes == [EvidenceFailureCode.EVIDENCE_BUDGET_EXCEEDED]


def test_request_contract_rejects_global_oversize_before_iterating_bundles() -> None:
    config = _config()
    manifest = _manifest(config)
    event = _event(manifest)
    bundle = _bundle(0)
    bundles = _IterationCountingBundles((bundle,) * (MAX_EVIDENCE_BUILD_FRAMES + 1))

    with pytest.raises(BudgetExceeded, match="contract budget"):
        EvidenceBuildRequest(
            run_id=RUN_ID,
            event=event,
            bundles=bundles,
            crop_contexts=(),
            available_end_frame_exclusive=151,
            complete=False,
        )

    assert bundles.iteration_count == 0

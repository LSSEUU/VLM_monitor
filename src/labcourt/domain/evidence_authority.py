"""Pure M4 evidence succession, disclosure, and hearing-history authority.

This module is the single translation boundary between acquisition artifacts and
what a hearing role may actually see.  Frames and detections can prove that a
tool ran, but they are never role-citable pixel evidence.  Only an explicitly
selected :class:`Crop` is disclosed as media.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from itertools import pairwise
from typing import TypeVar

from labcourt.contracts.acquisition_matrix import (
    acquisition_output_counts_match,
    acquisition_tool_rule,
)
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import (
    AcquisitionAction,
    ArtifactKind,
    CropSource,
    MediaAvailability,
)
from labcourt.contracts.events import ObjectiveFact
from labcourt.contracts.evidence import (
    Crop,
    CropRequest,
    EvidencePack,
    EvidencePackDraft,
    OtherCameraSameTimeParameters,
    RecropParameters,
    RedetectHighResolutionParameters,
    RequestMoreFramesParameters,
    ToolResult,
    TrackConfidenceCurveParameters,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.hearing import (
    AcquisitionRequest,
    ToolExecutionManifest,
    ToolExecutionReceipt,
    derive_m4_tool_result_id,
)
from labcourt.contracts.references import parse_frame_id
from labcourt.contracts.screening import VLMMediaRef
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.domain.procedural_gate import ArtifactBounds


class EvidenceAuthorityError(ValueError):
    """Typed base failure for incomplete or contradictory evidence authority."""


class AcquisitionAuthorityError(EvidenceAuthorityError):
    """An acquisition tried to consume or produce evidence outside its authority."""


class EvidencePackSuccessorError(EvidenceAuthorityError):
    """An M4 pack successor is not the exact semantic superset of its predecessor."""


class EvidenceDisclosureError(EvidenceAuthorityError):
    """A role disclosure is unavailable, unstable, or exceeds candidate authority."""


class RecropAuthorityUnrecoverable(AcquisitionAuthorityError):
    """A RECROP cannot be bound to a prior crop or frame-producing tool result."""


_T = TypeVar("_T")


def _artifact_ref(kind: ArtifactKind, artifact_id: str) -> ArtifactRef:
    return ArtifactRef(kind=kind, artifact_id=artifact_id)


def _frame_ref(frame: FrameRef) -> ArtifactRef:
    return _artifact_ref(ArtifactKind.FRAME, frame.frame_id)


def _crop_ref(crop: Crop) -> ArtifactRef:
    return _artifact_ref(ArtifactKind.CROP, crop.crop_id)


def _fact_ref(fact: ObjectiveFact) -> ArtifactRef:
    return _artifact_ref(ArtifactKind.OBJECTIVE_FACT, fact.fact_id)


def _detection_ref(detection: Detection) -> ArtifactRef:
    return _artifact_ref(ArtifactKind.DETECTION, detection.detection_id)


def _tool_result_ref(result: ToolResult) -> ArtifactRef:
    return _artifact_ref(ArtifactKind.TOOL_RESULT, result.tool_result_id)


def _require_stable_objects(
    name: str,
    values: tuple[object, ...],
    expected_type: type[object],
    refs: tuple[ArtifactRef, ...],
) -> None:
    if not isinstance(values, tuple) or any(
        not isinstance(value, expected_type) for value in values
    ):
        raise EvidenceAuthorityError(f"{name} must be a tuple of exact typed objects")
    keys = tuple(ref.sort_key for ref in refs)
    if len(keys) != len(set(keys)) or keys != tuple(sorted(keys)):
        raise EvidenceAuthorityError(f"{name} must be unique and use stable artifact order")


@dataclass(frozen=True, slots=True)
class LoadedEvidenceObjects:
    """Objects materialized by trusted repositories for one pack lineage."""

    frames: tuple[FrameRef, ...] = ()
    crops: tuple[Crop, ...] = ()
    objective_facts: tuple[ObjectiveFact, ...] = ()
    detections: tuple[Detection, ...] = ()

    def __post_init__(self) -> None:
        _require_stable_objects(
            "loaded frames",
            self.frames,
            FrameRef,
            tuple(_frame_ref(frame) for frame in self.frames),
        )
        _require_stable_objects(
            "loaded crops",
            self.crops,
            Crop,
            tuple(_crop_ref(crop) for crop in self.crops),
        )
        _require_stable_objects(
            "loaded objective facts",
            self.objective_facts,
            ObjectiveFact,
            tuple(_fact_ref(fact) for fact in self.objective_facts),
        )
        _require_stable_objects(
            "loaded detections",
            self.detections,
            Detection,
            tuple(_detection_ref(detection) for detection in self.detections),
        )

    @property
    def refs(self) -> tuple[ArtifactRef, ...]:
        refs = (
            *(_frame_ref(frame) for frame in self.frames),
            *(_crop_ref(crop) for crop in self.crops),
            *(_fact_ref(fact) for fact in self.objective_facts),
            *(_detection_ref(detection) for detection in self.detections),
        )
        return tuple(sorted(refs, key=lambda ref: ref.sort_key))


def _merge_typed_objects(
    name: str,
    left: tuple[_T, ...],
    right: tuple[_T, ...],
    ref_for: Callable[[_T], ArtifactRef],
) -> tuple[_T, ...]:
    by_key: dict[tuple[str, str], _T] = {}
    for value in (*left, *right):
        ref = ref_for(value)
        existing = by_key.get(ref.sort_key)
        if existing is not None and existing != value:
            raise EvidenceAuthorityError(f"{name} contains conflicting objects for one reference")
        by_key[ref.sort_key] = value
    return tuple(by_key[key] for key in sorted(by_key))


def merge_loaded_evidence_objects(
    left: LoadedEvidenceObjects,
    right: LoadedEvidenceObjects,
) -> LoadedEvidenceObjects:
    """Return a stable exact union; conflicting materializations fail closed."""

    if not isinstance(left, LoadedEvidenceObjects) or not isinstance(right, LoadedEvidenceObjects):
        raise EvidenceAuthorityError("loaded evidence union requires typed object collections")
    return LoadedEvidenceObjects(
        frames=tuple(_merge_typed_objects("frames", left.frames, right.frames, _frame_ref)),
        crops=tuple(_merge_typed_objects("crops", left.crops, right.crops, _crop_ref)),
        objective_facts=tuple(
            _merge_typed_objects(
                "objective facts",
                left.objective_facts,
                right.objective_facts,
                _fact_ref,
            )
        ),
        detections=tuple(
            _merge_typed_objects(
                "detections",
                left.detections,
                right.detections,
                _detection_ref,
            )
        ),
    )


@dataclass(frozen=True, slots=True)
class AcquisitionExecution:
    """Validated executor-port output before the EvidencePack successor is closed."""

    request: AcquisitionRequest
    execution_manifest: ToolExecutionManifest
    tool_result: ToolResult
    output_objects: LoadedEvidenceObjects
    crop_request: CropRequest | None = None

    def __post_init__(self) -> None:
        request = self.request
        manifest = self.execution_manifest
        result = self.tool_result
        if not isinstance(request, AcquisitionRequest):
            raise AcquisitionAuthorityError("execution requires a typed acquisition request")
        if not isinstance(manifest, ToolExecutionManifest) or not isinstance(result, ToolResult):
            raise AcquisitionAuthorityError("execution requires typed manifest and result objects")
        if not isinstance(self.output_objects, LoadedEvidenceObjects):
            raise AcquisitionAuthorityError("execution outputs require loaded typed objects")
        if (
            manifest.run_id != request.run_id
            or manifest.case_id != request.case_id
            or manifest.hearing_session_id != request.hearing_session_id
            or manifest.acquisition_request_id != request.request_id
            or manifest.action != request.action
            or manifest.manifest_id != request.manifest_id
        ):
            raise AcquisitionAuthorityError("execution manifest conflicts with its request")
        if (
            result.action != request.action
            or result.validated_parameters != request.validated_parameters
            or result.execution_manifest_id != manifest.execution_manifest_id
        ):
            raise AcquisitionAuthorityError("tool result conflicts with its request or manifest")
        expected_result_id = derive_m4_tool_result_id(
            result.action,
            result.input_refs,
            result.output_refs,
            result.validated_parameters,
            result.execution_manifest_id,
        )
        if result.tool_result_id != expected_result_id:
            raise AcquisitionAuthorityError("tool result is not its deterministic M4 address")
        if self.output_objects.refs != result.output_refs:
            raise AcquisitionAuthorityError("loaded outputs must exactly match tool output refs")
        self._validate_output_matrix()

    def _validate_output_matrix(self) -> None:
        action = self.request.action
        outputs = self.output_objects
        _validate_action_output_cardinality(action, len(self.tool_result.output_refs))
        if not acquisition_output_counts_match(
            action,
            frames=len(outputs.frames),
            crops=len(outputs.crops),
            objective_facts=len(outputs.objective_facts),
            detections=len(outputs.detections),
        ):
            raise AcquisitionAuthorityError("tool outputs violate the action/object matrix")

        parameters = self.request.validated_parameters
        if isinstance(parameters, RequestMoreFramesParameters):
            expected_indices = tuple(
                range(
                    parameters.start_frame,
                    parameters.end_frame_exclusive,
                    parameters.step,
                )
            )
            frames_by_index = {frame.frame_index: frame for frame in outputs.frames}
            if tuple(sorted(frames_by_index)) != expected_indices or any(
                frame.camera_id != parameters.camera_id
                or frame.stream_id != parameters.stream_id
                or frame.content_sha256 is None
                for frame in outputs.frames
            ):
                raise AcquisitionAuthorityError(
                    "requested frame outputs do not exactly close their range"
                )
        elif isinstance(parameters, OtherCameraSameTimeParameters):
            if any(
                frame.camera_id != parameters.target_camera_id or frame.content_sha256 is None
                for frame in outputs.frames
            ):
                raise AcquisitionAuthorityError(
                    "other-camera outputs lack target-camera content authority"
                )
        elif isinstance(parameters, RedetectHighResolutionParameters) and any(
            detection.label not in parameters.prompts for detection in outputs.detections
        ):
            raise AcquisitionAuthorityError(
                "redetection output label lies outside its frozen prompts"
            )

        result_ref = _tool_result_ref(self.tool_result)
        if action == AcquisitionAction.RECROP:
            if self.crop_request is None or not isinstance(self.crop_request, CropRequest):
                raise AcquisitionAuthorityError("RECROP requires its frozen CropRequest")
            crop = outputs.crops[0] if len(outputs.crops) == 1 else None
            if crop is None or not _crop_matches_request(crop, self.crop_request):
                raise AcquisitionAuthorityError("RECROP output does not match its CropRequest")
        elif self.crop_request is not None:
            raise AcquisitionAuthorityError("only RECROP can carry a CropRequest")

        if action == AcquisitionAction.TRACK_CONFIDENCE_CURVE and any(
            fact.source_ref != result_ref
            or fact.source_manifest_id != self.execution_manifest.execution_manifest_id
            for fact in outputs.objective_facts
        ):
            raise AcquisitionAuthorityError("track facts lack exact tool-result provenance")
        if action == AcquisitionAction.REDETECT_HIGH_RES:
            model_manifest_id = self.execution_manifest.model_manifest_id
            if model_manifest_id is None or any(
                detection.model_manifest_id != model_manifest_id for detection in outputs.detections
            ):
                raise AcquisitionAuthorityError("redetections lack the execution model manifest")


def _validate_action_output_cardinality(
    action: AcquisitionAction,
    output_count: int,
) -> None:
    """Apply one explicit output bound in both execution and reload paths."""

    if not acquisition_tool_rule(action).accepts_output_count(output_count):
        raise AcquisitionAuthorityError("tool output cardinality is out of bounds")


def _crop_matches_request(crop: Crop, request: CropRequest) -> bool:
    return (
        crop.source == CropSource.RECROP
        and request.source == CropSource.RECROP
        and crop.frame_id == request.frame_id
        and crop.bbox == request.bbox
        and crop.source_refs == request.source_refs
        and crop.output_width == request.output_width
        and crop.output_height == request.output_height
        and crop.encoding_version == request.encoding_version
        and crop.primary_track_ref == request.primary_track_ref
        and crop.observability == request.observability
        and crop.privacy_receipt.policy == request.privacy_policy
        and crop.privacy_receipt.transform_version == request.privacy_transform_version
        and crop.privacy_receipt.input_refs == request.source_refs
    )


@dataclass(frozen=True, slots=True)
class EvidenceAuthority:
    """Complete candidate universe for one closed EvidencePack."""

    pack: EvidencePack
    receipts: tuple[ToolExecutionReceipt, ...]
    loaded_objects: LoadedEvidenceObjects
    crops: tuple[Crop, ...]
    candidate_citable_refs: tuple[ArtifactRef, ...]
    acquisition_input_refs: tuple[ArtifactRef, ...]
    artifact_bounds: tuple[ArtifactBounds, ...]

    def __post_init__(self) -> None:
        citable_keys = tuple(ref.sort_key for ref in self.candidate_citable_refs)
        if len(citable_keys) != len(set(citable_keys)) or citable_keys != tuple(
            sorted(citable_keys)
        ):
            raise EvidenceAuthorityError("candidate citable refs must use stable unique order")
        if any(
            ref.kind
            not in {
                ArtifactKind.CROP,
                ArtifactKind.OBJECTIVE_FACT,
                ArtifactKind.TOOL_RESULT,
            }
            for ref in self.candidate_citable_refs
        ):
            raise EvidenceAuthorityError("candidate citable refs contain pixel-unsafe kinds")
        if any(
            ref.kind not in {ArtifactKind.FRAME, ArtifactKind.CROP}
            for ref in self.acquisition_input_refs
        ):
            raise EvidenceAuthorityError("acquisition inputs contain unsupported object kinds")
        crop_refs = {_crop_ref(crop) for crop in self.crops}
        if crop_refs != {
            ref for ref in self.candidate_citable_refs if ref.kind == ArtifactKind.CROP
        }:
            raise EvidenceAuthorityError("candidate crop refs do not match loaded crop objects")
        if {bounds.artifact_ref for bounds in self.artifact_bounds} != crop_refs:
            raise EvidenceAuthorityError("candidate crop bounds do not cover exact crop authority")


@dataclass(frozen=True, slots=True)
class RoleEvidenceDisclosure:
    """The exact media and references granted to one primary role call."""

    run_id: str
    case_id: str
    evidence_pack_id: str
    evidence_pack_version: int
    media: tuple[VLMMediaRef, ...]
    allowed_evidence_refs: tuple[ArtifactRef, ...]
    artifact_bounds: tuple[ArtifactBounds, ...]

    def __post_init__(self) -> None:
        media_keys = tuple(item.sort_key for item in self.media)
        if (
            not self.media
            or len(media_keys) != len(set(media_keys))
            or media_keys != tuple(sorted(media_keys))
        ):
            raise EvidenceDisclosureError("role media must be non-empty, unique, and stable")
        allowed_keys = tuple(ref.sort_key for ref in self.allowed_evidence_refs)
        if len(allowed_keys) != len(set(allowed_keys)) or allowed_keys != tuple(
            sorted(allowed_keys)
        ):
            raise EvidenceDisclosureError("role evidence refs must be unique and stable")
        if any(
            ref.kind
            not in {
                ArtifactKind.CROP,
                ArtifactKind.OBJECTIVE_FACT,
                ArtifactKind.TOOL_RESULT,
            }
            for ref in self.allowed_evidence_refs
        ):
            raise EvidenceDisclosureError("role evidence contains FRAME or DETECTION authority")
        media_ids = {item.crop_id for item in self.media}
        allowed_crop_ids = {
            ref.artifact_id for ref in self.allowed_evidence_refs if ref.kind == ArtifactKind.CROP
        }
        if media_ids != allowed_crop_ids:
            raise EvidenceDisclosureError("role crop whitelist must exactly match selected media")
        bound_ids = {bounds.artifact_ref.artifact_id for bounds in self.artifact_bounds}
        if any(bounds.artifact_ref.kind != ArtifactKind.CROP for bounds in self.artifact_bounds):
            raise EvidenceDisclosureError("role bounds may describe selected crops only")
        if bound_ids != media_ids:
            raise EvidenceDisclosureError("role bounds must exactly match selected media")


@dataclass(frozen=True, slots=True)
class HearingEvidenceGrant:
    """Union of actual role grants over the complete hearing history for L5."""

    run_id: str
    case_id: str
    latest_evidence_pack_id: str
    latest_evidence_pack_version: int
    allowed_evidence_refs: tuple[ArtifactRef, ...]
    artifact_bounds: tuple[ArtifactBounds, ...]

    def __post_init__(self) -> None:
        ref_keys = tuple(ref.sort_key for ref in self.allowed_evidence_refs)
        bound_keys = tuple(bounds.sort_key for bounds in self.artifact_bounds)
        if len(ref_keys) != len(set(ref_keys)) or ref_keys != tuple(sorted(ref_keys)):
            raise EvidenceDisclosureError("hearing grant refs must be unique and stable")
        if len(bound_keys) != len(set(bound_keys)) or bound_keys != tuple(sorted(bound_keys)):
            raise EvidenceDisclosureError("hearing grant bounds must be unique and stable")
        if any(
            ref.kind
            not in {
                ArtifactKind.CROP,
                ArtifactKind.OBJECTIVE_FACT,
                ArtifactKind.TOOL_RESULT,
            }
            for ref in self.allowed_evidence_refs
        ):
            raise EvidenceDisclosureError("hearing history cannot grant FRAME or DETECTION")
        crop_refs = {ref for ref in self.allowed_evidence_refs if ref.kind == ArtifactKind.CROP}
        if {bounds.artifact_ref for bounds in self.artifact_bounds} != crop_refs:
            raise EvidenceDisclosureError("hearing history bounds must cover exact granted crops")


@dataclass(frozen=True, slots=True)
class EvidencePackUpdate:
    """Closed successor plus the receipt/object authority needed by the next cycle."""

    pack: EvidencePack
    receipt: ToolExecutionReceipt
    receipts: tuple[ToolExecutionReceipt, ...]
    loaded_objects: LoadedEvidenceObjects
    authority: EvidenceAuthority

    def __post_init__(self) -> None:
        if not self.receipts or self.receipts[-1] != self.receipt:
            raise EvidencePackSuccessorError("pack update receipt history is incomplete")
        if self.authority.pack != self.pack or self.authority.receipts != self.receipts:
            raise EvidencePackSuccessorError("pack update authority conflicts with its successor")


def _receipt_sort_key(receipt: ToolExecutionReceipt) -> tuple[int, str]:
    return receipt.resulting_evidence_pack_version, receipt.receipt_id


def _validate_receipt_history(
    pack: EvidencePack,
    receipts: tuple[ToolExecutionReceipt, ...],
) -> None:
    if not isinstance(receipts, tuple) or any(
        not isinstance(receipt, ToolExecutionReceipt) for receipt in receipts
    ):
        raise EvidenceAuthorityError("acquisition receipts must be a typed tuple")
    keys = tuple(_receipt_sort_key(receipt) for receipt in receipts)
    if len(keys) != len(set(keys)) or keys != tuple(sorted(keys)):
        raise EvidenceAuthorityError("acquisition receipts must be unique and use version order")
    results = {result.tool_result_id: result for result in pack.tool_results}
    if len(receipts) != len(results):
        raise EvidenceAuthorityError("every pack tool result requires exactly one verified receipt")
    seen: set[str] = set()
    for receipt in receipts:
        request = receipt.request
        result = receipt.tool_result
        manifest = receipt.execution_manifest
        expected_result_id = derive_m4_tool_result_id(
            result.action,
            result.input_refs,
            result.output_refs,
            result.validated_parameters,
            result.execution_manifest_id,
        )
        if (
            request.run_id != pack.run_id
            or request.case_id != pack.case_id
            or request.manifest_id != pack.manifest_id
            or manifest.run_id != request.run_id
            or manifest.case_id != request.case_id
            or manifest.hearing_session_id != request.hearing_session_id
            or manifest.acquisition_request_id != request.request_id
            or manifest.action != request.action
            or manifest.manifest_id != request.manifest_id
            or result.action != request.action
            or result.validated_parameters != request.validated_parameters
            or result.execution_manifest_id != manifest.execution_manifest_id
            or result.tool_result_id != expected_result_id
            or receipt.resulting_evidence_pack_version != request.current_evidence_pack_version + 1
            or results.get(result.tool_result_id) != result
            or result.tool_result_id in seen
        ):
            raise EvidenceAuthorityError("acquisition receipt is outside the pack lineage")
        seen.add(result.tool_result_id)
    for previous, current in pairwise(receipts):
        if (
            current.request.current_evidence_pack_id != previous.resulting_evidence_pack_id
            or current.request.current_evidence_pack_version
            != previous.resulting_evidence_pack_version
        ):
            raise EvidenceAuthorityError("acquisition receipt pack lineage is discontinuous")
    if receipts and (
        receipts[-1].resulting_evidence_pack_id != pack.pack_id
        or receipts[-1].resulting_evidence_pack_version != pack.version
    ):
        raise EvidenceAuthorityError("latest acquisition receipt does not close the current pack")


def _draft_without_acquisitions(
    pack: EvidencePack,
    receipts: tuple[ToolExecutionReceipt, ...],
) -> EvidencePackDraft:
    acquired_fact_ids = {
        ref.artifact_id
        for receipt in receipts
        for ref in receipt.tool_result.output_refs
        if ref.kind == ArtifactKind.OBJECTIVE_FACT
    }
    base_facts = tuple(
        fact for fact in pack.objective_facts if fact.fact_id not in acquired_fact_ids
    )
    try:
        return EvidencePackDraft(
            run_id=pack.run_id,
            case_id=pack.case_id,
            version=pack.version,
            complete=pack.complete,
            event=pack.event,
            key_frame_ids=pack.key_frame_ids,
            panorama_crops=pack.panorama_crops,
            subject_crops=pack.subject_crops,
            focus_crops=pack.focus_crops,
            temporal_crops=pack.temporal_crops,
            objective_facts=base_facts,
            track_summary=pack.track_summary,
            confirmation_record=pack.confirmation_record,
            observation_sufficiency_input=pack.observation_sufficiency_input,
            tool_results=(),
            manifest_id=pack.manifest_id,
        )
    except ValueError as exc:
        raise EvidenceAuthorityError("pack acquisition history rewrote base evidence") from exc


def _object_maps(
    loaded: LoadedEvidenceObjects,
) -> tuple[
    dict[ArtifactRef, FrameRef],
    dict[ArtifactRef, Crop],
    dict[ArtifactRef, ObjectiveFact],
    dict[ArtifactRef, Detection],
]:
    return (
        {_frame_ref(frame): frame for frame in loaded.frames},
        {_crop_ref(crop): crop for crop in loaded.crops},
        {_fact_ref(fact): fact for fact in loaded.objective_facts},
        {_detection_ref(detection): detection for detection in loaded.detections},
    )


def _stable_recrop_sources(
    *,
    event_camera_id: str,
    event_stream_id: str,
    available_refs: set[ArtifactRef],
    available_crops: dict[ArtifactRef, Crop],
    prior_results: tuple[ToolResult, ...],
    parameters: RecropParameters,
) -> tuple[ArtifactRef, ...]:
    camera_id, stream_id, _ = parse_frame_id(parameters.frame_id)
    if (camera_id, stream_id) != (event_camera_id, event_stream_id):
        raise AcquisitionAuthorityError("RECROP is restricted to the current event stream")
    frame = _artifact_ref(ArtifactKind.FRAME, parameters.frame_id)
    if frame not in available_refs:
        raise AcquisitionAuthorityError("RECROP frame is absent from current pack closure")
    same_frame_crops = sorted(
        (ref for ref, crop in available_crops.items() if crop.frame_id == parameters.frame_id),
        key=lambda ref: ref.sort_key,
    )
    if same_frame_crops:
        source = same_frame_crops[0]
    else:
        source_results = sorted(
            (_tool_result_ref(result) for result in prior_results if frame in result.output_refs),
            key=lambda ref: ref.sort_key,
        )
        if not source_results:
            raise RecropAuthorityUnrecoverable(
                "RECROP frame has neither an existing crop nor a prior producing tool result"
            )
        source = source_results[0]
    return tuple(sorted((frame, source), key=lambda ref: ref.sort_key))


def derive_recrop_source_refs(
    authority: EvidenceAuthority,
    parameters: RecropParameters,
) -> tuple[ArtifactRef, ...]:
    """Derive the only legal, acyclic source set for a frozen RECROP request."""

    if not isinstance(authority, EvidenceAuthority) or not isinstance(parameters, RecropParameters):
        raise AcquisitionAuthorityError("RECROP source derivation requires typed authority")
    return _stable_recrop_sources(
        event_camera_id=authority.pack.event.camera_id,
        event_stream_id=authority.pack.event.stream_id,
        available_refs=set(authority.pack.expected_closure_refs()),
        available_crops={_crop_ref(crop): crop for crop in authority.crops},
        prior_results=authority.pack.tool_results,
        parameters=parameters,
    )


def validate_recrop_request_authority(
    authority: EvidenceAuthority,
    parameters: RecropParameters,
    crop_request: CropRequest,
) -> None:
    """Require a frozen CropRequest to use the deterministic prior source binding."""

    expected_refs = derive_recrop_source_refs(authority, parameters)
    if (
        not isinstance(crop_request, CropRequest)
        or crop_request.source != CropSource.RECROP
        or crop_request.frame_id != parameters.frame_id
        or crop_request.bbox != parameters.bbox
        or crop_request.source_refs != expected_refs
    ):
        raise AcquisitionAuthorityError("frozen RECROP request conflicts with evidence authority")


def _validate_action_in_history(
    pack: EvidencePack,
    receipt: ToolExecutionReceipt,
    available_refs: set[ArtifactRef],
    available_crops: dict[ArtifactRef, Crop],
    prior_results: tuple[ToolResult, ...],
    frame_objects: dict[ArtifactRef, FrameRef],
    crop_objects: dict[ArtifactRef, Crop],
    fact_objects: dict[ArtifactRef, ObjectiveFact],
    detection_objects: dict[ArtifactRef, Detection],
) -> None:
    result = receipt.tool_result
    parameters = result.validated_parameters
    _validate_action_output_cardinality(result.action, len(result.output_refs))
    if isinstance(parameters, RequestMoreFramesParameters):
        if (parameters.camera_id, parameters.stream_id) != (
            pack.event.camera_id,
            pack.event.stream_id,
        ):
            raise AcquisitionAuthorityError("REQUEST_MORE_FRAMES left the event stream")
        expected_refs = tuple(
            sorted(
                (
                    _artifact_ref(
                        ArtifactKind.FRAME,
                        f"{parameters.camera_id}:{parameters.stream_id}:{frame_index}",
                    )
                    for frame_index in range(
                        parameters.start_frame,
                        parameters.end_frame_exclusive,
                        parameters.step,
                    )
                ),
                key=lambda ref: ref.sort_key,
            )
        )
        if result.output_refs != expected_refs:
            raise AcquisitionAuthorityError(
                "requested-frame outputs do not exactly match range(start, end, step)"
            )
        for ref in expected_refs:
            frame = frame_objects.get(ref)
            if (
                frame is None
                or frame.frame_id != ref.artifact_id
                or frame.camera_id != parameters.camera_id
                or frame.stream_id != parameters.stream_id
                or frame.content_sha256 is None
            ):
                raise EvidenceAuthorityError(
                    "requested-frame output lacks exact loaded content closure"
                )
        return
    if isinstance(parameters, OtherCameraSameTimeParameters):
        source = _artifact_ref(ArtifactKind.FRAME, parameters.source_frame_id)
        source_frame = frame_objects.get(source)
        if (
            source not in available_refs
            or source_frame is None
            or source_frame.content_sha256 is None
        ):
            raise EvidenceAuthorityError("other-camera execution lacks frame closure")
        for ref in result.output_refs:
            frame = frame_objects.get(ref)
            if (
                ref.kind != ArtifactKind.FRAME
                or frame is None
                or frame.frame_id != ref.artifact_id
                or frame.camera_id != parameters.target_camera_id
                or frame.content_sha256 is None
                or frame.timestamp_ms != source_frame.timestamp_ms
            ):
                raise AcquisitionAuthorityError(
                    "other-camera output conflicts with target camera or source timestamp"
                )
        return
    if isinstance(parameters, RecropParameters):
        expected_sources = _stable_recrop_sources(
            event_camera_id=pack.event.camera_id,
            event_stream_id=pack.event.stream_id,
            available_refs=available_refs,
            available_crops=available_crops,
            prior_results=prior_results,
            parameters=parameters,
        )
        if not set(expected_sources).issubset(result.input_refs):
            raise AcquisitionAuthorityError("RECROP tool inputs omit deterministic source refs")
        crop = crop_objects.get(result.output_refs[0]) if len(result.output_refs) == 1 else None
        if (
            crop is None
            or crop.source != CropSource.RECROP
            or crop.frame_id != parameters.frame_id
            or crop.bbox != parameters.bbox
            or crop.source_refs != expected_sources
            or _tool_result_ref(result) in crop.source_refs
        ):
            raise AcquisitionAuthorityError("RECROP output has unstable or cyclic provenance")
        available_crops[_crop_ref(crop)] = crop
        return
    if isinstance(parameters, TrackConfidenceCurveParameters):
        if any(ref.kind != ArtifactKind.OBJECTIVE_FACT for ref in result.output_refs):
            raise AcquisitionAuthorityError("track-confidence outputs must be objective facts")
        allowed_tracks = {
            track
            for track in (pack.event.primary_track_ref, *pack.event.related_track_refs)
            if track is not None
        }
        if parameters.track_ref not in allowed_tracks or not (
            pack.track_summary.start_frame <= parameters.start_frame
            and parameters.end_frame_exclusive <= pack.track_summary.end_frame_exclusive
        ):
            raise AcquisitionAuthorityError("track-confidence request is outside event authority")
        pack_facts = {_fact_ref(fact): fact for fact in pack.objective_facts}
        expected_source = _tool_result_ref(result)
        for ref in result.output_refs:
            fact = pack_facts.get(ref)
            if fact is None:
                raise EvidenceAuthorityError("track-confidence output fact is absent from pack")
            loaded_fact = fact_objects.get(ref)
            if loaded_fact is not None and loaded_fact != fact:
                raise EvidenceAuthorityError("loaded objective fact conflicts with pack fact")
            if (
                fact.source_ref != expected_source
                or fact.source_manifest_id != result.execution_manifest_id
            ):
                raise AcquisitionAuthorityError("track fact lacks exact execution provenance")
        return
    if not isinstance(parameters, RedetectHighResolutionParameters):
        raise AcquisitionAuthorityError("unsupported acquisition parameters")
    source_crop = available_crops.get(_artifact_ref(ArtifactKind.CROP, parameters.crop_id))
    model_manifest_id = receipt.execution_manifest.model_manifest_id
    if source_crop is None or model_manifest_id is None:
        raise AcquisitionAuthorityError("redetection source crop or model authority is absent")
    for ref in result.output_refs:
        detection = detection_objects.get(ref)
        # Detection.bbox is frame-space XYXY.  A crop-local detector must be
        # translated back to this frame-space region before it crosses the port.
        if (
            detection is None
            or detection.frame_id != source_crop.frame_id
            or detection.model_manifest_id != model_manifest_id
            or detection.label not in parameters.prompts
            or detection.bbox.x1 < source_crop.bbox.x1
            or detection.bbox.y1 < source_crop.bbox.y1
            or detection.bbox.x2 > source_crop.bbox.x2
            or detection.bbox.y2 > source_crop.bbox.y2
        ):
            raise AcquisitionAuthorityError(
                "redetection output conflicts with crop, prompt, or model authority"
            )


def derive_artifact_bounds(crops: tuple[Crop, ...]) -> tuple[ArtifactBounds, ...]:
    """Derive deterministic local-pixel bounds for typed crop objects only."""

    refs = tuple(_crop_ref(crop) for crop in crops)
    keys = tuple(ref.sort_key for ref in refs)
    if len(keys) != len(set(keys)) or keys != tuple(sorted(keys)):
        raise EvidenceAuthorityError("artifact bounds require stable unique crop objects")
    return tuple(
        ArtifactBounds(
            artifact_ref=_crop_ref(crop),
            width=crop.output_width,
            height=crop.output_height,
        )
        for crop in crops
    )


def derive_evidence_authority(
    pack: EvidencePack,
    receipts: tuple[ToolExecutionReceipt, ...] = (),
    loaded_objects: LoadedEvidenceObjects | None = None,
) -> EvidenceAuthority:
    """Validate the complete pack lineage and derive its candidate evidence universe."""

    if not isinstance(pack, EvidencePack):
        raise EvidenceAuthorityError("evidence authority requires a closed EvidencePack")
    loaded = loaded_objects if loaded_objects is not None else LoadedEvidenceObjects()
    if not isinstance(loaded, LoadedEvidenceObjects):
        raise EvidenceAuthorityError("evidence authority requires typed loaded objects")
    _validate_receipt_history(pack, receipts)
    base = _draft_without_acquisitions(pack, receipts)
    available_refs = set(base.expected_closure_refs())
    available_crops = {_crop_ref(crop): crop for crop in pack.crops}
    frame_objects, crop_objects, fact_objects, detection_objects = _object_maps(loaded)
    for ref, crop in crop_objects.items():
        embedded = available_crops.get(ref)
        if embedded is not None and embedded != crop:
            raise EvidenceAuthorityError("loaded crop conflicts with immutable pack crop")
    pack_facts = {_fact_ref(fact): fact for fact in pack.objective_facts}
    for ref, fact in fact_objects.items():
        if ref in pack_facts and pack_facts[ref] != fact:
            raise EvidenceAuthorityError("loaded fact conflicts with immutable pack fact")

    prior_results: tuple[ToolResult, ...] = ()
    for receipt in receipts:
        result = receipt.tool_result
        _validate_action_output_cardinality(result.action, len(result.output_refs))
        expected_pack = _artifact_ref(
            ArtifactKind.EVIDENCE_PACK,
            receipt.request.current_evidence_pack_id,
        )
        pack_inputs = tuple(
            ref for ref in result.input_refs if ref.kind == ArtifactKind.EVIDENCE_PACK
        )
        if pack_inputs != (expected_pack,):
            raise AcquisitionAuthorityError("tool result lacks its exact predecessor pack")
        non_pack_inputs = {
            ref for ref in result.input_refs if ref.kind != ArtifactKind.EVIDENCE_PACK
        }
        if not non_pack_inputs.issubset(available_refs):
            raise AcquisitionAuthorityError("tool result consumed future or unclosed evidence")
        if any(ref in available_refs for ref in result.output_refs):
            raise AcquisitionAuthorityError("tool execution rewrote an existing evidence object")
        result_ref = _tool_result_ref(result)
        manifest_ref = _artifact_ref(
            ArtifactKind.MANIFEST,
            receipt.execution_manifest.execution_manifest_id,
        )
        if result_ref in available_refs or manifest_ref in available_refs:
            raise AcquisitionAuthorityError("tool execution identities collide with prior evidence")
        _validate_action_in_history(
            pack,
            receipt,
            available_refs,
            available_crops,
            prior_results,
            frame_objects,
            crop_objects,
            fact_objects,
            detection_objects,
        )
        available_refs.update(result.output_refs)
        available_refs.add(result_ref)
        available_refs.add(manifest_ref)
        prior_results = (*prior_results, result)

    final_refs = set(pack.expected_closure_refs())
    if any(ref not in final_refs for ref in loaded.refs):
        raise EvidenceAuthorityError("loaded object lies outside the exact pack closure")

    crops = tuple(sorted(available_crops.values(), key=lambda crop: _crop_ref(crop).sort_key))
    citable = {
        *(_crop_ref(crop) for crop in crops),
        *(_fact_ref(fact) for fact in pack.objective_facts),
        *(_tool_result_ref(result) for result in pack.tool_results),
    }
    candidate_refs = tuple(sorted(citable, key=lambda ref: ref.sort_key))
    acquisition_refs = tuple(
        sorted(
            (ref for ref in final_refs if ref.kind in {ArtifactKind.FRAME, ArtifactKind.CROP}),
            key=lambda ref: ref.sort_key,
        )
    )
    return EvidenceAuthority(
        pack=pack,
        receipts=receipts,
        loaded_objects=loaded,
        crops=crops,
        candidate_citable_refs=candidate_refs,
        acquisition_input_refs=acquisition_refs,
        artifact_bounds=derive_artifact_bounds(crops),
    )


def derive_citable_refs(authority: EvidenceAuthority) -> tuple[ArtifactRef, ...]:
    """Return candidate role-citable refs; FRAME and DETECTION are absent by design."""

    if not isinstance(authority, EvidenceAuthority):
        raise EvidenceAuthorityError("citable refs require typed evidence authority")
    return authority.candidate_citable_refs


def _media_ref(pack: EvidencePack, crop: Crop) -> VLMMediaRef:
    expected_path = f"{pack.run_id}/frames/{crop.media_sha256}.png"
    if (
        crop.availability != MediaAvailability.AVAILABLE
        or crop.local_path is None
        or crop.local_path != expected_path
    ):
        raise EvidenceDisclosureError("selected crop media is unavailable or non-canonical")
    return VLMMediaRef(
        crop_id=crop.crop_id,
        media_sha256=crop.media_sha256,
        local_path=crop.local_path,
        source=crop.source,
        media_access=crop.privacy_receipt.media_access,
        privacy_policy=crop.privacy_receipt.policy,
        privacy_transform_version=crop.privacy_receipt.transform_version,
        width=crop.output_width,
        height=crop.output_height,
    )


def derive_role_disclosure(
    authority: EvidenceAuthority,
    selected_crop_ids: tuple[str, ...],
) -> RoleEvidenceDisclosure:
    """Grant exactly selected crop pixels plus all non-pixel structured evidence."""

    if not isinstance(selected_crop_ids, tuple) or not selected_crop_ids:
        raise EvidenceDisclosureError("role disclosure requires selected crop IDs")
    if len(selected_crop_ids) != len(set(selected_crop_ids)) or selected_crop_ids != tuple(
        sorted(selected_crop_ids)
    ):
        raise EvidenceDisclosureError("selected crop IDs must be unique and stable")
    crops = {crop.crop_id: crop for crop in authority.crops}
    try:
        selected = tuple(crops[crop_id] for crop_id in selected_crop_ids)
    except KeyError as exc:
        raise EvidenceDisclosureError("selected crop lies outside candidate authority") from exc
    media = tuple(
        sorted(
            (_media_ref(authority.pack, crop) for crop in selected),
            key=lambda item: item.sort_key,
        )
    )
    non_media = {
        ref
        for ref in authority.candidate_citable_refs
        if ref.kind in {ArtifactKind.OBJECTIVE_FACT, ArtifactKind.TOOL_RESULT}
    }
    allowed = tuple(
        sorted(
            (*non_media, *(_crop_ref(crop) for crop in selected)),
            key=lambda ref: ref.sort_key,
        )
    )
    selected_crops = tuple(sorted(selected, key=lambda crop: _crop_ref(crop).sort_key))
    return RoleEvidenceDisclosure(
        run_id=authority.pack.run_id,
        case_id=authority.pack.case_id,
        evidence_pack_id=authority.pack.pack_id,
        evidence_pack_version=authority.pack.version,
        media=media,
        allowed_evidence_refs=allowed,
        artifact_bounds=derive_artifact_bounds(selected_crops),
    )


def extend_hearing_evidence_grant(
    current: HearingEvidenceGrant | None,
    disclosure: RoleEvidenceDisclosure,
) -> HearingEvidenceGrant:
    """Accumulate the exact union of role grants across all hearing cycles."""

    if not isinstance(disclosure, RoleEvidenceDisclosure):
        raise EvidenceDisclosureError("hearing grant requires a typed role disclosure")
    if current is None:
        return HearingEvidenceGrant(
            run_id=disclosure.run_id,
            case_id=disclosure.case_id,
            latest_evidence_pack_id=disclosure.evidence_pack_id,
            latest_evidence_pack_version=disclosure.evidence_pack_version,
            allowed_evidence_refs=disclosure.allowed_evidence_refs,
            artifact_bounds=disclosure.artifact_bounds,
        )
    if (current.run_id, current.case_id) != (disclosure.run_id, disclosure.case_id):
        raise EvidenceDisclosureError("role disclosure belongs to another hearing scope")
    if disclosure.evidence_pack_version == current.latest_evidence_pack_version:
        if disclosure.evidence_pack_id != current.latest_evidence_pack_id:
            raise EvidenceDisclosureError("one pack version cannot have two semantic identities")
    elif disclosure.evidence_pack_version == current.latest_evidence_pack_version + 1:
        if disclosure.evidence_pack_id == current.latest_evidence_pack_id:
            raise EvidenceDisclosureError("new pack version must have a new semantic identity")
    else:
        raise EvidenceDisclosureError("role disclosure pack lineage is not contiguous")

    refs = {ref.sort_key: ref for ref in current.allowed_evidence_refs}
    refs.update({ref.sort_key: ref for ref in disclosure.allowed_evidence_refs})
    bounds = {item.sort_key: item for item in current.artifact_bounds}
    for item in disclosure.artifact_bounds:
        prior = bounds.get(item.sort_key)
        if prior is not None and prior != item:
            raise EvidenceDisclosureError("hearing crop bounds changed across disclosures")
        bounds[item.sort_key] = item
    return HearingEvidenceGrant(
        run_id=current.run_id,
        case_id=current.case_id,
        latest_evidence_pack_id=disclosure.evidence_pack_id,
        latest_evidence_pack_version=disclosure.evidence_pack_version,
        allowed_evidence_refs=tuple(refs[key] for key in sorted(refs)),
        artifact_bounds=tuple(bounds[key] for key in sorted(bounds)),
    )


_IMMUTABLE_SUCCESSOR_FIELDS = (
    "run_id",
    "case_id",
    "complete",
    "event",
    "key_frame_ids",
    "panorama_crops",
    "subject_crops",
    "focus_crops",
    "temporal_crops",
    "track_summary",
    "confirmation_record",
    "observation_sufficiency_input",
    "manifest_id",
)


def _validate_execution_scope(
    current: EvidencePack,
    authority: EvidenceAuthority,
    execution: AcquisitionExecution,
) -> None:
    request = execution.request
    result = execution.tool_result
    if (
        request.run_id != current.run_id
        or request.case_id != current.case_id
        or request.current_evidence_pack_id != current.pack_id
        or request.current_evidence_pack_version != current.version
        or request.manifest_id != current.manifest_id
    ):
        raise AcquisitionAuthorityError("acquisition request is outside the current pack scope")
    expected_pack = _artifact_ref(ArtifactKind.EVIDENCE_PACK, current.pack_id)
    pack_inputs = tuple(ref for ref in result.input_refs if ref.kind == ArtifactKind.EVIDENCE_PACK)
    if pack_inputs != (expected_pack,):
        raise AcquisitionAuthorityError("tool result must bind exactly one current pack")
    current_refs = set(current.expected_closure_refs())
    non_pack_inputs = {ref for ref in result.input_refs if ref.kind != ArtifactKind.EVIDENCE_PACK}
    if not non_pack_inputs.issubset(current_refs):
        raise AcquisitionAuthorityError("tool result consumed evidence outside current closure")
    if any(ref in current_refs for ref in result.output_refs):
        raise AcquisitionAuthorityError("tool result rewrote an existing evidence object")
    if any(existing.tool_result_id == result.tool_result_id for existing in current.tool_results):
        raise AcquisitionAuthorityError("tool result replayed an existing acquisition")

    parameters = result.validated_parameters
    if isinstance(parameters, RequestMoreFramesParameters):
        if (parameters.camera_id, parameters.stream_id) != (
            current.event.camera_id,
            current.event.stream_id,
        ):
            raise AcquisitionAuthorityError("REQUEST_MORE_FRAMES left the event stream")
    elif isinstance(parameters, OtherCameraSameTimeParameters):
        source = _artifact_ref(ArtifactKind.FRAME, parameters.source_frame_id)
        if source not in current_refs:
            raise AcquisitionAuthorityError("other-camera source frame is outside current closure")
        source_frame = next(
            (
                frame
                for frame in authority.loaded_objects.frames
                if frame.frame_id == parameters.source_frame_id
            ),
            None,
        )
        if source_frame is None or source_frame.content_sha256 is None:
            raise AcquisitionAuthorityError(
                "other-camera source frame lacks loaded content authority"
            )
        if any(
            frame.camera_id != parameters.target_camera_id
            or frame.content_sha256 is None
            or frame.timestamp_ms != source_frame.timestamp_ms
            for frame in execution.output_objects.frames
        ):
            raise AcquisitionAuthorityError(
                "other-camera output conflicts with source timestamp authority"
            )
    elif isinstance(parameters, RecropParameters):
        crop_request = execution.crop_request
        if crop_request is None:
            raise AcquisitionAuthorityError("RECROP requires a frozen CropRequest")
        validate_recrop_request_authority(authority, parameters, crop_request)
        if not set(crop_request.source_refs).issubset(result.input_refs):
            raise AcquisitionAuthorityError("RECROP tool inputs omit frozen source authority")
    elif isinstance(parameters, TrackConfidenceCurveParameters):
        allowed_tracks = {
            track
            for track in (current.event.primary_track_ref, *current.event.related_track_refs)
            if track is not None
        }
        if parameters.track_ref not in allowed_tracks or not (
            current.track_summary.start_frame <= parameters.start_frame
            and parameters.end_frame_exclusive <= current.track_summary.end_frame_exclusive
        ):
            raise AcquisitionAuthorityError("track-confidence request is outside event authority")
    elif isinstance(parameters, RedetectHighResolutionParameters):
        source_crop = next(
            (crop for crop in authority.crops if crop.crop_id == parameters.crop_id),
            None,
        )
        if source_crop is None:
            raise AcquisitionAuthorityError("redetection crop is outside current pack authority")
        if any(
            detection.frame_id != source_crop.frame_id
            or detection.label not in parameters.prompts
            or detection.bbox.x1 < source_crop.bbox.x1
            or detection.bbox.y1 < source_crop.bbox.y1
            or detection.bbox.x2 > source_crop.bbox.x2
            or detection.bbox.y2 > source_crop.bbox.y2
            for detection in execution.output_objects.detections
        ):
            raise AcquisitionAuthorityError(
                "redetection output conflicts with source crop coordinates or prompts"
            )
    else:
        raise AcquisitionAuthorityError("unsupported acquisition action")


def derive_evidence_pack_successor(
    current: EvidencePack,
    execution: AcquisitionExecution,
    *,
    current_receipts: tuple[ToolExecutionReceipt, ...] = (),
    current_loaded_objects: LoadedEvidenceObjects | None = None,
) -> EvidencePackDraft:
    """Derive the only legal M4 EvidencePack v+1 draft for one execution."""

    authority = derive_evidence_authority(
        current,
        current_receipts,
        current_loaded_objects,
    )
    if not isinstance(execution, AcquisitionExecution):
        raise AcquisitionAuthorityError("successor derivation requires typed execution output")
    _validate_execution_scope(current, authority, execution)
    added_facts = (
        execution.output_objects.objective_facts
        if execution.request.action == AcquisitionAction.TRACK_CONFIDENCE_CURVE
        else ()
    )
    facts = tuple(sorted((*current.objective_facts, *added_facts), key=lambda fact: fact.fact_id))
    results = tuple(
        sorted(
            (*current.tool_results, execution.tool_result),
            key=lambda result: result.tool_result_id,
        )
    )
    try:
        return EvidencePackDraft(
            run_id=current.run_id,
            case_id=current.case_id,
            version=current.version + 1,
            complete=current.complete,
            event=current.event,
            key_frame_ids=current.key_frame_ids,
            panorama_crops=current.panorama_crops,
            subject_crops=current.subject_crops,
            focus_crops=current.focus_crops,
            temporal_crops=current.temporal_crops,
            objective_facts=facts,
            track_summary=current.track_summary,
            confirmation_record=current.confirmation_record,
            observation_sufficiency_input=current.observation_sufficiency_input,
            tool_results=results,
            manifest_id=current.manifest_id,
        )
    except ValueError as exc:
        raise EvidencePackSuccessorError("acquisition cannot form a valid pack successor") from exc


def _validate_semantic_superset(
    current: EvidencePack,
    successor: EvidencePack,
    receipt: ToolExecutionReceipt,
) -> None:
    if successor.version != current.version + 1:
        raise EvidencePackSuccessorError("acquisition successor must advance exactly one version")
    for field_name in _IMMUTABLE_SUCCESSOR_FIELDS:
        if getattr(successor, field_name) != getattr(current, field_name):
            raise EvidencePackSuccessorError(
                f"acquisition successor rewrote immutable field {field_name}"
            )
    old_results = {result.tool_result_id: result for result in current.tool_results}
    new_results = {result.tool_result_id: result for result in successor.tool_results}
    if any(new_results.get(result_id) != result for result_id, result in old_results.items()):
        raise EvidencePackSuccessorError("acquisition rewrote or removed an old tool result")
    added_results = set(new_results) - set(old_results)
    if added_results != {receipt.tool_result.tool_result_id} or (
        new_results.get(receipt.tool_result.tool_result_id) != receipt.tool_result
    ):
        raise EvidencePackSuccessorError("acquisition must add exactly its receipted tool result")
    old_facts = {fact.fact_id: fact for fact in current.objective_facts}
    new_facts = {fact.fact_id: fact for fact in successor.objective_facts}
    if any(new_facts.get(fact_id) != fact for fact_id, fact in old_facts.items()):
        raise EvidencePackSuccessorError("acquisition rewrote or removed an old objective fact")
    added_facts = set(new_facts) - set(old_facts)
    if receipt.request.action == AcquisitionAction.TRACK_CONFIDENCE_CURVE:
        expected = {ref.artifact_id for ref in receipt.tool_result.output_refs}
        if added_facts != expected:
            raise EvidencePackSuccessorError("track successor facts do not match exact outputs")
    elif added_facts:
        raise EvidencePackSuccessorError("non-track acquisition added objective facts")


def validate_evidence_pack_successor(
    current: EvidencePack,
    successor: EvidencePack,
    receipt: ToolExecutionReceipt,
    *,
    current_receipts: tuple[ToolExecutionReceipt, ...] = (),
    loaded_objects: LoadedEvidenceObjects | None = None,
) -> EvidenceAuthority:
    """Validate a persisted successor and return its complete hearing authority."""

    if not isinstance(successor, EvidencePack) or not isinstance(receipt, ToolExecutionReceipt):
        raise EvidencePackSuccessorError("successor validation requires closed typed artifacts")
    request = receipt.request
    if (
        request.run_id != current.run_id
        or request.case_id != current.case_id
        or request.current_evidence_pack_id != current.pack_id
        or request.current_evidence_pack_version != current.version
        or request.manifest_id != current.manifest_id
        or receipt.resulting_evidence_pack_id != successor.pack_id
        or receipt.resulting_evidence_pack_version != successor.version
    ):
        raise EvidencePackSuccessorError("tool receipt does not bind predecessor and successor")
    _validate_semantic_superset(current, successor, receipt)
    receipts = (*current_receipts, receipt)
    return derive_evidence_authority(successor, receipts, loaded_objects)


def finalize_evidence_pack_successor(
    current: EvidencePack,
    execution: AcquisitionExecution,
    closure_report: ClosureReport | None,
    *,
    current_receipts: tuple[ToolExecutionReceipt, ...] = (),
    current_loaded_objects: LoadedEvidenceObjects | None = None,
) -> EvidencePackUpdate:
    """Close, receipt, and revalidate one atomic semantic-superset update."""

    draft = derive_evidence_pack_successor(
        current,
        execution,
        current_receipts=current_receipts,
        current_loaded_objects=current_loaded_objects,
    )
    if not isinstance(closure_report, ClosureReport):
        raise EvidencePackSuccessorError("pack successor requires its exact passing closure")
    payload = draft.model_dump(mode="python", exclude={"pack_id"})
    payload["closure_report"] = closure_report
    try:
        successor = EvidencePack.model_validate(payload)
        receipt = ToolExecutionReceipt(
            request=execution.request,
            execution_manifest=execution.execution_manifest,
            tool_result=execution.tool_result,
            resulting_evidence_pack_id=successor.pack_id,
            resulting_evidence_pack_version=successor.version,
        )
    except ValueError as exc:
        raise EvidencePackSuccessorError("pack successor closure or receipt is invalid") from exc
    before = current_loaded_objects or LoadedEvidenceObjects()
    loaded = merge_loaded_evidence_objects(before, execution.output_objects)
    authority = validate_evidence_pack_successor(
        current,
        successor,
        receipt,
        current_receipts=current_receipts,
        loaded_objects=loaded,
    )
    receipts = (*current_receipts, receipt)
    return EvidencePackUpdate(
        pack=successor,
        receipt=receipt,
        receipts=receipts,
        loaded_objects=loaded,
        authority=authority,
    )


__all__ = [
    "AcquisitionAuthorityError",
    "AcquisitionExecution",
    "EvidenceAuthority",
    "EvidenceAuthorityError",
    "EvidenceDisclosureError",
    "EvidencePackSuccessorError",
    "EvidencePackUpdate",
    "HearingEvidenceGrant",
    "LoadedEvidenceObjects",
    "RecropAuthorityUnrecoverable",
    "RoleEvidenceDisclosure",
    "derive_artifact_bounds",
    "derive_citable_refs",
    "derive_evidence_authority",
    "derive_evidence_pack_successor",
    "derive_recrop_source_refs",
    "derive_role_disclosure",
    "extend_hearing_evidence_grant",
    "finalize_evidence_pack_successor",
    "merge_loaded_evidence_objects",
    "validate_evidence_pack_successor",
    "validate_recrop_request_authority",
]

"""Versioned, whitelist-only M6 semantic projection for a frozen Case."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import cast

from labcourt.contracts.alert_policy import AlertPolicyAuthority
from labcourt.contracts.alerts import AlertDecision
from labcourt.contracts.appeals import Appeal
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case, TimelineEntry, UsageSummary
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import (
    AlertLevel,
    AppealStatus,
    ArtifactKind,
    AuditAction,
    CaseStatus,
    ProceduralDefectCode,
    ProceduralReasonCode,
    ScreeningDecision,
    VlmRole,
)
from labcourt.contracts.events import CandidateEvent, ConfirmationRecord, ObjectiveFact
from labcourt.contracts.evidence import (
    Crop,
    CropRequest,
    EvidencePack,
    ObservationSufficiencyInput,
    ToolResult,
    TrackConfidenceCurveParameters,
    TrackSummary,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.hearing_acquisition import (
    AcquisitionExecutionPublication,
    AcquisitionRequest,
    ToolExecutionManifest,
    ToolExecutionReceipt,
)
from labcourt.contracts.hearing_persistence import EvidencePackDerivation
from labcourt.contracts.hearing_state import (
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
)
from labcourt.contracts.m3_models import EvidenceCitation
from labcourt.contracts.m5_precedent_usage import M5PrecedentExposureBatchAuthority
from labcourt.contracts.m5_precedents import (
    M5EmbeddingVector,
    M5PrecedentAuthority,
    M5PrecedentCandidateEvaluation,
    M5PrecedentPolicy,
    M5PrecedentRetrievalQuery,
    M5ScoredPrecedent,
)
from labcourt.contracts.m6_regression import (
    M6CaseReplaySnapshot,
    M6RegressionStage,
    M6SemanticStageRoot,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallInput,
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
    M6LockedToolResultInput,
)
from labcourt.contracts.precedents import Precedent, ScoredPrecedent
from labcourt.contracts.references import parse_frame_id, require_reference_token
from labcourt.contracts.screening import ParsedScreeningOutput, ScreeningResult
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.contracts.verdicts import (
    AcquisitionLogEntry,
    Argument,
    JudgeResponse,
    ObjectiveClaim,
    ObservationSufficiency,
    PrecedentApplication,
    ProceduralDefect,
    Verdict,
)
from labcourt.domain.m6_model_reference_authority import (
    M6CaseModelReferenceAuthority,
    M6FastVerdictModelReferenceBinding,
    M6ModelReferenceScope,
    M6VerdictModelReferenceBinding,
)
from labcourt.domain.m6_procedural_gate_authority import (
    M6CaseProceduralGateAuthority,
    M6ProceduralGateExecutionInput,
    build_m6_gate_precedent_resolutions,
)
from labcourt.domain.m6_semantic_identity import (
    M6SemanticTrackIndex,
    build_m6_semantic_track_index,
    m6_semantic_detection_body,
)
from labcourt.domain.screening_router import (
    FastVerdictBuilder,
    ScreeningRouteError,
    ScreeningRoutePolicy,
    ScreeningRouter,
)

_ALERT_RANK = {
    AlertLevel.ADVISORY: 0,
    AlertLevel.CONFIRMED: 1,
    AlertLevel.EMERGENCY: 2,
}
_MODEL_LAYER_RANK = {value: index for index, value in enumerate(M6LockedModelCallLayer)}
_MODEL_ROLE_RANK = {value: index for index, value in enumerate(M6LockedModelRole)}


def _require_sha256(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name} must be a lowercase SHA-256")
    return value


def _document_sha256(value: object) -> str:
    model_dump = getattr(value, "model_dump", None)
    if not callable(model_dump):
        raise TypeError("M6 authority document must be a typed contract")
    return hashlib.sha256(canonical_json(model_dump(mode="json")).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class M6ResolvedPerception:
    frames: tuple[FrameRef, ...]
    detections: tuple[Detection, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.frames, tuple) or not self.frames:
            raise ValueError("M6 resolved perception requires a non-empty Frame tuple")
        if any(not isinstance(item, FrameRef) for item in self.frames):
            raise TypeError("M6 resolved perception frames must be typed documents")
        if not isinstance(self.detections, tuple) or any(
            not isinstance(item, Detection) for item in self.detections
        ):
            raise TypeError("M6 resolved perception detections must be a tuple")
        frames = tuple(
            FrameRef.model_validate(item.model_dump(mode="json", exclude_computed_fields=True))
            for item in self.frames
        )
        detections = tuple(
            Detection.model_validate(item.model_dump(mode="json", exclude_computed_fields=True))
            for item in self.detections
        )
        frame_keys = tuple(parse_frame_id(item.frame_id) for item in frames)
        if frame_keys != tuple(sorted(frame_keys)) or len(frame_keys) != len(set(frame_keys)):
            raise ValueError("M6 resolved perception frames must be unique semantic-time order")
        if any(item.content_sha256 is None for item in frames):
            raise ValueError("M6 resolved perception Frame content hash is required")
        detection_keys = tuple(
            (parse_frame_id(item.frame_id), item.detection_id) for item in detections
        )
        if detection_keys != tuple(sorted(detection_keys)) or len(detection_keys) != len(
            set(detection_keys)
        ):
            raise ValueError("M6 resolved perception detections must be unique stable order")
        frame_by_id = {item.frame_id: item for item in frames}
        for detection in detections:
            frame = frame_by_id.get(detection.frame_id)
            if frame is None:
                raise ValueError("M6 resolved perception detection references an unknown Frame")
            detection.bbox.require_within(frame.width, frame.height)
        object.__setattr__(self, "frames", frames)
        object.__setattr__(self, "detections", detections)


@dataclass(frozen=True, slots=True)
class M6ResolvedRetrievalCycle:
    cycle_index: int
    success_exposure: M5PrecedentExposureBatchAuthority | None = None
    degraded_receipt: HearingPrecedentRetrievalReceipt | None = None

    def __post_init__(self) -> None:
        if isinstance(self.cycle_index, bool) or self.cycle_index < 1:
            raise ValueError("M6 resolved retrieval cycle_index must be positive")
        if (self.success_exposure is None) == (self.degraded_receipt is None):
            raise ValueError("M6 resolved retrieval cycle requires exactly one outcome authority")
        if self.success_exposure is not None:
            if not isinstance(self.success_exposure, M5PrecedentExposureBatchAuthority):
                raise TypeError("M6 successful retrieval must be an M5 exposure authority")
            exposure = M5PrecedentExposureBatchAuthority.model_validate(
                self.success_exposure.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                )
            )
            if exposure.cycle_index != self.cycle_index:
                raise ValueError("M6 successful retrieval authority uses another cycle")
            object.__setattr__(self, "success_exposure", exposure)
            return
        if not isinstance(self.degraded_receipt, HearingPrecedentRetrievalReceipt):
            raise TypeError("M6 degraded retrieval must be an M4 retrieval receipt")
        receipt = HearingPrecedentRetrievalReceipt.model_validate(
            self.degraded_receipt.model_dump(
                mode="json",
                exclude_computed_fields=True,
            )
        )
        if (
            receipt.round_index != self.cycle_index
            or receipt.status != HearingPrecedentRetrievalStatus.DEGRADED
            or receipt.candidate_precedent_refs
            or receipt.visible_precedent_refs
            or receipt.scored_precedents
        ):
            raise ValueError("M6 degraded retrieval receipt is not an empty exact cycle outcome")
        object.__setattr__(self, "degraded_receipt", receipt)

    @property
    def hearing_session_id(self) -> str:
        if self.success_exposure is not None:
            return self.success_exposure.hearing_session_id
        assert self.degraded_receipt is not None
        return self.degraded_receipt.hearing_session_id

    @property
    def cycle_scope_id(self) -> str:
        if self.success_exposure is not None:
            return self.success_exposure.cycle_scope_id
        assert self.degraded_receipt is not None
        return self.degraded_receipt.cycle_scope_id


@dataclass(frozen=True, slots=True)
class M6ResolvedModelResponse:
    """Operational response identity resolved to a run-independent semantic authority."""

    layer: M6LockedModelCallLayer
    role: M6LockedModelRole
    attempt_index: int
    response_id: str
    raw_content_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.layer, M6LockedModelCallLayer):
            raise TypeError("M6 resolved model response layer must be typed")
        if not isinstance(self.role, M6LockedModelRole):
            raise TypeError("M6 resolved model response role must be typed")
        if (
            isinstance(self.attempt_index, bool)
            or not isinstance(self.attempt_index, int)
            or self.attempt_index not in {0, 1}
        ):
            raise ValueError("M6 resolved model response attempt_index must be zero or one")
        _require_sha256(self.response_id, "M6 resolved model response_id")
        _require_sha256(
            self.raw_content_sha256,
            "M6 resolved model response content hash",
        )
        if self.layer == M6LockedModelCallLayer.SCREENING:
            if self.role != M6LockedModelRole.SCREENING:
                raise ValueError("M6 screening response requires the screening role")
        elif self.role == M6LockedModelRole.SCREENING:
            raise ValueError("M6 hearing response cannot use the screening role")

    @property
    def sort_key(self) -> tuple[int, int, int, str]:
        return (
            _MODEL_LAYER_RANK[self.layer],
            _MODEL_ROLE_RANK[self.role],
            self.attempt_index,
            self.response_id,
        )

    @property
    def semantic_sort_key(self) -> tuple[int, int, int, str]:
        return (
            _MODEL_LAYER_RANK[self.layer],
            _MODEL_ROLE_RANK[self.role],
            self.attempt_index,
            self.raw_content_sha256,
        )

    def semantic_projection(self) -> dict[str, object]:
        return {
            "layer": self.layer.value,
            "role": self.role.value,
            "attempt_index": self.attempt_index,
            "raw_content_sha256": self.raw_content_sha256,
        }


def resolve_m6_locked_model_responses(
    model_calls: tuple[M6LockedModelCallInput, ...],
) -> tuple[M6ResolvedModelResponse, ...]:
    """Resolve response IDs from a canonical locked call inventory.

    Failure calls remain part of the input closure but have no response content
    to project.  They therefore do not fabricate a semantic response authority.
    """

    if not isinstance(model_calls, tuple) or any(
        not isinstance(item, M6LockedModelCallInput) for item in model_calls
    ):
        raise TypeError("M6 locked model_calls must be a typed tuple")
    canonical_calls = tuple(
        M6LockedModelCallInput.model_validate(
            item.model_dump(mode="json", exclude_computed_fields=True)
        )
        for item in model_calls
    )
    call_keys = tuple(item.sort_key for item in canonical_calls)
    if call_keys != tuple(sorted(call_keys)) or len(call_keys) != len(set(call_keys)):
        raise ValueError("M6 locked model_calls must use stable unique order")
    responses = tuple(
        M6ResolvedModelResponse(
            layer=item.layer,
            role=item.role,
            attempt_index=item.attempt_index,
            response_id=item.response_ref.artifact_id,
            raw_content_sha256=item.raw_content_sha256,
        )
        for item in canonical_calls
        if item.result_kind == M6LockedModelCallResultKind.RESPONSE
        and item.response_ref is not None
        and item.raw_content_sha256 is not None
    )
    ordered = tuple(sorted(responses, key=lambda item: item.sort_key))
    response_ids = tuple(item.response_id for item in ordered)
    if len(response_ids) != len(set(response_ids)):
        raise ValueError("M6 locked model response authorities must be unique")
    return ordered


@dataclass(frozen=True, slots=True)
class M6ResolvedAcquisition:
    """One locked tool result resolved to its complete typed M4 authority chain."""

    locked_input: M6LockedToolResultInput
    request: AcquisitionRequest
    execution_manifest: ToolExecutionManifest
    publication: AcquisitionExecutionPublication
    receipt: ToolExecutionReceipt
    derivation: EvidencePackDerivation
    previous_evidence_pack: EvidencePack
    resulting_evidence_pack: EvidencePack

    def __post_init__(self) -> None:
        models = (
            ("locked_input", M6LockedToolResultInput),
            ("request", AcquisitionRequest),
            ("execution_manifest", ToolExecutionManifest),
            ("publication", AcquisitionExecutionPublication),
            ("receipt", ToolExecutionReceipt),
            ("derivation", EvidencePackDerivation),
            ("previous_evidence_pack", EvidencePack),
            ("resulting_evidence_pack", EvidencePack),
        )
        canonical: dict[str, object] = {}
        for field_name, model_type in models:
            value = getattr(self, field_name)
            if not isinstance(value, model_type):
                raise TypeError(f"M6 resolved acquisition {field_name} must be typed")
            validated = model_type.model_validate(
                value.model_dump(mode="json", exclude_computed_fields=True)
            )
            canonical[field_name] = validated
            object.__setattr__(self, field_name, validated)

        locked = canonical["locked_input"]
        request = canonical["request"]
        manifest = canonical["execution_manifest"]
        publication = canonical["publication"]
        receipt = canonical["receipt"]
        derivation = canonical["derivation"]
        previous = canonical["previous_evidence_pack"]
        resulting = canonical["resulting_evidence_pack"]
        assert isinstance(locked, M6LockedToolResultInput)
        assert isinstance(request, AcquisitionRequest)
        assert isinstance(manifest, ToolExecutionManifest)
        assert isinstance(publication, AcquisitionExecutionPublication)
        assert isinstance(receipt, ToolExecutionReceipt)
        assert isinstance(derivation, EvidencePackDerivation)
        assert isinstance(previous, EvidencePack)
        assert isinstance(resulting, EvidencePack)

        result = publication.tool_result
        if (
            publication.request != request
            or publication.execution_manifest != manifest
            or receipt.request != request
            or receipt.execution_manifest != manifest
            or receipt.tool_result != result
        ):
            raise ValueError("M6 acquisition documents do not form one exact execution")
        if (
            request.run_id != previous.run_id
            or request.case_id != previous.case_id
            or request.manifest_id != previous.manifest_id
            or request.current_evidence_pack_id != previous.pack_id
            or request.current_evidence_pack_version != previous.version
            or resulting.run_id != previous.run_id
            or resulting.case_id != previous.case_id
            or resulting.manifest_id != previous.manifest_id
        ):
            raise ValueError("M6 acquisition authority differs from its EvidencePack scope")
        if (
            receipt.resulting_evidence_pack_id != resulting.pack_id
            or receipt.resulting_evidence_pack_version != resulting.version
            or derivation.run_id != request.run_id
            or derivation.case_id != request.case_id
            or derivation.hearing_session_id != request.hearing_session_id
            or derivation.previous_evidence_pack_id != previous.pack_id
            or derivation.previous_evidence_pack_version != previous.version
            or derivation.new_evidence_pack_id != resulting.pack_id
            or derivation.new_evidence_pack_version != resulting.version
            or derivation.tool_execution_receipt_id != receipt.receipt_id
            or derivation.manifest_id != request.manifest_id
        ):
            raise ValueError("M6 acquisition derivation does not bind its exact pack transition")
        previous_results = {item.tool_result_id: item for item in previous.tool_results}
        resulting_results = {item.tool_result_id: item for item in resulting.tool_results}
        if (
            result.tool_result_id in previous_results
            or resulting_results.get(result.tool_result_id) != result
            or set(resulting_results) - set(previous_results) != {result.tool_result_id}
        ):
            raise ValueError("M6 acquisition successor lacks its exact new ToolResult")

        document_matrix = (
            (locked.acquisition_request_ref, request.request_id, request),
            (locked.execution_manifest_ref, manifest.execution_manifest_id, manifest),
            (locked.execution_publication_ref, publication.publication_id, publication),
            (locked.tool_receipt_ref, receipt.receipt_id, receipt),
            (locked.evidence_pack_derivation_ref, derivation.derivation_id, derivation),
            (
                locked.resulting_evidence_pack_ref,
                resulting.pack_id,
                resulting,
            ),
        )
        if any(
            ref.artifact_id != artifact_id or ref.document_sha256 != _document_sha256(document)
            for ref, artifact_id, document in document_matrix
        ):
            raise ValueError("M6 acquisition closure reference conflicts with typed authority")
        if (
            locked.tool_result_id != result.tool_result_id
            or locked.tool_result_document_sha256 != _document_sha256(result)
        ):
            raise ValueError("M6 acquisition closure conflicts with its ToolResult document")

    @property
    def tool_result_id(self) -> str:
        return self.publication.tool_result.tool_result_id

    @property
    def sort_key(self) -> tuple[int, str]:
        return self.resulting_evidence_pack.version, self.tool_result_id

    def semantic_projection(self) -> dict[str, object]:
        tracks = build_m6_semantic_track_index(acquisitions=((self.request, self.publication),))
        return _acquisition_authority(self, tracks)

    @property
    def semantic_sha256(self) -> str:
        return sha256_hex(["m6-resolved-acquisition-semantic", 1, self.semantic_projection()])


def _case_tool_result_refs(case: Case) -> tuple[ArtifactRef, ...]:
    refs: list[ArtifactRef] = []

    def include(ref: ArtifactRef) -> None:
        if ref.kind == ArtifactKind.TOOL_RESULT:
            refs.append(ref)

    for fact in case.event.objective_facts:
        include(fact.source_ref)
    for pack in case.evidence_packs:
        for fact in pack.objective_facts:
            include(fact.source_ref)
        for crop in pack.crops:
            for ref in crop.source_refs:
                include(ref)
            for ref in crop.privacy_receipt.input_refs:
                include(ref)
        for result in pack.tool_results:
            for ref in (*result.input_refs, *result.output_refs):
                include(ref)
    for verdict in case.verdicts:
        for citation in verdict.evidence_citations:
            include(citation.evidence_ref)
        for argument in (*verdict.prosecution_arguments, *verdict.defense_arguments):
            for ref in argument.evidence_refs:
                include(ref)
        for response in verdict.judge_responses:
            for ref in response.evidence_refs:
                include(ref)
        for entry in verdict.acquisition_log:
            if entry.tool_result_ref is not None:
                include(entry.tool_result_ref)
    return tuple(refs)


@dataclass(frozen=True, slots=True)
class M6VerifiedProjectionContext:
    """Typed semantic inputs reconstructed from one validated authority snapshot.

    The repository layer owns graph completeness.  This pure domain context keeps
    historical retrieval authority separate from the Case aggregate so an M5
    candidate-set or ranking change cannot disappear behind an unchanged Verdict.
    """

    case: Case
    perception: M6ResolvedPerception
    historical_source_run_id: str
    historical_source_case_id: str
    historical_source_manifest_id: str
    model_reference_authority: M6CaseModelReferenceAuthority
    procedural_gate_authority: M6CaseProceduralGateAuthority
    model_responses: tuple[M6ResolvedModelResponse, ...] = ()
    retrieval_cycles: tuple[M6ResolvedRetrievalCycle, ...] = ()
    acquisitions: tuple[M6ResolvedAcquisition, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.case, Case):
            raise TypeError("M6 projection context case must be a validated Case")
        if not isinstance(self.perception, M6ResolvedPerception):
            raise TypeError("M6 projection context perception must be resolved")
        if not isinstance(self.model_reference_authority, M6CaseModelReferenceAuthority):
            raise TypeError("M6 projection model reference authority must be resolved")
        if not isinstance(self.procedural_gate_authority, M6CaseProceduralGateAuthority):
            raise TypeError("M6 projection procedural Gate authority must be resolved")
        require_reference_token(
            self.historical_source_run_id,
            "M6 projection historical source run_id",
        )
        require_reference_token(
            self.historical_source_case_id,
            "M6 projection historical source case_id",
        )
        _require_sha256(
            self.historical_source_manifest_id,
            "M6 projection historical source manifest",
        )
        validated_case = Case.model_validate(
            self.case.model_dump(mode="json", exclude_computed_fields=True)
        )
        if (
            validated_case.run_id != self.historical_source_run_id
            or validated_case.case_id != self.historical_source_case_id
            or validated_case.manifest_id != self.historical_source_manifest_id
        ):
            raise ValueError("M6 projection Case differs from historical source scope")
        reference_authority = self.model_reference_authority
        if (
            reference_authority.run_id != validated_case.run_id
            or reference_authority.case_id != validated_case.case_id
            or reference_authority.manifest_id != validated_case.manifest_id
        ):
            raise ValueError("M6 model reference authority differs from source Case scope")
        gate_authority = self.procedural_gate_authority
        if (
            gate_authority.run_id != validated_case.run_id
            or gate_authority.case_id != validated_case.case_id
            or gate_authority.manifest_id != validated_case.manifest_id
            or gate_authority.source_identity_sha256 != reference_authority.source_identity_sha256
        ):
            raise ValueError("M6 procedural Gate authority differs from source Case scope")
        gate_inputs = tuple(
            gate_authority.input_for_review(review) for review in validated_case.procedural_reviews
        )
        if len(gate_inputs) != len(gate_authority.inputs):
            raise ValueError("M6 procedural Gate authority does not exactly cover source reviews")
        verdicts_by_id = {item.verdict_id: item for item in validated_case.verdicts}
        packs_by_key = {
            (item.pack_id, item.version): item for item in validated_case.evidence_packs
        }
        for item in gate_inputs:
            if (
                verdicts_by_id.get(item.verdict.verdict_id) != item.verdict
                or packs_by_key.get((item.evidence_pack.pack_id, item.evidence_pack.version))
                != item.evidence_pack
            ):
                raise ValueError("M6 procedural Gate input rewrites source authority")
        screening_bindings = {
            item.screening_id: item for item in reference_authority.screening_bindings
        }
        verdict_bindings = {item.verdict_id: item for item in reference_authority.verdict_bindings}
        fast_verdict_bindings = {
            item.verdict_id: item for item in reference_authority.fast_verdict_bindings
        }
        if set(screening_bindings) != {
            item.screening_id for item in validated_case.screening_results
        }:
            raise ValueError("M6 model reference authority does not exactly cover screenings")
        case_verdict_ids = {item.verdict_id for item in validated_case.verdicts}
        if (
            set(verdict_bindings) & set(fast_verdict_bindings)
            or set(verdict_bindings) | set(fast_verdict_bindings) != case_verdict_ids
        ):
            raise ValueError("M6 model reference authority does not exactly partition verdicts")
        for screening in validated_case.screening_results:
            screening_binding = screening_bindings[screening.screening_id]
            if (
                screening_binding.parsed_output_id != screening.parsed_output.parsed_output_id
                or screening_binding.scope.evidence_pack_id != screening.evidence_pack_id
                or screening_binding.scope.evidence_pack_version != screening.evidence_pack_version
                or screening_binding.scope.cycle_scope_id is not None
                or screening_binding.scope.allowed_precedent_refs
            ):
                raise ValueError("M6 screening reference binding conflicts with its result")
        for verdict in (
            item for item in validated_case.verdicts if item.verdict_id in verdict_bindings
        ):
            verdict_binding = verdict_bindings[verdict.verdict_id]
            verdict_response_ids = {ref.artifact_id for ref in verdict.model_response_refs}
            role_cycle_scope_ids = {
                item.scope.cycle_scope_id for item in verdict_binding.role_bindings
            }
            if (
                any(
                    item.scope.evidence_pack_id != verdict.evidence_pack_id
                    or item.scope.evidence_pack_version != verdict.evidence_pack_version
                    or item.response_id not in verdict_response_ids
                    for item in verdict_binding.role_bindings
                )
                or len(role_cycle_scope_ids) != 1
                or None in role_cycle_scope_ids
            ):
                raise ValueError("M6 Verdict reference binding conflicts with its terminal cycle")
        screenings_by_id = {item.screening_id: item for item in validated_case.screening_results}
        for verdict in (
            item for item in validated_case.verdicts if item.verdict_id in fast_verdict_bindings
        ):
            binding = fast_verdict_bindings[verdict.verdict_id]
            fast_screening = screenings_by_id.get(binding.screening_id)
            pack = packs_by_key.get((verdict.evidence_pack_id, verdict.evidence_pack_version))
            if (
                fast_screening is None
                or pack is None
                or verdict.screening_id != fast_screening.screening_id
                or binding.scope != screening_bindings[fast_screening.screening_id].scope
                or binding.scope.evidence_pack_id != verdict.evidence_pack_id
                or binding.scope.evidence_pack_version != verdict.evidence_pack_version
                or binding.scope.cycle_scope_id is not None
                or binding.scope.allowed_precedent_refs
                or binding.response_ids
                != tuple(sorted(ref.artifact_id for ref in verdict.model_response_refs))
                or fast_screening.parsed_output.response_id not in binding.response_ids
            ):
                raise ValueError("M6 fast Verdict binding conflicts with its screening route")
            try:
                rebuilt = FastVerdictBuilder().build(
                    fast_screening,
                    pack,
                    version=verdict.version,
                    model_response_refs=verdict.model_response_refs,
                )
            except (ScreeningRouteError, TypeError, ValueError) as exc:
                raise ValueError("M6 fast Verdict cannot be deterministically rebuilt") from exc
            if rebuilt != verdict:
                raise ValueError("M6 fast Verdict differs from deterministic M3 output")
        if not isinstance(self.retrieval_cycles, tuple) or any(
            not isinstance(item, M6ResolvedRetrievalCycle) for item in self.retrieval_cycles
        ):
            raise TypeError("M6 projection retrieval_cycles must be a typed tuple")
        if not isinstance(self.model_responses, tuple) or any(
            not isinstance(item, M6ResolvedModelResponse) for item in self.model_responses
        ):
            raise TypeError("M6 projection model_responses must be a typed tuple")
        response_keys = tuple(item.sort_key for item in self.model_responses)
        if response_keys != tuple(sorted(response_keys)):
            raise ValueError("M6 model responses must use stable authority order")
        all_response_ids = tuple(item.response_id for item in self.model_responses)
        if len(all_response_ids) != len(set(all_response_ids)):
            raise ValueError("M6 model response authorities must be unique")
        response_by_id = {item.response_id: item for item in self.model_responses}
        for screening in validated_case.screening_results:
            parsed = screening.parsed_output
            response = response_by_id.get(parsed.response_id)
            if response is None:
                raise ValueError("M6 screening response authority is missing")
            if (
                response.layer != M6LockedModelCallLayer.SCREENING
                or response.raw_content_sha256 != parsed.response_content_sha256
            ):
                raise ValueError("M6 screening response authority conflicts with parsed output")
        for verdict in validated_case.verdicts:
            for ref in verdict.model_response_refs:
                if ref.artifact_id not in response_by_id:
                    raise ValueError("M6 hearing response authority is missing")
        cycle_indices = tuple(item.cycle_index for item in self.retrieval_cycles)
        if cycle_indices != tuple(range(1, len(cycle_indices) + 1)):
            raise ValueError("M6 retrieval exposures must use stable cycle order")
        if len({item.hearing_session_id for item in self.retrieval_cycles}) > 1:
            raise ValueError("M6 retrieval context must bind one hearing session")
        retrieval_scope_ids = tuple(item.cycle_scope_id for item in self.retrieval_cycles)
        if len(retrieval_scope_ids) != len(set(retrieval_scope_ids)):
            raise ValueError("M6 retrieval context cycle scopes must be unique")
        for retrieval_cycle in self.retrieval_cycles:
            authority = retrieval_cycle.success_exposure or retrieval_cycle.degraded_receipt
            assert authority is not None
            if (
                authority.run_id != self.historical_source_run_id
                or authority.case_id != self.historical_source_case_id
                or authority.manifest_id != self.historical_source_manifest_id
            ):
                raise ValueError("M6 retrieval authority differs from historical source scope")
        retrieval_by_scope = {item.cycle_scope_id: item for item in self.retrieval_cycles}
        gate_input_by_verdict = {item.verdict.verdict_id: item for item in gate_inputs}
        for verdict_binding in reference_authority.verdict_bindings:
            terminal_scope_ids = {
                item.scope.cycle_scope_id for item in verdict_binding.role_bindings
            }
            if len(terminal_scope_ids) != 1 or None in terminal_scope_ids:
                raise ValueError("M6 Verdict reference binding lacks one terminal cycle")
            terminal_scope_id = next(iter(terminal_scope_ids))
            assert terminal_scope_id is not None
            terminal_cycle = retrieval_by_scope.get(terminal_scope_id)
            if terminal_cycle is None:
                raise ValueError("M6 Verdict reference scope lacks its retrieval cycle")
            gate_input = gate_input_by_verdict.get(verdict_binding.verdict_id)
            if gate_input is not None:
                receipt = (
                    terminal_cycle.success_exposure.m4_retrieval_outcome.receipt
                    if terminal_cycle.success_exposure is not None
                    else terminal_cycle.degraded_receipt
                )
                assert receipt is not None
                expected_resolutions = build_m6_gate_precedent_resolutions(
                    evidence_pack=gate_input.evidence_pack,
                    receipt=receipt,
                )
                if gate_input.precedent_resolutions != expected_resolutions:
                    raise ValueError(
                        "M6 procedural Gate precedent authority differs from its terminal cycle"
                    )
            for role_binding in verdict_binding.role_bindings:
                scope_id = role_binding.scope.cycle_scope_id
                assert scope_id is not None
                scoped_cycle = retrieval_by_scope.get(scope_id)
                if scoped_cycle is None:
                    raise ValueError("M6 Verdict reference scope lacks its retrieval cycle")
                exposed = (
                    tuple(
                        ArtifactRef(
                            kind=ArtifactKind.PRECEDENT,
                            artifact_id=item.precedent_id,
                        )
                        for item in scoped_cycle.success_exposure.exposed_precedents
                    )
                    if scoped_cycle.success_exposure is not None
                    else ()
                )
                if role_binding.scope.allowed_precedent_refs != tuple(
                    sorted(exposed, key=lambda ref: ref.sort_key)
                ):
                    raise ValueError(
                        "M6 Verdict precedent scope differs from its exact retrieval exposure"
                    )
        if not isinstance(self.acquisitions, tuple) or any(
            not isinstance(item, M6ResolvedAcquisition) for item in self.acquisitions
        ):
            raise TypeError("M6 projection acquisitions must be a typed tuple")
        acquisitions = tuple(
            M6ResolvedAcquisition(
                locked_input=item.locked_input,
                request=item.request,
                execution_manifest=item.execution_manifest,
                publication=item.publication,
                receipt=item.receipt,
                derivation=item.derivation,
                previous_evidence_pack=item.previous_evidence_pack,
                resulting_evidence_pack=item.resulting_evidence_pack,
            )
            for item in self.acquisitions
        )
        acquisition_keys = tuple(item.sort_key for item in acquisitions)
        if acquisition_keys != tuple(sorted(acquisition_keys)) or len(acquisition_keys) != len(
            set(acquisition_keys)
        ):
            raise ValueError("M6 acquisitions must use stable unique pack order")
        acquisition_by_result = {item.tool_result_id: item for item in acquisitions}
        if len(acquisition_by_result) != len(acquisitions):
            raise ValueError("M6 acquisition ToolResult authorities must be unique")
        for acquisition in acquisitions:
            if (
                acquisition.request.run_id != self.historical_source_run_id
                or acquisition.request.case_id != self.historical_source_case_id
                or acquisition.request.manifest_id != self.historical_source_manifest_id
            ):
                raise ValueError("M6 acquisition differs from historical source scope")

        case_results: dict[str, ToolResult] = {}
        for pack in validated_case.evidence_packs:
            for result in pack.tool_results:
                prior = case_results.get(result.tool_result_id)
                if prior is not None and prior != result:
                    raise ValueError("M6 Case rewrites a ToolResult authority")
                case_results[result.tool_result_id] = result
        if set(case_results) != set(acquisition_by_result):
            raise ValueError("M6 acquisition authority does not exactly cover Case ToolResults")
        if any(
            acquisition_by_result[result_id].publication.tool_result != result
            for result_id, result in case_results.items()
        ):
            raise ValueError("M6 Case ToolResult conflicts with resolved acquisition authority")
        for ref in _case_tool_result_refs(validated_case):
            if ref.artifact_id not in acquisition_by_result:
                raise ValueError("M6 Case TOOL_RESULT reference lacks resolved authority")

        request_lookup = {
            (
                item.request.round_index,
                item.request.action,
                item.request.source_model_request_ref.artifact_id,
                item.tool_result_id,
            ): item
            for item in acquisitions
        }
        for verdict in validated_case.verdicts:
            for entry in verdict.acquisition_log:
                result_id = (
                    entry.tool_result_ref.artifact_id if entry.tool_result_ref is not None else ""
                )
                key = (
                    entry.round_index,
                    entry.action,
                    entry.request_ref.artifact_id,
                    result_id,
                )
                if key not in request_lookup:
                    raise ValueError("M6 acquisition log lacks its exact resolved authority")
        object.__setattr__(self, "case", validated_case)
        object.__setattr__(self, "acquisitions", acquisitions)


@dataclass(frozen=True, slots=True)
class M6ReplayLockedM4CandidateProjectionContext:
    """Cross-run M4 candidate projection without forged candidate history.

    The candidate Case, its model-reference mapping, and its Gate invocation are
    newly derived authorities.  Perception, model responses, terminal hearing
    scopes, and retrieval receipts remain the immutable source authorities that
    were actually persisted.  This distinction is required once a locked replay
    uses M4 history whose run-scoped documents cannot truthfully be rebound.
    """

    case: Case
    source_context: M6VerifiedProjectionContext
    model_reference_authority: M6CaseModelReferenceAuthority
    procedural_gate_authority: M6CaseProceduralGateAuthority

    def __post_init__(self) -> None:
        if type(self.case) is not Case:
            raise TypeError("M6 locked M4 candidate Case must be canonical")
        if type(self.source_context) is not M6VerifiedProjectionContext:
            raise TypeError("M6 locked M4 candidate source context must be verified")
        if type(self.model_reference_authority) is not M6CaseModelReferenceAuthority:
            raise TypeError("M6 locked M4 candidate model references must be typed")
        if type(self.procedural_gate_authority) is not M6CaseProceduralGateAuthority:
            raise TypeError("M6 locked M4 candidate Gate authority must be typed")
        candidate = Case.model_validate(
            self.case.model_dump(mode="json", exclude_computed_fields=True)
        )
        if candidate != self.case:
            raise ValueError("M6 locked M4 candidate Case is not canonical")

        source = self.source_context.case
        candidate_references = self.model_reference_authority
        source_references = self.source_context.model_reference_authority
        candidate_gates = self.procedural_gate_authority
        source_gates = self.source_context.procedural_gate_authority
        source_identity_sha256 = source_references.source_identity_sha256
        expected_status = {
            True: CaseStatus.READY_FOR_ALERT_POLICY,
            False: CaseStatus.REWORK_REQUIRED,
        }
        response_route = tuple(
            (item.layer, item.role, item.attempt_index)
            for item in self.source_context.model_responses
        )
        expected_response_route = (
            (
                M6LockedModelCallLayer.SCREENING,
                M6LockedModelRole.SCREENING,
                0,
            ),
            (
                M6LockedModelCallLayer.HEARING,
                M6LockedModelRole.PROSECUTOR,
                0,
            ),
            (
                M6LockedModelCallLayer.HEARING,
                M6LockedModelRole.DEFENDER,
                0,
            ),
            (
                M6LockedModelCallLayer.HEARING,
                M6LockedModelRole.JUDGE,
                0,
            ),
        )
        if (
            candidate.run_id == source.run_id
            or candidate.case_id != source.case_id
            or candidate.manifest_id != source.manifest_id
            or candidate.event != source.event
            or len(candidate.evidence_packs) != 1
            or len(candidate.screening_results) != 1
            or len(candidate.verdicts) != 1
            or len(candidate.procedural_reviews) != 1
            or candidate.alerts
            or candidate.appeals
            or candidate.final_decision is not None
            or candidate.current_backlog_item_id is not None
            or candidate.timeline
            or candidate.usage != UsageSummary()
            or len(source.evidence_packs) != 1
            or len(source.screening_results) != 1
            or len(source.verdicts) != 1
            or len(source.procedural_reviews) != 1
            or source.alerts
            or source.appeals
            or source.final_decision is not None
            or source.current_backlog_item_id is not None
            or response_route != expected_response_route
            or len(self.source_context.retrieval_cycles) != 1
            or self.source_context.retrieval_cycles[0].success_exposure is not None
            or self.source_context.retrieval_cycles[0].degraded_receipt is None
            or self.source_context.acquisitions
        ):
            raise ValueError("M6 locked M4 candidate lies outside the terminal route")

        candidate_pack = candidate.evidence_packs[0]
        source_pack = source.evidence_packs[0]
        candidate_screening = candidate.screening_results[0]
        source_screening = source.screening_results[0]
        candidate_verdict = candidate.verdicts[0]
        source_verdict = source.verdicts[0]
        candidate_review = candidate.procedural_reviews[0]
        source_review = source.procedural_reviews[0]
        if (
            candidate_pack.version != 1
            or candidate_pack.tool_results
            or source_pack.version != 1
            or source_pack.tool_results
            or candidate_screening.decision != ScreeningDecision.ESCALATE
            or source_screening.decision != ScreeningDecision.ESCALATE
            or candidate.status != expected_status[candidate_review.passed]
            or source.status != expected_status[source_review.passed]
            or candidate_review.passed != source_review.passed
        ):
            raise ValueError("M6 locked M4 candidate has an invalid terminal shape")

        pack_payload = source_pack.model_dump(mode="json", exclude_computed_fields=True)
        closure_payload = source_pack.closure_report.model_dump(
            mode="json",
            exclude_computed_fields=True,
        )
        pack_payload["run_id"] = candidate.run_id
        pack_payload["closure_report"] = {
            **closure_payload,
            "run_id": candidate.run_id,
        }
        expected_pack = EvidencePack.model_validate(pack_payload)
        parsed_payload = source_screening.parsed_output.model_dump(
            mode="json",
            exclude_computed_fields=True,
        )
        parsed_payload["run_id"] = candidate.run_id
        expected_parsed = ParsedScreeningOutput.model_validate(parsed_payload)
        try:
            expected_screening = ScreeningRouter(
                ScreeningRoutePolicy(
                    low_probability=source_screening.low_probability,
                    high_probability=source_screening.high_probability,
                    strong_signal_threshold=source_screening.strong_signal_threshold,
                    router_version=source_screening.router_version,
                    conflict_policy_version=source_screening.conflict_policy_version,
                )
            ).route(
                expected_parsed,
                expected_pack,
                version=source_screening.version,
            )
        except ScreeningRouteError as exc:
            raise ValueError("M6 locked M4 screening cannot be rebuilt") from exc
        verdict_payload = source_verdict.model_dump(
            mode="json",
            exclude_computed_fields=True,
        )
        verdict_payload["run_id"] = candidate.run_id
        verdict_payload["screening_id"] = expected_screening.screening_id
        expected_verdict = Verdict.model_validate(verdict_payload)
        if (
            candidate_pack != expected_pack
            or candidate_screening != expected_screening
            or candidate_verdict != expected_verdict
        ):
            raise ValueError("M6 locked M4 candidate rewrites source semantics")

        if (
            candidate_references.source_identity_sha256 != source_identity_sha256
            or candidate_gates.source_identity_sha256 != source_identity_sha256
            or source_gates.source_identity_sha256 != source_identity_sha256
            or candidate_references.run_id != candidate.run_id
            or candidate_references.case_id != candidate.case_id
            or candidate_references.manifest_id != candidate.manifest_id
            or candidate_gates.run_id != candidate.run_id
            or candidate_gates.case_id != candidate.case_id
            or candidate_gates.manifest_id != candidate.manifest_id
            or len(candidate_references.screening_bindings) != 1
            or len(candidate_references.verdict_bindings) != 1
            or candidate_references.fast_verdict_bindings
            or len(source_references.screening_bindings) != 1
            or len(source_references.verdict_bindings) != 1
            or source_references.fast_verdict_bindings
            or len(candidate_gates.inputs) != 1
            or len(source_gates.inputs) != 1
        ):
            raise ValueError("M6 locked M4 candidate authority scope is invalid")

        candidate_screening_binding = candidate_references.screening_bindings[0]
        source_screening_binding = source_references.screening_bindings[0]
        candidate_verdict_binding = candidate_references.verdict_bindings[0]
        source_verdict_binding = source_references.verdict_bindings[0]
        if (
            candidate_screening_binding.screening_id != candidate_screening.screening_id
            or candidate_screening_binding.parsed_output_id
            != candidate_screening.parsed_output.parsed_output_id
            or candidate_screening_binding.final_request_id
            != source_screening_binding.final_request_id
            or candidate_screening_binding.scope != source_screening_binding.scope
            or candidate_verdict_binding.verdict_id != candidate_verdict.verdict_id
            or candidate_verdict_binding.hearing_record_id
            != source_verdict_binding.hearing_record_id
            or candidate_verdict_binding.judge_round_id != source_verdict_binding.judge_round_id
            or candidate_verdict_binding.role_bindings != source_verdict_binding.role_bindings
        ):
            raise ValueError("M6 locked M4 candidate reference mapping is cross-grafted")

        candidate_gate = candidate_gates.input_for_review(candidate_review)
        source_gate = source_gates.input_for_review(source_review)
        expected_closure_payload = source_gate.current_closure.model_dump(
            mode="json",
            exclude_computed_fields=True,
        )
        expected_closure_payload["run_id"] = candidate.run_id
        expected_closure = ClosureReport.model_validate(expected_closure_payload)
        if (
            candidate_gate.verdict != candidate_verdict
            or candidate_gate.evidence_pack != candidate_pack
            or candidate_gate.current_closure != expected_closure
            or candidate_gate.gate_config != source_gate.gate_config
            or candidate_gate.alert_config != source_gate.alert_config
            or candidate_gate.review_version != source_gate.review_version
            or candidate_gate.unknown_reference_attempts != source_gate.unknown_reference_attempts
            or candidate_gate.precedent_resolutions != source_gate.precedent_resolutions
            or candidate_gate.artifact_bounds != source_gate.artifact_bounds
            or candidate_gate.rebuild_review() != candidate_review
        ):
            raise ValueError("M6 locked M4 candidate Gate was not independently rebuilt")
        object.__setattr__(self, "case", candidate)

    @property
    def perception(self) -> M6ResolvedPerception:
        return self.source_context.perception

    @property
    def model_responses(self) -> tuple[M6ResolvedModelResponse, ...]:
        return self.source_context.model_responses

    @property
    def retrieval_cycles(self) -> tuple[M6ResolvedRetrievalCycle, ...]:
        return self.source_context.retrieval_cycles

    @property
    def acquisitions(self) -> tuple[M6ResolvedAcquisition, ...]:
        return self.source_context.acquisitions


M6ProjectionContext = M6VerifiedProjectionContext | M6ReplayLockedM4CandidateProjectionContext


@dataclass(frozen=True, slots=True)
class _M6SemanticAuthorityIndex:
    tracks: M6SemanticTrackIndex
    acquisitions_by_id: dict[str, M6ResolvedAcquisition]
    acquisition_projections_by_id: dict[str, dict[str, object]]
    acquisition_sha256_by_id: dict[str, str]
    artifact_sha256_by_key: dict[tuple[ArtifactKind, str], str]
    precedent_sha256_by_scope_key: dict[tuple[str, str], str] = field(default_factory=dict)


def _semantic_artifact_ref(
    ref: ArtifactRef,
    authorities: _M6SemanticAuthorityIndex,
) -> dict[str, object]:
    projection_sha256 = authorities.artifact_sha256_by_key.get((ref.kind, ref.artifact_id))
    if projection_sha256 is None and ref.kind == ArtifactKind.MEDIA:
        projection_sha256 = _require_sha256(
            ref.artifact_id,
            "M6 semantic media reference",
        )
    if projection_sha256 is None:
        raise ValueError(f"M6 semantic projection cannot resolve a {ref.kind.value} reference")
    return {
        "kind": ref.kind.value,
        "projection_sha256": projection_sha256,
    }


def _semantic_model_ref(
    ref: ArtifactRef,
    scope: M6ModelReferenceScope,
    authorities: _M6SemanticAuthorityIndex,
) -> dict[str, object]:
    allowed_refs = (
        scope.allowed_precedent_refs
        if ref.kind == ArtifactKind.PRECEDENT
        else scope.allowed_evidence_refs
    )
    if ref.sort_key not in {item.sort_key for item in allowed_refs}:
        return {"kind": ref.kind.value, "resolution": "UNRESOLVED"}
    if ref.kind != ArtifactKind.PRECEDENT:
        return _semantic_artifact_ref(ref, authorities)
    if scope.cycle_scope_id is None:
        raise ValueError("M6 precedent reference scope lacks its retrieval cycle")
    projection_sha256 = authorities.precedent_sha256_by_scope_key.get(
        (scope.cycle_scope_id, ref.artifact_id)
    )
    if projection_sha256 is None:
        raise ValueError("M6 semantic projection cannot resolve an exposed PRECEDENT")
    return {
        "kind": ref.kind.value,
        "projection_sha256": projection_sha256,
    }


def _frame(frame: FrameRef) -> dict[str, object]:
    return {
        "camera_id": frame.camera_id,
        "stream_id": frame.stream_id,
        "frame_index": frame.frame_index,
        "fps_num": frame.fps_num,
        "fps_den": frame.fps_den,
        "width": frame.width,
        "height": frame.height,
        "content_sha256": frame.content_sha256,
    }


def _detection(
    detection: Detection,
    tracks: M6SemanticTrackIndex,
) -> dict[str, object]:
    projection = m6_semantic_detection_body(detection)
    projection["track"] = tracks.project(detection.track_ref)
    return projection


def _acquisition_detection(
    detection: Detection,
    tracks: M6SemanticTrackIndex,
) -> dict[str, object]:
    return _detection(detection, tracks)


def _acquisition_crop(
    crop: Crop,
    tracks: M6SemanticTrackIndex,
) -> dict[str, object]:
    receipt = crop.privacy_receipt
    return {
        "frame_id": crop.frame_id,
        "source": crop.source.value,
        "bbox": crop.bbox.model_dump(mode="json"),
        "panorama_long_edge_limit": crop.panorama_long_edge_limit,
        "source_media_sha256": crop.source_media_sha256,
        "pixel_sha256": crop.pixel_sha256,
        "media_sha256": crop.media_sha256,
        "output_width": crop.output_width,
        "output_height": crop.output_height,
        "size_bytes": crop.size_bytes,
        "media_type": crop.media_type.value,
        "encoding_version": crop.encoding_version,
        "privacy_receipt": {
            "policy": receipt.policy.value,
            "transform_version": receipt.transform_version,
            "media_access": receipt.media_access.value,
            "reason_code": receipt.reason_code.value,
            "ppe_type": receipt.ppe_type.value if receipt.ppe_type is not None else None,
            "anchor_type": (receipt.anchor_type.value if receipt.anchor_type is not None else None),
            "preserved_regions": [
                item.model_dump(mode="json") for item in receipt.preserved_regions
            ],
            "keypoints": [item.model_dump(mode="json") for item in receipt.keypoints],
            "anchor_bbox": (
                receipt.anchor_bbox.model_dump(mode="json")
                if receipt.anchor_bbox is not None
                else None
            ),
            "association_method": (
                receipt.association_method.value if receipt.association_method is not None else None
            ),
            "fill_rgb": list(receipt.fill_rgb),
            "fallback_used": receipt.fallback_used,
        },
        "observability": (
            crop.observability.model_dump(mode="json") if crop.observability is not None else None
        ),
        "primary_track": tracks.project(crop.primary_track_ref),
    }


def _acquisition_crop_request(
    request: CropRequest | None,
    tracks: M6SemanticTrackIndex,
) -> object:
    if request is None:
        return None
    return {
        "frame_id": request.frame_id,
        "source": request.source.value,
        "bbox": request.bbox.model_dump(mode="json"),
        "output_width": request.output_width,
        "output_height": request.output_height,
        "panorama_long_edge_limit": request.panorama_long_edge_limit,
        "privacy_policy": request.privacy_policy.value,
        "privacy_transform_version": request.privacy_transform_version,
        "encoding_version": request.encoding_version,
        "primary_track": tracks.project(request.primary_track_ref),
        "ppe_type": request.ppe_type.value if request.ppe_type is not None else None,
        "anchor_type": request.anchor_type.value if request.anchor_type is not None else None,
        "anchor_bbox": (
            request.anchor_bbox.model_dump(mode="json") if request.anchor_bbox is not None else None
        ),
        "keypoints": [item.model_dump(mode="json") for item in request.keypoints],
        "association_method": (
            request.association_method.value if request.association_method is not None else None
        ),
        "observability": (
            request.observability.model_dump(mode="json")
            if request.observability is not None
            else None
        ),
    }


def _acquisition_parameters(
    request: AcquisitionRequest,
    tracks: M6SemanticTrackIndex,
) -> dict[str, object]:
    parameters = request.validated_parameters
    projection = parameters.model_dump(mode="json", exclude_computed_fields=True)
    if isinstance(parameters, TrackConfidenceCurveParameters):
        projection.pop("track_ref", None)
        projection["track"] = tracks.project(parameters.track_ref)
    return projection


def _acquisition_authority(
    authority: M6ResolvedAcquisition,
    tracks: M6SemanticTrackIndex,
) -> dict[str, object]:
    request = authority.request
    publication = authority.publication
    return {
        "round_index": request.round_index,
        "prior_acquisition_rounds": request.prior_acquisition_rounds,
        "prior_rework_rounds": request.prior_rework_rounds,
        "action": request.action.value,
        "validated_parameters": _acquisition_parameters(request, tracks),
        "request_reason_summary": request.request_payload.reason_summary,
        "outputs": {
            "frames": [_frame(item) for item in publication.frames],
            "crops": [_acquisition_crop(item, tracks) for item in publication.crops],
            "objective_facts": sorted(
                (
                    {
                        "kind": item.kind.value,
                        "value": item.value,
                        "source": "THIS_ACQUISITION",
                        "unit": item.unit,
                    }
                    for item in publication.objective_facts
                ),
                key=canonical_json,
            ),
            "detections": sorted(
                (_acquisition_detection(item, tracks) for item in publication.detections),
                key=canonical_json,
            ),
            "crop_request": _acquisition_crop_request(publication.crop_request, tracks),
        },
        "resulting_evidence_pack_version": authority.resulting_evidence_pack.version,
        "resulting_evidence_pack_complete": authority.resulting_evidence_pack.complete,
    }


def _semantic_authority_index(
    context: M6ProjectionContext,
) -> _M6SemanticAuthorityIndex:
    acquisitions_by_id = {item.tool_result_id: item for item in context.acquisitions}
    tracks = build_m6_semantic_track_index(
        case=context.case,
        perception_detections=context.perception.detections,
        acquisitions=tuple((item.request, item.publication) for item in context.acquisitions),
    )
    projections = {
        artifact_id: _acquisition_authority(authority, tracks)
        for artifact_id, authority in acquisitions_by_id.items()
    }
    projection_hashes = {
        artifact_id: sha256_hex(["m6-resolved-acquisition-semantic", 1, projection])
        for artifact_id, projection in projections.items()
    }
    artifact_hashes: dict[tuple[ArtifactKind, str], str] = {}
    precedent_hashes: dict[tuple[str, str], str] = {}

    def add_artifact(
        kind: ArtifactKind,
        artifact_id: str,
        projection: object,
    ) -> None:
        digest = sha256_hex(["m6-semantic-artifact-authority", 1, kind.value, projection])
        key = (kind, artifact_id)
        previous = artifact_hashes.get(key)
        if previous is not None and previous != digest:
            raise ValueError("M6 semantic artifact identity resolves to conflicting content")
        artifact_hashes[key] = digest

    for frame in (
        *context.perception.frames,
        *(frame for item in context.acquisitions for frame in item.publication.frames),
    ):
        add_artifact(ArtifactKind.FRAME, frame.frame_id, _frame(frame))
    for detection in (
        *context.perception.detections,
        *(detection for item in context.acquisitions for detection in item.publication.detections),
    ):
        add_artifact(
            ArtifactKind.DETECTION,
            detection.detection_id,
            _detection(detection, tracks),
        )
    for crop in (
        *(crop for pack in context.case.evidence_packs for crop in pack.crops),
        *(crop for item in context.acquisitions for crop in item.publication.crops),
    ):
        add_artifact(
            ArtifactKind.CROP,
            crop.crop_id,
            {
                "crop_id": crop.crop_id,
                "frame_id": crop.frame_id,
                "pixel_sha256": crop.pixel_sha256,
                "media_sha256": crop.media_sha256,
            },
        )
    for artifact_id, projection_sha256 in projection_hashes.items():
        artifact_hashes[(ArtifactKind.TOOL_RESULT, artifact_id)] = projection_sha256
    for response in context.model_responses:
        add_artifact(
            ArtifactKind.MODEL_RESPONSE,
            response.response_id,
            response.semantic_projection(),
        )

    index = _M6SemanticAuthorityIndex(
        tracks=tracks,
        acquisitions_by_id=acquisitions_by_id,
        acquisition_projections_by_id=projections,
        acquisition_sha256_by_id=projection_hashes,
        artifact_sha256_by_key=artifact_hashes,
        precedent_sha256_by_scope_key=precedent_hashes,
    )
    facts = (
        *context.case.event.objective_facts,
        *(fact for pack in context.case.evidence_packs for fact in pack.objective_facts),
        *(fact for item in context.acquisitions for fact in item.publication.objective_facts),
    )
    for fact in facts:
        add_artifact(
            ArtifactKind.OBJECTIVE_FACT,
            fact.fact_id,
            _objective_fact(fact, index),
        )
    for cycle in context.retrieval_cycles:
        exposure = cycle.success_exposure
        if exposure is None:
            continue
        for item in exposure.exposed_precedents:
            key = (cycle.cycle_scope_id, item.precedent_id)
            digest = sha256_hex(
                [
                    "m6-semantic-artifact-authority",
                    1,
                    ArtifactKind.PRECEDENT.value,
                    _precedent(item.historical_authority.precedent),
                ]
            )
            previous = precedent_hashes.get(key)
            if previous is not None and previous != digest:
                raise ValueError("M6 retrieval cycle rewrites exposed precedent authority")
            precedent_hashes[key] = digest
    add_artifact(
        ArtifactKind.EVENT,
        context.case.event.event_id,
        _event(context.case.event, index),
    )
    add_artifact(
        ArtifactKind.CASE,
        context.case.case_id,
        {
            "event": _semantic_artifact_ref(
                ArtifactRef(
                    kind=ArtifactKind.EVENT,
                    artifact_id=context.case.event.event_id,
                ),
                index,
            )
        },
    )
    return index


def _objective_fact(
    fact: ObjectiveFact,
    authorities: _M6SemanticAuthorityIndex,
) -> dict[str, object]:
    return {
        "kind": fact.kind.value,
        "value": fact.value,
        "source_ref": _semantic_artifact_ref(
            fact.source_ref,
            authorities,
        ),
        "unit": fact.unit,
    }


def _confirmation(record: ConfirmationRecord) -> dict[str, object]:
    return {
        "policy": record.policy.value,
        "examined_frame_ids": list(record.examined_frame_ids),
        "counterevidence_frame_ids": list(record.counterevidence_frame_ids),
        "post_threshold_recovery_frame_id": record.post_threshold_recovery_frame_id,
        "suppressed": record.suppressed,
        "suppression_reason": record.suppression_reason,
        "resolved_frame": record.resolved_frame,
        "causal_risk": record.causal_risk,
    }


def _event(
    event: CandidateEvent,
    authorities: _M6SemanticAuthorityIndex,
) -> dict[str, object]:
    return {
        "camera_id": event.camera_id,
        "stream_id": event.stream_id,
        "rule_version": event.rule_version,
        "violation_type": event.violation_type.value,
        "evidence_class": event.evidence_class.value,
        "zone_id": event.zone_id,
        "start_frame": event.start_frame,
        "end_frame_exclusive": event.end_frame_exclusive,
        "trigger_frame": event.trigger_frame,
        "primary_track": authorities.tracks.project(event.primary_track_ref),
        "related_tracks": sorted(
            (authorities.tracks.project(item) for item in event.related_track_refs),
            key=canonical_json,
        ),
        "hard_rule": event.hard_rule,
        "l1_score": event.l1_score,
        "confirmation": _confirmation(event.confirmation),
        "objective_facts": sorted(
            (_objective_fact(fact, authorities) for fact in event.objective_facts),
            key=canonical_json,
        ),
    }


def _track_summary(
    summary: TrackSummary,
    tracks: M6SemanticTrackIndex,
) -> dict[str, object]:
    return {
        "primary_track": tracks.project(summary.primary_track_ref),
        "start_frame": summary.start_frame,
        "end_frame_exclusive": summary.end_frame_exclusive,
        "observed_frame_count": summary.observed_frame_count,
    }


def _observation_input(value: ObservationSufficiencyInput | None) -> object:
    if value is None:
        return None
    return {
        "clear_crop_ids": list(value.clear_crop_ids),
        "unclear_crop_ids": list(value.unclear_crop_ids),
        "clear_threshold": value.clear_threshold,
        "required_clear_count": value.required_clear_count,
        "selected_by_observability": value.selected_by_observability,
        "consistency_status": value.consistency_status.value,
    }


def _tool_result(
    result: ToolResult,
    authorities: _M6SemanticAuthorityIndex,
) -> dict[str, object]:
    authority = authorities.acquisitions_by_id.get(result.tool_result_id)
    if authority is None or authority.publication.tool_result != result:
        raise ValueError("M6 EvidencePack ToolResult lacks exact resolved authority")
    return {
        "projection_sha256": authorities.acquisition_sha256_by_id[result.tool_result_id],
        "authority": authorities.acquisition_projections_by_id[result.tool_result_id],
    }


def _evidence_crop(
    crop: Crop,
    authorities: _M6SemanticAuthorityIndex,
) -> dict[str, object]:
    projection = crop.semantic_projection()
    projection["source_refs"] = [
        _semantic_artifact_ref(ref, authorities) for ref in crop.source_refs
    ]
    privacy_receipt = dict(cast(dict[str, object], projection["privacy_receipt"]))
    privacy_receipt["input_refs"] = [
        _semantic_artifact_ref(ref, authorities) for ref in crop.privacy_receipt.input_refs
    ]
    projection["privacy_receipt"] = privacy_receipt
    projection.pop("primary_track_ref", None)
    projection["primary_track"] = authorities.tracks.project(crop.primary_track_ref)
    return projection


def _evidence_pack(
    pack: EvidencePack,
    authorities: _M6SemanticAuthorityIndex,
) -> dict[str, object]:
    return {
        "version": pack.version,
        "complete": pack.complete,
        "key_frame_ids": list(pack.key_frame_ids),
        "panorama_crops": [_evidence_crop(crop, authorities) for crop in pack.panorama_crops],
        "subject_crops": [_evidence_crop(crop, authorities) for crop in pack.subject_crops],
        "focus_crops": [_evidence_crop(crop, authorities) for crop in pack.focus_crops],
        "temporal_crops": [_evidence_crop(crop, authorities) for crop in pack.temporal_crops],
        "objective_facts": sorted(
            (_objective_fact(fact, authorities) for fact in pack.objective_facts),
            key=canonical_json,
        ),
        "track_summary": _track_summary(pack.track_summary, authorities.tracks),
        "confirmation_record": _confirmation(pack.confirmation_record),
        "observation_sufficiency_input": _observation_input(pack.observation_sufficiency_input),
        "tool_results": [_tool_result(result, authorities) for result in pack.tool_results],
    }


def _semantic_pack_reference(
    case: Case,
    authorities: _M6SemanticAuthorityIndex,
    *,
    pack_id: str,
    version: int,
) -> dict[str, object]:
    matches = tuple(
        pack for pack in case.evidence_packs if pack.pack_id == pack_id and pack.version == version
    )
    if len(matches) != 1:
        raise ValueError("M6 retrieval context cannot resolve its exact EvidencePack")
    return {
        "version": version,
        "projection_sha256": sha256_hex(
            [
                "m6-evidence-pack-semantic-reference",
                1,
                _evidence_pack(matches[0], authorities),
            ]
        ),
    }


def _embedding(vector: M5EmbeddingVector | None) -> object:
    if vector is None:
        return None
    return {
        "channel": vector.request.channel.value,
        "dimensions": vector.request.dimensions,
        "algorithm": vector.request.algorithm,
        "values": list(vector.values),
    }


def _known_precedent_situation(precedent: Precedent) -> object:
    """Normalize exact M5-generated situation schemas without guessing prose."""

    try:
        decoded = json.loads(precedent.situation_text)
    except json.JSONDecodeError:
        return {"format": "AUTHORED_TEXT", "text": precedent.situation_text}
    if not isinstance(decoded, dict) or canonical_json(decoded) != precedent.situation_text:
        return {"format": "AUTHORED_TEXT", "text": precedent.situation_text}
    schema_version = decoded.get("schema_version")
    automatic_fields = {
        "schema_version",
        "case_id",
        "violation_type",
        "evidence_class",
        "rule_version",
        "verdict_id",
        "verdict_version",
        "verdict_sha256",
        "decision",
        "rationale_summary",
        "objective_claims",
        "observation_sufficiency",
    }
    if schema_version == "m5-automatic-precedent-situation-v1" and set(decoded) == automatic_fields:
        claims_value = decoded["objective_claims"]
        if not isinstance(claims_value, list):
            raise ValueError("M6 automatic precedent situation has invalid objective claims")
        claims = tuple(ObjectiveClaim.model_validate(item) for item in claims_value)
        sufficiency_value = decoded["observation_sufficiency"]
        sufficiency = (
            ObservationSufficiency.model_validate(sufficiency_value)
            if sufficiency_value is not None
            else None
        )
        return {
            "format": schema_version,
            "violation_type": decoded["violation_type"],
            "evidence_class": decoded["evidence_class"],
            "rule_version": decoded["rule_version"],
            "verdict_version": decoded["verdict_version"],
            "decision": decoded["decision"],
            "rationale_summary": decoded["rationale_summary"],
            "objective_claims": sorted(
                (
                    {
                        "kind": claim.kind.value,
                        "value": claim.value,
                        "evidence_kind": claim.evidence_ref.kind.value,
                    }
                    for claim in claims
                ),
                key=canonical_json,
            ),
            "observation_sufficiency": (
                {
                    "clear_threshold": sufficiency.clear_threshold,
                    "required_clear_count": sufficiency.required_clear_count,
                    "observations": sorted(
                        (
                            {
                                "crop_id": item.crop_id,
                                "wear_status": item.wear_status.value,
                            }
                            for item in sufficiency.observations
                        ),
                        key=canonical_json,
                    ),
                }
                if sufficiency is not None
                else None
            ),
        }
    appeal_fields = {
        "schema_version",
        "appeal_id",
        "case_id",
        "source_case_authority_sha256",
        "source_verdict_sha256",
        "source_decision",
        "resolved_decision",
        "evidence_class",
        "violation_type",
        "rule_version",
        "human_authored_situation",
    }
    if (
        schema_version == "m5-appeal-overturn-precedent-situation-v1"
        and set(decoded) == appeal_fields
    ):
        return {
            "format": schema_version,
            "source_decision": decoded["source_decision"],
            "resolved_decision": decoded["resolved_decision"],
            "evidence_class": decoded["evidence_class"],
            "violation_type": decoded["violation_type"],
            "rule_version": decoded["rule_version"],
            "human_authored_situation": decoded["human_authored_situation"],
        }
    return {"format": "AUTHORED_TEXT", "text": precedent.situation_text}


def _precedent(precedent: Precedent) -> dict[str, object]:
    return {
        "situation": _known_precedent_situation(precedent),
        "decision_direction": precedent.decision_direction.value,
        "source": precedent.source.value,
        "status": precedent.status.value,
        "evidence_class": precedent.evidence_class.value,
        "violation_type": precedent.violation_type.value,
        "rule_version": precedent.rule_version,
    }


def _precedent_policy(policy: M5PrecedentPolicy) -> dict[str, object]:
    return {
        "text_weight": policy.text_weight,
        "visual_weight": policy.visual_weight,
        "source_weights": {
            source.value: value
            for source, value in sorted(
                policy.source_weights.items(),
                key=lambda item: item[0].value,
            )
        },
        "source_priorities": {
            source.value: value
            for source, value in sorted(
                policy.source_priorities.items(),
                key=lambda item: item[0].value,
            )
        },
        "conflict_similarity": policy.conflict_similarity,
        "automatic_activation_delay_seconds": policy.automatic_activation_delay_seconds,
    }


def _precedent_authority(authority: M5PrecedentAuthority) -> dict[str, object]:
    return {
        "precedent": _precedent(authority.precedent),
        "text_embedding": _embedding(authority.text_embedding),
        "visual_embeddings": sorted(
            (_embedding(item) for item in authority.visual_embeddings),
            key=canonical_json,
        ),
    }


def _candidate_evaluation(
    evaluation: M5PrecedentCandidateEvaluation,
) -> dict[str, object]:
    return {
        "authority": _precedent_authority(evaluation.authority),
        "disposition": evaluation.disposition.value,
        "text_similarity": evaluation.text_similarity,
        "visual_similarity": evaluation.visual_similarity,
        "normalized_text_weight": evaluation.normalized_text_weight,
        "normalized_visual_weight": evaluation.normalized_visual_weight,
        "base_similarity": evaluation.base_similarity,
        "source_weight": evaluation.source_weight,
        "score": evaluation.score,
    }


def _m5_retrieval_query(query: M5PrecedentRetrievalQuery) -> dict[str, object]:
    return {
        "evidence_class": query.evidence_class.value,
        "rule_version": query.rule_version,
        "situation_text": query.situation_text,
        "text_embedding": _embedding(query.text_embedding),
        "visual_embeddings": sorted(
            (_embedding(item) for item in query.visual_embeddings),
            key=canonical_json,
        ),
        "policy": _precedent_policy(query.policy),
        "top_k": query.top_k,
        "run_mode": query.run_mode.value,
        "include_provisional_experiment": query.include_provisional_experiment,
    }


def _scored_precedent(scored: ScoredPrecedent) -> dict[str, object]:
    return {
        "precedent": _precedent(scored.precedent),
        "text_similarity": scored.text_similarity,
        "visual_similarity": scored.visual_similarity,
        "fused_score": scored.fused_score,
    }


def _m5_scored_precedent(scored: M5ScoredPrecedent) -> dict[str, object]:
    return {
        "authority": _precedent_authority(scored.authority),
        "text_similarity": scored.text_similarity,
        "visual_similarity": scored.visual_similarity,
        "normalized_text_weight": scored.normalized_text_weight,
        "normalized_visual_weight": scored.normalized_visual_weight,
        "base_similarity": scored.base_similarity,
        "source_weight": scored.source_weight,
        "score": scored.score,
    }


def _retrieval_exposure(
    case: Case,
    exposure: M5PrecedentExposureBatchAuthority,
    authorities: _M6SemanticAuthorityIndex,
) -> dict[str, object]:
    outcome = exposure.m4_retrieval_outcome
    if outcome.result is None:
        raise ValueError("M6 precedent exposure requires its successful M4 result")
    m4_query = outcome.query
    m4_result = outcome.result
    m5_result = exposure.m5_retrieval_result
    return {
        "cycle_index": exposure.cycle_index,
        "m4": {
            "query": {
                "current_evidence_pack": _semantic_pack_reference(
                    case,
                    authorities,
                    pack_id=m4_query.current_evidence_pack_id,
                    version=m4_query.current_evidence_pack_version,
                ),
                "evidence_class": m4_query.evidence_class.value,
                "violation_type": m4_query.violation_type.value,
                "rule_version": m4_query.rule_version,
                "situation_text": m4_query.situation_text,
                "top_k": m4_query.top_k,
            },
            "candidate_precedents": sorted(
                (_precedent(item) for item in m4_result.candidate_precedents),
                key=canonical_json,
            ),
            "visible_precedents": sorted(
                (_precedent(item) for item in m4_result.visible_precedents),
                key=canonical_json,
            ),
            "scored_precedents": [_scored_precedent(item) for item in m4_result.scored_precedents],
            "status": outcome.receipt.status.value,
            "degraded_reason": (
                outcome.receipt.degraded_reason.value
                if outcome.receipt.degraded_reason is not None
                else None
            ),
        },
        "m5": {
            "query": _m5_retrieval_query(m5_result.query),
            "candidate_evaluations": sorted(
                (_candidate_evaluation(item) for item in m5_result.candidate_evaluations),
                key=canonical_json,
            ),
            "scored_precedents": [
                _m5_scored_precedent(item) for item in m5_result.scored_precedents
            ],
        },
        "exposed_precedents": [
            {
                "rank": item.rank,
                "historical_authority": _precedent_authority(item.historical_authority),
                "candidate_evaluation": _candidate_evaluation(item.candidate_evaluation),
                "m4_scored_precedent": _scored_precedent(item.m4_scored_precedent),
            }
            for item in exposure.exposed_precedents
        ],
    }


def _degraded_retrieval(
    case: Case,
    receipt: HearingPrecedentRetrievalReceipt,
    authorities: _M6SemanticAuthorityIndex,
) -> dict[str, object]:
    if (
        receipt.status != HearingPrecedentRetrievalStatus.DEGRADED
        or receipt.degraded_reason is None
    ):
        raise ValueError("M6 degraded retrieval projection requires its typed reason")
    return {
        "cycle_index": receipt.round_index,
        "current_evidence_pack": _semantic_pack_reference(
            case,
            authorities,
            pack_id=receipt.current_evidence_pack_id,
            version=receipt.current_evidence_pack_version,
        ),
        "prior_acquisition_rounds": receipt.prior_acquisition_rounds,
        "prior_rework_rounds": receipt.prior_rework_rounds,
        "evidence_class": receipt.evidence_class.value,
        "violation_type": receipt.violation_type.value,
        "rule_version": receipt.rule_version,
        "top_k": receipt.top_k,
        "initial_defect_codes": [code.value for code in receipt.initial_defect_codes],
        "rework_defect_codes": [code.value for code in receipt.rework_defect_codes],
        "status": receipt.status.value,
        "degraded_reason": receipt.degraded_reason.value,
    }


def _retrieval_cycle(
    case: Case,
    cycle: M6ResolvedRetrievalCycle,
    authorities: _M6SemanticAuthorityIndex,
) -> dict[str, object]:
    if cycle.success_exposure is not None:
        return {
            "outcome": HearingPrecedentRetrievalStatus.SUCCESS.value,
            "authority": _retrieval_exposure(
                case,
                cycle.success_exposure,
                authorities,
            ),
        }
    assert cycle.degraded_receipt is not None
    return {
        "outcome": HearingPrecedentRetrievalStatus.DEGRADED.value,
        "authority": _degraded_retrieval(
            case,
            cycle.degraded_receipt,
            authorities,
        ),
    }


def _model_response(
    response_id: str,
    responses_by_id: dict[str, M6ResolvedModelResponse],
) -> dict[str, object]:
    response = responses_by_id.get(response_id)
    if response is None:
        raise ValueError("M6 semantic projection cannot resolve a model response")
    return response.semantic_projection()


def _screening(
    result: ScreeningResult,
    responses_by_id: dict[str, M6ResolvedModelResponse],
    authorities: _M6SemanticAuthorityIndex,
    scope: M6ModelReferenceScope,
) -> dict[str, object]:
    parsed = result.parsed_output
    payload = parsed.payload
    return {
        "version": result.version,
        "evidence_pack_version": result.evidence_pack_version,
        "parsed_output": {
            "response_content_sha256": parsed.response_content_sha256,
            "output_schema_sha256": parsed.output_schema_sha256,
            "payload": {
                "violation_type": payload.violation_type.value,
                "evidence_class": payload.evidence_class.value,
                "violation_probability": payload.violation_probability,
                "frame_observations": sorted(
                    (
                        {
                            "crop": _semantic_model_ref(
                                ArtifactRef(
                                    kind=ArtifactKind.CROP,
                                    artifact_id=item.crop_id,
                                ),
                                scope,
                                authorities,
                            ),
                            "wear_status": item.wear_status.value,
                            "reason_summary": item.reason_summary,
                        }
                        for item in payload.frame_observations
                    ),
                    key=canonical_json,
                ),
                "evidence_citations": sorted(
                    (_citation(item, authorities, scope) for item in payload.evidence_citations),
                    key=canonical_json,
                ),
                "objective_claims": sorted(
                    (
                        _objective_claim(item, authorities, scope)
                        for item in payload.objective_claims
                    ),
                    key=canonical_json,
                ),
                "prosecution_summary": payload.prosecution_summary,
                "rationale_summary": payload.rationale_summary,
            },
        },
        "model_response": _model_response(parsed.response_id, responses_by_id),
        "low_probability": result.low_probability,
        "high_probability": result.high_probability,
        "authoritative_evidence_class": result.authoritative_evidence_class.value,
        "authoritative_l1_score": result.authoritative_l1_score,
        "strong_signal_threshold": result.strong_signal_threshold,
        "conflict_policy_version": result.conflict_policy_version,
        "alleged_interval_crops": sorted(
            (
                _semantic_artifact_ref(
                    ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop_id),
                    authorities,
                )
                for crop_id in result.alleged_interval_crop_ids
            ),
            key=canonical_json,
        ),
        "authoritative_clear_crops": sorted(
            (
                _semantic_artifact_ref(
                    ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop_id),
                    authorities,
                )
                for crop_id in result.authoritative_clear_crop_ids
            ),
            key=canonical_json,
        ),
        "correction_frames": [
            _semantic_artifact_ref(
                ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame_id),
                authorities,
            )
            for frame_id in result.correction_frame_ids
        ],
        "required_clear_count": result.required_clear_count,
        "router_version": result.router_version,
        "decision": result.decision.value,
        "conflict_codes": [code.value for code in result.conflict_codes],
    }


def _citation(
    citation: EvidenceCitation,
    authorities: _M6SemanticAuthorityIndex,
    scope: M6ModelReferenceScope,
) -> dict[str, object]:
    return {
        "evidence_ref": _semantic_model_ref(
            citation.evidence_ref,
            scope,
            authorities,
        ),
        "bbox": citation.bbox.model_dump(mode="json") if citation.bbox is not None else None,
        "coordinate_space": citation.coordinate_space,
    }


def _argument(
    argument: Argument,
    authorities: _M6SemanticAuthorityIndex,
    scope: M6ModelReferenceScope,
) -> dict[str, object]:
    return {
        "stance": argument.stance.value,
        "claim": argument.claim,
        "evidence_refs": sorted(
            (_semantic_model_ref(ref, scope, authorities) for ref in argument.evidence_refs),
            key=canonical_json,
        ),
        "uncertainty": argument.uncertainty,
    }


def _judge_response(
    response: JudgeResponse,
    authorities: _M6SemanticAuthorityIndex,
    scope: M6ModelReferenceScope,
    defense_arguments_by_id: dict[str, str],
) -> dict[str, object]:
    defense_argument_sha256 = defense_arguments_by_id.get(response.defense_argument_id)
    return {
        "defense_argument": (
            {"projection_sha256": defense_argument_sha256}
            if defense_argument_sha256 is not None
            else {"resolution": "UNRESOLVED"}
        ),
        "disposition": response.disposition.value,
        "response_summary": response.response_summary,
        "evidence_refs": sorted(
            (_semantic_model_ref(ref, scope, authorities) for ref in response.evidence_refs),
            key=canonical_json,
        ),
    }


def _precedent_application(
    application: PrecedentApplication,
    authorities: _M6SemanticAuthorityIndex,
    scope: M6ModelReferenceScope,
) -> dict[str, object]:
    return {
        "precedent_ref": _semantic_model_ref(
            application.precedent_ref,
            scope,
            authorities,
        ),
        "mode": application.mode.value,
        "similarity_score": application.similarity_score,
        "distinguishing_reason": application.distinguishing_reason,
        "fact_difference_refs": sorted(
            (
                _semantic_model_ref(ref, scope, authorities)
                for ref in application.fact_difference_refs
            ),
            key=canonical_json,
        ),
    }


def _acquisition(
    entry: AcquisitionLogEntry,
    authorities: _M6SemanticAuthorityIndex,
) -> dict[str, object]:
    if entry.tool_result_ref is None:
        raise ValueError("M6 acquisition log is missing its ToolResult authority")
    authority = authorities.acquisitions_by_id.get(entry.tool_result_ref.artifact_id)
    if authority is None:
        raise ValueError("M6 acquisition log cannot resolve its ToolResult authority")
    return {
        "round_index": entry.round_index,
        "action": entry.action.value,
        "request": {
            "reason_summary": authority.request.request_payload.reason_summary,
            "validated_parameters": _acquisition_parameters(
                authority.request,
                authorities.tracks,
            ),
        },
        "tool_result": _semantic_artifact_ref(
            entry.tool_result_ref,
            authorities,
        ),
        "outcome_summary": entry.outcome_summary,
    }


def _objective_claim(
    claim: ObjectiveClaim,
    authorities: _M6SemanticAuthorityIndex,
    scope: M6ModelReferenceScope,
) -> dict[str, object]:
    return {
        "kind": claim.kind.value,
        "value": claim.value,
        "evidence_ref": _semantic_model_ref(
            claim.evidence_ref,
            scope,
            authorities,
        ),
    }


def _observation_sufficiency(
    value: ObservationSufficiency | None,
    authorities: _M6SemanticAuthorityIndex,
    scope: M6ModelReferenceScope,
) -> object:
    if value is None:
        return None
    return {
        "clear_threshold": value.clear_threshold,
        "required_clear_count": value.required_clear_count,
        "observations": [
            {
                "crop": _semantic_model_ref(
                    ArtifactRef(kind=ArtifactKind.CROP, artifact_id=item.crop_id),
                    scope,
                    authorities,
                ),
                "wear_status": item.wear_status.value,
            }
            for item in value.observations
        ],
    }


def _hearing(
    verdict: Verdict,
    responses_by_id: dict[str, M6ResolvedModelResponse],
    authorities: _M6SemanticAuthorityIndex,
    binding: M6VerdictModelReferenceBinding,
) -> dict[str, object]:
    prosecutor_scope = binding.scope_for_role(VlmRole.PROSECUTOR)
    defender_scope = binding.scope_for_role(VlmRole.DEFENDER)
    judge_scope = binding.scope_for_role(VlmRole.JUDGE)
    resolved_responses = tuple(
        responses_by_id[ref.artifact_id] for ref in verdict.model_response_refs
    )
    defense_arguments_by_id = {
        argument.argument_id: sha256_hex(
            [
                "m6-hearing-argument-semantic",
                1,
                _argument(argument, authorities, defender_scope),
            ]
        )
        for argument in verdict.defense_arguments
    }
    return {
        "version": verdict.version,
        "evidence_pack_version": verdict.evidence_pack_version,
        "violation_type": verdict.violation_type.value,
        "decision": verdict.decision.value,
        "confidence": verdict.confidence,
        "recommended_alert_level": verdict.recommended_alert_level.value,
        "rationale_summary": verdict.rationale_summary,
        "evidence_citations": sorted(
            (
                _citation(citation, authorities, judge_scope)
                for citation in verdict.evidence_citations
            ),
            key=canonical_json,
        ),
        "prosecution_arguments": sorted(
            (
                _argument(argument, authorities, prosecutor_scope)
                for argument in verdict.prosecution_arguments
            ),
            key=canonical_json,
        ),
        "defense_arguments": sorted(
            (
                _argument(argument, authorities, defender_scope)
                for argument in verdict.defense_arguments
            ),
            key=canonical_json,
        ),
        "judge_responses": sorted(
            (
                _judge_response(
                    response,
                    authorities,
                    judge_scope,
                    defense_arguments_by_id,
                )
                for response in verdict.judge_responses
            ),
            key=canonical_json,
        ),
        "precedent_applications": sorted(
            (
                _precedent_application(application, authorities, judge_scope)
                for application in verdict.precedent_applications
            ),
            key=canonical_json,
        ),
        "acquisition_log": [_acquisition(entry, authorities) for entry in verdict.acquisition_log],
        "objective_claims": sorted(
            (
                _objective_claim(claim, authorities, judge_scope)
                for claim in verdict.objective_claims
            ),
            key=canonical_json,
        ),
        "observation_sufficiency": _observation_sufficiency(
            verdict.observation_sufficiency,
            authorities,
            judge_scope,
        ),
        "model_responses": [
            response.semantic_projection()
            for response in sorted(
                resolved_responses,
                key=lambda item: item.semantic_sort_key,
            )
        ],
    }


def _fast_verdict(
    verdict: Verdict,
    responses_by_id: dict[str, M6ResolvedModelResponse],
    authorities: _M6SemanticAuthorityIndex,
    binding: M6FastVerdictModelReferenceBinding,
) -> dict[str, object]:
    """Project one deterministic M3 terminal verdict under its screening scope."""

    scope = binding.scope
    resolved_responses = tuple(
        responses_by_id[ref.artifact_id] for ref in verdict.model_response_refs
    )
    defense_arguments_by_id = {
        argument.argument_id: sha256_hex(
            [
                "m6-hearing-argument-semantic",
                1,
                _argument(argument, authorities, scope),
            ]
        )
        for argument in verdict.defense_arguments
    }
    return {
        "route": "M3_FAST_TERMINAL_POST_PARSE",
        "version": verdict.version,
        "evidence_pack_version": verdict.evidence_pack_version,
        "violation_type": verdict.violation_type.value,
        "decision": verdict.decision.value,
        "confidence": verdict.confidence,
        "recommended_alert_level": verdict.recommended_alert_level.value,
        "rationale_summary": verdict.rationale_summary,
        "evidence_citations": sorted(
            (_citation(citation, authorities, scope) for citation in verdict.evidence_citations),
            key=canonical_json,
        ),
        "prosecution_arguments": sorted(
            (_argument(argument, authorities, scope) for argument in verdict.prosecution_arguments),
            key=canonical_json,
        ),
        "defense_arguments": sorted(
            (_argument(argument, authorities, scope) for argument in verdict.defense_arguments),
            key=canonical_json,
        ),
        "judge_responses": sorted(
            (
                _judge_response(
                    response,
                    authorities,
                    scope,
                    defense_arguments_by_id,
                )
                for response in verdict.judge_responses
            ),
            key=canonical_json,
        ),
        "precedent_applications": sorted(
            (
                _precedent_application(application, authorities, scope)
                for application in verdict.precedent_applications
            ),
            key=canonical_json,
        ),
        "acquisition_log": [_acquisition(entry, authorities) for entry in verdict.acquisition_log],
        "objective_claims": sorted(
            (_objective_claim(claim, authorities, scope) for claim in verdict.objective_claims),
            key=canonical_json,
        ),
        "observation_sufficiency": _observation_sufficiency(
            verdict.observation_sufficiency,
            authorities,
            scope,
        ),
        "model_responses": [
            response.semantic_projection()
            for response in sorted(
                resolved_responses,
                key=lambda item: item.semantic_sort_key,
            )
        ],
    }


def _defense_cardinality_semantics(
    verdict: Verdict,
    authorities: _M6SemanticAuthorityIndex,
    scope: M6ModelReferenceScope,
) -> dict[str, object]:
    defense_arguments_by_id = {
        argument.argument_id: sha256_hex(
            [
                "m6-hearing-argument-semantic",
                1,
                _argument(argument, authorities, scope),
            ]
        )
        for argument in verdict.defense_arguments
    }
    return {
        "defense_arguments": sorted(defense_arguments_by_id.values()),
        "judge_response_targets": sorted(
            defense_arguments_by_id.get(response.defense_argument_id, "UNRESOLVED")
            for response in verdict.judge_responses
        ),
    }


def _defect(
    defect: ProceduralDefect,
    verdict: Verdict,
    authorities: _M6SemanticAuthorityIndex,
    binding: M6VerdictModelReferenceBinding | M6FastVerdictModelReferenceBinding,
) -> dict[str, object]:
    if isinstance(binding, M6FastVerdictModelReferenceBinding):
        defender_scope = binding.scope
        judge_scope = binding.scope
    else:
        defender_scope = binding.scope_for_role(VlmRole.DEFENDER)
        judge_scope = binding.scope_for_role(VlmRole.JUDGE)
    value: object = defect.value_sha256
    if (
        defect.code == ProceduralDefectCode.UNANSWERED_DEFENSE_POINT
        and defect.reason_code == ProceduralReasonCode.DEFENSE_RESPONSE_CARDINALITY
    ):
        value = _defense_cardinality_semantics(verdict, authorities, defender_scope)
    elif defect.code in {
        ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE,
        ProceduralDefectCode.FABRICATED_PRECEDENT_REFERENCE,
    }:
        value = {
            "category": "UNRESOLVED_MODEL_REFERENCE",
            "namespace": (
                "EVIDENCE"
                if defect.code == ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE
                else "PRECEDENT"
            ),
        }
    model_ref_kinds = {
        ArtifactKind.CROP,
        ArtifactKind.FRAME,
        ArtifactKind.OBJECTIVE_FACT,
        ArtifactKind.PRECEDENT,
        ArtifactKind.TOOL_RESULT,
    }
    return {
        "code": defect.code.value,
        "origin": defect.origin.value,
        "reason_code": defect.reason_code.value,
        "field": defect.field.value,
        "related_refs": sorted(
            (
                (
                    _semantic_model_ref(ref, judge_scope, authorities)
                    if ref.kind in model_ref_kinds
                    else _semantic_artifact_ref(ref, authorities)
                )
                for ref in defect.related_refs
            ),
            key=canonical_json,
        ),
        "semantic_value": value,
    }


def _gate(
    execution_input: M6ProceduralGateExecutionInput,
    authorities: _M6SemanticAuthorityIndex,
    binding: M6VerdictModelReferenceBinding | M6FastVerdictModelReferenceBinding,
) -> dict[str, object]:
    review = execution_input.rebuild_review()
    verdict = execution_input.verdict
    if binding.verdict_id != verdict.verdict_id:
        raise ValueError("M6 procedural review uses another Verdict reference binding")
    return {
        "version": review.version,
        "evidence_pack_version": review.evidence_pack_version,
        "reviewed_verdict_version": review.reviewed_verdict_version,
        "gate_version": review.gate_version,
        "defects": sorted(
            (_defect(defect, verdict, authorities, binding) for defect in review.defects),
            key=canonical_json,
        ),
        "passed": review.passed,
    }


def _alert(alert: AlertDecision) -> dict[str, object]:
    return {
        "level": alert.level.value,
        "recipients": sorted(alert.recipients),
        "policy_rule_ids": sorted(alert.policy_rule_ids),
        "suppressed_by_cooldown": alert.suppressed_by_cooldown,
        "merged": alert.merged_into_alert_id is not None,
        "human_review_required": alert.human_review_required,
        "rescinded": alert.rescinded,
    }


def _appeal(appeal: Appeal) -> dict[str, object]:
    return {
        "status": appeal.status.value,
        "reason": appeal.reason,
        "resolution_summary": appeal.resolution_summary,
        "resolved_decision": (
            appeal.resolved_decision.value if appeal.resolved_decision is not None else None
        ),
    }


def _stage_payloads(
    context: M6ProjectionContext,
) -> tuple[tuple[M6RegressionStage, dict[str, object]], ...]:
    case = context.case
    responses_by_id = {item.response_id: item for item in context.model_responses}
    authorities = _semantic_authority_index(context)
    screening_bindings = {
        item.screening_id: item for item in context.model_reference_authority.screening_bindings
    }
    verdict_bindings = {
        item.verdict_id: item for item in context.model_reference_authority.verdict_bindings
    }
    fast_verdict_bindings = {
        item.verdict_id: item for item in context.model_reference_authority.fast_verdict_bindings
    }
    return (
        (
            M6RegressionStage.PERCEPTION,
            {
                "frames": [_frame(frame) for frame in context.perception.frames],
                "detections": sorted(
                    (
                        _detection(detection, authorities.tracks)
                        for detection in context.perception.detections
                    ),
                    key=canonical_json,
                ),
                "event": _event(case.event, authorities),
                "initial_evidence_packs": [
                    _evidence_pack(pack, authorities)
                    for pack in case.evidence_packs
                    if pack.version == 1
                ],
            },
        ),
        (
            M6RegressionStage.SCREENING,
            {
                "screening_results": [
                    _screening(
                        result,
                        responses_by_id,
                        authorities,
                        screening_bindings[result.screening_id].scope,
                    )
                    for result in case.screening_results
                ]
            },
        ),
        (
            M6RegressionStage.RETRIEVAL,
            {
                "retrieval_cycles": [
                    _retrieval_cycle(case, cycle, authorities) for cycle in context.retrieval_cycles
                ]
            },
        ),
        (
            M6RegressionStage.HEARING,
            {
                "acquired_evidence_packs": [
                    _evidence_pack(pack, authorities)
                    for pack in case.evidence_packs
                    if pack.version > 1
                ],
                "acquisitions": [
                    authorities.acquisition_projections_by_id[item.tool_result_id]
                    for item in context.acquisitions
                ],
                "verdicts": [
                    (
                        _fast_verdict(
                            verdict,
                            responses_by_id,
                            authorities,
                            fast_verdict_bindings[verdict.verdict_id],
                        )
                        if verdict.verdict_id in fast_verdict_bindings
                        else _hearing(
                            verdict,
                            responses_by_id,
                            authorities,
                            verdict_bindings[verdict.verdict_id],
                        )
                    )
                    for verdict in case.verdicts
                ],
            },
        ),
        (
            M6RegressionStage.GATE,
            {
                "procedural_reviews": [
                    _gate(
                        context.procedural_gate_authority.input_for_review(review),
                        authorities,
                        (
                            fast_verdict_bindings[review.reviewed_verdict_id]
                            if review.reviewed_verdict_id in fast_verdict_bindings
                            else verdict_bindings[review.reviewed_verdict_id]
                        ),
                    )
                    for review in case.procedural_reviews
                ]
            },
        ),
        (
            M6RegressionStage.POLICY,
            {
                "alerts": sorted(
                    (_alert(alert) for alert in case.alerts),
                    key=canonical_json,
                ),
                "appeals": [_appeal(appeal) for appeal in case.appeals],
            },
        ),
    )


def _highest_active_alert(case: Case) -> AlertLevel | None:
    active = tuple(alert.level for alert in case.alerts if not alert.rescinded)
    return max(active, key=_ALERT_RANK.__getitem__) if active else None


def _terminal_appeal_status(case: Case) -> AppealStatus | None:
    terminal = tuple(
        appeal.status
        for appeal in case.appeals
        if appeal.status in {AppealStatus.UPHELD, AppealStatus.OVERTURNED}
    )
    return terminal[-1] if terminal else None


def _case_document_sha256(case: Case) -> str:
    document = canonical_json(case.model_dump(mode="json"))
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def build_m6_case_replay_snapshot(
    *,
    context: M6ProjectionContext,
    sample_id: str,
    source_case_revision: int,
) -> M6CaseReplaySnapshot:
    """Build one M6 snapshot from a typed, authority-validated projection context.

    The source document identity records operational differences for provenance,
    while the six stage roots are constructed only from explicit semantic fields.
    """

    if type(context) not in (
        M6VerifiedProjectionContext,
        M6ReplayLockedM4CandidateProjectionContext,
    ):
        raise TypeError("context must be a verified M6 projection context")
    validated = context.case
    stage_payloads = _stage_payloads(context)
    if type(context) is M6ReplayLockedM4CandidateProjectionContext:
        if source_case_revision != 1:
            raise ValueError("M6 locked M4 candidate projection requires Case revision one")
        source = context.source_context.case
        if (
            canonical_json(stage_payloads)
            != canonical_json(_stage_payloads(context.source_context))
            or validated.status != source.status
            or validated.final_decision != source.final_decision
            or _highest_active_alert(validated) != _highest_active_alert(source)
            or _terminal_appeal_status(validated) != _terminal_appeal_status(source)
        ):
            raise ValueError("M6 locked M4 candidate semantic projection diverges from source")
    stage_roots = tuple(
        M6SemanticStageRoot(
            stage=stage,
            projection_sha256=sha256_hex(["m6-semantic-stage", 1, stage.value, payload]),
        )
        for stage, payload in stage_payloads
    )
    return M6CaseReplaySnapshot(
        sample_id=sample_id,
        source_run_id=validated.run_id,
        source_case_id=validated.case_id,
        source_case_revision=source_case_revision,
        source_case_document_sha256=_case_document_sha256(validated),
        manifest_id=validated.manifest_id,
        stage_roots=stage_roots,
        case_status=validated.status,
        final_decision=validated.final_decision,
        highest_alert_level=_highest_active_alert(validated),
        terminal_appeal_status=_terminal_appeal_status(validated),
    )


def build_m6_closed_policy_case_replay_snapshot(
    *,
    pre_policy_snapshot: M6CaseReplaySnapshot,
    transient_ready_case: Case,
    candidate_alert_policy: AlertPolicyAuthority,
    closed_candidate_case: Case,
) -> M6CaseReplaySnapshot:
    """Extend an independently verified READY snapshot through pure L5 policy.

    Alert policy changes only the stable POLICY projection.  The first five
    stage roots remain the already verified pre-policy facts, while the final
    root is recomputed from the exact CLOSED successor rather than copied from
    evaluator truth or accepted from the candidate executor.
    """

    if type(pre_policy_snapshot) is not M6CaseReplaySnapshot:
        raise TypeError("M6 CLOSED policy projection requires an exact READY snapshot")
    if (
        type(transient_ready_case) is not Case
        or type(candidate_alert_policy) is not AlertPolicyAuthority
        or type(closed_candidate_case) is not Case
    ):
        raise TypeError("M6 CLOSED policy projection requires exact typed authorities")
    ready = Case.model_validate(
        transient_ready_case.model_dump(mode="json", exclude_computed_fields=True)
    )
    policy = AlertPolicyAuthority.model_validate(
        candidate_alert_policy.model_dump(
            mode="json",
            exclude_computed_fields=True,
        )
    )
    closed = Case.model_validate(
        closed_candidate_case.model_dump(mode="json", exclude_computed_fields=True)
    )
    snapshot = M6CaseReplaySnapshot.model_validate(
        pre_policy_snapshot.model_dump(
            mode="json",
            exclude_computed_fields=True,
        )
    )
    if (
        ready != transient_ready_case
        or policy != candidate_alert_policy
        or closed != closed_candidate_case
        or snapshot != pre_policy_snapshot
        or ready.status != CaseStatus.READY_FOR_ALERT_POLICY
        or ready.alerts
        or ready.appeals
        or ready.final_decision is not None
        or ready.timeline
        or snapshot.source_run_id != ready.run_id
        or snapshot.source_case_id != ready.case_id
        or snapshot.source_case_revision != 1
        or snapshot.source_case_document_sha256 != _case_document_sha256(ready)
        or snapshot.manifest_id != ready.manifest_id
        or snapshot.case_status != CaseStatus.READY_FOR_ALERT_POLICY
        or snapshot.final_decision is not None
        or snapshot.highest_alert_level is not None
        or snapshot.terminal_appeal_status is not None
    ):
        raise ValueError("M6 CLOSED policy pre-policy snapshot bindings differ")
    decision = policy.decision
    alert_id = decision.alert_id if decision is not None else "NONE"
    object_ref = decision.alert_id if decision is not None else ready.case_id
    expected_alerts = ready.alerts if decision is None else (*ready.alerts, decision)
    expected_closed = ready.model_copy(
        update={
            "status": CaseStatus.CLOSED,
            "alerts": expected_alerts,
            "final_decision": policy.final_decision,
            "timeline": (
                TimelineEntry(
                    sequence=0,
                    action=AuditAction.CASE_CLOSED.value,
                    stage="ALERT_POLICY",
                    object_ref=object_ref,
                    details={
                        "alert_id": alert_id,
                        "disposition": policy.disposition.value,
                        "status": CaseStatus.CLOSED.value,
                    },
                ),
            ),
        }
    )
    request = policy.request
    if (
        policy.target_case_status != CaseStatus.CLOSED
        or request.run_id != ready.run_id
        or request.case_id != ready.case_id
        or request.manifest_id != ready.manifest_id
        or expected_closed != closed
    ):
        raise ValueError("M6 CLOSED policy output is not the exact READY successor")
    policy_payload = {
        "alerts": sorted((_alert(alert) for alert in closed.alerts), key=canonical_json),
        "appeals": [_appeal(appeal) for appeal in closed.appeals],
    }
    policy_root = M6SemanticStageRoot(
        stage=M6RegressionStage.POLICY,
        projection_sha256=sha256_hex(
            [
                "m6-semantic-stage",
                1,
                M6RegressionStage.POLICY.value,
                policy_payload,
            ]
        ),
    )
    return M6CaseReplaySnapshot(
        sample_id=snapshot.sample_id,
        source_run_id=closed.run_id,
        source_case_id=closed.case_id,
        source_case_revision=1,
        source_case_document_sha256=_case_document_sha256(closed),
        manifest_id=closed.manifest_id,
        stage_roots=(*snapshot.stage_roots[:-1], policy_root),
        case_status=closed.status,
        final_decision=closed.final_decision,
        highest_alert_level=_highest_active_alert(closed),
        terminal_appeal_status=_terminal_appeal_status(closed),
    )


__all__ = [
    "M6ReplayLockedM4CandidateProjectionContext",
    "M6ResolvedAcquisition",
    "M6ResolvedModelResponse",
    "M6ResolvedPerception",
    "M6ResolvedRetrievalCycle",
    "M6VerifiedProjectionContext",
    "build_m6_case_replay_snapshot",
    "build_m6_closed_policy_case_replay_snapshot",
    "resolve_m6_locked_model_responses",
]

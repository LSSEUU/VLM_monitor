"""Assemble the narrow trusted source for M3 fast-terminal locked replay."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from pydantic import ValidationError

from labcourt.application.m6_model_call_authority import (
    M6ModelCallAuthorityError,
    assemble_m6_locked_screening_model_calls,
)
from labcourt.application.m6_model_reference_authority import (
    M6ModelReferenceAuthorityError,
    resolve_m6_fast_verdict_model_reference_bindings,
    resolve_m6_screening_model_reference_bindings,
)
from labcourt.application.m6_perception_authority import (
    M6PerceptionAuthorityError,
    assemble_m6_resolved_perception,
)
from labcourt.application.m6_source_authority import M6ValidatedSourceAuthority
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import ArtifactKind, CaseStatus, ModelParseStatus
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m3_models import UnknownReferenceAttempt
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_regression import M6CaseReplaySnapshot
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
    M6ReplayInputClosureAuthority,
)
from labcourt.contracts.m6_source_authority import M6ReplayInputAuthority
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.screening import (
    ModelParseReceipt,
    StructureRepairRequest,
    VLMRequest,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.m6_model_reference_authority import (
    M6CaseModelReferenceAuthority,
    M6ScreeningModelReferenceBinding,
)
from labcourt.domain.m6_procedural_gate_authority import (
    M6CaseProceduralGateAuthority,
    M6ProceduralGateExecutionInput,
)
from labcourt.domain.m6_semantic_projection import (
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
    resolve_m6_locked_model_responses,
)
from labcourt.domain.procedural_gate import ArtifactBounds
from labcourt.domain.screening_router import (
    ScreeningRouteError,
    ScreeningRoutePolicy,
    ScreeningRouter,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_model_calls import M6M3ModelCallAuthoritySnapshot
from labcourt.ports.m6_perception import M6PerceptionAuthoritySnapshot
from labcourt.ports.m6_replay_locked_fast_source import (
    M6ReplayLockedFastTerminalSource,
)


class M6ReplayLockedFastSourceErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SNAPSHOT_IDENTITY_MISMATCH = "SNAPSHOT_IDENTITY_MISMATCH"
    SOURCE_SCOPE_MISMATCH = "SOURCE_SCOPE_MISMATCH"
    ROUTE_REJECTED = "ROUTE_REJECTED"
    MODEL_CALL_CLOSURE_MISMATCH = "MODEL_CALL_CLOSURE_MISMATCH"
    SOURCE_GATE_INVALID = "SOURCE_GATE_INVALID"
    PROJECTION_INVALID = "PROJECTION_INVALID"


class M6ReplayLockedFastSourceError(LabCourtError):
    """Payload-free failure while narrowing a sealed M3 source authority."""

    def __init__(self, code: M6ReplayLockedFastSourceErrorCode) -> None:
        if not isinstance(code, M6ReplayLockedFastSourceErrorCode):
            raise TypeError("code must be an M6 locked fast-source error code")
        self.code = code
        super().__init__(f"M6 locked fast source failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6ReplayLockedFastPrePolicyProjection:
    """READY projection proven from a real adjacent CLOSED source authority.

    The private selector used to load the READY predecessor is deliberately not
    retained here.  Callers keep the real CLOSED catalog closure as the only
    published input authority.
    """

    source_identity_sha256: str
    projection_context: M6VerifiedProjectionContext
    source_snapshot: M6CaseReplaySnapshot

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source_identity_sha256, str)
            or len(self.source_identity_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.source_identity_sha256)
            or type(self.projection_context) is not M6VerifiedProjectionContext
            or type(self.source_snapshot) is not M6CaseReplaySnapshot
        ):
            raise ValueError("M6 Fast pre-policy projection has invalid authority types")
        context = self.projection_context
        snapshot = self.source_snapshot
        try:
            rebuilt = build_m6_case_replay_snapshot(
                context=context,
                sample_id=snapshot.sample_id,
                source_case_revision=snapshot.source_case_revision,
            )
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise ValueError("M6 Fast pre-policy projection cannot be rebuilt") from None
        if (
            context.case.status != CaseStatus.READY_FOR_ALERT_POLICY
            or rebuilt != snapshot
            or snapshot.source_case_id != context.case.case_id
            or snapshot.source_run_id != context.case.run_id
            or snapshot.manifest_id != context.case.manifest_id
            or snapshot.source_case_document_sha256 != _document_sha256(context.case)
            or self.source_identity_sha256
            != context.model_reference_authority.source_identity_sha256
            or self.source_identity_sha256
            != context.procedural_gate_authority.source_identity_sha256
        ):
            raise ValueError("M6 Fast pre-policy projection authorities are cross-grafted")


def _fail(code: M6ReplayLockedFastSourceErrorCode) -> NoReturn:
    raise M6ReplayLockedFastSourceError(code)


def _document_sha256(value: object) -> str:
    model_dump = getattr(value, "model_dump", None)
    if not callable(model_dump):
        _fail(M6ReplayLockedFastSourceErrorCode.INVALID_ARGUMENT)
    document = canonical_json(model_dump(mode="json"))
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _controlled_closure(value: object) -> M6ReplayInputClosureAuthority:
    if type(value) is not M6ReplayInputClosureAuthority:
        _fail(M6ReplayLockedFastSourceErrorCode.INVALID_ARGUMENT)
    try:
        controlled = M6ReplayInputClosureAuthority.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedFastSourceErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedFastSourceErrorCode.INVALID_ARGUMENT)
    return controlled


def _controlled_config(value: object) -> AppConfig:
    if type(value) is not AppConfig:
        _fail(M6ReplayLockedFastSourceErrorCode.INVALID_ARGUMENT)
    try:
        controlled = AppConfig.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedFastSourceErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedFastSourceErrorCode.INVALID_ARGUMENT)
    return controlled


def _controlled_case(value: object) -> Case:
    if type(value) is not Case:
        _fail(M6ReplayLockedFastSourceErrorCode.INVALID_ARGUMENT)
    try:
        controlled = Case.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedFastSourceErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedFastSourceErrorCode.INVALID_ARGUMENT)
    return controlled


def _controlled_source(value: object) -> M6ValidatedSourceAuthority:
    if type(value) is not M6ValidatedSourceAuthority:
        _fail(M6ReplayLockedFastSourceErrorCode.INVALID_ARGUMENT)
    try:
        authority = M6ReplayInputAuthority.model_validate(
            value.input_authority.model_dump(
                mode="json",
                exclude_computed_fields=True,
            )
        )
        report = M5ArtifactValidationReport.model_validate(
            value.source_validation_report.model_dump(
                mode="json",
                exclude_computed_fields=True,
            )
        )
        case = Case.model_validate(
            value.source_case.model_dump(mode="json", exclude_computed_fields=True)
        )
        manifest = RunManifest.model_validate(
            value.source_manifest.model_dump(mode="json", exclude_computed_fields=True)
        )
        controlled = M6ValidatedSourceAuthority(
            source_identity_sha256=value.source_identity_sha256,
            input_authority=authority,
            source_validation_report=report,
            source_case=case,
            source_manifest=manifest,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedFastSourceErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedFastSourceErrorCode.INVALID_ARGUMENT)
    return controlled


def _require_source_binding(
    closure: M6ReplayInputClosureAuthority,
    source: M6ValidatedSourceAuthority,
    config: AppConfig,
) -> None:
    authority = source.input_authority
    case = source.source_case
    manifest = source.source_manifest
    report = source.source_validation_report
    if (
        authority.sample_id != closure.sample_id
        or authority.source_run_id != closure.source_run_id
        or authority.source_case_id != closure.source_case_id
        or authority.source_case_revision != closure.source_case_revision
        or authority.source_case_document_sha256 != closure.source_case_document_sha256
        or authority.source_manifest_id != closure.source_manifest_id
        or authority.source_manifest_document_sha256 != closure.source_manifest_document_sha256
        or authority.input_authority_id != closure.input_authority_id
        or authority.input_authority_document_sha256 != closure.input_authority_document_sha256
        or authority.source_validation_report_id != closure.source_validation_report_id
        or authority.source_validation_report_document_sha256
        != closure.source_validation_report_document_sha256
        or authority.frame_inventory_root_sha256 != closure.frame_inventory_root_sha256
        or authority.detection_inventory_root_sha256 != closure.detection_inventory_root_sha256
        or authority.model_call_inventory_root_sha256 != closure.model_call_inventory_root_sha256
        or authority.embedding_inventory_root_sha256 != closure.embedding_inventory_root_sha256
        or authority.tool_result_inventory_root_sha256 != closure.tool_result_inventory_root_sha256
        or authority.historical_causal_cut_id != closure.historical_cut.causal_cut_id
        or case.run_id != closure.source_run_id
        or case.case_id != closure.source_case_id
        or case.manifest_id != closure.source_manifest_id
        or _document_sha256(case) != closure.source_case_document_sha256
        or manifest.manifest_id != closure.source_manifest_id
        or _document_sha256(manifest) != closure.source_manifest_document_sha256
        or manifest.config_sha256 != config.config_sha256
        or authority.source_config_sha256 != config.config_sha256
        or report.report_id != closure.source_validation_report_id
        or _document_sha256(report) != closure.source_validation_report_document_sha256
        or not report.passed
    ):
        _fail(M6ReplayLockedFastSourceErrorCode.SOURCE_SCOPE_MISMATCH)


def _parse_history(
    case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
    binding: M6ScreeningModelReferenceBinding,
) -> tuple[ModelParseReceipt, ...]:
    pack = case.evidence_packs[0]
    verdict = case.verdicts[0]
    response_ids = {item.artifact_id for item in verdict.model_response_refs}
    history = tuple(
        sorted(
            (
                item.receipt
                for item in snapshot.parse_receipts
                if item.receipt.response_id in response_ids
            ),
            key=lambda item: item.attempt_index,
        )
    )
    expected_attempts = (0,) if len(history) == 1 else (0, 1)
    expected_scope = (
        pack.run_id,
        pack.case_id,
        pack.pack_id,
        pack.version,
        pack.manifest_id,
    )
    requests_by_id = {item.request.request_id: item.request for item in snapshot.requests}
    final_request = requests_by_id.get(binding.final_request_id)
    scope_request = requests_by_id.get(binding.scope.request_id)
    expected_request_ids = (
        (binding.scope.request_id,)
        if binding.scope.request_id == binding.final_request_id
        else (binding.scope.request_id, binding.final_request_id)
    )
    expected_response_refs = tuple(
        sorted(
            (
                ArtifactRef(
                    kind=ArtifactKind.MODEL_RESPONSE,
                    artifact_id=item.response_id,
                )
                for item in history
            ),
            key=lambda item: item.sort_key,
        )
    )
    if (
        len(history) not in {1, 2}
        or len(history) != len(snapshot.parse_receipts)
        or tuple(item.attempt_index for item in history) != expected_attempts
        or history[-1].status != ModelParseStatus.PARSED
        or (len(history) == 2 and history[0].status != ModelParseStatus.REPAIR_REQUIRED)
        or any(
            (
                item.run_id,
                item.case_id,
                item.evidence_pack_id,
                item.evidence_pack_version,
                item.manifest_id,
            )
            != expected_scope
            for item in history
        )
        or history[-1].parsed_output_id != case.screening_results[0].parsed_output.parsed_output_id
        or history[-1].parsed_output_sha256
        != case.screening_results[0].parsed_output.parsed_output_sha256
        or response_ids != {item.response_id for item in history}
        or tuple(item.request_id for item in history) != expected_request_ids
        or case.verdicts[0].model_response_refs != expected_response_refs
        or not isinstance(scope_request, VLMRequest)
        or (binding.scope.request_id == binding.final_request_id and final_request != scope_request)
        or (
            binding.scope.request_id != binding.final_request_id
            and (
                not isinstance(final_request, StructureRepairRequest)
                or final_request.original_request_id != binding.scope.request_id
                or final_request.original_response_id != history[0].response_id
            )
        )
    ):
        _fail(M6ReplayLockedFastSourceErrorCode.MODEL_CALL_CLOSURE_MISMATCH)
    return history


def _unknown_attempts(
    history: tuple[ModelParseReceipt, ...],
) -> tuple[UnknownReferenceAttempt, ...]:
    values = {
        attempt.sort_key: attempt
        for receipt in history
        for attempt in receipt.unknown_reference_attempts
    }
    return tuple(values[key] for key in sorted(values))


def _artifact_bounds(
    case: Case,
    frames: tuple[FrameRef, ...],
) -> tuple[ArtifactBounds, ...]:
    pack = case.evidence_packs[0]
    values: dict[tuple[str, str], ArtifactBounds] = {}
    for crop in pack.crops:
        bound = ArtifactBounds(
            artifact_ref=ArtifactRef(
                kind=ArtifactKind.CROP,
                artifact_id=crop.crop_id,
            ),
            width=crop.output_width,
            height=crop.output_height,
        )
        values[bound.sort_key] = bound
    frames_by_id = {frame.frame_id: frame for frame in frames}
    required_frame_ids = {
        ref.artifact_id for ref in pack.expected_closure_refs() if ref.kind == ArtifactKind.FRAME
    }
    if set(frames_by_id) & required_frame_ids != required_frame_ids:
        _fail(M6ReplayLockedFastSourceErrorCode.SOURCE_GATE_INVALID)
    for frame_id in sorted(required_frame_ids):
        frame = frames_by_id[frame_id]
        try:
            bound = ArtifactBounds(
                artifact_ref=ArtifactRef(
                    kind=ArtifactKind.FRAME,
                    artifact_id=frame_id,
                ),
                width=frame.width,
                height=frame.height,
            )
        except (AttributeError, TypeError, ValueError):
            _fail(M6ReplayLockedFastSourceErrorCode.SOURCE_GATE_INVALID)
        values[bound.sort_key] = bound
    return tuple(values[key] for key in sorted(values))


def _assemble_m6_replay_locked_fast_projection(
    *,
    controlled: M6ReplayInputClosureAuthority,
    controlled_config: AppConfig,
    case: Case,
    source: M6ValidatedSourceAuthority,
    perception_snapshot: M6PerceptionAuthoritySnapshot,
    m3_snapshot: M6M3ModelCallAuthoritySnapshot,
) -> M6ReplayLockedFastPrePolicyProjection:
    """Build the shared READY Fast projection after source binding is proven."""

    if (
        perception_snapshot.source_identity_sha256 != m3_snapshot.source_identity_sha256
        or perception_snapshot.source_identity_sha256 != source.source_identity_sha256
    ):
        _fail(M6ReplayLockedFastSourceErrorCode.SNAPSHOT_IDENTITY_MISMATCH)
    if (
        len(case.evidence_packs) != 1
        or len(case.screening_results) != 1
        or len(case.verdicts) != 1
        or len(case.procedural_reviews) != 1
        or controlled.embeddings
        or controlled.tool_results
        or controlled.historical_cut.retrieval_cycles
    ):
        _fail(M6ReplayLockedFastSourceErrorCode.ROUTE_REJECTED)

    try:
        perception = assemble_m6_resolved_perception(
            closure=controlled,
            snapshot=perception_snapshot,
        )
        model_calls = assemble_m6_locked_screening_model_calls(
            source_case=case,
            snapshot=m3_snapshot,
        )
    except M6PerceptionAuthorityError:
        _fail(M6ReplayLockedFastSourceErrorCode.SOURCE_SCOPE_MISMATCH)
    except M6ModelCallAuthorityError:
        _fail(M6ReplayLockedFastSourceErrorCode.MODEL_CALL_CLOSURE_MISMATCH)
    if (
        model_calls != controlled.model_calls
        or len(model_calls) not in {1, 2}
        or any(
            item.layer != M6LockedModelCallLayer.SCREENING
            or item.role != M6LockedModelRole.SCREENING
            or item.result_kind != M6LockedModelCallResultKind.RESPONSE
            for item in model_calls
        )
    ):
        _fail(M6ReplayLockedFastSourceErrorCode.MODEL_CALL_CLOSURE_MISMATCH)

    pack = case.evidence_packs[0]
    screening = case.screening_results[0]
    verdict = case.verdicts[0]
    review = case.procedural_reviews[0]
    screening_config = controlled_config.screening
    try:
        rebuilt_screening = ScreeningRouter(
            ScreeningRoutePolicy(
                low_probability=screening_config.low_probability,
                high_probability=screening_config.high_probability,
                strong_signal_threshold=screening_config.strong_signal_threshold,
                router_version=screening_config.router_version,
                conflict_policy_version=screening_config.conflict_policy_version,
            )
        ).route(
            screening.parsed_output,
            pack,
            version=screening.version,
        )
    except (ScreeningRouteError, TypeError, ValueError):
        _fail(M6ReplayLockedFastSourceErrorCode.ROUTE_REJECTED)
    if rebuilt_screening != screening:
        _fail(M6ReplayLockedFastSourceErrorCode.ROUTE_REJECTED)
    try:
        screening_bindings = resolve_m6_screening_model_reference_bindings(
            source_case=case,
            snapshot=m3_snapshot,
        )
        fast_bindings = resolve_m6_fast_verdict_model_reference_bindings(
            source_case=case,
            screening_bindings=screening_bindings,
        )
        references = M6CaseModelReferenceAuthority(
            source_identity_sha256=source.source_identity_sha256,
            run_id=case.run_id,
            case_id=case.case_id,
            manifest_id=case.manifest_id,
            screening_bindings=screening_bindings,
            verdict_bindings=(),
            fast_verdict_bindings=fast_bindings,
        )
    except (M6ModelReferenceAuthorityError, TypeError, ValueError):
        _fail(M6ReplayLockedFastSourceErrorCode.ROUTE_REJECTED)
    if len(references.screening_bindings) != 1:
        _fail(M6ReplayLockedFastSourceErrorCode.ROUTE_REJECTED)
    history = _parse_history(case, m3_snapshot, references.screening_bindings[0])
    try:
        receipt = source.receipt_for_review(review.review_id)
        if (
            receipt.run_id != case.run_id
            or receipt.case_id != case.case_id
            or receipt.manifest_id != case.manifest_id
            or receipt.source_review_id != review.review_id
            or receipt.source_review_document_sha256 != _document_sha256(review)
            or receipt.review_version != review.version
            or receipt.evidence_pack_id != pack.pack_id
            or receipt.evidence_pack_version != pack.version
            or receipt.evidence_pack_document_sha256 != _document_sha256(pack)
        ):
            _fail(M6ReplayLockedFastSourceErrorCode.SOURCE_GATE_INVALID)
        gate_input = M6ProceduralGateExecutionInput(
            source_review_id=review.review_id,
            source_review_document_sha256=receipt.source_review_document_sha256,
            verdict=verdict,
            evidence_pack=pack,
            current_closure=receipt.current_closure,
            gate_config=controlled_config.procedural_gate,
            alert_config=controlled_config.alerts,
            review_version=review.version,
            unknown_reference_attempts=_unknown_attempts(history),
            artifact_bounds=_artifact_bounds(case, perception.frames),
        )
        if gate_input.rebuild_review() != review:
            _fail(M6ReplayLockedFastSourceErrorCode.SOURCE_GATE_INVALID)
        gates = M6CaseProceduralGateAuthority(
            source_identity_sha256=source.source_identity_sha256,
            run_id=case.run_id,
            case_id=case.case_id,
            manifest_id=case.manifest_id,
            inputs=(gate_input,),
        )
        context = M6VerifiedProjectionContext(
            case=case,
            perception=perception,
            historical_source_run_id=case.run_id,
            historical_source_case_id=case.case_id,
            historical_source_manifest_id=case.manifest_id,
            model_reference_authority=references,
            procedural_gate_authority=gates,
            model_responses=resolve_m6_locked_model_responses(model_calls),
        )
        assert controlled.source_case_revision is not None
        snapshot = build_m6_case_replay_snapshot(
            context=context,
            sample_id=controlled.sample_id,
            source_case_revision=controlled.source_case_revision,
        )
        return M6ReplayLockedFastPrePolicyProjection(
            source_identity_sha256=source.source_identity_sha256,
            projection_context=context,
            source_snapshot=snapshot,
        )
    except M6ReplayLockedFastSourceError:
        raise
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedFastSourceErrorCode.PROJECTION_INVALID)


def assemble_m6_replay_locked_fast_terminal_source(
    *,
    closure: object,
    perception_snapshot: object,
    m3_snapshot: object,
    source_authority: object,
    config: object,
) -> M6ReplayLockedFastTerminalSource:
    """Prove one post-parse source without loading M4/M5 execution capabilities."""

    controlled = _controlled_closure(closure)
    controlled_config = _controlled_config(config)
    source = _controlled_source(source_authority)
    if (
        type(perception_snapshot) is not M6PerceptionAuthoritySnapshot
        or type(m3_snapshot) is not M6M3ModelCallAuthoritySnapshot
    ):
        _fail(M6ReplayLockedFastSourceErrorCode.INVALID_ARGUMENT)
    _require_source_binding(controlled, source, controlled_config)
    projection = _assemble_m6_replay_locked_fast_projection(
        controlled=controlled,
        controlled_config=controlled_config,
        case=source.source_case,
        source=source,
        perception_snapshot=perception_snapshot,
        m3_snapshot=m3_snapshot,
    )
    try:
        return M6ReplayLockedFastTerminalSource(
            source_identity_sha256=projection.source_identity_sha256,
            closure=controlled,
            projection_context=projection.projection_context,
            source_snapshot=projection.source_snapshot,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedFastSourceErrorCode.PROJECTION_INVALID)


def assemble_m6_replay_locked_closed_policy_fast_predecessor_projection(
    *,
    catalog_closure: object,
    ready_case: object,
    ready_case_revision: object,
    perception_snapshot: object,
    m3_snapshot: object,
    source_authority: object,
    config: object,
) -> M6ReplayLockedFastPrePolicyProjection:
    """Prove the READY Fast predecessor while retaining a real CLOSED catalog cut."""

    closure = _controlled_closure(catalog_closure)
    controlled_config = _controlled_config(config)
    source = _controlled_source(source_authority)
    predecessor = _controlled_case(ready_case)
    if (
        not isinstance(ready_case_revision, int)
        or isinstance(ready_case_revision, bool)
        or ready_case_revision < 1
        or type(perception_snapshot) is not M6PerceptionAuthoritySnapshot
        or type(m3_snapshot) is not M6M3ModelCallAuthoritySnapshot
    ):
        _fail(M6ReplayLockedFastSourceErrorCode.INVALID_ARGUMENT)

    _require_source_binding(closure, source, controlled_config)
    closed = source.source_case
    predecessor_document_sha256 = _document_sha256(predecessor)
    ready_payload = predecessor.model_dump(mode="json", exclude_computed_fields=True)
    closed_payload = closed.model_dump(mode="json", exclude_computed_fields=True)
    for field_name in ("status", "alerts", "final_decision", "timeline"):
        ready_payload.pop(field_name, None)
        closed_payload.pop(field_name, None)
    if (
        closure.source_case_revision != ready_case_revision + 1
        or closure.source_case_document_sha256 == predecessor_document_sha256
        or predecessor.status != CaseStatus.READY_FOR_ALERT_POLICY
        or closed.status != CaseStatus.CLOSED
        or predecessor.alerts
        or predecessor.appeals
        or predecessor.final_decision is not None
        or predecessor.current_backlog_item_id is not None
        or len(closed.timeline) != len(predecessor.timeline) + 1
        or closed.timeline[:-1] != predecessor.timeline
        or ready_payload != closed_payload
    ):
        _fail(M6ReplayLockedFastSourceErrorCode.SOURCE_SCOPE_MISMATCH)

    try:
        selector = M6ReplayInputClosureAuthority.model_validate(
            {
                **closure.model_dump(mode="json", exclude_computed_fields=True),
                "source_case_revision": ready_case_revision,
                "source_case_document_sha256": predecessor_document_sha256,
            }
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedFastSourceErrorCode.PROJECTION_INVALID)
    return _assemble_m6_replay_locked_fast_projection(
        controlled=selector,
        controlled_config=controlled_config,
        case=predecessor,
        source=source,
        perception_snapshot=perception_snapshot,
        m3_snapshot=m3_snapshot,
    )


__all__ = [
    "M6ReplayLockedFastPrePolicyProjection",
    "M6ReplayLockedFastSourceError",
    "M6ReplayLockedFastSourceErrorCode",
    "assemble_m6_replay_locked_closed_policy_fast_predecessor_projection",
    "assemble_m6_replay_locked_fast_terminal_source",
]

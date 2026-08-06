"""Pure construction of opened candidate semantic projections."""

from __future__ import annotations

import hashlib
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_hearing_model_call_authority import (
    M6HearingModelCallAuthorityError,
    assemble_m6_locked_hearing_model_calls,
)
from labcourt.application.m6_historical_retrieval_cut import (
    M6HistoricalRetrievalCutError,
    assemble_m6_historical_retrieval_cut,
    resolve_m6_historical_retrieval_cycles,
)
from labcourt.application.m6_model_call_authority import (
    M6ModelCallAuthorityError,
    assemble_m6_locked_screening_model_calls,
)
from labcourt.application.m6_model_reference_authority import (
    M6ModelReferenceAuthorityError,
    resolve_m6_hearing_model_reference_bindings,
    resolve_m6_screening_model_reference_bindings,
)
from labcourt.application.m6_procedural_gate_authority import (
    M6ProceduralGateAuthorityError,
    assemble_m6_candidate_case_procedural_gate_authority,
)
from labcourt.application.m6_source_authority_sealing import M6SealedGateSource
from labcourt.application.m6_upgrade_m3_model_physical import (
    M6M3ModelPhysicalPlan,
    M6M3ModelPhysicalResolutionError,
    plan_m6_m3_observed_model_call_closures,
)
from labcourt.application.m6_upgrade_m4_model_physical import (
    M6M4ModelPhysicalPlan,
    M6M4ModelPhysicalResolutionError,
    plan_m6_m4_observed_model_call_closures,
)
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import ArtifactKind, CaseStatus
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationReport
from labcourt.contracts.m6_regression import (
    M6CaseReplaySnapshot,
    M6ReplayExecutionOutcome,
)
from labcourt.contracts.m6_regression_execution import M6UpgradeCandidateRunCutAuthority
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallInput,
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
    M6LockedRetrievalOutcomeKind,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.domain.m6_model_reference_authority import M6CaseModelReferenceAuthority
from labcourt.domain.m6_procedural_gate_authority import M6CaseProceduralGateAuthority
from labcourt.domain.m6_semantic_projection import (
    M6ResolvedPerception,
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
    resolve_m6_locked_model_responses,
)
from labcourt.ports.m6_acquisition_authority import M6ValidatedM4ReplayAuthoritySnapshot
from labcourt.ports.m6_historical_retrieval import M6ValidatedHistoricalRetrievalSnapshots
from labcourt.ports.m6_model_calls import (
    M6M3ModelCallAuthoritySnapshot,
    M6M4ModelCallAuthoritySnapshot,
)
from labcourt.ports.m6_procedural_gate_authority import M6ProceduralGateHistorySnapshot
from labcourt.ports.m6_upgrade_candidate_output import (
    M6UpgradeCandidateOutputError,
    M6UpgradeCandidateOutputFailureCode,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)
_FailureCode = M6UpgradeCandidateOutputFailureCode
_BASE_KINDS = {
    M6UpgradePhysicalArtifactKind.FRAME,
    M6UpgradePhysicalArtifactKind.DETECTION,
}
_MODEL_KINDS = frozenset(
    kind for kind in M6UpgradePhysicalArtifactKind if kind.value.startswith("MODEL_")
)


def _fail(code: _FailureCode) -> NoReturn:
    raise M6UpgradeCandidateOutputError(code) from None


def _canonical(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        _fail(_FailureCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(_FailureCode.INVALID_ARGUMENT)
    return controlled


def _document_sha256(value: BaseModel) -> str:
    return hashlib.sha256(canonical_json(value.model_dump(mode="json")).encode("utf-8")).hexdigest()


def _require_base_case(case: Case) -> None:
    if (
        case.evidence_packs
        or case.screening_results
        or case.verdicts
        or case.procedural_reviews
        or case.alerts
        or case.appeals
    ):
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)


def _require_case_perception(case: Case, perception: M6ResolvedPerception) -> None:
    event = case.event
    required_frame_ids = {
        f"{event.camera_id}:{event.stream_id}:{event.start_frame}",
        f"{event.camera_id}:{event.stream_id}:{event.end_frame_exclusive - 1}",
        f"{event.camera_id}:{event.stream_id}:{event.trigger_frame}",
        *event.confirmation.examined_frame_ids,
        *event.confirmation.counterevidence_frame_ids,
        *(
            (event.confirmation.post_threshold_recovery_frame_id,)
            if event.confirmation.post_threshold_recovery_frame_id is not None
            else ()
        ),
        *(
            fact.source_ref.artifact_id
            for fact in event.objective_facts
            if fact.source_ref.kind == ArtifactKind.FRAME
        ),
    }
    required_detection_ids = {
        fact.source_ref.artifact_id
        for fact in event.objective_facts
        if fact.source_ref.kind == ArtifactKind.DETECTION
    }
    for pack in case.evidence_packs:
        required_frame_ids.update(pack.key_frame_ids)
        required_frame_ids.update(pack.confirmation_record.examined_frame_ids)
        required_frame_ids.update(pack.confirmation_record.counterevidence_frame_ids)
        if pack.confirmation_record.post_threshold_recovery_frame_id is not None:
            required_frame_ids.add(pack.confirmation_record.post_threshold_recovery_frame_id)
        for crop in pack.crops:
            required_frame_ids.add(crop.frame_id)
            for ref in (*crop.source_refs, *crop.privacy_receipt.input_refs):
                if ref.kind == ArtifactKind.FRAME:
                    required_frame_ids.add(ref.artifact_id)
                elif ref.kind == ArtifactKind.DETECTION:
                    required_detection_ids.add(ref.artifact_id)
        for fact in pack.objective_facts:
            if fact.source_ref.kind == ArtifactKind.FRAME:
                required_frame_ids.add(fact.source_ref.artifact_id)
            elif fact.source_ref.kind == ArtifactKind.DETECTION:
                required_detection_ids.add(fact.source_ref.artifact_id)
    if not required_frame_ids.issubset({item.frame_id for item in perception.frames}) or not (
        required_detection_ids.issubset({item.detection_id for item in perception.detections})
    ):
        _fail(_FailureCode.OBSERVATION_CLOSURE_MISMATCH)


def _require_perception_record_closure(
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    record: M6UpgradeSampleExecutionRecordV2,
    perception: M6ResolvedPerception,
    *,
    expected_evidence_packs: tuple[EvidencePack, ...] = (),
    expected_model_refs: tuple[M6UpgradePhysicalArtifactRef, ...] = (),
) -> None:
    if type(expected_evidence_packs) is not tuple or any(
        type(item) is not EvidencePack for item in expected_evidence_packs
    ):
        _fail(_FailureCode.INVALID_ARGUMENT)
    if type(expected_model_refs) is not tuple or any(
        type(item) is not M6UpgradePhysicalArtifactRef for item in expected_model_refs
    ):
        _fail(_FailureCode.INVALID_ARGUMENT)
    if any(
        (
            item.source != M6UpgradePhysicalArtifactSource.M2_PERCEPTION
            or item.kind not in _BASE_KINDS
        )
        and (
            item.source != M6UpgradePhysicalArtifactSource.M2_EVIDENCE
            or item.kind != M6UpgradePhysicalArtifactKind.EVIDENCE_PACK
        )
        for item in observation.artifacts
    ):
        _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)
    observed = {
        (item.source, item.kind, item.artifact_id): item.usage for item in observation.artifacts
    }
    ordinary_links = tuple(
        link for link in record.artifact_links if link.artifact.kind not in _MODEL_KINDS
    )
    linked = {
        (link.artifact.source, link.artifact.kind, link.artifact.artifact_id): link
        for link in ordinary_links
    }
    perception_keys = {
        (
            M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
            M6UpgradePhysicalArtifactKind.FRAME,
            item.frame_id,
        )
        for item in perception.frames
    } | {
        (
            M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
            M6UpgradePhysicalArtifactKind.DETECTION,
            item.detection_id,
        )
        for item in perception.detections
    }
    evidence_pack_keys = {
        (
            M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
            M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
            item.pack_id,
        )
        for item in expected_evidence_packs
    }
    if (
        len(observed) != len(observation.artifacts)
        or len(linked) != len(ordinary_links)
        or set(observed) != set(linked)
        or set(observed) != perception_keys | evidence_pack_keys
        or any(linked[key].usage != usage for key, usage in observed.items())
    ):
        _fail(_FailureCode.OBSERVATION_CLOSURE_MISMATCH)

    for frame in perception.frames:
        ref = linked[
            (
                M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                M6UpgradePhysicalArtifactKind.FRAME,
                frame.frame_id,
            )
        ].artifact
        if (
            ref.container_id is not None
            or ref.document_sha256 != _document_sha256(frame)
            or ref.content_sha256 != frame.content_sha256
        ):
            _fail(_FailureCode.PHYSICAL_ARTIFACT_REJECTED)
    for detection in perception.detections:
        ref = linked[
            (
                M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                M6UpgradePhysicalArtifactKind.DETECTION,
                detection.detection_id,
            )
        ].artifact
        digest = _document_sha256(detection)
        if (
            ref.container_id != detection.frame_id
            or ref.document_sha256 != digest
            or ref.content_sha256 != digest
        ):
            _fail(_FailureCode.PHYSICAL_ARTIFACT_REJECTED)
    for pack in expected_evidence_packs:
        ref = linked[
            (
                M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
                M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
                pack.pack_id,
            )
        ].artifact
        digest = _document_sha256(pack)
        if (
            ref.container_id is not None
            or ref.document_sha256 != digest
            or ref.content_sha256 != digest
        ):
            _fail(_FailureCode.PHYSICAL_ARTIFACT_REJECTED)

    linked_model_refs = tuple(
        sorted(
            (link.artifact for link in record.artifact_links if link.artifact.kind in _MODEL_KINDS),
            key=lambda item: item.physical_key,
        )
    )
    controlled_model_refs = tuple(sorted(expected_model_refs, key=lambda item: item.physical_key))
    if linked_model_refs != controlled_model_refs:
        _fail(_FailureCode.PHYSICAL_ARTIFACT_REJECTED)


def build_m6_upgrade_base_candidate_case_snapshot(
    *,
    execution_ledger: M6UpgradeExecutionLedgerSealV2,
    run_cut: M6UpgradeCandidateRunCutAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    sample_record: M6UpgradeSampleExecutionRecordV2,
    selected_case: Case,
    perception: M6ResolvedPerception,
) -> M6CaseReplaySnapshot:
    """Build the model-free CASE_REPLAYED snapshot from one exact terminal cut."""

    ledger = _canonical(execution_ledger, M6UpgradeExecutionLedgerSealV2)
    cut = _canonical(run_cut, M6UpgradeCandidateRunCutAuthority)
    observed = _canonical(observation, M6UpgradeSampleExecutionObservationAuthorityV2)
    record = _canonical(sample_record, M6UpgradeSampleExecutionRecordV2)
    case = _canonical(selected_case, Case)
    if type(perception) is not M6ResolvedPerception:
        _fail(_FailureCode.INVALID_ARGUMENT)
    try:
        resolved_perception = M6ResolvedPerception(
            frames=perception.frames,
            detections=perception.detections,
        )
    except (TypeError, ValueError):
        _fail(_FailureCode.INVALID_ARGUMENT)

    scope = ledger.execution_scope
    binding = observed.candidate_case
    if (
        observed.outcome != M6ReplayExecutionOutcome.CASE_REPLAYED
        or record.outcome != M6ReplayExecutionOutcome.CASE_REPLAYED
        or binding is None
        or observed.selected_case_audit_anchor is None
        or record.candidate_case != binding
        or observed.observation_authority_id != record.observation_authority_id
        or observed.execution_entry != record.execution_entry
        or observed.ledger_sequence != record.ledger_sequence
        or record.ledger_sequence >= len(ledger.sample_executions)
        or ledger.sample_executions[record.ledger_sequence] != record
    ):
        _fail(_FailureCode.CASE_BINDING_MISMATCH)
    if (
        case.run_id != scope.candidate_run_id
        or case.manifest_id != scope.candidate_manifest.manifest_id
        or case.case_id != binding.case_id
        or _document_sha256(case) != binding.case_document_sha256
        or cut.candidate_run_id != scope.candidate_run_id
        or cut.candidate_manifest != scope.candidate_manifest
        or cut.audit_head_sequence != ledger.source_audit_head_sequence
        or cut.audit_head_hash != ledger.source_audit_head_hash
    ):
        _fail(_FailureCode.CASE_BINDING_MISMATCH)

    _require_base_case(case)
    _require_perception_record_closure(observed, record, resolved_perception)
    _require_case_perception(case, resolved_perception)
    source_identity = sha256_hex(
        [
            "m6-upgrade-candidate-projection-cut",
            1,
            ledger.ledger_seal_authority_id,
            cut.candidate_run_cut_authority_id,
            observed.observation_authority_id,
            record.sample_execution_record_id,
            binding.case_binding_id,
            [[item.frame_id, _document_sha256(item)] for item in resolved_perception.frames],
            [
                [item.detection_id, _document_sha256(item)]
                for item in resolved_perception.detections
            ],
        ]
    )
    try:
        context = M6VerifiedProjectionContext(
            case=case,
            perception=resolved_perception,
            historical_source_run_id=case.run_id,
            historical_source_case_id=case.case_id,
            historical_source_manifest_id=case.manifest_id,
            model_reference_authority=M6CaseModelReferenceAuthority(
                source_identity_sha256=source_identity,
                run_id=case.run_id,
                case_id=case.case_id,
                manifest_id=case.manifest_id,
                screening_bindings=(),
                verdict_bindings=(),
            ),
            procedural_gate_authority=M6CaseProceduralGateAuthority(
                source_identity_sha256=source_identity,
                run_id=case.run_id,
                case_id=case.case_id,
                manifest_id=case.manifest_id,
                inputs=(),
            ),
        )
        snapshot = build_m6_case_replay_snapshot(
            context=context,
            sample_id=record.sample_id,
            source_case_revision=binding.case_revision,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)
    if (
        snapshot.source_case_document_sha256 != binding.case_document_sha256
        or snapshot.source_case_revision != binding.case_revision
    ):
        _fail(_FailureCode.CASE_BINDING_MISMATCH)
    return snapshot


def _require_screening_only_case(case: Case) -> None:
    if (
        not case.evidence_packs
        or not case.screening_results
        or case.verdicts
        or case.procedural_reviews
        or case.alerts
        or case.appeals
        or any(pack.version != 1 or pack.tool_results for pack in case.evidence_packs)
    ):
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)


def _require_screening_observation_closure(
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    *,
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
    physical_plan: M6M3ModelPhysicalPlan,
) -> tuple[M6LockedModelCallInput, ...]:
    if (
        type(snapshot) is not M6M3ModelCallAuthoritySnapshot
        or type(physical_plan) is not M6M3ModelPhysicalPlan
    ):
        _fail(_FailureCode.INVALID_ARGUMENT)
    try:
        locked_calls = assemble_m6_locked_screening_model_calls(
            source_case=source_case,
            snapshot=snapshot,
        )
        rebuilt_plan = plan_m6_m3_observed_model_call_closures(
            source_case=source_case,
            snapshot=snapshot,
        )
    except (M6ModelCallAuthorityError, M6M3ModelPhysicalResolutionError):
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    observed = tuple(
        sorted(
            (
                (
                    item.layer,
                    item.role,
                    item.attempt_index,
                    item.request_id,
                    item.result_kind,
                )
                for item in observation.model_calls
            ),
            key=lambda item: (item[0].value, item[1].value, item[2], item[3]),
        )
    )
    locked = tuple(
        sorted(
            (
                (
                    item.layer,
                    item.role,
                    item.attempt_index,
                    item.request_ref.artifact_id,
                    item.result_kind,
                )
                for item in locked_calls
            ),
            key=lambda item: (item[0].value, item[1].value, item[2], item[3]),
        )
    )
    if not observed or observed != locked or rebuilt_plan != physical_plan:
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    return locked_calls


def build_m6_upgrade_screening_candidate_case_snapshot(
    *,
    execution_ledger: M6UpgradeExecutionLedgerSealV2,
    run_cut: M6UpgradeCandidateRunCutAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    sample_record: M6UpgradeSampleExecutionRecordV2,
    selected_case: Case,
    perception: M6ResolvedPerception,
    m3_snapshot: M6M3ModelCallAuthoritySnapshot,
    m3_physical_plan: M6M3ModelPhysicalPlan,
) -> M6CaseReplaySnapshot:
    """Build a screening-only CASE_REPLAYED snapshot from one exact terminal cut."""

    ledger = _canonical(execution_ledger, M6UpgradeExecutionLedgerSealV2)
    cut = _canonical(run_cut, M6UpgradeCandidateRunCutAuthority)
    observed = _canonical(observation, M6UpgradeSampleExecutionObservationAuthorityV2)
    record = _canonical(sample_record, M6UpgradeSampleExecutionRecordV2)
    case = _canonical(selected_case, Case)
    if type(perception) is not M6ResolvedPerception:
        _fail(_FailureCode.INVALID_ARGUMENT)
    try:
        resolved_perception = M6ResolvedPerception(
            frames=perception.frames,
            detections=perception.detections,
        )
    except (TypeError, ValueError):
        _fail(_FailureCode.INVALID_ARGUMENT)

    scope = ledger.execution_scope
    binding = observed.candidate_case
    if (
        observed.outcome != M6ReplayExecutionOutcome.CASE_REPLAYED
        or record.outcome != M6ReplayExecutionOutcome.CASE_REPLAYED
        or binding is None
        or observed.selected_case_audit_anchor is None
        or record.candidate_case != binding
        or observed.observation_authority_id != record.observation_authority_id
        or observed.execution_entry != record.execution_entry
        or observed.ledger_sequence != record.ledger_sequence
        or record.ledger_sequence >= len(ledger.sample_executions)
        or ledger.sample_executions[record.ledger_sequence] != record
    ):
        _fail(_FailureCode.CASE_BINDING_MISMATCH)
    if (
        case.run_id != scope.candidate_run_id
        or case.manifest_id != scope.candidate_manifest.manifest_id
        or case.case_id != binding.case_id
        or _document_sha256(case) != binding.case_document_sha256
        or cut.candidate_run_id != scope.candidate_run_id
        or cut.candidate_manifest != scope.candidate_manifest
        or cut.audit_head_sequence != ledger.source_audit_head_sequence
        or cut.audit_head_hash != ledger.source_audit_head_hash
    ):
        _fail(_FailureCode.CASE_BINDING_MISMATCH)

    _require_screening_only_case(case)
    locked_calls = _require_screening_observation_closure(
        observed,
        source_case=case,
        snapshot=m3_snapshot,
        physical_plan=m3_physical_plan,
    )
    _require_perception_record_closure(
        observed,
        record,
        resolved_perception,
        expected_evidence_packs=case.evidence_packs,
        expected_model_refs=m3_physical_plan.planned_refs,
    )
    _require_case_perception(case, resolved_perception)
    source_identity = sha256_hex(
        [
            "m6-upgrade-candidate-projection-cut",
            2,
            ledger.ledger_seal_authority_id,
            cut.candidate_run_cut_authority_id,
            observed.observation_authority_id,
            record.sample_execution_record_id,
            binding.case_binding_id,
            m3_snapshot.source_identity_sha256,
            m3_physical_plan.source_identity_sha256,
            [[item.frame_id, _document_sha256(item)] for item in resolved_perception.frames],
            [
                [item.detection_id, _document_sha256(item)]
                for item in resolved_perception.detections
            ],
        ]
    )
    try:
        screening_bindings = resolve_m6_screening_model_reference_bindings(
            source_case=case,
            snapshot=m3_snapshot,
        )
        model_responses = resolve_m6_locked_model_responses(locked_calls)
        context = M6VerifiedProjectionContext(
            case=case,
            perception=resolved_perception,
            historical_source_run_id=case.run_id,
            historical_source_case_id=case.case_id,
            historical_source_manifest_id=case.manifest_id,
            model_reference_authority=M6CaseModelReferenceAuthority(
                source_identity_sha256=source_identity,
                run_id=case.run_id,
                case_id=case.case_id,
                manifest_id=case.manifest_id,
                screening_bindings=screening_bindings,
                verdict_bindings=(),
            ),
            procedural_gate_authority=M6CaseProceduralGateAuthority(
                source_identity_sha256=source_identity,
                run_id=case.run_id,
                case_id=case.case_id,
                manifest_id=case.manifest_id,
                inputs=(),
            ),
            model_responses=model_responses,
        )
        candidate = build_m6_case_replay_snapshot(
            context=context,
            sample_id=record.sample_id,
            source_case_revision=binding.case_revision,
        )
    except (M6ModelReferenceAuthorityError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    if (
        candidate.source_case_document_sha256 != binding.case_document_sha256
        or candidate.source_case_revision != binding.case_revision
    ):
        _fail(_FailureCode.CASE_BINDING_MISMATCH)
    return candidate


def _require_terminal_hearing_case(case: Case) -> None:
    if (
        case.status != CaseStatus.READY_FOR_ALERT_POLICY
        or len(case.evidence_packs) != 1
        or len(case.screening_results) != 1
        or len(case.verdicts) != 1
        or len(case.procedural_reviews) != 1
        or not case.procedural_reviews[0].passed
        or case.alerts
        or case.appeals
        or case.evidence_packs[0].version != 1
        or case.evidence_packs[0].tool_results
    ):
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)


def _model_call_key(value: object) -> tuple[object, ...]:
    return (
        getattr(value, "layer", None),
        getattr(value, "role", None),
        getattr(value, "attempt_index", None),
        (
            getattr(getattr(value, "request_ref", None), "artifact_id", None)
            or getattr(value, "request_id", None)
        ),
        getattr(value, "result_kind", None),
    )


def _require_terminal_model_call_closure(
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    *,
    source_case: Case,
    m3_snapshot: M6M3ModelCallAuthoritySnapshot,
    m3_physical_plan: M6M3ModelPhysicalPlan,
    m4_snapshot: M6M4ModelCallAuthoritySnapshot,
    m4_physical_plan: M6M4ModelPhysicalPlan,
) -> tuple[M6LockedModelCallInput, ...]:
    if (
        type(m3_snapshot) is not M6M3ModelCallAuthoritySnapshot
        or type(m3_physical_plan) is not M6M3ModelPhysicalPlan
        or type(m4_snapshot) is not M6M4ModelCallAuthoritySnapshot
        or type(m4_physical_plan) is not M6M4ModelPhysicalPlan
    ):
        _fail(_FailureCode.INVALID_ARGUMENT)
    try:
        screening_calls = assemble_m6_locked_screening_model_calls(
            source_case=source_case,
            snapshot=m3_snapshot,
        )
        hearing_calls = assemble_m6_locked_hearing_model_calls(
            source_case=source_case,
            snapshot=m4_snapshot,
        )
        rebuilt_m3 = plan_m6_m3_observed_model_call_closures(
            source_case=source_case,
            snapshot=m3_snapshot,
        )
        rebuilt_m4 = plan_m6_m4_observed_model_call_closures(
            source_case=source_case,
            snapshot=m4_snapshot,
        )
    except (
        M6ModelCallAuthorityError,
        M6HearingModelCallAuthorityError,
        M6M3ModelPhysicalResolutionError,
        M6M4ModelPhysicalResolutionError,
    ):
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    locked = tuple(sorted((*screening_calls, *hearing_calls), key=lambda item: item.sort_key))
    expected_roles = {
        (M6LockedModelCallLayer.SCREENING, M6LockedModelRole.SCREENING),
        (M6LockedModelCallLayer.HEARING, M6LockedModelRole.PROSECUTOR),
        (M6LockedModelCallLayer.HEARING, M6LockedModelRole.DEFENDER),
        (M6LockedModelCallLayer.HEARING, M6LockedModelRole.JUDGE),
    }
    if (
        rebuilt_m3 != m3_physical_plan
        or rebuilt_m4 != m4_physical_plan
        or len(locked) != 4
        or {(item.layer, item.role) for item in locked} != expected_roles
        or any(
            item.attempt_index != 0 or item.result_kind != M6LockedModelCallResultKind.RESPONSE
            for item in locked
        )
        or tuple(_model_call_key(item) for item in observation.model_calls)
        != tuple(_model_call_key(item) for item in locked)
    ):
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    return locked


def build_m6_upgrade_hearing_candidate_case_snapshot(
    *,
    execution_ledger: M6UpgradeExecutionLedgerSealV2,
    run_cut: M6UpgradeCandidateRunCutAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    sample_record: M6UpgradeSampleExecutionRecordV2,
    selected_case: Case,
    perception: M6ResolvedPerception,
    m3_snapshot: M6M3ModelCallAuthoritySnapshot,
    m3_physical_plan: M6M3ModelPhysicalPlan,
    m4_snapshot: M6M4ModelCallAuthoritySnapshot,
    m4_physical_plan: M6M4ModelPhysicalPlan,
    gate_source: M6SealedGateSource,
    gate_history_snapshot: M6ProceduralGateHistorySnapshot,
    historical_snapshots: M6ValidatedHistoricalRetrievalSnapshots,
) -> M6CaseReplaySnapshot:
    """Build the first successful M4/Gate candidate from one immutable cut."""

    ledger = _canonical(execution_ledger, M6UpgradeExecutionLedgerSealV2)
    cut = _canonical(run_cut, M6UpgradeCandidateRunCutAuthority)
    observed = _canonical(observation, M6UpgradeSampleExecutionObservationAuthorityV2)
    record = _canonical(sample_record, M6UpgradeSampleExecutionRecordV2)
    case = _canonical(selected_case, Case)
    if (
        type(perception) is not M6ResolvedPerception
        or type(gate_source) is not M6SealedGateSource
        or type(gate_history_snapshot) is not M6ProceduralGateHistorySnapshot
        or type(historical_snapshots) is not M6ValidatedHistoricalRetrievalSnapshots
    ):
        _fail(_FailureCode.INVALID_ARGUMENT)
    try:
        resolved_perception = M6ResolvedPerception(
            frames=perception.frames,
            detections=perception.detections,
        )
    except (TypeError, ValueError):
        _fail(_FailureCode.INVALID_ARGUMENT)

    scope = ledger.execution_scope
    binding = observed.candidate_case
    if (
        observed.outcome != M6ReplayExecutionOutcome.CASE_REPLAYED
        or record.outcome != M6ReplayExecutionOutcome.CASE_REPLAYED
        or binding is None
        or observed.selected_case_audit_anchor is None
        or record.candidate_case != binding
        or observed.observation_authority_id != record.observation_authority_id
        or observed.execution_entry != record.execution_entry
        or observed.ledger_sequence != record.ledger_sequence
        or record.ledger_sequence >= len(ledger.sample_executions)
        or ledger.sample_executions[record.ledger_sequence] != record
    ):
        _fail(_FailureCode.CASE_BINDING_MISMATCH)
    if (
        case.run_id != scope.candidate_run_id
        or case.manifest_id != scope.candidate_manifest.manifest_id
        or case.case_id != binding.case_id
        or _document_sha256(case) != binding.case_document_sha256
        or cut.candidate_run_id != scope.candidate_run_id
        or cut.candidate_manifest != scope.candidate_manifest
        or cut.audit_head_sequence != ledger.source_audit_head_sequence
        or cut.audit_head_hash != ledger.source_audit_head_hash
    ):
        _fail(_FailureCode.CASE_BINDING_MISMATCH)

    _require_terminal_hearing_case(case)
    locked_calls = _require_terminal_model_call_closure(
        observed,
        source_case=case,
        m3_snapshot=m3_snapshot,
        m3_physical_plan=m3_physical_plan,
        m4_snapshot=m4_snapshot,
        m4_physical_plan=m4_physical_plan,
    )
    expected_model_refs = tuple(
        sorted(
            (*m3_physical_plan.planned_refs, *m4_physical_plan.planned_refs),
            key=lambda item: item.physical_key,
        )
    )
    _require_perception_record_closure(
        observed,
        record,
        resolved_perception,
        expected_evidence_packs=case.evidence_packs,
        expected_model_refs=expected_model_refs,
    )
    _require_case_perception(case, resolved_perception)

    m4_report = cut.validation_report.predecessor_report
    gate_history = gate_history_snapshot
    historical = historical_snapshots
    if (
        not isinstance(m4_report, M4ArtifactValidationReport)
        or m4_report.authority_root_sha256 is None
        or gate_history.source_m4_authority_root_sha256 != m4_report.authority_root_sha256
        or gate_history.run_id != case.run_id
        or historical.run_id != case.run_id
        or historical.manifest_id != case.manifest_id
        or not historical.authority_valid
        or historical.m4_documents != gate_history.documents
        or historical.m5_documents
        or m3_snapshot.run_id != case.run_id
        or m3_snapshot.case_id != case.case_id
        or m3_snapshot.manifest_id != case.manifest_id
        or m4_snapshot.run_id != case.run_id
        or m4_snapshot.case_id != case.case_id
        or m4_snapshot.manifest_id != case.manifest_id
    ):
        _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)
    try:
        historical_cut = assemble_m6_historical_retrieval_cut(
            source_case=case,
            snapshots=historical,
        )
    except M6HistoricalRetrievalCutError:
        _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)
    if (
        len(historical_cut.retrieval_cycles) != 1
        or historical_cut.retrieval_cycles[0].outcome != M6LockedRetrievalOutcomeKind.DEGRADED
    ):
        _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)

    source_identity = sha256_hex(
        [
            "m6-upgrade-candidate-projection-cut",
            3,
            ledger.ledger_seal_authority_id,
            cut.candidate_run_cut_authority_id,
            observed.observation_authority_id,
            record.sample_execution_record_id,
            binding.case_binding_id,
            m3_snapshot.source_identity_sha256,
            m3_physical_plan.source_identity_sha256,
            m4_snapshot.source_identity_sha256,
            m4_snapshot.m4_replay_authority_root_sha256,
            m4_snapshot.model_call_authority_root_sha256,
            m4_physical_plan.source_identity_sha256,
            gate_history.source_identity_sha256,
            gate_history.source_m4_authority_root_sha256,
            [
                [item.kind.value, item.artifact_id, item.document_sha256]
                for item in gate_history.documents
            ],
            historical.source_identity_sha256,
            historical_cut.causal_cut_id,
            [
                [item.receipt_id, item.receipt_document_sha256]
                for item in gate_source.gate_current_closures
            ],
            [[item.frame_id, _document_sha256(item)] for item in resolved_perception.frames],
            [
                [item.detection_id, _document_sha256(item)]
                for item in resolved_perception.detections
            ],
        ]
    )
    try:
        rebound_gate_history = M6ProceduralGateHistorySnapshot(
            source_identity_sha256=source_identity,
            run_id=gate_history.run_id,
            source_m4_authority_root_sha256=gate_history.source_m4_authority_root_sha256,
            documents=gate_history.documents,
            failure_count=gate_history.failure_count,
        )
        rebound_historical = M6ValidatedHistoricalRetrievalSnapshots(
            source_identity_sha256=source_identity,
            run_id=historical.run_id,
            manifest_id=historical.manifest_id,
            m4_documents=historical.m4_documents,
            m5_documents=historical.m5_documents,
            m4_failure_count=historical.m4_failure_count,
            m5_failure_count=historical.m5_failure_count,
            dataset_retention_failure_count=historical.dataset_retention_failure_count,
        )
        screening_bindings = resolve_m6_screening_model_reference_bindings(
            source_case=case,
            snapshot=m3_snapshot,
        )
        verdict_bindings = resolve_m6_hearing_model_reference_bindings(
            source_case=case,
            snapshot=M6ValidatedM4ReplayAuthoritySnapshot(
                source_identity_sha256=source_identity,
                run_id=case.run_id,
                documents=rebound_gate_history.documents,
            ),
        )
        model_reference_authority = M6CaseModelReferenceAuthority(
            source_identity_sha256=source_identity,
            run_id=case.run_id,
            case_id=case.case_id,
            manifest_id=case.manifest_id,
            screening_bindings=screening_bindings,
            verdict_bindings=verdict_bindings,
        )
    except (M6ModelReferenceAuthorityError, TypeError, ValueError):
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    try:
        procedural_gate_authority = assemble_m6_candidate_case_procedural_gate_authority(
            run_cut=cut,
            selected_case=case,
            selected_case_revision=binding.case_revision,
            selected_case_document_sha256=binding.case_document_sha256,
            source_identity_sha256=source_identity,
            gate_source=gate_source,
            snapshot=rebound_gate_history,
        )
    except M6ProceduralGateAuthorityError:
        _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)
    try:
        retrieval_cycles = resolve_m6_historical_retrieval_cycles(
            source_case=case,
            snapshots=rebound_historical,
            historical_cut=historical_cut,
        )
        model_responses = resolve_m6_locked_model_responses(locked_calls)
        context = M6VerifiedProjectionContext(
            case=case,
            perception=resolved_perception,
            historical_source_run_id=case.run_id,
            historical_source_case_id=case.case_id,
            historical_source_manifest_id=case.manifest_id,
            model_reference_authority=model_reference_authority,
            procedural_gate_authority=procedural_gate_authority,
            model_responses=model_responses,
            retrieval_cycles=retrieval_cycles,
        )
        candidate = build_m6_case_replay_snapshot(
            context=context,
            sample_id=record.sample_id,
            source_case_revision=binding.case_revision,
        )
    except (M6HistoricalRetrievalCutError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)
    if (
        candidate.source_case_document_sha256 != binding.case_document_sha256
        or candidate.source_case_revision != binding.case_revision
    ):
        _fail(_FailureCode.CASE_BINDING_MISMATCH)
    return candidate


__all__ = [
    "build_m6_upgrade_base_candidate_case_snapshot",
    "build_m6_upgrade_hearing_candidate_case_snapshot",
    "build_m6_upgrade_screening_candidate_case_snapshot",
]

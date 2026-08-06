from __future__ import annotations

import pytest

from labcourt.adapters.acquisition_fake import (
    DeterministicFakeHearingAcquisitionExecutor,
    FakeAcquisitionFixture,
    FakeAcquisitionToolSpec,
    acquisition_parameters_schema_sha256,
)
from labcourt.contracts.enums import (
    AcquisitionAction,
    ArtifactKind,
    ObjectiveFactKind,
)
from labcourt.contracts.events import ObjectiveFact
from labcourt.contracts.evidence import EvidencePack, OtherCameraSameTimeParameters
from labcourt.contracts.hearing import (
    ToolExecutionManifest,
    derive_m4_tool_result_id,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.evidence_authority import (
    AcquisitionExecution,
    LoadedEvidenceObjects,
    derive_evidence_authority,
)
from labcourt.ports.hearing_acquisition import (
    HearingAcquisitionExecutorError,
    HearingAcquisitionExecutorFailureCode,
)
from tests.unit.test_m4_evidence_authority import (
    _execution,
    _finalize,
    _frame,
    _pack,
)


def _ref(kind: ArtifactKind, artifact_id: str) -> ArtifactRef:
    return ArtifactRef(kind=kind, artifact_id=artifact_id)


def _specs() -> tuple[FakeAcquisitionToolSpec, ...]:
    specs = []
    for action in AcquisitionAction:
        reference = _execution(_pack(), action)
        manifest = reference.execution_manifest
        specs.append(
            FakeAcquisitionToolSpec(
                action=action,
                tool_id=manifest.tool_id,
                tool_revision=manifest.tool_revision,
                parameters_schema_sha256=acquisition_parameters_schema_sha256(action),
                component_manifest_id=manifest.component_manifest_id,
                model_manifest_id=manifest.model_manifest_id,
            )
        )
    return tuple(sorted(specs, key=lambda item: item.sort_key))


def _source_objects(
    execution: AcquisitionExecution,
) -> LoadedEvidenceObjects:
    if execution.request.action != AcquisitionAction.OTHER_CAMERA_SAME_TIME:
        return LoadedEvidenceObjects()
    parameters = execution.request.validated_parameters
    assert isinstance(parameters, OtherCameraSameTimeParameters)
    return LoadedEvidenceObjects(
        frames=(_frame(parameters.source_frame_id, "other-camera-source"),)
    )


def _fixture_execution(
    action: AcquisitionAction,
) -> tuple[
    EvidencePack,
    AcquisitionExecution,
    LoadedEvidenceObjects,
    tuple[FakeAcquisitionToolSpec, ...],
]:
    pack = _pack()
    reference = _execution(pack, action)
    loaded = _source_objects(reference)
    specs = _specs()
    spec = next(item for item in specs if item.action == action)
    outputs = reference.output_objects
    if action == AcquisitionAction.TRACK_CONFIDENCE_CURVE:
        request = reference.request
        manifest = ToolExecutionManifest(
            run_id=request.run_id,
            case_id=request.case_id,
            hearing_session_id=request.hearing_session_id,
            acquisition_request_id=request.request_id,
            action=action,
            tool_id=spec.tool_id,
            tool_revision=spec.tool_revision,
            parameters_schema_sha256=spec.parameters_schema_sha256,
            component_manifest_id=spec.component_manifest_id,
            manifest_id=request.manifest_id,
        )
        old_fact = outputs.objective_facts[0]
        output_refs = (_ref(ArtifactKind.OBJECTIVE_FACT, old_fact.fact_id),)
        input_refs = (_ref(ArtifactKind.EVIDENCE_PACK, request.current_evidence_pack_id),)
        result_id = derive_m4_tool_result_id(
            action,
            input_refs,
            output_refs,
            request.validated_parameters,
            manifest.execution_manifest_id,
        )
        outputs = LoadedEvidenceObjects(
            objective_facts=(
                ObjectiveFact(
                    fact_id=old_fact.fact_id,
                    kind=ObjectiveFactKind.DETECTION_SCORE,
                    value=old_fact.value,
                    source_ref=_ref(ArtifactKind.TOOL_RESULT, result_id),
                    source_manifest_id=manifest.execution_manifest_id,
                ),
            )
        )
    fixture = FakeAcquisitionFixture(
        request=reference.request,
        output_objects=outputs,
        crop_request=reference.crop_request,
    )
    executor = DeterministicFakeHearingAcquisitionExecutor(
        tool_specs=specs,
        fixtures=(fixture,),
    )
    authority = derive_evidence_authority(pack, loaded_objects=loaded)
    execution = executor.execute(
        reference.request,
        authority,
        idempotency_key=reference.request.request_id,
    )
    return pack, execution, loaded, specs


@pytest.mark.parametrize("action", tuple(AcquisitionAction))
def test_fake_executor_closes_all_five_actions_repeat_safely(
    action: AcquisitionAction,
) -> None:
    pack, execution, loaded, _specs_value = _fixture_execution(action)
    authority = derive_evidence_authority(pack, loaded_objects=loaded)
    executor = DeterministicFakeHearingAcquisitionExecutor(
        tool_specs=_specs(),
        fixtures=(
            FakeAcquisitionFixture(
                request=execution.request,
                output_objects=execution.output_objects,
                crop_request=execution.crop_request,
            ),
        ),
    )

    replay = executor.execute(
        execution.request,
        authority,
        idempotency_key=execution.request.request_id,
    )
    update = _finalize(pack, replay, loaded=loaded)

    assert replay == execution
    assert replay.execution_manifest.parameters_schema_sha256 == (
        acquisition_parameters_schema_sha256(action)
    )
    assert replay.tool_result.output_refs == replay.output_objects.refs
    assert update.pack.version == pack.version + 1
    assert update.receipt.tool_result == replay.tool_result


def test_missing_unavailable_and_wrong_pack_are_typed() -> None:
    pack = _pack()
    reference = _execution(pack, AcquisitionAction.REQUEST_MORE_FRAMES)
    authority = derive_evidence_authority(pack)
    missing = DeterministicFakeHearingAcquisitionExecutor(
        tool_specs=_specs(),
        fixtures=(),
    )
    with pytest.raises(HearingAcquisitionExecutorError) as missing_error:
        missing.execute(
            reference.request,
            authority,
            idempotency_key=reference.request.request_id,
        )
    assert missing_error.value.reason_code == HearingAcquisitionExecutorFailureCode.FIXTURE_MISSING

    unavailable = DeterministicFakeHearingAcquisitionExecutor(
        tool_specs=_specs(),
        fixtures=(
            FakeAcquisitionFixture(
                request=reference.request,
                failure_code=HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE,
            ),
        ),
    )
    with pytest.raises(HearingAcquisitionExecutorError) as unavailable_error:
        unavailable.execute(
            reference.request,
            authority,
            idempotency_key=reference.request.request_id,
        )
    assert (
        unavailable_error.value.reason_code
        == HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE
    )

    other_authority = derive_evidence_authority(_pack(crop_count=1))
    with pytest.raises(HearingAcquisitionExecutorError) as scope_error:
        unavailable.execute(
            reference.request,
            other_authority,
            idempotency_key=reference.request.request_id,
        )
    assert scope_error.value.reason_code == HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH


def test_invalid_physical_output_and_manifest_specs_fail_closed() -> None:
    pack = _pack()
    reference = _execution(pack, AcquisitionAction.REQUEST_MORE_FRAMES)
    frame = reference.output_objects.frames[0].model_copy(update={"content_sha256": None})
    executor = DeterministicFakeHearingAcquisitionExecutor(
        tool_specs=_specs(),
        fixtures=(
            FakeAcquisitionFixture(
                request=reference.request,
                output_objects=LoadedEvidenceObjects(frames=(frame,)),
            ),
        ),
    )

    with pytest.raises(HearingAcquisitionExecutorError) as output_error:
        executor.execute(
            reference.request,
            derive_evidence_authority(pack),
            idempotency_key=reference.request.request_id,
        )
    assert output_error.value.reason_code == HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID

    reference_manifest = reference.execution_manifest
    with pytest.raises(ValueError, match="manifest identity"):
        FakeAcquisitionToolSpec(
            action=AcquisitionAction.REQUEST_MORE_FRAMES,
            tool_id=reference_manifest.tool_id,
            tool_revision=reference_manifest.tool_revision,
            parameters_schema_sha256="0" * 64,
            component_manifest_id=reference_manifest.component_manifest_id,
        )


def test_fixture_provenance_cannot_be_detached_from_generated_result() -> None:
    pack = _pack()
    reference = _execution(pack, AcquisitionAction.TRACK_CONFIDENCE_CURVE)
    fact = reference.output_objects.objective_facts[0]
    detached = ObjectiveFact(
        fact_id=fact.fact_id,
        kind=fact.kind,
        value=fact.value,
        source_ref=_ref(ArtifactKind.TOOL_RESULT, "detached-tool-result"),
        source_manifest_id=reference.execution_manifest.execution_manifest_id,
    )
    executor = DeterministicFakeHearingAcquisitionExecutor(
        tool_specs=_specs(),
        fixtures=(
            FakeAcquisitionFixture(
                request=reference.request,
                output_objects=LoadedEvidenceObjects(objective_facts=(detached,)),
            ),
        ),
    )

    with pytest.raises(HearingAcquisitionExecutorError) as error:
        executor.execute(
            reference.request,
            derive_evidence_authority(pack),
            idempotency_key=reference.request.request_id,
        )
    assert error.value.reason_code == HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID

from __future__ import annotations

import pytest

from labcourt.adapters.acquisition_fake import (
    CONTROLLED_FAKE_ACQUISITION_COMPONENT,
    CONTROLLED_FAKE_ACQUISITION_COMPONENT_KEY,
    acquisition_parameters_schema_sha256,
    controlled_fake_acquisition_component_manifest_id,
)
from labcourt.contracts.enums import AcquisitionAction, ArtifactKind, ObjectiveFactKind
from labcourt.contracts.events import ObjectiveFact
from labcourt.contracts.hearing import (
    AcquisitionRequest,
    ToolExecutionManifest,
    derive_m4_tool_result_id,
)
from labcourt.contracts.m4_operations import (
    M4FakeAcquisitionFixtureInput,
    M4FakeVLMFixtureBundle,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.evidence_authority import (
    LoadedEvidenceObjects,
    derive_evidence_authority,
)
from labcourt.services.m4_operations import (
    M4OperationsBoundaryCode,
    M4OperationsBoundaryError,
    _fake_acquisition_executor,
)
from tests.unit.test_m4_acquisition_fake import _fixture_execution
from tests.unit.test_m4_hearing_acquisition import _manifest


def _tool_pinned_manifest():
    manifest = _manifest()
    return manifest.model_copy(
        update={
            "software_components": {
                **manifest.software_components,
                CONTROLLED_FAKE_ACQUISITION_COMPONENT_KEY: (CONTROLLED_FAKE_ACQUISITION_COMPONENT),
            }
        }
    )


def _controlled_outputs(
    action: AcquisitionAction,
    outputs: LoadedEvidenceObjects,
    request: AcquisitionRequest,
) -> LoadedEvidenceObjects:
    if action == AcquisitionAction.REDETECT_HIGH_RES:
        detector_manifest_id = _tool_pinned_manifest().models["detector"].model_manifest_id
        return LoadedEvidenceObjects(
            detections=tuple(
                detection.model_copy(update={"model_manifest_id": detector_manifest_id})
                for detection in outputs.detections
            )
        )
    if action != AcquisitionAction.TRACK_CONFIDENCE_CURVE:
        return outputs

    assert outputs.objective_facts
    manifest = ToolExecutionManifest(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        acquisition_request_id=request.request_id,
        action=action,
        tool_id="controlled-fake-track-confidence-curve",
        tool_revision="1.0.0",
        parameters_schema_sha256=acquisition_parameters_schema_sha256(action),
        component_manifest_id=controlled_fake_acquisition_component_manifest_id(),
        manifest_id=request.manifest_id,
    )
    original = outputs.objective_facts[0]
    input_refs = (
        ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id=request.current_evidence_pack_id,
        ),
    )
    output_refs = (ArtifactRef(kind=ArtifactKind.OBJECTIVE_FACT, artifact_id=original.fact_id),)
    result_id = derive_m4_tool_result_id(
        action,
        input_refs,
        output_refs,
        request.validated_parameters,
        manifest.execution_manifest_id,
    )
    return LoadedEvidenceObjects(
        objective_facts=(
            ObjectiveFact(
                fact_id=original.fact_id,
                kind=ObjectiveFactKind.DETECTION_SCORE,
                value=original.value,
                source_ref=ArtifactRef(
                    kind=ArtifactKind.TOOL_RESULT,
                    artifact_id=result_id,
                ),
                source_manifest_id=manifest.execution_manifest_id,
            ),
        )
    )


@pytest.mark.parametrize("action", tuple(AcquisitionAction))
def test_authored_acquisition_fixture_reaches_each_controlled_fake_tool(
    action: AcquisitionAction,
) -> None:
    pack, reference, loaded, _specs = _fixture_execution(action)
    outputs = _controlled_outputs(action, reference.output_objects, reference.request)
    authored = M4FakeAcquisitionFixtureInput(
        request=reference.request,
        frames=outputs.frames,
        crops=outputs.crops,
        objective_facts=outputs.objective_facts,
        detections=outputs.detections,
        crop_request=reference.crop_request,
    )
    bundle = M4FakeVLMFixtureBundle(
        schema_version="m4-fake-vlm-fixture-bundle-v1",
        fixtures=(),
        acquisition_fixtures=(authored,),
    )

    execution = _fake_acquisition_executor(_tool_pinned_manifest(), bundle).execute(
        reference.request,
        derive_evidence_authority(pack, loaded_objects=loaded),
        idempotency_key=reference.request.request_id,
    )

    assert bundle.acquisition_fixture_count == 1
    assert execution.request == reference.request
    assert execution.output_objects == outputs
    assert execution.crop_request == reference.crop_request
    assert execution.tool_result.output_refs == outputs.refs


def test_authored_acquisition_fixture_requires_pinned_run_component() -> None:
    _pack, reference, _loaded, _specs = _fixture_execution(AcquisitionAction.REQUEST_MORE_FRAMES)
    bundle = M4FakeVLMFixtureBundle(
        schema_version="m4-fake-vlm-fixture-bundle-v1",
        fixtures=(),
        acquisition_fixtures=(
            M4FakeAcquisitionFixtureInput(
                request=reference.request,
                frames=reference.output_objects.frames,
            ),
        ),
    )

    with pytest.raises(M4OperationsBoundaryError) as raised:
        _fake_acquisition_executor(_manifest(), bundle)

    assert raised.value.code == M4OperationsBoundaryCode.ACQUISITION_COMPONENT_UNPINNED

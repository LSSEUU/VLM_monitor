"""Deterministic, side-effect-free fixtures for all five M4 acquisition tools."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.acquisition_matrix import (
    AcquisitionSourceBinding,
    acquisition_tool_rule,
)
from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import (
    AcquisitionAction,
    AcquisitionExecutionMode,
    ArtifactKind,
)
from labcourt.contracts.evidence import (
    CropRequest,
    OtherCameraSameTimeParameters,
    RecropParameters,
    RedetectHighResolutionParameters,
    RequestMoreFramesParameters,
    ToolResult,
    TrackConfidenceCurveParameters,
)
from labcourt.contracts.hearing import (
    AcquisitionRequest,
    ToolExecutionManifest,
    derive_m4_tool_result_id,
)
from labcourt.contracts.manifests import SoftwareComponentManifest
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.evidence_authority import (
    AcquisitionExecution,
    EvidenceAuthority,
    EvidenceAuthorityError,
    LoadedEvidenceObjects,
    derive_evidence_authority,
    derive_evidence_pack_successor,
    derive_recrop_source_refs,
)
from labcourt.ports.hearing_acquisition import (
    HearingAcquisitionExecutorError,
    HearingAcquisitionExecutorFailureCode,
    HearingAcquisitionRecovery,
    HearingAcquisitionRecoveryStatus,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")

CONTROLLED_FAKE_ACQUISITION_COMPONENT_KEY = "m4-controlled-fake-acquisition"
CONTROLLED_FAKE_ACQUISITION_COMPONENT = SoftwareComponentManifest(
    component=CONTROLLED_FAKE_ACQUISITION_COMPONENT_KEY,
    package="labcourt",
    version="0.1.0",
    license_id="Proprietary",
)


def controlled_fake_acquisition_component_manifest_id() -> str:
    """Return the exact RunManifest software-component document digest."""

    document = canonical_json(CONTROLLED_FAKE_ACQUISITION_COMPONENT.model_dump(mode="json"))
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


_PARAMETER_MODEL: dict[AcquisitionAction, type[FrozenContractModel]] = {
    AcquisitionAction.REQUEST_MORE_FRAMES: RequestMoreFramesParameters,
    AcquisitionAction.RECROP: RecropParameters,
    AcquisitionAction.OTHER_CAMERA_SAME_TIME: OtherCameraSameTimeParameters,
    AcquisitionAction.TRACK_CONFIDENCE_CURVE: TrackConfidenceCurveParameters,
    AcquisitionAction.REDETECT_HIGH_RES: RedetectHighResolutionParameters,
}


def acquisition_parameters_schema_sha256(action: AcquisitionAction) -> str:
    """Return the implementation-independent schema identity for one action."""

    if not isinstance(action, AcquisitionAction):
        raise TypeError("action must be an AcquisitionAction")
    model = _PARAMETER_MODEL[action]
    return sha256_hex(
        [
            "m4-acquisition-parameters-schema",
            1,
            action.value,
            model.model_json_schema(mode="validation"),
        ]
    )


@dataclass(frozen=True, slots=True)
class FakeAcquisitionToolSpec:
    """Pinned implementation identity used to build an execution manifest."""

    action: AcquisitionAction
    tool_id: str
    tool_revision: str
    parameters_schema_sha256: str
    component_manifest_id: str
    model_manifest_id: str | None = None

    def __post_init__(self) -> None:
        try:
            require_reference_token(self.tool_id, "fake acquisition tool_id")
            require_reference_token(
                self.tool_revision,
                "fake acquisition tool_revision",
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("fake acquisition tool identity is invalid") from exc
        if (
            self.parameters_schema_sha256 != acquisition_parameters_schema_sha256(self.action)
            or _SHA256.fullmatch(self.component_manifest_id) is None
            or (
                self.model_manifest_id is not None
                and _SHA256.fullmatch(self.model_manifest_id) is None
            )
        ):
            raise ValueError("fake acquisition manifest identity is invalid")
        redetection = self.action == AcquisitionAction.REDETECT_HIGH_RES
        if redetection != (self.model_manifest_id is not None):
            raise ValueError("only fake redetection may bind a model manifest")

    @property
    def sort_key(self) -> str:
        return self.action.value


@dataclass(frozen=True, slots=True)
class FakeAcquisitionFixture:
    """Exact success output or explicit unavailability for one request."""

    request: AcquisitionRequest
    output_objects: LoadedEvidenceObjects | None = None
    crop_request: CropRequest | None = None
    failure_code: HearingAcquisitionExecutorFailureCode | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.request, AcquisitionRequest):
            raise TypeError("fake acquisition fixture requires an AcquisitionRequest")
        unavailable = self.failure_code is not None
        if unavailable:
            if (
                self.failure_code != HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE
                or self.output_objects is not None
                or self.crop_request is not None
            ):
                raise ValueError("failed fake acquisition fixture must be exactly TOOL_UNAVAILABLE")
            return
        if not isinstance(self.output_objects, LoadedEvidenceObjects):
            raise ValueError("successful fake acquisition fixture requires typed outputs")
        recrop = self.request.action == AcquisitionAction.RECROP
        if recrop != isinstance(self.crop_request, CropRequest):
            raise ValueError("only successful RECROP fixture requires a CropRequest")

    @property
    def sort_key(self) -> str:
        return self.request.request_id


class DeterministicFakeHearingAcquisitionExecutor:
    """Build and validate a pure execution closure without external side effects."""

    __slots__ = ("_fixtures", "_specs")

    def __init__(
        self,
        *,
        tool_specs: tuple[FakeAcquisitionToolSpec, ...],
        fixtures: tuple[FakeAcquisitionFixture, ...],
    ) -> None:
        if (
            not isinstance(tool_specs, tuple)
            or any(not isinstance(item, FakeAcquisitionToolSpec) for item in tool_specs)
            or tuple(item.sort_key for item in tool_specs)
            != tuple(sorted(item.sort_key for item in tool_specs))
            or len({item.action for item in tool_specs}) != len(tool_specs)
            or {item.action for item in tool_specs} != set(AcquisitionAction)
        ):
            raise ValueError("fake acquisition specs must cover every action once in stable order")
        if (
            not isinstance(fixtures, tuple)
            or any(not isinstance(item, FakeAcquisitionFixture) for item in fixtures)
            or tuple(item.sort_key for item in fixtures)
            != tuple(sorted(item.sort_key for item in fixtures))
            or len({item.request.request_id for item in fixtures}) != len(fixtures)
        ):
            raise ValueError("fake acquisition fixtures must use stable unique request order")
        self._specs = {item.action: item for item in tool_specs}
        self._fixtures = {item.request.request_id: item for item in fixtures}

    def __repr__(self) -> str:
        return f"DeterministicFakeHearingAcquisitionExecutor(fixture_count={len(self._fixtures)})"

    @property
    def execution_mode(self) -> AcquisitionExecutionMode:
        return AcquisitionExecutionMode.PURE

    def execute(
        self,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
        *,
        idempotency_key: str,
    ) -> AcquisitionExecution:
        request = self._require_request(request)
        authority = self._require_authority(authority)
        if idempotency_key != request.request_id:
            self._raise(HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT)
        if (
            request.run_id != authority.pack.run_id
            or request.case_id != authority.pack.case_id
            or request.current_evidence_pack_id != authority.pack.pack_id
            or request.current_evidence_pack_version != authority.pack.version
            or request.manifest_id != authority.pack.manifest_id
        ):
            self._raise(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)
        fixture = self._fixtures.get(request.request_id)
        if fixture is None:
            self._raise(HearingAcquisitionExecutorFailureCode.FIXTURE_MISSING)
        if fixture.request != request:
            self._raise(HearingAcquisitionExecutorFailureCode.FIXTURE_CONFLICT)
        if fixture.failure_code is not None:
            self._raise(fixture.failure_code)
        outputs = fixture.output_objects
        if outputs is None:  # pragma: no cover - fixture validation prevents this
            self._raise(HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID)

        spec = self._specs[request.action]
        try:
            manifest = ToolExecutionManifest(
                run_id=request.run_id,
                case_id=request.case_id,
                hearing_session_id=request.hearing_session_id,
                acquisition_request_id=request.request_id,
                action=request.action,
                tool_id=spec.tool_id,
                tool_revision=spec.tool_revision,
                parameters_schema_sha256=spec.parameters_schema_sha256,
                component_manifest_id=spec.component_manifest_id,
                model_manifest_id=spec.model_manifest_id,
                manifest_id=request.manifest_id,
            )
            input_refs = self._input_refs(request, authority, fixture)
            output_refs = outputs.refs
            result_id = derive_m4_tool_result_id(
                request.action,
                input_refs,
                output_refs,
                request.validated_parameters,
                manifest.execution_manifest_id,
            )
            result = ToolResult(
                tool_result_id=result_id,
                action=request.action,
                input_refs=input_refs,
                output_refs=output_refs,
                validated_parameters=request.validated_parameters,
                execution_manifest_id=manifest.execution_manifest_id,
            )
            execution = AcquisitionExecution(
                request=request,
                execution_manifest=manifest,
                tool_result=result,
                output_objects=outputs,
                crop_request=fixture.crop_request,
            )
            # Rebuild the successor draft as a pure validation pass.  Returning
            # the execution still leaves publication and side effects solely to
            # the coordinator/repository transaction.
            derive_evidence_pack_successor(
                authority.pack,
                execution,
                current_receipts=authority.receipts,
                current_loaded_objects=authority.loaded_objects,
            )
        except HearingAcquisitionExecutorError:
            raise
        except (
            EvidenceAuthorityError,
            TypeError,
            ValueError,
            ValidationError,
        ):
            self._raise(HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID)
        return execution

    def recover(
        self,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
        *,
        idempotency_key: str,
    ) -> HearingAcquisitionRecovery:
        self._require_request(request)
        self._require_authority(authority)
        if idempotency_key != request.request_id:
            self._raise(HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT)
        return HearingAcquisitionRecovery(status=HearingAcquisitionRecoveryStatus.UNKNOWN)

    @staticmethod
    def _input_refs(
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
        fixture: FakeAcquisitionFixture,
    ) -> tuple[ArtifactRef, ...]:
        refs = {
            ArtifactRef(
                kind=ArtifactKind.EVIDENCE_PACK,
                artifact_id=request.current_evidence_pack_id,
            )
        }
        parameters = request.validated_parameters
        source_binding = acquisition_tool_rule(request.action).source_binding
        if source_binding == AcquisitionSourceBinding.RECROP_DERIVED_SOURCES:
            if not isinstance(parameters, RecropParameters):
                DeterministicFakeHearingAcquisitionExecutor._raise(
                    HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID
                )
            expected_sources = derive_recrop_source_refs(authority, parameters)
            crop_request = fixture.crop_request
            if crop_request is None or crop_request.source_refs != expected_sources:
                DeterministicFakeHearingAcquisitionExecutor._raise(
                    HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID
                )
            refs.update(expected_sources)
        elif source_binding == AcquisitionSourceBinding.SOURCE_FRAME:
            if not isinstance(parameters, OtherCameraSameTimeParameters):
                DeterministicFakeHearingAcquisitionExecutor._raise(
                    HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID
                )
            refs.add(
                ArtifactRef(
                    kind=ArtifactKind.FRAME,
                    artifact_id=parameters.source_frame_id,
                )
            )
        elif source_binding == AcquisitionSourceBinding.SOURCE_CROP:
            if not isinstance(parameters, RedetectHighResolutionParameters):
                DeterministicFakeHearingAcquisitionExecutor._raise(
                    HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID
                )
            refs.add(
                ArtifactRef(
                    kind=ArtifactKind.CROP,
                    artifact_id=parameters.crop_id,
                )
            )
        return tuple(sorted(refs, key=lambda ref: ref.sort_key))

    @staticmethod
    def _require_request(request: object) -> AcquisitionRequest:
        if type(request) is not AcquisitionRequest:
            DeterministicFakeHearingAcquisitionExecutor._raise(
                HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT
            )
        typed = request
        try:
            validated = AcquisitionRequest.model_validate(typed.model_dump(mode="json"))
        except (TypeError, ValueError, ValidationError):
            DeterministicFakeHearingAcquisitionExecutor._raise(
                HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT
            )
        if validated != typed:
            DeterministicFakeHearingAcquisitionExecutor._raise(
                HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT
            )
        return validated

    @staticmethod
    def _require_authority(authority: object) -> EvidenceAuthority:
        if not isinstance(authority, EvidenceAuthority):
            DeterministicFakeHearingAcquisitionExecutor._raise(
                HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT
            )
        try:
            rebuilt = derive_evidence_authority(
                authority.pack,
                authority.receipts,
                authority.loaded_objects,
            )
        except EvidenceAuthorityError:
            DeterministicFakeHearingAcquisitionExecutor._raise(
                HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH
            )
        if rebuilt != authority:
            DeterministicFakeHearingAcquisitionExecutor._raise(
                HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH
            )
        return authority

    @staticmethod
    def _raise(reason: HearingAcquisitionExecutorFailureCode) -> NoReturn:
        raise HearingAcquisitionExecutorError(reason)


__all__ = [
    "CONTROLLED_FAKE_ACQUISITION_COMPONENT",
    "CONTROLLED_FAKE_ACQUISITION_COMPONENT_KEY",
    "DeterministicFakeHearingAcquisitionExecutor",
    "FakeAcquisitionFixture",
    "FakeAcquisitionToolSpec",
    "acquisition_parameters_schema_sha256",
    "controlled_fake_acquisition_component_manifest_id",
]

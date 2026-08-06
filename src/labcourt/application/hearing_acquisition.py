"""Execute and publish one authority-bound M4 evidence acquisition.

The model-facing Judge output is intentionally absent here.  This service only
accepts the already-derived :class:`AcquisitionRequest`, revalidates the current
Case/evidence/manifest authorities, checks the executor result before mutation,
and then verifies the repository's atomic successor publication.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from labcourt.contracts.cases import Case
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import AcquisitionExecutionMode, CaseStatus
from labcourt.contracts.events import ObjectiveFact
from labcourt.contracts.evidence import (
    Crop,
    CropRequest,
    EvidencePackDraft,
    OtherCameraSameTimeParameters,
    RecropParameters,
    RequestMoreFramesParameters,
    ToolResult,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.hearing import (
    AcquisitionExecutionPublication,
    AcquisitionRequest,
    ToolExecutionManifest,
)
from labcourt.contracts.manifests import RunManifest, StreamManifest
from labcourt.contracts.references import parse_frame_id
from labcourt.domain.evidence_authority import (
    AcquisitionExecution,
    EvidenceAuthority,
    EvidenceAuthorityError,
    LoadedEvidenceObjects,
    derive_evidence_authority,
    derive_evidence_pack_successor,
    merge_loaded_evidence_objects,
    validate_evidence_pack_successor,
)
from labcourt.exceptions import ConcurrentModification, ContractViolation, LabCourtError
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot
from labcourt.ports.hearing_acquisition import (
    HearingAcquisitionDeliveryCertainty,
    HearingAcquisitionExecutor,
    HearingAcquisitionExecutorError,
    HearingAcquisitionExecutorFailureCode,
    HearingAcquisitionRecovery,
    HearingAcquisitionRecoveryStatus,
)
from labcourt.ports.hearing_repository import (
    AcquisitionExecutionClaim,
    AcquisitionExecutionClaimStatus,
    AcquisitionPublishResult,
    HearingPersistenceConflict,
    HearingRepository,
)


class HearingAcquisitionFailureCode(StrEnum):
    """Stable, non-sensitive failure classes for coordinator routing."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    CASE_AUTHORITY_MISMATCH = "CASE_AUTHORITY_MISMATCH"
    EVIDENCE_AUTHORITY_MISMATCH = "EVIDENCE_AUTHORITY_MISMATCH"
    MANIFEST_AUTHORITY_MISMATCH = "MANIFEST_AUTHORITY_MISMATCH"
    STREAM_AUTHORITY_MISMATCH = "STREAM_AUTHORITY_MISMATCH"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    EXECUTION_IN_PROGRESS = "EXECUTION_IN_PROGRESS"
    EXECUTION_UNRECOVERABLE = "EXECUTION_UNRECOVERABLE"
    EXECUTOR_CONTRACT_VIOLATION = "EXECUTOR_CONTRACT_VIOLATION"
    PERSISTENCE_CONFLICT = "PERSISTENCE_CONFLICT"
    PERSISTENCE_REJECTED = "PERSISTENCE_REJECTED"
    PERSISTED_SUCCESSOR_INVALID = "PERSISTED_SUCCESSOR_INVALID"


class HearingAcquisitionError(ContractViolation):
    """One bounded acquisition did not reach a verified atomic successor."""

    def __init__(
        self,
        reason_code: HearingAcquisitionFailureCode,
        *,
        request_id: str,
        executor_reason_code: HearingAcquisitionExecutorFailureCode | None = None,
    ) -> None:
        if not isinstance(reason_code, HearingAcquisitionFailureCode):
            raise TypeError("reason_code must be a HearingAcquisitionFailureCode")
        if not isinstance(request_id, str):
            raise TypeError("request_id must be a string")
        if (reason_code == HearingAcquisitionFailureCode.EXECUTION_FAILED) != (
            executor_reason_code is not None
        ):
            raise TypeError("executor reason is required only for execution failures")
        self.reason_code = reason_code
        self.request_id = request_id
        self.executor_reason_code = executor_reason_code
        super().__init__(f"hearing acquisition failed: {reason_code.value}")


def _fail(
    code: HearingAcquisitionFailureCode,
    request: AcquisitionRequest | None,
    *,
    executor_code: HearingAcquisitionExecutorFailureCode | None = None,
) -> NoReturn:
    raise HearingAcquisitionError(
        code,
        request_id=request.request_id if request is not None else "",
        executor_reason_code=executor_code,
    )


@dataclass(frozen=True, slots=True)
class HearingAcquisitionContext:
    """Immutable authorities used for one dual-CAS acquisition publication."""

    case: CaseSnapshot
    audit_head: AuditHead
    request: AcquisitionRequest
    evidence: EvidenceAuthority
    run_manifest: RunManifest

    def __post_init__(self) -> None:
        expected = (
            (self.case, CaseSnapshot, "case"),
            (self.audit_head, AuditHead, "audit_head"),
            (self.request, AcquisitionRequest, "request"),
            (self.evidence, EvidenceAuthority, "evidence"),
            (self.run_manifest, RunManifest, "run_manifest"),
        )
        for value, expected_type, name in expected:
            if not isinstance(value, expected_type):
                raise TypeError(f"{name} has the wrong contract type")


@dataclass(frozen=True, slots=True)
class HearingAcquisitionResult:
    """Verified execution, atomic publication, and rebuilt evidence authority."""

    execution: AcquisitionExecution
    publication: AcquisitionPublishResult
    authority: EvidenceAuthority

    def __post_init__(self) -> None:
        if not isinstance(self.execution, AcquisitionExecution):
            raise TypeError("execution must be an AcquisitionExecution")
        if not isinstance(self.publication, AcquisitionPublishResult):
            raise TypeError("publication must be an AcquisitionPublishResult")
        if not isinstance(self.authority, EvidenceAuthority):
            raise TypeError("authority must be an EvidenceAuthority")


def _revalidate_model(value: object, model_type: type[object]) -> object:
    if not isinstance(value, model_type):
        raise TypeError("executor returned an object of the wrong type")
    model_dump = getattr(value, "model_dump", None)
    model_validate = getattr(model_type, "model_validate", None)
    if not callable(model_dump) or not callable(model_validate):
        raise TypeError("executor returned a non-contract object")
    return model_validate(model_dump(mode="json"))


def _revalidate_execution(
    returned: object,
    request: AcquisitionRequest,
) -> AcquisitionExecution:
    if not isinstance(returned, AcquisitionExecution):
        raise TypeError("executor must return AcquisitionExecution")
    manifest = _revalidate_model(returned.execution_manifest, ToolExecutionManifest)
    result = _revalidate_model(returned.tool_result, ToolResult)
    frames = tuple(_revalidate_model(item, FrameRef) for item in returned.output_objects.frames)
    crops = tuple(_revalidate_model(item, Crop) for item in returned.output_objects.crops)
    facts = tuple(
        _revalidate_model(item, ObjectiveFact) for item in returned.output_objects.objective_facts
    )
    detections = tuple(
        _revalidate_model(item, Detection) for item in returned.output_objects.detections
    )
    crop_request = (
        _revalidate_model(returned.crop_request, CropRequest)
        if returned.crop_request is not None
        else None
    )
    assert isinstance(manifest, ToolExecutionManifest)
    assert isinstance(result, ToolResult)
    assert crop_request is None or isinstance(crop_request, CropRequest)
    execution = AcquisitionExecution(
        request=request,
        execution_manifest=manifest,
        tool_result=result,
        output_objects=LoadedEvidenceObjects(
            frames=tuple(item for item in frames if isinstance(item, FrameRef)),
            crops=tuple(item for item in crops if isinstance(item, Crop)),
            objective_facts=tuple(item for item in facts if isinstance(item, ObjectiveFact)),
            detections=tuple(item for item in detections if isinstance(item, Detection)),
        ),
        crop_request=crop_request,
    )
    if returned.request != request or execution != returned:
        raise ValueError("executor result changed during strict revalidation")
    return execution


def _stream_map(manifest: RunManifest) -> dict[tuple[str, str], StreamManifest]:
    return {(stream.camera_id, stream.stream_id): stream for stream in manifest.streams}


def _require_frame_in_manifest(
    frame: FrameRef,
    streams: dict[tuple[str, str], StreamManifest],
) -> None:
    stream = streams.get((frame.camera_id, frame.stream_id))
    if stream is None or not 0 <= frame.frame_index < stream.frame_count:
        raise ValueError("frame is outside the immutable stream manifest")
    if (
        frame.fps_num != stream.fps_num
        or frame.fps_den != stream.fps_den
        or frame.width != stream.width
        or frame.height != stream.height
    ):
        raise ValueError("frame metadata conflicts with the immutable stream manifest")


def _require_frame_id_in_manifest(
    frame_id: str,
    streams: dict[tuple[str, str], StreamManifest],
) -> None:
    camera_id, stream_id, frame_index = parse_frame_id(frame_id)
    stream = streams.get((camera_id, stream_id))
    if stream is None or not 0 <= frame_index < stream.frame_count:
        raise ValueError("frame identity is outside the immutable stream manifest")


def _validate_stream_authority(
    request: AcquisitionRequest,
    execution: AcquisitionExecution | None,
    manifest: RunManifest,
) -> None:
    streams = _stream_map(manifest)
    parameters = request.validated_parameters
    if isinstance(parameters, RequestMoreFramesParameters):
        stream = streams.get((parameters.camera_id, parameters.stream_id))
        if stream is None or parameters.end_frame_exclusive > stream.frame_count:
            raise ValueError("requested interval is outside the immutable stream manifest")
    elif isinstance(parameters, OtherCameraSameTimeParameters):
        _require_frame_id_in_manifest(parameters.source_frame_id, streams)
        if not any(stream.camera_id == parameters.target_camera_id for stream in manifest.streams):
            raise ValueError("target camera is outside the immutable stream manifest")
    elif isinstance(parameters, RecropParameters):
        _require_frame_id_in_manifest(parameters.frame_id, streams)

    if execution is not None:
        for frame in execution.output_objects.frames:
            _require_frame_in_manifest(frame, streams)
        if isinstance(parameters, OtherCameraSameTimeParameters) and any(
            frame.camera_id != parameters.target_camera_id
            for frame in execution.output_objects.frames
        ):
            raise ValueError("other-camera output left its target camera")


def _default_acquisition_owner_token() -> str:
    return secrets.token_urlsafe(48)


class HearingAcquisitionService:
    """Execute once and verify the repository's dual-CAS evidence successor."""

    def __init__(
        self,
        *,
        repository: HearingRepository,
        executor: HearingAcquisitionExecutor,
        owner_token_factory: Callable[[], str] = _default_acquisition_owner_token,
    ) -> None:
        repository_methods = (
            "claim_acquisition_execution",
            "claim_acquisition_recovery",
            "complete_acquisition_execution",
            "abandon_acquisition_execution",
            "load_acquisition_execution",
            "persist_acquisition_successor",
        )
        if any(not callable(getattr(repository, method, None)) for method in repository_methods):
            raise TypeError("repository does not implement acquisition execution authority")
        if not callable(getattr(executor, "execute", None)) or not callable(
            getattr(executor, "recover", None)
        ):
            raise TypeError("executor must implement execute and recover")
        if not isinstance(getattr(executor, "execution_mode", None), AcquisitionExecutionMode):
            raise TypeError("executor must declare an AcquisitionExecutionMode")
        if not callable(owner_token_factory):
            raise TypeError("owner_token_factory must be callable")
        self._repository = repository
        self._executor = executor
        self._owner_token_factory = owner_token_factory

    def execute(self, context: HearingAcquisitionContext) -> HearingAcquisitionResult:
        """Run one exact acquisition and return only a verified successor."""

        if not isinstance(context, HearingAcquisitionContext):
            _fail(HearingAcquisitionFailureCode.INVALID_ARGUMENT, None)
        request = context.request
        self._validate_context(context)
        try:
            _validate_stream_authority(request, None, context.run_manifest)
        except (TypeError, ValueError):
            _fail(HearingAcquisitionFailureCode.STREAM_AUTHORITY_MISMATCH, request)

        try:
            durable = self._repository.load_acquisition_execution(
                request.run_id, request.request_id
            )
        except (ConcurrentModification, HearingPersistenceConflict):
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_CONFLICT, request)
        except LabCourtError:
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_REJECTED, request)
        if durable is None:
            owner_token = self._new_owner_token(request)
            try:
                claim = self._repository.claim_acquisition_execution(
                    request.run_id,
                    request,
                    self._executor.execution_mode,
                    owner_token,
                )
            except (ConcurrentModification, HearingPersistenceConflict):
                _fail(HearingAcquisitionFailureCode.PERSISTENCE_CONFLICT, request)
            except LabCourtError:
                _fail(HearingAcquisitionFailureCode.PERSISTENCE_REJECTED, request)
            durable = self._resolve_claim(context, claim, owner_token)

        try:
            execution = self._execution_from_publication(durable, request)
            _validate_stream_authority(request, execution, context.run_manifest)
            draft = derive_evidence_pack_successor(
                context.evidence.pack,
                execution,
                current_receipts=context.evidence.receipts,
                current_loaded_objects=context.evidence.loaded_objects,
            )
        except (TypeError, ValueError, EvidenceAuthorityError):
            _fail(HearingAcquisitionFailureCode.EXECUTOR_CONTRACT_VIOLATION, request)
        try:
            publication = self._repository.persist_acquisition_successor(
                request.run_id,
                context.case.revision,
                context.audit_head,
                request,
                durable,
            )
        except (ConcurrentModification, HearingPersistenceConflict):
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_CONFLICT, request)
        except LabCourtError:
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_REJECTED, request)

        try:
            publication, authority = self._validate_publication(
                context,
                execution,
                draft,
                publication,
            )
        except (TypeError, ValueError, EvidenceAuthorityError):
            _fail(HearingAcquisitionFailureCode.PERSISTED_SUCCESSOR_INVALID, request)
        return HearingAcquisitionResult(
            execution=execution,
            publication=publication,
            authority=authority,
        )

    def _resolve_claim(
        self,
        context: HearingAcquisitionContext,
        claim: AcquisitionExecutionClaim,
        owner_token: str,
    ) -> AcquisitionExecutionPublication:
        request = context.request
        if not isinstance(claim, AcquisitionExecutionClaim) or (
            claim.request_id != request.request_id
            or claim.execution_mode != self._executor.execution_mode
            or claim.idempotency_key != request.request_id
        ):
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_REJECTED, request)
        if claim.status == AcquisitionExecutionClaimStatus.COMPLETED:
            return self._require_durable_publication(request)
        if claim.status == AcquisitionExecutionClaimStatus.WAITING:
            _fail(HearingAcquisitionFailureCode.EXECUTION_IN_PROGRESS, request)
        if claim.status == AcquisitionExecutionClaimStatus.ABANDONED:
            _fail(HearingAcquisitionFailureCode.EXECUTION_UNRECOVERABLE, request)
        if claim.status == AcquisitionExecutionClaimStatus.EXPIRED_REQUIRES_RECOVERY:
            return self._recover_expired_execution(context, claim, owner_token)
        if claim.status != AcquisitionExecutionClaimStatus.ACQUIRED:
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_REJECTED, request)
        return self._execute_and_publish(context, claim, owner_token)

    def _recover_expired_execution(
        self,
        context: HearingAcquisitionContext,
        expired: AcquisitionExecutionClaim,
        owner_token: str,
    ) -> AcquisitionExecutionPublication:
        request = context.request
        try:
            recovery = self._executor.recover(
                request,
                context.evidence,
                idempotency_key=request.request_id,
            )
        except HearingAcquisitionExecutorError:
            raced = self._abandon_or_replay(request, expired, owner_token)
            if raced is not None:
                return raced
            _fail(HearingAcquisitionFailureCode.EXECUTION_UNRECOVERABLE, request)
        if not isinstance(recovery, HearingAcquisitionRecovery):
            raced = self._abandon_or_replay(request, expired, owner_token)
            if raced is not None:
                return raced
            _fail(HearingAcquisitionFailureCode.EXECUTION_UNRECOVERABLE, request)
        if recovery.status == HearingAcquisitionRecoveryStatus.UNKNOWN:
            raced = self._abandon_or_replay(request, expired, owner_token)
            if raced is not None:
                return raced
            _fail(HearingAcquisitionFailureCode.EXECUTION_UNRECOVERABLE, request)

        try:
            claim = self._repository.claim_acquisition_recovery(
                request.run_id,
                request,
                expired.owner_fence,
                owner_token,
            )
        except (ConcurrentModification, HearingPersistenceConflict):
            durable = self._repository.load_acquisition_execution(
                request.run_id, request.request_id
            )
            if durable is not None:
                return durable
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_CONFLICT, request)
        except LabCourtError:
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_REJECTED, request)
        if claim.status == AcquisitionExecutionClaimStatus.COMPLETED:
            return self._require_durable_publication(request)
        if claim.status == AcquisitionExecutionClaimStatus.WAITING:
            _fail(HearingAcquisitionFailureCode.EXECUTION_IN_PROGRESS, request)
        if claim.status == AcquisitionExecutionClaimStatus.ABANDONED:
            _fail(HearingAcquisitionFailureCode.EXECUTION_UNRECOVERABLE, request)
        if claim.status != AcquisitionExecutionClaimStatus.ACQUIRED:
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_CONFLICT, request)
        returned = (
            recovery.execution
            if recovery.status == HearingAcquisitionRecoveryStatus.COMPLETED
            else None
        )
        return self._execute_and_publish(
            context,
            claim,
            owner_token,
            recovered_execution=returned,
        )

    def _execute_and_publish(
        self,
        context: HearingAcquisitionContext,
        claim: AcquisitionExecutionClaim,
        owner_token: str,
        *,
        recovered_execution: AcquisitionExecution | None = None,
    ) -> AcquisitionExecutionPublication:
        request = context.request
        try:
            returned = recovered_execution or self._executor.execute(
                request,
                context.evidence,
                idempotency_key=request.request_id,
            )
        except HearingAcquisitionExecutorError as exc:
            if (
                self._executor.execution_mode == AcquisitionExecutionMode.IDEMPOTENT_EXTERNAL
                and exc.delivery_certainty == HearingAcquisitionDeliveryCertainty.COMPLETED
            ):
                try:
                    recovered = self._executor.recover(
                        request,
                        context.evidence,
                        idempotency_key=request.request_id,
                    )
                except HearingAcquisitionExecutorError:
                    recovered = HearingAcquisitionRecovery(
                        status=HearingAcquisitionRecoveryStatus.UNKNOWN
                    )
                if (
                    isinstance(recovered, HearingAcquisitionRecovery)
                    and recovered.status == HearingAcquisitionRecoveryStatus.COMPLETED
                    and recovered.execution is not None
                ):
                    returned = recovered.execution
                else:
                    raced = self._abandon_or_replay(request, claim, owner_token)
                    if raced is not None:
                        return raced
                    _fail(HearingAcquisitionFailureCode.EXECUTION_UNRECOVERABLE, request)
            else:
                raced = self._abandon_or_replay(request, claim, owner_token)
                if raced is not None:
                    return raced
                if (
                    self._executor.execution_mode == AcquisitionExecutionMode.IDEMPOTENT_EXTERNAL
                    and exc.delivery_certainty == HearingAcquisitionDeliveryCertainty.UNKNOWN
                ):
                    _fail(
                        HearingAcquisitionFailureCode.EXECUTION_UNRECOVERABLE,
                        request,
                    )
                _fail(
                    HearingAcquisitionFailureCode.EXECUTION_FAILED,
                    request,
                    executor_code=exc.reason_code,
                )
        try:
            execution = _revalidate_execution(returned, request)
            _validate_stream_authority(request, execution, context.run_manifest)
            derive_evidence_pack_successor(
                context.evidence.pack,
                execution,
                current_receipts=context.evidence.receipts,
                current_loaded_objects=context.evidence.loaded_objects,
            )
            durable = AcquisitionExecutionPublication(
                request=request,
                execution_manifest=execution.execution_manifest,
                tool_result=execution.tool_result,
                frames=execution.output_objects.frames,
                crops=execution.output_objects.crops,
                objective_facts=execution.output_objects.objective_facts,
                detections=execution.output_objects.detections,
                crop_request=execution.crop_request,
                execution_mode=claim.execution_mode,
                idempotency_key=request.request_id,
                claim_owner_sha256=hashlib.sha256(owner_token.encode("utf-8")).hexdigest(),
                claim_fence=claim.owner_fence,
            )
        except (TypeError, ValueError, EvidenceAuthorityError):
            raced = self._abandon_or_replay(request, claim, owner_token)
            if raced is not None:
                return raced
            _fail(HearingAcquisitionFailureCode.EXECUTOR_CONTRACT_VIOLATION, request)
        try:
            committed = self._repository.complete_acquisition_execution(
                request.run_id,
                durable,
                owner_token,
            )
        except (ConcurrentModification, HearingPersistenceConflict):
            replay = self._repository.load_acquisition_execution(request.run_id, request.request_id)
            if replay is not None:
                return replay
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_CONFLICT, request)
        except LabCourtError:
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_REJECTED, request)
        if committed.publication != durable:
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_REJECTED, request)
        return committed.publication

    def _abandon_or_replay(
        self,
        request: AcquisitionRequest,
        claim: AcquisitionExecutionClaim,
        owner_token: str,
    ) -> AcquisitionExecutionPublication | None:
        try:
            abandoned = self._repository.abandon_acquisition_execution(
                request.run_id,
                request,
                claim.owner_fence,
                owner_token,
            )
        except (ConcurrentModification, HearingPersistenceConflict):
            return self._repository.load_acquisition_execution(request.run_id, request.request_id)
        except LabCourtError:
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_REJECTED, request)
        if abandoned.status == AcquisitionExecutionClaimStatus.COMPLETED:
            return self._require_durable_publication(request)
        if abandoned.status != AcquisitionExecutionClaimStatus.ABANDONED:
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_CONFLICT, request)
        return None

    def _require_durable_publication(
        self,
        request: AcquisitionRequest,
    ) -> AcquisitionExecutionPublication:
        try:
            publication = self._repository.load_acquisition_execution(
                request.run_id, request.request_id
            )
        except (ConcurrentModification, HearingPersistenceConflict):
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_CONFLICT, request)
        except LabCourtError:
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_REJECTED, request)
        if publication is None or publication.request != request:
            _fail(HearingAcquisitionFailureCode.PERSISTENCE_REJECTED, request)
        return publication

    def _new_owner_token(self, request: AcquisitionRequest) -> str:
        try:
            token = self._owner_token_factory()
        except Exception as exc:
            raise HearingAcquisitionError(
                HearingAcquisitionFailureCode.INVALID_ARGUMENT,
                request_id=request.request_id,
            ) from exc
        if not isinstance(token, str) or not 32 <= len(token) <= 512:
            _fail(HearingAcquisitionFailureCode.INVALID_ARGUMENT, request)
        return token

    @staticmethod
    def _execution_from_publication(
        publication: AcquisitionExecutionPublication,
        request: AcquisitionRequest,
    ) -> AcquisitionExecution:
        if not isinstance(publication, AcquisitionExecutionPublication):
            raise TypeError("repository returned the wrong execution publication")
        return _revalidate_execution(
            AcquisitionExecution(
                request=publication.request,
                execution_manifest=publication.execution_manifest,
                tool_result=publication.tool_result,
                output_objects=LoadedEvidenceObjects(
                    frames=publication.frames,
                    crops=publication.crops,
                    objective_facts=publication.objective_facts,
                    detections=publication.detections,
                ),
                crop_request=publication.crop_request,
            ),
            request,
        )

    @staticmethod
    def _validate_context(context: HearingAcquisitionContext) -> None:
        request = context.request
        case = context.case.case
        evidence = context.evidence
        manifest = context.run_manifest
        try:
            validated_request = AcquisitionRequest.model_validate(request.model_dump(mode="json"))
            validated_case = Case.model_validate(case.model_dump(mode="json"))
            rebuilt = derive_evidence_authority(
                evidence.pack,
                evidence.receipts,
                evidence.loaded_objects,
            )
        except (TypeError, ValueError, EvidenceAuthorityError):
            _fail(HearingAcquisitionFailureCode.INVALID_ARGUMENT, request)
        if validated_request != request or validated_case != case or context.case.revision < 0:
            _fail(HearingAcquisitionFailureCode.INVALID_ARGUMENT, request)
        if rebuilt != evidence:
            _fail(HearingAcquisitionFailureCode.EVIDENCE_AUTHORITY_MISMATCH, request)
        if (
            case.run_id != request.run_id
            or case.case_id != request.case_id
            or case.status != CaseStatus.DELIBERATING
            or not case.evidence_packs
            or case.evidence_packs[-1] != evidence.pack
            or request.current_evidence_pack_id != evidence.pack.pack_id
            or request.current_evidence_pack_version != evidence.pack.version
            or not evidence.pack.complete
        ):
            _fail(HearingAcquisitionFailureCode.CASE_AUTHORITY_MISMATCH, request)
        head = context.audit_head
        if (
            manifest.manifest_id != request.manifest_id
            or case.manifest_id != request.manifest_id
            or evidence.pack.manifest_id != request.manifest_id
            or head.run_id != request.run_id
            or head.manifest_id != request.manifest_id
            or head.run_revision < 0
            or head.sequence < 0
        ):
            _fail(HearingAcquisitionFailureCode.MANIFEST_AUTHORITY_MISMATCH, request)

    @staticmethod
    def _validate_publication(
        context: HearingAcquisitionContext,
        execution: AcquisitionExecution,
        draft: EvidencePackDraft,
        publication: object,
    ) -> tuple[AcquisitionPublishResult, EvidenceAuthority]:
        if not isinstance(publication, AcquisitionPublishResult):
            raise TypeError("repository returned the wrong publication type")
        pack_type = type(context.evidence.pack)
        pack = pack_type.model_validate(publication.pack.model_dump(mode="json"))
        receipt_type = type(publication.receipt)
        receipt = receipt_type.model_validate(publication.receipt.model_dump(mode="json"))
        case = Case.model_validate(publication.case.case.model_dump(mode="json"))
        validated = AcquisitionPublishResult(
            case=CaseSnapshot(case=case, revision=publication.case.revision),
            pack=pack,
            receipt=receipt,
            created=publication.created,
        )
        if validated != publication or not isinstance(publication.created, bool):
            raise ValueError("publication changed during strict revalidation")
        draft_dump = draft.model_dump(mode="json")
        pack_dump = pack.model_dump(mode="json", exclude={"closure_report"})
        if draft_dump != pack_dump:
            raise ValueError("repository published a pack different from the derived draft")
        merged = merge_loaded_evidence_objects(
            context.evidence.loaded_objects,
            execution.output_objects,
        )
        authority = validate_evidence_pack_successor(
            context.evidence.pack,
            pack,
            receipt,
            current_receipts=context.evidence.receipts,
            loaded_objects=merged,
        )
        before = context.case.case
        after = validated.case.case
        if (
            validated.case.revision != context.case.revision + 1
            or after.run_id != before.run_id
            or after.case_id != before.case_id
            or after.manifest_id != before.manifest_id
            or after.status != CaseStatus.DELIBERATING
            or after.evidence_packs != (*before.evidence_packs, pack)
            or receipt.request != context.request
            or receipt.execution_manifest != execution.execution_manifest
            or receipt.tool_result != execution.tool_result
        ):
            raise ValueError("publication does not close the exact Case successor")
        return validated, authority


__all__ = [
    "HearingAcquisitionContext",
    "HearingAcquisitionError",
    "HearingAcquisitionFailureCode",
    "HearingAcquisitionResult",
    "HearingAcquisitionService",
]

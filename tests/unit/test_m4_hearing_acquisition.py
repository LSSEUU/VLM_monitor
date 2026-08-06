from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from labcourt.application.hearing_acquisition import (
    HearingAcquisitionContext,
    HearingAcquisitionError,
    HearingAcquisitionFailureCode,
    HearingAcquisitionService,
)
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    AcquisitionAction,
    AcquisitionExecutionMode,
    CaseStatus,
)
from labcourt.contracts.hearing import AcquisitionExecutionPublication
from labcourt.contracts.manifests import RunManifest
from labcourt.domain.evidence_authority import (
    AcquisitionExecution,
    EvidenceAuthority,
    LoadedEvidenceObjects,
    derive_evidence_authority,
)
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot
from labcourt.ports.hearing_acquisition import (
    HearingAcquisitionDeliveryCertainty,
    HearingAcquisitionExecutorError,
    HearingAcquisitionExecutorFailureCode,
    HearingAcquisitionRecovery,
    HearingAcquisitionRecoveryStatus,
)
from labcourt.ports.hearing_repository import (
    AcquisitionExecutionClaim,
    AcquisitionExecutionClaimStatus,
    AcquisitionExecutionCommit,
    AcquisitionPublishResult,
)
from tests.unit.test_m4_acquisition_fake import _fixture_execution
from tests.unit.test_m4_evidence_authority import _execution, _finalize, _pack

FIXTURES = Path(__file__).parents[1] / "fixtures" / "m2"


class _Executor:
    def __init__(
        self,
        execution: AcquisitionExecution | None = None,
        failure: HearingAcquisitionExecutorFailureCode | None = None,
        *,
        execution_mode: AcquisitionExecutionMode = AcquisitionExecutionMode.PURE,
        delivery_certainty: HearingAcquisitionDeliveryCertainty = (
            HearingAcquisitionDeliveryCertainty.UNKNOWN
        ),
    ) -> None:
        self.execution = execution
        self.failure = failure
        self.mode = execution_mode
        self.delivery_certainty = delivery_certainty
        self.calls = 0
        self.recovery_calls = 0

    @property
    def execution_mode(self) -> AcquisitionExecutionMode:
        return self.mode

    def execute(
        self,
        request: object,
        authority: object,
        *,
        idempotency_key: str,
    ) -> AcquisitionExecution:
        self.calls += 1
        if self.failure is not None:
            raise HearingAcquisitionExecutorError(
                self.failure,
                self.delivery_certainty,
            )
        assert isinstance(authority, EvidenceAuthority)
        assert self.execution is not None
        assert request == self.execution.request
        assert idempotency_key == self.execution.request.request_id
        return self.execution

    def recover(
        self,
        request: object,
        authority: object,
        *,
        idempotency_key: str,
    ) -> HearingAcquisitionRecovery:
        del request, authority, idempotency_key
        self.recovery_calls += 1
        return HearingAcquisitionRecovery(status=HearingAcquisitionRecoveryStatus.UNKNOWN)


class _Repository:
    def __init__(
        self,
        *,
        before: CaseSnapshot,
        authority: EvidenceAuthority,
        conflict: bool = False,
        corrupt_revision: bool = False,
    ) -> None:
        self.before = before
        self.authority = authority
        self.conflict = conflict
        self.corrupt_revision = corrupt_revision
        self.calls = 0
        self.execution_publication: AcquisitionExecutionPublication | None = None
        self.claim_status: AcquisitionExecutionClaimStatus | None = None
        self.claim_fence = 1
        self.execution_mode = AcquisitionExecutionMode.PURE

    def claim_acquisition_execution(
        self,
        run_id: str,
        request: object,
        execution_mode: AcquisitionExecutionMode,
        owner_token: str,
    ) -> AcquisitionExecutionClaim:
        del run_id, owner_token
        self.execution_mode = execution_mode
        if self.execution_publication is not None:
            return AcquisitionExecutionClaim(
                status=AcquisitionExecutionClaimStatus.COMPLETED,
                request_id=request.request_id,
                execution_mode=execution_mode,
                idempotency_key=request.request_id,
                owner_fence=self.claim_fence,
                publication_id=self.execution_publication.publication_id,
            )
        if self.claim_status == AcquisitionExecutionClaimStatus.ABANDONED:
            return AcquisitionExecutionClaim(
                status=AcquisitionExecutionClaimStatus.ABANDONED,
                request_id=request.request_id,
                execution_mode=execution_mode,
                idempotency_key=request.request_id,
                owner_fence=self.claim_fence,
            )
        self.claim_status = AcquisitionExecutionClaimStatus.ACQUIRED
        return AcquisitionExecutionClaim(
            status=AcquisitionExecutionClaimStatus.ACQUIRED,
            request_id=request.request_id,
            execution_mode=execution_mode,
            idempotency_key=request.request_id,
            owner_fence=1,
            lease_expires_at=datetime.now(UTC) + timedelta(seconds=30),
        )

    def claim_acquisition_recovery(
        self,
        run_id: str,
        request: object,
        observed_owner_fence: int,
        owner_token: str,
    ) -> AcquisitionExecutionClaim:
        del run_id, request, observed_owner_fence, owner_token
        raise AssertionError("pure fake must not request recovery")

    def complete_acquisition_execution(
        self,
        run_id: str,
        publication: AcquisitionExecutionPublication,
        owner_token: str,
    ) -> AcquisitionExecutionCommit:
        del run_id, owner_token
        self.execution_publication = publication
        self.claim_status = AcquisitionExecutionClaimStatus.COMPLETED
        self.claim_fence = publication.claim_fence
        return AcquisitionExecutionCommit(publication=publication, created=True)

    def abandon_acquisition_execution(
        self,
        run_id: str,
        request: object,
        observed_owner_fence: int,
        owner_token: str,
    ) -> AcquisitionExecutionClaim:
        del run_id, owner_token
        self.claim_status = AcquisitionExecutionClaimStatus.ABANDONED
        self.claim_fence = observed_owner_fence + 1
        return AcquisitionExecutionClaim(
            status=AcquisitionExecutionClaimStatus.ABANDONED,
            request_id=request.request_id,
            execution_mode=self.execution_mode,
            idempotency_key=request.request_id,
            owner_fence=self.claim_fence,
        )

    def load_acquisition_execution(
        self,
        run_id: str,
        request_id: str,
    ) -> AcquisitionExecutionPublication | None:
        del run_id, request_id
        return self.execution_publication

    def persist_acquisition_successor(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        request: object,
        publication: AcquisitionExecutionPublication,
    ) -> AcquisitionPublishResult:
        del expected_audit_head
        self.calls += 1
        if self.conflict:
            raise ConcurrentModification("test conflict")
        assert run_id == self.before.case.run_id
        assert expected_case_revision == self.before.revision
        execution = AcquisitionExecution(
            request=request,
            execution_manifest=publication.execution_manifest,
            tool_result=publication.tool_result,
            output_objects=LoadedEvidenceObjects(
                frames=publication.frames,
                crops=publication.crops,
                objective_facts=publication.objective_facts,
                detections=publication.detections,
            ),
            crop_request=publication.crop_request,
        )
        update = _finalize(
            self.authority.pack,
            execution,
            receipts=self.authority.receipts,
            loaded=self.authority.loaded_objects,
        )
        payload = self.before.case.model_dump(
            mode="python",
            exclude_computed_fields=True,
        )
        payload["evidence_packs"] = (*self.before.case.evidence_packs, update.pack)
        after = Case.model_validate(payload)
        revision = self.before.revision if self.corrupt_revision else self.before.revision + 1
        return AcquisitionPublishResult(
            case=CaseSnapshot(case=after, revision=revision),
            pack=update.pack,
            receipt=update.receipt,
            created=True,
        )


def _manifest() -> RunManifest:
    return RunManifest.model_validate_json(
        (FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )


def _case(pack: object) -> CaseSnapshot:
    return CaseSnapshot(
        case=Case(
            run_id=pack.run_id,
            status=CaseStatus.DELIBERATING,
            event=pack.event,
            evidence_packs=(pack,),
            manifest_id=pack.manifest_id,
        ),
        revision=7,
    )


def _head(pack: object) -> AuditHead:
    return AuditHead(
        run_id=pack.run_id,
        manifest_id=pack.manifest_id,
        run_revision=11,
        sequence=11,
        entry_hash="0" * 64,
    )


def _track_harness(
    *,
    conflict: bool = False,
    corrupt_revision: bool = False,
) -> tuple[
    HearingAcquisitionContext,
    _Executor,
    _Repository,
]:
    pack, execution, loaded, _ = _fixture_execution(AcquisitionAction.TRACK_CONFIDENCE_CURVE)
    authority = derive_evidence_authority(pack, loaded_objects=loaded)
    case = _case(pack)
    executor = _Executor(execution)
    repository = _Repository(
        before=case,
        authority=authority,
        conflict=conflict,
        corrupt_revision=corrupt_revision,
    )
    return (
        HearingAcquisitionContext(
            case=case,
            audit_head=_head(pack),
            request=execution.request,
            evidence=authority,
            run_manifest=_manifest(),
        ),
        executor,
        repository,
    )


def test_service_publishes_and_rebuilds_exact_successor_authority() -> None:
    context, executor, repository = _track_harness()
    service = HearingAcquisitionService(
        repository=repository,
        executor=executor,
    )

    result = service.execute(context)

    assert executor.calls == 1
    assert repository.calls == 1
    assert result.execution.request == context.request
    assert result.publication.case.revision == context.case.revision + 1
    assert result.publication.pack.version == context.evidence.pack.version + 1
    assert result.authority.pack == result.publication.pack
    assert result.authority.receipts == (
        *context.evidence.receipts,
        result.publication.receipt,
    )
    assert result.execution.output_objects.objective_facts


def test_executor_failure_preserves_typed_tool_reason_without_persisting() -> None:
    context, _executor, repository = _track_harness()
    executor = _Executor(failure=HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE)
    service = HearingAcquisitionService(
        repository=repository,
        executor=executor,
    )

    with pytest.raises(HearingAcquisitionError) as captured:
        service.execute(context)

    assert captured.value.reason_code == HearingAcquisitionFailureCode.EXECUTION_FAILED
    assert (
        captured.value.executor_reason_code
        == HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE
    )
    assert repository.calls == 0


def test_unknown_external_delivery_is_abandoned_and_never_blindly_retried() -> None:
    context, _executor, repository = _track_harness()
    executor = _Executor(
        failure=HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE,
        execution_mode=AcquisitionExecutionMode.IDEMPOTENT_EXTERNAL,
        delivery_certainty=HearingAcquisitionDeliveryCertainty.UNKNOWN,
    )
    service = HearingAcquisitionService(
        repository=repository,
        executor=executor,
        owner_token_factory=lambda: "external-owner-token" * 3,
    )

    for _ in range(2):
        with pytest.raises(HearingAcquisitionError) as captured:
            service.execute(context)
        assert captured.value.reason_code == HearingAcquisitionFailureCode.EXECUTION_UNRECOVERABLE

    assert executor.calls == 1
    assert executor.recovery_calls == 0
    assert repository.claim_status == AcquisitionExecutionClaimStatus.ABANDONED
    assert repository.calls == 0


def test_unregistered_other_camera_is_rejected_before_tool_execution() -> None:
    pack = _pack()
    execution = _execution(pack, AcquisitionAction.OTHER_CAMERA_SAME_TIME)
    source_loaded = LoadedEvidenceObjects()
    authority = derive_evidence_authority(pack, loaded_objects=source_loaded)
    case = _case(pack)
    context = HearingAcquisitionContext(
        case=case,
        audit_head=_head(pack),
        request=execution.request,
        evidence=authority,
        run_manifest=_manifest(),
    )
    executor = _Executor(execution)
    repository = _Repository(before=case, authority=authority)

    with pytest.raises(HearingAcquisitionError) as captured:
        HearingAcquisitionService(
            repository=repository,
            executor=executor,
        ).execute(context)

    assert captured.value.reason_code == HearingAcquisitionFailureCode.STREAM_AUTHORITY_MISMATCH
    assert executor.calls == 0
    assert repository.calls == 0


def test_dual_cas_conflict_and_corrupt_publication_fail_closed() -> None:
    conflict_context, conflict_executor, conflict_repository = _track_harness(conflict=True)
    with pytest.raises(HearingAcquisitionError) as conflict:
        HearingAcquisitionService(
            repository=conflict_repository,
            executor=conflict_executor,
        ).execute(conflict_context)
    assert conflict.value.reason_code == HearingAcquisitionFailureCode.PERSISTENCE_CONFLICT

    corrupt_context, corrupt_executor, corrupt_repository = _track_harness(corrupt_revision=True)
    with pytest.raises(HearingAcquisitionError) as corrupt:
        HearingAcquisitionService(
            repository=corrupt_repository,
            executor=corrupt_executor,
        ).execute(corrupt_context)
    assert corrupt.value.reason_code == HearingAcquisitionFailureCode.PERSISTED_SUCCESSOR_INVALID


def test_case_or_manifest_drift_is_rejected_without_side_effects() -> None:
    context, executor, repository = _track_harness()
    wrong_case = CaseSnapshot(
        case=context.case.case.model_copy(update={"status": CaseStatus.PROCEDURAL_REVIEW}),
        revision=context.case.revision,
    )
    drifted = HearingAcquisitionContext(
        case=wrong_case,
        audit_head=context.audit_head,
        request=context.request,
        evidence=context.evidence,
        run_manifest=context.run_manifest,
    )

    with pytest.raises(HearingAcquisitionError) as captured:
        HearingAcquisitionService(
            repository=repository,
            executor=executor,
        ).execute(drifted)

    assert captured.value.reason_code == HearingAcquisitionFailureCode.CASE_AUTHORITY_MISMATCH
    assert executor.calls == 0
    assert repository.calls == 0

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

import tests.integration.test_m3_sqlite_repository as m3_fixtures
from labcourt.adapters.acquisition_fake import (
    CONTROLLED_FAKE_ACQUISITION_COMPONENT,
    CONTROLLED_FAKE_ACQUISITION_COMPONENT_KEY,
    acquisition_parameters_schema_sha256,
    controlled_fake_acquisition_component_manifest_id,
)
from labcourt.adapters.fake_hearing_precedents import FakeHearingPrecedentRetriever
from labcourt.adapters.hearing_prompt_renderer import HearingJinjaPromptCatalog
from labcourt.adapters.storage import SecureHearingModelResponseStore, SecureWorkspace
from labcourt.adapters.storage.readonly_m4_artifacts import (
    M4AuthorityFailureType,
    ReadonlyM4ArtifactRepository,
)
from labcourt.adapters.storage.readonly_sqlite import readonly_sqlite_snapshot
from labcourt.adapters.storage.sqlite_hearing_repository import SQLiteHearingRepository
from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.adapters.vlm import DeterministicFakeHearingVLMClient
from labcourt.application._hearing_workflow_types import (
    HearingCoordinatorError,
    HearingCoordinatorErrorCode,
)
from labcourt.application.hearing_acquisition import (
    HearingAcquisitionError,
    HearingAcquisitionFailureCode,
)
from labcourt.application.hearing_coordinator import HearingCoordinator
from labcourt.application.hearing_precedent_retrieval import (
    HearingPrecedentRetrievalService,
)
from labcourt.application.hearing_procedural_review import (
    DeterministicHearingProceduralReviewVerifier,
)
from labcourt.application.hearing_role_call import HearingRoleCallService
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    AcquisitionExecutionMode,
    ArtifactKind,
    ClosureDefectCode,
    ObjectiveFactKind,
)
from labcourt.contracts.events import ObjectiveFact
from labcourt.contracts.evidence import ToolResult
from labcourt.contracts.hearing import (
    AcquisitionExecutionClaimAuthority,
    AcquisitionExecutionPublication,
    AcquisitionRequest,
    EvidencePackDerivation,
    HearingCheckpointPhase,
    ToolExecutionManifest,
    derive_m4_tool_result_id,
)
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.evidence_authority import (
    AcquisitionExecution,
    LoadedEvidenceObjects,
)
from labcourt.exceptions import ConcurrentModification, EvidenceMissing
from labcourt.ports.hearing_repository import AcquisitionExecutionClaimStatus
from tests.integration.test_m3_sqlite_repository import ROOT, RUN_ID, _clock
from tests.integration.test_m4_hearing_coordinator import (
    _CountingHearingVLMClient,
    _escalated_case,
    _fixtures_for_terminal_hearing,
    _hearing_schema_documents,
    _PromptRegistrar,
)


class _PauseAtAcquisition:
    def execute(self, context):
        raise HearingAcquisitionError(
            HearingAcquisitionFailureCode.EXECUTION_IN_PROGRESS,
            request_id=context.request.request_id,
        )


def _pending_acquisition(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    base_manifest = m3_fixtures._manifest()
    manifest_payload = base_manifest.model_dump(mode="json", exclude={"manifest_id"})
    manifest_payload["software_components"] = {
        **manifest_payload["software_components"],
        CONTROLLED_FAKE_ACQUISITION_COMPONENT_KEY: (
            CONTROLLED_FAKE_ACQUISITION_COMPONENT.model_dump(mode="json")
        ),
    }
    pinned_manifest = type(base_manifest).model_validate(manifest_payload)
    pinned_event = m3_fixtures._event().model_copy(
        update={"manifest_id": pinned_manifest.manifest_id}
    )
    monkeypatch.setattr(m3_fixtures, "_manifest", lambda: pinned_manifest)
    monkeypatch.setattr(m3_fixtures, "_event", lambda: pinned_event)
    database, repository, pack, escalated = _escalated_case(tmp_path)
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest = repository.load_run_manifest(RUN_ID)
    catalog = HearingJinjaPromptCatalog(output_schema_json_by_prompt=_hearing_schema_documents())
    precedents = HearingPrecedentRetrievalService(
        FakeHearingPrecedentRetriever(()),
        retriever_version="fake-hearing-precedents-v1",
        retriever_manifest_id=hashlib.sha256(b"fake-hearing-precedents").hexdigest(),
    )
    fixtures = _fixtures_for_terminal_hearing(
        source_case=escalated,
        config=config,
        manifest=manifest,
        catalog=catalog,
        precedents=precedents,
        judge_requests_acquisition=True,
    )
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    with SecureWorkspace(workspace_root, 256 * 1024) as workspace:
        response_store = SecureHearingModelResponseStore(workspace)
        client = _CountingHearingVLMClient(
            DeterministicFakeHearingVLMClient(fixtures, response_store)
        )
        role_calls = HearingRoleCallService(
            repository=repository,
            response_store=response_store,
            vlm_client=client,
            prompt_registrar=_PromptRegistrar(),
            owner_token_factory=lambda: "role-owner-token" * 3,
        )
        coordinator = HearingCoordinator(
            config=config,
            evidence_repository=repository,
            hearing_repository=repository,
            precedent_retrieval=precedents,
            role_calls=role_calls,
            acquisition=_PauseAtAcquisition(),
            prompt_catalog=catalog,
            review_verifier=DeterministicHearingProceduralReviewVerifier(
                config,
                repository,
            ),
        )
        with pytest.raises(HearingCoordinatorError) as paused:
            coordinator.process_case(RUN_ID, pack.case_id)
    assert paused.value.reason_code == HearingCoordinatorErrorCode.PERSISTENCE_CONFLICT
    session = repository.load_active_hearing(RUN_ID, pack.case_id)
    assert session is not None
    checkpoint = repository.load_latest_hearing_checkpoint(RUN_ID, session.session_id)
    assert checkpoint.phase == HearingCheckpointPhase.ACQUISITION_PENDING
    assert checkpoint.acquisition_request is not None
    assert len(client.calls) == 3
    clock = [_clock()]
    repository._clock = lambda: clock[0]
    return database, repository, checkpoint.acquisition_request, clock


def _track_execution(request: AcquisitionRequest) -> AcquisitionExecution:
    manifest = ToolExecutionManifest(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        acquisition_request_id=request.request_id,
        action=request.action,
        tool_id="track-confidence-tool",
        tool_revision="tool-v1",
        parameters_schema_sha256=acquisition_parameters_schema_sha256(request.action),
        component_manifest_id=controlled_fake_acquisition_component_manifest_id(),
        manifest_id=request.manifest_id,
    )
    input_refs = (
        ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id=request.current_evidence_pack_id,
        ),
    )
    output_refs = (
        ArtifactRef(
            kind=ArtifactKind.OBJECTIVE_FACT,
            artifact_id="acquired-confidence-fact",
        ),
    )
    result_id = derive_m4_tool_result_id(
        request.action,
        input_refs,
        output_refs,
        request.validated_parameters,
        manifest.execution_manifest_id,
    )
    fact = ObjectiveFact(
        fact_id=output_refs[0].artifact_id,
        kind=ObjectiveFactKind.DETECTION_SCORE,
        value=0.75,
        source_ref=ArtifactRef(kind=ArtifactKind.TOOL_RESULT, artifact_id=result_id),
        source_manifest_id=manifest.execution_manifest_id,
    )
    result = ToolResult(
        tool_result_id=result_id,
        action=request.action,
        input_refs=input_refs,
        output_refs=output_refs,
        validated_parameters=request.validated_parameters,
        execution_manifest_id=manifest.execution_manifest_id,
    )
    return AcquisitionExecution(
        request=request,
        execution_manifest=manifest,
        tool_result=result,
        output_objects=LoadedEvidenceObjects(objective_facts=(fact,)),
    )


def _publication(
    execution: AcquisitionExecution,
    *,
    mode: AcquisitionExecutionMode,
    owner_token: str,
    fence: int,
) -> AcquisitionExecutionPublication:
    return AcquisitionExecutionPublication(
        request=execution.request,
        execution_manifest=execution.execution_manifest,
        tool_result=execution.tool_result,
        objective_facts=execution.output_objects.objective_facts,
        execution_mode=mode,
        idempotency_key=execution.request.request_id,
        claim_owner_sha256=hashlib.sha256(owner_token.encode("utf-8")).hexdigest(),
        claim_fence=fence,
    )


def _committed_successor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    database, host, request, _clock_box = _pending_acquisition(tmp_path, monkeypatch)
    repository = SQLiteHearingRepository(host)
    owner = "closure-owner-secret" * 3
    claim = repository.claim_acquisition_execution(
        RUN_ID,
        request,
        AcquisitionExecutionMode.PURE,
        owner,
    )
    publication = _publication(
        _track_execution(request),
        mode=AcquisitionExecutionMode.PURE,
        owner_token=owner,
        fence=claim.owner_fence,
    )
    repository.complete_acquisition_execution(RUN_ID, publication, owner)
    before = host.load_case(RUN_ID, request.case_id)
    committed = repository.persist_acquisition_successor(
        RUN_ID,
        before.revision,
        host.get_audit_head(RUN_ID),
        request,
        publication,
    )
    return database, host, request, publication, committed


def test_acquisition_successor_closure_reconstructs_exact_m4_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _database, host, request, publication, committed = _committed_successor(
        tmp_path,
        monkeypatch,
    )

    closure = host.verify_current_pack(RUN_ID, committed.pack.pack_id)

    root = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=committed.pack.pack_id)
    expected_refs = {ref.sort_key: ref for ref in (*committed.pack.expected_closure_refs(), root)}
    assert closure.passed
    assert closure.checked_refs == tuple(expected_refs[key] for key in sorted(expected_refs))
    assert closure.input_sha256 == committed.pack.closure_input_sha256
    assert (
        ArtifactRef(
            kind=ArtifactKind.MANIFEST,
            artifact_id=publication.execution_manifest.execution_manifest_id,
        )
        in closure.checked_refs
    )
    assert (
        ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id=request.current_evidence_pack_id,
        )
        in closure.checked_refs
    )


def test_acquisition_successor_closure_rejects_manifest_document_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, host, _request, publication, committed = _committed_successor(
        tmp_path,
        monkeypatch,
    )
    trigger_name = "m4_tool_execution_manifests_no_update"
    with sqlite3.connect(database) as connection:
        raw = str(
            connection.execute(
                """
                SELECT manifest_json
                FROM m4_tool_execution_manifests
                WHERE run_id = ? AND execution_manifest_id = ?
                """,
                (RUN_ID, publication.execution_manifest.execution_manifest_id),
            ).fetchone()[0]
        )
        payload = json.loads(raw)
        payload["tool_revision"] = "tampered-revision"
        tampered_json = canonical_json(payload)
        tampered_sha256 = hashlib.sha256(tampered_json.encode("utf-8")).hexdigest()
        connection.execute(f'DROP TRIGGER "{trigger_name}"')
        connection.execute(
            """
            UPDATE m4_tool_execution_manifests
            SET manifest_json = ?, document_sha256 = ?
            WHERE run_id = ? AND execution_manifest_id = ?
            """,
            (
                tampered_json,
                tampered_sha256,
                RUN_ID,
                publication.execution_manifest.execution_manifest_id,
            ),
        )

    with pytest.raises(RepositoryIntegrityError):
        host.verify_current_pack(RUN_ID, committed.pack.pack_id)


@pytest.mark.parametrize("tamper_target", ("request", "receipt", "tool_result"))
def test_acquisition_successor_closure_rejects_request_receipt_and_result_tamper(
    tamper_target: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, host, request, _publication_value, committed = _committed_successor(
        tmp_path,
        monkeypatch,
    )
    with sqlite3.connect(database) as connection:
        if tamper_target == "request":
            table = "m4_acquisition_requests"
            document_column = "request_json"
            trigger_name = "m4_acquisition_requests_no_update"
            id_column = "acquisition_request_id"
            document_id = request.request_id
            payload_path = ("case_id",)
            tampered_value: str | int = "tampered-case"
        else:
            table = "m4_tool_execution_receipts"
            document_column = "receipt_json"
            trigger_name = "m4_tool_execution_receipts_no_update"
            id_column = "receipt_id"
            document_id = committed.receipt.receipt_id
            if tamper_target == "receipt":
                payload_path = ("resulting_evidence_pack_version",)
                tampered_value = committed.pack.version + 1
            else:
                payload_path = ("tool_result", "execution_manifest_id")
                tampered_value = "f" * 64
        row = connection.execute(
            f'SELECT "{document_column}" FROM "{table}" WHERE run_id = ? AND "{id_column}" = ?',
            (RUN_ID, document_id),
        ).fetchone()
        assert row is not None
        payload = json.loads(str(row[0]))
        target = payload
        for key in payload_path[:-1]:
            target = target[key]
        target[payload_path[-1]] = tampered_value
        tampered_json = canonical_json(payload)
        tampered_sha256 = hashlib.sha256(tampered_json.encode("utf-8")).hexdigest()
        connection.execute(f'DROP TRIGGER "{trigger_name}"')
        connection.execute(
            f'UPDATE "{table}" SET "{document_column}" = ?, document_sha256 = ? '
            f'WHERE run_id = ? AND "{id_column}" = ?',
            (tampered_json, tampered_sha256, RUN_ID, document_id),
        )

    with pytest.raises(RepositoryIntegrityError):
        host.verify_current_pack(RUN_ID, committed.pack.pack_id)


def test_acquisition_successor_closure_does_not_accept_cross_run_manifest_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, host, _request, publication, committed = _committed_successor(
        tmp_path,
        monkeypatch,
    )
    with sqlite3.connect(database) as connection:
        connection.execute('DROP TRIGGER "m4_tool_execution_manifests_no_update"')
        connection.execute(
            """
            UPDATE m4_tool_execution_manifests
            SET run_id = 'run-cross-scope'
            WHERE run_id = ? AND execution_manifest_id = ?
            """,
            (RUN_ID, publication.execution_manifest.execution_manifest_id),
        )

    with pytest.raises(EvidenceMissing):
        host.verify_current_pack(RUN_ID, committed.pack.pack_id)


def test_acquisition_successor_closure_rejects_typed_wrong_predecessor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, host, _request, _publication_value, committed = _committed_successor(
        tmp_path,
        monkeypatch,
    )
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT derivation_json
            FROM m4_evidence_pack_derivations
            WHERE run_id = ? AND new_pack_id = ?
            """,
            (RUN_ID, committed.pack.pack_id),
        ).fetchone()
        assert row is not None
        payload = json.loads(str(row[0]))
        payload.pop("derivation_id", None)
        payload.pop("derivation_sha256", None)
        payload["previous_evidence_pack_id"] = "f" * 64
        wrong = EvidencePackDerivation.model_validate(payload)
        wrong_json = canonical_json(wrong.model_dump(mode="json"))
        wrong_sha256 = hashlib.sha256(wrong_json.encode("utf-8")).hexdigest()
        connection.execute('DROP TRIGGER "m4_evidence_pack_derivations_no_update"')
        connection.execute(
            """
            UPDATE m4_evidence_pack_derivations
            SET derivation_id = ?, previous_pack_id = ?,
                derivation_json = ?, document_sha256 = ?
            WHERE run_id = ? AND new_pack_id = ?
            """,
            (
                wrong.derivation_id,
                wrong.previous_evidence_pack_id,
                wrong_json,
                wrong_sha256,
                RUN_ID,
                committed.pack.pack_id,
            ),
        )

    with pytest.raises(RepositoryIntegrityError):
        host.verify_current_pack(RUN_ID, committed.pack.pack_id)


def test_acquisition_successor_closure_reports_missing_derivation_gap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, host, _request, _publication_value, committed = _committed_successor(
        tmp_path,
        monkeypatch,
    )
    with sqlite3.connect(database) as connection:
        connection.execute('DROP TRIGGER "m4_evidence_pack_derivations_no_delete"')
        connection.execute(
            """
            DELETE FROM m4_evidence_pack_derivations
            WHERE run_id = ? AND new_pack_id = ?
            """,
            (RUN_ID, committed.pack.pack_id),
        )

    closure = host.verify_current_pack(RUN_ID, committed.pack.pack_id)

    assert not closure.passed
    assert {defect.code for defect in closure.defects} == {
        ClosureDefectCode.MISSING_REFERENCE,
        ClosureDefectCode.TOOL_INPUT_MISSING,
    }


def test_acquisition_successor_closure_rejects_forked_derivation_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, host, _request, _publication_value, committed = _committed_successor(
        tmp_path,
        monkeypatch,
    )
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT derivation_json
            FROM m4_evidence_pack_derivations
            WHERE run_id = ? AND new_pack_id = ?
            """,
            (RUN_ID, committed.pack.pack_id),
        ).fetchone()
        assert row is not None
        current = EvidencePackDerivation.model_validate_json(str(row[0]))
        fork_pack_id = hashlib.sha256(b"forked-acquisition-pack").hexdigest()
        fork: EvidencePackDerivation | None = None
        for index in range(4096):
            candidate = EvidencePackDerivation(
                run_id=current.run_id,
                case_id=current.case_id,
                hearing_session_id=current.hearing_session_id,
                source_cycle_scope_id=current.source_cycle_scope_id,
                source_cycle_scope_sha256=current.source_cycle_scope_sha256,
                previous_evidence_pack_id=current.previous_evidence_pack_id,
                previous_evidence_pack_version=current.previous_evidence_pack_version,
                new_evidence_pack_id=fork_pack_id,
                new_evidence_pack_version=current.new_evidence_pack_version,
                tool_execution_receipt_id=hashlib.sha256(
                    f"forked-receipt-{index}".encode()
                ).hexdigest(),
                manifest_id=current.manifest_id,
            )
            if candidate.derivation_id > current.derivation_id:
                fork = candidate
                break
        assert fork is not None
        fork_json = canonical_json(fork.model_dump(mode="json"))
        fork_sha256 = hashlib.sha256(fork_json.encode("utf-8")).hexdigest()
        connection.execute('DROP TRIGGER "m4_evidence_pack_derivations_validate_authority"')
        connection.execute(
            """
            INSERT INTO m4_evidence_pack_derivations(
                run_id, derivation_id, hearing_id,
                source_cycle_scope_id, source_cycle_scope_sha256, case_id,
                previous_pack_id, previous_pack_version,
                new_pack_id, new_pack_version, tool_receipt_id,
                manifest_id, derivation_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fork.run_id,
                fork.derivation_id,
                fork.hearing_session_id,
                fork.source_cycle_scope_id,
                fork.source_cycle_scope_sha256,
                fork.case_id,
                fork.previous_evidence_pack_id,
                fork.previous_evidence_pack_version,
                fork.new_evidence_pack_id,
                fork.new_evidence_pack_version,
                fork.tool_execution_receipt_id,
                fork.manifest_id,
                fork_json,
                fork_sha256,
            ),
        )

    with pytest.raises(RepositoryIntegrityError, match="forked or discontinuous"):
        host.verify_current_pack(RUN_ID, committed.pack.pack_id)


def test_sqlite_concurrent_claim_and_stale_owner_are_fenced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _database, host, request, clock = _pending_acquisition(tmp_path, monkeypatch)
    repository = SQLiteHearingRepository(host)
    owner_one = "owner-one-secret" * 3
    owner_two = "owner-two-secret" * 3

    first = repository.claim_acquisition_execution(
        RUN_ID, request, AcquisitionExecutionMode.PURE, owner_one
    )
    concurrent = repository.claim_acquisition_execution(
        RUN_ID, request, AcquisitionExecutionMode.PURE, owner_two
    )

    assert first.status == AcquisitionExecutionClaimStatus.ACQUIRED
    assert concurrent.status == AcquisitionExecutionClaimStatus.WAITING
    assert concurrent.owner_fence == first.owner_fence

    clock[0] += timedelta(seconds=31)
    takeover = repository.claim_acquisition_execution(
        RUN_ID, request, AcquisitionExecutionMode.PURE, owner_two
    )
    assert takeover.status == AcquisitionExecutionClaimStatus.ACQUIRED
    assert takeover.owner_fence == first.owner_fence + 1

    stale = _publication(
        _track_execution(request),
        mode=AcquisitionExecutionMode.PURE,
        owner_token=owner_one,
        fence=first.owner_fence,
    )
    with pytest.raises(ConcurrentModification):
        repository.complete_acquisition_execution(RUN_ID, stale, owner_one)
    assert repository.load_acquisition_execution(RUN_ID, request.request_id) is None


def test_sqlite_unknown_external_delivery_is_terminally_abandoned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _database, host, request, clock = _pending_acquisition(tmp_path, monkeypatch)
    repository = SQLiteHearingRepository(host)
    original = repository.claim_acquisition_execution(
        RUN_ID,
        request,
        AcquisitionExecutionMode.IDEMPOTENT_EXTERNAL,
        "original-external-owner" * 2,
    )
    clock[0] += timedelta(seconds=31)
    expired = repository.claim_acquisition_execution(
        RUN_ID,
        request,
        AcquisitionExecutionMode.IDEMPOTENT_EXTERNAL,
        "recovery-observer-owner" * 2,
    )
    assert expired.status == AcquisitionExecutionClaimStatus.EXPIRED_REQUIRES_RECOVERY

    abandoned = repository.abandon_acquisition_execution(
        RUN_ID,
        request,
        original.owner_fence,
        "recovery-observer-owner" * 2,
    )
    assert abandoned.status == AcquisitionExecutionClaimStatus.ABANDONED
    replay = repository.claim_acquisition_execution(
        RUN_ID,
        request,
        AcquisitionExecutionMode.IDEMPOTENT_EXTERNAL,
        "later-worker-owner" * 3,
    )
    assert replay.status == AcquisitionExecutionClaimStatus.ABANDONED


def test_readonly_claim_projection_detects_secret_free_fence_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, host, request, _clock_box = _pending_acquisition(tmp_path, monkeypatch)
    repository = SQLiteHearingRepository(host)
    repository.claim_acquisition_execution(
        RUN_ID,
        request,
        AcquisitionExecutionMode.PURE,
        "claim-projection-owner" * 2,
    )

    trigger_name = "m4_acquisition_execution_claims_controlled_update"
    with sqlite3.connect(database) as connection:
        trigger_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
            (trigger_name,),
        ).fetchone()
        assert trigger_row is not None
        trigger_sql = str(trigger_row[0])
        raw = str(
            connection.execute(
                """
                SELECT claim_json
                FROM m4_acquisition_execution_claims
                WHERE run_id = ? AND acquisition_request_id = ?
                """,
                (RUN_ID, request.request_id),
            ).fetchone()[0]
        )
        payload = json.loads(raw)
        payload["owner_token_sha256"] = "f" * 64
        tampered = AcquisitionExecutionClaimAuthority.model_validate(payload)
        tampered_json = canonical_json(tampered.model_dump(mode="json"))
        tampered_sha256 = hashlib.sha256(tampered_json.encode("utf-8")).hexdigest()
        connection.execute(f'DROP TRIGGER "{trigger_name}"')
        connection.execute(
            """
            UPDATE m4_acquisition_execution_claims
            SET claim_json = ?, document_sha256 = ?
            WHERE run_id = ? AND acquisition_request_id = ?
            """,
            (tampered_json, tampered_sha256, RUN_ID, request.request_id),
        )
        connection.execute(trigger_sql)

    with readonly_sqlite_snapshot(database) as snapshot_database:
        authority = ReadonlyM4ArtifactRepository(snapshot_database).scan(RUN_ID)
    assert any(
        failure.inventory_kind == M4ProjectionArtifactKind.ACQUISITION_EXECUTION_CLAIM
        and failure.failure_type == M4AuthorityFailureType.INDEX_MISMATCH
        and failure.reason_code == "INDEX_BINDING_MISMATCH"
        for failure in authority.failures
    )


def test_crash_after_execution_publication_recovers_without_tool_and_replays_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _database, host, request, _clock_box = _pending_acquisition(tmp_path, monkeypatch)
    repository = SQLiteHearingRepository(host)
    owner = "publication-owner-secret" * 2
    claim = repository.claim_acquisition_execution(
        RUN_ID, request, AcquisitionExecutionMode.PURE, owner
    )
    publication = _publication(
        _track_execution(request),
        mode=AcquisitionExecutionMode.PURE,
        owner_token=owner,
        fence=claim.owner_fence,
    )

    def crash_after_publication(phase: str) -> None:
        if phase == "hearing.acquisition.after_execution_publication":
            raise RuntimeError("simulated post-publication crash")

    host._fault_injector = crash_after_publication
    with pytest.raises(RuntimeError, match="post-publication crash"):
        repository.complete_acquisition_execution(RUN_ID, publication, owner)
    host._fault_injector = None

    restarted = SQLiteHearingRepository(host)
    assert restarted.load_acquisition_execution(RUN_ID, request.request_id) == publication
    with readonly_sqlite_snapshot(_database) as snapshot_database:
        authority = ReadonlyM4ArtifactRepository(snapshot_database).scan(RUN_ID)
    assert authority.failures == ()
    counts = {item.inventory_kind: item.count for item in authority.traversed}
    assert counts[M4ProjectionArtifactKind.ACQUISITION_EXECUTION_CLAIM] == 1
    assert counts[M4ProjectionArtifactKind.ACQUISITION_EXECUTION_PUBLICATION] == 1
    before = host.load_case(RUN_ID, request.case_id)
    head = host.get_audit_head(RUN_ID)
    committed = restarted.persist_acquisition_successor(
        RUN_ID,
        before.revision,
        head,
        request,
        publication,
    )
    replay = restarted.persist_acquisition_successor(
        RUN_ID,
        before.revision,
        head,
        request,
        publication,
    )

    assert committed.created
    assert not replay.created
    assert replay.receipt == committed.receipt
    assert replay.pack == committed.pack

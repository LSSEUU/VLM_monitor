from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from labcourt.adapters.storage.m4_json_projector import M4ProjectionFailure
from labcourt.adapters.storage.readonly_m4_artifacts import (
    M4AuthorityFailureType,
    ReadonlyM4ArtifactRepository,
)
from labcourt.adapters.storage.readonly_sqlite import (
    ReadOnlySnapshotError,
    readonly_sqlite_snapshot,
)
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.contracts.backlog import BacklogLeaseIdentity
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    AcquisitionAction,
    ArtifactKind,
    BacklogReasonCode,
    BacklogStatus,
    CaseStatus,
    EvidenceClass,
    ExecutionLocation,
    ModelParseStatus,
    ViolationType,
    VlmRole,
)
from labcourt.contracts.evidence import EvidencePack, OtherCameraSameTimeParameters, ToolResult
from labcourt.contracts.hearing import (
    DefenderModelPayload,
    HearingBacklogRetryFailure,
    HearingCheckpoint,
    HearingCycleScope,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
    HearingRecord,
    HearingRoleOutput,
    HearingRound,
    HearingSession,
    HearingUsageReceipt,
    JudgeModelPayload,
    ProsecutorModelPayload,
    derive_hearing_model_response_id,
)
from labcourt.contracts.m3_models import PromptManifest, VlmCallBudget
from labcourt.contracts.m4_projection import (
    M4ProjectionCurrentPointer,
    M4ProjectionGenerationManifest,
)
from labcourt.contracts.screening import VLMMediaRef
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.hearing_fsm import (
    HearingCallClosure,
    HearingCallTrace,
    begin_hearing,
    complete_defender,
    complete_judge,
    complete_precedent_retrieval,
    complete_prosecutor,
)
from labcourt.services.m4_projection import rebuild_m4_projection
from tests.integration.test_m3_sqlite_repository import (
    RUN_ID,
    _complete_call,
    _m3_setup,
    _parsed,
    _parsed_receipt,
    _request,
    _response,
    _screening_for,
)
from tests.integration.test_m4_sqlite_hearing_retry import _lease, _provider_outage_seed
from tests.unit.test_m4_hearing_domain import _payloads


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class _StartedHearing:
    database: Path
    repository: SQLiteEvidenceRepository
    session: HearingSession
    cycle: HearingCycleScope
    pack_id: str
    pack_version: int
    pack: EvidencePack


def _started_hearing(tmp_path: Path) -> _StartedHearing:
    database, evidence, m3, pack, closure, snapshot, audit_head = _m3_setup(tmp_path)
    request = _request(pack)
    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    output = _parsed(request, response, violation_probability=0.5)
    receipt = _parsed_receipt(request, response, output)
    _complete_call(m3, request, response)
    m3.append_parse_receipt(receipt, output)
    screening = _screening_for(pack, output)
    committed = m3.commit_screening(
        RUN_ID,
        snapshot.revision,
        audit_head,
        closure,
        screening,
    )
    session = HearingSession(
        run_id=RUN_ID,
        case_id=pack.case_id,
        screening_id=screening.screening_id,
        entry_status="ESCALATED",
        initial_evidence_pack_id=pack.pack_id,
        initial_evidence_pack_version=pack.version,
        acquisition_round_limit=2,
        rework_round_limit=2,
        max_total_images=64,
        max_total_output_tokens=8_192,
        hearing_prompt_bundle_sha256=_digest("M4 prompt bundle"),
        prosecutor_model_manifest_id=_digest("M4 prosecutor"),
        defender_model_manifest_id=_digest("M4 defender"),
        judge_model_manifest_id=_digest("M4 judge"),
        manifest_id=pack.manifest_id,
    )
    cycle = HearingCycleScope(
        run_id=RUN_ID,
        case_id=pack.case_id,
        hearing_session_id=session.session_id,
        cycle_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=pack.pack_id,
        cycle_evidence_pack_version=pack.version,
        manifest_id=pack.manifest_id,
    )
    evidence.begin_hearing_case(
        RUN_ID,
        committed.case.revision,
        evidence.get_audit_head(RUN_ID),
        session,
        cycle,
        begin_hearing(session),
    )
    return _StartedHearing(
        database=database,
        repository=evidence,
        session=session,
        cycle=cycle,
        pack_id=pack.pack_id,
        pack_version=pack.version,
        pack=pack,
    )


def _scan(database: Path):
    with readonly_sqlite_snapshot(database) as snapshot:
        return ReadonlyM4ArtifactRepository(snapshot).scan(RUN_ID)


def _hearing_retrieval(started: _StartedHearing) -> HearingPrecedentRetrievalReceipt:
    return HearingPrecedentRetrievalReceipt(
        run_id=RUN_ID,
        case_id=started.session.case_id,
        hearing_session_id=started.session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=started.pack_id,
        current_evidence_pack_version=started.pack_version,
        evidence_class=started.pack.event.evidence_class,
        violation_type=started.pack.event.violation_type,
        rule_version=started.pack.event.rule_version,
        top_k=0,
        query_sha256=_digest("full round query"),
        candidate_snapshot_sha256=_digest("full round candidates"),
        visible_snapshot_sha256=_digest("full round visible"),
        status=HearingPrecedentRetrievalStatus.SUCCESS,
        retriever_version="fake-retriever-v1",
        retriever_manifest_id=_digest("full round retriever"),
        embedding_model_manifest_id=_digest("full round embedding"),
        manifest_id=started.session.manifest_id,
    )


def _persist_hearing_call(
    started: _StartedHearing,
    checkpoint: HearingCheckpoint,
    retrieval: HearingPrecedentRetrievalReceipt,
    payload: ProsecutorModelPayload | DefenderModelPayload | JudgeModelPayload,
    *,
    prosecutor_output_id: str | None = None,
    defender_output_id: str | None = None,
) -> tuple[HearingRoleOutput, HearingCallTrace]:
    role = payload.role
    crop = next(item for item in started.pack.crops if item.local_path is not None)
    prompt = PromptManifest(
        prompt_id=f"readonly-{role.value.lower()}-v1",
        role=role,
        template_sha256=_digest(f"readonly {role.value} template"),
        output_schema_sha256=_digest(f"readonly {role.value} schema"),
        prompt_bundle_sha256=started.session.hearing_prompt_bundle_sha256,
        renderer_version="fixture-renderer-v1",
    )
    prosecutor_ref = (
        ArtifactRef(
            kind=ArtifactKind.PARSED_MODEL_OUTPUT,
            artifact_id=prosecutor_output_id,
        )
        if prosecutor_output_id is not None
        else None
    )
    defender_ref = (
        ArtifactRef(
            kind=ArtifactKind.PARSED_MODEL_OUTPUT,
            artifact_id=defender_output_id,
        )
        if defender_output_id is not None
        else None
    )
    model_manifest_id = {
        VlmRole.PROSECUTOR: started.session.prosecutor_model_manifest_id,
        VlmRole.DEFENDER: started.session.defender_model_manifest_id,
        VlmRole.JUDGE: started.session.judge_model_manifest_id,
    }[role]
    request = HearingModelRequest(
        run_id=RUN_ID,
        case_id=started.session.case_id,
        hearing_session_id=started.session.session_id,
        round_index=checkpoint.judge_cycle,
        prior_acquisition_rounds=checkpoint.prior_acquisition_rounds,
        prior_rework_rounds=checkpoint.prior_rework_rounds,
        current_evidence_pack_id=checkpoint.cycle_evidence_pack_id,
        current_evidence_pack_version=checkpoint.cycle_evidence_pack_version,
        screening_ref=ArtifactRef(
            kind=ArtifactKind.SCREENING_RESULT,
            artifact_id=started.session.screening_id,
        ),
        violation_type=started.pack.event.violation_type,
        evidence_class=started.pack.event.evidence_class,
        role=role,
        provider_profile=f"fake-{role.value.lower()}",
        provider="fixture",
        model=f"fixture-{role.value.lower()}",
        revision="1.0.0",
        model_manifest_id=model_manifest_id,
        execution_location=ExecutionLocation.LOCAL,
        prompt_manifest=prompt,
        hearing_prompt_bundle_sha256=started.session.hearing_prompt_bundle_sha256,
        rendered_prompt_sha256=_digest(f"readonly {role.value} rendered"),
        hearing_context_sha256=_digest(f"readonly {role.value} context"),
        media=(
            VLMMediaRef(
                crop_id=crop.crop_id,
                media_sha256=crop.media_sha256,
                local_path=f"{RUN_ID}/frames/{crop.media_sha256}.png",
                source=crop.source,
                media_access=crop.privacy_receipt.media_access,
                privacy_policy=crop.privacy_receipt.policy,
                privacy_transform_version=crop.privacy_receipt.transform_version,
                width=crop.output_width,
                height=crop.output_height,
            ),
        ),
        allowed_evidence_refs=(ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),),
        prosecutor_output_ref=prosecutor_ref,
        defender_output_ref=defender_ref,
        precedent_retrieval_degraded=False,
        precedent_retrieval_receipt_id=retrieval.receipt_id,
        precedent_retrieval_receipt_sha256=retrieval.receipt_sha256,
        temperature=0.0,
        seed=7,
        budget=VlmCallBudget(
            max_images=1,
            max_input_pixels=crop.output_width * crop.output_height,
            max_input_tokens=256,
            max_output_tokens=128,
            pricing_currency="USD",
            input_cost_per_million_tokens=0.0,
            output_cost_per_million_tokens=0.0,
            max_estimated_cost=0.0,
            max_response_bytes=8_192,
            max_json_depth=8,
            max_json_fields=128,
            max_string_chars=2_048,
            timeout_seconds=5.0,
        ),
        manifest_id=started.session.manifest_id,
    )
    content_sha256 = _digest(f"readonly {role.value} raw")
    response_id = derive_hearing_model_response_id(RUN_ID, request.request_id, content_sha256)
    response = HearingModelResponse(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        prior_acquisition_rounds=request.prior_acquisition_rounds,
        prior_rework_rounds=request.prior_rework_rounds,
        current_evidence_pack_id=request.current_evidence_pack_id,
        current_evidence_pack_version=request.current_evidence_pack_version,
        role=role,
        attempt_index=0,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        raw_response_ref=f"{RUN_ID}/model_responses/{response_id}.json",
        content_sha256=content_sha256,
        size_bytes=64,
        input_tokens=10,
        output_tokens=5,
        latency_ms=7,
        model_manifest_id=model_manifest_id,
        manifest_id=started.session.manifest_id,
    )
    parse = HearingModelParseReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        role=role,
        attempt_index=0,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        parser_version="strict-v1",
        output_schema_sha256=prompt.output_schema_sha256,
        status=ModelParseStatus.PARSED,
        parsed_payload_sha256=payload.payload_sha256,
        manifest_id=started.session.manifest_id,
    )
    request_ref = ArtifactRef(kind=ArtifactKind.MODEL_REQUEST, artifact_id=request.request_id)
    response_ref = ArtifactRef(
        kind=ArtifactKind.MODEL_RESPONSE,
        artifact_id=response.response_id,
    )
    parse_ref = ArtifactRef(
        kind=ArtifactKind.MODEL_PARSE_RECEIPT,
        artifact_id=parse.parse_receipt_id,
    )
    output = HearingRoleOutput(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        prior_acquisition_rounds=request.prior_acquisition_rounds,
        prior_rework_rounds=request.prior_rework_rounds,
        current_evidence_pack_id=request.current_evidence_pack_id,
        current_evidence_pack_version=request.current_evidence_pack_version,
        prompt_manifest=prompt,
        model_manifest_id=model_manifest_id,
        request_ref=request_ref,
        response_ref=response_ref,
        parse_receipt_ref=parse_ref,
        prosecutor_output_id=prosecutor_output_id,
        defender_output_id=defender_output_id,
        precedent_retrieval_degraded=False,
        precedent_retrieval_receipt_id=retrieval.receipt_id,
        precedent_retrieval_receipt_sha256=retrieval.receipt_sha256,
        payload=payload,
        manifest_id=started.session.manifest_id,
    )
    usage = HearingUsageReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        role=role,
        request_ref=request_ref,
        response_ref=response_ref,
        input_images=1,
        input_pixels=crop.output_width * crop.output_height,
        input_tokens=response.input_tokens,
        output_tokens=response.output_tokens,
        latency_ms=response.latency_ms,
        retry_count=0,
        estimated_cost=0.0,
        manifest_id=started.session.manifest_id,
    )
    owner = _digest(f"readonly owner {role.value}")
    claim = started.repository.claim_hearing_model_call(RUN_ID, request, owner)
    assert claim.status.value == "ACQUIRED"
    started.repository.complete_hearing_model_call(
        RUN_ID,
        request,
        response,
        usage,
        owner,
    )
    started.repository.append_hearing_parse_receipt(parse, output)
    closure = HearingCallClosure(
        request=request,
        response=response,
        parse_receipt=parse,
        usage=usage,
    )
    return output, HearingCallTrace(calls=(closure,))


def _drop_restore_trigger(
    connection: sqlite3.Connection,
    trigger_name: str,
    operation: Callable[[], None],
) -> None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
        (trigger_name,),
    ).fetchone()
    assert row is not None and isinstance(row[0], str)
    trigger_sql = row[0]
    connection.execute(f'DROP TRIGGER "{trigger_name}"')
    operation()
    connection.execute(trigger_sql)


def test_m4_readonly_scan_and_projection_round_trip_are_deterministic(tmp_path: Path) -> None:
    started = _started_hearing(tmp_path)

    authority = _scan(started.database)
    assert authority.failures == ()
    assert len(authority.hearing_roots) == 1
    assert authority.hearing_roots[0].latest_checkpoint_version == 1

    output_root = tmp_path / "projection-output"
    first = rebuild_m4_projection(
        run_id=RUN_ID,
        database_path=started.database,
        workspace_root=output_root,
    )
    second = rebuild_m4_projection(
        run_id=RUN_ID,
        database_path=started.database,
        workspace_root=output_root,
    )
    pointer = M4ProjectionCurrentPointer.model_validate_json(
        first.current_pointer_path.read_bytes()
    )
    manifest = M4ProjectionGenerationManifest.model_validate_json(first.manifest_path.read_bytes())

    assert first.generation_id == second.generation_id == pointer.generation_id
    assert manifest.generation_id == pointer.generation_id
    assert len(manifest.entries) == len(authority.documents)
    assert all(path.is_file() for path in first.document_paths)


def test_m4_projection_accepts_backlogged_retry_case_history(tmp_path: Path) -> None:
    seed = _provider_outage_seed(tmp_path)
    leased = _lease(seed)
    assert leased is not None and leased.lease_id is not None
    authority = seed.repository.load_hearing_backlog_retry_authority(
        RUN_ID,
        BacklogLeaseIdentity(
            run_id=leased.run_id,
            item_id=leased.item_id,
            lease_id=leased.lease_id,
            attempt_count=leased.attempt_count,
            retry_generation=leased.retry_generation,
        ),
    )
    failure = HearingBacklogRetryFailure(
        lease=authority.lease,
        source_checkpoint_id=authority.checkpoint.checkpoint_id,
        source_checkpoint_sha256=authority.checkpoint.checkpoint_sha256,
        source_checkpoint_version=authority.checkpoint.version,
        request=authority.stage_request,
        role=authority.stage_request.role,
        reason_code=BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE,
        next_status=BacklogStatus.PENDING,
        manifest_id=authority.item.manifest_id,
    )

    committed = seed.repository.commit_hearing_backlog_retry(
        RUN_ID,
        authority.case.revision,
        authority.audit_head,
        failure,
    )

    assert committed.case.case.status == CaseStatus.BACKLOGGED
    assert committed.item.status == BacklogStatus.PENDING
    assert _scan(seed.database).failures == ()
    rebuilt = rebuild_m4_projection(
        run_id=RUN_ID,
        database_path=seed.database,
        workspace_root=tmp_path / "retry-projection-output",
    )
    assert rebuilt.current_pointer_path.is_file()


def test_m4_readonly_rebuilds_complete_call_graph_and_hearing_record(tmp_path: Path) -> None:
    started = _started_hearing(tmp_path)
    checkpoint = begin_hearing(started.session)
    retrieval = _hearing_retrieval(started)
    started.repository.append_precedent_retrieval(RUN_ID, retrieval)
    checkpoint = complete_precedent_retrieval(started.session, checkpoint, retrieval)
    started.repository.append_hearing_checkpoint(RUN_ID, checkpoint)
    crop_ref = ArtifactRef(
        kind=ArtifactKind.CROP,
        artifact_id=started.pack.crops[0].crop_id,
    )
    prosecutor_payload, defender_payload, judge_payload = _payloads(evidence_ref=crop_ref)
    prosecutor, prosecutor_trace = _persist_hearing_call(
        started,
        checkpoint,
        retrieval,
        prosecutor_payload,
    )
    checkpoint = complete_prosecutor(
        started.session,
        checkpoint,
        prosecutor,
        prosecutor_trace,
    )
    started.repository.append_hearing_checkpoint(RUN_ID, checkpoint)
    defender, defender_trace = _persist_hearing_call(
        started,
        checkpoint,
        retrieval,
        defender_payload,
        prosecutor_output_id=prosecutor.output_id,
    )
    checkpoint = complete_defender(
        started.session,
        checkpoint,
        defender,
        defender_trace,
    )
    started.repository.append_hearing_checkpoint(RUN_ID, checkpoint)
    judge, judge_trace = _persist_hearing_call(
        started,
        checkpoint,
        retrieval,
        judge_payload,
        prosecutor_output_id=prosecutor.output_id,
        defender_output_id=defender.output_id,
    )
    transition = complete_judge(
        started.session,
        checkpoint,
        judge,
        judge_trace,
    )
    checkpoint = transition.checkpoint
    assert checkpoint.prosecutor_output is not None
    assert checkpoint.defender_output is not None
    assert checkpoint.judge_output is not None
    hearing_round = HearingRound(
        run_id=RUN_ID,
        case_id=started.session.case_id,
        hearing_session_id=started.session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=started.pack_id,
        current_evidence_pack_version=started.pack_version,
        precedent_retrieval_degraded=False,
        precedent_retrieval_receipt=retrieval,
        prosecutor_output=checkpoint.prosecutor_output,
        defender_output=checkpoint.defender_output,
        judge_output=checkpoint.judge_output,
        manifest_id=started.session.manifest_id,
    )
    started.repository.complete_hearing_round(RUN_ID, hearing_round)
    started.repository.append_hearing_checkpoint(RUN_ID, checkpoint)

    authority = _scan(started.database)
    assert authority.failures == ()
    stored_record = started.repository.load_hearing_record(
        RUN_ID,
        started.session.session_id,
    )
    assert stored_record is not None
    projected_record = next(
        HearingRecord.model_validate_json(item.canonical_document)
        for item in authority.documents
        if item.kind.value == "HEARING_RECORD"
    )
    assert projected_record == stored_record
    assert authority.hearing_roots[0].latest_record_id == stored_record.record_id


@pytest.mark.parametrize(
    ("column", "value", "failure_type", "reason_code"),
    (
        (
            "hearing_json",
            None,
            M4AuthorityFailureType.DOCUMENT_INVALID,
            "DOCUMENT_NOT_CANONICAL",
        ),
        (
            "hearing_prompt_bundle_sha256",
            "f" * 64,
            M4AuthorityFailureType.INDEX_MISMATCH,
            "INDEX_BINDING_MISMATCH",
        ),
    ),
)
def test_m4_readonly_scan_rejects_document_and_index_tamper(
    tmp_path: Path,
    column: str,
    value: str | None,
    failure_type: M4AuthorityFailureType,
    reason_code: str,
) -> None:
    started = _started_hearing(tmp_path)
    with sqlite3.connect(started.database) as connection:

        def tamper() -> None:
            replacement = value
            if replacement is None:
                replacement = (
                    str(
                        connection.execute(
                            "SELECT hearing_json FROM m4_hearings WHERE run_id = ?",
                            (RUN_ID,),
                        ).fetchone()[0]
                    )
                    + " "
                )
            connection.execute(
                f'UPDATE m4_hearings SET "{column}" = ? WHERE run_id = ?',
                (replacement, RUN_ID),
            )

        _drop_restore_trigger(connection, "m4_hearings_no_update", tamper)

    result = _scan(started.database)
    assert any(
        item.failure_type == failure_type and item.reason_code == reason_code
        for item in result.failures
    )


@pytest.mark.parametrize(
    ("table", "trigger", "column"),
    (
        ("m4_hearings", "m4_hearings_no_update", "initial_defect_codes_json"),
        ("m4_hearing_cycles", "m4_hearing_cycles_no_update", "initial_defect_codes_json"),
        (
            "m4_hearing_checkpoints",
            "m4_hearing_checkpoints_no_update",
            "model_request_refs_json",
        ),
    ),
)
def test_m4_readonly_scan_recomputes_embedded_index_json(
    tmp_path: Path,
    table: str,
    trigger: str,
    column: str,
) -> None:
    started = _started_hearing(tmp_path)
    with sqlite3.connect(started.database) as connection:

        def tamper() -> None:
            connection.execute(
                f'UPDATE "{table}" SET "{column}" = ? WHERE run_id = ?',
                ("[ ]", RUN_ID),
            )

        _drop_restore_trigger(connection, trigger, tamper)

    result = _scan(started.database)
    assert any(
        item.failure_type == M4AuthorityFailureType.INDEX_MISMATCH
        and item.reason_code == "INDEX_BINDING_MISMATCH"
        for item in result.failures
    )


def test_m4_readonly_scan_rejects_session_created_audit_rebinding(tmp_path: Path) -> None:
    started = _started_hearing(tmp_path)
    with sqlite3.connect(started.database) as connection:

        def tamper() -> None:
            connection.execute(
                "UPDATE m4_hearings SET created_audit_sequence = 0 WHERE run_id = ?",
                (RUN_ID,),
            )

        _drop_restore_trigger(connection, "m4_hearings_no_update", tamper)

    result = _scan(started.database)
    assert any(item.reason_code == "SESSION_CREATED_AUDIT_MISMATCH" for item in result.failures)


def test_m4_readonly_scan_rejects_reverse_orphan_response(tmp_path: Path) -> None:
    started = _started_hearing(tmp_path)
    request_id = _digest("orphan request")
    content_sha256 = _digest("orphan content")
    response_id = derive_hearing_model_response_id(RUN_ID, request_id, content_sha256)
    response = HearingModelResponse(
        run_id=RUN_ID,
        case_id=started.session.case_id,
        hearing_session_id=started.session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=started.pack_id,
        current_evidence_pack_version=started.pack_version,
        role=VlmRole.PROSECUTOR,
        attempt_index=0,
        request_id=request_id,
        request_sha256=_digest("orphan request document"),
        cache_key=_digest("orphan cache key"),
        raw_response_ref=f"{RUN_ID}/model_responses/{response_id}.json",
        content_sha256=content_sha256,
        size_bytes=17,
        input_tokens=3,
        output_tokens=2,
        latency_ms=4,
        model_manifest_id=started.session.prosecutor_model_manifest_id,
        manifest_id=started.session.manifest_id,
    )
    document = canonical_json(response.model_dump(mode="json"))
    with sqlite3.connect(started.database) as connection:

        def insert_orphan() -> None:
            connection.execute(
                """
                INSERT INTO m4_model_responses(
                    run_id, response_id, request_id, request_sha256, cache_key,
                    hearing_id, cycle_scope_id, cycle_scope_sha256, case_id,
                    role, purpose, attempt_index, retry_generation,
                    raw_response_ref, content_sha256, size_bytes,
                    model_manifest_id, manifest_id, response_json, document_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    response.run_id,
                    response.response_id,
                    response.request_id,
                    response.request_sha256,
                    response.cache_key,
                    response.hearing_session_id,
                    started.cycle.cycle_id,
                    started.cycle.cycle_sha256,
                    response.case_id,
                    response.role.value,
                    "ROLE_CALL",
                    response.attempt_index,
                    0,
                    response.raw_response_ref,
                    response.content_sha256,
                    response.size_bytes,
                    response.model_manifest_id,
                    response.manifest_id,
                    document,
                    hashlib.sha256(document.encode("utf-8")).hexdigest(),
                ),
            )

        _drop_restore_trigger(
            connection,
            "m4_model_responses_validate_claim",
            insert_orphan,
        )

    result = _scan(started.database)
    assert any(item.reason_code == "RESPONSE_CLAIM_ORPHAN" for item in result.failures)


def test_m4_readonly_scan_rejects_cross_case_foreign_key_contamination(
    tmp_path: Path,
) -> None:
    started = _started_hearing(tmp_path)
    with sqlite3.connect(started.database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")

        def tamper() -> None:
            connection.execute(
                "UPDATE m4_hearings SET case_id = 'another-case' WHERE run_id = ?",
                (RUN_ID,),
            )

        _drop_restore_trigger(connection, "m4_hearings_no_update", tamper)

    with (
        readonly_sqlite_snapshot(started.database) as snapshot,
        pytest.raises(ReadOnlySnapshotError, match="DATABASE_FOREIGN_KEY_INVALID"),
    ):
        ReadonlyM4ArtifactRepository(snapshot).scan(RUN_ID)


def test_m4_readonly_scan_fails_closed_when_foreign_camera_frame_escapes_tool_result(
    tmp_path: Path,
) -> None:
    started = _started_hearing(tmp_path)
    source_frame_id = "cam-01:demo-ntsc:90"
    foreign_frame_id = "cam-02:other-stream:90"
    parameters = OtherCameraSameTimeParameters(
        action=AcquisitionAction.OTHER_CAMERA_SAME_TIME,
        source_frame_id=source_frame_id,
        target_camera_id="cam-02",
    )
    tool_result = ToolResult(
        tool_result_id="foreign-camera-fixture",
        action=AcquisitionAction.OTHER_CAMERA_SAME_TIME,
        input_refs=tuple(
            sorted(
                (
                    ArtifactRef(
                        kind=ArtifactKind.EVIDENCE_PACK,
                        artifact_id=started.pack_id,
                    ),
                    ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=source_frame_id),
                ),
                key=lambda item: item.sort_key,
            )
        ),
        output_refs=(ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=foreign_frame_id),),
        validated_parameters=parameters,
        execution_manifest_id=_digest("foreign camera execution"),
    )
    with sqlite3.connect(started.database) as connection:
        raw = str(
            connection.execute(
                "SELECT pack_json FROM evidence_packs WHERE run_id = ? AND pack_id = ?",
                (RUN_ID, started.pack_id),
            ).fetchone()[0]
        )
        payload = json.loads(raw)
        payload["tool_results"] = [tool_result.model_dump(mode="json")]
        payload["key_frame_ids"] = sorted((*payload["key_frame_ids"], foreign_frame_id))
        corrupted = canonical_json(payload)

        def tamper() -> None:
            connection.execute(
                """
                UPDATE evidence_packs
                SET pack_json = ?, document_sha256 = ?
                WHERE run_id = ? AND pack_id = ?
                """,
                (
                    corrupted,
                    hashlib.sha256(corrupted.encode("utf-8")).hexdigest(),
                    RUN_ID,
                    started.pack_id,
                ),
            )

        _drop_restore_trigger(connection, "evidence_packs_no_update", tamper)

    result = _scan(started.database)
    assert any(
        item.reason_code in {"BASE_DOCUMENT_CONTRACT_INVALID", "BASE_INDEX_BINDING_MISMATCH"}
        for item in result.failures
    )
    with pytest.raises(M4ProjectionFailure):
        rebuild_m4_projection(
            run_id=RUN_ID,
            database_path=started.database,
            workspace_root=tmp_path / "foreign-escape-projection",
        )


def test_m4_projection_does_not_select_partial_generation(tmp_path: Path) -> None:
    started = _started_hearing(tmp_path)
    output_root = tmp_path / "projection-output"
    first = rebuild_m4_projection(
        run_id=RUN_ID,
        database_path=started.database,
        workspace_root=output_root,
    )
    original_pointer = first.current_pointer_path.read_bytes()
    retrieval = HearingPrecedentRetrievalReceipt(
        run_id=RUN_ID,
        case_id=started.session.case_id,
        hearing_session_id=started.session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=started.pack_id,
        current_evidence_pack_version=started.pack_version,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        rule_version="laboratory-v1",
        top_k=0,
        query_sha256=_digest("readonly projection query"),
        candidate_snapshot_sha256=_digest("readonly candidates"),
        visible_snapshot_sha256=_digest("readonly visible"),
        status=HearingPrecedentRetrievalStatus.SUCCESS,
        retriever_version="fake-retriever-v1",
        retriever_manifest_id=_digest("readonly retriever"),
        embedding_model_manifest_id=_digest("readonly embedding"),
        manifest_id=started.session.manifest_id,
    )
    started.repository.append_precedent_retrieval(RUN_ID, retrieval)

    def fail_before_current(phase: str) -> None:
        if phase == "before_current":
            raise RuntimeError("simulated crash before current")

    with pytest.raises(M4ProjectionFailure):
        rebuild_m4_projection(
            run_id=RUN_ID,
            database_path=started.database,
            workspace_root=output_root,
            fault_injector=fail_before_current,
        )

    assert first.current_pointer_path.read_bytes() == original_pointer
    committed = rebuild_m4_projection(
        run_id=RUN_ID,
        database_path=started.database,
        workspace_root=output_root,
    )
    assert committed.generation_id != first.generation_id


def test_m4_projection_detects_tampered_selected_generation(tmp_path: Path) -> None:
    started = _started_hearing(tmp_path)
    output_root = tmp_path / "projection-output"
    result = rebuild_m4_projection(
        run_id=RUN_ID,
        database_path=started.database,
        workspace_root=output_root,
    )
    original_pointer = result.current_pointer_path.read_bytes()
    result.document_paths[0].write_bytes(b"{}")

    with pytest.raises(M4ProjectionFailure):
        rebuild_m4_projection(
            run_id=RUN_ID,
            database_path=started.database,
            workspace_root=output_root,
        )

    assert result.current_pointer_path.read_bytes() == original_pointer

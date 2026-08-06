import hashlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    RepositoryIntegrityError,
    SQLiteEvidenceRepository,
)
from labcourt.contracts.enums import (
    ArgumentStance,
    ArtifactKind,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    ModelParseStatus,
    PrivacyPolicy,
    ViolationType,
    VlmRole,
)
from labcourt.contracts.hearing import (
    HearingCycleScope,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
    HearingRoleOutput,
    HearingSession,
    HearingSessionEntryStatus,
    HearingUsageReceipt,
    ProsecutorModelPayload,
    derive_hearing_model_response_id,
)
from labcourt.contracts.m3_models import PromptManifest, VlmCallBudget
from labcourt.contracts.screening import VLMMediaRef
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import Argument
from labcourt.domain.hearing_fsm import begin_hearing
from labcourt.ports.hearing_repository import HearingModelCallClaimStatus

BUSY_TIMEOUT_MS = 5_000
RUN_ID = "m4-repository-run"
CASE_ID = "case-m4-repository"
MANIFEST_ID = "a" * 64
NOW = "2026-07-28T01:02:03.000000Z"


def _clock() -> datetime:
    return datetime(2026, 7, 28, 1, 2, 3, tzinfo=UTC)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _seed_entry_authority(database: Path) -> tuple[str, str]:
    pack_id = _digest("m4-repository-pack")
    screening_id = _digest("m4-repository-screening")
    event_json = '{"event_id":"event-m4-repository"}'
    case_json = '{"case_id":"case-m4-repository","status":"EVIDENCE_READY"}'
    audit_json = '{"action":"CREATE","object_id":"case-m4-repository"}'
    pack_json = '{"schema_version":"fixture-pack"}'
    screening_json = '{"schema_version":"fixture-screening"}'
    with sqlite3.connect(database) as connection:
        # The fixture supplies the already-tested M2/M3 entry roots. M4 writes
        # run with foreign keys enabled and retain every M4 trigger.
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            """
            INSERT INTO run_manifests(
                manifest_id, schema_version, document_json,
                document_sha256, registered_at
            ) VALUES (?, '1.0', '{}', ?, ?)
            """,
            (MANIFEST_ID, _digest("{}"), NOW),
        )
        connection.execute(
            """
            INSERT INTO runs(
                run_id, manifest_id, revision,
                audit_head_sequence, audit_head_hash, registered_at
            ) VALUES (?, ?, 0, -1, ?, ?)
            """,
            (RUN_ID, MANIFEST_ID, "0" * 64, NOW),
        )
        connection.execute(
            """
            INSERT INTO audit_entries(
                run_id, sequence, manifest_id, actor, action,
                object_kind, object_id, before_sha256, after_sha256,
                recorded_at, prev_entry_hash, entry_hash,
                entry_json, document_sha256
            ) VALUES (?, 0, ?, 'MIGRATION_TEST', 'CREATE', 'CASE', ?, NULL, ?,
                      ?, ?, ?, ?, ?)
            """,
            (
                RUN_ID,
                MANIFEST_ID,
                CASE_ID,
                _digest(case_json),
                NOW,
                "0" * 64,
                _digest(audit_json),
                audit_json,
                _digest(audit_json),
            ),
        )
        connection.execute(
            """
            UPDATE runs
            SET revision = 1, audit_head_sequence = 0, audit_head_hash = ?
            WHERE run_id = ?
            """,
            (_digest(audit_json), RUN_ID),
        )
        connection.execute(
            """
            INSERT INTO cases(
                run_id, case_id, event_id, manifest_id, status,
                current_revision, latest_pack_id, latest_pack_version,
                event_json, event_sha256, created_audit_sequence
            ) VALUES (?, ?, 'event-m4-repository', ?, 'EVIDENCE_READY',
                      1, ?, 1, ?, ?, 0)
            """,
            (RUN_ID, CASE_ID, MANIFEST_ID, pack_id, event_json, _digest(event_json)),
        )
        connection.execute(
            """
            INSERT INTO case_versions(
                run_id, case_id, revision, status,
                case_json, document_sha256, audit_sequence
            ) VALUES (?, ?, 1, 'EVIDENCE_READY', ?, ?, 0)
            """,
            (RUN_ID, CASE_ID, case_json, _digest(case_json)),
        )
        connection.execute(
            """
            INSERT INTO evidence_packs(
                run_id, pack_id, case_id, manifest_id, version, complete,
                pack_input_sha256, closure_input_sha256,
                pack_json, document_sha256, created_audit_sequence
            ) VALUES (?, ?, ?, ?, 1, 1, ?, ?, ?, ?, 0)
            """,
            (
                RUN_ID,
                pack_id,
                CASE_ID,
                MANIFEST_ID,
                _digest("pack-input"),
                _digest("closure-input"),
                pack_json,
                _digest(pack_json),
            ),
        )
        connection.execute(
            """
            INSERT INTO screening_results(
                run_id, screening_id, case_id, version,
                evidence_pack_id, evidence_pack_version,
                parsed_output_id, decision, manifest_id,
                audit_sequence, result_json, document_sha256
            ) VALUES (?, ?, ?, 1, ?, 1, ?, 'ESCALATE', ?, 0, ?, ?)
            """,
            (
                RUN_ID,
                screening_id,
                CASE_ID,
                pack_id,
                _digest("fixture-parsed-output"),
                MANIFEST_ID,
                screening_json,
                _digest(screening_json),
            ),
        )
    return pack_id, screening_id


def _session_and_cycle(pack_id: str, screening_id: str) -> tuple[HearingSession, HearingCycleScope]:
    session = HearingSession(
        run_id=RUN_ID,
        case_id=CASE_ID,
        screening_id=screening_id,
        entry_status=HearingSessionEntryStatus.ESCALATED,
        initial_evidence_pack_id=pack_id,
        initial_evidence_pack_version=1,
        acquisition_round_limit=2,
        rework_round_limit=2,
        max_total_images=64,
        max_total_output_tokens=10_000,
        hearing_prompt_bundle_sha256=_digest("m4-prompt-bundle"),
        prosecutor_model_manifest_id=_digest("m4-prosecutor-model"),
        defender_model_manifest_id=_digest("m4-defender-model"),
        judge_model_manifest_id=_digest("m4-judge-model"),
        manifest_id=MANIFEST_ID,
    )
    cycle = HearingCycleScope(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        cycle_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=pack_id,
        cycle_evidence_pack_version=1,
        manifest_id=MANIFEST_ID,
    )
    return session, cycle


def _model_request(
    session: HearingSession,
    retrieval: HearingPrecedentRetrievalReceipt,
    *,
    role: VlmRole = VlmRole.PROSECUTOR,
    prosecutor_output_id: str | None = None,
) -> HearingModelRequest:
    media_sha256 = _digest("m4-request-media")
    crop_id = _digest("m4-request-crop")
    media = VLMMediaRef(
        crop_id=crop_id,
        media_sha256=media_sha256,
        local_path=f"{RUN_ID}/frames/{media_sha256}.png",
        source=CropSource.DETECTION_FOCUS,
        media_access=MediaAccess.LOCAL_ONLY,
        privacy_policy=PrivacyPolicy.FULL_REDACTION,
        privacy_transform_version="privacy-v1",
        width=8,
        height=8,
    )
    model_manifest_id = {
        VlmRole.PROSECUTOR: session.prosecutor_model_manifest_id,
        VlmRole.DEFENDER: session.defender_model_manifest_id,
        VlmRole.JUDGE: session.judge_model_manifest_id,
    }[role]
    return HearingModelRequest(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=retrieval.current_evidence_pack_id,
        current_evidence_pack_version=1,
        screening_ref=ArtifactRef(
            kind=ArtifactKind.SCREENING_RESULT,
            artifact_id=session.screening_id,
        ),
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        evidence_class=EvidenceClass.PRESENCE,
        role=role,
        provider_profile=f"fake-{role.value.lower()}",
        provider="fixture",
        model=f"fixture-{role.value.lower()}",
        revision="1.0.0",
        model_manifest_id=model_manifest_id,
        execution_location=ExecutionLocation.LOCAL,
        prompt_manifest=PromptManifest(
            prompt_id=f"hearing_{role.value.lower()}_v1",
            role=role,
            template_sha256=_digest(f"{role.value}-template"),
            output_schema_sha256=_digest(f"{role.value}-schema"),
            prompt_bundle_sha256=session.hearing_prompt_bundle_sha256,
            renderer_version="fixture-renderer-v1",
        ),
        hearing_prompt_bundle_sha256=session.hearing_prompt_bundle_sha256,
        rendered_prompt_sha256=_digest(f"{role.value}-rendered"),
        hearing_context_sha256=_digest("m4-hearing-context"),
        media=(media,),
        allowed_evidence_refs=(ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop_id),),
        prosecutor_output_ref=(
            ArtifactRef(
                kind=ArtifactKind.PARSED_MODEL_OUTPUT,
                artifact_id=prosecutor_output_id,
            )
            if prosecutor_output_id is not None
            else None
        ),
        precedent_retrieval_degraded=False,
        precedent_retrieval_receipt_id=retrieval.receipt_id,
        precedent_retrieval_receipt_sha256=retrieval.receipt_sha256,
        temperature=0.0,
        seed=7,
        budget=VlmCallBudget(
            max_images=1,
            max_input_pixels=64,
            max_input_tokens=256,
            max_output_tokens=128,
            pricing_currency="USD",
            input_cost_per_million_tokens=0.0,
            output_cost_per_million_tokens=0.0,
            max_estimated_cost=0.0,
            max_response_bytes=8_192,
            max_json_depth=8,
            max_json_fields=128,
            max_string_chars=1_024,
            timeout_seconds=5.0,
            claim_completion_grace_seconds=5.0,
        ),
        manifest_id=MANIFEST_ID,
    )


def _response_and_usage(
    request: HearingModelRequest,
) -> tuple[HearingModelResponse, HearingUsageReceipt]:
    content_sha256 = _digest(f"raw-{request.role.value}-{request.attempt_index}")
    response_id = derive_hearing_model_response_id(
        request.run_id,
        request.request_id,
        content_sha256,
    )
    response = HearingModelResponse(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        prior_acquisition_rounds=request.prior_acquisition_rounds,
        prior_rework_rounds=request.prior_rework_rounds,
        current_evidence_pack_id=request.current_evidence_pack_id,
        current_evidence_pack_version=request.current_evidence_pack_version,
        role=request.role,
        attempt_index=request.attempt_index,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        raw_response_ref=f"{RUN_ID}/model_responses/{response_id}.json",
        content_sha256=content_sha256,
        size_bytes=64,
        input_tokens=10,
        output_tokens=5,
        latency_ms=7,
        model_manifest_id=request.model_manifest_id,
        manifest_id=request.manifest_id,
    )
    usage = HearingUsageReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        role=request.role,
        request_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_REQUEST,
            artifact_id=request.request_id,
        ),
        response_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=response.response_id,
        ),
        input_images=len(request.media),
        input_pixels=sum(item.width * item.height for item in request.media),
        input_tokens=response.input_tokens,
        output_tokens=response.output_tokens,
        latency_ms=response.latency_ms,
        retry_count=0,
        estimated_cost=0.0,
        manifest_id=request.manifest_id,
    )
    return response, usage


def test_start_hearing_is_atomic_idempotent_and_typed_on_reload(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    pack_id, screening_id = _seed_entry_authority(database)
    session, cycle = _session_and_cycle(pack_id, screening_id)
    checkpoint = begin_hearing(session)
    repository = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS, clock=_clock)

    repository.start_hearing(RUN_ID, session, cycle, checkpoint)
    repository.start_hearing(RUN_ID, session, cycle, checkpoint)

    assert repository.load_hearing_session(RUN_ID, session.session_id) == session
    assert repository.load_hearing_cycle(RUN_ID, cycle.cycle_id) == cycle
    assert repository.load_hearing_checkpoint(RUN_ID, checkpoint.checkpoint_id) == checkpoint
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM m4_hearings").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM m4_hearing_cycles").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM m4_hearing_checkpoints").fetchone() == (1,)


def test_start_hearing_fault_rolls_back_all_three_roots(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    pack_id, screening_id = _seed_entry_authority(database)
    session, cycle = _session_and_cycle(pack_id, screening_id)
    checkpoint = begin_hearing(session)

    def fault(point: str) -> None:
        if point == "hearing.start.before_commit":
            raise RuntimeError("injected M4 hearing fault")

    repository = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        fault_injector=fault,
    )
    with pytest.raises(RuntimeError, match="injected M4 hearing fault"):
        repository.start_hearing(RUN_ID, session, cycle, checkpoint)

    with sqlite3.connect(database) as connection:
        for table in (
            "m4_hearings",
            "m4_hearing_cycles",
            "m4_hearing_checkpoints",
        ):
            assert connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone() == (0,)


def test_typed_load_rejects_noncanonical_cycle_document(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    pack_id, screening_id = _seed_entry_authority(database)
    session, cycle = _session_and_cycle(pack_id, screening_id)
    repository = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS, clock=_clock)
    repository.start_hearing(RUN_ID, session, cycle, begin_hearing(session))

    with sqlite3.connect(database) as connection:
        trigger_sql = str(
            connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'trigger' AND name = 'm4_hearing_cycles_no_update'
                """
            ).fetchone()[0]
        )
        connection.execute("DROP TRIGGER m4_hearing_cycles_no_update")
        raw = str(
            connection.execute(
                "SELECT cycle_json FROM m4_hearing_cycles WHERE run_id = ? AND cycle_id = ?",
                (RUN_ID, cycle.cycle_id),
            ).fetchone()[0]
        )
        connection.execute(
            "UPDATE m4_hearing_cycles SET cycle_json = ? WHERE run_id = ? AND cycle_id = ?",
            (raw + " ", RUN_ID, cycle.cycle_id),
        )
        connection.execute(trigger_sql)

    with pytest.raises(RepositoryIntegrityError, match="canonical contract document"):
        repository.load_hearing_cycle(RUN_ID, cycle.cycle_id)


def test_precedent_retrieval_binds_exact_cycle_id_and_hash(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    pack_id, screening_id = _seed_entry_authority(database)
    session, cycle = _session_and_cycle(pack_id, screening_id)
    repository = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS, clock=_clock)
    repository.start_hearing(RUN_ID, session, cycle, begin_hearing(session))
    receipt = HearingPrecedentRetrievalReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=pack_id,
        current_evidence_pack_version=1,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        rule_version="laboratory-v1",
        top_k=0,
        query_sha256=_digest("precedent-query"),
        candidate_snapshot_sha256=_digest("candidate-snapshot"),
        visible_snapshot_sha256=_digest("visible-snapshot"),
        status=HearingPrecedentRetrievalStatus.SUCCESS,
        retriever_version="fake-retriever-v1",
        retriever_manifest_id=_digest("retriever-manifest"),
        embedding_model_manifest_id=_digest("embedding-manifest"),
        manifest_id=MANIFEST_ID,
    )

    repository.append_precedent_retrieval(RUN_ID, receipt)
    repository.append_precedent_retrieval(RUN_ID, receipt)

    assert repository.load_precedent_retrieval(RUN_ID, receipt.receipt_id) == receipt
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            """
            SELECT cycle_scope_id, cycle_scope_sha256
            FROM m4_precedent_retrieval_receipts
            WHERE run_id = ? AND retrieval_receipt_id = ?
            """,
            (RUN_ID, receipt.receipt_id),
        ).fetchone() == (cycle.cycle_id, cycle.cycle_sha256)


def test_model_call_completion_is_atomic_idempotent_and_role_ordered(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    pack_id, screening_id = _seed_entry_authority(database)
    session, cycle = _session_and_cycle(pack_id, screening_id)
    repository = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS, clock=_clock)
    repository.start_hearing(RUN_ID, session, cycle, begin_hearing(session))
    retrieval = HearingPrecedentRetrievalReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=pack_id,
        current_evidence_pack_version=1,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        rule_version="laboratory-v1",
        top_k=0,
        query_sha256=_digest("model-precedent-query"),
        candidate_snapshot_sha256=_digest("model-candidates"),
        visible_snapshot_sha256=_digest("model-visible"),
        status=HearingPrecedentRetrievalStatus.SUCCESS,
        retriever_version="fake-retriever-v1",
        retriever_manifest_id=_digest("model-retriever"),
        embedding_model_manifest_id=_digest("model-embedding"),
        manifest_id=MANIFEST_ID,
    )
    repository.append_precedent_retrieval(RUN_ID, retrieval)

    with pytest.raises(ValueError, match="defender request requires"):
        # The contract itself prevents omitting the ordered prosecutor binding.
        _model_request(session, retrieval, role=VlmRole.DEFENDER)

    request = _model_request(session, retrieval)
    response, usage = _response_and_usage(request)
    owner = "m4-owner-token-000000000000000000"
    assert (
        repository.claim_hearing_model_call(RUN_ID, request, owner).status
        == HearingModelCallClaimStatus.ACQUIRED
    )
    assert (
        repository.claim_hearing_model_call(RUN_ID, request, owner).status
        == HearingModelCallClaimStatus.WAITING
    )

    cache = repository.complete_hearing_model_call(
        RUN_ID,
        request,
        response,
        usage,
        owner,
    )
    assert (
        repository.complete_hearing_model_call(
            RUN_ID,
            request,
            response,
            usage,
            owner,
        )
        == cache
    )
    assert repository.load_hearing_model_request(RUN_ID, request.request_id) == request
    assert repository.load_hearing_model_response(RUN_ID, response.response_id) == response
    assert repository.load_hearing_model_cache_entry(RUN_ID, request.cache_key) == cache
    assert repository.load_hearing_usage_receipt(RUN_ID, usage.usage_receipt_id) == usage

    payload = ProsecutorModelPayload(
        arguments=(
            Argument(
                stance=ArgumentStance.PROSECUTION,
                claim="The cited crop supports the alleged laboratory rule violation.",
                evidence_refs=request.allowed_evidence_refs,
                uncertainty=0.1,
            ),
        ),
        case_summary="The prosecution relies only on the typed crop reference.",
    )
    parse_receipt = HearingModelParseReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=1,
        role=VlmRole.PROSECUTOR,
        attempt_index=0,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        parser_version="strict-parser-v1",
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.PARSED,
        parsed_payload_sha256=payload.payload_sha256,
        manifest_id=MANIFEST_ID,
    )
    output = HearingRoleOutput(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=pack_id,
        current_evidence_pack_version=1,
        prompt_manifest=request.prompt_manifest,
        model_manifest_id=request.model_manifest_id,
        request_ref=usage.request_ref,
        response_ref=usage.response_ref,
        parse_receipt_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_PARSE_RECEIPT,
            artifact_id=parse_receipt.parse_receipt_id,
        ),
        precedent_retrieval_degraded=False,
        precedent_retrieval_receipt_id=retrieval.receipt_id,
        precedent_retrieval_receipt_sha256=retrieval.receipt_sha256,
        payload=payload,
        manifest_id=MANIFEST_ID,
    )
    repository.append_hearing_parse_receipt(parse_receipt, output)
    repository.append_hearing_parse_receipt(parse_receipt, output)
    assert (
        repository.load_hearing_parse_receipt(RUN_ID, parse_receipt.parse_receipt_id)
        == parse_receipt
    )
    assert repository.load_hearing_role_output(RUN_ID, output.output_id) == output

    defender = _model_request(
        session,
        retrieval,
        role=VlmRole.DEFENDER,
        prosecutor_output_id=output.output_id,
    )
    assert (
        repository.claim_hearing_model_call(RUN_ID, defender, owner).status
        == HearingModelCallClaimStatus.ACQUIRED
    )
    # No checkpoint has advanced yet.  Resume derives the exact completed
    # prosecutor call and the pending defender claim from durable roots rather
    # than creating a fresh request (or resetting either budget reservation).
    assert repository.list_hearing_model_requests(RUN_ID, session.session_id) == (
        request,
        defender,
    )
    assert repository.list_hearing_model_responses(RUN_ID, session.session_id) == (response,)
    assert repository.list_hearing_usage_receipts(RUN_ID, session.session_id) == (usage,)
    assert repository.list_hearing_parse_receipts(RUN_ID, session.session_id) == (parse_receipt,)
    assert repository.list_hearing_role_outputs(RUN_ID, session.session_id) == (output,)
    assert (
        repository.claim_hearing_model_call(RUN_ID, request, owner).status
        == HearingModelCallClaimStatus.COMPLETED
    )
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM m4_model_call_claims").fetchone() == (2,)


def test_model_call_fault_rolls_back_response_cache_usage_and_completion(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    pack_id, screening_id = _seed_entry_authority(database)
    session, cycle = _session_and_cycle(pack_id, screening_id)

    def fault(point: str) -> None:
        if point == "hearing.model.complete.after_response":
            raise RuntimeError("injected hearing response fault")

    repository = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        fault_injector=fault,
    )
    repository.start_hearing(RUN_ID, session, cycle, begin_hearing(session))
    retrieval = HearingPrecedentRetrievalReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=pack_id,
        current_evidence_pack_version=1,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        rule_version="laboratory-v1",
        top_k=0,
        query_sha256=_digest("fault-precedent-query"),
        candidate_snapshot_sha256=_digest("fault-candidates"),
        visible_snapshot_sha256=_digest("fault-visible"),
        status=HearingPrecedentRetrievalStatus.SUCCESS,
        retriever_version="fake-retriever-v1",
        retriever_manifest_id=_digest("fault-retriever"),
        embedding_model_manifest_id=_digest("fault-embedding"),
        manifest_id=MANIFEST_ID,
    )
    repository.append_precedent_retrieval(RUN_ID, retrieval)
    request = _model_request(session, retrieval)
    response, usage = _response_and_usage(request)
    owner = "m4-owner-token-000000000000000000"
    repository.claim_hearing_model_call(RUN_ID, request, owner)

    with pytest.raises(RuntimeError, match="injected hearing response fault"):
        repository.complete_hearing_model_call(
            RUN_ID,
            request,
            response,
            usage,
            owner,
        )

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT status, response_id FROM m4_model_call_claims"
        ).fetchone() == ("ACTIVE", None)
        for table in (
            "m4_model_responses",
            "m4_model_cache",
            "m4_hearing_usage_receipts",
        ):
            assert connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone() == (0,)

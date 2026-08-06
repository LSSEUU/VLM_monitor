from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.fake_hearing_precedents import (
    FakeHearingPrecedentRetriever,
)
from labcourt.adapters.hearing_prompt_renderer import HearingJinjaPromptCatalog
from labcourt.adapters.storage import (
    SecureHearingModelResponseStore,
    SecureWorkspace,
    SQLiteEvidenceRepository,
)
from labcourt.adapters.storage.sqlite_m3_repository import SQLiteM3Repository
from labcourt.adapters.vlm import (
    OUTAGE_FIXTURE,
    DeterministicFakeHearingVLMClient,
    FakeVLMFixture,
    VLMDeliveryCertainty,
    VLMProviderFailureCode,
)
from labcourt.application.hearing_acquisition import HearingAcquisitionService
from labcourt.application.hearing_coordinator import HearingCoordinator
from labcourt.application.hearing_model_parser import (
    finalize_hearing_parse,
    inspect_hearing_response,
)
from labcourt.application.hearing_precedent_retrieval import (
    HearingPrecedentRetrievalService,
)
from labcourt.application.hearing_procedural_review import (
    DeterministicHearingProceduralReviewVerifier,
)
from labcourt.application.hearing_request import (
    HearingBudgetUsage,
    PreparedHearingRequest,
    prepare_primary_hearing_request,
)
from labcourt.application.hearing_role_call import HearingRoleCallService
from labcourt.application.hearing_role_output import build_hearing_role_output
from labcourt.application.hearing_session import prepare_hearing_session
from labcourt.application.hearing_situation import build_hearing_situation_text
from labcourt.application.procedural_review import (
    DeterministicProceduralReviewVerifier,
)
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.enums import (
    AcquisitionAction,
    AcquisitionExecutionMode,
    AlertLevel,
    ArgumentStance,
    ArtifactKind,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
    CaseStatus,
    JudgeDisposition,
    PrecedentApplicationMode,
    VerdictDecision,
    VlmRole,
)
from labcourt.contracts.evidence import TrackConfidenceCurveParameters
from labcourt.contracts.hearing import (
    AcquisitionRequestPayload,
    DefenderModelPayload,
    HearingCheckpointPhase,
    HearingModelRequest,
    HearingModelResponse,
    HearingUsageReceipt,
    JudgeAcquisitionDecisionPayload,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
    ProsecutorModelPayload,
    derive_hearing_model_response_id,
)
from labcourt.contracts.m3_models import EvidenceCitation
from labcourt.contracts.model_call_failures import ModelCallFailureClosureKind
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import Argument, JudgeResponse, PrecedentApplication
from labcourt.domain.evidence_authority import (
    HearingEvidenceGrant,
    derive_evidence_authority,
)
from labcourt.domain.hearing_fsm import (
    HearingCallClosure,
    HearingCallTrace,
    complete_defender,
    complete_precedent_retrieval,
    complete_prosecutor,
)
from labcourt.ports.hearing_acquisition import (
    HearingAcquisitionRecovery,
    HearingAcquisitionRecoveryStatus,
)
from labcourt.ports.prompts import RenderedPrompt
from tests.integration.test_m3_sqlite_repository import (
    BUSY_TIMEOUT_MS,
    ROOT,
    RUN_ID,
    _clock,
    _complete_call,
    _draft,
    _parsed,
    _parsed_receipt,
    _RawVerifier,
    _register_case,
    _repository,
    _request,
    _response,
    _screening_for,
    _Verifier,
)
from tests.unit.test_m4_hearing_prompt_renderer import (
    _hearing_schema_documents,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class _PromptRegistrar:
    def __init__(self) -> None:
        self.values: dict[str, object] = {}

    def register(self, rendered: RenderedPrompt) -> None:
        identity = rendered.rendered_prompt_sha256
        existing = self.values.get(identity)
        if existing is not None:
            assert existing == rendered
        self.values[identity] = rendered


class _NeverAcquisitionExecutor:
    @property
    def execution_mode(self) -> AcquisitionExecutionMode:
        return AcquisitionExecutionMode.PURE

    def execute(self, request, authority, *, idempotency_key):
        del request, authority, idempotency_key
        raise AssertionError("terminal fixture must not execute acquisition")

    def recover(self, request, authority, *, idempotency_key):
        del request, authority, idempotency_key
        return HearingAcquisitionRecovery(status=HearingAcquisitionRecoveryStatus.UNKNOWN)


class _CountingHearingVLMClient:
    def __init__(self, delegate: DeterministicFakeHearingVLMClient) -> None:
        self._delegate = delegate
        self.calls: list[HearingModelRequest] = []

    def complete(self, request: HearingModelRequest) -> HearingModelResponse:
        self.calls.append(request)
        return self._delegate.complete(request)


def _escalated_case(tmp_path: Path):
    database, evidence = _repository(tmp_path)
    _register_case(evidence)
    draft = _draft(version=1, complete=True)
    source_crop = draft.focus_crops[0]
    crop = source_crop.model_copy(
        update={"local_path": (f"{RUN_ID}/frames/{source_crop.media_sha256}.png")}
    )
    draft = draft.model_copy(update={"focus_crops": (crop,)})
    published = evidence.publish_pack(RUN_ID, 1, draft)
    pack = published.pack
    closure = evidence.verify_current_pack(RUN_ID, pack.pack_id)
    config = load_config(ROOT / "configs" / "demo.yaml")
    m3 = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=_RawVerifier(),
        procedural_review_verifier=DeterministicProceduralReviewVerifier(
            config,
            evidence,
        ),
    )
    snapshot = published.case
    audit_head = evidence.get_audit_head(RUN_ID)
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
    assert committed.case.case.status == CaseStatus.ESCALATED
    return database, evidence, pack, committed.case


def _response_for(
    prepared: PreparedHearingRequest,
    raw: bytes,
) -> HearingModelResponse:
    request = prepared.request
    content_sha256 = hashlib.sha256(raw).hexdigest()
    response_id = derive_hearing_model_response_id(
        request.run_id,
        request.request_id,
        content_sha256,
    )
    return HearingModelResponse(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        prior_acquisition_rounds=request.prior_acquisition_rounds,
        prior_rework_rounds=request.prior_rework_rounds,
        current_evidence_pack_id=request.current_evidence_pack_id,
        current_evidence_pack_version=request.current_evidence_pack_version,
        role=request.role,
        attempt_index=0,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        raw_response_ref=f"{request.run_id}/model_responses/{response_id}.json",
        content_sha256=content_sha256,
        size_bytes=len(raw),
        input_tokens=2,
        output_tokens=3,
        latency_ms=4,
        model_manifest_id=request.model_manifest_id,
        manifest_id=request.manifest_id,
    )


def _simulated_call(
    prepared: PreparedHearingRequest,
    payload: ProsecutorModelPayload | DefenderModelPayload | JudgeModelPayload,
):
    raw = canonical_bytes(payload.model_dump(mode="json", exclude_computed_fields=True))
    response = _response_for(prepared, raw)
    parsed = finalize_hearing_parse(
        inspect_hearing_response(
            raw,
            request=prepared.request,
            response=response,
        )
    )
    assert parsed.payload is not None
    output = build_hearing_role_output(
        request=prepared.request,
        response=response,
        parse_receipt=parsed.receipt,
        payload=parsed.payload,
    )
    request = prepared.request
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
        estimated_cost=request.budget.estimate_cost(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        ),
        manifest_id=request.manifest_id,
    )
    trace = HearingCallTrace(
        calls=(
            HearingCallClosure(
                request=request,
                response=response,
                parse_receipt=parsed.receipt,
                usage=usage,
            ),
        )
    )
    return raw, output, trace


def _crop_ref(prepared: PreparedHearingRequest) -> ArtifactRef:
    return next(
        item for item in prepared.request.allowed_evidence_refs if item.kind == ArtifactKind.CROP
    )


def _fixtures_for_terminal_hearing(
    *,
    source_case,
    config,
    manifest,
    catalog,
    precedents,
    judge_requests_acquisition: bool = False,
    include_precedent_applications: bool = False,
) -> dict[str, FakeVLMFixture]:
    prepared_session = prepare_hearing_session(
        source_case,
        config=config,
        run_manifest=manifest,
        catalog=catalog,
    )
    session = prepared_session.session
    cycle = prepared_session.cycle_scope
    checkpoint = prepared_session.checkpoint
    evidence = derive_evidence_authority(prepared_session.evidence_pack)
    retrieval = precedents.retrieve(
        session=session,
        cycle_scope=cycle,
        evidence_pack=evidence.pack,
        run_manifest=manifest,
        config=config,
        situation_text=build_hearing_situation_text(evidence.pack),
    ).receipt
    checkpoint = complete_precedent_retrieval(session, checkpoint, retrieval)

    usage = HearingBudgetUsage()
    grant: HearingEvidenceGrant | None = None
    prosecutor = prepare_primary_hearing_request(
        role=VlmRole.PROSECUTOR,
        session=session,
        cycle_scope=cycle,
        retrieval=retrieval,
        evidence_pack=evidence.pack,
        evidence_authority=evidence,
        hearing_grant=grant,
        budget_usage=usage,
        config=config,
        run_manifest=manifest,
        catalog=catalog,
    )
    prosecution_argument = Argument(
        stance=ArgumentStance.PROSECUTION,
        claim="The disclosed crop supports the allegation.",
        evidence_refs=(_crop_ref(prosecutor),),
        uncertainty=0.1,
    )
    prosecutor_raw, prosecutor_output, prosecutor_trace = _simulated_call(
        prosecutor,
        ProsecutorModelPayload(
            arguments=(prosecution_argument,),
            case_summary="The prosecution uses only disclosed evidence.",
        ),
    )
    checkpoint = complete_prosecutor(
        session,
        checkpoint,
        prosecutor_output,
        prosecutor_trace,
    )
    grant = prosecutor.hearing_grant
    usage = HearingBudgetUsage(
        reserved_images=len(prosecutor.request.media),
        accounted_output_tokens=3,
    )

    defender = prepare_primary_hearing_request(
        role=VlmRole.DEFENDER,
        session=session,
        cycle_scope=cycle,
        retrieval=retrieval,
        evidence_pack=evidence.pack,
        evidence_authority=evidence,
        hearing_grant=grant,
        budget_usage=usage,
        config=config,
        run_manifest=manifest,
        catalog=catalog,
        prosecutor_output=prosecutor_output,
    )
    defense_argument = Argument(
        stance=ArgumentStance.DEFENSE,
        claim="The defense preserves one bounded objection.",
        evidence_refs=(_crop_ref(defender),),
        uncertainty=0.2,
    )
    defender_raw, defender_output, defender_trace = _simulated_call(
        defender,
        DefenderModelPayload(
            arguments=(defense_argument,),
            case_summary="The defense uses only disclosed evidence.",
        ),
    )
    checkpoint = complete_defender(
        session,
        checkpoint,
        defender_output,
        defender_trace,
    )
    grant = defender.hearing_grant
    usage = HearingBudgetUsage(
        reserved_images=len(prosecutor.request.media) + len(defender.request.media),
        accounted_output_tokens=6,
    )

    judge = prepare_primary_hearing_request(
        role=VlmRole.JUDGE,
        session=session,
        cycle_scope=cycle,
        retrieval=retrieval,
        evidence_pack=evidence.pack,
        evidence_authority=evidence,
        hearing_grant=grant,
        budget_usage=usage,
        config=config,
        run_manifest=manifest,
        catalog=catalog,
        prosecutor_output=prosecutor_output,
        defender_output=defender_output,
    )
    judge_outcome = (
        JudgeAcquisitionDecisionPayload(
            request=AcquisitionRequestPayload(
                action=AcquisitionAction.TRACK_CONFIDENCE_CURVE,
                validated_parameters=TrackConfidenceCurveParameters(
                    action=AcquisitionAction.TRACK_CONFIDENCE_CURVE,
                    track_ref=evidence.pack.event.primary_track_ref,
                    start_frame=evidence.pack.event.start_frame,
                    end_frame_exclusive=evidence.pack.event.end_frame_exclusive,
                ),
                reason_summary="Inspect the bounded confidence curve.",
                supporting_evidence_refs=(_crop_ref(judge),),
            )
        )
        if judge_requests_acquisition
        else JudgeFinalDecisionPayload(
            decision=VerdictDecision.ESTABLISHED,
            confidence=0.9,
            recommended_alert_level=AlertLevel.CONFIRMED,
            rationale_summary="The structured record supports the proposal.",
            evidence_citations=(EvidenceCitation(evidence_ref=_crop_ref(judge)),),
        )
    )
    judge_raw, _judge_output, _judge_trace = _simulated_call(
        judge,
        JudgeModelPayload(
            judge_responses=(
                JudgeResponse(
                    defense_argument_id=defense_argument.argument_id,
                    disposition=JudgeDisposition.REJECTED,
                    response_summary="The exact defense point is addressed.",
                ),
            ),
            precedent_applications=(
                tuple(
                    PrecedentApplication(
                        precedent_ref=ArtifactRef(
                            kind=ArtifactKind.PRECEDENT,
                            artifact_id=scored.precedent.precedent_id,
                        ),
                        mode=PrecedentApplicationMode.FOLLOWED,
                        similarity_score=scored.fused_score,
                    )
                    for scored in retrieval.scored_precedents
                )
                if include_precedent_applications
                else ()
            ),
            outcome=judge_outcome,
        ),
    )
    return {
        prosecutor.request.cache_key: FakeVLMFixture.response(
            prosecutor_raw,
            input_tokens=2,
            output_tokens=3,
            latency_ms=4,
        ),
        defender.request.cache_key: FakeVLMFixture.response(
            defender_raw,
            input_tokens=2,
            output_tokens=3,
            latency_ms=4,
        ),
        judge.request.cache_key: FakeVLMFixture.response(
            judge_raw,
            input_tokens=2,
            output_tokens=3,
            latency_ms=4,
        ),
    }


def test_coordinator_runs_full_offline_sqlite_hearing_to_ready(
    tmp_path: Path,
) -> None:
    _database, repository, pack, escalated = _escalated_case(tmp_path)
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest = repository.load_run_manifest(RUN_ID)
    catalog = HearingJinjaPromptCatalog(output_schema_json_by_prompt=_hearing_schema_documents())
    precedents = HearingPrecedentRetrievalService(
        FakeHearingPrecedentRetriever(()),
        retriever_version="fake-hearing-precedents-v1",
        retriever_manifest_id=_digest("fake-hearing-precedents"),
    )
    fixtures = _fixtures_for_terminal_hearing(
        source_case=escalated,
        config=config,
        manifest=manifest,
        catalog=catalog,
        precedents=precedents,
    )
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    with SecureWorkspace(workspace_root, 256 * 1024) as workspace:
        response_store = SecureHearingModelResponseStore(workspace)
        role_calls = HearingRoleCallService(
            repository=repository,
            response_store=response_store,
            vlm_client=DeterministicFakeHearingVLMClient(
                fixtures,
                response_store,
            ),
            prompt_registrar=_PromptRegistrar(),
            owner_token_factory=lambda: "o" * 43,
        )
        coordinator = HearingCoordinator(
            config=config,
            evidence_repository=repository,
            hearing_repository=repository,
            precedent_retrieval=precedents,
            role_calls=role_calls,
            acquisition=HearingAcquisitionService(
                repository=repository,
                executor=_NeverAcquisitionExecutor(),
            ),
            prompt_catalog=catalog,
            review_verifier=DeterministicHearingProceduralReviewVerifier(
                config,
                repository,
            ),
        )
        outcome = coordinator.process_case(RUN_ID, pack.case_id)

    assert outcome.case.case.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert outcome.review is not None and outcome.review.passed
    assert outcome.record is not None and outcome.record.complete
    assert outcome.checkpoint is not None
    assert outcome.cache_hit_count == 0
    assert outcome.recovered_response_count == 0
    assert (
        len(repository.list_hearing_model_requests(RUN_ID, outcome.record.hearing_session_id)) == 3
    )
    assert repository.load_active_hearing(RUN_ID, pack.case_id) is None

    repeated = coordinator.process_case(RUN_ID, pack.case_id)
    assert repeated.case == outcome.case
    assert repeated.verdict == outcome.verdict
    assert repeated.review == outcome.review


def test_coordinator_provider_outage_atomically_backlogs_exact_prosecutor(
    tmp_path: Path,
) -> None:
    database, repository, pack, escalated = _escalated_case(tmp_path)
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest = repository.load_run_manifest(RUN_ID)
    catalog = HearingJinjaPromptCatalog(output_schema_json_by_prompt=_hearing_schema_documents())
    precedents = HearingPrecedentRetrievalService(
        FakeHearingPrecedentRetriever(()),
        retriever_version="fake-hearing-precedents-v1",
        retriever_manifest_id=_digest("fake-hearing-precedents"),
    )
    fixtures = _fixtures_for_terminal_hearing(
        source_case=escalated,
        config=config,
        manifest=manifest,
        catalog=catalog,
        precedents=precedents,
    )
    prosecutor_cache_key = next(iter(fixtures))
    fixtures[prosecutor_cache_key] = OUTAGE_FIXTURE

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
            owner_token_factory=lambda: "o" * 43,
        )
        coordinator = HearingCoordinator(
            config=config,
            evidence_repository=repository,
            hearing_repository=repository,
            precedent_retrieval=precedents,
            role_calls=role_calls,
            acquisition=HearingAcquisitionService(
                repository=repository,
                executor=_NeverAcquisitionExecutor(),
            ),
            prompt_catalog=catalog,
            review_verifier=DeterministicHearingProceduralReviewVerifier(
                config,
                repository,
            ),
        )

        outcome = coordinator.process_case(RUN_ID, pack.case_id)
        repeated = coordinator.process_case(RUN_ID, pack.case_id)

    assert outcome.case.case.status == CaseStatus.BACKLOGGED
    assert outcome.session is not None
    assert outcome.checkpoint is not None
    assert outcome.checkpoint.phase == HearingCheckpointPhase.PROSECUTOR_PENDING
    assert outcome.backlog_item_id is not None
    assert repeated.case == outcome.case
    assert repeated.checkpoint == outcome.checkpoint
    assert repeated.backlog_item_id == outcome.backlog_item_id
    assert [request.role for request in client.calls] == [VlmRole.PROSECUTOR]

    backlog_reader = SQLiteM3Repository(database, BUSY_TIMEOUT_MS, clock=_clock)
    item = backlog_reader.load_backlog_item(RUN_ID, outcome.backlog_item_id)
    assert item.stage == BacklogStage.HEARING
    assert item.role == VlmRole.PROSECUTOR
    assert item.reason_code == BacklogReasonCode.PROVIDER_UNAVAILABLE
    assert item.status == BacklogStatus.PENDING
    assert item.attempt_count == 0
    assert item.retry_generation == 0
    assert outcome.case.case.current_backlog_item_id == item.item_id

    requests = repository.list_hearing_model_requests(
        RUN_ID,
        outcome.session.session_id,
    )
    authorities = repository.list_hearing_failure_authorities(
        RUN_ID,
        outcome.session.session_id,
    )
    assert len(requests) == 1
    assert len(authorities) == 1
    request = requests[0]
    authority = authorities[0]
    head = repository.get_audit_head(RUN_ID)
    assert request.role == VlmRole.PROSECUTOR
    assert authority.request == request
    assert authority.source_checkpoint_id == outcome.checkpoint.checkpoint_id
    assert authority.source_checkpoint_sha256 == outcome.checkpoint.checkpoint_sha256
    assert authority.source_checkpoint_version == outcome.checkpoint.version
    assert authority.claim_owner_sha256 == hashlib.sha256(("o" * 43).encode()).hexdigest()
    assert authority.claim_takeover_count == 0
    assert authority.failure_code == VLMProviderFailureCode.PROVIDER_OUTAGE
    assert authority.delivery_certainty == VLMDeliveryCertainty.DEFINITELY_NOT_SENT
    assert authority.backlog_reason_code == BacklogReasonCode.PROVIDER_UNAVAILABLE
    assert authority.backlog_item_id == item.item_id
    assert authority.backlog_version == 1
    assert authority.backlog_status == BacklogStatus.PENDING
    assert authority.backlog_attempt_count == 0
    assert authority.retry_generation == 0
    assert authority.closure_kind == ModelCallFailureClosureKind.INITIAL_BACKLOG
    assert authority.completion_receipt_id is None
    assert authority.provider_response_content_sha256 is None
    assert authority.reserved_images == len(request.media)
    assert authority.reserved_pixels == sum(media.width * media.height for media in request.media)
    assert authority.disclosed_images == 0
    assert authority.disclosed_pixels == 0
    assert authority.input_tokens == 0
    assert authority.output_tokens == 0
    assert authority.latency_ms == 0
    assert authority.estimated_cost == 0.0
    assert authority.closure_case_revision == outcome.case.revision
    assert authority.closure_audit_sequence == head.sequence
    assert authority.closure_audit_entry_hash == head.entry_hash

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM backlog_items").fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM m4_model_call_failure_authorities"
        ).fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM m4_model_responses").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM m4_hearing_usage_receipts").fetchone() == (
            0,
        )


def test_coordinator_recovers_persisted_prosecutor_after_checkpoint_fault(
    tmp_path: Path,
) -> None:
    database, seed_repository, pack, escalated = _escalated_case(tmp_path)
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest = seed_repository.load_run_manifest(RUN_ID)
    catalog = HearingJinjaPromptCatalog(output_schema_json_by_prompt=_hearing_schema_documents())
    precedents = HearingPrecedentRetrievalService(
        FakeHearingPrecedentRetriever(()),
        retriever_version="fake-hearing-precedents-v1",
        retriever_manifest_id=_digest("fake-hearing-precedents"),
    )
    fixtures = _fixtures_for_terminal_hearing(
        source_case=escalated,
        config=config,
        manifest=manifest,
        catalog=catalog,
        precedents=precedents,
    )
    faulted = False

    def fault(point: str) -> None:
        nonlocal faulted
        if point != "hearing.checkpoint.before_commit" or faulted:
            return
        with sqlite3.connect(database) as connection:
            persisted_responses = connection.execute(
                "SELECT COUNT(*) FROM m4_model_responses"
            ).fetchone()
        if persisted_responses == (1,):
            faulted = True
            raise RuntimeError("injected post-Prosecutor checkpoint fault")

    faulting_repository = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=_clock,
        fault_injector=fault,
    )
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    all_provider_calls: list[HearingModelRequest] = []

    with SecureWorkspace(workspace_root, 256 * 1024) as workspace:
        first_store = SecureHearingModelResponseStore(workspace)
        first_client = _CountingHearingVLMClient(
            DeterministicFakeHearingVLMClient(fixtures, first_store)
        )
        first_role_calls = HearingRoleCallService(
            repository=faulting_repository,
            response_store=first_store,
            vlm_client=first_client,
            prompt_registrar=_PromptRegistrar(),
            owner_token_factory=lambda: "o" * 43,
        )
        first_coordinator = HearingCoordinator(
            config=config,
            evidence_repository=faulting_repository,
            hearing_repository=faulting_repository,
            precedent_retrieval=precedents,
            role_calls=first_role_calls,
            acquisition=HearingAcquisitionService(
                repository=faulting_repository,
                executor=_NeverAcquisitionExecutor(),
            ),
            prompt_catalog=catalog,
            review_verifier=DeterministicHearingProceduralReviewVerifier(
                config,
                faulting_repository,
            ),
        )

        with pytest.raises(
            RuntimeError,
            match="injected post-Prosecutor checkpoint fault",
        ):
            first_coordinator.process_case(RUN_ID, pack.case_id)

        all_provider_calls.extend(first_client.calls)
        assert faulted is True
        assert [request.role for request in first_client.calls] == [VlmRole.PROSECUTOR]
        session = faulting_repository.load_active_hearing(RUN_ID, pack.case_id)
        assert session is not None
        checkpoint = faulting_repository.load_latest_hearing_checkpoint(
            RUN_ID,
            session.session_id,
        )
        assert checkpoint.phase == HearingCheckpointPhase.PROSECUTOR_PENDING
        assert len(faulting_repository.list_hearing_model_requests(RUN_ID, session.session_id)) == 1
        assert (
            len(faulting_repository.list_hearing_model_responses(RUN_ID, session.session_id)) == 1
        )
        assert len(faulting_repository.list_hearing_usage_receipts(RUN_ID, session.session_id)) == 1
        assert len(faulting_repository.list_hearing_parse_receipts(RUN_ID, session.session_id)) == 1
        assert len(faulting_repository.list_hearing_role_outputs(RUN_ID, session.session_id)) == 1

        recovered_repository = SQLiteEvidenceRepository(
            database,
            BUSY_TIMEOUT_MS,
            verifier=_Verifier(),
            clock=_clock,
        )
        recovered_store = SecureHearingModelResponseStore(workspace)
        recovered_client = _CountingHearingVLMClient(
            DeterministicFakeHearingVLMClient(fixtures, recovered_store)
        )
        recovered_role_calls = HearingRoleCallService(
            repository=recovered_repository,
            response_store=recovered_store,
            vlm_client=recovered_client,
            prompt_registrar=_PromptRegistrar(),
            owner_token_factory=lambda: "r" * 43,
        )
        recovered_coordinator = HearingCoordinator(
            config=config,
            evidence_repository=recovered_repository,
            hearing_repository=recovered_repository,
            precedent_retrieval=precedents,
            role_calls=recovered_role_calls,
            acquisition=HearingAcquisitionService(
                repository=recovered_repository,
                executor=_NeverAcquisitionExecutor(),
            ),
            prompt_catalog=catalog,
            review_verifier=DeterministicHearingProceduralReviewVerifier(
                config,
                recovered_repository,
            ),
        )
        outcome = recovered_coordinator.process_case(RUN_ID, pack.case_id)
        all_provider_calls.extend(recovered_client.calls)

    assert outcome.case.case.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert outcome.record is not None and outcome.record.complete
    assert outcome.review is not None and outcome.review.passed
    assert outcome.cache_hit_count == 1
    assert outcome.recovered_response_count == 0
    assert [request.role for request in all_provider_calls] == [
        VlmRole.PROSECUTOR,
        VlmRole.DEFENDER,
        VlmRole.JUDGE,
    ]
    assert [request.role for request in recovered_client.calls] == [
        VlmRole.DEFENDER,
        VlmRole.JUDGE,
    ]
    assert (
        len(
            recovered_repository.list_hearing_model_requests(
                RUN_ID,
                outcome.record.hearing_session_id,
            )
        )
        == 3
    )
    assert (
        len(
            recovered_repository.list_hearing_model_responses(
                RUN_ID,
                outcome.record.hearing_session_id,
            )
        )
        == 3
    )
    assert (
        len(
            recovered_repository.list_hearing_usage_receipts(
                RUN_ID,
                outcome.record.hearing_session_id,
            )
        )
        == 3
    )
    assert recovered_repository.load_active_hearing(RUN_ID, pack.case_id) is None

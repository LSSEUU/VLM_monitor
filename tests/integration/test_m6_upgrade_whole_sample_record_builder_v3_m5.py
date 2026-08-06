from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import pytest

import labcourt.adapters.storage.sqlite_m6_upgrade_whole_sample_record_builder as subject
from labcourt.adapters.fake_hearing_precedents import FakeHearingPrecedentRetriever
from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.hearing_prompt_renderer import HearingJinjaPromptCatalog
from labcourt.adapters.storage import SecureHearingModelResponseStore, SecureWorkspace
from labcourt.adapters.storage.sqlite_hearing_repository import SQLiteHearingRepository
from labcourt.adapters.storage.sqlite_m5_precedent_usage import (
    SQLiteM5PrecedentExposureCommitter,
)
from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_observation_v3 import (
    SQLiteM6UpgradeExecutionObservationV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_pending_sample_commitment_v3 import (
    SQLiteM6UpgradePendingSampleCommitmentV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_whole_sample_record_builder import (
    SQLiteM6UpgradeWholeSampleRecordBuilderV3,
)
from labcourt.adapters.vlm import DeterministicFakeHearingVLMClient
from labcourt.application.hearing_acquisition import HearingAcquisitionService
from labcourt.application.hearing_coordinator import HearingCoordinator
from labcourt.application.hearing_precedent_retrieval import (
    HearingPrecedentRetrievalService,
)
from labcourt.application.hearing_procedural_review import (
    DeterministicHearingProceduralReviewVerifier,
)
from labcourt.application.hearing_role_call import HearingRoleCallService
from labcourt.application.hearing_situation import build_hearing_situation_text
from labcourt.application.m5_hearing_precedent_bridge import (
    M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    M5_HEARING_PRECEDENT_BRIDGE_VERSION,
    M5HearingPrecedentRetriever,
)
from labcourt.application.m5_precedent_policy_verifier import (
    ConfiguredM5PrecedentPolicyVerifier,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import VlmRole
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.hearing_retrieval import (
    HearingPrecedentRetrievalQuery,
    HearingPrecedentRetrievalResult,
)
from labcourt.contracts.m5_precedents import M5EmbeddingRequest, M5EmbeddingVector
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeCandidateCaseBinding,
    M6UpgradeSampleArtifactLink,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
    M6UpgradeObservedModelCall,
    M6UpgradeSampleExecutionObservationAuthorityV2,
    M6UpgradeSelectedCaseAuditAnchor,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.ports.hearing_precedents import HearingPrecedentRetriever
from labcourt.ports.m6_upgrade_whole_sample_record_builder import (
    M6UpgradeWholeSampleRecordBuilderError,
    M6UpgradeWholeSampleRecordBuilderFailureCode,
)
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256
from tests.integration import test_m3_sqlite_repository as m3_fixture
from tests.integration import test_m4_hearing_coordinator as m4_fixture
from tests.integration import test_m5_sqlite_precedents as m5_fixture
from tests.integration.test_m6_upgrade_execution_ledger_repository import (
    _scope_and_no_case_records,
)
from tests.integration.test_m6_upgrade_whole_sample_record_builder_v3 import (
    _commitment,
    _PixelProvider,
)
from tests.integration.test_m6_upgrade_whole_sample_record_builder_v3_m4 import (
    _TrackingM3RawVerifier,
    _TrackingM4RawVerifier,
)
from tests.unit.test_m4_hearing_prompt_renderer import _hearing_schema_documents

BUSY_TIMEOUT_MS = 2_000
_HISTORICAL_PRECEDENT_SUFFIX = "\nHistorical precedent authority."


class _CountingEmbeddingProvider:
    def __init__(self) -> None:
        self._delegate = DeterministicFakePrecedentEmbeddingProvider()
        self.calls: list[tuple[M5EmbeddingRequest, bytes]] = []

    def embed(self, request: M5EmbeddingRequest, payload: bytes) -> M5EmbeddingVector:
        self.calls.append((request, payload))
        return self._delegate.embed(request, payload)


class _CountingRetriever:
    def __init__(self, delegate: HearingPrecedentRetriever) -> None:
        self._delegate = delegate
        self.calls: list[HearingPrecedentRetrievalQuery] = []

    def retrieve(
        self,
        query: HearingPrecedentRetrievalQuery,
    ) -> HearingPrecedentRetrievalResult:
        self.calls.append(query)
        return self._delegate.retrieve(query)


@dataclass(frozen=True, slots=True)
class _V3M5BuilderFixture:
    database: Path
    scope_run_id: str
    scope_id: str
    observation: M6UpgradeSampleExecutionObservationAuthorityV2
    pixels: _PixelProvider
    exposure_id: str | None
    query_embedding_id: str | None
    candidate_embedding_ids: tuple[str, ...]
    embedding_provider: _CountingEmbeddingProvider
    retriever: _CountingRetriever


def _prepare_v3_m5_builder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    events: list[str],
    degraded: bool = False,
) -> _V3M5BuilderFixture:
    scope, _records = _scope_and_no_case_records()
    event = m3_fixture._event().model_copy(
        update={"manifest_id": scope.candidate_manifest.manifest_id}
    )
    monkeypatch.setattr(m3_fixture, "RUN_ID", scope.candidate_run_id)
    monkeypatch.setattr(m3_fixture, "_manifest", lambda: scope.candidate_manifest)
    monkeypatch.setattr(m3_fixture, "_event", lambda: event)
    monkeypatch.setattr(m4_fixture, "RUN_ID", scope.candidate_run_id)
    monkeypatch.setattr(m4_fixture, "load_config", lambda _path: scope.candidate_config)
    monkeypatch.setattr(m5_fixture, "RUN_ID", scope.candidate_run_id)

    database, _evidence = m3_fixture._repository(tmp_path)
    observations = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    observations.begin_execution(scope)

    database, repository, pack, escalated = m4_fixture._escalated_case(tmp_path)
    config = scope.candidate_config
    manifest = repository.load_run_manifest(scope.candidate_run_id)
    policy_verifier = ConfiguredM5PrecedentPolicyVerifier(config)
    m5_repository = SQLiteM5Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=m3_fixture._clock,
        m5_precedent_policy_verifier=policy_verifier,
    )
    provider = _CountingEmbeddingProvider()
    if degraded:
        retriever = _CountingRetriever(FakeHearingPrecedentRetriever(()))
    else:
        pack_situation = build_hearing_situation_text(pack)
        authority = m5_fixture._authority(
            manifest,
            "builder-v3-m5-precedent",
            evidence_class=pack.event.evidence_class,
            violation_type=pack.event.violation_type,
            situation_text=pack_situation + _HISTORICAL_PRECEDENT_SUFFIX,
            policy=policy_verifier.expected_policy(manifest),
        )
        assert authority.text_embedding is not None
        m5_repository.append_authority(authority, None)
        retriever = _CountingRetriever(
            M5HearingPrecedentRetriever(
                repository=m5_repository,
                manifest=manifest,
                policy=policy_verifier.expected_policy(manifest),
                run_mode=policy_verifier.run_mode,
                embedding_provider=provider,
            )
        )
    precedents = HearingPrecedentRetrievalService(
        retriever,
        retriever_version=M5_HEARING_PRECEDENT_BRIDGE_VERSION,
        retriever_manifest_id=M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    )
    committer = SQLiteM5PrecedentExposureCommitter(
        repository=m5_repository,
        hearing_repository=SQLiteHearingRepository(repository),
        embedding_provider=provider,
    )
    catalog = HearingJinjaPromptCatalog(output_schema_json_by_prompt=_hearing_schema_documents())
    fixtures = m4_fixture._fixtures_for_terminal_hearing(
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
        coordinator = HearingCoordinator(
            config=config,
            evidence_repository=repository,
            hearing_repository=repository,
            precedent_retrieval=precedents,
            role_calls=HearingRoleCallService(
                repository=repository,
                response_store=response_store,
                vlm_client=DeterministicFakeHearingVLMClient(fixtures, response_store),
                prompt_registrar=m4_fixture._PromptRegistrar(),
                owner_token_factory=lambda: "o" * 43,
            ),
            acquisition=HearingAcquisitionService(
                repository=repository,
                executor=m4_fixture._NeverAcquisitionExecutor(),
            ),
            prompt_catalog=catalog,
            review_verifier=DeterministicHearingProceduralReviewVerifier(
                config,
                repository,
            ),
            precedent_outcome_committer=committer,
        )
        outcome = coordinator.process_case(scope.candidate_run_id, pack.case_id)

    case_document = canonical_json(outcome.case.case.model_dump(mode="json"))
    case_sha256 = hashlib.sha256(case_document.encode("utf-8")).hexdigest()
    matching_audits = tuple(
        item
        for item in repository.list_audit_entries(scope.candidate_run_id)
        if item.after_sha256 == case_sha256
    )
    assert len(matching_audits) == 1
    selected_audit = matching_audits[0]
    binding = M6UpgradeCandidateCaseBinding(
        case_id=outcome.case.case.case_id,
        case_revision=outcome.case.revision,
        case_document_sha256=case_sha256,
        case_audit_sequence=selected_audit.sequence,
        case_audit_entry_hash=selected_audit.entry_hash,
    )
    anchor = M6UpgradeSelectedCaseAuditAnchor(
        candidate_case_binding_id=binding.case_binding_id,
        action=selected_audit.action,
        object_ref=selected_audit.object_ref,
    )
    assert outcome.session is not None
    assert outcome.record is not None
    requests = repository.list_hearing_model_requests(
        scope.candidate_run_id,
        outcome.session.session_id,
    )
    assert len(requests) == 3
    screening_request = m3_fixture._request(pack)
    role_map = {
        VlmRole.PROSECUTOR: M6LockedModelRole.PROSECUTOR,
        VlmRole.DEFENDER: M6LockedModelRole.DEFENDER,
        VlmRole.JUDGE: M6LockedModelRole.JUDGE,
    }
    observed_calls = tuple(
        sorted(
            (
                M6UpgradeObservedModelCall(
                    request_id=screening_request.request_id,
                    layer=M6LockedModelCallLayer.SCREENING,
                    role=M6LockedModelRole.SCREENING,
                    attempt_index=0,
                    result_kind=M6LockedModelCallResultKind.RESPONSE,
                    provider_invoked=True,
                ),
                *(
                    M6UpgradeObservedModelCall(
                        request_id=request.request_id,
                        layer=M6LockedModelCallLayer.HEARING,
                        role=role_map[request.role],
                        attempt_index=request.attempt_index,
                        result_kind=M6LockedModelCallResultKind.RESPONSE,
                        provider_invoked=True,
                    )
                    for request in requests
                ),
            ),
            key=lambda value: value.sort_key,
        )
    )

    exposure_id: str | None = None
    query_embedding_id: str | None = None
    candidate_embedding_ids: tuple[str, ...] = ()
    assert outcome.checkpoint is not None
    cycle_scope_id = outcome.checkpoint.cycle_scope_id
    if degraded:
        assert (
            committer.load_exposure(
                scope.candidate_run_id,
                cycle_scope_id,
            )
            is None
        )
    else:
        exposure = committer.load_exposure(
            scope.candidate_run_id,
            cycle_scope_id,
        )
        assert exposure is not None
        query_embedding = exposure.m5_retrieval_result.query.text_embedding
        assert query_embedding is not None
        candidate_embedding_ids = tuple(
            sorted(
                embedding.embedding_id
                for evaluation in exposure.m5_retrieval_result.candidate_evaluations
                for embedding in (
                    (
                        ()
                        if evaluation.authority.text_embedding is None
                        else (evaluation.authority.text_embedding,)
                    )
                    + evaluation.authority.visual_embeddings
                )
            )
        )
        assert len(candidate_embedding_ids) == 1
        assert query_embedding.embedding_id not in candidate_embedding_ids
        exposure_id = exposure.exposure_id
        query_embedding_id = query_embedding.embedding_id

    pixel_bytes = bytes((9, 8, 7))
    frame = FrameRef(
        camera_id="camera-builder-v3-m5",
        stream_id="stream-builder-v3-m5",
        frame_index=0,
        fps_num=25,
        fps_den=1,
        width=1,
        height=1,
        content_sha256=rgb8_pixel_sha256(1, 1, pixel_bytes),
    )
    repository.register_frame(scope.candidate_run_id, frame)
    ordinary_artifacts = (
        M6UpgradeObservedArtifactIdentity(
            source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
            kind=M6UpgradePhysicalArtifactKind.FRAME,
            artifact_id=frame.frame_id,
            usage=M6UpgradeArtifactUsage.CONSUMED,
        ),
        M6UpgradeObservedArtifactIdentity(
            source=M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
            kind=M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
            artifact_id=pack.pack_id,
            usage=M6UpgradeArtifactUsage.PRODUCED,
        ),
    )
    m5_artifacts: tuple[M6UpgradeObservedArtifactIdentity, ...] = ()
    if exposure_id is not None and query_embedding_id is not None:
        m5_artifacts = (
            M6UpgradeObservedArtifactIdentity(
                source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
                kind=M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
                artifact_id=exposure_id,
                usage=M6UpgradeArtifactUsage.PRODUCED,
            ),
            M6UpgradeObservedArtifactIdentity(
                source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
                kind=M6UpgradePhysicalArtifactKind.EMBEDDING,
                artifact_id=query_embedding_id,
                usage=M6UpgradeArtifactUsage.PRODUCED,
            ),
            *(
                M6UpgradeObservedArtifactIdentity(
                    source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
                    kind=M6UpgradePhysicalArtifactKind.EMBEDDING,
                    artifact_id=embedding_id,
                    usage=M6UpgradeArtifactUsage.CONSUMED,
                )
                for embedding_id in candidate_embedding_ids
            ),
        )
    observation = M6UpgradeSampleExecutionObservationAuthorityV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[0],
        ledger_sequence=0,
        outcome=M6ReplayExecutionOutcome.CASE_REPLAYED,
        candidate_case=binding,
        selected_case_audit_anchor=anchor,
        artifacts=tuple(
            sorted(
                (*ordinary_artifacts, *m5_artifacts),
                key=lambda value: value.sort_key,
            )
        ),
        model_calls=observed_calls,
    )
    observations.append(observation)
    return _V3M5BuilderFixture(
        database=database,
        scope_run_id=scope.candidate_run_id,
        scope_id=scope.execution_scope_authority_id,
        observation=observation,
        pixels=_PixelProvider(RGB8Frame(frame=frame, pixels=pixel_bytes), events),
        exposure_id=exposure_id,
        query_embedding_id=query_embedding_id,
        candidate_embedding_ids=candidate_embedding_ids,
        embedding_provider=provider,
        retriever=retriever,
    )


def _track_optional_subject_function(
    monkeypatch: pytest.MonkeyPatch,
    events: list[str],
    *,
    attribute: str,
    event: str,
) -> None:
    original = getattr(subject, attribute, None)
    if not callable(original):
        return

    def tracked(*args: object, **kwargs: object) -> object:
        events.append(event)
        return original(*args, **kwargs)

    monkeypatch.setattr(subject, attribute, tracked)


def _tracked_builder(
    fixture: _V3M5BuilderFixture,
    monkeypatch: pytest.MonkeyPatch,
    events: list[str],
) -> SQLiteM6UpgradeWholeSampleRecordBuilderV3:
    for attribute, event in (
        ("plan_m6_sqlite_m5_precedent_documents", "m5-metadata"),
        ("resolve_m6_sqlite_m5_precedent_documents", "m5-body"),
        ("resolve_m6_sqlite_m3_model_documents", "m3-body"),
        ("resolve_m6_sqlite_m4_model_documents", "m4-body"),
        ("resolve_m6_sqlite_evidence_pack_physical_plan", "pack"),
    ):
        _track_optional_subject_function(
            monkeypatch,
            events,
            attribute=attribute,
            event=event,
        )
    return SQLiteM6UpgradeWholeSampleRecordBuilderV3(
        fixture.database,
        BUSY_TIMEOUT_MS,
        pixel_provider=fixture.pixels,
        m3_raw_response_verifier=_TrackingM3RawVerifier(events),
        m4_raw_response_verifier=_TrackingM4RawVerifier(events),
    )


def _forbid_external_m5_replay_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden_provider_call(
        _self: object,
        _request: M5EmbeddingRequest,
        _payload: bytes,
    ) -> M5EmbeddingVector:
        raise AssertionError("V3 replay builder called an M5 embedding provider")

    def forbidden_retriever_call(
        _self: object,
        _query: HearingPrecedentRetrievalQuery,
    ) -> HearingPrecedentRetrievalResult:
        raise AssertionError("V3 replay builder called an M5 retriever")

    monkeypatch.setattr(
        DeterministicFakePrecedentEmbeddingProvider,
        "embed",
        forbidden_provider_call,
    )
    monkeypatch.setattr(M5HearingPrecedentRetriever, "retrieve", forbidden_retriever_call)
    monkeypatch.setattr(FakeHearingPrecedentRetriever, "retrieve", forbidden_retriever_call)


def _conflicting_m5_record(
    record: M6UpgradeSampleExecutionRecordV2,
) -> M6UpgradeSampleExecutionRecordV2:
    links = list(record.artifact_links)
    index = next(
        position
        for position, link in enumerate(links)
        if link.artifact.source == M6UpgradePhysicalArtifactSource.M5_PRECEDENT
    )
    link = links[index]
    links[index] = link.model_copy(
        update={
            "artifact": link.artifact.model_copy(
                update={"document_sha256": "f" * 64, "content_sha256": "f" * 64}
            )
        }
    )
    payload = record.model_dump(
        mode="python",
        exclude={"schema_version"},
        exclude_computed_fields=True,
    )
    payload["artifact_links"] = tuple(links)
    return type(record)(**payload)


def _m5_links(
    record: M6UpgradeSampleExecutionRecordV2,
) -> tuple[M6UpgradeSampleArtifactLink, ...]:
    return tuple(
        link
        for link in record.artifact_links
        if link.artifact.source == M6UpgradePhysicalArtifactSource.M5_PRECEDENT
    )


def test_v3_builder_replays_real_m5_exposure_and_embedding_closure_without_services(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    fixture = _prepare_v3_m5_builder(tmp_path, monkeypatch, events=events)
    builder = _tracked_builder(fixture, monkeypatch, events)
    provider_calls = len(fixture.embedding_provider.calls)
    retriever_calls = len(fixture.retriever.calls)
    assert provider_calls > 0
    assert retriever_calls > 0
    _forbid_external_m5_replay_calls(monkeypatch)

    record = builder.build_m6_upgrade_sample_record(
        fixture.scope_run_id,
        fixture.scope_id,
    )

    links = _m5_links(record)
    exposure_links = tuple(
        link
        for link in links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE
    )
    embedding_links = tuple(
        link for link in links if link.artifact.kind == M6UpgradePhysicalArtifactKind.EMBEDDING
    )
    assert fixture.exposure_id is not None
    assert fixture.query_embedding_id is not None
    assert record.candidate_case == fixture.observation.candidate_case
    assert record.observation_authority_id == fixture.observation.observation_authority_id
    assert len(exposure_links) == 1
    assert exposure_links[0].artifact.artifact_id == fixture.exposure_id
    assert exposure_links[0].usage == M6UpgradeArtifactUsage.PRODUCED
    assert len(embedding_links) == 2
    assert {link.artifact.artifact_id for link in embedding_links} == {
        fixture.query_embedding_id,
        *fixture.candidate_embedding_ids,
    }
    assert {link.usage: link.artifact.artifact_id for link in embedding_links} == {
        M6UpgradeArtifactUsage.PRODUCED: fixture.query_embedding_id,
        M6UpgradeArtifactUsage.CONSUMED: fixture.candidate_embedding_ids[0],
    }
    assert len(fixture.embedding_provider.calls) == provider_calls
    assert len(fixture.retriever.calls) == retriever_calls
    assert events.count("m5-metadata") == 1
    assert events.count("m5-body") == 1
    assert events.index("m5-metadata") < min(
        events.index(event) for event in ("m5-body", "m3-body", "m4-body", "pack")
    )


def test_v3_builder_pending_m5_conflict_stops_before_every_physical_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    fixture = _prepare_v3_m5_builder(tmp_path, monkeypatch, events=events)
    builder = _tracked_builder(fixture, monkeypatch, events)
    first = builder.build_m6_upgrade_sample_record(
        fixture.scope_run_id,
        fixture.scope_id,
    )
    pending = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        fixture.database,
        BUSY_TIMEOUT_MS,
    )
    commitment = _commitment(_conflicting_m5_record(first))
    assert pending.append(commitment) == commitment
    events.clear()
    fixture.pixels.requested_ids.clear()
    provider_calls = len(fixture.embedding_provider.calls)
    retriever_calls = len(fixture.retriever.calls)
    _forbid_external_m5_replay_calls(monkeypatch)

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        builder.build_m6_upgrade_sample_record(
            fixture.scope_run_id,
            fixture.scope_id,
        )

    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT
    )
    assert events.count("m5-metadata") == 1
    assert not {
        "m5-body",
        "m3-body",
        "m4-body",
        "pack",
        "m3-raw",
        "m4-raw",
        "pixel",
    }.intersection(events)
    assert fixture.pixels.requested_ids == []
    assert len(fixture.embedding_provider.calls) == provider_calls
    assert len(fixture.retriever.calls) == retriever_calls


def test_v3_builder_accepts_bridge_degraded_hearing_without_m5_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    fixture = _prepare_v3_m5_builder(
        tmp_path,
        monkeypatch,
        events=events,
        degraded=True,
    )
    builder = _tracked_builder(fixture, monkeypatch, events)
    provider_calls = len(fixture.embedding_provider.calls)
    retriever_calls = len(fixture.retriever.calls)
    _forbid_external_m5_replay_calls(monkeypatch)

    record = builder.build_m6_upgrade_sample_record(
        fixture.scope_run_id,
        fixture.scope_id,
    )

    assert _m5_links(record) == ()
    assert not any(
        artifact.source == M6UpgradePhysicalArtifactSource.M5_PRECEDENT
        for artifact in fixture.observation.artifacts
    )
    assert events.count("m5-metadata") == 1
    assert events.count("m5-body") == 1
    assert len(fixture.embedding_provider.calls) == provider_calls
    assert len(fixture.retriever.calls) == retriever_calls

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import pytest

import labcourt.adapters.storage.sqlite_m6_upgrade_whole_sample_record_builder as subject
from labcourt.adapters.fake_hearing_precedents import FakeHearingPrecedentRetriever
from labcourt.adapters.hearing_prompt_renderer import HearingJinjaPromptCatalog
from labcourt.adapters.storage import SecureHearingModelResponseStore, SecureWorkspace
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
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import ArtifactKind, VlmRole
from labcourt.contracts.evidence import EvidencePackDraft
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.hearing_model import HearingModelRequest, HearingModelResponse
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeCandidateCaseBinding,
    M6UpgradeExecutionScopeAuthority,
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
from labcourt.contracts.references import parse_frame_id
from labcourt.contracts.screening import VLMCallRequest, VLMResponse
from labcourt.ports.m6_upgrade_whole_sample_record_builder import (
    M6UpgradeWholeSampleRecordBuilderError,
    M6UpgradeWholeSampleRecordBuilderFailureCode,
)
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256
from tests.integration import test_m3_sqlite_repository as m3_fixture
from tests.integration import test_m4_hearing_coordinator as m4_fixture
from tests.integration.test_m6_upgrade_execution_ledger_repository import (
    _scope_and_no_case_records,
)
from tests.integration.test_m6_upgrade_whole_sample_record_builder_v3 import (
    _commitment,
    _PixelProvider,
)
from tests.unit.test_m4_hearing_prompt_renderer import _hearing_schema_documents

BUSY_TIMEOUT_MS = 2_000


class _TrackingM4RawVerifier:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.calls: list[tuple[str, HearingModelRequest, HearingModelResponse]] = []

    def verify_raw_response(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> HearingModelResponse:
        self.events.append("m4-raw")
        self.calls.append((run_id, request, response))
        return response


class _TrackingM3RawVerifier:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.calls: list[tuple[str, VLMCallRequest, VLMResponse]] = []
        self._delegate = m3_fixture._RawVerifier()

    def verify_raw_response(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> VLMResponse:
        self.events.append("m3-raw")
        self.calls.append((run_id, request, response))
        return self._delegate.verify_raw_response(run_id, request, response)


@dataclass(frozen=True, slots=True)
class _V3M4BuilderFixture:
    database: Path
    scope: M6UpgradeExecutionScopeAuthority
    scope_run_id: str
    scope_id: str
    observation: M6UpgradeSampleExecutionObservationAuthorityV2
    pixels: _PixelProvider


def _prepare_v3_m4_builder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    events: list[str],
    current_m4_failure: bool = False,
    include_case_semantic_frames: bool = False,
) -> _V3M4BuilderFixture:
    scope, _records = _scope_and_no_case_records()
    event = m3_fixture._event().model_copy(
        update={"manifest_id": scope.candidate_manifest.manifest_id}
    )
    monkeypatch.setattr(m3_fixture, "RUN_ID", scope.candidate_run_id)
    monkeypatch.setattr(m3_fixture, "_manifest", lambda: scope.candidate_manifest)
    monkeypatch.setattr(m3_fixture, "_event", lambda: event)
    monkeypatch.setattr(m4_fixture, "RUN_ID", scope.candidate_run_id)
    monkeypatch.setattr(m4_fixture, "load_config", lambda _path: scope.candidate_config)

    semantic_rgb_frames: list[RGB8Frame] = []
    if include_case_semantic_frames:
        original_draft = m3_fixture._draft
        source_frame = m3_fixture._frame()
        source_pixels = bytes((31, 32, 33)) * (source_frame.width * source_frame.height)
        rgb_backed_source_frame = FrameRef(
            camera_id=source_frame.camera_id,
            stream_id=source_frame.stream_id,
            frame_index=source_frame.frame_index,
            fps_num=source_frame.fps_num,
            fps_den=source_frame.fps_den,
            width=source_frame.width,
            height=source_frame.height,
            content_sha256=rgb8_pixel_sha256(
                source_frame.width,
                source_frame.height,
                source_pixels,
            ),
        )
        monkeypatch.setattr(m3_fixture, "_frame", lambda: rgb_backed_source_frame)

        def rgb_backed_draft(*, version: int, complete: bool) -> EvidencePackDraft:
            draft = original_draft(version=version, complete=complete)
            payload = draft.model_dump(mode="python", exclude_computed_fields=True)
            for field_name in (
                "panorama_crops",
                "subject_crops",
                "focus_crops",
                "temporal_crops",
            ):
                payload[field_name] = tuple(
                    crop.model_copy(
                        update={
                            "source_media_sha256": rgb_backed_source_frame.content_sha256,
                            "local_path": (
                                f"{scope.candidate_run_id}/frames/{crop.media_sha256}.png"
                            ),
                        }
                    )
                    for crop in getattr(draft, field_name)
                )
            return EvidencePackDraft(**payload)

        monkeypatch.setattr(m3_fixture, "_draft", rgb_backed_draft)
        monkeypatch.setattr(m4_fixture, "_draft", rgb_backed_draft)
        semantic_rgb_frames.append(RGB8Frame(frame=rgb_backed_source_frame, pixels=source_pixels))

    database, _evidence = m3_fixture._repository(tmp_path)
    observations = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    observations.begin_execution(scope)

    database, repository, pack, escalated = m4_fixture._escalated_case(tmp_path)
    config = scope.candidate_config
    manifest = repository.load_run_manifest(scope.candidate_run_id)
    catalog = HearingJinjaPromptCatalog(output_schema_json_by_prompt=_hearing_schema_documents())
    precedents = HearingPrecedentRetrievalService(
        FakeHearingPrecedentRetriever(()),
        retriever_version="fake-hearing-precedents-v1",
        retriever_manifest_id=m4_fixture._digest("fake-hearing-precedents"),
    )
    fixtures = m4_fixture._fixtures_for_terminal_hearing(
        source_case=escalated,
        config=config,
        manifest=manifest,
        catalog=catalog,
        precedents=precedents,
    )
    if current_m4_failure:
        fixtures[next(iter(fixtures))] = m4_fixture.OUTAGE_FIXTURE
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
        )
        outcome = coordinator.process_case(scope.candidate_run_id, pack.case_id)

    if include_case_semantic_frames:
        selected_case = outcome.case.case
        required_frame_ids = {
            f"{selected_case.event.camera_id}:{selected_case.event.stream_id}:"
            f"{selected_case.event.start_frame}",
            f"{selected_case.event.camera_id}:{selected_case.event.stream_id}:"
            f"{selected_case.event.end_frame_exclusive - 1}",
            f"{selected_case.event.camera_id}:{selected_case.event.stream_id}:"
            f"{selected_case.event.trigger_frame}",
            *selected_case.event.confirmation.examined_frame_ids,
            *selected_case.event.confirmation.counterevidence_frame_ids,
            *(
                (selected_case.event.confirmation.post_threshold_recovery_frame_id,)
                if selected_case.event.confirmation.post_threshold_recovery_frame_id is not None
                else ()
            ),
            *(
                fact.source_ref.artifact_id
                for fact in selected_case.event.objective_facts
                if fact.source_ref.kind == ArtifactKind.FRAME
            ),
        }
        for selected_pack in selected_case.evidence_packs:
            required_frame_ids.update(selected_pack.key_frame_ids)
            required_frame_ids.update(selected_pack.confirmation_record.examined_frame_ids)
            required_frame_ids.update(selected_pack.confirmation_record.counterevidence_frame_ids)
            recovery = selected_pack.confirmation_record.post_threshold_recovery_frame_id
            if recovery is not None:
                required_frame_ids.add(recovery)
            for crop in selected_pack.crops:
                required_frame_ids.add(crop.frame_id)
                required_frame_ids.update(
                    ref.artifact_id
                    for ref in (*crop.source_refs, *crop.privacy_receipt.input_refs)
                    if ref.kind == ArtifactKind.FRAME
                )
            required_frame_ids.update(
                fact.source_ref.artifact_id
                for fact in selected_pack.objective_facts
                if fact.source_ref.kind == ArtifactKind.FRAME
            )
        existing_frame_ids = {item.frame.frame_id for item in semantic_rgb_frames}
        for sequence, frame_id in enumerate(
            sorted(required_frame_ids - existing_frame_ids, key=parse_frame_id)
        ):
            camera_id, stream_id, frame_index = parse_frame_id(frame_id)
            semantic_pixels = bytes((sequence + 41, sequence + 42, sequence + 43))
            semantic_frame = FrameRef(
                camera_id=camera_id,
                stream_id=stream_id,
                frame_index=frame_index,
                fps_num=30,
                fps_den=1,
                width=1,
                height=1,
                content_sha256=rgb8_pixel_sha256(1, 1, semantic_pixels),
            )
            repository.register_frame(scope.candidate_run_id, semantic_frame)
            semantic_rgb_frames.append(RGB8Frame(frame=semantic_frame, pixels=semantic_pixels))

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
    if current_m4_failure:
        assert outcome.record is None
    else:
        assert outcome.record is not None
    requests = repository.list_hearing_model_requests(
        scope.candidate_run_id,
        outcome.session.session_id,
    )
    assert len(requests) == (1 if current_m4_failure else 3)
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
                        result_kind=(
                            M6LockedModelCallResultKind.FAILURE
                            if current_m4_failure
                            else M6LockedModelCallResultKind.RESPONSE
                        ),
                        provider_invoked=True,
                    )
                    for request in requests
                ),
            ),
            key=lambda value: value.sort_key,
        )
    )

    pixel_bytes = bytes((9, 8, 7))
    frame = FrameRef(
        camera_id="camera-builder-v3-m4",
        stream_id="stream-builder-v3-m4",
        frame_index=0,
        fps_num=25,
        fps_den=1,
        width=1,
        height=1,
        content_sha256=rgb8_pixel_sha256(1, 1, pixel_bytes),
    )
    repository.register_frame(scope.candidate_run_id, frame)
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
                (
                    *(
                        M6UpgradeObservedArtifactIdentity(
                            source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                            kind=M6UpgradePhysicalArtifactKind.FRAME,
                            artifact_id=item.frame.frame_id,
                            usage=M6UpgradeArtifactUsage.CONSUMED,
                        )
                        for item in semantic_rgb_frames
                    ),
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
                    *(
                        (
                            M6UpgradeObservedArtifactIdentity(
                                source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                                kind=M6UpgradePhysicalArtifactKind.DETECTION,
                                artifact_id=m3_fixture._detection().detection_id,
                                usage=M6UpgradeArtifactUsage.PRODUCED,
                            ),
                        )
                        if include_case_semantic_frames
                        else ()
                    ),
                ),
                key=lambda value: value.sort_key,
            )
        ),
        model_calls=observed_calls,
    )
    observations.append(observation)
    return _V3M4BuilderFixture(
        database=database,
        scope=scope,
        scope_run_id=scope.candidate_run_id,
        scope_id=scope.execution_scope_authority_id,
        observation=observation,
        pixels=_PixelProvider(
            RGB8Frame(frame=frame, pixels=pixel_bytes),
            events,
            additional_frames=tuple(semantic_rgb_frames),
        ),
    )


def _tracked_builder(
    fixture: _V3M4BuilderFixture,
    monkeypatch: pytest.MonkeyPatch,
    events: list[str],
) -> tuple[SQLiteM6UpgradeWholeSampleRecordBuilderV3, _TrackingM4RawVerifier]:
    real_m3_body = subject.resolve_m6_sqlite_m3_model_documents
    real_m4_body = subject.resolve_m6_sqlite_m4_model_documents
    real_pack_body = subject.resolve_m6_sqlite_evidence_pack_physical_plan

    def tracked_m3_body(*args: object, **kwargs: object) -> object:
        events.append("m3-body")
        return real_m3_body(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_m4_body(*args: object, **kwargs: object) -> object:
        events.append("m4-body")
        return real_m4_body(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_pack_body(*args: object, **kwargs: object) -> object:
        events.append("pack")
        return real_pack_body(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(subject, "resolve_m6_sqlite_m3_model_documents", tracked_m3_body)
    monkeypatch.setattr(subject, "resolve_m6_sqlite_m4_model_documents", tracked_m4_body)
    monkeypatch.setattr(
        subject,
        "resolve_m6_sqlite_evidence_pack_physical_plan",
        tracked_pack_body,
    )
    raw = _TrackingM4RawVerifier(events)
    builder = SQLiteM6UpgradeWholeSampleRecordBuilderV3(
        fixture.database,
        BUSY_TIMEOUT_MS,
        pixel_provider=fixture.pixels,
        m3_raw_response_verifier=_TrackingM3RawVerifier(events),
        m4_raw_response_verifier=raw,
    )
    return builder, raw


def test_v3_builder_exact_joins_real_three_role_m4_hearing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    fixture = _prepare_v3_m4_builder(tmp_path, monkeypatch, events=events)
    builder, raw = _tracked_builder(fixture, monkeypatch, events)

    record = builder.build_m6_upgrade_sample_record(
        fixture.scope_run_id,
        fixture.scope_id,
    )

    m4_links = tuple(
        link
        for link in record.artifact_links
        if link.artifact.source == M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL
    )
    assert record.candidate_case == fixture.observation.candidate_case
    assert record.observation_authority_id == fixture.observation.observation_authority_id
    hearing_calls = tuple(
        item
        for item in fixture.observation.model_calls
        if item.layer == M6LockedModelCallLayer.HEARING
    )
    assert len(hearing_calls) == 3
    assert len(m4_links) == 18
    assert len(raw.calls) == 3
    assert {call[1].request_id for call in raw.calls} == {item.request_id for item in hearing_calls}
    assert events == [
        "m3-body",
        "m4-body",
        "pack",
        "m3-raw",
        "m4-raw",
        "m4-raw",
        "m4-raw",
        "pixel",
    ]


def test_v3_builder_closes_real_current_m4_failure_without_raw_response_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    fixture = _prepare_v3_m4_builder(
        tmp_path,
        monkeypatch,
        events=events,
        current_m4_failure=True,
    )
    builder, raw = _tracked_builder(fixture, monkeypatch, events)

    record = builder.build_m6_upgrade_sample_record(
        fixture.scope_run_id,
        fixture.scope_id,
    )

    hearing_calls = tuple(
        item
        for item in fixture.observation.model_calls
        if item.layer == M6LockedModelCallLayer.HEARING
    )
    m4_links = tuple(
        link
        for link in record.artifact_links
        if link.artifact.source == M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL
    )
    assert len(hearing_calls) == 1
    assert hearing_calls[0].result_kind == M6LockedModelCallResultKind.FAILURE
    assert len(m4_links) == 2
    assert {link.artifact.kind for link in m4_links} == {
        M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
        M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
    }
    request_link = next(
        link
        for link in m4_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.MODEL_REQUEST
    )
    assert request_link.artifact.artifact_id == hearing_calls[0].request_id
    assert raw.calls == []
    assert events == ["m3-body", "m4-body", "pack", "m3-raw", "pixel"]


def test_v3_builder_pending_m4_conflict_stops_before_m4_body_raw_and_pixel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    fixture = _prepare_v3_m4_builder(tmp_path, monkeypatch, events=events)
    builder, _raw = _tracked_builder(fixture, monkeypatch, events)
    first = builder.build_m6_upgrade_sample_record(
        fixture.scope_run_id,
        fixture.scope_id,
    )
    links = list(first.artifact_links)
    index = next(
        position
        for position, link in enumerate(links)
        if link.artifact.source == M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL
    )
    link = links[index]
    links[index] = link.model_copy(
        update={
            "artifact": link.artifact.model_copy(
                update={"document_sha256": "f" * 64, "content_sha256": "f" * 64}
            )
        }
    )
    payload = first.model_dump(
        mode="python",
        exclude={"schema_version"},
        exclude_computed_fields=True,
    )
    payload["artifact_links"] = tuple(links)
    conflicting = type(first)(**payload)
    pending = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        fixture.database,
        BUSY_TIMEOUT_MS,
    )
    commitment = _commitment(conflicting)
    assert pending.append(commitment) == commitment
    events.clear()
    fixture.pixels.requested_ids.clear()

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        builder.build_m6_upgrade_sample_record(
            fixture.scope_run_id,
            fixture.scope_id,
        )

    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT
    )
    assert events == []
    assert fixture.pixels.requested_ids == []

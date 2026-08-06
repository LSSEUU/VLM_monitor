from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import pytest
from pydantic import BaseModel

import labcourt.adapters.storage.sqlite_m6_upgrade_whole_sample_record_builder as subject
from labcourt.adapters.acquisition_fake import (
    CONTROLLED_FAKE_ACQUISITION_COMPONENT,
    CONTROLLED_FAKE_ACQUISITION_COMPONENT_KEY,
    controlled_fake_acquisition_component_manifest_id,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_acquisition_documents import (
    M6SQLiteAcquisitionDocumentsPlan,
    resolve_m6_sqlite_acquisition_documents,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_observation_v3 import (
    SQLiteM6UpgradeExecutionObservationV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_pending_sample_commitment_v3 import (
    SQLiteM6UpgradePendingSampleCommitmentV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_whole_sample_record_builder import (
    SQLiteM6UpgradeWholeSampleRecordBuilderV3,
)
from labcourt.application.hearing_acquisition import HearingAcquisitionService
from labcourt.application.m6_upgrade_whole_sample_record import (
    build_m6_upgrade_case_replayed_metadata_acquisition_record_v3,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeCandidateCaseBinding,
    M6UpgradeExecutionScopeAuthority,
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
from labcourt.contracts.manifests import RunManifest
from labcourt.ports.m6_upgrade_whole_sample_record_builder import (
    M6UpgradeWholeSampleRecordBuilderError,
    M6UpgradeWholeSampleRecordBuilderFailureCode,
)
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256
from tests.integration import test_m3_sqlite_repository as m3_fixture
from tests.integration import test_m4_acquisition_execution_fencing as acquisition_fixture
from tests.integration import test_m4_hearing_coordinator as m4_fixture
from tests.integration import (
    test_sqlite_m6_upgrade_acquisition_documents as acquisition_plan_fixture,
)
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

BUSY_TIMEOUT_MS = 2_000


def _document_identity(value: BaseModel) -> tuple[str, int]:
    raw = canonical_json(value.model_dump(mode="json"))
    encoded = raw.encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), len(encoded)


def _acquisition_pinned_manifest(base: RunManifest) -> RunManifest:
    payload = base.model_dump(mode="json", exclude={"manifest_id"})
    payload["software_components"] = {
        **payload["software_components"],
        CONTROLLED_FAKE_ACQUISITION_COMPONENT_KEY: (
            CONTROLLED_FAKE_ACQUISITION_COMPONENT.model_dump(mode="json")
        ),
    }
    return RunManifest.model_validate(payload)


def _scope_with_manifest(
    source: M6UpgradeExecutionScopeAuthority,
    manifest: RunManifest,
) -> M6UpgradeExecutionScopeAuthority:
    command = source.command.model_copy(update={"candidate_manifest_id": manifest.manifest_id})
    command_sha256, command_bytes = _document_identity(command)
    manifest_sha256, manifest_bytes = _document_identity(manifest)
    payload = source.model_dump(
        mode="python",
        exclude={"schema_version"},
        exclude_computed_fields=True,
    )
    payload.update(
        command=command,
        command_content_sha256=command_sha256,
        command_size_bytes=command_bytes,
        candidate_manifest=manifest,
        candidate_manifest_content_sha256=manifest_sha256,
        candidate_manifest_size_bytes=manifest_bytes,
    )
    return M6UpgradeExecutionScopeAuthority(**payload)


@dataclass(frozen=True, slots=True)
class _AcquisitionBuilderFixture:
    database: Path
    scope: M6UpgradeExecutionScopeAuthority
    observation: M6UpgradeSampleExecutionObservationAuthorityV2
    pixels: _PixelProvider
    execution_manifest_id: str
    tool_result_id: str


def _prepare_acquisition_builder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    events: list[str],
) -> _AcquisitionBuilderFixture:
    source_scope, _records = _scope_and_no_case_records()
    pinned_manifest = _acquisition_pinned_manifest(source_scope.candidate_manifest)
    scope = _scope_with_manifest(source_scope, pinned_manifest)
    run_id = scope.candidate_run_id

    # The M3/M4 integration fixtures use module-level run/config authorities.
    # Rebind all of them to the exact V3 candidate start cut before creating rows.
    monkeypatch.setattr(m3_fixture, "RUN_ID", run_id)
    monkeypatch.setattr(m3_fixture, "_manifest", lambda: pinned_manifest)
    monkeypatch.setattr(m4_fixture, "RUN_ID", run_id)
    monkeypatch.setattr(m4_fixture, "load_config", lambda _path: scope.candidate_config)
    monkeypatch.setattr(acquisition_fixture, "RUN_ID", run_id)
    monkeypatch.setattr(
        acquisition_fixture,
        "load_config",
        lambda _path: scope.candidate_config,
    )
    monkeypatch.setattr(acquisition_plan_fixture, "RUN_ID", run_id)

    database, _evidence = m3_fixture._repository(tmp_path)
    observations = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    observations.begin_execution(scope)
    database, repository, request, publication, committed = (
        acquisition_fixture._committed_successor(tmp_path, monkeypatch)
    )
    assert repository.load_run_manifest(run_id) == pinned_manifest
    assert (
        pinned_manifest.software_components[CONTROLLED_FAKE_ACQUISITION_COMPONENT_KEY]
        == CONTROLLED_FAKE_ACQUISITION_COMPONENT
    )
    assert publication.execution_manifest.component_manifest_id == (
        controlled_fake_acquisition_component_manifest_id()
    )
    assert publication.execution_manifest.model_manifest_id is None

    case_raw = canonical_json(committed.case.case.model_dump(mode="json"))
    case_sha256 = hashlib.sha256(case_raw.encode("utf-8")).hexdigest()
    matching_audits = tuple(
        item for item in repository.list_audit_entries(run_id) if item.after_sha256 == case_sha256
    )
    assert len(matching_audits) == 1
    selected_audit = matching_audits[0]
    binding = M6UpgradeCandidateCaseBinding(
        case_id=committed.case.case.case_id,
        case_revision=committed.case.revision,
        case_document_sha256=case_sha256,
        case_audit_sequence=selected_audit.sequence,
        case_audit_entry_hash=selected_audit.entry_hash,
    )
    anchor = M6UpgradeSelectedCaseAuditAnchor(
        candidate_case_binding_id=binding.case_binding_id,
        action=selected_audit.action,
        object_ref=selected_audit.object_ref,
    )

    previous_pack = repository.load_pack(run_id, request.current_evidence_pack_id)
    screening_request = m3_fixture._request(previous_pack)
    _role_bindings, hearing_calls = acquisition_plan_fixture._m4_inputs(
        repository,
        hearing_id=request.hearing_session_id,
    )
    model_calls = tuple(
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
                *hearing_calls,
            ),
            key=lambda item: item.sort_key,
        )
    )
    assert len(hearing_calls) == 3

    pixel_bytes = bytes((7, 8, 9))
    frame = FrameRef(
        camera_id="camera-builder-v3-acquisition",
        stream_id="stream-builder-v3-acquisition",
        frame_index=0,
        fps_num=25,
        fps_den=1,
        width=1,
        height=1,
        content_sha256=rgb8_pixel_sha256(1, 1, pixel_bytes),
    )
    repository.register_frame(run_id, frame)
    observation = M6UpgradeSampleExecutionObservationAuthorityV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=run_id,
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
                    M6UpgradeObservedArtifactIdentity(
                        source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                        kind=M6UpgradePhysicalArtifactKind.FRAME,
                        artifact_id=frame.frame_id,
                        usage=M6UpgradeArtifactUsage.CONSUMED,
                    ),
                    M6UpgradeObservedArtifactIdentity(
                        source=M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
                        kind=M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
                        artifact_id=committed.pack.pack_id,
                        usage=M6UpgradeArtifactUsage.PRODUCED,
                    ),
                    M6UpgradeObservedArtifactIdentity(
                        source=M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
                        kind=M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
                        artifact_id=(publication.execution_manifest.execution_manifest_id),
                        usage=M6UpgradeArtifactUsage.PRODUCED,
                    ),
                    M6UpgradeObservedArtifactIdentity(
                        source=M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
                        kind=M6UpgradePhysicalArtifactKind.TOOL_RESULT,
                        artifact_id=publication.tool_result.tool_result_id,
                        usage=M6UpgradeArtifactUsage.PRODUCED,
                    ),
                ),
                key=lambda item: item.sort_key,
            )
        ),
        model_calls=model_calls,
    )
    observations.append(observation)
    return _AcquisitionBuilderFixture(
        database=database,
        scope=scope,
        observation=observation,
        pixels=_PixelProvider(RGB8Frame(frame=frame, pixels=pixel_bytes), events),
        execution_manifest_id=publication.execution_manifest.execution_manifest_id,
        tool_result_id=publication.tool_result.tool_result_id,
    )


@dataclass(frozen=True, slots=True)
class _TrackedBuilder:
    builder: SQLiteM6UpgradeWholeSampleRecordBuilderV3
    m3_raw: _TrackingM3RawVerifier
    m4_raw: _TrackingM4RawVerifier
    pin_checks: list[tuple[str, str | None, str, str | None]]


def _tracked_builder(
    fixture: _AcquisitionBuilderFixture,
    monkeypatch: pytest.MonkeyPatch,
    events: list[str],
) -> _TrackedBuilder:
    real_pack_body = subject.resolve_m6_sqlite_evidence_pack_physical_plan
    real_m3_body = subject.resolve_m6_sqlite_m3_model_documents
    real_m4_body = subject.resolve_m6_sqlite_m4_model_documents
    real_metadata_record = build_m6_upgrade_case_replayed_metadata_acquisition_record_v3
    pin_checks: list[tuple[str, str | None, str, str | None]] = []

    def tracked_metadata_record(*args: object, **kwargs: object) -> object:
        events.append("metadata-record")
        return real_metadata_record(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_acquisition_body(*args: object, **kwargs: object) -> object:
        events.append("acquisition-body")
        metadata_plan = kwargs.get("metadata_plan")
        assert isinstance(metadata_plan, M6SQLiteAcquisitionDocumentsPlan)
        assert len(metadata_plan.closures) == 1
        manifest_slot = metadata_plan.closures[0].manifest
        snapshot = resolve_m6_sqlite_acquisition_documents(
            *args,  # type: ignore[arg-type]
            **kwargs,  # type: ignore[arg-type]
        )
        assert len(snapshot.resolved_acquisitions) == 1
        manifest_body = snapshot.resolved_acquisitions[0].execution_manifest
        pin_checks.append(
            (
                manifest_slot.component_manifest_id,
                manifest_slot.model_manifest_id,
                manifest_body.component_manifest_id,
                manifest_body.model_manifest_id,
            )
        )
        return snapshot

    def tracked_pack_body(*args: object, **kwargs: object) -> object:
        events.append("pack-body")
        return real_pack_body(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_m3_body(*args: object, **kwargs: object) -> object:
        events.append("m3-body")
        return real_m3_body(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_m4_body(*args: object, **kwargs: object) -> object:
        events.append("m4-body")
        return real_m4_body(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        subject,
        "build_m6_upgrade_case_replayed_metadata_acquisition_record_v3",
        tracked_metadata_record,
        raising=False,
    )
    monkeypatch.setattr(
        subject,
        "resolve_m6_sqlite_acquisition_documents",
        tracked_acquisition_body,
        raising=False,
    )
    monkeypatch.setattr(
        subject,
        "resolve_m6_sqlite_evidence_pack_physical_plan",
        tracked_pack_body,
    )
    monkeypatch.setattr(subject, "resolve_m6_sqlite_m3_model_documents", tracked_m3_body)
    monkeypatch.setattr(subject, "resolve_m6_sqlite_m4_model_documents", tracked_m4_body)
    m3_raw = _TrackingM3RawVerifier(events)
    m4_raw = _TrackingM4RawVerifier(events)
    return _TrackedBuilder(
        builder=SQLiteM6UpgradeWholeSampleRecordBuilderV3(
            fixture.database,
            BUSY_TIMEOUT_MS,
            pixel_provider=fixture.pixels,
            m3_raw_response_verifier=m3_raw,
            m4_raw_response_verifier=m4_raw,
        ),
        m3_raw=m3_raw,
        m4_raw=m4_raw,
        pin_checks=pin_checks,
    )


def _conflicting_acquisition_record(
    record: M6UpgradeSampleExecutionRecordV2,
) -> M6UpgradeSampleExecutionRecordV2:
    links = list(record.artifact_links)
    index = next(
        position
        for position, link in enumerate(links)
        if link.artifact.source == M6UpgradePhysicalArtifactSource.M4_ACQUISITION
    )
    link = links[index]
    links[index] = link.model_copy(
        update={
            "artifact": link.artifact.model_copy(
                update={
                    "document_sha256": "f" * 64,
                    "content_sha256": "f" * 64,
                }
            )
        }
    )
    payload = record.model_dump(
        mode="python",
        exclude={"schema_version"},
        exclude_computed_fields=True,
    )
    payload["artifact_links"] = tuple(links)
    return M6UpgradeSampleExecutionRecordV2(**payload)


def test_v3_builder_records_real_acquisition_without_calling_an_external_tool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    fixture = _prepare_acquisition_builder(tmp_path, monkeypatch, events)
    tracked = _tracked_builder(fixture, monkeypatch, events)

    def forbidden_external_tool(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("M6 replay must not execute an acquisition tool")

    monkeypatch.setattr(HearingAcquisitionService, "execute", forbidden_external_tool)
    record = tracked.builder.build_m6_upgrade_sample_record(
        fixture.scope.candidate_run_id,
        fixture.scope.execution_scope_authority_id,
    )

    acquisition_links = tuple(
        link
        for link in record.artifact_links
        if link.artifact.source == M6UpgradePhysicalArtifactSource.M4_ACQUISITION
    )
    assert record.observation_authority_id == fixture.observation.observation_authority_id
    assert len(acquisition_links) == 2
    assert {link.artifact.kind for link in acquisition_links} == {
        M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
        M6UpgradePhysicalArtifactKind.TOOL_RESULT,
    }
    assert {link.artifact.artifact_id for link in acquisition_links} == {
        fixture.execution_manifest_id,
        fixture.tool_result_id,
    }
    assert all(link.usage == M6UpgradeArtifactUsage.PRODUCED for link in acquisition_links)

    expected_component_pin = controlled_fake_acquisition_component_manifest_id()
    assert tracked.pin_checks == [(expected_component_pin, None, expected_component_pin, None)]
    assert events[0] == "metadata-record"
    for late_read in (
        "acquisition-body",
        "pack-body",
        "m3-body",
        "m4-body",
        "m3-raw",
        "m4-raw",
        "pixel",
    ):
        assert events.index(late_read) > events.index("metadata-record")


def test_v3_pending_conflict_stops_before_every_acquisition_and_existing_body_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    fixture = _prepare_acquisition_builder(tmp_path, monkeypatch, events)
    tracked = _tracked_builder(fixture, monkeypatch, events)
    first = tracked.builder.build_m6_upgrade_sample_record(
        fixture.scope.candidate_run_id,
        fixture.scope.execution_scope_authority_id,
    )
    pending = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        fixture.database,
        BUSY_TIMEOUT_MS,
    )
    conflicting = _conflicting_acquisition_record(first)
    commitment = _commitment(conflicting)
    assert pending.append(commitment) == commitment

    events.clear()
    tracked.m3_raw.calls.clear()
    tracked.m4_raw.calls.clear()
    tracked.pin_checks.clear()
    fixture.pixels.requested_ids.clear()
    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        tracked.builder.build_m6_upgrade_sample_record(
            fixture.scope.candidate_run_id,
            fixture.scope.execution_scope_authority_id,
        )

    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT
    )
    assert "metadata-record" in events
    assert not {
        "acquisition-body",
        "pack-body",
        "m3-body",
        "m4-body",
        "m3-raw",
        "m4-raw",
        "pixel",
    }.intersection(events)
    assert tracked.pin_checks == []
    assert tracked.m3_raw.calls == []
    assert tracked.m4_raw.calls == []
    assert fixture.pixels.requested_ids == []

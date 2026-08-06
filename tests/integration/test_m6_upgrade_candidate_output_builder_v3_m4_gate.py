from __future__ import annotations

from pathlib import Path

import pytest

import labcourt.adapters.storage.sqlite_m6_upgrade_candidate_output as subject
from labcourt.adapters.storage.sqlite_m6_upgrade_candidate_output import (
    SQLiteM6UpgradeCandidateOutputBuilderV3,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v3 import (
    SQLiteM6UpgradeExecutionLedgerV3Repository,
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
from labcourt.contracts.enums import (
    ArtifactKind,
    CaseStatus,
    MediaAvailability,
    VerificationStatus,
)
from labcourt.contracts.evidence import Crop
from labcourt.contracts.m6_regression import (
    M6RegressionStage,
    M6ReplayExecutionOutcome,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactKind
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification
from tests.integration.test_m6_upgrade_candidate_output_builder_v3 import (
    _commitment,
    _ExactArtifactVerifier,
    _FixedValidationReportProvider,
    _persist_run_cut,
)
from tests.integration.test_m6_upgrade_candidate_run_cut_migration import (
    _run_cut_for_seal,
)
from tests.integration.test_m6_upgrade_whole_sample_record_builder_v3_m4 import (
    BUSY_TIMEOUT_MS,
    _prepare_v3_m4_builder,
    _TrackingM3RawVerifier,
    _TrackingM4RawVerifier,
    _V3M4BuilderFixture,
)


class _TrackingCurrentCropVerifier:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.calls: list[str] = []

    def verify_crop(self, crop: Crop) -> ArtifactVerification:
        self.events.append("crop")
        self.calls.append(crop.crop_id)
        return ArtifactVerification(
            artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
            status=VerificationStatus.CURRENT_MEDIA_VERIFIED,
            availability=MediaAvailability.AVAILABLE,
            media_type=crop.media_type,
            expected_source_pixel_sha256=crop.source_media_sha256,
            expected_output_pixel_sha256=crop.pixel_sha256,
            actual_output_pixel_sha256=crop.pixel_sha256,
            expected_media_sha256=crop.media_sha256,
            actual_media_sha256=crop.media_sha256,
            expected_width=crop.output_width,
            actual_width=crop.output_width,
            expected_height=crop.output_height,
            actual_height=crop.output_height,
            expected_size_bytes=crop.size_bytes,
            actual_size_bytes=crop.size_bytes,
        )

    def reference_exists(self, run_id: str, ref: ArtifactRef) -> bool:
        del run_id, ref
        return False


def _seal_terminal_m4_fixture(
    fixture: _V3M4BuilderFixture,
    events: list[str],
) -> tuple[
    tuple[M6UpgradeSampleExecutionObservationAuthorityV2, ...],
    tuple[M6UpgradeSampleExecutionRecordV2, ...],
    M6UpgradeExecutionLedgerSealV2,
]:
    scope = fixture.scope
    verifier = _ExactArtifactVerifier()
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(
        fixture.database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=verifier,
    )
    observations_repository = SQLiteM6UpgradeExecutionObservationV3Repository(
        fixture.database,
        BUSY_TIMEOUT_MS,
    )
    commitments_repository = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        fixture.database,
        BUSY_TIMEOUT_MS,
    )
    ledger.begin_execution(scope)
    record_builder = SQLiteM6UpgradeWholeSampleRecordBuilderV3(
        fixture.database,
        BUSY_TIMEOUT_MS,
        pixel_provider=fixture.pixels,
        m3_raw_response_verifier=_TrackingM3RawVerifier(events),
        m4_raw_response_verifier=_TrackingM4RawVerifier(events),
    )
    execution_frame = next(
        item
        for item in fixture.observation.artifacts
        if item.kind == M6UpgradePhysicalArtifactKind.FRAME
        and item.artifact_id == fixture.pixels.frame.frame.frame_id
    )
    observations: list[M6UpgradeSampleExecutionObservationAuthorityV2] = []
    records: list[M6UpgradeSampleExecutionRecordV2] = []
    for sequence, entry in enumerate(scope.execution_dataset.entries):
        if sequence == 0:
            observation = fixture.observation
        else:
            payload = fixture.observation.model_dump(
                mode="python",
                exclude={"schema_version"},
                exclude_computed_fields=True,
            )
            payload.update(
                ledger_sequence=sequence,
                execution_entry=entry,
                outcome=M6ReplayExecutionOutcome.NO_CASE,
                candidate_case=None,
                selected_case_audit_anchor=None,
                artifacts=(execution_frame,),
                model_calls=(),
            )
            observation = M6UpgradeSampleExecutionObservationAuthorityV2(**payload)
            observations_repository.append(observation)
        record = record_builder.build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
        verifier.allow(record)
        commitment = _commitment(record)
        commitments_repository.append(commitment)
        assert ledger.append_committed_sample(commitment) == record
        observations.append(observation)
        records.append(record)
    seal = ledger.seal(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    return tuple(observations), tuple(records), seal


def test_terminal_m4_gate_builds_exact_inventory_in_global_late_read_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    fixture = _prepare_v3_m4_builder(
        tmp_path,
        monkeypatch,
        events=events,
        include_case_semantic_frames=True,
    )
    observations, records, seal = _seal_terminal_m4_fixture(fixture, events)
    cut = _run_cut_for_seal(fixture.scope, seal)
    _persist_run_cut(
        fixture.database,
        fixture.scope,
        seal,
        _FixedValidationReportProvider(cut.validation_report),
    )

    tracked_names = (
        ("resolve_m6_sqlite_evidence_pack_physical_plan", "pack-body"),
        ("resolve_m6_sqlite_m3_model_documents", "m3-body"),
        ("resolve_m6_sqlite_m4_model_documents", "m4-body"),
        ("resolve_m6_sqlite_m5_precedent_documents", "m5-body"),
        ("resolve_m6_sqlite_m4_gate_documents", "gate-body"),
    )
    for name, event_name in tracked_names:
        original = getattr(subject, name)

        def tracked(
            *args: object,
            _original: object = original,
            _event_name: str = event_name,
            **kwargs: object,
        ) -> object:
            events.append(_event_name)
            return _original(*args, **kwargs)  # type: ignore[operator]

        monkeypatch.setattr(subject, name, tracked)

    real_perception = SQLiteM6UpgradeCandidateOutputBuilderV3._resolved_perception

    def tracked_perception(*args: object, **kwargs: object) -> object:
        events.append("perception-body")
        return real_perception(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        SQLiteM6UpgradeCandidateOutputBuilderV3,
        "_resolved_perception",
        staticmethod(tracked_perception),
    )

    events.clear()
    fixture.pixels.requested_ids.clear()
    m3_raw = _TrackingM3RawVerifier(events)
    m4_raw = _TrackingM4RawVerifier(events)
    crop_verifier = _TrackingCurrentCropVerifier(events)
    observed = SQLiteM6UpgradeCandidateOutputBuilderV3(
        fixture.database,
        BUSY_TIMEOUT_MS,
        pixel_provider=fixture.pixels,
        m3_raw_response_verifier=m3_raw,
        m4_raw_response_verifier=m4_raw,
        current_crop_verifier=crop_verifier,
    ).build_terminal_inventory(
        fixture.scope_run_id,
        fixture.scope_id,
    )

    assert observed.execution_ledger == seal
    assert observed.execution_observations == observations
    assert len(observed.outputs) == len(records)
    first = observed.outputs[0]
    assert first.candidate_snapshot is not None
    assert first.candidate_snapshot.case_status == CaseStatus.READY_FOR_ALERT_POLICY
    assert tuple(root.stage for root in first.candidate_snapshot.stage_roots) == tuple(
        M6RegressionStage
    )
    assert len(first.model_calls) == 4
    assert all(item.provider_invoked for item in first.model_calls)
    assert len(first.evidence_packs) == 1
    assert all(item.candidate_snapshot is None for item in observed.outputs[1:])
    assert len(m3_raw.calls) == 1
    assert len(m4_raw.calls) == 3
    assert crop_verifier.calls
    assert len(crop_verifier.calls) == len(set(crop_verifier.calls))

    body_events = {
        "perception-body",
        "pack-body",
        "m3-body",
        "m4-body",
        "m5-body",
        "gate-body",
    }
    first_m3_raw = events.index("m3-raw")
    first_m4_raw = events.index("m4-raw")
    first_crop = events.index("crop")
    first_pixel = events.index("pixel")
    assert events[:first_m3_raw]
    assert set(events[:first_m3_raw]).issubset(body_events)
    assert first_m3_raw < first_m4_raw
    assert max(index for index, event in enumerate(events) if event == "m4-raw") < first_crop
    assert max(index for index, event in enumerate(events) if event == "crop") < first_pixel
    assert all(event == "pixel" for event in events[first_pixel:])

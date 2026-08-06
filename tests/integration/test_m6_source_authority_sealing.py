from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Event

import pytest

from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.application.m6_source_authority_sealing import (
    M6SourceAuthoritySealingError,
    M6SourceAuthoritySealingErrorCode,
    seal_m6_gate_current_closures,
)
from labcourt.contracts.enums import (
    ArtifactKind,
    MediaAvailability,
    VerificationStatus,
)
from labcourt.contracts.evidence import Crop, EvidencePackDraft
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.retention import PurgeLease
from tests.integration.test_m2_sqlite_repository import _retention_draft
from tests.integration.test_m3_sqlite_repository import (
    BUSY_TIMEOUT_MS,
    RECORDED_AT,
    RUN_ID,
)
from tests.integration.test_m5_sqlite_alert_repository import (
    _manifest_with_stream,
    _prepare_ready_case,
)
from tests.integration.test_m5_sqlite_appeals import _prepare_overturn


class _CurrentCropVerifier:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def verify_crop(self, crop: Crop) -> ArtifactVerification:
        self.calls.append(crop.crop_id)
        if crop.availability != MediaAvailability.AVAILABLE:
            return ArtifactVerification(
                artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
                status=VerificationStatus.MISSING,
                availability=crop.availability,
                media_type=crop.media_type,
                expected_source_pixel_sha256=crop.source_media_sha256,
                expected_output_pixel_sha256=crop.pixel_sha256,
                expected_media_sha256=crop.media_sha256,
                expected_width=crop.output_width,
                expected_height=crop.output_height,
                expected_size_bytes=crop.size_bytes,
                reason_code="MEDIA_NOT_AVAILABLE",
            )
        return ArtifactVerification(
            artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
            status=VerificationStatus.CURRENT_MEDIA_VERIFIED,
            availability=crop.availability,
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


class _BlockingCurrentCropVerifier(_CurrentCropVerifier):
    def __init__(self, entered: Event, release: Event) -> None:
        super().__init__()
        self._entered = entered
        self._release = release

    def verify_crop(self, crop: Crop) -> ArtifactVerification:
        self._entered.set()
        if not self._release.wait(timeout=5):
            raise AssertionError("test did not release the blocking verifier")
        return super().verify_crop(crop)


def _m5_retention_draft() -> EvidencePackDraft:
    manifest = _manifest_with_stream()
    base = _retention_draft(version=1, complete=True)
    payload = base.model_dump(mode="json", exclude_computed_fields=True)
    payload["manifest_id"] = manifest.manifest_id
    payload["event"] = base.event.model_copy(
        update={"manifest_id": manifest.manifest_id}
    ).model_dump(mode="json")
    return EvidencePackDraft.model_validate(payload)


def test_repository_observes_each_distinct_crop_once_without_writing(tmp_path: Path) -> None:
    database, evidence, _, ready, _, _ = _prepare_ready_case(tmp_path)
    verifier = _CurrentCropVerifier()
    observer = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS, verifier=verifier)
    before = evidence.get_audit_head(RUN_ID)

    observation = observer.observe_m6_gate_source(RUN_ID, ready.case.case_id)
    sealed = seal_m6_gate_current_closures(observation=observation)

    after = evidence.get_audit_head(RUN_ID)
    reviewed_pack_ids = {item.evidence_pack_id for item in ready.case.procedural_reviews}
    distinct_crop_ids = {
        crop.crop_id
        for pack in ready.case.evidence_packs
        if pack.pack_id in reviewed_pack_ids
        for crop in pack.crops
    }
    assert set(verifier.calls) == distinct_crop_ids
    assert len(verifier.calls) == len(distinct_crop_ids)
    assert before == after
    assert sealed.source_case == ready.case
    assert sealed.source_case_revision == ready.revision
    assert len(sealed.gate_current_closures) == len(ready.case.procedural_reviews)


def test_missing_verifier_cannot_create_current_media_receipts(tmp_path: Path) -> None:
    database, _, _, ready, _, _ = _prepare_ready_case(tmp_path)
    observer = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS)

    observation = observer.observe_m6_gate_source(RUN_ID, ready.case.case_id)

    assert observation.packs[0].current_closure.passed is False
    assert observation.packs[0].crop_verifications == ()
    with pytest.raises(M6SourceAuthoritySealingError) as raised:
        seal_m6_gate_current_closures(observation=observation)
    assert raised.value.code == M6SourceAuthoritySealingErrorCode.CURRENT_CLOSURE_INVALID


def test_repository_observes_exact_pre_appeal_revision_after_resolution(
    tmp_path: Path,
) -> None:
    database, repository, closed, _, _, _, _, _, _, intent = _prepare_overturn(tmp_path)
    repository.commit_resolution(intent)
    resolved = repository.load_case(RUN_ID, closed.case.case_id)
    assert resolved.revision == closed.revision + 3

    observer = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_CurrentCropVerifier(),
    )
    observation = observer.observe_m6_gate_source(
        RUN_ID,
        closed.case.case_id,
        closed.revision,
    )
    sealed = seal_m6_gate_current_closures(observation=observation)

    assert sealed.source_case == closed.case
    assert sealed.source_case_revision == closed.revision
    assert sealed.source_case.status.value == "CLOSED"
    assert sealed.source_case.final_decision != resolved.case.final_decision

    with pytest.raises(ValueError, match="positive integer"):
        observer.observe_m6_gate_source(RUN_ID, closed.case.case_id, 0)


def test_writer_fence_blocks_retention_until_all_crop_reads_finish(tmp_path: Path) -> None:
    database, evidence, _, ready, _, _ = _prepare_ready_case(
        tmp_path,
        draft=_m5_retention_draft(),
    )
    entered = Event()
    release = Event()
    verifier = _BlockingCurrentCropVerifier(entered, release)
    observer = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS, verifier=verifier)
    retention = SQLiteEvidenceRepository(database, 50)
    pack = next(
        item
        for item in ready.case.evidence_packs
        if item.pack_id == ready.case.procedural_reviews[0].evidence_pack_id
    )
    media_sha256 = pack.crops[0].media_sha256
    before = evidence.get_audit_head(RUN_ID)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            observer.observe_m6_gate_source,
            RUN_ID,
            ready.case.case_id,
        )
        try:
            assert entered.wait(timeout=2)
            with pytest.raises(ConcurrentModification):
                retention.begin_media_purge(
                    RUN_ID,
                    media_sha256,
                    RECORDED_AT + timedelta(days=3650),
                    "retention-v1",
                )
        finally:
            release.set()
        observation = future.result(timeout=5)

    assert evidence.get_audit_head(RUN_ID) == before
    sealed = seal_m6_gate_current_closures(observation=observation)
    assert sealed.gate_current_closures

    lease = retention.begin_media_purge(
        RUN_ID,
        media_sha256,
        RECORDED_AT + timedelta(days=3650),
        "retention-v1",
    )
    assert isinstance(lease, PurgeLease)
    after_purge = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_CurrentCropVerifier(),
    ).observe_m6_gate_source(RUN_ID, ready.case.case_id)
    with pytest.raises(M6SourceAuthoritySealingError):
        seal_m6_gate_current_closures(observation=after_purge)

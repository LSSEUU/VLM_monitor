from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.storage._sqlite_m6_live_read_cut import (
    M6LiveReader,
    m6_live_committed_read_cut,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_case_document import (
    M6SQLiteCaseAuthorityDocument,
    read_m6_sqlite_case_authority_v3,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_evidence_pack_document import (
    M6SQLiteEvidencePackPhysicalPlan,
    plan_m6_sqlite_evidence_pack_physical_identity,
    resolve_m6_sqlite_evidence_pack_physical_plan,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_gate_current_source import (
    M6SQLiteGateCurrentSourceError,
    M6SQLiteGateCurrentSourceFailureCode,
    seal_m6_sqlite_gate_current_source,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_physical_documents import (
    M6SQLiteCanonicalPhysicalDocument,
)
from labcourt.contracts.enums import (
    ArtifactKind,
    MediaAvailability,
    VerificationStatus,
)
from labcourt.contracts.evidence import Crop
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification
from tests.integration.test_m6_upgrade_whole_sample_record_builder_v3_m4 import (
    BUSY_TIMEOUT_MS,
    _prepare_v3_m4_builder,
    _V3M4BuilderFixture,
)


class _CurrentCropVerifier:
    def __init__(self, *, current: bool = True) -> None:
        self.calls: list[str] = []
        self._current = current

    def verify_crop(self, crop: Crop) -> ArtifactVerification:
        self.calls.append(crop.crop_id)
        return ArtifactVerification(
            artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
            status=(
                VerificationStatus.CURRENT_MEDIA_VERIFIED
                if self._current
                else VerificationStatus.VERIFIED
            ),
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


def _resolved_reviewed_packs(
    reader: M6LiveReader,
    fixture: _V3M4BuilderFixture,
) -> tuple[
    M6SQLiteCaseAuthorityDocument,
    tuple[M6SQLiteEvidencePackPhysicalPlan, ...],
    tuple[M6SQLiteCanonicalPhysicalDocument, ...],
    int,
    str,
]:
    observation = fixture.observation
    binding = observation.candidate_case
    anchor = observation.selected_case_audit_anchor
    assert binding is not None and anchor is not None
    authority = read_m6_sqlite_case_authority_v3(
        connection=reader,
        expected_run_id=fixture.scope.candidate_run_id,
        expected_manifest_id=fixture.scope.candidate_manifest.manifest_id,
        expected_manifest_rule_version=fixture.scope.candidate_manifest.rule_version,
        candidate_case_binding=binding,
        selected_case_audit_anchor=anchor,
    )
    reviewed_pack_ids = tuple(
        sorted({review.evidence_pack_id for review in authority.case.procedural_reviews})
    )
    plans = tuple(
        plan_m6_sqlite_evidence_pack_physical_identity(
            connection=reader,
            expected_run_id=authority.case.run_id,
            expected_manifest_id=authority.case.manifest_id,
            selected_case_authority=authority,
            pack_id=pack_id,
        )
        for pack_id in reviewed_pack_ids
    )
    documents = tuple(
        resolve_m6_sqlite_evidence_pack_physical_plan(
            connection=reader,
            physical_plan=plan,
        )
        for plan in plans
    )
    cursor = reader.execute(
        """
        SELECT audit_head_sequence, audit_head_hash
        FROM runs WHERE run_id = ?
        """,
        (authority.case.run_id,),
    )
    try:
        row = cursor.fetchone()
    finally:
        cursor.close()
    assert row is not None
    audit_head_sequence = row["audit_head_sequence"]
    audit_head_hash = row["audit_head_hash"]
    assert type(audit_head_sequence) is int
    assert isinstance(audit_head_hash, str)
    return authority, plans, documents, audit_head_sequence, audit_head_hash


def test_seals_exact_current_crop_rows_on_the_existing_live_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _prepare_v3_m4_builder(tmp_path, monkeypatch, events=[])
    verifier = _CurrentCropVerifier()

    with m6_live_committed_read_cut(fixture.database, BUSY_TIMEOUT_MS) as cut:
        with cut.selector():
            pass
        with cut.reader() as reader:
            authority, plans, documents, head_sequence, head_hash = _resolved_reviewed_packs(
                reader,
                fixture,
            )
            sealed = seal_m6_sqlite_gate_current_source(
                connection=reader,
                selected_case_authority=authority,
                evidence_pack_plans=plans,
                resolved_evidence_packs=documents,
                expected_audit_head_sequence=head_sequence,
                expected_audit_head_hash=head_hash,
                crop_verifier=verifier,
            )
            assert reader.in_transaction is True
        with cut.writer():
            pass

    reviewed_pack_ids = {review.evidence_pack_id for review in authority.case.procedural_reviews}
    expected_crop_ids = sorted(
        crop.crop_id
        for pack in authority.case.evidence_packs
        if pack.pack_id in reviewed_pack_ids
        for crop in pack.crops
    )
    assert verifier.calls == expected_crop_ids
    assert sealed.source_case == authority.case
    assert sealed.source_case_revision == authority.candidate_case_binding.case_revision
    assert sealed.source_case_document_sha256 == authority.case_document_sha256
    assert sealed.audit_head_sequence == head_sequence
    assert sealed.audit_head_hash == head_hash
    assert len(sealed.gate_current_closures) == len(
        {
            (item.evidence_pack_id, item.evidence_pack_version)
            for item in authority.case.procedural_reviews
        }
    )
    assert all(item.current_closure.passed for item in sealed.gate_current_closures)
    assert all(
        verification.status == VerificationStatus.CURRENT_MEDIA_VERIFIED
        for receipt in sealed.gate_current_closures
        for verification in receipt.crop_verifications
    )


def test_rejects_tampered_crop_document_before_calling_the_verifier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _prepare_v3_m4_builder(tmp_path, monkeypatch, events=[])
    connection = sqlite3.connect(fixture.database)
    try:
        trigger_row = connection.execute(
            """
            SELECT sql FROM sqlite_schema
            WHERE type = 'trigger' AND name = 'evidence_pack_crops_no_update'
            """
        ).fetchone()
        assert trigger_row is not None and isinstance(trigger_row[0], str)
        trigger_sql = trigger_row[0]
        connection.execute("DROP TRIGGER evidence_pack_crops_no_update")
        changed = connection.execute(
            """
            UPDATE evidence_pack_crops
            SET crop_json = '[' || substr(crop_json, 2)
            WHERE rowid = (SELECT MIN(rowid) FROM evidence_pack_crops)
            """
        ).rowcount
        assert changed == 1
        connection.execute(trigger_sql)
        connection.commit()
    finally:
        connection.close()
    verifier = _CurrentCropVerifier()

    with (
        pytest.raises(M6SQLiteGateCurrentSourceError) as raised,
        m6_live_committed_read_cut(fixture.database, BUSY_TIMEOUT_MS) as cut,
    ):
        with cut.selector():
            pass
        with cut.reader() as reader:
            authority, plans, documents, head_sequence, head_hash = _resolved_reviewed_packs(
                reader, fixture
            )
            seal_m6_sqlite_gate_current_source(
                connection=reader,
                selected_case_authority=authority,
                evidence_pack_plans=plans,
                resolved_evidence_packs=documents,
                expected_audit_head_sequence=head_sequence,
                expected_audit_head_hash=head_hash,
                crop_verifier=verifier,
            )

    assert raised.value.reason_code == M6SQLiteGateCurrentSourceFailureCode.CROP_DOCUMENT_INVALID
    assert verifier.calls == []


def test_rejects_a_noncurrent_verifier_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _prepare_v3_m4_builder(tmp_path, monkeypatch, events=[])
    verifier = _CurrentCropVerifier(current=False)

    with (
        pytest.raises(M6SQLiteGateCurrentSourceError) as raised,
        m6_live_committed_read_cut(fixture.database, BUSY_TIMEOUT_MS) as cut,
    ):
        with cut.selector():
            pass
        with cut.reader() as reader:
            authority, plans, documents, head_sequence, head_hash = _resolved_reviewed_packs(
                reader, fixture
            )
            seal_m6_sqlite_gate_current_source(
                connection=reader,
                selected_case_authority=authority,
                evidence_pack_plans=plans,
                resolved_evidence_packs=documents,
                expected_audit_head_sequence=head_sequence,
                expected_audit_head_hash=head_hash,
                crop_verifier=verifier,
            )

    assert raised.value.reason_code == (
        M6SQLiteGateCurrentSourceFailureCode.CURRENT_MEDIA_VERIFICATION_FAILED
    )
    assert verifier.calls

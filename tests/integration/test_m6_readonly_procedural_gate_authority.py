from __future__ import annotations

from pathlib import Path

from labcourt.adapters.storage.readonly_m4_artifacts import ReadonlyM4ArtifactRepository
from labcourt.adapters.storage.readonly_m6_procedural_gate_authority import (
    ReadonlyM6ProceduralGateAuthorityRepository,
)
from labcourt.contracts.enums import ArtifactKind
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.hearing_fsm import (
    begin_hearing,
    complete_precedent_retrieval,
    complete_prosecutor,
)
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m4_readonly_projection import (
    _hearing_retrieval,
    _persist_hearing_call,
    _started_hearing,
)
from tests.unit.test_m4_hearing_domain import _payloads


def test_gate_adapter_exports_full_scan_including_usage_authority(tmp_path: Path) -> None:
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
    prosecutor_payload, _, _ = _payloads(evidence_ref=crop_ref)
    prosecutor, trace = _persist_hearing_call(
        started,
        checkpoint,
        retrieval,
        prosecutor_payload,
    )
    checkpoint = complete_prosecutor(started.session, checkpoint, prosecutor, trace)
    started.repository.append_hearing_checkpoint(RUN_ID, checkpoint)

    full = ReadonlyM4ArtifactRepository(started.database, immutable=True).scan(RUN_ID)
    snapshot = ReadonlyM6ProceduralGateAuthorityRepository(
        started.database
    ).load_validated_snapshot(RUN_ID)

    kinds = {item.kind for item in snapshot.documents}
    assert full.failures == ()
    assert snapshot.source_m4_authority_root_sha256 == full.authority_root_sha256
    assert M4ProjectionArtifactKind.USAGE_RECEIPT in kinds
    assert M4ProjectionArtifactKind.HEARING_CHECKPOINT in kinds
    assert M4ProjectionArtifactKind.USAGE_RECEIPT in {item.kind for item in full.replay_documents}

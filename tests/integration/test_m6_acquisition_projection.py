from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from labcourt.adapters.storage.readonly_m6_acquisition_authority import (
    ReadonlyM6AcquisitionAuthorityRepository,
)
from labcourt.adapters.storage.readonly_sqlite import readonly_sqlite_snapshot
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m6_replay_locked import (
    M6LockedToolResultInput,
    M6ReplayAuthorityKind,
    M6ReplayAuthorityRef,
)
from labcourt.domain.hearing_fsm import complete_acquisition
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m4_acquisition_execution_fencing import (
    _committed_successor,
)


def _ref(kind: M6ReplayAuthorityKind, document: object) -> M6ReplayAuthorityRef:
    return M6ReplayAuthorityRef(
        kind=kind,
        artifact_id=document.artifact_id,
        document_sha256=document.document_sha256,
    )


def test_readonly_repository_resolves_real_scanned_acquisition_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, host, request, publication, committed = _committed_successor(
        tmp_path,
        monkeypatch,
    )
    session = host.load_active_hearing(RUN_ID, request.case_id)
    assert session is not None
    checkpoint = host.load_latest_hearing_checkpoint(RUN_ID, session.session_id)
    host.append_hearing_checkpoint(
        RUN_ID,
        complete_acquisition(session, checkpoint, committed.receipt),
    )
    source_case = host.load_case(RUN_ID, request.case_id).case

    with readonly_sqlite_snapshot(database) as snapshot_path:
        repository = ReadonlyM6AcquisitionAuthorityRepository(snapshot_path)
        authority = repository.load_validated_snapshot(RUN_ID)
        documents = {(item.kind, item.artifact_id): item for item in authority.documents}
        request_document = documents[
            (M4ProjectionArtifactKind.ACQUISITION_REQUEST, request.request_id)
        ]
        manifest_document = documents[
            (
                M4ProjectionArtifactKind.TOOL_EXECUTION_MANIFEST,
                publication.execution_manifest.execution_manifest_id,
            )
        ]
        publication_document = documents[
            (
                M4ProjectionArtifactKind.ACQUISITION_EXECUTION_PUBLICATION,
                publication.publication_id,
            )
        ]
        receipt_document = documents[
            (
                M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT,
                committed.receipt.receipt_id,
            )
        ]
        derivation_document = next(
            item
            for item in authority.documents
            if item.kind == M4ProjectionArtifactKind.EVIDENCE_PACK_DERIVATION
        )
        result_document = canonical_json(committed.receipt.tool_result.model_dump(mode="json"))
        pack_document = canonical_json(committed.pack.model_dump(mode="json"))
        locked = M6LockedToolResultInput(
            tool_result_id=committed.receipt.tool_result.tool_result_id,
            tool_result_document_sha256=hashlib.sha256(result_document.encode("utf-8")).hexdigest(),
            acquisition_request_ref=_ref(
                M6ReplayAuthorityKind.M4_ACQUISITION_REQUEST,
                request_document,
            ),
            execution_manifest_ref=_ref(
                M6ReplayAuthorityKind.M4_TOOL_EXECUTION_MANIFEST,
                manifest_document,
            ),
            execution_publication_ref=_ref(
                M6ReplayAuthorityKind.M4_ACQUISITION_PUBLICATION,
                publication_document,
            ),
            tool_receipt_ref=_ref(
                M6ReplayAuthorityKind.M4_TOOL_EXECUTION_RECEIPT,
                receipt_document,
            ),
            evidence_pack_derivation_ref=_ref(
                M6ReplayAuthorityKind.M4_EVIDENCE_PACK_DERIVATION,
                derivation_document,
            ),
            resulting_evidence_pack_ref=M6ReplayAuthorityRef(
                kind=M6ReplayAuthorityKind.EVIDENCE_PACK,
                artifact_id=committed.pack.pack_id,
                document_sha256=hashlib.sha256(pack_document.encode("utf-8")).hexdigest(),
            ),
        )
        resolved = repository.resolve(
            source_case=source_case,
            locked_tool_results=(locked,),
        )

    assert len(resolved) == 1
    assert resolved[0].publication == publication
    assert resolved[0].receipt == committed.receipt
    assert resolved[0].resulting_evidence_pack == committed.pack

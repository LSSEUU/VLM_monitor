from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

import labcourt.adapters.storage.readonly_m4_artifacts as readonly_m4_artifacts
from labcourt.adapters.storage.readonly_m4_artifacts import (
    M4ReplayAuthoritySnapshot,
    M4ValidatedReplayDocument,
    ReadonlyM4ArtifactRepository,
)
from labcourt.adapters.storage.readonly_sqlite import (
    ReadOnlySnapshotError,
    readonly_sqlite_snapshot,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import ArtifactKind
from labcourt.contracts.hearing import (
    AcquisitionExecutionPublication,
    AcquisitionRequest,
    EvidencePackDerivation,
    HearingModelCacheEntry,
    HearingModelCallFailureAuthority,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingPrecedentRetrievalReceipt,
    HearingRoleOutput,
    HearingUsageReceipt,
    ToolExecutionManifest,
    ToolExecutionReceipt,
)
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.hearing_fsm import (
    begin_hearing,
    complete_acquisition,
    complete_precedent_retrieval,
    complete_prosecutor,
)
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m4_acquisition_execution_fencing import _committed_successor
from tests.integration.test_m4_readonly_projection import (
    _drop_restore_trigger,
    _hearing_retrieval,
    _persist_hearing_call,
    _started_hearing,
)
from tests.integration.test_m4_sqlite_hearing_retry import _provider_outage_seed
from tests.unit.test_m4_hearing_domain import _payloads


def _scan_replay(database: Path) -> M4ReplayAuthoritySnapshot:
    with readonly_sqlite_snapshot(database) as snapshot:
        return ReadonlyM4ArtifactRepository(snapshot).scan_replay_authority(RUN_ID)


def _one_role_call(database_root: Path):
    started = _started_hearing(database_root)
    checkpoint = begin_hearing(started.session)
    retrieval = _hearing_retrieval(started)
    started.repository.append_precedent_retrieval(RUN_ID, retrieval)
    checkpoint = complete_precedent_retrieval(started.session, checkpoint, retrieval)
    started.repository.append_hearing_checkpoint(RUN_ID, checkpoint)
    evidence_ref = ArtifactRef(
        kind=ArtifactKind.CROP,
        artifact_id=started.pack.crops[0].crop_id,
    )
    prosecutor_payload, _defender_payload, _judge_payload = _payloads(evidence_ref=evidence_ref)
    prosecutor, trace = _persist_hearing_call(
        started,
        checkpoint,
        retrieval,
        prosecutor_payload,
    )
    checkpoint = complete_prosecutor(started.session, checkpoint, prosecutor, trace)
    started.repository.append_hearing_checkpoint(RUN_ID, checkpoint)
    return started


def test_replay_authority_exposes_exact_typed_model_call_documents(
    tmp_path: Path,
) -> None:
    started = _one_role_call(tmp_path)

    first = _scan_replay(started.database)
    second = _scan_replay(started.database)

    expected_types = {
        M4ProjectionArtifactKind.PRECEDENT_RETRIEVAL: (HearingPrecedentRetrievalReceipt),
        M4ProjectionArtifactKind.MODEL_REQUEST: HearingModelRequest,
        M4ProjectionArtifactKind.MODEL_RESPONSE: HearingModelResponse,
        M4ProjectionArtifactKind.MODEL_CACHE_ENTRY: HearingModelCacheEntry,
        M4ProjectionArtifactKind.USAGE_RECEIPT: HearingUsageReceipt,
        M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT: HearingModelParseReceipt,
        M4ProjectionArtifactKind.ROLE_OUTPUT: HearingRoleOutput,
    }
    assert first == second
    assert first.authority_root_sha256 == second.authority_root_sha256
    assert tuple(item.sort_key for item in first.documents) == tuple(
        sorted(item.sort_key for item in first.documents)
    )
    for kind, expected_type in expected_types.items():
        documents = first.documents_of_kind(kind)
        assert len(documents) == 1
        assert isinstance(documents[0].document, expected_type)
        canonical = canonical_json(documents[0].document.model_dump(mode="json"))
        assert documents[0].canonical_document == canonical
        assert documents[0].document_sha256 == hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def test_replay_authority_uses_one_read_only_sqlite_connection(tmp_path: Path) -> None:
    started = _one_role_call(tmp_path)

    with readonly_sqlite_snapshot(started.database) as snapshot:
        original_connect = sqlite3.connect
        with patch.object(
            readonly_m4_artifacts.sqlite3,
            "connect",
            wraps=original_connect,
        ) as connect:
            ReadonlyM4ArtifactRepository(snapshot).scan_replay_authority(RUN_ID)

    connect.assert_called_once()
    database_uri = connect.call_args.args[0]
    assert isinstance(database_uri, str) and database_uri.endswith("?mode=ro")
    assert connect.call_args.kwargs == {"uri": True, "isolation_level": None}


def test_replay_authority_exposes_closed_acquisition_chain(
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

    authority = _scan_replay(database)
    request_document = authority.documents_of_kind(M4ProjectionArtifactKind.ACQUISITION_REQUEST)
    manifest_document = authority.documents_of_kind(
        M4ProjectionArtifactKind.TOOL_EXECUTION_MANIFEST
    )
    publication_document = authority.documents_of_kind(
        M4ProjectionArtifactKind.ACQUISITION_EXECUTION_PUBLICATION
    )
    receipt_document = authority.documents_of_kind(M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT)
    derivation_document = authority.documents_of_kind(
        M4ProjectionArtifactKind.EVIDENCE_PACK_DERIVATION
    )

    assert tuple(item.document for item in request_document) == (request,)
    assert tuple(item.document for item in manifest_document) == (publication.execution_manifest,)
    assert tuple(item.document for item in publication_document) == (publication,)
    assert tuple(item.document for item in receipt_document) == (committed.receipt,)
    assert len(derivation_document) == 1
    derivation = derivation_document[0].document
    assert isinstance(derivation, EvidencePackDerivation)
    assert derivation.previous_evidence_pack_id == request.current_evidence_pack_id
    assert derivation.new_evidence_pack_id == committed.pack.pack_id
    assert derivation.tool_execution_receipt_id == committed.receipt.receipt_id
    assert isinstance(request_document[0].document, AcquisitionRequest)
    assert isinstance(manifest_document[0].document, ToolExecutionManifest)
    assert isinstance(publication_document[0].document, AcquisitionExecutionPublication)
    assert isinstance(receipt_document[0].document, ToolExecutionReceipt)


def test_replay_authority_exposes_typed_model_call_failure(tmp_path: Path) -> None:
    seed = _provider_outage_seed(tmp_path)

    authority = _scan_replay(seed.database)

    failure_documents = authority.documents_of_kind(
        M4ProjectionArtifactKind.MODEL_CALL_FAILURE_AUTHORITY
    )
    assert len(failure_documents) == 1
    failure = failure_documents[0].document
    assert isinstance(failure, HearingModelCallFailureAuthority)
    assert failure.authority_id == failure_documents[0].artifact_id


def test_replay_authority_snapshot_rejects_duplicate_foreign_and_forged_documents(
    tmp_path: Path,
) -> None:
    started = _one_role_call(tmp_path)
    authority = _scan_replay(started.database)
    request_document = authority.documents_of_kind(M4ProjectionArtifactKind.MODEL_REQUEST)[0]

    with pytest.raises(ReadOnlySnapshotError, match="DUPLICATE_VALIDATED_DOCUMENT"):
        M4ReplayAuthoritySnapshot(
            run_id=RUN_ID,
            source_authority_root_sha256=authority.source_authority_root_sha256,
            documents=(request_document, request_document),
        )

    with pytest.raises(ReadOnlySnapshotError, match="FOREIGN_VALIDATED_DOCUMENT"):
        M4ReplayAuthoritySnapshot(
            run_id="foreign-run",
            source_authority_root_sha256=authority.source_authority_root_sha256,
            documents=(request_document,),
        )

    forged_payload = request_document.document.model_dump(mode="python")
    forged_payload["prior_acquisition_rounds"] = -1
    forged_request = HearingModelRequest.model_construct(**forged_payload)
    with pytest.raises(
        ReadOnlySnapshotError,
        match="VALIDATED_DOCUMENT_CONTRACT_INVALID",
    ):
        M4ValidatedReplayDocument(
            kind=M4ProjectionArtifactKind.MODEL_REQUEST,
            artifact_id=request_document.artifact_id,
            document=forged_request,
            record_identity_sha256=request_document.record_identity_sha256,
        )

    nested_document = M4ValidatedReplayDocument(
        kind=request_document.kind,
        artifact_id=request_document.artifact_id,
        document=HearingModelRequest.model_validate(
            request_document.document.model_dump(mode="json")
        ),
        record_identity_sha256=request_document.record_identity_sha256,
    )
    object.__setattr__(nested_document.document, "prior_acquisition_rounds", -1)
    with pytest.raises(
        ReadOnlySnapshotError,
        match="VALIDATED_DOCUMENT_CONTRACT_INVALID",
    ):
        M4ReplayAuthoritySnapshot(
            run_id=RUN_ID,
            source_authority_root_sha256=authority.source_authority_root_sha256,
            documents=(nested_document,),
        )


def test_replay_authority_fails_closed_on_noncanonical_durable_document(
    tmp_path: Path,
) -> None:
    started = _one_role_call(tmp_path)
    with sqlite3.connect(started.database) as connection:

        def tamper() -> None:
            row = connection.execute(
                "SELECT response_json FROM m4_model_responses WHERE run_id = ?",
                (RUN_ID,),
            ).fetchone()
            assert row is not None and isinstance(row[0], str)
            connection.execute(
                "UPDATE m4_model_responses SET response_json = ? WHERE run_id = ?",
                (row[0] + " ", RUN_ID),
            )

        _drop_restore_trigger(connection, "m4_model_responses_no_update", tamper)

    with (
        readonly_sqlite_snapshot(started.database) as snapshot,
        pytest.raises(ReadOnlySnapshotError, match="DATABASE_AUTHORITY_INVALID"),
    ):
        ReadonlyM4ArtifactRepository(snapshot).scan_replay_authority(RUN_ID)

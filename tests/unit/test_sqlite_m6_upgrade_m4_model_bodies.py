from __future__ import annotations

import hashlib
import sqlite3
import traceback
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from labcourt.adapters.storage import _sqlite_m6_upgrade_m4_model_bodies as subject
from labcourt.adapters.storage import _sqlite_m6_upgrade_m4_model_documents as documents
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_documents import (
    M6SQLiteM4ModelDocumentError,
    M6SQLiteM4ModelDocumentFailureCode,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_plan import (
    M6SQLiteM4DocumentRoute,
    M6SQLiteM4DocumentSlot,
    _M6SQLiteM4MetadataFailure,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.hearing import HearingModelRequest
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m4_replay_authority_snapshot import _one_role_call


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@pytest.fixture(scope="module")
def hearing_request(tmp_path_factory: pytest.TempPathFactory) -> HearingModelRequest:
    started = _one_role_call(Path(tmp_path_factory.mktemp("m6-m4-body-unit")))
    values = started.repository.list_hearing_model_requests(
        RUN_ID,
        started.session.session_id,
    )
    assert len(values) == 1
    return values[0]


def _cache_row(request: HearingModelRequest) -> sqlite3.Row:
    raw = canonical_json(request.model_dump(mode="json"))
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT 7 AS document_rowid, ? AS request_id, ? AS request_json",
            (request.request_id, raw),
        ).fetchone()
    finally:
        connection.close()
    assert row is not None
    return row


def _cache_slot(request: HearingModelRequest) -> M6SQLiteM4DocumentSlot:
    raw = canonical_json(request.model_dump(mode="json"))
    return M6SQLiteM4DocumentSlot(
        route=M6SQLiteM4DocumentRoute.MODEL_CACHE_REQUEST,
        rowid=7,
        artifact_id=request.request_id,
        document_sha256=_sha(raw),
        document_bytes=len(raw.encode("utf-8")),
        index_identity_sha256=_sha("cache request index"),
    )


def test_cache_duplicate_requires_exact_canonical_claim_request(
    hearing_request: HearingModelRequest,
) -> None:
    row = _cache_row(hearing_request)
    slot = _cache_slot(hearing_request)

    replay = subject._cache_request(row, slot, hearing_request)

    assert replay.canonical_sha256 == slot.document_sha256
    different_claim = hearing_request.model_copy(update={"provider": "different-provider"})
    with pytest.raises(_M6SQLiteM4MetadataFailure) as raised:
        subject._cache_request(row, slot, different_claim)
    assert raised.value.reason_code == M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH


def test_cache_duplicate_rejects_body_hash_mismatch(
    hearing_request: HearingModelRequest,
) -> None:
    row = _cache_row(hearing_request)
    forged = replace(
        _cache_slot(hearing_request),
        document_sha256=_sha("forged cache request document"),
    )

    with pytest.raises(_M6SQLiteM4MetadataFailure) as raised:
        subject._cache_request(row, forged, hearing_request)

    assert raised.value.reason_code == M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID


def test_historical_request_projection_rejects_typed_semantic_drift(
    hearing_request: HearingModelRequest,
) -> None:
    same_projection = hearing_request.model_copy()
    semantic_drift = hearing_request.model_copy(update={"provider": "different-provider"})

    assert subject._request_projection_matches(hearing_request, same_projection)
    assert not subject._request_projection_matches(hearing_request, semantic_drift)


def test_replay_root_commits_historical_failure_canonical_body() -> None:
    plan = SimpleNamespace(
        plan_identity_sha256=_sha("plan"),
        run_id=RUN_ID,
        case_id="case-1",
        manifest_id=_sha("manifest"),
    )
    original = subject._ReplayBody(
        route=M6SQLiteM4DocumentRoute.MODEL_CALL_FAILURE.value,
        rowid=9,
        artifact_id=_sha("failure-authority"),
        commitment_kind="CANONICAL_DOCUMENT",
        commitment_sha256=_sha("committed failure"),
        canonical_sha256=_sha("original canonical failure"),
    )
    replaced_body = replace(
        original,
        canonical_sha256=_sha("different canonical failure"),
    )

    original_root = subject._replay_root(plan, [original])  # type: ignore[arg-type]
    replaced_root = subject._replay_root(plan, [replaced_body])  # type: ignore[arg-type]

    assert original_root != replaced_root


def test_public_resolver_rejects_invalid_arguments_with_fresh_payload_free_error() -> None:
    secret = "private-m4-body-secret-889900"
    with pytest.raises(M6SQLiteM4ModelDocumentError) as caught:
        documents.resolve_m6_sqlite_m4_model_documents(  # type: ignore[arg-type]
            connection=secret,
            metadata_plan=secret,
        )

    error = caught.value
    rendered = "".join(traceback.format_exception(error))
    assert error.reason_code == M6SQLiteM4ModelDocumentFailureCode.INVALID_ARGUMENT
    assert error.__cause__ is None
    assert error.__context__ is None
    assert secret not in str(error)
    assert secret not in rendered


def test_public_resolver_collapses_unexpected_runtime_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "private-m4-runtime-body-776655"

    def explode(**_kwargs: object) -> object:
        raise RuntimeError(secret)

    monkeypatch.setattr(
        documents,
        "build_m6_sqlite_m4_model_call_authority_snapshot",
        explode,
    )
    outcome = documents._capture_resolve(
        connection=object(),
        metadata_plan=object(),
    )

    assert outcome.value is None
    assert outcome.failure_code == M6SQLiteM4ModelDocumentFailureCode.DATABASE_REJECTED

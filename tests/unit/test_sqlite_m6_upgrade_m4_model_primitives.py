from __future__ import annotations

import hashlib
import sqlite3
from typing import cast

import pytest

from labcourt.adapters.storage import _sqlite_m6_upgrade_m4_model_primitives as subject
from labcourt.adapters.storage import _sqlite_m6_upgrade_m4_model_rows as rows_subject
from labcourt.adapters.storage._sqlite_m6_live_read_cut import M6LiveReader
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_plan import (
    M6SQLiteM4DocumentRoute,
    M6SQLiteM4ModelDocumentFailureCode,
    M6SQLiteM4RoleModelManifestBinding,
    M6SQLiteM4SupportDocumentCommitmentKind,
    M6SQLiteM4SupportDocumentRoute,
    M6SQLiteM4SupportRoute,
    _M6SQLiteM4MetadataFailure,
)
from labcourt.contracts.m6_replay_locked import M6LockedModelRole
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactKind


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _row(**values: object) -> sqlite3.Row:
    return cast(sqlite3.Row, values)


def _reader() -> M6LiveReader:
    return cast(M6LiveReader, object())


@pytest.mark.parametrize(
    ("call", "row"),
    (
        (lambda row: subject._text(row, "value"), _row(value=1)),
        (lambda row: subject._sha256(row, "value"), _row(value="f" * 63)),
        (lambda row: subject._integer(row, "value"), _row(value=True)),
        (lambda row: subject._integer(row, "value"), _row(value=-1)),
        (lambda row: subject._number(row, "value"), _row(value=True)),
        (lambda row: subject._number(row, "value"), _row(value=float("nan"))),
        (lambda row: subject._optional_text(row, "value"), _row(value=1)),
    ),
)
def test_scalar_readers_fail_closed_on_non_exact_shapes(
    call: object,
    row: sqlite3.Row,
) -> None:
    assert callable(call)
    with pytest.raises(_M6SQLiteM4MetadataFailure) as caught:
        call(row)
    assert caught.value.reason_code == M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH


def test_row_identity_ignores_only_type_and_length_projections() -> None:
    base = _row(
        support_rowid=7,
        identity="one",
        support_document_type="text",
        support_document_bytes=10,
    )
    same = _row(
        support_rowid=7,
        identity="one",
        support_document_type="blob",
        support_document_bytes=999,
    )
    changed = _row(
        support_rowid=7,
        identity="two",
        support_document_type="text",
        support_document_bytes=10,
    )
    assert subject._row_identity(base, "domain") == subject._row_identity(same, "domain")
    assert subject._row_identity(base, "domain") != subject._row_identity(changed, "domain")


def test_single_has_closed_missing_and_duplicate_results() -> None:
    with pytest.raises(_M6SQLiteM4MetadataFailure) as missing:
        subject._single((), missing=M6SQLiteM4ModelDocumentFailureCode.SCOPE_NOT_FOUND)
    assert missing.value.reason_code == M6SQLiteM4ModelDocumentFailureCode.SCOPE_NOT_FOUND
    row = _row(value=1)
    assert subject._single((row,)) is row
    with pytest.raises(_M6SQLiteM4MetadataFailure) as duplicate:
        subject._single((row, row))
    assert duplicate.value.reason_code == M6SQLiteM4ModelDocumentFailureCode.ROW_LIMIT_EXCEEDED


def test_role_manifest_inputs_require_the_exact_ordered_three_role_matrix() -> None:
    shared = _sha("shared model")
    bindings = tuple(
        M6SQLiteM4RoleModelManifestBinding(role=role, model_manifest_id=shared)
        for role in (
            M6LockedModelRole.PROSECUTOR,
            M6LockedModelRole.DEFENDER,
            M6LockedModelRole.JUDGE,
        )
    )
    assert subject._controlled_role_bindings(bindings) == bindings
    with pytest.raises(_M6SQLiteM4MetadataFailure) as caught:
        subject._controlled_role_bindings(tuple(reversed(bindings)))
    assert caught.value.reason_code == M6SQLiteM4ModelDocumentFailureCode.INVALID_ARGUMENT


def test_primary_document_slot_preserves_response_canonical_and_raw_sizes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rows_subject, "_USE_SQLITE_OCTET_LENGTH", True)
    document_hash = _sha("response document")
    content_hash = _sha("raw response")
    row = _row(
        document_rowid=4,
        response_document_type="text",
        response_document_bytes=31,
        response_id=_sha("response"),
    )
    slot = subject._document_slot(
        _reader(),
        row,
        route=M6SQLiteM4DocumentRoute.MODEL_RESPONSE,
        artifact_id=_sha("response"),
        document_sha256=document_hash,
        kind=M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
        content_sha256=content_hash,
        physical_size_bytes=47,
    )
    assert slot.document_bytes == 31
    assert slot.physical_ref is not None
    assert slot.physical_ref.document_sha256 == document_hash
    assert slot.physical_ref.content_sha256 == content_hash
    assert slot.physical_ref.size_bytes == 47


@pytest.mark.parametrize(
    ("document_route", "row_route", "expected_kind"),
    (
        (
            M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE,
            M6SQLiteM4SupportRoute.HEARING_CYCLE,
            M6SQLiteM4SupportDocumentCommitmentKind.SEMANTIC_DOCUMENT,
        ),
        (
            M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM_VERSION,
            M6SQLiteM4SupportRoute.BACKLOG_ITEM_VERSION,
            M6SQLiteM4SupportDocumentCommitmentKind.CANONICAL_DOCUMENT,
        ),
    ),
)
def test_support_pair_preserves_route_defined_commitment_meaning(
    monkeypatch: pytest.MonkeyPatch,
    document_route: M6SQLiteM4SupportDocumentRoute,
    row_route: M6SQLiteM4SupportRoute,
    expected_kind: M6SQLiteM4SupportDocumentCommitmentKind,
) -> None:
    monkeypatch.setattr(rows_subject, "_USE_SQLITE_OCTET_LENGTH", True)
    commitment = _sha("body commitment")
    row = _row(
        support_rowid=8,
        body_commitment_sha256=commitment,
        support_document_type="text",
        support_document_bytes=19,
        identity=_sha("identity"),
    )
    support, body = subject._support_pair(
        _reader(),
        row,
        row_route=row_route,
        document_route=document_route,
        artifact_id=_sha("identity"),
    )
    assert body.commitment_kind == expected_kind
    assert body.body_commitment_sha256 == commitment
    assert support.rowid == body.rowid == 8
    assert support.index_identity_sha256 == body.index_identity_sha256

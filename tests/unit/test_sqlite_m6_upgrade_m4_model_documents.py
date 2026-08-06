from __future__ import annotations

import pytest

from labcourt.adapters.storage import _sqlite_m6_upgrade_m4_model_documents as subject
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_documents import (
    M6SQLiteM4ModelDocumentError,
    M6SQLiteM4ModelDocumentFailureCode,
)


def test_public_plan_rejects_invalid_arguments_with_fresh_payload_free_error() -> None:
    with pytest.raises(M6SQLiteM4ModelDocumentError) as caught:
        subject.plan_m6_sqlite_m4_model_documents(  # type: ignore[arg-type]
            connection=object(),
            expected_run_id="secret-run",
            expected_manifest_id="secret-manifest",
            expected_role_model_manifests=(),
            selected_case_authority=object(),
            observed_model_calls=(),
        )
    error = caught.value
    assert error.reason_code == M6SQLiteM4ModelDocumentFailureCode.INVALID_ARGUMENT
    assert error.__cause__ is None
    assert error.__context__ is None
    assert "secret" not in str(error)


def test_public_capture_collapses_unexpected_runtime_payload() -> None:
    def explode(**_kwargs: object) -> object:
        raise RuntimeError("secret database path and body")

    original = subject.build_m6_sqlite_m4_model_documents_plan
    subject.build_m6_sqlite_m4_model_documents_plan = explode  # type: ignore[assignment]
    try:
        outcome = subject._capture_plan(
            connection=object(),
            expected_run_id=object(),
            expected_manifest_id=object(),
            expected_role_model_manifests=object(),
            selected_case_authority=object(),
            observed_model_calls=object(),
        )
    finally:
        subject.build_m6_sqlite_m4_model_documents_plan = original
    assert outcome.value is None
    assert outcome.failure_code == M6SQLiteM4ModelDocumentFailureCode.DATABASE_REJECTED

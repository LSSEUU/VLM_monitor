"""Canonical documents, identities, and bounded-recovery support for M3 SQLite."""

from __future__ import annotations

import hashlib
import re
import sqlite3
import sys
from collections.abc import Callable
from typing import TypeVar, cast

from pydantic import BaseModel, TypeAdapter, ValidationError

from labcourt.contracts.backlog import (
    BacklogRetryContext,
)
from labcourt.contracts.model_response_recovery import MAX_MODEL_CALL_RECOVERY_ITEMS
from labcourt.contracts.screening import (
    VLMCallRequest,
)
from labcourt.contracts.storage import ClosureReport
from labcourt.ports.vlm import (
    ModelResponseStoreFailureCode,
)

from .sqlite_repository import (
    RepositoryIntegrityError,
    _document,
    _row_str,
    _verify_document,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_ADAPTER: TypeAdapter[VLMCallRequest] = TypeAdapter(VLMCallRequest)
_ModelT = TypeVar("_ModelT", bound=BaseModel)
CurrentPackVerifier = Callable[[str, str], ClosureReport]
_MAX_RECOVERY_REQUEST_JSON_BYTES = 1024 * 1024
_MODEL_CALL_RECOVERY_SCAN_PAGE_SIZE = 256
_MODEL_CALL_RECOVERY_PAGE_COLUMNS = """
    run_id, request_id, request_sha256, cache_key, case_id,
    evidence_pack_id, evidence_pack_version, purpose,
    model_manifest_id, manifest_id,
    CASE
        WHEN length(CAST(request_json AS BLOB)) <= ?
        THEN request_json
        ELSE NULL
    END AS request_json,
    length(CAST(request_json AS BLOB)) AS request_json_bytes,
    request_document_sha256, status, owner_token_sha256,
    lease_expires_at, takeover_count, created_at,
    response_id, completed_at
"""
_MODEL_CALL_RECOVERY_PAGE_QUERY = f"""
    SELECT {_MODEL_CALL_RECOVERY_PAGE_COLUMNS}
    FROM model_call_claims
    WHERE run_id = ?
    ORDER BY request_id
    LIMIT ?
"""
_MODEL_CALL_RECOVERY_KEYSET_PAGE_QUERY = f"""
    SELECT {_MODEL_CALL_RECOVERY_PAGE_COLUMNS}
    FROM model_call_claims
    WHERE run_id = ? AND request_id > ?
    ORDER BY request_id
    LIMIT ?
"""
_BACKLOG_PROVABLE_RAW_FAILURES = frozenset(
    {
        ModelResponseStoreFailureCode.RUN_SCOPE_MISMATCH,
        ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND,
        ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE,
        ModelResponseStoreFailureCode.WORKSPACE_REJECTED,
    }
)

_PUBLIC_REPOSITORY_MODULE = "labcourt.adapters.storage.sqlite_m3_repository"


def _public_recovery_limit(name: str, default: int) -> int:
    """Honor old façade monkeypatches without reverse-importing the façade."""

    public_module = sys.modules.get(_PUBLIC_REPOSITORY_MODULE)
    if public_module is None:
        return default
    return cast(int, getattr(public_module, name, default))


def _runtime_model_call_recovery_item_limit() -> int:
    return _public_recovery_limit(
        "MAX_MODEL_CALL_RECOVERY_ITEMS",
        MAX_MODEL_CALL_RECOVERY_ITEMS,
    )


def _runtime_model_call_recovery_page_size() -> int:
    return _public_recovery_limit(
        "_MODEL_CALL_RECOVERY_SCAN_PAGE_SIZE",
        _MODEL_CALL_RECOVERY_SCAN_PAGE_SIZE,
    )


def m3_root_document_sha256(root: BaseModel) -> str:
    """Return the canonical full-root hash used by backlog stage input bindings.

    This is the SHA-256 of the root's complete LCJ-1 ``model_dump(mode="json")``
    document, including computed identities.  It is intentionally not an
    EvidencePack ``pack_input_sha256`` or ``closure_input_sha256``.
    """

    if not isinstance(root, BaseModel):
        raise TypeError("M3 stage input must be a Pydantic root contract")
    return _document(root)[1]


def _validated_copy(model: _ModelT, model_type: type[_ModelT]) -> _ModelT:
    return model_type.model_validate(model.model_dump(mode="json"))


def _validated_request(request: VLMCallRequest) -> VLMCallRequest:
    return _REQUEST_ADAPTER.validate_python(request.model_dump(mode="json"))


def _same_semantic_model_call_identity(left: VLMCallRequest, right: VLMCallRequest) -> bool:
    """Ignore queue item/lease provenance while retaining proven retry generation."""

    return type(left) is type(right) and left.request_projection() == right.request_projection()


def _request_matches_retry_generation(
    request: VLMCallRequest,
    expected: BacklogRetryContext,
) -> bool:
    context = request.backlog_retry_context
    if context is None:
        return expected.retry_generation == 0
    return (
        context.backlog_item_id == expected.backlog_item_id
        and context.retry_generation == expected.retry_generation
    )


def _require_sha256(value: str, name: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _owner_token_sha256(value: str) -> str:
    if not isinstance(value, str) or not 32 <= len(value) <= 512:
        raise ValueError("model call owner_token must contain 32 to 512 characters")
    if any(ord(character) < 33 or ord(character) > 126 for character in value):
        raise ValueError("model call owner_token must contain visible ASCII only")
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _load_document(
    row: sqlite3.Row,
    *,
    json_key: str,
    sha256_key: str,
    model_type: type[_ModelT],
) -> _ModelT:
    raw = _row_str(row, json_key)
    try:
        model = model_type.model_validate_json(raw)
    except ValidationError as exc:
        raise RepositoryIntegrityError(
            f"stored {model_type.__name__} contract document is invalid"
        ) from exc
    _verify_document(raw, _row_str(row, sha256_key), model)
    return model

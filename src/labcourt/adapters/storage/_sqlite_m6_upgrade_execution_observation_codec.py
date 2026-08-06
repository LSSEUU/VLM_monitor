"""Strict SQLite codec for pre-ledger M6 execution observations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeVar, cast

from pydantic import ValidationError

from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES,
    MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    MAX_M6_UPGRADE_MODEL_CALL_OBSERVATIONS_PER_SAMPLE,
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradeSampleExecutionObservationAuthorityV2,
    M6UpgradeSelectedCaseAuditAnchor,
)
from labcourt.ports.m6_upgrade_execution_observation import (
    M6UpgradeExecutionObservationError,
    M6UpgradeExecutionObservationFailureCode,
)

from ._sqlite_read_session import SQLiteReadSession
from .sqlite_repository import (
    RepositoryIntegrityError,
    _document,
    _row_int,
    _row_optional_int,
    _row_optional_str,
    _row_str,
    _verify_contract_document,
)

MAX_M6_UPGRADE_OBSERVATION_BYTES = 64 * 1024 * 1024
MAX_M6_UPGRADE_OBSERVATION_INVENTORY_BYTES = MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES

_ObservationT = TypeVar(
    "_ObservationT",
    bound=M6UpgradeSampleExecutionObservationAuthority,
)


@dataclass(frozen=True, slots=True)
class StoredM6UpgradeExecutionObservation:
    authority: M6UpgradeSampleExecutionObservationAuthority
    document_sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class StoredM6UpgradeExecutionObservationV2:
    authority: M6UpgradeSampleExecutionObservationAuthorityV2
    document_sha256: str
    size_bytes: int


def _error(
    code: M6UpgradeExecutionObservationFailureCode,
) -> M6UpgradeExecutionObservationError:
    return M6UpgradeExecutionObservationError(code)


def _canonical_observation(
    value: object,
    model_type: type[_ObservationT],
) -> _ObservationT:
    if type(value) is not model_type:
        raise _error(M6UpgradeExecutionObservationFailureCode.INVALID_ARGUMENT)
    try:
        controlled = model_type.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError) as exc:
        raise _error(M6UpgradeExecutionObservationFailureCode.INVALID_ARGUMENT) from exc
    if type(controlled) is not model_type or controlled != value:
        raise _error(M6UpgradeExecutionObservationFailureCode.INVALID_ARGUMENT)
    return controlled


def canonical_observation(
    value: object,
) -> M6UpgradeSampleExecutionObservationAuthority:
    return _canonical_observation(value, M6UpgradeSampleExecutionObservationAuthority)


def canonical_observation_v2(
    value: object,
) -> M6UpgradeSampleExecutionObservationAuthorityV2:
    return _canonical_observation(value, M6UpgradeSampleExecutionObservationAuthorityV2)


def _observation_document(
    value: object,
    model_type: type[_ObservationT],
) -> tuple[str, str, int]:
    controlled = _canonical_observation(value, model_type)
    raw, document_sha256 = _document(controlled)
    size_bytes = len(raw.encode("utf-8"))
    if size_bytes > MAX_M6_UPGRADE_OBSERVATION_BYTES:
        raise _error(M6UpgradeExecutionObservationFailureCode.DOCUMENT_TOO_LARGE)
    return raw, document_sha256, size_bytes


def observation_document(
    value: M6UpgradeSampleExecutionObservationAuthority,
) -> tuple[str, str, int]:
    return _observation_document(value, M6UpgradeSampleExecutionObservationAuthority)


def observation_v2_document(
    value: M6UpgradeSampleExecutionObservationAuthorityV2,
) -> tuple[str, str, int]:
    return _observation_document(value, M6UpgradeSampleExecutionObservationAuthorityV2)


def _preflight_observation(
    connection: SQLiteReadSession,
    *,
    run_id: str,
    ledger_sequence: int,
) -> int:
    row = connection.execute(
        """
        SELECT
            COUNT(*) AS item_count,
            COALESCE(SUM(
                CASE WHEN typeof(size_bytes) = 'integer'
                           AND size_bytes BETWEEN 1 AND ?
                     THEN size_bytes ELSE 0 END
            ), 0) AS claimed_bytes,
            COALESCE(SUM(
                CASE WHEN typeof(observation_json) = 'text'
                     THEN length(CAST(observation_json AS BLOB)) ELSE 0 END
            ), 0) AS actual_bytes,
            COALESCE(SUM(
                CASE WHEN typeof(size_bytes) <> 'integer'
                           OR typeof(observation_json) <> 'text'
                           OR size_bytes < 1
                           OR size_bytes <> length(CAST(observation_json AS BLOB))
                     THEN 1 ELSE 0 END
            ), 0) AS invalid_count,
            COALESCE(SUM(
                CASE WHEN (typeof(size_bytes) = 'integer' AND size_bytes > ?)
                           OR (typeof(observation_json) = 'text'
                               AND length(CAST(observation_json AS BLOB)) > ?)
                     THEN 1 ELSE 0 END
            ), 0) AS oversized_count
        FROM m6_upgrade_sample_execution_observations
        WHERE run_id = ? AND ledger_sequence = ?
        """,
        (
            MAX_M6_UPGRADE_OBSERVATION_BYTES,
            MAX_M6_UPGRADE_OBSERVATION_BYTES,
            MAX_M6_UPGRADE_OBSERVATION_BYTES,
            run_id,
            ledger_sequence,
        ),
    ).fetchone()
    try:
        if row is None:
            raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID)
        item_count = _row_int(row, "item_count")
        claimed_bytes = _row_int(row, "claimed_bytes")
        actual_bytes = _row_int(row, "actual_bytes")
        invalid_count = _row_int(row, "invalid_count")
        oversized_count = _row_int(row, "oversized_count")
    except M6UpgradeExecutionObservationError:
        raise
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID) from exc
    if oversized_count or actual_bytes > MAX_M6_UPGRADE_OBSERVATION_INVENTORY_BYTES:
        raise _error(M6UpgradeExecutionObservationFailureCode.DOCUMENT_TOO_LARGE)
    if item_count > 1 or invalid_count or claimed_bytes != actual_bytes:
        raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID)
    return item_count


def _bounded_child_count(
    connection: SQLiteReadSession,
    *,
    table: str,
    run_id: str,
    observation_authority_id: str,
    limit: int,
) -> int:
    row = connection.execute(
        f"""
        SELECT COUNT(*) AS item_count FROM (
            SELECT 1 FROM {table}
            WHERE run_id = ? AND observation_authority_id = ?
            LIMIT ?
        )
        """,
        (run_id, observation_authority_id, limit + 1),
    ).fetchone()
    try:
        if row is None:
            raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID)
        count = _row_int(row, "item_count")
    except M6UpgradeExecutionObservationError:
        raise
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID) from exc
    if count > limit:
        raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID)
    return count


def _observation_from_connection(
    connection: SQLiteReadSession,
    run_id: str,
    ledger_sequence: int,
    *,
    model_type: type[_ObservationT],
    observation_schema_version: str,
) -> tuple[_ObservationT, str, int] | None:
    if (
        _preflight_observation(
            connection,
            run_id=run_id,
            ledger_sequence=ledger_sequence,
        )
        == 0
    ):
        return None
    row = connection.execute(
        """
        SELECT * FROM m6_upgrade_sample_execution_observations
        WHERE run_id = ? AND ledger_sequence = ?
        """,
        (run_id, ledger_sequence),
    ).fetchone()
    if row is None:
        raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID)
    try:
        stored_observation_schema_version = _row_str(row, "observation_schema_version")
        stored_anchor = (
            _row_optional_str(row, "selected_case_audit_anchor_id"),
            _row_optional_str(row, "case_audit_action"),
            _row_optional_str(row, "case_audit_object_kind"),
            _row_optional_str(row, "case_audit_object_id"),
        )
        if stored_observation_schema_version != observation_schema_version or (
            model_type is M6UpgradeSampleExecutionObservationAuthority
            and any(value is not None for value in stored_anchor)
        ):
            raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID)
        raw = _row_str(row, "observation_json")
        document_sha256 = _row_str(row, "document_sha256")
        size_bytes = _row_int(row, "size_bytes")
        try:
            authority = model_type.model_validate_json(raw)
            if type(authority) is not model_type:
                raise RepositoryIntegrityError("stored observation model type differs")
            _verify_contract_document(raw, authority)
            canonical, observed_sha256 = _document(authority)
        except (TypeError, ValueError, ValidationError, RepositoryIntegrityError) as exc:
            raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID) from exc
        if (
            canonical != raw
            or observed_sha256 != document_sha256
            or len(raw.encode("utf-8")) != size_bytes
        ):
            raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID)

        candidate_case = authority.candidate_case
        anchor: M6UpgradeSelectedCaseAuditAnchor | None = None
        if model_type is M6UpgradeSampleExecutionObservationAuthorityV2:
            anchor = cast(
                M6UpgradeSampleExecutionObservationAuthorityV2,
                authority,
            ).selected_case_audit_anchor
        observed_parent = (
            _row_str(row, "run_id"),
            _row_str(row, "execution_scope_authority_id"),
            _row_int(row, "ledger_sequence"),
            _row_str(row, "observation_authority_id"),
            _row_str(row, "command_id"),
            _row_str(row, "execution_dataset_snapshot_id"),
            _row_str(row, "execution_entry_id"),
            _row_str(row, "sample_id"),
            _row_str(row, "outcome"),
            stored_observation_schema_version,
            *stored_anchor,
            _row_optional_str(row, "case_id"),
            _row_optional_int(row, "case_revision"),
            _row_optional_str(row, "case_document_sha256"),
            _row_optional_int(row, "case_audit_sequence"),
            _row_optional_str(row, "case_audit_entry_hash"),
            _row_int(row, "artifact_count"),
            _row_int(row, "model_call_count"),
        )
        expected_parent = (
            authority.candidate_run_id,
            authority.execution_scope_authority_id,
            authority.ledger_sequence,
            authority.observation_authority_id,
            authority.command_id,
            authority.execution_dataset_snapshot_id,
            authority.execution_entry.execution_entry_id,
            authority.execution_entry.sample_id,
            authority.outcome.value,
            observation_schema_version,
            anchor.selected_case_audit_anchor_id if anchor is not None else None,
            anchor.action.value if anchor is not None else None,
            anchor.object_ref.kind.value if anchor is not None else None,
            anchor.object_ref.artifact_id if anchor is not None else None,
            candidate_case.case_id if candidate_case is not None else None,
            candidate_case.case_revision if candidate_case is not None else None,
            candidate_case.case_document_sha256 if candidate_case is not None else None,
            candidate_case.case_audit_sequence if candidate_case is not None else None,
            candidate_case.case_audit_entry_hash if candidate_case is not None else None,
            len(authority.artifacts),
            len(authority.model_calls),
        )
        if observed_parent != expected_parent:
            raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID)

        artifact_count = _bounded_child_count(
            connection,
            table="m6_upgrade_observed_non_model_artifacts",
            run_id=run_id,
            observation_authority_id=authority.observation_authority_id,
            limit=MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE,
        )
        artifact_rows = connection.execute(
            """
            SELECT ordinal, source, kind, artifact_id, usage
            FROM m6_upgrade_observed_non_model_artifacts
            WHERE run_id = ? AND observation_authority_id = ?
            ORDER BY ordinal
            """,
            (run_id, authority.observation_authority_id),
        ).fetchall()
        observed_artifacts = tuple(
            (
                _row_int(child, "ordinal"),
                _row_str(child, "source"),
                _row_str(child, "kind"),
                _row_str(child, "artifact_id"),
                _row_str(child, "usage"),
            )
            for child in artifact_rows
        )
        expected_artifacts = tuple(
            (index, item.source.value, item.kind.value, item.artifact_id, item.usage.value)
            for index, item in enumerate(authority.artifacts)
        )
        if artifact_count != len(artifact_rows) or observed_artifacts != expected_artifacts:
            raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID)

        model_call_count = _bounded_child_count(
            connection,
            table="m6_upgrade_observed_model_calls",
            run_id=run_id,
            observation_authority_id=authority.observation_authority_id,
            limit=MAX_M6_UPGRADE_MODEL_CALL_OBSERVATIONS_PER_SAMPLE,
        )
        model_rows = connection.execute(
            """
            SELECT ordinal, request_id, layer, role, attempt_index,
                   result_kind, provider_invoked
            FROM m6_upgrade_observed_model_calls
            WHERE run_id = ? AND observation_authority_id = ?
            ORDER BY ordinal
            """,
            (run_id, authority.observation_authority_id),
        ).fetchall()
        observed_calls = tuple(
            (
                _row_int(child, "ordinal"),
                _row_str(child, "request_id"),
                _row_str(child, "layer"),
                _row_str(child, "role"),
                _row_int(child, "attempt_index"),
                _row_str(child, "result_kind"),
                _row_int(child, "provider_invoked"),
            )
            for child in model_rows
        )
        expected_calls = tuple(
            (
                index,
                item.request_id,
                item.layer.value,
                item.role.value,
                item.attempt_index,
                item.result_kind.value,
                int(item.provider_invoked),
            )
            for index, item in enumerate(authority.model_calls)
        )
        if model_call_count != len(model_rows) or observed_calls != expected_calls:
            raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID)
        return authority, document_sha256, size_bytes
    except M6UpgradeExecutionObservationError:
        raise
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID) from exc


def observation_from_connection(
    connection: SQLiteReadSession,
    run_id: str,
    ledger_sequence: int,
) -> StoredM6UpgradeExecutionObservation | None:
    decoded = _observation_from_connection(
        connection,
        run_id,
        ledger_sequence,
        model_type=M6UpgradeSampleExecutionObservationAuthority,
        observation_schema_version="v1",
    )
    if decoded is None:
        return None
    authority, document_sha256, size_bytes = decoded
    return StoredM6UpgradeExecutionObservation(
        authority=authority,
        document_sha256=document_sha256,
        size_bytes=size_bytes,
    )


def observation_v2_from_connection(
    connection: SQLiteReadSession,
    run_id: str,
    ledger_sequence: int,
) -> StoredM6UpgradeExecutionObservationV2 | None:
    decoded = _observation_from_connection(
        connection,
        run_id,
        ledger_sequence,
        model_type=M6UpgradeSampleExecutionObservationAuthorityV2,
        observation_schema_version="v2",
    )
    if decoded is None:
        return None
    authority, document_sha256, size_bytes = decoded
    return StoredM6UpgradeExecutionObservationV2(
        authority=authority,
        document_sha256=document_sha256,
        size_bytes=size_bytes,
    )


__all__ = [
    "MAX_M6_UPGRADE_OBSERVATION_BYTES",
    "MAX_M6_UPGRADE_OBSERVATION_INVENTORY_BYTES",
    "StoredM6UpgradeExecutionObservation",
    "StoredM6UpgradeExecutionObservationV2",
    "canonical_observation",
    "canonical_observation_v2",
    "observation_document",
    "observation_from_connection",
    "observation_v2_document",
    "observation_v2_from_connection",
]

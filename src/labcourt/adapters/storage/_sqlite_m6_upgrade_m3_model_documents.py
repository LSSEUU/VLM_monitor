"""Public payload-free facade for bounded same-snapshot M3 metadata plans."""

from __future__ import annotations

from dataclasses import dataclass

from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedModelCall,
)
from labcourt.exceptions import ContractViolation
from labcourt.ports.m6_model_calls import M6M3ModelCallAuthoritySnapshot

from ._sqlite_m6_live_read_cut import M6LiveReader
from ._sqlite_m6_upgrade_case_document import M6SQLiteCaseAuthorityDocument
from ._sqlite_m6_upgrade_m3_model_bodies import (
    build_m6_sqlite_m3_model_call_authority_snapshot,
)
from ._sqlite_m6_upgrade_m3_model_metadata import (
    build_m6_sqlite_m3_model_documents_plan,
)
from ._sqlite_m6_upgrade_m3_model_plan import (
    MAX_M6_SQLITE_M3_MODEL_DOCUMENT_BYTES,
    MAX_M6_SQLITE_M3_MODEL_DOCUMENT_TOTAL_BYTES,
    MAX_M6_SQLITE_M3_MODEL_PHYSICAL_TOTAL_BYTES,
    MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP,
    M6SQLiteM3CallGraphPlan,
    M6SQLiteM3DocumentRoute,
    M6SQLiteM3DocumentSlot,
    M6SQLiteM3HistoricalFailureBinding,
    M6SQLiteM3ModelDocumentFailureCode,
    M6SQLiteM3ModelDocumentsPlan,
    M6SQLiteM3SelectedPackBinding,
    M6SQLiteM3SupportDocumentRoute,
    M6SQLiteM3SupportDocumentSlot,
    M6SQLiteM3SupportRoute,
    M6SQLiteM3SupportSlot,
    _M6SQLiteM3MetadataFailure,
)


class M6SQLiteM3ModelDocumentError(ContractViolation):
    """One closed reason for rejecting an M3 metadata plan."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: M6SQLiteM3ModelDocumentFailureCode) -> None:
        if not isinstance(reason_code, M6SQLiteM3ModelDocumentFailureCode):
            raise TypeError("reason_code must be an M6 M3 model-document failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 SQLite M3 model-document planning failed: {reason_code.value}")


@dataclass(frozen=True, slots=True)
class _PlanAttempt:
    value: M6SQLiteM3ModelDocumentsPlan | None
    failure_code: M6SQLiteM3ModelDocumentFailureCode | None

    def __post_init__(self) -> None:
        if (self.value is None) == (self.failure_code is None):
            raise RuntimeError("M3 metadata attempt must contain exactly one outcome")


@dataclass(frozen=True, slots=True)
class _ResolveAttempt:
    value: M6M3ModelCallAuthoritySnapshot | None
    failure_code: M6SQLiteM3ModelDocumentFailureCode | None

    def __post_init__(self) -> None:
        if (self.value is None) == (self.failure_code is None):
            raise RuntimeError("M3 body attempt must contain exactly one outcome")


def _capture_plan(
    *,
    connection: object,
    expected_run_id: object,
    expected_manifest_id: object,
    expected_model_manifest_id: object,
    selected_case_authority: object,
    observed_model_calls: object,
) -> _PlanAttempt:
    """Collapse every private/runtime failure before crossing the public boundary."""

    try:
        value = build_m6_sqlite_m3_model_documents_plan(
            connection=connection,
            expected_run_id=expected_run_id,
            expected_manifest_id=expected_manifest_id,
            expected_model_manifest_id=expected_model_manifest_id,
            selected_case_authority=selected_case_authority,
            observed_model_calls=observed_model_calls,
        )
    except _M6SQLiteM3MetadataFailure as error:
        failure_code = error.reason_code
    except Exception:
        failure_code = M6SQLiteM3ModelDocumentFailureCode.DATABASE_REJECTED
    else:
        return _PlanAttempt(value=value, failure_code=None)
    return _PlanAttempt(value=None, failure_code=failure_code)


def plan_m6_sqlite_m3_model_documents(
    *,
    connection: M6LiveReader,
    expected_run_id: str,
    expected_manifest_id: str,
    expected_model_manifest_id: str,
    selected_case_authority: M6SQLiteCaseAuthorityDocument,
    observed_model_calls: tuple[M6UpgradeObservedModelCall, ...],
) -> M6SQLiteM3ModelDocumentsPlan:
    """Freeze the complete body-free M3 authority closure for one selected Case."""

    outcome = _capture_plan(
        connection=connection,
        expected_run_id=expected_run_id,
        expected_manifest_id=expected_manifest_id,
        expected_model_manifest_id=expected_model_manifest_id,
        selected_case_authority=selected_case_authority,
        observed_model_calls=observed_model_calls,
    )
    del (
        connection,
        expected_run_id,
        expected_manifest_id,
        expected_model_manifest_id,
        selected_case_authority,
        observed_model_calls,
    )
    if outcome.value is not None:
        return outcome.value
    reason_code = outcome.failure_code
    del outcome
    if reason_code is None:
        reason_code = M6SQLiteM3ModelDocumentFailureCode.DATABASE_REJECTED
    raise M6SQLiteM3ModelDocumentError(reason_code) from None


def _capture_resolve(
    *,
    connection: object,
    metadata_plan: object,
) -> _ResolveAttempt:
    """Collapse every decoder/runtime failure before the public boundary."""

    try:
        value = build_m6_sqlite_m3_model_call_authority_snapshot(
            connection=connection,
            metadata_plan=metadata_plan,
        )
    except _M6SQLiteM3MetadataFailure as error:
        failure_code = error.reason_code
    except Exception:
        failure_code = M6SQLiteM3ModelDocumentFailureCode.DATABASE_REJECTED
    else:
        return _ResolveAttempt(value=value, failure_code=None)
    return _ResolveAttempt(value=None, failure_code=failure_code)


def resolve_m6_sqlite_m3_model_documents(
    *,
    connection: M6LiveReader,
    metadata_plan: M6SQLiteM3ModelDocumentsPlan,
) -> M6M3ModelCallAuthoritySnapshot:
    """Resolve all canonical M3 bodies from the metadata plan's same B cut."""

    outcome = _capture_resolve(
        connection=connection,
        metadata_plan=metadata_plan,
    )
    del connection, metadata_plan
    if outcome.value is not None:
        return outcome.value
    reason_code = outcome.failure_code
    del outcome
    if reason_code is None:
        reason_code = M6SQLiteM3ModelDocumentFailureCode.DATABASE_REJECTED
    raise M6SQLiteM3ModelDocumentError(reason_code) from None


__all__ = [
    "MAX_M6_SQLITE_M3_MODEL_DOCUMENT_BYTES",
    "MAX_M6_SQLITE_M3_MODEL_DOCUMENT_TOTAL_BYTES",
    "MAX_M6_SQLITE_M3_MODEL_PHYSICAL_TOTAL_BYTES",
    "MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP",
    "M6SQLiteM3CallGraphPlan",
    "M6SQLiteM3DocumentRoute",
    "M6SQLiteM3DocumentSlot",
    "M6SQLiteM3HistoricalFailureBinding",
    "M6SQLiteM3ModelDocumentError",
    "M6SQLiteM3ModelDocumentFailureCode",
    "M6SQLiteM3ModelDocumentsPlan",
    "M6SQLiteM3SelectedPackBinding",
    "M6SQLiteM3SupportDocumentRoute",
    "M6SQLiteM3SupportDocumentSlot",
    "M6SQLiteM3SupportRoute",
    "M6SQLiteM3SupportSlot",
    "plan_m6_sqlite_m3_model_documents",
    "resolve_m6_sqlite_m3_model_documents",
]

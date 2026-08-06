"""Public payload-free facade for bounded same-snapshot M4 metadata plans."""

from __future__ import annotations

from dataclasses import dataclass

from labcourt.contracts.m6_upgrade_execution_observation import M6UpgradeObservedModelCall
from labcourt.exceptions import ContractViolation
from labcourt.ports.m6_model_calls import M6M4ModelCallAuthoritySnapshot

from ._sqlite_m6_live_read_cut import M6LiveReader
from ._sqlite_m6_upgrade_case_document import M6SQLiteCaseAuthorityDocument
from ._sqlite_m6_upgrade_m4_model_bodies import (
    build_m6_sqlite_m4_model_call_authority_snapshot,
)
from ._sqlite_m6_upgrade_m4_model_metadata import (
    build_m6_sqlite_m4_model_documents_plan,
)
from ._sqlite_m6_upgrade_m4_model_plan import (
    MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES,
    MAX_M6_SQLITE_M4_MODEL_DOCUMENT_TOTAL_BYTES,
    MAX_M6_SQLITE_M4_MODEL_PHYSICAL_TOTAL_BYTES,
    MAX_M6_SQLITE_M4_MODEL_ROWS_PER_GROUP,
    M6SQLiteM4CallGraphPlan,
    M6SQLiteM4DocumentRoute,
    M6SQLiteM4DocumentSlot,
    M6SQLiteM4HistoricalFailureBinding,
    M6SQLiteM4ModelDocumentFailureCode,
    M6SQLiteM4ModelDocumentsPlan,
    M6SQLiteM4RoleModelManifestBinding,
    M6SQLiteM4SelectedPackBinding,
    M6SQLiteM4SupportDocumentCommitmentKind,
    M6SQLiteM4SupportDocumentRoute,
    M6SQLiteM4SupportDocumentSlot,
    M6SQLiteM4SupportRoute,
    M6SQLiteM4SupportSlot,
    _M6SQLiteM4MetadataFailure,
)


class M6SQLiteM4ModelDocumentError(ContractViolation):
    """One closed reason for rejecting an M4 metadata plan."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: M6SQLiteM4ModelDocumentFailureCode) -> None:
        if not isinstance(reason_code, M6SQLiteM4ModelDocumentFailureCode):
            raise TypeError("reason_code must be an M6 M4 model-document failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 SQLite M4 model-document planning failed: {reason_code.value}")


@dataclass(frozen=True, slots=True)
class _PlanAttempt:
    value: M6SQLiteM4ModelDocumentsPlan | None
    failure_code: M6SQLiteM4ModelDocumentFailureCode | None

    def __post_init__(self) -> None:
        if (self.value is None) == (self.failure_code is None):
            raise RuntimeError("M4 metadata attempt must contain exactly one outcome")


@dataclass(frozen=True, slots=True)
class _ResolveAttempt:
    value: M6M4ModelCallAuthoritySnapshot | None
    failure_code: M6SQLiteM4ModelDocumentFailureCode | None

    def __post_init__(self) -> None:
        if (self.value is None) == (self.failure_code is None):
            raise RuntimeError("M4 body attempt must contain exactly one outcome")


def _capture_plan(
    *,
    connection: object,
    expected_run_id: object,
    expected_manifest_id: object,
    expected_role_model_manifests: object,
    selected_case_authority: object,
    observed_model_calls: object,
) -> _PlanAttempt:
    """Collapse every private/runtime failure before the public boundary."""

    try:
        value = build_m6_sqlite_m4_model_documents_plan(
            connection=connection,
            expected_run_id=expected_run_id,
            expected_manifest_id=expected_manifest_id,
            expected_role_model_manifests=expected_role_model_manifests,
            selected_case_authority=selected_case_authority,
            observed_model_calls=observed_model_calls,
        )
    except _M6SQLiteM4MetadataFailure as error:
        failure_code = error.reason_code
    except Exception:
        failure_code = M6SQLiteM4ModelDocumentFailureCode.DATABASE_REJECTED
    else:
        return _PlanAttempt(value=value, failure_code=None)
    return _PlanAttempt(value=None, failure_code=failure_code)


def plan_m6_sqlite_m4_model_documents(
    *,
    connection: M6LiveReader,
    expected_run_id: str,
    expected_manifest_id: str,
    expected_role_model_manifests: tuple[M6SQLiteM4RoleModelManifestBinding, ...],
    selected_case_authority: M6SQLiteCaseAuthorityDocument,
    observed_model_calls: tuple[M6UpgradeObservedModelCall, ...],
) -> M6SQLiteM4ModelDocumentsPlan:
    """Freeze the complete body-free M4 authority closure for one selected Case."""

    outcome = _capture_plan(
        connection=connection,
        expected_run_id=expected_run_id,
        expected_manifest_id=expected_manifest_id,
        expected_role_model_manifests=expected_role_model_manifests,
        selected_case_authority=selected_case_authority,
        observed_model_calls=observed_model_calls,
    )
    del (
        connection,
        expected_run_id,
        expected_manifest_id,
        expected_role_model_manifests,
        selected_case_authority,
        observed_model_calls,
    )
    if outcome.value is not None:
        return outcome.value
    reason_code = outcome.failure_code
    del outcome
    if reason_code is None:
        reason_code = M6SQLiteM4ModelDocumentFailureCode.DATABASE_REJECTED
    raise M6SQLiteM4ModelDocumentError(reason_code) from None


def _capture_resolve(
    *,
    connection: object,
    metadata_plan: object,
) -> _ResolveAttempt:
    """Collapse every decoder/runtime failure before the public boundary."""

    try:
        value = build_m6_sqlite_m4_model_call_authority_snapshot(
            connection=connection,
            metadata_plan=metadata_plan,
        )
    except _M6SQLiteM4MetadataFailure as error:
        failure_code = error.reason_code
    except Exception:
        failure_code = M6SQLiteM4ModelDocumentFailureCode.DATABASE_REJECTED
    else:
        return _ResolveAttempt(value=value, failure_code=None)
    return _ResolveAttempt(value=None, failure_code=failure_code)


def resolve_m6_sqlite_m4_model_documents(
    *,
    connection: M6LiveReader,
    metadata_plan: M6SQLiteM4ModelDocumentsPlan,
) -> M6M4ModelCallAuthoritySnapshot:
    """Resolve all canonical M4 response bodies from the plan's same B cut."""

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
        reason_code = M6SQLiteM4ModelDocumentFailureCode.DATABASE_REJECTED
    raise M6SQLiteM4ModelDocumentError(reason_code) from None


__all__ = [
    "MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES",
    "MAX_M6_SQLITE_M4_MODEL_DOCUMENT_TOTAL_BYTES",
    "MAX_M6_SQLITE_M4_MODEL_PHYSICAL_TOTAL_BYTES",
    "MAX_M6_SQLITE_M4_MODEL_ROWS_PER_GROUP",
    "M6SQLiteM4CallGraphPlan",
    "M6SQLiteM4DocumentRoute",
    "M6SQLiteM4DocumentSlot",
    "M6SQLiteM4HistoricalFailureBinding",
    "M6SQLiteM4ModelDocumentError",
    "M6SQLiteM4ModelDocumentFailureCode",
    "M6SQLiteM4ModelDocumentsPlan",
    "M6SQLiteM4RoleModelManifestBinding",
    "M6SQLiteM4SelectedPackBinding",
    "M6SQLiteM4SupportDocumentCommitmentKind",
    "M6SQLiteM4SupportDocumentRoute",
    "M6SQLiteM4SupportDocumentSlot",
    "M6SQLiteM4SupportRoute",
    "M6SQLiteM4SupportSlot",
    "plan_m6_sqlite_m4_model_documents",
    "resolve_m6_sqlite_m4_model_documents",
]

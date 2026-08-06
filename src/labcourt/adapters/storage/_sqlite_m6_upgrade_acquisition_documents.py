"""Public payload-free facade for same-snapshot acquisition metadata plans."""

from __future__ import annotations

from dataclasses import dataclass

from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
)
from labcourt.exceptions import ContractViolation

from ._sqlite_m6_live_read_cut import M6LiveReader
from ._sqlite_m6_upgrade_acquisition_bodies import (
    M6SQLiteAcquisitionAuthoritySnapshot,
    build_m6_sqlite_acquisition_authority_snapshot,
)
from ._sqlite_m6_upgrade_acquisition_metadata import (
    build_m6_sqlite_acquisition_documents_plan,
)
from ._sqlite_m6_upgrade_acquisition_plan import (
    MAX_M6_SQLITE_ACQUISITION_DOCUMENT_BYTES,
    MAX_M6_SQLITE_ACQUISITION_DOCUMENT_TOTAL_BYTES,
    MAX_M6_SQLITE_ACQUISITION_ITEMS,
    MAX_M6_SQLITE_ACQUISITION_PHYSICAL_TOTAL_BYTES,
    MAX_M6_SQLITE_ACQUISITION_SELECTED_PACKS,
    MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS,
    MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS_PER_ROUTE,
    MAX_M6_SQLITE_ACQUISITION_SUPPORT_TOTAL_BYTES,
    M6SQLiteAcquisitionClaimState,
    M6SQLiteAcquisitionClosurePlan,
    M6SQLiteAcquisitionCompletedClaimSlot,
    M6SQLiteAcquisitionDocumentCommitmentKind,
    M6SQLiteAcquisitionDocumentsPlan,
    M6SQLiteAcquisitionManifestSlot,
    M6SQLiteAcquisitionPackTransitionBinding,
    M6SQLiteAcquisitionPhysicalRoute,
    M6SQLiteAcquisitionPlanFailureCode,
    M6SQLiteAcquisitionSelectedPackBinding,
    M6SQLiteAcquisitionSupportDocumentRoute,
    M6SQLiteAcquisitionSupportDocumentSlot,
    M6SQLiteAcquisitionSupportRoute,
    M6SQLiteAcquisitionSupportSlot,
    M6SQLiteAcquisitionToolResultBinding,
    M6SQLiteAcquisitionUpstreamM4Binding,
    _M6SQLiteAcquisitionMetadataFailure,
)
from ._sqlite_m6_upgrade_case_document import M6SQLiteCaseAuthorityDocument
from ._sqlite_m6_upgrade_m4_model_plan import M6SQLiteM4ModelDocumentsPlan


class M6SQLiteAcquisitionDocumentError(ContractViolation):
    """One closed reason for rejecting an acquisition metadata plan."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: M6SQLiteAcquisitionPlanFailureCode) -> None:
        if type(reason_code) is not M6SQLiteAcquisitionPlanFailureCode:
            raise TypeError("reason_code must be an exact acquisition plan failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 SQLite acquisition planning failed: {reason_code.value}")


@dataclass(frozen=True, slots=True)
class _PlanAttempt:
    value: M6SQLiteAcquisitionDocumentsPlan | None
    failure_code: M6SQLiteAcquisitionPlanFailureCode | None

    def __post_init__(self) -> None:
        if (self.value is None) == (self.failure_code is None):
            raise RuntimeError("acquisition metadata attempt must contain exactly one outcome")


@dataclass(frozen=True, slots=True)
class _ResolveAttempt:
    value: M6SQLiteAcquisitionAuthoritySnapshot | None
    failure_code: M6SQLiteAcquisitionPlanFailureCode | None

    def __post_init__(self) -> None:
        if (self.value is None) == (self.failure_code is None):
            raise RuntimeError("acquisition body attempt must contain exactly one outcome")


def _capture_plan(
    *,
    connection: object,
    expected_run_id: object,
    expected_manifest_id: object,
    upstream_m4_model_plan: object,
    selected_case_authority: object,
    observed_acquisition_artifacts: object,
) -> _PlanAttempt:
    """Collapse every private/runtime failure before the public boundary."""

    try:
        value = build_m6_sqlite_acquisition_documents_plan(
            connection=connection,
            expected_run_id=expected_run_id,
            expected_manifest_id=expected_manifest_id,
            upstream_m4_model_plan=upstream_m4_model_plan,
            selected_case_authority=selected_case_authority,
            observed_acquisition_artifacts=observed_acquisition_artifacts,
        )
    except _M6SQLiteAcquisitionMetadataFailure as error:
        failure_code = error.reason_code
    except Exception:
        failure_code = M6SQLiteAcquisitionPlanFailureCode.DATABASE_REJECTED
    else:
        return _PlanAttempt(value=value, failure_code=None)
    return _PlanAttempt(value=None, failure_code=failure_code)


def plan_m6_sqlite_acquisition_documents(
    *,
    connection: M6LiveReader,
    expected_run_id: str,
    expected_manifest_id: str,
    upstream_m4_model_plan: M6SQLiteM4ModelDocumentsPlan,
    selected_case_authority: M6SQLiteCaseAuthorityDocument,
    observed_acquisition_artifacts: tuple[M6UpgradeObservedArtifactIdentity, ...],
) -> M6SQLiteAcquisitionDocumentsPlan:
    """Freeze the complete body-free acquisition closure for one selected Case."""

    outcome = _capture_plan(
        connection=connection,
        expected_run_id=expected_run_id,
        expected_manifest_id=expected_manifest_id,
        upstream_m4_model_plan=upstream_m4_model_plan,
        selected_case_authority=selected_case_authority,
        observed_acquisition_artifacts=observed_acquisition_artifacts,
    )
    del (
        connection,
        expected_run_id,
        expected_manifest_id,
        upstream_m4_model_plan,
        selected_case_authority,
        observed_acquisition_artifacts,
    )
    if outcome.value is not None:
        return outcome.value
    reason_code = outcome.failure_code
    del outcome
    if reason_code is None:
        reason_code = M6SQLiteAcquisitionPlanFailureCode.DATABASE_REJECTED
    raise M6SQLiteAcquisitionDocumentError(reason_code) from None


def _capture_resolve(
    *,
    connection: object,
    metadata_plan: object,
    upstream_m4_model_plan: object,
) -> _ResolveAttempt:
    """Collapse every acquisition decoder/runtime failure at the public boundary."""

    try:
        value = build_m6_sqlite_acquisition_authority_snapshot(
            connection=connection,
            metadata_plan=metadata_plan,
            upstream_m4_model_plan=upstream_m4_model_plan,
        )
    except _M6SQLiteAcquisitionMetadataFailure as error:
        failure_code = error.reason_code
    except Exception:
        failure_code = M6SQLiteAcquisitionPlanFailureCode.DATABASE_REJECTED
    else:
        return _ResolveAttempt(value=value, failure_code=None)
    return _ResolveAttempt(value=None, failure_code=failure_code)


def resolve_m6_sqlite_acquisition_documents(
    *,
    connection: M6LiveReader,
    metadata_plan: M6SQLiteAcquisitionDocumentsPlan,
    upstream_m4_model_plan: M6SQLiteM4ModelDocumentsPlan,
) -> M6SQLiteAcquisitionAuthoritySnapshot:
    """Resolve only planned acquisition bodies from the metadata plan's same B cut."""

    outcome = _capture_resolve(
        connection=connection,
        metadata_plan=metadata_plan,
        upstream_m4_model_plan=upstream_m4_model_plan,
    )
    del connection, metadata_plan, upstream_m4_model_plan
    if outcome.value is not None:
        return outcome.value
    reason_code = outcome.failure_code
    del outcome
    if reason_code is None:
        reason_code = M6SQLiteAcquisitionPlanFailureCode.DATABASE_REJECTED
    raise M6SQLiteAcquisitionDocumentError(reason_code) from None


__all__ = [
    "MAX_M6_SQLITE_ACQUISITION_DOCUMENT_BYTES",
    "MAX_M6_SQLITE_ACQUISITION_DOCUMENT_TOTAL_BYTES",
    "MAX_M6_SQLITE_ACQUISITION_ITEMS",
    "MAX_M6_SQLITE_ACQUISITION_PHYSICAL_TOTAL_BYTES",
    "MAX_M6_SQLITE_ACQUISITION_SELECTED_PACKS",
    "MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS",
    "MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS_PER_ROUTE",
    "MAX_M6_SQLITE_ACQUISITION_SUPPORT_TOTAL_BYTES",
    "M6SQLiteAcquisitionAuthoritySnapshot",
    "M6SQLiteAcquisitionClaimState",
    "M6SQLiteAcquisitionClosurePlan",
    "M6SQLiteAcquisitionCompletedClaimSlot",
    "M6SQLiteAcquisitionDocumentCommitmentKind",
    "M6SQLiteAcquisitionDocumentError",
    "M6SQLiteAcquisitionDocumentsPlan",
    "M6SQLiteAcquisitionManifestSlot",
    "M6SQLiteAcquisitionPackTransitionBinding",
    "M6SQLiteAcquisitionPhysicalRoute",
    "M6SQLiteAcquisitionPlanFailureCode",
    "M6SQLiteAcquisitionSelectedPackBinding",
    "M6SQLiteAcquisitionSupportDocumentRoute",
    "M6SQLiteAcquisitionSupportDocumentSlot",
    "M6SQLiteAcquisitionSupportRoute",
    "M6SQLiteAcquisitionSupportSlot",
    "M6SQLiteAcquisitionToolResultBinding",
    "M6SQLiteAcquisitionUpstreamM4Binding",
    "plan_m6_sqlite_acquisition_documents",
    "resolve_m6_sqlite_acquisition_documents",
]

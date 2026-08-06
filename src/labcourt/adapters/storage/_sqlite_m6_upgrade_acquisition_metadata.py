"""Orchestrate a bounded acquisition metadata plan without reading bodies."""

from __future__ import annotations

import hashlib
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.evidence import ToolResult
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeCandidateCaseBinding,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.references import require_reference_token

from ._sqlite_m6_live_read_cut import M6LiveReader
from ._sqlite_m6_upgrade_acquisition_graph import build_acquisition_closures
from ._sqlite_m6_upgrade_acquisition_plan import (
    MAX_M6_SQLITE_ACQUISITION_ITEMS,
    M6SQLiteAcquisitionDocumentsPlan,
    M6SQLiteAcquisitionPlanFailureCode,
    _M6SQLiteAcquisitionMetadataFailure,
)
from ._sqlite_m6_upgrade_acquisition_rows import (
    read_hearing_support_rows,
    read_primary_rows,
    read_selected_tool_result_output_rows,
    read_transition_support_rows,
)
from ._sqlite_m6_upgrade_case_document import (
    M6SQLiteCaseAuthorityDocument,
)
from ._sqlite_m6_upgrade_m4_model_plan import M6SQLiteM4ModelDocumentsPlan
from ._sqlite_m6_upgrade_m4_model_plan import (
    _plan_is_consistent as _m4_plan_is_consistent,
)

_ACQUISITION_PHYSICAL_KINDS = frozenset(
    {
        M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
        M6UpgradePhysicalArtifactKind.TOOL_RESULT,
    }
)


def _fail(reason_code: M6SQLiteAcquisitionPlanFailureCode) -> NoReturn:
    raise _M6SQLiteAcquisitionMetadataFailure(reason_code)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _case_authority_is_consistent(authority: M6SQLiteCaseAuthorityDocument) -> bool:
    if (
        type(authority.candidate_case_binding) is not M6UpgradeCandidateCaseBinding
        or type(authority.case) is not Case
        or type(authority.audit_entry) is not AuditEntry
        or type(authority.canonical_case_document) is not str
        or type(authority.canonical_audit_document) is not str
    ):
        return False
    try:
        binding = M6UpgradeCandidateCaseBinding.model_validate(
            authority.candidate_case_binding.model_dump(
                mode="json",
                exclude_computed_fields=True,
            )
        )
        selected_case = Case.model_validate(
            authority.case.model_dump(mode="json", exclude_computed_fields=True)
        )
        audit = AuditEntry.model_validate(
            authority.audit_entry.model_dump(mode="json", exclude_computed_fields=True)
        )
        canonical_case = canonical_json(selected_case.model_dump(mode="json"))
        canonical_audit = canonical_json(audit.model_dump(mode="json"))
        case_sha256 = hashlib.sha256(canonical_case.encode("utf-8")).hexdigest()
    except (AttributeError, TypeError, UnicodeError, ValueError, ValidationError):
        return False
    return (
        binding == authority.candidate_case_binding
        and selected_case == authority.case
        and audit == authority.audit_entry
        and canonical_case == authority.canonical_case_document
        and canonical_audit == authority.canonical_audit_document
        and binding.case_id == selected_case.case_id
        and binding.case_document_sha256 == case_sha256
        and binding.case_audit_sequence == audit.sequence
        and binding.case_audit_entry_hash == audit.entry_hash
        and audit.after_sha256 == case_sha256
    )


def _active(connection: M6LiveReader) -> None:
    active = connection.in_transaction
    if type(active) is not bool:
        _fail(M6SQLiteAcquisitionPlanFailureCode.DATABASE_REJECTED)
    if not active:
        _fail(M6SQLiteAcquisitionPlanFailureCode.TRANSACTION_REQUIRED)


def _controlled_observations(
    value: object,
) -> tuple[M6UpgradeObservedArtifactIdentity, ...]:
    if type(value) is not tuple or any(
        type(item) is not M6UpgradeObservedArtifactIdentity for item in value
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT)
    assert isinstance(value, tuple)
    try:
        controlled = tuple(
            M6UpgradeObservedArtifactIdentity.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in value
        )
    except (AttributeError, TypeError, UnicodeError, ValueError, ValidationError):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT)
    if (
        controlled != value
        or controlled != tuple(sorted(controlled, key=lambda item: item.sort_key))
        or len({item.identity_key for item in controlled}) != len(controlled)
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT)
    if len(controlled) > 2 * MAX_M6_SQLITE_ACQUISITION_ITEMS:
        _fail(M6SQLiteAcquisitionPlanFailureCode.ROW_LIMIT_EXCEEDED)
    if any(
        item.source != M6UpgradePhysicalArtifactSource.M4_ACQUISITION
        or item.kind not in _ACQUISITION_PHYSICAL_KINDS
        or item.usage != M6UpgradeArtifactUsage.PRODUCED
        for item in controlled
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT)
    return controlled


def _validated_arguments(
    connection: object,
    expected_run_id: object,
    expected_manifest_id: object,
    upstream_m4_model_plan: object,
    selected_case_authority: object,
    observed_acquisition_artifacts: object,
) -> tuple[
    M6LiveReader,
    str,
    str,
    M6SQLiteM4ModelDocumentsPlan,
    M6SQLiteCaseAuthorityDocument,
    tuple[M6UpgradeObservedArtifactIdentity, ...],
]:
    if (
        type(connection) is not M6LiveReader
        or type(expected_run_id) is not str
        or not _is_sha256(expected_manifest_id)
        or type(upstream_m4_model_plan) is not M6SQLiteM4ModelDocumentsPlan
        or type(selected_case_authority) is not M6SQLiteCaseAuthorityDocument
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT)
    assert isinstance(connection, M6LiveReader)
    assert isinstance(expected_run_id, str)
    assert isinstance(expected_manifest_id, str)
    assert isinstance(upstream_m4_model_plan, M6SQLiteM4ModelDocumentsPlan)
    assert isinstance(selected_case_authority, M6SQLiteCaseAuthorityDocument)
    try:
        run_id = require_reference_token(expected_run_id, "M6 acquisition run_id")
    except (TypeError, ValueError):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT)
    observations = _controlled_observations(observed_acquisition_artifacts)
    authority = selected_case_authority
    if not _case_authority_is_consistent(authority):
        _fail(M6SQLiteAcquisitionPlanFailureCode.CASE_BINDING_MISMATCH)
    case = authority.case
    binding = authority.candidate_case_binding
    audit = authority.audit_entry
    if case.run_id != run_id or case.manifest_id != expected_manifest_id:
        _fail(M6SQLiteAcquisitionPlanFailureCode.SCOPE_MISMATCH)

    upstream = upstream_m4_model_plan
    if not _m4_plan_is_consistent(upstream):
        _fail(M6SQLiteAcquisitionPlanFailureCode.CASE_BINDING_MISMATCH)
    if (
        upstream.run_id != run_id
        or upstream.case_id != case.case_id
        or upstream.manifest_id != expected_manifest_id
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.SCOPE_MISMATCH)
    if (
        upstream.selected_case_binding != binding
        or upstream.selected_case != case
        or upstream.selected_case_revision != binding.case_revision
        or upstream.selected_case_audit != audit
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.CASE_BINDING_MISMATCH)
    _active(connection)
    return connection, run_id, expected_manifest_id, upstream, authority, observations


def _selected_case_tool_results(case: Case) -> tuple[ToolResult, ...]:
    by_id: dict[str, ToolResult] = {}
    order: list[str] = []
    for pack in case.evidence_packs:
        for result in pack.tool_results:
            if type(result) is not ToolResult:
                _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
            existing = by_id.get(result.tool_result_id)
            if existing is not None and existing != result:
                _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
            if existing is None:
                by_id[result.tool_result_id] = result
                order.append(result.tool_result_id)
    if len(order) > MAX_M6_SQLITE_ACQUISITION_ITEMS:
        _fail(M6SQLiteAcquisitionPlanFailureCode.ROW_LIMIT_EXCEEDED)
    return tuple(by_id[result_id] for result_id in order)


def build_m6_sqlite_acquisition_documents_plan(
    *,
    connection: object,
    expected_run_id: object,
    expected_manifest_id: object,
    upstream_m4_model_plan: object,
    selected_case_authority: object,
    observed_acquisition_artifacts: object,
) -> M6SQLiteAcquisitionDocumentsPlan:
    """Build the exact metadata-only acquisition plan from one live B cut."""

    controlled, run_id, manifest_id, upstream, authority, observations = _validated_arguments(
        connection,
        expected_run_id,
        expected_manifest_id,
        upstream_m4_model_plan,
        selected_case_authority,
        observed_acquisition_artifacts,
    )
    case_id = authority.case.case_id
    primary = read_primary_rows(controlled, run_id=run_id, case_id=case_id)
    hearing = read_hearing_support_rows(controlled, run_id=run_id, case_id=case_id)
    transitions = read_transition_support_rows(
        controlled,
        run_id=run_id,
        case_id=case_id,
        selected_case_revision=authority.candidate_case_binding.case_revision,
    )
    outputs = read_selected_tool_result_output_rows(
        controlled,
        run_id=run_id,
        case_id=case_id,
        selected_case_tool_results=_selected_case_tool_results(authority.case),
    )
    closures = build_acquisition_closures(
        controlled,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
        selected_case_authority=authority,
        observed_acquisition_artifacts=observations,
        upstream_m4_model_plan=upstream,
        primary_rows=primary,
        hearing_rows=hearing,
        transition_rows=transitions,
        output_rows=outputs,
    )
    try:
        plan = M6SQLiteAcquisitionDocumentsPlan(
            run_id=run_id,
            case_id=case_id,
            manifest_id=manifest_id,
            upstream_m4_model_plan_identity_sha256=(upstream.plan_identity_sha256),
            selected_case_binding=authority.candidate_case_binding,
            selected_case=authority.case,
            selected_case_revision=authority.candidate_case_binding.case_revision,
            selected_case_audit=authority.audit_entry,
            observed_artifacts=observations,
            closures=closures,
        )
    except (TypeError, UnicodeError, ValueError, ValidationError):
        _fail(M6SQLiteAcquisitionPlanFailureCode.PHYSICAL_PLAN_INVALID)
    _active(controlled)
    return plan


__all__ = ["build_m6_sqlite_acquisition_documents_plan"]

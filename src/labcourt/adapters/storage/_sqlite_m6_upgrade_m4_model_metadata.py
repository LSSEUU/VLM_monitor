"""Orchestrate the bounded M4 response metadata plan without body reads."""

from __future__ import annotations

from pydantic import ValidationError

from ._sqlite_m6_upgrade_m4_model_graph import (
    _build_graphs,
    _caches,
    _claims,
    _failures,
    _historical_failure_bindings,
    _outputs,
    _receipts,
    _responses,
    _usages,
)
from ._sqlite_m6_upgrade_m4_model_plan import (
    MAX_M6_SQLITE_M4_MODEL_DOCUMENT_TOTAL_BYTES,
    MAX_M6_SQLITE_M4_MODEL_PHYSICAL_TOTAL_BYTES,
    M6SQLiteM4ModelDocumentFailureCode,
    M6SQLiteM4ModelDocumentsPlan,
)
from ._sqlite_m6_upgrade_m4_model_primitives import (
    _active,
    _fail,
    _validated_arguments,
)
from ._sqlite_m6_upgrade_m4_model_rows import (
    read_backlog_support_rows,
    read_base_support_rows,
    read_hearing_support_rows,
    read_primary_rows,
)
from ._sqlite_m6_upgrade_m4_model_support import (
    resolve_failure_support,
    resolve_response_support,
)


def build_m6_sqlite_m4_model_documents_plan(
    *,
    connection: object,
    expected_run_id: object,
    expected_manifest_id: object,
    expected_role_model_manifests: object,
    selected_case_authority: object,
    observed_model_calls: object,
) -> M6SQLiteM4ModelDocumentsPlan:
    """Build the exact current-terminal plus historical M4 metadata plan."""

    (
        controlled,
        run_id,
        manifest_id,
        role_bindings,
        authority,
        observations,
    ) = _validated_arguments(
        connection,
        expected_run_id,
        expected_manifest_id,
        expected_role_model_manifests,
        selected_case_authority,
        observed_model_calls,
    )
    case_id = authority.case.case_id
    primary = read_primary_rows(controlled, run_id=run_id, case_id=case_id)
    claims = _claims(
        controlled,
        primary.claims,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
        role_bindings=role_bindings,
        observations=observations,
    )
    responses = _responses(
        controlled,
        primary.responses,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
        claims=claims,
    )
    caches = _caches(
        controlled,
        primary.caches,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
        claims=claims,
        responses=responses,
    )
    receipts = _receipts(
        controlled,
        primary.receipts,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
        claims=claims,
        responses=responses,
        caches=caches,
    )
    outputs = _outputs(
        controlled,
        primary.outputs,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
        claims=claims,
        responses=responses,
        caches=caches,
        receipts=receipts,
    )
    usages = _usages(
        controlled,
        primary.usages,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
        claims=claims,
        responses=responses,
    )
    failures, historical_failures = _failures(
        controlled,
        primary.failures,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
        claims=claims,
    )
    base_rows = read_base_support_rows(
        controlled,
        run_id=run_id,
        case_id=case_id,
        selected_case_revision=authority.candidate_case_binding.case_revision,
        selected_audit_sequence=authority.candidate_case_binding.case_audit_sequence,
    )
    hearing_rows = read_hearing_support_rows(
        controlled,
        run_id=run_id,
        case_id=case_id,
    )
    support = resolve_response_support(
        controlled,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
        authority=authority,
        role_bindings=role_bindings,
        claims=claims,
        base_rows=base_rows,
        hearing_rows=hearing_rows,
    )
    support = resolve_failure_support(
        controlled,
        base=support,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
        claims=claims,
        failures=tuple(
            sorted(
                (*failures.values(), *historical_failures),
                key=lambda value: (
                    value.request_id,
                    value.takeover_count,
                    value.authority_id,
                ),
            )
        ),
        terminal_request_ids=set(failures),
        base_rows=base_rows,
        hearing_rows=hearing_rows,
        backlog_rows=read_backlog_support_rows(
            controlled,
            run_id=run_id,
            case_id=case_id,
        ),
    )
    try:
        graphs = _build_graphs(
            claims,
            responses,
            caches,
            receipts,
            outputs,
            failures,
            usages,
            support.contexts,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    document_total = (
        sum(slot.document_bytes for graph in graphs for slot in graph.document_slots)
        + sum(slot.document_bytes for slot in support.document_slots)
        + sum(failure.failure_slot.document_bytes for failure in historical_failures)
    )
    physical_total = sum(ref.size_bytes for graph in graphs for ref in graph.artifact_refs)
    if (
        document_total > MAX_M6_SQLITE_M4_MODEL_DOCUMENT_TOTAL_BYTES
        or physical_total > MAX_M6_SQLITE_M4_MODEL_PHYSICAL_TOTAL_BYTES
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_TOO_LARGE)
    try:
        plan = M6SQLiteM4ModelDocumentsPlan(
            run_id=run_id,
            case_id=case_id,
            manifest_id=manifest_id,
            selected_case_binding=authority.candidate_case_binding,
            selected_case=authority.case,
            selected_case_revision=authority.candidate_case_binding.case_revision,
            selected_case_audit=authority.audit_entry,
            hearing_model_bindings=support.hearing_bindings,
            selected_packs=support.selected_packs,
            observed_model_calls=observations,
            call_graphs=graphs,
            historical_failures=_historical_failure_bindings(historical_failures),
            support_slots=support.slots,
            support_document_slots=support.document_slots,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    _active(controlled)
    return plan

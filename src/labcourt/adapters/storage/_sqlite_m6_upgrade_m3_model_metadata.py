"""Orchestrate the bounded M3 metadata plan without reading document bodies."""

from __future__ import annotations

from pydantic import ValidationError

from ._sqlite_m6_upgrade_m3_model_graph import (
    _build_graphs,
    _caches,
    _claims,
    _failures,
    _historical_failure_bindings,
    _outputs,
    _receipts,
    _responses,
    _selected_packs,
    _usages,
)
from ._sqlite_m6_upgrade_m3_model_plan import (
    MAX_M6_SQLITE_M3_MODEL_DOCUMENT_TOTAL_BYTES,
    MAX_M6_SQLITE_M3_MODEL_PHYSICAL_TOTAL_BYTES,
    M6SQLiteM3ModelDocumentFailureCode,
    M6SQLiteM3ModelDocumentsPlan,
    M6SQLiteM3SupportRoute,
)
from ._sqlite_m6_upgrade_m3_model_primitives import (
    _active,
    _fail,
    _integer,
    _sha256,
    _single,
    _text,
    _validated_arguments,
)
from ._sqlite_m6_upgrade_m3_model_rows import (
    _M3PrimaryRows,
    read_primary_rows,
    read_run_row,
)
from ._sqlite_m6_upgrade_m3_model_support import (
    _bind_failure_support,
    _bind_usage_support,
    _SupportResolver,
)


def build_m6_sqlite_m3_model_documents_plan(
    *,
    connection: object,
    expected_run_id: object,
    expected_manifest_id: object,
    expected_model_manifest_id: object,
    selected_case_authority: object,
    observed_model_calls: object,
) -> M6SQLiteM3ModelDocumentsPlan:
    """Internal planner; its private failures are captured by the facade."""

    (
        controlled,
        run_id,
        manifest_id,
        model_manifest_id,
        authority,
        observations,
    ) = _validated_arguments(
        connection,
        expected_run_id,
        expected_manifest_id,
        expected_model_manifest_id,
        selected_case_authority,
        observed_model_calls,
    )
    run_row = _single(
        read_run_row(controlled, run_id=run_id),
        missing=M6SQLiteM3ModelDocumentFailureCode.SCOPE_NOT_FOUND,
    )
    if _text(run_row, "run_id") != run_id or _text(run_row, "manifest_id") != manifest_id:
        _fail(M6SQLiteM3ModelDocumentFailureCode.SCOPE_MISMATCH)
    resolver = _SupportResolver(
        controlled,
        run_id=run_id,
        case_id=authority.case.case_id,
        manifest_id=manifest_id,
        selected_revision=authority.candidate_case_binding.case_revision,
    )
    resolver.add(run_row, M6SQLiteM3SupportRoute.RUN, run_id)
    selected_case_version, selected_audit = resolver.bind_case_revision(
        authority.candidate_case_binding.case_revision
    )
    authority_audit = authority.audit_entry
    if (
        _sha256(selected_case_version, "document_sha256")
        != authority.candidate_case_binding.case_document_sha256
        or _integer(selected_case_version, "audit_sequence")
        != authority.candidate_case_binding.case_audit_sequence
        or _sha256(selected_audit, "entry_hash")
        != authority.candidate_case_binding.case_audit_entry_hash
        or _sha256(selected_audit, "after_sha256")
        != authority.candidate_case_binding.case_document_sha256
        or _text(selected_audit, "action") != authority_audit.action.value
        or _text(selected_audit, "object_kind") != authority_audit.object_ref.kind.value
        or _text(selected_audit, "object_id") != authority_audit.object_ref.artifact_id
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.CASE_BINDING_MISMATCH)
    primary: _M3PrimaryRows = read_primary_rows(
        controlled,
        run_id=run_id,
        case_id=authority.case.case_id,
    )
    claims = _claims(
        controlled,
        primary.claims,
        run_id=run_id,
        case_id=authority.case.case_id,
        manifest_id=manifest_id,
        model_manifest_id=model_manifest_id,
        observations=observations,
    )
    selected_packs = _selected_packs(controlled, resolver, authority, claims)
    selected_pack_by_key = {(value.pack_id, value.version): value for value in selected_packs}
    responses = _responses(
        controlled,
        primary.responses,
        run_id=run_id,
        case_id=authority.case.case_id,
        manifest_id=manifest_id,
        model_manifest_id=model_manifest_id,
        claims=claims,
    )
    caches = _caches(
        controlled,
        primary.caches,
        run_id=run_id,
        case_id=authority.case.case_id,
        manifest_id=manifest_id,
        model_manifest_id=model_manifest_id,
        claims=claims,
        responses=responses,
    )
    receipts = _receipts(
        controlled,
        primary.receipts,
        run_id=run_id,
        case_id=authority.case.case_id,
        manifest_id=manifest_id,
        claims=claims,
        responses=responses,
    )
    outputs = _outputs(
        controlled,
        primary.outputs,
        run_id=run_id,
        case_id=authority.case.case_id,
        manifest_id=manifest_id,
        claims=claims,
        responses=responses,
        caches=caches,
    )
    failures, historical_failures = _failures(
        controlled,
        primary.failures,
        run_id=run_id,
        case_id=authority.case.case_id,
        manifest_id=manifest_id,
        model_manifest_id=model_manifest_id,
        claims=claims,
    )
    usages = _usages(
        controlled,
        primary.usages,
        run_id=run_id,
        case_id=authority.case.case_id,
        claims=claims,
        responses=responses,
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
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM3ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    for failure in failures.values():
        _bind_failure_support(
            resolver,
            failure,
            selected_pack_by_key=selected_pack_by_key,
        )
    for failure in historical_failures:
        _bind_failure_support(
            resolver,
            failure,
            selected_pack_by_key=selected_pack_by_key,
            historical=True,
        )
    for usage in usages.values():
        _bind_usage_support(
            resolver,
            usage,
            selected_case=authority.case,
            failures=(*failures.values(), *historical_failures),
            claims=claims,
            receipts=receipts,
            outputs=outputs,
            usages=usages,
            selected_pack_by_key=selected_pack_by_key,
        )
    document_total = (
        sum(slot.document_bytes for graph in graphs for slot in graph.document_slots)
        + sum(slot.document_bytes for slot in resolver.document_slots)
        + sum(failure.slot.document_bytes for failure in historical_failures)
    )
    physical_total = sum(ref.size_bytes for graph in graphs for ref in graph.artifact_refs)
    if (
        document_total > MAX_M6_SQLITE_M3_MODEL_DOCUMENT_TOTAL_BYTES
        or physical_total > MAX_M6_SQLITE_M3_MODEL_PHYSICAL_TOTAL_BYTES
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.DOCUMENT_TOO_LARGE)
    try:
        plan = M6SQLiteM3ModelDocumentsPlan(
            run_id=run_id,
            case_id=authority.case.case_id,
            manifest_id=manifest_id,
            model_manifest_id=model_manifest_id,
            selected_case_binding=authority.candidate_case_binding,
            selected_case=authority.case,
            selected_case_revision=authority.candidate_case_binding.case_revision,
            selected_case_audit=authority.audit_entry,
            selected_packs=selected_packs,
            observed_model_calls=observations,
            call_graphs=graphs,
            historical_failures=_historical_failure_bindings(historical_failures),
            support_slots=resolver.slots,
            support_document_slots=resolver.document_slots,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM3ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    _active(controlled)
    return plan

"""Build the complete M6 source cut and candidate-safe execution catalog."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionExecutionSourceCatalogAuthority,
    M6RegressionExecutionSourceCatalogEntry,
    M6RegressionSourceInventoryCutAuthority,
    M6RegressionSourceInventoryItem,
    M6RegressionSourceRunCut,
)
from labcourt.contracts.m6_source_authority_store import (
    M6SourceAuthorityDocumentEntry,
    M6SourceAuthorityDocumentKind,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_regression_dataset import (
    M6RegressionRunScopeObservation,
    M6RegressionSealedSourceObservation,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6RegressionSourceCatalogErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SNAPSHOT_IDENTITY_MISMATCH = "SNAPSHOT_IDENTITY_MISMATCH"
    RUN_SCOPE_INVALID = "RUN_SCOPE_INVALID"
    SOURCE_SCOPE_INCOMPLETE = "SOURCE_SCOPE_INCOMPLETE"
    SOURCE_BUNDLE_INVALID = "SOURCE_BUNDLE_INVALID"
    SOURCE_DOCUMENT_INVALID = "SOURCE_DOCUMENT_INVALID"
    CATALOG_INVARIANT_VIOLATION = "CATALOG_INVARIANT_VIOLATION"


class M6RegressionSourceCatalogError(LabCourtError):
    """The evaluator source universe could not produce one blind catalog."""

    def __init__(self, code: M6RegressionSourceCatalogErrorCode) -> None:
        if not isinstance(code, M6RegressionSourceCatalogErrorCode):
            raise TypeError("code must be an M6RegressionSourceCatalogErrorCode")
        self.code = code
        super().__init__(f"M6 regression source catalog failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6RegressionSourceCatalogBundle:
    source_inventory_cut: M6RegressionSourceInventoryCutAuthority
    execution_source_catalog: M6RegressionExecutionSourceCatalogAuthority
    source_inventory_cut_document: str
    source_inventory_cut_content_sha256: str
    execution_source_catalog_document: str
    execution_source_catalog_content_sha256: str


def _fail(code: M6RegressionSourceCatalogErrorCode) -> NoReturn:
    raise M6RegressionSourceCatalogError(code)


def _canonical_model(
    value: object,
    expected: type[_ModelT],
    code: M6RegressionSourceCatalogErrorCode,
) -> _ModelT:
    if not isinstance(value, expected):
        _fail(M6RegressionSourceCatalogErrorCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(code)
    if controlled != value:
        _fail(code)
    return controlled


def _document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json"))


def _content(document: str) -> tuple[str, int]:
    payload = document.encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _require_exact_document(
    value: BaseModel,
    document: object,
) -> tuple[str, int]:
    if not isinstance(document, str) or _document(value) != document:
        _fail(M6RegressionSourceCatalogErrorCode.SOURCE_DOCUMENT_INVALID)
    return _content(document)


def _entry_by_kind(
    source: M6RegressionSealedSourceObservation,
) -> dict[M6SourceAuthorityDocumentKind, M6SourceAuthorityDocumentEntry]:
    return {item.kind: item for item in source.source_seal.entries}


def _validate_scope(
    value: M6RegressionRunScopeObservation,
) -> tuple[M5ArtifactValidationReport, str, int]:
    report = _canonical_model(
        value.m5_validation_report,
        M5ArtifactValidationReport,
        M6RegressionSourceCatalogErrorCode.RUN_SCOPE_INVALID,
    )
    report_content_sha256, report_size = _require_exact_document(
        report,
        value.m5_validation_report_document,
    )
    if (
        not report.passed
        or report.authority_root_sha256 is None
        or report.run_id != value.source_run_id
        or any(
            item.source_run_id != value.source_run_id
            or item.source_manifest_id != report.manifest_id
            for item in value.required_sources
        )
    ):
        _fail(M6RegressionSourceCatalogErrorCode.RUN_SCOPE_INVALID)
    return report, report_content_sha256, report_size


def _validate_source(
    value: M6RegressionSealedSourceObservation,
) -> tuple[
    M6RegressionSealedSourceObservation,
    dict[M6SourceAuthorityDocumentKind, M6SourceAuthorityDocumentEntry],
    str,
    int,
]:
    closure = _canonical_model(
        value.replay_input_closure,
        type(value.replay_input_closure),
        M6RegressionSourceCatalogErrorCode.SOURCE_BUNDLE_INVALID,
    )
    authority = _canonical_model(
        value.replay_input_authority,
        type(value.replay_input_authority),
        M6RegressionSourceCatalogErrorCode.SOURCE_BUNDLE_INVALID,
    )
    report = _canonical_model(
        value.source_validation_report,
        type(value.source_validation_report),
        M6RegressionSourceCatalogErrorCode.SOURCE_BUNDLE_INVALID,
    )
    case = _canonical_model(
        value.source_case,
        type(value.source_case),
        M6RegressionSourceCatalogErrorCode.SOURCE_BUNDLE_INVALID,
    )
    manifest = _canonical_model(
        value.source_manifest,
        type(value.source_manifest),
        M6RegressionSourceCatalogErrorCode.SOURCE_BUNDLE_INVALID,
    )
    seal = _canonical_model(
        value.source_seal,
        type(value.source_seal),
        M6RegressionSourceCatalogErrorCode.SOURCE_BUNDLE_INVALID,
    )
    documents = {
        M6SourceAuthorityDocumentKind.REPLAY_INPUT_CLOSURE: (
            closure,
            value.replay_input_closure_document,
        ),
        M6SourceAuthorityDocumentKind.REPLAY_INPUT_AUTHORITY: (
            authority,
            value.replay_input_authority_document,
        ),
        M6SourceAuthorityDocumentKind.SOURCE_VALIDATION_REPORT: (
            report,
            value.source_validation_report_document,
        ),
        M6SourceAuthorityDocumentKind.SOURCE_CASE: (case, value.source_case_document),
        M6SourceAuthorityDocumentKind.SOURCE_MANIFEST: (
            manifest,
            value.source_manifest_document,
        ),
    }
    entries = _entry_by_kind(value)
    if set(entries) != set(M6SourceAuthorityDocumentKind):
        _fail(M6RegressionSourceCatalogErrorCode.SOURCE_BUNDLE_INVALID)
    for kind, (model, document) in documents.items():
        content_sha256, size_bytes = _require_exact_document(model, document)
        entry = entries[kind]
        if entry.content_sha256 != content_sha256 or entry.size_bytes != size_bytes:
            _fail(M6RegressionSourceCatalogErrorCode.SOURCE_DOCUMENT_INVALID)
    seal_content_sha256, seal_size_bytes = _require_exact_document(
        seal,
        value.source_seal_document,
    )

    if (
        closure.source_case_id is None
        or closure.source_case_revision is None
        or closure.source_case_document_sha256 is None
        or closure.sample_id != seal.sample_id
        or closure.source_run_id != seal.source_run_id
        or closure.source_case_id != seal.source_case_id
        or closure.source_case_revision != seal.source_case_revision
        or closure.source_case_document_sha256 != seal.source_case_document_sha256
        or closure.source_manifest_id != seal.source_manifest_id
        or closure.input_authority_id != authority.input_authority_id
        or closure.input_authority_document_sha256 != authority.input_authority_document_sha256
        or closure.replay_input_closure_authority_id != seal.replay_input_closure_authority_id
        or closure.replay_input_closure_document_sha256 != seal.replay_input_closure_document_sha256
        or authority.input_authority_id != seal.replay_input_authority_id
        or authority.input_authority_document_sha256 != seal.replay_input_authority_document_sha256
        or authority.source_case_document_sha256 != seal.source_case_document_sha256
        or authority.source_manifest_id != seal.source_manifest_id
        or authority.source_m5_authority_root_sha256 != seal.source_m5_authority_root_sha256
        or report.report_id != seal.source_validation_report_id
        or not report.passed
        or report.authority_root_sha256 != seal.source_m5_authority_root_sha256
        or case.run_id != seal.source_run_id
        or case.case_id != seal.source_case_id
        or case.manifest_id != seal.source_manifest_id
        or case.status != CaseStatus.CLOSED
        or case.final_decision is None
        or manifest.manifest_id != seal.source_manifest_id
    ):
        _fail(M6RegressionSourceCatalogErrorCode.SOURCE_BUNDLE_INVALID)
    return value, entries, seal_content_sha256, seal_size_bytes


def _run_scope_root(
    run_id: str,
    items: tuple[M6RegressionSourceInventoryItem, ...],
) -> str:
    return sha256_hex(
        [
            "m6-regression-source-run-scope",
            1,
            run_id,
            [item.source_scope_key for item in items],
        ]
    )


def build_m6_regression_source_catalog(
    *,
    run_scopes: object,
    sealed_sources: object,
) -> M6RegressionSourceCatalogBundle:
    """Freeze the exact DB-enumerated source universe before candidate execution."""

    if (
        not isinstance(run_scopes, tuple)
        or not run_scopes
        or any(not isinstance(item, M6RegressionRunScopeObservation) for item in run_scopes)
        or not isinstance(sealed_sources, tuple)
        or not sealed_sources
        or any(not isinstance(item, M6RegressionSealedSourceObservation) for item in sealed_sources)
    ):
        _fail(M6RegressionSourceCatalogErrorCode.INVALID_ARGUMENT)
    controlled_scopes = tuple(run_scopes)
    controlled_sources = tuple(sealed_sources)
    scope_run_ids = tuple(item.source_run_id for item in controlled_scopes)
    if scope_run_ids != tuple(sorted(scope_run_ids)) or len(scope_run_ids) != len(
        set(scope_run_ids)
    ):
        _fail(M6RegressionSourceCatalogErrorCode.RUN_SCOPE_INVALID)
    identities = {item.source_identity_sha256 for item in controlled_scopes}
    if len(identities) != 1:
        _fail(M6RegressionSourceCatalogErrorCode.SNAPSHOT_IDENTITY_MISMATCH)

    scope_reports = {scope.source_run_id: _validate_scope(scope) for scope in controlled_scopes}
    baseline_manifest_ids = {report.manifest_id for report, _, _ in scope_reports.values()}
    if len(baseline_manifest_ids) != 1:
        _fail(M6RegressionSourceCatalogErrorCode.RUN_SCOPE_INVALID)
    baseline_manifest_id = next(iter(baseline_manifest_ids))

    required = {item.source_key for scope in controlled_scopes for item in scope.required_sources}
    if len(required) != sum(len(scope.required_sources) for scope in controlled_scopes):
        _fail(M6RegressionSourceCatalogErrorCode.RUN_SCOPE_INVALID)
    validated_sources = tuple(_validate_source(item) for item in controlled_sources)
    source_by_key = {item[0].source_key: item for item in validated_sources}
    if len(source_by_key) != len(validated_sources) or set(source_by_key) != required:
        _fail(M6RegressionSourceCatalogErrorCode.SOURCE_SCOPE_INCOMPLETE)

    inventory_items: list[M6RegressionSourceInventoryItem] = []
    for source, entries, seal_content_sha256, seal_size_bytes in validated_sources:
        closure = source.replay_input_closure
        seal = source.source_seal
        scope = next(item for item in controlled_scopes if item.source_run_id == seal.source_run_id)
        scope_report, scope_report_content_sha256, _ = scope_reports[seal.source_run_id]
        if (
            closure.source_manifest_id != baseline_manifest_id
            or source.source_validation_report != scope_report
            or seal.source_validation_report_id != scope_report.report_id
            or seal.source_validation_report_document_sha256 != scope_report_content_sha256
            or seal.source_m5_authority_root_sha256 != scope_report.authority_root_sha256
            or seal.audit_head_sequence != scope.audit_head_sequence
            or seal.audit_head_hash != scope.audit_head_hash
        ):
            _fail(M6RegressionSourceCatalogErrorCode.SNAPSHOT_IDENTITY_MISMATCH)
        closure_entry = entries[M6SourceAuthorityDocumentKind.REPLAY_INPUT_CLOSURE]
        authority_entry = entries[M6SourceAuthorityDocumentKind.REPLAY_INPUT_AUTHORITY]
        try:
            inventory_items.append(
                M6RegressionSourceInventoryItem(
                    sample_id=closure.sample_id,
                    source_run_id=closure.source_run_id,
                    source_case_id=seal.source_case_id,
                    source_case_revision=seal.source_case_revision,
                    source_case_document_sha256=seal.source_case_document_sha256,
                    source_manifest_id=seal.source_manifest_id,
                    sealed_source_validation_report_id=seal.source_validation_report_id,
                    sealed_source_validation_report_document_sha256=(
                        seal.source_validation_report_document_sha256
                    ),
                    sealed_source_m5_authority_root_sha256=(seal.source_m5_authority_root_sha256),
                    sealed_audit_head_sequence=seal.audit_head_sequence,
                    sealed_audit_head_hash=seal.audit_head_hash,
                    source_seal_id=seal.seal_id,
                    source_seal_content_sha256=seal_content_sha256,
                    source_seal_size_bytes=seal_size_bytes,
                    input_authority_id=closure.input_authority_id,
                    input_authority_document_sha256=(closure.input_authority_document_sha256),
                    input_authority_content_sha256=authority_entry.content_sha256,
                    input_authority_size_bytes=authority_entry.size_bytes,
                    replay_input_closure_authority_id=(closure.replay_input_closure_authority_id),
                    replay_input_closure_document_sha256=(
                        closure.replay_input_closure_document_sha256
                    ),
                    replay_input_closure_content_sha256=closure_entry.content_sha256,
                    replay_input_closure_size_bytes=closure_entry.size_bytes,
                )
            )
        except (TypeError, ValueError, ValidationError):
            _fail(M6RegressionSourceCatalogErrorCode.SOURCE_BUNDLE_INVALID)
    ordered_items = tuple(sorted(inventory_items, key=lambda item: item.sample_id))

    run_cuts: list[M6RegressionSourceRunCut] = []
    for scope in controlled_scopes:
        report, report_content_sha256, _ = scope_reports[scope.source_run_id]
        scoped_items = tuple(
            item for item in ordered_items if item.source_run_id == scope.source_run_id
        )
        try:
            run_cuts.append(
                M6RegressionSourceRunCut(
                    source_run_id=scope.source_run_id,
                    baseline_manifest_id=baseline_manifest_id,
                    source_config_sha256=report.config_sha256,
                    audit_head_sequence=scope.audit_head_sequence,
                    audit_head_hash=scope.audit_head_hash,
                    m5_validation_report_id=report.report_id,
                    m5_validation_report_content_sha256=report_content_sha256,
                    m5_authority_root_sha256=report.authority_root_sha256,
                    source_item_count=len(scoped_items),
                    source_scope_root_sha256=_run_scope_root(
                        scope.source_run_id,
                        scoped_items,
                    ),
                )
            )
        except (TypeError, ValueError, ValidationError):
            _fail(M6RegressionSourceCatalogErrorCode.RUN_SCOPE_INVALID)
    try:
        source_cut = M6RegressionSourceInventoryCutAuthority(
            baseline_manifest_id=baseline_manifest_id,
            run_cuts=tuple(run_cuts),
            items=ordered_items,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6RegressionSourceCatalogErrorCode.CATALOG_INVARIANT_VIOLATION)
    source_cut_document = _document(source_cut)
    source_cut_content_sha256, _ = _content(source_cut_document)

    source_by_item_id = {
        item.source_item_id: source_by_key[item.source_scope_key][0] for item in source_cut.items
    }
    try:
        catalog_entries = tuple(
            M6RegressionExecutionSourceCatalogEntry(
                source_item_id=item.source_item_id,
                sample_id=item.sample_id,
                source_seal_id=item.source_seal_id,
                source_seal_content_sha256=item.source_seal_content_sha256,
                source_seal_size_bytes=item.source_seal_size_bytes,
                input_authority_id=item.input_authority_id,
                input_authority_document_sha256=item.input_authority_document_sha256,
                input_authority_content_sha256=item.input_authority_content_sha256,
                input_authority_size_bytes=item.input_authority_size_bytes,
                replay_input_closure_content_sha256=(item.replay_input_closure_content_sha256),
                replay_input_closure_size_bytes=item.replay_input_closure_size_bytes,
                replay_input_closure=source_by_item_id[item.source_item_id].replay_input_closure,
            )
            for item in source_cut.items
        )
        catalog = M6RegressionExecutionSourceCatalogAuthority(
            baseline_manifest_id=baseline_manifest_id,
            source_inventory_cut_authority_id=(source_cut.source_inventory_cut_authority_id),
            source_inventory_cut_content_sha256=source_cut_content_sha256,
            source_inventory_item_count=source_cut.source_item_count,
            source_inventory_root_sha256=source_cut.source_inventory_root_sha256,
            entries=catalog_entries,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6RegressionSourceCatalogErrorCode.CATALOG_INVARIANT_VIOLATION)
    catalog_document = _document(catalog)
    catalog_content_sha256, _ = _content(catalog_document)
    return M6RegressionSourceCatalogBundle(
        source_inventory_cut=source_cut,
        execution_source_catalog=catalog,
        source_inventory_cut_document=source_cut_document,
        source_inventory_cut_content_sha256=source_cut_content_sha256,
        execution_source_catalog_document=catalog_document,
        execution_source_catalog_content_sha256=catalog_content_sha256,
    )


__all__ = [
    "M6RegressionSourceCatalogBundle",
    "M6RegressionSourceCatalogError",
    "M6RegressionSourceCatalogErrorCode",
    "build_m6_regression_source_catalog",
]

"""Resolve locked M6 ToolResults from one validated historical M4 snapshot."""

from __future__ import annotations

from enum import StrEnum
from typing import NoReturn, cast

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.hearing_acquisition import (
    AcquisitionExecutionPublication,
    AcquisitionRequest,
    ToolExecutionManifest,
    ToolExecutionReceipt,
)
from labcourt.contracts.hearing_persistence import EvidencePackDerivation
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m6_replay_locked import M6LockedToolResultInput
from labcourt.domain.m6_semantic_projection import M6ResolvedAcquisition
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_acquisition_authority import (
    M6ValidatedM4ReplayAuthoritySnapshot,
)
from labcourt.ports.m6_historical_retrieval import M6HistoricalAuthorityDocument


class M6AcquisitionProjectionErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SNAPSHOT_RUN_MISMATCH = "SNAPSHOT_RUN_MISMATCH"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    DOCUMENT_MISSING = "DOCUMENT_MISSING"
    DOCUMENT_DUPLICATE = "DOCUMENT_DUPLICATE"
    FOREIGN_AUTHORITY = "FOREIGN_AUTHORITY"
    EXTRA_AUTHORITY_DOCUMENT = "EXTRA_AUTHORITY_DOCUMENT"
    TOOL_RESULT_INVENTORY_MISMATCH = "TOOL_RESULT_INVENTORY_MISMATCH"
    PACK_AUTHORITY_MISSING = "PACK_AUTHORITY_MISSING"
    CLOSURE_INVALID = "CLOSURE_INVALID"


class M6AcquisitionProjectionError(LabCourtError):
    def __init__(self, code: M6AcquisitionProjectionErrorCode) -> None:
        if not isinstance(code, M6AcquisitionProjectionErrorCode):
            raise TypeError("code must be an M6AcquisitionProjectionErrorCode")
        self.code = code
        super().__init__(f"M6 acquisition projection failed: {code.value}")


def _fail(code: M6AcquisitionProjectionErrorCode) -> NoReturn:
    raise M6AcquisitionProjectionError(code)


_MODEL_BY_KIND: dict[M4ProjectionArtifactKind, type[BaseModel]] = {
    M4ProjectionArtifactKind.ACQUISITION_REQUEST: AcquisitionRequest,
    M4ProjectionArtifactKind.TOOL_EXECUTION_MANIFEST: ToolExecutionManifest,
    M4ProjectionArtifactKind.ACQUISITION_EXECUTION_PUBLICATION: (AcquisitionExecutionPublication),
    M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT: ToolExecutionReceipt,
    M4ProjectionArtifactKind.EVIDENCE_PACK_DERIVATION: EvidencePackDerivation,
}


def _document_id(kind: M4ProjectionArtifactKind, document: BaseModel) -> str:
    attribute = {
        M4ProjectionArtifactKind.ACQUISITION_REQUEST: "request_id",
        M4ProjectionArtifactKind.TOOL_EXECUTION_MANIFEST: "execution_manifest_id",
        M4ProjectionArtifactKind.ACQUISITION_EXECUTION_PUBLICATION: "publication_id",
        M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT: "receipt_id",
        M4ProjectionArtifactKind.EVIDENCE_PACK_DERIVATION: "derivation_id",
    }[kind]
    value = getattr(document, attribute, None)
    if not isinstance(value, str):
        _fail(M6AcquisitionProjectionErrorCode.DOCUMENT_INVALID)
    return value


def _document_scope(document: BaseModel) -> tuple[str, str, str]:
    if isinstance(document, (AcquisitionExecutionPublication, ToolExecutionReceipt)):
        return (
            document.request.run_id,
            document.request.case_id,
            document.request.manifest_id,
        )
    run_id = getattr(document, "run_id", None)
    case_id = getattr(document, "case_id", None)
    manifest_id = getattr(document, "manifest_id", None)
    if not all(isinstance(value, str) for value in (run_id, case_id, manifest_id)):
        _fail(M6AcquisitionProjectionErrorCode.DOCUMENT_INVALID)
    return cast(str, run_id), cast(str, case_id), cast(str, manifest_id)


def _parse_document(
    authority: M6HistoricalAuthorityDocument,
) -> BaseModel:
    if not isinstance(authority.kind, M4ProjectionArtifactKind):
        _fail(M6AcquisitionProjectionErrorCode.DOCUMENT_INVALID)
    model = _MODEL_BY_KIND.get(authority.kind)
    if model is None:
        _fail(M6AcquisitionProjectionErrorCode.DOCUMENT_INVALID)
    try:
        document = model.model_validate_json(authority.canonical_document)
    except (TypeError, ValueError, ValidationError):
        _fail(M6AcquisitionProjectionErrorCode.DOCUMENT_INVALID)
    if (
        canonical_json(document.model_dump(mode="json")) != authority.canonical_document
        or _document_id(authority.kind, document) != authority.artifact_id
    ):
        _fail(M6AcquisitionProjectionErrorCode.DOCUMENT_INVALID)
    return document


def _canonical_arguments(
    source_case: object,
    snapshot: object,
    locked_tool_results: object,
) -> tuple[
    Case,
    M6ValidatedM4ReplayAuthoritySnapshot,
    tuple[M6LockedToolResultInput, ...],
]:
    if (
        not isinstance(source_case, Case)
        or not isinstance(snapshot, M6ValidatedM4ReplayAuthoritySnapshot)
        or not isinstance(locked_tool_results, tuple)
        or any(not isinstance(item, M6LockedToolResultInput) for item in locked_tool_results)
    ):
        _fail(M6AcquisitionProjectionErrorCode.INVALID_ARGUMENT)
    try:
        case = Case.model_validate(
            source_case.model_dump(mode="json", exclude_computed_fields=True)
        )
        canonical_snapshot = M6ValidatedM4ReplayAuthoritySnapshot(
            source_identity_sha256=snapshot.source_identity_sha256,
            run_id=snapshot.run_id,
            documents=tuple(
                M6HistoricalAuthorityDocument(
                    kind=item.kind,
                    artifact_id=item.artifact_id,
                    canonical_document=item.canonical_document,
                )
                for item in snapshot.documents
            ),
        )
        locked = tuple(
            M6LockedToolResultInput.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in locked_tool_results
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6AcquisitionProjectionErrorCode.INVALID_ARGUMENT)
    ids = tuple(item.tool_result_id for item in locked)
    if len(ids) != len(set(ids)):
        _fail(M6AcquisitionProjectionErrorCode.TOOL_RESULT_INVENTORY_MISMATCH)
    return case, canonical_snapshot, locked


def _required_document(
    documents: dict[tuple[M4ProjectionArtifactKind, str], BaseModel],
    kind: M4ProjectionArtifactKind,
    artifact_id: str,
) -> BaseModel:
    document = documents.get((kind, artifact_id))
    if document is None:
        _fail(M6AcquisitionProjectionErrorCode.DOCUMENT_MISSING)
    return document


def resolve_m6_locked_acquisitions(
    *,
    source_case: Case,
    snapshot: M6ValidatedM4ReplayAuthoritySnapshot,
    locked_tool_results: tuple[M6LockedToolResultInput, ...],
) -> tuple[M6ResolvedAcquisition, ...]:
    """Resolve the complete acquisition chain without querying a live tool."""

    case, authority, locked = _canonical_arguments(
        source_case,
        snapshot,
        locked_tool_results,
    )
    if authority.run_id != case.run_id:
        _fail(M6AcquisitionProjectionErrorCode.SNAPSHOT_RUN_MISMATCH)

    parsed: dict[tuple[M4ProjectionArtifactKind, str], BaseModel] = {}
    scoped_document_keys: set[tuple[M4ProjectionArtifactKind, str]] = set()
    for snapshot_document in authority.documents:
        if snapshot_document.kind not in _MODEL_BY_KIND:
            continue
        document = _parse_document(snapshot_document)
        key = (
            cast(M4ProjectionArtifactKind, snapshot_document.kind),
            snapshot_document.artifact_id,
        )
        if key in parsed:
            _fail(M6AcquisitionProjectionErrorCode.DOCUMENT_DUPLICATE)
        parsed[key] = document
        run_id, case_id, manifest_id = _document_scope(document)
        if run_id != authority.run_id:
            _fail(M6AcquisitionProjectionErrorCode.FOREIGN_AUTHORITY)
        if case_id == case.case_id:
            if manifest_id != case.manifest_id:
                _fail(M6AcquisitionProjectionErrorCode.FOREIGN_AUTHORITY)
            scoped_document_keys.add(key)

    case_results = {
        result.tool_result_id: result
        for pack in case.evidence_packs
        for result in pack.tool_results
    }
    if set(case_results) != {item.tool_result_id for item in locked}:
        _fail(M6AcquisitionProjectionErrorCode.TOOL_RESULT_INVENTORY_MISMATCH)
    packs_by_id = {pack.pack_id: pack for pack in case.evidence_packs}
    used_document_keys: set[tuple[M4ProjectionArtifactKind, str]] = set()
    resolved: list[M6ResolvedAcquisition] = []
    for locked_item in locked:
        refs = (
            (
                M4ProjectionArtifactKind.ACQUISITION_REQUEST,
                locked_item.acquisition_request_ref.artifact_id,
            ),
            (
                M4ProjectionArtifactKind.TOOL_EXECUTION_MANIFEST,
                locked_item.execution_manifest_ref.artifact_id,
            ),
            (
                M4ProjectionArtifactKind.ACQUISITION_EXECUTION_PUBLICATION,
                locked_item.execution_publication_ref.artifact_id,
            ),
            (
                M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT,
                locked_item.tool_receipt_ref.artifact_id,
            ),
            (
                M4ProjectionArtifactKind.EVIDENCE_PACK_DERIVATION,
                locked_item.evidence_pack_derivation_ref.artifact_id,
            ),
        )
        request = _required_document(parsed, *refs[0])
        manifest = _required_document(parsed, *refs[1])
        publication = _required_document(parsed, *refs[2])
        receipt = _required_document(parsed, *refs[3])
        derivation = _required_document(parsed, *refs[4])
        used_document_keys.update(refs)
        if not (
            isinstance(request, AcquisitionRequest)
            and isinstance(manifest, ToolExecutionManifest)
            and isinstance(publication, AcquisitionExecutionPublication)
            and isinstance(receipt, ToolExecutionReceipt)
            and isinstance(derivation, EvidencePackDerivation)
        ):
            _fail(M6AcquisitionProjectionErrorCode.DOCUMENT_INVALID)
        previous = packs_by_id.get(request.current_evidence_pack_id)
        resulting = packs_by_id.get(locked_item.resulting_evidence_pack_ref.artifact_id)
        if previous is None or resulting is None:
            _fail(M6AcquisitionProjectionErrorCode.PACK_AUTHORITY_MISSING)
        try:
            resolved.append(
                M6ResolvedAcquisition(
                    locked_input=locked_item,
                    request=request,
                    execution_manifest=manifest,
                    publication=publication,
                    receipt=receipt,
                    derivation=derivation,
                    previous_evidence_pack=previous,
                    resulting_evidence_pack=resulting,
                )
            )
        except (TypeError, ValueError, ValidationError):
            _fail(M6AcquisitionProjectionErrorCode.CLOSURE_INVALID)
    if used_document_keys != scoped_document_keys:
        _fail(M6AcquisitionProjectionErrorCode.EXTRA_AUTHORITY_DOCUMENT)
    return tuple(sorted(resolved, key=lambda item: item.sort_key))


__all__ = [
    "M6AcquisitionProjectionError",
    "M6AcquisitionProjectionErrorCode",
    "resolve_m6_locked_acquisitions",
]

"""Read exact M3 screening-call authority for one locked M6 replay."""

from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from labcourt.adapters.storage._m6_snapshot_identity import (
    capture_m6_readonly_snapshot_identity,
)
from labcourt.adapters.storage.readonly_m3_artifacts import ReadonlyM3ArtifactRepository
from labcourt.adapters.storage.readonly_sqlite import ReadOnlySnapshotError
from labcourt.application.m6_model_call_authority import (
    M6ModelCallAuthorityError,
    M6ModelCallAuthorityErrorCode,
    assemble_m6_locked_screening_model_calls,
)
from labcourt.contracts.artifact_validation import M3ArtifactInventoryKind
from labcourt.contracts.cases import Case
from labcourt.contracts.m6_replay_locked import M6LockedModelCallInput
from labcourt.domain.m6_semantic_projection import (
    M6ResolvedModelResponse,
    resolve_m6_locked_model_responses,
)
from labcourt.ports.m6_model_calls import (
    M6M3ModelCacheAuthorityDocument,
    M6M3ModelCallAuthoritySnapshot,
    M6M3ModelCallFailureAuthorityDocument,
    M6M3ModelParseReceiptAuthorityDocument,
    M6M3ModelRequestAuthorityDocument,
    M6M3ModelResponseAuthorityDocument,
    M6M3ModelUsageAuthorityDocument,
    M6M3ParsedOutputAuthorityDocument,
)

_MODEL_CALL_AUTHORITY_INVENTORIES = frozenset(
    {
        M3ArtifactInventoryKind.MODEL_CALL_CLAIM,
        M3ArtifactInventoryKind.MODEL_CALL_FAILURE_AUTHORITY,
        M3ArtifactInventoryKind.MODEL_RESPONSE,
        M3ArtifactInventoryKind.PARSED_SCREENING_OUTPUT,
        M3ArtifactInventoryKind.MODEL_PARSE_RECEIPT,
        M3ArtifactInventoryKind.MODEL_CACHE_ENTRY,
        M3ArtifactInventoryKind.MODEL_CALL_USAGE,
    }
)


def _controlled_case(source_case: object) -> Case:
    if not isinstance(source_case, Case):
        raise M6ModelCallAuthorityError(M6ModelCallAuthorityErrorCode.INVALID_ARGUMENT)
    try:
        controlled = Case.model_validate(
            source_case.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (TypeError, ValueError, ValidationError):
        raise M6ModelCallAuthorityError(M6ModelCallAuthorityErrorCode.SOURCE_CASE_INVALID) from None
    if controlled != source_case:
        raise M6ModelCallAuthorityError(M6ModelCallAuthorityErrorCode.SOURCE_CASE_INVALID)
    return controlled


class ReadonlyM6ModelCallAuthorityRepository:
    """Assemble M3 calls from one private snapshot without providers or writes."""

    __slots__ = ("_snapshot",)

    def __init__(self, snapshot: str | Path) -> None:
        self._snapshot = Path(snapshot).absolute()

    def load_validated_snapshot(
        self,
        source_case: Case,
    ) -> M6M3ModelCallAuthoritySnapshot:
        controlled_case = _controlled_case(source_case)
        before = capture_m6_readonly_snapshot_identity(self._snapshot)
        authority = ReadonlyM3ArtifactRepository(self._snapshot).scan(controlled_case.run_id)
        if capture_m6_readonly_snapshot_identity(self._snapshot) != before:
            raise ReadOnlySnapshotError("DATABASE_CHANGED_DURING_M6_MODEL_CALL_SCAN")
        case_id = controlled_case.case_id
        return M6M3ModelCallAuthoritySnapshot(
            source_identity_sha256=before.identity_sha256,
            run_id=controlled_case.run_id,
            case_id=case_id,
            manifest_id=controlled_case.manifest_id,
            requests=tuple(
                M6M3ModelRequestAuthorityDocument(
                    request=document.request,
                    document_sha256=document.document_sha256,
                )
                for document in authority.model_call_requests
                if document.request.case_id == case_id
            ),
            responses=tuple(
                M6M3ModelResponseAuthorityDocument(
                    response=document.response,
                    document_sha256=document.document_sha256,
                )
                for document in authority.raw_responses
                if document.response.case_id == case_id
            ),
            caches=tuple(
                M6M3ModelCacheAuthorityDocument(
                    request=document.request,
                    request_document_sha256=document.request_document_sha256,
                    entry=document.entry,
                    document_sha256=document.document_sha256,
                )
                for document in authority.model_cache_entries
                if document.entry.case_id == case_id or document.request.case_id == case_id
            ),
            parse_receipts=tuple(
                M6M3ModelParseReceiptAuthorityDocument(
                    receipt=document.receipt,
                    document_sha256=document.document_sha256,
                )
                for document in authority.parse_receipts
                if document.receipt.case_id == case_id
            ),
            parsed_outputs=tuple(
                M6M3ParsedOutputAuthorityDocument(
                    output=document.output,
                    document_sha256=document.document_sha256,
                )
                for document in authority.parsed_outputs
                if document.output.case_id == case_id
            ),
            failures=tuple(
                M6M3ModelCallFailureAuthorityDocument(
                    authority=document.authority,
                    document_sha256=document.document_sha256,
                )
                for document in authority.model_call_failure_authorities
                if document.authority.request.case_id == case_id
            ),
            usages=tuple(
                M6M3ModelUsageAuthorityDocument(
                    usage=document.usage,
                    request_id=document.request_id,
                    response_id=document.response_id,
                    case_id=document.case_id,
                    case_revision=document.case_revision,
                    consumer_kind=document.consumer_kind,
                    consumer_id=document.consumer_id,
                    accounted_at=document.accounted_at,
                    document_sha256=document.document_sha256,
                )
                for document in authority.model_call_usages
                if document.case_id == case_id
            ),
            # ``ReadonlyM3ArtifactRepository`` validates the complete frozen M3
            # inventory, including Case-level screening, Verdict, review, and
            # backlog relations.  This DTO is deliberately narrower: it is the
            # authority for the selected Case's screening model-call graph.
            # Carrying unrelated inventory findings here makes a legal M4
            # successor impossible to replay because the frozen M3 validator
            # reports the old Verdict binding as a known successor finding.
            # The independently sealed M4/M5 report remains responsible for
            # proving that such whole-run findings are either gating or were
            # precisely superseded by a valid M4 graph.
            authority_failure_count=sum(
                failure.inventory_kind in _MODEL_CALL_AUTHORITY_INVENTORIES
                for failure in authority.failures
            ),
        )

    def assemble(self, source_case: Case) -> tuple[M6LockedModelCallInput, ...]:
        controlled_case = _controlled_case(source_case)
        snapshot = self.load_validated_snapshot(controlled_case)
        return assemble_m6_locked_screening_model_calls(
            source_case=controlled_case,
            snapshot=snapshot,
        )

    def resolve(self, source_case: Case) -> tuple[M6ResolvedModelResponse, ...]:
        return resolve_m6_locked_model_responses(self.assemble(source_case))


__all__ = [
    "ReadonlyM6ModelCallAuthorityRepository",
]

"""Read exact M4 hearing-call authority from one private SQLite snapshot."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from labcourt.application.m6_hearing_model_call_authority import (
    M6HearingModelCallAuthorityError,
    M6HearingModelCallAuthorityErrorCode,
    assemble_m6_locked_hearing_model_calls,
    derive_m6_hearing_model_call_authority_root,
    resolve_m6_locked_hearing_model_responses,
)
from labcourt.contracts.cases import Case
from labcourt.contracts.hearing import (
    HearingModelCacheEntry,
    HearingModelCallFailureAuthority,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingRoleOutput,
    HearingUsageReceipt,
)
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m6_replay_locked import M6LockedModelCallInput
from labcourt.domain.m6_semantic_projection import M6ResolvedModelResponse
from labcourt.ports.m6_model_calls import (
    M6M4ModelCacheAuthorityDocument,
    M6M4ModelCallAuthoritySnapshot,
    M6M4ModelCallFailureAuthorityDocument,
    M6M4ModelParseReceiptAuthorityDocument,
    M6M4ModelRequestAuthorityDocument,
    M6M4ModelResponseAuthorityDocument,
    M6M4ModelUsageAuthorityDocument,
    M6M4RoleOutputAuthorityDocument,
)

from ._m6_snapshot_identity import capture_m6_readonly_snapshot_identity
from .readonly_m4_artifacts import (
    M4ValidatedReplayDocument,
    ReadonlyM4ArtifactRepository,
)
from .readonly_sqlite import ReadOnlySnapshotError


def _invalid_snapshot() -> M6HearingModelCallAuthorityError:
    return M6HearingModelCallAuthorityError(
        M6HearingModelCallAuthorityErrorCode.SNAPSHOT_AUTHORITY_INVALID
    )


class ReadonlyM6HearingModelCallAuthorityRepository:
    """Expose only typed metadata; never open a raw response locator."""

    __slots__ = ("_snapshot",)

    def __init__(self, snapshot: str | Path) -> None:
        self._snapshot = Path(snapshot).absolute()

    def load_authority(self, source_case: Case) -> M6M4ModelCallAuthoritySnapshot:
        if not isinstance(source_case, Case):
            raise M6HearingModelCallAuthorityError(
                M6HearingModelCallAuthorityErrorCode.INVALID_ARGUMENT
            )
        try:
            controlled_case = Case.model_validate(
                source_case.model_dump(mode="json", exclude_computed_fields=True)
            )
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise M6HearingModelCallAuthorityError(
                M6HearingModelCallAuthorityErrorCode.SOURCE_CASE_INVALID
            ) from None
        if controlled_case != source_case:
            raise M6HearingModelCallAuthorityError(
                M6HearingModelCallAuthorityErrorCode.SOURCE_CASE_INVALID
            )
        try:
            before = capture_m6_readonly_snapshot_identity(self._snapshot)
            m4 = ReadonlyM4ArtifactRepository(
                self._snapshot,
                immutable=True,
            ).scan_replay_authority(controlled_case.run_id)
            after = capture_m6_readonly_snapshot_identity(self._snapshot)
        except ReadOnlySnapshotError:
            raise _invalid_snapshot() from None
        if after != before:
            raise _invalid_snapshot()

        def case_documents(
            kind: M4ProjectionArtifactKind,
        ) -> tuple[M4ValidatedReplayDocument[Any], ...]:
            return tuple(
                item
                for item in m4.documents_of_kind(kind)
                if getattr(item.document, "case_id", None) == controlled_case.case_id
            )

        request_rows = case_documents(M4ProjectionArtifactKind.MODEL_REQUEST)
        response_rows = case_documents(M4ProjectionArtifactKind.MODEL_RESPONSE)
        cache_rows = case_documents(M4ProjectionArtifactKind.MODEL_CACHE_ENTRY)
        usage_rows = case_documents(M4ProjectionArtifactKind.USAGE_RECEIPT)
        parse_rows = case_documents(M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT)
        output_rows = case_documents(M4ProjectionArtifactKind.ROLE_OUTPUT)
        failure_rows = case_documents(M4ProjectionArtifactKind.MODEL_CALL_FAILURE_AUTHORITY)
        typed_groups = (
            (request_rows, HearingModelRequest),
            (response_rows, HearingModelResponse),
            (cache_rows, HearingModelCacheEntry),
            (usage_rows, HearingUsageReceipt),
            (parse_rows, HearingModelParseReceipt),
            (output_rows, HearingRoleOutput),
            (failure_rows, HearingModelCallFailureAuthority),
        )
        if any(
            not isinstance(row.document, expected_type)
            for rows, expected_type in typed_groups
            for row in rows
        ):
            raise _invalid_snapshot()

        requests = tuple(
            M6M4ModelRequestAuthorityDocument(
                request=row.document,
                document_sha256=row.document_sha256,
            )
            for row in request_rows
            if isinstance(row.document, HearingModelRequest)
        )
        responses = tuple(
            M6M4ModelResponseAuthorityDocument(
                response=row.document,
                document_sha256=row.document_sha256,
            )
            for row in response_rows
            if isinstance(row.document, HearingModelResponse)
        )
        caches = tuple(
            M6M4ModelCacheAuthorityDocument(
                entry=row.document,
                document_sha256=row.document_sha256,
            )
            for row in cache_rows
            if isinstance(row.document, HearingModelCacheEntry)
        )
        usages = tuple(
            M6M4ModelUsageAuthorityDocument(
                receipt=row.document,
                document_sha256=row.document_sha256,
            )
            for row in usage_rows
            if isinstance(row.document, HearingUsageReceipt)
        )
        parse_receipts = tuple(
            M6M4ModelParseReceiptAuthorityDocument(
                receipt=row.document,
                document_sha256=row.document_sha256,
            )
            for row in parse_rows
            if isinstance(row.document, HearingModelParseReceipt)
        )
        role_outputs = tuple(
            M6M4RoleOutputAuthorityDocument(
                output=row.document,
                document_sha256=row.document_sha256,
            )
            for row in output_rows
            if isinstance(row.document, HearingRoleOutput)
        )
        failures = tuple(
            M6M4ModelCallFailureAuthorityDocument(
                authority=row.document,
                document_sha256=row.document_sha256,
            )
            for row in failure_rows
            if isinstance(row.document, HearingModelCallFailureAuthority)
        )
        call_root = derive_m6_hearing_model_call_authority_root(
            source_identity_sha256=before.identity_sha256,
            run_id=controlled_case.run_id,
            case_id=controlled_case.case_id,
            manifest_id=controlled_case.manifest_id,
            m4_replay_authority_root_sha256=m4.authority_root_sha256,
            requests=requests,
            responses=responses,
            caches=caches,
            usages=usages,
            parse_receipts=parse_receipts,
            role_outputs=role_outputs,
            failures=failures,
        )
        return M6M4ModelCallAuthoritySnapshot(
            source_identity_sha256=before.identity_sha256,
            m4_replay_authority_root_sha256=m4.authority_root_sha256,
            model_call_authority_root_sha256=call_root,
            run_id=controlled_case.run_id,
            case_id=controlled_case.case_id,
            manifest_id=controlled_case.manifest_id,
            requests=requests,
            responses=responses,
            caches=caches,
            usages=usages,
            parse_receipts=parse_receipts,
            role_outputs=role_outputs,
            failures=failures,
        )

    def assemble(self, source_case: Case) -> tuple[M6LockedModelCallInput, ...]:
        return assemble_m6_locked_hearing_model_calls(
            source_case=source_case,
            snapshot=self.load_authority(source_case),
        )

    def resolve(self, source_case: Case) -> tuple[M6ResolvedModelResponse, ...]:
        return resolve_m6_locked_hearing_model_responses(self.assemble(source_case))


__all__ = [
    "ReadonlyM6HearingModelCallAuthorityRepository",
]

"""Build one immutable publication V2 from a CLOSED-policy report bundle."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from pydantic import ValidationError

from labcourt.application.m6_replay_locked_closed_policy_regression import (
    M6ReplayLockedClosedPolicyRegressionAssemblyError,
    M6ReplayLockedClosedPolicyRegressionReportBundle,
    assemble_m6_replay_locked_closed_policy_regression_report,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_replay_locked_closed_policy_publication import (
    M6ReplayLockedClosedPolicyPublicationDocumentEntry,
    M6ReplayLockedClosedPolicyPublicationDocumentKind,
    M6ReplayLockedClosedPolicyPublicationSealAuthorityV2,
)
from labcourt.exceptions import LabCourtError


class M6ReplayLockedClosedPolicyPublicationBuildErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    REPORT_BUNDLE_INVALID = "REPORT_BUNDLE_INVALID"
    PUBLICATION_INVARIANT_VIOLATION = "PUBLICATION_INVARIANT_VIOLATION"


class M6ReplayLockedClosedPolicyPublicationBuildError(LabCourtError):
    def __init__(
        self,
        code: M6ReplayLockedClosedPolicyPublicationBuildErrorCode,
    ) -> None:
        if not isinstance(code, M6ReplayLockedClosedPolicyPublicationBuildErrorCode):
            raise TypeError("code must be an M6ReplayLockedClosedPolicyPublicationBuildErrorCode")
        self.code = code
        super().__init__(f"M6 CLOSED-policy publication build failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6ReplayLockedClosedPolicyPublicationBundle:
    report_bundle: M6ReplayLockedClosedPolicyRegressionReportBundle
    seal: M6ReplayLockedClosedPolicyPublicationSealAuthorityV2
    seal_document: str

    def document_for(
        self,
        kind: M6ReplayLockedClosedPolicyPublicationDocumentKind,
    ) -> str:
        if type(kind) is not M6ReplayLockedClosedPolicyPublicationDocumentKind:
            raise TypeError("kind must be an M6ReplayLockedClosedPolicyPublicationDocumentKind")
        if kind == M6ReplayLockedClosedPolicyPublicationDocumentKind.COMMAND:
            return self.report_bundle.command_document
        if kind == M6ReplayLockedClosedPolicyPublicationDocumentKind.EVALUATOR_DATASET:
            return self.report_bundle.evaluator_dataset_document
        if kind == M6ReplayLockedClosedPolicyPublicationDocumentKind.CLOSED_POLICY_EXECUTION_SEAL:
            return self.report_bundle.execution_seal_document
        if kind == M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT:
            return self.report_bundle.report_document
        raise TypeError("kind must be an M6ReplayLockedClosedPolicyPublicationDocumentKind")


def _fail(code: M6ReplayLockedClosedPolicyPublicationBuildErrorCode) -> NoReturn:
    raise M6ReplayLockedClosedPolicyPublicationBuildError(code)


def _sha256(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def build_m6_replay_locked_closed_policy_publication_bundle(
    report_bundle: object,
) -> M6ReplayLockedClosedPolicyPublicationBundle:
    if type(report_bundle) is not M6ReplayLockedClosedPolicyRegressionReportBundle:
        _fail(M6ReplayLockedClosedPolicyPublicationBuildErrorCode.INVALID_ARGUMENT)
    assert isinstance(report_bundle, M6ReplayLockedClosedPolicyRegressionReportBundle)
    try:
        rebuilt = assemble_m6_replay_locked_closed_policy_regression_report(
            stored_source_catalog=report_bundle.stored_source_catalog,
            evaluator_dataset=report_bundle.evaluator_dataset,
            evaluator_dataset_document=report_bundle.evaluator_dataset_document,
            execution_seal=report_bundle.execution_seal,
            execution_seal_document=report_bundle.execution_seal_document,
        )
    except M6ReplayLockedClosedPolicyRegressionAssemblyError as exc:
        raise M6ReplayLockedClosedPolicyPublicationBuildError(
            M6ReplayLockedClosedPolicyPublicationBuildErrorCode.REPORT_BUNDLE_INVALID
        ) from exc
    if rebuilt != report_bundle:
        _fail(M6ReplayLockedClosedPolicyPublicationBuildErrorCode.REPORT_BUNDLE_INVALID)

    seal_execution = rebuilt.execution_seal
    scope = seal_execution.execution_scope
    catalog = rebuilt.stored_source_catalog
    documents = {
        M6ReplayLockedClosedPolicyPublicationDocumentKind.COMMAND: (
            scope.command_id,
            rebuilt.command_document,
        ),
        M6ReplayLockedClosedPolicyPublicationDocumentKind.EVALUATOR_DATASET: (
            rebuilt.evaluator_dataset.dataset_snapshot_id,
            rebuilt.evaluator_dataset_document,
        ),
        M6ReplayLockedClosedPolicyPublicationDocumentKind.CLOSED_POLICY_EXECUTION_SEAL: (
            seal_execution.execution_seal_authority_id,
            rebuilt.execution_seal_document,
        ),
        M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT: (
            rebuilt.report.report_id,
            rebuilt.report_document,
        ),
    }
    entries = tuple(
        sorted(
            (
                M6ReplayLockedClosedPolicyPublicationDocumentEntry(
                    kind=kind,
                    artifact_id=artifact_id,
                    content_sha256=_sha256(document),
                    size_bytes=len(document.encode("utf-8")),
                )
                for kind, (artifact_id, document) in documents.items()
            ),
            key=lambda item: item.sort_key,
        )
    )
    try:
        seal = M6ReplayLockedClosedPolicyPublicationSealAuthorityV2(
            candidate_run_id=scope.candidate_run_id,
            candidate_manifest_id=scope.candidate_manifest_id,
            source_catalog_authority_id=(catalog.source_catalog.source_catalog_authority_id),
            source_catalog_document_sha256=catalog.content_sha256,
            command_id=scope.command_id,
            execution_dataset_snapshot_id=scope.execution_dataset_snapshot_id,
            evaluator_dataset_snapshot_id=rebuilt.evaluator_dataset.dataset_snapshot_id,
            closed_policy_execution_seal_authority_id=(seal_execution.execution_seal_authority_id),
            report_id=rebuilt.report.report_id,
            entries=entries,
        )
        seal_document = canonical_json(seal.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError, ValidationError) as exc:
        raise M6ReplayLockedClosedPolicyPublicationBuildError(
            M6ReplayLockedClosedPolicyPublicationBuildErrorCode.PUBLICATION_INVARIANT_VIOLATION
        ) from exc
    return M6ReplayLockedClosedPolicyPublicationBundle(
        report_bundle=rebuilt,
        seal=seal,
        seal_document=seal_document,
    )


__all__ = [
    "M6ReplayLockedClosedPolicyPublicationBuildError",
    "M6ReplayLockedClosedPolicyPublicationBuildErrorCode",
    "M6ReplayLockedClosedPolicyPublicationBundle",
    "build_m6_replay_locked_closed_policy_publication_bundle",
]

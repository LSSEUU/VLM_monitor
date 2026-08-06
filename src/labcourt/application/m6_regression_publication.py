"""Build one exact, immutable M6 regression publication bundle."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from pydantic import ValidationError

from labcourt.application.m6_upgrade_regression import (
    M6UpgradeRegressionAssemblyError,
    M6UpgradeRegressionReportBundle,
    assemble_m6_upgrade_regression_report,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression_publication import (
    M6RegressionPublicationDocumentEntry,
    M6RegressionPublicationDocumentKind,
    M6RegressionPublicationSeal,
)
from labcourt.exceptions import LabCourtError


class M6RegressionPublicationBuildErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    REPORT_BUNDLE_INVALID = "REPORT_BUNDLE_INVALID"
    PUBLICATION_INVARIANT_VIOLATION = "PUBLICATION_INVARIANT_VIOLATION"


class M6RegressionPublicationBuildError(LabCourtError):
    def __init__(self, code: M6RegressionPublicationBuildErrorCode) -> None:
        if not isinstance(code, M6RegressionPublicationBuildErrorCode):
            raise TypeError("code must be an M6RegressionPublicationBuildErrorCode")
        self.code = code
        super().__init__(f"M6 regression publication build failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6RegressionPublicationBundle:
    report_bundle: M6UpgradeRegressionReportBundle
    seal: M6RegressionPublicationSeal
    seal_document: str

    def document_for(self, kind: M6RegressionPublicationDocumentKind) -> str:
        if kind == M6RegressionPublicationDocumentKind.COMMAND:
            return self.report_bundle.command_document
        if kind == M6RegressionPublicationDocumentKind.EVALUATOR_DATASET:
            return self.report_bundle.dataset_document
        if kind == M6RegressionPublicationDocumentKind.CANDIDATE_OUTPUT_INVENTORY:
            return self.report_bundle.candidate_output_inventory_document
        if kind == M6RegressionPublicationDocumentKind.REGRESSION_REPORT:
            return self.report_bundle.report_document
        raise TypeError("kind must be an M6RegressionPublicationDocumentKind")


def _fail(code: M6RegressionPublicationBuildErrorCode) -> NoReturn:
    raise M6RegressionPublicationBuildError(code)


def _sha256(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def build_m6_regression_publication_bundle(
    report_bundle: object,
) -> M6RegressionPublicationBundle:
    if not isinstance(report_bundle, M6UpgradeRegressionReportBundle):
        _fail(M6RegressionPublicationBuildErrorCode.INVALID_ARGUMENT)
    try:
        rebuilt = assemble_m6_upgrade_regression_report(
            command=report_bundle.report.command,
            command_document=report_bundle.command_document,
            dataset=report_bundle.report.dataset,
            dataset_document=report_bundle.dataset_document,
            candidate_output_inventory=report_bundle.candidate_output_inventory,
            candidate_output_inventory_document=(report_bundle.candidate_output_inventory_document),
        )
    except M6UpgradeRegressionAssemblyError as exc:
        raise M6RegressionPublicationBuildError(
            M6RegressionPublicationBuildErrorCode.REPORT_BUNDLE_INVALID
        ) from exc
    if rebuilt != report_bundle:
        _fail(M6RegressionPublicationBuildErrorCode.REPORT_BUNDLE_INVALID)

    outputs = report_bundle.candidate_output_inventory
    run_cut = outputs.candidate_run_cut
    documents = {
        M6RegressionPublicationDocumentKind.COMMAND: (
            report_bundle.report.command.command_id,
            report_bundle.command_document,
        ),
        M6RegressionPublicationDocumentKind.EVALUATOR_DATASET: (
            report_bundle.report.dataset.dataset_snapshot_id,
            report_bundle.dataset_document,
        ),
        M6RegressionPublicationDocumentKind.CANDIDATE_OUTPUT_INVENTORY: (
            outputs.candidate_output_inventory_authority_id,
            report_bundle.candidate_output_inventory_document,
        ),
        M6RegressionPublicationDocumentKind.REGRESSION_REPORT: (
            report_bundle.report.report_id,
            report_bundle.report_document,
        ),
    }
    entries = tuple(
        sorted(
            (
                M6RegressionPublicationDocumentEntry(
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
        seal = M6RegressionPublicationSeal(
            candidate_run_id=run_cut.candidate_run_id,
            candidate_manifest_id=run_cut.candidate_manifest.manifest_id,
            candidate_run_cut_authority_id=run_cut.candidate_run_cut_authority_id,
            command_id=report_bundle.report.command.command_id,
            execution_dataset_snapshot_id=(
                report_bundle.report.dataset.execution_dataset.execution_dataset_snapshot_id
            ),
            evaluator_dataset_snapshot_id=report_bundle.report.dataset.dataset_snapshot_id,
            candidate_output_inventory_authority_id=(
                outputs.candidate_output_inventory_authority_id
            ),
            report_id=report_bundle.report.report_id,
            entries=entries,
        )
        seal_document = canonical_json(seal.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError, ValidationError) as exc:
        raise M6RegressionPublicationBuildError(
            M6RegressionPublicationBuildErrorCode.PUBLICATION_INVARIANT_VIOLATION
        ) from exc
    return M6RegressionPublicationBundle(
        report_bundle=report_bundle,
        seal=seal,
        seal_document=seal_document,
    )


__all__ = [
    "M6RegressionPublicationBuildError",
    "M6RegressionPublicationBuildErrorCode",
    "M6RegressionPublicationBundle",
    "build_m6_regression_publication_bundle",
]

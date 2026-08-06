from __future__ import annotations

import hashlib
from dataclasses import replace
from functools import lru_cache

import pytest

from labcourt.application.m6_regression_publication import (
    build_m6_regression_publication_bundle,
)
from labcourt.application.m6_replay_locked_closed_policy_publication import (
    M6ReplayLockedClosedPolicyPublicationBuildError,
    M6ReplayLockedClosedPolicyPublicationBuildErrorCode,
    M6ReplayLockedClosedPolicyPublicationBundle,
    build_m6_replay_locked_closed_policy_publication_bundle,
)
from labcourt.application.m6_upgrade_regression import (
    assemble_m6_upgrade_regression_report,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression_publication import (
    M6RegressionPublicationDocumentKind,
)
from labcourt.contracts.m6_replay_locked_closed_policy_publication import (
    M6ReplayLockedClosedPolicyPublicationDocumentKind,
)
from tests.unit.test_m6_replay_locked_closed_policy_regression import _assemble, _facts
from tests.unit.test_m6_upgrade_regression import _inputs


def _sha256(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


@lru_cache(maxsize=1)
def _report_bundle():  # type: ignore[no-untyped-def]
    return _assemble(_facts())


@lru_cache(maxsize=1)
def _publication():  # type: ignore[no-untyped-def]
    return build_m6_replay_locked_closed_policy_publication_bundle(_report_bundle())


def test_builder_accepts_only_the_previous_closed_policy_report_bundle() -> None:
    report_bundle = _report_bundle()

    publication = build_m6_replay_locked_closed_policy_publication_bundle(report_bundle)

    assert type(publication) is M6ReplayLockedClosedPolicyPublicationBundle
    assert publication.report_bundle == report_bundle
    assert publication.seal_document == canonical_json(publication.seal.model_dump(mode="json"))


def test_builder_maps_each_entry_to_the_exact_previous_bundle_document() -> None:
    publication = _publication()
    report_bundle = publication.report_bundle
    expected = {
        M6ReplayLockedClosedPolicyPublicationDocumentKind.COMMAND: (
            report_bundle.report.command.command_id,
            report_bundle.command_document,
        ),
        M6ReplayLockedClosedPolicyPublicationDocumentKind.EVALUATOR_DATASET: (
            report_bundle.evaluator_dataset.dataset_snapshot_id,
            report_bundle.evaluator_dataset_document,
        ),
        M6ReplayLockedClosedPolicyPublicationDocumentKind.CLOSED_POLICY_EXECUTION_SEAL: (
            report_bundle.execution_seal.execution_seal_authority_id,
            report_bundle.execution_seal_document,
        ),
        M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT: (
            report_bundle.report.report_id,
            report_bundle.report_document,
        ),
    }

    assert len(publication.seal.entries) == len(expected)
    for entry in publication.seal.entries:
        artifact_id, document = expected[entry.kind]
        assert entry.artifact_id == artifact_id
        assert entry.content_sha256 == _sha256(document)
        assert entry.size_bytes == len(document.encode("utf-8"))
        assert publication.document_for(entry.kind) == document


def test_builder_is_exactly_retryable() -> None:
    report_bundle = _report_bundle()

    assert build_m6_replay_locked_closed_policy_publication_bundle(
        report_bundle
    ) == build_m6_replay_locked_closed_policy_publication_bundle(report_bundle)


@pytest.mark.parametrize("value", [None, {}, object()])
def test_builder_rejects_untyped_inputs(value: object) -> None:
    with pytest.raises(M6ReplayLockedClosedPolicyPublicationBuildError) as raised:
        build_m6_replay_locked_closed_policy_publication_bundle(value)

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyPublicationBuildErrorCode.INVALID_ARGUMENT
    )
    assert not hasattr(raised.value, "report_bundle")


def test_builder_rejects_the_legacy_v1_report_publication_path() -> None:
    legacy_report = assemble_m6_upgrade_regression_report(**_inputs())
    legacy_publication = build_m6_regression_publication_bundle(legacy_report)

    with pytest.raises(M6ReplayLockedClosedPolicyPublicationBuildError) as report:
        build_m6_replay_locked_closed_policy_publication_bundle(legacy_report)
    assert report.value.code is (
        M6ReplayLockedClosedPolicyPublicationBuildErrorCode.INVALID_ARGUMENT
    )

    with pytest.raises(M6ReplayLockedClosedPolicyPublicationBuildError) as publication:
        build_m6_replay_locked_closed_policy_publication_bundle(legacy_publication)
    assert publication.value.code is (
        M6ReplayLockedClosedPolicyPublicationBuildErrorCode.INVALID_ARGUMENT
    )


@pytest.mark.parametrize(
    "field",
    [
        "report_document",
        "command_document",
        "evaluator_dataset_document",
        "execution_seal_document",
    ],
)
def test_builder_rebuild_rejects_tampered_canonical_documents(field: str) -> None:
    report_bundle = _report_bundle()
    forged = replace(report_bundle, **{field: getattr(report_bundle, field) + " "})

    with pytest.raises(M6ReplayLockedClosedPolicyPublicationBuildError) as raised:
        build_m6_replay_locked_closed_policy_publication_bundle(forged)

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyPublicationBuildErrorCode.REPORT_BUNDLE_INVALID
    )


@pytest.mark.parametrize(
    "field",
    [
        "report_content_sha256",
        "command_content_sha256",
        "evaluator_dataset_content_sha256",
        "execution_seal_content_sha256",
    ],
)
def test_builder_rebuild_rejects_tampered_physical_hashes(field: str) -> None:
    forged = replace(_report_bundle(), **{field: "0" * 64})

    with pytest.raises(M6ReplayLockedClosedPolicyPublicationBuildError) as raised:
        build_m6_replay_locked_closed_policy_publication_bundle(forged)

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyPublicationBuildErrorCode.REPORT_BUNDLE_INVALID
    )


@pytest.mark.parametrize("field", ["stored_source_catalog", "execution_seal"])
def test_builder_rebuild_rejects_untyped_nested_authorities(field: str) -> None:
    forged = replace(_report_bundle(), **{field: object()})

    with pytest.raises(M6ReplayLockedClosedPolicyPublicationBuildError) as raised:
        build_m6_replay_locked_closed_policy_publication_bundle(forged)

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyPublicationBuildErrorCode.REPORT_BUNDLE_INVALID
    )


@pytest.mark.parametrize(
    "kind",
    [
        "COMMAND",
        M6RegressionPublicationDocumentKind.COMMAND,
        object(),
    ],
)
def test_document_lookup_rejects_untyped_and_v1_kinds(kind: object) -> None:
    with pytest.raises(TypeError, match="M6ReplayLockedClosedPolicyPublicationDocumentKind"):
        _publication().document_for(kind)  # type: ignore[arg-type]


def test_build_error_requires_a_typed_error_code() -> None:
    with pytest.raises(TypeError, match="BuildErrorCode"):
        M6ReplayLockedClosedPolicyPublicationBuildError("INVALID_ARGUMENT")  # type: ignore[arg-type]

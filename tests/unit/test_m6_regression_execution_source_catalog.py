from __future__ import annotations

import hashlib

import pytest

from labcourt.application.m6_regression_execution_source_catalog import (
    M6RegressionExecutionSourceCatalogBindingError,
    M6RegressionExecutionSourceCatalogBindingErrorCode,
    bind_m6_regression_execution_source_catalog,
)
from labcourt.application.m6_regression_source_catalog import (
    build_m6_regression_source_catalog,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import (
    M6RegressionExecutionDatasetSnapshot,
    M6RegressionExecutionEntry,
    M6RegressionRunCommand,
)
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionExecutionSourceCatalogAuthority,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionScopeAuthority,
)
from tests.integration.test_m6_upgrade_execution_ledger_repository import (
    _scope_and_no_case_records,
)
from tests.unit.test_m6_regression_source_catalog import _sealed_source


def _identity(value: object) -> tuple[str, int]:
    document = canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]
    payload = document.encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _catalog(
    sample_seed: str = "opaque-sample",
):  # type: ignore[no-untyped-def]
    scope, source = _sealed_source(sample_seed)
    return build_m6_regression_source_catalog(
        run_scopes=(scope,),
        sealed_sources=(source,),
    )


def _execution_dataset(
    catalog: M6RegressionExecutionSourceCatalogAuthority,
    document_sha256: str,
) -> M6RegressionExecutionDatasetSnapshot:
    entries = tuple(
        M6RegressionExecutionEntry(
            sample_id=item.sample_id,
            input_authority_id=item.input_authority_id,
            input_authority_document_sha256=(item.input_authority_document_sha256),
            replay_input_closure_authority_id=(
                item.replay_input_closure.replay_input_closure_authority_id
            ),
            replay_input_closure_document_sha256=(
                item.replay_input_closure.replay_input_closure_document_sha256
            ),
        )
        for item in catalog.entries
    )
    return M6RegressionExecutionDatasetSnapshot(
        baseline_manifest_id=catalog.baseline_manifest_id,
        source_catalog_authority_id=catalog.source_catalog_authority_id,
        source_catalog_document_sha256=document_sha256,
        entries=entries,
    )


def _execution_scope(
    catalog: M6RegressionExecutionSourceCatalogAuthority,
    document_sha256: str,
    *,
    entries: tuple[M6RegressionExecutionEntry, ...] | None = None,
) -> M6UpgradeExecutionScopeAuthority:
    template, _ = _scope_and_no_case_records()
    dataset = _execution_dataset(catalog, document_sha256)
    if entries is not None:
        dataset = M6RegressionExecutionDatasetSnapshot(
            baseline_manifest_id=dataset.baseline_manifest_id,
            source_catalog_authority_id=dataset.source_catalog_authority_id,
            source_catalog_document_sha256=dataset.source_catalog_document_sha256,
            entries=entries,
        )
    command = M6RegressionRunCommand(
        mode=template.command.mode,
        execution_dataset_snapshot_id=dataset.execution_dataset_snapshot_id,
        baseline_manifest_id=dataset.baseline_manifest_id,
        candidate_manifest_id=template.candidate_manifest.manifest_id,
        policy_authority=template.command.policy_authority,
    )
    command_sha256, command_size = _identity(command)
    dataset_sha256, dataset_size = _identity(dataset)
    return M6UpgradeExecutionScopeAuthority(
        candidate_run_id=template.candidate_run_id,
        command=command,
        command_content_sha256=command_sha256,
        command_size_bytes=command_size,
        execution_dataset=dataset,
        execution_dataset_content_sha256=dataset_sha256,
        execution_dataset_size_bytes=dataset_size,
        candidate_manifest=template.candidate_manifest,
        candidate_manifest_content_sha256=template.candidate_manifest_content_sha256,
        candidate_manifest_size_bytes=template.candidate_manifest_size_bytes,
        candidate_config=template.candidate_config,
        candidate_config_content_sha256=template.candidate_config_content_sha256,
        candidate_config_size_bytes=template.candidate_config_size_bytes,
        execution_component=template.execution_component,
        execution_component_content_sha256=template.execution_component_content_sha256,
        execution_component_size_bytes=template.execution_component_size_bytes,
        execution_start_audit_head_sequence=template.execution_start_audit_head_sequence,
        execution_start_audit_head_hash=template.execution_start_audit_head_hash,
    )


def test_binds_the_complete_catalog_to_the_durable_execution_scope() -> None:
    bundle = _catalog()
    scope = _execution_scope(
        bundle.execution_source_catalog,
        bundle.execution_source_catalog_content_sha256,
    )

    bound = bind_m6_regression_execution_source_catalog(
        execution_scope=scope,
        execution_source_catalog=bundle.execution_source_catalog,
        execution_source_catalog_document=bundle.execution_source_catalog_document,
    )

    assert bound.execution_scope_authority_id == scope.execution_scope_authority_id
    assert bound.execution_dataset_snapshot_id == (
        scope.execution_dataset.execution_dataset_snapshot_id
    )
    assert bound.execution_source_catalog == bundle.execution_source_catalog
    assert bound.execution_source_catalog_document == (bundle.execution_source_catalog_document)
    assert bound.execution_source_catalog_content_sha256 == (
        bundle.execution_source_catalog_content_sha256
    )


def test_rejects_noncanonical_or_hash_mismatched_catalog_document() -> None:
    bundle = _catalog()
    scope = _execution_scope(
        bundle.execution_source_catalog,
        bundle.execution_source_catalog_content_sha256,
    )

    with pytest.raises(M6RegressionExecutionSourceCatalogBindingError) as raised:
        bind_m6_regression_execution_source_catalog(
            execution_scope=scope,
            execution_source_catalog=bundle.execution_source_catalog,
            execution_source_catalog_document=(bundle.execution_source_catalog_document + " "),
        )

    assert raised.value.code == (
        M6RegressionExecutionSourceCatalogBindingErrorCode.DOCUMENT_INVALID
    )


def test_rejects_a_valid_catalog_from_another_blinded_source_cut() -> None:
    bundle = _catalog()
    foreign = _catalog("foreign-opaque-sample")
    scope = _execution_scope(
        bundle.execution_source_catalog,
        bundle.execution_source_catalog_content_sha256,
    )

    with pytest.raises(M6RegressionExecutionSourceCatalogBindingError) as raised:
        bind_m6_regression_execution_source_catalog(
            execution_scope=scope,
            execution_source_catalog=foreign.execution_source_catalog,
            execution_source_catalog_document=(foreign.execution_source_catalog_document),
        )

    assert raised.value.code == (
        M6RegressionExecutionSourceCatalogBindingErrorCode.SCOPE_BINDING_MISMATCH
    )


def test_rejects_per_entry_graft_even_when_catalog_ids_are_declared() -> None:
    bundle = _catalog()
    dataset = _execution_dataset(
        bundle.execution_source_catalog,
        bundle.execution_source_catalog_content_sha256,
    )
    grafted = dataset.entries[0].model_copy(update={"input_authority_document_sha256": "f" * 64})
    scope = _execution_scope(
        bundle.execution_source_catalog,
        bundle.execution_source_catalog_content_sha256,
        entries=(grafted,),
    )

    with pytest.raises(M6RegressionExecutionSourceCatalogBindingError) as raised:
        bind_m6_regression_execution_source_catalog(
            execution_scope=scope,
            execution_source_catalog=bundle.execution_source_catalog,
            execution_source_catalog_document=bundle.execution_source_catalog_document,
        )

    assert raised.value.code == (
        M6RegressionExecutionSourceCatalogBindingErrorCode.ENTRY_CLOSURE_MISMATCH
    )

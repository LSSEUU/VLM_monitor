from __future__ import annotations

import pytest

from labcourt.application.m6_regression_source_catalog import (
    build_m6_regression_source_catalog,
)
from labcourt.application.m6_replay_locked_execution_scope import (
    M6ReplayLockedExecutionScopeError,
    M6ReplayLockedExecutionScopeErrorCode,
    build_m6_replay_locked_execution_scope,
)
from labcourt.contracts.enums import ReproducibilityMode
from labcourt.contracts.m6_regression import (
    M6RegressionExecutionDatasetSnapshot,
    M6RegressionExecutionEntry,
    M6RegressionPolicyAuthority,
    M6RegressionRunCommand,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionComponentAuthority,
)
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)
from tests.unit.test_m6_regression_source_catalog import _sealed_source
from tests.unit.test_m6_source_authority import _bundle


def _inputs() -> dict[str, object]:
    run_scope, source = _sealed_source()
    catalog_bundle = build_m6_regression_source_catalog(
        run_scopes=(run_scope,),
        sealed_sources=(source,),
    )
    catalog = catalog_bundle.execution_source_catalog
    dataset = M6RegressionExecutionDatasetSnapshot(
        baseline_manifest_id=catalog.baseline_manifest_id,
        source_catalog_authority_id=catalog.source_catalog_authority_id,
        source_catalog_document_sha256=(catalog_bundle.execution_source_catalog_content_sha256),
        entries=tuple(
            M6RegressionExecutionEntry(
                sample_id=item.sample_id,
                input_authority_id=item.input_authority_id,
                input_authority_document_sha256=item.input_authority_document_sha256,
                replay_input_closure_authority_id=(
                    item.replay_input_closure.replay_input_closure_authority_id
                ),
                replay_input_closure_document_sha256=(
                    item.replay_input_closure.replay_input_closure_document_sha256
                ),
            )
            for item in catalog.entries
        ),
    )
    config = _bundle().config
    manifest = source.source_manifest
    command = M6RegressionRunCommand(
        mode=ReproducibilityMode.REPLAY_LOCKED,
        execution_dataset_snapshot_id=dataset.execution_dataset_snapshot_id,
        baseline_manifest_id=manifest.manifest_id,
        candidate_manifest_id=manifest.manifest_id,
        policy_authority=M6RegressionPolicyAuthority(
            config_sha256=config.config_sha256,
            policy_version="m6-replay-locked-m3-fast-v1",
            maximum_machine_flip_rate=0.05,
            gold_set_max_accuracy_drop=0.0,
        ),
    )
    stored = M6StoredRegressionExecutionSourceCatalog(
        source_catalog=catalog,
        canonical_document=catalog_bundle.execution_source_catalog_document,
        content_sha256=catalog_bundle.execution_source_catalog_content_sha256,
        size_bytes=len(catalog_bundle.execution_source_catalog_document.encode("utf-8")),
    )
    component = M6ReplayLockedExecutionComponentAuthority(
        version="0.1.0",
        code_commit=manifest.code_commit,
    )
    return {
        "candidate_run_id": "m6-locked-candidate-run",
        "command": command,
        "execution_dataset": dataset,
        "stored_source_catalog": stored,
        "locked_manifest": manifest,
        "locked_config": config,
        "execution_component": component,
    }


def test_builder_derives_exact_scope_without_caller_supplied_hashes_or_run_inventory() -> None:
    inputs = _inputs()

    scope = build_m6_replay_locked_execution_scope(**inputs)

    stored = inputs["stored_source_catalog"]
    assert isinstance(stored, M6StoredRegressionExecutionSourceCatalog)
    assert scope.source_catalog_content_sha256 == stored.content_sha256
    assert scope.source_catalog_size_bytes == stored.size_bytes
    assert scope.source_catalog_entry_ids == tuple(
        item.catalog_entry_id for item in stored.source_catalog.entries
    )
    assert scope.source_run_ids == tuple(
        sorted({item.replay_input_closure.source_run_id for item in stored.source_catalog.entries})
    )
    assert scope.candidate_run_id not in scope.source_run_ids
    assert scope.execution_start_audit_head_sequence == -1
    assert scope.execution_start_audit_head_hash == "0" * 64


def test_builder_rejects_candidate_run_reuse_before_scope_construction() -> None:
    inputs = _inputs()
    stored = inputs["stored_source_catalog"]
    assert isinstance(stored, M6StoredRegressionExecutionSourceCatalog)
    inputs["candidate_run_id"] = stored.source_catalog.entries[0].replay_input_closure.source_run_id

    with pytest.raises(M6ReplayLockedExecutionScopeError) as raised:
        build_m6_replay_locked_execution_scope(**inputs)

    assert raised.value.code == M6ReplayLockedExecutionScopeErrorCode.CANDIDATE_RUN_NOT_DISTINCT


@pytest.mark.parametrize("candidate_run_id", ["NUL", "CON.txt", "run."])
def test_builder_rejects_a_nonportable_candidate_run_id(candidate_run_id: str) -> None:
    inputs = _inputs()
    inputs["candidate_run_id"] = candidate_run_id

    with pytest.raises(M6ReplayLockedExecutionScopeError) as raised:
        build_m6_replay_locked_execution_scope(**inputs)

    assert raised.value.code == M6ReplayLockedExecutionScopeErrorCode.INVALID_ARGUMENT


def test_builder_rejects_catalog_dataset_graft() -> None:
    inputs = _inputs()
    dataset = inputs["execution_dataset"]
    assert isinstance(dataset, M6RegressionExecutionDatasetSnapshot)
    inputs["execution_dataset"] = dataset.model_copy(
        update={"source_catalog_document_sha256": "0" * 64}
    )

    with pytest.raises(M6ReplayLockedExecutionScopeError) as raised:
        build_m6_replay_locked_execution_scope(**inputs)

    assert raised.value.code == M6ReplayLockedExecutionScopeErrorCode.SOURCE_CATALOG_MISMATCH


def test_builder_rejects_non_locked_command_without_reinterpreting_scope() -> None:
    inputs = _inputs()
    command = inputs["command"]
    assert isinstance(command, M6RegressionRunCommand)
    inputs["command"] = command.model_copy(update={"mode": ReproducibilityMode.REINFER_PINNED})

    with pytest.raises(M6ReplayLockedExecutionScopeError) as raised:
        build_m6_replay_locked_execution_scope(**inputs)

    assert raised.value.code == M6ReplayLockedExecutionScopeErrorCode.SCOPE_REJECTED


def test_builder_rejects_noncanonical_stored_catalog() -> None:
    inputs = _inputs()
    inputs["stored_source_catalog"] = object()

    with pytest.raises(M6ReplayLockedExecutionScopeError) as raised:
        build_m6_replay_locked_execution_scope(**inputs)

    assert raised.value.code == M6ReplayLockedExecutionScopeErrorCode.INVALID_ARGUMENT

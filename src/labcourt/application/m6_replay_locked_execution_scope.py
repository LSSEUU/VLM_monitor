"""Build one exact candidate-blind M6 locked execution start cut."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m6_regression import (
    M6RegressionExecutionDatasetSnapshot,
    M6RegressionRunCommand,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionComponentAuthority,
    M6ReplayLockedExecutionScopeAuthority,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import require_portable_run_id
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6ReplayLockedExecutionScopeErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SOURCE_CATALOG_MISMATCH = "SOURCE_CATALOG_MISMATCH"
    EXECUTION_DATASET_MISMATCH = "EXECUTION_DATASET_MISMATCH"
    MANIFEST_CONFIG_MISMATCH = "MANIFEST_CONFIG_MISMATCH"
    CANDIDATE_RUN_NOT_DISTINCT = "CANDIDATE_RUN_NOT_DISTINCT"
    SCOPE_REJECTED = "SCOPE_REJECTED"


class M6ReplayLockedExecutionScopeError(LabCourtError):
    """Payload-free locked execution-scope construction failure."""

    def __init__(self, code: M6ReplayLockedExecutionScopeErrorCode) -> None:
        if not isinstance(code, M6ReplayLockedExecutionScopeErrorCode):
            raise TypeError("code must be an M6 locked execution-scope error code")
        self.code = code
        super().__init__(f"M6 locked execution scope failed: {code.value}")


def _fail(code: M6ReplayLockedExecutionScopeErrorCode) -> NoReturn:
    raise M6ReplayLockedExecutionScopeError(code)


def _canonical_model(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        _fail(M6ReplayLockedExecutionScopeErrorCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedExecutionScopeErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedExecutionScopeErrorCode.INVALID_ARGUMENT)
    return controlled


def _identity(value: BaseModel) -> tuple[str, int]:
    payload = canonical_json(value.model_dump(mode="json")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _require_catalog_dataset_bijection(
    stored: M6StoredRegressionExecutionSourceCatalog,
    dataset: M6RegressionExecutionDatasetSnapshot,
) -> tuple[str, ...]:
    catalog = stored.source_catalog
    if (
        catalog.source_catalog_authority_id != dataset.source_catalog_authority_id
        or stored.content_sha256 != dataset.source_catalog_document_sha256
        or catalog.baseline_manifest_id != dataset.baseline_manifest_id
        or catalog.entry_count != len(dataset.entries)
    ):
        _fail(M6ReplayLockedExecutionScopeErrorCode.SOURCE_CATALOG_MISMATCH)
    catalog_bindings = tuple(
        (
            item.sample_id,
            item.input_authority_id,
            item.input_authority_document_sha256,
            item.replay_input_closure.replay_input_closure_authority_id,
            item.replay_input_closure.replay_input_closure_document_sha256,
        )
        for item in catalog.entries
    )
    dataset_bindings = tuple(
        (
            item.sample_id,
            item.input_authority_id,
            item.input_authority_document_sha256,
            item.replay_input_closure_authority_id,
            item.replay_input_closure_document_sha256,
        )
        for item in dataset.entries
    )
    if catalog_bindings != dataset_bindings:
        _fail(M6ReplayLockedExecutionScopeErrorCode.EXECUTION_DATASET_MISMATCH)
    return tuple(sorted({item.replay_input_closure.source_run_id for item in catalog.entries}))


def build_m6_replay_locked_execution_scope(
    *,
    candidate_run_id: object,
    command: object,
    execution_dataset: object,
    stored_source_catalog: object,
    locked_manifest: object,
    locked_config: object,
    execution_component: object,
) -> M6ReplayLockedExecutionScopeAuthority:
    """Derive every physical identity from canonical durable inputs."""

    try:
        if not isinstance(candidate_run_id, str):
            raise TypeError
        run_id = require_portable_run_id(candidate_run_id, "M6 locked candidate run_id")
    except (TypeError, ValueError):
        _fail(M6ReplayLockedExecutionScopeErrorCode.INVALID_ARGUMENT)
    controlled_command = _canonical_model(command, M6RegressionRunCommand)
    dataset = _canonical_model(execution_dataset, M6RegressionExecutionDatasetSnapshot)
    manifest = _canonical_model(locked_manifest, RunManifest)
    config = _canonical_model(locked_config, AppConfig)
    component = _canonical_model(
        execution_component,
        M6ReplayLockedExecutionComponentAuthority,
    )
    if type(stored_source_catalog) is not M6StoredRegressionExecutionSourceCatalog:
        _fail(M6ReplayLockedExecutionScopeErrorCode.INVALID_ARGUMENT)
    try:
        stored = M6StoredRegressionExecutionSourceCatalog(
            source_catalog=stored_source_catalog.source_catalog,
            canonical_document=stored_source_catalog.canonical_document,
            content_sha256=stored_source_catalog.content_sha256,
            size_bytes=stored_source_catalog.size_bytes,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(M6ReplayLockedExecutionScopeErrorCode.INVALID_ARGUMENT)
    source_run_ids = _require_catalog_dataset_bijection(stored, dataset)
    source_catalog_entry_ids = tuple(
        item.catalog_entry_id for item in stored.source_catalog.entries
    )
    if run_id in source_run_ids:
        _fail(M6ReplayLockedExecutionScopeErrorCode.CANDIDATE_RUN_NOT_DISTINCT)
    if (
        controlled_command.execution_dataset_snapshot_id != dataset.execution_dataset_snapshot_id
        or controlled_command.baseline_manifest_id != dataset.baseline_manifest_id
    ):
        _fail(M6ReplayLockedExecutionScopeErrorCode.EXECUTION_DATASET_MISMATCH)
    if (
        controlled_command.candidate_manifest_id != manifest.manifest_id
        or controlled_command.policy_authority.config_sha256 != config.config_sha256
        or manifest.config_sha256 != config.config_sha256
        or component.code_commit != manifest.code_commit
    ):
        _fail(M6ReplayLockedExecutionScopeErrorCode.MANIFEST_CONFIG_MISMATCH)
    command_sha, command_size = _identity(controlled_command)
    dataset_sha, dataset_size = _identity(dataset)
    manifest_sha, manifest_size = _identity(manifest)
    config_sha, config_size = _identity(config)
    component_sha, component_size = _identity(component)
    try:
        return M6ReplayLockedExecutionScopeAuthority(
            candidate_run_id=run_id,
            command=controlled_command,
            command_content_sha256=command_sha,
            command_size_bytes=command_size,
            execution_dataset=dataset,
            execution_dataset_content_sha256=dataset_sha,
            execution_dataset_size_bytes=dataset_size,
            source_catalog_content_sha256=stored.content_sha256,
            source_catalog_size_bytes=stored.size_bytes,
            source_catalog_entry_count=stored.source_catalog.entry_count,
            source_catalog_entry_ids=source_catalog_entry_ids,
            source_run_ids=source_run_ids,
            locked_manifest=manifest,
            locked_manifest_content_sha256=manifest_sha,
            locked_manifest_size_bytes=manifest_size,
            locked_config=config,
            locked_config_content_sha256=config_sha,
            locked_config_size_bytes=config_size,
            execution_component=component,
            execution_component_content_sha256=component_sha,
            execution_component_size_bytes=component_size,
            execution_start_audit_head_sequence=-1,
            execution_start_audit_head_hash=AUDIT_GENESIS_HASH,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedExecutionScopeErrorCode.SCOPE_REJECTED)


__all__ = [
    "M6ReplayLockedExecutionScopeError",
    "M6ReplayLockedExecutionScopeErrorCode",
    "build_m6_replay_locked_execution_scope",
]

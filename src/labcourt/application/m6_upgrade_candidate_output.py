"""Pure construction of terminal M6 candidate outputs and Inventory V3."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import NoReturn, TypeVar, cast

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import M6CaseReplaySnapshot, M6ReplayExecutionOutcome
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateCaseDocumentRef,
    M6UpgradeCandidateModelCallAuthority,
    M6UpgradeCandidateOutputInventoryAuthorityV3,
    M6UpgradeCandidateRunCutAuthority,
    M6UpgradeCandidateSampleOutputAuthority,
)
from labcourt.contracts.m6_replay_locked import M6LockedModelCallLayer, M6LockedModelRole
from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES,
    M6UpgradeExecutionLedgerSeal,
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionRecord,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedModelCall,
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
)
from labcourt.ports.m6_upgrade_candidate_output import (
    M6UpgradeCandidateOutputError,
    M6UpgradeCandidateOutputFailureCode,
)
from labcourt.ports.m6_upgrade_model_physical import (
    M6ObservedModelCallPhysicalClosure,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)
_FailureCode = M6UpgradeCandidateOutputFailureCode

_MODEL_ARTIFACT_KINDS = frozenset(
    kind for kind in M6UpgradePhysicalArtifactKind if kind.value.startswith("MODEL_")
)
_DIRECT_GROUP_BY_KIND = {
    M6UpgradePhysicalArtifactKind.FRAME: "frames",
    M6UpgradePhysicalArtifactKind.DETECTION: "detections",
    M6UpgradePhysicalArtifactKind.EMBEDDING: "embeddings",
    M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE: "precedent_exposures",
    M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST: "tool_execution_manifests",
    M6UpgradePhysicalArtifactKind.TOOL_RESULT: "tool_results",
    M6UpgradePhysicalArtifactKind.EVIDENCE_PACK: "evidence_packs",
}
if set(_DIRECT_GROUP_BY_KIND) != set(M6UpgradePhysicalArtifactKind) - set(_MODEL_ARTIFACT_KINDS):
    raise RuntimeError("M6 terminal output groups must exhaust every non-model artifact kind")

_MODEL_COMPONENT_BY_ROLE = {
    M6LockedModelRole.SCREENING: "screening",
    M6LockedModelRole.PROSECUTOR: "prosecutor",
    M6LockedModelRole.DEFENDER: "defender",
    M6LockedModelRole.JUDGE: "judge",
}


def _fail(code: _FailureCode) -> NoReturn:
    raise M6UpgradeCandidateOutputError(code) from None


def _canonical_exact(
    value: object,
    expected: type[_ModelT],
    failure: _FailureCode = _FailureCode.INVALID_ARGUMENT,
) -> _ModelT:
    if type(value) is not expected:
        _fail(failure)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(failure)
    if controlled != value:
        _fail(failure)
    return controlled


def _canonical_closure(value: object) -> M6ObservedModelCallPhysicalClosure:
    if type(value) is not M6ObservedModelCallPhysicalClosure:
        _fail(_FailureCode.INVALID_ARGUMENT)
    closure = value
    try:
        controlled = replace(closure)
    except (AttributeError, TypeError, ValueError):
        _fail(_FailureCode.INVALID_ARGUMENT)
    if controlled != closure:
        _fail(_FailureCode.INVALID_ARGUMENT)
    return controlled


def _canonical_closures(
    values: object,
) -> tuple[M6ObservedModelCallPhysicalClosure, ...]:
    if type(values) is not tuple:
        _fail(_FailureCode.INVALID_ARGUMENT)
    closures = tuple(_canonical_closure(item) for item in cast(tuple[object, ...], values))
    sort_keys = tuple(item.sort_key for item in closures)
    if sort_keys != tuple(sorted(sort_keys)) or len(sort_keys) != len(set(sort_keys)):
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    return closures


def _document_identity(value: BaseModel) -> tuple[str, int]:
    payload = canonical_json(value.model_dump(mode="json")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _require_run_cut_scope(
    scope: M6UpgradeExecutionScopeAuthority,
    run_cut: M6UpgradeCandidateRunCutAuthority,
) -> None:
    if (
        run_cut.candidate_run_id != scope.candidate_run_id
        or run_cut.candidate_manifest != scope.candidate_manifest
        or run_cut.candidate_manifest_content_sha256 != scope.candidate_manifest_content_sha256
        or run_cut.candidate_config != scope.candidate_config
        or run_cut.candidate_config_content_sha256 != scope.candidate_config_content_sha256
        or run_cut.execution_component_manifest_id
        != scope.execution_component.component_authority_id
    ):
        _fail(_FailureCode.RUN_CUT_MISMATCH)


def _provider_profile_for(
    scope: M6UpgradeExecutionScopeAuthority,
    role: M6LockedModelRole,
) -> str:
    if role == M6LockedModelRole.SCREENING:
        return scope.candidate_config.screening.provider_profile
    if role == M6LockedModelRole.PROSECUTOR:
        return scope.candidate_config.hearing.prosecutor_profile
    if role == M6LockedModelRole.DEFENDER:
        return scope.candidate_config.hearing.defender_profile
    return scope.candidate_config.hearing.judge_profile


def build_m6_upgrade_candidate_model_call(
    *,
    sample_id: str,
    observed_call: M6UpgradeObservedModelCall,
    physical_closure: M6ObservedModelCallPhysicalClosure,
) -> M6UpgradeCandidateModelCallAuthority:
    """Combine one trusted runtime observation with one verified physical closure."""

    if not isinstance(sample_id, str):
        _fail(_FailureCode.INVALID_ARGUMENT)
    observed = _canonical_exact(observed_call, M6UpgradeObservedModelCall)
    closure = _canonical_closure(physical_closure)
    if (
        closure.request_ref.artifact_id != observed.request_id
        or closure.layer != observed.layer
        or closure.role != observed.role
        or closure.attempt_index != observed.attempt_index
        or closure.result_kind != observed.result_kind
    ):
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    try:
        authority = M6UpgradeCandidateModelCallAuthority(
            sample_id=sample_id,
            layer=closure.layer,
            role=closure.role,
            attempt_index=closure.attempt_index,
            timeout_ms=closure.timeout_ms,
            execution_model_manifest_id=closure.execution_model_manifest_id,
            provider_invoked=observed.provider_invoked,
            request_ref=closure.request_ref,
            cache_ref=closure.cache_ref,
            result_kind=closure.result_kind,
            response_ref=closure.response_ref,
            parse_receipt_ref=closure.parse_receipt_ref,
            parsed_output_ref=closure.parsed_output_ref,
            failure_ref=closure.failure_ref,
            usage_receipt_ref=closure.usage_receipt_ref,
        )
        controlled = M6UpgradeCandidateModelCallAuthority.model_validate(
            authority.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    if controlled != authority:
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    return authority


def _require_sample_scope(
    scope: M6UpgradeExecutionScopeAuthority,
    record: M6UpgradeSampleExecutionRecordV2,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
) -> None:
    entries = scope.execution_dataset.entries
    if (
        record.ledger_sequence >= len(entries)
        or record.execution_scope_authority_id != scope.execution_scope_authority_id
        or record.candidate_run_id != scope.candidate_run_id
        or record.command_id != scope.command.command_id
        or record.execution_dataset_snapshot_id
        != scope.execution_dataset.execution_dataset_snapshot_id
        or record.execution_entry != entries[record.ledger_sequence]
    ):
        _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)
    if (
        observation.execution_scope_authority_id != scope.execution_scope_authority_id
        or observation.candidate_run_id != scope.candidate_run_id
        or observation.command_id != scope.command.command_id
        or observation.execution_dataset_snapshot_id
        != scope.execution_dataset.execution_dataset_snapshot_id
        or observation.execution_entry != record.execution_entry
        or observation.ledger_sequence != record.ledger_sequence
        or observation.observation_authority_id != record.observation_authority_id
        or observation.outcome != record.outcome
        or observation.candidate_case != record.candidate_case
    ):
        _fail(_FailureCode.OBSERVATION_CLOSURE_MISMATCH)


def _canonical_snapshot(
    value: object,
) -> M6CaseReplaySnapshot | None:
    if value is None:
        return None
    return _canonical_exact(value, M6CaseReplaySnapshot)


def _require_snapshot_binding(
    scope: M6UpgradeExecutionScopeAuthority,
    record: M6UpgradeSampleExecutionRecordV2,
    snapshot: M6CaseReplaySnapshot | None,
) -> None:
    case = record.candidate_case
    if (snapshot is not None) != (record.outcome == M6ReplayExecutionOutcome.CASE_REPLAYED):
        _fail(_FailureCode.CASE_BINDING_MISMATCH)
    if (snapshot is None) != (case is None):
        _fail(_FailureCode.CASE_BINDING_MISMATCH)
    if (
        snapshot is not None
        and case is not None
        and (
            snapshot.sample_id != record.sample_id
            or snapshot.source_run_id != scope.candidate_run_id
            or snapshot.source_case_id != case.case_id
            or snapshot.source_case_revision != case.case_revision
            or snapshot.source_case_document_sha256 != case.case_document_sha256
            or snapshot.manifest_id != scope.candidate_manifest.manifest_id
        )
    ):
        _fail(_FailureCode.CASE_BINDING_MISMATCH)


def _require_model_scope(
    scope: M6UpgradeExecutionScopeAuthority,
    record: M6UpgradeSampleExecutionRecordV2,
    closures: tuple[M6ObservedModelCallPhysicalClosure, ...],
) -> None:
    case = record.candidate_case
    if closures and case is None:
        _fail(_FailureCode.CASE_BINDING_MISMATCH)
    source_identities_by_layer = {
        layer: {item.source_identity_sha256 for item in closures if item.layer == layer}
        for layer in M6LockedModelCallLayer
    }
    if any(len(values) > 1 for values in source_identities_by_layer.values()):
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    for closure in closures:
        if case is None or closure.case_id != case.case_id:
            _fail(_FailureCode.CASE_BINDING_MISMATCH)
        profile_name = _provider_profile_for(scope, closure.role)
        if (
            closure.run_id != scope.candidate_run_id
            or closure.manifest_id != scope.candidate_manifest.manifest_id
            or closure.execution_model_manifest_id
            != scope.candidate_manifest.models[
                _MODEL_COMPONENT_BY_ROLE[closure.role]
            ].model_manifest_id
            or closure.timeout_ms
            > int(scope.candidate_config.providers[profile_name].timeout_seconds * 1_000)
        ):
            _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)


def _require_artifact_closure(
    record: M6UpgradeSampleExecutionRecordV2,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    observed_calls: tuple[M6UpgradeObservedModelCall, ...],
    closures: tuple[M6ObservedModelCallPhysicalClosure, ...],
) -> None:
    ordinary_links = tuple(
        link for link in record.artifact_links if link.artifact.kind not in _MODEL_ARTIFACT_KINDS
    )
    observed_artifacts = {item.identity_key: item.usage for item in observation.artifacts}
    linked_artifacts = {
        (link.artifact.source, link.artifact.kind, link.artifact.artifact_id): link.usage
        for link in ordinary_links
    }
    if len(linked_artifacts) != len(ordinary_links) or observed_artifacts != linked_artifacts:
        _fail(_FailureCode.OBSERVATION_CLOSURE_MISMATCH)

    model_links = tuple(
        link for link in record.artifact_links if link.artifact.kind in _MODEL_ARTIFACT_KINDS
    )
    closure_refs = tuple(ref for closure in closures for ref in closure.artifact_refs)
    closure_keys = tuple(ref.physical_key for ref in closure_refs)
    closure_ids = tuple(ref.artifact_ref_id for ref in closure_refs)
    if (
        len(closure_keys) != len(set(closure_keys))
        or len(closure_ids) != len(set(closure_ids))
        or {ref.physical_key: ref for ref in closure_refs}
        != {link.artifact.physical_key: link.artifact for link in model_links}
    ):
        _fail(_FailureCode.PHYSICAL_ARTIFACT_REJECTED)

    usage_by_ref_id = {link.artifact.artifact_ref_id: link.usage for link in model_links}
    for observed, closure in zip(observed_calls, closures, strict=True):
        cache = closure.cache_ref
        if cache is not None and usage_by_ref_id.get(cache.artifact_ref_id) != (
            M6UpgradeArtifactUsage.PRODUCED
            if observed.provider_invoked
            else M6UpgradeArtifactUsage.CONSUMED
        ):
            _fail(_FailureCode.PHYSICAL_ARTIFACT_REJECTED)


def build_m6_upgrade_candidate_sample_output(
    *,
    execution_scope: M6UpgradeExecutionScopeAuthority,
    run_cut: M6UpgradeCandidateRunCutAuthority,
    record: M6UpgradeSampleExecutionRecordV2,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    candidate_snapshot: M6CaseReplaySnapshot | None,
    model_call_closures: tuple[M6ObservedModelCallPhysicalClosure, ...],
) -> M6UpgradeCandidateSampleOutputAuthority:
    """Build one complete output from a sealed record and its exact observations."""

    scope = _canonical_exact(execution_scope, M6UpgradeExecutionScopeAuthority)
    cut = _canonical_exact(run_cut, M6UpgradeCandidateRunCutAuthority)
    if (
        isinstance(record, M6UpgradeSampleExecutionRecord)
        and type(record) is not M6UpgradeSampleExecutionRecordV2
    ):
        _fail(_FailureCode.LEDGER_VERSION_UNSUPPORTED)
    controlled_record = _canonical_exact(record, M6UpgradeSampleExecutionRecordV2)
    if (
        isinstance(observation, M6UpgradeSampleExecutionObservationAuthority)
        and type(observation) is not M6UpgradeSampleExecutionObservationAuthorityV2
    ):
        _fail(_FailureCode.LEDGER_VERSION_UNSUPPORTED)
    controlled_observation = _canonical_exact(
        observation,
        M6UpgradeSampleExecutionObservationAuthorityV2,
    )
    snapshot = _canonical_snapshot(candidate_snapshot)
    closures = _canonical_closures(model_call_closures)

    _require_run_cut_scope(scope, cut)
    _require_sample_scope(scope, controlled_record, controlled_observation)
    _require_snapshot_binding(scope, controlled_record, snapshot)
    _require_model_scope(scope, controlled_record, closures)

    observed_calls = controlled_observation.model_calls
    if len(observed_calls) != len(closures):
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    model_calls = tuple(
        build_m6_upgrade_candidate_model_call(
            sample_id=controlled_record.sample_id,
            observed_call=observed,
            physical_closure=closure,
        )
        for observed, closure in zip(observed_calls, closures, strict=True)
    )
    _require_artifact_closure(
        controlled_record,
        controlled_observation,
        observed_calls,
        closures,
    )

    direct_groups: dict[str, tuple[M6UpgradePhysicalArtifactRef, ...]] = {}
    for kind, field_name in _DIRECT_GROUP_BY_KIND.items():
        direct_groups[field_name] = tuple(
            link.artifact for link in controlled_record.artifact_links if link.artifact.kind == kind
        )
    try:
        authority = M6UpgradeCandidateSampleOutputAuthority(
            command_id=scope.command.command_id,
            execution_dataset_snapshot_id=(scope.execution_dataset.execution_dataset_snapshot_id),
            execution_entry=controlled_record.execution_entry,
            sample_execution_record_id=controlled_record.sample_execution_record_id,
            candidate_run_cut_authority_id=cut.candidate_run_cut_authority_id,
            candidate_run_id=scope.candidate_run_id,
            candidate_manifest_id=scope.candidate_manifest.manifest_id,
            execution_component_manifest_id=(scope.execution_component.component_authority_id),
            outcome=controlled_record.outcome,
            candidate_snapshot=snapshot,
            model_calls=model_calls,
            **direct_groups,
        )
        controlled = M6UpgradeCandidateSampleOutputAuthority.model_validate(
            authority.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)
    if controlled != authority:
        _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)
    _sha256, size = _document_identity(authority)
    if size > MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES:
        _fail(_FailureCode.DOCUMENT_TOO_LARGE)
    return authority


def _canonical_observations(
    values: object,
) -> tuple[M6UpgradeSampleExecutionObservationAuthorityV2, ...]:
    if type(values) is not tuple:
        _fail(_FailureCode.INVALID_ARGUMENT)
    observations: list[M6UpgradeSampleExecutionObservationAuthorityV2] = []
    for value in cast(tuple[object, ...], values):
        if (
            isinstance(value, M6UpgradeSampleExecutionObservationAuthority)
            and type(value) is not M6UpgradeSampleExecutionObservationAuthorityV2
        ):
            _fail(_FailureCode.LEDGER_VERSION_UNSUPPORTED)
        observations.append(_canonical_exact(value, M6UpgradeSampleExecutionObservationAuthorityV2))
    return tuple(observations)


def _canonical_snapshots(
    values: object,
) -> tuple[M6CaseReplaySnapshot | None, ...]:
    if type(values) is not tuple:
        _fail(_FailureCode.INVALID_ARGUMENT)
    return tuple(_canonical_snapshot(value) for value in cast(tuple[object, ...], values))


def _canonical_closure_groups(
    values: object,
) -> tuple[tuple[M6ObservedModelCallPhysicalClosure, ...], ...]:
    if type(values) is not tuple:
        _fail(_FailureCode.INVALID_ARGUMENT)
    return tuple(_canonical_closures(value) for value in cast(tuple[object, ...], values))


def build_m6_upgrade_candidate_output_inventory(
    *,
    execution_scope: M6UpgradeExecutionScopeAuthority,
    execution_ledger: M6UpgradeExecutionLedgerSealV2,
    run_cut: M6UpgradeCandidateRunCutAuthority,
    observations: tuple[M6UpgradeSampleExecutionObservationAuthorityV2, ...],
    candidate_snapshots: tuple[M6CaseReplaySnapshot | None, ...],
    model_call_closures: tuple[tuple[M6ObservedModelCallPhysicalClosure, ...], ...],
) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
    """Construct terminal Inventory V3 without accepting any derived claim."""

    scope = _canonical_exact(execution_scope, M6UpgradeExecutionScopeAuthority)
    if (
        isinstance(execution_ledger, M6UpgradeExecutionLedgerSeal)
        and type(execution_ledger) is not M6UpgradeExecutionLedgerSealV2
    ):
        _fail(_FailureCode.LEDGER_VERSION_UNSUPPORTED)
    ledger = _canonical_exact(execution_ledger, M6UpgradeExecutionLedgerSealV2)
    cut = _canonical_exact(run_cut, M6UpgradeCandidateRunCutAuthority)
    controlled_observations = _canonical_observations(observations)
    snapshots = _canonical_snapshots(candidate_snapshots)
    closure_groups = _canonical_closure_groups(model_call_closures)

    if ledger.execution_scope != scope:
        _fail(_FailureCode.RUN_CUT_MISMATCH)
    _require_run_cut_scope(scope, cut)
    if (
        ledger.candidate_run_id != cut.candidate_run_id
        or ledger.candidate_manifest_id != cut.candidate_manifest.manifest_id
        or ledger.candidate_manifest_content_sha256 != cut.candidate_manifest_content_sha256
        or ledger.candidate_config_sha256 != cut.candidate_config.config_sha256
        or ledger.candidate_config_content_sha256 != cut.candidate_config_content_sha256
        or ledger.execution_component.component_authority_id != cut.execution_component_manifest_id
        or ledger.source_audit_head_sequence != cut.audit_head_sequence
        or ledger.source_audit_head_hash != cut.audit_head_hash
        or cut.validation_report.counts.case_roots != ledger.candidate_case_count
    ):
        _fail(_FailureCode.RUN_CUT_MISMATCH)

    records = ledger.sample_executions
    expected_count = len(scope.execution_dataset.entries)
    if not (
        len(records)
        == len(controlled_observations)
        == len(snapshots)
        == len(closure_groups)
        == expected_count
    ):
        _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)
    outputs = tuple(
        build_m6_upgrade_candidate_sample_output(
            execution_scope=scope,
            run_cut=cut,
            record=record,
            observation=observation,
            candidate_snapshot=snapshot,
            model_call_closures=closures,
        )
        for record, observation, snapshot, closures in zip(
            records,
            controlled_observations,
            snapshots,
            closure_groups,
            strict=True,
        )
    )
    candidate_cases = tuple(
        sorted(
            (
                M6UpgradeCandidateCaseDocumentRef(
                    case_id=snapshot.source_case_id,
                    case_revision=snapshot.source_case_revision,
                    case_document_sha256=snapshot.source_case_document_sha256,
                )
                for snapshot in snapshots
                if snapshot is not None
            ),
            key=lambda item: item.sort_key,
        )
    )
    ledger_sha256, ledger_size = _document_identity(ledger)
    if ledger_size > MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES:
        _fail(_FailureCode.DOCUMENT_TOO_LARGE)
    try:
        inventory = M6UpgradeCandidateOutputInventoryAuthorityV3(
            command=scope.command,
            execution_dataset=scope.execution_dataset,
            candidate_run_cut=cut,
            execution_ledger=ledger,
            execution_ledger_content_sha256=ledger_sha256,
            execution_ledger_size_bytes=ledger_size,
            candidate_cases=candidate_cases,
            outputs=outputs,
            execution_observations=controlled_observations,
        )
        controlled = M6UpgradeCandidateOutputInventoryAuthorityV3.model_validate(
            inventory.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)
    if controlled != inventory:
        _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)
    _inventory_sha256, inventory_size = _document_identity(inventory)
    if inventory_size > MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES:
        _fail(_FailureCode.DOCUMENT_TOO_LARGE)
    return inventory


__all__ = [
    "build_m6_upgrade_candidate_model_call",
    "build_m6_upgrade_candidate_output_inventory",
    "build_m6_upgrade_candidate_sample_output",
]

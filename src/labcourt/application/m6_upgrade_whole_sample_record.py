"""Pure whole-sample composition for the M6 V2 upgrade ledger.

The storage adapter resolves physical authorities.  This module accepts only
the resulting typed references and closes them exactly against one durable
runtime observation before any record can be returned.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    MAX_M6_UPGRADE_LEDGER_LINKS,
    MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE,
    MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES,
    M6UpgradeCandidateCaseBinding,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleArtifactLink,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedModelCall,
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.contracts.m6_upgrade_physical import (
    MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES,
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.ports.m6_upgrade_model_physical import M6PlannedModelCallPhysicalClosure
from labcourt.ports.m6_upgrade_whole_sample_record_builder import (
    M6UpgradeWholeSampleRecordBuilderError,
    M6UpgradeWholeSampleRecordBuilderFailureCode,
)

_ArtifactIdentity = tuple[
    M6UpgradePhysicalArtifactSource,
    M6UpgradePhysicalArtifactKind,
    str,
]
_ArtifactRoute = tuple[
    M6UpgradePhysicalArtifactSource,
    M6UpgradePhysicalArtifactKind,
]

_BASE_ARTIFACT_ROUTES: frozenset[_ArtifactRoute] = frozenset(
    {
        (
            M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
            M6UpgradePhysicalArtifactKind.FRAME,
        ),
        (
            M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
            M6UpgradePhysicalArtifactKind.DETECTION,
        ),
    }
)
_V3_M2_EVIDENCE_ARTIFACT_ROUTES = _BASE_ARTIFACT_ROUTES | frozenset(
    {
        (
            M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
            M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
        )
    }
)
_MODEL_ARTIFACT_KINDS = frozenset(
    {
        M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
        M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
        M6UpgradePhysicalArtifactKind.MODEL_CACHE,
        M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
        M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
        M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
        M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
    }
)
_V3_M3_MODEL_ARTIFACT_ROUTES = _V3_M2_EVIDENCE_ARTIFACT_ROUTES | frozenset(
    (
        M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        kind,
    )
    for kind in _MODEL_ARTIFACT_KINDS
)
_V3_MODEL_ARTIFACT_ROUTES = _V3_M3_MODEL_ARTIFACT_ROUTES | frozenset(
    (
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        kind,
    )
    for kind in _MODEL_ARTIFACT_KINDS
)
_ACQUISITION_ARTIFACT_ROUTES: frozenset[_ArtifactRoute] = frozenset(
    {
        (
            M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
            M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
        ),
        (
            M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
            M6UpgradePhysicalArtifactKind.TOOL_RESULT,
        ),
    }
)
_V3_ACQUISITION_ARTIFACT_ROUTES = _V3_MODEL_ARTIFACT_ROUTES | _ACQUISITION_ARTIFACT_ROUTES
_PRECEDENT_ARTIFACT_ROUTES: frozenset[_ArtifactRoute] = frozenset(
    {
        (
            M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
            M6UpgradePhysicalArtifactKind.EMBEDDING,
        ),
        (
            M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
            M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
        ),
    }
)
_V3_PRECEDENT_ARTIFACT_ROUTES = _V3_ACQUISITION_ARTIFACT_ROUTES | _PRECEDENT_ARTIFACT_ROUTES
_MODEL_COMPONENT_BY_ROLE = {
    M6LockedModelRole.SCREENING: "screening",
    M6LockedModelRole.PROSECUTOR: "prosecutor",
    M6LockedModelRole.DEFENDER: "defender",
    M6LockedModelRole.JUDGE: "judge",
}
_MODEL_ARTIFACT_KIND_RANK = {
    kind: index
    for index, kind in enumerate(
        (
            M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
            M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
            M6UpgradePhysicalArtifactKind.MODEL_CACHE,
            M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
            M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
            M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
            M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
        )
    )
}


@dataclass(frozen=True, slots=True)
class M6MetadataModelCallArtifactPlan:
    """One body-free call-to-artifact grouping used for pending comparison."""

    observation: M6UpgradeObservedModelCall
    artifact_refs: tuple[M6UpgradePhysicalArtifactRef, ...]

    def __post_init__(self) -> None:
        if type(self.observation) is not M6UpgradeObservedModelCall:
            raise TypeError("metadata call plan requires an exact observation")
        try:
            observation = M6UpgradeObservedModelCall.model_validate(
                self.observation.model_dump(mode="json", exclude_computed_fields=True)
            )
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise ValueError("metadata call observation must be canonical") from None
        if observation != self.observation or type(self.artifact_refs) is not tuple:
            raise ValueError("metadata call plan must be canonical")
        refs: list[M6UpgradePhysicalArtifactRef] = []
        for value in self.artifact_refs:
            if type(value) is not M6UpgradePhysicalArtifactRef:
                raise TypeError("metadata call artifacts must be exact refs")
            controlled = M6UpgradePhysicalArtifactRef.model_validate(
                value.model_dump(mode="json", exclude_computed_fields=True)
            )
            if controlled != value:
                raise ValueError("metadata call artifacts must be canonical")
            refs.append(controlled)
        controlled_refs = tuple(refs)
        expected_source = (
            M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL
            if observation.layer == M6LockedModelCallLayer.SCREENING
            else M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL
        )
        if any(
            ref.source != expected_source or ref.kind not in _MODEL_ARTIFACT_KINDS
            for ref in controlled_refs
        ):
            raise ValueError("metadata call artifacts cross their model route")
        if controlled_refs != tuple(
            sorted(
                controlled_refs,
                key=lambda ref: (_MODEL_ARTIFACT_KIND_RANK[ref.kind], ref.artifact_id),
            )
        ):
            raise ValueError("metadata call artifacts must use route order")
        kinds = tuple(ref.kind for ref in controlled_refs)
        if len(kinds) != len(set(kinds)):
            raise ValueError("metadata call artifact kinds must be unique")
        required = (
            {
                M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
                M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
                M6UpgradePhysicalArtifactKind.MODEL_CACHE,
                M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
                M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
            }
            if observation.result_kind == M6LockedModelCallResultKind.RESPONSE
            else {
                M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
                M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
            }
        )
        allowed = required | (
            {M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT}
            if observation.result_kind == M6LockedModelCallResultKind.RESPONSE
            else set()
        )
        observed_kinds = set(kinds)
        if not required.issubset(observed_kinds) or observed_kinds - allowed:
            raise ValueError("metadata call artifact closure is incomplete")
        request = next(
            ref
            for ref in controlled_refs
            if ref.kind == M6UpgradePhysicalArtifactKind.MODEL_REQUEST
        )
        if request.artifact_id != observation.request_id:
            raise ValueError("metadata call request differs from its observation")
        if len({ref.physical_key for ref in controlled_refs}) != len(controlled_refs) or len(
            {ref.artifact_ref_id for ref in controlled_refs}
        ) != len(controlled_refs):
            raise ValueError("metadata call artifacts must be physically unique")
        object.__setattr__(self, "observation", observation)
        object.__setattr__(self, "artifact_refs", controlled_refs)

    @property
    def sort_key(self) -> tuple[int, int, int, str]:
        return self.observation.sort_key


def _fail(code: M6UpgradeWholeSampleRecordBuilderFailureCode) -> NoReturn:
    raise M6UpgradeWholeSampleRecordBuilderError(code) from None


def _canonical_scope(value: object) -> M6UpgradeExecutionScopeAuthority:
    if type(value) is not M6UpgradeExecutionScopeAuthority:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
    try:
        controlled = M6UpgradeExecutionScopeAuthority.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
    if controlled != value:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
    return controlled


def _canonical_observation(value: object) -> M6UpgradeSampleExecutionObservationAuthority:
    if type(value) is not M6UpgradeSampleExecutionObservationAuthority:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
    try:
        controlled = M6UpgradeSampleExecutionObservationAuthority.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
    if controlled != value:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
    return controlled


def _canonical_observation_v2(
    value: object,
) -> M6UpgradeSampleExecutionObservationAuthorityV2:
    if type(value) is not M6UpgradeSampleExecutionObservationAuthorityV2:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
    try:
        controlled = M6UpgradeSampleExecutionObservationAuthorityV2.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
    if controlled != value:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
    return controlled


def _canonical_candidate_case(
    value: object,
) -> M6UpgradeCandidateCaseBinding:
    if type(value) is not M6UpgradeCandidateCaseBinding:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH)
    try:
        controlled = M6UpgradeCandidateCaseBinding.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH)
    if controlled != value:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH)
    return controlled


def _canonical_prior_records(
    values: object,
) -> tuple[M6UpgradeSampleExecutionRecordV2, ...]:
    if not isinstance(values, tuple) or any(
        type(item) is not M6UpgradeSampleExecutionRecordV2 for item in values
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
    controlled: list[M6UpgradeSampleExecutionRecordV2] = []
    try:
        for item in values:
            canonical = M6UpgradeSampleExecutionRecordV2.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            if canonical != item:
                _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
            controlled.append(canonical)
    except M6UpgradeWholeSampleRecordBuilderError:
        raise
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
    return tuple(controlled)


def _canonical_artifacts(values: object) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
    if not isinstance(values, tuple):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT)
    if len(values) > MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.LINK_LIMIT_EXCEEDED)
    controlled: list[M6UpgradePhysicalArtifactRef] = []
    try:
        for item in values:
            if type(item) is not M6UpgradePhysicalArtifactRef:
                _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
            canonical = M6UpgradePhysicalArtifactRef.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            if canonical != item:
                _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
            controlled.append(canonical)
    except M6UpgradeWholeSampleRecordBuilderError:
        raise
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
    return tuple(controlled)


def _canonical_planned_model_calls(
    values: object,
    *,
    allow_hearing: bool = False,
) -> tuple[M6PlannedModelCallPhysicalClosure, ...]:
    if not isinstance(values, tuple):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT)
    controlled: list[M6PlannedModelCallPhysicalClosure] = []
    for item in values:
        if type(item) is not M6PlannedModelCallPhysicalClosure:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT)
        try:
            refs = item.artifact_refs
            expected_source = (
                M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL
                if item.layer == M6LockedModelCallLayer.SCREENING
                else M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL
            )
            if (
                (
                    item.layer == M6LockedModelCallLayer.SCREENING
                    and item.role != M6LockedModelRole.SCREENING
                )
                or (
                    item.layer == M6LockedModelCallLayer.HEARING
                    and (not allow_hearing or item.role == M6LockedModelRole.SCREENING)
                )
                or any(
                    ref.source != expected_source or ref.kind not in _MODEL_ARTIFACT_KINDS
                    for ref in refs
                )
            ):
                _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
            canonical = replace(item)
        except M6UpgradeWholeSampleRecordBuilderError:
            raise
        except (AttributeError, TypeError, ValueError, ValidationError):
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH)
        if canonical != item:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH)
        controlled.append(canonical)
    controlled_tuple = tuple(controlled)
    if tuple(item.sort_key for item in controlled_tuple) != tuple(
        sorted(item.sort_key for item in controlled_tuple)
    ) or len({item.request_ref.artifact_id for item in controlled_tuple}) != len(controlled_tuple):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    return controlled_tuple


def _validate_scope_prefix(
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthority,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
) -> tuple[int, str]:
    sequence = len(prior_records)
    entries = scope.execution_dataset.entries
    if sequence >= len(entries):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_NOT_FOUND)
    previous = M6_UPGRADE_LEDGER_GENESIS_HASH
    for index, record in enumerate(prior_records):
        if (
            record.ledger_sequence != index
            or record.previous_ledger_entry_hash != previous
            or record.execution_scope_authority_id != scope.execution_scope_authority_id
            or record.candidate_run_id != scope.candidate_run_id
            or record.command_id != scope.command.command_id
            or record.execution_dataset_snapshot_id
            != scope.execution_dataset.execution_dataset_snapshot_id
            or record.execution_entry != entries[index]
        ):
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
        previous = record.sample_execution_record_id
    if (
        observation.execution_scope_authority_id != scope.execution_scope_authority_id
        or observation.candidate_run_id != scope.candidate_run_id
        or observation.command_id != scope.command.command_id
        or observation.execution_dataset_snapshot_id
        != scope.execution_dataset.execution_dataset_snapshot_id
        or observation.ledger_sequence != sequence
        or observation.execution_entry != entries[sequence]
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    return sequence, previous


def _validate_prefix_identity(
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    current_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
) -> None:
    if (
        sum(item.artifact_link_count for item in prior_records) + len(current_artifacts)
        > MAX_M6_UPGRADE_LEDGER_LINKS
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.LINK_LIMIT_EXCEEDED)
    by_key: dict[tuple[int, int, str, str], M6UpgradePhysicalArtifactRef] = {}
    by_id: dict[str, M6UpgradePhysicalArtifactRef] = {}
    for record in prior_records:
        for link in record.artifact_links:
            artifact = link.artifact
            prior_key = by_key.setdefault(artifact.physical_key, artifact)
            prior_id = by_id.setdefault(artifact.artifact_ref_id, artifact)
            if prior_key != artifact or prior_id != artifact:
                _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
    for artifact in current_artifacts:
        prior_key = by_key.setdefault(artifact.physical_key, artifact)
        prior_id = by_id.setdefault(artifact.artifact_ref_id, artifact)
        if prior_key != artifact or prior_id != artifact:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)


def _validate_prefix_route(
    scope: M6UpgradeExecutionScopeAuthority,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    candidate_case: M6UpgradeCandidateCaseBinding | None,
    allowed_artifact_routes: frozenset[_ArtifactRoute],
) -> None:
    if any(
        (link.artifact.source, link.artifact.kind) not in allowed_artifact_routes
        for record in prior_records
        for link in record.artifact_links
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
    prior_case_ids = tuple(
        record.candidate_case.case_id
        for record in prior_records
        if record.candidate_case is not None
    )
    if len(prior_case_ids) != len(set(prior_case_ids)):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
    if candidate_case is None:
        return
    if candidate_case.case_id in prior_case_ids:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_PREFIX_MISMATCH)
    if candidate_case.case_audit_sequence <= scope.execution_start_audit_head_sequence:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH)


def _build_m6_upgrade_base_record(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthority,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    candidate_case: M6UpgradeCandidateCaseBinding | None,
    require_v2_observation: bool = False,
    current_artifact_routes: frozenset[_ArtifactRoute] = _BASE_ARTIFACT_ROUTES,
    prefix_artifact_routes: frozenset[_ArtifactRoute] = _BASE_ARTIFACT_ROUTES,
    model_artifact_usages: dict[_ArtifactIdentity, M6UpgradeArtifactUsage] | None = None,
) -> M6UpgradeSampleExecutionRecordV2:
    """Close one opened-route observation against an exact planned physical set.

    The physical references may be a metadata-derived plan.  This permits the
    adapter to check link, byte, record, and prefix budgets before it performs
    the first Pixel read.  The adapter must later prove that every verified
    physical reference is byte-for-byte equal to this plan.
    """

    controlled_scope = _canonical_scope(scope)
    controlled_observation = (
        _canonical_observation_v2(observation)
        if require_v2_observation
        else _canonical_observation(observation)
    )
    controlled_prior = _canonical_prior_records(prior_records)
    controlled_artifacts = _canonical_artifacts(artifacts)
    controlled_case = (
        _canonical_candidate_case(candidate_case) if candidate_case is not None else None
    )
    sequence, previous = _validate_scope_prefix(
        controlled_scope,
        controlled_observation,
        controlled_prior,
    )
    if controlled_observation.model_calls and model_artifact_usages is None:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
    if controlled_case is None:
        if (
            controlled_observation.outcome != M6ReplayExecutionOutcome.NO_CASE
            or controlled_observation.candidate_case is not None
        ):
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
    elif (
        controlled_observation.outcome != M6ReplayExecutionOutcome.CASE_REPLAYED
        or controlled_observation.candidate_case != controlled_case
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH)
    if any(
        (item.source, item.kind) not in current_artifact_routes
        for item in controlled_observation.artifacts
    ) or any(
        (item.source, item.kind) not in current_artifact_routes for item in controlled_artifacts
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)

    observed_usage = {item.identity_key: item.usage for item in controlled_observation.artifacts}
    if model_artifact_usages is not None:
        if set(observed_usage).intersection(model_artifact_usages):
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
        observed_usage.update(model_artifact_usages)
    physical_identities = {
        (item.source, item.kind, item.artifact_id) for item in controlled_artifacts
    }
    if len(physical_identities) != len(controlled_artifacts):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
    if physical_identities != set(observed_usage):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    physical_keys = tuple(item.physical_key for item in controlled_artifacts)
    ref_ids = tuple(item.artifact_ref_id for item in controlled_artifacts)
    if len(physical_keys) != len(set(physical_keys)) or len(ref_ids) != len(set(ref_ids)):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
    if sum(item.size_bytes for item in controlled_artifacts) > (
        MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.PHYSICAL_BYTE_LIMIT_EXCEEDED)
    _validate_prefix_route(
        controlled_scope,
        controlled_prior,
        controlled_case,
        prefix_artifact_routes,
    )
    _validate_prefix_identity(controlled_prior, controlled_artifacts)

    ordered = tuple(sorted(controlled_artifacts, key=lambda item: item.physical_key))
    try:
        links = tuple(
            M6UpgradeSampleArtifactLink(
                ordinal=ordinal,
                usage=observed_usage[(artifact.source, artifact.kind, artifact.artifact_id)],
                artifact=artifact,
            )
            for ordinal, artifact in enumerate(ordered)
        )
        record = M6UpgradeSampleExecutionRecordV2(
            execution_scope_authority_id=controlled_scope.execution_scope_authority_id,
            candidate_run_id=controlled_scope.candidate_run_id,
            command_id=controlled_scope.command.command_id,
            execution_dataset_snapshot_id=(
                controlled_scope.execution_dataset.execution_dataset_snapshot_id
            ),
            execution_entry=controlled_observation.execution_entry,
            outcome=controlled_observation.outcome,
            candidate_case=controlled_case,
            artifact_links=links,
            ledger_sequence=sequence,
            previous_ledger_entry_hash=previous,
            observation_authority_id=controlled_observation.observation_authority_id,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    if len(canonical_json(record.model_dump(mode="json")).encode("utf-8")) > (
        MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.RECORD_TOO_LARGE)
    return record


def build_m6_upgrade_no_case_record(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthority,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
) -> M6UpgradeSampleExecutionRecordV2:
    """Close one NO_CASE Frame/Detection observation."""

    return _build_m6_upgrade_base_record(
        scope=scope,
        observation=observation,
        prior_records=prior_records,
        artifacts=artifacts,
        candidate_case=None,
    )


def build_m6_upgrade_case_replayed_base_record(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthority,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
) -> M6UpgradeSampleExecutionRecordV2:
    """Close a CASE_REPLAYED observation limited to Frame/Detection authority."""

    controlled_case = _canonical_candidate_case(candidate_case)
    return _build_m6_upgrade_base_record(
        scope=scope,
        observation=observation,
        prior_records=prior_records,
        artifacts=artifacts,
        candidate_case=controlled_case,
    )


def build_m6_upgrade_no_case_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
) -> M6UpgradeSampleExecutionRecordV2:
    """Close one exact Observation V2 NO_CASE Frame/Detection observation."""

    return _build_m6_upgrade_base_record(
        scope=scope,
        observation=observation,
        prior_records=prior_records,
        artifacts=artifacts,
        candidate_case=None,
        require_v2_observation=True,
        prefix_artifact_routes=_V3_PRECEDENT_ARTIFACT_ROUTES,
    )


def build_m6_upgrade_case_replayed_base_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
) -> M6UpgradeSampleExecutionRecordV2:
    """Close an exact Observation V2 CASE_REPLAYED base-route observation."""

    controlled_case = _canonical_candidate_case(candidate_case)
    return _build_m6_upgrade_base_record(
        scope=scope,
        observation=observation,
        prior_records=prior_records,
        artifacts=artifacts,
        candidate_case=controlled_case,
        require_v2_observation=True,
        prefix_artifact_routes=_V3_PRECEDENT_ARTIFACT_ROUTES,
    )


def build_m6_upgrade_case_replayed_evidence_pack_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
) -> M6UpgradeSampleExecutionRecordV2:
    """Close one exact Observation V2 over the opened M2 EvidencePack route.

    Candidate-observed identities remain the only exact-set authority.  This
    composer accepts already resolved physical references and has no Case
    inventory input from which it could infer or add an unobserved pack.
    """

    controlled_case = _canonical_candidate_case(candidate_case)
    return _build_m6_upgrade_base_record(
        scope=scope,
        observation=observation,
        prior_records=prior_records,
        artifacts=artifacts,
        candidate_case=controlled_case,
        require_v2_observation=True,
        current_artifact_routes=_V3_M2_EVIDENCE_ARTIFACT_ROUTES,
        prefix_artifact_routes=_V3_PRECEDENT_ARTIFACT_ROUTES,
    )


def _attempt_build_m6_upgrade_case_replayed_model_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    planned_calls: tuple[M6PlannedModelCallPhysicalClosure, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
    allow_hearing: bool,
    acquisition_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...] = (),
    allow_acquisition: bool = False,
    precedent_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...] = (),
    allow_precedent: bool = False,
) -> M6UpgradeSampleExecutionRecordV2:
    """Attempt a model pending-record composition inside the private failure frame."""

    controlled_scope = _canonical_scope(scope)
    controlled_observation = _canonical_observation_v2(observation)
    controlled_case = _canonical_candidate_case(candidate_case)
    controlled_artifacts = _canonical_artifacts(artifacts)
    controlled_acquisition = (
        _canonical_acquisition_artifacts(acquisition_artifacts) if allow_acquisition else ()
    )
    controlled_precedent = (
        _canonical_precedent_artifacts(precedent_artifacts) if allow_precedent else ()
    )
    controlled_calls = _canonical_planned_model_calls(
        planned_calls,
        allow_hearing=allow_hearing,
    )

    if (
        controlled_observation.outcome != M6ReplayExecutionOutcome.CASE_REPLAYED
        or controlled_observation.candidate_case != controlled_case
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH)
    observed_calls = controlled_observation.model_calls
    if not observed_calls or not controlled_calls:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    if any(
        (
            item.layer == M6LockedModelCallLayer.SCREENING
            and item.role != M6LockedModelRole.SCREENING
        )
        or (
            item.layer == M6LockedModelCallLayer.HEARING
            and (not allow_hearing or item.role == M6LockedModelRole.SCREENING)
        )
        for item in observed_calls
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
    if any(item.case_id != controlled_case.case_id for item in controlled_calls):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH)
    source_identities_by_layer = {
        layer: {item.source_identity_sha256 for item in controlled_calls if item.layer == layer}
        for layer in M6LockedModelCallLayer
    }
    if (
        any(len(values) > 1 for values in source_identities_by_layer.values())
        or any(item.run_id != controlled_scope.candidate_run_id for item in controlled_calls)
        or any(
            item.manifest_id != controlled_scope.candidate_manifest.manifest_id
            for item in controlled_calls
        )
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH)

    provider_profile_by_role = {
        M6LockedModelRole.SCREENING: (controlled_scope.candidate_config.screening.provider_profile),
        M6LockedModelRole.PROSECUTOR: (
            controlled_scope.candidate_config.hearing.prosecutor_profile
        ),
        M6LockedModelRole.DEFENDER: (controlled_scope.candidate_config.hearing.defender_profile),
        M6LockedModelRole.JUDGE: controlled_scope.candidate_config.hearing.judge_profile,
    }
    if any(
        item.execution_model_manifest_id
        != controlled_scope.candidate_manifest.models[
            _MODEL_COMPONENT_BY_ROLE[item.role]
        ].model_manifest_id
        or item.timeout_ms
        > int(
            controlled_scope.candidate_config.providers[
                provider_profile_by_role[item.role]
            ].timeout_seconds
            * 1_000
        )
        for item in controlled_calls
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH)

    model_refs = tuple(
        ref for planned_call in controlled_calls for ref in planned_call.artifact_refs
    )
    model_identities = tuple((item.source, item.kind, item.artifact_id) for item in model_refs)
    model_physical_keys = tuple(item.physical_key for item in model_refs)
    model_ref_ids = tuple(item.artifact_ref_id for item in model_refs)
    if (
        len(model_identities) != len(set(model_identities))
        or len(model_physical_keys) != len(set(model_physical_keys))
        or len(model_ref_ids) != len(set(model_ref_ids))
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)

    planned_by_request = {item.request_ref.artifact_id: item for item in controlled_calls}
    observed_by_request = {item.request_id: item for item in observed_calls}
    if (
        len(planned_by_request) != len(controlled_calls)
        or len(observed_by_request) != len(observed_calls)
        or set(planned_by_request) != set(observed_by_request)
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH)

    model_usages: dict[_ArtifactIdentity, M6UpgradeArtifactUsage] = {}
    for request_id, observed_call in observed_by_request.items():
        planned_call = planned_by_request[request_id]
        if (
            planned_call.layer != observed_call.layer
            or planned_call.role != observed_call.role
            or planned_call.attempt_index != observed_call.attempt_index
            or planned_call.result_kind != observed_call.result_kind
        ):
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH)
        for ref in planned_call.artifact_refs:
            model_usages[(ref.source, ref.kind, ref.artifact_id)] = (
                M6UpgradeArtifactUsage.PRODUCED
                if ref.kind != M6UpgradePhysicalArtifactKind.MODEL_CACHE
                or observed_call.provider_invoked
                else M6UpgradeArtifactUsage.CONSUMED
            )

    ordinary_routes = (
        _V3_PRECEDENT_ARTIFACT_ROUTES
        if allow_precedent
        else (
            _V3_ACQUISITION_ARTIFACT_ROUTES
            if allow_acquisition
            else (_V3_MODEL_ARTIFACT_ROUTES if allow_hearing else _V3_M3_MODEL_ARTIFACT_ROUTES)
        )
    )
    observed_routes = (
        _V3_PRECEDENT_ARTIFACT_ROUTES
        if allow_precedent
        else (
            _V3_ACQUISITION_ARTIFACT_ROUTES
            if allow_acquisition
            else _V3_M2_EVIDENCE_ARTIFACT_ROUTES
        )
    )
    if any(
        (item.source, item.kind) not in observed_routes for item in controlled_observation.artifacts
    ) or any(
        (item.source, item.kind) not in _V3_M2_EVIDENCE_ARTIFACT_ROUTES
        for item in controlled_artifacts
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
    if allow_acquisition:
        observed_acquisition = tuple(
            item
            for item in controlled_observation.artifacts
            if (item.source, item.kind) in _ACQUISITION_ARTIFACT_ROUTES
        )
        if any(item.usage != M6UpgradeArtifactUsage.PRODUCED for item in observed_acquisition):
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    if allow_precedent:
        observed_exposures = tuple(
            item
            for item in controlled_observation.artifacts
            if item.source == M6UpgradePhysicalArtifactSource.M5_PRECEDENT
            and item.kind == M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE
        )
        if any(item.usage != M6UpgradeArtifactUsage.PRODUCED for item in observed_exposures):
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    supplied_artifacts = controlled_artifacts + controlled_acquisition + controlled_precedent
    observed_artifact_identities = {item.identity_key for item in controlled_observation.artifacts}
    physical_artifact_identities = {
        (item.source, item.kind, item.artifact_id) for item in supplied_artifacts
    }
    if len(physical_artifact_identities) != len(supplied_artifacts):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
    if observed_artifact_identities != physical_artifact_identities:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH)

    return _build_m6_upgrade_base_record(
        scope=controlled_scope,
        observation=controlled_observation,
        prior_records=prior_records,
        artifacts=supplied_artifacts + model_refs,
        candidate_case=controlled_case,
        require_v2_observation=True,
        current_artifact_routes=ordinary_routes,
        prefix_artifact_routes=_V3_PRECEDENT_ARTIFACT_ROUTES,
        model_artifact_usages=model_usages,
    )


def _attempt_build_m6_upgrade_case_replayed_m3_model_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    planned_calls: tuple[M6PlannedModelCallPhysicalClosure, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
) -> M6UpgradeSampleExecutionRecordV2:
    """Preserve the M3-only private seam used by payload-boundary tests."""

    return _attempt_build_m6_upgrade_case_replayed_model_record_v3(
        scope=scope,
        observation=observation,
        prior_records=prior_records,
        artifacts=artifacts,
        planned_calls=planned_calls,
        candidate_case=candidate_case,
        allow_hearing=False,
    )


def build_m6_upgrade_case_replayed_m3_model_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    planned_calls: tuple[M6PlannedModelCallPhysicalClosure, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
) -> M6UpgradeSampleExecutionRecordV2:
    """Compose an M3 pending record from metadata plans, without proving Raw bytes.

    ``planned_calls`` is only the pre-read physical plan reconstructed from
    trusted M3 metadata.  It is sufficient for exact joins and every link,
    byte, record, prefix, and identity budget, but it does not prove a planned
    response's Raw bytes.  The downstream builder must verify Raw and compare
    every late-observed closure reference byte-for-byte with this pending
    record before persistence.  Failures publish only a typed reason after all
    authority-bearing private frames have unwound.
    """

    failure_code = M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    try:
        result = _attempt_build_m6_upgrade_case_replayed_m3_model_record_v3(
            scope=scope,
            observation=observation,
            prior_records=prior_records,
            artifacts=artifacts,
            planned_calls=planned_calls,
            candidate_case=candidate_case,
        )
    except M6UpgradeWholeSampleRecordBuilderError as error:
        failure_code = error.reason_code
    except Exception:
        failure_code = M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    else:
        del scope, observation, prior_records, artifacts, planned_calls, candidate_case
        return result
    del scope, observation, prior_records, artifacts, planned_calls, candidate_case
    raise M6UpgradeWholeSampleRecordBuilderError(failure_code) from None


def _canonical_metadata_model_artifacts(
    values: object,
    *,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
) -> tuple[
    tuple[M6UpgradePhysicalArtifactRef, ...],
    dict[_ArtifactIdentity, M6UpgradeArtifactUsage],
]:
    if type(values) is not tuple or any(
        type(item) is not M6MetadataModelCallArtifactPlan for item in values
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT)
    try:
        controlled_calls = tuple(
            M6MetadataModelCallArtifactPlan(
                observation=item.observation,
                artifact_refs=item.artifact_refs,
            )
            for item in values
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    if (
        not controlled_calls
        or controlled_calls != tuple(sorted(controlled_calls, key=lambda item: item.sort_key))
        or tuple(item.observation for item in controlled_calls) != observation.model_calls
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    model_refs = tuple(ref for item in controlled_calls for ref in item.artifact_refs)
    if (
        len({(ref.source, ref.kind, ref.artifact_id) for ref in model_refs}) != len(model_refs)
        or len({ref.physical_key for ref in model_refs}) != len(model_refs)
        or len({ref.artifact_ref_id for ref in model_refs}) != len(model_refs)
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
    model_usages: dict[_ArtifactIdentity, M6UpgradeArtifactUsage] = {}
    for item in controlled_calls:
        for ref in item.artifact_refs:
            model_usages[(ref.source, ref.kind, ref.artifact_id)] = (
                M6UpgradeArtifactUsage.PRODUCED
                if ref.kind != M6UpgradePhysicalArtifactKind.MODEL_CACHE
                or item.observation.provider_invoked
                else M6UpgradeArtifactUsage.CONSUMED
            )
    return model_refs, model_usages


def _attempt_build_m6_upgrade_case_replayed_metadata_model_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    model_calls: tuple[M6MetadataModelCallArtifactPlan, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
) -> M6UpgradeSampleExecutionRecordV2:
    controlled_scope = _canonical_scope(scope)
    controlled_observation = _canonical_observation_v2(observation)
    controlled_case = _canonical_candidate_case(candidate_case)
    controlled_artifacts = _canonical_artifacts(artifacts)
    model_refs, model_usages = _canonical_metadata_model_artifacts(
        model_calls,
        observation=controlled_observation,
    )
    return _build_m6_upgrade_base_record(
        scope=controlled_scope,
        observation=controlled_observation,
        prior_records=prior_records,
        artifacts=controlled_artifacts + model_refs,
        candidate_case=controlled_case,
        require_v2_observation=True,
        current_artifact_routes=_V3_MODEL_ARTIFACT_ROUTES,
        prefix_artifact_routes=_V3_PRECEDENT_ARTIFACT_ROUTES,
        model_artifact_usages=model_usages,
    )


def _canonical_acquisition_artifacts(
    values: object,
) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
    controlled = _canonical_artifacts(values)
    if any((item.source, item.kind) not in _ACQUISITION_ARTIFACT_ROUTES for item in controlled):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
    identities = tuple((item.source, item.kind, item.artifact_id) for item in controlled)
    physical_keys = tuple(item.physical_key for item in controlled)
    ref_ids = tuple(item.artifact_ref_id for item in controlled)
    if (
        len(identities) != len(set(identities))
        or len(physical_keys) != len(set(physical_keys))
        or len(ref_ids) != len(set(ref_ids))
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
    if physical_keys != tuple(sorted(physical_keys)):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    return controlled


def _canonical_precedent_artifacts(
    values: object,
) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
    controlled = _canonical_artifacts(values)
    if any((item.source, item.kind) not in _PRECEDENT_ARTIFACT_ROUTES for item in controlled):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
    identities = tuple((item.source, item.kind, item.artifact_id) for item in controlled)
    physical_keys = tuple(item.physical_key for item in controlled)
    ref_ids = tuple(item.artifact_ref_id for item in controlled)
    if (
        len(identities) != len(set(identities))
        or len(physical_keys) != len(set(physical_keys))
        or len(ref_ids) != len(set(ref_ids))
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
    if physical_keys != tuple(sorted(physical_keys)):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    return controlled


def _attempt_build_m6_upgrade_case_replayed_acquisition_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    planned_calls: tuple[M6PlannedModelCallPhysicalClosure, ...],
    acquisition_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
) -> M6UpgradeSampleExecutionRecordV2:
    """Attempt acquisition composition with fully verified model plans."""

    return _attempt_build_m6_upgrade_case_replayed_model_record_v3(
        scope=scope,
        observation=observation,
        prior_records=prior_records,
        artifacts=artifacts,
        planned_calls=planned_calls,
        candidate_case=candidate_case,
        allow_hearing=True,
        acquisition_artifacts=acquisition_artifacts,
        allow_acquisition=True,
    )


def _attempt_build_m6_upgrade_case_replayed_precedent_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    planned_calls: tuple[M6PlannedModelCallPhysicalClosure, ...],
    acquisition_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    precedent_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
) -> M6UpgradeSampleExecutionRecordV2:
    """Attempt M5 composition with fully verified model and non-model plans."""

    return _attempt_build_m6_upgrade_case_replayed_model_record_v3(
        scope=scope,
        observation=observation,
        prior_records=prior_records,
        artifacts=artifacts,
        planned_calls=planned_calls,
        candidate_case=candidate_case,
        allow_hearing=True,
        acquisition_artifacts=acquisition_artifacts,
        allow_acquisition=True,
        precedent_artifacts=precedent_artifacts,
        allow_precedent=True,
    )


def _attempt_build_m6_upgrade_case_replayed_metadata_acquisition_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    model_calls: tuple[M6MetadataModelCallArtifactPlan, ...],
    acquisition_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
    precedent_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...] = (),
    allow_precedent: bool = False,
) -> M6UpgradeSampleExecutionRecordV2:
    """Attempt body-free composition through the explicitly opened route set."""

    controlled_scope = _canonical_scope(scope)
    controlled_observation = _canonical_observation_v2(observation)
    controlled_case = _canonical_candidate_case(candidate_case)
    controlled_artifacts = _canonical_artifacts(artifacts)
    controlled_acquisition = _canonical_acquisition_artifacts(acquisition_artifacts)
    controlled_precedent = (
        _canonical_precedent_artifacts(precedent_artifacts) if allow_precedent else ()
    )
    model_refs, model_usages = _canonical_metadata_model_artifacts(
        model_calls,
        observation=controlled_observation,
    )

    if any(
        (item.source, item.kind) not in _V3_M2_EVIDENCE_ARTIFACT_ROUTES
        for item in controlled_artifacts
    ) or any(
        (item.source, item.kind)
        not in (
            _V3_PRECEDENT_ARTIFACT_ROUTES if allow_precedent else _V3_ACQUISITION_ARTIFACT_ROUTES
        )
        for item in controlled_observation.artifacts
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
    observed_acquisition = tuple(
        item
        for item in controlled_observation.artifacts
        if (item.source, item.kind) in _ACQUISITION_ARTIFACT_ROUTES
    )
    if any(item.usage != M6UpgradeArtifactUsage.PRODUCED for item in observed_acquisition):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    if allow_precedent:
        observed_exposures = tuple(
            item
            for item in controlled_observation.artifacts
            if item.source == M6UpgradePhysicalArtifactSource.M5_PRECEDENT
            and item.kind == M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE
        )
        if any(item.usage != M6UpgradeArtifactUsage.PRODUCED for item in observed_exposures):
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH)

    supplied_non_model = controlled_artifacts + controlled_acquisition + controlled_precedent
    supplied_identities = tuple(
        (item.source, item.kind, item.artifact_id) for item in supplied_non_model
    )
    if len(supplied_identities) != len(set(supplied_identities)):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
    if set(supplied_identities) != {item.identity_key for item in controlled_observation.artifacts}:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH)

    return _build_m6_upgrade_base_record(
        scope=controlled_scope,
        observation=controlled_observation,
        prior_records=prior_records,
        artifacts=supplied_non_model + model_refs,
        candidate_case=controlled_case,
        require_v2_observation=True,
        current_artifact_routes=(
            _V3_PRECEDENT_ARTIFACT_ROUTES if allow_precedent else _V3_ACQUISITION_ARTIFACT_ROUTES
        ),
        prefix_artifact_routes=_V3_PRECEDENT_ARTIFACT_ROUTES,
        model_artifact_usages=model_usages,
    )


def _attempt_build_m6_upgrade_case_replayed_metadata_precedent_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    model_calls: tuple[M6MetadataModelCallArtifactPlan, ...],
    acquisition_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    precedent_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
) -> M6UpgradeSampleExecutionRecordV2:
    """Attempt an M5 pending record without reading any M5 authority body."""

    return _attempt_build_m6_upgrade_case_replayed_metadata_acquisition_record_v3(
        scope=scope,
        observation=observation,
        prior_records=prior_records,
        artifacts=artifacts,
        model_calls=model_calls,
        acquisition_artifacts=acquisition_artifacts,
        candidate_case=candidate_case,
        precedent_artifacts=precedent_artifacts,
        allow_precedent=True,
    )


def build_m6_upgrade_case_replayed_metadata_model_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    model_calls: tuple[M6MetadataModelCallArtifactPlan, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
) -> M6UpgradeSampleExecutionRecordV2:
    """Build the pending record from body-free M3/M4 metadata only."""

    failure_code = M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    try:
        result = _attempt_build_m6_upgrade_case_replayed_metadata_model_record_v3(
            scope=scope,
            observation=observation,
            prior_records=prior_records,
            artifacts=artifacts,
            model_calls=model_calls,
            candidate_case=candidate_case,
        )
    except M6UpgradeWholeSampleRecordBuilderError as error:
        failure_code = error.reason_code
    except Exception:
        failure_code = M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    else:
        del scope, observation, prior_records, artifacts, model_calls, candidate_case
        return result
    del scope, observation, prior_records, artifacts, model_calls, candidate_case
    raise M6UpgradeWholeSampleRecordBuilderError(failure_code) from None


def build_m6_upgrade_case_replayed_metadata_acquisition_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    model_calls: tuple[M6MetadataModelCallArtifactPlan, ...],
    acquisition_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
) -> M6UpgradeSampleExecutionRecordV2:
    """Build an acquisition pending record from body-free metadata plans.

    ``acquisition_artifacts`` may contain only stable, unique physical plans
    for a ToolExecutionManifest and ToolResult.  The selected Observation V2
    remains the exact identity and usage authority; this pure composer neither
    reads nor verifies any acquisition body.
    """

    failure_code = M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
    try:
        result = _attempt_build_m6_upgrade_case_replayed_metadata_acquisition_record_v3(
            scope=scope,
            observation=observation,
            prior_records=prior_records,
            artifacts=artifacts,
            model_calls=model_calls,
            acquisition_artifacts=acquisition_artifacts,
            candidate_case=candidate_case,
        )
    except M6UpgradeWholeSampleRecordBuilderError as error:
        failure_code = error.reason_code
    except Exception:
        failure_code = M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
    else:
        del (
            scope,
            observation,
            prior_records,
            artifacts,
            model_calls,
            acquisition_artifacts,
            candidate_case,
        )
        return result
    del (
        scope,
        observation,
        prior_records,
        artifacts,
        model_calls,
        acquisition_artifacts,
        candidate_case,
    )
    raise M6UpgradeWholeSampleRecordBuilderError(failure_code) from None


def build_m6_upgrade_case_replayed_acquisition_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    planned_calls: tuple[M6PlannedModelCallPhysicalClosure, ...],
    acquisition_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
) -> M6UpgradeSampleExecutionRecordV2:
    """Compose the verified acquisition record after canonical body reads.

    The planned model closures retain the complete scope, manifest, timeout,
    role and terminal checks used by the existing M3/M4 composer.  A caller
    can therefore compare this result byte-for-byte with the earlier metadata
    acquisition pending record before appending it.
    """

    failure_code = M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    try:
        result = _attempt_build_m6_upgrade_case_replayed_acquisition_record_v3(
            scope=scope,
            observation=observation,
            prior_records=prior_records,
            artifacts=artifacts,
            planned_calls=planned_calls,
            acquisition_artifacts=acquisition_artifacts,
            candidate_case=candidate_case,
        )
    except M6UpgradeWholeSampleRecordBuilderError as error:
        failure_code = error.reason_code
    except Exception:
        failure_code = M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    else:
        del (
            scope,
            observation,
            prior_records,
            artifacts,
            planned_calls,
            acquisition_artifacts,
            candidate_case,
        )
        return result
    del (
        scope,
        observation,
        prior_records,
        artifacts,
        planned_calls,
        acquisition_artifacts,
        candidate_case,
    )
    raise M6UpgradeWholeSampleRecordBuilderError(failure_code) from None


def build_m6_upgrade_case_replayed_metadata_precedent_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    model_calls: tuple[M6MetadataModelCallArtifactPlan, ...],
    acquisition_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    precedent_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
) -> M6UpgradeSampleExecutionRecordV2:
    """Build an M5 pending record from body-free physical metadata plans.

    The selected Observation V2 remains the exact identity and usage authority.
    Embedding usage is intentionally preserved as observed because the frozen
    physical contract permits both consumed and produced embeddings.
    """

    failure_code = M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
    try:
        result = _attempt_build_m6_upgrade_case_replayed_metadata_precedent_record_v3(
            scope=scope,
            observation=observation,
            prior_records=prior_records,
            artifacts=artifacts,
            model_calls=model_calls,
            acquisition_artifacts=acquisition_artifacts,
            precedent_artifacts=precedent_artifacts,
            candidate_case=candidate_case,
        )
    except M6UpgradeWholeSampleRecordBuilderError as error:
        failure_code = error.reason_code
    except Exception:
        failure_code = M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
    else:
        del (
            scope,
            observation,
            prior_records,
            artifacts,
            model_calls,
            acquisition_artifacts,
            precedent_artifacts,
            candidate_case,
        )
        return result
    del (
        scope,
        observation,
        prior_records,
        artifacts,
        model_calls,
        acquisition_artifacts,
        precedent_artifacts,
        candidate_case,
    )
    raise M6UpgradeWholeSampleRecordBuilderError(failure_code) from None


def build_m6_upgrade_case_replayed_precedent_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    planned_calls: tuple[M6PlannedModelCallPhysicalClosure, ...],
    acquisition_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    precedent_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
) -> M6UpgradeSampleExecutionRecordV2:
    """Compose the verified M5 record after canonical authority-body reads."""

    failure_code = M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    try:
        result = _attempt_build_m6_upgrade_case_replayed_precedent_record_v3(
            scope=scope,
            observation=observation,
            prior_records=prior_records,
            artifacts=artifacts,
            planned_calls=planned_calls,
            acquisition_artifacts=acquisition_artifacts,
            precedent_artifacts=precedent_artifacts,
            candidate_case=candidate_case,
        )
    except M6UpgradeWholeSampleRecordBuilderError as error:
        failure_code = error.reason_code
    except Exception:
        failure_code = M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    else:
        del (
            scope,
            observation,
            prior_records,
            artifacts,
            planned_calls,
            acquisition_artifacts,
            precedent_artifacts,
            candidate_case,
        )
        return result
    del (
        scope,
        observation,
        prior_records,
        artifacts,
        planned_calls,
        acquisition_artifacts,
        precedent_artifacts,
        candidate_case,
    )
    raise M6UpgradeWholeSampleRecordBuilderError(failure_code) from None


def build_m6_upgrade_case_replayed_model_record_v3(
    *,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    prior_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    planned_calls: tuple[M6PlannedModelCallPhysicalClosure, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
) -> M6UpgradeSampleExecutionRecordV2:
    """Compose one mixed M3/M4 pending record before any Raw or Pixel read."""

    failure_code = M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    try:
        result = _attempt_build_m6_upgrade_case_replayed_model_record_v3(
            scope=scope,
            observation=observation,
            prior_records=prior_records,
            artifacts=artifacts,
            planned_calls=planned_calls,
            candidate_case=candidate_case,
            allow_hearing=True,
        )
    except M6UpgradeWholeSampleRecordBuilderError as error:
        failure_code = error.reason_code
    except Exception:
        failure_code = M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    else:
        del scope, observation, prior_records, artifacts, planned_calls, candidate_case
        return result
    del scope, observation, prior_records, artifacts, planned_calls, candidate_case
    raise M6UpgradeWholeSampleRecordBuilderError(failure_code) from None


__all__ = [
    "M6MetadataModelCallArtifactPlan",
    "build_m6_upgrade_case_replayed_acquisition_record_v3",
    "build_m6_upgrade_case_replayed_base_record",
    "build_m6_upgrade_case_replayed_base_record_v3",
    "build_m6_upgrade_case_replayed_evidence_pack_record_v3",
    "build_m6_upgrade_case_replayed_m3_model_record_v3",
    "build_m6_upgrade_case_replayed_metadata_acquisition_record_v3",
    "build_m6_upgrade_case_replayed_metadata_model_record_v3",
    "build_m6_upgrade_case_replayed_metadata_precedent_record_v3",
    "build_m6_upgrade_case_replayed_model_record_v3",
    "build_m6_upgrade_case_replayed_precedent_record_v3",
    "build_m6_upgrade_no_case_record",
    "build_m6_upgrade_no_case_record_v3",
]

from __future__ import annotations

import traceback
from dataclasses import replace
from uuid import NAMESPACE_URL, uuid5

import pytest

import labcourt.application.m6_upgrade_whole_sample_record as subject
from labcourt.contracts.enums import ArtifactKind, AuditAction
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    M6UpgradeCandidateCaseBinding,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleArtifactLink,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
    M6UpgradeObservedModelCall,
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradeSampleExecutionObservationAuthorityV2,
    M6UpgradeSelectedCaseAuditAnchor,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.ports.m6_upgrade_model_physical import M6PlannedModelCallPhysicalClosure
from labcourt.ports.m6_upgrade_whole_sample_record_builder import (
    M6UpgradeWholeSampleRecordBuilderError,
    M6UpgradeWholeSampleRecordBuilderFailureCode,
)
from tests.integration.test_m6_upgrade_execution_ledger_repository import (
    _scope_and_no_case_records,
)


def _scope() -> M6UpgradeExecutionScopeAuthority:
    scope, _records = _scope_and_no_case_records()
    return scope


def _frame(index: int) -> M6UpgradePhysicalArtifactRef:
    return M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
        kind=M6UpgradePhysicalArtifactKind.FRAME,
        artifact_id=f"camera-builder:stream-builder:{index}",
        document_sha256=f"{index + 1:064x}",
        content_sha256=f"{index + 11:064x}",
        size_bytes=31,
    )


def _detection(frame: M6UpgradePhysicalArtifactRef, index: int) -> M6UpgradePhysicalArtifactRef:
    digest = f"{index + 21:064x}"
    return M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
        kind=M6UpgradePhysicalArtifactKind.DETECTION,
        artifact_id=f"detection-builder-{index}",
        container_id=frame.artifact_id,
        document_sha256=digest,
        content_sha256=digest,
        size_bytes=17,
    )


def _evidence_pack(index: int) -> M6UpgradePhysicalArtifactRef:
    digest = f"{index + 201:064x}"
    return M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
        kind=M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
        artifact_id=f"{index + 301:064x}",
        document_sha256=digest,
        content_sha256=digest,
        size_bytes=23 + index,
    )


def _observation(
    scope: M6UpgradeExecutionScopeAuthority,
    sequence: int,
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
) -> M6UpgradeSampleExecutionObservationAuthority:
    observed = tuple(
        sorted(
            (
                M6UpgradeObservedArtifactIdentity(
                    source=item.source,
                    kind=item.kind,
                    artifact_id=item.artifact_id,
                    usage=(
                        M6UpgradeArtifactUsage.CONSUMED
                        if item.kind == M6UpgradePhysicalArtifactKind.FRAME
                        else M6UpgradeArtifactUsage.PRODUCED
                    ),
                )
                for item in artifacts
            ),
            key=lambda item: item.sort_key,
        )
    )
    return M6UpgradeSampleExecutionObservationAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[sequence],
        ledger_sequence=sequence,
        outcome=M6ReplayExecutionOutcome.NO_CASE,
        candidate_case=None,
        artifacts=observed,
        model_calls=(),
    )


def _case_binding(case_id: str = "case-builder-base") -> M6UpgradeCandidateCaseBinding:
    return M6UpgradeCandidateCaseBinding(
        case_id=case_id,
        case_revision=1,
        case_document_sha256="a" * 64,
        case_audit_sequence=1,
        case_audit_entry_hash="b" * 64,
    )


def _v3_case_binding(label: str) -> M6UpgradeCandidateCaseBinding:
    return _case_binding(str(uuid5(NAMESPACE_URL, label)))


def _case_observation(
    scope: M6UpgradeExecutionScopeAuthority,
    sequence: int,
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
    *,
    model_calls: tuple[M6UpgradeObservedModelCall, ...] = (),
) -> M6UpgradeSampleExecutionObservationAuthority:
    observed_artifacts = tuple(
        sorted(
            (
                M6UpgradeObservedArtifactIdentity(
                    source=item.source,
                    kind=item.kind,
                    artifact_id=item.artifact_id,
                    usage=(
                        M6UpgradeArtifactUsage.CONSUMED
                        if item.kind == M6UpgradePhysicalArtifactKind.FRAME
                        else M6UpgradeArtifactUsage.PRODUCED
                    ),
                )
                for item in artifacts
            ),
            key=lambda item: item.sort_key,
        )
    )
    return M6UpgradeSampleExecutionObservationAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[sequence],
        ledger_sequence=sequence,
        outcome=M6ReplayExecutionOutcome.CASE_REPLAYED,
        candidate_case=candidate_case,
        artifacts=observed_artifacts,
        model_calls=model_calls,
    )


def _no_case_observation_v2(
    scope: M6UpgradeExecutionScopeAuthority,
    sequence: int,
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
) -> M6UpgradeSampleExecutionObservationAuthorityV2:
    legacy = _observation(scope, sequence, artifacts)
    return M6UpgradeSampleExecutionObservationAuthorityV2(
        **legacy.model_dump(
            mode="python",
            exclude={"schema_version"},
            exclude_computed_fields=True,
        ),
        selected_case_audit_anchor=None,
    )


def _case_observation_v2(
    scope: M6UpgradeExecutionScopeAuthority,
    sequence: int,
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    candidate_case: M6UpgradeCandidateCaseBinding,
    *,
    model_calls: tuple[M6UpgradeObservedModelCall, ...] = (),
) -> M6UpgradeSampleExecutionObservationAuthorityV2:
    legacy = _case_observation(
        scope,
        sequence,
        artifacts,
        candidate_case,
        model_calls=model_calls,
    )
    anchor = M6UpgradeSelectedCaseAuditAnchor(
        candidate_case_binding_id=candidate_case.case_binding_id,
        action=AuditAction.CASE_CREATED,
        object_ref=ArtifactRef(
            kind=ArtifactKind.CASE,
            artifact_id=candidate_case.case_id,
        ),
    )
    return M6UpgradeSampleExecutionObservationAuthorityV2(
        **legacy.model_dump(
            mode="python",
            exclude={"schema_version"},
            exclude_computed_fields=True,
        ),
        selected_case_audit_anchor=anchor,
    )


def _model_ref(
    kind: M6UpgradePhysicalArtifactKind,
    seed: int,
    *,
    artifact_id: str | None = None,
    size_bytes: int = 19,
) -> M6UpgradePhysicalArtifactRef:
    document_sha256 = f"{seed + 1_000:064x}"
    return M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        kind=kind,
        artifact_id=artifact_id or f"{seed + 2_000:064x}",
        document_sha256=document_sha256,
        content_sha256=(
            f"{seed + 3_000:064x}"
            if kind == M6UpgradePhysicalArtifactKind.MODEL_RESPONSE
            else document_sha256
        ),
        size_bytes=size_bytes,
    )


def _planned_m3_call(
    scope: M6UpgradeExecutionScopeAuthority,
    candidate_case: M6UpgradeCandidateCaseBinding,
    *,
    seed: int = 0,
    attempt_index: int = 0,
    result_kind: M6LockedModelCallResultKind = M6LockedModelCallResultKind.RESPONSE,
    include_parsed_output: bool = True,
) -> M6PlannedModelCallPhysicalClosure:
    request_id = f"{seed + 101:064x}"
    common = {
        "source_identity_sha256": "7" * 64,
        "run_id": scope.candidate_run_id,
        "case_id": candidate_case.case_id,
        "manifest_id": scope.candidate_manifest.manifest_id,
        "layer": M6LockedModelCallLayer.SCREENING,
        "role": M6LockedModelRole.SCREENING,
        "attempt_index": attempt_index,
        "timeout_ms": 1,
        "execution_model_manifest_id": scope.candidate_manifest.models[
            "screening"
        ].model_manifest_id,
        "request_ref": _model_ref(
            M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
            seed * 10,
            artifact_id=request_id,
        ),
        "result_kind": result_kind,
    }
    if result_kind == M6LockedModelCallResultKind.FAILURE:
        return M6PlannedModelCallPhysicalClosure(
            **common,
            failure_ref=_model_ref(
                M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
                seed * 10 + 6,
            ),
        )
    return M6PlannedModelCallPhysicalClosure(
        **common,
        response_ref=_model_ref(
            M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
            seed * 10 + 1,
        ),
        cache_ref=_model_ref(
            M6UpgradePhysicalArtifactKind.MODEL_CACHE,
            seed * 10 + 2,
        ),
        parse_receipt_ref=_model_ref(
            M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
            seed * 10 + 3,
        ),
        parsed_output_ref=(
            _model_ref(
                M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
                seed * 10 + 4,
            )
            if include_parsed_output
            else None
        ),
        usage_receipt_ref=_model_ref(
            M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
            seed * 10 + 5,
        ),
    )


def _observed_model_call(
    planned: M6PlannedModelCallPhysicalClosure,
    *,
    provider_invoked: bool,
) -> M6UpgradeObservedModelCall:
    return M6UpgradeObservedModelCall(
        request_id=planned.request_ref.artifact_id,
        layer=planned.layer,
        role=planned.role,
        attempt_index=planned.attempt_index,
        result_kind=planned.result_kind,
        provider_invoked=provider_invoked,
    )


def test_no_case_record_derives_chain_and_stable_physical_ordinals() -> None:
    scope = _scope()
    first_frame = _frame(0)
    first_detection = _detection(first_frame, 0)
    first_observation = _observation(scope, 0, (first_frame, first_detection))

    first = subject.build_m6_upgrade_no_case_record(
        scope=scope,
        observation=first_observation,
        prior_records=(),
        artifacts=(first_detection, first_frame),
    )

    assert first.ledger_sequence == 0
    assert first.previous_ledger_entry_hash == M6_UPGRADE_LEDGER_GENESIS_HASH
    assert tuple(link.ordinal for link in first.artifact_links) == (0, 1)
    assert tuple(link.physical_key for link in first.artifact_links) == tuple(
        sorted(link.physical_key for link in first.artifact_links)
    )
    assert first.observation_authority_id == first_observation.observation_authority_id

    second_frame = _frame(1)
    second_observation = _observation(scope, 1, (second_frame,))
    second = subject.build_m6_upgrade_no_case_record(
        scope=scope,
        observation=second_observation,
        prior_records=(first,),
        artifacts=(second_frame,),
    )
    assert second.ledger_sequence == 1
    assert second.previous_ledger_entry_hash == first.sample_execution_record_id


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        ("missing", M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH),
        ("extra", M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH),
        ("wrong_route", M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED),
    ),
)
def test_no_case_record_rejects_non_bijective_or_unsupported_closure(
    mutation: str,
    expected: M6UpgradeWholeSampleRecordBuilderFailureCode,
) -> None:
    scope = _scope()
    frame = _frame(0)
    detection = _detection(frame, 0)
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...]
    if mutation == "missing":
        observation = _observation(scope, 0, (frame, detection))
        artifacts = (frame,)
    elif mutation == "extra":
        observation = _observation(scope, 0, (frame,))
        artifacts = (frame, detection)
    else:
        observation = _observation(scope, 0, (frame,))
        digest = "f" * 64
        artifacts = (
            M6UpgradePhysicalArtifactRef(
                source=M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
                kind=M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
                artifact_id="unsupported-no-case-pack",
                document_sha256=digest,
                content_sha256=digest,
                size_bytes=1,
            ),
        )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_no_case_record(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=artifacts,
        )
    assert raised.value.reason_code == expected


def test_physical_budget_fails_before_a_record_is_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _scope()
    frame = _frame(0)
    detection = _detection(frame, 0)
    observation = _observation(scope, 0, (frame, detection))
    monkeypatch.setattr(
        subject,
        "MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES",
        frame.size_bytes + detection.size_bytes - 1,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_no_case_record(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=(frame, detection),
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.PHYSICAL_BYTE_LIMIT_EXCEEDED
    )


def test_exact_pending_record_can_be_compared_without_recomposition_inputs() -> None:
    scope = _scope()
    frame = _frame(0)
    observation = _observation(scope, 0, (frame,))
    first = subject.build_m6_upgrade_no_case_record(
        scope=scope,
        observation=observation,
        prior_records=(),
        artifacts=(frame,),
    )
    retry = subject.build_m6_upgrade_no_case_record(
        scope=scope,
        observation=observation,
        prior_records=(),
        artifacts=(frame,),
    )
    assert type(first) is M6UpgradeSampleExecutionRecordV2
    assert retry == first


def test_v2_and_v3_composers_require_their_exact_observation_model() -> None:
    scope = _scope()
    frame = _frame(0)
    legacy = _observation(scope, 0, (frame,))
    current = M6UpgradeSampleExecutionObservationAuthorityV2.model_validate(
        {
            **legacy.model_dump(mode="json", exclude_computed_fields=True),
            "schema_version": ("m6-upgrade-sample-execution-observation-authority-v2"),
            "selected_case_audit_anchor": None,
        }
    )

    record = subject.build_m6_upgrade_no_case_record_v3(
        scope=scope,
        observation=current,
        prior_records=(),
        artifacts=(frame,),
    )
    assert record.observation_authority_id == current.observation_authority_id

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as old_rejects_new:
        subject.build_m6_upgrade_no_case_record(
            scope=scope,
            observation=current,
            prior_records=(),
            artifacts=(frame,),
        )
    assert old_rejects_new.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as new_rejects_old:
        subject.build_m6_upgrade_no_case_record_v3(
            scope=scope,
            observation=legacy,  # type: ignore[arg-type]
            prior_records=(),
            artifacts=(frame,),
        )
    assert new_rejects_old.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID
    )


def test_v3_evidence_pack_record_closes_exact_observation_and_preserves_usage() -> None:
    scope = _scope()
    frame = _frame(0)
    detection = _detection(frame, 0)
    pack = _evidence_pack(0)
    candidate_case = _v3_case_binding("case-builder-v3-evidence")
    observation = _case_observation_v2(
        scope,
        0,
        (frame, detection, pack),
        candidate_case,
    )

    record = subject.build_m6_upgrade_case_replayed_evidence_pack_record_v3(
        scope=scope,
        observation=observation,
        prior_records=(),
        artifacts=(pack, detection, frame),
        candidate_case=candidate_case,
    )

    assert type(record) is M6UpgradeSampleExecutionRecordV2
    assert record.candidate_case == candidate_case
    assert record.observation_authority_id == observation.observation_authority_id
    assert tuple(link.artifact for link in record.artifact_links) == tuple(
        sorted((frame, detection, pack), key=lambda item: item.physical_key)
    )
    pack_link = next(
        link
        for link in record.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.EVIDENCE_PACK
    )
    assert pack_link.usage == M6UpgradeArtifactUsage.PRODUCED


def test_v3_evidence_pack_record_requires_exact_observation_v2_and_case_binding() -> None:
    scope = _scope()
    frame = _frame(0)
    pack = _evidence_pack(0)
    observed_case = _v3_case_binding("case-builder-v3-evidence-observed")
    supplied_case = _v3_case_binding("case-builder-v3-evidence-supplied")

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as legacy_rejected:
        subject.build_m6_upgrade_case_replayed_evidence_pack_record_v3(
            scope=scope,
            observation=_case_observation(scope, 0, (frame, pack), observed_case),  # type: ignore[arg-type]
            prior_records=(),
            artifacts=(frame, pack),
            candidate_case=observed_case,
        )
    assert legacy_rejected.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as binding_rejected:
        subject.build_m6_upgrade_case_replayed_evidence_pack_record_v3(
            scope=scope,
            observation=_case_observation_v2(scope, 0, (frame, pack), observed_case),
            prior_records=(),
            artifacts=(frame, pack),
            candidate_case=supplied_case,
        )
    assert binding_rejected.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH
    )


def test_v3_evidence_pack_record_does_not_infer_unobserved_case_inventory() -> None:
    scope = _scope()
    frame = _frame(0)
    simulated_case_inventory = (_evidence_pack(0), _evidence_pack(1))
    observed_pack = simulated_case_inventory[1]
    candidate_case = _v3_case_binding("case-builder-v3-selected-pack")
    observation = _case_observation_v2(
        scope,
        0,
        (frame, observed_pack),
        candidate_case,
    )

    record = subject.build_m6_upgrade_case_replayed_evidence_pack_record_v3(
        scope=scope,
        observation=observation,
        prior_records=(),
        artifacts=(frame, observed_pack),
        candidate_case=candidate_case,
    )

    assert tuple(
        link.artifact
        for link in record.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.EVIDENCE_PACK
    ) == (observed_pack,)
    assert simulated_case_inventory[0] not in tuple(link.artifact for link in record.artifact_links)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        ("missing", M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH),
        ("extra", M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH),
        ("duplicate", M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT),
        ("wrong_source", M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED),
        ("wrong_kind", M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED),
    ),
)
def test_v3_evidence_pack_record_rejects_non_exact_or_wrong_route_closure(
    mutation: str,
    expected: M6UpgradeWholeSampleRecordBuilderFailureCode,
) -> None:
    scope = _scope()
    frame = _frame(0)
    pack = _evidence_pack(0)
    candidate_case = _v3_case_binding("case-builder-v3-evidence-invalid")
    observation_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...] = (frame, pack)
    supplied_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...]
    if mutation == "missing":
        supplied_artifacts = (frame,)
    elif mutation == "extra":
        observation_artifacts = (frame,)
        supplied_artifacts = (frame, pack)
    elif mutation == "duplicate":
        supplied_artifacts = (frame, pack, pack)
    elif mutation == "wrong_source":
        payload = pack.model_dump(mode="python", exclude_computed_fields=True)
        payload["source"] = M6UpgradePhysicalArtifactSource.M2_PERCEPTION
        wrong_source = M6UpgradePhysicalArtifactRef.model_construct(**payload)
        supplied_artifacts = (frame, wrong_source)
    else:
        digest = "e" * 64
        wrong_kind = M6UpgradePhysicalArtifactRef(
            source=M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
            kind=M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
            artifact_id="case-builder-v3-wrong-kind",
            document_sha256=digest,
            content_sha256=digest,
            size_bytes=pack.size_bytes,
        )
        supplied_artifacts = (frame, wrong_kind)
    observation = _case_observation_v2(
        scope,
        0,
        observation_artifacts,
        candidate_case,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_evidence_pack_record_v3(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=supplied_artifacts,
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == expected


def test_v3_evidence_pack_record_rejects_consumed_pack_observation() -> None:
    scope = _scope()
    frame = _frame(0)
    pack = _evidence_pack(0)
    candidate_case = _v3_case_binding("case-builder-v3-evidence-usage")
    observation = _case_observation_v2(scope, 0, (frame, pack), candidate_case)
    invalid_artifacts = tuple(
        M6UpgradeObservedArtifactIdentity.model_construct(
            **{
                **{
                    field: getattr(item, field)
                    for field in M6UpgradeObservedArtifactIdentity.model_fields
                },
                "usage": M6UpgradeArtifactUsage.CONSUMED,
            }
        )
        if item.kind == M6UpgradePhysicalArtifactKind.EVIDENCE_PACK
        else item
        for item in observation.artifacts
    )
    invalid_observation = M6UpgradeSampleExecutionObservationAuthorityV2.model_construct(
        **{
            **{
                field: getattr(observation, field)
                for field in M6UpgradeSampleExecutionObservationAuthorityV2.model_fields
            },
            "artifacts": invalid_artifacts,
        }
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_evidence_pack_record_v3(
            scope=scope,
            observation=invalid_observation,
            prior_records=(),
            artifacts=(frame, pack),
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID
    )


def test_legacy_and_v3_base_composers_keep_evidence_pack_route_closed() -> None:
    scope = _scope()
    frame = _frame(0)
    pack = _evidence_pack(0)
    candidate_case = _v3_case_binding("case-builder-base-stays-closed")
    legacy_case = _case_observation(scope, 0, (frame, pack), candidate_case)
    current_case = _case_observation_v2(scope, 0, (frame, pack), candidate_case)
    current_no_case = _no_case_observation_v2(scope, 0, (frame,))

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as legacy_case_rejects:
        subject.build_m6_upgrade_case_replayed_base_record(
            scope=scope,
            observation=legacy_case,
            prior_records=(),
            artifacts=(frame, pack),
            candidate_case=candidate_case,
        )
    assert legacy_case_rejects.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as current_case_rejects:
        subject.build_m6_upgrade_case_replayed_base_record_v3(
            scope=scope,
            observation=current_case,
            prior_records=(),
            artifacts=(frame, pack),
            candidate_case=candidate_case,
        )
    assert current_case_rejects.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as no_case_rejects:
        subject.build_m6_upgrade_no_case_record_v3(
            scope=scope,
            observation=current_no_case,
            prior_records=(),
            artifacts=(frame, pack),
        )
    assert no_case_rejects.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED
    )


def test_v3_prefix_with_evidence_pack_allows_later_no_case_and_base_case() -> None:
    scope = _scope()
    first_frame = _frame(0)
    pack = _evidence_pack(0)
    first_case = _v3_case_binding("case-builder-v3-pack-prefix")
    first = subject.build_m6_upgrade_case_replayed_evidence_pack_record_v3(
        scope=scope,
        observation=_case_observation_v2(
            scope,
            0,
            (first_frame, pack),
            first_case,
        ),
        prior_records=(),
        artifacts=(first_frame, pack),
        candidate_case=first_case,
    )

    second_frame = _frame(1)
    second = subject.build_m6_upgrade_no_case_record_v3(
        scope=scope,
        observation=_no_case_observation_v2(scope, 1, (second_frame,)),
        prior_records=(first,),
        artifacts=(second_frame,),
    )
    assert second.previous_ledger_entry_hash == first.sample_execution_record_id

    third_frame = _frame(2)
    third_case = _v3_case_binding("case-builder-v3-base-after-pack")
    third = subject.build_m6_upgrade_case_replayed_base_record_v3(
        scope=scope,
        observation=_case_observation_v2(scope, 2, (third_frame,), third_case),
        prior_records=(first, second),
        artifacts=(third_frame,),
        candidate_case=third_case,
    )
    assert third.previous_ledger_entry_hash == second.sample_execution_record_id

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as legacy_rejects_prefix:
        subject.build_m6_upgrade_no_case_record(
            scope=scope,
            observation=_observation(scope, 1, (second_frame,)),
            prior_records=(first,),
            artifacts=(second_frame,),
        )
    assert legacy_rejects_prefix.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED
    )


@pytest.mark.parametrize(
    ("budget", "expected"),
    (
        ("links", M6UpgradeWholeSampleRecordBuilderFailureCode.LINK_LIMIT_EXCEEDED),
        (
            "physical",
            M6UpgradeWholeSampleRecordBuilderFailureCode.PHYSICAL_BYTE_LIMIT_EXCEEDED,
        ),
        ("record", M6UpgradeWholeSampleRecordBuilderFailureCode.RECORD_TOO_LARGE),
    ),
)
def test_v3_evidence_pack_record_keeps_all_sample_budgets(
    monkeypatch: pytest.MonkeyPatch,
    budget: str,
    expected: M6UpgradeWholeSampleRecordBuilderFailureCode,
) -> None:
    scope = _scope()
    frame = _frame(0)
    pack = _evidence_pack(0)
    candidate_case = _v3_case_binding("case-builder-v3-evidence-budget")
    if budget == "links":
        monkeypatch.setattr(subject, "MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE", 1)
    elif budget == "physical":
        monkeypatch.setattr(
            subject,
            "MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES",
            frame.size_bytes + pack.size_bytes - 1,
        )
    else:
        monkeypatch.setattr(
            subject,
            "MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES",
            1,
        )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_evidence_pack_record_v3(
            scope=scope,
            observation=_case_observation_v2(
                scope,
                0,
                (frame, pack),
                candidate_case,
            ),
            prior_records=(),
            artifacts=(frame, pack),
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == expected


def test_v3_evidence_pack_record_keeps_prefix_identity_conflicts_closed() -> None:
    scope = _scope()
    first_frame = _frame(0)
    pack = _evidence_pack(0)
    first_case = _v3_case_binding("case-builder-v3-pack-identity-first")
    first = subject.build_m6_upgrade_case_replayed_evidence_pack_record_v3(
        scope=scope,
        observation=_case_observation_v2(
            scope,
            0,
            (first_frame, pack),
            first_case,
        ),
        prior_records=(),
        artifacts=(first_frame, pack),
        candidate_case=first_case,
    )
    changed_pack = pack.model_copy(update={"document_sha256": "f" * 64, "content_sha256": "f" * 64})
    second_frame = _frame(1)
    second_case = _v3_case_binding("case-builder-v3-pack-identity-second")

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_evidence_pack_record_v3(
            scope=scope,
            observation=_case_observation_v2(
                scope,
                1,
                (second_frame, changed_pack),
                second_case,
            ),
            prior_records=(first,),
            artifacts=(second_frame, changed_pack),
            candidate_case=second_case,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT
    )


@pytest.mark.parametrize(
    ("provider_invoked", "expected_cache_usage"),
    (
        (True, M6UpgradeArtifactUsage.PRODUCED),
        (False, M6UpgradeArtifactUsage.CONSUMED),
    ),
)
def test_v3_m3_model_record_closes_response_plan_and_derives_cache_usage(
    provider_invoked: bool,
    expected_cache_usage: M6UpgradeArtifactUsage,
) -> None:
    scope = _scope()
    frame = _frame(0)
    pack = _evidence_pack(0)
    candidate_case = _v3_case_binding(f"case-builder-m3-response-{provider_invoked}")
    planned = _planned_m3_call(scope, candidate_case)
    observation = _case_observation_v2(
        scope,
        0,
        (frame, pack),
        candidate_case,
        model_calls=(_observed_model_call(planned, provider_invoked=provider_invoked),),
    )

    record = subject.build_m6_upgrade_case_replayed_m3_model_record_v3(
        scope=scope,
        observation=observation,
        prior_records=(),
        artifacts=(pack, frame),
        planned_calls=(planned,),
        candidate_case=candidate_case,
    )

    assert tuple(link.artifact for link in record.artifact_links) == tuple(
        sorted((frame, pack, *planned.artifact_refs), key=lambda item: item.physical_key)
    )
    cache_link = next(
        link
        for link in record.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.MODEL_CACHE
    )
    assert cache_link.usage == expected_cache_usage
    assert all(
        link.usage == M6UpgradeArtifactUsage.PRODUCED
        for link in record.artifact_links
        if link.artifact.source == M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL
        and link.artifact.kind != M6UpgradePhysicalArtifactKind.MODEL_CACHE
    )


def test_v3_m3_model_record_closes_failure_plan() -> None:
    scope = _scope()
    frame = _frame(0)
    candidate_case = _v3_case_binding("case-builder-m3-failure")
    planned = _planned_m3_call(
        scope,
        candidate_case,
        result_kind=M6LockedModelCallResultKind.FAILURE,
    )
    observation = _case_observation_v2(
        scope,
        0,
        (frame,),
        candidate_case,
        model_calls=(_observed_model_call(planned, provider_invoked=True),),
    )

    record = subject.build_m6_upgrade_case_replayed_m3_model_record_v3(
        scope=scope,
        observation=observation,
        prior_records=(),
        artifacts=(frame,),
        planned_calls=(planned,),
        candidate_case=candidate_case,
    )

    assert {
        link.artifact.kind
        for link in record.artifact_links
        if link.artifact.source == M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL
    } == {
        M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
        M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
    }
    assert all(
        link.usage == M6UpgradeArtifactUsage.PRODUCED
        for link in record.artifact_links
        if link.artifact.source == M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL
    )


def test_v3_m3_model_record_joins_repair_attempts_by_request_and_sorts_links() -> None:
    scope = _scope()
    frame = _frame(0)
    candidate_case = _v3_case_binding("case-builder-m3-repair")
    initial = _planned_m3_call(
        scope,
        candidate_case,
        seed=0,
        attempt_index=0,
        result_kind=M6LockedModelCallResultKind.FAILURE,
    )
    repair = _planned_m3_call(
        scope,
        candidate_case,
        seed=1,
        attempt_index=1,
    )
    observed_calls = tuple(
        sorted(
            (
                _observed_model_call(initial, provider_invoked=True),
                _observed_model_call(repair, provider_invoked=False),
            ),
            key=lambda item: item.sort_key,
        )
    )
    observation = _case_observation_v2(
        scope,
        0,
        (frame,),
        candidate_case,
        model_calls=observed_calls,
    )

    record = subject.build_m6_upgrade_case_replayed_m3_model_record_v3(
        scope=scope,
        observation=observation,
        prior_records=(),
        artifacts=(frame,),
        planned_calls=(initial, repair),
        candidate_case=candidate_case,
    )

    assert tuple(link.physical_key for link in record.artifact_links) == tuple(
        sorted(link.physical_key for link in record.artifact_links)
    )
    assert {
        link.artifact.artifact_id
        for link in record.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.MODEL_REQUEST
    } == {initial.request_ref.artifact_id, repair.request_ref.artifact_id}


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        (
            "missing_call",
            M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH,
        ),
        (
            "extra_call",
            M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH,
        ),
        (
            "attempt_mismatch",
            M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH,
        ),
        (
            "result_mismatch",
            M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH,
        ),
        (
            "unstable_order",
            M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH,
        ),
        ("wrong_layer", M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED),
        ("wrong_source", M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED),
        (
            "wrong_case",
            M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH,
        ),
        (
            "duplicate_ref",
            M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT,
        ),
    ),
)
def test_v3_m3_model_record_rejects_non_exact_call_or_physical_closure(
    mutation: str,
    expected: M6UpgradeWholeSampleRecordBuilderFailureCode,
) -> None:
    scope = _scope()
    frame = _frame(0)
    candidate_case = _v3_case_binding(f"case-builder-m3-invalid-{mutation}")
    planned = _planned_m3_call(scope, candidate_case)
    observed = _observed_model_call(planned, provider_invoked=True)
    planned_calls = (planned,)
    observed_calls = (observed,)
    if mutation == "missing_call":
        planned_calls = ()
    elif mutation == "extra_call":
        planned_calls = (planned, _planned_m3_call(scope, candidate_case, seed=1))
    elif mutation == "attempt_mismatch":
        observed_calls = (
            M6UpgradeObservedModelCall(
                request_id=observed.request_id,
                layer=observed.layer,
                role=observed.role,
                attempt_index=1,
                result_kind=observed.result_kind,
                provider_invoked=observed.provider_invoked,
            ),
        )
    elif mutation == "result_mismatch":
        observed_calls = (
            M6UpgradeObservedModelCall(
                request_id=observed.request_id,
                layer=observed.layer,
                role=observed.role,
                attempt_index=observed.attempt_index,
                result_kind=M6LockedModelCallResultKind.FAILURE,
                provider_invoked=observed.provider_invoked,
            ),
        )
    elif mutation == "wrong_layer":
        observed_calls = (
            M6UpgradeObservedModelCall(
                request_id=observed.request_id,
                layer=M6LockedModelCallLayer.HEARING,
                role=M6LockedModelRole.PROSECUTOR,
                attempt_index=observed.attempt_index,
                result_kind=observed.result_kind,
                provider_invoked=observed.provider_invoked,
            ),
        )
    elif mutation == "wrong_source":
        response_ref = planned.response_ref
        assert response_ref is not None
        wrong_source = M6UpgradePhysicalArtifactRef.model_construct(
            **{
                **response_ref.model_dump(mode="python", exclude_computed_fields=True),
                "source": M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
            }
        )
        object.__setattr__(planned, "response_ref", wrong_source)
    elif mutation == "wrong_case":
        planned_calls = (replace(planned, case_id="different-selected-case"),)
    elif mutation == "unstable_order":
        second = _planned_m3_call(scope, candidate_case, seed=1)
        planned_calls = (second, planned)
        observed_calls = tuple(
            sorted(
                (
                    observed,
                    _observed_model_call(second, provider_invoked=True),
                ),
                key=lambda item: item.sort_key,
            )
        )
    else:
        second = _planned_m3_call(scope, candidate_case, seed=1)
        assert planned.cache_ref is not None
        second = replace(second, cache_ref=planned.cache_ref)
        planned_calls = (planned, second)
        observed_calls = tuple(
            sorted(
                (
                    observed,
                    _observed_model_call(second, provider_invoked=True),
                ),
                key=lambda item: item.sort_key,
            )
        )
    observation = _case_observation_v2(
        scope,
        0,
        (frame,),
        candidate_case,
        model_calls=observed_calls,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_m3_model_record_v3(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=(frame,),
            planned_calls=planned_calls,
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == expected


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        (
            "missing",
            M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH,
        ),
        (
            "extra",
            M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH,
        ),
        ("duplicate", M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT),
    ),
)
def test_v3_m3_model_record_requires_exact_ordinary_physical_set(
    mutation: str,
    expected: M6UpgradeWholeSampleRecordBuilderFailureCode,
) -> None:
    scope = _scope()
    frame = _frame(0)
    pack = _evidence_pack(0)
    candidate_case = _v3_case_binding(f"case-builder-m3-ordinary-{mutation}")
    planned = _planned_m3_call(scope, candidate_case)
    observed_artifacts = (frame, pack)
    physical_artifacts = (frame, pack)
    if mutation == "missing":
        physical_artifacts = (frame,)
    elif mutation == "extra":
        observed_artifacts = (frame,)
    else:
        physical_artifacts = (frame, pack, pack)
    observation = _case_observation_v2(
        scope,
        0,
        observed_artifacts,
        candidate_case,
        model_calls=(_observed_model_call(planned, provider_invoked=True),),
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_m3_model_record_v3(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=physical_artifacts,
            planned_calls=(planned,),
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == expected


@pytest.mark.parametrize(
    "mutation",
    ("source_identity", "candidate_run", "candidate_manifest"),
)
def test_v3_m3_model_record_rejects_mixed_or_foreign_call_scope(mutation: str) -> None:
    scope = _scope()
    frame = _frame(0)
    candidate_case = _v3_case_binding(f"case-builder-m3-call-scope-{mutation}")
    first = _planned_m3_call(scope, candidate_case, seed=0)
    planned_calls = (first,)
    observed_calls = (_observed_model_call(first, provider_invoked=True),)
    if mutation == "source_identity":
        second = replace(
            _planned_m3_call(scope, candidate_case, seed=1),
            source_identity_sha256="9" * 64,
        )
        planned_calls = (first, second)
        observed_calls = tuple(
            sorted(
                (
                    observed_calls[0],
                    _observed_model_call(second, provider_invoked=True),
                ),
                key=lambda item: item.sort_key,
            )
        )
    elif mutation == "candidate_run":
        planned_calls = (replace(first, run_id="foreign-candidate-run"),)
    else:
        planned_calls = (replace(first, manifest_id="e" * 64),)
    observation = _case_observation_v2(
        scope,
        0,
        (frame,),
        candidate_case,
        model_calls=observed_calls,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_m3_model_record_v3(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=(frame,),
            planned_calls=planned_calls,
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    )


@pytest.mark.parametrize("mutation", ("manifest", "timeout"))
def test_v3_m3_model_record_binds_execution_manifest_and_provider_timeout(
    mutation: str,
) -> None:
    scope = _scope()
    frame = _frame(0)
    candidate_case = _v3_case_binding(f"case-builder-m3-scope-{mutation}")
    planned = _planned_m3_call(scope, candidate_case)
    observed = _observed_model_call(planned, provider_invoked=True)
    if mutation == "manifest":
        planned = replace(planned, execution_model_manifest_id="f" * 64)
    else:
        profile = scope.candidate_config.providers[
            scope.candidate_config.screening.provider_profile
        ]
        object.__setattr__(planned, "timeout_ms", int(profile.timeout_seconds * 1_000) + 1)
    observation = _case_observation_v2(
        scope,
        0,
        (frame,),
        candidate_case,
        model_calls=(observed,),
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_m3_model_record_v3(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=(frame,),
            planned_calls=(planned,),
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    )


@pytest.mark.parametrize(
    ("budget", "expected"),
    (
        ("links", M6UpgradeWholeSampleRecordBuilderFailureCode.LINK_LIMIT_EXCEEDED),
        (
            "physical",
            M6UpgradeWholeSampleRecordBuilderFailureCode.PHYSICAL_BYTE_LIMIT_EXCEEDED,
        ),
        ("record", M6UpgradeWholeSampleRecordBuilderFailureCode.RECORD_TOO_LARGE),
    ),
)
def test_v3_m3_model_record_counts_model_refs_in_every_sample_budget(
    monkeypatch: pytest.MonkeyPatch,
    budget: str,
    expected: M6UpgradeWholeSampleRecordBuilderFailureCode,
) -> None:
    scope = _scope()
    frame = _frame(0)
    candidate_case = _v3_case_binding(f"case-builder-m3-budget-{budget}")
    planned = _planned_m3_call(scope, candidate_case)
    observation = _case_observation_v2(
        scope,
        0,
        (frame,),
        candidate_case,
        model_calls=(_observed_model_call(planned, provider_invoked=True),),
    )
    if budget == "links":
        monkeypatch.setattr(subject, "MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE", 1)
    elif budget == "physical":
        monkeypatch.setattr(
            subject,
            "MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES",
            frame.size_bytes + sum(ref.size_bytes for ref in planned.artifact_refs) - 1,
        )
    else:
        monkeypatch.setattr(
            subject,
            "MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES",
            1,
        )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_m3_model_record_v3(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=(frame,),
            planned_calls=(planned,),
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == expected


def _assert_m3_composer_failure_is_payload_free(
    error: M6UpgradeWholeSampleRecordBuilderError,
    *,
    secret: str,
) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
    assert secret not in rendered
    public_frames = []
    current = error.__traceback__
    while current is not None:
        if (
            current.tb_frame.f_globals.get("__name__") == subject.__name__
            and current.tb_frame.f_code.co_name
            == "build_m6_upgrade_case_replayed_m3_model_record_v3"
        ):
            public_frames.append(current.tb_frame)
        current = current.tb_next
    assert len(public_frames) == 1
    public_locals = public_frames[0].f_locals
    assert {
        "self",
        "scope",
        "observation",
        "prior_records",
        "artifacts",
        "planned_calls",
        "candidate_case",
    }.isdisjoint(public_locals)
    assert not any(name.startswith("controlled") for name in public_locals)


def test_v3_m3_composer_sanitizes_typed_failure_after_private_frames_unwind() -> None:
    secret = "secret-authority-alice"
    scope = _scope()
    frame = _frame(0)
    candidate_case = _v3_case_binding("case-builder-m3-payload-typed")
    planned = _planned_m3_call(scope, candidate_case)
    observation = _case_observation_v2(
        scope,
        0,
        (frame,),
        candidate_case,
        model_calls=(_observed_model_call(planned, provider_invoked=True),),
    )
    distorted = replace(planned, case_id=secret)
    object.__setattr__(distorted, "timeout_ms", 0)

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_m3_model_record_v3(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=(frame,),
            planned_calls=(distorted,),
            candidate_case=candidate_case,
        )

    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    )
    _assert_m3_composer_failure_is_payload_free(raised.value, secret=secret)


def test_v3_m3_composer_sanitizes_unexpected_failure_with_fixed_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "secret unexpected composer payload"
    scope = _scope()
    frame = _frame(0)
    candidate_case = _v3_case_binding("case-builder-m3-payload-unexpected")
    planned = _planned_m3_call(scope, candidate_case)
    observation = _case_observation_v2(
        scope,
        0,
        (frame,),
        candidate_case,
        model_calls=(_observed_model_call(planned, provider_invoked=True),),
    )

    def unexpected(**_kwargs: object) -> M6UpgradeSampleExecutionRecordV2:
        raise RuntimeError(secret)

    monkeypatch.setattr(
        subject,
        "_attempt_build_m6_upgrade_case_replayed_m3_model_record_v3",
        unexpected,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_m3_model_record_v3(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=(frame,),
            planned_calls=(planned,),
            candidate_case=candidate_case,
        )

    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    )
    _assert_m3_composer_failure_is_payload_free(raised.value, secret=secret)


def test_v3_base_routes_still_reject_current_model_calls_and_refs() -> None:
    scope = _scope()
    frame = _frame(0)
    candidate_case = _v3_case_binding("case-builder-m3-base-stays-closed")
    planned = _planned_m3_call(scope, candidate_case)
    observation = _case_observation_v2(
        scope,
        0,
        (frame,),
        candidate_case,
        model_calls=(_observed_model_call(planned, provider_invoked=True),),
    )

    for build in (
        subject.build_m6_upgrade_case_replayed_base_record_v3,
        subject.build_m6_upgrade_case_replayed_evidence_pack_record_v3,
    ):
        with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as call_rejected:
            build(
                scope=scope,
                observation=observation,
                prior_records=(),
                artifacts=(frame,),
                candidate_case=candidate_case,
            )
        assert call_rejected.value.reason_code == (
            M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED
        )

    no_model_observation = _case_observation_v2(
        scope,
        0,
        (frame,),
        candidate_case,
    )
    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as ref_rejected:
        subject.build_m6_upgrade_case_replayed_evidence_pack_record_v3(
            scope=scope,
            observation=no_model_observation,
            prior_records=(),
            artifacts=(frame, planned.request_ref),
            candidate_case=candidate_case,
        )
    assert ref_rejected.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED
    )


def test_v3_m3_prefix_allows_later_no_case_and_new_case_but_not_duplicate_or_v1() -> None:
    scope = _scope()
    first_frame = _frame(0)
    first_case = _v3_case_binding("case-builder-m3-prefix-first")
    planned = _planned_m3_call(scope, first_case)
    first = subject.build_m6_upgrade_case_replayed_m3_model_record_v3(
        scope=scope,
        observation=_case_observation_v2(
            scope,
            0,
            (first_frame,),
            first_case,
            model_calls=(_observed_model_call(planned, provider_invoked=True),),
        ),
        prior_records=(),
        artifacts=(first_frame,),
        planned_calls=(planned,),
        candidate_case=first_case,
    )

    second_frame = _frame(1)
    second = subject.build_m6_upgrade_no_case_record_v3(
        scope=scope,
        observation=_no_case_observation_v2(scope, 1, (second_frame,)),
        prior_records=(first,),
        artifacts=(second_frame,),
    )
    third_frame = _frame(2)
    third_case = _v3_case_binding("case-builder-m3-prefix-third")
    third = subject.build_m6_upgrade_case_replayed_base_record_v3(
        scope=scope,
        observation=_case_observation_v2(scope, 2, (third_frame,), third_case),
        prior_records=(first, second),
        artifacts=(third_frame,),
        candidate_case=third_case,
    )
    assert third.previous_ledger_entry_hash == second.sample_execution_record_id

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as duplicate_rejected:
        subject.build_m6_upgrade_case_replayed_base_record_v3(
            scope=scope,
            observation=_case_observation_v2(scope, 1, (second_frame,), first_case),
            prior_records=(first,),
            artifacts=(second_frame,),
            candidate_case=first_case,
        )
    assert duplicate_rejected.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_PREFIX_MISMATCH
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as legacy_rejected:
        subject.build_m6_upgrade_no_case_record(
            scope=scope,
            observation=_observation(scope, 1, (second_frame,)),
            prior_records=(first,),
            artifacts=(second_frame,),
        )
    assert legacy_rejected.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED
    )


def test_v3_m3_model_record_keeps_cross_sample_model_identity_closed() -> None:
    scope = _scope()
    first_frame = _frame(0)
    first_case = _v3_case_binding("case-builder-m3-identity-first")
    first_plan = _planned_m3_call(scope, first_case)
    first = subject.build_m6_upgrade_case_replayed_m3_model_record_v3(
        scope=scope,
        observation=_case_observation_v2(
            scope,
            0,
            (first_frame,),
            first_case,
            model_calls=(_observed_model_call(first_plan, provider_invoked=True),),
        ),
        prior_records=(),
        artifacts=(first_frame,),
        planned_calls=(first_plan,),
        candidate_case=first_case,
    )
    changed_request = first_plan.request_ref.model_copy(
        update={"document_sha256": "f" * 64, "content_sha256": "f" * 64}
    )
    second_frame = _frame(1)
    second_case = _v3_case_binding("case-builder-m3-identity-second")
    second_plan = replace(
        _planned_m3_call(
            scope,
            second_case,
            seed=1,
            result_kind=M6LockedModelCallResultKind.FAILURE,
        ),
        request_ref=changed_request,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_m3_model_record_v3(
            scope=scope,
            observation=_case_observation_v2(
                scope,
                1,
                (second_frame,),
                second_case,
                model_calls=(_observed_model_call(second_plan, provider_invoked=True),),
            ),
            prior_records=(first,),
            artifacts=(second_frame,),
            planned_calls=(second_plan,),
            candidate_case=second_case,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT
    )


def test_v3_prefix_accepts_the_opened_m4_model_route() -> None:
    scope = _scope()
    first_frame = _frame(0)
    m4_request = M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        kind=M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
        artifact_id="m4-request-must-stay-closed",
        document_sha256="d" * 64,
        content_sha256="d" * 64,
        size_bytes=1,
    )
    first_case = _v3_case_binding("case-builder-m4-prefix")
    first_observation = _case_observation_v2(scope, 0, (first_frame,), first_case)
    prior = M6UpgradeSampleExecutionRecordV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[0],
        outcome=M6ReplayExecutionOutcome.CASE_REPLAYED,
        candidate_case=first_case,
        artifact_links=(
            M6UpgradeSampleArtifactLink(
                ordinal=0,
                usage=M6UpgradeArtifactUsage.CONSUMED,
                artifact=first_frame,
            ),
            M6UpgradeSampleArtifactLink(
                ordinal=1,
                usage=M6UpgradeArtifactUsage.PRODUCED,
                artifact=m4_request,
            ),
        ),
        ledger_sequence=0,
        previous_ledger_entry_hash=M6_UPGRADE_LEDGER_GENESIS_HASH,
        observation_authority_id=first_observation.observation_authority_id,
    )
    second_frame = _frame(1)

    record = subject.build_m6_upgrade_no_case_record_v3(
        scope=scope,
        observation=_no_case_observation_v2(scope, 1, (second_frame,)),
        prior_records=(prior,),
        artifacts=(second_frame,),
    )

    assert record.previous_ledger_entry_hash == prior.sample_execution_record_id


def test_no_case_entrypoint_rejects_case_replayed() -> None:
    scope = _scope()
    frame = _frame(0)
    case_observation = _case_observation(scope, 0, (frame,), _case_binding())

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_no_case_record(
            scope=scope,
            observation=case_observation,
            prior_records=(),
            artifacts=(frame,),
        )
    assert raised.value.reason_code == M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED


def test_case_replayed_base_record_preserves_exact_binding_and_physical_closure() -> None:
    scope = _scope()
    frame = _frame(0)
    detection = _detection(frame, 0)
    candidate_case = _case_binding()
    observation = _case_observation(scope, 0, (frame, detection), candidate_case)

    record = subject.build_m6_upgrade_case_replayed_base_record(
        scope=scope,
        observation=observation,
        prior_records=(),
        artifacts=(detection, frame),
        candidate_case=candidate_case,
    )

    assert record.outcome == M6ReplayExecutionOutcome.CASE_REPLAYED
    assert record.candidate_case == candidate_case
    assert record.observation_authority_id == observation.observation_authority_id
    assert tuple(link.artifact for link in record.artifact_links) == tuple(
        sorted((frame, detection), key=lambda item: item.physical_key)
    )


def test_case_replayed_base_rejects_observation_for_a_different_case() -> None:
    scope = _scope()
    frame = _frame(0)
    observed_case = _case_binding("case-builder-observed")
    supplied_case = _case_binding("case-builder-supplied")

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_base_record(
            scope=scope,
            observation=_case_observation(scope, 0, (frame,), observed_case),
            prior_records=(),
            artifacts=(frame,),
            candidate_case=supplied_case,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH
    )


def test_case_replayed_entrypoint_cannot_fall_back_to_no_case_at_runtime() -> None:
    scope = _scope()
    frame = _frame(0)

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_base_record(
            scope=scope,
            observation=_observation(scope, 0, (frame,)),
            prior_records=(),
            artifacts=(frame,),
            candidate_case=None,  # type: ignore[arg-type]
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH
    )


def test_case_replayed_base_rejects_duplicate_case_prefix_before_returning_record() -> None:
    scope = _scope()
    candidate_case = _case_binding("case-builder-duplicate")
    first_frame = _frame(0)
    first = subject.build_m6_upgrade_case_replayed_base_record(
        scope=scope,
        observation=_case_observation(scope, 0, (first_frame,), candidate_case),
        prior_records=(),
        artifacts=(first_frame,),
        candidate_case=candidate_case,
    )
    second_frame = _frame(1)

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_base_record(
            scope=scope,
            observation=_case_observation(scope, 1, (second_frame,), candidate_case),
            prior_records=(first,),
            artifacts=(second_frame,),
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_PREFIX_MISMATCH
    )


def test_base_builder_rejects_a_historical_prefix_with_duplicate_case_ids() -> None:
    scope = _scope()
    repeated_case_id = "case-builder-corrupt-prefix"
    first_frame = _frame(0)
    first_case = _case_binding(repeated_case_id)
    first = subject.build_m6_upgrade_case_replayed_base_record(
        scope=scope,
        observation=_case_observation(scope, 0, (first_frame,), first_case),
        prior_records=(),
        artifacts=(first_frame,),
        candidate_case=first_case,
    )
    second_frame = _frame(1)
    second_case = M6UpgradeCandidateCaseBinding(
        case_id=repeated_case_id,
        case_revision=2,
        case_document_sha256="c" * 64,
        case_audit_sequence=2,
        case_audit_entry_hash="d" * 64,
    )
    second_observation = _case_observation(scope, 1, (second_frame,), second_case)
    second = M6UpgradeSampleExecutionRecordV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[1],
        outcome=M6ReplayExecutionOutcome.CASE_REPLAYED,
        candidate_case=second_case,
        artifact_links=(
            M6UpgradeSampleArtifactLink(
                ordinal=0,
                usage=M6UpgradeArtifactUsage.CONSUMED,
                artifact=second_frame,
            ),
        ),
        ledger_sequence=1,
        previous_ledger_entry_hash=first.sample_execution_record_id,
        observation_authority_id=second_observation.observation_authority_id,
    )
    current_frame = _frame(2)
    current_case = _case_binding("case-builder-after-corrupt-prefix")

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_base_record(
            scope=scope,
            observation=_case_observation(scope, 2, (current_frame,), current_case),
            prior_records=(first, second),
            artifacts=(current_frame,),
            candidate_case=current_case,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID
    )


def test_no_case_can_follow_case_replayed_without_erasing_case_history() -> None:
    scope = _scope()
    first_frame = _frame(0)
    candidate_case = _case_binding("case-builder-mixed-prefix")
    first = subject.build_m6_upgrade_case_replayed_base_record(
        scope=scope,
        observation=_case_observation(scope, 0, (first_frame,), candidate_case),
        prior_records=(),
        artifacts=(first_frame,),
        candidate_case=candidate_case,
    )
    second_frame = _frame(1)
    second = subject.build_m6_upgrade_no_case_record(
        scope=scope,
        observation=_observation(scope, 1, (second_frame,)),
        prior_records=(first,),
        artifacts=(second_frame,),
    )

    assert second.ledger_sequence == 1
    assert second.previous_ledger_entry_hash == first.sample_execution_record_id
    assert second.outcome == M6ReplayExecutionOutcome.NO_CASE
    assert second.candidate_case is None
    assert sum(record.candidate_case is not None for record in (first, second)) == 1


def test_case_replayed_base_rejects_models_until_exact_set_reader_exists() -> None:
    scope = _scope()
    frame = _frame(0)
    candidate_case = _case_binding()
    model_call = M6UpgradeObservedModelCall(
        request_id="c" * 64,
        layer=M6LockedModelCallLayer.SCREENING,
        role=M6LockedModelRole.SCREENING,
        attempt_index=0,
        result_kind=M6LockedModelCallResultKind.FAILURE,
        provider_invoked=False,
    )
    observation = _case_observation(
        scope,
        0,
        (frame,),
        candidate_case,
        model_calls=(model_call,),
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_base_record(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=(frame,),
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED


def test_case_replayed_base_rejects_unopened_physical_route_from_observation() -> None:
    scope = _scope()
    frame = _frame(0)
    candidate_case = _case_binding()
    evidence_pack = M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
        kind=M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
        artifact_id="case-builder-unopened-pack",
        document_sha256="d" * 64,
        content_sha256="d" * 64,
        size_bytes=1,
    )
    observation = _case_observation(
        scope,
        0,
        (frame, evidence_pack),
        candidate_case,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_base_record(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=(frame,),
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED


def test_base_builder_rejects_a_prefix_with_unverified_model_routes() -> None:
    scope = _scope()
    prior_frame = _frame(0)
    request = M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        kind=M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
        artifact_id="case-builder-unverified-request",
        document_sha256="e" * 64,
        content_sha256="e" * 64,
        size_bytes=1,
    )
    prior = M6UpgradeSampleExecutionRecordV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[0],
        outcome=M6ReplayExecutionOutcome.CASE_REPLAYED,
        candidate_case=_case_binding("case-builder-unverified-prefix"),
        artifact_links=(
            M6UpgradeSampleArtifactLink(
                ordinal=0,
                usage=M6UpgradeArtifactUsage.CONSUMED,
                artifact=prior_frame,
            ),
            M6UpgradeSampleArtifactLink(
                ordinal=1,
                usage=M6UpgradeArtifactUsage.PRODUCED,
                artifact=request,
            ),
        ),
        ledger_sequence=0,
        previous_ledger_entry_hash=M6_UPGRADE_LEDGER_GENESIS_HASH,
        observation_authority_id="c" * 64,
    )
    frame = _frame(1)
    candidate_case = _case_binding("case-builder-after-unverified-prefix")

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_case_replayed_base_record(
            scope=scope,
            observation=_case_observation(scope, 1, (frame,), candidate_case),
            prior_records=(prior,),
            artifacts=(frame,),
            candidate_case=candidate_case,
        )
    assert raised.value.reason_code == M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED


def test_pure_composition_suppresses_invalid_authority_payload_from_traceback() -> None:
    scope = _scope()
    frame = _frame(0)
    payload = frame.model_dump(mode="python", exclude_computed_fields=True)
    payload["artifact_id"] = "SECRET C:\\people\\alice.png"
    invalid = M6UpgradePhysicalArtifactRef.model_construct(**payload)

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_no_case_record(
            scope=scope,
            observation=_observation(scope, 0, (frame,)),
            prior_records=(),
            artifacts=(invalid,),
        )
    assert raised.value.reason_code == M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__
    formatted = "".join(traceback.format_exception(raised.value))
    assert "SECRET" not in formatted
    assert "alice.png" not in formatted


def test_detection_container_must_be_one_of_the_same_sample_frames() -> None:
    scope = _scope()
    frame = _frame(0)
    detection = _detection(frame, 0)
    wrong_container = M6UpgradePhysicalArtifactRef(
        source=detection.source,
        kind=detection.kind,
        artifact_id=detection.artifact_id,
        container_id="camera-builder:stream-builder:999",
        document_sha256=detection.document_sha256,
        content_sha256=detection.content_sha256,
        size_bytes=detection.size_bytes,
    )
    observation = _observation(scope, 0, (frame, detection))

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_no_case_record(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=(frame, wrong_container),
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
    )


@pytest.mark.parametrize("invalid_kind", ("detection_without_container", "frame_with_container"))
def test_no_case_record_rejects_invalid_container_shape(invalid_kind: str) -> None:
    scope = _scope()
    frame = _frame(0)
    detection = _detection(frame, 0)
    if invalid_kind == "detection_without_container":
        payload = detection.model_dump(mode="python", exclude_computed_fields=True)
        payload["container_id"] = None
        invalid = M6UpgradePhysicalArtifactRef.model_construct(**payload)
        artifacts = (frame, invalid)
    else:
        payload = frame.model_dump(mode="python", exclude_computed_fields=True)
        payload["container_id"] = frame.artifact_id
        invalid = M6UpgradePhysicalArtifactRef.model_construct(**payload)
        artifacts = (invalid, detection)
    observation = _observation(scope, 0, (frame, detection))

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_no_case_record(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=artifacts,
        )
    assert raised.value.reason_code == M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED


def test_detection_cannot_introduce_an_unobserved_container_frame() -> None:
    scope = _scope()
    observed_frame = _frame(0)
    extra_frame = _frame(1)
    observed_detection = _detection(observed_frame, 0)
    redirected_detection = M6UpgradePhysicalArtifactRef(
        source=observed_detection.source,
        kind=observed_detection.kind,
        artifact_id=observed_detection.artifact_id,
        container_id=extra_frame.artifact_id,
        document_sha256=observed_detection.document_sha256,
        content_sha256=observed_detection.content_sha256,
        size_bytes=observed_detection.size_bytes,
    )
    observation = _observation(scope, 0, (observed_frame, observed_detection))

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        subject.build_m6_upgrade_no_case_record(
            scope=scope,
            observation=observation,
            prior_records=(),
            artifacts=(observed_frame, extra_frame, redirected_detection),
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
    )

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import ArtifactKind, AuditAction
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthority,
    M6UpgradeCandidateOutputInventoryAuthorityV2,
    M6UpgradeCandidateOutputInventoryAuthorityV3,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    M6UpgradeCandidateCaseBinding,
    M6UpgradeExecutionLedgerSeal,
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeSampleArtifactLink,
    M6UpgradeSampleExecutionRecord,
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
    MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES,
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
)
from labcourt.contracts.storage import (
    CONTENT_ADDRESSED_ARTIFACT_KINDS,
    UUID_ARTIFACT_KINDS,
    ArtifactRef,
)
from labcourt.schema_export import expected_schema_files
from tests.contract.test_m6_regression_execution_contracts import (
    _inventory,
    _physical_sha,
    _physical_size,
)

_FORGED = "f" * 64


def _observation_for(
    inventory: M6UpgradeCandidateOutputInventoryAuthority,
    index: int,
    *,
    embedding_consumed: bool = False,
) -> M6UpgradeSampleExecutionObservationAuthority:
    record = inventory.execution_ledger.sample_executions[index]
    output = inventory.outputs[index]
    artifacts = tuple(
        sorted(
            (
                M6UpgradeObservedArtifactIdentity(
                    source=link.artifact.source,
                    kind=link.artifact.kind,
                    artifact_id=link.artifact.artifact_id,
                    usage=(
                        M6UpgradeArtifactUsage.CONSUMED
                        if embedding_consumed
                        and link.artifact.kind == M6UpgradePhysicalArtifactKind.EMBEDDING
                        else link.usage
                    ),
                )
                for link in record.artifact_links
                if not link.artifact.kind.value.startswith("MODEL_")
            ),
            key=lambda item: item.sort_key,
        )
    )
    model_calls = tuple(
        M6UpgradeObservedModelCall(
            request_id=call.request_ref.artifact_id,
            layer=call.layer,
            role=call.role,
            attempt_index=call.attempt_index,
            result_kind=call.result_kind,
            provider_invoked=call.provider_invoked,
        )
        for call in output.model_calls
    )
    return M6UpgradeSampleExecutionObservationAuthority(
        execution_scope_authority_id=(
            inventory.execution_ledger.execution_scope.execution_scope_authority_id
        ),
        candidate_run_id=inventory.candidate_run_cut.candidate_run_id,
        command_id=inventory.command.command_id,
        execution_dataset_snapshot_id=(inventory.execution_dataset.execution_dataset_snapshot_id),
        execution_entry=record.execution_entry,
        ledger_sequence=index,
        outcome=record.outcome,
        candidate_case=record.candidate_case,
        artifacts=artifacts,
        model_calls=model_calls,
    )


def _v2_inventory(
    *,
    embedding_consumed: bool = False,
    candidate_run_id: str = "run-candidate",
) -> M6UpgradeCandidateOutputInventoryAuthorityV2:
    legacy = _inventory(candidate_run_id=candidate_run_id)
    observations = tuple(
        _observation_for(
            legacy,
            index,
            embedding_consumed=embedding_consumed,
        )
        for index in range(len(legacy.outputs))
    )
    previous = M6_UPGRADE_LEDGER_GENESIS_HASH
    records: list[M6UpgradeSampleExecutionRecordV2] = []
    for index, (legacy_record, observation) in enumerate(
        zip(legacy.execution_ledger.sample_executions, observations, strict=True)
    ):
        links = tuple(
            link.model_copy(update={"usage": M6UpgradeArtifactUsage.CONSUMED})
            if embedding_consumed and link.artifact.kind == M6UpgradePhysicalArtifactKind.EMBEDDING
            else link
            for link in legacy_record.artifact_links
        )
        record = M6UpgradeSampleExecutionRecordV2(
            execution_scope_authority_id=legacy_record.execution_scope_authority_id,
            candidate_run_id=legacy_record.candidate_run_id,
            command_id=legacy_record.command_id,
            execution_dataset_snapshot_id=legacy_record.execution_dataset_snapshot_id,
            execution_entry=legacy_record.execution_entry,
            outcome=legacy_record.outcome,
            candidate_case=legacy_record.candidate_case,
            artifact_links=links,
            ledger_sequence=index,
            previous_ledger_entry_hash=previous,
            observation_authority_id=observation.observation_authority_id,
        )
        records.append(record)
        previous = record.sample_execution_record_id
    legacy_ledger = legacy.execution_ledger
    ledger = M6UpgradeExecutionLedgerSealV2(
        execution_scope=legacy_ledger.execution_scope,
        execution_scope_content_sha256=legacy_ledger.execution_scope_content_sha256,
        execution_scope_size_bytes=legacy_ledger.execution_scope_size_bytes,
        source_audit_head_sequence=legacy_ledger.source_audit_head_sequence,
        source_audit_head_hash=legacy_ledger.source_audit_head_hash,
        sample_executions=tuple(records),
    )
    outputs = tuple(
        output.model_copy(update={"sample_execution_record_id": record.sample_execution_record_id})
        for output, record in zip(legacy.outputs, records, strict=True)
    )
    return M6UpgradeCandidateOutputInventoryAuthorityV2(
        command=legacy.command,
        execution_dataset=legacy.execution_dataset,
        candidate_run_cut=legacy.candidate_run_cut,
        execution_ledger=ledger,
        execution_ledger_content_sha256=_physical_sha(ledger),
        execution_ledger_size_bytes=_physical_size(ledger),
        candidate_cases=legacy.candidate_cases,
        outputs=outputs,
        execution_observations=observations,
    )


def _selected_case_anchor(
    candidate_case: M6UpgradeCandidateCaseBinding,
    index: int,
) -> M6UpgradeSelectedCaseAuditAnchor:
    return M6UpgradeSelectedCaseAuditAnchor(
        candidate_case_binding_id=candidate_case.case_binding_id,
        action=AuditAction.CASE_STATE_CHANGED,
        object_ref=ArtifactRef(
            kind=ArtifactKind.SCREENING_RESULT,
            artifact_id=sha256_hex(["m6-v3-selected-case-audit-object", index]),
        ),
    )


def _artifact_ref_for_kind(kind: ArtifactKind) -> ArtifactRef:
    if kind == ArtifactKind.FRAME:
        artifact_id = "camera-anchor:stream-anchor:0"
    elif kind in CONTENT_ADDRESSED_ARTIFACT_KINDS:
        artifact_id = "7" * 64
    elif kind in UUID_ARTIFACT_KINDS:
        artifact_id = "11111111-1111-1111-1111-111111111111"
    else:
        artifact_id = "selected-case-audit-object-001"
    return ArtifactRef(kind=kind, artifact_id=artifact_id)


def _v3_inventory(
    *,
    candidate_run_id: str = "run-candidate",
) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
    v2 = _v2_inventory(candidate_run_id=candidate_run_id)
    observations: list[M6UpgradeSampleExecutionObservationAuthorityV2] = []
    for index, observation in enumerate(v2.execution_observations):
        payload = observation.model_dump(mode="python", exclude_computed_fields=True)
        payload.pop("schema_version")
        candidate_case = observation.candidate_case
        if candidate_case is not None and candidate_case.case_revision == 1:
            candidate_case = candidate_case.model_copy(update={"case_revision": 2})
            payload["candidate_case"] = candidate_case
        observations.append(
            M6UpgradeSampleExecutionObservationAuthorityV2(
                **payload,
                selected_case_audit_anchor=(
                    None if candidate_case is None else _selected_case_anchor(candidate_case, index)
                ),
            )
        )

    previous = M6_UPGRADE_LEDGER_GENESIS_HASH
    records: list[M6UpgradeSampleExecutionRecordV2] = []
    for index, (record, observation) in enumerate(
        zip(v2.execution_ledger.sample_executions, observations, strict=True)
    ):
        rebound = record.model_copy(
            update={
                "candidate_case": observation.candidate_case,
                "ledger_sequence": index,
                "previous_ledger_entry_hash": previous,
                "observation_authority_id": observation.observation_authority_id,
            }
        )
        records.append(rebound)
        previous = rebound.sample_execution_record_id

    old_ledger = v2.execution_ledger
    ledger = M6UpgradeExecutionLedgerSealV2(
        execution_scope=old_ledger.execution_scope,
        execution_scope_content_sha256=old_ledger.execution_scope_content_sha256,
        execution_scope_size_bytes=old_ledger.execution_scope_size_bytes,
        source_audit_head_sequence=old_ledger.source_audit_head_sequence,
        source_audit_head_hash=old_ledger.source_audit_head_hash,
        sample_executions=tuple(records),
    )
    outputs = []
    for output, record in zip(v2.outputs, records, strict=True):
        snapshot = output.candidate_snapshot
        if snapshot is not None:
            assert record.candidate_case is not None
            snapshot = snapshot.model_copy(
                update={"source_case_revision": record.candidate_case.case_revision}
            )
        outputs.append(
            output.model_copy(
                update={
                    "sample_execution_record_id": record.sample_execution_record_id,
                    "candidate_snapshot": snapshot,
                }
            )
        )
    candidate_revisions = {
        record.candidate_case.case_id: record.candidate_case.case_revision
        for record in records
        if record.candidate_case is not None
    }
    candidate_cases = tuple(
        candidate_case.model_copy(
            update={"case_revision": candidate_revisions[candidate_case.case_id]}
        )
        for candidate_case in v2.candidate_cases
    )
    return M6UpgradeCandidateOutputInventoryAuthorityV3(
        command=v2.command,
        execution_dataset=v2.execution_dataset,
        candidate_run_cut=v2.candidate_run_cut,
        execution_ledger=ledger,
        execution_ledger_content_sha256=_physical_sha(ledger),
        execution_ledger_size_bytes=_physical_size(ledger),
        candidate_cases=candidate_cases,
        outputs=tuple(outputs),
        execution_observations=tuple(observations),
    )


def _rebind_observations(
    inventory: M6UpgradeCandidateOutputInventoryAuthorityV2,
    observations: tuple[M6UpgradeSampleExecutionObservationAuthority, ...],
    *,
    link_replacements: dict[int, tuple[M6UpgradeSampleArtifactLink, ...]] | None = None,
) -> M6UpgradeCandidateOutputInventoryAuthorityV2:
    previous = M6_UPGRADE_LEDGER_GENESIS_HASH
    records: list[M6UpgradeSampleExecutionRecordV2] = []
    for index, (record, observation) in enumerate(
        zip(inventory.execution_ledger.sample_executions, observations, strict=True)
    ):
        rebound = record.model_copy(
            update={
                "artifact_links": (
                    link_replacements[index]
                    if link_replacements is not None and index in link_replacements
                    else record.artifact_links
                ),
                "observation_authority_id": observation.observation_authority_id,
                "ledger_sequence": index,
                "previous_ledger_entry_hash": previous,
            }
        )
        records.append(rebound)
        previous = rebound.sample_execution_record_id
    ledger = inventory.execution_ledger.model_copy(update={"sample_executions": tuple(records)})
    outputs = tuple(
        output.model_copy(update={"sample_execution_record_id": record.sample_execution_record_id})
        for output, record in zip(inventory.outputs, records, strict=True)
    )
    return inventory.model_copy(
        update={
            "execution_ledger": ledger,
            "execution_ledger_content_sha256": _physical_sha(ledger),
            "execution_ledger_size_bytes": _physical_size(ledger),
            "outputs": outputs,
            "execution_observations": observations,
        }
    )


def test_v2_record_seal_and_inventory_are_strict_independent_wire_contracts() -> None:
    inventory = _v2_inventory()
    record = inventory.execution_ledger.sample_executions[0]
    assert record.schema_version == "m6-upgrade-sample-execution-record-v2"
    assert inventory.execution_ledger.schema_version == "m6-upgrade-execution-ledger-seal-v2"
    assert inventory.schema_version == "m6-upgrade-candidate-output-inventory-authority-v2"
    assert inventory.execution_observation_count == len(inventory.outputs)
    assert tuple(
        record.observation_authority_id for record in inventory.execution_ledger.sample_executions
    ) == tuple(
        observation.observation_authority_id for observation in inventory.execution_observations
    )
    assert (
        M6UpgradeCandidateOutputInventoryAuthorityV2.model_validate(
            inventory.model_dump(mode="json")
        )
        == inventory
    )

    legacy = _inventory()
    with pytest.raises(ValidationError):
        M6UpgradeSampleExecutionRecordV2.model_validate(
            legacy.execution_ledger.sample_executions[0].model_dump(mode="json")
        )
    with pytest.raises(ValidationError):
        M6UpgradeSampleExecutionRecord.model_validate(record.model_dump(mode="json"))
    with pytest.raises(ValidationError):
        M6UpgradeExecutionLedgerSeal.model_validate(
            inventory.execution_ledger.model_dump(mode="json")
        )
    with pytest.raises(ValidationError):
        M6UpgradeCandidateOutputInventoryAuthority.model_validate(inventory.model_dump(mode="json"))


def test_v2_ids_bind_observation_identity_without_changing_v1_hash_domain() -> None:
    produced = _v2_inventory()
    consumed = _v2_inventory(embedding_consumed=True)
    assert produced.execution_observation_inventory_root_sha256 != (
        consumed.execution_observation_inventory_root_sha256
    )
    assert produced.execution_ledger.ledger_seal_authority_id != (
        consumed.execution_ledger.ledger_seal_authority_id
    )
    assert produced.candidate_output_inventory_authority_id != (
        consumed.candidate_output_inventory_authority_id
    )

    legacy = _inventory()
    assert (
        M6UpgradeCandidateOutputInventoryAuthority.model_validate(
            legacy.model_dump(mode="json")
        ).candidate_output_inventory_authority_id
        == legacy.candidate_output_inventory_authority_id
    )

    payload = produced.model_dump(mode="json")
    payload["execution_observation_inventory_root_sha256"] = _FORGED
    with pytest.raises(
        ValidationError,
        match="execution_observation_inventory_root_sha256",
    ):
        M6UpgradeCandidateOutputInventoryAuthorityV2.model_validate(payload)


def test_v2_inventory_rejects_observation_scope_order_and_record_grafts() -> None:
    inventory = _v2_inventory()
    observations = inventory.execution_observations
    changed_command = observations[0].model_copy(update={"command_id": _FORGED})
    with pytest.raises(ValidationError, match="exact sample execution scope"):
        _rebind_observations(inventory, (changed_command, *observations[1:]))

    with pytest.raises(ValidationError, match="exact sample execution scope"):
        inventory.model_copy(update={"execution_observations": tuple(reversed(observations))})

    last_record = inventory.execution_ledger.sample_executions[-1].model_copy(
        update={"observation_authority_id": _FORGED}
    )
    ledger = inventory.execution_ledger.model_copy(
        update={
            "sample_executions": (
                *inventory.execution_ledger.sample_executions[:-1],
                last_record,
            )
        }
    )
    outputs = (
        *inventory.outputs[:-1],
        inventory.outputs[-1].model_copy(
            update={"sample_execution_record_id": last_record.sample_execution_record_id}
        ),
    )
    with pytest.raises(ValidationError, match="exact sample execution scope"):
        inventory.model_copy(
            update={
                "execution_ledger": ledger,
                "execution_ledger_content_sha256": _physical_sha(ledger),
                "execution_ledger_size_bytes": _physical_size(ledger),
                "outputs": outputs,
            }
        )


def test_v2_inventory_bijects_ordinary_observations_outputs_and_ledger_usage() -> None:
    inventory = _v2_inventory()
    index = next(
        index
        for index, observation in enumerate(inventory.execution_observations)
        if any(
            item.kind == M6UpgradePhysicalArtifactKind.EMBEDDING for item in observation.artifacts
        )
    )
    observation = inventory.execution_observations[index]
    without_embedding = observation.model_copy(
        update={
            "artifacts": tuple(
                item
                for item in observation.artifacts
                if item.kind != M6UpgradePhysicalArtifactKind.EMBEDDING
            )
        }
    )
    observations = tuple(
        without_embedding if item_index == index else item
        for item_index, item in enumerate(inventory.execution_observations)
    )
    with pytest.raises(ValidationError, match="ordinary observations"):
        _rebind_observations(inventory, observations)

    changed_artifacts = tuple(
        item.model_copy(update={"usage": M6UpgradeArtifactUsage.CONSUMED})
        if item.kind == M6UpgradePhysicalArtifactKind.EMBEDDING
        else item
        for item in observation.artifacts
    )
    changed_observation = observation.model_copy(update={"artifacts": changed_artifacts})
    changed_observations = tuple(
        changed_observation if item_index == index else item
        for item_index, item in enumerate(inventory.execution_observations)
    )
    with pytest.raises(ValidationError, match="ordinary observations"):
        _rebind_observations(inventory, changed_observations)


@pytest.mark.parametrize(
    "call_update",
    (
        {"request_id": _FORGED},
        {"attempt_index": 1},
        {"result_kind": M6LockedModelCallResultKind.FAILURE},
        {"provider_invoked": False},
        {
            "layer": M6LockedModelCallLayer.HEARING,
            "role": M6LockedModelRole.JUDGE,
        },
    ),
)
def test_v2_inventory_bijects_every_model_observation_runtime_fact(
    call_update: dict[str, object],
) -> None:
    inventory = _v2_inventory()
    index = next(
        index
        for index, observation in enumerate(inventory.execution_observations)
        if observation.model_calls
    )
    observation = inventory.execution_observations[index]
    changed_call = observation.model_calls[0].model_copy(update=call_update)
    changed_observation = observation.model_copy(update={"model_calls": (changed_call,)})
    observations = tuple(
        changed_observation if item_index == index else item
        for item_index, item in enumerate(inventory.execution_observations)
    )
    with pytest.raises(ValidationError, match="model observations"):
        _rebind_observations(inventory, observations)


def test_only_observation_backed_v2_enforces_the_sample_physical_budget() -> None:
    inventory = _v2_inventory()
    record = inventory.execution_ledger.sample_executions[0]
    frame_link = next(
        item
        for item in record.artifact_links
        if item.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
    )
    oversized = frame_link.artifact.model_copy(
        update={"size_bytes": MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES + 1}
    )
    links = tuple(
        item.model_copy(update={"artifact": oversized})
        if item.artifact.artifact_ref_id == frame_link.artifact.artifact_ref_id
        else item
        for item in record.artifact_links
    )
    with pytest.raises(ValidationError, match="v2 ledger sample physical byte budget"):
        record.model_copy(update={"artifact_links": links})

    legacy_record = _inventory().execution_ledger.sample_executions[0]
    legacy_frame = legacy_record.artifact_links[0]
    legacy_oversized = legacy_frame.artifact.model_copy(
        update={"size_bytes": MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES + 1}
    )
    legacy_links = tuple(
        item.model_copy(update={"artifact": legacy_oversized})
        if item.artifact.artifact_ref_id == legacy_frame.artifact.artifact_ref_id
        else item
        for item in legacy_record.artifact_links
    )
    assert legacy_record.model_copy(update={"artifact_links": legacy_links})


def test_v2_schemas_expose_required_observation_bindings_and_reject_extra_fields() -> None:
    inventory = _v2_inventory()
    artifacts = {
        "m6-upgrade-sample-execution-record-v2": (inventory.execution_ledger.sample_executions[0]),
        "m6-upgrade-execution-ledger-seal-v2": inventory.execution_ledger,
        "m6-upgrade-candidate-output-inventory-authority-v2": inventory,
    }
    schemas = expected_schema_files()
    for name, artifact in artifacts.items():
        schema = json.loads(schemas[f"{name}.schema.json"])
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(artifact.model_dump(mode="json"))
        assert schema["additionalProperties"] is False

    record_schema = json.loads(schemas["m6-upgrade-sample-execution-record-v2.schema.json"])
    assert "observation_authority_id" in record_schema["required"]
    assert record_schema["properties"]["schema_version"]["const"] == (
        "m6-upgrade-sample-execution-record-v2"
    )
    inventory_schema = json.loads(
        schemas["m6-upgrade-candidate-output-inventory-authority-v2.schema.json"]
    )
    assert "execution_observations" in inventory_schema["required"]

    payload = inventory.model_dump(mode="json")
    payload["untrusted_observation_digest"] = sha256_hex(["forged"])
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        M6UpgradeCandidateOutputInventoryAuthorityV2.model_validate(payload)


@pytest.mark.parametrize(
    ("action", "kind", "artifact_id"),
    (
        (AuditAction.CASE_CREATED, ArtifactKind.CASE, "11111111-1111-1111-1111-111111111111"),
        (
            AuditAction.EVIDENCE_PACK_PUBLISHED,
            ArtifactKind.CASE,
            "11111111-1111-1111-1111-111111111111",
        ),
        (AuditAction.CASE_STATE_CHANGED, ArtifactKind.CASE, "11111111-1111-1111-1111-111111111111"),
        (AuditAction.CASE_STATE_CHANGED, ArtifactKind.SCREENING_RESULT, "1" * 64),
        (AuditAction.CASE_STATE_CHANGED, ArtifactKind.PROCEDURAL_REVIEW, "2" * 64),
        (AuditAction.CASE_STATE_CHANGED, ArtifactKind.BACKLOG_ITEM, "3" * 64),
        (AuditAction.CASE_STATE_CHANGED, ArtifactKind.APPEAL, "appeal-selected-001"),
        (AuditAction.CASE_CLOSED, ArtifactKind.CASE, "11111111-1111-1111-1111-111111111111"),
        (AuditAction.CASE_CLOSED, ArtifactKind.ALERT, "alert-selected-001"),
    ),
)
def test_selected_case_audit_anchor_accepts_only_recognized_case_transition_shapes(
    action: AuditAction,
    kind: ArtifactKind,
    artifact_id: str,
) -> None:
    anchor = M6UpgradeSelectedCaseAuditAnchor(
        candidate_case_binding_id="a" * 64,
        action=action,
        object_ref=ArtifactRef(kind=kind, artifact_id=artifact_id),
    )

    assert anchor.schema_version == "m6-upgrade-selected-case-audit-anchor-v1"
    assert M6UpgradeSelectedCaseAuditAnchor.model_validate(anchor.model_dump(mode="json")) == anchor


def test_selected_case_audit_anchor_exhausts_action_object_kind_matrix() -> None:
    allowed = {
        AuditAction.CASE_CREATED: {ArtifactKind.CASE},
        AuditAction.EVIDENCE_PACK_PUBLISHED: {ArtifactKind.CASE},
        AuditAction.CASE_STATE_CHANGED: {
            ArtifactKind.CASE,
            ArtifactKind.SCREENING_RESULT,
            ArtifactKind.PROCEDURAL_REVIEW,
            ArtifactKind.BACKLOG_ITEM,
            ArtifactKind.APPEAL,
        },
        AuditAction.CASE_CLOSED: {ArtifactKind.CASE, ArtifactKind.ALERT},
    }
    for action in AuditAction:
        for kind in ArtifactKind:
            values = {
                "candidate_case_binding_id": "a" * 64,
                "action": action,
                "object_ref": _artifact_ref_for_kind(kind),
            }
            if kind in allowed.get(action, set()):
                assert M6UpgradeSelectedCaseAuditAnchor.model_validate(values)
            else:
                with pytest.raises(ValidationError, match="recognized Case transition"):
                    M6UpgradeSelectedCaseAuditAnchor.model_validate(values)


def test_observation_v2_requires_one_exact_selected_case_audit_anchor() -> None:
    inventory = _v3_inventory()
    case_observation = next(
        item for item in inventory.execution_observations if item.candidate_case is not None
    )
    no_case_observation = next(
        item for item in inventory.execution_observations if item.candidate_case is None
    )
    assert case_observation.selected_case_audit_anchor is not None
    assert (
        case_observation.selected_case_audit_anchor.candidate_case_binding_id
        == case_observation.candidate_case.case_binding_id
    )
    assert no_case_observation.selected_case_audit_anchor is None

    with pytest.raises(
        ValidationError,
        match="CASE_REPLAYED requires one selected Case audit anchor",
    ):
        case_observation.model_copy(update={"selected_case_audit_anchor": None})
    with pytest.raises(ValidationError, match="NO_CASE forbids a selected Case audit anchor"):
        no_case_observation.model_copy(
            update={"selected_case_audit_anchor": case_observation.selected_case_audit_anchor}
        )

    assert case_observation.selected_case_audit_anchor is not None
    conflicting_anchor = case_observation.selected_case_audit_anchor.model_copy(
        update={"candidate_case_binding_id": "f" * 64}
    )
    with pytest.raises(ValidationError, match="differs from candidate Case binding"):
        case_observation.model_copy(update={"selected_case_audit_anchor": conflicting_anchor})


def test_observation_v2_requires_case_audit_object_to_name_the_selected_case() -> None:
    inventory = _v3_inventory()
    template = next(
        item for item in inventory.execution_observations if item.candidate_case is not None
    )
    candidate_case = M6UpgradeCandidateCaseBinding(
        case_id="11111111-1111-1111-1111-111111111111",
        case_revision=1,
        case_document_sha256="a" * 64,
        case_audit_sequence=3,
        case_audit_entry_hash="b" * 64,
    )
    wrong_anchor = M6UpgradeSelectedCaseAuditAnchor(
        candidate_case_binding_id=candidate_case.case_binding_id,
        action=AuditAction.CASE_CREATED,
        object_ref=ArtifactRef(
            kind=ArtifactKind.CASE,
            artifact_id="22222222-2222-2222-2222-222222222222",
        ),
    )
    with pytest.raises(ValidationError, match="CASE audit object must name the selected Case"):
        template.model_copy(
            update={
                "candidate_case": candidate_case,
                "selected_case_audit_anchor": wrong_anchor,
            }
        )

    exact_anchor = wrong_anchor.model_copy(
        update={
            "object_ref": ArtifactRef(
                kind=ArtifactKind.CASE,
                artifact_id=candidate_case.case_id,
            )
        }
    )
    exact = template.model_copy(
        update={
            "candidate_case": candidate_case,
            "selected_case_audit_anchor": exact_anchor,
        }
    )
    assert exact.selected_case_audit_anchor == exact_anchor

    later_case = candidate_case.model_copy(update={"case_revision": 2})
    later_created_anchor = exact_anchor.model_copy(
        update={"candidate_case_binding_id": later_case.case_binding_id}
    )
    with pytest.raises(ValidationError, match="revision and audit action differ"):
        template.model_copy(
            update={
                "candidate_case": later_case,
                "selected_case_audit_anchor": later_created_anchor,
            }
        )

    revision_one_state_anchor = M6UpgradeSelectedCaseAuditAnchor(
        candidate_case_binding_id=candidate_case.case_binding_id,
        action=AuditAction.CASE_STATE_CHANGED,
        object_ref=ArtifactRef(kind=ArtifactKind.SCREENING_RESULT, artifact_id="4" * 64),
    )
    with pytest.raises(ValidationError, match="revision and audit action differ"):
        template.model_copy(
            update={
                "candidate_case": candidate_case,
                "selected_case_audit_anchor": revision_one_state_anchor,
            }
        )


def test_observation_v2_anchor_identity_commits_case_and_audit_fields() -> None:
    observation = next(
        item for item in _v3_inventory().execution_observations if item.candidate_case is not None
    )
    assert observation.candidate_case is not None
    assert observation.selected_case_audit_anchor is not None
    identities = {observation.observation_authority_id}
    for field, value in (
        ("case_document_sha256", "9" * 64),
        ("case_audit_sequence", observation.candidate_case.case_audit_sequence + 1),
        ("case_audit_entry_hash", "8" * 64),
    ):
        changed_case = observation.candidate_case.model_copy(update={field: value})
        changed_anchor = observation.selected_case_audit_anchor.model_copy(
            update={"candidate_case_binding_id": changed_case.case_binding_id}
        )
        changed = observation.model_copy(
            update={
                "candidate_case": changed_case,
                "selected_case_audit_anchor": changed_anchor,
            }
        )
        identities.add(changed.observation_authority_id)

    changed_anchor = M6UpgradeSelectedCaseAuditAnchor(
        candidate_case_binding_id=observation.candidate_case.case_binding_id,
        action=AuditAction.CASE_CLOSED,
        object_ref=ArtifactRef(kind=ArtifactKind.ALERT, artifact_id="alert-selected-002"),
    )
    identities.add(
        observation.model_copy(
            update={"selected_case_audit_anchor": changed_anchor}
        ).observation_authority_id
    )
    assert len(identities) == 5


def test_v3_inventory_reuses_frozen_v2_record_and_seal_with_v2_observations() -> None:
    inventory = _v3_inventory()
    assert inventory.schema_version == "m6-upgrade-candidate-output-inventory-authority-v3"
    assert inventory.execution_ledger.schema_version == "m6-upgrade-execution-ledger-seal-v2"
    assert all(
        record.schema_version == "m6-upgrade-sample-execution-record-v2"
        for record in inventory.execution_ledger.sample_executions
    )
    assert all(
        observation.schema_version == "m6-upgrade-sample-execution-observation-authority-v2"
        for observation in inventory.execution_observations
    )
    assert (
        M6UpgradeCandidateOutputInventoryAuthorityV3.model_validate(
            inventory.model_dump(mode="json")
        )
        == inventory
    )

    with pytest.raises(ValidationError):
        M6UpgradeCandidateOutputInventoryAuthorityV2.model_validate(
            inventory.model_dump(mode="json")
        )
    with pytest.raises(ValidationError):
        M6UpgradeCandidateOutputInventoryAuthorityV3.model_validate(
            _v2_inventory().model_dump(mode="json")
        )


def test_selected_case_anchor_addition_preserves_all_legacy_v2_hash_vectors() -> None:
    inventory = _v2_inventory()
    observation = next(item for item in inventory.execution_observations if item.candidate_case)
    assert observation.candidate_case is not None
    assert (
        observation.candidate_case.case_binding_id
        == "f69808347a4e8d87e490330ce520c192744cf65fef625cda0f59c7162bf4ed45"
    )
    assert (
        observation.observation_authority_id
        == "9cf932024eafe04dda87f771b97080768abd9df84cfc7d9728db585e7cf3e8c1"
    )
    assert (
        inventory.execution_ledger.ledger_seal_authority_id
        == "943d4a6f28d0278d8f362100792d5ab2091fb3ff9959579423f325dd463a2c78"
    )
    assert (
        inventory.candidate_output_inventory_authority_id
        == "191d1accf8f01a56f43af75d7758bb45f789519d06863fcfe3bd16c97da8309e"
    )


def test_selected_case_anchor_observation_and_inventory_v3_hash_vectors_are_frozen() -> None:
    inventory = _v3_inventory()
    observation = next(item for item in inventory.execution_observations if item.candidate_case)
    assert observation.selected_case_audit_anchor is not None
    assert (
        observation.selected_case_audit_anchor.selected_case_audit_anchor_id
        == "6183fb390659fc342b1509018d43d402e8a8c8a3b32d918b385bb9b13f2e01a6"
    )
    assert (
        observation.observation_authority_id
        == "df5db1631dea16b5241fa3052c432c5a408f346c84a6c9a23205c753d34efb74"
    )
    assert (
        inventory.execution_ledger.ledger_seal_authority_id
        == "281d5e56b16b961d4da005c1db43350ca513ef6fac4041e8a2eb5ee83c2c5424"
    )
    assert (
        inventory.execution_observation_inventory_root_sha256
        == "d7caed1adc7976d9521f6a30402b7ea069f836835440cf3acd8b9f6ae44ef47b"
    )
    assert (
        inventory.candidate_output_inventory_root_sha256
        == "e23298b73b7620968fcb89127289dea5c00c9e503a59551bdd6b99b918f18f03"
    )
    assert (
        inventory.candidate_output_inventory_authority_id
        == "7e793fd6758105149a573cc04e0a4b8118f61f43af32fd6cfe07b01f0ea7347d"
    )


def test_v2_and_v3_root_models_revalidate_cross_version_python_instances() -> None:
    v2 = _v2_inventory()
    v3 = _v3_inventory()
    v2_observation = v2.execution_observations[0]
    v3_observation = v3.execution_observations[0]

    with pytest.raises(ValidationError):
        M6UpgradeSampleExecutionObservationAuthority.model_validate(v3_observation)
    with pytest.raises(ValidationError):
        M6UpgradeSampleExecutionObservationAuthorityV2.model_validate(v2_observation)
    with pytest.raises(ValidationError):
        M6UpgradeCandidateOutputInventoryAuthorityV2.model_validate(v3)
    with pytest.raises(ValidationError):
        M6UpgradeCandidateOutputInventoryAuthorityV3.model_validate(v2)


def test_v2_anchor_and_v3_computed_claims_reject_serialized_tampering() -> None:
    inventory = _v3_inventory()
    observation = next(item for item in inventory.execution_observations if item.candidate_case)
    assert observation.selected_case_audit_anchor is not None

    anchor_payload = observation.selected_case_audit_anchor.model_dump(mode="json")
    anchor_payload["selected_case_audit_anchor_id"] = "f" * 64
    with pytest.raises(ValidationError, match="selected_case_audit_anchor_id"):
        M6UpgradeSelectedCaseAuditAnchor.model_validate(anchor_payload)

    observation_payload = observation.model_dump(mode="json")
    observation_payload["observation_authority_id"] = "f" * 64
    with pytest.raises(ValidationError, match="observation_authority_id"):
        M6UpgradeSampleExecutionObservationAuthorityV2.model_validate(observation_payload)

    for claim in (
        "execution_observation_inventory_root_sha256",
        "candidate_output_inventory_root_sha256",
        "candidate_output_inventory_authority_id",
    ):
        inventory_payload = inventory.model_dump(mode="json")
        inventory_payload[claim] = "f" * 64
        with pytest.raises(ValidationError, match=claim):
            M6UpgradeCandidateOutputInventoryAuthorityV3.model_validate(inventory_payload)


def test_v2_anchor_and_v3_inventory_schemas_are_strict_and_round_trip() -> None:
    inventory = _v3_inventory()
    observation = next(item for item in inventory.execution_observations if item.candidate_case)
    assert observation.selected_case_audit_anchor is not None
    artifacts = {
        "m6-upgrade-selected-case-audit-anchor": observation.selected_case_audit_anchor,
        "m6-upgrade-sample-execution-observation-authority-v2": observation,
        "m6-upgrade-candidate-output-inventory-authority-v3": inventory,
    }
    schemas = expected_schema_files()
    for name, artifact in artifacts.items():
        schema = json.loads(schemas[f"{name}.schema.json"])
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(artifact.model_dump(mode="json"))
        assert schema["additionalProperties"] is False

    observation_schema = json.loads(
        schemas["m6-upgrade-sample-execution-observation-authority-v2.schema.json"]
    )
    assert "selected_case_audit_anchor" in observation_schema["required"]
    inventory_schema = json.loads(
        schemas["m6-upgrade-candidate-output-inventory-authority-v3.schema.json"]
    )
    assert inventory_schema["properties"]["schema_version"]["const"] == (
        "m6-upgrade-candidate-output-inventory-authority-v3"
    )

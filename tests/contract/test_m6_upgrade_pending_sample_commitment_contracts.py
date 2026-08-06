from __future__ import annotations

import hashlib
import inspect
import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES,
    M6UpgradeSampleExecutionRecord,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactKind
from labcourt.ports.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentError,
    M6UpgradePendingSampleCommitmentFailureCode,
    M6UpgradePendingSampleCommitmentRepository,
)
from labcourt.schema_export import expected_schema_files
from tests.contract.test_m6_upgrade_observation_backed_inventory_contracts import (
    _v2_inventory,
)

_FORGED = "f" * 64


def _record_document(record: M6UpgradeSampleExecutionRecordV2) -> bytes:
    return canonical_json(record.model_dump(mode="json")).encode("utf-8")


def _commitment(index: int = 0) -> M6UpgradePendingSampleCommitmentAuthority:
    inventory = _v2_inventory()
    record = inventory.execution_ledger.sample_executions[index]
    document = _record_document(record)
    return M6UpgradePendingSampleCommitmentAuthority(
        execution_scope_authority_id=record.execution_scope_authority_id,
        candidate_run_id=record.candidate_run_id,
        command_id=record.command_id,
        execution_dataset_snapshot_id=record.execution_dataset_snapshot_id,
        execution_entry=record.execution_entry,
        ledger_sequence=record.ledger_sequence,
        observation_authority_id=record.observation_authority_id,
        sample_execution_record=record,
        sample_execution_record_document_sha256=(hashlib.sha256(document).hexdigest()),
        sample_execution_record_size_bytes=len(document),
    )


def _with_record(
    commitment: M6UpgradePendingSampleCommitmentAuthority,
    record: M6UpgradeSampleExecutionRecordV2,
) -> M6UpgradePendingSampleCommitmentAuthority:
    document = _record_document(record)
    return commitment.model_copy(
        update={
            "sample_execution_record": record,
            "sample_execution_record_document_sha256": (hashlib.sha256(document).hexdigest()),
            "sample_execution_record_size_bytes": len(document),
        }
    )


def test_pending_commitment_round_trips_one_exact_canonical_v2_record() -> None:
    commitment = _commitment()
    record = commitment.sample_execution_record
    assert commitment.schema_version == ("m6-upgrade-pending-sample-commitment-authority-v1")
    assert commitment.persistence_key == (
        record.candidate_run_id,
        record.execution_scope_authority_id,
        record.ledger_sequence,
    )
    assert commitment.sample_id == record.sample_id
    assert commitment.execution_entry_id == record.execution_entry_id
    assert commitment.sample_execution_record_id == record.sample_execution_record_id
    assert len(commitment.pending_sample_commitment_authority_id) == 64
    assert (
        M6UpgradePendingSampleCommitmentAuthority.model_validate(commitment.model_dump(mode="json"))
        == commitment
    )
    assert "never successfully persisted before a crash" in (
        M6UpgradePendingSampleCommitmentRepository.__doc__ or ""
    )


def test_commitment_id_binds_the_complete_record_document_identity() -> None:
    commitment = _commitment()
    record = commitment.sample_execution_record
    frame_link = next(
        item
        for item in record.artifact_links
        if item.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
    )
    changed_frame = frame_link.artifact.model_copy(
        update={"size_bytes": frame_link.artifact.size_bytes + 1}
    )
    changed_links = tuple(
        item.model_copy(update={"artifact": changed_frame})
        if item.ordinal == frame_link.ordinal
        else item
        for item in record.artifact_links
    )
    changed_record = record.model_copy(update={"artifact_links": changed_links})
    changed = _with_record(commitment, changed_record)

    assert changed.sample_execution_record_id != commitment.sample_execution_record_id
    assert changed.sample_execution_record_document_sha256 != (
        commitment.sample_execution_record_document_sha256
    )
    assert changed.pending_sample_commitment_authority_id != (
        commitment.pending_sample_commitment_authority_id
    )


@pytest.mark.parametrize(
    "update",
    (
        {"execution_scope_authority_id": _FORGED},
        {"candidate_run_id": "foreign-run"},
        {"command_id": _FORGED},
        {"execution_dataset_snapshot_id": _FORGED},
        {"ledger_sequence": 1},
        {"observation_authority_id": _FORGED},
    ),
)
def test_pending_commitment_rejects_every_outer_scope_graft(
    update: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="exact V2 sample record scope"):
        _commitment().model_copy(update=update)


def test_pending_commitment_rejects_execution_entry_and_legacy_record_grafts() -> None:
    commitment = _commitment()
    foreign_entry = _v2_inventory().execution_dataset.entries[1]
    with pytest.raises(ValidationError, match="exact V2 sample record scope"):
        commitment.model_copy(update={"execution_entry": foreign_entry})

    legacy_payload = commitment.sample_execution_record.model_dump(
        mode="python",
        exclude_computed_fields=True,
    )
    legacy_payload.pop("observation_authority_id")
    legacy_payload["schema_version"] = "m6-upgrade-sample-execution-record-v1"
    legacy_record = M6UpgradeSampleExecutionRecord.model_validate(legacy_payload)
    payload = commitment.model_dump(mode="python", exclude_computed_fields=True)
    payload["sample_execution_record"] = legacy_record
    with pytest.raises(ValidationError):
        M6UpgradePendingSampleCommitmentAuthority.model_validate(payload)


def test_pending_commitment_rejects_document_and_derived_claim_tampering() -> None:
    commitment = _commitment()
    with pytest.raises(ValidationError, match="record document identity differs"):
        commitment.model_copy(update={"sample_execution_record_document_sha256": _FORGED})
    with pytest.raises(ValidationError, match="record document identity differs"):
        commitment.model_copy(
            update={
                "sample_execution_record_size_bytes": (
                    commitment.sample_execution_record_size_bytes + 1
                )
            }
        )

    payload = commitment.model_dump(mode="json")
    payload["pending_sample_commitment_authority_id"] = _FORGED
    with pytest.raises(
        ValidationError,
        match="pending_sample_commitment_authority_id",
    ):
        M6UpgradePendingSampleCommitmentAuthority.model_validate(payload)
    payload = commitment.model_dump(mode="json")
    payload["sample_execution_record_id"] = _FORGED
    with pytest.raises(ValidationError, match="sample_execution_record_id"):
        M6UpgradePendingSampleCommitmentAuthority.model_validate(payload)


def test_pending_commitment_enforces_strict_bounded_document_claims() -> None:
    commitment = _commitment()
    with pytest.raises(ValidationError):
        commitment.model_copy(update={"sample_execution_record_size_bytes": True})
    with pytest.raises(ValidationError, match="less than or equal"):
        commitment.model_copy(
            update={
                "sample_execution_record_size_bytes": (
                    MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES + 1
                )
            }
        )
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        M6UpgradePendingSampleCommitmentAuthority.model_validate(
            {
                **commitment.model_dump(mode="json"),
                "record_payload_backup": "forbidden",
            }
        )


def test_pending_commitment_repository_port_is_append_load_and_payload_free() -> None:
    assert {item.value for item in M6UpgradePendingSampleCommitmentFailureCode} == {
        "INVALID_ARGUMENT",
        "SCOPE_NOT_FOUND",
        "SCOPE_MISMATCH",
        "OBSERVATION_NOT_FOUND",
        "OBSERVATION_MISMATCH",
        "COMMITMENT_NOT_FOUND",
        "COMMITMENT_CONFLICT",
        "COMMITMENT_OUT_OF_ORDER",
        "PENDING_COMMITMENT_EXISTS",
        "LEGACY_LEDGER_UNSUPPORTED",
        "LEDGER_SEALED",
        "DOCUMENT_TOO_LARGE",
        "STORED_AUTHORITY_INVALID",
        "STORAGE_REJECTED",
    }
    assert tuple(
        inspect.signature(M6UpgradePendingSampleCommitmentRepository.append).parameters
    ) == ("self", "commitment")
    assert tuple(inspect.signature(M6UpgradePendingSampleCommitmentRepository.load).parameters) == (
        "self",
        "candidate_run_id",
        "execution_scope_authority_id",
        "ledger_sequence",
    )

    error = M6UpgradePendingSampleCommitmentError(
        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_CONFLICT
    )
    assert error.args == ("M6 pending sample commitment failed: COMMITMENT_CONFLICT",)
    assert vars(error) == {"reason_code": error.reason_code}
    with pytest.raises(TypeError, match="reason_code"):
        M6UpgradePendingSampleCommitmentError("COMMITMENT_CONFLICT")  # type: ignore[arg-type]


def test_pending_commitment_schema_is_registered_strict_and_bounded() -> None:
    filename = "m6-upgrade-pending-sample-commitment-authority.schema.json"
    schema = json.loads(expected_schema_files()[filename])
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(_commitment().model_dump(mode="json"))
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == (
        "m6-upgrade-pending-sample-commitment-authority-v1"
    )
    assert set(
        (
            "execution_scope_authority_id",
            "candidate_run_id",
            "command_id",
            "execution_dataset_snapshot_id",
            "execution_entry",
            "ledger_sequence",
            "observation_authority_id",
            "sample_execution_record",
            "sample_execution_record_document_sha256",
            "sample_execution_record_size_bytes",
        )
    ).issubset(schema["required"])
    assert schema["properties"]["sample_execution_record_size_bytes"]["maximum"] == (
        MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES
    )

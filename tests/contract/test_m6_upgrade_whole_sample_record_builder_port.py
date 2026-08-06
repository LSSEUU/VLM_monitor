from __future__ import annotations

import inspect

import pytest

from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.ports import (
    M6UpgradeWholeSampleRecordBuilder,
    M6UpgradeWholeSampleRecordBuilderError,
    M6UpgradeWholeSampleRecordBuilderFailureCode,
)
from labcourt.schema_export import expected_schema_files


def test_whole_sample_record_builder_exposes_only_scope_identity() -> None:
    method = M6UpgradeWholeSampleRecordBuilder.build_m6_upgrade_sample_record
    assert tuple(inspect.signature(method).parameters) == (
        "self",
        "candidate_run_id",
        "execution_scope_authority_id",
    )

    annotations = inspect.get_annotations(method, eval_str=True)
    assert annotations == {
        "candidate_run_id": str,
        "execution_scope_authority_id": str,
        "return": M6UpgradeSampleExecutionRecordV2,
    }

    forbidden_inputs = {
        "observation",
        "record",
        "ref",
        "digest",
        "size",
        "container",
        "previous_hash",
        "ledger_sequence",
        "sequence",
        "ordinal",
        "verifier",
    }
    public_inputs = set(inspect.signature(method).parameters) - {"self"}
    assert public_inputs.isdisjoint(forbidden_inputs)


def test_whole_sample_record_builder_failure_is_exact_typed_and_payload_free() -> None:
    assert {item.value for item in M6UpgradeWholeSampleRecordBuilderFailureCode} == {
        "INVALID_ARGUMENT",
        "SCOPE_NOT_FOUND",
        "SCOPE_MISMATCH",
        "LEDGER_VERSION_UNSUPPORTED",
        "OBSERVATION_NOT_FOUND",
        "OBSERVATION_CLOSURE_MISMATCH",
        "CASE_PREFIX_MISMATCH",
        "CASE_BINDING_MISMATCH",
        "MODEL_CALL_CLOSURE_MISMATCH",
        "ROUTE_REJECTED",
        "IDENTITY_CONFLICT",
        "LINK_LIMIT_EXCEEDED",
        "PHYSICAL_BYTE_LIMIT_EXCEEDED",
        "CANONICAL_DOCUMENT_TOO_LARGE",
        "PIXEL_AUTHORITY_REJECTED",
        "RAW_RESPONSE_REJECTED",
        "RECORD_TOO_LARGE",
        "STORED_AUTHORITY_INVALID",
        "SNAPSHOT_REJECTED",
    }

    error = M6UpgradeWholeSampleRecordBuilderError(
        M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
    )
    assert error.args == (
        "M6 upgrade whole-sample record build failed: OBSERVATION_CLOSURE_MISMATCH",
    )
    assert vars(error) == {"reason_code": error.reason_code}

    with pytest.raises(TypeError, match="reason_code"):
        M6UpgradeWholeSampleRecordBuilderError(  # type: ignore[arg-type]
            "OBSERVATION_CLOSURE_MISMATCH"
        )


def test_whole_sample_record_builder_port_adds_no_serialization_schema() -> None:
    schemas = expected_schema_files()
    assert not any("whole-sample-record-builder" in name for name in schemas)

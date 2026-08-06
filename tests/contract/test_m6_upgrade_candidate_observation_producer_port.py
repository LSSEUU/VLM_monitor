from __future__ import annotations

import inspect

import pytest

from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.ports.m6_upgrade_candidate_observation_producer import (
    M6UpgradeCandidateObservationProducerError,
    M6UpgradeCandidateObservationProducerFailureCode,
    M6UpgradeCandidateObservationProducerV3,
)
from labcourt.schema_export import expected_schema_files


def test_candidate_observation_producer_exposes_only_two_durable_identities() -> None:
    method = M6UpgradeCandidateObservationProducerV3.produce_next_observation
    assert tuple(inspect.signature(method).parameters) == (
        "self",
        "candidate_run_id",
        "execution_scope_authority_id",
    )
    assert inspect.get_annotations(method, eval_str=True) == {
        "candidate_run_id": str,
        "execution_scope_authority_id": str,
        "return": M6UpgradeSampleExecutionObservationAuthorityV2,
    }
    forbidden_inputs = {
        "scope",
        "catalog",
        "entry",
        "observation",
        "artifact",
        "model_call",
        "outcome",
        "membership",
        "gold",
        "truth",
        "provider",
        "verifier",
    }
    public_inputs = set(inspect.signature(method).parameters) - {"self"}
    assert public_inputs.isdisjoint(forbidden_inputs)


def test_candidate_observation_producer_failure_is_closed_and_payload_free() -> None:
    assert {item.value for item in M6UpgradeCandidateObservationProducerFailureCode} == {
        "INVALID_ARGUMENT",
        "SCOPE_NOT_FOUND",
        "OBSERVATION_ALREADY_EXISTS",
        "APPEND_STATE_MISMATCH",
        "LEDGER_COMPLETE",
        "LEDGER_SEALED",
        "CATALOG_NOT_FOUND",
        "CATALOG_REJECTED",
        "CANDIDATE_PERCEPTION_REJECTED",
        "SOURCE_CLOSURE_REJECTED",
        "DOCUMENT_TOO_LARGE",
        "STORED_AUTHORITY_INVALID",
        "STORAGE_REJECTED",
    }
    error = M6UpgradeCandidateObservationProducerError(
        M6UpgradeCandidateObservationProducerFailureCode.CATALOG_REJECTED
    )
    assert error.args == ("M6 candidate observation production failed: CATALOG_REJECTED",)
    assert vars(error) == {"reason_code": error.reason_code}
    assert error.__context__ is None
    assert error.__cause__ is None
    with pytest.raises(TypeError, match="reason_code"):
        M6UpgradeCandidateObservationProducerError("CATALOG_REJECTED")  # type: ignore[arg-type]


def test_candidate_observation_producer_adds_no_wire_schema() -> None:
    assert not any("candidate-observation-producer" in name for name in expected_schema_files())

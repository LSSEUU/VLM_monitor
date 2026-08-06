from __future__ import annotations

import inspect

import pytest

from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthorityV3,
)
from labcourt.ports import (
    M6UpgradeCandidateOutputBuilder,
    M6UpgradeCandidateOutputError,
    M6UpgradeCandidateOutputFailureCode,
)
from labcourt.schema_export import expected_schema_files


class _StructuralCandidateOutputBuilder:
    def build_terminal_inventory(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
        del candidate_run_id, execution_scope_authority_id
        raise AssertionError("structural port check must not invoke the builder")


class _MissingCandidateOutputBuilder:
    pass


def test_candidate_output_builder_accepts_only_durable_scope_identities() -> None:
    method = M6UpgradeCandidateOutputBuilder.build_terminal_inventory
    assert tuple(inspect.signature(method).parameters) == (
        "self",
        "candidate_run_id",
        "execution_scope_authority_id",
    )
    assert inspect.get_annotations(method, eval_str=True) == {
        "candidate_run_id": str,
        "execution_scope_authority_id": str,
        "return": M6UpgradeCandidateOutputInventoryAuthorityV3,
    }

    forbidden_inputs = {
        "scope",
        "observation",
        "record",
        "commitment",
        "ledger",
        "seal",
        "run_cut",
        "candidate_case",
        "anchor",
        "snapshot",
        "artifact",
        "model_call",
        "output",
        "receipt",
        "inventory",
        "authority",
        "payload",
        "document",
        "digest",
        "size",
        "verifier",
    }
    public_inputs = set(inspect.signature(method).parameters) - {"self"}
    assert public_inputs == {"candidate_run_id", "execution_scope_authority_id"}
    assert public_inputs.isdisjoint(forbidden_inputs)
    assert M6UpgradeCandidateOutputInventoryAuthorityV3.model_config["frozen"] is True


def test_candidate_output_failure_is_exact_typed_and_payload_free() -> None:
    assert {item.value for item in M6UpgradeCandidateOutputFailureCode} == {
        "INVALID_ARGUMENT",
        "SCOPE_NOT_FOUND",
        "LEDGER_VERSION_UNSUPPORTED",
        "LEDGER_NOT_SEALED",
        "RUN_CUT_NOT_FOUND",
        "RUN_CUT_MISMATCH",
        "OBSERVATION_CLOSURE_MISMATCH",
        "CASE_BINDING_MISMATCH",
        "MODEL_CALL_CLOSURE_MISMATCH",
        "PHYSICAL_ARTIFACT_REJECTED",
        "INVENTORY_CLOSURE_MISMATCH",
        "DOCUMENT_TOO_LARGE",
        "STORED_AUTHORITY_INVALID",
        "SNAPSHOT_REJECTED",
        "STORAGE_REJECTED",
    }

    error = M6UpgradeCandidateOutputError(
        M6UpgradeCandidateOutputFailureCode.INVENTORY_CLOSURE_MISMATCH
    )
    assert error.args == ("M6 upgrade candidate output build failed: INVENTORY_CLOSURE_MISMATCH",)
    assert vars(error) == {"reason_code": error.reason_code}
    assert not hasattr(error, "payload")

    with pytest.raises(TypeError, match="reason_code"):
        M6UpgradeCandidateOutputError(
            "INVENTORY_CLOSURE_MISMATCH"  # type: ignore[arg-type]
        )


def test_candidate_output_builder_is_runtime_checkable_by_structure() -> None:
    assert isinstance(_StructuralCandidateOutputBuilder(), M6UpgradeCandidateOutputBuilder)
    assert not isinstance(_MissingCandidateOutputBuilder(), M6UpgradeCandidateOutputBuilder)


def test_candidate_output_port_adds_no_serialization_schema() -> None:
    schemas = expected_schema_files()
    assert "m6-upgrade-candidate-output-inventory-authority-v3.schema.json" in schemas
    assert not any("candidate-output-builder" in name for name in schemas)

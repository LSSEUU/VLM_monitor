from __future__ import annotations

import hashlib

import pytest

import labcourt.application.m6_upgrade_regression as upgrade_module
from labcourt.application.m6_upgrade_regression import (
    M6UpgradeRegressionAssemblyError,
    M6UpgradeRegressionAssemblyErrorCode,
    assemble_m6_upgrade_regression_report,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import M6RegressionDisposition
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthorityV3,
)
from tests.contract.test_m6_regression_contracts import _minimal_dataset
from tests.contract.test_m6_regression_execution_contracts import _inventory
from tests.contract.test_m6_upgrade_observation_backed_inventory_contracts import (
    _v2_inventory,
    _v3_inventory,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _legacy_inputs() -> dict[str, object]:
    outputs = _inventory()
    dataset = _minimal_dataset()
    assert outputs.execution_dataset == dataset.execution_dataset
    command = outputs.command
    return {
        "command": command,
        "command_document": canonical_json(command.model_dump(mode="json")),
        "dataset": dataset,
        "dataset_document": canonical_json(dataset.model_dump(mode="json")),
        "candidate_output_inventory": outputs,
        "candidate_output_inventory_document": canonical_json(outputs.model_dump(mode="json")),
    }


def _inputs() -> dict[str, object]:
    outputs = _v3_inventory()
    dataset = _minimal_dataset()
    assert outputs.execution_dataset == dataset.execution_dataset
    command = outputs.command
    return {
        "command": command,
        "command_document": canonical_json(command.model_dump(mode="json")),
        "dataset": dataset,
        "dataset_document": canonical_json(dataset.model_dump(mode="json")),
        "candidate_output_inventory": outputs,
        "candidate_output_inventory_document": canonical_json(outputs.model_dump(mode="json")),
    }


def _v3_inputs() -> dict[str, object]:
    return _inputs()


def test_assembler_derives_results_receipts_and_release_gate_from_outputs() -> None:
    inputs = _inputs()
    bundle = assemble_m6_upgrade_regression_report(**inputs)

    report = bundle.report
    outputs = inputs["candidate_output_inventory"]
    assert isinstance(outputs, M6UpgradeCandidateOutputInventoryAuthorityV3)
    assert report.disposition == M6RegressionDisposition.PASSED
    assert report.release_allowed
    assert tuple(report.execution_receipts) == tuple(
        item.execution_receipt for item in outputs.outputs
    )
    assert tuple(result.candidate_snapshot for result in report.results) == tuple(
        item.candidate_snapshot for item in outputs.outputs
    )
    assert bundle.report_document == canonical_json(report.model_dump(mode="json"))
    assert bundle.report_content_sha256 == _sha(bundle.report_document)


def test_assembler_preserves_terminal_v3_inventory_and_frozen_report_wire() -> None:
    inputs = _v3_inputs()

    bundle = assemble_m6_upgrade_regression_report(**inputs)

    outputs = inputs["candidate_output_inventory"]
    assert isinstance(outputs, M6UpgradeCandidateOutputInventoryAuthorityV3)
    assert type(bundle.candidate_output_inventory) is M6UpgradeCandidateOutputInventoryAuthorityV3
    assert bundle.candidate_output_inventory == outputs
    assert bundle.candidate_output_inventory.schema_version == (
        "m6-upgrade-candidate-output-inventory-authority-v3"
    )
    assert bundle.report.schema_version == "m6-regression-report-v1"
    assert tuple(bundle.report.execution_receipts) == tuple(
        item.execution_receipt for item in outputs.outputs
    )


def test_assembler_rejects_document_tamper_and_missing_output_authority() -> None:
    inputs = _inputs()
    tampered = dict(inputs)
    tampered["candidate_output_inventory_document"] = (
        str(inputs["candidate_output_inventory_document"]) + " "
    )
    with pytest.raises(M6UpgradeRegressionAssemblyError) as document:
        assemble_m6_upgrade_regression_report(**tampered)
    assert document.value.code == M6UpgradeRegressionAssemblyErrorCode.DOCUMENT_INVALID

    outputs = inputs["candidate_output_inventory"]
    assert isinstance(outputs, M6UpgradeCandidateOutputInventoryAuthorityV3)
    incomplete = M6UpgradeCandidateOutputInventoryAuthorityV3.model_construct(
        command=outputs.command,
        execution_dataset=outputs.execution_dataset,
        candidate_run_cut=outputs.candidate_run_cut,
        execution_ledger=outputs.execution_ledger,
        execution_ledger_content_sha256=outputs.execution_ledger_content_sha256,
        execution_ledger_size_bytes=outputs.execution_ledger_size_bytes,
        candidate_cases=outputs.candidate_cases,
        outputs=outputs.outputs[:-1],
        execution_observations=outputs.execution_observations,
    )
    attacked = dict(inputs)
    attacked["candidate_output_inventory"] = incomplete
    attacked["candidate_output_inventory_document"] = inputs["candidate_output_inventory_document"]
    with pytest.raises(M6UpgradeRegressionAssemblyError) as missing:
        assemble_m6_upgrade_regression_report(**attacked)
    assert missing.value.code == (M6UpgradeRegressionAssemblyErrorCode.CANDIDATE_OUTPUT_MISMATCH)


def test_assembler_rejects_legacy_inventory_instead_of_downgrading_v3_gate() -> None:
    with pytest.raises(M6UpgradeRegressionAssemblyError) as legacy:
        assemble_m6_upgrade_regression_report(**_legacy_inputs())

    assert legacy.value.code == M6UpgradeRegressionAssemblyErrorCode.CANDIDATE_OUTPUT_MISMATCH

    v2 = _v2_inventory()
    v2_inputs = _inputs()
    v2_inputs["candidate_output_inventory"] = v2
    v2_inputs["candidate_output_inventory_document"] = canonical_json(v2.model_dump(mode="json"))
    with pytest.raises(M6UpgradeRegressionAssemblyError) as observation_v1:
        assemble_m6_upgrade_regression_report(**v2_inputs)

    assert observation_v1.value.code == (
        M6UpgradeRegressionAssemblyErrorCode.CANDIDATE_OUTPUT_MISMATCH
    )


def test_assembler_enforces_explicit_input_and_report_document_budgets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs()
    monkeypatch.setattr(upgrade_module, "MAX_M6_UPGRADE_REGRESSION_DOCUMENT_BYTES", 1)
    with pytest.raises(M6UpgradeRegressionAssemblyError) as oversized:
        assemble_m6_upgrade_regression_report(**inputs)
    assert oversized.value.code == M6UpgradeRegressionAssemblyErrorCode.DOCUMENT_TOO_LARGE

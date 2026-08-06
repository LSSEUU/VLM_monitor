from __future__ import annotations

from pathlib import Path

import pytest

import labcourt.services.m6_upgrade_regression as runner_module
from labcourt.adapters.storage.m6_regression_store import M6StoredRegressionBundle
from labcourt.ports.m6_upgrade_candidate_coordinator import (
    M6UpgradeCandidateCoordinatorError,
    M6UpgradeCandidateCoordinatorFailureCode,
)
from labcourt.services.m6_upgrade_regression import (
    M6UpgradeRegressionRunError,
    M6UpgradeRegressionRunErrorCode,
    run_m6_upgrade_regression_v3,
)
from tests.contract.test_m6_upgrade_observation_backed_inventory_contracts import (
    _v3_inventory,
)
from tests.unit.test_m6_upgrade_regression import _inputs


class _Coordinator:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls = 0

    def run_to_terminal(self, _scope: object) -> object:
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    def resume_to_terminal(self, _run_id: str, _scope_id: str) -> object:
        raise AssertionError("run service must start from the exact supplied scope")


def test_runner_drives_terminal_v3_and_reads_back_atomic_report(tmp_path: Path) -> None:
    inputs = _inputs()
    inventory = inputs["candidate_output_inventory"]
    dataset = inputs["dataset"]
    coordinator = _Coordinator(inventory)

    result = run_m6_upgrade_regression_v3(
        execution_scope=inventory.execution_ledger.execution_scope,
        evaluator_dataset=dataset,
        evaluator_dataset_document=inputs["dataset_document"],
        coordinator=coordinator,
        output_root=tmp_path,
    )

    assert coordinator.calls == 1
    assert result.publication_result.report_path.is_file()
    assert result.stored_bundle.report == result.report_bundle.report
    assert result.stored_bundle.candidate_output_inventory == inventory
    assert result.stored_bundle.to_report_bundle() == result.report_bundle


def test_runner_exact_retry_reuses_terminal_inventory_and_publication(tmp_path: Path) -> None:
    inputs = _inputs()
    inventory = inputs["candidate_output_inventory"]
    coordinator = _Coordinator(inventory)
    arguments = {
        "execution_scope": inventory.execution_ledger.execution_scope,
        "evaluator_dataset": inputs["dataset"],
        "evaluator_dataset_document": inputs["dataset_document"],
        "coordinator": coordinator,
        "output_root": tmp_path,
    }

    first = run_m6_upgrade_regression_v3(**arguments)
    first_files = tuple(
        sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*") if path.is_file())
    )
    second = run_m6_upgrade_regression_v3(**arguments)
    second_files = tuple(
        sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*") if path.is_file())
    )

    assert coordinator.calls == 2
    assert second.report_bundle == first.report_bundle
    assert second.publication_bundle == first.publication_bundle
    assert second.publication_result == first.publication_result
    assert second.stored_bundle == first.stored_bundle
    assert second_files == first_files


def test_runner_rejects_evaluator_graft_before_candidate_execution(tmp_path: Path) -> None:
    inputs = _inputs()
    inventory = inputs["candidate_output_inventory"]
    dataset = inputs["dataset"]
    grafted = dataset.model_copy(
        update={
            "execution_dataset": dataset.execution_dataset.model_copy(
                update={"source_catalog_document_sha256": "0" * 64}
            )
        }
    )
    coordinator = _Coordinator(inventory)

    with pytest.raises(M6UpgradeRegressionRunError) as raised:
        run_m6_upgrade_regression_v3(
            execution_scope=inventory.execution_ledger.execution_scope,
            evaluator_dataset=grafted,
            evaluator_dataset_document=inputs["dataset_document"],
            coordinator=coordinator,
            output_root=tmp_path,
        )

    assert raised.value.code == M6UpgradeRegressionRunErrorCode.DATASET_SCOPE_MISMATCH
    assert coordinator.calls == 0
    assert not tuple(tmp_path.iterdir())


def test_runner_rejects_oversized_dataset_document_before_candidate_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs()
    inventory = inputs["candidate_output_inventory"]
    coordinator = _Coordinator(inventory)
    monkeypatch.setattr(runner_module, "MAX_M6_UPGRADE_REGRESSION_DOCUMENT_BYTES", 1)

    with pytest.raises(M6UpgradeRegressionRunError) as raised:
        run_m6_upgrade_regression_v3(
            execution_scope=inventory.execution_ledger.execution_scope,
            evaluator_dataset=inputs["dataset"],
            evaluator_dataset_document=inputs["dataset_document"],
            coordinator=coordinator,
            output_root=tmp_path,
        )

    assert raised.value.code == M6UpgradeRegressionRunErrorCode.DATASET_DOCUMENT_TOO_LARGE
    assert coordinator.calls == 0
    assert not tuple(tmp_path.iterdir())


def test_runner_maps_coordinator_failure_without_publishing(tmp_path: Path) -> None:
    inputs = _inputs()
    inventory = inputs["candidate_output_inventory"]
    coordinator = _Coordinator(
        M6UpgradeCandidateCoordinatorError(
            M6UpgradeCandidateCoordinatorFailureCode.STORAGE_REJECTED
        )
    )

    with pytest.raises(M6UpgradeRegressionRunError) as raised:
        run_m6_upgrade_regression_v3(
            execution_scope=inventory.execution_ledger.execution_scope,
            evaluator_dataset=inputs["dataset"],
            evaluator_dataset_document=inputs["dataset_document"],
            coordinator=coordinator,
            output_root=tmp_path,
        )

    assert raised.value.code == M6UpgradeRegressionRunErrorCode.CANDIDATE_EXECUTION_REJECTED
    assert coordinator.calls == 1
    assert not tuple(tmp_path.iterdir())


def test_runner_rejects_foreign_terminal_scope_before_publishing(tmp_path: Path) -> None:
    inputs = _inputs()
    expected_inventory = inputs["candidate_output_inventory"]
    foreign_inventory = _v3_inventory(candidate_run_id="run-foreign-candidate")
    coordinator = _Coordinator(foreign_inventory)

    with pytest.raises(M6UpgradeRegressionRunError) as raised:
        run_m6_upgrade_regression_v3(
            execution_scope=expected_inventory.execution_ledger.execution_scope,
            evaluator_dataset=inputs["dataset"],
            evaluator_dataset_document=inputs["dataset_document"],
            coordinator=coordinator,
            output_root=tmp_path,
        )

    assert raised.value.code == M6UpgradeRegressionRunErrorCode.CANDIDATE_SCOPE_MISMATCH
    assert coordinator.calls == 1
    assert not tuple(tmp_path.iterdir())


def test_runner_rejects_invalid_output_root_before_candidate_execution(tmp_path: Path) -> None:
    inputs = _inputs()
    inventory = inputs["candidate_output_inventory"]
    coordinator = _Coordinator(inventory)

    with pytest.raises(M6UpgradeRegressionRunError) as raised:
        run_m6_upgrade_regression_v3(
            execution_scope=inventory.execution_ledger.execution_scope,
            evaluator_dataset=inputs["dataset"],
            evaluator_dataset_document=inputs["dataset_document"],
            coordinator=coordinator,
            output_root="invalid\x00root",
        )

    assert raised.value.code == M6UpgradeRegressionRunErrorCode.INVALID_ARGUMENT
    assert coordinator.calls == 0
    assert not tuple(tmp_path.iterdir())


def test_runner_rejects_unusable_output_root_before_candidate_execution(
    tmp_path: Path,
) -> None:
    inputs = _inputs()
    inventory = inputs["candidate_output_inventory"]
    coordinator = _Coordinator(inventory)
    output_file = tmp_path / "not-a-directory"
    output_file.write_text("occupied", encoding="utf-8")

    with pytest.raises(M6UpgradeRegressionRunError) as raised:
        run_m6_upgrade_regression_v3(
            execution_scope=inventory.execution_ledger.execution_scope,
            evaluator_dataset=inputs["dataset"],
            evaluator_dataset_document=inputs["dataset_document"],
            coordinator=coordinator,
            output_root=output_file,
        )

    assert raised.value.code == M6UpgradeRegressionRunErrorCode.PUBLICATION_REJECTED
    assert coordinator.calls == 0
    assert output_file.read_text(encoding="utf-8") == "occupied"


def test_runner_rejects_linked_output_root_before_candidate_execution(
    tmp_path: Path,
) -> None:
    inputs = _inputs()
    inventory = inputs["candidate_output_inventory"]
    coordinator = _Coordinator(inventory)
    target = tmp_path / "real-output"
    target.mkdir()
    linked = tmp_path / "linked-output"
    try:
        linked.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable in this environment")

    with pytest.raises(M6UpgradeRegressionRunError) as raised:
        run_m6_upgrade_regression_v3(
            execution_scope=inventory.execution_ledger.execution_scope,
            evaluator_dataset=inputs["dataset"],
            evaluator_dataset_document=inputs["dataset_document"],
            coordinator=coordinator,
            output_root=linked,
        )

    assert raised.value.code == M6UpgradeRegressionRunErrorCode.PUBLICATION_REJECTED
    assert coordinator.calls == 0


@pytest.mark.parametrize("returned", [object(), RuntimeError("secret C:/alice")])
def test_runner_closes_untrusted_coordinator_failures_without_publishing(
    tmp_path: Path,
    returned: object,
) -> None:
    inputs = _inputs()
    inventory = inputs["candidate_output_inventory"]
    coordinator = _Coordinator(returned)

    with pytest.raises(M6UpgradeRegressionRunError) as raised:
        run_m6_upgrade_regression_v3(
            execution_scope=inventory.execution_ledger.execution_scope,
            evaluator_dataset=inputs["dataset"],
            evaluator_dataset_document=inputs["dataset_document"],
            coordinator=coordinator,
            output_root=tmp_path,
        )

    assert raised.value.code == M6UpgradeRegressionRunErrorCode.CANDIDATE_EXECUTION_REJECTED
    assert raised.value.__cause__ is None
    assert coordinator.calls == 1
    assert not tuple(tmp_path.iterdir())


def test_runner_maps_readback_rebuild_failure_to_typed_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs()
    inventory = inputs["candidate_output_inventory"]

    def _fail_rebuild(_stored: M6StoredRegressionBundle) -> object:
        raise RuntimeError("secret C:/alice")

    monkeypatch.setattr(M6StoredRegressionBundle, "to_report_bundle", _fail_rebuild)

    with pytest.raises(M6UpgradeRegressionRunError) as raised:
        run_m6_upgrade_regression_v3(
            execution_scope=inventory.execution_ledger.execution_scope,
            evaluator_dataset=inputs["dataset"],
            evaluator_dataset_document=inputs["dataset_document"],
            coordinator=_Coordinator(inventory),
            output_root=tmp_path,
        )

    assert raised.value.code == M6UpgradeRegressionRunErrorCode.READBACK_REJECTED
    assert raised.value.__cause__ is None

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import pytest

import labcourt.services.m6_replay_locked_closed_policy_regression as runner_module
from labcourt.application.m6_replay_locked_closed_policy_execution import (
    build_m6_replay_locked_closed_policy_execution_scope,
)
from labcourt.application.m6_replay_locked_execution_scope import (
    build_m6_replay_locked_execution_scope,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6RegressionExecutionSourceCatalogError,
    M6RegressionExecutionSourceCatalogFailureCode,
)
from labcourt.ports.m6_replay_locked_closed_policy_coordinator import (
    M6ReplayLockedClosedPolicyCoordinatorError,
    M6ReplayLockedClosedPolicyCoordinatorFailureCode,
)
from labcourt.services.m6_replay_locked_closed_policy_regression import (
    M6ReplayLockedClosedPolicyRegressionRunError,
    M6ReplayLockedClosedPolicyRegressionRunErrorCode,
    M6ReplayLockedClosedPolicyRegressionRunResult,
    run_m6_replay_locked_closed_policy_regression_v2,
)
from tests.integration.test_m6_regression_execution_source_catalog_store import (
    _catalog as _catalog_bundle,
)
from tests.integration.test_m6_regression_execution_source_catalog_store import (
    _expected as _expected_catalog,
)
from tests.unit.test_m6_replay_locked_closed_policy_regression import (
    _document,
    _facts,
)


class _Coordinator:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[tuple[object, object]] = []

    def run_to_terminal(
        self,
        execution_scope: object,
        stored_source_catalog: object,
    ) -> object:
        self.calls.append((execution_scope, stored_source_catalog))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class _CatalogProvider:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[tuple[str, str]] = []

    def load(
        self,
        source_catalog_authority_id: str,
        source_catalog_document_sha256: str,
    ) -> object:
        self.calls.append(
            (
                source_catalog_authority_id,
                source_catalog_document_sha256,
            )
        )
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@lru_cache(maxsize=1)
def _closed_facts():  # type: ignore[no-untyped-def]
    return _facts()


@lru_cache(maxsize=1)
def _foreign_catalog():  # type: ignore[no-untyped-def]
    return _expected_catalog(_catalog_bundle("closed-runner-foreign-catalog"))


@lru_cache(maxsize=1)
def _foreign_scope():  # type: ignore[no-untyped-def]
    facts = _closed_facts()
    scope = facts.seal.execution_scope
    pre_policy = scope.pre_policy_execution_scope
    foreign_pre_policy = build_m6_replay_locked_execution_scope(
        candidate_run_id="closed-runner-foreign-candidate",
        command=pre_policy.command,
        execution_dataset=pre_policy.execution_dataset,
        stored_source_catalog=facts.stored_catalog,
        locked_manifest=pre_policy.locked_manifest,
        locked_config=pre_policy.locked_config,
        execution_component=pre_policy.execution_component,
    )
    return build_m6_replay_locked_closed_policy_execution_scope(
        pre_policy_execution_scope=foreign_pre_policy,
        execution_component=scope.execution_component,
    )


def _catalog_identity() -> tuple[str, str]:
    stored = _closed_facts().stored_catalog
    return (
        stored.source_catalog.source_catalog_authority_id,
        stored.content_sha256,
    )


def _arguments(
    tmp_path: Path,
    *,
    coordinator: _Coordinator | None = None,
    provider: _CatalogProvider | None = None,
) -> dict[str, object]:
    facts = _closed_facts()
    return {
        "execution_scope": facts.seal.execution_scope,
        "stored_source_catalog": facts.stored_catalog,
        "evaluator_dataset": facts.dataset,
        "evaluator_dataset_document": _document(facts.dataset),
        "coordinator": coordinator or _Coordinator(facts.seal),
        "source_catalog_provider": provider or _CatalogProvider(facts.stored_catalog),
        "output_root": tmp_path,
    }


def test_closed_policy_runner_executes_seal_and_reads_back_atomic_publication(
    tmp_path: Path,
) -> None:
    facts = _closed_facts()
    coordinator = _Coordinator(facts.seal)
    provider = _CatalogProvider(facts.stored_catalog)

    result = run_m6_replay_locked_closed_policy_regression_v2(
        **_arguments(tmp_path, coordinator=coordinator, provider=provider)
    )

    assert type(result) is M6ReplayLockedClosedPolicyRegressionRunResult
    assert coordinator.calls == [(facts.seal.execution_scope, facts.stored_catalog)]
    assert provider.calls
    assert set(provider.calls) == {_catalog_identity()}
    assert result.execution_seal == facts.seal
    assert result.report_bundle.execution_seal == facts.seal
    assert result.report_bundle.stored_source_catalog == facts.stored_catalog
    assert result.publication_bundle.report_bundle == result.report_bundle
    assert result.publication_result.report_path.is_file()
    assert result.stored_bundle.report_bundle == result.report_bundle
    assert result.stored_bundle.to_publication_bundle() == result.publication_bundle


def test_closed_policy_runner_exact_retry_reuses_seal_report_and_publication(
    tmp_path: Path,
) -> None:
    facts = _closed_facts()
    coordinator = _Coordinator(facts.seal)
    provider = _CatalogProvider(facts.stored_catalog)
    arguments = _arguments(tmp_path, coordinator=coordinator, provider=provider)

    first = run_m6_replay_locked_closed_policy_regression_v2(**arguments)
    first_files = tuple(
        sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*") if path.is_file())
    )
    second = run_m6_replay_locked_closed_policy_regression_v2(**arguments)
    second_files = tuple(
        sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*") if path.is_file())
    )

    assert len(coordinator.calls) == 2
    assert second == first
    assert second_files == first_files
    assert set(provider.calls) == {_catalog_identity()}


@pytest.mark.parametrize(
    ("field", "value", "expected_code"),
    (
        (
            "execution_scope",
            object(),
            M6ReplayLockedClosedPolicyRegressionRunErrorCode.INVALID_ARGUMENT,
        ),
        (
            "stored_source_catalog",
            object(),
            M6ReplayLockedClosedPolicyRegressionRunErrorCode.SOURCE_CATALOG_INVALID,
        ),
        (
            "evaluator_dataset",
            object(),
            M6ReplayLockedClosedPolicyRegressionRunErrorCode.DATASET_INVALID,
        ),
        (
            "coordinator",
            object(),
            M6ReplayLockedClosedPolicyRegressionRunErrorCode.INVALID_ARGUMENT,
        ),
        (
            "source_catalog_provider",
            object(),
            M6ReplayLockedClosedPolicyRegressionRunErrorCode.INVALID_ARGUMENT,
        ),
    ),
)
def test_runner_rejects_untyped_inputs_before_candidate_execution(
    tmp_path: Path,
    field: str,
    value: object,
    expected_code: M6ReplayLockedClosedPolicyRegressionRunErrorCode,
) -> None:
    coordinator = _Coordinator(_closed_facts().seal)
    arguments = _arguments(tmp_path, coordinator=coordinator)
    arguments[field] = value

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionRunError) as raised:
        run_m6_replay_locked_closed_policy_regression_v2(**arguments)

    assert raised.value.code is expected_code
    assert raised.value.__cause__ is None
    assert coordinator.calls == []
    assert not tuple(tmp_path.iterdir())


def test_runner_rejects_catalog_scope_graft_before_candidate_execution(
    tmp_path: Path,
) -> None:
    coordinator = _Coordinator(_closed_facts().seal)
    foreign = _foreign_catalog()
    arguments = _arguments(
        tmp_path,
        coordinator=coordinator,
        provider=_CatalogProvider(foreign),
    )
    arguments["stored_source_catalog"] = foreign

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionRunError) as raised:
        run_m6_replay_locked_closed_policy_regression_v2(**arguments)

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyRegressionRunErrorCode.SOURCE_CATALOG_MISMATCH
    )
    assert coordinator.calls == []
    assert not tuple(tmp_path.iterdir())


def test_runner_rejects_durable_catalog_mismatch_before_candidate_execution(
    tmp_path: Path,
) -> None:
    coordinator = _Coordinator(_closed_facts().seal)
    provider = _CatalogProvider(_foreign_catalog())

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionRunError) as raised:
        run_m6_replay_locked_closed_policy_regression_v2(
            **_arguments(tmp_path, coordinator=coordinator, provider=provider)
        )

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyRegressionRunErrorCode.SOURCE_CATALOG_MISMATCH
    )
    assert provider.calls == [_catalog_identity()]
    assert coordinator.calls == []
    assert not tuple(tmp_path.iterdir())


def test_runner_maps_catalog_provider_failure_without_payload_or_execution(
    tmp_path: Path,
) -> None:
    coordinator = _Coordinator(_closed_facts().seal)
    provider = _CatalogProvider(
        M6RegressionExecutionSourceCatalogError(
            M6RegressionExecutionSourceCatalogFailureCode.CATALOG_NOT_FOUND
        )
    )

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionRunError) as raised:
        run_m6_replay_locked_closed_policy_regression_v2(
            **_arguments(tmp_path, coordinator=coordinator, provider=provider)
        )

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyRegressionRunErrorCode.SOURCE_CATALOG_LOAD_REJECTED
    )
    assert raised.value.__cause__ is None
    assert vars(raised.value) == {"code": raised.value.code}
    assert provider.calls == [_catalog_identity()]
    assert coordinator.calls == []
    assert not tuple(tmp_path.iterdir())


def test_runner_rejects_evaluator_scope_graft_before_candidate_execution(
    tmp_path: Path,
) -> None:
    facts = _closed_facts()
    execution_dataset = facts.dataset.execution_dataset.model_copy(
        update={"source_catalog_document_sha256": "0" * 64}
    )
    grafted = facts.dataset.model_copy(update={"execution_dataset": execution_dataset})
    coordinator = _Coordinator(facts.seal)
    arguments = _arguments(tmp_path, coordinator=coordinator)
    arguments.update(
        {
            "evaluator_dataset": grafted,
            "evaluator_dataset_document": canonical_json(grafted.model_dump(mode="json")),
        }
    )

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionRunError) as raised:
        run_m6_replay_locked_closed_policy_regression_v2(**arguments)

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyRegressionRunErrorCode.DATASET_SCOPE_MISMATCH
    )
    assert coordinator.calls == []
    assert not tuple(tmp_path.iterdir())


def test_runner_rejects_noncanonical_dataset_document_before_candidate_execution(
    tmp_path: Path,
) -> None:
    coordinator = _Coordinator(_closed_facts().seal)
    arguments = _arguments(tmp_path, coordinator=coordinator)
    arguments["evaluator_dataset_document"] = str(arguments["evaluator_dataset_document"]) + " "

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionRunError) as raised:
        run_m6_replay_locked_closed_policy_regression_v2(**arguments)

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyRegressionRunErrorCode.DATASET_DOCUMENT_INVALID
    )
    assert coordinator.calls == []
    assert not tuple(tmp_path.iterdir())


def test_runner_rejects_oversized_dataset_document_before_candidate_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator = _Coordinator(_closed_facts().seal)
    monkeypatch.setattr(
        runner_module,
        "MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_DOCUMENT_BYTES",
        1,
    )

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionRunError) as raised:
        run_m6_replay_locked_closed_policy_regression_v2(
            **_arguments(tmp_path, coordinator=coordinator)
        )

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyRegressionRunErrorCode.DATASET_DOCUMENT_TOO_LARGE
    )
    assert coordinator.calls == []
    assert not tuple(tmp_path.iterdir())


def test_runner_rejects_foreign_terminal_seal_before_publication(tmp_path: Path) -> None:
    facts = _closed_facts()
    coordinator = _Coordinator(facts.seal)
    arguments = _arguments(tmp_path, coordinator=coordinator)
    arguments["execution_scope"] = _foreign_scope()

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionRunError) as raised:
        run_m6_replay_locked_closed_policy_regression_v2(**arguments)

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyRegressionRunErrorCode.CANDIDATE_SCOPE_MISMATCH
    )
    assert len(coordinator.calls) == 1
    assert not tuple(path for path in tmp_path.rglob("*") if path.is_file())


@pytest.mark.parametrize(
    "returned",
    (
        object(),
        RuntimeError("secret C:/alice"),
        M6ReplayLockedClosedPolicyCoordinatorError(
            M6ReplayLockedClosedPolicyCoordinatorFailureCode.PENDING_REJECTED
        ),
    ),
)
def test_runner_closes_untrusted_coordinator_failures_without_publishing(
    tmp_path: Path,
    returned: object,
) -> None:
    coordinator = _Coordinator(returned)

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionRunError) as raised:
        run_m6_replay_locked_closed_policy_regression_v2(
            **_arguments(tmp_path, coordinator=coordinator)
        )

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyRegressionRunErrorCode.CANDIDATE_EXECUTION_REJECTED
    )
    assert raised.value.__cause__ is None
    assert len(coordinator.calls) == 1
    assert not tuple(path for path in tmp_path.rglob("*") if path.is_file())


@pytest.mark.parametrize(
    ("output_root", "expected_code"),
    (
        (
            "invalid\x00root",
            M6ReplayLockedClosedPolicyRegressionRunErrorCode.INVALID_ARGUMENT,
        ),
        (
            None,
            M6ReplayLockedClosedPolicyRegressionRunErrorCode.INVALID_ARGUMENT,
        ),
    ),
)
def test_runner_rejects_invalid_output_root_before_candidate_execution(
    tmp_path: Path,
    output_root: object,
    expected_code: M6ReplayLockedClosedPolicyRegressionRunErrorCode,
) -> None:
    coordinator = _Coordinator(_closed_facts().seal)
    arguments = _arguments(tmp_path, coordinator=coordinator)
    arguments["output_root"] = output_root

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionRunError) as raised:
        run_m6_replay_locked_closed_policy_regression_v2(**arguments)

    assert raised.value.code is expected_code
    assert coordinator.calls == []
    assert not tuple(tmp_path.iterdir())


def test_runner_rejects_unusable_output_root_before_candidate_execution(
    tmp_path: Path,
) -> None:
    coordinator = _Coordinator(_closed_facts().seal)
    output_file = tmp_path / "not-a-directory"
    output_file.write_text("occupied", encoding="utf-8")
    arguments = _arguments(tmp_path, coordinator=coordinator)
    arguments["output_root"] = output_file

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionRunError) as raised:
        run_m6_replay_locked_closed_policy_regression_v2(**arguments)

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyRegressionRunErrorCode.PUBLICATION_REJECTED
    )
    assert coordinator.calls == []
    assert output_file.read_text(encoding="utf-8") == "occupied"


def test_runner_maps_readback_rebuild_failure_to_payload_free_typed_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _BrokenStored:
        def to_publication_bundle(self) -> object:
            raise RuntimeError("secret C:/alice")

    class _BrokenReadback:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def load(self, _candidate_run_id: object) -> _BrokenStored:
            return _BrokenStored()

    monkeypatch.setattr(
        runner_module,
        "ReadonlyM6ReplayLockedClosedPolicyRegressionStore",
        _BrokenReadback,
    )

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionRunError) as raised:
        run_m6_replay_locked_closed_policy_regression_v2(**_arguments(tmp_path))

    assert raised.value.code is (M6ReplayLockedClosedPolicyRegressionRunErrorCode.READBACK_REJECTED)
    assert raised.value.__cause__ is None


def test_run_error_requires_typed_code_and_exposes_no_authority_payload() -> None:
    error = M6ReplayLockedClosedPolicyRegressionRunError(
        M6ReplayLockedClosedPolicyRegressionRunErrorCode.PUBLICATION_REJECTED
    )

    assert vars(error) == {"code": error.code}
    with pytest.raises(TypeError, match="run error code"):
        M6ReplayLockedClosedPolicyRegressionRunError("PUBLICATION_REJECTED")  # type: ignore[arg-type]

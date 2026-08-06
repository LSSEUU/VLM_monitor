from __future__ import annotations

from dataclasses import replace

import pytest

from labcourt.application.m6_upgrade_candidate_output import (
    build_m6_upgrade_candidate_model_call,
    build_m6_upgrade_candidate_output_inventory,
    build_m6_upgrade_candidate_sample_output,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthorityV3,
)
from labcourt.contracts.m6_replay_locked import M6LockedModelCallResultKind
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedModelCall,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
)
from labcourt.ports.m6_upgrade_candidate_output import (
    M6UpgradeCandidateOutputError,
    M6UpgradeCandidateOutputFailureCode,
)
from labcourt.ports.m6_upgrade_model_physical import (
    M6ObservedModelCallPhysicalClosure,
)
from tests.contract.test_m6_upgrade_observation_backed_inventory_contracts import (
    _v3_inventory,
)


def _physical_closures(
    inventory: M6UpgradeCandidateOutputInventoryAuthorityV3,
) -> tuple[tuple[M6ObservedModelCallPhysicalClosure, ...], ...]:
    groups: list[tuple[M6ObservedModelCallPhysicalClosure, ...]] = []
    for output, observation, record in zip(
        inventory.outputs,
        inventory.execution_observations,
        inventory.execution_ledger.sample_executions,
        strict=True,
    ):
        assert len(output.model_calls) == len(observation.model_calls)
        if not output.model_calls:
            assert record.candidate_case is None
            groups.append(())
            continue
        assert record.candidate_case is not None
        closures = tuple(
            M6ObservedModelCallPhysicalClosure(
                source_identity_sha256=sha256_hex(
                    ["unit-terminal-model-source", 1, output.sample_id, call.layer]
                ),
                run_id=output.candidate_run_id,
                case_id=record.candidate_case.case_id,
                manifest_id=output.candidate_manifest_id,
                layer=call.layer,
                role=call.role,
                attempt_index=call.attempt_index,
                timeout_ms=call.timeout_ms,
                execution_model_manifest_id=call.execution_model_manifest_id,
                request_ref=call.request_ref,
                result_kind=call.result_kind,
                response_ref=call.response_ref,
                cache_ref=call.cache_ref,
                parse_receipt_ref=call.parse_receipt_ref,
                parsed_output_ref=call.parsed_output_ref,
                failure_ref=call.failure_ref,
                usage_receipt_ref=call.usage_receipt_ref,
            )
            for call in output.model_calls
        )
        assert tuple(item.request_ref.artifact_id for item in closures) == tuple(
            item.request_id for item in observation.model_calls
        )
        groups.append(closures)
    return tuple(groups)


def _inputs() -> tuple[
    M6UpgradeCandidateOutputInventoryAuthorityV3,
    tuple[tuple[M6ObservedModelCallPhysicalClosure, ...], ...],
]:
    inventory = _v3_inventory()
    return inventory, _physical_closures(inventory)


def _assert_failure(
    expected: M6UpgradeCandidateOutputFailureCode,
    action: object,
) -> M6UpgradeCandidateOutputError:
    assert callable(action)
    with pytest.raises(M6UpgradeCandidateOutputError) as raised:
        action()
    assert raised.value.reason_code == expected
    assert vars(raised.value) == {"reason_code": expected}
    assert raised.value.__cause__ is None
    return raised.value


def test_terminal_inventory_reconstructs_the_frozen_v3_fixture_exactly() -> None:
    expected, closure_groups = _inputs()
    ledger = expected.execution_ledger

    rebuilt = build_m6_upgrade_candidate_output_inventory(
        execution_scope=ledger.execution_scope,
        execution_ledger=ledger,
        run_cut=expected.candidate_run_cut,
        observations=expected.execution_observations,
        candidate_snapshots=tuple(item.candidate_snapshot for item in expected.outputs),
        model_call_closures=closure_groups,
    )

    assert rebuilt == expected
    assert rebuilt.model_dump(mode="json") == expected.model_dump(mode="json")
    assert tuple(item.execution_receipt for item in rebuilt.outputs) == tuple(
        item.execution_receipt for item in expected.outputs
    )


def test_sample_output_reconstructs_no_case_and_case_replayed_exactly() -> None:
    expected, closure_groups = _inputs()
    scope = expected.execution_ledger.execution_scope

    for index in (0, 1):
        rebuilt = build_m6_upgrade_candidate_sample_output(
            execution_scope=scope,
            run_cut=expected.candidate_run_cut,
            record=expected.execution_ledger.sample_executions[index],
            observation=expected.execution_observations[index],
            candidate_snapshot=expected.outputs[index].candidate_snapshot,
            model_call_closures=closure_groups[index],
        )
        assert rebuilt == expected.outputs[index]
        assert rebuilt.execution_receipt == expected.outputs[index].execution_receipt

    assert expected.outputs[0].candidate_snapshot is None
    assert expected.outputs[0].model_calls == ()
    assert expected.outputs[1].candidate_snapshot is not None


def test_model_call_combines_failure_closure_with_observed_provider_fact() -> None:
    expected, closure_groups = _inputs()
    base = closure_groups[1][0]
    observed = expected.execution_observations[1].model_calls[0]
    document_sha256 = sha256_hex(["unit-terminal-model-failure-document", 1])
    failure_ref = M6UpgradePhysicalArtifactRef(
        source=base.request_ref.source,
        kind=M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
        artifact_id=sha256_hex(["unit-terminal-model-failure", 1]),
        document_sha256=document_sha256,
        content_sha256=document_sha256,
        size_bytes=97,
    )
    failure_observation = M6UpgradeObservedModelCall(
        request_id=base.request_ref.artifact_id,
        layer=base.layer,
        role=base.role,
        attempt_index=base.attempt_index,
        result_kind=M6LockedModelCallResultKind.FAILURE,
        provider_invoked=False,
    )
    failure_closure = replace(
        base,
        result_kind=M6LockedModelCallResultKind.FAILURE,
        response_ref=None,
        cache_ref=None,
        parse_receipt_ref=None,
        parsed_output_ref=None,
        failure_ref=failure_ref,
        usage_receipt_ref=None,
    )

    rebuilt = build_m6_upgrade_candidate_model_call(
        sample_id=expected.outputs[1].sample_id,
        observed_call=failure_observation,
        physical_closure=failure_closure,
    )

    assert rebuilt.result_kind == M6LockedModelCallResultKind.FAILURE
    assert rebuilt.provider_invoked is False
    assert rebuilt.request_ref == base.request_ref
    assert rebuilt.failure_ref == failure_ref
    assert rebuilt.artifact_refs == (base.request_ref, failure_ref)
    assert observed.provider_invoked is True


def test_terminal_inventory_rejects_reordered_observations_and_missing_sample_group() -> None:
    expected, closure_groups = _inputs()
    ledger = expected.execution_ledger
    snapshots = tuple(item.candidate_snapshot for item in expected.outputs)

    _assert_failure(
        M6UpgradeCandidateOutputFailureCode.OBSERVATION_CLOSURE_MISMATCH,
        lambda: build_m6_upgrade_candidate_output_inventory(
            execution_scope=ledger.execution_scope,
            execution_ledger=ledger,
            run_cut=expected.candidate_run_cut,
            observations=tuple(reversed(expected.execution_observations)),
            candidate_snapshots=snapshots,
            model_call_closures=closure_groups,
        ),
    )
    _assert_failure(
        M6UpgradeCandidateOutputFailureCode.INVENTORY_CLOSURE_MISMATCH,
        lambda: build_m6_upgrade_candidate_output_inventory(
            execution_scope=ledger.execution_scope,
            execution_ledger=ledger,
            run_cut=expected.candidate_run_cut,
            observations=expected.execution_observations,
            candidate_snapshots=snapshots,
            model_call_closures=closure_groups[:-1],
        ),
    )


def test_sample_output_rejects_cross_case_closure_graft_and_missing_model_ref() -> None:
    expected, closure_groups = _inputs()
    scope = expected.execution_ledger.execution_scope
    first_case = expected.execution_ledger.sample_executions[1]
    second_case = expected.execution_ledger.sample_executions[2]
    assert first_case.candidate_case is not None
    assert second_case.candidate_case is not None
    assert first_case.candidate_case.case_id != second_case.candidate_case.case_id

    _assert_failure(
        M6UpgradeCandidateOutputFailureCode.CASE_BINDING_MISMATCH,
        lambda: build_m6_upgrade_candidate_sample_output(
            execution_scope=scope,
            run_cut=expected.candidate_run_cut,
            record=first_case,
            observation=expected.execution_observations[1],
            candidate_snapshot=expected.outputs[1].candidate_snapshot,
            model_call_closures=closure_groups[2],
        ),
    )

    missing_optional_ref = replace(closure_groups[1][0], parsed_output_ref=None)
    _assert_failure(
        M6UpgradeCandidateOutputFailureCode.PHYSICAL_ARTIFACT_REJECTED,
        lambda: build_m6_upgrade_candidate_sample_output(
            execution_scope=scope,
            run_cut=expected.candidate_run_cut,
            record=first_case,
            observation=expected.execution_observations[1],
            candidate_snapshot=expected.outputs[1].candidate_snapshot,
            model_call_closures=(missing_optional_ref,),
        ),
    )


def test_sample_output_rejects_cache_usage_that_conflicts_with_provider_delivery() -> None:
    expected, closure_groups = _inputs()
    record = expected.execution_ledger.sample_executions[1]
    changed_links = tuple(
        link.model_copy(update={"usage": M6UpgradeArtifactUsage.CONSUMED})
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.MODEL_CACHE
        else link
        for link in record.artifact_links
    )
    changed_record = M6UpgradeSampleExecutionRecordV2.model_validate(
        record.model_copy(update={"artifact_links": changed_links}).model_dump(
            mode="json",
            exclude_computed_fields=True,
        )
    )

    _assert_failure(
        M6UpgradeCandidateOutputFailureCode.PHYSICAL_ARTIFACT_REJECTED,
        lambda: build_m6_upgrade_candidate_sample_output(
            execution_scope=expected.execution_ledger.execution_scope,
            run_cut=expected.candidate_run_cut,
            record=changed_record,
            observation=expected.execution_observations[1],
            candidate_snapshot=expected.outputs[1].candidate_snapshot,
            model_call_closures=closure_groups[1],
        ),
    )


def test_composer_rejects_noncanonical_authority_and_physical_closure() -> None:
    expected, closure_groups = _inputs()
    bad_observation = expected.execution_observations[1].model_copy(deep=True)
    object.__setattr__(bad_observation, "candidate_run_id", "")

    _assert_failure(
        M6UpgradeCandidateOutputFailureCode.INVALID_ARGUMENT,
        lambda: build_m6_upgrade_candidate_sample_output(
            execution_scope=expected.execution_ledger.execution_scope,
            run_cut=expected.candidate_run_cut,
            record=expected.execution_ledger.sample_executions[1],
            observation=bad_observation,
            candidate_snapshot=expected.outputs[1].candidate_snapshot,
            model_call_closures=closure_groups[1],
        ),
    )

    bad_closure = replace(closure_groups[1][0])
    object.__setattr__(bad_closure, "timeout_ms", True)
    _assert_failure(
        M6UpgradeCandidateOutputFailureCode.INVALID_ARGUMENT,
        lambda: build_m6_upgrade_candidate_model_call(
            sample_id=expected.outputs[1].sample_id,
            observed_call=expected.execution_observations[1].model_calls[0],
            physical_closure=bad_closure,
        ),
    )

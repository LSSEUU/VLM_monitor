from __future__ import annotations

import traceback
from types import SimpleNamespace
from typing import cast

import pytest

from labcourt.adapters.storage import _sqlite_m6_upgrade_acquisition_documents as subject
from labcourt.adapters.storage import _sqlite_m6_upgrade_acquisition_metadata as metadata
from labcourt.adapters.storage._sqlite_m6_upgrade_acquisition_plan import (
    M6SQLiteAcquisitionDocumentsPlan,
    M6SQLiteAcquisitionPlanFailureCode,
    _M6SQLiteAcquisitionMetadataFailure,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)


def _sha(value: int) -> str:
    return f"{value:064x}"


def _observation(
    kind: M6UpgradePhysicalArtifactKind,
    value: int,
) -> M6UpgradeObservedArtifactIdentity:
    return M6UpgradeObservedArtifactIdentity(
        source=M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
        kind=kind,
        artifact_id=_sha(value),
        usage=M6UpgradeArtifactUsage.PRODUCED,
    )


def test_metadata_orchestrator_passes_one_exact_body_free_cut_to_graph(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace: list[str] = []
    controlled = object()
    binding = SimpleNamespace(case_revision=7)
    case = SimpleNamespace(case_id="case-1", evidence_packs=())
    audit = object()
    authority = SimpleNamespace(
        case=case,
        candidate_case_binding=binding,
        audit_entry=audit,
    )
    upstream = SimpleNamespace(plan_identity_sha256=_sha(900))
    observations = (
        _observation(M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST, 1),
        _observation(M6UpgradePhysicalArtifactKind.TOOL_RESULT, 2),
    )
    primary = object()
    hearing = object()
    transitions = object()
    outputs = object()
    closures = (object(),)
    planned = object()
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        metadata,
        "_validated_arguments",
        lambda *_args: (
            controlled,
            "run-1",
            _sha(99),
            upstream,
            authority,
            observations,
        ),
    )

    def primary_spy(connection: object, *, run_id: str, case_id: str) -> object:
        trace.append("primary")
        assert (connection, run_id, case_id) == (controlled, "run-1", "case-1")
        return primary

    def hearing_spy(connection: object, *, run_id: str, case_id: str) -> object:
        trace.append("hearing")
        assert (connection, run_id, case_id) == (controlled, "run-1", "case-1")
        return hearing

    def transition_spy(
        connection: object,
        *,
        run_id: str,
        case_id: str,
        selected_case_revision: int,
    ) -> object:
        trace.append("transition")
        assert (connection, run_id, case_id, selected_case_revision) == (
            controlled,
            "run-1",
            "case-1",
            7,
        )
        return transitions

    def output_spy(
        connection: object,
        *,
        run_id: str,
        case_id: str,
        selected_case_tool_results: object,
    ) -> object:
        trace.append("output")
        assert (connection, run_id, case_id) == (controlled, "run-1", "case-1")
        assert selected_case_tool_results == ()
        return outputs

    def graph_spy(connection: object, **kwargs: object) -> tuple[object, ...]:
        trace.append("graph")
        assert connection is controlled
        captured.update(kwargs)
        return closures

    def plan_spy(**kwargs: object) -> object:
        trace.append("plan")
        captured["plan_kwargs"] = kwargs
        return planned

    def active_spy(connection: object) -> None:
        trace.append("active")
        assert connection is controlled

    monkeypatch.setattr(metadata, "read_primary_rows", primary_spy)
    monkeypatch.setattr(metadata, "read_hearing_support_rows", hearing_spy)
    monkeypatch.setattr(metadata, "read_transition_support_rows", transition_spy)
    monkeypatch.setattr(metadata, "read_selected_tool_result_output_rows", output_spy)
    monkeypatch.setattr(metadata, "build_acquisition_closures", graph_spy)
    monkeypatch.setattr(metadata, "M6SQLiteAcquisitionDocumentsPlan", plan_spy)
    monkeypatch.setattr(metadata, "_active", active_spy)

    result = metadata.build_m6_sqlite_acquisition_documents_plan(
        connection=object(),
        expected_run_id=object(),
        expected_manifest_id=object(),
        upstream_m4_model_plan=object(),
        selected_case_authority=object(),
        observed_acquisition_artifacts=object(),
    )

    assert result is planned
    assert trace == ["primary", "hearing", "transition", "output", "graph", "plan", "active"]
    assert captured == {
        "run_id": "run-1",
        "case_id": "case-1",
        "manifest_id": _sha(99),
        "selected_case_authority": authority,
        "observed_acquisition_artifacts": observations,
        "upstream_m4_model_plan": upstream,
        "primary_rows": primary,
        "hearing_rows": hearing,
        "transition_rows": transitions,
        "output_rows": outputs,
        "plan_kwargs": {
            "run_id": "run-1",
            "case_id": "case-1",
            "manifest_id": _sha(99),
            "upstream_m4_model_plan_identity_sha256": _sha(900),
            "selected_case_binding": binding,
            "selected_case": case,
            "selected_case_revision": 7,
            "selected_case_audit": audit,
            "observed_artifacts": observations,
            "closures": closures,
        },
    }


def test_empty_acquisition_still_binds_the_upstream_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controlled = object()
    authority = SimpleNamespace(
        case=SimpleNamespace(case_id="case-1", evidence_packs=()),
        candidate_case_binding=SimpleNamespace(case_revision=1),
        audit_entry=object(),
    )
    upstream = SimpleNamespace(plan_identity_sha256=_sha(700))
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        metadata,
        "_validated_arguments",
        lambda *_args: (controlled, "run-1", _sha(5), upstream, authority, ()),
    )
    monkeypatch.setattr(metadata, "read_primary_rows", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        metadata,
        "read_hearing_support_rows",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        metadata,
        "read_transition_support_rows",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        metadata,
        "read_selected_tool_result_output_rows",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(metadata, "build_acquisition_closures", lambda *_args, **_kwargs: ())

    def plan_spy(**kwargs: object) -> object:
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(metadata, "M6SQLiteAcquisitionDocumentsPlan", plan_spy)
    monkeypatch.setattr(metadata, "_active", lambda _connection: None)

    metadata.build_m6_sqlite_acquisition_documents_plan(
        connection=object(),
        expected_run_id=object(),
        expected_manifest_id=object(),
        upstream_m4_model_plan=object(),
        selected_case_authority=object(),
        observed_acquisition_artifacts=object(),
    )
    assert captured["upstream_m4_model_plan_identity_sha256"] == _sha(700)
    assert captured["observed_artifacts"] == ()
    assert captured["closures"] == ()


def test_validation_rejects_invalid_arguments_before_any_read() -> None:
    with pytest.raises(_M6SQLiteAcquisitionMetadataFailure) as caught:
        metadata._validated_arguments(
            object(),
            "secret-run",
            _sha(1),
            object(),
            object(),
            (),
        )
    assert caught.value.reason_code == M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT


def test_validation_rejects_an_inconsistent_upstream_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Reader:
        in_transaction = True

    class _Authority:
        case = SimpleNamespace(run_id="run-1", manifest_id=_sha(1), case_id="case-1")
        candidate_case_binding = object()
        audit_entry = object()

    class _Upstream:
        pass

    monkeypatch.setattr(metadata, "M6LiveReader", _Reader)
    monkeypatch.setattr(metadata, "M6SQLiteCaseAuthorityDocument", _Authority)
    monkeypatch.setattr(metadata, "M6SQLiteM4ModelDocumentsPlan", _Upstream)
    monkeypatch.setattr(metadata, "_case_authority_is_consistent", lambda _value: True)
    monkeypatch.setattr(metadata, "_m4_plan_is_consistent", lambda _value: False)

    with pytest.raises(_M6SQLiteAcquisitionMetadataFailure) as caught:
        metadata._validated_arguments(
            _Reader(),
            "run-1",
            _sha(1),
            _Upstream(),
            _Authority(),
            (),
        )
    assert caught.value.reason_code == M6SQLiteAcquisitionPlanFailureCode.CASE_BINDING_MISMATCH


def test_observations_are_exact_stable_acquisition_produced_artifacts() -> None:
    manifest = _observation(M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST, 1)
    result = _observation(M6UpgradePhysicalArtifactKind.TOOL_RESULT, 2)
    stable = tuple(sorted((manifest, result), key=lambda item: item.sort_key))
    assert metadata._controlled_observations(stable) == stable

    with pytest.raises(_M6SQLiteAcquisitionMetadataFailure) as reversed_error:
        metadata._controlled_observations(tuple(reversed(stable)))
    assert reversed_error.value.reason_code == M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT

    foreign = M6UpgradeObservedArtifactIdentity(
        source=M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
        kind=M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
        artifact_id=_sha(3),
        usage=M6UpgradeArtifactUsage.PRODUCED,
    )
    with pytest.raises(_M6SQLiteAcquisitionMetadataFailure) as foreign_error:
        metadata._controlled_observations((foreign,))
    assert foreign_error.value.reason_code == M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT


def test_inactive_reader_is_a_typed_transaction_failure() -> None:
    reader = SimpleNamespace(in_transaction=False)
    with pytest.raises(_M6SQLiteAcquisitionMetadataFailure) as caught:
        metadata._active(cast(object, reader))  # type: ignore[arg-type]
    assert caught.value.reason_code == M6SQLiteAcquisitionPlanFailureCode.TRANSACTION_REQUIRED


def test_public_plan_forwards_success_arguments_and_returns_the_exact_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planned = cast(M6SQLiteAcquisitionDocumentsPlan, object())
    captured: dict[str, object] = {}

    def build_spy(**kwargs: object) -> M6SQLiteAcquisitionDocumentsPlan:
        captured.update(kwargs)
        return planned

    monkeypatch.setattr(subject, "build_m6_sqlite_acquisition_documents_plan", build_spy)
    arguments = {
        "connection": object(),
        "expected_run_id": "run-secret",
        "expected_manifest_id": "manifest-secret",
        "upstream_m4_model_plan": object(),
        "selected_case_authority": object(),
        "observed_acquisition_artifacts": object(),
    }
    result = subject.plan_m6_sqlite_acquisition_documents(**arguments)  # type: ignore[arg-type]
    assert result is planned
    assert captured == arguments


def test_public_plan_maps_private_reason_to_fresh_payload_free_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject(**_kwargs: object) -> object:
        raise _M6SQLiteAcquisitionMetadataFailure(
            M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH
        )

    monkeypatch.setattr(subject, "build_m6_sqlite_acquisition_documents_plan", reject)
    with pytest.raises(subject.M6SQLiteAcquisitionDocumentError) as caught:
        subject.plan_m6_sqlite_acquisition_documents(  # type: ignore[arg-type]
            connection=object(),
            expected_run_id="secret-run",
            expected_manifest_id="secret-manifest",
            upstream_m4_model_plan=object(),
            selected_case_authority=object(),
            observed_acquisition_artifacts=object(),
        )
    error = caught.value
    assert error.reason_code == M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH
    assert error.__cause__ is None
    assert error.__context__ is None
    assert "secret" not in str(error)


def test_unknown_exception_and_public_traceback_drop_all_authority_payloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "secret acquisition database path and canonical body"

    def explode(**_kwargs: object) -> object:
        raise RuntimeError(secret)

    monkeypatch.setattr(subject, "build_m6_sqlite_acquisition_documents_plan", explode)
    with pytest.raises(subject.M6SQLiteAcquisitionDocumentError) as caught:
        subject.plan_m6_sqlite_acquisition_documents(  # type: ignore[arg-type]
            connection=object(),
            expected_run_id=f"run-{secret}",
            expected_manifest_id=f"manifest-{secret}",
            upstream_m4_model_plan=object(),
            selected_case_authority=object(),
            observed_acquisition_artifacts=object(),
        )
    error = caught.value
    assert error.reason_code == M6SQLiteAcquisitionPlanFailureCode.DATABASE_REJECTED
    assert error.__cause__ is None
    assert error.__context__ is None
    rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
    assert secret not in rendered
    public_frames = []
    current = error.__traceback__
    while current is not None:
        if (
            current.tb_frame.f_globals.get("__name__") == subject.__name__
            and current.tb_frame.f_code.co_name == "plan_m6_sqlite_acquisition_documents"
        ):
            public_frames.append(current.tb_frame)
        current = current.tb_next
    assert len(public_frames) == 1
    forbidden = {
        "connection",
        "expected_run_id",
        "expected_manifest_id",
        "upstream_m4_model_plan",
        "selected_case_authority",
        "observed_acquisition_artifacts",
    }
    assert forbidden.isdisjoint(public_frames[0].f_locals)

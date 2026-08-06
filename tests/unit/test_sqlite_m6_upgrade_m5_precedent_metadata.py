from __future__ import annotations

import inspect
import traceback

import pytest

import labcourt.adapters.storage._sqlite_m6_upgrade_m5_precedent_metadata as subject
from labcourt.adapters.storage._sqlite_m6_upgrade_m5_precedent_plan import (
    M6SQLiteM5PrecedentDocumentsPlan,
    M6SQLiteM5PrecedentPlanFailureCode,
    _M6SQLiteM5PrecedentMetadataFailure,
)
from labcourt.contracts.canonical import sha256_hex


def _sha(label: str) -> str:
    return sha256_hex(["m6-m5-metadata-facade-test", label])


def _plan() -> M6SQLiteM5PrecedentDocumentsPlan:
    return M6SQLiteM5PrecedentDocumentsPlan(
        run_id="m6-m5-metadata-run",
        case_id="m6-m5-metadata-case",
        manifest_id=_sha("manifest"),
        upstream_m4_plan_identity_sha256=_sha("upstream"),
        upstream_retrieval_keys=(),
        observed_artifacts=(),
        hearings=(),
        cycles=(),
        retrievals=(),
        exposures=(),
        derived_query_embeddings=(),
        durable_embeddings=(),
        precedent_revisions=(),
    )


def _arguments() -> dict[str, object]:
    return {
        "connection": object(),
        "manifest": object(),
        "config": object(),
        "selected_case_authority": object(),
        "upstream_m4_model_plan": object(),
        "observed_precedent_artifacts": object(),
    }


def test_public_plan_facade_forwards_the_exact_six_authorities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _plan()
    captured: dict[str, object] = {}

    def fake_builder(**kwargs: object) -> M6SQLiteM5PrecedentDocumentsPlan:
        captured.update(kwargs)
        return expected

    monkeypatch.setattr(subject, "build_m6_sqlite_m5_precedent_documents_plan", fake_builder)
    arguments = _arguments()

    result = subject.plan_m6_sqlite_m5_precedent_documents(**arguments)  # type: ignore[arg-type]

    assert result == expected
    assert captured == arguments


@pytest.mark.parametrize(
    "reason_code",
    (
        M6SQLiteM5PrecedentPlanFailureCode.INVENTORY_MISMATCH,
        M6SQLiteM5PrecedentPlanFailureCode.BRIDGE_PIN_MISMATCH,
        M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_BUDGET_EXCEEDED,
    ),
)
def test_public_plan_facade_preserves_private_failure_codes_without_payload(
    monkeypatch: pytest.MonkeyPatch,
    reason_code: M6SQLiteM5PrecedentPlanFailureCode,
) -> None:
    def failed_builder(**_kwargs: object) -> M6SQLiteM5PrecedentDocumentsPlan:
        raise _M6SQLiteM5PrecedentMetadataFailure(reason_code)

    monkeypatch.setattr(subject, "build_m6_sqlite_m5_precedent_documents_plan", failed_builder)

    with pytest.raises(subject.M6SQLiteM5PrecedentDocumentError) as captured:
        subject.plan_m6_sqlite_m5_precedent_documents(  # type: ignore[arg-type]
            **_arguments()
        )

    assert captured.value.reason_code == reason_code
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_public_plan_facade_collapses_unexpected_failures_and_deletes_public_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "SECRET C:\\people\\alice-precedent.json"

    def failed_builder(**_kwargs: object) -> M6SQLiteM5PrecedentDocumentsPlan:
        raise RuntimeError(secret)

    monkeypatch.setattr(subject, "build_m6_sqlite_m5_precedent_documents_plan", failed_builder)

    with pytest.raises(subject.M6SQLiteM5PrecedentDocumentError) as captured:
        subject.plan_m6_sqlite_m5_precedent_documents(  # type: ignore[arg-type]
            **_arguments()
        )

    assert captured.value.reason_code == M6SQLiteM5PrecedentPlanFailureCode.DATABASE_REJECTED
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert secret not in "".join(traceback.format_exception(captured.value))
    public_frames = []
    current = captured.value.__traceback__
    while current is not None:
        if (
            current.tb_frame.f_globals.get("__name__") == subject.__name__
            and current.tb_frame.f_code.co_name == "plan_m6_sqlite_m5_precedent_documents"
        ):
            public_frames.append(current.tb_frame)
        current = current.tb_next
    assert len(public_frames) == 1
    assert set(_arguments()).isdisjoint(public_frames[0].f_locals)


def test_internal_builder_signature_is_frozen_for_same_reader_body_replanning() -> None:
    assert tuple(
        inspect.signature(subject.build_m6_sqlite_m5_precedent_documents_plan).parameters
    ) == (
        "connection",
        "manifest",
        "config",
        "selected_case_authority",
        "upstream_m4_model_plan",
        "observed_precedent_artifacts",
    )


def test_public_resolve_facade_forwards_the_exact_six_authorities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = object()
    captured: dict[str, object] = {}

    def fake_resolver(**kwargs: object) -> object:
        captured.update(kwargs)
        return expected

    monkeypatch.setattr(subject, "build_m6_sqlite_m5_precedent_authority_snapshot", fake_resolver)
    arguments = {
        "connection": object(),
        "metadata_plan": object(),
        "selected_case": object(),
        "config": object(),
        "manifest": object(),
        "upstream_m4_model_plan": object(),
    }

    result = subject.resolve_m6_sqlite_m5_precedent_documents(  # type: ignore[arg-type]
        **arguments
    )

    assert result is expected
    assert captured == arguments


def test_public_resolve_facade_translates_private_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reason = M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH

    def failed_resolver(**_kwargs: object) -> object:
        raise _M6SQLiteM5PrecedentMetadataFailure(reason)

    monkeypatch.setattr(subject, "build_m6_sqlite_m5_precedent_authority_snapshot", failed_resolver)

    with pytest.raises(subject.M6SQLiteM5PrecedentDocumentError) as captured:
        subject.resolve_m6_sqlite_m5_precedent_documents(  # type: ignore[arg-type]
            connection=object(),
            metadata_plan=object(),
            selected_case=object(),
            config=object(),
            manifest=object(),
            upstream_m4_model_plan=object(),
        )

    assert captured.value.reason_code == reason
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None

from __future__ import annotations

import json

import pytest
from pydantic import TypeAdapter, ValidationError

from labcourt.contracts.enums import ArtifactKind, CaseStatus
from labcourt.contracts.m3_operations import (
    MAX_FAKE_VLM_FIXTURE_RESPONSE_BYTES,
    FakeVLMFailureFixtureInput,
    FakeVLMFixtureBundle,
    FakeVLMFixtureDisposition,
    FakeVLMFixtureInput,
    FakeVLMResponseFixtureInput,
    M3ProcessCaseOutcome,
    M3ProcessCounts,
    M3ProcessDisposition,
    M3ProcessReport,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.schema_export import expected_schema_files


def _response_fixture(cache_key: str = "1" * 64) -> FakeVLMResponseFixtureInput:
    return FakeVLMResponseFixtureInput(
        disposition=FakeVLMFixtureDisposition.RESPONSE,
        cache_key=cache_key,
        raw_response_utf8='{"decision":"fixture-secret-body"}',
        input_tokens=3,
        output_tokens=5,
        latency_ms=7,
    )


def _bundle(*fixtures: FakeVLMFixtureInput) -> FakeVLMFixtureBundle:
    return FakeVLMFixtureBundle(
        schema_version="m3-fake-vlm-fixture-bundle-v1",
        fixtures=fixtures,
    )


def _processed_outcome() -> M3ProcessCaseOutcome:
    return M3ProcessCaseOutcome(
        event_id="event-a",
        case_id="case-a",
        initial_status=CaseStatus.EVIDENCE_READY,
        status=CaseStatus.READY_FOR_ALERT_POLICY,
        revision=4,
        disposition=M3ProcessDisposition.PROCESSED,
        pipeline_invoked=True,
        screening_result_ref=ArtifactRef(
            kind=ArtifactKind.SCREENING_RESULT,
            artifact_id="2" * 64,
        ),
        verdict_ref=ArtifactRef(kind=ArtifactKind.VERDICT, artifact_id="3" * 64),
        procedural_review_ref=ArtifactRef(
            kind=ArtifactKind.PROCEDURAL_REVIEW,
            artifact_id="4" * 64,
        ),
        backlog_item_ref=None,
        cache_hit_count=1,
        recovered_response_count=0,
        repair_attempt_count=1,
    )


def _report(outcome: M3ProcessCaseOutcome) -> M3ProcessReport:
    return M3ProcessReport(
        run_id="run-a",
        manifest_id="5" * 64,
        provider_profile="fake-screening",
        perception_mode="SIMULATED PERCEPTION",
        model_mode="FAKE VLM",
        fixture_bundle_id="6" * 64,
        fixture_entry_count=1,
        requested_case_id="case-a",
        selection_limit=1,
        available_case_count=1,
        selection_truncated=False,
        outcomes=(outcome,),
        counts=M3ProcessCounts(
            selected_cases=1,
            pipeline_invocations=1,
            processed_cases=1,
            deferred_to_backlog_cases=0,
            observed_existing_cases=0,
            skipped_not_ready_cases=0,
            cache_hits=1,
            recovered_responses=0,
            repair_attempts=1,
        ),
    )


def test_fake_fixture_union_requires_explicit_semantics() -> None:
    adapter = TypeAdapter(FakeVLMFixtureInput)
    with pytest.raises(ValidationError):
        adapter.validate_python(
            {
                "disposition": "RESPONSE",
                "cache_key": "1" * 64,
                "raw_response_utf8": "{}",
            }
        )
    with pytest.raises(ValidationError):
        adapter.validate_python(
            {
                "disposition": "OUTAGE",
                "cache_key": "1" * 64,
                "raw_response_utf8": "hidden fallback",
            }
        )

    outage = adapter.validate_python({"disposition": "OUTAGE", "cache_key": "1" * 64})
    timeout = adapter.validate_python({"disposition": "TIMEOUT", "cache_key": "2" * 64})
    assert isinstance(outage, FakeVLMFailureFixtureInput)
    assert outage.disposition == FakeVLMFixtureDisposition.OUTAGE
    assert isinstance(timeout, FakeVLMFailureFixtureInput)
    assert timeout.disposition == FakeVLMFixtureDisposition.TIMEOUT


def test_fake_fixture_bundle_is_unique_stable_bounded_and_repr_safe() -> None:
    response = _response_fixture()
    bundle = _bundle(response)

    assert bundle.fixture_count == 1
    assert bundle.raw_response_total_bytes == len(response.raw_response_utf8.encode("utf-8"))
    assert response.raw_response_utf8 not in repr(response)
    assert response.raw_response_utf8 not in repr(bundle)
    assert bundle.fixture_bundle_id in repr(bundle)
    assert FakeVLMFixtureBundle.model_validate_json(bundle.model_dump_json()) == bundle

    serialized = bundle.model_dump(mode="python")
    for name in (
        "fixture_bundle_id",
        "fixture_count",
        "raw_response_total_bytes",
    ):
        forged = dict(serialized)
        forged[name] = "0" * 64 if name == "fixture_bundle_id" else 999
        with pytest.raises(ValidationError, match=name):
            FakeVLMFixtureBundle.model_validate(forged)

    with pytest.raises(ValidationError, match="unique"):
        _bundle(response, response)
    with pytest.raises(ValidationError, match="stable"):
        _bundle(_response_fixture("2" * 64), _response_fixture("1" * 64))
    with pytest.raises(ValidationError, match="per-entry"):
        FakeVLMResponseFixtureInput(
            disposition=FakeVLMFixtureDisposition.RESPONSE,
            cache_key="1" * 64,
            raw_response_utf8="界" * 100_000,
            input_tokens=0,
            output_tokens=0,
            latency_ms=0,
        )
    with pytest.raises(ValidationError, match="valid UTF-8"):
        FakeVLMResponseFixtureInput(
            disposition=FakeVLMFixtureDisposition.RESPONSE,
            cache_key="1" * 64,
            raw_response_utf8="\ud800",
            input_tokens=0,
            output_tokens=0,
            latency_ms=0,
        )
    with pytest.raises(ValidationError, match="authored as a UTF-8 string"):
        FakeVLMResponseFixtureInput.model_validate(
            {
                "disposition": FakeVLMFixtureDisposition.RESPONSE,
                "cache_key": "1" * 64,
                "raw_response_utf8": b"{}",
                "input_tokens": 0,
                "output_tokens": 0,
                "latency_ms": 0,
            }
        )


def test_fake_fixture_bundle_enforces_entry_and_total_byte_caps() -> None:
    failures = tuple(
        FakeVLMFailureFixtureInput(
            disposition=FakeVLMFixtureDisposition.OUTAGE,
            cache_key=f"{index:064x}",
        )
        for index in range(1_001)
    )
    with pytest.raises(ValidationError, match="at most 1000"):
        _bundle(*failures)

    raw = "x" * MAX_FAKE_VLM_FIXTURE_RESPONSE_BYTES
    responses = tuple(
        FakeVLMResponseFixtureInput(
            disposition=FakeVLMFixtureDisposition.RESPONSE,
            cache_key=f"{index:064x}",
            raw_response_utf8=raw,
            input_tokens=0,
            output_tokens=0,
            latency_ms=0,
        )
        for index in range(65)
    )
    with pytest.raises(ValidationError, match="total UTF-8 byte limit"):
        _bundle(*responses)


def test_process_report_has_strict_modes_refs_counts_and_no_raw_fixture() -> None:
    report = _report(_processed_outcome())
    serialized = report.model_dump_json()

    assert report.perception_mode == "SIMULATED PERCEPTION"
    assert report.model_mode == "FAKE VLM"
    assert "fixture-secret-body" not in serialized
    assert M3ProcessReport.model_validate_json(serialized) == report
    payload = json.loads(serialized)
    assert payload["counts"]["cache_hits"] == 1
    assert payload["outcomes"][0]["procedural_review_ref"]["kind"] == (
        ArtifactKind.PROCEDURAL_REVIEW.value
    )


def test_process_report_rejects_false_success_and_inconsistent_counts() -> None:
    candidate_payload = _processed_outcome().model_dump(mode="python")
    candidate_payload.update(
        {
            "initial_status": CaseStatus.CANDIDATE,
            "status": CaseStatus.CANDIDATE,
            "disposition": M3ProcessDisposition.PROCESSED,
            "pipeline_invoked": False,
            "screening_result_ref": None,
            "verdict_ref": None,
            "procedural_review_ref": None,
            "cache_hit_count": 0,
            "repair_attempt_count": 0,
        }
    )
    with pytest.raises(ValidationError):
        M3ProcessCaseOutcome.model_validate(candidate_payload)

    report_payload = _report(_processed_outcome()).model_dump(mode="python")
    report_payload["counts"] = M3ProcessCounts(
        selected_cases=1,
        pipeline_invocations=0,
        processed_cases=0,
        deferred_to_backlog_cases=0,
        observed_existing_cases=1,
        skipped_not_ready_cases=0,
        cache_hits=0,
        recovered_responses=0,
        repair_attempts=0,
    )
    with pytest.raises(ValidationError, match="counts conflict"):
        M3ProcessReport.model_validate(report_payload)


def test_process_outcome_rejects_forged_status_without_required_result_refs() -> None:
    escalated = _processed_outcome().model_dump(mode="python")
    escalated.update(
        {
            "status": CaseStatus.ESCALATED,
            "screening_result_ref": None,
            "verdict_ref": None,
            "procedural_review_ref": None,
        }
    )
    with pytest.raises(ValidationError, match="ESCALATED outcome"):
        M3ProcessCaseOutcome.model_validate(escalated)

    reviewed = _processed_outcome().model_dump(mode="python")
    reviewed["procedural_review_ref"] = None
    with pytest.raises(ValidationError, match="screening, verdict, and review refs"):
        M3ProcessCaseOutcome.model_validate(reviewed)

    observed = _processed_outcome().model_dump(mode="python")
    observed.update(
        {
            "initial_status": CaseStatus.READY_FOR_ALERT_POLICY,
            "disposition": M3ProcessDisposition.OBSERVED_EXISTING,
            "pipeline_invoked": False,
            "screening_result_ref": None,
            "verdict_ref": None,
            "procedural_review_ref": None,
            "cache_hit_count": 0,
            "repair_attempt_count": 0,
        }
    )
    with pytest.raises(ValidationError, match="screening, verdict, and review refs"):
        M3ProcessCaseOutcome.model_validate(observed)


def test_backlog_disposition_requires_typed_current_item_reference() -> None:
    payload = _processed_outcome().model_dump(mode="python")
    payload.update(
        {
            "status": CaseStatus.BACKLOGGED,
            "disposition": M3ProcessDisposition.DEFERRED_TO_BACKLOG,
            "screening_result_ref": None,
            "verdict_ref": None,
            "procedural_review_ref": None,
            "backlog_item_ref": None,
            "cache_hit_count": 0,
            "repair_attempt_count": 0,
        }
    )
    with pytest.raises(ValidationError, match="current item reference"):
        M3ProcessCaseOutcome.model_validate(payload)

    payload["backlog_item_ref"] = ArtifactRef(
        kind=ArtifactKind.BACKLOG_ITEM,
        artifact_id="7" * 64,
    )
    outcome = M3ProcessCaseOutcome.model_validate(payload)
    assert outcome.disposition == M3ProcessDisposition.DEFERRED_TO_BACKLOG


def test_public_schemas_expose_fixture_bounds_and_simulation_markers() -> None:
    schemas = expected_schema_files()
    fixture = json.loads(schemas["fake-vlm-fixture-bundle.schema.json"])
    response = fixture["$defs"]["FakeVLMResponseFixtureInput"]
    report = json.loads(schemas["m3-process-report.schema.json"])

    assert fixture["properties"]["fixtures"]["maxItems"] == 1_000
    assert response["properties"]["raw_response_utf8"]["maxLength"] == (
        MAX_FAKE_VLM_FIXTURE_RESPONSE_BYTES
    )
    assert set(response["required"]) == {
        "disposition",
        "cache_key",
        "raw_response_utf8",
        "input_tokens",
        "output_tokens",
        "latency_ms",
    }
    assert report["properties"]["perception_mode"]["const"] == "SIMULATED PERCEPTION"
    assert report["properties"]["model_mode"]["const"] == "FAKE VLM"
    assert "raw_response_utf8" not in schemas["m3-process-report.schema.json"]

from __future__ import annotations

from copy import deepcopy

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.enums import (
    CaseStatus,
    ExecutionLocation,
    ProviderTransport,
    ScreeningDecision,
    VlmRole,
)
from labcourt.contracts.m8_hearing_api import (
    M8HearingEligibility,
    M8HearingL5Status,
    M8HearingModelMode,
    M8HearingProviderSelectionV1,
    M8HearingStartRequestV1,
    M8HearingViewV1,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def _start_request(
    mode: M8HearingModelMode = M8HearingModelMode.OFFLINE_FIXTURE,
) -> M8HearingStartRequestV1:
    return M8HearingStartRequestV1(
        run_id="run-m8-hearing",
        case_id="case-m8-hearing",
        source_status=CaseStatus.ESCALATED,
        source_screening_id=SHA_A,
        source_evidence_pack_id=SHA_B,
        source_evidence_pack_version=1,
        model_mode=mode,
        explicit_start=True,
        request_manifest_id=SHA_C,
    )


def _fake_selections() -> tuple[M8HearingProviderSelectionV1, ...]:
    return tuple(
        M8HearingProviderSelectionV1(
            role=role,
            provider_profile=f"fake-{role.value.lower()}",
            provider="fake",
            model=f"deterministic-{role.value.lower()}",
            revision="1.0.0",
            model_manifest_id=character * 64,
            execution_location=ExecutionLocation.LOCAL,
            transport=ProviderTransport.IN_PROCESS,
        )
        for role, character in (
            (VlmRole.PROSECUTOR, "1"),
            (VlmRole.DEFENDER, "2"),
            (VlmRole.JUDGE, "3"),
        )
    )


def _eligible_view() -> M8HearingViewV1:
    return M8HearingViewV1(
        run_id="run-m8-hearing",
        case_id="case-m8-hearing",
        case_location_id="room-chem-301",
        model_mode=M8HearingModelMode.OFFLINE_FIXTURE,
        provider_selections=_fake_selections(),
        case_revision=4,
        case_status=CaseStatus.ESCALATED,
        eligibility=M8HearingEligibility.ELIGIBLE_ESCALATED,
        request_manifest_id=SHA_C,
        screening_id=SHA_A,
        screening_decision=ScreeningDecision.ESCALATE,
        screening_conflict_flags=("MODEL_SENSOR_CONFLICT",),
        current_evidence_pack_id=SHA_B,
        current_evidence_pack_version=1,
        l5_status=M8HearingL5Status.NOT_RUN,
    )


def test_start_request_is_explicit_fenced_and_cannot_force_clear_case() -> None:
    request = _start_request()
    payload = request.model_dump(mode="json")
    assert request.model_mode == M8HearingModelMode.OFFLINE_FIXTURE
    assert request.client_actor_authority_permitted is False
    assert request.automatic_start_permitted is False
    assert request.clear_case_forcing_permitted is False
    assert len(request.start_request_id) == 64

    payload.pop("start_request_id")
    payload["source_status"] = "READY_FOR_ALERT_POLICY"
    with pytest.raises(ValidationError, match="ESCALATED or REWORK_REQUIRED"):
        M8HearingStartRequestV1.model_validate(payload)
    forged = request.model_dump(mode="json")
    forged["actor_authority"] = {"role": "SAFETY_OFFICER"}
    with pytest.raises(ValidationError, match="Extra inputs"):
        M8HearingStartRequestV1.model_validate(forged)


def test_view_is_additive_read_only_and_rejects_silent_real_model_fallback() -> None:
    view = _eligible_view()
    assert view.raw_model_response_content_exposed is False
    assert view.case_transition_permitted is False
    assert view.request_manifest_id == SHA_C
    assert view.hearing_session_id is None
    assert len(view.view_id) == 64

    payload = view.model_dump(mode="json")
    payload.pop("view_id")
    payload.pop("hearing_session_id")
    payload["model_mode"] = "OPENAI_COMPATIBLE_QWEN"
    with pytest.raises(ValidationError, match="OpenAI-compatible Qwen"):
        M8HearingViewV1.model_validate(payload)


def test_view_requires_exact_role_order_independent_profiles_and_consistent_eligibility() -> None:
    view = _eligible_view()
    reversed_roles = tuple(reversed(view.provider_selections))
    with pytest.raises(ValidationError, match="prosecutor/defender/judge order"):
        view.model_copy(update={"provider_selections": reversed_roles})

    aliased = list(view.provider_selections)
    aliased[1] = aliased[1].model_copy(update={"provider_profile": aliased[0].provider_profile})
    with pytest.raises(ValidationError, match="independent profiles"):
        view.model_copy(update={"provider_selections": tuple(aliased)})

    with pytest.raises(ValidationError, match="eligible escalated"):
        view.model_copy(update={"screening_decision": ScreeningDecision.ESTABLISHED})


@pytest.mark.parametrize("model", (_start_request(), _eligible_view()))
def test_m8_hearing_contracts_validate_as_serialization_schema(model: object) -> None:
    schema = type(model).model_json_schema(mode="serialization")  # type: ignore[attr-defined]
    Draft202012Validator(schema).validate(model.model_dump(mode="json"))  # type: ignore[attr-defined]


def test_computed_claims_and_unknown_fields_fail_closed() -> None:
    view = _eligible_view()
    forged = deepcopy(view.model_dump(mode="json"))
    forged["view_id"] = "0" * 64
    with pytest.raises(ValidationError, match="view_id"):
        M8HearingViewV1.model_validate(forged)

    request = _start_request()
    forged_request = request.model_dump(mode="json")
    forged_request["start_request_id"] = "0" * 64
    with pytest.raises(ValidationError, match="start_request_id"):
        M8HearingStartRequestV1.model_validate(forged_request)

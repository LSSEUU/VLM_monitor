from __future__ import annotations

from datetime import UTC, datetime

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import M8OperationalRiskLevel
from labcourt.contracts.m8_operations import (
    M8OperationalSource,
    M8OperationalSourceMode,
    M8SensorType,
)
from labcourt.contracts.m8_sensor_signals import (
    M8SensorAdapterCapabilityAuthorityV1,
    M8SensorAssessmentReasonCode,
    M8SensorPollRequestV1,
    M8SensorPollResultV1,
    M8SensorQuality,
    M8SensorRiskAssessmentV1,
    M8SensorRiskOperator,
    M8SensorRiskPolicyAuthorityV1,
    M8SensorRiskPolicyPurpose,
    M8SensorRiskRule,
    M8SensorSample,
    M8SensorUnit,
    M8SimulatedSensorReading,
    M8SimulatedSensorScenarioAuthorityV1,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _source(
    sensor_type: M8SensorType = M8SensorType.SMOKE,
    *,
    mode: M8OperationalSourceMode = M8OperationalSourceMode.SIMULATED_SENSOR,
) -> M8OperationalSource:
    suffix = sensor_type.value.lower().replace("_", "-")
    return M8OperationalSource(
        source_id=f"sensor-{suffix}",
        device_id=f"device-{suffix}",
        location_id="room-chem-301",
        mode=mode,
        sensor_type=sensor_type,
        adapter_id="m8-sensor-adapter",
        manifest_id=SHA_A,
    )


def _capability() -> M8SensorAdapterCapabilityAuthorityV1:
    return M8SensorAdapterCapabilityAuthorityV1(
        adapter_id="m8-sensor-adapter",
        adapter_manifest_id=SHA_A,
        supported_source_modes=(M8OperationalSourceMode.SIMULATED_SENSOR,),
        supported_sensor_types=tuple(sorted(M8SensorType, key=lambda item: item.value)),
        offline_capable=True,
        network_required=False,
        deterministic_replay=True,
        raw_reference_required=True,
        max_batch_size=32,
        poll_timeout_ms=1_000,
    )


def _sample(
    sensor_type: M8SensorType = M8SensorType.SMOKE,
    *,
    value: bool | int = True,
    quality: M8SensorQuality = M8SensorQuality.GOOD,
    mode: M8OperationalSourceMode = M8OperationalSourceMode.SIMULATED_SENSOR,
) -> M8SensorSample:
    live = mode == M8OperationalSourceMode.LIVE_SENSOR
    return M8SensorSample(
        source_catalog_id=SHA_B,
        source=_source(sensor_type, mode=mode),
        source_sequence=7,
        observed_at_utc=datetime(2026, 8, 10, 10, 0, tzinfo=UTC) if live else None,
        simulation_tick=None if live else 42,
        value=value,
        quality=quality,
        raw_signal_ref=f"m8/raw/{sensor_type.value.lower()}/7.json",
        raw_signal_sha256=SHA_C,
        adapter_input_authority_id=SHA_D,
        adapter_manifest_id=SHA_A,
    )


def _request() -> M8SensorPollRequestV1:
    return M8SensorPollRequestV1(
        source_catalog_id=SHA_B,
        source=_source(),
        adapter_capability=_capability(),
        after_source_sequence=None,
        limit=2,
        timeout_ms=500,
    )


def _smoke_policy() -> M8SensorRiskPolicyAuthorityV1:
    return M8SensorRiskPolicyAuthorityV1(
        policy_id="offline-smoke-demo-policy",
        revision=1,
        purpose=M8SensorRiskPolicyPurpose.DEMONSTRATION,
        rules=(
            M8SensorRiskRule(
                rule_id="simulated-smoke-active-emergency",
                sensor_type=M8SensorType.SMOKE,
                priority=0,
                operator=M8SensorRiskOperator.BOOLEAN_EQUALS,
                boolean_threshold=True,
                risk_level=M8OperationalRiskLevel.EMERGENCY,
                create_pending_case=True,
                response_deadline_seconds=60,
            ),
        ),
        policy_manifest_id=SHA_D,
    )


@pytest.mark.parametrize(
    ("sensor_type", "value", "unit"),
    (
        (M8SensorType.SMOKE, True, M8SensorUnit.BOOLEAN),
        (M8SensorType.TEMPERATURE, 37_500, M8SensorUnit.MILLI_CELSIUS),
        (M8SensorType.COMBUSTIBLE_GAS, 10_000, M8SensorUnit.MILLI_PERCENT_LFL),
        (M8SensorType.TOXIC_GAS, 25_000, M8SensorUnit.MILLI_PPM),
        (M8SensorType.DOOR_CONTACT, True, M8SensorUnit.BOOLEAN),
        (M8SensorType.WATER_LEAK, False, M8SensorUnit.BOOLEAN),
        (M8SensorType.EMERGENCY_BUTTON, True, M8SensorUnit.BOOLEAN),
    ),
)
def test_sensor_sample_uses_closed_type_unit_and_simulation_truth_matrix(
    sensor_type: M8SensorType,
    value: bool | int,
    unit: M8SensorUnit,
) -> None:
    sample = _sample(sensor_type, value=value)

    assert sample.sensor_type == sensor_type
    assert sample.unit == unit
    assert sample.simulated is True
    assert sample.display_badge == "SIMULATED · SENSOR"
    assert sample.observed_at_utc is None
    assert sample.simulation_tick == 42
    assert len(sample.sample_integrity_sha256) == 64
    assert len(sample.sample_id) == 64
    Draft202012Validator(M8SensorSample.model_json_schema(mode="serialization")).validate(
        sample.model_dump(mode="json")
    )


def test_live_sensor_sample_requires_utc_and_never_accepts_simulation_tick() -> None:
    sample = _sample(
        M8SensorType.TEMPERATURE,
        value=32_000,
        mode=M8OperationalSourceMode.LIVE_SENSOR,
    )

    assert sample.simulated is False
    assert sample.display_badge == "LIVE · SENSOR"
    assert sample.observed_at_utc == datetime(2026, 8, 10, 10, 0, tzinfo=UTC)
    assert sample.simulation_tick is None

    with pytest.raises(ValidationError, match="simulation_tick"):
        sample.model_copy(update={"simulation_tick": 1})
    with pytest.raises(ValidationError, match="UTC"):
        sample.model_copy(update={"observed_at_utc": datetime(2026, 8, 10, 10, 0)})


@pytest.mark.parametrize(
    ("sensor_type", "value"),
    (
        (M8SensorType.SMOKE, 1),
        (M8SensorType.DOOR_CONTACT, 0),
        (M8SensorType.TEMPERATURE, True),
        (M8SensorType.COMBUSTIBLE_GAS, -1),
        (M8SensorType.TOXIC_GAS, False),
    ),
)
def test_sensor_sample_rejects_wrong_scalar_type_or_range(
    sensor_type: M8SensorType,
    value: bool | int,
) -> None:
    with pytest.raises(ValidationError, match=r"strict|non-negative"):
        _sample(sensor_type, value=value)


def test_sensor_sample_rejects_manifest_time_raw_ref_and_computed_grafts() -> None:
    sample = _sample()

    with pytest.raises(ValidationError, match="manifest"):
        sample.model_copy(update={"adapter_manifest_id": SHA_B})
    with pytest.raises(ValidationError, match="simulation_tick"):
        sample.model_copy(update={"simulation_tick": None})
    with pytest.raises(ValidationError, match="relative POSIX"):
        sample.model_copy(update={"raw_signal_ref": "../outside.json"})

    forged = sample.model_dump(mode="json")
    forged["sensor_type"] = M8SensorType.TEMPERATURE.value
    with pytest.raises(ValidationError, match="sensor_type"):
        M8SensorSample.model_validate(forged)


def test_adapter_capability_and_poll_request_pin_bounds_manifest_and_cache_identity() -> None:
    request = _request()

    assert request.source.adapter_id == request.adapter_capability.adapter_id
    assert request.source.manifest_id == request.adapter_capability.adapter_manifest_id
    assert len(request.request_id) == 64
    assert len(request.cache_key) == 64

    with pytest.raises(ValidationError, match="limit"):
        request.model_copy(update={"limit": 33})
    with pytest.raises(ValidationError, match="timeout"):
        request.model_copy(update={"timeout_ms": 1_001})
    with pytest.raises(ValidationError, match="manifest"):
        request.model_copy(
            update={"source": request.source.model_copy(update={"manifest_id": SHA_C})}
        )


def test_poll_result_binds_exact_request_source_sequence_and_sample_inventory() -> None:
    request = _request()
    first = _sample(value=False).model_copy(update={"source_sequence": 0, "simulation_tick": 0})
    second = _sample(value=True).model_copy(update={"source_sequence": 1, "simulation_tick": 1})
    result = M8SensorPollResultV1(
        request=request,
        samples=(first, second),
        exhausted=True,
    )

    assert result.sample_count == 2
    assert result.first_source_sequence == 0
    assert result.last_source_sequence == 1
    assert len(result.sample_inventory_sha256) == 64
    assert len(result.result_id) == 64

    with pytest.raises(ValidationError, match="stable"):
        result.model_copy(update={"samples": (second, first)})
    with pytest.raises(ValidationError, match="another source"):
        result.model_copy(
            update={
                "samples": (
                    first.model_copy(update={"source": _source(M8SensorType.DOOR_CONTACT)}),
                )
            }
        )


def test_simulated_scenario_is_ordered_typed_and_content_addressed() -> None:
    scenario = M8SimulatedSensorScenarioAuthorityV1(
        scenario_id="smoke-demo",
        source_catalog_id=SHA_B,
        source=_source(),
        readings=(
            M8SimulatedSensorReading(source_sequence=0, simulation_tick=0, value=False),
            M8SimulatedSensorReading(source_sequence=1, simulation_tick=5, value=True),
        ),
        fixture_manifest_id=SHA_D,
    )

    assert len(scenario.reading_inventory_sha256) == 64
    assert len(scenario.scenario_authority_id) == 64

    with pytest.raises(ValidationError, match="stable"):
        scenario.model_copy(update={"readings": tuple(reversed(scenario.readings))})
    with pytest.raises(ValidationError, match="strict boolean"):
        scenario.model_copy(
            update={
                "readings": (
                    M8SimulatedSensorReading(
                        source_sequence=0,
                        simulation_tick=0,
                        value=1,
                    ),
                )
            }
        )


def test_smoke_risk_assessment_is_emergency_candidate_without_automated_authority() -> None:
    assessment = M8SensorRiskAssessmentV1(
        sample=_sample(value=True),
        policy=_smoke_policy(),
        evaluator_manifest_id=SHA_C,
    )

    assert assessment.matched_rule_id == "simulated-smoke-active-emergency"
    assert assessment.assessment_reason_code == M8SensorAssessmentReasonCode.MATCHED_RULE
    assert assessment.risk_level == M8OperationalRiskLevel.EMERGENCY
    assert assessment.create_pending_case_recommended is True
    assert assessment.response_deadline_seconds == 60
    assert assessment.human_verification_required is True
    assert assessment.direct_disciplinary_action_permitted is False
    assert assessment.life_safety_action_permitted is False
    assert assessment.certified_fire_detection_claim_permitted is False
    assert assessment.display_badge == (
        "SIMULATED · EMERGENCY CANDIDATE · NOT CERTIFIED FIRE DETECTION"
    )

    schema = M8SensorRiskAssessmentV1.model_json_schema(mode="serialization")
    Draft202012Validator(schema).validate(assessment.model_dump(mode="json"))
    forged = assessment.model_dump(mode="json")
    forged["life_safety_action_permitted"] = True
    with pytest.raises(ValidationError, match="life_safety_action_permitted"):
        M8SensorRiskAssessmentV1.model_validate(forged)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(forged)


def test_inactive_or_bad_quality_smoke_is_reminder_without_case_creation() -> None:
    inactive = M8SensorRiskAssessmentV1(
        sample=_sample(value=False),
        policy=_smoke_policy(),
        evaluator_manifest_id=SHA_C,
    )
    degraded = M8SensorRiskAssessmentV1(
        sample=_sample(value=True, quality=M8SensorQuality.DEGRADED),
        policy=_smoke_policy(),
        evaluator_manifest_id=SHA_C,
    )

    assert inactive.assessment_reason_code == M8SensorAssessmentReasonCode.NO_MATCHING_RULE
    assert degraded.assessment_reason_code == (M8SensorAssessmentReasonCode.SAMPLE_QUALITY_NOT_GOOD)
    for assessment in (inactive, degraded):
        assert assessment.risk_level == M8OperationalRiskLevel.REMINDER
        assert assessment.create_pending_case_recommended is False
        assert assessment.response_deadline_seconds is None


def test_risk_policy_rejects_free_form_or_ambiguous_threshold_semantics() -> None:
    smoke_rule = _smoke_policy().rules[0]

    with pytest.raises(ValidationError, match="operator"):
        smoke_rule.model_copy(update={"operator": M8SensorRiskOperator.INTEGER_GTE})
    with pytest.raises(ValidationError, match="only boolean_threshold"):
        smoke_rule.model_copy(update={"integer_threshold": 1})
    with pytest.raises(ValidationError, match="REMINDER"):
        smoke_rule.model_copy(update={"risk_level": M8OperationalRiskLevel.REMINDER})


def test_m8_sensor_schemas_are_registered_serialization_roots() -> None:
    from labcourt.schema_registry import SCHEMA_MODELS, SCHEMA_VALIDATION_MODELS

    expected = {
        "m8-sensor-adapter-capability-authority-v1": (M8SensorAdapterCapabilityAuthorityV1),
        "m8-sensor-poll-request-v1": M8SensorPollRequestV1,
        "m8-sensor-poll-result-v1": M8SensorPollResultV1,
        "m8-sensor-risk-assessment-v1": M8SensorRiskAssessmentV1,
        "m8-sensor-risk-policy-authority-v1": M8SensorRiskPolicyAuthorityV1,
        "m8-sensor-sample": M8SensorSample,
        "m8-simulated-sensor-scenario-authority-v1": (M8SimulatedSensorScenarioAuthorityV1),
    }
    assert {name: SCHEMA_MODELS[name] for name in expected} == expected
    assert expected.keys().isdisjoint(SCHEMA_VALIDATION_MODELS)
    for model in expected.values():
        assert model.model_json_schema(mode="serialization")["additionalProperties"] is False

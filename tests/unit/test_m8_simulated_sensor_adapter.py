from __future__ import annotations

import hashlib
import json

import pytest

from labcourt.adapters.simulated_sensors import DeterministicSimulatedSensorAdapter
from labcourt.application.m8_sensor_demo import build_offline_smoke_demo_bundle
from labcourt.contracts.m8_access_cases import M8OperationalRiskLevel
from labcourt.contracts.m8_operations import (
    M8OperationalSource,
    M8OperationalSourceMode,
    M8SensorType,
)
from labcourt.contracts.m8_sensor_signals import (
    M8SensorAdapterCapabilityAuthorityV1,
    M8SensorPollRequestV1,
    M8SensorRiskAssessmentV1,
    M8SimulatedSensorReading,
    M8SimulatedSensorScenarioAuthorityV1,
)
from labcourt.ports.m8_sensors import (
    M8SensorAdapterError,
    M8SensorAdapterFailureCode,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def _source(sensor_type: M8SensorType = M8SensorType.SMOKE) -> M8OperationalSource:
    suffix = sensor_type.value.lower().replace("_", "-")
    return M8OperationalSource(
        source_id=f"sensor-{suffix}",
        device_id=f"device-{suffix}",
        location_id="room-chem-301",
        mode=M8OperationalSourceMode.SIMULATED_SENSOR,
        sensor_type=sensor_type,
        adapter_id="m8-offline-sensor-simulator",
        manifest_id=SHA_A,
    )


def _capability(
    supported_sensor_types: tuple[M8SensorType, ...] | None = None,
) -> M8SensorAdapterCapabilityAuthorityV1:
    return M8SensorAdapterCapabilityAuthorityV1(
        adapter_id="m8-offline-sensor-simulator",
        adapter_manifest_id=SHA_A,
        supported_source_modes=(M8OperationalSourceMode.SIMULATED_SENSOR,),
        supported_sensor_types=supported_sensor_types
        or tuple(sorted(M8SensorType, key=lambda item: item.value)),
        offline_capable=True,
        network_required=False,
        deterministic_replay=True,
        raw_reference_required=True,
        max_batch_size=16,
        poll_timeout_ms=1_000,
    )


def _scenario(
    sensor_type: M8SensorType = M8SensorType.SMOKE,
    *,
    values: tuple[bool | int, ...] = (False, True),
) -> M8SimulatedSensorScenarioAuthorityV1:
    return M8SimulatedSensorScenarioAuthorityV1(
        scenario_id=f"offline-{sensor_type.value.lower().replace('_', '-')}",
        source_catalog_id=SHA_B,
        source=_source(sensor_type),
        readings=tuple(
            M8SimulatedSensorReading(
                source_sequence=index,
                simulation_tick=index * 5,
                value=value,
            )
            for index, value in enumerate(values)
        ),
        fixture_manifest_id=SHA_C,
    )


def _request(
    scenario: M8SimulatedSensorScenarioAuthorityV1,
    capability: M8SensorAdapterCapabilityAuthorityV1,
    *,
    after_source_sequence: int | None = None,
    limit: int = 1,
) -> M8SensorPollRequestV1:
    return M8SensorPollRequestV1(
        source_catalog_id=scenario.source_catalog_id,
        source=scenario.source,
        adapter_capability=capability,
        after_source_sequence=after_source_sequence,
        limit=limit,
        timeout_ms=500,
    )


def test_offline_adapter_paginates_caches_and_replays_exact_results() -> None:
    scenario = _scenario()
    capability = _capability()
    adapter = DeterministicSimulatedSensorAdapter(scenario, capability)

    first_request = _request(scenario, capability)
    first = adapter.poll(first_request)
    assert first.first_source_sequence == 0
    assert first.exhausted is False
    assert adapter.generation_count == 1

    assert adapter.poll(first_request) is first
    assert adapter.replay(first_request.request_id) is first
    assert adapter.generation_count == 1

    second_request = _request(scenario, capability, after_source_sequence=0)
    second = adapter.poll(second_request)
    assert second.first_source_sequence == 1
    assert second.exhausted is True
    assert adapter.generation_count == 2


def test_raw_signal_bytes_match_sample_hash_and_preserve_simulation_disclosure() -> None:
    scenario = _scenario()
    capability = _capability()
    adapter = DeterministicSimulatedSensorAdapter(scenario, capability)
    sample = adapter.poll(_request(scenario, capability)).samples[0]

    raw_bytes = adapter.read_raw_signal(sample.raw_signal_ref)
    payload = json.loads(raw_bytes)
    assert hashlib.sha256(raw_bytes).hexdigest() == sample.raw_signal_sha256
    assert payload["simulated"] is True
    assert payload["certified_fire_detection_claim"] is False
    assert payload["scenario_authority_id"] == scenario.scenario_authority_id
    assert "\\" not in sample.raw_signal_ref
    assert ":" not in sample.raw_signal_ref


@pytest.mark.parametrize(
    ("sensor_type", "value"),
    (
        (M8SensorType.SMOKE, True),
        (M8SensorType.TEMPERATURE, 38_000),
        (M8SensorType.COMBUSTIBLE_GAS, 10_000),
        (M8SensorType.TOXIC_GAS, 5_000),
        (M8SensorType.DOOR_CONTACT, True),
        (M8SensorType.WATER_LEAK, True),
        (M8SensorType.EMERGENCY_BUTTON, True),
    ),
)
def test_default_adapter_accepts_each_closed_sensor_type(
    sensor_type: M8SensorType,
    value: bool | int,
) -> None:
    scenario = _scenario(sensor_type, values=(value,))
    capability = _capability()
    adapter = DeterministicSimulatedSensorAdapter(scenario, capability)

    result = adapter.poll(_request(scenario, capability))
    assert result.samples[0].sensor_type == sensor_type
    assert result.samples[0].value == value
    assert result.samples[0].simulated is True


def test_adapter_fails_with_typed_codes_for_capability_source_and_missing_replay() -> None:
    scenario = _scenario()
    capability = _capability()
    adapter = DeterministicSimulatedSensorAdapter(scenario, capability)

    with pytest.raises(M8SensorAdapterError) as replay_error:
        adapter.replay("0" * 64)
    assert replay_error.value.reason_code == M8SensorAdapterFailureCode.REPLAY_NOT_FOUND

    with pytest.raises(M8SensorAdapterError) as raw_error:
        adapter.read_raw_signal("m8/sensor-raw/missing/0.json")
    assert raw_error.value.reason_code == M8SensorAdapterFailureCode.RAW_SIGNAL_NOT_FOUND

    other_scenario = _scenario(M8SensorType.DOOR_CONTACT, values=(True,))
    with pytest.raises(M8SensorAdapterError) as source_error:
        adapter.poll(_request(other_scenario, capability))
    assert source_error.value.reason_code == M8SensorAdapterFailureCode.SOURCE_MISMATCH

    unsupported = _capability((M8SensorType.TEMPERATURE,))
    with pytest.raises(M8SensorAdapterError) as capability_error:
        DeterministicSimulatedSensorAdapter(scenario, unsupported)
    assert capability_error.value.reason_code == (M8SensorAdapterFailureCode.CAPABILITY_MISMATCH)


def test_default_smoke_bundle_reaches_advisory_emergency_without_life_safety_claim() -> None:
    bundle = build_offline_smoke_demo_bundle(
        source_catalog_id=SHA_B,
        location_id="room-chem-301",
        adapter_manifest_id=SHA_A,
        fixture_manifest_id=SHA_C,
        policy_manifest_id="d" * 64,
    )
    adapter = DeterministicSimulatedSensorAdapter(bundle.scenario, bundle.capability)
    result = adapter.poll(_request(bundle.scenario, bundle.capability, limit=2))
    assessment = M8SensorRiskAssessmentV1(
        sample=result.samples[1],
        policy=bundle.risk_policy,
        evaluator_manifest_id="e" * 64,
    )

    assert assessment.risk_level == M8OperationalRiskLevel.EMERGENCY
    assert assessment.create_pending_case_recommended is True
    assert assessment.human_verification_required is True
    assert assessment.life_safety_action_permitted is False
    assert assessment.direct_disciplinary_action_permitted is False
    assert "SIMULATED" in assessment.display_badge
    assert "NOT CERTIFIED FIRE DETECTION" in assessment.display_badge

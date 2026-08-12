"""Pinned construction of the default offline M8 smoke-sensor demonstration."""

from __future__ import annotations

from dataclasses import dataclass

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import M8OperationalRiskLevel
from labcourt.contracts.m8_operations import (
    M8OperationalSource,
    M8OperationalSourceMode,
    M8SensorType,
)
from labcourt.contracts.m8_sensor_signals import (
    M8SensorAdapterCapabilityAuthorityV1,
    M8SensorRiskOperator,
    M8SensorRiskPolicyAuthorityV1,
    M8SensorRiskPolicyPurpose,
    M8SensorRiskRule,
    M8SimulatedSensorReading,
    M8SimulatedSensorScenarioAuthorityV1,
)
from labcourt.contracts.references import ReferenceToken


@dataclass(frozen=True)
class M8OfflineSmokeDemoBundle:
    capability: M8SensorAdapterCapabilityAuthorityV1
    scenario: M8SimulatedSensorScenarioAuthorityV1
    risk_policy: M8SensorRiskPolicyAuthorityV1


def build_offline_smoke_demo_bundle(
    *,
    source_catalog_id: Sha256Hex,
    location_id: ReferenceToken,
    adapter_manifest_id: Sha256Hex,
    fixture_manifest_id: Sha256Hex,
    policy_manifest_id: Sha256Hex,
) -> M8OfflineSmokeDemoBundle:
    """Build a deterministic inactive-to-active smoke scenario with pinned manifests."""

    adapter_id = "m8-offline-sensor-simulator"
    source = M8OperationalSource(
        source_id="sensor-simulated-smoke-01",
        device_id="device-simulated-smoke-01",
        location_id=location_id,
        mode=M8OperationalSourceMode.SIMULATED_SENSOR,
        sensor_type=M8SensorType.SMOKE,
        adapter_id=adapter_id,
        manifest_id=adapter_manifest_id,
    )
    capability = M8SensorAdapterCapabilityAuthorityV1(
        adapter_id=adapter_id,
        adapter_manifest_id=adapter_manifest_id,
        supported_source_modes=(M8OperationalSourceMode.SIMULATED_SENSOR,),
        supported_sensor_types=tuple(sorted(M8SensorType, key=lambda item: item.value)),
        offline_capable=True,
        network_required=False,
        deterministic_replay=True,
        raw_reference_required=True,
        max_batch_size=32,
        poll_timeout_ms=1_000,
    )
    scenario = M8SimulatedSensorScenarioAuthorityV1(
        scenario_id="offline-smoke-emergency-demo-v1",
        source_catalog_id=source_catalog_id,
        source=source,
        readings=(
            M8SimulatedSensorReading(
                source_sequence=0,
                simulation_tick=0,
                value=False,
            ),
            M8SimulatedSensorReading(
                source_sequence=1,
                simulation_tick=5,
                value=True,
            ),
        ),
        fixture_manifest_id=fixture_manifest_id,
    )
    risk_policy = M8SensorRiskPolicyAuthorityV1(
        policy_id="offline-smoke-demo-policy-v1",
        revision=1,
        purpose=M8SensorRiskPolicyPurpose.DEMONSTRATION,
        rules=(
            M8SensorRiskRule(
                rule_id="simulated-smoke-active-emergency-v1",
                sensor_type=M8SensorType.SMOKE,
                priority=0,
                operator=M8SensorRiskOperator.BOOLEAN_EQUALS,
                boolean_threshold=True,
                risk_level=M8OperationalRiskLevel.EMERGENCY,
                create_pending_case=True,
                response_deadline_seconds=60,
            ),
        ),
        policy_manifest_id=policy_manifest_id,
    )
    return M8OfflineSmokeDemoBundle(
        capability=capability,
        scenario=scenario,
        risk_policy=risk_policy,
    )


__all__ = ["M8OfflineSmokeDemoBundle", "build_offline_smoke_demo_bundle"]

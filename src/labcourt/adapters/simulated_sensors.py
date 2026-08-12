"""Default deterministic, offline-only M8 simulated sensor adapter."""

from __future__ import annotations

import hashlib

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_operations import M8OperationalSourceMode
from labcourt.contracts.m8_sensor_signals import (
    M8SensorAdapterCapabilityAuthorityV1,
    M8SensorPollRequestV1,
    M8SensorPollResultV1,
    M8SensorSample,
    M8SimulatedSensorReading,
    M8SimulatedSensorScenarioAuthorityV1,
)
from labcourt.ports.m8_sensors import (
    M8SensorAdapterError,
    M8SensorAdapterFailureCode,
)


class DeterministicSimulatedSensorAdapter:
    """Poll a frozen scenario without network, GPU, wall clock, or sleeping."""

    def __init__(
        self,
        scenario: M8SimulatedSensorScenarioAuthorityV1,
        capability: M8SensorAdapterCapabilityAuthorityV1,
    ) -> None:
        if not isinstance(scenario, M8SimulatedSensorScenarioAuthorityV1):
            raise TypeError("simulated sensor adapter requires an M8 scenario authority")
        if not isinstance(capability, M8SensorAdapterCapabilityAuthorityV1):
            raise TypeError("simulated sensor adapter requires an M8 capability authority")
        if (
            not capability.offline_capable
            or capability.network_required
            or not capability.deterministic_replay
            or not capability.raw_reference_required
            or M8OperationalSourceMode.SIMULATED_SENSOR not in capability.supported_source_modes
            or scenario.source.sensor_type not in capability.supported_sensor_types
            or scenario.source.adapter_id != capability.adapter_id
            or scenario.source.manifest_id != capability.adapter_manifest_id
        ):
            raise M8SensorAdapterError(M8SensorAdapterFailureCode.CAPABILITY_MISMATCH)
        self._scenario = scenario
        self._capability = capability
        self._results: dict[str, M8SensorPollResultV1] = {}
        self._raw_signals: dict[str, bytes] = {}
        self._generation_count = 0

    def capability_authority(self) -> M8SensorAdapterCapabilityAuthorityV1:
        return self._capability

    def poll(self, request: M8SensorPollRequestV1) -> M8SensorPollResultV1:
        if not isinstance(request, M8SensorPollRequestV1):
            raise TypeError("simulated sensor poll requires M8SensorPollRequestV1")
        cached = self._results.get(request.request_id)
        if cached is not None:
            return cached
        if request.adapter_capability.capability_id != self._capability.capability_id:
            raise M8SensorAdapterError(M8SensorAdapterFailureCode.CAPABILITY_MISMATCH)
        if (
            request.source_catalog_id != self._scenario.source_catalog_id
            or request.source != self._scenario.source
        ):
            raise M8SensorAdapterError(M8SensorAdapterFailureCode.SOURCE_MISMATCH)

        after = request.after_source_sequence
        remaining = tuple(
            reading
            for reading in self._scenario.readings
            if after is None or reading.source_sequence > after
        )
        selected = remaining[: request.limit]
        samples = tuple(self._sample(reading) for reading in selected)
        result = M8SensorPollResultV1(
            request=request,
            samples=samples,
            exhausted=len(selected) == len(remaining),
        )
        self._results[request.request_id] = result
        self._generation_count += 1
        return result

    def replay(self, request_id: str) -> M8SensorPollResultV1:
        if not isinstance(request_id, str):
            raise TypeError("M8 sensor replay request_id must be str")
        result = self._results.get(request_id)
        if result is None:
            raise M8SensorAdapterError(M8SensorAdapterFailureCode.REPLAY_NOT_FOUND)
        return result

    def read_raw_signal(self, raw_signal_ref: str) -> bytes:
        if not isinstance(raw_signal_ref, str):
            raise TypeError("M8 raw_signal_ref must be str")
        raw_signal = self._raw_signals.get(raw_signal_ref)
        if raw_signal is None:
            raise M8SensorAdapterError(M8SensorAdapterFailureCode.RAW_SIGNAL_NOT_FOUND)
        return raw_signal

    @property
    def generation_count(self) -> int:
        return self._generation_count

    def _sample(self, reading: M8SimulatedSensorReading) -> M8SensorSample:
        raw_signal_ref = (
            f"m8/sensor-raw/{self._scenario.scenario_authority_id}/{reading.source_sequence}.json"
        )
        raw_payload = {
            "schema_version": "m8-simulated-raw-sensor-signal-v1",
            "scenario_authority_id": self._scenario.scenario_authority_id,
            "fixture_manifest_id": self._scenario.fixture_manifest_id,
            "source_catalog_id": self._scenario.source_catalog_id,
            "source_id": self._scenario.source.source_id,
            "device_id": self._scenario.source.device_id,
            "location_id": self._scenario.source.location_id,
            "sensor_type": self._scenario.source.sensor_type,
            "source_sequence": reading.source_sequence,
            "simulation_tick": reading.simulation_tick,
            "value": reading.value,
            "quality": reading.quality,
            "simulated": True,
            "certified_fire_detection_claim": False,
            "adapter_manifest_id": self._capability.adapter_manifest_id,
        }
        raw_bytes = (canonical_json(raw_payload) + "\n").encode("utf-8")
        raw_signal_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        prior = self._raw_signals.setdefault(raw_signal_ref, raw_bytes)
        if prior != raw_bytes:  # pragma: no cover - deterministic identity guards this branch
            raise M8SensorAdapterError(M8SensorAdapterFailureCode.RAW_SIGNAL_NOT_FOUND)
        return M8SensorSample(
            source_catalog_id=self._scenario.source_catalog_id,
            source=self._scenario.source,
            source_sequence=reading.source_sequence,
            simulation_tick=reading.simulation_tick,
            value=reading.value,
            quality=reading.quality,
            raw_signal_ref=raw_signal_ref,
            raw_signal_sha256=raw_signal_sha256,
            adapter_input_authority_id=self._scenario.scenario_authority_id,
            adapter_manifest_id=self._capability.adapter_manifest_id,
        )


__all__ = ["DeterministicSimulatedSensorAdapter"]

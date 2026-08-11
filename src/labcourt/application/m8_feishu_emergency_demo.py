"""Assemble the deterministic offline smoke-to-Feishu demonstration."""

from __future__ import annotations

import hashlib
from datetime import datetime

from labcourt.adapters.simulated_sensors import DeterministicSimulatedSensorAdapter
from labcourt.application.m8_sensor_demo import build_offline_smoke_demo_bundle
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_emergency_demo import M8FeishuEmergencyDemoProbeV1
from labcourt.contracts.m8_sensor_signals import (
    M8SensorPollRequestV1,
    M8SensorRiskAssessmentV1,
)


def _manifest(name: bytes) -> Sha256Hex:
    return hashlib.sha256(name).hexdigest()


def build_m8_feishu_emergency_demo_probe(
    *,
    app_id_sha256: Sha256Hex,
    recipient_open_id_sha256: Sha256Hex,
    requested_at: datetime,
) -> M8FeishuEmergencyDemoProbeV1:
    """Build one evidence-bound probe without a clock, network, GPU, or database."""

    bundle = build_offline_smoke_demo_bundle(
        source_catalog_id=_manifest(b"labcourt-personal-demo-source-catalog-v1"),
        location_id="chemistry-lab-301-demo",
        adapter_manifest_id=_manifest(b"labcourt-offline-sensor-adapter-v1"),
        fixture_manifest_id=_manifest(b"labcourt-offline-smoke-fixture-v1"),
        policy_manifest_id=_manifest(b"labcourt-offline-smoke-policy-v1"),
    )
    adapter = DeterministicSimulatedSensorAdapter(bundle.scenario, bundle.capability)
    poll_result = adapter.poll(
        M8SensorPollRequestV1(
            source_catalog_id=bundle.scenario.source_catalog_id,
            source=bundle.scenario.source,
            adapter_capability=bundle.capability,
            limit=2,
            timeout_ms=500,
        )
    )
    assessment = M8SensorRiskAssessmentV1(
        sample=poll_result.samples[-1],
        policy=bundle.risk_policy,
        evaluator_manifest_id=_manifest(b"labcourt-deterministic-risk-evaluator-v1"),
    )
    return M8FeishuEmergencyDemoProbeV1(
        app_id_sha256=app_id_sha256,
        recipient_open_id_sha256=recipient_open_id_sha256,
        requested_at=requested_at,
        poll_result=poll_result,
        risk_assessment=assessment,
        probe_manifest_id=_manifest(b"labcourt-feishu-emergency-demo-probe-v1"),
    )


__all__ = ["build_m8_feishu_emergency_demo_probe"]

"""Idempotent assembly of one persisted, fully offline M8 product demo cut."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from labcourt.adapters.simulated_sensors import DeterministicSimulatedSensorAdapter
from labcourt.adapters.storage.sqlite_m8_inventory_repository import SQLiteM8InventoryRepository
from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.adapters.storage.sqlite_m8_sensor_persistence_repository import (
    SQLiteM8SensorPersistenceRepository,
)
from labcourt.application.m8_projection_workflow import build_operations_projection
from labcourt.application.m8_sensor_demo import build_offline_smoke_demo_bundle
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8ActorScopeKind,
    M8AuthorityReference,
    M8AuthorityReferenceKind,
    M8OperationalCaseCreateCommandV1,
)
from labcourt.contracts.m8_operations import (
    M8CampusLocation,
    M8CampusLocationKind,
    M8CampusTopologyAuthorityV1,
    M8OperationalSource,
    M8OperationalSourceCatalogAuthorityV1,
    M8OperationalSourceMode,
    M8SensorType,
)
from labcourt.contracts.m8_personal_demo import (
    M8PersonalDemoActorBindingV1,
    M8PersonalDemoBootstrapReceiptV1,
)
from labcourt.contracts.m8_projections import M8OperationsProjectionV1
from labcourt.contracts.m8_sensor_signals import (
    M8SensorPollRequestV1,
    M8SensorRiskAssessmentV1,
)

_BUSY_TIMEOUT_MS = 5_000


def _manifest(name: str) -> Sha256Hex:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class M8PersonalDemoBootstrapRun:
    receipt: M8PersonalDemoBootstrapReceiptV1
    projection: M8OperationsProjectionV1


def _topology() -> M8CampusTopologyAuthorityV1:
    return M8CampusTopologyAuthorityV1(
        revision=1,
        locations=(
            M8CampusLocation(
                location_id="campus-demo",
                kind=M8CampusLocationKind.CAMPUS,
                parent_location_id=None,
                display_name="演示校区",
            ),
            M8CampusLocation(
                location_id="building-chem",
                kind=M8CampusLocationKind.BUILDING,
                parent_location_id="campus-demo",
                display_name="化学楼",
            ),
            M8CampusLocation(
                location_id="floor-chem-03",
                kind=M8CampusLocationKind.FLOOR,
                parent_location_id="building-chem",
                display_name="三层",
            ),
            M8CampusLocation(
                location_id="room-chem-301",
                kind=M8CampusLocationKind.ROOM,
                parent_location_id="floor-chem-03",
                display_name="实验室 301 (演示)",
            ),
        ),
        manifest_id=_manifest("labcourt-personal-demo-topology-v1"),
    )


def _source(adapter_manifest_id: Sha256Hex) -> M8OperationalSource:
    return M8OperationalSource(
        source_id="sensor-simulated-smoke-01",
        device_id="device-simulated-smoke-01",
        location_id="room-chem-301",
        mode=M8OperationalSourceMode.SIMULATED_SENSOR,
        sensor_type=M8SensorType.SMOKE,
        adapter_id="m8-offline-sensor-simulator",
        manifest_id=adapter_manifest_id,
    )


def _actors() -> tuple[M8ActorAuthorityV1, ...]:
    values = (
        ("leader-demo", M8ActorRole.LEADER, M8ActorScopeKind.CAMPUS_WIDE, ()),
        ("operations-demo", M8ActorRole.OPERATIONS, M8ActorScopeKind.CAMPUS_WIDE, ()),
        (
            "safety-officer-demo",
            M8ActorRole.SAFETY_OFFICER,
            M8ActorScopeKind.LOCATIONS,
            ("room-chem-301",),
        ),
        ("student-demo", M8ActorRole.STUDENT, M8ActorScopeKind.SELF_ONLY, ()),
    )
    return tuple(
        M8ActorAuthorityV1(
            actor_id=actor_id,
            role=role,
            scope_kind=scope,
            scope_location_ids=locations,
            identity_provider_id="personal-demo-local-idp",
            subject_binding_sha256=hashlib.sha256(actor_id.encode("utf-8")).hexdigest(),
            authority_revision=1,
            active=True,
            manifest_id=_manifest("labcourt-personal-demo-actor-authority-v1"),
        )
        for actor_id, role, scope, locations in values
    )


def bootstrap_m8_personal_demo(database_path: Path) -> M8PersonalDemoBootstrapRun:
    """Create or replay the exact local demo authorities in one SQLite database."""

    if not isinstance(database_path, Path):
        raise TypeError("M8 personal demo database_path must be a Path")
    database_path.parent.mkdir(parents=True, exist_ok=True)
    repository_manifest_id = _manifest("labcourt-personal-demo-sqlite-repository-v1")
    inventory = SQLiteM8InventoryRepository.initialize(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    topology = _topology()
    topology_commit = inventory.publish_topology(topology, None)
    adapter_manifest_id = _manifest("labcourt-offline-sensor-adapter-v1")
    catalog = M8OperationalSourceCatalogAuthorityV1(
        revision=1,
        topology=topology,
        sources=(_source(adapter_manifest_id),),
        catalog_manifest_id=_manifest("labcourt-personal-demo-source-catalog-v1"),
    )
    catalog_commit = inventory.publish_source_catalog(catalog, None)

    operations = SQLiteM8OperationsRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    actor_commits = tuple(operations.publish_actor_authority(actor, None) for actor in _actors())

    smoke = build_offline_smoke_demo_bundle(
        source_catalog_id=catalog.catalog_id,
        location_id="room-chem-301",
        adapter_manifest_id=adapter_manifest_id,
        fixture_manifest_id=_manifest("labcourt-personal-demo-smoke-fixture-v1"),
        policy_manifest_id=_manifest("labcourt-personal-demo-smoke-policy-v1"),
    )
    adapter = DeterministicSimulatedSensorAdapter(smoke.scenario, smoke.capability)
    poll_result = adapter.poll(
        M8SensorPollRequestV1(
            source_catalog_id=catalog.catalog_id,
            source=smoke.scenario.source,
            adapter_capability=smoke.capability,
            limit=2,
            timeout_ms=500,
        )
    )
    raw_signals = tuple(
        adapter.read_raw_signal(sample.raw_signal_ref) for sample in poll_result.samples
    )
    sensors = SQLiteM8SensorPersistenceRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    poll_commit = sensors.commit_poll_result(
        poll_result,
        raw_signals,
        _manifest("labcourt-personal-demo-raw-signal-store-v1"),
        _manifest("labcourt-personal-demo-sensor-cache-v1"),
    )
    latest_sample = poll_commit.sample_receipts[-1]
    assessment = M8SensorRiskAssessmentV1(
        sample=latest_sample.sample,
        policy=smoke.risk_policy,
        evaluator_manifest_id=_manifest("labcourt-deterministic-risk-evaluator-v1"),
    )
    if not assessment.create_pending_case_recommended:
        raise ValueError("M8 personal demo smoke policy did not recommend a pending Case")
    case_commit = operations.create_operational_case(
        M8OperationalCaseCreateCommandV1(
            source_catalog_id=catalog.catalog_id,
            location_id=latest_sample.sample.location_id,
            risk_level=assessment.risk_level,
            policy_rule_id=assessment.matched_rule_id or "unmatched-demo-rule",
            policy_manifest_id=smoke.risk_policy.policy_manifest_id,
            source_ids=(latest_sample.sample.source_id,),
            simulated_source_ids=(latest_sample.sample.source_id,),
            trigger_authorities=(
                M8AuthorityReference(
                    kind=M8AuthorityReferenceKind.SENSOR_SIGNAL,
                    authority_id=latest_sample.sample.sample_id,
                    document_sha256=latest_sample.sample_document_sha256,
                ),
            ),
            automation_component_id="m8-personal-demo-case-builder",
            automation_manifest_id=_manifest("labcourt-personal-demo-case-builder-v1"),
        ),
        None,
        _manifest("labcourt-personal-demo-case-authority-v1"),
        _manifest("labcourt-personal-demo-case-audit-v1"),
    )

    projection = build_operations_projection(
        topology_commit,
        catalog_commit,
        (latest_sample,),
        (case_commit,),
        (case_commit.audit_event,),
        (),
        (),
        _manifest("labcourt-personal-demo-operations-projection-v1"),
    )
    overview = projection.overview
    receipt = M8PersonalDemoBootstrapReceiptV1(
        topology_commit_receipt_id=topology_commit.commit_receipt_id,
        source_catalog_commit_receipt_id=catalog_commit.commit_receipt_id,
        actor_bindings=tuple(
            M8PersonalDemoActorBindingV1(
                actor_id=commit.authority.actor_id,
                role=commit.authority.role,
                actor_commit_receipt_id=commit.commit_receipt_id,
            )
            for commit in actor_commits
        ),
        sensor_poll_cache_commit_receipt_id=poll_commit.commit_receipt_id,
        latest_sensor_sample_commit_receipt_id=latest_sample.commit_receipt_id,
        raw_signal_refs=tuple(sample.raw_signal_ref for sample in poll_result.samples),
        case_commit_receipt_id=case_commit.commit_receipt_id,
        case_id=case_commit.case_id,
        operations_projection_id=projection.projection_id,
        location_count=overview.location_count,
        source_count=overview.source_count,
        observed_sensor_count=overview.observed_sensor_count,
        current_case_count=overview.current_case_count,
        pending_verification_case_count=overview.pending_verification_case_count,
        bootstrap_manifest_id=_manifest("labcourt-personal-demo-bootstrap-v1"),
    )
    return M8PersonalDemoBootstrapRun(receipt=receipt, projection=projection)


__all__ = ["M8PersonalDemoBootstrapRun", "bootstrap_m8_personal_demo"]

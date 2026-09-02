"""Build the empty, offline campus-operations Demo baseline."""

from __future__ import annotations

import hashlib
import os
import shutil
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from labcourt.adapters.storage.sqlite_m8_inventory_repository import SQLiteM8InventoryRepository
from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.application.m8_personal_demo_knowledge import (
    bootstrap_m8_personal_demo_knowledge,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8ActorScopeKind,
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
from labcourt.contracts.m8_personal_demo import M8PersonalDemoRecordedMediaReceiptV1
from labcourt.contracts.m8_platform_demo import (
    M8PlatformBootstrapReceiptV1,
    M8PlatformReservationAuthorityV1,
)

_BUSY_TIMEOUT_MS = 5_000
PLATFORM_CAMPUS_ID = "campus-demo"
PLATFORM_LOCATION_ID = "room-chem-301"
PLATFORM_CAMERA_ID = "camera-recorded-demo-01"
PLATFORM_SMOKE_ID = "sensor-simulated-smoke-01"
PLATFORM_TEMPERATURE_ID = "sensor-simulated-temperature-01"
PLATFORM_DATABASE_NAME = "labcourt.sqlite3"
PLATFORM_BOOTSTRAP_RECEIPT_NAME = "platform-bootstrap-receipt.json"
PLATFORM_MEDIA_RECEIPT_NAME = "camera-media-receipt.json"
PLATFORM_SCENARIO_STATE_NAME = "platform-scenario-state.json"
PLATFORM_ACCESS_NAME = "platform-local-access.json"
PLATFORM_PLAYBACK_REF = Path("media/camera-recorded-demo-01.mp4")


def platform_manifest(name: str) -> Sha256Hex:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


def _topology() -> M8CampusTopologyAuthorityV1:
    return M8CampusTopologyAuthorityV1(
        revision=1,
        locations=(
            M8CampusLocation(
                location_id=PLATFORM_CAMPUS_ID,
                kind=M8CampusLocationKind.CAMPUS,
                parent_location_id=None,
                display_name="演示校区",
            ),
            M8CampusLocation(
                location_id="building-chem",
                kind=M8CampusLocationKind.BUILDING,
                parent_location_id=PLATFORM_CAMPUS_ID,
                display_name="化学楼",
            ),
            M8CampusLocation(
                location_id="floor-chem-03",
                kind=M8CampusLocationKind.FLOOR,
                parent_location_id="building-chem",
                display_name="三层",
            ),
            M8CampusLocation(
                location_id=PLATFORM_LOCATION_ID,
                kind=M8CampusLocationKind.ROOM,
                parent_location_id="floor-chem-03",
                display_name="实验室 301",
            ),
        ),
        manifest_id=platform_manifest("labcourt-platform-topology-v1"),
    )


def _sources() -> tuple[M8OperationalSource, ...]:
    values = (
        (
            PLATFORM_CAMERA_ID,
            "camera-device-demo-01",
            M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION,
            None,
        ),
        (
            PLATFORM_SMOKE_ID,
            "smoke-device-demo-01",
            M8OperationalSourceMode.SIMULATED_SENSOR,
            M8SensorType.SMOKE,
        ),
        (
            PLATFORM_TEMPERATURE_ID,
            "temperature-device-demo-01",
            M8OperationalSourceMode.SIMULATED_SENSOR,
            M8SensorType.TEMPERATURE,
        ),
    )
    return tuple(
        M8OperationalSource(
            source_id=source_id,
            device_id=device_id,
            location_id=PLATFORM_LOCATION_ID,
            mode=mode,
            sensor_type=sensor_type,
            adapter_id=(
                "m8-recorded-video-adapter"
                if mode == M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION
                else "m8-offline-sensor-simulator"
            ),
            manifest_id=platform_manifest(f"labcourt-platform-source-{source_id}-v1"),
        )
        for source_id, device_id, mode, sensor_type in values
    )


def _actors() -> tuple[M8ActorAuthorityV1, ...]:
    values = (
        ("leader-demo", M8ActorRole.LEADER, M8ActorScopeKind.CAMPUS_WIDE, ()),
        ("operations-demo", M8ActorRole.OPERATIONS, M8ActorScopeKind.CAMPUS_WIDE, ()),
        (
            "safety-officer-demo",
            M8ActorRole.SAFETY_OFFICER,
            M8ActorScopeKind.LOCATIONS,
            (PLATFORM_LOCATION_ID,),
        ),
        ("student-demo", M8ActorRole.STUDENT, M8ActorScopeKind.SELF_ONLY, ()),
    )
    return tuple(
        M8ActorAuthorityV1(
            actor_id=actor_id,
            role=role,
            scope_kind=scope,
            scope_location_ids=locations,
            identity_provider_id="platform-demo-local-idp",
            subject_binding_sha256=platform_manifest(f"platform-subject-{actor_id}"),
            authority_revision=1,
            active=True,
            manifest_id=platform_manifest("labcourt-platform-actor-authority-v1"),
        )
        for actor_id, role, scope, locations in values
    )


def _reservation(session_id: str) -> M8PlatformReservationAuthorityV1:
    starts_at = datetime(2026, 8, 12, 0, 0, tzinfo=UTC)
    return M8PlatformReservationAuthorityV1(
        reservation_id=f"reservation-{session_id}",
        actor_id="student-demo",
        location_id=PLATFORM_LOCATION_ID,
        starts_at=starts_at,
        ends_at=starts_at + timedelta(days=3650),
        manifest_id=platform_manifest("labcourt-platform-reservation-v1"),
    )


def _copy_media(
    *,
    input_media_path: Path,
    artifact_root: Path,
    source_catalog_id: str,
    source_catalog_commit_receipt_id: str,
) -> M8PersonalDemoRecordedMediaReceiptV1:
    source = input_media_path.resolve(strict=True)
    if source.suffix.lower() != ".mp4" or not source.is_file():
        raise ValueError("platform Demo requires inputs/goggles-missing.mp4")
    header = source.read_bytes()[:32]
    size = source.stat().st_size
    if len(header) < 16 or header[4:8] != b"ftyp":
        raise ValueError("platform Demo recorded video must be an ISO-BMFF MP4")
    destination = artifact_root / PLATFORM_PLAYBACK_REF
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".mp4.tmp")
    shutil.copyfile(source, temporary)
    with temporary.open("r+b") as stream:
        stream.flush()
        os.fsync(stream.fileno())
    digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
    if temporary.stat().st_size != size:
        temporary.unlink(missing_ok=True)
        raise ValueError("platform Demo recorded video changed while binding")
    temporary.replace(destination)
    receipt = M8PersonalDemoRecordedMediaReceiptV1(
        source_catalog_id=source_catalog_id,
        source_catalog_commit_receipt_id=source_catalog_commit_receipt_id,
        raw_media_ref=f"raw-media-{digest[:24]}",
        input_file_sha256=digest,
        input_size_bytes=size,
        playback_file_sha256=digest,
        playback_size_bytes=size,
        media_binding_manifest_id=platform_manifest("labcourt-platform-media-binding-v1"),
    )
    (artifact_root / PLATFORM_MEDIA_RECEIPT_NAME).write_text(
        canonical_json(receipt.model_dump(mode="json")), encoding="utf-8"
    )
    return receipt


@dataclass(frozen=True, slots=True)
class M8PlatformBootstrapRun:
    receipt: M8PlatformBootstrapReceiptV1
    media_receipt: M8PersonalDemoRecordedMediaReceiptV1


def bootstrap_m8_platform_demo(
    database_path: Path,
    input_media_path: Path,
    *,
    session_id: str | None = None,
) -> M8PlatformBootstrapRun:
    """Create a new baseline without invoking the legacy personal Demo bootstrap."""

    artifact_root = database_path.parent
    artifact_root.mkdir(parents=True, exist_ok=True)
    effective_session_id = session_id or f"session-{uuid.uuid4().hex[:16]}"
    repository_manifest_id = platform_manifest("labcourt-platform-sqlite-repository-v1")
    inventory = SQLiteM8InventoryRepository.initialize(
        database_path, _BUSY_TIMEOUT_MS, repository_manifest_id
    )
    topology = _topology()
    topology_commit = inventory.publish_topology(topology, None)
    catalog = M8OperationalSourceCatalogAuthorityV1(
        revision=1,
        topology=topology,
        sources=_sources(),
        catalog_manifest_id=platform_manifest("labcourt-platform-source-catalog-v1"),
    )
    catalog_commit = inventory.publish_source_catalog(catalog, None)
    operations = SQLiteM8OperationsRepository(
        database_path, _BUSY_TIMEOUT_MS, repository_manifest_id
    )
    actor_commits = tuple(operations.publish_actor_authority(actor, None) for actor in _actors())
    bootstrap_m8_personal_demo_knowledge(database_path)
    media_receipt = _copy_media(
        input_media_path=input_media_path,
        artifact_root=artifact_root,
        source_catalog_id=catalog.catalog_id,
        source_catalog_commit_receipt_id=catalog_commit.commit_receipt_id,
    )
    receipt = M8PlatformBootstrapReceiptV1(
        session_id=effective_session_id,
        topology_commit_receipt_id=topology_commit.commit_receipt_id,
        source_catalog_commit_receipt_id=catalog_commit.commit_receipt_id,
        actor_commit_receipt_ids=tuple(item.commit_receipt_id for item in actor_commits),
        reservation=_reservation(effective_session_id),
        camera_media_binding_receipt_id=media_receipt.media_binding_receipt_id,
        bootstrap_manifest_id=platform_manifest("labcourt-platform-bootstrap-v1"),
    )
    (artifact_root / PLATFORM_BOOTSTRAP_RECEIPT_NAME).write_text(
        canonical_json(receipt.model_dump(mode="json", exclude_computed_fields=True)),
        encoding="utf-8",
    )
    return M8PlatformBootstrapRun(receipt=receipt, media_receipt=media_receipt)


def load_m8_platform_bootstrap(artifact_root: Path) -> M8PlatformBootstrapReceiptV1:
    return M8PlatformBootstrapReceiptV1.model_validate_json(
        (artifact_root / PLATFORM_BOOTSTRAP_RECEIPT_NAME).read_bytes()
    )


__all__ = [
    "PLATFORM_ACCESS_NAME",
    "PLATFORM_BOOTSTRAP_RECEIPT_NAME",
    "PLATFORM_CAMERA_ID",
    "PLATFORM_CAMPUS_ID",
    "PLATFORM_DATABASE_NAME",
    "PLATFORM_LOCATION_ID",
    "PLATFORM_MEDIA_RECEIPT_NAME",
    "PLATFORM_SCENARIO_STATE_NAME",
    "PLATFORM_SMOKE_ID",
    "PLATFORM_TEMPERATURE_ID",
    "M8PlatformBootstrapRun",
    "bootstrap_m8_platform_demo",
    "load_m8_platform_bootstrap",
    "platform_manifest",
]

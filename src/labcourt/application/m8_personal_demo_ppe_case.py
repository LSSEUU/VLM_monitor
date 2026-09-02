"""Create one simulated PPE weak-label candidate Case from bound Demo media."""

from __future__ import annotations

import hashlib
from pathlib import Path

from labcourt.adapters.storage.sqlite_m8_inventory_repository import SQLiteM8InventoryRepository
from labcourt.adapters.storage.sqlite_m8_operations_repository import SQLiteM8OperationsRepository
from labcourt.application.m8_personal_demo_bootstrap import bootstrap_m8_personal_demo
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import (
    M8ActorRole,
    M8AuthorityReference,
    M8AuthorityReferenceKind,
    M8OperationalCaseCreateCommandV1,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_personal_demo import (
    M8PersonalDemoPpeCaseReceiptV1,
    M8PersonalDemoRecordedMediaReceiptV1,
)

_BUSY_TIMEOUT_MS = 5_000
_CHUNK_SIZE = 1024 * 1024


def _manifest(name: str) -> Sha256Hex:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


def _verify_playback_bytes(
    artifact_root: Path,
    binding: M8PersonalDemoRecordedMediaReceiptV1,
) -> None:
    path = artifact_root / binding.playback_media_ref
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
    if size != binding.playback_size_bytes or digest.hexdigest() != binding.playback_file_sha256:
        raise ValueError("M8 personal Demo PPE media conflicts with binding authority")


def create_m8_personal_demo_ppe_case(
    database_path: Path,
    artifact_root: Path,
    binding: M8PersonalDemoRecordedMediaReceiptV1,
) -> M8PersonalDemoPpeCaseReceiptV1:
    """Persist one general-risk candidate that has no fact or disciplinary authority."""

    if not isinstance(binding, M8PersonalDemoRecordedMediaReceiptV1):
        raise TypeError("M8 personal Demo PPE Case requires a recorded-media binding")
    _verify_playback_bytes(artifact_root, binding)
    bootstrap = bootstrap_m8_personal_demo(database_path)
    repository_manifest_id = bootstrap.projection.topology_receipt.repository_manifest_id
    inventory = SQLiteM8InventoryRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    operations = SQLiteM8OperationsRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    catalog = inventory.get_current_source_catalog("campus-demo")
    if (
        catalog.catalog.catalog_id != binding.source_catalog_id
        or catalog.commit_receipt_id != binding.source_catalog_commit_receipt_id
        or not any(source.source_id == binding.source_id for source in catalog.catalog.sources)
    ):
        raise ValueError("M8 personal Demo PPE media belongs to another source catalog cut")
    student = operations.get_current_actor_authority("student-demo").authority
    if not student.active or student.role != M8ActorRole.STUDENT:
        raise ValueError("M8 personal Demo PPE subject authority changed")

    video_event_document_sha256 = sha256_hex(binding.model_dump(mode="json"))
    case = operations.create_operational_case(
        M8OperationalCaseCreateCommandV1(
            source_catalog_id=catalog.catalog.catalog_id,
            location_id="room-chem-301",
            risk_level=M8OperationalRiskLevel.GENERAL,
            policy_rule_id="ppe-goggles-missing-candidate-v1",
            policy_manifest_id=_manifest("labcourt-personal-demo-ppe-candidate-policy-v1"),
            source_ids=(binding.source_id,),
            simulated_source_ids=(binding.source_id,),
            trigger_authorities=(
                M8AuthorityReference(
                    kind=M8AuthorityReferenceKind.VIDEO_EVENT,
                    authority_id=binding.media_binding_receipt_id,
                    document_sha256=video_event_document_sha256,
                ),
            ),
            automation_component_id="m8-personal-demo-ppe-candidate-builder",
            automation_manifest_id=_manifest("labcourt-personal-demo-ppe-candidate-builder-v1"),
        ),
        "student-demo",
        _manifest("labcourt-personal-demo-case-authority-v1"),
        _manifest("labcourt-personal-demo-case-audit-v1"),
    )
    return M8PersonalDemoPpeCaseReceiptV1(
        source_catalog_id=catalog.catalog.catalog_id,
        media_binding_receipt_id=binding.media_binding_receipt_id,
        video_event_document_sha256=video_event_document_sha256,
        case_id=case.case_id,
        case_commit_receipt_id=case.commit_receipt_id,
        ppe_case_manifest_id=_manifest("labcourt-personal-demo-ppe-case-v1"),
    )


__all__ = ["create_m8_personal_demo_ppe_case"]

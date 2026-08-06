from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from labcourt.contracts.artifact_validation import (
    ArtifactValidationReport,
    ProjectionArtifactKind,
)
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.projection_generation import (
    ProjectionCurrentPointer,
    ProjectionGenerationEntry,
    ProjectionGenerationManifest,
)

RUN_ID = "projection-contract-run"
HEAD_HASH = "1" * 64


def _manifest() -> ProjectionGenerationManifest:
    return ProjectionGenerationManifest(
        run_id=RUN_ID,
        audit_head_sequence=2,
        audit_head_hash=HEAD_HASH,
        entries=(
            ProjectionGenerationEntry(
                kind=ProjectionArtifactKind.AUDIT_JSONL,
                projection_id=RUN_ID,
                relative_path="audit.jsonl",
                sha256="2" * 64,
                size_bytes=20,
            ),
            ProjectionGenerationEntry(
                kind=ProjectionArtifactKind.EVENTS_JSONL,
                projection_id=RUN_ID,
                relative_path="events.jsonl",
                sha256="3" * 64,
                size_bytes=30,
            ),
        ),
    )


def test_generation_and_pointer_computed_identities_cannot_be_forged() -> None:
    manifest = _manifest()
    serialized = manifest.model_dump(mode="json")
    serialized["generation_id"] = "f" * 64
    with pytest.raises(ValidationError, match="generation_id conflicts"):
        ProjectionGenerationManifest.model_validate(serialized)

    manifest_bytes = canonical_bytes(manifest.model_dump(mode="json"))
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    pointer = ProjectionCurrentPointer(
        run_id=RUN_ID,
        audit_head_sequence=manifest.audit_head_sequence,
        audit_head_hash=manifest.audit_head_hash,
        generation_id=manifest.generation_id,
        manifest_relative_path=(
            f"{RUN_ID}/projections/generations/{manifest.generation_id}/"
            f"manifest-{manifest_sha}.json"
        ),
        manifest_sha256=manifest_sha,
        manifest_size_bytes=len(manifest_bytes),
    )
    serialized_pointer = pointer.model_dump(mode="json")
    serialized_pointer["pointer_id"] = "e" * 64
    with pytest.raises(ValidationError, match="pointer_id conflicts"):
        ProjectionCurrentPointer.model_validate(serialized_pointer)


def test_generation_inventory_is_exact_stable_and_path_bound() -> None:
    manifest = _manifest()
    assert (
        ProjectionGenerationManifest.model_validate_json(
            canonical_bytes(manifest.model_dump(mode="json"))
        )
        == manifest
    )

    with pytest.raises(ValidationError, match="stable order"):
        ProjectionGenerationManifest(
            run_id=RUN_ID,
            audit_head_sequence=2,
            audit_head_hash=HEAD_HASH,
            entries=tuple(reversed(manifest.entries)),
        )
    with pytest.raises(ValidationError, match="path conflicts"):
        ProjectionGenerationEntry(
            kind=ProjectionArtifactKind.CASE_JSON,
            projection_id="550e8400-e29b-41d4-a716-446655440000",
            relative_path="cases/other.json",
            sha256="4" * 64,
            size_bytes=1,
        )


def test_projection_contract_modules_import_without_a_cycle() -> None:
    assert ArtifactValidationReport(run_id=RUN_ID).run_id == RUN_ID
    assert ProjectionGenerationManifest.model_json_schema(mode="serialization")
    assert ProjectionCurrentPointer.model_json_schema(mode="serialization")

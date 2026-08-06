from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from labcourt.contracts.m4_projection import (
    M4ProjectionArtifactKind,
    M4ProjectionCurrentPointer,
    M4ProjectionGenerationEntry,
    M4ProjectionGenerationManifest,
    m4_projection_relative_path,
)

RUN_ID = "m4-projection-contract"


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _entry(
    kind: M4ProjectionArtifactKind = M4ProjectionArtifactKind.HEARING_SESSION,
    artifact_id: str | None = None,
) -> M4ProjectionGenerationEntry:
    identity = artifact_id or _sha(kind.value)
    return M4ProjectionGenerationEntry(
        kind=kind,
        artifact_id=identity,
        relative_path=m4_projection_relative_path(kind, identity),
        sha256=_sha(f"payload-{kind.value}-{identity}"),
        size_bytes=17,
    )


def test_m4_projection_generation_and_pointer_are_content_addressed() -> None:
    entries = tuple(
        sorted(
            (
                _entry(M4ProjectionArtifactKind.HEARING_SESSION),
                _entry(M4ProjectionArtifactKind.HEARING_CYCLE),
            ),
            key=lambda item: item.sort_key,
        )
    )
    manifest = M4ProjectionGenerationManifest(
        run_id=RUN_ID,
        authority_root_sha256=_sha("authority-root"),
        entries=entries,
    )
    manifest_sha = _sha(manifest.model_dump_json())
    pointer = M4ProjectionCurrentPointer(
        run_id=RUN_ID,
        authority_root_sha256=manifest.authority_root_sha256,
        generation_id=manifest.generation_id,
        manifest_relative_path=(
            f"{RUN_ID}/m4-projections/generations/{manifest.generation_id}/"
            f"manifest-{manifest_sha}.json"
        ),
        manifest_sha256=manifest_sha,
        manifest_size_bytes=100,
    )

    assert (
        M4ProjectionGenerationManifest.model_validate_json(manifest.model_dump_json()) == manifest
    )
    assert M4ProjectionCurrentPointer.model_validate_json(pointer.model_dump_json()) == pointer


def test_m4_projection_contract_rejects_path_and_duplicate_identity() -> None:
    entry = _entry()
    with pytest.raises(ValidationError, match="path conflicts"):
        M4ProjectionGenerationEntry(
            kind=entry.kind,
            artifact_id=entry.artifact_id,
            relative_path=f"documents/wrong/{entry.artifact_id}.json",
            sha256=entry.sha256,
            size_bytes=entry.size_bytes,
        )
    with pytest.raises(ValidationError, match="entries must be unique"):
        M4ProjectionGenerationManifest(
            run_id=RUN_ID,
            authority_root_sha256=_sha("authority-root"),
            entries=(entry, entry.model_copy(update={"relative_path": entry.relative_path})),
        )


def test_m4_projection_contract_rejects_forged_computed_id() -> None:
    manifest = M4ProjectionGenerationManifest(
        run_id=RUN_ID,
        authority_root_sha256=_sha("authority-root"),
        entries=(_entry(),),
    )
    payload = manifest.model_dump(mode="json")
    payload["generation_id"] = "f" * 64
    with pytest.raises(ValidationError, match="generation ID conflicts"):
        M4ProjectionGenerationManifest.model_validate(payload)


def test_m4_projection_path_portably_hashes_frame_identity() -> None:
    entry = _entry(M4ProjectionArtifactKind.FRAME, "camera-a:stream-a:42")

    assert ":" not in entry.relative_path
    assert entry.artifact_id == "camera-a:stream-a:42"

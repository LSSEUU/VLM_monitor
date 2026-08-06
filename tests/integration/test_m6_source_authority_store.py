from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from labcourt.adapters.storage.m6_source_authority_store import (
    M6SourceAuthorityPublisher,
    M6SourceAuthorityStoreError,
    M6SourceAuthorityStoreErrorCode,
    M6StoredSourceAuthorityBundle,
    ReadonlyM6SourceAuthorityStore,
)
from labcourt.adapters.storage.readonly_m6_source_authority import (
    ReadonlyM6SealedSourceAuthorityRepository,
)
from labcourt.adapters.storage.readonly_sqlite import ReadOnlySnapshotError
from labcourt.application.m6_source_authority import assemble_m6_validated_source_authority
from labcourt.application.m6_source_authority_builder import (
    M6SealedSourceBundle,
    build_m6_sealed_source_bundle,
)
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.ports.m6_source_authority_builder import M6ReplayInputSelection
from tests.unit.test_m6_source_authority import _Bundle, _bundle
from tests.unit.test_m6_source_authority_builder import _inputs


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _source_bundle(*, sample_id: str | None = None) -> tuple[_Bundle, M6SealedSourceBundle]:
    source = _bundle()
    selection, gate_source, manifest, report = _inputs(source)
    if sample_id is not None:
        selection = replace(selection, sample_id=sample_id)
    built = build_m6_sealed_source_bundle(
        selection=selection,
        gate_source=gate_source,
        source_manifest=manifest,
        source_validation_report=report,
        config=source.config,
    )
    return source, built


def test_publishes_idempotently_and_resolves_the_complete_source_chain(tmp_path: Path) -> None:
    source, bundle = _source_bundle()
    root = tmp_path / "artifacts"
    publisher = M6SourceAuthorityPublisher(root)

    first = publisher.publish(bundle, config=source.config)
    second = publisher.publish(bundle, config=source.config)
    stored = ReadonlyM6SourceAuthorityStore(root).load(bundle.replay_input_closure)

    assert first == second
    assert first.seal_path.is_file()
    assert all(path.is_file() for path in first.document_paths)
    assert stored.seal == bundle.seal
    assert stored.replay_input_closure == bundle.replay_input_closure
    validated = assemble_m6_validated_source_authority(
        closure=stored.replay_input_closure,
        snapshot=stored.to_source_snapshot(_sha("immutable-source-snapshot")),
        config=source.config,
    )
    assert validated.input_authority == bundle.replay_input_authority


def test_sealed_source_repository_binds_readback_to_one_snapshot_identity(
    tmp_path: Path,
) -> None:
    source, bundle = _source_bundle()
    store = tmp_path / "artifacts"
    snapshot = tmp_path / "private-snapshot.sqlite3"
    snapshot.write_bytes(b"immutable-private-snapshot")
    M6SourceAuthorityPublisher(store).publish(bundle, config=source.config)

    validated = ReadonlyM6SealedSourceAuthorityRepository(
        snapshot,
        store_root=store,
        config=source.config,
    ).load_validated_source(bundle.replay_input_closure)

    assert validated.input_authority == bundle.replay_input_authority
    assert len(validated.source_identity_sha256) == 64


def test_sealed_source_repository_rejects_snapshot_change_during_store_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, bundle = _source_bundle()
    store = tmp_path / "artifacts"
    snapshot = tmp_path / "private-snapshot.sqlite3"
    snapshot.write_bytes(b"snapshot-before")
    M6SourceAuthorityPublisher(store).publish(bundle, config=source.config)
    original = ReadonlyM6SourceAuthorityStore.load

    def mutate_after_read(
        reader: ReadonlyM6SourceAuthorityStore,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6StoredSourceAuthorityBundle:
        result = original(reader, closure)
        snapshot.write_bytes(b"snapshot-changed-after-authority-read")
        return result

    monkeypatch.setattr(ReadonlyM6SourceAuthorityStore, "load", mutate_after_read)
    with pytest.raises(ReadOnlySnapshotError) as changed:
        ReadonlyM6SealedSourceAuthorityRepository(
            snapshot,
            store_root=store,
            config=source.config,
        ).load_validated_source(bundle.replay_input_closure)
    assert changed.value.reason_code == "DATABASE_CHANGED_DURING_M6_SOURCE_SEAL_READ"


@pytest.mark.parametrize(
    "phase",
    (
        "after_staging",
        "after_dependency:REPLAY_INPUT_CLOSURE",
        "before_commit",
    ),
)
def test_faults_before_commit_leave_no_resolvable_seal_and_retry_cleanly(
    tmp_path: Path,
    phase: str,
) -> None:
    source, bundle = _source_bundle()
    root = tmp_path / "artifacts"

    def fault(observed: str) -> None:
        if observed == phase:
            raise RuntimeError(f"fault:{phase}")

    with pytest.raises(M6SourceAuthorityStoreError):
        M6SourceAuthorityPublisher(root, fault_injector=fault).publish(
            bundle,
            config=source.config,
        )
    with pytest.raises(M6SourceAuthorityStoreError) as missing:
        ReadonlyM6SourceAuthorityStore(root).load(bundle.replay_input_closure)
    assert missing.value.code == M6SourceAuthorityStoreErrorCode.SEAL_MISSING

    recovered = M6SourceAuthorityPublisher(root).publish(bundle, config=source.config)
    assert recovered.seal_path.is_file()


def test_lost_commit_receipt_is_recovered_by_full_readback(tmp_path: Path) -> None:
    source, bundle = _source_bundle()

    def fault(phase: str) -> None:
        if phase == "after_commit":
            raise RuntimeError("simulated lost rename receipt")

    result = M6SourceAuthorityPublisher(
        tmp_path,
        fault_injector=fault,
    ).publish(bundle, config=source.config)

    assert result.seal_path.is_file()
    assert (
        ReadonlyM6SourceAuthorityStore(tmp_path).load(bundle.replay_input_closure).seal
        == bundle.seal
    )


def test_reader_rejects_extra_seal_inventory_and_document_tampering(tmp_path: Path) -> None:
    source, bundle = _source_bundle()
    result = M6SourceAuthorityPublisher(tmp_path).publish(bundle, config=source.config)
    extra = result.seal_path.parent / "extra.json"
    extra.write_text("{}", encoding="utf-8")

    with pytest.raises(M6SourceAuthorityStoreError) as inventory:
        ReadonlyM6SourceAuthorityStore(tmp_path).load(bundle.replay_input_closure)
    assert inventory.value.code == M6SourceAuthorityStoreErrorCode.INVENTORY_INVALID

    extra.unlink()
    result.document_paths[0].write_bytes(b"{}")
    with pytest.raises(M6SourceAuthorityStoreError) as tampered:
        ReadonlyM6SourceAuthorityStore(tmp_path).load(bundle.replay_input_closure)
    assert tampered.value.code == M6SourceAuthorityStoreErrorCode.STORAGE_BOUNDARY_FAILURE


def test_reader_never_discovers_a_different_closure_by_scanning(tmp_path: Path) -> None:
    source, bundle = _source_bundle()
    _, other = _source_bundle(sample_id="sample-other")
    M6SourceAuthorityPublisher(tmp_path).publish(bundle, config=source.config)

    with pytest.raises(M6SourceAuthorityStoreError) as missing:
        ReadonlyM6SourceAuthorityStore(tmp_path).load(other.replay_input_closure)

    assert missing.value.code == M6SourceAuthorityStoreErrorCode.SEAL_MISSING
    assert other.replay_input_closure.replay_input_closure_authority_id != (
        bundle.replay_input_closure.replay_input_closure_authority_id
    )


def test_publisher_rejects_untyped_or_physically_inconsistent_bundle(tmp_path: Path) -> None:
    source, bundle = _source_bundle()
    with pytest.raises(M6SourceAuthorityStoreError) as invalid:
        M6SourceAuthorityPublisher(tmp_path).publish(object(), config=source.config)
    assert invalid.value.code == M6SourceAuthorityStoreErrorCode.INVALID_ARGUMENT

    forged = replace(bundle, replay_input_authority_document="{}")
    with pytest.raises(M6SourceAuthorityStoreError) as inconsistent:
        M6SourceAuthorityPublisher(tmp_path).publish(forged, config=source.config)
    assert inconsistent.value.code == M6SourceAuthorityStoreErrorCode.BUNDLE_INVALID


def test_selection_type_remains_non_wire_and_contains_no_placeholder_hashes() -> None:
    selection, _, _, _ = _inputs(_bundle())

    assert isinstance(selection, M6ReplayInputSelection)
    assert not hasattr(selection, "input_authority_id")
    assert not hasattr(selection, "source_validation_report_id")

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from labcourt.adapters.storage.m6_source_authority_store import M6SourceAuthorityPublisher
from labcourt.adapters.storage.readonly_sqlite import ReadOnlySnapshotError
from labcourt.services import m6_source_input as service
from labcourt.services.m6_source_input import (
    M6SourceInputSealError,
    M6SourceInputSealErrorCode,
    seal_m6_source_input,
)
from tests.unit.test_m6_source_authority import _bundle
from tests.unit.test_m6_source_authority_builder import _inputs


def test_one_shot_service_publishes_only_after_snapshot_finally_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _bundle()
    selection, gate_source, manifest, report = _inputs(source)
    snapshot = tmp_path / "private.sqlite3"
    snapshot.write_bytes(b"private-snapshot")
    output = tmp_path / "published"
    events: list[str] = []

    def capture(**kwargs: object):  # type: ignore[no-untyped-def]
        del kwargs
        events.append("capture")
        return gate_source

    @contextmanager
    def snapshot_context(*args: object, **kwargs: object) -> Iterator[Path]:
        del args, kwargs
        events.append("snapshot-enter")
        yield snapshot
        events.append("snapshot-exit")

    def validate(**kwargs: object):  # type: ignore[no-untyped-def]
        del kwargs
        events.append("validate")
        return report, manifest

    class RecordingPublisher:
        def __init__(self, root: str | Path) -> None:
            self._publisher = M6SourceAuthorityPublisher(root)

        def publish(self, bundle: object, *, config: object):  # type: ignore[no-untyped-def]
            assert events[-1] == "snapshot-exit"
            events.append("publish")
            return self._publisher.publish(bundle, config=config)

    monkeypatch.setattr(service, "_capture_live_gate_source", capture)
    monkeypatch.setattr(service, "readonly_sqlite_snapshot", snapshot_context)
    monkeypatch.setattr(service, "snapshot_contains_run", lambda *_: True)
    monkeypatch.setattr(service, "_validate_m6_source_snapshot", validate)
    monkeypatch.setattr(service, "M6SourceAuthorityPublisher", RecordingPublisher)

    result = seal_m6_source_input(
        config=source.config,
        database_path=tmp_path / "source.sqlite3",
        workspace_root=tmp_path,
        output_root=output,
        selection=selection,
    )

    assert events == ["capture", "snapshot-enter", "validate", "snapshot-exit", "publish"]
    assert result.publication.seal_path.is_file()


def test_snapshot_finally_failure_never_publishes_a_commit_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _bundle()
    selection, gate_source, manifest, report = _inputs(source)
    snapshot = tmp_path / "private.sqlite3"
    snapshot.write_bytes(b"private-snapshot")
    output = tmp_path / "published"

    @contextmanager
    def unstable_snapshot(*args: object, **kwargs: object) -> Iterator[Path]:
        del args, kwargs
        yield snapshot
        raise ReadOnlySnapshotError("DATABASE_SOURCE_SET_CHANGED")

    monkeypatch.setattr(service, "_capture_live_gate_source", lambda **_: gate_source)
    monkeypatch.setattr(service, "readonly_sqlite_snapshot", unstable_snapshot)
    monkeypatch.setattr(service, "snapshot_contains_run", lambda *_: True)
    monkeypatch.setattr(
        service,
        "_validate_m6_source_snapshot",
        lambda **_: (report, manifest),
    )

    with pytest.raises(M6SourceInputSealError) as raised:
        seal_m6_source_input(
            config=source.config,
            database_path=tmp_path / "source.sqlite3",
            workspace_root=tmp_path,
            output_root=output,
            selection=selection,
        )

    assert raised.value.code == M6SourceInputSealErrorCode.SNAPSHOT_CHANGED
    assert not output.exists()


def test_missing_run_and_untyped_selection_fail_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _bundle()
    selection, gate_source, _, _ = _inputs(source)
    snapshot = tmp_path / "private.sqlite3"
    snapshot.write_bytes(b"private-snapshot")

    @contextmanager
    def snapshot_context(*args: object, **kwargs: object) -> Iterator[Path]:
        del args, kwargs
        yield snapshot

    monkeypatch.setattr(service, "_capture_live_gate_source", lambda **_: gate_source)
    monkeypatch.setattr(service, "readonly_sqlite_snapshot", snapshot_context)
    monkeypatch.setattr(service, "snapshot_contains_run", lambda *_: False)

    with pytest.raises(M6SourceInputSealError) as missing:
        seal_m6_source_input(
            config=source.config,
            database_path=tmp_path / "source.sqlite3",
            workspace_root=tmp_path,
            output_root=tmp_path / "output",
            selection=selection,
        )
    assert missing.value.code == M6SourceInputSealErrorCode.RUN_NOT_FOUND

    with pytest.raises(M6SourceInputSealError) as invalid:
        seal_m6_source_input(
            config=source.config,
            database_path=tmp_path / "source.sqlite3",
            workspace_root=tmp_path,
            output_root=tmp_path / "output",
            selection=object(),
        )
    assert invalid.value.code == M6SourceInputSealErrorCode.INVALID_ARGUMENT

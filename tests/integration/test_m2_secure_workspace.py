from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from labcourt.adapters.storage import SecureWorkspace
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    PathBoundaryViolation,
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _new_workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    root.mkdir()
    return root


def _create_symlink(link: Path, target: Path, *, directory: bool) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlink creation is unavailable for this test: {error.__class__.__name__}")


def _create_windows_junction(link: Path, target: Path) -> None:
    result = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip("junction creation is unavailable for this test")


def test_read_verified_returns_bytes_from_one_safe_handle(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    data = b"verified artifact bytes"
    (root / "artifact.bin").write_bytes(data)

    with SecureWorkspace(root, max_file_bytes=1024) as workspace:
        snapshot = workspace.read_verified("artifact.bin", _digest(data))

    assert snapshot.relative_path == "artifact.bin"
    assert snapshot.size_bytes == len(data)
    assert snapshot.sha256 == _digest(data)
    assert snapshot.bytes == data


def test_secure_file_snapshot_repr_exposes_only_safe_metadata(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    raw_marker = b"SENSITIVE_RAW_IMAGE_MARKER_DO_NOT_LOG"
    (root / "artifact.bin").write_bytes(raw_marker)

    with SecureWorkspace(root, max_file_bytes=1024) as workspace:
        snapshot = workspace.read_verified("artifact.bin", _digest(raw_marker))

    assert repr(snapshot) == (
        "SecureFileSnapshot(relative_path='artifact.bin', "
        f"size_bytes={len(raw_marker)}, sha256='{_digest(raw_marker)}')"
    )
    assert ", bytes=" not in repr(snapshot)
    assert raw_marker.decode("ascii") not in repr(snapshot)


def test_ensure_private_directory_creates_and_revalidates_owner_only_directory(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)

    with SecureWorkspace(root, 1024) as workspace:
        workspace.ensure_private_directory("private")
        workspace.ensure_private_directory("private")

    assert (root / "private").is_dir()
    if os.name == "posix":
        assert stat.S_IMODE((root / "private").stat().st_mode) == 0o700


def test_ensure_private_directory_rejects_preexisting_broad_permissions(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    broad = root / "broad"
    broad.mkdir()
    if os.name == "posix":
        broad.chmod(0o755)

    with (
        SecureWorkspace(root, 1024) as workspace,
        pytest.raises(PathBoundaryViolation, match="DIRECTORY_NOT_PRIVATE"),
    ):
        workspace.ensure_private_directory("broad")


def test_fault_hook_proves_read_does_not_reopen_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _new_workspace(tmp_path)
    data = b"opened once"
    (root / "artifact.bin").write_bytes(data)
    workspace: SecureWorkspace

    def deny_any_later_open(_: str) -> None:
        if os.name == "nt":
            assert workspace._windows is not None

            def fail_windows_open(*args: object, **kwargs: object) -> int:
                raise AssertionError("read_verified reopened the path")

            monkeypatch.setattr(workspace._windows, "open_handle", fail_windows_open)
        else:

            def fail_posix_open(*args: object, **kwargs: object) -> int:
                raise AssertionError("read_verified reopened the path")

            monkeypatch.setattr(os, "open", fail_posix_open)

    with SecureWorkspace(root, 1024, fault_hook=deny_any_later_open) as workspace:
        snapshot = workspace.read_verified("artifact.bin", _digest(data))

    assert snapshot.bytes == data


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "../outside.bin",
        "/absolute.bin",
        "C:/absolute.bin",
        "//server/share/file.bin",
        "dir\\file.bin",
        "file.bin:stream",
        "https://example.test/file.bin",
        "CON",
        "aux.txt",
        "COM¹.txt",
        "safe/\x7f.bin",
    ],
)
def test_lexical_attacks_are_rejected_without_echoing_input(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    root = _new_workspace(tmp_path)
    with (
        SecureWorkspace(root, 1024) as workspace,
        pytest.raises(PathBoundaryViolation) as captured,
    ):
        workspace.read_verified(unsafe_path)

    assert captured.value.reason_code == "INVALID_RELATIVE_PATH"
    assert captured.value.relative_path is None
    assert str(root) not in str(captured.value)


def test_root_symlink_is_rejected(tmp_path: Path) -> None:
    real_root = tmp_path / "real-root"
    real_root.mkdir()
    linked_root = tmp_path / "linked-root"
    _create_symlink(linked_root, real_root, directory=True)

    with pytest.raises(PathBoundaryViolation) as linked_error:
        SecureWorkspace(linked_root, 1024)
    assert str(real_root) not in str(linked_error.value)
    assert str(linked_root) not in str(linked_error.value)


def test_root_regular_file_is_rejected(tmp_path: Path) -> None:
    regular_file = tmp_path / "not-a-directory"
    regular_file.write_bytes(b"x")
    with pytest.raises(PathBoundaryViolation):
        SecureWorkspace(regular_file, 1024)


def test_intermediate_and_leaf_symlinks_are_rejected_even_inside_root(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    real = root / "real"
    real.mkdir()
    (real / "artifact.bin").write_bytes(b"inside")
    _create_symlink(root / "segment-link", real, directory=True)
    _create_symlink(root / "leaf-link.bin", real / "artifact.bin", directory=False)

    with SecureWorkspace(root, 1024) as workspace:
        with pytest.raises(PathBoundaryViolation):
            workspace.read_verified("segment-link/artifact.bin")
        with pytest.raises(PathBoundaryViolation):
            workspace.read_verified("leaf-link.bin")


@pytest.mark.skipif(os.name != "nt", reason="Windows junction semantics")
def test_windows_junction_segment_is_rejected(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    target = tmp_path / "junction-target"
    target.mkdir()
    (target / "artifact.bin").write_bytes(b"outside")
    _create_windows_junction(root / "junction", target)

    with SecureWorkspace(root, 1024) as workspace, pytest.raises(PathBoundaryViolation):
        workspace.read_verified("junction/artifact.bin")


@pytest.mark.skipif(os.name != "nt", reason="Windows junction semantics")
def test_windows_junction_root_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "junction-root-target"
    target.mkdir()
    junction = tmp_path / "junction-root"
    _create_windows_junction(junction, target)

    with pytest.raises(PathBoundaryViolation):
        SecureWorkspace(junction, 1024)


def test_hardlinks_are_rejected(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    original = root / "original.bin"
    original.write_bytes(b"same inode")
    try:
        os.link(original, root / "hardlink.bin")
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"hardlink creation is unavailable: {error.__class__.__name__}")

    with (
        SecureWorkspace(root, 1024) as workspace,
        pytest.raises(PathBoundaryViolation, match="UNSAFE_LINK_COUNT"),
    ):
        workspace.read_verified("original.bin")


def test_non_regular_and_oversize_files_are_rejected(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    (root / "directory-leaf").mkdir()
    with (root / "oversize.bin").open("wb") as stream:
        stream.seek(1024)
        stream.write(b"x")

    with SecureWorkspace(root, 1024) as workspace:
        with pytest.raises(PathBoundaryViolation):
            workspace.read_verified("directory-leaf")
        with pytest.raises(PathBoundaryViolation, match="FILE_TOO_LARGE"):
            workspace.read_verified("oversize.bin")


@pytest.mark.skipif(os.name != "posix", reason="FIFO is a POSIX filesystem object")
def test_posix_fifo_is_rejected_without_blocking(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    os.mkfifo(root / "pipe")  # type: ignore[attr-defined]
    with (
        SecureWorkspace(root, 1024) as workspace,
        pytest.raises(PathBoundaryViolation, match="NOT_REGULAR_FILE"),
    ):
        workspace.read_verified("pipe")


def test_hash_mismatch_is_typed(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    (root / "artifact.bin").write_bytes(b"actual")
    with (
        SecureWorkspace(root, 1024) as workspace,
        pytest.raises(ArtifactIntegrityViolation, match="EXPECTED_HASH_MISMATCH"),
    ):
        workspace.read_verified("artifact.bin", _digest(b"expected"))


def test_create_new_is_private_verified_and_never_overwrites(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    data = b"new staged data"
    with SecureWorkspace(root, 1024) as workspace:
        workspace.create_directory(".staging")
        workspace.create_directory(".staging/op-01")
        snapshot = workspace.create_new(".staging/op-01/new.bin", data, _digest(data))
        assert snapshot.bytes == data

        with pytest.raises(ArtifactConflict, match="TARGET_ALREADY_EXISTS"):
            workspace.create_new(".staging/op-01/new.bin", b"replacement", _digest(b"replacement"))
        with pytest.raises(ArtifactIntegrityViolation, match="EXPECTED_HASH_MISMATCH"):
            workspace.create_new(".staging/op-01/bad.bin", data, _digest(b"other"))

    assert (root / ".staging" / "op-01" / "new.bin").read_bytes() == data
    assert not (root / ".staging" / "op-01" / "bad.bin").exists()
    if os.name == "posix":
        assert stat.S_IMODE((root / ".staging").stat().st_mode) == 0o700
        assert stat.S_IMODE((root / ".staging" / "op-01" / "new.bin").stat().st_mode) == 0o600


def test_remove_empty_staging_directory_is_scoped_non_recursive_and_idempotent(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    run_id = "run-cleanup-01"
    empty = f".staging/{run_id}/crop-{'a' * 64}"
    nonempty = f".staging/{run_id}/crop-{'b' * 64}"
    with SecureWorkspace(root, 4096) as workspace:
        for directory in (
            ".staging",
            f".staging/{run_id}",
            empty,
            nonempty,
        ):
            workspace.ensure_private_directory(directory)
        workspace.create_new(
            f"{nonempty}/media.png",
            b"still present",
            _digest(b"still present"),
        )

        workspace.remove_empty_staging_directory(empty)
        workspace.remove_empty_staging_directory(empty)
        with pytest.raises(ArtifactConflict, match="STAGING_DIRECTORY_NOT_EMPTY"):
            workspace.remove_empty_staging_directory(nonempty)
        with pytest.raises(PathBoundaryViolation, match="DIRECTORY_NOT_STAGING_OPERATION"):
            workspace.remove_empty_staging_directory(f".staging/{run_id}")

    assert not (root / Path(*empty.split("/"))).exists()
    assert (root / Path(*nonempty.split("/")) / "media.png").read_bytes() == b"still present"


def test_publish_is_atomic_idempotent_and_rejects_mismatch(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    data = b"content addressed artifact"
    digest = _digest(data)
    conflicting = b"different existing bytes"

    with SecureWorkspace(root, 4096) as workspace:
        for directory in (".staging", ".staging/op-01", "media"):
            workspace.create_directory(directory)

        workspace.create_new(".staging/op-01/artifact.bin", data, digest)
        published = workspace.publish_staged(
            ".staging/op-01/artifact.bin",
            "media/artifact.bin",
            digest,
        )
        assert published.bytes == data
        assert not (root / ".staging" / "op-01" / "artifact.bin").exists()

        retry = workspace.publish_staged(
            ".staging/op-01/artifact.bin",
            "media/artifact.bin",
            digest,
        )
        assert retry == published

        workspace.create_new(".staging/op-01/artifact.bin", data, digest)
        same_target = workspace.publish_staged(
            ".staging/op-01/artifact.bin",
            "media/artifact.bin",
            digest,
        )
        assert same_target == published
        assert (root / ".staging" / "op-01" / "artifact.bin").exists()

        workspace.create_new(
            "media/conflict.bin",
            conflicting,
            _digest(conflicting),
        )
        workspace.create_new(".staging/op-01/conflict.bin", data, digest)
        with pytest.raises(ArtifactConflict, match="DESTINATION_CONTENT_CONFLICT"):
            workspace.publish_staged(
                ".staging/op-01/conflict.bin",
                "media/conflict.bin",
                digest,
            )

    assert (root / "media" / "conflict.bin").read_bytes() == conflicting


def test_publish_never_treats_a_directory_as_an_idempotent_target(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    data = b"publish source"
    digest = _digest(data)
    with SecureWorkspace(root, 4096) as workspace:
        for directory in (".staging", ".staging/op-01", "media", "media/target.bin"):
            workspace.create_directory(directory)
        workspace.create_new(".staging/op-01/target.bin", data, digest)

        with pytest.raises(PathBoundaryViolation):
            workspace.publish_staged(
                ".staging/op-01/target.bin",
                "media/target.bin",
                digest,
            )

    assert (root / ".staging" / "op-01" / "target.bin").read_bytes() == data
    assert (root / "media" / "target.bin").is_dir()


def test_publish_never_treats_a_hardlink_as_an_idempotent_target(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    data = b"publish source"
    digest = _digest(data)
    with SecureWorkspace(root, 4096) as workspace:
        for directory in (".staging", ".staging/op-01", "media"):
            workspace.create_directory(directory)
        workspace.create_new(".staging/op-01/target.bin", data, digest)
        workspace.create_new("media/linked-source.bin", data, digest)
        try:
            os.link(root / "media" / "linked-source.bin", root / "media" / "target.bin")
        except (NotImplementedError, OSError) as error:
            pytest.skip(f"hardlink creation is unavailable: {error.__class__.__name__}")

        with pytest.raises(PathBoundaryViolation, match="UNSAFE_LINK_COUNT"):
            workspace.publish_staged(
                ".staging/op-01/target.bin",
                "media/target.bin",
                digest,
            )

    assert (root / ".staging" / "op-01" / "target.bin").read_bytes() == data


def test_replace_verified_atomically_installs_a_sibling_projection(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    old = b'{"revision":1}'
    new = b'{"revision":2}'
    another = b'{"revision":3}'

    with SecureWorkspace(root, 4096) as workspace:
        workspace.create_directory("run-01")
        workspace.create_new("run-01/events.jsonl", old, _digest(old))
        workspace.create_new(
            "run-01/.events.jsonl.operation-01.tmp",
            new,
            _digest(new),
        )

        replaced = workspace.replace_verified(
            "run-01/.events.jsonl.operation-01.tmp",
            "run-01/events.jsonl",
            _digest(new),
        )
        assert replaced.relative_path == "run-01/events.jsonl"
        assert replaced.bytes == new
        assert not (root / "run-01" / ".events.jsonl.operation-01.tmp").exists()

        workspace.create_new(
            "run-01/.audit.jsonl.operation-02.tmp",
            another,
            _digest(another),
        )
        created = workspace.replace_verified(
            "run-01/.audit.jsonl.operation-02.tmp",
            "run-01/audit.jsonl",
            _digest(another),
        )
        assert created.bytes == another

    assert (root / "run-01" / "events.jsonl").read_bytes() == new
    assert (root / "run-01" / "audit.jsonl").read_bytes() == another


def test_replace_verified_rejects_unsafe_shape_hash_and_existing_target(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    payload = b"projection"
    digest = _digest(payload)

    with SecureWorkspace(root, 4096) as workspace:
        workspace.create_directory("run-01")
        workspace.create_directory("run-01/other")
        workspace.create_new("run-01/.events.jsonl.operation.tmp", payload, digest)

        with pytest.raises(PathBoundaryViolation, match="REPLACEMENT_NOT_SIBLING"):
            workspace.replace_verified(
                "run-01/.events.jsonl.operation.tmp",
                "run-01/other/events.jsonl",
                digest,
            )
        with pytest.raises(PathBoundaryViolation, match="INVALID_REPLACEMENT_TEMP"):
            workspace.replace_verified(
                "run-01/.events.jsonl.operation.tmp",
                "run-01/audit.jsonl",
                digest,
            )
        with pytest.raises(ArtifactIntegrityViolation, match="EXPECTED_HASH_MISMATCH"):
            workspace.replace_verified(
                "run-01/.events.jsonl.operation.tmp",
                "run-01/events.jsonl",
                _digest(b"other"),
            )

        workspace.create_directory("run-01/events.jsonl")
        with pytest.raises(PathBoundaryViolation, match="UNSAFE_REPLACEMENT_TARGET"):
            workspace.replace_verified(
                "run-01/.events.jsonl.operation.tmp",
                "run-01/events.jsonl",
                digest,
            )

    assert (root / "run-01" / ".events.jsonl.operation.tmp").read_bytes() == payload
    assert (root / "run-01" / "events.jsonl").is_dir()


def test_projection_publish_lock_rejects_hardlinked_lock_file(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    with SecureWorkspace(root, 4096) as workspace:
        workspace.create_directory("run-01")
        workspace.create_directory("run-01/projections")
        with workspace.projection_publish_lock("run-01"):
            pass

    lock_path = root / "run-01" / "projections" / ".publish.lock"
    alias = root / "lock-alias"
    try:
        os.link(lock_path, alias)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"hardlink creation is unavailable: {error.__class__.__name__}")
    with (
        SecureWorkspace(root, 4096) as workspace,
        pytest.raises(PathBoundaryViolation, match="LINK"),
        workspace.projection_publish_lock("run-01"),
    ):
        pass


def test_projection_publish_lock_is_released_after_crashed_process(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    with SecureWorkspace(root, 4096) as workspace:
        workspace.create_directory("run-01")
        workspace.create_directory("run-01/projections")
    acquired = tmp_path / "child-acquired"
    script = """
import os
import sys
from pathlib import Path
from labcourt.adapters.storage.secure_workspace import SecureWorkspace

root = Path(sys.argv[1])
marker = Path(sys.argv[2])
with SecureWorkspace(root, 4096) as workspace:
    with workspace.projection_publish_lock("run-01"):
        marker.write_bytes(b"acquired")
        os._exit(23)
"""
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(root), str(acquired)],
        check=False,
        timeout=10,
    )
    assert crashed.returncode == 23
    assert acquired.read_bytes() == b"acquired"

    with (
        SecureWorkspace(root, 4096) as workspace,
        workspace.projection_publish_lock("run-01"),
    ):
        assert True


def _ensure_m6_static_report_lock_parent(workspace: SecureWorkspace) -> None:
    for directory in (
        ".staging",
        ".staging/run-01",
        ".staging/run-01/m6-static-report",
    ):
        workspace.ensure_private_directory(directory)


def test_m6_static_report_publish_lock_has_one_narrow_private_path(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_m6_static_report_lock_parent(workspace)
        with workspace.m6_static_report_publish_lock("run-01"):
            pass

        lock = workspace.read_verified(
            ".staging/run-01/m6-static-report/.publish.lock",
            max_bytes=128,
        )
        assert lock.bytes == b"labcourt-m6-static-report-publish-lock-v1\n"

        for value in (None, "", "../escape", "run/escape", object()):
            with (
                pytest.raises(
                    PathBoundaryViolation,
                    match="INVALID_M6_STATIC_REPORT_RUN",
                ),
                workspace.m6_static_report_publish_lock(value),  # type: ignore[arg-type]
            ):
                pass

    missing_root = tmp_path / "missing-parent-workspace"
    missing_root.mkdir()
    with (
        SecureWorkspace(missing_root, 4096) as workspace,
        pytest.raises(PathBoundaryViolation, match="PARENT_MISSING"),
        workspace.m6_static_report_publish_lock("run-01"),
    ):
        pass


def test_m6_static_report_publish_lock_rejects_hardlinked_lock_file(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_m6_static_report_lock_parent(workspace)
        with workspace.m6_static_report_publish_lock("run-01"):
            pass

    lock_path = root / ".staging" / "run-01" / "m6-static-report" / ".publish.lock"
    alias = root / "m6-static-lock-alias"
    try:
        os.link(lock_path, alias)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"hardlink creation is unavailable: {error.__class__.__name__}")
    with (
        SecureWorkspace(root, 4096) as workspace,
        pytest.raises(PathBoundaryViolation, match="LINK"),
        workspace.m6_static_report_publish_lock("run-01"),
    ):
        pass


def test_m6_static_report_publish_lock_serializes_two_workspace_handles(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_m6_static_report_lock_parent(workspace)

    first_entered = threading.Event()
    release_first = threading.Event()
    second_attempted = threading.Event()
    second_entered = threading.Event()
    order: list[str] = []

    def first_writer() -> None:
        with (
            SecureWorkspace(root, 4096) as workspace,
            workspace.m6_static_report_publish_lock("run-01"),
        ):
            order.append("first")
            first_entered.set()
            assert release_first.wait(timeout=10)

    def second_writer() -> None:
        assert first_entered.wait(timeout=10)
        with SecureWorkspace(root, 4096) as workspace:
            second_attempted.set()
            with workspace.m6_static_report_publish_lock("run-01"):
                order.append("second")
                second_entered.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(first_writer)
        assert first_entered.wait(timeout=10)
        second = executor.submit(second_writer)
        assert second_attempted.wait(timeout=10)
        assert not second_entered.wait(timeout=0.1)
        release_first.set()
        first.result(timeout=10)
        second.result(timeout=10)

    assert second_entered.is_set()
    assert order == ["first", "second"]


def _ensure_m6_offline_demo_lock_parent(workspace: SecureWorkspace) -> None:
    for directory in (
        ".staging",
        ".staging/run-01",
        ".staging/run-01/m6-offline-demo",
    ):
        workspace.ensure_private_directory(directory)


def test_m6_offline_demo_publish_lock_has_one_narrow_private_path(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_m6_offline_demo_lock_parent(workspace)
        with workspace.m6_offline_demo_publish_lock("run-01"):
            pass

        lock = workspace.read_verified(
            ".staging/run-01/m6-offline-demo/.publish.lock",
            max_bytes=128,
        )
        assert lock.bytes == b"labcourt-m6-offline-demo-publish-lock-v1\n"

        for value in (None, "", "../escape", "run/escape", object()):
            with (
                pytest.raises(
                    PathBoundaryViolation,
                    match="INVALID_M6_OFFLINE_DEMO_RUN",
                ),
                workspace.m6_offline_demo_publish_lock(value),  # type: ignore[arg-type]
            ):
                pass

    missing_root = tmp_path / "missing-demo-lock-parent-workspace"
    missing_root.mkdir()
    with (
        SecureWorkspace(missing_root, 4096) as workspace,
        pytest.raises(PathBoundaryViolation, match="PARENT_MISSING"),
        workspace.m6_offline_demo_publish_lock("run-01"),
    ):
        pass


def test_m6_offline_demo_publish_lock_rejects_hardlinked_lock_file(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_m6_offline_demo_lock_parent(workspace)
        with workspace.m6_offline_demo_publish_lock("run-01"):
            pass

    lock_path = root / ".staging" / "run-01" / "m6-offline-demo" / ".publish.lock"
    alias = root / "m6-offline-demo-lock-alias"
    try:
        os.link(lock_path, alias)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"hardlink creation is unavailable: {error.__class__.__name__}")
    with (
        SecureWorkspace(root, 4096) as workspace,
        pytest.raises(PathBoundaryViolation, match="LINK"),
        workspace.m6_offline_demo_publish_lock("run-01"),
    ):
        pass


def test_m6_offline_demo_publish_lock_serializes_two_workspace_handles(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_m6_offline_demo_lock_parent(workspace)

    first_entered = threading.Event()
    release_first = threading.Event()
    second_attempted = threading.Event()
    second_entered = threading.Event()
    order: list[str] = []

    def first_writer() -> None:
        with (
            SecureWorkspace(root, 4096) as workspace,
            workspace.m6_offline_demo_publish_lock("run-01"),
        ):
            order.append("first")
            first_entered.set()
            assert release_first.wait(timeout=10)

    def second_writer() -> None:
        assert first_entered.wait(timeout=10)
        with SecureWorkspace(root, 4096) as workspace:
            second_attempted.set()
            with workspace.m6_offline_demo_publish_lock("run-01"):
                order.append("second")
                second_entered.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(first_writer)
        assert first_entered.wait(timeout=10)
        second = executor.submit(second_writer)
        assert second_attempted.wait(timeout=10)
        assert not second_entered.wait(timeout=0.1)
        release_first.set()
        first.result(timeout=10)
        second.result(timeout=10)

    assert second_entered.is_set()
    assert order == ["first", "second"]


def test_move_verified_targets_trash_and_is_retry_safe(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    data = b"retained hashes survive purge"
    digest = _digest(data)

    with SecureWorkspace(root, 4096) as workspace:
        workspace.create_directory("media")
        workspace.create_directory(".trash")
        workspace.create_new("media/item.bin", data, digest)

        moved = workspace.move_verified("media/item.bin", ".trash/item.bin", digest)
        assert moved.relative_path == ".trash/item.bin"
        assert moved.bytes == data
        assert not (root / "media" / "item.bin").exists()

        retry = workspace.move_verified("media/item.bin", ".trash/item.bin", digest)
        assert retry == moved

        workspace.create_new("media/other.bin", data, digest)
        with pytest.raises(ArtifactConflict, match="DESTINATION_ALREADY_EXISTS"):
            workspace.move_verified("media/other.bin", ".trash/item.bin", digest)

        with pytest.raises(PathBoundaryViolation, match="DESTINATION_NOT_TRASH"):
            workspace.move_verified("media/other.bin", "elsewhere/item.bin", digest)


def test_delete_verified_trash_is_handle_bound_and_hash_guarded(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    data = b"private trash bytes"
    digest = _digest(data)
    trash_path = ".trash/run-01/item.bin"

    with SecureWorkspace(root, 4096) as workspace:
        for directory in (".trash", ".trash/run-01", "media"):
            workspace.create_directory(directory)
        workspace.create_new(trash_path, data, digest)

        with pytest.raises(ArtifactIntegrityViolation, match="EXPECTED_HASH_MISMATCH"):
            workspace.delete_verified_trash(trash_path, _digest(b"other"))
        assert workspace.read_verified(trash_path, digest).bytes == data

        receipt = workspace.delete_verified_trash(trash_path, digest)
        assert receipt.relative_path == trash_path
        assert receipt.size_bytes == len(data)
        assert receipt.sha256 == digest
        assert not hasattr(receipt, "bytes")

        with pytest.raises(PathBoundaryViolation, match="FILE_MISSING"):
            workspace.delete_verified_trash(trash_path, digest)

        workspace.create_new("media/not-trash.bin", data, digest)
        with pytest.raises(PathBoundaryViolation, match="SOURCE_NOT_RUN_TRASH"):
            workspace.delete_verified_trash("media/not-trash.bin", digest)

    assert not (root / Path(trash_path)).exists()
    assert (root / "media" / "not-trash.bin").read_bytes() == data


def test_delete_verified_temporary_is_narrow_hash_guarded_cleanup(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    data = b"temporary projection"
    digest = _digest(data)
    temporary_path = "run-01/.events.jsonl.operation.tmp"

    with SecureWorkspace(root, 4096) as workspace:
        workspace.create_directory("run-01")
        workspace.create_new(temporary_path, data, digest)

        with pytest.raises(ArtifactIntegrityViolation, match="EXPECTED_HASH_MISMATCH"):
            workspace.delete_verified_temporary(temporary_path, _digest(b"other"))
        with pytest.raises(PathBoundaryViolation, match="SOURCE_NOT_PROJECTION_TEMP"):
            workspace.delete_verified_temporary("run-01/events.jsonl", digest)

        receipt = workspace.delete_verified_temporary(temporary_path, digest)
        assert receipt.relative_path == temporary_path
        assert receipt.sha256 == digest
        assert receipt.size_bytes == len(data)

    assert not (root / Path(temporary_path)).exists()


def test_closed_workspace_fails_typed_and_close_is_idempotent(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    workspace = SecureWorkspace(root, 1024)
    workspace.close()
    workspace.close()

    with pytest.raises(PathBoundaryViolation, match="WORKSPACE_CLOSED"):
        workspace.read_verified("artifact.bin")


def test_root_failures_do_not_expose_host_absolute_paths(tmp_path: Path) -> None:
    missing_root = tmp_path / "private-host-path" / "missing"
    with pytest.raises(PathBoundaryViolation) as captured:
        SecureWorkspace(missing_root, 1024)

    assert str(tmp_path) not in str(captured.value)
    assert captured.value.relative_path is None
    assert captured.value.__cause__ is None


def test_video_input_applies_its_own_limit_and_rejects_empty_files(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    (root / "large.fake").write_bytes(b"1234")
    (root / "empty.fake").write_bytes(b"")

    with SecureWorkspace(root, 4096) as workspace:
        with (
            pytest.raises(PathBoundaryViolation, match="FILE_TOO_LARGE"),
            workspace.open_verified_video("large.fake", 3),
        ):
            pytest.fail("oversize input must fail before yielding a decoder path")
        with (
            pytest.raises(PathBoundaryViolation, match="EMPTY_VIDEO_INPUT"),
            workspace.open_verified_video("empty.fake", 4096),
        ):
            pytest.fail("empty input must fail before yielding a decoder path")


@pytest.mark.skipif(os.name != "nt", reason="Windows locked-handle decoder lease")
def test_windows_video_input_holds_verified_file_immutable(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    data = b"synthetic video bytes"
    video_path = root / "input.fake"
    video_path.write_bytes(data)

    with (
        SecureWorkspace(root, 4096) as workspace,
        workspace.open_verified_video("input.fake", 4096) as video,
    ):
        assert Path(video.decoder_path).read_bytes() == data
        assert video.input_file_sha256 == _digest(data)
        assert video.size_bytes == len(data)
        with pytest.raises(OSError):
            os.replace(video_path, root / "replacement.fake")

    os.replace(video_path, root / "replacement.fake")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux sealed memfd")
def test_linux_video_input_is_a_sealed_memfd(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    data = b"synthetic video bytes"
    (root / "input.fake").write_bytes(data)

    with SecureWorkspace(root, 4096) as workspace:
        with workspace.open_verified_video("input.fake", 4096) as video:
            decoder_path = Path(video.decoder_path)
            assert decoder_path.read_bytes() == data
            assert video.input_file_sha256 == _digest(data)
            writer = os.open(decoder_path, os.O_WRONLY)
            try:
                with pytest.raises(OSError):
                    os.write(writer, b"x")
            finally:
                os.close(writer)
        assert not decoder_path.exists()

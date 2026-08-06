from __future__ import annotations

import hashlib
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.storage import SecureOrphanRecoveryFileOps, SecureWorkspace
from labcourt.application.recovery import OrphanRecoveryCoordinator
from labcourt.contracts.enums import (
    RecoveryDisposition,
    RecoveryReasonCode,
)
from labcourt.contracts.recovery import recovery_source_token
from labcourt.exceptions import BudgetExceeded, PathBoundaryViolation

RUN_ID = "run-recovery-01"
NOW = datetime(2026, 7, 27, 12, tzinfo=UTC)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _new_workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    root.mkdir()
    return root


def _ensure_layout(workspace: SecureWorkspace) -> None:
    for directory in (
        ".staging",
        f".staging/{RUN_ID}",
        RUN_ID,
        f"{RUN_ID}/frames",
    ):
        workspace.ensure_private_directory(directory)


def _make_old(root: Path, relative_path: str) -> None:
    old = (NOW - timedelta(hours=2)).timestamp()
    os.utime(root / Path(*relative_path.split("/")), (old, old))


class _References:
    def __init__(self, referenced: set[str]) -> None:
        self.referenced = referenced

    def media_is_referenced(self, run_id: str, media_sha256: str) -> bool:
        assert run_id == RUN_ID
        return media_sha256 in self.referenced


def test_recovery_quarantines_old_staging_and_orphan_but_keeps_referenced_media(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    referenced_data = b"referenced-final"
    orphan_data = b"orphan-final"
    staging_data = b"unfinished-staging"
    referenced_sha = _digest(referenced_data)
    orphan_sha = _digest(orphan_data)
    crop_id = "c" * 64
    staging_path = f".staging/{RUN_ID}/crop-{crop_id}/media.png"
    referenced_path = f"{RUN_ID}/frames/{referenced_sha}.png"
    orphan_path = f"{RUN_ID}/frames/{orphan_sha}.png"

    with SecureWorkspace(root, 4096) as workspace:
        _ensure_layout(workspace)
        workspace.ensure_private_directory(f".staging/{RUN_ID}/crop-{crop_id}")
        workspace.create_new(staging_path, staging_data, _digest(staging_data))
        workspace.create_new(referenced_path, referenced_data, referenced_sha)
        workspace.create_new(orphan_path, orphan_data, orphan_sha)
        for path in (staging_path, referenced_path, orphan_path):
            _make_old(root, path)

        coordinator = OrphanRecoveryCoordinator(
            _References({referenced_sha}),
            SecureOrphanRecoveryFileOps(workspace),
            max_items=20,
            max_depth=2,
            max_name_bytes=128,
        )
        report = coordinator.recover(RUN_ID, NOW, timedelta(hours=1))

    by_reason = {item.reason_code: item for item in report.items}
    assert by_reason[RecoveryReasonCode.REFERENCED_MEDIA].content_sha256 == referenced_sha
    assert by_reason[RecoveryReasonCode.ORPHAN_QUARANTINED].content_sha256 == orphan_sha
    staging_result = by_reason[RecoveryReasonCode.STAGING_QUARANTINED]
    assert staging_result.content_sha256 == _digest(staging_data)
    assert (root / Path(*referenced_path.split("/"))).is_file()
    assert not (root / Path(*orphan_path.split("/"))).exists()
    assert not (root / Path(*staging_path.split("/"))).exists()
    assert (
        root / ".quarantine" / RUN_ID / "frames" / f"{orphan_sha}.png"
    ).read_bytes() == orphan_data
    assert (
        root
        / ".quarantine"
        / RUN_ID
        / "staging"
        / f"{recovery_source_token(staging_path)}-{_digest(staging_data)}.bin"
    ).read_bytes() == staging_data
    serialized = report.model_dump_json()
    assert str(root) not in serialized
    assert '"bytes"' not in serialized


def test_recovery_rechecks_minimum_age_on_the_move_handle(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    data = b"young-orphan"
    digest = _digest(data)
    source_path = f"{RUN_ID}/frames/{digest}.png"
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_layout(workspace)
        workspace.create_new(source_path, data, digest)
        result = OrphanRecoveryCoordinator(
            _References(set()),
            SecureOrphanRecoveryFileOps(workspace),
            max_items=10,
            max_depth=2,
            max_name_bytes=128,
        ).recover(RUN_ID, NOW, timedelta(days=1))

    assert result.items[0].disposition == RecoveryDisposition.RETAINED
    assert result.items[0].reason_code == RecoveryReasonCode.MINIMUM_AGE_NOT_MET
    assert (root / Path(*source_path.split("/"))).read_bytes() == data


def test_recovery_removes_exact_empty_staging_directories_without_recursion(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    empty_operation = f".staging/{RUN_ID}/crop-{'0' * 64}"
    populated_operation = f".staging/{RUN_ID}/crop-{'1' * 64}"
    unknown_path = f"{populated_operation}/notes.txt"
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_layout(workspace)
        workspace.ensure_private_directory(empty_operation)
        workspace.ensure_private_directory(populated_operation)
        workspace.create_new(unknown_path, b"retain-me", _digest(b"retain-me"))
        _make_old(root, empty_operation)
        report = OrphanRecoveryCoordinator(
            _References(set()),
            SecureOrphanRecoveryFileOps(workspace),
            max_items=10,
            max_depth=2,
            max_name_bytes=128,
        ).recover(RUN_ID, NOW, timedelta(hours=1))

    assert not (root / Path(*empty_operation.split("/"))).exists()
    assert (root / Path(*unknown_path.split("/"))).read_bytes() == b"retain-me"
    assert RecoveryReasonCode.EMPTY_STAGING_CLEANED in {item.reason_code for item in report.items}
    assert RecoveryReasonCode.UNKNOWN_ENTRY_SHAPE in {item.reason_code for item in report.items}


def test_recovery_retains_a_fresh_empty_staging_directory(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    operation = f".staging/{RUN_ID}/crop-{'2' * 64}"
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_layout(workspace)
        workspace.ensure_private_directory(operation)
        report = OrphanRecoveryCoordinator(
            _References(set()),
            SecureOrphanRecoveryFileOps(workspace),
            max_items=10,
            max_depth=2,
            max_name_bytes=128,
        ).recover(RUN_ID, NOW, timedelta(days=1))

    assert (root / Path(*operation.split("/"))).is_dir()
    assert report.items[0].disposition == RecoveryDisposition.RETAINED
    assert report.items[0].reason_code == RecoveryReasonCode.MINIMUM_AGE_NOT_MET


def test_full_staging_budget_does_not_hide_a_final_orphan(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    orphan_data = b"orphan-behind-empty-staging"
    orphan_sha = _digest(orphan_data)
    orphan_path = f"{RUN_ID}/frames/{orphan_sha}.png"
    operations = tuple(f".staging/{RUN_ID}/crop-{index:064x}" for index in range(3))
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_layout(workspace)
        for operation in operations:
            workspace.ensure_private_directory(operation)
            _make_old(root, operation)
        workspace.create_new(orphan_path, orphan_data, orphan_sha)
        _make_old(root, orphan_path)
        report = OrphanRecoveryCoordinator(
            _References(set()),
            SecureOrphanRecoveryFileOps(workspace),
            max_items=3,
            max_depth=2,
            max_name_bytes=128,
        ).recover(RUN_ID, NOW, timedelta(hours=1))

    assert all(not (root / Path(*operation.split("/"))).exists() for operation in operations)
    assert not (root / Path(*orphan_path.split("/"))).exists()
    assert (
        sum(item.reason_code == RecoveryReasonCode.EMPTY_STAGING_CLEANED for item in report.items)
        == 3
    )
    assert any(item.reason_code == RecoveryReasonCode.ORPHAN_QUARANTINED for item in report.items)


def test_recovery_reports_unknown_and_unsafe_shapes_without_deleting_them(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    data = b"hardlinked"
    digest = _digest(data)
    canonical = root / RUN_ID / "frames" / f"{digest}.png"
    linked_source = root / RUN_ID / "frames" / "linked-source.bin"
    unknown = root / RUN_ID / "frames" / "notes.txt"
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_layout(workspace)
        linked_source.write_bytes(data)
        try:
            os.link(linked_source, canonical)
        except (NotImplementedError, OSError) as error:
            pytest.skip(f"hardlink creation is unavailable: {error.__class__.__name__}")
        unknown.write_bytes(b"do-not-touch")

        scan = SecureOrphanRecoveryFileOps(workspace).discover(RUN_ID, 10, 2, 128)

    reasons = {item.source_token: item.reason_code for item in scan.anomalies}
    assert reasons[recovery_source_token(f"{RUN_ID}/frames/{digest}.png")] == (
        RecoveryReasonCode.UNSAFE_FILESYSTEM_ENTRY
    )
    assert reasons[recovery_source_token(f"{RUN_ID}/frames/notes.txt")] == (
        RecoveryReasonCode.UNKNOWN_ENTRY_SHAPE
    )
    assert canonical.exists()
    assert unknown.read_bytes() == b"do-not-touch"


def test_recovery_reports_expected_file_shape_that_is_a_directory_as_unsafe(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    digest = "d" * 64
    directory = root / RUN_ID / "frames" / f"{digest}.png"
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_layout(workspace)
        directory.mkdir()
        scan = SecureOrphanRecoveryFileOps(workspace).discover(RUN_ID, 10, 2, 128)

    result = next(
        item
        for item in scan.anomalies
        if item.source_token == recovery_source_token(f"{RUN_ID}/frames/{digest}.png")
    )
    assert result.reason_code == RecoveryReasonCode.UNSAFE_FILESYSTEM_ENTRY
    assert directory.is_dir()


def test_recovery_rejects_staging_symlink_or_windows_junction_without_traversal(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "media.png").write_bytes(b"outside-must-remain")
    operation_name = f"crop-{'e' * 64}"
    link = root / ".staging" / RUN_ID / operation_name
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_layout(workspace)
        if os.name == "nt":
            result = subprocess.run(
                ["cmd", "/d", "/c", "mklink", "/J", str(link), str(outside)],
                capture_output=True,
                check=False,
                text=True,
            )
            if result.returncode != 0:
                pytest.skip("junction creation is unavailable")
        else:
            try:
                os.symlink(outside, link, target_is_directory=True)
            except (NotImplementedError, OSError) as error:
                pytest.skip(f"symlink creation is unavailable: {error.__class__.__name__}")

        scan = SecureOrphanRecoveryFileOps(workspace).discover(RUN_ID, 10, 2, 128)

    operation_path = f".staging/{RUN_ID}/{operation_name}"
    result = next(
        item
        for item in scan.anomalies
        if item.source_token == recovery_source_token(operation_path)
    )
    assert result.reason_code == RecoveryReasonCode.UNSAFE_FILESYSTEM_ENTRY
    assert (outside / "media.png").read_bytes() == b"outside-must-remain"


@pytest.mark.skipif(os.name != "posix", reason="FIFO is a POSIX filesystem object")
def test_recovery_reports_fifo_as_unsafe_without_blocking_or_deleting(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    digest = "f" * 64
    fifo = root / RUN_ID / "frames" / f"{digest}.png"
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_layout(workspace)
        os.mkfifo(fifo)  # type: ignore[attr-defined]
        scan = SecureOrphanRecoveryFileOps(workspace).discover(RUN_ID, 10, 2, 128)

    result = next(
        item
        for item in scan.anomalies
        if item.source_token == recovery_source_token(f"{RUN_ID}/frames/{digest}.png")
    )
    assert result.reason_code == RecoveryReasonCode.UNSAFE_FILESYSTEM_ENTRY
    assert fifo.exists()


def test_recovery_depth_and_name_budgets_report_anomalies_without_descending(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    operation_name = f"crop-{'1' * 64}"
    operation_path = f".staging/{RUN_ID}/{operation_name}"
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_layout(workspace)
        workspace.ensure_private_directory(operation_path)
        workspace.create_new(f"{operation_path}/media.png", b"staged", _digest(b"staged"))
        workspace.create_new(
            f"{RUN_ID}/frames/long-unknown-name.png",
            b"unknown",
            _digest(b"unknown"),
        )
        file_ops = SecureOrphanRecoveryFileOps(workspace)
        depth_scan = file_ops.discover(RUN_ID, 10, 1, 128)
        name_scan = file_ops.discover(RUN_ID, 10, 1, 8)

    assert RecoveryReasonCode.DEPTH_LIMIT_REACHED in {
        item.reason_code for item in depth_scan.anomalies
    }
    assert RecoveryReasonCode.UNSAFE_FILESYSTEM_ENTRY in {
        item.reason_code for item in name_scan.anomalies
    }
    serialized = name_scan.model_dump_json()
    assert "long-unknown-name.png" not in serialized
    assert (root / Path(*operation_path.split("/")) / "media.png").exists()


def test_recovery_detects_content_change_after_database_query_and_does_not_move(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    original = b"original-orphan"
    changed = b"changed-after-discovery"
    digest = _digest(original)
    source_path = f"{RUN_ID}/frames/{digest}.png"
    source = root / Path(*source_path.split("/"))

    class _MutatingReferences:
        def media_is_referenced(self, run_id: str, media_sha256: str) -> bool:
            assert (run_id, media_sha256) == (RUN_ID, digest)
            source.write_bytes(changed)
            _make_old(root, source_path)
            return False

    with SecureWorkspace(root, 4096) as workspace:
        _ensure_layout(workspace)
        workspace.create_new(source_path, original, digest)
        _make_old(root, source_path)
        report = OrphanRecoveryCoordinator(
            _MutatingReferences(),
            SecureOrphanRecoveryFileOps(workspace),
            max_items=10,
            max_depth=2,
            max_name_bytes=128,
        ).recover(RUN_ID, NOW, timedelta(hours=1))

    assert report.items[0].reason_code == RecoveryReasonCode.CONTENT_IDENTITY_MISMATCH
    assert source.read_bytes() == changed
    assert not (root / ".quarantine" / RUN_ID / "frames" / f"{digest}.png").exists()


def test_recovery_scan_budget_fails_before_any_quarantine_action(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_layout(workspace)
        for index in range(3):
            data = f"orphan-{index}".encode()
            digest = _digest(data)
            path = f"{RUN_ID}/frames/{digest}.png"
            workspace.create_new(path, data, digest)
            _make_old(root, path)

        with pytest.raises(BudgetExceeded):
            OrphanRecoveryCoordinator(
                _References(set()),
                SecureOrphanRecoveryFileOps(workspace),
                max_items=2,
                max_depth=2,
                max_name_bytes=128,
            ).recover(RUN_ID, NOW, timedelta(hours=1))

    assert not (root / ".quarantine").exists()


def test_quarantine_is_idempotent_for_same_hash(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    data = b"idempotent-orphan"
    digest = _digest(data)
    source_path = f"{RUN_ID}/frames/{digest}.png"
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_layout(workspace)
        workspace.create_new(source_path, data, digest)
        _make_old(root, source_path)
        file_ops = SecureOrphanRecoveryFileOps(workspace)
        candidate = file_ops.discover(RUN_ID, 10, 2, 128).candidates[0]
        first = file_ops.quarantine(candidate, NOW - timedelta(hours=1))
        retry = file_ops.quarantine(candidate, NOW - timedelta(hours=1))

        assert retry == first


def test_same_hash_preexisting_quarantine_target_completes_isolation(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    data = b"same-target-and-source"
    digest = _digest(data)
    source_path = f"{RUN_ID}/frames/{digest}.png"
    target_path = f".quarantine/{RUN_ID}/frames/{digest}.png"
    with SecureWorkspace(root, 4096) as workspace:
        _ensure_layout(workspace)
        workspace.create_new(source_path, data, digest)
        _make_old(root, source_path)
        for directory in (
            ".quarantine",
            f".quarantine/{RUN_ID}",
            f".quarantine/{RUN_ID}/frames",
        ):
            workspace.ensure_private_directory(directory)
        workspace.create_new(target_path, data, digest)
        file_ops = SecureOrphanRecoveryFileOps(workspace)
        candidate = file_ops.discover(RUN_ID, 10, 2, 128).candidates[0]

        result = file_ops.quarantine(candidate, NOW - timedelta(hours=1))

    assert result.reason_code == RecoveryReasonCode.ORPHAN_QUARANTINED
    assert not (root / Path(*source_path.split("/"))).exists()
    assert (root / Path(*target_path.split("/"))).read_bytes() == data


def test_conflicting_quarantine_target_is_typed_and_does_not_starve_later_orphan(
    tmp_path: Path,
) -> None:
    root = _new_workspace(tmp_path)
    choices: list[tuple[str, bytes, str]] = []
    for index in range(12):
        data = f"ordered-orphan-{index}".encode()
        digest = _digest(data)
        source_path = f"{RUN_ID}/frames/{digest}.png"
        choices.append((recovery_source_token(source_path), data, digest))
    ordered = sorted(choices)
    _, poison_data, poison_sha = ordered[0]
    _, healthy_data, healthy_sha = ordered[-1]
    poison_source = f"{RUN_ID}/frames/{poison_sha}.png"
    healthy_source = f"{RUN_ID}/frames/{healthy_sha}.png"
    poison_target = f".quarantine/{RUN_ID}/frames/{poison_sha}.png"
    conflict = b"preexisting-conflicting-quarantine"

    with SecureWorkspace(root, 4096) as workspace:
        _ensure_layout(workspace)
        workspace.create_new(poison_source, poison_data, poison_sha)
        workspace.create_new(healthy_source, healthy_data, healthy_sha)
        _make_old(root, poison_source)
        _make_old(root, healthy_source)
        for directory in (
            ".quarantine",
            f".quarantine/{RUN_ID}",
            f".quarantine/{RUN_ID}/frames",
        ):
            workspace.ensure_private_directory(directory)
        workspace.create_new(poison_target, conflict, _digest(conflict))

        report = OrphanRecoveryCoordinator(
            _References(set()),
            SecureOrphanRecoveryFileOps(workspace),
            max_items=10,
            max_depth=2,
            max_name_bytes=128,
        ).recover(RUN_ID, NOW, timedelta(hours=1))

    by_content = {item.content_sha256: item for item in report.items}
    assert by_content[poison_sha].reason_code == RecoveryReasonCode.CONTENT_IDENTITY_MISMATCH
    assert by_content[poison_sha].disposition == RecoveryDisposition.ANOMALY
    assert by_content[healthy_sha].reason_code == RecoveryReasonCode.ORPHAN_QUARANTINED
    assert (root / Path(*poison_source.split("/"))).read_bytes() == poison_data
    assert (root / Path(*poison_target.split("/"))).read_bytes() == conflict
    assert not (root / Path(*healthy_source.split("/"))).exists()


def test_recovery_refuses_to_enumerate_workspace_root_or_another_run(tmp_path: Path) -> None:
    root = _new_workspace(tmp_path)
    with SecureWorkspace(root, 1024) as workspace:
        with pytest.raises(PathBoundaryViolation, match="DIRECTORY_NOT_RECOVERY_SCOPED"):
            workspace.list_recovery_directory("runs", 10, 128)
        with pytest.raises(ValueError):
            SecureOrphanRecoveryFileOps(workspace).discover("../other", 10, 2, 128)

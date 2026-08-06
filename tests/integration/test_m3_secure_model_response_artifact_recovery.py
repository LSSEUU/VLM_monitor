"""Secure filesystem integration for M3 model-response artifact recovery."""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.storage.model_response_artifact_recovery import (
    SecureModelResponseArtifactRecovery,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.application.model_response_artifacts import (
    ModelResponseArtifactRecoveryCoordinator,
)
from labcourt.contracts.model_response_recovery import (
    ModelResponseRecoveryArea,
    ModelResponseRecoveryDisposition,
    ModelResponseRecoveryReason,
)

RUN_ID = "run-model-artifact-recovery-01"
AUTHORITY_A = "a" * 64
AUTHORITY_B = "b" * 64
AUTHORITY_C = "c" * 64


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    root.mkdir()
    return root


def _seed(
    workspace: SecureWorkspace,
    area: ModelResponseRecoveryArea,
    authority_id: str,
    payload: bytes,
) -> str:
    if area == ModelResponseRecoveryArea.STAGED_RESPONSE:
        operation = f".staging/{RUN_ID}/model-response-{authority_id}"
        relative = f"{operation}/response.json"
        directories = (".staging", f".staging/{RUN_ID}", operation)
    elif area == ModelResponseRecoveryArea.JOURNAL:
        operation = f".staging/{RUN_ID}/model-request-{authority_id}"
        relative = f"{operation}/receipt.json"
        directories = (".staging", f".staging/{RUN_ID}", operation)
    elif area == ModelResponseRecoveryArea.FINAL_RESPONSE:
        relative = f"{RUN_ID}/model_responses/{authority_id}.json"
        directories = (RUN_ID, f"{RUN_ID}/model_responses")
    else:
        raise AssertionError("test requires an artifact area")
    for directory in directories:
        workspace.ensure_private_directory(directory)
    workspace.create_new(relative, payload, _digest(payload))
    return relative


class _References:
    def __init__(self, referenced: set[str] | None = None) -> None:
        self.referenced = referenced or set()

    def model_response_is_referenced(
        self,
        run_id: str,
        response_id: str,
        content_sha256: str,
    ) -> bool:
        assert run_id == RUN_ID
        assert len(content_sha256) == 64
        return response_id in self.referenced


def test_discovery_reopens_staging_final_and_journal_files_with_stable_identity(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    payloads = {
        ModelResponseRecoveryArea.STAGED_RESPONSE: b'{"stage":true}',
        ModelResponseRecoveryArea.FINAL_RESPONSE: b'{"final":true}',
        ModelResponseRecoveryArea.JOURNAL: b'{"journal":true}',
    }
    with SecureWorkspace(root, 4096) as workspace:
        _seed(
            workspace,
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            AUTHORITY_A,
            payloads[ModelResponseRecoveryArea.STAGED_RESPONSE],
        )
        _seed(
            workspace,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            AUTHORITY_B,
            payloads[ModelResponseRecoveryArea.FINAL_RESPONSE],
        )
        _seed(
            workspace,
            ModelResponseRecoveryArea.JOURNAL,
            AUTHORITY_C,
            payloads[ModelResponseRecoveryArea.JOURNAL],
        )
        scan = SecureModelResponseArtifactRecovery(workspace).discover_model_response_artifacts(
            RUN_ID, 10, 255, 4096, 40_960
        )

    assert scan.complete is True
    assert scan.artifacts_scanned == 3
    assert scan.anomalies == ()
    assert {
        (candidate.area, candidate.authority_id, candidate.content_sha256)
        for candidate in scan.candidates
    } == {
        (
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            AUTHORITY_A,
            _digest(payloads[ModelResponseRecoveryArea.STAGED_RESPONSE]),
        ),
        (
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            AUTHORITY_B,
            _digest(payloads[ModelResponseRecoveryArea.FINAL_RESPONSE]),
        ),
        (
            ModelResponseRecoveryArea.JOURNAL,
            AUTHORITY_C,
            _digest(payloads[ModelResponseRecoveryArea.JOURNAL]),
        ),
    }


def test_discovery_reports_per_file_byte_excess_without_reading_or_mutating(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    payload = b"x" * 17
    with SecureWorkspace(root, 4096) as workspace:
        source = _seed(
            workspace,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            AUTHORITY_A,
            payload,
        )
        scan = SecureModelResponseArtifactRecovery(workspace).discover_model_response_artifacts(
            RUN_ID, 10, 255, 16, 160
        )

    assert scan.complete is True
    assert scan.bytes_scanned == 0
    assert scan.candidates == ()
    assert scan.artifacts_scanned == 1
    assert scan.anomalies[0].reason_code == (
        ModelResponseRecoveryReason.ARTIFACT_FILE_BYTES_EXCEEDED
    )
    assert (root / Path(*source.split("/"))).read_bytes() == payload


def test_aggregate_byte_exhaustion_is_typed_and_suppresses_all_mutation(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    first_payload = b"a" * 8
    second_payload = b"b" * 8
    with SecureWorkspace(root, 4096) as workspace:
        first = _seed(
            workspace,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            AUTHORITY_A,
            first_payload,
        )
        second = _seed(
            workspace,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            AUTHORITY_B,
            second_payload,
        )
        result = ModelResponseArtifactRecoveryCoordinator(
            _References(),
            SecureModelResponseArtifactRecovery(workspace),
            max_items=10,
            max_file_bytes=10,
            max_total_bytes=12,
        ).recover(RUN_ID, datetime.now(UTC) + timedelta(seconds=1))

    assert result.scan_complete is False
    assert result.bytes_scanned == 8
    assert result.artifacts_scanned == 2
    assert {item.reason_code for item in result.items} == {
        ModelResponseRecoveryReason.ARTIFACT_SCAN_INCOMPLETE,
        ModelResponseRecoveryReason.ARTIFACT_TOTAL_BYTES_EXHAUSTED,
    }
    assert all(
        item.disposition == ModelResponseRecoveryDisposition.RETAINED for item in result.items
    )
    assert (root / Path(*first.split("/"))).read_bytes() == first_payload
    assert (root / Path(*second.split("/"))).read_bytes() == second_payload
    assert not (root / ".quarantine").exists()


def test_discovery_budget_exhaustion_returns_incomplete_without_mutation(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    with SecureWorkspace(root, 4096) as workspace:
        first = _seed(
            workspace,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            AUTHORITY_A,
            b"first",
        )
        second = _seed(
            workspace,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            AUTHORITY_B,
            b"second",
        )
        before = {
            first: (root / first).read_bytes(),
            second: (root / second).read_bytes(),
        }
        scan = SecureModelResponseArtifactRecovery(workspace).discover_model_response_artifacts(
            RUN_ID, 1, 255, 4096, 4096
        )

    assert scan.complete is False
    assert scan.artifacts_scanned == 0
    assert (root / first).read_bytes() == before[first]
    assert (root / second).read_bytes() == before[second]


def test_unknown_child_suppresses_coordinator_mutation(tmp_path: Path) -> None:
    root = _root(tmp_path)
    response_path: str
    with SecureWorkspace(root, 4096) as workspace:
        response_path = _seed(
            workspace,
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            AUTHORITY_A,
            b"response",
        )
        operation = f".staging/{RUN_ID}/model-response-{AUTHORITY_A}"
        workspace.create_new(f"{operation}/unexpected.bin", b"unexpected", _digest(b"unexpected"))
        adapter = SecureModelResponseArtifactRecovery(workspace)
        result = ModelResponseArtifactRecoveryCoordinator(
            _References(),
            adapter,
            max_items=10,
            max_file_bytes=4096,
            max_total_bytes=40_960,
        ).recover(RUN_ID, datetime.now(UTC) + timedelta(seconds=1))

    assert result.has_anomaly is True
    assert any(
        item.reason_code == ModelResponseRecoveryReason.ORPHAN_MUTATION_SUPPRESSED
        for item in result.items
    )
    assert (root / response_path).read_bytes() == b"response"


@pytest.mark.parametrize(
    ("area", "authority_id", "area_name"),
    (
        (ModelResponseRecoveryArea.STAGED_RESPONSE, AUTHORITY_A, "staging"),
        (ModelResponseRecoveryArea.FINAL_RESPONSE, AUTHORITY_B, "final"),
        (ModelResponseRecoveryArea.JOURNAL, AUTHORITY_C, "journal"),
    ),
)
def test_quarantine_is_age_checked_and_uses_controlled_destination(
    tmp_path: Path,
    area: ModelResponseRecoveryArea,
    authority_id: str,
    area_name: str,
) -> None:
    root = _root(tmp_path)
    payload = f"{area.value}-payload".encode()
    with SecureWorkspace(root, 4096) as workspace:
        source = _seed(workspace, area, authority_id, payload)
        adapter = SecureModelResponseArtifactRecovery(workspace)
        scan = adapter.discover_model_response_artifacts(RUN_ID, 10, 255, 4096, 40_960)
        candidate = next(item for item in scan.candidates if item.area == area)

        young = adapter.quarantine_model_response_artifact(
            candidate,
            datetime.now(UTC) - timedelta(days=1),
            4096,
        )
        assert young.disposition == ModelResponseRecoveryDisposition.RETAINED
        assert young.reason_code == ModelResponseRecoveryReason.MINIMUM_AGE_NOT_MET
        assert (root / source).read_bytes() == payload

        moved = adapter.quarantine_model_response_artifact(
            candidate,
            datetime.now(UTC) + timedelta(seconds=1),
            4096,
        )

    expected = (
        f".quarantine/{RUN_ID}/model_responses/{area_name}/{authority_id}-{_digest(payload)}.json"
    )
    assert moved.disposition == ModelResponseRecoveryDisposition.QUARANTINED
    assert moved.quarantine_relative_path == expected
    assert (root / expected).read_bytes() == payload
    assert not (root / source).exists()
    if area != ModelResponseRecoveryArea.FINAL_RESPONSE:
        assert not (root / Path(*source.rsplit("/", 1)[0].split("/"))).exists()


def test_referenced_final_is_retained_while_orphan_stage_is_quarantined(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    with SecureWorkspace(root, 4096) as workspace:
        final = _seed(
            workspace,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            AUTHORITY_A,
            b"authoritative",
        )
        staged = _seed(
            workspace,
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            AUTHORITY_B,
            b"orphan",
        )
        result = ModelResponseArtifactRecoveryCoordinator(
            _References({AUTHORITY_A}),
            SecureModelResponseArtifactRecovery(workspace),
            max_items=10,
            max_file_bytes=4096,
            max_total_bytes=40_960,
        ).recover(RUN_ID, datetime.now(UTC) + timedelta(seconds=1))

    assert (root / final).read_bytes() == b"authoritative"
    assert not (root / staged).exists()
    assert not (root / Path(*staged.rsplit("/", 1)[0].split("/"))).exists()
    assert {item.reason_code for item in result.items} == {
        ModelResponseRecoveryReason.DATABASE_REFERENCED_ARTIFACT,
        ModelResponseRecoveryReason.ORPHAN_STAGE_QUARANTINED,
    }


def test_empty_response_and_journal_operations_are_age_gated_then_cleaned(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    response_operation = f".staging/{RUN_ID}/model-response-{AUTHORITY_A}"
    journal_operation = f".staging/{RUN_ID}/model-request-{AUTHORITY_B}"
    with SecureWorkspace(root, 4096) as workspace:
        for directory in (
            ".staging",
            f".staging/{RUN_ID}",
            response_operation,
            journal_operation,
        ):
            workspace.ensure_private_directory(directory)
        adapter = SecureModelResponseArtifactRecovery(workspace)
        scan = adapter.discover_model_response_artifacts(RUN_ID, 10, 255, 4096, 40_960)
        assert scan.anomalies == ()
        assert scan.candidates == ()
        assert len(scan.cleanup_candidates) == 2

        young = ModelResponseArtifactRecoveryCoordinator(
            _References(),
            adapter,
            max_items=10,
            max_file_bytes=4096,
            max_total_bytes=40_960,
        ).recover(RUN_ID, datetime.now(UTC) - timedelta(days=1))
        assert {item.reason_code for item in young.items} == {
            ModelResponseRecoveryReason.MINIMUM_AGE_NOT_MET
        }
        assert (root / Path(*response_operation.split("/"))).is_dir()
        assert (root / Path(*journal_operation.split("/"))).is_dir()

        cleaned = ModelResponseArtifactRecoveryCoordinator(
            _References(),
            adapter,
            max_items=10,
            max_file_bytes=4096,
            max_total_bytes=40_960,
        ).recover(RUN_ID, datetime.now(UTC) + timedelta(seconds=1))

    assert {item.reason_code for item in cleaned.items} == {
        ModelResponseRecoveryReason.EMPTY_OPERATION_CLEANED
    }
    assert not (root / Path(*response_operation.split("/"))).exists()
    assert not (root / Path(*journal_operation.split("/"))).exists()


def test_empty_operation_cleanup_never_recursively_deletes_a_raced_file(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    operation = f".staging/{RUN_ID}/model-response-{AUTHORITY_A}"
    raced_relative = f"{operation}/response.json"
    with SecureWorkspace(root, 4096) as workspace:
        for directory in (".staging", f".staging/{RUN_ID}", operation):
            workspace.ensure_private_directory(directory)
        adapter = SecureModelResponseArtifactRecovery(workspace)
        scan = adapter.discover_model_response_artifacts(RUN_ID, 10, 255, 4096, 40_960)
        candidate = scan.cleanup_candidates[0]
        workspace.create_new(raced_relative, b"raced", _digest(b"raced"))

        outcome = adapter.cleanup_empty_model_response_operation(
            candidate,
            datetime.now(UTC) + timedelta(seconds=1),
        )

    assert outcome.disposition == ModelResponseRecoveryDisposition.ANOMALY
    assert outcome.reason_code == (ModelResponseRecoveryReason.ENTRY_CHANGED_DURING_RECOVERY)
    assert (root / Path(*raced_relative.split("/"))).read_bytes() == b"raced"


def test_discovery_rejects_hardlinked_response_without_mutation(tmp_path: Path) -> None:
    root = _root(tmp_path)
    source_relative: str
    with SecureWorkspace(root, 4096) as workspace:
        source_relative = _seed(
            workspace,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            AUTHORITY_A,
            b"hardlinked",
        )
        alias = root / "hardlink-alias.json"
        try:
            os.link(root / Path(*source_relative.split("/")), alias)
        except (NotImplementedError, OSError) as error:
            pytest.skip(f"hardlink creation is unavailable: {error.__class__.__name__}")

        result = ModelResponseArtifactRecoveryCoordinator(
            _References(),
            SecureModelResponseArtifactRecovery(workspace),
            max_items=10,
            max_file_bytes=4096,
            max_total_bytes=40_960,
        ).recover(RUN_ID, datetime.now(UTC) + timedelta(seconds=1))

    assert result.has_anomaly is True
    assert result.items[0].reason_code == (ModelResponseRecoveryReason.UNSAFE_FILESYSTEM_ENTRY)
    assert (root / Path(*source_relative.split("/"))).read_bytes() == b"hardlinked"
    assert alias.read_bytes() == b"hardlinked"


def test_discovery_rejects_symlinked_response_without_following_it(tmp_path: Path) -> None:
    root = _root(tmp_path)
    target = root / "outside-response.json"
    target.write_bytes(b"outside")
    operation = root / ".staging" / RUN_ID / f"model-response-{AUTHORITY_A}"
    operation.mkdir(parents=True)
    try:
        os.symlink(target, operation / "response.json", target_is_directory=False)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlink creation is unavailable: {error.__class__.__name__}")

    with SecureWorkspace(root, 4096) as workspace:
        result = ModelResponseArtifactRecoveryCoordinator(
            _References(),
            SecureModelResponseArtifactRecovery(workspace),
            max_items=10,
            max_file_bytes=4096,
            max_total_bytes=40_960,
        ).recover(RUN_ID, datetime.now(UTC) + timedelta(seconds=1))

    assert result.has_anomaly is True
    assert result.items[0].reason_code == (ModelResponseRecoveryReason.UNSAFE_FILESYSTEM_ENTRY)
    assert target.read_bytes() == b"outside"
    assert (operation / "response.json").is_symlink()


def test_quarantine_reopens_and_rejects_content_changed_after_discovery(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    with SecureWorkspace(root, 4096) as workspace:
        source = _seed(
            workspace,
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            AUTHORITY_A,
            b"observed",
        )
        adapter = SecureModelResponseArtifactRecovery(workspace)
        candidate = adapter.discover_model_response_artifacts(
            RUN_ID,
            10,
            255,
            4096,
            40_960,
        ).candidates[0]
        (root / Path(*source.split("/"))).write_bytes(b"changed")

        outcome = adapter.quarantine_model_response_artifact(
            candidate,
            datetime.now(UTC) + timedelta(seconds=1),
            4096,
        )

    assert outcome.disposition == ModelResponseRecoveryDisposition.ANOMALY
    assert outcome.reason_code == (ModelResponseRecoveryReason.CONTENT_IDENTITY_MISMATCH)
    assert (root / Path(*source.split("/"))).read_bytes() == b"changed"


def test_quarantine_rechecks_exact_discovered_size_before_move(tmp_path: Path) -> None:
    root = _root(tmp_path)
    observed = b"observed"
    enlarged = observed + b"-growth"
    with SecureWorkspace(root, 4096) as workspace:
        source = _seed(
            workspace,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            AUTHORITY_A,
            observed,
        )
        adapter = SecureModelResponseArtifactRecovery(workspace)
        candidate = adapter.discover_model_response_artifacts(
            RUN_ID,
            10,
            255,
            4096,
            40_960,
        ).candidates[0]
        (root / Path(*source.split("/"))).write_bytes(enlarged)

        outcome = adapter.quarantine_model_response_artifact(
            candidate,
            datetime.now(UTC) + timedelta(seconds=1),
            4096,
        )

    assert outcome.disposition == ModelResponseRecoveryDisposition.ANOMALY
    assert outcome.reason_code == (ModelResponseRecoveryReason.ENTRY_CHANGED_DURING_RECOVERY)
    assert (root / Path(*source.split("/"))).read_bytes() == enlarged


def test_quarantine_rejects_hardlink_added_after_discovery(tmp_path: Path) -> None:
    root = _root(tmp_path)
    with SecureWorkspace(root, 4096) as workspace:
        source = _seed(
            workspace,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            AUTHORITY_A,
            b"observed",
        )
        adapter = SecureModelResponseArtifactRecovery(workspace)
        candidate = adapter.discover_model_response_artifacts(
            RUN_ID,
            10,
            255,
            4096,
            40_960,
        ).candidates[0]
        alias = root / "late-hardlink.json"
        try:
            os.link(root / Path(*source.split("/")), alias)
        except (NotImplementedError, OSError) as error:
            pytest.skip(f"hardlink creation is unavailable: {error.__class__.__name__}")

        outcome = adapter.quarantine_model_response_artifact(
            candidate,
            datetime.now(UTC) + timedelta(seconds=1),
            4096,
        )

    assert outcome.disposition == ModelResponseRecoveryDisposition.ANOMALY
    assert outcome.reason_code == (ModelResponseRecoveryReason.UNSAFE_FILESYSTEM_ENTRY)
    assert (root / Path(*source.split("/"))).read_bytes() == b"observed"
    assert alias.read_bytes() == b"observed"


def test_quarantine_rejects_symlink_replacement_after_discovery(tmp_path: Path) -> None:
    root = _root(tmp_path)
    target = root / "replacement-target.json"
    target.write_bytes(b"outside")
    with SecureWorkspace(root, 4096) as workspace:
        source = _seed(
            workspace,
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            AUTHORITY_A,
            b"observed",
        )
        adapter = SecureModelResponseArtifactRecovery(workspace)
        candidate = adapter.discover_model_response_artifacts(
            RUN_ID,
            10,
            255,
            4096,
            40_960,
        ).candidates[0]
        source_path = root / Path(*source.split("/"))
        source_path.unlink()
        try:
            os.symlink(target, source_path, target_is_directory=False)
        except (NotImplementedError, OSError) as error:
            pytest.skip(f"symlink creation is unavailable: {error.__class__.__name__}")

        outcome = adapter.quarantine_model_response_artifact(
            candidate,
            datetime.now(UTC) + timedelta(seconds=1),
            4096,
        )

    assert outcome.disposition == ModelResponseRecoveryDisposition.ANOMALY
    assert outcome.reason_code == (ModelResponseRecoveryReason.UNSAFE_FILESYSTEM_ENTRY)
    assert target.read_bytes() == b"outside"
    assert source_path.is_symlink()


def test_quarantine_rejects_a_symlinked_quarantine_root(tmp_path: Path) -> None:
    root = _root(tmp_path)
    outside = tmp_path / "outside-quarantine"
    outside.mkdir()
    try:
        os.symlink(outside, root / ".quarantine", target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlink creation is unavailable: {error.__class__.__name__}")

    with SecureWorkspace(root, 4096) as workspace:
        source = _seed(
            workspace,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            AUTHORITY_A,
            b"orphan",
        )
        adapter = SecureModelResponseArtifactRecovery(workspace)
        candidate = adapter.discover_model_response_artifacts(
            RUN_ID,
            10,
            255,
            4096,
            40_960,
        ).candidates[0]
        outcome = adapter.quarantine_model_response_artifact(
            candidate,
            datetime.now(UTC) + timedelta(seconds=1),
            4096,
        )

    assert outcome.disposition == ModelResponseRecoveryDisposition.ANOMALY
    assert outcome.reason_code == (ModelResponseRecoveryReason.UNSAFE_FILESYSTEM_ENTRY)
    assert (root / Path(*source.split("/"))).read_bytes() == b"orphan"
    assert tuple(outside.iterdir()) == ()


def test_quarantine_rejects_a_symlinked_existing_destination(tmp_path: Path) -> None:
    root = _root(tmp_path)
    payload = b"orphan"
    digest = _digest(payload)
    destination = f".quarantine/{RUN_ID}/model_responses/final/{AUTHORITY_A}-{digest}.json"
    target = root / "destination-target.json"
    target.write_bytes(payload)
    with SecureWorkspace(root, 4096) as workspace:
        source = _seed(
            workspace,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            AUTHORITY_A,
            payload,
        )
        for directory in (
            ".quarantine",
            f".quarantine/{RUN_ID}",
            f".quarantine/{RUN_ID}/model_responses",
            f".quarantine/{RUN_ID}/model_responses/final",
        ):
            workspace.ensure_private_directory(directory)
        try:
            os.symlink(
                target,
                root / Path(*destination.split("/")),
                target_is_directory=False,
            )
        except (NotImplementedError, OSError) as error:
            pytest.skip(f"symlink creation is unavailable: {error.__class__.__name__}")
        adapter = SecureModelResponseArtifactRecovery(workspace)
        candidate = adapter.discover_model_response_artifacts(
            RUN_ID,
            10,
            255,
            4096,
            40_960,
        ).candidates[0]
        outcome = adapter.quarantine_model_response_artifact(
            candidate,
            datetime.now(UTC) + timedelta(seconds=1),
            4096,
        )

    assert outcome.disposition == ModelResponseRecoveryDisposition.ANOMALY
    assert outcome.reason_code in {
        ModelResponseRecoveryReason.RESPONSE_CONFLICT,
        ModelResponseRecoveryReason.UNSAFE_FILESYSTEM_ENTRY,
    }
    assert (root / Path(*source.split("/"))).read_bytes() == payload
    assert target.read_bytes() == payload


def test_staging_root_budget_exhaustion_is_incomplete_and_read_only(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    operations = (
        f".staging/{RUN_ID}/model-response-{AUTHORITY_A}",
        f".staging/{RUN_ID}/model-response-{AUTHORITY_B}",
    )
    with SecureWorkspace(root, 4096) as workspace:
        for directory in (".staging", f".staging/{RUN_ID}", *operations):
            workspace.ensure_private_directory(directory)
        scan = SecureModelResponseArtifactRecovery(workspace).discover_model_response_artifacts(
            RUN_ID, 1, 255, 4096, 4096
        )

    assert scan.complete is False
    assert scan.artifacts_scanned == 0
    assert all((root / Path(*operation.split("/"))).is_dir() for operation in operations)


def test_nested_operation_budget_exhaustion_is_incomplete_and_read_only(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    operation = f".staging/{RUN_ID}/model-response-{AUTHORITY_A}"
    response = f"{operation}/response.json"
    unexpected = f"{operation}/unexpected.bin"
    with SecureWorkspace(root, 4096) as workspace:
        for directory in (".staging", f".staging/{RUN_ID}", operation):
            workspace.ensure_private_directory(directory)
        workspace.create_new(response, b"response", _digest(b"response"))
        workspace.create_new(unexpected, b"unexpected", _digest(b"unexpected"))
        scan = SecureModelResponseArtifactRecovery(workspace).discover_model_response_artifacts(
            RUN_ID, 1, 255, 4096, 4096
        )

    assert scan.complete is False
    assert scan.artifacts_scanned == 0
    assert (root / Path(*response.split("/"))).read_bytes() == b"response"
    assert (root / Path(*unexpected.split("/"))).read_bytes() == b"unexpected"

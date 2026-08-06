from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

import labcourt.adapters.storage.readonly_m5_artifacts as readonly_module
from labcourt.adapters.storage.readonly_m5_artifacts import (
    M5AuthorityBudgetExceeded,
    ReadonlyM5ArtifactRepository,
)
from labcourt.adapters.storage.readonly_sqlite import ReadOnlySnapshotError
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.cli import app
from labcourt.contracts.m5_artifact_validation import (
    M5ArtifactValidationBudget,
    M5ArtifactValidationIssueCode,
    M5ArtifactValidationReport,
)
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.manifests import RunManifest
from labcourt.services.m5_artifact_validation import validate_m5_snapshot
from tests.integration.test_m5_sqlite_precedents import (
    BUSY_TIMEOUT_MS,
    ROOT,
    RUN_ID,
    _clock,
    _config,
    _install,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _insert_immediate_documents(
    database: Path,
    manifest_id: str,
    documents: tuple[str, ...],
) -> None:
    trigger = "m5_immediate_safety_deliveries_reject_uncertified_insert"
    with sqlite3.connect(database) as connection:
        trigger_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
            (trigger,),
        ).fetchone()
        assert trigger_row is not None and isinstance(trigger_row[0], str)
        connection.execute(f'DROP TRIGGER "{trigger}"')
        for index, document in enumerate(documents):
            incident_id = f"budget-incident-{index}"
            connection.execute(
                """
                INSERT INTO m5_immediate_safety_deliveries(
                    run_id, authority_id, incident_id, signal_id, zone_id,
                    delivery_idempotency_key, delivery_alert_id, delivery_channel,
                    provider_receipt_ref, manifest_id, authority_json, document_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    RUN_ID,
                    _sha(f"authority-{index}"),
                    incident_id,
                    f"signal-{index}",
                    "zone-a",
                    incident_id,
                    incident_id,
                    "fake",
                    None,
                    manifest_id,
                    document,
                    _sha(document),
                ),
            )
        connection.execute(trigger_row[0])


def _insert_capability_root(database: Path, manifest_id: str, config_sha256: str) -> None:
    document = "{}"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO alert_channel_capabilities(
                run_id, capability_id, channel, capability_revision,
                idempotency_guarantee, provider_idempotency_key,
                manifest_id, config_sha256, authority_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                RUN_ID,
                _sha("capability-only"),
                "capability-only-channel",
                "revision-1",
                "NONE",
                None,
                manifest_id,
                config_sha256,
                document,
                _sha(document),
            ),
        )


def _insert_dataset_root(database: Path, manifest: RunManifest) -> None:
    document = "{}"
    with sqlite3.connect(database) as connection:
        trigger = "dataset_artifacts_validate_registration_snapshot"
        trigger_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
            (trigger,),
        ).fetchone()
        assert trigger_row is not None and isinstance(trigger_row[0], str)
        connection.execute(f'DROP TRIGGER "{trigger}"')
        connection.execute(
            """
            INSERT INTO dataset_artifacts(
                run_id, dataset_id, report_id, command_id, format, relative_path,
                content_sha256, content_size_bytes, label_count, minimum_quality,
                rule_version, detector_manifest_id, manifest_id,
                registration_snapshot_authority_id,
                artifact_json, report_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                RUN_ID,
                "dataset-only",
                _sha("dataset-report"),
                _sha("dataset-command"),
                "COCO",
                "exports/dataset-only.json",
                _sha("dataset-content"),
                0,
                0,
                "HUMAN_CONFIRMED",
                manifest.rule_version,
                manifest.models["detector"].model_manifest_id,
                manifest.manifest_id,
                _sha("dataset-snapshot"),
                document,
                document,
                _sha(document),
            ),
        )
        connection.execute(trigger_row[0])


def _insert_orphan_m5_retention_hold(
    database: Path,
    manifest_id: str,
    owner_kind: str,
) -> None:
    document = "{}"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO retention_holds(
                run_id, hold_id, target_kind, target_id, hold_kind,
                owner_kind, owner_id, active, manifest_id, policy_version,
                reason_code, hold_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                RUN_ID,
                f"orphan-{owner_kind.lower()}-hold",
                "MEDIA",
                f"missing-{owner_kind.lower()}-target",
                "APPEAL" if owner_kind == "APPEAL" else "GOLD_SET",
                owner_kind,
                f"missing-{owner_kind.lower()}-owner",
                1,
                manifest_id,
                "retention-v1",
                "M5_OWNER_MISSING",
                document,
                _sha(document),
            ),
        )


@pytest.mark.parametrize(
    ("documents", "budget", "expected_code"),
    (
        (
            ('{"row":0}', '{"row":1}'),
            M5ArtifactValidationBudget(
                max_authority_records=1,
                max_authority_record_bytes=1024,
                max_authority_total_bytes=4096,
            ),
            M5ArtifactValidationIssueCode.AUTHORITY_RECORD_COUNT_BUDGET_EXCEEDED,
        ),
        (
            (json.dumps({"padding": "x" * 512}, separators=(",", ":")),),
            M5ArtifactValidationBudget(
                max_authority_records=10,
                max_authority_record_bytes=128,
                max_authority_total_bytes=4096,
            ),
            M5ArtifactValidationIssueCode.AUTHORITY_RECORD_BYTES_BUDGET_EXCEEDED,
        ),
        (
            (
                json.dumps({"padding": "x" * 96}, separators=(",", ":")),
                json.dumps({"padding": "y" * 96}, separators=(",", ":")),
            ),
            M5ArtifactValidationBudget(
                max_authority_records=10,
                max_authority_record_bytes=1024,
                max_authority_total_bytes=128,
            ),
            M5ArtifactValidationIssueCode.AUTHORITY_TOTAL_BYTES_BUDGET_EXCEEDED,
        ),
    ),
)
def test_sql_budget_preflight_rejects_before_json_decode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    documents: tuple[str, ...],
    budget: M5ArtifactValidationBudget,
    expected_code: M5ArtifactValidationIssueCode,
) -> None:
    database, _, manifest = _install(tmp_path)
    config = _config()
    _insert_immediate_documents(database, manifest.manifest_id, documents)
    decode_calls = 0

    def forbidden_decode(*args: object, **kwargs: object) -> object:
        nonlocal decode_calls
        del args, kwargs
        decode_calls += 1
        raise AssertionError("authority JSON was decoded before SQL budget rejection")

    monkeypatch.setattr(readonly_module, "load_m5_record", forbidden_decode)
    repository = ReadonlyM5ArtifactRepository(database, config=config, budget=budget)
    with pytest.raises(M5AuthorityBudgetExceeded) as captured:
        repository.scan(RUN_ID)

    assert decode_calls == 0
    assert expected_code in captured.value.issue_codes
    report = validate_m5_snapshot(
        config=config,
        run_id=RUN_ID,
        snapshot_path=database,
        workspace_root=tmp_path,
        budget=budget,
    )
    assert report is not None
    assert decode_calls == 0
    assert report.counts.validated_authority_documents == 0
    assert report.counts.projection_files == 0
    assert {issue.code for issue in report.issues} == set(captured.value.issue_codes)


def test_readonly_root_revalidates_full_configured_model_binding(tmp_path: Path) -> None:
    database, _, manifest = _install(tmp_path)
    config = _config()
    models = dict(manifest.models)
    models["screening"] = models["screening"].model_copy(update={"model": "foreign-model"})
    foreign_manifest = RunManifest.model_validate(
        manifest.model_copy(update={"models": models}).model_dump(mode="json")
    )
    assert foreign_manifest.config_sha256 == config.config_sha256
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS, clock=_clock).register_run(
        "model-mismatch-run",
        foreign_manifest,
    )

    with pytest.raises(ReadOnlySnapshotError) as captured:
        ReadonlyM5ArtifactRepository(database, config=config).preflight("model-mismatch-run")

    assert captured.value.reason_code == "CONFIG_MANIFEST_MISMATCH"


@pytest.mark.parametrize(
    "authority_kind",
    (
        M5AuthorityKind.ALERT_CHANNEL_CAPABILITY,
        M5AuthorityKind.IMMEDIATE_SAFETY_DELIVERY,
        M5AuthorityKind.DATASET_ARTIFACT,
    ),
)
def test_every_durable_m5_root_makes_validation_applicable(
    tmp_path: Path,
    authority_kind: M5AuthorityKind,
) -> None:
    database, _, manifest = _install(tmp_path)
    config = _config()
    if authority_kind == M5AuthorityKind.ALERT_CHANNEL_CAPABILITY:
        _insert_capability_root(database, manifest.manifest_id, config.config_sha256)
    elif authority_kind == M5AuthorityKind.IMMEDIATE_SAFETY_DELIVERY:
        _insert_immediate_documents(database, manifest.manifest_id, ("{}",))
    else:
        _insert_dataset_root(database, manifest)

    repository = ReadonlyM5ArtifactRepository(database, config=config)
    assert repository.has_authority(RUN_ID) is True
    preflight = repository.preflight(RUN_ID)
    inventory = {item.authority_kind: item.count for item in preflight.traversed}
    assert preflight.authority_rows == 1
    assert inventory[authority_kind] == 1


@pytest.mark.parametrize("owner_kind", ("APPEAL", "DATASET"))
def test_orphan_m5_owned_retention_hold_cannot_skip_m5_validation(
    tmp_path: Path,
    owner_kind: str,
) -> None:
    database, _, manifest = _install(tmp_path)
    _insert_orphan_m5_retention_hold(database, manifest.manifest_id, owner_kind)

    repository = ReadonlyM5ArtifactRepository(database, config=_config())
    assert repository.has_authority(RUN_ID) is True
    assert repository.preflight(RUN_ID).authority_rows == 0


def test_standard_artifacts_validate_routes_capability_only_run_through_m5(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "runs"
    workspace.mkdir()
    database, _, manifest = _install(workspace)
    config = _config()
    _insert_capability_root(database, manifest.manifest_id, config.config_sha256)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(
        app,
        (
            "artifacts",
            "validate",
            "--run-id",
            RUN_ID,
            "--config",
            str(ROOT / "configs" / "demo.yaml"),
            "--json",
        ),
    )

    assert result.exit_code == 1, result.stdout
    report = M5ArtifactValidationReport.model_validate_json(result.stdout)
    assert report.predecessor_report is not None
    inventory = {
        item.authority_kind: item.authoritative_count for item in report.counts.inventories
    }
    assert inventory[M5AuthorityKind.ALERT_CHANNEL_CAPABILITY] == 1

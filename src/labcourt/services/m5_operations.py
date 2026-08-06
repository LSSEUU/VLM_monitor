"""Composition root for bounded offline M5 close and alert-dispatch operations."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from labcourt.adapters.fake_alert_channel import DeterministicFakeAlertChannel
from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.m5_precedent_jsonl import (
    MAX_M5_IMPORT_ENTRIES,
    MAX_M5_IMPORT_FILE_BYTES,
    MAX_M5_IMPORT_LINE_BYTES,
    load_m5_precedent_jsonl,
)
from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.application.alert_policy_verifier import ConfiguredAlertPolicyVerifier
from labcourt.application.automatic_precedent_verifier import (
    ConfiguredAutomaticPrecedentVerifier,
)
from labcourt.application.m5_dispatch import dispatch_pending_alerts
from labcourt.application.m5_finalization import M5FinalizationCoordinator
from labcourt.application.m5_precedent_operations import (
    activate_m5_precedents,
    import_m5_precedent_authorities,
    reconcile_m5_precedent_conflicts,
)
from labcourt.application.m5_precedent_policy_verifier import (
    ConfiguredM5PrecedentPolicyVerifier,
)
from labcourt.application.m5_precedent_usage_verifier import (
    ConfiguredM5PrecedentApplicationVerifier,
)
from labcourt.application.m5_precedents import m5_precedent_policy_from_config
from labcourt.contracts.alert_policy import AlertChannelCapabilityAuthority
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m5_operations import (
    M5DispatchCommandReport,
    M5FinalizeCommandReport,
    M5PrecedentActivationCommandReport,
    M5PrecedentConflictCommandReport,
    M5PrecedentImportReport,
)
from labcourt.contracts.m5_precedents import MAX_M5_PRECEDENTS, M5PrecedentAuthority
from labcourt.exceptions import ContractViolation, ManifestMismatch
from labcourt.ports.alerts import AlertChannel


def _controlled_paths(
    *,
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
) -> tuple[Path, Path]:
    if not isinstance(config, AppConfig):
        raise TypeError("config must be an AppConfig")
    supplied_root = Path(workspace_root)
    supplied_database = Path(database_path)
    if ".." in supplied_root.parts or ".." in supplied_database.parts:
        raise ValueError("M5 operation paths cannot contain parent traversal")
    root = supplied_root.absolute()
    database = supplied_database.absolute()
    expected = root / config.storage.database_filename
    if database != expected or database.parent != root:
        raise ValueError("database_path must be the configured authority inside workspace_root")
    return root, database


def _require_import_budget(value: int, maximum: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ContractViolation(f"{name} must be an integer in [1, {maximum}]")
    return value


def finalize_m5_run(
    *,
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
    run_id: str,
    limit: int = 256,
    clock: Callable[[], datetime] | None = None,
) -> M5FinalizeCommandReport:
    """Close one bounded READY batch using only local deterministic adapters."""

    _, database = _controlled_paths(
        config=config,
        workspace_root=workspace_root,
        database_path=database_path,
    )
    operation_time = clock() if clock is not None else datetime.now(UTC)

    def operation_clock() -> datetime:
        return operation_time

    evidence = SQLiteEvidenceRepository(database, config.storage.busy_timeout_ms)
    manifest = evidence.load_run_manifest(run_id)
    alert_verifier = ConfiguredAlertPolicyVerifier(config)
    embedding_provider = DeterministicFakePrecedentEmbeddingProvider()
    automatic_verifier = ConfiguredAutomaticPrecedentVerifier(config, embedding_provider)
    precedent_policy_verifier = ConfiguredM5PrecedentPolicyVerifier(config)
    repository = SQLiteM5Repository(
        database,
        config.storage.busy_timeout_ms,
        clock=operation_clock,
        alert_policy_verifier=alert_verifier,
        automatic_precedent_verifier=automatic_verifier,
        m5_precedent_policy_verifier=precedent_policy_verifier,
        m5_precedent_application_verifier=ConfiguredM5PrecedentApplicationVerifier(config),
    )
    return M5FinalizationCoordinator(
        repository=repository,
        verifier=alert_verifier,
        embedding_provider=embedding_provider,
        config=config,
        manifest=manifest,
        clock=operation_clock,
    ).finalize(run_id, limit=limit)


def dispatch_m5_alerts(
    *,
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
    run_id: str,
    worker_id: str,
    limit: int = 256,
    channel: AlertChannel | None = None,
) -> M5DispatchCommandReport:
    """Dispatch one bounded pending batch with restart-safe SQLite receipts."""

    _, database = _controlled_paths(
        config=config,
        workspace_root=workspace_root,
        database_path=database_path,
    )
    evidence = SQLiteEvidenceRepository(database, config.storage.busy_timeout_ms)
    manifest = evidence.load_run_manifest(run_id)
    if manifest.config_sha256 != config.config_sha256:
        raise ManifestMismatch("M5 dispatch config differs from the run manifest")
    selected_channel = channel if channel is not None else DeterministicFakeAlertChannel()
    capability_factory = getattr(selected_channel, "capability_authority", None)
    if not callable(capability_factory):
        raise TypeError("alert channel must generate a scoped capability authority")
    channel_capability = capability_factory(
        run_id=run_id,
        manifest_id=manifest.manifest_id,
        config_sha256=manifest.config_sha256,
    )
    if not isinstance(channel_capability, AlertChannelCapabilityAuthority):
        raise ContractViolation("alert channel returned an invalid capability authority")
    if (
        channel_capability.run_id != run_id
        or channel_capability.manifest_id != manifest.manifest_id
        or channel_capability.config_sha256 != manifest.config_sha256
    ):
        raise ManifestMismatch(
            "alert channel capability differs from the selected run manifest/config"
        )
    repository = SQLiteM5Repository(
        database,
        config.storage.busy_timeout_ms,
        alert_channel_capability=channel_capability,
    )
    return dispatch_pending_alerts(
        outbox=repository,
        cases=evidence,
        channel=selected_channel,
        channel_capability=channel_capability,
        run_id=run_id,
        worker_id=worker_id,
        limit=limit,
    )


def import_m5_precedent_file(
    *,
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
    run_id: str,
    source_path: str | Path,
    max_file_bytes: int = MAX_M5_IMPORT_FILE_BYTES,
    max_line_bytes: int = MAX_M5_IMPORT_LINE_BYTES,
    max_entries: int = MAX_M5_PRECEDENTS,
) -> M5PrecedentImportReport:
    """Strictly validate and append an offline JSONL batch of authored precedents."""

    _, database = _controlled_paths(
        config=config,
        workspace_root=workspace_root,
        database_path=database_path,
    )
    records = load_m5_precedent_jsonl(
        Path(source_path),
        max_file_bytes=_require_import_budget(
            max_file_bytes,
            MAX_M5_IMPORT_FILE_BYTES,
            "M5 import max_file_bytes",
        ),
        max_line_bytes=_require_import_budget(
            max_line_bytes,
            MAX_M5_IMPORT_LINE_BYTES,
            "M5 import max_line_bytes",
        ),
        max_entries=_require_import_budget(
            max_entries,
            MAX_M5_IMPORT_ENTRIES,
            "M5 import max_entries",
        ),
    )
    try:
        authorities = tuple(M5PrecedentAuthority.model_validate(item) for item in records)
    except ValidationError as exc:
        raise ContractViolation("M5 precedent JSONL contains an invalid authority") from exc
    repository = SQLiteM5Repository(
        database,
        config.storage.busy_timeout_ms,
        m5_precedent_policy_verifier=ConfiguredM5PrecedentPolicyVerifier(config),
    )
    return import_m5_precedent_authorities(
        repository=repository,
        run_id=run_id,
        authorities=authorities,
    )


def activate_m5_precedents_for_run(
    *,
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
    run_id: str,
    limit: int = MAX_M5_PRECEDENTS,
    clock: Callable[[], datetime] | None = None,
) -> M5PrecedentActivationCommandReport:
    """Evaluate one bounded due batch using a single controlled operation time."""

    _, database = _controlled_paths(
        config=config,
        workspace_root=workspace_root,
        database_path=database_path,
    )
    evaluated_at = clock() if clock is not None else datetime.now(UTC)

    def operation_clock() -> datetime:
        return evaluated_at

    repository = SQLiteM5Repository(
        database,
        config.storage.busy_timeout_ms,
        clock=operation_clock,
        m5_precedent_policy_verifier=ConfiguredM5PrecedentPolicyVerifier(config),
    )
    return activate_m5_precedents(
        repository=repository,
        run_id=run_id,
        evaluated_at=evaluated_at,
        limit=limit,
    )


def reconcile_m5_precedents_for_run(
    *,
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
    run_id: str,
    limit: int = MAX_M5_PRECEDENTS,
) -> M5PrecedentConflictCommandReport:
    """Exact-compare active authored precedents and persist conflict governance."""

    _, database = _controlled_paths(
        config=config,
        workspace_root=workspace_root,
        database_path=database_path,
    )
    manifest = SQLiteEvidenceRepository(
        database,
        config.storage.busy_timeout_ms,
    ).load_run_manifest(run_id)
    if manifest.config_sha256 != config.config_sha256:
        raise ManifestMismatch("M5 conflict config differs from the run manifest")
    repository = SQLiteM5Repository(
        database,
        config.storage.busy_timeout_ms,
        m5_precedent_policy_verifier=ConfiguredM5PrecedentPolicyVerifier(config),
    )
    return reconcile_m5_precedent_conflicts(
        repository=repository,
        run_id=run_id,
        policy=m5_precedent_policy_from_config(config),
        limit=limit,
    )


__all__ = [
    "MAX_M5_IMPORT_FILE_BYTES",
    "MAX_M5_IMPORT_LINE_BYTES",
    "activate_m5_precedents_for_run",
    "dispatch_m5_alerts",
    "finalize_m5_run",
    "import_m5_precedent_file",
    "reconcile_m5_precedents_for_run",
]

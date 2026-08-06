"""Offline composition root for bounded M2/M3 maintenance recovery."""

from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path

from labcourt.adapters.storage.model_response_artifact_recovery import (
    SecureModelResponseArtifactRecovery,
)
from labcourt.adapters.storage.model_response_store import SecureModelResponseStore
from labcourt.adapters.storage.secure_recovery import SecureOrphanRecoveryFileOps
from labcourt.adapters.storage.secure_retention import SecureRetentionFileOps
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_m3_repository import SQLiteM3Repository
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.application.maintenance_recovery import (
    MaintenanceRecoveryCoordinator,
    ModelResponseStartupRecoveryCoordinator,
)
from labcourt.application.model_response_artifacts import (
    ModelResponseArtifactRecoveryCoordinator,
)
from labcourt.application.model_response_recovery import (
    MAX_MODEL_CALL_RECOVERY_ITEMS,
    ModelCallRecoveryCoordinator,
)
from labcourt.application.recovery import OrphanRecoveryCoordinator, StartupRecoveryCoordinator
from labcourt.application.retention import RetentionCoordinator
from labcourt.contracts.model_response_recovery import (
    MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
    MAX_MODEL_RESPONSE_RECOVERY_ITEMS,
    MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
)
from labcourt.ports.model_response_recovery import ModelResponseRecoveryIdentity


class _IdentityBoundRecoveryFence:
    """Expose only the writer fence plus an opaque composition identity."""

    __slots__ = ("_delegate", "_recovery_identity")

    def __init__(
        self,
        delegate: SQLiteM3Repository,
        recovery_identity: ModelResponseRecoveryIdentity,
    ) -> None:
        self._delegate = delegate
        self._recovery_identity = recovery_identity

    @property
    def recovery_identity(self) -> ModelResponseRecoveryIdentity:
        return self._recovery_identity

    def model_response_artifact_recovery_fence(
        self,
        run_id: str,
    ) -> AbstractContextManager[None]:
        return self._delegate.model_response_artifact_recovery_fence(run_id)


def build_maintenance_recovery_coordinator(
    *,
    database_path: str | Path,
    busy_timeout_ms: int,
    workspace: SecureWorkspace,
    storage_repository: SQLiteEvidenceRepository,
    max_items: int,
    max_claim_items: int = MAX_MODEL_CALL_RECOVERY_ITEMS,
    max_response_bytes: int = MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
) -> MaintenanceRecoveryCoordinator:
    """Build provider-free recovery over one shared M3 SQLite authority.

    This composition root deliberately has no provider, transport, prompt, or
    model-client input. Recovery only reads durable SQLite claims and exact
    SecureWorkspace artifacts; an expired journaled claim may complete its
    existing T1 receipt but can never make a new external model call.
    """

    if not isinstance(workspace, SecureWorkspace):
        raise TypeError("workspace must be a SecureWorkspace")
    if not isinstance(storage_repository, SQLiteEvidenceRepository):
        raise TypeError("storage_repository must be a SQLiteEvidenceRepository")
    if (
        not isinstance(max_items, int)
        or isinstance(max_items, bool)
        or not 1 <= max_items <= MAX_MODEL_RESPONSE_RECOVERY_ITEMS
    ):
        raise ValueError(
            f"max_items must be an integer from 1 through {MAX_MODEL_RESPONSE_RECOVERY_ITEMS}"
        )
    if (
        not isinstance(max_response_bytes, int)
        or isinstance(max_response_bytes, bool)
        or not 1 <= max_response_bytes <= MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES
    ):
        raise ValueError(
            "max_response_bytes must be an integer from 1 through "
            f"{MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES}"
        )
    if (
        not isinstance(max_claim_items, int)
        or isinstance(max_claim_items, bool)
        or not 1 <= max_claim_items <= MAX_MODEL_CALL_RECOVERY_ITEMS
    ):
        raise ValueError(
            f"max_claim_items must be an integer from 1 through {MAX_MODEL_CALL_RECOVERY_ITEMS}"
        )
    max_total_bytes = min(
        max_items * max_response_bytes,
        MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
    )

    response_store = SecureModelResponseStore(workspace)
    recovery_identity = ModelResponseRecoveryIdentity()
    response_repository = SQLiteM3Repository(
        database_path,
        busy_timeout_ms,
        raw_response_verifier=response_store,
    )
    model_calls = ModelCallRecoveryCoordinator(
        response_repository,
        response_store,
        limit=max_claim_items,
        recovery_identity=recovery_identity,
    )
    response_artifacts = ModelResponseArtifactRecoveryCoordinator(
        response_repository,
        SecureModelResponseArtifactRecovery(workspace),
        max_items=max_items,
        max_file_bytes=max_response_bytes,
        max_total_bytes=max_total_bytes,
        recovery_identity=recovery_identity,
    )
    recovery_fence = _IdentityBoundRecoveryFence(
        response_repository,
        recovery_identity,
    )
    model_responses = ModelResponseStartupRecoveryCoordinator(
        claims=model_calls,
        artifacts=response_artifacts,
        fence=recovery_fence,
        claim_limit=max_claim_items,
        artifact_limit=max_items,
        artifact_file_bytes_limit=max_response_bytes,
        artifact_total_bytes_limit=max_total_bytes,
    )
    storage = StartupRecoveryCoordinator(
        retention=RetentionCoordinator(
            repository=storage_repository,
            file_ops=SecureRetentionFileOps(workspace),
            max_items=max_items,
        ),
        orphan=OrphanRecoveryCoordinator(
            repository=storage_repository,
            file_ops=SecureOrphanRecoveryFileOps(workspace),
            max_items=max_items,
        ),
    )
    return MaintenanceRecoveryCoordinator(
        storage=storage,
        model_responses=model_responses,
    )


__all__ = ["build_maintenance_recovery_coordinator"]

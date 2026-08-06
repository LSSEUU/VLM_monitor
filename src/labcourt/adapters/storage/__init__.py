"""Secure storage, SQLite authority, and rebuildable JSON projections."""

from labcourt.adapters.storage.hearing_model_response_store import (
    SecureHearingModelResponseStore,
)
from labcourt.adapters.storage.hearing_response_cache import (
    ImmutableHearingVLMResponseCache,
)
from labcourt.adapters.storage.json_projector import (
    JsonProjector,
    ProjectionFailure,
    ProjectionResult,
)
from labcourt.adapters.storage.model_response_artifact_recovery import (
    SecureModelResponseArtifactRecovery,
)
from labcourt.adapters.storage.model_response_store import (
    ModelResponseStoreError,
    ModelResponseStoreFailureCode,
    SecureModelResponseStore,
)
from labcourt.adapters.storage.readonly_m3_artifacts import (
    M3ArtifactAuthorityFailure,
    M3ArtifactAuthoritySnapshot,
    M3AuthorityFailureType,
    M3TraversedInventory,
    M3ValidatedModelCacheEntry,
    M3ValidatedModelCallFailureAuthority,
    M3ValidatedModelCallRequest,
    M3ValidatedModelParseReceipt,
    M3ValidatedParsedScreeningOutput,
    M3ValidatedRawResponse,
    ReadonlyM3ArtifactRepository,
)
from labcourt.adapters.storage.readonly_sqlite import (
    DEFAULT_MAX_DATABASE_BYTES,
    ReadOnlySnapshotError,
    SnapshotRunCounts,
    readonly_sqlite_snapshot,
    snapshot_contains_run,
    snapshot_run_counts,
)
from labcourt.adapters.storage.secure_recovery import SecureOrphanRecoveryFileOps
from labcourt.adapters.storage.secure_retention import SecureRetentionFileOps
from labcourt.adapters.storage.secure_workspace import (
    SecureDeletionReceipt,
    SecureDirectoryHint,
    SecureFileMetadata,
    SecureFileSnapshot,
    SecureVideoInput,
    SecureWorkspace,
    create_owner_only_directory,
    require_owner_only_directory,
)
from labcourt.adapters.storage.sqlite_authority import (
    SQLITE_AUTHORITY_FILENAME,
    SQLiteAuthorityError,
    SQLiteAuthorityGuard,
)
from labcourt.adapters.storage.sqlite_hearing_recovery import (
    SQLiteHearingModelCallRecoveryRepository,
)
from labcourt.adapters.storage.sqlite_hearing_repository import SQLiteHearingRepository
from labcourt.adapters.storage.sqlite_m3_repository import (
    SQLiteM3Repository,
    m3_root_document_sha256,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger import (
    SQLiteM6UpgradeExecutionLedgerRepository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v2 import (
    SQLiteM6UpgradeExecutionLedgerV2Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_observation import (
    SQLiteM6UpgradeExecutionObservationRepository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_pending_sample_commitment import (
    SQLiteM6UpgradePendingSampleCommitmentRepository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_whole_sample_record_builder import (
    SQLiteM6UpgradeWholeSampleRecordBuilder,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationIntegrityError,
    MigrationRunner,
    RepositoryIntegrityError,
    SQLiteEvidenceRepository,
)
from labcourt.ports.hearing_vlm import (
    HearingModelResponseStoreError,
    HearingModelResponseStoreFailureCode,
)
from labcourt.ports.screening_repository import M3CaseCommit

__all__ = [
    "DEFAULT_MAX_DATABASE_BYTES",
    "SQLITE_AUTHORITY_FILENAME",
    "HearingModelResponseStoreError",
    "HearingModelResponseStoreFailureCode",
    "ImmutableHearingVLMResponseCache",
    "JsonProjector",
    "M3ArtifactAuthorityFailure",
    "M3ArtifactAuthoritySnapshot",
    "M3AuthorityFailureType",
    "M3CaseCommit",
    "M3TraversedInventory",
    "M3ValidatedModelCacheEntry",
    "M3ValidatedModelCallFailureAuthority",
    "M3ValidatedModelCallRequest",
    "M3ValidatedModelParseReceipt",
    "M3ValidatedParsedScreeningOutput",
    "M3ValidatedRawResponse",
    "MigrationIntegrityError",
    "MigrationRunner",
    "ModelResponseStoreError",
    "ModelResponseStoreFailureCode",
    "ProjectionFailure",
    "ProjectionResult",
    "ReadOnlySnapshotError",
    "ReadonlyM3ArtifactRepository",
    "RepositoryIntegrityError",
    "SQLiteAuthorityError",
    "SQLiteAuthorityGuard",
    "SQLiteEvidenceRepository",
    "SQLiteHearingModelCallRecoveryRepository",
    "SQLiteHearingRepository",
    "SQLiteM3Repository",
    "SQLiteM6UpgradeExecutionLedgerRepository",
    "SQLiteM6UpgradeExecutionLedgerV2Repository",
    "SQLiteM6UpgradeExecutionObservationRepository",
    "SQLiteM6UpgradePendingSampleCommitmentRepository",
    "SQLiteM6UpgradeWholeSampleRecordBuilder",
    "SecureDeletionReceipt",
    "SecureDirectoryHint",
    "SecureFileMetadata",
    "SecureFileSnapshot",
    "SecureHearingModelResponseStore",
    "SecureModelResponseArtifactRecovery",
    "SecureModelResponseStore",
    "SecureOrphanRecoveryFileOps",
    "SecureRetentionFileOps",
    "SecureVideoInput",
    "SecureWorkspace",
    "SnapshotRunCounts",
    "create_owner_only_directory",
    "m3_root_document_sha256",
    "readonly_sqlite_snapshot",
    "require_owner_only_directory",
    "snapshot_contains_run",
    "snapshot_run_counts",
]

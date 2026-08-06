"""Fail-closed deterministic helpers used only while applying SQL migrations."""

from __future__ import annotations

import hashlib
import sqlite3

from pydantic import BaseModel

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerSeal,
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleArtifactLink,
    M6UpgradeSampleExecutionRecord,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactRef

MIGRATION_SHA256_UTF8_FUNCTION = "labcourt_migration_sha256_utf8"
MIGRATION_CONTRACT_IS_CANONICAL_FUNCTION = "labcourt_migration_contract_is_canonical"

_MIGRATION_CONTRACT_TYPES: dict[str, type[BaseModel]] = {
    "execution-scope-v1": M6UpgradeExecutionScopeAuthority,
    "physical-artifact-ref-v1": M6UpgradePhysicalArtifactRef,
    "sample-artifact-link-v1": M6UpgradeSampleArtifactLink,
    "sample-execution-observation-v1": (M6UpgradeSampleExecutionObservationAuthority),
    "sample-execution-observation-v2": (M6UpgradeSampleExecutionObservationAuthorityV2),
    "sample-execution-record-v1": M6UpgradeSampleExecutionRecord,
    "sample-execution-record-v2": M6UpgradeSampleExecutionRecordV2,
    "pending-sample-commitment-v1": M6UpgradePendingSampleCommitmentAuthority,
    "execution-ledger-seal-v1": M6UpgradeExecutionLedgerSeal,
    "execution-ledger-seal-v2": M6UpgradeExecutionLedgerSealV2,
}


def migration_sha256_utf8(raw: object) -> str | None:
    """Return a UTF-8 digest, or NULL for every invalid input or failure."""

    if type(raw) is not str:
        return None
    try:
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
    except Exception:
        return None


def migration_contract_is_canonical(kind: object, raw: object) -> int:
    """Validate one allowlisted contract and its exact computed-field wire form."""

    if type(kind) is not str or type(raw) is not str:
        return 0
    model_type = _MIGRATION_CONTRACT_TYPES.get(kind)
    if model_type is None:
        return 0
    try:
        value = model_type.model_validate_json(raw)
        canonical = canonical_json(value.model_dump(mode="json"))
    except Exception:
        return 0
    return int(canonical == raw)


def register_migration_contract_functions(connection: sqlite3.Connection) -> None:
    """Install deterministic direct-statement helpers on a controlled connection."""

    connection.create_function(
        MIGRATION_SHA256_UTF8_FUNCTION,
        1,
        migration_sha256_utf8,
        deterministic=True,
    )
    connection.create_function(
        MIGRATION_CONTRACT_IS_CANONICAL_FUNCTION,
        2,
        migration_contract_is_canonical,
        deterministic=True,
    )


__all__ = [
    "MIGRATION_CONTRACT_IS_CANONICAL_FUNCTION",
    "MIGRATION_SHA256_UTF8_FUNCTION",
    "migration_contract_is_canonical",
    "migration_sha256_utf8",
    "register_migration_contract_functions",
]

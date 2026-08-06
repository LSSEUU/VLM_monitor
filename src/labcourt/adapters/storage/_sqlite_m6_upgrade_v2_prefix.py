"""Shared fail-closed identity checks for one M6 V2 ledger prefix."""

from __future__ import annotations

from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_LEDGER_LINKS,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactRef


def validate_m6_upgrade_v2_prefix_identity_closure(
    records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
) -> None:
    """Reject a prefix that a terminal V2 ledger can never represent."""

    if sum(record.artifact_link_count for record in records) > MAX_M6_UPGRADE_LEDGER_LINKS:
        raise ValueError("M6 V2 prefix exceeds the global artifact-link budget")

    artifacts_by_key: dict[tuple[int, int, str, str], M6UpgradePhysicalArtifactRef] = {}
    artifacts_by_id: dict[str, M6UpgradePhysicalArtifactRef] = {}
    for record in records:
        for link in record.artifact_links:
            artifact = link.artifact
            prior_by_key = artifacts_by_key.setdefault(artifact.physical_key, artifact)
            prior_by_id = artifacts_by_id.setdefault(artifact.artifact_ref_id, artifact)
            if prior_by_key != artifact or prior_by_id != artifact:
                raise ValueError("M6 V2 physical artifact identity conflicts across samples")

    case_ids = tuple(
        record.candidate_case.case_id for record in records if record.candidate_case is not None
    )
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("M6 V2 current Case bindings must be unique")


__all__ = ["validate_m6_upgrade_v2_prefix_identity_closure"]

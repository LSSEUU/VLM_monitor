"""Read-only SQLite and local-artifact source for A4 operator publication."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.contracts.cases import Case
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.pilot_report import PilotLocalAlertDocument
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ContractViolation, ManifestMismatch
from labcourt.ports.evidence_repository import CaseSnapshot


def load_pilot_case_snapshots(
    *,
    database_path: Path,
    busy_timeout_ms: int,
    run_id: str,
) -> tuple[CaseSnapshot, ...]:
    """Load every indexed case through the existing validated evidence repository."""

    controlled_run_id = require_reference_token(run_id, "pilot report run_id")
    repository = SQLiteEvidenceRepository(database_path, busy_timeout_ms)
    repository.load_run_manifest(controlled_run_id)
    with sqlite3.connect(database_path, timeout=busy_timeout_ms / 1000) as connection:
        rows = connection.execute(
            "SELECT case_id FROM cases WHERE run_id = ? ORDER BY case_id",
            (controlled_run_id,),
        ).fetchall()
    case_ids = tuple(row[0] for row in rows)
    if any(not isinstance(case_id, str) for case_id in case_ids):
        raise ContractViolation("pilot report case index contains an invalid reference")
    if case_ids != tuple(sorted(set(case_ids))):
        raise ContractViolation("pilot report case index is not unique and stably ordered")
    return tuple(repository.load_case(controlled_run_id, case_id) for case_id in case_ids)


def verified_local_alert_paths(
    *,
    cases: tuple[Case, ...],
    run_root: Path,
    manifest: RunManifest,
) -> tuple[str, ...]:
    """Return only exact local alert documents that still match their Case authority."""

    paths: list[str] = []
    for case in sorted(cases, key=lambda item: item.case_id):
        current_alert = next((item for item in reversed(case.alerts) if not item.rescinded), None)
        if current_alert is None:
            continue
        target = run_root / "alerts" / f"{current_alert.alert_id}.json"
        if not target.exists():
            continue
        if not target.is_file():
            raise ContractViolation("pilot local alert path is not a regular file")
        document = PilotLocalAlertDocument.model_validate_json(target.read_bytes())
        if (
            document.run_id != case.run_id
            or document.case_id != case.case_id
            or document.final_decision != case.final_decision
            or document.alert != current_alert
            or document.manifest_id != manifest.manifest_id
            or document.config_sha256 != manifest.config_sha256
        ):
            raise ManifestMismatch("pilot local alert differs from current Case authority")
        paths.append(f"runs/{case.run_id}/alerts/{current_alert.alert_id}.json")
    return tuple(sorted(paths))


__all__ = ["load_pilot_case_snapshots", "verified_local_alert_paths"]

"""M5 connection guard, shared fault hook, manifest reader, and Case commit base."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path

from pydantic import ValidationError

from labcourt.contracts.alert_policy import AlertChannelCapabilityAuthority
from labcourt.contracts.audit import AuditEntry, AuditEntryDraft
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import AuditAction, AuditActorRole
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import ConcurrentModification, ContractViolation
from labcourt.ports.alert_policy import AlertPolicyVerifier, AutomaticPrecedentVerifier
from labcourt.ports.dataset_export import (
    M5DatasetArtifactVerifier,
    M5TrainingCropVerifier,
)
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot
from labcourt.ports.m3_semantics import M3SemanticVerifier
from labcourt.ports.m5_precedent_policy import M5PrecedentPolicyVerifier
from labcourt.ports.m5_precedent_usage import M5PrecedentApplicationVerifier
from labcourt.ports.procedural_review import ProceduralReviewVerifier
from labcourt.ports.vlm import RawModelResponseVerifier

from .sqlite_m3_repository import SQLiteM3Repository
from .sqlite_m3_repository_support import CurrentPackVerifier
from .sqlite_m5_case_transitions import m5_case_transition_audit
from .sqlite_m5_repository_host import SQLiteM5RepositoryHost
from .sqlite_repository import (
    MigrationIntegrityError,
    RepositoryIntegrityError,
    _document,
    _row_str,
    _verify_document,
)
from .sqlite_schema import m5_authority_installed


class SQLiteM5RepositoryFoundation(SQLiteM3Repository, SQLiteM5RepositoryHost):
    """Frozen M3 behavior plus complete migration-0009 authority checks."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        clock: object | None = None,
        *,
        current_pack_verifier: CurrentPackVerifier | None = None,
        raw_response_verifier: RawModelResponseVerifier | None = None,
        procedural_review_verifier: ProceduralReviewVerifier | None = None,
        semantic_verifier: M3SemanticVerifier | None = None,
        alert_policy_verifier: AlertPolicyVerifier | None = None,
        automatic_precedent_verifier: AutomaticPrecedentVerifier | None = None,
        m5_precedent_policy_verifier: M5PrecedentPolicyVerifier | None = None,
        m5_precedent_application_verifier: M5PrecedentApplicationVerifier | None = None,
        alert_channel_capability: AlertChannelCapabilityAuthority | None = None,
        training_crop_verifier: M5TrainingCropVerifier | None = None,
        dataset_artifact_verifier: M5DatasetArtifactVerifier | None = None,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(
            database_path,
            busy_timeout_ms,
            clock,
            current_pack_verifier=current_pack_verifier,
            raw_response_verifier=raw_response_verifier,
            procedural_review_verifier=procedural_review_verifier,
            semantic_verifier=semantic_verifier,
        )
        if alert_policy_verifier is not None and not callable(
            getattr(alert_policy_verifier, "rebuild", None)
        ):
            raise TypeError("alert_policy_verifier must implement rebuild")
        if fault_injector is not None and not callable(fault_injector):
            raise TypeError("fault_injector must be callable")
        if automatic_precedent_verifier is not None and not callable(
            getattr(automatic_precedent_verifier, "rebuild", None)
        ):
            raise TypeError("automatic_precedent_verifier must implement rebuild")
        if m5_precedent_policy_verifier is not None and (
            not callable(getattr(m5_precedent_policy_verifier, "expected_policy", None))
            or not isinstance(
                getattr(m5_precedent_policy_verifier, "run_mode", None),
                str,
            )
        ):
            raise TypeError("m5_precedent_policy_verifier must expose run_mode and expected_policy")
        if m5_precedent_application_verifier is not None and (
            not callable(getattr(m5_precedent_application_verifier, "rebuild_application", None))
            or not callable(getattr(m5_precedent_application_verifier, "rebuild_citations", None))
        ):
            raise TypeError(
                "m5_precedent_application_verifier must rebuild applications and citations"
            )
        if alert_channel_capability is not None and not isinstance(
            alert_channel_capability, AlertChannelCapabilityAuthority
        ):
            raise TypeError("alert_channel_capability must be an AlertChannelCapabilityAuthority")
        if training_crop_verifier is not None and not callable(
            getattr(training_crop_verifier, "verify_crop", None)
        ):
            raise TypeError("training_crop_verifier must implement verify_crop")
        if dataset_artifact_verifier is not None and not callable(
            getattr(dataset_artifact_verifier, "verify_published_dataset", None)
        ):
            raise TypeError("dataset_artifact_verifier must implement verify_published_dataset")
        self._alert_policy_verifier = alert_policy_verifier
        self._automatic_precedent_verifier = automatic_precedent_verifier
        self._m5_precedent_policy_verifier = m5_precedent_policy_verifier
        self._m5_precedent_application_verifier = m5_precedent_application_verifier
        self._alert_channel_capability = (
            AlertChannelCapabilityAuthority.model_validate(
                alert_channel_capability.model_dump(mode="json")
            )
            if alert_channel_capability is not None
            else None
        )
        self._training_crop_verifier = training_crop_verifier
        self._dataset_artifact_verifier = dataset_artifact_verifier
        self._fault_injector = fault_injector

    def _connection(self) -> sqlite3.Connection:
        connection = super()._connection()
        try:
            if not m5_authority_installed(connection):
                raise MigrationIntegrityError(
                    "SQLite M5 authority layout is incomplete; apply migration 0009"
                )
            return connection
        except BaseException:
            connection.close()
            raise

    def _m5_fault(self, phase: str) -> None:
        if not isinstance(phase, str) or not phase:
            raise TypeError("M5 fault phase must be a non-empty string")
        if self._fault_injector is not None:
            self._fault_injector(phase)

    def _load_run_manifest(
        self,
        connection: sqlite3.Connection,
        run_id: str,
    ) -> RunManifest:
        row = connection.execute(
            """
            SELECT rm.manifest_id, rm.schema_version,
                   rm.document_json, rm.document_sha256
            FROM runs AS r
            JOIN run_manifests AS rm ON rm.manifest_id = r.manifest_id
            WHERE r.run_id = ?
            """,
            (run_id,),
        ).fetchone()
        if row is None:
            raise ContractViolation(f"unknown run_id: {run_id}")
        raw = _row_str(row, "document_json")
        try:
            manifest = RunManifest.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored run manifest is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), manifest)
        if manifest.manifest_id != _row_str(
            row, "manifest_id"
        ) or manifest.schema_version != _row_str(row, "schema_version"):
            raise RepositoryIntegrityError(
                "run manifest index columns do not match its canonical document"
            )
        return manifest

    def _append_m5_audit(
        self,
        connection: sqlite3.Connection,
        head: AuditHead,
        *,
        action: AuditAction,
        object_ref: ArtifactRef,
        before_sha256: str,
        after_sha256: str,
    ) -> AuditEntry:
        entry = AuditEntryDraft(
            run_id=head.run_id,
            sequence=head.sequence + 1,
            actor=AuditActorRole.SYSTEM.value,
            action=action,
            object_ref=object_ref,
            before_sha256=before_sha256,
            after_sha256=after_sha256,
            manifest_id=head.manifest_id,
            recorded_at=self._recorded_at(),
            prev_entry_hash=head.entry_hash,
        ).seal()
        entry_json, entry_sha256 = _document(entry)
        connection.execute(
            """
            INSERT INTO audit_entries(
                run_id, sequence, manifest_id, actor, action,
                object_kind, object_id, before_sha256, after_sha256,
                recorded_at, prev_entry_hash, entry_hash,
                entry_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.run_id,
                entry.sequence,
                entry.manifest_id,
                entry.actor,
                entry.action.value,
                entry.object_ref.kind.value,
                entry.object_ref.artifact_id,
                entry.before_sha256,
                entry.after_sha256,
                entry.recorded_at,
                entry.prev_entry_hash,
                entry.entry_hash,
                entry_json,
                entry_sha256,
            ),
        )
        cursor = connection.execute(
            """
            UPDATE runs
            SET revision = ?, audit_head_sequence = ?, audit_head_hash = ?
            WHERE run_id = ? AND revision = ?
              AND audit_head_sequence = ? AND audit_head_hash = ?
            """,
            (
                head.run_revision + 1,
                entry.sequence,
                entry.entry_hash,
                head.run_id,
                head.run_revision,
                head.sequence,
                head.entry_hash,
            ),
        )
        if cursor.rowcount != 1:
            raise ConcurrentModification("run audit head changed during M5 transaction")
        return entry

    def _commit_m5_case_version(
        self,
        connection: sqlite3.Connection,
        *,
        previous: CaseSnapshot,
        new_case: Case,
        expected_head: AuditHead,
        action: AuditAction,
        object_ref: ArtifactRef,
    ) -> CaseSnapshot:
        recognized = m5_case_transition_audit(previous.case, new_case)
        if recognized != (action, object_ref):
            raise ContractViolation("Case documents do not describe the claimed M5 transition")
        _, previous_sha256 = _document(previous.case)
        case_json, case_sha256 = _document(new_case)
        audit = self._append_m5_audit(
            connection,
            expected_head,
            action=action,
            object_ref=object_ref,
            before_sha256=previous_sha256,
            after_sha256=case_sha256,
        )
        new_revision = previous.revision + 1
        connection.execute(
            """
            INSERT INTO case_versions(
                run_id, case_id, revision, status,
                case_json, document_sha256, audit_sequence
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_case.run_id,
                new_case.case_id,
                new_revision,
                new_case.status.value,
                case_json,
                case_sha256,
                audit.sequence,
            ),
        )
        cursor = connection.execute(
            """
            UPDATE cases
            SET status = ?, current_revision = ?
            WHERE run_id = ? AND case_id = ? AND current_revision = ?
            """,
            (
                new_case.status.value,
                new_revision,
                new_case.run_id,
                new_case.case_id,
                previous.revision,
            ),
        )
        if cursor.rowcount != 1:
            raise ConcurrentModification("case revision changed during M5 transaction")
        return CaseSnapshot(case=new_case, revision=new_revision)


__all__ = ["SQLiteM5RepositoryFoundation"]

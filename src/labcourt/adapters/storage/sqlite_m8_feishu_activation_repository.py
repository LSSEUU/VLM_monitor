"""SQLite authority for Feishu sandbox activation and immediate revocation."""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from pydantic import ValidationError

from labcourt.application.m8_adapter_commissioning_workflow import (
    build_adapter_readiness_assessment,
)
from labcourt.application.m8_feishu_activation_workflow import (
    build_feishu_sandbox_activation_commit,
    build_feishu_sandbox_activation_revocation_commit,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_adapter_commissioning import (
    M8AdapterActivationIntentV1,
    M8AdapterReadinessAssessmentV1,
    M8CommissioningEvidenceCommitReceiptV1,
)
from labcourt.contracts.m8_feishu_activation import (
    M8FeishuSandboxActivationCommitReceiptV1,
    M8FeishuSandboxActivationRevocationCommitReceiptV1,
    M8FeishuSandboxActivationStatusV1,
    M8FeishuSandboxRevocationReason,
    M8FeishuSandboxRuntimeConfigV1,
    m8_feishu_runtime_config_bytes,
)
from labcourt.contracts.m8_notification_persistence import (
    M8NotificationTargetCommitReceiptV1,
)
from labcourt.contracts.m8_notifications import M8NotificationChannelKind
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import BudgetExceeded, ConcurrentModification, EvidenceMissing

from .sqlite_m8_adapter_commissioning_repository import (
    MAX_M8_COMMISSIONING_EVIDENCE_QUERY,
    SQLiteM8AdapterCommissioningRepository,
)
from .sqlite_m8_operations_repository import M8_MIGRATIONS
from .sqlite_repository import (
    MigrationRunner,
    RepositoryIntegrityError,
    _row_int,
    _row_optional_str,
    _row_str,
)

_REQUIRED_OBJECTS = frozenset(
    {
        "m8_feishu_sandbox_activations",
        "idx_m8_feishu_sandbox_activations_current",
        "m8_feishu_sandbox_activation_revocations",
        "idx_m8_feishu_sandbox_revocations_candidate",
        "m8_feishu_sandbox_activations_validate_contiguous",
        "m8_feishu_sandbox_activations_no_update",
        "m8_feishu_sandbox_activations_no_delete",
        "m8_feishu_sandbox_activations_no_replace",
        "m8_feishu_sandbox_activation_revocations_no_update",
        "m8_feishu_sandbox_activation_revocations_no_delete",
        "m8_feishu_sandbox_activation_revocations_no_replace",
    }
)


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 {name} must be lowercase SHA-256 hex")
    return value


def _require_utc(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 Feishu sandbox {name} must be timezone-aware UTC")
    return value


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


class SQLiteM8FeishuActivationRepository(SQLiteM8AdapterCommissioningRepository):
    """Commit only current dual-human sandbox authority in one SQLite transaction."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
        assessment_manifest_id: Sha256Hex,
    ) -> None:
        self._assessment_manifest_id = _validate_sha256(
            assessment_manifest_id,
            "Feishu activation readiness assessment manifest",
        )
        super().__init__(database_path, busy_timeout_ms, repository_manifest_id)

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
        assessment_manifest_id: Sha256Hex | None = None,
    ) -> SQLiteM8FeishuActivationRepository:
        MigrationRunner(database_path, busy_timeout_ms, M8_MIGRATIONS).apply_all()
        return cls(
            database_path,
            busy_timeout_ms,
            repository_manifest_id,
            assessment_manifest_id or repository_manifest_id,
        )

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        SQLiteM8AdapterCommissioningRepository._require_schema(connection)
        try:
            migration = connection.execute(
                "SELECT name FROM schema_migrations WHERE version = 7"
            ).fetchone()
        except sqlite3.DatabaseError as error:
            raise RepositoryIntegrityError(
                "M8 Feishu activation migration ledger is invalid"
            ) from error
        if migration is None or _row_str(migration, "name") != "m8_feishu_sandbox_activation":
            raise RepositoryIntegrityError("M8 Feishu activation migration 0007 is absent")
        observed = {
            _row_str(row, "name")
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name IN ({})".format(
                    ",".join("?" for _name in _REQUIRED_OBJECTS)
                ),
                tuple(sorted(_REQUIRED_OBJECTS)),
            ).fetchall()
        }
        if observed != _REQUIRED_OBJECTS:
            raise RepositoryIntegrityError("M8 Feishu activation layout is incomplete")

    def commit_activation(
        self,
        activation_intent: M8AdapterActivationIntentV1,
        runtime_config: M8FeishuSandboxRuntimeConfigV1,
        runtime_config_bytes: bytes,
        runtime_config_storage_manifest_id: str,
        current_assessed_at: datetime,
        committed_at: datetime,
    ) -> M8FeishuSandboxActivationCommitReceiptV1:
        if not isinstance(activation_intent, M8AdapterActivationIntentV1):
            raise TypeError("M8 Feishu activation requires a typed activation intent")
        if not isinstance(runtime_config, M8FeishuSandboxRuntimeConfigV1):
            raise TypeError("M8 Feishu activation requires a typed runtime config")
        if not isinstance(runtime_config_bytes, bytes):
            raise TypeError("M8 Feishu activation requires exact runtime config bytes")
        storage_manifest = _validate_sha256(
            runtime_config_storage_manifest_id,
            "Feishu runtime config storage manifest",
        )
        assessed_at = _require_utc(current_assessed_at, "current_assessed_at")
        commit_time = _require_utc(committed_at, "committed_at")
        candidate_id = activation_intent.readiness_assessment.candidate.candidate_authority_id
        with self._immediate() as connection:
            retry_row = connection.execute(
                """
                SELECT * FROM m8_feishu_sandbox_activations
                WHERE activation_intent_id = ?
                """,
                (activation_intent.activation_intent_id,),
            ).fetchone()
            if retry_row is not None:
                retry, persisted = self._load_activation_row(connection, retry_row)
                if (
                    retry.activation_intent == activation_intent
                    and retry.runtime_config == runtime_config
                    and persisted == runtime_config_bytes
                    and retry.runtime_config_storage_manifest_id == storage_manifest
                ):
                    return retry
                raise ConcurrentModification("M8 Feishu activation retry conflicts")

            candidate_row = connection.execute(
                """
                SELECT * FROM m8_production_adapter_candidates
                WHERE candidate_authority_id = ?
                """,
                (candidate_id,),
            ).fetchone()
            if candidate_row is None:
                raise EvidenceMissing("M8 Feishu activation candidate was not registered")
            candidate_receipt = self._load_candidate_row(candidate_row)
            if candidate_receipt.candidate != activation_intent.readiness_assessment.candidate:
                raise ConcurrentModification("M8 Feishu activation candidate is not current")

            latest_row = self._select_latest_activation_row(connection, candidate_id)
            prior_commit_id: str | None = None
            revision = 1
            if latest_row is not None:
                latest, _raw = self._load_activation_row(connection, latest_row)
                revocation_row = self._select_revocation_row(
                    connection,
                    latest.activation_commit_id,
                )
                if revocation_row is None:
                    raise ConcurrentModification("M8 Feishu sandbox activation is already active")
                self._load_revocation_row(connection, revocation_row, latest)
                prior_commit_id = latest.activation_commit_id
                revision = latest.activation_revision + 1

            operations = self._load_current_actor(
                connection,
                activation_intent.operations_actor_receipt.authority.actor_id,
            )
            safety = self._load_current_actor(
                connection,
                activation_intent.safety_actor_receipt.authority.actor_id,
            )
            evidence = self._load_candidate_evidence(connection, candidate_id)
            try:
                current_readiness = build_adapter_readiness_assessment(
                    candidate_receipt,
                    evidence,
                    operations,
                    assessed_at,
                    self._assessment_manifest_id,
                )
                self._require_exact_current_targets(connection, runtime_config)
                receipt = build_feishu_sandbox_activation_commit(
                    activation_intent,
                    runtime_config,
                    runtime_config_bytes,
                    current_readiness,
                    operations,
                    safety,
                    revision,
                    prior_commit_id,
                    commit_time,
                    storage_manifest,
                    self._repository_manifest_id,
                )
            except (ValidationError, ValueError) as error:
                raise ConcurrentModification("M8 Feishu activation gate is not current") from error
            self._insert_activation(connection, receipt, runtime_config_bytes)
            return receipt

    def get_activation(
        self,
        activation_commit_id: str,
    ) -> M8FeishuSandboxActivationCommitReceiptV1:
        commit_id = _validate_sha256(activation_commit_id, "Feishu activation commit ID")
        with self._read() as connection:
            row = connection.execute(
                """
                SELECT * FROM m8_feishu_sandbox_activations
                WHERE activation_commit_id = ?
                """,
                (commit_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 Feishu activation was not found")
            return self._load_activation_row(connection, row)[0]

    def get_current_status(
        self,
        candidate_authority_id: str,
        assessed_at: datetime,
    ) -> M8FeishuSandboxActivationStatusV1:
        candidate_id = _validate_sha256(
            candidate_authority_id,
            "Feishu activation candidate ID",
        )
        status_time = _require_utc(assessed_at, "status assessed_at")
        with self._read() as connection:
            row = self._select_latest_activation_row(connection, candidate_id)
            if row is None:
                raise EvidenceMissing("M8 Feishu activation status was not found")
            activation, _raw = self._load_activation_row(connection, row)
            revocation_row = self._select_revocation_row(
                connection,
                activation.activation_commit_id,
            )
            revocation = (
                self._load_revocation_row(connection, revocation_row, activation)
                if revocation_row is not None
                else None
            )
            operations = self._load_current_actor(
                connection,
                activation.current_operations_actor_receipt.authority.actor_id,
            )
            safety = self._load_current_actor(
                connection,
                activation.current_safety_actor_receipt.authority.actor_id,
            )
            targets = self._load_current_targets(connection, activation.runtime_config)
            readiness: M8AdapterReadinessAssessmentV1 | None = None
            candidate_row = connection.execute(
                """
                SELECT * FROM m8_production_adapter_candidates
                WHERE candidate_authority_id = ?
                """,
                (candidate_id,),
            ).fetchone()
            if candidate_row is None:
                raise RepositoryIntegrityError("M8 Feishu activation candidate is missing")
            candidate = self._load_candidate_row(candidate_row)
            evidence = self._load_candidate_evidence(connection, candidate_id)
            try:
                readiness = build_adapter_readiness_assessment(
                    candidate,
                    evidence,
                    operations,
                    status_time,
                    self._assessment_manifest_id,
                )
            except (ValidationError, ValueError):
                readiness = None
            try:
                return M8FeishuSandboxActivationStatusV1(
                    activation_receipt=activation,
                    revocation_receipt=revocation,
                    current_operations_actor_receipt=operations,
                    current_safety_actor_receipt=safety,
                    current_recipient_target_receipts=targets,
                    current_readiness_assessment=readiness,
                    assessed_at=status_time,
                    repository_manifest_id=self._repository_manifest_id,
                )
            except (ValidationError, ValueError) as error:
                raise RepositoryIntegrityError("M8 Feishu activation status is invalid") from error

    def revoke_activation(
        self,
        activation_commit_id: str,
        revoker_actor_id: str,
        reason: M8FeishuSandboxRevocationReason,
        reason_ref: str,
        revoked_at: datetime,
        revocation_manifest_id: str,
    ) -> M8FeishuSandboxActivationRevocationCommitReceiptV1:
        commit_id = _validate_sha256(activation_commit_id, "Feishu activation commit ID")
        actor_id = require_reference_token(revoker_actor_id, "M8 Feishu revoker actor")
        if not isinstance(reason, M8FeishuSandboxRevocationReason):
            raise TypeError("M8 Feishu revocation requires a typed reason")
        controlled_reason_ref = require_reference_token(
            reason_ref,
            "M8 Feishu revocation reason",
        )
        revocation_time = _require_utc(revoked_at, "revoked_at")
        manifest_id = _validate_sha256(
            revocation_manifest_id,
            "Feishu revocation manifest",
        )
        with self._immediate() as connection:
            activation_row = connection.execute(
                """
                SELECT * FROM m8_feishu_sandbox_activations
                WHERE activation_commit_id = ?
                """,
                (commit_id,),
            ).fetchone()
            if activation_row is None:
                raise EvidenceMissing("M8 Feishu activation was not found")
            activation, _raw = self._load_activation_row(connection, activation_row)
            latest = self._select_latest_activation_row(
                connection,
                activation.runtime_config.profile.candidate.candidate_authority_id,
            )
            if latest is None or _row_str(latest, "activation_commit_id") != commit_id:
                raise ConcurrentModification("M8 Feishu revocation target is not current")
            existing_row = self._select_revocation_row(connection, commit_id)
            if existing_row is not None:
                existing = self._load_revocation_row(connection, existing_row, activation)
                if (
                    existing.revoked_by_actor_receipt.authority.actor_id == actor_id
                    and existing.reason == reason
                    and existing.reason_ref == controlled_reason_ref
                    and existing.revoked_at == revocation_time
                    and existing.revocation_manifest_id == manifest_id
                ):
                    return existing
                raise ConcurrentModification("M8 Feishu revocation retry conflicts")
            revoker = self._load_current_actor(connection, actor_id)
            try:
                receipt = build_feishu_sandbox_activation_revocation_commit(
                    activation,
                    revoker,
                    reason,
                    controlled_reason_ref,
                    revocation_time,
                    manifest_id,
                    self._repository_manifest_id,
                )
            except (ValidationError, ValueError) as error:
                raise ConcurrentModification("M8 Feishu revocation is not authorized") from error
            self._insert_revocation(connection, receipt)
            return receipt

    def read_runtime_config(self, runtime_config_ref: str) -> bytes:
        controlled_ref = require_reference_token(
            runtime_config_ref,
            "M8 Feishu runtime config",
        )
        with self._read() as connection:
            row = connection.execute(
                """
                SELECT * FROM m8_feishu_sandbox_activations
                WHERE runtime_config_ref = ?
                """,
                (controlled_ref,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 Feishu runtime config was not found")
            return self._load_activation_row(connection, row)[1]

    def _load_candidate_evidence(
        self,
        connection: sqlite3.Connection,
        candidate_authority_id: str,
    ) -> tuple[M8CommissioningEvidenceCommitReceiptV1, ...]:
        rows = connection.execute(
            """
            SELECT * FROM m8_commissioning_evidence
            WHERE candidate_authority_id = ?
            ORDER BY evidence_kind, reviewed_at, evidence_authority_id
            LIMIT ?
            """,
            (candidate_authority_id, MAX_M8_COMMISSIONING_EVIDENCE_QUERY + 1),
        ).fetchall()
        if len(rows) > MAX_M8_COMMISSIONING_EVIDENCE_QUERY:
            raise BudgetExceeded("M8 Feishu activation evidence query exceeds its limit")
        return tuple(self._load_evidence_row(connection, row)[0] for row in rows)

    def _require_exact_current_targets(
        self,
        connection: sqlite3.Connection,
        config: M8FeishuSandboxRuntimeConfigV1,
    ) -> None:
        current = self._load_current_targets(connection, config)
        if any(
            receipt.target != binding.target
            for binding, receipt in zip(config.recipient_allowlist, current, strict=True)
        ):
            raise ConcurrentModification("M8 Feishu sandbox recipient target is not current")

    def _load_current_targets(
        self,
        connection: sqlite3.Connection,
        config: M8FeishuSandboxRuntimeConfigV1,
    ) -> tuple[M8NotificationTargetCommitReceiptV1, ...]:
        receipts: list[M8NotificationTargetCommitReceiptV1] = []
        for binding in config.recipient_allowlist:
            row = connection.execute(
                """
                SELECT * FROM m8_notification_targets
                WHERE actor_id = ? AND channel = ?
                ORDER BY authority_revision DESC LIMIT 1
                """,
                (binding.target.actor_id, M8NotificationChannelKind.FEISHU.value),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 Feishu sandbox recipient target was not found")
            receipts.append(self._load_target_row(row))
        return tuple(receipts)

    def _load_target_row(self, row: sqlite3.Row) -> M8NotificationTargetCommitReceiptV1:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8NotificationTargetCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 Feishu target is invalid") from error
        target = receipt.target
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or target.actor_id != _row_str(row, "actor_id")
            or target.channel.value != _row_str(row, "channel")
            or target.authority_revision != _row_int(row, "authority_revision")
            or target.target_authority_id != _row_str(row, "target_authority_id")
            or receipt.target_document_sha256 != _row_str(row, "target_document_sha256")
            or int(target.active) != _row_int(row, "active")
            or receipt.prior_target_authority_id
            != _row_optional_str(row, "prior_target_authority_id")
            or receipt.prior_document_sha256 != _row_optional_str(row, "prior_document_sha256")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
        ):
            raise RepositoryIntegrityError("M8 Feishu target index conflicts with receipt")
        return receipt

    @staticmethod
    def _select_latest_activation_row(
        connection: sqlite3.Connection,
        candidate_authority_id: str,
    ) -> sqlite3.Row | None:
        row: sqlite3.Row | None = connection.execute(
            """
            SELECT * FROM m8_feishu_sandbox_activations
            WHERE candidate_authority_id = ?
            ORDER BY activation_revision DESC LIMIT 1
            """,
            (candidate_authority_id,),
        ).fetchone()
        return row

    @staticmethod
    def _select_revocation_row(
        connection: sqlite3.Connection,
        activation_commit_id: str,
    ) -> sqlite3.Row | None:
        row: sqlite3.Row | None = connection.execute(
            """
            SELECT * FROM m8_feishu_sandbox_activation_revocations
            WHERE activation_commit_id = ?
            """,
            (activation_commit_id,),
        ).fetchone()
        return row

    def _load_activation_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> tuple[M8FeishuSandboxActivationCommitReceiptV1, bytes]:
        raw_receipt = _row_str(row, "receipt_json")
        try:
            receipt = M8FeishuSandboxActivationCommitReceiptV1.model_validate_json(raw_receipt)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 Feishu activation is invalid") from error
        config = receipt.runtime_config
        candidate = config.profile.candidate
        persisted = row["runtime_config_bytes"]
        if not isinstance(persisted, bytes):
            raise RepositoryIntegrityError("M8 Feishu runtime config column must contain bytes")
        candidate_row = connection.execute(
            """
            SELECT * FROM m8_production_adapter_candidates
            WHERE candidate_authority_id = ?
            """,
            (candidate.candidate_authority_id,),
        ).fetchone()
        if candidate_row is None or self._load_candidate_row(candidate_row).candidate != candidate:
            raise RepositoryIntegrityError("M8 Feishu activation candidate is missing or changed")
        operations_row = connection.execute(
            "SELECT * FROM m8_actor_authorities WHERE actor_authority_id = ?",
            (receipt.current_operations_actor_receipt.authority.actor_authority_id,),
        ).fetchone()
        safety_row = connection.execute(
            "SELECT * FROM m8_actor_authorities WHERE actor_authority_id = ?",
            (receipt.current_safety_actor_receipt.authority.actor_authority_id,),
        ).fetchone()
        if (
            operations_row is None
            or safety_row is None
            or self._load_actor_row(operations_row) != receipt.current_operations_actor_receipt
            or self._load_actor_row(safety_row) != receipt.current_safety_actor_receipt
        ):
            raise RepositoryIntegrityError("M8 Feishu activation human authority is missing")
        for evidence in receipt.current_readiness_assessment.evidence:
            evidence_row = connection.execute(
                """
                SELECT * FROM m8_commissioning_evidence WHERE commit_receipt_id = ?
                """,
                (evidence.commit_receipt_id,),
            ).fetchone()
            if (
                evidence_row is None
                or self._load_evidence_row(connection, evidence_row)[0] != evidence
            ):
                raise RepositoryIntegrityError("M8 Feishu activation evidence is missing")
        for binding in config.recipient_allowlist:
            target_row = connection.execute(
                """
                SELECT * FROM m8_notification_targets WHERE target_authority_id = ?
                """,
                (binding.target.target_authority_id,),
            ).fetchone()
            if target_row is None or self._load_target_row(target_row).target != binding.target:
                raise RepositoryIntegrityError("M8 Feishu activation recipient is missing")
        expected_bytes = m8_feishu_runtime_config_bytes(config)
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw_receipt
            or canonical_json(config.model_dump(mode="json"))
            != _row_str(row, "runtime_config_json")
            or candidate.candidate_authority_id != _row_str(row, "candidate_authority_id")
            or config.profile.profile_id != _row_str(row, "profile_id")
            or config.runtime_config_id != _row_str(row, "runtime_config_id")
            or config.runtime_config_ref != _row_str(row, "runtime_config_ref")
            or persisted != expected_bytes
            or len(persisted) != _row_int(row, "runtime_config_size_bytes")
            or hashlib.sha256(persisted).hexdigest()
            != _row_str(row, "runtime_config_document_sha256")
            or receipt.runtime_config_document_sha256
            != _row_str(row, "runtime_config_document_sha256")
            or receipt.activation_intent.activation_intent_id
            != _row_str(row, "activation_intent_id")
            or receipt.activation_revision != _row_int(row, "activation_revision")
            or receipt.prior_activation_commit_id
            != _row_optional_str(row, "prior_activation_commit_id")
            or receipt.current_operations_actor_receipt.authority.actor_authority_id
            != _row_str(row, "operations_actor_authority_id")
            or receipt.current_safety_actor_receipt.authority.actor_authority_id
            != _row_str(row, "safety_actor_authority_id")
            or _canonical_utc(receipt.committed_at) != _row_str(row, "committed_at")
            or receipt.runtime_config_storage_manifest_id
            != _row_str(row, "runtime_config_storage_manifest_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
            or receipt.activation_commit_id != _row_str(row, "activation_commit_id")
        ):
            raise RepositoryIntegrityError("M8 Feishu activation index conflicts with receipt")
        return receipt, persisted

    def _load_revocation_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        activation: M8FeishuSandboxActivationCommitReceiptV1,
    ) -> M8FeishuSandboxActivationRevocationCommitReceiptV1:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8FeishuSandboxActivationRevocationCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 Feishu revocation is invalid") from error
        actor_row = connection.execute(
            "SELECT * FROM m8_actor_authorities WHERE actor_authority_id = ?",
            (receipt.revoked_by_actor_receipt.authority.actor_authority_id,),
        ).fetchone()
        if actor_row is None or self._load_actor_row(actor_row) != receipt.revoked_by_actor_receipt:
            raise RepositoryIntegrityError("M8 Feishu revocation actor is missing")
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or receipt.activation_receipt != activation
            or activation.activation_commit_id != _row_str(row, "activation_commit_id")
            or activation.runtime_config.profile.candidate.candidate_authority_id
            != _row_str(row, "candidate_authority_id")
            or receipt.revoked_by_actor_receipt.authority.actor_authority_id
            != _row_str(row, "revoked_by_actor_authority_id")
            or receipt.reason.value != _row_str(row, "reason")
            or receipt.reason_ref != _row_str(row, "reason_ref")
            or _canonical_utc(receipt.revoked_at) != _row_str(row, "revoked_at")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
            or receipt.revocation_commit_id != _row_str(row, "revocation_commit_id")
        ):
            raise RepositoryIntegrityError("M8 Feishu revocation index conflicts with receipt")
        return receipt

    def _insert_activation(
        self,
        connection: sqlite3.Connection,
        receipt: M8FeishuSandboxActivationCommitReceiptV1,
        runtime_config_bytes: bytes,
    ) -> None:
        config = receipt.runtime_config
        candidate = config.profile.candidate
        try:
            connection.execute(
                """
                INSERT INTO m8_feishu_sandbox_activations(
                    activation_commit_id, candidate_authority_id, profile_id,
                    runtime_config_id, runtime_config_ref,
                    runtime_config_document_sha256, runtime_config_size_bytes,
                    runtime_config_bytes, activation_intent_id, activation_revision,
                    prior_activation_commit_id, operations_actor_authority_id,
                    safety_actor_authority_id, committed_at,
                    runtime_config_storage_manifest_id, repository_manifest_id,
                    runtime_config_json, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.activation_commit_id,
                    candidate.candidate_authority_id,
                    config.profile.profile_id,
                    config.runtime_config_id,
                    config.runtime_config_ref,
                    receipt.runtime_config_document_sha256,
                    receipt.runtime_config_size_bytes,
                    runtime_config_bytes,
                    receipt.activation_intent.activation_intent_id,
                    receipt.activation_revision,
                    receipt.prior_activation_commit_id,
                    receipt.current_operations_actor_receipt.authority.actor_authority_id,
                    receipt.current_safety_actor_receipt.authority.actor_authority_id,
                    _canonical_utc(receipt.committed_at),
                    receipt.runtime_config_storage_manifest_id,
                    receipt.repository_manifest_id,
                    canonical_json(config.model_dump(mode="json")),
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 Feishu activation append was rejected") from error

    def _insert_revocation(
        self,
        connection: sqlite3.Connection,
        receipt: M8FeishuSandboxActivationRevocationCommitReceiptV1,
    ) -> None:
        activation = receipt.activation_receipt
        try:
            connection.execute(
                """
                INSERT INTO m8_feishu_sandbox_activation_revocations(
                    revocation_commit_id, activation_commit_id, candidate_authority_id,
                    revoked_by_actor_authority_id, reason, reason_ref, revoked_at,
                    repository_manifest_id, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.revocation_commit_id,
                    activation.activation_commit_id,
                    activation.runtime_config.profile.candidate.candidate_authority_id,
                    receipt.revoked_by_actor_receipt.authority.actor_authority_id,
                    receipt.reason.value,
                    receipt.reason_ref,
                    _canonical_utc(receipt.revoked_at),
                    receipt.repository_manifest_id,
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 Feishu revocation append was rejected") from error


__all__ = ["SQLiteM8FeishuActivationRepository"]

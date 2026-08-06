"""Application-level reference closure and current-head checks for M5."""

from __future__ import annotations

import hashlib
import sqlite3
from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import pairwise
from typing import TypeAlias, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.alert_policy_verifier import ConfiguredAlertPolicyVerifier
from labcourt.application.m5_automatic_precedent import (
    AutomaticPrecedentError,
    derive_automatic_precedent_authority,
)
from labcourt.application.m5_dataset_retention import m5_dataset_retention_holds
from labcourt.application.m5_hearing_precedent_bridge import derive_m5_query_for_hearing
from labcourt.application.m5_precedent_policy_verifier import (
    ConfiguredM5PrecedentPolicyVerifier,
)
from labcourt.application.m5_precedent_usage_verifier import (
    ConfiguredM5PrecedentApplicationVerifier,
)
from labcourt.application.m5_precedents import (
    ExactM5PrecedentRetrievalService,
    evaluate_m5_automatic_activation,
    record_m5_precedent_citation,
    resolve_m5_precedent_conflict,
)
from labcourt.application.m5_training_history import (
    M5TrainingHistoryError,
    M5TrainingHistoryErrorCode,
    build_m5_dataset_label_snapshot_receipts,
    require_m5_training_causal_chain,
    resolve_m5_dataset_historical_replay,
)
from labcourt.application.m5_training_provenance import (
    M5TrainingLabelProvenanceError,
    M5TrainingLabelProvenanceErrorCode,
    require_m5_strong_training_label_provenance,
)
from labcourt.contracts.alert_policy import (
    AlertChannelCapabilityAuthority,
    AlertChannelIdempotencyGuarantee,
    AlertCooldownAuthority,
    AlertCooldownKey,
    AlertDispatchAttempt,
    AlertDispatchContinuation,
    AlertDispatchDisposition,
    AlertDispatchReceipt,
    AlertOutboxItem,
    AlertPolicyAuthority,
    ImmediateSafetyDeliveryAuthority,
)
from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    AppealStatus,
    ArtifactKind,
    AuditAction,
    AuditActorRole,
    CaseStatus,
    PrecedentSource,
    PrecedentStatus,
)
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.hearing_common import JudgeFinalDecisionPayload, JudgeModelPayload
from labcourt.contracts.hearing_state import (
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
    HearingRound,
    HearingVerdictBinding,
)
from labcourt.contracts.m5_appeals import (
    AppealResolutionSideEffectIntent,
    AppealVersionAuthority,
    M5AppealResolutionCommitReceipt,
)
from labcourt.contracts.m5_artifact_validation import (
    M5ActivationAuthorityReasonCode,
    M5AlertAuthorityReasonCode,
    M5AppealResolutionHistoryReasonCode,
    M5ArtifactValidationBudget,
    M5PrecedentCausalLedgerReasonCode,
    M5PrecedentConflictHistoryReasonCode,
    M5PrecedentRevocationHistoryReasonCode,
    M5TrainingHistoryReasonCode,
    M5TrainingLabelProvenanceReasonCode,
)
from labcourt.contracts.m5_precedent_causal_ledger import (
    M5_PRECEDENT_CAUSAL_GENESIS_SHA256,
    M5PrecedentCausalEvent,
    M5PrecedentCausalEventKind,
    M5PrecedentCausalEventSourceKind,
)
from labcourt.contracts.m5_precedent_usage import (
    M5PrecedentApplicationBatchAuthority,
    M5PrecedentApplicationCitationCommit,
    M5PrecedentExposureBatchAuthority,
)
from labcourt.contracts.m5_precedents import (
    M5AppealWindowSnapshot,
    M5EmbeddingVector,
    M5PrecedentActivationReceipt,
    M5PrecedentAuthority,
    M5PrecedentCitationCommit,
    M5PrecedentCitationSnapshot,
    M5PrecedentConflictBatchAuthority,
    M5PrecedentConflictBatchReceipt,
    M5PrecedentConflictReceipt,
    M5PrecedentPolicy,
    M5PrecedentRevocationReceipt,
)
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.m5_training import DatasetExportReport
from labcourt.contracts.m5_training_history import (
    M5DatasetCropSnapshotAuthority,
    M5DatasetRegistrationSnapshotAuthority,
    M5TrainingCausalEvent,
    M5TrainingCausalEventKind,
)
from labcourt.contracts.m5_training_provenance import (
    STRONG_TRAINING_LABEL_QUALITIES,
    M5StrongTrainingLabelProvenanceReceipt,
    M5TrainingLabelAuthority,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef, RetentionHold
from labcourt.contracts.training import TrainingLabel
from labcourt.contracts.verdicts import Verdict
from labcourt.domain.alert_policy import AlertPolicyError
from labcourt.ports.evidence_repository import CaseSnapshot

from ._m5_precedent_conflict_history import (
    M5PrecedentConflictHistoryError,
    M5PrecedentConflictHistoryErrorCode,
    rebuild_m5_precedent_conflict_history,
)
from ._m5_precedent_revocation_history import (
    M5PrecedentRevocationHistoryError,
    M5PrecedentRevocationHistoryErrorCode,
    rebuild_m5_precedent_revocation_history,
)
from ._readonly_m4_artifact_codec import (
    M4_TYPED_TABLES,
    M4DocumentFailure,
    M4IndexFailure,
    M4Record,
    load_m4_record,
)
from ._readonly_m5_artifact_codec import M5Record
from .readonly_m5_artifacts import (
    M5AlertPolicyCausalSource,
    M5AlertPolicyCooldownHistoryInventory,
    M5AlertPolicyCooldownHistorySource,
    M5ArtifactAuthorityFailure,
    M5AuthorityFailureType,
    M5CaseAuthorityRoot,
    M5DatasetHistoricalAuthority,
    M5DatasetRetentionFailure,
    M5DatasetRetentionFailureType,
    M5TrainingCaseAuthority,
)
from .sqlite_m5_case_transitions import m5_case_transition_audit
from .sqlite_m5_repository_alerts import MAX_AUTOMATIC_PRECEDENT_CLOCK_SKEW_SECONDS

ModelT = TypeVar("ModelT", bound=BaseModel)
M5CitationCommit: TypeAlias = M5PrecedentCitationCommit | M5PrecedentApplicationCitationCommit

_M4_SPEC_BY_TABLE = {spec.table: spec for spec in M4_TYPED_TABLES}

_CONFLICT_HISTORY_REASON_BY_ERROR = {
    M5PrecedentConflictHistoryErrorCode.TRUSTED_POLICY_MISMATCH: (
        M5PrecedentConflictHistoryReasonCode.CONFLICT_BATCH_TRUSTED_POLICY_MISMATCH
    ),
    M5PrecedentConflictHistoryErrorCode.CAUSAL_CUT_ANCHOR_INVALID: (
        M5PrecedentConflictHistoryReasonCode.CONFLICT_BATCH_CAUSAL_CUT_INVALID
    ),
    M5PrecedentConflictHistoryErrorCode.CAUSAL_EVENT_INVENTORY_INVALID: (
        M5PrecedentConflictHistoryReasonCode.CONFLICT_BATCH_CAUSAL_CUT_INVALID
    ),
    M5PrecedentConflictHistoryErrorCode.ACTIVE_SNAPSHOT_INVALID: (
        M5PrecedentConflictHistoryReasonCode.CONFLICT_BATCH_ACTIVE_ROOT_MISMATCH
    ),
    M5PrecedentConflictHistoryErrorCode.AUTHORITY_INTERVAL_INVALID: (
        M5PrecedentConflictHistoryReasonCode.CONFLICT_BATCH_CAUSAL_INTERVAL_INVALID
    ),
    M5PrecedentConflictHistoryErrorCode.COMMIT_MARKER_INVALID: (
        M5PrecedentConflictHistoryReasonCode.CONFLICT_BATCH_MARKER_MISSING_OR_INVALID
    ),
    M5PrecedentConflictHistoryErrorCode.RECEIPT_CLOSURE_INVALID: (
        M5PrecedentConflictHistoryReasonCode.CONFLICT_BATCH_RECEIPT_CLOSURE_INVALID
    ),
    M5PrecedentConflictHistoryErrorCode.AUTHORITY_INVENTORY_INVALID: (
        M5PrecedentConflictHistoryReasonCode.CONFLICT_BATCH_AUTHORITY_REFERENCE_INVALID
    ),
    M5PrecedentConflictHistoryErrorCode.RESULT_AUTHORITY_INVALID: (
        M5PrecedentConflictHistoryReasonCode.CONFLICT_BATCH_AUTHORITY_REFERENCE_INVALID
    ),
    M5PrecedentConflictHistoryErrorCode.RESOLVER_REPLAY_MISMATCH: (
        M5PrecedentConflictHistoryReasonCode.CONFLICT_BATCH_POLICY_REPLAY_INVALID
    ),
}

_REVOCATION_HISTORY_REASON_BY_ERROR = {
    M5PrecedentRevocationHistoryErrorCode.AUTHORITY_INVENTORY_INVALID: (
        M5PrecedentRevocationHistoryReasonCode.REVOCATION_RECEIPT_CLOSURE_INVALID
    ),
    M5PrecedentRevocationHistoryErrorCode.CITATION_INVENTORY_INVALID: (
        M5PrecedentRevocationHistoryReasonCode.REVOCATION_CITATION_SNAPSHOT_MISMATCH
    ),
    M5PrecedentRevocationHistoryErrorCode.CAUSAL_EVENT_INVENTORY_INVALID: (
        M5PrecedentRevocationHistoryReasonCode.REVOCATION_CAUSAL_INTERVAL_INVALID
    ),
    M5PrecedentRevocationHistoryErrorCode.RECEIPT_CLOSURE_INVALID: (
        M5PrecedentRevocationHistoryReasonCode.REVOCATION_RECEIPT_CLOSURE_INVALID
    ),
    M5PrecedentRevocationHistoryErrorCode.COMMIT_MARKER_INVALID: (
        M5PrecedentRevocationHistoryReasonCode.REVOCATION_MARKER_MISSING_OR_INVALID
    ),
    M5PrecedentRevocationHistoryErrorCode.CAUSAL_INTERVAL_INVALID: (
        M5PrecedentRevocationHistoryReasonCode.REVOCATION_CAUSAL_INTERVAL_INVALID
    ),
    M5PrecedentRevocationHistoryErrorCode.RESULT_AUTHORITY_INVALID: (
        M5PrecedentRevocationHistoryReasonCode.REVOCATION_RECEIPT_CLOSURE_INVALID
    ),
    M5PrecedentRevocationHistoryErrorCode.CITATION_SNAPSHOT_INVALID: (
        M5PrecedentRevocationHistoryReasonCode.REVOCATION_CITATION_SNAPSHOT_MISMATCH
    ),
    M5PrecedentRevocationHistoryErrorCode.REVOCATION_REPLAY_MISMATCH: (
        M5PrecedentRevocationHistoryReasonCode.REVOCATION_RECEIPT_CLOSURE_INVALID
    ),
}

_TRAINING_PROVENANCE_REASON_BY_ERROR = {
    M5TrainingLabelProvenanceErrorCode.LABEL_AUTHORITY_INVALID: (
        M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_AUTHORITY_INVALID
    ),
    M5TrainingLabelProvenanceErrorCode.REVIEW_AUTHORITY_INVALID: (
        M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_REVIEW_AUTHORITY_INVALID
    ),
    M5TrainingLabelProvenanceErrorCode.TERMINAL_AUTHORITY_INVALID: (
        M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_TERMINAL_AUTHORITY_INVALID
    ),
    M5TrainingLabelProvenanceErrorCode.RESOLUTION_INTENT_INVALID: (
        M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_RESOLUTION_INTENT_INVALID
    ),
    M5TrainingLabelProvenanceErrorCode.RESOLUTION_COMMIT_INVALID: (
        M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_RESOLUTION_COMMIT_INVALID
    ),
    M5TrainingLabelProvenanceErrorCode.RESOLUTION_MARKER_INVALID: (
        M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_RESOLUTION_MARKER_INVALID
    ),
}

_TRAINING_HISTORY_REASON_BY_ERROR = {
    M5TrainingHistoryErrorCode.CHAIN_INVALID: (
        M5TrainingHistoryReasonCode.TRAINING_CAUSAL_EVENT_CHAIN_INVALID
    ),
    M5TrainingHistoryErrorCode.LABEL_SOURCE_INVALID: (
        M5TrainingHistoryReasonCode.DATASET_LABEL_AUTHORITY_MISMATCH
    ),
    M5TrainingHistoryErrorCode.CUT_INVALID: (
        M5TrainingHistoryReasonCode.DATASET_CAUSAL_CUT_INVALID
    ),
    M5TrainingHistoryErrorCode.REPORT_SCOPE_INVALID: (
        M5TrainingHistoryReasonCode.DATASET_LABEL_CUT_ACCOUNTING_INVALID
    ),
    M5TrainingHistoryErrorCode.REGISTRATION_MARKER_INVALID: (
        M5TrainingHistoryReasonCode.DATASET_REGISTRATION_MARKER_MISSING_OR_INVALID
    ),
    M5TrainingHistoryErrorCode.LABEL_ROOT_INVALID: (
        M5TrainingHistoryReasonCode.DATASET_LABEL_INVENTORY_ROOT_MISMATCH
    ),
    M5TrainingHistoryErrorCode.CROP_ROOT_INVALID: (
        M5TrainingHistoryReasonCode.DATASET_CROP_SNAPSHOT_ROOT_MISMATCH
    ),
}


@dataclass(frozen=True, slots=True)
class M5RelationValidation:
    case_roots: tuple[M5CaseAuthorityRoot, ...]
    failures: tuple[M5ArtifactAuthorityFailure, ...]
    training_labels: tuple[TrainingLabel, ...]
    dataset_reports: tuple[DatasetExportReport, ...]
    training_cases: tuple[M5TrainingCaseAuthority, ...]
    dataset_histories: tuple[M5DatasetHistoricalAuthority, ...]
    dataset_retention_failures: tuple[M5DatasetRetentionFailure, ...]
    dataset_retention_hold_count: int
    orphan_retention_hold_count: int
    retention_root_sha256: str
    alert_policy_causal_sources: tuple[M5AlertPolicyCausalSource, ...]
    alert_policy_cooldown_history_inventories: tuple[
        M5AlertPolicyCooldownHistoryInventory,
        ...,
    ]


@dataclass(frozen=True, slots=True)
class _AlertPolicyCausalValidation:
    sources: tuple[M5AlertPolicyCausalSource, ...]
    cooldown_history_inventories: tuple[M5AlertPolicyCooldownHistoryInventory, ...]


@dataclass(frozen=True, slots=True)
class _CurrentCase:
    case_id: str
    revision: int
    status: str
    document_sha256: str
    case: Case


@dataclass(frozen=True, slots=True)
class _AlertClosingAudit:
    sequence: int
    recorded_at: datetime
    entry: AuditEntry
    canonical_document: str


@dataclass(frozen=True, slots=True)
class _CooldownCausalRow:
    revision: int
    writer_closing_audit: _AlertClosingAudit
    record: M5Record
    authority: AlertCooldownAuthority
    writer_alert_policy_authority_id: str


@dataclass(frozen=True, slots=True)
class _FinalHearingUsage:
    binding: HearingVerdictBinding
    hearing_round: HearingRound


class M5ArtifactReferenceValidator:
    """Reject missing reverse references even when SQLite has no declarative FK."""

    def validate(
        self,
        *,
        connection: sqlite3.Connection,
        run_id: str,
        manifest: RunManifest,
        config: AppConfig,
        records: dict[M5AuthorityKind, list[M5Record]],
        budget: M5ArtifactValidationBudget,
        retention_hold_rows: int,
        retention_link_rows: int,
        retention_audit_rows: int,
    ) -> M5RelationValidation:
        manifest_id = manifest.manifest_id
        failures: list[M5ArtifactAuthorityFailure] = []
        embeddings = _typed(records, M5AuthorityKind.PRECEDENT_EMBEDDING, M5EmbeddingVector)
        precedents = _typed(records, M5AuthorityKind.PRECEDENT, M5PrecedentAuthority)
        exposures = _typed(
            records,
            M5AuthorityKind.PRECEDENT_EXPOSURE,
            M5PrecedentExposureBatchAuthority,
        )
        application_batches = _typed(
            records,
            M5AuthorityKind.PRECEDENT_APPLICATION_BATCH,
            M5PrecedentApplicationBatchAuthority,
        )
        citations = _citation_commits(records)
        causal_events = _typed(
            records,
            M5AuthorityKind.PRECEDENT_CAUSAL_EVENT,
            M5PrecedentCausalEvent,
        )
        conflict_batches = _typed(
            records,
            M5AuthorityKind.PRECEDENT_CONFLICT_BATCH,
            M5PrecedentConflictBatchAuthority,
        )
        conflict_batch_receipts = _typed(
            records,
            M5AuthorityKind.PRECEDENT_CONFLICT_BATCH_RECEIPT,
            M5PrecedentConflictBatchReceipt,
        )
        lifecycle_receipts = _lifecycle_receipts(records)
        alerts = _typed(records, M5AuthorityKind.ALERT, AlertPolicyAuthority)
        cooldowns = _typed(records, M5AuthorityKind.ALERT_COOLDOWN, AlertCooldownAuthority)
        outbox = _typed(records, M5AuthorityKind.ALERT_OUTBOX, AlertOutboxItem)
        capabilities = _typed(
            records,
            M5AuthorityKind.ALERT_CHANNEL_CAPABILITY,
            AlertChannelCapabilityAuthority,
        )
        attempts = _typed(records, M5AuthorityKind.ALERT_DISPATCH_ATTEMPT, AlertDispatchAttempt)
        receipts = _typed(records, M5AuthorityKind.ALERT_DISPATCH_RECEIPT, AlertDispatchReceipt)
        immediate_deliveries = _typed(
            records,
            M5AuthorityKind.IMMEDIATE_SAFETY_DELIVERY,
            ImmediateSafetyDeliveryAuthority,
        )
        appeals = _typed(records, M5AuthorityKind.APPEAL, AppealVersionAuthority)
        resolutions = _typed(
            records,
            M5AuthorityKind.APPEAL_RESOLUTION,
            AppealResolutionSideEffectIntent,
        )
        resolution_commits = _typed(
            records,
            M5AuthorityKind.APPEAL_RESOLUTION_COMMIT,
            M5AppealResolutionCommitReceipt,
        )
        strong_label_provenance = _typed(
            records,
            M5AuthorityKind.STRONG_TRAINING_LABEL_PROVENANCE,
            M5StrongTrainingLabelProvenanceReceipt,
        )
        labels = _typed(records, M5AuthorityKind.TRAINING_LABEL, TrainingLabel)
        datasets = _typed(records, M5AuthorityKind.DATASET_ARTIFACT, DatasetExportReport)
        training_events = _typed(
            records,
            M5AuthorityKind.TRAINING_CAUSAL_EVENT,
            M5TrainingCausalEvent,
        )
        dataset_snapshots = _typed(
            records,
            M5AuthorityKind.DATASET_REGISTRATION_SNAPSHOT,
            M5DatasetRegistrationSnapshotAuthority,
        )
        dataset_crop_snapshots = _typed(
            records,
            M5AuthorityKind.DATASET_CROP_SNAPSHOT,
            M5DatasetCropSnapshotAuthority,
        )

        self._validate_manifest_bindings(run_id, manifest, records, failures)
        self._validate_precedent_causal_ledger(
            precedents=precedents,
            citations=citations,
            conflict_batch_receipts=conflict_batch_receipts,
            lifecycle_receipts=lifecycle_receipts,
            resolution_commits=resolution_commits,
            events=causal_events,
            failures=failures,
        )

        case_ids = _case_ids(
            precedents,
            exposures,
            application_batches,
            citations,
            alerts,
            appeals,
            labels,
        )
        cases = self._load_current_cases(
            connection,
            run_id,
            manifest_id,
            case_ids,
            records,
            failures,
        )
        self._validate_precedents(
            connection,
            run_id,
            manifest,
            config,
            records,
            embeddings,
            precedents,
            citations,
            causal_events,
            conflict_batches,
            conflict_batch_receipts,
            alerts,
            appeals,
            failures,
        )
        self._validate_precedent_usage(
            connection=connection,
            run_id=run_id,
            manifest=manifest,
            config=config,
            exposures=exposures,
            application_batches=application_batches,
            citations=citations,
            precedents=precedents,
            alerts=alerts,
            failures=failures,
        )
        alert_policy_causal_validation = self._validate_alerts(
            connection,
            run_id,
            manifest,
            config,
            records,
            cases,
            embeddings,
            precedents,
            alerts,
            cooldowns,
            outbox,
            capabilities,
            attempts,
            receipts,
            failures,
        )
        for record, _authority in immediate_deliveries:
            _fail(
                failures,
                record.kind,
                record,
                "IMMEDIATE_SAFETY_DELIVERY_UNTRUSTED_NO_CERTIFIED_SIGNAL",
                head=True,
            )
        self._validate_appeals(
            connection,
            run_id,
            records,
            cases,
            precedents,
            citations,
            alerts,
            appeals,
            resolutions,
            resolution_commits,
            lifecycle_receipts,
            labels,
            failures,
        )
        valid_strong_label_ids = self._validate_training_label_provenance(
            appeals=appeals,
            resolutions=resolutions,
            resolution_commits=resolution_commits,
            causal_events=causal_events,
            labels=labels,
            provenance_receipts=strong_label_provenance,
            failures=failures,
        )
        dataset_histories = self._validate_training_history(
            connection=connection,
            run_id=run_id,
            manifest_id=manifest_id,
            labels=labels,
            provenance_receipts=strong_label_provenance,
            events=training_events,
            datasets=datasets,
            registration_snapshots=dataset_snapshots,
            crop_snapshots=dataset_crop_snapshots,
            valid_strong_label_ids=valid_strong_label_ids,
            failures=failures,
        )
        retention = _validate_dataset_retention_authority(
            connection=connection,
            run_id=run_id,
            datasets=tuple(item for _record, item in datasets),
            appeal_ids=frozenset(item.appeal.appeal_id for _record, item in appeals),
            budget=budget,
            retention_hold_rows=retention_hold_rows,
            retention_link_rows=retention_link_rows,
            retention_audit_rows=retention_audit_rows,
        )
        return M5RelationValidation(
            case_roots=self._build_roots(
                records,
                cases,
                precedents,
                alerts,
                appeals,
                resolutions,
            ),
            failures=tuple(failures),
            training_labels=tuple(
                sorted((item for _record, item in labels), key=lambda item: item.label_id)
            ),
            dataset_reports=tuple(
                sorted(
                    (item for _record, item in datasets),
                    key=lambda item: item.dataset.dataset_id,
                )
            ),
            training_cases=tuple(
                M5TrainingCaseAuthority(
                    case_id=item.case_id,
                    revision=item.revision,
                    document_sha256=item.document_sha256,
                    case=item.case,
                )
                for item in sorted(cases.values(), key=lambda item: item.case_id)
            ),
            dataset_histories=dataset_histories,
            dataset_retention_failures=retention.failures,
            dataset_retention_hold_count=retention.dataset_hold_count,
            orphan_retention_hold_count=retention.orphan_count,
            retention_root_sha256=retention.root_sha256,
            alert_policy_causal_sources=alert_policy_causal_validation.sources,
            alert_policy_cooldown_history_inventories=(
                alert_policy_causal_validation.cooldown_history_inventories
            ),
        )

    @staticmethod
    def _validate_manifest_bindings(
        run_id: str,
        manifest: RunManifest,
        records: dict[M5AuthorityKind, list[M5Record]],
        failures: list[M5ArtifactAuthorityFailure],
    ) -> None:
        """Bind every M5 document to the selected canonical run authority."""

        for values in records.values():
            for record in values:
                if not _document_matches_manifest(
                    record.document,
                    run_id,
                    manifest,
                ) or not _secondary_documents_match_manifest(record, run_id, manifest):
                    _fail(
                        failures,
                        record.kind,
                        record,
                        "RUN_MANIFEST_AUTHORITY_BINDING_MISMATCH",
                    )

    def _load_current_cases(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        manifest_id: str,
        case_ids: set[str],
        records: dict[M5AuthorityKind, list[M5Record]],
        failures: list[M5ArtifactAuthorityFailure],
    ) -> dict[str, _CurrentCase]:
        result: dict[str, _CurrentCase] = {}
        for case_id in sorted(case_ids):
            rows = connection.execute(
                """
                SELECT c.current_revision, c.status AS current_status,
                       c.manifest_id, v.status, v.case_json, v.document_sha256
                FROM cases AS c
                JOIN case_versions AS v
                  ON v.run_id = c.run_id AND v.case_id = c.case_id
                 AND v.revision = c.current_revision
                WHERE c.run_id = ? AND c.case_id = ?
                """,
                (run_id, case_id),
            ).fetchall()
            kind, record = _case_anchor(records, case_id)
            if len(rows) != 1:
                _fail(failures, kind, record, "CURRENT_CASE_MISSING", head=True)
                continue
            row = rows[0]
            raw = row["case_json"]
            try:
                if not isinstance(raw, str):
                    raise TypeError
                case = Case.model_validate_json(raw)
                canonical = canonical_json(case.model_dump(mode="json"))
            except (TypeError, ValidationError, ValueError):
                _fail(failures, kind, record, "CURRENT_CASE_DOCUMENT_INVALID", head=True)
                continue
            digest = hashlib.sha256(raw.encode()).hexdigest()
            revision = row["current_revision"]
            if (
                canonical != raw
                or row["document_sha256"] != digest
                or not isinstance(revision, int)
                or isinstance(revision, bool)
                or row["manifest_id"] != manifest_id
                or case.run_id != run_id
                or case.case_id != case_id
                or row["current_status"] != row["status"]
                or row["status"] != case.status.value
            ):
                _fail(failures, kind, record, "CURRENT_CASE_INDEX_MISMATCH", head=True)
                continue
            maximum = connection.execute(
                "SELECT MAX(revision) FROM case_versions WHERE run_id = ? AND case_id = ?",
                (run_id, case_id),
            ).fetchone()
            if maximum is None or maximum[0] != revision:
                _fail(failures, kind, record, "CURRENT_CASE_NOT_LATEST", head=True)
                continue
            result[case_id] = _CurrentCase(case_id, revision, case.status.value, digest, case)
        return result

    @staticmethod
    def _validate_precedent_causal_ledger(
        *,
        precedents: tuple[tuple[M5Record, M5PrecedentAuthority], ...],
        citations: tuple[tuple[M5Record, M5CitationCommit], ...],
        conflict_batch_receipts: tuple[tuple[M5Record, M5PrecedentConflictBatchReceipt], ...],
        lifecycle_receipts: tuple[tuple[M5Record, LifecycleReceipt], ...],
        resolution_commits: tuple[tuple[M5Record, M5AppealResolutionCommitReceipt], ...],
        events: tuple[tuple[M5Record, M5PrecedentCausalEvent], ...],
        failures: list[M5ArtifactAuthorityFailure],
    ) -> None:
        """Prove one event per source, one source per event, and the full chain."""

        expected: dict[
            tuple[str, str],
            list[tuple[M5Record, tuple[object, ...]]],
        ] = defaultdict(list)
        for record, authority in precedents:
            key = (
                M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED.value,
                authority.authority_id,
            )
            expected[key].append(
                (
                    record,
                    (
                        authority.run_id,
                        M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED,
                        authority.authority_id,
                        authority.precedent.precedent_id,
                        authority.authority_id,
                        authority.revision,
                        None,
                        record.row["manifest_id"],
                        record.row["document_sha256"],
                    ),
                )
            )
        for record, commit in citations:
            citation = commit.citation
            citation_kind = M5PrecedentCausalEventSourceKind(str(record.row["citation_kind"]))
            key = (
                M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED.value,
                citation.citation_id,
            )
            expected[key].append(
                (
                    record,
                    (
                        citation.run_id,
                        M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED,
                        citation.citation_id,
                        citation.precedent_id,
                        citation.precedent_authority_id,
                        citation.precedent_revision,
                        citation_kind,
                        record.row["manifest_id"],
                        record.row["document_sha256"],
                    ),
                )
            )
        for record, batch_receipt in conflict_batch_receipts:
            key = (
                M5PrecedentCausalEventKind.PRECEDENT_CONFLICT_BATCH_COMMITTED.value,
                batch_receipt.receipt_id,
            )
            expected[key].append(
                (
                    record,
                    (
                        batch_receipt.run_id,
                        M5PrecedentCausalEventKind.PRECEDENT_CONFLICT_BATCH_COMMITTED,
                        batch_receipt.receipt_id,
                        None,
                        None,
                        None,
                        None,
                        record.row["manifest_id"],
                        record.row["document_sha256"],
                    ),
                )
            )
        for record, lifecycle_receipt in lifecycle_receipts:
            if not isinstance(lifecycle_receipt, M5PrecedentRevocationReceipt):
                continue
            key = (
                M5PrecedentCausalEventKind.PRECEDENT_REVOCATION_COMMITTED.value,
                lifecycle_receipt.receipt_id,
            )
            expected[key].append(
                (
                    record,
                    (
                        lifecycle_receipt.run_id,
                        M5PrecedentCausalEventKind.PRECEDENT_REVOCATION_COMMITTED,
                        lifecycle_receipt.receipt_id,
                        lifecycle_receipt.precedent_id,
                        lifecycle_receipt.resulting_authority_id,
                        lifecycle_receipt.resulting_revision,
                        None,
                        record.row["manifest_id"],
                        record.row["document_sha256"],
                    ),
                )
            )
        for record, appeal_commit in resolution_commits:
            key = (
                M5PrecedentCausalEventKind.APPEAL_RESOLUTION_COMMITTED.value,
                appeal_commit.receipt_id,
            )
            expected[key].append(
                (
                    record,
                    (
                        appeal_commit.run_id,
                        M5PrecedentCausalEventKind.APPEAL_RESOLUTION_COMMITTED,
                        appeal_commit.receipt_id,
                        None,
                        None,
                        None,
                        None,
                        appeal_commit.manifest_id,
                        record.row["document_sha256"],
                    ),
                )
            )

        observed: dict[
            tuple[str, str],
            list[tuple[M5Record, M5PrecedentCausalEvent]],
        ] = defaultdict(list)
        for record, event in events:
            observed[(event.event_kind.value, event.source_id)].append((record, event))

        for key, source_entries in expected.items():
            matches = observed.get(key, [])
            if len(source_entries) != 1:
                for source_record, _expected_binding in source_entries:
                    _fail(
                        failures,
                        M5AuthorityKind.PRECEDENT_CAUSAL_EVENT,
                        source_record,
                        M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_SOURCE_DUPLICATE.value,
                    )
            if not matches:
                for source_record, _expected_binding in source_entries:
                    _fail(
                        failures,
                        M5AuthorityKind.PRECEDENT_CAUSAL_EVENT,
                        source_record,
                        M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_EVENT_MISSING.value,
                    )
                continue
            if len(matches) != 1:
                for event_record, _event in matches:
                    _fail(
                        failures,
                        M5AuthorityKind.PRECEDENT_CAUSAL_EVENT,
                        event_record,
                        M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_EVENT_DUPLICATE.value,
                    )
                continue
            if len(source_entries) != 1:
                continue
            _source_record, expected_binding = source_entries[0]
            event_record, event = matches[0]
            actual_binding = (
                event.run_id,
                event.event_kind,
                event.source_id,
                event.precedent_id,
                event.precedent_authority_id,
                event.precedent_revision,
                event.citation_kind,
                event.manifest_id,
                event.source_document_sha256,
            )
            if actual_binding != expected_binding:
                _fail(
                    failures,
                    M5AuthorityKind.PRECEDENT_CAUSAL_EVENT,
                    event_record,
                    M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_EVENT_SOURCE_MISMATCH.value,
                )

        for key, matches in observed.items():
            if key not in expected:
                for event_record, _event in matches:
                    _fail(
                        failures,
                        M5AuthorityKind.PRECEDENT_CAUSAL_EVENT,
                        event_record,
                        M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_EVENT_ORPHAN.value,
                    )
            if len(matches) > 1:
                for event_record, _event in matches:
                    _fail(
                        failures,
                        M5AuthorityKind.PRECEDENT_CAUSAL_EVENT,
                        event_record,
                        M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_EVENT_DUPLICATE.value,
                    )

        ordered = tuple(sorted(events, key=lambda item: item[1].sequence))
        revocation_receipt_count = sum(
            isinstance(lifecycle_receipt, M5PrecedentRevocationReceipt)
            for _record, lifecycle_receipt in lifecycle_receipts
        )
        raw_source_count = (
            len(precedents)
            + len(citations)
            + len(conflict_batch_receipts)
            + revocation_receipt_count
            + len(resolution_commits)
        )
        chain_valid = len(ordered) == raw_source_count == len(events)
        last_authority_revision: dict[str, int] = {}
        authority_event_sequences: dict[tuple[str, str, int], int] = {}
        for ordinal, (_record, event) in enumerate(ordered, start=1):
            expected_previous = (
                M5_PRECEDENT_CAUSAL_GENESIS_SHA256
                if ordinal == 1
                else ordered[ordinal - 2][1].event_sha256
            )
            if event.sequence != ordinal or event.previous_event_sha256 != expected_previous:
                chain_valid = False
            if event.event_kind == M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED:
                precedent_id = event.precedent_id
                authority_id = event.precedent_authority_id
                revision = event.precedent_revision
                if precedent_id is None or authority_id is None or revision is None:
                    chain_valid = False
                    continue
                expected_revision = last_authority_revision.get(precedent_id, 0) + 1
                if revision != expected_revision:
                    chain_valid = False
                last_authority_revision[precedent_id] = revision
                authority_event_sequences[(precedent_id, authority_id, revision)] = event.sequence
            elif event.event_kind == M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED:
                precedent_id = event.precedent_id
                authority_id = event.precedent_authority_id
                revision = event.precedent_revision
                authority_sequence = (
                    None
                    if precedent_id is None or authority_id is None or revision is None
                    else authority_event_sequences.get((precedent_id, authority_id, revision))
                )
                if authority_sequence is None or authority_sequence >= event.sequence:
                    chain_valid = False
        event_at_sequence = {event.sequence: (record, event) for record, event in ordered}
        revocation_by_id = {
            lifecycle_receipt.receipt_id: lifecycle_receipt
            for _record, lifecycle_receipt in lifecycle_receipts
            if isinstance(lifecycle_receipt, M5PrecedentRevocationReceipt)
        }
        for commit_record, appeal_commit in resolution_commits:
            marker_matches = observed.get(
                (
                    M5PrecedentCausalEventKind.APPEAL_RESOLUTION_COMMITTED.value,
                    appeal_commit.receipt_id,
                ),
                [],
            )
            if len(marker_matches) != 1:
                _fail(
                    failures,
                    commit_record.kind,
                    commit_record,
                    M5AppealResolutionHistoryReasonCode.APPEAL_RESOLUTION_MARKER_MISSING_OR_INVALID.value,
                )
                continue
            marker = marker_matches[0][1]
            cursor = marker.sequence - 1
            interval_valid = True
            if appeal_commit.replacement_precedent_authority_id is not None:
                replacement_entry = event_at_sequence.get(cursor)
                if replacement_entry is None:
                    interval_valid = False
                else:
                    replacement = replacement_entry[1]
                    interval_valid = (
                        replacement.event_kind
                        == M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED
                        and replacement.source_id
                        == appeal_commit.replacement_precedent_authority_id
                        and replacement.precedent_authority_id
                        == appeal_commit.replacement_precedent_authority_id
                    )
                cursor -= 1
            observed_revocations: list[str] = []
            for _receipt_id in appeal_commit.precedent_revocation_receipt_ids:
                marker_entry = event_at_sequence.get(cursor)
                authority_entry = event_at_sequence.get(cursor - 1)
                if marker_entry is None or authority_entry is None:
                    interval_valid = False
                    break
                child_marker = marker_entry[1]
                child_authority = authority_entry[1]
                child_receipt = revocation_by_id.get(child_marker.source_id)
                if (
                    child_marker.event_kind
                    != M5PrecedentCausalEventKind.PRECEDENT_REVOCATION_COMMITTED
                    or child_authority.event_kind
                    != M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED
                    or child_authority.source_id != child_marker.precedent_authority_id
                    or child_authority.precedent_id != child_marker.precedent_id
                    or child_authority.precedent_revision != child_marker.precedent_revision
                    or child_receipt is None
                    or child_receipt.outcome.value != "REVOKED"
                ):
                    interval_valid = False
                    break
                observed_revocations.append(child_marker.source_id)
                cursor -= 2
            if (
                tuple(sorted(observed_revocations))
                != appeal_commit.precedent_revocation_receipt_ids
            ):
                interval_valid = False
            if not interval_valid:
                _fail(
                    failures,
                    commit_record.kind,
                    commit_record,
                    M5AppealResolutionHistoryReasonCode.APPEAL_RESOLUTION_CAUSAL_INTERVAL_INVALID.value,
                )
        if not chain_valid:
            anchor = ordered[0][0] if ordered else None
            _fail(
                failures,
                M5AuthorityKind.PRECEDENT_CAUSAL_EVENT,
                anchor,
                M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_EVENT_CHAIN_INVALID.value,
                head=True,
            )

    def _validate_precedents(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        manifest: RunManifest,
        config: AppConfig,
        records: dict[M5AuthorityKind, list[M5Record]],
        embeddings: tuple[tuple[M5Record, M5EmbeddingVector], ...],
        precedents: tuple[tuple[M5Record, M5PrecedentAuthority], ...],
        citations: tuple[tuple[M5Record, M5CitationCommit], ...],
        causal_events: tuple[tuple[M5Record, M5PrecedentCausalEvent], ...],
        conflict_batches: tuple[tuple[M5Record, M5PrecedentConflictBatchAuthority], ...],
        conflict_batch_receipts: tuple[tuple[M5Record, M5PrecedentConflictBatchReceipt], ...],
        alerts: tuple[tuple[M5Record, AlertPolicyAuthority], ...],
        appeals: tuple[tuple[M5Record, AppealVersionAuthority], ...],
        failures: list[M5ArtifactAuthorityFailure],
    ) -> None:
        trusted_policy = ConfiguredM5PrecedentPolicyVerifier(config).expected_policy(manifest)
        embedding_by_id = {item.embedding_id: (record, item) for record, item in embeddings}
        referenced_embeddings: set[str] = set()
        authorities: dict[tuple[str, int], tuple[M5Record, M5PrecedentAuthority]] = {}
        by_precedent: dict[str, list[tuple[M5Record, M5PrecedentAuthority]]] = defaultdict(list)
        for record, authority in precedents:
            precedent_id = authority.precedent.precedent_id
            authorities[(precedent_id, authority.revision)] = (record, authority)
            by_precedent[precedent_id].append((record, authority))
            embedded = (
                () if authority.text_embedding is None else (authority.text_embedding,)
            ) + authority.visual_embeddings
            for vector in embedded:
                referenced_embeddings.add(vector.embedding_id)
                durable = embedding_by_id.get(vector.embedding_id)
                if durable is None or durable[1] != vector:
                    _fail(failures, record.kind, record, "PRECEDENT_EMBEDDING_REFERENCE_INVALID")
        for embedding_id, (record, _embedding) in embedding_by_id.items():
            if embedding_id not in referenced_embeddings:
                _fail(failures, record.kind, record, "ORPHAN_PRECEDENT_EMBEDDING")

        resulting_authorities: CounterKey = defaultdict(int)
        for record, commit in citations:
            if isinstance(commit, M5PrecedentApplicationCitationCommit):
                continue
            citation = commit.citation
            historical = authorities.get((citation.precedent_id, citation.precedent_revision))
            replay_candidates: list[M5PrecedentAuthority] = []
            references_close = historical is not None and (
                historical[1].authority_id == citation.precedent_authority_id
            )
            for evaluation in commit.retrieval_result.candidate_evaluations:
                claimed = evaluation.authority
                durable_authority = authorities.get(
                    (claimed.precedent.precedent_id, claimed.revision)
                )
                if durable_authority is None or durable_authority[1] != claimed:
                    references_close = False
                    continue
                replay_candidates.append(durable_authority[1])
            if not references_close:
                _fail(failures, record.kind, record, "CITATION_AUTHORITY_REFERENCE_INVALID")
                continue
            try:
                rebuilt_result = ExactM5PrecedentRetrievalService().retrieve(
                    commit.retrieval_result.query,
                    tuple(replay_candidates),
                )
                rebuilt_commit = record_m5_precedent_citation(
                    result=rebuilt_result,
                    precedent_id=citation.precedent_id,
                    cited_at=citation.cited_at,
                )
            except (TypeError, ValidationError, ValueError, RuntimeError):
                _fail(failures, record.kind, record, "CITATION_RETRIEVAL_REPLAY_INVALID")
                continue
            if rebuilt_result != commit.retrieval_result or rebuilt_commit != commit:
                _fail(failures, record.kind, record, "CITATION_RETRIEVAL_REPLAY_INVALID")

        appeal_present_decisions: dict[tuple[str, str], int] = defaultdict(int)
        for record, receipt in _lifecycle_receipts(records):
            for precedent_id, authority_id, revision, is_result in _receipt_refs(receipt):
                lifecycle_durable = authorities.get((precedent_id, revision))
                if lifecycle_durable is None or lifecycle_durable[1].authority_id != authority_id:
                    _fail(failures, record.kind, record, "LIFECYCLE_AUTHORITY_REFERENCE_INVALID")
                if is_result and revision > 1:
                    resulting_authorities[(precedent_id, revision)] += 1
            if isinstance(receipt, M5PrecedentActivationReceipt):
                if receipt.outcome.value == "APPEAL_PRESENT":
                    appeal_present_decisions[
                        (receipt.precedent_id, receipt.prior_authority_id)
                    ] += 1
                self._validate_activation_receipt(
                    connection=connection,
                    run_id=run_id,
                    record=record,
                    receipt=receipt,
                    authorities=authorities,
                    alerts=alerts,
                    appeals=appeals,
                    failures=failures,
                )
            elif isinstance(receipt, M5PrecedentConflictReceipt):
                existing_prior = authorities.get(
                    (receipt.existing_precedent_id, receipt.existing_prior_revision)
                )
                new_prior = authorities.get((receipt.new_precedent_id, receipt.new_prior_revision))
                existing_result = authorities.get(
                    (receipt.existing_precedent_id, receipt.existing_resulting_revision)
                )
                new_result = authorities.get(
                    (receipt.new_precedent_id, receipt.new_resulting_revision)
                )
                try:
                    raw_context = record.row["context_json"]
                    if not isinstance(raw_context, str):
                        raise TypeError
                    stored_policy = M5PrecedentPolicy.model_validate_json(raw_context)
                    if stored_policy != trusted_policy:
                        raise ValueError
                    if existing_prior is None or new_prior is None:
                        raise ValueError
                    rebuilt_conflict = resolve_m5_precedent_conflict(
                        existing=existing_prior[1],
                        new=new_prior[1],
                        policy=trusted_policy,
                    )
                except (TypeError, ValidationError, ValueError, RuntimeError):
                    _fail(
                        failures,
                        record.kind,
                        record,
                        "LEGACY_CONFLICT_POLICY_REPLAY_INVALID",
                    )
                    continue
                if (
                    existing_result is None
                    or new_result is None
                    or rebuilt_conflict.receipt != receipt
                    or rebuilt_conflict.existing_authority != existing_result[1]
                    or rebuilt_conflict.new_authority != new_result[1]
                ):
                    _fail(
                        failures,
                        record.kind,
                        record,
                        "LEGACY_CONFLICT_POLICY_REPLAY_INVALID",
                    )
            elif isinstance(receipt, M5PrecedentRevocationReceipt):
                try:
                    raw_context = record.row["context_json"]
                    if not isinstance(raw_context, str):
                        raise TypeError
                    citation_snapshot = M5PrecedentCitationSnapshot.model_validate_json(raw_context)
                    if canonical_json(citation_snapshot.model_dump(mode="json")) != raw_context:
                        raise ValueError
                    rebuild_m5_precedent_revocation_history(
                        authorities=tuple(authority for _record, authority in precedents),
                        citations=tuple(commit.citation for _record, commit in citations),
                        causal_events=tuple(event for _record, event in causal_events),
                        receipt=receipt,
                        citation_snapshot=citation_snapshot,
                    )
                except M5PrecedentRevocationHistoryError as exc:
                    _fail(
                        failures,
                        record.kind,
                        record,
                        _REVOCATION_HISTORY_REASON_BY_ERROR[exc.code].value,
                    )
                except (TypeError, ValidationError, ValueError, RuntimeError):
                    _fail(
                        failures,
                        record.kind,
                        record,
                        M5PrecedentRevocationHistoryReasonCode.REVOCATION_RECEIPT_CLOSURE_INVALID.value,
                    )
                    continue

        for record, receipt in _lifecycle_receipts(records):
            if (
                isinstance(receipt, M5PrecedentActivationReceipt)
                and receipt.outcome.value == "APPEAL_PRESENT"
                and appeal_present_decisions[(receipt.precedent_id, receipt.prior_authority_id)]
                != 1
            ):
                _fail(
                    failures,
                    record.kind,
                    record,
                    M5ActivationAuthorityReasonCode.ACTIVATION_REPLAY_MISMATCH,
                )

        receipts_by_batch: dict[
            str,
            list[tuple[M5Record, M5PrecedentConflictBatchReceipt]],
        ] = defaultdict(list)
        for batch_receipt_record, batch_receipt in conflict_batch_receipts:
            receipts_by_batch[batch_receipt.batch_authority_id].append(
                (batch_receipt_record, batch_receipt)
            )
        consumed_receipts: set[str] = set()
        for batch_record, batch in conflict_batches:
            matching_receipts = receipts_by_batch.get(batch.batch_authority_id, [])
            if len(matching_receipts) != 1:
                _fail(
                    failures,
                    batch_record.kind,
                    batch_record,
                    "CONFLICT_BATCH_RECEIPT_CLOSURE_INVALID",
                )
                continue
            batch_receipt_record, batch_receipt = matching_receipts[0]
            consumed_receipts.add(batch_receipt.receipt_id)
            raw_policy = batch_record.row["policy_json"]
            try:
                if not isinstance(raw_policy, str):
                    raise TypeError
                stored_policy = M5PrecedentPolicy.model_validate_json(raw_policy)
                if stored_policy != trusted_policy:
                    raise M5PrecedentConflictHistoryError(
                        M5PrecedentConflictHistoryErrorCode.TRUSTED_POLICY_MISMATCH
                    )
                rebuild_m5_precedent_conflict_history(
                    authorities=tuple(item for _record, item in precedents),
                    causal_events=tuple(item for _record, item in causal_events),
                    trusted_policy=trusted_policy,
                    batch_authority=batch,
                    receipt=batch_receipt,
                )
            except M5PrecedentConflictHistoryError as exc:
                _fail(
                    failures,
                    batch_record.kind,
                    batch_record,
                    _CONFLICT_HISTORY_REASON_BY_ERROR[exc.code].value,
                )
                continue
            except (TypeError, ValidationError, ValueError, RuntimeError):
                _fail(
                    failures,
                    batch_record.kind,
                    batch_record,
                    M5PrecedentConflictHistoryReasonCode.CONFLICT_BATCH_POLICY_REPLAY_INVALID,
                )
                continue
            for node in batch_receipt.results:
                if node.resulting_revision > node.prior_revision:
                    resulting_authorities[(node.precedent_id, node.resulting_revision)] += 1
        for batch_receipt_record, batch_receipt in conflict_batch_receipts:
            if batch_receipt.receipt_id not in consumed_receipts:
                _fail(
                    failures,
                    batch_receipt_record.kind,
                    batch_receipt_record,
                    "ORPHAN_CONFLICT_BATCH_RECEIPT",
                )

        for precedent_id, revisions in by_precedent.items():
            ordered = sorted(revisions, key=lambda item: item[1].revision)
            if [item.revision for _record, item in ordered] != list(range(1, len(ordered) + 1)):
                _fail(
                    failures,
                    ordered[0][0].kind,
                    ordered[0][0],
                    "PRECEDENT_HEAD_NOT_CONTIGUOUS",
                    head=True,
                )
                continue
            _head_record, _head = ordered[-1]
            for successor_record, successor in ordered[1:]:
                if resulting_authorities[(precedent_id, successor.revision)] != 1:
                    _fail(
                        failures,
                        successor_record.kind,
                        successor_record,
                        "PRECEDENT_SUCCESSOR_RECEIPT_CLOSURE_INVALID",
                    )

    def _validate_activation_receipt(
        self,
        *,
        connection: sqlite3.Connection,
        run_id: str,
        record: M5Record,
        receipt: M5PrecedentActivationReceipt,
        authorities: Mapping[
            tuple[str, int],
            tuple[M5Record, M5PrecedentAuthority],
        ],
        alerts: tuple[tuple[M5Record, AlertPolicyAuthority], ...],
        appeals: tuple[tuple[M5Record, AppealVersionAuthority], ...],
        failures: list[M5ArtifactAuthorityFailure],
    ) -> None:
        try:
            raw_context = record.row["context_json"]
            if not isinstance(raw_context, str):
                raise TypeError
            snapshot = M5AppealWindowSnapshot.model_validate_json(raw_context)
            if canonical_json(snapshot.model_dump(mode="json")) != raw_context:
                raise ValueError
        except (TypeError, ValidationError, ValueError):
            _fail(
                failures,
                record.kind,
                record,
                M5ActivationAuthorityReasonCode.ACTIVATION_SOURCE_CASE_CUT_INVALID,
            )
            return

        prior = authorities.get((receipt.precedent_id, receipt.prior_revision))
        resulting = authorities.get((receipt.precedent_id, receipt.resulting_revision))
        cut = _load_case_version(
            connection,
            run_id,
            snapshot.source_case_id,
            snapshot.source_case_revision,
        )
        if (
            cut is None
            or cut[0] != snapshot.source_case_document_sha256
            or snapshot.run_id != run_id
        ):
            _fail(
                failures,
                record.kind,
                record,
                M5ActivationAuthorityReasonCode.ACTIVATION_SOURCE_CASE_CUT_INVALID,
            )
            return
        source_case = cut[1]

        case_alerts = tuple(
            (alert_record, alert)
            for alert_record, alert in alerts
            if alert.request.case_id == snapshot.source_case_id
        )
        closing_revision: int | None = None
        if len(case_alerts) == 1:
            raw_closing_revision = case_alerts[0][0].row["closing_case_revision"]
            if isinstance(raw_closing_revision, int) and not isinstance(raw_closing_revision, bool):
                closing_revision = raw_closing_revision
        causal_state_valid = (
            prior is not None
            and prior[1].authority_id == receipt.prior_authority_id
            and prior[1].precedent.source == PrecedentSource.AUTOMATIC
            and prior[1].precedent.source_case_id == snapshot.source_case_id
            and receipt.run_id == run_id
            and snapshot.observed_through == receipt.evaluated_at
            and source_case.run_id == run_id
            and source_case.case_id == snapshot.source_case_id
            and closing_revision is not None
        )
        if closing_revision is not None:
            if snapshot.appeal_ids:
                causal_state_valid = causal_state_valid and (
                    closing_revision < snapshot.source_case_revision <= closing_revision + 3
                    and source_case.status in {CaseStatus.APPEALED, CaseStatus.APPEAL_RESOLVED}
                )
            else:
                causal_state_valid = causal_state_valid and (
                    snapshot.source_case_revision == closing_revision
                    and source_case.status == CaseStatus.CLOSED
                )
        if not causal_state_valid:
            _fail(
                failures,
                record.kind,
                record,
                M5ActivationAuthorityReasonCode.ACTIVATION_CASE_CAUSAL_STATE_INVALID,
            )

        inventory_valid = closing_revision is not None and self._activation_appeal_chain_is_valid(
            connection=connection,
            run_id=run_id,
            snapshot=snapshot,
            source_case=source_case,
            closing_revision=closing_revision or 0,
            appeals=appeals,
        )
        if not inventory_valid:
            _fail(
                failures,
                record.kind,
                record,
                M5ActivationAuthorityReasonCode.ACTIVATION_APPEAL_INVENTORY_MISMATCH,
            )

        rebuilt = None
        if prior is not None:
            try:
                rebuilt = evaluate_m5_automatic_activation(
                    authority=prior[1],
                    appeal_snapshot=snapshot,
                    evaluated_at=receipt.evaluated_at,
                )
            except (TypeError, ValidationError, ValueError, RuntimeError):
                rebuilt = None
        if (
            rebuilt is None
            or resulting is None
            or rebuilt.receipt != receipt
            or rebuilt.authority != resulting[1]
        ):
            _fail(
                failures,
                record.kind,
                record,
                M5ActivationAuthorityReasonCode.ACTIVATION_REPLAY_MISMATCH,
            )

    @staticmethod
    def _activation_appeal_chain_is_valid(
        *,
        connection: sqlite3.Connection,
        run_id: str,
        snapshot: M5AppealWindowSnapshot,
        source_case: Case,
        closing_revision: int,
        appeals: tuple[tuple[M5Record, AppealVersionAuthority], ...],
    ) -> bool:
        case_appeal_ids = tuple(sorted(item.appeal_id for item in source_case.appeals))
        if case_appeal_ids != snapshot.appeal_ids or len(case_appeal_ids) != len(
            set(case_appeal_ids)
        ):
            return False
        offset = snapshot.source_case_revision - closing_revision
        if offset == 0:
            return not source_case.appeals
        if offset not in {1, 2, 3} or len(source_case.appeals) != 1:
            return False
        appeal_id = source_case.appeals[0].appeal_id
        previous = _load_case_version(
            connection,
            run_id,
            snapshot.source_case_id,
            closing_revision,
        )
        if previous is None or previous[1].status != CaseStatus.CLOSED:
            return False
        source_authority_sha256: str | None = None
        for version in range(1, offset + 1):
            matching = tuple(
                authority
                for _record, authority in appeals
                if authority.appeal.case_id == snapshot.source_case_id
                and authority.appeal.appeal_id == appeal_id
                and authority.source_case_revision == closing_revision
                and authority.version == version
            )
            current = _load_case_version(
                connection,
                run_id,
                snapshot.source_case_id,
                closing_revision + version,
            )
            if len(matching) != 1 or current is None:
                return False
            authority = matching[0]
            if source_authority_sha256 is None:
                source_authority_sha256 = authority.source_case_authority_sha256
            if (
                authority.source_case_authority_sha256 != source_authority_sha256
                or authority.source_case_authority.case_revision != closing_revision
            ):
                return False
            if version == 1 and authority.source_case_authority.effective_appeal_ids != tuple(
                sorted(item.appeal_id for item in previous[1].appeals)
            ):
                return False
            if (
                not current[1].appeals
                or current[1].appeals[-1] != authority.appeal
                or m5_case_transition_audit(previous[1], current[1])
                != (
                    AuditAction.CASE_STATE_CHANGED,
                    ArtifactRef(kind=ArtifactKind.APPEAL, artifact_id=appeal_id),
                )
            ):
                return False
            audit_row = connection.execute(
                """
                SELECT ae.*
                FROM case_versions AS cv
                JOIN audit_entries AS ae
                  ON ae.run_id = cv.run_id AND ae.sequence = cv.audit_sequence
                WHERE cv.run_id = ? AND cv.case_id = ? AND cv.revision = ?
                """,
                (run_id, snapshot.source_case_id, closing_revision + version),
            ).fetchone()
            audit = _parse_audit_entry(audit_row) if audit_row is not None else None
            if (
                audit is None
                or audit.actor != AuditActorRole.SYSTEM.value
                or audit.action != AuditAction.CASE_STATE_CHANGED
                or audit.object_ref != ArtifactRef(kind=ArtifactKind.APPEAL, artifact_id=appeal_id)
                or audit.before_sha256 != previous[0]
                or audit.after_sha256 != current[0]
                or audit.manifest_id != source_case.manifest_id
            ):
                return False
            previous = current
        return previous[0] == snapshot.source_case_document_sha256 and previous[1] == source_case

    def _validate_precedent_usage(
        self,
        *,
        connection: sqlite3.Connection,
        run_id: str,
        manifest: RunManifest,
        config: AppConfig,
        exposures: tuple[tuple[M5Record, M5PrecedentExposureBatchAuthority], ...],
        application_batches: tuple[tuple[M5Record, M5PrecedentApplicationBatchAuthority], ...],
        citations: tuple[tuple[M5Record, M5CitationCommit], ...],
        precedents: tuple[tuple[M5Record, M5PrecedentAuthority], ...],
        alerts: tuple[tuple[M5Record, AlertPolicyAuthority], ...],
        failures: list[M5ArtifactAuthorityFailure],
    ) -> None:
        """Prove EXPOSED/APPLIED roots against immutable M4 and M5 history."""

        authorities = {
            (authority.precedent.precedent_id, authority.revision): authority
            for _record, authority in precedents
        }
        exposures_by_id: dict[
            str,
            list[tuple[M5Record, M5PrecedentExposureBatchAuthority]],
        ] = defaultdict(list)
        exposures_by_cycle: dict[
            str,
            list[tuple[M5Record, M5PrecedentExposureBatchAuthority]],
        ] = defaultdict(list)
        policy_verifier = ConfiguredM5PrecedentPolicyVerifier(config)
        expected_policy = policy_verifier.expected_policy(manifest)
        for exposure_record, exposure in exposures:
            exposures_by_id[exposure.exposure_id].append((exposure_record, exposure))
            exposures_by_cycle[exposure.cycle_scope_id].append((exposure_record, exposure))
            durable_receipt = _load_exact_m4_document(
                connection,
                run_id=run_id,
                table="m4_precedent_retrieval_receipts",
                artifact_id=exposure.m4_retrieval_outcome.receipt.receipt_id,
            )
            receipt_exact = (
                durable_receipt is not None
                and isinstance(durable_receipt.document, HearingPrecedentRetrievalReceipt)
                and durable_receipt.document == exposure.m4_retrieval_outcome.receipt
            )
            if not receipt_exact:
                _fail(
                    failures,
                    exposure_record.kind,
                    exposure_record,
                    "PRECEDENT_EXPOSURE_M4_RECEIPT_INVALID",
                )

            trusted_query = None
            try:
                trusted_query = derive_m5_query_for_hearing(
                    query=exposure.m4_retrieval_outcome.query,
                    manifest=manifest,
                    policy=expected_policy,
                    run_mode=policy_verifier.run_mode,
                )
            except (TypeError, ValidationError, ValueError, RuntimeError):
                trusted_query = None
            query_exact = trusted_query == exposure.m5_retrieval_result.query
            if not query_exact:
                _fail(
                    failures,
                    exposure_record.kind,
                    exposure_record,
                    "PRECEDENT_EXPOSURE_TRUSTED_QUERY_MISMATCH",
                )

            replay_candidates: list[M5PrecedentAuthority] = []
            historical_exact = True
            for evaluation in exposure.m5_retrieval_result.candidate_evaluations:
                claimed = evaluation.authority
                durable = authorities.get((claimed.precedent.precedent_id, claimed.revision))
                if durable != claimed:
                    historical_exact = False
                else:
                    replay_candidates.append(durable)
            rebuilt_result = None
            if historical_exact and query_exact and trusted_query is not None:
                try:
                    rebuilt_result = ExactM5PrecedentRetrievalService().retrieve(
                        trusted_query,
                        tuple(replay_candidates),
                    )
                except (TypeError, ValidationError, ValueError, RuntimeError):
                    rebuilt_result = None
            if rebuilt_result != exposure.m5_retrieval_result:
                _fail(
                    failures,
                    exposure_record.kind,
                    exposure_record,
                    "PRECEDENT_EXPOSURE_RETRIEVAL_REPLAY_INVALID",
                )

        batches_by_id: dict[
            str,
            list[tuple[M5Record, M5PrecedentApplicationBatchAuthority]],
        ] = defaultdict(list)
        batches_by_case: dict[
            str,
            list[tuple[M5Record, M5PrecedentApplicationBatchAuthority]],
        ] = defaultdict(list)
        for batch_record, batch in application_batches:
            batches_by_id[batch.application_batch_id].append((batch_record, batch))
            batches_by_case[batch.case_id].append((batch_record, batch))

        applied_by_batch: dict[
            str,
            list[tuple[M5Record, M5PrecedentApplicationCitationCommit]],
        ] = defaultdict(list)
        applied_by_case: dict[
            str,
            list[tuple[M5Record, M5PrecedentApplicationCitationCommit]],
        ] = defaultdict(list)
        for citation_record, commit in citations:
            if not isinstance(commit, M5PrecedentApplicationCitationCommit):
                continue
            batch_id = commit.application_batch.application_batch_id
            applied_by_batch[batch_id].append((citation_record, commit))
            applied_by_case[commit.citation.case_id].append((citation_record, commit))

        verifier = ConfiguredM5PrecedentApplicationVerifier(config)
        for batch_record, batch in application_batches:
            durable_exposures = exposures_by_id.get(batch.exposure.exposure_id, [])
            exposure_exact = (
                len(durable_exposures) == 1 and durable_exposures[0][1] == batch.exposure
            )
            if not exposure_exact:
                _fail(
                    failures,
                    batch_record.kind,
                    batch_record,
                    "APPLICATION_BATCH_EXPOSURE_REFERENCE_INVALID",
                )

            ready = _load_case_version(
                connection,
                run_id,
                batch.case_id,
                batch.ready_case_revision,
            )
            durable_verdict = _load_exact_verdict(
                connection,
                run_id=run_id,
                case_id=batch.case_id,
                verdict=batch.verdict,
            )
            final_usage = _load_final_hearing_usage(
                connection,
                run_id=run_id,
                case_id=batch.case_id,
                verdict=batch.verdict,
            )
            batch_roots_exact = (
                ready is not None
                and ready[0] == batch.ready_case_document_sha256
                and ready[1] == batch.ready_case
                and durable_verdict == batch.verdict
                and final_usage is not None
                and final_usage.hearing_round.precedent_retrieval_receipt.status
                == HearingPrecedentRetrievalStatus.SUCCESS
                and final_usage.hearing_round.cycle_scope_id == batch.exposure.cycle_scope_id
                and final_usage.hearing_round.cycle_scope_sha256
                == batch.exposure.cycle_scope_sha256
                and final_usage.hearing_round.precedent_retrieval_receipt
                == batch.exposure.m4_retrieval_outcome.receipt
            )
            if not batch_roots_exact:
                _fail(
                    failures,
                    batch_record.kind,
                    batch_record,
                    "APPLICATION_BATCH_READY_VERDICT_FINAL_ROUND_INVALID",
                )

            rebuilt_batch = None
            if exposure_exact and ready is not None:
                try:
                    rebuilt_batch = verifier.rebuild_application(
                        CaseSnapshot(case=ready[1], revision=batch.ready_case_revision),
                        durable_exposures[0][1],
                    )
                except (TypeError, ValidationError, ValueError, RuntimeError):
                    rebuilt_batch = None
            if rebuilt_batch != batch:
                _fail(
                    failures,
                    batch_record.kind,
                    batch_record,
                    "APPLICATION_BATCH_CONFIG_REPLAY_INVALID",
                )

            commits = applied_by_batch.get(batch.application_batch_id, [])
            expected_bindings = {
                binding.binding_id: binding for binding in batch.application_bindings
            }
            by_binding: dict[
                str,
                tuple[M5Record, M5PrecedentApplicationCitationCommit],
            ] = {}
            citations_exact = len(commits) == len(expected_bindings)
            for citation_record, commit in commits:
                binding_id = commit.application_binding.binding_id
                expected_binding = expected_bindings.get(binding_id)
                evaluation_score = (
                    commit.application_binding.exposure_item.candidate_evaluation.score
                )
                if (
                    commit.application_batch != batch
                    or expected_binding is None
                    or commit.application_binding != expected_binding
                    or binding_id in by_binding
                    or evaluation_score is None
                    or commit.citation.score != evaluation_score
                ):
                    citations_exact = False
                    _fail(
                        failures,
                        citation_record.kind,
                        citation_record,
                        "APPLICATION_CITATION_BINDING_OR_SCORE_INVALID",
                    )
                    continue
                by_binding[binding_id] = (citation_record, commit)
            ordered_commits = tuple(
                by_binding[binding.binding_id][1]
                for binding in batch.application_bindings
                if binding.binding_id in by_binding
            )
            if len(ordered_commits) != len(batch.application_bindings):
                citations_exact = False
            if ordered_commits:
                cited_at_values = {commit.citation.cited_at for commit in ordered_commits}
                if len(cited_at_values) != 1:
                    citations_exact = False
                else:
                    try:
                        rebuilt_citations = verifier.rebuild_citations(
                            batch,
                            next(iter(cited_at_values)),
                        )
                    except (TypeError, ValidationError, ValueError, RuntimeError):
                        rebuilt_citations = ()
                    if rebuilt_citations != ordered_commits:
                        citations_exact = False
            if not citations_exact:
                _fail(
                    failures,
                    batch_record.kind,
                    batch_record,
                    "APPLICATION_BATCH_CITATION_CLOSURE_INVALID",
                )

        for batch_id, commits in applied_by_batch.items():
            durable_batches = batches_by_id.get(batch_id, [])
            for citation_record, commit in commits:
                if len(durable_batches) != 1 or durable_batches[0][1] != commit.application_batch:
                    _fail(
                        failures,
                        citation_record.kind,
                        citation_record,
                        "ORPHAN_APPLICATION_CITATION",
                    )

        alert_cases: set[str] = set()
        for alert_record, alert in alerts:
            case_id = alert.request.case_id
            alert_cases.add(case_id)
            try:
                source_revision = _required_integer(alert_record.row, "source_case_revision")
                closing_revision = _required_integer(alert_record.row, "closing_case_revision")
            except ValueError:
                source_revision = 0
                closing_revision = 0
            source = _load_case_version(connection, run_id, case_id, source_revision)
            case_batches = batches_by_case.get(case_id, [])
            case_citations = applied_by_case.get(case_id, [])
            roots_absent = not case_batches and not case_citations
            if source is None or not source[1].verdicts:
                _fail(
                    failures,
                    alert_record.kind,
                    alert_record,
                    "PRECEDENT_USAGE_READY_CASE_INVALID",
                )
                continue
            verdict = source[1].verdicts[-1]
            binding_rows = connection.execute(
                """
                SELECT * FROM m4_hearing_verdict_bindings
                WHERE run_id = ? AND case_id = ?
                  AND verdict_id = ? AND verdict_version = ?
                LIMIT 2
                """,
                (run_id, case_id, verdict.verdict_id, verdict.version),
            ).fetchall()
            if not binding_rows:
                if (
                    _verdict_has_m4_response_origin(connection, run_id, verdict)
                    or verdict.precedent_applications
                    or not roots_absent
                ):
                    _fail(
                        failures,
                        alert_record.kind,
                        alert_record,
                        "FAST_PRECEDENT_USAGE_ROOTS_INVALID",
                    )
                continue
            final_usage = _load_final_hearing_usage(
                connection,
                run_id=run_id,
                case_id=case_id,
                verdict=verdict,
            )
            if len(binding_rows) != 1 or final_usage is None:
                _fail(
                    failures,
                    alert_record.kind,
                    alert_record,
                    "FINAL_PRECEDENT_USAGE_HEARING_BINDING_INVALID",
                )
                continue
            hearing_round = final_usage.hearing_round
            if (
                hearing_round.precedent_retrieval_receipt.status
                == HearingPrecedentRetrievalStatus.DEGRADED
            ):
                final_exposures = exposures_by_cycle.get(hearing_round.cycle_scope_id, [])
                if final_exposures or verdict.precedent_applications or not roots_absent:
                    _fail(
                        failures,
                        alert_record.kind,
                        alert_record,
                        "FINAL_DEGRADED_PRECEDENT_USAGE_ROOTS_INVALID",
                    )
                continue

            final_exposures = exposures_by_cycle.get(hearing_round.cycle_scope_id, [])
            final_exposure = final_exposures[0][1] if len(final_exposures) == 1 else None
            case_batch = case_batches[0][1] if len(case_batches) == 1 else None
            if (
                final_exposure is None
                or final_exposure.m4_retrieval_outcome.receipt
                != hearing_round.precedent_retrieval_receipt
                or case_batch is None
                or case_batch.exposure != final_exposure
                or case_batch.ready_case_revision != source_revision
                or case_batch.ready_case != source[1]
                or case_batches[0][0].row["closing_case_revision"] != closing_revision
            ):
                _fail(
                    failures,
                    alert_record.kind,
                    alert_record,
                    "FINAL_EXPOSED_APPLICATION_BATCH_CLOSURE_INVALID",
                )

        for batch_record, batch in application_batches:
            if batch.case_id not in alert_cases:
                _fail(
                    failures,
                    batch_record.kind,
                    batch_record,
                    "ORPHAN_APPLICATION_BATCH",
                )

    def _validate_alerts(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        manifest: RunManifest,
        config: AppConfig,
        records: dict[M5AuthorityKind, list[M5Record]],
        cases: dict[str, _CurrentCase],
        embeddings: tuple[tuple[M5Record, M5EmbeddingVector], ...],
        precedents: tuple[tuple[M5Record, M5PrecedentAuthority], ...],
        alerts: tuple[tuple[M5Record, AlertPolicyAuthority], ...],
        cooldowns: tuple[tuple[M5Record, AlertCooldownAuthority], ...],
        outbox: tuple[tuple[M5Record, AlertOutboxItem], ...],
        capabilities: tuple[tuple[M5Record, AlertChannelCapabilityAuthority], ...],
        attempts: tuple[tuple[M5Record, AlertDispatchAttempt], ...],
        receipts: tuple[tuple[M5Record, AlertDispatchReceipt], ...],
        failures: list[M5ArtifactAuthorityFailure],
    ) -> _AlertPolicyCausalValidation:
        alert_by_id = {
            authority.decision.alert_id: (record, authority)
            for record, authority in alerts
            if authority.decision is not None
        }
        causal_validation = self._validate_alert_automatic_precedent_closure(
            connection=connection,
            run_id=run_id,
            manifest=manifest,
            config=config,
            embeddings=embeddings,
            precedents=precedents,
            alerts=alerts,
            cooldowns=cooldowns,
            failures=failures,
        )
        outbox_by_id = {item.outbox_id: (record, item) for record, item in outbox}
        capability_by_id: dict[str, tuple[M5Record, AlertChannelCapabilityAuthority]] = {}
        capability_by_channel: dict[str, tuple[M5Record, AlertChannelCapabilityAuthority]] = {}
        for record, capability in capabilities:
            if (
                capability.run_id != run_id
                or capability.config_sha256 != manifest.config_sha256
                or capability.manifest_id != manifest.manifest_id
            ):
                _fail(
                    failures,
                    record.kind,
                    record,
                    "ALERT_CHANNEL_CAPABILITY_RUN_MANIFEST_CONFIG_MISMATCH",
                    head=True,
                )
            if capability.capability_id in capability_by_id:
                _fail(
                    failures,
                    record.kind,
                    record,
                    "DUPLICATE_ALERT_CHANNEL_CAPABILITY_ID",
                    head=True,
                )
            else:
                capability_by_id[capability.capability_id] = (record, capability)
            if capability.channel in capability_by_channel:
                _fail(
                    failures,
                    record.kind,
                    record,
                    "ALERT_CHANNEL_CAPABILITY_CHANGED_FOR_CHANNEL",
                    head=True,
                )
            else:
                capability_by_channel[capability.channel] = (record, capability)
        referenced_capability_ids: set[str] = set()
        cooldown_refs: set[str] = set()
        outbox_refs: set[str] = set()
        for record, authority in alerts:
            request = authority.request
            row = record.row
            source = _load_case_version(
                connection,
                run_id,
                request.case_id,
                row["source_case_revision"],
            )
            closing = _load_case_version(
                connection,
                run_id,
                request.case_id,
                row["closing_case_revision"],
            )
            if (
                source is None
                or sha256_hex(["alert-case-authority", 1, source[1].model_dump(mode="json")])
                != request.case_authority_sha256
                or source[1].status != CaseStatus.READY_FOR_ALERT_POLICY
                or closing is None
                or closing[1].status != CaseStatus.CLOSED
                or closing[1].final_decision != authority.final_decision
                or (authority.decision is not None and authority.decision not in closing[1].alerts)
            ):
                _fail(failures, record.kind, record, "ALERT_CASE_REVISION_CLOSURE_INVALID")
            if request.case_id not in cases:
                _fail(failures, record.kind, record, "ALERT_CURRENT_CASE_MISSING", head=True)
            if authority.cooldown_write is not None:
                cooldown_refs.add(authority.cooldown_write.authority_id)
                matches = [item for _source, item in cooldowns if item == authority.cooldown_write]
                if len(matches) != 1:
                    _fail(failures, record.kind, record, "ALERT_COOLDOWN_CLOSURE_INVALID")
                else:
                    cooldown_row = next(
                        source.row for source, item in cooldowns if item == authority.cooldown_write
                    )
                    if cooldown_row["stream_authority_sha256"] != request.stream_authority_sha256:
                        _fail(failures, record.kind, record, "COOLDOWN_STREAM_AUTHORITY_MISMATCH")
            if authority.outbox_item is not None:
                outbox_refs.add(authority.outbox_item.outbox_id)
                durable = outbox_by_id.get(authority.outbox_item.outbox_id)
                if (
                    durable is None
                    or durable[1] != authority.outbox_item
                    or durable[0].row["alert_authority_id"] != authority.authority_id
                ):
                    _fail(failures, record.kind, record, "ALERT_OUTBOX_CLOSURE_INVALID")

        for record, cooldown in cooldowns:
            if cooldown.authority_id not in cooldown_refs:
                _fail(failures, record.kind, record, "ORPHAN_ALERT_COOLDOWN")
        for record, item in outbox:
            if item.outbox_id not in outbox_refs:
                _fail(failures, record.kind, record, "ORPHAN_ALERT_OUTBOX")
            if item.alert.alert_id not in alert_by_id:
                _fail(failures, record.kind, record, "OUTBOX_ALERT_REFERENCE_INVALID")

        attempts_by_outbox: dict[str, list[tuple[M5Record, AlertDispatchAttempt]]] = defaultdict(
            list
        )
        for record, attempt in attempts:
            attempts_by_outbox[attempt.outbox_id].append((record, attempt))
            durable = outbox_by_id.get(attempt.outbox_id)
            if (
                durable is None
                or attempt.alert_id != durable[1].alert.alert_id
                or attempt.case_id != durable[1].case_id
            ):
                _fail(failures, record.kind, record, "DISPATCH_OUTBOX_REFERENCE_INVALID")
            durable_capability = capability_by_id.get(attempt.channel_capability.capability_id)
            if durable_capability is None or durable_capability[1] != attempt.channel_capability:
                _fail(
                    failures,
                    record.kind,
                    record,
                    "DISPATCH_CHANNEL_CAPABILITY_ROOT_INVALID",
                    head=True,
                )
            else:
                referenced_capability_ids.add(attempt.channel_capability.capability_id)
        for record, capability in capabilities:
            if capability.capability_id not in referenced_capability_ids:
                _fail(
                    failures,
                    record.kind,
                    record,
                    "ORPHAN_ALERT_CHANNEL_CAPABILITY",
                    head=True,
                )
        attempt_by_id: dict[str, tuple[M5Record, AlertDispatchAttempt]] = {}
        for record, attempt in attempts:
            if attempt.attempt_id in attempt_by_id:
                _fail(failures, record.kind, record, "DUPLICATE_DISPATCH_ATTEMPT_ID")
            else:
                attempt_by_id[attempt.attempt_id] = (record, attempt)

        receipts_by_attempt: dict[str, list[tuple[M5Record, AlertDispatchReceipt]]] = defaultdict(
            list
        )
        successful: dict[str, int] = defaultdict(int)
        for record, receipt in receipts:
            receipts_by_attempt[receipt.attempt_id].append((record, receipt))
            durable_attempt = attempt_by_id.get(receipt.attempt_id)
            if durable_attempt is None or (
                durable_attempt[1].outbox_id,
                durable_attempt[1].alert_id,
                durable_attempt[1].case_id,
                durable_attempt[1].attempt_number,
                durable_attempt[1].fence,
                durable_attempt[1].lease_owner_sha256,
                durable_attempt[1].started_at,
                durable_attempt[1].lease_expires_at,
                durable_attempt[1].channel_capability,
                durable_attempt[1].idempotency_key,
            ) != (
                receipt.outbox_id,
                receipt.alert_id,
                receipt.case_id,
                receipt.attempt_number,
                receipt.fence,
                receipt.lease_owner_sha256,
                receipt.started_at,
                receipt.lease_expires_at,
                receipt.channel_capability,
                receipt.idempotency_key,
            ):
                _fail(failures, record.kind, record, "DISPATCH_ATTEMPT_REFERENCE_INVALID")
            if receipt.disposition == AlertDispatchDisposition.SUCCEEDED:
                successful[receipt.outbox_id] += 1

        for _attempt_id, receipt_values in receipts_by_attempt.items():
            if len(receipt_values) > 1:
                _fail(
                    failures,
                    receipt_values[0][0].kind,
                    receipt_values[0][0],
                    "MULTIPLE_DISPATCH_RECEIPTS_FOR_ATTEMPT",
                )

        for _outbox_id, attempt_values in attempts_by_outbox.items():
            ordered_attempts = sorted(attempt_values, key=lambda item: item[1].attempt_number)
            if [item.attempt_number for _record, item in ordered_attempts] != list(
                range(1, len(ordered_attempts) + 1)
            ) or any(item.fence != item.attempt_number for _record, item in ordered_attempts):
                _fail(
                    failures,
                    ordered_attempts[0][0].kind,
                    ordered_attempts[0][0],
                    "DISPATCH_ATTEMPTS_NOT_CONTIGUOUS",
                    head=True,
                )
            if (
                len({item.channel_capability.capability_id for _record, item in ordered_attempts})
                > 1
            ):
                _fail(
                    failures,
                    ordered_attempts[0][0].kind,
                    ordered_attempts[0][0],
                    "DISPATCH_CHANNEL_CAPABILITY_CHANGED",
                    head=True,
                )
            for index, (attempt_record, dispatch_attempt) in enumerate(ordered_attempts):
                outcomes = receipts_by_attempt.get(dispatch_attempt.attempt_id, [])
                if index < len(ordered_attempts) - 1:
                    if len(outcomes) != 1:
                        _fail(
                            failures,
                            attempt_record.kind,
                            attempt_record,
                            "DISPATCH_SUCCESSOR_WITHOUT_ONE_PREDECESSOR_RECEIPT",
                            head=True,
                        )
                        continue
                    prior_receipt = outcomes[0][1]
                    if prior_receipt.continuation != AlertDispatchContinuation.RETRY_ALLOWED:
                        _fail(
                            failures,
                            outcomes[0][0].kind,
                            outcomes[0][0],
                            "DISPATCH_SUCCESSOR_AFTER_TERMINAL_RECEIPT",
                            head=True,
                        )
                    if (
                        prior_receipt.disposition == AlertDispatchDisposition.UNKNOWN_DELIVERY
                        and dispatch_attempt.channel_capability.idempotency_guarantee
                        != AlertChannelIdempotencyGuarantee.EXACT_ALERT_ID
                    ):
                        _fail(
                            failures,
                            outcomes[0][0].kind,
                            outcomes[0][0],
                            "UNKNOWN_DELIVERY_SUCCESSOR_WITHOUT_EXACT_IDEMPOTENCY",
                            head=True,
                        )
                elif len(outcomes) == 0:
                    # Without a validation clock, only the current head may be active or expired.
                    continue
                elif outcomes[0][1].continuation == AlertDispatchContinuation.RETRY_ALLOWED and (
                    dispatch_attempt.attempt_number >= 3
                ):
                    _fail(
                        failures,
                        outcomes[0][0].kind,
                        outcomes[0][0],
                        "DISPATCH_MAX_ATTEMPTS_NOT_TERMINAL",
                        head=True,
                    )
        for outbox_id, count in successful.items():
            if count > 1:
                durable = outbox_by_id.get(outbox_id)
                if durable is None:
                    continue
                record = durable[0]
                _fail(failures, record.kind, record, "MULTIPLE_SUCCESSFUL_DELIVERIES")

        self._validate_cooldown_heads(cooldowns, failures)
        return causal_validation

    def _validate_alert_automatic_precedent_closure(
        self,
        *,
        connection: sqlite3.Connection,
        run_id: str,
        manifest: RunManifest,
        config: AppConfig,
        embeddings: tuple[tuple[M5Record, M5EmbeddingVector], ...],
        precedents: tuple[tuple[M5Record, M5PrecedentAuthority], ...],
        alerts: tuple[tuple[M5Record, AlertPolicyAuthority], ...],
        cooldowns: tuple[tuple[M5Record, AlertCooldownAuthority], ...],
        failures: list[M5ArtifactAuthorityFailure],
    ) -> _AlertPolicyCausalValidation:
        """Replay every close and prove its exact bidirectional automatic root."""

        policy_verifier = ConfiguredAlertPolicyVerifier(config)
        causal_sources: list[M5AlertPolicyCausalSource] = []
        embeddings_by_id: dict[str, list[tuple[M5Record, M5EmbeddingVector]]] = defaultdict(list)
        for embedding_record, embedding in embeddings:
            embeddings_by_id[embedding.embedding_id].append((embedding_record, embedding))
        cooldowns_by_id: dict[
            str,
            list[tuple[M5Record, AlertCooldownAuthority]],
        ] = defaultdict(list)
        for cooldown_record, cooldown in cooldowns:
            cooldowns_by_id[cooldown.authority_id].append((cooldown_record, cooldown))

        alert_versions: dict[
            str,
            tuple[int, int, tuple[str, Case] | None, tuple[str, Case] | None],
        ] = {}
        closing_audits: dict[str, _AlertClosingAudit | None] = {}
        for alert_record, alert in alerts:
            try:
                source_revision = _required_integer(alert_record.row, "source_case_revision")
                closing_revision = _required_integer(alert_record.row, "closing_case_revision")
            except ValueError:
                source_revision = 0
                closing_revision = 0
            source = _load_case_version(
                connection,
                run_id,
                alert.request.case_id,
                source_revision,
            )
            closing = _load_case_version(
                connection,
                run_id,
                alert.request.case_id,
                closing_revision,
            )
            alert_versions[alert.authority_id] = (
                source_revision,
                closing_revision,
                source,
                closing,
            )
            closing_audits[alert.authority_id] = (
                self._alert_closing_audit(
                    connection=connection,
                    run_id=run_id,
                    manifest_id=manifest.manifest_id,
                    case_id=alert.request.case_id,
                    closing_revision=closing_revision,
                    source_sha256=source[0],
                    closing_sha256=closing[0],
                    alert=alert,
                )
                if source is not None and closing is not None
                else None
            )

        cooldown_writers: dict[
            str,
            list[tuple[M5Record, AlertPolicyAuthority]],
        ] = defaultdict(list)
        for alert_record, alert in alerts:
            if alert.cooldown_write is not None:
                cooldown_writers[alert.cooldown_write.authority_id].append((alert_record, alert))

        cooldown_history: dict[str, list[_CooldownCausalRow]] = defaultdict(list)
        invalid_cooldown_keys: set[str] = set()
        for cooldown_record, cooldown in cooldowns:
            try:
                revision = _required_integer(cooldown_record.row, "revision")
            except ValueError:
                invalid_cooldown_keys.add(cooldown.key.key_id)
                continue
            writers = tuple(
                (writer_record, writer)
                for writer_record, writer in cooldown_writers.get(cooldown.authority_id, [])
                if writer.cooldown_write == cooldown
            )
            if len(writers) != 1:
                invalid_cooldown_keys.add(cooldown.key.key_id)
                continue
            _writer_record, writer = writers[0]
            writer_audit = closing_audits.get(writer.authority_id)
            if (
                writer_audit is None
                or writer.decision is None
                or cooldown.source_alert_id != writer.decision.alert_id
            ):
                invalid_cooldown_keys.add(cooldown.key.key_id)
                continue
            cooldown_history[cooldown.key.key_id].append(
                _CooldownCausalRow(
                    revision=revision,
                    writer_closing_audit=writer_audit,
                    record=cooldown_record,
                    authority=cooldown,
                    writer_alert_policy_authority_id=writer.authority_id,
                )
            )
        for key_id, values in cooldown_history.items():
            ordered = sorted(values, key=lambda item: item.revision)
            revisions = [item.revision for item in ordered]
            closing_sequences = [item.writer_closing_audit.sequence for item in ordered]
            if revisions != list(range(1, len(ordered) + 1)) or closing_sequences != sorted(
                set(closing_sequences)
            ):
                invalid_cooldown_keys.add(key_id)
            cooldown_history[key_id] = ordered
        cooldown_closing_sequences = {
            key_id: tuple(item.writer_closing_audit.sequence for item in values)
            for key_id, values in cooldown_history.items()
        }

        automatic_by_case: dict[
            str,
            list[tuple[M5Record, M5PrecedentAuthority]],
        ] = defaultdict(list)
        for precedent_record, precedent in precedents:
            if precedent.precedent.source != PrecedentSource.AUTOMATIC:
                continue
            source_case_id = precedent.precedent.source_case_id
            if source_case_id is None:
                _fail(
                    failures,
                    precedent_record.kind,
                    precedent_record,
                    M5AlertAuthorityReasonCode.ALERT_AUTOMATIC_PRECEDENT_ORPHAN,
                )
                continue
            automatic_by_case[source_case_id].append((precedent_record, precedent))

        alert_cases: set[str] = set()
        for alert_record, alert in alerts:
            request = alert.request
            alert_cases.add(request.case_id)
            source_revision, closing_revision, source, closing = alert_versions[alert.authority_id]
            closing_audit = closing_audits[alert.authority_id]
            expected_closing_ref = (
                ArtifactRef(kind=ArtifactKind.CASE, artifact_id=request.case_id)
                if alert.decision is None
                else ArtifactRef(kind=ArtifactKind.ALERT, artifact_id=alert.decision.alert_id)
            )
            policy_roots_valid = (
                source is not None
                and closing is not None
                and closing_audit is not None
                and source_revision > 0
                and closing_revision == source_revision + 1
                and source[1].status == CaseStatus.READY_FOR_ALERT_POLICY
                and closing[1].status == CaseStatus.CLOSED
                and source[1].manifest_id == manifest.manifest_id
                and closing[1].manifest_id == manifest.manifest_id
                and closing[1].final_decision == alert.final_decision
                and closing[1].alerts
                == (
                    source[1].alerts
                    if alert.decision is None
                    else (*source[1].alerts, alert.decision)
                )
                and m5_case_transition_audit(source[1], closing[1])
                == (AuditAction.CASE_CLOSED, expected_closing_ref)
            )

            stream_matches = tuple(
                stream
                for stream in manifest.streams
                if (stream.camera_id, stream.stream_id) == (request.camera_id, request.stream_id)
            )
            if len(stream_matches) != 1:
                policy_roots_valid = False
            else:
                stream = stream_matches[0]
                expected_stream_sha256 = sha256_hex(
                    ["alert-stream-authority", 1, stream.model_dump(mode="json")]
                )
                policy_roots_valid = policy_roots_valid and (
                    request.stream_authority_sha256 == expected_stream_sha256
                    and source is not None
                    and source[1].event.camera_id == request.camera_id
                    and source[1].event.stream_id == request.stream_id
                )

            expected_prior_cooldown: AlertCooldownAuthority | None = None
            historical_count = 0
            current_cooldowns: tuple[_CooldownCausalRow, ...] = ()
            cooldown_key: AlertCooldownKey | None = None
            prior_causal_valid = source is not None and closing_audit is not None
            cooldown_write_causal_valid = prior_causal_valid
            if source is not None and closing_audit is not None:
                track_ref = source[1].event.primary_track_ref
                if track_ref is not None:
                    cooldown_key = AlertCooldownKey(
                        zone_id=source[1].event.zone_id,
                        violation_type=source[1].event.violation_type,
                        track_ref=track_ref,
                    )
                    if cooldown_key.key_id in invalid_cooldown_keys:
                        prior_causal_valid = False
                        cooldown_write_causal_valid = False
                    keyed_history = cooldown_history.get(cooldown_key.key_id, [])
                    keyed_sequences = cooldown_closing_sequences.get(cooldown_key.key_id, ())
                    historical_count = bisect_left(keyed_sequences, closing_audit.sequence)
                    current_end = bisect_right(keyed_sequences, closing_audit.sequence)
                    current_cooldowns = tuple(keyed_history[historical_count:current_end])
                    if historical_count:
                        expected_prior_cooldown = keyed_history[historical_count - 1].authority

            prior_cooldown = request.prior_cooldown
            prior_causal_valid = prior_causal_valid and prior_cooldown == expected_prior_cooldown
            if prior_cooldown is not None:
                durable_cooldowns = cooldowns_by_id.get(prior_cooldown.authority_id, [])
                policy_roots_valid = policy_roots_valid and (
                    len(durable_cooldowns) == 1
                    and durable_cooldowns[0][1] == prior_cooldown
                    and durable_cooldowns[0][0].row["stream_authority_sha256"]
                    == request.stream_authority_sha256
                )

            cooldown_write = alert.cooldown_write
            if cooldown_write is None:
                cooldown_write_causal_valid = cooldown_write_causal_valid and not current_cooldowns
            else:
                expected_revision = historical_count + 1
                cooldown_write_causal_valid = cooldown_write_causal_valid and (
                    cooldown_key is not None
                    and cooldown_write.key == cooldown_key
                    and len(current_cooldowns) == 1
                    and current_cooldowns[0].revision == expected_revision
                    and current_cooldowns[0].authority == cooldown_write
                    and alert.decision is not None
                    and cooldown_write.source_alert_id == alert.decision.alert_id
                )
            if request.prior_emergency_delivery is not None:
                # The current M5 authority layout deliberately has no certified
                # emergency-signal root from which this input could be proven.
                policy_roots_valid = False

            if not policy_roots_valid or source is None or closing is None:
                _fail(
                    failures,
                    alert_record.kind,
                    alert_record,
                    M5AlertAuthorityReasonCode.ALERT_POLICY_INPUT_ROOT_INVALID,
                )
            if not prior_causal_valid:
                _fail(
                    failures,
                    alert_record.kind,
                    alert_record,
                    M5AlertAuthorityReasonCode.ALERT_PRIOR_COOLDOWN_CAUSAL_HEAD_MISMATCH,
                )
            if not cooldown_write_causal_valid:
                _fail(
                    failures,
                    alert_record.kind,
                    alert_record,
                    M5AlertAuthorityReasonCode.ALERT_COOLDOWN_WRITE_CAUSAL_CLOSURE_INVALID,
                )
            if (
                policy_roots_valid
                and prior_causal_valid
                and cooldown_write_causal_valid
                and source is not None
                and closing is not None
                and closing_audit is not None
            ):
                try:
                    rebuilt_alert = policy_verifier.rebuild(
                        source[1],
                        manifest,
                        expected_prior_cooldown,
                        None,
                    )
                except (TypeError, ValueError, AlertPolicyError):
                    rebuilt_alert = None
                if rebuilt_alert != alert:
                    _fail(
                        failures,
                        alert_record.kind,
                        alert_record,
                        M5AlertAuthorityReasonCode.ALERT_POLICY_REPLAY_MISMATCH,
                    )
                else:
                    causal_sources.append(
                        M5AlertPolicyCausalSource(
                            source_case_revision=source_revision,
                            source_case_document_sha256=source[0],
                            source_case=source[1],
                            source_case_canonical_document=canonical_json(
                                source[1].model_dump(mode="json")
                            ),
                            closing_case_revision=closing_revision,
                            closing_case_document_sha256=closing[0],
                            closing_case=closing[1],
                            closing_case_canonical_document=canonical_json(
                                closing[1].model_dump(mode="json")
                            ),
                            alert_policy=alert,
                            alert_policy_canonical_document=alert_record.canonical_document,
                            closing_audit_entry=closing_audit.entry,
                            closing_audit_entry_canonical_document=(
                                closing_audit.canonical_document
                            ),
                            cooldown_history_key_id=(
                                cooldown_key.key_id if cooldown_key is not None else None
                            ),
                            cooldown_eligible_history_count=historical_count,
                        )
                    )

            automatic_values = automatic_by_case.get(request.case_id, [])
            roots = tuple(
                (record, authority)
                for record, authority in automatic_values
                if authority.revision == 1
            )
            if not roots:
                _fail(
                    failures,
                    alert_record.kind,
                    alert_record,
                    M5AlertAuthorityReasonCode.ALERT_AUTOMATIC_PRECEDENT_MISSING,
                )
                continue
            if len(roots) != 1:
                for root_record, _root in roots:
                    _fail(
                        failures,
                        root_record.kind,
                        root_record,
                        M5AlertAuthorityReasonCode.ALERT_AUTOMATIC_PRECEDENT_DUPLICATE,
                    )
                continue
            root_record, root = roots[0]
            lineage_ids = {
                authority.precedent.precedent_id for _record, authority in automatic_values
            }
            if lineage_ids != {root.precedent.precedent_id}:
                for candidate_record, candidate in automatic_values:
                    if candidate.precedent.precedent_id != root.precedent.precedent_id:
                        _fail(
                            failures,
                            candidate_record.kind,
                            candidate_record,
                            M5AlertAuthorityReasonCode.ALERT_AUTOMATIC_PRECEDENT_DUPLICATE,
                        )

            embedded = (
                () if root.text_embedding is None else (root.text_embedding,)
            ) + root.visual_embeddings
            if not embedded or any(
                len(embeddings_by_id.get(vector.embedding_id, [])) != 1
                or embeddings_by_id[vector.embedding_id][0][1] != vector
                for vector in embedded
            ):
                _fail(
                    failures,
                    root_record.kind,
                    root_record,
                    M5AlertAuthorityReasonCode.ALERT_AUTOMATIC_PRECEDENT_EMBEDDING_CLOSURE_INVALID,
                )

            if (
                closing_audit is None
                or abs((root.created_at - closing_audit.recorded_at).total_seconds())
                > MAX_AUTOMATIC_PRECEDENT_CLOCK_SKEW_SECONDS
            ):
                _fail(
                    failures,
                    root_record.kind,
                    root_record,
                    M5AlertAuthorityReasonCode.ALERT_AUTOMATIC_PRECEDENT_TIME_INVALID,
                )
            rebuilt_automatic = None
            if source is not None:
                with suppress(TypeError, ValueError, AutomaticPrecedentError):
                    rebuilt_automatic = derive_automatic_precedent_authority(
                        case=source[1],
                        manifest=manifest,
                        alert_authority=alert,
                        config=config,
                        created_at=root.created_at,
                    )
            if root.precedent.status != PrecedentStatus.PROVISIONAL or rebuilt_automatic != root:
                _fail(
                    failures,
                    root_record.kind,
                    root_record,
                    M5AlertAuthorityReasonCode.ALERT_AUTOMATIC_PRECEDENT_REPLAY_MISMATCH,
                )

        for case_id, automatic_values in automatic_by_case.items():
            if case_id in alert_cases:
                continue
            for automatic_record, _automatic in automatic_values:
                _fail(
                    failures,
                    automatic_record.kind,
                    automatic_record,
                    M5AlertAuthorityReasonCode.ALERT_AUTOMATIC_PRECEDENT_ORPHAN,
                )
        source_key_ids = {
            item.cooldown_history_key_id
            for item in causal_sources
            if item.cooldown_history_key_id is not None
        }
        inventory_key_ids = source_key_ids | {
            key_id for key_id in cooldown_history if key_id not in invalid_cooldown_keys
        }
        inventories = tuple(
            M5AlertPolicyCooldownHistoryInventory(
                key_id=key_id,
                rows=tuple(
                    M5AlertPolicyCooldownHistorySource(
                        revision=item.revision,
                        writer_close_audit_sequence=item.writer_closing_audit.sequence,
                        writer_close_audit_entry_hash=(item.writer_closing_audit.entry.entry_hash),
                        writer_alert_policy_authority_id=(item.writer_alert_policy_authority_id),
                        authority=item.authority,
                        authority_canonical_document=item.record.canonical_document,
                    )
                    for item in cooldown_history.get(key_id, ())
                ),
            )
            for key_id in sorted(inventory_key_ids)
        )
        return _AlertPolicyCausalValidation(
            sources=tuple(
                sorted(
                    causal_sources,
                    key=lambda item: (
                        item.closing_case.case_id,
                        item.closing_case_revision,
                        item.alert_policy.authority_id,
                    ),
                )
            ),
            cooldown_history_inventories=inventories,
        )

    @staticmethod
    def _alert_closing_audit(
        *,
        connection: sqlite3.Connection,
        run_id: str,
        manifest_id: str,
        case_id: str,
        closing_revision: int,
        source_sha256: str,
        closing_sha256: str,
        alert: AlertPolicyAuthority,
    ) -> _AlertClosingAudit | None:
        link = connection.execute(
            """
            SELECT audit_sequence FROM case_versions
            WHERE run_id = ? AND case_id = ? AND revision = ?
            """,
            (run_id, case_id, closing_revision),
        ).fetchone()
        if link is None:
            return None
        try:
            sequence = _required_integer(link, "audit_sequence")
        except ValueError:
            return None
        audit_row = connection.execute(
            "SELECT * FROM audit_entries WHERE run_id = ? AND sequence = ?",
            (run_id, sequence),
        ).fetchone()
        entry = _parse_audit_entry(audit_row) if audit_row is not None else None
        expected_ref = (
            ArtifactRef(kind=ArtifactKind.CASE, artifact_id=case_id)
            if alert.decision is None
            else ArtifactRef(kind=ArtifactKind.ALERT, artifact_id=alert.decision.alert_id)
        )
        if (
            entry is None
            or entry.manifest_id != manifest_id
            or entry.actor != AuditActorRole.SYSTEM.value
            or entry.action != AuditAction.CASE_CLOSED
            or entry.object_ref != expected_ref
            or entry.before_sha256 != source_sha256
            or entry.after_sha256 != closing_sha256
        ):
            return None
        try:
            return _AlertClosingAudit(
                sequence=sequence,
                recorded_at=datetime.strptime(
                    entry.recorded_at,
                    "%Y-%m-%dT%H:%M:%S.%fZ",
                ).replace(tzinfo=UTC),
                entry=entry,
                canonical_document=canonical_json(entry.model_dump(mode="json")),
            )
        except ValueError:
            return None

    def _validate_cooldown_heads(
        self,
        cooldowns: tuple[tuple[M5Record, AlertCooldownAuthority], ...],
        failures: list[M5ArtifactAuthorityFailure],
    ) -> None:
        by_key: dict[str, list[M5Record]] = defaultdict(list)
        for record, cooldown in cooldowns:
            by_key[cooldown.key.key_id].append(record)
        for records in by_key.values():
            revisions = [int(record.row["revision"]) for record in records]
            if revisions != list(range(1, len(revisions) + 1)):
                _fail(
                    failures, records[0].kind, records[0], "COOLDOWN_HEAD_NOT_CONTIGUOUS", head=True
                )

    def _validate_appeals(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        records: dict[M5AuthorityKind, list[M5Record]],
        cases: dict[str, _CurrentCase],
        precedents: tuple[tuple[M5Record, M5PrecedentAuthority], ...],
        citations: tuple[tuple[M5Record, M5CitationCommit], ...],
        alerts: tuple[tuple[M5Record, AlertPolicyAuthority], ...],
        appeals: tuple[tuple[M5Record, AppealVersionAuthority], ...],
        resolutions: tuple[tuple[M5Record, AppealResolutionSideEffectIntent], ...],
        resolution_commits: tuple[tuple[M5Record, M5AppealResolutionCommitReceipt], ...],
        lifecycle_receipts: tuple[tuple[M5Record, LifecycleReceipt], ...],
        labels: tuple[tuple[M5Record, TrainingLabel], ...],
        failures: list[M5ArtifactAuthorityFailure],
    ) -> None:
        by_id: dict[str, list[tuple[M5Record, AppealVersionAuthority]]] = defaultdict(list)
        for record, appeal in appeals:
            by_id[appeal.appeal.appeal_id].append((record, appeal))
        resolution_by_appeal = {
            item.appeal_authority.appeal.appeal_id: (record, item) for record, item in resolutions
        }
        resolution_commit_by_appeal = {
            item.appeal_id: (record, item) for record, item in resolution_commits
        }
        precedent_by_revision = {
            (item.precedent.precedent_id, item.revision): item for _record, item in precedents
        }
        revocations_by_prior: dict[
            tuple[str, str],
            list[M5PrecedentRevocationReceipt],
        ] = defaultdict(list)
        for _record, receipt in lifecycle_receipts:
            if isinstance(receipt, M5PrecedentRevocationReceipt):
                revocations_by_prior[(receipt.precedent_id, receipt.prior_authority_id)].append(
                    receipt
                )
        citation_by_id = {item.citation.citation_id: item.citation for _record, item in citations}
        label_by_id = {item.label_id: item for _record, item in labels}
        alert_ids = {
            item.decision.alert_id for _record, item in alerts if item.decision is not None
        }
        for appeal_id, versions in by_id.items():
            ordered = sorted(versions, key=lambda item: item[1].version)
            numbers = [item.version for _record, item in ordered]
            if numbers != list(range(1, len(ordered) + 1)):
                _fail(
                    failures,
                    ordered[0][0].kind,
                    ordered[0][0],
                    "APPEAL_HEAD_NOT_CONTIGUOUS",
                    head=True,
                )
                continue
            for (_previous_record, previous), (record, current) in pairwise(ordered):
                if current.previous_authority_sha256 != previous.authority_sha256:
                    _fail(
                        failures, record.kind, record, "APPEAL_PREDECESSOR_HASH_MISMATCH", head=True
                    )
                if (
                    current.source_case_authority != previous.source_case_authority
                    or current.source_case_revision != previous.source_case_revision
                    or current.source_verdict_id != previous.source_verdict_id
                    or current.source_verdict_sha256 != previous.source_verdict_sha256
                ):
                    _fail(failures, record.kind, record, "APPEAL_SOURCE_AUTHORITY_REWRITTEN")
            head_record, head = ordered[-1]
            current_case = cases.get(head.appeal.case_id)
            expected_status = (
                CaseStatus.APPEAL_RESOLVED
                if head.appeal.status in {AppealStatus.UPHELD, AppealStatus.OVERTURNED}
                else CaseStatus.APPEALED
            )
            if (
                current_case is None
                or current_case.revision != head.source_case_revision + head.version
                or current_case.case.status != expected_status
                or not current_case.case.appeals
                or current_case.case.appeals[-1] != head.appeal
            ):
                _fail(
                    failures,
                    head_record.kind,
                    head_record,
                    "APPEAL_CURRENT_CASE_HEAD_MISMATCH",
                    head=True,
                )
            resolution = resolution_by_appeal.get(appeal_id)
            resolution_commit = resolution_commit_by_appeal.get(appeal_id)
            if head.version == 3:
                if resolution is None or resolution[1].appeal_authority != head:
                    _fail(
                        failures, head_record.kind, head_record, "TERMINAL_APPEAL_RECEIPT_MISSING"
                    )
                else:
                    if resolution_commit is None:
                        _fail(
                            failures,
                            resolution[0].kind,
                            resolution[0],
                            M5AppealResolutionHistoryReasonCode.APPEAL_RESOLUTION_RECEIPT_CLOSURE_INVALID.value,
                        )
                    else:
                        self._validate_resolution_closure(
                            connection,
                            run_id,
                            records,
                            resolution[0],
                            resolution[1],
                            resolution_commit[1],
                            precedent_by_revision,
                            revocations_by_prior,
                            citation_by_id,
                            alert_ids,
                            label_by_id,
                            failures,
                        )
            elif resolution is not None:
                _fail(
                    failures, resolution[0].kind, resolution[0], "NONTERMINAL_APPEAL_HAS_RESOLUTION"
                )
        for appeal_id, (record, _resolution) in resolution_by_appeal.items():
            if appeal_id not in by_id:
                _fail(failures, record.kind, record, "ORPHAN_APPEAL_RESOLUTION")
        for appeal_id, (record, _commit) in resolution_commit_by_appeal.items():
            if appeal_id not in resolution_by_appeal:
                _fail(
                    failures,
                    record.kind,
                    record,
                    M5AppealResolutionHistoryReasonCode.APPEAL_RESOLUTION_RECEIPT_CLOSURE_INVALID.value,
                )

    def _validate_resolution_closure(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        records: dict[M5AuthorityKind, list[M5Record]],
        record: M5Record,
        intent: AppealResolutionSideEffectIntent,
        commit_receipt: M5AppealResolutionCommitReceipt,
        precedent_by_revision: Mapping[tuple[str, int], M5PrecedentAuthority],
        revocations_by_prior: Mapping[
            tuple[str, str],
            list[M5PrecedentRevocationReceipt],
        ],
        citation_by_id: Mapping[str, object],
        alert_ids: set[str],
        label_by_id: dict[str, TrainingLabel],
        failures: list[M5ArtifactAuthorityFailure],
    ) -> None:
        if (
            commit_receipt.run_id != intent.run_id
            or commit_receipt.resolution_intent_id != intent.intent_id
            or commit_receipt.appeal_id != intent.appeal_authority.appeal.appeal_id
            or commit_receipt.appeal_authority_sha256 != intent.appeal_authority.authority_sha256
            or commit_receipt.case_id != intent.case_id
            or commit_receipt.manifest_id != intent.manifest_id
        ):
            _fail(
                failures,
                record.kind,
                record,
                M5AppealResolutionHistoryReasonCode.APPEAL_RESOLUTION_RECEIPT_CLOSURE_INVALID.value,
            )
        verdict_rows = connection.execute(
            "SELECT * FROM verdict_rescissions WHERE run_id = ? AND resolution_intent_id = ?",
            (run_id, intent.intent_id),
        ).fetchall()
        alert_rows = connection.execute(
            """
            SELECT * FROM alert_rescissions
            WHERE run_id = ? AND resolution_intent_id = ?
            ORDER BY alert_id
            """,
            (run_id, intent.intent_id),
        ).fetchall()
        expected_verdict = 1 if intent.verdict_rescission is not None else 0
        if len(verdict_rows) != expected_verdict:
            _fail(failures, record.kind, record, "VERDICT_RESCISSION_CLOSURE_INVALID")
        expected_alert_ids = tuple(item.alert_id for item in intent.alert_rescissions)
        actual_alert_ids = tuple(str(item["alert_id"]) for item in alert_rows)
        if actual_alert_ids != expected_alert_ids or any(
            alert_id not in alert_ids for alert_id in expected_alert_ids
        ):
            _fail(failures, record.kind, record, "ALERT_RESCISSION_CLOSURE_INVALID")
        revocation_receipts: list[M5PrecedentRevocationReceipt] = []
        for revocation in intent.precedent_revocations:
            matches = revocations_by_prior.get(
                (revocation.precedent_id, revocation.prior_authority_id),
                [],
            )
            receipt = matches[0] if len(matches) == 1 else None
            resulting = (
                None
                if receipt is None
                else precedent_by_revision.get((receipt.precedent_id, receipt.resulting_revision))
            )
            if (
                receipt is None
                or resulting is None
                or receipt.prior_revision != revocation.prior_revision
                or receipt.resulting_revision != revocation.prior_revision + 1
                or receipt.resulting_authority_id != resulting.authority_id
                or receipt.revoked_by_ref != intent.appeal_authority.appeal.appeal_id
                or resulting.precedent.status != PrecedentStatus.REVOKED
                or resulting.precedent.invalidated_by != intent.appeal_authority.appeal.appeal_id
            ):
                _fail(failures, record.kind, record, "PRECEDENT_REVOCATION_CLOSURE_INVALID")
                continue
            revocation_receipts.append(receipt)
        replacement = intent.appeal_precedent_authority
        if (
            replacement is not None
            and precedent_by_revision.get(
                (replacement.precedent.precedent_id, replacement.revision)
            )
            != replacement
        ):
            _fail(failures, record.kind, record, "APPEAL_PRECEDENT_CLOSURE_INVALID")
        if any(label_by_id.get(label.label_id) != label for label in intent.training_labels):
            _fail(failures, record.kind, record, "APPEAL_TRAINING_LABEL_CLOSURE_INVALID")
        if any(
            getattr(citation_by_id.get(item.source_citation_id), "case_id", None)
            != item.citing_case_id
            for item in intent.affected_citations.citations
        ):
            _fail(failures, record.kind, record, "AFFECTED_CITATION_CLOSURE_INVALID")

        expected_record_ids = {
            item.artifact_id
            for item in records[M5AuthorityKind.VERDICT_RESCISSION]
            if item.row["resolution_intent_id"] == intent.intent_id
        } | {
            item.artifact_id
            for item in records[M5AuthorityKind.ALERT_RESCISSION]
            if item.row["resolution_intent_id"] == intent.intent_id
        }
        if len(expected_record_ids) != expected_verdict + len(expected_alert_ids):
            _fail(failures, record.kind, record, "RESCISSION_DOCUMENT_CLOSURE_INVALID")

        case_row = connection.execute(
            """
            SELECT * FROM case_versions
            WHERE run_id = ? AND case_id = ? AND revision = ?
            """,
            (
                run_id,
                intent.case_id,
                commit_receipt.resulting_case_revision,
            ),
        ).fetchone()
        case_document_sha256: str | None = None
        if case_row is not None:
            try:
                raw_case = case_row["case_json"]
                if not isinstance(raw_case, str):
                    raise TypeError
                historical_case = Case.model_validate_json(raw_case)
                digest = hashlib.sha256(raw_case.encode("utf-8")).hexdigest()
                if (
                    canonical_json(historical_case.model_dump(mode="json")) != raw_case
                    or case_row["document_sha256"] != digest
                    or historical_case.run_id != intent.run_id
                    or historical_case.case_id != intent.case_id
                    or historical_case.status != CaseStatus.APPEAL_RESOLVED
                    or not historical_case.appeals
                    or historical_case.appeals[-1] != intent.appeal_authority.appeal
                ):
                    raise ValueError
                case_document_sha256 = digest
            except (TypeError, ValidationError, ValueError):
                pass
        if case_document_sha256 is None:
            _fail(
                failures,
                record.kind,
                record,
                M5AppealResolutionHistoryReasonCode.APPEAL_RESOLUTION_RECEIPT_CLOSURE_INVALID.value,
            )
            return
        intent_json = canonical_json(intent.model_dump(mode="json"))
        intent_sha256 = hashlib.sha256(intent_json.encode("utf-8")).hexdigest()
        try:
            expected_commit = M5AppealResolutionCommitReceipt(
                run_id=intent.run_id,
                resolution_intent_id=intent.intent_id,
                resolution_document_sha256=intent_sha256,
                appeal_id=intent.appeal_authority.appeal.appeal_id,
                appeal_authority_sha256=intent.appeal_authority.authority_sha256,
                case_id=intent.case_id,
                source_case_revision=intent.appeal_authority.source_case_revision,
                resulting_case_revision=commit_receipt.resulting_case_revision,
                resulting_case_document_sha256=case_document_sha256,
                verdict_rescission_ids=tuple(
                    sorted(str(row["rescission_id"]) for row in verdict_rows)
                ),
                alert_rescission_ids=tuple(sorted(str(row["rescission_id"]) for row in alert_rows)),
                precedent_revocation_receipt_ids=tuple(
                    sorted(item.receipt_id for item in revocation_receipts)
                ),
                replacement_precedent_authority_id=(
                    replacement.authority_id if replacement is not None else None
                ),
                training_label_ids=tuple(
                    sorted(label.label_id for label in intent.training_labels)
                ),
                affected_citation_report_sha256=intent.affected_citations.report_sha256,
                manifest_id=intent.manifest_id,
            )
        except (TypeError, ValidationError, ValueError):
            expected_commit = None
        if expected_commit != commit_receipt:
            _fail(
                failures,
                record.kind,
                record,
                M5AppealResolutionHistoryReasonCode.APPEAL_RESOLUTION_EFFECT_ROOT_MISMATCH.value,
            )

    def _validate_training_label_provenance(
        self,
        *,
        appeals: tuple[tuple[M5Record, AppealVersionAuthority], ...],
        resolutions: tuple[tuple[M5Record, AppealResolutionSideEffectIntent], ...],
        resolution_commits: tuple[tuple[M5Record, M5AppealResolutionCommitReceipt], ...],
        causal_events: tuple[tuple[M5Record, M5PrecedentCausalEvent], ...],
        labels: tuple[tuple[M5Record, TrainingLabel], ...],
        provenance_receipts: tuple[tuple[M5Record, M5StrongTrainingLabelProvenanceReceipt], ...],
        failures: list[M5ArtifactAuthorityFailure],
    ) -> frozenset[str]:
        label_by_id: dict[str, list[tuple[M5Record, TrainingLabel]]] = defaultdict(list)
        provenance_by_id: dict[
            str,
            list[tuple[M5Record, M5StrongTrainingLabelProvenanceReceipt]],
        ] = defaultdict(list)
        provenance_by_label: dict[
            str,
            list[tuple[M5Record, M5StrongTrainingLabelProvenanceReceipt]],
        ] = defaultdict(list)
        appeal_by_authority: dict[
            str,
            list[tuple[M5Record, AppealVersionAuthority]],
        ] = defaultdict(list)
        resolution_by_id: dict[
            str,
            list[tuple[M5Record, AppealResolutionSideEffectIntent]],
        ] = defaultdict(list)
        commit_by_id: dict[
            str,
            list[tuple[M5Record, M5AppealResolutionCommitReceipt]],
        ] = defaultdict(list)
        event_by_source_id: dict[
            str,
            list[tuple[M5Record, M5PrecedentCausalEvent]],
        ] = defaultdict(list)

        for record, label in labels:
            label_by_id[label.label_id].append((record, label))
        for record, receipt in provenance_receipts:
            provenance_by_id[receipt.provenance_id].append((record, receipt))
            provenance_by_label[receipt.label_id].append((record, receipt))
        for record, appeal in appeals:
            appeal_by_authority[appeal.authority_sha256].append((record, appeal))
        for record, resolution in resolutions:
            resolution_by_id[resolution.intent_id].append((record, resolution))
        for record, commit in resolution_commits:
            commit_by_id[commit.receipt_id].append((record, commit))
        for record, event in causal_events:
            event_by_source_id[event.source_id].append((record, event))

        duplicate_provenance_ids = {
            provenance_id for provenance_id, values in provenance_by_id.items() if len(values) != 1
        }
        for provenance_id in sorted(duplicate_provenance_ids):
            for record, _receipt in provenance_by_id[provenance_id]:
                _fail(
                    failures,
                    record.kind,
                    record,
                    M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_PROVENANCE_DUPLICATE.value,
                )

        valid_label_ids: set[str] = set()
        for label_record, label in labels:
            row_pointer = label_record.row["strong_provenance_id"]
            receipts = provenance_by_label[label.label_id]
            if label.quality not in STRONG_TRAINING_LABEL_QUALITIES:
                if row_pointer is not None or receipts:
                    _fail(
                        failures,
                        label_record.kind,
                        label_record,
                        M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_WEAK_PROVENANCE_FORBIDDEN.value,
                    )
                    for receipt_record, _receipt in receipts:
                        _fail(
                            failures,
                            receipt_record.kind,
                            receipt_record,
                            M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_WEAK_PROVENANCE_FORBIDDEN.value,
                        )
                continue
            if not receipts:
                _fail(
                    failures,
                    label_record.kind,
                    label_record,
                    M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_PROVENANCE_MISSING.value,
                )
                continue
            if len(receipts) != 1:
                _fail(
                    failures,
                    label_record.kind,
                    label_record,
                    M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_PROVENANCE_DUPLICATE.value,
                )
                for receipt_record, _receipt in receipts:
                    _fail(
                        failures,
                        receipt_record.kind,
                        receipt_record,
                        M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_PROVENANCE_DUPLICATE.value,
                    )
                continue

            receipt_record, receipt = receipts[0]
            if receipt.provenance_id in duplicate_provenance_ids:
                _fail(
                    failures,
                    label_record.kind,
                    label_record,
                    M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_PROVENANCE_DUPLICATE.value,
                )
                continue
            if row_pointer != receipt.provenance_id:
                _fail(
                    failures,
                    label_record.kind,
                    label_record,
                    M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_AUTHORITY_INVALID.value,
                )
                _fail(
                    failures,
                    receipt_record.kind,
                    receipt_record,
                    M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_PROVENANCE_ORPHAN.value,
                )
                continue
            try:
                authority = M5TrainingLabelAuthority(
                    label=label,
                    strong_provenance=receipt,
                )
            except (TypeError, ValidationError, ValueError):
                _fail(
                    failures,
                    receipt_record.kind,
                    receipt_record,
                    M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_AUTHORITY_INVALID.value,
                )
                continue

            review_matches = appeal_by_authority[receipt.review_authority_sha256]
            if len(review_matches) != 1:
                _fail(
                    failures,
                    receipt_record.kind,
                    receipt_record,
                    M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_REVIEW_AUTHORITY_INVALID.value,
                )
                continue
            terminal_matches = appeal_by_authority[receipt.terminal_authority_sha256]
            if len(terminal_matches) != 1:
                _fail(
                    failures,
                    receipt_record.kind,
                    receipt_record,
                    M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_TERMINAL_AUTHORITY_INVALID.value,
                )
                continue
            resolution_matches = resolution_by_id[receipt.resolution_intent_id]
            if len(resolution_matches) != 1:
                _fail(
                    failures,
                    receipt_record.kind,
                    receipt_record,
                    M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_RESOLUTION_INTENT_INVALID.value,
                )
                continue
            commit_matches = commit_by_id[receipt.resolution_commit_receipt_id]
            if len(commit_matches) != 1:
                _fail(
                    failures,
                    receipt_record.kind,
                    receipt_record,
                    M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_RESOLUTION_COMMIT_INVALID.value,
                )
                continue
            marker_matches = event_by_source_id[receipt.resolution_commit_receipt_id]
            if len(marker_matches) != 1:
                _fail(
                    failures,
                    receipt_record.kind,
                    receipt_record,
                    M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_RESOLUTION_MARKER_INVALID.value,
                )
                continue

            try:
                require_m5_strong_training_label_provenance(
                    authority=authority,
                    review_authority=review_matches[0][1],
                    terminal_authority=terminal_matches[0][1],
                    resolution_intent=resolution_matches[0][1],
                    resolution_commit_receipt=commit_matches[0][1],
                    resolution_commit_event=marker_matches[0][1],
                )
            except M5TrainingLabelProvenanceError as error:
                _fail(
                    failures,
                    receipt_record.kind,
                    receipt_record,
                    _TRAINING_PROVENANCE_REASON_BY_ERROR[error.code].value,
                )
                continue
            valid_label_ids.add(label.label_id)

        for receipt_record, receipt in provenance_receipts:
            matching_labels = label_by_id[receipt.label_id]
            if len(matching_labels) != 1:
                _fail(
                    failures,
                    receipt_record.kind,
                    receipt_record,
                    M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_PROVENANCE_ORPHAN.value,
                )
                continue
            label_record, label = matching_labels[0]
            if label.quality not in STRONG_TRAINING_LABEL_QUALITIES:
                _fail(
                    failures,
                    receipt_record.kind,
                    receipt_record,
                    M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_WEAK_PROVENANCE_FORBIDDEN.value,
                )
            elif label_record.row["strong_provenance_id"] != receipt.provenance_id:
                _fail(
                    failures,
                    receipt_record.kind,
                    receipt_record,
                    M5TrainingLabelProvenanceReasonCode.TRAINING_LABEL_PROVENANCE_ORPHAN.value,
                )

        return frozenset(valid_label_ids)

    def _validate_training_history(
        self,
        *,
        connection: sqlite3.Connection,
        run_id: str,
        manifest_id: str,
        labels: tuple[tuple[M5Record, TrainingLabel], ...],
        provenance_receipts: tuple[tuple[M5Record, M5StrongTrainingLabelProvenanceReceipt], ...],
        events: tuple[tuple[M5Record, M5TrainingCausalEvent], ...],
        datasets: tuple[tuple[M5Record, DatasetExportReport], ...],
        registration_snapshots: tuple[tuple[M5Record, M5DatasetRegistrationSnapshotAuthority], ...],
        crop_snapshots: tuple[tuple[M5Record, M5DatasetCropSnapshotAuthority], ...],
        valid_strong_label_ids: frozenset[str],
        failures: list[M5ArtifactAuthorityFailure],
    ) -> tuple[M5DatasetHistoricalAuthority, ...]:
        provenance_by_label: dict[str, list[M5StrongTrainingLabelProvenanceReceipt]] = defaultdict(
            list
        )
        for _record, receipt in provenance_receipts:
            provenance_by_label[receipt.label_id].append(receipt)

        authorities: list[M5TrainingLabelAuthority] = []
        label_record_by_id: dict[str, M5Record] = {}
        for record, label in labels:
            label_record_by_id[label.label_id] = record
            receipts = provenance_by_label[label.label_id]
            provenance = receipts[0] if len(receipts) == 1 else None
            try:
                authorities.append(
                    M5TrainingLabelAuthority(
                        label=label,
                        strong_provenance=provenance,
                    )
                )
            except (TypeError, ValidationError, ValueError):
                continue
        label_authorities = tuple(sorted(authorities, key=lambda item: item.label.label_id))
        authority_by_label = {item.label.label_id: item for item in label_authorities}
        event_values = tuple(item for _record, item in events)
        event_records_by_label: dict[str, list[tuple[M5Record, M5TrainingCausalEvent]]] = (
            defaultdict(list)
        )
        for record, event in events:
            if event.event_kind == M5TrainingCausalEventKind.TRAINING_LABEL_APPENDED:
                assert event.label_id is not None
                event_records_by_label[event.label_id].append((record, event))
                authority = authority_by_label.get(event.label_id)
                if authority is None:
                    _fail(
                        failures,
                        record.kind,
                        record,
                        M5TrainingHistoryReasonCode.TRAINING_CAUSAL_EVENT_ORPHAN.value,
                    )
                elif (
                    event.source_id != authority.authority_sha256
                    or event.source_document_sha256 != sha256_hex(authority.model_dump(mode="json"))
                ):
                    _fail(
                        failures,
                        record.kind,
                        record,
                        M5TrainingHistoryReasonCode.TRAINING_CAUSAL_EVENT_SOURCE_MISMATCH.value,
                    )
        for label_id in sorted(authority_by_label):
            matching = event_records_by_label[label_id]
            if not matching:
                _fail(
                    failures,
                    M5AuthorityKind.TRAINING_LABEL,
                    label_record_by_id[label_id],
                    M5TrainingHistoryReasonCode.TRAINING_CAUSAL_EVENT_MISSING.value,
                )
            elif len(matching) > 1:
                _fail(
                    failures,
                    M5AuthorityKind.TRAINING_LABEL,
                    label_record_by_id[label_id],
                    M5TrainingHistoryReasonCode.TRAINING_CAUSAL_EVENT_DUPLICATE.value,
                )
                for record, _event in matching:
                    _fail(
                        failures,
                        record.kind,
                        record,
                        M5TrainingHistoryReasonCode.TRAINING_CAUSAL_EVENT_DUPLICATE.value,
                    )

        chain_valid = True
        try:
            require_m5_training_causal_chain(
                run_id=run_id,
                manifest_id=manifest_id,
                events=event_values,
                label_authorities=label_authorities,
            )
        except M5TrainingHistoryError as error:
            chain_valid = False
            reason = _TRAINING_HISTORY_REASON_BY_ERROR[error.code].value
            targets = events or labels
            for record, _document in targets:
                _fail(failures, record.kind, record, reason)

        snapshots_by_report: dict[
            str, list[tuple[M5Record, M5DatasetRegistrationSnapshotAuthority]]
        ] = defaultdict(list)
        for record, snapshot in registration_snapshots:
            snapshots_by_report[snapshot.report_id].append((record, snapshot))
        crop_rows_by_snapshot: dict[str, list[tuple[M5Record, M5DatasetCropSnapshotAuthority]]] = (
            defaultdict(list)
        )
        known_snapshot_ids = {item.authority_id for _record, item in registration_snapshots}
        for record, crop_snapshot in crop_snapshots:
            pointer = record.row["registration_snapshot_authority_id"]
            crop_rows_by_snapshot[str(pointer)].append((record, crop_snapshot))
            if pointer not in known_snapshot_ids:
                _fail(
                    failures,
                    record.kind,
                    record,
                    M5TrainingHistoryReasonCode.DATASET_CROP_SNAPSHOT_EXTRA.value,
                )

        referenced_snapshot_ids = {
            str(record.row["registration_snapshot_authority_id"]) for record, _report in datasets
        }
        for record, snapshot in registration_snapshots:
            if snapshot.authority_id not in referenced_snapshot_ids:
                _fail(
                    failures,
                    record.kind,
                    record,
                    M5TrainingHistoryReasonCode.DATASET_REGISTRATION_SNAPSHOT_DUPLICATE.value,
                )
        for record, event in events:
            if (
                event.event_kind == M5TrainingCausalEventKind.DATASET_REGISTRATION_COMMITTED
                and event.source_id not in known_snapshot_ids
            ):
                _fail(
                    failures,
                    record.kind,
                    record,
                    M5TrainingHistoryReasonCode.DATASET_REGISTRATION_MARKER_MISSING_OR_INVALID.value,
                )

        histories: list[M5DatasetHistoricalAuthority] = []
        for report_record, report in datasets:
            matches = snapshots_by_report[report.report_id]
            pointer = report_record.row["registration_snapshot_authority_id"]
            if not matches:
                _fail(
                    failures,
                    report_record.kind,
                    report_record,
                    M5TrainingHistoryReasonCode.DATASET_REGISTRATION_SNAPSHOT_MISSING.value,
                )
                continue
            if len(matches) != 1:
                _fail(
                    failures,
                    report_record.kind,
                    report_record,
                    M5TrainingHistoryReasonCode.DATASET_REGISTRATION_SNAPSHOT_DUPLICATE.value,
                )
                for record, _snapshot in matches:
                    _fail(
                        failures,
                        record.kind,
                        record,
                        M5TrainingHistoryReasonCode.DATASET_REGISTRATION_SNAPSHOT_DUPLICATE.value,
                    )
                continue
            snapshot_record, snapshot = matches[0]
            if pointer != snapshot.authority_id:
                _fail(
                    failures,
                    report_record.kind,
                    report_record,
                    M5TrainingHistoryReasonCode.DATASET_REGISTRATION_SNAPSHOT_MISSING.value,
                )
                continue
            markers = tuple(
                (record, event)
                for record, event in events
                if event.event_kind == M5TrainingCausalEventKind.DATASET_REGISTRATION_COMMITTED
                and event.source_id == snapshot.authority_id
            )
            if len(markers) != 1:
                _fail(
                    failures,
                    snapshot_record.kind,
                    snapshot_record,
                    M5TrainingHistoryReasonCode.DATASET_REGISTRATION_MARKER_MISSING_OR_INVALID.value,
                )
                continue
            crop_rows = crop_rows_by_snapshot[snapshot.authority_id]
            crop_documents = tuple(item for _record, item in crop_rows)
            if len(crop_documents) != len({item.sort_key for item in crop_documents}):
                for record, _item in crop_rows:
                    _fail(
                        failures,
                        record.kind,
                        record,
                        M5TrainingHistoryReasonCode.DATASET_CROP_SNAPSHOT_DUPLICATE.value,
                    )
                continue
            if len(crop_documents) < snapshot.crop_count:
                _fail(
                    failures,
                    snapshot_record.kind,
                    snapshot_record,
                    M5TrainingHistoryReasonCode.DATASET_CROP_SNAPSHOT_MISSING.value,
                )
                continue
            if len(crop_documents) > snapshot.crop_count:
                for record, _item in crop_rows:
                    _fail(
                        failures,
                        record.kind,
                        record,
                        M5TrainingHistoryReasonCode.DATASET_CROP_SNAPSHOT_EXTRA.value,
                    )
                continue
            if not all(
                _validate_historical_crop_snapshot(
                    connection=connection,
                    run_id=run_id,
                    record=record,
                    snapshot=item,
                    failures=failures,
                )
                for record, item in crop_rows
            ):
                continue
            if not set(report.exported_label_ids).issubset(valid_strong_label_ids):
                _fail(
                    failures,
                    report_record.kind,
                    report_record,
                    M5TrainingLabelProvenanceReasonCode.DATASET_LABEL_PROVENANCE_INVALID.value,
                )
                continue
            if not chain_valid:
                continue
            try:
                label_receipts = build_m5_dataset_label_snapshot_receipts(
                    report=report,
                    causal_cut=snapshot.causal_cut,
                    events=event_values,
                    label_authorities=label_authorities,
                )
                historical_labels, historical_crops = resolve_m5_dataset_historical_replay(
                    report=report,
                    snapshot=snapshot,
                    registration_marker=markers[0][1],
                    events=event_values,
                    label_authorities=label_authorities,
                    label_receipts=label_receipts,
                    crop_snapshots=crop_documents,
                )
            except M5TrainingHistoryError as error:
                _fail(
                    failures,
                    snapshot_record.kind,
                    snapshot_record,
                    _TRAINING_HISTORY_REASON_BY_ERROR[error.code].value,
                )
                continue
            histories.append(
                M5DatasetHistoricalAuthority(
                    dataset_id=report.dataset.dataset_id,
                    registration_snapshot_authority_id=snapshot.authority_id,
                    labels=historical_labels,
                    crop_authorities=historical_crops,
                )
            )
        return tuple(sorted(histories, key=lambda item: item.dataset_id))

    def _build_roots(
        self,
        records: dict[M5AuthorityKind, list[M5Record]],
        cases: dict[str, _CurrentCase],
        precedents: tuple[tuple[M5Record, M5PrecedentAuthority], ...],
        alerts: tuple[tuple[M5Record, AlertPolicyAuthority], ...],
        appeals: tuple[tuple[M5Record, AppealVersionAuthority], ...],
        resolutions: tuple[tuple[M5Record, AppealResolutionSideEffectIntent], ...],
    ) -> tuple[M5CaseAuthorityRoot, ...]:
        precedent_by_case: dict[str, list[M5PrecedentAuthority]] = defaultdict(list)
        for _record, precedent_authority in precedents:
            if precedent_authority.precedent.source_case_id is not None:
                precedent_by_case[precedent_authority.precedent.source_case_id].append(
                    precedent_authority
                )
        alert_by_case = {item.request.case_id: item for _record, item in alerts}
        appeal_by_case: dict[str, list[AppealVersionAuthority]] = defaultdict(list)
        for _record, appeal_authority in appeals:
            appeal_by_case[appeal_authority.appeal.case_id].append(appeal_authority)
        resolution_by_case = {item.case_id: item for _record, item in resolutions}
        documents_by_case = _documents_by_case(records)
        roots: list[M5CaseAuthorityRoot] = []
        for case_id, current in sorted(cases.items()):
            precedent_heads = _precedent_heads_for_case(precedent_by_case[case_id])
            appeals_for_case = appeal_by_case[case_id]
            appeal_head = max(appeals_for_case, key=lambda item: item.version, default=None)
            alert = alert_by_case.get(case_id)
            resolution = resolution_by_case.get(case_id)
            root_sha256 = hashlib.sha256(
                canonical_json(
                    [
                        "m5-case-authority-root",
                        1,
                        case_id,
                        current.revision,
                        current.document_sha256,
                        current.status,
                        [
                            [item.kind.value, item.artifact_id, _document_sha(item)]
                            for item in documents_by_case[case_id]
                        ],
                    ]
                ).encode()
            ).hexdigest()
            roots.append(
                M5CaseAuthorityRoot(
                    case_id=case_id,
                    current_case_revision=current.revision,
                    current_case_sha256=current.document_sha256,
                    current_case_status=current.status,
                    alert_authority_id=alert.authority_id if alert is not None else None,
                    current_precedent_authority_ids=tuple(
                        item.authority_id for item in precedent_heads
                    ),
                    current_appeal_authority_sha256=(
                        appeal_head.authority_sha256 if appeal_head is not None else None
                    ),
                    resolution_intent_id=resolution.intent_id if resolution is not None else None,
                    root_sha256=root_sha256,
                )
            )
        return tuple(roots)


@dataclass(frozen=True, slots=True)
class _RetentionAuthorityRow:
    row: sqlite3.Row
    hold: RetentionHold | None
    parse_reason: str | None
    hold_identity_sha256: str


@dataclass(frozen=True, slots=True)
class _DatasetRetentionValidation:
    failures: tuple[M5DatasetRetentionFailure, ...]
    dataset_hold_count: int
    orphan_count: int
    root_sha256: str


def _validate_dataset_retention_authority(
    *,
    connection: sqlite3.Connection,
    run_id: str,
    datasets: tuple[DatasetExportReport, ...],
    appeal_ids: frozenset[str],
    budget: M5ArtifactValidationBudget,
    retention_hold_rows: int,
    retention_link_rows: int,
    retention_audit_rows: int,
) -> _DatasetRetentionValidation:
    if (
        retention_hold_rows + retention_link_rows + retention_audit_rows
        > budget.max_retention_records
    ):
        raise AssertionError("retention rows escaped the SQL budget preflight")

    hold_rows = _stream_retention_holds(connection, run_id, retention_hold_rows)
    link_rows = _stream_retention_links(connection, run_id, retention_link_rows)
    audit_rows = _stream_retention_audits(connection, run_id, retention_audit_rows)
    links_by_hold_id = {_required_text(row, "hold_id"): row for row in link_rows}
    audits_by_sequence: dict[int, AuditEntry | None] = {}
    audit_digests: dict[int, str] = {}
    for row in audit_rows:
        sequence = _required_integer(row, "sequence")
        audit_digests[sequence] = _retention_row_digest(
            "audit_entries",
            row,
            (
                "run_id",
                "sequence",
                "manifest_id",
                "actor",
                "action",
                "object_kind",
                "object_id",
                "before_sha256",
                "after_sha256",
                "recorded_at",
                "prev_entry_hash",
                "entry_hash",
                "entry_json",
                "document_sha256",
            ),
        )
        audits_by_sequence[sequence] = _parse_audit_entry(row)

    reports_by_dataset = {item.dataset.dataset_id: item for item in datasets}
    expected_by_hold_id: dict[str, tuple[str, RetentionHold]] = {}
    expected_ids_by_dataset: dict[str, frozenset[str]] = {}
    for report in datasets:
        expected_holds = m5_dataset_retention_holds(report)
        expected_ids_by_dataset[report.dataset.dataset_id] = frozenset(
            item.hold_id for item in expected_holds
        )
        for hold in expected_holds:
            prior = expected_by_hold_id.setdefault(
                hold.hold_id,
                (report.dataset.dataset_id, hold),
            )
            if prior != (report.dataset.dataset_id, hold):
                raise AssertionError("canonical dataset holds collided")

    rows_by_hold_id: dict[str, _RetentionAuthorityRow] = {}
    for row in hold_rows:
        raw_hold_id = _required_text(row, "hold_id")
        parsed_hold, reason = _parse_retention_hold(row)
        rows_by_hold_id[raw_hold_id] = _RetentionAuthorityRow(
            row=row,
            hold=parsed_hold,
            parse_reason=reason,
            hold_identity_sha256=_hold_identity(run_id, raw_hold_id),
        )

    failures: list[M5DatasetRetentionFailure] = []
    for hold_id, (expected_dataset_id, expected_hold) in sorted(expected_by_hold_id.items()):
        durable = rows_by_hold_id.get(hold_id)
        identity = _hold_identity(run_id, hold_id)
        if durable is None:
            failures.append(
                M5DatasetRetentionFailure(
                    M5DatasetRetentionFailureType.HOLD_MISSING,
                    identity,
                    expected_dataset_id,
                    "EXPECTED_HOLD_MISSING",
                )
            )
            continue
        row = durable.row
        indexed_owner = (
            _required_text(row, "owner_kind"),
            _required_text(row, "owner_id"),
        )
        expected_owner = (
            expected_hold.owner_ref.ref.kind.value,
            expected_hold.owner_ref.ref.artifact_id,
        )
        if indexed_owner != expected_owner or (
            durable.hold is not None and durable.hold.owner_ref != expected_hold.owner_ref
        ):
            failures.append(
                M5DatasetRetentionFailure(
                    M5DatasetRetentionFailureType.HOLD_OWNER_MISMATCH,
                    identity,
                    expected_dataset_id,
                    "EXPECTED_DATASET_OWNER_MISMATCH",
                )
            )
        link = links_by_hold_id.get(hold_id)
        released_sequence = (
            _optional_integer(link, "released_audit_sequence") if link is not None else None
        )
        if _required_integer(row, "active") != 1 or released_sequence is not None:
            failures.append(
                M5DatasetRetentionFailure(
                    M5DatasetRetentionFailureType.HOLD_RELEASED,
                    identity,
                    expected_dataset_id,
                    "EXPECTED_HOLD_NOT_ACTIVE",
                )
            )
        if durable.hold != expected_hold:
            failures.append(
                M5DatasetRetentionFailure(
                    M5DatasetRetentionFailureType.HOLD_DOCUMENT_MISMATCH,
                    identity,
                    expected_dataset_id,
                    durable.parse_reason or "EXPECTED_HOLD_DOCUMENT_MISMATCH",
                )
            )
        if not _valid_dataset_hold_audit_link(
            expected=expected_hold,
            link=link,
            audits_by_sequence=audits_by_sequence,
        ):
            failures.append(
                M5DatasetRetentionFailure(
                    M5DatasetRetentionFailureType.AUDIT_LINK_INVALID,
                    identity,
                    expected_dataset_id,
                    "RETENTION_HOLD_CREATED_AUDIT_INVALID",
                )
            )

    for hold_id, durable in sorted(rows_by_hold_id.items()):
        row = durable.row
        owner_kind = _required_text(row, "owner_kind")
        owner_id = _required_text(row, "owner_id")
        owner_dataset_id: str | None = (
            owner_id
            if owner_kind == ArtifactKind.DATASET.value and owner_id in reports_by_dataset
            else None
        )
        if owner_kind == ArtifactKind.DATASET.value:
            expected_ids = expected_ids_by_dataset.get(owner_id)
            if expected_ids is not None and hold_id not in expected_ids:
                failures.append(
                    M5DatasetRetentionFailure(
                        M5DatasetRetentionFailureType.HOLD_EXTRA,
                        durable.hold_identity_sha256,
                        owner_id,
                        "UNEXPECTED_DATASET_OWNED_HOLD",
                    )
                )
            if owner_id not in reports_by_dataset:
                failures.append(
                    M5DatasetRetentionFailure(
                        M5DatasetRetentionFailureType.ORPHAN_DATASET_HOLD,
                        durable.hold_identity_sha256,
                        owner_dataset_id,
                        "DATASET_OWNER_NOT_REGISTERED",
                    )
                )
        elif owner_kind == ArtifactKind.APPEAL.value and owner_id not in appeal_ids:
            failures.append(
                M5DatasetRetentionFailure(
                    M5DatasetRetentionFailureType.ORPHAN_APPEAL_HOLD,
                    durable.hold_identity_sha256,
                    None,
                    "APPEAL_OWNER_NOT_REGISTERED",
                )
            )

    failures = sorted(
        set(failures),
        key=lambda item: (
            item.failure_type.value,
            item.hold_identity_sha256,
            item.dataset_id or "",
            item.reason_code,
        ),
    )
    orphan_types = {
        M5DatasetRetentionFailureType.ORPHAN_APPEAL_HOLD,
        M5DatasetRetentionFailureType.ORPHAN_DATASET_HOLD,
    }
    relevant_hold_ids = {
        hold_id
        for hold_id, durable in rows_by_hold_id.items()
        if _required_text(durable.row, "owner_kind")
        in {ArtifactKind.APPEAL.value, ArtifactKind.DATASET.value}
        or hold_id in expected_by_hold_id
    }
    linked_sequences = {
        sequence
        for hold_id in relevant_hold_ids
        for sequence in _link_sequences(links_by_hold_id.get(hold_id))
    }
    root_sha256 = hashlib.sha256(
        canonical_json(
            [
                "m5-retention-authority-root",
                1,
                run_id,
                [
                    [
                        _hold_identity(run_id, hold_id),
                        _retention_row_digest(
                            "retention_holds",
                            rows_by_hold_id[hold_id].row,
                            (
                                "run_id",
                                "hold_id",
                                "target_kind",
                                "target_id",
                                "hold_kind",
                                "owner_kind",
                                "owner_id",
                                "active",
                                "manifest_id",
                                "policy_version",
                                "reason_code",
                                "hold_json",
                                "document_sha256",
                            ),
                        ),
                    ]
                    for hold_id in sorted(relevant_hold_ids)
                ],
                [
                    [
                        _hold_identity(run_id, hold_id),
                        _retention_row_digest(
                            "retention_hold_audit_links",
                            links_by_hold_id[hold_id],
                            (
                                "run_id",
                                "hold_id",
                                "created_audit_sequence",
                                "released_audit_sequence",
                            ),
                        ),
                    ]
                    for hold_id in sorted(relevant_hold_ids)
                    if hold_id in links_by_hold_id
                ],
                [[sequence, audit_digests[sequence]] for sequence in sorted(linked_sequences)],
            ]
        ).encode()
    ).hexdigest()
    return _DatasetRetentionValidation(
        failures=tuple(failures),
        dataset_hold_count=sum(
            _required_text(row.row, "owner_kind") == ArtifactKind.DATASET.value
            for row in rows_by_hold_id.values()
        ),
        orphan_count=sum(item.failure_type in orphan_types for item in failures),
        root_sha256=root_sha256,
    )


def _stream_retention_holds(
    connection: sqlite3.Connection,
    run_id: str,
    expected_count: int,
) -> tuple[sqlite3.Row, ...]:
    cursor = connection.execute(
        "SELECT * FROM retention_holds WHERE run_id = ? ORDER BY hold_id LIMIT ?",
        (run_id, expected_count + 1),
    )
    return _consume_exact_rows(cursor, expected_count)


def _stream_retention_links(
    connection: sqlite3.Connection,
    run_id: str,
    expected_count: int,
) -> tuple[sqlite3.Row, ...]:
    cursor = connection.execute(
        """
        SELECT * FROM retention_hold_audit_links
        WHERE run_id = ? ORDER BY hold_id LIMIT ?
        """,
        (run_id, expected_count + 1),
    )
    return _consume_exact_rows(cursor, expected_count)


def _stream_retention_audits(
    connection: sqlite3.Connection,
    run_id: str,
    expected_count: int,
) -> tuple[sqlite3.Row, ...]:
    cursor = connection.execute(
        """
        SELECT audit.*
        FROM audit_entries AS audit
        JOIN (
            SELECT run_id, created_audit_sequence AS sequence
            FROM retention_hold_audit_links WHERE run_id = ?
            UNION
            SELECT run_id, released_audit_sequence AS sequence
            FROM retention_hold_audit_links
            WHERE run_id = ? AND released_audit_sequence IS NOT NULL
        ) AS linked
          ON linked.run_id = audit.run_id AND linked.sequence = audit.sequence
        WHERE audit.run_id = ?
        ORDER BY audit.sequence LIMIT ?
        """,
        (run_id, run_id, run_id, expected_count + 1),
    )
    return _consume_exact_rows(cursor, expected_count)


def _consume_exact_rows(
    cursor: sqlite3.Cursor,
    expected_count: int,
) -> tuple[sqlite3.Row, ...]:
    rows: list[sqlite3.Row] = []
    for row in cursor:
        rows.append(row)
        if len(rows) > expected_count:
            raise ValueError("retention authority changed after SQL preflight")
    if len(rows) != expected_count:
        raise ValueError("retention authority changed after SQL preflight")
    return tuple(rows)


def _parse_retention_hold(row: sqlite3.Row) -> tuple[RetentionHold | None, str | None]:
    try:
        raw = _required_text(row, "hold_json")
        claimed_sha256 = _required_text(row, "document_sha256")
        if hashlib.sha256(raw.encode()).hexdigest() != claimed_sha256:
            return None, "HOLD_DOCUMENT_HASH_MISMATCH"
        hold = RetentionHold.model_validate_json(raw)
        if canonical_json(hold.model_dump(mode="json")) != raw:
            return None, "HOLD_DOCUMENT_NONCANONICAL"
        expected_index = (
            hold.run_id,
            hold.hold_id,
            hold.target_ref.ref.kind.value,
            hold.target_ref.ref.artifact_id,
            hold.kind.value,
            hold.owner_ref.ref.kind.value,
            hold.owner_ref.ref.artifact_id,
            hold.manifest_id,
            hold.policy_version,
            hold.reason_code,
        )
        actual_index = tuple(
            row[column]
            for column in (
                "run_id",
                "hold_id",
                "target_kind",
                "target_id",
                "hold_kind",
                "owner_kind",
                "owner_id",
                "manifest_id",
                "policy_version",
                "reason_code",
            )
        )
        if actual_index != expected_index:
            return None, "HOLD_DOCUMENT_INDEX_MISMATCH"
        return hold, None
    except (TypeError, ValueError):
        return None, "HOLD_DOCUMENT_INVALID"


def _parse_audit_entry(row: sqlite3.Row) -> AuditEntry | None:
    try:
        raw = _required_text(row, "entry_json")
        claimed_sha256 = _required_text(row, "document_sha256")
        if hashlib.sha256(raw.encode()).hexdigest() != claimed_sha256:
            return None
        entry = AuditEntry.model_validate_json(raw)
        if canonical_json(entry.model_dump(mode="json")) != raw:
            return None
        expected_index = (
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
        )
        actual_index = tuple(
            row[column]
            for column in (
                "run_id",
                "sequence",
                "manifest_id",
                "actor",
                "action",
                "object_kind",
                "object_id",
                "before_sha256",
                "after_sha256",
                "recorded_at",
                "prev_entry_hash",
                "entry_hash",
            )
        )
        return entry if actual_index == expected_index else None
    except (TypeError, ValueError):
        return None


def _valid_dataset_hold_audit_link(
    *,
    expected: RetentionHold,
    link: sqlite3.Row | None,
    audits_by_sequence: Mapping[int, AuditEntry | None],
) -> bool:
    if link is None or _optional_integer(link, "released_audit_sequence") is not None:
        return False
    try:
        created_sequence = _required_integer(link, "created_audit_sequence")
    except ValueError:
        return False
    audit = audits_by_sequence.get(created_sequence)
    hold_sha256 = hashlib.sha256(
        canonical_json(expected.model_dump(mode="json")).encode()
    ).hexdigest()
    return (
        audit is not None
        and audit.actor == AuditActorRole.RETENTION.value
        and audit.action == AuditAction.RETENTION_HOLD_CREATED
        and audit.object_ref == expected.target_ref.ref
        and audit.before_sha256 is None
        and audit.after_sha256 == hold_sha256
        and audit.manifest_id == expected.manifest_id
    )


def _required_text(row: sqlite3.Row, key: str) -> str:
    value = row[key]
    if not isinstance(value, str):
        raise ValueError(f"{key} must be text")
    return value


def _required_integer(row: sqlite3.Row, key: str) -> int:
    value = row[key]
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{key} must be a non-negative integer")
    return value


def _optional_integer(row: sqlite3.Row | None, key: str) -> int | None:
    if row is None or row[key] is None:
        return None
    return _required_integer(row, key)


def _link_sequences(row: sqlite3.Row | None) -> tuple[int, ...]:
    if row is None:
        return ()
    created = _required_integer(row, "created_audit_sequence")
    released = _optional_integer(row, "released_audit_sequence")
    return (created,) if released is None else (created, released)


def _hold_identity(run_id: str, hold_id: str) -> str:
    return hashlib.sha256(
        canonical_json(["m5-retention-hold-identity", 1, run_id, hold_id]).encode()
    ).hexdigest()


def _retention_row_digest(
    table: str,
    row: sqlite3.Row,
    columns: tuple[str, ...],
) -> str:
    return hashlib.sha256(
        canonical_json(["m5-retention-row", 1, table, [row[item] for item in columns]]).encode()
    ).hexdigest()


CounterKey = dict[tuple[str, int], int]


def _typed(
    records: dict[M5AuthorityKind, list[M5Record]],
    kind: M5AuthorityKind,
    model_type: type[ModelT],
) -> tuple[tuple[M5Record, ModelT], ...]:
    return tuple(
        (record, record.document)
        for record in records[kind]
        if isinstance(record.document, model_type)
    )


def _citation_commits(
    records: dict[M5AuthorityKind, list[M5Record]],
) -> tuple[tuple[M5Record, M5CitationCommit], ...]:
    valid = (M5PrecedentCitationCommit, M5PrecedentApplicationCitationCommit)
    return tuple(
        (record, record.document)
        for record in records[M5AuthorityKind.PRECEDENT_CITATION]
        if isinstance(record.document, valid)
    )


LifecycleReceipt: TypeAlias = (
    M5PrecedentActivationReceipt | M5PrecedentConflictReceipt | M5PrecedentRevocationReceipt
)


def _lifecycle_receipts(
    records: dict[M5AuthorityKind, list[M5Record]],
) -> tuple[
    tuple[
        M5Record,
        LifecycleReceipt,
    ],
    ...,
]:
    valid = (
        M5PrecedentActivationReceipt,
        M5PrecedentConflictReceipt,
        M5PrecedentRevocationReceipt,
    )
    result: list[tuple[M5Record, LifecycleReceipt]] = []
    for record in records[M5AuthorityKind.PRECEDENT_LIFECYCLE]:
        if isinstance(record.document, valid):
            result.append((record, record.document))
    return tuple(result)


def _receipt_refs(
    receipt: M5PrecedentActivationReceipt
    | M5PrecedentConflictReceipt
    | M5PrecedentRevocationReceipt,
) -> tuple[tuple[str, str, int, bool], ...]:
    if isinstance(receipt, (M5PrecedentActivationReceipt, M5PrecedentRevocationReceipt)):
        return (
            (receipt.precedent_id, receipt.prior_authority_id, receipt.prior_revision, False),
            (
                receipt.precedent_id,
                receipt.resulting_authority_id,
                receipt.resulting_revision,
                receipt.resulting_revision > receipt.prior_revision,
            ),
        )
    return (
        (
            receipt.existing_precedent_id,
            receipt.existing_prior_authority_id,
            receipt.existing_prior_revision,
            False,
        ),
        (
            receipt.existing_precedent_id,
            receipt.existing_resulting_authority_id,
            receipt.existing_resulting_revision,
            receipt.existing_resulting_revision > receipt.existing_prior_revision,
        ),
        (
            receipt.new_precedent_id,
            receipt.new_prior_authority_id,
            receipt.new_prior_revision,
            False,
        ),
        (
            receipt.new_precedent_id,
            receipt.new_resulting_authority_id,
            receipt.new_resulting_revision,
            receipt.new_resulting_revision > receipt.new_prior_revision,
        ),
    )


def _case_ids(
    precedents: tuple[tuple[M5Record, M5PrecedentAuthority], ...],
    exposures: tuple[tuple[M5Record, M5PrecedentExposureBatchAuthority], ...],
    application_batches: tuple[tuple[M5Record, M5PrecedentApplicationBatchAuthority], ...],
    citations: tuple[tuple[M5Record, M5CitationCommit], ...],
    alerts: tuple[tuple[M5Record, AlertPolicyAuthority], ...],
    appeals: tuple[tuple[M5Record, AppealVersionAuthority], ...],
    labels: tuple[tuple[M5Record, TrainingLabel], ...],
) -> set[str]:
    return {
        *(
            item.precedent.source_case_id
            for _record, item in precedents
            if item.precedent.source_case_id
        ),
        *(item.case_id for _record, item in exposures),
        *(item.case_id for _record, item in application_batches),
        *(item.citation.case_id for _record, item in citations),
        *(item.request.case_id for _record, item in alerts),
        *(item.appeal.case_id for _record, item in appeals),
        *(item.case_id for _record, item in labels),
    }


def _case_anchor(
    records: dict[M5AuthorityKind, list[M5Record]],
    case_id: str,
) -> tuple[M5AuthorityKind, M5Record | None]:
    for kind in (
        M5AuthorityKind.ALERT,
        M5AuthorityKind.APPEAL,
        M5AuthorityKind.TRAINING_LABEL,
        M5AuthorityKind.PRECEDENT_APPLICATION_BATCH,
        M5AuthorityKind.PRECEDENT_EXPOSURE,
        M5AuthorityKind.PRECEDENT_CITATION,
        M5AuthorityKind.PRECEDENT,
    ):
        for record in records[kind]:
            if _record_case_id(record) == case_id:
                return kind, record
    return M5AuthorityKind.ALERT, None


def _record_case_id(record: M5Record) -> str | None:
    row = record.row
    columns = frozenset(row.keys())
    if "case_id" in columns and isinstance(row["case_id"], str):
        return str(row["case_id"])
    if "source_case_id" in columns and isinstance(row["source_case_id"], str):
        return str(row["source_case_id"])
    return None


def _load_case_version(
    connection: sqlite3.Connection,
    run_id: str,
    case_id: str,
    revision: object,
) -> tuple[str, Case] | None:
    if not isinstance(revision, int) or isinstance(revision, bool):
        return None
    row = connection.execute(
        """
        SELECT case_json, document_sha256 FROM case_versions
        WHERE run_id = ? AND case_id = ? AND revision = ?
        """,
        (run_id, case_id, revision),
    ).fetchone()
    if row is None or not isinstance(row["case_json"], str):
        return None
    raw = str(row["case_json"])
    try:
        case = Case.model_validate_json(raw)
    except ValidationError:
        return None
    digest = hashlib.sha256(raw.encode()).hexdigest()
    if canonical_json(case.model_dump(mode="json")) != raw or row["document_sha256"] != digest:
        return None
    return digest, case


def _validate_historical_crop_snapshot(
    *,
    connection: sqlite3.Connection,
    run_id: str,
    record: M5Record,
    snapshot: M5DatasetCropSnapshotAuthority,
    failures: list[M5ArtifactAuthorityFailure],
) -> bool:
    case_rows = connection.execute(
        """
        SELECT case_json, document_sha256 FROM case_versions
        WHERE run_id = ? AND case_id = ? AND revision = ?
        LIMIT 2
        """,
        (run_id, snapshot.crop_authority.case_id, snapshot.case_revision),
    ).fetchall()
    if len(case_rows) != 1:
        _fail(
            failures,
            record.kind,
            record,
            M5TrainingHistoryReasonCode.DATASET_HISTORICAL_CASE_MISSING.value,
        )
        return False
    case_row = case_rows[0]
    raw_case = case_row["case_json"]
    try:
        case = Case.model_validate_json(raw_case)
    except (TypeError, ValidationError, ValueError):
        case = None
    if (
        case is None
        or not isinstance(raw_case, str)
        or canonical_json(case.model_dump(mode="json")) != raw_case
        or hashlib.sha256(raw_case.encode()).hexdigest() != case_row["document_sha256"]
        or case_row["document_sha256"] != snapshot.case_document_sha256
        or case.run_id != run_id
        or case.case_id != snapshot.crop_authority.case_id
    ):
        _fail(
            failures,
            record.kind,
            record,
            M5TrainingHistoryReasonCode.DATASET_HISTORICAL_CASE_DOCUMENT_MISMATCH.value,
        )
        return False

    pack_rows = connection.execute(
        """
        SELECT * FROM evidence_packs
        WHERE run_id = ? AND case_id = ? AND pack_id = ? AND version = ?
        LIMIT 2
        """,
        (
            run_id,
            snapshot.crop_authority.case_id,
            snapshot.evidence_pack_id,
            snapshot.evidence_pack_version,
        ),
    ).fetchall()
    if len(pack_rows) != 1:
        _fail(
            failures,
            record.kind,
            record,
            M5TrainingHistoryReasonCode.DATASET_HISTORICAL_PACK_INVALID.value,
        )
        return False
    pack_row = pack_rows[0]
    raw_pack = pack_row["pack_json"]
    try:
        pack = EvidencePack.model_validate_json(raw_pack)
    except (TypeError, ValidationError, ValueError):
        pack = None
    embedded_pack = next(
        (
            item
            for item in case.evidence_packs
            if item.pack_id == snapshot.evidence_pack_id
            and item.version == snapshot.evidence_pack_version
        ),
        None,
    )
    if (
        pack is None
        or not isinstance(raw_pack, str)
        or canonical_json(pack.model_dump(mode="json")) != raw_pack
        or hashlib.sha256(raw_pack.encode()).hexdigest() != pack_row["document_sha256"]
        or pack_row["document_sha256"] != snapshot.evidence_pack_document_sha256
        or pack.run_id != run_id
        or pack.case_id != snapshot.crop_authority.case_id
        or pack.pack_id != snapshot.evidence_pack_id
        or pack.version != snapshot.evidence_pack_version
        or pack.manifest_id != pack_row["manifest_id"]
        or pack.complete != bool(pack_row["complete"])
        or pack.pack_input_sha256 != pack_row["pack_input_sha256"]
        or pack.closure_input_sha256 != pack_row["closure_input_sha256"]
        or embedded_pack != pack
    ):
        _fail(
            failures,
            record.kind,
            record,
            M5TrainingHistoryReasonCode.DATASET_HISTORICAL_PACK_INVALID.value,
        )
        return False
    crop = next(
        (item for item in pack.crops if item.crop_id == snapshot.crop_authority.crop.crop_id),
        None,
    )
    if (
        crop is None
        or crop != snapshot.crop_authority.crop
        or snapshot.crop_authority.run_id != run_id
        or snapshot.crop_authority.manifest_id != case.manifest_id
    ):
        _fail(
            failures,
            record.kind,
            record,
            M5TrainingHistoryReasonCode.DATASET_HISTORICAL_CROP_INVALID.value,
        )
        return False
    return True


def _load_exact_m4_document(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    table: str,
    artifact_id: str,
) -> M4Record | None:
    spec = _M4_SPEC_BY_TABLE.get(table)
    if spec is None:
        return None
    rows = connection.execute(
        f"SELECT * FROM {table} WHERE run_id = ? AND {spec.id_column} = ? LIMIT 2",
        (run_id, artifact_id),
    ).fetchall()
    if len(rows) != 1:
        return None
    try:
        return load_m4_record(rows[0], spec)
    except (M4DocumentFailure, M4IndexFailure, TypeError, ValueError):
        return None


def _load_exact_verdict(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    case_id: str,
    verdict: Verdict,
) -> Verdict | None:
    rows = connection.execute(
        """
        SELECT * FROM verdicts
        WHERE run_id = ? AND case_id = ? AND verdict_id = ? AND version = ?
        LIMIT 2
        """,
        (run_id, case_id, verdict.verdict_id, verdict.version),
    ).fetchall()
    if len(rows) != 1 or not isinstance(rows[0]["verdict_json"], str):
        return None
    row = rows[0]
    raw = str(row["verdict_json"])
    try:
        durable = Verdict.model_validate_json(raw)
    except (ValidationError, TypeError, ValueError):
        return None
    if (
        canonical_json(durable.model_dump(mode="json")) != raw
        or hashlib.sha256(raw.encode("utf-8")).hexdigest() != row["document_sha256"]
        or durable.run_id != row["run_id"]
        or durable.case_id != row["case_id"]
        or durable.verdict_id != row["verdict_id"]
        or durable.version != row["version"]
        or durable.screening_id != row["screening_id"]
        or durable.evidence_pack_id != row["evidence_pack_id"]
        or durable.evidence_pack_version != row["evidence_pack_version"]
        or durable.verdict_input_sha256 != row["verdict_input_sha256"]
        or durable.verdict_sha256 != row["verdict_sha256"]
        or durable.manifest_id != row["manifest_id"]
    ):
        return None
    return durable


def _load_final_hearing_usage(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    case_id: str,
    verdict: Verdict,
) -> _FinalHearingUsage | None:
    rows = connection.execute(
        """
        SELECT * FROM m4_hearing_verdict_bindings
        WHERE run_id = ? AND case_id = ? AND verdict_id = ? AND verdict_version = ?
        LIMIT 2
        """,
        (run_id, case_id, verdict.verdict_id, verdict.version),
    ).fetchall()
    if len(rows) != 1:
        return None
    binding_record = _load_exact_m4_document(
        connection,
        run_id=run_id,
        table="m4_hearing_verdict_bindings",
        artifact_id=str(rows[0]["binding_id"]),
    )
    if binding_record is None or not isinstance(
        binding_record.document,
        HearingVerdictBinding,
    ):
        return None
    binding = binding_record.document
    round_record = _load_exact_m4_document(
        connection,
        run_id=run_id,
        table="m4_hearing_rounds",
        artifact_id=binding.judge_round_id,
    )
    if round_record is None or not isinstance(round_record.document, HearingRound):
        return None
    hearing_round = round_record.document
    receipt_record = _load_exact_m4_document(
        connection,
        run_id=run_id,
        table="m4_precedent_retrieval_receipts",
        artifact_id=hearing_round.precedent_retrieval_receipt.receipt_id,
    )
    maximum = connection.execute(
        """
        SELECT MAX(round_index) AS maximum_round
        FROM m4_hearing_rounds WHERE run_id = ? AND hearing_id = ?
        """,
        (run_id, binding.hearing_session_id),
    ).fetchone()
    judge_payload = hearing_round.judge_output.payload
    binding_row = binding_record.row
    if (
        receipt_record is None
        or not isinstance(receipt_record.document, HearingPrecedentRetrievalReceipt)
        or receipt_record.document != hearing_round.precedent_retrieval_receipt
        or maximum is None
        or maximum["maximum_round"] != hearing_round.round_index
        or binding.run_id != run_id
        or binding.case_id != case_id
        or binding.verdict_id != verdict.verdict_id
        or binding.verdict_version != verdict.version
        or binding.verdict_input_sha256 != verdict.verdict_input_sha256
        or binding.verdict_sha256 != verdict.verdict_sha256
        or binding.evidence_pack_id != verdict.evidence_pack_id
        or binding.evidence_pack_version != verdict.evidence_pack_version
        or binding.hearing_session_id != hearing_round.hearing_session_id
        or binding.judge_round_id != hearing_round.round_id
        or binding.judge_round_index != hearing_round.round_index
        or binding.prosecutor_output_id != hearing_round.prosecutor_output.output_id
        or binding.defender_output_id != hearing_round.defender_output.output_id
        or binding.judge_output_id != hearing_round.judge_output.output_id
        or binding.manifest_id != hearing_round.manifest_id
        or binding_row["cycle_scope_id"] != hearing_round.cycle_scope_id
        or binding_row["cycle_scope_sha256"] != hearing_round.cycle_scope_sha256
        or not isinstance(judge_payload, JudgeModelPayload)
        or not isinstance(judge_payload.outcome, JudgeFinalDecisionPayload)
    ):
        return None
    return _FinalHearingUsage(binding=binding, hearing_round=hearing_round)


def _verdict_has_m4_response_origin(
    connection: sqlite3.Connection,
    run_id: str,
    verdict: Verdict,
) -> bool:
    response_ids = tuple(
        reference.artifact_id
        for reference in verdict.model_response_refs
        if reference.kind == ArtifactKind.MODEL_RESPONSE
    )
    if not response_ids:
        return False
    placeholders = ", ".join("?" for _response_id in response_ids)
    row = connection.execute(
        f"""
        SELECT COUNT(*) AS response_count FROM m4_model_responses
        WHERE run_id = ? AND response_id IN ({placeholders})
        """,
        (run_id, *response_ids),
    ).fetchone()
    return row is not None and isinstance(row["response_count"], int) and row["response_count"] > 0


def _document_matches_manifest(
    document: BaseModel | dict[str, object],
    run_id: str,
    manifest: RunManifest,
) -> bool:
    text_model = manifest.models["text_embedding"].model_manifest_id
    visual_model = manifest.models["visual_embedding"].model_manifest_id
    detector_model = manifest.models["detector"].model_manifest_id

    if isinstance(document, M5EmbeddingVector):
        expected = text_model if document.request.channel.value == "TEXT" else visual_model
        return document.request.model_manifest_id == expected
    if isinstance(document, M5PrecedentAuthority):
        return (
            document.run_id == run_id
            and document.config_sha256 == manifest.config_sha256
            and document.precedent.rule_version == manifest.rule_version
            and (
                document.text_embedding is None
                or _document_matches_manifest(document.text_embedding, run_id, manifest)
            )
            and all(
                _document_matches_manifest(item, run_id, manifest)
                for item in document.visual_embeddings
            )
        )
    if isinstance(document, M5PrecedentCausalEvent):
        return document.run_id == run_id and document.manifest_id == manifest.manifest_id
    if isinstance(document, M5TrainingCausalEvent):
        return document.run_id == run_id and document.manifest_id == manifest.manifest_id
    if isinstance(document, M5PrecedentExposureBatchAuthority):
        m4_query = document.m4_retrieval_outcome.query
        m5_query = document.m5_retrieval_result.query
        return (
            document.run_id == run_id
            and document.manifest_id == manifest.manifest_id
            and document.config_sha256 == manifest.config_sha256
            and m4_query.run_id == run_id
            and m4_query.manifest_id == manifest.manifest_id
            and m4_query.config_sha256 == manifest.config_sha256
            and m4_query.rule_version == manifest.rule_version
            and m4_query.embedding_model_manifest.model_manifest_id == text_model
            and m5_query.run_id == run_id
            and m5_query.rule_version == manifest.rule_version
            and m5_query.policy.config_sha256 == manifest.config_sha256
            and m5_query.text_embedding_model_manifest_id == text_model
            and m5_query.visual_embedding_model_manifest_id == visual_model
        )
    if isinstance(document, M5PrecedentApplicationBatchAuthority):
        return (
            document.run_id == run_id
            and document.manifest_id == manifest.manifest_id
            and document.config_sha256 == manifest.config_sha256
            and document.ready_case.run_id == run_id
            and document.ready_case.manifest_id == manifest.manifest_id
            and document.verdict.run_id == run_id
            and document.verdict.manifest_id == manifest.manifest_id
            and _document_matches_manifest(document.exposure, run_id, manifest)
        )
    if isinstance(document, M5PrecedentApplicationCitationCommit):
        return document.citation.run_id == run_id and _document_matches_manifest(
            document.application_batch, run_id, manifest
        )
    if isinstance(document, M5PrecedentCitationCommit):
        query = document.retrieval_result.query
        return (
            document.citation.run_id == run_id
            and query.run_id == run_id
            and query.rule_version == manifest.rule_version
            and query.policy.config_sha256 == manifest.config_sha256
            and query.text_embedding_model_manifest_id == text_model
            and query.visual_embedding_model_manifest_id == visual_model
            and (
                query.text_embedding is None
                or _document_matches_manifest(query.text_embedding, run_id, manifest)
            )
            and all(
                _document_matches_manifest(item, run_id, manifest)
                for item in query.visual_embeddings
            )
        )
    if isinstance(document, M5PrecedentConflictBatchAuthority):
        return (
            document.run_id == run_id
            and document.config_sha256 == manifest.config_sha256
            and document.causal_cut.manifest_id == manifest.manifest_id
            and all(item.rule_version == manifest.rule_version for item in document.candidates)
        )
    if isinstance(document, M5PrecedentConflictBatchReceipt):
        return document.run_id == run_id and document.config_sha256 == manifest.config_sha256
    if isinstance(
        document,
        (
            M5PrecedentActivationReceipt,
            M5PrecedentConflictReceipt,
            M5PrecedentRevocationReceipt,
        ),
    ):
        return document.run_id == run_id
    if isinstance(document, AlertPolicyAuthority):
        request = document.request
        return (
            request.run_id == run_id
            and request.manifest_id == manifest.manifest_id
            and request.config_sha256 == manifest.config_sha256
            and (
                document.outbox_item is None
                or _document_matches_manifest(document.outbox_item, run_id, manifest)
            )
        )
    if isinstance(document, AlertOutboxItem):
        return document.run_id == run_id and document.manifest_id == manifest.manifest_id
    if isinstance(document, AlertChannelCapabilityAuthority):
        return (
            document.run_id == run_id
            and document.manifest_id == manifest.manifest_id
            and document.config_sha256 == manifest.config_sha256
        )
    if isinstance(document, (AlertDispatchAttempt, AlertDispatchReceipt)):
        return _document_matches_manifest(document.channel_capability, run_id, manifest)
    if isinstance(document, AppealVersionAuthority):
        return _appeal_matches_manifest(document, run_id, manifest)
    if isinstance(document, AppealResolutionSideEffectIntent):
        return (
            document.run_id == run_id
            and document.manifest_id == manifest.manifest_id
            and document.rule_version == manifest.rule_version
            and document.text_embedding_manifest_id == text_model
            and document.visual_embedding_manifest_id == visual_model
            and _appeal_matches_manifest(document.appeal_authority, run_id, manifest)
            and all(
                _document_matches_manifest(item, run_id, manifest)
                for item in document.training_labels
            )
            and (
                document.appeal_precedent_authority is None
                or _document_matches_manifest(
                    document.appeal_precedent_authority,
                    run_id,
                    manifest,
                )
            )
        )
    if isinstance(document, M5StrongTrainingLabelProvenanceReceipt):
        return (
            document.run_id == run_id
            and document.manifest_id == manifest.manifest_id
            and document.rule_version == manifest.rule_version
            and document.detector_manifest_id == detector_model
        )
    if isinstance(document, TrainingLabel):
        return (
            document.rule_version == manifest.rule_version
            and document.detector_manifest_id == detector_model
        )
    if isinstance(document, DatasetExportReport):
        return (
            document.run_id == run_id
            and document.manifest_id == manifest.manifest_id
            and document.rule_version == manifest.rule_version
            and document.detector_manifest_id == detector_model
        )
    if isinstance(document, M5DatasetRegistrationSnapshotAuthority):
        return (
            document.run_id == run_id
            and document.manifest_id == manifest.manifest_id
            and document.rule_version == manifest.rule_version
            and document.detector_manifest_id == detector_model
        )
    if isinstance(document, M5DatasetCropSnapshotAuthority):
        authority = document.crop_authority
        return (
            document.run_id == run_id
            and authority.run_id == run_id
            and authority.manifest_id == manifest.manifest_id
            and authority.rule_version == manifest.rule_version
            and authority.detector_manifest_id == detector_model
        )
    # Cooldown, rescission, and immediate-safety documents carry their trust
    # through graph/index closure rather than their own run fields.
    return True


def _secondary_documents_match_manifest(
    record: M5Record,
    run_id: str,
    manifest: RunManifest,
) -> bool:
    if record.table != "precedent_lifecycle_receipts":
        return True
    raw = record.row["context_json"]
    kind = record.row["receipt_kind"]
    if not isinstance(raw, str) or not isinstance(kind, str):
        return False
    try:
        if kind == "ACTIVATION":
            return M5AppealWindowSnapshot.model_validate_json(raw).run_id == run_id
        if kind == "CONFLICT":
            return (
                M5PrecedentPolicy.model_validate_json(raw).config_sha256 == manifest.config_sha256
            )
        if kind == "REVOCATION":
            return M5PrecedentCitationSnapshot.model_validate_json(raw).run_id == run_id
    except ValidationError:
        return False
    return False


def _appeal_matches_manifest(
    appeal: AppealVersionAuthority,
    run_id: str,
    manifest: RunManifest,
) -> bool:
    source = appeal.source_case_authority
    return (
        appeal.run_id == run_id
        and appeal.manifest_id == manifest.manifest_id
        and appeal.rule_version == manifest.rule_version
        and appeal.text_embedding_manifest_id == manifest.models["text_embedding"].model_manifest_id
        and appeal.visual_embedding_manifest_id
        == manifest.models["visual_embedding"].model_manifest_id
        and source.run_id == run_id
        and source.manifest_id == manifest.manifest_id
        and source.config_sha256 == manifest.config_sha256
        and source.rule_version == manifest.rule_version
        and source.detector_manifest_id == manifest.models["detector"].model_manifest_id
        and source.text_embedding_manifest_id == manifest.models["text_embedding"].model_manifest_id
        and source.visual_embedding_manifest_id
        == manifest.models["visual_embedding"].model_manifest_id
    )


def _precedent_heads(
    precedents: tuple[tuple[M5Record, M5PrecedentAuthority], ...],
) -> dict[str, M5PrecedentAuthority]:
    result: dict[str, M5PrecedentAuthority] = {}
    for _record, authority in precedents:
        precedent_id = authority.precedent.precedent_id
        current = result.get(precedent_id)
        if current is None or authority.revision > current.revision:
            result[precedent_id] = authority
    return result


def _precedent_heads_for_case(
    precedents: list[M5PrecedentAuthority],
) -> tuple[M5PrecedentAuthority, ...]:
    result: dict[str, M5PrecedentAuthority] = {}
    for authority in precedents:
        precedent_id = authority.precedent.precedent_id
        if precedent_id not in result or authority.revision > result[precedent_id].revision:
            result[precedent_id] = authority
    return tuple(result[key] for key in sorted(result))


def _case_crop_ids(case: Case) -> set[str]:
    return {
        crop.crop_id
        for pack in case.evidence_packs
        for group in (
            pack.panorama_crops,
            pack.subject_crops,
            pack.focus_crops,
            pack.temporal_crops,
        )
        for crop in group
    }


def _documents_by_case(
    records: dict[M5AuthorityKind, list[M5Record]],
) -> dict[str, list[M5Record]]:
    result: dict[str, list[M5Record]] = defaultdict(list)
    for kind_records in records.values():
        for record in kind_records:
            case_id = _record_case_id(record)
            if case_id is not None:
                result[case_id].append(record)
    for case_id in result:
        result[case_id].sort(key=lambda item: (item.kind.value, item.artifact_id))
    return result


def _document_sha(record: M5Record) -> str:
    return hashlib.sha256(record.canonical_document.encode()).hexdigest()


def _fail(
    failures: list[M5ArtifactAuthorityFailure],
    kind: M5AuthorityKind,
    record: M5Record | None,
    reason: str,
    *,
    head: bool = False,
) -> None:
    artifact_id = record.artifact_id if record is not None else None
    identity = hashlib.sha256(
        canonical_json(
            [
                "m5-reference-record",
                1,
                kind.value,
                record.table if record is not None else None,
                artifact_id,
            ]
        ).encode()
    ).hexdigest()
    failure = M5ArtifactAuthorityFailure(
        M5AuthorityFailureType.HEAD_INVALID if head else M5AuthorityFailureType.REFERENCE_INVALID,
        kind,
        identity,
        artifact_id,
        reason,
    )
    if failure not in failures:
        failures.append(failure)


__all__ = ["M5ArtifactReferenceValidator", "M5RelationValidation"]

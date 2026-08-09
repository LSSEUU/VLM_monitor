"""Transactional M5 appeal, rescission, label, and dataset authority."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.application.appeal_resolution import (
    AppealResolutionError,
    build_appeal_resolution_intent,
)
from labcourt.application.dataset_export import DatasetExportError
from labcourt.application.m5_dataset_integrity import (
    M5DatasetIntegrityError,
    rebuild_and_verify_m5_dataset,
)
from labcourt.application.m5_dataset_retention import m5_dataset_retention_holds
from labcourt.application.m5_embedding_integrity import (
    M5EmbeddingIntegrityError,
    build_m5_controlled_fake_embedding,
    is_m5_controlled_fake_model_manifest,
)
from labcourt.application.m5_human_labels import build_m5_appeal_training_labels
from labcourt.application.m5_training_history import (
    M5TrainingHistoryError,
    build_m5_dataset_label_snapshot_receipts,
    build_m5_dataset_registration_commit_event,
    build_m5_dataset_registration_snapshot,
    build_m5_training_causal_watermark,
    build_m5_training_label_causal_event,
    require_m5_training_causal_chain,
    resolve_m5_dataset_historical_replay,
)
from labcourt.application.m5_training_provenance import (
    M5TrainingLabelProvenanceError,
    build_m5_strong_training_label_provenance_receipts,
    require_m5_strong_training_label_provenance,
)
from labcourt.contracts.alert_policy import AlertPolicyAuthority
from labcourt.contracts.audit import AuditEntry, AuditEntryDraft
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.enums import (
    AppealStatus,
    ArtifactKind,
    AuditAction,
    AuditActorRole,
    CaseStatus,
    PrecedentSource,
    PrecedentStatus,
    VerificationStatus,
)
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.m5_appeals import (
    MAX_M5_APPEAL_TRAINING_LABELS,
    AffectedPrecedentCitation,
    AlertRescissionIntent,
    AppealableAlertAuthority,
    AppealResolutionCommand,
    AppealResolutionPrecedentSnapshot,
    AppealResolutionSideEffectIntent,
    AppealReviewCommand,
    AppealSubmissionCommand,
    AppealVersionAuthority,
    AutomaticPrecedentAppealAuthority,
    ClosedCaseAppealAuthority,
    M5AppealResolutionCommitReceipt,
    PrecedentRevocationIntent,
    VerdictRescissionIntent,
)
from labcourt.contracts.m5_precedents import (
    MAX_M5_CITATION_SNAPSHOT_ENTRIES,
    MAX_M5_PRECEDENTS,
    M5PrecedentAuthority,
    M5PrecedentRevocationOutcome,
    M5PrecedentRevocationReceipt,
)
from labcourt.contracts.m5_training import (
    DatasetExportReport,
    TrainingCropAuthority,
)
from labcourt.contracts.m5_training_history import (
    M5_TRAINING_CAUSAL_GENESIS_SHA256,
    M5DatasetCropSnapshotAuthority,
)
from labcourt.contracts.m5_training_provenance import (
    STRONG_TRAINING_LABEL_QUALITIES,
    M5StrongTrainingLabelProvenanceReceipt,
    M5TrainingLabelAuthority,
)
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import (
    ArtifactRef,
    ArtifactVerification,
    RetentionHold,
)
from labcourt.contracts.training import DatasetArtifact, TrainingLabel
from labcourt.domain.appeal_fsm import (
    AppealTransitionError,
    begin_appeal_review,
    resolve_appeal,
    submit_appeal,
)
from labcourt.domain.training_quality_gate import training_label_is_exportable
from labcourt.exceptions import (
    ConcurrentModification,
    ContractViolation,
    ManifestMismatch,
)
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot

from ._sqlite_m5_precedent_causal_ledger import (
    append_m5_precedent_causal_event,
    m5_appeal_resolution_commit_causal_source,
    require_m5_precedent_causal_event,
)
from ._sqlite_m5_training_history import (
    insert_m5_dataset_crop_snapshot,
    insert_m5_dataset_registration_snapshot,
    insert_m5_training_causal_event,
    list_m5_dataset_crop_snapshots,
    load_m5_dataset_registration_snapshot,
    load_m5_training_causal_events,
    require_m5_dataset_registration_marker,
)
from .sqlite_m3_repository_support import _load_document, _validated_copy
from .sqlite_m5_repository_host import SQLiteM5RepositoryHost
from .sqlite_repository import (
    RepositoryIntegrityError,
    _audit_entry_from_row,
    _document,
    _row_int,
    _row_optional_int,
    _row_optional_str,
    _row_str,
)

MAX_M5_TRAINING_LABELS = MAX_M5_APPEAL_TRAINING_LABELS


def _payload_document(payload: object) -> tuple[str, str]:
    raw = canonical_json(payload)
    return raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _authority_source_projection(authority: AppealVersionAuthority) -> tuple[object, ...]:
    return (
        authority.run_id,
        authority.appeal.appeal_id,
        authority.appeal.case_id,
        authority.appeal.reason,
        authority.appeal.submitted_by,
        authority.source_case_authority,
        authority.source_case_revision,
        authority.source_case_authority_sha256,
        authority.source_verdict_id,
        authority.source_verdict_version,
        authority.source_verdict_sha256,
        authority.source_decision,
        authority.text_embedding_manifest_id,
        authority.visual_embedding_manifest_id,
        authority.manifest_id,
        authority.rule_version,
    )


class SQLiteM5AppealRepository(SQLiteM5RepositoryHost):
    """Behavior-only mixin composed over the guarded M5 foundation."""

    @contextmanager
    def _appeal_immediate(self) -> Iterator[sqlite3.Connection]:
        """Keep SQLite constraint failures inside the repository failure surface."""

        try:
            with self._immediate() as connection:
                yield connection
        except sqlite3.IntegrityError as exc:
            raise RepositoryIntegrityError(
                "M5 appeal/training persistence constraint failed"
            ) from exc

    def load_closed_case_authority(
        self,
        run_id: str,
        case_id: str,
    ) -> ClosedCaseAppealAuthority:
        require_reference_token(run_id, "appeal repository run_id")
        require_reference_token(case_id, "appeal repository case_id")
        with self._read() as connection:
            current = self._load_current_appeal_in_connection(connection, run_id, case_id)
            if current is not None:
                self._validate_durable_appeal_head(connection, current)
                return current.source_case_authority
            snapshot = self._load_case(connection, run_id, case_id)
            if snapshot.case.status != CaseStatus.CLOSED:
                raise ContractViolation("only a CLOSED Case can create appeal authority")
            return self._build_closed_case_authority(connection, snapshot)

    def load_current_appeal(
        self,
        run_id: str,
        case_id: str,
    ) -> AppealVersionAuthority | None:
        require_reference_token(run_id, "appeal repository run_id")
        require_reference_token(case_id, "appeal repository case_id")
        with self._read() as connection:
            current = self._load_current_appeal_in_connection(connection, run_id, case_id)
            if current is not None:
                self._validate_durable_appeal_head(connection, current)
            return current

    def load_appeal_by_id(
        self,
        run_id: str,
        appeal_id: str,
    ) -> AppealVersionAuthority | None:
        require_reference_token(run_id, "appeal repository run_id")
        require_reference_token(appeal_id, "appeal repository appeal_id")
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM appeals
                WHERE run_id = ? AND appeal_id = ?
                ORDER BY version
                """,
                (run_id, appeal_id),
            ).fetchall()
            current = self._appeal_head_from_rows(connection, rows)
            if current is not None:
                self._validate_durable_appeal_head(connection, current)
            return current

    def load_resolution(
        self,
        run_id: str,
        appeal_id: str,
    ) -> AppealResolutionSideEffectIntent | None:
        """Load and fully verify the durable receipt for one terminal appeal."""

        require_reference_token(run_id, "appeal resolution repository run_id")
        require_reference_token(appeal_id, "appeal resolution repository appeal_id")
        with self._read() as connection:
            intent = self._load_resolution_receipt_for_appeal(
                connection,
                run_id,
                appeal_id,
            )
            if intent is not None:
                self._validate_resolution_replay(connection, intent)
            return intent

    def load_resolution_precedent_snapshot(
        self,
        run_id: str,
        case_id: str,
    ) -> AppealResolutionPrecedentSnapshot:
        require_reference_token(run_id, "appeal repository run_id")
        require_reference_token(case_id, "appeal repository case_id")
        with self._read() as connection:
            case = self._load_case(connection, run_id, case_id)
            appeal = self._load_current_appeal_in_connection(connection, run_id, case_id)
            if (
                case.case.status != CaseStatus.APPEALED
                or appeal is None
                or appeal.version != 2
                or appeal.appeal.status != AppealStatus.UNDER_REVIEW
                or case.revision != appeal.source_case_revision + 2
            ):
                raise ConcurrentModification(
                    "resolution snapshot requires the exact UNDER_REVIEW Case revision"
                )
            return self._build_resolution_precedent_snapshot(
                connection,
                appeal.source_case_authority,
            )

    def append_appeal_version(
        self,
        authority: AppealVersionAuthority,
        expected_previous_authority_sha256: str | None,
    ) -> AppealVersionAuthority:
        validated = _validated_copy(authority, AppealVersionAuthority)
        if validated.version not in {1, 2}:
            raise ContractViolation("terminal appeal authority must use commit_resolution")
        if expected_previous_authority_sha256 != validated.previous_authority_sha256:
            raise ConcurrentModification("appeal predecessor CAS differs from authority")

        with self._appeal_immediate() as connection:
            current = self._load_current_appeal_in_connection(
                connection,
                validated.run_id,
                validated.appeal.case_id,
            )
            if current == validated:
                self._validate_committed_appeal_case(connection, validated)
                return current
            self._require_append_preconditions(
                connection,
                validated,
                current=current,
                expected_previous_authority_sha256=expected_previous_authority_sha256,
            )
            snapshot = self._load_case(
                connection,
                validated.run_id,
                validated.appeal.case_id,
            )
            self._insert_appeal_authority(connection, validated)
            self._m5_fault("appeal.append.after_authority")
            new_case = self._appeal_case_successor(snapshot.case, validated)
            head = self._validated_head(connection, validated.run_id)
            self._commit_m5_case_version(
                connection,
                previous=snapshot,
                new_case=new_case,
                expected_head=head,
                action=AuditAction.CASE_STATE_CHANGED,
                object_ref=ArtifactRef(
                    kind=ArtifactKind.APPEAL,
                    artifact_id=validated.appeal.appeal_id,
                ),
            )
            self._m5_fault("appeal.append.after_case")
            return validated

    def commit_resolution(
        self,
        intent: AppealResolutionSideEffectIntent,
    ) -> AppealResolutionSideEffectIntent:
        validated = _validated_copy(intent, AppealResolutionSideEffectIntent)
        terminal = validated.appeal_authority
        with self._appeal_immediate() as connection:
            existing = self._load_resolution_receipt_for_appeal(
                connection,
                validated.run_id,
                terminal.appeal.appeal_id,
            )
            if existing is not None:
                if existing != validated:
                    raise RepositoryIntegrityError(
                        "appeal terminal identity already binds another resolution"
                    )
                self._validate_resolution_replay(connection, validated)
                return existing

            current = self._load_current_appeal_in_connection(
                connection,
                validated.run_id,
                validated.case_id,
            )
            case = self._load_case(connection, validated.run_id, validated.case_id)
            self._require_resolution_preconditions(
                connection,
                validated,
                current=current,
                case=case,
            )
            resolution_time = self._resolution_time()

            self._insert_appeal_authority(connection, terminal)
            self._m5_fault("appeal.resolve.after_authority")
            self._insert_resolution_receipt(connection, validated)
            self._m5_fault("appeal.resolve.after_receipt")
            if validated.verdict_rescission is not None:
                self._insert_verdict_rescission(
                    connection,
                    validated,
                    validated.verdict_rescission,
                )
            self._m5_fault("appeal.resolve.after_verdict_rescission")
            for rescission in validated.alert_rescissions:
                self._insert_alert_rescission(connection, validated, rescission)
            self._m5_fault("appeal.resolve.after_alert_rescissions")

            revocation_receipts: list[M5PrecedentRevocationReceipt] = []
            for revocation in validated.precedent_revocations:
                result = self._commit_m5_appeal_revocation(
                    connection,
                    run_id=validated.run_id,
                    intent=revocation,
                    revoked_by_ref=terminal.appeal.appeal_id,
                    revoked_at=resolution_time,
                )
                self._validate_revocation_result(validated, revocation, result.receipt)
                revocation_receipts.append(result.receipt)
            self._m5_fault("appeal.resolve.after_precedent_revocations")

            if validated.appeal_precedent_authority is not None:
                inserted = self._insert_m5_precedent_authority(
                    connection,
                    validated.appeal_precedent_authority,
                    None,
                    causal_fault_scope="appeal.resolve.replacement_precedent",
                )
                if inserted != validated.appeal_precedent_authority:
                    raise RepositoryIntegrityError(
                        "replacement appeal precedent insertion returned another authority"
                    )
            self._m5_fault("appeal.resolve.after_replacement_precedent")

            new_case = self._appeal_case_successor(case.case, terminal)
            head = self._validated_head(connection, validated.run_id)
            resulting_case = self._commit_m5_case_version(
                connection,
                previous=case,
                new_case=new_case,
                expected_head=head,
                action=AuditAction.CASE_STATE_CHANGED,
                object_ref=ArtifactRef(
                    kind=ArtifactKind.APPEAL,
                    artifact_id=terminal.appeal.appeal_id,
                ),
            )
            self._m5_fault("appeal.resolve.after_case")
            commit_receipt = self._build_resolution_commit_receipt(
                connection,
                intent=validated,
                resulting_case=resulting_case,
                revocation_receipts=tuple(revocation_receipts),
            )
            provenance_receipts = build_m5_strong_training_label_provenance_receipts(
                intent=validated,
                resolution_commit_receipt=commit_receipt,
            )
            prior_label_authorities = self._list_training_label_authorities_in_connection(
                connection,
                validated.run_id,
                MAX_M5_TRAINING_LABELS,
            )
            if len(prior_label_authorities) + len(validated.training_labels) > (
                MAX_M5_TRAINING_LABELS
            ):
                raise ContractViolation("training label inventory exceeds its hard limit")
            causal_events = load_m5_training_causal_events(
                connection,
                validated.run_id,
            )
            provenance_by_label = {receipt.label_id: receipt for receipt in provenance_receipts}
            for receipt in provenance_receipts:
                self._insert_strong_training_label_provenance(connection, receipt)
            self._m5_fault("appeal.resolve.after_training_label_provenance")
            appended_authorities: list[M5TrainingLabelAuthority] = []
            previous_event_sha256 = (
                causal_events[-1].event_sha256
                if causal_events
                else M5_TRAINING_CAUSAL_GENESIS_SHA256
            )
            for label in validated.training_labels:
                provenance = provenance_by_label.get(label.label_id)
                if provenance is None:
                    raise RepositoryIntegrityError(
                        "strong appeal label lacks its generated provenance receipt"
                    )
                authority = M5TrainingLabelAuthority(
                    label=label,
                    strong_provenance=provenance,
                )
                event = build_m5_training_label_causal_event(
                    run_id=validated.run_id,
                    manifest_id=validated.manifest_id,
                    authority=authority,
                    sequence=len(causal_events) + 1,
                    previous_event_sha256=previous_event_sha256,
                )
                insert_m5_training_causal_event(connection, event)
                causal_events = (*causal_events, event)
                previous_event_sha256 = event.event_sha256
                appended_authorities.append(authority)
            self._m5_fault("appeal.resolve.after_training_label_causal_events")
            for authority in appended_authorities:
                provenance = authority.strong_provenance
                if provenance is None:
                    raise RepositoryIntegrityError(
                        "strong appeal label lost its provenance before persistence"
                    )
                self._insert_training_label(
                    connection,
                    validated,
                    authority.label,
                    provenance,
                )
            self._m5_fault("appeal.resolve.after_training_labels")
            try:
                require_m5_training_causal_chain(
                    run_id=validated.run_id,
                    manifest_id=validated.manifest_id,
                    events=causal_events,
                    label_authorities=tuple(
                        sorted(
                            (*prior_label_authorities, *appended_authorities),
                            key=lambda item: item.label.label_id,
                        )
                    ),
                )
            except M5TrainingHistoryError as exc:
                raise RepositoryIntegrityError(
                    "training label causal append closure is invalid"
                ) from exc
            self._insert_resolution_commit_receipt(connection, commit_receipt)
            self._require_resolution_training_label_provenance(
                connection,
                validated,
                commit_receipt,
            )
            self._m5_fault("appeal.resolve.after_commit_marker")
            return validated

    def register_dataset_artifact(
        self,
        report: DatasetExportReport,
        content: bytes,
    ) -> DatasetArtifact:
        if not isinstance(content, bytes):
            raise TypeError("dataset registration content must be bytes")
        validated = _validated_copy(report, DatasetExportReport)
        dataset = validated.dataset
        with self._appeal_immediate() as connection:
            manifest = self._load_run_manifest(connection, validated.run_id)
            if (
                validated.manifest_id != manifest.manifest_id
                or validated.detector_manifest_id != manifest.models["detector"].model_manifest_id
                or validated.rule_version != manifest.rule_version
            ):
                raise ManifestMismatch("dataset report conflicts with the run manifest")
            existing_rows = connection.execute(
                """
                SELECT * FROM dataset_artifacts
                WHERE run_id = ? AND (
                    dataset_id = ? OR report_id = ? OR command_id = ? OR relative_path = ?
                )
                """,
                (
                    validated.run_id,
                    dataset.dataset_id,
                    validated.report_id,
                    validated.command_id,
                    dataset.relative_path,
                ),
            ).fetchall()
            if existing_rows:
                if len(existing_rows) != 1:
                    raise RepositoryIntegrityError(
                        "dataset identities select multiple immutable artifacts"
                    )
                existing_row = existing_rows[0]
                existing = self._dataset_report_from_row(existing_row)
                if existing != validated:
                    raise RepositoryIntegrityError(
                        "dataset identity or path already binds different content"
                    )
                replay = True
            else:
                existing_row = None
                existing = None
                replay = False

            if self._training_crop_verifier is None:
                raise ContractViolation(
                    "dataset registration requires a trusted current-Crop verifier"
                )
            dataset_verifier = self._dataset_artifact_verifier
            if dataset_verifier is None:
                raise ContractViolation(
                    "dataset registration requires a trusted published-dataset verifier"
                )
            verified_dataset = dataset_verifier.verify_published_dataset(
                validated,
                content,
            )
            if verified_dataset != dataset:
                raise ContractViolation(
                    "published-dataset verifier returned another dataset authority"
                )
            label_authorities = self._list_training_label_authorities_in_connection(
                connection,
                validated.run_id,
                MAX_M5_TRAINING_LABELS,
            )
            causal_events = load_m5_training_causal_events(
                connection,
                validated.run_id,
            )
            try:
                if existing_row is None:
                    causal_cut = build_m5_training_causal_watermark(
                        run_id=validated.run_id,
                        manifest_id=validated.manifest_id,
                        events=causal_events,
                    )
                    label_receipts = build_m5_dataset_label_snapshot_receipts(
                        report=validated,
                        causal_cut=causal_cut,
                        events=causal_events,
                        label_authorities=label_authorities,
                    )
                    crop_snapshots = self._current_training_crop_snapshots(
                        connection,
                        validated,
                        tuple(item.label for item in label_authorities),
                    )
                    registration_snapshot = build_m5_dataset_registration_snapshot(
                        report=validated,
                        causal_cut=causal_cut,
                        label_receipts=label_receipts,
                        crop_snapshots=crop_snapshots,
                    )
                    registration_marker = build_m5_dataset_registration_commit_event(
                        registration_snapshot
                    )
                    replay_events = (*causal_events, registration_marker)
                else:
                    snapshot_authority_id = _row_str(
                        existing_row,
                        "registration_snapshot_authority_id",
                    )
                    registration_snapshot = load_m5_dataset_registration_snapshot(
                        connection,
                        validated.run_id,
                        snapshot_authority_id,
                    )
                    crop_snapshots = list_m5_dataset_crop_snapshots(
                        connection,
                        validated.run_id,
                        registration_snapshot.authority_id,
                    )
                    registration_marker = require_m5_dataset_registration_marker(
                        connection,
                        registration_snapshot,
                    )
                    label_receipts = build_m5_dataset_label_snapshot_receipts(
                        report=validated,
                        causal_cut=registration_snapshot.causal_cut,
                        events=causal_events,
                        label_authorities=label_authorities,
                    )
                    replay_events = causal_events

                historical_labels, crop_authorities = resolve_m5_dataset_historical_replay(
                    report=validated,
                    snapshot=registration_snapshot,
                    registration_marker=registration_marker,
                    events=replay_events,
                    label_authorities=label_authorities,
                    label_receipts=label_receipts,
                    crop_snapshots=crop_snapshots,
                )
                self._require_historical_training_crop_snapshots(
                    connection,
                    validated,
                    crop_snapshots,
                )
                rebuild_and_verify_m5_dataset(
                    report=validated,
                    content=content,
                    labels=historical_labels,
                    crop_authorities=crop_authorities,
                )
            except RepositoryIntegrityError:
                raise
            except (
                ContractViolation,
                DatasetExportError,
                M5DatasetIntegrityError,
                M5TrainingHistoryError,
                TypeError,
                ValueError,
            ) as exc:
                if replay:
                    raise RepositoryIntegrityError(
                        "registered dataset no longer rebuilds from its historical authority"
                    ) from exc
                raise ContractViolation(
                    "dataset report and content do not rebuild from durable authority"
                ) from exc
            expected_holds = m5_dataset_retention_holds(validated)
            head = self._validated_head(connection, validated.run_id)
            if existing is not None:
                self._validate_dataset_retention_replay(
                    connection,
                    validated,
                    expected_holds,
                )
                return existing.dataset

            insert_m5_dataset_registration_snapshot(
                connection,
                registration_snapshot,
            )
            self._m5_fault("dataset.register.after_snapshot")
            for crop_snapshot in crop_snapshots:
                insert_m5_dataset_crop_snapshot(
                    connection,
                    registration_snapshot.authority_id,
                    crop_snapshot,
                )
            self._m5_fault("dataset.register.after_snapshot_crops")
            insert_m5_training_causal_event(connection, registration_marker)
            self._m5_fault("dataset.register.after_registration_marker")
            artifact_json, _ = _document(dataset)
            report_json, report_sha256 = _document(validated)
            connection.execute(
                """
                INSERT INTO dataset_artifacts(
                    run_id, dataset_id, report_id, command_id, format,
                    relative_path, content_sha256, content_size_bytes,
                    label_count, minimum_quality, rule_version,
                    detector_manifest_id, manifest_id,
                    registration_snapshot_authority_id,
                    artifact_json, report_json, document_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    validated.run_id,
                    dataset.dataset_id,
                    validated.report_id,
                    validated.command_id,
                    dataset.format.value,
                    dataset.relative_path,
                    dataset.content_sha256,
                    validated.content_size_bytes,
                    dataset.label_count,
                    dataset.minimum_quality.value,
                    dataset.rule_version,
                    validated.detector_manifest_id,
                    validated.manifest_id,
                    registration_snapshot.authority_id,
                    artifact_json,
                    report_json,
                    report_sha256,
                ),
            )
            self._m5_fault("dataset.register.after_artifact")
            current_crop_ids = frozenset(authority.crop.crop_id for authority in crop_authorities)
            for hold in expected_holds:
                head = self._insert_dataset_retention_hold(
                    connection,
                    report=validated,
                    hold=hold,
                    current_crop_ids=current_crop_ids,
                    head=head,
                )
            self._m5_fault("dataset.register.after_holds")
            self._validate_dataset_retention_replay(
                connection,
                validated,
                expected_holds,
            )
            self._m5_fault("dataset.register.before_commit")
            return dataset

    def load_registered_dataset_report(
        self,
        run_id: str,
        command_id: str,
    ) -> DatasetExportReport | None:
        """Discover an immutable report; registration replay performs full verification."""

        require_reference_token(run_id, "registered dataset run_id")
        require_reference_token(command_id, "registered dataset command_id")
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM dataset_artifacts
                WHERE run_id = ? AND command_id = ?
                """,
                (run_id, command_id),
            ).fetchall()
            if not rows:
                return None
            if len(rows) != 1:
                raise RepositoryIntegrityError("dataset command selects multiple immutable reports")
            report = self._dataset_report_from_row(rows[0])
            if report.run_id != run_id or report.command_id != command_id:
                raise RepositoryIntegrityError(
                    "dataset command index differs from its canonical report"
                )
            return report

    def list_training_labels(
        self,
        run_id: str,
        limit: int,
    ) -> tuple[TrainingLabel, ...]:
        return tuple(
            authority.label for authority in self.list_training_label_authorities(run_id, limit)
        )

    def list_training_label_authorities(
        self,
        run_id: str,
        limit: int,
    ) -> tuple[M5TrainingLabelAuthority, ...]:
        require_reference_token(run_id, "training label repository run_id")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_M5_TRAINING_LABELS
        ):
            raise ContractViolation(
                f"training label complete-scan limit must be 1..{MAX_M5_TRAINING_LABELS}"
            )
        with self._read() as connection:
            return self._list_training_label_authorities_in_connection(
                connection,
                run_id,
                limit,
            )

    def _list_training_labels_in_connection(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        limit: int,
    ) -> tuple[TrainingLabel, ...]:
        return tuple(
            authority.label
            for authority in self._list_training_label_authorities_in_connection(
                connection,
                run_id,
                limit,
            )
        )

    def _list_training_label_authorities_in_connection(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        limit: int,
    ) -> tuple[M5TrainingLabelAuthority, ...]:
        manifest = self._load_run_manifest(connection, run_id)
        rows = connection.execute(
            """
            SELECT * FROM training_labels
            WHERE run_id = ? ORDER BY label_id LIMIT ?
            """,
            (run_id, limit + 1),
        ).fetchall()
        if len(rows) > limit:
            raise ContractViolation(
                "training label inventory exceeds the requested complete-scan limit"
            )
        label_rows: dict[str, sqlite3.Row] = {}
        labels: dict[str, TrainingLabel] = {}
        for row in rows:
            label = self._training_label_from_row(row)
            if (
                _row_str(row, "run_id") != run_id
                or _row_str(row, "manifest_id") != manifest.manifest_id
                or label.rule_version != manifest.rule_version
                or label.detector_manifest_id != manifest.models["detector"].model_manifest_id
            ):
                raise RepositoryIntegrityError(
                    "training label differs from its immutable run authority"
                )
            label_rows[label.label_id] = row
            labels[label.label_id] = label
        label_ids = tuple(labels)
        if label_ids != tuple(sorted(set(label_ids))):
            raise RepositoryIntegrityError(
                "training label inventory is not unique and stably ordered"
            )
        provenance_rows = connection.execute(
            """
            SELECT * FROM strong_training_label_provenance_receipts
            WHERE run_id = ? ORDER BY label_id
            """,
            (run_id,),
        ).fetchall()
        provenance_by_label: dict[str, M5StrongTrainingLabelProvenanceReceipt] = {}
        for row in provenance_rows:
            provenance = self._strong_training_label_provenance_from_row(row)
            if provenance.label_id in provenance_by_label:
                raise RepositoryIntegrityError(
                    "strong training label selects multiple provenance receipts"
                )
            provenance_by_label[provenance.label_id] = provenance
        if set(provenance_by_label) - set(labels):
            raise RepositoryIntegrityError("strong training label provenance is orphaned")

        authority_by_label: dict[str, M5TrainingLabelAuthority] = {}
        appeal_ids: set[str] = set()
        for label_id, label in labels.items():
            indexed_provenance_id = _row_optional_str(
                label_rows[label_id],
                "strong_provenance_id",
            )
            stored_provenance = provenance_by_label.get(label_id)
            if label.quality in STRONG_TRAINING_LABEL_QUALITIES:
                if (
                    stored_provenance is None
                    or indexed_provenance_id != stored_provenance.provenance_id
                ):
                    raise RepositoryIntegrityError("strong training label lacks exact provenance")
                appeal_ids.add(stored_provenance.appeal_id)
            elif stored_provenance is not None or indexed_provenance_id is not None:
                raise RepositoryIntegrityError(
                    "weak training label carries forbidden strong provenance"
                )
            else:
                authority_by_label[label_id] = M5TrainingLabelAuthority(label=label)

        for appeal_id in sorted(appeal_ids):
            intent = self._load_resolution_receipt_for_appeal(
                connection,
                run_id,
                appeal_id,
            )
            if intent is None:
                raise RepositoryIntegrityError(
                    "strong training label lacks its terminal resolution roots"
                )
            for authority in self._validate_resolution_replay(connection, intent):
                authority_by_label[authority.label.label_id] = authority
        if set(authority_by_label) != set(labels):
            raise RepositoryIntegrityError("training label authority inventory is incomplete")
        authorities = tuple(authority_by_label[label_id] for label_id in label_ids)
        events = load_m5_training_causal_events(connection, run_id)
        try:
            require_m5_training_causal_chain(
                run_id=run_id,
                manifest_id=manifest.manifest_id,
                events=events,
                label_authorities=authorities,
            )
        except M5TrainingHistoryError as exc:
            raise RepositoryIntegrityError(
                "training label causal ledger differs from durable authority"
            ) from exc
        return authorities

    def _require_resolution_training_label_provenance(
        self,
        connection: sqlite3.Connection,
        intent: AppealResolutionSideEffectIntent,
        commit_receipt: M5AppealResolutionCommitReceipt,
    ) -> tuple[M5TrainingLabelAuthority, ...]:
        terminal = intent.appeal_authority
        appeal_id = terminal.appeal.appeal_id
        provenance_rows = connection.execute(
            """
            SELECT * FROM strong_training_label_provenance_receipts
            WHERE run_id = ? AND resolution_intent_id = ?
            ORDER BY label_id
            """,
            (intent.run_id, intent.intent_id),
        ).fetchall()
        provenances = tuple(
            self._strong_training_label_provenance_from_row(row) for row in provenance_rows
        )
        expected_label_ids = tuple(label.label_id for label in intent.training_labels)
        if tuple(item.label_id for item in provenances) != expected_label_ids:
            raise RepositoryIntegrityError(
                "appeal resolution provenance inventory differs from its labels"
            )

        appeal_rows = connection.execute(
            """
            SELECT * FROM appeals
            WHERE run_id = ? AND appeal_id = ? ORDER BY version
            """,
            (intent.run_id, appeal_id),
        ).fetchall()
        if tuple(_row_int(row, "version") for row in appeal_rows) != (1, 2, 3):
            raise RepositoryIntegrityError(
                "strong training label appeal authority chain is incomplete"
            )
        appeal_authorities = tuple(self._appeal_authority_from_row(row) for row in appeal_rows)
        self._validate_appeal_chain(appeal_authorities)
        review_authority = appeal_authorities[1]
        terminal_authority = appeal_authorities[2]
        if terminal_authority != terminal:
            raise RepositoryIntegrityError(
                "strong training label terminal authority differs from its intent"
            )

        _commit_raw, commit_document_sha256 = _document(commit_receipt)
        commit_event = require_m5_precedent_causal_event(
            connection,
            source=m5_appeal_resolution_commit_causal_source(
                commit_receipt,
                source_document_sha256=commit_document_sha256,
            ),
        )
        labels_by_id = {label.label_id: label for label in intent.training_labels}
        authorities: list[M5TrainingLabelAuthority] = []
        for provenance in provenances:
            label_row = connection.execute(
                """
                SELECT * FROM training_labels
                WHERE run_id = ? AND label_id = ?
                """,
                (intent.run_id, provenance.label_id),
            ).fetchone()
            expected_label = labels_by_id.get(provenance.label_id)
            if (
                label_row is None
                or expected_label is None
                or self._training_label_from_row(label_row) != expected_label
                or _row_optional_str(label_row, "strong_provenance_id") != provenance.provenance_id
            ):
                raise RepositoryIntegrityError(
                    "strong provenance does not resolve to its exact training label"
                )
            try:
                authority = M5TrainingLabelAuthority(
                    label=expected_label,
                    strong_provenance=provenance,
                )
                require_m5_strong_training_label_provenance(
                    authority=authority,
                    review_authority=review_authority,
                    terminal_authority=terminal_authority,
                    resolution_intent=intent,
                    resolution_commit_receipt=commit_receipt,
                    resolution_commit_event=commit_event,
                )
            except (M5TrainingLabelProvenanceError, TypeError, ValueError) as exc:
                raise RepositoryIntegrityError(
                    "strong training label provenance chain is invalid"
                ) from exc
            authorities.append(authority)

        try:
            rebuilt_labels = build_m5_appeal_training_labels(
                appeal_authority=review_authority,
                terminal_status=terminal_authority.appeal.status,
                authored_inputs=tuple(provenance.authored_input for provenance in provenances),
            )
        except (ContractViolation, TypeError, ValueError) as exc:
            raise RepositoryIntegrityError(
                "strong training label human inputs cannot be rebuilt"
            ) from exc
        if rebuilt_labels != intent.training_labels:
            raise RepositoryIntegrityError(
                "strong training label inventory differs from the human review rebuild"
            )
        return tuple(authorities)

    def _current_training_crop_snapshots(
        self,
        connection: sqlite3.Connection,
        report: DatasetExportReport,
        labels: tuple[TrainingLabel, ...],
    ) -> tuple[M5DatasetCropSnapshotAuthority, ...]:
        verifier = self._training_crop_verifier
        if verifier is None:
            raise ContractViolation("dataset registration requires a trusted current-Crop verifier")
        labels_by_case: dict[str, list[TrainingLabel]] = {}
        for label in labels:
            if training_label_is_exportable(
                quality=label.quality,
                excluded_reason=label.excluded_reason,
            ):
                labels_by_case.setdefault(label.case_id, []).append(label)

        authorities: dict[str, M5DatasetCropSnapshotAuthority] = {}
        for case_id in sorted(labels_by_case):
            snapshot = self._load_case(connection, report.run_id, case_id)
            case = snapshot.case
            if (
                case.run_id != report.run_id
                or case.case_id != case_id
                or case.manifest_id != report.manifest_id
            ):
                raise ContractViolation("training label Case differs from dataset report authority")
            if not case.evidence_packs:
                raise ContractViolation("training label Case has no evidence pack")
            latest_pack = case.evidence_packs[-1]
            if not latest_pack.complete:
                raise ContractViolation("training label Case latest pack is incomplete")
            case_row = connection.execute(
                """
                SELECT * FROM case_versions
                WHERE run_id = ? AND case_id = ? AND revision = ?
                """,
                (report.run_id, case_id, snapshot.revision),
            ).fetchone()
            if case_row is None:
                raise RepositoryIntegrityError(
                    "current training Case lacks its immutable version document"
                )
            stored_case = _load_document(
                case_row,
                json_key="case_json",
                sha256_key="document_sha256",
                model_type=Case,
            )
            if stored_case != case:
                raise RepositoryIntegrityError(
                    "current training Case differs from its immutable version document"
                )
            pack_row = connection.execute(
                """
                SELECT * FROM evidence_packs
                WHERE run_id = ? AND case_id = ? AND pack_id = ? AND version = ?
                """,
                (
                    report.run_id,
                    case_id,
                    latest_pack.pack_id,
                    latest_pack.version,
                ),
            ).fetchone()
            if pack_row is None:
                raise RepositoryIntegrityError(
                    "current training EvidencePack lacks its immutable document"
                )
            stored_pack = _load_document(
                pack_row,
                json_key="pack_json",
                sha256_key="document_sha256",
                model_type=EvidencePack,
            )
            if stored_pack != latest_pack:
                raise RepositoryIntegrityError(
                    "current training EvidencePack differs from its immutable document"
                )
            crops = {crop.crop_id: crop for crop in latest_pack.crops}
            crop_ids = tuple(sorted({label.crop_id for label in labels_by_case[case_id]}))
            for crop_id in crop_ids:
                crop = crops.get(crop_id)
                if crop is None:
                    raise ContractViolation(
                        "training label Crop is not in the current evidence pack"
                    )
                crop_ref = ArtifactRef(
                    kind=ArtifactKind.CROP,
                    artifact_id=crop.crop_id,
                )
                verification = verifier.verify_crop(crop)
                if (
                    not isinstance(verification, ArtifactVerification)
                    or verification.artifact_ref != crop_ref
                    or verification.status != VerificationStatus.CURRENT_MEDIA_VERIFIED
                ):
                    raise ContractViolation(
                        "training Crop current bytes failed trusted verification"
                    )
                crop_authority = TrainingCropAuthority(
                    run_id=report.run_id,
                    case_id=case_id,
                    crop=crop,
                    verification=verification,
                    detector_manifest_id=report.detector_manifest_id,
                    manifest_id=report.manifest_id,
                    rule_version=report.rule_version,
                )
                authority = M5DatasetCropSnapshotAuthority(
                    run_id=report.run_id,
                    dataset_id=report.dataset.dataset_id,
                    report_id=report.report_id,
                    crop_authority=crop_authority,
                    case_revision=snapshot.revision,
                    case_document_sha256=_row_str(case_row, "document_sha256"),
                    evidence_pack_id=latest_pack.pack_id,
                    evidence_pack_version=latest_pack.version,
                    evidence_pack_document_sha256=_row_str(
                        pack_row,
                        "document_sha256",
                    ),
                )
                prior = authorities.get(crop_id)
                if prior is not None and prior != authority:
                    raise ContractViolation(
                        "training Crop is bound to conflicting current Case authorities"
                    )
                authorities[crop_id] = authority
        return tuple(authorities[crop_id] for crop_id in sorted(authorities))

    def _require_historical_training_crop_snapshots(
        self,
        connection: sqlite3.Connection,
        report: DatasetExportReport,
        snapshots: tuple[M5DatasetCropSnapshotAuthority, ...],
    ) -> tuple[TrainingCropAuthority, ...]:
        verifier = self._training_crop_verifier
        if verifier is None:
            raise ContractViolation("dataset registration requires a trusted current-Crop verifier")
        authorities: list[TrainingCropAuthority] = []
        for snapshot in snapshots:
            authority = snapshot.crop_authority
            if (
                snapshot.run_id != report.run_id
                or snapshot.dataset_id != report.dataset.dataset_id
                or snapshot.report_id != report.report_id
                or authority.run_id != report.run_id
                or authority.manifest_id != report.manifest_id
                or authority.rule_version != report.rule_version
                or authority.detector_manifest_id != report.detector_manifest_id
            ):
                raise RepositoryIntegrityError(
                    "historical training Crop snapshot crosses dataset authority"
                )
            case_row = connection.execute(
                """
                SELECT * FROM case_versions
                WHERE run_id = ? AND case_id = ? AND revision = ?
                """,
                (report.run_id, authority.case_id, snapshot.case_revision),
            ).fetchone()
            if (
                case_row is None
                or _row_str(case_row, "document_sha256") != snapshot.case_document_sha256
            ):
                raise RepositoryIntegrityError(
                    "historical dataset Case version is missing or changed"
                )
            historical_case = _load_document(
                case_row,
                json_key="case_json",
                sha256_key="document_sha256",
                model_type=Case,
            )
            if (
                historical_case.run_id != report.run_id
                or historical_case.case_id != authority.case_id
                or historical_case.status.value != _row_str(case_row, "status")
                or _row_int(case_row, "revision") != snapshot.case_revision
            ):
                raise RepositoryIntegrityError(
                    "historical dataset Case indexes differ from its document"
                )
            pack_row = connection.execute(
                """
                SELECT * FROM evidence_packs
                WHERE run_id = ? AND case_id = ? AND pack_id = ? AND version = ?
                """,
                (
                    report.run_id,
                    authority.case_id,
                    snapshot.evidence_pack_id,
                    snapshot.evidence_pack_version,
                ),
            ).fetchone()
            if (
                pack_row is None
                or _row_str(pack_row, "document_sha256") != snapshot.evidence_pack_document_sha256
            ):
                raise RepositoryIntegrityError(
                    "historical dataset EvidencePack is missing or changed"
                )
            historical_pack = _load_document(
                pack_row,
                json_key="pack_json",
                sha256_key="document_sha256",
                model_type=EvidencePack,
            )
            case_pack = next(
                (
                    item
                    for item in historical_case.evidence_packs
                    if item.pack_id == snapshot.evidence_pack_id
                    and item.version == snapshot.evidence_pack_version
                ),
                None,
            )
            if (
                case_pack != historical_pack
                or historical_pack.run_id != report.run_id
                or historical_pack.case_id != authority.case_id
                or historical_pack.manifest_id != report.manifest_id
                or not historical_pack.complete
                or historical_pack.pack_id != _row_str(pack_row, "pack_id")
                or historical_pack.version != _row_int(pack_row, "version")
                or int(historical_pack.complete) != _row_int(pack_row, "complete")
                or historical_pack.pack_input_sha256 != _row_str(pack_row, "pack_input_sha256")
                or historical_pack.closure_input_sha256
                != _row_str(pack_row, "closure_input_sha256")
            ):
                raise RepositoryIntegrityError("historical dataset EvidencePack closure is invalid")
            historical_crop = next(
                (item for item in historical_pack.crops if item.crop_id == authority.crop.crop_id),
                None,
            )
            if historical_crop != authority.crop:
                raise RepositoryIntegrityError(
                    "historical dataset Crop differs from its EvidencePack"
                )
            crop_ref = ArtifactRef(
                kind=ArtifactKind.CROP,
                artifact_id=authority.crop.crop_id,
            )
            verification = verifier.verify_crop(authority.crop)
            if (
                not isinstance(verification, ArtifactVerification)
                or verification.artifact_ref != crop_ref
                or verification.status != VerificationStatus.CURRENT_MEDIA_VERIFIED
                or verification != authority.verification
            ):
                raise ContractViolation(
                    "historical training Crop current bytes failed trusted verification"
                )
            authorities.append(authority)
        return tuple(authorities)

    def _insert_dataset_retention_hold(
        self,
        connection: sqlite3.Connection,
        *,
        report: DatasetExportReport,
        hold: RetentionHold,
        current_crop_ids: frozenset[str],
        head: AuditHead,
    ) -> AuditHead:
        if (
            hold.run_id != report.run_id
            or hold.manifest_id != report.manifest_id
            or hold.owner_ref.ref.kind != ArtifactKind.DATASET
            or hold.owner_ref.ref.artifact_id != report.dataset.dataset_id
            or hold.target_ref.ref.kind != ArtifactKind.CROP
            or hold.target_ref.ref.artifact_id not in current_crop_ids
        ):
            raise RepositoryIntegrityError(
                "derived dataset retention hold differs from current authority"
            )
        owner_row = connection.execute(
            """
            SELECT * FROM dataset_artifacts
            WHERE run_id = ? AND dataset_id = ?
            """,
            (report.run_id, report.dataset.dataset_id),
        ).fetchone()
        if owner_row is None or self._dataset_report_from_row(owner_row) != report:
            raise RepositoryIntegrityError(
                "dataset retention hold owner is not the exact registered report"
            )
        existing = connection.execute(
            "SELECT 1 FROM retention_holds WHERE run_id = ? AND hold_id = ?",
            (hold.run_id, hold.hold_id),
        ).fetchone()
        if existing is not None:
            raise RepositoryIntegrityError(
                "dataset retention hold identity already exists before registration"
            )

        hold_json, hold_sha256 = _document(hold)
        audit, new_head = self._append_dataset_retention_audit(
            connection,
            head,
            hold=hold,
            hold_sha256=hold_sha256,
        )
        self._m5_fault("dataset.register.after_hold_audit")
        connection.execute(
            """
            INSERT INTO retention_holds(
                run_id, hold_id, target_kind, target_id,
                hold_kind, owner_kind, owner_id, active,
                manifest_id, policy_version, reason_code,
                hold_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
            """,
            (
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
                hold_json,
                hold_sha256,
            ),
        )
        self._m5_fault("dataset.register.after_hold")
        connection.execute(
            """
            INSERT INTO retention_hold_audit_links(
                run_id, hold_id, created_audit_sequence, released_audit_sequence
            ) VALUES (?, ?, ?, NULL)
            """,
            (hold.run_id, hold.hold_id, audit.sequence),
        )
        self._m5_fault("dataset.register.after_hold_link")
        return new_head

    def _append_dataset_retention_audit(
        self,
        connection: sqlite3.Connection,
        head: AuditHead,
        *,
        hold: RetentionHold,
        hold_sha256: str,
    ) -> tuple[AuditEntry, AuditHead]:
        entry = AuditEntryDraft(
            run_id=head.run_id,
            sequence=head.sequence + 1,
            actor=AuditActorRole.RETENTION.value,
            action=AuditAction.RETENTION_HOLD_CREATED,
            object_ref=hold.target_ref.ref,
            before_sha256=None,
            after_sha256=hold_sha256,
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
            raise ConcurrentModification(
                "run audit head changed during dataset retention registration"
            )
        return entry, AuditHead(
            run_id=head.run_id,
            manifest_id=head.manifest_id,
            run_revision=head.run_revision + 1,
            sequence=entry.sequence,
            entry_hash=entry.entry_hash,
        )

    def _validate_dataset_retention_replay(
        self,
        connection: sqlite3.Connection,
        report: DatasetExportReport,
        expected_holds: tuple[RetentionHold, ...],
    ) -> None:
        rows = connection.execute(
            """
            SELECT hold_id FROM retention_holds
            WHERE run_id = ? AND owner_kind = ? AND owner_id = ?
            ORDER BY hold_id
            """,
            (
                report.run_id,
                ArtifactKind.DATASET.value,
                report.dataset.dataset_id,
            ),
        ).fetchall()
        durable_ids = tuple(_row_str(row, "hold_id") for row in rows)
        expected_ids = tuple(sorted(hold.hold_id for hold in expected_holds))
        if durable_ids != expected_ids:
            raise RepositoryIntegrityError(
                "dataset retention hold inventory is missing or contains extras"
            )
        for expected in expected_holds:
            row = connection.execute(
                """
                SELECT rh.*, links.created_audit_sequence,
                       links.released_audit_sequence
                FROM retention_holds AS rh
                LEFT JOIN retention_hold_audit_links AS links
                  ON links.run_id = rh.run_id AND links.hold_id = rh.hold_id
                WHERE rh.run_id = ? AND rh.hold_id = ?
                """,
                (expected.run_id, expected.hold_id),
            ).fetchone()
            if row is None:
                raise RepositoryIntegrityError("dataset retention hold is missing")
            durable = _load_document(
                row,
                json_key="hold_json",
                sha256_key="document_sha256",
                model_type=RetentionHold,
            )
            indexed = (
                _row_str(row, "run_id"),
                _row_str(row, "hold_id"),
                _row_str(row, "target_kind"),
                _row_str(row, "target_id"),
                _row_str(row, "hold_kind"),
                _row_str(row, "owner_kind"),
                _row_str(row, "owner_id"),
                _row_str(row, "manifest_id"),
                _row_str(row, "policy_version"),
                _row_optional_str(row, "reason_code"),
            )
            expected_index = (
                expected.run_id,
                expected.hold_id,
                expected.target_ref.ref.kind.value,
                expected.target_ref.ref.artifact_id,
                expected.kind.value,
                expected.owner_ref.ref.kind.value,
                expected.owner_ref.ref.artifact_id,
                expected.manifest_id,
                expected.policy_version,
                expected.reason_code,
            )
            if durable != expected or indexed != expected_index:
                raise RepositoryIntegrityError(
                    "dataset retention hold differs from its canonical authority"
                )
            if _row_int(row, "active") != 1:
                raise RepositoryIntegrityError("dataset retention hold was released")
            created_sequence = _row_optional_int(row, "created_audit_sequence")
            released_sequence = _row_optional_int(row, "released_audit_sequence")
            if created_sequence is None or released_sequence is not None:
                raise RepositoryIntegrityError(
                    "dataset retention hold audit link is incomplete or released"
                )
            audit_row = connection.execute(
                "SELECT * FROM audit_entries WHERE run_id = ? AND sequence = ?",
                (report.run_id, created_sequence),
            ).fetchone()
            if audit_row is None:
                raise RepositoryIntegrityError("dataset retention hold creation audit is missing")
            audit = _audit_entry_from_row(audit_row)
            _, hold_sha256 = _document(expected)
            if (
                audit.actor != AuditActorRole.RETENTION.value
                or audit.action != AuditAction.RETENTION_HOLD_CREATED
                or audit.object_ref != expected.target_ref.ref
                or audit.before_sha256 is not None
                or audit.after_sha256 != hold_sha256
                or audit.manifest_id != expected.manifest_id
            ):
                raise RepositoryIntegrityError(
                    "dataset retention hold is not bound to its creation audit"
                )

    def _require_append_preconditions(
        self,
        connection: sqlite3.Connection,
        authority: AppealVersionAuthority,
        *,
        current: AppealVersionAuthority | None,
        expected_previous_authority_sha256: str | None,
    ) -> None:
        source = authority.source_case_authority
        if authority.version == 1:
            if current is not None or expected_previous_authority_sha256 is not None:
                raise ConcurrentModification("Case already has an effective appeal")
            case = self._load_case(connection, authority.run_id, authority.appeal.case_id)
            if case.revision != authority.source_case_revision:
                raise ConcurrentModification("appeal submission Case revision changed")
            current_source = self._build_closed_case_authority(connection, case)
            if current_source != source:
                raise ConcurrentModification("closed Case appeal authority changed")
            expected = submit_appeal(
                source,
                AppealSubmissionCommand(
                    run_id=authority.run_id,
                    case_id=authority.appeal.case_id,
                    appeal_id=authority.appeal.appeal_id,
                    expected_case_revision=authority.source_case_revision,
                    expected_case_authority_sha256=authority.source_case_authority_sha256,
                    reason=authority.appeal.reason,
                    submitted_by=authority.appeal.submitted_by,
                ),
                None,
            )
        else:
            if (
                current is None
                or current.version != 1
                or expected_previous_authority_sha256 != current.authority_sha256
                or authority.previous_authority_sha256 != current.authority_sha256
            ):
                raise ConcurrentModification("appeal review predecessor changed")
            case = self._load_case(connection, authority.run_id, authority.appeal.case_id)
            if case.revision != authority.source_case_revision + 1:
                raise ConcurrentModification("appeal review Case revision changed")
            if _authority_source_projection(authority) != _authority_source_projection(current):
                raise ContractViolation("appeal review rewrote submit-time authority")
            if authority.assigned_reviewer_id is None:
                raise ContractViolation("appeal review requires an assigned reviewer")
            expected = begin_appeal_review(
                current,
                AppealReviewCommand(
                    run_id=authority.run_id,
                    case_id=authority.appeal.case_id,
                    appeal_id=authority.appeal.appeal_id,
                    expected_appeal_authority_sha256=current.authority_sha256,
                    reviewer_id=authority.assigned_reviewer_id,
                ),
            )
        if expected != authority:
            raise ContractViolation("appeal authority is not the exact next state")

    def _require_resolution_preconditions(
        self,
        connection: sqlite3.Connection,
        intent: AppealResolutionSideEffectIntent,
        *,
        current: AppealVersionAuthority | None,
        case: CaseSnapshot,
    ) -> None:
        terminal = intent.appeal_authority
        if (
            current is None
            or current.version != 2
            or current.appeal.status != AppealStatus.UNDER_REVIEW
            or terminal.previous_authority_sha256 != current.authority_sha256
            or terminal.assigned_reviewer_id != current.assigned_reviewer_id
            or terminal.appeal.reviewer_id != current.assigned_reviewer_id
        ):
            raise ConcurrentModification("appeal is not the exact review authority")
        if _authority_source_projection(terminal) != _authority_source_projection(current):
            raise ContractViolation("terminal appeal rewrote submit-time authority")
        if (
            case.revision != terminal.source_case_revision + 2
            or case.case.status != CaseStatus.APPEALED
            or not case.case.appeals
            or case.case.appeals[-1] != current.appeal
        ):
            raise ConcurrentModification("terminal appeal Case revision changed")
        self._validate_embedded_closed_case_authority(connection, terminal)
        fresh_snapshot = self._build_resolution_precedent_snapshot(
            connection,
            terminal.source_case_authority,
        )
        if fresh_snapshot != intent.precedent_snapshot:
            raise ConcurrentModification(
                "automatic precedent or citation snapshot changed before resolution"
            )
        self._require_trusted_resolution_intent(
            connection,
            current=current,
            fresh_snapshot=fresh_snapshot,
            proposed=intent,
        )
        self._validate_resolution_effect_scope(connection, case.case, intent)

    def _require_trusted_resolution_intent(
        self,
        connection: sqlite3.Connection,
        *,
        current: AppealVersionAuthority,
        fresh_snapshot: AppealResolutionPrecedentSnapshot,
        proposed: AppealResolutionSideEffectIntent,
    ) -> None:
        terminal = proposed.appeal_authority
        status = terminal.appeal.status
        reviewer_id = terminal.appeal.reviewer_id
        summary = terminal.appeal.resolution_summary
        decision = terminal.appeal.resolved_decision
        if (
            status not in {AppealStatus.UPHELD, AppealStatus.OVERTURNED}
            or reviewer_id is None
            or summary is None
            or decision is None
        ):
            raise ContractViolation("terminal appeal lacks trusted human resolution fields")
        command = AppealResolutionCommand(
            run_id=current.run_id,
            case_id=current.appeal.case_id,
            appeal_id=current.appeal.appeal_id,
            expected_appeal_authority_sha256=current.authority_sha256,
            status=status,
            reviewer_id=reviewer_id,
            resolution_summary=summary,
            resolved_decision=decision,
            appeal_precedent_authority=proposed.appeal_precedent_authority,
            training_labels=proposed.training_labels,
        )
        try:
            rebuilt = build_appeal_resolution_intent(
                case_authority=current.source_case_authority,
                appeal_authority=current,
                precedent_snapshot=fresh_snapshot,
                command=command,
            )
        except (AppealResolutionError, AppealTransitionError, TypeError, ValueError) as exc:
            raise ContractViolation("trusted appeal resolution reconstruction failed") from exc
        if rebuilt != proposed:
            raise ContractViolation(
                "proposed appeal side effects differ from trusted reconstruction"
            )
        replacement = proposed.appeal_precedent_authority
        if replacement is not None:
            self._require_trusted_replacement_embedding(connection, replacement)

    def _require_trusted_replacement_embedding(
        self,
        connection: sqlite3.Connection,
        authority: M5PrecedentAuthority,
    ) -> None:
        manifest = self._load_run_manifest(connection, authority.run_id)
        embedding = authority.text_embedding
        if (
            not is_m5_controlled_fake_model_manifest(manifest.models["text_embedding"])
            or embedding is None
            or authority.visual_embeddings
        ):
            raise ContractViolation(
                "replacement appeal precedent lacks a trusted fake text embedding"
            )
        try:
            rebuilt = build_m5_controlled_fake_embedding(
                channel=embedding.request.channel,
                situation_text=authority.precedent.situation_text,
                model_manifest=manifest.models["text_embedding"],
                embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
            )
        except M5EmbeddingIntegrityError as exc:
            raise ContractViolation(
                "replacement appeal precedent embedding reconstruction failed"
            ) from exc
        if rebuilt != embedding:
            raise ContractViolation(
                "replacement appeal precedent vector differs from trusted reconstruction"
            )

    def _validate_resolution_effect_scope(
        self,
        connection: sqlite3.Connection,
        case: Case,
        intent: AppealResolutionSideEffectIntent,
    ) -> None:
        source = intent.appeal_authority.source_case_authority
        manifest = self._load_run_manifest(connection, intent.run_id)
        if (
            case.manifest_id != intent.manifest_id
            or manifest.manifest_id != intent.manifest_id
            or source.config_sha256 != manifest.config_sha256
            or manifest.rule_version != intent.rule_version
            or manifest.models["detector"].model_manifest_id != source.detector_manifest_id
            or manifest.models["text_embedding"].model_manifest_id
            != intent.text_embedding_manifest_id
            or manifest.models["visual_embedding"].model_manifest_id
            != intent.visual_embedding_manifest_id
            or (
                intent.appeal_precedent_authority is not None
                and intent.appeal_precedent_authority.config_sha256 != manifest.config_sha256
            )
        ):
            raise ManifestMismatch("appeal resolution manifest scope changed")
        if not case.verdicts or case.verdicts[-1].verdict_id != intent.source_verdict_id:
            raise ConcurrentModification("appeal source verdict is no longer latest")
        expected_alert_ids = tuple(item.alert_id for item in source.alerts)
        actual_alert_ids = tuple(item.alert_id for item in intent.alert_rescissions)
        if intent.appeal_authority.appeal.status == AppealStatus.OVERTURNED:
            if actual_alert_ids != expected_alert_ids:
                raise ContractViolation("overturn must rescind every source alert")
        elif actual_alert_ids:
            raise ContractViolation("upheld appeal cannot rescind alerts")

        latest_crops = case.evidence_packs[-1].crops if case.evidence_packs else ()
        crops = {crop.crop_id: crop for crop in latest_crops}
        for label in intent.training_labels:
            crop = crops.get(label.crop_id)
            if (
                crop is None
                or not label.bbox.is_within(crop.output_width, crop.output_height)
                or label.detector_manifest_id != source.detector_manifest_id
                or label.excluded_reason is not None
            ):
                raise ContractViolation(
                    "appeal training label lacks Case Crop or detector authority"
                )

    def _validate_committed_appeal_case(
        self,
        connection: sqlite3.Connection,
        authority: AppealVersionAuthority,
    ) -> None:
        snapshot = self._load_case(connection, authority.run_id, authority.appeal.case_id)
        if (
            snapshot.revision != authority.source_case_revision + authority.version
            or not snapshot.case.appeals
            or snapshot.case.appeals[-1] != authority.appeal
            or snapshot.case.timeline[-1].object_ref != authority.appeal.appeal_id
            or snapshot.case.timeline[-1].details.get("version") != authority.version
        ):
            raise RepositoryIntegrityError(
                "idempotent appeal authority lacks its exact Case revision"
            )

    def _validate_resolution_replay(
        self,
        connection: sqlite3.Connection,
        intent: AppealResolutionSideEffectIntent,
    ) -> tuple[M5TrainingLabelAuthority, ...]:
        terminal = intent.appeal_authority
        commit_receipt = self._load_resolution_commit_receipt_for_appeal(
            connection,
            intent.run_id,
            terminal.appeal.appeal_id,
        )
        if (
            commit_receipt is None
            or commit_receipt.resolution_intent_id != intent.intent_id
            or commit_receipt.appeal_authority_sha256 != terminal.authority_sha256
            or commit_receipt.case_id != intent.case_id
        ):
            raise RepositoryIntegrityError(
                "resolution replay lacks its final causal commit receipt"
            )
        current = self._load_current_appeal_in_connection(
            connection,
            intent.run_id,
            intent.case_id,
        )
        case = self._load_resolution_case_revision(
            connection,
            run_id=intent.run_id,
            case_id=intent.case_id,
            revision=commit_receipt.resulting_case_revision,
        )
        if (
            current != terminal
            or case.revision != terminal.source_case_revision + 3
            or case.case.status != CaseStatus.APPEAL_RESOLVED
            or not case.case.appeals
            or case.case.appeals[-1] != terminal.appeal
        ):
            raise RepositoryIntegrityError("resolution replay Case authority is incomplete")
        review_row = connection.execute(
            """
            SELECT * FROM appeals
            WHERE run_id = ? AND appeal_id = ? AND version = 2
            """,
            (intent.run_id, terminal.appeal.appeal_id),
        ).fetchone()
        if review_row is None:
            raise RepositoryIntegrityError("resolution replay review authority is missing")
        reviewed = self._appeal_authority_from_row(review_row)
        self._require_trusted_resolution_intent(
            connection,
            current=reviewed,
            fresh_snapshot=intent.precedent_snapshot,
            proposed=intent,
        )
        self._validate_rescission_replay(connection, intent)
        for label in intent.training_labels:
            row = connection.execute(
                "SELECT * FROM training_labels WHERE run_id = ? AND label_id = ?",
                (intent.run_id, label.label_id),
            ).fetchone()
            if row is None or self._training_label_from_row(row) != label:
                raise RepositoryIntegrityError("resolution replay training label is missing")
        label_authorities = self._require_resolution_training_label_provenance(
            connection,
            intent,
            commit_receipt,
        )
        causal_events = load_m5_training_causal_events(connection, intent.run_id)
        event_by_label = {
            event.label_id: event for event in causal_events if event.label_id is not None
        }
        for authority in label_authorities:
            event = event_by_label.get(authority.label.label_id)
            if event is None:
                raise RepositoryIntegrityError(
                    "resolution replay training-label causal event is missing"
                )
            try:
                expected_event = build_m5_training_label_causal_event(
                    run_id=intent.run_id,
                    manifest_id=intent.manifest_id,
                    authority=authority,
                    sequence=event.sequence,
                    previous_event_sha256=event.previous_event_sha256,
                )
            except M5TrainingHistoryError as exc:
                raise RepositoryIntegrityError(
                    "resolution replay training-label causal authority is invalid"
                ) from exc
            if expected_event != event:
                raise RepositoryIntegrityError(
                    "resolution replay training-label causal authority is invalid"
                )
        if intent.appeal_precedent_authority is not None:
            replacement_precedent = self._load_m5_precedent_revision(
                connection,
                intent.run_id,
                intent.appeal_precedent_authority.precedent.precedent_id,
                intent.appeal_precedent_authority.revision,
            )
            if replacement_precedent != intent.appeal_precedent_authority:
                raise RepositoryIntegrityError("resolution replay replacement precedent is missing")
        revocation_receipts: list[M5PrecedentRevocationReceipt] = []
        for revocation in intent.precedent_revocations:
            durable_revocation = self._find_revocation_by_prior(
                connection,
                run_id=intent.run_id,
                precedent_id=revocation.precedent_id,
                prior_authority_id=revocation.prior_authority_id,
            )
            if durable_revocation is None:
                raise RepositoryIntegrityError("resolution replay precedent revocation is missing")
            receipt, citation_snapshot = durable_revocation
            resulting_precedent = self._load_m5_precedent_revision(
                connection,
                intent.run_id,
                revocation.precedent_id,
                receipt.resulting_revision,
            )
            if (
                resulting_precedent is None
                or resulting_precedent.authority_id != receipt.resulting_authority_id
                or resulting_precedent.revision != revocation.prior_revision + 1
                or resulting_precedent.precedent.status != PrecedentStatus.REVOKED
                or resulting_precedent.precedent.invalidated_by != terminal.appeal.appeal_id
            ):
                raise RepositoryIntegrityError("resolution replay precedent revocation is missing")
            self._validate_revocation_result(intent, revocation, receipt)
            expected = next(
                item
                for item in intent.precedent_snapshot.automatic_precedents
                if item.precedent_id == revocation.precedent_id
            )
            if tuple(item.citation_id for item in citation_snapshot.citations) != tuple(
                item.source_citation_id for item in expected.citations
            ):
                raise RepositoryIntegrityError(
                    "resolution replay precedent citation snapshot differs"
                )
            revocation_receipts.append(receipt)
        rebuilt_commit = self._build_resolution_commit_receipt(
            connection,
            intent=intent,
            resulting_case=case,
            revocation_receipts=tuple(revocation_receipts),
        )
        if rebuilt_commit != commit_receipt:
            raise RepositoryIntegrityError(
                "resolution replay effect roots differ from its final commit receipt"
            )
        return label_authorities

    def _validate_rescission_replay(
        self,
        connection: sqlite3.Connection,
        intent: AppealResolutionSideEffectIntent,
    ) -> None:
        verdict_rows = connection.execute(
            "SELECT * FROM verdict_rescissions WHERE run_id = ? AND resolution_intent_id = ?",
            (intent.run_id, intent.intent_id),
        ).fetchall()
        expected_verdict_count = int(intent.verdict_rescission is not None)
        if len(verdict_rows) != expected_verdict_count:
            raise RepositoryIntegrityError("resolution replay verdict rescission differs")
        if intent.verdict_rescission is not None:
            self._validate_verdict_rescission_row(
                verdict_rows[0],
                intent,
                intent.verdict_rescission,
            )
        alert_rows = connection.execute(
            """
            SELECT * FROM alert_rescissions
            WHERE run_id = ? AND resolution_intent_id = ? ORDER BY alert_id
            """,
            (intent.run_id, intent.intent_id),
        ).fetchall()
        if len(alert_rows) != len(intent.alert_rescissions):
            raise RepositoryIntegrityError("resolution replay alert rescissions differ")
        for row, rescission in zip(alert_rows, intent.alert_rescissions, strict=True):
            self._validate_alert_rescission_row(row, intent, rescission)

    def _load_current_appeal_in_connection(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        case_id: str,
    ) -> AppealVersionAuthority | None:
        rows = connection.execute(
            """
            SELECT * FROM appeals
            WHERE run_id = ? AND case_id = ?
            ORDER BY appeal_id, version
            """,
            (run_id, case_id),
        ).fetchall()
        return self._appeal_head_from_rows(connection, rows)

    def _appeal_head_from_rows(
        self,
        connection: sqlite3.Connection,
        rows: list[sqlite3.Row],
    ) -> AppealVersionAuthority | None:
        if not rows:
            return None
        appeal_ids = {_row_str(row, "appeal_id") for row in rows}
        if len(appeal_ids) != 1:
            raise RepositoryIntegrityError("Case has multiple effective appeal identities")
        case_ids = {_row_str(row, "case_id") for row in rows}
        if len(case_ids) != 1:
            raise RepositoryIntegrityError("appeal identity spans multiple Case scopes")
        versions = tuple(_row_int(row, "version") for row in rows)
        if versions != tuple(range(1, len(rows) + 1)) or len(rows) > 3:
            raise RepositoryIntegrityError("appeal version history is not contiguous")
        authorities = tuple(self._appeal_authority_from_row(row) for row in rows)
        self._validate_appeal_chain(authorities)
        self._validate_embedded_closed_case_authority(connection, authorities[-1])
        return authorities[-1]

    def _validate_durable_appeal_head(
        self,
        connection: sqlite3.Connection,
        authority: AppealVersionAuthority,
    ) -> None:
        if authority.version < 3:
            self._validate_committed_appeal_case(connection, authority)
            return
        receipt = self._load_resolution_receipt_for_appeal(
            connection,
            authority.run_id,
            authority.appeal.appeal_id,
        )
        if receipt is None or receipt.appeal_authority != authority:
            raise RepositoryIntegrityError(
                "terminal appeal head lacks its exact resolution receipt"
            )
        self._validate_resolution_replay(connection, receipt)

    def _validate_appeal_chain(
        self,
        authorities: tuple[AppealVersionAuthority, ...],
    ) -> None:
        first = authorities[0]
        expected_first = submit_appeal(
            first.source_case_authority,
            AppealSubmissionCommand(
                run_id=first.run_id,
                case_id=first.appeal.case_id,
                appeal_id=first.appeal.appeal_id,
                expected_case_revision=first.source_case_revision,
                expected_case_authority_sha256=first.source_case_authority_sha256,
                reason=first.appeal.reason,
                submitted_by=first.appeal.submitted_by,
            ),
            None,
        )
        if first != expected_first:
            raise RepositoryIntegrityError("stored appeal submission is not canonical")
        if len(authorities) >= 2:
            second = authorities[1]
            if second.assigned_reviewer_id is None:
                raise RepositoryIntegrityError("stored review has no reviewer")
            expected_second = begin_appeal_review(
                first,
                AppealReviewCommand(
                    run_id=first.run_id,
                    case_id=first.appeal.case_id,
                    appeal_id=first.appeal.appeal_id,
                    expected_appeal_authority_sha256=first.authority_sha256,
                    reviewer_id=second.assigned_reviewer_id,
                ),
            )
            if second != expected_second:
                raise RepositoryIntegrityError("stored appeal review is not canonical")
        if len(authorities) == 3:
            second = authorities[1]
            terminal = authorities[2]
            reviewer_id = terminal.appeal.reviewer_id
            summary = terminal.appeal.resolution_summary
            resolved_decision = terminal.appeal.resolved_decision
            if reviewer_id is None or summary is None or resolved_decision is None:
                raise RepositoryIntegrityError("stored terminal appeal lacks resolution fields")
            expected_terminal = resolve_appeal(
                second,
                AppealResolutionCommand(
                    run_id=second.run_id,
                    case_id=second.appeal.case_id,
                    appeal_id=second.appeal.appeal_id,
                    expected_appeal_authority_sha256=second.authority_sha256,
                    status=terminal.appeal.status,
                    reviewer_id=reviewer_id,
                    resolution_summary=summary,
                    resolved_decision=resolved_decision,
                ),
            )
            if terminal != expected_terminal:
                raise RepositoryIntegrityError("stored terminal appeal is not canonical")

    def _appeal_authority_from_row(self, row: sqlite3.Row) -> AppealVersionAuthority:
        authority = _load_document(
            row,
            json_key="authority_json",
            sha256_key="document_sha256",
            model_type=AppealVersionAuthority,
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "appeal_id"),
            _row_int(row, "version"),
            _row_str(row, "authority_sha256"),
            _row_optional_str(row, "previous_authority_sha256"),
            _row_str(row, "case_id"),
            _row_str(row, "status"),
            _row_optional_str(row, "assigned_reviewer_id"),
            _row_int(row, "source_case_revision"),
            _row_str(row, "source_case_authority_sha256"),
            _row_str(row, "source_verdict_id"),
            _row_int(row, "source_verdict_version"),
            _row_str(row, "source_verdict_sha256"),
            _row_str(row, "source_decision"),
            _row_str(row, "text_embedding_manifest_id"),
            _row_str(row, "visual_embedding_manifest_id"),
            _row_str(row, "manifest_id"),
            _row_str(row, "rule_version"),
        )
        expected = (
            authority.run_id,
            authority.appeal.appeal_id,
            authority.version,
            authority.authority_sha256,
            authority.previous_authority_sha256,
            authority.appeal.case_id,
            authority.appeal.status.value,
            authority.assigned_reviewer_id,
            authority.source_case_revision,
            authority.source_case_authority_sha256,
            authority.source_verdict_id,
            authority.source_verdict_version,
            authority.source_verdict_sha256,
            authority.source_decision.value,
            authority.text_embedding_manifest_id,
            authority.visual_embedding_manifest_id,
            authority.manifest_id,
            authority.rule_version,
        )
        if indexed != expected:
            raise RepositoryIntegrityError("appeal indexes differ from canonical authority")
        return authority

    def _insert_appeal_authority(
        self,
        connection: sqlite3.Connection,
        authority: AppealVersionAuthority,
    ) -> None:
        authority_json, document_sha256 = _document(authority)
        connection.execute(
            """
            INSERT INTO appeals(
                run_id, appeal_id, version, authority_sha256,
                previous_authority_sha256, case_id, status,
                assigned_reviewer_id, source_case_revision,
                source_case_authority_sha256, source_verdict_id,
                source_verdict_version, source_verdict_sha256, source_decision,
                text_embedding_manifest_id, visual_embedding_manifest_id,
                manifest_id, rule_version, authority_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                authority.run_id,
                authority.appeal.appeal_id,
                authority.version,
                authority.authority_sha256,
                authority.previous_authority_sha256,
                authority.appeal.case_id,
                authority.appeal.status.value,
                authority.assigned_reviewer_id,
                authority.source_case_revision,
                authority.source_case_authority_sha256,
                authority.source_verdict_id,
                authority.source_verdict_version,
                authority.source_verdict_sha256,
                authority.source_decision.value,
                authority.text_embedding_manifest_id,
                authority.visual_embedding_manifest_id,
                authority.manifest_id,
                authority.rule_version,
                authority_json,
                document_sha256,
            ),
        )

    def _build_closed_case_authority(
        self,
        connection: sqlite3.Connection,
        snapshot: CaseSnapshot,
    ) -> ClosedCaseAppealAuthority:
        case = snapshot.case
        if case.status != CaseStatus.CLOSED or not case.verdicts or case.final_decision is None:
            raise ContractViolation("appeal source is not a finalized CLOSED Case")
        verdict = case.verdicts[-1]
        if case.final_decision != verdict.decision:
            raise RepositoryIntegrityError("closed Case final decision differs from verdict")
        manifest = self._load_run_manifest(connection, case.run_id)
        if (
            manifest.manifest_id != case.manifest_id
            or manifest.rule_version != case.event.rule_version
            or verdict.manifest_id != case.manifest_id
            or verdict.violation_type != case.event.violation_type
        ):
            raise ManifestMismatch("closed Case appeal source has inconsistent manifest scope")
        alerts = tuple(
            sorted(
                (AppealableAlertAuthority(alert_id=item.alert_id) for item in case.alerts),
                key=lambda item: item.alert_id,
            )
        )
        if any(item.rescinded for item in case.alerts):
            raise ContractViolation("a rescinded alert cannot enter a new appeal source")
        self._validate_case_alert_roots(connection, case)
        automatic = self._automatic_precedent_authorities(connection, case)
        return ClosedCaseAppealAuthority(
            run_id=case.run_id,
            case_id=case.case_id,
            case_revision=snapshot.revision,
            verdict_id=verdict.verdict_id,
            verdict_version=verdict.version,
            verdict_sha256=verdict.verdict_sha256,
            final_decision=case.final_decision,
            evidence_class=case.event.evidence_class,
            violation_type=case.event.violation_type,
            alerts=alerts,
            automatic_precedents=automatic,
            effective_appeal_ids=tuple(sorted(item.appeal_id for item in case.appeals)),
            detector_manifest_id=manifest.models["detector"].model_manifest_id,
            text_embedding_manifest_id=manifest.models["text_embedding"].model_manifest_id,
            visual_embedding_manifest_id=manifest.models["visual_embedding"].model_manifest_id,
            manifest_id=manifest.manifest_id,
            config_sha256=manifest.config_sha256,
            rule_version=manifest.rule_version,
        )

    def _validate_embedded_closed_case_authority(
        self,
        connection: sqlite3.Connection,
        appeal: AppealVersionAuthority,
    ) -> None:
        source_snapshot = self._load_case_version(
            connection,
            appeal.run_id,
            appeal.appeal.case_id,
            appeal.source_case_revision,
        )
        source = appeal.source_case_authority
        reconstructed = self._build_closed_case_authority_with_frozen_precedents(
            connection,
            source_snapshot,
            source.automatic_precedents,
        )
        if reconstructed != source:
            raise RepositoryIntegrityError(
                "embedded closed Case authority differs from immutable source roots"
            )

    def _build_closed_case_authority_with_frozen_precedents(
        self,
        connection: sqlite3.Connection,
        snapshot: CaseSnapshot,
        automatic_precedents: tuple[AutomaticPrecedentAppealAuthority, ...],
    ) -> ClosedCaseAppealAuthority:
        persisted_ids = tuple(
            _row_str(row, "precedent_id")
            for row in connection.execute(
                """
                SELECT DISTINCT precedent_id FROM precedents
                WHERE run_id = ? AND source = ? AND source_case_id = ?
                ORDER BY precedent_id
                """,
                (
                    snapshot.case.run_id,
                    PrecedentSource.AUTOMATIC.value,
                    snapshot.case.case_id,
                ),
            ).fetchall()
        )
        frozen_ids = tuple(item.precedent_id for item in automatic_precedents)
        if frozen_ids != persisted_ids:
            raise RepositoryIntegrityError(
                "embedded automatic precedent set differs from durable Case roots"
            )
        for frozen in automatic_precedents:
            persisted = self._load_precedent_revision(
                connection,
                snapshot.case.run_id,
                frozen.precedent_id,
                frozen.precedent_revision,
            )
            if (
                persisted.authority_id != frozen.precedent_authority_id
                or persisted.precedent.source != PrecedentSource.AUTOMATIC
                or persisted.precedent.status != frozen.status
                or persisted.precedent.source_case_id != frozen.source_case_id
                or persisted.precedent.decision_direction != frozen.decision_direction
            ):
                raise RepositoryIntegrityError(
                    "embedded automatic precedent differs from historical authority"
                )
            persisted_citations = {
                citation.source_citation_id: citation
                for citation in self._affected_citations(
                    connection,
                    snapshot.case.run_id,
                    frozen.precedent_id,
                )
            }
            if any(
                persisted_citations.get(citation.source_citation_id) != citation
                for citation in frozen.citations
            ):
                raise RepositoryIntegrityError(
                    "embedded appeal citation differs from immutable citation history"
                )
        current = self._build_closed_case_authority_without_precedents(connection, snapshot)
        return ClosedCaseAppealAuthority.model_validate(
            {
                **current.model_dump(mode="python", exclude={"authority_sha256"}),
                "automatic_precedents": automatic_precedents,
            }
        )

    def _build_closed_case_authority_without_precedents(
        self,
        connection: sqlite3.Connection,
        snapshot: CaseSnapshot,
    ) -> ClosedCaseAppealAuthority:
        case = snapshot.case
        if case.status != CaseStatus.CLOSED or not case.verdicts or case.final_decision is None:
            raise RepositoryIntegrityError("historical appeal source Case is not CLOSED")
        manifest = self._load_run_manifest(connection, case.run_id)
        verdict = case.verdicts[-1]
        self._validate_case_alert_roots(connection, case)
        return ClosedCaseAppealAuthority(
            run_id=case.run_id,
            case_id=case.case_id,
            case_revision=snapshot.revision,
            verdict_id=verdict.verdict_id,
            verdict_version=verdict.version,
            verdict_sha256=verdict.verdict_sha256,
            final_decision=case.final_decision,
            evidence_class=case.event.evidence_class,
            violation_type=case.event.violation_type,
            alerts=tuple(
                sorted(
                    (AppealableAlertAuthority(alert_id=item.alert_id) for item in case.alerts),
                    key=lambda item: item.alert_id,
                )
            ),
            effective_appeal_ids=tuple(sorted(item.appeal_id for item in case.appeals)),
            detector_manifest_id=manifest.models["detector"].model_manifest_id,
            text_embedding_manifest_id=manifest.models["text_embedding"].model_manifest_id,
            visual_embedding_manifest_id=manifest.models["visual_embedding"].model_manifest_id,
            manifest_id=manifest.manifest_id,
            config_sha256=manifest.config_sha256,
            rule_version=manifest.rule_version,
        )

    def _automatic_precedent_authorities(
        self,
        connection: sqlite3.Connection,
        case: Case,
    ) -> tuple[AutomaticPrecedentAppealAuthority, ...]:
        rows = connection.execute(
            """
            SELECT p.precedent_id
            FROM precedents AS p
            JOIN (
                SELECT precedent_id, MAX(revision) AS revision
                FROM precedents
                WHERE run_id = ? AND source_case_id = ? AND source = 'AUTOMATIC'
                GROUP BY precedent_id
            ) AS latest
              ON latest.precedent_id = p.precedent_id AND latest.revision = p.revision
            WHERE p.run_id = ? AND p.status <> 'REVOKED'
            ORDER BY p.precedent_id
            LIMIT ?
            """,
            (case.run_id, case.case_id, case.run_id, MAX_M5_PRECEDENTS + 1),
        ).fetchall()
        if len(rows) > MAX_M5_PRECEDENTS:
            raise RepositoryIntegrityError("automatic precedent snapshot exceeds its bound")
        authorities: list[AutomaticPrecedentAppealAuthority] = []
        for row in rows:
            precedent_id = _row_str(row, "precedent_id")
            authority = self._load_m5_precedent_authority(
                connection,
                case.run_id,
                precedent_id,
            )
            if authority is None:
                raise RepositoryIntegrityError("automatic precedent head is missing")
            precedent = authority.precedent
            if (
                precedent.source != PrecedentSource.AUTOMATIC
                or precedent.source_case_id != case.case_id
                or precedent.decision_direction != case.final_decision
                or precedent.evidence_class != case.event.evidence_class
                or precedent.violation_type != case.event.violation_type
                or precedent.rule_version != case.event.rule_version
                or precedent.status == PrecedentStatus.REVOKED
            ):
                raise RepositoryIntegrityError("automatic precedent conflicts with its source Case")
            authorities.append(
                AutomaticPrecedentAppealAuthority(
                    precedent_id=precedent.precedent_id,
                    precedent_authority_id=authority.authority_id,
                    precedent_revision=authority.revision,
                    status=precedent.status,
                    decision_direction=precedent.decision_direction,
                    source_case_id=case.case_id,
                    citations=self._affected_citations(
                        connection,
                        case.run_id,
                        precedent.precedent_id,
                    ),
                )
            )
        return tuple(authorities)

    def _build_resolution_precedent_snapshot(
        self,
        connection: sqlite3.Connection,
        source: ClosedCaseAppealAuthority,
    ) -> AppealResolutionPrecedentSnapshot:
        source_case = self._load_case_version(
            connection,
            source.run_id,
            source.case_id,
            source.case_revision,
        ).case
        return AppealResolutionPrecedentSnapshot(
            run_id=source.run_id,
            case_id=source.case_id,
            automatic_precedents=self._automatic_precedent_authorities(
                connection,
                source_case,
            ),
        )

    def _affected_citations(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        precedent_id: str,
    ) -> tuple[AffectedPrecedentCitation, ...]:
        rows = connection.execute(
            """
            SELECT * FROM precedent_citations
            WHERE run_id = ? AND precedent_id = ?
            ORDER BY case_id, citation_id
            LIMIT ?
            """,
            (run_id, precedent_id, MAX_M5_CITATION_SNAPSHOT_ENTRIES + 1),
        ).fetchall()
        if len(rows) > MAX_M5_CITATION_SNAPSHOT_ENTRIES:
            raise RepositoryIntegrityError("precedent citation snapshot exceeds its bound")
        citations: list[AffectedPrecedentCitation] = []
        for row in rows:
            commit = self._citation_commit_from_row(connection, row)
            citation = commit.citation
            citations.append(
                AffectedPrecedentCitation(
                    source_citation_id=citation.citation_id,
                    citing_case_id=citation.case_id,
                    precedent_id=citation.precedent_id,
                    similarity_score=citation.score,
                )
            )
        citations.sort(key=lambda item: item.sort_key)
        if len({item.source_citation_id for item in citations}) != len(citations):
            raise RepositoryIntegrityError("precedent citation identity is duplicated")
        return tuple(citations)

    def _load_precedent_revision(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        precedent_id: str,
        revision: int,
    ) -> M5PrecedentAuthority:
        authority = self._load_m5_precedent_revision(
            connection,
            run_id,
            precedent_id,
            revision,
        )
        if authority is None:
            raise RepositoryIntegrityError("historical precedent authority is missing")
        return authority

    def _validate_case_alert_roots(
        self,
        connection: sqlite3.Connection,
        case: Case,
    ) -> None:
        rows = connection.execute(
            "SELECT * FROM alerts WHERE run_id = ? AND case_id = ?",
            (case.run_id, case.case_id),
        ).fetchall()
        decisions = tuple(item for item in case.alerts)
        if not decisions:
            if rows:
                for row in rows:
                    authority = _load_document(
                        row,
                        json_key="authority_json",
                        sha256_key="document_sha256",
                        model_type=AlertPolicyAuthority,
                    )
                    if authority.decision is not None:
                        raise RepositoryIntegrityError(
                            "closed Case omits its alert policy decision"
                        )
            return
        if len(rows) != 1:
            raise RepositoryIntegrityError("closed Case alert authority is missing")
        authority = _load_document(
            rows[0],
            json_key="authority_json",
            sha256_key="document_sha256",
            model_type=AlertPolicyAuthority,
        )
        if authority.decision is None or decisions != (authority.decision,):
            raise RepositoryIntegrityError("Case alert differs from policy authority")

    def _appeal_case_successor(
        self,
        case: Case,
        authority: AppealVersionAuthority,
    ) -> Case:
        if case.final_decision is None:
            raise RepositoryIntegrityError("appeal Case has no final decision")
        if authority.version == 1:
            appeals = (*case.appeals, authority.appeal)
            status = CaseStatus.APPEALED
            alerts = case.alerts
            final_decision = case.final_decision
        elif authority.version == 2:
            if not case.appeals:
                raise RepositoryIntegrityError("appeal review Case has no submission")
            appeals = (*case.appeals[:-1], authority.appeal)
            status = CaseStatus.APPEALED
            alerts = case.alerts
            final_decision = case.final_decision
        else:
            if not case.appeals:
                raise RepositoryIntegrityError("terminal appeal Case has no review")
            resolved_decision = authority.appeal.resolved_decision
            if resolved_decision is None:
                raise RepositoryIntegrityError("terminal appeal lacks a final decision")
            appeals = (*case.appeals[:-1], authority.appeal)
            status = CaseStatus.APPEAL_RESOLVED
            final_decision = resolved_decision
            alerts = (
                tuple(item.model_copy(update={"rescinded": True}) for item in case.alerts)
                if authority.appeal.status == AppealStatus.OVERTURNED
                else case.alerts
            )
        timeline = (
            *case.timeline,
            TimelineEntry(
                sequence=len(case.timeline),
                action=AuditAction.CASE_STATE_CHANGED.value,
                stage="APPEAL",
                object_ref=authority.appeal.appeal_id,
                details={
                    "final_decision": final_decision.value,
                    "status": authority.appeal.status.value,
                    "version": authority.version,
                },
            ),
        )
        payload = case.model_dump(mode="json", exclude_computed_fields=True)
        payload.update(
            {
                "status": status.value,
                "alerts": [item.model_dump(mode="json") for item in alerts],
                "appeals": [item.model_dump(mode="json") for item in appeals],
                "final_decision": final_decision.value,
                "timeline": [item.model_dump(mode="json") for item in timeline],
            }
        )
        return Case.model_validate(payload)

    def _insert_resolution_receipt(
        self,
        connection: sqlite3.Connection,
        intent: AppealResolutionSideEffectIntent,
    ) -> None:
        raw, digest = _document(intent)
        connection.execute(
            """
            INSERT INTO appeal_resolution_receipts(
                run_id, intent_id, appeal_id, appeal_authority_sha256,
                case_id, final_decision, final_decision_changed,
                affected_citation_report_sha256, manifest_id,
                intent_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                intent.run_id,
                intent.intent_id,
                intent.appeal_authority.appeal.appeal_id,
                intent.appeal_authority.authority_sha256,
                intent.case_id,
                intent.final_decision.value,
                int(intent.final_decision_changed),
                intent.affected_citations.report_sha256,
                intent.manifest_id,
                raw,
                digest,
            ),
        )

    def _load_resolution_receipt_for_appeal(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        appeal_id: str,
    ) -> AppealResolutionSideEffectIntent | None:
        rows = connection.execute(
            """
            SELECT * FROM appeal_resolution_receipts
            WHERE run_id = ? AND appeal_id = ?
            """,
            (run_id, appeal_id),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RepositoryIntegrityError("appeal selects multiple terminal receipts")
        row = rows[0]
        intent = _load_document(
            row,
            json_key="intent_json",
            sha256_key="document_sha256",
            model_type=AppealResolutionSideEffectIntent,
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "intent_id"),
            _row_str(row, "appeal_id"),
            _row_str(row, "appeal_authority_sha256"),
            _row_str(row, "case_id"),
            _row_str(row, "final_decision"),
            _row_int(row, "final_decision_changed"),
            _row_str(row, "affected_citation_report_sha256"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            intent.run_id,
            intent.intent_id,
            intent.appeal_authority.appeal.appeal_id,
            intent.appeal_authority.authority_sha256,
            intent.case_id,
            intent.final_decision.value,
            int(intent.final_decision_changed),
            intent.affected_citations.report_sha256,
            intent.manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError("appeal resolution indexes differ from canonical intent")
        return intent

    def _load_resolution_case_revision(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        case_id: str,
        revision: int,
    ) -> CaseSnapshot:
        row = connection.execute(
            """
            SELECT * FROM case_versions
            WHERE run_id = ? AND case_id = ? AND revision = ?
            """,
            (run_id, case_id, revision),
        ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("appeal resolution Case revision is missing")
        case = _load_document(
            row,
            json_key="case_json",
            sha256_key="document_sha256",
            model_type=Case,
        )
        if (
            _row_str(row, "run_id") != case.run_id
            or _row_str(row, "case_id") != case.case_id
            or _row_int(row, "revision") != revision
            or _row_str(row, "status") != case.status.value
        ):
            raise RepositoryIntegrityError(
                "appeal resolution Case indexes differ from canonical content"
            )
        return CaseSnapshot(case=case, revision=revision)

    def _build_resolution_commit_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        intent: AppealResolutionSideEffectIntent,
        resulting_case: CaseSnapshot,
        revocation_receipts: tuple[M5PrecedentRevocationReceipt, ...],
    ) -> M5AppealResolutionCommitReceipt:
        _intent_raw, intent_sha256 = _document(intent)
        _case_raw, case_sha256 = _document(resulting_case.case)
        verdict_rows = connection.execute(
            """
            SELECT rescission_id FROM verdict_rescissions
            WHERE run_id = ? AND resolution_intent_id = ?
            ORDER BY rescission_id
            """,
            (intent.run_id, intent.intent_id),
        ).fetchall()
        alert_rows = connection.execute(
            """
            SELECT rescission_id FROM alert_rescissions
            WHERE run_id = ? AND resolution_intent_id = ?
            ORDER BY rescission_id
            """,
            (intent.run_id, intent.intent_id),
        ).fetchall()
        replacement = intent.appeal_precedent_authority
        return M5AppealResolutionCommitReceipt(
            run_id=intent.run_id,
            resolution_intent_id=intent.intent_id,
            resolution_document_sha256=intent_sha256,
            appeal_id=intent.appeal_authority.appeal.appeal_id,
            appeal_authority_sha256=intent.appeal_authority.authority_sha256,
            case_id=intent.case_id,
            source_case_revision=intent.appeal_authority.source_case_revision,
            resulting_case_revision=resulting_case.revision,
            resulting_case_document_sha256=case_sha256,
            verdict_rescission_ids=tuple(_row_str(row, "rescission_id") for row in verdict_rows),
            alert_rescission_ids=tuple(_row_str(row, "rescission_id") for row in alert_rows),
            precedent_revocation_receipt_ids=tuple(
                sorted(receipt.receipt_id for receipt in revocation_receipts)
            ),
            replacement_precedent_authority_id=(
                replacement.authority_id if replacement is not None else None
            ),
            training_label_ids=tuple(sorted(label.label_id for label in intent.training_labels)),
            affected_citation_report_sha256=intent.affected_citations.report_sha256,
            manifest_id=intent.manifest_id,
        )

    def _insert_resolution_commit_receipt(
        self,
        connection: sqlite3.Connection,
        receipt: M5AppealResolutionCommitReceipt,
    ) -> M5AppealResolutionCommitReceipt:
        raw, digest = _document(receipt)
        source = m5_appeal_resolution_commit_causal_source(
            receipt,
            source_document_sha256=digest,
        )

        def insert_source() -> None:
            try:
                connection.execute(
                    """
                    INSERT INTO appeal_resolution_commit_receipts(
                        run_id, receipt_id, effect_root_sha256,
                        resolution_intent_id, resolution_document_sha256,
                        appeal_id, appeal_authority_sha256, case_id,
                        source_case_revision, resulting_case_revision,
                        resulting_case_document_sha256,
                        verdict_rescission_ids_json, alert_rescission_ids_json,
                        precedent_revocation_receipt_ids_json,
                        replacement_precedent_authority_id,
                        training_label_ids_json, affected_citation_report_sha256,
                        manifest_id, receipt_json, document_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        receipt.run_id,
                        receipt.receipt_id,
                        receipt.effect_root_sha256,
                        receipt.resolution_intent_id,
                        receipt.resolution_document_sha256,
                        receipt.appeal_id,
                        receipt.appeal_authority_sha256,
                        receipt.case_id,
                        receipt.source_case_revision,
                        receipt.resulting_case_revision,
                        receipt.resulting_case_document_sha256,
                        canonical_json(list(receipt.verdict_rescission_ids)),
                        canonical_json(list(receipt.alert_rescission_ids)),
                        canonical_json(list(receipt.precedent_revocation_receipt_ids)),
                        receipt.replacement_precedent_authority_id,
                        canonical_json(list(receipt.training_label_ids)),
                        receipt.affected_citation_report_sha256,
                        receipt.manifest_id,
                        raw,
                        digest,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConcurrentModification(
                    "appeal resolution commit receipt could not be appended"
                ) from exc
            self._m5_fault("appeal.resolve.commit_receipt.after_source")

        append_m5_precedent_causal_event(
            connection,
            source=source,
            insert_source=insert_source,
            fault_scope="appeal.resolve.commit_receipt",
            fault=self._m5_fault,
        )
        durable = self._load_resolution_commit_receipt_for_appeal(
            connection,
            receipt.run_id,
            receipt.appeal_id,
        )
        if durable != receipt:
            raise RepositoryIntegrityError("appeal resolution commit marker replay differs")
        return receipt

    def _resolution_commit_receipt_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> M5AppealResolutionCommitReceipt:
        receipt = _load_document(
            row,
            json_key="receipt_json",
            sha256_key="document_sha256",
            model_type=M5AppealResolutionCommitReceipt,
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "receipt_id"),
            _row_str(row, "effect_root_sha256"),
            _row_str(row, "resolution_intent_id"),
            _row_str(row, "resolution_document_sha256"),
            _row_str(row, "appeal_id"),
            _row_str(row, "appeal_authority_sha256"),
            _row_str(row, "case_id"),
            _row_int(row, "source_case_revision"),
            _row_int(row, "resulting_case_revision"),
            _row_str(row, "resulting_case_document_sha256"),
            _row_str(row, "verdict_rescission_ids_json"),
            _row_str(row, "alert_rescission_ids_json"),
            _row_str(row, "precedent_revocation_receipt_ids_json"),
            _row_optional_str(row, "replacement_precedent_authority_id"),
            _row_str(row, "training_label_ids_json"),
            _row_str(row, "affected_citation_report_sha256"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            receipt.run_id,
            receipt.receipt_id,
            receipt.effect_root_sha256,
            receipt.resolution_intent_id,
            receipt.resolution_document_sha256,
            receipt.appeal_id,
            receipt.appeal_authority_sha256,
            receipt.case_id,
            receipt.source_case_revision,
            receipt.resulting_case_revision,
            receipt.resulting_case_document_sha256,
            canonical_json(list(receipt.verdict_rescission_ids)),
            canonical_json(list(receipt.alert_rescission_ids)),
            canonical_json(list(receipt.precedent_revocation_receipt_ids)),
            receipt.replacement_precedent_authority_id,
            canonical_json(list(receipt.training_label_ids)),
            receipt.affected_citation_report_sha256,
            receipt.manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError(
                "appeal resolution commit indexes differ from canonical receipt"
            )
        require_m5_precedent_causal_event(
            connection,
            source=m5_appeal_resolution_commit_causal_source(
                receipt,
                source_document_sha256=_row_str(row, "document_sha256"),
            ),
        )
        return receipt

    def _load_resolution_commit_receipt_for_appeal(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        appeal_id: str,
    ) -> M5AppealResolutionCommitReceipt | None:
        rows = connection.execute(
            """
            SELECT * FROM appeal_resolution_commit_receipts
            WHERE run_id = ? AND appeal_id = ?
            """,
            (run_id, appeal_id),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RepositoryIntegrityError(
                "appeal selects multiple final resolution commit receipts"
            )
        return self._resolution_commit_receipt_from_row(connection, rows[0])

    def _insert_verdict_rescission(
        self,
        connection: sqlite3.Connection,
        intent: AppealResolutionSideEffectIntent,
        rescission: VerdictRescissionIntent,
    ) -> None:
        payload = {
            "run_id": intent.run_id,
            "resolution_intent_id": intent.intent_id,
            "case_id": intent.case_id,
            "rescission": rescission.model_dump(mode="json"),
        }
        raw, digest = _payload_document(payload)
        rescission_id = sha256_hex(["m5-verdict-rescission", 1, payload])
        connection.execute(
            """
            INSERT INTO verdict_rescissions(
                run_id, rescission_id, resolution_intent_id, case_id,
                verdict_id, verdict_version, verdict_sha256,
                rescission_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                intent.run_id,
                rescission_id,
                intent.intent_id,
                intent.case_id,
                rescission.verdict_id,
                rescission.verdict_version,
                rescission.verdict_sha256,
                raw,
                digest,
            ),
        )

    def _insert_alert_rescission(
        self,
        connection: sqlite3.Connection,
        intent: AppealResolutionSideEffectIntent,
        rescission: AlertRescissionIntent,
    ) -> None:
        payload = {
            "run_id": intent.run_id,
            "resolution_intent_id": intent.intent_id,
            "case_id": intent.case_id,
            "rescission": rescission.model_dump(mode="json"),
        }
        raw, digest = _payload_document(payload)
        rescission_id = sha256_hex(["m5-alert-rescission", 1, payload])
        connection.execute(
            """
            INSERT INTO alert_rescissions(
                run_id, rescission_id, resolution_intent_id,
                case_id, alert_id, rescission_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                intent.run_id,
                rescission_id,
                intent.intent_id,
                intent.case_id,
                rescission.alert_id,
                raw,
                digest,
            ),
        )

    def _validate_verdict_rescission_row(
        self,
        row: sqlite3.Row,
        intent: AppealResolutionSideEffectIntent,
        rescission: VerdictRescissionIntent,
    ) -> None:
        payload = {
            "run_id": intent.run_id,
            "resolution_intent_id": intent.intent_id,
            "case_id": intent.case_id,
            "rescission": rescission.model_dump(mode="json"),
        }
        raw, digest = _payload_document(payload)
        expected_id = sha256_hex(["m5-verdict-rescission", 1, payload])
        if (
            _row_str(row, "run_id") != intent.run_id
            or _row_str(row, "rescission_id") != expected_id
            or _row_str(row, "resolution_intent_id") != intent.intent_id
            or _row_str(row, "case_id") != intent.case_id
            or _row_str(row, "verdict_id") != rescission.verdict_id
            or _row_int(row, "verdict_version") != rescission.verdict_version
            or _row_str(row, "verdict_sha256") != rescission.verdict_sha256
            or _row_str(row, "rescission_json") != raw
            or _row_str(row, "document_sha256") != digest
        ):
            raise RepositoryIntegrityError("verdict rescission row differs from intent")

    def _validate_alert_rescission_row(
        self,
        row: sqlite3.Row,
        intent: AppealResolutionSideEffectIntent,
        rescission: AlertRescissionIntent,
    ) -> None:
        payload = {
            "run_id": intent.run_id,
            "resolution_intent_id": intent.intent_id,
            "case_id": intent.case_id,
            "rescission": rescission.model_dump(mode="json"),
        }
        raw, digest = _payload_document(payload)
        expected_id = sha256_hex(["m5-alert-rescission", 1, payload])
        if (
            _row_str(row, "run_id") != intent.run_id
            or _row_str(row, "rescission_id") != expected_id
            or _row_str(row, "resolution_intent_id") != intent.intent_id
            or _row_str(row, "case_id") != intent.case_id
            or _row_str(row, "alert_id") != rescission.alert_id
            or _row_str(row, "rescission_json") != raw
            or _row_str(row, "document_sha256") != digest
        ):
            raise RepositoryIntegrityError("alert rescission row differs from intent")

    def _validate_revocation_result(
        self,
        resolution: AppealResolutionSideEffectIntent,
        intent: PrecedentRevocationIntent,
        receipt: M5PrecedentRevocationReceipt,
    ) -> None:
        citations = tuple(
            citation
            for precedent in resolution.precedent_snapshot.automatic_precedents
            if precedent.precedent_id == intent.precedent_id
            for citation in precedent.citations
        )
        if (
            receipt.outcome != M5PrecedentRevocationOutcome.REVOKED
            or receipt.prior_authority_id != intent.prior_authority_id
            or receipt.prior_revision != intent.prior_revision
            or receipt.resulting_revision != intent.prior_revision + 1
            or receipt.revoked_by_ref != resolution.appeal_authority.appeal.appeal_id
            or receipt.historical_case_ids
            != tuple(sorted({item.citing_case_id for item in citations}))
            or receipt.historical_citation_ids
            != tuple(sorted(item.source_citation_id for item in citations))
        ):
            raise RepositoryIntegrityError(
                "precedent revocation result differs from resolution snapshot"
            )

    def _insert_training_label(
        self,
        connection: sqlite3.Connection,
        intent: AppealResolutionSideEffectIntent,
        label: TrainingLabel,
        provenance: M5StrongTrainingLabelProvenanceReceipt,
    ) -> None:
        raw, digest = _document(label)
        connection.execute(
            """
            INSERT INTO training_labels(
                run_id, label_id, case_id, crop_id, quality, source,
                reviewer_id, rule_version, detector_manifest_id, manifest_id,
                strong_provenance_id, label_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                intent.run_id,
                label.label_id,
                label.case_id,
                label.crop_id,
                label.quality.value,
                label.source,
                label.reviewer_id,
                label.rule_version,
                label.detector_manifest_id,
                intent.manifest_id,
                provenance.provenance_id,
                raw,
                digest,
            ),
        )

    def _insert_strong_training_label_provenance(
        self,
        connection: sqlite3.Connection,
        receipt: M5StrongTrainingLabelProvenanceReceipt,
    ) -> None:
        raw, digest = _document(receipt)
        connection.execute(
            """
            INSERT INTO strong_training_label_provenance_receipts(
                run_id, provenance_id, case_id, appeal_id, label_id,
                label_document_sha256, crop_id, reviewer_id, quality,
                authored_input_id, review_authority_sha256,
                terminal_authority_sha256, terminal_status,
                resolution_intent_id, resolution_document_sha256,
                resolution_commit_receipt_id,
                resolution_commit_effect_root_sha256,
                manifest_id, rule_version, detector_manifest_id,
                provenance_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt.run_id,
                receipt.provenance_id,
                receipt.case_id,
                receipt.appeal_id,
                receipt.label_id,
                receipt.label_document_sha256,
                receipt.crop_id,
                receipt.reviewer_id,
                receipt.quality.value,
                receipt.authored_input.input_id,
                receipt.review_authority_sha256,
                receipt.terminal_authority_sha256,
                receipt.terminal_status.value,
                receipt.resolution_intent_id,
                receipt.resolution_document_sha256,
                receipt.resolution_commit_receipt_id,
                receipt.resolution_commit_effect_root_sha256,
                receipt.manifest_id,
                receipt.rule_version,
                receipt.detector_manifest_id,
                raw,
                digest,
            ),
        )

    def _strong_training_label_provenance_from_row(
        self,
        row: sqlite3.Row,
    ) -> M5StrongTrainingLabelProvenanceReceipt:
        receipt = _load_document(
            row,
            json_key="provenance_json",
            sha256_key="document_sha256",
            model_type=M5StrongTrainingLabelProvenanceReceipt,
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "provenance_id"),
            _row_str(row, "case_id"),
            _row_str(row, "appeal_id"),
            _row_str(row, "label_id"),
            _row_str(row, "label_document_sha256"),
            _row_str(row, "crop_id"),
            _row_str(row, "reviewer_id"),
            _row_str(row, "quality"),
            _row_str(row, "authored_input_id"),
            _row_str(row, "review_authority_sha256"),
            _row_str(row, "terminal_authority_sha256"),
            _row_str(row, "terminal_status"),
            _row_str(row, "resolution_intent_id"),
            _row_str(row, "resolution_document_sha256"),
            _row_str(row, "resolution_commit_receipt_id"),
            _row_str(row, "resolution_commit_effect_root_sha256"),
            _row_str(row, "manifest_id"),
            _row_str(row, "rule_version"),
            _row_str(row, "detector_manifest_id"),
        )
        expected = (
            receipt.run_id,
            receipt.provenance_id,
            receipt.case_id,
            receipt.appeal_id,
            receipt.label_id,
            receipt.label_document_sha256,
            receipt.crop_id,
            receipt.reviewer_id,
            receipt.quality.value,
            receipt.authored_input.input_id,
            receipt.review_authority_sha256,
            receipt.terminal_authority_sha256,
            receipt.terminal_status.value,
            receipt.resolution_intent_id,
            receipt.resolution_document_sha256,
            receipt.resolution_commit_receipt_id,
            receipt.resolution_commit_effect_root_sha256,
            receipt.manifest_id,
            receipt.rule_version,
            receipt.detector_manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError(
                "strong training label provenance indexes differ from canonical content"
            )
        return receipt

    def _training_label_from_row(self, row: sqlite3.Row) -> TrainingLabel:
        label = _load_document(
            row,
            json_key="label_json",
            sha256_key="document_sha256",
            model_type=TrainingLabel,
        )
        indexed = (
            _row_str(row, "label_id"),
            _row_str(row, "case_id"),
            _row_str(row, "crop_id"),
            _row_str(row, "quality"),
            _row_str(row, "source"),
            _row_optional_str(row, "reviewer_id"),
            _row_str(row, "rule_version"),
            _row_str(row, "detector_manifest_id"),
        )
        expected = (
            label.label_id,
            label.case_id,
            label.crop_id,
            label.quality.value,
            label.source,
            label.reviewer_id,
            label.rule_version,
            label.detector_manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError("training label indexes differ from canonical content")
        return label

    def _dataset_report_from_row(self, row: sqlite3.Row) -> DatasetExportReport:
        report = _load_document(
            row,
            json_key="report_json",
            sha256_key="document_sha256",
            model_type=DatasetExportReport,
        )
        artifact_json, _ = _document(report.dataset)
        if _row_str(row, "artifact_json") != artifact_json:
            raise RepositoryIntegrityError(
                "dataset artifact JSON differs from its canonical report"
            )
        dataset = report.dataset
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "dataset_id"),
            _row_str(row, "report_id"),
            _row_str(row, "command_id"),
            _row_str(row, "format"),
            _row_str(row, "relative_path"),
            _row_str(row, "content_sha256"),
            _row_int(row, "content_size_bytes"),
            _row_int(row, "label_count"),
            _row_str(row, "minimum_quality"),
            _row_str(row, "rule_version"),
            _row_str(row, "detector_manifest_id"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            report.run_id,
            dataset.dataset_id,
            report.report_id,
            report.command_id,
            dataset.format.value,
            dataset.relative_path,
            dataset.content_sha256,
            report.content_size_bytes,
            dataset.label_count,
            dataset.minimum_quality.value,
            dataset.rule_version,
            report.detector_manifest_id,
            report.manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError("dataset indexes differ from canonical report")
        return report

    def _resolution_time(self) -> datetime:
        raw = self._recorded_at()
        try:
            value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RepositoryIntegrityError("repository clock emitted invalid UTC") from exc
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise RepositoryIntegrityError("repository clock did not emit UTC")
        return value


__all__ = ["MAX_M5_TRAINING_LABELS", "SQLiteM5AppealRepository"]

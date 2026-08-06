"""Strict canonical decoding and duplicated-index checks for M5 rows."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import TypeVar, cast

from pydantic import BaseModel, ValidationError

from labcourt.contracts.alert_policy import (
    AlertChannelCapabilityAuthority,
    AlertCooldownAuthority,
    AlertDispatchAttempt,
    AlertDispatchReceipt,
    AlertOutboxItem,
    AlertPolicyAuthority,
    ImmediateSafetyDeliveryAuthority,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m5_appeals import (
    AlertRescissionIntent,
    AppealResolutionSideEffectIntent,
    AppealVersionAuthority,
    M5AppealResolutionCommitReceipt,
    VerdictRescissionIntent,
)
from labcourt.contracts.m5_precedent_causal_ledger import M5PrecedentCausalEvent
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
)
from labcourt.contracts.m5_training_provenance import (
    M5StrongTrainingLabelProvenanceReceipt,
)
from labcourt.contracts.training import TrainingLabel


class M5DocumentFailure(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class M5IndexFailure(ValueError):
    def __init__(self, reason_code: str = "INDEX_BINDING_MISMATCH") -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class M5TableSpec:
    table: str
    kind: M5AuthorityKind
    id_column: str
    order_by: str


@dataclass(frozen=True, slots=True)
class M5Record:
    kind: M5AuthorityKind
    table: str
    artifact_id: str
    row: sqlite3.Row
    document: BaseModel | dict[str, object]
    canonical_document: str


M5_TABLE_SPECS: tuple[M5TableSpec, ...] = (
    M5TableSpec(
        "precedent_embeddings",
        M5AuthorityKind.PRECEDENT_EMBEDDING,
        "embedding_id",
        "embedding_id",
    ),
    M5TableSpec("precedents", M5AuthorityKind.PRECEDENT, "precedent_id", "precedent_id, revision"),
    M5TableSpec(
        "m5_precedent_exposures",
        M5AuthorityKind.PRECEDENT_EXPOSURE,
        "exposure_id",
        "case_id, hearing_id, cycle_index, exposure_id",
    ),
    M5TableSpec(
        "m5_precedent_application_batches",
        M5AuthorityKind.PRECEDENT_APPLICATION_BATCH,
        "application_batch_id",
        "case_id, ready_case_revision, application_batch_id",
    ),
    M5TableSpec(
        "m5_precedent_causal_events",
        M5AuthorityKind.PRECEDENT_CAUSAL_EVENT,
        "event_id",
        "sequence",
    ),
    M5TableSpec(
        "precedent_citations",
        M5AuthorityKind.PRECEDENT_CITATION,
        "citation_id",
        "case_id, precedent_id, citation_id",
    ),
    M5TableSpec(
        "precedent_lifecycle_receipts",
        M5AuthorityKind.PRECEDENT_LIFECYCLE,
        "receipt_id",
        "receipt_id",
    ),
    M5TableSpec(
        "precedent_conflict_batches",
        M5AuthorityKind.PRECEDENT_CONFLICT_BATCH,
        "batch_authority_id",
        "batch_authority_id",
    ),
    M5TableSpec(
        "precedent_conflict_batch_receipts",
        M5AuthorityKind.PRECEDENT_CONFLICT_BATCH_RECEIPT,
        "receipt_id",
        "receipt_id",
    ),
    M5TableSpec("alerts", M5AuthorityKind.ALERT, "authority_id", "case_id"),
    M5TableSpec(
        "alert_cooldowns",
        M5AuthorityKind.ALERT_COOLDOWN,
        "authority_id",
        "key_id, revision",
    ),
    M5TableSpec("alert_outbox", M5AuthorityKind.ALERT_OUTBOX, "outbox_id", "outbox_id"),
    M5TableSpec(
        "alert_channel_capabilities",
        M5AuthorityKind.ALERT_CHANNEL_CAPABILITY,
        "capability_id",
        "channel, capability_id",
    ),
    M5TableSpec(
        "alert_dispatch_attempts",
        M5AuthorityKind.ALERT_DISPATCH_ATTEMPT,
        "attempt_id",
        "outbox_id, attempt_number",
    ),
    M5TableSpec(
        "alert_dispatch_receipts",
        M5AuthorityKind.ALERT_DISPATCH_RECEIPT,
        "receipt_id",
        "outbox_id, attempt_number",
    ),
    M5TableSpec(
        "m5_immediate_safety_deliveries",
        M5AuthorityKind.IMMEDIATE_SAFETY_DELIVERY,
        "authority_id",
        "incident_id",
    ),
    M5TableSpec("appeals", M5AuthorityKind.APPEAL, "appeal_id", "appeal_id, version"),
    M5TableSpec(
        "appeal_resolution_receipts",
        M5AuthorityKind.APPEAL_RESOLUTION,
        "intent_id",
        "appeal_id",
    ),
    M5TableSpec(
        "appeal_resolution_commit_receipts",
        M5AuthorityKind.APPEAL_RESOLUTION_COMMIT,
        "receipt_id",
        "appeal_id",
    ),
    M5TableSpec(
        "verdict_rescissions",
        M5AuthorityKind.VERDICT_RESCISSION,
        "rescission_id",
        "rescission_id",
    ),
    M5TableSpec(
        "alert_rescissions",
        M5AuthorityKind.ALERT_RESCISSION,
        "rescission_id",
        "rescission_id",
    ),
    M5TableSpec(
        "strong_training_label_provenance_receipts",
        M5AuthorityKind.STRONG_TRAINING_LABEL_PROVENANCE,
        "provenance_id",
        "label_id",
    ),
    M5TableSpec("training_labels", M5AuthorityKind.TRAINING_LABEL, "label_id", "label_id"),
    M5TableSpec(
        "m5_training_causal_events",
        M5AuthorityKind.TRAINING_CAUSAL_EVENT,
        "event_id",
        "sequence",
    ),
    M5TableSpec(
        "dataset_artifacts",
        M5AuthorityKind.DATASET_ARTIFACT,
        "dataset_id",
        "dataset_id",
    ),
    M5TableSpec(
        "dataset_registration_snapshots",
        M5AuthorityKind.DATASET_REGISTRATION_SNAPSHOT,
        "authority_id",
        "authority_id",
    ),
    M5TableSpec(
        "dataset_crop_snapshots",
        M5AuthorityKind.DATASET_CROP_SNAPSHOT,
        "authority_id",
        "authority_id",
    ),
)


# Fixed authority payload columns.  The read-only validator uses this allow-list
# for SQL-side byte preflight before any JSON document is returned to Python.
M5_AUTHORITY_DOCUMENT_COLUMNS: dict[str, tuple[str, ...]] = {
    "precedent_embeddings": ("embedding_json",),
    "precedents": ("authority_json",),
    "m5_precedent_exposures": ("exposure_json",),
    "m5_precedent_application_batches": ("application_batch_json",),
    "m5_precedent_causal_events": ("event_json",),
    "precedent_citations": ("commit_json", "citation_json"),
    "precedent_lifecycle_receipts": ("receipt_json", "context_json"),
    "precedent_conflict_batches": ("authority_json", "policy_json"),
    "precedent_conflict_batch_receipts": ("receipt_json",),
    "alerts": ("authority_json",),
    "alert_cooldowns": ("authority_json",),
    "alert_outbox": ("outbox_json",),
    "alert_channel_capabilities": ("authority_json",),
    "alert_dispatch_attempts": ("attempt_json",),
    "alert_dispatch_receipts": ("receipt_json",),
    "m5_immediate_safety_deliveries": ("authority_json",),
    "appeals": ("authority_json",),
    "appeal_resolution_receipts": ("intent_json",),
    "appeal_resolution_commit_receipts": ("receipt_json",),
    "verdict_rescissions": ("rescission_json",),
    "alert_rescissions": ("rescission_json",),
    "strong_training_label_provenance_receipts": ("provenance_json",),
    "training_labels": ("label_json",),
    "m5_training_causal_events": ("event_json",),
    "dataset_artifacts": ("report_json", "artifact_json"),
    "dataset_registration_snapshots": ("snapshot_json",),
    "dataset_crop_snapshots": ("authority_json",),
}

if set(M5_AUTHORITY_DOCUMENT_COLUMNS) != {spec.table for spec in M5_TABLE_SPECS}:
    raise RuntimeError("M5 authority byte-preflight columns are incomplete")


def load_m5_record(row: sqlite3.Row, spec: M5TableSpec, manifest_id: str) -> M5Record:
    artifact_id = _artifact_id(row, spec)
    try:
        document, projection, expected, hash_document = _decode(row, spec.table, manifest_id)
    except (KeyError, TypeError, ValueError, ValidationError, json.JSONDecodeError):
        raise M5DocumentFailure("CANONICAL_DOCUMENT_INVALID") from None
    for column, value in expected.items():
        if row[column] != value:
            raise M5IndexFailure()
    actual_sha256 = _text(row, "document_sha256")
    expected_sha256 = hashlib.sha256(hash_document.encode("utf-8")).hexdigest()
    if actual_sha256 != expected_sha256:
        raise M5IndexFailure("DOCUMENT_HASH_MISMATCH")
    return M5Record(
        kind=spec.kind,
        table=spec.table,
        artifact_id=artifact_id,
        row=row,
        document=document,
        canonical_document=canonical_json(projection),
    )


def _artifact_id(row: sqlite3.Row, spec: M5TableSpec) -> str:
    base = _text(row, spec.id_column)
    if spec.table in {"precedents", "alert_cooldowns"}:
        return f"{base}-revision-{int(row['revision']):06d}"
    if spec.table == "appeals":
        return f"{base}-version-{int(row['version']):06d}"
    return base


def _decode(
    row: sqlite3.Row,
    table: str,
    manifest_id: str,
) -> tuple[BaseModel | dict[str, object], object, dict[str, object], str]:
    run_id = _text(row, "run_id")
    if table == "precedent_embeddings":
        embedding, raw = _model(row, "embedding_json", M5EmbeddingVector)
        embedding_request = embedding.request
        expected: dict[str, object] = {
            "run_id": run_id,
            "embedding_id": embedding.embedding_id,
            "request_id": embedding_request.request_id,
            "channel": embedding_request.channel.value,
            "input_ref": embedding_request.input_ref,
            "input_sha256": embedding_request.input_sha256,
            "model_manifest_id": embedding_request.model_manifest_id,
            "dimensions": embedding_request.dimensions,
            "algorithm": embedding_request.algorithm,
            "manifest_id": manifest_id,
        }
        return embedding, embedding.model_dump(mode="json"), expected, raw
    if table == "precedents":
        authority, raw = _model(row, "authority_json", M5PrecedentAuthority)
        precedent = authority.precedent
        dump = authority.model_dump(mode="json")
        expected = {
            "run_id": authority.run_id,
            "precedent_id": precedent.precedent_id,
            "revision": authority.revision,
            "authority_id": authority.authority_id,
            "status": precedent.status.value,
            "source": precedent.source.value,
            "evidence_class": precedent.evidence_class.value,
            "violation_type": precedent.violation_type.value,
            "decision_direction": precedent.decision_direction.value,
            "rule_version": precedent.rule_version,
            "source_case_id": precedent.source_case_id,
            "citation_count": precedent.citation_count,
            "text_embedding_id": (
                authority.text_embedding.embedding_id
                if authority.text_embedding is not None
                else None
            ),
            "visual_embedding_ids_json": canonical_json(
                [item.embedding_id for item in authority.visual_embeddings]
            ),
            "created_at": dump["created_at"],
            "activation_not_before": dump["activation_not_before"],
            "activated_at": dump["activated_at"],
            "manifest_id": manifest_id,
        }
        return authority, dump, expected, raw
    if table == "m5_precedent_exposures":
        exposure, raw = _model(row, "exposure_json", M5PrecedentExposureBatchAuthority)
        m4 = exposure.m4_retrieval_outcome
        m5 = exposure.m5_retrieval_result
        expected = {
            "run_id": exposure.run_id,
            "exposure_id": exposure.exposure_id,
            "exposure_sha256": exposure.exposure_sha256,
            "case_id": exposure.case_id,
            "hearing_id": exposure.hearing_session_id,
            "cycle_index": exposure.cycle_index,
            "cycle_scope_id": exposure.cycle_scope_id,
            "cycle_scope_sha256": exposure.cycle_scope_sha256,
            "retrieval_receipt_id": m4.receipt.receipt_id,
            "m4_query_id": m4.query.query_id,
            "m5_query_id": m5.query.query_id,
            "m5_result_id": m5.result_id,
            "candidate_count": m5.candidate_count,
            "exposed_count": len(exposure.exposed_precedents),
            "policy_id": exposure.policy_id,
            "bridge_manifest_id": exposure.bridge_manifest_id,
            "manifest_id": exposure.manifest_id,
        }
        return exposure, exposure.model_dump(mode="json"), expected, raw
    if table == "m5_precedent_application_batches":
        application_batch, raw = _model(
            row,
            "application_batch_json",
            M5PrecedentApplicationBatchAuthority,
        )
        expected = {
            "run_id": application_batch.run_id,
            "application_batch_id": application_batch.application_batch_id,
            "application_batch_sha256": application_batch.application_batch_sha256,
            "case_id": application_batch.case_id,
            "ready_case_revision": application_batch.ready_case_revision,
            "closing_case_revision": application_batch.ready_case_revision + 1,
            "ready_case_document_sha256": application_batch.ready_case_document_sha256,
            "verdict_id": application_batch.verdict.verdict_id,
            "verdict_version": application_batch.verdict.version,
            "verdict_sha256": application_batch.verdict.verdict_sha256,
            "exposure_id": application_batch.exposure.exposure_id,
            "binding_count": len(application_batch.application_bindings),
            "config_sha256": application_batch.config_sha256,
            "manifest_id": application_batch.manifest_id,
        }
        return (
            application_batch,
            application_batch.model_dump(mode="json"),
            expected,
            raw,
        )
    if table == "precedent_citations":
        citation_kind = _text(row, "citation_kind")
        if citation_kind == "DIRECT":
            direct_commit, raw = _model(row, "commit_json", M5PrecedentCitationCommit)
            commit: M5PrecedentCitationCommit | M5PrecedentApplicationCitationCommit = direct_commit
            retrieval_result = direct_commit.retrieval_result
            application_batch_id = None
            application_binding_id = None
        elif citation_kind == "APPLIED":
            applied_commit, raw = _model(
                row,
                "commit_json",
                M5PrecedentApplicationCitationCommit,
            )
            commit = applied_commit
            retrieval_result = applied_commit.application_batch.exposure.m5_retrieval_result
            application_batch_id = applied_commit.application_batch.application_batch_id
            application_binding_id = applied_commit.application_binding.binding_id
        else:
            raise ValueError("unknown M5 citation discriminator")
        citation = commit.citation
        citation_raw = _canonical_secondary(row, "citation_json", citation)
        expected = {
            "run_id": citation.run_id,
            "citation_kind": citation_kind,
            "citation_id": citation.citation_id,
            "commit_id": commit.commit_id,
            "case_id": citation.case_id,
            "precedent_id": citation.precedent_id,
            "precedent_authority_id": citation.precedent_authority_id,
            "precedent_revision": citation.precedent_revision,
            "retrieval_result_id": retrieval_result.result_id,
            "application_batch_id": application_batch_id,
            "application_binding_id": application_binding_id,
            "query_id": citation.query_id,
            "score": citation.score,
            "cited_at": citation.model_dump(mode="json")["cited_at"],
            "manifest_id": manifest_id,
            "citation_json": citation_raw,
        }
        return commit, commit.model_dump(mode="json"), expected, raw
    if table == "m5_precedent_causal_events":
        event, raw = _model(row, "event_json", M5PrecedentCausalEvent)
        expected = {
            "run_id": event.run_id,
            "sequence": event.sequence,
            "event_id": event.event_id,
            "source_identity_sha256": event.source_identity_sha256,
            "event_kind": event.event_kind.value,
            "source_id": event.source_id,
            "precedent_id": event.precedent_id,
            "precedent_authority_id": event.precedent_authority_id,
            "precedent_revision": event.precedent_revision,
            "citation_kind": (
                event.citation_kind.value if event.citation_kind is not None else None
            ),
            "manifest_id": event.manifest_id,
            "source_document_sha256": event.source_document_sha256,
            "previous_event_sha256": event.previous_event_sha256,
            "event_sha256": event.event_sha256,
        }
        return event, event.model_dump(mode="json"), expected, raw
    if table == "precedent_lifecycle_receipts":
        kind = _text(row, "receipt_kind")
        receipt_type = cast(
            type[BaseModel],
            {
                "ACTIVATION": M5PrecedentActivationReceipt,
                "CONFLICT": M5PrecedentConflictReceipt,
                "REVOCATION": M5PrecedentRevocationReceipt,
            }[kind],
        )
        receipt_base, raw = _base_model(row, "receipt_json", receipt_type)
        receipt = cast(
            M5PrecedentActivationReceipt
            | M5PrecedentConflictReceipt
            | M5PrecedentRevocationReceipt,
            receipt_base,
        )
        context_type = cast(
            type[BaseModel],
            {
                "ACTIVATION": M5AppealWindowSnapshot,
                "CONFLICT": M5PrecedentPolicy,
                "REVOCATION": M5PrecedentCitationSnapshot,
            }[kind],
        )
        context, context_raw = _base_model(row, "context_json", context_type)
        expected = _lifecycle_expected(receipt, kind, manifest_id)
        expected["context_sha256"] = hashlib.sha256(context_raw.encode()).hexdigest()
        _require_lifecycle_context(receipt, context)
        projection = {
            "receipt": receipt.model_dump(mode="json"),
            "context": context.model_dump(mode="json"),
        }
        return receipt, projection, expected, raw
    if table == "precedent_conflict_batches":
        conflict_batch, raw = _model(
            row,
            "authority_json",
            M5PrecedentConflictBatchAuthority,
        )
        policy, policy_raw = _model(row, "policy_json", M5PrecedentPolicy)
        expected = {
            "run_id": conflict_batch.run_id,
            "batch_authority_id": conflict_batch.batch_authority_id,
            "policy_id": conflict_batch.policy_id,
            "config_sha256": conflict_batch.config_sha256,
            "causal_cut_id": conflict_batch.causal_cut.cut_id,
            "authority_event_sequence": conflict_batch.causal_cut.authority_event_sequence,
            "authority_event_sha256": conflict_batch.causal_cut.authority_event_sha256,
            "active_head_root_sha256": conflict_batch.causal_cut.active_head_root_sha256,
            "scan_limit": conflict_batch.scan_limit,
            "candidate_count": len(conflict_batch.candidates),
            "evaluated_pair_count": conflict_batch.evaluated_pair_count,
            "edge_count": len(conflict_batch.edges),
            "manifest_id": manifest_id,
            "policy_sha256": hashlib.sha256(policy_raw.encode()).hexdigest(),
        }
        if (
            policy.policy_id != conflict_batch.policy_id
            or policy.config_sha256 != conflict_batch.config_sha256
        ):
            raise ValueError("M5 conflict batch policy does not bind its authority")
        projection = {
            "authority": conflict_batch.model_dump(mode="json"),
            "policy": policy.model_dump(mode="json"),
        }
        return conflict_batch, projection, expected, raw
    if table == "precedent_conflict_batch_receipts":
        batch_receipt, raw = _model(row, "receipt_json", M5PrecedentConflictBatchReceipt)
        changed_count = sum(
            item.resulting_authority_id != item.prior_authority_id for item in batch_receipt.results
        )
        expected = {
            "run_id": batch_receipt.run_id,
            "receipt_id": batch_receipt.receipt_id,
            "batch_authority_id": batch_receipt.batch_authority_id,
            "causal_cut_id": batch_receipt.causal_cut_id,
            "result_count": len(batch_receipt.results),
            "changed_count": changed_count,
            "manifest_id": manifest_id,
        }
        return batch_receipt, batch_receipt.model_dump(mode="json"), expected, raw
    if table == "alerts":
        alert_authority, raw = _model(row, "authority_json", AlertPolicyAuthority)
        policy_request = alert_authority.request
        decision = alert_authority.decision
        expected = {
            "run_id": policy_request.run_id,
            "authority_id": alert_authority.authority_id,
            "case_id": policy_request.case_id,
            "policy_request_id": policy_request.request_id,
            "verdict_id": policy_request.verdict_id,
            "verdict_version": policy_request.verdict_version,
            "procedural_review_id": policy_request.procedural_review_id,
            "procedural_review_version": policy_request.procedural_review_version,
            "disposition": alert_authority.disposition.value,
            "alert_id": decision.alert_id if decision is not None else None,
            "final_decision": alert_authority.final_decision.value,
            "config_sha256": policy_request.config_sha256,
            "manifest_id": policy_request.manifest_id,
        }
        return alert_authority, alert_authority.model_dump(mode="json"), expected, raw
    if table == "alert_cooldowns":
        cooldown, raw = _model(row, "authority_json", AlertCooldownAuthority)
        expected = {
            "run_id": run_id,
            "key_id": cooldown.key.key_id,
            "authority_id": cooldown.authority_id,
            "zone_id": cooldown.key.zone_id,
            "violation_type": cooldown.key.violation_type.value,
            "track_ref": cooldown.key.track_ref,
            "tracker_epoch": cooldown.key.tracker_epoch,
            "stream_id": cooldown.stream_id,
            "source_alert_id": cooldown.source_alert_id,
            "source_trigger_frame": cooldown.source_trigger_frame,
            "cooldown_until_frame_exclusive": cooldown.cooldown_until_frame_exclusive,
            "manifest_id": manifest_id,
        }
        return cooldown, cooldown.model_dump(mode="json"), expected, raw
    if table == "alert_outbox":
        outbox, raw = _model(row, "outbox_json", AlertOutboxItem)
        expected = {
            "run_id": outbox.run_id,
            "outbox_id": outbox.outbox_id,
            "alert_id": outbox.alert.alert_id,
            "case_id": outbox.case_id,
            "case_authority_sha256": outbox.case_authority_sha256,
            "policy_request_id": outbox.policy_request_id,
            "priority": outbox.priority.value,
            "idempotency_key": outbox.idempotency_key,
            "manifest_id": outbox.manifest_id,
        }
        return outbox, outbox.model_dump(mode="json"), expected, raw
    if table == "alert_channel_capabilities":
        capability, raw = _model(
            row,
            "authority_json",
            AlertChannelCapabilityAuthority,
        )
        expected = {
            "run_id": capability.run_id,
            "capability_id": capability.capability_id,
            "channel": capability.channel,
            "capability_revision": capability.capability_revision,
            "idempotency_guarantee": capability.idempotency_guarantee.value,
            "provider_idempotency_key": capability.provider_idempotency_key,
            "manifest_id": capability.manifest_id,
            "config_sha256": capability.config_sha256,
        }
        return capability, capability.model_dump(mode="json"), expected, raw
    if table == "alert_dispatch_attempts":
        attempt, raw = _model(row, "attempt_json", AlertDispatchAttempt)
        expected = {
            "run_id": run_id,
            "attempt_id": attempt.attempt_id,
            "outbox_id": attempt.outbox_id,
            "alert_id": attempt.alert_id,
            "case_id": attempt.case_id,
            "attempt_number": attempt.attempt_number,
            "fence": attempt.fence,
            "lease_owner_sha256": attempt.lease_owner_sha256,
            "started_at": _utc_text(attempt.started_at),
            "lease_expires_at": _utc_text(attempt.lease_expires_at),
            "channel_capability_id": attempt.channel_capability.capability_id,
            "idempotency_key": attempt.idempotency_key,
        }
        return attempt, attempt.model_dump(mode="json"), expected, raw
    if table == "alert_dispatch_receipts":
        dispatch_receipt, raw = _model(row, "receipt_json", AlertDispatchReceipt)
        expected = {
            "run_id": run_id,
            "receipt_id": dispatch_receipt.receipt_id,
            "attempt_id": dispatch_receipt.attempt_id,
            "outbox_id": dispatch_receipt.outbox_id,
            "alert_id": dispatch_receipt.alert_id,
            "case_id": dispatch_receipt.case_id,
            "attempt_number": dispatch_receipt.attempt_number,
            "fence": dispatch_receipt.fence,
            "lease_owner_sha256": dispatch_receipt.lease_owner_sha256,
            "channel_capability_id": dispatch_receipt.channel_capability.capability_id,
            "idempotency_key": dispatch_receipt.idempotency_key,
            "disposition": dispatch_receipt.disposition.value,
            "continuation": dispatch_receipt.continuation.value,
        }
        return dispatch_receipt, dispatch_receipt.model_dump(mode="json"), expected, raw
    if table == "m5_immediate_safety_deliveries":
        immediate, raw = _model(row, "authority_json", ImmediateSafetyDeliveryAuthority)
        incident = immediate.incident
        delivery = immediate.delivery_receipt
        expected = {
            "run_id": run_id,
            "authority_id": immediate.authority_id,
            "incident_id": incident.incident_id,
            "signal_id": incident.signal_id,
            "zone_id": incident.zone_id,
            "delivery_idempotency_key": incident.delivery_idempotency_key,
            "delivery_alert_id": delivery.alert_id,
            "delivery_channel": delivery.channel,
            "provider_receipt_ref": delivery.provider_receipt_ref,
            "manifest_id": manifest_id,
        }
        return immediate, immediate.model_dump(mode="json"), expected, raw
    if table == "appeals":
        appeal, raw = _model(row, "authority_json", AppealVersionAuthority)
        expected = {
            "run_id": appeal.run_id,
            "appeal_id": appeal.appeal.appeal_id,
            "version": appeal.version,
            "authority_sha256": appeal.authority_sha256,
            "previous_authority_sha256": appeal.previous_authority_sha256,
            "case_id": appeal.appeal.case_id,
            "status": appeal.appeal.status.value,
            "assigned_reviewer_id": appeal.assigned_reviewer_id,
            "source_case_revision": appeal.source_case_revision,
            "source_case_authority_sha256": appeal.source_case_authority_sha256,
            "source_verdict_id": appeal.source_verdict_id,
            "source_verdict_version": appeal.source_verdict_version,
            "source_verdict_sha256": appeal.source_verdict_sha256,
            "source_decision": appeal.source_decision.value,
            "text_embedding_manifest_id": appeal.text_embedding_manifest_id,
            "visual_embedding_manifest_id": appeal.visual_embedding_manifest_id,
            "manifest_id": appeal.manifest_id,
            "rule_version": appeal.rule_version,
        }
        return appeal, appeal.model_dump(mode="json"), expected, raw
    if table == "appeal_resolution_receipts":
        intent, raw = _model(row, "intent_json", AppealResolutionSideEffectIntent)
        expected = {
            "run_id": intent.run_id,
            "intent_id": intent.intent_id,
            "appeal_id": intent.appeal_authority.appeal.appeal_id,
            "appeal_authority_sha256": intent.appeal_authority.authority_sha256,
            "case_id": intent.case_id,
            "final_decision": intent.final_decision.value,
            "final_decision_changed": int(intent.final_decision_changed),
            "affected_citation_report_sha256": intent.affected_citations.report_sha256,
            "manifest_id": intent.manifest_id,
        }
        return intent, intent.model_dump(mode="json"), expected, raw
    if table == "appeal_resolution_commit_receipts":
        commit_receipt, raw = _model(
            row,
            "receipt_json",
            M5AppealResolutionCommitReceipt,
        )
        expected = {
            "run_id": commit_receipt.run_id,
            "receipt_id": commit_receipt.receipt_id,
            "effect_root_sha256": commit_receipt.effect_root_sha256,
            "resolution_intent_id": commit_receipt.resolution_intent_id,
            "resolution_document_sha256": commit_receipt.resolution_document_sha256,
            "appeal_id": commit_receipt.appeal_id,
            "appeal_authority_sha256": commit_receipt.appeal_authority_sha256,
            "case_id": commit_receipt.case_id,
            "source_case_revision": commit_receipt.source_case_revision,
            "resulting_case_revision": commit_receipt.resulting_case_revision,
            "resulting_case_document_sha256": (commit_receipt.resulting_case_document_sha256),
            "verdict_rescission_ids_json": canonical_json(
                list(commit_receipt.verdict_rescission_ids)
            ),
            "alert_rescission_ids_json": canonical_json(list(commit_receipt.alert_rescission_ids)),
            "precedent_revocation_receipt_ids_json": canonical_json(
                list(commit_receipt.precedent_revocation_receipt_ids)
            ),
            "replacement_precedent_authority_id": (
                commit_receipt.replacement_precedent_authority_id
            ),
            "training_label_ids_json": canonical_json(list(commit_receipt.training_label_ids)),
            "affected_citation_report_sha256": (commit_receipt.affected_citation_report_sha256),
            "manifest_id": commit_receipt.manifest_id,
        }
        return commit_receipt, commit_receipt.model_dump(mode="json"), expected, raw
    if table in {"verdict_rescissions", "alert_rescissions"}:
        return _decode_rescission(row, table)
    if table == "strong_training_label_provenance_receipts":
        provenance, raw = _model(
            row,
            "provenance_json",
            M5StrongTrainingLabelProvenanceReceipt,
        )
        expected = {
            "run_id": provenance.run_id,
            "provenance_id": provenance.provenance_id,
            "case_id": provenance.case_id,
            "appeal_id": provenance.appeal_id,
            "label_id": provenance.label_id,
            "label_document_sha256": provenance.label_document_sha256,
            "crop_id": provenance.crop_id,
            "reviewer_id": provenance.reviewer_id,
            "quality": provenance.quality.value,
            "authored_input_id": provenance.authored_input.input_id,
            "review_authority_sha256": provenance.review_authority_sha256,
            "terminal_authority_sha256": provenance.terminal_authority_sha256,
            "terminal_status": provenance.terminal_status.value,
            "resolution_intent_id": provenance.resolution_intent_id,
            "resolution_document_sha256": provenance.resolution_document_sha256,
            "resolution_commit_receipt_id": provenance.resolution_commit_receipt_id,
            "resolution_commit_effect_root_sha256": (
                provenance.resolution_commit_effect_root_sha256
            ),
            "manifest_id": provenance.manifest_id,
            "rule_version": provenance.rule_version,
            "detector_manifest_id": provenance.detector_manifest_id,
        }
        return provenance, provenance.model_dump(mode="json"), expected, raw
    if table == "training_labels":
        label, raw = _model(row, "label_json", TrainingLabel)
        expected = {
            "run_id": run_id,
            "label_id": label.label_id,
            "case_id": label.case_id,
            "crop_id": label.crop_id,
            "quality": label.quality.value,
            "source": label.source,
            "reviewer_id": label.reviewer_id,
            "rule_version": label.rule_version,
            "detector_manifest_id": label.detector_manifest_id,
            "manifest_id": manifest_id,
        }
        return label, label.model_dump(mode="json"), expected, raw
    if table == "m5_training_causal_events":
        training_event, raw = _model(row, "event_json", M5TrainingCausalEvent)
        expected = {
            "run_id": training_event.run_id,
            "sequence": training_event.sequence,
            "event_id": training_event.event_id,
            "source_identity": training_event.source_identity,
            "event_kind": training_event.event_kind.value,
            "source_id": training_event.source_id,
            "source_document_sha256": training_event.source_document_sha256,
            "manifest_id": training_event.manifest_id,
            "previous_event_sha256": training_event.previous_event_sha256,
            "event_sha256": training_event.event_sha256,
            "label_id": training_event.label_id,
        }
        return training_event, training_event.model_dump(mode="json"), expected, raw
    if table == "dataset_artifacts":
        report, raw = _model(row, "report_json", DatasetExportReport)
        artifact_raw = _canonical_secondary(row, "artifact_json", report.dataset)
        expected = {
            "run_id": report.run_id,
            "dataset_id": report.dataset.dataset_id,
            "report_id": report.report_id,
            "command_id": report.command_id,
            "format": report.dataset.format.value,
            "relative_path": report.dataset.relative_path,
            "content_sha256": report.dataset.content_sha256,
            "content_size_bytes": report.content_size_bytes,
            "label_count": report.dataset.label_count,
            "minimum_quality": report.dataset.minimum_quality.value,
            "rule_version": report.rule_version,
            "detector_manifest_id": report.detector_manifest_id,
            "manifest_id": report.manifest_id,
            "artifact_json": artifact_raw,
        }
        return report, report.model_dump(mode="json"), expected, raw
    if table == "dataset_registration_snapshots":
        registration_snapshot, raw = _model(
            row,
            "snapshot_json",
            M5DatasetRegistrationSnapshotAuthority,
        )
        expected = {
            "run_id": registration_snapshot.run_id,
            "authority_id": registration_snapshot.authority_id,
            "dataset_id": registration_snapshot.dataset_id,
            "report_id": registration_snapshot.report_id,
            "command_id": registration_snapshot.command_id,
            "report_document_sha256": registration_snapshot.report_document_sha256,
            "causal_cut_sequence": registration_snapshot.causal_cut.sequence,
            "causal_cut_event_id": registration_snapshot.causal_cut.event_id,
            "causal_cut_event_sha256": registration_snapshot.causal_cut.event_sha256,
            "label_count": registration_snapshot.label_count,
            "label_inventory_root_sha256": registration_snapshot.label_inventory_root_sha256,
            "crop_count": registration_snapshot.crop_count,
            "crop_inventory_root_sha256": registration_snapshot.crop_inventory_root_sha256,
            "manifest_id": registration_snapshot.manifest_id,
            "rule_version": registration_snapshot.rule_version,
            "detector_manifest_id": registration_snapshot.detector_manifest_id,
        }
        return (
            registration_snapshot,
            registration_snapshot.model_dump(mode="json"),
            expected,
            raw,
        )
    if table == "dataset_crop_snapshots":
        crop_snapshot, raw = _model(
            row,
            "authority_json",
            M5DatasetCropSnapshotAuthority,
        )
        crop_authority = crop_snapshot.crop_authority
        expected = {
            "run_id": crop_snapshot.run_id,
            "authority_id": crop_snapshot.authority_id,
            "dataset_id": crop_snapshot.dataset_id,
            "report_id": crop_snapshot.report_id,
            "crop_id": crop_authority.crop.crop_id,
            "crop_authority_sha256": crop_authority.authority_sha256,
            "case_id": crop_authority.case_id,
            "case_revision": crop_snapshot.case_revision,
            "case_document_sha256": crop_snapshot.case_document_sha256,
            "evidence_pack_id": crop_snapshot.evidence_pack_id,
            "evidence_pack_version": crop_snapshot.evidence_pack_version,
            "evidence_pack_document_sha256": crop_snapshot.evidence_pack_document_sha256,
        }
        return crop_snapshot, crop_snapshot.model_dump(mode="json"), expected, raw
    raise KeyError(table)


def _decode_rescission(
    row: sqlite3.Row,
    table: str,
) -> tuple[dict[str, object], object, dict[str, object], str]:
    raw = _text(row, "rescission_json")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict) or set(parsed) != {
        "run_id",
        "resolution_intent_id",
        "case_id",
        "rescission",
    }:
        raise ValueError("invalid rescission envelope")
    if canonical_json(parsed) != raw:
        raise ValueError("non-canonical rescission envelope")
    intent_type = (
        VerdictRescissionIntent if table == "verdict_rescissions" else AlertRescissionIntent
    )
    rescission = intent_type.model_validate(parsed["rescission"])
    parsed["rescission"] = rescission.model_dump(mode="json")
    domain = "m5-verdict-rescission" if table == "verdict_rescissions" else "m5-alert-rescission"
    from labcourt.contracts.canonical import sha256_hex

    expected = {
        "run_id": parsed["run_id"],
        "rescission_id": sha256_hex([domain, 1, parsed]),
        "resolution_intent_id": parsed["resolution_intent_id"],
        "case_id": parsed["case_id"],
    }
    if isinstance(rescission, VerdictRescissionIntent):
        expected.update(
            {
                "verdict_id": rescission.verdict_id,
                "verdict_version": rescission.verdict_version,
                "verdict_sha256": rescission.verdict_sha256,
            }
        )
    else:
        expected["alert_id"] = rescission.alert_id
    return parsed, parsed, expected, raw


def _lifecycle_expected(
    receipt: M5PrecedentActivationReceipt
    | M5PrecedentConflictReceipt
    | M5PrecedentRevocationReceipt,
    kind: str,
    manifest_id: str,
) -> dict[str, object]:
    values: tuple[
        str,
        str,
        int,
        str,
        int,
        str | None,
        str | None,
        int | None,
        str | None,
        int | None,
    ]
    if isinstance(
        receipt,
        (M5PrecedentActivationReceipt, M5PrecedentRevocationReceipt),
    ):
        values = (
            receipt.precedent_id,
            receipt.prior_authority_id,
            receipt.prior_revision,
            receipt.resulting_authority_id,
            receipt.resulting_revision,
            None,
            None,
            None,
            None,
            None,
        )
    else:
        values = (
            receipt.existing_precedent_id,
            receipt.existing_prior_authority_id,
            receipt.existing_prior_revision,
            receipt.existing_resulting_authority_id,
            receipt.existing_resulting_revision,
            receipt.new_precedent_id,
            receipt.new_prior_authority_id,
            receipt.new_prior_revision,
            receipt.new_resulting_authority_id,
            receipt.new_resulting_revision,
        )
    return dict(
        zip(
            (
                "primary_precedent_id",
                "primary_prior_authority_id",
                "primary_prior_revision",
                "primary_resulting_authority_id",
                "primary_resulting_revision",
                "secondary_precedent_id",
                "secondary_prior_authority_id",
                "secondary_prior_revision",
                "secondary_resulting_authority_id",
                "secondary_resulting_revision",
            ),
            values,
            strict=True,
        ),
        run_id=receipt.run_id,
        receipt_id=receipt.receipt_id,
        receipt_kind=kind,
        outcome=receipt.outcome.value,
        manifest_id=manifest_id,
    )


def _require_lifecycle_context(receipt: BaseModel, context: BaseModel) -> None:
    valid = (
        (
            isinstance(receipt, M5PrecedentActivationReceipt)
            and isinstance(context, M5AppealWindowSnapshot)
            and receipt.appeal_snapshot_id == context.snapshot_id
        )
        or (
            isinstance(receipt, M5PrecedentConflictReceipt)
            and isinstance(context, M5PrecedentPolicy)
            and receipt.policy_id == context.policy_id
        )
        or (
            isinstance(receipt, M5PrecedentRevocationReceipt)
            and isinstance(context, M5PrecedentCitationSnapshot)
            and receipt.citation_snapshot_id == context.snapshot_id
        )
    )
    if not valid:
        raise ValueError("lifecycle context binding mismatch")


ModelT = TypeVar("ModelT", bound=BaseModel)


def _model(
    row: sqlite3.Row,
    json_column: str,
    model_type: type[ModelT],
) -> tuple[ModelT, str]:
    raw = _text(row, json_column)
    model = model_type.model_validate_json(raw)
    if canonical_json(model.model_dump(mode="json")) != raw:
        raise ValueError("non-canonical document")
    return model, raw


def _base_model(
    row: sqlite3.Row,
    json_column: str,
    model_type: type[BaseModel],
) -> tuple[BaseModel, str]:
    raw = _text(row, json_column)
    model = model_type.model_validate_json(raw)
    if canonical_json(model.model_dump(mode="json")) != raw:
        raise ValueError("non-canonical document")
    return model, raw


def _canonical_secondary(row: sqlite3.Row, column: str, model: BaseModel) -> str:
    raw = _text(row, column)
    if canonical_json(model.model_dump(mode="json")) != raw:
        raise ValueError("secondary canonical document mismatch")
    return raw


def _text(row: sqlite3.Row, key: str) -> str:
    value = row[key]
    if not isinstance(value, str):
        raise TypeError(key)
    return value


__all__ = [
    "M5_AUTHORITY_DOCUMENT_COLUMNS",
    "M5_TABLE_SPECS",
    "M5DocumentFailure",
    "M5IndexFailure",
    "M5Record",
    "M5TableSpec",
    "load_m5_record",
]

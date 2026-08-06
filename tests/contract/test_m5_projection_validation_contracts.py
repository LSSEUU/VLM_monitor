from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from labcourt.contracts.artifact_validation import (
    ArtifactValidationArea,
    ArtifactValidationIssue,
    ArtifactValidationIssueCode,
    ArtifactValidationReport,
    M3ArtifactValidationReport,
)
from labcourt.contracts.m5_artifact_validation import (
    M5AlertAuthorityReasonCode,
    M5AppealResolutionHistoryReasonCode,
    M5ArtifactValidationArea,
    M5ArtifactValidationBudget,
    M5ArtifactValidationCounts,
    M5ArtifactValidationInventoryCount,
    M5ArtifactValidationIssue,
    M5ArtifactValidationIssueCode,
    M5ArtifactValidationProjectionCount,
    M5ArtifactValidationReport,
    M5PrecedentCausalLedgerReasonCode,
    M5PrecedentRevocationHistoryReasonCode,
    M5TrainingHistoryReasonCode,
    M5TrainingLabelProvenanceReasonCode,
)
from labcourt.contracts.m5_projection import (
    M5AuthorityKind,
    M5ProjectionCurrentPointer,
    M5ProjectionFileKind,
    M5ProjectionGenerationEntry,
    M5ProjectionGenerationManifest,
    M5ProjectionRecordReceipt,
    m5_projection_relative_path,
)

RUN_ID = "m5-projection-contract"


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _entries() -> tuple[M5ProjectionGenerationEntry, ...]:
    groups = {
        M5ProjectionFileKind.ALERTS: (
            M5AuthorityKind.ALERT,
            M5AuthorityKind.ALERT_CHANNEL_CAPABILITY,
            M5AuthorityKind.ALERT_COOLDOWN,
            M5AuthorityKind.ALERT_DISPATCH_ATTEMPT,
            M5AuthorityKind.ALERT_DISPATCH_RECEIPT,
            M5AuthorityKind.ALERT_OUTBOX,
            M5AuthorityKind.IMMEDIATE_SAFETY_DELIVERY,
        ),
        M5ProjectionFileKind.PRECEDENTS: (
            M5AuthorityKind.PRECEDENT,
            M5AuthorityKind.PRECEDENT_APPLICATION_BATCH,
            M5AuthorityKind.PRECEDENT_CAUSAL_EVENT,
            M5AuthorityKind.PRECEDENT_CITATION,
            M5AuthorityKind.PRECEDENT_CONFLICT_BATCH,
            M5AuthorityKind.PRECEDENT_CONFLICT_BATCH_RECEIPT,
            M5AuthorityKind.PRECEDENT_EMBEDDING,
            M5AuthorityKind.PRECEDENT_EXPOSURE,
            M5AuthorityKind.PRECEDENT_LIFECYCLE,
        ),
        M5ProjectionFileKind.APPEALS: (
            M5AuthorityKind.ALERT_RESCISSION,
            M5AuthorityKind.APPEAL,
            M5AuthorityKind.APPEAL_RESOLUTION,
            M5AuthorityKind.APPEAL_RESOLUTION_COMMIT,
            M5AuthorityKind.VERDICT_RESCISSION,
        ),
        M5ProjectionFileKind.TRAIN_BUFFER: (
            M5AuthorityKind.DATASET_ARTIFACT,
            M5AuthorityKind.DATASET_CROP_SNAPSHOT,
            M5AuthorityKind.DATASET_REGISTRATION_SNAPSHOT,
            M5AuthorityKind.STRONG_TRAINING_LABEL_PROVENANCE,
            M5AuthorityKind.TRAINING_CAUSAL_EVENT,
            M5AuthorityKind.TRAINING_LABEL,
        ),
    }
    return tuple(
        sorted(
            (
                M5ProjectionGenerationEntry(
                    file_kind=file_kind,
                    relative_path=m5_projection_relative_path(file_kind),
                    sha256=_sha(file_kind.value),
                    size_bytes=10,
                    record_count=1,
                    authority_kinds=tuple(sorted(kinds, key=lambda item: item.value)),
                    records=(
                        M5ProjectionRecordReceipt(
                            authority_kind=sorted(kinds, key=lambda item: item.value)[0],
                            artifact_id=_sha(file_kind.value),
                            sha256=_sha(f"record-{file_kind.value}"),
                        ),
                    ),
                )
                for file_kind, kinds in groups.items()
            ),
            key=lambda item: item.sort_key,
        )
    )


def test_m5_generation_and_pointer_bind_complete_named_projection() -> None:
    manifest = M5ProjectionGenerationManifest(
        run_id=RUN_ID,
        authority_root_sha256=_sha("authority"),
        authority_record_count=4,
        case_root_count=2,
        entries=_entries(),
    )
    manifest_sha = _sha(manifest.model_dump_json())
    pointer = M5ProjectionCurrentPointer(
        run_id=RUN_ID,
        authority_root_sha256=manifest.authority_root_sha256,
        generation_id=manifest.generation_id,
        manifest_relative_path=(
            f"{RUN_ID}/m5-projections/generations/{manifest.generation_id}/"
            f"manifest-{manifest_sha}.json"
        ),
        manifest_sha256=manifest_sha,
        manifest_size_bytes=100,
    )

    assert {entry.relative_path for entry in manifest.entries} == {
        "alerts.jsonl",
        "precedents.jsonl",
        "appeals.jsonl",
        "train_buffer.jsonl",
    }
    assert M5ProjectionCurrentPointer.model_validate_json(pointer.model_dump_json()) == pointer


def test_m5_generation_rejects_missing_file_or_wrong_authority_partition() -> None:
    entries = _entries()
    with pytest.raises(ValidationError, match="complete ordered inventory"):
        M5ProjectionGenerationManifest(
            run_id=RUN_ID,
            authority_root_sha256=_sha("authority"),
            authority_record_count=3,
            case_root_count=0,
            entries=entries[:-1],
        )
    payload = entries[0].model_dump()
    payload["authority_kinds"] = tuple(
        sorted((*payload["authority_kinds"], M5AuthorityKind.APPEAL), key=lambda item: item.value)
    )
    with pytest.raises(ValidationError, match="conflict with file kind"):
        M5ProjectionGenerationEntry.model_validate(payload)


def test_m5_validation_report_has_complete_count_and_derived_pass_contract() -> None:
    inventories = tuple(
        M5ArtifactValidationInventoryCount(authority_kind=kind, authoritative_count=0)
        for kind in sorted(M5AuthorityKind, key=lambda item: item.value)
    )
    projections = tuple(
        M5ArtifactValidationProjectionCount(file_kind=kind, record_count=0)
        for kind in sorted(M5ProjectionFileKind, key=lambda item: item.value)
    )
    report = M5ArtifactValidationReport(
        run_id=RUN_ID,
        manifest_id=_sha("manifest"),
        config_sha256=_sha("config"),
        authority_root_sha256=_sha("authority"),
        counts=M5ArtifactValidationCounts(
            authority_bytes=0,
            projection_files=4,
            inventories=inventories,
            projections=projections,
        ),
    )
    assert report.passed is True
    assert report.scope.canonical_run_manifest is True
    assert report.scope.config_manifest_binding is True
    assert report.scope.sql_authority_budget_preflight is True
    assert report.scope.streaming_limit_plus_one is True
    assert report.scope.automatic_activation_case_cut_replay is True
    assert report.scope.precedent_causal_ledger_bijection is True
    payload = report.model_dump(mode="json")
    payload["passed"] = False
    with pytest.raises(ValidationError, match="passed conflicts"):
        M5ArtifactValidationReport.model_validate(payload)


def test_m5_report_gates_an_embedded_predecessor_and_budgets_total_authority_bytes() -> None:
    m2_report = ArtifactValidationReport(
        run_id=RUN_ID,
        issues=(
            ArtifactValidationIssue(
                code=ArtifactValidationIssueCode.DOCUMENT_BYTES_BUDGET_EXCEEDED,
                area=ArtifactValidationArea.BUDGET,
                limit=1,
                observed=2,
                reason_code="PREFLIGHT_LIMIT",
            ),
        ),
    )
    report = M5ArtifactValidationReport(
        run_id=RUN_ID,
        manifest_id=_sha("manifest"),
        config_sha256=_sha("config"),
        predecessor_report=M3ArtifactValidationReport(run_id=RUN_ID, m2_report=m2_report),
        authority_root_sha256=_sha("authority"),
    )

    assert report.issues == ()
    assert report.passed is False
    assert M5ArtifactValidationBudget().max_authority_total_bytes == 1024**3
    assert M5ArtifactValidationBudget().max_dataset_file_bytes == 64 * 1024**2
    assert report.scope.deterministic_dataset_rebuild is True
    assert report.scope.dataset_retention_closure is True
    assert report.scope.dataset_mutation is False


def test_m5_validation_issue_requires_typed_context_and_real_content_mismatch() -> None:
    with pytest.raises(ValidationError, match="typed record identity"):
        M5ArtifactValidationIssue(
            code=M5ArtifactValidationIssueCode.AUTHORITY_REFERENCE_INVALID,
            area=M5ArtifactValidationArea.AUTHORITY,
            reason_code="REFERENCE_MISSING",
        )
    with pytest.raises(ValidationError, match="real mismatch"):
        M5ArtifactValidationIssue(
            code=M5ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
            area=M5ArtifactValidationArea.PROJECTION,
            source_token=_sha("source"),
            reason_code="CONTENT_CHANGED",
            expected_sha256=_sha("same"),
            actual_sha256=_sha("same"),
        )


def test_alert_replay_issue_and_reason_codes_are_typed_and_stable() -> None:
    policy = M5ArtifactValidationIssue(
        code=M5ArtifactValidationIssueCode.ALERT_POLICY_REPLAY_INVALID,
        area=M5ArtifactValidationArea.AUTHORITY,
        authority_kind=M5AuthorityKind.ALERT,
        record_identity_sha256=_sha("alert-policy-row"),
        reason_code=M5AlertAuthorityReasonCode.ALERT_POLICY_REPLAY_MISMATCH,
    )
    automatic = M5ArtifactValidationIssue(
        code=M5ArtifactValidationIssueCode.ALERT_AUTOMATIC_PRECEDENT_INVALID,
        area=M5ArtifactValidationArea.AUTHORITY,
        authority_kind=M5AuthorityKind.PRECEDENT,
        record_identity_sha256=_sha("automatic-precedent-row"),
        reason_code=(
            M5AlertAuthorityReasonCode.ALERT_AUTOMATIC_PRECEDENT_EMBEDDING_CLOSURE_INVALID
        ),
    )
    causal = policy.model_copy(
        update={
            "reason_code": (M5AlertAuthorityReasonCode.ALERT_PRIOR_COOLDOWN_CAUSAL_HEAD_MISMATCH)
        }
    )

    assert policy.reason_code == "ALERT_POLICY_REPLAY_MISMATCH"
    assert automatic.reason_code == ("ALERT_AUTOMATIC_PRECEDENT_EMBEDDING_CLOSURE_INVALID")
    assert policy.sort_key != causal.sort_key
    assert tuple(reason.value for reason in M5AlertAuthorityReasonCode) == (
        "ALERT_POLICY_INPUT_ROOT_INVALID",
        "ALERT_PRIOR_COOLDOWN_CAUSAL_HEAD_MISMATCH",
        "ALERT_COOLDOWN_WRITE_CAUSAL_CLOSURE_INVALID",
        "ALERT_POLICY_REPLAY_MISMATCH",
        "ALERT_AUTOMATIC_PRECEDENT_MISSING",
        "ALERT_AUTOMATIC_PRECEDENT_DUPLICATE",
        "ALERT_AUTOMATIC_PRECEDENT_ORPHAN",
        "ALERT_AUTOMATIC_PRECEDENT_REPLAY_MISMATCH",
        "ALERT_AUTOMATIC_PRECEDENT_EMBEDDING_CLOSURE_INVALID",
        "ALERT_AUTOMATIC_PRECEDENT_TIME_INVALID",
    )


def test_precedent_causal_ledger_reason_codes_are_typed_and_stable() -> None:
    issue = M5ArtifactValidationIssue(
        code=M5ArtifactValidationIssueCode.PRECEDENT_CAUSAL_LEDGER_INVALID,
        area=M5ArtifactValidationArea.AUTHORITY,
        authority_kind=M5AuthorityKind.PRECEDENT_CAUSAL_EVENT,
        record_identity_sha256=_sha("causal-event-row"),
        reason_code=M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_EVENT_CHAIN_INVALID,
    )

    assert issue.reason_code == "PRECEDENT_CAUSAL_EVENT_CHAIN_INVALID"
    assert tuple(reason.value for reason in M5PrecedentCausalLedgerReasonCode) == (
        "PRECEDENT_CAUSAL_SOURCE_DUPLICATE",
        "PRECEDENT_CAUSAL_EVENT_MISSING",
        "PRECEDENT_CAUSAL_EVENT_DUPLICATE",
        "PRECEDENT_CAUSAL_EVENT_ORPHAN",
        "PRECEDENT_CAUSAL_EVENT_SOURCE_MISMATCH",
        "PRECEDENT_CAUSAL_EVENT_CHAIN_INVALID",
    )
    assert tuple(reason.value for reason in M5PrecedentRevocationHistoryReasonCode) == (
        "REVOCATION_CAUSAL_INTERVAL_INVALID",
        "REVOCATION_CITATION_SNAPSHOT_MISMATCH",
        "REVOCATION_MARKER_MISSING_OR_INVALID",
        "REVOCATION_RECEIPT_CLOSURE_INVALID",
    )
    assert tuple(reason.value for reason in M5AppealResolutionHistoryReasonCode) == (
        "APPEAL_RESOLUTION_EFFECT_ROOT_MISMATCH",
        "APPEAL_RESOLUTION_CAUSAL_INTERVAL_INVALID",
        "APPEAL_RESOLUTION_MARKER_MISSING_OR_INVALID",
        "APPEAL_RESOLUTION_RECEIPT_CLOSURE_INVALID",
    )


def test_training_label_provenance_reason_codes_are_typed_and_stable() -> None:
    assert tuple(reason.value for reason in M5TrainingLabelProvenanceReasonCode) == (
        "TRAINING_LABEL_PROVENANCE_MISSING",
        "TRAINING_LABEL_PROVENANCE_DUPLICATE",
        "TRAINING_LABEL_PROVENANCE_ORPHAN",
        "TRAINING_LABEL_WEAK_PROVENANCE_FORBIDDEN",
        "TRAINING_LABEL_AUTHORITY_INVALID",
        "TRAINING_LABEL_REVIEW_AUTHORITY_INVALID",
        "TRAINING_LABEL_TERMINAL_AUTHORITY_INVALID",
        "TRAINING_LABEL_RESOLUTION_INTENT_INVALID",
        "TRAINING_LABEL_RESOLUTION_COMMIT_INVALID",
        "TRAINING_LABEL_RESOLUTION_MARKER_INVALID",
        "DATASET_LABEL_PROVENANCE_INVALID",
    )


def test_training_history_authorities_and_reason_codes_are_typed_and_stable() -> None:
    train_buffer = next(
        entry for entry in _entries() if entry.file_kind is M5ProjectionFileKind.TRAIN_BUFFER
    )
    assert {
        M5AuthorityKind.TRAINING_CAUSAL_EVENT,
        M5AuthorityKind.DATASET_REGISTRATION_SNAPSHOT,
        M5AuthorityKind.DATASET_CROP_SNAPSHOT,
    }.issubset(train_buffer.authority_kinds)

    causal_issue = M5ArtifactValidationIssue(
        code=M5ArtifactValidationIssueCode.TRAINING_CAUSAL_LEDGER_INVALID,
        area=M5ArtifactValidationArea.AUTHORITY,
        authority_kind=M5AuthorityKind.TRAINING_CAUSAL_EVENT,
        record_identity_sha256=_sha("training-causal-event-row"),
        reason_code=M5TrainingHistoryReasonCode.TRAINING_CAUSAL_EVENT_CHAIN_INVALID,
    )
    snapshot_issue = M5ArtifactValidationIssue(
        code=M5ArtifactValidationIssueCode.DATASET_SNAPSHOT_CLOSURE_INVALID,
        area=M5ArtifactValidationArea.AUTHORITY,
        authority_kind=M5AuthorityKind.DATASET_REGISTRATION_SNAPSHOT,
        record_identity_sha256=_sha("dataset-registration-snapshot-row"),
        reason_code=M5TrainingHistoryReasonCode.DATASET_CAUSAL_CUT_INVALID,
    )

    assert causal_issue.reason_code == "TRAINING_CAUSAL_EVENT_CHAIN_INVALID"
    assert snapshot_issue.reason_code == "DATASET_CAUSAL_CUT_INVALID"
    assert tuple(reason.value for reason in M5TrainingHistoryReasonCode) == (
        "TRAINING_CAUSAL_EVENT_MISSING",
        "TRAINING_CAUSAL_EVENT_DUPLICATE",
        "TRAINING_CAUSAL_EVENT_ORPHAN",
        "TRAINING_CAUSAL_EVENT_SOURCE_MISMATCH",
        "TRAINING_CAUSAL_EVENT_CHAIN_INVALID",
        "DATASET_REGISTRATION_SNAPSHOT_MISSING",
        "DATASET_REGISTRATION_SNAPSHOT_DUPLICATE",
        "DATASET_REGISTRATION_MARKER_MISSING_OR_INVALID",
        "DATASET_CAUSAL_CUT_INVALID",
        "DATASET_LABEL_CUT_ACCOUNTING_INVALID",
        "DATASET_LABEL_AUTHORITY_MISMATCH",
        "DATASET_LABEL_INVENTORY_ROOT_MISMATCH",
        "DATASET_CROP_SNAPSHOT_MISSING",
        "DATASET_CROP_SNAPSHOT_EXTRA",
        "DATASET_CROP_SNAPSHOT_DUPLICATE",
        "DATASET_CROP_SNAPSHOT_ROOT_MISMATCH",
        "DATASET_HISTORICAL_CASE_MISSING",
        "DATASET_HISTORICAL_CASE_DOCUMENT_MISMATCH",
        "DATASET_HISTORICAL_PACK_INVALID",
        "DATASET_HISTORICAL_CROP_INVALID",
    )


def test_m5_dataset_and_retention_issues_require_non_path_typed_identities() -> None:
    dataset_id = _sha("dataset")
    hold_id = _sha("hold")

    dataset_issue = M5ArtifactValidationIssue(
        code=M5ArtifactValidationIssueCode.DATASET_REPORT_REBUILD_MISMATCH,
        area=M5ArtifactValidationArea.DATASET,
        dataset_id=dataset_id,
        reason_code="REPORT_REBUILD_MISMATCH",
    )
    retention_issue = M5ArtifactValidationIssue(
        code=M5ArtifactValidationIssueCode.DATASET_RETENTION_HOLD_MISSING,
        area=M5ArtifactValidationArea.RETENTION,
        dataset_id=dataset_id,
        hold_identity_sha256=hold_id,
        reason_code="EXPECTED_HOLD_MISSING",
    )

    assert dataset_issue.dataset_id == dataset_id
    assert retention_issue.hold_identity_sha256 == hold_id
    with pytest.raises(ValidationError, match="dataset or opaque source identity"):
        M5ArtifactValidationIssue(
            code=M5ArtifactValidationIssueCode.DATASET_UNREGISTERED_FILE,
            area=M5ArtifactValidationArea.DATASET,
            reason_code="UNREGISTERED_DATASET_FILE",
        )
    with pytest.raises(ValidationError, match="typed hold identity"):
        M5ArtifactValidationIssue(
            code=M5ArtifactValidationIssueCode.ORPHAN_DATASET_RETENTION_HOLD,
            area=M5ArtifactValidationArea.RETENTION,
            reason_code="OWNER_NOT_REGISTERED",
        )

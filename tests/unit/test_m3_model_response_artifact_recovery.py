from __future__ import annotations

from datetime import UTC, datetime

import pytest

from labcourt.application.model_response_artifacts import (
    ModelResponseArtifactRecoveryCoordinator,
    ModelResponseArtifactRecoveryResult,
)
from labcourt.contracts.model_response_recovery import (
    MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
    ModelResponseRecoveryArea,
    ModelResponseRecoveryDisposition,
    ModelResponseRecoveryItem,
    ModelResponseRecoveryReason,
)
from labcourt.contracts.recovery import recovery_source_token
from labcourt.exceptions import ContractViolation
from labcourt.ports.model_response_artifacts import (
    ModelResponseArtifactCandidate,
    ModelResponseArtifactScan,
    ModelResponseEmptyOperationCandidate,
)

RUN_ID = "run-model-artifacts-01"
CUTOFF = datetime(2026, 7, 28, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _source(area: ModelResponseRecoveryArea, authority: str) -> str:
    if area == ModelResponseRecoveryArea.STAGED_RESPONSE:
        return f".staging/{RUN_ID}/model-response-{authority}/response.json"
    if area == ModelResponseRecoveryArea.FINAL_RESPONSE:
        return f"{RUN_ID}/model_responses/{authority}.json"
    if area == ModelResponseRecoveryArea.JOURNAL:
        return f".staging/{RUN_ID}/model-request-{authority}/receipt.json"
    raise AssertionError("test requires an artifact area")


def _candidate(
    area: ModelResponseRecoveryArea,
    authority: str,
    content: str,
) -> ModelResponseArtifactCandidate:
    return ModelResponseArtifactCandidate(
        run_id=RUN_ID,
        area=area,
        authority_id=authority,
        source_token=recovery_source_token(_source(area, authority)),
        content_sha256=content,
        size_bytes=1,
    )


def _cleanup_candidate(
    area: ModelResponseRecoveryArea,
    authority: str,
) -> ModelResponseEmptyOperationCandidate:
    source = {
        ModelResponseRecoveryArea.STAGED_RESPONSE: (
            f".staging/{RUN_ID}/model-response-{authority}"
        ),
        ModelResponseRecoveryArea.JOURNAL: (f".staging/{RUN_ID}/model-request-{authority}"),
    }[area]
    return ModelResponseEmptyOperationCandidate(
        run_id=RUN_ID,
        area=area,
        authority_id=authority,
        source_token=recovery_source_token(source),
    )


def _quarantined(candidate: ModelResponseArtifactCandidate) -> ModelResponseRecoveryItem:
    area_name, reason = {
        ModelResponseRecoveryArea.STAGED_RESPONSE: (
            "staging",
            ModelResponseRecoveryReason.ORPHAN_STAGE_QUARANTINED,
        ),
        ModelResponseRecoveryArea.FINAL_RESPONSE: (
            "final",
            ModelResponseRecoveryReason.ORPHAN_FINAL_QUARANTINED,
        ),
        ModelResponseRecoveryArea.JOURNAL: (
            "journal",
            ModelResponseRecoveryReason.ORPHAN_JOURNAL_QUARANTINED,
        ),
    }[candidate.area]
    return ModelResponseRecoveryItem(
        run_id=RUN_ID,
        area=candidate.area,
        source_token=candidate.source_token,
        content_sha256=candidate.content_sha256,
        quarantine_relative_path=(
            f".quarantine/{RUN_ID}/model_responses/{area_name}/"
            f"{candidate.authority_id}-{candidate.content_sha256}.json"
        ),
        disposition=ModelResponseRecoveryDisposition.QUARANTINED,
        reason_code=reason,
    )


def _anomaly(
    area: ModelResponseRecoveryArea,
    source_token: str = SHA_D,
) -> ModelResponseRecoveryItem:
    return ModelResponseRecoveryItem(
        run_id=RUN_ID,
        area=area,
        source_token=source_token,
        disposition=ModelResponseRecoveryDisposition.ANOMALY,
        reason_code=ModelResponseRecoveryReason.UNKNOWN_ENTRY_SHAPE,
    )


class _Repository:
    def __init__(
        self,
        referenced: set[str] | None = None,
        *,
        fail_on_call: int | None = None,
    ) -> None:
        self.referenced = referenced or set()
        self.fail_on_call = fail_on_call
        self.calls: list[tuple[str, str, str]] = []

    def model_response_is_referenced(
        self,
        run_id: str,
        response_id: str,
        content_sha256: str,
    ) -> bool:
        self.calls.append((run_id, response_id, content_sha256))
        if self.fail_on_call == len(self.calls):
            raise ContractViolation("simulated database integrity failure")
        return response_id in self.referenced


class _FileOps:
    def __init__(
        self,
        scan: ModelResponseArtifactScan,
        outcomes: dict[str, ModelResponseRecoveryItem] | None = None,
    ) -> None:
        self.scan = scan
        self.outcomes = outcomes or {}
        self.discover_calls = 0
        self.quarantine_calls: list[str] = []
        self.cleanup_calls: list[str] = []

    def discover_model_response_artifacts(
        self,
        run_id: str,
        max_items: int,
        max_name_bytes: int,
        max_file_bytes: int,
        max_total_bytes: int,
    ) -> ModelResponseArtifactScan:
        del run_id, max_items, max_name_bytes, max_file_bytes, max_total_bytes
        self.discover_calls += 1
        return self.scan

    def quarantine_model_response_artifact(
        self,
        candidate: ModelResponseArtifactCandidate,
        not_modified_after: datetime,
        max_file_bytes: int,
    ) -> ModelResponseRecoveryItem:
        del not_modified_after, max_file_bytes
        self.quarantine_calls.append(candidate.source_token)
        return self.outcomes.get(candidate.source_token, _quarantined(candidate))

    def cleanup_empty_model_response_operation(
        self,
        candidate: ModelResponseEmptyOperationCandidate,
        not_modified_after: datetime,
    ) -> ModelResponseRecoveryItem:
        del not_modified_after
        self.cleanup_calls.append(candidate.source_token)
        return self.outcomes.get(
            candidate.source_token,
            ModelResponseRecoveryItem(
                run_id=candidate.run_id,
                area=candidate.area,
                source_token=candidate.source_token,
                disposition=ModelResponseRecoveryDisposition.CLEANED,
                reason_code=ModelResponseRecoveryReason.EMPTY_OPERATION_CLEANED,
            ),
        )


def _scan(
    candidates: tuple[ModelResponseArtifactCandidate, ...] = (),
    anomalies: tuple[ModelResponseRecoveryItem, ...] = (),
    cleanup_candidates: tuple[ModelResponseEmptyOperationCandidate, ...] = (),
    *,
    complete: bool = True,
    max_items: int | None = None,
) -> ModelResponseArtifactScan:
    stable_candidates = tuple(sorted(candidates, key=lambda item: item.sort_key))
    stable_anomalies = tuple(sorted(anomalies, key=lambda item: item.sort_key))
    stable_cleanup = tuple(sorted(cleanup_candidates, key=lambda item: item.sort_key))
    effective_max_items = max_items or max(
        1,
        len(candidates) + len(cleanup_candidates) + len(anomalies),
    )
    return ModelResponseArtifactScan(
        run_id=RUN_ID,
        max_items=effective_max_items,
        max_file_bytes=MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
        max_total_bytes=effective_max_items * MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
        bytes_scanned=sum(candidate.size_bytes for candidate in stable_candidates),
        candidates=stable_candidates,
        anomalies=stable_anomalies,
        complete=complete,
        cleanup_candidates=stable_cleanup,
    )


def test_complete_clean_scan_retains_referenced_final_and_quarantines_orphans() -> None:
    final = _candidate(ModelResponseRecoveryArea.FINAL_RESPONSE, SHA_A, SHA_C)
    staged = _candidate(ModelResponseRecoveryArea.STAGED_RESPONSE, SHA_B, SHA_D)
    scan = _scan((staged, final))
    repository = _Repository({SHA_A})
    file_ops = _FileOps(scan)

    result = ModelResponseArtifactRecoveryCoordinator(
        repository,
        file_ops,
        max_items=2,
    ).recover(RUN_ID, CUTOFF)

    assert result.scan_complete is True
    assert result.artifacts_scanned == 2
    assert result.has_anomaly is False
    by_source = {item.source_token: item for item in result.items}
    assert (
        by_source[final.source_token].reason_code
        == ModelResponseRecoveryReason.DATABASE_REFERENCED_ARTIFACT
    )
    assert (
        by_source[staged.source_token].reason_code
        == ModelResponseRecoveryReason.ORPHAN_STAGE_QUARANTINED
    )
    assert file_ops.quarantine_calls == [staged.source_token]


def test_incomplete_scan_performs_no_reference_query_or_mutation() -> None:
    final = _candidate(ModelResponseRecoveryArea.FINAL_RESPONSE, SHA_A, SHA_C)
    staged = _candidate(ModelResponseRecoveryArea.STAGED_RESPONSE, SHA_B, SHA_D)
    scan = _scan((final, staged), complete=False, max_items=2)
    repository = _Repository({SHA_A})
    file_ops = _FileOps(scan)

    result = ModelResponseArtifactRecoveryCoordinator(
        repository,
        file_ops,
        max_items=2,
    ).recover(RUN_ID, CUTOFF)

    assert result.scan_complete is False
    assert repository.calls == []
    assert file_ops.quarantine_calls == []
    assert file_ops.cleanup_calls == []
    assert {item.reason_code for item in result.items} == {
        ModelResponseRecoveryReason.ARTIFACT_SCAN_INCOMPLETE
    }


def test_scan_anomaly_suppresses_every_candidate_without_database_queries() -> None:
    final = _candidate(ModelResponseRecoveryArea.FINAL_RESPONSE, SHA_A, SHA_C)
    anomaly = _anomaly(ModelResponseRecoveryArea.JOURNAL)
    scan = _scan((final,), (anomaly,))
    repository = _Repository({SHA_A})
    file_ops = _FileOps(scan)

    result = ModelResponseArtifactRecoveryCoordinator(
        repository,
        file_ops,
        max_items=2,
    ).recover(RUN_ID, CUTOFF)

    assert result.has_anomaly is True
    assert repository.calls == []
    assert file_ops.quarantine_calls == []
    assert file_ops.cleanup_calls == []
    assert any(
        item.reason_code == ModelResponseRecoveryReason.ORPHAN_MUTATION_SUPPRESSED
        for item in result.items
    )


def test_mutation_race_stops_later_quarantines_and_returns_full_typed_inventory() -> None:
    final = _candidate(ModelResponseRecoveryArea.FINAL_RESPONSE, SHA_A, SHA_C)
    staged = _candidate(ModelResponseRecoveryArea.STAGED_RESPONSE, SHA_B, SHA_D)
    scan = _scan((staged, final))
    raced = ModelResponseRecoveryItem(
        run_id=RUN_ID,
        area=final.area,
        source_token=final.source_token,
        content_sha256=final.content_sha256,
        disposition=ModelResponseRecoveryDisposition.ANOMALY,
        reason_code=ModelResponseRecoveryReason.ENTRY_CHANGED_DURING_RECOVERY,
    )
    file_ops = _FileOps(scan, {final.source_token: raced})

    result = ModelResponseArtifactRecoveryCoordinator(
        _Repository(),
        file_ops,
        max_items=2,
    ).recover(RUN_ID, CUTOFF)

    assert result.has_anomaly is True
    assert len(result.items) == 2
    assert file_ops.quarantine_calls == [final.source_token]
    assert any(
        item.reason_code == ModelResponseRecoveryReason.ORPHAN_MUTATION_SUPPRESSED
        for item in result.items
    )


def test_partial_success_is_reported_before_anomaly_suppresses_remaining_work() -> None:
    final = _candidate(ModelResponseRecoveryArea.FINAL_RESPONSE, SHA_A, SHA_C)
    journal = _candidate(ModelResponseRecoveryArea.JOURNAL, SHA_B, SHA_D)
    staged = _candidate(ModelResponseRecoveryArea.STAGED_RESPONSE, SHA_C, SHA_A)
    scan = _scan((staged, journal, final))
    raced = ModelResponseRecoveryItem(
        run_id=RUN_ID,
        area=journal.area,
        source_token=journal.source_token,
        content_sha256=journal.content_sha256,
        disposition=ModelResponseRecoveryDisposition.ANOMALY,
        reason_code=ModelResponseRecoveryReason.ENTRY_CHANGED_DURING_RECOVERY,
    )
    file_ops = _FileOps(scan, {journal.source_token: raced})

    result = ModelResponseArtifactRecoveryCoordinator(
        _Repository(),
        file_ops,
        max_items=3,
    ).recover(RUN_ID, CUTOFF)

    by_source = {item.source_token: item for item in result.items}
    assert by_source[final.source_token].disposition == ModelResponseRecoveryDisposition.QUARANTINED
    assert by_source[journal.source_token].disposition == ModelResponseRecoveryDisposition.ANOMALY
    assert by_source[staged.source_token].reason_code == (
        ModelResponseRecoveryReason.ORPHAN_MUTATION_SUPPRESSED
    )
    assert file_ops.quarantine_calls == [
        final.source_token,
        journal.source_token,
    ]


def test_all_reference_queries_finish_before_first_file_mutation() -> None:
    first = _candidate(ModelResponseRecoveryArea.FINAL_RESPONSE, SHA_A, SHA_C)
    second = _candidate(ModelResponseRecoveryArea.FINAL_RESPONSE, SHA_B, SHA_D)
    scan = _scan((first, second))
    file_ops = _FileOps(scan)

    with pytest.raises(ContractViolation, match="database integrity"):
        ModelResponseArtifactRecoveryCoordinator(
            _Repository(fail_on_call=2),
            file_ops,
            max_items=2,
        ).recover(RUN_ID, CUTOFF)

    assert file_ops.quarantine_calls == []


def test_invalid_file_outcome_is_rejected_without_private_details() -> None:
    staged = _candidate(ModelResponseRecoveryArea.STAGED_RESPONSE, SHA_B, SHA_D)
    scan = _scan((staged,))
    wrong = _anomaly(ModelResponseRecoveryArea.JOURNAL)
    file_ops = _FileOps(scan, {staged.source_token: wrong})

    with pytest.raises(ContractViolation, match="exact candidate"):
        ModelResponseArtifactRecoveryCoordinator(
            _Repository(),
            file_ops,
            max_items=1,
        ).recover(RUN_ID, CUTOFF)


def test_scan_budget_mismatch_is_rejected_before_query_or_mutation() -> None:
    final = _candidate(ModelResponseRecoveryArea.FINAL_RESPONSE, SHA_A, SHA_C)
    scan = _scan((final,), max_items=1)
    repository = _Repository()
    file_ops = _FileOps(scan)

    with pytest.raises(ContractViolation, match="scan is outside"):
        ModelResponseArtifactRecoveryCoordinator(
            repository,
            file_ops,
            max_items=2,
        ).recover(RUN_ID, CUTOFF)

    assert repository.calls == []
    assert file_ops.quarantine_calls == []
    assert file_ops.cleanup_calls == []


def test_artifact_result_rejects_impossible_complete_and_incomplete_matrices() -> None:
    final = _candidate(ModelResponseRecoveryArea.FINAL_RESPONSE, SHA_A, SHA_C)
    quarantined = _quarantined(final)
    with pytest.raises(ValueError, match="cannot claim a filesystem mutation"):
        ModelResponseArtifactRecoveryResult(
            run_id=RUN_ID,
            limit=1,
            artifacts_scanned=1,
            file_bytes_limit=MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
            total_bytes_limit=MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
            bytes_scanned=1,
            scan_complete=False,
            items=(quarantined,),
        )

    suppressed = ModelResponseRecoveryItem(
        run_id=RUN_ID,
        area=final.area,
        source_token=final.source_token,
        content_sha256=final.content_sha256,
        disposition=ModelResponseRecoveryDisposition.RETAINED,
        reason_code=ModelResponseRecoveryReason.ORPHAN_MUTATION_SUPPRESSED,
    )
    with pytest.raises(ValueError, match="requires a typed anomaly"):
        ModelResponseArtifactRecoveryResult(
            run_id=RUN_ID,
            limit=1,
            artifacts_scanned=1,
            file_bytes_limit=MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
            total_bytes_limit=MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
            bytes_scanned=1,
            scan_complete=True,
            items=(suppressed,),
        )


def test_complete_scan_age_gates_and_cleans_exact_empty_operations() -> None:
    empty_stage = _cleanup_candidate(
        ModelResponseRecoveryArea.STAGED_RESPONSE,
        SHA_A,
    )
    empty_journal = _cleanup_candidate(ModelResponseRecoveryArea.JOURNAL, SHA_B)
    scan = _scan(cleanup_candidates=(empty_stage, empty_journal))
    file_ops = _FileOps(scan)

    result = ModelResponseArtifactRecoveryCoordinator(
        _Repository(),
        file_ops,
        max_items=2,
    ).recover(RUN_ID, CUTOFF)

    assert result.has_anomaly is False
    assert result.artifacts_scanned == 2
    assert {item.reason_code for item in result.items} == {
        ModelResponseRecoveryReason.EMPTY_OPERATION_CLEANED
    }
    assert set(file_ops.cleanup_calls) == {
        empty_stage.source_token,
        empty_journal.source_token,
    }


def test_incomplete_scan_never_cleans_observed_empty_operation() -> None:
    empty_stage = _cleanup_candidate(
        ModelResponseRecoveryArea.STAGED_RESPONSE,
        SHA_A,
    )
    scan = _scan(
        cleanup_candidates=(empty_stage,),
        complete=False,
        max_items=1,
    )
    file_ops = _FileOps(scan)

    result = ModelResponseArtifactRecoveryCoordinator(
        _Repository(),
        file_ops,
        max_items=1,
    ).recover(RUN_ID, CUTOFF)

    assert file_ops.cleanup_calls == []
    assert result.items[0].reason_code == (ModelResponseRecoveryReason.ARTIFACT_SCAN_INCOMPLETE)

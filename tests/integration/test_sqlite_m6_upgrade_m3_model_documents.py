from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import traceback
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from importlib import import_module
from pathlib import Path
from typing import NoReturn, cast

import pytest
from pydantic import BaseModel

import labcourt.adapters.storage._sqlite_m6_live_read_cut as live_cut_subject
import labcourt.adapters.storage._sqlite_m6_upgrade_m3_model_documents as documents_subject
import labcourt.adapters.storage._sqlite_m6_upgrade_m3_model_metadata as metadata_subject
import labcourt.adapters.storage._sqlite_m6_upgrade_m3_model_rows as rows_subject
import labcourt.adapters.storage._sqlite_m6_upgrade_m3_model_support as support_subject
from labcourt.adapters.storage._sqlite_m6_live_read_cut import (
    M6LiveCursor,
    M6LiveDocumentColumn,
    M6LiveReader,
    m6_live_committed_read_cut,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_case_document import (
    M6SQLiteCaseAuthorityDocument,
    read_m6_sqlite_case_authority,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m3_model_documents import (
    M6SQLiteM3DocumentRoute,
    M6SQLiteM3ModelDocumentError,
    M6SQLiteM3ModelDocumentFailureCode,
    M6SQLiteM3ModelDocumentsPlan,
    M6SQLiteM3SupportDocumentRoute,
    M6SQLiteM3SupportRoute,
    plan_m6_sqlite_m3_model_documents,
    resolve_m6_sqlite_m3_model_documents,
)
from labcourt.contracts.backlog import BacklogCompletionReceipt
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeCandidateCaseBinding,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedModelCall,
)
from labcourt.ports.m6_model_calls import M6M3ModelCallAuthoritySnapshot

m3_fixture = import_module("tests.integration.test_m3_sqlite_repository")
m3_pipeline_fixture = import_module("tests.e2e.test_m3_pipeline_scenarios")

_BODY_COLUMNS = (
    "request_json",
    "response_json",
    "entry_json",
    "receipt_json",
    "output_json",
    "authority_json",
    "usage_json",
)
_BODY_COLUMN_PATTERN = re.compile(
    rf"\b(?:{'|'.join(_BODY_COLUMNS)})\b",
    flags=re.IGNORECASE,
)
_ALLOWED_BODY_METADATA_PATTERN = re.compile(
    rf"\b(?:typeof|octet_length)\s*\(\s*(?:\w+\.)?"
    rf"(?:{'|'.join(_BODY_COLUMNS)})\s*\)",
    flags=re.IGNORECASE,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _contains_body_value_read(statement: str) -> bool:
    metadata_free = _ALLOWED_BODY_METADATA_PATTERN.sub("", statement)
    return _BODY_COLUMN_PATTERN.search(metadata_free) is not None


@dataclass(frozen=True, slots=True)
class _StoredPlanInputs:
    binding: M6UpgradeCandidateCaseBinding
    observations: tuple[M6UpgradeObservedModelCall, ...]
    manifest_id: str
    manifest_rule_version: str
    model_manifest_id: str


def _known_failure_retry_response_database(tmp_path: Path) -> Path:
    database, evidence, _, pack, closure, snapshot, head = m3_fixture._m3_setup(tmp_path)
    now = [m3_fixture.RECORDED_AT]
    review_verifier = m3_fixture.DeterministicProceduralReviewVerifier(
        m3_fixture.load_config(m3_fixture.ROOT / "configs" / "demo.yaml"),
        evidence,
    )
    repository = m3_fixture.SQLiteM3Repository(
        database,
        m3_fixture.BUSY_TIMEOUT_MS,
        clock=lambda: now[0],
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=m3_fixture._RawVerifier(),
        procedural_review_verifier=review_verifier,
    )
    request = m3_fixture._request(pack)
    first_owner = "planner-known-failure-owner-token-with-at-least-thirty-two-bytes"
    claim = repository.claim_model_call(m3_fixture.RUN_ID, request, first_owner)
    assert claim.lease_expires_at is not None
    item = m3_fixture._backlog_item(pack)
    failure_intent = m3_fixture.ModelCallFailureIntent(
        request=request,
        owner_token=first_owner,
        claim_lease_expires_at=claim.lease_expires_at,
        claim_takeover_count=claim.takeover_count,
        failure_code=m3_fixture.VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=m3_fixture.VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        backlog_reason_code=m3_fixture.BacklogReasonCode.PROVIDER_UNAVAILABLE,
    )
    repository.commit_backlog(
        m3_fixture.RUN_ID,
        snapshot.revision,
        head,
        closure,
        item,
        model_call_failure=failure_intent,
    )
    lease = repository.lease_next(
        m3_fixture.RUN_ID,
        m3_fixture.BacklogStage.SCREENING,
        "7" * 64,
        now[0] + timedelta(minutes=5),
    )
    assert lease is not None
    now[0] += timedelta(minutes=2)
    retry_request = m3_fixture._request(
        pack,
        backlog_retry_context=m3_fixture.BacklogRetryContext(
            backlog_item_id=lease.item_id,
            retry_generation=lease.retry_generation,
        ),
    )
    assert retry_request.request_id == request.request_id
    second_owner = "planner-known-failure-retry-owner-with-at-least-thirty-two-bytes"
    acquired = repository.claim_model_call(
        m3_fixture.RUN_ID,
        retry_request,
        second_owner,
        m3_fixture._lease_identity(lease),
    )
    assert acquired.takeover_count == 1
    response = m3_fixture._response(
        retry_request,
        content_sha256="e" * 64,
        input_tokens=13,
        output_tokens=5,
        latency_ms=17,
    )
    repository.complete_model_call(
        m3_fixture.RUN_ID,
        retry_request,
        response,
        second_owner,
    )
    output = m3_fixture._parsed(
        retry_request,
        response,
        violation_probability=0.5,
    )
    parse_receipt = m3_fixture._parsed_receipt(retry_request, response, output)
    repository.append_parse_receipt(parse_receipt, output)
    screening = m3_fixture._screening_for(pack, output)
    success = m3_fixture.BacklogRetrySuccess(
        lease=m3_fixture._lease_identity(lease),
        completion_case_status=m3_fixture.CaseStatus.ESCALATED,
        completion_ref=m3_fixture.ArtifactRef(
            kind=m3_fixture.ArtifactKind.SCREENING_RESULT,
            artifact_id=screening.screening_id,
        ),
        response_refs=(
            m3_fixture.ArtifactRef(
                kind=m3_fixture.ArtifactKind.MODEL_RESPONSE,
                artifact_id=response.response_id,
            ),
        ),
        manifest_id=pack.manifest_id,
    )
    current_case = evidence.load_case(m3_fixture.RUN_ID, pack.case_id)
    repository.commit_backlog_screening_success(
        m3_fixture.RUN_ID,
        current_case.revision,
        evidence.get_audit_head(m3_fixture.RUN_ID),
        closure,
        success,
        screening,
    )
    return cast(Path, database)


def _two_generation_failure_database(tmp_path: Path) -> Path:
    database, evidence, _, pack, closure, snapshot, head = m3_fixture._m3_setup(tmp_path)
    now = [m3_fixture.RECORDED_AT]
    repository = m3_fixture.SQLiteM3Repository(
        database,
        m3_fixture.BUSY_TIMEOUT_MS,
        clock=lambda: now[0],
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=m3_fixture._RawVerifier(),
    )
    request = m3_fixture._request(pack)
    first_owner = "planner-first-failure-owner-token-with-at-least-thirty-two-bytes"
    first_claim = repository.claim_model_call(
        m3_fixture.RUN_ID,
        request,
        first_owner,
    )
    assert first_claim.lease_expires_at is not None
    item = m3_fixture._backlog_item(pack)
    first_intent = m3_fixture.ModelCallFailureIntent(
        request=request,
        owner_token=first_owner,
        claim_lease_expires_at=first_claim.lease_expires_at,
        claim_takeover_count=first_claim.takeover_count,
        failure_code=m3_fixture.VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=m3_fixture.VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        backlog_reason_code=m3_fixture.BacklogReasonCode.PROVIDER_UNAVAILABLE,
    )
    repository.commit_backlog(
        m3_fixture.RUN_ID,
        snapshot.revision,
        head,
        closure,
        item,
        model_call_failure=first_intent,
    )
    lease = repository.lease_next(
        m3_fixture.RUN_ID,
        m3_fixture.BacklogStage.SCREENING,
        "8" * 64,
        now[0] + timedelta(minutes=5),
    )
    assert lease is not None
    now[0] += timedelta(minutes=2)
    retry_request = m3_fixture._request(
        pack,
        backlog_retry_context=m3_fixture.BacklogRetryContext(
            backlog_item_id=lease.item_id,
            retry_generation=lease.retry_generation,
        ),
    )
    second_owner = "planner-second-failure-owner-token-with-at-least-thirty-two-bytes"
    second_claim = repository.claim_model_call(
        m3_fixture.RUN_ID,
        retry_request,
        second_owner,
        m3_fixture._lease_identity(lease),
    )
    assert second_claim.takeover_count == 1
    assert second_claim.lease_expires_at is not None
    second_intent = m3_fixture.ModelCallFailureIntent(
        request=retry_request,
        owner_token=second_owner,
        claim_lease_expires_at=second_claim.lease_expires_at,
        claim_takeover_count=second_claim.takeover_count,
        failure_code=m3_fixture.VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=m3_fixture.VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        backlog_reason_code=m3_fixture.BacklogReasonCode.PROVIDER_UNAVAILABLE,
    )
    failure = m3_fixture.BacklogRetryFailure(
        lease=m3_fixture._lease_identity(lease),
        reason_code=m3_fixture.BacklogReasonCode.PROVIDER_UNAVAILABLE,
        next_status=m3_fixture.BacklogStatus.PENDING,
        manifest_id=pack.manifest_id,
    )
    current_case = evidence.load_case(m3_fixture.RUN_ID, pack.case_id)
    repository.commit_backlog_retry_failure(
        m3_fixture.RUN_ID,
        current_case.revision,
        evidence.get_audit_head(m3_fixture.RUN_ID),
        closure,
        failure,
        second_intent,
    )
    return cast(Path, database)


def _known_repair_failure_retry_response_database(tmp_path: Path) -> Path:
    database, evidence, _, pack, closure, snapshot, head = m3_fixture._m3_setup(tmp_path)
    now = [m3_fixture.RECORDED_AT]
    review_verifier = m3_fixture.DeterministicProceduralReviewVerifier(
        m3_fixture.load_config(m3_fixture.ROOT / "configs" / "demo.yaml"),
        evidence,
    )
    repository = m3_fixture.SQLiteM3Repository(
        database,
        m3_fixture.BUSY_TIMEOUT_MS,
        clock=lambda: now[0],
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=m3_fixture._RawVerifier(),
        procedural_review_verifier=review_verifier,
    )
    request = m3_fixture._request(pack)
    primary_response = m3_fixture._response(
        request,
        content_sha256="a" * 64,
        input_tokens=13,
        output_tokens=3,
        latency_ms=17,
    )
    repair_request = m3_fixture._repair_request(request, primary_response)
    primary_receipt = m3_fixture.ModelParseReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=primary_response.response_id,
        response_content_sha256=primary_response.content_sha256,
        attempt_index=0,
        parser_version="strict-json-v1",
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        status=m3_fixture.ModelParseStatus.REPAIR_REQUIRED,
        defects=(m3_fixture._parser_defect(primary_response.response_id),),
        repair_request_id=repair_request.request_id,
        manifest_id=request.manifest_id,
    )
    m3_fixture._complete_call(repository, request, primary_response)
    repository.append_parse_receipt(primary_receipt)

    first_owner = "planner-repair-failure-owner-token-with-at-least-thirty-two-bytes"
    first_claim = repository.claim_model_call(
        m3_fixture.RUN_ID,
        repair_request,
        first_owner,
    )
    assert first_claim.lease_expires_at is not None
    initial_item = m3_fixture._backlog_item(pack)
    item_payload = initial_item.model_dump(mode="json", exclude_computed_fields=True)
    item_payload["role"] = m3_fixture.VlmRole.STRUCTURE_REPAIR.value
    item = m3_fixture.BacklogItem.model_validate(item_payload)
    failure_intent = m3_fixture.ModelCallFailureIntent(
        request=repair_request,
        owner_token=first_owner,
        claim_lease_expires_at=first_claim.lease_expires_at,
        claim_takeover_count=first_claim.takeover_count,
        failure_code=m3_fixture.VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=m3_fixture.VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        backlog_reason_code=m3_fixture.BacklogReasonCode.PROVIDER_UNAVAILABLE,
    )
    enqueued = repository.commit_backlog(
        m3_fixture.RUN_ID,
        snapshot.revision,
        head,
        closure,
        item,
        response_ids=(primary_response.response_id,),
        model_call_failure=failure_intent,
    )
    lease = repository.lease_next(
        m3_fixture.RUN_ID,
        m3_fixture.BacklogStage.SCREENING,
        "6" * 64,
        m3_fixture.RECORDED_AT + timedelta(minutes=5),
    )
    assert lease is not None
    now[0] += timedelta(minutes=2)
    context = m3_fixture.BacklogRetryContext(
        backlog_item_id=lease.item_id,
        retry_generation=lease.retry_generation,
    )
    retry_request = m3_fixture._request(pack, backlog_retry_context=context)
    retry_repair = m3_fixture._repair_request(retry_request, primary_response)
    assert retry_repair.request_id == repair_request.request_id
    final_response = m3_fixture._response(
        retry_repair,
        content_sha256="b" * 64,
        input_tokens=5,
        output_tokens=9,
        latency_ms=23,
    )
    output = m3_fixture._parsed(
        retry_repair,
        final_response,
        evidence_ref=request.allowed_evidence_refs[0],
        violation_probability=0.5,
    )
    final_receipt = m3_fixture._parsed_receipt(retry_repair, final_response, output)
    m3_fixture._complete_call(
        repository,
        retry_repair,
        final_response,
        m3_fixture._lease_identity(lease),
    )
    repository.append_parse_receipt(final_receipt, output)
    screening = m3_fixture._screening_for(pack, output)
    response_refs = tuple(
        sorted(
            (
                m3_fixture.ArtifactRef(
                    kind=m3_fixture.ArtifactKind.MODEL_RESPONSE,
                    artifact_id=response.response_id,
                )
                for response in (primary_response, final_response)
            ),
            key=lambda reference: reference.sort_key,
        )
    )
    success = m3_fixture.BacklogRetrySuccess(
        lease=m3_fixture._lease_identity(lease),
        completion_case_status=m3_fixture.CaseStatus.ESCALATED,
        completion_ref=m3_fixture.ArtifactRef(
            kind=m3_fixture.ArtifactKind.SCREENING_RESULT,
            artifact_id=screening.screening_id,
        ),
        response_refs=response_refs,
        manifest_id=pack.manifest_id,
    )
    repository.commit_backlog_screening_success(
        m3_fixture.RUN_ID,
        enqueued.case.revision,
        evidence.get_audit_head(m3_fixture.RUN_ID),
        closure,
        success,
        screening,
    )
    return cast(Path, database)


def _fixture_database(tmp_path: Path, shape: str) -> Path:
    if shape == "response":
        return cast(Path, m3_fixture._all_m3_artifacts_for_validation(tmp_path))
    if shape == "failure":
        return cast(Path, m3_fixture._failed_model_call_for_validation(tmp_path)[0])
    if shape == "repair":
        return cast(Path, m3_fixture._repair_artifacts_for_validation(tmp_path)[0])
    if shape == "shared_receipt":
        m3_fixture.test_strict_two_call_failure_advances_generation_and_accounts_once(tmp_path)
        return tmp_path / "labcourt.sqlite3"
    if shape == "initial_model_output_invalid":
        m3_pipeline_fixture.test_two_malformed_responses_persist_typed_backlog_without_partial_screening(
            tmp_path
        )
        return tmp_path / "labcourt.sqlite3"
    if shape == "known_failure_retry_response":
        return _known_failure_retry_response_database(tmp_path)
    if shape == "two_generation_failure":
        return _two_generation_failure_database(tmp_path)
    if shape == "known_repair_failure_retry_response":
        return _known_repair_failure_retry_response_database(tmp_path)
    raise ValueError(f"unsupported M3 fixture shape: {shape}")


def _stored_plan_inputs(database: Path) -> _StoredPlanInputs:
    manifest = m3_fixture._manifest()
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        case_row = connection.execute(
            """
            SELECT c.case_id,
                   c.current_revision,
                   cv.document_sha256,
                   cv.audit_sequence,
                   a.entry_hash
            FROM cases AS c
            JOIN case_versions AS cv
              ON cv.run_id = c.run_id
             AND cv.case_id = c.case_id
             AND cv.revision = c.current_revision
            JOIN audit_entries AS a
              ON a.run_id = cv.run_id
             AND a.sequence = cv.audit_sequence
            WHERE c.run_id = ?
            """,
            (m3_fixture.RUN_ID,),
        ).fetchone()
        if case_row is None:
            raise AssertionError("M3 fixture has no selected Case authority")
        call_rows = connection.execute(
            """
            SELECT claim.request_id,
                   claim.purpose,
                   EXISTS(
                       SELECT 1 FROM model_responses AS response
                       WHERE response.run_id = claim.run_id
                         AND response.request_id = claim.request_id
                   ) AS has_response,
                   EXISTS(
                       SELECT 1 FROM model_call_failure_authorities AS failure
                       WHERE failure.run_id = claim.run_id
                         AND failure.request_id = claim.request_id
                   ) AS has_failure
            FROM model_call_claims AS claim
            WHERE claim.run_id = ? AND claim.case_id = ?
            ORDER BY claim.request_id
            """,
            (m3_fixture.RUN_ID, case_row["case_id"]),
        ).fetchall()
    observations: list[M6UpgradeObservedModelCall] = []
    for row in call_rows:
        has_response = row["has_response"] == 1
        has_failure = row["has_failure"] == 1
        if not has_response and not has_failure:
            raise AssertionError("M3 fixture call has no result authority")
        observations.append(
            M6UpgradeObservedModelCall(
                request_id=row["request_id"],
                layer=M6LockedModelCallLayer.SCREENING,
                role=M6LockedModelRole.SCREENING,
                attempt_index=0 if row["purpose"] == "SCREENING" else 1,
                result_kind=(
                    M6LockedModelCallResultKind.RESPONSE
                    if has_response
                    else M6LockedModelCallResultKind.FAILURE
                ),
                provider_invoked=has_response,
            )
        )
    binding = M6UpgradeCandidateCaseBinding(
        case_id=case_row["case_id"],
        case_revision=case_row["current_revision"],
        case_document_sha256=case_row["document_sha256"],
        case_audit_sequence=case_row["audit_sequence"],
        case_audit_entry_hash=case_row["entry_hash"],
    )
    return _StoredPlanInputs(
        binding=binding,
        observations=tuple(sorted(observations, key=lambda item: item.sort_key)),
        manifest_id=manifest.manifest_id,
        manifest_rule_version=manifest.rule_version,
        model_manifest_id=manifest.models["screening"].model_manifest_id,
    )


@contextmanager
def _live_reader(database: Path) -> Iterator[M6LiveReader]:
    with m6_live_committed_read_cut(database, m3_fixture.BUSY_TIMEOUT_MS) as cut:
        with cut.selector() as selector:
            selected = selector.execute("SELECT 1 AS ready").fetchone()
            assert selected is not None and selected["ready"] == 1
        with cut.reader() as reader:
            assert reader.in_transaction
            yield reader
            assert reader.in_transaction
        with cut.writer() as writer:
            selected = writer.execute("SELECT 1 AS ready").fetchone()
            assert selected is not None and selected["ready"] == 1


def _selected_case_authority(
    reader: M6LiveReader,
    inputs: _StoredPlanInputs,
) -> M6SQLiteCaseAuthorityDocument:
    return read_m6_sqlite_case_authority(
        connection=reader,
        expected_run_id=m3_fixture.RUN_ID,
        expected_manifest_id=inputs.manifest_id,
        expected_manifest_rule_version=inputs.manifest_rule_version,
        candidate_case_binding=inputs.binding,
    )


def _authority_snapshot(
    database: Path,
    inputs: _StoredPlanInputs,
) -> M6SQLiteCaseAuthorityDocument:
    with _live_reader(database) as reader:
        return _selected_case_authority(reader, inputs)


def _mutate_all_scalar_rows(
    database: Path,
    *,
    table: str,
    column: str,
    value: object,
) -> None:
    allowed_targets = {
        ("model_call_claims", "manifest_id"),
        ("model_call_claims", "model_manifest_id"),
        ("evidence_packs", "document_sha256"),
        ("case_versions", "document_sha256"),
        ("backlog_completion_receipts", "completion_audit_entry_hash"),
        ("backlog_heads", "current_version"),
        ("backlog_items", "stage"),
        ("backlog_items", "role"),
    }
    if (table, column) not in allowed_targets:
        raise AssertionError("test scalar mutation target is not allowlisted")
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        trigger_names = tuple(
            cast(
                str,
                row[0],
            )
            for row in connection.execute(
                """
                SELECT name FROM sqlite_schema
                WHERE type = 'trigger' AND tbl_name = ?
                ORDER BY name
                """,
                (table,),
            )
        )
        for trigger_name in trigger_names:
            escaped_name = trigger_name.replace('"', '""')
            connection.execute(f'DROP TRIGGER "{escaped_name}"')
        cursor = connection.execute(
            f'UPDATE "{table}" SET "{column}" = ?',
            (value,),
        )
        assert cursor.rowcount > 0


def _mutate_completion_response_refs(database: Path, mutation: str) -> None:
    if mutation not in {"missing", "extra", "foreign"}:
        raise AssertionError("unsupported completion response-ref mutation")
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT rowid, receipt_json
            FROM backlog_completion_receipts
            ORDER BY rowid LIMIT 1
            """
        ).fetchone()
        if row is None:
            raise AssertionError("test fixture has no completion receipt")
        payload = cast(dict[str, object], json.loads(cast(str, row[1])))
        outcome = cast(dict[str, object], payload["outcome"])
        response_refs = cast(list[dict[str, str]], outcome["response_refs"])
        if mutation == "missing":
            if len(response_refs) < 2:
                raise AssertionError("missing-ref attack needs a multi-response receipt")
            response_refs = response_refs[1:]
        elif mutation == "extra":
            response_refs = [
                *response_refs,
                {
                    "kind": "MODEL_RESPONSE",
                    "artifact_id": _sha("foreign-completion-response"),
                },
            ]
        else:
            response_refs = [
                *response_refs[:-1],
                {
                    "kind": "MODEL_RESPONSE",
                    "artifact_id": _sha("foreign-completion-response"),
                },
            ]
        outcome["response_refs"] = sorted(
            response_refs,
            key=lambda value: (value["kind"], value["artifact_id"]),
        )
        canonical = canonical_json(payload)
        trigger_names = tuple(
            cast(str, trigger[0])
            for trigger in connection.execute(
                """
                SELECT name FROM sqlite_schema
                WHERE type = 'trigger'
                  AND tbl_name = 'backlog_completion_receipts'
                ORDER BY name
                """
            )
        )
        for trigger_name in trigger_names:
            escaped_name = trigger_name.replace('"', '""')
            connection.execute(f'DROP TRIGGER "{escaped_name}"')
        updated = connection.execute(
            """
            UPDATE backlog_completion_receipts
            SET receipt_json = ?, document_sha256 = ?
            WHERE rowid = ?
            """,
            (
                canonical,
                hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                row[0],
            ),
        )
        assert updated.rowcount == 1


def _mutate_success_completion_response_refs_canonically(
    database: Path,
    mutation: str,
) -> None:
    if mutation not in {"missing", "extra", "foreign"}:
        raise AssertionError("unsupported success completion response-ref mutation")
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT rowid, receipt_json
            FROM backlog_completion_receipts
            WHERE outcome_kind = 'SUCCESS'
            """
        ).fetchone()
        if row is None:
            raise AssertionError("test fixture has no success completion receipt")
        payload = cast(dict[str, object], json.loads(cast(str, row[1])))
        outcome = cast(dict[str, object], payload["outcome"])
        response_refs = cast(list[dict[str, str]], outcome["response_refs"])
        foreign = {
            "kind": "MODEL_RESPONSE",
            "artifact_id": _sha("foreign-cross-consumer-response"),
        }
        if mutation == "missing":
            if len(response_refs) < 2:
                raise AssertionError("missing-ref attack needs a multi-response success")
            response_refs = response_refs[1:]
        elif mutation == "extra":
            response_refs = [*response_refs, foreign]
        else:
            response_refs = [*response_refs[:-1], foreign]
        outcome["response_refs"] = sorted(
            response_refs,
            key=lambda value: (value["kind"], value["artifact_id"]),
        )
        outcome.pop("outcome_id", None)
        payload.pop("receipt_id", None)
        receipt = BacklogCompletionReceipt.model_validate(payload)
        canonical = canonical_json(receipt.model_dump(mode="json"))
        trigger_names = tuple(
            cast(str, trigger[0])
            for trigger in connection.execute(
                """
                SELECT name FROM sqlite_schema
                WHERE type = 'trigger'
                  AND tbl_name = 'backlog_completion_receipts'
                ORDER BY name
                """
            )
        )
        for trigger_name in trigger_names:
            escaped_name = trigger_name.replace('"', '""')
            connection.execute(f'DROP TRIGGER "{escaped_name}"')
        updated = connection.execute(
            """
            UPDATE backlog_completion_receipts
            SET receipt_id = ?, outcome_id = ?, receipt_json = ?, document_sha256 = ?
            WHERE rowid = ?
            """,
            (
                receipt.receipt_id,
                receipt.outcome.outcome_id,
                canonical,
                hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                row[0],
            ),
        )
        assert updated.rowcount == 1


def _mutate_oldest_failure_scalar(
    database: Path,
    *,
    column: str,
    value: object,
) -> None:
    if column not in {"claim_takeover_count", "closure_case_revision"}:
        raise AssertionError("unsupported historical failure mutation")
    with sqlite3.connect(database) as connection:
        trigger_names = tuple(
            cast(str, trigger[0])
            for trigger in connection.execute(
                """
                SELECT name FROM sqlite_schema
                WHERE type = 'trigger'
                  AND tbl_name = 'model_call_failure_authorities'
                ORDER BY name
                """
            )
        )
        for trigger_name in trigger_names:
            escaped_name = trigger_name.replace('"', '""')
            connection.execute(f'DROP TRIGGER "{escaped_name}"')
        updated = connection.execute(
            f"""
            UPDATE model_call_failure_authorities
            SET "{column}" = ?
            WHERE claim_takeover_count = 0
            """,
            (value,),
        )
        assert updated.rowcount == 1


def _delete_oldest_failure(database: Path) -> None:
    with sqlite3.connect(database) as connection:
        trigger_names = tuple(
            cast(str, trigger[0])
            for trigger in connection.execute(
                """
                SELECT name FROM sqlite_schema
                WHERE type = 'trigger'
                  AND tbl_name = 'model_call_failure_authorities'
                ORDER BY name
                """
            )
        )
        for trigger_name in trigger_names:
            escaped_name = trigger_name.replace('"', '""')
            connection.execute(f'DROP TRIGGER "{escaped_name}"')
        deleted = connection.execute(
            """
            DELETE FROM model_call_failure_authorities
            WHERE claim_takeover_count = 0
            """
        )
        assert deleted.rowcount == 1


def _delete_success_completion(database: Path) -> None:
    with sqlite3.connect(database) as connection:
        trigger_names = tuple(
            cast(str, trigger[0])
            for trigger in connection.execute(
                """
                SELECT name FROM sqlite_schema
                WHERE type = 'trigger'
                  AND tbl_name = 'backlog_completion_receipts'
                ORDER BY name
                """
            )
        )
        for trigger_name in trigger_names:
            escaped_name = trigger_name.replace('"', '""')
            connection.execute(f'DROP TRIGGER "{escaped_name}"')
        deleted = connection.execute(
            "DELETE FROM backlog_completion_receipts WHERE outcome_kind = 'SUCCESS'"
        )
        assert deleted.rowcount == 1


def _tamper_oldest_failure_body_only(database: Path) -> None:
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT rowid, authority_json, closure_audit_entry_hash
            FROM model_call_failure_authorities
            WHERE claim_takeover_count = 0
            """
        ).fetchone()
        if row is None:
            raise AssertionError("test fixture has no historical failure body")
        body = cast(str, row[1])
        committed_hash = cast(str, row[2])
        foreign_hash = _sha("foreign-historical-closure-audit")
        tampered = body.replace(committed_hash, foreign_hash)
        if tampered == body or len(tampered.encode("utf-8")) != len(body.encode("utf-8")):
            raise AssertionError("historical body attack did not preserve its metadata length")
        trigger_names = tuple(
            cast(str, trigger[0])
            for trigger in connection.execute(
                """
                SELECT name FROM sqlite_schema
                WHERE type = 'trigger'
                  AND tbl_name = 'model_call_failure_authorities'
                ORDER BY name
                """
            )
        )
        for trigger_name in trigger_names:
            escaped_name = trigger_name.replace('"', '""')
            connection.execute(f'DROP TRIGGER "{escaped_name}"')
        updated = connection.execute(
            """
            UPDATE model_call_failure_authorities
            SET authority_json = ?
            WHERE rowid = ?
            """,
            (tampered, row[0]),
        )
        assert updated.rowcount == 1


def _plan_from_reader(
    reader: M6LiveReader,
    inputs: _StoredPlanInputs,
    *,
    observations: tuple[M6UpgradeObservedModelCall, ...] | None = None,
    selected_case_authority: M6SQLiteCaseAuthorityDocument | None = None,
    expected_run_id: str | None = None,
    expected_manifest_id: str | None = None,
    expected_model_manifest_id: str | None = None,
) -> M6SQLiteM3ModelDocumentsPlan:
    return plan_m6_sqlite_m3_model_documents(
        connection=reader,
        expected_run_id=(m3_fixture.RUN_ID if expected_run_id is None else expected_run_id),
        expected_manifest_id=(
            inputs.manifest_id if expected_manifest_id is None else expected_manifest_id
        ),
        expected_model_manifest_id=(
            inputs.model_manifest_id
            if expected_model_manifest_id is None
            else expected_model_manifest_id
        ),
        selected_case_authority=(
            _selected_case_authority(reader, inputs)
            if selected_case_authority is None
            else selected_case_authority
        ),
        observed_model_calls=(inputs.observations if observations is None else observations),
    )


def _plan_and_resolve_from_reader(
    reader: M6LiveReader,
    inputs: _StoredPlanInputs,
) -> tuple[M6SQLiteM3ModelDocumentsPlan, M6M3ModelCallAuthoritySnapshot]:
    plan = _plan_from_reader(reader, inputs)
    assert reader.in_transaction
    snapshot = resolve_m6_sqlite_m3_model_documents(
        connection=reader,
        metadata_plan=plan,
    )
    assert reader.in_transaction
    return plan, snapshot


def _resolved_document_records(
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> tuple[tuple[M6SQLiteM3DocumentRoute, str, str, BaseModel], ...]:
    records: list[tuple[M6SQLiteM3DocumentRoute, str, str, BaseModel]] = []
    records.extend(
        (
            M6SQLiteM3DocumentRoute.MODEL_REQUEST,
            value.request.request_id,
            value.document_sha256,
            value.request,
        )
        for value in snapshot.requests
    )
    records.extend(
        (
            M6SQLiteM3DocumentRoute.MODEL_RESPONSE,
            value.response.response_id,
            value.document_sha256,
            value.response,
        )
        for value in snapshot.responses
    )
    for value in snapshot.caches:
        records.extend(
            (
                (
                    M6SQLiteM3DocumentRoute.MODEL_CACHE_REQUEST,
                    value.request.request_id,
                    value.request_document_sha256,
                    value.request,
                ),
                (
                    M6SQLiteM3DocumentRoute.MODEL_CACHE_ENTRY,
                    value.entry.cache_entry_id,
                    value.document_sha256,
                    value.entry,
                ),
            )
        )
    records.extend(
        (
            M6SQLiteM3DocumentRoute.MODEL_PARSE_RECEIPT,
            value.receipt.parse_receipt_id,
            value.document_sha256,
            value.receipt,
        )
        for value in snapshot.parse_receipts
    )
    records.extend(
        (
            M6SQLiteM3DocumentRoute.PARSED_SCREENING_OUTPUT,
            value.output.parsed_output_id,
            value.document_sha256,
            value.output,
        )
        for value in snapshot.parsed_outputs
    )
    records.extend(
        (
            M6SQLiteM3DocumentRoute.MODEL_CALL_FAILURE,
            value.authority.authority_id,
            value.document_sha256,
            value.authority,
        )
        for value in snapshot.failures
    )
    records.extend(
        (
            M6SQLiteM3DocumentRoute.MODEL_USAGE,
            value.request_id,
            value.document_sha256,
            value.usage,
        )
        for value in snapshot.usages
    )
    return tuple(records)


def _assert_resolved_snapshot_exactly_closes_plan(
    plan: M6SQLiteM3ModelDocumentsPlan,
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> None:
    assert snapshot.run_id == plan.run_id
    assert snapshot.case_id == plan.case_id
    assert snapshot.manifest_id == plan.manifest_id
    assert re.fullmatch(r"[0-9a-f]{64}", snapshot.source_identity_sha256)
    assert snapshot.authority_failure_count == 0
    records = _resolved_document_records(snapshot)
    slots = {
        (slot.route, slot.artifact_id, slot.document_sha256): slot for slot in plan.document_slots
    }
    assert len(slots) == len(plan.document_slots)
    assert Counter((route, artifact_id, digest) for route, artifact_id, digest, _ in records) == (
        Counter(slots.keys())
    )
    for route, artifact_id, digest, document in records:
        canonical = canonical_json(document.model_dump(mode="json"))
        assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == digest
        assert len(canonical.encode("utf-8")) == slots[(route, artifact_id, digest)].document_bytes


def _observation_with_request_id(
    value: M6UpgradeObservedModelCall,
    request_id: str,
) -> M6UpgradeObservedModelCall:
    return M6UpgradeObservedModelCall(
        request_id=request_id,
        layer=value.layer,
        role=value.role,
        attempt_index=value.attempt_index,
        result_kind=value.result_kind,
        provider_invoked=value.provider_invoked,
    )


@pytest.mark.parametrize(
    ("shape", "expected_kinds"),
    [
        ("response", (M6LockedModelCallResultKind.RESPONSE,)),
        ("failure", (M6LockedModelCallResultKind.FAILURE,)),
        (
            "repair",
            (
                M6LockedModelCallResultKind.RESPONSE,
                M6LockedModelCallResultKind.RESPONSE,
            ),
        ),
    ],
)
def test_public_planner_closes_real_m3_storage_rows_bidirectionally(
    tmp_path: Path,
    shape: str,
    expected_kinds: tuple[M6LockedModelCallResultKind, ...],
) -> None:
    database = _fixture_database(tmp_path, shape)
    inputs = _stored_plan_inputs(database)

    with _live_reader(database) as reader:
        plan = _plan_from_reader(reader, inputs)
        assert reader.in_transaction

    assert plan.selected_case_binding == inputs.binding
    assert plan.observed_model_calls == inputs.observations
    assert tuple(graph.observation for graph in plan.call_graphs) == inputs.observations
    assert tuple(graph.observation.result_kind for graph in plan.call_graphs) == expected_kinds
    assert all(graph.model_manifest_id == inputs.model_manifest_id for graph in plan.call_graphs)


@pytest.mark.parametrize("direction", ["missing", "extra"])
def test_public_planner_rejects_both_observation_closure_directions(
    tmp_path: Path,
    direction: str,
) -> None:
    database = _fixture_database(tmp_path, "failure")
    inputs = _stored_plan_inputs(database)
    if direction == "missing":
        observations: tuple[M6UpgradeObservedModelCall, ...] = ()
    else:
        foreign = _observation_with_request_id(
            inputs.observations[0],
            _sha("foreign-observation"),
        )
        observations = tuple(
            sorted((*inputs.observations, foreign), key=lambda item: item.sort_key)
        )

    with (
        _live_reader(database) as reader,
        pytest.raises(M6SQLiteM3ModelDocumentError) as raised,
    ):
        _plan_from_reader(reader, inputs, observations=observations)

    assert (
        raised.value.reason_code == M6SQLiteM3ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH
    )


@pytest.mark.parametrize("malformation", ["duplicate", "out_of_order"])
def test_public_planner_rejects_duplicate_or_unordered_observations_before_sql_join(
    tmp_path: Path,
    malformation: str,
) -> None:
    database = _fixture_database(tmp_path, "repair")
    inputs = _stored_plan_inputs(database)
    assert len(inputs.observations) == 2
    observations = (
        (inputs.observations[0], inputs.observations[0])
        if malformation == "duplicate"
        else tuple(reversed(inputs.observations))
    )

    with _live_reader(database) as reader:
        authority = _selected_case_authority(reader, inputs)
        with pytest.raises(M6SQLiteM3ModelDocumentError) as raised:
            _plan_from_reader(
                reader,
                inputs,
                observations=observations,
                selected_case_authority=authority,
            )

    assert raised.value.reason_code == M6SQLiteM3ModelDocumentFailureCode.INVALID_ARGUMENT


def test_backlog_usage_receipt_is_one_budgeted_nonphysical_support_document(
    tmp_path: Path,
) -> None:
    database = _fixture_database(tmp_path, "shared_receipt")
    inputs = _stored_plan_inputs(database)
    with sqlite3.connect(database) as connection:
        usage_count, consumer_count = cast(
            tuple[int, int],
            connection.execute(
                """
                SELECT COUNT(*), COUNT(DISTINCT consumer_id)
                FROM model_call_usage_accounting
                WHERE consumer_kind = 'BACKLOG_ITEM'
                """
            ).fetchone(),
        )
        stored_receipt_count = cast(
            int,
            connection.execute("SELECT COUNT(*) FROM backlog_completion_receipts").fetchone()[0],
        )
    assert (usage_count, consumer_count, stored_receipt_count) == (2, 1, 1)

    with _live_reader(database) as reader:
        plan = _plan_from_reader(reader, inputs)

    receipt_documents = tuple(
        slot
        for slot in plan.support_document_slots
        if slot.route == M6SQLiteM3SupportDocumentRoute.BACKLOG_COMPLETION_RECEIPT
    )
    receipt_support = tuple(
        slot
        for slot in plan.support_slots
        if slot.route == M6SQLiteM3SupportRoute.BACKLOG_COMPLETION_RECEIPT
    )
    assert len(receipt_documents) == len(receipt_support) == 1
    receipt_document = receipt_documents[0]
    assert (receipt_document.rowid, receipt_document.artifact_id) == (
        receipt_support[0].rowid,
        receipt_support[0].identity,
    )
    assert plan.planned_document_bytes == sum(
        slot.document_bytes for slot in plan.document_slots
    ) + sum(slot.document_bytes for slot in plan.support_document_slots)
    assert all(
        reference.artifact_id != receipt_document.artifact_id
        for reference in plan.planned_artifact_refs
    )


def test_initial_model_output_invalid_backlog_needs_no_completion_receipt(
    tmp_path: Path,
) -> None:
    database = _fixture_database(tmp_path, "initial_model_output_invalid")
    inputs = _stored_plan_inputs(database)
    with sqlite3.connect(database) as connection:
        stored_shape = cast(
            tuple[int, int, int, int],
            connection.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM model_responses),
                    (SELECT COUNT(*) FROM model_call_usage_accounting
                     WHERE consumer_kind = 'BACKLOG_ITEM'),
                    (SELECT COUNT(DISTINCT consumer_id)
                     FROM model_call_usage_accounting
                     WHERE consumer_kind = 'BACKLOG_ITEM'),
                    (SELECT COUNT(*) FROM backlog_completion_receipts)
                """
            ).fetchone(),
        )
    assert stored_shape == (2, 2, 1, 0)

    with _live_reader(database) as reader:
        plan = _plan_from_reader(reader, inputs)

    assert len(plan.call_graphs) == 2
    assert all(
        graph.observation.result_kind == M6LockedModelCallResultKind.RESPONSE
        for graph in plan.call_graphs
    )
    assert (
        sum(
            slot.route.value == "model_call_usage_accounting.usage_json"
            for slot in plan.document_slots
        )
        == 2
    )
    assert not any(
        slot.route == M6SQLiteM3SupportRoute.BACKLOG_COMPLETION_RECEIPT
        for slot in plan.support_slots
    )
    assert plan.support_document_slots == ()


@pytest.mark.parametrize(
    ("table", "column", "value"),
    [
        ("backlog_heads", "current_version", 999),
        ("backlog_items", "stage", "HEARING"),
        ("backlog_items", "role", "SCREENING"),
    ],
)
def test_initial_backlog_usage_rejects_item_head_stage_or_final_repair_role_corruption(
    tmp_path: Path,
    table: str,
    column: str,
    value: object,
) -> None:
    database = _fixture_database(tmp_path, "initial_model_output_invalid")
    inputs = _stored_plan_inputs(database)
    authority = _authority_snapshot(database, inputs)
    _mutate_all_scalar_rows(
        database,
        table=table,
        column=column,
        value=value,
    )

    with (
        _live_reader(database) as reader,
        pytest.raises(M6SQLiteM3ModelDocumentError) as raised,
    ):
        _plan_from_reader(
            reader,
            inputs,
            selected_case_authority=authority,
        )

    assert raised.value.reason_code == M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH


def test_known_failure_retry_response_preserves_history_and_current_request_context(
    tmp_path: Path,
) -> None:
    database = _fixture_database(tmp_path, "known_failure_retry_response")
    inputs = _stored_plan_inputs(database)
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT
                (SELECT request_document_sha256
                 FROM model_call_failure_authorities),
                (SELECT request_document_sha256 FROM model_cache),
                (SELECT authority_id FROM model_call_failure_authorities),
                (SELECT outcome_kind FROM backlog_completion_receipts),
                (SELECT completion_kind FROM backlog_completion_receipts),
                (SELECT consumer_kind FROM model_call_usage_accounting)
            """
        ).fetchone()
    assert row is not None
    assert row[0] != row[1]
    assert tuple(row[3:]) == ("SUCCESS", "SCREENING_RESULT", "SCREENING_RESULT")

    with _live_reader(database) as reader:
        plan = _plan_from_reader(reader, inputs)

    assert len(plan.call_graphs) == 1
    assert plan.call_graphs[0].observation.result_kind == (M6LockedModelCallResultKind.RESPONSE)
    assert plan.call_graphs[0].claim_takeover_count == 1
    assert plan.call_graphs[0].failure is None
    assert len(plan.historical_failures) == 1
    assert plan.historical_failures[0].claim_takeover_count == 0
    assert plan.historical_failures[0].authority_id == row[2]
    assert plan.historical_failures[0].closure_kind == "INITIAL_BACKLOG"
    assert all(
        reference.artifact_id != plan.historical_failures[0].authority_id
        for reference in plan.planned_artifact_refs
    )
    assert plan.planned_document_bytes == sum(
        slot.document_bytes for slot in plan.document_slots
    ) + sum(slot.document_bytes for slot in plan.support_document_slots) + sum(
        history.document_bytes for history in plan.historical_failures
    )


@pytest.mark.parametrize("mutation", ["missing", "duplicate"])
def test_retry_success_requires_exactly_one_completion_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    database = _fixture_database(tmp_path, "known_failure_retry_response")
    inputs = _stored_plan_inputs(database)
    authority = _authority_snapshot(database, inputs)
    if mutation == "missing":
        _delete_success_completion(database)
    else:
        original = support_subject.read_backlog_success_completion_for_revision  # type: ignore[attr-defined]

        def duplicate_success_completion(
            connection: M6LiveReader,
            *,
            run_id: str,
            case_id: str,
            case_revision: int,
        ) -> tuple[sqlite3.Row, ...]:
            rows = original(
                connection,
                run_id=run_id,
                case_id=case_id,
                case_revision=case_revision,
            )
            assert len(rows) == 1
            return (*rows, rows[0])

        monkeypatch.setattr(
            support_subject,
            "read_backlog_success_completion_for_revision",
            duplicate_success_completion,
        )

    with (
        _live_reader(database) as reader,
        pytest.raises(M6SQLiteM3ModelDocumentError) as raised,
    ):
        _plan_from_reader(
            reader,
            inputs,
            selected_case_authority=authority,
        )

    assert raised.value.reason_code == M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH


def test_repair_failure_retry_success_binds_structure_repair_backlog_role(
    tmp_path: Path,
) -> None:
    database = _fixture_database(tmp_path, "known_repair_failure_retry_response")
    inputs = _stored_plan_inputs(database)
    with sqlite3.connect(database) as connection:
        stored = connection.execute(
            """
            SELECT
                (SELECT role FROM backlog_items),
                (SELECT purpose FROM model_call_failure_authorities),
                (SELECT COUNT(*) FROM backlog_completion_receipts
                 WHERE outcome_kind = 'SUCCESS'),
                (SELECT COUNT(*) FROM model_call_usage_accounting
                 WHERE consumer_kind = 'BACKLOG_ITEM'),
                (SELECT COUNT(*) FROM model_call_usage_accounting
                 WHERE consumer_kind = 'SCREENING_RESULT')
            """
        ).fetchone()
    assert stored == ("STRUCTURE_REPAIR", "STRUCTURE_REPAIR", 1, 1, 1)

    with _live_reader(database) as reader:
        plan = _plan_from_reader(reader, inputs)

    assert len(plan.historical_failures) == 1
    assert plan.historical_failures[0].claim_takeover_count == 0
    assert any(graph.purpose == "STRUCTURE_REPAIR" for graph in plan.call_graphs)


def test_two_generation_failure_selects_current_epoch_and_binds_older_history(
    tmp_path: Path,
) -> None:
    database = _fixture_database(tmp_path, "two_generation_failure")
    inputs = _stored_plan_inputs(database)
    assert len(inputs.observations) == 1
    with sqlite3.connect(database) as connection:
        stored_failures = tuple(
            connection.execute(
                """
                SELECT claim_takeover_count, authority_id
                FROM model_call_failure_authorities
                ORDER BY claim_takeover_count
                """
            )
        )
    assert len(stored_failures) == 2

    with _live_reader(database) as reader:
        plan = _plan_from_reader(reader, inputs)

    graph = plan.call_graphs[0]
    assert graph.observation.result_kind == M6LockedModelCallResultKind.FAILURE
    assert graph.claim_takeover_count == 1
    assert graph.failure is not None
    assert len(plan.historical_failures) == 1
    history = plan.historical_failures[0]
    assert (history.claim_takeover_count, history.closure_kind) == (0, "INITIAL_BACKLOG")
    assert (history.claim_takeover_count, history.authority_id) == stored_failures[0]
    assert (graph.claim_takeover_count, graph.failure.artifact_id) == stored_failures[1]
    assert history.authority_id != graph.failure.artifact_id
    assert any(
        reference.artifact_id == graph.failure.artifact_id
        for reference in plan.planned_artifact_refs
    )
    assert all(
        reference.artifact_id != history.authority_id for reference in plan.planned_artifact_refs
    )
    assert len(plan.support_document_slots) == 1


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("claim_takeover_count", 2),
        ("closure_case_revision", 999),
    ],
)
def test_two_generation_failure_rejects_future_epoch_or_tampered_history(
    tmp_path: Path,
    column: str,
    value: object,
) -> None:
    database = _fixture_database(tmp_path, "two_generation_failure")
    inputs = _stored_plan_inputs(database)
    authority = _authority_snapshot(database, inputs)
    _mutate_oldest_failure_scalar(database, column=column, value=value)

    with (
        _live_reader(database) as reader,
        pytest.raises(M6SQLiteM3ModelDocumentError) as raised,
    ):
        _plan_from_reader(
            reader,
            inputs,
            selected_case_authority=authority,
        )

    assert raised.value.reason_code == (M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)


def test_retry_response_rejects_a_missing_historical_failure_epoch(
    tmp_path: Path,
) -> None:
    database = _fixture_database(tmp_path, "known_failure_retry_response")
    inputs = _stored_plan_inputs(database)
    authority = _authority_snapshot(database, inputs)
    _delete_oldest_failure(database)

    with (
        _live_reader(database) as reader,
        pytest.raises(M6SQLiteM3ModelDocumentError) as raised,
    ):
        _plan_from_reader(
            reader,
            inputs,
            selected_case_authority=authority,
        )

    assert raised.value.reason_code == M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH


@pytest.mark.parametrize(
    ("shape", "terminal_failure_count", "historical_failure_count"),
    [
        ("response", 0, 0),
        ("failure", 1, 0),
        ("repair", 0, 0),
        ("initial_model_output_invalid", 0, 0),
        ("shared_receipt", 0, 0),
        ("known_failure_retry_response", 0, 1),
        ("known_repair_failure_retry_response", 0, 1),
        ("two_generation_failure", 1, 1),
    ],
)
def test_public_resolver_closes_every_real_m3_body_on_the_same_live_reader(
    tmp_path: Path,
    shape: str,
    terminal_failure_count: int,
    historical_failure_count: int,
) -> None:
    database = _fixture_database(tmp_path, shape)
    inputs = _stored_plan_inputs(database)

    with _live_reader(database) as reader:
        plan, snapshot = _plan_and_resolve_from_reader(reader, inputs)

    _assert_resolved_snapshot_exactly_closes_plan(plan, snapshot)
    assert len(snapshot.failures) == terminal_failure_count
    assert len(plan.historical_failures) == historical_failure_count
    terminal_failure_ids = {value.authority.authority_id for value in snapshot.failures}
    historical_failure_ids = {value.authority_id for value in plan.historical_failures}
    assert terminal_failure_ids.isdisjoint(historical_failure_ids)
    assert terminal_failure_ids == {
        graph.failure.artifact_id for graph in plan.call_graphs if graph.failure is not None
    }
    if plan.historical_failures:
        with sqlite3.connect(database) as connection:
            stored_history = {
                (cast(int, row[0]), cast(str, row[1])): (
                    cast(str, row[2]),
                    len(cast(str, row[3]).encode("utf-8")),
                )
                for row in connection.execute(
                    """
                    SELECT rowid, authority_id, document_sha256, authority_json
                    FROM model_call_failure_authorities
                    WHERE claim_takeover_count < (
                        SELECT takeover_count FROM model_call_claims
                        WHERE request_id = model_call_failure_authorities.request_id
                    )
                    """
                )
            }
        assert {
            (value.rowid, value.authority_id): (
                value.document_sha256,
                value.document_bytes,
            )
            for value in plan.historical_failures
        } == stored_history


def test_resolver_validates_shared_completion_receipt_response_refs_exactly(
    tmp_path: Path,
) -> None:
    database = _fixture_database(tmp_path, "shared_receipt")
    inputs = _stored_plan_inputs(database)
    with sqlite3.connect(database) as connection:
        receipt_row = connection.execute(
            "SELECT receipt_json FROM backlog_completion_receipts"
        ).fetchone()
        if receipt_row is None:
            raise AssertionError("shared-receipt fixture has no completion receipt")
        receipt_body = cast(str, receipt_row[0])
        usage_response_ids = {
            cast(str, row[0])
            for row in connection.execute("SELECT response_id FROM model_call_usage_accounting")
        }
    payload = cast(dict[str, object], json.loads(receipt_body))
    outcome = cast(dict[str, object], payload["outcome"])
    response_refs = cast(list[dict[str, str]], outcome["response_refs"])
    assert {value["artifact_id"] for value in response_refs} == usage_response_ids

    with _live_reader(database) as reader:
        plan, snapshot = _plan_and_resolve_from_reader(reader, inputs)

    assert len(plan.support_document_slots) == 1
    support_document = plan.support_document_slots[0]
    assert (
        support_document.document_sha256 == hashlib.sha256(receipt_body.encode("utf-8")).hexdigest()
    )
    assert support_document.document_bytes == len(receipt_body.encode("utf-8"))
    _assert_resolved_snapshot_exactly_closes_plan(plan, snapshot)


@pytest.mark.parametrize("mutation", ["missing", "extra", "foreign"])
def test_resolver_rejects_missing_extra_or_foreign_completion_response_refs(
    tmp_path: Path,
    mutation: str,
) -> None:
    database = _fixture_database(tmp_path, "shared_receipt")
    inputs = _stored_plan_inputs(database)
    _mutate_completion_response_refs(database, mutation)

    with _live_reader(database) as reader:
        plan = _plan_from_reader(reader, inputs)
        assert len(plan.support_document_slots) == 1
        with pytest.raises(M6SQLiteM3ModelDocumentError) as raised:
            resolve_m6_sqlite_m3_model_documents(
                connection=reader,
                metadata_plan=plan,
            )

    assert raised.value.reason_code == M6SQLiteM3ModelDocumentFailureCode.DOCUMENT_INVALID


@pytest.mark.parametrize("mutation", ["missing", "extra", "foreign"])
def test_resolver_rejects_canonical_cross_consumer_success_receipt_ref_attacks(
    tmp_path: Path,
    mutation: str,
) -> None:
    database = _fixture_database(tmp_path, "known_repair_failure_retry_response")
    inputs = _stored_plan_inputs(database)
    _mutate_success_completion_response_refs_canonically(database, mutation)

    with _live_reader(database) as reader:
        plan = _plan_from_reader(reader, inputs)
        assert len(plan.call_graphs) == 2
        assert len(plan.historical_failures) == 1
        assert len(plan.support_document_slots) == 1
        with pytest.raises(M6SQLiteM3ModelDocumentError) as raised:
            resolve_m6_sqlite_m3_model_documents(
                connection=reader,
                metadata_plan=plan,
            )

    assert raised.value.reason_code == (M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)


def test_resolver_reads_and_rejects_tampered_historical_failure_body(
    tmp_path: Path,
) -> None:
    database = _fixture_database(tmp_path, "known_failure_retry_response")
    inputs = _stored_plan_inputs(database)
    _tamper_oldest_failure_body_only(database)

    with _live_reader(database) as reader:
        plan = _plan_from_reader(reader, inputs)
        assert len(plan.historical_failures) == 1
        with pytest.raises(M6SQLiteM3ModelDocumentError) as raised:
            resolve_m6_sqlite_m3_model_documents(
                connection=reader,
                metadata_plan=plan,
            )

    assert raised.value.reason_code == M6SQLiteM3ModelDocumentFailureCode.DOCUMENT_INVALID


def test_resolver_replays_metadata_before_bodies_without_opening_another_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _fixture_database(tmp_path, "shared_receipt")
    inputs = _stored_plan_inputs(database)
    statements: list[str] = []
    reader_open_count = 0
    original_open = live_cut_subject._open_committed_reader
    original_execute = M6LiveReader.execute

    def tracked_open(database_path: Path, busy_timeout_ms: int) -> sqlite3.Connection:
        nonlocal reader_open_count
        reader_open_count += 1
        return original_open(database_path, busy_timeout_ms)

    def tracked_execute(
        self: M6LiveReader,
        statement: str,
        parameters: tuple[object, ...] | dict[str, object] = (),
    ) -> M6LiveCursor:
        statements.append(statement)
        return original_execute(self, statement, parameters)

    def forbidden_raw_read(_path: Path) -> NoReturn:
        raise AssertionError("M3 canonical resolver must not read Raw or Pixel files")

    monkeypatch.setattr(live_cut_subject, "_open_committed_reader", tracked_open)
    monkeypatch.setattr(M6LiveReader, "execute", tracked_execute)
    monkeypatch.setattr(Path, "read_bytes", forbidden_raw_read)
    with _live_reader(database) as reader:
        plan = _plan_from_reader(reader, inputs)
        statements.clear()
        snapshot = resolve_m6_sqlite_m3_model_documents(
            connection=reader,
            metadata_plan=plan,
        )
        assert reader.in_transaction

    first_body_read = next(
        index for index, statement in enumerate(statements) if _contains_body_value_read(statement)
    )
    metadata_prefix = "\n".join(statements[:first_body_read]).lower()
    assert reader_open_count == 1
    assert "typeof(request_json)" in metadata_prefix
    assert "octet_length(request_json)" in metadata_prefix
    assert not any(
        re.search(r"\b(?:frames|detections)\b", statement, re.IGNORECASE)
        for statement in statements
    )
    _assert_resolved_snapshot_exactly_closes_plan(plan, snapshot)


@pytest.mark.parametrize("mode", ["invalid_connection", "spoofed_plan", "unexpected"])
def test_public_resolver_argument_failures_are_fresh_typed_and_payload_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    database = _fixture_database(tmp_path, "failure")
    inputs = _stored_plan_inputs(database)
    secret = f"private-resolver-{mode}-payload-550011"

    with _live_reader(database) as reader:
        plan = _plan_from_reader(reader, inputs)
        connection = reader
        metadata_plan = plan
        if mode == "invalid_connection":
            connection = cast(M6LiveReader, secret)
        elif mode == "spoofed_plan":
            metadata_plan = cast(M6SQLiteM3ModelDocumentsPlan, secret)
        else:

            def explode(**_arguments: object) -> M6M3ModelCallAuthoritySnapshot:
                raise RuntimeError(secret)

            monkeypatch.setattr(
                documents_subject,
                "build_m6_sqlite_m3_model_call_authority_snapshot",
                explode,
            )
        with pytest.raises(M6SQLiteM3ModelDocumentError) as raised:
            resolve_m6_sqlite_m3_model_documents(
                connection=connection,
                metadata_plan=metadata_plan,
            )

    error = raised.value
    rendered = "".join(traceback.format_exception(error))
    assert error.reason_code == (
        M6SQLiteM3ModelDocumentFailureCode.DATABASE_REJECTED
        if mode == "unexpected"
        else M6SQLiteM3ModelDocumentFailureCode.INVALID_ARGUMENT
    )
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.__suppress_context__
    assert secret not in str(error)
    assert secret not in rendered
    assert "RuntimeError" not in rendered
    assert set(vars(error)) <= {"reason_code"}


def test_old_sqlite_blob_length_fallback_produces_the_exact_same_metadata_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _fixture_database(tmp_path, "shared_receipt")
    inputs = _stored_plan_inputs(database)
    with _live_reader(database) as reader:
        native_plan = _plan_from_reader(reader, inputs)

    fallback_calls: list[M6LiveDocumentColumn] = []
    original = M6LiveReader.document_octet_length

    def tracked_document_octet_length(
        self: M6LiveReader,
        column: M6LiveDocumentColumn,
        rowid: int,
    ) -> int:
        fallback_calls.append(column)
        return original(self, column, rowid)

    monkeypatch.setattr(rows_subject, "_USE_SQLITE_OCTET_LENGTH", False)
    monkeypatch.setattr(
        M6LiveReader,
        "document_octet_length",
        tracked_document_octet_length,
    )
    with _live_reader(database) as reader:
        fallback_plan = _plan_from_reader(reader, inputs)

    expected_routes = Counter(slot.route.value for slot in native_plan.document_slots)
    expected_routes.update(slot.route.value for slot in native_plan.support_document_slots)
    assert Counter(column.value for column in fallback_calls) == expected_routes
    assert fallback_plan == native_plan
    assert fallback_plan.plan_identity_sha256 == native_plan.plan_identity_sha256
    assert tuple(slot.index_identity_sha256 for slot in fallback_plan.document_slots) == tuple(
        slot.index_identity_sha256 for slot in native_plan.document_slots
    )
    assert tuple(
        slot.index_identity_sha256 for slot in fallback_plan.support_document_slots
    ) == tuple(slot.index_identity_sha256 for slot in native_plan.support_document_slots)


def test_metadata_planner_sql_reads_only_type_length_and_scalar_commitments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _fixture_database(tmp_path, "shared_receipt")
    inputs = _stored_plan_inputs(database)
    statements: list[str] = []
    guarded_statements: list[str] = []
    length_calls: list[M6LiveDocumentColumn] = []
    armed = False
    original_open = live_cut_subject._open_committed_reader
    original_execute = M6LiveReader.execute
    original_length = M6LiveReader.document_octet_length

    def traced_open(database_path: Path, busy_timeout_ms: int) -> sqlite3.Connection:
        connection = original_open(database_path, busy_timeout_ms)
        connection.set_trace_callback(statements.append)
        return connection

    def guarded_execute(
        self: M6LiveReader,
        statement: str,
        parameters: tuple[object, ...] | dict[str, object] = (),
    ) -> M6LiveCursor:
        if armed:
            guarded_statements.append(statement)
            assert not _contains_body_value_read(statement)
            assert re.search(r"\b(?:frames|detections)\b", statement, re.IGNORECASE) is None
        return original_execute(self, statement, parameters)

    def tracked_length(
        self: M6LiveReader,
        column: M6LiveDocumentColumn,
        rowid: int,
    ) -> int:
        if armed:
            length_calls.append(column)
        return original_length(self, column, rowid)

    monkeypatch.setattr(live_cut_subject, "_open_committed_reader", traced_open)
    monkeypatch.setattr(M6LiveReader, "execute", guarded_execute)
    monkeypatch.setattr(M6LiveReader, "document_octet_length", tracked_length)
    with _live_reader(database) as reader:
        authority = _selected_case_authority(reader, inputs)
        statements.clear()
        armed = True
        plan = _plan_from_reader(
            reader,
            inputs,
            selected_case_authority=authority,
        )
        armed = False

    traced_sql = "\n".join(statements)
    assert guarded_statements
    assert not _contains_body_value_read(traced_sql)
    assert all(column in traced_sql.lower() for column in _BODY_COLUMNS)
    assert "backlog_completion_receipts" in traced_sql.lower()
    assert "typeof(receipt_json)" in traced_sql.lower()
    assert "octet_length(receipt_json)" in traced_sql.lower()
    assert length_calls == []
    assert len(plan.support_document_slots) == 1


@pytest.mark.parametrize(
    ("mode", "expected_code"),
    [
        ("invalid", M6SQLiteM3ModelDocumentFailureCode.INVALID_ARGUMENT),
        ("spoof", M6SQLiteM3ModelDocumentFailureCode.INVALID_ARGUMENT),
        ("unexpected", M6SQLiteM3ModelDocumentFailureCode.DATABASE_REJECTED),
    ],
)
def test_public_failures_are_typed_strict_and_payload_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected_code: M6SQLiteM3ModelDocumentFailureCode,
) -> None:
    database = _fixture_database(tmp_path, "failure")
    inputs = _stored_plan_inputs(database)
    secret = f"private-{mode}-payload-998877"

    with _live_reader(database) as reader:
        authority = _selected_case_authority(reader, inputs)
        selected_authority = authority
        manifest_id = inputs.manifest_id
        if mode == "invalid":
            manifest_id = secret
        elif mode == "spoof":
            selected_authority = cast(M6SQLiteCaseAuthorityDocument, object())
        else:

            def explode(**_arguments: object) -> M6SQLiteM3ModelDocumentsPlan:
                raise RuntimeError(secret)

            monkeypatch.setattr(
                documents_subject,
                "build_m6_sqlite_m3_model_documents_plan",
                explode,
            )
        with pytest.raises(M6SQLiteM3ModelDocumentError) as raised:
            _plan_from_reader(
                reader,
                inputs,
                selected_case_authority=selected_authority,
                expected_manifest_id=manifest_id,
            )

    error = raised.value
    rendered = "".join(traceback.format_exception(error))
    assert error.reason_code == expected_code
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.__suppress_context__
    assert secret not in str(error)
    assert secret not in rendered
    assert "RuntimeError" not in rendered
    assert set(vars(error)) <= {"reason_code"}
    with pytest.raises(TypeError):
        M6SQLiteM3ModelDocumentError(cast(M6SQLiteM3ModelDocumentFailureCode, "INVALID_ARGUMENT"))


def test_public_planner_maps_the_257th_sqlite_row_sentinel_to_typed_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _fixture_database(tmp_path, "failure")
    inputs = _stored_plan_inputs(database)

    def oversized_primary_rows(
        connection: M6LiveReader,
        *,
        run_id: str,
        case_id: str,
    ) -> NoReturn:
        del run_id, case_id
        boundary = rows_subject._rows(
            connection,
            """
            SELECT first.rowid
            FROM sqlite_schema AS first
            CROSS JOIN sqlite_schema AS second
            ORDER BY first.rowid, second.rowid
            LIMIT 256
            """,
            (),
        )
        assert len(boundary) == 256
        rows_subject._rows(
            connection,
            """
            SELECT first.rowid
            FROM sqlite_schema AS first
            CROSS JOIN sqlite_schema AS second
            ORDER BY first.rowid, second.rowid
            LIMIT 257
            """,
            (),
        )
        raise AssertionError("257-row sentinel did not reject the oversized group")

    monkeypatch.setattr(metadata_subject, "read_primary_rows", oversized_primary_rows)
    with (
        _live_reader(database) as reader,
        pytest.raises(M6SQLiteM3ModelDocumentError) as raised,
    ):
        _plan_from_reader(reader, inputs)

    assert raised.value.reason_code == M6SQLiteM3ModelDocumentFailureCode.ROW_LIMIT_EXCEEDED


@pytest.mark.parametrize(
    ("shape", "table", "column", "value", "expected_code"),
    [
        (
            "failure",
            "model_call_claims",
            "manifest_id",
            _sha("foreign-scope-manifest"),
            M6SQLiteM3ModelDocumentFailureCode.SCOPE_MISMATCH,
        ),
        (
            "failure",
            "model_call_claims",
            "model_manifest_id",
            _sha("foreign-model-manifest"),
            M6SQLiteM3ModelDocumentFailureCode.SCOPE_MISMATCH,
        ),
        (
            "failure",
            "evidence_packs",
            "document_sha256",
            _sha("foreign-selected-pack-document"),
            M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
        (
            "failure",
            "case_versions",
            "document_sha256",
            _sha("foreign-case-document"),
            M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
        (
            "shared_receipt",
            "backlog_completion_receipts",
            "completion_audit_entry_hash",
            _sha("foreign-completion-audit-entry"),
            M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
    ],
)
def test_public_planner_rejects_scope_model_pack_case_and_support_scalar_corruption(
    tmp_path: Path,
    shape: str,
    table: str,
    column: str,
    value: object,
    expected_code: M6SQLiteM3ModelDocumentFailureCode,
) -> None:
    database = _fixture_database(tmp_path, shape)
    inputs = _stored_plan_inputs(database)
    authority = _authority_snapshot(database, inputs)
    _mutate_all_scalar_rows(
        database,
        table=table,
        column=column,
        value=value,
    )

    with (
        _live_reader(database) as reader,
        pytest.raises(M6SQLiteM3ModelDocumentError) as raised,
    ):
        _plan_from_reader(
            reader,
            inputs,
            selected_case_authority=authority,
        )

    assert raised.value.reason_code == expected_code

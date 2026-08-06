from __future__ import annotations

import hashlib
import sqlite3
from typing import cast

import pytest

from labcourt.adapters.storage import _sqlite_m6_upgrade_m4_model_graph as subject
from labcourt.adapters.storage import _sqlite_m6_upgrade_m4_model_rows as rows_subject
from labcourt.adapters.storage._sqlite_m6_live_read_cut import M6LiveReader
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_plan import (
    M6SQLiteM4ClaimStatus,
    M6SQLiteM4ModelDocumentFailureCode,
    M6SQLiteM4RoleModelManifestBinding,
    _M6SQLiteM4MetadataFailure,
)
from labcourt.contracts.enums import ModelParseStatus
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_observation import M6UpgradeObservedModelCall


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _row(**values: object) -> sqlite3.Row:
    return cast(sqlite3.Row, values)


def _reader() -> M6LiveReader:
    return cast(M6LiveReader, object())


RUN_ID = "run-1"
CASE_ID = "case-1"
MANIFEST_ID = _sha("manifest")
REQUEST_ID = _sha("request")
REQUEST_SHA256 = _sha("request semantic")
REQUEST_DOCUMENT_SHA256 = _sha("request document")
CACHE_KEY = _sha("cache key")
HEARING_ID = _sha("hearing")
CYCLE_ID = _sha("cycle")
CYCLE_SHA256 = _sha("cycle semantic")
PACK_ID = _sha("pack")
MODEL_ID = _sha("prosecutor model")
PROMPT_ID = _sha("prompt")
RESPONSE_ID = _sha("response")
RESPONSE_CONTENT = _sha("raw response")
CACHE_ENTRY_ID = _sha("cache entry")
SCHEMA_SHA256 = _sha("output schema")
RECEIPT_ID = _sha("parse receipt")
OUTPUT_ID = _sha("output")
RETRIEVAL_ID = _sha("retrieval")
RETRIEVAL_COMMITMENT = _sha("retrieval semantic")
USAGE_ID = _sha("usage")


def _observation(
    result_kind: M6LockedModelCallResultKind = M6LockedModelCallResultKind.RESPONSE,
) -> M6UpgradeObservedModelCall:
    return M6UpgradeObservedModelCall(
        request_id=REQUEST_ID,
        layer=M6LockedModelCallLayer.HEARING,
        role=M6LockedModelRole.PROSECUTOR,
        attempt_index=0,
        result_kind=result_kind,
        provider_invoked=True,
    )


def _role_bindings() -> tuple[M6SQLiteM4RoleModelManifestBinding, ...]:
    return (
        M6SQLiteM4RoleModelManifestBinding(
            role=M6LockedModelRole.PROSECUTOR,
            model_manifest_id=MODEL_ID,
        ),
        M6SQLiteM4RoleModelManifestBinding(
            role=M6LockedModelRole.DEFENDER,
            model_manifest_id=_sha("defender model"),
        ),
        M6SQLiteM4RoleModelManifestBinding(
            role=M6LockedModelRole.JUDGE,
            model_manifest_id=_sha("judge model"),
        ),
    )


def _claim_row(**updates: object) -> sqlite3.Row:
    values: dict[str, object] = {
        "document_rowid": 1,
        "run_id": RUN_ID,
        "request_id": REQUEST_ID,
        "request_sha256": REQUEST_SHA256,
        "cache_key": CACHE_KEY,
        "hearing_id": HEARING_ID,
        "cycle_scope_id": CYCLE_ID,
        "cycle_scope_sha256": CYCLE_SHA256,
        "case_id": CASE_ID,
        "role": "PROSECUTOR",
        "purpose": "ROLE_CALL",
        "attempt_index": 0,
        "call_generation": "INITIAL",
        "backlog_item_id": None,
        "retry_generation": 0,
        "reserved_images": 3,
        "reserved_pixels": 300,
        "evidence_pack_id": PACK_ID,
        "evidence_pack_version": 2,
        "model_manifest_id": MODEL_ID,
        "prompt_manifest_id": PROMPT_ID,
        "manifest_id": MANIFEST_ID,
        "request_document_sha256": REQUEST_DOCUMENT_SHA256,
        "status": "COMPLETED",
        "owner_token_sha256": _sha("owner"),
        "lease_expires_at": "2026-01-01T00:00:00.000000Z",
        "takeover_count": 0,
        "created_at": "2026-01-01T00:00:00.000000Z",
        "response_id": RESPONSE_ID,
        "completed_at": "2026-01-01T00:00:01.000000Z",
        "request_document_type": "text",
        "request_document_bytes": 31,
    }
    values.update(updates)
    return _row(**values)


def _response_row(**updates: object) -> sqlite3.Row:
    values: dict[str, object] = {
        "document_rowid": 2,
        "run_id": RUN_ID,
        "response_id": RESPONSE_ID,
        "request_id": REQUEST_ID,
        "request_sha256": REQUEST_SHA256,
        "cache_key": CACHE_KEY,
        "hearing_id": HEARING_ID,
        "cycle_scope_id": CYCLE_ID,
        "cycle_scope_sha256": CYCLE_SHA256,
        "case_id": CASE_ID,
        "role": "PROSECUTOR",
        "purpose": "ROLE_CALL",
        "attempt_index": 0,
        "retry_generation": 0,
        "raw_response_ref": "fixture://response",
        "content_sha256": RESPONSE_CONTENT,
        "size_bytes": 43,
        "model_manifest_id": MODEL_ID,
        "manifest_id": MANIFEST_ID,
        "document_sha256": _sha("response document"),
        "response_document_type": "text",
        "response_document_bytes": 37,
    }
    values.update(updates)
    return _row(**values)


def _cache_row(**updates: object) -> sqlite3.Row:
    values: dict[str, object] = {
        "document_rowid": 3,
        "run_id": RUN_ID,
        "cache_key": CACHE_KEY,
        "cache_entry_id": CACHE_ENTRY_ID,
        "hearing_id": HEARING_ID,
        "cycle_scope_id": CYCLE_ID,
        "cycle_scope_sha256": CYCLE_SHA256,
        "case_id": CASE_ID,
        "role": "PROSECUTOR",
        "request_id": REQUEST_ID,
        "request_sha256": REQUEST_SHA256,
        "response_id": RESPONSE_ID,
        "response_content_sha256": RESPONSE_CONTENT,
        "model_manifest_id": MODEL_ID,
        "prompt_manifest_id": PROMPT_ID,
        "output_schema_sha256": SCHEMA_SHA256,
        "manifest_id": MANIFEST_ID,
        "request_document_sha256": REQUEST_DOCUMENT_SHA256,
        "document_sha256": _sha("cache document"),
        "cache_request_document_type": "text",
        "cache_request_document_bytes": 31,
        "cache_entry_document_type": "text",
        "cache_entry_document_bytes": 41,
    }
    values.update(updates)
    return _row(**values)


def _receipt_row(**updates: object) -> sqlite3.Row:
    values: dict[str, object] = {
        "document_rowid": 4,
        "run_id": RUN_ID,
        "parse_receipt_id": RECEIPT_ID,
        "hearing_id": HEARING_ID,
        "cycle_scope_id": CYCLE_ID,
        "cycle_scope_sha256": CYCLE_SHA256,
        "case_id": CASE_ID,
        "role": "PROSECUTOR",
        "request_id": REQUEST_ID,
        "request_sha256": REQUEST_SHA256,
        "response_id": RESPONSE_ID,
        "response_content_sha256": RESPONSE_CONTENT,
        "attempt_index": 0,
        "parser_version": "parser-v1",
        "output_schema_sha256": SCHEMA_SHA256,
        "status": "PARSED",
        "parsed_output_id": OUTPUT_ID,
        "repair_request_id": None,
        "manifest_id": MANIFEST_ID,
        "document_sha256": _sha("receipt document"),
        "receipt_document_type": "text",
        "receipt_document_bytes": 29,
    }
    values.update(updates)
    return _row(**values)


def _output_row(**updates: object) -> sqlite3.Row:
    values: dict[str, object] = {
        "document_rowid": 5,
        "run_id": RUN_ID,
        "parsed_output_id": OUTPUT_ID,
        "hearing_id": HEARING_ID,
        "cycle_scope_id": CYCLE_ID,
        "cycle_scope_sha256": CYCLE_SHA256,
        "case_id": CASE_ID,
        "prior_acquisition_rounds": 0,
        "prior_rework_rounds": 0,
        "current_pack_id": PACK_ID,
        "current_pack_version": 2,
        "role": "PROSECUTOR",
        "payload_kind": "PROSECUTION",
        "request_id": REQUEST_ID,
        "response_id": RESPONSE_ID,
        "parse_receipt_id": RECEIPT_ID,
        "response_content_sha256": RESPONSE_CONTENT,
        "output_schema_sha256": SCHEMA_SHA256,
        "prompt_manifest_id": PROMPT_ID,
        "model_manifest_id": MODEL_ID,
        "prosecutor_output_id": None,
        "defender_output_id": None,
        "precedent_retrieval_degraded": 0,
        "precedent_retrieval_receipt_id": RETRIEVAL_ID,
        "precedent_retrieval_receipt_sha256": RETRIEVAL_COMMITMENT,
        "initial_trigger_review_id": None,
        "rework_review_id": None,
        "payload_sha256": _sha("payload"),
        "manifest_id": MANIFEST_ID,
        "document_sha256": _sha("output document"),
        "output_document_type": "text",
        "output_document_bytes": 47,
    }
    values.update(updates)
    return _row(**values)


def _usage_row(**updates: object) -> sqlite3.Row:
    values: dict[str, object] = {
        "document_rowid": 6,
        "run_id": RUN_ID,
        "usage_receipt_id": USAGE_ID,
        "request_id": REQUEST_ID,
        "response_id": RESPONSE_ID,
        "hearing_id": HEARING_ID,
        "cycle_scope_id": CYCLE_ID,
        "cycle_scope_sha256": CYCLE_SHA256,
        "case_id": CASE_ID,
        "role": "PROSECUTOR",
        "accounted_at": "2026-01-01T00:00:01.000000Z",
        "input_images": 3,
        "input_pixels": 300,
        "input_tokens": 100,
        "output_tokens": 20,
        "provider_latency_ms": 200,
        "retries": 0,
        "estimated_cost": 0.1,
        "manifest_id": MANIFEST_ID,
        "document_sha256": _sha("usage document"),
        "usage_document_type": "text",
        "usage_document_bytes": 23,
    }
    values.update(updates)
    return _row(**values)


def _failure_row(*, epoch: int = 0, ordinal: int = 0, **updates: object) -> sqlite3.Row:
    values: dict[str, object] = {
        "document_rowid": 20 + ordinal,
        "run_id": RUN_ID,
        "authority_id": _sha(f"failure {ordinal}"),
        "request_id": REQUEST_ID,
        "request_sha256": REQUEST_SHA256,
        "request_document_sha256": _sha("failure request document"),
        "cache_key": CACHE_KEY,
        "hearing_id": HEARING_ID,
        "cycle_scope_id": CYCLE_ID,
        "cycle_scope_sha256": CYCLE_SHA256,
        "case_id": CASE_ID,
        "role": "PROSECUTOR",
        "source_checkpoint_id": _sha("checkpoint"),
        "source_checkpoint_sha256": _sha("checkpoint body"),
        "source_checkpoint_version": 1,
        "lease_identity_sha256": None,
        "lease_id": None,
        "backlog_attempt_count": 0,
        "retry_generation": 0,
        "claim_owner_sha256": _sha("owner"),
        "claim_lease_expires_at": "2026-01-01T00:00:00.000000Z",
        "claim_takeover_count": epoch,
        "failure_code": "PROVIDER_OUTAGE",
        "delivery_certainty": "DEFINITELY_NOT_SENT",
        "provider_response_content_sha256": None,
        "reserved_images": 3,
        "reserved_pixels": 300,
        "disclosed_images": 0,
        "disclosed_pixels": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "latency_ms": 0,
        "estimated_cost": 0.0,
        "backlog_item_id": _sha("backlog"),
        "backlog_reason_code": "PROVIDER_UNAVAILABLE",
        "backlog_version": 1,
        "backlog_status": "PENDING",
        "closure_kind": "INITIAL_BACKLOG",
        "completion_receipt_id": None,
        "closure_case_revision": 2,
        "closure_audit_sequence": 2,
        "closure_audit_entry_hash": _sha("closure audit"),
        "manifest_id": MANIFEST_ID,
        "recorded_at": "2026-01-01T00:00:02.000000Z",
        "document_sha256": _sha(f"failure document {ordinal}"),
        "failure_document_type": "text",
        "failure_document_bytes": 53,
    }
    values.update(updates)
    return _row(**values)


def _success_graph(
    monkeypatch: pytest.MonkeyPatch,
    *,
    claim_row: sqlite3.Row | None = None,
    cache_row: sqlite3.Row | None = None,
    output_row: sqlite3.Row | None = None,
    context_pack: tuple[str, int] = (PACK_ID, 2),
) -> object:
    monkeypatch.setattr(rows_subject, "_USE_SQLITE_OCTET_LENGTH", True)
    observations = (_observation(),)
    claims = subject._claims(
        _reader(),
        (claim_row or _claim_row(),),
        run_id=RUN_ID,
        case_id=CASE_ID,
        manifest_id=MANIFEST_ID,
        role_bindings=_role_bindings(),
        observations=observations,
    )
    responses = subject._responses(
        _reader(),
        (_response_row(),),
        run_id=RUN_ID,
        case_id=CASE_ID,
        manifest_id=MANIFEST_ID,
        claims=claims,
    )
    caches = subject._caches(
        _reader(),
        (cache_row or _cache_row(),),
        run_id=RUN_ID,
        case_id=CASE_ID,
        manifest_id=MANIFEST_ID,
        claims=claims,
        responses=responses,
    )
    receipts = subject._receipts(
        _reader(),
        (_receipt_row(),),
        run_id=RUN_ID,
        case_id=CASE_ID,
        manifest_id=MANIFEST_ID,
        claims=claims,
        responses=responses,
        caches=caches,
    )
    outputs = subject._outputs(
        _reader(),
        (output_row or _output_row(),),
        run_id=RUN_ID,
        case_id=CASE_ID,
        manifest_id=MANIFEST_ID,
        claims=claims,
        responses=responses,
        caches=caches,
        receipts=receipts,
    )
    usages = subject._usages(
        _reader(),
        (_usage_row(),),
        run_id=RUN_ID,
        case_id=CASE_ID,
        manifest_id=MANIFEST_ID,
        claims=claims,
        responses=responses,
    )
    contexts = {
        CYCLE_ID: subject._CycleContext(
            hearing_id=HEARING_ID,
            cycle_scope_id=CYCLE_ID,
            cycle_scope_sha256=CYCLE_SHA256,
            cycle_index=1,
            prior_acquisition_rounds=0,
            prior_rework_rounds=0,
            pack_key=context_pack,
            retrieval_receipt_id=RETRIEVAL_ID,
            retrieval_commitment_sha256=RETRIEVAL_COMMITMENT,
        )
    }
    return subject._build_response_graphs(
        claims,
        responses,
        caches,
        receipts,
        outputs,
        usages,
        contexts,
    )[0]


def test_complete_response_graph_closes_all_seven_physical_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph = _success_graph(monkeypatch)
    assert graph.claim_status == M6SQLiteM4ClaimStatus.COMPLETED
    assert graph.parse_status == ModelParseStatus.PARSED
    assert graph.retrieval_commitment_sha256 == RETRIEVAL_COMMITMENT
    assert len(graph.document_slots) == 7
    assert len(graph.artifact_refs) == 6
    assert graph.cache_request is not None and graph.cache_request.physical_ref is None


@pytest.mark.parametrize(
    "claim_row",
    (
        _claim_row(role="DEFENDER"),
        _claim_row(model_manifest_id=_sha("wrong model")),
        _claim_row(status="ACTIVE", response_id=None, completed_at=None),
    ),
)
def test_claim_must_match_observation_role_model_and_terminal_status(
    monkeypatch: pytest.MonkeyPatch,
    claim_row: sqlite3.Row,
) -> None:
    with pytest.raises(_M6SQLiteM4MetadataFailure) as caught:
        _success_graph(monkeypatch, claim_row=claim_row)
    assert (
        caught.value.reason_code == M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH
    )


def test_cache_request_must_be_the_same_committed_request_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(_M6SQLiteM4MetadataFailure) as caught:
        _success_graph(
            monkeypatch,
            cache_row=_cache_row(cache_request_document_bytes=32),
        )
    assert caught.value.reason_code == M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH


def test_output_must_bind_the_exact_cycle_retrieval_commitment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(_M6SQLiteM4MetadataFailure) as caught:
        _success_graph(
            monkeypatch,
            output_row=_output_row(precedent_retrieval_receipt_sha256=_sha("wrong retrieval")),
        )
    assert caught.value.reason_code == M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH


def test_graph_context_rejects_crossed_pack_even_after_valid_primary_joins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(_M6SQLiteM4MetadataFailure) as caught:
        _success_graph(monkeypatch, context_pack=(_sha("other pack"), 2))
    assert (
        caught.value.reason_code == M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH
    )


def test_current_failure_and_every_older_takeover_epoch_are_classified_exactly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rows_subject, "_USE_SQLITE_OCTET_LENGTH", True)
    observations = (_observation(M6LockedModelCallResultKind.FAILURE),)
    claims = subject._claims(
        _reader(),
        (
            _claim_row(
                status="ACTIVE",
                response_id=None,
                completed_at=None,
                takeover_count=2,
            ),
        ),
        run_id=RUN_ID,
        case_id=CASE_ID,
        manifest_id=MANIFEST_ID,
        role_bindings=_role_bindings(),
        observations=observations,
    )
    terminal, history = subject._failures(
        _reader(),
        (
            _failure_row(epoch=0, ordinal=0),
            _failure_row(epoch=1, ordinal=1),
            _failure_row(epoch=2, ordinal=2),
        ),
        run_id=RUN_ID,
        case_id=CASE_ID,
        manifest_id=MANIFEST_ID,
        claims=claims,
    )
    bindings = subject._historical_failure_bindings(history)
    graphs = subject._build_failure_graphs(
        claims,
        terminal,
        {
            CYCLE_ID: subject._CycleContext(
                hearing_id=HEARING_ID,
                cycle_scope_id=CYCLE_ID,
                cycle_scope_sha256=CYCLE_SHA256,
                cycle_index=1,
                prior_acquisition_rounds=0,
                prior_rework_rounds=0,
                pack_key=(PACK_ID, 2),
                retrieval_receipt_id=RETRIEVAL_ID,
                retrieval_commitment_sha256=RETRIEVAL_COMMITMENT,
            )
        },
    )
    assert tuple(value.claim_takeover_count for value in bindings) == (0, 1)
    assert tuple(value.authority_id for value in bindings) == tuple(
        value.failure_slot.artifact_id for value in history
    )
    assert len(graphs) == 1
    assert graphs[0].failure == terminal[REQUEST_ID].failure_slot
    assert len(graphs[0].artifact_refs) == 2
    assert all(
        binding.authority_id not in {ref.artifact_id for ref in graphs[0].artifact_refs}
        for binding in bindings
    )


@pytest.mark.parametrize(
    "rows",
    (
        (_failure_row(epoch=1, ordinal=1), _failure_row(epoch=2, ordinal=2)),
        (
            _failure_row(epoch=0, ordinal=0),
            _failure_row(epoch=0, ordinal=1),
            _failure_row(epoch=2, ordinal=2),
        ),
        (
            _failure_row(epoch=0, ordinal=0),
            _failure_row(epoch=1, ordinal=1),
            _failure_row(epoch=3, ordinal=3),
        ),
    ),
)
def test_failure_epoch_gaps_duplicates_and_future_rows_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    rows: tuple[sqlite3.Row, ...],
) -> None:
    monkeypatch.setattr(rows_subject, "_USE_SQLITE_OCTET_LENGTH", True)
    claims = subject._claims(
        _reader(),
        (
            _claim_row(
                status="ACTIVE",
                response_id=None,
                completed_at=None,
                takeover_count=2,
            ),
        ),
        run_id=RUN_ID,
        case_id=CASE_ID,
        manifest_id=MANIFEST_ID,
        role_bindings=_role_bindings(),
        observations=(_observation(M6LockedModelCallResultKind.FAILURE),),
    )
    with pytest.raises(_M6SQLiteM4MetadataFailure):
        subject._failures(
            _reader(),
            rows,
            run_id=RUN_ID,
            case_id=CASE_ID,
            manifest_id=MANIFEST_ID,
            claims=claims,
        )

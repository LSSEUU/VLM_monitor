"""Exact primary-row joins for body-free M3 model metadata."""

from __future__ import annotations

import hashlib
import sqlite3

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_replay_locked import M6LockedModelCallResultKind
from labcourt.contracts.m6_upgrade_execution_observation import M6UpgradeObservedModelCall
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactKind

from ._sqlite_m6_live_read_cut import M6LiveReader
from ._sqlite_m6_upgrade_case_document import M6SQLiteCaseAuthorityDocument
from ._sqlite_m6_upgrade_m3_model_plan import (
    M6SQLiteM3CallGraphPlan,
    M6SQLiteM3DocumentRoute,
    M6SQLiteM3HistoricalFailureBinding,
    M6SQLiteM3ModelDocumentFailureCode,
    M6SQLiteM3SelectedPackBinding,
    M6SQLiteM3SupportRoute,
)
from ._sqlite_m6_upgrade_m3_model_primitives import (
    _Cache,
    _Claim,
    _document_slot,
    _fail,
    _Failure,
    _integer,
    _is_sha256,
    _number,
    _optional_text,
    _Output,
    _Receipt,
    _Response,
    _row_identity,
    _sha256,
    _single,
    _text,
    _Usage,
)
from ._sqlite_m6_upgrade_m3_model_rows import read_pack_row
from ._sqlite_m6_upgrade_m3_model_support import _SupportResolver


def _require_scope(
    row: sqlite3.Row,
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    model_manifest_id: str | None = None,
) -> None:
    if (
        _text(row, "run_id") != run_id
        or _text(row, "case_id") != case_id
        or _text(row, "manifest_id") != manifest_id
        or (
            model_manifest_id is not None and _sha256(row, "model_manifest_id") != model_manifest_id
        )
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.SCOPE_MISMATCH)


def _pack_key(row: sqlite3.Row) -> tuple[str, int]:
    return (
        _sha256(row, "evidence_pack_id"),
        _integer(row, "evidence_pack_version", minimum=1),
    )


def _claims(
    connection: M6LiveReader,
    rows: tuple[sqlite3.Row, ...],
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    model_manifest_id: str,
    observations: tuple[M6UpgradeObservedModelCall, ...],
) -> dict[str, _Claim]:
    observation_by_id = {value.request_id: value for value in observations}
    row_request_ids = tuple(_sha256(row, "request_id") for row in rows)
    if row_request_ids != tuple(sorted(row_request_ids)) or len(row_request_ids) != len(
        set(row_request_ids)
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    if set(row_request_ids) != set(observation_by_id):
        _fail(M6SQLiteM3ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    claims: dict[str, _Claim] = {}
    for row, request_id in zip(rows, row_request_ids, strict=True):
        _require_scope(
            row,
            run_id=run_id,
            case_id=case_id,
            manifest_id=manifest_id,
            model_manifest_id=model_manifest_id,
        )
        observation = observation_by_id[request_id]
        purpose = _text(row, "purpose")
        expected_purpose = "SCREENING" if observation.attempt_index == 0 else "STRUCTURE_REPAIR"
        if purpose != expected_purpose:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        request_sha256 = _sha256(row, "request_sha256")
        cache_key = _sha256(row, "cache_key")
        request_document_sha256 = _sha256(row, "request_document_sha256")
        status = _text(row, "status")
        response_id = _optional_text(row, "response_id")
        completed_at = _optional_text(row, "completed_at")
        _sha256(row, "owner_token_sha256")
        _text(row, "lease_expires_at")
        takeover_count = _integer(row, "takeover_count")
        _text(row, "created_at")
        if status == "ACTIVE":
            if response_id is not None or completed_at is not None:
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        elif status == "COMPLETED":
            if response_id is None or not _is_sha256(response_id) or completed_at is None:
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        else:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        slot = _document_slot(
            connection,
            row,
            route=M6SQLiteM3DocumentRoute.MODEL_REQUEST,
            artifact_id=request_id,
            document_sha256=request_document_sha256,
            kind=M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
        )
        claims[request_id] = _Claim(
            row=row,
            observation=observation,
            request_id=request_id,
            request_sha256=request_sha256,
            cache_key=cache_key,
            pack_key=_pack_key(row),
            purpose=purpose,
            takeover_count=takeover_count,
            request_slot=slot,
        )
    return claims


def _selected_packs(
    connection: M6LiveReader,
    resolver: _SupportResolver,
    authority: M6SQLiteCaseAuthorityDocument,
    claims: dict[str, _Claim],
) -> tuple[M6SQLiteM3SelectedPackBinding, ...]:
    embedded_by_key = {(pack.pack_id, pack.version): pack for pack in authority.case.evidence_packs}
    bindings: list[M6SQLiteM3SelectedPackBinding] = []
    for pack_key in sorted(
        {claim.pack_key for claim in claims.values()}, key=lambda key: (key[1], key[0])
    ):
        embedded = embedded_by_key.get(pack_key)
        if embedded is None:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        row = _single(
            read_pack_row(
                connection,
                run_id=resolver.run_id,
                case_id=resolver.case_id,
                pack_id=pack_key[0],
                version=pack_key[1],
            )
        )
        canonical_pack = canonical_json(embedded.model_dump(mode="json"))
        document_sha256 = hashlib.sha256(canonical_pack.encode("utf-8")).hexdigest()
        created_audit_sequence = _integer(row, "created_audit_sequence")
        indexed = (
            _text(row, "run_id"),
            _sha256(row, "pack_id"),
            _text(row, "case_id"),
            _sha256(row, "manifest_id"),
            _integer(row, "version", minimum=1),
            _integer(row, "complete"),
            _sha256(row, "pack_input_sha256"),
            _sha256(row, "closure_input_sha256"),
            _sha256(row, "document_sha256"),
        )
        expected = (
            resolver.run_id,
            embedded.pack_id,
            resolver.case_id,
            resolver.manifest_id,
            embedded.version,
            int(embedded.complete),
            embedded.pack_input_sha256,
            embedded.closure_input_sha256,
            document_sha256,
        )
        if (
            indexed != expected
            or created_audit_sequence > authority.candidate_case_binding.case_audit_sequence
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        resolver.add(
            row,
            M6SQLiteM3SupportRoute.EVIDENCE_PACK,
            f"{embedded.pack_id}:{embedded.version}",
        )
        bindings.append(
            M6SQLiteM3SelectedPackBinding(
                rowid=_integer(row, "support_rowid", minimum=1),
                pack_id=embedded.pack_id,
                version=embedded.version,
                document_sha256=document_sha256,
                created_audit_sequence=created_audit_sequence,
                index_identity_sha256=_row_identity(
                    row,
                    M6SQLiteM3SupportRoute.EVIDENCE_PACK.value,
                ),
            )
        )
    return tuple(bindings)


def _responses(
    connection: M6LiveReader,
    rows: tuple[sqlite3.Row, ...],
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    model_manifest_id: str,
    claims: dict[str, _Claim],
) -> dict[str, _Response]:
    responses: dict[str, _Response] = {}
    response_ids: set[str] = set()
    for row in rows:
        request_id = _sha256(row, "request_id")
        claim = claims.get(request_id)
        if claim is None or request_id in responses:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _require_scope(
            row,
            run_id=run_id,
            case_id=case_id,
            manifest_id=manifest_id,
            model_manifest_id=model_manifest_id,
        )
        response_id = _sha256(row, "response_id")
        content_sha256 = _sha256(row, "content_sha256")
        document_sha256 = _sha256(row, "document_sha256")
        raw_size = _integer(row, "size_bytes", minimum=1)
        if response_id in response_ids or not _text(row, "raw_response_ref"):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        response_ids.add(response_id)
        indexed = (
            _sha256(row, "request_sha256"),
            _sha256(row, "cache_key"),
            _pack_key(row),
            _text(row, "purpose"),
            _integer(row, "attempt_index"),
        )
        expected = (
            claim.request_sha256,
            claim.cache_key,
            claim.pack_key,
            claim.purpose,
            claim.observation.attempt_index,
        )
        if indexed != expected:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        if (
            _text(claim.row, "status") != "COMPLETED"
            or _optional_text(claim.row, "response_id") != response_id
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        slot = _document_slot(
            connection,
            row,
            route=M6SQLiteM3DocumentRoute.MODEL_RESPONSE,
            artifact_id=response_id,
            document_sha256=document_sha256,
            kind=M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
            content_sha256=content_sha256,
            physical_size_bytes=raw_size,
        )
        responses[request_id] = _Response(
            row=row,
            response_id=response_id,
            request_id=request_id,
            content_sha256=content_sha256,
            response_slot=slot,
        )
    return responses


def _caches(
    connection: M6LiveReader,
    rows: tuple[sqlite3.Row, ...],
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    model_manifest_id: str,
    claims: dict[str, _Claim],
    responses: dict[str, _Response],
) -> dict[str, _Cache]:
    caches: dict[str, _Cache] = {}
    entry_ids: set[str] = set()
    for row in rows:
        request_id = _sha256(row, "request_id")
        claim = claims.get(request_id)
        response = responses.get(request_id)
        if claim is None or response is None or request_id in caches:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _require_scope(
            row,
            run_id=run_id,
            case_id=case_id,
            manifest_id=manifest_id,
            model_manifest_id=model_manifest_id,
        )
        entry_id = _sha256(row, "cache_entry_id")
        if entry_id in entry_ids:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        entry_ids.add(entry_id)
        output_schema_sha256 = _sha256(row, "output_schema_sha256")
        indexed = (
            _sha256(row, "cache_key"),
            _sha256(row, "request_sha256"),
            _pack_key(row),
            _sha256(row, "response_id"),
            _sha256(row, "response_content_sha256"),
        )
        expected = (
            claim.cache_key,
            claim.request_sha256,
            claim.pack_key,
            response.response_id,
            response.content_sha256,
        )
        if indexed != expected:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _sha256(row, "prompt_manifest_id")
        request_slot = _document_slot(
            connection,
            row,
            route=M6SQLiteM3DocumentRoute.MODEL_CACHE_REQUEST,
            artifact_id=request_id,
            document_sha256=_sha256(row, "request_document_sha256"),
            kind=None,
        )
        cache_slot = _document_slot(
            connection,
            row,
            route=M6SQLiteM3DocumentRoute.MODEL_CACHE_ENTRY,
            artifact_id=entry_id,
            document_sha256=_sha256(row, "document_sha256"),
            kind=M6UpgradePhysicalArtifactKind.MODEL_CACHE,
        )
        caches[request_id] = _Cache(
            row=row,
            request_id=request_id,
            response_id=response.response_id,
            output_schema_sha256=output_schema_sha256,
            request_slot=request_slot,
            cache_slot=cache_slot,
        )
    return caches


def _receipts(
    connection: M6LiveReader,
    rows: tuple[sqlite3.Row, ...],
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    claims: dict[str, _Claim],
    responses: dict[str, _Response],
) -> dict[str, _Receipt]:
    receipts: dict[str, _Receipt] = {}
    receipt_ids: set[str] = set()
    for row in rows:
        request_id = _sha256(row, "request_id")
        claim = claims.get(request_id)
        response = responses.get(request_id)
        if claim is None or response is None or request_id in receipts:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _require_scope(
            row,
            run_id=run_id,
            case_id=case_id,
            manifest_id=manifest_id,
        )
        receipt_id = _sha256(row, "parse_receipt_id")
        if receipt_id in receipt_ids:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        receipt_ids.add(receipt_id)
        if (
            _pack_key(row) != claim.pack_key
            or _sha256(row, "response_id") != response.response_id
            or _integer(row, "attempt_index") != claim.observation.attempt_index
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        status = _text(row, "status")
        parsed_output_id = _optional_text(row, "parsed_output_id")
        parsed_output_sha256 = _optional_text(row, "parsed_output_sha256")
        repair_request_id = _optional_text(row, "repair_request_id")
        if status == "PARSED":
            if not _is_sha256(parsed_output_id) or not _is_sha256(parsed_output_sha256):
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            if repair_request_id is not None:
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        elif status == "REPAIR_REQUIRED":
            if (
                claim.observation.attempt_index != 0
                or parsed_output_id is not None
                or parsed_output_sha256 is not None
                or not _is_sha256(repair_request_id)
            ):
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        elif status == "INVALID_FINAL":
            if (
                claim.observation.attempt_index != 1
                or parsed_output_id is not None
                or parsed_output_sha256 is not None
                or repair_request_id is not None
            ):
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        else:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        receipts[request_id] = _Receipt(
            row=row,
            request_id=request_id,
            response_id=response.response_id,
            status=status,
            parsed_output_id=parsed_output_id,
            parsed_output_sha256=parsed_output_sha256,
            repair_request_id=repair_request_id,
            slot=_document_slot(
                connection,
                row,
                route=M6SQLiteM3DocumentRoute.MODEL_PARSE_RECEIPT,
                artifact_id=receipt_id,
                document_sha256=_sha256(row, "document_sha256"),
                kind=M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
            ),
        )
    return receipts


def _outputs(
    connection: M6LiveReader,
    rows: tuple[sqlite3.Row, ...],
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    claims: dict[str, _Claim],
    responses: dict[str, _Response],
    caches: dict[str, _Cache],
) -> dict[str, _Output]:
    outputs: dict[str, _Output] = {}
    output_ids: set[str] = set()
    for row in rows:
        request_id = _sha256(row, "request_id")
        claim = claims.get(request_id)
        response = responses.get(request_id)
        cache = caches.get(request_id)
        if claim is None or response is None or cache is None or request_id in outputs:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _require_scope(
            row,
            run_id=run_id,
            case_id=case_id,
            manifest_id=manifest_id,
        )
        output_id = _sha256(row, "parsed_output_id")
        if output_id in output_ids:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        output_ids.add(output_id)
        parsed_output_sha256 = _sha256(row, "parsed_output_sha256")
        if (
            _pack_key(row) != claim.pack_key
            or _sha256(row, "response_id") != response.response_id
            or _sha256(row, "response_content_sha256") != response.content_sha256
            or _sha256(row, "output_schema_sha256") != cache.output_schema_sha256
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _sha256(row, "model_payload_sha256")
        outputs[request_id] = _Output(
            row=row,
            request_id=request_id,
            response_id=response.response_id,
            parsed_output_id=output_id,
            parsed_output_sha256=parsed_output_sha256,
            slot=_document_slot(
                connection,
                row,
                route=M6SQLiteM3DocumentRoute.PARSED_SCREENING_OUTPUT,
                artifact_id=output_id,
                document_sha256=_sha256(row, "document_sha256"),
                kind=M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
            ),
        )
    return outputs


def _failures(
    connection: M6LiveReader,
    rows: tuple[sqlite3.Row, ...],
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    model_manifest_id: str,
    claims: dict[str, _Claim],
) -> tuple[dict[str, _Failure], tuple[_Failure, ...]]:
    terminal_failures: dict[str, _Failure] = {}
    historical_failures: list[_Failure] = []
    historical_epochs: dict[str, set[int]] = {}
    epoch_keys: set[tuple[str, int]] = set()
    authority_ids: set[str] = set()
    for row in rows:
        request_id = _sha256(row, "request_id")
        claim = claims.get(request_id)
        if claim is None:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _require_scope(
            row,
            run_id=run_id,
            case_id=case_id,
            manifest_id=manifest_id,
            model_manifest_id=model_manifest_id,
        )
        authority_id = _sha256(row, "authority_id")
        if authority_id in authority_ids:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        authority_ids.add(authority_id)
        claim_takeover_count = _integer(row, "claim_takeover_count")
        epoch_key = request_id, claim_takeover_count
        if epoch_key in epoch_keys or claim_takeover_count > claim.takeover_count:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        epoch_keys.add(epoch_key)
        indexed = (
            _sha256(row, "request_sha256"),
            _sha256(row, "cache_key"),
            _pack_key(row),
            _text(row, "purpose"),
        )
        expected = (
            claim.request_sha256,
            claim.cache_key,
            claim.pack_key,
            claim.purpose,
        )
        if indexed != expected:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _sha256(row, "request_document_sha256")
        claim_owner_sha256 = _sha256(row, "claim_owner_sha256")
        claim_lease_expires_at = _text(row, "claim_lease_expires_at")
        _text(row, "failure_code")
        _text(row, "delivery_certainty")
        _text(row, "recorded_at")
        failure = _Failure(
            row=row,
            request_id=request_id,
            authority_id=authority_id,
            claim_takeover_count=claim_takeover_count,
            slot=_document_slot(
                connection,
                row,
                route=M6SQLiteM3DocumentRoute.MODEL_CALL_FAILURE,
                artifact_id=authority_id,
                document_sha256=_sha256(row, "document_sha256"),
                kind=M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
            ),
        )
        if claim_takeover_count < claim.takeover_count:
            historical_failures.append(failure)
            historical_epochs.setdefault(request_id, set()).add(claim_takeover_count)
            continue
        if (
            claim.observation.result_kind != M6LockedModelCallResultKind.FAILURE
            or request_id in terminal_failures
            or _text(claim.row, "status") != "ACTIVE"
            or claim_owner_sha256 != _sha256(claim.row, "owner_token_sha256")
            or claim_lease_expires_at != _text(claim.row, "lease_expires_at")
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        terminal_failures[request_id] = failure
    for request_id, claim in claims.items():
        if historical_epochs.get(request_id, set()) != set(range(claim.takeover_count)):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return terminal_failures, tuple(historical_failures)


def _historical_failure_bindings(
    failures: tuple[_Failure, ...],
) -> tuple[M6SQLiteM3HistoricalFailureBinding, ...]:
    try:
        return tuple(
            M6SQLiteM3HistoricalFailureBinding(
                request_id=value.request_id,
                claim_takeover_count=value.claim_takeover_count,
                authority_id=value.authority_id,
                backlog_item_id=_sha256(value.row, "backlog_item_id"),
                backlog_version=_integer(value.row, "backlog_version", minimum=1),
                closure_kind=_text(value.row, "closure_kind"),
                closure_case_revision=_integer(
                    value.row,
                    "closure_case_revision",
                    minimum=1,
                ),
                rowid=value.slot.rowid,
                document_sha256=value.slot.document_sha256,
                document_bytes=value.slot.document_bytes,
                index_identity_sha256=value.slot.index_identity_sha256,
            )
            for value in failures
        )
    except (TypeError, ValueError):
        _fail(M6SQLiteM3ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)


def _usages(
    connection: M6LiveReader,
    rows: tuple[sqlite3.Row, ...],
    *,
    run_id: str,
    case_id: str,
    claims: dict[str, _Claim],
    responses: dict[str, _Response],
) -> dict[str, _Usage]:
    usages: dict[str, _Usage] = {}
    response_ids: set[str] = set()
    for row in rows:
        request_id = _sha256(row, "request_id")
        claim = claims.get(request_id)
        response = responses.get(request_id)
        if claim is None or response is None or request_id in usages:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        if _text(row, "run_id") != run_id or _text(row, "case_id") != case_id:
            _fail(M6SQLiteM3ModelDocumentFailureCode.SCOPE_MISMATCH)
        response_id = _sha256(row, "response_id")
        if response_id != response.response_id or response_id in response_ids:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        response_ids.add(response_id)
        consumer_kind = _text(row, "consumer_kind")
        consumer_id = _sha256(row, "consumer_id")
        if consumer_kind not in {"SCREENING_RESULT", "BACKLOG_ITEM"}:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        for column in (
            "input_images",
            "input_pixels",
            "input_tokens",
            "output_tokens",
            "provider_latency_ms",
        ):
            _integer(row, column)
        if _integer(row, "retries") != claim.observation.attempt_index:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _number(row, "estimated_cost")
        _text(row, "accounted_at")
        usages[request_id] = _Usage(
            row=row,
            request_id=request_id,
            response_id=response_id,
            case_revision=_integer(row, "case_revision", minimum=1),
            consumer_kind=consumer_kind,
            consumer_id=consumer_id,
            slot=_document_slot(
                connection,
                row,
                route=M6SQLiteM3DocumentRoute.MODEL_USAGE,
                artifact_id=request_id,
                document_sha256=_sha256(row, "document_sha256"),
                kind=M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
            ),
        )
    return usages


def _build_graphs(
    claims: dict[str, _Claim],
    responses: dict[str, _Response],
    caches: dict[str, _Cache],
    receipts: dict[str, _Receipt],
    outputs: dict[str, _Output],
    failures: dict[str, _Failure],
    usages: dict[str, _Usage],
) -> tuple[M6SQLiteM3CallGraphPlan, ...]:
    response_requests = {
        request_id
        for request_id, claim in claims.items()
        if claim.observation.result_kind == M6LockedModelCallResultKind.RESPONSE
    }
    failure_requests = set(claims) - response_requests
    if set(responses) != response_requests or set(failures) != failure_requests:
        _fail(M6SQLiteM3ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    if (
        set(caches) != response_requests
        or set(receipts) != response_requests
        or set(usages) != response_requests
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    parsed_requests = {
        request_id for request_id, receipt in receipts.items() if receipt.status == "PARSED"
    }
    if set(outputs) != parsed_requests:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    graphs: list[M6SQLiteM3CallGraphPlan] = []
    for claim in sorted(claims.values(), key=lambda value: value.observation.sort_key):
        request_id = claim.request_id
        if request_id in failure_requests:
            failure = failures[request_id]
            graphs.append(
                M6SQLiteM3CallGraphPlan(
                    observation=claim.observation,
                    evidence_pack_id=claim.pack_key[0],
                    evidence_pack_version=claim.pack_key[1],
                    purpose=claim.purpose,
                    model_manifest_id=_sha256(claim.row, "model_manifest_id"),
                    request=claim.request_slot,
                    claim_takeover_count=claim.takeover_count,
                    failure=failure.slot,
                )
            )
            continue
        response = responses[request_id]
        cache = caches[request_id]
        receipt = receipts[request_id]
        output = outputs.get(request_id)
        if receipt.status == "PARSED" and (
            output is None
            or receipt.parsed_output_id != output.parsed_output_id
            or receipt.parsed_output_sha256 != output.parsed_output_sha256
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        graphs.append(
            M6SQLiteM3CallGraphPlan(
                observation=claim.observation,
                evidence_pack_id=claim.pack_key[0],
                evidence_pack_version=claim.pack_key[1],
                purpose=claim.purpose,
                model_manifest_id=_sha256(claim.row, "model_manifest_id"),
                request=claim.request_slot,
                claim_takeover_count=claim.takeover_count,
                response=response.response_slot,
                cache_request=cache.request_slot,
                cache=cache.cache_slot,
                parse_receipt=receipt.slot,
                parsed_output=output.slot if output is not None else None,
                usage=usages[request_id].slot,
                parse_status=receipt.status,
                repair_request_id=receipt.repair_request_id,
            )
        )
    try:
        return tuple(graphs)
    except (TypeError, ValueError):
        _fail(M6SQLiteM3ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)

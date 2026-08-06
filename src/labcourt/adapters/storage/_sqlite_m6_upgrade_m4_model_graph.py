"""Strict primary-row joins for the M4 model metadata graph."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from labcourt.contracts.enums import ModelParseStatus
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_observation import M6UpgradeObservedModelCall
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactKind

from ._sqlite_m6_live_read_cut import M6LiveReader
from ._sqlite_m6_upgrade_m4_model_plan import (
    M6SQLiteM4CallGeneration,
    M6SQLiteM4CallGraphPlan,
    M6SQLiteM4ClaimStatus,
    M6SQLiteM4DocumentRoute,
    M6SQLiteM4FailureClosureKind,
    M6SQLiteM4HistoricalFailureBinding,
    M6SQLiteM4ModelDocumentFailureCode,
    M6SQLiteM4RoleModelManifestBinding,
)
from ._sqlite_m6_upgrade_m4_model_primitives import (
    _Cache,
    _Claim,
    _document_slot,
    _fail,
    _Failure,
    _integer,
    _number,
    _optional_text,
    _Output,
    _pack_key,
    _Receipt,
    _Response,
    _sha256,
    _text,
    _Usage,
)


@dataclass(frozen=True, slots=True)
class _CycleContext:
    hearing_id: str
    cycle_scope_id: str
    cycle_scope_sha256: str
    cycle_index: int
    prior_acquisition_rounds: int
    prior_rework_rounds: int
    pack_key: tuple[str, int]
    retrieval_receipt_id: str
    retrieval_commitment_sha256: str


def _require_scope(
    row: sqlite3.Row,
    *,
    run_id: str,
    case_id: str,
    manifest_id: str | None = None,
) -> None:
    if _text(row, "run_id") != run_id or _text(row, "case_id") != case_id:
        _fail(M6SQLiteM4ModelDocumentFailureCode.SCOPE_MISMATCH)
    if manifest_id is not None and _sha256(row, "manifest_id") != manifest_id:
        _fail(M6SQLiteM4ModelDocumentFailureCode.SCOPE_MISMATCH)


def _role(row: sqlite3.Row) -> M6LockedModelRole:
    try:
        role = M6LockedModelRole(_text(row, "role"))
    except ValueError:
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    if role not in (
        M6LockedModelRole.PROSECUTOR,
        M6LockedModelRole.DEFENDER,
        M6LockedModelRole.JUDGE,
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return role


def _claims(
    connection: M6LiveReader,
    rows: tuple[sqlite3.Row, ...],
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    role_bindings: tuple[M6SQLiteM4RoleModelManifestBinding, ...],
    observations: tuple[M6UpgradeObservedModelCall, ...],
) -> dict[str, _Claim]:
    observations_by_request = {item.request_id: item for item in observations}
    model_by_role = {item.role: item.model_manifest_id for item in role_bindings}
    if len(rows) != len(observations_by_request):
        _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    claims: dict[str, _Claim] = {}
    for row in rows:
        _require_scope(row, run_id=run_id, case_id=case_id, manifest_id=manifest_id)
        request_id = _sha256(row, "request_id")
        observation = observations_by_request.get(request_id)
        if observation is None or request_id in claims:
            _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
        role = _role(row)
        try:
            generation = M6SQLiteM4CallGeneration(_text(row, "call_generation"))
            status = M6SQLiteM4ClaimStatus(_text(row, "status"))
        except ValueError:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        attempt_index = _integer(row, "attempt_index")
        expected_purpose = "ROLE_CALL" if attempt_index == 0 else "STRUCTURE_REPAIR"
        expected_status = (
            M6SQLiteM4ClaimStatus.COMPLETED
            if observation.result_kind == M6LockedModelCallResultKind.RESPONSE
            else M6SQLiteM4ClaimStatus.ACTIVE
        )
        model_manifest_id = _sha256(row, "model_manifest_id")
        backlog_item_id = _optional_text(row, "backlog_item_id")
        retry_generation = _integer(row, "retry_generation")
        response_id = _optional_text(row, "response_id")
        completed_at = _optional_text(row, "completed_at")
        if (
            observation.role != role
            or observation.attempt_index != attempt_index
            or _text(row, "purpose") != expected_purpose
            or status != expected_status
            or model_by_role.get(role) != model_manifest_id
            or (status == M6SQLiteM4ClaimStatus.COMPLETED)
            != (response_id is not None and completed_at is not None)
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
        if generation == M6SQLiteM4CallGeneration.INITIAL:
            if backlog_item_id is not None or retry_generation != 0:
                _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        elif (
            backlog_item_id is None
            or len(backlog_item_id) != 64
            or any(character not in "0123456789abcdef" for character in backlog_item_id)
            or retry_generation <= 0
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        request_sha256 = _sha256(row, "request_sha256")
        cache_key = _sha256(row, "cache_key")
        request_document_sha256 = _sha256(row, "request_document_sha256")
        _sha256(row, "prompt_manifest_id")
        _sha256(row, "owner_token_sha256")
        _text(row, "lease_expires_at")
        _text(row, "created_at")
        _integer(row, "reserved_images")
        _integer(row, "reserved_pixels")
        request_slot = _document_slot(
            connection,
            row,
            route=M6SQLiteM4DocumentRoute.MODEL_REQUEST,
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
            hearing_id=_sha256(row, "hearing_id"),
            cycle_scope_id=_sha256(row, "cycle_scope_id"),
            cycle_scope_sha256=_sha256(row, "cycle_scope_sha256"),
            role=role,
            purpose=expected_purpose,
            call_generation=generation,
            backlog_item_id=backlog_item_id,
            retry_generation=retry_generation,
            pack_key=_pack_key(row),
            model_manifest_id=model_manifest_id,
            status=status,
            takeover_count=_integer(row, "takeover_count"),
            request_slot=request_slot,
        )
    if set(claims) != set(observations_by_request):
        _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    return claims


def _responses(
    connection: M6LiveReader,
    rows: tuple[sqlite3.Row, ...],
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    claims: dict[str, _Claim],
) -> dict[str, _Response]:
    expected = {
        request_id
        for request_id, claim in claims.items()
        if claim.observation.result_kind == M6LockedModelCallResultKind.RESPONSE
    }
    responses: dict[str, _Response] = {}
    for row in rows:
        _require_scope(row, run_id=run_id, case_id=case_id, manifest_id=manifest_id)
        request_id = _sha256(row, "request_id")
        claim = claims.get(request_id)
        response_id = _sha256(row, "response_id")
        if claim is None or request_id not in expected or request_id in responses:
            _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
        if (
            _sha256(row, "request_sha256") != claim.request_sha256
            or _sha256(row, "cache_key") != claim.cache_key
            or _sha256(row, "hearing_id") != claim.hearing_id
            or _sha256(row, "cycle_scope_id") != claim.cycle_scope_id
            or _sha256(row, "cycle_scope_sha256") != claim.cycle_scope_sha256
            or _role(row) != claim.role
            or _text(row, "purpose") != claim.purpose
            or _integer(row, "attempt_index") != claim.observation.attempt_index
            or _integer(row, "retry_generation") != claim.retry_generation
            or _sha256(row, "model_manifest_id") != claim.model_manifest_id
            or _optional_text(claim.row, "response_id") != response_id
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        content_sha256 = _sha256(row, "content_sha256")
        raw_size = _integer(row, "size_bytes")
        response_slot = _document_slot(
            connection,
            row,
            route=M6SQLiteM4DocumentRoute.MODEL_RESPONSE,
            artifact_id=response_id,
            document_sha256=_sha256(row, "document_sha256"),
            kind=M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
            content_sha256=content_sha256,
            physical_size_bytes=raw_size,
        )
        _text(row, "raw_response_ref")
        responses[request_id] = _Response(
            row=row,
            response_id=response_id,
            request_id=request_id,
            content_sha256=content_sha256,
            response_slot=response_slot,
        )
    if set(responses) != expected:
        _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    return responses


def _caches(
    connection: M6LiveReader,
    rows: tuple[sqlite3.Row, ...],
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    claims: dict[str, _Claim],
    responses: dict[str, _Response],
) -> dict[str, _Cache]:
    caches: dict[str, _Cache] = {}
    for row in rows:
        _require_scope(row, run_id=run_id, case_id=case_id, manifest_id=manifest_id)
        request_id = _sha256(row, "request_id")
        claim = claims.get(request_id)
        response = responses.get(request_id)
        if claim is None or response is None or request_id in caches:
            _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
        request_document_sha256 = _sha256(row, "request_document_sha256")
        if (
            _sha256(row, "cache_key") != claim.cache_key
            or _sha256(row, "hearing_id") != claim.hearing_id
            or _sha256(row, "cycle_scope_id") != claim.cycle_scope_id
            or _sha256(row, "cycle_scope_sha256") != claim.cycle_scope_sha256
            or _role(row) != claim.role
            or _sha256(row, "request_sha256") != claim.request_sha256
            or _sha256(row, "response_id") != response.response_id
            or _sha256(row, "response_content_sha256") != response.content_sha256
            or _sha256(row, "model_manifest_id") != claim.model_manifest_id
            or request_document_sha256 != claim.request_slot.document_sha256
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _sha256(row, "prompt_manifest_id")
        output_schema_sha256 = _sha256(row, "output_schema_sha256")
        request_slot = _document_slot(
            connection,
            row,
            route=M6SQLiteM4DocumentRoute.MODEL_CACHE_REQUEST,
            artifact_id=request_id,
            document_sha256=request_document_sha256,
            kind=None,
        )
        if request_slot.document_bytes != claim.request_slot.document_bytes:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        cache_entry_id = _sha256(row, "cache_entry_id")
        cache_slot = _document_slot(
            connection,
            row,
            route=M6SQLiteM4DocumentRoute.MODEL_CACHE_ENTRY,
            artifact_id=cache_entry_id,
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
    if set(caches) != set(responses):
        _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
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
    caches: dict[str, _Cache],
) -> dict[str, _Receipt]:
    receipts: dict[str, _Receipt] = {}
    for row in rows:
        _require_scope(row, run_id=run_id, case_id=case_id, manifest_id=manifest_id)
        request_id = _sha256(row, "request_id")
        claim = claims.get(request_id)
        response = responses.get(request_id)
        cache = caches.get(request_id)
        if claim is None or response is None or cache is None or request_id in receipts:
            _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
        try:
            status = ModelParseStatus(_text(row, "status"))
        except ValueError:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        parsed_output_id = _optional_text(row, "parsed_output_id")
        repair_request_id = _optional_text(row, "repair_request_id")
        if (
            _sha256(row, "hearing_id") != claim.hearing_id
            or _sha256(row, "cycle_scope_id") != claim.cycle_scope_id
            or _sha256(row, "cycle_scope_sha256") != claim.cycle_scope_sha256
            or _role(row) != claim.role
            or _sha256(row, "request_sha256") != claim.request_sha256
            or _sha256(row, "response_id") != response.response_id
            or _sha256(row, "response_content_sha256") != response.content_sha256
            or _integer(row, "attempt_index") != claim.observation.attempt_index
            or _sha256(row, "output_schema_sha256") != cache.output_schema_sha256
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        parse_receipt_id = _sha256(row, "parse_receipt_id")
        receipt_slot = _document_slot(
            connection,
            row,
            route=M6SQLiteM4DocumentRoute.MODEL_PARSE_RECEIPT,
            artifact_id=parse_receipt_id,
            document_sha256=_sha256(row, "document_sha256"),
            kind=M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
        )
        _text(row, "parser_version")
        receipts[request_id] = _Receipt(
            row=row,
            parse_receipt_id=parse_receipt_id,
            request_id=request_id,
            response_id=response.response_id,
            status=status,
            parsed_output_id=parsed_output_id,
            repair_request_id=repair_request_id,
            receipt_slot=receipt_slot,
        )
    if set(receipts) != set(responses):
        _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
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
    receipts: dict[str, _Receipt],
) -> dict[str, _Output]:
    expected = {
        request_id
        for request_id, receipt in receipts.items()
        if receipt.status == ModelParseStatus.PARSED
    }
    outputs: dict[str, _Output] = {}
    for row in rows:
        _require_scope(row, run_id=run_id, case_id=case_id, manifest_id=manifest_id)
        request_id = _sha256(row, "request_id")
        claim = claims.get(request_id)
        response = responses.get(request_id)
        cache = caches.get(request_id)
        receipt = receipts.get(request_id)
        if (
            claim is None
            or response is None
            or cache is None
            or receipt is None
            or request_id not in expected
            or request_id in outputs
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
        output_id = _sha256(row, "parsed_output_id")
        payload_kind = _text(row, "payload_kind")
        expected_payload = {
            M6LockedModelRole.PROSECUTOR: "PROSECUTION",
            M6LockedModelRole.DEFENDER: "DEFENSE",
        }.get(claim.role)
        if claim.role == M6LockedModelRole.JUDGE:
            payload_valid = payload_kind in ("JUDGE_VERDICT", "JUDGE_ACQUISITION")
        else:
            payload_valid = payload_kind == expected_payload
        if (
            not payload_valid
            or _sha256(row, "hearing_id") != claim.hearing_id
            or _sha256(row, "cycle_scope_id") != claim.cycle_scope_id
            or _sha256(row, "cycle_scope_sha256") != claim.cycle_scope_sha256
            or _role(row) != claim.role
            or _sha256(row, "response_id") != response.response_id
            or _sha256(row, "parse_receipt_id") != receipt.parse_receipt_id
            or receipt.parsed_output_id != output_id
            or _sha256(row, "response_content_sha256") != response.content_sha256
            or _sha256(row, "output_schema_sha256") != cache.output_schema_sha256
            or _sha256(row, "model_manifest_id") != claim.model_manifest_id
            or (_sha256(row, "current_pack_id"), _integer(row, "current_pack_version", minimum=1))
            != claim.pack_key
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _sha256(row, "prompt_manifest_id")
        _sha256(row, "payload_sha256")
        output_slot = _document_slot(
            connection,
            row,
            route=M6SQLiteM4DocumentRoute.ROLE_OUTPUT,
            artifact_id=output_id,
            document_sha256=_sha256(row, "document_sha256"),
            kind=M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
        )
        outputs[request_id] = _Output(
            row=row,
            output_id=output_id,
            request_id=request_id,
            response_id=response.response_id,
            output_slot=output_slot,
        )
    if set(outputs) != expected:
        _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    by_cycle_role = {
        (claims[request_id].cycle_scope_id, claims[request_id].role): output
        for request_id, output in outputs.items()
    }
    if len(by_cycle_role) != len(outputs):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    for request_id, output in outputs.items():
        claim = claims[request_id]
        prosecutor = by_cycle_role.get((claim.cycle_scope_id, M6LockedModelRole.PROSECUTOR))
        defender = by_cycle_role.get((claim.cycle_scope_id, M6LockedModelRole.DEFENDER))
        stored_prosecutor = _optional_text(output.row, "prosecutor_output_id")
        stored_defender = _optional_text(output.row, "defender_output_id")
        if claim.role == M6LockedModelRole.PROSECUTOR:
            valid = stored_prosecutor is None and stored_defender is None
        elif claim.role == M6LockedModelRole.DEFENDER:
            valid = (
                prosecutor is not None
                and stored_prosecutor == prosecutor.output_id
                and stored_defender is None
            )
        else:
            valid = (
                prosecutor is not None
                and defender is not None
                and stored_prosecutor == prosecutor.output_id
                and stored_defender == defender.output_id
            )
        if not valid:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return outputs


def _usages(
    connection: M6LiveReader,
    rows: tuple[sqlite3.Row, ...],
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    claims: dict[str, _Claim],
    responses: dict[str, _Response],
) -> dict[str, _Usage]:
    usages: dict[str, _Usage] = {}
    for row in rows:
        _require_scope(row, run_id=run_id, case_id=case_id, manifest_id=manifest_id)
        request_id = _sha256(row, "request_id")
        claim = claims.get(request_id)
        response = responses.get(request_id)
        if claim is None or response is None or request_id in usages:
            _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
        if (
            _sha256(row, "response_id") != response.response_id
            or _sha256(row, "hearing_id") != claim.hearing_id
            or _sha256(row, "cycle_scope_id") != claim.cycle_scope_id
            or _sha256(row, "cycle_scope_sha256") != claim.cycle_scope_sha256
            or _role(row) != claim.role
            or _text(row, "accounted_at") != _text(claim.row, "completed_at")
            or _integer(row, "input_images") != _integer(claim.row, "reserved_images")
            or _integer(row, "input_pixels") != _integer(claim.row, "reserved_pixels")
            or _integer(row, "retries") != claim.takeover_count
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        for column in (
            "input_images",
            "input_pixels",
            "input_tokens",
            "output_tokens",
            "provider_latency_ms",
            "retries",
        ):
            _integer(row, column)
        _number(row, "estimated_cost")
        usage_receipt_id = _sha256(row, "usage_receipt_id")
        usage_slot = _document_slot(
            connection,
            row,
            route=M6SQLiteM4DocumentRoute.MODEL_USAGE,
            artifact_id=usage_receipt_id,
            document_sha256=_sha256(row, "document_sha256"),
            kind=M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
        )
        usages[request_id] = _Usage(
            row=row,
            request_id=request_id,
            response_id=response.response_id,
            usage_slot=usage_slot,
        )
    if set(usages) != set(responses):
        _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    return usages


def _failures(
    connection: M6LiveReader,
    rows: tuple[sqlite3.Row, ...],
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    claims: dict[str, _Claim],
) -> tuple[dict[str, _Failure], tuple[_Failure, ...]]:
    """Classify every Case-scoped failure row against the current claim epoch."""

    terminal: dict[str, _Failure] = {}
    historical: list[_Failure] = []
    historical_epochs: dict[str, set[int]] = {}
    epoch_keys: set[tuple[str, int]] = set()
    authority_ids: set[str] = set()
    for row in rows:
        _require_scope(row, run_id=run_id, case_id=case_id, manifest_id=manifest_id)
        request_id = _sha256(row, "request_id")
        claim = claims.get(request_id)
        if claim is None:
            _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
        authority_id = _sha256(row, "authority_id")
        takeover_count = _integer(row, "claim_takeover_count")
        epoch_key = (request_id, takeover_count)
        if (
            authority_id in authority_ids
            or epoch_key in epoch_keys
            or takeover_count > claim.takeover_count
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        authority_ids.add(authority_id)
        epoch_keys.add(epoch_key)
        if (
            _sha256(row, "request_sha256") != claim.request_sha256
            or _sha256(row, "cache_key") != claim.cache_key
            or _sha256(row, "hearing_id") != claim.hearing_id
            or _sha256(row, "cycle_scope_id") != claim.cycle_scope_id
            or _sha256(row, "cycle_scope_sha256") != claim.cycle_scope_sha256
            or _role(row) != claim.role
            or _integer(row, "retry_generation") != claim.retry_generation
            or _integer(row, "reserved_images") != _integer(claim.row, "reserved_images")
            or _integer(row, "reserved_pixels") != _integer(claim.row, "reserved_pixels")
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        for column in (
            "request_document_sha256",
            "source_checkpoint_id",
            "source_checkpoint_sha256",
            "claim_owner_sha256",
            "closure_audit_entry_hash",
        ):
            _sha256(row, column)
        for column in (
            "source_checkpoint_version",
            "backlog_attempt_count",
            "backlog_version",
            "closure_case_revision",
        ):
            _integer(row, column, minimum=1 if column != "backlog_attempt_count" else 0)
        for column in (
            "disclosed_images",
            "disclosed_pixels",
            "input_tokens",
            "output_tokens",
            "latency_ms",
            "closure_audit_sequence",
        ):
            _integer(row, column)
        _number(row, "estimated_cost")
        _text(row, "claim_lease_expires_at")
        _text(row, "failure_code")
        _text(row, "delivery_certainty")
        _text(row, "backlog_reason_code")
        _text(row, "backlog_status")
        _text(row, "recorded_at")
        _sha256(row, "backlog_item_id")
        try:
            closure_kind = M6SQLiteM4FailureClosureKind(_text(row, "closure_kind"))
        except ValueError:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        lease_identity = _optional_text(row, "lease_identity_sha256")
        lease_id = _optional_text(row, "lease_id")
        completion_id = _optional_text(row, "completion_receipt_id")
        if closure_kind == M6SQLiteM4FailureClosureKind.INITIAL_BACKLOG:
            if (
                lease_identity is not None
                or lease_id is not None
                or completion_id is not None
                or _integer(row, "backlog_version", minimum=1) != 1
                or _integer(row, "backlog_attempt_count") != 0
                or _integer(row, "retry_generation") != 0
                or _text(row, "backlog_status") != "PENDING"
            ):
                _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        elif (
            lease_identity is None
            or lease_id is None
            or completion_id is None
            or len(lease_identity) != 64
            or len(lease_id) != 64
            or len(completion_id) != 64
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        failure = _Failure(
            row=row,
            request_id=request_id,
            authority_id=authority_id,
            takeover_count=takeover_count,
            failure_slot=_document_slot(
                connection,
                row,
                route=M6SQLiteM4DocumentRoute.MODEL_CALL_FAILURE,
                artifact_id=authority_id,
                document_sha256=_sha256(row, "document_sha256"),
                kind=M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
            ),
        )
        if takeover_count < claim.takeover_count:
            historical.append(failure)
            historical_epochs.setdefault(request_id, set()).add(takeover_count)
            continue
        if (
            claim.observation.result_kind != M6LockedModelCallResultKind.FAILURE
            or claim.status != M6SQLiteM4ClaimStatus.ACTIVE
            or request_id in terminal
            or _sha256(row, "claim_owner_sha256") != _sha256(claim.row, "owner_token_sha256")
            or _text(row, "claim_lease_expires_at") != _text(claim.row, "lease_expires_at")
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
        terminal[request_id] = failure
    for request_id, claim in claims.items():
        if historical_epochs.get(request_id, set()) != set(range(claim.takeover_count)):
            _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    expected_terminal = {
        request_id
        for request_id, claim in claims.items()
        if claim.observation.result_kind == M6LockedModelCallResultKind.FAILURE
    }
    if set(terminal) != expected_terminal:
        _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    return terminal, tuple(
        sorted(
            historical,
            key=lambda value: (value.request_id, value.takeover_count, value.authority_id),
        )
    )


def _historical_failure_bindings(
    failures: tuple[_Failure, ...],
) -> tuple[M6SQLiteM4HistoricalFailureBinding, ...]:
    try:
        return tuple(
            M6SQLiteM4HistoricalFailureBinding(
                request_id=value.request_id,
                claim_takeover_count=value.takeover_count,
                authority_id=value.authority_id,
                hearing_id=_sha256(value.row, "hearing_id"),
                cycle_scope_id=_sha256(value.row, "cycle_scope_id"),
                cycle_scope_sha256=_sha256(value.row, "cycle_scope_sha256"),
                case_id=_text(value.row, "case_id"),
                role=_role(value.row),
                source_checkpoint_id=_sha256(value.row, "source_checkpoint_id"),
                source_checkpoint_sha256=_sha256(value.row, "source_checkpoint_sha256"),
                source_checkpoint_version=_integer(
                    value.row, "source_checkpoint_version", minimum=1
                ),
                backlog_item_id=_sha256(value.row, "backlog_item_id"),
                backlog_version=_integer(value.row, "backlog_version", minimum=1),
                retry_generation=_integer(value.row, "retry_generation"),
                closure_kind=M6SQLiteM4FailureClosureKind(_text(value.row, "closure_kind")),
                completion_receipt_id=_optional_text(value.row, "completion_receipt_id"),
                closure_case_revision=_integer(value.row, "closure_case_revision", minimum=1),
                closure_audit_sequence=_integer(value.row, "closure_audit_sequence"),
                closure_audit_entry_hash=_sha256(value.row, "closure_audit_entry_hash"),
                rowid=value.failure_slot.rowid,
                document_sha256=value.failure_slot.document_sha256,
                document_bytes=value.failure_slot.document_bytes,
                index_identity_sha256=value.failure_slot.index_identity_sha256,
            )
            for value in failures
        )
    except (TypeError, ValueError):
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)


def _build_response_graphs(
    claims: dict[str, _Claim],
    responses: dict[str, _Response],
    caches: dict[str, _Cache],
    receipts: dict[str, _Receipt],
    outputs: dict[str, _Output],
    usages: dict[str, _Usage],
    contexts: dict[str, _CycleContext],
) -> tuple[M6SQLiteM4CallGraphPlan, ...]:
    graphs: list[M6SQLiteM4CallGraphPlan] = []
    for claim in claims.values():
        if claim.observation.result_kind != M6LockedModelCallResultKind.RESPONSE:
            continue
        response = responses.get(claim.request_id)
        cache = caches.get(claim.request_id)
        receipt = receipts.get(claim.request_id)
        usage = usages.get(claim.request_id)
        context = contexts.get(claim.cycle_scope_id)
        if (
            response is None
            or cache is None
            or receipt is None
            or usage is None
            or context is None
            or context.hearing_id != claim.hearing_id
            or context.cycle_scope_sha256 != claim.cycle_scope_sha256
            or context.pack_key != claim.pack_key
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
        output = outputs.get(claim.request_id)
        if output is not None and (
            _integer(output.row, "prior_acquisition_rounds") != context.prior_acquisition_rounds
            or _integer(output.row, "prior_rework_rounds") != context.prior_rework_rounds
            or _sha256(output.row, "precedent_retrieval_receipt_id") != context.retrieval_receipt_id
            or _sha256(output.row, "precedent_retrieval_receipt_sha256")
            != context.retrieval_commitment_sha256
            or _integer(output.row, "precedent_retrieval_degraded") not in (0, 1)
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        graphs.append(
            M6SQLiteM4CallGraphPlan(
                observation=claim.observation,
                hearing_id=claim.hearing_id,
                cycle_scope_id=claim.cycle_scope_id,
                cycle_scope_sha256=claim.cycle_scope_sha256,
                cycle_index=context.cycle_index,
                prior_acquisition_rounds=context.prior_acquisition_rounds,
                prior_rework_rounds=context.prior_rework_rounds,
                evidence_pack_id=claim.pack_key[0],
                evidence_pack_version=claim.pack_key[1],
                retrieval_receipt_id=context.retrieval_receipt_id,
                retrieval_commitment_sha256=context.retrieval_commitment_sha256,
                purpose=claim.purpose,
                call_generation=claim.call_generation,
                backlog_item_id=claim.backlog_item_id,
                retry_generation=claim.retry_generation,
                model_manifest_id=claim.model_manifest_id,
                claim_status=claim.status,
                claim_takeover_count=claim.takeover_count,
                request=claim.request_slot,
                response=response.response_slot,
                cache_request=cache.request_slot,
                cache=cache.cache_slot,
                parse_receipt=receipt.receipt_slot,
                role_output=output.output_slot if output is not None else None,
                usage=usage.usage_slot,
                parse_status=receipt.status,
                repair_request_id=receipt.repair_request_id,
            )
        )
    return tuple(sorted(graphs, key=lambda value: value.sort_key))


def _build_failure_graphs(
    claims: dict[str, _Claim],
    failures: dict[str, _Failure],
    contexts: dict[str, _CycleContext],
) -> tuple[M6SQLiteM4CallGraphPlan, ...]:
    graphs: list[M6SQLiteM4CallGraphPlan] = []
    for claim in claims.values():
        if claim.observation.result_kind != M6LockedModelCallResultKind.FAILURE:
            continue
        failure = failures.get(claim.request_id)
        context = contexts.get(claim.cycle_scope_id)
        if (
            failure is None
            or failure.takeover_count != claim.takeover_count
            or context is None
            or context.hearing_id != claim.hearing_id
            or context.cycle_scope_sha256 != claim.cycle_scope_sha256
            or context.pack_key != claim.pack_key
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
        graphs.append(
            M6SQLiteM4CallGraphPlan(
                observation=claim.observation,
                hearing_id=claim.hearing_id,
                cycle_scope_id=claim.cycle_scope_id,
                cycle_scope_sha256=claim.cycle_scope_sha256,
                cycle_index=context.cycle_index,
                prior_acquisition_rounds=context.prior_acquisition_rounds,
                prior_rework_rounds=context.prior_rework_rounds,
                evidence_pack_id=claim.pack_key[0],
                evidence_pack_version=claim.pack_key[1],
                retrieval_receipt_id=context.retrieval_receipt_id,
                retrieval_commitment_sha256=context.retrieval_commitment_sha256,
                purpose=claim.purpose,
                call_generation=claim.call_generation,
                backlog_item_id=claim.backlog_item_id,
                retry_generation=claim.retry_generation,
                model_manifest_id=claim.model_manifest_id,
                claim_status=claim.status,
                claim_takeover_count=claim.takeover_count,
                request=claim.request_slot,
                failure=failure.failure_slot,
            )
        )
    return tuple(sorted(graphs, key=lambda value: value.sort_key))


def _build_graphs(
    claims: dict[str, _Claim],
    responses: dict[str, _Response],
    caches: dict[str, _Cache],
    receipts: dict[str, _Receipt],
    outputs: dict[str, _Output],
    failures: dict[str, _Failure],
    usages: dict[str, _Usage],
    contexts: dict[str, _CycleContext],
) -> tuple[M6SQLiteM4CallGraphPlan, ...]:
    return tuple(
        sorted(
            (
                *_build_response_graphs(
                    claims,
                    responses,
                    caches,
                    receipts,
                    outputs,
                    usages,
                    contexts,
                ),
                *_build_failure_graphs(claims, failures, contexts),
            ),
            key=lambda value: value.sort_key,
        )
    )

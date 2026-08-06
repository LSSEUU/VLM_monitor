"""Targeted relational support validation for M3 metadata plans."""

from __future__ import annotations

import hashlib
import sqlite3

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case

from ._sqlite_m6_live_read_cut import M6LiveReader
from ._sqlite_m6_upgrade_m3_model_plan import (
    M6SQLiteM3ModelDocumentFailureCode,
    M6SQLiteM3SelectedPackBinding,
    M6SQLiteM3SupportDocumentRoute,
    M6SQLiteM3SupportDocumentSlot,
    M6SQLiteM3SupportRoute,
    M6SQLiteM3SupportSlot,
)
from ._sqlite_m6_upgrade_m3_model_primitives import (
    _Claim,
    _fail,
    _Failure,
    _integer,
    _is_sha256,
    _optional_text,
    _Output,
    _pack_key,
    _Receipt,
    _row_identity,
    _sha256,
    _single,
    _text,
    _Usage,
)
from ._sqlite_m6_upgrade_m3_model_rows import (
    read_audit_row,
    read_backlog_completions_for_revision,
    read_backlog_head_row,
    read_backlog_item_row,
    read_backlog_success_completion_for_revision,
    read_backlog_version_row,
    read_case_version_row,
    read_completion_row,
    read_screening_row,
    support_document_bytes,
)


class _SupportResolver:
    """Targeted support-row resolver; it never enumerates Case history."""

    def __init__(
        self,
        connection: M6LiveReader,
        *,
        run_id: str,
        case_id: str,
        manifest_id: str,
        selected_revision: int,
    ) -> None:
        self.connection = connection
        self.run_id = run_id
        self.case_id = case_id
        self.manifest_id = manifest_id
        self.selected_revision = selected_revision
        self._slots: dict[tuple[M6SQLiteM3SupportRoute, int], M6SQLiteM3SupportSlot] = {}
        self._document_slots: dict[
            tuple[M6SQLiteM3SupportDocumentRoute, int],
            M6SQLiteM3SupportDocumentSlot,
        ] = {}
        self.case_versions: dict[int, sqlite3.Row] = {}
        self.audits: dict[int, sqlite3.Row] = {}
        self.items: dict[str, sqlite3.Row] = {}
        self.versions: dict[tuple[str, int], sqlite3.Row] = {}
        self.heads: dict[str, sqlite3.Row] = {}
        self.screenings: dict[str, sqlite3.Row] = {}
        self.completions: dict[str, sqlite3.Row] = {}
        self.completion_revisions: dict[tuple[str, int], sqlite3.Row | None] = {}
        self.success_completion_revisions: dict[int, sqlite3.Row | None] = {}

    def add(
        self,
        row: sqlite3.Row,
        route: M6SQLiteM3SupportRoute,
        identity: str,
    ) -> None:
        rowid = _integer(row, "support_rowid", minimum=1)
        slot = M6SQLiteM3SupportSlot(
            route=route,
            rowid=rowid,
            identity=identity,
            index_identity_sha256=_row_identity(row, route.value),
        )
        key = route, rowid
        previous = self._slots.get(key)
        if previous is not None and previous != slot:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        self._slots[key] = slot

    @property
    def slots(self) -> tuple[M6SQLiteM3SupportSlot, ...]:
        return tuple(sorted(self._slots.values(), key=lambda value: value.sort_key))

    def add_document(
        self,
        row: sqlite3.Row,
        route: M6SQLiteM3SupportDocumentRoute,
        artifact_id: str,
    ) -> None:
        rowid = _integer(row, "support_rowid", minimum=1)
        try:
            slot = M6SQLiteM3SupportDocumentSlot(
                route=route,
                rowid=rowid,
                artifact_id=artifact_id,
                document_sha256=_sha256(row, "document_sha256"),
                document_bytes=support_document_bytes(self.connection, row, route),
                index_identity_sha256=_row_identity(row, route.value),
            )
        except (TypeError, ValueError):
            _fail(M6SQLiteM3ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
        key = route, rowid
        previous = self._document_slots.get(key)
        if previous is not None and previous != slot:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        self._document_slots[key] = slot

    @property
    def document_slots(self) -> tuple[M6SQLiteM3SupportDocumentSlot, ...]:
        return tuple(sorted(self._document_slots.values(), key=lambda value: value.sort_key))

    def case_version(self, revision: int) -> sqlite3.Row:
        row = self.case_versions.get(revision)
        if row is None:
            row = _single(
                read_case_version_row(
                    self.connection,
                    run_id=self.run_id,
                    case_id=self.case_id,
                    revision=revision,
                )
            )
            if (
                _text(row, "run_id") != self.run_id
                or _text(row, "case_id") != self.case_id
                or _integer(row, "revision", minimum=1) != revision
                or revision > self.selected_revision
            ):
                _fail(M6SQLiteM3ModelDocumentFailureCode.CASE_BINDING_MISMATCH)
            _sha256(row, "document_sha256")
            _integer(row, "audit_sequence")
            self.add(row, M6SQLiteM3SupportRoute.CASE_VERSION, str(revision))
            self.case_versions[revision] = row
        return row

    def audit(self, sequence: int) -> sqlite3.Row:
        row = self.audits.get(sequence)
        if row is None:
            row = _single(
                read_audit_row(
                    self.connection,
                    run_id=self.run_id,
                    sequence=sequence,
                )
            )
            if (
                _text(row, "run_id") != self.run_id
                or _integer(row, "sequence") != sequence
                or _text(row, "manifest_id") != self.manifest_id
            ):
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            _sha256(row, "entry_hash")
            self.add(row, M6SQLiteM3SupportRoute.AUDIT_ENTRY, str(sequence))
            self.audits[sequence] = row
        return row

    def bind_case_revision(self, revision: int) -> tuple[sqlite3.Row, sqlite3.Row]:
        case_version = self.case_version(revision)
        audit = self.audit(_integer(case_version, "audit_sequence"))
        if _sha256(audit, "after_sha256") != _sha256(
            case_version,
            "document_sha256",
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        return case_version, audit

    def screening(self, screening_id: str) -> sqlite3.Row:
        row = self.screenings.get(screening_id)
        if row is None:
            row = _single(
                read_screening_row(
                    self.connection,
                    run_id=self.run_id,
                    case_id=self.case_id,
                    screening_id=screening_id,
                )
            )
            if (
                _text(row, "run_id") != self.run_id
                or _text(row, "case_id") != self.case_id
                or _sha256(row, "screening_id") != screening_id
                or _text(row, "manifest_id") != self.manifest_id
            ):
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            self.add(row, M6SQLiteM3SupportRoute.SCREENING_RESULT, screening_id)
            self.screenings[screening_id] = row
        return row

    def item(self, item_id: str) -> sqlite3.Row:
        row = self.items.get(item_id)
        if row is None:
            row = _single(
                read_backlog_item_row(
                    self.connection,
                    run_id=self.run_id,
                    case_id=self.case_id,
                    item_id=item_id,
                )
            )
            if (
                _text(row, "run_id") != self.run_id
                or _text(row, "case_id") != self.case_id
                or _sha256(row, "item_id") != item_id
                or _text(row, "manifest_id") != self.manifest_id
            ):
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            self.add(row, M6SQLiteM3SupportRoute.BACKLOG_ITEM, item_id)
            self.items[item_id] = row
        return row

    def version(self, item_id: str, version: int) -> sqlite3.Row:
        key = item_id, version
        row = self.versions.get(key)
        if row is None:
            row = _single(
                read_backlog_version_row(
                    self.connection,
                    run_id=self.run_id,
                    item_id=item_id,
                    version=version,
                )
            )
            if (
                _text(row, "run_id") != self.run_id
                or _sha256(row, "item_id") != item_id
                or _integer(row, "version", minimum=1) != version
            ):
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            self.add(
                row,
                M6SQLiteM3SupportRoute.BACKLOG_ITEM_VERSION,
                f"{item_id}:{version}",
            )
            self.versions[key] = row
        return row

    def head(self, item_id: str) -> sqlite3.Row:
        row = self.heads.get(item_id)
        if row is None:
            row = _single(
                read_backlog_head_row(
                    self.connection,
                    run_id=self.run_id,
                    item_id=item_id,
                )
            )
            if _text(row, "run_id") != self.run_id or _sha256(row, "item_id") != item_id:
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            self.add(row, M6SQLiteM3SupportRoute.BACKLOG_HEAD, item_id)
            self.heads[item_id] = row
        return row

    def completion(self, receipt_id: str) -> sqlite3.Row:
        row = self.completions.get(receipt_id)
        if row is None:
            row = _single(
                read_completion_row(
                    self.connection,
                    run_id=self.run_id,
                    case_id=self.case_id,
                    receipt_id=receipt_id,
                )
            )
            self._remember_completion(row, receipt_id)
        return row

    def completion_for_revision(
        self,
        item_id: str,
        case_revision: int,
    ) -> sqlite3.Row | None:
        key = item_id, case_revision
        if key not in self.completion_revisions:
            rows = read_backlog_completions_for_revision(
                self.connection,
                run_id=self.run_id,
                case_id=self.case_id,
                item_id=item_id,
                case_revision=case_revision,
            )
            if len(rows) > 1:
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            row = rows[0] if rows else None
            if row is not None:
                self._remember_completion(row, _sha256(row, "receipt_id"))
            self.completion_revisions[key] = row
        return self.completion_revisions[key]

    def success_completion_for_revision(self, case_revision: int) -> sqlite3.Row | None:
        if case_revision not in self.success_completion_revisions:
            rows = read_backlog_success_completion_for_revision(
                self.connection,
                run_id=self.run_id,
                case_id=self.case_id,
                case_revision=case_revision,
            )
            if len(rows) > 1:
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            row = rows[0] if rows else None
            if row is not None:
                self._remember_completion(row, _sha256(row, "receipt_id"))
            self.success_completion_revisions[case_revision] = row
        return self.success_completion_revisions[case_revision]

    def _remember_completion(self, row: sqlite3.Row, receipt_id: str) -> None:
        if (
            _text(row, "run_id") != self.run_id
            or _text(row, "case_id") != self.case_id
            or _sha256(row, "receipt_id") != receipt_id
            or _text(row, "manifest_id") != self.manifest_id
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        previous = self.completions.get(receipt_id)
        if previous is not None and _row_identity(
            previous,
            M6SQLiteM3SupportRoute.BACKLOG_COMPLETION_RECEIPT.value,
        ) != _row_identity(
            row,
            M6SQLiteM3SupportRoute.BACKLOG_COMPLETION_RECEIPT.value,
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        self.add(
            row,
            M6SQLiteM3SupportRoute.BACKLOG_COMPLETION_RECEIPT,
            receipt_id,
        )
        self.add_document(
            row,
            M6SQLiteM3SupportDocumentRoute.BACKLOG_COMPLETION_RECEIPT,
            receipt_id,
        )
        self.completions[receipt_id] = row


def _bind_failure_support(
    resolver: _SupportResolver,
    failure: _Failure,
    *,
    selected_pack_by_key: dict[tuple[str, int], M6SQLiteM3SelectedPackBinding],
    historical: bool = False,
) -> None:
    row = failure.row
    item_id = _sha256(row, "backlog_item_id")
    version_number = _integer(row, "backlog_version", minimum=1)
    item = resolver.item(item_id)
    version = resolver.version(item_id, version_number)
    head = resolver.head(item_id)
    pack_key = _pack_key(row)
    selected_pack = selected_pack_by_key.get(pack_key)
    if selected_pack is None:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    purpose = _text(row, "purpose")
    expected_role = (
        "SCREENING"
        if purpose == "SCREENING"
        else "STRUCTURE_REPAIR"
        if purpose == "STRUCTURE_REPAIR"
        else None
    )
    current_version = _integer(head, "current_version", minimum=1)
    if (
        _text(item, "stage") != "SCREENING"
        or expected_role is None
        or _optional_text(item, "role") != expected_role
        or _text(item, "reason_code") != _text(row, "backlog_reason_code")
        or _text(item, "stage_input_kind") != "EVIDENCE_PACK"
        or _text(item, "stage_input_id") != pack_key[0]
        or _sha256(item, "stage_input_sha256") != selected_pack.document_sha256
        or (current_version < version_number if historical else current_version != version_number)
        or _text(version, "status") != _text(row, "backlog_status")
        or _integer(version, "attempt_count") != _integer(row, "backlog_attempt_count")
        or _integer(version, "retry_generation") != _integer(row, "retry_generation")
        or any(
            _optional_text(version, column) is not None
            for column in ("lease_id", "lease_owner_sha256", "lease_expires_at")
        )
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    case_revision = _integer(row, "closure_case_revision", minimum=1)
    case_version, audit = resolver.bind_case_revision(case_revision)
    closure_sequence = _integer(row, "closure_audit_sequence")
    if (
        _integer(case_version, "audit_sequence") != closure_sequence
        or _integer(audit, "sequence") != closure_sequence
        or _sha256(audit, "entry_hash") != _sha256(row, "closure_audit_entry_hash")
        or _text(audit, "object_kind") != "BACKLOG_ITEM"
        or _text(audit, "object_id") != item_id
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    closure_kind = _text(row, "closure_kind")
    completion_receipt_id = _optional_text(row, "completion_receipt_id")
    if closure_kind == "INITIAL_BACKLOG":
        if (
            version_number != 1
            or _integer(row, "backlog_attempt_count") != 0
            or completion_receipt_id is not None
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        return
    if closure_kind != "RETRY_FAILURE" or not _is_sha256(completion_receipt_id):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    assert isinstance(completion_receipt_id, str)
    completion = resolver.completion(completion_receipt_id)
    if (
        _sha256(completion, "item_id") != item_id
        or _text(completion, "outcome_kind") != "FAILURE"
        or _text(completion, "completion_kind") != "BACKLOG_ITEM"
        or _sha256(completion, "completion_id") != item_id
        or _integer(completion, "backlog_version", minimum=1) != version_number
        or _text(completion, "backlog_status") != _text(row, "backlog_status")
        or _integer(completion, "attempt_count") != _integer(row, "backlog_attempt_count")
        or _integer(completion, "retry_generation") != _integer(row, "retry_generation")
        or _integer(completion, "completion_case_revision", minimum=1) != case_revision
        or _integer(completion, "completion_audit_sequence") != closure_sequence
        or _sha256(completion, "completion_audit_entry_hash")
        != _sha256(row, "closure_audit_entry_hash")
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)


def _backlog_usage_role(
    group: tuple[_Usage, ...],
    *,
    reason_code: str,
    claims: dict[str, _Claim],
    receipts: dict[str, _Receipt],
) -> str:
    if not group:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    by_attempt: dict[int, tuple[_Usage, _Claim, _Receipt]] = {}
    for grouped_usage in group:
        claim = claims.get(grouped_usage.request_id)
        receipt = receipts.get(grouped_usage.request_id)
        if (
            claim is None
            or receipt is None
            or receipt.response_id != grouped_usage.response_id
            or claim.observation.attempt_index in by_attempt
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        by_attempt[claim.observation.attempt_index] = (grouped_usage, claim, receipt)
    if set(by_attempt) not in ({0}, {0, 1}):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    primary_usage, primary_claim, primary_receipt = by_attempt[0]
    expected_role = "SCREENING"
    repair_values = by_attempt.get(1)
    if repair_values is None:
        if primary_receipt.status == "REPAIR_REQUIRED":
            expected_role = "STRUCTURE_REPAIR"
        if reason_code == "MODEL_OUTPUT_INVALID" and primary_receipt.status != "INVALID_FINAL":
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        return expected_role
    repair_usage, repair_claim, repair_receipt = repair_values
    if (
        primary_receipt.status != "REPAIR_REQUIRED"
        or primary_receipt.repair_request_id != repair_claim.request_id
        or repair_receipt.status == "REPAIR_REQUIRED"
        or primary_claim.pack_key != repair_claim.pack_key
        or primary_usage.response_id != primary_receipt.response_id
        or repair_usage.response_id != repair_receipt.response_id
        or (reason_code == "MODEL_OUTPUT_INVALID" and repair_receipt.status != "INVALID_FINAL")
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return repair_claim.purpose


def _bind_initial_backlog_usage(
    resolver: _SupportResolver,
    usage: _Usage,
    *,
    selected_case: Case,
    item: sqlite3.Row,
    audit: sqlite3.Row,
    claims: dict[str, _Claim],
    receipts: dict[str, _Receipt],
    usages: dict[str, _Usage],
) -> None:
    initial = resolver.version(usage.consumer_id, 1)
    head = resolver.head(usage.consumer_id)
    current_version = _integer(head, "current_version", minimum=1)
    resolver.version(usage.consumer_id, current_version)
    group = tuple(
        value
        for value in usages.values()
        if value.consumer_kind == "BACKLOG_ITEM"
        and value.consumer_id == usage.consumer_id
        and value.case_revision == usage.case_revision
    )
    expected_role = _backlog_usage_role(
        group,
        reason_code=_text(item, "reason_code"),
        claims=claims,
        receipts=receipts,
    )
    if (
        _sha256(initial, "document_sha256") != _sha256(item, "initial_document_sha256")
        or _text(initial, "status") != "PENDING"
        or _integer(initial, "attempt_count") != 0
        or any(
            _optional_text(initial, column) is not None
            for column in ("lease_id", "lease_owner_sha256", "lease_expires_at")
        )
        or _text(audit, "object_kind") != "BACKLOG_ITEM"
        or _text(audit, "object_id") != usage.consumer_id
        or _text(item, "stage") != "SCREENING"
        or _optional_text(item, "role") != expected_role
        or (
            resolver.selected_revision == usage.case_revision
            and selected_case.status.value == "BACKLOGGED"
            and selected_case.current_backlog_item_id == usage.consumer_id
            and current_version != 1
        )
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)


def _retry_backlog_role(
    resolver: _SupportResolver,
    item: sqlite3.Row,
    *,
    failures: tuple[_Failure, ...],
    claims: dict[str, _Claim],
    receipts: dict[str, _Receipt],
    usages: dict[str, _Usage],
) -> str:
    item_id = _sha256(item, "item_id")
    initial_failures = tuple(
        failure
        for failure in failures
        if _sha256(failure.row, "backlog_item_id") == item_id
        and _text(failure.row, "closure_kind") == "INITIAL_BACKLOG"
    )
    if len(initial_failures) > 1:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    expected_roles: set[str] = set()
    if initial_failures:
        expected_roles.add(_text(initial_failures[0].row, "purpose"))
    initial_usage_revisions: list[int] = []
    for case_revision in sorted(
        {
            value.case_revision
            for value in usages.values()
            if value.consumer_kind == "BACKLOG_ITEM" and value.consumer_id == item_id
        }
    ):
        if resolver.completion_for_revision(item_id, case_revision) is None:
            initial_usage_revisions.append(case_revision)
    if len(initial_usage_revisions) > 1:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    if initial_usage_revisions:
        case_revision = initial_usage_revisions[0]
        group = tuple(
            value
            for value in usages.values()
            if value.consumer_kind == "BACKLOG_ITEM"
            and value.consumer_id == item_id
            and value.case_revision == case_revision
        )
        expected_roles.add(
            _backlog_usage_role(
                group,
                reason_code=_text(item, "reason_code"),
                claims=claims,
                receipts=receipts,
            )
        )
    if not expected_roles:
        return "SCREENING"
    if len(expected_roles) != 1:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return next(iter(expected_roles))


def _bind_usage_support(
    resolver: _SupportResolver,
    usage: _Usage,
    *,
    selected_case: Case,
    failures: tuple[_Failure, ...],
    claims: dict[str, _Claim],
    receipts: dict[str, _Receipt],
    outputs: dict[str, _Output],
    usages: dict[str, _Usage],
    selected_pack_by_key: dict[tuple[str, int], M6SQLiteM3SelectedPackBinding],
) -> None:
    case_version, audit = resolver.bind_case_revision(usage.case_revision)
    case_audit_sequence = _integer(case_version, "audit_sequence")
    if usage.consumer_kind == "SCREENING_RESULT":
        screening = resolver.screening(usage.consumer_id)
        embedded_values = tuple(
            value
            for value in selected_case.screening_results
            if value.screening_id == usage.consumer_id
        )
        if len(embedded_values) != 1:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        embedded = embedded_values[0]
        pack_key = (
            _sha256(screening, "evidence_pack_id"),
            _integer(screening, "evidence_pack_version", minimum=1),
        )
        output_values = tuple(
            value
            for value in outputs.values()
            if value.parsed_output_id == embedded.parsed_output.parsed_output_id
        )
        if len(output_values) != 1:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        output = output_values[0]
        canonical_screening = canonical_json(embedded.model_dump(mode="json"))
        canonical_output = canonical_json(embedded.parsed_output.model_dump(mode="json"))
        if (
            pack_key not in selected_pack_by_key
            or embedded.run_id != resolver.run_id
            or embedded.case_id != resolver.case_id
            or embedded.manifest_id != resolver.manifest_id
            or embedded.version != _integer(screening, "version", minimum=1)
            or (embedded.evidence_pack_id, embedded.evidence_pack_version) != pack_key
            or _sha256(screening, "parsed_output_id") != embedded.parsed_output.parsed_output_id
            or _sha256(screening, "document_sha256")
            != hashlib.sha256(canonical_screening.encode("utf-8")).hexdigest()
            or _integer(screening, "audit_sequence") != case_audit_sequence
            or output.parsed_output_sha256 != embedded.parsed_output.parsed_output_sha256
            or output.response_id != embedded.parsed_output.response_id
            or _sha256(output.row, "response_content_sha256")
            != embedded.parsed_output.response_content_sha256
            or _sha256(output.row, "output_schema_sha256")
            != embedded.parsed_output.output_schema_sha256
            or _sha256(output.row, "model_payload_sha256")
            != embedded.parsed_output.model_payload_sha256
            or output.slot.document_sha256
            != hashlib.sha256(canonical_output.encode("utf-8")).hexdigest()
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        final_receipt = receipts.get(output.request_id)
        final_claim = claims.get(output.request_id)
        if (
            final_receipt is None
            or final_claim is None
            or final_receipt.status != "PARSED"
            or final_receipt.response_id != output.response_id
            or final_receipt.parsed_output_id != output.parsed_output_id
            or final_receipt.parsed_output_sha256 != output.parsed_output_sha256
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        expected_response_ids = {final_receipt.response_id}
        if final_claim.observation.attempt_index == 1:
            predecessors = tuple(
                value
                for value in receipts.values()
                if value.status == "REPAIR_REQUIRED"
                and value.repair_request_id == final_receipt.request_id
            )
            if len(predecessors) != 1:
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            predecessor = predecessors[0]
            predecessor_claim = claims.get(predecessor.request_id)
            if predecessor_claim is None or predecessor_claim.observation.attempt_index != 0:
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            expected_response_ids.add(predecessor.response_id)
        elif final_claim.observation.attempt_index != 0:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        if usage.case_revision <= 1:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        previous_case_version = resolver.case_version(usage.case_revision - 1)
        completion_required = _text(previous_case_version, "status") == "BACKLOGGED"
        completion = resolver.success_completion_for_revision(usage.case_revision)
        if completion_required != (completion is not None):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        completion_item_id = _sha256(completion, "item_id") if completion is not None else None
        current_usage_response_ids = {
            value.response_id
            for value in usages.values()
            if value.consumer_kind == "SCREENING_RESULT" and value.consumer_id == usage.consumer_id
        }
        if not current_usage_response_ids <= expected_response_ids:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        actual_response_ids = {
            value.response_id
            for value in usages.values()
            if value.response_id in expected_response_ids
            and (
                (
                    value.consumer_kind == "SCREENING_RESULT"
                    and value.consumer_id == usage.consumer_id
                )
                or (
                    completion_item_id is not None
                    and value.consumer_kind == "BACKLOG_ITEM"
                    and value.consumer_id == completion_item_id
                )
            )
        }
        if actual_response_ids != expected_response_ids:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        if completion is not None:
            item_id = completion_item_id
            assert isinstance(item_id, str)
            item = resolver.item(item_id)
            backlog_version = _integer(completion, "backlog_version", minimum=1)
            version = resolver.version(item_id, backlog_version)
            head = resolver.head(item_id)
            expected_role = _retry_backlog_role(
                resolver,
                item,
                failures=failures,
                claims=claims,
                receipts=receipts,
                usages=usages,
            )
            completion_kind = _text(completion, "completion_kind")
            completion_id = _sha256(completion, "completion_id")
            if completion_kind == "SCREENING_RESULT":
                completion_matches_usage = completion_id == usage.consumer_id
            elif completion_kind == "PROCEDURAL_REVIEW":
                matching_reviews = tuple(
                    value
                    for value in selected_case.procedural_reviews
                    if value.review_id == completion_id
                )
                if len(matching_reviews) != 1:
                    _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
                review = matching_reviews[0]
                matching_verdicts = tuple(
                    value
                    for value in selected_case.verdicts
                    if value.verdict_id == review.reviewed_verdict_id
                    and value.version == review.reviewed_verdict_version
                    and value.verdict_sha256 == review.reviewed_verdict_sha256
                )
                completion_matches_usage = (
                    len(matching_verdicts) == 1
                    and matching_verdicts[0].screening_id == usage.consumer_id
                )
            else:
                completion_matches_usage = False
            if (
                _text(completion, "outcome_kind") != "SUCCESS"
                or not completion_matches_usage
                or _text(completion, "backlog_status") != "COMPLETED"
                or _integer(completion, "completion_case_revision", minimum=1)
                != usage.case_revision
                or _integer(completion, "completion_audit_sequence") != case_audit_sequence
                or _sha256(completion, "completion_audit_entry_hash")
                != _sha256(audit, "entry_hash")
                or _text(completion, "completion_case_status") != _text(case_version, "status")
                or _text(audit, "object_kind") != completion_kind
                or _text(audit, "object_id") != completion_id
                or _text(item, "stage") != "SCREENING"
                or _optional_text(item, "role") != expected_role
                or _text(item, "stage_input_kind") != "EVIDENCE_PACK"
                or _text(item, "stage_input_id") != pack_key[0]
                or _sha256(item, "stage_input_sha256")
                != selected_pack_by_key[pack_key].document_sha256
                or _integer(head, "current_version", minimum=1) != backlog_version
                or _text(version, "status") != "COMPLETED"
                or _integer(version, "attempt_count") != _integer(completion, "attempt_count")
                or _integer(version, "retry_generation") != _integer(completion, "retry_generation")
                or any(
                    _optional_text(version, column) is not None
                    for column in ("lease_id", "lease_owner_sha256", "lease_expires_at")
                )
            ):
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        return
    item = resolver.item(usage.consumer_id)
    matching_keys = {key for key in selected_pack_by_key if key[0] == _text(item, "stage_input_id")}
    if len(matching_keys) != 1:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    pack_key = next(iter(matching_keys))
    if (
        _text(item, "stage_input_kind") != "EVIDENCE_PACK"
        or _sha256(item, "stage_input_sha256") != selected_pack_by_key[pack_key].document_sha256
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    completion = resolver.completion_for_revision(
        usage.consumer_id,
        usage.case_revision,
    )
    if completion is None:
        _bind_initial_backlog_usage(
            resolver,
            usage,
            selected_case=selected_case,
            item=item,
            audit=audit,
            claims=claims,
            receipts=receipts,
            usages=usages,
        )
        return
    if (
        _text(completion, "manifest_id") != resolver.manifest_id
        or _sha256(completion, "item_id") != usage.consumer_id
        or _text(completion, "outcome_kind") != "FAILURE"
        or _text(completion, "completion_kind") != "BACKLOG_ITEM"
        or _sha256(completion, "completion_id") != usage.consumer_id
        or _integer(completion, "completion_case_revision", minimum=1) != usage.case_revision
        or _integer(completion, "completion_audit_sequence") != case_audit_sequence
        or _sha256(completion, "completion_audit_entry_hash") != _sha256(audit, "entry_hash")
        or _text(audit, "object_kind") != "BACKLOG_ITEM"
        or _text(audit, "object_id") != usage.consumer_id
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)

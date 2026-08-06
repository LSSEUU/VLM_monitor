from __future__ import annotations

import hashlib
import sqlite3
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import pytest

import labcourt.adapters.storage._sqlite_m6_upgrade_case_document as case_document
from labcourt.adapters.storage._sqlite_m6_upgrade_case_document import (
    M6SQLiteCaseAuthorityDocument,
    M6SQLiteCaseDocumentError,
    M6SQLiteCaseDocumentFailureCode,
    read_m6_sqlite_case_authority,
    read_m6_sqlite_case_authority_v3,
)
from labcourt.contracts.audit import AUDIT_GENESIS_HASH, AuditEntry, AuditEntryDraft
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditAction,
    AuditActorRole,
    CaseStatus,
    EvidenceFailureCode,
)
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeCandidateCaseBinding,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSelectedCaseAuditAnchor,
)
from labcourt.contracts.storage import ArtifactRef
from tests.integration import test_m2_sqlite_repository as m2_fixture
from tests.integration import test_m3_sqlite_repository as m3_fixture

RUN_ID = "run-case-authority"
MANIFEST_ID = m3_fixture._manifest().manifest_id
MANIFEST_RULE_VERSION = m3_fixture._manifest().rule_version
RECORDED_AT = "2026-08-04T01:02:03.000004Z"


class _CommitOnCursorConnection(sqlite3.Connection):
    commit_on_next_cursor = False

    def cursor(self, *args: object, **kwargs: object) -> sqlite3.Cursor:
        if self.commit_on_next_cursor:
            self.commit_on_next_cursor = False
            self.commit()
        return super().cursor(*args, **kwargs)  # type: ignore[arg-type]


class _RuntimeBoundaryConnection(sqlite3.Connection):
    rejected_boundary: Literal["transaction", "cursor", "blobopen"] | None = None
    secret = ""

    @property
    def in_transaction(self) -> bool:
        if self.rejected_boundary == "transaction":
            raise RuntimeError(self.secret)
        return super().in_transaction

    def cursor(self, *args: object, **kwargs: object) -> sqlite3.Cursor:
        if self.rejected_boundary == "cursor":
            raise RuntimeError(self.secret)
        return super().cursor(*args, **kwargs)  # type: ignore[arg-type]

    def blobopen(
        self,
        table: str,
        column: str,
        row: int,
        /,
        *,
        readonly: bool = False,
        name: str = "main",
    ) -> sqlite3.Blob:
        if self.rejected_boundary == "blobopen":
            raise RuntimeError(self.secret)
        return super().blobopen(table, column, row, readonly=readonly, name=name)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class _Authority:
    case: Case
    case_document: str
    case_document_sha256: str
    audit: AuditEntry
    audit_document: str
    audit_document_sha256: str
    binding: M6UpgradeCandidateCaseBinding


def _selected_case_audit_anchor(
    authority: _Authority,
) -> M6UpgradeSelectedCaseAuditAnchor:
    return M6UpgradeSelectedCaseAuditAnchor(
        candidate_case_binding_id=authority.binding.case_binding_id,
        action=authority.audit.action,
        object_ref=authority.audit.object_ref,
    )


def _authority(
    *,
    event_rule_version: str | None = None,
    audit_action: AuditAction = AuditAction.CASE_CREATED,
    audit_before_sha256: str | None = None,
    audit_object_kind: ArtifactKind = ArtifactKind.CASE,
    audit_object_id: str | None = None,
    audit_after_sha256: str | None = None,
) -> _Authority:
    event = m3_fixture._event()
    if event_rule_version is not None:
        event_payload = event.model_dump(mode="json", exclude_computed_fields=True)
        event_payload["rule_version"] = event_rule_version
        event = type(event).model_validate(event_payload)
    case = Case(
        run_id=RUN_ID,
        status=CaseStatus.CANDIDATE,
        event=event,
        manifest_id=MANIFEST_ID,
    )
    case_raw = canonical_json(case.model_dump(mode="json"))
    case_sha256 = _sha256(case_raw)
    audit = AuditEntryDraft(
        run_id=RUN_ID,
        sequence=0,
        actor=AuditActorRole.SYSTEM.value,
        action=audit_action,
        object_ref=ArtifactRef(
            kind=audit_object_kind,
            artifact_id=audit_object_id or case.case_id,
        ),
        before_sha256=audit_before_sha256,
        after_sha256=audit_after_sha256 or case_sha256,
        manifest_id=MANIFEST_ID,
        recorded_at=RECORDED_AT,
        prev_entry_hash=AUDIT_GENESIS_HASH,
    ).seal()
    audit_raw = canonical_json(audit.model_dump(mode="json"))
    audit_sha256 = _sha256(audit_raw)
    binding = M6UpgradeCandidateCaseBinding(
        case_id=case.case_id,
        case_revision=1,
        case_document_sha256=case_sha256,
        case_audit_sequence=audit.sequence,
        case_audit_entry_hash=audit.entry_hash,
    )
    return _Authority(
        case=case,
        case_document=case_raw,
        case_document_sha256=case_sha256,
        audit=audit,
        audit_document=audit_raw,
        audit_document_sha256=audit_sha256,
        binding=binding,
    )


def _revision_two_authorities(
    *,
    audit_action: AuditAction = AuditAction.CASE_STATE_CHANGED,
    wrong_before: bool = False,
    wrong_prev_entry_hash: bool = False,
    unsupported_transition: bool = False,
) -> tuple[_Authority, _Authority]:
    first = _authority()
    if unsupported_transition:
        payload = first.case.model_dump(mode="json")
        payload["usage"]["input_tokens"] = 1
        second_case = Case.model_validate(payload)
    else:
        second_case = first.case.model_copy(
            update={
                "status": CaseStatus.HUMAN_REVIEW,
                "timeline": (
                    TimelineEntry(
                        sequence=0,
                        action=AuditAction.CASE_STATE_CHANGED.value,
                        stage="EVIDENCE",
                        object_ref=first.case.case_id,
                        details={"failure_code": EvidenceFailureCode.EVIDENCE_MISSING.value},
                    ),
                ),
            }
        )
    second_document = canonical_json(second_case.model_dump(mode="json"))
    second_sha256 = _sha256(second_document)
    second_audit = AuditEntryDraft(
        run_id=RUN_ID,
        sequence=1,
        actor=AuditActorRole.SYSTEM.value,
        action=audit_action,
        object_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=first.case.case_id),
        before_sha256="f" * 64 if wrong_before else first.case_document_sha256,
        after_sha256=second_sha256,
        manifest_id=MANIFEST_ID,
        recorded_at="2026-08-04T01:02:04.000005Z",
        prev_entry_hash="e" * 64 if wrong_prev_entry_hash else first.audit.entry_hash,
    ).seal()
    second_audit_document = canonical_json(second_audit.model_dump(mode="json"))
    second_binding = M6UpgradeCandidateCaseBinding(
        case_id=second_case.case_id,
        case_revision=2,
        case_document_sha256=second_sha256,
        case_audit_sequence=second_audit.sequence,
        case_audit_entry_hash=second_audit.entry_hash,
    )
    second = _Authority(
        case=second_case,
        case_document=second_document,
        case_document_sha256=second_sha256,
        audit=second_audit,
        audit_document=second_audit_document,
        audit_document_sha256=_sha256(second_audit_document),
        binding=second_binding,
    )
    return first, second


def _mature_creation_authority() -> _Authority:
    _, mature = _revision_two_authorities()
    audit = AuditEntryDraft(
        run_id=RUN_ID,
        sequence=0,
        actor=AuditActorRole.SYSTEM.value,
        action=AuditAction.CASE_CREATED,
        object_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=mature.case.case_id),
        before_sha256=None,
        after_sha256=mature.case_document_sha256,
        manifest_id=MANIFEST_ID,
        recorded_at=RECORDED_AT,
        prev_entry_hash=AUDIT_GENESIS_HASH,
    ).seal()
    audit_document = canonical_json(audit.model_dump(mode="json"))
    return _Authority(
        case=mature.case,
        case_document=mature.case_document,
        case_document_sha256=mature.case_document_sha256,
        audit=audit,
        audit_document=audit_document,
        audit_document_sha256=_sha256(audit_document),
        binding=M6UpgradeCandidateCaseBinding(
            case_id=mature.case.case_id,
            case_revision=1,
            case_document_sha256=mature.case_document_sha256,
            case_audit_sequence=0,
            case_audit_entry_hash=audit.entry_hash,
        ),
    )


def _revision_two_connection(
    *,
    audit_action: AuditAction = AuditAction.CASE_STATE_CHANGED,
    wrong_before: bool = False,
    wrong_prev_entry_hash: bool = False,
    unsupported_transition: bool = False,
) -> tuple[sqlite3.Connection, _Authority]:
    first, second = _revision_two_authorities(
        audit_action=audit_action,
        wrong_before=wrong_before,
        wrong_prev_entry_hash=wrong_prev_entry_hash,
        unsupported_transition=unsupported_transition,
    )
    connection = _connection(authority=first, begin=False)
    connection.execute(
        "INSERT INTO case_versions VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            RUN_ID,
            second.case.case_id,
            2,
            second.case.status.value,
            second.case_document,
            second.case_document_sha256,
            second.audit.sequence,
        ),
    )
    connection.execute(
        "INSERT INTO audit_entries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            RUN_ID,
            second.audit.sequence,
            MANIFEST_ID,
            second.audit.actor,
            second.audit.action.value,
            second.audit.object_ref.kind.value,
            second.audit.object_ref.artifact_id,
            second.audit.before_sha256,
            second.audit.after_sha256,
            second.audit.recorded_at,
            second.audit.prev_entry_hash,
            second.audit.entry_hash,
            second.audit_document,
            second.audit_document_sha256,
        ),
    )
    connection.execute(
        "UPDATE cases SET status = ?, current_revision = 2 WHERE run_id = ? AND case_id = ?",
        (second.case.status.value, RUN_ID, second.case.case_id),
    )
    connection.execute(
        """
        UPDATE runs
        SET revision = 2, audit_head_sequence = ?, audit_head_hash = ?
        WHERE run_id = ?
        """,
        (second.audit.sequence, second.audit.entry_hash, RUN_ID),
    )
    connection.execute("BEGIN")
    return connection, second


def _replace_future_case_metadata(
    connection: sqlite3.Connection,
    first: _Authority,
    second: _Authority,
    *,
    status: CaseStatus,
    action: AuditAction,
    object_ref: ArtifactRef,
    actor: AuditActorRole = AuditActorRole.SYSTEM,
) -> AuditEntry:
    forged = AuditEntryDraft(
        run_id=RUN_ID,
        sequence=second.audit.sequence,
        actor=actor.value,
        action=action,
        object_ref=object_ref,
        before_sha256=first.case_document_sha256,
        after_sha256=second.case_document_sha256,
        manifest_id=MANIFEST_ID,
        recorded_at=second.audit.recorded_at,
        prev_entry_hash=first.audit.entry_hash,
    ).seal()
    forged_document = canonical_json(forged.model_dump(mode="json"))
    connection.execute(
        "UPDATE case_versions SET status = ? WHERE run_id = ? AND case_id = ? AND revision = 2",
        (status.value, RUN_ID, first.case.case_id),
    )
    connection.execute(
        "UPDATE cases SET status = ? WHERE run_id = ? AND case_id = ?",
        (status.value, RUN_ID, first.case.case_id),
    )
    connection.execute(
        """
        UPDATE audit_entries
        SET actor = ?, action = ?, object_kind = ?, object_id = ?, entry_hash = ?,
            entry_json = ?, document_sha256 = ?
        WHERE run_id = ? AND sequence = ?
        """,
        (
            forged.actor,
            forged.action.value,
            forged.object_ref.kind.value,
            forged.object_ref.artifact_id,
            forged.entry_hash,
            forged_document,
            _sha256(forged_document),
            RUN_ID,
            forged.sequence,
        ),
    )
    connection.execute(
        "UPDATE runs SET audit_head_hash = ? WHERE run_id = ?",
        (forged.entry_hash, RUN_ID),
    )
    return forged


def _future_pack_publication_connection(
    *,
    status: CaseStatus = CaseStatus.EVIDENCE_READY,
    version: int = 1,
    complete: int = 1,
    pack_id: str = "a" * 64,
    pack_input_sha256: str = "b" * 64,
    closure_input_sha256: str = "c" * 64,
    document_sha256: str = "d" * 64,
    created_audit_sequence: int = 1,
    pack_json: str | bytes = b"untrusted-future-pack",
) -> tuple[sqlite3.Connection, _Authority, _Authority]:
    first, second = _revision_two_authorities()
    connection, _selected = _revision_two_connection()
    _replace_future_case_metadata(
        connection,
        first,
        second,
        status=status,
        action=AuditAction.EVIDENCE_PACK_PUBLISHED,
        object_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=first.case.case_id),
        actor=AuditActorRole.EVIDENCE,
    )
    connection.execute(
        """
        INSERT INTO evidence_packs(
            run_id, pack_id, case_id, manifest_id, version, complete,
            pack_input_sha256, closure_input_sha256, pack_json,
            document_sha256, created_audit_sequence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            RUN_ID,
            pack_id,
            first.case.case_id,
            MANIFEST_ID,
            version,
            complete,
            pack_input_sha256,
            closure_input_sha256,
            pack_json,
            document_sha256,
            created_audit_sequence,
        ),
    )
    connection.execute(
        """
        UPDATE cases
        SET latest_pack_id = ?, latest_pack_version = ?
        WHERE run_id = ? AND case_id = ?
        """,
        (pack_id, version, RUN_ID, first.case.case_id),
    )
    return connection, first, second


def _real_m2_published_case(
    tmp_path: Path,
) -> tuple[Path, Case, EvidencePack, M6UpgradeCandidateCaseBinding]:
    database, repository = m2_fixture._repository(tmp_path)
    m2_fixture._register_case(repository)
    published = repository.publish_pack(
        m2_fixture.RUN_ID,
        1,
        m2_fixture._draft(version=1, complete=True),
    )
    current = published.case
    connection = sqlite3.connect(database, isolation_level=None)
    try:
        case_row = connection.execute(
            """
            SELECT document_sha256, audit_sequence
            FROM case_versions
            WHERE run_id = ? AND case_id = ? AND revision = ?
            """,
            (m2_fixture.RUN_ID, current.case.case_id, current.revision),
        ).fetchone()
        assert case_row is not None
        audit_row = connection.execute(
            "SELECT entry_hash FROM audit_entries WHERE run_id = ? AND sequence = ?",
            (m2_fixture.RUN_ID, case_row[1]),
        ).fetchone()
        assert audit_row is not None
    finally:
        connection.close()
    binding = M6UpgradeCandidateCaseBinding(
        case_id=current.case.case_id,
        case_revision=current.revision,
        case_document_sha256=case_row[0],
        case_audit_sequence=case_row[1],
        case_audit_entry_hash=audit_row[0],
    )
    return database, current.case, published.pack, binding


def _connection(
    *,
    authority: _Authority | None = None,
    case_body: str | bytes | None = None,
    audit_body: str | bytes | None = None,
    row_manifest_id: str = MANIFEST_ID,
    case_row_status: str | None = None,
    case_row_document_sha256: str | None = None,
    case_row_audit_sequence: int | None = None,
    audit_row_object_id: str | None = None,
    audit_row_entry_hash: str | None = None,
    audit_row_document_sha256: str | None = None,
    root_event_body: str | bytes | None = None,
    root_event_sha256: str | None = None,
    root_event_id: str | None = None,
    root_manifest_id: str | None = None,
    root_status: str | None = None,
    root_created_audit_sequence: int | None = None,
    root_current_revision: int = 1,
    root_latest_pack_id: str | None = None,
    root_latest_pack_version: int | None = None,
    latest_pack_row: tuple[str, int] | None = None,
    run_revision: int | None = None,
    run_audit_head_sequence: int | None = None,
    run_audit_head_hash: str | None = None,
    duplicate: Literal["run", "root", "case", "audit"] | None = None,
    insert_root: bool = True,
    insert_case: bool = True,
    insert_audit: bool = True,
    begin: bool = True,
    connection_factory: type[sqlite3.Connection] = sqlite3.Connection,
) -> sqlite3.Connection:
    stored = authority or _authority()
    connection = sqlite3.connect(
        ":memory:",
        isolation_level=None,
        factory=connection_factory,
    )
    connection.executescript(
        """
        CREATE TABLE runs(
            run_id TEXT NOT NULL,
            manifest_id TEXT NOT NULL,
            revision INTEGER NOT NULL,
            audit_head_sequence INTEGER NOT NULL,
            audit_head_hash TEXT NOT NULL
        );
        CREATE TABLE cases(
            run_id TEXT NOT NULL,
            case_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            manifest_id TEXT NOT NULL,
            status TEXT NOT NULL,
            current_revision INTEGER NOT NULL,
            latest_pack_id TEXT,
            latest_pack_version INTEGER,
            event_json,
            event_sha256 TEXT NOT NULL,
            created_audit_sequence INTEGER NOT NULL
        );
        CREATE TABLE case_versions(
            run_id TEXT NOT NULL,
            case_id TEXT NOT NULL,
            revision INTEGER NOT NULL,
            status TEXT NOT NULL,
            case_json,
            document_sha256 TEXT NOT NULL,
            audit_sequence INTEGER NOT NULL
        );
        CREATE TABLE audit_entries(
            run_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            manifest_id TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            object_kind TEXT NOT NULL,
            object_id TEXT NOT NULL,
            before_sha256 TEXT,
            after_sha256 TEXT,
            recorded_at TEXT NOT NULL,
            prev_entry_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            entry_json,
            document_sha256 TEXT NOT NULL
        );
        CREATE TABLE evidence_packs(
            run_id TEXT NOT NULL,
            pack_id TEXT NOT NULL,
            case_id TEXT NOT NULL,
            manifest_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            complete INTEGER NOT NULL,
            pack_input_sha256 TEXT NOT NULL,
            closure_input_sha256 TEXT NOT NULL,
            pack_json,
            document_sha256 TEXT NOT NULL,
            created_audit_sequence INTEGER NOT NULL
        );
        """
    )
    head_sequence = (
        stored.audit.sequence if run_audit_head_sequence is None else run_audit_head_sequence
    )
    run_values = (
        RUN_ID,
        row_manifest_id,
        head_sequence + 1 if run_revision is None else run_revision,
        head_sequence,
        stored.audit.entry_hash if run_audit_head_hash is None else run_audit_head_hash,
    )
    connection.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?)", run_values)
    if duplicate == "run":
        connection.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?)", run_values)

    event_document = canonical_json(stored.case.event.model_dump(mode="json"))
    root_values = (
        RUN_ID,
        stored.case.case_id,
        root_event_id or stored.case.event.event_id,
        root_manifest_id or row_manifest_id,
        root_status or stored.case.status.value,
        root_current_revision,
        root_latest_pack_id,
        root_latest_pack_version,
        event_document if root_event_body is None else root_event_body,
        root_event_sha256 or _sha256(event_document),
        (
            stored.audit.sequence
            if root_created_audit_sequence is None
            else root_created_audit_sequence
        ),
    )
    if insert_root:
        connection.execute(
            "INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", root_values
        )
        if duplicate == "root":
            connection.execute(
                "INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                root_values,
            )

    if latest_pack_row is not None:
        connection.execute(
            "INSERT INTO evidence_packs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                RUN_ID,
                latest_pack_row[0],
                stored.case.case_id,
                MANIFEST_ID,
                latest_pack_row[1],
                1,
                "a" * 64,
                "b" * 64,
                "{}",
                "c" * 64,
                stored.audit.sequence,
            ),
        )

    case_values = (
        RUN_ID,
        stored.case.case_id,
        1,
        case_row_status or stored.case.status.value,
        stored.case_document if case_body is None else case_body,
        case_row_document_sha256 or stored.case_document_sha256,
        (stored.audit.sequence if case_row_audit_sequence is None else case_row_audit_sequence),
    )
    if insert_case:
        connection.execute(
            "INSERT INTO case_versions VALUES (?, ?, ?, ?, ?, ?, ?)",
            case_values,
        )
        if duplicate == "case":
            connection.execute(
                "INSERT INTO case_versions VALUES (?, ?, ?, ?, ?, ?, ?)",
                case_values,
            )

    audit_values = (
        RUN_ID,
        stored.audit.sequence,
        row_manifest_id,
        stored.audit.actor,
        stored.audit.action.value,
        stored.audit.object_ref.kind.value,
        audit_row_object_id or stored.audit.object_ref.artifact_id,
        stored.audit.before_sha256,
        stored.audit.after_sha256,
        stored.audit.recorded_at,
        stored.audit.prev_entry_hash,
        audit_row_entry_hash or stored.audit.entry_hash,
        stored.audit_document if audit_body is None else audit_body,
        audit_row_document_sha256 or stored.audit_document_sha256,
    )
    if insert_audit:
        connection.execute(
            "INSERT INTO audit_entries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            audit_values,
        )
        if duplicate == "audit":
            connection.execute(
                "INSERT INTO audit_entries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                audit_values,
            )
    if begin:
        connection.execute("BEGIN")
        assert connection.in_transaction
    return connection


def _failure(
    connection: sqlite3.Connection,
    *,
    binding: M6UpgradeCandidateCaseBinding | None = None,
    run_id: str = RUN_ID,
    manifest_id: str = MANIFEST_ID,
    manifest_rule_version: str = MANIFEST_RULE_VERSION,
) -> M6SQLiteCaseDocumentError:
    with pytest.raises(M6SQLiteCaseDocumentError) as raised:
        read_m6_sqlite_case_authority(
            connection=connection,
            expected_run_id=run_id,
            expected_manifest_id=manifest_id,
            expected_manifest_rule_version=manifest_rule_version,
            candidate_case_binding=binding or _authority().binding,
        )
    return raised.value


def _v3_failure(
    connection: sqlite3.Connection,
    *,
    binding: M6UpgradeCandidateCaseBinding,
    anchor: M6UpgradeSelectedCaseAuditAnchor,
) -> M6SQLiteCaseDocumentError:
    with pytest.raises(M6SQLiteCaseDocumentError) as raised:
        read_m6_sqlite_case_authority_v3(
            connection=connection,
            expected_run_id=RUN_ID,
            expected_manifest_id=MANIFEST_ID,
            expected_manifest_rule_version=MANIFEST_RULE_VERSION,
            candidate_case_binding=binding,
            selected_case_audit_anchor=anchor,
        )
    return raised.value


def _close(connection: sqlite3.Connection) -> None:
    if connection.in_transaction:
        connection.rollback()
    connection.close()


def test_case_reader_reconstructs_a_real_case_revision_and_audit_on_the_caller_cut(
    tmp_path: Path,
) -> None:
    database, repository = m3_fixture._repository(tmp_path)
    snapshot = repository.create_or_get_case(m3_fixture.RUN_ID, m3_fixture._event())
    case_raw = canonical_json(snapshot.case.model_dump(mode="json"))
    case_sha256 = _sha256(case_raw)
    audit = repository.list_audit_entries(m3_fixture.RUN_ID)[-1]
    binding = M6UpgradeCandidateCaseBinding(
        case_id=snapshot.case.case_id,
        case_revision=snapshot.revision,
        case_document_sha256=case_sha256,
        case_audit_sequence=audit.sequence,
        case_audit_entry_hash=audit.entry_hash,
    )
    connection = sqlite3.connect(database, isolation_level=None)
    connection.execute("BEGIN")
    changes_before = connection.total_changes
    try:
        observed = read_m6_sqlite_case_authority(
            connection=connection,
            expected_run_id=m3_fixture.RUN_ID,
            expected_manifest_id=m3_fixture._manifest().manifest_id,
            expected_manifest_rule_version=m3_fixture._manifest().rule_version,
            candidate_case_binding=binding,
        )
        assert connection.in_transaction
        assert connection.total_changes == changes_before
    finally:
        _close(connection)

    assert isinstance(observed, M6SQLiteCaseAuthorityDocument)
    assert observed.candidate_case_binding == binding
    assert observed.case == snapshot.case
    assert observed.canonical_case_document == case_raw
    assert observed.case_document_sha256 == case_sha256
    assert observed.audit_entry == audit
    assert observed.canonical_audit_document == canonical_json(audit.model_dump(mode="json"))
    assert observed.audit_document_sha256 == _sha256(observed.canonical_audit_document)


def test_v3_case_reader_exact_joins_the_genesis_selected_audit_anchor() -> None:
    authority = _authority()
    anchor = _selected_case_audit_anchor(authority)
    connection = _connection(authority=authority)
    try:
        observed = read_m6_sqlite_case_authority_v3(
            connection=connection,
            expected_run_id=RUN_ID,
            expected_manifest_id=MANIFEST_ID,
            expected_manifest_rule_version=MANIFEST_RULE_VERSION,
            candidate_case_binding=authority.binding,
            selected_case_audit_anchor=anchor,
        )
    finally:
        _close(connection)

    assert observed.case == authority.case
    assert observed.audit_entry == authority.audit


def test_v3_case_reader_exact_joins_a_later_selected_audit_anchor() -> None:
    connection, selected = _revision_two_connection()
    try:
        observed = read_m6_sqlite_case_authority_v3(
            connection=connection,
            expected_run_id=RUN_ID,
            expected_manifest_id=MANIFEST_ID,
            expected_manifest_rule_version=MANIFEST_RULE_VERSION,
            candidate_case_binding=selected.binding,
            selected_case_audit_anchor=_selected_case_audit_anchor(selected),
        )
    finally:
        _close(connection)

    assert observed.case == selected.case
    assert observed.audit_entry == selected.audit


@pytest.mark.parametrize("drift", ("action", "object_ref", "binding"))
def test_v3_case_reader_rejects_selected_audit_anchor_drift(drift: str) -> None:
    authority = _authority()
    anchor_payload = _selected_case_audit_anchor(authority).model_dump(
        mode="json",
        exclude_computed_fields=True,
    )
    if drift == "action":
        anchor_payload["action"] = AuditAction.CASE_STATE_CHANGED.value
    elif drift == "object_ref":
        anchor_payload["object_ref"] = {
            "kind": ArtifactKind.CASE.value,
            "artifact_id": "123e4567-e89b-42d3-a456-426614174000",
        }
    else:
        anchor_payload["candidate_case_binding_id"] = "0" * 64
    anchor = M6UpgradeSelectedCaseAuditAnchor.model_validate(anchor_payload)
    connection = _connection(authority=authority)
    try:
        failure = _v3_failure(
            connection,
            binding=authority.binding,
            anchor=anchor,
        )
    finally:
        _close(connection)

    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.SELECTED_AUDIT_ANCHOR_MISMATCH


def test_v3_case_reader_rejects_a_noncanonical_selected_audit_anchor() -> None:
    authority = _authority()
    anchor = M6UpgradeSelectedCaseAuditAnchor.model_construct(
        schema_version="not-the-anchor-schema",
        candidate_case_binding_id=authority.binding.case_binding_id,
        action=authority.audit.action,
        object_ref=authority.audit.object_ref,
    )
    connection = _connection(authority=authority)
    try:
        failure = _v3_failure(
            connection,
            binding=authority.binding,
            anchor=anchor,
        )
    finally:
        _close(connection)

    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.INVALID_ARGUMENT


def test_v3_case_reader_exact_joins_a_real_m3_non_case_transition(tmp_path: Path) -> None:
    database, evidence, repository, pack, closure, snapshot, head = m3_fixture._m3_setup(tmp_path)
    _request, _response, output, _receipt = m3_fixture._persist_direct_parse(
        repository,
        pack,
    )
    screening = m3_fixture._screening_for(pack, output)
    committed = repository.commit_screening(
        m3_fixture.RUN_ID,
        snapshot.revision,
        head,
        closure,
        screening,
    )
    case_raw = canonical_json(committed.case.case.model_dump(mode="json"))
    case_sha256 = _sha256(case_raw)
    selected_audit = next(
        audit
        for audit in evidence.list_audit_entries(m3_fixture.RUN_ID)
        if audit.after_sha256 == case_sha256
    )
    assert selected_audit.action == AuditAction.CASE_STATE_CHANGED
    assert selected_audit.object_ref == ArtifactRef(
        kind=ArtifactKind.SCREENING_RESULT,
        artifact_id=screening.screening_id,
    )
    binding = M6UpgradeCandidateCaseBinding(
        case_id=committed.case.case.case_id,
        case_revision=committed.case.revision,
        case_document_sha256=case_sha256,
        case_audit_sequence=selected_audit.sequence,
        case_audit_entry_hash=selected_audit.entry_hash,
    )
    anchor = M6UpgradeSelectedCaseAuditAnchor(
        candidate_case_binding_id=binding.case_binding_id,
        action=selected_audit.action,
        object_ref=selected_audit.object_ref,
    )
    connection = sqlite3.connect(database, isolation_level=None)
    connection.execute("BEGIN")
    try:
        observed = read_m6_sqlite_case_authority_v3(
            connection=connection,
            expected_run_id=m3_fixture.RUN_ID,
            expected_manifest_id=m3_fixture._manifest().manifest_id,
            expected_manifest_rule_version=m3_fixture._manifest().rule_version,
            candidate_case_binding=binding,
            selected_case_audit_anchor=anchor,
        )
    finally:
        _close(connection)

    assert observed.case == committed.case.case
    assert observed.audit_entry == selected_audit


def test_case_reader_requires_a_caller_owned_active_transaction() -> None:
    connection = _connection(begin=False)
    try:
        failure = _failure(connection)
    finally:
        connection.close()
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.TRANSACTION_REQUIRED


@pytest.mark.parametrize(
    ("run_id", "manifest_id", "insert_case", "insert_audit", "expected"),
    (
        (
            "missing-run",
            MANIFEST_ID,
            True,
            True,
            M6SQLiteCaseDocumentFailureCode.SCOPE_NOT_FOUND,
        ),
        (
            RUN_ID,
            "f" * 64,
            True,
            True,
            M6SQLiteCaseDocumentFailureCode.SCOPE_MISMATCH,
        ),
        (
            RUN_ID,
            MANIFEST_ID,
            False,
            True,
            M6SQLiteCaseDocumentFailureCode.DOCUMENT_NOT_FOUND,
        ),
        (
            RUN_ID,
            MANIFEST_ID,
            True,
            False,
            M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
        ),
    ),
)
def test_case_reader_distinguishes_scope_case_and_audit_absence(
    run_id: str,
    manifest_id: str,
    insert_case: bool,
    insert_audit: bool,
    expected: M6SQLiteCaseDocumentFailureCode,
) -> None:
    connection = _connection(insert_case=insert_case, insert_audit=insert_audit)
    try:
        failure = _failure(
            connection,
            run_id=run_id,
            manifest_id=manifest_id,
        )
    finally:
        _close(connection)
    assert failure.reason_code == expected


@pytest.mark.parametrize("target", ("case", "audit"))
def test_case_reader_preflights_each_document_before_typed_parse(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    authority = _authority()
    if target == "case":
        monkeypatch.setattr(case_document, "MAX_M6_SQLITE_CASE_DOCUMENT_BYTES", 4)
        connection = _connection(authority=authority, case_body="not-json")
    else:
        case_size = len(authority.case_document.encode("utf-8"))
        monkeypatch.setattr(
            case_document,
            "MAX_M6_SQLITE_CASE_DOCUMENT_BYTES",
            case_size,
        )
        connection = _connection(
            authority=authority,
            audit_body="x" * (case_size + 1),
        )
    try:
        failure = _failure(connection, binding=authority.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.DOCUMENT_TOO_LARGE


def test_case_reader_uses_sqlite_octet_length_metadata_for_both_documents() -> None:
    if sqlite3.sqlite_version_info < case_document._SQLITE_OCTET_LENGTH_MIN_VERSION:
        pytest.skip("SQLite octet_length is unavailable")
    authority = _authority()
    connection = _connection(authority=authority)
    statements: list[str] = []
    connection.set_trace_callback(statements.append)
    try:
        read_m6_sqlite_case_authority(
            connection=connection,
            expected_run_id=RUN_ID,
            expected_manifest_id=MANIFEST_ID,
            expected_manifest_rule_version=MANIFEST_RULE_VERSION,
            candidate_case_binding=authority.binding,
        )
        case_bytecode = connection.execute(
            """
            EXPLAIN
            SELECT octet_length(case_json)
            FROM case_versions
            WHERE run_id = ? AND case_id = ? AND revision = ?
            """,
            (RUN_ID, authority.case.case_id, 1),
        ).fetchall()
        audit_bytecode = connection.execute(
            """
            EXPLAIN
            SELECT octet_length(entry_json)
            FROM audit_entries
            WHERE run_id = ? AND sequence = ?
            """,
            (RUN_ID, authority.audit.sequence),
        ).fetchall()
    finally:
        _close(connection)

    assert any("octet_length(case_json)" in statement for statement in statements)
    assert any("octet_length(entry_json)" in statement for statement in statements)
    case_column_ops = [row for row in case_bytecode if row[1] == "Column" and row[3] == 4]
    audit_column_ops = [row for row in audit_bytecode if row[1] == "Column" and row[3] == 12]
    assert case_column_ops and audit_column_ops
    assert all(int(row[6]) & 0x40 for row in (*case_column_ops, *audit_column_ops))


def test_case_reader_has_a_pre_343_incremental_blob_size_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(case_document, "_USE_SQLITE_OCTET_LENGTH", False)
    authority = _authority()
    connection = _connection(authority=authority)
    statements: list[str] = []
    connection.set_trace_callback(statements.append)
    try:
        observed = read_m6_sqlite_case_authority(
            connection=connection,
            expected_run_id=RUN_ID,
            expected_manifest_id=MANIFEST_ID,
            expected_manifest_rule_version=MANIFEST_RULE_VERSION,
            candidate_case_binding=authority.binding,
        )
    finally:
        _close(connection)

    assert observed.case == authority.case
    assert observed.audit_entry == authority.audit
    assert all("octet_length" not in statement for statement in statements)


@pytest.mark.parametrize("target", ("case", "audit"))
def test_case_reader_rejects_noncanonical_documents(target: str) -> None:
    authority = _authority()
    connection = (
        _connection(authority=authority, case_body=authority.case_document + " ")
        if target == "case"
        else _connection(authority=authority, audit_body=authority.audit_document + " ")
    )
    try:
        failure = _failure(connection, binding=authority.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.DOCUMENT_INVALID


def test_case_reader_distinguishes_case_index_and_audit_index_corruption() -> None:
    authority = _authority()
    corruptions = (
        (
            _connection(authority=authority, case_row_status=CaseStatus.CLOSED.value),
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
        (
            _connection(authority=authority, case_row_document_sha256="f" * 64),
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
        (
            _connection(authority=authority, audit_row_object_id="another-case"),
            M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
        ),
        (
            _connection(authority=authority, audit_row_document_sha256="f" * 64),
            M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
        ),
        (
            _connection(authority=authority, audit_row_entry_hash="f" * 64),
            M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
        ),
    )
    for connection, expected in corruptions:
        try:
            failure = _failure(connection, binding=authority.binding)
        finally:
            _close(connection)
        assert failure.reason_code == expected


def test_case_reader_distinguishes_untrusted_binding_drift() -> None:
    authority = _authority()
    forged_bindings = (
        authority.binding.model_copy(update={"case_document_sha256": "f" * 64}),
        authority.binding.model_copy(update={"case_audit_sequence": 1}),
        authority.binding.model_copy(update={"case_audit_entry_hash": "f" * 64}),
    )
    for binding in forged_bindings:
        connection = _connection(authority=authority)
        try:
            failure = _failure(connection, binding=binding)
        finally:
            _close(connection)
        assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.BINDING_MISMATCH


@pytest.mark.parametrize(
    "authority",
    (
        _authority(audit_object_kind=ArtifactKind.EVENT),
        _authority(audit_object_id="123e4567-e89b-42d3-a456-426614174000"),
        _authority(audit_after_sha256="e" * 64),
    ),
)
def test_case_reader_rejects_audit_object_and_after_hash_mismatch(
    authority: _Authority,
) -> None:
    connection = _connection(authority=authority)
    try:
        failure = _failure(connection, binding=authority.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH


@pytest.mark.parametrize("duplicate", ("run", "root", "case", "audit"))
def test_case_reader_enforces_one_row_at_every_boundary(
    duplicate: Literal["run", "root", "case", "audit"],
) -> None:
    authority = _authority()
    connection = _connection(authority=authority, duplicate=duplicate)
    try:
        failure = _failure(connection, binding=authority.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.ROW_LIMIT_EXCEEDED


def test_case_reader_errors_are_typed_payload_free_and_arguments_fail_closed() -> None:
    error = M6SQLiteCaseDocumentError(M6SQLiteCaseDocumentFailureCode.BINDING_MISMATCH)
    assert error.args == ("M6 SQLite Case document failed: BINDING_MISMATCH",)
    assert vars(error) == {"reason_code": error.reason_code}

    authority = _authority()
    invalid_binding = M6UpgradeCandidateCaseBinding.model_construct(
        case_id=authority.binding.case_id,
        case_revision=0,
        case_document_sha256=authority.binding.case_document_sha256,
        case_audit_sequence=authority.binding.case_audit_sequence,
        case_audit_entry_hash=authority.binding.case_audit_entry_hash,
    )
    connection = _connection(authority=authority)
    try:
        invalid = _failure(connection, binding=invalid_binding)
    finally:
        _close(connection)
    assert invalid.reason_code == M6SQLiteCaseDocumentFailureCode.INVALID_ARGUMENT

    secret = "../private/person/case.json"
    connection = _connection(authority=authority)
    try:
        unsafe = _failure(connection, binding=authority.binding, run_id=secret)
    finally:
        _close(connection)
    assert unsafe.reason_code == M6SQLiteCaseDocumentFailureCode.INVALID_ARGUMENT
    assert secret not in str(unsafe)
    assert secret not in repr(unsafe)

    closed = _connection(authority=authority)
    closed.close()
    rejected = _failure(closed, binding=authority.binding)
    assert rejected.reason_code == M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED

    with pytest.raises(TypeError, match="reason_code"):
        M6SQLiteCaseDocumentError("BINDING_MISMATCH")  # type: ignore[arg-type]


def test_case_reader_proves_every_revision_and_the_genesis_audit_prefix() -> None:
    connection, selected = _revision_two_connection()
    statements: list[str] = []
    connection.set_trace_callback(statements.append)
    try:
        observed = read_m6_sqlite_case_authority(
            connection=connection,
            expected_run_id=RUN_ID,
            expected_manifest_id=MANIFEST_ID,
            expected_manifest_rule_version=MANIFEST_RULE_VERSION,
            candidate_case_binding=selected.binding,
        )
    finally:
        _close(connection)

    assert observed.case == selected.case
    assert observed.audit_entry == selected.audit
    case_preflight = next(
        index for index, statement in enumerate(statements) if "typeof(case_json)" in statement
    )
    root_preflight = next(
        index for index, statement in enumerate(statements) if "typeof(event_json)" in statement
    )
    audit_preflight = next(
        index for index, statement in enumerate(statements) if "typeof(entry_json)" in statement
    )
    case_materialization = next(
        index
        for index, statement in enumerate(statements)
        if "status," in statement and "case_json, document_sha256" in statement
    )
    audit_materialization = next(
        index
        for index, statement in enumerate(statements)
        if "entry_json, document_sha256" in statement and "typeof(entry_json)" not in statement
    )
    root_materialization = next(
        index
        for index, statement in enumerate(statements)
        if "event_json, event_sha256" in statement and "typeof(event_json)" not in statement
    )
    assert max(root_preflight, case_preflight, audit_preflight) < min(
        root_materialization,
        case_materialization,
        audit_materialization,
    )


@pytest.mark.parametrize(
    ("before_sha256", "expected"),
    (
        (None, M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH),
        ("f" * 64, M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH),
    ),
)
def test_case_reader_rejects_wrong_creation_action_and_before_hash(
    before_sha256: str | None,
    expected: M6SQLiteCaseDocumentFailureCode,
) -> None:
    authority = _authority(
        audit_action=AuditAction.CASE_STATE_CHANGED,
        audit_before_sha256=before_sha256,
    )
    connection = _connection(authority=authority)
    try:
        failure = _failure(connection, binding=authority.binding)
    finally:
        _close(connection)
    assert failure.reason_code == expected


def test_case_reader_rejects_a_missing_predecessor_revision() -> None:
    connection, selected = _revision_two_connection()
    connection.execute(
        "DELETE FROM case_versions WHERE run_id = ? AND case_id = ? AND revision = 1",
        (RUN_ID, selected.case.case_id),
    )
    try:
        failure = _failure(connection, binding=selected.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH


def test_case_reader_classifies_a_lagging_binding_audit_anchor_as_binding_drift() -> None:
    first, _second = _revision_two_authorities()
    connection, selected = _revision_two_connection()
    lagging = selected.binding.model_copy(
        update={
            "case_audit_sequence": first.audit.sequence,
            "case_audit_entry_hash": first.audit.entry_hash,
        }
    )
    try:
        failure = _failure(connection, binding=lagging)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.BINDING_MISMATCH


def test_case_reader_classifies_a_binding_revision_beyond_the_case_head_as_drift() -> None:
    authority = _authority()
    connection = _connection(authority=authority)
    ahead = authority.binding.model_copy(update={"case_revision": 2})
    try:
        failure = _failure(connection, binding=ahead)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.BINDING_MISMATCH


@pytest.mark.parametrize(
    ("options", "expected"),
    (
        (
            {"wrong_before": True},
            M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
        ),
        (
            {"audit_action": AuditAction.EVIDENCE_PACK_PUBLISHED},
            M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
        ),
        (
            {"unsupported_transition": True},
            M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
        ),
    ),
)
def test_case_reader_rejects_broken_before_action_and_transition_semantics(
    options: dict[str, object],
    expected: M6SQLiteCaseDocumentFailureCode,
) -> None:
    connection, selected = _revision_two_connection(**options)  # type: ignore[arg-type]
    try:
        failure = _failure(connection, binding=selected.binding)
    finally:
        _close(connection)
    assert failure.reason_code == expected


def test_case_reader_rejects_a_self_hashed_but_detached_candidate_audit() -> None:
    connection, selected = _revision_two_connection(wrong_prev_entry_hash=True)
    try:
        failure = _failure(connection, binding=selected.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH


def test_case_reader_total_history_budget_fails_before_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection, selected = _revision_two_connection()
    monkeypatch.setattr(case_document, "MAX_M6_SQLITE_CASE_HISTORY_BYTES", 1)
    statements: list[str] = []
    connection.set_trace_callback(statements.append)
    try:
        failure = _failure(connection, binding=selected.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.DOCUMENT_TOO_LARGE
    assert not any(
        "case_json, document_sha256" in statement or "entry_json, document_sha256" in statement
        for statement in statements
    )


def test_case_reader_suppresses_custom_text_factory_payloads_from_tracebacks() -> None:
    secret = "../private/person/case-chain.json"
    authority = _authority()
    connection = _connection(authority=authority)

    def rejecting_text_factory(_value: bytes) -> str:
        raise RuntimeError(secret)

    connection.text_factory = rejecting_text_factory
    try:
        failure = _failure(connection, binding=authority.binding)
    finally:
        _close(connection)
    rendered = "".join(traceback.format_exception(type(failure), failure, failure.__traceback__))
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED
    assert failure.__cause__ is None
    assert failure.__suppress_context__ is True
    assert secret not in rendered
    assert "RuntimeError" not in rendered


@pytest.mark.parametrize("boundary", ("transaction", "cursor", "blobopen"))
def test_case_reader_suppresses_connection_boundary_runtime_payloads_from_tracebacks(
    monkeypatch: pytest.MonkeyPatch,
    boundary: Literal["transaction", "cursor", "blobopen"],
) -> None:
    secret = "../private/person/case-boundary.json"
    authority = _authority()
    connection = _connection(
        authority=authority,
        connection_factory=_RuntimeBoundaryConnection,
    )
    assert isinstance(connection, _RuntimeBoundaryConnection)
    if boundary == "blobopen":
        monkeypatch.setattr(case_document, "_USE_SQLITE_OCTET_LENGTH", False)
    connection.secret = secret
    connection.rejected_boundary = boundary
    try:
        failure = _failure(connection, binding=authority.binding)
    finally:
        connection.rejected_boundary = None
        _close(connection)
    rendered = "".join(traceback.format_exception(type(failure), failure, failure.__traceback__))
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED
    assert failure.__cause__ is None
    assert failure.__suppress_context__ is True
    assert secret not in rendered
    assert "RuntimeError" not in rendered


def test_case_reader_rejects_a_mature_case_disguised_as_revision_one_creation() -> None:
    authority = _mature_creation_authority()
    connection = _connection(authority=authority)
    try:
        failure = _failure(connection, binding=authority.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH


@pytest.mark.parametrize(
    ("options", "expected"),
    (
        (
            {"insert_root": False},
            M6SQLiteCaseDocumentFailureCode.DOCUMENT_NOT_FOUND,
        ),
        (
            {"root_event_id": "another-event"},
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
        (
            {"root_manifest_id": "f" * 64},
            M6SQLiteCaseDocumentFailureCode.SCOPE_MISMATCH,
        ),
        (
            {
                "root_event_body": canonical_json(_authority().case.event.model_dump(mode="json"))
                + " "
            },
            M6SQLiteCaseDocumentFailureCode.DOCUMENT_INVALID,
        ),
        (
            {"root_event_sha256": "f" * 64},
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
        (
            {"root_created_audit_sequence": 1},
            M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
        ),
        (
            {"root_current_revision": 0},
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
        (
            {"root_current_revision": 2},
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
        (
            {"root_status": CaseStatus.CLOSED.value},
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
        (
            {
                "root_latest_pack_id": "f" * 64,
                "root_latest_pack_version": 1,
            },
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
    ),
)
def test_case_reader_rejects_missing_or_corrupt_case_aggregate_roots(
    options: dict[str, object],
    expected: M6SQLiteCaseDocumentFailureCode,
) -> None:
    authority = _authority()
    connection = _connection(authority=authority, **options)  # type: ignore[arg-type]
    try:
        failure = _failure(connection, binding=authority.binding)
    finally:
        _close(connection)
    assert failure.reason_code == expected


def test_case_reader_rejects_a_self_consistent_event_for_another_manifest_rule() -> None:
    authority = _authority(event_rule_version="forged-rule-version")
    connection = _connection(authority=authority)
    try:
        failure = _failure(connection, binding=authority.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH


@pytest.mark.parametrize(
    ("options", "expected"),
    (
        (
            {"run_revision": 2},
            M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
        ),
        (
            {"run_audit_head_hash": "f" * 64},
            M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
        ),
        (
            {
                "run_revision": 2,
                "run_audit_head_sequence": 1,
                "run_audit_head_hash": "f" * 64,
            },
            M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
        ),
        (
            {
                "run_revision": 0,
                "run_audit_head_sequence": -1,
                "run_audit_head_hash": AUDIT_GENESIS_HASH,
            },
            M6SQLiteCaseDocumentFailureCode.BINDING_MISMATCH,
        ),
    ),
)
def test_case_reader_rejects_a_run_head_that_does_not_cover_the_candidate(
    options: dict[str, object],
    expected: M6SQLiteCaseDocumentFailureCode,
) -> None:
    authority = _authority()
    connection = _connection(authority=authority, **options)  # type: ignore[arg-type]
    try:
        failure = _failure(connection, binding=authority.binding)
    finally:
        _close(connection)
    assert failure.reason_code == expected


def test_case_reader_rejects_an_audit_tail_hidden_after_the_run_head() -> None:
    first, second = _revision_two_authorities()
    connection = _connection(authority=first)
    connection.execute(
        "INSERT INTO audit_entries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            RUN_ID,
            second.audit.sequence,
            MANIFEST_ID,
            second.audit.actor,
            second.audit.action.value,
            second.audit.object_ref.kind.value,
            second.audit.object_ref.artifact_id,
            second.audit.before_sha256,
            second.audit.after_sha256,
            second.audit.recorded_at,
            second.audit.prev_entry_hash,
            second.audit.entry_hash,
            second.audit_document,
            second.audit_document_sha256,
        ),
    )
    try:
        failure = _failure(connection, binding=first.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH


def test_case_reader_rejects_a_transaction_replaced_after_entry_check() -> None:
    authority = _authority()
    connection = _connection(
        authority=authority,
        connection_factory=_CommitOnCursorConnection,
    )
    assert isinstance(connection, _CommitOnCursorConnection)
    connection.commit_on_next_cursor = True
    try:
        failure = _failure(connection, binding=authority.binding)
        assert not connection.in_transaction
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.TRANSACTION_REQUIRED


def test_historical_case_selection_requires_the_head_anchor_but_not_future_case_bodies() -> None:
    first, _ = _revision_two_authorities()
    connection, _selected = _revision_two_connection()
    connection.execute(
        "UPDATE case_versions SET case_json = ? WHERE run_id = ? AND case_id = ? AND revision = 2",
        (b"untrusted-future-case", RUN_ID, first.case.case_id),
    )
    try:
        observed = read_m6_sqlite_case_authority(
            connection=connection,
            expected_run_id=RUN_ID,
            expected_manifest_id=MANIFEST_ID,
            expected_manifest_rule_version=MANIFEST_RULE_VERSION,
            candidate_case_binding=first.binding,
        )
    finally:
        _close(connection)
    assert observed.case == first.case
    assert observed.audit_entry == first.audit


def test_historical_case_selection_rejects_a_gap_hidden_behind_the_current_revision() -> None:
    first, second = _revision_two_authorities()
    connection, _selected = _revision_two_connection()
    connection.execute(
        "DELETE FROM case_versions WHERE run_id = ? AND case_id = ? AND revision = 2",
        (RUN_ID, first.case.case_id),
    )
    connection.execute(
        "INSERT INTO case_versions VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            RUN_ID,
            first.case.case_id,
            3,
            second.case.status.value,
            second.case_document,
            second.case_document_sha256,
            second.audit.sequence,
        ),
    )
    connection.execute(
        "UPDATE cases SET current_revision = 3 WHERE run_id = ? AND case_id = ?",
        (RUN_ID, first.case.case_id),
    )
    try:
        failure = _failure(connection, binding=first.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH


@pytest.mark.parametrize(
    "mutation",
    (
        "UPDATE cases SET status = 'ALIEN' WHERE run_id = ? AND case_id = ?",
        (
            "UPDATE case_versions SET status = 'ALIEN' "
            "WHERE run_id = ? AND case_id = ? AND revision = 2"
        ),
    ),
)
def test_historical_case_selection_rejects_invalid_future_status_metadata(
    mutation: str,
) -> None:
    first, _ = _revision_two_authorities()
    connection, _selected = _revision_two_connection()
    parameters: tuple[object, ...] = (RUN_ID, first.case.case_id)
    connection.execute(mutation, parameters)
    try:
        failure = _failure(connection, binding=first.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH


def test_historical_case_selection_rejects_self_consistent_invalid_future_status_metadata() -> None:
    first, _ = _revision_two_authorities()
    connection, _selected = _revision_two_connection()
    connection.execute(
        "UPDATE cases SET status = 'ALIEN' WHERE run_id = ? AND case_id = ?",
        (RUN_ID, first.case.case_id),
    )
    connection.execute(
        "UPDATE case_versions SET status = 'ALIEN' "
        "WHERE run_id = ? AND case_id = ? AND revision = 2",
        (RUN_ID, first.case.case_id),
    )
    try:
        failure = _failure(connection, binding=first.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH


def test_historical_case_selection_rejects_future_version_detached_from_audit() -> None:
    first, _ = _revision_two_authorities()
    connection, _selected = _revision_two_connection()
    connection.execute(
        "UPDATE case_versions SET document_sha256 = ? "
        "WHERE run_id = ? AND case_id = ? AND revision = 2",
        ("f" * 64, RUN_ID, first.case.case_id),
    )
    try:
        failure = _failure(connection, binding=first.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH


def test_historical_case_selection_rejects_future_case_hashes_on_unrelated_audit_action() -> None:
    first, second = _revision_two_authorities()
    connection, _selected = _revision_two_connection()
    forged = AuditEntryDraft(
        run_id=RUN_ID,
        sequence=second.audit.sequence,
        actor=AuditActorRole.RETENTION.value,
        action=AuditAction.MEDIA_PURGE_REQUESTED,
        object_ref=ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id="a" * 64),
        before_sha256=first.case_document_sha256,
        after_sha256=second.case_document_sha256,
        manifest_id=MANIFEST_ID,
        recorded_at=second.audit.recorded_at,
        prev_entry_hash=first.audit.entry_hash,
    ).seal()
    forged_document = canonical_json(forged.model_dump(mode="json"))
    connection.execute(
        """
        UPDATE audit_entries
        SET actor = ?, action = ?, object_kind = ?, object_id = ?,
            before_sha256 = ?, after_sha256 = ?, recorded_at = ?,
            prev_entry_hash = ?, entry_hash = ?, entry_json = ?, document_sha256 = ?
        WHERE run_id = ? AND sequence = ?
        """,
        (
            forged.actor,
            forged.action.value,
            forged.object_ref.kind.value,
            forged.object_ref.artifact_id,
            forged.before_sha256,
            forged.after_sha256,
            forged.recorded_at,
            forged.prev_entry_hash,
            forged.entry_hash,
            forged_document,
            _sha256(forged_document),
            RUN_ID,
            forged.sequence,
        ),
    )
    connection.execute(
        "UPDATE runs SET audit_head_hash = ? WHERE run_id = ?",
        (forged.entry_hash, RUN_ID),
    )
    try:
        failure = _failure(connection, binding=first.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH


def test_historical_case_selection_rejects_case_closed_audit_for_non_closed_metadata() -> None:
    first, second = _revision_two_authorities()
    connection, _selected = _revision_two_connection()
    forged = AuditEntryDraft(
        run_id=RUN_ID,
        sequence=second.audit.sequence,
        actor=AuditActorRole.SYSTEM.value,
        action=AuditAction.CASE_CLOSED,
        object_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=first.case.case_id),
        before_sha256=first.case_document_sha256,
        after_sha256=second.case_document_sha256,
        manifest_id=MANIFEST_ID,
        recorded_at=second.audit.recorded_at,
        prev_entry_hash=first.audit.entry_hash,
    ).seal()
    forged_document = canonical_json(forged.model_dump(mode="json"))
    connection.execute(
        """
        UPDATE audit_entries
        SET action = ?, object_kind = ?, object_id = ?, entry_hash = ?,
            entry_json = ?, document_sha256 = ?
        WHERE run_id = ? AND sequence = ?
        """,
        (
            forged.action.value,
            forged.object_ref.kind.value,
            forged.object_ref.artifact_id,
            forged.entry_hash,
            forged_document,
            _sha256(forged_document),
            RUN_ID,
            forged.sequence,
        ),
    )
    connection.execute(
        "UPDATE runs SET audit_head_hash = ? WHERE run_id = ?",
        (forged.entry_hash, RUN_ID),
    )
    try:
        failure = _failure(connection, binding=first.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH


def test_historical_case_selection_rejects_case_state_change_to_candidate_metadata() -> None:
    first, _ = _revision_two_authorities(unsupported_transition=True)
    connection, _selected = _revision_two_connection(unsupported_transition=True)
    try:
        failure = _failure(connection, binding=first.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH


def test_historical_case_selection_rejects_impossible_action_kind_status_metadata() -> None:
    first, second = _revision_two_authorities()
    connection, _selected = _revision_two_connection()
    forged = AuditEntryDraft(
        run_id=RUN_ID,
        sequence=second.audit.sequence,
        actor=AuditActorRole.SYSTEM.value,
        action=AuditAction.CASE_STATE_CHANGED,
        object_ref=ArtifactRef(kind=ArtifactKind.APPEAL, artifact_id="a" * 64),
        before_sha256=first.case_document_sha256,
        after_sha256=second.case_document_sha256,
        manifest_id=MANIFEST_ID,
        recorded_at=second.audit.recorded_at,
        prev_entry_hash=first.audit.entry_hash,
    ).seal()
    forged_document = canonical_json(forged.model_dump(mode="json"))
    connection.execute(
        "UPDATE case_versions SET status = ? WHERE run_id = ? AND case_id = ? AND revision = 2",
        (CaseStatus.SCREENED.value, RUN_ID, first.case.case_id),
    )
    connection.execute(
        "UPDATE cases SET status = ? WHERE run_id = ? AND case_id = ?",
        (CaseStatus.SCREENED.value, RUN_ID, first.case.case_id),
    )
    connection.execute(
        """
        UPDATE audit_entries
        SET action = ?, object_kind = ?, object_id = ?, entry_hash = ?,
            entry_json = ?, document_sha256 = ?
        WHERE run_id = ? AND sequence = ?
        """,
        (
            forged.action.value,
            forged.object_ref.kind.value,
            forged.object_ref.artifact_id,
            forged.entry_hash,
            forged_document,
            _sha256(forged_document),
            RUN_ID,
            forged.sequence,
        ),
    )
    connection.execute(
        "UPDATE runs SET audit_head_hash = ? WHERE run_id = ?",
        (forged.entry_hash, RUN_ID),
    )
    try:
        failure = _failure(connection, binding=first.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH


def test_historical_case_selection_rejects_impossible_predecessor_status_metadata() -> None:
    first, second = _revision_two_authorities()
    connection, _selected = _revision_two_connection()
    _replace_future_case_metadata(
        connection,
        first,
        second,
        status=CaseStatus.APPEALED,
        action=AuditAction.CASE_STATE_CHANGED,
        object_ref=ArtifactRef(kind=ArtifactKind.APPEAL, artifact_id="a" * 64),
    )
    try:
        failure = _failure(connection, binding=first.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH


def test_historical_case_selection_rejects_pack_publication_without_pack_metadata() -> None:
    first, second = _revision_two_authorities()
    connection, _selected = _revision_two_connection()
    forged = AuditEntryDraft(
        run_id=RUN_ID,
        sequence=second.audit.sequence,
        actor=AuditActorRole.EVIDENCE.value,
        action=AuditAction.EVIDENCE_PACK_PUBLISHED,
        object_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=first.case.case_id),
        before_sha256=first.case_document_sha256,
        after_sha256=second.case_document_sha256,
        manifest_id=MANIFEST_ID,
        recorded_at=second.audit.recorded_at,
        prev_entry_hash=first.audit.entry_hash,
    ).seal()
    forged_document = canonical_json(forged.model_dump(mode="json"))
    connection.execute(
        "UPDATE case_versions SET status = ? WHERE run_id = ? AND case_id = ? AND revision = 2",
        (CaseStatus.EVIDENCE_READY.value, RUN_ID, first.case.case_id),
    )
    connection.execute(
        "UPDATE cases SET status = ? WHERE run_id = ? AND case_id = ?",
        (CaseStatus.EVIDENCE_READY.value, RUN_ID, first.case.case_id),
    )
    connection.execute(
        """
        UPDATE audit_entries
        SET actor = ?, action = ?, entry_hash = ?, entry_json = ?, document_sha256 = ?
        WHERE run_id = ? AND sequence = ?
        """,
        (
            forged.actor,
            forged.action.value,
            forged.entry_hash,
            forged_document,
            _sha256(forged_document),
            RUN_ID,
            forged.sequence,
        ),
    )
    connection.execute(
        "UPDATE runs SET audit_head_hash = ? WHERE run_id = ?",
        (forged.entry_hash, RUN_ID),
    )
    try:
        failure = _failure(connection, binding=first.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH


def test_historical_case_selection_uses_future_pack_metadata_without_reading_body() -> None:
    connection, first, _second = _future_pack_publication_connection()
    connection.execute(
        "UPDATE case_versions SET case_json = ? WHERE run_id = ? AND case_id = ? AND revision = 2",
        (b"untrusted-future-case", RUN_ID, first.case.case_id),
    )
    try:
        observed = read_m6_sqlite_case_authority(
            connection=connection,
            expected_run_id=RUN_ID,
            expected_manifest_id=MANIFEST_ID,
            expected_manifest_rule_version=MANIFEST_RULE_VERSION,
            candidate_case_binding=first.binding,
        )
    finally:
        _close(connection)
    assert observed.case == first.case
    assert observed.audit_entry == first.audit


@pytest.mark.parametrize(
    ("options", "expected"),
    (
        (
            {"version": 2},
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
        (
            {"created_audit_sequence": 0},
            M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
        ),
        (
            {"complete": 0},
            M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
        ),
        (
            {"document_sha256": "not-a-digest"},
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
    ),
)
def test_historical_case_selection_rejects_corrupt_future_pack_metadata(
    options: dict[str, object],
    expected: M6SQLiteCaseDocumentFailureCode,
) -> None:
    connection, first, _second = _future_pack_publication_connection(**options)  # type: ignore[arg-type]
    try:
        failure = _failure(connection, binding=first.binding)
    finally:
        _close(connection)
    assert failure.reason_code == expected


def test_historical_case_selection_rejects_pack_inventory_detached_from_root_latest() -> None:
    connection, first, _second = _future_pack_publication_connection()
    connection.execute(
        "UPDATE cases SET latest_pack_id = ? WHERE run_id = ? AND case_id = ?",
        ("e" * 64, RUN_ID, first.case.case_id),
    )
    try:
        failure = _failure(connection, binding=first.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH


def test_case_reader_accepts_real_m2_published_pack_metadata(tmp_path: Path) -> None:
    database, current_case, published_pack, binding = _real_m2_published_case(tmp_path)
    connection = sqlite3.connect(database, isolation_level=None)
    connection.execute("BEGIN")
    try:
        observed = read_m6_sqlite_case_authority(
            connection=connection,
            expected_run_id=m2_fixture.RUN_ID,
            expected_manifest_id=m2_fixture._manifest().manifest_id,
            expected_manifest_rule_version=m2_fixture._manifest().rule_version,
            candidate_case_binding=binding,
        )
    finally:
        _close(connection)
    assert observed.case == current_case
    assert observed.case.evidence_packs == (published_pack,)


def test_case_reader_rejects_selected_pack_metadata_detached_from_case_body(
    tmp_path: Path,
) -> None:
    database, current_case, _published_pack, binding = _real_m2_published_case(tmp_path)
    connection = sqlite3.connect(database, isolation_level=None)
    connection.execute("DROP TRIGGER evidence_packs_no_update")
    connection.execute(
        """
        UPDATE evidence_packs
        SET document_sha256 = ?
        WHERE run_id = ? AND case_id = ? AND version = 1
        """,
        ("e" * 64, m2_fixture.RUN_ID, current_case.case_id),
    )
    connection.execute("BEGIN")
    try:
        failure = _failure(
            connection,
            binding=binding,
            run_id=m2_fixture.RUN_ID,
            manifest_id=m2_fixture._manifest().manifest_id,
            manifest_rule_version=m2_fixture._manifest().rule_version,
        )
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH


def test_case_reader_bounds_the_current_revision_before_inventory() -> None:
    authority = _authority()
    connection = _connection(
        authority=authority,
        root_current_revision=case_document.MAX_M6_SQLITE_CASE_HISTORY_ROWS + 1,
    )
    try:
        failure = _failure(connection, binding=authority.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.ROW_LIMIT_EXCEEDED


@pytest.mark.parametrize("current_revision", (1, 3))
def test_case_reader_rejects_a_head_before_selected_or_beyond_max_revision(
    current_revision: int,
) -> None:
    connection, selected = _revision_two_connection()
    connection.execute(
        "UPDATE cases SET current_revision = ? WHERE run_id = ? AND case_id = ?",
        (current_revision, RUN_ID, selected.case.case_id),
    )
    try:
        failure = _failure(connection, binding=selected.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH


@pytest.mark.parametrize(
    ("target", "expected"),
    (
        ("case", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH),
        ("audit", M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH),
    ),
)
def test_case_reader_inventory_rejects_negative_rows_before_the_selected_prefix(
    target: Literal["case", "audit"],
    expected: M6SQLiteCaseDocumentFailureCode,
) -> None:
    authority = _authority()
    connection = _connection(authority=authority)
    if target == "case":
        connection.execute(
            "INSERT INTO case_versions VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                RUN_ID,
                authority.case.case_id,
                -1,
                authority.case.status.value,
                authority.case_document,
                authority.case_document_sha256,
                authority.audit.sequence,
            ),
        )
    else:
        connection.execute(
            "INSERT INTO audit_entries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                RUN_ID,
                -1,
                MANIFEST_ID,
                authority.audit.actor,
                authority.audit.action.value,
                authority.audit.object_ref.kind.value,
                authority.audit.object_ref.artifact_id,
                authority.audit.before_sha256,
                authority.audit.after_sha256,
                authority.audit.recorded_at,
                authority.audit.prev_entry_hash,
                authority.audit.entry_hash,
                authority.audit_document,
                authority.audit_document_sha256,
            ),
        )
    try:
        failure = _failure(connection, binding=authority.binding)
    finally:
        _close(connection)
    assert failure.reason_code == expected


def test_case_root_event_body_is_included_in_the_pre_materialization_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _authority()
    budget_without_root = len(authority.case_document.encode("utf-8")) + len(
        authority.audit_document.encode("utf-8")
    )
    monkeypatch.setattr(
        case_document,
        "MAX_M6_SQLITE_CASE_HISTORY_BYTES",
        budget_without_root,
    )
    connection = _connection(authority=authority)
    statements: list[str] = []
    connection.set_trace_callback(statements.append)
    try:
        failure = _failure(connection, binding=authority.binding)
    finally:
        _close(connection)
    assert failure.reason_code == M6SQLiteCaseDocumentFailureCode.DOCUMENT_TOO_LARGE
    assert not any(
        "event_json, event_sha256" in statement
        or "case_json, document_sha256" in statement
        or "entry_json, document_sha256" in statement
        for statement in statements
    )

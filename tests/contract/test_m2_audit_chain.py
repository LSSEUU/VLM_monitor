import pytest
from pydantic import ValidationError

from labcourt.contracts.audit import (
    AUDIT_GENESIS_HASH,
    AuditChainReport,
    AuditEntry,
    AuditEntryDraft,
    validate_audit_chain,
)
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditAction,
    AuditChainFailureReason,
)
from labcourt.contracts.storage import ArtifactRef

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
CASE_ID = "d5dc6bd1-9bc7-5cc6-a9b1-ecba4cadd617"
RUN_ID = "run-01"
RECORDED_AT = "2026-07-27T12:34:56.123456Z"


def _case_ref() -> ArtifactRef:
    return ArtifactRef(kind=ArtifactKind.CASE, artifact_id=CASE_ID)


def _audit_entry(
    *,
    sequence: int = 0,
    prev_entry_hash: str = AUDIT_GENESIS_HASH,
    run_id: str = RUN_ID,
    manifest_id: str = SHA_B,
    actor: str = "SYSTEM",
    action: AuditAction = AuditAction.CASE_CREATED,
    before_sha256: str | None = None,
    after_sha256: str | None = SHA_A,
) -> AuditEntry:
    return AuditEntryDraft(
        run_id=run_id,
        sequence=sequence,
        actor=actor,
        action=action,
        object_ref=_case_ref(),
        before_sha256=before_sha256,
        after_sha256=after_sha256,
        manifest_id=manifest_id,
        recorded_at=RECORDED_AT,
        prev_entry_hash=prev_entry_hash,
    ).seal()


def _second_entry(first: AuditEntry) -> AuditEntry:
    return _audit_entry(
        sequence=1,
        prev_entry_hash=first.entry_hash,
        action=AuditAction.CASE_STATE_CHANGED,
        before_sha256=SHA_A,
        after_sha256=SHA_C,
    )


def _verify(
    entries: tuple[AuditEntry, ...],
    *,
    expected_head_sequence: int,
    expected_head_hash: str,
    expected_run_id: str = RUN_ID,
    expected_manifest_id: str = SHA_B,
) -> AuditChainReport:
    return validate_audit_chain(
        entries,
        expected_run_id=expected_run_id,
        expected_manifest_id=expected_manifest_id,
        expected_head_sequence=expected_head_sequence,
        expected_head_hash=expected_head_hash,
    )


def test_audit_entry_matches_lcj_audit_1_golden_hash() -> None:
    entry = _audit_entry()
    assert entry.hash_body() == {
        "schema_version": "1.0.0",
        "run_id": RUN_ID,
        "sequence": 0,
        "actor": "SYSTEM",
        "action": "CASE_CREATED",
        "object_ref": {"kind": "CASE", "artifact_id": CASE_ID},
        "before_sha256": None,
        "after_sha256": SHA_A,
        "manifest_id": SHA_B,
        "recorded_at": RECORDED_AT,
    }
    assert len(entry.hash_body()) == 10
    assert entry.entry_hash == "c0da3d966ffda47662204935c54d10c4d3ad69948d18135951c62876447f0cc8"
    assert (
        AuditEntry.model_json_schema(mode="serialization")["properties"]["entry_hash"]["readOnly"]
        is True
    )
    assert AuditEntry.model_validate(entry.model_dump(mode="json")) == entry


def test_stored_audit_entry_requires_and_recomputes_explicit_hash() -> None:
    entry = _audit_entry()
    missing = entry.model_dump(mode="json")
    missing.pop("entry_hash")
    with pytest.raises(ValidationError, match="Field required"):
        AuditEntry.model_validate(missing)

    tampered = entry.model_dump(mode="json")
    tampered["action"] = AuditAction.CASE_CLOSED
    with pytest.raises(ValidationError, match="does not match"):
        AuditEntry.model_validate(tampered)

    forged = entry.model_dump(mode="json")
    forged["entry_hash"] = SHA_C
    with pytest.raises(ValidationError, match="does not match"):
        AuditEntry.model_validate(forged)


def test_audit_action_actor_and_transition_are_controlled() -> None:
    with pytest.raises(ValidationError, match="Input should be"):
        AuditEntryDraft(
            run_id=RUN_ID,
            sequence=0,
            actor="SYSTEM",
            action="ARBITRARY_ACTION",
            object_ref=_case_ref(),
            after_sha256=SHA_A,
            manifest_id=SHA_B,
            recorded_at=RECORDED_AT,
            prev_entry_hash=AUDIT_GENESIS_HASH,
        )
    with pytest.raises(ValidationError, match="controlled system role"):
        _audit_entry(actor="alice@example.com")

    anonymous = _audit_entry(actor=f"anon_{SHA_C}")
    assert anonymous.actor == f"anon_{SHA_C}"

    with pytest.raises(ValidationError, match="unchanged state"):
        _audit_entry(
            action=AuditAction.CASE_STATE_CHANGED,
            before_sha256=SHA_A,
            after_sha256=SHA_A,
        )
    with pytest.raises(ValidationError, match="CASE_CREATED requires"):
        _audit_entry(before_sha256=SHA_B)


def test_audit_entry_enforces_genesis_and_real_utc_time() -> None:
    with pytest.raises(ValidationError, match="sequence zero"):
        _audit_entry(prev_entry_hash=SHA_C)
    with pytest.raises(ValidationError, match="only audit sequence zero"):
        _audit_entry(sequence=1)

    with pytest.raises(ValidationError, match="real fixed-width UTC"):
        AuditEntryDraft(
            run_id=RUN_ID,
            sequence=0,
            actor="SYSTEM",
            action=AuditAction.CASE_CREATED,
            object_ref=_case_ref(),
            after_sha256=SHA_A,
            manifest_id=SHA_B,
            recorded_at="2026-02-30T12:34:56.123456Z",
            prev_entry_hash=AUDIT_GENESIS_HASH,
        )


def test_audit_chain_is_bound_to_authoritative_run_manifest_and_head() -> None:
    first = _audit_entry()
    second = _second_entry(first)
    report = _verify(
        (first, second),
        expected_head_sequence=1,
        expected_head_hash=second.entry_hash,
    )

    assert report.passed is True
    assert report.checked_entry_count == 2
    assert report.actual_head_sequence == 1
    assert report.actual_head_hash == second.entry_hash
    assert AuditChainReport.model_validate(report.model_dump(mode="json")) == report

    forged = report.model_dump(mode="json")
    forged["passed"] = False
    with pytest.raises(ValidationError, match="passed does not match"):
        AuditChainReport.model_validate(forged)


def test_audit_chain_rejects_a_valid_truncated_prefix() -> None:
    first = _audit_entry()
    second = _second_entry(first)

    report = _verify(
        (first,),
        expected_head_sequence=1,
        expected_head_hash=second.entry_hash,
    )
    assert report.passed is False
    assert report.failure_reason == AuditChainFailureReason.HEAD_SEQUENCE_MISMATCH
    assert report.failure_sequence == 1


def test_audit_chain_returns_the_typed_first_error() -> None:
    first = _audit_entry()
    other_run = _audit_entry(
        sequence=1,
        prev_entry_hash=first.entry_hash,
        run_id="run-02",
        action=AuditAction.CASE_STATE_CHANGED,
        before_sha256=SHA_A,
        after_sha256=SHA_C,
    )
    report = _verify(
        (first, other_run),
        expected_head_sequence=1,
        expected_head_hash=other_run.entry_hash,
    )
    assert report.failure_reason == AuditChainFailureReason.RUN_MISMATCH
    assert report.failure_sequence == 1

    other_manifest = _audit_entry(
        sequence=1,
        prev_entry_hash=first.entry_hash,
        manifest_id=SHA_C,
        action=AuditAction.CASE_STATE_CHANGED,
        before_sha256=SHA_A,
        after_sha256=SHA_C,
    )
    report = _verify(
        (first, other_manifest),
        expected_head_sequence=1,
        expected_head_hash=other_manifest.entry_hash,
    )
    assert report.failure_reason == AuditChainFailureReason.MANIFEST_MISMATCH

    wrong_link = _audit_entry(
        sequence=1,
        prev_entry_hash=SHA_C,
        action=AuditAction.CASE_STATE_CHANGED,
        before_sha256=SHA_A,
        after_sha256=SHA_C,
    )
    report = _verify(
        (first, wrong_link),
        expected_head_sequence=1,
        expected_head_hash=wrong_link.entry_hash,
    )
    assert report.failure_reason == AuditChainFailureReason.PREVIOUS_HASH_MISMATCH


def test_audit_chain_detects_entry_and_head_hash_tampering() -> None:
    first = _audit_entry()
    raw = dict(first.__dict__)
    raw["entry_hash"] = SHA_C
    tampered = AuditEntry.model_construct(**raw)
    report = _verify(
        (tampered,),
        expected_head_sequence=0,
        expected_head_hash=SHA_C,
    )
    assert report.failure_reason == AuditChainFailureReason.ENTRY_HASH_MISMATCH

    report = _verify(
        (first,),
        expected_head_sequence=0,
        expected_head_hash=SHA_C,
    )
    assert report.failure_reason == AuditChainFailureReason.HEAD_HASH_MISMATCH


def test_empty_audit_chain_requires_the_genesis_authoritative_head() -> None:
    report = _verify(
        (),
        expected_head_sequence=-1,
        expected_head_hash=AUDIT_GENESIS_HASH,
    )
    assert report.passed is True
    assert report.actual_head_sequence == -1

    with pytest.raises(ValueError, match="empty audit chain"):
        _verify((), expected_head_sequence=-1, expected_head_hash=SHA_C)

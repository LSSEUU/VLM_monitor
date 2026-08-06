import hashlib

import pytest
from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.m5_precedent_causal_ledger import (
    M5PrecedentCausalEvent,
    M5PrecedentCausalEventKind,
    M5PrecedentCausalEventSourceKind,
)

ZERO_SHA256 = "0" * 64


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _authority_event(**updates: object) -> M5PrecedentCausalEvent:
    authority_id = _sha("authority-1")
    payload: dict[str, object] = {
        "run_id": "run-m5-causal-ledger",
        "sequence": 1,
        "event_kind": M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED,
        "source_id": authority_id,
        "precedent_id": "precedent-m5-causal-ledger",
        "precedent_authority_id": authority_id,
        "precedent_revision": 1,
        "citation_kind": None,
        "manifest_id": _sha("manifest"),
        "source_document_sha256": _sha("authority-document"),
        "previous_event_sha256": ZERO_SHA256,
    }
    payload.update(updates)
    return M5PrecedentCausalEvent.model_validate(payload)


def test_authority_event_has_stable_source_identity_and_explicit_chain_hash() -> None:
    first = _authority_event()
    second = _authority_event(
        sequence=2,
        previous_event_sha256=first.event_sha256,
    )

    assert first.schema_version == "m5-precedent-causal-event-v1"
    assert first.source_identity_sha256 == second.source_identity_sha256
    assert first.event_id == second.event_id
    assert first.event_sha256 != second.event_sha256
    body = [
        "m5-precedent-causal-event-chain",
        1,
        first.event_id,
        first.run_id,
        first.sequence,
        first.event_kind,
        first.source_id,
        first.precedent_id,
        first.precedent_authority_id,
        first.precedent_revision,
        first.citation_kind,
        first.manifest_id,
        first.source_document_sha256,
    ]
    expected = hashlib.sha256(
        first.previous_event_sha256.encode("ascii") + canonical_bytes(body)
    ).hexdigest()
    assert first.event_sha256 == expected


def test_serialized_computed_claims_are_all_revalidated() -> None:
    event = _authority_event()
    payload = event.model_dump(mode="json")
    assert M5PrecedentCausalEvent.model_validate(payload) == event

    for claim in ("source_identity_sha256", "event_id", "event_sha256"):
        attacked = dict(payload)
        attacked[claim] = _sha(f"attacked-{claim}")
        with pytest.raises(ValidationError, match=claim):
            M5PrecedentCausalEvent.model_validate(attacked)


def test_sequence_one_reserves_the_zero_predecessor_and_later_events_forbid_it() -> None:
    with pytest.raises(ValidationError, match="first causal event"):
        _authority_event(previous_event_sha256=_sha("not-zero"))
    with pytest.raises(ValidationError, match="later causal event"):
        _authority_event(sequence=2, previous_event_sha256=ZERO_SHA256)


@pytest.mark.parametrize(
    "citation_kind",
    [
        M5PrecedentCausalEventSourceKind.DIRECT,
        M5PrecedentCausalEventSourceKind.APPLIED,
    ],
)
def test_citation_event_accepts_only_the_strict_direct_applied_discriminator(
    citation_kind: M5PrecedentCausalEventSourceKind,
) -> None:
    event = _authority_event(
        event_kind=M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED,
        source_id=_sha(f"citation-{citation_kind.value}"),
        citation_kind=citation_kind,
    )

    assert event.citation_kind == citation_kind
    assert tuple(item.value for item in M5PrecedentCausalEventKind) == (
        "PRECEDENT_AUTHORITY_APPENDED",
        "PRECEDENT_CITATION_APPENDED",
        "PRECEDENT_CONFLICT_BATCH_COMMITTED",
        "PRECEDENT_REVOCATION_COMMITTED",
        "APPEAL_RESOLUTION_COMMITTED",
    )
    assert tuple(item.value for item in M5PrecedentCausalEventSourceKind) == (
        "DIRECT",
        "APPLIED",
    )


def test_event_discriminator_rejects_authority_citation_shape_confusion() -> None:
    with pytest.raises(ValidationError, match="authority event"):
        _authority_event(citation_kind=M5PrecedentCausalEventSourceKind.DIRECT)
    with pytest.raises(ValidationError, match="authority event"):
        _authority_event(source_id=_sha("not-the-authority"))
    with pytest.raises(ValidationError, match="citation event"):
        _authority_event(
            event_kind=M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED,
            source_id=_sha("citation-without-kind"),
        )


def test_conflict_batch_marker_uses_receipt_source_without_precedent_shape() -> None:
    marker = _authority_event(
        event_kind=M5PrecedentCausalEventKind.PRECEDENT_CONFLICT_BATCH_COMMITTED,
        source_id=_sha("conflict-batch-receipt"),
        precedent_id=None,
        precedent_authority_id=None,
        precedent_revision=None,
    )

    assert marker.precedent_id is None
    assert marker.precedent_authority_id is None
    assert marker.precedent_revision is None
    assert marker.citation_kind is None
    serialized = marker.model_dump(mode="json")
    for field in (
        "precedent_id",
        "precedent_authority_id",
        "precedent_revision",
        "citation_kind",
    ):
        attacked = dict(serialized)
        attacked.pop(field)
        with pytest.raises(ValidationError, match=field):
            M5PrecedentCausalEvent.model_validate(attacked)


def test_revocation_marker_binds_resulting_precedent_authority() -> None:
    marker = _authority_event(
        event_kind=M5PrecedentCausalEventKind.PRECEDENT_REVOCATION_COMMITTED,
        source_id=_sha("revocation-receipt"),
    )

    assert marker.source_id != marker.precedent_authority_id
    assert marker.precedent_id == "precedent-m5-causal-ledger"
    assert marker.precedent_revision == 1
    assert marker.citation_kind is None

    for field in ("precedent_id", "precedent_authority_id", "precedent_revision"):
        attacked = marker.model_dump(
            mode="json",
            exclude={"source_identity_sha256", "event_id", "event_sha256"},
        )
        attacked[field] = None
        with pytest.raises(ValidationError, match="revocation marker"):
            M5PrecedentCausalEvent.model_validate(attacked)
    with pytest.raises(ValidationError, match="revocation marker"):
        M5PrecedentCausalEvent.model_validate(
            {
                **marker.model_dump(
                    mode="json",
                    exclude={"source_identity_sha256", "event_id", "event_sha256"},
                ),
                "citation_kind": M5PrecedentCausalEventSourceKind.DIRECT,
            }
        )


def test_appeal_resolution_marker_uses_final_receipt_without_precedent_shape() -> None:
    marker = _authority_event(
        event_kind=M5PrecedentCausalEventKind.APPEAL_RESOLUTION_COMMITTED,
        source_id=_sha("appeal-resolution-commit-receipt"),
        precedent_id=None,
        precedent_authority_id=None,
        precedent_revision=None,
    )

    assert marker.precedent_id is None
    assert marker.precedent_authority_id is None
    assert marker.precedent_revision is None
    assert marker.citation_kind is None

    for field in (
        "precedent_id",
        "precedent_authority_id",
        "precedent_revision",
        "citation_kind",
    ):
        attacked = marker.model_dump(mode="json")
        attacked.pop(field)
        with pytest.raises(ValidationError, match=field):
            M5PrecedentCausalEvent.model_validate(attacked)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("precedent_id", "precedent-m5-causal-ledger"),
        ("precedent_authority_id", _sha("authority-1")),
        ("precedent_revision", 1),
        ("citation_kind", M5PrecedentCausalEventSourceKind.DIRECT),
    ],
)
def test_aggregate_marker_rejects_each_foreign_shape_field(
    field: str,
    value: object,
) -> None:
    updates: dict[str, object] = {
        "event_kind": M5PrecedentCausalEventKind.PRECEDENT_CONFLICT_BATCH_COMMITTED,
        "source_id": _sha(f"conflict-batch-receipt-{field}"),
        "precedent_id": None,
        "precedent_authority_id": None,
        "precedent_revision": None,
    }
    updates[field] = value
    with pytest.raises(ValidationError, match="aggregate commit marker"):
        _authority_event(**updates)


@pytest.mark.parametrize(
    "field",
    ["precedent_id", "precedent_authority_id", "precedent_revision"],
)
@pytest.mark.parametrize(
    "event_kind",
    [
        M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED,
        M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED,
    ],
)
def test_authority_and_citation_events_reject_each_missing_precedent_field(
    event_kind: M5PrecedentCausalEventKind,
    field: str,
) -> None:
    updates: dict[str, object] = {
        "event_kind": event_kind,
        "source_id": _sha(f"source-{event_kind.value}-{field}"),
        field: None,
    }
    if event_kind == M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED:
        updates["source_id"] = _sha("authority-1")
    else:
        updates["citation_kind"] = M5PrecedentCausalEventSourceKind.DIRECT
    with pytest.raises(ValidationError, match=r"authority event|citation event"):
        _authority_event(**updates)

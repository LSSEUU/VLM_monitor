from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.m6_source_authority_store import (
    M6SourceAuthorityDocumentEntry,
    M6SourceAuthorityDocumentKind,
    M6SourceAuthoritySeal,
    m6_source_authority_document_relative_path,
    m6_source_authority_seal_relative_path,
)
from labcourt.schema_export import expected_schema_files


def _sha(character: str) -> str:
    return character * 64


_BINDINGS = {
    M6SourceAuthorityDocumentKind.REPLAY_INPUT_CLOSURE: (
        _sha("1"),
        _sha("2"),
        _sha("3"),
    ),
    M6SourceAuthorityDocumentKind.REPLAY_INPUT_AUTHORITY: (
        _sha("4"),
        _sha("5"),
        _sha("6"),
    ),
    M6SourceAuthorityDocumentKind.SOURCE_VALIDATION_REPORT: (
        _sha("7"),
        _sha("8"),
        _sha("8"),
    ),
    M6SourceAuthorityDocumentKind.SOURCE_CASE: (
        "case-source",
        _sha("9"),
        _sha("9"),
    ),
    M6SourceAuthorityDocumentKind.SOURCE_MANIFEST: (
        _sha("a"),
        _sha("b"),
        _sha("b"),
    ),
}


def _entry(kind: M6SourceAuthorityDocumentKind) -> M6SourceAuthorityDocumentEntry:
    artifact_id, declared, content = _BINDINGS[kind]
    return M6SourceAuthorityDocumentEntry(
        kind=kind,
        artifact_id=artifact_id,
        declared_document_sha256=declared,
        content_sha256=content,
        size_bytes=1024 + list(M6SourceAuthorityDocumentKind).index(kind),
    )


def _seal() -> M6SourceAuthoritySeal:
    return M6SourceAuthoritySeal(
        sample_id="sample-source",
        source_run_id="run-source",
        source_case_id="case-source",
        source_case_revision=7,
        source_case_document_sha256=_sha("9"),
        source_manifest_id=_sha("a"),
        source_manifest_document_sha256=_sha("b"),
        source_config_sha256=_sha("c"),
        source_m4_authority_root_sha256=_sha("d"),
        source_m5_authority_root_sha256=_sha("e"),
        audit_head_sequence=42,
        audit_head_hash=_sha("f"),
        replay_input_authority_id=_sha("4"),
        replay_input_authority_document_sha256=_sha("5"),
        replay_input_closure_authority_id=_sha("1"),
        replay_input_closure_document_sha256=_sha("2"),
        source_validation_report_id=_sha("7"),
        source_validation_report_document_sha256=_sha("8"),
        entries=tuple(_entry(kind) for kind in M6SourceAuthorityDocumentKind),
    )


def test_seal_binds_exact_five_documents_and_round_trips_computed_claims() -> None:
    seal = _seal()

    assert M6SourceAuthoritySeal.model_validate(seal.model_dump(mode="json")) == seal
    assert len(seal.entries) == 5
    assert len(seal.seal_id) == 64
    assert seal.seal_relative_path == f"seals/{_sha('1')}/seal.json"
    authority = next(
        item
        for item in seal.entries
        if item.kind == M6SourceAuthorityDocumentKind.REPLAY_INPUT_AUTHORITY
    )
    assert authority.declared_document_sha256 != authority.content_sha256
    assert authority.relative_path.endswith(f"/{_sha('6')}.json")


@pytest.mark.parametrize(
    "field",
    ("document_inventory_root_sha256", "seal_id", "seal_relative_path"),
)
def test_seal_rejects_forged_derived_claims(field: str) -> None:
    payload = _seal().model_dump(mode="json")
    payload[field] = "seals/forged/seal.json" if field.endswith("path") else _sha("0")

    with pytest.raises(ValidationError):
        M6SourceAuthoritySeal.model_validate(payload)


def test_seal_rejects_missing_duplicate_reordered_or_misbound_documents() -> None:
    seal = _seal()
    payload = seal.model_dump(mode="json", exclude_computed_fields=True)
    payload["entries"] = payload["entries"][:-1]
    with pytest.raises(ValidationError):
        M6SourceAuthoritySeal.model_validate(payload)

    payload = seal.model_dump(mode="json", exclude_computed_fields=True)
    payload["entries"][-1] = payload["entries"][-2]
    with pytest.raises(ValidationError):
        M6SourceAuthoritySeal.model_validate(payload)

    payload = seal.model_dump(mode="json", exclude_computed_fields=True)
    payload["entries"] = list(reversed(payload["entries"]))
    with pytest.raises(ValidationError):
        M6SourceAuthoritySeal.model_validate(payload)

    payload = seal.model_dump(mode="json", exclude_computed_fields=True)
    payload["entries"][0]["declared_document_sha256"] = _sha("0")
    with pytest.raises(ValidationError):
        M6SourceAuthoritySeal.model_validate(payload)


def test_document_entry_paths_are_derived_and_cannot_escape() -> None:
    entry = _entry(M6SourceAuthorityDocumentKind.SOURCE_CASE)
    payload = entry.model_dump(mode="json")
    payload["relative_path"] = "../../outside.json"
    with pytest.raises(ValidationError):
        M6SourceAuthorityDocumentEntry.model_validate(payload)

    assert (
        m6_source_authority_document_relative_path(
            M6SourceAuthorityDocumentKind.SOURCE_CASE,
            _sha("9"),
        )
        == f"documents/source-cases/{_sha('9')}.json"
    )
    assert m6_source_authority_seal_relative_path(_sha("1")) == (f"seals/{_sha('1')}/seal.json")


def test_public_m6_source_authority_seal_schema_validates_document() -> None:
    schema = json.loads(expected_schema_files()["m6-source-authority-seal.schema.json"])
    Draft202012Validator(schema).validate(_seal().model_dump(mode="json"))

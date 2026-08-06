"""Raw read-only documents needed to validate one M6 source authority."""

from __future__ import annotations

from dataclasses import dataclass

MAX_M6_SOURCE_DOCUMENT_BYTES = 64 * 1024 * 1024


def _require_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _require_document(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError(f"{label} must be a non-empty canonical document")
    if len(value.encode("utf-8")) > MAX_M6_SOURCE_DOCUMENT_BYTES:
        raise ValueError(f"{label} exceeds the source-authority byte budget")
    return value


@dataclass(frozen=True, slots=True)
class M6SourceAuthoritySnapshot:
    """Untrusted canonical text and snapshot facts from one immutable read."""

    source_identity_sha256: str
    input_authority_canonical_document: str
    source_validation_report_canonical_document: str
    source_case_canonical_document: str
    source_case_document_sha256: str
    source_manifest_canonical_document: str
    source_manifest_document_sha256: str
    source_m4_authority_root_sha256: str
    source_m5_authority_root_sha256: str
    audit_head_sequence: int
    audit_head_hash: str
    m4_authority_failure_count: int = 0
    m5_authority_failure_count: int = 0

    def __post_init__(self) -> None:
        for digest, label in (
            (self.source_identity_sha256, "source identity"),
            (self.source_case_document_sha256, "source Case document"),
            (self.source_manifest_document_sha256, "source manifest document"),
            (self.source_m4_authority_root_sha256, "source M4 authority root"),
            (self.source_m5_authority_root_sha256, "source M5 authority root"),
            (self.audit_head_hash, "source audit head"),
        ):
            _require_sha256(digest, label)
        for document, label in (
            (self.input_authority_canonical_document, "M6 input authority"),
            (self.source_validation_report_canonical_document, "source validation report"),
            (self.source_case_canonical_document, "source Case"),
            (self.source_manifest_canonical_document, "source manifest"),
        ):
            _require_document(document, label)
        if (
            not isinstance(self.audit_head_sequence, int)
            or isinstance(self.audit_head_sequence, bool)
            or self.audit_head_sequence < -1
        ):
            raise ValueError("audit_head_sequence must be an integer at least -1")
        for count, label in (
            (self.m4_authority_failure_count, "M4 authority failure count"),
            (self.m5_authority_failure_count, "M5 authority failure count"),
        ):
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise ValueError(f"{label} must be a non-negative integer")


__all__ = [
    "MAX_M6_SOURCE_DOCUMENT_BYTES",
    "M6SourceAuthoritySnapshot",
]

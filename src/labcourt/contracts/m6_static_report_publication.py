"""Atomic publication seal for one privacy-safe M6 static HTML report."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M6_PRIVACY_SAFE_STATIC_REPORT_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_M6_PRIVACY_SAFE_STATIC_REPORT_HTML_BYTES = 256 * 1024 * 1024


def _pop_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


class M6PrivacySafeStaticReportPublicationSealAuthorityV1(FrozenContractModel):
    schema_version: Literal["m6-privacy-safe-static-report-publication-seal-authority-v1"] = (
        "m6-privacy-safe-static-report-publication-seal-authority-v1"
    )
    candidate_run_id: ReferenceToken
    report_id: Sha256Hex
    regression_publication_seal_id: Sha256Hex
    static_report_manifest_id: Sha256Hex
    static_report_manifest_content_sha256: Sha256Hex
    static_report_manifest_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_PRIVACY_SAFE_STATIC_REPORT_MANIFEST_BYTES,
        strict=True,
    )
    html_content_sha256: Sha256Hex
    html_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_PRIVACY_SAFE_STATIC_REPORT_HTML_BYTES,
        strict=True,
    )
    evidence_inventory_root_sha256: Sha256Hex

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 static report candidate run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "html_relative_path",
                "manifest_relative_path",
                "seal_relative_path",
                "seal_id",
            ),
        )
        seal = handler(payload)
        serialized = seal.model_dump(mode="json")
        for name, (present, claimed) in claims.items():
            if present and canonical_json(claimed) != canonical_json(serialized[name]):
                raise ValueError("serialized claim conflicts with derived M6 static publication")
        return seal

    @computed_field  # type: ignore[prop-decorator]
    @property
    def html_relative_path(self) -> Literal["index.html"]:
        return "index.html"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def manifest_relative_path(self) -> str:
        return f"m6-static-report/manifests/{self.static_report_manifest_content_sha256}.json"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def seal_relative_path(self) -> Literal["m6-static-report/seal.json"]:
        return "m6-static-report/seal.json"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def seal_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-privacy-safe-static-report-publication-seal",
                1,
                self.candidate_run_id,
                self.report_id,
                self.regression_publication_seal_id,
                self.static_report_manifest_id,
                self.static_report_manifest_content_sha256,
                self.static_report_manifest_size_bytes,
                self.html_content_sha256,
                self.html_size_bytes,
                self.evidence_inventory_root_sha256,
                self.html_relative_path,
                self.manifest_relative_path,
                self.seal_relative_path,
            ]
        )


__all__ = [
    "MAX_M6_PRIVACY_SAFE_STATIC_REPORT_HTML_BYTES",
    "MAX_M6_PRIVACY_SAFE_STATIC_REPORT_MANIFEST_BYTES",
    "M6PrivacySafeStaticReportPublicationSealAuthorityV1",
]

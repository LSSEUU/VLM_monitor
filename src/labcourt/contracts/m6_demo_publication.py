"""Atomic publication seal for the complete offline M6 demo site."""

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

MAX_M6_OFFLINE_DEMO_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_M6_OFFLINE_DEMO_LANDING_BYTES = 16 * 1024 * 1024


def _pop_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


class M6OfflineDemoPublicationSealAuthorityV1(FrozenContractModel):
    schema_version: Literal["m6-offline-demo-publication-seal-authority-v1"] = (
        "m6-offline-demo-publication-seal-authority-v1"
    )
    candidate_run_id: ReferenceToken
    demo_manifest_id: Sha256Hex
    demo_manifest_content_sha256: Sha256Hex
    demo_manifest_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_OFFLINE_DEMO_MANIFEST_BYTES,
        strict=True,
    )
    landing_content_sha256: Sha256Hex
    landing_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_OFFLINE_DEMO_LANDING_BYTES,
        strict=True,
    )
    scenario_inventory_root_sha256: Sha256Hex

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 offline demo publication candidate run_id")

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
                "landing_relative_path",
                "manifest_relative_path",
                "seal_relative_path",
                "seal_id",
            ),
        )
        seal = handler(payload)
        serialized = seal.model_dump(mode="json")
        for name, (present, claimed) in claims.items():
            if present and canonical_json(claimed) != canonical_json(serialized[name]):
                raise ValueError("serialized claim conflicts with derived M6 demo publication")
        return seal

    @computed_field  # type: ignore[prop-decorator]
    @property
    def landing_relative_path(self) -> Literal["demo/index.html"]:
        return "demo/index.html"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def manifest_relative_path(self) -> str:
        return f"demo/manifests/{self.demo_manifest_content_sha256}.json"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def seal_relative_path(self) -> Literal["demo/seal.json"]:
        return "demo/seal.json"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def seal_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-offline-demo-publication-seal",
                1,
                self.candidate_run_id,
                self.demo_manifest_id,
                self.demo_manifest_content_sha256,
                self.demo_manifest_size_bytes,
                self.landing_content_sha256,
                self.landing_size_bytes,
                self.scenario_inventory_root_sha256,
                self.landing_relative_path,
                self.manifest_relative_path,
                self.seal_relative_path,
            ]
        )


__all__ = [
    "MAX_M6_OFFLINE_DEMO_LANDING_BYTES",
    "MAX_M6_OFFLINE_DEMO_MANIFEST_BYTES",
    "M6OfflineDemoPublicationSealAuthorityV1",
]

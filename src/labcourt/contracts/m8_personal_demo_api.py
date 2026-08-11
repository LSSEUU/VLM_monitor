"""Hashed runtime profile for the loopback-only personal Demo API."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, computed_field, model_validator
from pydantic.functional_validators import ModelWrapValidatorHandler

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_api import M8ApiCredentialCatalogAuthorityV1


class M8PersonalDemoApiProfileV1(FrozenContractModel):
    schema_version: Literal["m8-personal-demo-api-profile-v1"] = "m8-personal-demo-api-profile-v1"
    display_badge: Literal["PERSONAL DEMO · LOOPBACK API"] = "PERSONAL DEMO · LOOPBACK API"
    bind_host: Literal["127.0.0.1"] = "127.0.0.1"
    bind_port: int = Field(ge=1, le=65_535, strict=True)
    bootstrap_receipt_id: Sha256Hex
    credential_catalog: M8ApiCredentialCatalogAuthorityV1
    server_manifest_id: Sha256Hex
    personal_demo_only: Literal[True] = True
    plaintext_demo_tokens_in_authority: Literal[False] = False
    production_ready: Literal[False] = False
    automatic_case_transition_permitted: Literal[False] = False

    @model_validator(mode="wrap")
    @classmethod
    def validate_computed_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        claims: dict[str, object] = {}
        if isinstance(value, dict):
            payload = dict(value)
            for name in ("base_url", "api_profile_id"):
                if name in payload:
                    claims[name] = payload.pop(name)
            value = payload
        profile = handler(value)
        serialized = profile.model_dump(mode="json")
        for name, claimed in claims.items():
            if canonical_json(claimed) != canonical_json(serialized[name]):
                raise ValueError(f"serialized {name} conflicts with personal Demo API profile")
        return profile

    @model_validator(mode="after")
    def validate_fixed_role_credentials(self) -> Self:
        observed = tuple(
            (item.credential_id, item.actor_id) for item in self.credential_catalog.credentials
        )
        expected = (
            ("credential-leader-demo", "leader-demo"),
            ("credential-operations-demo", "operations-demo"),
            ("credential-safety-demo", "safety-officer-demo"),
            ("credential-student-demo", "student-demo"),
        )
        if observed != expected:
            raise ValueError("M8 personal Demo API requires the fixed four-role credentials")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def base_url(self) -> str:
        return f"http://{self.bind_host}:{self.bind_port}"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def api_profile_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-personal-demo-api-profile",
                1,
                self.bind_host,
                self.bind_port,
                self.bootstrap_receipt_id,
                self.credential_catalog.credential_catalog_id,
                self.server_manifest_id,
                self.personal_demo_only,
                self.plaintext_demo_tokens_in_authority,
                self.production_ready,
                self.automatic_case_transition_permitted,
            ]
        )


__all__ = ["M8PersonalDemoApiProfileV1"]

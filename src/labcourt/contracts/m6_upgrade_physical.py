"""Shared physical artifact envelopes for M6 upgrade execution."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, ModelWrapValidatorHandler, computed_field, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import parse_frame_id, require_reference_token

MAX_M6_UPGRADE_PHYSICAL_IDENTIFIER_LENGTH = 192
MAX_M6_UPGRADE_PHYSICAL_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES = 256 * 1024 * 1024


class M6UpgradePhysicalArtifactKind(StrEnum):
    FRAME = "FRAME"
    DETECTION = "DETECTION"
    MODEL_REQUEST = "MODEL_REQUEST"
    MODEL_RESPONSE = "MODEL_RESPONSE"
    MODEL_CACHE = "MODEL_CACHE"
    MODEL_PARSE_RECEIPT = "MODEL_PARSE_RECEIPT"
    MODEL_PARSED_OUTPUT = "MODEL_PARSED_OUTPUT"
    MODEL_CALL_FAILURE = "MODEL_CALL_FAILURE"
    MODEL_USAGE_RECEIPT = "MODEL_USAGE_RECEIPT"
    EMBEDDING = "EMBEDDING"
    PRECEDENT_EXPOSURE = "PRECEDENT_EXPOSURE"
    TOOL_EXECUTION_MANIFEST = "TOOL_EXECUTION_MANIFEST"
    TOOL_RESULT = "TOOL_RESULT"
    EVIDENCE_PACK = "EVIDENCE_PACK"


class M6UpgradePhysicalArtifactSource(StrEnum):
    M2_PERCEPTION = "M2_PERCEPTION"
    M2_EVIDENCE = "M2_EVIDENCE"
    M3_SCREENING_MODEL = "M3_SCREENING_MODEL"
    M4_HEARING_MODEL = "M4_HEARING_MODEL"
    M4_ACQUISITION = "M4_ACQUISITION"
    M5_PRECEDENT = "M5_PRECEDENT"


class M6UpgradePhysicalByteAuthority(StrEnum):
    """Exact byte authority a typed resolver must observe for one physical route."""

    CANONICAL_JSON = "CANONICAL_JSON"
    CANONICAL_PLUS_RAW = "CANONICAL_PLUS_RAW"
    LCPIX1 = "LCPIX1"
    DERIVED_CANONICAL_JSON = "DERIVED_CANONICAL_JSON"


class M6UpgradeArtifactUsage(StrEnum):
    """Relationship to this candidate sample execution, not global ownership."""

    CONSUMED = "CONSUMED"
    PRODUCED = "PRODUCED"


_ARTIFACT_KIND_RANK = {kind: index for index, kind in enumerate(M6UpgradePhysicalArtifactKind)}
_ARTIFACT_SOURCE_RANK = {
    source: index for index, source in enumerate(M6UpgradePhysicalArtifactSource)
}
_MODEL_ARTIFACT_KINDS = frozenset(
    {
        M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
        M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
        M6UpgradePhysicalArtifactKind.MODEL_CACHE,
        M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
        M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
        M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
        M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
    }
)
_CASE_SCOPED_ARTIFACT_KINDS = frozenset(M6UpgradePhysicalArtifactKind) - frozenset(
    {
        M6UpgradePhysicalArtifactKind.FRAME,
        M6UpgradePhysicalArtifactKind.DETECTION,
    }
)
_ARTIFACT_KINDS_BY_SOURCE = {
    M6UpgradePhysicalArtifactSource.M2_PERCEPTION: frozenset(
        {
            M6UpgradePhysicalArtifactKind.FRAME,
            M6UpgradePhysicalArtifactKind.DETECTION,
        }
    ),
    M6UpgradePhysicalArtifactSource.M2_EVIDENCE: frozenset(
        {M6UpgradePhysicalArtifactKind.EVIDENCE_PACK}
    ),
    M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL: _MODEL_ARTIFACT_KINDS,
    M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL: _MODEL_ARTIFACT_KINDS,
    M6UpgradePhysicalArtifactSource.M4_ACQUISITION: frozenset(
        {
            M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
            M6UpgradePhysicalArtifactKind.TOOL_RESULT,
        }
    ),
    M6UpgradePhysicalArtifactSource.M5_PRECEDENT: frozenset(
        {
            M6UpgradePhysicalArtifactKind.EMBEDDING,
            M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
        }
    ),
}
_BYTE_AUTHORITY_BY_ROUTE = {
    (
        M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
        M6UpgradePhysicalArtifactKind.FRAME,
    ): M6UpgradePhysicalByteAuthority.LCPIX1,
    (
        M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
        M6UpgradePhysicalArtifactKind.DETECTION,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
        M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_PLUS_RAW,
    (
        M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_CACHE,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_PLUS_RAW,
    (
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_CACHE,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
        M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
        M6UpgradePhysicalArtifactKind.TOOL_RESULT,
    ): M6UpgradePhysicalByteAuthority.DERIVED_CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
        M6UpgradePhysicalArtifactKind.EMBEDDING,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
    (
        M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
        M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
    ): M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
}
_LEGAL_ARTIFACT_ROUTES = frozenset(
    (source, kind) for source, kinds in _ARTIFACT_KINDS_BY_SOURCE.items() for kind in kinds
)
if (
    set(_ARTIFACT_KINDS_BY_SOURCE) != set(M6UpgradePhysicalArtifactSource)
    or frozenset().union(*_ARTIFACT_KINDS_BY_SOURCE.values())
    != frozenset(M6UpgradePhysicalArtifactKind)
    or frozenset(_BYTE_AUTHORITY_BY_ROUTE) != _LEGAL_ARTIFACT_ROUTES
):
    raise RuntimeError("M6 physical byte-authority routes must exhaust the legal matrix")

_CANONICAL_CONTENT_AUTHORITIES = frozenset(
    {
        M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
        M6UpgradePhysicalByteAuthority.DERIVED_CANONICAL_JSON,
    }
)
_CONSUMED_ONLY_ARTIFACT_KINDS = frozenset({M6UpgradePhysicalArtifactKind.FRAME})
_PRODUCED_ONLY_ARTIFACT_KINDS = frozenset(
    {
        M6UpgradePhysicalArtifactKind.DETECTION,
        M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
        M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
        M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
        M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
        M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
        M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
        M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
        M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
        M6UpgradePhysicalArtifactKind.TOOL_RESULT,
        M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
    }
)


def _pop_claim(value: object, name: str) -> tuple[object, bool, object]:
    if not isinstance(value, dict):
        return value, False, None
    payload = dict(value)
    present = name in payload
    claim = payload.pop(name, None)
    return payload, present, claim


def _validate_physical_identifier(value: str, *, frame: bool, label: str) -> str:
    if frame:
        parse_frame_id(value)
        return value
    return require_reference_token(value, label)


def m6_upgrade_physical_byte_authority_for(
    source: M6UpgradePhysicalArtifactSource,
    kind: M6UpgradePhysicalArtifactKind,
) -> M6UpgradePhysicalByteAuthority:
    """Return the only byte-authority policy allowed for one physical route."""

    if not isinstance(source, M6UpgradePhysicalArtifactSource):
        raise TypeError("source must be an M6 physical artifact source")
    if not isinstance(kind, M6UpgradePhysicalArtifactKind):
        raise TypeError("kind must be an M6 physical artifact kind")
    authority = _BYTE_AUTHORITY_BY_ROUTE.get((source, kind))
    if authority is None:
        raise ValueError("M6 physical artifact kind has no resolver for its source")
    return authority


def m6_upgrade_physical_artifact_requires_case(
    kind: M6UpgradePhysicalArtifactKind,
) -> bool:
    """Return whether the artifact can only exist inside a persisted Case workflow."""

    if not isinstance(kind, M6UpgradePhysicalArtifactKind):
        raise TypeError("kind must be an M6 physical artifact kind")
    return kind in _CASE_SCOPED_ARTIFACT_KINDS


class M6UpgradePhysicalArtifactRef(FrozenContractModel):
    """One resolver-addressable artifact with exact canonical/raw byte identity."""

    schema_version: Literal["m6-upgrade-physical-artifact-ref-v1"] = (
        "m6-upgrade-physical-artifact-ref-v1"
    )
    source: M6UpgradePhysicalArtifactSource
    kind: M6UpgradePhysicalArtifactKind
    artifact_id: str = Field(min_length=1, max_length=MAX_M6_UPGRADE_PHYSICAL_IDENTIFIER_LENGTH)
    container_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_M6_UPGRADE_PHYSICAL_IDENTIFIER_LENGTH,
    )
    document_sha256: Sha256Hex
    content_sha256: Sha256Hex
    size_bytes: int = Field(
        gt=0,
        le=MAX_M6_UPGRADE_PHYSICAL_ARTIFACT_BYTES,
        strict=True,
    )

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_ref_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, present, claim = _pop_claim(value, "artifact_ref_id")
        artifact = handler(payload)
        if present and canonical_json(claim) != canonical_json(artifact.artifact_ref_id):
            raise ValueError(
                "serialized artifact_ref_id conflicts with derived M6 physical content"
            )
        return artifact

    @model_validator(mode="after")
    def validate_resolver_identity(self) -> Self:
        byte_authority = m6_upgrade_physical_byte_authority_for(self.source, self.kind)
        _validate_physical_identifier(
            self.artifact_id,
            frame=self.kind == M6UpgradePhysicalArtifactKind.FRAME,
            label="M6 physical artifact_id",
        )
        if self.kind == M6UpgradePhysicalArtifactKind.DETECTION:
            if self.container_id is None:
                raise ValueError("M6 physical Detection requires its containing frame_id")
            parse_frame_id(self.container_id)
        elif self.container_id is not None:
            raise ValueError(
                "M6 physical artifact cannot claim a container unless it is a Detection"
            )
        if (
            byte_authority in _CANONICAL_CONTENT_AUTHORITIES
            and self.content_sha256 != self.document_sha256
        ):
            raise ValueError("M6 canonical physical content_sha256 must equal document_sha256")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def artifact_ref_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-physical-artifact-ref",
                1,
                self.source,
                self.kind,
                self.artifact_id,
                self.container_id,
                self.document_sha256,
                self.content_sha256,
                self.size_bytes,
            ]
        )

    @property
    def physical_key(self) -> tuple[int, int, str, str]:
        return (
            _ARTIFACT_SOURCE_RANK[self.source],
            _ARTIFACT_KIND_RANK[self.kind],
            self.container_id or "",
            self.artifact_id,
        )

    @property
    def sort_key(self) -> tuple[int, int, str, str]:
        return self.physical_key


def require_m6_upgrade_artifact_usage(
    kind: M6UpgradePhysicalArtifactKind,
    usage: M6UpgradeArtifactUsage,
) -> None:
    if kind in _CONSUMED_ONLY_ARTIFACT_KINDS and usage != M6UpgradeArtifactUsage.CONSUMED:
        raise ValueError("M6 physical input artifact must be recorded as consumed")
    if kind in _PRODUCED_ONLY_ARTIFACT_KINDS and usage != M6UpgradeArtifactUsage.PRODUCED:
        raise ValueError("M6 physical output artifact must be recorded as produced")


__all__ = [
    "MAX_M6_UPGRADE_PHYSICAL_ARTIFACT_BYTES",
    "MAX_M6_UPGRADE_PHYSICAL_IDENTIFIER_LENGTH",
    "MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES",
    "M6UpgradeArtifactUsage",
    "M6UpgradePhysicalArtifactKind",
    "M6UpgradePhysicalArtifactRef",
    "M6UpgradePhysicalArtifactSource",
    "M6UpgradePhysicalByteAuthority",
    "m6_upgrade_physical_artifact_requires_case",
    "m6_upgrade_physical_byte_authority_for",
    "require_m6_upgrade_artifact_usage",
]

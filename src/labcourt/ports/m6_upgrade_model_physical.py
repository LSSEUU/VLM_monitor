"""Planned and observed physical model-call closures for M6 upgrades.

Both closures record only authority reconstructed from trusted documents and
physical-byte receipts.  A planned response reference is explicitly not proof
that its raw bytes have been read; the observed refinement is emitted only
after an exact raw-byte verifier succeeds.  Neither closure has a
``provider_invoked`` field because provider delivery is a separate runtime
observation.
"""

from __future__ import annotations

from dataclasses import dataclass

from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.references import require_reference_token

_LAYER_RANK = {layer: index for index, layer in enumerate(M6LockedModelCallLayer)}
_ROLE_RANK = {role: index for index, role in enumerate(M6LockedModelRole)}


def _require_sha256(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _controlled_ref(value: object, label: str) -> M6UpgradePhysicalArtifactRef:
    if not isinstance(value, M6UpgradePhysicalArtifactRef):
        raise TypeError(f"{label} must be a typed M6 physical artifact ref")
    try:
        controlled = M6UpgradePhysicalArtifactRef.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a canonical M6 physical artifact ref") from None
    if controlled != value:
        raise ValueError(f"{label} must be a canonical M6 physical artifact ref")
    return controlled


@dataclass(frozen=True, slots=True)
class _ModelCallPhysicalClosure:
    """Shared immutable shape and invariants for a physical call closure."""

    source_identity_sha256: str
    run_id: str
    case_id: str
    manifest_id: str
    layer: M6LockedModelCallLayer
    role: M6LockedModelRole
    attempt_index: int
    timeout_ms: int
    execution_model_manifest_id: str
    request_ref: M6UpgradePhysicalArtifactRef
    result_kind: M6LockedModelCallResultKind
    response_ref: M6UpgradePhysicalArtifactRef | None = None
    cache_ref: M6UpgradePhysicalArtifactRef | None = None
    parse_receipt_ref: M6UpgradePhysicalArtifactRef | None = None
    parsed_output_ref: M6UpgradePhysicalArtifactRef | None = None
    failure_ref: M6UpgradePhysicalArtifactRef | None = None
    usage_receipt_ref: M6UpgradePhysicalArtifactRef | None = None

    def __post_init__(self) -> None:
        _require_sha256(self.source_identity_sha256, "source_identity_sha256")
        _require_sha256(self.manifest_id, "manifest_id")
        _require_sha256(
            self.execution_model_manifest_id,
            "execution_model_manifest_id",
        )
        if not isinstance(self.run_id, str):
            raise TypeError("run_id must be a string")
        require_reference_token(self.run_id, "M6 model call run_id")
        if not isinstance(self.case_id, str):
            raise TypeError("case_id must be a string")
        require_reference_token(self.case_id, "M6 model call case_id")
        if not isinstance(self.layer, M6LockedModelCallLayer):
            raise TypeError("layer must be an M6 locked model-call layer")
        if not isinstance(self.role, M6LockedModelRole):
            raise TypeError("role must be an M6 locked model role")
        if not isinstance(self.result_kind, M6LockedModelCallResultKind):
            raise TypeError("result_kind must be an M6 locked result kind")
        if (
            not isinstance(self.attempt_index, int)
            or isinstance(self.attempt_index, bool)
            or self.attempt_index not in {0, 1}
        ):
            raise ValueError("attempt_index must be zero or one")
        if (
            not isinstance(self.timeout_ms, int)
            or isinstance(self.timeout_ms, bool)
            or not 0 < self.timeout_ms <= 3_600_000
        ):
            raise ValueError("timeout_ms must be an integer in [1, 3600000]")

        expected_source = (
            M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL
            if self.layer == M6LockedModelCallLayer.SCREENING
            else M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL
        )
        if self.layer == M6LockedModelCallLayer.SCREENING:
            if self.role != M6LockedModelRole.SCREENING:
                raise ValueError("screening model closure requires the SCREENING role")
        elif self.role == M6LockedModelRole.SCREENING:
            raise ValueError("hearing model closure cannot use the SCREENING role")

        controlled: dict[str, M6UpgradePhysicalArtifactRef | None] = {}
        for field_name, value in (
            ("request_ref", self.request_ref),
            ("response_ref", self.response_ref),
            ("cache_ref", self.cache_ref),
            ("parse_receipt_ref", self.parse_receipt_ref),
            ("parsed_output_ref", self.parsed_output_ref),
            ("failure_ref", self.failure_ref),
            ("usage_receipt_ref", self.usage_receipt_ref),
        ):
            controlled[field_name] = (
                _controlled_ref(value, field_name) if value is not None else None
            )
        request_ref = controlled["request_ref"]
        if request_ref is None:
            raise ValueError("model physical closure requires a request ref")
        if any(ref.source != expected_source for ref in controlled.values() if ref is not None):
            raise ValueError("model physical closure crosses its layer source")
        expected_kinds = {
            "request_ref": M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
            "response_ref": M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
            "cache_ref": M6UpgradePhysicalArtifactKind.MODEL_CACHE,
            "parse_receipt_ref": M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
            "parsed_output_ref": M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
            "failure_ref": M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
            "usage_receipt_ref": M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
        }
        if any(
            ref is not None and ref.kind != expected_kinds[field_name]
            for field_name, ref in controlled.items()
        ):
            raise ValueError("model physical closure contains an incorrect artifact kind")
        refs = tuple(ref for ref in controlled.values() if ref is not None)
        if len({ref.physical_key for ref in refs}) != len(refs):
            raise ValueError("model physical closure artifacts must be physically unique")

        if self.result_kind == M6LockedModelCallResultKind.RESPONSE:
            if (
                controlled["response_ref"] is None
                or controlled["cache_ref"] is None
                or controlled["parse_receipt_ref"] is None
                or controlled["usage_receipt_ref"] is None
                or controlled["failure_ref"] is not None
            ):
                raise ValueError("response model-call closure is incomplete")
        elif (
            controlled["failure_ref"] is None
            or controlled["response_ref"] is not None
            or controlled["cache_ref"] is not None
            or controlled["parse_receipt_ref"] is not None
            or controlled["parsed_output_ref"] is not None
            or controlled["usage_receipt_ref"] is not None
        ):
            raise ValueError("failed model-call closure must contain request and failure")

    @property
    def artifact_refs(self) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
        return tuple(
            ref
            for ref in (
                self.request_ref,
                self.response_ref,
                self.cache_ref,
                self.parse_receipt_ref,
                self.parsed_output_ref,
                self.failure_ref,
                self.usage_receipt_ref,
            )
            if ref is not None
        )

    @property
    def sort_key(self) -> tuple[int, int, int, str]:
        return (
            _LAYER_RANK[self.layer],
            _ROLE_RANK[self.role],
            self.attempt_index,
            self.request_ref.artifact_id,
        )


@dataclass(frozen=True, slots=True)
class M6PlannedModelCallPhysicalClosure(_ModelCallPhysicalClosure):
    """One complete call plan whose raw response bytes are not yet verified."""


@dataclass(frozen=True, slots=True)
class M6ObservedModelCallPhysicalClosure(_ModelCallPhysicalClosure):
    """One exact model call observed after any response raw bytes are verified."""


__all__ = [
    "M6ObservedModelCallPhysicalClosure",
    "M6PlannedModelCallPhysicalClosure",
]

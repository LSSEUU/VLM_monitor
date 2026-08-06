"""Typed request scopes for model-authored references in M6 replay.

These values contain only already-validated identities and disclosure scopes.
They do not read storage and do not decide whether a referenced artifact exists.
"""

from __future__ import annotations

from dataclasses import dataclass

from labcourt.contracts.enums import ArtifactKind, VlmRole
from labcourt.contracts.storage import ArtifactRef

_HEARING_ROLES = (VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE)


def _require_token(value: str, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise TypeError(f"{label} must be a non-empty string")


def _require_refs(refs: tuple[ArtifactRef, ...], label: str) -> None:
    if not isinstance(refs, tuple) or any(not isinstance(ref, ArtifactRef) for ref in refs):
        raise TypeError(f"{label} must be a typed tuple")
    keys = tuple(ref.sort_key for ref in refs)
    if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
        raise ValueError(f"{label} must use stable unique order")


@dataclass(frozen=True, slots=True)
class M6ModelReferenceScope:
    """Exact evidence and precedent disclosure of one model request."""

    request_id: str
    evidence_pack_id: str
    evidence_pack_version: int
    cycle_scope_id: str | None
    allowed_evidence_refs: tuple[ArtifactRef, ...]
    allowed_precedent_refs: tuple[ArtifactRef, ...] = ()

    def __post_init__(self) -> None:
        _require_token(self.request_id, "scope request_id")
        _require_token(self.evidence_pack_id, "scope evidence_pack_id")
        if (
            not isinstance(self.evidence_pack_version, int)
            or isinstance(self.evidence_pack_version, bool)
            or self.evidence_pack_version <= 0
        ):
            raise ValueError("scope evidence_pack_version must be positive")
        if self.cycle_scope_id is not None:
            _require_token(self.cycle_scope_id, "scope cycle_scope_id")
        _require_refs(self.allowed_evidence_refs, "allowed_evidence_refs")
        _require_refs(self.allowed_precedent_refs, "allowed_precedent_refs")
        if any(ref.kind != ArtifactKind.PRECEDENT for ref in self.allowed_precedent_refs):
            raise ValueError("allowed_precedent_refs must contain only PRECEDENT refs")


@dataclass(frozen=True, slots=True)
class M6ScreeningModelReferenceBinding:
    """Bind one Case ScreeningResult to its final and scope-authority requests."""

    screening_id: str
    parsed_output_id: str
    final_request_id: str
    scope: M6ModelReferenceScope

    def __post_init__(self) -> None:
        _require_token(self.screening_id, "screening_id")
        _require_token(self.parsed_output_id, "parsed_output_id")
        _require_token(self.final_request_id, "final_request_id")
        if not isinstance(self.scope, M6ModelReferenceScope):
            raise TypeError("screening scope must be typed")


@dataclass(frozen=True, slots=True)
class M6HearingRoleModelReferenceBinding:
    """Bind one terminal hearing role output to its exact request scope."""

    role: VlmRole
    output_id: str
    response_id: str
    final_request_id: str
    scope: M6ModelReferenceScope

    def __post_init__(self) -> None:
        if self.role not in _HEARING_ROLES:
            raise ValueError("hearing role binding requires prosecutor, defender, or judge")
        _require_token(self.output_id, "role output_id")
        _require_token(self.response_id, "role response_id")
        _require_token(self.final_request_id, "role final_request_id")
        if not isinstance(self.scope, M6ModelReferenceScope):
            raise TypeError("hearing role scope must be typed")


@dataclass(frozen=True, slots=True)
class M6VerdictModelReferenceBinding:
    """Exact terminal three-role request authority for one frozen Verdict."""

    verdict_id: str
    hearing_record_id: str
    judge_round_id: str
    role_bindings: tuple[M6HearingRoleModelReferenceBinding, ...]

    def __post_init__(self) -> None:
        _require_token(self.verdict_id, "verdict_id")
        _require_token(self.hearing_record_id, "hearing_record_id")
        _require_token(self.judge_round_id, "judge_round_id")
        if not isinstance(self.role_bindings, tuple) or any(
            not isinstance(item, M6HearingRoleModelReferenceBinding) for item in self.role_bindings
        ):
            raise TypeError("role_bindings must be a typed tuple")
        if tuple(item.role for item in self.role_bindings) != _HEARING_ROLES:
            raise ValueError("role_bindings must contain prosecutor, defender, and judge")

    def scope_for_role(self, role: VlmRole) -> M6ModelReferenceScope:
        if role not in _HEARING_ROLES:
            raise KeyError(role)
        return next(item.scope for item in self.role_bindings if item.role == role)


@dataclass(frozen=True, slots=True)
class M6FastVerdictModelReferenceBinding:
    """Bind one deterministic M3 fast Verdict to its screening response scope."""

    verdict_id: str
    screening_id: str
    response_ids: tuple[str, ...]
    scope: M6ModelReferenceScope

    def __post_init__(self) -> None:
        _require_token(self.verdict_id, "fast verdict_id")
        _require_token(self.screening_id, "fast screening_id")
        if (
            not isinstance(self.response_ids, tuple)
            or not self.response_ids
            or any(not isinstance(item, str) or not item for item in self.response_ids)
            or self.response_ids != tuple(sorted(self.response_ids))
            or len(self.response_ids) != len(set(self.response_ids))
        ):
            raise ValueError("fast verdict response_ids must be a stable unique tuple")
        if not isinstance(self.scope, M6ModelReferenceScope):
            raise TypeError("fast verdict scope must be typed")


@dataclass(frozen=True, slots=True)
class M6CaseModelReferenceAuthority:
    """Case-wide model-reference scopes resolved from validated M3/M4 snapshots."""

    source_identity_sha256: str
    run_id: str
    case_id: str
    manifest_id: str
    screening_bindings: tuple[M6ScreeningModelReferenceBinding, ...]
    verdict_bindings: tuple[M6VerdictModelReferenceBinding, ...]
    fast_verdict_bindings: tuple[M6FastVerdictModelReferenceBinding, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source_identity_sha256, str)
            or len(self.source_identity_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.source_identity_sha256)
        ):
            raise ValueError("source_identity_sha256 must be a lowercase SHA-256")
        _require_token(self.run_id, "run_id")
        _require_token(self.case_id, "case_id")
        _require_token(self.manifest_id, "manifest_id")
        if not isinstance(self.screening_bindings, tuple) or any(
            not isinstance(item, M6ScreeningModelReferenceBinding)
            for item in self.screening_bindings
        ):
            raise TypeError("screening_bindings must be a typed tuple")
        if not isinstance(self.verdict_bindings, tuple) or any(
            not isinstance(item, M6VerdictModelReferenceBinding) for item in self.verdict_bindings
        ):
            raise TypeError("verdict_bindings must be a typed tuple")
        if not isinstance(self.fast_verdict_bindings, tuple) or any(
            not isinstance(item, M6FastVerdictModelReferenceBinding)
            for item in self.fast_verdict_bindings
        ):
            raise TypeError("fast_verdict_bindings must be a typed tuple")
        screening_ids = tuple(item.screening_id for item in self.screening_bindings)
        verdict_ids = tuple(item.verdict_id for item in self.verdict_bindings)
        fast_verdict_ids = tuple(item.verdict_id for item in self.fast_verdict_bindings)
        if screening_ids != tuple(sorted(screening_ids)) or len(screening_ids) != len(
            set(screening_ids)
        ):
            raise ValueError("screening bindings must use stable unique order")
        if verdict_ids != tuple(sorted(verdict_ids)) or len(verdict_ids) != len(set(verdict_ids)):
            raise ValueError("verdict bindings must use stable unique order")
        if fast_verdict_ids != tuple(sorted(fast_verdict_ids)) or len(fast_verdict_ids) != len(
            set(fast_verdict_ids)
        ):
            raise ValueError("fast verdict bindings must use stable unique order")
        if set(verdict_ids) & set(fast_verdict_ids):
            raise ValueError("fast and hearing verdict bindings must be disjoint")


__all__ = [
    "M6CaseModelReferenceAuthority",
    "M6FastVerdictModelReferenceBinding",
    "M6HearingRoleModelReferenceBinding",
    "M6ModelReferenceScope",
    "M6ScreeningModelReferenceBinding",
    "M6VerdictModelReferenceBinding",
]

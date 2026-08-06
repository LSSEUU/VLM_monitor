"""LCJ-AUDIT-1 immutable audit entries and authoritative-head chain checks."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.enums import (
    AuditAction,
    AuditActorRole,
    AuditChainFailureReason,
)
from labcourt.contracts.frames import SHA256_PATTERN, Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import ArtifactRef

AUDIT_SCHEMA_VERSION: Literal["1.0.0"] = "1.0.0"
AUDIT_GENESIS_HASH = "0" * 64

_RECORDED_AT_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_ANONYMOUS_ACTOR = re.compile(r"^anon_[0-9a-f]{64}$")
_SHA256 = re.compile(SHA256_PATTERN)
_SYSTEM_ACTORS = frozenset(role.value for role in AuditActorRole)


def _derive_entry_hash(prev_entry_hash: str, body: Mapping[str, object]) -> str:
    return hashlib.sha256(prev_entry_hash.encode("ascii") + canonical_bytes(body)).hexdigest()


class _AuditEntryBody(FrozenContractModel):
    schema_version: Literal["1.0.0"] = AUDIT_SCHEMA_VERSION
    run_id: ReferenceToken
    sequence: int = Field(ge=0, strict=True)
    actor: str = Field(min_length=1, max_length=69)
    action: AuditAction
    object_ref: ArtifactRef
    before_sha256: Sha256Hex | None = None
    after_sha256: Sha256Hex | None = None
    manifest_id: Sha256Hex
    recorded_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
    prev_entry_hash: Sha256Hex

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "audit run_id")

    @field_validator("actor")
    @classmethod
    def validate_anonymous_actor(cls, value: str) -> str:
        if value not in _SYSTEM_ACTORS and _ANONYMOUS_ACTOR.fullmatch(value) is None:
            raise ValueError(
                "audit actor must be a controlled system role or anon_<sha256> pseudonym"
            )
        return value

    @field_validator("recorded_at")
    @classmethod
    def validate_utc_wall_clock(cls, value: str) -> str:
        try:
            parsed = datetime.strptime(value, _RECORDED_AT_FORMAT)
        except ValueError:
            raise ValueError("recorded_at must be a real fixed-width UTC timestamp") from None
        if parsed.strftime(_RECORDED_AT_FORMAT) != value:
            raise ValueError("recorded_at must use canonical fixed-width UTC form")
        return value

    def hash_body(self) -> dict[str, object]:
        """Return the exact ten-field LCJ-AUDIT-1 body, excluding both chain hashes."""

        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "sequence": self.sequence,
            "actor": self.actor,
            "action": self.action.value,
            "object_ref": self.object_ref.model_dump(mode="json"),
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "manifest_id": self.manifest_id,
            "recorded_at": self.recorded_at,
        }

    @model_validator(mode="after")
    def validate_chain_position_and_transition(self) -> Self:
        if self.before_sha256 is None and self.after_sha256 is None:
            raise ValueError("an audit entry requires a before or after hash")
        if (
            self.before_sha256 is not None
            and self.after_sha256 is not None
            and self.before_sha256 == self.after_sha256
        ):
            raise ValueError("an audit entry cannot record an unchanged state")
        if self.action == AuditAction.CASE_CREATED and (
            self.before_sha256 is not None or self.after_sha256 is None
        ):
            raise ValueError("CASE_CREATED requires no before hash and one after hash")
        if self.sequence == 0 and self.prev_entry_hash != AUDIT_GENESIS_HASH:
            raise ValueError("audit sequence zero must reference the genesis hash")
        if self.sequence > 0 and self.prev_entry_hash == AUDIT_GENESIS_HASH:
            raise ValueError("only audit sequence zero can reference the genesis hash")
        return self


class AuditEntryDraft(_AuditEntryBody):
    """Validated audit body used only before an immutable stored entry is sealed."""

    def seal(self) -> AuditEntry:
        payload = self.model_dump(mode="python")
        payload["entry_hash"] = _derive_entry_hash(self.prev_entry_hash, self.hash_body())
        return AuditEntry.model_validate(payload)


class AuditEntry(_AuditEntryBody):
    """Stored audit entry; entry_hash is mandatory and verified on every parse."""

    entry_hash: Sha256Hex = Field(json_schema_extra={"readOnly": True})

    @model_validator(mode="after")
    def validate_stored_entry_hash(self) -> AuditEntry:
        expected = _derive_entry_hash(self.prev_entry_hash, self.hash_body())
        if self.entry_hash != expected:
            raise ValueError("stored audit entry_hash does not match its LCJ-AUDIT-1 body")
        return self


class AuditChainReport(FrozenContractModel):
    """Typed first-error result bound to a run, manifest, and authoritative head."""

    expected_run_id: ReferenceToken
    expected_manifest_id: Sha256Hex
    expected_head_sequence: int = Field(ge=-1, strict=True)
    expected_head_hash: Sha256Hex
    actual_head_sequence: int = Field(ge=-1, strict=True)
    actual_head_hash: Sha256Hex
    checked_entry_count: int = Field(ge=0, strict=True)
    failure_sequence: int | None = Field(default=None, ge=0, strict=True)
    failure_reason: AuditChainFailureReason | None = None

    @field_validator("expected_run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "audit chain expected_run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_passed(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "passed" in payload
        claimed = payload.pop("passed", None)
        report = handler(payload)
        if claimed_present and not isinstance(claimed, bool):
            raise ValueError("serialized audit-chain passed must be a boolean")
        if claimed_present and claimed != report.passed:
            raise ValueError("serialized audit-chain passed does not match failure_reason")
        return report

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> bool:
        return self.failure_reason is None

    @model_validator(mode="after")
    def validate_failure_pair(self) -> AuditChainReport:
        if (self.failure_reason is None) != (self.failure_sequence is None):
            raise ValueError("audit-chain failure reason and sequence must be present together")
        if self.expected_head_sequence == -1 and self.expected_head_hash != AUDIT_GENESIS_HASH:
            raise ValueError("an expected empty audit chain must use the genesis head hash")
        if self.actual_head_sequence == -1 and self.actual_head_hash != AUDIT_GENESIS_HASH:
            raise ValueError("an observed empty audit chain must use the genesis head hash")
        return self


def _chain_report(
    *,
    chain: tuple[AuditEntry, ...],
    expected_run_id: str,
    expected_manifest_id: str,
    expected_head_sequence: int,
    expected_head_hash: str,
    checked_entry_count: int,
    failure_sequence: int | None = None,
    failure_reason: AuditChainFailureReason | None = None,
) -> AuditChainReport:
    if chain:
        actual_head_sequence = chain[-1].sequence
        actual_head_hash = chain[-1].entry_hash
    else:
        actual_head_sequence = -1
        actual_head_hash = AUDIT_GENESIS_HASH
    return AuditChainReport(
        expected_run_id=expected_run_id,
        expected_manifest_id=expected_manifest_id,
        expected_head_sequence=expected_head_sequence,
        expected_head_hash=expected_head_hash,
        actual_head_sequence=actual_head_sequence,
        actual_head_hash=actual_head_hash,
        checked_entry_count=checked_entry_count,
        failure_sequence=failure_sequence,
        failure_reason=failure_reason,
    )


def verify_audit_chain(
    entries: Sequence[AuditEntry],
    *,
    expected_run_id: str,
    expected_manifest_id: str,
    expected_head_sequence: int,
    expected_head_hash: str,
) -> AuditChainReport:
    """Verify an ordered chain against authoritative scope and head state."""

    if not isinstance(expected_run_id, str):
        raise ValueError("expected_run_id must be an anonymous reference token")
    require_reference_token(expected_run_id, "audit chain expected_run_id")
    if not isinstance(expected_manifest_id, str) or _SHA256.fullmatch(expected_manifest_id) is None:
        raise ValueError("expected_manifest_id must be a lowercase SHA-256 digest")
    if (
        not isinstance(expected_head_sequence, int)
        or isinstance(expected_head_sequence, bool)
        or expected_head_sequence < -1
    ):
        raise ValueError("expected_head_sequence must be an integer greater than or equal to -1")
    if not isinstance(expected_head_hash, str) or _SHA256.fullmatch(expected_head_hash) is None:
        raise ValueError("expected_head_hash must be a lowercase SHA-256 digest")
    if expected_head_sequence == -1 and expected_head_hash != AUDIT_GENESIS_HASH:
        raise ValueError("an expected empty audit chain must use the genesis head hash")

    chain = tuple(entries)
    expected_prev = AUDIT_GENESIS_HASH
    seen_hashes: set[str] = set()
    for expected_sequence, entry in enumerate(chain):
        if entry.run_id != expected_run_id:
            return _chain_report(
                chain=chain,
                expected_run_id=expected_run_id,
                expected_manifest_id=expected_manifest_id,
                expected_head_sequence=expected_head_sequence,
                expected_head_hash=expected_head_hash,
                checked_entry_count=expected_sequence + 1,
                failure_sequence=expected_sequence,
                failure_reason=AuditChainFailureReason.RUN_MISMATCH,
            )
        if entry.manifest_id != expected_manifest_id:
            return _chain_report(
                chain=chain,
                expected_run_id=expected_run_id,
                expected_manifest_id=expected_manifest_id,
                expected_head_sequence=expected_head_sequence,
                expected_head_hash=expected_head_hash,
                checked_entry_count=expected_sequence + 1,
                failure_sequence=expected_sequence,
                failure_reason=AuditChainFailureReason.MANIFEST_MISMATCH,
            )
        if entry.sequence != expected_sequence:
            return _chain_report(
                chain=chain,
                expected_run_id=expected_run_id,
                expected_manifest_id=expected_manifest_id,
                expected_head_sequence=expected_head_sequence,
                expected_head_hash=expected_head_hash,
                checked_entry_count=expected_sequence + 1,
                failure_sequence=expected_sequence,
                failure_reason=AuditChainFailureReason.SEQUENCE_MISMATCH,
            )
        derived_hash = _derive_entry_hash(entry.prev_entry_hash, entry.hash_body())
        if entry.entry_hash != derived_hash:
            return _chain_report(
                chain=chain,
                expected_run_id=expected_run_id,
                expected_manifest_id=expected_manifest_id,
                expected_head_sequence=expected_head_sequence,
                expected_head_hash=expected_head_hash,
                checked_entry_count=expected_sequence + 1,
                failure_sequence=expected_sequence,
                failure_reason=AuditChainFailureReason.ENTRY_HASH_MISMATCH,
            )
        if entry.prev_entry_hash != expected_prev:
            return _chain_report(
                chain=chain,
                expected_run_id=expected_run_id,
                expected_manifest_id=expected_manifest_id,
                expected_head_sequence=expected_head_sequence,
                expected_head_hash=expected_head_hash,
                checked_entry_count=expected_sequence + 1,
                failure_sequence=expected_sequence,
                failure_reason=AuditChainFailureReason.PREVIOUS_HASH_MISMATCH,
            )
        if entry.entry_hash in seen_hashes:
            return _chain_report(
                chain=chain,
                expected_run_id=expected_run_id,
                expected_manifest_id=expected_manifest_id,
                expected_head_sequence=expected_head_sequence,
                expected_head_hash=expected_head_hash,
                checked_entry_count=expected_sequence + 1,
                failure_sequence=expected_sequence,
                failure_reason=AuditChainFailureReason.DUPLICATE_ENTRY_HASH,
            )
        seen_hashes.add(entry.entry_hash)
        expected_prev = entry.entry_hash

    actual_head_sequence = chain[-1].sequence if chain else -1
    actual_head_hash = chain[-1].entry_hash if chain else AUDIT_GENESIS_HASH
    if actual_head_sequence != expected_head_sequence:
        return _chain_report(
            chain=chain,
            expected_run_id=expected_run_id,
            expected_manifest_id=expected_manifest_id,
            expected_head_sequence=expected_head_sequence,
            expected_head_hash=expected_head_hash,
            checked_entry_count=len(chain),
            failure_sequence=max(actual_head_sequence, expected_head_sequence, 0),
            failure_reason=AuditChainFailureReason.HEAD_SEQUENCE_MISMATCH,
        )
    if actual_head_hash != expected_head_hash:
        return _chain_report(
            chain=chain,
            expected_run_id=expected_run_id,
            expected_manifest_id=expected_manifest_id,
            expected_head_sequence=expected_head_sequence,
            expected_head_hash=expected_head_hash,
            checked_entry_count=len(chain),
            failure_sequence=max(expected_head_sequence, 0),
            failure_reason=AuditChainFailureReason.HEAD_HASH_MISMATCH,
        )
    return _chain_report(
        chain=chain,
        expected_run_id=expected_run_id,
        expected_manifest_id=expected_manifest_id,
        expected_head_sequence=expected_head_sequence,
        expected_head_hash=expected_head_hash,
        checked_entry_count=len(chain),
    )


def validate_audit_chain(
    entries: Sequence[AuditEntry],
    *,
    expected_run_id: str,
    expected_manifest_id: str,
    expected_head_sequence: int,
    expected_head_hash: str,
) -> AuditChainReport:
    """Compatibility name for the authoritative-head verifier."""

    return verify_audit_chain(
        entries,
        expected_run_id=expected_run_id,
        expected_manifest_id=expected_manifest_id,
        expected_head_sequence=expected_head_sequence,
        expected_head_hash=expected_head_hash,
    )


__all__ = [
    "AUDIT_GENESIS_HASH",
    "AUDIT_SCHEMA_VERSION",
    "AuditChainReport",
    "AuditEntry",
    "AuditEntryDraft",
    "validate_audit_chain",
    "verify_audit_chain",
]

"""Read-only facade for one same-snapshot M6 SQLite projection assembly."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import NoReturn

from pydantic import ValidationError

from labcourt.application.m6_replay_locked_fast_source import (
    M6ReplayLockedFastPrePolicyProjection,
    assemble_m6_replay_locked_closed_policy_fast_predecessor_projection,
    assemble_m6_replay_locked_fast_terminal_source,
)
from labcourt.application.m6_replay_locked_m4_source import (
    M6ReplayLockedM4PrePolicyProjection,
    assemble_m6_replay_locked_closed_policy_m4_predecessor_projection,
    narrow_m6_replay_locked_m4_gate_terminal_source,
)
from labcourt.application.m6_verified_projection_context import (
    M6SqliteProjectionAssembly,
    M6SqliteProjectionAssemblyError,
    M6SqliteProjectionAssemblyErrorCode,
    assemble_m6_sqlite_projection_authority,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.hearing_state import HearingRecord, HearingVerdictBinding
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.ports.m6_replay_locked_fast_source import (
    M6ReplayLockedFastTerminalSource,
)
from labcourt.ports.m6_replay_locked_m4_source import (
    M6ReplayLockedM4GateTerminalSource,
)

from ._m6_snapshot_identity import (
    M6ReadonlySnapshotIdentity,
    capture_m6_readonly_snapshot_identity,
)
from .readonly_m4_artifacts import ReadonlyM4ArtifactRepository
from .readonly_m6_acquisition_authority import (
    ReadonlyM6AcquisitionAuthorityRepository,
)
from .readonly_m6_embeddings import ReadonlyM6EmbeddingAuthorityRepository
from .readonly_m6_hearing_model_calls import (
    ReadonlyM6HearingModelCallAuthorityRepository,
)
from .readonly_m6_historical_retrieval import (
    ReadonlyM6HistoricalRetrievalCutRepository,
)
from .readonly_m6_model_calls import ReadonlyM6ModelCallAuthorityRepository
from .readonly_m6_perception import ReadonlyM6PerceptionAuthorityRepository
from .readonly_m6_procedural_gate_authority import (
    ReadonlyM6ProceduralGateAuthorityRepository,
)
from .readonly_m6_source_authority import (
    ReadonlyM6SealedSourceAuthorityRepository,
)
from .readonly_sqlite import ReadOnlySnapshotError


def _fail(code: M6SqliteProjectionAssemblyErrorCode) -> NoReturn:
    raise M6SqliteProjectionAssemblyError(code)


def _controlled_closure(value: object) -> M6ReplayInputClosureAuthority:
    if not isinstance(value, M6ReplayInputClosureAuthority):
        _fail(M6SqliteProjectionAssemblyErrorCode.INVALID_ARGUMENT)
    try:
        controlled = M6ReplayInputClosureAuthority.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6SqliteProjectionAssemblyErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6SqliteProjectionAssemblyErrorCode.INVALID_ARGUMENT)
    return controlled


def _case_for_scoped_reads(
    closure: M6ReplayInputClosureAuthority,
    canonical_document: str | None,
) -> Case:
    if (
        closure.source_case_id is None
        or closure.source_case_revision is None
        or closure.source_case_document_sha256 is None
        or canonical_document is None
    ):
        _fail(M6SqliteProjectionAssemblyErrorCode.SOURCE_CASE_REQUIRED)
    try:
        case = Case.model_validate_json(canonical_document)
    except (TypeError, ValueError, ValidationError):
        _fail(M6SqliteProjectionAssemblyErrorCode.SOURCE_CASE_DOCUMENT_INVALID)
    if canonical_json(case.model_dump(mode="json")) != canonical_document:
        _fail(M6SqliteProjectionAssemblyErrorCode.SOURCE_CASE_DOCUMENT_INVALID)
    if (
        case.run_id != closure.source_run_id
        or case.case_id != closure.source_case_id
        or case.manifest_id != closure.source_manifest_id
    ):
        _fail(M6SqliteProjectionAssemblyErrorCode.SOURCE_SCOPE_MISMATCH)
    return case


def _require_unchanged_after_failure(
    snapshot: Path,
    before: M6ReadonlySnapshotIdentity,
) -> None:
    try:
        observed = capture_m6_readonly_snapshot_identity(snapshot)
    except ReadOnlySnapshotError:
        _fail(M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_CHANGED)
    if observed != before:
        _fail(M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_CHANGED)


def _load_m4_terminal_join(
    snapshot: Path,
    case: Case,
) -> tuple[HearingRecord, HearingVerdictBinding]:
    if len(case.verdicts) != 1 or len(case.procedural_reviews) != 1:
        _fail(M6SqliteProjectionAssemblyErrorCode.PROJECTION_CONTEXT_INVALID)
    verdict = case.verdicts[0]
    m4 = ReadonlyM4ArtifactRepository(
        snapshot,
        immutable=True,
    ).scan(case.run_id)
    if m4.failures:
        _fail(M6SqliteProjectionAssemblyErrorCode.PROJECTION_CONTEXT_INVALID)
    bindings = tuple(
        HearingVerdictBinding.model_validate_json(item.canonical_document)
        for item in m4.documents
        if item.kind == M4ProjectionArtifactKind.VERDICT_BINDING
    )
    matching_bindings = tuple(
        item
        for item in bindings
        if item.run_id == case.run_id
        and item.case_id == case.case_id
        and item.manifest_id == case.manifest_id
        and item.verdict_id == verdict.verdict_id
        and item.verdict_version == verdict.version
        and item.verdict_sha256 == verdict.verdict_sha256
    )
    if len(matching_bindings) != 1:
        _fail(M6SqliteProjectionAssemblyErrorCode.PROJECTION_CONTEXT_INVALID)
    binding = matching_bindings[0]
    records = tuple(
        HearingRecord.model_validate_json(item.canonical_document)
        for item in m4.documents
        if item.kind == M4ProjectionArtifactKind.HEARING_RECORD
    )
    matching_records = tuple(
        item
        for item in records
        if item.run_id == case.run_id
        and item.case_id == case.case_id
        and item.manifest_id == case.manifest_id
        and item.record_id == binding.hearing_record_id
        and item.version == binding.hearing_record_version
        and item.record_sha256 == binding.hearing_record_sha256
    )
    if len(matching_records) != 1:
        _fail(M6SqliteProjectionAssemblyErrorCode.PROJECTION_CONTEXT_INVALID)
    return matching_records[0], binding


class ReadonlyM6SqliteProjectionAssemblyRepository:
    """Load six DTOs and assemble a partial source-projection authority.

    Only the DTO-producing read methods are used.  Component convenience
    ``assemble`` methods are intentionally bypassed so all six identities can be
    compared before any semantic projection is accepted.  This facade does not
    run candidate application or alert policy and cannot issue a replay receipt.
    """

    __slots__ = ("_config", "_snapshot", "_source_authority_root")

    def __init__(
        self,
        snapshot: str | Path,
        *,
        config: AppConfig,
        source_authority_root: str | Path | None = None,
    ) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be a fully resolved AppConfig")
        self._snapshot = Path(snapshot).absolute()
        self._config = AppConfig.model_validate(config.model_dump(mode="json"))
        self._source_authority_root = (
            Path(source_authority_root).absolute() if source_authority_root is not None else None
        )

    def assemble(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6SqliteProjectionAssembly:
        controlled = _controlled_closure(closure)
        before = capture_m6_readonly_snapshot_identity(self._snapshot)
        try:
            perception = ReadonlyM6PerceptionAuthorityRepository(
                self._snapshot
            ).read_authority_snapshot(controlled)
            source_case = _case_for_scoped_reads(
                controlled,
                perception.source_case_canonical_document,
            )
            m3 = ReadonlyM6ModelCallAuthorityRepository(self._snapshot).load_validated_snapshot(
                source_case
            )
            m4 = ReadonlyM6HearingModelCallAuthorityRepository(self._snapshot).load_authority(
                source_case
            )
            historical = ReadonlyM6HistoricalRetrievalCutRepository(
                self._snapshot,
                config=self._config,
            ).load_validated_snapshots(controlled.source_run_id)
            acquisition = ReadonlyM6AcquisitionAuthorityRepository(
                self._snapshot
            ).load_validated_snapshot(controlled.source_run_id)
            embedding = ReadonlyM6EmbeddingAuthorityRepository(
                self._snapshot,
                config=self._config,
            ).read_authority_snapshot(controlled.source_run_id)
            source_authority = None
            gate_history = None
            if self._source_authority_root is not None:
                source_authority = ReadonlyM6SealedSourceAuthorityRepository(
                    self._snapshot,
                    store_root=self._source_authority_root,
                    config=self._config,
                ).load_validated_source(controlled)
                gate_history = ReadonlyM6ProceduralGateAuthorityRepository(
                    self._snapshot
                ).load_validated_snapshot(controlled.source_run_id)
            after = capture_m6_readonly_snapshot_identity(self._snapshot)
        except ReadOnlySnapshotError as error:
            if "CHANGED" in error.reason_code:
                _fail(M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_CHANGED)
            _require_unchanged_after_failure(self._snapshot, before)
            raise
        except Exception:
            _require_unchanged_after_failure(self._snapshot, before)
            raise

        if after != before:
            _fail(M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_CHANGED)
        identity = before.identity_sha256
        if any(
            item.source_identity_sha256 != identity
            for item in (perception, m3, m4, historical, acquisition, embedding)
        ):
            _fail(M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_IDENTITY_MISMATCH)
        if source_authority is not None and (
            source_authority.input_authority.source_m5_authority_root_sha256
            != embedding.source_authority_root_sha256
        ):
            _fail(M6SqliteProjectionAssemblyErrorCode.SOURCE_AUTHORITY_INVALID)
        return assemble_m6_sqlite_projection_authority(
            closure=controlled,
            perception_snapshot=perception,
            m3_snapshot=m3,
            m4_snapshot=m4,
            historical_snapshots=historical,
            acquisition_snapshot=acquisition,
            embedding_snapshot=embedding,
            source_authority=source_authority,
            gate_history_snapshot=gate_history,
            config=self._config if source_authority is not None else None,
        )

    def assemble_closed_policy_fast_predecessor(
        self,
        closure: M6ReplayInputClosureAuthority,
        *,
        ready_case: Case,
        ready_case_revision: int,
    ) -> M6ReplayLockedFastPrePolicyProjection:
        """Rebuild a Fast READY predecessor without publishing a selector closure."""

        controlled = _controlled_closure(closure)
        if type(ready_case) is not Case:
            _fail(M6SqliteProjectionAssemblyErrorCode.INVALID_ARGUMENT)
        try:
            ready_document = canonical_json(ready_case.model_dump(mode="json"))
        except (AttributeError, TypeError, ValueError, ValidationError):
            _fail(M6SqliteProjectionAssemblyErrorCode.INVALID_ARGUMENT)
        ready_case_document_sha256 = hashlib.sha256(ready_document.encode("utf-8")).hexdigest()
        if (
            self._source_authority_root is None
            or not isinstance(ready_case_revision, int)
            or isinstance(ready_case_revision, bool)
            or ready_case_revision < 1
            or controlled.source_case_revision != ready_case_revision + 1
            or controlled.source_case_document_sha256 == ready_case_document_sha256
        ):
            _fail(M6SqliteProjectionAssemblyErrorCode.INVALID_ARGUMENT)
        selector = M6ReplayInputClosureAuthority.model_validate(
            {
                **controlled.model_dump(mode="json", exclude_computed_fields=True),
                "source_case_revision": ready_case_revision,
                "source_case_document_sha256": ready_case_document_sha256,
            }
        )
        before = capture_m6_readonly_snapshot_identity(self._snapshot)
        try:
            perception = ReadonlyM6PerceptionAuthorityRepository(
                self._snapshot
            ).read_authority_snapshot(selector)
            source_case = _case_for_scoped_reads(
                selector,
                perception.source_case_canonical_document,
            )
            m3 = ReadonlyM6ModelCallAuthorityRepository(self._snapshot).load_validated_snapshot(
                source_case
            )
            source_authority = ReadonlyM6SealedSourceAuthorityRepository(
                self._snapshot,
                store_root=self._source_authority_root,
                config=self._config,
            ).load_validated_source(controlled)
            after = capture_m6_readonly_snapshot_identity(self._snapshot)
        except ReadOnlySnapshotError as error:
            if "CHANGED" in error.reason_code:
                _fail(M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_CHANGED)
            _require_unchanged_after_failure(self._snapshot, before)
            raise
        except Exception:
            _require_unchanged_after_failure(self._snapshot, before)
            raise
        if (
            after != before
            or source_case != ready_case
            or hashlib.sha256(
                canonical_json(source_case.model_dump(mode="json")).encode("utf-8")
            ).hexdigest()
            != ready_case_document_sha256
            or perception.source_identity_sha256 != before.identity_sha256
            or m3.source_identity_sha256 != before.identity_sha256
            or source_authority.source_identity_sha256 != before.identity_sha256
        ):
            _fail(M6SqliteProjectionAssemblyErrorCode.SOURCE_AUTHORITY_INVALID)
        return assemble_m6_replay_locked_closed_policy_fast_predecessor_projection(
            catalog_closure=controlled,
            ready_case=source_case,
            ready_case_revision=ready_case_revision,
            perception_snapshot=perception,
            m3_snapshot=m3,
            source_authority=source_authority,
            config=self._config,
        )

    def assemble_closed_policy_m4_predecessor(
        self,
        closure: M6ReplayInputClosureAuthority,
        *,
        ready_case: Case,
        ready_case_revision: int,
    ) -> M6ReplayLockedM4PrePolicyProjection:
        """Join an M4 READY predecessor while publishing only the CLOSED cut."""

        controlled = _controlled_closure(closure)
        if type(ready_case) is not Case:
            _fail(M6SqliteProjectionAssemblyErrorCode.INVALID_ARGUMENT)
        try:
            ready_document = canonical_json(ready_case.model_dump(mode="json"))
        except (AttributeError, TypeError, ValueError, ValidationError):
            _fail(M6SqliteProjectionAssemblyErrorCode.INVALID_ARGUMENT)
        ready_case_document_sha256 = hashlib.sha256(ready_document.encode("utf-8")).hexdigest()
        if (
            self._source_authority_root is None
            or not isinstance(ready_case_revision, int)
            or isinstance(ready_case_revision, bool)
            or ready_case_revision < 1
            or controlled.source_case_revision != ready_case_revision + 1
            or controlled.source_case_document_sha256 == ready_case_document_sha256
        ):
            _fail(M6SqliteProjectionAssemblyErrorCode.INVALID_ARGUMENT)
        try:
            selector = M6ReplayInputClosureAuthority.model_validate(
                {
                    **controlled.model_dump(
                        mode="json",
                        exclude_computed_fields=True,
                    ),
                    "source_case_revision": ready_case_revision,
                    "source_case_document_sha256": ready_case_document_sha256,
                }
            )
        except (AttributeError, TypeError, ValueError, ValidationError):
            _fail(M6SqliteProjectionAssemblyErrorCode.INVALID_ARGUMENT)

        before = capture_m6_readonly_snapshot_identity(self._snapshot)
        try:
            closed_assembly = self.assemble(controlled)
            ready_perception = ReadonlyM6PerceptionAuthorityRepository(
                self._snapshot
            ).read_authority_snapshot(selector)
            observed_ready = _case_for_scoped_reads(
                selector,
                ready_perception.source_case_canonical_document,
            )
            hearing_record, hearing_binding = _load_m4_terminal_join(
                self._snapshot,
                closed_assembly.projection_context.case,
            )
            source_authority = ReadonlyM6SealedSourceAuthorityRepository(
                self._snapshot,
                store_root=self._source_authority_root,
                config=self._config,
            ).load_validated_source(controlled)
            review = closed_assembly.projection_context.case.procedural_reviews[0]
            gate_receipt = source_authority.receipt_for_review(review.review_id)
            after = capture_m6_readonly_snapshot_identity(self._snapshot)
        except ReadOnlySnapshotError as error:
            if "CHANGED" in error.reason_code:
                _fail(M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_CHANGED)
            _require_unchanged_after_failure(self._snapshot, before)
            raise
        except Exception:
            _require_unchanged_after_failure(self._snapshot, before)
            raise
        if (
            after != before
            or observed_ready != ready_case
            or canonical_json(observed_ready.model_dump(mode="json")) != ready_document
            or closed_assembly.source_identity_sha256 != before.identity_sha256
            or ready_perception.source_identity_sha256 != before.identity_sha256
            or source_authority.source_identity_sha256 != before.identity_sha256
        ):
            _fail(M6SqliteProjectionAssemblyErrorCode.SOURCE_AUTHORITY_INVALID)
        return assemble_m6_replay_locked_closed_policy_m4_predecessor_projection(
            catalog_closure=controlled,
            closed_projection_assembly=closed_assembly,
            ready_case=observed_ready,
            ready_case_revision=ready_case_revision,
            hearing_record=hearing_record,
            hearing_verdict_binding=hearing_binding,
            gate_current_closure_receipt=gate_receipt,
        )

    def assemble_fast_terminal(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedFastTerminalSource:
        """Load only the sealed M3 post-parse graph required by the first route."""

        controlled = _controlled_closure(closure)
        if self._source_authority_root is None:
            _fail(M6SqliteProjectionAssemblyErrorCode.CURRENT_CLOSURE_AUTHORITY_MISSING)
        before = capture_m6_readonly_snapshot_identity(self._snapshot)
        try:
            perception = ReadonlyM6PerceptionAuthorityRepository(
                self._snapshot
            ).read_authority_snapshot(controlled)
            source_case = _case_for_scoped_reads(
                controlled,
                perception.source_case_canonical_document,
            )
            m3 = ReadonlyM6ModelCallAuthorityRepository(self._snapshot).load_validated_snapshot(
                source_case
            )
            source_authority = ReadonlyM6SealedSourceAuthorityRepository(
                self._snapshot,
                store_root=self._source_authority_root,
                config=self._config,
            ).load_validated_source(controlled)
            after = capture_m6_readonly_snapshot_identity(self._snapshot)
        except ReadOnlySnapshotError as error:
            if "CHANGED" in error.reason_code:
                _fail(M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_CHANGED)
            _require_unchanged_after_failure(self._snapshot, before)
            raise
        except Exception:
            _require_unchanged_after_failure(self._snapshot, before)
            raise
        if after != before:
            _fail(M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_CHANGED)
        if (
            perception.source_identity_sha256 != before.identity_sha256
            or m3.source_identity_sha256 != before.identity_sha256
            or source_authority.source_identity_sha256 != before.identity_sha256
        ):
            _fail(M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_IDENTITY_MISMATCH)
        return assemble_m6_replay_locked_fast_terminal_source(
            closure=controlled,
            perception_snapshot=perception,
            m3_snapshot=m3,
            source_authority=source_authority,
            config=self._config,
        )

    def assemble_m4_gate_terminal(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedM4GateTerminalSource:
        """Join one exact HearingRecord, Verdict binding, and Gate receipt."""

        controlled = _controlled_closure(closure)
        if self._source_authority_root is None:
            _fail(M6SqliteProjectionAssemblyErrorCode.CURRENT_CLOSURE_AUTHORITY_MISSING)
        before = capture_m6_readonly_snapshot_identity(self._snapshot)
        try:
            assembly = self.assemble(controlled)
            case = assembly.projection_context.case
            hearing_record, hearing_binding = _load_m4_terminal_join(
                self._snapshot,
                case,
            )
            review = case.procedural_reviews[0]
            source_authority = ReadonlyM6SealedSourceAuthorityRepository(
                self._snapshot,
                store_root=self._source_authority_root,
                config=self._config,
            ).load_validated_source(controlled)
            receipt = source_authority.receipt_for_review(review.review_id)
            after = capture_m6_readonly_snapshot_identity(self._snapshot)
        except ReadOnlySnapshotError as error:
            if "CHANGED" in error.reason_code:
                _fail(M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_CHANGED)
            _require_unchanged_after_failure(self._snapshot, before)
            raise
        except Exception:
            _require_unchanged_after_failure(self._snapshot, before)
            raise
        if (
            after != before
            or assembly.source_identity_sha256 != before.identity_sha256
            or source_authority.source_identity_sha256 != before.identity_sha256
        ):
            _fail(M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_CHANGED)
        return narrow_m6_replay_locked_m4_gate_terminal_source(
            projection_assembly=assembly,
            hearing_record=hearing_record,
            hearing_verdict_binding=hearing_binding,
            gate_current_closure_receipt=receipt,
        )


__all__ = ["ReadonlyM6SqliteProjectionAssemblyRepository"]

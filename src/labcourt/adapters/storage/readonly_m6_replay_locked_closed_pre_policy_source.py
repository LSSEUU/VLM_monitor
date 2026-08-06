"""Read one immutable CLOSED cut and expose its candidate-safe READY source."""

from __future__ import annotations

import sqlite3
from enum import StrEnum
from pathlib import Path
from typing import NoReturn

from pydantic import ValidationError

from labcourt.application.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPrePolicySourceError,
    build_m6_replay_locked_closed_policy_pre_policy_source,
)
from labcourt.application.m6_replay_locked_fast_source import (
    M6ReplayLockedFastPrePolicyProjection,
)
from labcourt.application.m6_replay_locked_m4_source import (
    M6ReplayLockedM4PrePolicyProjection,
)
from labcourt.application.m6_replay_locked_policy_source import (
    M6ReplayLockedPolicySourceBuildError,
    build_m6_replay_locked_alert_policy_causal_cut,
)
from labcourt.application.m6_verified_projection_context import (
    M6SqliteProjectionAssemblyError,
    M6SqliteProjectionAssemblyErrorCode,
)
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicySourceBindingAuthority,
)
from labcourt.contracts.m6_replay_locked_execution import M6ReplayLockedExecutionRoute
from labcourt.domain.m6_semantic_projection import (
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPolicyFastPrePolicySource,
    M6ReplayLockedClosedPolicyM4PrePolicySource,
    M6ReplayLockedClosedPolicyPrePolicySource,
)

from ._m6_snapshot_identity import capture_m6_readonly_snapshot_identity
from .readonly_m6_projection_context import (
    ReadonlyM6SqliteProjectionAssemblyRepository,
)
from .readonly_m6_replay_locked_policy_source import (
    M6ReplayLockedPolicySourceReadError,
    M6ReplayLockedPolicySourceReadErrorCode,
    ReadonlyM6ReplayLockedAlertPolicySourceRepository,
)
from .readonly_sqlite import ReadOnlySnapshotError


class M6ReplayLockedClosedPrePolicySourceReadErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    UNSUPPORTED_ROUTE = "UNSUPPORTED_ROUTE"
    SNAPSHOT_CHANGED = "SNAPSHOT_CHANGED"
    SOURCE_CUT_REJECTED = "SOURCE_CUT_REJECTED"
    DATABASE_INVALID = "DATABASE_INVALID"
    PRODUCER_INVARIANT_VIOLATION = "PRODUCER_INVARIANT_VIOLATION"


class M6ReplayLockedClosedPrePolicySourceReadError(LabCourtError):
    """Payload-free failure while rebasing one immutable CLOSED source."""

    def __init__(
        self,
        code: M6ReplayLockedClosedPrePolicySourceReadErrorCode,
    ) -> None:
        if not isinstance(code, M6ReplayLockedClosedPrePolicySourceReadErrorCode):
            raise TypeError("code must be an M6 CLOSED pre-policy source read code")
        self.code = code
        super().__init__(f"M6 CLOSED pre-policy source read failed: {code.value}")


def _error(
    code: M6ReplayLockedClosedPrePolicySourceReadErrorCode,
) -> M6ReplayLockedClosedPrePolicySourceReadError:
    return M6ReplayLockedClosedPrePolicySourceReadError(code)


def _fail(code: M6ReplayLockedClosedPrePolicySourceReadErrorCode) -> NoReturn:
    raise _error(code) from None


def _controlled_closure(value: object) -> M6ReplayInputClosureAuthority:
    if type(value) is not M6ReplayInputClosureAuthority:
        _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.INVALID_ARGUMENT)
    try:
        controlled = M6ReplayInputClosureAuthority.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.INVALID_ARGUMENT)
    return controlled


def _controlled_binding(
    value: object,
) -> M6ReplayLockedClosedPolicySourceBindingAuthority:
    if type(value) is not M6ReplayLockedClosedPolicySourceBindingAuthority:
        _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.INVALID_ARGUMENT)
    try:
        controlled = M6ReplayLockedClosedPolicySourceBindingAuthority.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.INVALID_ARGUMENT)
    return controlled


def _map_policy_read(error: M6ReplayLockedPolicySourceReadError) -> NoReturn:
    if error.code == M6ReplayLockedPolicySourceReadErrorCode.INVALID_ARGUMENT:
        _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.INVALID_ARGUMENT)
    if error.code == M6ReplayLockedPolicySourceReadErrorCode.SNAPSHOT_CHANGED:
        _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.SNAPSHOT_CHANGED)
    if error.code == M6ReplayLockedPolicySourceReadErrorCode.DATABASE_INVALID:
        _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.DATABASE_INVALID)
    _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.SOURCE_CUT_REJECTED)


class ReadonlyM6ReplayLockedClosedPolicyPrePolicySourceRepository:
    """Join policy truth and projection only inside one immutable SQLite cut."""

    __slots__ = ("_assembly", "_policy_sources", "_snapshot")

    def __init__(
        self,
        snapshot: str | Path,
        *,
        store_root: str | Path,
        config: AppConfig,
    ) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be a fully resolved AppConfig")
        self._snapshot = Path(snapshot).absolute()
        controlled_config = AppConfig.model_validate(config.model_dump(mode="json"))
        self._policy_sources = ReadonlyM6ReplayLockedAlertPolicySourceRepository(
            self._snapshot,
            store_root=store_root,
            config=controlled_config,
        )
        self._assembly = ReadonlyM6SqliteProjectionAssemblyRepository(
            self._snapshot,
            config=controlled_config,
            source_authority_root=store_root,
        )

    def _attempt_load(
        self,
        closure: object,
        source_binding: object,
    ) -> M6ReplayLockedClosedPolicyPrePolicySource:
        controlled_closure = _controlled_closure(closure)
        binding = _controlled_binding(source_binding)
        if binding.pre_policy_route not in {
            M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,
            M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE,
        }:
            _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.UNSUPPORTED_ROUTE)
        try:
            before = capture_m6_readonly_snapshot_identity(self._snapshot)
            observation = self._policy_sources.load_alert_policy_source(controlled_closure)
            cut = build_m6_replay_locked_alert_policy_causal_cut(observation=observation)
            assembly: M6ReplayLockedFastPrePolicyProjection | M6ReplayLockedM4PrePolicyProjection
            if binding.pre_policy_route == (
                M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE
            ):
                assembly = self._assembly.assemble_closed_policy_fast_predecessor(
                    controlled_closure,
                    ready_case=cut.source_ready_case,
                    ready_case_revision=cut.source_ready_case_revision,
                )
            else:
                assembly = self._assembly.assemble_closed_policy_m4_predecessor(
                    controlled_closure,
                    ready_case=cut.source_ready_case,
                    ready_case_revision=cut.source_ready_case_revision,
                )
            after = capture_m6_readonly_snapshot_identity(self._snapshot)
        except M6ReplayLockedClosedPrePolicySourceReadError:
            raise
        except M6ReplayLockedPolicySourceReadError as error:
            _map_policy_read(error)
        except M6SqliteProjectionAssemblyError as error:
            if error.code == M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_CHANGED:
                _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.SNAPSHOT_CHANGED)
            _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.SOURCE_CUT_REJECTED)
        except M6ReplayLockedPolicySourceBuildError:
            _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.SOURCE_CUT_REJECTED)
        except ReadOnlySnapshotError:
            _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.DATABASE_INVALID)
        except (OSError, sqlite3.Error):
            _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.DATABASE_INVALID)
        except LabCourtError:
            _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.SOURCE_CUT_REJECTED)
        except (AttributeError, KeyError, TypeError, ValueError, ValidationError):
            _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.PRODUCER_INVARIANT_VIOLATION)
        if (
            after != before
            or observation.source_identity_sha256 != before.identity_sha256
            or assembly.source_identity_sha256 != before.identity_sha256
            or observation.replay_input_closure != controlled_closure
            or assembly.projection_context.case != cut.source_ready_case
            or assembly.source_snapshot.source_case_revision != cut.source_ready_case_revision
            or assembly.source_snapshot.source_case_document_sha256
            != cut.source_ready_case_content_sha256
        ):
            _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.SNAPSHOT_CHANGED)
        try:
            ready_context = assembly.projection_context
            closed_context = M6VerifiedProjectionContext(
                case=cut.source_closed_case,
                perception=ready_context.perception,
                historical_source_run_id=ready_context.historical_source_run_id,
                historical_source_case_id=ready_context.historical_source_case_id,
                historical_source_manifest_id=(ready_context.historical_source_manifest_id),
                model_reference_authority=(ready_context.model_reference_authority),
                procedural_gate_authority=(ready_context.procedural_gate_authority),
                model_responses=ready_context.model_responses,
                retrieval_cycles=ready_context.retrieval_cycles,
                acquisitions=ready_context.acquisitions,
            )
            closed_snapshot = build_m6_case_replay_snapshot(
                context=closed_context,
                sample_id=controlled_closure.sample_id,
                source_case_revision=cut.source_closed_case_revision,
            )
            if (
                closed_snapshot.source_case_document_sha256
                != controlled_closure.source_case_document_sha256
                or closed_snapshot.source_case_revision != controlled_closure.source_case_revision
            ):
                _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.SOURCE_CUT_REJECTED)
            m4_projection = (
                assembly if type(assembly) is M6ReplayLockedM4PrePolicyProjection else None
            )
            source = build_m6_replay_locked_closed_policy_pre_policy_source(
                source_binding=binding,
                policy_causal_cut=cut,
                catalog_closure=controlled_closure,
                closed_projection_context=closed_context,
                hearing_record=(
                    m4_projection.hearing_record if m4_projection is not None else None
                ),
                hearing_verdict_binding=(
                    m4_projection.hearing_verdict_binding if m4_projection is not None else None
                ),
                gate_current_closure_receipt=(
                    m4_projection.gate_current_closure_receipt
                    if m4_projection is not None
                    else None
                ),
            )
        except M6ReplayLockedClosedPrePolicySourceError:
            _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.SOURCE_CUT_REJECTED)
        if (
            binding.pre_policy_route == (M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE)
            and type(source) is not M6ReplayLockedClosedPolicyFastPrePolicySource
        ):
            _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.UNSUPPORTED_ROUTE)
        if (
            binding.pre_policy_route
            == (M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE)
            and type(source) is not M6ReplayLockedClosedPolicyM4PrePolicySource
        ):
            _fail(M6ReplayLockedClosedPrePolicySourceReadErrorCode.UNSUPPORTED_ROUTE)
        return source

    def load_closed_policy_pre_policy_source(
        self,
        closure: M6ReplayInputClosureAuthority,
        source_binding: M6ReplayLockedClosedPolicySourceBindingAuthority,
    ) -> M6ReplayLockedClosedPolicyPrePolicySource:
        """Load through a fresh failure frame retaining no evaluator authority."""

        failure = M6ReplayLockedClosedPrePolicySourceReadErrorCode.PRODUCER_INVARIANT_VIOLATION
        try:
            return self._attempt_load(closure, source_binding)
        except M6ReplayLockedClosedPrePolicySourceReadError as error:
            failure = error.code
        except Exception:
            failure = M6ReplayLockedClosedPrePolicySourceReadErrorCode.PRODUCER_INVARIANT_VIOLATION
        del self, closure, source_binding
        raise _error(failure) from None


__all__ = [
    "M6ReplayLockedClosedPrePolicySourceReadError",
    "M6ReplayLockedClosedPrePolicySourceReadErrorCode",
    "ReadonlyM6ReplayLockedClosedPolicyPrePolicySourceRepository",
]

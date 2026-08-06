"""Resolve one sealed M6 CLOSED policy source from an immutable SQLite cut."""

from __future__ import annotations

import sqlite3
from enum import StrEnum
from pathlib import Path
from typing import NoReturn

from pydantic import ValidationError

from labcourt.application.m6_source_authority import (
    M6SourceAuthorityError,
    assemble_m6_validated_source_authority,
)
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_policy import (
    MAX_M6_REPLAY_LOCKED_COOLDOWN_HISTORY_ENTRIES,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_replay_locked_policy_source import (
    M6ReplayLockedAlertPolicySourceObservation,
    M6ReplayLockedCooldownHistoryRowObservation,
)

from ._m6_snapshot_identity import capture_m6_readonly_snapshot_identity
from .m6_source_authority_store import (
    M6SourceAuthorityStoreError,
    ReadonlyM6SourceAuthorityStore,
)
from .readonly_m5_artifacts import (
    M5AlertPolicyCausalSource,
    M5AlertPolicyCooldownHistorySource,
    M5ArtifactAuthoritySnapshot,
    M5AuthorityBudgetExceeded,
    ReadonlyM5ArtifactRepository,
)
from .readonly_m6_regression_source_scope import (
    M6RegressionSourceScopeReadError,
    M6RegressionSourceScopeReadErrorCode,
    ReadonlyM6RegressionSourceScopeRepository,
)
from .readonly_sqlite import ReadOnlySnapshotError


class M6ReplayLockedPolicySourceReadErrorCode(StrEnum):
    """Closed public reasons without paths, SQL, or source authority payloads."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SOURCE_SEAL_INVALID = "SOURCE_SEAL_INVALID"
    SNAPSHOT_CHANGED = "SNAPSHOT_CHANGED"
    DATABASE_INVALID = "DATABASE_INVALID"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    M5_AUTHORITY_INVALID = "M5_AUTHORITY_INVALID"
    SOURCE_SCOPE_MISMATCH = "SOURCE_SCOPE_MISMATCH"
    POLICY_CAUSAL_CUT_UNAVAILABLE = "POLICY_CAUSAL_CUT_UNAVAILABLE"
    PRODUCER_INVARIANT_VIOLATION = "PRODUCER_INVARIANT_VIOLATION"


class M6ReplayLockedPolicySourceReadError(LabCourtError):
    """A sealed source could not yield one exact alert-policy replay cut."""

    def __init__(self, code: M6ReplayLockedPolicySourceReadErrorCode) -> None:
        if not isinstance(code, M6ReplayLockedPolicySourceReadErrorCode):
            raise TypeError("code must be an M6ReplayLockedPolicySourceReadErrorCode")
        self.code = code
        super().__init__(f"M6 locked policy source read failed: {code.value}")


def _fail(code: M6ReplayLockedPolicySourceReadErrorCode) -> NoReturn:
    raise M6ReplayLockedPolicySourceReadError(code) from None


def _error(
    code: M6ReplayLockedPolicySourceReadErrorCode,
) -> M6ReplayLockedPolicySourceReadError:
    return M6ReplayLockedPolicySourceReadError(code)


def _controlled_closure(value: object) -> M6ReplayInputClosureAuthority:
    if type(value) is not M6ReplayInputClosureAuthority:
        _fail(M6ReplayLockedPolicySourceReadErrorCode.INVALID_ARGUMENT)
    try:
        controlled = M6ReplayInputClosureAuthority.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedPolicySourceReadErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedPolicySourceReadErrorCode.INVALID_ARGUMENT)
    return controlled


def _map_scope_error(error: M6RegressionSourceScopeReadError) -> NoReturn:
    if error.code == M6RegressionSourceScopeReadErrorCode.INVALID_ARGUMENT:
        _fail(M6ReplayLockedPolicySourceReadErrorCode.INVALID_ARGUMENT)
    if error.code == M6RegressionSourceScopeReadErrorCode.SNAPSHOT_CHANGED:
        _fail(M6ReplayLockedPolicySourceReadErrorCode.SNAPSHOT_CHANGED)
    if error.code == M6RegressionSourceScopeReadErrorCode.BUDGET_EXCEEDED:
        _fail(M6ReplayLockedPolicySourceReadErrorCode.BUDGET_EXCEEDED)
    if error.code in {
        M6RegressionSourceScopeReadErrorCode.DATABASE_INVALID,
        M6RegressionSourceScopeReadErrorCode.RUN_NOT_FOUND,
    }:
        _fail(M6ReplayLockedPolicySourceReadErrorCode.DATABASE_INVALID)
    if error.code in {
        M6RegressionSourceScopeReadErrorCode.M5_AUTHORITY_INVALID,
        M6RegressionSourceScopeReadErrorCode.M5_REPORT_INVALID,
        M6RegressionSourceScopeReadErrorCode.AUDIT_CHAIN_INVALID,
    }:
        _fail(M6ReplayLockedPolicySourceReadErrorCode.M5_AUTHORITY_INVALID)
    _fail(M6ReplayLockedPolicySourceReadErrorCode.SOURCE_SCOPE_MISMATCH)


def _require_exact_scope(
    *,
    closure: M6ReplayInputClosureAuthority,
    stored: object,
    validated_source_identity_sha256: str,
    scope: object,
    snapshot: M5ArtifactAuthoritySnapshot,
    source_identity_sha256: str,
) -> None:
    from labcourt.adapters.storage.m6_source_authority_store import (
        M6StoredSourceAuthorityBundle,
    )
    from labcourt.ports.m6_regression_dataset import M6RegressionRunScopeObservation

    if (
        type(stored) is not M6StoredSourceAuthorityBundle
        or type(scope) is not M6RegressionRunScopeObservation
    ):
        _fail(M6ReplayLockedPolicySourceReadErrorCode.PRODUCER_INVARIANT_VIOLATION)
    if (
        closure.source_case_id is None
        or closure.source_case_revision is None
        or closure.source_case_document_sha256 is None
    ):
        _fail(M6ReplayLockedPolicySourceReadErrorCode.SOURCE_SCOPE_MISMATCH)
    required = tuple(
        item
        for item in scope.required_sources
        if item.source_run_id == closure.source_run_id
        and item.source_case_id == closure.source_case_id
        and item.source_case_revision == closure.source_case_revision
        and item.source_case_document_sha256 == closure.source_case_document_sha256
        and item.source_manifest_id == closure.source_manifest_id
    )
    seal = stored.seal
    report = stored.source_validation_report
    if (
        len(required) != 1
        or validated_source_identity_sha256 != source_identity_sha256
        or scope.source_identity_sha256 != source_identity_sha256
        or scope.source_run_id != closure.source_run_id
        or scope.audit_head_sequence != seal.audit_head_sequence
        or scope.audit_head_hash != seal.audit_head_hash
        or scope.m5_validation_report != report
        or scope.m5_validation_report_document != stored.source_validation_report_document
        or report.authority_root_sha256 != snapshot.authority_root_sha256
        or seal.source_m5_authority_root_sha256 != snapshot.authority_root_sha256
        or snapshot.failures
        or snapshot.run_id != closure.source_run_id
        or snapshot.manifest_id != closure.source_manifest_id
        or snapshot.config_sha256 != report.config_sha256
    ):
        _fail(M6ReplayLockedPolicySourceReadErrorCode.SOURCE_SCOPE_MISMATCH)


def _eligible_cooldown_history(
    *,
    snapshot: M5ArtifactAuthoritySnapshot,
    causal_source: M5AlertPolicyCausalSource,
) -> tuple[M5AlertPolicyCooldownHistorySource, ...]:
    count = causal_source.cooldown_eligible_history_count
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        _fail(M6ReplayLockedPolicySourceReadErrorCode.PRODUCER_INVARIANT_VIOLATION)
    if count > MAX_M6_REPLAY_LOCKED_COOLDOWN_HISTORY_ENTRIES:
        _fail(M6ReplayLockedPolicySourceReadErrorCode.BUDGET_EXCEEDED)
    key_id = causal_source.cooldown_history_key_id
    if key_id is None:
        if count != 0:
            _fail(M6ReplayLockedPolicySourceReadErrorCode.M5_AUTHORITY_INVALID)
        return ()
    matches = tuple(
        item for item in snapshot.alert_policy_cooldown_history_inventories if item.key_id == key_id
    )
    if len(matches) != 1 or count > len(matches[0].rows):
        _fail(M6ReplayLockedPolicySourceReadErrorCode.M5_AUTHORITY_INVALID)
    return matches[0].rows[:count]


class ReadonlyM6ReplayLockedAlertPolicySourceRepository:
    """Load a single closure-scoped policy source without discovering alternatives."""

    __slots__ = ("_config", "_snapshot", "_store")

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
        self._store = ReadonlyM6SourceAuthorityStore(store_root)
        self._config = AppConfig.model_validate(config.model_dump(mode="json"))

    def _attempt_load_alert_policy_source(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedAlertPolicySourceObservation:
        controlled = _controlled_closure(closure)
        try:
            before = capture_m6_readonly_snapshot_identity(self._snapshot)
            stored = self._store.load(controlled)
            validated = assemble_m6_validated_source_authority(
                closure=controlled,
                snapshot=stored.to_source_snapshot(before.identity_sha256),
                config=self._config,
            )
            if capture_m6_readonly_snapshot_identity(self._snapshot) != before:
                _fail(M6ReplayLockedPolicySourceReadErrorCode.SNAPSHOT_CHANGED)
            try:
                scope = ReadonlyM6RegressionSourceScopeRepository(
                    self._snapshot,
                    config=self._config,
                ).observe(
                    controlled.source_run_id,
                    m5_validation_report=stored.source_validation_report,
                    m5_validation_report_document=stored.source_validation_report_document,
                )
            except M6RegressionSourceScopeReadError as error:
                _map_scope_error(error)
            snapshot = ReadonlyM5ArtifactRepository(
                self._snapshot,
                config=self._config,
                immutable=True,
            ).scan(controlled.source_run_id)
            _require_exact_scope(
                closure=controlled,
                stored=stored,
                validated_source_identity_sha256=validated.source_identity_sha256,
                scope=scope,
                snapshot=snapshot,
                source_identity_sha256=before.identity_sha256,
            )
            matches = tuple(
                item
                for item in snapshot.alert_policy_causal_sources
                if item.closing_case.run_id == controlled.source_run_id
                and item.closing_case.case_id == controlled.source_case_id
                and item.closing_case_revision == controlled.source_case_revision
                and item.closing_case_document_sha256 == controlled.source_case_document_sha256
            )
            if len(matches) != 1:
                _fail(M6ReplayLockedPolicySourceReadErrorCode.POLICY_CAUSAL_CUT_UNAVAILABLE)
            causal_source = matches[0]
            if (
                causal_source.closing_case != validated.source_case
                or causal_source.closing_case_canonical_document != stored.source_case_document
                or causal_source.alert_policy.request.config_sha256 != self._config.config_sha256
            ):
                _fail(M6ReplayLockedPolicySourceReadErrorCode.SOURCE_SCOPE_MISMATCH)
            eligible_history = _eligible_cooldown_history(
                snapshot=snapshot,
                causal_source=causal_source,
            )
            history = tuple(
                M6ReplayLockedCooldownHistoryRowObservation(
                    source_identity_sha256=before.identity_sha256,
                    revision=item.revision,
                    writer_close_audit_sequence=item.writer_close_audit_sequence,
                    writer_close_audit_entry_hash=item.writer_close_audit_entry_hash,
                    writer_alert_policy_authority_id=(item.writer_alert_policy_authority_id),
                    authority=item.authority,
                    authority_canonical_document=item.authority_canonical_document,
                )
                for item in eligible_history
            )
            observation = M6ReplayLockedAlertPolicySourceObservation(
                source_identity_sha256=before.identity_sha256,
                replay_input_closure=stored.replay_input_closure,
                replay_input_closure_canonical_document=(stored.replay_input_closure_document),
                source_validation_report=stored.source_validation_report,
                source_validation_report_canonical_document=(
                    stored.source_validation_report_document
                ),
                source_m5_authority_root_sha256=snapshot.authority_root_sha256,
                source_ready_case_revision=causal_source.source_case_revision,
                source_ready_case=causal_source.source_case,
                source_ready_case_canonical_document=(causal_source.source_case_canonical_document),
                source_closed_case_revision=causal_source.closing_case_revision,
                source_closed_case=causal_source.closing_case,
                source_closed_case_canonical_document=(
                    causal_source.closing_case_canonical_document
                ),
                source_alert_policy=causal_source.alert_policy,
                source_alert_policy_canonical_document=(
                    causal_source.alert_policy_canonical_document
                ),
                closing_audit_entry=causal_source.closing_audit_entry,
                closing_audit_entry_canonical_document=(
                    causal_source.closing_audit_entry_canonical_document
                ),
                cooldown_eligible_history_rows=history,
            )
            after = capture_m6_readonly_snapshot_identity(self._snapshot)
        except M6ReplayLockedPolicySourceReadError:
            raise
        except (M6SourceAuthorityStoreError, M6SourceAuthorityError):
            _fail(M6ReplayLockedPolicySourceReadErrorCode.SOURCE_SEAL_INVALID)
        except M5AuthorityBudgetExceeded:
            _fail(M6ReplayLockedPolicySourceReadErrorCode.BUDGET_EXCEEDED)
        except ReadOnlySnapshotError:
            _fail(M6ReplayLockedPolicySourceReadErrorCode.DATABASE_INVALID)
        except (sqlite3.Error, OSError, ValidationError):
            _fail(M6ReplayLockedPolicySourceReadErrorCode.DATABASE_INVALID)
        except (AttributeError, KeyError, TypeError, ValueError):
            _fail(M6ReplayLockedPolicySourceReadErrorCode.PRODUCER_INVARIANT_VIOLATION)
        if after != before:
            _fail(M6ReplayLockedPolicySourceReadErrorCode.SNAPSHOT_CHANGED)
        return observation

    def load_alert_policy_source(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedAlertPolicySourceObservation:
        """Load through a fresh public failure frame retaining no source authority."""

        failure = M6ReplayLockedPolicySourceReadErrorCode.PRODUCER_INVARIANT_VIOLATION
        try:
            return self._attempt_load_alert_policy_source(closure)
        except M6ReplayLockedPolicySourceReadError as error:
            failure = error.code
        except Exception:
            pass
        del self, closure
        raise _error(failure) from None


__all__ = [
    "M6ReplayLockedPolicySourceReadError",
    "M6ReplayLockedPolicySourceReadErrorCode",
    "ReadonlyM6ReplayLockedAlertPolicySourceRepository",
]

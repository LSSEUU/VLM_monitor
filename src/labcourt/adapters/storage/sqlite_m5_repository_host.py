"""Static host surface shared by behavior-only M5 repository mixins."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import sqlite3
    from collections.abc import Callable
    from datetime import datetime
    from typing import Protocol

    from labcourt.contracts.alert_policy import AlertChannelCapabilityAuthority
    from labcourt.contracts.audit import AuditEntry
    from labcourt.contracts.cases import Case
    from labcourt.contracts.enums import AuditAction
    from labcourt.contracts.m5_appeals import PrecedentRevocationIntent
    from labcourt.contracts.m5_precedent_usage import (
        M5PrecedentApplicationBatchAuthority,
        M5PrecedentApplicationCitationCommit,
    )
    from labcourt.contracts.m5_precedents import (
        M5PrecedentAuthority,
        M5PrecedentCitationCommit,
        M5PrecedentCitationSnapshot,
        M5PrecedentRevocationReceipt,
        M5PrecedentRevocationResult,
    )
    from labcourt.contracts.manifests import RunManifest
    from labcourt.contracts.storage import ArtifactRef
    from labcourt.ports.alert_policy import AlertPolicyVerifier, AutomaticPrecedentVerifier
    from labcourt.ports.dataset_export import (
        M5DatasetArtifactVerifier,
        M5TrainingCropVerifier,
    )
    from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot
    from labcourt.ports.m5_precedent_policy import M5PrecedentPolicyVerifier
    from labcourt.ports.m5_precedent_usage import (
        M5PrecedentApplicationVerifier,
        M5ReadyPrecedentUsage,
    )

    from .sqlite_m3_repository_host import SQLiteM3RepositoryHost

    class SQLiteM5RepositoryHost(SQLiteM3RepositoryHost, Protocol):
        _alert_policy_verifier: AlertPolicyVerifier | None
        _automatic_precedent_verifier: AutomaticPrecedentVerifier | None
        _alert_channel_capability: AlertChannelCapabilityAuthority | None
        _m5_precedent_policy_verifier: M5PrecedentPolicyVerifier | None
        _m5_precedent_application_verifier: M5PrecedentApplicationVerifier | None
        _training_crop_verifier: M5TrainingCropVerifier | None
        _dataset_artifact_verifier: M5DatasetArtifactVerifier | None
        _fault_injector: Callable[[str], None] | None

        def _m5_fault(self, phase: str) -> None: ...

        def _load_run_manifest(
            self,
            connection: sqlite3.Connection,
            run_id: str,
        ) -> RunManifest: ...

        def _load_m5_precedent_authority(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            precedent_id: str,
        ) -> M5PrecedentAuthority | None: ...

        def _m5_authority_from_row(
            self,
            connection: sqlite3.Connection,
            row: sqlite3.Row,
        ) -> M5PrecedentAuthority: ...

        def _load_m5_precedent_revision(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            precedent_id: str,
            revision: int,
        ) -> M5PrecedentAuthority | None: ...

        def _insert_m5_precedent_authority(
            self,
            connection: sqlite3.Connection,
            authority: M5PrecedentAuthority,
            expected_revision: int | None,
            *,
            causal_fault_scope: str,
        ) -> M5PrecedentAuthority: ...

        def _commit_m5_appeal_revocation(
            self,
            connection: sqlite3.Connection,
            *,
            run_id: str,
            intent: PrecedentRevocationIntent,
            revoked_by_ref: str,
            revoked_at: datetime,
        ) -> M5PrecedentRevocationResult: ...

        def _find_revocation_by_prior(
            self,
            connection: sqlite3.Connection,
            *,
            run_id: str,
            precedent_id: str,
            prior_authority_id: str,
        ) -> tuple[M5PrecedentRevocationReceipt, M5PrecedentCitationSnapshot] | None: ...

        def _citation_commit_from_row(
            self,
            connection: sqlite3.Connection,
            row: sqlite3.Row,
        ) -> M5PrecedentCitationCommit | M5PrecedentApplicationCitationCommit: ...

        def _application_batch_from_row(
            self,
            connection: sqlite3.Connection,
            row: sqlite3.Row,
        ) -> M5PrecedentApplicationBatchAuthority: ...

        def _resolve_ready_precedent_usage_in_connection(
            self,
            connection: sqlite3.Connection,
            snapshot: CaseSnapshot,
        ) -> M5ReadyPrecedentUsage: ...

        @staticmethod
        def _validated_application_batch(
            batch: M5PrecedentApplicationBatchAuthority | None,
        ) -> M5PrecedentApplicationBatchAuthority | None: ...

        @staticmethod
        def _validated_application_citations(
            commits: tuple[M5PrecedentApplicationCitationCommit, ...],
        ) -> tuple[M5PrecedentApplicationCitationCommit, ...]: ...

        def _require_rebuilt_application_roots(
            self,
            *,
            snapshot: CaseSnapshot,
            usage: M5ReadyPrecedentUsage,
            proposed_batch: M5PrecedentApplicationBatchAuthority | None,
            proposed_citations: tuple[M5PrecedentApplicationCitationCommit, ...],
            cited_at: datetime,
        ) -> tuple[
            M5PrecedentApplicationBatchAuthority | None,
            tuple[M5PrecedentApplicationCitationCommit, ...],
        ]: ...

        @staticmethod
        def _require_application_roots_absent(
            connection: sqlite3.Connection,
            *,
            run_id: str,
            case_id: str,
        ) -> None: ...

        def _insert_application_roots(
            self,
            connection: sqlite3.Connection,
            *,
            batch: M5PrecedentApplicationBatchAuthority | None,
            citations: tuple[M5PrecedentApplicationCitationCommit, ...],
            closing_case_revision: int,
        ) -> None: ...

        def _require_stored_application_roots(
            self,
            connection: sqlite3.Connection,
            *,
            run_id: str,
            case_id: str,
            expected_batch: M5PrecedentApplicationBatchAuthority | None,
            expected_citations: tuple[M5PrecedentApplicationCitationCommit, ...],
            closing_case_revision: int,
        ) -> None: ...

        def _append_m5_audit(
            self,
            connection: sqlite3.Connection,
            head: AuditHead,
            *,
            action: AuditAction,
            object_ref: ArtifactRef,
            before_sha256: str,
            after_sha256: str,
        ) -> AuditEntry: ...

        def _commit_m5_case_version(
            self,
            connection: sqlite3.Connection,
            *,
            previous: CaseSnapshot,
            new_case: Case,
            expected_head: AuditHead,
            action: AuditAction,
            object_ref: ArtifactRef,
        ) -> CaseSnapshot: ...

else:

    class SQLiteM5RepositoryHost:
        """Runtime-empty base; implementations are composed by the public facade."""


__all__ = ["SQLiteM5RepositoryHost"]

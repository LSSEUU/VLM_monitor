from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.application.alert_policy_verifier import ConfiguredAlertPolicyVerifier
from labcourt.application.m5_finalization import (
    M5FinalizationCoordinator,
    M5FinalizationError,
    M5FinalizationErrorCode,
)
from labcourt.config_loader import load_config
from labcourt.contracts.alert_policy import (
    AlertCooldownAuthority,
    AlertCooldownKey,
    AlertPolicyAuthority,
    ImmediateSafetyDeliveryAuthority,
)
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.enums import AuditAction, CaseStatus, PrecedentStatus
from labcourt.contracts.m5_precedent_usage import (
    M5PrecedentApplicationBatchAuthority,
    M5PrecedentApplicationCitationCommit,
)
from labcourt.contracts.m5_precedents import M5PrecedentAuthority
from labcourt.ports.evidence_repository import CaseSnapshot
from labcourt.ports.m5_precedent_usage import (
    M5ReadyPrecedentUsage,
    M5ReadyPrecedentUsageKind,
)
from tests.unit.test_m5_alert_policy import _manifest_with_stream, _ready_case

ROOT = Path(__file__).parents[2]
NOW = datetime(2026, 8, 2, 12, tzinfo=UTC)


def _closed_case(case: Case, authority: AlertPolicyAuthority) -> Case:
    alert_id = authority.decision.alert_id if authority.decision is not None else "NONE"
    alerts = (*case.alerts, authority.decision) if authority.decision is not None else case.alerts
    return case.model_copy(
        update={
            "status": CaseStatus.CLOSED,
            "alerts": alerts,
            "final_decision": authority.final_decision,
            "timeline": (
                *case.timeline,
                TimelineEntry(
                    sequence=len(case.timeline),
                    action=AuditAction.CASE_CLOSED.value,
                    stage="ALERT_POLICY",
                    object_ref=(alert_id if alert_id != "NONE" else case.case_id),
                    details={
                        "alert_id": alert_id,
                        "disposition": authority.disposition.value,
                        "status": CaseStatus.CLOSED.value,
                    },
                ),
            ),
        }
    )


class _Repository:
    def __init__(self, snapshot: CaseSnapshot, *, invalid_revision: bool = False) -> None:
        self.snapshot = snapshot
        self.invalid_revision = invalid_revision
        self.cooldown_loads: list[AlertCooldownKey] = []
        self.committed_precedent: M5PrecedentAuthority | None = None

    def list_ready_cases(self, run_id: str, limit: int) -> tuple[CaseSnapshot, ...]:
        assert run_id == self.snapshot.case.run_id
        assert limit == 256
        return (self.snapshot,)

    def load_current_cooldown(
        self,
        run_id: str,
        key: AlertCooldownKey,
        stream_id: str,
        stream_authority_sha256: str,
    ) -> AlertCooldownAuthority | None:
        assert run_id == self.snapshot.case.run_id
        assert stream_id == self.snapshot.case.event.stream_id
        assert len(stream_authority_sha256) == 64
        self.cooldown_loads.append(key)
        return None

    def record_immediate_safety_delivery(
        self,
        run_id: str,
        authority: ImmediateSafetyDeliveryAuthority,
    ) -> ImmediateSafetyDeliveryAuthority:
        raise AssertionError("not used by finalization")

    def load_immediate_safety_delivery(
        self,
        run_id: str,
        incident_id: str,
    ) -> ImmediateSafetyDeliveryAuthority | None:
        raise AssertionError("not used by finalization")

    def resolve_ready_precedent_usage(
        self,
        run_id: str,
        case_id: str,
        expected_revision: int,
    ) -> M5ReadyPrecedentUsage:
        assert run_id == self.snapshot.case.run_id
        assert case_id == self.snapshot.case.case_id
        assert expected_revision == self.snapshot.revision
        return M5ReadyPrecedentUsage(kind=M5ReadyPrecedentUsageKind.FAST)

    def commit_alert_policy(
        self,
        run_id: str,
        expected_revision: int,
        authority: AlertPolicyAuthority,
        automatic_precedent: M5PrecedentAuthority,
        application_batch: M5PrecedentApplicationBatchAuthority | None = None,
        application_citations: tuple[M5PrecedentApplicationCitationCommit, ...] = (),
    ) -> CaseSnapshot:
        assert run_id == self.snapshot.case.run_id
        assert expected_revision == self.snapshot.revision
        assert application_batch is None
        assert application_citations == ()
        self.committed_precedent = automatic_precedent
        revision = expected_revision + (2 if self.invalid_revision else 1)
        return CaseSnapshot(
            case=_closed_case(self.snapshot.case, authority),
            revision=revision,
        )


def _coordinator(repository: _Repository) -> M5FinalizationCoordinator:
    config = load_config(ROOT / "configs/demo.yaml")
    manifest = _manifest_with_stream()
    assert repository.snapshot.case.manifest_id == manifest.manifest_id
    verifier = ConfiguredAlertPolicyVerifier(config)
    return M5FinalizationCoordinator(
        repository=repository,
        verifier=verifier,
        embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
        config=config,
        manifest=manifest,
        clock=lambda: NOW,
    )


def test_finalization_closes_ready_case_with_same_transaction_precedent_intent() -> None:
    manifest = _manifest_with_stream()
    repository = _Repository(CaseSnapshot(case=_ready_case(manifest), revision=8))

    report = _coordinator(repository).finalize("run-01")

    assert report.selected_count == 1
    assert report.outcomes[0].source_revision == 8
    assert report.outcomes[0].closed_revision == 9
    assert report.outcomes[0].alert_id is not None
    assert len(repository.cooldown_loads) == 1
    assert repository.committed_precedent is not None
    assert repository.committed_precedent.precedent.status == PrecedentStatus.PROVISIONAL
    assert (
        report.outcomes[0].automatic_precedent_authority_id
        == repository.committed_precedent.authority_id
    )


def test_finalization_rejects_a_repository_result_with_nonadjacent_revision() -> None:
    manifest = _manifest_with_stream()
    repository = _Repository(
        CaseSnapshot(case=_ready_case(manifest), revision=8),
        invalid_revision=True,
    )

    with pytest.raises(M5FinalizationError) as raised:
        _coordinator(repository).finalize("run-01")

    assert raised.value.code == M5FinalizationErrorCode.COMMIT_RESULT_INVALID

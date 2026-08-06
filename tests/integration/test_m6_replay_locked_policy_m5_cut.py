from __future__ import annotations

from pathlib import Path

from labcourt.adapters.storage.readonly_m5_artifacts import ReadonlyM5ArtifactRepository
from labcourt.application.alert_policy_verifier import ConfiguredAlertPolicyVerifier
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m5_readonly_alert_automatic_closure import (
    _append_second_ready_case,
)
from tests.integration.test_m5_sqlite_alert_repository import (
    _automatic_precedent,
    _MutableClock,
    _prepare_ready_case,
)
from tests.integration.test_m5_sqlite_appeals import _prepare_closed_case


def _eligible_history(snapshot: object, source: object) -> tuple[object, ...]:
    key_id = source.cooldown_history_key_id  # type: ignore[attr-defined]
    count = source.cooldown_eligible_history_count  # type: ignore[attr-defined]
    if key_id is None:
        assert count == 0
        return ()
    matches = tuple(
        item
        for item in snapshot.alert_policy_cooldown_history_inventories  # type: ignore[attr-defined]
        if item.key_id == key_id
    )
    assert len(matches) == 1
    return matches[0].rows[:count]


def test_full_m5_scan_exports_one_exact_empty_history_policy_cut(tmp_path: Path) -> None:
    database, _repository, closed, _manifest, config, _automatic = _prepare_closed_case(tmp_path)

    snapshot = ReadonlyM5ArtifactRepository(database, config=config).scan(RUN_ID)
    matches = tuple(
        item
        for item in snapshot.alert_policy_causal_sources
        if item.closing_case.case_id == closed.case.case_id
        and item.closing_case_revision == closed.revision
    )

    assert snapshot.failures == ()
    assert len(matches) == 1
    cut = matches[0]
    assert cut.source_case_revision + 1 == cut.closing_case_revision
    assert cut.closing_case == closed.case
    assert cut.alert_policy.final_decision == closed.case.final_decision
    assert cut.closing_audit_entry.after_sha256 == cut.closing_case_document_sha256
    assert cut.cooldown_eligible_history_count == 0
    assert _eligible_history(snapshot, cut) == ()


def test_full_m5_scan_exports_only_prior_same_key_cooldowns(tmp_path: Path) -> None:
    clock = _MutableClock()
    database, evidence, repository, first_ready, manifest, config = _prepare_ready_case(
        tmp_path,
        clock=clock,
    )
    verifier = ConfiguredAlertPolicyVerifier(config)
    first_policy = verifier.rebuild(first_ready.case, manifest, None, None)
    assert first_policy.cooldown_write is not None
    first_automatic = _automatic_precedent(
        first_ready,
        manifest,
        config,
        first_policy,
        created_at=clock.value,
    )
    repository.commit_alert_policy(
        RUN_ID,
        first_ready.revision,
        first_policy,
        first_automatic,
    )

    clock.advance(seconds=1)
    second_ready = _append_second_ready_case(
        database=database,
        evidence=evidence,
        manifest=manifest,
        config=config,
        clock=clock,
    )
    second_policy = verifier.rebuild(
        second_ready.case,  # type: ignore[attr-defined]
        manifest,
        first_policy.cooldown_write,
        None,
    )
    second_automatic = _automatic_precedent(
        second_ready,  # type: ignore[arg-type]
        manifest,
        config,
        second_policy,
        created_at=clock.value,
    )
    second_closed = repository.commit_alert_policy(
        RUN_ID,
        second_ready.revision,  # type: ignore[attr-defined]
        second_policy,
        second_automatic,
    )

    snapshot = ReadonlyM5ArtifactRepository(database, config=config).scan(RUN_ID)
    matches = tuple(
        item
        for item in snapshot.alert_policy_causal_sources
        if item.closing_case.case_id == second_closed.case.case_id
        and item.closing_case_revision == second_closed.revision
    )

    assert snapshot.failures == ()
    assert len(matches) == 1
    history = _eligible_history(snapshot, matches[0])
    assert tuple(item.revision for item in history) == (1,)
    assert history[0].authority == first_policy.cooldown_write
    assert history[0].writer_alert_policy_authority_id == first_policy.authority_id
    assert history[0].writer_close_audit_sequence < (matches[0].closing_audit_entry.sequence)
    assert sum(len(item.rows) for item in snapshot.alert_policy_cooldown_history_inventories) == 1
    assert all(
        not hasattr(item, "cooldown_eligible_history")
        for item in snapshot.alert_policy_causal_sources
    )

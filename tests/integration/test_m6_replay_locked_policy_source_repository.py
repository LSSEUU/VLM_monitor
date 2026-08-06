from __future__ import annotations

import os
import traceback
from dataclasses import replace
from pathlib import Path

import pytest

import labcourt.adapters.storage.readonly_m6_replay_locked_policy_source as policy_source_module
from labcourt.adapters.storage.m6_source_authority_store import (
    M6SourceAuthorityPublisher,
    ReadonlyM6SourceAuthorityStore,
)
from labcourt.adapters.storage.readonly_m4_artifacts import ReadonlyM4ArtifactRepository
from labcourt.adapters.storage.readonly_m6_replay_locked_policy_source import (
    M6ReplayLockedPolicySourceReadError,
    M6ReplayLockedPolicySourceReadErrorCode,
    ReadonlyM6ReplayLockedAlertPolicySourceRepository,
)
from labcourt.adapters.storage.readonly_sqlite import readonly_sqlite_snapshot
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.application.alert_policy_verifier import ConfiguredAlertPolicyVerifier
from labcourt.application.m6_replay_locked_policy_source import (
    build_m6_replay_locked_alert_policy_causal_cut,
)
from labcourt.application.m6_source_authority_builder import (
    M6SealedSourceBundle,
    build_m6_sealed_source_bundle,
)
from labcourt.application.m6_source_authority_sealing import (
    seal_m6_gate_current_closures,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_replay_locked_policy import (
    M6ReplayLockedCooldownCausalBasis,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.ports.evidence_repository import CaseSnapshot
from labcourt.ports.m6_source_authority_builder import M6ReplayInputSelection
from labcourt.services.m5_artifact_validation import validate_m5_artifacts
from labcourt.services.m5_projection import rebuild_m5_projection
from tests.integration.test_m3_sqlite_repository import BUSY_TIMEOUT_MS, RUN_ID
from tests.integration.test_m5_readonly_alert_automatic_closure import (
    _append_second_ready_case,
)
from tests.integration.test_m5_sqlite_alert_repository import (
    _automatic_precedent,
    _MutableClock,
    _prepare_ready_case,
)
from tests.integration.test_m5_sqlite_appeals import _prepare_closed_case
from tests.integration.test_m6_source_authority_sealing import _CurrentCropVerifier
from tests.unit.test_m6_source_authority import _bundle
from tests.unit.test_m6_source_authority_builder import _inputs


def _publish_source(
    tmp_path: Path,
    *,
    database: Path,
    closed: CaseSnapshot,
    manifest: RunManifest,
    config: AppConfig,
    selection_override: M6ReplayInputSelection | None = None,
) -> tuple[Path, Path, M6SealedSourceBundle, AppConfig]:
    projection = tmp_path / "projection"
    rebuild_m5_projection(
        config=config,
        run_id=RUN_ID,
        database_path=database,
        workspace_root=projection,
    )
    standalone_report = validate_m5_artifacts(
        config=config,
        run_id=RUN_ID,
        database_path=database,
        workspace_root=projection,
    )
    assert standalone_report.passed

    observer = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_CurrentCropVerifier(),
    )
    gate_source = seal_m6_gate_current_closures(
        observation=observer.observe_m6_gate_source(
            RUN_ID,
            closed.case.case_id,
            closed.revision,
        )
    )
    template_selection, _gate, _manifest, template_report = _inputs(_bundle())
    template_m4 = template_report.predecessor_report
    assert template_m4 is not None
    m2_report = template_m4.m3_report.m2_report.model_copy(
        update={
            "run_id": RUN_ID,
            "manifest_id": manifest.manifest_id,
            "audit_head_sequence": gate_source.audit_head_sequence,
            "audit_head_hash": gate_source.audit_head_hash,
        }
    )
    m3_report = template_m4.m3_report.model_copy(update={"run_id": RUN_ID, "m2_report": m2_report})
    m4_authority = ReadonlyM4ArtifactRepository(database).scan(RUN_ID)
    assert m4_authority.failures == ()
    m4_report = template_m4.model_copy(
        update={
            "run_id": RUN_ID,
            "m3_report": m3_report,
            "authority_root_sha256": m4_authority.authority_root_sha256,
        }
    )
    report = M5ArtifactValidationReport.model_validate(
        standalone_report.model_copy(update={"predecessor_report": m4_report}).model_dump(
            mode="json"
        )
    )
    selection = selection_override or replace(
        template_selection,
        sample_id="m6-policy-source-sample",
        source_run_id=RUN_ID,
        source_case_id=closed.case.case_id,
        source_case_revision=closed.revision,
    )
    bundle = build_m6_sealed_source_bundle(
        selection=selection,
        gate_source=gate_source,
        source_manifest=manifest,
        source_validation_report=report,
        config=config,
    )
    source_root = tmp_path / "source-authority"
    M6SourceAuthorityPublisher(source_root).publish(bundle, config=config)
    return database, source_root, bundle, config


def _published_source(
    tmp_path: Path,
) -> tuple[Path, Path, M6SealedSourceBundle, AppConfig]:
    database, _repository, closed, manifest, config, _automatic = _prepare_closed_case(tmp_path)
    return _publish_source(
        tmp_path,
        database=database,
        closed=closed,
        manifest=manifest,
        config=config,
    )


def _published_exact_prior_source(
    tmp_path: Path,
) -> tuple[Path, Path, M6SealedSourceBundle, AppConfig, str]:
    clock = _MutableClock()
    database, evidence, repository, first_ready, manifest, config = _prepare_ready_case(
        tmp_path,
        clock=clock,
    )
    verifier = ConfiguredAlertPolicyVerifier(config)
    first_policy = verifier.rebuild(first_ready.case, manifest, None, None)
    assert first_policy.cooldown_write is not None
    repository.commit_alert_policy(
        RUN_ID,
        first_ready.revision,
        first_policy,
        _automatic_precedent(
            first_ready,
            manifest,
            config,
            first_policy,
            created_at=clock.value,
        ),
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
        second_ready.case,
        manifest,
        first_policy.cooldown_write,
        None,
    )
    second_closed = repository.commit_alert_policy(
        RUN_ID,
        second_ready.revision,
        second_policy,
        _automatic_precedent(
            second_ready,
            manifest,
            config,
            second_policy,
            created_at=clock.value,
        ),
    )
    database, source_root, bundle, config = _publish_source(
        tmp_path,
        database=database,
        closed=second_closed,
        manifest=manifest,
        config=config,
    )
    return (
        database,
        source_root,
        bundle,
        config,
        canonical_json(first_policy.cooldown_write.model_dump(mode="json")),
    )


def _assert_public_failure_has_no_authority(
    error: BaseException,
    *,
    forbidden_texts: tuple[str, ...],
) -> None:
    module_path = Path(policy_source_module.__file__).resolve()
    forbidden_names = {
        "self",
        "closure",
        "stored",
        "snapshot",
        "causal_source",
        "eligible_history",
        "history",
        "observation",
    }
    forbidden_types = {
        "Case",
        "M5ArtifactAuthoritySnapshot",
        "M6ReplayLockedAlertPolicySourceObservation",
        "M6ReplayLockedCooldownHistoryRowObservation",
        "M6StoredSourceAuthorityBundle",
    }
    pending = [error]
    observed: list[BaseException] = []
    while pending:
        current = pending.pop()
        if current in observed:
            continue
        observed.append(current)
        for linked in (current.__cause__, current.__context__):
            if linked is not None:
                pending.append(linked)
        formatted = "".join(traceback.format_exception(current))
        assert all(secret not in formatted for secret in forbidden_texts)
        current_traceback = current.__traceback__
        while current_traceback is not None:
            frame = current_traceback.tb_frame
            if Path(frame.f_code.co_filename).resolve() == module_path:
                assert forbidden_names.isdisjoint(frame.f_locals)
                for value in frame.f_locals.values():
                    assert type(value).__name__ not in forbidden_types
                    rendered = repr(value)
                    assert all(secret not in rendered for secret in forbidden_texts)
            current_traceback = current_traceback.tb_next
    assert observed == [error]
    assert error.__cause__ is None
    assert error.__context__ is None


def test_repository_resolves_real_sqlite_empty_history_cut_and_builds_authority(
    tmp_path: Path,
) -> None:
    database, source_root, bundle, config = _published_source(tmp_path)

    with readonly_sqlite_snapshot(database) as snapshot:
        observation = ReadonlyM6ReplayLockedAlertPolicySourceRepository(
            snapshot,
            store_root=source_root,
            config=config,  # type: ignore[arg-type]
        ).load_alert_policy_source(bundle.replay_input_closure)
        cut = build_m6_replay_locked_alert_policy_causal_cut(observation=observation)

    assert observation.source_closed_case == bundle.source_case
    assert observation.source_ready_case_revision + 1 == (observation.source_closed_case_revision)
    assert observation.source_alert_policy.final_decision == bundle.source_case.final_decision
    assert cut.cooldown_causal_head.basis == M6ReplayLockedCooldownCausalBasis.EMPTY_HISTORY
    assert cut.cooldown_causal_head.eligible_history == ()


def test_repository_materializes_only_the_target_exact_prior_prefix(tmp_path: Path) -> None:
    database, source_root, bundle, config, _history_document = _published_exact_prior_source(
        tmp_path
    )

    with readonly_sqlite_snapshot(database) as snapshot:
        observation = ReadonlyM6ReplayLockedAlertPolicySourceRepository(
            snapshot,
            store_root=source_root,
            config=config,
        ).load_alert_policy_source(bundle.replay_input_closure)
        cut = build_m6_replay_locked_alert_policy_causal_cut(observation=observation)

    assert len(observation.cooldown_eligible_history_rows) == 1
    assert cut.cooldown_causal_head.basis == M6ReplayLockedCooldownCausalBasis.EXACT_PRIOR
    assert cut.cooldown_causal_head.eligible_count == 1


def test_repository_rejects_history_budget_before_materializing_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, source_root, bundle, config, _history_document = _published_exact_prior_source(
        tmp_path
    )

    def forbidden_materialization(**_values: object) -> object:
        raise AssertionError("history rows must not be materialized after budget rejection")

    monkeypatch.setattr(
        policy_source_module,
        "MAX_M6_REPLAY_LOCKED_COOLDOWN_HISTORY_ENTRIES",
        0,
    )
    monkeypatch.setattr(
        policy_source_module,
        "M6ReplayLockedCooldownHistoryRowObservation",
        forbidden_materialization,
    )
    with (
        readonly_sqlite_snapshot(database) as snapshot,
        pytest.raises(M6ReplayLockedPolicySourceReadError) as raised,
    ):
        ReadonlyM6ReplayLockedAlertPolicySourceRepository(
            snapshot,
            store_root=source_root,
            config=config,
        ).load_alert_policy_source(bundle.replay_input_closure)

    assert raised.value.code == M6ReplayLockedPolicySourceReadErrorCode.BUDGET_EXCEEDED


def test_repository_public_failure_drops_paths_cases_history_and_inner_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, source_root, bundle, config, history_document = _published_exact_prior_source(
        tmp_path
    )

    with readonly_sqlite_snapshot(database) as snapshot_name:
        snapshot = Path(snapshot_name)
        original_capture = policy_source_module.capture_m6_readonly_snapshot_identity
        capture_count = 0

        def drift_on_final_capture(path: str | Path):
            nonlocal capture_count
            capture_count += 1
            identity = original_capture(path)
            if capture_count == 3:
                return replace(identity, modified_ns=identity.modified_ns + 1)
            return identity

        monkeypatch.setattr(
            policy_source_module,
            "capture_m6_readonly_snapshot_identity",
            drift_on_final_capture,
        )
        with pytest.raises(M6ReplayLockedPolicySourceReadError) as raised:
            ReadonlyM6ReplayLockedAlertPolicySourceRepository(
                snapshot,
                store_root=source_root,
                config=config,
            ).load_alert_policy_source(bundle.replay_input_closure)

    assert capture_count == 3
    assert raised.value.code == M6ReplayLockedPolicySourceReadErrorCode.SNAPSHOT_CHANGED
    _assert_public_failure_has_no_authority(
        raised.value,
        forbidden_texts=(
            str(snapshot),
            str(source_root),
            canonical_json(bundle.source_case.model_dump(mode="json")),
            canonical_json(bundle.replay_input_closure.model_dump(mode="json")),
            history_document,
        ),
    )


def test_repository_detects_snapshot_identity_change_after_seal_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, source_root, bundle, config = _published_source(tmp_path)

    with readonly_sqlite_snapshot(database) as snapshot_name:
        snapshot = Path(snapshot_name)
        original = ReadonlyM6SourceAuthorityStore.load

        def touch_after_load(
            store: ReadonlyM6SourceAuthorityStore,
            closure: object,
        ):  # type: ignore[no-untyped-def]
            stored = original(store, closure)  # type: ignore[arg-type]
            stat = snapshot.stat()
            os.utime(snapshot, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))
            return stored

        monkeypatch.setattr(ReadonlyM6SourceAuthorityStore, "load", touch_after_load)
        with pytest.raises(M6ReplayLockedPolicySourceReadError) as raised:
            ReadonlyM6ReplayLockedAlertPolicySourceRepository(
                snapshot,
                store_root=source_root,
                config=config,  # type: ignore[arg-type]
            ).load_alert_policy_source(bundle.replay_input_closure)

    assert raised.value.code == M6ReplayLockedPolicySourceReadErrorCode.SNAPSHOT_CHANGED
    assert vars(raised.value) == {"code": raised.value.code}
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__
    assert str(snapshot) not in str(raised.value)
    assert "source-authority" not in str(raised.value)


def test_repository_rejects_an_unpublished_foreign_closure_without_scanning(
    tmp_path: Path,
) -> None:
    database, source_root, bundle, config = _published_source(tmp_path)
    foreign = bundle.replay_input_closure.model_copy(update={"sample_id": "foreign-sample"})

    with (
        readonly_sqlite_snapshot(database) as snapshot,
        pytest.raises(M6ReplayLockedPolicySourceReadError) as raised,
    ):
        ReadonlyM6ReplayLockedAlertPolicySourceRepository(
            snapshot,
            store_root=source_root,
            config=config,  # type: ignore[arg-type]
        ).load_alert_policy_source(foreign)

    assert raised.value.code == M6ReplayLockedPolicySourceReadErrorCode.SOURCE_SEAL_INVALID
    assert canonical_json(foreign.model_dump(mode="json")) not in str(raised.value)

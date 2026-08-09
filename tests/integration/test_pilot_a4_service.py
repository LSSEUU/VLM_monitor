from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from PIL import Image

from labcourt.contracts.enums import AppealStatus, CaseStatus, VerdictDecision
from labcourt.contracts.evidence import EvidencePackDraft
from labcourt.contracts.pilot_report import PilotA4Metrics, PilotLocalAlertDocument
from labcourt.services.pilot_a4 import (
    close_pilot_run,
    publish_pilot_run,
    review_pilot_case,
)
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m5_sqlite_alert_repository import (
    _clock,
    _draft_for_manifest,
    _manifest_with_stream,
    _prepare_ready_case,
)


def test_pilot_a4_closes_run_scoped_authority_without_dispatch(tmp_path: Path) -> None:
    run_root = tmp_path / RUN_ID
    run_root.mkdir()
    database, evidence, _, ready, _, config = _prepare_ready_case(run_root)

    report = close_pilot_run(
        config=config,
        runs_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        clock=_clock,
    )
    repeated = close_pilot_run(
        config=config,
        runs_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        clock=_clock,
    )

    assert report.selected_count == 1
    assert report.outcomes[0].case_id == ready.case.case_id
    assert report.outcomes[0].closed_revision == ready.revision + 1
    assert report.production_delivery_count == 0
    assert repeated.selected_count == 0
    assert evidence.load_case(RUN_ID, ready.case.case_id).case.status == CaseStatus.CLOSED


def test_pilot_a4_rejects_database_outside_selected_run(tmp_path: Path) -> None:
    config = _prepare_ready_case(tmp_path)[-1]

    with pytest.raises(ValueError, match="selected pilot run"):
        close_pilot_run(
            config=config,
            runs_root=tmp_path,
            database_path=tmp_path / config.storage.database_filename,
            run_id=RUN_ID,
            clock=_clock,
        )


def test_pilot_a4_publishes_local_alert_and_operator_report_idempotently(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / RUN_ID
    run_root.mkdir()
    database, _, _, ready, _, config = _prepare_ready_case(run_root)

    first = publish_pilot_run(
        config=config,
        runs_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        clock=_clock,
    )
    first_index = (run_root / "report" / "index.html").read_bytes()
    repeated = publish_pilot_run(
        config=config,
        runs_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        clock=_clock,
    )

    assert first.closure.selected_count == 1
    assert first.dispatch.selected_count == first.dispatch.succeeded_count == 1
    assert first.metrics.case_count == first.metrics.closed_count == 1
    assert first.metrics.production_delivery_count == 0
    assert first.metrics.verified_local_alert_count == 1
    assert repeated.closure.selected_count == 0
    assert repeated.dispatch.selected_count == 0
    assert (run_root / "report" / "index.html").read_bytes() == first_index
    assert 'href="../metrics.json"' in first_index.decode("utf-8")
    metrics = PilotA4Metrics.model_validate_json(run_root.joinpath("metrics.json").read_bytes())
    assert metrics.metrics_id == first.metrics.metrics_id == repeated.metrics.metrics_id
    case_page = run_root / "report" / "cases" / f"{ready.case.case_id}.html"
    assert case_page.is_file()
    assert "用于安全辅助与记录" in case_page.read_text(encoding="utf-8")
    alert_path = run_root / "alerts" / f"{first.closure.outcomes[0].alert_id}.json"
    alert = PilotLocalAlertDocument.model_validate_json(alert_path.read_bytes())
    assert alert.alert.alert_id == first.closure.outcomes[0].alert_id
    assert first.local_alert_paths == repeated.local_alert_paths


def test_pilot_a4_review_reuses_appeal_authority_and_republishes_idempotently(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / RUN_ID
    run_root.mkdir()
    frames = run_root / "frames"
    frames.mkdir()
    media_path = frames / "focus.png"
    Image.new("RGB", (100, 200), (12, 24, 36)).save(media_path, format="PNG")
    media = media_path.read_bytes()
    draft = _draft_for_manifest(_manifest_with_stream())
    crop = draft.focus_crops[0].model_copy(
        update={
            "media_sha256": hashlib.sha256(media).hexdigest(),
            "size_bytes": len(media),
        }
    )
    payload = draft.model_dump(mode="python", exclude_computed_fields=True)
    payload["focus_crops"] = (crop.model_dump(mode="python", exclude_computed_fields=True),)
    verified_draft = EvidencePackDraft.model_validate(payload)
    database, evidence, _, ready, _, config = _prepare_ready_case(
        run_root,
        draft=verified_draft,
    )
    published = publish_pilot_run(
        config=config,
        runs_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        clock=_clock,
    )

    first = review_pilot_case(
        config=config,
        runs_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        case_id=ready.case.case_id,
        decision=VerdictDecision.NOT_ESTABLISHED,
        reason="Human review found the cited evidence insufficient.",
        clock=_clock,
    )
    repeated = review_pilot_case(
        config=config,
        runs_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        case_id=ready.case.case_id,
        decision=VerdictDecision.NOT_ESTABLISHED,
        reason="Human review found the cited evidence insufficient.",
        clock=_clock,
    )

    assert first == repeated
    assert first.resolution.status == AppealStatus.OVERTURNED
    assert first.resolution.source_decision == VerdictDecision.ESTABLISHED
    assert first.resolution.final_decision == VerdictDecision.NOT_ESTABLISHED
    assert first.review_label is not None
    assert len(first.resolution.training_label_ids) == 1
    assert len(first.resolution.rescinded_alert_ids) == 1
    assert first.production_delivery_count == 0
    assert first.publication_id != published.publication_id
    current = evidence.load_case(RUN_ID, ready.case.case_id).case
    assert current.status == CaseStatus.APPEAL_RESOLVED
    assert current.final_decision == VerdictDecision.NOT_ESTABLISHED
    assert current.appeals[-1].status == AppealStatus.OVERTURNED
    metrics = PilotA4Metrics.model_validate_json(run_root.joinpath("metrics.json").read_bytes())
    assert metrics.not_established_count == 1
    assert metrics.established_count == 0
    assert metrics.verified_local_alert_count == 0
    assert metrics.human_review_count == 0
    case_page = run_root / "report" / "cases" / f"{ready.case.case_id}.html"
    case_html = case_page.read_text(encoding="utf-8")
    assert "告警级别 CONFIRMED · 已撤销" in case_html
    assert 'src="../../frames/focus.png"' in case_html

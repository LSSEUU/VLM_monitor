from pathlib import Path

import pytest

from labcourt.adapters.precomputed import PrecomputedFrameSource
from labcourt.application.perception import PerceptionPipeline
from labcourt.config_loader import load_config
from labcourt.contracts.config import ZoneConfig
from labcourt.contracts.enums import ConfirmationPolicy, PpeType, RiskLevel
from labcourt.contracts.manifests import RunManifest

PROJECT_ROOT = Path(__file__).parents[2]


def test_m1_precomputed_replay_is_deterministic_and_l0_writes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config(PROJECT_ROOT / "configs" / "default.yaml")
    config = config.model_copy(
        update={
            "zones": (
                ZoneConfig(
                    zone_id="zone-01",
                    camera_id="cam-01",
                    polygon=((0, 0), (639, 0), (639, 479), (0, 479)),
                    risk_level=RiskLevel.HIGH,
                    required_ppe=(PpeType.GOGGLES,),
                    reminder_channel="display-01",
                ),
            ),
            "absence": config.absence.model_copy(
                update={
                    "dwell_seconds_by_risk": {
                        RiskLevel.LOW: 2.0,
                        RiskLevel.MEDIUM: 2.0,
                        RiskLevel.HIGH: 2.0,
                    },
                    "context_lookahead_seconds": 1.0,
                }
            ),
            "perception": config.perception.model_copy(
                update={
                    "detector": config.perception.detector.model_copy(
                        update={"model_id": "precomputed-demo-v1"}
                    )
                }
            ),
        }
    )
    manifest_path = PROJECT_ROOT / "tests" / "fixtures" / "m2" / "run-manifest-fake.json"
    manifest = RunManifest.model_validate_json(
        manifest_path.read_text(encoding="utf-8")
    ).model_copy(
        update={
            "config_sha256": config.config_sha256,
            "reproducibility_mode": config.run.reproducibility_mode,
            "random_seed": config.run.random_seed,
            "storage_boundary": config.run.storage_boundary,
        }
    )
    source_path = PROJECT_ROOT / "tests" / "fixtures" / "m1" / "precomputed-goggles-missing.json"

    monkeypatch.chdir(tmp_path)
    first = PerceptionPipeline(config=config, run_manifest=manifest).run(
        PrecomputedFrameSource.from_json_file(source_path)
    )
    replay = PerceptionPipeline(config=config, run_manifest=manifest).run(
        PrecomputedFrameSource.from_json_file(source_path)
    )

    assert first == replay
    assert first.frames_processed == 3
    assert len(first.reminders) == 1
    assert set(type(first.reminders[0]).model_fields) == {
        "zone_id",
        "ppe_type",
        "message",
        "channel",
    }
    assert len(first.events) == 1
    assert first.events[0].confirmation.policy == ConfirmationPolicy.STRICT_CAUSAL
    assert (first.events[0].start_frame, first.events[0].end_frame_exclusive) == (0, 2)
    assert list(tmp_path.rglob("*")) == []

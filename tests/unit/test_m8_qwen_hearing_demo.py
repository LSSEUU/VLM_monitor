from pathlib import Path

from labcourt.config_loader import load_config
from labcourt.services.m8_qwen_hearing_demo import (
    QWEN_API_KEY_ENV,
    QWEN_ENDPOINT_ENV,
    QWEN_MODEL_SNAPSHOT,
    QWEN_PROFILE_NAMES,
    build_m8_qwen_hearing_demo_config,
)

ROOT = Path(__file__).parents[2]


def test_qwen_demo_config_pins_three_independent_secret_free_profiles() -> None:
    config = build_m8_qwen_hearing_demo_config(load_config(ROOT / "configs" / "demo.yaml"))
    profiles = tuple(config.providers[name] for name in QWEN_PROFILE_NAMES)

    assert len(set(QWEN_PROFILE_NAMES)) == 3
    assert all(profile.model == QWEN_MODEL_SNAPSHOT for profile in profiles)
    assert all(profile.endpoint_env == QWEN_ENDPOINT_ENV for profile in profiles)
    assert all(profile.api_key_env == QWEN_API_KEY_ENV for profile in profiles)
    assert all(profile.enable_thinking is False for profile in profiles)
    assert all(profile.cache_enabled is True for profile in profiles)
    assert config.hearing.max_acquisition_rounds == 1
    assert config.hearing.max_rework_rounds == 1
    serialized = config.model_dump_json()
    assert "sk-" not in serialized
    assert "fixture" not in {profile.provider for profile in profiles}

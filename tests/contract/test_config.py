from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from labcourt.config_loader import load_config
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import ConfirmationPolicy, RunMode
from labcourt.contracts.manifests import RunManifest
from labcourt.exceptions import ContractViolation

PROJECT_ROOT = Path(__file__).parents[2]


def test_default_and_demo_configs_are_valid() -> None:
    default = load_config(PROJECT_ROOT / "configs" / "default.yaml")
    demo = load_config(PROJECT_ROOT / "configs" / "demo.yaml")
    assert default.schema_version == "2.0.0"
    assert demo.safety.hard_alerts_enabled
    assert default.config_sha256 != demo.config_sha256
    assert default.storage.database_filename == "labcourt.sqlite3"
    assert default.storage.busy_timeout_ms == 5_000
    assert default.storage.max_media_bytes == 104_857_600
    assert default.storage.max_image_pixels == 100_000_000
    assert default.pilot is None
    serialized = default.model_dump(mode="json", exclude={"config_sha256"})
    assert "pilot" not in serialized
    assert not {
        "detector_manifest",
        "pose",
        "pose_manifest",
        "tracker_manifest",
        "tracker_thresholds",
        "worker",
    }.intersection(serialized["perception"])


def test_pilot_config_is_strict_and_does_not_claim_future_rules() -> None:
    pilot = load_config(PROJECT_ROOT / "configs" / "pilot.yaml")
    assert pilot.pilot is not None
    assert [rule.value for rule in pilot.pilot.selected_rules] == ["PPE_GOGGLES_MISSING"]
    assert pilot.pilot.max_cases == 20
    assert pilot.perception.provider == "local-worker"
    assert pilot.perception.detector_manifest is not None
    assert pilot.perception.detector_manifest.weights_sha256 == (
        "1a2412ef99bd74bcd3c2a246fa1e48581f8889a1300c9051974741314fc042f3"
    )
    assert pilot.perception.tracker_manifest is not None
    assert pilot.perception.tracker_manifest.model == "trackers.ByteTrackTracker"
    assert pilot.perception.pose is not None
    assert pilot.perception.pose.keypoint_score_threshold == 0.8
    assert pilot.perception.pose.minimum_eye_span_ratio == 0.03
    assert pilot.perception.pose_manifest is not None
    assert pilot.perception.pose_manifest.weights_sha256 == (
        "f7bad8ed09eeeb2a7de6b38faaa8a88d07838e23e9c06a2a782099bca7467cb9"
    )
    assert pilot.perception.worker is not None
    assert pilot.perception.worker.local_files_only
    assert pilot.perception.worker.cache_enabled
    assert pilot.screening.provider_profile == "pilot-screening"
    screening_profile = pilot.providers[pilot.screening.provider_profile]
    assert screening_profile.provider == "alibaba-cloud-model-studio"
    assert screening_profile.model == "qwen3-vl-plus-2025-12-19"
    assert screening_profile.revision == "2025-12-19"
    assert screening_profile.pricing_currency == "CNY"
    assert screening_profile.input_cost_per_million_tokens == 1.0
    assert screening_profile.output_cost_per_million_tokens == 10.0
    assert screening_profile.endpoint_env == "LABCOURT_SCREENING_ENDPOINT"
    assert screening_profile.api_key_env == "LABCOURT_SCREENING_API_KEY"
    assert not screening_profile.allow_full_frame
    assert (
        pilot.config_sha256 != load_config(PROJECT_ROOT / "configs" / "default.yaml").config_sha256
    )

    payload = pilot.model_dump(mode="json", exclude={"config_sha256"})
    payload["pilot"]["selected_rules"] = ["REAGENT_CONTAINER_OPEN"]
    with pytest.raises(ValidationError, match="alpha1"):
        AppConfig.model_validate(payload)


def test_local_perception_worker_requires_complete_real_model_pins() -> None:
    pilot = load_config(PROJECT_ROOT / "configs" / "pilot.yaml")
    payload = pilot.perception.model_dump(mode="python", exclude_computed_fields=True)
    payload["detector_manifest"] = None
    with pytest.raises(ValidationError, match="complete model and worker pins"):
        type(pilot.perception).model_validate(payload)

    payload = pilot.perception.model_dump(mode="python", exclude_computed_fields=True)
    payload["worker"]["cache_enabled"] = False
    with pytest.raises(ValidationError):
        type(pilot.perception).model_validate(payload)

    payload = pilot.perception.model_dump(mode="python", exclude_computed_fields=True)
    payload["pose_manifest"] = None
    with pytest.raises(ValidationError, match="supplied together"):
        type(pilot.perception).model_validate(payload)


def test_workspace_does_not_change_config_fingerprint() -> None:
    config = load_config(PROJECT_ROOT / "configs" / "demo.yaml")
    changed_run = config.run.model_copy(update={"workspace": "another-machine/runs"})
    changed = config.model_copy(update={"run": changed_run})
    assert changed.config_sha256 == config.config_sha256

    manifest = RunManifest.model_validate_json(
        (PROJECT_ROOT / "tests" / "fixtures" / "m2" / "run-manifest-fake.json").read_text(
            encoding="utf-8"
        )
    )
    replay_manifest = manifest.model_copy(update={"config_sha256": changed.config_sha256})
    assert replay_manifest.manifest_id == manifest.manifest_id


def test_decision_threshold_changes_config_fingerprint() -> None:
    config = load_config(PROJECT_ROOT / "configs" / "demo.yaml")
    changed_screening = config.screening.model_copy(update={"high_probability": 0.9})
    changed = config.model_copy(update={"screening": changed_screening})
    assert changed.config_sha256 != config.config_sha256


def test_token_pricing_and_cost_cap_change_config_fingerprint() -> None:
    config = load_config(PROJECT_ROOT / "configs" / "demo.yaml")
    profile = config.providers["fake-screening"]
    priced_profile = profile.model_copy(update={"input_cost_per_million_tokens": 0.25})
    priced = config.model_copy(
        update={"providers": {**config.providers, "fake-screening": priced_profile}}
    )
    tighter_screening = config.screening.model_copy(update={"max_estimated_cost": 0.5})
    capped = config.model_copy(update={"screening": tighter_screening})

    assert priced.config_sha256 != config.config_sha256
    assert capped.config_sha256 != config.config_sha256


def test_misindented_evidence_is_rejected() -> None:
    path = PROJECT_ROOT / "tests" / "fixtures" / "m0" / "config-invalid-evidence-indent.yaml"
    with pytest.raises(ContractViolation):
        load_config(path)


def test_only_moving_evidence_under_presence_breaks_an_otherwise_valid_config(
    tmp_path: Path,
) -> None:
    source = (PROJECT_ROOT / "configs" / "demo.yaml").read_text(encoding="utf-8")
    before, evidence_and_after = source.split("\nevidence:\n", maxsplit=1)
    evidence_body, after = evidence_and_after.split("\nscreening:\n", maxsplit=1)
    nested_evidence = "\n  evidence:\n" + "\n".join(
        f"  {line}" if line else line for line in evidence_body.splitlines()
    )
    malformed = f"{before}{nested_evidence}\nscreening:\n{after}"

    original_data = yaml.safe_load(source)
    malformed_data = yaml.safe_load(malformed)
    moved_evidence = malformed_data["presence"].pop("evidence")
    expected_data = deepcopy(original_data)
    assert moved_evidence == expected_data.pop("evidence")
    assert malformed_data == expected_data

    path = tmp_path / "misindented.yaml"
    path.write_text(malformed, encoding="utf-8", newline="\n")
    with pytest.raises(ContractViolation) as captured:
        load_config(path)
    message = str(captured.value)
    assert "presence.evidence" in message
    assert "evidence" in message


def test_duplicate_yaml_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.yaml"
    path.write_text(
        'schema_version: "2.0.0"\nschema_version: "2.0.0"\n',
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(ContractViolation, match="duplicate YAML key"):
        load_config(path)


def test_source_compat_requires_offline_experiment() -> None:
    config = load_config(PROJECT_ROOT / "configs" / "demo.yaml")
    absence = config.absence.model_copy(
        update={
            "confirmation_policy": ConfirmationPolicy.SOURCE_COMPAT,
            "source_compat_enabled_for_offline_experiments": True,
        }
    )
    invalid_payload = config.model_dump(mode="json", exclude={"config_sha256"})
    invalid_payload["absence"] = absence.model_dump(mode="json")
    with pytest.raises(ValueError, match="OFFLINE_EXPERIMENT"):
        AppConfig.model_validate(invalid_payload)

    run = config.run.model_copy(update={"mode": RunMode.OFFLINE_EXPERIMENT})
    valid_payload = dict(invalid_payload)
    valid_payload["run"] = run.model_dump(mode="json")
    experimental = AppConfig.model_validate(valid_payload)
    assert experimental.absence.confirmation_policy == ConfirmationPolicy.SOURCE_COMPAT


@pytest.mark.parametrize(
    "workspace",
    [
        "../outside",
        "/absolute/runs",
        "C:/outside/runs",
        r"\\server\share\runs",
        "//server/share/runs",
        "https://example.invalid/runs",
    ],
)
def test_workspace_is_confined_to_a_portable_local_boundary(workspace: str) -> None:
    config = load_config(PROJECT_ROOT / "configs" / "demo.yaml")
    with pytest.raises(ValidationError):
        config.run.model_copy(update={"workspace": workspace})


@pytest.mark.parametrize(
    ("field", "value"),
    [("schema_version", "999.0.0"), ("rule_version", "unknown-rules")],
)
def test_unsupported_contract_versions_are_rejected(field: str, value: str) -> None:
    config = load_config(PROJECT_ROOT / "configs" / "demo.yaml")
    payload = config.model_dump(mode="json", exclude={"config_sha256"})
    payload[field] = value
    with pytest.raises(ValidationError):
        AppConfig.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("busy_timeout_ms", 0),
        ("busy_timeout_ms", 60_001),
        ("busy_timeout_ms", True),
        ("max_media_bytes", 0),
        ("max_image_pixels", 0),
    ],
)
def test_storage_limits_are_strict_positive_and_bounded(field: str, value: object) -> None:
    config = load_config(PROJECT_ROOT / "configs" / "default.yaml")
    payload = config.storage.model_dump(mode="json")
    payload[field] = value
    with pytest.raises(ValidationError):
        type(config.storage).model_validate(payload)


def test_storage_database_filename_is_fixed() -> None:
    config = load_config(PROJECT_ROOT / "configs" / "default.yaml")
    with pytest.raises(ValidationError):
        config.storage.model_copy(update={"database_filename": "another.sqlite3"})


def test_configuration_errors_do_not_echo_secret_values_or_chain_raw_inputs(
    tmp_path: Path,
) -> None:
    fake_secret = "sk-fixture-value-that-must-not-appear"
    path = tmp_path / "secret.yaml"
    path.write_text(
        f'schema_version: "2.0.0"\napi_key: "{fake_secret}"\n',
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(ContractViolation) as captured:
        load_config(path)
    assert fake_secret not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__


def test_yaml_aliases_are_rejected_before_validation(tmp_path: Path) -> None:
    path = tmp_path / "alias.yaml"
    path.write_text(
        'schema_version: &version "2.0.0"\nrule_version: *version\n',
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(ContractViolation, match="aliases"):
        load_config(path)


def test_empty_detector_prompt_and_certification_id_are_rejected() -> None:
    config = load_config(PROJECT_ROOT / "configs" / "demo.yaml")
    detector = config.perception.detector.model_dump(mode="json")
    detector["prompts"]["person"] = [""]
    with pytest.raises(ValidationError, match="prompts"):
        type(config.perception.detector).model_validate(detector)

    safety = config.safety.model_dump(mode="json")
    safety["certification_ids"] = [""]
    with pytest.raises(ValidationError, match="certification"):
        type(config.safety).model_validate(safety)


def test_model_and_hearing_calls_have_bounded_time_and_rounds() -> None:
    config = load_config(PROJECT_ROOT / "configs" / "demo.yaml")
    assert all(profile.timeout_seconds > 0 for profile in config.providers.values())
    assert all(profile.cache_enabled for profile in config.providers.values())
    assert config.screening.max_input_pixels == 16_777_216
    assert config.screening.max_prompt_bytes == 524_288
    assert config.screening.max_input_tokens == 32_768
    assert config.screening.max_output_tokens == 2_048
    assert config.screening.max_estimated_cost == 1.0
    assert config.screening.max_response_bytes == 262_144
    assert config.screening.max_json_depth == 16
    assert config.screening.max_json_fields == 512
    assert config.screening.max_string_chars == 8_192
    assert config.screening.strong_signal_threshold == 0.5
    assert config.screening.router_version == "screening-router-v1"
    assert config.screening.conflict_policy_version == "strong-signal-v1"
    assert config.screening.backlog_max_attempts == 3
    assert all(profile.pricing_currency == "USD" for profile in config.providers.values())
    assert all(
        profile.input_cost_per_million_tokens == 0.0
        and profile.output_cost_per_million_tokens == 0.0
        for profile in config.providers.values()
    )
    assert config.procedural_gate.gate_version == "procedural-gate-v1"
    with pytest.raises(ValidationError):
        config.hearing.model_copy(update={"max_acquisition_rounds": 3})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_images", 0),
        ("max_images", 65),
        ("timeout_seconds", 3_600.1),
        ("max_input_pixels", 0),
        ("max_prompt_bytes", 0),
        ("max_prompt_bytes", 1_048_577),
        ("max_input_tokens", 0),
        ("max_input_tokens", 262_145),
        ("max_output_tokens", 0),
        ("max_estimated_cost", -0.01),
        ("max_estimated_cost", 1_000_001.0),
        ("max_response_bytes", 0),
        ("max_response_bytes", 262_145),
        ("max_json_depth", 0),
        ("max_json_fields", 0),
        ("max_string_chars", 0),
    ],
)
def test_screening_budgets_are_strict_positive_and_bounded(
    field: str,
    value: object,
) -> None:
    config = load_config(PROJECT_ROOT / "configs" / "default.yaml")
    payload = config.screening.model_dump(mode="json")
    payload[field] = value
    with pytest.raises(ValidationError):
        type(config.screening).model_validate(payload)


@pytest.mark.parametrize("currency", ["USD", "CNY"])
def test_provider_token_pricing_accepts_supported_currencies(currency: str) -> None:
    profile = load_config(PROJECT_ROOT / "configs" / "default.yaml").providers[
        "fake-screening"
    ]
    payload = profile.model_dump(mode="json")
    payload["pricing_currency"] = currency

    resolved = type(profile).model_validate(payload)

    assert resolved.pricing_currency == currency


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("pricing_currency", "EUR"),
        ("timeout_seconds", 3_600.1),
        ("input_cost_per_million_tokens", -0.01),
        ("output_cost_per_million_tokens", -0.01),
        ("input_cost_per_million_tokens", 1_000_001.0),
    ],
)
def test_provider_token_pricing_is_supported_and_non_negative(
    field: str,
    value: object,
) -> None:
    profile = load_config(PROJECT_ROOT / "configs" / "default.yaml").providers["fake-screening"]
    payload = profile.model_dump(mode="json")
    payload[field] = value
    with pytest.raises(ValidationError):
        type(profile).model_validate(payload)


def test_http_provider_requires_explicit_token_pricing_and_currency() -> None:
    config = load_config(PROJECT_ROOT / "configs" / "default.yaml")
    profile = config.providers["fake-screening"].model_dump(mode="json")
    profile.update(
        {
            "provider": "remote-compatible",
            "execution_location": "EXTERNAL",
            "transport": "HTTP",
            "endpoint_env": "REMOTE_VLM_ENDPOINT",
            "api_key_env": "REMOTE_VLM_API_KEY",
        }
    )
    for field in (
        "pricing_currency",
        "input_cost_per_million_tokens",
        "output_cost_per_million_tokens",
    ):
        profile.pop(field)
    with pytest.raises(ValidationError, match="explicit token pricing and currency"):
        type(config.providers["fake-screening"]).model_validate(profile)

    profile.update(
        {
            "pricing_currency": "USD",
            "input_cost_per_million_tokens": 2.5,
            "output_cost_per_million_tokens": 10.0,
        }
    )
    resolved = type(config.providers["fake-screening"]).model_validate(profile)
    assert resolved.input_cost_per_million_tokens == 2.5
    assert resolved.output_cost_per_million_tokens == 10.0


def test_http_provider_model_identity_can_be_resolved_from_deployment_environment(
    tmp_path: Path,
) -> None:
    source = (PROJECT_ROOT / "configs" / "default.yaml").read_text(encoding="utf-8")
    source = source.replace("provider: fake", "provider: openai-compatible", 1)
    source = source.replace(
        "model: deterministic-screening",
        "model: ${LABCOURT_TEST_MODEL}",
        1,
    )
    source = source.replace('revision: "1.0.0"', "revision: ${LABCOURT_TEST_REVISION}", 1)
    source = source.replace("execution_location: LOCAL", "execution_location: EXTERNAL", 1)
    source = source.replace("transport: IN_PROCESS", "transport: HTTP", 1)
    source = source.replace("endpoint_env: null", "endpoint_env: LABCOURT_TEST_ENDPOINT", 1)
    source = source.replace("api_key_env: null", "api_key_env: LABCOURT_TEST_API_KEY", 1)
    path = tmp_path / "environment-config.yaml"
    path.write_text(source, encoding="utf-8")

    config = load_config(
        path,
        environment={
            "LABCOURT_TEST_MODEL": "vision-model",
            "LABCOURT_TEST_REVISION": "2026-08-01",
        },
    )

    profile = config.providers["fake-screening"]
    assert profile.model == "vision-model"
    assert profile.revision == "2026-08-01"
    serialized = config.model_dump_json()
    assert "LABCOURT_TEST_MODEL" not in serialized
    assert "LABCOURT_TEST_REVISION" not in serialized


def test_missing_model_deployment_environment_is_a_redacted_configuration_failure(
    tmp_path: Path,
) -> None:
    source = (PROJECT_ROOT / "configs" / "default.yaml").read_text(encoding="utf-8")
    source = source.replace(
        "model: deterministic-screening",
        "model: ${LABCOURT_SECRET_MODEL_NAME}",
        1,
    )
    path = tmp_path / "missing-environment-config.yaml"
    path.write_text(source, encoding="utf-8")

    with pytest.raises(ContractViolation) as captured:
        load_config(path, environment={})

    assert "deployment environment variable is missing" in str(captured.value)
    assert "LABCOURT_SECRET_MODEL_NAME" not in str(captured.value)


def test_procedural_gate_tolerances_cover_every_objective_numeric_kind() -> None:
    tolerances = load_config(
        PROJECT_ROOT / "configs" / "default.yaml"
    ).procedural_gate.objective_numeric_tolerance
    assert tolerances.duration_frames == 1
    assert tolerances.person_count == 0
    assert tolerances.frame_interval_frames == 1
    assert tolerances.track_presence_interval_frames == 1
    assert tolerances.detection_score == 0.01
    assert tolerances.observability == 0.01


def test_m2_config_shape_resolves_new_m3_budgets_without_schema_bump() -> None:
    current = load_config(PROJECT_ROOT / "configs" / "default.yaml")
    legacy_payload = current.model_dump(mode="json", exclude={"config_sha256"})
    for field in (
        "strong_signal_threshold",
        "router_version",
        "conflict_policy_version",
        "backlog_max_attempts",
        "max_input_pixels",
        "max_prompt_bytes",
        "max_input_tokens",
        "max_output_tokens",
        "max_estimated_cost",
        "max_response_bytes",
        "max_json_depth",
        "max_json_fields",
        "max_string_chars",
    ):
        legacy_payload["screening"].pop(field)
    for field in (
        "frame_interval_frames",
        "track_presence_interval_frames",
        "detection_score",
        "observability",
    ):
        legacy_payload["procedural_gate"]["objective_numeric_tolerance"].pop(field)
    legacy_payload["procedural_gate"].pop("gate_version")

    resolved = AppConfig.model_validate(legacy_payload)

    assert resolved.schema_version == "2.0.0"
    assert resolved.screening == current.screening
    assert (
        resolved.procedural_gate.objective_numeric_tolerance
        == current.procedural_gate.objective_numeric_tolerance
    )
    assert resolved.config_sha256 == current.config_sha256

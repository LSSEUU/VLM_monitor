from __future__ import annotations

import hashlib
import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_demo import (
    MAX_M6_OFFLINE_DEMO_SCENARIO_ARTIFACT_BYTES,
    MAX_M6_OFFLINE_DEMO_VERIFICATION_TARGET_CHARACTERS,
    M6OfflineDemoManifestAuthorityV1,
    M6OfflineDemoScenarioArtifactReceiptV1,
    M6OfflineDemoScenarioName,
    M6OfflineDemoScenarioResultAuthorityV1,
)
from labcourt.schema_export import expected_schema_files

_SCENARIO_NAMES = (
    "presence_true_positive",
    "presence_false_positive",
    "absence_true_violation",
    "absence_detector_miss_but_worn",
    "absence_all_unclear",
    "absence_don_after_threshold",
    "late_result_inside_interval",
    "fabricated_crop_reference",
    "objective_person_count_conflict",
    "unanswered_defense",
    "precedent_direction_mismatch",
    "provider_outage",
    "hard_signal_uncertified",
    "appeal_overturn",
    "replay_locked_identical",
    "upgrade_flip_gate",
)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _result(
    name: M6OfflineDemoScenarioName,
) -> M6OfflineDemoScenarioResultAuthorityV1:
    return M6OfflineDemoScenarioResultAuthorityV1(
        scenario_name=name,
        verification_target=(f"tests/e2e/test_m6_demo_scenarios.py::test_{name.value}"),
    )


def _artifact_document(name: M6OfflineDemoScenarioName) -> str:
    return canonical_json(_result(name).model_dump(mode="json"))


def _receipt(
    name: M6OfflineDemoScenarioName,
) -> M6OfflineDemoScenarioArtifactReceiptV1:
    document = _artifact_document(name)
    return M6OfflineDemoScenarioArtifactReceiptV1(
        scenario_name=name,
        artifact_content_sha256=_sha256(document),
        artifact_size_bytes=len(document.encode("utf-8")),
    )


def _manifest() -> M6OfflineDemoManifestAuthorityV1:
    return M6OfflineDemoManifestAuthorityV1(
        candidate_run_id="offline-demo-candidate",
        closed_regression_report_id=_sha256("closed-regression-report"),
        closed_regression_publication_seal_id=_sha256("closed-regression-publication-seal"),
        static_report_publication_seal_id=_sha256("static-report-publication-seal"),
        static_report_index_content_sha256=_sha256("static-report-index"),
        scenario_receipts=tuple(_receipt(name) for name in M6OfflineDemoScenarioName),
    )


def test_demo_scenario_names_and_order_are_exactly_the_m6_acceptance_list() -> None:
    assert tuple(name.value for name in M6OfflineDemoScenarioName) == _SCENARIO_NAMES


def test_scenario_result_is_a_fixed_offline_pytest_verification_authority() -> None:
    result = _result(M6OfflineDemoScenarioName.PRESENCE_TRUE_POSITIVE)

    assert result.schema_version == "m6-offline-demo-scenario-result-authority-v1"
    assert result.scenario_name is M6OfflineDemoScenarioName.PRESENCE_TRUE_POSITIVE
    assert result.classification == "SYNTHETIC_PRECOMPUTED_FAKE"
    assert result.status == "PASSED"
    assert result.verification_kind == "PYTEST_NODE"
    assert result.verification_target == (
        "tests/e2e/test_m6_demo_scenarios.py::test_presence_true_positive"
    )
    assert result.network_used is False
    assert result.gpu_used is False
    assert result.provider_called is False
    assert len(result.result_id) == 64


@pytest.mark.parametrize(
    "target",
    (
        "tests/e2e/test_m6_demo_scenarios.py",
        "tests/e2e/test_m6_demo_scenarios.py::helper",
        "test/e2e/test_m6_demo_scenarios.py::test_scenario",
        "../tests/e2e/test_m6_demo_scenarios.py::test_scenario",
        "/tests/e2e/test_m6_demo_scenarios.py::test_scenario",
        "tests\\e2e\\test_m6_demo_scenarios.py::test_scenario",
        "tests/e2e/test_m6_demo_scenarios.txt::test_scenario",
        "tests/e2e/test-m6-demo.py::test_scenario",
        "tests/e2e/test_m6_demo.py::TestDemo::test_scenario",
        "tests/e2e/test_m6_demo.py::test_scenario[param]",
        "tests/e2e/test_m6_demo.py::test_scenario\nforged",
        "tests/e2e/test_m6_demo.py::test_scenario\x7f",
        "tests/e2e/test_m6_demo.py::test_scenario\x85",
        "tests/e2e/test_m6_demo.py::test_scenario\ud800",
        "x" * (MAX_M6_OFFLINE_DEMO_VERIFICATION_TARGET_CHARACTERS + 1),
    ),
)
def test_scenario_result_rejects_uncontrolled_verification_targets(target: str) -> None:
    with pytest.raises(ValidationError):
        M6OfflineDemoScenarioResultAuthorityV1(
            scenario_name=M6OfflineDemoScenarioName.PRESENCE_TRUE_POSITIVE,
            verification_target=target,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("classification", "REAL_PRODUCTION"),
        ("status", "FAILED"),
        ("verification_kind", "SHELL_COMMAND"),
        ("network_used", True),
        ("gpu_used", True),
        ("provider_called", True),
    ),
)
def test_scenario_result_rejects_nonpassing_or_nonoffline_claims(
    field: str,
    value: object,
) -> None:
    payload = _result(M6OfflineDemoScenarioName.PRESENCE_TRUE_POSITIVE).model_dump(
        mode="json", exclude_computed_fields=True
    )
    payload[field] = value

    with pytest.raises(ValidationError):
        M6OfflineDemoScenarioResultAuthorityV1.model_validate(payload)


def test_scenario_result_id_commits_name_and_verification_target() -> None:
    result = _result(M6OfflineDemoScenarioName.PRESENCE_TRUE_POSITIVE)
    changed_target = result.model_copy(
        update={
            "verification_target": (
                "tests/e2e/test_m6_demo_scenarios.py::test_presence_true_positive_v2"
            )
        }
    )
    changed_name = result.model_copy(
        update={"scenario_name": M6OfflineDemoScenarioName.PRESENCE_FALSE_POSITIVE}
    )

    assert changed_target.result_id != result.result_id
    assert changed_name.result_id != result.result_id


def test_scenario_result_rejects_serialized_result_id_tampering() -> None:
    payload = _result(M6OfflineDemoScenarioName.PRESENCE_TRUE_POSITIVE).model_dump(mode="json")
    payload["result_id"] = "0" * 64

    with pytest.raises(ValidationError):
        M6OfflineDemoScenarioResultAuthorityV1.model_validate(payload)


def test_scenario_receipt_has_a_fixed_content_addressed_relative_path() -> None:
    receipt = _receipt(M6OfflineDemoScenarioName.PRESENCE_TRUE_POSITIVE)

    assert receipt.schema_version == "m6-offline-demo-scenario-artifact-receipt-v1"
    assert receipt.artifact_relative_path == ("demo/scenarios/presence_true_positive/result.json")
    assert not receipt.artifact_relative_path.startswith(("/", "../"))
    assert "\\" not in receipt.artifact_relative_path
    assert len(receipt.artifact_content_sha256) == 64
    assert receipt.artifact_size_bytes > 0
    assert len(receipt.artifact_receipt_id) == 64


def test_each_scenario_has_an_independent_artifact_dual_identity() -> None:
    manifest = _manifest()

    assert len({item.artifact_receipt_id for item in manifest.scenario_receipts}) == 16
    assert len({item.artifact_content_sha256 for item in manifest.scenario_receipts}) == 16
    assert all(item.artifact_size_bytes > 0 for item in manifest.scenario_receipts)
    assert tuple(item.scenario_name.value for item in manifest.scenario_receipts) == (
        _SCENARIO_NAMES
    )


def test_receipt_dual_identity_is_the_exact_canonical_result_document() -> None:
    name = M6OfflineDemoScenarioName.REPLAY_LOCKED_IDENTICAL
    result = _result(name)
    document = canonical_json(result.model_dump(mode="json"))
    receipt = _receipt(name)

    assert receipt.artifact_content_sha256 == _sha256(document)
    assert receipt.artifact_size_bytes == len(document.encode("utf-8"))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("artifact_content_sha256", "not-a-sha256"),
        ("artifact_content_sha256", "A" * 64),
        ("artifact_size_bytes", 0),
        ("artifact_size_bytes", -1),
        ("artifact_size_bytes", True),
        (
            "artifact_size_bytes",
            MAX_M6_OFFLINE_DEMO_SCENARIO_ARTIFACT_BYTES + 1,
        ),
    ),
)
def test_scenario_artifact_dual_identity_is_strict_and_bounded(
    field: str,
    value: object,
) -> None:
    payload = _receipt(M6OfflineDemoScenarioName.PRESENCE_TRUE_POSITIVE).model_dump(
        mode="json", exclude_computed_fields=True
    )
    payload[field] = value

    with pytest.raises(ValidationError):
        M6OfflineDemoScenarioArtifactReceiptV1.model_validate(payload)


@pytest.mark.parametrize("claim", ("artifact_relative_path", "artifact_receipt_id"))
def test_scenario_receipt_rejects_serialized_computed_claim_tampering(
    claim: str,
) -> None:
    payload = _receipt(M6OfflineDemoScenarioName.PRESENCE_TRUE_POSITIVE).model_dump(mode="json")
    payload[claim] = "0" * 64 if claim == "artifact_receipt_id" else "../raw.json"

    with pytest.raises(ValidationError):
        M6OfflineDemoScenarioArtifactReceiptV1.model_validate(payload)


def test_demo_manifest_is_fixed_to_the_offline_synthetic_execution_profile() -> None:
    manifest = _manifest()

    assert manifest.schema_version == "m6-offline-demo-manifest-authority-v1"
    assert manifest.classification == "SYNTHETIC_PRECOMPUTED_FAKE"
    assert manifest.network_used is False
    assert manifest.gpu_used is False
    assert manifest.provider_called is False
    assert manifest.scenario_count == 16
    assert len(manifest.scenario_inventory_root_sha256) == 64
    assert len(manifest.demo_manifest_id) == 64


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("classification", "REAL_PRODUCTION"),
        ("network_used", True),
        ("gpu_used", True),
        ("provider_called", True),
    ),
)
def test_demo_manifest_rejects_online_accelerated_or_provider_execution_claims(
    field: str,
    value: object,
) -> None:
    payload = _manifest().model_dump(mode="json", exclude_computed_fields=True)
    payload[field] = value

    with pytest.raises(ValidationError):
        M6OfflineDemoManifestAuthorityV1.model_validate(payload)


def test_demo_manifest_binds_closed_and_static_publication_roots() -> None:
    manifest = _manifest()

    assert manifest.candidate_run_id == "offline-demo-candidate"
    assert manifest.closed_regression_report_id == _sha256("closed-regression-report")
    assert manifest.closed_regression_publication_seal_id == _sha256(
        "closed-regression-publication-seal"
    )
    assert manifest.static_report_publication_seal_id == _sha256("static-report-publication-seal")
    assert manifest.static_report_index_content_sha256 == _sha256("static-report-index")


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("candidate_run_id", "foreign-demo-candidate"),
        ("closed_regression_report_id", "1" * 64),
        ("closed_regression_publication_seal_id", "2" * 64),
        ("static_report_publication_seal_id", "3" * 64),
        ("static_report_index_content_sha256", "4" * 64),
    ),
)
def test_demo_manifest_id_commits_every_upstream_publication_root(
    field: str,
    replacement: object,
) -> None:
    manifest = _manifest()

    forged = manifest.model_copy(update={field: replacement})

    assert forged.demo_manifest_id != manifest.demo_manifest_id, field


def test_demo_manifest_id_commits_the_exact_scenario_inventory() -> None:
    manifest = _manifest()
    first = manifest.scenario_receipts[0]
    changed_first = M6OfflineDemoScenarioArtifactReceiptV1(
        scenario_name=first.scenario_name,
        artifact_content_sha256="5" * 64,
        artifact_size_bytes=first.artifact_size_bytes,
    )
    changed = M6OfflineDemoManifestAuthorityV1(
        candidate_run_id=manifest.candidate_run_id,
        closed_regression_report_id=manifest.closed_regression_report_id,
        closed_regression_publication_seal_id=(manifest.closed_regression_publication_seal_id),
        static_report_publication_seal_id=(manifest.static_report_publication_seal_id),
        static_report_index_content_sha256=(manifest.static_report_index_content_sha256),
        scenario_receipts=(changed_first, *manifest.scenario_receipts[1:]),
    )

    assert changed.scenario_inventory_root_sha256 != (manifest.scenario_inventory_root_sha256)
    assert changed.demo_manifest_id != manifest.demo_manifest_id


def test_demo_manifest_rejects_missing_duplicate_and_unordered_scenarios() -> None:
    manifest = _manifest()
    base = manifest.model_dump(mode="json", exclude_computed_fields=True)
    invalid_inventories = (
        base["scenario_receipts"][:-1],
        [*base["scenario_receipts"][:-1], base["scenario_receipts"][0]],
        list(reversed(base["scenario_receipts"])),
    )

    for scenario_receipts in invalid_inventories:
        payload = dict(base)
        payload["scenario_receipts"] = scenario_receipts
        with pytest.raises(ValidationError):
            M6OfflineDemoManifestAuthorityV1.model_validate(payload)


def test_demo_manifest_rejects_extra_or_unknown_scenario_names() -> None:
    manifest = _manifest()
    base = manifest.model_dump(mode="json", exclude_computed_fields=True)
    unknown = dict(base["scenario_receipts"][0])
    unknown["scenario_name"] = "unexpected_demo_scenario"

    replaced = dict(base)
    replaced["scenario_receipts"] = [unknown, *base["scenario_receipts"][1:]]
    with pytest.raises(ValidationError):
        M6OfflineDemoManifestAuthorityV1.model_validate(replaced)

    appended = dict(base)
    appended["scenario_receipts"] = [*base["scenario_receipts"], unknown]
    with pytest.raises(ValidationError):
        M6OfflineDemoManifestAuthorityV1.model_validate(appended)


@pytest.mark.parametrize(
    "claim",
    ("scenario_count", "scenario_inventory_root_sha256", "demo_manifest_id"),
)
def test_demo_manifest_rejects_serialized_computed_claim_tampering(claim: str) -> None:
    payload = _manifest().model_dump(mode="json")
    payload[claim] = 17 if claim == "scenario_count" else "0" * 64

    with pytest.raises(ValidationError):
        M6OfflineDemoManifestAuthorityV1.model_validate(payload)


def test_demo_contract_schemas_accept_the_canonical_wire_documents() -> None:
    expected = {
        "m6-offline-demo-scenario-result-authority-v1.schema.json": _result(
            M6OfflineDemoScenarioName.PRESENCE_TRUE_POSITIVE
        ).model_dump(mode="json"),
        "m6-offline-demo-scenario-artifact-receipt-v1.schema.json": _receipt(
            M6OfflineDemoScenarioName.PRESENCE_TRUE_POSITIVE
        ).model_dump(mode="json"),
        "m6-offline-demo-manifest-authority-v1.schema.json": _manifest().model_dump(mode="json"),
    }
    schemas = expected_schema_files()

    for filename, document in expected.items():
        schema = json.loads(schemas[filename])
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from labcourt.adapters.hearing_prompt_renderer import (
    HEARING_PROMPT_DEFINITIONS,
    HearingJinjaPromptCatalog,
)
from labcourt.adapters.jinja_prompt_renderer import JinjaPromptCatalog
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import VlmRole
from labcourt.ports.prompts import (
    PromptCatalog,
    PromptRenderError,
    PromptRenderFailureCode,
)
from labcourt.schema_export import expected_schema_files

PROJECT_ROOT = Path(__file__).parents[2]
PROMPTS = PROJECT_ROOT / "prompts"
HEARING_PROMPT_IDS = tuple(definition.prompt_id for definition in HEARING_PROMPT_DEFINITIONS)
M3_PROMPT_IDS = (
    "screening_presence_v1",
    "screening_absence_v1",
    "screening_structure_repair_v1",
)


def _hearing_schema_documents() -> dict[str, str]:
    schemas = expected_schema_files()
    return {
        "hearing_prosecutor_v1": canonical_json(
            json.loads(schemas["prosecutor-model-payload.schema.json"])
        ),
        "hearing_defender_v1": canonical_json(
            json.loads(schemas["defender-model-payload.schema.json"])
        ),
        "hearing_judge_v1": canonical_json(json.loads(schemas["judge-model-payload.schema.json"])),
    }


def _m3_schema_documents() -> dict[str, str]:
    schema = canonical_json({"additionalProperties": False, "type": "object"})
    return dict.fromkeys(M3_PROMPT_IDS, schema)


def _variables(prompt_id: str) -> dict[str, str]:
    definition = next(item for item in HEARING_PROMPT_DEFINITIONS if item.prompt_id == prompt_id)
    variables = {
        name: canonical_json({"bound": name})
        for name in definition.variable_names
        if name != "output_schema_json"
    }
    variables["repair_context_json"] = "null"
    variables["prior_response_json"] = "null"
    return variables


def _copy_prompts(tmp_path: Path) -> Path:
    destination = tmp_path / "prompts"
    shutil.copytree(PROMPTS, destination)
    return destination


def test_hearing_catalog_is_independent_and_renders_every_role_strictly() -> None:
    catalog = HearingJinjaPromptCatalog(output_schema_json_by_prompt=_hearing_schema_documents())

    assert isinstance(catalog, PromptCatalog)
    assert tuple(definition.role for definition in HEARING_PROMPT_DEFINITIONS) == (
        VlmRole.PROSECUTOR,
        VlmRole.DEFENDER,
        VlmRole.JUDGE,
    )
    for prompt_id in HEARING_PROMPT_IDS:
        variables = _variables(prompt_id)
        rendered = catalog.render(prompt_id=prompt_id, variables=variables)
        repeated = catalog.render(
            prompt_id=prompt_id,
            variables=dict(reversed(tuple(variables.items()))),
        )

        assert rendered.utf8_bytes == repeated.utf8_bytes
        assert rendered.manifest.prompt_bundle_sha256 == catalog.bundle_sha256
        assert rendered.manifest.role in {
            VlmRole.PROSECUTOR,
            VlmRole.DEFENDER,
            VlmRole.JUDGE,
        }
        assert "REPAIR_CONTEXT_JSON=null" in rendered.text
        assert "PRIOR_RESPONSE_JSON=null" in rendered.text
        assert _hearing_schema_documents()[prompt_id] in rendered.text


@pytest.mark.parametrize("prompt_id", HEARING_PROMPT_IDS)
def test_hearing_prompt_variables_are_an_exact_canonical_json_set(prompt_id: str) -> None:
    catalog = HearingJinjaPromptCatalog(output_schema_json_by_prompt=_hearing_schema_documents())
    variables = _variables(prompt_id)
    missing = dict(variables)
    missing.pop(next(iter(missing)))
    extra = {**variables, "unexpected_json": "{}"}

    for invalid_set in (missing, extra):
        with pytest.raises(PromptRenderError) as captured:
            catalog.render(prompt_id=prompt_id, variables=invalid_set)
        assert captured.value.reason_code == PromptRenderFailureCode.PROMPT_VARIABLE_SET_INVALID

    invalid_value = {**variables, "hearing_context_json": '{ "not":"canonical" }'}
    with pytest.raises(PromptRenderError) as captured:
        catalog.render(prompt_id=prompt_id, variables=invalid_value)
    assert captured.value.reason_code == PromptRenderFailureCode.PROMPT_VARIABLE_NOT_CANONICAL_JSON


def test_hearing_template_tamper_fails_closed(tmp_path: Path) -> None:
    prompt_root = _copy_prompts(tmp_path)
    target = prompt_root / "hearing_judge_v1.jinja"
    target.write_text(
        target.read_text(encoding="utf-8") + "UNKNOWN={{ unknown_json }}\n",
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(PromptRenderError) as captured:
        HearingJinjaPromptCatalog(
            output_schema_json_by_prompt=_hearing_schema_documents(),
            template_root=prompt_root,
        )
    assert captured.value.reason_code == PromptRenderFailureCode.TEMPLATE_CONSTRUCT_FORBIDDEN
    assert str(prompt_root) not in str(captured.value)


def test_hearing_schema_tamper_changes_only_the_independent_bundle() -> None:
    original = HearingJinjaPromptCatalog(output_schema_json_by_prompt=_hearing_schema_documents())
    changed = HearingJinjaPromptCatalog(
        output_schema_json_by_prompt={
            **_hearing_schema_documents(),
            "hearing_judge_v1": canonical_json({"type": "array"}),
        }
    )
    m3 = JinjaPromptCatalog(output_schema_json_by_prompt=_m3_schema_documents())

    assert original.bundle_sha256 != changed.bundle_sha256
    assert (
        original.manifest("hearing_judge_v1").output_schema_sha256
        != changed.manifest("hearing_judge_v1").output_schema_sha256
    )
    assert m3.bundle_sha256 == ("5a0c1df90ad96c57ded58c079a239b7ed01a1978ec255cc3ea7f8336dbfe0c31")


def test_hearing_expected_bundle_and_schema_set_fail_closed() -> None:
    with pytest.raises(PromptRenderError) as mismatch:
        HearingJinjaPromptCatalog(
            output_schema_json_by_prompt=_hearing_schema_documents(),
            expected_bundle_sha256="f" * 64,
        )
    assert mismatch.value.reason_code == PromptRenderFailureCode.PROMPT_BUNDLE_MISMATCH

    incomplete = _hearing_schema_documents()
    incomplete.pop("hearing_judge_v1")
    with pytest.raises(PromptRenderError) as schema_set:
        HearingJinjaPromptCatalog(output_schema_json_by_prompt=incomplete)
    assert schema_set.value.reason_code == PromptRenderFailureCode.PROMPT_SCHEMA_SET_INVALID


def test_m3_bundle_and_manifest_bytes_remain_frozen() -> None:
    catalog = JinjaPromptCatalog(output_schema_json_by_prompt=_m3_schema_documents())
    manifest_bytes = canonical_json(
        catalog.manifest("screening_presence_v1").model_dump(mode="json")
    ).encode("utf-8")

    assert catalog.bundle_sha256 == (
        "5a0c1df90ad96c57ded58c079a239b7ed01a1978ec255cc3ea7f8336dbfe0c31"
    )
    assert hashlib.sha256(manifest_bytes).hexdigest() == (
        "28c10ad6439ab65a54ed58e7578470c0b63b1d5775593aa5218e2acf034ad757"
    )


def test_hearing_prompt_golden_identities_are_frozen() -> None:
    catalog = HearingJinjaPromptCatalog(output_schema_json_by_prompt=_hearing_schema_documents())
    rendered = {
        prompt_id: catalog.render(prompt_id=prompt_id, variables=_variables(prompt_id))
        for prompt_id in HEARING_PROMPT_IDS
    }

    assert catalog.bundle_sha256 == (
        "0b7d777f01abe5bc74fc511f7a10a03dbdd3365c9b6b8f784cc32995fd5fb8a8"
    )
    assert {prompt_id: value.manifest.template_sha256 for prompt_id, value in rendered.items()} == {
        "hearing_prosecutor_v1": (
            "10ae08871b7df647f06ed56e15f13735cd656fa84ec6b0d3a26b4c272065702a"
        ),
        "hearing_defender_v1": ("6e5128a6f9b23e13ef2f2c2e2db4bd1cce30f2d647875e8bcd85e82a03f8d1b0"),
        "hearing_judge_v1": ("d8ea831de99741ff800a6c3ea6093d7b2368161d1725a77cf657807592aed1bd"),
    }
    assert {prompt_id: value.rendered_prompt_sha256 for prompt_id, value in rendered.items()} == {
        "hearing_prosecutor_v1": (
            "729a596f4c12fc697f47adc678c9c6fd18a612dd7b874e4800465c9e5c1d96bd"
        ),
        "hearing_defender_v1": ("587eafc69139bfde03a519650ba364ccf4d5c0c54d69a0c5c359e53f16384d75"),
        "hearing_judge_v1": ("845681d1245f0e6e12356bc32c03ab1ae191c1a0c2678885364f1c2d21c7c8e6"),
    }

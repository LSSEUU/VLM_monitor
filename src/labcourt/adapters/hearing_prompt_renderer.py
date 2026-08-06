"""Strict, deterministic rendering for the independent M4 hearing prompt bundle."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Final

import jinja2
from jinja2 import Template, TemplateError

from labcourt.adapters.jinja_prompt_renderer import (
    MAX_RENDERED_PROMPT_BYTES,
    RENDERER_VERSION,
    PromptDefinition,
    _load_template,
    _LoadedTemplate,
    _require_canonical_json_values,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import VlmRole
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m3_models import PromptManifest
from labcourt.ports.prompts import (
    PromptCatalog,
    PromptRenderError,
    PromptRenderFailureCode,
    RenderedPrompt,
)

HEARING_PROMPT_DEFINITIONS: Final = (
    PromptDefinition(
        prompt_id="hearing_prosecutor_v1",
        filename="hearing_prosecutor_v1.jinja",
        role=VlmRole.PROSECUTOR,
        variable_names=(
            "allowed_refs_json",
            "hearing_context_json",
            "output_schema_json",
            "precedents_json",
            "prior_response_json",
            "repair_context_json",
        ),
    ),
    PromptDefinition(
        prompt_id="hearing_defender_v1",
        filename="hearing_defender_v1.jinja",
        role=VlmRole.DEFENDER,
        variable_names=(
            "allowed_refs_json",
            "hearing_context_json",
            "output_schema_json",
            "precedents_json",
            "prior_response_json",
            "prosecutor_output_json",
            "repair_context_json",
        ),
    ),
    PromptDefinition(
        prompt_id="hearing_judge_v1",
        filename="hearing_judge_v1.jinja",
        role=VlmRole.JUDGE,
        variable_names=(
            "allowed_refs_json",
            "defender_output_json",
            "hearing_context_json",
            "output_schema_json",
            "precedents_json",
            "prior_response_json",
            "prosecutor_output_json",
            "repair_context_json",
        ),
    ),
)

_HEARING_DEFINITIONS_BY_ID: Final = {
    definition.prompt_id: definition for definition in HEARING_PROMPT_DEFINITIONS
}


class HearingJinjaPromptCatalog(PromptCatalog):
    """Loaded M4 prompt authority with a bundle identity separate from M3."""

    def __init__(
        self,
        *,
        output_schema_json_by_prompt: Mapping[str, str],
        expected_bundle_sha256: Sha256Hex | None = None,
        template_root: Path | None = None,
    ) -> None:
        if jinja2.__version__ != "3.1.6":
            raise PromptRenderError(PromptRenderFailureCode.RENDERER_VERSION_MISMATCH)
        if template_root is not None and not template_root.is_absolute():
            raise PromptRenderError(PromptRenderFailureCode.TEMPLATE_ROOT_INVALID)
        try:
            schema_documents = dict(output_schema_json_by_prompt)
        except (RuntimeError, TypeError, ValueError):
            raise PromptRenderError(PromptRenderFailureCode.PROMPT_SCHEMA_SET_INVALID) from None
        if set(schema_documents) != set(_HEARING_DEFINITIONS_BY_ID):
            raise PromptRenderError(PromptRenderFailureCode.PROMPT_SCHEMA_SET_INVALID)
        _require_canonical_json_values(
            schema_documents,
            failure_code=PromptRenderFailureCode.PROMPT_SCHEMA_NOT_CANONICAL_JSON,
        )
        schema_sha256_by_prompt = {
            prompt_id: hashlib.sha256(schema.encode("utf-8")).hexdigest()
            for prompt_id, schema in schema_documents.items()
        }

        loaded: dict[str, _LoadedTemplate] = {}
        templates: dict[str, Template] = {}
        for definition in HEARING_PROMPT_DEFINITIONS:
            loaded_template, compiled_template = _load_template(
                definition,
                template_root=template_root,
            )
            loaded[definition.prompt_id] = loaded_template
            templates[definition.prompt_id] = compiled_template

        bundle_projection = [
            {
                "prompt_id": definition.prompt_id,
                "role": definition.role.value,
                "template_sha256": loaded[definition.prompt_id].template_sha256,
                "output_schema_sha256": schema_sha256_by_prompt[definition.prompt_id],
                "variable_names": list(definition.variable_names),
                "renderer_version": RENDERER_VERSION,
            }
            for definition in HEARING_PROMPT_DEFINITIONS
        ]
        bundle_sha256 = sha256_hex(["hearing-prompt-bundle", 1, bundle_projection])
        if expected_bundle_sha256 is not None and expected_bundle_sha256 != bundle_sha256:
            raise PromptRenderError(PromptRenderFailureCode.PROMPT_BUNDLE_MISMATCH)

        self._loaded = loaded
        self._templates = templates
        self._output_schema_json_by_prompt = schema_documents
        self._schema_sha256_by_prompt = schema_sha256_by_prompt
        self._bundle_sha256 = bundle_sha256

    @property
    def bundle_sha256(self) -> Sha256Hex:
        return self._bundle_sha256

    def manifest(self, prompt_id: str) -> PromptManifest:
        loaded = self._loaded.get(prompt_id)
        if loaded is None:
            raise PromptRenderError(PromptRenderFailureCode.PROMPT_ID_UNKNOWN)
        return PromptManifest(
            prompt_id=prompt_id,
            role=loaded.definition.role,
            template_sha256=loaded.template_sha256,
            output_schema_sha256=self._schema_sha256_by_prompt[prompt_id],
            prompt_bundle_sha256=self._bundle_sha256,
            renderer_version=RENDERER_VERSION,
        )

    def render(
        self,
        *,
        prompt_id: str,
        variables: Mapping[str, str],
    ) -> RenderedPrompt:
        loaded = self._loaded.get(prompt_id)
        if loaded is None:
            raise PromptRenderError(PromptRenderFailureCode.PROMPT_ID_UNKNOWN)
        try:
            variable_snapshot = dict(variables)
        except (RuntimeError, TypeError, ValueError):
            raise PromptRenderError(PromptRenderFailureCode.PROMPT_VARIABLE_SET_INVALID) from None
        caller_names = set(loaded.definition.variable_names) - {"output_schema_json"}
        if set(variable_snapshot) != caller_names:
            raise PromptRenderError(PromptRenderFailureCode.PROMPT_VARIABLE_SET_INVALID)
        _require_canonical_json_values(
            variable_snapshot,
            failure_code=PromptRenderFailureCode.PROMPT_VARIABLE_NOT_CANONICAL_JSON,
        )
        bound_variables = {
            **variable_snapshot,
            "output_schema_json": self._output_schema_json_by_prompt[prompt_id],
        }
        try:
            text = self._templates[prompt_id].render(**bound_variables)
            rendered = text.encode("utf-8")
        except (TemplateError, UnicodeError):
            raise PromptRenderError(PromptRenderFailureCode.PROMPT_RENDER_FAILED) from None
        if len(rendered) > MAX_RENDERED_PROMPT_BYTES:
            raise PromptRenderError(PromptRenderFailureCode.PROMPT_RENDER_TOO_LARGE)
        return RenderedPrompt(
            manifest=self.manifest(prompt_id),
            rendered_prompt_sha256=hashlib.sha256(rendered).hexdigest(),
            text=text,
        )


__all__ = ["HEARING_PROMPT_DEFINITIONS", "HearingJinjaPromptCatalog"]

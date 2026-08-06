"""Strict, deterministic rendering of versioned LabCourt prompt artifacts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Final

import jinja2
from jinja2 import DictLoader, StrictUndefined, Template, TemplateError, meta, nodes
from jinja2.sandbox import SandboxedEnvironment

from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import VlmRole
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m3_models import PromptManifest
from labcourt.ports.prompts import (
    MAX_PROMPT_STRING_CHARS,
    MAX_PROMPT_VARIABLE_BYTES,
    PromptRenderError,
    PromptRenderFailureCode,
    RenderedPrompt,
)

RENDERER_VERSION: Final = "labcourt-jinja2-3.1.6-v1"
MAX_TEMPLATE_BYTES: Final = 65_536
MAX_RENDERED_PROMPT_BYTES: Final = 1_048_576
MAX_PROMPT_JSON_DEPTH: Final = 64
MAX_PROMPT_JSON_FIELDS: Final = 10_000


@dataclass(frozen=True, slots=True)
class PromptDefinition:
    prompt_id: str
    filename: str
    role: VlmRole
    variable_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _LoadedTemplate:
    definition: PromptDefinition
    template_sha256: Sha256Hex


PROMPT_DEFINITIONS: Final = (
    PromptDefinition(
        prompt_id="screening_presence_v1",
        filename="screening_presence_v1.jinja",
        role=VlmRole.SCREENING,
        variable_names=("evidence_json", "output_schema_json", "rules_json"),
    ),
    PromptDefinition(
        prompt_id="screening_absence_v1",
        filename="screening_absence_v1.jinja",
        role=VlmRole.SCREENING,
        variable_names=("evidence_json", "output_schema_json", "rules_json"),
    ),
    PromptDefinition(
        prompt_id="screening_structure_repair_v1",
        filename="screening_structure_repair_v1.jinja",
        role=VlmRole.STRUCTURE_REPAIR,
        variable_names=(
            "original_response_json",
            "output_schema_json",
            "parse_defects_json",
        ),
    ),
)

_DEFINITIONS_BY_ID: Final = {definition.prompt_id: definition for definition in PROMPT_DEFINITIONS}
_ALLOWED_AST_NODES: Final = (
    nodes.Template,
    nodes.Output,
    nodes.TemplateData,
    nodes.Name,
)


def _source_tree_prompt_root() -> Path:
    return Path(__file__).resolve().parents[3] / "prompts"


def _read_template_bytes(filename: str, template_root: Path | None) -> bytes:
    try:
        if template_root is not None:
            return (template_root / filename).read_bytes()

        packaged = resources.files("labcourt").joinpath("prompts", filename)
        if packaged.is_file():
            return packaged.read_bytes()
        return (_source_tree_prompt_root() / filename).read_bytes()
    except (OSError, TypeError):
        raise PromptRenderError(PromptRenderFailureCode.TEMPLATE_NOT_FOUND) from None


def _decode_template(raw: bytes) -> str:
    if not raw:
        raise PromptRenderError(PromptRenderFailureCode.TEMPLATE_EMPTY)
    if len(raw) > MAX_TEMPLATE_BYTES:
        raise PromptRenderError(PromptRenderFailureCode.TEMPLATE_TOO_LARGE)
    if raw.startswith(b"\xef\xbb\xbf"):
        raise PromptRenderError(PromptRenderFailureCode.TEMPLATE_ENCODING_INVALID)
    if b"\r" in raw:
        raise PromptRenderError(PromptRenderFailureCode.TEMPLATE_LINE_ENDING_INVALID)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise PromptRenderError(PromptRenderFailureCode.TEMPLATE_ENCODING_INVALID) from None


def _strict_environment(
    name: str,
    source: str,
    allowed_names: tuple[str, ...],
) -> SandboxedEnvironment:
    environment = SandboxedEnvironment(
        loader=DictLoader({name: source}),
        undefined=StrictUndefined,
        auto_reload=False,
        keep_trailing_newline=True,
        autoescape=False,
    )
    environment.globals.clear()
    environment.filters.clear()
    environment.tests.clear()
    try:
        parsed = environment.parse(source, name=name)
    except TemplateError:
        raise PromptRenderError(PromptRenderFailureCode.TEMPLATE_SYNTAX_INVALID) from None

    for node in parsed.find_all(nodes.Node):
        if not isinstance(node, _ALLOWED_AST_NODES):
            raise PromptRenderError(PromptRenderFailureCode.TEMPLATE_CONSTRUCT_FORBIDDEN)
        if isinstance(node, nodes.Name) and node.ctx != "load":
            raise PromptRenderError(PromptRenderFailureCode.TEMPLATE_CONSTRUCT_FORBIDDEN)
        if isinstance(node, nodes.Name) and node.name not in allowed_names:
            raise PromptRenderError(PromptRenderFailureCode.TEMPLATE_CONSTRUCT_FORBIDDEN)
    return environment


def _load_template(
    definition: PromptDefinition,
    *,
    template_root: Path | None,
) -> tuple[_LoadedTemplate, Template]:
    raw = _read_template_bytes(definition.filename, template_root)
    source = _decode_template(raw)
    environment = _strict_environment(
        definition.filename,
        source,
        definition.variable_names,
    )
    try:
        parsed = environment.parse(source, name=definition.filename)
    except TemplateError:
        raise PromptRenderError(PromptRenderFailureCode.TEMPLATE_SYNTAX_INVALID) from None
    variables = tuple(sorted(meta.find_undeclared_variables(parsed)))
    if variables != definition.variable_names:
        raise PromptRenderError(PromptRenderFailureCode.TEMPLATE_VARIABLE_SET_INVALID)
    try:
        template = environment.get_template(definition.filename)
    except TemplateError:
        raise PromptRenderError(PromptRenderFailureCode.TEMPLATE_SYNTAX_INVALID) from None
    return (
        _LoadedTemplate(
            definition=definition,
            template_sha256=hashlib.sha256(raw).hexdigest(),
        ),
        template,
    )


def _require_canonical_json_values(
    variables: Mapping[str, str],
    *,
    failure_code: PromptRenderFailureCode,
) -> None:
    for value in variables.values():
        if not isinstance(value, str):
            raise PromptRenderError(failure_code)
        try:
            encoded = value.encode("utf-8")
            if len(encoded) > MAX_PROMPT_VARIABLE_BYTES:
                raise ValueError
            decoded = json.loads(value)
            _validate_json_shape(decoded)
            canonical = canonical_json(decoded)
            canonical.encode("utf-8")
        except (OverflowError, RecursionError, TypeError, UnicodeError, ValueError):
            raise PromptRenderError(failure_code) from None
        if canonical != value:
            raise PromptRenderError(failure_code)


def _validate_json_shape(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 1)]
    field_count = 0
    while pending:
        current, depth = pending.pop()
        if depth > MAX_PROMPT_JSON_DEPTH:
            raise ValueError
        if isinstance(current, dict):
            field_count += len(current)
            if field_count > MAX_PROMPT_JSON_FIELDS:
                raise ValueError
            for key, child in current.items():
                if len(key) > MAX_PROMPT_STRING_CHARS:
                    raise ValueError
                pending.append((child, depth + 1))
        elif isinstance(current, list):
            field_count += len(current)
            if field_count > MAX_PROMPT_JSON_FIELDS:
                raise ValueError
            pending.extend((child, depth + 1) for child in current)
        elif isinstance(current, str) and len(current) > MAX_PROMPT_STRING_CHARS:
            raise ValueError


class JinjaPromptCatalog:
    """Loaded prompt authority with one reproducible bundle identity."""

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
        if set(schema_documents) != set(_DEFINITIONS_BY_ID):
            raise PromptRenderError(PromptRenderFailureCode.PROMPT_SCHEMA_SET_INVALID)
        _require_canonical_json_values(
            schema_documents,
            failure_code=PromptRenderFailureCode.PROMPT_SCHEMA_NOT_CANONICAL_JSON,
        )
        output_schema_sha256_by_prompt = {
            prompt_id: hashlib.sha256(schema.encode("utf-8")).hexdigest()
            for prompt_id, schema in schema_documents.items()
        }

        loaded: dict[str, _LoadedTemplate] = {}
        templates: dict[str, Template] = {}
        for definition in PROMPT_DEFINITIONS:
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
                "output_schema_sha256": output_schema_sha256_by_prompt[definition.prompt_id],
                "variable_names": list(definition.variable_names),
                "renderer_version": RENDERER_VERSION,
            }
            for definition in PROMPT_DEFINITIONS
        ]
        bundle_sha256 = sha256_hex(["prompt-bundle", 1, bundle_projection])
        if expected_bundle_sha256 is not None and expected_bundle_sha256 != bundle_sha256:
            raise PromptRenderError(PromptRenderFailureCode.PROMPT_BUNDLE_MISMATCH)

        self._loaded = loaded
        self._templates = templates
        self._output_schema_json_by_prompt = schema_documents
        self._output_schema_sha256_by_prompt = dict(output_schema_sha256_by_prompt)
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
            output_schema_sha256=self._output_schema_sha256_by_prompt[prompt_id],
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
        caller_variable_names = set(loaded.definition.variable_names) - {"output_schema_json"}
        if set(variable_snapshot) != caller_variable_names:
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


__all__ = [
    "MAX_PROMPT_JSON_DEPTH",
    "MAX_PROMPT_JSON_FIELDS",
    "MAX_PROMPT_STRING_CHARS",
    "MAX_PROMPT_VARIABLE_BYTES",
    "MAX_RENDERED_PROMPT_BYTES",
    "MAX_TEMPLATE_BYTES",
    "PROMPT_DEFINITIONS",
    "RENDERER_VERSION",
    "JinjaPromptCatalog",
    "PromptRenderError",
    "PromptRenderFailureCode",
    "RenderedPrompt",
]

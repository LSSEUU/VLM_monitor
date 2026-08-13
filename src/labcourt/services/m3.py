"""M3 composition helpers kept outside the application dependency boundary."""

from __future__ import annotations

import json
from typing import Final

from labcourt.adapters.jinja_prompt_renderer import (
    CITATION_REQUIRED_PROMPT_DEFINITIONS,
    LEGACY_PROMPT_DEFINITIONS,
    PROMPT_DEFINITIONS,
    JinjaPromptCatalog,
)
from labcourt.application.screening_request import (
    CITATION_REQUIRED_M3_PROMPT_BUNDLE_SHA256,
    FROZEN_M3_PROMPT_BUNDLE_SHA256,
    LEGACY_M3_PROMPT_BUNDLE_SHA256,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.manifests import RunManifest
from labcourt.exceptions import ManifestMismatch
from labcourt.ports.prompts import PromptCatalog
from labcourt.schema_export import expected_schema_files

_SCREENING_SCHEMA_FILENAME: Final = "screening-model-payload.schema.json"


def build_screening_prompt_catalog(run_manifest: RunManifest) -> PromptCatalog:
    """Assemble the frozen production prompt catalog for one run authority."""

    if not isinstance(run_manifest, RunManifest):
        raise TypeError("run_manifest must be a RunManifest")
    if run_manifest.prompt_bundle_sha256 == FROZEN_M3_PROMPT_BUNDLE_SHA256:
        definitions = PROMPT_DEFINITIONS
    elif run_manifest.prompt_bundle_sha256 == CITATION_REQUIRED_M3_PROMPT_BUNDLE_SHA256:
        definitions = CITATION_REQUIRED_PROMPT_DEFINITIONS
    elif run_manifest.prompt_bundle_sha256 == LEGACY_M3_PROMPT_BUNDLE_SHA256:
        definitions = LEGACY_PROMPT_DEFINITIONS
    else:
        definitions = None
    if definitions is None:
        raise ManifestMismatch("run manifest does not use the frozen M3 prompt bundle")

    schema_document = json.loads(expected_schema_files()[_SCREENING_SCHEMA_FILENAME])
    output_schema_json = canonical_json(schema_document)
    schemas = {definition.prompt_id: output_schema_json for definition in definitions}
    return JinjaPromptCatalog(
        output_schema_json_by_prompt=schemas,
        expected_bundle_sha256=run_manifest.prompt_bundle_sha256,
        definitions=definitions,
    )


__all__ = ["build_screening_prompt_catalog"]

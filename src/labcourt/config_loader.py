"""UTF-8 YAML loading with duplicate-key rejection."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import TypeAlias

import yaml
from pydantic import ValidationError
from yaml.events import AliasEvent
from yaml.nodes import MappingNode

from labcourt.contracts.config import AppConfig
from labcourt.exceptions import ContractViolation

YamlMapping: TypeAlias = dict[str, object]
MAX_CONFIG_BYTES = 1_048_576
_DEPLOYMENT_ENV_REFERENCE = re.compile(r"^\$\{([A-Z][A-Z0-9_]*)\}$")


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate and merge keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: MappingNode,
    deep: bool = False,
) -> YamlMapping:
    mapping: YamlMapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise ContractViolation("configuration mapping keys must be strings")
        if key == "<<":
            raise ContractViolation("YAML merge keys are not allowed in configuration")
        if key in mapping:
            raise ContractViolation(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _summarize_validation_error(exc: ValidationError) -> str:
    lines = ["configuration validation failed"]
    for error in exc.errors(include_input=False, include_url=False):
        location = ".".join(str(part) for part in error["loc"]) or "<root>"
        lines.append(f"- {location}: {error['msg']} [{error['type']}]")
    return "\n".join(lines)


def _reject_yaml_aliases(text: str) -> None:
    try:
        events = yaml.parse(text)
        if any(isinstance(event, AliasEvent) for event in events):
            raise ContractViolation("YAML aliases are not allowed in configuration")
    except ContractViolation:
        raise
    except yaml.YAMLError:
        # The authoritative parse below emits the sanitized line/column error.
        return


def _resolve_provider_deployment_environment(
    raw: YamlMapping,
    environment: Mapping[str, str],
) -> None:
    providers = raw.get("providers")
    if not isinstance(providers, dict):
        return
    for profile in providers.values():
        if not isinstance(profile, dict):
            continue
        for field in ("model", "revision"):
            value = profile.get(field)
            if not isinstance(value, str):
                continue
            matched = _DEPLOYMENT_ENV_REFERENCE.fullmatch(value)
            if matched is None:
                continue
            resolved = environment.get(matched.group(1))
            if not isinstance(resolved, str) or not resolved:
                raise ContractViolation("configuration deployment environment variable is missing")
            profile[field] = resolved


def load_config(
    path: str | Path,
    *,
    environment: Mapping[str, str] | None = None,
) -> AppConfig:
    config_path = Path(path)
    try:
        raw_bytes = config_path.read_bytes()
    except (OSError, UnicodeError):
        raise ContractViolation("cannot read configuration file") from None
    if len(raw_bytes) > MAX_CONFIG_BYTES:
        raise ContractViolation("configuration file exceeds the 1 MiB limit")
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeError:
        raise ContractViolation("configuration must be valid UTF-8") from None
    try:
        _reject_yaml_aliases(text)
        raw = yaml.load(text, Loader=_UniqueKeyLoader)
    except ContractViolation:
        raise
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        location = f" at line {mark.line + 1}, column {mark.column + 1}" if mark is not None else ""
        raise ContractViolation(f"invalid YAML{location}") from None
    if not isinstance(raw, dict):
        raise ContractViolation("configuration root must be a mapping")
    _resolve_provider_deployment_environment(
        raw,
        os.environ if environment is None else environment,
    )
    try:
        return AppConfig.model_validate(raw)
    except ValidationError as exc:
        raise ContractViolation(_summarize_validation_error(exc)) from None

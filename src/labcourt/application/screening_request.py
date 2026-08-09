"""Reproducible preparation of privacy-bounded M3 screening requests."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Final

from labcourt.contracts.backlog import BacklogRetryContext
from labcourt.contracts.base import Scalar
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.config import AppConfig, VlmProviderProfile
from labcourt.contracts.enums import (
    ArtifactKind,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    MediaAvailability,
    ObjectiveFactKind,
)
from labcourt.contracts.events import ObjectiveFact
from labcourt.contracts.evidence import Crop, EvidencePack
from labcourt.contracts.m3_models import VlmCallBudget
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.metadata import validate_safe_scalar_metadata
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.screening import VLMMediaRef, VLMRequest
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import (
    BudgetExceeded,
    ContractViolation,
    EvidenceMissing,
    ManifestMismatch,
    PrivacyPolicyViolation,
)
from labcourt.ports.prompts import PromptCatalog, RenderedPrompt

FROZEN_M3_PROMPT_BUNDLE_SHA256: Final = (
    "b6a7e737fb9942b41e1b5027a694ec3ee9db55a9a6705b5988d5a806b99291d7"
)
LEGACY_M3_PROMPT_BUNDLE_SHA256: Final = (
    "b6a7e737fb9942b41e1b5027a694ec3ee9db55a9a6705b5988d5a806b99291d7"
)
CITATION_REQUIRED_M3_PROMPT_BUNDLE_SHA256: Final = (
    "a2465fd6bcd0ef02834aeb0fb7ee6d9512ee2213515722e9a120caffd17c9e2a"
)
SUPPORTED_M3_PROMPT_BUNDLE_SHA256S: Final = frozenset(
    {
        FROZEN_M3_PROMPT_BUNDLE_SHA256,
        CITATION_REQUIRED_M3_PROMPT_BUNDLE_SHA256,
    }
)
SCREENING_PRESENCE_PROMPT_ID: Final = "screening_presence_v1"
SCREENING_ABSENCE_PROMPT_ID: Final = "screening_absence_v1"
_CITABLE_NON_MEDIA_KINDS: Final = frozenset(
    {
        ArtifactKind.FRAME,
        ArtifactKind.OBJECTIVE_FACT,
        ArtifactKind.TOOL_RESULT,
    }
)


@dataclass(frozen=True, slots=True)
class PreparedScreeningRequest:
    """A request and the exact immutable prompt bytes to register for its call."""

    request: VLMRequest
    rendered_prompt: RenderedPrompt

    def __post_init__(self) -> None:
        if not isinstance(self.request, VLMRequest):
            raise TypeError("request must be a VLMRequest")
        if not isinstance(self.rendered_prompt, RenderedPrompt):
            raise TypeError("rendered_prompt must be a RenderedPrompt")
        if self.request.prompt_manifest != self.rendered_prompt.manifest:
            raise ValueError("prepared request prompt manifest does not match rendered prompt")
        if self.request.rendered_prompt_sha256 != self.rendered_prompt.rendered_prompt_sha256:
            raise ValueError("prepared request does not bind the rendered prompt bytes")


def _validate_authorities(
    pack: EvidencePack,
    config: AppConfig,
    run_manifest: RunManifest,
    catalog: PromptCatalog,
) -> tuple[str, VlmProviderProfile]:
    if not isinstance(pack, EvidencePack):
        raise TypeError("pack must be an EvidencePack")
    if not isinstance(config, AppConfig):
        raise TypeError("config must be an AppConfig")
    if not isinstance(run_manifest, RunManifest):
        raise TypeError("run_manifest must be a RunManifest")
    if not isinstance(catalog, PromptCatalog):
        raise TypeError("catalog must implement PromptCatalog")

    prompt_id = (
        SCREENING_PRESENCE_PROMPT_ID
        if pack.event.evidence_class == EvidenceClass.PRESENCE
        else SCREENING_ABSENCE_PROMPT_ID
    )
    profile_name = config.screening.provider_profile
    profile = config.providers.get(profile_name)
    if profile is None:
        raise ManifestMismatch("screening request references an unknown provider profile")
    model_manifest = run_manifest.models.get("screening")
    if model_manifest is None:
        raise ManifestMismatch("run manifest has no screening model authority")
    decoding_limit = run_manifest.decoding_parameters.max_output_tokens

    checks = {
        "schema_version": config.schema_version == run_manifest.schema_version,
        "config_sha256": config.config_sha256 == run_manifest.config_sha256,
        "rule_version": config.rule_version == run_manifest.rule_version,
        "reproducibility_mode": (
            config.run.reproducibility_mode == run_manifest.reproducibility_mode
        ),
        "random_seed": config.run.random_seed == run_manifest.random_seed,
        "privacy_transform_version": (
            config.evidence.privacy_transform_version == run_manifest.privacy_transform_version
        ),
        "image_encoding_version": (
            config.evidence.encoding_version == run_manifest.image_encoding_version
        ),
        "event.rule_version": pack.event.rule_version == run_manifest.rule_version,
        "manifest_id": pack.manifest_id == run_manifest.manifest_id,
        "event.manifest_id": pack.event.manifest_id == run_manifest.manifest_id,
        "prompt_bundle_sha256": (
            run_manifest.prompt_bundle_sha256 in SUPPORTED_M3_PROMPT_BUNDLE_SHA256S
            and catalog.bundle_sha256 == run_manifest.prompt_bundle_sha256
        ),
        "screening.component": model_manifest.component == "screening",
        "screening.provider": model_manifest.provider == profile.provider,
        "screening.model": model_manifest.model == profile.model,
        "screening.revision": model_manifest.revision == profile.revision,
        "screening.quantization": model_manifest.quantization == profile.quantization,
        "screening.timeout": config.screening.timeout_seconds <= profile.timeout_seconds,
        "screening.max_output_tokens": (
            decoding_limit is None or config.screening.max_output_tokens <= decoding_limit
        ),
    }
    mismatches = tuple(sorted(name for name, matches in checks.items() if not matches))
    if mismatches:
        raise ManifestMismatch(f"screening request authority mismatch: {', '.join(mismatches)}")
    if not pack.complete:
        raise EvidenceMissing("screening requires a complete evidence pack")
    return prompt_id, profile


def _policy_allowed_crops(
    pack: EvidencePack,
    profile: VlmProviderProfile,
) -> tuple[Crop, ...]:
    available = tuple(
        crop for crop in pack.crops if crop.availability == MediaAvailability.AVAILABLE
    )
    if not available:
        raise EvidenceMissing("screening evidence contains no available crop media")

    def policy_allows(crop: Crop) -> bool:
        if crop.source == CropSource.PANORAMA and not profile.allow_full_frame:
            return False
        if profile.execution_location == ExecutionLocation.EXTERNAL:
            return (
                crop.source != CropSource.PANORAMA
                and crop.privacy_receipt.media_access == MediaAccess.CLOUD_ALLOWED
            )
        return True

    selected = tuple(sorted(filter(policy_allows, available), key=lambda crop: crop.crop_id))
    if not selected:
        raise PrivacyPolicyViolation(
            "no available crop satisfies the screening provider privacy policy"
        )
    return selected


def _validate_crop_manifest(crops: tuple[Crop, ...], run_manifest: RunManifest) -> None:
    if any(
        crop.privacy_receipt.transform_version != run_manifest.privacy_transform_version
        for crop in crops
    ):
        raise ManifestMismatch("screening crop privacy transform does not match the run manifest")
    if any(crop.encoding_version != run_manifest.image_encoding_version for crop in crops):
        raise ManifestMismatch("screening crop encoding does not match the run manifest")


def _call_budget(config: AppConfig, profile: VlmProviderProfile) -> VlmCallBudget:
    screening = config.screening
    return VlmCallBudget(
        max_images=screening.max_images,
        max_input_pixels=screening.max_input_pixels,
        max_prompt_bytes=screening.max_prompt_bytes,
        max_input_tokens=screening.max_input_tokens,
        max_output_tokens=screening.max_output_tokens,
        pricing_currency=profile.pricing_currency,
        input_cost_per_million_tokens=profile.input_cost_per_million_tokens,
        output_cost_per_million_tokens=profile.output_cost_per_million_tokens,
        max_estimated_cost=screening.max_estimated_cost,
        max_response_bytes=screening.max_response_bytes,
        max_json_depth=screening.max_json_depth,
        max_json_fields=screening.max_json_fields,
        max_string_chars=screening.max_string_chars,
        timeout_seconds=screening.timeout_seconds,
    )


def _preflight_media_budget(crops: tuple[Crop, ...], budget: VlmCallBudget) -> None:
    if len(crops) > budget.max_images:
        raise BudgetExceeded("screening crop count exceeds the configured image budget")
    pixels = sum(crop.output_width * crop.output_height for crop in crops)
    if pixels > budget.max_input_pixels:
        raise BudgetExceeded("screening crop pixels exceed the configured input budget")


def _media_refs(pack: EvidencePack, crops: tuple[Crop, ...]) -> tuple[VLMMediaRef, ...]:
    media: list[VLMMediaRef] = []
    for crop in crops:
        expected_path = f"{pack.run_id}/frames/{crop.media_sha256}.png"
        if crop.local_path != expected_path:
            raise ContractViolation("screening crop does not use its canonical run media locator")
        media.append(
            VLMMediaRef(
                crop_id=crop.crop_id,
                media_sha256=crop.media_sha256,
                local_path=expected_path,
                source=crop.source,
                media_access=crop.privacy_receipt.media_access,
                privacy_policy=crop.privacy_receipt.policy,
                privacy_transform_version=crop.privacy_receipt.transform_version,
                width=crop.output_width,
                height=crop.output_height,
            )
        )
    return tuple(media)


def _allowed_evidence_refs(
    pack: EvidencePack,
    crops: tuple[Crop, ...],
) -> tuple[ArtifactRef, ...]:
    refs = {
        ref.sort_key: ref
        for ref in pack.expected_closure_refs()
        if ref.kind in _CITABLE_NON_MEDIA_KINDS
    }
    for crop in crops:
        ref = ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id)
        refs[ref.sort_key] = ref
    return tuple(refs[key] for key in sorted(refs))


def _objective_summary(facts: tuple[ObjectiveFact, ...]) -> dict[str, Scalar]:
    kind_counts = Counter(fact.kind for fact in facts)
    seen: Counter[object] = Counter()
    summary: dict[str, Scalar] = {}
    for fact in facts:
        if fact.kind == ObjectiveFactKind.ZONE_ID:
            try:
                require_reference_token(str(fact.value), "objective zone reference")
            except (TypeError, ValueError):
                raise ContractViolation(
                    "objective fact contains an unsafe zone reference"
                ) from None
        seen[fact.kind] += 1
        suffix = f"_{seen[fact.kind]}" if kind_counts[fact.kind] > 1 else ""
        key = f"{fact.kind.value.lower()}{suffix}"
        if isinstance(fact.value, tuple):
            summary[f"{key}_start"] = fact.value[0]
            summary[f"{key}_end_exclusive"] = fact.value[1]
        else:
            summary[key] = fact.value
    if len(summary) > 32:
        raise ContractViolation("objective fact summary exceeds its scalar metadata budget")
    try:
        validate_safe_scalar_metadata(summary)
    except (TypeError, ValueError):
        raise ContractViolation("objective fact summary contains unsafe scalar metadata") from None
    return summary


def _rules_projection(pack: EvidencePack, config: AppConfig) -> dict[str, object]:
    matching_zones = tuple(
        zone
        for zone in config.zones
        if zone.zone_id == pack.event.zone_id and zone.camera_id == pack.event.camera_id
    )
    if len(matching_zones) != 1:
        raise ContractViolation("screening event has no unique configured zone authority")
    zone = matching_zones[0]
    rules: dict[str, object] = {
        "evidence_class": pack.event.evidence_class.value,
        "rule_version": config.rule_version,
        "screening_probability_band": {
            "high": config.screening.high_probability,
            "low": config.screening.low_probability,
        },
        "violation_type": pack.event.violation_type.value,
        "zone": {
            "required_ppe": [item.value for item in zone.required_ppe],
            "risk_level": zone.risk_level.value,
            "zone_id": zone.zone_id,
        },
    }
    if pack.event.evidence_class == EvidenceClass.ABSENCE:
        rules["absence"] = {
            "confirmation_policy": config.absence.confirmation_policy.value,
            "minimum_consistent_clear_frames": (config.absence.minimum_consistent_clear_frames),
            "observability_clear_threshold": (
                config.perception.observability.clear_frame_threshold
            ),
            "required_dwell_seconds": config.absence.dwell_seconds_by_risk[zone.risk_level],
        }
    else:
        rules["presence"] = {
            "default_dwell_seconds": config.presence.default_dwell_seconds,
        }
    return rules


def _artifact_projection(ref: ArtifactRef) -> dict[str, str]:
    return {"artifact_id": ref.artifact_id, "kind": ref.kind.value}


def _evidence_projection(
    pack: EvidencePack,
    crops: tuple[Crop, ...],
    allowed_refs: tuple[ArtifactRef, ...],
) -> dict[str, object]:
    selected_ids = {crop.crop_id for crop in crops}
    authority = pack.observation_sufficiency_input
    sufficiency: dict[str, object] | None = None
    if authority is not None:
        sufficiency = {
            "authoritative_clear_crop_ids": sorted(
                selected_ids.intersection(authority.clear_crop_ids)
            ),
            "authoritative_unclear_crop_ids": sorted(
                selected_ids.intersection(authority.unclear_crop_ids)
            ),
            "clear_threshold": authority.clear_threshold,
            "required_clear_count": authority.required_clear_count,
            "selected_by_observability": authority.selected_by_observability,
        }

    return {
        "allowed_evidence_refs": [_artifact_projection(ref) for ref in allowed_refs],
        "case": {
            "case_id": pack.case_id,
            "evidence_pack_id": pack.pack_id,
            "evidence_pack_version": pack.version,
        },
        "confirmation": {
            "counterevidence_frame_ids": list(pack.confirmation_record.counterevidence_frame_ids),
            "examined_frame_ids": list(pack.confirmation_record.examined_frame_ids),
            "policy": pack.confirmation_record.policy.value,
            "post_threshold_recovery_frame_id": (
                pack.confirmation_record.post_threshold_recovery_frame_id
            ),
        },
        "event": {
            "end_frame_exclusive": pack.event.end_frame_exclusive,
            "evidence_class": pack.event.evidence_class.value,
            "event_id": pack.event.event_id,
            "hard_rule": pack.event.hard_rule,
            "l1_score": pack.event.l1_score,
            "primary_track_ref": pack.event.primary_track_ref,
            "start_frame": pack.event.start_frame,
            "trigger_frame": pack.event.trigger_frame,
            "violation_type": pack.event.violation_type.value,
            "zone_id": pack.event.zone_id,
        },
        "key_frame_ids": list(pack.key_frame_ids),
        "media": [
            {
                "crop_id": crop.crop_id,
                "frame_id": crop.frame_id,
                "height": crop.output_height,
                "media_access": crop.privacy_receipt.media_access.value,
                "media_ordinal": index,
                "media_sha256": crop.media_sha256,
                "observability_total": (
                    crop.observability.total if crop.observability is not None else None
                ),
                "privacy_policy": crop.privacy_receipt.policy.value,
                "privacy_transform_version": crop.privacy_receipt.transform_version,
                "source": crop.source.value,
                "width": crop.output_width,
            }
            for index, crop in enumerate(crops)
        ],
        "objective_facts": [
            {
                "fact_id": fact.fact_id,
                "kind": fact.kind.value,
                "value": fact.value,
            }
            for fact in pack.objective_facts
        ],
        "observation_sufficiency": sufficiency,
        "tool_results": [
            {"action": result.action.value, "tool_result_id": result.tool_result_id}
            for result in pack.tool_results
        ],
        "track_summary": pack.track_summary.model_dump(mode="json"),
    }


def prepare_screening_request(
    pack: EvidencePack,
    config: AppConfig,
    run_manifest: RunManifest,
    catalog: PromptCatalog,
    *,
    backlog_retry_context: BacklogRetryContext | None = None,
) -> PreparedScreeningRequest:
    """Prepare one deterministic screening call without reading media or the network."""

    prompt_id, profile = _validate_authorities(pack, config, run_manifest, catalog)
    crops = _policy_allowed_crops(pack, profile)
    _validate_crop_manifest(crops, run_manifest)
    budget = _call_budget(config, profile)
    _preflight_media_budget(crops, budget)
    media = _media_refs(pack, crops)
    allowed_refs = _allowed_evidence_refs(pack, crops)
    objective_summary = _objective_summary(pack.objective_facts)

    rules_json = canonical_json(_rules_projection(pack, config))
    evidence_json = canonical_json(_evidence_projection(pack, crops, allowed_refs))
    rendered_prompt = catalog.render(
        prompt_id=prompt_id,
        variables={
            "evidence_json": evidence_json,
            "rules_json": rules_json,
        },
    )
    if len(rendered_prompt.utf8_bytes) > budget.max_prompt_bytes:
        raise BudgetExceeded("screening rendered prompt exceeds the configured prompt byte budget")
    if rendered_prompt.manifest.prompt_bundle_sha256 != run_manifest.prompt_bundle_sha256:
        raise ManifestMismatch("rendered screening prompt uses another prompt bundle")

    model_manifest = run_manifest.models["screening"]
    request = VLMRequest(
        run_id=pack.run_id,
        case_id=pack.case_id,
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        provider_profile=config.screening.provider_profile,
        provider=profile.provider,
        model=profile.model,
        revision=profile.revision,
        model_manifest_id=model_manifest.model_manifest_id,
        execution_location=profile.execution_location,
        prompt_manifest=rendered_prompt.manifest,
        rendered_prompt_sha256=rendered_prompt.rendered_prompt_sha256,
        violation_type=pack.event.violation_type,
        evidence_class=pack.event.evidence_class,
        rule_summary=rules_json,
        media=media,
        allowed_evidence_refs=allowed_refs,
        objective_summary=objective_summary,
        temperature=run_manifest.decoding_parameters.temperature,
        seed=run_manifest.decoding_parameters.seed,
        enable_thinking=profile.enable_thinking,
        budget=budget,
        backlog_retry_context=backlog_retry_context,
        manifest_id=run_manifest.manifest_id,
    )
    return PreparedScreeningRequest(request=request, rendered_prompt=rendered_prompt)


__all__ = [
    "CITATION_REQUIRED_M3_PROMPT_BUNDLE_SHA256",
    "FROZEN_M3_PROMPT_BUNDLE_SHA256",
    "LEGACY_M3_PROMPT_BUNDLE_SHA256",
    "SCREENING_ABSENCE_PROMPT_ID",
    "SCREENING_PRESENCE_PROMPT_ID",
    "SUPPORTED_M3_PROMPT_BUNDLE_SHA256S",
    "PreparedScreeningRequest",
    "prepare_screening_request",
]

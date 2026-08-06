"""M6 source-inventory cut and candidate-safe execution catalog contracts.

The evaluator first freezes the complete source universe.  The candidate then
receives a separate catalog containing only replay inputs and physical source
seal references; baseline semantics, membership, truth, challenge labels, and
selection policy cannot be represented by the candidate-facing contract.
"""

from __future__ import annotations

import hashlib
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m6_regression import MAX_M6_REGRESSION_CASES
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M6_REGRESSION_SOURCE_DOCUMENT_BYTES = 64 * 1024 * 1024


def require_m6_opaque_sample_id(value: str) -> str:
    """Require a label-free, fixed-width sample identifier at publication."""

    require_reference_token(value, "M6 opaque regression sample_id")
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("M6 regression sample_id must be an opaque lowercase SHA-256 token")
    return value


def _pop_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M6 dataset authority")


def _content_identity(value: FrozenContractModel) -> tuple[str, int]:
    payload = canonical_json(value.model_dump(mode="json")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(payload)


class M6RegressionSourceRunCut(FrozenContractModel):
    """One validated run scope from the immutable evaluator snapshot."""

    source_run_id: ReferenceToken
    baseline_manifest_id: Sha256Hex
    source_config_sha256: Sha256Hex
    audit_head_sequence: int = Field(ge=-1, strict=True)
    audit_head_hash: Sha256Hex
    m5_validation_report_id: Sha256Hex
    m5_validation_report_content_sha256: Sha256Hex
    m5_authority_root_sha256: Sha256Hex
    source_item_count: int = Field(gt=0, le=MAX_M6_REGRESSION_CASES, strict=True)
    source_scope_root_sha256: Sha256Hex

    @field_validator("source_run_id")
    @classmethod
    def validate_source_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 regression source run")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_run_cut_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("run_cut_id",))
        cut = handler(payload)
        _verify_claims(cut, claims)
        return cut

    @computed_field  # type: ignore[prop-decorator]
    @property
    def run_cut_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-source-run-cut",
                1,
                self.source_run_id,
                self.baseline_manifest_id,
                self.source_config_sha256,
                self.audit_head_sequence,
                self.audit_head_hash,
                self.m5_validation_report_id,
                self.m5_validation_report_content_sha256,
                self.m5_authority_root_sha256,
                self.source_item_count,
                self.source_scope_root_sha256,
            ]
        )


class M6RegressionSourceInventoryItem(FrozenContractModel):
    """One exact historical Case and its already-committed replay source seal."""

    sample_id: ReferenceToken
    source_run_id: ReferenceToken
    source_case_id: ReferenceToken
    source_case_revision: int = Field(gt=0, strict=True)
    source_case_document_sha256: Sha256Hex
    source_manifest_id: Sha256Hex
    sealed_source_validation_report_id: Sha256Hex
    sealed_source_validation_report_document_sha256: Sha256Hex
    sealed_source_m5_authority_root_sha256: Sha256Hex
    sealed_audit_head_sequence: int = Field(ge=-1, strict=True)
    sealed_audit_head_hash: Sha256Hex
    source_seal_id: Sha256Hex
    source_seal_content_sha256: Sha256Hex
    source_seal_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REGRESSION_SOURCE_DOCUMENT_BYTES,
        strict=True,
    )
    input_authority_id: Sha256Hex
    input_authority_document_sha256: Sha256Hex
    input_authority_content_sha256: Sha256Hex
    input_authority_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REGRESSION_SOURCE_DOCUMENT_BYTES,
        strict=True,
    )
    replay_input_closure_authority_id: Sha256Hex
    replay_input_closure_document_sha256: Sha256Hex
    replay_input_closure_content_sha256: Sha256Hex
    replay_input_closure_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REGRESSION_SOURCE_DOCUMENT_BYTES,
        strict=True,
    )

    @field_validator("sample_id")
    @classmethod
    def validate_sample_id(cls, value: str) -> str:
        return require_m6_opaque_sample_id(value)

    @field_validator("source_run_id", "source_case_id")
    @classmethod
    def validate_source_references(cls, value: str) -> str:
        return require_reference_token(value, "M6 regression source inventory reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_source_item_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("source_item_id",))
        item = handler(payload)
        _verify_claims(item, claims)
        return item

    @property
    def source_scope_key(self) -> tuple[str, str, int, str]:
        return (
            self.source_run_id,
            self.source_case_id,
            self.source_case_revision,
            self.source_case_document_sha256,
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_item_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-source-inventory-item",
                1,
                self.sample_id,
                self.source_scope_key,
                self.source_manifest_id,
                self.sealed_source_validation_report_id,
                self.sealed_source_validation_report_document_sha256,
                self.sealed_source_m5_authority_root_sha256,
                self.sealed_audit_head_sequence,
                self.sealed_audit_head_hash,
                self.source_seal_id,
                self.source_seal_content_sha256,
                self.source_seal_size_bytes,
                self.input_authority_id,
                self.input_authority_document_sha256,
                self.input_authority_content_sha256,
                self.input_authority_size_bytes,
                self.replay_input_closure_authority_id,
                self.replay_input_closure_document_sha256,
                self.replay_input_closure_content_sha256,
                self.replay_input_closure_size_bytes,
            ]
        )


class M6RegressionSourceInventoryCutAuthority(FrozenContractModel):
    """Complete bounded source universe before any candidate execution exists."""

    schema_version: Literal["m6-regression-source-inventory-cut-v1"] = (
        "m6-regression-source-inventory-cut-v1"
    )
    baseline_manifest_id: Sha256Hex
    run_cuts: tuple[M6RegressionSourceRunCut, ...] = Field(
        min_length=1,
        max_length=MAX_M6_REGRESSION_CASES,
    )
    items: tuple[M6RegressionSourceInventoryItem, ...] = Field(
        min_length=1,
        max_length=MAX_M6_REGRESSION_CASES,
    )

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "source_run_ids",
                "source_item_count",
                "source_inventory_root_sha256",
                "source_inventory_cut_authority_id",
            ),
        )
        cut = handler(payload)
        _verify_claims(cut, claims)
        return cut

    @staticmethod
    def _run_scope_root(
        run_id: str,
        items: tuple[M6RegressionSourceInventoryItem, ...],
    ) -> str:
        return sha256_hex(
            [
                "m6-regression-source-run-scope",
                1,
                run_id,
                [item.source_scope_key for item in items],
            ]
        )

    @model_validator(mode="after")
    def validate_complete_inventory(self) -> Self:
        canonical_run_cuts = tuple(
            M6RegressionSourceRunCut.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in self.run_cuts
        )
        canonical_items = tuple(
            M6RegressionSourceInventoryItem.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in self.items
        )
        if canonical_run_cuts != self.run_cuts or canonical_items != self.items:
            raise ValueError("M6 source inventory contains non-canonical nested authorities")

        run_ids = tuple(item.source_run_id for item in canonical_run_cuts)
        if run_ids != tuple(sorted(run_ids)) or len(run_ids) != len(set(run_ids)):
            raise ValueError("M6 source run cuts must be unique and use stable order")
        sample_ids = tuple(item.sample_id for item in canonical_items)
        if sample_ids != tuple(sorted(sample_ids)) or len(sample_ids) != len(set(sample_ids)):
            raise ValueError("M6 source inventory sample_ids must be unique and ordered")
        if any(item.source_manifest_id != self.baseline_manifest_id for item in canonical_items):
            raise ValueError("M6 source inventory contains another baseline manifest")
        if any(
            item.baseline_manifest_id != self.baseline_manifest_id for item in canonical_run_cuts
        ):
            raise ValueError("M6 source run cut contains another baseline manifest")

        for values, label in (
            (
                tuple((item.source_run_id, item.source_case_id) for item in canonical_items),
                "source Cases",
            ),
            (tuple(item.source_seal_id for item in canonical_items), "source seals"),
            (tuple(item.input_authority_id for item in canonical_items), "input authorities"),
            (
                tuple(item.replay_input_closure_authority_id for item in canonical_items),
                "input closures",
            ),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"M6 source inventory {label} must be unique")

        by_run = {
            run_id: tuple(item for item in canonical_items if item.source_run_id == run_id)
            for run_id in run_ids
        }
        if set(by_run) != {item.source_run_id for item in canonical_items}:
            raise ValueError("M6 source run cuts and inventory scopes differ")
        for run_cut in canonical_run_cuts:
            scoped = by_run[run_cut.source_run_id]
            if run_cut.source_item_count != len(
                scoped
            ) or run_cut.source_scope_root_sha256 != self._run_scope_root(
                run_cut.source_run_id, scoped
            ):
                raise ValueError("M6 source run cut does not cover its exact Case inventory")
            if any(
                (
                    item.sealed_source_validation_report_id,
                    item.sealed_source_validation_report_document_sha256,
                    item.sealed_source_m5_authority_root_sha256,
                    item.sealed_audit_head_sequence,
                    item.sealed_audit_head_hash,
                )
                != (
                    run_cut.m5_validation_report_id,
                    run_cut.m5_validation_report_content_sha256,
                    run_cut.m5_authority_root_sha256,
                    run_cut.audit_head_sequence,
                    run_cut.audit_head_hash,
                )
                for item in scoped
            ):
                raise ValueError("M6 source run cut and sealed sources use different snapshots")
        object.__setattr__(self, "run_cuts", canonical_run_cuts)
        object.__setattr__(self, "items", canonical_items)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_run_ids(self) -> tuple[str, ...]:
        return tuple(item.source_run_id for item in self.run_cuts)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_item_count(self) -> int:
        return len(self.items)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-source-inventory",
                1,
                [item.source_item_id for item in self.items],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_inventory_cut_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-source-inventory-cut",
                1,
                self.baseline_manifest_id,
                [item.run_cut_id for item in self.run_cuts],
                self.source_inventory_root_sha256,
            ]
        )


class M6RegressionExecutionSourceCatalogEntry(FrozenContractModel):
    """Candidate-safe replay source with no evaluator-only classifications."""

    source_item_id: Sha256Hex
    sample_id: ReferenceToken
    source_seal_id: Sha256Hex
    source_seal_content_sha256: Sha256Hex
    source_seal_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REGRESSION_SOURCE_DOCUMENT_BYTES,
        strict=True,
    )
    input_authority_id: Sha256Hex
    input_authority_document_sha256: Sha256Hex
    input_authority_content_sha256: Sha256Hex
    input_authority_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REGRESSION_SOURCE_DOCUMENT_BYTES,
        strict=True,
    )
    replay_input_closure_content_sha256: Sha256Hex
    replay_input_closure_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REGRESSION_SOURCE_DOCUMENT_BYTES,
        strict=True,
    )
    replay_input_closure: M6ReplayInputClosureAuthority

    @field_validator("sample_id")
    @classmethod
    def validate_sample_id(cls, value: str) -> str:
        return require_m6_opaque_sample_id(value)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_catalog_entry_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("catalog_entry_id",))
        entry = handler(payload)
        _verify_claims(entry, claims)
        return entry

    @model_validator(mode="after")
    def validate_closure_binding(self) -> Self:
        closure = M6ReplayInputClosureAuthority.model_validate(
            self.replay_input_closure.model_dump(
                mode="json",
                exclude_computed_fields=True,
            )
        )
        content_sha256, size_bytes = _content_identity(closure)
        if closure != self.replay_input_closure:
            raise ValueError("M6 execution source catalog contains a non-canonical closure")
        if (
            closure.sample_id != self.sample_id
            or closure.input_authority_id != self.input_authority_id
            or closure.input_authority_document_sha256 != self.input_authority_document_sha256
            or content_sha256 != self.replay_input_closure_content_sha256
            or size_bytes != self.replay_input_closure_size_bytes
        ):
            raise ValueError("M6 execution source catalog closure binding differs")
        object.__setattr__(self, "replay_input_closure", closure)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def catalog_entry_id(self) -> Sha256Hex:
        closure = self.replay_input_closure
        return sha256_hex(
            [
                "m6-regression-execution-source-catalog-entry",
                1,
                self.source_item_id,
                self.sample_id,
                self.source_seal_id,
                self.source_seal_content_sha256,
                self.source_seal_size_bytes,
                self.input_authority_id,
                self.input_authority_document_sha256,
                self.input_authority_content_sha256,
                self.input_authority_size_bytes,
                closure.replay_input_closure_authority_id,
                closure.replay_input_closure_document_sha256,
                self.replay_input_closure_content_sha256,
                self.replay_input_closure_size_bytes,
            ]
        )


class M6RegressionExecutionSourceCatalogAuthority(FrozenContractModel):
    """Full candidate-facing source catalog, deliberately free of evaluator truth."""

    schema_version: Literal["m6-regression-execution-source-catalog-v1"] = (
        "m6-regression-execution-source-catalog-v1"
    )
    baseline_manifest_id: Sha256Hex
    source_inventory_cut_authority_id: Sha256Hex
    source_inventory_cut_content_sha256: Sha256Hex
    source_inventory_item_count: int = Field(
        gt=0,
        le=MAX_M6_REGRESSION_CASES,
        strict=True,
    )
    source_inventory_root_sha256: Sha256Hex
    entries: tuple[M6RegressionExecutionSourceCatalogEntry, ...] = Field(
        min_length=1,
        max_length=MAX_M6_REGRESSION_CASES,
    )

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "entry_count",
                "catalog_inventory_root_sha256",
                "source_catalog_authority_id",
            ),
        )
        catalog = handler(payload)
        _verify_claims(catalog, claims)
        return catalog

    @model_validator(mode="after")
    def validate_catalog_inventory(self) -> Self:
        canonical_entries = tuple(
            M6RegressionExecutionSourceCatalogEntry.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in self.entries
        )
        if canonical_entries != self.entries:
            raise ValueError("M6 execution source catalog entries are not canonical")
        sample_ids = tuple(item.sample_id for item in canonical_entries)
        if sample_ids != tuple(sorted(sample_ids)) or len(sample_ids) != len(set(sample_ids)):
            raise ValueError("M6 execution source catalog sample_ids must be unique and ordered")
        for values, label in (
            (tuple(item.source_item_id for item in canonical_entries), "source items"),
            (tuple(item.source_seal_id for item in canonical_entries), "source seals"),
            (tuple(item.input_authority_id for item in canonical_entries), "input authorities"),
            (
                tuple(
                    item.replay_input_closure.replay_input_closure_authority_id
                    for item in canonical_entries
                ),
                "input closures",
            ),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"M6 execution source catalog {label} must be unique")
        if self.source_inventory_item_count != len(canonical_entries):
            raise ValueError("M6 execution source catalog omits part of the source inventory")
        expected_source_root = sha256_hex(
            [
                "m6-regression-source-inventory",
                1,
                [item.source_item_id for item in canonical_entries],
            ]
        )
        if self.source_inventory_root_sha256 != expected_source_root:
            raise ValueError("M6 execution source catalog source inventory root differs")
        if any(
            item.replay_input_closure.source_manifest_id != self.baseline_manifest_id
            for item in canonical_entries
        ):
            raise ValueError("M6 execution source catalog contains another baseline manifest")
        object.__setattr__(self, "entries", canonical_entries)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def entry_count(self) -> int:
        return len(self.entries)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def catalog_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-execution-source-catalog-inventory",
                1,
                [item.catalog_entry_id for item in self.entries],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_catalog_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-execution-source-catalog",
                1,
                self.baseline_manifest_id,
                self.source_inventory_cut_authority_id,
                self.source_inventory_cut_content_sha256,
                self.source_inventory_item_count,
                self.source_inventory_root_sha256,
                self.catalog_inventory_root_sha256,
            ]
        )


__all__ = [
    "MAX_M6_REGRESSION_SOURCE_DOCUMENT_BYTES",
    "M6RegressionExecutionSourceCatalogAuthority",
    "M6RegressionExecutionSourceCatalogEntry",
    "M6RegressionSourceInventoryCutAuthority",
    "M6RegressionSourceInventoryItem",
    "M6RegressionSourceRunCut",
    "require_m6_opaque_sample_id",
]

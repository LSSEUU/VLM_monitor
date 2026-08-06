"""Typed, candidate-blind authority closure for M6 locked replay.

The contracts in this module describe the exact historical inputs that a
``REPLAY_LOCKED`` executor may consume.  Inventory counts and roots are always
derived from typed, stably ordered bindings; callers cannot supply aggregate
claims independently of the per-artifact evidence.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self, TypeVar

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
from labcourt.contracts.references import (
    FrameId,
    ReferenceToken,
    parse_frame_id,
    require_reference_token,
)

MAX_M6_LOCKED_FRAMES_PER_CASE = 100_000
MAX_M6_LOCKED_DETECTIONS_PER_CASE = 250_000
MAX_M6_LOCKED_MODEL_CALLS_PER_CASE = 256
MAX_M6_LOCKED_EMBEDDINGS_PER_CASE = 4_096
MAX_M6_LOCKED_TOOL_RESULTS_PER_CASE = 64
MAX_M6_LOCKED_PRECEDENT_CUT_ITEMS = 64

_CanonicalModelT = TypeVar("_CanonicalModelT", bound=FrozenContractModel)


class M6ReplayAuthorityKind(StrEnum):
    RUN_MANIFEST = "RUN_MANIFEST"
    CASE_VERSION = "CASE_VERSION"
    EVIDENCE_PACK = "EVIDENCE_PACK"
    FRAME = "FRAME"
    DETECTION = "DETECTION"
    M3_MODEL_REQUEST = "M3_MODEL_REQUEST"
    M3_MODEL_RESPONSE = "M3_MODEL_RESPONSE"
    M3_MODEL_CACHE = "M3_MODEL_CACHE"
    M3_PARSE_RECEIPT = "M3_PARSE_RECEIPT"
    M3_PARSED_OUTPUT = "M3_PARSED_OUTPUT"
    M3_MODEL_CALL_FAILURE = "M3_MODEL_CALL_FAILURE"
    M4_MODEL_REQUEST = "M4_MODEL_REQUEST"
    M4_MODEL_RESPONSE = "M4_MODEL_RESPONSE"
    M4_MODEL_CACHE = "M4_MODEL_CACHE"
    M4_PARSE_RECEIPT = "M4_PARSE_RECEIPT"
    M4_ROLE_OUTPUT = "M4_ROLE_OUTPUT"
    M4_PRECEDENT_RETRIEVAL_RECEIPT = "M4_PRECEDENT_RETRIEVAL_RECEIPT"
    M4_MODEL_CALL_FAILURE = "M4_MODEL_CALL_FAILURE"
    M4_ACQUISITION_REQUEST = "M4_ACQUISITION_REQUEST"
    M4_TOOL_EXECUTION_MANIFEST = "M4_TOOL_EXECUTION_MANIFEST"
    M4_ACQUISITION_PUBLICATION = "M4_ACQUISITION_PUBLICATION"
    M4_TOOL_EXECUTION_RECEIPT = "M4_TOOL_EXECUTION_RECEIPT"
    M4_EVIDENCE_PACK_DERIVATION = "M4_EVIDENCE_PACK_DERIVATION"
    M5_EMBEDDING = "M5_EMBEDDING"
    M5_PRECEDENT_EXPOSURE = "M5_PRECEDENT_EXPOSURE"


class M6LockedModelCallLayer(StrEnum):
    SCREENING = "SCREENING"
    HEARING = "HEARING"


class M6LockedModelRole(StrEnum):
    SCREENING = "SCREENING"
    PROSECUTOR = "PROSECUTOR"
    DEFENDER = "DEFENDER"
    JUDGE = "JUDGE"


class M6LockedModelCallResultKind(StrEnum):
    RESPONSE = "RESPONSE"
    FAILURE = "FAILURE"


class M6LockedRetrievalOutcomeKind(StrEnum):
    SUCCESS = "SUCCESS"
    DEGRADED = "DEGRADED"


class M6LockedEmbeddingScope(StrEnum):
    QUERY = "QUERY"
    PRECEDENT = "PRECEDENT"


class M6LockedEmbeddingChannel(StrEnum):
    TEXT = "TEXT"
    VISUAL = "VISUAL"


_AUTHORITY_KIND_RANK = {kind: index for index, kind in enumerate(M6ReplayAuthorityKind)}
_MODEL_LAYER_RANK = {kind: index for index, kind in enumerate(M6LockedModelCallLayer)}
_MODEL_ROLE_RANK = {kind: index for index, kind in enumerate(M6LockedModelRole)}
_EMBEDDING_SCOPE_RANK = {kind: index for index, kind in enumerate(M6LockedEmbeddingScope)}
_EMBEDDING_CHANNEL_RANK = {kind: index for index, kind in enumerate(M6LockedEmbeddingChannel)}


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
    if not claims:
        return
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} does not match derived M6 locked content")


def _require_canonical_nested(
    model_type: type[_CanonicalModelT],
    value: object,
    label: str,
) -> _CanonicalModelT:
    if not isinstance(value, model_type):
        raise ValueError(f"{label} must be a canonical typed document")
    canonical = model_type.model_validate(
        value.model_dump(mode="json", exclude_computed_fields=True)
    )
    if canonical != value:
        raise ValueError(f"{label} must be a canonical typed document")
    return canonical


class M6ReplayAuthorityRef(FrozenContractModel):
    kind: M6ReplayAuthorityKind
    artifact_id: ReferenceToken
    document_sha256: Sha256Hex

    @field_validator("artifact_id")
    @classmethod
    def validate_artifact_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 replay authority artifact_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_ref_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("authority_ref_id",))
        ref = handler(payload)
        _verify_claims(ref, claims)
        return ref

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authority_ref_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-authority-ref",
                1,
                self.kind,
                self.artifact_id,
                self.document_sha256,
            ]
        )

    @property
    def sort_key(self) -> tuple[int, str]:
        return _AUTHORITY_KIND_RANK[self.kind], self.artifact_id


class M6LockedFrameInput(FrozenContractModel):
    frame_id: FrameId
    document_sha256: Sha256Hex
    content_sha256: Sha256Hex

    @field_validator("frame_id")
    @classmethod
    def validate_frame_id(cls, value: str) -> str:
        parse_frame_id(value)
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_input_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("frame_input_id",))
        item = handler(payload)
        _verify_claims(item, claims)
        return item

    @computed_field  # type: ignore[prop-decorator]
    @property
    def frame_input_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-locked-frame-input",
                1,
                self.frame_id,
                self.document_sha256,
                self.content_sha256,
            ]
        )

    @property
    def sort_key(self) -> tuple[str, str, int]:
        return parse_frame_id(self.frame_id)


class M6LockedDetectionInput(FrozenContractModel):
    detection_id: ReferenceToken
    frame_id: FrameId
    document_sha256: Sha256Hex
    model_manifest_id: Sha256Hex

    @field_validator("detection_id")
    @classmethod
    def validate_detection_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 locked detection_id")

    @field_validator("frame_id")
    @classmethod
    def validate_frame_id(cls, value: str) -> str:
        parse_frame_id(value)
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_input_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("detection_input_id",))
        item = handler(payload)
        _verify_claims(item, claims)
        return item

    @computed_field  # type: ignore[prop-decorator]
    @property
    def detection_input_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-locked-detection-input",
                1,
                self.detection_id,
                self.frame_id,
                self.document_sha256,
                self.model_manifest_id,
            ]
        )

    @property
    def sort_key(self) -> tuple[tuple[str, str, int], str]:
        return parse_frame_id(self.frame_id), self.detection_id


class M6LockedModelCallInput(FrozenContractModel):
    layer: M6LockedModelCallLayer
    role: M6LockedModelRole
    attempt_index: int = Field(ge=0, le=1, strict=True)
    request_ref: M6ReplayAuthorityRef
    result_kind: M6LockedModelCallResultKind
    response_ref: M6ReplayAuthorityRef | None = None
    cache_ref: M6ReplayAuthorityRef | None = None
    parse_receipt_ref: M6ReplayAuthorityRef | None = None
    parsed_output_ref: M6ReplayAuthorityRef | None = None
    failure_ref: M6ReplayAuthorityRef | None = None
    raw_content_sha256: Sha256Hex | None = None
    raw_size_bytes: int | None = Field(default=None, ge=0, strict=True)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_input_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("model_call_input_id",))
        item = handler(payload)
        _verify_claims(item, claims)
        return item

    @model_validator(mode="after")
    def validate_layer_role_and_result_matrix(self) -> Self:
        for label, ref in (
            ("M6 locked model request", self.request_ref),
            ("M6 locked model response", self.response_ref),
            ("M6 locked model cache", self.cache_ref),
            ("M6 locked model parse receipt", self.parse_receipt_ref),
            ("M6 locked model parsed output", self.parsed_output_ref),
            ("M6 locked model failure", self.failure_ref),
        ):
            if ref is not None:
                _require_canonical_nested(M6ReplayAuthorityRef, ref, label)

        if self.layer == M6LockedModelCallLayer.SCREENING:
            expected_role = M6LockedModelRole.SCREENING
            expected_kinds = {
                "request": M6ReplayAuthorityKind.M3_MODEL_REQUEST,
                "response": M6ReplayAuthorityKind.M3_MODEL_RESPONSE,
                "cache": M6ReplayAuthorityKind.M3_MODEL_CACHE,
                "parse": M6ReplayAuthorityKind.M3_PARSE_RECEIPT,
                "output": M6ReplayAuthorityKind.M3_PARSED_OUTPUT,
                "failure": M6ReplayAuthorityKind.M3_MODEL_CALL_FAILURE,
            }
        else:
            expected_role = None
            expected_kinds = {
                "request": M6ReplayAuthorityKind.M4_MODEL_REQUEST,
                "response": M6ReplayAuthorityKind.M4_MODEL_RESPONSE,
                "cache": M6ReplayAuthorityKind.M4_MODEL_CACHE,
                "parse": M6ReplayAuthorityKind.M4_PARSE_RECEIPT,
                "output": M6ReplayAuthorityKind.M4_ROLE_OUTPUT,
                "failure": M6ReplayAuthorityKind.M4_MODEL_CALL_FAILURE,
            }
        if expected_role is not None and self.role != expected_role:
            raise ValueError("M6 locked model role conflicts with its layer")
        if expected_role is None and self.role == M6LockedModelRole.SCREENING:
            raise ValueError("M6 locked model role conflicts with its layer")
        if self.request_ref.kind != expected_kinds["request"]:
            raise ValueError("M6 locked model request kind conflicts with its layer")

        response_values = (
            self.response_ref,
            self.cache_ref,
            self.parse_receipt_ref,
            self.raw_content_sha256,
            self.raw_size_bytes,
        )
        if self.result_kind == M6LockedModelCallResultKind.RESPONSE:
            if any(value is None for value in response_values) or self.failure_ref is not None:
                raise ValueError("M6 locked response closure is incomplete or crossed with failure")
            assert self.response_ref is not None
            assert self.cache_ref is not None
            assert self.parse_receipt_ref is not None
            if (
                self.response_ref.kind != expected_kinds["response"]
                or self.cache_ref.kind != expected_kinds["cache"]
                or self.parse_receipt_ref.kind != expected_kinds["parse"]
                or (
                    self.parsed_output_ref is not None
                    and self.parsed_output_ref.kind != expected_kinds["output"]
                )
            ):
                raise ValueError("M6 locked response closure authority kind differs from layer")
        else:
            if (
                self.failure_ref is None
                or any(value is not None for value in response_values)
                or self.parsed_output_ref is not None
            ):
                raise ValueError("M6 locked failure closure must contain only failure authority")
            if self.failure_ref.kind != expected_kinds["failure"]:
                raise ValueError("M6 locked failure closure authority kind differs from layer")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def model_call_input_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-locked-model-call-input",
                1,
                self.layer,
                self.role,
                self.attempt_index,
                self.request_ref.authority_ref_id,
                self.result_kind,
                self.response_ref.authority_ref_id if self.response_ref else None,
                self.cache_ref.authority_ref_id if self.cache_ref else None,
                self.parse_receipt_ref.authority_ref_id if self.parse_receipt_ref else None,
                self.parsed_output_ref.authority_ref_id if self.parsed_output_ref else None,
                self.failure_ref.authority_ref_id if self.failure_ref else None,
                self.raw_content_sha256,
                self.raw_size_bytes,
            ]
        )

    @property
    def sort_key(self) -> tuple[int, int, str]:
        return (
            _MODEL_LAYER_RANK[self.layer],
            _MODEL_ROLE_RANK[self.role],
            self.request_ref.artifact_id,
        )


class M6LockedEmbeddingInput(FrozenContractModel):
    scope: M6LockedEmbeddingScope
    channel: M6LockedEmbeddingChannel
    embedding_ref: M6ReplayAuthorityRef
    request_id: Sha256Hex
    model_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_input_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("embedding_input_id",))
        item = handler(payload)
        _verify_claims(item, claims)
        return item

    @model_validator(mode="after")
    def validate_embedding_kind(self) -> Self:
        _require_canonical_nested(
            M6ReplayAuthorityRef,
            self.embedding_ref,
            "M6 locked embedding authority",
        )
        if self.embedding_ref.kind != M6ReplayAuthorityKind.M5_EMBEDDING:
            raise ValueError("M6 locked embedding input requires an embedding authority")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def embedding_input_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-locked-embedding-input",
                1,
                self.scope,
                self.channel,
                self.embedding_ref.authority_ref_id,
                self.request_id,
                self.model_manifest_id,
            ]
        )

    @property
    def sort_key(self) -> tuple[int, int, str]:
        return (
            _EMBEDDING_SCOPE_RANK[self.scope],
            _EMBEDDING_CHANNEL_RANK[self.channel],
            self.embedding_ref.artifact_id,
        )


class M6LockedToolResultInput(FrozenContractModel):
    tool_result_id: Sha256Hex
    tool_result_document_sha256: Sha256Hex
    acquisition_request_ref: M6ReplayAuthorityRef
    execution_manifest_ref: M6ReplayAuthorityRef
    execution_publication_ref: M6ReplayAuthorityRef
    tool_receipt_ref: M6ReplayAuthorityRef
    evidence_pack_derivation_ref: M6ReplayAuthorityRef
    resulting_evidence_pack_ref: M6ReplayAuthorityRef

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_input_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("tool_result_input_id",))
        item = handler(payload)
        _verify_claims(item, claims)
        return item

    @model_validator(mode="after")
    def validate_authority_kinds(self) -> Self:
        matrix = (
            (
                self.acquisition_request_ref,
                M6ReplayAuthorityKind.M4_ACQUISITION_REQUEST,
            ),
            (
                self.execution_manifest_ref,
                M6ReplayAuthorityKind.M4_TOOL_EXECUTION_MANIFEST,
            ),
            (
                self.execution_publication_ref,
                M6ReplayAuthorityKind.M4_ACQUISITION_PUBLICATION,
            ),
            (
                self.tool_receipt_ref,
                M6ReplayAuthorityKind.M4_TOOL_EXECUTION_RECEIPT,
            ),
            (
                self.evidence_pack_derivation_ref,
                M6ReplayAuthorityKind.M4_EVIDENCE_PACK_DERIVATION,
            ),
            (
                self.resulting_evidence_pack_ref,
                M6ReplayAuthorityKind.EVIDENCE_PACK,
            ),
        )
        for ref, _ in matrix:
            _require_canonical_nested(
                M6ReplayAuthorityRef,
                ref,
                "M6 locked tool authority",
            )
        if any(ref.kind != expected for ref, expected in matrix):
            raise ValueError("M6 locked tool execution authority kind is invalid")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def tool_result_input_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-locked-tool-result-input",
                1,
                self.tool_result_id,
                self.tool_result_document_sha256,
                self.acquisition_request_ref.authority_ref_id,
                self.execution_manifest_ref.authority_ref_id,
                self.execution_publication_ref.authority_ref_id,
                self.tool_receipt_ref.authority_ref_id,
                self.evidence_pack_derivation_ref.authority_ref_id,
                self.resulting_evidence_pack_ref.authority_ref_id,
            ]
        )


class M6LockedRetrievalCycleInput(FrozenContractModel):
    """One exact historical retrieval authority for one hearing cycle.

    Successful cycles bind the M5 prompt-visible exposure.  Degraded cycles have
    no exposure and bind the exact M4 durable retrieval receipt preserving the
    typed degraded reason.  Source applications, alerts, appeals, and every
    training-label authority remain evaluator-side outputs.
    """

    source_run_id: ReferenceToken
    source_case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    cycle_index: int = Field(gt=0, strict=True)
    cycle_scope_id: Sha256Hex
    outcome: M6LockedRetrievalOutcomeKind
    authority_ref: M6ReplayAuthorityRef

    @field_validator("source_run_id", "source_case_id")
    @classmethod
    def validate_source_references(cls, value: str) -> str:
        return require_reference_token(value, "M6 historical retrieval source reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_input_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("retrieval_cycle_input_id",))
        item = handler(payload)
        _verify_claims(item, claims)
        return item

    @model_validator(mode="after")
    def validate_retrieval_kind(self) -> Self:
        _require_canonical_nested(
            M6ReplayAuthorityRef,
            self.authority_ref,
            "M6 locked retrieval authority",
        )
        expected_kind = {
            M6LockedRetrievalOutcomeKind.SUCCESS: (M6ReplayAuthorityKind.M5_PRECEDENT_EXPOSURE),
            M6LockedRetrievalOutcomeKind.DEGRADED: (
                M6ReplayAuthorityKind.M4_PRECEDENT_RETRIEVAL_RECEIPT
            ),
        }[self.outcome]
        if self.authority_ref.kind != expected_kind:
            raise ValueError("M6 historical retrieval authority kind conflicts with outcome")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def retrieval_cycle_input_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-locked-retrieval-cycle-input",
                1,
                self.source_run_id,
                self.source_case_id,
                self.hearing_session_id,
                self.cycle_index,
                self.cycle_scope_id,
                self.outcome,
                self.authority_ref.authority_ref_id,
            ]
        )

    @property
    def sort_key(self) -> tuple[str, int, str]:
        return self.hearing_session_id, self.cycle_index, self.authority_ref.artifact_id


class M6HistoricalCausalCut(FrozenContractModel):
    retrieval_cycles: tuple[M6LockedRetrievalCycleInput, ...] = Field(
        default=(),
        max_length=MAX_M6_LOCKED_PRECEDENT_CUT_ITEMS,
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
                "retrieval_cycle_count",
                "successful_exposure_count",
                "degraded_retrieval_count",
                "causal_cut_id",
            ),
        )
        cut = handler(payload)
        _verify_claims(cut, claims)
        return cut

    @model_validator(mode="after")
    def validate_cut(self) -> Self:
        canonical_cycles = tuple(
            _require_canonical_nested(
                M6LockedRetrievalCycleInput,
                item,
                "M6 historical retrieval cycle",
            )
            for item in self.retrieval_cycles
        )
        if canonical_cycles != self.retrieval_cycles:
            raise ValueError("M6 historical retrieval cycles are not canonical")

        keys = tuple(item.sort_key for item in self.retrieval_cycles)
        if keys != tuple(sorted(keys)):
            raise ValueError("M6 historical retrieval cycles must use stable cycle order")
        if len(keys) != len(set(keys)):
            raise ValueError("M6 historical retrieval cycles must be unique")
        cycle_indices = tuple(item.cycle_index for item in self.retrieval_cycles)
        if cycle_indices != tuple(range(1, len(cycle_indices) + 1)):
            raise ValueError("M6 historical retrieval cycle cut must be contiguous from one")
        hearing_session_ids = {item.hearing_session_id for item in self.retrieval_cycles}
        if len(hearing_session_ids) > 1:
            raise ValueError("M6 historical retrieval cut must bind one hearing session")
        cycle_scope_ids = tuple(item.cycle_scope_id for item in self.retrieval_cycles)
        if len(cycle_scope_ids) != len(set(cycle_scope_ids)):
            raise ValueError("M6 historical retrieval cycle scopes must be unique")
        authority_ids = tuple(item.authority_ref.artifact_id for item in self.retrieval_cycles)
        if len(authority_ids) != len(set(authority_ids)):
            raise ValueError("M6 historical retrieval authorities must be unique")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def retrieval_cycle_count(self) -> int:
        return len(self.retrieval_cycles)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def successful_exposure_count(self) -> int:
        return sum(
            item.outcome == M6LockedRetrievalOutcomeKind.SUCCESS for item in self.retrieval_cycles
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def degraded_retrieval_count(self) -> int:
        return sum(
            item.outcome == M6LockedRetrievalOutcomeKind.DEGRADED for item in self.retrieval_cycles
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def causal_cut_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-historical-causal-cut",
                1,
                [item.retrieval_cycle_input_id for item in self.retrieval_cycles],
            ]
        )


class M6ReplayInputClosureAuthority(FrozenContractModel):
    schema_version: Literal["m6-replay-input-closure-authority-v1"] = (
        "m6-replay-input-closure-authority-v1"
    )
    sample_id: ReferenceToken
    source_run_id: ReferenceToken
    source_case_id: ReferenceToken | None = None
    source_case_revision: int | None = Field(default=None, gt=0, strict=True)
    source_case_document_sha256: Sha256Hex | None = None
    source_manifest_id: Sha256Hex
    source_manifest_document_sha256: Sha256Hex
    input_authority_id: Sha256Hex
    input_authority_document_sha256: Sha256Hex
    source_validation_report_id: Sha256Hex
    source_validation_report_document_sha256: Sha256Hex
    frames: tuple[M6LockedFrameInput, ...] = Field(
        min_length=1,
        max_length=MAX_M6_LOCKED_FRAMES_PER_CASE,
    )
    detections: tuple[M6LockedDetectionInput, ...] = Field(
        default=(),
        max_length=MAX_M6_LOCKED_DETECTIONS_PER_CASE,
    )
    model_calls: tuple[M6LockedModelCallInput, ...] = Field(
        default=(),
        max_length=MAX_M6_LOCKED_MODEL_CALLS_PER_CASE,
    )
    embeddings: tuple[M6LockedEmbeddingInput, ...] = Field(
        default=(),
        max_length=MAX_M6_LOCKED_EMBEDDINGS_PER_CASE,
    )
    tool_results: tuple[M6LockedToolResultInput, ...] = Field(
        default=(),
        max_length=MAX_M6_LOCKED_TOOL_RESULTS_PER_CASE,
    )
    historical_cut: M6HistoricalCausalCut = Field(default_factory=M6HistoricalCausalCut)

    @field_validator("sample_id", "source_run_id")
    @classmethod
    def validate_required_references(cls, value: str) -> str:
        return require_reference_token(value, "M6 replay input closure reference")

    @field_validator("source_case_id")
    @classmethod
    def validate_optional_case_reference(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M6 replay source case_id")

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
                "frame_count",
                "frame_inventory_root_sha256",
                "detection_count",
                "detection_inventory_root_sha256",
                "model_call_count",
                "model_call_inventory_root_sha256",
                "model_response_count",
                "model_response_inventory_root_sha256",
                "embedding_count",
                "embedding_inventory_root_sha256",
                "tool_result_count",
                "tool_result_inventory_root_sha256",
                "replay_input_closure_authority_id",
                "replay_input_closure_document_sha256",
            ),
        )
        closure = handler(payload)
        _verify_claims(closure, claims)
        return closure

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        canonical_frames = tuple(
            _require_canonical_nested(
                M6LockedFrameInput,
                item,
                "M6 locked frame input",
            )
            for item in self.frames
        )
        canonical_detections = tuple(
            _require_canonical_nested(
                M6LockedDetectionInput,
                item,
                "M6 locked detection input",
            )
            for item in self.detections
        )
        canonical_model_calls = tuple(
            _require_canonical_nested(
                M6LockedModelCallInput,
                item,
                "M6 locked model call input",
            )
            for item in self.model_calls
        )
        canonical_embeddings = tuple(
            _require_canonical_nested(
                M6LockedEmbeddingInput,
                item,
                "M6 locked embedding input",
            )
            for item in self.embeddings
        )
        canonical_tool_results = tuple(
            _require_canonical_nested(
                M6LockedToolResultInput,
                item,
                "M6 locked tool result input",
            )
            for item in self.tool_results
        )
        canonical_historical_cut = _require_canonical_nested(
            M6HistoricalCausalCut,
            self.historical_cut,
            "M6 historical causal cut",
        )
        if (
            canonical_frames != self.frames
            or canonical_detections != self.detections
            or canonical_model_calls != self.model_calls
            or canonical_embeddings != self.embeddings
            or canonical_tool_results != self.tool_results
            or canonical_historical_cut != self.historical_cut
        ):
            raise ValueError("M6 replay input closure contains non-canonical nested input")

        case_values = (
            self.source_case_id,
            self.source_case_revision,
            self.source_case_document_sha256,
        )
        if not (
            all(value is None for value in case_values)
            or all(value is not None for value in case_values)
        ):
            raise ValueError("M6 replay source Case binding must be all present or all absent")

        frame_keys = tuple(frame.sort_key for frame in self.frames)
        if frame_keys != tuple(sorted(frame_keys)):
            raise ValueError("M6 replay frames must use stable semantic-time order")
        frame_ids = tuple(frame.frame_id for frame in self.frames)
        if len(frame_ids) != len(set(frame_ids)):
            raise ValueError("M6 replay frames must be unique")

        detection_keys = tuple(item.sort_key for item in self.detections)
        if detection_keys != tuple(sorted(detection_keys)):
            raise ValueError("M6 replay detections must use stable order")
        detection_ids = tuple(item.detection_id for item in self.detections)
        if len(detection_ids) != len(set(detection_ids)):
            raise ValueError("M6 replay detections must be unique")
        known_frames = set(frame_ids)
        if any(item.frame_id not in known_frames for item in self.detections):
            raise ValueError("M6 replay detection references an unknown frame")

        for values, name in (
            (self.model_calls, "model_calls"),
            (self.embeddings, "embeddings"),
        ):
            keys = tuple(item.sort_key for item in values)
            if keys != tuple(sorted(keys)):
                raise ValueError(f"M6 replay {name} must use stable order")
            if len(keys) != len(set(keys)):
                raise ValueError(f"M6 replay {name} must be unique")
        request_ids = tuple(item.request_ref.artifact_id for item in self.model_calls)
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("M6 replay model_calls request authorities must be unique")
        embedding_ids = tuple(item.embedding_ref.artifact_id for item in self.embeddings)
        if len(embedding_ids) != len(set(embedding_ids)):
            raise ValueError("M6 replay embeddings authorities must be unique")

        tool_ids = tuple(item.tool_result_id for item in self.tool_results)
        if tool_ids != tuple(sorted(tool_ids)):
            raise ValueError("M6 replay tool_results must use stable order")
        if len(tool_ids) != len(set(tool_ids)):
            raise ValueError("M6 replay tool_results must be unique")

        if self.historical_cut.retrieval_cycles and self.source_case_id is None:
            raise ValueError("M6 historical retrieval requires a source Case")
        if any(
            item.source_run_id != self.source_run_id or item.source_case_id != self.source_case_id
            for item in self.historical_cut.retrieval_cycles
        ):
            raise ValueError("M6 historical retrieval scope differs from replay source scope")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def frame_count(self) -> int:
        return len(self.frames)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def frame_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-locked-frame-inventory",
                1,
                [item.frame_input_id for item in self.frames],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def detection_count(self) -> int:
        return len(self.detections)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def detection_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-locked-detection-inventory",
                1,
                [item.detection_input_id for item in self.detections],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def model_call_count(self) -> int:
        return len(self.model_calls)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def model_call_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-locked-model-call-inventory",
                1,
                [item.model_call_input_id for item in self.model_calls],
            ]
        )

    def _response_calls(self) -> tuple[M6LockedModelCallInput, ...]:
        return tuple(
            item
            for item in self.model_calls
            if item.result_kind == M6LockedModelCallResultKind.RESPONSE
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def model_response_count(self) -> int:
        return len(self._response_calls())

    @computed_field  # type: ignore[prop-decorator]
    @property
    def model_response_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-locked-model-response-inventory",
                1,
                [item.model_call_input_id for item in self._response_calls()],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def embedding_count(self) -> int:
        return len(self.embeddings)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def embedding_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-locked-embedding-inventory",
                1,
                [item.embedding_input_id for item in self.embeddings],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def tool_result_count(self) -> int:
        return len(self.tool_results)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def tool_result_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-locked-tool-result-inventory",
                1,
                [item.tool_result_input_id for item in self.tool_results],
            ]
        )

    def authority_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "sample_id": self.sample_id,
            "source_run_id": self.source_run_id,
            "source_case_id": self.source_case_id,
            "source_case_revision": self.source_case_revision,
            "source_case_document_sha256": self.source_case_document_sha256,
            "source_manifest_id": self.source_manifest_id,
            "source_manifest_document_sha256": self.source_manifest_document_sha256,
            "input_authority_id": self.input_authority_id,
            "input_authority_document_sha256": self.input_authority_document_sha256,
            "source_validation_report_id": self.source_validation_report_id,
            "source_validation_report_document_sha256": (
                self.source_validation_report_document_sha256
            ),
            "frame_inventory_root_sha256": self.frame_inventory_root_sha256,
            "detection_inventory_root_sha256": self.detection_inventory_root_sha256,
            "model_call_inventory_root_sha256": self.model_call_inventory_root_sha256,
            "model_response_inventory_root_sha256": (self.model_response_inventory_root_sha256),
            "embedding_inventory_root_sha256": self.embedding_inventory_root_sha256,
            "tool_result_inventory_root_sha256": self.tool_result_inventory_root_sha256,
            "historical_causal_cut_id": self.historical_cut.causal_cut_id,
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def replay_input_closure_authority_id(self) -> Sha256Hex:
        return sha256_hex(["m6-replay-input-closure-authority", 1, self.authority_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def replay_input_closure_document_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-input-closure-document",
                1,
                self.replay_input_closure_authority_id,
                self.authority_projection(),
            ]
        )


class M6ProviderCapabilityCounters(FrozenContractModel):
    perception_provider_calls: int = Field(default=0, ge=0, strict=True)
    screening_vlm_provider_calls: int = Field(default=0, ge=0, strict=True)
    hearing_vlm_provider_calls: int = Field(default=0, ge=0, strict=True)
    embedding_provider_calls: int = Field(default=0, ge=0, strict=True)
    acquisition_provider_calls: int = Field(default=0, ge=0, strict=True)
    safety_signal_provider_calls: int = Field(default=0, ge=0, strict=True)
    alert_channel_calls: int = Field(default=0, ge=0, strict=True)
    response_recovery_calls: int = Field(default=0, ge=0, strict=True)
    cache_write_calls: int = Field(default=0, ge=0, strict=True)
    live_precedent_tail_query_calls: int = Field(default=0, ge=0, strict=True)
    live_training_label_tail_query_calls: int = Field(default=0, ge=0, strict=True)

    @property
    def total(self) -> int:
        return sum(
            (
                self.perception_provider_calls,
                self.screening_vlm_provider_calls,
                self.hearing_vlm_provider_calls,
                self.embedding_provider_calls,
                self.acquisition_provider_calls,
                self.safety_signal_provider_calls,
                self.alert_channel_calls,
                self.response_recovery_calls,
                self.cache_write_calls,
                self.live_precedent_tail_query_calls,
                self.live_training_label_tail_query_calls,
            )
        )


class M6ProviderTrapAuthority(FrozenContractModel):
    schema_version: Literal["m6-provider-trap-authority-v1"] = "m6-provider-trap-authority-v1"
    command_id: Sha256Hex
    candidate_run_id: ReferenceToken
    execution_component_manifest_id: Sha256Hex
    counters: M6ProviderCapabilityCounters

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 provider trap candidate_run_id")

    @model_validator(mode="after")
    def revalidate_nested_counters(self) -> Self:
        canonical = M6ProviderCapabilityCounters.model_validate(
            self.counters.model_dump(mode="json")
        )
        if canonical != self.counters:
            raise ValueError("M6 provider trap counters are not canonical")
        return self

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
                "external_capability_call_count",
                "clean",
                "provider_trap_authority_id",
                "provider_trap_document_sha256",
            ),
        )
        trap = handler(payload)
        _verify_claims(trap, claims)
        return trap

    @computed_field  # type: ignore[prop-decorator]
    @property
    def external_capability_call_count(self) -> int:
        return self.counters.total

    @computed_field  # type: ignore[prop-decorator]
    @property
    def clean(self) -> bool:
        return self.external_capability_call_count == 0

    def authority_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "command_id": self.command_id,
            "candidate_run_id": self.candidate_run_id,
            "execution_component_manifest_id": self.execution_component_manifest_id,
            "counters": self.counters.model_dump(mode="json"),
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_trap_authority_id(self) -> Sha256Hex:
        return sha256_hex(["m6-provider-trap-authority", 1, self.authority_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_trap_document_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-provider-trap-document",
                1,
                self.provider_trap_authority_id,
                self.authority_projection(),
            ]
        )


class M6ReplayLockedSourceDeterminismAuthority(FrozenContractModel):
    """Two-read source projection proof, deliberately not a replay receipt.

    This authority binds a future, distinct candidate run while proving only
    that one immutable source closure produced the same source projection on
    two fresh reads.  It contains no candidate snapshot or provider-trap claim.
    """

    schema_version: Literal["m6-replay-locked-source-determinism-authority-v1"] = (
        "m6-replay-locked-source-determinism-authority-v1"
    )
    projection_read_count: Literal[2] = 2
    command_id: Sha256Hex
    execution_entry_id: Sha256Hex
    sample_id: ReferenceToken
    source_run_id: ReferenceToken
    candidate_run_id: ReferenceToken
    source_manifest_id: Sha256Hex
    execution_component_manifest_id: Sha256Hex
    replay_input_closure_authority_id: Sha256Hex
    replay_input_closure_document_sha256: Sha256Hex
    source_identity_sha256: Sha256Hex
    first_source_snapshot_id: Sha256Hex
    second_source_snapshot_id: Sha256Hex
    first_semantic_case_hash: Sha256Hex
    second_semantic_case_hash: Sha256Hex

    @field_validator("sample_id", "source_run_id", "candidate_run_id")
    @classmethod
    def validate_references(cls, value: str) -> str:
        return require_reference_token(value, "M6 locked source determinism reference")

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
                "source_determinism_authority_id",
                "source_determinism_document_sha256",
            ),
        )
        authority = handler(payload)
        _verify_claims(authority, claims)
        return authority

    @model_validator(mode="after")
    def validate_distinct_run_and_equal_projection(self) -> Self:
        if self.candidate_run_id == self.source_run_id:
            raise ValueError("M6 locked candidate run must differ from its source run")
        if (
            self.first_source_snapshot_id != self.second_source_snapshot_id
            or self.first_semantic_case_hash != self.second_semantic_case_hash
        ):
            raise ValueError("M6 locked source projections are not deterministic")
        return self

    def authority_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "projection_read_count": self.projection_read_count,
            "command_id": self.command_id,
            "execution_entry_id": self.execution_entry_id,
            "sample_id": self.sample_id,
            "source_run_id": self.source_run_id,
            "candidate_run_id": self.candidate_run_id,
            "source_manifest_id": self.source_manifest_id,
            "execution_component_manifest_id": self.execution_component_manifest_id,
            "replay_input_closure_authority_id": self.replay_input_closure_authority_id,
            "replay_input_closure_document_sha256": (self.replay_input_closure_document_sha256),
            "source_identity_sha256": self.source_identity_sha256,
            "first_source_snapshot_id": self.first_source_snapshot_id,
            "second_source_snapshot_id": self.second_source_snapshot_id,
            "first_semantic_case_hash": self.first_semantic_case_hash,
            "second_semantic_case_hash": self.second_semantic_case_hash,
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_determinism_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            ["m6-replay-locked-source-determinism-authority", 1, self.authority_projection()]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_determinism_document_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-source-determinism-document",
                1,
                self.source_determinism_authority_id,
                self.authority_projection(),
            ]
        )


__all__ = [
    "M6HistoricalCausalCut",
    "M6LockedDetectionInput",
    "M6LockedEmbeddingChannel",
    "M6LockedEmbeddingInput",
    "M6LockedEmbeddingScope",
    "M6LockedFrameInput",
    "M6LockedModelCallInput",
    "M6LockedModelCallLayer",
    "M6LockedModelCallResultKind",
    "M6LockedModelRole",
    "M6LockedRetrievalCycleInput",
    "M6LockedRetrievalOutcomeKind",
    "M6LockedToolResultInput",
    "M6ProviderCapabilityCounters",
    "M6ProviderTrapAuthority",
    "M6ReplayAuthorityKind",
    "M6ReplayAuthorityRef",
    "M6ReplayInputClosureAuthority",
    "M6ReplayLockedSourceDeterminismAuthority",
]

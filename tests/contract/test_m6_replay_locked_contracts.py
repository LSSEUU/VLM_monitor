"""Typed, candidate-blind input closure for M6 REPLAY_LOCKED."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.m6_replay_locked import (
    M6HistoricalCausalCut,
    M6LockedDetectionInput,
    M6LockedEmbeddingChannel,
    M6LockedEmbeddingInput,
    M6LockedEmbeddingScope,
    M6LockedFrameInput,
    M6LockedModelCallInput,
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
    M6LockedRetrievalCycleInput,
    M6LockedRetrievalOutcomeKind,
    M6LockedToolResultInput,
    M6ProviderCapabilityCounters,
    M6ProviderTrapAuthority,
    M6ReplayAuthorityKind,
    M6ReplayAuthorityRef,
    M6ReplayInputClosureAuthority,
    M6ReplayLockedSourceDeterminismAuthority,
)
from labcourt.schema_export import expected_schema_files


def _sha(character: str) -> str:
    return character * 64


def _ref(
    kind: M6ReplayAuthorityKind,
    label: str,
    character: str,
) -> M6ReplayAuthorityRef:
    return M6ReplayAuthorityRef(
        kind=kind,
        artifact_id=label,
        document_sha256=_sha(character),
    )


def _response_call() -> M6LockedModelCallInput:
    return M6LockedModelCallInput(
        layer=M6LockedModelCallLayer.SCREENING,
        role=M6LockedModelRole.SCREENING,
        attempt_index=0,
        request_ref=_ref(M6ReplayAuthorityKind.M3_MODEL_REQUEST, "request-screening", "1"),
        result_kind=M6LockedModelCallResultKind.RESPONSE,
        response_ref=_ref(
            M6ReplayAuthorityKind.M3_MODEL_RESPONSE,
            "response-screening",
            "2",
        ),
        cache_ref=_ref(M6ReplayAuthorityKind.M3_MODEL_CACHE, "cache-screening", "3"),
        parse_receipt_ref=_ref(
            M6ReplayAuthorityKind.M3_PARSE_RECEIPT,
            "parse-screening",
            "4",
        ),
        parsed_output_ref=_ref(
            M6ReplayAuthorityKind.M3_PARSED_OUTPUT,
            "output-screening",
            "5",
        ),
        raw_content_sha256=_sha("6"),
        raw_size_bytes=321,
    )


def _failure_call() -> M6LockedModelCallInput:
    return M6LockedModelCallInput(
        layer=M6LockedModelCallLayer.HEARING,
        role=M6LockedModelRole.JUDGE,
        attempt_index=0,
        request_ref=_ref(M6ReplayAuthorityKind.M4_MODEL_REQUEST, "request-judge", "7"),
        result_kind=M6LockedModelCallResultKind.FAILURE,
        failure_ref=_ref(
            M6ReplayAuthorityKind.M4_MODEL_CALL_FAILURE,
            "failure-judge",
            "8",
        ),
    )


def _tool_result() -> M6LockedToolResultInput:
    return M6LockedToolResultInput(
        tool_result_id=_sha("9"),
        tool_result_document_sha256=_sha("a"),
        acquisition_request_ref=_ref(
            M6ReplayAuthorityKind.M4_ACQUISITION_REQUEST,
            "acquisition-request",
            "b",
        ),
        execution_manifest_ref=_ref(
            M6ReplayAuthorityKind.M4_TOOL_EXECUTION_MANIFEST,
            "tool-manifest",
            "c",
        ),
        execution_publication_ref=_ref(
            M6ReplayAuthorityKind.M4_ACQUISITION_PUBLICATION,
            "tool-publication",
            "d",
        ),
        tool_receipt_ref=_ref(
            M6ReplayAuthorityKind.M4_TOOL_EXECUTION_RECEIPT,
            "tool-receipt",
            "e",
        ),
        evidence_pack_derivation_ref=_ref(
            M6ReplayAuthorityKind.M4_EVIDENCE_PACK_DERIVATION,
            "pack-derivation",
            "f",
        ),
        resulting_evidence_pack_ref=_ref(
            M6ReplayAuthorityKind.EVIDENCE_PACK,
            "resulting-pack",
            "0",
        ),
    )


def _historical_retrieval(
    *,
    cycle_index: int = 1,
    outcome: M6LockedRetrievalOutcomeKind = M6LockedRetrievalOutcomeKind.SUCCESS,
) -> M6LockedRetrievalCycleInput:
    authority_kind = (
        M6ReplayAuthorityKind.M5_PRECEDENT_EXPOSURE
        if outcome == M6LockedRetrievalOutcomeKind.SUCCESS
        else M6ReplayAuthorityKind.M4_PRECEDENT_RETRIEVAL_RECEIPT
    )
    return M6LockedRetrievalCycleInput(
        source_run_id="run-baseline",
        source_case_id="case-baseline",
        hearing_session_id=_sha("1"),
        cycle_index=cycle_index,
        cycle_scope_id=_sha(format(cycle_index + 1, "x")),
        outcome=outcome,
        authority_ref=_ref(
            authority_kind,
            f"retrieval-cycle-{cycle_index:03d}",
            "3",
        ),
    )


def _closure(*, with_case: bool = True) -> M6ReplayInputClosureAuthority:
    return M6ReplayInputClosureAuthority(
        sample_id="sample-locked-001",
        source_run_id="run-baseline",
        source_case_id="case-baseline" if with_case else None,
        source_case_revision=7 if with_case else None,
        source_case_document_sha256=_sha("1") if with_case else None,
        source_manifest_id=_sha("2"),
        source_manifest_document_sha256=_sha("3"),
        input_authority_id=_sha("4"),
        input_authority_document_sha256=_sha("5"),
        source_validation_report_id=_sha("6"),
        source_validation_report_document_sha256=_sha("7"),
        frames=(
            M6LockedFrameInput(
                frame_id="cam-01:stream-01:10",
                document_sha256=_sha("8"),
                content_sha256=_sha("9"),
            ),
            M6LockedFrameInput(
                frame_id="cam-01:stream-01:11",
                document_sha256=_sha("a"),
                content_sha256=_sha("b"),
            ),
        ),
        detections=(
            M6LockedDetectionInput(
                detection_id="detection-001",
                frame_id="cam-01:stream-01:10",
                document_sha256=_sha("c"),
                model_manifest_id=_sha("d"),
            ),
        ),
        model_calls=(_response_call(), _failure_call()),
        embeddings=(
            M6LockedEmbeddingInput(
                scope=M6LockedEmbeddingScope.QUERY,
                channel=M6LockedEmbeddingChannel.TEXT,
                embedding_ref=_ref(
                    M6ReplayAuthorityKind.M5_EMBEDDING,
                    "embedding-query-text",
                    "b",
                ),
                request_id=_sha("c"),
                model_manifest_id=_sha("d"),
            ),
            M6LockedEmbeddingInput(
                scope=M6LockedEmbeddingScope.PRECEDENT,
                channel=M6LockedEmbeddingChannel.VISUAL,
                embedding_ref=_ref(
                    M6ReplayAuthorityKind.M5_EMBEDDING,
                    "embedding-precedent-visual",
                    "e",
                ),
                request_id=_sha("f"),
                model_manifest_id=_sha("0"),
            ),
        ),
        tool_results=(_tool_result(),),
        historical_cut=M6HistoricalCausalCut(
            retrieval_cycles=(_historical_retrieval(),) if with_case else (),
        ),
    )


def test_replay_input_closure_derives_every_inventory_claim_and_round_trips() -> None:
    closure = _closure()

    assert closure.frame_count == 2
    assert closure.detection_count == 1
    assert closure.model_call_count == 2
    assert closure.model_response_count == 1
    assert closure.embedding_count == 2
    assert closure.tool_result_count == 1
    assert closure.historical_cut.retrieval_cycle_count == 1
    assert closure.historical_cut.successful_exposure_count == 1
    assert closure.historical_cut.degraded_retrieval_count == 0
    assert len(closure.replay_input_closure_authority_id) == 64
    assert len(closure.replay_input_closure_document_sha256) == 64
    assert M6ReplayInputClosureAuthority.model_validate(closure.model_dump(mode="json")) == closure

    serialized = closure.model_dump(mode="json")
    for field, forged in (
        ("frame_count", 99),
        ("model_response_inventory_root_sha256", _sha("f")),
        ("replay_input_closure_authority_id", _sha("e")),
        ("replay_input_closure_document_sha256", _sha("d")),
    ):
        attacked = dict(serialized)
        attacked[field] = forged
        with pytest.raises(ValidationError, match=field):
            M6ReplayInputClosureAuthority.model_validate(attacked)


def test_closure_is_candidate_blind_and_has_no_training_label_authority_kind() -> None:
    serialized = json.dumps(_closure().model_dump(mode="json"), sort_keys=True)

    for forbidden in (
        "expected_decision",
        "gold_truth",
        "memberships",
        "TRAINING_LABEL",
        "M5_PRECEDENT_APPLICATION",
        "M5_ALERT_POLICY",
        "M5_APPEAL_RESOLUTION",
        "application_batch",
        "appeal_resolution",
        "alert_ref",
    ):
        assert forbidden not in serialized
        assert forbidden not in {kind.value for kind in M6ReplayAuthorityKind}


def test_source_case_binding_is_all_or_none_and_no_case_challenge_is_supported() -> None:
    no_case = _closure(with_case=False)
    assert no_case.source_case_id is None

    with pytest.raises(ValidationError, match="source Case"):
        no_case.model_copy(update={"source_case_revision": 1})


def test_authority_inventories_are_typed_stable_unique_and_cross_bound() -> None:
    closure = _closure()

    with pytest.raises(ValidationError, match="frames"):
        closure.model_copy(update={"frames": tuple(reversed(closure.frames))})
    with pytest.raises(ValidationError, match="unknown frame"):
        closure.model_copy(
            update={
                "detections": (
                    M6LockedDetectionInput(
                        detection_id="detection-foreign",
                        frame_id="cam-01:stream-01:999",
                        document_sha256=_sha("1"),
                        model_manifest_id=_sha("2"),
                    ),
                )
            }
        )
    with pytest.raises(ValidationError, match="unique"):
        closure.model_copy(update={"model_calls": (_response_call(), _response_call())})


def test_model_call_response_and_failure_matrices_are_closed() -> None:
    response = _response_call()
    failure = _failure_call()

    with pytest.raises(ValidationError, match="response closure"):
        response.model_copy(update={"cache_ref": None})
    with pytest.raises(ValidationError, match="failure closure"):
        failure.model_copy(
            update={
                "raw_content_sha256": _sha("1"),
                "raw_size_bytes": 12,
            }
        )
    with pytest.raises(ValidationError, match="layer"):
        response.model_copy(update={"role": M6LockedModelRole.JUDGE})

    hearing_response = response.model_copy(
        update={
            "layer": M6LockedModelCallLayer.HEARING,
            "role": M6LockedModelRole.PROSECUTOR,
            "request_ref": _ref(
                M6ReplayAuthorityKind.M4_MODEL_REQUEST,
                "request-prosecutor",
                "1",
            ),
            "response_ref": _ref(
                M6ReplayAuthorityKind.M4_MODEL_RESPONSE,
                "response-prosecutor",
                "2",
            ),
            "cache_ref": _ref(
                M6ReplayAuthorityKind.M4_MODEL_CACHE,
                "cache-prosecutor",
                "3",
            ),
            "parse_receipt_ref": _ref(
                M6ReplayAuthorityKind.M4_PARSE_RECEIPT,
                "parse-prosecutor",
                "4",
            ),
            "parsed_output_ref": _ref(
                M6ReplayAuthorityKind.M4_ROLE_OUTPUT,
                "role-output-prosecutor",
                "5",
            ),
        }
    )
    assert hearing_response.parsed_output_ref is not None
    assert hearing_response.parsed_output_ref.kind == M6ReplayAuthorityKind.M4_ROLE_OUTPUT
    assert "M4_PARSED_OUTPUT" not in {kind.value for kind in M6ReplayAuthorityKind}


def test_tool_result_requires_exact_publication_receipt_derivation_and_successor_kinds() -> None:
    tool = _tool_result()

    with pytest.raises(ValidationError, match="tool execution authority kind"):
        tool.model_copy(
            update={
                "execution_publication_ref": _ref(
                    M6ReplayAuthorityKind.M4_MODEL_RESPONSE,
                    "wrong-publication-kind",
                    "1",
                )
            }
        )


def test_historical_cut_is_typed_per_cycle_and_forbids_output_or_live_tail_authority() -> None:
    cut = _closure().historical_cut
    assert tuple(item.authority_ref.kind for item in cut.retrieval_cycles) == (
        M6ReplayAuthorityKind.M5_PRECEDENT_EXPOSURE,
    )
    assert all("TRAINING" not in kind.value for kind in M6ReplayAuthorityKind)

    with pytest.raises(ValidationError, match="retrieval"):
        cut.model_copy(
            update={
                "retrieval_cycles": (
                    _historical_retrieval().model_copy(
                        update={
                            "authority_ref": _ref(
                                M6ReplayAuthorityKind.M5_EMBEDDING,
                                "current-tail",
                                "1",
                            )
                        }
                    ),
                )
            }
        )

    with pytest.raises(ValidationError, match="cycle"):
        cut.model_copy(
            update={
                "retrieval_cycles": (
                    _historical_retrieval(),
                    _historical_retrieval(),
                )
            }
        )


def test_degraded_retrieval_cycle_binds_exact_m4_receipt_and_requires_contiguous_cut() -> None:
    degraded = _historical_retrieval(
        cycle_index=2,
        outcome=M6LockedRetrievalOutcomeKind.DEGRADED,
    )
    cut = M6HistoricalCausalCut(
        retrieval_cycles=(_historical_retrieval(), degraded),
    )

    assert cut.retrieval_cycle_count == 2
    assert cut.successful_exposure_count == 1
    assert cut.degraded_retrieval_count == 1

    with pytest.raises(ValidationError, match="retrieval authority kind"):
        degraded.model_copy(
            update={
                "authority_ref": _ref(
                    M6ReplayAuthorityKind.M5_PRECEDENT_EXPOSURE,
                    "wrong-degraded-authority",
                    "4",
                )
            }
        )
    with pytest.raises(ValidationError, match="contiguous"):
        cut.model_copy(
            update={
                "retrieval_cycles": (
                    _historical_retrieval(),
                    _historical_retrieval(cycle_index=3),
                )
            }
        )

    with pytest.raises(ValidationError, match="one hearing session"):
        cut.model_copy(
            update={
                "retrieval_cycles": (
                    _historical_retrieval(),
                    degraded.model_copy(update={"hearing_session_id": _sha("9")}),
                )
            }
        )
    with pytest.raises(ValidationError, match="cycle scopes"):
        cut.model_copy(
            update={
                "retrieval_cycles": (
                    _historical_retrieval(),
                    degraded.model_copy(update={"cycle_scope_id": _sha("2")}),
                )
            }
        )


def test_historical_retrieval_scope_must_match_closure_source_scope() -> None:
    closure = _closure()

    with pytest.raises(ValidationError, match="historical retrieval scope"):
        closure.model_copy(
            update={
                "historical_cut": M6HistoricalCausalCut(
                    retrieval_cycles=(
                        _historical_retrieval().model_copy(
                            update={"source_case_id": "case-foreign"}
                        ),
                    )
                )
            }
        )


@pytest.mark.parametrize(
    ("field_name", "forged_value"),
    (
        (
            "frames",
            (
                M6LockedFrameInput.model_construct(
                    frame_id="cam-01:stream-01:10",
                    document_sha256="BAD",
                    content_sha256=_sha("9"),
                ),
            ),
        ),
        (
            "detections",
            (
                M6LockedDetectionInput.model_construct(
                    detection_id="detection-001",
                    frame_id="cam-01:stream-01:10",
                    document_sha256="BAD",
                    model_manifest_id="BAD",
                ),
            ),
        ),
        (
            "embeddings",
            (
                M6LockedEmbeddingInput.model_construct(
                    scope=M6LockedEmbeddingScope.QUERY,
                    channel=M6LockedEmbeddingChannel.TEXT,
                    embedding_ref=_ref(
                        M6ReplayAuthorityKind.M5_EMBEDDING,
                        "embedding-query-text",
                        "b",
                    ),
                    request_id="BAD",
                    model_manifest_id=_sha("d"),
                ),
            ),
        ),
        (
            "model_calls",
            (
                M6LockedModelCallInput.model_construct(
                    **{
                        **_response_call().model_dump(mode="python", exclude_computed_fields=True),
                        "raw_size_bytes": -1,
                    }
                ),
            ),
        ),
        (
            "tool_results",
            (
                M6LockedToolResultInput.model_construct(
                    **{
                        **_tool_result().model_dump(mode="python", exclude_computed_fields=True),
                        "tool_result_document_sha256": "BAD",
                    }
                ),
            ),
        ),
        (
            "historical_cut",
            M6HistoricalCausalCut.model_construct(
                retrieval_cycles=(
                    M6LockedRetrievalCycleInput.model_construct(
                        source_run_id=_historical_retrieval().source_run_id,
                        source_case_id=_historical_retrieval().source_case_id,
                        hearing_session_id=_historical_retrieval().hearing_session_id,
                        cycle_index=0,
                        cycle_scope_id=_historical_retrieval().cycle_scope_id,
                        outcome=_historical_retrieval().outcome,
                        authority_ref=_historical_retrieval().authority_ref,
                    ),
                )
            ),
        ),
    ),
)
def test_replay_input_closure_revalidates_constructed_nested_inputs(
    field_name: str,
    forged_value: object,
) -> None:
    closure = _closure()
    payload = closure.model_dump(mode="python", exclude_computed_fields=True)
    payload[field_name] = forged_value

    with pytest.raises(ValidationError):
        M6ReplayInputClosureAuthority(**payload)


def test_provider_trap_binds_exact_execution_and_recomputes_capability_total() -> None:
    trap = M6ProviderTrapAuthority(
        command_id=_sha("1"),
        candidate_run_id="run-candidate",
        execution_component_manifest_id=_sha("2"),
        counters=M6ProviderCapabilityCounters(),
    )

    assert trap.external_capability_call_count == 0
    assert trap.clean is True
    assert M6ProviderTrapAuthority.model_validate(trap.model_dump(mode="json")) == trap

    called = trap.model_copy(
        update={
            "counters": M6ProviderCapabilityCounters(
                embedding_provider_calls=1,
                live_precedent_tail_query_calls=2,
                live_training_label_tail_query_calls=3,
            )
        }
    )
    assert called.external_capability_call_count == 6
    assert called.clean is False

    attacked = trap.model_dump(mode="json")
    attacked["external_capability_call_count"] = 1
    with pytest.raises(ValidationError, match="external_capability_call_count"):
        M6ProviderTrapAuthority.model_validate(attacked)


def test_provider_trap_revalidates_constructed_nested_counters() -> None:
    forged = M6ProviderCapabilityCounters.model_construct(
        perception_provider_calls=0,
        screening_vlm_provider_calls=0,
        hearing_vlm_provider_calls=0,
        embedding_provider_calls=1,
        acquisition_provider_calls=0,
        safety_signal_provider_calls=0,
        alert_channel_calls=0,
        response_recovery_calls=0,
        cache_write_calls=-1,
        live_precedent_tail_query_calls=0,
        live_training_label_tail_query_calls=0,
    )

    with pytest.raises(ValidationError):
        M6ProviderTrapAuthority(
            command_id=_sha("1"),
            candidate_run_id="run-candidate",
            execution_component_manifest_id=_sha("2"),
            counters=forged,
        )


def _source_determinism() -> M6ReplayLockedSourceDeterminismAuthority:
    return M6ReplayLockedSourceDeterminismAuthority(
        command_id=_sha("1"),
        execution_entry_id=_sha("2"),
        sample_id="sample-locked-001",
        source_run_id="run-baseline",
        candidate_run_id="run-candidate",
        source_manifest_id=_sha("3"),
        execution_component_manifest_id=_sha("4"),
        replay_input_closure_authority_id=_sha("5"),
        replay_input_closure_document_sha256=_sha("6"),
        source_identity_sha256=_sha("7"),
        first_source_snapshot_id=_sha("8"),
        second_source_snapshot_id=_sha("8"),
        first_semantic_case_hash=_sha("9"),
        second_semantic_case_hash=_sha("9"),
    )


def test_source_determinism_authority_binds_distinct_candidate_and_two_equal_reads() -> None:
    proof = _source_determinism()

    assert proof.projection_read_count == 2
    assert proof.first_source_snapshot_id == proof.second_source_snapshot_id
    assert proof.first_semantic_case_hash == proof.second_semantic_case_hash
    assert (
        M6ReplayLockedSourceDeterminismAuthority.model_validate(proof.model_dump(mode="json"))
        == proof
    )

    with pytest.raises(ValidationError, match="candidate run must differ"):
        proof.model_copy(update={"candidate_run_id": proof.source_run_id})
    with pytest.raises(ValidationError, match="not deterministic"):
        proof.model_copy(update={"second_semantic_case_hash": _sha("0")})

    attacked = proof.model_dump(mode="json")
    attacked["source_determinism_authority_id"] = _sha("0")
    with pytest.raises(ValidationError, match="source_determinism_authority_id"):
        M6ReplayLockedSourceDeterminismAuthority.model_validate(attacked)


def test_public_locked_replay_authority_schemas_validate_complete_documents() -> None:
    closure = _closure()
    trap = M6ProviderTrapAuthority(
        command_id=_sha("1"),
        candidate_run_id="run-candidate",
        execution_component_manifest_id=_sha("2"),
        counters=M6ProviderCapabilityCounters(),
    )
    schemas = expected_schema_files()

    for name, artifact in (
        ("m6-replay-input-closure-authority", closure),
        ("m6-provider-trap-authority", trap),
        ("m6-replay-locked-source-determinism-authority", _source_determinism()),
    ):
        schema = json.loads(schemas[f"{name}.schema.json"])
        Draft202012Validator(schema).validate(artifact.model_dump(mode="json"))

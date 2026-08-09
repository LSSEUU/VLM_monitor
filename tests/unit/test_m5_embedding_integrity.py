from __future__ import annotations

from pathlib import Path

import pytest

import labcourt.adapters.fake_precedent_embeddings as fake_precedent_embeddings
from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.application.m5_embedding_integrity import (
    M5_CONTROLLED_FAKE_EMBEDDING_DIMENSIONS,
    M5EmbeddingIntegrityError,
    M5EmbeddingIntegrityErrorCode,
    build_m5_controlled_fake_embedding,
    derive_m5_controlled_embedding_input_ref,
    derive_m5_controlled_fake_embedding,
    derive_m5_fake_sha256_signed_projection,
    is_m5_controlled_fake_model_manifest,
    require_m5_fake_sha256_signed_projection,
)
from labcourt.contracts.m5_precedents import M5EmbeddingChannel
from labcourt.contracts.manifests import ModelManifest, RunManifest

ROOT = Path(__file__).parents[2]


def _manifest() -> RunManifest:
    return RunManifest.model_validate_json(
        (ROOT / "tests" / "fixtures" / "m2" / "run-manifest-fake.json").read_text(encoding="utf-8")
    )


def test_controlled_fake_embedding_is_content_derived_and_channel_pinned() -> None:
    manifest = _manifest()
    provider = DeterministicFakePrecedentEmbeddingProvider()
    situation = "The same controlled situation has one stable semantic fake vector."
    first = build_m5_controlled_fake_embedding(
        channel=M5EmbeddingChannel.TEXT,
        situation_text=situation,
        model_manifest=manifest.models["text_embedding"],
        embedding_provider=provider,
    )
    second = build_m5_controlled_fake_embedding(
        channel=M5EmbeddingChannel.TEXT,
        situation_text=situation,
        model_manifest=manifest.models["text_embedding"],
        embedding_provider=provider,
    )
    visual = build_m5_controlled_fake_embedding(
        channel=M5EmbeddingChannel.VISUAL,
        situation_text=situation,
        model_manifest=manifest.models["visual_embedding"],
        embedding_provider=provider,
    )

    assert first == second
    assert first.request.dimensions == M5_CONTROLLED_FAKE_EMBEDDING_DIMENSIONS
    assert first.request.model_manifest_id == manifest.models["text_embedding"].model_manifest_id
    assert visual.request.model_manifest_id == (
        manifest.models["visual_embedding"].model_manifest_id
    )
    assert visual.request.input_ref != first.request.input_ref
    assert first.request.input_ref == derive_m5_controlled_embedding_input_ref(
        channel=M5EmbeddingChannel.TEXT,
        situation_text=situation,
    )


def test_fake_signed_projection_is_pure_and_rejects_a_forged_stored_vector() -> None:
    manifest = _manifest()
    situation = "One stored vector must remain exactly reproducible without a provider."
    payload = situation.encode("utf-8")
    stored = derive_m5_controlled_fake_embedding(
        channel=M5EmbeddingChannel.TEXT,
        situation_text=situation,
        model_manifest=manifest.models["text_embedding"],
    )

    assert derive_m5_fake_sha256_signed_projection(stored.request, payload) == stored
    assert require_m5_fake_sha256_signed_projection(stored, payload) == stored

    forged = stored.model_copy(update={"values": tuple(-value for value in stored.values)})
    with pytest.raises(ValueError, match="exact fake embedding derivation"):
        require_m5_fake_sha256_signed_projection(forged, payload)


def test_fake_provider_delegates_to_the_shared_pure_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest()
    situation = "The provider adapter must not own a second projection implementation."
    payload = situation.encode("utf-8")
    expected = derive_m5_controlled_fake_embedding(
        channel=M5EmbeddingChannel.TEXT,
        situation_text=situation,
        model_manifest=manifest.models["text_embedding"],
    )
    calls: list[tuple[object, bytes]] = []

    def projection(request: object, authored_payload: bytes) -> object:
        calls.append((request, authored_payload))
        return expected

    monkeypatch.setattr(
        fake_precedent_embeddings,
        "derive_m5_fake_sha256_signed_projection",
        projection,
    )

    actual = DeterministicFakePrecedentEmbeddingProvider().embed(expected.request, payload)

    assert actual is expected
    assert calls == [(expected.request, payload)]


def test_controlled_fake_embedding_rejects_cross_channel_manifest() -> None:
    manifest = _manifest()
    with pytest.raises(M5EmbeddingIntegrityError) as raised:
        build_m5_controlled_fake_embedding(
            channel=M5EmbeddingChannel.VISUAL,
            situation_text="Controlled visual input.",
            model_manifest=manifest.models["text_embedding"],
            embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
        )
    assert raised.value.code == M5EmbeddingIntegrityErrorCode.MANIFEST_MISMATCH


def test_exact_legacy_pilot_disabled_identity_is_a_replayable_fake_projection() -> None:
    model = ModelManifest(
        component="text_embedding",
        provider="not-invoked",
        model="pilot-a2-text_embedding-disabled",
        revision="1.0.0",
        weights_sha256=None,
        license_id="no-weights",
    )

    assert is_m5_controlled_fake_model_manifest(model)
    embedding = derive_m5_controlled_fake_embedding(
        channel=M5EmbeddingChannel.TEXT,
        situation_text="Legacy pilot closure remains offline and exactly replayable.",
        model_manifest=model,
    )
    assert embedding.request.model_manifest_id == model.model_manifest_id


def test_arbitrary_not_invoked_embedding_identity_remains_unsupported() -> None:
    model = ModelManifest(
        component="text_embedding",
        provider="not-invoked",
        model="uncontrolled-disabled-model",
        revision="1.0.0",
        weights_sha256=None,
        license_id="no-weights",
    )

    assert not is_m5_controlled_fake_model_manifest(model)
    with pytest.raises(M5EmbeddingIntegrityError) as raised:
        derive_m5_controlled_fake_embedding(
            channel=M5EmbeddingChannel.TEXT,
            situation_text="This identity is outside the exact pilot compatibility profile.",
            model_manifest=model,
        )
    assert raised.value.code == M5EmbeddingIntegrityErrorCode.PROVIDER_UNSUPPORTED


@pytest.mark.parametrize(
    ("channel", "ordinal"),
    [
        (M5EmbeddingChannel.TEXT, 1),
        (M5EmbeddingChannel.VISUAL, -1),
        (M5EmbeddingChannel.VISUAL, True),
    ],
)
def test_controlled_input_reference_rejects_unbounded_or_ambiguous_ordinal(
    channel: M5EmbeddingChannel,
    ordinal: object,
) -> None:
    with pytest.raises(M5EmbeddingIntegrityError) as raised:
        derive_m5_controlled_embedding_input_ref(
            channel=channel,
            situation_text="Controlled input.",
            ordinal=ordinal,  # type: ignore[arg-type]
        )
    assert raised.value.code == M5EmbeddingIntegrityErrorCode.INVALID_ARGUMENT

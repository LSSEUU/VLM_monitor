"""Controlled deterministic M5 embedding inputs at trusted boundaries."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from math import fsum, sqrt

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.m5_precedents import (
    MAX_M5_VISUAL_EMBEDDINGS,
    M5EmbeddingChannel,
    M5EmbeddingRequest,
    M5EmbeddingVector,
)
from labcourt.contracts.manifests import ModelManifest
from labcourt.ports.m5_precedents import M5PrecedentEmbeddingProvider

M5_CONTROLLED_FAKE_EMBEDDING_DIMENSIONS = 32
MAX_M5_FAKE_EMBEDDING_INPUT_BYTES = 16 * 1024 * 1024
_M5_FAKE_EMBEDDING_DOMAIN = b"labcourt-m5-fake-embedding-v1\x00"


class M5EmbeddingIntegrityErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    MANIFEST_MISMATCH = "MANIFEST_MISMATCH"
    PROVIDER_CONTRACT_VIOLATION = "PROVIDER_CONTRACT_VIOLATION"
    PROVIDER_UNSUPPORTED = "PROVIDER_UNSUPPORTED"


class M5EmbeddingIntegrityError(RuntimeError):
    """A controlled fake embedding cannot be derived from trusted inputs."""

    def __init__(self, code: M5EmbeddingIntegrityErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


def _component_for_channel(channel: M5EmbeddingChannel) -> str:
    return {
        M5EmbeddingChannel.TEXT: "text_embedding",
        M5EmbeddingChannel.VISUAL: "visual_embedding",
    }[channel]


def derive_m5_controlled_embedding_input_ref(
    *,
    channel: M5EmbeddingChannel,
    situation_text: str,
    ordinal: int = 0,
) -> str:
    """Derive a domain-separated reference from the exact semantic fake input."""

    if (
        not isinstance(channel, M5EmbeddingChannel)
        or not isinstance(situation_text, str)
        or not situation_text
        or isinstance(ordinal, bool)
        or not isinstance(ordinal, int)
        or not 0 <= ordinal < MAX_M5_VISUAL_EMBEDDINGS
        or (channel == M5EmbeddingChannel.TEXT and ordinal != 0)
    ):
        raise M5EmbeddingIntegrityError(M5EmbeddingIntegrityErrorCode.INVALID_ARGUMENT)
    payload_sha256 = hashlib.sha256(situation_text.encode("utf-8")).hexdigest()
    return sha256_hex(
        [
            "m5-controlled-fake-embedding-input",
            1,
            channel,
            payload_sha256,
            ordinal,
        ]
    )


def derive_m5_fake_sha256_signed_projection(
    request: M5EmbeddingRequest,
    payload: bytes,
) -> M5EmbeddingVector:
    """Pure implementation of ``FAKE_SHA256_SIGNED_PROJECTION_V1``."""

    if not isinstance(request, M5EmbeddingRequest):
        raise TypeError("fake embedding request must be an M5EmbeddingRequest")
    if not isinstance(payload, bytes):
        raise TypeError("fake embedding payload must be bytes")
    if len(payload) > MAX_M5_FAKE_EMBEDDING_INPUT_BYTES:
        raise ValueError("fake embedding payload exceeds the bounded input size")
    if hashlib.sha256(payload).hexdigest() != request.input_sha256:
        raise ValueError("fake embedding payload does not match input_sha256")

    seed = _M5_FAKE_EMBEDDING_DOMAIN + request.request_id.encode("ascii") + b"\x00" + payload
    values: list[float] = []
    for index in range(request.dimensions):
        digest = hashlib.sha256(seed + index.to_bytes(4, "big")).digest()
        unsigned = int.from_bytes(digest[:8], "big")
        values.append((unsigned / ((1 << 64) - 1)) * 2.0 - 1.0)
    norm = sqrt(fsum(value * value for value in values))
    if norm == 0.0:  # Cryptographically implausible; keep the fake total.
        values[0] = 1.0
        norm = 1.0
    return M5EmbeddingVector(
        request=request,
        values=tuple(float(value / norm) for value in values),
    )


def require_m5_fake_sha256_signed_projection(
    embedding: M5EmbeddingVector,
    payload: bytes,
) -> M5EmbeddingVector:
    """Verify one stored vector against the exact pure fake derivation."""

    if not isinstance(embedding, M5EmbeddingVector):
        raise TypeError("stored embedding must be an M5EmbeddingVector")
    expected = derive_m5_fake_sha256_signed_projection(embedding.request, payload)
    if embedding != expected:
        raise ValueError("stored vector does not match the exact fake embedding derivation")
    return expected


def _require_controlled_fake_authorities(
    *,
    channel: M5EmbeddingChannel,
    model_manifest: ModelManifest,
) -> None:
    if not isinstance(channel, M5EmbeddingChannel) or not isinstance(model_manifest, ModelManifest):
        raise M5EmbeddingIntegrityError(M5EmbeddingIntegrityErrorCode.INVALID_ARGUMENT)
    expected_component = _component_for_channel(channel)
    if model_manifest.component != expected_component:
        raise M5EmbeddingIntegrityError(M5EmbeddingIntegrityErrorCode.MANIFEST_MISMATCH)
    if model_manifest.provider != "fake":
        raise M5EmbeddingIntegrityError(M5EmbeddingIntegrityErrorCode.PROVIDER_UNSUPPORTED)


def _controlled_fake_request(
    *,
    channel: M5EmbeddingChannel,
    situation_text: str,
    model_manifest: ModelManifest,
    ordinal: int,
) -> tuple[M5EmbeddingRequest, bytes]:
    payload = situation_text.encode("utf-8")
    return (
        M5EmbeddingRequest(
            channel=channel,
            input_ref=derive_m5_controlled_embedding_input_ref(
                channel=channel,
                situation_text=situation_text,
                ordinal=ordinal,
            ),
            input_sha256=hashlib.sha256(payload).hexdigest(),
            model_manifest_id=model_manifest.model_manifest_id,
            dimensions=M5_CONTROLLED_FAKE_EMBEDDING_DIMENSIONS,
        ),
        payload,
    )


def derive_m5_controlled_fake_embedding(
    *,
    channel: M5EmbeddingChannel,
    situation_text: str,
    model_manifest: ModelManifest,
    ordinal: int = 0,
) -> M5EmbeddingVector:
    """Derive a manifest-pinned controlled embedding without a provider call."""

    _require_controlled_fake_authorities(channel=channel, model_manifest=model_manifest)
    try:
        request, payload = _controlled_fake_request(
            channel=channel,
            situation_text=situation_text,
            model_manifest=model_manifest,
            ordinal=ordinal,
        )
        return derive_m5_fake_sha256_signed_projection(request, payload)
    except M5EmbeddingIntegrityError:
        raise
    except (TypeError, ValueError) as exc:
        raise M5EmbeddingIntegrityError(M5EmbeddingIntegrityErrorCode.INVALID_ARGUMENT) from exc


def build_m5_controlled_fake_embedding(
    *,
    channel: M5EmbeddingChannel,
    situation_text: str,
    model_manifest: ModelManifest,
    embedding_provider: M5PrecedentEmbeddingProvider,
    ordinal: int = 0,
) -> M5EmbeddingVector:
    """Build one fixed-dimension vector from a manifest-pinned authored input."""

    if not callable(getattr(embedding_provider, "embed", None)):
        raise M5EmbeddingIntegrityError(M5EmbeddingIntegrityErrorCode.INVALID_ARGUMENT)
    _require_controlled_fake_authorities(channel=channel, model_manifest=model_manifest)

    try:
        request, payload = _controlled_fake_request(
            channel=channel,
            situation_text=situation_text,
            model_manifest=model_manifest,
            ordinal=ordinal,
        )
        embedding = embedding_provider.embed(request, payload)
    except M5EmbeddingIntegrityError:
        raise
    except (TypeError, ValueError, RuntimeError) as exc:
        raise M5EmbeddingIntegrityError(
            M5EmbeddingIntegrityErrorCode.PROVIDER_CONTRACT_VIOLATION
        ) from exc
    if not isinstance(embedding, M5EmbeddingVector) or embedding.request != request:
        raise M5EmbeddingIntegrityError(M5EmbeddingIntegrityErrorCode.PROVIDER_CONTRACT_VIOLATION)
    try:
        canonical = M5EmbeddingVector.model_validate(embedding.model_dump(mode="json"))
        return require_m5_fake_sha256_signed_projection(canonical, payload)
    except (TypeError, ValueError) as exc:
        raise M5EmbeddingIntegrityError(
            M5EmbeddingIntegrityErrorCode.PROVIDER_CONTRACT_VIOLATION
        ) from exc


__all__ = [
    "M5_CONTROLLED_FAKE_EMBEDDING_DIMENSIONS",
    "MAX_M5_FAKE_EMBEDDING_INPUT_BYTES",
    "M5EmbeddingIntegrityError",
    "M5EmbeddingIntegrityErrorCode",
    "build_m5_controlled_fake_embedding",
    "derive_m5_controlled_embedding_input_ref",
    "derive_m5_controlled_fake_embedding",
    "derive_m5_fake_sha256_signed_projection",
    "require_m5_fake_sha256_signed_projection",
]

"""Fail-closed physical byte resolution for selected M6 upgrade artifacts.

This module is application-only glue. It does not query SQLite, open media, or
invoke a model: callers provide already scoped read-only authority and a local
pixel port. Every returned reference is rebuilt from bytes observed here.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import NoReturn, cast

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.references import parse_frame_id, require_reference_token
from labcourt.domain.m6_embedding_authority import M6ResolvedEmbeddingAuthority
from labcourt.domain.m6_semantic_projection import M6ResolvedAcquisition
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_perception import M6FrameAuthorityDocument
from labcourt.ports.pixels import (
    PixelFrameProvider,
    RGB8Frame,
    rgb8_pixel_preimage_size_bytes,
    rgb8_pixel_sha256,
)


class M6UpgradePhysicalResolutionErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    FRAME_SCOPE_MISMATCH = "FRAME_SCOPE_MISMATCH"
    FRAME_DOCUMENT_INVALID = "FRAME_DOCUMENT_INVALID"
    FRAME_BINDING_MISMATCH = "FRAME_BINDING_MISMATCH"
    FRAME_PROVIDER_FAILED = "FRAME_PROVIDER_FAILED"
    FRAME_PIXEL_AUTHORITY_INVALID = "FRAME_PIXEL_AUTHORITY_INVALID"
    FRAME_PHYSICAL_REF_INVALID = "FRAME_PHYSICAL_REF_INVALID"
    TOOL_RESULT_AUTHORITY_INVALID = "TOOL_RESULT_AUTHORITY_INVALID"
    TOOL_RESULT_SCOPE_MISMATCH = "TOOL_RESULT_SCOPE_MISMATCH"
    TOOL_RESULT_BINDING_MISMATCH = "TOOL_RESULT_BINDING_MISMATCH"
    TOOL_RESULT_PHYSICAL_REF_INVALID = "TOOL_RESULT_PHYSICAL_REF_INVALID"
    EMBEDDING_AUTHORITY_INVALID = "EMBEDDING_AUTHORITY_INVALID"
    EMBEDDING_BINDING_MISMATCH = "EMBEDDING_BINDING_MISMATCH"
    EMBEDDING_PHYSICAL_REF_INVALID = "EMBEDDING_PHYSICAL_REF_INVALID"


class M6UpgradePhysicalResolutionError(LabCourtError):
    """One physical artifact could not be proven from trusted authority."""

    def __init__(self, code: M6UpgradePhysicalResolutionErrorCode) -> None:
        if not isinstance(code, M6UpgradePhysicalResolutionErrorCode):
            raise TypeError("code must be an M6UpgradePhysicalResolutionErrorCode")
        self.code = code
        super().__init__(f"M6 upgrade physical resolution failed: {code.value}")


def _fail(code: M6UpgradePhysicalResolutionErrorCode) -> NoReturn:
    raise M6UpgradePhysicalResolutionError(code)


def _document_sha256(canonical_document: str) -> str:
    return hashlib.sha256(canonical_document.encode("utf-8")).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_frame_arguments(
    *,
    expected_run_id: object,
    expected_frame_id: object,
    authority: object,
    provider: object,
) -> tuple[str, str, M6FrameAuthorityDocument, PixelFrameProvider]:
    if not isinstance(authority, M6FrameAuthorityDocument):
        _fail(M6UpgradePhysicalResolutionErrorCode.INVALID_ARGUMENT)
    try:
        if not isinstance(expected_run_id, str):
            raise TypeError("expected_run_id must be a string")
        controlled_run_id = require_reference_token(
            expected_run_id,
            "M6 upgrade Frame run_id",
        )
        if not isinstance(expected_frame_id, str):
            raise TypeError("expected_frame_id must be a string")
        parse_frame_id(expected_frame_id)
    except (TypeError, ValueError):
        _fail(M6UpgradePhysicalResolutionErrorCode.INVALID_ARGUMENT)
    if not callable(getattr(provider, "read_rgb8", None)):
        _fail(M6UpgradePhysicalResolutionErrorCode.INVALID_ARGUMENT)
    return controlled_run_id, expected_frame_id, authority, cast(PixelFrameProvider, provider)


def _parse_canonical_frame(authority: M6FrameAuthorityDocument) -> FrameRef:
    if (
        not isinstance(authority.canonical_document, str)
        or not _is_sha256(authority.document_sha256)
        or not _is_sha256(authority.content_sha256)
    ):
        _fail(M6UpgradePhysicalResolutionErrorCode.FRAME_DOCUMENT_INVALID)
    try:
        frame = FrameRef.model_validate_json(authority.canonical_document)
    except (TypeError, ValueError, ValidationError):
        _fail(M6UpgradePhysicalResolutionErrorCode.FRAME_DOCUMENT_INVALID)
    if (
        canonical_json(frame.model_dump(mode="json")) != authority.canonical_document
        or _document_sha256(authority.canonical_document) != authority.document_sha256
    ):
        _fail(M6UpgradePhysicalResolutionErrorCode.FRAME_DOCUMENT_INVALID)
    return frame


def resolve_m6_upgrade_frame_physical_ref(
    *,
    expected_run_id: str,
    expected_frame_id: str,
    authority: M6FrameAuthorityDocument,
    provider: PixelFrameProvider,
) -> M6UpgradePhysicalArtifactRef:
    """Rebuild one FRAME reference from canonical metadata and LCPIX1 bytes.

    ``authority.run_id`` is compared with the caller's frozen source run. The
    Frame document is required to be exact LCJ-1 text, while ``content_sha256``
    and ``size_bytes`` are recomputed from the complete LCPIX1 preimage returned
    by the local pixel provider.
    """

    run_id, frame_id, controlled_authority, controlled_provider = _validate_frame_arguments(
        expected_run_id=expected_run_id,
        expected_frame_id=expected_frame_id,
        authority=authority,
        provider=provider,
    )
    if controlled_authority.run_id != run_id:
        _fail(M6UpgradePhysicalResolutionErrorCode.FRAME_SCOPE_MISMATCH)
    if controlled_authority.frame_id != frame_id:
        _fail(M6UpgradePhysicalResolutionErrorCode.FRAME_BINDING_MISMATCH)

    frame = _parse_canonical_frame(controlled_authority)
    if (
        frame.frame_id != frame_id
        or frame.content_sha256 is None
        or frame.content_sha256 != controlled_authority.content_sha256
    ):
        _fail(M6UpgradePhysicalResolutionErrorCode.FRAME_BINDING_MISMATCH)

    try:
        observed = controlled_provider.read_rgb8(frame_id)
    except Exception:
        _fail(M6UpgradePhysicalResolutionErrorCode.FRAME_PROVIDER_FAILED)
    if not isinstance(observed, RGB8Frame):
        _fail(M6UpgradePhysicalResolutionErrorCode.FRAME_PIXEL_AUTHORITY_INVALID)
    try:
        pixels = RGB8Frame(frame=observed.frame, pixels=observed.pixels)
    except (TypeError, ValueError):
        _fail(M6UpgradePhysicalResolutionErrorCode.FRAME_PIXEL_AUTHORITY_INVALID)
    if pixels.frame != frame:
        _fail(M6UpgradePhysicalResolutionErrorCode.FRAME_PIXEL_AUTHORITY_INVALID)
    try:
        content_sha256 = rgb8_pixel_sha256(frame.width, frame.height, pixels.pixels)
        size_bytes = rgb8_pixel_preimage_size_bytes(
            frame.width,
            frame.height,
            pixels.pixels,
        )
    except (TypeError, ValueError):
        _fail(M6UpgradePhysicalResolutionErrorCode.FRAME_PIXEL_AUTHORITY_INVALID)
    if content_sha256 != frame.content_sha256:
        _fail(M6UpgradePhysicalResolutionErrorCode.FRAME_PIXEL_AUTHORITY_INVALID)
    try:
        return M6UpgradePhysicalArtifactRef(
            source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
            kind=M6UpgradePhysicalArtifactKind.FRAME,
            artifact_id=frame.frame_id,
            document_sha256=controlled_authority.document_sha256,
            content_sha256=content_sha256,
            size_bytes=size_bytes,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6UpgradePhysicalResolutionErrorCode.FRAME_PHYSICAL_REF_INVALID)


def _controlled_acquisition(authority: object) -> M6ResolvedAcquisition:
    if not isinstance(authority, M6ResolvedAcquisition):
        _fail(M6UpgradePhysicalResolutionErrorCode.INVALID_ARGUMENT)
    try:
        return M6ResolvedAcquisition(
            locked_input=authority.locked_input,
            request=authority.request,
            execution_manifest=authority.execution_manifest,
            publication=authority.publication,
            receipt=authority.receipt,
            derivation=authority.derivation,
            previous_evidence_pack=authority.previous_evidence_pack,
            resulting_evidence_pack=authority.resulting_evidence_pack,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6UpgradePhysicalResolutionErrorCode.TOOL_RESULT_AUTHORITY_INVALID)


def derive_m6_upgrade_tool_result_physical_ref(
    *,
    expected_run_id: str,
    expected_tool_result_id: str,
    authority: M6ResolvedAcquisition,
) -> M6UpgradePhysicalArtifactRef:
    """Derive one TOOL_RESULT document from a complete M4 successor closure.

    M4 stores ToolResult nested in publication, receipt, and resulting
    EvidencePack authority. ``M6ResolvedAcquisition`` proves those copies are
    identical and binds their request, manifest, derivation, and predecessor.
    Therefore no new persistence schema is needed for this derived document.
    """

    try:
        run_id = require_reference_token(expected_run_id, "M6 upgrade ToolResult run_id")
    except (TypeError, ValueError):
        _fail(M6UpgradePhysicalResolutionErrorCode.INVALID_ARGUMENT)
    if not _is_sha256(expected_tool_result_id):
        _fail(M6UpgradePhysicalResolutionErrorCode.INVALID_ARGUMENT)
    controlled = _controlled_acquisition(authority)
    if controlled.request.run_id != run_id:
        _fail(M6UpgradePhysicalResolutionErrorCode.TOOL_RESULT_SCOPE_MISMATCH)
    result = controlled.publication.tool_result
    if result.tool_result_id != expected_tool_result_id:
        _fail(M6UpgradePhysicalResolutionErrorCode.TOOL_RESULT_BINDING_MISMATCH)

    canonical_document = canonical_json(result.model_dump(mode="json"))
    document_sha256 = _document_sha256(canonical_document)
    if document_sha256 != controlled.locked_input.tool_result_document_sha256:
        _fail(M6UpgradePhysicalResolutionErrorCode.TOOL_RESULT_AUTHORITY_INVALID)
    try:
        return M6UpgradePhysicalArtifactRef(
            source=M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
            kind=M6UpgradePhysicalArtifactKind.TOOL_RESULT,
            artifact_id=result.tool_result_id,
            document_sha256=document_sha256,
            content_sha256=document_sha256,
            size_bytes=len(canonical_document.encode("utf-8")),
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6UpgradePhysicalResolutionErrorCode.TOOL_RESULT_PHYSICAL_REF_INVALID)


def derive_m6_upgrade_embedding_physical_ref(
    *,
    expected_embedding_id: str,
    authority: M6ResolvedEmbeddingAuthority,
) -> M6UpgradePhysicalArtifactRef:
    """Rebuild an M5 embedding ref from a fully resolved retrieval closure.

    Query vectors are nested in the exact exposure rather than stored in the
    durable ``precedent_embeddings`` table. The resolved authority validates
    both forms, so this identity-first derivation covers query and precedent
    vectors without silently dropping the nested query artifact.
    """

    if not _is_sha256(expected_embedding_id) or not isinstance(
        authority,
        M6ResolvedEmbeddingAuthority,
    ):
        _fail(M6UpgradePhysicalResolutionErrorCode.INVALID_ARGUMENT)
    try:
        controlled = M6ResolvedEmbeddingAuthority(
            scope=authority.scope,
            channel=authority.channel,
            vector=authority.vector,
            document_sha256=authority.document_sha256,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6UpgradePhysicalResolutionErrorCode.EMBEDDING_AUTHORITY_INVALID)
    if controlled != authority:
        _fail(M6UpgradePhysicalResolutionErrorCode.EMBEDDING_AUTHORITY_INVALID)
    if controlled.embedding_id != expected_embedding_id:
        _fail(M6UpgradePhysicalResolutionErrorCode.EMBEDDING_BINDING_MISMATCH)
    canonical_document = canonical_json(controlled.vector.model_dump(mode="json"))
    if _document_sha256(canonical_document) != controlled.document_sha256:
        _fail(M6UpgradePhysicalResolutionErrorCode.EMBEDDING_AUTHORITY_INVALID)
    try:
        return M6UpgradePhysicalArtifactRef(
            source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
            kind=M6UpgradePhysicalArtifactKind.EMBEDDING,
            artifact_id=controlled.embedding_id,
            document_sha256=controlled.document_sha256,
            content_sha256=controlled.document_sha256,
            size_bytes=len(canonical_document.encode("utf-8")),
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6UpgradePhysicalResolutionErrorCode.EMBEDDING_PHYSICAL_REF_INVALID)


__all__ = [
    "M6UpgradePhysicalResolutionError",
    "M6UpgradePhysicalResolutionErrorCode",
    "derive_m6_upgrade_embedding_physical_ref",
    "derive_m6_upgrade_tool_result_physical_ref",
    "resolve_m6_upgrade_frame_physical_ref",
]

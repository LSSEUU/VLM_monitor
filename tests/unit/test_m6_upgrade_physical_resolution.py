"""Physical byte-authority tests for M6 upgrade execution artifacts."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from labcourt.application.m6_acquisition_projection import resolve_m6_locked_acquisitions
from labcourt.application.m6_embedding_authority import assemble_m6_resolved_embeddings
from labcourt.application.m6_upgrade_physical_resolution import (
    M6UpgradePhysicalResolutionError,
    M6UpgradePhysicalResolutionErrorCode,
    derive_m6_upgrade_embedding_physical_ref,
    derive_m6_upgrade_tool_result_physical_ref,
    resolve_m6_upgrade_frame_physical_ref,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.ports.m6_perception import M6FrameAuthorityDocument
from labcourt.ports.pixels import (
    RGB8Frame,
    rgb8_pixel_preimage,
    rgb8_pixel_preimage_size_bytes,
    rgb8_pixel_sha256,
)
from tests.contract.test_m5_precedent_usage_contracts import _exposure
from tests.unit.test_m6_acquisition_projection import _bundle
from tests.unit.test_m6_embedding_authority import (
    _closure as _embedding_closure,
)
from tests.unit.test_m6_embedding_authority import (
    _snapshot as _embedding_snapshot,
)


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_text(value: str) -> str:
    return _sha_bytes(value.encode("utf-8"))


def _frame_authority(
    *,
    run_id: str = "run-source",
    frame_index: int = 7,
    pixels: bytes = bytes((1, 2, 3, 4, 5, 6)),
) -> tuple[M6FrameAuthorityDocument, RGB8Frame]:
    frame = FrameRef(
        camera_id="cam-01",
        stream_id="stream-01",
        frame_index=frame_index,
        fps_num=30,
        fps_den=1,
        width=2,
        height=1,
        content_sha256=rgb8_pixel_sha256(2, 1, pixels),
    )
    document = canonical_json(frame.model_dump(mode="json"))
    authority = M6FrameAuthorityDocument(
        run_id=run_id,
        manifest_id="a" * 64,
        frame_id=frame.frame_id,
        content_sha256=frame.content_sha256,
        canonical_document=document,
        document_sha256=_sha_text(document),
    )
    return authority, RGB8Frame(frame=frame, pixels=pixels)


class _PixelProvider:
    def __init__(self, value: object) -> None:
        self.value = value
        self.requested_ids: list[str] = []

    def read_rgb8(self, frame_id: str) -> RGB8Frame:
        self.requested_ids.append(frame_id)
        if isinstance(self.value, BaseException):
            raise self.value
        return self.value  # type: ignore[return-value]


def _error_code(call: object) -> M6UpgradePhysicalResolutionErrorCode:
    assert callable(call)
    with pytest.raises(M6UpgradePhysicalResolutionError) as raised:
        call()
    return raised.value.code


def test_lcpix1_preimage_and_size_include_the_complete_domain_separated_bytes() -> None:
    pixels = bytes((1, 2, 3, 4, 5, 6))
    expected = b"LCPIX1\x00\x00\x00\x00\x02\x00\x00\x00\x01RGB8\x00" + pixels

    assert rgb8_pixel_preimage(2, 1, pixels) == expected
    assert rgb8_pixel_preimage_size_bytes(2, 1, pixels) == len(expected) == 20 + len(pixels)
    assert rgb8_pixel_sha256(2, 1, pixels) == _sha_bytes(expected)


def test_frame_resolver_rebuilds_exact_document_and_lcpix1_authority() -> None:
    authority, runtime = _frame_authority()
    provider = _PixelProvider(runtime)

    resolved = resolve_m6_upgrade_frame_physical_ref(
        expected_run_id=authority.run_id,
        expected_frame_id=authority.frame_id,
        authority=authority,
        provider=provider,
    )

    assert resolved.source == M6UpgradePhysicalArtifactSource.M2_PERCEPTION
    assert resolved.kind == M6UpgradePhysicalArtifactKind.FRAME
    assert resolved.artifact_id == authority.frame_id
    assert resolved.container_id is None
    assert resolved.document_sha256 == authority.document_sha256
    assert resolved.content_sha256 == runtime.frame.content_sha256
    assert resolved.size_bytes == rgb8_pixel_preimage_size_bytes(
        runtime.frame.width,
        runtime.frame.height,
        runtime.pixels,
    )
    assert provider.requested_ids == [authority.frame_id]


@pytest.mark.parametrize(
    ("mutate", "expected"),
    (
        (
            lambda authority: replace(authority, run_id="other-run"),
            M6UpgradePhysicalResolutionErrorCode.FRAME_SCOPE_MISMATCH,
        ),
        (
            lambda authority: replace(authority, frame_id="cam-01:stream-01:8"),
            M6UpgradePhysicalResolutionErrorCode.FRAME_BINDING_MISMATCH,
        ),
        (
            lambda authority: replace(authority, document_sha256="b" * 64),
            M6UpgradePhysicalResolutionErrorCode.FRAME_DOCUMENT_INVALID,
        ),
        (
            lambda authority: replace(
                authority,
                canonical_document=authority.canonical_document + " ",
            ),
            M6UpgradePhysicalResolutionErrorCode.FRAME_DOCUMENT_INVALID,
        ),
    ),
)
def test_frame_resolver_rejects_scope_binding_and_document_forgery(
    mutate: object,
    expected: M6UpgradePhysicalResolutionErrorCode,
) -> None:
    assert callable(mutate)
    authority, runtime = _frame_authority()
    forged = mutate(authority)

    assert (
        _error_code(
            lambda: resolve_m6_upgrade_frame_physical_ref(
                expected_run_id=authority.run_id,
                expected_frame_id=authority.frame_id,
                authority=forged,
                provider=_PixelProvider(runtime),
            )
        )
        == expected
    )


def test_frame_resolver_converts_provider_failure_and_wrong_runtime_frame_to_typed_failures() -> (
    None
):
    authority, runtime = _frame_authority()
    other_authority, other_runtime = _frame_authority(frame_index=8)
    assert other_authority.frame_id != authority.frame_id

    assert (
        _error_code(
            lambda: resolve_m6_upgrade_frame_physical_ref(
                expected_run_id=authority.run_id,
                expected_frame_id=authority.frame_id,
                authority=authority,
                provider=_PixelProvider(RuntimeError("offline fixture missing")),
            )
        )
        == M6UpgradePhysicalResolutionErrorCode.FRAME_PROVIDER_FAILED
    )
    assert (
        _error_code(
            lambda: resolve_m6_upgrade_frame_physical_ref(
                expected_run_id=authority.run_id,
                expected_frame_id=authority.frame_id,
                authority=authority,
                provider=_PixelProvider(other_runtime),
            )
        )
        == M6UpgradePhysicalResolutionErrorCode.FRAME_PIXEL_AUTHORITY_INVALID
    )
    assert runtime.frame.frame_id == authority.frame_id


def test_tool_result_resolver_derives_canonical_document_from_complete_m4_closure() -> None:
    case, snapshot, locked = _bundle()
    (authority,) = resolve_m6_locked_acquisitions(
        source_case=case,
        snapshot=snapshot,
        locked_tool_results=(locked,),
    )
    tool_result = authority.publication.tool_result
    document = canonical_json(tool_result.model_dump(mode="json"))

    resolved = derive_m6_upgrade_tool_result_physical_ref(
        expected_run_id=case.run_id,
        expected_tool_result_id=tool_result.tool_result_id,
        authority=authority,
    )

    assert resolved.source == M6UpgradePhysicalArtifactSource.M4_ACQUISITION
    assert resolved.kind == M6UpgradePhysicalArtifactKind.TOOL_RESULT
    assert resolved.artifact_id == tool_result.tool_result_id
    assert resolved.document_sha256 == _sha_text(document)
    assert resolved.content_sha256 == resolved.document_sha256
    assert resolved.size_bytes == len(document.encode("utf-8"))


def test_tool_result_resolver_rejects_scope_id_and_broken_m4_closure() -> None:
    case, snapshot, locked = _bundle()
    (authority,) = resolve_m6_locked_acquisitions(
        source_case=case,
        snapshot=snapshot,
        locked_tool_results=(locked,),
    )

    assert (
        _error_code(
            lambda: derive_m6_upgrade_tool_result_physical_ref(
                expected_run_id="other-run",
                expected_tool_result_id=authority.tool_result_id,
                authority=authority,
            )
        )
        == M6UpgradePhysicalResolutionErrorCode.TOOL_RESULT_SCOPE_MISMATCH
    )
    assert (
        _error_code(
            lambda: derive_m6_upgrade_tool_result_physical_ref(
                expected_run_id=case.run_id,
                expected_tool_result_id="f" * 64,
                authority=authority,
            )
        )
        == M6UpgradePhysicalResolutionErrorCode.TOOL_RESULT_BINDING_MISMATCH
    )

    _other_case, other_snapshot, other_locked = _bundle(run_id="other-run")
    (other_authority,) = resolve_m6_locked_acquisitions(
        source_case=_other_case,
        snapshot=other_snapshot,
        locked_tool_results=(other_locked,),
    )
    object.__setattr__(authority, "receipt", other_authority.receipt)
    assert (
        _error_code(
            lambda: derive_m6_upgrade_tool_result_physical_ref(
                expected_run_id=case.run_id,
                expected_tool_result_id=authority.tool_result_id,
                authority=authority,
            )
        )
        == M6UpgradePhysicalResolutionErrorCode.TOOL_RESULT_AUTHORITY_INVALID
    )


def test_embedding_resolver_derives_query_and_precedent_canonical_bytes() -> None:
    exposure = _exposure()
    snapshot = _embedding_snapshot((exposure,))
    resolved = assemble_m6_resolved_embeddings(
        closure=_embedding_closure((exposure,), snapshot),
        snapshot=snapshot,
    )

    refs = tuple(
        derive_m6_upgrade_embedding_physical_ref(
            expected_embedding_id=item.embedding_id,
            authority=item,
        )
        for item in resolved
    )

    assert len(refs) == len(resolved) == 4
    assert all(item.source == M6UpgradePhysicalArtifactSource.M5_PRECEDENT for item in refs)
    assert all(item.kind == M6UpgradePhysicalArtifactKind.EMBEDDING for item in refs)
    assert tuple(item.artifact_id for item in refs) == tuple(item.embedding_id for item in resolved)
    for ref, authority in zip(refs, resolved, strict=True):
        document = canonical_json(authority.vector.model_dump(mode="json"))
        assert ref.document_sha256 == ref.content_sha256 == _sha_text(document)
        assert ref.size_bytes == len(document.encode("utf-8"))


def test_embedding_resolver_rejects_wrong_identity_and_forged_resolved_authority() -> None:
    exposure = _exposure()
    snapshot = _embedding_snapshot((exposure,))
    authority = assemble_m6_resolved_embeddings(
        closure=_embedding_closure((exposure,), snapshot),
        snapshot=snapshot,
    )[0]

    assert (
        _error_code(
            lambda: derive_m6_upgrade_embedding_physical_ref(
                expected_embedding_id="f" * 64,
                authority=authority,
            )
        )
        == M6UpgradePhysicalResolutionErrorCode.EMBEDDING_BINDING_MISMATCH
    )
    object.__setattr__(authority, "document_sha256", "e" * 64)
    assert (
        _error_code(
            lambda: derive_m6_upgrade_embedding_physical_ref(
                expected_embedding_id=authority.embedding_id,
                authority=authority,
            )
        )
        == M6UpgradePhysicalResolutionErrorCode.EMBEDDING_AUTHORITY_INVALID
    )

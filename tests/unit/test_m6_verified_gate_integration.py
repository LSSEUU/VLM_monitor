from __future__ import annotations

import hashlib
from pathlib import Path

from labcourt.application.m6_source_authority import M6ValidatedSourceAuthority
from labcourt.application.m6_verified_projection_context import (
    assemble_m6_sqlite_projection_authority,
)
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_source_authority import M6ReplayInputAuthority
from labcourt.ports.m6_historical_retrieval import M6HistoricalAuthorityDocument
from labcourt.ports.m6_procedural_gate_authority import (
    M6ProceduralGateHistorySnapshot,
)
from tests.unit.test_m6_perception_authority import _manifest
from tests.unit.test_m6_verified_projection_context import _bundle

ROOT = Path(__file__).parents[2]


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_verified_facade_accepts_exact_bound_source_and_full_gate_snapshot() -> None:
    base = _bundle()
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest, _ = _manifest()
    assert manifest.manifest_id == base.case.manifest_id
    assert manifest.config_sha256 == config.config_sha256
    closure = base.closure
    assert closure.source_case_id is not None
    assert closure.source_case_revision is not None
    assert closure.source_case_document_sha256 is not None
    m4_root = _sha("complete-m4-gate-root")
    input_authority = M6ReplayInputAuthority(
        sample_id=closure.sample_id,
        source_run_id=closure.source_run_id,
        source_case_id=closure.source_case_id,
        source_case_revision=closure.source_case_revision,
        source_case_document_sha256=closure.source_case_document_sha256,
        source_manifest_id=closure.source_manifest_id,
        source_manifest_document_sha256=closure.source_manifest_document_sha256,
        source_config_sha256=config.config_sha256,
        source_m4_authority_root_sha256=m4_root,
        source_m5_authority_root_sha256=_sha("m5-root"),
        source_validation_report_id=closure.source_validation_report_id,
        source_validation_report_document_sha256=(closure.source_validation_report_document_sha256),
        frame_inventory_root_sha256=closure.frame_inventory_root_sha256,
        detection_inventory_root_sha256=closure.detection_inventory_root_sha256,
        model_call_inventory_root_sha256=closure.model_call_inventory_root_sha256,
        embedding_inventory_root_sha256=closure.embedding_inventory_root_sha256,
        tool_result_inventory_root_sha256=closure.tool_result_inventory_root_sha256,
        historical_causal_cut_id=closure.historical_cut.causal_cut_id,
        gate_current_closures=(),
    )
    bound_closure = M6ReplayInputClosureAuthority.model_validate(
        {
            **closure.model_dump(mode="json", exclude_computed_fields=True),
            "input_authority_id": input_authority.input_authority_id,
            "input_authority_document_sha256": (input_authority.input_authority_document_sha256),
        }
    )
    report = M5ArtifactValidationReport(
        run_id=base.case.run_id,
        manifest_id=base.case.manifest_id,
        config_sha256=config.config_sha256,
        authority_root_sha256=input_authority.source_m5_authority_root_sha256,
    )
    source = M6ValidatedSourceAuthority(
        source_identity_sha256=base.perception.source_identity_sha256,
        input_authority=input_authority,
        source_validation_report=report,
        source_case=base.case,
        source_manifest=manifest,
    )
    documents = tuple(
        sorted(
            (
                M6HistoricalAuthorityDocument(
                    kind=M4ProjectionArtifactKind.EVIDENCE_PACK,
                    artifact_id=pack.pack_id,
                    canonical_document=canonical_json(pack.model_dump(mode="json")),
                )
                for pack in base.case.evidence_packs
            ),
            key=lambda item: item.sort_key,
        )
    )
    gate_history = M6ProceduralGateHistorySnapshot(
        source_identity_sha256=base.perception.source_identity_sha256,
        run_id=base.case.run_id,
        source_m4_authority_root_sha256=m4_root,
        documents=documents,
    )

    result = assemble_m6_sqlite_projection_authority(
        closure=bound_closure,
        perception_snapshot=base.perception,
        m3_snapshot=base.m3,
        m4_snapshot=base.m4,
        historical_snapshots=base.historical,
        acquisition_snapshot=base.acquisition,
        embedding_snapshot=base.embedding,
        source_authority=source,
        gate_history_snapshot=gate_history,
        config=config,
    )

    assert result.projection_context.procedural_gate_authority.inputs == ()
    assert result.closure == bound_closure

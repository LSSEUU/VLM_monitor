"""M8 evidence repository adapter for current M4 acquisition crop closure."""

from __future__ import annotations

from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.contracts.enums import ArtifactKind, ClosureDefectCode
from labcourt.contracts.evidence import EvidencePackDraft
from labcourt.contracts.storage import ArtifactRef, ClosureDefect, ClosureReport


class SQLiteM8HearingEvidenceRepository(SQLiteEvidenceRepository):
    """Extend current closure checks to M4 crops proven by acquisition lineage.

    The frozen EvidencePack contract intentionally keeps its original ``crops``
    tuple immutable. M4 successor packs carry acquired crop references through
    typed ToolResult output refs instead. The base M2 verifier cannot resolve
    those M4-only objects, so M8 adds this narrow adapter after the base semantic
    verifier and the M4 lineage reconstruction have both run.
    """

    def verify_current_pack(self, run_id: str, pack_id: str) -> ClosureReport:
        base = super().verify_current_pack(run_id, pack_id)
        missing_crops = tuple(
            defect.artifact_ref
            for defect in base.defects
            if defect.code == ClosureDefectCode.TOOL_OUTPUT_MISSING
            and defect.artifact_ref is not None
            and defect.artifact_ref.kind == ArtifactKind.CROP
        )
        if not missing_crops:
            return base

        connection = self._connection()
        try:
            connection.execute("BEGIN")
            pack = self._load_pack(connection, run_id, pack_id)
            payload = pack.model_dump(mode="json", exclude_computed_fields=True)
            payload.pop("closure_report")
            draft = EvidencePackDraft.model_validate(payload)
            hearing = self._hearing_repository()
            hearing._load_pack_closure_authority(connection, draft)
            acquired = tuple(
                hearing._load_acquired_crop(connection, run_id, ref.artifact_id)
                for ref in missing_crops
            )
        finally:
            connection.close()

        resolved = {ref.sort_key for ref in missing_crops}
        defects = [
            defect
            for defect in base.defects
            if not (
                defect.code == ClosureDefectCode.TOOL_OUTPUT_MISSING
                and defect.artifact_ref is not None
                and defect.artifact_ref.sort_key in resolved
            )
        ]
        if self._verifier is None:
            defects.extend(
                ClosureDefect(
                    code=ClosureDefectCode.MEDIA_MISSING,
                    artifact_ref=ArtifactRef(
                        kind=ArtifactKind.CROP,
                        artifact_id=crop.crop_id,
                    ),
                    reason_code="VERIFIER_UNAVAILABLE",
                )
                for crop in acquired
            )
        else:
            for crop in acquired:
                verification = self._verifier.verify_crop(crop)
                defect = self._verification_defect(crop, verification)
                if defect is not None:
                    defects.append(defect)

        return ClosureReport(
            run_id=base.run_id,
            root_ref=base.root_ref,
            manifest_id=base.manifest_id,
            input_sha256=base.input_sha256,
            checked_refs=base.checked_refs,
            defects=tuple(sorted(set(defects), key=lambda item: item.sort_key)),
        )


__all__ = ["SQLiteM8HearingEvidenceRepository"]

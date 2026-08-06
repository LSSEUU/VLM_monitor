"""Read-only orchestration for M4 authority and its selected projection."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Sequence
from typing import Protocol

from labcourt.application.m4_current_projection_validation import (
    M4CurrentProjectionValidation,
    M4CurrentProjectionValidator,
    M4ProjectionArtifactReader,
    M4ProjectionAuthorityDocument,
)
from labcourt.contracts.artifact_validation import (
    ArtifactValidationIssue,
    ArtifactValidationIssueCode,
    M3ArtifactInventoryKind,
    M3ArtifactValidationIssue,
    M3ArtifactValidationIssueCode,
    M3ArtifactValidationReport,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import VerificationStatus
from labcourt.contracts.evidence import Crop, EvidencePack
from labcourt.contracts.m4_artifact_validation import (
    M4ArtifactValidationArea,
    M4ArtifactValidationBudget,
    M4ArtifactValidationCounts,
    M4ArtifactValidationInventoryCount,
    M4ArtifactValidationIssue,
    M4ArtifactValidationIssueCode,
    M4ArtifactValidationReport,
)
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactVerification
from labcourt.exceptions import ContractViolation


class M4AuthorityFailureObservation(Protocol):
    @property
    def failure_type(self) -> str: ...

    @property
    def inventory_kind(self) -> M4ProjectionArtifactKind: ...

    @property
    def record_identity_sha256(self) -> str: ...

    @property
    def artifact_id(self) -> str | None: ...

    @property
    def reason_code(self) -> str: ...


class M4HearingRootObservation(Protocol):
    @property
    def root_sha256(self) -> str: ...

    @property
    def current_evidence_pack_id(self) -> str: ...

    @property
    def current_evidence_pack_version(self) -> int: ...


class M4MediaVerifier(Protocol):
    def verify_crop(self, crop: Crop) -> ArtifactVerification: ...


class M4AuthoritySnapshotObservation(Protocol):
    @property
    def run_id(self) -> str: ...

    @property
    def documents(self) -> Sequence[M4ProjectionAuthorityDocument]: ...

    @property
    def failures(self) -> Sequence[M4AuthorityFailureObservation]: ...

    @property
    def hearing_roots(self) -> Sequence[M4HearingRootObservation]: ...

    @property
    def authority_root_sha256(self) -> str: ...


class M4ArtifactAuthorityReader(Protocol):
    def scan(self, run_id: str) -> M4AuthoritySnapshotObservation: ...


_FAILURE_CODES = {
    "DOCUMENT_INVALID": M4ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_INVALID,
    "INDEX_MISMATCH": M4ArtifactValidationIssueCode.AUTHORITY_INDEX_MISMATCH,
    "REFERENCE_INVALID": M4ArtifactValidationIssueCode.AUTHORITY_REFERENCE_INVALID,
    "SCHEMA_UNSUPPORTED": M4ArtifactValidationIssueCode.AUTHORITY_SCHEMA_UNSUPPORTED,
}
_M4_ARTIFACT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,213}$")


class M4ArtifactValidator:
    """Validate M4 without mutating SQLite or rebuilding the JSON projection."""

    __slots__ = (
        "_artifact_reader",
        "_authority",
        "_authority_rows",
        "_budget",
        "_media_verifier",
        "_preflight_max_document_bytes",
    )

    def __init__(
        self,
        *,
        authority: M4ArtifactAuthorityReader,
        artifact_reader: M4ProjectionArtifactReader,
        authority_rows: int,
        preflight_max_document_bytes: int,
        media_verifier: M4MediaVerifier,
        budget: M4ArtifactValidationBudget | None = None,
    ) -> None:
        if (
            not isinstance(authority_rows, int)
            or isinstance(authority_rows, bool)
            or authority_rows < 0
            or not isinstance(preflight_max_document_bytes, int)
            or isinstance(preflight_max_document_bytes, bool)
            or preflight_max_document_bytes < 0
        ):
            raise TypeError("M4 artifact preflight counts must be non-negative integers")
        self._authority = authority
        self._artifact_reader = artifact_reader
        self._authority_rows = authority_rows
        self._preflight_max_document_bytes = preflight_max_document_bytes
        self._media_verifier = media_verifier
        self._budget = budget or M4ArtifactValidationBudget()

    def validate(
        self,
        run_id: str,
        m3_report: M3ArtifactValidationReport,
    ) -> M4ArtifactValidationReport:
        controlled_run_id = require_reference_token(run_id, "M4 artifact validator run_id")
        if not isinstance(m3_report, M3ArtifactValidationReport):
            raise TypeError("M4 artifact validation requires an M3 validation report")
        if m3_report.run_id != controlled_run_id:
            raise ContractViolation("M4 and M3 artifact validation run IDs differ")

        embedded_total = len(m3_report.m2_report.issues) + len(m3_report.issues)
        preflight_issues = self._preflight_budget_issues()
        if preflight_issues:
            embedded_issues = _embedded_m3_defects(
                m3_report,
                m4_raw_response_ids=set(),
                m4_verdict_ids=set(),
                successor_ready=False,
            )[1]
            return self._report(
                controlled_run_id,
                m3_report,
                authority_root_sha256=None,
                authority_counts=Counter(),
                authority_failures=0,
                hearing_roots=0,
                max_document_bytes=self._preflight_max_document_bytes,
                embedded_total=embedded_total,
                embedded_superseded=0,
                validated_media=0,
                media_failures=0,
                projection=None,
                issues=[*preflight_issues, *embedded_issues],
            )

        try:
            snapshot = self._authority.scan(controlled_run_id)
        except (ContractViolation, TypeError, ValueError) as error:
            reason = getattr(error, "reason_code", "AUTHORITY_READER_REJECTED")
            try:
                reason = require_reference_token(reason, "M4 authority schema reason")
            except (TypeError, ValueError):
                reason = "AUTHORITY_READER_REJECTED"
            issue = M4ArtifactValidationIssue(
                code=M4ArtifactValidationIssueCode.AUTHORITY_SCHEMA_INVALID,
                area=M4ArtifactValidationArea.AUTHORITY,
                reason_code=reason,
            )
            embedded_issues = _embedded_m3_defects(
                m3_report,
                m4_raw_response_ids=set(),
                m4_verdict_ids=set(),
                successor_ready=False,
            )[1]
            return self._report(
                controlled_run_id,
                m3_report,
                authority_root_sha256=None,
                authority_counts=Counter(),
                authority_failures=1,
                hearing_roots=0,
                max_document_bytes=self._preflight_max_document_bytes,
                embedded_total=embedded_total,
                embedded_superseded=0,
                validated_media=0,
                media_failures=0,
                projection=None,
                issues=[issue, *embedded_issues],
            )
        if snapshot.run_id != controlled_run_id:
            raise ContractViolation("M4 authority reader returned another run")

        authority_issues = self._authority_issues(snapshot.failures)
        authority_counts: Counter[M4ProjectionArtifactKind] = Counter()
        max_document_bytes = self._preflight_max_document_bytes
        seen: set[tuple[M4ProjectionArtifactKind, str]] = set()
        for document in snapshot.documents:
            if not isinstance(document.kind, M4ProjectionArtifactKind):
                raise ContractViolation("M4 authority reader returned an unknown document kind")
            identity = (document.kind, document.artifact_id)
            if identity in seen:
                raise ContractViolation("M4 authority reader returned duplicate documents")
            seen.add(identity)
            authority_counts[document.kind] += 1
            try:
                max_document_bytes = max(
                    max_document_bytes,
                    len(document.canonical_document.encode("utf-8")),
                )
            except (AttributeError, UnicodeEncodeError):
                raise ContractViolation(
                    "M4 authority reader returned invalid document bytes"
                ) from None

        validated_media, media_issues = self._validate_media(snapshot.documents)
        authority_issues.extend(media_issues)
        m4_raw_response_ids = _m4_raw_response_ids(snapshot.documents, controlled_run_id)
        m4_verdict_ids = {
            document.artifact_id
            for document in snapshot.documents
            if document.kind == M4ProjectionArtifactKind.VERDICT
        }
        embedded_superseded, embedded_issues = _embedded_m3_defects(
            m3_report,
            m4_raw_response_ids=m4_raw_response_ids,
            m4_verdict_ids=m4_verdict_ids,
            successor_ready=not snapshot.failures and not media_issues,
        )
        authority_issues.extend(embedded_issues)

        if len(snapshot.documents) > self._budget.max_authority_documents:
            authority_issues.append(
                _budget_issue(
                    M4ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_COUNT_BUDGET_EXCEEDED,
                    self._budget.max_authority_documents,
                    len(snapshot.documents),
                )
            )
        if max_document_bytes > self._budget.max_authority_document_bytes:
            authority_issues.append(
                _budget_issue(
                    M4ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_BYTES_BUDGET_EXCEEDED,
                    self._budget.max_authority_document_bytes,
                    max_document_bytes,
                )
            )

        projection: M4CurrentProjectionValidation | None = None
        if not authority_issues:
            projection = M4CurrentProjectionValidator(
                artifact_reader=self._artifact_reader,
                budget=self._budget,
            ).validate(controlled_run_id, snapshot)
        all_issues = [*authority_issues, *(projection.issues if projection is not None else ())]
        return self._report(
            controlled_run_id,
            m3_report,
            authority_root_sha256=(
                snapshot.authority_root_sha256 if not authority_issues else None
            ),
            authority_counts=authority_counts,
            authority_failures=len(snapshot.failures),
            hearing_roots=len(snapshot.hearing_roots),
            max_document_bytes=max_document_bytes,
            embedded_total=embedded_total,
            embedded_superseded=embedded_superseded,
            validated_media=validated_media,
            media_failures=len(media_issues),
            projection=projection,
            issues=all_issues,
        )

    def _validate_media(
        self,
        documents: Sequence[M4ProjectionAuthorityDocument],
    ) -> tuple[int, list[M4ArtifactValidationIssue]]:
        crops: dict[str, Crop] = {}
        for document in documents:
            try:
                if document.kind == M4ProjectionArtifactKind.EVIDENCE_PACK:
                    pack = EvidencePack.model_validate_json(document.canonical_document)
                    candidates = pack.crops
                elif document.kind == M4ProjectionArtifactKind.ACQUIRED_CROP:
                    candidates = (Crop.model_validate_json(document.canonical_document),)
                else:
                    continue
            except (TypeError, ValueError):
                raise ContractViolation(
                    "M4 validated authority returned an invalid media document"
                ) from None
            for crop in candidates:
                previous = crops.get(crop.crop_id)
                if previous is not None and previous != crop:
                    raise ContractViolation("M4 authority returned conflicting crop documents")
                crops[crop.crop_id] = crop

        issues: list[M4ArtifactValidationIssue] = []
        for crop_id in sorted(crops):
            crop = crops[crop_id]
            try:
                verification = self._media_verifier.verify_crop(crop)
            except (ContractViolation, TypeError, ValueError):
                verification = None
            if (
                not isinstance(verification, ArtifactVerification)
                or verification.status != VerificationStatus.CURRENT_MEDIA_VERIFIED
            ):
                reason = (
                    verification.reason_code or verification.status.value
                    if isinstance(verification, ArtifactVerification)
                    else "MEDIA_VERIFIER_REJECTED"
                )
                try:
                    reason = require_reference_token(reason, "M4 media failure reason")
                except (TypeError, ValueError):
                    reason = "MEDIA_VERIFICATION_FAILED"
                issues.append(
                    M4ArtifactValidationIssue(
                        code=M4ArtifactValidationIssueCode.AUTHORITY_MEDIA_INVALID,
                        area=M4ArtifactValidationArea.AUTHORITY,
                        inventory_kind=M4ProjectionArtifactKind.EVIDENCE_PACK,
                        record_identity_sha256=_identity_sha256(
                            "m4-media-verification",
                            crop_id,
                        ),
                        artifact_id=crop_id,
                        reason_code=reason,
                    )
                )
        return len(crops), issues

    def _preflight_budget_issues(self) -> list[M4ArtifactValidationIssue]:
        checks = (
            (
                M4ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_COUNT_BUDGET_EXCEEDED,
                self._budget.max_authority_documents,
                self._authority_rows,
            ),
            (
                M4ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_BYTES_BUDGET_EXCEEDED,
                self._budget.max_authority_document_bytes,
                self._preflight_max_document_bytes,
            ),
        )
        return [
            _budget_issue(code, limit, observed)
            for code, limit, observed in checks
            if observed > limit
        ]

    @staticmethod
    def _authority_issues(
        failures: Sequence[M4AuthorityFailureObservation],
    ) -> list[M4ArtifactValidationIssue]:
        issues: list[M4ArtifactValidationIssue] = []
        seen: set[tuple[str, str, str, str, str]] = set()
        for failure in failures:
            if not isinstance(failure.inventory_kind, M4ProjectionArtifactKind):
                raise ContractViolation("M4 authority reader returned an unknown failure kind")
            failure_type = getattr(failure.failure_type, "value", failure.failure_type)
            code = _FAILURE_CODES.get(str(failure_type))
            if code is None:
                raise ContractViolation("M4 authority reader returned an unknown failure type")
            artifact_id = failure.artifact_id
            if artifact_id is not None and (
                not isinstance(artifact_id, str) or _M4_ARTIFACT_ID.fullmatch(artifact_id) is None
            ):
                artifact_id = None
            try:
                issue = M4ArtifactValidationIssue(
                    code=code,
                    area=M4ArtifactValidationArea.AUTHORITY,
                    inventory_kind=failure.inventory_kind,
                    record_identity_sha256=failure.record_identity_sha256,
                    artifact_id=artifact_id,
                    reason_code=failure.reason_code,
                )
            except (TypeError, ValueError):
                raise ContractViolation(
                    "M4 authority reader returned invalid failure context"
                ) from None
            key = (
                str(failure_type),
                failure.inventory_kind.value,
                failure.record_identity_sha256,
                artifact_id or "",
                failure.reason_code,
            )
            if key in seen:
                raise ContractViolation("M4 authority reader returned duplicate failures")
            seen.add(key)
            issues.append(issue)
        return issues

    def _report(
        self,
        run_id: str,
        m3_report: M3ArtifactValidationReport,
        *,
        authority_root_sha256: str | None,
        authority_counts: Counter[M4ProjectionArtifactKind],
        authority_failures: int,
        hearing_roots: int,
        max_document_bytes: int,
        embedded_total: int,
        embedded_superseded: int,
        validated_media: int,
        media_failures: int,
        projection: M4CurrentProjectionValidation | None,
        issues: list[M4ArtifactValidationIssue],
    ) -> M4ArtifactValidationReport:
        projected = dict(projection.projected_by_kind) if projection is not None else {}
        inventories = tuple(
            M4ArtifactValidationInventoryCount(
                inventory_kind=kind,
                authoritative_count=authority_counts[kind],
                projected_count=projected.get(kind, 0),
            )
            for kind in sorted(M4ProjectionArtifactKind, key=lambda item: item.value)
        )
        unique = {issue.sort_key: issue for issue in issues}
        ordered = tuple(unique[key] for key in sorted(unique))
        embedded_gating = embedded_total - embedded_superseded
        counts = M4ArtifactValidationCounts(
            embedded_m3_issues=embedded_total,
            embedded_m3_superseded_issues=embedded_superseded,
            embedded_m3_gating_issues=embedded_gating,
            authority_rows=self._authority_rows,
            validated_authority_documents=sum(authority_counts.values()),
            authority_failures=authority_failures,
            hearing_roots=hearing_roots,
            max_authority_document_bytes=max_document_bytes,
            validated_media=validated_media,
            media_failures=media_failures,
            projection_files=projection.projection_files if projection is not None else 0,
            projection_documents=(projection.projection_documents if projection is not None else 0),
            projection_bytes=projection.projection_bytes if projection is not None else 0,
            max_projection_file_bytes=(
                projection.max_projection_file_bytes if projection is not None else 0
            ),
            inventories=inventories,
        )
        return M4ArtifactValidationReport(
            run_id=run_id,
            m3_report=m3_report,
            authority_root_sha256=authority_root_sha256,
            budget=self._budget,
            counts=counts,
            issues=ordered,
        )


def _embedded_m3_defects(
    report: M3ArtifactValidationReport,
    *,
    m4_raw_response_ids: set[str],
    m4_verdict_ids: set[str],
    successor_ready: bool,
) -> tuple[int, list[M4ArtifactValidationIssue]]:
    superseded = 0
    defects: list[M4ArtifactValidationIssue] = []
    embedded: tuple[tuple[str, ArtifactValidationIssue | M3ArtifactValidationIssue], ...] = (
        *(("M2", issue) for issue in report.m2_report.issues),
        *(("M3", issue) for issue in report.issues),
    )
    for layer, issue in embedded:
        if successor_ready and _is_m4_successor_finding(
            issue,
            m4_raw_response_ids=m4_raw_response_ids,
            m4_verdict_ids=m4_verdict_ids,
        ):
            superseded += 1
            continue
        source = canonical_json(
            ["m4-embedded-artifact-defect", 1, layer, issue.model_dump(mode="json")]
        ).encode("utf-8")
        defects.append(
            M4ArtifactValidationIssue(
                code=M4ArtifactValidationIssueCode.EMBEDDED_M3_DEFECT,
                area=M4ArtifactValidationArea.EMBEDDED_M3,
                source_token=hashlib.sha256(source).hexdigest(),
                reason_code=issue.code.value,
            )
        )
    return superseded, defects


def _is_m4_successor_finding(
    issue: ArtifactValidationIssue | M3ArtifactValidationIssue,
    *,
    m4_raw_response_ids: set[str],
    m4_verdict_ids: set[str],
) -> bool:
    if isinstance(issue, ArtifactValidationIssue):
        return (
            issue.code == ArtifactValidationIssueCode.PROJECTION_UNSAFE
            and issue.reason_code == "CURRENT_POINTER_AUTHORITY_MISMATCH"
        )
    if issue.code == M3ArtifactValidationIssueCode.RAW_RESPONSE_UNREFERENCED:
        return issue.artifact_id in m4_raw_response_ids
    return (
        issue.code == M3ArtifactValidationIssueCode.AUTHORITY_REFERENCE_INVALID
        and issue.inventory_kind == M3ArtifactInventoryKind.VERDICT
        and issue.reason_code == "VERDICT_AUTHORITY_BINDING_MISMATCH"
        and issue.artifact_id in m4_verdict_ids
    )


def _m4_raw_response_ids(
    documents: Sequence[M4ProjectionAuthorityDocument],
    run_id: str,
) -> set[str]:
    prefix = f"{run_id}/model_responses/"
    result: set[str] = set()

    def visit(value: object) -> None:
        if isinstance(value, dict):
            raw_ref = value.get("raw_response_ref")
            if (
                isinstance(raw_ref, str)
                and raw_ref.startswith(prefix)
                and raw_ref.endswith(".json")
            ):
                response_id = raw_ref[len(prefix) : -len(".json")]
                if re.fullmatch(r"[0-9a-f]{64}", response_id) is not None:
                    result.add(response_id)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    for document in documents:
        try:
            visit(json.loads(document.canonical_document))
        except (json.JSONDecodeError, TypeError):
            raise ContractViolation("M4 authority returned invalid canonical JSON") from None
    return result


def _identity_sha256(domain: str, identity: str) -> str:
    return hashlib.sha256(canonical_json([domain, 1, identity]).encode("utf-8")).hexdigest()


def _budget_issue(
    code: M4ArtifactValidationIssueCode,
    limit: int,
    observed: int,
) -> M4ArtifactValidationIssue:
    return M4ArtifactValidationIssue(
        code=code,
        area=M4ArtifactValidationArea.BUDGET,
        limit=limit,
        observed=observed,
    )


__all__ = [
    "M4ArtifactAuthorityReader",
    "M4ArtifactValidator",
    "M4AuthoritySnapshotObservation",
    "M4MediaVerifier",
]

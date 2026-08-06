"""Build one standalone privacy-safe HTML view of a CLOSED M6 publication."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from html import escape as escape_html
from string import Template
from typing import NoReturn

from pydantic import ValidationError

from labcourt.application._m6_static_report_template import M6_STATIC_REPORT_TEMPLATE
from labcourt.application.m6_replay_locked_closed_policy_publication import (
    M6ReplayLockedClosedPolicyPublicationBuildError,
    M6ReplayLockedClosedPolicyPublicationBundle,
    build_m6_replay_locked_closed_policy_publication_bundle,
)
from labcourt.contracts.m6_static_report import (
    M6PrivacySafeStaticReportManifestAuthorityV1,
    M6StaticReportEvidenceDisposition,
    M6StaticReportEvidenceItem,
)
from labcourt.exceptions import LabCourtError


class M6StaticReportBuildErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    PUBLICATION_BUNDLE_INVALID = "PUBLICATION_BUNDLE_INVALID"
    EVIDENCE_INVENTORY_INVALID = "EVIDENCE_INVENTORY_INVALID"
    MANIFEST_INVARIANT_VIOLATION = "MANIFEST_INVARIANT_VIOLATION"
    RENDER_FAILED = "RENDER_FAILED"


class M6StaticReportBuildError(LabCourtError):
    def __init__(self, code: M6StaticReportBuildErrorCode) -> None:
        if not isinstance(code, M6StaticReportBuildErrorCode):
            raise TypeError("code must be an M6StaticReportBuildErrorCode")
        self.code = code
        super().__init__(f"M6 static report build failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6PrivacySafeStaticReportBundle:
    manifest: M6PrivacySafeStaticReportManifestAuthorityV1
    html_document: str
    html_content_sha256: str


def _fail(code: M6StaticReportBuildErrorCode) -> NoReturn:
    raise M6StaticReportBuildError(code)


def _controlled_publication(
    value: object,
) -> M6ReplayLockedClosedPolicyPublicationBundle:
    if type(value) is not M6ReplayLockedClosedPolicyPublicationBundle:
        _fail(M6StaticReportBuildErrorCode.INVALID_ARGUMENT)
    assert isinstance(value, M6ReplayLockedClosedPolicyPublicationBundle)
    try:
        rebuilt = build_m6_replay_locked_closed_policy_publication_bundle(value.report_bundle)
    except (M6ReplayLockedClosedPolicyPublicationBuildError, AttributeError, TypeError, ValueError):
        _fail(M6StaticReportBuildErrorCode.PUBLICATION_BUNDLE_INVALID)
    if rebuilt != value:
        _fail(M6StaticReportBuildErrorCode.PUBLICATION_BUNDLE_INVALID)
    return rebuilt


def _controlled_evidence(
    value: object,
    sample_ids: tuple[str, ...],
) -> tuple[M6StaticReportEvidenceItem, ...]:
    if not isinstance(value, tuple):
        _fail(M6StaticReportBuildErrorCode.EVIDENCE_INVENTORY_INVALID)
    try:
        controlled = tuple(
            M6StaticReportEvidenceItem.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in value
            if type(item) is M6StaticReportEvidenceItem
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6StaticReportBuildErrorCode.EVIDENCE_INVENTORY_INVALID)
    if len(controlled) != len(value):
        _fail(M6StaticReportBuildErrorCode.EVIDENCE_INVENTORY_INVALID)
    ordered = tuple(sorted(controlled, key=lambda item: item.sample_id))
    if tuple(item.sample_id for item in ordered) != tuple(sorted(sample_ids)):
        _fail(M6StaticReportBuildErrorCode.EVIDENCE_INVENTORY_INVALID)
    if len({item.sample_id for item in ordered}) != len(ordered):
        _fail(M6StaticReportBuildErrorCode.EVIDENCE_INVENTORY_INVALID)
    return ordered


def _value(value: object | None) -> str:
    if value is None:
        return "NOT_AVAILABLE"
    candidate = getattr(value, "value", value)
    return str(candidate)


def _render(
    publication: M6ReplayLockedClosedPolicyPublicationBundle,
    manifest: M6PrivacySafeStaticReportManifestAuthorityV1,
) -> str:
    report = publication.report_bundle.report
    entries = {entry.sample_id: entry for entry in report.dataset.entries}
    results = {result.sample_id: result for result in report.results}
    case_rows: list[str] = []
    for evidence in manifest.evidence_items:
        result = results[evidence.sample_id]
        dataset_entry = entries[evidence.sample_id]
        sample_id = escape_html(evidence.sample_id)
        memberships = escape_html(" / ".join(_value(item) for item in dataset_entry.memberships))
        baseline_decision = escape_html(
            _value(
                result.baseline_snapshot.final_decision
                if result.baseline_snapshot is not None
                else None
            )
        )
        candidate_decision = escape_html(
            _value(
                result.candidate_snapshot.final_decision
                if result.candidate_snapshot is not None
                else None
            )
        )
        if evidence.disposition == M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE:
            if evidence.artifact_relative_path is None:
                raise ValueError("available evidence must have an artifact path")
            evidence_detail = (
                f'<img class="evidence-thumb" '
                f'src="{escape_html(evidence.artifact_relative_path, quote=True)}" '
                f'alt="Privacy-processed evidence for sample {sample_id}">'
            )
        elif evidence.disposition == M6StaticReportEvidenceDisposition.RETENTION_PURGED:
            deletion_audit_id = escape_html(_value(evidence.deletion_audit_id))
            retention_reason_code = escape_html(_value(evidence.retention_reason_code))
            evidence_detail = (
                '<div class="placeholder">Retention removed this evidence. '
                f'Deletion audit: <span class="mono">{deletion_audit_id}'
                "</span>. Reason: "
                f'<span class="mono">{retention_reason_code}'
                "</span>.</div>"
            )
        else:
            evidence_detail = (
                '<div class="placeholder">No media was published for this sample.</div>'
            )
        case_rows.append(
            f"""            <tr>
              <th scope="row">{sample_id}</th>
              <td>{memberships}</td>
              <td>{baseline_decision}</td>
              <td>{candidate_decision}</td>
              <td>{escape_html(_value(result.first_divergence_stage))}</td>
              <td>{escape_html(_value(result.disposition))}</td>
              <td>
                <span class="evidence-state">{escape_html(evidence.disposition.value)}</span>
                {evidence_detail}
              </td>
            </tr>"""
        )
    artifacts = [
        (entry.kind.value.replace("_", " ").title(), entry.relative_path)
        for entry in publication.seal.entries
    ]
    artifacts.append(("Publication Seal", publication.seal.seal_relative_path))
    metrics = (
        ("Total cases", len(report.results)),
        ("Stability cases", report.stability_case_count),
        ("Machine flips", report.machine_flip_count),
        ("Gold cases", report.gold_case_count),
        ("Challenge cases", report.challenge_case_count),
        ("Gate reasons", len(report.gate_reason_codes)),
        ("Emergency degradations", len(report.emergency_degradation_sample_ids)),
        ("Evidence items", manifest.evidence_item_count),
    )
    identities = (
        ("Report ID", report.report_id),
        ("Publication seal ID", publication.seal.seal_id),
        ("Candidate run", publication.seal.candidate_run_id),
        ("Candidate manifest", publication.seal.candidate_manifest_id),
        ("Source catalog", publication.seal.source_catalog_authority_id),
        ("Static manifest", manifest.manifest_id),
    )
    metric_items = "\n".join(
        f'        <div class="metric"><dt>{escape_html(label)}</dt>'
        f"<dd>{escape_html(str(value))}</dd></div>"
        for label, value in metrics
    )
    identity_items = "\n".join(
        f"        <dt>{escape_html(label)}</dt><dd>{escape_html(value)}</dd>"
        for label, value in identities
    )
    artifact_items = "\n".join(
        f'          <li><a href="{escape_html(href, quote=True)}">{escape_html(label)}</a></li>'
        for label, href in artifacts
    )
    return Template(M6_STATIC_REPORT_TEMPLATE).substitute(
        classification=escape_html(manifest.classification),
        release_status_class="status--pass" if report.release_allowed else "status--hold",
        release_allowed="YES" if report.release_allowed else "NO",
        report_disposition=escape_html(_value(report.disposition)),
        mode=escape_html(_value(report.command.mode)),
        metric_items=metric_items,
        identity_items=identity_items,
        artifact_items=artifact_items,
        case_rows="\n".join(case_rows),
    )


def build_m6_privacy_safe_static_report(
    publication_bundle: object,
    evidence_items: object,
) -> M6PrivacySafeStaticReportBundle:
    publication = _controlled_publication(publication_bundle)
    sample_ids = tuple(result.sample_id for result in publication.report_bundle.report.results)
    evidence = _controlled_evidence(evidence_items, sample_ids)
    try:
        manifest = M6PrivacySafeStaticReportManifestAuthorityV1(
            report_id=publication.report_bundle.report.report_id,
            publication_seal_id=publication.seal.seal_id,
            candidate_run_id=publication.seal.candidate_run_id,
            evidence_items=evidence,
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise M6StaticReportBuildError(
            M6StaticReportBuildErrorCode.MANIFEST_INVARIANT_VIOLATION
        ) from exc
    try:
        document = _render(publication, manifest)
        payload = document.encode("utf-8", errors="strict")
    except (KeyError, TypeError, UnicodeError, ValueError) as exc:
        raise M6StaticReportBuildError(M6StaticReportBuildErrorCode.RENDER_FAILED) from exc
    return M6PrivacySafeStaticReportBundle(
        manifest=manifest,
        html_document=document,
        html_content_sha256=hashlib.sha256(payload).hexdigest(),
    )


__all__ = [
    "M6PrivacySafeStaticReportBundle",
    "M6StaticReportBuildError",
    "M6StaticReportBuildErrorCode",
    "build_m6_privacy_safe_static_report",
]

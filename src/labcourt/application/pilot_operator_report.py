"""Deterministic privacy-safe projection and HTML rendering for A4 operators."""

# ruff: noqa: E501, RUF001

from __future__ import annotations

import hashlib
from html import escape
from pathlib import Path, PurePosixPath

from labcourt.contracts.enums import (
    AppealStatus,
    CaseStatus,
    MediaAvailability,
    VerdictDecision,
)
from labcourt.contracts.evidence import Crop
from labcourt.contracts.manifests import ModelManifest, RunManifest
from labcourt.contracts.pilot_report import (
    PILOT_OPERATOR_DISCLAIMER,
    PilotA4CaseView,
    PilotA4MediaView,
    PilotA4Metrics,
    PilotA4ModelVersion,
)
from labcourt.exceptions import ContractViolation, ManifestMismatch, PathBoundaryViolation
from labcourt.ports.evidence_repository import CaseSnapshot

_TERMINAL_STATUSES = frozenset({CaseStatus.CLOSED, CaseStatus.APPEALED, CaseStatus.APPEAL_RESOLVED})


def build_pilot_case_views(
    *,
    snapshots: tuple[CaseSnapshot, ...],
    manifest: RunManifest,
    runs_root: Path,
    run_id: str,
) -> tuple[PilotA4CaseView, ...]:
    """Project exact Case authorities into a bounded, prose-free operator view."""

    detector = _model_version(manifest, "detector")
    screening_model = _model_version(manifest, "screening")
    ordered = tuple(sorted(snapshots, key=lambda item: item.case.case_id))
    if len(ordered) != len({item.case.case_id for item in ordered}):
        raise ContractViolation("pilot report source contains duplicate cases")
    return tuple(
        _case_view(
            snapshot=snapshot,
            manifest=manifest,
            runs_root=runs_root,
            run_id=run_id,
            detector=detector,
            screening_model=screening_model,
        )
        for snapshot in ordered
    )


def build_pilot_metrics(
    *,
    views: tuple[PilotA4CaseView, ...],
    manifest: RunManifest,
    run_id: str,
    verified_local_alert_count: int,
) -> PilotA4Metrics:
    """Build count fields from current authoritative case projections."""

    decisions = tuple(item.final_decision for item in views)
    return PilotA4Metrics(
        run_id=run_id,
        manifest_id=manifest.manifest_id,
        config_sha256=manifest.config_sha256,
        case_count=len(views),
        closed_count=sum(item.status in _TERMINAL_STATUSES for item in views),
        human_review_count=sum(item.human_review_required for item in views),
        established_count=decisions.count(VerdictDecision.ESTABLISHED),
        not_established_count=decisions.count(VerdictDecision.NOT_ESTABLISHED),
        insufficient_evidence_count=decisions.count(VerdictDecision.INSUFFICIENT_EVIDENCE),
        unresolved_count=decisions.count(None),
        verified_local_alert_count=verified_local_alert_count,
        cases=views,
    )


def render_pilot_index(metrics: PilotA4Metrics) -> str:
    """Render the report landing page as standalone offline HTML."""

    cards = "".join(
        (
            _metric_card("案件总数", metrics.case_count, "本次 run 的完整案件清单"),
            _metric_card("已结案", metrics.closed_count, "已通过确定性告警策略"),
            _metric_card("需人工关注", metrics.human_review_count, "人工复核或申诉链存在"),
            _metric_card(
                "本地告警",
                metrics.verified_local_alert_count,
                "仅写入本机 JSON，未对外发送",
            ),
        )
    )
    rows = "".join(_index_case_row(case) for case in metrics.cases)
    empty = (
        '<div class="empty"><strong>没有案件</strong><p>当前 run 没有可发布的案件记录。</p></div>'
        if not metrics.cases
        else ""
    )
    body = f"""
      <section class="hero" aria-labelledby="page-title">
        <p class="eyebrow">LABCOURT · A4 OPERATOR REPORT</p>
        <h1 id="page-title">实验室安全辅助报告</h1>
        <p class="lede">将确定性检测、模型筛查与程序复核结果汇总为可追溯的本地运营视图。</p>
        <div class="identity"><span>Run</span><code>{escape(metrics.run_id)}</code></div>
      </section>
      <aside class="notice" role="note"><strong>使用边界</strong><span>{escape(PILOT_OPERATOR_DISCLAIMER)}</span></aside>
      <section aria-labelledby="summary-heading">
        <h2 id="summary-heading">结果概览</h2>
        <div class="metric-grid">{cards}</div>
      </section>
      <section aria-labelledby="cases-heading">
        <div class="section-head"><div><p class="kicker">CASE INVENTORY</p><h2 id="cases-heading">案件清单</h2></div><a class="data-link" href="../metrics.json">查看机器可读指标</a></div>
        {empty}
        <div class="case-list">{rows}</div>
      </section>
      <section class="trace" aria-labelledby="trace-heading">
        <h2 id="trace-heading">追溯标识</h2>
        <dl>
          <div><dt>Manifest</dt><dd><code>{escape(metrics.manifest_id)}</code></dd></div>
          <div><dt>Config</dt><dd><code>{escape(metrics.config_sha256)}</code></dd></div>
          <div><dt>Metrics</dt><dd><code>{escape(metrics.metrics_id)}</code></dd></div>
        </dl>
      </section>
    """
    return _page(title=f"LabCourt A4 · {metrics.run_id}", body=body, home_href="index.html")


def render_pilot_case(case: PilotA4CaseView) -> str:
    """Render one case without exposing raw model narrative or identity fields."""

    crops = "".join(_crop_card(item) for item in case.key_crops)
    if not crops:
        crops = '<div class="empty"><strong>无关键截图</strong><p>案件契约没有可展示的截图记录。</p></div>'
    screening = (
        f"{escape(case.screening_decision.value)} · {case.screening_probability:.1%}"
        if case.screening_decision is not None and case.screening_probability is not None
        else "未生成"
    )
    procedure = (
        "通过"
        if case.procedural_review_passed
        else "未通过"
        if case.procedural_review_passed is not None
        else "未执行"
    )
    alert = case.alert_level.value if case.alert_level is not None else "无"
    alert_state = "已撤销" if case.alert_rescinded else "当前有效" if case.alert_level else "无"
    appeal = case.appeal_status.value if case.appeal_status is not None else "无"
    observed = str(case.observed_frame_count) if case.observed_frame_count is not None else "未记录"
    association_interval = (
        f"轨迹区间 {case.association_start_frame}-{case.association_end_frame_exclusive - 1}"
        if case.association_start_frame is not None
        and case.association_end_frame_exclusive is not None
        else "轨迹区间未记录"
    )
    final = case.final_decision.value if case.final_decision is not None else "待处理"
    verdict = case.verdict_decision.value if case.verdict_decision is not None else "未生成"
    confidence = f"{case.verdict_confidence:.1%}" if case.verdict_confidence is not None else "—"
    body = f"""
      <nav class="breadcrumb" aria-label="面包屑"><a href="../index.html">报告首页</a><span aria-hidden="true">/</span><span>案件详情</span></nav>
      <section class="hero compact" aria-labelledby="page-title">
        <p class="eyebrow">CASE · {escape(case.case_id)}</p>
        <div class="title-row"><h1 id="page-title">{escape(case.violation_type.value)}</h1>{_status_badge(case.status.value)}</div>
        <p class="lede">帧区间 {case.start_frame}–{case.end_frame_exclusive - 1} · 匿名轨迹 <code>{escape(case.anonymous_track_ref or "无")}</code></p>
      </section>
      <aside class="notice" role="note"><strong>使用边界</strong><span>{escape(case.disclaimer)}</span></aside>
      <section aria-labelledby="decision-heading">
        <p class="kicker">DECISION CHAIN</p><h2 id="decision-heading">判定链</h2>
        <div class="decision-grid">
          {_fact("检测与关联", f"观测 {observed} 帧", association_interval)}
          {_fact("模型筛查", screening, case.screening_router_version or "未生成")}
          {_fact("快速裁决", verdict, f"置信度 {confidence}")}
          {_fact("程序复核", procedure, case.procedural_gate_version or "未执行")}
          {_fact("最终结果", final, f"告警级别 {alert} · {alert_state}")}
          {_fact("人工流程", "需要" if case.human_review_required else "不需要", f"申诉状态 {appeal}")}
        </div>
      </section>
      <section aria-labelledby="evidence-heading">
        <p class="kicker">VERIFIED MEDIA</p><h2 id="evidence-heading">关键证据截图</h2>
        <p class="section-copy">只有文件内容与案件中记录的 SHA-256 完全一致时才显示图片。</p>
        <div class="media-grid">{crops}</div>
      </section>
      <section aria-labelledby="version-heading">
        <p class="kicker">REPRODUCIBILITY</p><h2 id="version-heading">版本与追溯</h2>
        <div class="version-grid">
          {_model_card("确定性检测器", case.detector)}
          {_model_card("视觉语言模型", case.screening_model)}
        </div>
        <dl class="trace-list">
          <div><dt>规则版本</dt><dd><code>{escape(case.rule_version)}</code></dd></div>
          <div><dt>Prompt bundle</dt><dd><code>{escape(case.prompt_bundle_sha256)}</code></dd></div>
          <div><dt>Run manifest</dt><dd><code>{escape(case.manifest_id)}</code></dd></div>
          <div><dt>Case view</dt><dd><code>{escape(case.case_view_id)}</code></dd></div>
        </dl>
      </section>
    """
    return _page(title=f"案件 {case.case_id} · LabCourt", body=body, home_href="../index.html")


def _case_view(
    *,
    snapshot: CaseSnapshot,
    manifest: RunManifest,
    runs_root: Path,
    run_id: str,
    detector: PilotA4ModelVersion,
    screening_model: PilotA4ModelVersion,
) -> PilotA4CaseView:
    case = snapshot.case
    if case.run_id != run_id or case.manifest_id != manifest.manifest_id:
        raise ManifestMismatch("pilot report Case differs from the selected run manifest")
    pack = case.evidence_packs[-1] if case.evidence_packs else None
    screening = case.screening_results[-1] if case.screening_results else None
    verdict = case.verdicts[-1] if case.verdicts else None
    review = case.procedural_reviews[-1] if case.procedural_reviews else None
    latest_alert = case.alerts[-1] if case.alerts else None
    current_appeal = case.appeals[-1] if case.appeals else None
    crops = _key_crop_views(pack, runs_root=runs_root, run_id=run_id) if pack else ()
    return PilotA4CaseView(
        run_id=run_id,
        case_id=case.case_id,
        revision=snapshot.revision,
        status=case.status,
        violation_type=case.event.violation_type,
        start_frame=case.event.start_frame,
        end_frame_exclusive=case.event.end_frame_exclusive,
        anonymous_track_ref=case.event.primary_track_ref,
        association_start_frame=(pack.track_summary.start_frame if pack else None),
        association_end_frame_exclusive=(pack.track_summary.end_frame_exclusive if pack else None),
        observed_frame_count=(pack.track_summary.observed_frame_count if pack else None),
        key_crops=crops,
        screening_decision=(screening.decision if screening else None),
        screening_probability=(
            screening.parsed_output.violation_probability if screening else None
        ),
        screening_router_version=(screening.router_version if screening else None),
        verdict_decision=(verdict.decision if verdict else None),
        verdict_confidence=(verdict.confidence if verdict else None),
        procedural_review_passed=(review.passed if review else None),
        procedural_gate_version=(review.gate_version if review else None),
        final_decision=case.final_decision,
        alert_level=(latest_alert.level if latest_alert else None),
        alert_rescinded=(latest_alert.rescinded if latest_alert else False),
        human_review_required=(
            case.status == CaseStatus.HUMAN_REVIEW
            or (
                current_appeal is not None
                and current_appeal.status in {AppealStatus.SUBMITTED, AppealStatus.UNDER_REVIEW}
            )
            or (
                case.final_decision == VerdictDecision.INSUFFICIENT_EVIDENCE
                and (
                    current_appeal is None
                    or current_appeal.status not in {AppealStatus.UPHELD, AppealStatus.OVERTURNED}
                )
            )
        ),
        appeal_status=(current_appeal.status if current_appeal else None),
        detector=detector,
        screening_model=screening_model,
        prompt_bundle_sha256=manifest.prompt_bundle_sha256,
        rule_version=case.event.rule_version,
        manifest_id=manifest.manifest_id,
    )


def _model_version(manifest: RunManifest, component: str) -> PilotA4ModelVersion:
    model = manifest.models.get(component)
    if not isinstance(model, ModelManifest):
        raise ContractViolation(f"pilot report manifest lacks {component} model identity")
    return PilotA4ModelVersion(
        component=model.component,
        provider=model.provider,
        model=model.model,
        revision=model.revision,
        model_manifest_id=model.model_manifest_id,
    )


def _key_crop_views(
    pack: object,
    *,
    runs_root: Path,
    run_id: str,
) -> tuple[PilotA4MediaView, ...]:
    inventory: list[tuple[str, Crop]] = []
    for role, attribute in (
        ("PANORAMA", "panorama_crops"),
        ("SUBJECT", "subject_crops"),
        ("FOCUS", "focus_crops"),
        ("TEMPORAL", "temporal_crops"),
    ):
        crops = getattr(pack, attribute, ())
        inventory.extend((role, crop) for crop in crops)
    return tuple(
        _media_view(crop, role=role, runs_root=runs_root, run_id=run_id)
        for role, crop in inventory[:12]
    )


def _media_view(
    crop: Crop,
    *,
    role: str,
    runs_root: Path,
    run_id: str,
) -> PilotA4MediaView:
    integrity = "NOT_AVAILABLE"
    run_relative_path: str | None = None
    if crop.availability == MediaAvailability.AVAILABLE and crop.local_path is not None:
        relative = PurePosixPath(crop.local_path)
        run_root = (runs_root / run_id).resolve()
        if not relative.parts:
            raise PathBoundaryViolation("pilot crop path is empty")
        if relative.parts[0] == run_id:
            run_relative = PurePosixPath(*relative.parts[1:])
            candidate = (runs_root / Path(*relative.parts)).resolve()
        else:
            run_relative = relative
            candidate = (run_root / Path(*relative.parts)).resolve()
        if not candidate.is_relative_to(run_root):
            raise PathBoundaryViolation("pilot crop resolved outside the selected run")
        if not candidate.is_file():
            integrity = "MISSING"
        elif _file_sha256(candidate) != crop.media_sha256:
            integrity = "HASH_MISMATCH"
        else:
            integrity = "VERIFIED"
            run_relative_path = run_relative.as_posix()
    return PilotA4MediaView(
        crop_id=crop.crop_id,
        role=role,
        frame_id=crop.frame_id,
        integrity=integrity,
        run_relative_path=run_relative_path,
        media_sha256=crop.media_sha256,
        width=crop.output_width,
        height=crop.output_height,
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _metric_card(label: str, value: int, note: str) -> str:
    return f'<article class="metric"><span>{escape(label)}</span><strong>{value}</strong><p>{escape(note)}</p></article>'


def _index_case_row(case: PilotA4CaseView) -> str:
    final = case.final_decision.value if case.final_decision is not None else "待处理"
    return f"""
      <article class="case-row">
        <div><p class="mono-label">{escape(case.case_id)}</p><h3>{escape(case.violation_type.value)}</h3><p>帧 {case.start_frame}–{case.end_frame_exclusive - 1} · 最终结果 {escape(final)}</p></div>
        <div class="case-actions">{_status_badge(case.status.value)}<a href="cases/{escape(case.case_id)}.html">查看详情<span aria-hidden="true"> →</span></a></div>
      </article>
    """


def _status_badge(status: str) -> str:
    semantic = "success" if status in {item.value for item in _TERMINAL_STATUSES} else "warning"
    return f'<span class="badge {semantic}"><span aria-hidden="true" class="dot"></span>{escape(status)}</span>'


def _fact(label: str, value: str, note: str) -> str:
    return f'<article class="fact"><span>{escape(label)}</span><strong>{escape(value)}</strong><p>{escape(note)}</p></article>'


def _crop_card(media: PilotA4MediaView) -> str:
    label = f"{media.role} · {media.frame_id}"
    if media.integrity != "VERIFIED" or media.run_relative_path is None:
        return f'<article class="media unavailable"><div class="media-placeholder"><strong>图片不可显示</strong><span>完整性状态：{escape(media.integrity)}</span></div><p>{escape(label)}</p></article>'
    source = f"../../{escape(media.run_relative_path)}"
    return f'<figure class="media"><img src="{source}" width="{media.width}" height="{media.height}" loading="lazy" decoding="async" alt="案件关键截图：{escape(label)}"><figcaption>{escape(label)}<span>SHA-256 已验证</span></figcaption></figure>'


def _model_card(label: str, model: PilotA4ModelVersion) -> str:
    return f"""
      <article class="model-card"><span>{escape(label)}</span><h3>{escape(model.model)}</h3><dl><div><dt>Provider</dt><dd>{escape(model.provider)}</dd></div><div><dt>Revision</dt><dd><code>{escape(model.revision)}</code></dd></div><div><dt>Manifest</dt><dd><code>{escape(model.model_manifest_id)}</code></dd></div></dl></article>
    """


def _page(*, title: str, body: str, home_href: str) -> str:
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>{escape(title)}</title>
  <style>{_CSS}</style>
</head>
<body>
  <a class="skip" href="#main">跳到主要内容</a>
  <header class="site-head"><a href="{escape(home_href)}" aria-label="LabCourt 报告首页"><span class="mark" aria-hidden="true"></span><strong>LabCourt</strong></a><span>本地安全辅助报告</span></header>
  <main id="main">{body}</main>
  <footer><span>LabCourt · Local operator artifact</span><span>{escape(PILOT_OPERATOR_DISCLAIMER)}</span></footer>
</body>
</html>
"""


_CSS = """
:root{--bg:#f6f8fb;--surface:#fff;--surface-2:#edf2f7;--text:#142033;--muted:#52627a;--line:#d6dfeb;--accent:#174ea6;--accent-2:#0b6b57;--danger:#a52424;--warn-bg:#fff4d6;--warn-text:#6d4700;--ok-bg:#dff4ec;--ok-text:#075844;--radius:16px;--shadow:0 16px 40px rgba(20,32,51,.08)}
@media(prefers-color-scheme:dark){:root{--bg:#0d1420;--surface:#151f2e;--surface-2:#1e2b3d;--text:#f2f6fb;--muted:#b5c2d4;--line:#34445b;--accent:#8fbbff;--accent-2:#6ed9bd;--danger:#ff9c9c;--warn-bg:#3b2e11;--warn-text:#ffdb83;--ok-bg:#123b31;--ok-text:#96ead3;--shadow:none}}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;font-size:16px;line-height:1.6}a{color:var(--accent);text-underline-offset:4px}a:focus-visible{outline:3px solid var(--accent);outline-offset:4px;border-radius:4px}.skip{position:fixed;left:16px;top:-80px;z-index:100;background:var(--surface);padding:12px 16px;border:2px solid var(--accent)}.skip:focus{top:16px}.site-head{height:64px;padding:0 max(20px,calc((100vw - 1120px)/2));display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);background:color-mix(in srgb,var(--bg) 92%,transparent);color:var(--muted)}.site-head a{display:flex;align-items:center;gap:10px;color:var(--text);text-decoration:none;min-height:44px}.mark{width:18px;height:18px;border:5px solid var(--accent);border-radius:50%}main{max-width:1120px;margin:0 auto;padding:56px 24px 96px}.hero{padding:24px 0 48px;max-width:880px}.hero.compact{padding-bottom:32px}.eyebrow,.kicker,.mono-label{font-family:"Cascadia Code",Consolas,monospace;font-size:.78rem;letter-spacing:.1em;text-transform:uppercase;color:var(--accent);overflow-wrap:anywhere}.hero h1{font-size:clamp(2.4rem,7vw,5.6rem);line-height:1.02;letter-spacing:-.045em;margin:12px 0 24px}.hero.compact h1{font-size:clamp(2rem,5vw,4rem)}.lede{font-size:clamp(1.05rem,2vw,1.35rem);color:var(--muted);max-width:720px}.identity{display:flex;gap:12px;align-items:center;margin-top:24px;color:var(--muted)}code{font-family:"Cascadia Code",Consolas,monospace;font-size:.88em;overflow-wrap:anywhere}.notice{display:flex;gap:16px;padding:18px 20px;margin:0 0 56px;border-left:5px solid var(--danger);background:var(--surface);box-shadow:var(--shadow);border-radius:0 var(--radius) var(--radius) 0}.notice strong{white-space:nowrap}.notice span{color:var(--muted)}section+section{margin-top:64px}h2{font-size:clamp(1.55rem,3vw,2.25rem);line-height:1.2;margin:4px 0 24px}.metric-grid,.decision-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}.metric,.fact{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:22px;min-height:168px}.metric span,.fact span,.model-card>span{color:var(--muted);font-weight:600}.metric strong{display:block;font-size:2.8rem;line-height:1.1;margin:14px 0;font-variant-numeric:tabular-nums}.metric p,.fact p{margin:0;color:var(--muted);font-size:.9rem}.fact strong{display:block;font-size:1.18rem;margin:12px 0;overflow-wrap:anywhere}.section-head,.title-row{display:flex;align-items:flex-end;justify-content:space-between;gap:24px}.title-row{align-items:center}.data-link,.case-actions a{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:8px 14px;border:1px solid var(--line);border-radius:10px;background:var(--surface);font-weight:650;text-decoration:none;transition:background-color .18s ease,border-color .18s ease}.data-link:hover,.case-actions a:hover{background:var(--surface-2);border-color:var(--accent)}.case-list{display:grid;gap:12px}.case-row{display:flex;justify-content:space-between;align-items:center;gap:24px;padding:24px;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius)}.case-row h3{margin:4px 0;font-size:1.2rem}.case-row p{margin:0;color:var(--muted)}.case-actions{display:flex;align-items:center;gap:12px;flex-shrink:0}.badge{display:inline-flex;align-items:center;gap:8px;padding:7px 11px;border-radius:999px;font-family:"Cascadia Code",Consolas,monospace;font-size:.75rem;font-weight:700}.badge.success{background:var(--ok-bg);color:var(--ok-text)}.badge.warning{background:var(--warn-bg);color:var(--warn-text)}.dot{width:7px;height:7px;border-radius:50%;background:currentColor}.trace{padding:28px;background:var(--surface-2);border-radius:var(--radius)}.trace dl,.trace-list{display:grid;gap:12px}.trace dl div,.trace-list div{display:grid;grid-template-columns:140px minmax(0,1fr);gap:16px;padding-top:12px;border-top:1px solid var(--line)}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}.breadcrumb{display:flex;gap:10px;color:var(--muted);margin-bottom:24px}.section-copy{color:var(--muted);max-width:720px;margin:-12px 0 24px}.media-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}.media{margin:0;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);overflow:hidden}.media img{display:block;width:100%;height:auto;aspect-ratio:16/9;object-fit:contain;background:#10151d}.media figcaption,.media>p{display:flex;justify-content:space-between;gap:12px;padding:14px 16px;margin:0;color:var(--muted);font-size:.85rem;overflow-wrap:anywhere}.media figcaption span{color:var(--ok-text);white-space:nowrap}.media-placeholder{aspect-ratio:16/9;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;background:var(--surface-2);color:var(--muted)}.version-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}.model-card{padding:24px;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius)}.model-card h3{font-size:1.35rem;margin:8px 0 20px;overflow-wrap:anywhere}.model-card dl{display:grid;gap:10px}.model-card dl div{display:grid;grid-template-columns:90px minmax(0,1fr);gap:12px}.trace-list{margin-top:18px;padding:24px;background:var(--surface-2);border-radius:var(--radius)}.empty{padding:32px;border:1px dashed var(--line);border-radius:var(--radius);color:var(--muted);text-align:center}.empty p{margin:6px 0 0}footer{display:flex;justify-content:space-between;gap:24px;padding:28px max(24px,calc((100vw - 1120px)/2));border-top:1px solid var(--line);color:var(--muted);font-size:.88rem}
@media(max-width:860px){.metric-grid,.decision-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.media-grid,.version-grid{grid-template-columns:1fr}.section-head,.case-row{align-items:flex-start}.case-row{flex-direction:column}.case-actions{width:100%;justify-content:space-between}.site-head>span{display:none}}
@media(max-width:520px){main{padding:32px 16px 72px}.hero{padding-top:12px}.metric-grid,.decision-grid{grid-template-columns:1fr}.section-head,.title-row,.notice,footer{flex-direction:column;align-items:flex-start}.data-link{width:100%}.case-actions{flex-direction:column;align-items:stretch}.case-actions a{text-align:center}.trace dl div,.trace-list div{grid-template-columns:1fr;gap:4px}.notice strong{white-space:normal}.media figcaption{flex-direction:column}.media figcaption span{white-space:normal}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}*,*::before,*::after{transition-duration:.01ms!important;animation-duration:.01ms!important;animation-iteration-count:1!important}}
"""


__all__ = [
    "build_pilot_case_views",
    "build_pilot_metrics",
    "render_pilot_case",
    "render_pilot_index",
]

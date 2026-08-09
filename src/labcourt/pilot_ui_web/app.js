"use strict";

const state = {
  dashboard: null,
  selectedCaseId: null,
  selectedRunId: null,
  selectedVideoId: null,
  job: null,
  pollTimer: null,
};

const el = Object.fromEntries([
  "authority-state", "video-select", "run-select", "run-id-input", "start-button",
  "run-feedback", "stage-list", "progress-summary", "preview-badge", "video-player",
  "video-empty", "video-loading", "meta-duration", "meta-fps", "meta-frames",
  "meta-current", "case-count", "case-tabs", "case-detail", "timeline",
  "timeline-count", "alert-count", "alert-list", "disclaimer", "toast", "clock",
].map((id) => [id, document.getElementById(id)]));

const labels = {
  violation: { PPE_GOGGLES_MISSING: "未佩戴护目镜" },
  decision: {
    ESTABLISHED: "违规成立",
    NOT_ESTABLISHED: "违规不成立",
    INSUFFICIENT_EVIDENCE: "证据不足",
    UNCLEAR: "无法判断",
  },
  status: {
    CLOSED: "已结案", APPEALED: "申诉中", APPEAL_RESOLVED: "申诉已处理",
    HUMAN_REVIEW: "待人工复核", BACKLOGGED: "等待重试", ESCALATED: "已升级",
    REWORK_REQUIRED: "需要返工", READY_FOR_HEARING: "待裁决",
  },
  appeal: { UPHELD: "维持原判", OVERTURNED: "已改判", SUBMITTED: "已提交", UNDER_REVIEW: "复核中" },
  alert: { CONFIRMED: "确认告警", REVIEW: "复核告警", WATCH: "关注", EMERGENCY: "紧急" },
};

function esc(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
  })[char]);
}

function short(value, length = 10) {
  const text = String(value ?? "");
  return text.length > length ? `${text.slice(0, length)}…` : text;
}

function fmtTime(milliseconds) {
  if (milliseconds === null || milliseconds === undefined) return "—";
  const total = Math.max(0, Number(milliseconds));
  const minutes = Math.floor(total / 60000);
  const seconds = Math.floor((total % 60000) / 1000);
  const millis = Math.floor(total % 1000);
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}.${String(millis).padStart(3, "0")}`;
}

function makeRunId() {
  const now = new Date();
  const pad = (value) => String(value).padStart(2, "0");
  return `pilot-${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
}

async function api(url, options = {}) {
  const response = await fetch(url, { cache: "no-store", ...options });
  const payload = await response.json().catch(() => ({ reason_code: "INVALID_SERVER_RESPONSE" }));
  if (!response.ok) {
    const error = new Error(payload.reason_code || "REQUEST_FAILED");
    error.reasonCode = payload.reason_code || "REQUEST_FAILED";
    throw error;
  }
  return payload;
}

function reasonText(code) {
  const known = {
    RUN_NOT_FOUND: "没有找到该运行。请刷新后重试。",
    VIDEO_NOT_FOUND: "视频不可用或未通过边界检查。",
    JOB_ALREADY_RUNNING: "已有分析正在运行，请等待它完成。",
    INVALID_REQUEST: "输入不符合要求，请检查运行编号。",
    PILOT_RUN_FAILED: "分析未完成。请检查本地模型与环境变量后重试。",
    RUN_ARTIFACT_INVALID: "运行产物校验失败，界面已停止展示其结论。",
  };
  return known[code] || `操作未完成（${code || "UNKNOWN"}）`;
}

function showToast(message, isError = false) {
  el.toast.textContent = message;
  el.toast.classList.toggle("error", isError);
  el.toast.hidden = false;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => { el.toast.hidden = true; }, 4500);
}

function renderSelectors(dashboard) {
  const currentVideo = state.selectedVideoId || dashboard.selected_video_id || "";
  el["video-select"].innerHTML = dashboard.videos.length
    ? dashboard.videos.map((video) => `<option value="${esc(video.video_id)}">${esc(video.display_name)} · ${(video.size_bytes / 1048576).toFixed(1)} MB</option>`).join("")
    : '<option value="">inputs 中暂无可用 MP4</option>';
  el["video-select"].value = dashboard.videos.some((video) => video.video_id === currentVideo) ? currentVideo : (dashboard.selected_video_id || "");
  state.selectedVideoId = el["video-select"].value || null;

  el["run-select"].innerHTML = '<option value="">仅预览所选视频</option>' + dashboard.runs.map((run) => {
    const suffix = run.state === "COMPLETE" ? "已完成" : run.state === "RUNNING" ? "运行中" : run.state === "ATTENTION_REQUIRED" ? "需关注" : run.state === "INVALID" ? "校验失败" : "未完成";
    return `<option value="${esc(run.run_id)}">${esc(run.run_id)} · ${suffix}</option>`;
  }).join("");
  el["run-select"].value = dashboard.selected_run_id || "";
  state.selectedRunId = dashboard.selected_run_id;
}

function renderStages(dashboard) {
  const classByState = { COMPLETE: "complete", IN_PROGRESS: "active", ATTENTION_REQUIRED: "attention", UNAVAILABLE: "unavailable", PENDING: "pending" };
  const symbol = { COMPLETE: "✓", IN_PROGRESS: "•", ATTENTION_REQUIRED: "!", UNAVAILABLE: "×" };
  el["stage-list"].innerHTML = dashboard.stages.map((stage, index) => `
    <li class="stage-item ${classByState[stage.state] || "pending"}">
      <div class="stage-head">
        <span class="stage-index" aria-label="${esc(stage.state)}">${symbol[stage.state] || String(index + 1).padStart(2, "0")}</span>
        <span class="stage-copy"><strong>${esc(stage.label)}</strong><small title="${esc(stage.summary)}">${esc(stage.summary)}</small></span>
      </div>
    </li>`).join("");
  const complete = dashboard.stages.filter((stage) => stage.state === "COMPLETE").length;
  const active = dashboard.stages.find((stage) => stage.state === "IN_PROGRESS");
  const attention = dashboard.stages.some((stage) => stage.state === "ATTENTION_REQUIRED");
  el["progress-summary"].textContent = active ? `正在执行：${active.label}` : attention ? "结果需要关注" : `${complete} / 5 已完成`;
}

function renderVideo(dashboard) {
  const player = el["video-player"];
  const desired = dashboard.preview_url || "";
  if (player.dataset.source !== desired) {
    player.pause();
    player.removeAttribute("src");
    player.load();
    player.dataset.source = desired;
    if (desired) {
      el["video-loading"].hidden = false;
      player.src = desired;
      player.load();
    }
  }
  el["video-empty"].hidden = Boolean(desired);
  el["preview-badge"].className = `status-badge ${dashboard.preview_kind === "DEBUG" ? "debug" : dashboard.preview_kind === "SOURCE" ? "source" : "neutral"}`;
  el["preview-badge"].textContent = dashboard.preview_kind === "DEBUG" ? "红框预览 · 非权威" : dashboard.preview_kind === "SOURCE" ? "原始视频" : "未选择";
  el["meta-duration"].textContent = fmtTime(dashboard.duration_millis);
  el["meta-fps"].textContent = dashboard.fps_num ? `${dashboard.fps_num / dashboard.fps_den} FPS` : "—";
  el["meta-frames"].textContent = dashboard.frame_count ?? "—";
}

function emptyMarkup(title, copy) {
  return `<div class="empty-state"><svg viewBox="0 0 48 48" aria-hidden="true"><path d="M9 13h30v25H9z"></path><path d="M16 9h16M16 21h16M16 28h11"></path></svg><strong>${esc(title)}</strong><span>${esc(copy)}</span></div>`;
}

function evidenceLabel(role) {
  return { PANORAMA: "现场全景", SUBJECT: "主体证据", FOCUS: "护目镜区域", TEMPORAL: "时序证据" }[role] || role;
}

function selectCase(caseId) {
  state.selectedCaseId = caseId;
  renderCases(state.dashboard);
}

function renderCases(dashboard) {
  el["case-count"].textContent = dashboard.cases.length;
  if (!dashboard.cases.length) {
    el["case-tabs"].innerHTML = "";
    el["case-detail"].innerHTML = emptyMarkup("暂无案件", "完成证据构建和模型初审后，案件详情会出现在这里。");
    return;
  }
  if (!dashboard.cases.some((item) => item.case_id === state.selectedCaseId)) state.selectedCaseId = dashboard.cases[0].case_id;
  el["case-tabs"].innerHTML = dashboard.cases.map((item, index) => `<button class="case-tab" type="button" role="tab" aria-selected="${item.case_id === state.selectedCaseId}" data-case-id="${esc(item.case_id)}">案件 ${String(index + 1).padStart(2, "0")}</button>`).join("");
  el["case-tabs"].querySelectorAll("button").forEach((button) => button.addEventListener("click", () => selectCase(button.dataset.caseId)));
  const item = dashboard.cases.find((entry) => entry.case_id === state.selectedCaseId);
  const decision = labels.decision[item.final_decision] || "等待结论";
  const tagClass = item.human_review_required ? "warning" : item.final_decision === "ESTABLISHED" ? "danger" : "";
  const evidence = item.evidence.map((media) => media.media_url
    ? `<button class="evidence-thumb" type="button" data-time="${media.time_millis}" aria-label="跳到 ${esc(evidenceLabel(media.role))} ${fmtTime(media.time_millis)}"><img src="${esc(media.media_url)}" alt="${esc(evidenceLabel(media.role))}" loading="lazy"><span>${fmtTime(media.time_millis)}</span></button>`
    : `<div class="evidence-thumb unavailable"><span>${media.integrity === "MISSING" ? "文件缺失" : "校验失败"}</span></div>`).join("");
  el["case-detail"].innerHTML = `
    <div class="decision-hero">
      <div><small>${esc(labels.violation[item.violation_type] || item.violation_type)}</small><strong>${esc(decision)}</strong></div>
      <span class="decision-tag ${tagClass}">${item.human_review_required ? "需要人工复核" : esc(labels.status[item.status] || item.status)}</span>
    </div>
    <dl class="detail-grid">
      <div><dt>案件编号</dt><dd class="data-text" title="${esc(item.case_id)}">${esc(short(item.case_id, 18))}</dd></div>
      <div><dt>证据区间</dt><dd class="data-text">${fmtTime(item.start_time_millis)} – ${fmtTime(item.end_time_millis)}</dd></div>
      <div><dt>模型初审</dt><dd>${esc(labels.decision[item.screening_decision] || item.screening_decision || "—")} ${item.screening_probability === null ? "" : `· ${(item.screening_probability * 100).toFixed(0)}%`}</dd></div>
      <div><dt>告警级别</dt><dd>${esc(labels.alert[item.alert_level] || item.alert_level || "无告警")}${item.alert_rescinded ? " · 已撤销" : ""}</dd></div>
      <div><dt>案件状态</dt><dd>${esc(labels.status[item.status] || item.status)}</dd></div>
      <div><dt>申诉状态</dt><dd>${esc(labels.appeal[item.appeal_status] || item.appeal_status || "无")}</dd></div>
    </dl>
    <div class="evidence-strip"><h3>关键证据 · ${item.evidence.length} 张</h3><div class="evidence-grid">${evidence || "<span>暂无可展示证据</span>"}</div></div>`;
  el["case-detail"].querySelectorAll("[data-time]").forEach((button) => button.addEventListener("click", () => seekVideo(Number(button.dataset.time))));
}

function seekVideo(milliseconds) {
  const player = el["video-player"];
  if (!player.src) return;
  player.currentTime = Math.max(0, milliseconds / 1000);
  player.play().catch(() => {});
}

function renderTimeline(dashboard) {
  el["timeline-count"].textContent = `${dashboard.timeline.length} 个节点`;
  if (!dashboard.timeline.length) {
    el.timeline.innerHTML = emptyMarkup("暂无证据时间线", "选择一个完成的运行，查看候选事件与关键证据帧。");
    return;
  }
  el.timeline.innerHTML = dashboard.timeline.map((item) => {
    const boundary = item.kind !== "EVIDENCE";
    return `<button type="button" class="timeline-item ${boundary ? "boundary" : ""}" data-time="${item.time_millis}" data-case-id="${esc(item.case_id)}">
      <span class="timeline-dot" aria-hidden="true"></span>
      <span class="timeline-time">${fmtTime(item.time_millis)}</span>
      <span class="timeline-copy"><strong>${esc(item.label)}</strong><small>FRAME ${item.frame_index}</small></span>
      ${item.media_url ? `<img class="timeline-thumb" src="${esc(item.media_url)}" alt="${esc(item.label)}" loading="lazy">` : ""}
    </button>`;
  }).join("");
  el.timeline.querySelectorAll("button").forEach((button) => button.addEventListener("click", () => {
    selectCase(button.dataset.caseId);
    seekVideo(Number(button.dataset.time));
  }));
}

function renderAlerts(dashboard) {
  el["alert-count"].textContent = dashboard.alerts.length;
  if (!dashboard.alerts.length) {
    el["alert-list"].innerHTML = emptyMarkup("暂无本地告警", "只有通过结案策略且仍有效的告警才会出现在这里。");
    return;
  }
  el["alert-list"].innerHTML = dashboard.alerts.map((alert) => `
    <article class="alert-item">
      <div class="alert-item-header"><strong>${esc(labels.alert[alert.level] || alert.level)}</strong><span class="alert-level">${alert.rescinded ? "RESCINDED" : "ACTIVE"}</span></div>
      <dl><dt>案件</dt><dd class="data-text" title="${esc(alert.case_id)}">${esc(short(alert.case_id, 18))}</dd><dt>结论</dt><dd>${esc(labels.decision[alert.final_decision] || alert.final_decision)}</dd><dt>接收方</dt><dd>${esc(alert.recipients.join(" · "))}</dd></dl>
    </article>`).join("");
}

function renderAuthority(dashboard) {
  const invalid = dashboard.runs.find((run) => run.run_id === dashboard.selected_run_id)?.state === "INVALID";
  el["authority-state"].textContent = invalid ? "校验失败" : dashboard.metrics_id ? "权威产物已验证" : dashboard.selected_run_id ? "运行尚未完成" : "仅视频预览";
  el.disclaimer.textContent = dashboard.disclaimer;
}

function render(dashboard) {
  state.dashboard = dashboard;
  renderSelectors(dashboard);
  renderStages(dashboard);
  renderVideo(dashboard);
  renderCases(dashboard);
  renderTimeline(dashboard);
  renderAlerts(dashboard);
  renderAuthority(dashboard);
  const running = state.job?.state === "RUNNING";
  el["start-button"].disabled = running || !dashboard.videos.length;
  el["video-select"].disabled = running || !dashboard.videos.length;
  el["run-id-input"].disabled = running;
}

async function loadDashboard({ runId = state.selectedRunId, videoId = state.selectedVideoId } = {}) {
  const params = new URLSearchParams();
  if (runId !== null && runId !== undefined) params.set("run_id", runId);
  if (videoId) params.set("video_id", videoId);
  const dashboard = await api(`/api/dashboard?${params.toString()}`);
  render(dashboard);
}

async function loadJob() {
  state.job = await api("/api/jobs/current");
  if (state.job.state === "RUNNING") {
    state.selectedRunId = state.job.run_id;
    el["run-feedback"].textContent = `正在分析 ${state.job.run_id}；当前阶段会自动刷新。`;
    await loadDashboard({ runId: state.job.run_id, videoId: state.job.video_id });
    schedulePoll();
  } else if (state.job.state === "SUCCEEDED" || state.job.state === "ATTENTION_REQUIRED") {
    state.selectedRunId = state.job.run_id;
    el["run-feedback"].textContent = state.job.state === "SUCCEEDED" ? "分析已完成，案件与告警已刷新。" : "分析已完成，但有项目需要人工关注。";
    await loadDashboard({ runId: state.job.run_id, videoId: state.job.video_id });
  } else if (state.job.state === "FAILED") {
    el["run-feedback"].textContent = reasonText(state.job.reason_code);
    showToast(reasonText(state.job.reason_code), true);
  }
}

function schedulePoll() {
  window.clearTimeout(state.pollTimer);
  if (state.job?.state === "RUNNING") state.pollTimer = window.setTimeout(() => loadJob().catch(handleError), 1400);
}

async function startRun() {
  const videoId = el["video-select"].value;
  const runId = el["run-id-input"].value.trim();
  if (!videoId || !runId) {
    showToast("请选择视频并填写运行编号。", true);
    return;
  }
  el["start-button"].disabled = true;
  el["run-feedback"].textContent = "正在创建受控分析任务…";
  try {
    state.job = await api("/api/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ video_id: videoId, run_id: runId, resume: true }),
    });
    state.selectedRunId = runId;
    state.selectedVideoId = videoId;
    showToast("分析任务已启动。页面会自动更新阶段进度。");
    await loadJob();
  } catch (error) {
    handleError(error);
    el["start-button"].disabled = false;
  }
}

function handleError(error) {
  const message = reasonText(error?.reasonCode || error?.message || "REQUEST_FAILED");
  showToast(message, true);
  el["run-feedback"].textContent = message;
}

function bindEvents() {
  el["start-button"].addEventListener("click", startRun);
  el["video-select"].addEventListener("change", () => {
    state.selectedVideoId = el["video-select"].value || null;
    state.selectedRunId = "";
    loadDashboard({ runId: "", videoId: state.selectedVideoId }).catch(handleError);
  });
  el["run-select"].addEventListener("change", () => {
    state.selectedRunId = el["run-select"].value;
    state.selectedVideoId = null;
    loadDashboard({ runId: state.selectedRunId, videoId: null }).catch(handleError);
  });
  el["video-player"].addEventListener("loadedmetadata", () => { el["video-loading"].hidden = true; });
  el["video-player"].addEventListener("canplay", () => { el["video-loading"].hidden = true; });
  el["video-player"].addEventListener("error", () => { el["video-loading"].hidden = true; });
  el["video-player"].addEventListener("timeupdate", () => { el["meta-current"].textContent = fmtTime(el["video-player"].currentTime * 1000); });
}

function tickClock() {
  el.clock.textContent = new Intl.DateTimeFormat("zh-CN", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date());
}

async function boot() {
  el["run-id-input"].value = makeRunId();
  bindEvents();
  tickClock();
  window.setInterval(tickClock, 1000);
  try {
    await loadDashboard({ runId: null, videoId: null });
    await loadJob();
  } catch (error) {
    handleError(error);
  }
}

boot();

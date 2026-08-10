"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const PREVIEW_DATA = Object.freeze({
  cameras: [
    { id: "CAM-LAB-301-A", shortId: "CAM-301-A", name: "化学实验区 · 主操作台", shortName: "主操作台", state: "检测到匿名轨迹", scene: "scene-a" },
    { id: "CAM-LAB-301-B", shortId: "CAM-301-B", name: "化学实验区 · 通风橱", shortName: "通风橱", state: "无活动", scene: "scene-b" },
    { id: "CAM-LAB-302-A", shortId: "CAM-302-A", name: "仪器分析室 · 西侧", shortName: "仪器分析室", state: "设备在线", scene: "scene-c" },
    { id: "CAM-LAB-303-B", shortId: "CAM-303-B", name: "实验准备区 · 入口", shortName: "实验准备区", state: "1 条匿名轨迹", scene: "scene-b" },
  ],
  events: [
    { id: "sensor-emergency", category: "emergency", level: "紧急 · 模拟传感器", title: "温度与烟雾信号联动", location: "化学实验区 · 主操作台", time: "14:32:14", detail: "可靠信号路径演示 · VLM 不参与安全底线", signals: ["78.4°C", "SMK 0.82"] },
    { id: "goggles-case", category: "case", level: "一般 · 案件候选", title: "护目镜缺失候选", location: "匿名轨迹 T-07 · 高风险区", time: "14:31:48", detail: "AI 初审建议 · 尚未直接定责", signals: [] },
    { id: "soft-reminder", category: "resolved", level: "已化解 · 软提醒", title: "进入风险区后已补戴", location: "仅实时提醒 · 未建案、未落盘", time: "14:28:09", detail: "L0 预防路径 · 不形成问责记录", signals: [] },
  ],
  evidence: {
    context: { frameClass: "scene scene-a", frame: "45812", ref: "CROP-7A", thumbLabel: "全景上下文", label: "全景 · FRAME 45812", time: "14:31:43.833 · CROP-7A", title: "全景上下文建立区域与时序", copy: "显示匿名轨迹进入高风险区后的第一张清晰全景；身份信息未采集，轨迹只在当前机位与当前 tracker epoch 内有效。", visual: "focus" },
    ppe: { frameClass: "crop-head", frame: "45865", ref: "CROP-91", thumbLabel: "PPE 区域", label: "PPE 区域 · FRAME 45865", time: "14:31:46.041 · CROP-91", title: "最小裁切用于检查护目镜佩戴状态", copy: "仅保留完成 PPE 检查所需的头部区域。该观察用于形成候选建议，不作为身份识别、客观计数或直接定责来源。", visual: "head" },
    counter: { frameClass: "crop-head alternate", frame: "45910", ref: "CROP-B4", thumbLabel: "时序反证", label: "时序反证 · FRAME 45910", time: "14:31:48.125 · CROP-B4", title: "后续时刻用于寻找可能被忽略的反证", copy: "复核涉嫌区间末端是否出现清晰佩戴证据，并记录镜片反光与遮挡检查结果；当前仍需人工作最终判断。", visual: "head" },
  },
});

const elements = {
  clock: $("#live-clock"),
  mainCamera: $("#main-camera"),
  mainCameraName: $("#main-camera-name"),
  mainCameraId: $("#main-camera-id"),
  mainCameraMeta: $("#main-camera-meta"),
  mainCameraTime: $("#main-camera-time"),
  cameraThumbnails: $("#camera-thumbnails"),
  eventList: $("#event-list"),
  eventFilter: $("#event-filter"),
  drawer: $("#event-drawer"),
  drawerContent: $("#drawer-content"),
  drawerScrim: $("#drawer-scrim"),
  agentPanel: $("#agent-panel"),
  agentToggle: $("#agent-toggle"),
  agentMessages: $("#agent-messages"),
  agentForm: $("#agent-form"),
  agentInput: $("#agent-input"),
  confirmDialog: $("#confirm-dialog"),
  confirmActionName: $("#confirm-action-name"),
  pipelineToggle: $("#pipeline-toggle"),
  pipelineDetails: $("#pipeline-details"),
  evidenceMain: $("#evidence-main"),
  evidenceThumbnails: $("#evidence-thumbnails"),
  evidenceCaptionTitle: $("#evidence-caption-title"),
  evidenceCaptionCopy: $("#evidence-caption-copy"),
  newPendingCount: $("#new-pending-count"),
  newPendingEmpty: $("#new-pending-empty"),
  toast: $("#toast"),
};

let currentCameraId = PREVIEW_DATA.cameras[0].id;
let drawerReturnFocus = null;
let pendingReadEvent = null;
let toastTimer = null;
const unreadEvents = new Set(["sensor-emergency", "goggles-case"]);

const drawerViews = {
  "goggles-case": `
    <section class="drawer-event-head">
      <span class="status-label attention">一般案件 · SIMULATED</span>
      <h3>护目镜缺失案件候选</h3>
      <p>AI 只给出结构化建议；是否生成安全提醒仍需人工确认。</p>
    </section>
    <section class="drawer-section">
      <h3>客观事实</h3>
      <div class="drawer-facts">
        <div><span>案件编号</span><strong class="mono">LC-2026-0810-014</strong></div>
        <div><span>单机位轨迹</span><strong class="mono">T-07</strong></div>
        <div><span>涉嫌区间</span><strong class="mono">5.0 秒</strong></div>
        <div><span>清晰裁切</span><strong class="mono">3 / 3</strong></div>
      </div>
    </section>
    <section class="drawer-section">
      <h3>当前建议</h3>
      <p>证据支持生成建议级安全提醒；程序检查已通过，尚未执行任何真实动作。</p>
    </section>
    <div class="source-mini"><span>制度引用 · SIMULATED</span><strong>KB-PPE-004 · 条目 4.2 · v3.2</strong><small>生效日期 2026-03-01</small></div>
    <div class="drawer-actions">
      <button class="button secondary" type="button" data-close-drawer>稍后处理</button>
      <button class="button primary wide-action" type="button" data-open-case>进入案件详情</button>
    </div>`,
  "sensor-emergency": `
    <section class="drawer-event-head danger">
      <span class="status-label attention">紧急 · 模拟可靠信号</span>
      <h3>温度与烟雾信号联动</h3>
      <p>安全信号旁路先于 VLM。此处只演示处置界面，不声称已实现真实烟火检测。</p>
    </section>
    <section class="drawer-section">
      <h3>信号快照</h3>
      <div class="drawer-facts">
        <div><span>温度</span><strong class="mono">78.4°C</strong></div>
        <div><span>烟雾指数</span><strong class="mono">SMK 0.82</strong></div>
        <div><span>信号来源</span><strong>SIMULATED SENSOR</strong></div>
        <div><span>智能层状态</span><strong>不参与底线判断</strong></div>
      </div>
    </section>
    <section class="drawer-section"><h3>预览边界</h3><p>未连接 PLC、物理传感器、真实通知通道或应急广播。</p></section>
    <div class="drawer-actions">
      <button class="button secondary" type="button" data-direct-action="接单状态">确认已接单</button>
      <button class="button primary wide-action" type="button" data-placeholder="紧急处置卡">打开处置卡</button>
    </div>`,
  "soft-reminder": `
    <section class="drawer-event-head">
      <span class="status-label success">L0 软提醒 · 已化解</span>
      <h3>进入风险区后已补戴</h3>
      <p>该提醒未建案、未落盘、未保留轨迹标识，也不形成问责记录。</p>
    </section>
    <section class="drawer-section"><h3>路径说明</h3><p>预防提醒与案件问责明确分流。此记录仅为前端模拟内容。</p></section>
    <div class="drawer-actions"><button class="button secondary wide-action" type="button" data-close-drawer>关闭</button></div>`,
};

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
  })[character]);
}

function showToast(message) {
  window.clearTimeout(toastTimer);
  elements.toast.textContent = message;
  elements.toast.hidden = false;
  toastTimer = window.setTimeout(() => { elements.toast.hidden = true; }, 3600);
}

function routeTo(name) {
  const routes = { workbench: "/workbench", cameras: "/cameras", cases: "/cases", map: "/map", knowledge: "/knowledge", case: "/case/LC-2026-0810-014" };
  window.location.hash = routes[name] || routes.workbench;
}

function resolveRoute() {
  const hash = window.location.hash || "";
  if (!hash || hash === "#" || hash === "#/" || hash === "#/monitor") {
    window.location.replace(`${window.location.pathname}${window.location.search}#/workbench`);
    return null;
  }
  if (hash.startsWith("#/case/")) return { view: "case-view", nav: "cases", title: "case-title" };
  if (hash === "#/cameras") return { view: "cameras-view", nav: "cameras", title: "cameras-title" };
  if (hash === "#/workbench") return { view: "workbench-view", nav: "workbench", title: "workbench-title" };
  const placeholders = {
    "#/cases": ["案件中心", "案件列表将在确认字段、筛选条件和批量操作后继续打磨。", "cases"],
    "#/map": ["校园地图", "校园、楼宇、楼层、房间与设备的逐级下钻将在后续页面阶段制作。", "map"],
    "#/knowledge": ["知识库", "制度、SOP、判例、应急预案和设备资料将在确认内容模型后制作。", "knowledge"],
  };
  const placeholder = placeholders[hash] || placeholders["#/cases"];
  $("#placeholder-title").textContent = placeholder[0];
  $("#placeholder-copy").textContent = `${placeholder[1]} 当前仅保留纯前端预览入口。`;
  return { view: "placeholder-view", nav: placeholder[2], title: "placeholder-title" };
}

function applyRoute({ focus = true } = {}) {
  const route = resolveRoute();
  if (!route) return;
  $$(".page-view").forEach((view) => { view.hidden = view.id !== route.view; });
  $$('[data-nav]').forEach((link) => {
    const active = link.dataset.nav === route.nav;
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
  });
  closeDrawer(false);
  window.scrollTo({ top: 0, behavior: "auto" });
  if (focus) window.requestAnimationFrame(() => $(`#${route.title}`)?.focus({ preventScroll: true }));
}

function renderCameraThumbnails() {
  elements.cameraThumbnails.innerHTML = PREVIEW_DATA.cameras.filter((camera) => camera.id !== currentCameraId).map((camera) => `
    <button class="camera-thumb scene ${camera.scene}" type="button" data-camera-id="${escapeHtml(camera.id)}" aria-label="切换到 ${escapeHtml(camera.name)}">
      <span class="mini-architecture" aria-hidden="true"><i></i><i></i><i></i></span>
      <span class="camera-overlay top"><b><i class="live-pulse"></i>LIVE</b><small class="mono">${escapeHtml(camera.shortId)}</small></span>
      <span class="camera-overlay bottom"><strong>${escapeHtml(camera.shortName)}</strong><small>${escapeHtml(camera.state)}</small></span>
    </button>`).join("");
}

function selectCamera(cameraId) {
  const camera = PREVIEW_DATA.cameras.find((item) => item.id === cameraId);
  if (!camera) return;
  currentCameraId = camera.id;
  elements.mainCamera.classList.remove("scene-a", "scene-b", "scene-c");
  elements.mainCamera.classList.add(camera.scene);
  elements.mainCamera.dataset.camera = camera.id;
  elements.mainCameraName.textContent = camera.name;
  elements.mainCameraId.textContent = camera.id;
  elements.mainCameraMeta.textContent = `${camera.id} · 1080P · 24 FPS`;
  renderCameraThumbnails();
  showToast(`主画面已切换至 ${camera.name} · 模拟机位`);
}

function renderEvents(filter = "all") {
  const events = filter === "all" ? PREVIEW_DATA.events : PREVIEW_DATA.events.filter((event) => event.category === filter);
  elements.eventList.innerHTML = events.map((event) => `
    <button class="event-row ${escapeHtml(event.category)}" type="button" data-event="${escapeHtml(event.id)}">
      <span class="event-row-top"><b>${escapeHtml(event.level)}</b><time class="mono">${escapeHtml(event.time)}</time></span>
      <strong>${escapeHtml(event.title)}</strong>
      <span>${escapeHtml(event.location)}</span>
      ${event.signals.length ? `<span class="event-signals">${event.signals.map((signal) => `<i>${escapeHtml(signal)}</i>`).join("")}</span>` : ""}
      <small>${escapeHtml(event.detail)}</small>
    </button>`).join("") || '<div class="placeholder-page"><p>当前筛选下没有模拟事件。</p></div>';
}

function syncUnreadItems() {
  $$('[data-new-event]').forEach((card) => { card.hidden = !unreadEvents.has(card.dataset.newEvent); });
  $$('[data-queue-event]').forEach((row) => { row.hidden = unreadEvents.has(row.dataset.queueEvent); });
  const count = unreadEvents.size;
  elements.newPendingCount.textContent = `${count} NEW`;
  elements.newPendingCount.hidden = count === 0;
  elements.newPendingEmpty.hidden = count !== 0;
}

function markEventRead(eventName) {
  if (!eventName || !unreadEvents.delete(eventName)) return null;
  syncUnreadItems();
  const queueRow = $(`[data-queue-event="${eventName}"]`);
  showToast(`已查看新增事项，并入待处理队列 · ${eventName === "sensor-emergency" ? "模拟传感器事件" : "模拟案件候选"}`);
  return queueRow;
}

function selectEvidence(evidenceId) {
  const evidence = PREVIEW_DATA.evidence[evidenceId];
  if (!evidence) return;
  elements.evidenceMain.className = `evidence-frame evidence-main ${evidence.frameClass}`;
  const visual = evidence.visual === "head"
    ? '<div class="abstract-head" aria-hidden="true"><i></i><b></b></div>'
    : '<div class="focus-outline wide" aria-hidden="true"></div>';
  elements.evidenceMain.innerHTML = `<span class="evidence-label">${escapeHtml(evidence.label)}</span>${visual}<small class="mono">${escapeHtml(evidence.time)}</small>`;
  elements.evidenceCaptionTitle.textContent = evidence.title;
  elements.evidenceCaptionCopy.textContent = evidence.copy;
  elements.evidenceThumbnails.innerHTML = Object.entries(PREVIEW_DATA.evidence)
    .filter(([id]) => id !== evidenceId)
    .map(([id, item]) => {
      const thumbVisual = item.visual === "head"
        ? '<i class="abstract-head" aria-hidden="true"><i></i><b></b></i>'
        : '<i class="focus-outline wide" aria-hidden="true"></i>';
      return `<button class="evidence-thumb" type="button" data-evidence-id="${escapeHtml(id)}"><span class="evidence-frame ${escapeHtml(item.frameClass)}"><span class="evidence-label">${escapeHtml(item.frame)}</span>${thumbVisual}</span><span><b>${escapeHtml(item.thumbLabel)}</b><small class="mono">${escapeHtml(item.ref)}</small></span></button>`;
    }).join("");
}

function togglePipeline() {
  const expanded = elements.pipelineToggle.getAttribute("aria-expanded") === "true";
  elements.pipelineToggle.setAttribute("aria-expanded", String(!expanded));
  elements.pipelineDetails.hidden = expanded;
  $(".progress-action", elements.pipelineToggle).childNodes[0].textContent = expanded ? "展开完整链路 " : "收起完整链路 ";
}

function openDrawer(eventName, trigger = document.activeElement) {
  elements.drawerContent.innerHTML = drawerViews[eventName] || drawerViews["goggles-case"];
  drawerReturnFocus = trigger instanceof HTMLElement ? trigger : null;
  pendingReadEvent = trigger instanceof HTMLElement ? trigger.dataset.newEvent || null : null;
  elements.drawerScrim.hidden = false;
  window.requestAnimationFrame(() => {
    elements.drawerScrim.classList.add("visible");
    elements.drawer.classList.add("open");
  });
  elements.drawer.setAttribute("aria-hidden", "false");
  window.setTimeout(() => $("[data-close-drawer]", elements.drawer)?.focus(), 40);
  if (eventName === "goggles-case") selectCamera("CAM-LAB-301-A");
}

function closeDrawer(returnFocus = true) {
  if (!elements.drawer.classList.contains("open") && elements.drawer.getAttribute("aria-hidden") === "true") return;
  const queueFocus = markEventRead(pendingReadEvent);
  pendingReadEvent = null;
  elements.drawer.classList.remove("open");
  elements.drawerScrim.classList.remove("visible");
  elements.drawer.setAttribute("aria-hidden", "true");
  window.setTimeout(() => { elements.drawerScrim.hidden = true; }, 190);
  if (returnFocus) (queueFocus || drawerReturnFocus)?.focus();
}

function setAgentOpen(open) {
  elements.agentPanel.classList.toggle("open", open);
  elements.agentPanel.setAttribute("aria-hidden", String(!open));
  elements.agentToggle.setAttribute("aria-expanded", String(open));
  if (open) window.setTimeout(() => elements.agentInput.focus(), 40);
  else elements.agentToggle.focus();
}

function showConfirmation(action) {
  elements.confirmActionName.textContent = action;
  if (typeof elements.confirmDialog.showModal === "function") elements.confirmDialog.showModal();
  else showToast(`${action}：当前浏览器不支持原生确认对话框`);
}

function activateCaseTab(tabName, focus = false) {
  const tabs = $$('[data-case-tab]');
  tabs.forEach((tab) => {
    const active = tab.dataset.caseTab === tabName;
    tab.setAttribute("aria-selected", String(active));
    tab.tabIndex = active ? 0 : -1;
    if (active && focus) tab.focus();
  });
  $$('[data-tab-panel]').forEach((panel) => { panel.hidden = panel.dataset.tabPanel !== tabName; });
}

function handleAgentSubmit(event) {
  event.preventDefault();
  const message = elements.agentInput.value.trim();
  if (!message) return;
  elements.agentMessages.insertAdjacentHTML("beforeend", `<div class="agent-message user"><small>值班安全员</small><p>${escapeHtml(message)}</p><span>本地预览回复</span></div>`);
  const risky = /(确认违规|撤销|结案|生成|关闭案件|发出通知)/.test(message);
  const direct = /(接单|到场|已查看)/.test(message);
  let response;
  if (risky) {
    response = `<div class="agent-message"><small>Agent 解析结果</small><p>这条回复可能改变案件或通知状态。我已生成明确动作卡，执行前需要二次确认。</p><div class="parsed-warning">解析动作：${escapeHtml(message)} · PREVIEW · 未执行</div><button class="button primary" type="button" data-confirm-action="${escapeHtml(message)}">检查并确认</button></div>`;
  } else if (direct) {
    response = `<div class="agent-message"><small>Agent 解析结果</small><p>已将“${escapeHtml(message)}”记录为低风险模拟动作。</p><span>未发送真实消息或修改生产状态。</span></div>`;
  } else {
    response = `<div class="agent-message"><small>通知 Agent · SIMULATED</small><p>我已收到回复。由于当前是纯前端预览，不会调用任何业务接口。</p><span>如需执行高风险动作，我会先展示明确动作卡。</span></div>`;
  }
  elements.agentMessages.insertAdjacentHTML("beforeend", response);
  elements.agentInput.value = "";
  elements.agentMessages.scrollTop = elements.agentMessages.scrollHeight;
}

function updateClock() {
  const now = new Date();
  const time = new Intl.DateTimeFormat("zh-CN", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(now);
  elements.clock.textContent = time;
  elements.mainCameraTime.textContent = `${time}.${String(now.getMilliseconds()).padStart(3, "0")}`;
}

function initializeTheme() {
  const saved = window.localStorage.getItem("labcourt-preview-theme");
  const preferred = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  const theme = saved || preferred;
  document.documentElement.dataset.theme = theme;
  $("#theme-toggle").setAttribute("aria-pressed", String(theme === "dark"));
}

function bindEvents() {
  document.addEventListener("click", (event) => {
    const target = event.target.closest("button, a");
    if (!target) return;
    if (target.dataset.route) { event.preventDefault(); routeTo(target.dataset.route); }
    if (target.dataset.placeholder) showToast(`${target.dataset.placeholder}将在逐页确认内容后继续打磨`);
    if (target.dataset.event) openDrawer(target.dataset.event, target);
    if (target.hasAttribute("data-close-drawer")) closeDrawer();
    if (target.hasAttribute("data-open-case")) { closeDrawer(false); routeTo("case"); }
    if (target.hasAttribute("data-open-agent")) setAgentOpen(true);
    if (target.hasAttribute("data-close-agent")) setAgentOpen(false);
    if (target.dataset.directAction) { showToast(`${target.dataset.directAction}：低风险模拟动作已记录，未连接生产系统`); closeDrawer(); }
    if (target.dataset.confirmAction) showConfirmation(target.dataset.confirmAction);
    if (target.dataset.openTab) activateCaseTab(target.dataset.openTab, true);
    if (target.dataset.cameraId) selectCamera(target.dataset.cameraId);
    if (target.dataset.evidenceId) selectEvidence(target.dataset.evidenceId);
    if (target.id === "pipeline-toggle") togglePipeline();
  });

  $("#theme-toggle").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    window.localStorage.setItem("labcourt-preview-theme", next);
    $("#theme-toggle").setAttribute("aria-pressed", String(next === "dark"));
    showToast(`已切换至${next === "dark" ? "深色" : "浅色"}模式`);
  });
  elements.agentToggle.addEventListener("click", () => setAgentOpen(!elements.agentPanel.classList.contains("open")));
  elements.agentForm.addEventListener("submit", handleAgentSubmit);
  elements.drawerScrim.addEventListener("click", () => closeDrawer());
  elements.eventFilter.addEventListener("change", () => renderEvents(elements.eventFilter.value));
  window.addEventListener("hashchange", () => applyRoute());

  $$('[data-case-tab]').forEach((tab) => {
    tab.addEventListener("click", () => activateCaseTab(tab.dataset.caseTab));
    tab.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const tabs = $$('[data-case-tab]');
      const current = tabs.indexOf(tab);
      const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : event.key === "ArrowRight" ? (current + 1) % tabs.length : (current - 1 + tabs.length) % tabs.length;
      activateCaseTab(tabs[next].dataset.caseTab, true);
    });
  });

  elements.confirmDialog.addEventListener("close", () => {
    if (elements.confirmDialog.returnValue === "confirm") showToast(`${elements.confirmActionName.textContent}：模拟确认完成，未连接任何生产动作`);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    if (elements.drawer.classList.contains("open")) closeDrawer();
    else if (elements.agentPanel.classList.contains("open")) setAgentOpen(false);
  });
}

initializeTheme();
renderCameraThumbnails();
renderEvents();
syncUnreadItems();
selectEvidence("context");
bindEvents();
updateClock();
window.setInterval(updateClock, 1000);
applyRoute({ focus: false });

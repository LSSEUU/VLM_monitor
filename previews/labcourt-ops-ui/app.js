"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const elements = {
  root: document.documentElement,
  themeToggle: $("#theme-toggle"),
  liveClock: $("#live-clock"),
  mainCamera: $("#main-camera"),
  mainCameraName: $("#main-camera-name"),
  mainCameraId: $("#main-camera-id"),
  mainCameraTime: $("#main-camera-time"),
  pages: $$("[data-page]"),
  drawer: $("#event-drawer"),
  drawerContent: $("#drawer-content"),
  drawerScrim: $("#drawer-scrim"),
  agentLauncher: $("#agent-launcher"),
  agentPanel: $("#agent-panel"),
  agentMessages: $("#agent-messages"),
  agentForm: $("#agent-form"),
  agentInput: $("#agent-input"),
  confirmDialog: $("#confirm-dialog"),
  confirmActionName: $("#confirm-action-name"),
  toast: $("#toast"),
};

const roomViews = {
  chem: {
    title: "化学实验区",
    code: "ROOM-CHEM-301",
    summary: "高风险实验区。当前包含一条模拟传感器紧急事件与一条一般案件候选。",
    cameras: "4 / 4 在线",
    sensors: "12 / 12 在线",
    events: "02",
  },
  instrument: {
    title: "仪器分析室",
    code: "ROOM-INS-302",
    summary: "精密仪器操作区。当前有一条需要补充证据的模拟案件，不存在紧急信号。",
    cameras: "3 / 3 在线",
    sensors: "8 / 8 在线",
    events: "01",
  },
  storage: {
    title: "试剂暂存间",
    code: "ROOM-STO-303",
    summary: "受控暂存空间。模拟门磁、烟雾与温度传感器心跳正常，当前无开放事件。",
    cameras: "1 / 1 在线",
    sensors: "3 / 3 在线",
    events: "00",
  },
};

const knowledgeViews = {
  ppe: { type: "模拟制度", title: "化学实验室个人防护示例规范", description: "进入标记为高风险的化学操作区域时，应按区域要求佩戴护目镜。该条目仅用于预览引用结构。", source: "校级制度库（模拟）", version: "v3.2", date: "2026-03-01", id: "KB-PPE-004", note: "普通知识条目不会自动成为裁判规则；案件必须记录实际引用版本，并由程序检查与人工复核。" },
  smoke: { type: "应急预案", title: "烟雾与温度联动处置示例", description: "可靠传感器信号达到演示阈值时进入紧急路径，并优先通知现场值班员。VLM 不参与该安全底线。", source: "安全管理处（模拟）", version: "v2.1", date: "2026-06-15", id: "SOP-EMG-012", note: "模拟阈值与流程仅用于交互演示，不能被解释为现场认证、设备性能或生产处置依据。" },
  appeal: { type: "模拟判例", title: "镜片反光导致误报的撤销记录", description: "人工复核发现反光区域被错误解释为未佩戴，反证成立后撤销候选，并保留完整审计原因。", source: "复核案例库（模拟）", version: "v1.0", date: "2026-07-18", id: "CASE-REF-019", note: "判例用于提示复核方向，不替代当前案件证据，也不能自动决定裁决。" },
  hood: { type: "操作 SOP", title: "通风橱启动前检查步骤", description: "示例步骤包括电源、风速指示、视窗位置与异常声音检查，并要求记录异常项。", source: "化学中心（模拟）", version: "v4.0", date: "2026-02-10", id: "SOP-CHEM-022", note: "操作人员仍需遵循现场有效版本；本地预览不会下发设备控制指令。" },
  sensor: { type: "设备资料", title: "模拟烟雾传感器状态字段说明", description: "说明状态值、心跳时间、模拟读数与质量标记在界面中的展示方式。", source: "设备资料库（模拟）", version: "v1.4", date: "2026-05-20", id: "DEV-SMK-003", note: "页面数值全部为模拟数据，不构成传感器精度、延迟或可靠性结论。" },
  question: { type: "常见问答", title: "AI 建议是否可以直接确认违规？", description: "不可以。AI 只能输出结构化建议，客观事实由代码核验，最终确认、撤销和结案必须由有权人员完成。", source: "平台说明（模拟）", version: "v1.1", date: "2026-08-01", id: "QA-AI-002", note: "页面不会展示模型隐藏思维链，只展示结构化依据、证据引用和可审计的裁决摘要。" },
};

const drawerViews = {
  "goggles-case": `
    <section class="drawer-event-head">
      <span class="status-badge amber">一般案件 · SIMULATED</span>
      <h3>护目镜缺失候选</h3>
      <p>匿名轨迹 T-07 在高风险区域内形成 5 秒涉嫌区间。AI 初审仅提供语义建议，尚未直接定责。</p>
    </section>
    <section class="drawer-section">
      <h3>快速事实</h3>
      <div class="drawer-facts">
        <div><span>事件时间</span><strong class="mono">14:31:43–14:31:48</strong></div>
        <div><span>模拟机位</span><strong class="mono">CAM-LAB-301-A</strong></div>
        <div><span>关键证据</span><strong>3 张时序裁切</strong></div>
        <div><span>当前状态</span><strong>等待人工确认</strong></div>
      </div>
    </section>
    <section class="drawer-section">
      <h3>结构化初审</h3>
      <p>3 张清晰裁切均输出 <code>NOT_WORN</code>。系统同时检查是否存在佩戴反证；客观时长、帧号和证据存在性均由代码核验。</p>
    </section>
    <div class="source-mini">
      <span>知识库引用 · 模拟制度</span>
      <strong>《化学实验室个人防护示例规范》4.2</strong>
      <small>v3.2 · 生效日期 2026-03-01 · KB-PPE-004</small>
    </div>
    <div class="drawer-actions">
      <button class="secondary-button" type="button" data-close-drawer>稍后处理</button>
      <button class="primary-button" type="button" data-open-case>进入案件详情</button>
      <button class="secondary-button full-span" type="button" data-open-agent>交给通知 Agent</button>
    </div>`,
  "sensor-emergency": `
    <section class="drawer-event-head">
      <span class="status-badge" style="color:var(--danger);background:var(--danger-muted);border-color:color-mix(in srgb,var(--danger) 35%,var(--border-default))">紧急 · 模拟传感器</span>
      <h3>温度与烟雾信号联动</h3>
      <p>由模拟温度与烟雾信号直接触发紧急路径。VLM 不参与安全底线，也不能撤销该信号。</p>
    </section>
    <section class="drawer-section">
      <h3>可靠信号路径 · 演示</h3>
      <div class="drawer-facts">
        <div><span>模拟温度 T-02</span><strong class="mono">78.4 °C</strong></div>
        <div><span>模拟烟雾 SMK-03</span><strong class="mono">0.82</strong></div>
        <div><span>触发时间</span><strong class="mono">14:32:14.080</strong></div>
        <div><span>当前响应</span><strong>值班员已接单</strong></div>
      </div>
    </section>
    <section class="drawer-section">
      <h3>处置边界</h3>
      <p>本页面只展示紧急层级与响应流程，不声称模拟信号具备现场认证能力；生产告警、消防或设备联动均未连接。</p>
    </section>
    <div class="drawer-actions">
      <button class="secondary-button" type="button" data-direct-action="接单状态">确认已接单</button>
      <button class="primary-button" type="button" data-placeholder="紧急处置卡">打开处置卡</button>
      <button class="secondary-button full-span" type="button" data-open-agent>查看通知 Agent 对话</button>
    </div>`,
  "soft-reminder": `
    <section class="drawer-event-head">
      <span class="status-badge green">已化解 · L0 预防</span>
      <h3>进入风险区后已补戴</h3>
      <p>现场人员在软提醒后完成佩戴。本事件未建案、未保存匿名轨迹，也不进入问责记录。</p>
    </section>
    <section class="drawer-section">
      <h3>预防优先</h3>
      <p>此路径只在内存中维持短暂冷却，不调用 VLM，不产生持久证据。它用于及时帮助人员纠正风险。</p>
    </section>
    <div class="drawer-actions">
      <button class="secondary-button full-span" type="button" data-close-drawer>知道了</button>
    </div>`,
};

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    '"': "&quot;",
  })[character]);
}

function setTheme(theme) {
  elements.root.dataset.theme = theme;
  const dark = theme === "dark";
  elements.themeToggle.setAttribute("aria-pressed", String(dark));
  elements.themeToggle.setAttribute("aria-label", dark ? "切换到浅色模式" : "切换到深色模式");
  $("meta[name='theme-color']").setAttribute("content", dark ? "#0d1117" : "#f6f8fa");
}

function toggleTheme() {
  setTheme(elements.root.dataset.theme === "dark" ? "light" : "dark");
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.hidden = false;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => {
    elements.toast.hidden = true;
  }, 3400);
}

function tickClock() {
  const now = new Date();
  const time = new Intl.DateTimeFormat("zh-CN", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(now);
  elements.liveClock.textContent = time;
  elements.mainCameraTime.textContent = `${time}.${String(now.getMilliseconds()).padStart(3, "0")}`;
}

function selectCamera(button) {
  $$(".camera-thumb").forEach((item) => item.classList.toggle("active", item === button));
  elements.mainCamera.classList.remove("scene-a", "scene-b", "scene-c");
  const sceneClass = ["scene-a", "scene-b", "scene-c"].find((name) => button.classList.contains(name)) || "scene-a";
  elements.mainCamera.classList.add(sceneClass);
  elements.mainCamera.dataset.camera = button.dataset.camera;
  elements.mainCameraName.textContent = button.dataset.name;
  elements.mainCameraId.textContent = button.dataset.camera;
  showToast(`主画面已切换至 ${button.dataset.name} · 模拟机位`);
}

function openDrawer(eventName) {
  elements.drawerContent.innerHTML = drawerViews[eventName] || drawerViews["goggles-case"];
  elements.drawerScrim.hidden = false;
  window.requestAnimationFrame(() => {
    elements.drawerScrim.classList.add("visible");
    elements.drawer.classList.add("open");
  });
  elements.drawer.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
  $("[data-close-drawer]", elements.drawer)?.focus();
  if (eventName === "sensor-emergency") {
    const mainCameraButton = $(".camera-thumb[data-camera='CAM-LAB-301-A']");
    if (mainCameraButton) selectCamera(mainCameraButton);
    showToast("模拟紧急事件已置顶相关机位，可随时切换其他画面");
  }
}

function closeDrawer({ returnFocus = true } = {}) {
  elements.drawer.classList.remove("open");
  elements.drawerScrim.classList.remove("visible");
  elements.drawer.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
  window.setTimeout(() => {
    elements.drawerScrim.hidden = true;
  }, 190);
  if (returnFocus) $(".event-card.selected")?.focus();
}

function setAgentOpen(open, { returnFocus = true } = {}) {
  elements.agentPanel.classList.toggle("open", open);
  elements.agentPanel.setAttribute("aria-hidden", String(!open));
  elements.agentLauncher.setAttribute("aria-expanded", String(open));
  if (open) {
    elements.agentInput.focus();
    elements.agentMessages.scrollTop = elements.agentMessages.scrollHeight;
  } else if (returnFocus) {
    elements.agentLauncher.focus();
  }
}

function showPage(pageName, { focus = true } = {}) {
  if (elements.drawer.classList.contains("open")) closeDrawer({ returnFocus: false });
  if (elements.agentPanel.classList.contains("open")) setAgentOpen(false, { returnFocus: false });
  elements.pages.forEach((page) => {
    const active = page.dataset.page === pageName;
    page.hidden = !active;
    page.classList.toggle("active", active);
  });

  const navName = pageName === "case" ? "cases" : pageName;
  $$(".rail-link").forEach((item) => {
    const active = item.dataset.nav === navName;
    item.classList.toggle("active", active);
    if (active) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  });

  const activePage = elements.pages.find((page) => page.dataset.page === pageName);
  if (focus) $("h1[tabindex='-1']", activePage)?.focus({ preventScroll: true });
  window.scrollTo(0, 0);
  window.requestAnimationFrame(() => window.scrollTo(0, 0));
}

function openCaseView({ updateHash = true, focus = true } = {}) {
  showPage("case", { focus });
  if (updateHash) window.location.hash = "/case/LC-2026-0810-014";
}

function openMonitorView({ updateHash = true, focus = true } = {}) {
  showPage("monitor", { focus });
  if (updateHash) window.location.hash = "/monitor";
}

function syncRoute({ focus = true } = {}) {
  const hash = window.location.hash || "#/monitor";
  if (hash.startsWith("#/case/")) return showPage("case", { focus });
  const pageName = hash.slice(2).split("/")[0];
  const supported = ["monitor", "cameras", "cases", "map", "knowledge", "settings"];
  showPage(supported.includes(pageName) ? pageName : "monitor", { focus });
}

function showConfirmation(action) {
  elements.confirmActionName.textContent = action;
  if (typeof elements.confirmDialog.showModal === "function") {
    elements.confirmDialog.showModal();
  } else {
    showToast(`预览确认：${action}（未执行真实动作）`);
  }
}

function addAgentMessage(message) {
  const article = document.createElement("article");
  article.className = "agent-message user";
  article.innerHTML = `<small>管理员 · 刚刚</small><p>${escapeHtml(message)}</p>`;
  elements.agentMessages.append(article);

  const response = document.createElement("article");
  response.className = "agent-message system";
  const sensitive = /确认|违规|撤销|结案/.test(message);
  response.innerHTML = sensitive
    ? `<small>Agent 解析结果</small><p>这条回复可能改变案件状态。我已生成明确动作卡，执行前需要二次确认。</p><span>PREVIEW · 未执行</span><button type="button" data-confirm-action="${escapeHtml(message)}">检查并确认</button>`
    : `<small>Agent · 刚刚</small><p>已记录为低风险沟通回复，并保持在模拟通知线程中。</p><span>PREVIEW · 本地记录</span>`;
  elements.agentMessages.append(response);
  elements.agentMessages.scrollTop = elements.agentMessages.scrollHeight;
}

function filterCases() {
  const state = $("#case-status-filter").value;
  const query = $("#case-search").value.trim().toLocaleLowerCase("zh-CN");
  let visible = 0;
  $$(".case-row").forEach((row) => {
    const stateMatch = state === "all" || row.dataset.caseState === state;
    const queryMatch = !query || row.dataset.search.toLocaleLowerCase("zh-CN").includes(query);
    row.hidden = !(stateMatch && queryMatch);
    if (!row.hidden) visible += 1;
  });
  $("#case-empty").hidden = visible !== 0;
}

function showRoom(roomId) {
  const room = roomViews[roomId];
  if (!room) return;
  $$("[data-room]").forEach((button) => button.classList.toggle("active", button.dataset.room === roomId));
  $("#room-detail-title").textContent = room.title;
  $("#room-detail-code").textContent = room.code;
  $("#room-detail-summary").textContent = room.summary;
  const values = $$("dd", $("#room-detail-stats"));
  [room.cameras, room.sensors, room.events, "未接入"].forEach((value, index) => { values[index].textContent = value; });
  values[2].classList.toggle("danger-text", room.events !== "00");
}

function showKnowledge(knowledgeId) {
  const item = knowledgeViews[knowledgeId];
  if (!item) return;
  $$(".knowledge-item").forEach((button) => button.classList.toggle("active", button.dataset.knowledgeId === knowledgeId));
  $("#knowledge-detail-type").textContent = item.type;
  $("#knowledge-detail-title").textContent = item.title;
  $("#knowledge-detail-description").textContent = item.description;
  $("#knowledge-detail-source").textContent = item.source;
  $("#knowledge-detail-version").textContent = item.version;
  $("#knowledge-detail-date").textContent = item.date;
  $("#knowledge-detail-id").textContent = item.id;
  $("#knowledge-detail-note").textContent = item.note;
}

function filterKnowledge() {
  const activeFilter = $("[data-knowledge-filter].active")?.dataset.knowledgeFilter || "all";
  const query = $("#knowledge-search").value.trim().toLocaleLowerCase("zh-CN");
  let visible = 0;
  $$(".knowledge-item").forEach((item) => {
    const typeMatch = activeFilter === "all" || item.dataset.knowledgeType === activeFilter;
    const queryMatch = !query || item.dataset.search.toLocaleLowerCase("zh-CN").includes(query);
    item.hidden = !(typeMatch && queryMatch);
    if (!item.hidden) visible += 1;
  });
  $("#knowledge-empty").hidden = visible !== 0;
}

function togglePreference(button, preference) {
  const active = button.getAttribute("aria-checked") !== "true";
  button.setAttribute("aria-checked", String(active));
  if (preference === "motion") {
    elements.root.dataset.motion = active ? "reduced" : "normal";
    $("b", button).textContent = active ? "已减少" : "标准动画";
  } else {
    elements.root.dataset.density = active ? "compact" : "standard";
    $("b", button).textContent = active ? "紧凑" : "标准";
  }
  showToast(`${preference === "motion" ? "动画偏好" : "信息密度"}已在本地预览中更新`);
}

function bindEvents() {
  elements.themeToggle.addEventListener("click", toggleTheme);

  $$(".camera-thumb").forEach((button) => {
    button.addEventListener("click", () => selectCamera(button));
  });

  $$(".event-card").forEach((button) => {
    button.addEventListener("click", () => {
      $$(".event-card").forEach((item) => item.classList.toggle("selected", item === button));
      openDrawer(button.dataset.event);
    });
  });

  $$(".wall-camera").forEach((button) => {
    button.addEventListener("click", () => showToast(`已选择 ${button.dataset.wallName} · ${button.dataset.wallCamera} · 模拟机位`));
  });

  elements.drawerScrim.addEventListener("click", () => closeDrawer());
  elements.drawer.addEventListener("click", (event) => {
    const target = event.target.closest("button");
    if (!target) return;
    if (target.hasAttribute("data-close-drawer")) closeDrawer();
    if (target.hasAttribute("data-open-case")) openCaseView();
    if (target.hasAttribute("data-open-agent")) {
      closeDrawer({ returnFocus: false });
      setAgentOpen(true);
    }
    if (target.dataset.directAction) showToast(`${target.dataset.directAction}已在预览中模拟记录`);
    if (target.dataset.placeholder) showToast(`${target.dataset.placeholder}将在后续功能预览中展开`);
  });

  $("#case-perspective-button").addEventListener("click", () => openCaseView());
  $("#back-to-monitor").addEventListener("click", () => openMonitorView());

  $("#case-status-filter").addEventListener("change", filterCases);
  $("#case-search").addEventListener("input", filterCases);

  $$("[data-room]").forEach((button) => button.addEventListener("click", () => showRoom(button.dataset.room)));

  $$(".knowledge-item").forEach((button) => button.addEventListener("click", () => showKnowledge(button.dataset.knowledgeId)));
  $$("[data-knowledge-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      $$("[data-knowledge-filter]").forEach((item) => item.classList.toggle("active", item === button));
      filterKnowledge();
    });
  });
  $("#knowledge-search").addEventListener("input", filterKnowledge);

  $("#settings-theme-toggle").addEventListener("click", toggleTheme);
  $("#motion-toggle").addEventListener("click", (event) => togglePreference(event.currentTarget, "motion"));
  $("#density-toggle").addEventListener("click", (event) => togglePreference(event.currentTarget, "density"));

  $$('[data-placeholder]').forEach((button) => {
    button.addEventListener("click", () => showToast(`${button.dataset.placeholder}将在风格确认后继续完善`));
  });

  elements.agentLauncher.addEventListener("click", () => setAgentOpen(!elements.agentPanel.classList.contains("open")));
  $("#close-agent").addEventListener("click", () => setAgentOpen(false));
  elements.agentForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const message = elements.agentInput.value.trim();
    if (!message) return;
    addAgentMessage(message);
    elements.agentInput.value = "";
  });

  document.addEventListener("click", (event) => {
    const target = event.target.closest("[data-confirm-action]");
    if (target) showConfirmation(target.dataset.confirmAction);
  });

  elements.confirmDialog.addEventListener("close", () => {
    if (elements.confirmDialog.returnValue === "confirm") {
      showToast(`${elements.confirmActionName.textContent}：模拟确认完成，未连接任何生产动作`);
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    if (elements.drawer.classList.contains("open")) closeDrawer();
    else if (elements.agentPanel.classList.contains("open")) setAgentOpen(false);
  });

  window.addEventListener("hashchange", syncRoute);
}

function boot() {
  if ("scrollRestoration" in window.history) window.history.scrollRestoration = "manual";
  const prefersDark = window.matchMedia?.("(prefers-color-scheme: dark)").matches;
  const prefersReducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  setTheme(prefersDark ? "dark" : "light");
  if (prefersReducedMotion) {
    elements.root.dataset.motion = "reduced";
    $("#motion-toggle").setAttribute("aria-checked", "true");
    $("#motion-toggle b").textContent = "跟随系统";
  }
  bindEvents();
  tickClock();
  window.setInterval(tickClock, 250);
  syncRoute({ focus: false });
  if (!window.location.hash) window.location.hash = "/monitor";
}

boot();

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
  monitorView: $("#monitor-view"),
  caseView: $("#case-view"),
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

function setAgentOpen(open) {
  elements.agentPanel.classList.toggle("open", open);
  elements.agentPanel.setAttribute("aria-hidden", String(!open));
  elements.agentLauncher.setAttribute("aria-expanded", String(open));
  if (open) {
    elements.agentInput.focus();
    elements.agentMessages.scrollTop = elements.agentMessages.scrollHeight;
  } else {
    elements.agentLauncher.focus();
  }
}

function openCaseView({ updateHash = true, focus = true } = {}) {
  closeDrawer({ returnFocus: false });
  setAgentOpen(false);
  elements.monitorView.classList.remove("active");
  elements.monitorView.hidden = true;
  elements.caseView.hidden = false;
  elements.caseView.classList.add("active");
  $$(".rail-link").forEach((item) => item.classList.remove("active"));
  if (updateHash) window.location.hash = "/case/LC-2026-0810-014";
  if (focus) $("#case-title").focus({ preventScroll: true });
  window.scrollTo(0, 0);
  window.requestAnimationFrame(() => window.scrollTo(0, 0));
}

function openMonitorView({ updateHash = true, focus = true } = {}) {
  elements.caseView.classList.remove("active");
  elements.caseView.hidden = true;
  elements.monitorView.hidden = false;
  elements.monitorView.classList.add("active");
  $("[data-nav='monitor']").classList.add("active");
  if (updateHash) window.location.hash = "/monitor";
  if (focus) $("#monitor-title").focus({ preventScroll: true });
  window.scrollTo(0, 0);
  window.requestAnimationFrame(() => window.scrollTo(0, 0));
}

function syncRoute({ focus = true } = {}) {
  if (window.location.hash.startsWith("#/case/")) {
    openCaseView({ updateHash: false, focus });
  } else {
    openMonitorView({ updateHash: false, focus });
  }
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
  setTheme(prefersDark ? "dark" : "light");
  bindEvents();
  tickClock();
  window.setInterval(tickClock, 250);
  syncRoute({ focus: false });
  if (!window.location.hash) window.location.hash = "/monitor";
}

boot();

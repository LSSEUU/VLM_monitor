"use strict";

const app = document.getElementById("app");
const TOKEN_KEY = "labcourt.platform.token";
const ROLE_LABELS = {LEADER:"校级领导",SAFETY_OFFICER:"安全负责人",STUDENT:"学生",OPERATIONS:"运维人员"};
const STATUS_LABELS = {PENDING_VERIFICATION:"等待人工核实",CONFIRMED:"已确认",REJECTED:"已排除",EVIDENCE_REQUESTED:"待补充证据",RESOLVED:"已结案",APPEALED:"申诉处理中",APPEAL_RESOLVED:"申诉已处理",DELIVERED:"已送达",RESPONDED:"已回复",ACKNOWLEDGED:"已确认"};
const STAGE_LABELS = {VIDEO:"录像",PERCEPTION:"视觉感知",EVIDENCE:"证据裁剪",SCREENING:"结构化初审",CASE:"规则建案",NOTIFICATION:"消息通知"};
const NAV = [["/app/monitor","监控"],["/app/cases","案件"],["/app/map","地图"],["/app/notifications","通知"],["/app/knowledge","知识库"],["/app/agent","Agent"],["/app/profile","我的"],["/app/settings","设置"]];
const state = {
  token:sessionStorage.getItem(TOKEN_KEY),session:null,cases:[],notifications:[],conversations:[],projection:null,
  cameras:[],reservations:[],run:null,readiness:null,feishu:null,feishuRuntime:null,feishuRoute:null,users:null,rules:null,knowledgeCatalog:null,
  knowledgeAnswer:null,knowledgeDocument:null,knowledgeSearch:"",agentMessages:[],action:null,agentTyping:false,loginRole:"SAFETY_OFFICER",
  videoUrl:null,videoPromise:null,videoPositions:new Map(),evidenceUrls:[],pollTimer:null,
  pollFailures:0,pollInFlight:false,toastTimer:null,routeController:null,routeSequence:0,
  shellMounted:false,currentRoute:"",casesFilter:"ALL",knowledgeFilter:"ALL",knowledgeSelected:null,
  settingsSection:"messages",mapFloor:null,mapLocation:null,confirmationOpen:false,navOpen:false,scrollSaveFrame:0,
  lastRunAnnouncement:"",caseDetail:null,settingsPanels:null,evidenceWorkspace:null,conversation:null,confirmationTrigger:null,
};

const esc = value => String(value ?? "").replace(/[&<>'"]/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[char]));
const short = value => value ? `${String(value).slice(0,8)}…${String(value).slice(-6)}` : "—";
const label = value => STATUS_LABELS[value] || value || "—";
const role = () => state.session?.authority?.role;
const caseAuthority = item => item?.audit_event?.case_authority;
const caseCommand = item => caseAuthority(item)?.create_command;
const notificationAuthority = item => item?.audit_event?.notification_authority;
const notificationPlan = item => notificationAuthority(item)?.plan;
const visible = () => state.projection?.visible_projection;
const sources = () => visible()?.sources || [];
const locations = () => visible()?.topology_receipt?.topology?.locations || [];
const terminalCase = value => ["REJECTED","RESOLVED","APPEAL_RESOLVED"].includes(value);
const isEmergency = () => state.run?.scenario_kind === "SMOKE_TEMPERATURE_EMERGENCY" && !terminalCase(state.run?.case_status);

async function api(path, options={}) {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", options.binary ? "*/*" : "application/json");
  if (state.token) headers.set("Authorization", `Bearer ${state.token}`);
  if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const response = await fetch(path,{...options,headers,body:options.body && typeof options.body !== "string" ? JSON.stringify(options.body) : options.body});
  if (response.status === 401) {
    logout(false);
    throw new Error("登录状态已失效，请重新选择角色");
  }
  if (!response.ok) {
    let reason = `HTTP ${response.status}`;
    try { const failure=await response.json(); reason=failure.reason_code||failure.reason||reason; } catch (_) {}
    throw new Error(reason);
  }
  if (options.binary) return response.blob();
  return response.status === 204 ? null : response.json();
}

async function optional(path, fallback, options={}) {
  try { return await api(path,options); } catch (error) {
    if (["FORBIDDEN","RESOURCE_NOT_FOUND"].includes(error.message)) return fallback;
    throw error;
  }
}

function clearObjectUrls() {
  if (state.videoUrl) URL.revokeObjectURL(state.videoUrl);
  state.videoUrl = null;
  state.videoPromise = null;
  state.evidenceUrls.forEach(URL.revokeObjectURL);
  state.evidenceUrls = [];
}

function logout(navigate=true) {
  sessionStorage.removeItem(TOKEN_KEY); state.token=null; state.session=null; clearObjectUrls();
  if (state.pollTimer) clearTimeout(state.pollTimer);
  state.shellMounted=false;
  if (navigate) navigateTo("/login",{replace:true});
}

function toast(message, type="success") {
  document.querySelector(".toast")?.remove();
  const node=document.createElement("div"); node.className=`toast ${type}`; node.setAttribute("role",type === "error" ? "alert" : "status"); node.textContent=message; document.body.append(node);
  clearTimeout(state.toastTimer); state.toastTimer=setTimeout(()=>node.remove(),4500);
}

function publicRibbon() {
  return `<div class="ribbon"><span>LABCOURT · CAMPUS OPERATIONS</span><span>OFFLINE LOCAL DEMO · PRODUCTION READY: FALSE</span></div>`;
}

function renderHome() {
  const entryHref=state.token?"/app/monitor":"/login";
  const entryLabel=state.token?"返回安全运营平台":"进入平台";
  app.innerHTML=`<header class="landing-head"><div class="landing-wrap landing-head__in"><a class="landing-brand" href="/">LabCourt <small>校园实验室安全</small></a><nav aria-label="首页导航"><a href="#problem">现状</a><a href="#principles">原则</a><a href="#workflow">闭环</a><a href="#ethics">伦理</a></nav><a class="landing-cta" href="${entryHref}">${entryLabel} →</a></div></header>
  <main id="main-content" class="landing">
    <section class="landing-hero">
      <div class="landing-hero__media" data-parallax><video src="/api/m8/demo/public-media/recorded-video" autoplay muted loop playsinline preload="metadata"></video><div class="landing-grid" aria-hidden="true"></div></div>
      <span class="recorded-tag"><i></i>SIMULATED · RECORDED VIDEO</span>
      <div class="landing-hud" aria-hidden="true"><span></span><span></span><span></span><span></span><b>CAMERA-RECORDED-DEMO-01<br>NO VISUAL IDENTITY</b></div>
      <div class="landing-wrap landing-hero__content"><p class="landing-eyebrow"><b>LabCourt</b> · 海南大学 · 信通学院 · 校园实验室安全</p><h1>实验室的每一秒，<br>都值得被认真对待。</h1><p>录像与模拟传感器进入同一条可审计流程：真实模型识别、结构化取证、规则建案与人在环处置。不做人脸识别，AI 不自动定责。</p><div class="landing-actions"><a class="landing-button primary" href="${entryHref}">${state.token?"返回安全运营平台":"选择演示角色"} →</a><a class="landing-button" href="#workflow">了解处理闭环</a></div></div>
    </section>
    <section class="landing-block" id="problem"><div class="landing-wrap"><p class="landing-eyebrow reveal"><b>现状</b> · WHY</p><h2 class="reveal">传统监控只录像，不“看懂”。</h2><p class="landing-lead reveal">人防有盲区、事后追溯难、来源说不清。安全运营需要的不只是画面，而是一条能解释、能复核、能回应的证据链。</p><div class="landing-three"><article class="landing-rule reveal"><i>01</i><h3>盲区</h3><p>值班人员无法持续覆盖每一路录像和每一类传感器变化。</p></article><article class="landing-rule reveal"><i>02</i><h3>滞后</h3><p>只在事后翻看录像，无法形成即时、可核验的处置入口。</p></article><article class="landing-rule reveal"><i>03</i><h3>难说清</h3><p>机器发现与人工决定之间，需要保留结构化证据、版本和回复。</p></article></div></div></section>
    <section class="landing-block landing-paper" id="principles"><div class="landing-wrap"><p class="landing-eyebrow reveal"><b>我们的做法</b> · PRINCIPLES</p><h2 class="reveal">AI 看见，人做决定。</h2><p class="landing-lead reveal">模型只生成弱标签和证据引用；规则守住边界，安全负责人完成核实，学生可以说明或申诉。</p><div class="landing-three"><article class="landing-card reveal"><i>01 / 识别</i><h3>真实模型，来源可见</h3><p>本地 Grounding DINO、ViTPose 与 ByteTrack 处理录像；Qwen3-VL 生成严格结构化初审。</p></article><article class="landing-card reveal"><i>02 / 伦理</i><h3>不识别人，不自动定责</h3><p>预约关联不是视觉身份识别，不做人脸识别或跨摄像头重识别。</p></article><article class="landing-card reveal"><i>03 / 处置</i><h3>确认、回应、申诉</h3><p>案件、通知、学生回复和结果确认都由服务端状态机留痕。</p></article></div></div></section>
    <section class="landing-block" id="workflow"><div class="landing-wrap"><p class="landing-eyebrow reveal"><b>功能</b> · WORKFLOW</p><h2 class="reveal">从看见到归档，一条闭环。</h2><p class="landing-lead reveal">同一套设计语言承载录像、感知、证据、初审、案件与通知六个真实阶段。</p><div class="landing-slices">
      <article class="landing-slice reveal"><div class="landing-screen"><video src="/api/m8/demo/public-media/recorded-video" autoplay muted loop playsinline preload="none"></video><span>SIMULATED · RECORDED VIDEO</span><div class="screen-reticle" aria-hidden="true"></div></div><h3>录像与视觉感知</h3><p>播放时钟映射真实帧序号；没有产物就显示“尚未生成”，不伪造检测框和置信度。</p></article>
      <article class="landing-slice reveal"><div class="landing-screen paper-screen"><div class="mini-stage"><b>VIDEO</b><b>PERCEPTION</b><b>EVIDENCE</b><b>SCREENING</b><b>CASE</b><b>NOTIFICATION</b></div></div><h3>六阶段产物链</h3><p>每个状态来自真实 job 和持久化 authority；失败保留阶段与 typed failure。</p></article>
      <article class="landing-slice reveal"><div class="landing-screen paper-screen"><div class="mini-flow"><span class="done">自动建案</span><i></i><span class="done">人工核实</span><i></i><span>学生回应</span><i></i><span>归档</span></div></div><h3>案件与申诉</h3><p>机器输出不直接形成处分；学生说明、申诉与安全负责人决定保留原通知。</p></article>
      <article class="landing-slice reveal"><div class="landing-screen paper-screen"><div class="mini-devices"><span><b>VIDEO</b>录像模拟机位</span><span><b>SMOKE</b>模拟烟雾</span><span><b>TEMP</b>模拟温度</span><span><b>RULE</b>联动建案</span></div></div><h3>设备与传感器联动</h3><p>温度和烟雾信号经 typed 持久化与规则生成紧急案件，不通过页面属性伪造。</p></article>
    </div></div></section>
    <section class="landing-ethics" id="ethics"><div class="landing-wrap"><p class="landing-eyebrow reveal"><b>伦理立场</b> · BOUNDARIES</p><h2 class="reveal">AI 提议，代码守门，<br>人，<em>盖章</em>。</h2><p class="landing-lead reveal">技术可以辅助发现风险，但不能替人完成责任判断。每一步都必须能回到原始来源。</p><div class="landing-four"><article class="reveal"><i>01</i><h3>不做人脸识别</h3><p>预约关联，非视觉身份识别。</p></article><article class="reveal"><i>02</i><h3>弱标签</h3><p>模型输出不是事实或处分依据。</p></article><article class="reveal"><i>03</i><h3>可说明与申诉</h3><p>回复和结果各自生成新 authority。</p></article><article class="reveal"><i>04</i><h3>人在环</h3><p>操作卡和状态变更都需确认。</p></article></div><div class="landing-stamp reveal" aria-hidden="true">人工<br>确认</div></div></section>
    <section class="landing-block landing-proof"><div class="landing-wrap"><p class="landing-eyebrow reveal"><b>能力证明</b> · API-BACKED</p><h2 class="reveal">不展示未经测量的数字。</h2><div class="landing-proof__grid"><article class="reveal"><i>输入</i><strong>录像 · 传感器</strong><p>来源类型由正式适配器定义</p></article><article class="reveal"><i>处理</i><strong>六阶段</strong><p>状态来自真实运行产物</p></article><article class="reveal"><i>决定</i><strong>人工确认</strong><p>机器不直接执行处分</p></article></div></div></section>
    <section class="landing-final"><div class="landing-wrap reveal"><h2>走进控制台。</h2><p>切换四种角色，运行真实识别或明确标记的演示回退，亲自完成一条安全闭环。</p><div class="landing-actions"><a class="landing-button primary" href="${entryHref}">${entryLabel} →</a><a class="landing-button" href="#ethics">查看边界</a></div></div></section>
  </main><footer class="landing-footer"><div class="landing-wrap"><b>LabCourt <small>校园实验室安全</small></b><span>海南大学 · 信息与通信工程学院</span><span>PERSONAL DEMO ONLY · PRODUCTION READY: FALSE</span></div></footer>`;
  initLandingMotion();
}

function renderLogin() {
  const roles=[
    ["LEADER","校级领导","查看全局态势、重大事件与处置结果，不参与审批。"],
    ["SAFETY_OFFICER","安全负责人","核实案件、处理申诉并发送案件结果通知。"],
    ["STUDENT","学生","仅查看本人预约关联的案件和通知，并提交说明或申诉。"],
    ["OPERATIONS","运维人员","查看设备来源、触发两个演示场景并执行一键复位。"]
  ];
  const selected=roles.find(item=>item[0]===state.loginRole)||roles[1];
  app.innerHTML=`<div class="login-stage" data-login-stage aria-hidden="true"><video src="/api/m8/demo/public-media/recorded-video" autoplay muted loop playsinline></video><div class="login-reticle one"><i></i><i></i><i></i><i></i><span>RECORDED SOURCE</span></div><div class="login-reticle two"><i></i><i></i><i></i><i></i><span>NO VISUAL IDENTITY</span></div></div><div class="login-hud" aria-hidden="true"><i></i><i></i><i></i><i></i><span class="login-scan"></span></div><span class="login-cam"><i></i>CAMERA-RECORDED-DEMO-01 · SIMULATED</span><span class="login-time">REC <b data-timecode>00:00</b></span>
  <main id="main-content" class="login-shell"><section class="login-card" aria-labelledby="login-title"><a class="login-brand" href="/">LabCourt <small>校园实验室安全</small></a><p class="login-eyebrow">海南大学 · 信息与通信工程学院</p><h1 id="login-title">安全运营统一入口</h1><form class="login-form" data-login-form><div class="login-fields"><label class="login-field"><span>工号 / 校园邮箱</span><input id="login-account" name="account" type="text" autocomplete="username" placeholder="请输入工号或邮箱"></label><label class="login-field"><span>密码</span><input id="login-password" name="password" type="password" autocomplete="current-password" placeholder="请输入密码"></label></div><fieldset class="login-role-field"><legend>进入身份</legend><div class="login-roles" role="group" aria-label="选择平台角色">${roles.map(([key,title])=>`<button type="button" data-role-select="${key}" class="${key===selected[0]?"active":""}" aria-pressed="${key===selected[0]}">${title.replace("校级","").replace("人员","")}</button>`).join("")}</div></fieldset><div class="login-authority" aria-live="polite"><span data-login-role-code>${esc(selected[0])}</span><strong data-login-role-title>${esc(selected[1])}</strong><p data-login-role-copy>${esc(selected[2])}</p></div><button class="login-submit" type="submit" data-login="${selected[0]}"><span data-login-button-copy>以${esc(selected[1])}身份进入</span><i>→</i></button></form><p class="login-note">校内安全运营 · 当前身份权限由服务端 authority 校验<br>外发演示消息保留 FAKE DELIVERY 来源标识</p></section></main><div class="login-flash" aria-hidden="true"></div><div class="login-stamp" aria-hidden="true"><span>已授权<i>AUTHORIZED</i></span></div>`;
  initLoginMotion();
}

function patchLoginRole(nextRole) {
  const roles={LEADER:["校级领导","查看全局态势、重大事件与处置结果，不参与审批。"],SAFETY_OFFICER:["安全负责人","核实案件、处理申诉并发送案件结果通知。"],STUDENT:["学生","仅查看本人预约关联的案件和通知，并提交说明或申诉。"],OPERATIONS:["运维人员","查看设备来源、触发两个演示场景并执行一键复位。"]};
  const selected=roles[nextRole];if(!selected)return false;state.loginRole=nextRole;
  document.querySelectorAll("[data-role-select]").forEach(node=>{const active=node.dataset.roleSelect===nextRole;node.classList.toggle("active",active);node.setAttribute("aria-pressed",String(active));});
  const code=document.querySelector("[data-login-role-code]"),title=document.querySelector("[data-login-role-title]"),copy=document.querySelector("[data-login-role-copy]"),button=document.querySelector("[data-login]");
  if(code)code.textContent=nextRole;if(title)title.textContent=selected[0];if(copy)copy.textContent=selected[1];if(button){button.dataset.login=nextRole;button.querySelector("[data-login-button-copy]").textContent=`以${selected[0]}身份进入`;}
  return true;
}

function initLandingMotion(){
  const reduced=matchMedia("(prefers-reduced-motion: reduce)").matches;
  const nodes=document.querySelectorAll(".reveal");
  if(reduced||!("IntersectionObserver" in window)){nodes.forEach(node=>node.classList.add("in"));return;}
  const observer=new IntersectionObserver(entries=>entries.forEach(entry=>{if(entry.isIntersecting){entry.target.classList.add("in");observer.unobserve(entry.target);}}),{threshold:.12});
  nodes.forEach((node,index)=>{node.style.setProperty("--reveal-delay",`${Math.min(index%4,3)*45}ms`);observer.observe(node);});
  const layer=document.querySelector("[data-parallax]");let ticking=false;
  const update=()=>{if(layer&&scrollY<innerHeight*1.2)layer.style.transform=`translate3d(0,${Math.min(scrollY*.16,96)}px,0)`;ticking=false;};
  addEventListener("scroll",()=>{if(!ticking){requestAnimationFrame(update);ticking=true;}},{passive:true});
}

function initLoginMotion(){
  const video=document.querySelector(".login-stage video"),time=document.querySelector("[data-timecode]");
  video?.addEventListener("timeupdate",()=>{const seconds=Math.floor(video.currentTime);if(time)time.textContent=`${String(Math.floor(seconds/60)).padStart(2,"0")}:${String(seconds%60).padStart(2,"0")}`;});
  if(matchMedia("(prefers-reduced-motion: reduce)").matches)return;
  const stage=document.querySelector("[data-login-stage]");
  addEventListener("pointermove",event=>{if(stage)stage.style.transform=`translate3d(${((event.clientX/innerWidth)-.5)*-12}px,${((event.clientY/innerHeight)-.5)*-12}px,0)`;},{passive:true});
}

function currentNav(path) { return NAV.find(([href]) => path === href || (["/app/cases","/app/notifications"].includes(href) && path.startsWith(`${href}/`)))?.[0]; }
function runStripMarkup() {
  const run=state.run;
  if(!run)return `<div id="global-run-strip" class="global-run-strip" hidden></div>`;
  const active=run.stages.find(item=>item.state==="RUNNING"||item.state==="FAILED")||run.stages.at(-1);
  const perception=run.stages.find(item=>item.stage==="PERCEPTION");
  const frame=perception?.total_units?`${perception.completed_units} / ${perception.total_units} FRAME`:"AUTHORITY STAGES";
  const runClass=run.state==="SUCCEEDED"?"complete":run.state.toLowerCase();
  const failure=run.state==="FAILED"?` · ${esc(run.failure_code||"TYPED FAILURE")}`:"";
  return `<div id="global-run-strip" class="global-run-strip is-${runClass}"><div class="run-strip__state"><span class="run-strip__summary" data-run-summary>${run.state==="RUNNING"?"识别运行中":run.state==="FAILED"?"识别失败":"识别已完成"} · ${esc(STAGE_LABELS[active?.stage]||active?.stage||"等待")}${failure}</span></div><div class="run-strip__rail" role="list" aria-label="识别六阶段">${run.stages.map(item=>`<span role="listitem" class="run-strip__stage ${item.state==="RUNNING"?"is-active":item.state==="COMPLETE"?"is-complete":item.state==="FAILED"?"is-failed":""}" data-run-stage="${esc(item.stage)}"><i aria-hidden="true"></i><b>${esc(STAGE_LABELS[item.stage]||item.stage)}</b></span>`).join("")}</div><div class="run-strip__meta"><strong data-run-frame>${esc(frame)}</strong><span data-run-mode>${esc(run.recognition_mode||run.scenario_kind)}</span><a data-run-case href="${run.case_id?`/app/cases/${esc(run.case_id)}`:"/app/cases"}" ${run.case_id?"":"hidden"}>案件 →</a></div></div>`;
}

function alarmMarkup(){return isEmergency()?`<div class="alarm-banner" role="alert"><div><p class="eyebrow">EMERGENCY · SIMULATED SENSOR</p><strong>实验室 301 烟雾与高温信号联动</strong></div><a href="${state.run?.case_id?`/app/cases/${state.run.case_id}`:"/app/cases"}">查看案件 →</a></div>`:"";}

function ensureShell() {
  if(state.shellMounted&&document.getElementById("route-view"))return;
  const active=currentNav(location.pathname);
  app.innerHTML=`<div class="app-shell shell-frame">${publicRibbon()}<header class="shell-head"><div class="head-row"><a class="brand" href="/" aria-label="返回 LabCourt 产品介绍首页">LabCourt<small>校园安全运营平台</small></a><button class="icon-button nav-toggle" type="button" data-action="nav-toggle" aria-expanded="false" aria-controls="primary-nav">菜单</button><nav id="primary-nav" class="nav" aria-label="主导航">${NAV.map(([href,text])=>`<a href="${href}" ${active===href?'aria-current="page"':""}>${text}</a>`).join("")}</nav><div class="head-actions"><span class="role-chip"><span>${esc(ROLE_LABELS[role()]||role())}</span></span><button class="icon-button" type="button" data-action="logout" aria-label="退出当前角色">退出</button></div></div></header><div id="alarm-host">${alarmMarkup()}</div><div id="run-strip-host">${runStripMarkup()}</div><main id="main-content" class="page"><div id="route-view" class="route-view"></div></main><p class="route-live-region sr-only" aria-live="polite"></p></div>`;
  state.shellMounted=true;
}

function patchShell() {
  if(!state.shellMounted)return;
  const active=currentNav(location.pathname);
  document.querySelectorAll(".nav a").forEach(link=>{const current=new URL(link.href).pathname===active;if(current)link.setAttribute("aria-current","page");else link.removeAttribute("aria-current");});
  const alarm=document.getElementById("alarm-host");if(alarm){const markup=alarmMarkup();if(alarm.innerHTML!==markup)alarm.innerHTML=markup;}
  patchRunStrip();
}

function patchRunStrip() {
  const host=document.getElementById("run-strip-host");if(!host)return;
  let strip=document.getElementById("global-run-strip");
  if(!state.run){if(strip)strip.hidden=true;return;}
  if(!strip?.querySelector("[data-run-summary]")){host.innerHTML=runStripMarkup();strip=document.getElementById("global-run-strip");}
  if(!strip)return;
  const run=state.run,active=run.stages.find(item=>item.state==="RUNNING"||item.state==="FAILED")||run.stages.at(-1);
  const perception=run.stages.find(item=>item.stage==="PERCEPTION");
  const frame=perception?.total_units?`${perception.completed_units} / ${perception.total_units} FRAME`:"AUTHORITY STAGES";
  const runClass=run.state==="SUCCEEDED"?"complete":run.state.toLowerCase();
  strip.hidden=false;strip.classList.remove("is-running","is-failed","is-complete");strip.classList.add(`is-${runClass}`);
  strip.querySelector("[data-run-summary]").textContent=`${run.state==="RUNNING"?"识别运行中":run.state==="FAILED"?"识别失败":"识别已完成"} · ${STAGE_LABELS[active?.stage]||active?.stage||"等待"}${run.state==="FAILED"?` · ${run.failure_code||"TYPED FAILURE"}`:""}`;
  strip.querySelector("[data-run-frame]").textContent=frame;
  strip.querySelector("[data-run-mode]").textContent=run.recognition_mode||run.scenario_kind;
  strip.querySelectorAll("[data-run-stage]").forEach(node=>{const item=run.stages.find(value=>value.stage===node.dataset.runStage);node.classList.toggle("is-active",item?.state==="RUNNING");node.classList.toggle("is-complete",item?.state==="COMPLETE");node.classList.toggle("is-failed",item?.state==="FAILED");});
  const caseLink=strip.querySelector("[data-run-case]");if(caseLink){caseLink.hidden=!run.case_id;caseLink.href=run.case_id?`/app/cases/${run.case_id}`:"/app/cases";}
  const semanticKey=`${run.run_id}:${run.state}:${active?.stage||"NONE"}`;
  if(semanticKey!==state.lastRunAnnouncement){state.lastRunAnnouncement=semanticKey;const live=document.querySelector(".route-live-region");if(live)live.textContent=strip.querySelector("[data-run-summary]").textContent;}
}

function setRouteContent(content,{mount,announcement}={}) {
  ensureShell();const host=document.getElementById("route-view");if(!host)return;
  const commit=()=>{host.innerHTML=content;host.classList.remove("is-leaving");host.classList.add("is-entering");mount?.();requestAnimationFrame(()=>host.classList.remove("is-entering"));};
  if(document.startViewTransition&&!matchMedia("(prefers-reduced-motion: reduce)").matches)document.startViewTransition(commit);else commit();
  patchShell();document.querySelector(".route-live-region").textContent=announcement||document.querySelector(".page-head h1")?.textContent||"页面已更新";
}

function shell(content) { return content; }
function loadingPage(){setRouteContent(`<div class="page-head"><div><p class="eyebrow">LOADING</p><h1>正在读取运营投影</h1></div></div><div class="grid three"><div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div></div>`);}
function errorPage(error){setRouteContent(`<div class="page-head"><div><p class="eyebrow">TYPED FAILURE</p><h1>页面暂时无法读取</h1></div></div><div class="error-state"><strong>${esc(error.message)}</strong><p>状态未被伪装为成功。可检查本地服务后重试。</p><button class="button" type="button" data-action="reload">重新读取</button></div>`);}

async function loadCore(signal) {
  const options=signal?{signal}:{};state.session=await api("/api/m8/session",options);
  const [cases,notifications,conversations,projection,cameras,reservations,run,readiness,feishu,feishuRuntime,feishuRoute]=await Promise.all([
    optional("/api/m8/cases",[],options),optional("/api/m8/notifications",[],options),optional("/api/m8/notification-conversations",[],options),optional("/api/m8/campuses/campus-demo/operations-projection",null,options),optional("/api/m8/cameras",[],options),optional("/api/m8/reservations",[],options),optional("/api/m8/demo/scenario-runs/current",null,options),optional("/api/m8/demo/model-readiness",null,options),optional("/api/m8/integrations/feishu/status",null,options),optional("/api/m8/integrations/feishu/runtime-status",null,options),optional("/api/m8/integrations/feishu/duty-route",null,options)
  ]);
  Object.assign(state,{cases,notifications,conversations,projection,cameras,reservations,run,readiness,feishu,feishuRuntime,feishuRoute});
}

function metric(value,name,note) { return `<div class="metric"><span>${esc(name)}</span><strong>${esc(value)}</strong><small>${esc(note)}</small></div>`; }
function pageHead(kicker,title,deck,actions="") { return `<header class="page-head"><div><p class="eyebrow">${kicker}</p><h1>${title}</h1><p class="deck">${deck}</p></div>${actions?`<div class="page-head__actions">${actions}</div>`:""}</header>`; }
function empty(title,copy) { return `<div class="empty"><strong>${title}</strong><p>${copy}</p></div>`; }

function sourceValue(item) {
  const sample=item.latest_sample_receipt?.sample;
  if (!sample) return item.source.source_kind === "CAMERA" ? "已绑定" : "待机";
  if (item.source.sensor_type === "TEMPERATURE") return `${Number(sample.value)/1000} °C`;
  if (item.source.sensor_type === "SMOKE") return sample.value ? "检出烟雾" : "未检出";
  return String(sample.value);
}

function runFailureExplanation(run=state.run) {
  if(!run||run.state!=="FAILED")return "";
  if(run.failure_code==="SCREENING_PROVIDER_UNAVAILABLE"||(run.failure_code==="ValueError"&&run.recognition_mode==="FULL_MODEL"&&!run.screening_decision))return "本地视觉识别和证据生成已完成，云端 Qwen 初审未能完成，因此没有建案。请重新运行真实模式；平台不会自动切换演示结果。";
  if(run.failure_code==="SCREENING_RESPONSE_INVALID")return "本地识别和证据已完成，但 Qwen 返回内容未通过严格结构校验，因此没有建案。";
  if(run.failure_code==="SCREENING_RESPONSE_BUDGET_EXCEEDED")return "本地识别和证据已完成，但 Qwen 响应超出受控预算，因此没有建案。";
  if(run.failure_code==="SCREENING_EVIDENCE_CHANGED")return "初审期间证据 authority 已变化，平台已停止本次建案。";
  if(run.failure_code==="SCREENING_PROJECTION_INVALID")return "本地识别和证据已完成，但初审结果投影不完整，因此没有进入规则建案。";
  return `识别在 ${STAGE_LABELS[run.stages?.find(item=>item.state==="FAILED")?.stage]||"当前阶段"}结束；失败代码 ${run.failure_code}。状态未伪装为成功。`;
}

function monitorCandidatesMarkup() {
  const active=state.cases.filter(item=>!terminalCase(item.status));
  return active.length?active.slice(0,4).map(item=>`<a class="candidate-card" href="/app/cases/${item.case_id}"><div><h3>${caseTitle(item)}</h3><p>${esc(caseAuthority(item)?.location_id)} · ${short(item.case_id)}</p></div><span class="candidate-card__state">${esc(label(item.status))}<br>查看卷宗 →</span></a>`).join(""):empty("暂无候选事件","标准现场没有活动案件；运行场景后会在这里出现入口。");
}

function monitorDevicesMarkup() {
  return sources().map(item=>`<article class="device ${item.latest_sample_receipt?.sample?.value===true||item.source.sensor_type==="TEMPERATURE"&&Number(item.latest_sample_receipt?.sample?.value)>60000?"alert":""}"><div class="device-head"><h3>${esc(item.source.device_id)}</h3><span class="badge">${item.source.source_kind==="SENSOR"?"SIMULATED SENSOR":"RECORDED"}</span></div><strong>${esc(sourceValue(item))}</strong><small>${esc(item.source.sensor_type||item.source.mode)} · ${esc(item.observation_state)}</small></article>`).join("")||empty("设备不可见","当前角色不具备设备健康读取能力。");
}

function monitorFailureMarkup() {
  const run=state.run;if(run?.state!=="FAILED")return "";
  const actions=role()==="OPERATIONS"&&run.recognition_mode==="FULL_MODEL"?`<div class="form-actions"><button class="button" type="button" data-scenario="PPE_GOGGLES_MISSING" data-mode="FULL_MODEL">重新运行真实模式</button><button class="button quiet" type="button" data-scenario="PPE_GOGGLES_MISSING" data-mode="DEMO_FIXTURE" data-retry="${esc(run.run_id)}">以演示模式重试</button></div>`:"";
  return `<div class="run-failure-card"><p class="help risk">${esc(runFailureExplanation(run))}</p><small>原始响应：${run.raw_response_ref?esc(run.raw_response_ref):"未生成"}</small>${actions}</div>`;
}

function stageList() {
  const stages=state.run?.stages || Object.keys(STAGE_LABELS).map(stage=>({stage,state:"PENDING",summary:"尚未生成"}));
  return `<div class="stage-list">${stages.map((item,i)=>`<div class="stage ${item.state.toLowerCase()}"><span class="stage-mark">${item.state==="COMPLETE"?"✓":i+1}</span><span class="stage-name">${STAGE_LABELS[item.stage]}</span><span class="stage-summary">${esc(item.summary)}</span></div>`).join("")}</div>`;
}

function renderMonitor() {
  const ops=role()==="OPERATIONS"; const active=state.cases.filter(item=>!terminalCase(item.status));
  const profile=state.run?.video_profile; const totalFrames=profile?.frame_count||"—";
  const videoMeta=profile?`${profile.fps_num/profile.fps_den} FPS · ${profile.width}×${profile.height} · ${(profile.duration_millis/1000).toFixed(1)} 秒 · ${profile.timing_authority}`:"录像帧信息将在 Pilot manifest 生成后显示";
  const realReady=state.readiness?.full_model_ready===true;
  const actions=ops?`<button class="button primary" type="button" data-scenario="PPE_GOGGLES_MISSING" data-mode="FULL_MODEL" ${state.run?.state==="RUNNING"||!realReady?"disabled":""}>运行真实 PPE 识别</button><button class="button quiet" type="button" data-scenario="PPE_GOGGLES_MISSING" data-mode="DEMO_FIXTURE" ${state.run?.state==="RUNNING"?"disabled":""}>运行明确标记的演示模式</button><button class="button alarm" type="button" data-scenario="SMOKE_TEMPERATURE_EMERGENCY" ${state.run?.state==="RUNNING"?"disabled":""}>触发烟雾—高温联动</button>`:"";
  const videoAllowed=state.cameras.length>0;
  const candidates=monitorCandidatesMarkup();
  const deviceCards=monitorDevicesMarkup();
  const eventFrame=state.run?.evidence?.[0]?.frame_index;const eventPosition=profile&&Number.isInteger(eventFrame)?Math.max(0,Math.min(100,eventFrame/profile.frame_count*100)):null;
  const content=`${pageHead("LIVE OPERATIONS","实时监控","演示校区 / 化学楼 / 三层 / 实验室 301。主画面用于巡看；证据、初审和处置集中在案件卷宗。",actions)}<div class="monitor-layout"><section class="monitor-workspace"><div class="panel-head"><h2>实验室 301 · 原始录像</h2><span>CAMERA-RECORDED-DEMO-01</span></div><div class="camera-main"><div class="video-stage ${state.run?.state==="RUNNING"?"is-recognizing":""}">${videoAllowed?`<video id="recorded-video" controls muted playsinline preload="metadata"></video>`:`<div class="video-placeholder">当前角色无录像读取权限</div>`}<span class="source-badge">SIMULATED · RECORDED VIDEO</span><span id="frame-counter" class="frame-counter">FRAME — / ${totalFrames}</span><div class="monitor-hud ${state.run?.state==="RUNNING"?"is-running":""}"><span class="monitor-hud__status">${state.run?.state==="RUNNING"?"识别运行中":"录像待机"}</span><b class="monitor-hud__stage">${esc(STAGE_LABELS[state.run?.stages?.find(item=>item.state==="RUNNING")?.stage]||state.run?.state||"READY")}</b></div></div><div class="camera-meta"><span>${esc(videoMeta)}</span><span>预约关联，非视觉身份识别</span></div></div><div class="camera-strip" aria-label="真实机位"><button class="camera-thumb active" type="button" aria-selected="true"><span class="camera-thumb__preview"></span><span><strong>实验室 301</strong><small>录像模拟机位 · 已选择</small></span></button></div><section class="monitor-timeline"><div class="panel-head"><h2>录像事件时间轴</h2><span>FRAME AUTHORITY</span></div><div class="timeline-rail"><span class="timeline-flow" aria-hidden="true"><i></i></span>${eventPosition!==null?`<a class="timeline-event is-alert" href="${state.run?.case_id?`/app/cases/${state.run.case_id}?tab=evidence`:"/app/cases"}" style="left:${eventPosition}%" data-label="证据帧 ${eventFrame}" aria-label="查看证据帧 ${eventFrame}"></a>`:""}</div><p class="help">时间轴只使用真实录像帧索引与已生成证据；没有产物时不补造事件。</p></section></section><aside class="monitor-side"><section class="panel"><div class="panel-head"><h2>当前候选</h2><span data-candidate-count>${active.length} CASES</span></div><div id="monitor-candidates" class="candidate-list">${candidates}</div><div id="monitor-failure">${monitorFailureMarkup()}</div></section><section><div class="panel-head"><h2>设备状态</h2><span>OPERATIONS PROJECTION</span></div><div id="monitor-devices" class="device-grid">${deviceCards}</div></section></aside></div>`;
  setRouteContent(content,{mount:()=>{if(videoAllowed)attachVideo();schedulePoll();},announcement:"实时监控"});
}

async function attachVideo() {
  const video=document.getElementById("recorded-video");if(!video)return;const saved=state.videoPositions.get("recorded-video")||0;
  try{if(!state.videoUrl){if(!state.videoPromise){const camera=state.cameras[0];state.videoPromise=api(camera.media_api_path,{binary:true,headers:{Range:"bytes=0-"}}).then(blob=>{state.videoUrl=URL.createObjectURL(blob);return state.videoUrl;});}await state.videoPromise;}if(!video.isConnected)return;video.src=state.videoUrl;}catch(error){state.videoPromise=null;toast(`录像读取失败：${error.message}`,"error");return;}
  const restore=()=>{if(saved)video.currentTime=Math.min(saved,Number.isFinite(video.duration)?video.duration:saved);};if(video.readyState>=1)restore();else video.addEventListener("loadedmetadata",restore,{once:true});
  video.addEventListener("timeupdate",()=>{state.videoPositions.set("recorded-video",video.currentTime);const counter=document.getElementById("frame-counter"),profile=state.run?.video_profile;if(counter&&profile)counter.textContent=`FRAME ${Math.min(profile.frame_count-1,Math.floor(video.currentTime*profile.fps_num/profile.fps_den))} / ${profile.frame_count}`;});
}

async function attachWorkspaceImages() {
  for (const image of document.querySelectorAll("img[data-workspace-evidence]")) {
    const item=state.evidenceWorkspace?.evidence?.find(value=>value.evidence_id===image.dataset.workspaceEvidence);
    if(!item?.media_url)continue;
    try { const blob=await api(item.media_url,{binary:true}); const url=URL.createObjectURL(blob);state.evidenceUrls.push(url);image.src=url;image.hidden=false;image.previousElementSibling?.remove(); }
    catch(error){image.replaceWith(Object.assign(document.createElement("p"),{className:"help risk",textContent:`证据读取失败 · ${error.message}`}));}
  }
}

function paintWorkspaceFrame(video) {
  const workspace=state.evidenceWorkspace,svg=document.getElementById("evidence-overlay"),counter=document.getElementById("evidence-frame-counter");
  if(!workspace||!video||!svg)return;
  const profile=workspace.video_profile,fps=profile.fps_num/profile.fps_den,frame=Math.min(profile.frame_count-1,Math.max(0,Math.floor(video.currentTime*fps)));
  if(counter)counter.textContent=`FRAME ${frame} / ${profile.frame_count}`;
  const record=workspace.frame_annotations.find(item=>item.frame_index===frame);svg.setAttribute("viewBox",`0 0 ${profile.width} ${profile.height}`);
  svg.innerHTML=record?(record.detections||[]).map(detection=>{const b=detection.bbox;return `<g><rect class="evidence-bbox" x="${b.x1}" y="${b.y1}" width="${b.x2-b.x1}" height="${b.y2-b.y1}"/><text class="evidence-track" x="${b.x1+8}" y="${Math.max(18,b.y1-8)}">ANONYMOUS TRACK</text>${(detection.keypoints||[]).map(point=>`<circle class="evidence-keypoint" cx="${point.x}" cy="${point.y}" r="5"/>`).join("")}</g>`;}).join(""):"";
}

function attachEvidenceWorkspace() {
  const video=document.getElementById("evidence-source-video");attachWorkspaceImages();if(!video)return;
  const saved=state.videoPositions.get("evidence-source-video")||0;video.src=state.evidenceWorkspace.media_url;
  video.addEventListener("loadedmetadata",()=>{video.currentTime=Math.min(saved,Number.isFinite(video.duration)?video.duration:saved);paintWorkspaceFrame(video);},{once:true});
  const update=()=>{if(!video.isConnected)return;state.videoPositions.set("evidence-source-video",video.currentTime);paintWorkspaceFrame(video);if("requestVideoFrameCallback" in video)video.requestVideoFrameCallback(update);};
  if("requestVideoFrameCallback" in video)video.requestVideoFrameCallback(update);else video.addEventListener("timeupdate",()=>paintWorkspaceFrame(video));
  const selected=new URL(location.href).searchParams.get("evidence");if(selected)seekWorkspaceEvidence(selected,false);
}

function seekWorkspaceEvidence(evidenceId,play=false) {
  const item=state.evidenceWorkspace?.evidence?.find(value=>value.evidence_id===evidenceId),video=document.getElementById("evidence-source-video");if(!item)return false;
  if(video){video.currentTime=item.timestamp_millis/1000;paintWorkspaceFrame(video);if(play)video.play().catch(()=>{});}
  const cropPanel=document.querySelector('[data-evidence-view="crops"]');if(cropPanel){cropPanel.innerHTML=item.access==="SEALED_LOCAL"?`<div class="sealed-main"><span>LOCAL SEALED</span><h3>全量脱敏证据</h3><p>该产物按 FULL_REDACTION 生成，只用于证明隐私处理已执行，不作为黑色图片展示，也从未送往云端。</p></div>`:`<div class="crop-main"><span class="spinner"></span><img data-workspace-evidence="${item.evidence_id}" alt="选中的送审证据" hidden><div><b>FRAME ${item.frame_index}</b><p>${item.width}×${item.height} · ${esc(item.privacy_policy)}</p><button class="button quiet" type="button" data-evidence-locate="${item.evidence_id}">回到录像定位</button></div></div>`;attachWorkspaceImages();}
  document.querySelectorAll("[data-workspace-card]").forEach(node=>node.classList.toggle("is-selected",node.dataset.workspaceCard===evidenceId));return true;
}

function patchEvidenceStage(stage,evidenceId=null,{historyMode="push",focus=false}={}) {
  const allowed=["replay","localization","crops","vlm"];if(!allowed.includes(stage)||!state.evidenceWorkspace)return false;
  const url=new URL(location.href);url.searchParams.set("tab","evidence");url.searchParams.set("stage",stage);if(evidenceId)url.searchParams.set("evidence",evidenceId);else url.searchParams.delete("evidence");
  if(historyMode)history[historyMode==="replace"?"replaceState":"pushState"]({labcourt:{key:crypto.randomUUID(),ui:captureEntry()}},"",`${url.pathname}${url.search}`);state.currentRoute=`${url.pathname}${url.search}`;
  document.querySelectorAll("[data-evidence-stage]").forEach(node=>{const selected=node.dataset.evidenceStage===stage;node.setAttribute("aria-selected",String(selected));node.tabIndex=selected?0:-1;});
  const videoRegion=document.querySelector("[data-evidence-video]");if(videoRegion)videoRegion.hidden=["crops","vlm"].includes(stage);document.querySelectorAll("[data-evidence-caption]").forEach(node=>node.hidden=node.dataset.evidenceCaption!==stage);document.querySelectorAll("[data-evidence-view]").forEach(node=>node.hidden=node.dataset.evidenceView!==stage);document.querySelector(".evidence-workbench")?.setAttribute("data-stage",stage);if(evidenceId)seekWorkspaceEvidence(evidenceId);if(focus)document.querySelector(`[data-evidence-stage="${stage}"]`)?.focus();return true;
}

function schedulePoll() {
  clearTimeout(state.pollTimer);if(document.hidden||state.pollInFlight||state.run?.state!=="RUNNING")return;
  const delay=state.pollFailures?[2000,4000,8000][Math.min(state.pollFailures-1,2)]:1000;
  state.pollTimer=setTimeout(async()=>{state.pollInFlight=true;const prior=state.run;try{const next=await api("/api/m8/demo/scenario-runs/current");state.pollFailures=0;state.run=next;patchRunUi();if(prior?.state==="RUNNING"&&next?.state!=="RUNNING")await refreshAfterRun(next);}catch(error){if(error.name!=="AbortError"){state.pollFailures+=1;toast(`进度同步暂时中断，正在自动重连：${error.message}`,"error");}}finally{state.pollInFlight=false;schedulePoll();}},delay);
}

function patchRunUi(){patchShell();const run=state.run;const running=run?.state==="RUNNING";const hud=document.querySelector(".monitor-hud");if(hud){const active=run?.stages?.find(item=>item.state==="RUNNING"||item.state==="FAILED");hud.classList.toggle("is-running",running);hud.querySelector(".monitor-hud__status").textContent=running?"识别运行中":run?.state==="FAILED"?"识别失败":"识别已完成";hud.querySelector(".monitor-hud__stage").textContent=STAGE_LABELS[active?.stage]||active?.stage||run?.state||"READY";}document.querySelector(".video-stage")?.classList.toggle("is-recognizing",running);document.querySelectorAll("[data-scenario]").forEach(button=>{const requiresModel=button.dataset.scenario==="PPE_GOGGLES_MISSING"&&(button.dataset.mode||"FULL_MODEL")==="FULL_MODEL";button.disabled=running||(requiresModel&&state.readiness?.full_model_ready!==true);if(!running)button.removeAttribute("aria-busy");});const failure=document.getElementById("monitor-failure");if(failure)failure.innerHTML=monitorFailureMarkup();}

async function refreshAfterRun(run){const [cases,notifications,conversations,projection]=await Promise.all([optional("/api/m8/cases",[]),optional("/api/m8/notifications",[]),optional("/api/m8/notification-conversations",[]),optional("/api/m8/campuses/campus-demo/operations-projection",null)]);Object.assign(state,{cases,notifications,conversations,projection});if(location.pathname==="/app/monitor"){const candidates=document.getElementById("monitor-candidates"),devices=document.getElementById("monitor-devices"),count=document.querySelector("[data-candidate-count]"),failure=document.getElementById("monitor-failure");if(candidates)candidates.innerHTML=monitorCandidatesMarkup();if(devices)devices.innerHTML=monitorDevicesMarkup();if(count)count.textContent=`${state.cases.filter(item=>!terminalCase(item.status)).length} CASES`;if(failure)failure.innerHTML=monitorFailureMarkup();}patchShell();toast(run.state==="SUCCEEDED"?(run.case_id?"识别已完成，候选案件入口已出现":"识别已完成，未建立可行动风险"):runFailureExplanation(run),run.state==="SUCCEEDED"?"success":"error");}

function caseTitle(item) { const command=caseCommand(item); return command?.risk_level==="EMERGENCY"?"烟雾与高温联动紧急事件":"护目镜缺失候选事件"; }
function caseList(items=state.cases) {
  if(!items.length)return empty("暂无可见案件","标准现场保持无活动案件；可由运维角色启动演示场景。")
  return `<div class="list">${items.map(item=>{const authority=caseAuthority(item);return `<a class="list-item" href="/app/cases/${item.case_id}"><div><h3>${caseTitle(item)}</h3><p>${esc(authority.location_id)} · ${short(item.case_id)} · V${item.case_version}</p></div><div class="status"><span class="badge ${authority.risk_level==="EMERGENCY"?"risk":""}">${esc(authority.risk_level)}</span><p>${esc(label(item.status))} →</p></div></a>`}).join("")}</div>`;
}

function caseFilterProjection() {
  const active=state.cases.filter(x=>!terminalCase(x.status)), archived=state.cases.filter(x=>terminalCase(x.status));
  const filters=[["ALL","全部",state.cases.length],["ACTIVE","进行中",active.length],["EMERGENCY","紧急",state.cases.filter(x=>caseAuthority(x)?.risk_level==="EMERGENCY").length],["ARCHIVED","已归档",archived.length]];
  let items=state.cases;if(state.casesFilter==="ACTIVE")items=active;if(state.casesFilter==="EMERGENCY")items=state.cases.filter(x=>caseAuthority(x)?.risk_level==="EMERGENCY");if(state.casesFilter==="ARCHIVED")items=archived;
  return {active,archived,filters,items};
}

function renderCases() {
  const requested=new URL(location.href).searchParams.get("filter")?.toUpperCase();if(["ALL","ACTIVE","EMERGENCY","ARCHIVED"].includes(requested))state.casesFilter=requested;
  const {filters,items}=caseFilterProjection();
  setRouteContent(`${pageHead("CASE CENTER","案件中心","案件来自服务端状态机。候选事件需经人工核实；机器输出不能直接产生处分。")}<div class="case-tabs" role="tablist" aria-label="案件筛选">${filters.map(([key,text,count])=>`<button class="case-tab" type="button" role="tab" data-case-filter="${key}" aria-selected="${state.casesFilter===key}">${text}<span class="case-tab-count">${count}</span></button>`).join("")}</div><section data-case-list-region><div class="panel-head"><h2 data-case-list-title>${filters.find(x=>x[0]===state.casesFilter)?.[1]||"全部"}卷宗</h2><span data-case-list-count>${items.length} CASES</span></div><div data-case-list>${caseList(items)}</div></section>`,{announcement:"案件中心"});
}

function patchCasesFilter(filter,{historyMode="push"}={}) {
  if(!["ALL","ACTIVE","EMERGENCY","ARCHIVED"].includes(filter))return false;state.casesFilter=filter;
  if(historyMode){const url=new URL(location.href);url.searchParams.set("filter",filter);history[historyMode==="replace"?"replaceState":"pushState"]({labcourt:{key:crypto.randomUUID(),ui:captureEntry()}},"",`${url.pathname}${url.search}`);state.currentRoute=`${url.pathname}${url.search}`;}
  const {filters,items}=caseFilterProjection();document.querySelectorAll("[data-case-filter]").forEach(node=>node.setAttribute("aria-selected",String(node.dataset.caseFilter===filter)));
  const region=document.querySelector("[data-case-list-region]");if(!region)return false;region.classList.remove("is-updating");document.querySelector("[data-case-list-title]").textContent=`${filters.find(x=>x[0]===filter)?.[1]||"全部"}卷宗`;document.querySelector("[data-case-list-count]").textContent=`${items.length} CASES`;document.querySelector("[data-case-list]").innerHTML=caseList(items);requestAnimationFrame(()=>region.classList.add("is-updating"));return true;
}

function flow(status) {
  const names=["检测触发","证据采集","AI 初审","复核会审","程序守门","人工确认","通知送达","结案归档"];
  const current=status==="PENDING_VERIFICATION"||status==="EVIDENCE_REQUESTED"?5:status==="CONFIRMED"||status==="APPEALED"?6:7;
  return `<div class="case-flow-8" aria-label="案件流程">${names.map((name,index)=>`${index?`<span class="case-flow-join ${index<current?"is-complete":""}"></span>`:""}<span class="case-flow-node ${index<current?"is-complete":index===current?"is-current":""}" style="--flow-index:${index}"><i>${index<current?"✓":index+1}</i>${name}</span>`).join("")}</div>`;
}

function caseActions(item) {
  if(role()!=="SAFETY_OFFICER")return `<p class="help">当前角色仅可查询案件，不具备处置权限。</p>`;
  const status=item.status; const buttons=[];
  if(status==="PENDING_VERIFICATION") buttons.push(["CONFIRM","确认事件","primary"],["REQUEST_EVIDENCE","要求补充证据","quiet"],["REJECT","排除候选","quiet"]);
  if(status==="EVIDENCE_REQUESTED") buttons.push(["RETURN_TO_VERIFICATION","证据已收到","primary"]);
  if(status==="CONFIRMED") buttons.push(["RESOLVE","完成处置并结案","primary"]);
  if(status==="APPEALED") buttons.push(["RESOLVE_APPEAL:UPHELD","维持原处理","primary"],["RESOLVE_APPEAL:OVERTURNED","撤销原处理","quiet"]);
  if(!buttons.length)return `<p class="help">此状态没有可执行的安全负责人动作。</p>`;
  return `<div class="field"><label for="case-reason">人工处置说明</label><textarea id="case-reason">已复核现有证据与现场来源，按演示流程记录本次人工决定。</textarea></div><div class="form-actions">${buttons.map(([action,text,kind])=>`<button class="button ${kind}" type="button" data-transition="${action}" data-case="${item.case_id}">${text}</button>`).join("")}</div><p class="help">提交前后端将再次校验角色、案件版本和显式人工确认。</p>`;
}

function caseRecognitionDossier(caseId,section="hearing") {
  const run=state.run;
  if(!run||run.case_id!==caseId)return empty("运行产物尚不可见","当前案件没有可读取的场景运行投影。");
  const components=(run.model_components||[]).map(item=>`<article class="dossier-source"><span>${esc(item.component)} · ${esc(item.source)}</span><strong>${esc(item.model)}</strong><small>${esc(item.provider)} · ${esc(item.revision)} · MANIFEST ${short(item.manifest_id)}</small></article>`).join("");
  if(section==="evidence")return evidenceWorkspaceMarkup();
  return `<div class="hearing-grid"><article class="hearing-card"><p class="eyebrow">机器初审 · WEAK LABEL</p><strong class="dossier-decision">${esc(run.screening_decision||"尚未生成")}</strong><p>${esc(run.screening_summary||"结构化初审尚未生成。")}</p><small>机器输出不是事实或处分依据</small></article><article class="hearing-card"><p class="eyebrow">反证检查</p><strong>当前投影无独立反证 authority</strong><p>不把缺少独立反证引用误写为“已经证明不存在反证”。</p></article><article class="hearing-card"><p class="eyebrow">STRICT_CAUSAL 规则守门</p><strong>${esc(run.rule_judgment||"尚未生成")}</strong><p>后续合规不会抹除较早风险；规则只投影风险，不替人定责。</p></article><article class="hearing-card"><p class="eyebrow">人工复核</p><strong>${run.case_status&&run.case_status!=="PENDING_VERIFICATION"?"已有人工作出状态变更":"等待安全负责人确认"}</strong><p>处置动作集中在“处理”页签并再次校验版本。</p></article></div><div class="panel" style="margin-top:20px"><p class="eyebrow">MODEL / FIXTURE PROVENANCE</p>${components||empty("暂无模型来源","本场景没有模型调用。")}${run.raw_response_ref?`<p class="help mono">RAW · ${esc(run.raw_response_ref)}</p>`:""}</div>`;
}

function evidenceWorkspaceMarkup() {
  const workspace=state.evidenceWorkspace;if(!workspace)return empty("证据工作台尚未生成","完成真实感知和证据阶段后，这里会按来源、定位、裁剪和初审展示完整链路。");
  const query=new URL(location.href).searchParams,requested=query.get("stage")||"replay",stage=["replay","localization","crops","vlm"].includes(requested)?requested:"replay";
  const cloud=workspace.evidence.filter(item=>item.access==="CLOUD_ALLOWED"),sealed=workspace.evidence.filter(item=>item.access==="SEALED_LOCAL"),selected=query.get("evidence")||cloud[0]?.evidence_id;
  const stageMeta={replay:["01","录像回放","H.264 RANGE"],localization:["02","人员定位",`${workspace.frame_annotations.length} FRAMES`],crops:["03","隐私裁剪",`${cloud.length} SENT · ${sealed.length} SEALED`],vlm:["04","VLM 初审",workspace.screening?.source||"NOT GENERATED"]};
  const nav=Object.entries(stageMeta).map(([key,[number,title,meta]])=>`<button class="evidence-stage-tab" type="button" role="tab" data-evidence-stage="${key}" aria-selected="${stage===key}" tabindex="${stage===key?0:-1}"><i>${number}</i><span><b>${title}</b><small>${esc(meta)}</small></span></button>`).join("");
  const video=workspace.media_url?`<div class="evidence-video"><video id="evidence-source-video" controls muted playsinline preload="metadata"></video><svg id="evidence-overlay" aria-hidden="true"></svg><span class="source-badge">SIMULATED · RECORDED VIDEO</span><span id="evidence-frame-counter" class="frame-counter">FRAME — / ${workspace.video_profile.frame_count}</span></div>`:`<div class="evidence-restricted"><b>案件依据已脱敏</b><p>当前角色不能查看原始录像、人物框或匿名轨迹；可查看本人案件的裁剪依据与处理结论。</p></div>`;
  const folders=workspace.evidence.map(item=>item.access==="SEALED_LOCAL"?`<button class="evidence-file sealed" type="button" data-workspace-card="${item.evidence_id}" data-evidence-card="${item.evidence_id}"><span class="evidence-lock">封</span><i>${esc(item.role)}</i><b>本地封存件</b><small>FULL REDACTION · LOCAL ONLY<br>未送云端 · FRAME ${item.frame_index}</small></button>`:`<button class="evidence-file ${item.evidence_id===selected?"is-selected":""}" type="button" data-workspace-card="${item.evidence_id}" data-evidence-card="${item.evidence_id}"><span class="evidence-thumb"><span class="spinner"></span><img data-workspace-evidence="${item.evidence_id}" alt="帧 ${item.frame_index} 眼部区域送审裁剪" hidden></span><i>${esc(item.role)}</i><b>送审证据 ${String(cloud.indexOf(item)+1).padStart(2,"0")}</b><small>FRAME ${item.frame_index} · ${esc(item.integrity)}</small></button>`).join("");
  const selectedItem=workspace.evidence.find(item=>item.evidence_id===selected);const cropMain=selectedItem?selectedItem.access==="SEALED_LOCAL"?`<div class="sealed-main"><span>LOCAL SEALED</span><h3>全量脱敏证据</h3><p>该产物按 FULL_REDACTION 生成，只用于证明隐私处理已执行，不作为黑色图片展示，也从未送往云端。</p></div>`:`<div class="crop-main"><span class="spinner"></span><img data-workspace-evidence="${selectedItem.evidence_id}" alt="选中的送审证据" hidden><div><b>FRAME ${selectedItem.frame_index}</b><p>${selectedItem.width}×${selectedItem.height} · ${esc(selectedItem.privacy_policy)}</p><button class="button quiet" type="button" data-evidence-locate="${selectedItem.evidence_id}">回到录像定位</button></div></div>`:empty("选择证据夹","选择一份送审裁剪或本地封存件查看来源链。");
  const screening=workspace.screening?`<article class="vlm-receipt"><p class="eyebrow">${esc(workspace.screening.source)} · WEAK LABEL</p><h3>${esc(workspace.screening.decision)}</h3><p>${esc(workspace.screening.summary)}</p><dl><div><dt>提供方 / 模型</dt><dd>${esc(workspace.screening.provider)} · ${esc(workspace.screening.model)}</dd></div><div><dt>送审输入</dt><dd>${workspace.screening.input_evidence_ids.map(short).join(" · ")}</dd></div><div><dt>模型清单</dt><dd>${short(workspace.screening.manifest_id)}</dd></div><div><dt>原始响应</dt><dd>${esc(workspace.screening.raw_response_ref)}</dd></div></dl><a class="button primary" href="?tab=hearing">进入会审 →</a></article>`:empty("初审尚未生成","没有结构化 authority 时不展示猜测的模型结论。");
  const sources=`<aside class="evidence-provenance"><p class="eyebrow">SOURCE CHAIN</p><ol><li><b>H.264 原始录像</b><span>${workspace.video_profile.width}×${workspace.video_profile.height} · ${workspace.video_profile.frame_count} 帧</span></li><li><b>Grounding DINO + ViTPose</b><span>真实人物框、匿名轨迹与关键点</span></li><li><b>隐私变换</b><span>${cloud.length} 份送审裁剪 · ${sealed.length} 份本地封存</span></li><li><b>Qwen 结构化初审</b><span>${workspace.screening?`${workspace.screening.source} · ${workspace.screening.decision}`:"尚未生成"}</span></li></ol><p class="help">预约关联，非视觉身份识别。机器输出是弱标签，不直接作为处分依据。</p></aside>`;
  return `<section class="evidence-workbench" data-stage="${stage}"><nav class="evidence-stage-nav" role="tablist" aria-label="识别证据流程">${nav}</nav><div class="evidence-workbench__grid"><div class="evidence-workbench__main"><section data-evidence-video ${["crops","vlm"].includes(stage)?"hidden":""}>${video}<div class="evidence-caption" data-evidence-caption="replay" ${stage!=="replay"?"hidden":""}><b>原始画面回放</b><span>浏览器兼容 H.264 · 支持播放、拖动和 Range</span></div><div class="evidence-caption" data-evidence-caption="localization" ${stage!=="localization"?"hidden":""}><b>真实人物定位</b><span>按播放时钟映射 frame bundle；不插值，不显示虚假准确率</span></div></section><section data-evidence-view="crops" ${stage!=="crops"?"hidden":""}>${cropMain}</section><section data-evidence-view="vlm" ${stage!=="vlm"?"hidden":""}>${screening}</section></div>${sources}</div><div class="evidence-folder-head"><div><p class="eyebrow">EVIDENCE FOLDER</p><h2>送审证据夹与本地封存件</h2></div><span>${cloud.length} CLOUD ALLOWED · ${sealed.length} SEALED LOCAL</span></div><div class="evidence-folder">${folders}</div></section>`;
}

async function renderCaseDetail(caseId) {
  let item=state.cases.find(value=>value.case_id===caseId); if(!item) item=await api(`/api/m8/cases/${caseId}`);
  const authority=caseAuthority(item),command=caseCommand(item),triggers=command.trigger_authorities||[];
  const related=state.notifications.filter(n=>notificationPlan(n)?.case_id===caseId);
  const tab=new URL(location.href).searchParams.get("tab")||"overview";const allowed=["overview","evidence","hearing","handling"];const activeTab=allowed.includes(tab)?tab:"overview";
  const run=state.run?.case_id===caseId?state.run:null;state.evidenceWorkspace=run?await optional(`/api/m8/demo/scenario-runs/${run.run_id}/evidence-workspace`,null):null;
  const conversationSummary=state.conversations.find(value=>value.case_id===caseId),hasMessage=related.some(value=>["CASE_UPDATED","APPEAL_OUTCOME"].includes(notificationPlan(value)?.purpose));
  const notifyAction=role()==="SAFETY_OFFICER"&&item.status==="CONFIRMED"&&authority.subject_actor_id?(hasMessage?`<a class="button" href="/app/notifications/${item.case_id}">查看会话</a><button class="button quiet" type="button" data-confirm-dispatch="CASE_UPDATED" data-case="${item.case_id}">再次发送</button>`:`<button class="button" type="button" data-dispatch="CASE_UPDATED" data-case="${item.case_id}">发送学生消息</button>`):"";
  const hasOutcome=related.some(value=>notificationPlan(value)?.purpose==="APPEAL_OUTCOME");const outcomeAction=role()==="SAFETY_OFFICER"&&item.status==="APPEAL_RESOLVED"?(hasOutcome?`<a class="button" href="/app/notifications/${item.case_id}">查看处理结果会话</a>`:`<button class="button" type="button" data-dispatch="APPEAL_OUTCOME" data-case="${item.case_id}">发送申诉结果</button>`):"";
  const overview=`<section class="facts"><div class="fact"><span>状态</span><strong>${label(item.status)}</strong></div><div class="fact"><span>风险等级</span><strong class="${authority.risk_level==="EMERGENCY"?"risk":""}">${authority.risk_level}</strong></div><div class="fact"><span>案件版本</span><strong>V${item.case_version}</strong></div><div class="fact"><span>关联主体</span><strong>${esc(authority.subject_actor_id||"无")}</strong></div></section><div class="panel"><div class="panel-head"><h2>触发 authority</h2><span>${triggers.length} REFERENCES</span></div><div class="authority-list">${triggers.map(ref=>`<div class="authority"><b>${esc(ref.kind)}</b><code>${esc(ref.authority_id)}<br>${esc(ref.document_sha256)}</code></div>`).join("")}</div></div>`;
  const handling=`<div class="processing-layout"><section class="panel"><div class="panel-head"><h2>处置工作台</h2><span>HUMAN CONFIRMATION</span></div>${caseActions(item)}</section><aside><div class="panel-head"><h2>审计时间线</h2><span>STATE MACHINE</span></div><div class="case-timeline"><article class="timeline-event is-complete"><b>案件建立</b><p>${label("PENDING_VERIFICATION")} · V1</p></article><article class="timeline-event is-current"><b>当前状态</b><p>${esc(label(item.status))} · V${item.case_version}</p></article></div></aside></div><section class="case-conversation-summary"><div class="panel-head"><h2>案件会话</h2><span>${conversationSummary?`${conversationSummary.notification_count} 通知 · ${conversationSummary.reply_count} 回复`:"尚未建立"}</span></div>${conversationSummary?`<a class="conversation-inline" href="/app/notifications/${caseId}"><div><b>${esc(conversationSummary.latest_title)}</b><p>${esc(conversationSummary.latest_progress)}</p></div><span>查看完整会话 →</span></a>`:empty("尚无案件会话","发送学生消息后，双方会在同一条时间线查看说明、申诉和处理结果。")}</section>`;
  const panels={overview,evidence:caseRecognitionDossier(caseId,"evidence"),hearing:caseRecognitionDossier(caseId,"hearing"),handling};
  const tabs=[["overview","概览"],["evidence","证据"],["hearing","会审"],["handling","处理"]];
  const content=`${pageHead(authority.risk_level,caseTitle(item),`${authority.location_id} · 案件 ${short(item.case_id)} · ${authority.subject_actor_id?"预约关联，非视觉身份识别":"未关联个人身份"}`,`${notifyAction}${outcomeAction}<a class="button quiet" href="/app/cases">返回列表</a>`)}${flow(item.status)}<nav class="case-tabs" role="tablist" aria-label="案件卷宗内容">${tabs.map(([key,text])=>`<a class="case-tab" role="tab" data-case-tab="${key}" aria-selected="${activeTab===key}" tabindex="${activeTab===key?0:-1}" href="?tab=${key}">${text}${key==="evidence"?`<span class="case-tab-count">${state.run?.case_id===caseId?state.run.evidence?.length||0:0}</span>`:""}</a>`).join("")}</nav><section class="case-panel is-active" role="tabpanel" data-case-panel="${activeTab}">${panels[activeTab]}</section>`;
  state.caseDetail={caseId,panels,tabs};
  setRouteContent(content,{mount:()=>{if(activeTab==="evidence")attachEvidenceWorkspace();},announcement:`${caseTitle(item)} · ${tabs.find(x=>x[0]===activeTab)[1]}`});
}

function patchCaseTab(tab,{historyMode="push",focus=false}={}) {
  const detail=state.caseDetail;if(!detail||!["overview","evidence","hearing","handling"].includes(tab))return false;
  if(historyMode){const url=new URL(location.href);url.searchParams.set("tab",tab);history[historyMode==="replace"?"replaceState":"pushState"]({labcourt:{key:crypto.randomUUID(),ui:captureEntry()}},"",`${url.pathname}${url.search}`);state.currentRoute=`${url.pathname}${url.search}`;}
  document.querySelectorAll("[data-case-tab]").forEach(node=>{const selected=node.dataset.caseTab===tab;node.setAttribute("aria-selected",String(selected));node.tabIndex=selected?0:-1;});
  const panel=document.querySelector("[data-case-panel]");if(!panel)return false;panel.classList.remove("is-updating");panel.dataset.casePanel=tab;panel.innerHTML=detail.panels[tab];requestAnimationFrame(()=>panel.classList.add("is-updating"));if(tab==="evidence")attachEvidenceWorkspace();if(focus)document.querySelector(`[data-case-tab="${tab}"]`)?.focus();return true;
}

function notificationDeliveryMeta(notification) {
  const authority=notificationAuthority(notification),plan=authority?.plan,command=notification?.audit_event?.transition_command;
  const dispatch=command?.dispatch_result,delivery=command?.delivery_receipt;
  return {channel:plan?.target?.channel||dispatch?.request?.plan?.target?.channel||"UNKNOWN",realDeliveryConfirmed:Boolean(delivery?.real_delivery_confirmed),notificationId:notification?.notification_id};
}
function conversationDeliveryMeta(caseId) {
  const rows=state.notifications.filter(item=>notificationPlan(item)?.case_id===caseId).map(notificationDeliveryMeta),channels=[...new Set(rows.map(item=>item.channel))];
  return {channels:channels.length?channels:["UNKNOWN"],realDeliveryConfirmed:rows.some(item=>item.realDeliveryConfirmed)};
}
function conversationCards(items=state.conversations) {
  if(!items.length)return empty("暂无案件会话","发送案件消息后，同一案件的通知、回复和决定会聚合到这里。")
  return `<div class="conversation-list">${items.map(item=>{const delivery=conversationDeliveryMeta(item.case_id);return `<a class="conversation-card" href="/app/notifications/${item.case_id}"><div class="conversation-card__index"><span>${String(item.notification_count).padStart(2,"0")}</span><small>MESSAGES</small></div><div><p class="eyebrow">${esc(item.case_status)} · ${esc(item.location_id)}</p><h2>${esc(item.latest_title)}</h2><p>${esc(item.latest_progress)}</p><div class="conversation-card__meta"><span>${item.notification_count} 条通知</span><span>${item.reply_count} 条回复</span><span>${item.last_activity_at?new Date(item.last_activity_at).toLocaleString("zh-CN"):"时间未单独持久化"}</span>${delivery.channels.map(channel=>`<span class="badge ${channel==="FEISHU"?"live":"fake"}">${esc(channel)}</span>`).join("")}<span>real_delivery_confirmed=${String(delivery.realDeliveryConfirmed)}</span></div></div><div class="conversation-card__next"><small>当前待办</small><b>${item.pending_actor_role==="STUDENT"?"学生":item.pending_actor_role==="SAFETY_OFFICER"?"安全负责人":"无"}</b><span>打开会话 →</span></div></a>`;}).join("")}</div>`;
}

function renderNotifications() {
  const replies=state.conversations.reduce((sum,item)=>sum+item.reply_count,0),pending=state.conversations.filter(item=>item.pending_actor_role!=="NONE").length;
  setRouteContent(`${pageHead("CASE CONVERSATIONS","通知与会话","每个案件只有一条完整会话。通知、学生回复、申诉决定、结果送达和确认历史均保留，不改写原消息。")}<section class="metrics">${metric(state.conversations.length,"案件会话","按 case_id 聚合")}${metric(state.notifications.length,"底层通知","审计历史未合并")}${metric(replies,"学生回复","正文可在会话查看")}${metric(pending,"当前待办","按真实状态推导")}</section>${conversationCards()}`,{announcement:"通知与会话"});
}

const CONVERSATION_STEP_LABELS={NOTIFICATION:"通知送达",STUDENT_EXPLANATION:"学生回应",STUDENT_APPEAL:"申诉提交",SAFETY_DECISION:"安全处理",OUTCOME_NOTIFICATION:"结果通知",STUDENT_ACKNOWLEDGEMENT:"学生确认"};

function conversationActionsMarkup(conversation) {
  if(!conversation.actions.length)return `<div class="conversation-complete"><span>✓</span><div><b>当前没有待执行动作</b><p>完整历史仍可查看，底层通知和回复 authority 未被合并或删除。</p></div></div>`;
  const replyActions=conversation.actions.filter(item=>["SUBMIT_EXPLANATION","SUBMIT_APPEAL"].includes(item.action));const other=conversation.actions.filter(item=>!replyActions.includes(item));
  const reply=replyActions.length?`<div class="field"><label for="conversation-reply">写下现场说明或申诉理由</label><textarea id="conversation-reply" placeholder="正文将单独持久化并校验哈希；提交申诉后还会调用案件状态机。"></textarea></div><div class="form-actions">${replyActions.map(item=>`<button class="button ${item.action==="SUBMIT_APPEAL"?"primary":"quiet"}" type="button" data-conversation-reply="${item.action}" data-notification="${item.target_notification_id}" data-case="${conversation.case_id}">${item.action==="SUBMIT_APPEAL"?"提交申诉":"提交说明"}</button>`).join("")}</div>`:"";
  const buttons=other.map(item=>{if(item.action==="RETRY_APPEAL")return `<button class="button primary" type="button" data-retry-appeal="${conversation.case_id}" data-authority="${item.supporting_authority_id}" data-document="${item.supporting_document_sha256}">重试提交案件申诉</button>`;if(item.action.startsWith("RESOLVE_APPEAL"))return `<button class="button ${item.action.endsWith("UPHELD")?"primary":"quiet"}" type="button" data-transition="RESOLVE_APPEAL:${item.action.endsWith("OVERTURNED")?"OVERTURNED":"UPHELD"}" data-case="${conversation.case_id}">${item.action.endsWith("OVERTURNED")?"撤销原处理":"维持原处理"}</button>`;if(item.action==="SEND_CASE_UPDATE")return `<button class="button quiet" type="button" data-confirm-dispatch="CASE_UPDATED" data-case="${conversation.case_id}">再次发送案件消息</button>`;if(item.action==="SEND_APPEAL_OUTCOME")return `<button class="button primary" type="button" data-dispatch="APPEAL_OUTCOME" data-case="${conversation.case_id}">发送处理结果</button>`;if(item.action==="ACKNOWLEDGE_OUTCOME")return `<button class="button primary" type="button" data-ack="${item.target_notification_id}">确认收到处理结果</button>`;return "";}).join("");
  return `${reply}${other.some(item=>item.action.startsWith("RESOLVE_APPEAL"))?`<div class="field"><label for="case-reason">安全负责人处理理由</label><textarea id="case-reason">已复核学生申诉、录像证据和预约关联，现记录人工处理决定。</textarea></div>`:""}<div class="form-actions">${buttons}</div>`;
}

async function renderNotificationConversation(caseId) {
  const conversation=await api(`/api/m8/notification-conversations/${caseId}`);state.conversation=conversation;
  const stages=["NOTIFICATION","STUDENT_EXPLANATION","STUDENT_APPEAL","SAFETY_DECISION","OUTCOME_NOTIFICATION","STUDENT_ACKNOWLEDGEMENT"],present=new Set(conversation.events.map(item=>item.kind));let reached=true;
  // An appeal is itself a student response. Keep the six-step rail continuous
  // when the student chose appeal without first submitting a separate explanation.
  if(present.has("STUDENT_APPEAL"))present.add("STUDENT_EXPLANATION");
  const flowMarkup=`<div class="conversation-flow">${stages.map((kind,index)=>{const done=present.has(kind),current=!done&&reached;if(!done)reached=false;return `${index?`<i class="${done?"done":""}"></i>`:""}<div class="${done?"done":current?"current":""}"><span>${done?"✓":index+1}</span><b>${CONVERSATION_STEP_LABELS[kind]}</b></div>`;}).join("")}</div>`;
  const timeline=conversation.events.map(event=>{const notification=state.notifications.find(item=>item.notification_id===event.notification_id),delivery=notification?notificationDeliveryMeta(notification):null;return `<article class="conversation-event ${event.sender.toLowerCase()}"><div class="conversation-event__mark"><span>${String(event.sequence).padStart(2,"0")}</span><i></i></div><div class="conversation-event__paper"><header><div><p class="eyebrow">${esc(event.kind)} · ${esc(event.sender)}</p><h3>${esc(event.title)}</h3></div><time>${event.occurred_at?new Date(event.occurred_at).toLocaleString("zh-CN"):"案件审计未单独记录时间"}</time></header>${event.body?`<p class="conversation-body">${esc(event.body)}</p>`:`<p class="conversation-redacted">正文按当前角色隐藏</p>`}<footer><span>${esc(event.status)}</span>${event.technical?`<details><summary>投递与审计信息</summary><code>${esc(delivery?.channel||event.technical.channel||"UNKNOWN")} · real_delivery_confirmed=${String(delivery?.realDeliveryConfirmed||false)}<br>${esc(event.technical.authority_ref)}<br>${esc(event.technical.document_sha256)}</code></details>`:""}</footer></div></article>`;}).join("");
  const content=`${pageHead("CASE CONVERSATION","案件会话",`${conversation.location_id} · 案件 ${short(caseId)} · V${conversation.case_version}`,`<a class="button quiet" href="/app/notifications">返回会话列表</a><a class="button" href="/app/cases/${caseId}?tab=handling">查看案件处理</a>`)}${flowMarkup}<div class="conversation-layout"><section class="conversation-timeline">${timeline}</section><aside class="conversation-action-panel"><p class="eyebrow">NEXT ACTION</p><h2>${esc(conversation.summary.latest_progress)}</h2><p>所有操作继续调用既有业务接口，并由服务端再次校验角色与案件版本。</p>${conversationActionsMarkup(conversation)}</aside></div>`;
  setRouteContent(content,{announcement:"案件完整会话"});
}

function renderMap() {
  const query=new URL(location.href).searchParams,floors=locations().filter(item=>item.kind==="FLOOR"),rooms=locations().filter(item=>item.kind==="ROOM");
  state.mapFloor=query.get("floor")||floors[0]?.location_id||null;state.mapLocation=query.get("location")||rooms.find(item=>item.parent_location_id===state.mapFloor)?.location_id||rooms[0]?.location_id||null;
  const floorTabs=floors.map(item=>`<button type="button" data-map-floor="${esc(item.location_id)}" class="${item.location_id===state.mapFloor?"active":""}" aria-pressed="${item.location_id===state.mapFloor}">${esc(item.display_name)}</button>`).join("");
  setRouteContent(`${pageHead("CAMPUS TOPOLOGY","校园空间态势","海南大学 · 化学楼。平面仅呈现 topology 中登记的空间与来源，不补造房间、摄像头或人员轨迹。")}<div class="map-floor-tabs" aria-label="登记楼层">${floorTabs}</div><div class="map-page-grid"><section class="map-plan-panel"><div class="map-plan-head"><div><p class="eyebrow">CHEMISTRY BUILDING</p><h2 data-map-floor-title>${esc(floors.find(item=>item.location_id===state.mapFloor)?.display_name||"登记楼层")}</h2></div><span><i class="map-status-dot ${isEmergency()?"alert":""}"></i>${isEmergency()?"联动告警":"标准现场"}</span></div><div class="map-plan" aria-label="登记空间平面图"><span class="map-corridor horizontal" aria-hidden="true"></span><span class="map-corridor vertical" aria-hidden="true"></span><div class="map-unregistered zone-a">未登记区域</div><div class="map-unregistered zone-b">未登记区域</div><div class="map-unregistered zone-c">未登记区域</div><div id="map-room-host">${mapRoomMarkup()}</div></div><footer class="map-plan-legend"><span><i class="registered"></i>已登记空间</span><span><i></i>未登记区域</span><span><i class="sensor"></i>SIMULATED SENSOR</span></footer></section><aside id="map-detail" class="map-detail">${mapDetailMarkup()}</aside></div>`,{announcement:"校园空间态势"});
}

function mapRoomMarkup() {
  const rooms=locations().filter(item=>item.kind==="ROOM"&&item.parent_location_id===state.mapFloor);return rooms.map((item,index)=>{const active=item.location_id===state.mapLocation,hasCase=state.cases.some(value=>caseAuthority(value)?.location_id===item.location_id&&!terminalCase(value.status));return `<button type="button" class="map-room-real ${active?"active":""} ${hasCase||isEmergency()?"alert":""}" data-location="${esc(item.location_id)}" style="--room-index:${index}" aria-pressed="${active}"><span class="map-room-code">301</span><strong>${esc(item.display_name)}</strong><small>${sources().filter(value=>value.source.location_id===item.location_id).length} 个登记来源</small><i></i></button>`;}).join("")||empty("当前楼层无登记房间","平面不会补造未进入 topology 的房间。");
}

function mapDetailMarkup() {
  const room=locations().find(item=>item.location_id===state.mapLocation),roomSources=sources().filter(item=>item.source.location_id===state.mapLocation),roomCases=state.cases.filter(item=>caseAuthority(item)?.location_id===state.mapLocation);
  if(!room)return empty("尚未选择登记空间","请选择 topology 中存在的房间。");
  const devices=roomSources.map(item=>`<article class="map-source ${String(sourceValue(item)).includes("烟雾")||Number(item.latest_sample_receipt?.sample?.value)>60000?"alert":""}"><i class="${item.source.source_kind.toLowerCase()}"></i><div><strong>${esc(item.source.sensor_type||"录像机位")}</strong><span>${esc(sourceValue(item))}</span></div><small>${esc(item.display_badge)}<br>${esc(item.observation_state)}</small></article>`).join("");
  const cases=roomCases.map(item=>`<a class="map-case-link" href="/app/cases/${esc(item.case_id)}"><span>${esc(label(item.status))}</span><strong>${esc(caseTitle(item))}</strong><i>查看卷宗 →</i></a>`).join("")||`<p class="map-no-case">当前无关联案件</p>`;
  return `<header><p class="eyebrow">REGISTERED ROOM</p><span class="map-detail-number">301</span><h2>${esc(room.display_name)}</h2><p>${esc(room.location_id)} · ${roomSources.length} 个登记来源</p></header><section><div class="panel-head"><h3>设备与信号</h3><span>OPERATIONS PROJECTION</span></div><div class="map-source-list">${devices}</div></section><section><div class="panel-head"><h3>关联案件</h3><span>${roomCases.length} CASES</span></div>${cases}</section><footer>预约关联，非视觉身份识别<br>没有人脸识别或跨摄像头重识别</footer>`;
}

function patchMapSelection({floor=state.mapFloor,location:selectionLocation=state.mapLocation,historyMode="push"}={}) {
  const floorExists=locations().some(item=>item.kind==="FLOOR"&&item.location_id===floor);if(!floorExists)return false;state.mapFloor=floor;
  const roomExists=locations().some(item=>item.kind==="ROOM"&&item.parent_location_id===floor&&item.location_id===selectionLocation);state.mapLocation=roomExists?selectionLocation:locations().find(item=>item.kind==="ROOM"&&item.parent_location_id===floor)?.location_id||null;
  if(historyMode){const url=new URL(location.href);url.searchParams.set("floor",state.mapFloor);if(state.mapLocation)url.searchParams.set("location",state.mapLocation);history[historyMode==="replace"?"replaceState":"pushState"]({labcourt:{key:crypto.randomUUID(),ui:captureEntry()}},"",`${url.pathname}${url.search}`);state.currentRoute=`${url.pathname}${url.search}`;}
  document.querySelectorAll("[data-map-floor]").forEach(node=>{const active=node.dataset.mapFloor===state.mapFloor;node.classList.toggle("active",active);node.setAttribute("aria-pressed",String(active));});
  const floorTitle=document.querySelector("[data-map-floor-title]"),floorNode=locations().find(item=>item.location_id===state.mapFloor);if(floorTitle)floorTitle.textContent=floorNode?.display_name||"登记楼层";
  const roomHost=document.getElementById("map-room-host"),detail=document.getElementById("map-detail");if(roomHost)roomHost.innerHTML=mapRoomMarkup();if(detail){detail.classList.remove("is-updating");detail.innerHTML=mapDetailMarkup();requestAnimationFrame(()=>detail.classList.add("is-updating"));}return true;
}

function knowledgeCatalog() { return state.knowledgeCatalog?.catalog||null; }
function knowledgeDocuments() { return knowledgeCatalog()?.documents||[]; }
function knowledgeTypes() { return [...new Set(knowledgeDocuments().map(item=>item.document_type))].sort(); }
function knowledgeDocumentListMarkup() {
  const needle=state.knowledgeSearch.trim().toLocaleLowerCase("zh-CN"),docs=knowledgeDocuments().filter(item=>(state.knowledgeFilter==="ALL"||item.document_type===state.knowledgeFilter)&&(!needle||`${item.title} ${item.logical_document_id}`.toLocaleLowerCase("zh-CN").includes(needle)));
  return docs.map(item=>`<button type="button" class="kb-doc ${item.logical_document_id===state.knowledgeSelected?"active":""}" data-knowledge-doc="${esc(item.logical_document_id)}" aria-pressed="${item.logical_document_id===state.knowledgeSelected}"><span>${esc(item.document_type)}</span><strong>${esc(item.title)}</strong><small>V${item.document_version} · ${new Date(item.effective_at).toLocaleDateString("zh-CN")}</small><i>→</i></button>`).join("")||empty("没有匹配文档","调整类型或搜索词后重试；目录不会补造结果。");
}
function knowledgeReaderMarkup(view=state.knowledgeDocument) {
  if(!view)return empty("请选择一份文档","正文只从当前 catalog 中读取，并在服务端校验 SHA-256 与 UTF-8。");const doc=view.document,lines=view.content.split(/\r?\n/).filter(Boolean);
  return `<header class="kb-reader-head"><div><p class="eyebrow">${esc(doc.document_type)} · VERIFIED</p><h2>${esc(doc.title)}</h2></div><span>V${doc.document_version}</span></header><div class="kb-paper-meta"><span>来源 ${esc(doc.source_ref)}</span><span>生效 ${new Date(doc.effective_at).toLocaleDateString("zh-CN")}</span><span>签发 ${esc(doc.issuer_id)}</span></div><div class="kb-paper-body">${lines.map((line,index)=>index===0?`<h3>${esc(line)}</h3>`:`<p>${esc(line)}</p>`).join("")}</div><footer class="kb-integrity"><strong>CONTENT INTEGRITY · ${esc(view.content_integrity)}</strong><code>${short(doc.content_sha256)} · ${esc(doc.document_authority_id)}</code><span>NETWORK_USED=${String(view.network_used).toUpperCase()}</span></footer>`;
}

async function renderKnowledge() {
  const query=new URL(location.href).searchParams,docs=knowledgeDocuments();state.knowledgeFilter=query.get("type")||"ALL";if(!["ALL",...knowledgeTypes()].includes(state.knowledgeFilter))state.knowledgeFilter="ALL";state.knowledgeSelected=query.get("doc")||docs[0]?.logical_document_id||null;
  if(state.knowledgeSelected&&!docs.some(item=>item.logical_document_id===state.knowledgeSelected))state.knowledgeSelected=docs[0]?.logical_document_id||null;
  state.knowledgeDocument=state.knowledgeSelected?await api(`/api/m8/knowledge/catalogs/campus-safety-knowledge/documents/${encodeURIComponent(state.knowledgeSelected)}`):null;
  const filters=[["ALL","全部"],...knowledgeTypes().map(item=>[item,item.replaceAll("_"," ")])].map(([key,text])=>`<button type="button" data-knowledge-type="${esc(key)}" class="${state.knowledgeFilter===key?"active":""}" aria-pressed="${state.knowledgeFilter===key}">${esc(text)}</button>`).join("");
  setRouteContent(`${pageHead("VERIFIED OFFLINE CATALOG","校园安全知识库","文档来自当前离线目录；正文经 SHA-256 与 UTF-8 校验。严格问答不调用模型或网络。")}<section class="knowledge-toolbar"><label class="kb-search"><span class="sr-only">搜索当前目录</span><input id="knowledge-search" type="search" placeholder="搜索标题或文档编号" value="${esc(state.knowledgeSearch)}"><i>⌕</i></label><div class="kb-filters" role="group" aria-label="文档类型">${filters}</div></section><div class="kb-layout"><aside class="kb-catalog"><header><p class="eyebrow">CURRENT CATALOG</p><strong>${knowledgeCatalog()?.catalog_id||"campus-safety-knowledge"}</strong><span>${docs.length} DOCS · REV ${knowledgeCatalog()?.catalog_revision||"—"}</span></header><div id="knowledge-document-list">${knowledgeDocumentListMarkup()}</div></aside><article id="knowledge-reader" class="kb-reader">${knowledgeReaderMarkup()}</article></div><section class="kb-query"><div><p class="eyebrow">STRICT QUESTION</p><h2>向当前目录提问</h2><p>回答只抽取已校验文档，并保留精确引用；没有匹配时返回 NO_MATCH。</p></div><form data-knowledge-form><label><span class="sr-only">知识问题</span><input id="knowledge-query" maxlength="512" placeholder="例如：进入化学实验室需要佩戴哪些防护装备？"></label><button class="button primary" type="submit" data-action="knowledge-query">查询</button></form><div id="knowledge-answer" class="kb-answer">${empty("尚未查询","答案与引用会显示在这里，不会改写上方文档阅读器。")}</div></section>`,{announcement:"校园安全知识库"});
}

async function selectKnowledgeDocument(logicalId,{historyMode="push"}={}) {
  if(!knowledgeDocuments().some(item=>item.logical_document_id===logicalId))return false;state.knowledgeSelected=logicalId;
  if(historyMode){const url=new URL(location.href);url.searchParams.set("doc",logicalId);url.searchParams.set("type",state.knowledgeFilter);history[historyMode==="replace"?"replaceState":"pushState"]({labcourt:{key:crypto.randomUUID(),ui:captureEntry()}},"",`${url.pathname}${url.search}`);state.currentRoute=`${url.pathname}${url.search}`;}
  document.querySelectorAll("[data-knowledge-doc]").forEach(node=>{const active=node.dataset.knowledgeDoc===logicalId;node.classList.toggle("active",active);node.setAttribute("aria-pressed",String(active));});
  const reader=document.getElementById("knowledge-reader");if(reader)reader.innerHTML=`<div class="kb-reader-loading"><span class="spinner"></span><p>正在校验文档 authority…</p></div>`;
  try{state.knowledgeDocument=await api(`/api/m8/knowledge/catalogs/campus-safety-knowledge/documents/${encodeURIComponent(logicalId)}`);if(reader){reader.classList.remove("is-updating");reader.innerHTML=knowledgeReaderMarkup();requestAnimationFrame(()=>reader.classList.add("is-updating"));}}catch(error){if(reader)reader.innerHTML=`<div class="error-state"><strong>${esc(error.message)}</strong><p>正文未通过校验，因此没有展示。</p><button class="button" type="button" data-knowledge-doc="${esc(logicalId)}">重新读取</button></div>`;}return true;
}

function knowledgeQueryPayload(query) {const types=["DEVICE_MANUAL","EMERGENCY_PLAN","FAQ","HISTORICAL_PRECEDENT","POLICY","SOP"];return {query_text:query,locale:"zh-CN",as_of:new Date().toISOString(),allowed_document_types:state.knowledgeFilter==="ALL"?types:[state.knowledgeFilter],max_citations:3};}

function agentQuickPrompts() {
  const common=[["查看当前案件","当前案件"],["查看通知状态","通知状态"],["查看飞书连接状态","飞书状态"],["护目镜有什么要求？","PPE 规范"]];if(role()==="OPERATIONS")return [...common,["检查飞书测试卡条件","测试卡检查"],["触发烟雾与温度场景","传感器演示"],["复位演示现场","复位现场"]];if(role()==="SAFETY_OFFICER")return [["确认当前待核实案件","生成处置卡"],["发送当前案件通知","通知操作卡"],...common];return common;
}
function agentMessageMarkup(message) {
  const refs=(message.source_refs||[]).map(item=>`<span>${esc(item)}</span>`).join("");return `<article class="agent-message ${esc(message.kind)}"><div class="agent-avatar">${message.kind==="agent"?"A":"你"}</div><div><p>${esc(message.text)}</p>${refs?`<div class="agent-sources">${refs}</div>`:""}<small>${esc(message.meta||"")}</small></div></article>`;
}
function agentActionMarkup() {
  if(!state.action)return "";return `<article class="agent-action-card"><p class="eyebrow">PROPOSED ACTION · HUMAN CONFIRMATION</p><h3>${esc(state.action.action_kind)}</h3><p>${esc(state.action.impact_summary)}</p><dl><div><dt>目标</dt><dd>${esc(state.action.target_ref)}</dd></div><div><dt>当前版本</dt><dd>V${state.action.current_version}</dd></div><div><dt>当前 fence</dt><dd>${short(state.action.current_fence)}</dd></div><div><dt>确认接口</dt><dd>${esc(state.action.endpoint_path)}</dd></div></dl><button class="button primary" type="button" data-action="open-agent-confirm">检查并确认 →</button></article>`;
}
function agentContextMarkup() {return `<p><span>当前角色</span><strong>${esc(ROLE_LABELS[role()]||role())}</strong></p><p><span>路由</span><strong>DETERMINISTIC · OFFLINE</strong></p><p><span>可见案件</span><strong>${state.cases.length}</strong></p><p><span>登记来源</span><strong>${sources().length}</strong></p><p><span>待确认操作</span><strong>${state.action?1:0}</strong></p>`;}
function renderAgent() {
  if(window.LabCourtAgentChat)return window.LabCourtAgentChat.render({api,state,role,esc,short,pageHead,setRouteContent,agentQuickPrompts,agentActionMarkup,agentContextMarkup,toast,navigateTo});
  if(!state.agentMessages.length)state.agentMessages.push({kind:"agent",text:"我是安全运营 Agent。可以查询案件、设备、地图和离线知识；有权限的操作只会生成待确认卡，不会直接执行。",meta:"MODEL_USED=FALSE · NETWORK_USED=FALSE"});
  const messages=state.agentMessages.map(agentMessageMarkup).join("");
  setRouteContent(`${pageHead("DETERMINISTIC OPERATIONS AGENT","安全运营 Agent","严格意图路由连接现有 authority。查询可立即返回，操作必须经过确认并由业务接口再次校验权限和版本。")}<div class="agent-workspace"><section class="agent-console"><div class="agent-console-head"><span><i></i>OFFLINE ROUTER READY</span><small>模型未使用 · 网络未使用</small></div><div id="agent-messages" class="agent-messages" aria-live="polite">${messages}<div id="agent-action-host">${agentActionMarkup()}</div></div><div class="agent-quick-list">${agentQuickPrompts().map(([prompt,text])=>`<button type="button" class="agent-quick" data-agent-quick="${esc(prompt)}">${esc(text)} <i>↗</i></button>`).join("")}</div><form class="agent-composer" data-agent-form><label for="agent-query" class="sr-only">查询或操作意图</label><textarea id="agent-query" maxlength="512" rows="2" placeholder="查询当前案件，或输入明确操作意图…"></textarea><button type="submit" data-action="agent-query" aria-label="发送给 Agent">发送 <i>→</i></button></form></section><aside class="agent-context"><header><span class="agent-mark">A</span><div><p class="eyebrow">LIVE CONTEXT</p><h2>当前上下文</h2></div></header><div id="agent-context-facts">${agentContextMarkup()}</div><footer>操作卡本身不写数据库<br>确认后仍由后端执行 RBAC 与版本校验</footer></aside></div><div id="agent-confirm-modal" class="agent-modal" hidden><div class="agent-modal__backdrop" data-action="close-agent-confirm"></div><section role="dialog" aria-modal="true" aria-labelledby="agent-confirm-title"><p class="eyebrow">HUMAN CONFIRMATION</p><h2 id="agent-confirm-title">确认执行操作卡？</h2><p data-agent-confirm-copy>${esc(state.action?.impact_summary||"")}</p><code data-agent-confirm-ref>${state.action?`${esc(state.action.target_ref)} · V${state.action.current_version}`:""}</code><div class="form-actions"><button type="button" class="button quiet" data-action="close-agent-confirm">取消</button><button type="button" class="button primary" data-action="confirm-agent">确认并交给业务接口</button></div></section></div>`,{announcement:"安全运营 Agent"});
}

function renderProfile() {
  const authority=state.session.authority;
  const reservations=state.reservations.map(item=>`<article class="profile-shortcut card"><h3>${esc(item.location_id)}</h3><p>${esc(item.association_notice)} · ${esc(item.starts_at)} → ${esc(item.ends_at)}</p></article>`).join("")||empty("没有可见预约","当前角色没有预约 authority。");
  setRouteContent(`${pageHead("SESSION AUTHORITY","我的资料","角色、范围和能力全部来自服务端 session 投影；切换角色会清除当前标签页令牌。",`<a class="button" href="/login" data-action="switch-role">切换演示角色</a>`)}<div class="profile-grid"><section class="panel"><div class="facts"><div class="fact"><span>角色</span><strong>${esc(ROLE_LABELS[authority.role])}</strong></div><div class="fact"><span>主体</span><strong>${esc(authority.actor_id)}</strong></div><div class="fact"><span>范围</span><strong>${esc(authority.scope_kind)}</strong></div><div class="fact"><span>版本</span><strong>V${authority.authority_revision}</strong></div></div><h2 class="section-title">能力</h2><div class="quick-list">${authority.capabilities.map(value=>`<span class="badge">${esc(value)}</span>`).join("")}</div><h2 class="section-title">预约与关联</h2>${reservations}</section><aside class="panel"><h2 class="section-title">Demo 边界</h2><p>personal_demo_only=true</p><p>production_ready=false</p><p>令牌位置：sessionStorage</p><p>网络模型调用：真实模式可调用已配置的 Qwen3-VL；来源随场景记录展示</p></aside></div>`,{announcement:"我的资料"});
}

function feishuSettingsMarkup() {
  const value=state.feishu;if(!value)return empty("消息平台状态不可见","后端没有返回飞书平台投影，页面不会显示已连接。");
  const missing=[...(value.missing_evidence_kinds||[]),...(value.failed_evidence_kinds||[]),...(value.expired_evidence_kinds||[])];
  const last=value.last_audited_attempt;
  const runtime=state.feishuRuntime,route=state.feishuRoute;
  const runtimeItems=[
    ["长连接",runtime?.connection?.connection_state||"未运行"],
    ["Agent worker",runtime?.authority_worker?.worker_state||"未运行"],
    ["发送 worker",runtime?.delivery_worker?.worker_state||"未运行"],
  ];
  const liveAction=role()==="OPERATIONS"&&runtime?.live_dispatch_available&&route?`<button class="button primary" type="button" data-action="feishu-live-test">发送真实测试卡</button>`:"";
  const checkAction=role()==="OPERATIONS"&&value.test_card_check_available?`<button class="button quiet" type="button" data-action="feishu-test-check">仅检查配置</button>`:"";
  return `<section class="message-platform feishu-live-settings"><header><div><p class="eyebrow">MESSAGE PLATFORM</p><h2>飞书</h2></div><span class="integration-state ${runtime?.live_dispatch_available?"active":""}">${runtime?.live_dispatch_available?"可发送":esc(value.display_status)}</span></header><div class="integration-default"><div><span>默认通道</span><strong>${esc(value.default_channel)}</strong></div><p>本地通知仍是默认通道；真实飞书只有在下方全部就绪时才可发送。</p></div><div class="feishu-runtime-grid">${runtimeItems.map(([name,status])=>`<div><span>${name}</span><strong>${esc(status)}</strong><i class="${["READY"].includes(status)?"ready":""}"></i></div>`).join("")}</div><div class="integration-facts"><p><span>应用状态</span><strong>${esc(value.display_status)}</strong></p><p><span>激活版本</span><strong>${value.activation_revision?`V${value.activation_revision}`:"—"}</strong></p><p><span>接收人绑定</span><strong>${value.recipient_binding_count}</strong></p><p><span>入站状态</span><strong>${esc(value.inbound_status)}</strong></p><p><span>值班安全管理员</span><strong>${route?esc(route.actor_id):"未设置"}</strong></p><p><span>值班路由</span><strong>${route?`V${route.route_revision}`:"—"}</strong></p></div>${missing.length?`<div class="integration-blocked"><strong>还不能启用</strong><p>${missing.map(esc).join(" · ")}</p></div>`:""}${last?`<div class="integration-attempt"><span>最近发送</span><strong>${esc(last.disposition)}</strong><code>${short(last.notification_id)}</code><small>${last.disposition==="UNKNOWN_DELIVERY"?"结果不确定，不会自动重试":"发送结果来自审计回执"}</small></div>`:`<p class="help">还没有发送记录。</p>`}<div class="form-actions">${liveAction}${checkAction}</div><footer>${runtime?.live_dispatch_available?"真实发送已经具备当前 authority；每次仍需人工确认。":"请先完成应用激活、接收人绑定、值班路由并启动三个 worker。"}</footer></section>`;
}

function renderSettings() {
  const requested=new URL(location.href).searchParams.get("section");if(["messages","models","devices","rules","users"].includes(requested))state.settingsSection=requested;
  const ops=role()==="OPERATIONS";
  const userRows=(state.users||[]).map(item=>{const a=item.authority||item;return `<tr><td>${esc(a.actor_id)}</td><td>${esc(a.role)}</td><td>${esc(a.scope_kind)}</td><td>V${a.authority_revision}</td></tr>`}).join("");
  const reset=ops?`<section class="panel"><div class="panel-head"><h2>演示现场复位</h2><span>OPERATIONS ONLY</span></div><p>复位会将当前数据库和演示回执归档到 session 目录，再原子替换为无案件、无告警的标准现场。历史不会删除。</p><button class="button alarm" type="button" data-action="reset">确认归档并一键复位</button></section>`:"";
  const lastCall=state.run?state.run.state==="FAILED"?runFailureExplanation(state.run):state.run.state==="RUNNING"?"最近实际调用：运行中。":"最近实际调用：已完成；结果以该运行的阶段和产物为准。":"最近实际调用：尚无运行记录。";
  const modelStatus=state.readiness?`<section class="model-readiness"><p class="eyebrow">MODEL CONFIGURATION</p>${state.readiness.components.map(item=>`<div><span class="readiness-dot ${item.ready?"ready":""}"></span><b>${esc(item.component)}</b><span>${esc(item.model)}</span><small>${item.ready?"配置就绪":esc(item.failure_code)}</small></div>`).join("")}<p class="help">“配置就绪”只表示本地依赖或云端参数已经提供，不代表远端服务当前在线。失败不会自动替换为演示结果。</p><p class="help">${esc(lastCall)}</p></section>`:"";
  const sections={messages:feishuSettingsMarkup(),models:`${modelStatus||empty("模型状态不可见","当前角色无模型 readiness 读取权限。")} ${reset}`,devices:`<div class="panel-head"><h2>来源与接口</h2><span>${sources().length} REGISTERED</span></div><div class="table-wrap"><table class="table"><thead><tr><th>设备</th><th>类型</th><th>适配器</th><th>状态</th></tr></thead><tbody>${sources().map(x=>`<tr><td>${esc(x.source.device_id)}</td><td>${esc(x.source.sensor_type||x.source.source_kind)}</td><td>${esc(x.source.adapter_id)}</td><td>${esc(x.observation_state)}</td></tr>`).join("")}</tbody></table></div>`,rules:`<section class="panel"><div class="panel-head"><h2>规则状态</h2><span>SERVER AUTHORITY</span></div><p>${state.rules?`当前规则修订 V${esc(state.rules.revision||state.rules.authority_revision||"—")}`:"当前角色无规则读取权限"}</p><p class="help">烟雾与温度联动由后端规则生成 EMERGENCY，不通过页面属性伪造。</p></section>`,users:`<div class="panel-head"><h2>用户权限</h2><span>${state.users?state.users.length:"ROLE-SCOPED"}</span></div>${state.users?`<div class="table-wrap"><table class="table"><thead><tr><th>用户</th><th>角色</th><th>范围</th><th>版本</th></tr></thead><tbody>${userRows}</tbody></table></div>`:empty("权限清单不可见","当前角色不具备用户权限管理能力。")}`};
  state.settingsPanels=sections;
  setRouteContent(`${pageHead("PLATFORM SETTINGS","消息平台、设备、规则与权限","只显示具备真实读取或执行接口的设置；飞书状态来自当前 authority 投影。")}<div class="settings-layout"><nav class="settings-nav" aria-label="设置分区">${[["messages","消息平台"],["models","模型与复位"],["devices","设备来源"],["rules","规则"],["users","用户权限"]].map(([key,text])=>`<button type="button" data-settings-section="${key}" class="${state.settingsSection===key?"active":""}" aria-current="${state.settingsSection===key}">${text}</button>`).join("")}</nav><section class="settings-panel">${sections[state.settingsSection]||sections.messages}</section></div>`,{announcement:"平台设置"});
}

function patchSettingsSection(section,{historyMode="push"}={}) {
  if(!state.settingsPanels||!["messages","models","devices","rules","users"].includes(section))return false;state.settingsSection=section;
  if(historyMode){const url=new URL(location.href);url.searchParams.set("section",section);history[historyMode==="replace"?"replaceState":"pushState"]({labcourt:{key:crypto.randomUUID(),ui:captureEntry()}},"",`${url.pathname}${url.search}`);state.currentRoute=`${url.pathname}${url.search}`;}
  document.querySelectorAll("[data-settings-section]").forEach(node=>{const selected=node.dataset.settingsSection===section;node.classList.toggle("active",selected);node.setAttribute("aria-current",String(selected));});
  const panel=document.querySelector(".settings-panel");if(!panel)return false;panel.classList.remove("is-updating");panel.innerHTML=state.settingsPanels[section];requestAnimationFrame(()=>panel.classList.add("is-updating"));return true;
}

function captureEntry(){const video=document.getElementById("recorded-video"),evidenceVideo=document.getElementById("evidence-source-video");if(video)state.videoPositions.set("recorded-video",video.currentTime);if(evidenceVideo)state.videoPositions.set("evidence-source-video",evidenceVideo.currentTime);return {scrollX,scrollY,videoTime:video?.currentTime||state.videoPositions.get("recorded-video")||0,evidenceVideoTime:evidenceVideo?.currentTime||state.videoPositions.get("evidence-source-video")||0};}
function persistEntry(){history.replaceState({...history.state,labcourt:{...(history.state?.labcourt||{}),ui:captureEntry()}},"",location.href);}
async function navigateTo(target,{replace=false,restore=null}={}){persistEntry();const url=new URL(target,location.href);history[replace?"replaceState":"pushState"]({labcourt:{key:crypto.randomUUID(),ui:restore}},"",`${url.pathname}${url.search}${url.hash}`);await renderRoute({restore});}

async function renderRoute({restore=null}={}) {
  const routeId=++state.routeSequence;state.routeController?.abort();const controller=new AbortController();state.routeController=controller;const path=location.pathname;
  if(path==="/"){state.shellMounted=false;renderHome();if(restore)requestAnimationFrame(()=>scrollTo(restore.scrollX||0,restore.scrollY||0));return}if(path==="/login"){state.shellMounted=false;renderLogin();return}
  if(!state.token){await navigateTo("/login",{replace:true});return}
  try {
    if(!state.session){app.innerHTML=`${publicRibbon()}<main class="boot-state"><span class="spinner"></span><p>正在读取角色 authority…</p></main>`;await loadCore(controller.signal);}
    if(routeId!==state.routeSequence||controller.signal.aborted)return;ensureShell();
    if(path==="/app/settings"){[state.users,state.rules]=await Promise.all([optional("/api/m8/users",null,{signal:controller.signal}),optional("/api/m8/rules",null,{signal:controller.signal})]);}
    if(path==="/app/knowledge")state.knowledgeCatalog=await api("/api/m8/knowledge/catalogs/campus-safety-knowledge",{signal:controller.signal});
    if(routeId!==state.routeSequence||controller.signal.aborted)return;
    if(path==="/app/monitor")renderMonitor();else if(path==="/app/cases")renderCases();else if(path.startsWith("/app/cases/"))await renderCaseDetail(decodeURIComponent(path.split("/").pop()));else if(path==="/app/map")renderMap();else if(path==="/app/notifications")renderNotifications();else if(path.startsWith("/app/notifications/"))await renderNotificationConversation(decodeURIComponent(path.split("/").pop()));else if(path==="/app/knowledge")await renderKnowledge();else if(path==="/app/agent")await renderAgent();else if(path==="/app/profile")renderProfile();else if(path==="/app/settings")renderSettings();else{await navigateTo("/app/monitor",{replace:true});return;}
    state.currentRoute=`${path}${location.search}`;if(restore){state.videoPositions.set("recorded-video",restore.videoTime||0);state.videoPositions.set("evidence-source-video",restore.evidenceVideoTime||0);requestAnimationFrame(()=>scrollTo(restore.scrollX||0,restore.scrollY||0));}if(state.run?.state==="RUNNING")schedulePoll();
  } catch(error){if(error.name!=="AbortError"&&routeId===state.routeSequence)errorPage(error)}
}

async function refresh(message) { await loadCore(); await renderRoute(); if(message)toast(message); }
async function hashManifest(text) { const bytes=new TextEncoder().encode(text); const digest=await crypto.subtle.digest("SHA-256",bytes); return [...new Uint8Array(digest)].map(v=>v.toString(16).padStart(2,"0")).join(""); }
async function transitionCase(caseId,descriptor,extraAuthorities=[],expected=null) {
  const [action,resolution]=descriptor.split(":"); const item=await api(`/api/m8/cases/${caseId}`); const authority=caseAuthority(item); const reason=document.getElementById("case-reason")?.value?.trim()||"本人确认按演示流程提交此状态变更。";
  if(expected&&(item.case_version!==expected.version||item.case_document_sha256!==expected.fence))throw new Error("CONCURRENT_MODIFICATION");
  const reasonCodes={CONFIRM:"VERIFIED_VIOLATION",REJECT:"FALSE_POSITIVE",REQUEST_EVIDENCE:"MORE_EVIDENCE_REQUIRED",RETURN_TO_VERIFICATION:"EVIDENCE_RECEIVED",RESOLVE:"HAZARD_CLEARED",SUBMIT_APPEAL:"SUBJECT_DISPUTE",RESOLVE_APPEAL:resolution==="OVERTURNED"?"APPEAL_OVERTURNED":"APPEAL_UPHELD"};
  const refs=[...(authority.create_command.trigger_authorities||[]),...extraAuthorities].sort((a,b)=>`${a.kind}|${a.authority_id}|${a.document_sha256}`.localeCompare(`${b.kind}|${b.authority_id}|${b.document_sha256}`));
  const payload={source_case_version:item.case_version,source_case_authority_sha256:item.case_document_sha256,source_status:item.status,case_location_id:authority.location_id,subject_actor_id:authority.subject_actor_id,action,reason_code:reasonCodes[action],reason_summary:reason,supporting_authorities:refs,appeal_resolution:action==="RESOLVE_APPEAL"?resolution:null,explicit_human_confirmation:true,command_manifest_id:await hashManifest("labcourt-platform-ui-human-command-v1")};
  return api(`/api/m8/cases/${caseId}/transitions`,{method:"POST",body:payload});
}

function patchKnowledgeDocumentList() {
  const host=document.getElementById("knowledge-document-list");if(host)host.innerHTML=knowledgeDocumentListMarkup();
}

function patchKnowledgeFilter(nextType,{historyMode="push"}={}) {
  if(!["ALL",...knowledgeTypes()].includes(nextType))return false;state.knowledgeFilter=nextType;
  document.querySelectorAll("[data-knowledge-type]").forEach(node=>{const active=node.dataset.knowledgeType===nextType;node.classList.toggle("active",active);node.setAttribute("aria-pressed",String(active));});patchKnowledgeDocumentList();
  if(historyMode){const url=new URL(location.href);url.searchParams.set("type",nextType);if(state.knowledgeSelected)url.searchParams.set("doc",state.knowledgeSelected);history[historyMode==="replace"?"replaceState":"pushState"]({labcourt:{key:crypto.randomUUID(),ui:captureEntry()}},"",`${url.pathname}${url.search}`);state.currentRoute=`${url.pathname}${url.search}`;}return true;
}

async function submitKnowledgeQuery(button) {
  const input=document.getElementById("knowledge-query"),query=input?.value.trim();if(!query)return;button.disabled=true;button.setAttribute("aria-busy","true");button.textContent="查询中…";
  const answerHost=document.getElementById("knowledge-answer");if(answerHost)answerHost.innerHTML=`<div class="kb-answer-loading"><span class="spinner"></span><p>正在当前离线目录中检索…</p></div>`;
  try {const projection=await api("/api/m8/knowledge/catalogs/campus-safety-knowledge/query-projections",{method:"POST",body:knowledgeQueryPayload(query)}),answer=projection.answer_receipt.answer;state.knowledgeAnswer=projection;
    const hits=(projection.document_hits||[]).map((item,index)=>`<details ${index===0?"open":""}><summary>${index+1}. ${esc(item.document_type)} · ${esc(item.logical_document_id)} · V${item.document_version}</summary><blockquote>${esc(item.exact_snippet)}</blockquote><code>${esc(item.source_ref)} · ${new Date(item.effective_at).toLocaleDateString("zh-CN")} · ${short(item.citation_id)} · [${item.start_char}, ${item.end_char})</code></details>`).join("");
    const memory=projection.case_memory,entries=(memory.entries||[]).map(item=>`<article><strong>${esc(item.summary)}</strong><code>${short(item.case_authority_id)} · V${item.case_version} · ${short(item.audit_event_id)}</code></article>`).join("");
    const explain=`<div class="kb-explain"><div><span>归一化意图</span><strong>${esc(projection.normalized_intent)}</strong></div><div><span>实际文档过滤</span><strong>${projection.applied_document_types.map(esc).join(" · ")}</strong></div><div><span>结果</span><strong>${esc(projection.outcome)}</strong></div></div>`;
    const memoryMarkup=`<section class="kb-memory"><header><p class="eyebrow">SEPARATE CASE MEMORY</p><h4>案例记忆 / 会审先例边界</h4></header>${entries||`<p>${memory.availability==="NO_PLATFORM_AUTHORITY"?"当前没有可引用的平台化 Case authority。":"本次没有命中持久化终态案件。"}</p>`}<small>机器弱标签不是 ground truth · 历史案件不能自动改写当前规则</small></section>`;
    if(answerHost)answerHost.innerHTML=`<header><p class="eyebrow">${esc(answer.outcome)} · MODEL_USED=${String(answer.model_used).toUpperCase()}</p><h3>${answer.outcome==="NO_MATCH"?"当前目录无匹配":"离线严格回答"}</h3></header>${explain}<p class="kb-answer-text">${esc(answer.answer_text)}</p>${hits?`<div class="kb-citations">${hits}</div>`:"<p class=\"help\">没有生成引用，也没有执行任何案件操作。</p>"}${memoryMarkup}<div class="kb-agent-handoff"><a class="button" href="/app/agent?q=${encodeURIComponent(query)}">交给 Agent 结合平台上下文解释 →</a><small>Agent 仍调用同一 exact-citation 检索，不建立第二套知识库。</small></div>`;
  } finally {button.disabled=false;button.removeAttribute("aria-busy");button.textContent="查询";}
}

function appendAgentMessage(message) {
  const host=document.getElementById("agent-messages"),actionHost=document.getElementById("agent-action-host");if(!host||!actionHost)return;actionHost.insertAdjacentHTML("beforebegin",agentMessageMarkup(message));host.scrollTop=host.scrollHeight;
}
function patchAgentChrome() {const actionHost=document.getElementById("agent-action-host"),facts=document.getElementById("agent-context-facts");if(actionHost)actionHost.innerHTML=agentActionMarkup();if(facts)facts.innerHTML=agentContextMarkup();}
async function submitAgentQuery(button) {
  const input=document.getElementById("agent-query"),query=input?.value.trim();if(!query)return;button.disabled=true;button.setAttribute("aria-busy","true");
  const userMessage={kind:"user",text:query,meta:ROLE_LABELS[role()]};state.agentMessages.push(userMessage);appendAgentMessage(userMessage);input.value="";
  const actionHost=document.getElementById("agent-action-host");actionHost?.insertAdjacentHTML("beforebegin",`<div id="agent-typing" class="agent-typing" role="status" aria-label="Agent 正在查询"><i></i><i></i><i></i><span>正在读取 authority</span></div>`);
  try {const answer=await api("/api/m8/agent/queries",{method:"POST",body:{query}}),message={kind:"agent",text:answer.answer,meta:`${answer.outcome} · ${answer.normalized_intent} · MODEL_USED=${answer.model_used} · NETWORK_USED=${answer.network_used}`,source_refs:answer.source_refs};document.getElementById("agent-typing")?.remove();state.agentMessages.push(message);appendAgentMessage(message);state.action=answer.proposed_action;patchAgentChrome();}
  finally {document.getElementById("agent-typing")?.remove();button.disabled=false;button.removeAttribute("aria-busy");input?.focus();}
}
function openAgentConfirmation(trigger) {if(!state.action)return;const modal=document.getElementById("agent-confirm-modal");if(!modal)return;state.confirmationTrigger=trigger;state.confirmationOpen=true;modal.hidden=false;requestAnimationFrame(()=>modal.classList.add("is-open"));modal.querySelector("[data-agent-confirm-copy]").textContent=state.action.impact_summary;modal.querySelector("[data-agent-confirm-ref]").textContent=`${state.action.target_ref} · V${state.action.current_version} · ${short(state.action.current_fence)}`;modal.querySelector("[data-action=confirm-agent]")?.focus();}
function closeAgentConfirmation() {const modal=document.getElementById("agent-confirm-modal");if(!modal)return;modal.classList.remove("is-open");state.confirmationOpen=false;setTimeout(()=>{modal.hidden=true;state.confirmationTrigger?.focus();state.confirmationTrigger=null;},matchMedia("(prefers-reduced-motion: reduce)").matches?0:180);}

async function handleClick(event) {
  const target=event.target.closest("button,a"); if(!target)return;
  if(target.dataset.roleSelect){patchLoginRole(target.dataset.roleSelect);return;}
  if(target.dataset.login){event.preventDefault();target.disabled=true;target.setAttribute("aria-busy","true");const copy=target.querySelector("[data-login-button-copy]");if(copy)copy.textContent="正在建立安全会话…";try{const response=await api("/api/m8/demo/login",{method:"POST",body:{role:target.dataset.login}});state.token=response.bearer_token;state.session=null;sessionStorage.setItem(TOKEN_KEY,state.token);document.body.classList.add("login-authorizing");setTimeout(()=>{document.body.classList.remove("login-authorizing");state.shellMounted=false;navigateTo("/app/monitor",{replace:true});},720);}catch(error){target.disabled=false;target.removeAttribute("aria-busy");if(copy)copy.textContent="重新尝试进入";toast(error.message,"error");}return;}
  if(target.dataset.action==="logout"){logout();return} if(target.dataset.action==="switch-role"){event.preventDefault();logout();return} if(target.dataset.action==="reload"){state.session=null;renderRoute();return}
  try {
    if(target.dataset.action==="nav-toggle"){state.navOpen=!state.navOpen;target.setAttribute("aria-expanded",String(state.navOpen));document.getElementById("primary-nav")?.classList.toggle("is-open",state.navOpen);return;}
    if(target.dataset.caseFilter){patchCasesFilter(target.dataset.caseFilter);return;}
    if(target.dataset.settingsSection){patchSettingsSection(target.dataset.settingsSection);return;}
    if(target.dataset.evidenceStage){patchEvidenceStage(target.dataset.evidenceStage);return;}
    if(target.dataset.evidenceCard){patchEvidenceStage("crops",target.dataset.evidenceCard);return;}
    if(target.dataset.evidenceLocate){patchEvidenceStage("localization",target.dataset.evidenceLocate);return;}
    if(target.dataset.agentQuick){const input=document.getElementById("agent-query");input.value=target.dataset.agentQuick;input.focus();return;}
    if(target.dataset.mapFloor){patchMapSelection({floor:target.dataset.mapFloor});return;}
    if(target.dataset.location){patchMapSelection({location:target.dataset.location});return;}
    if(target.dataset.knowledgeType){patchKnowledgeFilter(target.dataset.knowledgeType);return;}
    if(target.dataset.knowledgeDoc){await selectKnowledgeDocument(target.dataset.knowledgeDoc);return;}
    if(target.dataset.scenario){target.disabled=true;target.setAttribute("aria-busy","true");const payload={scenario_kind:target.dataset.scenario,explicit_human_confirmation:true};if(target.dataset.scenario==="PPE_GOGGLES_MISSING")payload.recognition_mode=target.dataset.mode||"FULL_MODEL";if(target.dataset.retry)payload.retry_of_run_id=target.dataset.retry;state.run=await api("/api/m8/demo/scenario-runs",{method:"POST",body:payload});patchRunUi();schedulePoll();toast(payload.recognition_mode==="FULL_MODEL"?"真实识别已启动，进度将在本页连续更新":"演示模式已明确启动，并创建了独立运行记录");return;}
    if(target.dataset.transition){target.disabled=true;await transitionCase(target.dataset.case,target.dataset.transition);await refresh("案件状态已由服务端状态机更新");return;}
    if(target.dataset.dispatch){target.disabled=true;await api(`/api/m8/cases/${target.dataset.case}/notification-dispatches`,{method:"POST",body:{kind:target.dataset.dispatch,explicit_human_confirmation:true}});await refresh("新通知卡已通过本地模拟通道送达");return;}
    if(target.dataset.confirmDispatch){if(!confirm("这会在当前案件会话中新增一条通知，原消息不会被覆盖。确认再次发送吗？"))return;target.disabled=true;await api(`/api/m8/cases/${target.dataset.case}/notification-dispatches`,{method:"POST",body:{kind:target.dataset.confirmDispatch,explicit_human_confirmation:true}});await refresh("新的后续通知已加入同一案件会话");return;}
    if(target.dataset.conversationReply){const box=document.getElementById("conversation-reply"),body=box?.value?.trim();if(!body){toast("请先填写正文","error");return}target.disabled=true;const kind=target.dataset.conversationReply==="SUBMIT_APPEAL"?"APPEAL_REQUEST":"EXPLANATION";const receipt=await api(`/api/m8/notifications/${target.dataset.notification}/replies`,{method:"POST",body:{reply_kind:kind,body,explicit_human_confirmation:true}});if(kind==="APPEAL_REQUEST"){const reply=receipt.audit_event?.transition_command?.reply;if(!reply)throw new Error("申诉正文已保存，但回复 authority 暂不可读取");try{await transitionCase(target.dataset.case,"SUBMIT_APPEAL",[{kind:"NOTIFICATION_REPLY",authority_id:reply.reply_authority_id,document_sha256:reply.reply_document_sha256}]);}catch(error){await refresh(`申诉正文已保存，案件状态尚未提交；会话中提供重试动作：${error.message}`);return;}}await refresh(kind==="APPEAL_REQUEST"?"申诉正文与案件状态已记录":"情况说明已保存到案件会话");return;}
    if(target.dataset.retryAppeal){target.disabled=true;await transitionCase(target.dataset.retryAppeal,"SUBMIT_APPEAL",[{kind:"NOTIFICATION_REPLY",authority_id:target.dataset.authority,document_sha256:target.dataset.document}]);await refresh("已使用原申诉正文 authority 完成案件状态提交");return;}
    if(target.dataset.reply){const box=document.getElementById(`reply-${target.dataset.notification}`);const body=box?.value?.trim();if(!body){toast("请先填写正文","error");return}target.disabled=true;const receipt=await api(`/api/m8/notifications/${target.dataset.notification}/replies`,{method:"POST",body:{reply_kind:target.dataset.reply,body,explicit_human_confirmation:true}});if(target.dataset.reply==="APPEAL_REQUEST"){const reply=receipt.audit_event?.transition_command?.reply;if(!reply)throw new Error("回复已记录，但回复 authority 尚不可读取，请重试案件申诉步骤");try{await transitionCase(target.dataset.case,"SUBMIT_APPEAL",[{kind:"NOTIFICATION_REPLY",authority_id:reply.reply_authority_id,document_sha256:reply.reply_document_sha256}]);}catch(error){await refresh(`申诉回复已记录；案件提交未完成，可从案件页重试：${error.message}`);return;}}await refresh(target.dataset.reply==="APPEAL_REQUEST"?"申诉回复与案件申诉状态均已记录":"说明已记录，原通知未被改写");return;}
    if(target.dataset.ack){target.disabled=true;await api(`/api/m8/notifications/${target.dataset.ack}/acknowledgements`,{method:"POST",body:{explicit_human_confirmation:true}});await refresh("结果通知已确认");return;}
    if(target.dataset.action==="knowledge-query"){event.preventDefault();await submitKnowledgeQuery(target);return;}
    if(target.dataset.action==="agent-query"){event.preventDefault();await submitAgentQuery(target);return;}
    if(target.dataset.action==="feishu-test-check"){if(!state.feishu?.test_card_check_available)throw new Error("当前飞书 authority 不允许形成测试卡检查");if(!confirm("此操作只生成 CHECK_ONLY 收据，不联网、不发送真实飞书消息。是否继续？"))return;target.disabled=true;await api("/api/m8/integrations/feishu/test-card-checks",{method:"POST",body:{activation_revision:state.feishu.activation_revision,activation_status_id:state.feishu.activation_status_id,explicit_human_confirmation:true}});state.feishu=await api("/api/m8/integrations/feishu/status");renderSettings();toast("已生成 CHECK_ONLY 收据；没有真实消息发送");return;}
    if(target.dataset.action==="feishu-live-test"){const route=state.feishuRoute;if(!state.feishuRuntime?.live_dispatch_available||!route)throw new Error("飞书实时通道尚未全部就绪");if(!confirm("将向当前值班安全管理员发送一张真实测试卡。测试卡不是案件通知，且失败后不会自动重试。确认发送吗？"))return;target.disabled=true;await api("/api/m8/integrations/feishu/test-card-dispatches",{method:"POST",body:{activation_revision:route.activation_revision,activation_status_id:route.activation_status_id,duty_route_id:route.route_id,duty_route_revision:route.route_revision,explicit_human_confirmation:true}});await loadCore();renderSettings();toast("真实测试卡调用已完成，请以飞书和审计回执为准");return;}
    if(target.dataset.action==="open-agent-confirm"){openAgentConfirmation(target);return;}
    if(target.dataset.action==="close-agent-confirm"){closeAgentConfirmation();return;}
    if(target.dataset.action==="confirm-agent"){target.disabled=true;await executeAgentAction(state.action);closeAgentConfirmation();state.action=null;await loadCore();const message={kind:"agent",text:"操作卡已由既有业务接口重新校验并执行，当前上下文已同步。",meta:"CONFIRMED · SERVER REVALIDATED"};state.agentMessages.push(message);appendAgentMessage(message);patchAgentChrome();patchRunUi();toast("操作已完成");return;}
    if(target.dataset.action==="reset"){target.disabled=true;const result=await api("/api/m8/demo/reset",{method:"POST",body:{explicit_human_confirmation:true}});state.session=null;clearObjectUrls();await renderRoute();toast(`已复位到标准现场；归档 ${result.archive_ref}`);return;}
  } catch(error){target.disabled=false;target.removeAttribute("aria-busy");toast(error.message,"error");}
}

async function executeAgentAction(action) {
  if(!action)throw new Error("没有待确认操作");
  const {action_kind:_payloadKind,...payload}=action.request_payload;
  if(action.action_kind==="RUN_SCENARIO")return api(action.endpoint_path,{method:"POST",body:payload});
  if(action.action_kind==="RESET_DEMO")return api(action.endpoint_path,{method:"POST",body:payload});
  if(action.action_kind==="CASE_TRANSITION")return transitionCase(action.target_ref,payload.action,[],{version:action.current_version,fence:action.current_fence});
  if(action.action_kind==="NOTIFICATION_SEND")return api(action.endpoint_path,{method:"POST",body:payload});
  if(action.action_kind==="FEISHU_TEST_CARD_CHECK")return api(action.endpoint_path,{method:"POST",body:payload});
  throw new Error("操作卡类型不在闭合集合中");
}

document.addEventListener("click",event=>{
  const link=event.target.closest("a[href]");if(!link||event.defaultPrevented||event.button!==0||event.metaKey||event.ctrlKey||event.shiftKey||event.altKey||link.target&&link.target!=="_self"||link.hasAttribute("download")||link.dataset.action)return;
  const raw=link.getAttribute("href");if(!raw||raw.startsWith("#"))return;const url=new URL(link.href,location.href);if(url.origin!==location.origin)return;event.preventDefault();if(link.dataset.caseTab&&url.pathname===location.pathname){patchCaseTab(link.dataset.caseTab);return;}navigateTo(url);
},{capture:true});
document.addEventListener("click",handleClick);
document.addEventListener("submit",event=>{const form=event.target;if(form.matches("[data-login-form]")){event.preventDefault();form.querySelector("[data-login]")?.click();}else if(form.matches("[data-knowledge-form]")){event.preventDefault();form.querySelector("[data-action=knowledge-query]")?.click();}else if(form.matches("[data-agent-form]")){event.preventDefault();form.querySelector("[data-action=agent-query]")?.click();}});
document.addEventListener("input",event=>{if(event.target.id!=="knowledge-search")return;state.knowledgeSearch=event.target.value;patchKnowledgeDocumentList();});
document.addEventListener("keydown",event=>{const tab=event.target.closest('[role="tab"][data-case-tab]');if(!tab||!["ArrowLeft","ArrowRight"].includes(event.key))return;const tabs=[...tab.parentElement.querySelectorAll('[role="tab"][data-case-tab]')],next=tabs[(tabs.indexOf(tab)+(event.key==="ArrowRight"?1:-1)+tabs.length)%tabs.length];event.preventDefault();patchCaseTab(next.dataset.caseTab,{historyMode:"replace",focus:true});});
document.addEventListener("keydown",event=>{const tab=event.target.closest('[role="tab"][data-evidence-stage]');if(!tab||!["ArrowLeft","ArrowRight"].includes(event.key))return;const tabs=[...tab.parentElement.querySelectorAll('[role="tab"][data-evidence-stage]')],next=tabs[(tabs.indexOf(tab)+(event.key==="ArrowRight"?1:-1)+tabs.length)%tabs.length];event.preventDefault();patchEvidenceStage(next.dataset.evidenceStage,null,{historyMode:"replace",focus:true});});
document.addEventListener("keydown",event=>{if(event.key==="Escape"&&state.confirmationOpen){event.preventDefault();closeAgentConfirmation();return;}if(event.target.id==="agent-query"&&event.key==="Enter"&&(event.ctrlKey||event.metaKey)){event.preventDefault();document.querySelector("[data-action=agent-query]")?.click();}});
addEventListener("popstate",event=>{const priorPath=state.currentRoute.split("?")[0],path=location.pathname;if(path===priorPath){const query=new URL(location.href).searchParams;if(path==="/app/cases"&&patchCasesFilter((query.get("filter")||"ALL").toUpperCase(),{historyMode:null}))return;if(path==="/app/settings"&&patchSettingsSection(query.get("section")||"models",{historyMode:null}))return;if(path==="/app/map"&&patchMapSelection({floor:query.get("floor")||locations().find(item=>item.kind==="FLOOR")?.location_id,location:query.get("location"),historyMode:null}))return;if(path==="/app/knowledge"){const type=query.get("type")||"ALL",doc=query.get("doc")||knowledgeDocuments()[0]?.logical_document_id;if(patchKnowledgeFilter(type,{historyMode:null})&&doc){selectKnowledgeDocument(doc,{historyMode:null});return;}}if(path.startsWith("/app/cases/")&&query.get("tab")==="evidence"&&patchEvidenceStage(query.get("stage")||"replay",query.get("evidence"),{historyMode:null}))return;if(path.startsWith("/app/cases/")&&patchCaseTab(query.get("tab")||"overview",{historyMode:null}))return;}renderRoute({restore:event.state?.labcourt?.ui||null});});
document.addEventListener("visibilitychange",()=>{document.body.classList.toggle("is-page-hidden",document.hidden);if(document.hidden){clearTimeout(state.pollTimer);persistEntry();}else if(state.run?.state==="RUNNING")schedulePoll();});
addEventListener("scroll",()=>{if(!state.scrollSaveFrame)state.scrollSaveFrame=requestAnimationFrame(()=>{state.scrollSaveFrame=0;if(location.pathname.startsWith("/app/"))persistEntry();});},{passive:true});
if(!history.state?.labcourt)history.replaceState({labcourt:{key:crypto.randomUUID(),ui:null}},"",location.href);
renderRoute({restore:history.state?.labcourt?.ui||null});

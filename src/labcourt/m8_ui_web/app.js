"use strict";

const app = document.getElementById("app");
const TOKEN_KEY = "labcourt.platform.token";
const ROLE_LABELS = {LEADER:"校级领导",SAFETY_OFFICER:"安全负责人",STUDENT:"学生",OPERATIONS:"运维人员"};
const STATUS_LABELS = {PENDING_VERIFICATION:"等待人工核实",CONFIRMED:"已确认",REJECTED:"已排除",EVIDENCE_REQUESTED:"待补充证据",RESOLVED:"已结案",APPEALED:"申诉处理中",APPEAL_RESOLVED:"申诉已处理",DELIVERED:"已送达",RESPONDED:"已回复",ACKNOWLEDGED:"已确认"};
const STAGE_LABELS = {VIDEO:"录像",PERCEPTION:"视觉感知",EVIDENCE:"证据裁剪",SCREENING:"结构化初审",CASE:"规则建案",NOTIFICATION:"消息通知"};
const NAV = [["/app/monitor","监控"],["/app/cases","案件"],["/app/map","地图"],["/app/notifications","通知"],["/app/knowledge","知识库"],["/app/agent","Agent"],["/app/profile","我的"],["/app/settings","设置"]];
const state = {
  token:sessionStorage.getItem(TOKEN_KEY),session:null,cases:[],notifications:[],projection:null,
  cameras:[],reservations:[],run:null,readiness:null,users:null,rules:null,knowledgeCatalog:null,
  knowledgeAnswer:null,agentMessages:[],action:null,agentTyping:false,loginRole:"SAFETY_OFFICER",
  videoUrl:null,videoPromise:null,videoPositions:new Map(),evidenceUrls:[],pollTimer:null,
  pollFailures:0,pollInFlight:false,toastTimer:null,routeController:null,routeSequence:0,
  shellMounted:false,currentRoute:"",casesFilter:"ALL",knowledgeFilter:"ALL",knowledgeSelected:null,
  settingsSection:"models",mapFloor:null,mapLocation:null,confirmationOpen:false,navOpen:false,scrollSaveFrame:0,
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
  app.innerHTML=`<header class="landing-head"><div class="landing-wrap landing-head__in"><a class="landing-brand" href="/">LabCourt <small>校园实验室安全</small></a><nav aria-label="首页导航"><a href="#problem">现状</a><a href="#principles">原则</a><a href="#workflow">闭环</a><a href="#ethics">伦理</a></nav><a class="landing-cta" href="/login">进入平台 →</a></div></header>
  <main id="main-content" class="landing">
    <section class="landing-hero">
      <div class="landing-hero__media" data-parallax><video src="/api/m8/demo/public-media/recorded-video" autoplay muted loop playsinline preload="metadata"></video><div class="landing-grid" aria-hidden="true"></div></div>
      <span class="recorded-tag"><i></i>SIMULATED · RECORDED VIDEO</span>
      <div class="landing-hud" aria-hidden="true"><span></span><span></span><span></span><span></span><b>CAMERA-RECORDED-DEMO-01<br>NO VISUAL IDENTITY</b></div>
      <div class="landing-wrap landing-hero__content"><p class="landing-eyebrow"><b>LabCourt</b> · 海南大学 · 信通学院 · 校园实验室安全</p><h1>实验室的每一秒，<br>都值得被认真对待。</h1><p>录像与模拟传感器进入同一条可审计流程：真实模型识别、结构化取证、规则建案与人在环处置。不做人脸识别，AI 不自动定责。</p><div class="landing-actions"><a class="landing-button primary" href="/login">选择演示角色 →</a><a class="landing-button" href="#workflow">了解处理闭环</a></div></div>
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
    <section class="landing-final"><div class="landing-wrap reveal"><h2>走进控制台。</h2><p>切换四种角色，运行真实识别或明确标记的演示回退，亲自完成一条安全闭环。</p><div class="landing-actions"><a class="landing-button primary" href="/login">进入平台 →</a><a class="landing-button" href="#ethics">查看边界</a></div></div></section>
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
  <main id="main-content" class="login-shell"><section class="login-card" aria-labelledby="login-title"><a class="login-brand" href="/">LabCourt <small>校园实验室安全</small></a><p class="login-eyebrow">登录 · LOCAL ROLE SWITCH</p><h1 id="login-title">进入安全运营平台</h1><div class="login-roles" role="group" aria-label="选择演示角色">${roles.map(([key,title])=>`<button type="button" data-role-select="${key}" class="${key===selected[0]?"active":""}" aria-pressed="${key===selected[0]}">${title}</button>`).join("")}</div><div class="login-authority"><span>${esc(selected[0])}</span><strong>${esc(selected[1])}</strong><p>${esc(selected[2])}</p></div><button class="login-submit" type="button" data-login="${selected[0]}">以${esc(selected[1])}身份进入 →</button><p class="login-note">令牌仅存于当前标签页 · personal_demo_only=true<br>所有外发消息均标记 FAKE DELIVERY</p></section></main><div class="login-flash" aria-hidden="true"></div><div class="login-stamp" aria-hidden="true"><span>已授权<i>AUTHORIZED</i></span></div>`;
  initLoginMotion();
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

function currentNav(path) { return NAV.find(([href]) => path === href || (href === "/app/cases" && path.startsWith("/app/cases/")))?.[0]; }
function runStripMarkup() {
  const run=state.run;
  if(!run)return `<div id="global-run-strip" class="global-run-strip" hidden></div>`;
  const active=run.stages.find(item=>item.state==="RUNNING"||item.state==="FAILED")||run.stages.at(-1);
  const perception=run.stages.find(item=>item.stage==="PERCEPTION");
  const progress=perception?.total_units?perception.completed_units/perception.total_units:run.stages.filter(item=>item.state==="COMPLETE").length/run.stages.length;
  const frame=perception?.total_units?`${perception.completed_units} / ${perception.total_units} FRAME`:"AUTHORITY STAGES";
  const runClass=run.state==="SUCCEEDED"?"complete":run.state.toLowerCase();
  return `<div id="global-run-strip" class="global-run-strip is-${runClass}" style="--progress:${Math.max(0,Math.min(1,progress||0))}" aria-live="polite"><div class="run-strip__state"><span class="run-strip__summary">${run.state==="RUNNING"?"识别运行中":run.state==="FAILED"?"识别失败":"识别已完成"} · ${esc(STAGE_LABELS[active?.stage]||active?.stage||"等待")}</span></div><div><div class="run-strip__track"><i class="run-strip__fill"></i></div><div class="run-strip__stages" aria-hidden="true">${run.stages.map(item=>`<i class="run-strip__stage ${item.state==="RUNNING"?"is-active":item.state==="COMPLETE"?"is-complete":item.state==="FAILED"?"is-failed":""}">${esc(item.stage)}</i>`).join("")}</div></div><div class="run-strip__meta"><strong data-run-frame>${esc(frame)}</strong><span>${esc(run.recognition_mode||run.scenario_kind)}</span></div></div>`;
}

function alarmMarkup(){return isEmergency()?`<div class="alarm-banner" role="alert"><div><p class="eyebrow">EMERGENCY · SIMULATED SENSOR</p><strong>实验室 301 烟雾与高温信号联动</strong></div><a href="${state.run?.case_id?`/app/cases/${state.run.case_id}`:"/app/cases"}">查看案件 →</a></div>`:"";}

function ensureShell() {
  if(state.shellMounted&&document.getElementById("route-view"))return;
  const active=currentNav(location.pathname);
  app.innerHTML=`<div class="app-shell shell-frame">${publicRibbon()}<header class="shell-head"><div class="head-row"><a class="brand" href="/app/monitor">LabCourt<small>校园安全运营平台</small></a><button class="icon-button nav-toggle" type="button" data-action="nav-toggle" aria-expanded="false" aria-controls="primary-nav">菜单</button><nav id="primary-nav" class="nav" aria-label="主导航">${NAV.map(([href,text])=>`<a href="${href}" ${active===href?'aria-current="page"':""}>${text}</a>`).join("")}</nav><div class="head-actions"><span class="role-chip"><span>${esc(ROLE_LABELS[role()]||role())}</span></span><button class="icon-button" type="button" data-action="logout" aria-label="退出当前角色">退出</button></div></div></header><div id="alarm-host">${alarmMarkup()}</div><div id="run-strip-host">${runStripMarkup()}</div><main id="main-content" class="page"><div id="route-view" class="route-view"></div></main><p class="route-live-region sr-only" aria-live="polite"></p></div>`;
  state.shellMounted=true;
}

function patchShell() {
  if(!state.shellMounted)return;
  const active=currentNav(location.pathname);
  document.querySelectorAll(".nav a").forEach(link=>{const current=new URL(link.href).pathname===active;if(current)link.setAttribute("aria-current","page");else link.removeAttribute("aria-current");});
  const alarm=document.getElementById("alarm-host");if(alarm)alarm.innerHTML=alarmMarkup();
  const strip=document.getElementById("run-strip-host");if(strip)strip.innerHTML=runStripMarkup();
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
  const [cases,notifications,projection,cameras,reservations,run,readiness]=await Promise.all([
    optional("/api/m8/cases",[],options),optional("/api/m8/notifications",[],options),optional("/api/m8/campuses/campus-demo/operations-projection",null,options),optional("/api/m8/cameras",[],options),optional("/api/m8/reservations",[],options),optional("/api/m8/demo/scenario-runs/current",null,options),optional("/api/m8/demo/model-readiness",null,options)
  ]);
  Object.assign(state,{cases,notifications,projection,cameras,reservations,run,readiness});
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
  const fallback=ops&&state.run?.state==="FAILED"&&state.run?.recognition_mode==="FULL_MODEL"?`<button class="button quiet" type="button" data-scenario="PPE_GOGGLES_MISSING" data-mode="DEMO_FIXTURE" data-retry="${esc(state.run.run_id)}">以演示模式重试（创建新运行）</button>`:"";
  const candidates=active.length?active.slice(0,4).map(item=>`<a class="candidate-card" href="/app/cases/${item.case_id}"><div><h3>${caseTitle(item)}</h3><p>${esc(caseAuthority(item)?.location_id)} · ${short(item.case_id)}</p></div><span class="candidate-card__state">${esc(label(item.status))}<br>查看卷宗 →</span></a>`).join(""):empty("暂无候选事件","标准现场没有活动案件；运行场景后会在这里出现入口。");
  const deviceCards=sources().map(item=>`<article class="device ${item.latest_sample_receipt?.sample?.value===true||item.source.sensor_type==="TEMPERATURE"&&Number(item.latest_sample_receipt?.sample?.value)>60000?"alert":""}"><div class="device-head"><h3>${esc(item.source.device_id)}</h3><span class="badge">${item.source.source_kind==="SENSOR"?"SIMULATED SENSOR":"RECORDED"}</span></div><strong>${esc(sourceValue(item))}</strong><small>${esc(item.source.sensor_type||item.source.mode)} · ${esc(item.observation_state)}</small></article>`).join("")||empty("设备不可见","当前角色不具备设备健康读取能力。");
  const eventFrame=state.run?.evidence?.[0]?.frame_index;const eventPosition=profile&&Number.isInteger(eventFrame)?Math.max(0,Math.min(100,eventFrame/profile.frame_count*100)):null;
  const content=`${pageHead("LIVE OPERATIONS","实时监控","演示校区 / 化学楼 / 三层 / 实验室 301。主画面用于巡看；证据、初审和处置集中在案件卷宗。",actions)}<div class="monitor-layout"><section class="monitor-workspace"><div class="panel-head"><h2>实验室 301 · 原始录像</h2><span>CAMERA-RECORDED-DEMO-01</span></div><div class="camera-main"><div class="video-stage ${state.run?.state==="RUNNING"?"is-recognizing":""}">${videoAllowed?`<video id="recorded-video" controls muted playsinline preload="metadata"></video>`:`<div class="video-placeholder">当前角色无录像读取权限</div>`}<span class="source-badge">SIMULATED · RECORDED VIDEO</span><span id="frame-counter" class="frame-counter">FRAME — / ${totalFrames}</span><div class="monitor-hud ${state.run?.state==="RUNNING"?"is-running":""}"><span class="monitor-hud__status">${state.run?.state==="RUNNING"?"识别运行中":"录像待机"}</span><b class="monitor-hud__stage">${esc(STAGE_LABELS[state.run?.stages?.find(item=>item.state==="RUNNING")?.stage]||state.run?.state||"READY")}</b></div></div><div class="camera-meta"><span>${esc(videoMeta)}</span><span>预约关联，非视觉身份识别</span></div></div><div class="camera-strip" aria-label="真实机位"><button class="camera-thumb active" type="button" aria-selected="true"><span class="camera-thumb__preview"></span><span><strong>实验室 301</strong><small>录像模拟机位 · 已选择</small></span></button></div><section class="monitor-timeline"><div class="panel-head"><h2>录像事件时间轴</h2><span>FRAME AUTHORITY</span></div><div class="timeline-rail">${eventPosition!==null?`<a class="timeline-event is-alert" href="${state.run?.case_id?`/app/cases/${state.run.case_id}?tab=evidence`:"/app/cases"}" style="left:${eventPosition}%" data-label="证据帧 ${eventFrame}" aria-label="查看证据帧 ${eventFrame}"></a>`:""}</div><p class="help">时间轴只使用真实录像帧索引与已生成证据；没有产物时不补造事件。</p></section></section><aside class="monitor-side"><section class="panel"><div class="panel-head"><h2>当前候选</h2><span>${active.length} CASES</span></div><div id="monitor-candidates" class="candidate-list">${candidates}</div>${state.run?.state==="FAILED"?`<p class="help risk">${esc(state.run.failure_code)} · 状态未伪装为成功</p>${fallback}`:""}</section><section><div class="panel-head"><h2>设备状态</h2><span>OPERATIONS PROJECTION</span></div><div id="monitor-devices" class="device-grid">${deviceCards}</div></section></aside></div>`;
  setRouteContent(content,{mount:()=>{if(videoAllowed)attachVideo();schedulePoll();},announcement:"实时监控"});
}

async function attachVideo() {
  const video=document.getElementById("recorded-video");if(!video)return;const saved=state.videoPositions.get("recorded-video")||0;
  try{if(!state.videoUrl){if(!state.videoPromise){const camera=state.cameras[0];state.videoPromise=api(camera.media_api_path,{binary:true,headers:{Range:"bytes=0-"}}).then(blob=>{state.videoUrl=URL.createObjectURL(blob);return state.videoUrl;});}await state.videoPromise;}if(!video.isConnected)return;video.src=state.videoUrl;}catch(error){state.videoPromise=null;toast(`录像读取失败：${error.message}`,"error");return;}
  const restore=()=>{if(saved)video.currentTime=Math.min(saved,Number.isFinite(video.duration)?video.duration:saved);};if(video.readyState>=1)restore();else video.addEventListener("loadedmetadata",restore,{once:true});
  video.addEventListener("timeupdate",()=>{state.videoPositions.set("recorded-video",video.currentTime);const counter=document.getElementById("frame-counter"),profile=state.run?.video_profile;if(counter&&profile)counter.textContent=`FRAME ${Math.min(profile.frame_count-1,Math.floor(video.currentTime*profile.fps_num/profile.fps_den))} / ${profile.frame_count}`;});
}

async function attachPerception() {
  const video=document.getElementById("perception-video"); if(!video)return;
  try { const blob=await api(state.run.perception_preview_url,{binary:true,headers:{Range:"bytes=0-"}}); const url=URL.createObjectURL(blob); state.evidenceUrls.push(url); video.src=url; }
  catch(error){video.replaceWith(Object.assign(document.createElement("p"),{className:"help risk",textContent:`感知预览尚未生成 · ${error.message}`}));}
}

async function attachEvidence() {
  for (const image of document.querySelectorAll("img[data-evidence]")) {
    try { const item=state.run.evidence.find(value=>value.evidence_id===image.dataset.evidence); const blob=await api(item.media_url,{binary:true}); const url=URL.createObjectURL(blob); state.evidenceUrls.push(url); image.src=url; image.hidden=false; image.previousElementSibling?.remove(); } catch(error){ image.parentElement.textContent=`尚未生成 · ${error.message}`; }
  }
}

function schedulePoll() {
  clearTimeout(state.pollTimer);if(document.hidden||state.pollInFlight||state.run?.state!=="RUNNING")return;
  const delay=state.pollFailures?[2000,4000,8000][Math.min(state.pollFailures-1,2)]:1000;
  state.pollTimer=setTimeout(async()=>{state.pollInFlight=true;const prior=state.run;try{const next=await api("/api/m8/demo/scenario-runs/current");state.pollFailures=0;state.run=next;patchRunUi();if(prior?.state==="RUNNING"&&next?.state!=="RUNNING")await refreshAfterRun(next);}catch(error){if(error.name!=="AbortError"){state.pollFailures+=1;toast(`进度同步暂时中断，正在自动重连：${error.message}`,"error");}}finally{state.pollInFlight=false;schedulePoll();}},delay);
}

function patchRunUi(){patchShell();const run=state.run;const hud=document.querySelector(".monitor-hud");if(hud){const active=run?.stages?.find(item=>item.state==="RUNNING"||item.state==="FAILED");hud.classList.toggle("is-running",run?.state==="RUNNING");hud.querySelector(".monitor-hud__status").textContent=run?.state==="RUNNING"?"识别运行中":run?.state==="FAILED"?"识别失败":"识别已完成";hud.querySelector(".monitor-hud__stage").textContent=STAGE_LABELS[active?.stage]||active?.stage||run?.state||"READY";}document.querySelector(".video-stage")?.classList.toggle("is-recognizing",run?.state==="RUNNING");}

async function refreshAfterRun(run){const [cases,notifications,projection]=await Promise.all([optional("/api/m8/cases",[]),optional("/api/m8/notifications",[]),optional("/api/m8/campuses/campus-demo/operations-projection",null)]);Object.assign(state,{cases,notifications,projection});if(location.pathname==="/app/monitor")renderMonitor();else patchShell();toast(run.state==="SUCCEEDED"?(run.case_id?"识别已完成，候选案件入口已出现":"识别已完成，未建立可行动风险"):"识别已结束，请查看失败阶段",run.state==="SUCCEEDED"?"success":"error");}

function caseTitle(item) { const command=caseCommand(item); return command?.risk_level==="EMERGENCY"?"烟雾与高温联动紧急事件":"护目镜缺失候选事件"; }
function caseList(items=state.cases) {
  if(!items.length)return empty("暂无可见案件","标准现场保持无活动案件；可由运维角色启动演示场景。")
  return `<div class="list">${items.map(item=>{const authority=caseAuthority(item);return `<a class="list-item" href="/app/cases/${item.case_id}"><div><h3>${caseTitle(item)}</h3><p>${esc(authority.location_id)} · ${short(item.case_id)} · V${item.case_version}</p></div><div class="status"><span class="badge ${authority.risk_level==="EMERGENCY"?"risk":""}">${esc(authority.risk_level)}</span><p>${esc(label(item.status))} →</p></div></a>`}).join("")}</div>`;
}

function renderCases() {
  const active=state.cases.filter(x=>!terminalCase(x.status)), archived=state.cases.filter(x=>terminalCase(x.status));
  const filters=[["ALL","全部",state.cases.length],["ACTIVE","进行中",active.length],["EMERGENCY","紧急",state.cases.filter(x=>caseAuthority(x)?.risk_level==="EMERGENCY").length],["ARCHIVED","已归档",archived.length]];
  let items=state.cases;if(state.casesFilter==="ACTIVE")items=active;if(state.casesFilter==="EMERGENCY")items=state.cases.filter(x=>caseAuthority(x)?.risk_level==="EMERGENCY");if(state.casesFilter==="ARCHIVED")items=archived;
  setRouteContent(`${pageHead("CASE CENTER","案件中心","案件来自服务端状态机。候选事件需经人工核实；机器输出不能直接产生处分。")}<div class="case-tabs" role="tablist" aria-label="案件筛选">${filters.map(([key,text,count])=>`<button class="case-tab" type="button" role="tab" data-case-filter="${key}" aria-selected="${state.casesFilter===key}">${text}<span class="case-tab-count">${count}</span></button>`).join("")}</div><section><div class="panel-head"><h2>${filters.find(x=>x[0]===state.casesFilter)?.[1]||"全部"}卷宗</h2><span>${items.length} CASES</span></div>${caseList(items)}</section>`,{announcement:"案件中心"});
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
  const evidence=(run.evidence||[]).map(item=>`<figure class="evidence"><div class="evidence-media"><span class="spinner"></span><img data-evidence="${esc(item.evidence_id)}" alt="${esc(item.role)} 证据裁剪" hidden></div><figcaption>${esc(item.role==="TEMPORAL"?"TEMPORAL · EYE-REGION FOCUS":item.role)} · FRAME ${item.frame_index} · ${esc(item.integrity)}</figcaption></figure>`).join("");
  if(section==="evidence")return evidence?`<div class="panel-head"><h2>已校验证据</h2><span>${run.evidence.length} ARTIFACTS</span></div><div class="evidence-grid">${evidence}</div>${run.perception_preview_url?`<div class="panel" style="margin-top:20px"><div class="video-stage"><video id="perception-video" controls muted playsinline></video><span class="source-badge">PILOT PERCEPTION ARTIFACT</span></div></div>`:""}`:empty("尚未生成证据","证据阶段完成后会显示全景、主体与眼部焦点裁剪。");
  return `<div class="hearing-grid"><article class="hearing-card"><p class="eyebrow">机器初审 · WEAK LABEL</p><strong class="dossier-decision">${esc(run.screening_decision||"尚未生成")}</strong><p>${esc(run.screening_summary||"结构化初审尚未生成。")}</p><small>机器输出不是事实或处分依据</small></article><article class="hearing-card"><p class="eyebrow">反证检查</p><strong>当前投影无独立反证 authority</strong><p>不把缺少独立反证引用误写为“已经证明不存在反证”。</p></article><article class="hearing-card"><p class="eyebrow">STRICT_CAUSAL 规则守门</p><strong>${esc(run.rule_judgment||"尚未生成")}</strong><p>后续合规不会抹除较早风险；规则只投影风险，不替人定责。</p></article><article class="hearing-card"><p class="eyebrow">人工复核</p><strong>${run.case_status&&run.case_status!=="PENDING_VERIFICATION"?"已有人工作出状态变更":"等待安全负责人确认"}</strong><p>处置动作集中在“处理”页签并再次校验版本。</p></article></div><div class="panel" style="margin-top:20px"><p class="eyebrow">MODEL / FIXTURE PROVENANCE</p>${components||empty("暂无模型来源","本场景没有模型调用。")}${run.raw_response_ref?`<p class="help mono">RAW · ${esc(run.raw_response_ref)}</p>`:""}</div>`;
}

async function renderCaseDetail(caseId) {
  let item=state.cases.find(value=>value.case_id===caseId); if(!item) item=await api(`/api/m8/cases/${caseId}`);
  const authority=caseAuthority(item),command=caseCommand(item),triggers=command.trigger_authorities||[];
  const related=state.notifications.filter(n=>notificationPlan(n)?.case_id===caseId);
  const tab=new URL(location.href).searchParams.get("tab")||"overview";const allowed=["overview","evidence","hearing","handling"];const activeTab=allowed.includes(tab)?tab:"overview";
  const notifyAction=role()==="SAFETY_OFFICER"&&item.status==="CONFIRMED"&&authority.subject_actor_id?`<button class="button" type="button" data-dispatch="CASE_UPDATED" data-case="${item.case_id}">发送学生消息</button>`:"";
  const outcomeAction=role()==="SAFETY_OFFICER"&&item.status==="APPEAL_RESOLVED"?`<button class="button" type="button" data-dispatch="APPEAL_OUTCOME" data-case="${item.case_id}">发送申诉结果</button>`:"";
  const overview=`<section class="facts"><div class="fact"><span>状态</span><strong>${label(item.status)}</strong></div><div class="fact"><span>风险等级</span><strong class="${authority.risk_level==="EMERGENCY"?"risk":""}">${authority.risk_level}</strong></div><div class="fact"><span>案件版本</span><strong>V${item.case_version}</strong></div><div class="fact"><span>关联主体</span><strong>${esc(authority.subject_actor_id||"无")}</strong></div></section><div class="panel"><div class="panel-head"><h2>触发 authority</h2><span>${triggers.length} REFERENCES</span></div><div class="authority-list">${triggers.map(ref=>`<div class="authority"><b>${esc(ref.kind)}</b><code>${esc(ref.authority_id)}<br>${esc(ref.document_sha256)}</code></div>`).join("")}</div></div>`;
  const handling=`<div class="processing-layout"><section class="panel"><div class="panel-head"><h2>处置工作台</h2><span>HUMAN CONFIRMATION</span></div>${caseActions(item)}</section><aside><div class="panel-head"><h2>审计时间线</h2><span>STATE MACHINE</span></div><div class="case-timeline"><article class="timeline-event is-complete"><b>案件建立</b><p>${label("PENDING_VERIFICATION")} · V1</p></article><article class="timeline-event is-current"><b>当前状态</b><p>${esc(label(item.status))} · V${item.case_version}</p></article></div></aside></div><section style="margin-top:28px"><div class="panel-head"><h2>关联通知</h2><span>${related.length} MESSAGES</span></div>${notificationCards(related)}</section>`;
  const panels={overview,evidence:caseRecognitionDossier(caseId,"evidence"),hearing:caseRecognitionDossier(caseId,"hearing"),handling};
  const tabs=[["overview","概览"],["evidence","证据"],["hearing","会审"],["handling","处理"]];
  const content=`${pageHead(authority.risk_level,caseTitle(item),`${authority.location_id} · 案件 ${short(item.case_id)} · ${authority.subject_actor_id?"预约关联，非视觉身份识别":"未关联个人身份"}`,`${notifyAction}${outcomeAction}<a class="button quiet" href="/app/cases">返回列表</a>`)}${flow(item.status)}<nav class="case-tabs" role="tablist" aria-label="案件卷宗内容">${tabs.map(([key,text])=>`<a class="case-tab" role="tab" data-case-tab="${key}" aria-selected="${activeTab===key}" tabindex="${activeTab===key?0:-1}" href="?tab=${key}">${text}${key==="evidence"?`<span class="case-tab-count">${state.run?.case_id===caseId?state.run.evidence?.length||0:0}</span>`:""}</a>`).join("")}</nav><section class="case-panel is-active" role="tabpanel" data-case-panel="${activeTab}">${panels[activeTab]}</section>`;
  setRouteContent(content,{mount:()=>{if(activeTab==="evidence"){attachEvidence();attachPerception();}},announcement:`${caseTitle(item)} · ${tabs.find(x=>x[0]===activeTab)[1]}`});
}

function notificationCards(items=state.notifications) {
  if(!items.length)return empty("暂无消息","当前角色没有可见通知。")
  return items.map(item=>{const plan=notificationPlan(item);return `<article class="notice-card"><div class="notice-card__head"><div><p class="eyebrow">${esc(plan.purpose)} · ${esc(plan.audience)}</p><h3>${plan.purpose==="APPEAL_OUTCOME"?"申诉处理结果":plan.purpose==="CASE_UPDATED"?"案件状态更新":"安全事件待处理"}</h3><p>${esc(label(plan.case_status))} · ${esc(plan.location_id)} · 案件 ${short(plan.case_id)}</p></div><span class="badge">${esc(label(item.status))}</span></div><span class="badge fake">FAKE DELIVERY · real_delivery_confirmed=false</span>${role()==="STUDENT"?studentNotificationActions(item):""}</article>`}).join("");
}

function studentNotificationActions(item) {
  const plan=notificationPlan(item); if(plan.target.actor_id!=="student-demo")return "";
  if(item.status==="DELIVERED"&&plan.target.inbound_response_supported) return `<div style="margin-top:16px"><div class="field"><label for="reply-${item.notification_id}">说明正文</label><textarea id="reply-${item.notification_id}" placeholder="请说明现场情况或申诉理由"></textarea></div><div class="form-actions"><button class="button quiet" data-reply="EXPLANATION" data-notification="${item.notification_id}" data-case="${plan.case_id}">提交说明</button><button class="button primary" data-reply="APPEAL_REQUEST" data-notification="${item.notification_id}" data-case="${plan.case_id}">提交申诉</button></div></div>`;
  if(item.status==="DELIVERED"&&!plan.target.inbound_response_supported) return `<div class="form-actions" style="margin-top:14px"><button class="button primary" data-ack="${item.notification_id}">确认收到结果</button></div>`;
  return `<p class="help">该消息已${label(item.status)}；原通知保持不变。</p>`;
}

function renderNotifications() { setRouteContent(`${pageHead("MESSAGE CENTER","通知中心","通知通过本地离线模拟通道送达；每张卡片保留真实投递属性，不声称外部送达。")}<section class="metrics">${metric(state.notifications.length,"消息总数","当前角色可见")}${metric(state.notifications.filter(x=>x.status==="DELIVERED").length,"待回应","已模拟送达")}${metric(state.notifications.filter(x=>x.status==="RESPONDED").length,"已回复","说明或申诉")}${metric(state.notifications.filter(x=>x.status==="ACKNOWLEDGED").length,"已确认","结果通知")}</section>${notificationCards()}`,{announcement:"通知中心"}); }

function renderMap() {
  const alert=isEmergency();
  setRouteContent(`${pageHead("CAMPUS MAP","校园态势地图","示意地图层级和设备状态来自校区 topology 与 operations projection。地图仅表达当前演示现场。")}<div class="grid two"><section class="map-board" aria-label="演示校区示意地图"><div class="campus-outline"><span class="building lib">图书馆<br>非演示区域</span><span class="building chem">化学楼<br>三层</span><span class="road h"></span><span class="road v"></span><span class="room-node ${alert?"alert":""}"><i></i><b>实验室 301</b></span></div><div class="map-legend">${alert?"朱红：烟雾与高温联动":"蓝点：标准现场"}<br>SIMULATED SENSOR</div></section><aside><div class="panel-head"><h2>空间层级</h2><span>${locations().length} LOCATIONS</span></div><div class="list">${locations().map((loc,index)=>`<button class="list-item map-room" type="button" data-location="${esc(loc.location_id)}" style="--room-index:${index}"><div><h3>${esc(loc.display_name)}</h3><p>${esc(loc.kind)} · ${esc(loc.location_id)}</p></div><span class="badge">${esc(loc.parent_location_id||"ROOT")}</span></button>`).join("")}</div><div class="panel-head" style="margin-top:26px"><h2>实验室来源</h2><span>${sources().length} SOURCES</span></div>${sources().map(item=>`<div class="card ${sourceValue(item).includes("烟雾")||sourceValue(item).includes("82")?"alert":""}"><h3>${esc(item.source.sensor_type||"录像机位")}</h3><p>${esc(sourceValue(item))} · ${esc(item.observation_state)}</p></div>`).join("")}</aside></div>`,{announcement:"校园态势地图"});
}

function renderKnowledge() {
  setRouteContent(`${pageHead("OFFLINE KNOWLEDGE","知识库","查询校内安全规范、实验室 PPE 与应急处置文档。未命中时明确返回 NO_MATCH。")}<div class="knowledge-layout"><aside class="knowledge-index"><p class="eyebrow">离线目录</p><button class="knowledge-item active" type="button" data-query="护目镜有什么要求？">实验室 PPE</button><button class="knowledge-item" type="button" data-query="发现烟雾和高温后如何处置？">烟雾与高温应急</button><button class="knowledge-item" type="button" data-query="学生如何提交说明和申诉？">说明与申诉</button></aside><section><div class="panel"><div class="field"><label for="knowledge-query">知识问题</label><textarea id="knowledge-query">进入化学实验室需要佩戴哪些个人防护装备？</textarea></div><div class="form-actions"><button class="button primary" type="button" data-action="knowledge-query">查询知识库</button></div></div><article class="knowledge-reader" id="knowledge-answer">${empty("选择目录或输入问题","答案由离线严格意图路由与现有知识库生成；无匹配时明确返回 NO_MATCH。")}</article></section></div>`,{announcement:"知识库"});
}

function renderAgent() {
  const messages=state.agentMessages.length?state.agentMessages.map(m=>`<div class="message ${m.kind}"><p>${esc(m.text)}</p><small>${esc(m.meta||"")}</small></div>`).join(""):empty("等待提问","Agent 只查询现有 authority 或提出需确认的操作卡，不直接写数据库。");
  const action=state.action?`<div class="action-card"><p class="eyebrow">PROPOSED ACTION</p><h3>${esc(state.action.action_kind)}</h3><p>${esc(state.action.impact_summary)}</p><code>目标 ${esc(state.action.target_ref)} · 版本 ${state.action.current_version}</code><button class="button primary" data-action="confirm-agent">确认并交给业务接口执行</button></div>`:empty("无待确认操作","领导和学生只会收到查询与知识回答。")
  setRouteContent(`${pageHead("DETERMINISTIC AGENT","安全运营 Agent","默认离线、确定性路由。操作卡闭合、带目标与版本，且必须由人确认。")}<div class="agent-layout"><section><div class="panel agent-log">${messages}${state.agentTyping?`<div class="agent-typing" aria-label="正在查询"><i></i><i></i><i></i></div>`:""}</div><div class="quick-list"><button class="quick" data-agent-quick="查看当前案件">当前案件</button><button class="quick" data-agent-quick="查看设备和传感器状态">设备状态</button><button class="quick" data-agent-quick="护目镜有什么要求？">PPE 规范</button></div><div class="panel" style="margin-top:12px"><div class="field"><label for="agent-query">输入查询或明确操作意图</label><textarea id="agent-query" placeholder="例如：查看当前案件；触发烟雾与温度场景；如何佩戴护目镜"></textarea></div><div class="form-actions"><button class="button primary" data-action="agent-query">发送</button></div></div></section><aside>${action}</aside></div>`,{announcement:"安全运营 Agent"});
}

function renderProfile() {
  const authority=state.session.authority;
  const reservations=state.reservations.map(item=>`<article class="profile-shortcut card"><h3>${esc(item.location_id)}</h3><p>${esc(item.association_notice)} · ${esc(item.starts_at)} → ${esc(item.ends_at)}</p></article>`).join("")||empty("没有可见预约","当前角色没有预约 authority。");
  setRouteContent(`${pageHead("SESSION AUTHORITY","我的资料","角色、范围和能力全部来自服务端 session 投影；切换角色会清除当前标签页令牌。",`<a class="button" href="/login" data-action="switch-role">切换演示角色</a>`)}<div class="profile-grid"><section class="panel"><div class="facts"><div class="fact"><span>角色</span><strong>${esc(ROLE_LABELS[authority.role])}</strong></div><div class="fact"><span>主体</span><strong>${esc(authority.actor_id)}</strong></div><div class="fact"><span>范围</span><strong>${esc(authority.scope_kind)}</strong></div><div class="fact"><span>版本</span><strong>V${authority.authority_revision}</strong></div></div><h2 class="section-title">能力</h2><div class="quick-list">${authority.capabilities.map(value=>`<span class="badge">${esc(value)}</span>`).join("")}</div><h2 class="section-title">预约与关联</h2>${reservations}</section><aside class="panel"><h2 class="section-title">Demo 边界</h2><p>personal_demo_only=true</p><p>production_ready=false</p><p>令牌位置：sessionStorage</p><p>网络模型调用：真实模式可调用已配置的 Qwen3-VL；来源随场景记录展示</p></aside></div>`,{announcement:"我的资料"});
}

function renderSettings() {
  const ops=role()==="OPERATIONS";
  const userRows=(state.users||[]).map(item=>{const a=item.authority||item;return `<tr><td>${esc(a.actor_id)}</td><td>${esc(a.role)}</td><td>${esc(a.scope_kind)}</td><td>V${a.authority_revision}</td></tr>`}).join("");
  const reset=ops?`<section class="panel"><div class="panel-head"><h2>演示现场复位</h2><span>OPERATIONS ONLY</span></div><p>复位会将当前数据库和演示回执归档到 session 目录，再原子替换为无案件、无告警的标准现场。历史不会删除。</p><button class="button alarm" type="button" data-action="reset">确认归档并一键复位</button></section>`:"";
  const modelStatus=state.readiness?`<section class="model-readiness"><p class="eyebrow">MODEL READINESS</p>${state.readiness.components.map(item=>`<div><span class="readiness-dot ${item.ready?"ready":""}"></span><b>${esc(item.component)}</b><span>${esc(item.model)}</span><small>${item.ready?"READY":esc(item.failure_code)}</small></div>`).join("")}<p class="help">真实模式在启动前预检；失败不会自动替换为演示结果。</p></section>`:"";
  const sections={models:`${modelStatus||empty("模型状态不可见","当前角色无模型 readiness 读取权限。")} ${reset}`,devices:`<div class="panel-head"><h2>来源与接口</h2><span>${sources().length} REGISTERED</span></div><div class="table-wrap"><table class="table"><thead><tr><th>设备</th><th>类型</th><th>适配器</th><th>状态</th></tr></thead><tbody>${sources().map(x=>`<tr><td>${esc(x.source.device_id)}</td><td>${esc(x.source.sensor_type||x.source.source_kind)}</td><td>${esc(x.source.adapter_id)}</td><td>${esc(x.observation_state)}</td></tr>`).join("")}</tbody></table></div>`,rules:`<section class="panel"><div class="panel-head"><h2>规则状态</h2><span>SERVER AUTHORITY</span></div><p>${state.rules?`当前规则修订 V${esc(state.rules.revision||state.rules.authority_revision||"—")}`:"当前角色无规则读取权限"}</p><p class="help">烟雾与温度联动由后端规则生成 EMERGENCY，不通过页面属性伪造。</p></section>`,users:`<div class="panel-head"><h2>用户权限</h2><span>${state.users?state.users.length:"ROLE-SCOPED"}</span></div>${state.users?`<div class="table-wrap"><table class="table"><thead><tr><th>用户</th><th>角色</th><th>范围</th><th>版本</th></tr></thead><tbody>${userRows}</tbody></table></div>`:empty("权限清单不可见","当前角色不具备用户权限管理能力。")}`};
  setRouteContent(`${pageHead("PLATFORM SETTINGS","设备、规则与权限","只显示具备真实读取或执行接口的设置；不存在虚假保存按钮。")}<div class="settings-layout"><nav class="settings-nav" aria-label="设置分区">${[["models","模型与复位"],["devices","设备来源"],["rules","规则"],["users","用户权限"]].map(([key,text])=>`<button type="button" data-settings-section="${key}" class="${state.settingsSection===key?"active":""}" aria-current="${state.settingsSection===key}">${text}</button>`).join("")}</nav><section class="settings-panel">${sections[state.settingsSection]||sections.models}</section></div>`,{announcement:"平台设置"});
}

function captureEntry(){const video=document.getElementById("recorded-video");if(video)state.videoPositions.set("recorded-video",video.currentTime);return {scrollX,scrollY,videoTime:video?.currentTime||state.videoPositions.get("recorded-video")||0};}
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
    if(routeId!==state.routeSequence||controller.signal.aborted)return;
    if(path==="/app/monitor")renderMonitor();else if(path==="/app/cases")renderCases();else if(path.startsWith("/app/cases/"))await renderCaseDetail(decodeURIComponent(path.split("/").pop()));else if(path==="/app/map")renderMap();else if(path==="/app/notifications")renderNotifications();else if(path==="/app/knowledge")renderKnowledge();else if(path==="/app/agent")renderAgent();else if(path==="/app/profile")renderProfile();else if(path==="/app/settings")renderSettings();else{await navigateTo("/app/monitor",{replace:true});return;}
    state.currentRoute=`${path}${location.search}`;if(restore){state.videoPositions.set("recorded-video",restore.videoTime||0);requestAnimationFrame(()=>scrollTo(restore.scrollX||0,restore.scrollY||0));}if(state.run?.state==="RUNNING")schedulePoll();
  } catch(error){if(error.name!=="AbortError"&&routeId===state.routeSequence)errorPage(error)}
}

async function refresh(message) { await loadCore(); await renderRoute(); if(message)toast(message); }
async function hashManifest(text) { const bytes=new TextEncoder().encode(text); const digest=await crypto.subtle.digest("SHA-256",bytes); return [...new Uint8Array(digest)].map(v=>v.toString(16).padStart(2,"0")).join(""); }
async function transitionCase(caseId,descriptor,extraAuthorities=[]) {
  const [action,resolution]=descriptor.split(":"); const item=await api(`/api/m8/cases/${caseId}`); const authority=caseAuthority(item); const reason=document.getElementById("case-reason")?.value?.trim()||"本人确认按演示流程提交此状态变更。";
  const reasonCodes={CONFIRM:"VERIFIED_VIOLATION",REJECT:"FALSE_POSITIVE",REQUEST_EVIDENCE:"MORE_EVIDENCE_REQUIRED",RETURN_TO_VERIFICATION:"EVIDENCE_RECEIVED",RESOLVE:"HAZARD_CLEARED",SUBMIT_APPEAL:"SUBJECT_DISPUTE",RESOLVE_APPEAL:resolution==="OVERTURNED"?"APPEAL_OVERTURNED":"APPEAL_UPHELD"};
  const refs=[...(authority.create_command.trigger_authorities||[]),...extraAuthorities].sort((a,b)=>`${a.kind}|${a.authority_id}|${a.document_sha256}`.localeCompare(`${b.kind}|${b.authority_id}|${b.document_sha256}`));
  const payload={source_case_version:item.case_version,source_case_authority_sha256:item.case_document_sha256,source_status:item.status,case_location_id:authority.location_id,subject_actor_id:authority.subject_actor_id,action,reason_code:reasonCodes[action],reason_summary:reason,supporting_authorities:refs,appeal_resolution:action==="RESOLVE_APPEAL"?resolution:null,explicit_human_confirmation:true,command_manifest_id:await hashManifest("labcourt-platform-ui-human-command-v1")};
  return api(`/api/m8/cases/${caseId}/transitions`,{method:"POST",body:payload});
}

async function handleClick(event) {
  const target=event.target.closest("button,a"); if(!target)return;
  if(target.dataset.roleSelect){state.loginRole=target.dataset.roleSelect;renderLogin();return;}
  if(target.dataset.login){target.disabled=true;target.setAttribute("aria-busy","true");target.textContent="正在建立本地会话…";try{const response=await api("/api/m8/demo/login",{method:"POST",body:{role:target.dataset.login}});state.token=response.bearer_token;state.session=null;sessionStorage.setItem(TOKEN_KEY,state.token);document.body.classList.add("login-authorizing");setTimeout(()=>{document.body.classList.remove("login-authorizing");state.shellMounted=false;navigateTo("/app/monitor",{replace:true});},720);}catch(error){target.disabled=false;target.removeAttribute("aria-busy");target.textContent="重新尝试进入";toast(error.message,"error");}return;}
  if(target.dataset.action==="logout"){logout();return} if(target.dataset.action==="switch-role"){event.preventDefault();logout();return} if(target.dataset.action==="reload"){state.session=null;renderRoute();return}
  try {
    if(target.dataset.action==="nav-toggle"){state.navOpen=!state.navOpen;target.setAttribute("aria-expanded",String(state.navOpen));document.getElementById("primary-nav")?.classList.toggle("is-open",state.navOpen);return;}
    if(target.dataset.caseFilter){state.casesFilter=target.dataset.caseFilter;renderCases();return;}
    if(target.dataset.settingsSection){state.settingsSection=target.dataset.settingsSection;renderSettings();return;}
    if(target.dataset.agentQuick){document.getElementById("agent-query").value=target.dataset.agentQuick;return;}
    if(target.dataset.location){state.mapLocation=target.dataset.location;toast(`已选择 ${target.textContent.trim()}；详情来自 topology 与来源投影`);return;}
    if(target.dataset.scenario){target.disabled=true;target.setAttribute("aria-busy","true");const payload={scenario_kind:target.dataset.scenario,explicit_human_confirmation:true};if(target.dataset.scenario==="PPE_GOGGLES_MISSING")payload.recognition_mode=target.dataset.mode||"FULL_MODEL";if(target.dataset.retry)payload.retry_of_run_id=target.dataset.retry;state.run=await api("/api/m8/demo/scenario-runs",{method:"POST",body:payload});patchRunUi();schedulePoll();toast(payload.recognition_mode==="FULL_MODEL"?"真实识别已启动，进度将在本页连续更新":"演示模式已明确启动，并创建了独立运行记录");return;}
    if(target.dataset.transition){target.disabled=true;await transitionCase(target.dataset.case,target.dataset.transition);await refresh("案件状态已由服务端状态机更新");return;}
    if(target.dataset.dispatch){target.disabled=true;await api(`/api/m8/cases/${target.dataset.case}/notification-dispatches`,{method:"POST",body:{kind:target.dataset.dispatch,explicit_human_confirmation:true}});await refresh("新通知卡已通过本地模拟通道送达");return;}
    if(target.dataset.reply){const box=document.getElementById(`reply-${target.dataset.notification}`);const body=box?.value?.trim();if(!body){toast("请先填写正文","error");return}target.disabled=true;const receipt=await api(`/api/m8/notifications/${target.dataset.notification}/replies`,{method:"POST",body:{reply_kind:target.dataset.reply,body,explicit_human_confirmation:true}});if(target.dataset.reply==="APPEAL_REQUEST"){const reply=receipt.audit_event?.transition_command?.reply;if(!reply)throw new Error("回复已记录，但回复 authority 尚不可读取，请重试案件申诉步骤");try{await transitionCase(target.dataset.case,"SUBMIT_APPEAL",[{kind:"NOTIFICATION_REPLY",authority_id:reply.reply_authority_id,document_sha256:reply.reply_document_sha256}]);}catch(error){await refresh(`申诉回复已记录；案件提交未完成，可从案件页重试：${error.message}`);return;}}await refresh(target.dataset.reply==="APPEAL_REQUEST"?"申诉回复与案件申诉状态均已记录":"说明已记录，原通知未被改写");return;}
    if(target.dataset.ack){target.disabled=true;await api(`/api/m8/notifications/${target.dataset.ack}/acknowledgements`,{method:"POST",body:{explicit_human_confirmation:true}});await refresh("结果通知已确认");return;}
    if(target.dataset.query){document.getElementById("knowledge-query").value=target.dataset.query;return;}
    if(target.dataset.action==="knowledge-query"){const query=document.getElementById("knowledge-query").value.trim();if(!query)return;target.disabled=true;const answer=await api("/api/m8/agent/queries",{method:"POST",body:{query}});document.getElementById("knowledge-answer").innerHTML=`<p class="eyebrow">${answer.outcome}</p><h2 class="section-title">离线回答</h2><p>${esc(answer.answer)}</p><p class="help mono">${answer.source_refs.map(short).join(" · ")||"无匹配引用"}</p>`;target.disabled=false;return;}
    if(target.dataset.action==="agent-query"){const input=document.getElementById("agent-query"),query=input.value.trim();if(!query)return;target.disabled=true;state.agentMessages.push({kind:"user",text:query,meta:ROLE_LABELS[role()]});state.agentTyping=true;renderAgent();const answer=await api("/api/m8/agent/queries",{method:"POST",body:{query}});state.agentTyping=false;state.agentMessages.push({kind:"agent",text:answer.answer,meta:`${answer.outcome} · MODEL_USED=${answer.model_used}`});state.action=answer.proposed_action;renderAgent();return;}
    if(target.dataset.action==="confirm-agent"){target.disabled=true;await executeAgentAction(state.action);state.action=null;await refresh("操作卡已由既有业务接口复核并执行");return;}
    if(target.dataset.action==="reset"){target.disabled=true;const result=await api("/api/m8/demo/reset",{method:"POST",body:{explicit_human_confirmation:true}});state.session=null;clearObjectUrls();await renderRoute();toast(`已复位到标准现场；归档 ${result.archive_ref}`);return;}
  } catch(error){target.disabled=false;toast(error.message,"error");}
}

async function executeAgentAction(action) {
  if(!action)throw new Error("没有待确认操作");
  if(action.action_kind==="RUN_SCENARIO")return api("/api/m8/demo/scenario-runs",{method:"POST",body:action.request_payload});
  if(action.action_kind==="RESET_DEMO")return api("/api/m8/demo/reset",{method:"POST",body:action.request_payload});
  if(action.action_kind==="CASE_TRANSITION")return transitionCase(action.target_ref,action.request_payload.action);
  throw new Error("操作卡类型不在闭合集合中");
}

document.addEventListener("click",event=>{
  const link=event.target.closest("a[href]");if(!link||event.defaultPrevented||event.button!==0||event.metaKey||event.ctrlKey||event.shiftKey||event.altKey||link.target&&link.target!=="_self"||link.hasAttribute("download")||link.dataset.action)return;
  const raw=link.getAttribute("href");if(!raw||raw.startsWith("#"))return;const url=new URL(link.href,location.href);if(url.origin!==location.origin)return;event.preventDefault();navigateTo(url);
},{capture:true});
document.addEventListener("click",handleClick);
document.addEventListener("keydown",event=>{const tab=event.target.closest('[role="tab"][data-case-tab]');if(!tab||!["ArrowLeft","ArrowRight"].includes(event.key))return;const tabs=[...tab.parentElement.querySelectorAll('[role="tab"][data-case-tab]')],next=tabs[(tabs.indexOf(tab)+(event.key==="ArrowRight"?1:-1)+tabs.length)%tabs.length];event.preventDefault();navigateTo(next.href,{replace:true}).then(()=>document.querySelector(`[data-case-tab="${next.dataset.caseTab}"]`)?.focus());});
addEventListener("popstate",event=>renderRoute({restore:event.state?.labcourt?.ui||null}));
document.addEventListener("visibilitychange",()=>{document.body.classList.toggle("is-page-hidden",document.hidden);if(document.hidden){clearTimeout(state.pollTimer);persistEntry();}else if(state.run?.state==="RUNNING")schedulePoll();});
addEventListener("scroll",()=>{if(!state.scrollSaveFrame)state.scrollSaveFrame=requestAnimationFrame(()=>{state.scrollSaveFrame=0;if(location.pathname.startsWith("/app/"))persistEntry();});},{passive:true});
if(!history.state?.labcourt)history.replaceState({labcourt:{key:crypto.randomUUID(),ui:null}},"",location.href);
renderRoute({restore:history.state?.labcourt?.ui||null});

"use strict";

const app = document.getElementById("app");
const TOKEN_KEY = "labcourt.platform.token";
const ROLE_LABELS = {LEADER:"校级领导",SAFETY_OFFICER:"安全负责人",STUDENT:"学生",OPERATIONS:"运维人员"};
const STATUS_LABELS = {PENDING_VERIFICATION:"等待人工核实",CONFIRMED:"已确认",REJECTED:"已排除",EVIDENCE_REQUESTED:"待补充证据",RESOLVED:"已结案",APPEALED:"申诉处理中",APPEAL_RESOLVED:"申诉已处理",DELIVERED:"已送达",RESPONDED:"已回复",ACKNOWLEDGED:"已确认"};
const STAGE_LABELS = {VIDEO:"录像",PERCEPTION:"视觉感知",EVIDENCE:"证据裁剪",SCREENING:"结构化初审",CASE:"规则建案",NOTIFICATION:"消息通知"};
const NAV = [["/app/monitor","监控"],["/app/cases","案件"],["/app/map","地图"],["/app/notifications","通知"],["/app/knowledge","知识库"],["/app/agent","Agent"],["/app/profile","我的"],["/app/settings","设置"]];
const state = {token:sessionStorage.getItem(TOKEN_KEY),session:null,cases:[],notifications:[],projection:null,cameras:[],reservations:[],run:null,users:null,rules:null,agentMessages:[],action:null,videoUrl:null,evidenceUrls:[],pollTimer:null,toastTimer:null};

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

async function optional(path, fallback) {
  try { return await api(path); } catch (error) {
    if (["FORBIDDEN","RESOURCE_NOT_FOUND"].includes(error.message)) return fallback;
    throw error;
  }
}

function clearObjectUrls() {
  if (state.videoUrl) URL.revokeObjectURL(state.videoUrl);
  state.videoUrl = null;
  state.evidenceUrls.forEach(URL.revokeObjectURL);
  state.evidenceUrls = [];
}

function logout(navigate=true) {
  sessionStorage.removeItem(TOKEN_KEY); state.token=null; state.session=null; clearObjectUrls();
  if (state.pollTimer) clearTimeout(state.pollTimer);
  if (navigate) location.assign("/login");
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
  app.innerHTML=`${publicRibbon()}<div class="hero-page"><header class="public-head"><a class="brand" href="/">LabCourt<small>校园安全运营平台</small></a><a class="button" href="/login">进入平台 →</a></header><main id="main-content" class="hero"><section><p class="eyebrow">CAMPUS SAFETY · AUDITABLE OPERATIONS</p><h1>让每一次安全判断<br>都有来处与回声。</h1><p class="deck">从录像与传感器信号，到人工核实、学生说明、申诉处置与归档。LabCourt 在同一个可审计工作台中保留来源、权限和状态流转。</p><div class="hero-actions"><a class="button primary" href="/login">选择演示角色</a><a class="button quiet" href="/app/monitor">打开实时监控</a></div></section><div class="hero-mark" aria-hidden="true"><span>VIDEO · SENSOR<br>↓<br>EVIDENCE · CASE<br>↓<br>HUMAN DECISION</span></div></main><footer class="public-foot"><span>PERSONAL DEMO ONLY · 本地离线运行</span><span>机器输出是弱标签，不作为处分依据</span></footer></div>`;
}

function renderLogin() {
  const roles=[
    ["LEADER","校级领导","查看全局态势、重大事件与处置结果，不参与审批。"],
    ["SAFETY_OFFICER","安全负责人","核实案件、处理申诉并发送案件结果通知。"],
    ["STUDENT","学生","仅查看本人预约关联的案件和通知，并提交说明或申诉。"],
    ["OPERATIONS","运维人员","查看设备来源、触发两个演示场景并执行一键复位。"]
  ];
  app.innerHTML=`${publicRibbon()}<main id="main-content" class="login-page"><section class="login-sheet"><header class="login-head"><div><p class="eyebrow">LOCAL ROLE SWITCH</p><h1>选择演示角色</h1><p>身份由本地服务端 authority 解析，页面令牌仅保存在当前标签页。</p></div><a class="button quiet" href="/">返回首页</a></header><div class="role-grid">${roles.map(([key,title,copy],i)=>`<button class="role-card" type="button" data-login="${key}"><span class="eyebrow">0${i+1} · ${key}</span><strong>${title}</strong><p>${copy}</p><span>快捷登录 →</span></button>`).join("")}</div><p class="help">此环境用于个人演示；production_ready=false。所有外发消息均使用离线模拟通道。</p></section></main>`;
}

function currentNav(path) { return NAV.find(([href]) => path === href || (href === "/app/cases" && path.startsWith("/app/cases/")))?.[0]; }
function shell(content) {
  const path=location.pathname; const active=currentNav(path); const emergency=isEmergency();
  return `${publicRibbon()}<header class="shell-head"><div class="head-row"><a class="brand" href="/app/monitor">LabCourt<small>校园安全运营平台</small></a><nav class="nav" aria-label="主导航">${NAV.map(([href,text])=>`<a href="${href}" ${active===href?'aria-current="page"':""}>${text}</a>`).join("")}</nav><div class="head-actions"><span class="role-chip"><span>${esc(ROLE_LABELS[role()] || role())}</span></span><button class="icon-button" type="button" data-action="logout" aria-label="退出当前角色">退出</button></div></div></header>${emergency?`<div class="alarm-banner" role="alert"><div><p class="eyebrow">EMERGENCY · SIMULATED SENSOR</p><strong>实验室 301 烟雾与高温信号联动</strong></div><a href="${state.run?.case_id?`/app/cases/${state.run.case_id}`:"/app/cases"}">查看案件 →</a></div>`:""}<main id="main-content" class="page">${content}</main>`;
}

function loadingPage() { app.innerHTML=shell(`<div class="page-head"><div><p class="eyebrow">LOADING</p><h1>正在读取运营投影</h1></div></div><div class="grid three"><div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div></div>`); }
function errorPage(error) { app.innerHTML=shell(`<div class="page-head"><div><p class="eyebrow">TYPED FAILURE</p><h1>页面暂时无法读取</h1></div></div><div class="error-state"><strong>${esc(error.message)}</strong><p>状态未被伪装为成功。可检查本地服务后重试。</p><button class="button" type="button" data-action="reload">重新读取</button></div>`); }

async function loadCore() {
  state.session=await api("/api/m8/session");
  const [cases,notifications,projection,cameras,reservations,run]=await Promise.all([
    optional("/api/m8/cases",[]),optional("/api/m8/notifications",[]),optional("/api/m8/campuses/campus-demo/operations-projection",null),optional("/api/m8/cameras",[]),optional("/api/m8/reservations",[]),optional("/api/m8/demo/scenario-runs/current",null)
  ]);
  Object.assign(state,{cases,notifications,projection,cameras,reservations,run});
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
  const ops=role()==="OPERATIONS"; const active=state.cases.filter(item=>!terminalCase(item.status)); const complete=(state.run?.stages||[]).filter(s=>s.state==="COMPLETE").length;
  const profile=state.run?.video_profile; const totalFrames=profile?.frame_count||"—";
  const videoMeta=profile?`${profile.fps_num/profile.fps_den} FPS · ${profile.width}×${profile.height} · ${(profile.duration_millis/1000).toFixed(1)} 秒 · ${profile.timing_authority}`:"录像帧信息将在 Pilot manifest 生成后显示";
  const actions=ops?`<button class="button primary" type="button" data-scenario="PPE_GOGGLES_MISSING" ${state.run?.state==="RUNNING"?"disabled":""}>运行 PPE 录像流程</button><button class="button alarm" type="button" data-scenario="SMOKE_TEMPERATURE_EMERGENCY" ${state.run?.state==="RUNNING"?"disabled":""}>触发烟雾—高温联动</button>`:"";
  const videoAllowed=state.cameras.length>0;
  const content=`${pageHead("LIVE OPERATIONS","实时监控",`演示校区 / 化学楼 / 三层 / 实验室 301。录像按播放时钟映射帧序号，视觉关联不用于身份识别。`,actions)}<section class="metrics">${metric(sources().length,"数据源","来自运营投影")}${metric(active.length,"活动案件","当前角色可见")}${metric(state.notifications.length,"通知","当前角色可见")}${metric(state.run?`${complete}/6`:"0/6","流程阶段",state.run?.state||"尚未运行")}</section><div class="grid two"><section><div class="panel-head"><h2>实验室 301 · 原始录像</h2><span>CAMERA-RECORDED-DEMO-01</span></div><div class="panel"><div class="video-stage">${videoAllowed?`<video id="recorded-video" controls muted playsinline></video>`:`<div class="video-placeholder">当前角色无录像读取权限</div>`}<span class="source-badge">SIMULATED · RECORDED VIDEO</span><span id="frame-counter" class="frame-counter">FRAME — / ${totalFrames}</span></div><div class="video-meta"><span>${esc(videoMeta)}</span><span>预约关联，非视觉身份识别</span></div></div></section><aside class="panel"><div class="panel-head"><h2>场景阶段</h2><span>${esc(state.run?.model_or_fixture_id||"等待运行")}</span></div>${stageList()}${state.run?.failure_code?`<p class="help risk">${esc(state.run.failure_code)} · 状态未伪装为成功</p>`:""}${state.run?.raw_response_ref?`<p class="help mono">RAW · ${esc(state.run.raw_response_ref)}</p>`:""}${state.run?.screening_decision?`<div class="screening-card"><p class="eyebrow">VLM STRUCTURED WEAK LABEL</p><strong>${esc(state.run.screening_decision)}</strong><p>${esc(state.run.screening_summary)}</p><small>规则判断 · ${esc(state.run.rule_judgment)} · 不作为处分依据</small></div>`:""}</aside></div>${state.run?.perception_preview_url?`<section style="margin-top:32px"><div class="panel-head"><h2>视觉感知与目标定位</h2><span>VERIFIED PILOT ARTIFACT</span></div><div class="panel"><div class="video-stage"><video id="perception-video" controls muted playsinline></video><span class="source-badge">PILOT PERCEPTION ARTIFACT</span></div></div></section>`:""}<section style="margin-top:32px"><div class="panel-head"><h2>设备与传感器</h2><span>状态来自 OPERATIONS PROJECTION</span></div><div class="device-grid">${sources().map(item=>`<article class="device ${item.latest_sample_receipt?.sample?.value===true||item.source.sensor_type==="TEMPERATURE"&&Number(item.latest_sample_receipt?.sample?.value)>60000?"alert":""}"><div class="device-head"><h3>${esc(item.source.device_id)}</h3><span class="badge">${item.source.source_kind==="SENSOR"?"SIMULATED SENSOR":"RECORDED"}</span></div><strong>${esc(sourceValue(item))}</strong><small>${esc(item.source.sensor_type||item.source.mode)} · ${esc(item.observation_state)}</small></article>`).join("")||empty("设备不可见","当前角色不具备设备健康读取能力。")}</div></section>${state.run?.evidence?.length?`<section style="margin-top:32px"><div class="panel-head"><h2>Pilot 证据裁剪</h2><span>仅显示已校验产物</span></div><div class="evidence-grid">${state.run.evidence.map(item=>`<figure class="evidence"><div class="evidence-media"><span class="spinner"></span><img data-evidence="${esc(item.evidence_id)}" alt="${esc(item.role)} 证据裁剪" hidden></div><figcaption>${esc(item.role==="TEMPORAL"?"TEMPORAL · EYE-REGION FOCUS":item.role)} · FRAME ${item.frame_index} · ${esc(item.integrity)}</figcaption></figure>`).join("")}</div></section>`:""}`;
  app.innerHTML=shell(content); if (videoAllowed) attachVideo(); if (state.run?.perception_preview_url) attachPerception(); if (state.run?.evidence?.length) attachEvidence(); schedulePoll();
}

async function attachVideo() {
  const video=document.getElementById("recorded-video"); if (!video||state.videoUrl) { if(video&&state.videoUrl) video.src=state.videoUrl; return; }
  try { const camera=state.cameras[0]; const blob=await api(camera.media_api_path,{binary:true,headers:{Range:"bytes=0-"}}); state.videoUrl=URL.createObjectURL(blob); video.src=state.videoUrl; video.addEventListener("timeupdate",()=>{const counter=document.getElementById("frame-counter"),profile=state.run?.video_profile; if(counter&&profile) counter.textContent=`FRAME ${Math.min(profile.frame_count-1,Math.floor(video.currentTime*profile.fps_num/profile.fps_den))} / ${profile.frame_count}`;}); }
  catch(error){toast(`录像读取失败：${error.message}`,"error");}
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
  clearTimeout(state.pollTimer); if(state.run?.state!=="RUNNING")return;
  state.pollTimer=setTimeout(async()=>{try{state.run=await api("/api/m8/demo/scenario-runs/current"); if(location.pathname==="/app/monitor")renderMonitor();}catch(error){toast(error.message,"error");}},1000);
}

function caseTitle(item) { const command=caseCommand(item); return command?.risk_level==="EMERGENCY"?"烟雾与高温联动紧急事件":"护目镜缺失候选事件"; }
function caseList(items=state.cases) {
  if(!items.length)return empty("暂无可见案件","标准现场保持无活动案件；可由运维角色启动演示场景。")
  return `<div class="list">${items.map(item=>{const authority=caseAuthority(item);return `<a class="list-item" href="/app/cases/${item.case_id}"><div><h3>${caseTitle(item)}</h3><p>${esc(authority.location_id)} · ${short(item.case_id)} · V${item.case_version}</p></div><div class="status"><span class="badge ${authority.risk_level==="EMERGENCY"?"risk":""}">${esc(authority.risk_level)}</span><p>${esc(label(item.status))} →</p></div></a>`}).join("")}</div>`;
}

function renderCases() {
  const active=state.cases.filter(x=>!terminalCase(x.status)), archived=state.cases.filter(x=>terminalCase(x.status));
  app.innerHTML=shell(`${pageHead("CASE CENTER","案件中心","案件来自服务端状态机。候选事件需经人工核实；机器输出不能直接产生处分。")}<section class="metrics">${metric(state.cases.length,"全部案件","当前权限范围")}${metric(active.length,"进行中","待核实或处置")}${metric(state.cases.filter(x=>caseAuthority(x)?.risk_level==="EMERGENCY").length,"紧急","传感器联动")}${metric(archived.length,"已归档","已结束状态")}</section><div class="grid two"><section><div class="panel-head"><h2>进行中</h2><span>${active.length} CASES</span></div>${caseList(active)}</section><aside><div class="panel-head"><h2>已结束</h2><span>${archived.length} ARCHIVED</span></div>${caseList(archived)}</aside></div>`);
}

function flow(status) {
  const order=status==="APPEALED"||status==="APPEAL_RESOLVED"?["PENDING_VERIFICATION","CONFIRMED","APPEALED","APPEAL_RESOLVED"]:["PENDING_VERIFICATION","CONFIRMED","RESOLVED"];
  const index=Math.max(0,order.indexOf(status)); return `<div class="case-flow">${order.map((item,i)=>`${i?`<span class="flow-join ${i<=index?"done":""}"></span>`:""}<span class="flow-node ${i<index?"done":i===index?"current":""}"><i>${i<index?"✓":i+1}</i>${label(item)}</span>`).join("")}</div>`;
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

async function renderCaseDetail(caseId) {
  let item=state.cases.find(value=>value.case_id===caseId); if(!item) item=await api(`/api/m8/cases/${caseId}`);
  const authority=caseAuthority(item),command=caseCommand(item),triggers=command.trigger_authorities||[];
  const related=state.notifications.filter(n=>notificationPlan(n)?.case_id===caseId);
  const notifyAction=role()==="SAFETY_OFFICER"&&item.status==="CONFIRMED"&&authority.subject_actor_id?`<button class="button" type="button" data-dispatch="CASE_UPDATED" data-case="${item.case_id}">发送学生消息</button>`:"";
  const outcomeAction=role()==="SAFETY_OFFICER"&&item.status==="APPEAL_RESOLVED"?`<button class="button" type="button" data-dispatch="APPEAL_OUTCOME" data-case="${item.case_id}">发送申诉结果</button>`:"";
  app.innerHTML=shell(`${pageHead(authority.risk_level,caseTitle(item),`${authority.location_id} · 案件 ${short(item.case_id)} · ${authority.subject_actor_id?"预约关联，非视觉身份识别":"未关联个人身份"}`,`${notifyAction}${outcomeAction}<a class="button quiet" href="/app/cases">返回列表</a>`)}${flow(item.status)}<section class="facts"><div class="fact"><span>状态</span><strong>${label(item.status)}</strong></div><div class="fact"><span>风险等级</span><strong class="${authority.risk_level==="EMERGENCY"?"risk":""}">${authority.risk_level}</strong></div><div class="fact"><span>案件版本</span><strong>V${item.case_version}</strong></div><div class="fact"><span>关联主体</span><strong>${esc(authority.subject_actor_id||"无")}</strong></div></section><div class="grid two"><section class="panel"><div class="panel-head"><h2>处置工作台</h2><span>HUMAN CONFIRMATION</span></div>${caseActions(item)}</section><aside class="panel"><div class="panel-head"><h2>触发 authority</h2><span>${triggers.length} REFERENCES</span></div><div class="authority-list">${triggers.map(ref=>`<div class="authority"><b>${esc(ref.kind)}</b><code>${esc(ref.authority_id)}<br>${esc(ref.document_sha256)}</code></div>`).join("")}</div></aside></div><section style="margin-top:28px"><div class="panel-head"><h2>关联通知</h2><span>${related.length} MESSAGES</span></div>${notificationCards(related)}</section>`);
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

function renderNotifications() { app.innerHTML=shell(`${pageHead("MESSAGE CENTER","通知中心","通知通过本地离线模拟通道送达；每张卡片保留真实投递属性，不声称外部送达。")}<section class="metrics">${metric(state.notifications.length,"消息总数","当前角色可见")}${metric(state.notifications.filter(x=>x.status==="DELIVERED").length,"待回应","已模拟送达")}${metric(state.notifications.filter(x=>x.status==="RESPONDED").length,"已回复","说明或申诉")}${metric(state.notifications.filter(x=>x.status==="ACKNOWLEDGED").length,"已确认","结果通知")}</section>${notificationCards()}`); }

function renderMap() {
  const alert=isEmergency();
  app.innerHTML=shell(`${pageHead("CAMPUS MAP","校园态势地图","示意地图层级和设备状态来自校区 topology 与 operations projection。地图仅表达当前演示现场。")}<div class="grid two"><section class="map-board" aria-label="演示校区示意地图"><div class="campus-outline"><span class="building lib">图书馆<br>非演示区域</span><span class="building chem">化学楼<br>三层</span><span class="road h"></span><span class="road v"></span><span class="room-node ${alert?"alert":""}"><i></i><b>实验室 301</b></span></div><div class="map-legend">${alert?"朱红：烟雾与高温联动":"蓝点：标准现场"}<br>SIMULATED SENSOR</div></section><aside><div class="panel-head"><h2>空间层级</h2><span>${locations().length} LOCATIONS</span></div><div class="list">${locations().map(loc=>`<div class="list-item"><div><h3>${esc(loc.display_name)}</h3><p>${esc(loc.kind)} · ${esc(loc.location_id)}</p></div><span class="badge">${esc(loc.parent_location_id||"ROOT")}</span></div>`).join("")}</div><div class="panel-head" style="margin-top:26px"><h2>实验室来源</h2><span>${sources().length} SOURCES</span></div>${sources().map(item=>`<div class="card ${sourceValue(item).includes("烟雾")||sourceValue(item).includes("82")?"alert":""}"><h3>${esc(item.source.sensor_type||"录像机位")}</h3><p>${esc(sourceValue(item))} · ${esc(item.observation_state)}</p></div>`).join("")}</aside></div>`);
}

function renderKnowledge() {
  app.innerHTML=shell(`${pageHead("OFFLINE KNOWLEDGE","知识库","查询校内安全规范、实验室 PPE 与应急处置文档。未命中时明确返回 NO_MATCH。")}<div class="grid two"><section class="panel"><div class="field"><label for="knowledge-query">知识问题</label><textarea id="knowledge-query">进入化学实验室需要佩戴哪些个人防护装备？</textarea></div><div class="quick-list"><button class="quick" data-query="护目镜有什么要求？">护目镜要求</button><button class="quick" data-query="发现烟雾和高温后如何处置？">烟雾应急</button><button class="quick" data-query="学生如何提交说明和申诉？">说明与申诉</button></div><div class="form-actions" style="margin-top:16px"><button class="button primary" type="button" data-action="knowledge-query">查询知识库</button></div></section><aside class="panel" id="knowledge-answer">${empty("等待查询","答案由离线严格意图路由与现有知识库生成。")}</aside></div>`);
}

function renderAgent() {
  const messages=state.agentMessages.length?state.agentMessages.map(m=>`<div class="message ${m.kind}"><p>${esc(m.text)}</p><small>${esc(m.meta||"")}</small></div>`).join(""):empty("等待提问","Agent 只查询现有 authority 或提出需确认的操作卡，不直接写数据库。");
  const action=state.action?`<div class="action-card"><p class="eyebrow">PROPOSED ACTION</p><h3>${esc(state.action.action_kind)}</h3><p>${esc(state.action.impact_summary)}</p><code>目标 ${esc(state.action.target_ref)} · 版本 ${state.action.current_version}</code><button class="button primary" data-action="confirm-agent">确认并交给业务接口执行</button></div>`:empty("无待确认操作","领导和学生只会收到查询与知识回答。")
  app.innerHTML=shell(`${pageHead("DETERMINISTIC AGENT","安全运营 Agent","默认离线、确定性路由。操作卡闭合、带目标与版本，且必须由人确认。")}<div class="agent-layout"><section><div class="panel agent-log">${messages}</div><div class="panel" style="margin-top:12px"><div class="field"><label for="agent-query">输入查询或明确操作意图</label><textarea id="agent-query" placeholder="例如：查看当前案件；触发烟雾与温度场景；如何佩戴护目镜"></textarea></div><div class="form-actions"><button class="button primary" data-action="agent-query">发送</button></div></div></section><aside>${action}</aside></div>`);
}

function renderProfile() {
  const authority=state.session.authority;
  app.innerHTML=shell(`${pageHead("SESSION AUTHORITY","我的资料","角色、范围和能力全部来自服务端 session 投影；切换角色会清除当前标签页令牌。",`<a class="button" href="/login" data-action="switch-role">切换演示角色</a>`)}<div class="grid two"><section class="panel"><div class="facts"><div class="fact"><span>角色</span><strong>${esc(ROLE_LABELS[authority.role])}</strong></div><div class="fact"><span>主体</span><strong>${esc(authority.actor_id)}</strong></div><div class="fact"><span>范围</span><strong>${esc(authority.scope_kind)}</strong></div><div class="fact"><span>版本</span><strong>V${authority.authority_revision}</strong></div></div><h2 class="section-title">能力</h2><div class="quick-list">${authority.capabilities.map(value=>`<span class="badge">${esc(value)}</span>`).join("")}</div></section><aside class="panel"><h2 class="section-title">Demo 边界</h2><p>personal_demo_only=true</p><p>production_ready=false</p><p>令牌位置：sessionStorage</p><p>网络模型调用：无</p></aside></div>`);
}

function renderSettings() {
  const ops=role()==="OPERATIONS";
  const userRows=(state.users||[]).map(item=>{const a=item.authority||item;return `<tr><td>${esc(a.actor_id)}</td><td>${esc(a.role)}</td><td>${esc(a.scope_kind)}</td><td>V${a.authority_revision}</td></tr>`}).join("");
  const reset=ops?`<section class="panel"><div class="panel-head"><h2>演示现场复位</h2><span>OPERATIONS ONLY</span></div><p>复位会将当前数据库和演示回执归档到 session 目录，再原子替换为无案件、无告警的标准现场。历史不会删除。</p><button class="button alarm" type="button" data-action="reset">确认归档并一键复位</button></section>`:"";
  app.innerHTML=shell(`${pageHead("PLATFORM SETTINGS","设备、规则与权限","展示当前 authority 和设备来源状态。只有运维角色可复位演示现场。")}<div class="grid two"><section><div class="panel-head"><h2>来源与接口</h2><span>${sources().length} REGISTERED</span></div><div class="table-wrap"><table class="table"><thead><tr><th>设备</th><th>类型</th><th>适配器</th><th>状态</th></tr></thead><tbody>${sources().map(x=>`<tr><td>${esc(x.source.device_id)}</td><td>${esc(x.source.sensor_type||x.source.source_kind)}</td><td>${esc(x.source.adapter_id)}</td><td>${esc(x.observation_state)}</td></tr>`).join("")}</tbody></table></div></section><aside>${reset}<section class="panel" style="margin-top:${reset?"18px":"0"}"><div class="panel-head"><h2>规则状态</h2><span>SERVER AUTHORITY</span></div><p>${state.rules?`当前规则修订 V${esc(state.rules.revision||state.rules.authority_revision||"—")}`:"当前角色无规则读取权限"}</p><p class="help">烟雾与温度联动由后端规则生成 EMERGENCY，不通过页面属性伪造。</p></section></aside></div><section style="margin-top:30px"><div class="panel-head"><h2>用户权限</h2><span>${state.users?state.users.length:"ROLE-SCOPED"}</span></div>${state.users?`<div class="table-wrap"><table class="table"><thead><tr><th>用户</th><th>角色</th><th>范围</th><th>版本</th></tr></thead><tbody>${userRows}</tbody></table></div>`:empty("权限清单不可见","当前角色不具备用户权限管理能力。")}</section>`);
}

async function renderRoute() {
  clearTimeout(state.pollTimer); const path=location.pathname;
  if(path==="/"){renderHome();return} if(path==="/login"){renderLogin();return}
  if(!state.token){location.assign("/login");return}
  try { if(!state.session){app.innerHTML=`${publicRibbon()}<main class="boot-state"><span class="spinner"></span><p>正在读取角色 authority…</p></main>`;await loadCore();} loadingPage();
    if(path==="/app/settings"){[state.users,state.rules]=await Promise.all([optional("/api/m8/users",null),optional("/api/m8/rules",null)]);}
    if(path==="/app/monitor")renderMonitor(); else if(path==="/app/cases")renderCases(); else if(path.startsWith("/app/cases/"))await renderCaseDetail(decodeURIComponent(path.split("/").pop())); else if(path==="/app/map")renderMap(); else if(path==="/app/notifications")renderNotifications(); else if(path==="/app/knowledge")renderKnowledge(); else if(path==="/app/agent")renderAgent(); else if(path==="/app/profile")renderProfile(); else if(path==="/app/settings")renderSettings(); else location.assign("/app/monitor");
  } catch(error){errorPage(error)}
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
  if(target.dataset.login){target.disabled=true;try{const response=await api("/api/m8/demo/login",{method:"POST",body:{role:target.dataset.login}});state.token=response.bearer_token;state.session=response.session;sessionStorage.setItem(TOKEN_KEY,state.token);location.assign("/app/monitor");}catch(error){target.disabled=false;toast(error.message,"error");}return;}
  if(target.dataset.action==="logout"){logout();return} if(target.dataset.action==="switch-role"){event.preventDefault();logout();return} if(target.dataset.action==="reload"){state.session=null;renderRoute();return}
  try {
    if(target.dataset.scenario){target.disabled=true;state.run=await api("/api/m8/demo/scenario-runs",{method:"POST",body:{scenario_kind:target.dataset.scenario,explicit_human_confirmation:true}});await loadCore();renderMonitor();toast("场景已启动，阶段将按真实产物更新");return;}
    if(target.dataset.transition){target.disabled=true;await transitionCase(target.dataset.case,target.dataset.transition);await refresh("案件状态已由服务端状态机更新");return;}
    if(target.dataset.dispatch){target.disabled=true;await api(`/api/m8/cases/${target.dataset.case}/notification-dispatches`,{method:"POST",body:{kind:target.dataset.dispatch,explicit_human_confirmation:true}});await refresh("新通知卡已通过本地模拟通道送达");return;}
    if(target.dataset.reply){const box=document.getElementById(`reply-${target.dataset.notification}`);const body=box?.value?.trim();if(!body){toast("请先填写正文","error");return}target.disabled=true;const receipt=await api(`/api/m8/notifications/${target.dataset.notification}/replies`,{method:"POST",body:{reply_kind:target.dataset.reply,body,explicit_human_confirmation:true}});if(target.dataset.reply==="APPEAL_REQUEST"){const reply=receipt.audit_event?.transition_command?.reply;if(!reply)throw new Error("回复已记录，但回复 authority 尚不可读取，请重试案件申诉步骤");try{await transitionCase(target.dataset.case,"SUBMIT_APPEAL",[{kind:"NOTIFICATION_REPLY",authority_id:reply.reply_authority_id,document_sha256:reply.reply_document_sha256}]);}catch(error){await refresh(`申诉回复已记录；案件提交未完成，可从案件页重试：${error.message}`);return;}}await refresh(target.dataset.reply==="APPEAL_REQUEST"?"申诉回复与案件申诉状态均已记录":"说明已记录，原通知未被改写");return;}
    if(target.dataset.ack){target.disabled=true;await api(`/api/m8/notifications/${target.dataset.ack}/acknowledgements`,{method:"POST",body:{explicit_human_confirmation:true}});await refresh("结果通知已确认");return;}
    if(target.dataset.query){document.getElementById("knowledge-query").value=target.dataset.query;return;}
    if(target.dataset.action==="knowledge-query"){const query=document.getElementById("knowledge-query").value.trim();if(!query)return;target.disabled=true;const answer=await api("/api/m8/agent/queries",{method:"POST",body:{query}});document.getElementById("knowledge-answer").innerHTML=`<p class="eyebrow">${answer.outcome}</p><h2 class="section-title">离线回答</h2><p>${esc(answer.answer)}</p><p class="help mono">${answer.source_refs.map(short).join(" · ")||"无匹配引用"}</p>`;target.disabled=false;return;}
    if(target.dataset.action==="agent-query"){const input=document.getElementById("agent-query"),query=input.value.trim();if(!query)return;target.disabled=true;state.agentMessages.push({kind:"user",text:query,meta:ROLE_LABELS[role()]});const answer=await api("/api/m8/agent/queries",{method:"POST",body:{query}});state.agentMessages.push({kind:"agent",text:answer.answer,meta:`${answer.outcome} · MODEL_USED=${answer.model_used}`});state.action=answer.proposed_action;renderAgent();return;}
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

document.addEventListener("click",handleClick);
window.addEventListener("pageshow",()=>renderRoute());

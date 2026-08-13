"use strict";

window.LabCourtAgentChat=(()=>{
  let context=null,modelStatus=null,conversations=[],activeConversation=null,busy=false;
  const executionLabels={LIVE_QWEN:"QWEN LIVE",CACHE_REPLAY:"CACHE REPLAY",OFFLINE_FALLBACK:"OFFLINE FALLBACK",DETERMINISTIC_ACTION:"DETERMINISTIC ACTION"};
  const toolLabels={READ_CASES:"案件",READ_NOTIFICATIONS:"通知",READ_OPERATIONS_PROJECTION:"设备 / 传感器 / 地图",QUERY_KNOWLEDGE:"知识库"};
  const storageKey=()=>`labcourt.agent.conversation.${context.state.session?.authority?.actor_id||"anonymous"}`;

  function statusCopy(){
    if(!modelStatus)return ["状态读取中","尚未读取模型配置"];
    if(modelStatus.availability==="NOT_CONFIGURED")return ["OFFLINE FALLBACK","未配置 Qwen，当前使用确定性离线能力"];
    if(modelStatus.availability==="DEGRADED")return ["QWEN DEGRADED",`最近调用失败 · ${modelStatus.last_failure_code||"UNKNOWN"}`];
    if(modelStatus.availability==="AVAILABLE")return ["QWEN AVAILABLE",`${modelStatus.model} · 最近调用已完成`];
    return ["QWEN CONFIGURED",`${modelStatus.model} · 尚未主动探测`];
  }

  function sourceMarkup(completion){
    const refs=(completion.source_refs||[]).map(item=>`<span>${context.esc(item)}</span>`).join("");
    const tools=(completion.tool_receipts||[]).map(item=>`<span class="agent-tool-chip">${context.esc(toolLabels[item.tool_kind]||item.tool_kind)} · ${item.result_count}</span>`).join("");
    const citations=(completion.knowledge_projection?.document_hits||[]).map(item=>`<details><summary>${context.esc(item.document_type)} · ${context.esc(item.logical_document_id)} · V${item.document_version}</summary><blockquote>${context.esc(item.exact_snippet)}</blockquote><code>${context.esc(item.source_ref)} · ${context.short(item.citation_id)} · [${item.start_char}, ${item.end_char})</code></details>`).join("");
    return `${tools?`<div class="agent-tool-chips">${tools}</div>`:""}${refs?`<div class="agent-sources">${refs}</div>`:""}${citations?`<div class="agent-chat-citations">${citations}</div>`:""}`;
  }

  function actionMarkup(completion){
    if(!completion.proposed_action)return "";
    context.state.action=completion.proposed_action;
    return context.agentActionMarkup();
  }

  function turnMarkup(turn){
    const completion=turn.completion;
    const terminal=completion?`<article class="agent-message agent"><div class="agent-avatar">A</div><div><p>${context.esc(completion.answer)}</p>${sourceMarkup(completion)}<small>${context.esc(completion.outcome)} · ${context.esc(executionLabels[completion.execution_mode]||completion.execution_mode)} · ${completion.model_call_receipts?.length||0} MODEL CALL</small></div></article>${actionMarkup(completion)}`:turn.state==="FAILED"?`<article class="agent-message agent failed"><div class="agent-avatar">!</div><div><p>本轮没有形成完整回答，已保留 typed failure。</p><small>${context.esc(turn.failure_code)}</small><button type="button" class="button quiet" data-agent-retry="${context.esc(turn.user_text)}">重试本轮</button></div></article>`:`<article class="agent-message agent"><div class="agent-avatar">A</div><div><p>该轮仍在处理中。</p><small>ACCEPTED</small></div></article>`;
    return `<article class="agent-message user"><div class="agent-avatar">你</div><div><p>${context.esc(turn.user_text)}</p><small>${context.esc(context.state.session?.authority?.role)}</small></div></article>${terminal}`;
  }

  function conversationListMarkup(){
    return conversations.map(item=>`<button type="button" data-agent-conversation="${item.conversation_id}" class="${activeConversation?.summary?.conversation_id===item.conversation_id?"active":""}"><strong>${context.esc(item.title)}</strong><span>${item.turn_count} TURN · ${new Date(item.latest_activity_at).toLocaleString("zh-CN",{month:"numeric",day:"numeric",hour:"2-digit",minute:"2-digit"})}</span></button>`).join("")||`<p class="help">尚无会话</p>`;
  }

  function workspaceMarkup(){
    const [status,statusDetail]=statusCopy();
    const turns=(activeConversation?.turns||[]).map(turnMarkup).join("")||`<article class="agent-message agent"><div class="agent-avatar">A</div><div><p>我是 LabCourt 平台 Agent。可以自然交流，也可以通过可信工具读取你有权查看的案件、通知、设备、传感器、地图和本地知识。</p><small>写操作仍只生成待确认卡</small></div></article>`;
    const prompt=new URL(location.href).searchParams.get("q")||"";
    return `${context.pageHead("TOOL-GROUNDED PLATFORM AGENT","安全运营 Agent","真实 Qwen 只负责多轮编排与表述；平台事实来自角色裁剪后的只读工具，写操作继续走既有确定性确认卡。")}
      <div class="agent-chat-layout">
        <aside class="agent-conversations"><header><div><p class="eyebrow">PERSISTENT CHAT</p><h2>对话</h2></div><button type="button" data-agent-new aria-label="新对话">＋</button></header><div data-agent-conversation-list>${conversationListMarkup()}</div><footer>会话绑定创建时 actor authority<br>权限换版后旧会话自动封存</footer></aside>
        <section class="agent-console agent-chat-console">
          <div class="agent-console-head ${modelStatus?.availability==="AVAILABLE"?"live":""}"><span><i></i>${context.esc(status)}</span><small>${context.esc(statusDetail)}</small></div>
          <div id="agent-messages" class="agent-messages" aria-live="polite">${turns}<div id="agent-action-host"></div><div data-agent-live-anchor></div></div>
          <div class="agent-live-tools" data-agent-tools hidden></div>
          <div class="agent-quick-list">${context.agentQuickPrompts().filter(([query])=>!query.includes("飞书")).map(([query,label])=>`<button type="button" class="agent-quick" data-agent-v3-quick="${context.esc(query)}">${context.esc(label)} <i>↗</i></button>`).join("")}</div>
          <form class="agent-composer" data-agent-v3-form><label for="agent-query" class="sr-only">给平台 Agent 发送消息</label><textarea id="agent-query" maxlength="4096" rows="2" placeholder="问案件、设备、传感器、地图或知识，也可以直接聊天…">${context.esc(prompt)}</textarea><button type="submit" data-agent-send aria-label="发送给 Agent">发送 <i>→</i></button></form>
        </section>
        <aside class="agent-context agent-chat-context"><header><span class="agent-mark">A</span><div><p class="eyebrow">TRUSTED CONTEXT</p><h2>本轮边界</h2></div></header><div><p><span>当前角色</span><strong>${context.esc(context.state.session?.authority?.role)}</strong></p><p><span>模型</span><strong>${context.esc(modelStatus?.model||"OFFLINE")}</strong></p><p><span>工具调用</span><strong>READ ONLY</strong></p><p><span>联网搜索</span><strong>DISABLED</strong></p><p><span>并行工具</span><strong>DISABLED</strong></p></div><footer>API Key 不进入浏览器、SQLite 或日志<br>引用与 raw response receipt 由服务端持久化</footer></aside>
      </div>
      <div id="agent-confirm-modal" class="agent-modal" hidden><div class="agent-modal__backdrop" data-action="close-agent-confirm"></div><section role="dialog" aria-modal="true" aria-labelledby="agent-confirm-title"><p class="eyebrow">HUMAN CONFIRMATION</p><h2 id="agent-confirm-title">确认执行操作卡？</h2><p data-agent-confirm-copy>${context.esc(context.state.action?.impact_summary||"")}</p><code data-agent-confirm-ref>${context.state.action?`${context.esc(context.state.action.target_ref)} · V${context.state.action.current_version}`:""}</code><div class="form-actions"><button type="button" class="button quiet" data-action="close-agent-confirm">取消</button><button type="button" class="button primary" data-action="confirm-agent">确认并交给业务接口</button></div></section></div>`;
  }

  function bind(){
    const root=document.querySelector(".agent-chat-layout");if(!root)return;
    root.dataset.agentBound="true";
    root.addEventListener("click",async event=>{
      const target=event.target.closest("button");if(!target)return;
      if(target.dataset.agentConversation){await selectConversation(target.dataset.agentConversation);return;}
      if(target.hasAttribute("data-agent-new")){await newConversation();return;}
      if(target.dataset.agentV3Quick!==undefined){const box=document.getElementById("agent-query");box.value=target.dataset.agentV3Quick;box.focus();return;}
      if(target.dataset.agentRetry!==undefined)await sendTurn(target.dataset.agentRetry);
    });
    root.querySelector("[data-agent-v3-form]")?.addEventListener("submit",async event=>{event.preventDefault();const box=document.getElementById("agent-query"),query=box?.value.trim();if(!query||busy)return;box.value="";await sendTurn(query);});
    if(new URL(location.href).searchParams.get("q"))document.getElementById("agent-query")?.focus();
  }

  async function render(ctx){
    context=ctx;
    context.setRouteContent(`${context.pageHead("PLATFORM AGENT","安全运营 Agent","正在恢复角色隔离的 Agent 会话。")}`+`<section class="panel agent-chat-loading"><span class="spinner"></span><p>正在读取模型状态与会话 authority…</p></section>`,{announcement:"安全运营 Agent"});
    [modelStatus,conversations]=await Promise.all([context.api("/api/m8/agent/status"),context.api("/api/m8/agent/conversations")]);
    let id=sessionStorage.getItem(storageKey());
    if(!id||!conversations.some(item=>item.conversation_id===id))id=conversations[0]?.conversation_id;
    if(!id){const created=await context.api("/api/m8/agent/conversations",{method:"POST",body:{}});conversations=[created];id=created.conversation_id;}
    activeConversation=await context.api(`/api/m8/agent/conversations/${encodeURIComponent(id)}`);sessionStorage.setItem(storageKey(),id);context.state.action=[...(activeConversation.turns||[])].reverse().find(item=>item.completion?.proposed_action)?.completion?.proposed_action||null;
    context.setRouteContent(workspaceMarkup(),{announcement:"安全运营 Agent",mount:()=>{bind();scrollMessages();}});
  }

  async function selectConversation(id){
    if(busy)return;activeConversation=await context.api(`/api/m8/agent/conversations/${encodeURIComponent(id)}`);sessionStorage.setItem(storageKey(),id);context.state.action=[...(activeConversation.turns||[])].reverse().find(item=>item.completion?.proposed_action)?.completion?.proposed_action||null;context.setRouteContent(workspaceMarkup(),{announcement:"已恢复 Agent 会话",mount:()=>{bind();scrollMessages();}});
  }

  async function newConversation(){
    if(busy)return;const created=await context.api("/api/m8/agent/conversations",{method:"POST",body:{}});conversations=[created,...conversations];activeConversation={summary:created,turns:[]};sessionStorage.setItem(storageKey(),created.conversation_id);context.state.action=null;context.setRouteContent(workspaceMarkup(),{announcement:"已创建新对话",mount:()=>{bind();document.getElementById("agent-query")?.focus();}});
  }

  function scrollMessages(){const host=document.getElementById("agent-messages");if(host)host.scrollTop=host.scrollHeight;}

  function appendLive(query){
    const anchor=document.querySelector("[data-agent-live-anchor]");if(!anchor)return null;
    anchor.insertAdjacentHTML("beforebegin",`<article class="agent-message user"><div class="agent-avatar">你</div><div><p>${context.esc(query)}</p><small>${context.esc(context.state.session?.authority?.role)}</small></div></article><article class="agent-message agent is-streaming" data-agent-live-message><div class="agent-avatar">A</div><div><p data-agent-live-text></p><div class="agent-stream-state"><span class="spinner"></span><small data-agent-live-state>已接受，正在编排可信工具…</small></div></div></article>`);scrollMessages();return document.querySelector("[data-agent-live-message]");
  }

  function updateTool(event){
    const host=document.querySelector("[data-agent-tools]");if(!host)return;host.hidden=false;
    if(event.event_kind==="tool.started")host.insertAdjacentHTML("beforeend",`<span data-call="${context.esc(event.tool_call_id)}"><i></i>正在读取${context.esc(toolLabels[event.tool_kind]||event.tool_kind)}</span>`);
    else {const node=host.querySelector(`[data-call="${CSS.escape(event.tool_call_id)}"]`);if(node){node.classList.add("done");node.innerHTML=`<i></i>${context.esc(toolLabels[event.tool_kind]||event.tool_kind)}已返回 · ${(event.source_refs||[]).length} REF`;}}
  }

  async function sendTurn(query){
    if(busy||!activeConversation)return;busy=true;const live=appendLive(query),button=document.querySelector("[data-agent-send]");if(button){button.disabled=true;button.setAttribute("aria-busy","true");}
    try{
      const response=await fetch(`/api/m8/agent/conversations/${encodeURIComponent(activeConversation.summary.conversation_id)}/turns`,{method:"POST",headers:{Accept:"text/event-stream","Content-Type":"application/json",Authorization:`Bearer ${context.state.token}`},body:JSON.stringify({query})});
      if(!response.ok){let reason=`HTTP ${response.status}`;try{const body=await response.json();reason=body.failure_code||body.reason_code||reason;}catch(_error){}throw new Error(reason);}
      let completion=null,failure=null;
      await readEvents(response,event=>{
        if(event.event_kind==="tool.started"||event.event_kind==="tool.completed")updateTool(event);
        if(event.event_kind==="message.delta"){const text=live?.querySelector("[data-agent-live-text]");if(text)text.textContent+=event.text_delta;const label=live?.querySelector("[data-agent-live-state]");if(label)label.textContent="正在接收回答…";scrollMessages();}
        if(event.event_kind==="message.completed")completion=event.completion;
        if(event.event_kind==="turn.failed")failure=event.failure_code;
      });
      if(failure)throw new Error(failure);
      if(!completion)throw new Error("STREAM_INTERRUPTED");
      activeConversation=await context.api(`/api/m8/agent/conversations/${encodeURIComponent(activeConversation.summary.conversation_id)}`);
      conversations=await context.api("/api/m8/agent/conversations");modelStatus=await context.api("/api/m8/agent/status");context.state.action=completion.proposed_action||null;context.setRouteContent(workspaceMarkup(),{announcement:"Agent 回答已完成",mount:()=>{bind();scrollMessages();}});
    }catch(error){if(live){live.classList.remove("is-streaming");live.classList.add("failed");live.querySelector("[data-agent-live-text]").textContent="本轮没有形成完整回答。";live.querySelector("[data-agent-live-state]").textContent=error.message;live.querySelector(".agent-stream-state")?.insertAdjacentHTML("beforeend",`<button type="button" class="button quiet" data-agent-retry="${context.esc(query)}">重试</button>`);}context.toast(error.message,"error");}
    finally{busy=false;if(button){button.disabled=false;button.removeAttribute("aria-busy");}document.querySelector("[data-agent-tools]")?.replaceChildren();}
  }

  async function readEvents(response,onEvent){
    if(!response.body)throw new Error("STREAM_UNAVAILABLE");const reader=response.body.getReader(),decoder=new TextDecoder("utf-8",{fatal:true});let buffer="",bytes=0;
    while(true){const {done,value}=await reader.read();if(done)break;bytes+=value.byteLength;if(bytes>4*1024*1024)throw new Error("STREAM_TOO_LARGE");buffer+=decoder.decode(value,{stream:true});const blocks=buffer.split(/\r?\n\r?\n/);buffer=blocks.pop()||"";for(const block of blocks){const data=block.split(/\r?\n/).filter(line=>line.startsWith("data:" )).map(line=>line.slice(5).trimStart()).join("\n");if(data)onEvent(JSON.parse(data));}}
    buffer+=decoder.decode();if(buffer.trim())throw new Error("STREAM_INTERRUPTED");
  }

  return {render};
})();

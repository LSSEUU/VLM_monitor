"use strict";

window.LabCourtAgentChat=(()=>{
  let context=null;
  let modelStatus=null;
  let conversations=[];
  let activeConversation=null;
  let channelProjections=new Map();
  let busy=false;
  let sidebarCollapsed=false;
  let pendingDeleteConversationId=null;
  let deletingConversation=false;
  let deleteReturnFocus=null;

  const toolLabels={
    READ_CASES:"案件",
    READ_NOTIFICATIONS:"通知",
    READ_OPERATIONS_PROJECTION:"设备 / 传感器 / 地图",
    QUERY_KNOWLEDGE:"知识库",
    READ_FEISHU_STATUS:"飞书状态",
  };
  const actionLabels={
    CASE_TRANSITION:"案件状态操作",
    NOTIFICATION_SEND:"通知发送",
    RUN_SCENARIO:"运行演示场景",
    RESET_DEMO:"复位演示现场",
    FEISHU_TEST_CARD_CHECK:"飞书测试卡检查",
  };
  const storageKey=()=>`labcourt.agent.conversation.${context.state.session?.authority?.actor_id||"anonymous"}`;
  const sidebarKey=()=>`labcourt.agent.sidebar.${context.state.session?.authority?.actor_id||"anonymous"}`;
  const reducedMotion=()=>matchMedia("(prefers-reduced-motion: reduce)").matches;
  const isMobile=()=>matchMedia("(max-width: 700px)").matches;
  const modelCanSend=()=>modelStatus?.availability!=="NOT_CONFIGURED"&&modelStatus!==null;

  function statusCopy(){
    if(!modelStatus)return {kind:"loading",label:"正在连接 Qwen",detail:""};
    if(modelStatus.availability==="NOT_CONFIGURED")return {kind:"blocked",label:"Qwen 未配置",detail:"配置后重启服务"};
    if(modelStatus.availability==="DEGRADED")return {kind:"failed",label:"Qwen 调用失败",detail:modelStatus.last_failure_code||"请重试"};
    if(modelStatus.availability==="AVAILABLE")return {kind:"ready",label:"Qwen 已就绪",detail:modelStatus.model};
    return {kind:"ready",label:"Qwen 已配置",detail:"发送消息开始连接"};
  }

  function failureCopy(code){
    const values={
      NOT_CONFIGURED:"Qwen 尚未配置，请配置后重启服务。",
      PROVIDER_TIMEOUT:"Qwen 响应超时，请重试。",
      TRANSPORT_UNAVAILABLE:"暂时无法连接 Qwen，请检查网络后重试。",
      PROVIDER_REJECTED:"Qwen 拒绝了本次请求，请检查模型授权。",
      RESPONSE_INVALID:"Qwen 返回了无法使用的响应，请重试。",
      RESPONSE_TOO_LARGE:"Qwen 返回内容超过本轮上限。",
      TOOL_ARGUMENT_INVALID:"Qwen 提交了无效的查询参数。",
      TOOL_FORBIDDEN:"Qwen 尝试了当前角色无权使用的工具。",
      TOOL_LOOP_LIMIT:"本轮工具查询次数已达到上限。",
      STREAM_INTERRUPTED:"Qwen 流式响应中断，请重试。",
      AUTHORITY_CHANGED:"当前权限已变化，请新建对话。",
    };
    return values[code]||"本轮未能完成，请重试。";
  }

  function sourceMarkup(completion){
    const tools=(completion.tool_receipts||[]).map(item=>`<span class="agent-tool-chip">已查询${context.esc(toolLabels[item.tool_kind]||item.tool_kind)} · ${item.result_count}</span>`).join("");
    const refs=(completion.source_refs||[]).map(item=>`<span>${context.esc(item)}</span>`).join("");
    const citations=(completion.knowledge_projection?.document_hits||[]).map(item=>`<details><summary>${context.esc(item.document_type)} · ${context.esc(item.logical_document_id)} · V${item.document_version}</summary><blockquote>${context.esc(item.exact_snippet)}</blockquote><code>${context.esc(item.source_ref)} · ${context.short(item.citation_id)} · [${item.start_char}, ${item.end_char})</code></details>`).join("");
    return `${tools?`<div class="agent-tool-chips">${tools}</div>`:""}${citations?`<div class="agent-chat-citations">${citations}</div>`:""}${refs?`<details class="agent-source-receipts"><summary>查看 ${completion.source_refs.length} 个可信来源</summary><div>${refs}</div></details>`:""}`;
  }

  function compactActionMarkup(action){
    if(!action)return "";
    return `<article class="agent-action-card"><p class="eyebrow">待确认操作</p><h3>${context.esc(actionLabels[action.action_kind]||action.action_kind)}</h3><p>${context.esc(action.impact_summary)}</p><div class="agent-action-summary"><span>目标 ${context.esc(action.target_ref)}</span><span>版本 V${action.current_version}</span></div><button class="button primary" type="button" data-action="open-agent-confirm">检查并确认 →</button></article>`;
  }

  function completionState(completion){
    if(completion.execution_mode==="DETERMINISTIC_ACTION")return completion.proposed_action?"待确认操作":"业务检查";
    if(completion.execution_mode==="OFFLINE_FALLBACK"||completion.execution_mode==="CACHE_REPLAY")return "历史回答";
    if(completion.outcome==="NO_MATCH")return "未找到匹配";
    return "Qwen";
  }

  function turnMarkup(turn){
    const completion=turn.completion;
    let terminal;
    if(completion){
      terminal=`<article class="agent-message agent"><div class="agent-avatar">A</div><div><p>${context.esc(completion.answer)}</p>${sourceMarkup(completion)}<span class="agent-message-state">${context.esc(completionState(completion))}</span></div></article>`;
    }else if(turn.state==="FAILED"){
      terminal=`<article class="agent-message agent failed"><div class="agent-avatar">!</div><div><p>${context.esc(failureCopy(turn.failure_code))}</p><button type="button" class="button quiet" data-agent-retry="${context.esc(turn.user_text)}">重试</button></div></article>`;
    }else{
      terminal=`<article class="agent-message agent"><div class="agent-avatar">A</div><div><div class="agent-stream-state"><span class="spinner"></span><span>正在处理…</span></div></div></article>`;
    }
    return `<article class="agent-message user"><div class="agent-avatar">你</div><div><p>${context.esc(turn.user_text)}</p></div></article>${terminal}`;
  }

  function messagesMarkup(){
    const turns=(activeConversation?.turns||[]).map(turnMarkup).join("");
    const welcome=`<article class="agent-message agent agent-welcome"><div class="agent-avatar">A</div><div><p>你好，我可以帮你查询案件、设备、通知和知识库。</p></div></article>`;
    return `${turns||welcome}<div id="agent-action-host">${compactActionMarkup(context.state.action)}</div><div data-agent-live-anchor></div>`;
  }

  function conversationListMarkup(){
    if(!conversations.length)return `<p class="agent-list-empty">还没有对话</p>`;
    return conversations.map((item,index)=>{
      const active=activeConversation?.summary?.conversation_id===item.conversation_id;
      const title=context.esc(item.title);
      const channel=channelProjections.has(item.conversation_id)?`<em class="agent-channel-badge">飞书</em>`:"";
      return `<div class="agent-conversation-row ${active?"active":""}" style="--agent-item-index:${index}"><button type="button" data-agent-conversation="${item.conversation_id}" class="${active?"active":""}" aria-pressed="${active}"><i class="agent-conversation-index" aria-hidden="true">${String(index+1).padStart(2,"0")}</i><span class="agent-conversation-copy"><strong data-agent-conversation-title>${title}${channel}</strong><small data-agent-conversation-meta>${item.turn_count} 轮 · ${new Date(item.latest_activity_at).toLocaleString("zh-CN",{month:"numeric",day:"numeric",hour:"2-digit",minute:"2-digit"})}</small></span></button><button type="button" class="agent-conversation-delete" data-agent-delete-conversation="${item.conversation_id}" aria-label="删除对话：${title}" title="删除对话">删</button></div>`;
    }).join("");
  }

  async function loadChannelProjections(){
    const rows=await Promise.all(conversations.map(async item=>{
      try{return [item.conversation_id,await context.api(`/api/m8/agent/conversations/${encodeURIComponent(item.conversation_id)}/channel-projection`)];}
      catch(_){return [item.conversation_id,null];}
    }));
    channelProjections=new Map(rows.filter(([,projection])=>projection));
  }

  function quickPromptMarkup(){
    return context.agentQuickPrompts().filter(([query])=>!query.includes("飞书")).map(([query,label])=>`<button type="button" class="agent-quick" data-agent-v3-quick="${context.esc(query)}">${context.esc(label)} <i>↗</i></button>`).join("");
  }

  function workspaceMarkup(){
    const prompt=new URL(location.href).searchParams.get("q")||"";
    return `<header class="page-head agent-page-head"><div><p class="eyebrow">实时平台助手</p><h1>安全运营 Agent</h1><p class="deck">连接案件、通知、设备与知识库，用自然语言完成查询和处置准备。</p></div></header>
      <div class="agent-chat-layout ${sidebarCollapsed?"is-sidebar-collapsed":""}" data-agent-chat-root>
        <aside id="agent-conversations" class="agent-conversations" aria-label="Agent 对话列表">
          <header><h2>对话</h2><div><button type="button" data-agent-collapse aria-label="收起对话列表">‹</button><button type="button" data-agent-new aria-label="新对话">＋</button></div></header>
          <div data-agent-conversation-list><span class="spinner"></span></div>
        </aside>
        <button type="button" class="agent-conversation-scrim" data-agent-close-drawer aria-label="关闭对话列表"></button>
        <section class="agent-console agent-chat-console">
          <div class="agent-console-head" data-agent-model-state="loading">
            <button type="button" class="agent-sidebar-toggle" data-agent-toggle-sidebar aria-controls="agent-conversations" aria-expanded="${!sidebarCollapsed}" aria-label="打开对话列表">☰</button>
            <span class="agent-model-label"><i></i><b data-agent-status-label>正在连接 Qwen</b></span>
            <small data-agent-status-detail></small>
          </div>
          <div id="agent-messages" class="agent-messages" aria-live="polite">${messagesMarkup()}</div>
          <div class="agent-live-tools" data-agent-tools hidden></div>
          <div class="agent-quick-list">${quickPromptMarkup()}</div>
          <form class="agent-composer" data-agent-v3-form>
            <label for="agent-query" class="sr-only">给平台 Agent 发送消息</label>
            <textarea id="agent-query" maxlength="4096" rows="2" data-default-placeholder="问案件、设备、传感器、地图或知识，也可以直接聊天…" placeholder="正在连接 Qwen…" disabled>${context.esc(prompt)}</textarea>
            <button type="submit" data-agent-send aria-label="发送给 Agent" disabled>发送 <i>→</i></button>
          </form>
        </section>
      </div>
      <div id="agent-confirm-modal" class="agent-modal" hidden><div class="agent-modal__backdrop" data-action="close-agent-confirm"></div><section role="dialog" aria-modal="true" aria-labelledby="agent-confirm-title"><p class="eyebrow">确认操作</p><h2 id="agent-confirm-title">确认执行操作卡？</h2><p data-agent-confirm-copy>${context.esc(context.state.action?.impact_summary||"")}</p><code data-agent-confirm-ref>${context.state.action?`${context.esc(context.state.action.target_ref)} · V${context.state.action.current_version}`:""}</code><div class="form-actions"><button type="button" class="button quiet" data-action="close-agent-confirm">取消</button><button type="button" class="button primary" data-action="confirm-agent">确认执行</button></div></section></div>
      <div id="agent-delete-modal" class="agent-modal agent-delete-modal" hidden><div class="agent-modal__backdrop" data-agent-cancel-delete></div><section role="dialog" aria-modal="true" aria-labelledby="agent-delete-title"><p class="eyebrow">删除对话</p><h2 id="agent-delete-title">删除这条对话？</h2><p data-agent-delete-copy></p><div class="form-actions"><button type="button" class="button quiet" data-agent-cancel-delete>取消</button><button type="button" class="button danger" data-agent-confirm-delete>删除</button></div></section></div>`;
  }

  function root(){return document.querySelector("[data-agent-chat-root]");}

  function announce(value){
    const live=document.querySelector(".route-live-region");
    if(live)live.textContent=value;
  }

  function syncAction(){
    context.state.action=[...(activeConversation?.turns||[])].reverse().find(item=>item.completion?.proposed_action)?.completion?.proposed_action||null;
  }

  function patchConversationList(){
    const host=document.querySelector("[data-agent-conversation-list]");
    if(!host)return;
    const items=[...host.querySelectorAll("[data-agent-conversation]")];
    const sameItems=items.length===conversations.length&&items.every((item,index)=>item.dataset.agentConversation===conversations[index].conversation_id);
    if(!sameItems){
      host.innerHTML=conversationListMarkup();
      return;
    }
    items.forEach((item,index)=>{
      const conversation=conversations[index];
      const active=activeConversation?.summary?.conversation_id===conversation.conversation_id;
      item.classList.toggle("active",active);
      item.closest(".agent-conversation-row")?.classList.toggle("active",active);
      item.setAttribute("aria-pressed",String(active));
      const titleNode=item.querySelector("[data-agent-conversation-title]");
      titleNode.textContent=conversation.title;
      if(channelProjections.has(conversation.conversation_id))titleNode.insertAdjacentHTML("beforeend",'<em class="agent-channel-badge">飞书</em>');
      item.querySelector("[data-agent-conversation-meta]").textContent=`${conversation.turn_count} 轮 · ${new Date(conversation.latest_activity_at).toLocaleString("zh-CN",{month:"numeric",day:"numeric",hour:"2-digit",minute:"2-digit"})}`;
      const remove=item.closest(".agent-conversation-row")?.querySelector("[data-agent-delete-conversation]");
      if(remove)remove.setAttribute("aria-label",`删除对话：${conversation.title}`);
    });
  }

  function patchMessages({animate=true}={}){
    const host=document.getElementById("agent-messages");
    if(!host)return;
    host.innerHTML=messagesMarkup();
    if(animate&&!reducedMotion()){
      host.classList.remove("is-refreshed");
      void host.offsetWidth;
      host.classList.add("is-refreshed");
    }
    scrollMessages();
  }

  function patchComposer(){
    const box=document.getElementById("agent-query");
    const button=document.querySelector("[data-agent-send]");
    const unavailable=!modelCanSend();
    if(box){
      box.disabled=unavailable||busy;
      box.placeholder=unavailable?"请先配置 Qwen 并重启服务":box.dataset.defaultPlaceholder;
    }
    if(button){
      button.disabled=unavailable||busy;
      button.toggleAttribute("aria-busy",busy);
    }
  }

  function patchStatus(){
    const host=document.querySelector(".agent-console-head");
    if(!host)return;
    const status=statusCopy();
    host.dataset.agentModelState=status.kind;
    host.querySelector("[data-agent-status-label]").textContent=status.label;
    host.querySelector("[data-agent-status-detail]").textContent=status.detail;
    patchComposer();
  }

  function patchSidebarState(){
    const host=root();
    if(!host)return;
    host.classList.toggle("is-sidebar-collapsed",sidebarCollapsed&&!isMobile());
    host.querySelectorAll("[data-agent-toggle-sidebar]").forEach(button=>button.setAttribute("aria-expanded",String(isMobile()?host.classList.contains("is-drawer-open"):!sidebarCollapsed)));
  }

  function closeDrawer(){
    const host=root();
    host?.classList.remove("is-drawer-open");
    patchSidebarState();
  }

  function toggleSidebar(){
    const host=root();
    if(!host)return;
    if(isMobile()){
      host.classList.toggle("is-drawer-open");
    }else{
      sidebarCollapsed=!sidebarCollapsed;
      sessionStorage.setItem(sidebarKey(),String(sidebarCollapsed));
    }
    patchSidebarState();
  }

  function patchWorkspace({focus=false,animate=true}={}){
    syncAction();
    patchConversationList();
    patchMessages({animate});
    patchStatus();
    closeDrawer();
    if(focus&&!document.getElementById("agent-query")?.disabled)document.getElementById("agent-query")?.focus();
  }

  function bind(){
    const host=root();
    if(!host||host.dataset.agentBound)return;
    host.dataset.agentBound="true";
    host.addEventListener("click",async event=>{
      const target=event.target.closest("button");
      if(!target)return;
      if(target.hasAttribute("data-agent-toggle-sidebar")||target.hasAttribute("data-agent-collapse")){toggleSidebar();return;}
      if(target.hasAttribute("data-agent-close-drawer")){closeDrawer();return;}
      if(target.dataset.agentDeleteConversation){openDeleteConversation(target.dataset.agentDeleteConversation,target);return;}
      if(target.dataset.agentConversation){await selectConversation(target.dataset.agentConversation);return;}
      if(target.hasAttribute("data-agent-new")){await newConversation();return;}
      if(target.dataset.agentV3Quick!==undefined){const box=document.getElementById("agent-query");if(box&&!box.disabled){box.value=target.dataset.agentV3Quick;box.focus();}return;}
      if(target.dataset.agentRetry!==undefined)await sendTurn(target.dataset.agentRetry);
    });
    host.querySelector("[data-agent-v3-form]")?.addEventListener("submit",async event=>{
      event.preventDefault();
      const box=document.getElementById("agent-query"),query=box?.value.trim();
      if(!query||busy||!modelCanSend())return;
      box.value="";
      await sendTurn(query);
    });
    host.addEventListener("keydown",event=>{
      if(event.key==="Escape"&&host.classList.contains("is-drawer-open")){event.preventDefault();closeDrawer();return;}
      if(event.target.id==="agent-query"&&event.key==="Enter"&&(event.ctrlKey||event.metaKey)){event.preventDefault();host.querySelector("[data-agent-v3-form]")?.requestSubmit();}
    });
    const deleteModal=document.getElementById("agent-delete-modal");
    if(deleteModal&&!deleteModal.dataset.agentBound){
      deleteModal.dataset.agentBound="true";
      deleteModal.addEventListener("click",async event=>{
        if(event.target.closest("[data-agent-cancel-delete]")){closeDeleteConversation();return;}
        if(event.target.closest("[data-agent-confirm-delete]"))await removeConversation();
      });
      deleteModal.addEventListener("keydown",event=>{
        if(event.key==="Escape"){event.preventDefault();closeDeleteConversation();}
      });
    }
  }

  async function render(ctx){
    context=ctx;
    modelStatus=null;
    conversations=[];
    activeConversation=null;
    channelProjections=new Map();
    busy=false;
    sidebarCollapsed=sessionStorage.getItem(sidebarKey())==="true";
    pendingDeleteConversationId=null;
    deletingConversation=false;
    deleteReturnFocus=null;
    context.setRouteContent(workspaceMarkup(),{announcement:"安全运营 Agent",mount:()=>{bind();patchStatus();}});
    try{
      [modelStatus,conversations]=await Promise.all([context.api("/api/m8/agent/status"),context.api("/api/m8/agent/conversations")]);
      await loadChannelProjections();
      let id=sessionStorage.getItem(storageKey());
      if(!id||!conversations.some(item=>item.conversation_id===id))id=conversations[0]?.conversation_id;
      if(!id){
        const created=await context.api("/api/m8/agent/conversations",{method:"POST",body:{}});
        conversations=[created];
        id=created.conversation_id;
      }
      activeConversation=await context.api(`/api/m8/agent/conversations/${encodeURIComponent(id)}`);
      if(!channelProjections.has(id)){
        const projection=await context.api(`/api/m8/agent/conversations/${encodeURIComponent(id)}/channel-projection`);
        if(projection)channelProjections.set(id,projection);
      }
      sessionStorage.setItem(storageKey(),id);
      patchWorkspace({focus:Boolean(new URL(location.href).searchParams.get("q")),animate:false});
    }catch(error){
      const host=document.getElementById("agent-messages");
      if(host)host.innerHTML=`<article class="agent-message agent failed"><div class="agent-avatar">!</div><div><p>${context.esc(error.message)}</p><button type="button" class="button quiet" data-action="reload">重新读取</button></div></article>`;
      context.toast(error.message,"error");
    }
  }

  async function selectConversation(id){
    if(busy||id===activeConversation?.summary?.conversation_id){closeDrawer();return;}
    const host=root();
    host?.classList.add("is-conversation-loading");
    try{
      activeConversation=await context.api(`/api/m8/agent/conversations/${encodeURIComponent(id)}`);
      sessionStorage.setItem(storageKey(),id);
      patchWorkspace();
      announce("已切换对话");
    }catch(error){context.toast(error.message,"error");}
    finally{host?.classList.remove("is-conversation-loading");}
  }

  async function newConversation(){
    if(busy)return;
    const host=root();
    host?.classList.add("is-conversation-loading");
    try{
      const created=await context.api("/api/m8/agent/conversations",{method:"POST",body:{}});
      conversations=[created,...conversations];
      activeConversation={summary:created,turns:[]};
      sessionStorage.setItem(storageKey(),created.conversation_id);
      patchWorkspace({focus:true});
      announce("已创建新对话");
    }catch(error){context.toast(error.message,"error");}
    finally{host?.classList.remove("is-conversation-loading");}
  }

  function openDeleteConversation(id,trigger){
    if(busy||deletingConversation)return;
    const conversation=conversations.find(item=>item.conversation_id===id);
    const modal=document.getElementById("agent-delete-modal");
    if(!conversation||!modal)return;
    pendingDeleteConversationId=id;
    deleteReturnFocus=trigger;
    modal.querySelector("[data-agent-delete-copy]").textContent=`“${conversation.title}”将从对话列表中移除，此操作无法撤销。`;
    modal.hidden=false;
    requestAnimationFrame(()=>{
      modal.classList.add("is-open");
      modal.querySelector("[data-agent-confirm-delete]")?.focus();
    });
  }

  function closeDeleteConversation({restoreFocus=true}={}){
    if(deletingConversation)return;
    const modal=document.getElementById("agent-delete-modal");
    if(!modal)return;
    modal.classList.remove("is-open");
    const finish=()=>{
      modal.hidden=true;
      pendingDeleteConversationId=null;
      if(restoreFocus&&deleteReturnFocus?.isConnected)deleteReturnFocus.focus();
      deleteReturnFocus=null;
    };
    if(reducedMotion())finish();else setTimeout(finish,180);
  }

  async function removeConversation(){
    const id=pendingDeleteConversationId;
    if(!id||busy||deletingConversation)return;
    deletingConversation=true;
    const confirm=document.querySelector("[data-agent-confirm-delete]");
    if(confirm){confirm.disabled=true;confirm.setAttribute("aria-busy","true");}
    const removedIndex=conversations.findIndex(item=>item.conversation_id===id);
    const removedActive=activeConversation?.summary?.conversation_id===id;
    try{
      await context.api(`/api/m8/agent/conversations/${encodeURIComponent(id)}`,{method:"DELETE"});
      conversations=await context.api("/api/m8/agent/conversations");
      if(removedActive){
        if(!conversations.length){
          const created=await context.api("/api/m8/agent/conversations",{method:"POST",body:{}});
          conversations=[created];
        }
        const next=conversations[Math.min(Math.max(removedIndex,0),conversations.length-1)];
        activeConversation=await context.api(`/api/m8/agent/conversations/${encodeURIComponent(next.conversation_id)}`);
        sessionStorage.setItem(storageKey(),next.conversation_id);
      }
      deletingConversation=false;
      closeDeleteConversation({restoreFocus:false});
      patchWorkspace({animate:removedActive});
      context.toast("对话已删除","success");
      announce("对话已删除");
    }catch(error){
      deletingConversation=false;
      context.toast(error.message,"error");
    }finally{
      if(confirm){confirm.disabled=false;confirm.removeAttribute("aria-busy");}
    }
  }

  function scrollMessages(){
    const host=document.getElementById("agent-messages");
    if(host)host.scrollTop=host.scrollHeight;
  }

  function appendLive(query){
    const anchor=document.querySelector("[data-agent-live-anchor]");
    if(!anchor)return null;
    anchor.insertAdjacentHTML("beforebegin",`<article class="agent-message user"><div class="agent-avatar">你</div><div><p>${context.esc(query)}</p></div></article><article class="agent-message agent is-streaming" data-agent-live-message><div class="agent-avatar">A</div><div><p data-agent-live-text></p><div class="agent-stream-state"><span class="spinner"></span><span data-agent-live-state>正在连接 Qwen…</span></div></div></article>`);
    scrollMessages();
    return anchor.previousElementSibling;
  }

  function updateTool(event){
    const host=document.querySelector("[data-agent-tools]");
    if(!host)return;
    host.hidden=false;
    if(event.event_kind==="tool.started"){
      host.insertAdjacentHTML("beforeend",`<span data-call="${context.esc(event.tool_call_id)}"><i></i>正在查询${context.esc(toolLabels[event.tool_kind]||event.tool_kind)}</span>`);
      return;
    }
    const node=host.querySelector(`[data-call="${CSS.escape(event.tool_call_id)}"]`);
    if(node){node.classList.add("done");node.innerHTML=`<i></i>${context.esc(toolLabels[event.tool_kind]||event.tool_kind)}查询完成`;}
  }

  async function sendTurn(query){
    if(busy||!activeConversation||!modelCanSend())return;
    busy=true;
    patchComposer();
    const conversationId=activeConversation.summary.conversation_id;
    const live=appendLive(query);
    try{
      const response=await fetch(`/api/m8/agent/conversations/${encodeURIComponent(conversationId)}/turns`,{method:"POST",headers:{Accept:"text/event-stream","Content-Type":"application/json",Authorization:`Bearer ${context.state.token}`},body:JSON.stringify({query})});
      if(!response.ok){
        let reason=`HTTP ${response.status}`;
        try{const body=await response.json();reason=body.failure_code||body.reason_code||reason;}catch(_error){reason=`HTTP ${response.status}`;}
        throw new Error(reason);
      }
      let completion=null,failure=null;
      await readEvents(response,event=>{
        if(event.event_kind==="tool.started"||event.event_kind==="tool.completed")updateTool(event);
        if(event.event_kind==="message.delta"){
          const text=live?.querySelector("[data-agent-live-text]");
          if(text)text.textContent+=event.text_delta;
          const label=live?.querySelector("[data-agent-live-state]");
          if(label)label.textContent="正在接收回答…";
          scrollMessages();
        }
        if(event.event_kind==="message.completed")completion=event.completion;
        if(event.event_kind==="turn.failed")failure=event.failure_code;
      });
      if(failure)throw new Error(failure);
      if(!completion)throw new Error("STREAM_INTERRUPTED");
      [activeConversation,conversations,modelStatus]=await Promise.all([
        context.api(`/api/m8/agent/conversations/${encodeURIComponent(conversationId)}`),
        context.api("/api/m8/agent/conversations"),
        context.api("/api/m8/agent/status"),
      ]);
      patchWorkspace({animate:true});
      announce("Agent 回答已完成");
    }catch(error){
      const code=error.message;
      if(live){
        live.removeAttribute("data-agent-live-message");
        live.classList.remove("is-streaming");
        live.classList.add("failed");
        const text=live.querySelector("[data-agent-live-text]");
        if(text)text.textContent=failureCopy(code);
        const state=live.querySelector(".agent-stream-state");
        if(state)state.innerHTML=`<button type="button" class="button quiet" data-agent-retry="${context.esc(query)}">重试</button>`;
      }
      if(code!=="NOT_CONFIGURED"&&modelStatus)modelStatus={...modelStatus,availability:"DEGRADED",last_failure_code:code};
      patchStatus();
      context.toast(failureCopy(code),"error");
    }finally{
      busy=false;
      const tools=document.querySelector("[data-agent-tools]");
      if(tools){tools.replaceChildren();tools.hidden=true;}
      patchComposer();
      if(!document.getElementById("agent-query")?.disabled)document.getElementById("agent-query")?.focus();
    }
  }

  async function readEvents(response,onEvent){
    if(!response.body)throw new Error("STREAM_UNAVAILABLE");
    const reader=response.body.getReader(),decoder=new TextDecoder("utf-8",{fatal:true});
    let buffer="",bytes=0;
    while(true){
      const {done,value}=await reader.read();
      if(done)break;
      bytes+=value.byteLength;
      if(bytes>4*1024*1024)throw new Error("STREAM_TOO_LARGE");
      buffer+=decoder.decode(value,{stream:true});
      const blocks=buffer.split(/\r?\n\r?\n/);
      buffer=blocks.pop()||"";
      for(const block of blocks){
        const data=block.split(/\r?\n/).filter(line=>line.startsWith("data:" )).map(line=>line.slice(5).trimStart()).join("\n");
        if(data)onEvent(JSON.parse(data));
      }
    }
    buffer+=decoder.decode();
    if(buffer.trim())throw new Error("STREAM_INTERRUPTED");
  }

  return {render};
})();

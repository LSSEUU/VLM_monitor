/* LabCourt 全局导航 · 挂载到 #gnav-mount */
(function(){
  var mount=document.getElementById('gnav-mount'); if(!mount) return;
  var path=(location.pathname.split('/').pop()||'index.html').toLowerCase();
  var PAGES=[
    {href:'landing.html',label:'首页'},
    {href:'monitor.html',label:'实时监控'},
    {href:'case-file.html',label:'案件中心'},
    {href:'knowledge.html',label:'知识库'},
    {href:'map.html',label:'校园地图'}
  ];
  var links=PAGES.map(function(p){
    var on = path===p.href.toLowerCase();
    return '<a class="gnav__link'+(on?' active':'')+'" href="'+p.href+'">'+p.label+'</a>';
  }).join('');

  mount.innerHTML=
    '<nav class="gnav" id="gnav" aria-label="主导航">'+
      '<div class="gnav__inner">'+
        '<a class="gnav__brand" href="landing.html">LabCourt <small>校园实验室安全</small></a>'+
        '<div class="gnav__links">'+links+'</div>'+
        '<div class="gnav__spacer"></div>'+
        '<div class="gnav__right">'+
          '<span class="gnav__pulse" title="系统脉搏">'+
            '<svg class="gnav__ecg" viewBox="0 0 32 14" width="30" height="13" aria-hidden="true"><path d="M0 7 L9 7 L12 3 L15 11 L18 7 L32 7"/></svg>'+
          '</span>'+
          '<button class="gnav__cmd" id="gnav-cmd" type="button" aria-label="快速跳转"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg><span>跳转</span><kbd>⌘K</kbd></button>'+
          '<div class="gnav__avatar" id="gnav-avatar" tabindex="0" aria-haspopup="true" aria-expanded="false">'+
            '<span class="pic" id="gnav-pic">管</span>'+
            '<span class="who"><b id="gnav-name">安全管理员</b><i id="gnav-role">ADMIN</i></span>'+
            '<span class="gnav__caret" aria-hidden="true">▾</span>'+
            '<div class="gnav__menu" role="menu">'+
              '<a href="profile.html" role="menuitem">个人中心</a>'+
              '<h6>切换视角（演示）</h6>'+
              '<div class="roles">'+
                '<button class="active" data-role="ADMIN" data-name="安全管理员" data-pic="管" type="button" role="menuitem">管理员</button>'+
                '<button data-role="负责人" data-name="李老师" data-pic="李" type="button" role="menuitem">实验室负责人</button>'+
                '<button data-role="学生" data-name="王同学" data-pic="王" type="button" role="menuitem">学生</button>'+
              '</div>'+
              '<a href="login.html" role="menuitem">退出登录</a>'+
            '</div>'+
          '</div>'+
        '</div>'+
      '</div>'+
    '</nav>'+
    '<div class="gnav__palette" id="gnav-palette" aria-hidden="true" role="dialog" aria-label="快速跳转">'+
      '<div class="gnav__palette__panel">'+
        '<input id="gnav-palette-input" type="text" placeholder="跳转到…（监控 / 案件 / 知识库 / 地图）" autocomplete="off">'+
        '<ul id="gnav-palette-list"></ul>'+
      '</div>'+
    '</div>';

  var gnav=document.getElementById('gnav');
  function onScroll(){ if(window.scrollY>12) gnav.classList.add('scrolled'); else gnav.classList.remove('scrolled'); }
  window.addEventListener('scroll',onScroll,{passive:true}); onScroll();

  var avatar=document.getElementById('gnav-avatar');
  function openAvatar(v){ avatar.classList.toggle('open',v); avatar.setAttribute('aria-expanded', v?'true':'false'); }
  avatar.addEventListener('click',function(e){ if(e.target.closest('.gnav__menu')) return; openAvatar(!avatar.classList.contains('open')); });
  document.addEventListener('click',function(e){ if(!e.target.closest('#gnav-avatar')) openAvatar(false); });
  var picEl=document.getElementById('gnav-pic'),nameEl=document.getElementById('gnav-name'),roleEl=document.getElementById('gnav-role');
  avatar.querySelectorAll('.roles button').forEach(function(b){
    b.addEventListener('click',function(){
      picEl.textContent=b.dataset.pic; nameEl.textContent=b.dataset.name; roleEl.textContent=b.dataset.role;
      avatar.querySelectorAll('.roles button').forEach(function(x){x.classList.remove('active')}); b.classList.add('active');
      openAvatar(false);
    });
  });

  var pal=document.getElementById('gnav-palette'),input=document.getElementById('gnav-palette-input'),list=document.getElementById('gnav-palette-list'),cmdBtn=document.getElementById('gnav-cmd');
  var items=PAGES.map(function(p){return {label:p.label,href:p.href};});
  function renderList(q){
    q=(q||'').trim().toLowerCase();
    var f=items.filter(function(it){return it.label.toLowerCase().indexOf(q)>=0||it.href.toLowerCase().indexOf(q)>=0;});
    list.innerHTML=f.length?f.map(function(it,i){return '<li><a href="'+it.href+'" class="'+(i===0?'focus':'')+'">'+it.label+' <span>'+it.href+'</span></a></li>';}).join(''):'<div class="empty">无匹配</div>';
  }
  function openPal(){ pal.classList.add('open'); pal.setAttribute('aria-hidden','false'); input.value=''; renderList(''); setTimeout(function(){input.focus();},20); }
  function closePal(){ pal.classList.remove('open'); pal.setAttribute('aria-hidden','true'); }
  cmdBtn.addEventListener('click',openPal);
  pal.addEventListener('click',function(e){ if(e.target===pal) closePal(); });
  input.addEventListener('input',function(){renderList(input.value);});
  document.addEventListener('keydown',function(e){
    if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='k'){ e.preventDefault(); pal.classList.contains('open')?closePal():openPal(); }
    if(e.key==='Escape') closePal();
  });
})();

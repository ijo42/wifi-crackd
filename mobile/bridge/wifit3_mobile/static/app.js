'use strict';
const $ = id => document.getElementById(id);
let token = location.hash.slice(1) || sessionStorage.getItem('wifit3-token') || '';
if (location.hash) history.replaceState(null, '', location.pathname);
let state = null, busy = false, connected = false, pollHandle = null, errorTimer, hashCache = null, detailTarget = null;
const phases = {idle:'Готов', starting:'Подключение', scanning:'В эфире', stopping:'Остановка', error:'Ошибка'};
function el(tag, className, text) { const n = document.createElement(tag); if(className) n.className=className; if(text !== undefined) n.textContent=String(text); return n; }
function showError(message) { $('error').textContent=message; $('error').hidden=false; clearTimeout(errorTimer); errorTimer=setTimeout(()=>$('error').hidden=true,12000); }
async function api(path, body) {
  const response = await fetch('/api/' + path, {method:body ? 'POST':'GET', headers:{'Authorization':'Bearer '+token, ...(body ? {'Content-Type':'application/json'} : {})}, ...(body ? {body:JSON.stringify(body)} : {}), cache:'no-store'});
  const data=await response.json();
  if(!response.ok) { if(response.status===401) {connected=false;clearTimeout(pollHandle);$('workspace').hidden=true;$('pairing').hidden=false;sessionStorage.removeItem('wifit3-token');} throw new Error(data.error || 'Ошибка модуля'); }
  return data;
}
const CAMPAIGNS=[['deauth','Deauth','Deauth: форсировать хендшейк'],['pmkid','PMKID','PMKID: собрать без клиентов'],['wps','WPS PIN','WPS PIN / Pixie Dust']];
function campaignAvailability(n) {
  const out={};
  out.deauth=n.psk_family?{ok:true}:(n.pmf_required?{ok:false,why:'PMF required/invalid без маяка: нечем послать CSA'}:{ok:false,why:'не подтверждён WPA/WPA2-PSK'});
  out.pmkid=n.hidden?{ok:false,why:'скрытый SSID: ассоциироваться не с чем'}
    :(n.psk_family&&n.rsn_valid)||(!n.encryption||n.encryption==='Unknown')?{ok:true}:n.wps_locked?{ok:false,why:'WPS заблокирован'}:{ok:false,why:'RSN не подтверждён (нет маяка)'};
  out.wps=!n.wps?{ok:false,why:'WPS не обнаружен в маяках'}:n.hidden?{ok:false,why:'скрытый SSID'}:n.wps_locked?{ok:false,why:'WPS заблокирован'}:((n.encryption||'').toUpperCase()==='WEP')?{ok:false,why:'WEP-цель'}:{ok:true};
  return out;
}
function renderCampaignCard(target) {
  const d=state.attack||{}, box=$('campaignBtns');
  $('campaignStatus').textContent=(d.active||d.captured)?d.headline:'Кампании не запущены.';
  const last=(d.last||{}).bssid===(target&&target.bssid)?d.last:null;
  $('campaignLast').hidden=!last;
  if(last){
    let txt='Прошлая попытка ('+last.key.toUpperCase()+'): ';
    if(last.key==='deauth')txt+=last.captured?'новый крэкабельный захват получен.':'без нового захвата.';
    else if(last.key==='pmkid')txt+=last.result&&last.result.harvested?'PMKID собран.':('не удалась'+(last.result&&last.result.fail?' ('+last.result.fail+')':''));
    else txt+=last.result&&last.result.pin!=null?'PIN найден: '+last.result.pin+(last.result.psk?' · PSK: '+last.result.psk:''):'PIN не найден.';
    txt+=' acks/попытки: '+JSON.stringify(last.stats);
    $('campaignLast').textContent=txt;
  }
  box.replaceChildren();
  if(!target)return;
  const activeHere=d.active&&d.bssid===target.bssid;
  if(activeHere){
    const stop=el('button','danger full','■ Остановить '+d.key.toUpperCase());
    stop.disabled=busy;stop.addEventListener('click',()=>action('attack/stop'));
    box.append(stop);return;
  }
  if(d.active){
    box.append(el('p','hint','Занято целью '+(d.ssid||d.bssid)+' ('+d.key.toUpperCase()+'). Сначала остановите её.'));
    return;
  }
  const avail=campaignAvailability(target);
  for(const [key,short] of CAMPAIGNS){
    const a=avail[key];
    const btn=el('button','secondary full',short);
    if(state.phase!=='scanning'){btn.disabled=true;}
    else if(!a.ok){btn.disabled=true;btn.title=a.why;}
    else btn.disabled=busy || !$('authorized').checked;
    if(a.ok && state.phase==='scanning' && !$('authorized').checked)btn.title='Требуется согласие на аудит (вкладка «Модуль»)';
    btn.addEventListener('click',()=>action('attack/start',{campaign:key,bssid:target.bssid,authorized:$('authorized').checked===true}));
    box.append(btn);
    if(!a.ok)box.append(el('p','hint',short+': '+a.why));
  }
}
function controls() {
  if(!state)return;
  const active=['starting','scanning','stopping'].includes(state.phase);
  $('start').hidden=active; $('stop').hidden=!active && state.phase!=='error';
  $('start').disabled=busy || !$('device').value || !$('authorized').checked;
  $('stop').disabled=busy || state.phase==='stopping';
  for(const id of ['refresh','device','band']) $(id).disabled=busy || active;
  $('export').disabled=!state.networks.length;
  $('shutdownModule').disabled=busy;
  const d=state.attack||{};
  const anyHere=!!(d.active && detailTarget);
  $('detailActions').hidden=!detailTarget || (!anyHere && state.phase!=='scanning');
  if(detailTarget)renderCampaignCard(detailTarget);
}
async function action(name, body={}) {
  if(busy)return; busy=true;controls();
  try {const data=await api(name,body); if(data && data.networks) render(data);} catch(e){showError(e.message);} finally{busy=false;controls();}
}
async function pair() {
  token=$('token').value.trim() || token;
  if(!token)return showError('Вставьте код из Termux.');
  $('connect').disabled=true;
  try{render(await api('state'));connected=true;sessionStorage.setItem('wifit3-token',token);$('token').value='';$('pairing').hidden=true;$('workspace').hidden=false;poll();}
  catch(e){showError(e.message);}finally{$('connect').disabled=false;}
}
async function poll() {
  clearTimeout(pollHandle);
  if(!connected)return;
  try {render(await api('state'));$('linkState').textContent='● Подключено';}
  catch(e){$('linkState').textContent='Нет связи';$('progress').textContent='Связь с Termux потеряна. Состояние приёма неизвестно; проверьте Termux.';}
  if(connected)pollHandle=setTimeout(poll,1800);
}
function selectView(view) {
  for(const name of ['scan','hashes','log','devices']) $('view-'+name).hidden=name!==view;
  document.querySelectorAll('[data-view]').forEach(b=>b.classList.toggle('active',b.dataset.view===view));
  if(view==='hashes')loadHashes();
}
function render(data) {
  state=data; $('demoNotice').hidden=!data.demo;$('phase').textContent=phases[data.phase]||data.phase;
  $('progress').textContent=data.error || data.progress;
  $('mode').textContent=data.demo?'● DEMO · диагностика':'● USB · Termux';
  $('networkCount').textContent=data.networks.length;
  $('clientCount').textContent=new Set(data.networks.flatMap(n=>n.clients.map(c=>c.mac))).size;
  $('hashCount').textContent=(data.hashes&&data.hashes.count)||0;
  if($('htpUrl').value==='' && data.htp && data.htp.url) $('htpUrl').value=data.htp.url;
  if($('htpUser').value==='' && data.htp && data.htp.user) $('htpUser').value=data.htp.user;
  if(data.htp && data.htp.has_token) $('htpToken').placeholder='сохранён · введите новый для замены';
  const signature=JSON.stringify(data.devices.map(d=>[d.id,d.name]));
  if($('device').dataset.signature!==signature){
    const prev=$('device').value;$('device').replaceChildren();
    if(!data.devices.length) $('device').append(new Option('Нет адаптеров — обновите список',''));
    else for(const d of data.devices)$('device').append(new Option(d.name+' · '+d.usb,d.id));
    if(data.devices.some(d=>d.id===prev))$('device').value=prev;
    $('device').dataset.signature=signature;
  }
  renderNetworks(); renderLogs(); renderObservations();
  if($('details').open && detailTarget)renderFocusLive();
  controls();
  $('snapshot').textContent=data.networks.length ? (data.phase==='scanning'?'Живой приём · ':'Последний снимок · ') + (data.snapshot_at?new Date(data.snapshot_at).toLocaleTimeString('ru-RU'):'—') + ' · Счётчики за текущую сессию.' : '';
}
function renderNetworks(){
  if(!state)return;
  const q=$('search').value.toLocaleLowerCase(),band=$('filterBand').value,sort=$('sort').value;
  const enc=$('filterEnc').value,hashF=$('filterHash').value,cliF=$('filterClients').value;
  const list=state.networks.filter(n=>(n.ssid+' '+n.bssid).toLocaleLowerCase().includes(q)
      && (band==='all'||(band==='2g'?n.channel<=14:n.channel>14))
      && (enc==='all'||(enc==='SCE'?(n.encryption||'').includes('WPA2/WPA3'):(n.encryption||'').includes(enc)))
      && (hashF==='any'||(hashF==='no'?!(n.captures>0):(n.captures>0)))
      && (cliF==='any'||(cliF==='has'?n.clients.length>0:n.clients.length===0)))
    .sort((a,b)=>sort==='ssid'?a.ssid.localeCompare(b.ssid):sort==='channel'?a.channel-b.channel
      :sort==='captures'?(b.captures||0)-(a.captures||0):sort==='clients'?b.clients.length-a.clients.length:b.signal-a.signal);
  $('shownCount').textContent='НАЙДЕННЫЕ СЕТИ / '+list.length;
  $('networks').replaceChildren();$('empty').hidden=list.length>0;
  if(!list.length && state.networks.length){$('empty').querySelector('h2').textContent='Нет совпадений';$('empty').querySelector('p').textContent='Попробуйте изменить поиск или диапазон.';}
  else if(!list.length){$('empty').querySelector('h2').textContent=state.phase==='scanning'?'Слушаем эфир…':'Здесь появятся сети';$('empty').querySelector('p').textContent=state.phase==='scanning'?'Дождитесь маяков точек доступа. Проверьте диапазон и питание адаптера.':'Подключите USB‑адаптер в разделе «Модуль» и запустите приём.';}
  for(const n of list){
    const row=el('button','network');row.type='button';row.setAttribute('aria-label',(n.ssid||'Скрытая сеть')+', '+n.signal+' dBm, подробности');
    const info=el('div');info.append(el('div','network-name',n.ssid||'Скрытая сеть'),el('div','network-info',n.bssid+' · CH '+n.channel+' · маяки '+n.beacons));
    const tags=el('div','network-tags');tags.append(el('span','tag'+(n.wpa3?' good':n.encryption==='OPEN'?' warn':''),n.encryption));
    tags.append(el('span','tag',n.channel>14?'5 GHz':'2.4 GHz'));
    if(n.wps)tags.append(el('span','tag warn','WPS'));
    if(n.pmf_required)tags.append(el('span','tag','PMF'));
    if(n.transition_mode)tags.append(el('span','tag good','SCE'));
    if(n.captures)tags.append(el('span','tag good','хешей: '+n.captures));
    if(n.clients.length)tags.append(el('span','tag','клиентов: '+n.clients.length));
    if(n.age_seconds>30)tags.append(el('span','tag','Не видна >30 c'));
    info.append(tags);const signal=el('div','signal'),bars=el('div','bars');const count=n.signal>=-50?4:n.signal>=-65?3:n.signal>=-80?2:1;
    for(let i=0;i<4;i++)bars.append(el('i',i<count?'on':''));signal.append(bars,el('strong','',n.signal),el('small','','dBm'));
    row.append(info,signal);row.addEventListener('click',()=>focusNetwork(n));$('networks').append(row);
  }
}
function focusNetwork(n){
  detailTarget=n;
  $('detailName').textContent=n.ssid||'Скрытая сеть';
  $('detailTags').replaceChildren();
  for(const t of [[n.encryption,!n.wpa3&&n.encryption==='OPEN'?'warn':'good'],[n.pmf_required?'PMF обязателен':n.pmf_capable?'PMF':'',n.pmf_required?'warn':''],[n.transition_mode?'WPA2/WPA3 SCE':'','good'],[n.wps?(n.wps_locked?'WPS · заблокирован':'WPS'):'','warn']].filter(x=>x[0]))
    $('detailTags').append(el('span','tag '+t[1],t[0]));
  $('detailList').replaceChildren();
  const rows=[['BSSID',n.bssid],['Канал',n.channel],['Сигнал',n.signal+' dBm'],['Защита',n.encryption],['Производитель',n.vendor||'Не определён'],['Маяки',n.beacons],['Последний маяк',new Date(n.last_seen*1000).toLocaleTimeString('ru-RU')],['Крэкабельных захватов',(n.captures||0)+(n.pmkid?' · есть PMKID':'')]];
  for(const [label,value] of rows){const row=el('div');row.append(el('dt','',label),el('dd','',value));$('detailList').append(row);}
  $('detailClients').replaceChildren(el('p','eyebrow','КЛИЕНТЫ / '+n.clients.length));
  for(const c of n.clients)$('detailClients').append(el('p','network-info',c.mac+' · '+c.signal+' dBm · '+c.packets+' пакетов'));
  const mac=n.bssid.replace(/:/g,'');
  const lines=(hashCache&&hashCache.lines||[]).filter(l=>(l.split('*')[3]||'')===mac);
  $('detailHashes').hidden=!lines.length;
  if(lines.length)$('detailHashLines').textContent=lines.join('\n');
  $('detailHashes').open=false;
  renderCampaignCard(n);
  $('details').showModal();controls();
}
function renderFocusLive(){
  if(!detailTarget)return;
  const fresh=state.networks.find(n=>n.bssid===detailTarget.bssid);
  if(fresh)detailTarget=fresh;
  controls();
}
function renderLogs(){ $('logs').replaceChildren(); for(const entry of [...state.logs].reverse()){const li=el('li');li.append(el('time','',new Date(entry.time).toLocaleTimeString('ru-RU')),el('span','',entry.message));$('logs').append(li);} }
function renderObservations(){
  const box=$('disconnectEvents');if(!box)return;
  const data=state.disconnect_observations || {counts:{deauth:0,disassoc:0},events:[]};
  $('disconnectSummary').textContent='Принято: deauth '+data.counts.deauth+' / disassoc '+data.counts.disassoc;
  box.replaceChildren();
  for(const e of [...data.events].reverse()){
    const row=el('li');row.append(el('time','',new Date(e.time).toLocaleTimeString('ru-RU')),
      el('span','',e.type+' · '+e.bssid+' · '+e.source+' → '+e.destination+' · '+e.signal+' dBm · '+(e.protected?'Защищённый кадр; причина не прочитана':'reason '+(e.reason ?? 'неизвестен'))));
    box.append(row);
  }
}
async function loadHashes() {
  try {
    const data=await api('hashes');hashCache=data;
    $('hashSummary').textContent=data.count?('Уникальных хешей: '+data.count+' · сетей: '+Object.keys(data.networks).length):'Крэкабельных хешей нет. Откройте цель и запустите deauth — он провоцирует новый хендшейк.';
    const nets=$('hashNets');nets.replaceChildren();
    for(const [bssid,count] of Object.entries(data.networks||{})){
      const n=(state&&state.networks||[]).find(x=>x.bssid===bssid);
      nets.append(el('span','tag good',(n&&n.ssid||bssid)+' · '+count));
    }
    $('hashLines').hidden=!data.lines||!data.lines.length;
    if(data.lines&&data.lines.length)$('hashLines').textContent=data.lines.join('\n');
    $('exportHashes').disabled=!data.lines||!data.lines.length;
    $('htpSend').disabled=!data.lines||!data.lines.length;
    if($('details').open && detailTarget)focusHashRefresh();
  } catch(e){showError(e.message);}
}
function focusHashRefresh(){
  const mac=detailTarget.bssid.replace(/:/g,'');
  const lines=(hashCache&&hashCache.lines||[]).filter(l=>(l.split('*')[3]||'')===mac);
  $('detailHashes').hidden=!lines.length;
  if(lines.length)$('detailHashLines').textContent=lines.join('\n');
}
function exportHashes() {
  if(!hashCache||!hashCache.lines||!hashCache.lines.length)return showError('Хешей нет.');
  const text=hashCache.lines.join('\n')+'\n';
  if(window.Android && typeof window.Android.saveHashes==='function')window.Android.saveHashes(text);
  else{const url=URL.createObjectURL(new Blob([text],{type:'text/plain'}));const a=el('a');a.href=url;a.download='wifit3-mobile.hc22000';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
}
async function htpCall(path, body) {
  const buttons={'htp':$('htpSave'),'htp/test':$('htpTest'),'hashes/send':$('htpSend')};
  const btn=buttons[path];if(btn)btn.disabled=true;
  try{
    const data=await api(path,body);
    $('htpResult').hidden=false;$('htpResult').textContent=JSON.stringify(data,null,1).slice(0,1500);
    if(path==='htp')$('htpToken').value='';
    if(path==='hashes/send')loadHashes();
    return data;
  }catch(e){showError(e.message);}
  finally{if(btn)btn.disabled=false;}
}
function exportReport(){
  if(!state)return;const report={format:'wifit3-mobile/survey-v1',exported_at:new Date().toISOString(),demo:state.demo,upstream_commit:state.upstream_commit,snapshot_at:state.snapshot_at,phase:state.phase,networks:state.networks,disconnect_observations:state.disconnect_observations,deauth:state.deauth,hashes:state.hashes};
  const text=JSON.stringify(report,null,2);
  if(window.Android && typeof window.Android.saveReport==='function')window.Android.saveReport(text);
  else{const url=URL.createObjectURL(new Blob([text],{type:'application/json'}));const a=el('a');a.href=url;a.download='wifi-survey.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
}
let shutdownArmed=null;
async function shutdownModule(){
  // No native confirm(): Android WebView without a WebChromeClient returns false silently.
  const btn=$('shutdownModule');
  if(!shutdownArmed){
    btn.textContent='Нажмите ещё раз для подтверждения завершения';
    shutdownArmed=setTimeout(()=>{shutdownArmed=null;btn.textContent='Завершить модуль: остановить приём и выйти';},5000);
    return;
  }
  clearTimeout(shutdownArmed);shutdownArmed=null;btn.textContent='Завершить модуль: остановить приём и выйти';
  try{await api('shutdown',{});}catch(e){/* server is already gone */}
  connected=false;token='';clearTimeout(pollHandle);sessionStorage.removeItem('wifit3-token');
  $('workspace').hidden=true;$('pairing').hidden=false;$('linkState').textContent='Модуль остановлен';
  $('progress').textContent='';
}
$('connect').addEventListener('click',pair);$('token').addEventListener('keydown',e=>{if(e.key==='Enter')pair();});
$('refresh').addEventListener('click',()=>action('refresh'));
$('start').addEventListener('click',()=>{if(!$('device').value || !$('authorized').checked){selectView('devices');return;}action('start',{device_id:$('device').value,band:$('band').value,authorized:true});});
$('stop').addEventListener('click',()=>action('stop'));
$('authorized').addEventListener('change',controls);$('device').addEventListener('change',controls);
for(const id of ['search','filterBand','sort','filterEnc','filterHash','filterClients'])$(id).addEventListener('input',renderNetworks);
for(const b of document.querySelectorAll('[data-view]'))b.addEventListener('click',()=>selectView(b.dataset.view));
$('closeDetails').addEventListener('click',()=>$('details').close());
$('export').addEventListener('click',exportReport);
$('exportHashes').addEventListener('click',exportHashes);
$('shutdownModule').addEventListener('click',shutdownModule);
$('htpSave').addEventListener('click',()=>htpCall('htp',{url:$('htpUrl').value.trim(),user:$('htpUser').value.trim(),token:$('htpToken').value.trim()}));
$('htpClear').addEventListener('click',()=>htpCall('htp',{clear:true}));
$('htpTest').addEventListener('click',()=>htpCall('htp/test',{url:$('htpUrl').value.trim(),user:$('htpUser').value.trim(),token:$('htpToken').value.trim(),password:$('htpPassword').value}));
$('htpSend').addEventListener('click',()=>htpCall('hashes/send',{url:$('htpUrl').value.trim(),user:$('htpUser').value.trim(),token:$('htpToken').value.trim(),password:$('htpPassword').value,batch:Math.max(1,parseInt($('htpBatch').value,10)||250),dry_run:$('htpDry').checked,all_wpa:$('htpAllWpa').checked}));
$('disconnect').addEventListener('click',()=>{connected=false;token='';clearTimeout(pollHandle);sessionStorage.removeItem('wifit3-token');$('workspace').hidden=true;$('pairing').hidden=false;$('linkState').textContent='Отключено';});
document.addEventListener('visibilitychange',()=>{if(!document.hidden && connected)poll();});
if(token)pair();

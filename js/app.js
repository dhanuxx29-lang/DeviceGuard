import{state,load,save,reset,audit,DEFAULTS}from'./storage.js';import{h,sha256,DEMO_HASH,fmt,download,csv,logo}from'./utils.js';
import{sevName,refreshAll,staleCheck}from'./threat-dna.js';import{SCENARIOS,sim,start,pause,resume,stop,emit}from'./simulation.js';
import{answer,SUGGESTIONS}from'./assistant.js';import{replayPage,rp}from'./replay.js';import{whatIfPage}from'./whatif.js';import{mapView}from'./network-map.js';import{posture,WEIGHTS,TIPS}from'./posture.js';
const root=document.getElementById('root');let user=null,page='dashboard',sel=null,flt={q:'',st:''};
load();
const tag=s=>h('span',{class:'tag '+s},s);
const SYM={Low:'● ',Guarded:'▲ ',High:'◆ ',Critical:'■ '};const sv=s=>h('span',{class:'tag '+s},(SYM[s]||'')+s);
const mon=()=>!user?'Unavailable':sim.running&&!sim.paused?'Simulation running':sim.running?'Simulation paused':'Stopped (no new events processed)';
function confirmBox(msg,fn){const m=h('div',{class:'modal',role:'dialog','aria-modal':'true'},h('div',{},h('p',{},msg),h('button',{class:'d',onclick:()=>{m.remove();fn()}},'Confirm'),' ',h('button',{onclick:()=>m.remove()},'Cancel')));document.body.append(m);m.querySelector('button').focus()}
async function loginView(msg=''){root.replaceChildren(h('div',{class:'login'},h('h1',{class:'brand'},logo(38),' DeviceGuard'),h('p',{},'Protecting the devices that protect us.'),
 h('p',{class:'mut'},'Local educational prototype. This demonstration login runs in your browser and is NOT real authentication; a real system needs a trusted backend. All devices and events are simulated.'),
 h('form',{onsubmit:async e=>{e.preventDefault();const f=e.target,u=f.u.value.trim(),p=f.p.value;
  if(!u||!p)return loginView('Enter a username and password.');
  if(u==='analyst'&&await sha256(p)===DEMO_HASH){user=u;audit('login','demo session');render()}else loginView('Invalid demonstration credentials.')}},
  h('label',{},'Username',h('input',{name:'u',autocomplete:'off'})),h('label',{},'Password',h('input',{name:'p',type:'password',id:'pw'})),
  h('label',{class:'chk'},h('input',{type:'checkbox',onchange:e=>document.getElementById('pw').type=e.target.checked?'text':'password'}),' Show password'),
  h('button',{class:'p'},'Log in'),h('div',{class:'err',role:'alert'},msg)),h('p',{class:'mut'},'Demo account: analyst / devguard-demo (synthetic).')))}
const PAGES={dashboard,devices,map:mapPg,incidents,replay:replayPg,whatif:whatifPg,posture:posturePg,input:inputPg,lab,audit:auditPg,assistant:assistantPg,settings};
function render(){if(!user)return loginView();refreshAll(state.clock);
 const nav=h('nav',{},h('h1',{class:'brand'},logo(26),' DeviceGuard'),...Object.keys(PAGES).map(p=>h('a',{href:'#'+p,class:p===page?'on':'',onclick:e=>{e.preventDefault();page=p;sel=null;render()}},p[0].toUpperCase()+p.slice(1))),
  h('button',{onclick:()=>{stop(true);audit('logout','');user=null;sel=null;loginView()}},'Log out'));
 const bar=h('div',{class:'bar'},h('b',{},'Monitoring: '+mon()),h('span',{class:'mut'},'Last processed: '+(sim.lastProcessed?fmt(sim.lastProcessed):'none yet')),h('span',{class:'mut'},'Simulated data only'),
  state.storageError?h('span',{class:'err',role:'alert'},state.storageError):'');
 root.replaceChildren(h('div',{class:'app'},nav,h('main',{},bar,PAGES[page]())))}
window.addEventListener('dg-update',()=>user&&render());
function dashboard(){const D=state.devices,c=s=>D.filter(d=>d.status===s).length,open=state.incidents.filter(i=>!['Resolved','False Positive'].includes(i.status)),nodata=D.filter(d=>!d.lastSeen).length;
 const cards=[['Devices',D.length],['Healthy',c('Healthy')],['Warning',c('Warning')],['Stale',c('Stale')],['Offline',c('Offline')],['Insufficient baseline / no data',nodata],['Active incidents',open.length],['Critical open',open.filter(i=>i.severity==='Critical').length]];
 const status=!state.events.length?'Insufficient data: no events processed yet. This is not the same as "secure".':open.length?'Open incidents need review.':'No alerts detected in simulated data so far. This does not guarantee security.';
 return h('div',{},h('h2',{},'Security overview'),h('p',{},status),h('div',{class:'grid'},cards.map(([k,v])=>h('div',{class:'card'},h('b',{class:'n'},v),h('span',{class:'mut'},k)))),
  h('div',{class:'card'},h('h3',{},'Highest-risk devices'),table(['Device','Risk','Status'],[...D].filter(d=>d.risk>0).sort((a,b)=>b.risk-a.risk).slice(0,5).map(d=>[d.name,d.risk+' ('+sevName(d.risk)+')',d.status]),'No risky devices. Run a scenario in the Lab.')),
  h('div',{class:'card'},h('h3',{},'Recent events'),table(['Time','Device','Type','Rules'],state.events.slice(-8).reverse().map(e=>[fmt(e.timestamp),e.deviceId,e.eventType,e.detectionRuleIds.join(', ')||'-']),'No events yet.')))}
function table(head,rows,empty){return rows.length?h('div',{class:'wrap'},h('table',{},h('tr',{},head.map(x=>h('th',{},x))),rows.map(r=>h('tr',{},r.map(c=>h('td',{},c)))))):h('p',{class:'mut'},empty)}
function devices(){if(sel){const d=state.devices.find(x=>x.id===sel);return h('div',{},h('button',{onclick:()=>{sel=null;render()}},'Back'),h('h2',{},d.name),
  h('p',{},`${d.id} · ${d.type} · ${d.loc} · criticality ${d.crit} · status ${d.status} · risk ${d.risk} (${sevName(d.risk)}) · config v${d.cfg} (expected v${d.expectedCfg})`),
  h('div',{class:'card'},h('h3',{},'Expected baseline'),h('p',{},`Report every ${d.interval}s, range ${d.range[0]}–${d.range[1]}. `+(state.events.filter(e=>e.deviceId===d.id).length<5?'Insufficient baseline data: not treated as suspicious.':'Baseline has sample data.'))),
  h('div',{class:'card'},h('h3',{},'Risk factors'),table(['Factor','Points'],(d.riskFactors||[]).map(f=>[f.k,f.pts]),'No active risk factors.')),
  h('div',{class:'card'},h('h3',{},'Connected devices (configured links)'),h('p',{},d.links.join(', ')||'None')),
  h('div',{class:'card'},h('h3',{},'Findings'),table(['Rule','Expected','Actual','Why','Next step'],state.findings.filter(f=>f.deviceId===d.id).map(f=>[f.ruleName+(f.count>1?` ×${f.count}`:''),f.expected,f.actual,f.explanation+' '+f.alt,f.next]),'None.')),
  h('div',{class:'card'},h('h3',{},'Event history'),table(['Time','Type','Value'],state.events.filter(e=>e.deviceId===d.id).slice(-15).reverse().map(e=>[fmt(e.timestamp),e.eventType,e.value??'-']),'No events.')),
  h('button',{onclick:()=>confirmBox('Reset this simulated device to baseline? Incident history is kept. No physical device is affected.',()=>{d.online=true;d.cfg=d.expectedCfg;d.status='Healthy';state.findings.filter(f=>f.deviceId===d.id).forEach(f=>f.fp=f.fp||false);audit('device_reset',d.id);refreshAll(state.clock);save();render()})},'Reset simulated device'))}
 const q=h('input',{placeholder:'Search devices','aria-label':'Search',value:flt.q,oninput:e=>{flt.q=e.target.value;render();document.querySelector('input[aria-label=Search]').focus()}});
 const st=h('select',{'aria-label':'Status',onchange:e=>{flt.st=e.target.value;render()}},['','Healthy','Warning','Stale','Offline','No data'].map(s=>h('option',{value:s,selected:s===flt.st?'':null},s||'All statuses')));
 const L=state.devices.filter(d=>(d.name+d.id+d.loc).toLowerCase().includes(flt.q.toLowerCase())&&(!flt.st||d.status===flt.st)).sort((a,b)=>(b.risk||0)-(a.risk||0));
 return h('div',{},h('h2',{},'Device explorer'),h('div',{class:'bar'},q,st),h('div',{class:'wrap'},h('table',{},h('tr',{},['Device','Type','Location','Crit.','Status','Risk','Last seen',''].map(x=>h('th',{},x))),
  L.map(d=>h('tr',{},h('td',{},d.name,h('div',{class:'mut'},d.id)),h('td',{},d.type),h('td',{},d.loc),h('td',{},d.crit),h('td',{},d.status),h('td',{},d.risk+' '+sevName(d.risk)),h('td',{},d.lastSeen?fmt(d.lastSeen):'never'),h('td',{},h('button',{onclick:()=>{sel=d.id;render()}},'Open')))))))}
function incidents(){const note=(i,label,needs,status)=>h('button',{onclick:()=>{const t=prompt(needs?label+' (required):':label+' (optional):');if(needs&&!(t||'').trim())return alert('A note is required.');
  i.status=status;i.history.push({at:new Date().toISOString(),text:`Status → ${status}${t?': '+t:''}`});if(status==='False Positive')i.findingIds.forEach(id=>{const f=state.findings.find(x=>x.id===id);if(f){f.fp=true;f.fpReason=t}});
  audit('incident_'+status,i.id+(t?' '+t:''));refreshAll(state.clock);save();render()}},status==='New'?'Reopen':status);
 return h('div',{},h('h2',{},'Incident centre'),state.incidents.length?state.incidents.slice().reverse().map(i=>h('div',{class:'card'},h('h3',{},i.title+' '),sv(i.severity),' ',tag(i.status),
  h('p',{class:'mut'},`${i.id} · detected ${fmt(i.detected)} · risk ${i.risk} · devices ${i.deviceIds.join(', ')} · simulated · "Critical" = configured rules flagged high priority, not a verified attack`),
  h('p',{},'Why: ',i.why.join(' ')),h('p',{class:'mut'},'Evidence events: '+i.eventIds.join(', ')),
  h('div',{},note(i,'Acknowledge note',false,'Acknowledged'),' ',note(i,'Investigation note',false,'Investigating'),' ',note(i,'Resolution note',true,'Resolved'),' ',note(i,'False-positive reason',true,'False Positive'),' ',
   ['Resolved','False Positive'].includes(i.status)?note(i,'Reopen reason',false,'New'):'',' ',h('button',{onclick:()=>{const t=prompt('Operator note:');if(t){i.notes.push({at:new Date().toISOString(),text:t});audit('note',i.id);save();render()}}},'Add note'),' ',
   h('button',{onclick:()=>{rp.id=i.id;rp.i=0;page='replay';render()}},'Replay / forensics'),' ',h('button',{onclick:()=>download(i.id+'.json',JSON.stringify({label:'SIMULATED DATA',incident:i,findings:state.findings.filter(f=>i.findingIds.includes(f.id)),events:state.events.filter(e=>i.eventIds.includes(e.eventId))},null,2),'application/json')},'Export report')),
  h('details',{},h('summary',{},'History and notes'),h('ul',{},i.history.map(x=>h('li',{},fmt(x.at)+' '+x.text)),i.notes.map(x=>h('li',{},'Note: '+x.text)))))):h('p',{class:'mut'},'No incidents. Run a scenario in the Lab to generate simulated evidence.'))}
function lab(){return h('div',{},h('h2',{},'Simulation lab'),h('p',{class:'mut'},'Generates synthetic events locally only. Nothing touches real devices or networks.'),
 h('div',{class:'bar'},h('button',{onclick:()=>{pause();render()}},'Pause'),h('button',{onclick:()=>{resume();render()}},'Resume'),h('button',{onclick:()=>{stop();render()}},'Stop'),
  h('label',{},'Speed ',h('select',{onchange:e=>sim.speed=+e.target.value},[1,2,4].map(s=>h('option',{value:s},s+'×'))))),
 SCENARIOS.map(s=>h('div',{class:'card'},h('b',{},s.name),h('p',{class:'mut'},`Objective: ${s.goal} Expected: ${s.expect}`),h('button',{class:'p',onclick:()=>{start(s.id);render()}},'Start'))),
 sim.sc?h('div',{class:'card'},h('h3',{},'Last run: '+sim.sc.name),h('p',{},`Expected: ${sim.sc.expect}. Actual rules fired: ${[...new Set(state.events.filter(e=>e.sourceScenario===sim.sc.id).flatMap(e=>e.detectionRuleIds))].join(', ')||'none'}`)):'')}
function auditPg(){return h('div',{},h('h2',{},'Audit log'),h('p',{class:'mut'},'Local demonstration records. Not cryptographically verified evidence.'),table(['Time','Action','Detail'],state.audit.map(a=>[fmt(a.at),a.action,a.detail]),'No records.'))}
function settings(){const s=state.settings,F=[['failThreshold','Failed-access threshold',1,20],['windowSec','Access/flip window (s)',10,3600],['staleSec','Stale timeout (s)',10,3600],['burstCount','Burst event count',2,100],['burstSec','Burst window (s)',1,120],['flipCount','State-flip threshold',2,20],['corrSec','Correlation window (s)',30,3600],['cooldownSec','Duplicate cooldown (s)',0,3600]];
 return h('div',{},h('h2',{},'Settings, data and privacy'),h('p',{class:'mut'},'Changes affect future detection only; existing evidence is unchanged.'),
  h('form',{class:'card',onsubmit:e=>{e.preventDefault();const o={};for(const[k,l,a,b]of F){const v=+e.target[k].value;if(!Number.isFinite(v)||v<a||v>b)return alert(`${l} must be ${a}–${b}`);o[k]=v}Object.assign(s,o);audit('settings_saved','');save();render()}},
   F.map(([k,l,a,b])=>h('p',{},h('label',{},l+' ',h('input',{name:k,type:'number',value:s[k],min:a,max:b})))),h('button',{class:'p'},'Save settings'),' ',h('button',{type:'button',onclick:()=>{state.settings=structuredClone(DEFAULTS);audit('settings_defaults','');save();render()}},'Restore defaults')),
  h('div',{class:'card'},h('h3',{},'Data and privacy'),h('p',{},'Stored in this browser (localStorage): synthetic devices, events, findings, incidents, settings, audit records. Not encrypted, no backup or sync; clearing browser data erases it. No personal data is collected.')),
  h('div',{class:'card'},h('h3',{},'Export (simulated data)'),h('button',{onclick:()=>download('events.csv',csv(state.events.map(e=>({...e,detectionRuleIds:e.detectionRuleIds.join('|'),label:'SIMULATED'}))),'text/csv')},'Event log CSV'),' ',
   h('button',{onclick:()=>download('devices.json',JSON.stringify({label:'SIMULATED DATA',devices:state.devices},null,2),'application/json')},'Device inventory JSON')),
  h('button',{class:'d',onclick:()=>confirmBox('Delete ALL stored demonstration data (events, incidents, audit log, settings)? This cannot be undone.',()=>{stop(true);reset();audit('reset','all data');render()})},'Reset all data'))}
let mapSel=null;
function mapPg(){return mapView(mapSel,id=>{mapSel=id;render()},id=>{sel=id;page='devices';render()},()=>{mapSel=null;render()})}
function posturePg(){const p=posture();if(!p)return h('div',{},h('h2',{},'Security posture'),h('p',{},'Insufficient data: run a scenario so devices report. No score is shown until then.'));
 return h('div',{},h('h2',{},'Security posture (simulated)'),h('div',{class:'card'},h('b',{class:'n'},p.score+' / 100'),h('span',{class:'mut'},'Documented weighted score of simulated data. Not a certified assessment; it does not mean the network is secure.')),
  h('div',{class:'card'},h('h3',{},'Components'),table(['Component','Weight','Score'],Object.keys(WEIGHTS).map(k=>[k,WEIGHTS[k]+'%',Math.round(p.comp[k])+'']),'')),
  h('div',{class:'card'},h('h3',{},'Contributing weaknesses and improvements'),p.weak.length?h('ul',{},p.weak.map(k=>h('li',{},`${k} (${Math.round(p.comp[k])}): ${TIPS[k]}`))):h('p',{},'No component below 80 in the current simulated data.')))}
const chat=[{who:'bot',text:'Hi, I am the Guard Assistant: a local, rule-based helper that reads the simulated data in this app. I am not an AI model and cannot control any device. Ask me something below.'}];
function assistantPg(){const ask=q=>{q=q.trim();if(!q)return;chat.push({who:'you',text:q.slice(0,300)},{who:'bot',text:answer(q)});render();document.getElementById('chatq')?.focus()};
 return h('div',{},h('h2',{},'Guard Assistant'),h('p',{class:'mut'},'Rule-based, runs locally, answers only from simulated app data.'),
  h('div',{class:'bar'},SUGGESTIONS.map(s=>h('button',{onclick:()=>ask(s)},s))),
  h('div',{class:'card',role:'log','aria-live':'polite'},chat.map(m=>h('p',{style:'white-space:pre-wrap;margin:6px 0'},h('b',{},m.who==='you'?'You: ':'Assistant: '),m.text))),
  h('form',{class:'bar',onsubmit:e=>{e.preventDefault();ask(e.target.q.value)}},h('input',{id:'chatq',name:'q','aria-label':'Ask the assistant',maxlength:'300',placeholder:'Ask about devices, incidents, risk...',style:'flex:1;min-width:200px'}),h('button',{class:'p'},'Ask')))}
let inMsg='';
function inputPg(){const T=[['reading','Sensor reading (needs a value)'],['access_fail','Failed access attempt'],['config_change','Configuration change (value = new version number)'],['disconnect','Device disconnects'],['reconnect','Device reconnects']];
 return h('div',{},h('h2',{},'Send your own events'),h('p',{class:'mut'},'Type in a pretend event, as if a device just sent it. Nothing is sent to any real device. Detection rules run on it exactly like Lab events.'),
  h('form',{class:'card',onsubmit:e=>{e.preventDefault();const f=e.target,type=f.type.value,raw=f.val.value.trim(),gap=Number(f.gap.value);
   if(!(gap>=0&&gap<=3600)){inMsg='Seconds since last event must be between 0 and 3600.';return render()}
   let v=null;if(type==='reading'||type==='config_change'){v=Number(raw);if(raw===''||!Number.isFinite(v)){inMsg='This event type needs a number in the value box.';return render()}}
   const before=state.findings.length;state.clock+=gap*1000;const ev=emit(f.dev.value,type,v,'manual');
   if(!ev){inMsg='Event rejected: '+sim.log[sim.log.length-1];return render()}audit('manual_event',`${ev.deviceId} ${type} ${v??''}`);
   inMsg=ev.detectionRuleIds.length?'Event accepted. It triggered: '+ev.detectionRuleIds.join(', ')+'. See Incidents.':'Event accepted. Nothing suspicious found.';render()}},
   h('p',{},h('label',{},'Device ',h('select',{name:'dev'},state.devices.map(d=>h('option',{value:d.id},d.name+' ('+d.id+')'))))),
   h('p',{},h('label',{},'Event ',h('select',{name:'type'},T.map(([k,l])=>h('option',{value:k},l))))),
   h('p',{},h('label',{},'Value ',h('input',{name:'val',placeholder:'e.g. 24 (temperature) or 1 (door open)'}))),
   h('p',{},h('label',{},'Seconds since last event ',h('input',{name:'gap',type:'number',value:'10',min:'0',max:'3600'}))),
   h('button',{class:'p'},'Send event'),h('p',{role:'status'},inMsg)),
  h('div',{class:'card'},h('h3',{},'Check for silent devices'),h('p',{class:'mut'},'Moves the pretend clock forward and checks which devices stopped reporting (stale).'),
   h('form',{onsubmit:e=>{e.preventDefault();const n=Number(e.target.s.value);if(!(n>=1&&n<=86400)){inMsg='Enter 1 to 86400 seconds.';return render()}state.clock+=n*1000;staleCheck(state.clock);audit('stale_check',n+'s');
    const st=state.devices.filter(d=>d.status==='Stale').map(d=>d.id);inMsg=st.length?'Stale devices: '+st.join(', '):'No device is stale.';render()}},
    h('input',{name:'s',type:'number',value:'120',min:'1',max:'86400','aria-label':'Seconds to move forward'}),' seconds ',h('button',{},'Move clock and check'))))}
function replayPg(){return replayPage(render,()=>user&&page==='replay')}
function whatifPg(){return whatIfPage(render)}
render();

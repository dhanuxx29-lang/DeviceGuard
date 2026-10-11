// Replay + forensics: READ-ONLY view of recorded events. Never creates events.
import{state,audit}from'./storage.js';import{h,fmt,download,csv}from'./utils.js';import{sevName,ruleName}from'./threat-dna.js';
export const rp={id:null,i:0,playing:false,speed:1,timer:null};
const T=x=>Date.parse(x),inc0=id=>state.incidents.find(x=>x.id===id);
export function build(inc){const fs=state.findings.filter(f=>inc.findingIds.includes(f.id)),first=Math.min(T(inc.detected),...fs.map(f=>T(f.time))),from=first-state.settings.corrSec*1000,to=T(inc.lastTime);
 const ev=state.events.filter(e=>inc.deviceIds.includes(e.deviceId)&&T(e.timestamp)>=from&&T(e.timestamp)<=to).map(e=>({t:T(e.timestamp),ev:e}));
 const ck=fs.filter(f=>!f.eventIds[0]).map(f=>({t:T(f.time),check:f}));return[...ev,...ck].sort((a,b)=>a.t-b.t)}
export function riskAt(inc,t){const w=state.settings.weights;let best={score:0,dev:null};
 inc.deviceIds.forEach(id=>{const d=state.devices.find(x=>x.id===id);if(!d)return;const kinds=[...new Set(state.findings.filter(f=>inc.findingIds.includes(f.id)&&f.deviceId===id&&T(f.time)<=t).map(f=>f.rule))];
  if(!kinds.length)return;const sc=Math.min(100,Math.max(0,kinds.reduce((a,k)=>a+(w[k]||0),0)+(kinds.length>=3?w.corr:0)+d.crit*3));if(sc>best.score)best={score:sc,dev:id}});return best}
const what=s=>s.ev?`${s.ev.eventType}${s.ev.value!=null?' (value '+s.ev.value+')':''}`:'Silence check: no report received';
const where=s=>s.ev?s.ev.deviceId:s.check.deviceId;
function detections(inc,s){return state.findings.filter(f=>inc.findingIds.includes(f.id)&&(s.check===f||(s.ev&&f.eventIds.includes(s.ev.eventId))))}
function devState(inc,t){return inc.deviceIds.map(id=>{const e=state.events.filter(x=>x.deviceId===id&&T(x.timestamp)<=t),dis=[...e].reverse().find(x=>x.eventType==='disconnect'||x.eventType==='reconnect');
 return{id,text:!e.length?'no data yet':dis&&dis.eventType==='disconnect'?'offline':'reporting'}})}
export function summary(inc){const steps=build(inc),fs=state.findings.filter(f=>inc.findingIds.includes(f.id)).sort((a,b)=>T(a.time)-T(b.time)),prog=[];
 steps.forEach(s=>{const v=riskAt(inc,s.t).score;if(prog[prog.length-1]!==v)prog.push(v)});
 const acts=[...inc.history.slice(1).map(x=>`${fmt(x.at)} ${x.text}`),...inc.notes.map(x=>`${fmt(x.at)} Note: ${x.text}`),...state.audit.filter(a=>a.detail.includes(inc.id)).map(a=>`${fmt(a.at)} ${a.action}`)];
 return[['Incident overview',`${inc.title}\nID ${inc.id}. Severity ${inc.severity} (configured rules flag high priority; not a verified attack). Risk ${inc.risk}/100. Devices: ${inc.deviceIds.join(', ')}.`],
  ['Initial event',steps[0]?`${fmt(steps[0].t)}: ${where(steps[0])} ${what(steps[0])}`:'No recorded events.'],
  ['Sequence of suspicious events',fs.map(f=>`${fmt(f.time)}  ${f.deviceId}  ${f.ruleName}: expected ${f.expected}, actual ${f.actual}${f.count>1?` (repeated ${f.count} times, grouped)`:''}`).join('\n')||'None'],
  ['Detection rules triggered',[...new Set(fs.map(f=>f.ruleName))].join('\n')||'None'],['Affected devices',inc.deviceIds.join(', ')],
  ['Risk progression',prog.join(' → ')||'0'],['Operator actions',acts.join('\n')||'No operator actions recorded yet.'],
  ['Current status',`${inc.status}`],
  ['Remaining uncertainties','• All data is simulated; nothing came from real devices.\n• Links between devices are inferred from configured connections, not confirmed spread.\n• Each symptom could also be a hardware fault, a communication problem or a wrong setting.\n• Local browser records are not tamper-proof.']]}
function stop(){clearInterval(rp.timer);rp.timer=null;rp.playing=false}
function printReport(inc){const w=window.open('','_blank');if(!w)return alert('Please allow pop-ups to print the report.');const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
 w.document.write(`<!doctype html><title>${esc(inc.id)}</title><style>body{font:14px system-ui;margin:30px}h1{font-size:20px}h3{margin:16px 0 4px}pre{white-space:pre-wrap;font:inherit}</style><h1>DeviceGuard incident report</h1><p><b>SIMULATED DATA.</b> Not evidence from real devices. Local demonstration records are not tamper-proof. Generated ${esc(new Date().toISOString())}</p>`+summary(inc).map(([a,b])=>`<h3>${esc(a)}</h3><pre>${esc(b)}</pre>`).join(''));w.document.close();w.focus();w.print()}
export function replayPage(rerender,active){const inc=inc0(rp.id);
 const pick=h('select',{'aria-label':'Choose incident',onchange:e=>{stop();rp.id=e.target.value||null;rp.i=0;rerender()}},h('option',{value:''},'Choose an incident'),state.incidents.map(i=>h('option',{value:i.id,selected:i.id===rp.id?'':null},i.title+' ('+i.id+')')));
 if(!inc)return h('div',{},h('h2',{},'Replay and forensics'),h('div',{class:'bar'},pick),h('p',{class:'mut'},state.incidents.length?'Pick an incident to replay it step by step.':'No incidents to replay yet. Run a scenario in the Lab first.'));
 const steps=build(inc);if(!steps.length)return h('div',{},h('h2',{},'Replay and forensics'),h('div',{class:'bar'},pick),h('p',{},'No recorded events for this incident.'));
 rp.i=Math.min(Math.max(rp.i,0),steps.length-1);const cur=steps[rp.i],r=riskAt(inc,cur.t),go=n=>{rp.i=Math.min(steps.length-1,Math.max(0,n));rerender()};
 const play=()=>{if(rp.playing){stop();return rerender()}if(rp.i>=steps.length-1)rp.i=0;rp.playing=true;rp.timer=setInterval(()=>{if(!active()){stop();return}if(rp.i<steps.length-1){rp.i++;rerender()}else{stop();rerender()}},1000/rp.speed);rerender()};
 const dets=detections(inc,cur);
 return h('div',{},h('h2',{},'Replay and forensics'),h('p',{class:'mut'},'Replays recorded events only. No new events are created. Simulated data.'),
  h('div',{class:'bar'},pick,h('button',{onclick:()=>{stop();go(rp.i-1)}},'Step back'),h('button',{class:'p',onclick:play},rp.playing?'Pause':'Play'),h('button',{onclick:()=>{stop();go(rp.i+1)}},'Step forward'),
   h('label',{},'Speed ',h('select',{onchange:e=>{rp.speed=+e.target.value;if(rp.playing){stop();play()}}},[1,2,4].map(v=>h('option',{value:v,selected:rp.speed===v?'':null},v+'×'))))),
  h('input',{type:'range',min:0,max:steps.length-1,value:rp.i,'aria-label':'Replay position',oninput:e=>{stop();go(+e.target.value)}}),
  h('div',{class:'card'},h('b',{},`Step ${rp.i+1} of ${steps.length}: ${fmt(cur.t)}`),h('p',{},`${where(cur)} → ${what(cur)}`),
   h('p',{},`Risk from this incident's evidence so far: ${r.score}/100 (${sevName(r.score)})${r.dev?' on '+r.dev:''}`),
   h('div',{},devState(inc,cur.t).map(d=>h('span',{class:'chip'+(d.id===where(cur)?' now':'')},(d.id===where(cur)?'▶ ':'')+d.id+': '+d.text)))),
  h('div',{class:'card'},h('h3',{},'What the detection engine said at this step'),dets.length?dets.map(f=>h('p',{},h('b',{},f.ruleName+': '),f.eventIds[0]===(cur.ev&&cur.ev.eventId)||cur.check===f?`New finding. Expected ${f.expected}, actual ${f.actual}. ${f.explanation} ${f.alt}`:'Repeat of an existing finding. Grouped into the same alert, no new incident created.')):h('p',{class:'mut'},'Nothing flagged at this step.')),
  h('div',{class:'card wrap'},h('h3',{},'Timeline so far'),h('table',{},h('tr',{},['Time','Device','Event','Flagged','Risk after'].map(x=>h('th',{},x))),
   steps.slice(0,rp.i+1).map((s,i)=>h('tr',{class:i===rp.i?'row-on':''},h('td',{},fmt(s.t)),h('td',{},where(s)),h('td',{},what(s)),h('td',{},detections(inc,s).map(f=>f.rule).join(', ')||'-'),h('td',{},riskAt(inc,s.t).score))))),
  h('div',{class:'card'},h('h2',{},'Forensic summary'),summary(inc).map(([a,b])=>h('div',{},h('h3',{},a),h('pre',{class:'sum'},b))),
   h('p',{},h('button',{onclick:()=>download(inc.id+'-timeline.csv',csv(steps.map((s,i)=>({step:i+1,time:new Date(s.t).toISOString(),device:where(s),event:what(s),flagged:detections(inc,s).map(f=>f.rule).join('|'),risk_after:riskAt(inc,s.t).score,label:'SIMULATED'}))),'text/csv')},'Export timeline CSV'),' ',
    h('button',{onclick:()=>{audit('print_report',inc.id);printReport(inc)}},'Print / save as PDF'))))}

// ThreatDNA: transparent rule-based detection (no ML). Events -> findings -> risk -> incidents.
import{state,save}from'./storage.js';import{uid,clamp}from'./utils.js';
const RULES={access:'R1 Repeated failed access',config:'R2 Unexpected configuration change',conflict:'R3 Conflicting sensor states',range:'R4 Implausible reading',
 stale:'R5 Stale telemetry',offline:'R6 Unexpected disconnection',burst:'R7 Excessive event frequency'};
const NEXT={access:'Review simulated access logs for the source identity.',config:'Compare current configuration with the expected version.',conflict:'Inspect the event timeline and mark the device for investigation.',
 range:'Validate the reading against the configured range.',stale:'Inspect the reporting interval and simulated connection.',offline:'Check connectivity before assuming compromise.',burst:'Check for a faulty sensor or message loop.'};
export const ruleName=k=>RULES[k]||k;
const dev=id=>state.devices.find(d=>d.id===id),ts=e=>Date.parse(e.timestamp);
export function validate(e){const er=[];if(!/^[A-Z]{2,4}-\d{2}$/.test(e.deviceId||''))er.push('malformed deviceId');else if(!dev(e.deviceId))er.push('unknown device');
 if(isNaN(Date.parse(e.timestamp)))er.push('invalid timestamp');if(e.value!=null&&!Number.isFinite(e.value))er.push('non-numeric value');
 if(state.events.some(x=>x.eventId===e.eventId))er.push('duplicate event');return er}
const recent=(id,sec,now,type)=>state.events.filter(e=>e.deviceId===id&&(!type||e.eventType===type)&&now-ts(e)<=sec*1000);
function raise(d,rule,ev,expected,actual,why,strength){const s=state.settings,now=ts(ev);
 const dup=state.findings.find(f=>f.deviceId===d.id&&f.rule===rule&&now-Date.parse(f.time)<s.cooldownSec*1000);
 if(dup){dup.count++;ev.eventId&&!dup.eventIds.includes(ev.eventId)&&dup.eventIds.push(ev.eventId);return null}
 const f={id:uid('F'),deviceId:d.id,rule,ruleName:RULES[rule],time:ev.timestamp,eventIds:[ev.eventId],expected,actual,explanation:why,strength,count:1,simulated:true,
  next:NEXT[rule],alt:'Alternatives: hardware malfunction, communication problem or misconfiguration. This is not proof of tampering.'};
 state.findings.push(f);ev.detectionRuleIds.push(rule);attach(f,d);return f}
export function evaluate(ev){const s=state.settings,d=dev(ev.deviceId),now=ts(ev);d.lastSeen=ev.timestamp;
 if(ev.eventType==='reconnect')d.online=true;
 if(ev.eventType==='disconnect'){d.online=false;raise(d,'offline',ev,'Continuous reporting','Device disconnected','One disconnect is a health signal, not proof of compromise.','weak')}
 if(ev.eventType==='access_fail'){const n=recent(d.id,s.windowSec,now,'access_fail').length;
  if(n>=s.failThreshold)raise(d,'access',ev,`< ${s.failThreshold} failures in ${s.windowSec}s`,n+' failures','Failures reached the configured threshold within the window.','moderate')}
 if(ev.eventType==='config_change'){d.cfg=ev.value;if(d.cfg!==d.expectedCfg)raise(d,'config',ev,'Config v'+d.expectedCfg,'Config v'+d.cfg,'Configuration version differs from the expected baseline.','moderate')}
 if(ev.eventType==='reading'){
  if(ev.value<d.range[0]||ev.value>d.range[1])raise(d,'range',ev,`${d.range[0]} to ${d.range[1]}`,String(ev.value),'Reading is outside the allowed range.','moderate');
  else if(d.range[1]===1){const r=recent(d.id,s.windowSec,now,'reading').sort((a,b)=>ts(a)-ts(b));let fl=0;r.forEach((e,i)=>{if(i&&e.value!==r[i-1].value)fl++});
   if(fl>=s.flipCount)raise(d,'conflict',ev,`< ${s.flipCount} state flips in ${s.windowSec}s`,fl+' flips','State alternates more often than expected.','moderate')}}
 const b=recent(d.id,s.burstSec,now).length;if(b>=s.burstCount)raise(d,'burst',ev,`< ${s.burstCount} events in ${s.burstSec}s`,b+' events','Event frequency exceeds the configured threshold.','moderate');
 refreshAll(now);save()}
export function staleCheck(now){state.devices.forEach(d=>{if(!d.lastSeen||!d.online)return;const gap=now-Date.parse(d.lastSeen);
 if(gap>state.settings.staleSec*1000)raise(d,'stale',{eventId:null,timestamp:new Date(now).toISOString(),detectionRuleIds:[]},`Report every ${d.interval}s`,`Silent ${Math.round(gap/1000)}s`,'No telemetry and no disconnect event: stale, not necessarily offline.','weak')});
 refreshAll(now);save()}
// Risk: each distinct active rule counts once (no duplicate penalty); correlation bonus needs 3+ rule kinds; criticality weighting; clamped 0-100.
export function risk(d,now){const w=state.settings.weights,win=state.settings.corrSec*1000;
 const kinds=[...new Set(state.findings.filter(f=>f.deviceId===d.id&&!f.fp&&now-Date.parse(f.time)<=win).map(f=>f.rule))];
 const factors=kinds.map(k=>({k:RULES[k],pts:w[k]||0}));if(kinds.length>=3)factors.push({k:'Correlated suspicious events',pts:w.corr});
 if(kinds.length)factors.push({k:'Criticality level '+d.crit,pts:d.crit*3});
 return{score:clamp(factors.reduce((a,f)=>a+f.pts,0),0,100),factors}}
export const sevName=sc=>{const t=state.settings.sev;return sc<t[0]?'Low':sc<t[1]?'Guarded':sc<t[2]?'High':'Critical'};
export function refreshAll(now){state.devices.forEach(d=>{const r=risk(d,now);d.risk=r.score;d.riskFactors=r.factors;
 if(d.lastSeen)d.status=!d.online?'Offline':state.findings.some(f=>f.deviceId===d.id&&f.rule==='stale'&&!f.fp&&now-Date.parse(f.time)<state.settings.corrSec*1000)?'Stale':r.score>=state.settings.sev[0]?'Warning':'Healthy'});
 state.incidents.forEach(i=>{if(['Resolved','False Positive'].includes(i.status))return;i.risk=Math.max(...i.deviceIds.map(x=>dev(x)?.risk||0));i.severity=sevName(i.risk)})}
// Correlation: only the same or directly linked devices, inside the window, join one open incident. Links are inferred, not confirmed.
function attach(f,d){const win=state.settings.corrSec*1000,t=Date.parse(f.time);
 const rel=x=>x===d.id||d.links.includes(x)&&x!=='GW-01'||(dev(x)?.links||[]).includes(d.id)&&d.id!=='GW-01';
 const inc=state.incidents.find(i=>['New','Acknowledged','Investigating'].includes(i.status)&&i.deviceIds.some(rel)&&t-Date.parse(i.lastTime)<=win);
 if(inc){inc.findingIds.push(f.id);inc.eventIds.push(...f.eventIds.filter(Boolean));inc.lastTime=f.time;if(!inc.deviceIds.includes(d.id))inc.deviceIds.push(d.id);
  inc.why.push(`${f.ruleName} on ${d.id} linked: same/directly connected device within ${state.settings.corrSec}s (inferred relationship).`);inc.history.push({at:new Date().toISOString(),text:'Evidence added: '+f.ruleName});return}
 state.incidents.push({id:uid('INC'),title:`${f.ruleName}: ${d.name}`,status:'New',deviceIds:[d.id],findingIds:[f.id],eventIds:f.eventIds.filter(Boolean),detected:f.time,lastTime:f.time,risk:0,severity:'Low',
  why:[f.explanation],notes:[],history:[{at:new Date().toISOString(),text:'Created by '+f.ruleName}],simulated:true})}

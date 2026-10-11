// Simulated posture score: weighted components, all documented below. Not a certified assessment.
import{state}from'./storage.js';import{clamp}from'./utils.js';
export const WEIGHTS={Availability:30,'Unresolved incidents':30,'Device health':15,'Configuration':15,'Critical devices':10};
export function posture(){const D=state.devices.filter(d=>d.lastSeen);if(!state.events.length||!D.length)return null;
 const open=state.incidents.filter(i=>!['Resolved','False Positive'].includes(i.status)),pen={Low:5,Guarded:15,High:30,Critical:50};
 const comp={Availability:100*D.filter(d=>d.online&&d.status!=='Stale').length/D.length,
  'Unresolved incidents':clamp(100-open.reduce((a,i)=>a+(pen[i.severity]||0),0),0,100),
  'Device health':100-D.reduce((a,d)=>a+d.risk,0)/D.length,
  Configuration:100*D.filter(d=>d.cfg===d.expectedCfg).length/D.length,
  'Critical devices':(c=>c.length?100*c.filter(d=>d.status==='Healthy').length/c.length:100)(D.filter(d=>d.crit>=3))};
 const tot=Object.keys(WEIGHTS).reduce((a,k)=>a+comp[k]*WEIGHTS[k],0)/100;
 const weak=Object.keys(comp).filter(k=>comp[k]<80).sort((a,b)=>comp[a]-comp[b]);
 return{score:Math.round(clamp(tot,0,100)),comp,weak}}
export const TIPS={Availability:'Investigate offline or stale devices.','Unresolved incidents':'Review and resolve open incidents in the Incident Centre.','Device health':'Inspect devices with elevated risk.',Configuration:'Compare configuration versions with the expected baseline.','Critical devices':'Prioritise critical (level 3) devices that are not healthy.'};

// Simulation only emits synthetic events into the engine; it holds no detection logic.
import{state,save,audit}from'./storage.js';import{uid}from'./utils.js';import{validate,evaluate,staleCheck}from'./threat-dna.js';
const rd=(d,v,dt)=>({d,t:'reading',v,dt}),af=(d,dt)=>({d,t:'access_fail',v:null,dt});
export const SCENARIOS=[
 {id:'normal',name:'Normal device behaviour',goal:'Normal data is not flagged.',expect:'No findings',steps:[22,22.3,22.6,22.4,22.8].map(v=>rd('TMP-03',v,30))},
 {id:'access',name:'Repeated failed access attempts',goal:'Threshold alert for failed access.',expect:'R1',steps:[af('ACC-01',10),af('ACC-01',10),af('ACC-01',10),af('ACC-01',10)]},
 {id:'door',name:'Conflicting door sensor states',goal:'Detect contradictory open/closed flips.',expect:'R3',steps:[0,1,0,1,0,1].map(v=>rd('DOOR-01',v,8))},
 {id:'spoof',name:'Out-of-range sensor reading',goal:'Implausible value vs allowed range.',expect:'R4',steps:[rd('TMP-03',23,30),rd('TMP-03',87,30)]},
 {id:'config',name:'Unexpected configuration change',goal:'Config version differs from expected.',expect:'R2',steps:[{d:'GW-01',t:'config_change',v:2,dt:20}]},
 {id:'disc',name:'Disconnection then silence',goal:'Offline is not proof of compromise.',expect:'R6',steps:[rd('LAB-06',22,20),{d:'LAB-06',t:'disconnect',v:null,dt:20}]},
 {id:'stale',name:'Stale device (no disconnect)',goal:'Stale differs from offline.',expect:'R5',steps:[rd('STO-07',20,20)]},
 {id:'burst',name:'Abnormal data burst',goal:'Excessive event frequency.',expect:'R7',steps:Array.from({length:8},()=>rd('MOT-02',1,1))},
 {id:'chain',name:'Combined attack chain',goal:'Failures, config change, disconnect, abnormal neighbour: one incident.',expect:'R1,R2,R6,R3 in one incident',
  steps:[af('ACC-01',5),af('ACC-01',5),af('ACC-01',5),{d:'ACC-01',t:'config_change',v:2,dt:15},{d:'ACC-01',t:'disconnect',v:null,dt:15},...[0,1,0,1,0].map(v=>rd('DOOR-01',v,5))]},
 {id:'unrel',name:'Unrelated events on separate devices',goal:'No false correlation.',expect:'Separate incidents',steps:[rd('ENV-05',80,10),rd('STO-07',70,10)]}];
export const sim={running:false,paused:false,speed:1,lastProcessed:null,timer:null,sc:null,i:0,log:[]};
export function emit(deviceId,type,value,src){const ev={eventId:uid('E'),deviceId,eventType:type,timestamp:new Date(state.clock).toISOString(),value,previousState:null,currentState:value,
 expectedValueRange:null,severity:'info',sourceScenario:src||'manual',description:'Simulated '+type,detectionRuleIds:[]};
 const er=validate(ev);if(er.length){sim.log.push('Rejected event: '+er.join(', '));return null}
 state.events.push(ev);evaluate(ev);sim.lastProcessed=ev.timestamp;return ev}
export function start(id){stop(true);sim.sc=SCENARIOS.find(s=>s.id===id);sim.i=0;sim.running=true;sim.paused=false;sim.log=[];audit('simulation_start',id);tick()}
function tick(){if(!sim.running||sim.paused)return;const st=sim.sc.steps[sim.i];
 if(!st){state.clock+=(state.settings.staleSec+30)*1000;staleCheck(state.clock);sim.running=false;window.dispatchEvent(new Event('dg-update'));return}
 state.clock+=st.dt*1000;emit(st.d,st.t,st.v,sim.sc.id);sim.i++;window.dispatchEvent(new Event('dg-update'));sim.timer=setTimeout(tick,700/sim.speed)}
export const pause=()=>{if(sim.running){sim.paused=true;clearTimeout(sim.timer)}};export const resume=()=>{if(sim.running&&sim.paused){sim.paused=false;tick()}};
export function stop(quiet){clearTimeout(sim.timer);sim.running=false;sim.paused=false;if(!quiet)audit('simulation_stop',sim.sc?.id)}

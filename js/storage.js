const K='deviceguard.v1';
export const DEFAULTS={failThreshold:3,windowSec:120,staleSec:90,burstCount:6,burstSec:10,flipCount:4,corrSec:300,cooldownSec:120,
 weights:{access:25,config:20,conflict:20,range:20,stale:15,offline:10,burst:15,corr:20},sev:[25,50,75]};
const SEED=[['DOOR-01','Door Sensor 01','door','Entrance',3,[0,1],30,['GW-01']],['MOT-02','Motion Sensor 02','motion','Corridor',2,[0,1],30,['GW-01']],
 ['TMP-03','Temperature Sensor 03','temp','Server room',3,[10,35],30,['GW-01']],['SMK-04','Smoke Sensor 04','smoke','Server room',3,[0,1],60,['GW-01']],
 ['GW-01','Network Gateway 01','gateway','Core',3,[0,1],30,[]],['CAM-01','Smart Camera 01','camera','Entrance',2,[0,1],30,['GW-01']],
 ['ACC-01','Access Controller 01','access','Entrance',3,[0,1],60,['GW-01','DOOR-01']],['ENV-05','Environmental Sensor 05','temp','Lobby',1,[10,35],30,['GW-01']],
 ['LAB-06','Laboratory Sensor 06','temp','Lab',2,[15,30],30,['GW-01']],['STO-07','Storage Room Sensor 07','temp','Storage',1,[5,30],60,['GW-01']]]
 .map(([id,name,type,loc,crit,range,interval,links])=>({id,name,type,loc,crit,range,interval,links,status:'No data',lastSeen:null,cfg:1,expectedCfg:1,online:true,risk:0,riskFactors:[]}));
export const fresh=()=>({settings:structuredClone(DEFAULTS),devices:structuredClone(SEED),events:[],incidents:[],findings:[],audit:[],clock:Date.parse('2026-01-01T09:00:00Z')});
export const state={...fresh(),storageError:null};
export function load(){try{const r=localStorage.getItem(K);if(!r)return;const d=JSON.parse(r);
 if(!d||!Array.isArray(d.devices)||!Array.isArray(d.events)||!Array.isArray(d.incidents)||!Array.isArray(d.findings))throw new Error('failed consistency check');
 Object.assign(state,fresh(),d,{settings:{...DEFAULTS,...d.settings,weights:{...DEFAULTS.weights,...(d.settings||{}).weights}}})}
 catch(e){state.storageError='Stored data was unreadable and was ignored ('+e.message+').'}}
export function save(){try{const{storageError,...d}=state;localStorage.setItem(K,JSON.stringify(d));state.storageError=null}catch(e){state.storageError='Save failed: '+e.message}}
export function reset(){Object.assign(state,fresh());localStorage.removeItem(K)}
export function audit(action,detail){state.audit.unshift({at:new Date().toISOString(),action,detail:String(detail??'')});state.audit.length=Math.min(state.audit.length,300);save()}

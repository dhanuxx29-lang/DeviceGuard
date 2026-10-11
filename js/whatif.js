// What-if simulator: computes projected scores only. Changes NOTHING in the real app state.
import{state}from'./storage.js';import{h,clamp}from'./utils.js';import{risk,sevName,ruleName}from'./threat-dna.js';
const KINDS=['config','conflict','range','stale','offline','burst'];
export function project(kinds,crit){const w=state.settings.weights,f=kinds.map(k=>({k:ruleName(k),pts:w[k]||0}));if(kinds.length>=3)f.push({k:'Correlated suspicious events',pts:w.corr});if(kinds.length)f.push({k:'Criticality level '+crit,pts:crit*3});
 return{score:clamp(f.reduce((a,x)=>a+x.pts,0),0,100),factors:f}}
const wi={dev:null,kinds:[],crit:1,fails:0,thr:3,res:null};
function activeKinds(d){const win=state.settings.corrSec*1000;return[...new Set(state.findings.filter(f=>f.deviceId===d.id&&!f.fp&&state.clock-Date.parse(f.time)<=win).map(f=>f.rule))]}
function load(id){const d=state.devices.find(x=>x.id===id);wi.dev=id;wi.kinds=activeKinds(d).filter(k=>k!=='access');wi.crit=d.crit;wi.fails=activeKinds(d).includes('access')?state.settings.failThreshold:0;wi.thr=state.settings.failThreshold;wi.res=null}
export function whatIfPage(rerender){if(!wi.dev||!state.devices.find(d=>d.id===wi.dev))load(state.devices[0].id);const d=state.devices.find(x=>x.id===wi.dev);
 return h('div',{},h('h2',{},'What-if risk simulator'),h('p',{class:'mut'},'Change the conditions below and compare. These are projections. Nothing in the app or any device is changed.'),
  h('form',{class:'card',onsubmit:e=>{e.preventDefault();const f=e.target,k=KINDS.filter(x=>f['k_'+x].checked);wi.crit=+f.crit.value;wi.fails=+f.fails.value;wi.thr=+f.thr.value;
   if(!(wi.thr>=1&&wi.thr<=20&&wi.fails>=0&&wi.fails<=1000)){wi.res={err:'Threshold must be 1-20 and failed attempts 0-1000.'};return rerender()}
   const accessOn=wi.fails>=wi.thr,kinds=accessOn?['access',...k]:k,prev=risk(d,state.clock),now=project(kinds,wi.crit);
   wi.kinds=k;wi.res={prev:prev.score,now:now.score,factors:now.factors,accessOn,kinds};rerender()}},
   h('p',{},h('label',{},'Device ',h('select',{onchange:e=>{load(e.target.value);rerender()}},state.devices.map(x=>h('option',{value:x.id,selected:x.id===wi.dev?'':null},x.name))))),
   h('p',{},h('label',{},'Criticality ',h('select',{name:'crit'},[1,2,3].map(v=>h('option',{value:v,selected:wi.crit===v?'':null},v))))),
   h('fieldset',{},h('legend',{},'Suspicious conditions to assume'),KINDS.map(k=>h('label',{style:'display:block'},h('input',{type:'checkbox',name:'k_'+k,checked:wi.kinds.includes(k)?'':null}),' '+ruleName(k)))),
   h('p',{},h('label',{},'Failed access attempts ',h('input',{name:'fails',type:'number',value:wi.fails,min:0,max:1000})),' ',h('label',{},'Alert threshold ',h('input',{name:'thr',type:'number',value:wi.thr,min:1,max:20}))),
   h('button',{class:'p'},'Compare')),
  wi.res?(wi.res.err?h('p',{class:'err',role:'alert'},wi.res.err):h('div',{class:'card'},h('h3',{},'Projected result (simulation)'),
   h('p',{},`Previous risk (current state): ${wi.res.prev}/100 (${sevName(wi.res.prev)})`),h('p',{},`Projected risk: ${wi.res.now}/100 (${sevName(wi.res.now)})`),
   h('p',{},wi.res.accessOn?`Expected alert behaviour: ${wi.fails} failed attempts reaches the threshold of ${wi.thr}, so the failed-access rule would fire.`:`Expected alert behaviour: ${wi.fails} failed attempts is below the threshold of ${wi.thr}, so the failed-access rule would stay quiet.`),
   h('p',{},wi.res.now>=state.settings.sev[0]?'This would be flagged as at least Guarded.':'This would stay Low and probably not raise an incident.'),
   h('h4',{},'Factors behind the projection'),h('ul',{},wi.res.factors.length?wi.res.factors.map(x=>h('li',{},`${x.k}: +${x.pts}`)):h('li',{},'No risk factors assumed.')))):'')}

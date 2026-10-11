// Native SVG network map. Edges are the configured simulated links; "possible impact" is inferred, never confirmed propagation.
import{state}from'./storage.js';import{h}from'./utils.js';
const NS='http://www.w3.org/2000/svg',S=(t,a={},...k)=>{const e=document.createElementNS(NS,t);for(const[x,v]of Object.entries(a))e.setAttribute(x,v);k.forEach(c=>e.append(c));return e};
const COL={Healthy:'#4fb477',Warning:'#d9b44a',Stale:'#e8873a',Offline:'#8da0ae','No data':'#4a5a67'};
export function mapView(sel,pick,open,reset){const D=state.devices,W=640,H=420,cx=W/2,cy=H/2,gw=D.filter(d=>d.type==='gateway'),others=D.filter(d=>d.type!=='gateway');
 const pos={};gw.forEach((d,i)=>pos[d.id]=[cx+i*60,cy]);others.forEach((d,i)=>{const a=2*Math.PI*i/others.length-Math.PI/2;pos[d.id]=[cx+Math.cos(a)*165,cy+Math.sin(a)*150]});
 const nb=new Set();if(sel){const s=D.find(d=>d.id===sel);D.forEach(d=>{if(s.links.includes(d.id)||d.links.includes(sel))nb.add(d.id)})}
 const svg=S('svg',{viewBox:`0 0 ${W} ${H}`,role:'img','aria-label':'Simulated device network map',style:'width:100%;max-width:760px;background:#0a0f13;border-radius:8px'});
 D.forEach(d=>d.links.forEach(l=>{if(!pos[l])return;const hi=sel&&((d.id===sel&&nb.has(l))||(l===sel&&nb.has(d.id)));
  svg.append(S('line',{x1:pos[d.id][0],y1:pos[d.id][1],x2:pos[l][0],y2:pos[l][1],stroke:hi?'#e8873a':'#3a4a57','stroke-width':hi?2.5:1.2,'stroke-dasharray':hi?'6 4':''}))}));
 D.forEach(d=>{const[x,y]=pos[d.id],g=S('g',{tabindex:'0',role:'button','aria-label':`${d.name}, ${d.status}, risk ${d.risk}`,style:'cursor:pointer',opacity:sel&&d.id!==sel&&!nb.has(d.id)?.35:1});
  const fill=COL[d.status]||COL['No data'],r=d.crit>=3?16:12,stroke=d.risk>=50?'#e5534b':'#0e1419';
  g.append(d.type==='gateway'?S('rect',{x:x-r,y:y-r,width:2*r,height:2*r,fill,stroke,'stroke-width':3}):S('circle',{cx:x,cy:y,r,fill,stroke,'stroke-width':3,'stroke-dasharray':d.crit>=3?'':'3 2'}));
  const t=S('text',{x,y:y+r+13,'text-anchor':'middle',fill:'#dbe5ec','font-size':'10'});t.textContent=d.id;g.append(t);
  if(d.status==='Offline'){const o=S('text',{x,y:y+4,'text-anchor':'middle',fill:'#0e1419','font-size':'12'});o.textContent='×';g.append(o)}
  g.addEventListener('click',()=>pick(d.id));g.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();pick(d.id)}});svg.append(g)});
 const s=D.find(d=>d.id===sel),panel=s?h('div',{class:'card'},h('b',{},s.name),h('p',{},`${s.status}, risk ${s.risk}. Configured connections: ${s.links.join(', ')||'none'}.`),
  h('p',{class:'mut'},nb.size&&s.risk>0?'Possible impact (inferred, NOT confirmed propagation): '+[...nb].join(', ')+'. Dashed orange lines show configured links to these devices.':'No elevated risk on this device, or no linked devices; no possible impact flagged.'),
  h('button',{onclick:()=>open(s.id)},'Open device details')):h('p',{class:'mut'},'Select a device to highlight its configured connections.');
 return h('div',{},h('h2',{},'Network map'),h('p',{class:'mut'},'Simulated topology. Fill = status; square = gateway; solid outline = critical device (level 3); dashed outline = lower criticality; red ring = risk 50+; × = offline.'),
  h('div',{class:'bar'},h('button',{onclick:reset},'Reset view'),Object.entries(COL).map(([k,c])=>h('span',{},h('span',{style:`display:inline-block;width:10px;height:10px;border-radius:50%;background:${c}`}),' '+k))),svg,panel)}

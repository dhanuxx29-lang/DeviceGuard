export const sha256=async s=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))].map(b=>b.toString(16).padStart(2,'0')).join('');
export const DEMO_HASH='8a8ceacbe3ab075e368a657eb636364be1544354c96a4a9ad852dfcae55fc336';
export const uid=p=>p+'-'+Date.now().toString(36)+Math.random().toString(36).slice(2,6);
export const clamp=(v,a,b)=>Math.min(b,Math.max(a,v));
export function h(tag,attrs={},...kids){const e=document.createElement(tag);for(const[k,v]of Object.entries(attrs)){if(v==null||v===false)continue;if(k.startsWith('on'))e.addEventListener(k.slice(2),v);else if(k==='class')e.className=v;else e.setAttribute(k,v)}
 kids.flat().forEach(c=>{if(c!=null&&c!==false)e.append(c.nodeType?c:document.createTextNode(String(c)))});return e}
export const fmt=t=>new Date(t).toISOString().replace('T',' ').slice(0,19)+' UTC';
export function download(name,text,type){const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([text],{type}));a.download=name;a.click()}
export const csv=rows=>{if(!rows.length)return'';const k=Object.keys(rows[0]);return[k.join(','),...rows.map(r=>k.map(c=>'"'+String(r[c]??'').replace(/"/g,'""')+'"').join(','))].join('\n')};
export function logo(size=28){const N='http://www.w3.org/2000/svg',s=document.createElementNS(N,'svg');s.setAttribute('viewBox','0 0 32 32');s.setAttribute('width',size);s.setAttribute('height',size);s.setAttribute('role','img');s.setAttribute('aria-label','DeviceGuard logo');
 s.innerHTML='<path d="M16 2.5 28 9.5v13L16 29.5 4 22.5v-13z" fill="#0e1419" stroke="#2bc4b4" stroke-width="2"/><circle cx="16" cy="16" r="3.2" fill="#2bc4b4"/><path d="M16 12.8V8M19 17.6l4 2.3M13 17.6l-4 2.3" stroke="#2bc4b4" stroke-width="1.6" stroke-linecap="round"/><circle cx="16" cy="7.5" r="1.3" fill="#2bc4b4"/><circle cx="23.5" cy="20.2" r="1.3" fill="#2bc4b4"/><circle cx="8.5" cy="20.2" r="1.3" fill="#2bc4b4"/>';return s}

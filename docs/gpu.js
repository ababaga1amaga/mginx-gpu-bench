// Base-game exact EV (lines / ways) by full reel-stop enumeration: config packing, WASM-MT runner, WebGPU runner.
export function pack(spec){
  const reels=spec.base?.reels||spec.baseReels||spec.strips||spec.reels;if(!reels||!Array.isArray(reels[0])||spec.rows!==3)return null;
  const cols=reels.length,lines=spec.lines||[],ways=spec.base?.eval==="WAYS";if(cols>8||(!ways&&!lines.length))return null;
  const nSym=spec.nSym,stride=spec.pay.length/nSym;if(!Number.isInteger(stride)||spec.pay.length>128||lines.length*cols>160)return null;
  const wild=Array.isArray(spec.wild)?spec.wild:Array.from({length:nSym},(_,i)=>+(i===spec.wild));
  const c=new Uint32Array(328+reels.reduce((a,r)=>a+r.length,0));c[0]=cols;c[1]=stride;c[2]=ways?1:0;c[3]=lines.length;c[4]=nSym;
  let o=328;reels.forEach((r,k)=>{c[8+k]=r.length;c[16+k]=o-328;c.set(r,o);o+=r.length});wild.forEach((w,i)=>c[24+i]=w?1:0);c.set(spec.pay,40);
  lines.forEach((l,i)=>c.set(l,168+i*cols));let combos=1;reels.forEach(r=>combos*=r.length);
  return {cfg:c,combos,n0:reels[0].length,mode:ways?"ways":`${lines.length} линий`};}

let pool=[];const ask=(w,m)=>new Promise(r=>{w.onmessage=e=>r(e.data);w.postMessage(m)});
export async function wasmMT(p,n){while(pool.length<n)pool.push(new Worker("./base-worker.js"));const ws=pool.slice(0,n);
  await Promise.all(ws.map(w=>ask(w,{cfg:p.cfg})));const t=performance.now();let next=0,sum=0;
  await Promise.all(ws.map(w=>(async()=>{while(next<p.n0){const i=next++;const r=await ask(w,{lo:i,hi:i+1});sum+=r.v}})()));
  return {sum,ms:performance.now()-t};}

const WGSL=`struct U{base:u32,total:u32,rest:u32,pad:u32};
@group(0)@binding(0) var<uniform> u:U; @group(0)@binding(1) var<storage,read> c:array<u32>; @group(0)@binding(2) var<storage,read_write> acc:array<atomic<u32>,2>;
var<workgroup> sh:array<u32,256>;
fn cell(g:ptr<function,array<u32,8>>,col:u32,row:u32)->u32{let len=c[8u+col];return c[328u+c[16u+col]+((*g)[col]+row)%len];}
fn isw(x:u32)->bool{return c[24u+x]==1u;}
fn eval(g:ptr<function,array<u32,8>>)->u32{let cols=c[0];let st=c[1];var win=0u;
 if(c[2]==0u){for(var l=0u;l<c[3];l++){let b=168u+l*cols;let s0=cell(g,0u,c[b]);var wl=0u;
   loop{if(wl>=cols){break;} if(!isw(cell(g,wl,c[b+wl]))){break;} wl++;}
   var best=0u;if(wl>0u){best=c[40u+s0*st+wl];}
   if(wl<cols){let s=cell(g,wl,c[b+wl]);var n=wl+1u;loop{if(n>=cols){break;} let x=cell(g,n,c[b+n]);if(x==s||isw(x)){n++;}else{break;}}
     best=max(best,c[40u+s*st+n]);}
   win+=best;}}
 else{for(var s=0u;s<c[4];s++){if(isw(s)){continue;} var ways=1u;var n=0u;
   for(var k=0u;k<cols;k++){var m=0u;for(var r=0u;r<3u;r++){let x=cell(g,k,r);if(x==s||isw(x)){m++;}} if(m==0u){break;} ways*=m;n++;}
   if(n>0u){win+=c[40u+s*st+n]*ways;}}}
 return win;}
@compute @workgroup_size(256) fn main(@builtin(global_invocation_id) gid:vec3<u32>,@builtin(local_invocation_index) li:u32,@builtin(num_workgroups) nw:vec3<u32>){
 let idx=u.base+gid.x+gid.y*nw.x*256u;var w=0u;
 if(idx<u.total){var g:array<u32,8>;g[0]=idx/u.rest;var i=idx%u.rest;for(var k=1u;k<c[0];k++){let l=c[8u+k];g[k]=i%l;i=i/l;} w=eval(&g);}
 sh[li]=w;workgroupBarrier();
 for(var s=128u;s>0u;s=s>>1u){if(li<s){sh[li]+=sh[li+s];} workgroupBarrier();}
 if(li==0u){let v=sh[0];let old=atomicAdd(&acc[0],v);if(old+v<old){atomicAdd(&acc[1],1u);}}}`;

let G=null;
export async function initGPU(){if(!navigator.gpu)throw"navigator.gpu отсутствует (браузер без WebGPU)";
  const ad=await navigator.gpu.requestAdapter({powerPreference:"high-performance"});if(!ad)throw"GPU-адаптер не найден";
  const dev=await ad.requestDevice();const pl=await dev.createComputePipelineAsync({layout:"auto",compute:{module:dev.createShaderModule({code:WGSL}),entryPoint:"main"}});
  const i=ad.info||{};G={dev,pl};return [i.vendor,i.architecture,i.description].filter(Boolean).join(" ")||"адаптер без имени";}
const CH=1<<24;
export async function gpuRun(p){const {dev,pl}=G;const B=(size,usage)=>dev.createBuffer({size,usage});
  const cb=B(p.cfg.byteLength,GPUBufferUsage.STORAGE|GPUBufferUsage.COPY_DST);dev.queue.writeBuffer(cb,0,p.cfg);
  const acc=B(8,GPUBufferUsage.STORAGE|GPUBufferUsage.COPY_SRC|GPUBufferUsage.COPY_DST),rb=B(8,GPUBufferUsage.MAP_READ|GPUBufferUsage.COPY_DST);
  const nch=Math.ceil(p.combos/CH),us=[],bgs=[];
  for(let k=0;k<nch;k++){const ub=B(16,GPUBufferUsage.UNIFORM|GPUBufferUsage.COPY_DST);dev.queue.writeBuffer(ub,0,new Uint32Array([k*CH,p.combos,p.combos/p.n0,0]));us.push(ub);
    bgs.push(dev.createBindGroup({layout:pl.getBindGroupLayout(0),entries:[{binding:0,resource:{buffer:ub}},{binding:1,resource:{buffer:cb}},{binding:2,resource:{buffer:acc}}]}));}
  await dev.queue.onSubmittedWorkDone();
  const t=performance.now();let e=dev.createCommandEncoder();e.clearBuffer(acc);
  for(let k=0;k<nch;k++){const n=Math.min(CH,p.combos-k*CH),wg=Math.ceil(n/256),x=Math.min(wg,65535),y=Math.ceil(wg/x);const c=e.beginComputePass();c.setPipeline(pl);c.setBindGroup(0,bgs[k]);c.dispatchWorkgroups(x,y);c.end();
    if(k<nch-1){dev.queue.submit([e.finish()]);e=dev.createCommandEncoder();}}
  e.copyBufferToBuffer(acc,0,rb,0,8);dev.queue.submit([e.finish()]);await rb.mapAsync(GPUMapMode.READ);const r=new Uint32Array(rb.getMappedRange()).slice();rb.unmap();
  const ms=performance.now()-t;[cb,acc,rb,...us].forEach(b=>b.destroy());return {sum:r[1]*4294967296+r[0],ms};}

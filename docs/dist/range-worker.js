// Pool worker: own WASM instance. {spec} sets the spec for range work, {i} sums reel-1 stop i (dynamic queue),
// {meta} returns split_meta, {solve} runs a whole exact solve single-threaded and reports its time.
import init, { solve_range, split_meta, solve } from "./pkg/mginx_bench.js";
let spec;const ready=init({module_or_path:new URL("./pkg/mginx_bench_bg.wasm",self.location.href)});
self.onmessage=async e=>{await ready;const d=e.data;
  if(d.ping){self.postMessage({ready:true});return;}
  if(d.meta){self.postMessage({meta:JSON.parse(split_meta(d.meta))});return;}
  if(d.solve){const t=performance.now();const r=JSON.parse(solve(d.solve));self.postMessage({ev:r.ev,ms:performance.now()-t});return;}
  if(d.spec){spec=d.spec;self.postMessage({ready:true});return;}
  self.postMessage({v:solve_range(spec,d.i,d.i+1)});};

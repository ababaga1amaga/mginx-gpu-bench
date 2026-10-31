// One of N cascade workers: own WASM instance, sums stop[0] values handed out by the page (dynamic queue).
import init, { cascade_range } from "./pkg/mginx_bench.js";
let spec;const ready=init(new URL("./pkg/mginx_bench_bg.wasm",self.location.href));
self.onmessage=async e=>{await ready;if(e.data.spec){spec=e.data.spec;self.postMessage({ready:true});return;}const i=e.data.i;self.postMessage({v:cascade_range(spec,i,i+1)});};

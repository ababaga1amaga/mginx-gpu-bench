// WASM worker for base-game enumeration: {cfg:Uint32Array} loads config, {lo,hi} returns partial sum.
let W;const ready=WebAssembly.instantiateStreaming(fetch(new URL("./bench.wasm",self.location.href))).then(r=>W=r.instance.exports);
self.onmessage=async e=>{await ready;const d=e.data;
  if(d.cfg){new Uint32Array(W.memory.buffer,W.cfg_ptr(),16384).set(d.cfg);self.postMessage({ok:1});return;}
  self.postMessage({v:W.solve_range(d.lo,d.hi)});};

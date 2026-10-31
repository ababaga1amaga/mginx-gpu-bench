# mginx-gpu-bench

The same mechanic/variant table as [mginx-bench-preview](https://ababaga1amaga.github.io/mginx-bench-preview/) (12 mechanics, frozen MC slices, WASM exact EV), plus **WebGPU vs WASM** columns.

**Live:** https://ababaga1amaga.github.io/mginx-gpu-bench/

WebGPU columns: for every variant with 3-row reel strips and lines/ways, the exact **base-game** EV (no features; wild substitution; simplified evaluator) is computed by full enumeration of all reel-stop combinations — the identical task on
- WASM (`src/lib.rs`, Rust no_std, all CPU threads via workers, split by reel-1 stop), and
- WebGPU (`docs/gpu.js` WGSL compute shader, 1 combination = 1 GPU thread, workgroup reduce + 64-bit integer atomic sum).

Integer sums → deterministic, compared bit-for-bit ("WASM = GPU?"). Times exclude pipeline compilation; GPU time includes readback (second run, after warm-up). Megaways, Hold&Win, instant are not ported ("не переносилось"). Without WebGPU the page shows a message and still runs WASM/MC.

Original columns (`docs/index.html`, `docs/dist/`) are copied unchanged from mginx-bench-preview.

Build: `cargo build --release --target wasm32-unknown-unknown && cp target/wasm32-unknown-unknown/release/bench.wasm docs/`. Pages serves `/docs` on `master`.

# mginx-gpu-bench

PoC microbenchmark: **WebGPU compute vs WASM (Rust, single-thread) vs plain JS** for math-engine-like parallel integer work (slot/plinko-style folds).

**Live:** https://ababaga1amaga.github.io/mginx-gpu-bench/

Workloads (identical PCG u32 hash in all backends → deterministic, bit-exact checksums):
- **Plinko MC** — N independent balls × R pegs, histogram of landing bins (GPU: atomicAdd).
- **Column-product fold** — N columns × K rows, wrapping u32 product per column, wrap-sum of all columns.

Timing: median/min of N reps after warm-up. WebGPU timing is end-to-end (uniform write, dispatch, readback). Falls back to WASM+JS if WebGPU is unavailable.

Build wasm: `cargo build --release --target wasm32-unknown-unknown && cp target/wasm32-unknown-unknown/release/bench.wasm docs/`. Pages serves `/docs`.

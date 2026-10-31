/* tslint:disable */
/* eslint-disable */

export function cascade_meta(spec: string): string;

/**
 * Legacy aliases kept for existing JS callers.
 */
export function cascade_range(spec: string, lo: number, hi: number): number;

export function solve(spec: string): string;

/**
 * Partial EV for reel-1 stops [lo,hi) of a `parallel: stopRange` plan (stopEnum cascades, columnDP ways).
 */
export function solve_range(spec: string, lo: number, hi: number): number;

/**
 * {"n0": reel-1 stops} for stopRange plans, {"n0":0} otherwise.
 */
export function split_meta(spec: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly cascade_meta: (a: number, b: number) => [number, number];
    readonly cascade_range: (a: number, b: number, c: number, d: number) => number;
    readonly solve: (a: number, b: number) => [number, number];
    readonly solve_range: (a: number, b: number, c: number, d: number) => number;
    readonly split_meta: (a: number, b: number) => [number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;

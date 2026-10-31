// node_modules/@noble/hashes/_u64.js
var fromNumH = (n) => n / 2 ** 32 | 0;
var fromNumL = (n) => n >>> 0;
function setU64FromNum(view, byteOffset, n, isLE) {
  const h = fromNumH(n);
  const l = fromNumL(n);
  view.setUint32(byteOffset, isLE ? l : h, isLE);
  view.setUint32(byteOffset + 4, isLE ? h : l, isLE);
}

// node_modules/@noble/hashes/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
var atitle = (title) => title ? `"${title}" ` : "";
function anumber(n, title = "") {
  if (typeof n !== "number")
    throw new TypeError(atitle(title) + "expected number, got " + typeof n);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
  return n;
}
function abytes(value, length, title = "") {
  if (isBytes(value) && (length === void 0 || value.length === length))
    return value;
  if (length !== void 0)
    anumber(length, "length");
  const bytes = isBytes(value);
  const ofLen = length !== void 0 ? ` of length ${length}` : "";
  const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
  const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
  if (!bytes)
    throw new TypeError(message);
  throw new RangeError(message);
}
var aobject = (value, label) => {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError((label === "object" ? "" : `"${label}" `) + "expected object, got type=" + typeof value);
};
var aopts = (value, label) => {
  aobject(value, label);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null)
    throw new TypeError(`"${label}" expected plain object`);
  if (Object.hasOwn(value, "__proto__"))
    throw new TypeError(`"${label}.__proto__" is not allowed`);
};
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("hash was destroyed");
  if (checkFinished && instance.finished)
    throw new Error("digest() was already called");
}
function aoutput(out, instance) {
  abytes(out, void 0, "output");
  const min = instance.outputLen;
  if (!(out.length >= min)) {
    throw new RangeError('"output" expected length >= ' + min);
  }
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
function checkOpts(defaults, opts, title = "opts") {
  aopts(defaults, "defaults");
  if (opts !== void 0)
    aopts(opts, title);
  const merged = Object.assign(/* @__PURE__ */ Object.create(null), defaults, opts);
  return merged;
}
function createHasher(hashCons, info = {}) {
  if (typeof hashCons !== "function")
    throw new TypeError('"hashCons" expected function, got type=' + typeof hashCons);
  info = checkOpts({}, info, "info");
  const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
  const tmp = hashCons(void 0);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.canXOF = tmp.canXOF;
  hashC.create = (opts) => hashCons(opts);
  Object.assign(hashC, info);
  return Object.freeze(hashC);
}
var oidNist = (suffix) => ({
  // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
  // Larger suffix values would need base-128 OID encoding and a different length byte.
  oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
});

// node_modules/@noble/hashes/_md.js
function Chi(a, b, c2) {
  return a & b ^ ~a & c2;
}
function Maj(a, b, c2) {
  return a & b ^ a & c2 ^ b & c2;
}
var HashMD = class {
  blockLen;
  outputLen;
  canXOF = false;
  padOffset;
  isLE;
  // For partial updates less than block size
  buffer;
  view;
  finished = false;
  length = 0;
  pos = 0;
  destroyed = false;
  constructor(blockLen, outputLen, padOffset, isLE) {
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    aexists(this);
    abytes(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    let processed = false;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        processed = true;
        continue;
      }
      buffer.set(pos === 0 && take === len ? data : data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
        processed = true;
      }
    }
    this.length += data.length;
    if (processed)
      this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    buffer.fill(0, pos);
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      buffer.fill(0);
    }
    setU64FromNum(view, blockLen - 8, this.length * 8, isLE);
    this.process(view, 0);
    this.roundClean();
    const oview = out === buffer ? view : createView(out);
    const len = this.outputLen;
    const outLen = len / 4;
    const state = this.get();
    if (len % 4 || outLen > state.length)
      throw new Error("invalid outputLen");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneIntoMeta(to) {
    const { buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (pos)
      to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};
var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);

// node_modules/@noble/hashes/sha2.js
var SHA256_K = /* @__PURE__ */ Uint32Array.from([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
var SHA2_32B = class extends HashMD {
  // We cannot use array here since array allows indexing by variable
  // which means optimizer/compiler cannot use registers.
  // Numeric initializers matter: starting the fields as `undefined` changes
  // V8's field representation and makes sha256 3x slower (measured).
  A = 0;
  B = 0;
  C = 0;
  D = 0;
  E = 0;
  F = 0;
  G = 0;
  H = 0;
  constructor(outputLen, IV) {
    super(64, outputLen, 8, false);
    this.A = IV[0] | 0;
    this.B = IV[1] | 0;
    this.C = IV[2] | 0;
    this.D = IV[3] | 0;
    this.E = IV[4] | 0;
    this.F = IV[5] | 0;
    this.G = IV[6] | 0;
    this.H = IV[7] | 0;
  }
  get() {
    const { A, B, C, D, E, F, G, H } = this;
    return [A, B, C, D, E, F, G, H];
  }
  // prettier-ignore
  set(A, B, C, D, E, F, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  _cloneInto(to) {
    (to ||= new this.constructor()).set(...this.get());
    return this._cloneIntoMeta(to);
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D, E, F, G, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G;
      G = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D, E, F, G, H);
  }
  roundClean() {
    clean(SHA256_W);
  }
  destroy() {
    this.destroyed = true;
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    clean(this.buffer);
  }
};
var _SHA256 = class extends SHA2_32B {
  constructor() {
    super(32, SHA256_IV);
  }
};
var sha256 = /* @__PURE__ */ createHasher(
  () => new _SHA256(),
  /* @__PURE__ */ oidNist(1)
);

// bench/web/shims/crypto.js
var hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
function createHash(name) {
  if (name !== "sha256") throw new Error("shim: only sha256");
  const parts = [];
  return {
    update(d) {
      parts.push(typeof d === "string" ? new TextEncoder().encode(d) : d);
      return this;
    },
    digest(enc) {
      let n = 0;
      for (const p of parts) n += p.length;
      const all = new Uint8Array(n);
      let o = 0;
      for (const p of parts) {
        all.set(p, o);
        o += p.length;
      }
      const h = sha256(all);
      if (enc === "hex") return hex(h);
      h.readBigUInt64BE = function(off = 0) {
        return new DataView(this.buffer, this.byteOffset).getBigUint64(off, false);
      };
      return h;
    }
  };
}

// dist/src/runtime/rng.js
function uint64(a) {
  const s = [a.seed, a.modeId, a.nodeId, a.invocation, a.index].map(String).join("");
  const b = createHash("sha256").update(s).digest();
  return b.readBigUInt64BE(0);
}
function weightedIndex(weights, a) {
  const total = weights.reduce((x, y) => x + y, 0n);
  if (total <= 0n)
    throw new Error("invalid weights");
  let r = uint64(a) % total;
  for (let i = 0; i < weights.length; i++) {
    if (r < weights[i])
      return i;
    r -= weights[i];
  }
  throw new Error("unreachable");
}

// dist/src/math/nodeHandlers.js
function refs(e, out = /* @__PURE__ */ new Set()) {
  if (!e || typeof e !== "object")
    return out;
  if ("ref" in e) {
    out.add(e.ref);
    return out;
  }
  if ("left" in e)
    refs(e.left, out);
  if ("right" in e)
    refs(e.right, out);
  return out;
}
function splitRefs(xs) {
  const frame = [], state = [];
  for (const r of xs)
    r.startsWith("$state.") ? state.push(r.slice(7)) : frame.push(r);
  return { frame, state };
}
function base() {
  return { stochastic: false, enumerable: false, deterministic: true, readsFrame: [], writesFrame: [], readsState: [], writesState: [], mayBranch: false, mayTransitionMode: false };
}
function evalExpression(e, frame, state) {
  const get = (k) => frame instanceof Map ? frame.get(k) : frame[k], values = state.values ?? state;
  if ("const" in e)
    return e.const;
  if ("ref" in e)
    return e.ref.startsWith("$state.") ? values[e.ref.slice(7)] : get(e.ref);
  const l = evalExpression(e.left, frame, state), r = evalExpression(e.right, frame, state);
  switch (e.op) {
    case "+":
      return l + r;
    case "-":
      return l - r;
    case "*":
      return l * r;
    case "==":
      return l === r;
    case ">=":
      return l >= r;
    case ">":
      return l > r;
    case "<=":
      return l <= r;
    case "<":
      return l < r;
  }
}
function reelSpin(def, node, seed, modeId, invocation) {
  const set = def.reelSets[node.source.reelSetId];
  if (!set)
    throw new Error(`missing reel set ${node.source.reelSetId}`);
  const stops = set.reels.map((r, i) => Number(uint64({ seed, modeId, nodeId: node.id, invocation, index: BigInt(i) }) % BigInt(r.symbols.length)));
  return { rows: node.source.rows, cols: set.reels.length, stops, symbols: Array.from({ length: node.source.rows }, (_, row) => set.reels.map((r, col) => r.symbols[(stops[col] + row) % r.symbols.length])) };
}
function runtimeFrame(frame) {
  return Object.fromEntries(frame);
}
var builtinNodeHandlers = {
  SOURCE: { kind: "SOURCE", stochasticBoundary: true, capabilities: (n) => ({ ...base(), stochastic: true, enumerable: n.source.type === "WEIGHTED_CHOICE" || n.source.type === "REEL_SPIN", deterministic: false, writesFrame: [n.output] }), runtime: (c2) => {
    let v;
    if (c2.node.source.type === "WEIGHTED_CHOICE") {
      const i = weightedIndex(c2.node.source.outcomes.map((x) => x.weight), { seed: c2.seed, modeId: c2.modeId, nodeId: c2.node.id, invocation: c2.invocation, index: 0n });
      v = c2.node.source.outcomes[i].value;
    } else
      v = reelSpin(c2.def, c2.node, c2.seed, c2.modeId, c2.invocation);
    c2.frame.set(c2.node.output, v);
    return { next: c2.node.next, payload: { invocation: c2.invocation.toString(), value: v } };
  }, expandExact: (c2) => {
    const lower = c2.lowering.sources[c2.node.source.type];
    if (!lower)
      throw new Error(`no exact source lowerer for ${c2.node.source.type}`);
    return Array.from(lower(c2.def, c2.node), (o) => ({ value: o.value, probability: o.probability, next: c2.node.next, frame: { ...c2.frame, [c2.node.output]: o.value } }));
  } },
  TRANSFORM: { kind: "TRANSFORM", capabilities: (n) => ({ ...base(), readsFrame: [n.operation.input], writesFrame: [n.output] }), runtime: (c2) => {
    const v = c2.frame.get(c2.node.operation.input);
    c2.frame.set(c2.node.output, v);
    return { next: c2.node.next, payload: v };
  }, exact: (c2) => {
    c2.frame[c2.node.output] = c2.frame[c2.node.operation.input];
    return { next: c2.node.next };
  } },
  EVALUATE: { kind: "EVALUATE", capabilities: (n) => {
    const c2 = base(), e = n.evaluator;
    c2.writesFrame = [n.output];
    c2.readsFrame = [e.input ?? e.board ?? e.wins].filter(Boolean);
    return c2;
  }, runtime: (c2) => {
    const h = c2.evaluators[c2.node.evaluator.type];
    if (!h)
      throw new Error(`no evaluator for ${c2.node.evaluator.type}`);
    const v = h(c2.def, c2.node, runtimeFrame(c2.frame));
    c2.frame.set(c2.node.output, v);
    return { next: c2.node.next, payload: v };
  }, exact: (c2) => {
    const h = c2.lowering.evaluators[c2.node.evaluator.type];
    if (!h)
      throw new Error(`no exact evaluator lowerer for ${c2.node.evaluator.type}`);
    c2.frame[c2.node.output] = h(c2.def, c2.node, c2.frame);
    return { next: c2.node.next };
  } },
  CONDITION: { kind: "CONDITION", capabilities: (n) => {
    const r = splitRefs(refs(n.expression));
    return { ...base(), readsFrame: r.frame, readsState: r.state, mayBranch: true };
  }, runtime: (c2) => {
    const ok = Boolean(evalExpression(c2.node.expression, c2.frame, c2.state));
    return { next: ok ? c2.node.onTrue : c2.node.onFalse, payload: ok };
  }, exact: (c2) => ({ next: Boolean(evalExpression(c2.node.expression, c2.frame, c2.values)) ? c2.node.onTrue : c2.node.onFalse }) },
  AWARD: { kind: "AWARD", capabilities: (n) => {
    const r = splitRefs(refs(n.amount));
    return { ...base(), readsFrame: r.frame, readsState: r.state };
  }, runtime: (c2) => {
    const a = BigInt(evalExpression(c2.node.amount, c2.frame, c2.state));
    return { next: c2.node.next, state: { ...c2.state, totalAward: c2.state.totalAward + a }, payload: a.toString() };
  }, exact: (c2) => ({ next: c2.node.next, reward: BigInt(evalExpression(c2.node.amount, c2.frame, c2.values)) }) },
  STATE: { kind: "STATE", capabilities: (n) => {
    const r = splitRefs(refs(n.value));
    const reads = [...r.state];
    if (n.op === "ADD")
      reads.push(n.target);
    return { ...base(), readsFrame: r.frame, readsState: reads, writesState: [n.target] };
  }, runtime: (c2) => {
    const v = evalExpression(c2.node.value, c2.frame, c2.state), values = { ...c2.state.values }, old = values[c2.node.target];
    values[c2.node.target] = c2.node.op === "SET" ? v : (old ?? 0) + v;
    return { next: c2.node.next, state: { ...c2.state, values }, payload: values[c2.node.target] };
  }, exact: (c2) => {
    const v = evalExpression(c2.node.value, c2.frame, c2.values), old = c2.values[c2.node.target];
    c2.values[c2.node.target] = c2.node.op === "SET" ? v : (old ?? 0) + v;
    return { next: c2.node.next };
  } },
  FLOW: { kind: "FLOW", capabilities: (n) => ({ ...base(), mayTransitionMode: n.operation.type === "ENTER_MODE" }), runtime: (c2) => c2.node.operation.type === "END_GAME" ? { terminal: true, payload: "END_GAME" } : { modeId: c2.node.operation.modeId }, exact: (c2) => c2.node.operation.type === "END_GAME" ? { terminal: true } : { modeId: c2.node.operation.modeId, clearFrame: true } }
};

// dist/src/math/evaluators.js
function evaluatePaylines(def, board, paytableId, lineIds, wildTag = "WILD") {
  const pt = def.paytables[paytableId], out = [];
  for (const lineId of lineIds) {
    const line = def.paylines[lineId], seq = line.rows.map((row, col) => board.symbols[row][col]);
    let target;
    for (const s of seq)
      if (!def.symbols[s]?.tags.includes(wildTag)) {
        target = s;
        break;
      }
    target ??= seq[0];
    let count = 0;
    for (const s of seq) {
      if (s === target || def.symbols[s]?.tags.includes(wildTag))
        count++;
      else
        break;
    }
    const payout = pt.pays[target]?.[count] ?? 0n;
    if (payout > 0n)
      out.push({ lineId, symbolId: target, count, payout });
  }
  return out;
}
var builtinEvaluatorHandlers = Object.freeze({
  IDENTITY: (_d, n, f) => {
    if (n.evaluator.type !== "IDENTITY")
      throw 0;
    return f[n.evaluator.input];
  },
  SUM_WINS: (_d, n, f) => {
    if (n.evaluator.type !== "SUM_WINS")
      throw 0;
    return f[n.evaluator.wins].reduce((s, w) => s + w.payout, 0n);
  },
  COUNT_TAG: (d, n, f) => {
    if (n.evaluator.type !== "COUNT_TAG")
      throw 0;
    const e = n.evaluator, b = f[e.board];
    return b.symbols.flat().filter((s) => d.symbols[s]?.tags.includes(e.tag)).length;
  },
  PAYLINES: (d, n, f) => {
    if (n.evaluator.type !== "PAYLINES")
      throw 0;
    return evaluatePaylines(d, f[n.evaluator.board], n.evaluator.paytableId, n.evaluator.paylineIds, n.evaluator.wildTag);
  }
});

// dist/src/runtime/executor.js
function play(def, seed, opts = {}) {
  let state = { currentModeId: def.entryModeId, totalAward: 0n, values: {}, step: 0n };
  const frame = /* @__PURE__ */ new Map(), trace = [], inv = /* @__PURE__ */ new Map(), handlers = opts.handlers ?? builtinNodeHandlers, evaluators = opts.evaluators ?? builtinEvaluatorHandlers;
  let nodeId = def.modes[state.currentModeId].entryNodeId;
  for (let guard = 0; guard < 1e5; guard++) {
    const mode = def.modes[state.currentModeId], node = mode.nodes[nodeId];
    if (!node)
      throw new Error(`missing node ${nodeId} in ${mode.id}`);
    const h = handlers[node.kind];
    if (!h)
      throw new Error(`no node handler for ${node.kind}`);
    state = { ...state, step: state.step + 1n, values: { ...state.values } };
    const k = `${mode.id}:${node.id}`, invocation = inv.get(k) ?? 0n;
    if (h.stochasticBoundary)
      inv.set(k, invocation + 1n);
    const r = h.runtime({ def, node, modeId: mode.id, seed, invocation, frame, state, evaluators });
    if (r.state)
      state = r.state;
    if (r.terminal) {
      trace.push({ sequence: state.step.toString(), modeId: mode.id, nodeId: node.id, kind: node.kind, payload: r.payload });
      return { state, trace };
    }
    let next = r.next;
    if (r.modeId) {
      state = { ...state, currentModeId: r.modeId };
      next = def.modes[state.currentModeId].entryNodeId;
      frame.clear();
    }
    trace.push({ sequence: state.step.toString(), modeId: mode.id, nodeId: node.id, kind: node.kind, payload: r.payload ?? null });
    if (!next)
      throw new Error(`node ${node.id} has no next`);
    nodeId = next;
  }
  throw new Error("execution guard exceeded");
}

// dist/src/core/rational.js
var Rational = class _Rational {
  n;
  d;
  constructor(n, d = 1n) {
    if (d === 0n)
      throw new Error("zero denominator");
    const sign = d < 0n ? -1n : 1n;
    const g = gcd(abs(n), abs(d));
    this.n = sign * n / g;
    this.d = abs(d) / g;
  }
  add(x) {
    return new _Rational(this.n * x.d + x.n * this.d, this.d * x.d);
  }
  sub(x) {
    return new _Rational(this.n * x.d - x.n * this.d, this.d * x.d);
  }
  mul(x) {
    return new _Rational(this.n * x.n, this.d * x.d);
  }
  div(x) {
    if (x.n === 0n)
      throw new Error("division by zero");
    return new _Rational(this.n * x.d, this.d * x.n);
  }
  neg() {
    return new _Rational(-this.n, this.d);
  }
  toNumber() {
    return Number(this.n) / Number(this.d);
  }
  toString() {
    return this.d === 1n ? `${this.n}` : `${this.n}/${this.d}`;
  }
};
var abs = (x) => x < 0n ? -x : x;
function gcd(a, b) {
  while (b) {
    const t = a % b;
    a = b;
    b = t;
  }
  return a || 1n;
}

// dist/src/math/queryCompiler.js
function compileMathQuery(query, opts = {}) {
  switch (query.type) {
    case "EV":
    case "RTP":
      return { queryType: query.type, observables: ["rewardMean"], backend: "REWARD", partitionable: true };
    case "VARIANCE":
      return { queryType: query.type, observables: ["rewardSecond"], backend: "REWARD", partitionable: true };
    case "EXPECTED_DURATION":
      return { queryType: query.type, observables: ["steps"], backend: "DURATION", partitionable: true };
    case "HIT_RATE":
      return { queryType: query.type, observables: ["hitProbability"], backend: "ZERO_WIN", partitionable: true };
    case "DISTRIBUTION":
      return { queryType: query.type, observables: opts.pgfZ === void 0 ? [] : ["pgf"], backend: "PGF", partitionable: opts.pgfZ !== void 0, pgfZ: opts.pgfZ };
    case "FEATURE_FREQUENCY":
      return { queryType: query.type, observables: [], backend: "ENTRY_PROBABILITY", partitionable: false };
  }
  throw new Error(`unregistered query type: ${query.type}`);
}

// dist/src/math/exactReels.js
var ZERO = new Rational(0n);
var ONE = new Rational(1n);
function addTo(m, k, v) {
  m.set(k, (m.get(k) ?? ZERO).add(v));
}
function rowSymbolDistribution(reel, row) {
  const counts2 = /* @__PURE__ */ new Map();
  for (let stop = 0; stop < reel.symbols.length; stop++) {
    const s = reel.symbols[(stop + row) % reel.symbols.length];
    counts2.set(s, (counts2.get(s) ?? 0n) + 1n);
  }
  return new Map([...counts2].map(([s, c2]) => [s, new Rational(c2, BigInt(reel.symbols.length))]));
}
function expectedPayline(def, reelSetId, paytableId, rows, wildTag = "WILD") {
  const reels = def.reelSets[reelSetId].reels;
  const pt = def.paytables[paytableId];
  let states = /* @__PURE__ */ new Map();
  states.set("|0", ONE);
  for (let col = 0; col < reels.length; col++) {
    const dist = rowSymbolDistribution(reels[col], rows[col]);
    const next = /* @__PURE__ */ new Map();
    for (const [key, p0] of states) {
      const [target0, countText] = key.split("|");
      const count0 = Number(countText);
      for (const [symbol, ps] of dist) {
        const wild = def.symbols[symbol]?.tags.includes(wildTag) ?? false;
        let target = target0, count = count0;
        if (count0 === col) {
          if (!target && !wild)
            target = symbol;
          if (wild || !target || symbol === target)
            count++;
        }
        addTo(next, `${target}|${count}`, p0.mul(ps));
      }
    }
    states = next;
  }
  let ev = ZERO;
  for (const [key, p] of states) {
    let [target, countText] = key.split("|");
    const count = Number(countText);
    if (!target)
      target = "W";
    const pay = pt.pays[target]?.[count] ?? 0n;
    if (pay)
      ev = ev.add(p.mul(new Rational(pay)));
  }
  return ev;
}
function reelScatterDistribution(def, reel, rows, tag) {
  const counts2 = /* @__PURE__ */ new Map();
  for (let stop = 0; stop < reel.symbols.length; stop++) {
    let n = 0;
    for (let row = 0; row < rows; row++)
      if (def.symbols[reel.symbols[(stop + row) % reel.symbols.length]]?.tags.includes(tag))
        n++;
    counts2.set(n, (counts2.get(n) ?? 0n) + 1n);
  }
  return new Map([...counts2].map(([n, c2]) => [n, new Rational(c2, BigInt(reel.symbols.length))]));
}
function scatterDistribution(def, reelSetId, rows, tag = "SCATTER") {
  let total = /* @__PURE__ */ new Map([[0, ONE]]);
  for (const reel of def.reelSets[reelSetId].reels) {
    const rd = reelScatterDistribution(def, reel, rows, tag), next = /* @__PURE__ */ new Map();
    for (const [a, pa] of total)
      for (const [b, pb] of rd)
        addTo(next, a + b, pa.mul(pb));
    total = next;
  }
  return total;
}
function exactSpinSummary(def, reelSetId, paytableId, paylineIds, rows, multiplier = 1n, triggerAt = 3) {
  let lineEv = ZERO;
  for (const id of paylineIds)
    lineEv = lineEv.add(expectedPayline(def, reelSetId, paytableId, def.paylines[id].rows));
  lineEv = lineEv.mul(new Rational(multiplier));
  const scatters = scatterDistribution(def, reelSetId, rows);
  let trigger = ZERO;
  for (const [n, p] of scatters)
    if (n >= triggerAt)
      trigger = trigger.add(p);
  return { expectedLineWin: lineEv, scatterCount: scatters, triggerProbability: trigger };
}
function linePayout(def, paytableId, seq, wildTag = "WILD") {
  const pt = def.paytables[paytableId];
  let target;
  for (const s of seq) {
    if (!def.symbols[s]?.tags.includes(wildTag)) {
      target = s;
      break;
    }
  }
  target ??= seq[0];
  let count = 0;
  for (const s of seq) {
    if (s === target || def.symbols[s]?.tags.includes(wildTag))
      count++;
    else
      break;
  }
  return pt.pays[target]?.[count] ?? 0n;
}
function exactLineJoint(def, reelSetId, paytableId, rowsA, rowsB) {
  const reels = def.reelSets[reelSetId].reels;
  let states = /* @__PURE__ */ new Map([["", { p: ONE, a: [], b: [] }]]);
  for (let col = 0; col < reels.length; col++) {
    const reel = reels[col], grouped = /* @__PURE__ */ new Map();
    for (let stop = 0; stop < reel.symbols.length; stop++) {
      const a = reel.symbols[(stop + rowsA[col]) % reel.symbols.length], b = rowsB ? reel.symbols[(stop + rowsB[col]) % reel.symbols.length] : a;
      grouped.set(`${a}${b}`, (grouped.get(`${a}${b}`) ?? 0n) + 1n);
    }
    const next = /* @__PURE__ */ new Map();
    let serial = 0;
    for (const st of states.values())
      for (const [pair, c2] of grouped) {
        const [a, b] = pair.split("");
        const x = { p: st.p.mul(new Rational(c2, BigInt(reel.symbols.length))), a: [...st.a, a], b: [...st.b, b] };
        next.set(String(serial++), x);
      }
    states = next;
  }
  let out = ZERO;
  for (const st of states.values())
    out = out.add(st.p.mul(new Rational(linePayout(def, paytableId, st.a) * linePayout(def, paytableId, st.b))));
  return out;
}
function exactLineTimesTrigger(def, reelSetId, paytableId, rowsLine, rows, triggerAt) {
  const reels = def.reelSets[reelSetId].reels;
  let states = [{ p: ONE, seq: [], sc: 0 }];
  for (let col = 0; col < reels.length; col++) {
    const reel = reels[col], grouped = /* @__PURE__ */ new Map();
    for (let stop = 0; stop < reel.symbols.length; stop++) {
      const s = reel.symbols[(stop + rowsLine[col]) % reel.symbols.length];
      let sc = 0;
      for (let r = 0; r < rows; r++)
        if (def.symbols[reel.symbols[(stop + r) % reel.symbols.length]]?.tags.includes("SCATTER"))
          sc++;
      const k = `${s}${sc}`, g = grouped.get(k);
      if (g)
        g.c++;
      else
        grouped.set(k, { c: 1n, s, sc });
    }
    const next = [];
    for (const st of states)
      for (const g of grouped.values())
        next.push({ p: st.p.mul(new Rational(g.c, BigInt(reel.symbols.length))), seq: [...st.seq, g.s], sc: st.sc + g.sc });
    states = next;
  }
  let out = ZERO;
  for (const st of states)
    if (st.sc >= triggerAt)
      out = out.add(st.p.mul(new Rational(linePayout(def, paytableId, st.seq))));
  return out;
}
function exactSpinMoments(def, reelSetId, paytableId, paylineIds, rows, multiplier = 1n, triggerAt = 3) {
  const summary = exactSpinSummary(def, reelSetId, paytableId, paylineIds, rows, multiplier, triggerAt);
  let rawSecond = ZERO, rawTrigger = ZERO;
  for (let i = 0; i < paylineIds.length; i++) {
    const a = def.paylines[paylineIds[i]].rows;
    rawSecond = rawSecond.add(exactLineJoint(def, reelSetId, paytableId, a));
    rawTrigger = rawTrigger.add(exactLineTimesTrigger(def, reelSetId, paytableId, a, rows, triggerAt));
    for (let j = i + 1; j < paylineIds.length; j++) {
      const b = def.paylines[paylineIds[j]].rows;
      rawSecond = rawSecond.add(new Rational(2n).mul(exactLineJoint(def, reelSetId, paytableId, a, b)));
    }
  }
  const m = new Rational(multiplier);
  return { ...summary, rewardSecond: rawSecond.mul(m).mul(m), rewardTimesTrigger: rawTrigger.mul(m) };
}
function hitLineKey(x) {
  return `${x.target},${x.count},${x.alive ? 1 : 0}`;
}
function advanceHitLine(def, x, s) {
  if (!x.alive)
    return x;
  const wild = def.symbols[s]?.tags.includes("WILD") ?? false;
  let target = x.target;
  if (!target && !wild)
    target = s;
  if (wild || !target || s === target)
    return { target, count: x.count + 1, alive: true };
  return { target, count: x.count, alive: false };
}
function exactSpinHitSummary(def, reelSetId, paytableId, paylineIds, rows, triggerAt = 3) {
  const reels = def.reelSets[reelSetId].reels, lines = paylineIds.map((id) => def.paylines[id]);
  let states = /* @__PURE__ */ new Map();
  const init2 = { ls: lines.map(() => ({ target: "", count: 0, alive: true })), sc: 0 };
  states.set("init", { s: init2, ways: 1n });
  let denominator = 1n;
  for (let col = 0; col < reels.length; col++) {
    const reel = reels[col], next = /* @__PURE__ */ new Map();
    denominator *= BigInt(reel.symbols.length);
    const visible = /* @__PURE__ */ new Map();
    for (let stop = 0; stop < reel.symbols.length; stop++) {
      const cells = Array.from({ length: rows }, (_, r) => reel.symbols[(stop + r) % reel.symbols.length]);
      const k = cells.join("");
      const g = visible.get(k);
      if (g)
        g.count++;
      else
        visible.set(k, { cells, count: 1n });
    }
    for (const { s, ways } of states.values())
      for (const v of visible.values()) {
        const ls = s.ls.map((x, i) => advanceHitLine(def, x, v.cells[lines[i].rows[col]]));
        const sc = s.sc + v.cells.reduce((n, sym) => n + (def.symbols[sym]?.tags.includes("SCATTER") ? 1 : 0), 0);
        const ns = { ls, sc }, key = `${ls.map(hitLineKey).join("|")}#${sc}`;
        const old = next.get(key);
        if (old)
          old.ways += ways * v.count;
        else
          next.set(key, { s: ns, ways: ways * v.count });
      }
    states = next;
  }
  let win = 0n, zt = 0n, zn = 0n;
  for (const { s, ways } of states.values()) {
    const hasWin = s.ls.some((x) => {
      let target = x.target;
      if (!target)
        target = "W";
      return (def.paytables[paytableId].pays[target]?.[x.count] ?? 0n) > 0n;
    });
    if (hasWin)
      win += ways;
    else if (s.sc >= triggerAt)
      zt += ways;
    else
      zn += ways;
  }
  if (win + zt + zn !== denominator)
    throw new Error("hit summary probability mass mismatch");
  return { winProbability: new Rational(win, denominator), zeroAndTriggerProbability: new Rational(zt, denominator), zeroAndNoTriggerProbability: new Rational(zn, denominator) };
}
function exactSpinPayoutTriggerDistribution(def, reelSetId, paytableId, paylineIds, rows, multiplier = 1n, triggerAt = 3) {
  const reels = def.reelSets[reelSetId].reels, lines = paylineIds.map((id) => def.paylines[id]);
  let states = /* @__PURE__ */ new Map();
  const init2 = { ls: lines.map(() => ({ target: "", count: 0, alive: true })), sc: 0 };
  states.set("init", { s: init2, ways: 1n });
  let denominator = 1n;
  for (let col = 0; col < reels.length; col++) {
    const reel = reels[col], next = /* @__PURE__ */ new Map();
    denominator *= BigInt(reel.symbols.length);
    const visible = /* @__PURE__ */ new Map();
    for (let stop = 0; stop < reel.symbols.length; stop++) {
      const cells = Array.from({ length: rows }, (_, r) => reel.symbols[(stop + r) % reel.symbols.length]), k = cells.join("");
      const g = visible.get(k);
      if (g)
        g.count++;
      else
        visible.set(k, { cells, count: 1n });
    }
    for (const { s, ways } of states.values())
      for (const v of visible.values()) {
        const ls = s.ls.map((x, i) => advanceHitLine(def, x, v.cells[lines[i].rows[col]]));
        const sc = s.sc + v.cells.reduce((n, sym) => n + (def.symbols[sym]?.tags.includes("SCATTER") ? 1 : 0), 0);
        const ns = { ls, sc }, key = `${ls.map(hitLineKey).join("|")}#${sc}`, old = next.get(key);
        if (old)
          old.ways += ways * v.count;
        else
          next.set(key, { s: ns, ways: ways * v.count });
      }
    states = next;
  }
  const grouped = /* @__PURE__ */ new Map();
  for (const { s, ways } of states.values()) {
    let payout = 0n;
    for (const x of s.ls) {
      let target = x.target;
      if (!target)
        target = "W";
      payout += def.paytables[paytableId].pays[target]?.[x.count] ?? 0n;
    }
    payout *= multiplier;
    const trigger = s.sc >= triggerAt, key = `${payout}:${trigger ? 1 : 0}`, g = grouped.get(key);
    if (g)
      g.ways += ways;
    else
      grouped.set(key, { payout, trigger, ways });
  }
  let mass = 0n;
  for (const x of grouped.values())
    mass += x.ways;
  if (mass !== denominator)
    throw new Error("payout distribution probability mass mismatch");
  return [...grouped.values()].sort((a, b) => a.payout < b.payout ? -1 : a.payout > b.payout ? 1 : Number(a.trigger) - Number(b.trigger)).map((x) => ({ payout: x.payout, trigger: x.trigger, probability: new Rational(x.ways, denominator) }));
}

// dist/src/math/markov.js
function solveRegenerative(meanReward, expectedOffspring) {
  if (expectedOffspring.n >= expectedOffspring.d)
    throw new Error(`non-terminating/divergent regenerative process: offspring=${expectedOffspring}`);
  const denom = new Rational(expectedOffspring.d - expectedOffspring.n, expectedOffspring.d);
  const inv = new Rational(denom.d, denom.n);
  return { expectedVisits: inv, expectedReward: meanReward.mul(inv) };
}

// dist/src/math/invariants.js
function refs2(e, out = /* @__PURE__ */ new Set()) {
  if ("ref" in e)
    out.add(e.ref);
  else if ("op" in e) {
    refs2(e.left, out);
    refs2(e.right, out);
  }
  return out;
}
function cbi(e) {
  return "const" in e && (typeof e.const === "bigint" || typeof e.const === "number") ? BigInt(e.const) : void 0;
}
function findScatterThreshold(mode) {
  for (const n of Object.values(mode.nodes))
    if (n.kind === "CONDITION" && "op" in n.expression && n.expression.op === ">=") {
      const l = "ref" in n.expression.left ? n.expression.left.ref : void 0, r = cbi(n.expression.right);
      if (l?.toLowerCase().includes("scatter") && r !== void 0)
        return { node: n, threshold: Number(r) };
    }
}
function awardMultiplier(mode) {
  const a = Object.values(mode.nodes).find((n) => n.kind === "AWARD");
  if (!a || a.kind !== "AWARD")
    return 0n;
  if ("ref" in a.amount)
    return 1n;
  if ("op" in a.amount && a.amount.op === "*") {
    const l = cbi(a.amount.left), r = cbi(a.amount.right);
    if (l !== void 0)
      return l;
    if (r !== void 0)
      return r;
  }
  throw new Error(`invariant analyzer: unsupported award expression in ${mode.id}`);
}
function detectAdditiveRegenerativeCounter(def, modeId) {
  const mode = def.modes[modeId];
  if (!mode)
    return void 0;
  const mutations = Object.values(mode.nodes).filter((n) => n.kind === "STATE" && n.op === "ADD" && cbi(n.value) !== void 0);
  const neg = mutations.filter((n) => cbi(n.value) < 0n);
  const pos = mutations.filter((n) => cbi(n.value) > 0n);
  if (neg.length !== 1 || pos.length < 1 || pos.some((n) => n.target !== neg[0].target))
    return void 0;
  const counter = neg[0].target, decrement = -cbi(neg[0].value);
  if (pos.length > 1) {
    if (decrement !== 1n || !hasAdditiveRegenerativeCounter(def, modeId))
      return void 0;
    return { kind: "ADDITIVE_REGENERATIVE_COUNTER", modeId, counter, decrement, retriggerIncrement: 0n, triggerProbability: new Rational(0n), expectedOffspring: new Rational(0n), meanReward: new Rational(0n), numericLegacyValid: false, reason: `${counter} is translation-invariant with multiple offspring increments; generic Event Graph regenerative execution required` };
  }
  const increment = cbi(pos[0].value);
  if (decrement !== 1n)
    return void 0;
  const stateRef = `$state.${counter}`;
  let terminationUses = 0;
  for (const n of Object.values(mode.nodes)) {
    if (n.kind === "CONDITION" && refs2(n.expression).has(stateRef)) {
      if ("op" in n.expression && n.expression.op === ">" && "ref" in n.expression.left && n.expression.left.ref === stateRef && cbi(n.expression.right) === 0n)
        terminationUses++;
      else
        return void 0;
    }
    if (n.kind === "AWARD" && refs2(n.amount).has(stateRef))
      return void 0;
    if (n.kind === "STATE" && n.target !== counter && refs2(n.value).has(stateRef))
      return void 0;
  }
  if (terminationUses !== 1)
    return void 0;
  const source = Object.values(mode.nodes).find((n) => n.kind === "SOURCE" && n.source.type === "REEL_SPIN");
  const pay = Object.values(mode.nodes).find((n) => n.kind === "EVALUATE" && n.evaluator.type === "PAYLINES");
  const trigger = findScatterThreshold(mode);
  if (!source || source.kind !== "SOURCE" || source.source.type !== "REEL_SPIN" || !pay || pay.kind !== "EVALUATE" || pay.evaluator.type !== "PAYLINES" || !trigger) {
    if (!hasAdditiveRegenerativeCounter(def, modeId))
      return void 0;
    return { kind: "ADDITIVE_REGENERATIVE_COUNTER", modeId, counter, decrement, retriggerIncrement: increment, triggerProbability: new Rational(0n), expectedOffspring: new Rational(0n), meanReward: new Rational(0n), numericLegacyValid: false, reason: `${counter} is translation-invariant (each visit consumes 1, trigger adds ${increment}); generic Event Graph regenerative execution required` };
  }
  const summary = exactSpinSummary(def, source.source.reelSetId, pay.evaluator.paytableId, pay.evaluator.paylineIds, source.source.rows, awardMultiplier(mode), trigger.threshold);
  const offspring = summary.triggerProbability.mul(new Rational(increment));
  return { kind: "ADDITIVE_REGENERATIVE_COUNTER", modeId, counter, decrement, retriggerIncrement: increment, triggerProbability: summary.triggerProbability, expectedOffspring: offspring, meanReward: summary.expectedLineWin, reason: `${counter} is translation-invariant for EV/duration: each visit consumes 1 and trigger adds ${increment}`, numericLegacyValid: true };
}
function hasAdditiveRegenerativeCounter(def, modeId) {
  const mode = def.modes[modeId];
  if (!mode)
    return false;
  const muts = Object.values(mode.nodes).filter((n) => n.kind === "STATE" && n.op === "ADD" && cbi(n.value) !== void 0);
  const neg = muts.filter((n) => cbi(n.value) < 0n), pos = muts.filter((n) => cbi(n.value) > 0n);
  if (neg.length !== 1 || pos.length < 1 || -cbi(neg[0].value) !== 1n)
    return false;
  const counter = neg[0].target;
  if (pos.some((n) => n.target !== counter))
    return false;
  const stateRef = `$state.${counter}`;
  let terminationUses = 0;
  for (const n of Object.values(mode.nodes)) {
    if (n.kind === "CONDITION" && refs2(n.expression).has(stateRef)) {
      if ("op" in n.expression && n.expression.op === ">" && "ref" in n.expression.left && n.expression.left.ref === stateRef && cbi(n.expression.right) === 0n)
        terminationUses++;
      else
        return false;
    }
    if (n.kind === "AWARD" && refs2(n.amount).has(stateRef))
      return false;
    if (n.kind === "STATE" && n.target !== counter && refs2(n.value).has(stateRef))
      return false;
  }
  return terminationUses === 1;
}

// dist/src/math/solverRegistry.js
var solverCapabilityRegistry = [
  { id: "symbolic-pgf", solver: "HYBRID", exact: true, requirements: ["PGF"], cyclic: true, partitioned: false, priority: 100 },
  { id: "regenerative", solver: "HYBRID", exact: true, requirements: ["REWARD", "DURATION", "ZERO_WIN", "PGF"], cyclic: true, partitioned: false, priority: 90 },
  { id: "state-exact-markov", solver: "MARKOV", exact: true, requirements: ["REWARD", "DURATION", "ZERO_WIN", "PGF"], cyclic: true, partitioned: false, priority: 80 },
  { id: "finite-enum", solver: "ENUM", exact: true, requirements: ["REWARD", "ENTRY_PROBABILITY", "ZERO_WIN", "PGF"], cyclic: false, partitioned: false, priority: 70 },
  { id: "finite-dp", solver: "DP", exact: true, requirements: ["DURATION"], cyclic: false, partitioned: false, priority: 70 },
  { id: "partitioned-hybrid", solver: "HYBRID", exact: false, requirements: ["REWARD", "DURATION", "ZERO_WIN", "PGF"], cyclic: true, partitioned: true, priority: 60 },
  { id: "monte-carlo", solver: "MC", exact: false, requirements: ["REWARD", "DURATION", "ENTRY_PROBABILITY", "ZERO_WIN", "PGF"], cyclic: true, partitioned: false, priority: 10 }
];
function modeHasCycle(mode) {
  const seen = /* @__PURE__ */ new Set(), stack = /* @__PURE__ */ new Set();
  const edges = (n) => n.kind === "CONDITION" ? [n.onTrue, n.onFalse] : n.kind === "FLOW" ? [] : n.next ? [n.next] : [];
  const dfs = (id) => {
    if (stack.has(id))
      return true;
    if (seen.has(id))
      return false;
    seen.add(id);
    stack.add(id);
    const n = mode.nodes[id];
    if (n) {
      for (const x of edges(n))
        if (dfs(x))
          return true;
    }
    stack.delete(id);
    return false;
  };
  return dfs(mode.entryNodeId);
}
function selectSolverCapability(def, q, registry = solverCapabilityRegistry) {
  const cyclic = Object.values(def.modes).some(modeHasCycle);
  const regenerative = Object.keys(def.modes).some((id) => hasAdditiveRegenerativeCounter(def, id));
  const candidates = registry.filter((c2) => c2.requirements.includes(q.backend) && (q.backend === "ENTRY_PROBABILITY" || (cyclic ? c2.cyclic : true)));
  let capability;
  if (q.backend === "ENTRY_PROBABILITY")
    capability = candidates.find((c2) => c2.id === "finite-enum");
  else if (q.backend === "PGF" && q.observables.length === 0)
    capability = candidates.find((c2) => c2.id === "symbolic-pgf");
  else if (regenerative)
    capability = candidates.find((c2) => c2.id === "regenerative");
  else if (cyclic)
    capability = candidates.find((c2) => c2.id === "state-exact-markov");
  else
    capability = candidates.find((c2) => c2.id === (q.backend === "DURATION" ? "finite-dp" : "finite-enum"));
  const custom = candidates.filter((c2) => !solverCapabilityRegistry.some((b) => b.id === c2.id) && !c2.partitioned).sort((a, b) => b.priority - a.priority)[0];
  if (custom && (!capability || custom.priority > capability.priority))
    capability = custom;
  capability ??= candidates.sort((a, b) => b.priority - a.priority)[0];
  if (!capability)
    throw new Error(`no solver capability for ${q.backend}`);
  return { capability, reason: `${capability.id} satisfies ${q.backend}${cyclic ? " on cyclic graph" : " on acyclic graph"}${regenerative ? " with recognized regenerative quotient" : ""}` };
}

// dist/src/math/planner.js
function exprRefs(e, out = /* @__PURE__ */ new Set()) {
  if ("ref" in e)
    out.add(e.ref);
  else if ("op" in e) {
    exprRefs(e.left, out);
    exprRefs(e.right, out);
  }
  return out;
}
function sourceCardinality(def, n) {
  if (n.source.type === "WEIGHTED_CHOICE")
    return BigInt(n.source.outcomes.filter((x) => x.weight > 0n).length);
  const rs = def.reelSets[n.source.reelSetId];
  if (!rs)
    throw new Error(`planner: missing reel set ${n.source.reelSetId}`);
  return rs.reels.reduce((p, r) => p * BigInt(r.symbols.length), 1n);
}
function sourceEstimates(def) {
  const r = {};
  for (const m of Object.values(def.modes))
    for (const n of Object.values(m.nodes))
      if (n.kind === "SOURCE")
        r[`${m.id}.${n.id}`] = sourceCardinality(def, n).toString();
  return r;
}
function persistentDependencies(def) {
  const out = /* @__PURE__ */ new Set();
  for (const m of Object.values(def.modes))
    for (const n of Object.values(m.nodes)) {
      const es = [];
      if (n.kind === "CONDITION")
        es.push(n.expression);
      if (n.kind === "AWARD")
        es.push(n.amount);
      if (n.kind === "STATE")
        es.push(n.value);
      for (const e of es)
        for (const r of exprRefs(e))
          if (r.startsWith("$state."))
            out.add(r.slice(7));
    }
  return out;
}
function invariants(def) {
  const a = [];
  for (const id of Object.keys(def.modes)) {
    const x = detectAdditiveRegenerativeCounter(def, id);
    if (x)
      a.push(x);
  }
  return a;
}
function syntheticFor(q) {
  switch (q.type) {
    case "VARIANCE":
      return ["rewardMoment1", "rewardMoment2"];
    case "HIT_RATE":
      return ["hasWon"];
    case "DISTRIBUTION":
      return ["payoutPGF"];
    case "FEATURE_FREQUENCY":
      return [`entered:${q.modeId}`];
    default:
      return [];
  }
}
function planMathQuery(def, query, options = {}) {
  const cq = options.compiled ?? compileMathQuery(query), selected = selectSolverCapability(def, cq, options.solverCapabilities), invs = invariants(def), deps = persistentDependencies(def);
  const useRegen = selected.capability.id === "regenerative" || selected.capability.id === "symbolic-pgf";
  const reductions = useRegen ? invs.map((i) => ({ kind: i.kind, scope: i.modeId, variable: i.counter, reason: i.reason })) : [];
  if (useRegen)
    for (const i of invs)
      deps.delete(i.counter);
  const stages = [{ id: selected.capability.id, solver: selected.capability.solver, scope: def.entryModeId, reason: selected.reason }];
  if (useRegen)
    for (const i of invs)
      stages.push({ id: `regen:${i.modeId}`, solver: "REGENERATIVE", scope: i.modeId, reason: `recognized ${i.kind} quotient over ${i.counter}` });
  const estimates = sourceEstimates(def), diagnostics = [`Capability registry selected ${selected.capability.id}: ${selected.reason}.`];
  if (Object.values(estimates).some((x) => BigInt(x) > 1000000n))
    diagnostics.push("Large raw SOURCE cardinality detected; aggregate equivalent outcomes before state expansion.");
  return { query, solver: selected.capability.solver, exact: selected.capability.exact, observables: cq.observables.length ? [...cq.observables] : cq.backend === "PGF" ? ["P(totalAward=x)"] : cq.backend === "ENTRY_PROBABILITY" && query.type === "FEATURE_FREQUENCY" ? [`entered:${query.modeId}`] : [], livePersistentState: [...deps].sort(), syntheticState: syntheticFor(query), reductions, stages, diagnostics, estimatedSourceOutcomes: estimates };
}

// dist/src/math/stateGraph.js
var StateSpaceLimitError = class extends Error {
  limit;
  discovered;
  constructor(limit, discovered) {
    super(`state-space limit exceeded (${limit}); discovered at least ${discovered} canonical states`);
    this.name = "StateSpaceLimitError";
    this.limit = limit;
    this.discovered = discovered;
  }
};
function buildReachableStateGraph(args) {
  const max = args.maxStates ?? 1e5;
  const initialKey = args.canonicalize(args.initial);
  const concrete = /* @__PURE__ */ new Map([[initialKey, args.initial]]);
  const queue = [initialKey];
  const states = {};
  while (queue.length) {
    const key = queue.shift();
    const state = concrete.get(key);
    if (args.isTerminal(state)) {
      states[key] = { key, terminal: true, transitions: [] };
      continue;
    }
    const merged = /* @__PURE__ */ new Map();
    for (const t of args.expand(state)) {
      if (t.probability.n < 0n)
        throw new Error(`negative transition probability from ${key}`);
      const to = args.canonicalize(t.state);
      const reward = t.reward ?? new Rational(0n);
      const old = merged.get(to) ?? { probability: new Rational(0n), rewardMass: new Rational(0n), rewardSecondMass: new Rational(0n), atoms: /* @__PURE__ */ new Map() };
      const atom = old.atoms.get(reward.toString());
      old.atoms.set(reward.toString(), { reward, mass: (atom?.mass ?? new Rational(0n)).add(t.probability) });
      merged.set(to, {
        probability: old.probability.add(t.probability),
        rewardMass: old.rewardMass.add(t.probability.mul(reward)),
        rewardSecondMass: old.rewardSecondMass.add(t.probability.mul(reward).mul(reward)),
        atoms: old.atoms
      });
      if (!concrete.has(to)) {
        if (concrete.size >= max)
          throw new StateSpaceLimitError(max, concrete.size + 1);
        concrete.set(to, t.state);
        queue.push(to);
      }
    }
    let total = new Rational(0n);
    const transitions = [];
    for (const [to, m] of merged) {
      total = total.add(m.probability);
      const meanReward = m.probability.n === 0n ? new Rational(0n) : m.rewardMass.div(m.probability);
      const rewardSecond = m.probability.n === 0n ? new Rational(0n) : m.rewardSecondMass.div(m.probability);
      transitions.push({ to, probability: m.probability, reward: meanReward, rewardSecond, rewardAtoms: [...m.atoms.values()].map((a) => ({ reward: a.reward, probability: m.probability.n === 0n ? new Rational(0n) : a.mass.div(m.probability) })) });
    }
    if (total.n !== total.d)
      throw new Error(`transition probabilities from ${key} sum to ${total}, expected 1`);
    states[key] = { key, terminal: false, transitions };
  }
  return { initialState: initialKey, states };
}

// dist/src/math/capabilities.js
function analyzeCapabilities(def, handlers = builtinNodeHandlers) {
  const nodes2 = {}, unsupported = [];
  for (const [mid, m] of Object.entries(def.modes))
    for (const [nid, n] of Object.entries(m.nodes)) {
      const h = handlers[n.kind];
      if (!h) {
        unsupported.push(`${mid}.${nid}: no node handler for ${n.kind}`);
        continue;
      }
      const c2 = h.capabilities(n);
      nodes2[`${mid}.${nid}`] = c2;
      if (c2.stochastic && !c2.enumerable)
        unsupported.push(`${mid}.${nid}: stochastic node is not enumerable`);
      if (h.stochasticBoundary && !h.expandExact)
        unsupported.push(`${mid}.${nid}: stochastic node has no exact boundary expander`);
      else if (!h.stochasticBoundary && !h.exact)
        unsupported.push(`${mid}.${nid}: no exact node handler`);
    }
  return { nodes: nodes2, exactCompatible: unsupported.length === 0, unsupported };
}

// dist/src/math/lowering.js
var MAX_RAW_REEL_BOARDS = 2e6;
var RawReelBoardLimitError = class extends StateSpaceLimitError {
  rawReelBoards = true;
};
var builtinSourceLowerers = {
  WEIGHTED_CHOICE: function* (def, node) {
    if (node.source.type !== "WEIGHTED_CHOICE")
      return;
    const total = node.source.outcomes.reduce((s, x) => s + x.weight, 0n);
    if (total <= 0n)
      throw new Error(`invalid weights at ${node.id}`);
    for (const x of node.source.outcomes)
      if (x.weight > 0n)
        yield { value: x.value, probability: new Rational(x.weight, total) };
  },
  REEL_SPIN: function* (def, node) {
    if (node.source.type !== "REEL_SPIN")
      return;
    const src = node.source, set = def.reelSets[src.reelSetId];
    if (!set)
      throw new Error(`missing reel set ${src.reelSetId}`);
    const windows = set.reels.map((r) => {
      const m = /* @__PURE__ */ new Map();
      for (let stop = 0; stop < r.symbols.length; stop++) {
        const symbols = Array.from({ length: src.rows }, (_, row) => r.symbols[(stop + row) % r.symbols.length]);
        const k = JSON.stringify(symbols), x = m.get(k);
        if (x)
          x.count++;
        else
          m.set(k, { symbols, count: 1n, stop });
      }
      return { length: BigInt(r.symbols.length), items: [...m.values()] };
    });
    const product = windows.reduce((n, w) => n * w.items.length, 1);
    if (product > MAX_RAW_REEL_BOARDS)
      throw new RawReelBoardLimitError(MAX_RAW_REEL_BOARDS, product);
    const chosen = new Array(windows.length);
    function* rec(col, weight) {
      if (col === windows.length) {
        let den = 1n;
        for (const w of windows)
          den *= w.length;
        const symbols = Array.from({ length: src.rows }, (_, row) => chosen.map((x) => x.symbols[row]));
        yield { value: { rows: src.rows, cols: windows.length, symbols, stops: chosen.map((x) => x.stop) }, probability: new Rational(weight, den) };
        return;
      }
      for (const x of windows[col].items) {
        chosen[col] = x;
        yield* rec(col + 1, weight * x.count);
      }
    }
    yield* rec(0, 1n);
  }
};
var builtinExactLowering = { sources: builtinSourceLowerers, evaluators: builtinEvaluatorHandlers };

// dist/src/math/reelObservableDistribution.js
function exactReelObservableDistribution(def, reelSetId, rows, descriptors) {
  const reelSet = def.reelSets[reelSetId];
  if (!reelSet)
    throw new Error(`Unknown reel set ${reelSetId}`);
  let frontier = /* @__PURE__ */ new Map();
  const initial = descriptors.map((d) => d.init(def));
  frontier.set(descriptors.map((d, i) => d.stateKey(initial[i])).join(""), { state: initial, weight: 1n });
  let denominator = 1n;
  for (let column = 0; column < reelSet.reels.length; column++) {
    const strip2 = reelSet.reels[column].symbols;
    const windows = /* @__PURE__ */ new Map();
    for (let stop = 0; stop < strip2.length; stop++) {
      const visible = Array.from({ length: rows }, (_, row) => strip2[(stop + row) % strip2.length]);
      const key = visible.join("");
      const old = windows.get(key);
      if (old)
        old.count += 1n;
      else
        windows.set(key, { visible, count: 1n });
    }
    denominator *= BigInt(strip2.length);
    const next = /* @__PURE__ */ new Map();
    for (const entry of frontier.values())
      for (const window of windows.values()) {
        const state = descriptors.map((d, i) => d.advance(entry.state[i], window.visible, column, def));
        const key = descriptors.map((d, i) => d.stateKey(state[i])).join("");
        const w = entry.weight * window.count;
        const old = next.get(key);
        if (old)
          old.weight += w;
        else
          next.set(key, { state, weight: w });
      }
    frontier = next;
  }
  const atoms = /* @__PURE__ */ new Map();
  for (const entry of frontier.values()) {
    const values = Object.fromEntries(descriptors.map((d, i) => [d.output, d.finish(entry.state[i], def)]));
    const key = JSON.stringify(values, (_k, v) => typeof v === "bigint" ? `${v}n` : v);
    const old = atoms.get(key);
    if (old)
      old.weight += entry.weight;
    else
      atoms.set(key, { values, weight: entry.weight });
  }
  return [...atoms.values()].map((a) => ({ values: a.values, probability: new Rational(a.weight, denominator) }));
}

// dist/src/math/sufficientProjection.js
function projectByDeterministicContinuation(args) {
  const grouped = /* @__PURE__ */ new Map();
  for (const atom of args.atoms) {
    const s = { modeId: args.boundary.modeId, nodeId: args.continuationNodeId, values: { ...args.boundary.values }, frame: args.inject(atom.value) };
    const r = runDeterministic(args.def, s, args.lowering, args.handlers);
    const atomReward = atom.reward ?? new Rational(0n), reward = atomReward.add(r.reward);
    const rewardByMode = { ...r.rewardByMode };
    if (atomReward.n !== 0n) {
      if (atomReward.d !== 1n)
        throw new Error("projection: non-integer atom reward cannot be attributed to a mode");
      rewardByMode[args.boundary.modeId] = (rewardByMode[args.boundary.modeId] ?? 0n) + atomReward.n;
    }
    const visitedModes = [...new Set(r.visitedModes)].sort();
    const byMode = Object.keys(rewardByMode).sort().map((k) => `${k}=${rewardByMode[k]}`).join(",");
    const key = `${canonicalExecutionState(r.state)}|reward=${reward.toString()}|visited=${visitedModes.join(",")}|byMode=${byMode}`;
    const old = grouped.get(key);
    if (old)
      old.probability = old.probability.add(atom.probability);
    else
      grouped.set(key, { representative: atom.value, state: r.state, probability: atom.probability, reward, visitedModes, rewardByMode });
  }
  return [...grouped.values()];
}

// dist/src/math/reelObservableRegistry.js
function lineStateKey(state) {
  if (!state.alive)
    return `$${state.paid ?? 0n}`;
  return state.target ? `${state.target}:${state.count}` : `:${state.first}:${state.count}`;
}
var linePay = (pays3, s) => {
  const target = s.target || s.first;
  return target ? pays3?.[target]?.[s.count] ?? 0n : 0n;
};
var countTagFactory = ({ node, boardAliases }) => {
  if (node?.kind !== "EVALUATE" || node.evaluator?.type !== "COUNT_TAG" || !boardAliases.has(node.evaluator.board))
    return;
  const tag = node.evaluator.tag;
  return {
    consumedNodeIds: [node.id],
    erasedFrameNames: [],
    descriptor: {
      key: `COUNT_TAG:${node.id}:${tag}`,
      output: node.output,
      init: () => 0,
      advance: (state, visibleColumn, _column, def) => state + visibleColumn.filter((symbol) => def.symbols[symbol]?.tags.includes(tag)).length,
      stateKey: (state) => String(state),
      finish: (state) => state
    }
  };
};
var paylinesFactory = ({ node, nodes: nodes2, boardAliases }) => {
  if (node?.kind !== "EVALUATE" || node.evaluator?.type !== "PAYLINES" || !boardAliases.has(node.evaluator.board))
    return;
  const sum = nodes2[node.next];
  if (sum?.kind !== "EVALUATE" || sum.evaluator?.type !== "SUM_WINS" || sum.evaluator.wins !== node.output)
    return;
  const paylineIds = node.evaluator.paylineIds;
  const paytableId = node.evaluator.paytableId;
  const wildTag = node.evaluator.wildTag ?? "WILD";
  return {
    consumedNodeIds: [node.id, sum.id],
    erasedFrameNames: [node.output],
    rewardCandidateOutput: sum.output,
    descriptor: {
      key: `PAYLINES:${node.id}:${sum.id}`,
      output: sum.output,
      init: () => paylineIds.map(() => ({ target: "", first: "", count: 0, alive: true })),
      advance: (states, visibleColumn, column, game2) => states.map((state, i) => {
        const line = game2.paylines[paylineIds[i]];
        const symbol = visibleColumn[line.rows[column]];
        if (!state.alive)
          return state;
        const first = state.first || symbol;
        const wild = game2.symbols[symbol]?.tags.includes(wildTag) ?? false;
        if (!state.target)
          return wild ? { target: "", first, count: state.count + 1, alive: true } : { target: symbol, first, count: state.count + 1, alive: true };
        if (symbol === state.target || wild)
          return { ...state, first, count: state.count + 1 };
        return { target: "", first: "", count: 0, alive: false, paid: linePay(game2.paytables[paytableId]?.pays, { ...state, first }) };
      }),
      stateKey: (states) => states.map(lineStateKey).join("|"),
      finish: (states, game2) => {
        const pays3 = game2.paytables[paytableId]?.pays;
        let payout = 0n;
        for (const state of states)
          payout += state.alive ? linePay(pays3, state) : state.paid ?? 0n;
        return payout;
      }
    }
  };
};
var BUILTIN_REEL_OBSERVATIONS = Object.freeze({ COUNT_TAG: countTagFactory, PAYLINES: paylinesFactory });
function builtinReelObservationRegistry() {
  return BUILTIN_REEL_OBSERVATIONS;
}
function claimReelObservation(registry, ctx) {
  const type = ctx.node?.evaluator?.type;
  return type ? registry[type]?.(ctx) : void 0;
}

// dist/src/math/reelDependencyAnalysis.js
function references(value, names) {
  if (typeof value === "string")
    return names.has(value);
  if (!value || typeof value !== "object")
    return false;
  if (Array.isArray(value))
    return value.some((x) => references(x, names));
  return Object.values(value).some((x) => references(x, names));
}
function successors(node) {
  if (!node)
    return [];
  if (node.kind === "CONDITION")
    return [node.onTrue, node.onFalse].filter(Boolean);
  if (node.kind === "FLOW")
    return [];
  return node.next ? [node.next] : [];
}
function isLiveDownstream(nodes2, start, erased, spinId) {
  const todo = [start], seen = /* @__PURE__ */ new Set();
  while (todo.length) {
    const id = todo.pop();
    if (seen.has(id))
      continue;
    seen.add(id);
    const node = nodes2[id];
    if (!node)
      continue;
    if (id === spinId)
      continue;
    if (references(node, erased))
      return true;
    todo.push(...successors(node));
  }
  return false;
}
function awardMultiplier2(amount, raw) {
  if (amount?.ref === raw)
    return 1n;
  if (amount?.op !== "*")
    return;
  const left = amount.left?.ref === raw, right = amount.right?.ref === raw;
  if (left === right)
    return;
  const k = left ? amount.right?.const : amount.left?.const;
  if (k === void 0 || typeof k !== "number" && typeof k !== "bigint")
    return;
  return BigInt(k);
}
function analyzeReelProjectionPlan(def, b, registry = builtinReelObservationRegistry()) {
  const mode = def.modes[b.modeId], nodes2 = mode.nodes, spin2 = nodes2[b.nodeId];
  if (spin2?.kind !== "SOURCE" || spin2.source?.type !== "REEL_SPIN")
    return;
  const boardAliases = /* @__PURE__ */ new Set([spin2.output]);
  const descriptors = [];
  const erased = /* @__PURE__ */ new Set([spin2.output]);
  let rawPayoutOutput, multiplier, n = nodes2[spin2.next];
  const consumed = /* @__PURE__ */ new Set();
  while (n && !consumed.has(n.id)) {
    if (n.kind === "TRANSFORM" && n.operation?.input && boardAliases.has(n.operation.input)) {
      consumed.add(n.id);
      boardAliases.add(n.output);
      erased.add(n.output);
      n = nodes2[n.next];
      continue;
    }
    if (n.kind === "EVALUATE" && references(n.evaluator, boardAliases)) {
      const claim = claimReelObservation(registry, { def, node: n, nodes: nodes2, boardAliases });
      if (!claim)
        return;
      if (claim.consumedNodeIds.some((id) => consumed.has(id)))
        return;
      if (claim.rewardCandidateOutput) {
        if (rawPayoutOutput && rawPayoutOutput !== claim.rewardCandidateOutput)
          return;
        rawPayoutOutput = claim.rewardCandidateOutput;
      }
      claim.consumedNodeIds.forEach((id) => consumed.add(id));
      claim.erasedFrameNames.forEach((name) => erased.add(name));
      descriptors.push(claim.descriptor);
      const tail = nodes2[claim.consumedNodeIds[claim.consumedNodeIds.length - 1]];
      n = nodes2[tail.next];
      continue;
    }
    if (rawPayoutOutput && multiplier === void 0 && n.kind === "AWARD") {
      const m = awardMultiplier2(n.amount, rawPayoutOutput);
      if (m === void 0)
        break;
      consumed.add(n.id);
      multiplier = m;
      n = nodes2[n.next];
      continue;
    }
    break;
  }
  if (!n || !rawPayoutOutput || multiplier === void 0 || descriptors.length === 0)
    return;
  for (const alias of boardAliases)
    erased.add(alias);
  if (isLiveDownstream(nodes2, n.id, erased, spin2.id))
    return;
  return { reelSetId: spin2.source.reelSetId, rows: spin2.source.rows, descriptors, rawPayoutOutput, awardMultiplier: multiplier, continuationNodeId: n.id };
}

// dist/src/math/reelOutcomeAggregation.js
var memo = /* @__PURE__ */ new WeakMap();
function memoFor(...keys) {
  let m = memo;
  for (let i = 0; i < 3; i++) {
    let n = m.get(keys[i]);
    if (!n) {
      n = /* @__PURE__ */ new WeakMap();
      m.set(keys[i], n);
    }
    m = n;
  }
  let leaf = m.get(keys[3]);
  if (!leaf) {
    leaf = /* @__PURE__ */ new Map();
    m.set(keys[3], leaf);
  }
  return leaf;
}
function tryExpandAggregatedReelBoundary(def, b, lowering, handlers, observations = builtinReelObservationRegistry()) {
  const cache3 = memoFor(def, lowering, handlers, observations), key = canonicalExecutionState(b);
  if (cache3.has(key))
    return cache3.get(key) ?? void 0;
  const r = expandUncached(def, b, lowering, handlers, observations);
  cache3.set(key, r ?? null);
  return r;
}
function expandUncached(def, b, lowering, handlers, observations) {
  const plan2 = analyzeReelProjectionPlan(def, b, observations);
  if (!plan2)
    return;
  const atoms = exactReelObservableDistribution(def, plan2.reelSetId, plan2.rows, plan2.descriptors);
  const projected = projectByDeterministicContinuation({
    def,
    boundary: b,
    continuationNodeId: plan2.continuationNodeId,
    lowering,
    handlers,
    atoms: atoms.map((x) => ({
      value: x.values,
      probability: x.probability,
      reward: new Rational(BigInt(x.values[plan2.rawPayoutOutput]) * plan2.awardMultiplier)
    })),
    inject: (values) => values
  });
  return projected.map((x) => ({ state: x.state, probability: x.probability, reward: x.reward, visitedModes: x.visitedModes, rewardByMode: x.rewardByMode }));
}

// dist/src/math/eventGraphCompiler.js
function cloneState(s) {
  return { modeId: s.modeId, nodeId: s.nodeId, values: { ...s.values }, frame: { ...s.frame }, terminal: s.terminal };
}
function runDeterministic(def, input, lowering = builtinExactLowering, handlers = builtinNodeHandlers) {
  const s = cloneState(input);
  let reward = 0n;
  const visitedModes = [s.modeId], rewardByMode = {};
  for (let guard = 0; guard < 1e4; guard++) {
    if (s.terminal)
      return { state: s, reward: new Rational(reward), visitedModes, rewardByMode };
    const node = def.modes[s.modeId].nodes[s.nodeId];
    if (!node)
      throw new Error(`missing node ${s.nodeId} in ${s.modeId}`);
    const h = handlers[node.kind];
    if (!h)
      throw new Error(`no node handler for ${node.kind}`);
    if (h.stochasticBoundary) {
      s.frame = {};
      return { state: s, reward: new Rational(reward), visitedModes, rewardByMode };
    }
    if (!h.exact)
      throw new Error(`no exact node handler for ${node.kind}`);
    const r = h.exact({ def, node, frame: s.frame, values: s.values, lowering });
    reward += r.reward ?? 0n;
    rewardByMode[s.modeId] = (rewardByMode[s.modeId] ?? 0n) + (r.reward ?? 0n);
    if (r.terminal) {
      s.terminal = true;
      s.nodeId = "@END";
      return { state: s, reward: new Rational(reward), visitedModes, rewardByMode };
    }
    let next = r.next;
    if (r.modeId) {
      s.modeId = r.modeId;
      visitedModes.push(s.modeId);
      next = def.modes[s.modeId].entryNodeId;
    }
    if (r.clearFrame)
      s.frame = {};
    if (!next)
      throw new Error(`node ${node.id} has no next`);
    s.nodeId = next;
  }
  throw new Error("exact deterministic execution guard exceeded");
}
function stable(v) {
  if (typeof v === "bigint")
    return `#${v}`;
  if (Array.isArray(v))
    return `[${v.map(stable).join(",")}]`;
  if (v && typeof v === "object")
    return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + stable(v[k])).join(",")}}`;
  return JSON.stringify(v);
}
function canonicalExecutionState(s) {
  if (s.terminal)
    return "@TERMINAL";
  return stable({ modeId: s.modeId, nodeId: s.nodeId, values: s.values, frame: s.frame, terminal: false });
}
function initialExactBoundary(def, lowering = builtinExactLowering, handlers = builtinNodeHandlers) {
  return runDeterministic(def, { modeId: def.entryModeId, nodeId: def.modes[def.entryModeId].entryNodeId, values: {}, frame: {} }, lowering, handlers).state;
}
function expandExactBoundary(def, boundary, lowering = builtinExactLowering, handlers = builtinNodeHandlers) {
  if (boundary.terminal)
    return [];
  const node = def.modes[boundary.modeId].nodes[boundary.nodeId];
  const handler2 = handlers[node.kind];
  if (!handler2?.stochasticBoundary)
    throw new Error(`expected stochastic boundary, got ${node.kind}`);
  if (!handler2.expandExact)
    throw new Error(`stochastic node ${node.kind} has no exact boundary expander`);
  const out = [];
  for (const o of handler2.expandExact({ def, node, modeId: boundary.modeId, frame: { ...boundary.frame }, values: { ...boundary.values }, lowering })) {
    const s = cloneState(boundary);
    s.frame = o.frame ?? s.frame;
    s.values = o.values ?? s.values;
    if (o.terminal) {
      s.terminal = true;
      s.nodeId = "@END";
      out.push({ state: s, probability: o.probability, reward: new Rational(o.reward ?? 0n), visitedModes: [s.modeId], rewardByMode: { [s.modeId]: o.reward ?? 0n } });
      continue;
    }
    if (o.modeId) {
      s.modeId = o.modeId;
      s.nodeId = def.modes[s.modeId].entryNodeId;
    } else {
      const next = o.next ?? node.next;
      if (!next)
        throw new Error(`stochastic node ${node.id} has no next`);
      s.nodeId = next;
    }
    if (o.clearFrame)
      s.frame = {};
    const r = runDeterministic(def, s, lowering, handlers);
    out.push({ state: r.state, probability: o.probability, reward: new Rational(o.reward ?? 0n).add(r.reward), visitedModes: r.visitedModes, rewardByMode: { ...r.rewardByMode, [boundary.modeId]: (r.rewardByMode[boundary.modeId] ?? 0n) + (o.reward ?? 0n) } });
  }
  return out;
}
function compileEventGraphToStateIR(def, opts = {}) {
  const handlers = opts.handlers ?? builtinNodeHandlers;
  const capabilities = analyzeCapabilities(def, handlers);
  if (!capabilities.exactCompatible)
    throw new Error(`definition is not exact-compatible: ${capabilities.unsupported.join("; ")}`);
  const lowering = opts.lowering ?? builtinExactLowering, observations = opts.reelObservations ?? builtinReelObservationRegistry();
  const start = runDeterministic(def, { modeId: def.entryModeId, nodeId: def.modes[def.entryModeId].entryNodeId, values: {}, frame: {} }, lowering, handlers);
  return { ...buildReachableStateGraph({ initial: start.state, canonicalize: canonicalExecutionState, isTerminal: (s) => !!s.terminal, maxStates: opts.maxStates ?? 1e5, expand: (boundary) => {
    if (boundary.terminal)
      return [];
    const agg = tryExpandAggregatedReelBoundary(def, boundary, lowering, handlers, observations);
    return agg ?? expandExactBoundary(def, boundary, lowering, handlers);
  } }), initialReward: start.reward };
}

// dist/src/math/costPlanner.js
var defaultSolverBudget = { maxStates: 1e5, mcSamples: 1e5 };
function tryCompileStateGraph(def, budget = defaultSolverBudget, deps = {}) {
  try {
    const graph = compileEventGraphToStateIR(def, { maxStates: budget.maxStates, ...deps });
    return { kind: "EXACT", graph, states: Object.keys(graph.states).length };
  } catch (e) {
    if (e instanceof StateSpaceLimitError)
      return e.rawReelBoards ? { kind: "OVER_BUDGET", limit: e.limit, discovered: e.discovered, rawReelBoards: true, reason: `raw reel-board enumeration of ${e.discovered} windows exceeds ${e.limit} and no aggregated reel observation applies` } : { kind: "OVER_BUDGET", limit: e.limit, discovered: e.discovered, reason: `canonical state expansion exceeded budget ${e.limit} (discovered at least ${e.discovered})` };
    throw e;
  }
}

// dist/src/math/executionPlanner.js
function buildExecutionPlan(def, query, o = {}) {
  const queryIR = o.compiledQuery ?? compileMathQuery(query, { pgfZ: o.pgfZ });
  let math = planMathQuery(def, query, { compiled: queryIR, solverCapabilities: o.solverCapabilities });
  const budget = { maxStates: o.maxStates ?? defaultSolverBudget.maxStates, mcSamples: o.mcSamples ?? defaultSolverBudget.mcSamples };
  if (query.type === "EXPECTED_DURATION" && query.modeId) {
    const regen = hasAdditiveRegenerativeCounter(def, query.modeId);
    return { math: { ...math, solver: regen ? "HYBRID" : "MARKOV", exact: true, diagnostics: [...math.diagnostics, regen ? "Mode-specific duration uses the regenerative solver." : "Mode-specific stochastic duration uses an augmented finite state graph."] }, queryIR, budget, decision: { kind: "DIRECT" } };
  }
  if (math.solver === "MC")
    return { math, queryIR, budget, decision: { kind: "MONTE_CARLO", reason: "selected Monte Carlo solver capability" } };
  if (query.type === "FEATURE_FREQUENCY" && !Object.keys(def.modes).some((id) => hasAdditiveRegenerativeCounter(def, id)))
    return { math: { ...math, solver: "MARKOV", exact: true, stages: [...math.stages, { id: "mode-entry-state", solver: "MARKOV", scope: query.modeId, reason: "track mode visits in the reachable state graph" }], diagnostics: [...math.diagnostics, "Mode entry uses an augmented finite state graph."] }, queryIR, budget, decision: { kind: "DIRECT" } };
  const regenerative = Object.keys(def.modes).some((id) => hasAdditiveRegenerativeCounter(def, id));
  const genericFinite = !regenerative && (queryIR.backend === "REWARD" || queryIR.backend === "DURATION" || queryIR.backend === "ZERO_WIN" || queryIR.backend === "PGF");
  if (math.solver !== "MARKOV" && !genericFinite)
    return { math, queryIR, budget, decision: { kind: "DIRECT" } };
  const attempt = tryCompileStateGraph(def, budget, { lowering: o.lowering, handlers: o.handlers, reelObservations: o.reelObservations });
  if (attempt.kind === "EXACT") {
    math = { ...math, solver: math.solver === "HYBRID" ? "MARKOV" : math.solver, diagnostics: [...math.diagnostics, `Cost gate accepted exact state graph: ${attempt.states}/${budget.maxStates} canonical states.`] };
    return { math, queryIR, budget, decision: { kind: "STATE_EXACT", graph: attempt.graph, states: attempt.states } };
  }
  if (queryIR.partitionable && queryIR.observables.length && !attempt.rawReelBoards) {
    math = { ...math, solver: "HYBRID", exact: false, stages: [...math.stages, { id: "query-observable-boundary", solver: "MC", scope: def.entryModeId, reason: `sample ${queryIR.observables.join(", ")} only beyond exact cut boundaries` }], diagnostics: [...math.diagnostics, `Exact STATE_EXACT exceeded budget: ${attempt.reason}. Partitioned model selected; exact prefix retained.`] };
    return { math, queryIR, budget, decision: { kind: "PARTITIONED_HYBRID", reason: attempt.reason } };
  }
  math = { ...math, solver: "MC", exact: false, stages: [...math.stages, { id: "budget-fallback", solver: "MC", scope: def.entryModeId, reason: attempt.reason }], diagnostics: [...math.diagnostics, `Exact STATE_EXACT rejected by cost gate: ${attempt.reason}; no partitionable observable boundary is available.`] };
  return { math, queryIR, budget, decision: { kind: "MONTE_CARLO", reason: attempt.reason } };
}

// dist/src/math/compiler.js
function constantBigInt(e) {
  if ("const" in e && (typeof e.const === "bigint" || typeof e.const === "number"))
    return BigInt(e.const);
  return void 0;
}
function refName(e) {
  return "ref" in e ? e.ref : void 0;
}
function walk(mode, start = mode.entryNodeId, limit = 1e3) {
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  let id = start;
  while (id && out.length < limit && !seen.has(id)) {
    seen.add(id);
    const n = mode.nodes[id];
    if (!n)
      throw new Error(`missing node ${id} in ${mode.id}`);
    out.push(n);
    if (n.kind === "CONDITION")
      id = n.onFalse;
    else if (n.kind === "FLOW" && n.operation.type === "ENTER_MODE")
      break;
    else
      id = n.next;
  }
  return out;
}
function findReelSpin(mode) {
  const n = Object.values(mode.nodes).find((x) => x.kind === "SOURCE" && x.source.type === "REEL_SPIN");
  if (!n)
    throw new Error(`math compiler: mode ${mode.id} has no REEL_SPIN`);
  return n;
}
function findPaylineEval(mode) {
  const n = Object.values(mode.nodes).find((x) => x.kind === "EVALUATE" && x.evaluator.type === "PAYLINES");
  if (!n || n.evaluator.type !== "PAYLINES")
    throw new Error(`math compiler: mode ${mode.id} has no PAYLINES evaluator`);
  return n;
}
function awardMultiplier3(mode) {
  const award2 = Object.values(mode.nodes).find((x) => x.kind === "AWARD");
  if (!award2)
    return 0n;
  const a = award2.amount;
  if ("ref" in a)
    return 1n;
  if ("op" in a && a.op === "*") {
    const l = constantBigInt(a.left), r = constantBigInt(a.right);
    if (l !== void 0)
      return l;
    if (r !== void 0)
      return r;
  }
  throw new Error(`math compiler: unsupported award expression in ${mode.id}`);
}
function triggerCondition(mode) {
  for (const n of Object.values(mode.nodes))
    if (n.kind === "CONDITION" && "op" in n.expression && n.expression.op === ">=") {
      const l = refName(n.expression.left), r = constantBigInt(n.expression.right);
      if (l?.toLowerCase().includes("scatter") && r !== void 0)
        return { node: n, threshold: Number(r) };
    }
  return void 0;
}
function compileSpin(def, mode) {
  const source = findReelSpin(mode);
  if (source.source.type !== "REEL_SPIN")
    throw new Error("unreachable");
  const pay = findPaylineEval(mode);
  const trigger = triggerCondition(mode);
  const multiplier = awardMultiplier3(mode);
  const summary = exactSpinSummary(def, source.source.reelSetId, pay.evaluator.paytableId, pay.evaluator.paylineIds, source.source.rows, multiplier, trigger?.threshold ?? Number.MAX_SAFE_INTEGER);
  return { modeId: mode.id, expectedReward: summary.expectedLineWin, triggerProbability: trigger ? summary.triggerProbability : new Rational(0n), triggerConditionNodeId: trigger?.node.id };
}
function branchNodes(mode, start) {
  return walk(mode, start);
}
function stateConstant(nodes2, op, target) {
  return nodes2.find((n) => n.kind === "STATE" && n.op === op && (!target || n.target === target) && constantBigInt(n.value) !== void 0);
}
function enteredMode(nodes2) {
  return nodes2.find((n) => n.kind === "FLOW" && n.operation.type === "ENTER_MODE")?.kind === "FLOW" ? nodes2.find((n) => n.kind === "FLOW" && n.operation.type === "ENTER_MODE").operation.modeId : void 0;
}
function compileExpectedValueIR(def) {
  const spins = {};
  for (const m of Object.values(def.modes))
    spins[m.id] = compileSpin(def, m);
  const entry = def.modes[def.entryModeId];
  const entryTrigger = triggerCondition(entry);
  let entryFeature;
  if (entryTrigger) {
    const yes = branchNodes(entry, entryTrigger.node.onTrue);
    const set = stateConstant(yes, "SET");
    const to = enteredMode(yes);
    if (set && to) {
      const amount = constantBigInt(set.value);
      entryFeature = { fromModeId: entry.id, toModeId: to, triggerProbability: spins[entry.id].triggerProbability, initialSpins: amount };
    }
  }
  const regenerativeFeatures = {};
  for (const m of Object.values(def.modes)) {
    if (m.id === def.entryModeId)
      continue;
    const trig = triggerCondition(m);
    if (!trig)
      continue;
    const yes = branchNodes(m, trig.node.onTrue);
    const add3 = yes.find((n) => n.kind === "STATE" && n.op === "ADD" && constantBigInt(n.value) !== void 0 && constantBigInt(n.value) > 0n);
    const all = Object.values(m.nodes);
    const dec = all.find((n) => n.kind === "STATE" && n.op === "ADD" && constantBigInt(n.value) < 0n);
    if (add3 && dec)
      regenerativeFeatures[m.id] = { modeId: m.id, spin: spins[m.id], retriggerAward: constantBigInt(add3.value), decrement: -constantBigInt(dec.value) };
  }
  return { entryModeId: def.entryModeId, spins, entryFeature, regenerativeFeatures };
}
function compileSpinMoments(def, mode) {
  const source = findReelSpin(mode);
  if (source.source.type !== "REEL_SPIN")
    throw new Error("unreachable");
  const pay = findPaylineEval(mode), trigger = triggerCondition(mode), multiplier = awardMultiplier3(mode);
  const x = exactSpinMoments(def, source.source.reelSetId, pay.evaluator.paytableId, pay.evaluator.paylineIds, source.source.rows, multiplier, trigger?.threshold ?? Number.MAX_SAFE_INTEGER);
  return { modeId: mode.id, expectedReward: x.expectedLineWin, triggerProbability: trigger ? x.triggerProbability : new Rational(0n), triggerConditionNodeId: trigger?.node.id, rewardSecond: x.rewardSecond, rewardTimesTrigger: trigger ? x.rewardTimesTrigger : new Rational(0n) };
}
function compileMomentIR(def) {
  const ev = compileExpectedValueIR(def), spins = {};
  for (const m of Object.values(def.modes))
    spins[m.id] = compileSpinMoments(def, m);
  return { ...ev, spins };
}

// dist/src/math/solver.js
function solveExpectedValueIR(ir) {
  const base3 = ir.spins[ir.entryModeId];
  if (!base3)
    throw new Error("missing entry spin IR");
  if (!ir.entryFeature)
    return { baseEV: base3.expectedReward, featureTriggerProbability: new Rational(0n), featureEV: new Rational(0n), expectedFeatureSpins: new Rational(0n), totalEV: base3.expectedReward };
  const link = ir.entryFeature, feature = ir.regenerativeFeatures[link.toModeId];
  if (!feature)
    throw new Error(`feature ${link.toModeId} is not a supported regenerative feature`);
  if (feature.decrement !== 1n)
    throw new Error(`unsupported feature decrement ${feature.decrement}`);
  const offspring = feature.spin.triggerProbability.mul(new Rational(feature.retriggerAward));
  const one = solveRegenerative(feature.spin.expectedReward, offspring);
  const initial = new Rational(link.initialSpins);
  const featureEV = one.expectedReward.mul(initial), expectedFeatureSpins = one.expectedVisits.mul(initial);
  return { baseEV: base3.expectedReward, featureTriggerProbability: link.triggerProbability, featureEV, expectedFeatureSpins, totalEV: base3.expectedReward.add(link.triggerProbability.mul(featureEV)) };
}

// dist/src/math/moments.js
var ZERO2 = new Rational(0n);
var ONE2 = new Rational(1n);
function solveRegenerativeMoments(x) {
  if (x.expectedOffspring.n >= x.expectedOffspring.d)
    throw new Error(`non-terminating/divergent regenerative process: offspring=${x.expectedOffspring}`);
  const denom = ONE2.sub(x.expectedOffspring);
  const mean2 = x.rewardMean.div(denom);
  const second2 = x.rewardSecond.add(new Rational(2n).mul(x.rewardOffspring).mul(mean2)).add(x.offspringFactorial2.mul(mean2).mul(mean2)).div(denom);
  return { expectedVisits: ONE2.div(denom), mean: mean2, second: second2, variance: second2.sub(mean2.mul(mean2)) };
}
function iidSumMoments(one, n) {
  if (n < 0n)
    throw new Error("negative iid count");
  const N = new Rational(n), pairs = new Rational(n * (n - 1n));
  const mean2 = N.mul(one.mean);
  const second2 = N.mul(one.second).add(pairs.mul(one.mean).mul(one.mean));
  return { mean: mean2, second: second2, variance: second2.sub(mean2.mul(mean2)) };
}

// dist/src/math/momentSolver.js
function solveMomentIR(ir) {
  const base3 = ir.spins[ir.entryModeId];
  if (!base3)
    throw new Error("missing entry spin IR");
  if (!ir.entryFeature) {
    const variance = base3.rewardSecond.sub(base3.expectedReward.mul(base3.expectedReward));
    return { mean: base3.expectedReward, second: base3.rewardSecond, variance, featureMean: new Rational(0n), featureSecond: new Rational(0n) };
  }
  const link = ir.entryFeature, feature = ir.regenerativeFeatures[link.toModeId], spin2 = ir.spins[link.toModeId];
  if (!feature || !spin2)
    throw new Error(`feature ${link.toModeId} is not a supported regenerative feature`);
  if (feature.decrement !== 1n)
    throw new Error(`unsupported feature decrement ${feature.decrement}`);
  const c2 = feature.retriggerAward, C = new Rational(c2), p = spin2.triggerProbability;
  const one = solveRegenerativeMoments({ rewardMean: spin2.expectedReward, rewardSecond: spin2.rewardSecond, expectedOffspring: p.mul(C), rewardOffspring: spin2.rewardTimesTrigger.mul(C), offspringFactorial2: p.mul(new Rational(c2 * (c2 - 1n))) });
  const totalFeature = iidSumMoments(one, link.initialSpins);
  const mean2 = base3.expectedReward.add(link.triggerProbability.mul(totalFeature.mean));
  const second2 = base3.rewardSecond.add(new Rational(2n).mul(base3.rewardTimesTrigger).mul(totalFeature.mean)).add(link.triggerProbability.mul(totalFeature.second));
  return { mean: mean2, second: second2, variance: second2.sub(mean2.mul(mean2)), featureMean: totalFeature.mean, featureSecond: totalFeature.second };
}

// dist/src/math/hitRate.js
function solveExactHitRate(def, tolerance = 1e-15, maxIterations = 1e4) {
  const ir = compileExpectedValueIR(def), link = ir.entryFeature;
  const lineIds = Object.keys(def.paylines);
  const baseMode = def.modes[def.entryModeId];
  const baseSource = Object.values(baseMode.nodes).find((n) => n.kind === "SOURCE" && n.source.type === "REEL_SPIN");
  const basePay = Object.values(baseMode.nodes).find((n) => n.kind === "EVALUATE" && n.evaluator.type === "PAYLINES");
  if (!baseSource || baseSource.kind !== "SOURCE" || baseSource.source.type !== "REEL_SPIN" || !basePay || basePay.kind !== "EVALUATE" || basePay.evaluator.type !== "PAYLINES")
    throw new Error("hit rate: unsupported entry mode");
  const base3 = exactSpinHitSummary(def, baseSource.source.reelSetId, basePay.evaluator.paytableId, basePay.evaluator.paylineIds, baseSource.source.rows, 3);
  if (!link) {
    const miss2 = base3.zeroAndNoTriggerProbability.add(base3.zeroAndTriggerProbability).toNumber();
    return { hitRate: 1 - miss2, missRate: miss2, featureZeroProbability: 1, fixedPointResidual: 0, iterations: 0 };
  }
  const feature = ir.regenerativeFeatures[link.toModeId];
  if (!feature)
    throw new Error(`hit rate: feature ${link.toModeId} is not regenerative`);
  const fm = def.modes[link.toModeId], fs2 = Object.values(fm.nodes).find((n) => n.kind === "SOURCE" && n.source.type === "REEL_SPIN"), fp = Object.values(fm.nodes).find((n) => n.kind === "EVALUATE" && n.evaluator.type === "PAYLINES");
  if (!fs2 || fs2.kind !== "SOURCE" || fs2.source.type !== "REEL_SPIN" || !fp || fp.kind !== "EVALUATE" || fp.evaluator.type !== "PAYLINES")
    throw new Error("hit rate: unsupported feature mode");
  const h = exactSpinHitSummary(def, fs2.source.reelSetId, fp.evaluator.paytableId, fp.evaluator.paylineIds, fs2.source.rows, 3);
  const q0 = h.zeroAndNoTriggerProbability.toNumber(), qt = h.zeroAndTriggerProbability.toNumber(), k = Number(feature.retriggerAward);
  let z = 0, iterations = 0;
  for (; iterations < maxIterations; iterations++) {
    const nz = q0 + qt * Math.pow(z, k);
    if (Math.abs(nz - z) <= tolerance) {
      z = nz;
      break;
    }
    z = nz;
  }
  if (iterations === maxIterations)
    throw new Error("hit rate fixed point did not converge");
  const residual = Math.abs(z - (q0 + qt * Math.pow(z, k))), featureZero = Math.pow(z, Number(link.initialSpins));
  const miss = base3.zeroAndNoTriggerProbability.toNumber() + base3.zeroAndTriggerProbability.toNumber() * featureZero;
  return { hitRate: 1 - miss, missRate: miss, featureZeroProbability: featureZero, fixedPointResidual: residual, iterations };
}

// dist/src/math/pgf.js
var Z = new Rational(0n);
var O = new Rational(1n);
function add(m, k, p) {
  m.set(k, (m.get(k) ?? Z).add(p));
}
function split(atoms) {
  const no = /* @__PURE__ */ new Map(), yes = /* @__PURE__ */ new Map();
  for (const a of atoms)
    add(a.trigger ? yes : no, a.payout, a.probability);
  return { no, yes };
}
function modeAtoms(def, modeId, threshold = 3) {
  const m = def.modes[modeId], src = Object.values(m.nodes).find((n) => n.kind === "SOURCE" && n.source.type === "REEL_SPIN"), pay = Object.values(m.nodes).find((n) => n.kind === "EVALUATE" && n.evaluator.type === "PAYLINES"), award2 = Object.values(m.nodes).find((n) => n.kind === "AWARD");
  if (!src || src.kind !== "SOURCE" || src.source.type !== "REEL_SPIN" || !pay || pay.kind !== "EVALUATE" || pay.evaluator.type !== "PAYLINES")
    throw new Error(`pgf: unsupported mode ${modeId}`);
  let mult = 1n;
  if (award2 && award2.kind === "AWARD" && "op" in award2.amount && award2.amount.op === "*") {
    const c2 = "const" in award2.amount.left ? award2.amount.left.const : "const" in award2.amount.right ? award2.amount.right.const : 1;
    mult = BigInt(c2);
  }
  return exactSpinPayoutTriggerDistribution(def, src.source.reelSetId, pay.evaluator.paytableId, pay.evaluator.paylineIds, src.source.rows, mult, threshold);
}
function compilePaidGamePGF(def) {
  const ir = compileExpectedValueIR(def), base3 = split(modeAtoms(def, def.entryModeId));
  if (!ir.entryFeature)
    return { kind: "PAID_GAME_PGF", baseNonTrigger: base3.no, baseTrigger: base3.yes, initialFeatureSpins: 0n, equation: "G(z)=C(z)+D(z)" };
  const link = ir.entryFeature, regen = ir.regenerativeFeatures[link.toModeId];
  if (!regen)
    throw new Error("pgf: feature is not regenerative");
  const f = split(modeAtoms(def, link.toModeId));
  const feature = { kind: "REGENERATIVE_PGF", nonTrigger: f.no, trigger: f.yes, offspringOnTrigger: regen.retriggerAward, equation: `F(z)=A(z)+B(z)*F(z)^${regen.retriggerAward}` };
  return { kind: "PAID_GAME_PGF", baseNonTrigger: base3.no, baseTrigger: base3.yes, initialFeatureSpins: link.initialSpins, feature, equation: `G(z)=C(z)+D(z)*F(z)^${link.initialSpins}` };
}
function evalPolynomial(p, z) {
  let s = 0;
  for (const [k, v] of p)
    s += v.toNumber() * Math.pow(z, Number(k));
  return s;
}
function evaluateFeaturePGF(p, z, tolerance = 1e-14, maxIterations = 1e5) {
  if (z < 0 || z > 1)
    throw new Error("PGF evaluation currently requires 0<=z<=1");
  const a = evalPolynomial(p.nonTrigger, z), b = evalPolynomial(p.trigger, z), k = Number(p.offspringOnTrigger);
  let f = 0, it = 0;
  for (; it < maxIterations; it++) {
    const n = a + b * Math.pow(f, k);
    if (Math.abs(n - f) <= tolerance) {
      f = n;
      break;
    }
    f = n;
  }
  if (it === maxIterations)
    throw new Error("PGF fixed point did not converge");
  return { value: f, iterations: it, residual: Math.abs(f - (a + b * Math.pow(f, k))) };
}
function evaluatePaidGamePGF(p, z, tolerance = 1e-14) {
  const c2 = evalPolynomial(p.baseNonTrigger, z), d = evalPolynomial(p.baseTrigger, z);
  if (!p.feature)
    return { value: c2 + d, featureValue: 1, residual: 0 };
  const f = evaluateFeaturePGF(p.feature, z, tolerance);
  return { value: c2 + d * Math.pow(f.value, Number(p.initialFeatureSpins)), featureValue: f.value, residual: f.residual };
}

// dist/src/math/finiteMarkov.js
function solveLinear(a, b) {
  const n = a.length;
  const m = a.map((row, i) => [...row, b[i]]);
  for (let col = 0; col < n; col++) {
    let pivot = col;
    while (pivot < n && m[pivot][col].n === 0n)
      pivot++;
    if (pivot === n)
      throw new Error("singular Markov system: model may be non-terminating or states are not independent");
    [m[col], m[pivot]] = [m[pivot], m[col]];
    const d = m[col][col];
    for (let j = col; j <= n; j++)
      m[col][j] = m[col][j].div(d);
    for (let i = 0; i < n; i++)
      if (i !== col && m[i][col].n !== 0n) {
        const f = m[i][col];
        for (let j = col; j <= n; j++)
          m[i][j] = m[i][j].sub(f.mul(m[col][j]));
      }
  }
  return m.map((row) => row[n]);
}
function solveFiniteMarkov(ir) {
  const transient = Object.values(ir.states).filter((s) => !s.terminal);
  const terminals = Object.values(ir.states).filter((s) => s.terminal);
  const index = new Map(transient.map((s, i) => [s.key, i]));
  const n = transient.length;
  const A = Array.from({ length: n }, (_, i) => Array.from({ length: n }, (_2, j) => new Rational(i === j ? 1n : 0n)));
  const reward = Array.from({ length: n }, () => new Rational(0n));
  const steps2 = Array.from({ length: n }, () => new Rational(1n));
  for (let i = 0; i < n; i++) {
    const s = transient[i];
    for (const t of s.transitions) {
      reward[i] = reward[i].add(t.probability.mul(t.reward));
      const j = index.get(t.to);
      if (j !== void 0)
        A[i][j] = A[i][j].sub(t.probability);
      else if (!ir.states[t.to]?.terminal)
        throw new Error(`transition to missing state ${t.to}`);
    }
  }
  const ev = solveLinear(A, reward);
  const duration = solveLinear(A, steps2);
  const rhs2 = Array.from({ length: n }, () => new Rational(0n));
  for (let i = 0; i < n; i++)
    for (const t of transient[i].transitions) {
      const j = index.get(t.to), future = j === void 0 ? new Rational(0n) : ev[j];
      rhs2[i] = rhs2[i].add(t.probability.mul(t.rewardSecond.add(new Rational(2n).mul(t.reward).mul(future))));
    }
  const second2 = solveLinear(A, rhs2);
  const byState = {};
  transient.forEach((s, i) => byState[s.key] = { expectedReward: ev[i], expectedSteps: duration[i], rewardSecond: second2[i], rewardVariance: second2[i].sub(ev[i].mul(ev[i])) });
  terminals.forEach((s) => byState[s.key] = { expectedReward: new Rational(0n), expectedSteps: new Rational(0n), rewardSecond: new Rational(0n), rewardVariance: new Rational(0n) });
  const root = byState[ir.initialState];
  if (!root)
    throw new Error(`missing initial state ${ir.initialState}`);
  const r = ir.initialReward ?? new Rational(0n), initial = { ...root, expectedReward: root.expectedReward.add(r), rewardSecond: root.rewardSecond.add(new Rational(2n).mul(r).mul(root.expectedReward)).add(r.mul(r)) };
  return { initial, byState, transientStates: n, terminalStates: terminals.length };
}

// dist/src/math/genericRegenerative.js
function c(e) {
  return "const" in e && (typeof e.const === "number" || typeof e.const === "bigint") ? BigInt(e.const) : void 0;
}
function featureCounter(def, modeId) {
  const m = def.modes[modeId], adds = Object.values(m.nodes).filter((n) => n.kind === "STATE" && n.op === "ADD" && c(n.value) !== void 0);
  const dec = adds.find((n) => c(n.value) === -1n);
  if (!dec)
    return;
  const counter = dec.target;
  for (const n of Object.values(m.nodes))
    if (n.kind === "STATE" && n.target === counter && n.op === "ADD" && c(n.value) > 0n)
      return { counter };
  return { counter };
}
function add2(a, b) {
  return a.add(b);
}
var cache = /* @__PURE__ */ new WeakMap();
function solveGenericRegenerative(def, opts = {}) {
  const lowering = opts.lowering ?? builtinExactLowering, handlers = opts.handlers ?? builtinNodeHandlers, observations = opts.reelObservations ?? builtinReelObservationRegistry();
  const cached = cache.get(def)?.get(handlers)?.get(lowering)?.get(observations);
  if (cached)
    return cached;
  const expand2 = (b) => tryExpandAggregatedReelBoundary(def, b, lowering, handlers, observations) ?? expandExactBoundary(def, b, lowering, handlers);
  const entry = initialExactBoundary(def, lowering, handlers);
  const base3 = expand2(entry);
  const featureModes = [...new Set(base3.filter((x) => !x.state.terminal && x.state.modeId !== def.entryModeId).map((x) => x.state.modeId))];
  if (featureModes.length !== 1)
    throw new Error(`generic regenerative solver expected one entered feature mode, got ${featureModes.length}`);
  const fm = featureModes[0], inv = featureCounter(def, fm);
  if (!inv)
    throw new Error(`generic regenerative solver: no additive work counter in ${fm}`);
  const fs0 = runDeterministic(def, { modeId: fm, nodeId: def.modes[fm].entryNodeId, values: { [inv.counter]: 1 }, frame: {} }, lowering, handlers).state;
  const fo = expand2(fs0);
  let er = new Rational(0n), er2 = new Rational(0n), ek = new Rational(0n), ekk1 = new Rational(0n), erk = new Rational(0n), q0 = new Rational(0n);
  const one = new Rational(1n);
  for (const o of fo) {
    const r = o.reward, k = o.state.terminal ? 0n : BigInt(o.state.values[inv.counter] ?? 0);
    er = add2(er, o.probability.mul(r));
    er2 = add2(er2, o.probability.mul(r.mul(r)));
    ek = add2(ek, o.probability.mul(new Rational(k)));
    ekk1 = add2(ekk1, o.probability.mul(new Rational(k * (k - 1n))));
    erk = add2(erk, o.probability.mul(r.mul(new Rational(k))));
    if (r.n === 0n && k === 0n)
      q0 = add2(q0, o.probability);
  }
  const denom = one.sub(ek);
  if (denom.n <= 0n)
    throw new Error("generic regenerative solver: non-terminating feature (E[K] >= 1)");
  const fm1 = er.div(denom);
  const fm2 = er2.add(new Rational(2n).mul(erk).mul(fm1)).add(ekk1.mul(fm1.mul(fm1))).div(denom);
  let z = 0;
  for (let it = 0; it < 1e4; it++) {
    let nz = 0;
    for (const o of fo) {
      if (o.reward.n !== 0n)
        continue;
      const k = o.state.terminal ? 0 : Number(BigInt(o.state.values[inv.counter] ?? 0));
      nz += o.probability.toNumber() * Math.pow(z, k);
    }
    if (Math.abs(nz - z) < 1e-15) {
      z = nz;
      break;
    }
    z = nz;
  }
  const zRat = new Rational(BigInt(Math.round(z * 1e15)), 1000000000000000n);
  let mean2 = new Rational(0n), second2 = new Rational(0n), miss = new Rational(0n), pfeat = new Rational(0n), paidSpins = new Rational(0n);
  let conditionalSpins = new Rational(0n);
  for (const o of base3) {
    const p = o.probability, r = o.reward;
    if (o.state.terminal) {
      mean2 = add2(mean2, p.mul(r));
      second2 = add2(second2, p.mul(r.mul(r)));
      if (r.n === 0n)
        miss = add2(miss, p);
      continue;
    }
    if (o.state.modeId !== fm)
      throw new Error(`unexpected continuation mode ${o.state.modeId}`);
    const n = BigInt(o.state.values[inv.counter] ?? 0);
    pfeat = add2(pfeat, p);
    const nr = new Rational(n), fmean = fm1.mul(nr), fsecond = fm2.mul(nr).add(fm1.mul(fm1).mul(new Rational(n * (n - 1n))));
    mean2 = add2(mean2, p.mul(r.add(fmean)));
    second2 = add2(second2, p.mul(r.mul(r).add(new Rational(2n).mul(r).mul(fmean)).add(fsecond)));
    const visits = nr.div(denom);
    paidSpins = add2(paidSpins, p.mul(visits));
    conditionalSpins = add2(conditionalSpins, p.mul(visits));
    if (r.n === 0n)
      miss = add2(miss, p.mul(new Rational(zRat.n ** n, zRat.d ** n)));
  }
  const result = { featureModeId: fm, mean: mean2, second: second2, variance: second2.sub(mean2.mul(mean2)), hitRate: one.sub(miss), featureTriggerProbability: pfeat, expectedFeatureSpins: pfeat.n === 0n ? new Rational(0n) : conditionalSpins.div(pfeat), expectedPaidGameFeatureSpins: paidSpins, featureMean: fm1, featureSecond: fm2 };
  let a = cache.get(def);
  if (!a) {
    a = /* @__PURE__ */ new WeakMap();
    cache.set(def, a);
  }
  let bb = a.get(handlers);
  if (!bb) {
    bb = /* @__PURE__ */ new WeakMap();
    a.set(handlers, bb);
  }
  let cc = bb.get(lowering);
  if (!cc) {
    cc = /* @__PURE__ */ new WeakMap();
    bb.set(lowering, cc);
  }
  cc.set(observations, result);
  return result;
}

// dist/src/math/modeStatistics.js
function boundaryExpander(def, lowering, handlers, obs) {
  return (b) => tryExpandAggregatedReelBoundary(def, b, lowering, handlers, obs) ?? expandExactBoundary(def, b, lowering, handlers);
}
function solveModeStatistics(def, modeId, opts = {}) {
  if (!def.modes[modeId])
    throw new Error(`unknown mode ${modeId}`);
  const handlers = opts.handlers ?? builtinNodeHandlers, lowering = opts.lowering ?? builtinExactLowering, expand2 = boundaryExpander(def, lowering, handlers, opts.reelObservations ?? builtinReelObservationRegistry());
  const capabilities = analyzeCapabilities(def, handlers);
  if (!capabilities.exactCompatible)
    throw new Error(`definition is not exact-compatible: ${capabilities.unsupported.join("; ")}`);
  const start = runDeterministic(def, { modeId: def.entryModeId, nodeId: def.modes[def.entryModeId].entryNodeId, values: {}, frame: {} }, lowering, handlers);
  const initial = { execution: start.state, visited: start.visitedModes.includes(modeId) };
  const graph = (metric) => buildReachableStateGraph({
    initial,
    maxStates: opts.maxStates,
    canonicalize: (s) => `${s.visited ? 1 : 0}:${canonicalExecutionState(s.execution)}`,
    isTerminal: (s) => !!s.execution.terminal,
    expand: (s) => expand2(s.execution).map((o) => {
      const visited = s.visited || o.visitedModes.includes(modeId);
      return { state: { execution: o.state, visited }, probability: o.probability, reward: new Rational(metric === "entry" ? !s.visited && visited ? 1n : 0n : s.execution.modeId === modeId ? 1n : 0n) };
    })
  });
  const probability = initial.visited ? new Rational(1n) : solveFiniteMarkov(graph("entry")).initial.expectedReward;
  const expectedSteps = solveFiniteMarkov(graph("steps")).initial.expectedReward;
  return { modeId, probability, expectedSteps, expectedStepsWhenEntered: probability.n === 0n ? new Rational(0n) : expectedSteps.div(probability) };
}
function solveModeReward(def, modeId, opts = {}) {
  const handlers = opts.handlers ?? builtinNodeHandlers, lowering = opts.lowering ?? builtinExactLowering, expand2 = boundaryExpander(def, lowering, handlers, opts.reelObservations ?? builtinReelObservationRegistry());
  const start = runDeterministic(def, { modeId: def.entryModeId, nodeId: def.modes[def.entryModeId].entryNodeId, values: {}, frame: {} }, lowering, handlers);
  const graph = buildReachableStateGraph({
    initial: start.state,
    maxStates: opts.maxStates,
    canonicalize: canonicalExecutionState,
    isTerminal: (s) => !!s.terminal,
    expand: (s) => expand2(s).map((o) => ({ state: o.state, probability: o.probability, reward: new Rational(o.rewardByMode[modeId] ?? 0n) }))
  });
  return solveFiniteMarkov(graph).initial.expectedReward.add(new Rational(start.rewardByMode[modeId] ?? 0n));
}

// dist/src/math/statePGF.js
function compileStatePGF(graph) {
  for (const state of Object.values(graph.states))
    for (const t of state.transitions) {
      if (!t.rewardAtoms)
        throw new Error("state PGF requires individual reward atoms");
      for (const a of t.rewardAtoms)
        if (a.reward.n < 0n || a.reward.d !== 1n)
          throw new Error("state PGF requires non-negative integer rewards");
    }
  const r = graph.initialReward;
  if (r && (r.n < 0n || r.d !== 1n))
    throw new Error("state PGF requires non-negative integer rewards");
  return { kind: "STATE_GRAPH_PGF", equation: "F_s(z) = sum p(s,t,r) z^r F_t(z); F_terminal(z) = 1", graph };
}
function evaluateStatePGF(p, z) {
  if (!Number.isFinite(z) || z < 0 || z > 1)
    throw new Error("PGF evaluation requires 0<=z<=1");
  const graph = p.graph, states = Object.values(graph.states).filter((s) => !s.terminal), index = new Map(states.map((s, i) => [s.key, i]));
  const n = states.length, A = Array.from({ length: n }, (_, i) => Array.from({ length: n }, (_2, j) => i === j ? 1 : 0)), b = Array(n).fill(0);
  for (let i = 0; i < n; i++)
    for (const t of states[i].transitions)
      for (const atom of t.rewardAtoms) {
        const weight = t.probability.toNumber() * atom.probability.toNumber() * Math.pow(z, Number(atom.reward.n)), j = index.get(t.to);
        if (j === void 0) {
          if (!graph.states[t.to]?.terminal)
            throw new Error(`missing state ${t.to}`);
          b[i] += weight;
        } else
          A[i][j] -= weight;
      }
  const original = A.map((row, i) => [...row, b[i]]), m = original.map((row) => [...row]);
  for (let col = 0; col < n; col++) {
    let pivot = col;
    while (pivot < n && Math.abs(m[pivot][col]) < 1e-14)
      pivot++;
    if (pivot === n)
      throw new Error("singular state PGF system: model may be non-terminating");
    [m[col], m[pivot]] = [m[pivot], m[col]];
    const d = m[col][col];
    for (let j = col; j <= n; j++)
      m[col][j] /= d;
    for (let i = 0; i < n; i++)
      if (i !== col) {
        const f = m[i][col];
        for (let j = col; j <= n; j++)
          m[i][j] -= f * m[col][j];
      }
  }
  const x = m.map((row) => row[n]);
  let residual = 0;
  for (let i = 0; i < n; i++)
    residual = Math.max(residual, Math.abs(original[i].slice(0, n).reduce((s, a, j) => s + a * x[j], 0) - original[i][n]));
  const initial = index.get(graph.initialState), value = (initial === void 0 ? 1 : x[initial]) * Math.pow(z, Number(graph.initialReward?.n ?? 0n));
  return { value, residual };
}

// dist/src/math/primitives/kernels.js
function stripFreq(strip2) {
  const m = /* @__PURE__ */ new Map();
  for (const x of strip2)
    m.set(x, (m.get(x) ?? 0n) + 1n);
  return [...m];
}
var stopSpace = (reels) => reels.reduce((a, s) => a * BigInt(s.length), 1n);
function maskedLinePayNumerator(def, S, reels, mask = 0, wild, cache3 = /* @__PURE__ */ new Map()) {
  const freq = reels.map(stripFreq);
  const one = { ...def, paylines: { "@L": { id: "@L", rows: Array(S.cols).fill(0) } } };
  let tot = 0n;
  for (const id of S.lineIds) {
    const rows = mask ? def.paylines[id].rows : Array(S.cols).fill(0);
    const stuck = rows.map((r, c2) => mask >> r * S.cols + c2 & 1).join("");
    let v = cache3.get(stuck);
    if (v === void 0) {
      let acc = 0n;
      const seq = [];
      const go = (c2, w) => {
        if (c2 === S.cols) {
          const p = evaluatePaylines(one, { rows: 1, cols: S.cols, stops: Array(S.cols).fill(0), symbols: [seq] }, S.paytableId, ["@L"], S.wildTag).reduce((a, x) => a + x.payout, 0n);
          acc += p * w;
          return;
        }
        if (stuck[c2] === "1") {
          seq[c2] = wild;
          go(c2 + 1, w * BigInt(reels[c2].length));
          return;
        }
        for (const [x, k] of freq[c2]) {
          seq[c2] = x;
          go(c2 + 1, w * k);
        }
      };
      go(0, 1n);
      v = acc;
      cache3.set(stuck, v);
    }
    tot += v;
  }
  return tot;
}
function maskUpdateColumn(strip2, rows, prior, lock, value = () => 0) {
  const m = /* @__PURE__ */ new Map(), L = strip2.length;
  for (let st = 0; st < L; st++) {
    let q = prior, v = 0;
    for (let r = 0; r < rows; r++) {
      if (prior >> r & 1)
        continue;
      const s = strip2[(st + r) % L];
      if (lock(s)) {
        q |= 1 << r;
        v += value(s);
      }
    }
    const e = m.get(q) ?? [0, 0];
    e[0]++;
    e[1] += v;
    m.set(q, e);
  }
  return [...m].map(([q, [n, v]]) => [q, n, v]);
}
var columnToMask = (c2, p, rows, cols) => {
  let m = 0;
  for (let r = 0; r < rows; r++)
    if (p >> r & 1)
      m |= 1 << r * cols + c2;
  return m;
};
var popcount = (m) => {
  let n = 0;
  while (m) {
    m &= m - 1;
    n++;
  }
  return n;
};
function tagCountDistribution(reels, rows, tagged) {
  let dist = [1n];
  for (const st of reels) {
    const cnt = [];
    for (let s = 0; s < st.length; s++) {
      let n = 0;
      for (let r = 0; r < rows; r++)
        if (tagged(st[(s + r) % st.length]))
          n++;
      cnt[n] = (cnt[n] ?? 0n) + 1n;
    }
    const nd = [];
    dist.forEach((a, i) => cnt.forEach((b, j) => {
      if (b)
        nd[i + j] = (nd[i + j] ?? 0n) + a * (b ?? 0n);
    }));
    dist = nd;
  }
  return dist;
}
function respinResetGeometric(q, R2) {
  let g = 0, qq = 1;
  for (let i = 0; i < R2; i++) {
    g += qq;
    qq *= q;
  }
  return g;
}
var ladderMultiplier = (ladder, t) => ladder[Math.min(t, ladder.length - 1)];
function boardOps(T) {
  const { rows: R2, cols: C, lines, pay, wild: W } = T, P = C + 1, NL = lines.length;
  const strips = T.strips.map((s) => Int16Array.from(s)), LEN = strips.map((s) => s.length);
  const LR = Int8Array.from(lines.flat());
  const board = new Int16Array(R2 * C), stops = new Int32Array(C), hitCnt = new Int8Array(NL), tmp = new Int16Array(R2);
  const spin2 = (s) => {
    for (let c2 = 0; c2 < C; c2++) {
      stops[c2] = s[c2];
      for (let r = 0; r < R2; r++)
        board[r * C + c2] = strips[c2][(s[c2] + r) % LEN[c2]];
    }
  };
  const winCells = () => {
    let win = 0;
    for (let l = 0; l < NL; l++) {
      const o = l * C;
      let t = -1;
      for (let c2 = 0; c2 < C; c2++) {
        const s = board[LR[o + c2] * C + c2];
        if (s !== W) {
          t = s;
          break;
        }
      }
      if (t < 0)
        t = W;
      let n = 0;
      for (; n < C; n++) {
        const s = board[LR[o + n] * C + n];
        if (s !== t && s !== W)
          break;
      }
      const p = pay[t * P + n];
      hitCnt[l] = p > 0 ? n : 0;
      win += p;
    }
    return win;
  };
  const dynamicsRefill = () => {
    for (let c2 = 0; c2 < C; c2++) {
      let mask = 0;
      for (let l = 0; l < NL; l++)
        if (hitCnt[l] > c2)
          mask |= 1 << LR[l * C + c2];
      if (!mask)
        continue;
      let k = 0, rem = 0;
      for (let r = 0; r < R2; r++)
        if (mask & 1 << r)
          rem++;
        else
          tmp[k++] = board[r * C + c2];
      const L = LEN[c2], st = ((stops[c2] - rem) % L + L) % L;
      stops[c2] = st;
      for (let i = 0; i < rem; i++)
        board[i * C + c2] = strips[c2][(st + i) % L];
      for (let i = 0; i < k; i++)
        board[(rem + i) * C + c2] = tmp[i];
    }
  };
  return { spin: spin2, winCells, dynamicsRefill, strips, LEN, LR, NL, P };
}
var columnEV = (def) => solveExpectedValueIR(compileExpectedValueIR(def));
var columnMoments = (def) => solveMomentIR(compileMomentIR(def));
var columnHitRate = (def, o = {}) => solveExactHitRate(def, o.tolerance ?? 1e-15, o.maxIterations ?? 1e4);
var columnPGF = (def) => compilePaidGamePGF(def);
var columnPGFAt = (pgf2, z, tol = 1e-14) => evaluatePaidGamePGF(pgf2, z, tol);
var columnEVIR = (def) => compileExpectedValueIR(def);
var graphSolve = (g) => solveFiniteMarkov(g);
var graphPGF = (g) => compileStatePGF(g);
var graphPGFAt = (p, z) => evaluateStatePGF(p, z);
var modeStatistics = (def, modeId, o = {}) => solveModeStatistics(def, modeId, { maxStates: o.maxStates, handlers: o.handlers, lowering: o.lowering, reelObservations: o.reelObservations });
var modeReward = (def, modeId, o = {}) => solveModeReward(def, modeId, { maxStates: o.maxStates, handlers: o.handlers, lowering: o.lowering, reelObservations: o.reelObservations });
var renewal = (decrement, retriggerMass) => solveRegenerative(decrement, retriggerMass);
var regenerativeSolve = (def, o = {}) => solveGenericRegenerative(def, { lowering: o.lowering, handlers: o.handlers, reelObservations: o.reelObservations });
function composeRegen(baseEV, triggerProbability, featureEVGivenTrigger) {
  const featureEV = triggerProbability.mul(featureEVGivenTrigger);
  return { ev: baseEV.add(featureEV), featureEV };
}

// dist/src/math/primitives/folds/graphExact.js
function graphEV(def, g, o = {}) {
  const x = graphSolve(g), modes = Object.keys(def.modes).filter((id) => id !== def.entryModeId);
  const mode = modes.length === 1 ? modeStatistics(def, modes[0], o) : void 0;
  const baseEV = modes.length ? modeReward(def, def.entryModeId, o) : x.initial.expectedReward;
  const featureEV = mode ? mode.probability.n === 0n ? new Rational(0n) : modeReward(def, modes[0], o).div(mode.probability) : modes.length ? null : new Rational(0n);
  return { ev: x.initial.expectedReward, baseEV, featureEV, featureTriggerProbability: mode?.probability ?? (modes.length ? null : new Rational(0n)), expectedFeatureSpins: mode?.expectedStepsWhenEntered ?? (modes.length ? null : new Rational(0n)) };
}
function graphDuration(g) {
  const x = graphSolve(g);
  return { expectedFeatureSpins: x.initial.expectedSteps, expectedPaidGameFeatureSpins: x.initial.expectedSteps };
}
function graphHitRate(g) {
  const x = graphPGFAt(graphPGF(g), 0);
  return { hitRate: 1 - x.value, missRate: x.value, featureZeroProbability: NaN, fixedPointResidual: x.residual, iterations: 0 };
}
function graphVariance(g) {
  const x = graphSolve(g);
  return { mean: x.initial.expectedReward, secondMoment: x.initial.rewardSecond, variance: x.initial.rewardVariance, featureMean: new Rational(0n), featureSecondMoment: new Rational(0n) };
}
function graphDistribution(g, z) {
  const pgf2 = graphPGF(g);
  return { pgf: pgf2, evaluation: z === void 0 ? void 0 : { z, ...graphPGFAt(pgf2, z) } };
}

// dist/src/math/primitives/folds/columnDP.js
function columnDPEV(def, g, o = {}) {
  if (g)
    return graphEV(def, g, o);
  const x = columnEV(def);
  return { ev: x.totalEV, baseEV: x.baseEV, featureEV: x.featureEV, featureTriggerProbability: x.featureTriggerProbability, expectedFeatureSpins: x.expectedFeatureSpins };
}
function columnDPDuration(def, g) {
  if (g)
    return graphDuration(g);
  const ir = columnEVIR(def), link = ir.entryFeature;
  if (!link)
    return { expectedFeatureSpins: new Rational(0n), expectedPaidGameFeatureSpins: new Rational(0n) };
  const f = ir.regenerativeFeatures[link.toModeId];
  if (!f)
    throw new Error(`duration: feature ${link.toModeId} is not regenerative`);
  if (f.decrement !== 1n)
    throw new Error(`duration: unsupported decrement ${f.decrement}`);
  const one = renewal(new Rational(1n), f.spin.triggerProbability.mul(new Rational(f.retriggerAward)));
  const conditional = one.expectedVisits.mul(new Rational(link.initialSpins));
  return { expectedFeatureSpins: conditional, expectedPaidGameFeatureSpins: link.triggerProbability.mul(conditional) };
}
function columnDPHitRate(def, g, o = {}) {
  return g ? graphHitRate(g) : columnHitRate(def, o);
}
function columnDPVariance(def, g) {
  if (g)
    return graphVariance(g);
  const x = columnMoments(def);
  return { mean: x.mean, secondMoment: x.second, variance: x.variance, featureMean: x.featureMean, featureSecondMoment: x.featureSecond };
}
function columnDPDistribution(def, g, z, tol) {
  if (g)
    return graphDistribution(g, z);
  const pgf2 = columnPGF(def);
  return { pgf: pgf2, evaluation: z === void 0 ? void 0 : { z, ...columnPGFAt(pgf2, z, tol ?? 1e-14) } };
}

// dist/src/math/primitives/folds/regen.js
var hasRegenCounter = (def) => Object.keys(def.modes).some((id) => hasAdditiveRegenerativeCounter(def, id));
function regenEV(def, o = {}) {
  const g = regenerativeSolve(def, o);
  return { ev: g.mean, baseEV: g.mean.sub(g.featureTriggerProbability.mul(g.featureMean)), featureEV: g.featureMean, featureTriggerProbability: g.featureTriggerProbability, expectedFeatureSpins: g.expectedFeatureSpins };
}
function regenDuration(def, o = {}) {
  const g = regenerativeSolve(def, o);
  return { expectedFeatureSpins: g.expectedFeatureSpins, expectedPaidGameFeatureSpins: g.expectedPaidGameFeatureSpins };
}
function regenHitRate(def, o = {}) {
  const g = regenerativeSolve(def, o);
  return { hitRate: g.hitRate.toNumber(), missRate: 1 - g.hitRate.toNumber(), featureZeroProbability: NaN, fixedPointResidual: 0, iterations: 0 };
}
function regenVariance(def, o = {}) {
  const g = regenerativeSolve(def, o);
  return { mean: g.mean, secondMoment: g.second, variance: g.variance, featureMean: g.featureMean, featureSecondMoment: g.featureSecond };
}
function regenModeDuration(def, modeId, o = {}) {
  if (hasRegenCounter(def)) {
    const g = regenerativeSolve(def, o);
    if (g.featureModeId === modeId)
      return { expectedFeatureSpins: g.expectedFeatureSpins, expectedPaidGameFeatureSpins: g.expectedPaidGameFeatureSpins };
  }
  const s = modeStatistics(def, modeId, o);
  return { expectedFeatureSpins: s.expectedStepsWhenEntered, expectedPaidGameFeatureSpins: s.expectedSteps };
}
function regenFeatureFrequency(def, modeId, useRegen, o = {}) {
  if (!def.modes[modeId])
    throw new Error(`feature frequency: unknown mode ${modeId}`);
  if (modeId === def.entryModeId)
    return { modeId, probability: new Rational(1n) };
  if (useRegen) {
    const g = regenerativeSolve(def, o);
    if (modeId !== g.featureModeId)
      throw new Error(`feature frequency: mode ${modeId} is not a directly supported entry feature`);
    return { modeId, probability: g.featureTriggerProbability };
  }
  return { modeId, probability: modeStatistics(def, modeId, o).probability };
}

// dist/src/math/primitives/exactFolds.js
var isRegen = (e) => e.math.reductions.some((x) => x.kind === "ADDITIVE_REGENERATIVE_COUNTER");
var hasReels = (def) => Object.values(def.modes).some((m) => Object.values(m.nodes).some((n) => n.kind === "SOURCE" && n.source?.type === "REEL_SPIN"));
var graphOf = (e) => e.decision.kind === "STATE_EXACT" ? e.decision.graph : void 0;
function wager(def, explicit) {
  const b = explicit ?? def.wager?.totalBet;
  if (b === void 0)
    throw new Error("RTP requires query.bet or GameDefinition.wager");
  if (b <= 0n)
    throw new Error("RTP bet must be positive");
  return b;
}
function genericFoldKind(def, e) {
  return isRegen(e) ? "regen" : hasReels(def) ? "columnDP" : "graphExact";
}
function genericFoldPlan(def, e) {
  const k = genericFoldKind(def, e);
  if (k === "graphExact")
    return { kind: "graphExact" };
  if (k === "regen" || Object.keys(def.modes).length > 1 || e.math.solver === "REGENERATIVE")
    return { kind: "regen", inner: { kind: "columnDP", observe: [] }, buyOnly: false, retrigger: false };
  return { kind: "columnDP", observe: [] };
}
function foldEV({ def, execution, options }) {
  if (isRegen(execution))
    return regenEV(def, options);
  const g = graphOf(execution);
  return genericFoldKind(def, execution) === "graphExact" && g ? graphEV(def, g, options) : columnDPEV(def, g, options);
}
var exactFoldExecutors = {
  EV: (ctx) => foldEV(ctx),
  RTP: (ctx) => {
    const q = ctx.query;
    if (q.type !== "RTP")
      throw new Error("RTP projector mismatch");
    const bet = wager(ctx.def, q.bet), x = foldEV(ctx);
    return { ...x, bet, rtp: x.ev.div(new Rational(bet)) };
  },
  EXPECTED_DURATION: ({ def, query, execution, options }) => {
    if (query.type === "EXPECTED_DURATION" && query.modeId)
      return regenModeDuration(def, query.modeId, options);
    return isRegen(execution) ? regenDuration(def, options) : columnDPDuration(def, graphOf(execution));
  },
  FEATURE_FREQUENCY: ({ def, query, execution, options }) => {
    if (query.type !== "FEATURE_FREQUENCY")
      throw new Error("feature-frequency projector mismatch");
    return regenFeatureFrequency(def, query.modeId, isRegen(execution) || hasRegenCounter(def), options);
  },
  HIT_RATE: ({ def, execution, options }) => isRegen(execution) ? regenHitRate(def, options) : columnDPHitRate(def, graphOf(execution), options),
  VARIANCE: ({ def, execution, options }) => isRegen(execution) ? regenVariance(def, options) : columnDPVariance(def, graphOf(execution)),
  DISTRIBUTION: ({ def, execution, options }) => columnDPDistribution(def, graphOf(execution), options.pgfZ, options.tolerance)
};
function runExactFold(ctx) {
  return exactFoldExecutors[ctx.query.type](ctx);
}

// dist/src/math/observableAlgebra.js
var mean = { name: "rewardMean", dependsOn: [], immediate: (c2) => c2.reward, continuationCoefficient: () => 1, cutContribution: (c2) => c2.cut?.rewardMean ?? 0 };
var second = { name: "rewardSecond", dependsOn: ["rewardMean"], immediate: (c2) => c2.reward * c2.reward + 2 * c2.reward * (c2.future.rewardMean ?? c2.cut?.rewardMean ?? 0), continuationCoefficient: () => 1, cutContribution: (c2) => c2.cut?.rewardSecond ?? 0 };
var steps = { name: "steps", dependsOn: [], immediate: () => 1, continuationCoefficient: () => 1, cutContribution: (c2) => c2.cut?.steps ?? 0 };
var hit = { name: "hitProbability", dependsOn: [], immediate: (c2) => c2.reward > 0 ? 1 : 0, continuationCoefficient: (c2) => c2.reward > 0 ? 0 : 1, cutContribution: (c2) => c2.reward > 0 ? 0 : c2.cut?.hitProbability ?? 0 };
var pgf = { name: "pgf", dependsOn: [], immediate: (c2) => c2.terminal ? Math.pow(c2.pgfZ ?? 1, c2.reward) : 0, continuationCoefficient: (c2) => Math.pow(c2.pgfZ ?? 1, c2.reward), cutContribution: (c2) => Math.pow(c2.pgfZ ?? 1, c2.reward) * (c2.cut?.pgf ?? 0) };
function observableAlgebra(names, extensions = {}) {
  const all = /* @__PURE__ */ new Map([[mean.name, mean], [second.name, second], [steps.name, steps], [hit.name, hit], [pgf.name, pgf]]);
  for (const [name, component] of Object.entries(extensions))
    if (component)
      all.set(name, component);
  const wanted = /* @__PURE__ */ new Set();
  const visiting = /* @__PURE__ */ new Set();
  const add3 = (n) => {
    if (wanted.has(n))
      return;
    if (visiting.has(n))
      throw new Error(`cyclic observable dependency: ${n}`);
    const c2 = all.get(n);
    if (!c2)
      throw new Error(`unknown observable ${n}`);
    if (c2.name !== n)
      throw new Error(`observable name mismatch: ${n} != ${c2.name}`);
    visiting.add(n);
    for (const d of c2.dependsOn)
      add3(d);
    visiting.delete(n);
    wanted.add(n);
  };
  for (const n of names)
    add3(n);
  return { components: [...wanted].map((n) => all.get(n)) };
}
var fullBoundaryAlgebra = observableAlgebra(["rewardMean", "rewardSecond", "steps", "hitProbability", "pgf"]);

// dist/src/math/hybrid.js
function u01(seed, sample, step) {
  const b = createHash("sha256").update(`${seed}${sample}${step}`).digest();
  const x = b.readBigUInt64BE(0) >> 11n;
  return Number(x) / 9007199254740992;
}
function sampleContinuation(def, start, samples, seed, pgfZ, lowering, handlers) {
  let sum = 0, sum2 = 0, stepsSum = 0, hits = 0, pgf2 = 0;
  for (let i = 0; i < samples; i++) {
    let s = start, total = 0, steps2 = 0;
    for (let step = 0; step < 1e5; step++) {
      if (s.terminal)
        break;
      const outs = expandExactBoundary(def, s, lowering, handlers);
      const u = u01(seed, i, step);
      let c2 = 0, chosen = outs[outs.length - 1];
      for (const o of outs) {
        c2 += o.probability.toNumber();
        if (u < c2) {
          chosen = o;
          break;
        }
      }
      total += chosen.reward.toNumber();
      steps2++;
      s = chosen.state;
      if (step === 99999)
        throw new Error("hybrid continuation guard exceeded");
    }
    sum += total;
    sum2 += total * total;
    stepsSum += steps2;
    if (total > 0)
      hits++;
    if (pgfZ !== void 0)
      pgf2 += Math.pow(pgfZ, total);
  }
  return { rewardMean: sum / samples, rewardSecond: sum2 / samples, steps: stepsSum / samples, hitProbability: hits / samples, pgf: pgfZ === void 0 ? void 0 : pgf2 / samples };
}
function solveLinear2(A, b) {
  const n = A.length, m = A.map((r, i) => [...r, b[i]]);
  for (let c2 = 0; c2 < n; c2++) {
    let p = c2;
    while (p < n && Math.abs(m[p][c2]) < 1e-14)
      p++;
    if (p === n)
      throw new Error("singular hybrid prefix system");
    [m[c2], m[p]] = [m[p], m[c2]];
    const d = m[c2][c2];
    for (let j = c2; j <= n; j++)
      m[c2][j] /= d;
    for (let i = 0; i < n; i++)
      if (i !== c2) {
        const f = m[i][c2];
        for (let j = c2; j <= n; j++)
          m[i][j] -= f * m[c2][j];
      }
  }
  return m.map((r) => r[n]);
}
function buildPartition(def, maxExactStates, lowering, handlers) {
  const initial = initialExactBoundary(def, lowering, handlers), initialKey = canonicalExecutionState(initial);
  const concrete = /* @__PURE__ */ new Map([[initialKey, initial]]), retained = /* @__PURE__ */ new Set([initialKey]), cuts = /* @__PURE__ */ new Map();
  const nodes2 = /* @__PURE__ */ new Map(), q = [initialKey];
  while (q.length) {
    const key = q.shift(), s = concrete.get(key);
    if (s.terminal) {
      nodes2.set(key, { key, terminal: true, edges: [] });
      continue;
    }
    const edges = [];
    for (const o of expandExactBoundary(def, s, lowering, handlers)) {
      const k = canonicalExecutionState(o.state);
      if (!concrete.has(k))
        concrete.set(k, o.state);
      if (!retained.has(k) && !cuts.has(k)) {
        if (retained.size < maxExactStates) {
          retained.add(k);
          q.push(k);
        } else
          cuts.set(k, o.state);
      }
      edges.push({ to: k, p: o.probability, reward: o.reward });
    }
    nodes2.set(key, { key, terminal: false, edges });
  }
  return { initialKey, retained, cuts, nodes: nodes2 };
}
function solveHybridAlgebra(def, opts) {
  const part = buildPartition(def, opts.maxExactStates, opts.lowering, opts.handlers), cutValues = /* @__PURE__ */ new Map();
  let ci = 0;
  const cutResults = [];
  for (const [k2, s] of part.cuts) {
    const v = sampleContinuation(def, s, opts.samplesPerCut, (opts.masterSeed ?? 1n) + BigInt(ci++) * 1000003n, opts.pgfZ, opts.lowering, opts.handlers);
    cutValues.set(k2, v);
    cutResults.push({ key: k2, samples: opts.samplesPerCut, observables: v });
  }
  const transient = [...part.nodes.values()].filter((n2) => !n2.terminal), idx = new Map(transient.map((n2, i) => [n2.key, i])), n = transient.length;
  const solved = /* @__PURE__ */ new Map();
  for (const component of opts.algebra.components) {
    const A = Array.from({ length: n }, (_, i) => Array.from({ length: n }, (_2, j) => i === j ? 1 : 0)), rhs = Array(n).fill(0);
    for (let i = 0; i < n; i++)
      for (const e of transient[i].edges) {
        const p = e.p.toNumber(), r = e.reward.toNumber(), j = idx.get(e.to), cut = cutValues.get(e.to), terminal = part.nodes.get(e.to)?.terminal === true;
        const future = {};
        for (const d of component.dependsOn)
          future[d] = j !== void 0 ? solved.get(d)?.[j] : cut?.[d];
        const ctx = { reward: r, future, cut, terminal, pgfZ: opts.pgfZ };
        rhs[i] += p * component.immediate(ctx);
        if (j !== void 0)
          A[i][j] -= p * component.continuationCoefficient(ctx);
        else if (cut)
          rhs[i] += p * component.cutContribution(ctx);
      }
    solved.set(component.name, solveLinear2(A, rhs));
  }
  const k = idx.get(part.initialKey);
  const get = (name) => solved.get(name)?.[k];
  return { exactStates: part.retained.size, cutStates: part.cuts.size, cuts: cutResults, samplesPerCut: opts.samplesPerCut, observables: { rewardMean: get("rewardMean") ?? 0, rewardSecond: get("rewardSecond") ?? 0, steps: get("steps") ?? 0, hitProbability: get("hitProbability") ?? 0, pgf: get("pgf") } };
}
function solveHybridObservables(def, opts) {
  const names = opts.observables ?? ["rewardMean", "rewardSecond", "steps", "hitProbability", ...opts.pgfZ === void 0 ? [] : ["pgf"]];
  return solveHybridAlgebra(def, { ...opts, algebra: observableAlgebra(names, opts.observableComponents) });
}

// dist/src/math/monteCarlo.js
function deriveSeed(master, index) {
  const b = createHash("sha256").update(`${master}${index}`).digest();
  return b.readBigUInt64BE(0);
}
function simulate(def, samples, masterSeed = 1n, handlers, evaluators) {
  if (!Number.isSafeInteger(samples) || samples <= 0)
    throw new Error("samples must be a positive safe integer");
  let sum = 0, sum2 = 0, hits = 0, features = 0, featureSpins = 0;
  const stats = Object.fromEntries(Object.keys(def.modes).map((id) => [id, { entries: 0, steps: 0 }]));
  const nodeHandlers = handlers ?? builtinNodeHandlers;
  for (let i = 0; i < samples; i++) {
    const r = play(def, deriveSeed(masterSeed, BigInt(i)), { handlers, evaluators });
    const x = Number(r.state.totalAward);
    sum += x;
    sum2 += x * x;
    if (x > 0)
      hits++;
    const entered = /* @__PURE__ */ new Set(), steps2 = {};
    for (const event of r.trace) {
      entered.add(event.modeId);
      if (nodeHandlers[event.kind]?.stochasticBoundary)
        steps2[event.modeId] = (steps2[event.modeId] ?? 0) + 1;
    }
    for (const id of entered) {
      stats[id].entries++;
      stats[id].steps += steps2[id] ?? 0;
    }
    const featureModes = [...entered].filter((id) => id !== def.entryModeId);
    if (featureModes.length) {
      features++;
      for (const id of featureModes)
        featureSpins += steps2[id] ?? 0;
    }
  }
  const modes = Object.fromEntries(Object.entries(stats).map(([id, s]) => [id, { entryProbability: s.entries / samples, averageStochasticSteps: s.steps / samples, averageStochasticStepsWhenEntered: s.entries ? s.steps / s.entries : 0 }]));
  const mean2 = sum / samples;
  return { samples, mean: mean2, variance: sum2 / samples - mean2 * mean2, hitRate: hits / samples, featureRate: features / samples, averageFeatureSpins: features ? featureSpins / features : 0, modes };
}

// dist/src/math/backendExecutors.js
function wager2(def, explicit) {
  const b = explicit ?? def.wager?.totalBet;
  if (b === void 0)
    throw new Error("RTP requires query.bet or GameDefinition.wager");
  if (b <= 0n)
    throw new Error("RTP bet must be positive");
  return b;
}
var directExecutorRegistry = Object.fromEntries(Object.entries(exactFoldExecutors).map(([k, f]) => [k, (ctx) => f(ctx)]));
var hybridProjectorRegistry = {
  EV: (h, ctx) => ({ ...h, approximate: true, hybrid: true, reason: ctx.execution.decision.reason, mean: h.observables.rewardMean }),
  RTP: (h, ctx) => {
    if (ctx.query.type !== "RTP")
      throw new Error("RTP projector mismatch");
    return { ...h, approximate: true, hybrid: true, reason: ctx.execution.decision.reason, mean: h.observables.rewardMean, bet: wager2(ctx.def, ctx.query.bet), rtp: h.observables.rewardMean / Number(wager2(ctx.def, ctx.query.bet)) };
  },
  VARIANCE: (h, ctx) => ({ ...h, approximate: true, hybrid: true, reason: ctx.execution.decision.reason, queryType: "VARIANCE", mean: h.observables.rewardMean, variance: h.observables.rewardSecond - h.observables.rewardMean * h.observables.rewardMean }),
  EXPECTED_DURATION: (h, ctx) => ({ ...h, approximate: true, hybrid: true, reason: ctx.execution.decision.reason, queryType: "EXPECTED_DURATION", expectedSteps: h.observables.steps }),
  HIT_RATE: (h, ctx) => ({ ...h, approximate: true, hybrid: true, reason: ctx.execution.decision.reason, queryType: "HIT_RATE", hitRate: h.observables.hitProbability }),
  DISTRIBUTION: (h, ctx) => ({ ...h, approximate: true, hybrid: true, reason: ctx.execution.decision.reason, queryType: "DISTRIBUTION", pgfValue: h.observables.pgf }),
  FEATURE_FREQUENCY: () => {
    throw new Error("FEATURE_FREQUENCY is not partitionable");
  }
};
var backendExecutorRegistry = {
  DIRECT: (ctx) => directExecutorRegistry[ctx.query.type](ctx),
  STATE_EXACT: (ctx) => directExecutorRegistry[ctx.query.type](ctx),
  PARTITIONED_HYBRID: (ctx) => {
    const q = ctx.execution.queryIR;
    const h = solveHybridObservables(ctx.def, { maxExactStates: ctx.execution.budget.maxStates, samplesPerCut: ctx.execution.budget.mcSamples, masterSeed: ctx.options.masterSeed ?? 1n, pgfZ: q.pgfZ, observables: q.observables, lowering: ctx.options.lowering, handlers: ctx.options.handlers, observableComponents: ctx.options.observableComponents });
    return (ctx.options.hybridProjectors?.[ctx.query.type] ?? hybridProjectorRegistry[ctx.query.type])(h, ctx);
  },
  MONTE_CARLO: (ctx) => ({ ...simulate(ctx.def, ctx.execution.budget.mcSamples, ctx.options.masterSeed ?? 1n, ctx.options.handlers, ctx.options.lowering?.evaluators), approximate: true, reason: ctx.execution.decision.reason })
};
function executeBackend(ctx) {
  const executor = ctx.options.backendExecutors?.[ctx.execution.decision.kind] ?? backendExecutorRegistry[ctx.execution.decision.kind];
  if (!executor)
    throw new Error(`no backend executor registered for ${ctx.execution.decision.kind}`);
  return executor(ctx);
}

// bench/web/shims/os.js
var os_default = { availableParallelism: () => 1, cpus: () => [{}] };

// bench/web/shims/worker_threads.js
var Worker = class {
  constructor() {
    throw new Error("worker_threads not available in browser");
  }
};

// dist/src/math/primitives/folds/stopEnum.js
var lit = (e, env) => {
  if (!e)
    return;
  if ("const" in e)
    return Number(e.const);
  if ("ref" in e)
    return env[e.ref];
  if ("op" in e) {
    const a = lit(e.left, env), b = lit(e.right, env);
    if (a === void 0 || b === void 0)
      return;
    switch (e.op) {
      case "*":
        return a * b;
      case "+":
        return a + b;
      case "-":
        return a - b;
      case ">":
        return +(a > b);
      case ">=":
        return +(a >= b);
      case "<":
        return +(a < b);
      case "<=":
        return +(a <= b);
      case "==":
        return +(a === b);
    }
  }
  return;
};
function compileCascade(def) {
  for (const mode of Object.values(def.modes)) {
    const nodes2 = mode.nodes;
    const all = Object.values(nodes2);
    const tum = all.find((n) => n.kind === "EVALUATE" && n.evaluator?.type === "TUMBLE");
    if (!tum)
      continue;
    if (Object.keys(def.modes).length !== 1)
      return null;
    const spin2 = all.find((n) => n.kind === "SOURCE" && n.source?.type === "REEL_SPIN");
    if (!spin2 || spin2.source.reelSetId !== tum.evaluator.reelSetId)
      return null;
    const lines = nodes2[spin2.next];
    if (lines?.evaluator?.type !== "PAYLINES" || lines.evaluator.board !== spin2.output)
      return null;
    const sum = nodes2[lines.next];
    if (sum?.evaluator?.type !== "SUM_WINS")
      return null;
    const has = nodes2[sum.next];
    if (has?.kind !== "CONDITION")
      return null;
    if (nodes2[has.onFalse]?.operation?.type !== "END_GAME")
      return null;
    const init2 = nodes2[mode.entryNodeId];
    if (init2?.kind !== "STATE" || init2.op !== "SET" || init2.next !== spin2.id)
      return null;
    const key = init2.target;
    const tKey = `$state.${key}`;
    const inc = nodes2[tum.next];
    if (inc?.kind !== "STATE" || inc.target !== key || inc.op !== "ADD" || Number(inc.value?.const) !== 1)
      return null;
    const cap = nodes2[inc.next];
    if (cap?.kind !== "CONDITION" || cap.onFalse !== lines.id || nodes2[cap.onTrue]?.operation?.type !== "END_GAME")
      return null;
    const mult = [];
    for (let t = Number(init2.value.const); t < 1e3; t++) {
      const env = { [tKey]: t, [sum.output]: 1 };
      let n = nodes2[has.onTrue], g = 0;
      while (n?.kind === "CONDITION" && g++ < 100) {
        const v = lit(n.expression, env);
        if (v === void 0)
          return null;
        n = nodes2[v ? n.onTrue : n.onFalse];
      }
      if (n?.kind !== "AWARD" || n.next !== tum.id)
        return null;
      const m = lit(n.amount, env);
      if (m === void 0 || !Number.isInteger(m))
        return null;
      mult.push(m);
      const stop = lit(cap.expression, { [tKey]: t + 1 });
      if (stop === void 0)
        return null;
      if (stop)
        break;
    }
    if (lit(has.expression, { [sum.output]: 0 }))
      return null;
    if (!lit(has.expression, { [sum.output]: 1 }))
      return null;
    const rs = def.reelSets[spin2.source.reelSetId];
    const rows = Number(spin2.source.rows), cols = rs.reels.length;
    const ids = Object.keys(def.symbols), SI = new Map(ids.map((s, i) => [s, i]));
    const wildTag = lines.evaluator.wildTag;
    const wilds = ids.filter((s) => wildTag && def.symbols[s].tags.includes(wildTag));
    if (wilds.length > 1)
      return null;
    const wild = wilds.length ? SI.get(wilds[0]) : -1;
    const strips = rs.reels.map((r) => r.symbols.map((s) => SI.get(s)));
    const pay = new Array(ids.length * (cols + 1)).fill(0);
    let minN = Infinity;
    for (const [s, p] of Object.entries(def.paytables[lines.evaluator.paytableId].pays))
      for (const [n, v] of Object.entries(p)) {
        if (!SI.has(s))
          continue;
        pay[SI.get(s) * (cols + 1) + +n] = Number(v);
        if (Number(v) > 0)
          minN = Math.min(minN, +n);
      }
    const lineIds = lines.evaluator.paylineIds;
    const L = lineIds.map((id) => [...def.paylines[id].rows]);
    if (L.some((r) => r.length !== cols))
      return null;
    const prune = cols >= 3 && minN >= 3 && wild >= 0 ? !strips[0].includes(wild) : cols >= 3 && minN >= 3;
    return { rows, cols, strips, lines: L, pay, nSym: ids.length, wild, multipliers: mult, prune };
  }
  return null;
}
function cascadeKernel(T) {
  const { cols: C, pay, wild: W, multipliers: MULT, prune } = T;
  const ops = boardOps(T);
  const { strips, LEN, LR, NL, P } = ops;
  const play2 = (s) => {
    ops.spin(s);
    let tot = 0;
    for (let t = 0; t < MULT.length; t++) {
      const w = ops.winCells();
      if (w <= 0)
        break;
      tot += w * ladderMultiplier(MULT, t);
      ops.dynamicsRefill();
    }
    return tot;
  };
  const first3 = (a0, a1, a2) => {
    for (let l = 0; l < NL; l++) {
      const a = strips[0][(a0 + LR[l * C]) % LEN[0]], b = strips[1][(a1 + LR[l * C + 1]) % LEN[1]], c2 = strips[2][(a2 + LR[l * C + 2]) % LEN[2]];
      if ((b === a || b === W) && (c2 === a || c2 === W) && pay[a * P + 3] > 0)
        return true;
    }
    return false;
  };
  const run = (from, step) => {
    let sum = 0, sumSq = 0, hits = 0, evaluated = 0, max = 0;
    const s = new Int32Array(C);
    const inner = (c2) => {
      if (c2 === C) {
        const v = play2(s);
        evaluated++;
        if (v > 0) {
          hits++;
          sum += v;
          sumSq += v * v;
          if (v > max)
            max = v;
        }
        return;
      }
      for (let i = 0; i < LEN[c2]; i++) {
        s[c2] = i;
        if (c2 === 2 && prune && !first3(s[0], s[1], s[2]))
          continue;
        inner(c2 + 1);
      }
    };
    for (let a = from; a < LEN[0]; a += step) {
      s[0] = a;
      inner(1);
    }
    return { sum, sumSq, hits, evaluated, max };
  };
  return { play: play2, run, LEN };
}
var cache2 = /* @__PURE__ */ new Map();
function enumerateCascade(T, opts = {}) {
  const key = JSON.stringify(T);
  const hit2 = cache2.get(key);
  const LEN = T.strips.map((s) => s.length);
  const nW = Math.max(1, Math.min(opts.workers ?? os_default.availableParallelism?.() ?? os_default.cpus().length, LEN[0]));
  if (hit2)
    return { ...hit2, workers: 0 };
  const outcomes = LEN.reduce((a, b) => a * BigInt(b), 1n);
  let agg = { sum: 0, sumSq: 0, hits: 0, evaluated: 0, max: 0 };
  if (nW === 1)
    agg = cascadeKernel(T).run(0, 1);
  else {
    const sab = new SharedArrayBuffer(8 * (1 + 5 * nW)), done = new Int32Array(sab, 0, 1), out = new Float64Array(sab, 8);
    const ws = [];
    for (let w = 0; w < nW; w++) {
      const wk = new Worker(new URL("./stopEnumWorker.js", import.meta.url), { workerData: { T, from: w, step: nW, sab, index: w } });
      wk.unref();
      ws.push(wk);
    }
    const deadline = Date.now() + 6e5;
    while (Atomics.load(done, 0) < nW) {
      if (Date.now() > deadline) {
        for (const wk of ws)
          void wk.terminate();
        throw new Error("cascade exact: workers timed out");
      }
      const cur = Atomics.load(done, 0);
      if (cur < 0)
        throw new Error("cascade worker failed");
      Atomics.wait(done, 0, cur, 6e4);
    }
    for (const wk of ws)
      void wk.terminate();
    for (let w = 0; w < nW; w++) {
      const o = out.subarray(5 * w, 5 * w + 5);
      agg.sum += o[0];
      agg.sumSq += o[1];
      agg.hits += o[2];
      agg.evaluated += o[3];
      agg.max = Math.max(agg.max, o[4]);
    }
  }
  if (!(agg.sumSq < 2 ** 53))
    throw new Error("cascade exact: sums exceed float64 integer range");
  const m = { ...agg, outcomes };
  cache2.set(key, m);
  return { ...m, workers: nW };
}
function solveCascadeExact(def, opts = {}) {
  const T = compileCascade(def);
  if (!T)
    return null;
  const t0 = performance.now();
  const m = enumerateCascade(T, opts);
  const N = m.outcomes, ev = new Rational(BigInt(m.sum), N), m2 = new Rational(BigInt(m.sumSq), N);
  const bet = def.wager?.totalBet ?? 1n;
  return { ev, secondMoment: m2, variance: m2.sub(ev.mul(ev)), hitRate: new Rational(BigInt(m.hits), N), outcomes: N, evaluated: m.evaluated, maxPayout: BigInt(m.max), bet, rtp: ev.div(new Rational(bet)), workers: m.workers, ms: performance.now() - t0, method: "CASCADE_DENSE_STOP_ENUMERATION" };
}

// dist/src/math/primitives/folds/maskMarkov.js
function compileHoldWin(def) {
  const modes = Object.values(def.modes);
  if (modes.length !== 2)
    return null;
  const base3 = def.modes[def.entryModeId];
  if (!base3)
    return null;
  const bn = base3.nodes, ball = Object.values(bn);
  const lock = ball.find((n) => n.kind === "HOLD_COINS");
  if (!lock)
    return null;
  const spin2 = bn[base3.entryNodeId];
  if (spin2?.source?.type !== "REEL_SPIN")
    return null;
  const count = ball.find((n) => n.evaluator?.type === "COUNT_TAG" && n.evaluator.tag === lock.tag);
  const trig = ball.find((n) => n.kind === "CONDITION" && n.expression?.left?.ref === count?.output && n.onTrue === lock.id);
  if (!count || !trig || trig.expression.op !== ">=" || nodes(bn, trig.onFalse)?.operation?.type !== "END_GAME")
    return null;
  const setR = bn[lock.next];
  if (setR?.kind !== "STATE" || setR.op !== "SET")
    return null;
  const rKey = setR.target;
  const enter2 = bn[setR.next];
  if (enter2?.operation?.type !== "ENTER_MODE")
    return null;
  const hold = def.modes[enter2.operation.modeId];
  const hn = hold.nodes;
  const respin = hn[hold.entryNodeId];
  if (respin?.source?.type !== "REEL_SPIN")
    return null;
  const hl = hn[respin.next];
  if (hl?.kind !== "HOLD_COINS" || hl.stateKey !== lock.stateKey || hl.tag !== lock.tag || hl.paytableId !== lock.paytableId)
    return null;
  const full = hn[hl.next], grand = hn[full?.onTrue], landed = hn[full?.onFalse];
  if (full?.kind !== "CONDITION" || full.expression.op !== ">=" || full.expression.left.ref !== `${hl.output}.filled` || grand?.kind !== "AWARD" || !("const" in grand.amount))
    return null;
  const pay = hn[grand.next];
  if (pay?.kind !== "AWARD" || pay.amount.ref !== `${hl.output}.total` || hn[pay.next]?.operation?.type !== "END_GAME")
    return null;
  if (landed?.kind !== "CONDITION" || landed.expression.left.ref !== `${hl.output}.new` || landed.expression.op !== ">" || Number(landed.expression.right.const) !== 0)
    return null;
  const reset = hn[landed.onTrue], dec = hn[landed.onFalse], more = hn[dec?.next];
  if (reset?.target !== rKey || reset.op !== "SET" || Number(reset.value.const) !== Number(setR.value.const) || reset.next !== respin.id)
    return null;
  if (dec?.target !== rKey || dec.op !== "ADD" || Number(dec.value.const) !== -1 || more?.kind !== "CONDITION" || more.expression.op !== ">" || Number(more.expression.right.const) !== 0 || more.onTrue !== respin.id || more.onFalse !== pay.id)
    return null;
  const lines = bn[spin2.next];
  if (lines?.evaluator?.type !== "PAYLINES" || lines.evaluator.board !== spin2.output)
    return null;
  const sum = bn[lines.next];
  if (sum?.evaluator?.type !== "SUM_WINS" || sum.evaluator.wins !== lines.output)
    return null;
  const aw = bn[sum.next];
  if (aw?.kind !== "AWARD" || aw.amount.ref !== sum.output || aw.next !== count?.id || count.next !== trig.id)
    return null;
  const rows = Number(spin2.source.rows), bR = def.reelSets[spin2.source.reelSetId].reels, hR = def.reelSets[respin.source.reelSetId].reels;
  if (Number(respin.source.rows) !== rows || bR.length !== hR.length || Number(full.expression.right.const) !== rows * bR.length)
    return null;
  const coinValue2 = {};
  for (const [s, d] of Object.entries(def.symbols))
    if (d.tags.includes(lock.tag))
      coinValue2[s] = Number(def.paytables[lock.paytableId].pays[s]?.[1] ?? 0n);
  return { linePaytableId: lines.evaluator.paytableId, lineIds: [...lines.evaluator.paylineIds], wildTag: lines.evaluator.wildTag, rows, cols: bR.length, baseReels: bR.map((r) => [...r.symbols]), holdReels: hR.map((r) => [...r.symbols]), coinValue: coinValue2, trigger: Number(trig.expression.right.const), respins: Number(setR.value.const), grand: Number(grand.amount.const) };
}
var nodes = (n, id) => n[id];
function coinTables(S, reels) {
  const P = 1 << S.rows;
  const isCoin = (s) => s in S.coinValue;
  return reels.map((st) => Array.from({ length: P }, (_, p) => maskUpdateColumn(st, S.rows, p, isCoin, (s) => S.coinValue[s]).map(([q, n, v]) => [q, n / st.length, v / st.length])));
}
function holdWinValueFunction(S) {
  const { rows: R2, cols: C, respins: RS, grand: G } = S, P = 1 << R2, FULL = 2 ** (R2 * C) - 1;
  const T = coinTables(S, S.holdReels);
  const order = Array.from({ length: FULL + 1 }, (_, i) => i).sort((a, b) => popcount(b) - popcount(a));
  const V = new Float64Array(FULL + 1);
  let terms = 0;
  for (const m of order) {
    if (m === FULL) {
      V[m] = G;
      continue;
    }
    const pats = Array.from({ length: C }, (_, c2) => m >> R2 * c2 & P - 1);
    let q = 1;
    for (let c2 = 0; c2 < C; c2++) {
      const e = T[c2][pats[c2]].find((x) => x[0] === pats[c2]);
      q *= e ? e[1] : 0;
    }
    let A = 0;
    const rec = (c2, mm, pr, ev) => {
      if (c2 === C) {
        if (mm === m)
          return;
        terms++;
        A += ev + pr * V[mm];
        return;
      }
      for (const [q2, p, e] of T[c2][pats[c2]])
        rec(c2 + 1, mm | q2 << R2 * c2, pr * p, ev * p + e * pr);
    };
    rec(0, 0, 1, 0);
    V[m] = A * respinResetGeometric(q, RS);
  }
  return { V, terms, FULL };
}
function exactLineEV(def, S) {
  return new Rational(maskedLinePayNumerator(def, { paytableId: S.linePaytableId, lineIds: S.lineIds, wildTag: S.wildTag, cols: S.cols }, S.baseReels), stopSpace(S.baseReels));
}
function solveHoldWinExact(def, _opts = {}) {
  const S = compileHoldWin(def);
  if (!S)
    return null;
  const t0 = performance.now();
  const { V, terms, FULL } = holdWinValueFunction(S);
  const B = coinTables(S, S.baseReels).map((t) => t[0]);
  let pT = 0, evT = 0, coinT = 0;
  const rec = (c2, mm, pr, ev2) => {
    if (c2 === S.cols) {
      if (popcount(mm) >= S.trigger) {
        pT += pr;
        coinT += ev2;
        evT += ev2 + pr * (mm === FULL ? S.grand : V[mm]);
      }
      return;
    }
    for (const [q2, p, e] of B[c2])
      rec(c2 + 1, mm | q2 << S.rows * c2, pr * p, ev2 * p + e * pr);
  };
  rec(0, 0, 1, 0);
  const line = exactLineEV(def, S);
  const bet = def.wager?.totalBet ?? 1n;
  const ev = line.toNumber() + evT;
  return { ev, rtp: ev / Number(bet), bet, lineEV: line, featureEV: evT, featureTriggerProbability: pT, featureEVGivenTrigger: evT / pT, coinsEVAtTrigger: coinT / pT, states: (FULL + 1) * S.respins, transitionTerms: terms, ms: performance.now() - t0, method: "HOLD_WIN_MASK_RESPIN_MARKOV" };
}
function compileStickyWild(def) {
  const base3 = def.modes[def.entryModeId];
  if (!base3 || Object.keys(def.modes).length !== 2)
    return null;
  const bn = base3.nodes;
  const sp = bn[base3.entryNodeId];
  if (sp?.source?.type !== "REEL_SPIN")
    return null;
  const li = bn[sp.next];
  if (li?.evaluator?.type !== "PAYLINES" || li.evaluator.board !== sp.output)
    return null;
  const su = bn[li.next];
  if (su?.evaluator?.type !== "SUM_WINS" || su.evaluator.wins !== li.output)
    return null;
  const aw = bn[su.next];
  if (aw?.kind !== "AWARD" || aw.amount?.ref !== su.output)
    return null;
  const ct = bn[aw.next];
  if (ct?.evaluator?.type !== "COUNT_TAG" || ct.evaluator.board !== sp.output)
    return null;
  const tr = bn[ct.next];
  if (tr?.kind !== "CONDITION" || tr.expression.op !== ">=" || tr.expression.left?.ref !== ct.output || bn[tr.onFalse]?.operation?.type !== "END_GAME")
    return null;
  const set = bn[tr.onTrue];
  if (set?.kind !== "STATE" || set.op !== "SET")
    return null;
  const en = bn[set.next];
  if (en?.operation?.type !== "ENTER_MODE")
    return null;
  const F = compileStickyFS(def, en.operation.modeId, set.target, Number(set.value.const));
  if (!F || F.rows !== Number(sp.source.rows))
    return null;
  if (F.paytableId !== li.evaluator.paytableId || F.lineIds.join() !== li.evaluator.paylineIds.join() || (li.evaluator.wildTag ?? "WILD") !== F.wildTag)
    return null;
  const bR = def.reelSets[sp.source.reelSetId].reels;
  if (bR.length !== F.cols)
    return null;
  return { ...F, baseReels: bR.map((r) => [...r.symbols]), scatterTag: ct.evaluator.tag, trigger: Number(tr.expression.right.const) };
}
function compileStickyFS(def, fsModeId, counter, spins) {
  const fm = def.modes[fsModeId];
  if (!fm)
    return null;
  const fn = fm.nodes;
  const fsp = fn[fm.entryNodeId];
  if (fsp?.source?.type !== "REEL_SPIN")
    return null;
  const st = fn[fsp.next];
  if (st?.kind !== "STICKY_WILD" || st.board !== fsp.output)
    return null;
  const fl = fn[st.next];
  if (fl?.evaluator?.type !== "PAYLINES" || fl.evaluator.board !== st.output)
    return null;
  const fs2 = fn[fl.next];
  if (fs2?.evaluator?.type !== "SUM_WINS" || fs2.evaluator.wins !== fl.output)
    return null;
  const fa = fn[fs2.next];
  if (fa?.kind !== "AWARD" || fa.amount?.ref !== fs2.output)
    return null;
  const dec = fn[fa.next];
  if (dec?.kind !== "STATE" || dec.op !== "ADD" || dec.target !== counter || Number(dec.value.const) !== -1)
    return null;
  const mo = fn[dec.next];
  if (mo?.kind !== "CONDITION" || mo.expression.op !== ">" || mo.expression.left?.ref !== `$state.${counter}` || Number(mo.expression.right.const) !== 0 || mo.onTrue !== fsp.id || fn[mo.onFalse]?.operation?.type !== "END_GAME")
    return null;
  const wildTag = fl.evaluator.wildTag ?? "WILD";
  if (!def.symbols[st.wild]?.tags.includes(wildTag))
    return null;
  const fR = def.reelSets[fsp.source.reelSetId].reels;
  return { paytableId: fl.evaluator.paytableId, lineIds: [...fl.evaluator.paylineIds], wildTag, wild: st.wild, rows: Number(fsp.source.rows), cols: fR.length, fsReels: fR.map((r) => [...r.symbols]), spins };
}
function stickyFsValue(def, S) {
  const { rows: R2, cols: C } = S;
  const LS = { paytableId: S.paytableId, lineIds: S.lineIds, wildTag: S.wildTag, cols: C };
  const D = stopSpace(S.fsReels);
  const colT = S.fsReels.map((st) => maskUpdateColumn(st, R2, 0, (s) => s === S.wild).map(([p, n]) => [p, BigInt(n)]));
  const trans = (m) => {
    let acc = /* @__PURE__ */ new Map([[m, 1n]]);
    for (let c2 = 0; c2 < C; c2++) {
      const nx = /* @__PURE__ */ new Map();
      for (const [mm, w] of acc)
        for (const [p, k] of colT[c2]) {
          const q = mm | columnToMask(c2, p, R2, C);
          nx.set(q, (nx.get(q) ?? 0n) + w * k);
        }
      acc = nx;
    }
    return acc;
  };
  const seen = /* @__PURE__ */ new Set([0]), stack = [0], T = /* @__PURE__ */ new Map();
  while (stack.length) {
    const m = stack.pop();
    const t = trans(m);
    T.set(m, t);
    for (const q of t.keys())
      if (!seen.has(q)) {
        seen.add(q);
        stack.push(q);
      }
  }
  const cache3 = /* @__PURE__ */ new Map(), Np = /* @__PURE__ */ new Map();
  for (const m of seen)
    Np.set(m, maskedLinePayNumerator(def, LS, S.fsReels, m, S.wild, cache3));
  let U = new Map([...seen].map((m) => [m, 0n]));
  let Dk = 1n;
  for (let k = 1; k <= S.spins; k++) {
    const nu = /* @__PURE__ */ new Map();
    for (const m of seen) {
      let s = Np.get(m) * Dk;
      for (const [q, w] of T.get(m))
        s += w * U.get(q);
      nu.set(m, s);
    }
    U = nu;
    Dk *= D;
  }
  return { fsEV: new Rational(U.get(0), Dk), reachableMasks: seen.size };
}
function solveStickyWildExact(def) {
  const S = compileStickyWild(def);
  if (!S)
    return null;
  const t0 = performance.now();
  const LS = { paytableId: S.paytableId, lineIds: S.lineIds, wildTag: S.wildTag, cols: S.cols };
  const R2 = S.rows;
  const DB = stopSpace(S.baseReels);
  const { fsEV, reachableMasks } = stickyFsValue(def, S);
  const seen = { size: reachableMasks };
  const dist = tagCountDistribution(S.baseReels, R2, (s) => !!def.symbols[s]?.tags.includes(S.scatterTag));
  let trig = 0n;
  dist.forEach((w, i) => {
    if (i >= S.trigger && w)
      trig += w;
  });
  const pT = new Rational(trig, DB);
  const baseLine = new Rational(maskedLinePayNumerator(def, LS, S.baseReels), DB);
  const { ev, featureEV } = composeRegen(baseLine, pT, fsEV);
  const bet = def.wager?.totalBet ?? 1n;
  return { ev, bet, rtp: ev.div(new Rational(bet)), baseLineEV: baseLine, featureEV, featureTriggerProbability: pT, featureEVGivenTrigger: fsEV, reachableMasks: seen.size, states: seen.size * S.spins, ms: performance.now() - t0, method: "STICKY_WILD_MASK_SPINS_MARKOV" };
}

// dist/src/math/primitives/folds/compose.js
var clone = (x) => structuredClone(x);
var js = (x) => JSON.stringify(x, (_, v) => typeof v === "bigint" ? String(v) : v);
function splitFsTrigger(def) {
  const base3 = def.modes[def.entryModeId];
  if (!base3)
    return null;
  const bn = base3.nodes;
  for (const ct of Object.values(bn)) {
    if (ct.evaluator?.type !== "COUNT_TAG")
      continue;
    const chk = Object.values(bn).find((n) => n.kind === "CONDITION" && n.expression?.op === ">=" && n.expression.left?.ref === ct.output);
    if (!chk)
      continue;
    const set = bn[chk.onTrue];
    if (set?.kind !== "STATE" || set.op !== "SET" || !("const" in (set.value ?? {})))
      continue;
    const en = bn[set.next];
    if (en?.operation?.type !== "ENTER_MODE")
      continue;
    const fsModeId = en.operation.modeId;
    const fm = def.modes[fsModeId];
    if (!fm || fsModeId === def.entryModeId)
      continue;
    const uses = Object.values(bn).filter((n) => n !== chk && js(n).includes(`"${ct.output}"`) && n !== ct);
    if (uses.length)
      continue;
    if (Object.values(fm.nodes).some((n) => n.operation?.type === "ENTER_MODE"))
      continue;
    const sb = clone(def);
    const nb = sb.modes[sb.entryModeId].nodes;
    const redirect = (id) => id === ct.id ? ct.next : id === chk.id ? chk.onFalse : id;
    for (const k of [ct.id, chk.id, set.id, en.id])
      delete nb[k];
    for (const n of Object.values(nb))
      for (const f of ["next", "onTrue", "onFalse"])
        if (typeof n[f] === "string")
          n[f] = redirect(redirect(n[f]));
    if (sb.modes[sb.entryModeId].entryNodeId === ct.id)
      sb.modes[sb.entryModeId].entryNodeId = ct.next;
    delete sb.modes[fsModeId];
    if (Object.values(sb.modes).some((m) => js(m).includes(`"${fsModeId}"`)))
      continue;
    const entry = clone(def);
    entry.entryModeId = "FS_ENTRY";
    entry.modes = { FS_ENTRY: { id: "FS_ENTRY", entryNodeId: "fs_set", nodes: { fs_set: { ...clone(set), id: "fs_set", next: "fs_enter" }, fs_enter: { ...clone(en), id: "fs_enter" } } }, [fsModeId]: clone(fm) };
    const sticky = Object.values(fm.nodes).some((n) => n.kind === "STICKY_WILD");
    return { scatterTag: ct.evaluator.tag, trigger: Number(chk.expression.right.const), spins: Number(set.value.const), counter: set.target, fsModeId, base: sb, entry, sticky };
  }
  return null;
}
function fsEntryValue(def, sp, regenEV2) {
  if (sp.sticky) {
    const S = compileStickyFS(def, sp.fsModeId, sp.counter, sp.spins);
    if (!S)
      return null;
    return { value: stickyFsValue(def, S).fsEV, inner: "maskMarkov" };
  }
  const v = regenEV2(sp.entry);
  return v ? { value: v, inner: "regen" } : null;
}
function solveCascadeFreeSpins(def, regenEV2, opts = {}) {
  const sp = splitFsTrigger(def);
  if (!sp || sp.sticky)
    return null;
  if (!compileCascade(sp.base))
    return null;
  const t0 = performance.now();
  const F = fsEntryValue(def, sp, regenEV2);
  if (!F)
    return null;
  const c2 = solveCascadeExact(sp.base, opts);
  if (!c2)
    return null;
  const bm = sp.base.modes[sp.base.entryModeId];
  const spin2 = Object.values(bm.nodes).find((n) => n.source?.type === "REEL_SPIN");
  const reels = def.reelSets[spin2.source.reelSetId].reels.map((r) => r.symbols);
  const dist = tagCountDistribution(reels, Number(spin2.source.rows), (s) => !!def.symbols[s]?.tags.includes(sp.scatterTag));
  let w = 0n;
  dist.forEach((x, i) => {
    if (i >= sp.trigger && x)
      w += x;
  });
  const pT = new Rational(w, stopSpace(reels));
  const { ev, featureEV } = composeRegen(c2.ev, pT, F.value);
  const bet = def.wager?.totalBet ?? 1n;
  return { ev, bet, rtp: ev.div(new Rational(bet)), baseEV: c2.ev, featureEV, featureTriggerProbability: pT, featureEVGivenTrigger: F.value, base: "stopEnum", inner: F.inner, exactRational: true, method: "COMPOSE(stopEnum base, regen FS)", ms: performance.now() - t0, cascade: c2 };
}
function solveHoldWinFreeSpins(def, regenEV2) {
  const sp = splitFsTrigger(def);
  if (!sp)
    return null;
  const S = compileHoldWin(sp.base);
  if (!S)
    return null;
  const t0 = performance.now();
  const F = fsEntryValue(def, sp, regenEV2);
  if (!F)
    return null;
  const Fn = F.value.toNumber();
  const { V, FULL } = holdWinValueFunction(S);
  const R2 = S.rows, cap = sp.trigger;
  const isScat = (s) => !!def.symbols[s]?.tags.includes(sp.scatterTag);
  const cols = S.baseReels.map((st) => {
    const m = /* @__PURE__ */ new Map(), L = st.length;
    for (let i = 0; i < L; i++) {
      let sc = 0, p = 0, v = 0;
      for (let r = 0; r < R2; r++) {
        const s = st[(i + r) % L];
        if (isScat(s))
          sc++;
        if (s in S.coinValue) {
          p |= 1 << r;
          v += S.coinValue[s];
        }
      }
      const k = `${sc}|${p}`;
      const e = m.get(k) ?? [sc, p, 0, 0];
      e[2] += 1 / L;
      e[3] += v / L;
      m.set(k, e);
    }
    return [...m.values()];
  });
  let pFS = 0, pH = 0, evH = 0;
  const rec = (c2, sc, mm, pr, ev2) => {
    if (c2 === S.cols) {
      if (sc >= cap)
        pFS += pr;
      else if (popcount(mm) >= S.trigger) {
        pH += pr;
        evH += ev2 + pr * (mm === FULL ? S.grand : V[mm]);
      }
      return;
    }
    for (const [s, q, p, e] of cols[c2])
      rec(c2 + 1, Math.min(cap, sc + s), mm | q << R2 * c2, pr * p, ev2 * p + e * pr);
  };
  rec(0, 0, 0, 1, 0);
  const line = exactLineEV(sp.base, S);
  const featureEV = pFS * Fn + evH;
  const ev = line.toNumber() + featureEV;
  const bet = def.wager?.totalBet ?? 1n;
  return { ev, bet, rtp: ev / Number(bet), baseEV: line, featureEV, featureTriggerProbability: pFS, featureEVGivenTrigger: F.value, holdEV: evH, base: "maskMarkov", inner: F.inner, exactRational: false, method: "COMPOSE(maskMarkov coin base, FS)", ms: performance.now() - t0, spec: S };
}

// dist/src/math/primitives/runner.js
var foldQueries = { stopEnum: ["EV", "RTP", "VARIANCE", "HIT_RATE"], maskMarkovCoin: ["EV", "RTP"], maskMarkovSticky: ["EV", "RTP"], composed: ["EV", "RTP"] };
var cascadeFsFold = { kind: "regen", inner: { kind: "stopEnum", ladder: true }, base: { kind: "stopEnum", ladder: true }, buyOnly: false, retrigger: false };
var holdFsFold = (sticky) => ({ kind: "regen", inner: sticky ? { kind: "maskMarkov", mask: "stickyWild" } : { kind: "columnDP", observe: ["lines"] }, base: { kind: "maskMarkov", mask: "coin" }, buyOnly: false, retrigger: false });
function specialisedFold(def) {
  if (compileCascade(def))
    return { kind: "stopEnum", ladder: true };
  if (compileHoldWin(def))
    return { kind: "maskMarkov", mask: "coin" };
  if (compileStickyWild(def))
    return { kind: "regen", inner: { kind: "maskMarkov", mask: "stickyWild" }, buyOnly: false, retrigger: false };
  const sp = splitFsTrigger(def);
  if (sp && !sp.sticky && compileCascade(sp.base))
    return cascadeFsFold;
  if (sp && compileHoldWin(sp.base))
    return holdFsFold(sp.sticky);
  return null;
}
function genericFold(def, execution) {
  if (!execution.math.exact)
    return { kind: "mc", reason: execution.math.diagnostics.at(-1) ?? "no exact fold" };
  return genericFoldPlan(def, execution);
}
var plan = (def, query, options) => buildExecutionPlan(def, query, { pgfZ: options.pgfZ, maxStates: options.maxStates, mcSamples: options.mcSamples, lowering: options.lowering, handlers: options.handlers, reelObservations: options.reelObservations, solverCapabilities: options.solverCapabilities, compiledQuery: options.compiledQuery });
function holdStateBoundExceeded(def, options) {
  const sp = splitFsTrigger(def);
  const S = sp && compileHoldWin(sp.base);
  if (!S)
    return false;
  const states = Math.pow(1 + Object.keys(S.coinValue).length, S.rows * S.cols) * S.respins;
  return states > (options.maxStates ?? defaultSolverBudget.maxStates);
}
function isCascadeStructure(def) {
  const f = specialisedFold(def);
  return !!f && (f.kind === "stopEnum" || f.kind === "regen" && f.base?.kind === "stopEnum");
}
function runSpecialisedFold(def, query, options = {}) {
  const q = query.type;
  if (foldQueries.composed.includes(q)) {
    const regenEV2 = (d) => {
      try {
        const m = regenerativeSolve(d, {}).mean;
        if (m instanceof Rational)
          return m;
      } catch {
      }
      const r = runPipeline(d, { type: "EV" }, options);
      const ev = r.result.ev;
      return r.plan.exact && ev instanceof Rational ? ev : null;
    };
    const c2 = solveCascadeFreeSpins(def, regenEV2);
    if (c2)
      return { fold: cascadeFsFold, ...composedAnswer(query, c2) };
    const h = solveHoldWinFreeSpins(def, regenEV2);
    if (h)
      return { fold: holdFsFold(h.inner === "maskMarkov"), ...composedAnswer(query, h) };
  }
  if (foldQueries.stopEnum.includes(q)) {
    const r = solveCascadeExact(def);
    if (r)
      return { fold: { kind: "stopEnum", ladder: true }, ...cascadeAnswer(query, r) };
  }
  if (foldQueries.maskMarkovCoin.includes(q)) {
    const r = solveHoldWinExact(def);
    if (r)
      return { fold: { kind: "maskMarkov", mask: "coin" }, ...holdWinAnswer(query, r) };
  }
  if (foldQueries.maskMarkovSticky.includes(q)) {
    const r = solveStickyWildExact(def);
    if (r)
      return { fold: { kind: "regen", inner: { kind: "maskMarkov", mask: "stickyWild" }, buyOnly: false, retrigger: false }, ...stickyAnswer(query, r) };
  }
  return null;
}
function runPipeline(def, query, options = {}) {
  if (isCascadeStructure(def)) {
    const spec = runSpecialisedFold(def, query, options);
    if (spec)
      return spec;
  }
  const execution = plan(def, query, options);
  if (!execution.math.exact || holdStateBoundExceeded(def, options)) {
    const spec = runSpecialisedFold(def, query, options);
    if (spec)
      return spec;
  }
  const kind = execution.decision.kind, fold = genericFold(def, execution);
  const result = fold.kind !== "mc" && (kind === "DIRECT" || kind === "STATE_EXACT") && !options.backendExecutors?.[kind] ? runExactFold({ def, query, execution, options }) : executeBackend({ def, query, execution, options });
  return { fold, plan: execution.math, result };
}
var mkPlan = (query, solver, fold, scope, reason, diag, reductions) => ({ query, solver, exact: true, observables: [], livePersistentState: [], syntheticState: [], reductions, stages: [{ id: `fold:${fold}`, solver, scope, reason }], diagnostics: [`fold=${fold}`, ...diag], estimatedSourceOutcomes: {} });
function cascadeAnswer(query, r) {
  const p = mkPlan(query, "ENUM", "stopEnum", "paid spin stops (whole tumble chain)", "Spin \u2192 (WinCells \u2192 BoardDynamics \u2192 Refill(strip) \u2192 CounterStep ladder)*: deterministic in the stop vector, dense enumeration", [`outcomes=${r.outcomes}`, `evaluated=${r.evaluated}`, `workers=${r.workers}`, `ms=${r.ms.toFixed(0)}`, r.method], [{ kind: "PRUNE", scope: "reels 1-3", reason: "no paying 3-of-a-kind on reels 1-3 => zero win, no tumble" }]);
  const mean2 = r.ev;
  let result;
  switch (query.type) {
    case "EV":
      result = { ev: mean2, baseEV: mean2, featureEV: null, featureTriggerProbability: null, expectedFeatureSpins: null };
      break;
    case "RTP": {
      const bet = query.bet ?? r.bet;
      result = { ev: mean2, baseEV: mean2, featureEV: null, featureTriggerProbability: null, expectedFeatureSpins: null, bet, rtp: mean2.div(new Rational(bet)) };
      break;
    }
    case "VARIANCE":
      result = { mean: mean2, secondMoment: r.secondMoment, variance: r.variance, featureMean: new Rational(0n), featureSecondMoment: new Rational(0n) };
      break;
    case "HIT_RATE": {
      const h = r.hitRate.toNumber();
      result = { hitRate: h, missRate: 1 - h, featureZeroProbability: 1, fixedPointResidual: 0, iterations: 0 };
      break;
    }
  }
  return { plan: p, result };
}
function holdWinAnswer(query, r) {
  const p = mkPlan(query, "MARKOV", "maskMarkov", "HOLD feature: (locked mask, respins)", "CellMask(coin) \xD7 CounterStep(respinReset) Markov chain by popcount order; Pay(maskSum+grand) by linearity; base lines by column DP", [`states=${r.states}`, `transitionTerms=${r.transitionTerms}`, `ms=${r.ms.toFixed(0)}`, r.method, "feature part float64 exact enumeration (no sampling)"], [{ kind: "LINEARITY", scope: "HOLD", variable: "locked coin values", reason: "payout additive in locked values; landing law independent of values" }]);
  const bet = query.type === "RTP" ? query.bet ?? r.bet : r.bet;
  const result = { ev: r.ev, rtp: r.ev / Number(bet), bet, exact: true, method: r.method, lineEV: r.lineEV, featureEV: r.featureEV, featureTriggerProbability: r.featureTriggerProbability, details: r };
  return { plan: p, result };
}
function stickyAnswer(query, r) {
  const p = mkPlan(query, "MARKOV", "regen(maskMarkov)", "FREE_SPINS: (sticky wild mask, spins left)", "CellMask(stickyWild) \xD7 CounterStep(stepDown) Markov chain; per-line Pay given mask; base trigger law (tagCount) outer; integer-scaled exact Rational", [`reachableMasks=${r.reachableMasks}`, `states=${r.states}`, `ms=${r.ms.toFixed(0)}`, r.method], [{ kind: "LINEARITY", scope: "FREE_SPINS", variable: "line pay", reason: "E[pay+V(next)]=E[pay|mask]+E[V(next)|mask]" }]);
  const bet = query.type === "RTP" ? query.bet ?? r.bet : r.bet;
  const result = { ev: r.ev, baseEV: r.baseLineEV, featureEV: r.featureEV, featureTriggerProbability: r.featureTriggerProbability, featureEVGivenTrigger: r.featureEVGivenTrigger, expectedFeatureSpins: null, bet, rtp: r.ev.div(new Rational(bet)), exact: true, method: r.method, details: r };
  return { plan: p, result };
}
function composedAnswer(query, r) {
  const fold = `regen(${r.base}+${r.inner})`;
  const p = mkPlan(query, r.base === "stopEnum" ? "ENUM" : "MARKOV", fold, "paid round: base fold + FS entry", r.base === "stopEnum" ? "split FS trigger: stopEnum(base tumble chain) + P(scatter\u2265S on paid board)\xB7E[FS | entry] (composeRegen, linearity)" : "split FS trigger: joint column law (scatter count, coin mask) \u2192 FS has precedence over HOLD; maskMarkov(coin) V[mask] + P(FS)\xB7E[FS | entry]", [r.method, `ms=${r.ms.toFixed(0)}`, ...r.exactRational ? [] : ["feature part float64 exact enumeration (no sampling)"]], [{ kind: "LINEARITY", scope: "paid round", variable: "base pay + feature pay", reason: "EV(round)=EV(base)+\u03A3 P(entry)\xB7E[feature|entry]; feature starts from a fixed state" }]);
  const bet = query.type === "RTP" ? query.bet ?? r.bet : r.bet;
  const rtp = r.ev instanceof Rational ? r.ev.div(new Rational(bet)) : r.ev / Number(bet);
  const result = { ev: r.ev, baseEV: r.baseEV, featureEV: r.featureEV, featureTriggerProbability: r.featureTriggerProbability, featureEVGivenTrigger: r.featureEVGivenTrigger, expectedFeatureSpins: null, bet, rtp, exact: true, method: r.method, details: r };
  return { plan: p, result };
}

// dist/src/math/queryEngine.js
function solve(def, query, options = {}) {
  const r = runPipeline(def, query, options);
  return { query, plan: r.plan, result: r.result, fold: r.fold };
}

// dist/src/math/extensions.js
var ENGINE_EXTENSION_API = { major: 1, minor: 1 };
function compatible(r) {
  return r.major === ENGINE_EXTENSION_API.major && (r.minMinor ?? 0) <= ENGINE_EXTENSION_API.minor && (r.maxMinor ?? Number.MAX_SAFE_INTEGER) >= ENGINE_EXTENSION_API.minor;
}
function validSemver(v) {
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(v);
}
function assertFree(owner, kind, key) {
  const previous = owner.get(key);
  if (previous)
    throw new Error(`${kind} already registered: ${key} by ${previous}`);
}
function createExtensionRegistry() {
  const extensions = /* @__PURE__ */ new Map(), queries = /* @__PURE__ */ new Map(), nodes2 = /* @__PURE__ */ new Map();
  const sources = /* @__PURE__ */ new Map(), evaluators = /* @__PURE__ */ new Map(), reelObservations = /* @__PURE__ */ new Map(), backendExecutors = /* @__PURE__ */ new Map(), observables = /* @__PURE__ */ new Map(), projectors = /* @__PURE__ */ new Map(), capabilities = /* @__PURE__ */ new Map();
  return {
    extensions,
    register(extension) {
      if (!extension.id.trim())
        throw new Error("extension id must be non-empty");
      if (!validSemver(extension.version))
        throw new Error(`extension ${extension.id}: version must be semver`);
      if (!compatible(extension.compatibility.engineApi))
        throw new Error(`extension ${extension.id}@${extension.version} is incompatible with engine extension API ${ENGINE_EXTENSION_API.major}.${ENGINE_EXTENSION_API.minor}`);
      if (extensions.has(extension.id))
        throw new Error(`extension already registered: ${extension.id}`);
      const queryTypes = extension.queryTypes ?? [], nodeTypes = extension.nodeTypes ?? [], sourceKeys = Object.keys(extension.sources ?? {}), evaluatorKeys = Object.keys(extension.evaluators ?? {}), observationKeys = Object.keys(extension.reelObservations ?? {}), executorKeys = Object.keys(extension.backendExecutors ?? {});
      const observableKeys = Object.keys(extension.observables ?? {}), projectorKeys = Object.keys(extension.hybridProjectors ?? {}), capabilityKeys = (extension.solverCapabilities ?? []).map((x) => x.id);
      const localUnique = (kind, keys) => {
        const seen = /* @__PURE__ */ new Set();
        for (const key of keys) {
          if (seen.has(key))
            throw new Error(`${kind} duplicated inside extension ${extension.id}: ${key}`);
          seen.add(key);
        }
      };
      localUnique("query type", queryTypes.map((x) => x.type));
      localUnique("node kind", nodeTypes.map((x) => x.kind));
      localUnique("solver capability", capabilityKeys);
      for (const q of queryTypes)
        if (queries.has(q.type))
          throw new Error(`query type already registered: ${q.type}`);
      for (const n of nodeTypes)
        if (nodes2.has(n.kind))
          throw new Error(`node kind already registered: ${n.kind}`);
      for (const key of sourceKeys)
        assertFree(sources, "source", key);
      for (const key of evaluatorKeys)
        assertFree(evaluators, "evaluator", key);
      for (const key of observationKeys)
        assertFree(reelObservations, "reel observation", key);
      for (const key of executorKeys)
        assertFree(backendExecutors, "backend executor", key);
      for (const key of observableKeys)
        assertFree(observables, "observable", key);
      for (const key of projectorKeys)
        assertFree(projectors, "hybrid projector", key);
      for (const key of capabilityKeys)
        assertFree(capabilities, "solver capability", key);
      extensions.set(extension.id, extension);
      for (const q of queryTypes)
        queries.set(q.type, q);
      for (const n of nodeTypes)
        nodes2.set(n.kind, n);
      for (const key of sourceKeys)
        sources.set(key, extension.id);
      for (const key of evaluatorKeys)
        evaluators.set(key, extension.id);
      for (const key of observationKeys)
        reelObservations.set(key, extension.id);
      for (const key of executorKeys)
        backendExecutors.set(key, extension.id);
      for (const key of observableKeys)
        observables.set(key, extension.id);
      for (const key of projectorKeys)
        projectors.set(key, extension.id);
      for (const key of capabilityKeys)
        capabilities.set(key, extension.id);
    },
    buildNodeHandlers(base3) {
      const out = { ...base3 };
      for (const d of nodes2.values())
        if (d.handler)
          out[d.kind] = d.handler;
      return out;
    },
    buildLowering(base3) {
      const outSources = { ...base3.sources }, outEvaluators = { ...base3.evaluators };
      for (const x of extensions.values()) {
        Object.assign(outSources, x.sources ?? {});
        Object.assign(outEvaluators, x.evaluators ?? {});
      }
      return { sources: outSources, evaluators: outEvaluators };
    },
    buildReelObservations(base3) {
      const out = { ...base3 };
      for (const x of extensions.values())
        Object.assign(out, x.reelObservations ?? {});
      return out;
    },
    buildSolverCapabilities(base3) {
      return [...base3, ...[...extensions.values()].flatMap((x) => x.solverCapabilities ?? [])];
    },
    buildBackendExecutors(base3) {
      const out = { ...base3 };
      for (const x of extensions.values())
        Object.assign(out, x.backendExecutors ?? {});
      return out;
    },
    buildHybridProjectors(base3) {
      const out = { ...base3 };
      for (const x of extensions.values())
        Object.assign(out, x.hybridProjectors ?? {});
      return out;
    },
    observable(name) {
      for (const x of [...extensions.values()].reverse()) {
        const v = x.observables?.[name];
        if (v)
          return v;
      }
      return void 0;
    },
    queryDescriptor(type) {
      return queries.get(type);
    },
    nodeDescriptor(kind) {
      return nodes2.get(kind);
    },
    compileQuery(query, opts = {}) {
      const type = query.type, d = queries.get(type);
      if (!d)
        throw new Error(`unregistered query type: ${type}`);
      if (!d.validate(query))
        throw new Error(`invalid query payload for ${type}`);
      return d.compile(query, opts);
    },
    validateNode(node) {
      const d = nodes2.get(node.kind);
      return !!d && d.validate(node);
    }
  };
}
function defineExtension(x) {
  return { ...x, compatibility: x.compatibility ?? { engineApi: { major: ENGINE_EXTENSION_API.major, minMinor: 0, maxMinor: ENGINE_EXTENSION_API.minor } } };
}

// dist/src/math/bundleManifest.js
var ENGINE_CORE_VERSION = "0.36.0";
var ENGINE_MATH_SEMANTICS = { id: "MATH_IR_V1", version: 1 };
var ENGINE_RNG_SEMANTICS = { algorithm: "ADDRESS_HASH_V1", algorithmVersion: 1, addressingVersion: 1 };
var ENGINE_BUNDLE_MANIFEST_VERSION = 1;
function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string")
    return JSON.stringify(value);
  if (typeof value === "number")
    return Number.isFinite(value) ? JSON.stringify(value) : (() => {
      throw new Error("non-finite manifest number");
    })();
  if (Array.isArray(value))
    return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    const x = value;
    return `{${Object.keys(x).sort().map((k) => `${JSON.stringify(k)}:${canonical(x[k])}`).join(",")}}`;
  }
  throw new Error(`unsupported manifest value: ${typeof value}`);
}
function createEngineBundleManifest(extensions, policies) {
  return Object.freeze({
    manifestVersion: ENGINE_BUNDLE_MANIFEST_VERSION,
    core: Object.freeze({ name: "slot-math-engine", version: ENGINE_CORE_VERSION, extensionApi: Object.freeze({ ...ENGINE_EXTENSION_API }) }),
    extensions: Object.freeze(extensions.map((x) => Object.freeze({ id: x.id, version: x.version })).sort((a, b) => a.id.localeCompare(b.id) || a.version.localeCompare(b.version))),
    policies: Object.freeze({ maxStates: policies.maxStates ?? null, mcSamples: policies.mcSamples ?? null, masterSeed: policies.masterSeed?.toString() ?? null }),
    rng: Object.freeze({ ...ENGINE_RNG_SEMANTICS }),
    math: Object.freeze({ ...ENGINE_MATH_SEMANTICS })
  });
}
function canonicalEngineBundleManifest(manifest) {
  return canonical(manifest);
}
function fingerprintEngineBundle(manifest) {
  return `sha256:${createHash("sha256").update(canonicalEngineBundleManifest(manifest)).digest("hex")}`;
}

// dist/src/math/engine.js
function freezeRecord(x) {
  return Object.freeze(x);
}
function createMathEngine(config = {}) {
  const extensions = createExtensionRegistry();
  for (const extension of config.extensions ?? [])
    extensions.register(extension);
  const handlers = freezeRecord(extensions.buildNodeHandlers(builtinNodeHandlers));
  const rawLowering = extensions.buildLowering(builtinExactLowering);
  const lowering = freezeRecord({ sources: freezeRecord({ ...rawLowering.sources }), evaluators: freezeRecord({ ...rawLowering.evaluators }) });
  const reelObservations = freezeRecord(extensions.buildReelObservations(builtinReelObservationRegistry()));
  const solverCapabilities = Object.freeze(extensions.buildSolverCapabilities(solverCapabilityRegistry));
  const backendExecutors = freezeRecord(extensions.buildBackendExecutors(backendExecutorRegistry));
  const hybridProjectors = freezeRecord(extensions.buildHybridProjectors(hybridProjectorRegistry));
  const policies = freezeRecord({ ...config.policies });
  const manifest = createEngineBundleManifest([...extensions.extensions.values()], policies);
  const id = fingerprintEngineBundle(manifest);
  const observableComponents = Object.freeze(Object.assign({}, ...[...extensions.extensions.values()].map((x) => x.observables ?? {})));
  const queryDescriptors = new Map([...extensions.extensions.values()].flatMap((x) => x.queryTypes ?? []).map((d) => [d.type, d]));
  const bundle = Object.freeze({ manifest, id, handlers, lowering, reelObservations, solverCapabilities, backendExecutors, hybridProjectors });
  return Object.freeze({
    extensions,
    policies,
    bundle,
    bundleId: id,
    play: (def, seed) => play(def, seed, { handlers, evaluators: lowering.evaluators }),
    solve: (def, query, options = {}) => {
      const descriptor = queryDescriptors.get(query.type);
      if (descriptor && !descriptor.validate(query))
        throw new Error(`invalid query payload for ${query.type}`);
      const compiledQuery = descriptor?.compile(query, { pgfZ: options.pgfZ });
      return solve(def, query, { maxStates: policies.maxStates, mcSamples: policies.mcSamples, masterSeed: policies.masterSeed, ...options, handlers, lowering, reelObservations, backendExecutors, hybridProjectors, solverCapabilities, observableComponents, compiledQuery });
    }
  });
}

// dist/src/mechanics/slotMechanics.js
var isWild = (def, s, tag) => def.symbols[s]?.tags.includes(tag) ?? false;
function expandWilds(def, board, wildTag = "WILD") {
  const wildByCol = Array.from({ length: board.cols }, (_, c2) => board.symbols.map((r) => r[c2]).find((s) => isWild(def, s, wildTag)));
  return { ...board, symbols: board.symbols.map((row) => row.map((s, c2) => wildByCol[c2] ?? s)) };
}
function evaluatePayways(def, board, paytableId, wildTag = "WILD") {
  const pt = def.paytables[paytableId], out = [];
  for (const symbolId of Object.keys(pt.pays)) {
    if (isWild(def, symbolId, wildTag))
      continue;
    let ways = 1n, count = 0;
    for (let c2 = 0; c2 < board.cols; c2++) {
      const n = board.symbols.reduce((k, r) => k + (r[c2] === symbolId || isWild(def, r[c2], wildTag) ? 1 : 0), 0);
      if (!n)
        break;
      ways *= BigInt(n);
      count++;
    }
    const pay = pt.pays[symbolId]?.[count] ?? 0n;
    if (pay > 0n)
      out.push({ lineId: `ways:${ways}`, symbolId, count, payout: pay * ways });
  }
  return out;
}
var expand = (d, n, f) => {
  const e = n.evaluator;
  return expandWilds(d, f[e.board], e.wildTag);
};
var payways = (d, n, f) => {
  const e = n.evaluator;
  return evaluatePayways(d, f[e.board], e.paytableId, e.wildTag);
};
function tumble(def, board, wins, reelSetId) {
  const reels = def.reelSets[reelSetId].reels, hit2 = /* @__PURE__ */ new Set();
  for (const w of wins) {
    const line = def.paylines[w.lineId];
    for (let c2 = 0; c2 < w.count; c2++)
      hit2.add(`${line.rows[c2]},${c2}`);
  }
  const cols = Array.from({ length: board.cols }, (_, c2) => {
    const strip2 = reels[c2].symbols, keep = board.symbols.map((r) => r[c2]).filter((_2, r) => !hit2.has(`${r},${c2}`)), removed = board.rows - keep.length;
    const stop = ((board.stops[c2] - removed) % strip2.length + strip2.length) % strip2.length;
    return { stop, cells: [...Array.from({ length: removed }, (_2, i) => strip2[(stop + i) % strip2.length]), ...keep] };
  });
  return { rows: board.rows, cols: board.cols, stops: cols.map((c2) => c2.stop), symbols: Array.from({ length: board.rows }, (_, r) => cols.map((c2) => c2.cells[r])) };
}
var tumbleEval = (d, n, f) => {
  const e = n.evaluator;
  return tumble(d, f[e.board], f[e.wins], e.reelSetId);
};
var coinValue = (def, paytableId, s) => def.paytables[paytableId].pays[s]?.[1] ?? 0n;
function lockCoins(def, board, previous, tag, paytableId) {
  const cells = Array.isArray(previous) ? [...previous] : Array(board.rows * board.cols).fill(null);
  let added = 0;
  for (let r = 0; r < board.rows; r++)
    for (let c2 = 0; c2 < board.cols; c2++) {
      const i = r * board.cols + c2, s = board.symbols[r][c2];
      if (cells[i] === null && def.symbols[s]?.tags.includes(tag)) {
        cells[i] = s;
        added++;
      }
    }
  const filled = cells.filter((x) => x !== null).length, total = cells.reduce((t, x) => x ? t + coinValue(def, paytableId, x) : t, 0n);
  return { cells, added, filled, total };
}
var holdCoins = {
  kind: "HOLD_COINS",
  capabilities: (n) => ({ stochastic: false, enumerable: false, deterministic: true, readsFrame: [n.board], writesFrame: [`${n.output}.new`, `${n.output}.filled`, `${n.output}.total`], readsState: [n.stateKey], writesState: [n.stateKey], mayBranch: false, mayTransitionMode: false }),
  runtime: (c2) => {
    const r = lockCoins(c2.def, c2.frame.get(c2.node.board), c2.state.values[c2.node.stateKey], c2.node.tag, c2.node.paytableId);
    c2.frame.set(`${c2.node.output}.new`, r.added);
    c2.frame.set(`${c2.node.output}.filled`, r.filled);
    c2.frame.set(`${c2.node.output}.total`, r.total);
    return { next: c2.node.next, payload: r, state: { ...c2.state, values: { ...c2.state.values, [c2.node.stateKey]: r.cells } } };
  },
  exact: (c2) => {
    const r = lockCoins(c2.def, c2.frame[c2.node.board], c2.values[c2.node.stateKey], c2.node.tag, c2.node.paytableId);
    c2.frame[`${c2.node.output}.new`] = r.added;
    c2.frame[`${c2.node.output}.filled`] = r.filled;
    c2.frame[`${c2.node.output}.total`] = r.total;
    c2.values[c2.node.stateKey] = r.cells;
    return { next: c2.node.next };
  }
};
function collectValues(def, board, collectorTag, valueTag, paytableId) {
  let n = 0n, sum = 0n;
  for (const row of board.symbols)
    for (const s of row) {
      const t = def.symbols[s]?.tags ?? [];
      if (t.includes(collectorTag))
        n++;
      if (t.includes(valueTag))
        sum += coinValue(def, paytableId, s);
    }
  return n * sum;
}
var collect = (d, n, f) => {
  const e = n.evaluator;
  return collectValues(d, f[e.board], e.collectorTag, e.valueTag, e.paytableId);
};
var expandColumn = (def, col, tag) => {
  const w = col.find((s) => isWild(def, s, tag));
  return w ? col.map(() => w) : col;
};
var expandWildsObservation = (ctx) => {
  const { node, nodes: nodes2, boardAliases } = ctx, e = node?.evaluator;
  if (node?.kind !== "EVALUATE" || e?.type !== "EXPAND_WILDS" || !boardAliases.has(e.board))
    return;
  const lines = nodes2[node.next];
  if (lines?.evaluator?.type !== "PAYLINES" || lines.evaluator.board !== node.output)
    return;
  const inner = builtinReelObservationRegistry().PAYLINES({ ...ctx, node: lines, boardAliases: /* @__PURE__ */ new Set([node.output]) });
  if (!inner)
    return;
  const d = inner.descriptor, tag = e.wildTag ?? "WILD";
  return {
    ...inner,
    consumedNodeIds: [node.id, ...inner.consumedNodeIds],
    erasedFrameNames: [node.output, ...inner.erasedFrameNames],
    descriptor: { ...d, key: `EXPAND_WILDS:${node.id}:${d.key}`, advance: (s, col, c2, def) => d.advance(s, expandColumn(def, col, tag), c2, def) }
  };
};
var paywaysObservation = ({ node, nodes: nodes2, boardAliases }) => {
  const e = node?.evaluator;
  if (node?.kind !== "EVALUATE" || e?.type !== "PAYWAYS" || !boardAliases.has(e.board))
    return;
  const sum = nodes2[node.next];
  if (sum?.evaluator?.type !== "SUM_WINS" || sum.evaluator.wins !== node.output)
    return;
  const tag = e.wildTag ?? "WILD", pid = e.paytableId;
  const syms = (def) => Object.keys(def.paytables[pid].pays).filter((s) => !isWild(def, s, tag));
  return { consumedNodeIds: [node.id, sum.id], erasedFrameNames: [node.output], rewardCandidateOutput: sum.output, descriptor: {
    key: `PAYWAYS:${node.id}:${sum.id}`,
    output: sum.output,
    init: (def) => syms(def).map(() => ({ count: 0, ways: 1n, alive: true })),
    advance: (st, col, _c, def) => {
      const ss = syms(def);
      return st.map((x, i) => {
        if (!x.alive)
          return x;
        const n = col.filter((s) => s === ss[i] || isWild(def, s, tag)).length;
        return n ? { count: x.count + 1, ways: x.ways * BigInt(n), alive: true } : { ...x, alive: false };
      });
    },
    stateKey: (st) => st.map((x) => `${x.count}:${x.ways}:${x.alive ? 1 : 0}`).join("|"),
    finish: (st, def) => {
      const ss = syms(def), pays3 = def.paytables[pid].pays;
      return st.reduce((t, x, i) => t + (pays3[ss[i]]?.[x.count] ?? 0n) * x.ways, 0n);
    }
  } };
};
var collectObservation = ({ node, boardAliases }) => {
  const e = node?.evaluator;
  if (node?.kind !== "EVALUATE" || e?.type !== "COLLECT_VALUES" || !boardAliases.has(e.board))
    return;
  return { consumedNodeIds: [node.id], erasedFrameNames: [], descriptor: {
    key: `COLLECT_VALUES:${node.id}`,
    output: node.output,
    init: () => [0n, 0n],
    advance: ([n, v], col, _c, def) => {
      for (const s of col) {
        const t = def.symbols[s]?.tags ?? [];
        if (t.includes(e.collectorTag))
          n++;
        if (t.includes(e.valueTag))
          v += coinValue(def, e.paytableId, s);
      }
      return [n, v];
    },
    stateKey: ([n, v]) => `${n}:${v}`,
    finish: ([n, v]) => n * v
  } };
};
var slotMechanicsExtension = defineExtension({
  id: "mechanic.slot-evaluators",
  version: "1.2.0",
  evaluators: { EXPAND_WILDS: expand, PAYWAYS: payways, TUMBLE: tumbleEval, COLLECT_VALUES: collect },
  reelObservations: { EXPAND_WILDS: expandWildsObservation, PAYWAYS: paywaysObservation, COLLECT_VALUES: collectObservation },
  nodeTypes: [{ kind: "HOLD_COINS", validate: (n) => n.kind === "HOLD_COINS" && typeof n.board === "string" && typeof n.stateKey === "string" && typeof n.output === "string" && typeof n.tag === "string" && typeof n.paytableId === "string", capabilities: (n) => holdCoins.capabilities(n), handler: holdCoins }]
});

// dist/src/builder/primitives.js
var ref = (name) => ({ ref: name });
var lit2 = (value) => ({ const: value });
var ge = (left, right) => ({ op: ">=", left, right });
var gt = (left, right) => ({ op: ">", left, right });
var mul = (left, right) => ({ op: "*", left, right });
function symbolMap(rows) {
  return Object.fromEntries(rows.map(([id, name, tags]) => [id, { id, name, tags }]));
}
function lineMap(paths) {
  const out = {};
  paths.forEach((rows, i) => {
    const id = `L${i + 1}`;
    out[id] = { id, rows };
  });
  return out;
}
function end(id = "end") {
  return { id, kind: "FLOW", phase: "TRANSITION", operation: { type: "END_GAME" } };
}
function enter(id, modeId) {
  return { id, kind: "FLOW", phase: "TRANSITION", operation: { type: "ENTER_MODE", modeId } };
}
function award(id, amount, next) {
  return { id, kind: "AWARD", phase: "SETTLE", amount, next };
}
function setState(id, target, value, next) {
  return { id, kind: "STATE", phase: "MUTATE", target, op: "SET", value, next };
}
function addState(id, target, value, next) {
  return { id, kind: "STATE", phase: "MUTATE", target, op: "ADD", value, next };
}
function when(id, expression, onTrue, onFalse) {
  return { id, kind: "CONDITION", phase: "TRIGGER", expression, onTrue, onFalse };
}
function spin(id, reelSetId, rows, output, next) {
  return { id, kind: "SOURCE", phase: "GENERATE", source: { type: "REEL_SPIN", reelSetId, rows }, output, next };
}
function evalLines(id, board, paytableId, paylineIds, output, next, wildTag) {
  return { id, kind: "EVALUATE", phase: "EVALUATE", evaluator: { type: "PAYLINES", board, paytableId, paylineIds, wildTag }, output, next };
}
function sumWins(id, wins, output, next) {
  return { id, kind: "EVALUATE", phase: "EVALUATE", evaluator: { type: "SUM_WINS", wins }, output, next };
}
function countTag(id, board, tag, output, next) {
  return { id, kind: "EVALUATE", phase: "EVALUATE", evaluator: { type: "COUNT_TAG", board, tag }, output, next };
}
function game(partial) {
  return {
    id: partial.id,
    version: "0.33.0",
    semanticsVersion: 1,
    rng: { algorithm: "ADDRESS_HASH_V1", algorithmVersion: 1, addressingVersion: 1 },
    symbols: partial.symbols ?? {},
    reelSets: partial.reelSets ?? {},
    paytables: partial.paytables ?? {},
    paylines: partial.paylines ?? {},
    wager: partial.wager,
    entryModeId: partial.entryModeId,
    modes: partial.modes
  };
}
function strip(counts2, seed) {
  const out = Object.entries(counts2).flatMap(([s, n]) => Array(n).fill(s));
  let x = seed * 2654435761 >>> 0;
  for (let i = out.length - 1; i > 0; i--) {
    x = Math.imul(x, 1664525) + 1013904223 >>> 0;
    const j = x % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}
var lines20 = [[1, 1, 1, 1, 1], [0, 0, 0, 0, 0], [2, 2, 2, 2, 2], [0, 1, 2, 1, 0], [2, 1, 0, 1, 2], [1, 0, 0, 0, 1], [1, 2, 2, 2, 1], [0, 0, 1, 2, 2], [2, 2, 1, 0, 0], [1, 2, 1, 0, 1], [1, 0, 1, 2, 1], [0, 1, 1, 1, 0], [2, 1, 1, 1, 2], [0, 1, 0, 1, 0], [2, 1, 2, 1, 2], [1, 1, 0, 1, 1], [1, 1, 2, 1, 1], [0, 0, 2, 0, 0], [2, 2, 0, 2, 2], [0, 2, 0, 2, 0]];
var R = (id, strip2) => ({ id, symbols: strip2.trim().split(/\s+/) });
function winChain(p, kind, paytableId, paylineIds, next) {
  const n = {}, sum = sumWins(`${p}sum`, "$spin.wins", "$spin.rawWin", next);
  if (kind === "WAYS")
    n[`${p}ways`] = { id: `${p}ways`, kind: "EVALUATE", phase: "EVALUATE", evaluator: { type: "PAYWAYS", board: "$spin.board", paytableId, wildTag: "WILD" }, output: "$spin.wins", next: `${p}sum` };
  else if (kind === "EXPAND") {
    n[`${p}expand`] = { id: `${p}expand`, kind: "EVALUATE", phase: "TRANSFORM", evaluator: { type: "EXPAND_WILDS", board: "$spin.board", wildTag: "WILD" }, output: "$spin.expanded", next: `${p}lines` };
    n[`${p}lines`] = evalLines(`${p}lines`, "$spin.expanded", paytableId, paylineIds, "$spin.wins", `${p}sum`, "WILD");
  } else
    n[`${p}lines`] = evalLines(`${p}lines`, "$spin.board", paytableId, paylineIds, "$spin.wins", `${p}sum`, "WILD");
  n[`${p}sum`] = sum;
  return n;
}
function freeSpinsModes(o) {
  const stage = (p, s, after) => {
    const award2 = { id: `${p}award`, kind: "AWARD", phase: "SETTLE", amount: s.multiplier && s.multiplier !== 1n ? mul(ref("$spin.rawWin"), lit2(s.multiplier)) : ref("$spin.rawWin"), next: `${p}scatter` };
    return {
      [`${p}spin`]: spin(`${p}spin`, s.reelSetId, 3, "$spin.board", Object.keys(winChain(p, s.eval, o.paytableId, o.paylineIds, ""))[0]),
      ...winChain(p, s.eval, o.paytableId, o.paylineIds, `${p}award`),
      [`${p}award`]: award2,
      [`${p}scatter`]: countTag(`${p}scatter`, "$spin.board", "SCATTER", "$spin.scatterCount", s.extra ? `${p}x0` : after),
      ...s.extra ? s.extra(p, after) : {}
    };
  };
  const modes = { FREE_SPINS: { id: "FREE_SPINS", entryNodeId: "f_spin", nodes: {
    ...stage("f_", o.fs, "f_retrigger"),
    f_retrigger: when("f_retrigger", ge(ref("$spin.scatterCount"), lit2(o.scatterMin)), "f_add", "f_dec"),
    f_add: addState("f_add", "remainingSpins", lit2(o.retrigger), "f_dec"),
    f_dec: addState("f_dec", "remainingSpins", lit2(-1), "f_more"),
    f_more: { id: "f_more", kind: "CONDITION", phase: "TRANSITION", expression: gt(ref("$state.remainingSpins"), lit2(0)), onTrue: "f_spin", onFalse: "f_end" },
    f_end: end("f_end")
  } } };
  if (o.base)
    modes.BASE = { id: "BASE", entryNodeId: "b_spin", nodes: {
      ...stage("b_", o.base, "b_trigger"),
      b_trigger: when("b_trigger", ge(ref("$spin.scatterCount"), lit2(o.scatterMin)), "b_setfs", "b_end"),
      b_setfs: setState("b_setfs", "remainingSpins", lit2(o.spins), "b_enterfs"),
      b_enterfs: enter("b_enterfs", "FREE_SPINS"),
      b_end: end("b_end")
    } };
  else
    modes.BUY = { id: "BUY", entryNodeId: "buy_set", nodes: { buy_set: setState("buy_set", "remainingSpins", lit2(o.spins), "buy_enter"), buy_enter: enter("buy_enter", "FREE_SPINS") } };
  return modes;
}

// dist/src/demo/slots/classic3Reel.js
function classic3ReelDemo() {
  const paylines = lineMap([[1, 1, 1], [0, 0, 0], [2, 2, 2], [0, 1, 2], [2, 1, 0]]), ids = Object.keys(paylines);
  return game({
    id: "classic-3-reel",
    wager: { activePaylineIds: ids, totalBet: 5n, payoutUnit: "CREDITS" },
    symbols: symbolMap([
      ["SV", "Seven", ["HIGH"]],
      ["B3", "Triple Bar", ["BAR"]],
      ["B2", "Double Bar", ["BAR"]],
      ["B1", "Bar", ["BAR"]],
      ["BL", "Bell", ["MID"]],
      ["CH", "Cherry", ["LOW"]],
      ["X", "Blank", ["BLANK"]],
      ["W", "Wild Seven", ["WILD"]]
    ]),
    reelSets: {
      base: { id: "base", reels: [
        R("b1", "B3 B2 X B2 SV CH B2 B1 X CH X B1 X B1 X CH BL BL X X B3 X X B2 B1 BL B3 CH B1 SV X X"),
        R("b2", "B3 BL SV X X B2 B1 X CH W X B1 BL CH SV X B1 B1 BL X X B3 X BL B3 X B2 CH B1 B2 B2 X X"),
        R("b3", "W CH BL B1 B2 X B2 B1 X X SV B3 B3 BL X X B3 X B1 X X B2 BL CH B2 X B1 X CH SV BL B1 X X")
      ] }
    },
    paylines,
    paytables: { main: { id: "main", pays: { SV: { 3: 250n }, B3: { 3: 100n }, B2: { 3: 50n }, B1: { 3: 25n }, BL: { 3: 37n }, CH: { 1: 2n, 2: 7n, 3: 25n }, W: { 3: 500n } } } },
    entryModeId: "BASE",
    modes: { BASE: { id: "BASE", entryNodeId: "spin", nodes: {
      spin: spin("spin", "base", 3, "$spin.board", "lines"),
      lines: evalLines("lines", "$spin.board", "main", ids, "$spin.wins", "sum", "WILD"),
      sum: sumWins("sum", "$spin.wins", "$spin.rawWin", "award"),
      award: award("award", ref("$spin.rawWin"), "end"),
      end: end()
    } } }
  });
}

// dist/src/demo/slots/videoSlot20.js
function videoSlot20Demo() {
  const paylines = lineMap(lines20), ids = Object.keys(paylines);
  return game({
    id: "video-slot-20",
    wager: { activePaylineIds: ids, totalBet: 20n, payoutUnit: "CREDITS" },
    symbols: symbolMap([
      ["H1", "Pharaoh", ["HIGH"]],
      ["H2", "Scarab", ["HIGH"]],
      ["H3", "Ankh", ["HIGH"]],
      ["H4", "Eye of Horus", ["HIGH"]],
      ["A", "Ace", ["LOW"]],
      ["K", "King", ["LOW"]],
      ["Q", "Queen", ["LOW"]],
      ["J", "Jack", ["LOW"]],
      ["T", "Ten", ["LOW"]],
      ["W", "Wild", ["WILD"]],
      ["S", "Scatter", ["SCATTER"]]
    ]),
    reelSets: {
      base: { id: "base", reels: [
        R("b1", "H4 H3 A H3 K Q Q H4 J J K A Q K K J T H4 J H2 A H4 H2 Q J S H1 S K T T T T H2 T Q H3 H1 A J Q H3 A"),
        R("b2", "A H4 H3 H3 H2 H4 H4 J H3 T H2 J J A H1 Q J J K H2 K A H3 J A T Q H1 K T Q S A K Q S T W Q Q K T T H4"),
        R("b3", "J H4 A A H1 H1 T H4 T T S J A H3 K K H3 A Q H3 K Q A J S T K J Q K T H2 H4 Q Q W J H2 W H4 T Q H2 J H3"),
        R("b4", "A H2 H1 W H1 H4 J A H4 Q T J S J H4 Q K Q H3 J H4 H2 K T Q H2 Q T A J H3 T H3 Q K K A S H3 A T K T J"),
        R("b5", "H1 T Q H4 H2 T H4 A A J S T H3 A A K Q H3 J T A Q H4 S H4 H1 K T K K J H2 H2 J H3 T Q Q Q K H3 J J")
      ] },
      fs: { id: "fs", reels: [
        R("f1", "H1 K H3 T H4 H2 H3 T J H3 A Q A J K A K A A J J Q H2 H3 Q T Q H2 H1 T H4 T H4 K K H4 Q H4 J S H2 H1"),
        R("f2", "J H2 H4 H3 H2 S Q Q J H4 H1 H4 H1 A T K K T Q K H3 H2 Q H3 K J A J H4 T H2 J W H4 H1 A A W Q T A H3 T K"),
        R("f3", "S Q W H3 H2 H3 H2 K H1 K J J Q Q H2 A K T H1 W H3 A H4 Q J J Q W H4 J H4 T A T H1 H4 T H2 A H3 K T H4 A K"),
        R("f4", "A J H2 H3 Q H2 H2 H3 H4 S Q Q H1 K H1 K A Q K J J A T H3 K H4 H4 J A W H4 Q A K H2 H4 J T H3 H1 T T T W"),
        R("f5", "Q H2 A K A T J A T H1 H2 A H1 K H4 J H2 J T H3 H2 H3 T Q T J H3 K H1 J H3 H4 S H4 Q A H4 K Q Q K H4")
      ] }
    },
    paylines,
    paytables: { main: { id: "main", pays: { H1: { 2: 5n, 3: 49n, 4: 247n, 5: 1235n }, H2: { 3: 37n, 4: 148n, 5: 617n }, H3: { 3: 25n, 4: 99n, 5: 370n }, H4: { 3: 20n, 4: 74n, 5: 247n }, A: { 3: 12n, 4: 37n, 5: 123n }, K: { 3: 12n, 4: 37n, 5: 123n }, Q: { 3: 10n, 4: 25n, 5: 99n }, J: { 3: 10n, 4: 25n, 5: 99n }, T: { 3: 7n, 4: 20n, 5: 74n }, W: { 3: 62n, 4: 370n, 5: 2470n } } } },
    entryModeId: "BASE",
    modes: freeSpinsModes({ paytableId: "main", paylineIds: ids, base: { reelSetId: "base", eval: "LINES" }, fs: { reelSetId: "fs", eval: "LINES", multiplier: 3n }, spins: 10, retrigger: 10, scatterMin: 3 })
  });
}

// dist/src/demo/slots/ways243.js
function ways243Demo() {
  const ids = [];
  return game({
    id: "ways-243",
    wager: { activePaylineIds: [], totalBet: 25n, payoutUnit: "CREDITS" },
    symbols: symbolMap([
      ["H1", "Tiger", ["HIGH"]],
      ["H2", "Dragon", ["HIGH"]],
      ["H3", "Koi", ["HIGH"]],
      ["H4", "Lantern", ["HIGH"]],
      ["A", "Ace", ["LOW"]],
      ["K", "King", ["LOW"]],
      ["Q", "Queen", ["LOW"]],
      ["J", "Jack", ["LOW"]],
      ["T", "Ten", ["LOW"]],
      ["W", "Wild", ["WILD"]],
      ["S", "Scatter", ["SCATTER"]]
    ]),
    reelSets: {
      base: { id: "base", reels: [
        R("b1", "J H3 K J T A A H4 Q K K J J H4 A Q T H2 K Q H4 Q A S H2 K Q T H3 J Q H3 H1 T H2 A T H4 J H1 S T H3"),
        R("b2", "H4 H3 K Q A H3 J H4 H2 T H1 J K H4 W A Q Q A J Q T H3 J J T H4 T J Q A K H2 H3 K A H1 S S H2 K Q T T"),
        R("b3", "K K A J Q H3 H1 A T T H2 T H4 K H2 K S J Q T H3 H4 Q Q A J Q A H4 H3 K J J H2 W T J H4 H3 A Q S T H1"),
        R("b4", "H2 Q T H4 Q H1 A A K H4 J A H3 K Q J H1 H2 S H3 A H2 H3 Q T J H3 T K K Q T J J Q T K A S J T H4 W H4"),
        R("b5", "J T H2 H4 H3 H3 Q H4 A J T Q A H1 H3 J T S Q T T A K H2 H1 J J S H3 K A T Q J K A H4 H2 K H4 Q Q K")
      ] },
      fs: { id: "fs", reels: [
        R("f1", "H1 K A A H4 H2 S Q H3 H3 T H4 K A H2 A A K H4 Q J T T J K K H4 J H2 Q Q T H3 Q H1 J J H2 T H1 H3 H4"),
        R("f2", "H1 K J K H3 H4 H2 W Q J S A H4 K Q T J H1 Q J Q H2 K T A Q H2 J A H3 K T H4 H1 H3 H4 A T T H3 A W H4 H2"),
        R("f3", "H1 H2 Q J H3 H4 H2 Q A T H1 T H1 H2 T J A A J A Q J H3 H4 K T S W H4 K Q K W J K T H4 Q H3 H2 K A H4 H3"),
        R("f4", "H2 A H3 H3 H1 H2 K H4 H4 W A A H3 Q H1 K T A K Q K H4 S T T K J T H4 J J J H3 Q H1 H2 H2 J Q W T Q H4 A"),
        R("f5", "H1 K A H2 H3 Q H3 Q K J H1 T A J A S H2 Q Q T H3 T T J H4 H2 H3 A H2 J K T H4 H4 J H1 K H4 A H4 Q K")
      ] }
    },
    paylines: {},
    paytables: { main: { id: "main", pays: { H1: { 3: 40n, 4: 101n, 5: 402n }, H2: { 3: 30n, 4: 80n, 5: 302n }, H3: { 3: 20n, 4: 60n, 5: 201n }, H4: { 3: 16n, 4: 40n, 5: 161n }, A: { 3: 10n, 4: 20n, 5: 80n }, K: { 3: 10n, 4: 20n, 5: 80n }, Q: { 3: 8n, 4: 16n, 5: 60n }, J: { 3: 8n, 4: 16n, 5: 60n }, T: { 3: 6n, 4: 12n, 5: 50n } } } },
    entryModeId: "BASE",
    modes: freeSpinsModes({ paytableId: "main", paylineIds: ids, base: { reelSetId: "base", eval: "WAYS" }, fs: { reelSetId: "fs", eval: "WAYS", multiplier: 2n }, spins: 8, retrigger: 8, scatterMin: 3 })
  });
}

// dist/src/demo/slots/scatterPays.js
function scatterPaysDemo() {
  const paylines = lineMap(lines20), ids = Object.keys(paylines);
  const scatterPay = (p, next) => ({
    [`${p}x0`]: when(`${p}x0`, ge(ref("$spin.scatterCount"), lit2(5)), `${p}sp5`, `${p}x1`),
    [`${p}x1`]: when(`${p}x1`, ge(ref("$spin.scatterCount"), lit2(4)), `${p}sp4`, `${p}x2`),
    [`${p}x2`]: when(`${p}x2`, ge(ref("$spin.scatterCount"), lit2(3)), `${p}sp3`, next),
    [`${p}sp5`]: award(`${p}sp5`, lit2(1000n), next),
    [`${p}sp4`]: award(`${p}sp4`, lit2(200n), next),
    [`${p}sp3`]: award(`${p}sp3`, lit2(40n), next)
  });
  return game({
    id: "scatter-pays",
    wager: { activePaylineIds: ids, totalBet: 20n, payoutUnit: "CREDITS" },
    symbols: symbolMap([
      ["H1", "Pharaoh", ["HIGH"]],
      ["H2", "Scarab", ["HIGH"]],
      ["H3", "Ankh", ["HIGH"]],
      ["H4", "Eye of Horus", ["HIGH"]],
      ["A", "Ace", ["LOW"]],
      ["K", "King", ["LOW"]],
      ["Q", "Queen", ["LOW"]],
      ["J", "Jack", ["LOW"]],
      ["T", "Ten", ["LOW"]],
      ["W", "Wild", ["WILD"]],
      ["S", "Golden Scatter", ["SCATTER"]]
    ]),
    reelSets: {
      base: { id: "base", reels: [
        R("b1", "J K H1 H2 T K A S H4 K H3 T Q S H4 J T J T K A Q T H3 K H1 H3 Q H4 J Q S T A H2 Q A J J Q H3 H4 A H2"),
        R("b2", "Q K H3 Q H2 H4 H1 T H1 A H3 S J A Q J H4 K H3 Q K T K K H4 T H2 S Q J A J H2 A T H3 S H4 T Q W A J T J"),
        R("b3", "K A T J K J J W H3 T A A H2 Q H2 Q H4 A J S Q A H3 Q H1 S H3 H4 K T H3 T H4 H2 T Q J H1 W T H4 Q S K J K"),
        R("b4", "S J H2 Q K J H4 T H3 Q H1 K H4 Q H2 Q T S H2 J T A H1 A J K A H4 W T H4 T H3 T A J Q A H3 H3 J Q K S K"),
        R("b5", "K H2 K J T H1 H2 H4 Q Q A T H3 K Q K H4 H3 Q J H1 T J S J Q H3 Q H4 T A J A T H2 S A A J S H3 K H4 T")
      ] },
      fs: { id: "fs", reels: [
        R("f1", "J H3 H2 H2 H4 T J T H3 H4 H1 H4 Q K H4 A K H3 A Q Q Q A J H1 H3 H1 H2 J Q K J K H2 S T K H4 A T A T S"),
        R("f2", "T J H1 K K H2 A H3 K H4 H2 Q A H4 W J K H1 J Q T H3 T T H2 H4 J Q W H2 A J H4 S H3 K Q H3 H4 T A Q S A H1"),
        R("f3", "A H2 H4 K J T S Q H3 H4 T Q J A W K H3 Q J H4 K K H3 H3 Q H2 H1 A S H2 T J H1 K H2 J H4 Q T W A H4 T H1 A"),
        R("f4", "S A H3 H2 H4 W T J H4 Q H4 K H1 H2 H1 K T Q Q S H2 J J Q H3 K H3 J T H2 H4 W A A K H3 H1 H4 K A A T J Q T"),
        R("f5", "H1 H4 H2 H3 H2 H3 J K H3 K H2 H4 S H4 K Q S A A T T J K Q Q H1 A T Q J A K H4 T J A T H2 J H3 H1 Q H4")
      ] }
    },
    paylines,
    paytables: { main: { id: "main", pays: { H1: { 2: 3n, 3: 28n, 4: 138n, 5: 690n }, H2: { 3: 21n, 4: 83n, 5: 345n }, H3: { 3: 14n, 4: 55n, 5: 207n }, H4: { 3: 11n, 4: 41n, 5: 138n }, A: { 3: 7n, 4: 21n, 5: 69n }, K: { 3: 7n, 4: 21n, 5: 69n }, Q: { 3: 6n, 4: 14n, 5: 55n }, J: { 3: 6n, 4: 14n, 5: 55n }, T: { 3: 4n, 4: 11n, 5: 41n }, W: { 3: 35n, 4: 207n, 5: 1380n } } } },
    entryModeId: "BASE",
    modes: freeSpinsModes({ paytableId: "main", paylineIds: ids, base: { reelSetId: "base", eval: "LINES", extra: scatterPay }, fs: { reelSetId: "fs", eval: "LINES", extra: scatterPay }, spins: 15, retrigger: 15, scatterMin: 3 })
  });
}

// dist/src/demo/slots/buyFreeSpins.js
function buyFreeSpinsDemo() {
  const paylines = lineMap(lines20), ids = Object.keys(paylines);
  return game({
    id: "buy-free-spins",
    wager: { activePaylineIds: ids, totalBet: 2000n, payoutUnit: "CREDITS" },
    symbols: symbolMap([
      ["H1", "Pharaoh", ["HIGH"]],
      ["H2", "Scarab", ["HIGH"]],
      ["H3", "Ankh", ["HIGH"]],
      ["H4", "Eye of Horus", ["HIGH"]],
      ["A", "Ace", ["LOW"]],
      ["K", "King", ["LOW"]],
      ["Q", "Queen", ["LOW"]],
      ["J", "Jack", ["LOW"]],
      ["T", "Ten", ["LOW"]],
      ["W", "Wild", ["WILD"]],
      ["S", "Scatter", ["SCATTER"]]
    ]),
    reelSets: {
      fs: { id: "fs", reels: [
        R("f1", "H1 K A H3 K Q H2 Q H1 J H3 T Q H2 K H4 H3 T H2 J J H3 A S T H4 H4 T J H4 H4 J A T K Q A H1 H2 K A Q"),
        R("f2", "A J H2 Q K A Q H4 H3 K H2 H4 W H3 W J K H1 Q K Q T A T A H3 H2 J H1 T S H2 H4 J K H1 H3 Q T H4 H4 A J T"),
        R("f3", "A T T H4 Q T K Q H3 A H2 A W J A K H3 W H1 S H1 J H2 J H4 J K H3 H1 K H3 W H4 A H4 T K Q Q H4 H2 Q H2 J T"),
        R("f4", "H2 A J H3 H4 H2 H2 H4 H1 K J A K H4 H2 A A K T W H4 S Q H4 J Q H1 Q J K Q T H3 H3 A W K T J T T H1 Q H3"),
        R("f5", "H1 H2 T A A H4 H3 Q Q H4 H1 J H4 A T H1 H2 K J K H3 Q K Q H2 J Q H3 H4 T H3 A K K J T H2 H4 A J T S")
      ] }
    },
    paylines,
    paytables: { main: { id: "main", pays: { H1: { 2: 34n, 3: 343n, 4: 1716n, 5: 8578n }, H2: { 3: 257n, 4: 1029n, 5: 4289n }, H3: { 3: 172n, 4: 686n, 5: 2573n }, H4: { 3: 137n, 4: 515n, 5: 1716n }, A: { 3: 86n, 4: 257n, 5: 858n }, K: { 3: 86n, 4: 257n, 5: 858n }, Q: { 3: 69n, 4: 172n, 5: 686n }, J: { 3: 69n, 4: 172n, 5: 686n }, T: { 3: 51n, 4: 137n, 5: 515n }, W: { 3: 429n, 4: 2573n, 5: 17155n } } } },
    entryModeId: "BUY",
    modes: freeSpinsModes({ paytableId: "main", paylineIds: ids, fs: { reelSetId: "fs", eval: "LINES", multiplier: 2n }, spins: 10, retrigger: 10, scatterMin: 3 })
  });
}

// dist/src/demo/slots/expandingWilds.js
function expandingWildsDemo() {
  const paylines = lineMap(lines20.slice(0, 10)), ids = Object.keys(paylines);
  return game({
    id: "expanding-wilds",
    wager: { activePaylineIds: ids, totalBet: 10n, payoutUnit: "CREDITS" },
    symbols: symbolMap([
      ["H1", "Seven", ["HIGH"]],
      ["H2", "Bar", ["HIGH"]],
      ["H3", "Ruby", ["HIGH"]],
      ["H4", "Emerald", ["HIGH"]],
      ["A", "Ace", ["LOW"]],
      ["K", "King", ["LOW"]],
      ["Q", "Queen", ["LOW"]],
      ["J", "Jack", ["LOW"]],
      ["T", "Ten", ["LOW"]],
      ["W", "Expanding Star", ["WILD"]],
      ["S", "Scatter", ["SCATTER"]]
    ]),
    reelSets: {
      base: { id: "base", reels: [
        R("b1", "A A K T J K H3 S Q A H3 K S H2 Q H4 H2 Q T A H4 J H3 Q H4 K Q H1 K T H1 J T H2 T H3 H4 J A Q T J J"),
        R("b2", "K H2 A A T H4 H4 T H3 K H4 A H1 A H3 Q T A J Q K J T H3 H2 K Q K W T J Q Q T S J Q H3 S H1 H4 J J H2"),
        R("b3", "J H2 H3 A H2 Q T H4 Q H4 K K A H2 J S A J T Q K Q K J H3 T J A H1 T H1 S Q H3 T H4 K H4 T W Q H3 J A"),
        R("b4", "H4 J H3 H3 H1 K Q A J H1 T S H4 H4 A J H3 T T J T Q Q Q H4 H2 K A Q W H2 S K H2 T T H3 A A Q J K J K"),
        R("b5", "H1 H2 S H3 S A H4 H4 A A Q K K K J J Q T K T H3 J Q J H3 H4 A J H4 T T J H2 T T H3 Q K Q H1 Q A H2")
      ] },
      fs: { id: "fs", reels: [
        R("f1", "H3 H2 H2 J A H3 H4 T K H2 H1 H4 Q K Q T H3 K H1 A T H3 J S A J Q A H4 H4 Q J A H2 H1 H4 T K J K Q T"),
        R("f2", "H3 K H3 H2 H4 H1 K H2 T H2 H2 H4 T A H4 Q A H3 Q K J Q T W T J Q W K J H1 H4 H1 K A T S A J Q H4 H3 J A"),
        R("f3", "H4 K J J Q J T H4 W A Q K H3 A A A K H3 H2 T Q J Q T H4 H4 Q H4 H2 H3 H3 W J A H1 H2 H1 T T H1 S K H2 K"),
        R("f4", "K H3 H2 H1 J H3 H1 H4 K H2 T Q Q K W T A T K T A A H3 J A H4 H4 H3 H1 J H4 H2 Q Q Q K J W A H4 S T H2 J"),
        R("f5", "H1 Q Q J H4 H2 H3 K J A K Q H1 H2 H3 K H2 A H3 T A Q T J H2 S H3 T H4 H4 K T A K J A H4 H1 Q J T H4")
      ] }
    },
    paylines,
    paytables: { main: { id: "main", pays: { H1: { 2: 4n, 3: 42n, 4: 209n, 5: 1043n }, H2: { 3: 31n, 4: 125n, 5: 521n }, H3: { 3: 21n, 4: 83n, 5: 313n }, H4: { 3: 17n, 4: 63n, 5: 209n }, A: { 3: 10n, 4: 31n, 5: 104n }, K: { 3: 10n, 4: 31n, 5: 104n }, Q: { 3: 8n, 4: 21n, 5: 83n }, J: { 3: 8n, 4: 21n, 5: 83n }, T: { 3: 6n, 4: 17n, 5: 63n }, W: { 3: 52n, 4: 313n, 5: 2086n } } } },
    entryModeId: "BASE",
    modes: freeSpinsModes({ paytableId: "main", paylineIds: ids, base: { reelSetId: "base", eval: "EXPAND" }, fs: { reelSetId: "fs", eval: "EXPAND" }, spins: 10, retrigger: 10, scatterMin: 3 })
  });
}

// dist/src/demo/slots/fishCollector.js
function fishCollectorDemo() {
  const paylines = lineMap(lines20.slice(0, 10)), ids = Object.keys(paylines);
  const collect2 = (p, next) => ({
    [`${p}x0`]: { id: `${p}x0`, kind: "EVALUATE", phase: "EVALUATE", evaluator: { type: "COLLECT_VALUES", board: "$spin.board", collectorTag: "COLLECTOR", valueTag: "MONEY", paytableId: "money" }, output: "$spin.collected", next: `${p}x1` },
    [`${p}x1`]: award(`${p}x1`, ref("$spin.collected"), next)
  });
  return game({
    id: "fish-collector",
    wager: { activePaylineIds: ids, totalBet: 10n, payoutUnit: "CREDITS" },
    symbols: symbolMap([
      ["H1", "Tackle Box", ["HIGH"]],
      ["H2", "Dragonfly", ["HIGH"]],
      ["H3", "Rod", ["HIGH"]],
      ["A", "Ace", ["LOW"]],
      ["K", "King", ["LOW"]],
      ["Q", "Queen", ["LOW"]],
      ["J", "Jack", ["LOW"]],
      ["T", "Ten", ["LOW"]],
      ["F2", "Fish 2x", ["MONEY"]],
      ["F5", "Fish 5x", ["MONEY"]],
      ["F10", "Fish 10x", ["MONEY"]],
      ["F50", "Fish 50x", ["MONEY"]],
      ["W", "Fisherman Wild", ["WILD", "COLLECTOR"]],
      ["S", "Scatter", ["SCATTER"]]
    ]),
    reelSets: {
      base: { id: "base", reels: [
        R("b1", "S H3 F5 J F5 J K K K Q K Q J Q A H3 H1 H2 T T T H1 A T J F2 H3 F2 H2 F10 F2 Q A H2 T T H3 A Q K A Q J S J"),
        R("b2", "F2 H3 F2 H3 K T H1 A J T A A T J Q K T S J H2 H1 T F5 J A K Q A Q H3 H2 F2 K Q H2 J Q F5 F10 T H3 J W Q S K"),
        R("b3", "H1 Q H2 S H3 A J J A K Q T H3 A H3 T F2 J J T J A Q Q S F5 F10 T H2 F2 K H3 K T K F5 T K H1 Q H2 A Q W J F2"),
        R("b4", "H1 H3 W H3 H2 K F5 Q A J A S Q K H3 F2 H2 J T T H1 F5 Q J T T J T H2 J Q F2 Q H3 A K A J Q S T F2 F10 A K K"),
        R("b5", "A A H2 S H3 A F2 K K F2 K W H1 A T J H3 T K A T F5 F10 J Q H3 J F2 T Q F5 T Q K Q J S H2 H3 H1 J Q Q J H2 T")
      ] },
      fs: { id: "fs", reels: [
        R("f1", "H2 K K F5 H2 Q F5 Q H1 A H3 F2 F2 T H3 J J F2 H1 F10 J K A F5 A K F2 F2 S A T H2 H3 F10 F50 T J T Q Q"),
        R("f2", "F10 J H2 A H1 H3 F2 F5 F2 W A T F2 Q K Q T H1 H2 J F10 J T H2 K F2 J F5 T K F5 S H3 A A H3 F50 F2 Q Q K W"),
        R("f3", "Q H2 F2 A H2 K F2 F5 W Q F2 A H3 F10 K J H3 J A Q T F2 T W J H3 T F5 F50 K A J H1 T H2 K H1 F10 Q F2 S F5"),
        R("f4", "H1 W H3 F2 H3 A F2 A F50 S H3 Q K T A F10 K J Q Q F2 F10 W J J H2 H2 H1 T K F5 F5 T F5 A F2 F2 K Q H2 J T"),
        R("f5", "H2 H2 K J J A A K A Q H3 H3 F2 W J T Q T H2 F50 H1 F2 T F2 F2 J A F10 Q S W F5 K F2 F10 H1 K T F5 F5 H3 Q")
      ] }
    },
    paylines,
    paytables: { main: { id: "main", pays: { H1: { 3: 92n, 4: 369n, 5: 1384n }, H2: { 3: 46n, 4: 185n, 5: 692n }, H3: { 3: 37n, 4: 138n, 5: 461n }, A: { 3: 23n, 4: 46n, 5: 185n }, K: { 3: 23n, 4: 46n, 5: 185n }, Q: { 3: 18n, 4: 37n, 5: 138n }, J: { 3: 18n, 4: 37n, 5: 138n }, T: { 3: 14n, 4: 28n, 5: 115n }, W: { 3: 92n, 4: 461n, 5: 2307n } } }, money: { id: "money", pays: { F2: { 1: 2n }, F5: { 1: 5n }, F10: { 1: 10n }, F50: { 1: 50n } } } },
    entryModeId: "BASE",
    modes: freeSpinsModes({ paytableId: "main", paylineIds: ids, base: { reelSetId: "base", eval: "LINES" }, fs: { reelSetId: "fs", eval: "LINES", extra: collect2 }, spins: 10, retrigger: 10, scatterMin: 3 })
  });
}

// dist/src/demo/slots/cascades.js
function cascadesDemo() {
  const paylines = lineMap(lines20), ids = Object.keys(paylines);
  const nodes2 = {
    init: { id: "init", kind: "STATE", phase: "MUTATE", target: "tumbles", op: "SET", value: { const: 0 }, next: "spin" },
    spin: { id: "spin", kind: "SOURCE", phase: "GENERATE", source: { type: "REEL_SPIN", reelSetId: "base", rows: 3 }, output: "$spin.board", next: "lines" },
    lines: { id: "lines", kind: "EVALUATE", phase: "EVALUATE", evaluator: { type: "PAYLINES", board: "$spin.board", paytableId: "main", paylineIds: ids, wildTag: "WILD" }, output: "$spin.wins", next: "sum" },
    sum: { id: "sum", kind: "EVALUATE", phase: "EVALUATE", evaluator: { type: "SUM_WINS", wins: "$spin.wins" }, output: "$spin.win", next: "hasWin" },
    hasWin: { id: "hasWin", kind: "CONDITION", phase: "TRIGGER", expression: { op: ">", left: { ref: "$spin.win" }, right: { const: 0n } }, onTrue: "m1", onFalse: "end" },
    m1: { id: "m1", kind: "CONDITION", phase: "TRIGGER", expression: { op: "<", left: { ref: "$state.tumbles" }, right: { const: 1 } }, onTrue: "x1", onFalse: "m2" },
    m2: { id: "m2", kind: "CONDITION", phase: "TRIGGER", expression: { op: "<", left: { ref: "$state.tumbles" }, right: { const: 2 } }, onTrue: "x2", onFalse: "m3" },
    m3: { id: "m3", kind: "CONDITION", phase: "TRIGGER", expression: { op: "<", left: { ref: "$state.tumbles" }, right: { const: 3 } }, onTrue: "x3", onFalse: "x5" },
    x1: { id: "x1", kind: "AWARD", phase: "SETTLE", amount: { ref: "$spin.win" }, next: "tumble" },
    x2: { id: "x2", kind: "AWARD", phase: "SETTLE", amount: { op: "*", left: { ref: "$spin.win" }, right: { const: 2n } }, next: "tumble" },
    x3: { id: "x3", kind: "AWARD", phase: "SETTLE", amount: { op: "*", left: { ref: "$spin.win" }, right: { const: 3n } }, next: "tumble" },
    x5: { id: "x5", kind: "AWARD", phase: "SETTLE", amount: { op: "*", left: { ref: "$spin.win" }, right: { const: 5n } }, next: "tumble" },
    tumble: { id: "tumble", kind: "EVALUATE", phase: "TRANSFORM", evaluator: { type: "TUMBLE", board: "$spin.board", wins: "$spin.wins", reelSetId: "base" }, output: "$spin.board", next: "count" },
    count: { id: "count", kind: "STATE", phase: "MUTATE", target: "tumbles", op: "ADD", value: { const: 1 }, next: "cap" },
    cap: { id: "cap", kind: "CONDITION", phase: "TRIGGER", expression: { op: ">=", left: { ref: "$state.tumbles" }, right: { const: 8 } }, onTrue: "end", onFalse: "lines" },
    end: { id: "end", kind: "FLOW", phase: "TRANSITION", operation: { type: "END_GAME" } }
  };
  return game({
    id: "cascades",
    wager: { activePaylineIds: ids, totalBet: 20n, payoutUnit: "CREDITS" },
    symbols: symbolMap([["H1", "Red Gem", ["HIGH"]], ["H2", "Blue Gem", ["HIGH"]], ["H3", "Green Gem", ["HIGH"]], ["A", "Ace", ["LOW"]], ["K", "King", ["LOW"]], ["Q", "Queen", ["LOW"]], ["J", "Jack", ["LOW"]], ["T", "Ten", ["LOW"]], ["W", "Wild", ["WILD"]]]),
    reelSets: { base: { id: "base", reels: [
      R("c1", "A K H2 T A H3 T Q H2 Q K J H1 J A K Q Q H3 T H2 J T T J A T H3 J T A H1 J K Q Q T H3 A K Q K J"),
      R("c2", "H2 H3 H1 K H3 H1 T J H3 J H2 A K K J Q A A K W J Q T T Q Q K H3 H2 H1 H2 K T T A A Q T T T J W A J J Q Q"),
      R("c3", "W Q A K A K H2 Q J H2 K K H2 W Q J H3 T J H1 H3 J T Q A T A T A T J A Q Q T K J H3 H3 T Q T K J H1"),
      R("c4", "H3 H3 Q H3 H1 A J T H2 W K J A Q W K J T T K H1 Q J Q H2 A A J H1 T H3 T J K K T K H2 T Q T H2 J Q A A Q"),
      R("c5", "K A H1 Q Q A J K H2 Q J K A J H2 K Q K J T J T A T H3 J T T H1 T H3 H3 Q A T Q K T Q J A H3 H2")
    ] } },
    paylines,
    paytables: { main: { id: "main", pays: { H1: { 3: 59n, 4: 236n, 5: 1180n }, H2: { 3: 35n, 4: 142n, 5: 590n }, H3: { 3: 24n, 4: 94n, 5: 354n }, A: { 3: 12n, 4: 28n, 5: 94n }, K: { 3: 12n, 4: 28n, 5: 94n }, Q: { 3: 9n, 4: 24n, 5: 71n }, J: { 3: 7n, 4: 19n, 5: 59n }, T: { 3: 7n, 4: 19n, 5: 59n } } } },
    entryModeId: "BASE",
    modes: { BASE: { id: "BASE", entryNodeId: "init", nodes: nodes2 } }
  });
}

// dist/src/demo/slots/holdAndWin.js
function holdAndWinDemo() {
  const paylines = lineMap(lines20), ids = Object.keys(paylines);
  const base3 = {
    spin: { id: "spin", kind: "SOURCE", phase: "GENERATE", source: { type: "REEL_SPIN", reelSetId: "base", rows: 3 }, output: "$spin.board", next: "lines" },
    lines: { id: "lines", kind: "EVALUATE", phase: "EVALUATE", evaluator: { type: "PAYLINES", board: "$spin.board", paytableId: "main", paylineIds: ids, wildTag: "WILD" }, output: "$spin.wins", next: "sum" },
    sum: { id: "sum", kind: "EVALUATE", phase: "EVALUATE", evaluator: { type: "SUM_WINS", wins: "$spin.wins" }, output: "$spin.win", next: "award" },
    award: { id: "award", kind: "AWARD", phase: "SETTLE", amount: { ref: "$spin.win" }, next: "coins" },
    coins: { id: "coins", kind: "EVALUATE", phase: "EVALUATE", evaluator: { type: "COUNT_TAG", board: "$spin.board", tag: "COIN" }, output: "$spin.coins", next: "trigger" },
    trigger: { id: "trigger", kind: "CONDITION", phase: "TRIGGER", expression: { op: ">=", left: { ref: "$spin.coins" }, right: { const: 6 } }, onTrue: "lock", onFalse: "end" },
    lock: { id: "lock", kind: "HOLD_COINS", phase: "MUTATE", board: "$spin.board", stateKey: "locked", tag: "COIN", paytableId: "coins", output: "$hold", next: "setRespins" },
    setRespins: { id: "setRespins", kind: "STATE", phase: "MUTATE", target: "respins", op: "SET", value: { const: 3 }, next: "enter" },
    enter: { id: "enter", kind: "FLOW", phase: "TRANSITION", operation: { type: "ENTER_MODE", modeId: "HOLD" } },
    end: { id: "end", kind: "FLOW", phase: "TRANSITION", operation: { type: "END_GAME" } }
  };
  const hold = {
    respin: { id: "respin", kind: "SOURCE", phase: "GENERATE", source: { type: "REEL_SPIN", reelSetId: "hold", rows: 3 }, output: "$spin.board", next: "lock" },
    lock: { id: "lock", kind: "HOLD_COINS", phase: "MUTATE", board: "$spin.board", stateKey: "locked", tag: "COIN", paytableId: "coins", output: "$hold", next: "full" },
    full: { id: "full", kind: "CONDITION", phase: "TRIGGER", expression: { op: ">=", left: { ref: "$hold.filled" }, right: { const: 15 } }, onTrue: "grand", onFalse: "landed" },
    grand: { id: "grand", kind: "AWARD", phase: "SETTLE", amount: { const: 20000n }, next: "pay" },
    landed: { id: "landed", kind: "CONDITION", phase: "TRIGGER", expression: { op: ">", left: { ref: "$hold.new" }, right: { const: 0 } }, onTrue: "reset", onFalse: "dec" },
    reset: { id: "reset", kind: "STATE", phase: "MUTATE", target: "respins", op: "SET", value: { const: 3 }, next: "respin" },
    dec: { id: "dec", kind: "STATE", phase: "MUTATE", target: "respins", op: "ADD", value: { const: -1 }, next: "more" },
    more: { id: "more", kind: "CONDITION", phase: "TRIGGER", expression: { op: ">", left: { ref: "$state.respins" }, right: { const: 0 } }, onTrue: "respin", onFalse: "pay" },
    pay: { id: "pay", kind: "AWARD", phase: "SETTLE", amount: { ref: "$hold.total" }, next: "end" },
    end: { id: "end", kind: "FLOW", phase: "TRANSITION", operation: { type: "END_GAME" } }
  };
  return game({
    id: "hold-and-win",
    wager: { activePaylineIds: ids, totalBet: 20n, payoutUnit: "CREDITS" },
    symbols: symbolMap([
      ["H1", "Dragon", ["HIGH"]],
      ["H2", "Tiger", ["HIGH"]],
      ["A", "Ace", ["LOW"]],
      ["K", "King", ["LOW"]],
      ["Q", "Queen", ["LOW"]],
      ["J", "Jack", ["LOW"]],
      ["T", "Ten", ["LOW"]],
      ["W", "Wild", ["WILD"]],
      ["C1", "Coin 1x", ["COIN"]],
      ["C2", "Coin 2x", ["COIN"]],
      ["C5", "Coin 5x", ["COIN"]],
      ["C10", "Coin 10x", ["COIN"]],
      ["X", "Blank", ["BLANK"]]
    ]),
    reelSets: {
      base: { id: "base", reels: [
        R("b1", "Q T H2 H2 K C1 T K J A K Q H2 Q H1 C1 H2 T Q H1 K J H1 J J Q C5 J K T A K Q A A C1 T Q T C2 T C2 J A T A J"),
        R("b2", "A H2 H2 J C2 C2 Q C1 A C1 T K A H1 H1 C5 Q J J T T J Q Q W T A C1 K T Q W T K J Q H1 J K A A J T T H2 K K Q H2"),
        R("b3", "A H2 T C2 J A J Q K J A Q H1 K C5 Q J Q T Q Q J K T T T T C1 H2 C2 C1 J A A H2 H2 K K W T W C1 Q H1 T A H1 K J"),
        R("b4", "J T K H2 A J H2 A H1 K H2 T T T Q J C1 J K K Q A J W T Q A J C2 H1 C1 Q Q Q Q T T H1 C5 T C1 K C2 A W K J H2 A"),
        R("b5", "Q H1 J J H2 T K T K H2 A Q T T J Q Q J H1 T A J C5 J K C1 A A H2 C2 T Q Q Q C1 K A C2 K T A H1 K H2 T C1 J")
      ] },
      hold: { id: "hold", reels: [
        R("h1", "X X X C2 X X X X X X X X X X X X X X X X X X C1 X X X X X X X X X X X X X X X X X X X X C5 C2 X X X X X X X X X X X C1 C1 X C10 X X X X X X X X X X X"),
        R("h2", "X X X X X X X C10 X X X X X X X X X X X X X X X X X X X X C1 X X X X X X X X X C2 X X X X X X C2 X X X X X X X X X X X X X X C1 X X X X X C5 X X X C1 X X"),
        R("h3", "X X X X X X X X X X X X X X X X X X X X C1 X X X X X X C1 X X X X X X X X X X X X X X X X X X X C1 X X X X X X X X X C5 X X X X C10 C2 X X X X X X X X C2 X X X X"),
        R("h4", "X X X C2 X X X X X X X X X X X X X X X X X C1 X X X X X X X X X X X X X X C2 X X C10 X X X X X X X X X X X X X X X C1 X X X X X X X C5 X C1 X X X X X X X"),
        R("h5", "X X X X X X X X X C2 X X X X X X X X X X X X X X X X X X X X X X X X X X X C5 X X X X C1 X X X X C2 X X C10 X X X X X X X X X X X X C1 X X X C1 X X X")
      ] }
    },
    paylines,
    paytables: { main: { id: "main", pays: { H1: { 3: 64n, 4: 256n, 5: 960n }, H2: { 3: 38n, 4: 160n, 5: 640n }, A: { 3: 16n, 4: 38n, 5: 128n }, K: { 3: 16n, 4: 38n, 5: 128n }, Q: { 3: 13n, 4: 32n, 5: 96n }, J: { 3: 10n, 4: 26n, 5: 80n }, T: { 3: 10n, 4: 26n, 5: 80n } } }, coins: { id: "coins", pays: { C1: { 1: 20n }, C2: { 1: 40n }, C5: { 1: 100n }, C10: { 1: 200n } } } },
    entryModeId: "BASE",
    modes: { BASE: { id: "BASE", entryNodeId: "spin", nodes: base3 }, HOLD: { id: "HOLD", entryNodeId: "respin", nodes: hold } }
  });
}

// dist/src/demo/crash.js
var crashLadder = [10n, 15n, 20n, 30n, 50n, 100n];
function crashDemo(cashoutRung = 3) {
  if (cashoutRung < 1 || cashoutRung >= crashLadder.length)
    throw new Error("cashoutRung out of range");
  const nodes2 = {};
  for (let i = 0; i < cashoutRung; i++) {
    const fly = i === 0 ? 97n : crashLadder[i] * 10n, all = i === 0 ? 150n : crashLadder[i + 1] * 10n;
    nodes2[`flight${i}`] = { id: `flight${i}`, kind: "SOURCE", phase: "GENERATE", source: { type: "WEIGHTED_CHOICE", outcomes: [{ value: "FLY", weight: fly }, { value: "CRASH", weight: all - fly }] }, output: "$round.flight", next: `check${i}` };
    nodes2[`check${i}`] = { id: `check${i}`, kind: "CONDITION", phase: "TRIGGER", expression: { op: "==", left: { ref: "$round.flight" }, right: { const: "FLY" } }, onTrue: i + 1 === cashoutRung ? "cashout" : `flight${i + 1}`, onFalse: "crashed" };
  }
  nodes2.cashout = { id: "cashout", kind: "AWARD", phase: "SETTLE", amount: { const: crashLadder[cashoutRung] }, next: "end" };
  nodes2.crashed = { id: "crashed", kind: "FLOW", phase: "TRANSITION", operation: { type: "END_GAME" } };
  nodes2.end = { id: "end", kind: "FLOW", phase: "TRANSITION", operation: { type: "END_GAME" } };
  return {
    id: "crash-demo",
    version: "1.0.0",
    semanticsVersion: 1,
    rng: { algorithm: "ADDRESS_HASH_V1", algorithmVersion: 1, addressingVersion: 1 },
    wager: { activePaylineIds: [], totalBet: 10n, payoutUnit: "CREDITS" },
    symbols: { FLY: { id: "FLY", name: "Plane climbs", tags: ["FLIGHT"] }, CRASH: { id: "CRASH", name: "Plane crashes", tags: ["CRASH"] } },
    reelSets: {},
    paylines: {},
    paytables: { cashout: { id: "cashout", pays: { CASHOUT: Object.fromEntries(crashLadder.map((m, i) => [i, m])) } } },
    entryModeId: "BASE",
    modes: { BASE: { id: "BASE", entryNodeId: "flight0", nodes: nodes2 } }
  };
}

// dist/src/demo/plinko.js
var plinkoBuckets = [400n, 80n, 20n, 80n, 400n];
function plinkoDemo() {
  const rows = 4;
  const nodes2 = {
    initPos: { id: "initPos", kind: "STATE", phase: "MUTATE", target: "pos", op: "SET", value: { const: 0n }, next: "initRow" },
    initRow: { id: "initRow", kind: "STATE", phase: "MUTATE", target: "row", op: "SET", value: { const: 0n }, next: "peg" },
    peg: { id: "peg", kind: "SOURCE", phase: "GENERATE", source: { type: "WEIGHTED_CHOICE", outcomes: [{ value: "L", weight: 1n }, { value: "R", weight: 1n }] }, output: "$ball.peg", next: "isRight" },
    isRight: { id: "isRight", kind: "CONDITION", phase: "TRIGGER", expression: { op: "==", left: { ref: "$ball.peg" }, right: { const: "R" } }, onTrue: "moveRight", onFalse: "nextRow" },
    moveRight: { id: "moveRight", kind: "STATE", phase: "MUTATE", target: "pos", op: "ADD", value: { const: 1n }, next: "nextRow" },
    nextRow: { id: "nextRow", kind: "STATE", phase: "MUTATE", target: "row", op: "ADD", value: { const: 1n }, next: "landed" },
    landed: { id: "landed", kind: "CONDITION", phase: "TRIGGER", expression: { op: ">=", left: { ref: "$state.row" }, right: { const: BigInt(rows) } }, onTrue: "bucket0", onFalse: "peg" },
    end: { id: "end", kind: "FLOW", phase: "TRANSITION", operation: { type: "END_GAME" } }
  };
  const buckets = plinkoBuckets;
  buckets.forEach((pay, i) => {
    nodes2[`bucket${i}`] = { id: `bucket${i}`, kind: "CONDITION", phase: "TRIGGER", expression: { op: "==", left: { ref: "$state.pos" }, right: { const: BigInt(i) } }, onTrue: `payB${i}`, onFalse: i === rows ? "end" : `bucket${i + 1}` };
    nodes2[`payB${i}`] = { id: `payB${i}`, kind: "AWARD", phase: "SETTLE", amount: { const: pay }, next: "end" };
  });
  return {
    id: "plinko-demo",
    version: "1.0.0",
    semanticsVersion: 1,
    rng: { algorithm: "ADDRESS_HASH_V1", algorithmVersion: 1, addressingVersion: 1 },
    wager: { activePaylineIds: [], totalBet: 100n, payoutUnit: "CREDITS" },
    symbols: { L: { id: "L", name: "Peg bounce left", tags: ["PEG"] }, R: { id: "R", name: "Peg bounce right", tags: ["PEG"] }, ...Object.fromEntries(buckets.map((_, i) => [`B${i}`, { id: `B${i}`, name: `Bucket ${i}`, tags: ["BUCKET"] }])) },
    reelSets: {},
    paylines: {},
    paytables: { buckets: { id: "buckets", pays: Object.fromEntries(buckets.map((p, i) => [`B${i}`, { 1: p }])) } },
    entryModeId: "BASE",
    modes: { BASE: { id: "BASE", entryNodeId: "initPos", nodes: nodes2 } }
  };
}

// dist/src/demo/slots/megaways.js
var pays = { H1: { 3: 10n, 4: 25n, 5: 50n, 6: 150n }, H2: { 3: 6n, 4: 15n, 5: 30n, 6: 80n }, H3: { 3: 4n, 4: 10n, 5: 20n, 6: 50n }, A: { 3: 2n, 4: 5n, 5: 10n, 6: 25n }, K: { 3: 2n, 4: 4n, 5: 8n, 6: 20n }, Q: { 3: 1n, 4: 3n, 5: 6n, 6: 15n }, J: { 3: 1n, 4: 2n, 5: 5n, 6: 10n } };
var counts = (wild) => ({ H1: 2, H2: 3, H3: 4, A: 6, K: 6, Q: 7, J: 8, W: wild });
function megaStrip(seed, wild, scale) {
  const syms = strip(counts(wild), seed), out = [];
  const runs = [0, 1, 2, 3, 4, 5];
  syms.forEach((s, i) => {
    out.push(s);
    const r = runs[(i * 7 + seed) % runs.length] * scale;
    if (i % 3 === 2)
      for (let k = 0; k < r; k++)
        out.push("X");
  });
  return out;
}
function megawaysDemo(scale = 1, wild = 1) {
  const reels = Array.from({ length: 6 }, (_, i) => ({ id: `m${i + 1}`, symbols: megaStrip(11 + i * 17, i === 0 ? 0 : wild, scale) }));
  return game({
    id: "megaways-6x7",
    wager: { activePaylineIds: [], totalBet: 30n, payoutUnit: "CREDITS" },
    symbols: symbolMap([["H1", "Viking", ["HIGH"]], ["H2", "Shield", ["HIGH"]], ["H3", "Axe", ["HIGH"]], ["A", "Ace", ["LOW"]], ["K", "King", ["LOW"]], ["Q", "Queen", ["LOW"]], ["J", "Jack", ["LOW"]], ["W", "Wild", ["WILD"]], ["X", "Blocker (no symbol)", ["BLANK"]]]),
    reelSets: { base: { id: "base", reels } },
    paylines: {},
    paytables: { main: { id: "main", pays } },
    entryModeId: "BASE",
    modes: { BASE: { id: "BASE", entryNodeId: "b_spin", nodes: {
      b_spin: spin("b_spin", "base", 7, "$spin.board", "b_ways"),
      b_ways: { id: "b_ways", kind: "EVALUATE", phase: "EVALUATE", evaluator: { type: "PAYWAYS", board: "$spin.board", paytableId: "main", wildTag: "WILD" }, output: "$spin.wins", next: "b_sum" },
      b_sum: sumWins("b_sum", "$spin.wins", "$spin.rawWin", "b_award"),
      b_award: { id: "b_award", kind: "AWARD", phase: "SETTLE", amount: { ref: "$spin.rawWin" }, next: "b_end" },
      b_end: end("b_end")
    } } }
  });
}

// dist/src/demo/slots/stickyWilds.js
var pays2 = {
  H1: { 2: 10n, 3: 105n, 4: 420n, 5: 2100n },
  H2: { 3: 63n, 4: 252n, 5: 1050n },
  H3: { 3: 42n, 4: 168n, 5: 630n },
  H4: { 3: 32n, 4: 126n, 5: 420n },
  A: { 3: 21n, 4: 63n, 5: 210n },
  K: { 3: 21n, 4: 63n, 5: 210n },
  Q: { 3: 17n, 4: 42n, 5: 168n },
  J: { 3: 10n, 4: 42n, 5: 168n },
  T: { 3: 10n, 4: 32n, 5: 126n },
  W: { 3: 105n, 4: 525n, 5: 3150n }
};
var base2 = (c2) => ({ H1: 2, H2: 3, H3: 3, H4: 4, A: 5, K: 5, Q: 6, J: 6, T: 7, ...c2 === 1 || c2 === 2 || c2 === 3 ? { W: 1 } : {}, ...c2 % 2 === 0 ? { S: 3 } : {} });
var fs = (c2) => ({ H1: 2, H2: 2, H3: 3, H4: 3, A: 5, K: 5, Q: 6, J: 6, T: 6, ...c2 === 1 || c2 === 2 || c2 === 3 ? { W: c2 === 2 ? 1 : 2 } : {}, ...c2 % 2 === 0 ? { S: 1 } : {} });
var stickyWildsSpins = 8;
function stickyWildsDemo() {
  const paylines = lineMap(lines20.slice(0, 10)), ids = Object.keys(paylines);
  const B = {
    b_spin: spin("b_spin", "base", 3, "$spin.board", "b_lines"),
    b_lines: evalLines("b_lines", "$spin.board", "main", ids, "$spin.wins", "b_sum", "WILD"),
    b_sum: sumWins("b_sum", "$spin.wins", "$spin.win", "b_award"),
    b_award: { id: "b_award", kind: "AWARD", phase: "SETTLE", amount: ref("$spin.win"), next: "b_scatter" },
    b_scatter: countTag("b_scatter", "$spin.board", "SCATTER", "$spin.scatterCount", "b_trigger"),
    b_trigger: when("b_trigger", ge(ref("$spin.scatterCount"), lit2(3)), "b_setfs", "b_end"),
    b_setfs: setState("b_setfs", "remainingSpins", lit2(stickyWildsSpins), "b_enterfs"),
    b_enterfs: enter("b_enterfs", "FREE_SPINS"),
    b_end: end("b_end")
  };
  const F = {
    f_spin: spin("f_spin", "fs", 3, "$spin.board", "f_sticky"),
    f_sticky: { id: "f_sticky", kind: "STICKY_WILD", phase: "TRANSFORM", board: "$spin.board", output: "$spin.sticky", stateKey: "sticky", wild: "W", next: "f_lines" },
    f_lines: evalLines("f_lines", "$spin.sticky", "main", ids, "$spin.wins", "f_sum", "WILD"),
    f_sum: sumWins("f_sum", "$spin.wins", "$spin.win", "f_award"),
    f_award: { id: "f_award", kind: "AWARD", phase: "SETTLE", amount: ref("$spin.win"), next: "f_dec" },
    f_dec: addState("f_dec", "remainingSpins", lit2(-1), "f_more"),
    f_more: { id: "f_more", kind: "CONDITION", phase: "TRANSITION", expression: gt(ref("$state.remainingSpins"), lit2(0)), onTrue: "f_spin", onFalse: "f_end" },
    f_end: end("f_end")
  };
  return game({
    id: "sticky-wilds",
    wager: { activePaylineIds: ids, totalBet: 10n, payoutUnit: "CREDITS" },
    symbols: symbolMap([["H1", "Pharaoh", ["HIGH"]], ["H2", "Scarab", ["HIGH"]], ["H3", "Ankh", ["HIGH"]], ["H4", "Eye", ["HIGH"]], ["A", "Ace", ["LOW"]], ["K", "King", ["LOW"]], ["Q", "Queen", ["LOW"]], ["J", "Jack", ["LOW"]], ["T", "Ten", ["LOW"]], ["W", "Sticky Wild", ["WILD"]], ["S", "Pyramid Scatter", ["SCATTER"]]]),
    reelSets: {
      base: { id: "base", reels: Array.from({ length: 5 }, (_, c2) => ({ id: `b${c2 + 1}`, symbols: strip(base2(c2), 101 + c2 * 31) })) },
      fs: { id: "fs", reels: Array.from({ length: 5 }, (_, c2) => ({ id: `f${c2 + 1}`, symbols: strip(fs(c2), 907 + c2 * 13) })) }
    },
    paylines,
    paytables: { main: { id: "main", pays: pays2 } },
    entryModeId: "BASE",
    modes: { BASE: { id: "BASE", entryNodeId: "b_spin", nodes: B }, FREE_SPINS: { id: "FREE_SPINS", entryNodeId: "f_spin", nodes: F } }
  });
}

// dist/src/mechanics/stickyWild.js
function apply(board, previous, wild) {
  const positions = new Set(Array.isArray(previous) ? previous : []);
  for (let row = 0; row < board.rows; row++)
    for (let col = 0; col < board.cols; col++)
      if (board.symbols[row][col] === wild)
        positions.add(row * board.cols + col);
  const symbols = board.symbols.map((line, row) => line.map((symbol, col) => positions.has(row * board.cols + col) ? wild : symbol));
  return { board: { ...board, symbols }, positions: [...positions].sort((a, b) => a - b) };
}
var handler = {
  kind: "STICKY_WILD",
  capabilities: (n) => ({ stochastic: false, enumerable: false, deterministic: true, readsFrame: [n.board], writesFrame: [n.output], readsState: [n.stateKey], writesState: [n.stateKey], mayBranch: false, mayTransitionMode: false }),
  runtime: (c2) => {
    const result = apply(c2.frame.get(c2.node.board), c2.state.values[c2.node.stateKey], c2.node.wild);
    c2.frame.set(c2.node.output, result.board);
    return { next: c2.node.next, state: { ...c2.state, values: { ...c2.state.values, [c2.node.stateKey]: result.positions } } };
  },
  exact: (c2) => {
    const result = apply(c2.frame[c2.node.board], c2.values[c2.node.stateKey], c2.node.wild);
    c2.frame[c2.node.output] = result.board;
    c2.values[c2.node.stateKey] = result.positions;
    return { next: c2.node.next };
  }
};
var stickyWildExtension = defineExtension({ id: "mechanic.sticky-wild", version: "1.0.0", nodeTypes: [{
  kind: "STICKY_WILD",
  validate: (n) => n.kind === "STICKY_WILD" && typeof n.board === "string" && typeof n.output === "string" && typeof n.stateKey === "string" && typeof n.wild === "string",
  capabilities: (n) => handler.capabilities(n),
  handler
}] });

// dist/src/demo/instant/mines.js
var binom = (n, k) => {
  let r = 1n;
  for (let i = 0; i < k; i++)
    r = r * BigInt(n - i) / BigInt(i + 1);
  return r;
};
function minesPay(mines, picks, tiles = 25) {
  const num2 = 97n * binom(tiles, picks), den = binom(tiles - mines, picks);
  return (2n * num2 + den) / (2n * den);
}
function minesDemo(mines = 3, picks = 5) {
  const tiles = 25;
  if (mines < 1 || mines >= tiles || picks < 1 || picks > tiles - mines)
    throw new Error("bad mines/picks");
  const nodes2 = {};
  for (let i = 0; i < picks; i++) {
    nodes2[`reveal${i}`] = { id: `reveal${i}`, kind: "SOURCE", phase: "GENERATE", source: { type: "WEIGHTED_CHOICE", outcomes: [{ value: "GEM", weight: BigInt(tiles - mines - i) }, { value: "MINE", weight: BigInt(mines) }] }, output: "$round.tile", next: `check${i}` };
    nodes2[`check${i}`] = { id: `check${i}`, kind: "CONDITION", phase: "TRIGGER", expression: { op: "==", left: { ref: "$round.tile" }, right: { const: "GEM" } }, onTrue: i + 1 === picks ? "cashout" : `reveal${i + 1}`, onFalse: "boom" };
  }
  nodes2.cashout = { id: "cashout", kind: "AWARD", phase: "SETTLE", amount: { const: minesPay(mines, picks) }, next: "end" };
  nodes2.boom = { id: "boom", kind: "FLOW", phase: "TRANSITION", operation: { type: "END_GAME" } };
  nodes2.end = { id: "end", kind: "FLOW", phase: "TRANSITION", operation: { type: "END_GAME" } };
  return {
    id: `mines-${mines}m-${picks}p`,
    version: "1.0.0",
    semanticsVersion: 1,
    rng: { algorithm: "ADDRESS_HASH_V1", algorithmVersion: 1, addressingVersion: 1 },
    wager: { activePaylineIds: [], totalBet: 100n, payoutUnit: "CREDITS" },
    symbols: { GEM: { id: "GEM", name: "Gem (safe tile)", tags: ["SAFE"] }, MINE: { id: "MINE", name: "Mine", tags: ["MINE"] } },
    reelSets: {},
    paylines: {},
    paytables: { cashout: { id: "cashout", pays: { CASHOUT: Object.fromEntries(Array.from({ length: tiles - mines }, (_, k) => [k + 1, minesPay(mines, k + 1)])) } } },
    entryModeId: "BASE",
    modes: { BASE: { id: "BASE", entryNodeId: "reveal0", nodes: nodes2 } }
  };
}

// dist/src/demo/instant/scratch.js
var scratchPrizes = [
  { id: "JACKPOT", name: "Jackpot 1000x", pay: 100000n, weight: 1n },
  { id: "P100", name: "Prize 100x", pay: 10000n, weight: 2n },
  { id: "P50", name: "Prize 50x", pay: 5000n, weight: 3n },
  { id: "P20", name: "Prize 20x", pay: 2000n, weight: 4n },
  { id: "P10", name: "Prize 10x", pay: 1000n, weight: 6n },
  { id: "P5", name: "Prize 5x", pay: 500n, weight: 9n },
  { id: "P3", name: "Prize 3x", pay: 300n, weight: 13n },
  { id: "P1_5", name: "Prize 1.5x", pay: 150n, weight: 18n },
  { id: "P1", name: "Prize 1x (ticket back)", pay: 100n, weight: 24n }
];
function scratchDemo(cells = 6) {
  const P = scratchPrizes, nodes2 = {};
  P.forEach((p, i) => {
    nodes2[`init${p.id}`] = { id: `init${p.id}`, kind: "STATE", phase: "MUTATE", target: `c${p.id}`, op: "SET", value: { const: 0n }, next: i + 1 < P.length ? `init${P[i + 1].id}` : "cell0" };
  });
  for (let c2 = 0; c2 < cells; c2++) {
    const nxt = c2 + 1 < cells ? `cell${c2 + 1}` : `pay${P[0].id}`;
    nodes2[`cell${c2}`] = { id: `cell${c2}`, kind: "SOURCE", phase: "GENERATE", source: { type: "WEIGHTED_CHOICE", outcomes: P.map((p) => ({ value: p.id, weight: p.weight })) }, output: "$cell.symbol", next: `is${c2}_${P[0].id}` };
    P.forEach((p, i) => {
      if (i + 1 < P.length)
        nodes2[`is${c2}_${p.id}`] = { id: `is${c2}_${p.id}`, kind: "CONDITION", phase: "TRIGGER", expression: { op: "==", left: { ref: "$cell.symbol" }, right: { const: p.id } }, onTrue: `add${c2}_${p.id}`, onFalse: i + 2 < P.length ? `is${c2}_${P[i + 1].id}` : `add${c2}_${P[i + 1].id}` };
      nodes2[`add${c2}_${p.id}`] = { id: `add${c2}_${p.id}`, kind: "STATE", phase: "MUTATE", target: `c${p.id}`, op: "ADD", value: { const: 1n }, next: nxt };
    });
  }
  P.forEach((p, i) => {
    nodes2[`pay${p.id}`] = { id: `pay${p.id}`, kind: "CONDITION", phase: "TRIGGER", expression: { op: ">=", left: { ref: `$state.c${p.id}` }, right: { const: 3n } }, onTrue: `award${p.id}`, onFalse: i + 1 < P.length ? `pay${P[i + 1].id}` : "end" };
    nodes2[`award${p.id}`] = { id: `award${p.id}`, kind: "AWARD", phase: "SETTLE", amount: { const: p.pay }, next: "end" };
  });
  nodes2.end = { id: "end", kind: "FLOW", phase: "TRANSITION", operation: { type: "END_GAME" } };
  return {
    id: "scratch-match3",
    version: "1.0.0",
    semanticsVersion: 1,
    rng: { algorithm: "ADDRESS_HASH_V1", algorithmVersion: 1, addressingVersion: 1 },
    wager: { activePaylineIds: [], totalBet: 100n, payoutUnit: "CREDITS" },
    symbols: Object.fromEntries(P.map((p) => [p.id, { id: p.id, name: p.name, tags: ["PRIZE"] }])),
    reelSets: {},
    paylines: {},
    paytables: { ticket: { id: "ticket", pays: Object.fromEntries(P.map((p) => [p.id, { 3: p.pay }])) } },
    entryModeId: "BASE",
    modes: { BASE: { id: "BASE", entryNodeId: `init${P[0].id}`, nodes: nodes2 } }
  };
}

// dist/src/demo/instant/dice.js
function dicePay(winOutcomes) {
  return 9900n / BigInt(winOutcomes);
}
function diceDemo(direction = "UNDER", target = 50) {
  const win = direction === "UNDER" ? target : 99 - target;
  if (win < 1 || win > 98)
    throw new Error("target out of range");
  const nodes2 = {
    roll: { id: "roll", kind: "SOURCE", phase: "GENERATE", source: { type: "WEIGHTED_CHOICE", outcomes: Array.from({ length: 100 }, (_, v) => ({ value: BigInt(v), weight: 1n })) }, output: "$round.roll", next: "check" },
    check: { id: "check", kind: "CONDITION", phase: "TRIGGER", expression: { op: direction === "UNDER" ? "<" : ">", left: { ref: "$round.roll" }, right: { const: BigInt(target) } }, onTrue: "pay", onFalse: "end" },
    pay: { id: "pay", kind: "AWARD", phase: "SETTLE", amount: { const: dicePay(win) }, next: "end" },
    end: { id: "end", kind: "FLOW", phase: "TRANSITION", operation: { type: "END_GAME" } }
  };
  return {
    id: `dice-${direction.toLowerCase()}-${target}`,
    version: "1.0.0",
    semanticsVersion: 1,
    rng: { algorithm: "ADDRESS_HASH_V1", algorithmVersion: 1, addressingVersion: 1 },
    wager: { activePaylineIds: [], totalBet: 100n, payoutUnit: "CREDITS" },
    symbols: {},
    reelSets: {},
    paylines: {},
    paytables: { dice: { id: "dice", pays: { WIN: { 1: dicePay(win) } } } },
    entryModeId: "BASE",
    modes: { BASE: { id: "BASE", entryNodeId: "roll", nodes: nodes2 } }
  };
}

// dist/src/demo/catalog.js
var finite = ["EV", "HIT_RATE", "VARIANCE", "EXPECTED_DURATION", "DISTRIBUTION"];
var slot = [slotMechanicsExtension];
var demoCatalog = Object.freeze([
  { id: "classic3Reel", title: "Classic 3x3 fruit slot, 5 lines, bet 5", tags: ["reels", "paylines", "classic"], definition: classic3ReelDemo, extensions: slot, exactQueries: finite },
  { id: "videoSlot20", title: "5x3 video slot, 20 lines, 10 free spins x3 on FS reels", tags: ["reels", "paylines", "free-spins", "retrigger", "multiplier"], definition: videoSlot20Demo, extensions: slot, exactQueries: finite },
  { id: "ways243", title: "5x3 243 ways, 8 free spins x2 on FS reels", tags: ["reels", "ways", "free-spins", "extension"], definition: ways243Demo, extensions: slot, exactQueries: ["EV", "HIT_RATE", "VARIANCE", "EXPECTED_DURATION"] },
  { id: "scatterPays", title: "5x3, 20 lines + scatter pays 2x/10x/50x, 15 free spins", tags: ["reels", "paylines", "scatter-pays", "free-spins"], definition: scatterPaysDemo, extensions: slot, exactQueries: finite },
  { id: "buyFreeSpins", title: "Bonus buy 100x bet: 10 free spins x2 on FS reels", tags: ["reels", "paylines", "bonus-buy", "free-spins"], definition: buyFreeSpinsDemo, extensions: slot, exactQueries: ["EV", "HIT_RATE", "VARIANCE", "EXPECTED_DURATION"] },
  { id: "expandingWilds", title: "5x3, 10 lines, expanding wilds in base and free spins", tags: ["reels", "paylines", "expanding-wild", "free-spins", "extension"], definition: expandingWildsDemo, extensions: slot, exactQueries: finite },
  { id: "fishCollector", title: "5x3, 10 lines, fisherman wild collects fish money in free spins", tags: ["reels", "paylines", "collector", "free-spins", "extension"], definition: fishCollectorDemo, extensions: slot, exactQueries: ["EV", "HIT_RATE"] },
  { id: "cascades", title: "5x3 cascading reels, 20 lines, x1/x2/x3/x5 tumble multiplier", tags: ["reels", "paylines", "cascade", "tumble", "multiplier", "extension"], definition: cascadesDemo, extensions: slot, exactQueries: ["EV", "VARIANCE", "HIT_RATE"] },
  { id: "holdAndWin", title: "5x3 Hold & Win, 6+ coins, 3 respins on hold reels, grand", tags: ["reels", "paylines", "respins", "sticky-coins", "extension"], definition: holdAndWinDemo, extensions: slot, exactQueries: ["EV"] },
  { id: "megaways", title: "Megaways 6 \u0431\u0430\u0440\u0430\u0431\u0430\u043D\u043E\u0432, \u0432\u044B\u0441\u043E\u0442\u0430 2-7, \u0434\u043E 117 649 ways, bet 30", tags: ["reels", "ways", "megaways", "variable-height", "extension"], definition: megawaysDemo, extensions: slot, exactQueries: ["EV"] },
  { id: "stickyWilds", title: "5x3, 10 lines, 8 free spins with sticky wilds on reels 2-4, bet 10", tags: ["reels", "paylines", "sticky-wild", "free-spins", "extension"], definition: stickyWildsDemo, extensions: [slotMechanicsExtension, stickyWildExtension], exactQueries: ["EV", "RTP"] },
  { id: "crash", title: "Aviator-style crash ladder (auto cashout 3x, 97% RTP)", tags: ["crash", "weighted-choice"], definition: () => crashDemo(), extensions: [], exactQueries: finite },
  { id: "plinko", title: "Plinko 4 peg rows, 5 buckets, bet 100, 97.5% RTP", tags: ["plinko", "markov", "buckets"], definition: plinkoDemo, extensions: [], exactQueries: finite },
  { id: "mines", title: "Mines 5x5, 3 \u043C\u0438\u043D\u044B, \u043A\u044D\u0448\u0430\u0443\u0442 \u043F\u043E\u0441\u043B\u0435 5 \u0433\u0435\u043C\u043E\u0432 (x1.96), 97% RTP", tags: ["mines", "grid-reveal", "cashout", "markov"], definition: () => minesDemo(), extensions: [], exactQueries: finite },
  { id: "scratch", title: "\u0421\u043A\u0440\u0435\u0442\u0447-\u043A\u0430\u0440\u0442\u0430 \xAB3 \u043E\u0434\u0438\u043D\u0430\u043A\u043E\u0432\u044B\u0445\xBB \u0438\u0437 6 \u044F\u0447\u0435\u0435\u043A, \u0431\u0438\u043B\u0435\u0442 100, \u0434\u0436\u0435\u043A\u043F\u043E\u0442 1000x", tags: ["scratch", "instant-win", "markov"], definition: () => scratchDemo(), extensions: [], exactQueries: finite },
  { id: "dice", title: "Dice under 50 (0-99), \u0432\u044B\u043F\u043B\u0430\u0442\u0430 x1.98, 99% RTP", tags: ["dice", "over-under", "instant"], definition: () => diceDemo(), extensions: [], exactQueries: finite }
]);
function getDemo(id) {
  const d = demoCatalog.find((x) => x.id === id);
  if (!d)
    throw new Error(`unknown demo ${id}`);
  return d;
}
function solveDemo(id, query, options = {}) {
  const d = getDemo(id);
  return createMathEngine({ extensions: [...d.extensions] }).solve(d.definition(), { type: query }, options);
}

// dist/src/math/primitives/plan.js
var PLAN_SCHEMA = "mginx.plan/1";
var OPERATOR_FOLDS = {
  cascade: { kind: "stopEnum", ladder: true },
  holdWin: { kind: "maskMarkov", mask: "coin" },
  stickyWild: { kind: "regen", inner: { kind: "maskMarkov", mask: "stickyWild" }, buyOnly: false, retrigger: false },
  linesEnum: { kind: "columnDP", observe: ["lines"] },
  waysDp: { kind: "columnDP", observe: ["ways"] },
  freeSpins: { kind: "regen", inner: { kind: "columnDP", observe: ["lines"] }, buyOnly: false, retrigger: true },
  dice: { kind: "graphExact" },
  survivalChain: { kind: "graphExact" },
  scratch: { kind: "graphExact" },
  plinko: { kind: "graphExact" }
};
function foldSignature(f) {
  switch (f.kind) {
    case "columnDP":
      return `columnDP`;
    case "stopEnum":
      return "stopEnum";
    case "maskMarkov":
      return `maskMarkov:${f.mask}`;
    case "graphExact":
      return "graphExact";
    case "regen":
      return `regen(${f.base ? foldSignature(f.base) + "+" : ""}${foldSignature(f.inner)})`;
  }
}
function emitPlan(def, id, operator) {
  const bet = Number(def.wager?.totalBet ?? 1n);
  const opFold = OPERATOR_FOLDS[operator.kind] ?? null;
  const spec = specialisedFold(def);
  const fold = opFold && spec && foldSignature(spec) === foldSignature(opFold) ? spec : opFold;
  const parallel = fold && (fold.kind === "stopEnum" || fold.kind === "columnDP" && operator.kind === "waysDp") ? "stopRange" : "none";
  return { schema: PLAN_SCHEMA, id, bet, fold, operator, parallel };
}

// bench/core.mjs
var num = (x) => x == null ? null : typeof x === "number" ? x : typeof x === "bigint" ? Number(x) : typeof x.toNumber === "function" ? x.toNumber() : Number(x);
var demos = () => demoCatalog.map((d) => ({ id: d.id, title: d.title, tags: d.tags }));
var now = () => performance.now();
var median = (a) => {
  const s = [...a].sort((x, y) => x - y);
  return s[s.length >> 1];
};
function tsSolveOnce(id) {
  const d = demoCatalog.find((x) => x.id === id);
  const bet = Number(d.definition().wager?.totalBet ?? 1n);
  const t = now();
  const r = solveDemo(id, "EV");
  const ms = now() - t;
  const ev = num(r.result.ev);
  return { ms, ev, rtp: ev / bet, solver: r.plan.solver, exact: !!r.plan.exact };
}
function tsBench(id, { runs = 5, longMs = 1500 } = {}) {
  const first = tsSolveOnce(id);
  if (first.ms > longMs) return { ...first, runs: 1, mode: "single" };
  const ms = [];
  let last = first;
  for (let i = 0; i < runs; i++) {
    last = tsSolveOnce(id);
    ms.push(last.ms);
  }
  return { ...last, ms: median(ms), firstMs: first.ms, runs, mode: `median${runs}` };
}
var symIndex = (def) => {
  const ids = Object.keys(def.symbols);
  return { ids, SI: new Map(ids.map((s, i) => [s, i])) };
};
var tagSet = (def, ids, tag) => ids.map((s) => def.symbols[s]?.tags.includes(tag) ? 1 : 0);
var payTable = (def, pid, ids, cols) => {
  const P = cols + 1, pay = new Array(ids.length * P).fill(0);
  for (const [s, p] of Object.entries(def.paytables[pid].pays)) {
    const i = ids.indexOf(s);
    if (i < 0) continue;
    for (const [n, v] of Object.entries(p)) if (+n <= cols) pay[i * P + +n] = Number(v);
  }
  return pay;
};
var nodesOf = (def) => def.modes[def.entryModeId].nodes;
function exportPlanDef(def, id, kind = id) {
  const op = exportSpecDef(def, id, kind);
  const { id: _i, bet: _b, ...operator } = op;
  return emitPlan(def, id, operator);
}
function exportPlan(id) {
  const d = demoCatalog.find((x) => x.id === id);
  return exportPlanDef(d.definition(), id, id);
}
function exportSpecDef(def, id, kind = id) {
  const bet = Number(def.wager?.totalBet ?? 1n);
  const base3 = { id, bet };
  const T = compileCascade(def);
  if (T) return { ...base3, kind: "cascade", ...T };
  const H = compileHoldWin(def);
  if (H) {
    const { ids, SI } = symIndex(def);
    const map = (r) => r.map((s) => SI.get(s));
    return {
      ...base3,
      kind: "holdWin",
      rows: H.rows,
      cols: H.cols,
      nSym: ids.length,
      baseReels: H.baseReels.map(map),
      holdReels: H.holdReels.map(map),
      coinValue: ids.map((s) => H.coinValue[s] ?? 0),
      isCoin: ids.map((s) => s in H.coinValue ? 1 : 0),
      trigger: H.trigger,
      respins: H.respins,
      grand: H.grand,
      wild: tagSet(def, ids, H.wildTag ?? "WILD"),
      pay: payTable(def, H.linePaytableId, ids, H.cols),
      nLines: H.lineIds.length
    };
  }
  const S = compileStickyWild(def);
  if (S) {
    const { ids, SI } = symIndex(def);
    const map = (r) => r.map((s) => SI.get(s));
    return {
      ...base3,
      kind: "stickyWild",
      rows: S.rows,
      cols: S.cols,
      nSym: ids.length,
      baseReels: S.baseReels.map(map),
      fsReels: S.fsReels.map(map),
      wildSym: SI.get(S.wild),
      wild: tagSet(def, ids, S.wildTag),
      scatter: tagSet(def, ids, S.scatterTag),
      trigger: S.trigger,
      spins: S.spins,
      pay: payTable(def, S.paytableId, ids, S.cols),
      lines: S.lineIds.map((l) => [...def.paylines[l].rows])
    };
  }
  const fsSpec = exportFreeSpins(def);
  if (fsSpec) return { ...base3, ...fsSpec };
  const nodes2 = nodesOf(def), all = Object.values(nodes2);
  if (Object.keys(def.modes).length === 1) {
    const spin2 = all.find((n) => n.source?.type === "REEL_SPIN");
    if (spin2) {
      const ev = nodes2[spin2.next]?.evaluator;
      const { ids, SI } = symIndex(def);
      const reels = def.reelSets[spin2.source.reelSetId].reels.map((r) => r.symbols.map((s) => SI.get(s)));
      const cols = reels.length;
      if (ev?.type === "PAYLINES") return { ...base3, kind: "linesEnum", rows: Number(spin2.source.rows), cols, nSym: ids.length, reels, wild: tagSet(def, ids, ev.wildTag ?? "WILD"), pay: payTable(def, ev.paytableId, ids, cols), lines: ev.paylineIds.map((l) => [...def.paylines[l].rows]) };
      if (ev?.type === "PAYWAYS") {
        const wild = tagSet(def, ids, ev.wildTag ?? "WILD");
        const paying = Object.keys(def.paytables[ev.paytableId].pays).filter((s) => !wild[SI.get(s)]).map((s) => SI.get(s));
        return { ...base3, kind: "waysDp", rows: Number(spin2.source.rows), cols, nSym: ids.length, reels, wild, paying, pay: payTable(def, ev.paytableId, ids, cols) };
      }
    }
    if (kind === "dice") {
      const r = nodes2.roll, c2 = nodes2.check;
      return { ...base3, kind: "dice", outcomes: r.source.outcomes.map((o) => Number(o.weight)), op: c2.expression.op, target: Number(c2.expression.right.const), pay: Number(nodes2.pay.amount.const) };
    }
    if (kind === "crash" || kind === "mines") {
      const steps2 = all.filter((n) => n.source?.type === "WEIGHTED_CHOICE").map((n) => {
        const w = n.source.outcomes.map((o) => Number(o.weight));
        return [w[0], w.reduce((a, b) => a + b, 0)];
      });
      return { ...base3, kind: "survivalChain", steps: steps2, pay: Number(nodes2.cashout.amount.const) };
    }
    if (kind === "scratch") {
      const src = all.find((n) => n.source?.type === "WEIGHTED_CHOICE");
      const cells = all.filter((n) => /^cell\d+$/.test(n.id)).length;
      const order = src.source.outcomes.map((o) => o.value);
      const pays3 = order.map((s) => Number(def.paytables.ticket.pays[s][3]));
      return { ...base3, kind: "scratch", cells, need: 3, weights: src.source.outcomes.map((o) => Number(o.weight)), pays: pays3 };
    }
    if (kind === "plinko") {
      const rows = Number(nodes2.landed.expression.right.const);
      const buckets = all.filter((n) => /^payB\d+$/.test(n.id)).sort((a, b) => a.id.localeCompare(b.id)).map((n) => Number(n.amount.const));
      const w = nodes2.peg.source.outcomes.map((o) => Number(o.weight));
      return { ...base3, kind: "plinko", rows, buckets, wL: w[0], wR: w[1] };
    }
  }
  return { ...base3, kind: "notPorted", reason: "generic HYBRID column-DP + regenerative free-spins planner (not ported to Rust yet)" };
}
function exportFreeSpins(def) {
  const fm = def.modes.FREE_SPINS;
  if (!fm || !fm.nodes.f_spin || !fm.nodes.f_retrigger) return null;
  const { ids, SI } = symIndex(def);
  const stage = (p, nodes2) => {
    const sp = nodes2[`${p}spin`];
    const reels = def.reelSets[sp.source.reelSetId].reels.map((r) => r.symbols.map((s) => SI.get(s)));
    const ev = nodes2[`${p}ways`] ? "WAYS" : nodes2[`${p}expand`] ? "EXPAND" : "LINES";
    const ln = nodes2[`${p}lines`] ?? nodes2[`${p}ways`];
    const aw = nodes2[`${p}award`].amount;
    const mult = "op" in aw ? Number(aw.right.const) : 1;
    let extra = null;
    if (nodes2[`${p}sp3`]) {
      const steps2 = [];
      let n = nodes2[`${p}x0`];
      while (n?.kind === "CONDITION" && nodes2[n.onTrue]?.kind === "AWARD") {
        steps2.push([Number(n.expression.right.const), Number(nodes2[n.onTrue].amount.const)]);
        n = nodes2[n.onFalse];
      }
      extra = { kind: "scatterPay", steps: steps2 };
    } else if (nodes2[`${p}x0`]?.evaluator?.type === "COLLECT_VALUES") {
      const e = nodes2[`${p}x0`].evaluator;
      extra = { kind: "collect", collector: tagSet(def, ids, e.collectorTag), value: ids.map((s) => def.symbols[s].tags.includes(e.valueTag) ? Number(def.paytables[e.paytableId].pays[s]?.[1] ?? 0n) : 0) };
    }
    return { reels, eval: ev, mult, extra, paytableId: ln.evaluator.paytableId };
  };
  const fsN = fm.nodes, f = stage("f_", fsN);
  const b = def.modes.BASE ? stage("b_", def.modes.BASE.nodes) : null;
  const spins = Number((def.modes.BASE?.nodes.b_setfs ?? def.modes.BUY.nodes.buy_set).value.const), retrigger = Number(fsN.f_add.value.const), scatterMin = Number(fsN.f_retrigger.expression.right.const);
  const pid = f.paytableId, cols = f.reels.length;
  const lineIds = fsN.f_lines?.evaluator.paylineIds ?? [];
  return {
    kind: "freeSpins",
    rows: 3,
    cols,
    nSym: ids.length,
    base: b,
    fs: f,
    spins,
    retrigger,
    scatterMin,
    scatter: tagSet(def, ids, "SCATTER"),
    wild: tagSet(def, ids, "WILD"),
    pay: payTable(def, pid, ids, cols),
    paying: Object.keys(def.paytables[pid].pays).filter((s) => !def.symbols[s].tags.includes("WILD")).map((s) => SI.get(s)),
    lines: lineIds.map((l) => [...def.paylines[l].rows])
  };
}

// bench/web/worker.mjs
import init, { solve as solve2, split_meta } from "./pkg/mginx_bench.js";

// bench/scripts/common.mjs
var median2 = (a) => {
  const s = [...a].sort((x, y) => x - y);
  return s[s.length >> 1];
};
function timeIt(fn, { runs = 5, longMs = 1500 } = {}) {
  let t = performance.now();
  let r = fn();
  const first = performance.now() - t;
  if (first > longMs || r?.notPorted) return { ...r, ms: first, runs: 1, mode: "single" };
  const ms = [];
  for (let i = 0; i < runs; i++) {
    t = performance.now();
    r = fn();
    ms.push(performance.now() - t);
  }
  return { ...r, ms: median2(ms), firstMs: first, runs, mode: `median${runs}` };
}

// bench/web/worker.mjs
var ready = init({ module_or_path: new URL("./pkg/mginx_bench_bg.wasm", self.location.href) });
self.onmessage = async (e) => {
  if (e.data.specOf) {
    const spec = JSON.stringify(exportPlan(e.data.specOf));
    self.postMessage({ specOf: e.data.specOf, spec, n0: JSON.parse(split_meta(spec)).n0 });
    return;
  }
  const { id, engine } = e.data;
  await ready;
  let r;
  try {
    r = engine === "ts" ? tsBench(id) : timeIt(() => JSON.parse(solve2(JSON.stringify(exportPlan(id)))));
  } catch (err) {
    r = { error: String(err?.message ?? err) };
  }
  self.postMessage({ id, engine, r });
};
await ready;
self.postMessage({ demos: demos(), splittable: demos().map((d) => d.id).filter((id) => JSON.parse(split_meta(JSON.stringify(exportPlan(id)))).n0 > 0) });

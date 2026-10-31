#![no_std]
//! Base-game exact EV by full reel-stop enumeration (lines / ways), same algorithm as docs/kernel.wgsl.
//! Config layout (u32): [0]=cols [1]=pay stride [2]=mode(0 lines,1 ways) [3]=nLines [4]=nSym
//! [8..16]=reel lens [16..24]=reel offsets [24..40]=wild flags [40..168]=pay [168..328]=lines [328..]=reels
#[panic_handler] fn p(_: &core::panic::PanicInfo) -> ! { loop {} }

static mut CFG: [u32; 16384] = [0; 16384];
#[unsafe(no_mangle)] pub extern "C" fn cfg_ptr() -> *mut u32 { core::ptr::addr_of_mut!(CFG) as *mut u32 }

#[inline(always)] fn cell(c: &[u32], g: &[u32; 8], col: usize, row: u32) -> u32 {
    let len = c[8 + col]; c[328 + (c[16 + col] + (g[col] + row) % len) as usize]
}

fn eval(c: &[u32], g: &[u32; 8]) -> u32 {
    let cols = c[0] as usize; let st = c[1]; let mut win = 0u32;
    if c[2] == 0 {
        for l in 0..c[3] as usize {
            let row = |k: usize| c[168 + l * cols + k];
            let s0 = cell(c, g, 0, row(0));
            // wild run
            let mut wl = 0u32; while (wl as usize) < cols && c[24 + cell(c, g, wl as usize, row(wl as usize)) as usize] == 1 { wl += 1; }
            let mut best = if wl > 0 { c[40 + (s0 * st + wl) as usize] } else { 0 };
            if (wl as usize) < cols {
                let s = cell(c, g, wl as usize, row(wl as usize));
                let mut n = wl + 1;
                while (n as usize) < cols { let x = cell(c, g, n as usize, row(n as usize)); if x == s || c[24 + x as usize] == 1 { n += 1 } else { break } }
                let pw = c[40 + (s * st + n) as usize]; if pw > best { best = pw; }
            }
            win += best;
        }
    } else {
        for s in 0..c[4] {
            if c[24 + s as usize] == 1 { continue; }
            let mut ways = 1u32; let mut n = 0u32;
            for k in 0..cols { let mut m = 0u32; for r in 0..3 { let x = cell(c, g, k, r); if x == s || c[24 + x as usize] == 1 { m += 1; } }
                if m == 0 { break; } ways *= m; n += 1; }
            if n > 0 { win += c[40 + (s * st + n) as usize] * ways; }
        }
    }
    win
}

/// Sum of base-game wins over all stop combos with reel-1 stop in [lo,hi).
#[unsafe(no_mangle)] pub extern "C" fn solve_range(lo: u32, hi: u32) -> f64 {
    let c: &[u32] = unsafe { &*core::ptr::addr_of!(CFG) };
    let cols = c[0] as usize; let mut g = [0u32; 8]; let mut tot = 0f64;
    let mut rest = 1u64; for k in 1..cols { rest *= c[8 + k] as u64; }
    for s0 in lo..hi { g[0] = s0;
        for mut i in 0..rest { for k in 1..cols { let l = c[8 + k] as u64; g[k] = (i % l) as u32; i /= l; }
            tot += eval(c, &g) as f64; } }
    tot
}

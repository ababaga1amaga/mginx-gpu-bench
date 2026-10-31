#![no_std]
#[panic_handler] fn p(_: &core::panic::PanicInfo) -> ! { loop {} }

#[inline(always)]
fn pcg(v: u32) -> u32 {
    let s = v.wrapping_mul(747796405).wrapping_add(2891336453);
    let w = ((s >> ((s >> 28) + 4)) ^ s).wrapping_mul(277803737);
    (w >> 22) ^ w
}

static mut BINS: [u32; 256] = [0; 256];

#[unsafe(no_mangle)] pub extern "C" fn bins_ptr() -> *const u32 { unsafe { core::ptr::addr_of!(BINS) as *const u32 } }

/// Plinko MC: n balls, rows pegs; returns nothing, fills BINS[0..=rows].
#[unsafe(no_mangle)] pub extern "C" fn plinko(n: u32, rows: u32, seed: u32) {
    unsafe {
        let b = &mut *core::ptr::addr_of_mut!(BINS);
        for x in b.iter_mut() { *x = 0; }
        for i in 0..n {
            let mut st = pcg(i ^ seed);
            let mut pos = 0u32;
            for _ in 0..rows { st = pcg(st); pos += st & 1; }
            b[(pos & 255) as usize] += 1;
        }
    }
}

/// Column fold: n columns, k rows each; per column product of (pcg(..)|1) and wrap-sum of products.
#[unsafe(no_mangle)] pub extern "C" fn colfold(n: u32, k: u32, seed: u32) -> u32 {
    let mut acc = 0u32;
    for c in 0..n {
        let mut st = pcg(c ^ seed);
        let mut prod = 1u32;
        for _ in 0..k { st = pcg(st); prod = prod.wrapping_mul(st | 1); }
        acc = acc.wrapping_add(prod);
    }
    acc
}

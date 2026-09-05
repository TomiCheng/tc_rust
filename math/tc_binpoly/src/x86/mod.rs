//! PCLMULQDQ-backed carryless multiplication.

#[cfg(target_arch = "x86")]
use core::arch::x86::{
    __m128i, _mm_clmulepi64_si128, _mm_loadu_si128, _mm_set_epi32, _mm_slli_si128, _mm_srli_si128,
    _mm_storeu_si128, _mm_unpackhi_epi64, _mm_unpacklo_epi64, _mm_xor_si128,
};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m128i, _mm_clmulepi64_si128, _mm_cvtsi64_si128, _mm_loadu_si128, _mm_slli_si128,
    _mm_srli_si128, _mm_storeu_si128, _mm_unpackhi_epi64, _mm_unpacklo_epi64, _mm_xor_si128,
};

use tc_runtime::intrinsics::x86::Pclmulqdq;

/// Measured crossover on the Rust PCLMULQDQ kernel, in `u64` limbs.
pub(crate) const KARATSUBA_CUTOFF: usize = 64;

/// Carryless multiplication over packed two-limb SIMD blocks.
pub(crate) fn impl_mul(proof: Pclmulqdq, x: &[u64], y: &[u64], zz: &mut [u64]) {
    assert_eq!(x.len(), y.len(), "input lengths differ");
    assert_eq!(zz.len(), x.len() * 2, "invalid extended output length");

    match x.len() {
        1 => impl_mul_size::<1>(proof, x, y, zz),
        2 => impl_mul_size::<2>(proof, x, y, zz),
        3 => impl_mul_size::<3>(proof, x, y, zz),
        4 => impl_mul_size::<4>(proof, x, y, zz),
        5 => impl_mul_size::<5>(proof, x, y, zz),
        6 => impl_mul_size::<6>(proof, x, y, zz),
        7 => impl_mul_size::<7>(proof, x, y, zz),
        8 => impl_mul_size::<8>(proof, x, y, zz),
        9 => impl_mul_size::<9>(proof, x, y, zz),
        10 => impl_mul_size::<10>(proof, x, y, zz),
        _ => {
            // SAFETY: construction of `proof` establishes PCLMULQDQ support.
            unsafe { impl_mul_dynamic(x, y, zz) }
        }
    }
}

#[cfg(feature = "alloc")]
pub(crate) fn karatsuba_scratch_size(len: usize) -> usize {
    crate::scalar::karatsuba_scratch_size_with_cutoff(len, KARATSUBA_CUTOFF)
}

#[cfg(feature = "alloc")]
pub(crate) fn impl_karatsuba(
    proof: Pclmulqdq,
    x: &[u64],
    y: &[u64],
    zz: &mut [u64],
    scratch: &mut [u64],
) {
    crate::scalar::impl_karatsuba_with_leaf(x, y, zz, scratch, KARATSUBA_CUTOFF, |a, b, output| {
        impl_mul(proof, a, b, output)
    });
}

/// One const-generic implementation replaces BC's Size1 through Size10
/// wrappers. `N` remains visible through the SIMD loops so LLVM can specialize
/// and unroll each fixed-width instantiation.
#[inline]
fn impl_mul_size<const N: usize>(_proof: Pclmulqdq, x: &[u64], y: &[u64], zz: &mut [u64]) {
    let x: &[u64; N] = x.try_into().expect("size dispatch checked x");
    let y: &[u64; N] = y.try_into().expect("size dispatch checked y");
    // SAFETY: the proof token establishes PCLMULQDQ support and the fixed-size
    // conversions establish every input bound used by the SIMD loops.
    unsafe { impl_mul_inner::<N>(x, y, zz) }
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn impl_mul_inner<const N: usize>(x: &[u64; N], y: &[u64; N], zz: &mut [u64]) {
    if N == 1 {
        // SAFETY: this function has the required target features.
        unsafe { impl_mul_one(x[0], y[0], zz) };
    } else if N & 1 == 0 {
        // SAFETY: this function has the required target features and N >= 2.
        unsafe { impl_mul_even_const::<N>(x, y, zz) };
    } else {
        // SAFETY: this function has the required target features and N >= 3.
        unsafe { impl_mul_odd_const::<N>(x, y, zz) };
    }
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn impl_mul_dynamic(x: &[u64], y: &[u64], zz: &mut [u64]) {
    if x.len() & 1 == 0 {
        // SAFETY: this function has the required target features.
        unsafe { impl_mul_even(x, y, zz) };
    } else {
        // The dynamic path is used only for lengths above ten.
        // SAFETY: this function has the required target features.
        unsafe { impl_mul_odd(x, y, zz) };
    }
}

/// Two-by-two Karatsuba: three CLMUL instructions instead of four. Inputs,
/// cross-term reconstruction, and outputs remain in SIMD registers.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul2x2(x: __m128i, y: __m128i) -> (__m128i, __m128i) {
    let sums = _mm_xor_si128(_mm_unpacklo_epi64(x, y), _mm_unpackhi_epi64(x, y));
    let a = _mm_clmulepi64_si128::<0x00>(x, y);
    let b = _mm_clmulepi64_si128::<0x11>(x, y);
    let c = _mm_clmulepi64_si128::<0x01>(sums, sums);
    let middle = _mm_xor_si128(_mm_xor_si128(a, b), c);
    (
        _mm_xor_si128(a, _mm_slli_si128::<8>(middle)),
        _mm_xor_si128(b, _mm_srli_si128::<8>(middle)),
    )
}

#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn impl_mul_one(x: u64, y: u64, zz: &mut [u64]) {
    // SAFETY: this function has the required target features.
    let (x, y) = unsafe { (scalar_lane(x), scalar_lane(y)) };
    let xy = _mm_unpacklo_epi64(x, y);
    let product = _mm_clmulepi64_si128::<0x01>(xy, xy);
    // SAFETY: zz contains one complete 128-bit output lane.
    unsafe { store_lane(zz, 0, product) };
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn impl_mul_even_const<const N: usize>(x: &[u64; N], y: &[u64; N], zz: &mut [u64]) {
    let len = N >> 1;
    for i in 0..len {
        // SAFETY: i addresses complete two-word lanes in x and y.
        let (xi, yi) = unsafe { (load_lane(x, i), load_lane(y, i)) };
        // SAFETY: target features are enabled by this function.
        let (w0, w1) = unsafe { mul2x2(xi, yi) };
        // SAFETY: 2*i and 2*i+1 are within the N output lanes.
        unsafe {
            store_lane(zz, i << 1, w0);
            store_lane(zz, (i << 1) + 1, w1);
        }
    }
    // SAFETY: len >= 1 and the diagonal phase initialized all output lanes.
    unsafe { finish_even(x, y, zz, len) };
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn impl_mul_odd_const<const N: usize>(x: &[u64; N], y: &[u64; N], zz: &mut [u64]) {
    let full = N >> 1;
    for i in 0..full {
        // SAFETY: i addresses complete two-word lanes in x and y.
        let (xi, yi) = unsafe { (load_lane(x, i), load_lane(y, i)) };
        // SAFETY: target features are enabled by this function.
        let (w0, w1) = unsafe { mul2x2(xi, yi) };
        // SAFETY: the full lanes occupy output lanes below 2*full.
        unsafe {
            store_lane(zz, i << 1, w0);
            store_lane(zz, (i << 1) + 1, w1);
        }
    }
    // SAFETY: N is odd and at least three here, so x[2*full] and y[2*full]
    // are the real tail words and every output lane is in bounds.
    unsafe { finish_odd(x, y, zz, full) };
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn impl_mul_even(x: &[u64], y: &[u64], zz: &mut [u64]) {
    let len = x.len() >> 1;
    for i in 0..len {
        // SAFETY: i addresses complete two-word lanes in x and y.
        let (xi, yi) = unsafe { (load_lane(x, i), load_lane(y, i)) };
        // SAFETY: target features are enabled by this function.
        let (w0, w1) = unsafe { mul2x2(xi, yi) };
        // SAFETY: the output has x.len() SIMD lanes.
        unsafe {
            store_lane(zz, i << 1, w0);
            store_lane(zz, (i << 1) + 1, w1);
        }
    }
    // SAFETY: the dynamic path has even length greater than ten.
    unsafe { finish_even(x, y, zz, len) };
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn impl_mul_odd(x: &[u64], y: &[u64], zz: &mut [u64]) {
    let full = x.len() >> 1;
    for i in 0..full {
        // SAFETY: i addresses complete two-word lanes in x and y.
        let (xi, yi) = unsafe { (load_lane(x, i), load_lane(y, i)) };
        // SAFETY: target features are enabled by this function.
        let (w0, w1) = unsafe { mul2x2(xi, yi) };
        // SAFETY: the full lanes occupy output lanes below 2*full.
        unsafe {
            store_lane(zz, i << 1, w0);
            store_lane(zz, (i << 1) + 1, w1);
        }
    }
    // SAFETY: the dynamic path has odd length greater than ten.
    unsafe { finish_odd(x, y, zz, full) };
}

/// BC's arbitrary-degree even V128 kernel: diagonal 2x2 products, a streak
/// fixup, then Karatsuba cross products grouped by output position.
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn finish_even(x: &[u64], y: &[u64], zz: &mut [u64], len: usize) {
    // SAFETY: the diagonal phase initialized lanes zero and one.
    let (mut v0, mut v1) = unsafe { (load_lane(zz, 0), load_lane(zz, 1)) };
    for i in 1..len {
        // SAFETY: all referenced lanes are within the initialized output.
        unsafe {
            v0 = _mm_xor_si128(v0, load_lane(zz, i << 1));
            store_lane(zz, i, _mm_xor_si128(v0, v1));
            v1 = _mm_xor_si128(v1, load_lane(zz, (i << 1) + 1));
        }
    }

    let streak = _mm_xor_si128(v0, v1);
    for i in 0..len {
        // SAFETY: sources are below len and destinations are in [len, 2*len).
        unsafe { store_lane(zz, len + i, _mm_xor_si128(load_lane(zz, i), streak)) };
    }

    let last = len - 1;
    for z_pos in 1..(last << 1) {
        let mut hi = core::cmp::min(last, z_pos);
        let mut lo = z_pos - hi;
        while lo < hi {
            // SAFETY: lo and hi address complete input lanes.
            let (x_lo, x_hi, y_lo, y_hi) = unsafe {
                (
                    load_lane(x, lo),
                    load_lane(x, hi),
                    load_lane(y, lo),
                    load_lane(y, hi),
                )
            };
            // SAFETY: target features are enabled by this function.
            let (w0, w1) = unsafe { mul2x2(_mm_xor_si128(x_lo, x_hi), _mm_xor_si128(y_lo, y_hi)) };
            // SAFETY: z_pos and z_pos+1 are valid output lanes.
            unsafe {
                xor_lane(zz, z_pos, w0);
                xor_lane(zz, z_pos + 1, w1);
            }
            lo += 1;
            hi -= 1;
        }
    }
}

/// Odd-length sibling of [`finish_even`], using a half-full SIMD tail lane.
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn finish_odd(x: &[u64], y: &[u64], zz: &mut [u64], full: usize) {
    // SAFETY: this function has the required target features.
    let (x_tail, y_tail) = unsafe { (scalar_lane(x[full << 1]), scalar_lane(y[full << 1])) };
    let tail_product = _mm_clmulepi64_si128::<0x00>(x_tail, y_tail);
    // SAFETY: lane 2*full is the last real output lane.
    unsafe { store_lane(zz, full << 1, tail_product) };

    // SAFETY: full >= 1 and the diagonal phase initialized lanes zero and one.
    let (mut v0, mut v1) = unsafe { (load_lane(zz, 0), load_lane(zz, 1)) };
    for i in 1..full {
        // SAFETY: all referenced lanes are within the initialized output.
        unsafe {
            v0 = _mm_xor_si128(v0, load_lane(zz, i << 1));
            store_lane(zz, i, _mm_xor_si128(v0, v1));
            v1 = _mm_xor_si128(v1, load_lane(zz, (i << 1) + 1));
        }
    }
    // SAFETY: the final diagonal lane is in bounds.
    unsafe {
        v0 = _mm_xor_si128(v0, load_lane(zz, full << 1));
        store_lane(zz, full, _mm_xor_si128(v0, v1));
    }

    let streak = _mm_xor_si128(v0, v1);
    let virtual_len = full + 1;
    for i in 0..full {
        // SAFETY: the shortened output pass never reaches a virtual slack lane.
        unsafe { store_lane(zz, virtual_len + i, _mm_xor_si128(load_lane(zz, i), streak)) };
    }

    for z_pos in 1..(full << 1) {
        let mut hi = core::cmp::min(full, z_pos);
        let mut lo = z_pos - hi;
        while lo < hi {
            // SAFETY: lo is always a complete input lane; hi may select tail.
            let (x_lo, y_lo) = unsafe { (load_lane(x, lo), load_lane(y, lo)) };
            let (x_hi, y_hi) = if hi < full {
                // SAFETY: hi addresses a complete input lane.
                unsafe { (load_lane(x, hi), load_lane(y, hi)) }
            } else {
                (x_tail, y_tail)
            };
            // SAFETY: target features are enabled by this function.
            let (w0, w1) = unsafe { mul2x2(_mm_xor_si128(x_lo, x_hi), _mm_xor_si128(y_lo, y_hi)) };
            // SAFETY: the final cross product ends at the last real lane.
            unsafe {
                xor_lane(zz, z_pos, w0);
                xor_lane(zz, z_pos + 1, w1);
            }
            lo += 1;
            hi -= 1;
        }
    }
}

#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn load_lane(words: &[u64], index: usize) -> __m128i {
    // SAFETY: callers establish that two words starting at index*2 exist.
    unsafe { _mm_loadu_si128(words.as_ptr().add(index << 1).cast::<__m128i>()) }
}

#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn store_lane(words: &mut [u64], index: usize, value: __m128i) {
    // SAFETY: callers establish that two writable words at index*2 exist.
    unsafe { _mm_storeu_si128(words.as_mut_ptr().add(index << 1).cast::<__m128i>(), value) };
}

#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn xor_lane(words: &mut [u64], index: usize, value: __m128i) {
    // SAFETY: callers establish that the lane is in bounds.
    let current = unsafe { load_lane(words, index) };
    // SAFETY: the same lane is writable.
    unsafe { store_lane(words, index, _mm_xor_si128(current, value)) };
}

#[cfg(target_arch = "x86")]
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn scalar_lane(value: u64) -> __m128i {
    _mm_set_epi32(0, 0, (value >> 32) as i32, value as i32)
}

#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn scalar_lane(value: u64) -> __m128i {
    _mm_cvtsi64_si128(value as i64)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use alloc::vec;

    use super::*;

    const REQUIRE_PCLMUL: &str = "TC_REQUIRE_X86_PCLMULQDQ";

    fn proof_or_report() -> Option<Pclmulqdq> {
        match Pclmulqdq::detect() {
            Some(proof) => Some(proof),
            None if std::env::var_os(REQUIRE_PCLMUL).is_some() => {
                panic!("PCLMULQDQ unavailable but {REQUIRE_PCLMUL} is set")
            }
            None => {
                std::eprintln!(
                    "warning: PCLMULQDQ test skipped; set {REQUIRE_PCLMUL}=1 to require it"
                );
                None
            }
        }
    }

    #[test]
    fn pclmul_matches_scalar_when_available() {
        let Some(proof) = proof_or_report() else {
            return;
        };
        for len in 1..=67 {
            let x: alloc::vec::Vec<_> = (0..len)
                .map(|i| 0x9E37_79B9_7F4A_7C15_u64.wrapping_mul(i as u64 + 1))
                .collect();
            let y: alloc::vec::Vec<_> = (0..len)
                .map(|i| 0xD1B5_4A32_D192_ED03_u64.wrapping_mul(i as u64 + 3))
                .collect();
            let mut expected = vec![0_u64; len * 2];
            crate::scalar::impl_mul(&x, &y, &mut expected);
            let mut actual = vec![0_u64; len * 2];
            impl_mul(proof, &x, &y, &mut actual);
            assert_eq!(actual, expected, "len={len}");
        }
    }

    #[test]
    fn pclmul_karatsuba_matches_scalar_when_available() {
        let Some(proof) = proof_or_report() else {
            return;
        };
        for len in [KARATSUBA_CUTOFF, KARATSUBA_CUTOFF + 1, 129] {
            let x: alloc::vec::Vec<_> = (0..len)
                .map(|i| 0xA076_1D64_78BD_642F_u64.wrapping_mul(i as u64 + 1))
                .collect();
            let y: alloc::vec::Vec<_> = (0..len)
                .map(|i| 0xE703_7ED1_A0B4_28DB_u64.wrapping_mul(i as u64 + 3))
                .collect();
            let mut expected = vec![0_u64; len * 2];
            crate::scalar::impl_mul(&x, &y, &mut expected);
            let mut actual = vec![0_u64; len * 2];
            let mut scratch = vec![0_u64; karatsuba_scratch_size(len)];
            impl_karatsuba(proof, &x, &y, &mut actual, &mut scratch);
            assert_eq!(actual, expected, "len={len}");
        }
    }
}

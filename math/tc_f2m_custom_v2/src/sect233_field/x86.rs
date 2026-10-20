// The intrinsics are unsafe before Rust 1.87 and safe inside these functions after it.
#![allow(unused_unsafe)]

#[cfg(target_arch = "x86")]
use core::arch::x86::{
    __m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_slli_si128, _mm_srli_si128,
    _mm_storeu_si128, _mm_xor_si128,
};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_slli_si128, _mm_srli_si128,
    _mm_storeu_si128, _mm_xor_si128,
};
use tc_runtime::intrinsics::x86::Pclmulqdq;

// BC's `SecT233Field.ImplMultiply` on its PCLMULQDQ path: the eight-limb product of four limbs
// by four, a 2 + 2 Karatsuba over schoolbook halves in twelve CLMULs. Constant time.
pub(super) fn impl_multiply(_proof: Pclmulqdq, x: &[u64; 4], y: &[u64; 4]) -> [u64; 8] {
    let mut zz = [0; 8];
    // SAFETY: the proof shows the CPU has PCLMULQDQ, and every such CPU has SSE2.
    unsafe { clmul(x, y, &mut zz) };
    zz
}

// The 128-bit product of two halves, as BC's three steps: low, the two middles, high.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul2(x: __m128i, y: __m128i) -> (__m128i, __m128i) {
    unsafe {
        let lo = _mm_clmulepi64_si128::<0x00>(x, y);
        let mid = _mm_xor_si128(
            _mm_clmulepi64_si128::<0x01>(x, y),
            _mm_clmulepi64_si128::<0x10>(x, y),
        );
        let hi = _mm_clmulepi64_si128::<0x11>(x, y);
        (
            _mm_xor_si128(lo, _mm_slli_si128::<8>(mid)),
            _mm_xor_si128(hi, _mm_srli_si128::<8>(mid)),
        )
    }
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn clmul(x: &[u64; 4], y: &[u64; 4], zz: &mut [u64; 8]) {
    unsafe {
        let x01 = _mm_set_epi64x(x[1] as i64, x[0] as i64);
        let x23 = _mm_set_epi64x(x[3] as i64, x[2] as i64);
        let y01 = _mm_set_epi64x(y[1] as i64, y[0] as i64);
        let y23 = _mm_set_epi64x(y[3] as i64, y[2] as i64);

        let (z01, z23) = mul2(x01, y01);
        let (z45, z67) = mul2(x23, y23);

        let x03 = _mm_xor_si128(x01, x23);
        let y03 = _mm_xor_si128(y01, y23);
        let k01 = _mm_clmulepi64_si128::<0x00>(x03, y03);
        let k12 = _mm_xor_si128(
            _mm_clmulepi64_si128::<0x01>(x03, y03),
            _mm_clmulepi64_si128::<0x10>(x03, y03),
        );
        let k23 = _mm_clmulepi64_si128::<0x11>(x03, y03);

        let t = _mm_xor_si128(z23, z45);
        let mut mid_lo = _mm_xor_si128(t, z01);
        let mut mid_hi = _mm_xor_si128(t, z67);
        mid_lo = _mm_xor_si128(mid_lo, k01);
        mid_lo = _mm_xor_si128(mid_lo, _mm_slli_si128::<8>(k12));
        mid_hi = _mm_xor_si128(mid_hi, _mm_srli_si128::<8>(k12));
        mid_hi = _mm_xor_si128(mid_hi, k23);

        let out = zz.as_mut_ptr().cast::<__m128i>();
        _mm_storeu_si128(out, z01);
        _mm_storeu_si128(out.add(1), mid_lo);
        _mm_storeu_si128(out.add(2), mid_hi);
        _mm_storeu_si128(out.add(3), z67);
    }
}

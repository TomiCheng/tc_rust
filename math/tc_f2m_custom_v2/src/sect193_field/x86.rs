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

// BC's `SecT193Field.ImplMultiply` on its PCLMULQDQ path: the low three limbs by schoolbook in
// nine CLMULs, and the one bit of the top limbs by masks rather than products. Constant time.
pub(super) fn impl_multiply(_proof: Pclmulqdq, x: &[u64; 4], y: &[u64; 4]) -> [u64; 8] {
    let mut zz = [0; 8];
    // SAFETY: the proof shows the CPU has PCLMULQDQ, and every such CPU has SSE2.
    unsafe { clmul(x, y, &mut zz) };
    let (x3, y3) = (0_u64.wrapping_sub(x[3]), 0_u64.wrapping_sub(y[3]));
    zz[3] ^= (x3 & y[0]) ^ (x[0] & y3);
    zz[4] ^= (x3 & y[1]) ^ (x[1] & y3);
    zz[5] ^= (x3 & y[2]) ^ (x[2] & y3);
    zz[6] = x3 & y[3];
    zz
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn clmul(x: &[u64; 4], y: &[u64; 4], zz: &mut [u64; 8]) {
    unsafe {
        let x01 = _mm_set_epi64x(x[1] as i64, x[0] as i64);
        let y01 = _mm_set_epi64x(y[1] as i64, y[0] as i64);
        let xy2 = _mm_set_epi64x(y[2] as i64, x[2] as i64);

        let mut z01 = _mm_clmulepi64_si128::<0x00>(x01, y01);
        let z12 = _mm_xor_si128(
            _mm_clmulepi64_si128::<0x01>(x01, y01),
            _mm_clmulepi64_si128::<0x10>(x01, y01),
        );
        let mut z23 = _mm_xor_si128(
            _mm_clmulepi64_si128::<0x10>(x01, xy2),
            _mm_xor_si128(
                _mm_clmulepi64_si128::<0x11>(x01, y01),
                _mm_clmulepi64_si128::<0x00>(xy2, y01),
            ),
        );
        let z34 = _mm_xor_si128(
            _mm_clmulepi64_si128::<0x11>(x01, xy2),
            _mm_clmulepi64_si128::<0x10>(xy2, y01),
        );
        let mut z45 = _mm_clmulepi64_si128::<0x10>(xy2, xy2);

        z01 = _mm_xor_si128(z01, _mm_slli_si128::<8>(z12));
        z23 = _mm_xor_si128(z23, _mm_srli_si128::<8>(z12));
        z23 = _mm_xor_si128(z23, _mm_slli_si128::<8>(z34));
        z45 = _mm_xor_si128(z45, _mm_srli_si128::<8>(z34));

        let out = zz.as_mut_ptr().cast::<__m128i>();
        _mm_storeu_si128(out, z01);
        _mm_storeu_si128(out.add(1), z23);
        _mm_storeu_si128(out.add(2), z45);
    }
}

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

// BC's `SecT283Field.ImplMultiply` on its PCLMULQDQ path: the ten-limb product of five limbs
// by five, schoolbook in 25 CLMULs gathered by output lane. Constant time.
pub(super) fn impl_multiply(_proof: Pclmulqdq, x: &[u64; 5], y: &[u64; 5]) -> [u64; 10] {
    let mut zz = [0; 10];
    // SAFETY: the proof shows the CPU has PCLMULQDQ, and every such CPU has SSE2.
    unsafe { clmul(x, y, &mut zz) };
    zz
}

#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn xor3(a: __m128i, b: __m128i, c: __m128i) -> __m128i {
    unsafe { _mm_xor_si128(a, _mm_xor_si128(b, c)) }
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn clmul(x: &[u64; 5], y: &[u64; 5], zz: &mut [u64; 10]) {
    unsafe {
        let x01 = _mm_set_epi64x(x[1] as i64, x[0] as i64);
        let x23 = _mm_set_epi64x(x[3] as i64, x[2] as i64);
        let x4 = _mm_set_epi64x(0, x[4] as i64);
        let y01 = _mm_set_epi64x(y[1] as i64, y[0] as i64);
        let y23 = _mm_set_epi64x(y[3] as i64, y[2] as i64);
        let y4 = _mm_set_epi64x(0, y[4] as i64);

        let mut z01 = _mm_clmulepi64_si128::<0x00>(x01, y01);
        let z12 = _mm_xor_si128(
            _mm_clmulepi64_si128::<0x01>(x01, y01),
            _mm_clmulepi64_si128::<0x10>(x01, y01),
        );
        let mut z23 = xor3(
            _mm_clmulepi64_si128::<0x00>(x01, y23),
            _mm_clmulepi64_si128::<0x11>(x01, y01),
            _mm_clmulepi64_si128::<0x00>(x23, y01),
        );
        let z34 = _mm_xor_si128(
            xor3(
                _mm_clmulepi64_si128::<0x01>(x01, y23),
                _mm_clmulepi64_si128::<0x10>(x01, y23),
                _mm_clmulepi64_si128::<0x01>(x23, y01),
            ),
            _mm_clmulepi64_si128::<0x10>(x23, y01),
        );
        let mut z45 = _mm_xor_si128(
            xor3(
                _mm_clmulepi64_si128::<0x00>(x01, y4),
                _mm_clmulepi64_si128::<0x11>(x01, y23),
                _mm_clmulepi64_si128::<0x00>(x23, y23),
            ),
            _mm_xor_si128(
                _mm_clmulepi64_si128::<0x11>(x23, y01),
                _mm_clmulepi64_si128::<0x00>(x4, y01),
            ),
        );
        let z56 = _mm_xor_si128(
            xor3(
                _mm_clmulepi64_si128::<0x01>(x01, y4),
                _mm_clmulepi64_si128::<0x01>(x23, y23),
                _mm_clmulepi64_si128::<0x10>(x23, y23),
            ),
            _mm_clmulepi64_si128::<0x10>(x4, y01),
        );
        let mut z67 = xor3(
            _mm_clmulepi64_si128::<0x00>(x23, y4),
            _mm_clmulepi64_si128::<0x11>(x23, y23),
            _mm_clmulepi64_si128::<0x00>(x4, y23),
        );
        let z78 = _mm_xor_si128(
            _mm_clmulepi64_si128::<0x01>(x23, y4),
            _mm_clmulepi64_si128::<0x10>(x4, y23),
        );
        let mut z89 = _mm_clmulepi64_si128::<0x00>(x4, y4);

        z01 = _mm_xor_si128(z01, _mm_slli_si128::<8>(z12));
        z23 = _mm_xor_si128(z23, _mm_srli_si128::<8>(z12));
        z23 = _mm_xor_si128(z23, _mm_slli_si128::<8>(z34));
        z45 = _mm_xor_si128(z45, _mm_srli_si128::<8>(z34));
        z45 = _mm_xor_si128(z45, _mm_slli_si128::<8>(z56));
        z67 = _mm_xor_si128(z67, _mm_srli_si128::<8>(z56));
        z67 = _mm_xor_si128(z67, _mm_slli_si128::<8>(z78));
        z89 = _mm_xor_si128(z89, _mm_srli_si128::<8>(z78));

        let out = zz.as_mut_ptr().cast::<__m128i>();
        _mm_storeu_si128(out, z01);
        _mm_storeu_si128(out.add(1), z23);
        _mm_storeu_si128(out.add(2), z45);
        _mm_storeu_si128(out.add(3), z67);
        _mm_storeu_si128(out.add(4), z89);
    }
}

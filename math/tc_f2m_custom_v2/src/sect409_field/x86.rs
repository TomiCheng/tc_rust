// The intrinsics are unsafe before Rust 1.87 and safe inside these functions after it.
#![allow(unused_unsafe)]

#[cfg(target_arch = "x86")]
use core::arch::x86::{__m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128};
use tc_runtime::intrinsics::x86::Pclmulqdq;

// BC's `SecT409Field.ImplMulwAcc` on its PCLMULQDQ path: the 128-bit product of two words in
// one CLMUL. Constant time.
pub(super) fn mulw(_proof: Pclmulqdq, x: u64, y: u64) -> [u64; 2] {
    let mut z = [0; 2];
    // SAFETY: the proof shows the CPU has PCLMULQDQ, and every such CPU has SSE2.
    unsafe { clmul(x, y, &mut z) };
    z
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn clmul(x: u64, y: u64, z: &mut [u64; 2]) {
    unsafe {
        let product =
            _mm_clmulepi64_si128::<0x00>(_mm_set_epi64x(0, x as i64), _mm_set_epi64x(0, y as i64));
        _mm_storeu_si128(z.as_mut_ptr().cast::<__m128i>(), product);
    }
}

// The intrinsics are unsafe before Rust 1.87 and safe inside these functions after it.
#![allow(unused_unsafe)]

#[cfg(target_arch = "x86")]
use core::arch::x86::{
    __m128i, _mm_clmulepi64_si128, _mm_loadu_si128, _mm_set_epi64x, _mm_slli_si128, _mm_srli_si128,
    _mm_storeu_si128, _mm_unpackhi_epi64, _mm_unpacklo_epi64, _mm_xor_si128,
};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m128i, _mm_clmulepi64_si128, _mm_loadu_si128, _mm_set_epi64x, _mm_slli_si128, _mm_srli_si128,
    _mm_storeu_si128, _mm_unpackhi_epi64, _mm_unpacklo_epi64, _mm_xor_si128,
};
use tc_runtime::intrinsics::x86::Pclmulqdq;

/// BC's X86.V128 `ImplMulEven` / `ImplMulOdd`: `zz = x · y` unreduced, for `x` and `y` of
/// the same length and `zz` of twice it. Constant time: the work depends on the length
/// alone.
pub(crate) fn impl_mul(_proof: Pclmulqdq, x: &[u64], y: &[u64], zz: &mut [u64]) {
    let len = x.len();
    assert_eq!(y.len(), len, "invalid operand length");
    assert_eq!(zz.len(), len * 2, "invalid product length");
    // SAFETY: the proof shows the CPU has PCLMULQDQ, and every such CPU has SSE2.
    unsafe {
        if len == 1 {
            mul_one(x[0], y[0], zz);
        } else if len & 1 == 0 {
            mul_even(x, y, zz);
        } else {
            mul_odd(x, y, zz);
        }
    }
}

// BC's `Mul2x2`: two limbs by two in three CLMULs.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
pub(super) unsafe fn mul2x2(x: __m128i, y: __m128i) -> (__m128i, __m128i) {
    unsafe {
        let sums = _mm_xor_si128(_mm_unpacklo_epi64(x, y), _mm_unpackhi_epi64(x, y));
        let a = _mm_clmulepi64_si128::<0x00>(x, y);
        let b = _mm_clmulepi64_si128::<0x11>(x, y);
        let c = _mm_clmulepi64_si128::<0x01>(sums, sums);
        let mid = _mm_xor_si128(_mm_xor_si128(a, b), c);
        (
            _mm_xor_si128(a, _mm_slli_si128::<8>(mid)),
            _mm_xor_si128(b, _mm_srli_si128::<8>(mid)),
        )
    }
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul_one(x: u64, y: u64, zz: &mut [u64]) {
    unsafe {
        let product = _mm_clmulepi64_si128::<0x00>(lane_of(x), lane_of(y));
        store(zz, 0, product);
    }
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul_even(x: &[u64], y: &[u64], zz: &mut [u64]) {
    let len = x.len() / 2;
    unsafe {
        for i in 0..len {
            let (w0, w1) = mul2x2(load(x, i), load(y, i));
            store(zz, 2 * i, w0);
            store(zz, 2 * i + 1, w1);
        }

        let (mut v0, mut v1) = (load(zz, 0), load(zz, 1));
        for i in 1..len {
            v0 = _mm_xor_si128(v0, load(zz, 2 * i));
            store(zz, i, _mm_xor_si128(v0, v1));
            v1 = _mm_xor_si128(v1, load(zz, 2 * i + 1));
        }
        let w = _mm_xor_si128(v0, v1);
        for i in 0..len {
            store(zz, len + i, _mm_xor_si128(load(zz, i), w));
        }

        let last = len - 1;
        for z_pos in 1..2 * last {
            let mut hi = last.min(z_pos);
            let mut lo = z_pos - hi;
            while lo < hi {
                let (w0, w1) = mul2x2(
                    _mm_xor_si128(load(x, lo), load(x, hi)),
                    _mm_xor_si128(load(y, lo), load(y, hi)),
                );
                xor_into(zz, z_pos, w0);
                xor_into(zz, z_pos + 1, w1);
                lo += 1;
                hi -= 1;
            }
        }
    }
}

// The top limb is the low half of a virtual lane whose high half is zero; nothing touches
// the lane past the product that this would need.
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul_odd(x: &[u64], y: &[u64], zz: &mut [u64]) {
    let l = x.len() / 2;
    unsafe {
        let (x_tail, y_tail) = (lane_of(x[2 * l]), lane_of(y[2 * l]));
        for i in 0..l {
            let (w0, w1) = mul2x2(load(x, i), load(y, i));
            store(zz, 2 * i, w0);
            store(zz, 2 * i + 1, w1);
        }
        store(zz, 2 * l, _mm_clmulepi64_si128::<0x00>(x_tail, y_tail));

        let (mut v0, mut v1) = (load(zz, 0), load(zz, 1));
        for i in 1..l {
            v0 = _mm_xor_si128(v0, load(zz, 2 * i));
            store(zz, i, _mm_xor_si128(v0, v1));
            v1 = _mm_xor_si128(v1, load(zz, 2 * i + 1));
        }
        v0 = _mm_xor_si128(v0, load(zz, 2 * l));
        store(zz, l, _mm_xor_si128(v0, v1));
        let w = _mm_xor_si128(v0, v1);
        for i in 0..l {
            store(zz, l + 1 + i, _mm_xor_si128(load(zz, i), w));
        }

        for z_pos in 1..2 * l {
            let mut hi = l.min(z_pos);
            let mut lo = z_pos - hi;
            while lo < hi {
                let (x_hi, y_hi) = if hi < l {
                    (load(x, hi), load(y, hi))
                } else {
                    (x_tail, y_tail)
                };
                let (w0, w1) = mul2x2(
                    _mm_xor_si128(load(x, lo), x_hi),
                    _mm_xor_si128(load(y, lo), y_hi),
                );
                xor_into(zz, z_pos, w0);
                xor_into(zz, z_pos + 1, w1);
                lo += 1;
                hi -= 1;
            }
        }
    }
}

#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn lane_of(low: u64) -> __m128i {
    unsafe { _mm_set_epi64x(0, low as i64) }
}

#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
pub(super) unsafe fn load(words: &[u64], lane: usize) -> __m128i {
    let words = &words[2 * lane..2 * lane + 2];
    // SAFETY: the slice above holds the 16 bytes read, unaligned.
    unsafe { _mm_loadu_si128(words.as_ptr().cast()) }
}

#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
pub(super) unsafe fn store(words: &mut [u64], lane: usize, value: __m128i) {
    let words = &mut words[2 * lane..2 * lane + 2];
    // SAFETY: the slice above holds the 16 bytes written, unaligned.
    unsafe { _mm_storeu_si128(words.as_mut_ptr().cast(), value) }
}

#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn xor_into(words: &mut [u64], lane: usize, value: __m128i) {
    unsafe { store(words, lane, _mm_xor_si128(load(words, lane), value)) }
}

#[cfg(test)]
mod tests {
    use super::super::super::scalar::kernels::{schoolbook, words};
    use super::impl_mul;
    use tc_runtime::intrinsics::x86::Pclmulqdq;

    #[test]
    fn the_product_matches_a_bit_by_bit_schoolbook_for_every_length_up_to_forty() {
        let Some(proof) = Pclmulqdq::detect() else {
            return;
        };
        let mut state = 0xC1A5_5C1A_55C1_A55C;
        for len in 1..=40 {
            for _ in 0..8 {
                let x = words(len, &mut state);
                let y = words(len, &mut state);
                let mut zz = alloc::vec![0; 2 * len];
                impl_mul(proof, &x, &y, &mut zz);
                assert_eq!(zz, schoolbook(&x, &y), "len = {len}");
            }
        }
    }
}

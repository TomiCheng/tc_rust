//! PCLMULQDQ-backed carryless multiplication.

#[cfg(target_arch = "x86")]
use core::arch::x86::{__m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128};

use tc_runtime::intrinsics::x86::Pclmulqdq;

pub(crate) const KARATSUBA_CUTOFF: usize = 32;

/// Carryless schoolbook multiplication with a PCLMULQDQ leaf.
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
            unsafe { impl_mul_inner(x, y, zz) }
        }
    }
}

pub(crate) fn karatsuba_scratch_size(len: usize) -> usize {
    crate::scalar::karatsuba_scratch_size_with_cutoff(len, KARATSUBA_CUTOFF)
}

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
/// wrappers. The const width lets LLVM fully unroll the small loops.
#[inline]
fn impl_mul_size<const N: usize>(_proof: Pclmulqdq, x: &[u64], y: &[u64], zz: &mut [u64]) {
    let x: &[u64; N] = x.try_into().expect("size dispatch checked x");
    let y: &[u64; N] = y.try_into().expect("size dispatch checked y");
    let zz: &mut [u64] = zz;
    // SAFETY: the proof token was obtained from `Pclmulqdq::detect` and the
    // fixed-size conversions establish all slice bounds.
    unsafe { impl_mul_inner(x, y, zz) }
}

#[target_feature(enable = "pclmulqdq")]
unsafe fn impl_mul_inner(x: &[u64], y: &[u64], zz: &mut [u64]) {
    zz.fill(0);
    for (i, &x_i) in x.iter().enumerate() {
        for (j, &y_j) in y.iter().enumerate() {
            let a = _mm_set_epi64x(0, x_i as i64);
            let b = _mm_set_epi64x(0, y_j as i64);
            let product = _mm_clmulepi64_si128::<0x00>(a, b);
            let mut words = [0_u64; 2];
            // SAFETY: `words` has exactly 16 writable bytes.
            unsafe {
                _mm_storeu_si128(words.as_mut_ptr().cast::<__m128i>(), product);
            }
            zz[i + j] ^= words[0];
            zz[i + j + 1] ^= words[1];
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn pclmul_matches_scalar_when_available() {
        let Some(proof) = Pclmulqdq::detect() else {
            return;
        };
        for len in 1..=12 {
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
        let Some(proof) = Pclmulqdq::detect() else {
            return;
        };
        for len in [KARATSUBA_CUTOFF, KARATSUBA_CUTOFF + 1, 65] {
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

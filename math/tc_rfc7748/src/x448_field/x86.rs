//! Four independent 28-bit products per AVX2 instruction. Each coefficient
//! accumulates at most 16 products, strictly below 2^60, so u64 lanes suffice.
use super::Fe448;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use tc_runtime::intrinsics::x86::Avx2;

pub(super) fn multiply(a: Fe448, b: Fe448, _proof: Avx2) -> Fe448 {
    // SAFETY: proof verifies CPU and OS AVX2 support.
    let product = unsafe { convolution(a.0, b.0) };
    Fe448::reduce_wide(product.map(u128::from))
}

#[target_feature(enable = "avx2")]
unsafe fn convolution(a: [u32; 16], b: [u32; 16]) -> [u64; 32] {
    let mut product = [0_u64; 32];
    for (i, word) in a.iter().enumerate() {
        let left = _mm256_set1_epi64x(*word as i64);
        for j in [0, 4, 8, 12] {
            // SAFETY: the b load covers j..j+4 within 16 u32s. Product
            // load/store covers i+j..i+j+4 within 32 u64s. Unaligned allowed.
            unsafe {
                let right = _mm256_cvtepu32_epi64(_mm_loadu_si128(b.as_ptr().add(j).cast()));
                let previous = _mm256_loadu_si256(product.as_ptr().add(i + j).cast());
                let next = _mm256_add_epi64(previous, _mm256_mul_epu32(left, right));
                _mm256_storeu_si256(product.as_mut_ptr().add(i + j).cast(), next);
            }
        }
    }
    product
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn avx2_matches_scalar_at_boundaries_and_random_inputs() {
        let Some(proof) = Avx2::detect() else {
            return;
        };
        let mut state = 0x9183abfa7654_u64;
        for i in 0..100 {
            let mut a = [0_u8; 56];
            let mut b = [0_u8; 56];
            for byte in a.iter_mut().chain(b.iter_mut()) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            if i == 0 {
                a.fill(0);
                b.fill(255);
            }
            if i == 1 {
                a.fill(255);
                b.fill(255);
            }
            let a = Fe448::decode(&a);
            let b = Fe448::decode(&b);
            assert_eq!(multiply(a, b, proof), a.mul_scalar(b));
        }
    }
}

//! Unstable helpers used only by this crate's performance tuning benchmark.

use crate::reduce::{Reduce, Reducer};

/// Reducer comparison handle for the shared and specialized paths.
pub struct BenchReducer {
    n: usize,
    highest_tap: usize,
    taps: [usize; 4],
    tap_count: usize,
    specialized: Reducer,
}

impl BenchReducer {
    /// Creates a tuning handle for a trinomial.
    pub fn trinomial(n: usize, k: usize) -> Self {
        Self {
            n,
            highest_tap: k,
            taps: [0, k, 0, 0],
            tap_count: 2,
            specialized: Reducer::trinomial(n, k),
        }
    }

    /// Creates a tuning handle for a pentanomial.
    pub fn pentanomial(n: usize, k1: usize, k2: usize, k3: usize) -> Self {
        Self {
            n,
            highest_tap: k3,
            taps: [0, k1, k2, k3],
            tap_count: 4,
            specialized: Reducer::pentanomial(n, k1, k2, k3),
        }
    }

    /// Runs the former shared `reduce_words` production path.
    pub fn reduce_words(&self, tt: &mut [u64], z: &mut [u64]) {
        crate::reduce::reduce_words(
            self.n,
            self.highest_tap,
            &self.taps[..self.tap_count],
            tt,
            z,
        );
    }

    /// Runs the production enum's BC-family specialized path.
    pub fn reduce_bc_shape(&self, tt: &mut [u64], z: &mut [u64]) {
        self.specialized.reduce(tt, z);
    }
}

/// Scratch length for multiplication with a selected Karatsuba cutoff.
pub const fn karatsuba_scratch_size(len: usize, cutoff: usize) -> usize {
    crate::scalar::karatsuba_scratch_size_with_cutoff(len, cutoff)
}

/// Multiplies with the scalar backend and a selected Karatsuba cutoff.
pub fn scalar_multiply_with_cutoff(
    x: &[u64],
    y: &[u64],
    zz: &mut [u64],
    scratch: &mut [u64],
    cutoff: usize,
) {
    assert!(cutoff >= 2);
    if x.len() < cutoff {
        crate::scalar::impl_mul(x, y, zz);
        return;
    }
    crate::scalar::impl_karatsuba_with_leaf(x, y, zz, scratch, cutoff, crate::scalar::impl_mul);
}

/// Multiplies with the PCLMULQDQ backend and a selected Karatsuba cutoff.
/// Returns `false` when the CPU backend is unavailable.
#[cfg(all(feature = "x86", any(target_arch = "x86", target_arch = "x86_64")))]
pub fn x86_multiply_with_cutoff(
    x: &[u64],
    y: &[u64],
    zz: &mut [u64],
    scratch: &mut [u64],
    cutoff: usize,
) -> bool {
    use tc_runtime::intrinsics::x86::Pclmulqdq;

    let Some(proof) = Pclmulqdq::detect() else {
        return false;
    };
    assert!(cutoff >= 2);
    if x.len() < cutoff {
        crate::x86::impl_mul(proof, x, y, zz);
        return true;
    }
    crate::scalar::impl_karatsuba_with_leaf(x, y, zz, scratch, cutoff, |a, b, output| {
        crate::x86::impl_mul(proof, a, b, output)
    });
    true
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    fn inputs(len: usize) -> (Vec<u64>, Vec<u64>) {
        let x = (0..len)
            .map(|i| 0x9E37_79B9_7F4A_7C15_u64.wrapping_mul(i as u64 + 1))
            .collect();
        let y = (0..len)
            .map(|i| 0xD1B5_4A32_D192_ED03_u64.wrapping_mul(i as u64 + 3))
            .collect();
        (x, y)
    }

    #[test]
    fn production_reducers_match_shared_reduce_words() {
        let cases = [
            (113, BenchReducer::trinomial(113, 9)),
            (193, BenchReducer::trinomial(193, 15)),
            (233, BenchReducer::trinomial(233, 74)),
            (239, BenchReducer::trinomial(239, 158)),
            (409, BenchReducer::trinomial(409, 87)),
            (131, BenchReducer::pentanomial(131, 2, 3, 8)),
            (163, BenchReducer::pentanomial(163, 3, 6, 7)),
            (283, BenchReducer::pentanomial(283, 5, 7, 12)),
            (571, BenchReducer::pentanomial(571, 2, 5, 10)),
        ];
        for (n, reducer) in cases {
            let len = (n + 63) >> 6;
            let (mut x, mut y) = inputs(len);
            let mask = (1_u64 << (n & 63)) - 1;
            x[len - 1] &= mask;
            y[len - 1] &= mask;
            let mut product = vec![0_u64; len * 2];
            crate::scalar::impl_mul(&x, &y, &mut product);
            let mut shared_tt = product.clone();
            let mut specialized_tt = product;
            let mut shared = vec![0_u64; len];
            let mut specialized = vec![0_u64; len];
            reducer.reduce_words(&mut shared_tt, &mut shared);
            reducer.reduce_bc_shape(&mut specialized_tt, &mut specialized);
            assert_eq!(specialized, shared, "n={n}");
        }
    }

    #[test]
    fn tunable_scalar_cutoffs_match_medium() {
        for len in [6, 8, 9, 12, 16, 24, 32] {
            let (x, y) = inputs(len);
            let mut expected = vec![0_u64; len * 2];
            crate::scalar::impl_mul(&x, &y, &mut expected);
            for cutoff in [4, 6, 8, 10, 12, 16] {
                if cutoff > len {
                    continue;
                }
                let mut actual = vec![0_u64; len * 2];
                let mut scratch = vec![0_u64; karatsuba_scratch_size(len, cutoff)];
                scalar_multiply_with_cutoff(&x, &y, &mut actual, &mut scratch, cutoff);
                assert_eq!(actual, expected, "len={len}, cutoff={cutoff}");
            }
        }
    }
}

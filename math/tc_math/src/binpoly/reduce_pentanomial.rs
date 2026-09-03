//! Reduction modulo a pentanomial `xⁿ + xᵏ³ + xᵏ² + xᵏ¹ + 1`.
//!
//! Ported from Bouncy Castle `BinPolyMulBase.Pentanomial` — but only the general
//! bit-by-bit fold (its `C` reducer); the word-at-a-time fast paths are deferred
//! (see the TODO on [`create`]).

use alloc::boxed::Box;

use super::reduce::Reduce;

/// Builds a boxed [`Reduce`]r for `GF(2ⁿ)` under the pentanomial
/// `xⁿ + xᵏ³ + xᵏ² + xᵏ¹ + 1`. Mirrors bc's `PentanomialReduce.Create`.
// TODO(binpoly-reduce-fastpath): bc's Create picks a size/alignment-specialised
// reducer (A/B/D/E, per-size A3..A8) here; we always return the general fold [`C`].
pub fn create(n: usize, k1: usize, k2: usize, k3: usize) -> Box<dyn Reduce> {
    Box::new(C { n, k1, k2, k3 })
}

/// bc `PentanomialReduce.C`: the general bit-by-bit fold with four taps
/// `x^(pos+n) ≡ x^pos + x^(pos+k1) + x^(pos+k2) + x^(pos+k3)`. Correct for any
/// `0 < k1 < k2 < k3 < n`.
struct C {
    n: usize,
    k1: usize,
    k2: usize,
    k3: usize,
}

impl Reduce for C {
    fn reduce(&self, tt: &mut [u64], z: &mut [u64]) {
        let (n, k1, k2, k3) = (self.n, self.k1, self.k2, self.k3);
        debug_assert!(0 < k1 && k1 < k2 && k2 < k3 && k3 < n);
        debug_assert_eq!(tt.len(), 2 * z.len());

        let mut pos = n - 1;
        while pos > 0 {
            pos -= 1;
            let bit_n = (tt[(pos + n) / 64] >> ((pos + n) % 64)) & 1;
            tt[pos / 64] ^= bit_n << (pos % 64);
            tt[(pos + k1) / 64] ^= bit_n << ((pos + k1) % 64);
            tt[(pos + k2) / 64] ^= bit_n << ((pos + k2) % 64);
            tt[(pos + k3) / 64] ^= bit_n << ((pos + k3) % 64);
        }

        let w_top = n / 64;
        let s_top = n % 64;
        z[..w_top].copy_from_slice(&tt[..w_top]);
        if s_top != 0 {
            z[w_top] = tt[w_top] & !(u64::MAX << s_top);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pentanomial 版定義式 fixpoint 參考（4 taps）。
    fn reduce_pentanomial_ref(n: usize, k1: usize, k2: usize, k3: usize, tt: &[u64]) -> Vec<u64> {
        let size = n.div_ceil(64);
        let total_bits = tt.len() * 64;
        let mut bits = tt.to_vec();
        let test = |b: &[u64], p: usize| (b[p / 64] >> (p % 64)) & 1 == 1;
        let flip = |b: &mut [u64], p: usize| b[p / 64] ^= 1u64 << (p % 64);
        loop {
            let mut hb = None;
            for p in (0..total_bits).rev() {
                if test(&bits, p) {
                    hb = Some(p);
                    break;
                }
            }
            match hb {
                Some(p) if p >= n => {
                    flip(&mut bits, p);
                    flip(&mut bits, p - n);
                    flip(&mut bits, p - n + k1);
                    flip(&mut bits, p - n + k2);
                    flip(&mut bits, p - n + k3);
                }
                _ => break,
            }
        }
        let mut z = bits[..size].to_vec();
        let s = n % 64;
        if s != 0 {
            z[size - 1] &= !(u64::MAX << s);
        }
        z
    }

    /// 保留 `v` 的低 `nbits` 位元，其餘清零。
    fn mask_bits(v: &mut [u64], nbits: usize) {
        for (w, limb) in v.iter_mut().enumerate() {
            let lo = w * 64;
            if lo >= nbits {
                *limb = 0;
            } else if lo + 64 > nbits {
                *limb &= !(u64::MAX << (nbits - lo));
            }
        }
    }

    #[test]
    fn reduce_pentanomial_x5_case() {
        // r = x⁵+x³+x²+x+1；x⁵ ≡ x³+x²+x+1
        let mut tt = [0b10_0000u64, 0]; // bit 5
        let mut z = [0u64];
        C {
            n: 5,
            k1: 1,
            k2: 2,
            k3: 3,
        }
        .reduce(&mut tt, &mut z);
        assert_eq!(z, [0b1111]);
    }

    #[test]
    fn reduce_pentanomial_matches_reference_fuzz() {
        // 含真實 SECT 五項式（sect163k1/283/571）與字邊界、k 為 64 倍數等
        let cases = [
            (5usize, 1usize, 2usize, 3usize),
            (7, 1, 2, 3),
            (64, 1, 2, 3),
            (65, 1, 2, 3),
            (128, 1, 2, 64),
            (163, 3, 6, 7),
            (192, 1, 64, 128),
            (283, 5, 7, 12),
            (571, 2, 5, 10),
        ];
        let mut s = 0x2468_ACE0_1357_9BDFu64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for &(n, k1, k2, k3) in &cases {
            let size = n.div_ceil(64);
            for _ in 0..500 {
                let mut tt: Vec<u64> = (0..2 * size).map(|_| next()).collect();
                mask_bits(&mut tt, 2 * n - 1);
                let tt_ref = tt.clone();
                let mut z = vec![0u64; size];
                C { n, k1, k2, k3 }.reduce(&mut tt, &mut z);
                assert_eq!(
                    z,
                    reduce_pentanomial_ref(n, k1, k2, k3, &tt_ref),
                    "n={n} k={k1},{k2},{k3}"
                );
            }
        }
    }
}

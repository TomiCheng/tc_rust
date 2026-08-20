//! Reduction of a double-width product modulo the field polynomial `r(x)`.
//!
//! The multiply kernels ([`super::scalar::impl_mul`]) produce an unreduced
//! `2·size`-limb product; these routines fold it back to a `size`-limb field
//! element. Reduction is independent of the multiply backend.
//!
//! We port only Bouncy Castle's **general bit-by-bit fold** (its `D` reducer),
//! which is correct for any `(n, k…)`. bc additionally has word-at-a-time fast
//! paths selected by limb alignment — see the per-function TODOs.

/// Reduces the `2·size`-limb product `tt` modulo the trinomial `xⁿ + xᵏ + 1`,
/// writing the `size`-limb result into `z`. Correct for any `0 < k < n`.
///
/// `tt` is mutated in place during folding (it is scratch). Ported from Bouncy
/// Castle `TrinomialReduce.D` (bit-by-bit top-down fold).
///
/// The relation `x^(pos+n) ≡ x^pos + x^(pos+k)` (from `xⁿ ≡ xᵏ + 1`) is applied
/// top-down: each fold only creates bits at positions strictly below the one read,
/// so a single sweep suffices — later iterations re-fold anything a `+xᵏ` tap
/// pushed back above `n`.
///
// TODO(binpoly-reduce-fastpath): bc has word-at-a-time reducers (A/B/C/E and the
// per-size A3..A8 / C5..C8) chosen by n%64 and k alignment; here we use only the
// general bit-by-bit fold. Add the fast paths later if F2m becomes performance-critical.
pub(crate) fn reduce_trinomial(n: usize, k: usize, tt: &mut [u64], z: &mut [u64]) {
    debug_assert!(0 < k && k < n);
    debug_assert_eq!(tt.len(), 2 * z.len());

    let mut pos = n - 1;
    while pos > 0 {
        pos -= 1;
        // 讀高位 x^(pos+n)，摺到 x^pos 與 x^(pos+k)
        let bit_n = (tt[(pos + n) / 64] >> ((pos + n) % 64)) & 1;
        tt[pos / 64] ^= bit_n << (pos % 64);
        tt[(pos + k) / 64] ^= bit_n << ((pos + k) % 64);
    }

    // 低 n 位即結果；最高 limb 依 n%64 遮罩多餘高位
    let w_top = n / 64;
    let s_top = n % 64;
    z[..w_top].copy_from_slice(&tt[..w_top]);
    if s_top != 0 {
        z[w_top] = tt[w_top] & !(u64::MAX << s_top);
    }
}

/// Reduces the `2·size`-limb product `tt` modulo the pentanomial
/// `xⁿ + xᵏ³ + xᵏ² + xᵏ¹ + 1`, writing the `size`-limb result into `z`. Correct
/// for any `0 < k1 < k2 < k3 < n`.
///
/// `tt` is mutated in place during folding. Ported from Bouncy Castle
/// `PentanomialReduce.C` — the trinomial fold with four taps:
/// `x^(pos+n) ≡ x^pos + x^(pos+k1) + x^(pos+k2) + x^(pos+k3)`.
///
// TODO(binpoly-reduce-fastpath): bc has word-at-a-time reducers (A/B/D/E and the
// per-size A3..A8) chosen by n%64 and k alignment; here we use only the general
// bit-by-bit fold. Add the fast paths later if F2m becomes performance-critical.
pub(crate) fn reduce_pentanomial(n: usize, k1: usize, k2: usize, k3: usize, tt: &mut [u64], z: &mut [u64]) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 獨立參考：定義式 fixpoint —— 反覆取最高的 ≥n 設定位元，套 `x^p = x^(p-n) +
    /// x^(p-n+k)` 摺掉，直到無 ≥n 位元。與 D 的單趟掃法結構不同，作交叉驗證。
    fn reduce_trinomial_ref(n: usize, k: usize, tt: &[u64]) -> Vec<u64> {
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
                    flip(&mut bits, p); // 清掉 x^p
                    flip(&mut bits, p - n); // + x^(p-n)
                    flip(&mut bits, p - n + k); // + x^(p-n+k)
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

    /// 保留 `v` 的低 `nbits` 位元，其餘清零（模擬「degree < nbits 的積」）。
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
    fn reduce_trinomial_x3_plus_x_plus_1() {
        // r = x³+x+1；x³ ≡ x+1
        let mut tt = [0b1000u64, 0]; // bit 3
        let mut z = [0u64];
        reduce_trinomial(3, 1, &mut tt, &mut z);
        assert_eq!(z, [0b011]); // x+1
    }

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

    #[test]
    fn reduce_pentanomial_x5_case() {
        // r = x⁵+x³+x²+x+1；x⁵ ≡ x³+x²+x+1
        let mut tt = [0b10_0000u64, 0]; // bit 5
        let mut z = [0u64];
        reduce_pentanomial(5, 1, 2, 3, &mut tt, &mut z);
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
                reduce_pentanomial(n, k1, k2, k3, &mut tt, &mut z);
                assert_eq!(z, reduce_pentanomial_ref(n, k1, k2, k3, &tt_ref), "n={n} k={k1},{k2},{k3}");
            }
        }
    }

    #[test]
    fn reduce_trinomial_matches_reference_fuzz() {
        // 各種 (n,k)：跨字、字對齊、n-k 大小不一
        let cases = [
            (3usize, 1usize),
            (5, 2),
            (63, 1),
            (64, 1),
            (65, 1),
            (127, 63),
            (128, 1),
            (163, 7),
            (233, 74),
            (256, 129),
        ];
        let mut s = 0x1357_9BDF_2468_ACE0u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for &(n, k) in &cases {
            let size = n.div_ceil(64);
            for _ in 0..500 {
                let mut tt: Vec<u64> = (0..2 * size).map(|_| next()).collect();
                mask_bits(&mut tt, 2 * n - 1); // 積 degree ≤ 2n-2
                let tt_ref = tt.clone();
                let mut z = vec![0u64; size];
                reduce_trinomial(n, k, &mut tt, &mut z);
                assert_eq!(z, reduce_trinomial_ref(n, k, &tt_ref), "n={n} k={k}");
            }
        }
    }
}

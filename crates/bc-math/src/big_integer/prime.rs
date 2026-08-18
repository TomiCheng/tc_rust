//! Primality testing and random prime generation.
//!
//! Split into a submodule so the `rand` dependency stays isolated here and the
//! parent `big_integer.rs` remains pure arithmetic. As a descendant module this
//! can reach the parent's private items (`sign`, `magnitude`, `BigInteger::new`).

use super::BigInteger;
use rand_core::RngCore;

// no_std 下 `vec!` 巨集需從 alloc 引入；std 由 prelude 提供。
#[cfg(not(feature = "std"))]
use alloc::vec;

impl BigInteger {
    /// Miller-Rabin probabilistic primality test.
    ///
    /// Returns `true` if `self` is probably prime, `false` if definitely composite.
    /// A `true` result is wrong with probability at most `2^-certainty`; a larger
    /// `certainty` runs more rounds. The test uses `|self|` (sign is ignored).
    ///
    /// `rng` supplies the random witnesses — passed in (rather than sourced
    /// internally) to keep this usable under `no_std`.
    pub fn is_probable_prime(&self, _certainty: u32, _rng: &mut dyn RngCore) -> bool {
        // TODO(質數): 前置篩（n<2 邊界、偶數、小質數試除）後，跑隨機見證的
        //   Miller-Rabin 迴圈（約 certainty/2 輪），每輪委派 miller_rabin_round。
        todo!("is_probable_prime")
    }

    /// Returns the smallest probable prime strictly greater than `self`.
    pub fn next_probable_prime(&self, _rng: &mut dyn RngCore) -> BigInteger {
        // TODO(質數): 從 max(self+1, 2) 起，湊成奇數後逐次 +2，直到 is_probable_prime。
        todo!("next_probable_prime")
    }

    /// Generates a random probable prime with exactly `bit_length` bits.
    ///
    /// # Panics
    ///
    /// Panics if `bit_length < 2`.
    pub fn probable_prime(bit_length: u32, _rng: &mut dyn RngCore) -> BigInteger {
        if bit_length < 2 {
            panic!("bit_length must be at least 2");
        }
        // TODO(質數): 反覆 random_bits（最高位、最低位設 1 → 正確長度的奇數）
        //   + is_probable_prime，直到命中；對齊 bc-csharp with_random_certainty。
        todo!("probable_prime")
    }

    /// One Miller-Rabin round: tests `self` (an odd `n > 2`) against the single
    /// witness `base`. Returns `false` if `base` proves `self` composite, `true`
    /// otherwise (probably prime for this witness).
    #[allow(dead_code)] // TODO(質數): is_probable_prime 接上後移除此 allow
    fn miller_rabin_round(&self, base: &BigInteger) -> bool {
        let one = BigInteger::from_u32(1);
        let n_minus_1 = self - &one; // n-1（n 為奇 → n-1 為偶）

        // n-1 = d · 2^s，d 為奇：s = n-1 尾端零位數，d = (n-1) >> s
        let s = n_minus_1.get_lowest_set_bit().expect("n > 1 so n-1 > 0");
        let d = &n_minus_1 >> s;

        // x = base^d mod n
        let mut x = base.mod_pow(&d, self);
        if x == one || x == n_minus_1 {
            return true; // 這一輪過關
        }
        // 連續平方 s-1 次，看是否出現 n-1（1..s 恰好 s-1 次，且不會下溢）
        for _ in 1..s {
            x = &x.square() % self; // x = x² mod n
            if x == n_minus_1 {
                return true;
            }
        }
        false // base 是見證數 → n 確定為合數
    }

    /// A uniformly random non-negative integer in `[0, 2^bit_length)`
    /// (`bit_length == 0` yields zero). The excess high bits of the top byte
    /// are masked off, so the result has at most `bit_length` bits.
    ///
    /// The base primitive for choosing Miller-Rabin witnesses; prime generation
    /// composes this with forcing the top/bottom bits.
    #[allow(dead_code)] // TODO(質數): 見證挑選 / probable_prime 接上後移除此 allow
    fn random_bits(bit_length: u32, rng: &mut dyn RngCore) -> BigInteger {
        if bit_length == 0 {
            return BigInteger::from_u32(0);
        }
        let n_bytes = bit_length.div_ceil(8) as usize; // ⌈bit_length / 8⌉
        let mut bytes = vec![0u8; n_bytes];
        rng.fill_bytes(&mut bytes);
        // 遮掉最高位元組多出來的高位，使總位元數 ≤ bit_length
        let excess = 8 * n_bytes as u32 - bit_length; // 0..=7
        bytes[0] &= 0xFFu8 >> excess;
        BigInteger::from_bytes_be_unsigned(&bytes)
    }
}

/// 小質數試除表：3～1289 的質數，依「該組乘積 < 2³²」分組。
/// 試除時每組只做「一次大數 mod 乘積」得 u32，再對組內各質數做便宜的 u32 取餘，
/// 把昂貴的大數除法從「每質數一次」攤成「每組一次」。純字面值 → 可 `const`。
#[allow(dead_code)] // TODO(質數): is_probable_prime 的試除接上後移除此 allow
const PRIME_LISTS: &[&[u32]] = &[
    &[3, 5, 7, 11, 13, 17, 19, 23],
    &[29, 31, 37, 41, 43],
    &[47, 53, 59, 61, 67],
    &[71, 73, 79, 83],
    &[89, 97, 101, 103],
    &[107, 109, 113, 127],
    &[131, 137, 139, 149],
    &[151, 157, 163, 167],
    &[173, 179, 181, 191],
    &[193, 197, 199, 211],
    &[223, 227, 229],
    &[233, 239, 241],
    &[251, 257, 263],
    &[269, 271, 277],
    &[281, 283, 293],
    &[307, 311, 313],
    &[317, 331, 337],
    &[347, 349, 353],
    &[359, 367, 373],
    &[379, 383, 389],
    &[397, 401, 409],
    &[419, 421, 431],
    &[433, 439, 443],
    &[449, 457, 461],
    &[463, 467, 479],
    &[487, 491, 499],
    &[503, 509, 521],
    &[523, 541, 547],
    &[557, 563, 569],
    &[571, 577, 587],
    &[593, 599, 601],
    &[607, 613, 617],
    &[619, 631, 641],
    &[643, 647, 653],
    &[659, 661, 673],
    &[677, 683, 691],
    &[701, 709, 719],
    &[727, 733, 739],
    &[743, 751, 757],
    &[761, 769, 773],
    &[787, 797, 809],
    &[811, 821, 823],
    &[827, 829, 839],
    &[853, 857, 859],
    &[863, 877, 881],
    &[883, 887, 907],
    &[911, 919, 929],
    &[937, 941, 947],
    &[953, 967, 971],
    &[977, 983, 991],
    &[997, 1009, 1013],
    &[1019, 1021, 1031],
    &[1033, 1039, 1049],
    &[1051, 1061, 1063],
    &[1069, 1087, 1091],
    &[1093, 1097, 1103],
    &[1109, 1117, 1123],
    &[1129, 1151, 1153],
    &[1163, 1171, 1181],
    &[1187, 1193, 1201],
    &[1213, 1217, 1223],
    &[1229, 1231, 1237],
    &[1249, 1259, 1277],
    &[1279, 1283, 1289],
];

/// 各組質數的乘積（皆 < 2³²）。用 `const fn` 於編譯期由 [`PRIME_LISTS`] 算出，
/// 不手抄；乘積若溢位 u32，const 求值會直接編譯失敗（分組已保證不溢位）。
#[allow(dead_code)] // TODO(質數): is_probable_prime 的試除接上後移除此 allow
const PRIME_PRODUCTS: [u32; PRIME_LISTS.len()] = {
    let mut out = [0u32; PRIME_LISTS.len()];
    let mut i = 0;
    while i < PRIME_LISTS.len() {
        let group = PRIME_LISTS[i];
        let mut product = 1u32;
        let mut j = 0;
        while j < group.len() {
            product *= group[j];
            j += 1;
        }
        out[i] = product;
        i += 1;
    }
    out
};

#[cfg(test)]
mod tests {
    use super::BigInteger;
    use rand_core::RngCore;

    /// 測試用的確定性 RNG（LCG），讓隨機測試可重現，不必加相依。
    struct SeqRng(u64);
    impl RngCore for SeqRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0
        }
        fn fill_bytes(&mut self, dst: &mut [u8]) {
            for chunk in dst.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
        }
    }

    #[test]
    fn random_bits_in_range() {
        let mut rng = SeqRng(0x1234_5678_9ABC_DEF0);
        for bits in [0u32, 1, 7, 8, 9, 32, 33, 100, 256] {
            for _ in 0..50 {
                let x = BigInteger::random_bits(bits, &mut rng);
                assert!(x.sign() >= 0, "非負 bits={bits}");
                assert!(x.bit_length() <= bits, "應 < 2^{bits}，但 bit_length={}", x.bit_length());
            }
        }
        // bit_length == 0 → 0
        assert_eq!(BigInteger::random_bits(0, &mut rng), BigInteger::from_u32(0));
        // 有隨機性：兩次 128 位不應相同（極大機率）
        let a = BigInteger::random_bits(128, &mut rng);
        let b = BigInteger::random_bits(128, &mut rng);
        assert_ne!(a, b);
    }

    #[test]
    fn prime_module_reaches_private_fields() {
        // 冒煙測試：證明子模組能直接存取父模組的私有欄位（子孫可見）。
        let n = BigInteger::from_u32(0);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }

    #[test]
    fn prime_lists_are_valid() {
        // 抓手抄錯誤：每個數須為質數、整體嚴格遞增；乘積須 < 2³² 且與 const 值相符
        fn is_prime(n: u32) -> bool {
            if n < 2 {
                return false;
            }
            let mut d = 2u32;
            while d * d <= n {
                if n % d == 0 {
                    return false;
                }
                d += 1;
            }
            true
        }
        let mut prev = 0u32;
        for group in super::PRIME_LISTS {
            for &p in *group {
                assert!(is_prime(p), "{p} 不是質數");
                assert!(p > prev, "非嚴格遞增：{p} 在 {prev} 之後");
                prev = p;
            }
        }
        for (i, group) in super::PRIME_LISTS.iter().enumerate() {
            let prod: u64 = group.iter().map(|&p| p as u64).product();
            assert!(prod < (1u64 << 32), "第 {i} 組乘積溢位 u32");
            assert_eq!(super::PRIME_PRODUCTS[i] as u64, prod, "第 {i} 組乘積不符");
        }
    }
}

//! Primality testing and random prime generation.
//!
//! Split into a submodule so the `rand` dependency stays isolated here and the
//! parent `big_integer.rs` remains pure arithmetic. As a descendant module this
//! can reach the parent's private items (`sign`, `magnitude`, `BigInteger::new`).

use super::BigInteger;
use rand_core::Rng;

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
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
    /// # use rand_core::TryRng;
    /// # struct DemoRng(u64);
    /// # impl TryRng for DemoRng {
    /// #     type Error = core::convert::Infallible;
    /// #     fn try_next_u32(&mut self) -> Result<u32, Self::Error> { Ok(self.try_next_u64()? as u32) }
    /// #     fn try_next_u64(&mut self) -> Result<u64, Self::Error> { self.0 = self.0.wrapping_mul(0x5851_F42D_4C95_7F2D).wrapping_add(1); Ok(self.0) }
    /// #     fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> { for c in dst.chunks_mut(8) { c.copy_from_slice(&self.try_next_u64()?.to_le_bytes()[..c.len()]); } Ok(()) }
    /// # }
    /// # let mut rng = DemoRng(1);
    /// // `rng` is any `rand_core::Rng` (e.g. from the `rand` crate)
    /// assert!(BigInteger::from_u32(7919).is_probable_prime(40, &mut rng)); // 質數
    /// assert!(!BigInteger::from_u32(7917).is_probable_prime(40, &mut rng)); // 合數
    /// ```
    pub fn is_probable_prime(&self, certainty: u32, rng: &mut dyn Rng) -> bool {
        if certainty == 0 {
            return true; // certainty 0 → 不驗，一律當質數
        }
        let n = self.clone().abs(); // 忽略符號（abs 以值接收，先 clone）
        if !n.test_bit(0) {
            return n == BigInteger::from_u32(2); // 偶數 → 只有 2（0 也走這，0==2 為 false）
        }
        if n == BigInteger::from_u32(1) {
            return false;
        }
        if n == BigInteger::from_u32(3) {
            return true; // 最小奇質數；MR 對它無合法見證，特判掉
        }
        // n：奇數且 ≥ 5
        if n.has_small_factor() {
            return false; // 有真小因數 → 確定合數
        }
        // 無真小因數（小質數或大數）→ Miller-Rabin，⌈certainty/2⌉ 輪隨機見證
        n.miller_rabin_test(certainty.div_ceil(2), rng)
    }

    /// Trial division by the small primes in [`PRIME_LISTS`]. Returns `true` if a
    /// *proper* small factor is found (`self` is then composite); `false`
    /// otherwise (`self` is itself a small prime, or has no small factor).
    fn has_small_factor(&self) -> bool {
        let num_lists = (self.bit_length() as usize).saturating_sub(1).min(PRIME_LISTS.len());
        for i in 0..num_lists {
            let rem = self.remainder_u32(PRIME_PRODUCTS[i]); // 一次大數 mod 乘積
            for &prime in PRIME_LISTS[i] {
                if rem % prime == 0 {
                    return *self != BigInteger::from_u32(prime); // 整除且非自身 → 真因數
                }
            }
        }
        false
    }

    /// Returns the smallest probable prime strictly greater than `self`.
    pub fn next_probable_prime(&self, _rng: &mut dyn Rng) -> BigInteger {
        // TODO(質數): 從 max(self+1, 2) 起，湊成奇數後逐次 +2，直到 is_probable_prime。
        todo!("next_probable_prime")
    }

    /// Generates a random probable prime with exactly `bit_length` bits.
    ///
    /// # Panics
    ///
    /// Panics if `bit_length < 2`.
    pub fn probable_prime(bit_length: u32, _rng: &mut dyn Rng) -> BigInteger {
        if bit_length < 2 {
            panic!("bit_length must be at least 2");
        }
        // TODO(質數): 反覆 random_bits（最高位、最低位設 1 → 正確長度的奇數）
        //   + is_probable_prime，直到命中；對齊 bc-csharp with_random_certainty。
        todo!("probable_prime")
    }

    /// Miller-Rabin primality test over `rounds` random bases, working in the
    /// Montgomery domain. `self` = n must be **odd** and larger than the
    /// trial-division limit (so a valid witness range exists).
    ///
    /// Compares `a^r` against `R` ("1") and `n − R` ("-1") without converting
    /// out of Montgomery form each step. Returns `false` as soon as a base
    /// witnesses compositeness, otherwise `true` (probably prime).
    fn miller_rabin_test(&self, rounds: u32, rng: &mut dyn Rng) -> bool {
        let n = self;
        let one = BigInteger::from_u32(1);

        // n − 1 = r · 2^s，r 為奇
        let n_minus_1 = n - &one;
        let s = n_minus_1.get_lowest_set_bit().expect("n > 1 so n-1 > 0");
        let r = &n_minus_1 >> s;

        // Montgomery 域的「1」與「-1」：R mod n、n − (R mod n)（R = 2^(32·字數)）
        let mont_one = &(&one << (32 * n.magnitude.len() as u32)) % n;
        let mont_minus_one = n - &mont_one;

        for _ in 0..rounds {
            // 隨機見證 a：拒絕 0、≥n、以及會退化成基底 ±1 的 a（== R、== n−R）
            let a = loop {
                let a = BigInteger::random_bits(n.bit_length(), rng);
                if a.is_zero() || &a >= n || a == mont_one || a == mont_minus_one {
                    continue;
                }
                break a;
            };

            // y = a^r（convert=false，留在 Montgomery 域）→ 有效基底為 a·R⁻¹
            let mut y = BigInteger::mod_pow_monty(&a, &r, n, false);
            if y != mont_one {
                let mut j = 0;
                while y != mont_minus_one {
                    j += 1;
                    if j == s {
                        return false; // 平方 s 次仍沒 -1 → 合數
                    }
                    y = BigInteger::mod_square_monty(&y, n);
                    if y == mont_one {
                        return false; // 提早變 1（1 的非平凡平方根）→ 合數
                    }
                }
            }
        }
        true
    }

    /// A uniformly random non-negative integer in `[0, 2^bit_length)`
    /// (`bit_length == 0` yields zero). The excess high bits of the top byte
    /// are masked off, so the result has at most `bit_length` bits.
    ///
    /// The base primitive for choosing Miller-Rabin witnesses; prime generation
    /// composes this with forcing the top/bottom bits.
    fn random_bits(bit_length: u32, rng: &mut dyn Rng) -> BigInteger {
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
    use core::convert::Infallible;
    use rand_core::TryRng;

    /// 測試用的確定性 RNG（LCG），讓隨機測試可重現，不必加相依。
    /// rand_core 0.10：實作 `TryRng`（Error = Infallible），即自動獲得 `Rng`。
    struct SeqRng(u64);
    impl TryRng for SeqRng {
        type Error = Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            Ok(self.try_next_u64()? as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            Ok(self.0)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
            for chunk in dst.chunks_mut(8) {
                let v = self.try_next_u64()?.to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
            Ok(())
        }
    }

    #[test]
    fn is_probable_prime_known() {
        let mut rng = SeqRng(0x00DE_FACED_BAD_5EED);
        let cert = 40;
        // 質數 → true（含小質數、> 表上限的 1291、2¹²⁷−1）
        for p in [2u32, 3, 5, 7, 11, 13, 97, 1289, 1291, 7919, 104729] {
            assert!(BigInteger::from_u32(p).is_probable_prime(cert, &mut rng), "prime {p}");
        }
        assert!(
            BigInteger::from_str_radix("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
                .unwrap()
                .is_probable_prime(cert, &mut rng),
            "2^127-1"
        );
        // 合數 → false（含偶數、小合數、Carmichael、平方、2¹²⁸−1）
        for c in [0u32, 1, 4, 6, 9, 15, 25, 91, 561, 1105, 1729, 2821, 100000] {
            assert!(!BigInteger::from_u32(c).is_probable_prime(cert, &mut rng), "composite {c}");
        }
        assert!(
            !BigInteger::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
                .unwrap()
                .is_probable_prime(cert, &mut rng),
            "2^128-1"
        );
        // 負數走 abs：-97 視為 97 → true
        assert!(BigInteger::from_i32(-97).is_probable_prime(cert, &mut rng));
        // certainty == 0 → 一律 true（即使合數）
        assert!(BigInteger::from_u32(9).is_probable_prime(0, &mut rng));
    }

    #[test]
    fn miller_rabin_test_known() {
        let mut rng = SeqRng(0x00C0_FFEE_1234_5678);
        // 質數 → true（含 2¹²⁷−1 Mersenne 質數）
        let primes = [
            BigInteger::from_u32(97),
            BigInteger::from_u32(7919),
            BigInteger::from_u32(104729),
            BigInteger::from_str_radix("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16).unwrap(),
        ];
        for p in &primes {
            assert!(p.miller_rabin_test(20, &mut rng), "prime {p} 應通過");
        }
        // 合數 → false（含 Carmichael 561/1105/1729/2821/8911、2¹²⁸−1）
        let composites = [
            BigInteger::from_u32(9),
            BigInteger::from_u32(15),
            BigInteger::from_u32(25),
            BigInteger::from_u32(91),
            BigInteger::from_u32(561),
            BigInteger::from_u32(1105),
            BigInteger::from_u32(1729),
            BigInteger::from_u32(2821),
            BigInteger::from_u32(8911),
            BigInteger::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16).unwrap(),
        ];
        for c in &composites {
            assert!(!c.miller_rabin_test(20, &mut rng), "composite {c} 應判為合數");
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

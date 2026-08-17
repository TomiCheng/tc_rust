//! Primality testing and random prime generation.
//!
//! Split into a submodule so the `rand` dependency stays isolated here and the
//! parent `big_integer.rs` remains pure arithmetic. As a descendant module this
//! can reach the parent's private items (`sign`, `magnitude`, `BigInteger::new`).

use super::BigInteger;
use rand_core::RngCore;

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

    /// One Miller-Rabin round: tests `self` against the single witness `base`.
    /// Returns `false` if `base` proves `self` composite, `true` otherwise.
    #[allow(dead_code)] // TODO(質數): is_probable_prime 接上後移除此 allow
    fn miller_rabin_round(&self, _base: &BigInteger) -> bool {
        // TODO(質數): 把 n-1 寫成 d·2^s；算 base^d mod n；檢查是否等於 1，或在
        //   連續平方鏈中出現 n-1。重用既有的 mod_pow / square / rem。
        todo!("miller_rabin_round")
    }

    /// A uniformly random non-negative integer with exactly `bit_length` bits
    /// (the top bit is forced set, so the width is always exactly `bit_length`).
    #[allow(dead_code)] // TODO(質數): probable_prime / 見證挑選接上後移除此 allow
    fn random_bits(_bit_length: u32, _rng: &mut dyn RngCore) -> BigInteger {
        // TODO(質數): 取 ceil(bit_length/8) 個隨機位元組，遮罩多餘高位，組成 magnitude。
        todo!("random_bits")
    }
}

#[cfg(test)]
mod tests {
    use super::BigInteger;

    #[test]
    fn prime_module_reaches_private_fields() {
        // 冒煙測試：證明子模組能直接存取父模組的私有欄位（子孫可見）。
        let n = BigInteger::from_u32(0);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }
}

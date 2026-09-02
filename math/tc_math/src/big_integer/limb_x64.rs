use alloc::{vec, vec::Vec};

use super::{BigInteger, WORD_BITS};
pub(crate) type Limb = u64;
pub(crate) type DoubleLimb = u128;

impl BigInteger {
    /// Creates a `BigInteger` from an unsigned 64-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_u64(5);
    /// ```
    pub fn from_u64(value: u64) -> Self {
        if value == 0 {
            BigInteger::new(0, Vec::new())
        } else {
            BigInteger::new(1, vec![Limb::from(value)])
        }
    }
    /// Creates a `BigInteger` from an unsigned 128-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_u128(5);
    /// ```
    pub fn from_u128(value: u128) -> Self {
        if value == 0 {
            return BigInteger::new(0, Vec::new());
        }
        // Split into 2 big-endian words (most-significant first).
        let words = [
            (value >> WORD_BITS) as Limb,
            value as Limb,
        ];
        // Skip leading zero words. `value != 0` guarantees at least one non-zero.
        let start = words.iter().position(|&w| w != 0).unwrap();
        BigInteger::new(1, words[start..].to_vec())
    }
}

/// magnitude(u64 limb)→ u32 字:交叉,每個 u64 拆成(高 u32,低 u32),再去前導零。
pub(crate) fn mag_to_u32_be(mag: &[Limb]) -> Vec<u32> {
    let mut out = Vec::with_capacity(mag.len() * 2);
    for &w in mag {
        out.push((w >> 32) as u32);
        out.push(w as u32);
    }
    let start = out.iter().position(|&x| x != 0).unwrap_or(out.len());
    out[start..].to_vec()
}

/// u32 字 → magnitude(u64 limb):交叉,先去輸入前導零,再每兩個 u32(高、低)併成 u64。
pub(crate) fn mag_from_u32_be(words: &[u32]) -> Vec<Limb> {
    let start = words.iter().position(|&w| w != 0).unwrap_or(words.len());
    let words = &words[start..]; // 讓配對從真正最高位開始 → 輸出 canonical
    let n64 = words.len().div_ceil(2);
    let mut out = vec![0u64; n64];
    let mut i = words.len();
    for slot in (0..n64).rev() {
        let low = words[i - 1] as u64;
        let high = if i >= 2 { words[i - 2] as u64 } else { 0 };
        out[slot] = (high << 32) | low;
        i = i.saturating_sub(2);
    }
    out
}

/// magnitude(u64 limb)→ u64 字:原生,直接複製。
pub(crate) fn mag_to_u64_be(mag: &[Limb]) -> Vec<u64> {
    mag.to_vec()
}

/// u64 字 → magnitude(u64 limb):原生,去前導零字成 canonical。
// 目前未用：from_u64_* 經 split→words_u32；保留與 mag_from_u32_be 對稱、供日後原生路徑。
#[allow(dead_code)]
pub(crate) fn mag_from_u64_be(words: &[u64]) -> Vec<Limb> {
    let start = words.iter().position(|&w| w != 0).unwrap_or(words.len());
    words[start..].to_vec()
}
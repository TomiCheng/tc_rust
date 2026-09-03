//! Big-endian / little-endian **u64-word** (de)serialization for [`BigInteger`].
//!
//! The `u64` counterpart of [`super::words_u32`]: the same be/le × signed/unsigned ×
//! from/length/to/into family, but the unit is a 64-bit word. The internal magnitude
//! is a big-endian `u32` array, so the `from_*` constructors compose on the tested
//! `from_u32_*` (each `u64` split into two `u32` halves), while the `to_*` / `*_into`
//! writers pack magnitude `u32` pairs into `u64` words directly, keeping the `_into`
//! forms allocation-free.
//!
//! Word ordering mirrors [`super::words_u32`]: **big-endian** puts the
//! most-significant word first, **little-endian** puts it last. Signed forms treat
//! the whole word array as a base-2⁶⁴ two's-complement integer (sign = top bit of the
//! most-significant word).

use super::limb::mag_to_u64_be;
use super::{BigInteger, BufferTooSmall, WORD_BITS, bit_len};

// no_std 下沒有 std prelude，`vec!` 巨集與 `Vec` 型別需從 alloc 顯式引入。
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

impl BigInteger {
    /// Creates a `BigInteger` from a big-endian, two's-complement `u64` slice.
    ///
    /// The most-significant word comes first. A set top bit (bit 63) in that word
    /// means the value is negative (two's complement). An empty slice is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u64_be(&[0xFFFF_FFFF_FFFF_FFFF]), BigInteger::from_i32(-1));
    /// assert_eq!(BigInteger::from_u64_be(&[1, 0]), BigInteger::from_u128(1u128 << 64));
    /// ```
    pub fn from_u64_be(words: &[u64]) -> Self {
        BigInteger::from_u32_be(&split_be_u32(words))
    }

    /// Creates a non-negative `BigInteger` from a big-endian, **unsigned** `u64`
    /// slice: the top bit is data, never a sign. An empty (or all-zero) slice is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::BigInteger;
    ///
    /// // 有別於 from_u64_be：0x8000… 是 2^63，不是 -2^63
    /// assert_eq!(
    ///     BigInteger::from_u64_be_unsigned(&[0x8000_0000_0000_0000]),
    ///     BigInteger::from_u128(1u128 << 63)
    /// );
    /// ```
    pub fn from_u64_be_unsigned(words: &[u64]) -> Self {
        BigInteger::from_u32_be_unsigned(&split_be_u32(words))
    }

    /// Creates a `BigInteger` from a little-endian, two's-complement `u64` slice.
    ///
    /// The least-significant word comes first, so the sign lives in the top bit of
    /// the *last* word. An empty slice is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u64_le(&[0xFFFF_FFFF_FFFF_FFFF]), BigInteger::from_i32(-1));
    /// assert_eq!(BigInteger::from_u64_le(&[0, 1]), BigInteger::from_u128(1u128 << 64));
    /// ```
    pub fn from_u64_le(words: &[u64]) -> Self {
        BigInteger::from_u32_le(&split_le_u32(words))
    }

    /// Creates a non-negative `BigInteger` from a little-endian, **unsigned** `u64`
    /// slice: the top bit (of the last word) is data, never a sign. An empty (or
    /// all-zero) slice is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::BigInteger;
    ///
    /// assert_eq!(
    ///     BigInteger::from_u64_le_unsigned(&[0, 0x8000_0000_0000_0000]),
    ///     BigInteger::from_u128(1u128 << 127)
    /// );
    /// ```
    pub fn from_u64_le_unsigned(words: &[u64]) -> Self {
        BigInteger::from_u32_le_unsigned(&split_le_u32(words))
    }

    /// Returns the number of `u64` words in the minimal two's-complement (signed)
    /// representation — the length [`BigInteger::to_u64_be`] produces.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_i32(0).u64_length(), 1);
    /// assert_eq!(BigInteger::from_u128(1u128 << 63).u64_length(), 2); // 需符號字
    /// assert_eq!(BigInteger::from_i64(i64::MIN).u64_length(), 1);
    /// ```
    pub fn u64_length(&self) -> usize {
        // 同 u32_length，但字寬 64；bit_length() 已含符號處理，+1 容納符號位。
        self.bit_length() as usize / 64 + 1
    }

    /// Returns the number of `u64` words in the minimal unsigned (magnitude)
    /// representation — the length [`BigInteger::to_u64_be_unsigned`] produces.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u128(1u128 << 63).u64_length_unsigned(), 1);
    /// assert_eq!(BigInteger::from_u128(1u128 << 64).u64_length_unsigned(), 2);
    /// ```
    pub fn u64_length_unsigned(&self) -> usize {
        if self.sign == 0 {
            return 1; // 零輸出 [0]
        }
        // |self| 位元長度 → ⌈/64⌉ 個 u64 字（與 mag_to_u64_be 的輸出字數一致）
        let bits = WORD_BITS * (self.magnitude.len() - 1) + bit_len(self.magnitude[0]) as usize;
        bits.div_ceil(64)
    }

    /// 把 `n = out.len()` 個 u64 詞的 big-endian 編碼寫進 `out`（零配置核心）。
    ///
    /// 先把 `|self|` 轉成最小 u64 字、右對齊寫入、高位補 0；`signed` 且為負時再對整段
    /// 取兩補數。`out.len()` 須等於對應的 `u64_length*`。
    fn write_magnitude_be_u64(&self, out: &mut [u64], signed: bool) {
        // magnitude 是 Limb 字，先轉成最小 u64 字（無前導零）
        let words = mag_to_u64_be(&self.magnitude);
        let n = out.len();
        let mlen = words.len();
        for i in 0..n {
            // 第 i 個低位字：取自 words 的第 i 個低位字（不足則補 0）
            out[n - 1 - i] = if i < mlen { words[mlen - 1 - i] } else { 0 };
        }
        if signed && self.sign < 0 {
            twos_complement_in_place_u64(out); // 負數：整段兩補數
        }
    }

    /// Returns the magnitude (absolute value) as minimal big-endian `u64` words,
    /// **without** any sign. Zero is `[0]`; the top bit is data, not a sign.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u128(1u128 << 63).to_u64_be_unsigned(), vec![0x8000_0000_0000_0000]);
    /// ```
    pub fn to_u64_be_unsigned(&self) -> Vec<u64> {
        let mut v = vec![0u64; self.u64_length_unsigned()];
        self.write_magnitude_be_u64(&mut v, false);
        v
    }

    /// Little-endian counterpart of [`BigInteger::to_u64_be_unsigned`].
    pub fn to_u64_le_unsigned(&self) -> Vec<u64> {
        let mut v = self.to_u64_be_unsigned();
        v.reverse();
        v
    }

    /// Returns the minimal two's-complement big-endian `u64` words (with sign).
    ///
    /// Inverse of [`BigInteger::from_u64_be`]. Zero is `[0]`. A leading all-zero
    /// (non-negative) or all-ones (negative) word is included when needed so the
    /// sign bit reads correctly.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u128(1u128 << 63).to_u64_be(), vec![0x0000_0000_0000_0000, 0x8000_0000_0000_0000]);
    /// assert_eq!(BigInteger::from_i32(-1).to_u64_be(), vec![0xFFFF_FFFF_FFFF_FFFF]);
    /// ```
    pub fn to_u64_be(&self) -> Vec<u64> {
        let mut v = vec![0u64; self.u64_length()];
        self.write_magnitude_be_u64(&mut v, true);
        v
    }

    /// Little-endian counterpart of [`BigInteger::to_u64_be`].
    pub fn to_u64_le(&self) -> Vec<u64> {
        let mut v = self.to_u64_be();
        v.reverse();
        v
    }

    /// Writes the signed (two's-complement) big-endian encoding into the front of
    /// `dst`, returning the number of words written (= [`BigInteger::u64_length`]),
    /// or [`BufferTooSmall`] if `dst` is too short. Allocation-free.
    ///
    /// Note: `BufferTooSmall`'s `needed`/`available` here count **u64 words**.
    pub fn try_to_u64_be_into(&self, dst: &mut [u64]) -> Result<usize, BufferTooSmall> {
        let n = self.u64_length();
        if dst.len() < n {
            return Err(BufferTooSmall {
                needed: n,
                available: dst.len(),
            });
        }
        self.write_magnitude_be_u64(&mut dst[..n], true);
        Ok(n)
    }

    /// Little-endian counterpart of [`BigInteger::try_to_u64_be_into`].
    pub fn try_to_u64_le_into(&self, dst: &mut [u64]) -> Result<usize, BufferTooSmall> {
        let n = self.u64_length();
        if dst.len() < n {
            return Err(BufferTooSmall {
                needed: n,
                available: dst.len(),
            });
        }
        self.write_magnitude_be_u64(&mut dst[..n], true);
        dst[..n].reverse();
        Ok(n)
    }

    /// Unsigned (magnitude) big-endian counterpart of [`BigInteger::try_to_u64_be_into`].
    pub fn try_to_u64_be_unsigned_into(&self, dst: &mut [u64]) -> Result<usize, BufferTooSmall> {
        let n = self.u64_length_unsigned();
        if dst.len() < n {
            return Err(BufferTooSmall {
                needed: n,
                available: dst.len(),
            });
        }
        self.write_magnitude_be_u64(&mut dst[..n], false);
        Ok(n)
    }

    /// Little-endian counterpart of [`BigInteger::try_to_u64_be_unsigned_into`].
    pub fn try_to_u64_le_unsigned_into(&self, dst: &mut [u64]) -> Result<usize, BufferTooSmall> {
        let n = self.u64_length_unsigned();
        if dst.len() < n {
            return Err(BufferTooSmall {
                needed: n,
                available: dst.len(),
            });
        }
        self.write_magnitude_be_u64(&mut dst[..n], false);
        dst[..n].reverse();
        Ok(n)
    }

    /// Panicking version of [`BigInteger::try_to_u64_be_into`]; returns the number
    /// of words written. Allocation-free.
    ///
    /// # Panics
    ///
    /// Panics if `dst.len() < self.u64_length()`.
    pub fn to_u64_be_into(&self, dst: &mut [u64]) -> usize {
        self.try_to_u64_be_into(dst)
            .unwrap_or_else(|e| panic!("to_u64_be_into: {e}"))
    }

    /// Little-endian counterpart of [`BigInteger::to_u64_be_into`].
    ///
    /// # Panics
    ///
    /// Panics if `dst.len() < self.u64_length()`.
    pub fn to_u64_le_into(&self, dst: &mut [u64]) -> usize {
        self.try_to_u64_le_into(dst)
            .unwrap_or_else(|e| panic!("to_u64_le_into: {e}"))
    }

    /// Panicking version of [`BigInteger::try_to_u64_be_unsigned_into`].
    ///
    /// # Panics
    ///
    /// Panics if `dst.len() < self.u64_length_unsigned()`.
    pub fn to_u64_be_unsigned_into(&self, dst: &mut [u64]) -> usize {
        self.try_to_u64_be_unsigned_into(dst)
            .unwrap_or_else(|e| panic!("to_u64_be_unsigned_into: {e}"))
    }

    /// Little-endian counterpart of [`BigInteger::to_u64_be_unsigned_into`].
    ///
    /// # Panics
    ///
    /// Panics if `dst.len() < self.u64_length_unsigned()`.
    pub fn to_u64_le_unsigned_into(&self, dst: &mut [u64]) -> usize {
        self.try_to_u64_le_unsigned_into(dst)
            .unwrap_or_else(|e| panic!("to_u64_le_unsigned_into: {e}"))
    }
}

/// 對 u64 陣列原地取兩補數：`words = ~words + 1`（進位由低位端往高位傳）。
fn twos_complement_in_place_u64(words: &mut [u64]) {
    let mut carry = true;
    for w in words.iter_mut().rev() {
        *w = !*w;
        if carry {
            let (v, c) = w.overflowing_add(1);
            *w = v;
            carry = c;
        }
    }
}

/// big-endian u64 詞 → big-endian u32 詞：每個 u64 拆成 [高 u32, 低 u32]。
fn split_be_u32(words: &[u64]) -> Vec<u32> {
    let mut out = Vec::with_capacity(words.len() * 2);
    for &w in words {
        out.push((w >> 32) as u32); // 高位在前（BE）
        out.push(w as u32);
    }
    out
}

/// little-endian u64 詞 → little-endian u32 詞：每個 u64 拆成 [低 u32, 高 u32]。
fn split_le_u32(words: &[u64]) -> Vec<u32> {
    let mut out = Vec::with_capacity(words.len() * 2);
    for &w in words {
        out.push(w as u32); // 低位在前（LE）
        out.push((w >> 32) as u32);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- from_u64_be / _unsigned ---

    #[test]
    fn from_u64_be_empty_is_zero() {
        assert_eq!(BigInteger::from_u64_be(&[]), BigInteger::from_i32(0));
    }

    #[test]
    fn from_u64_be_all_zero_is_zero() {
        assert_eq!(BigInteger::from_u64_be(&[0, 0, 0]), BigInteger::from_i32(0));
    }

    #[test]
    fn from_u64_be_positive_multiword() {
        assert_eq!(
            BigInteger::from_u64_be(&[1, 0]),
            BigInteger::from_u128(1u128 << 64)
        );
    }

    #[test]
    fn from_u64_be_strips_leading_zero_words() {
        assert_eq!(BigInteger::from_u64_be(&[0, 0, 5]), BigInteger::from_u32(5));
    }

    #[test]
    fn from_u64_be_leading_zero_word_forces_positive() {
        // 最高字為 0 → 非負，即使下個字最高位為 1
        assert_eq!(
            BigInteger::from_u64_be(&[0, 0x8000_0000_0000_0000]),
            BigInteger::from_u128(1u128 << 63)
        );
    }

    #[test]
    fn from_u64_be_minus_one() {
        assert_eq!(
            BigInteger::from_u64_be(&[0xFFFF_FFFF_FFFF_FFFF]),
            BigInteger::from_i32(-1)
        );
    }

    #[test]
    fn from_u64_be_min_i64_word() {
        // 0x8000… 最高位為 1 → 負數 = -2^63
        assert_eq!(
            BigInteger::from_u64_be(&[0x8000_0000_0000_0000]),
            BigInteger::from_i64(i64::MIN)
        );
    }

    #[test]
    fn from_u64_be_unsigned_top_bit_is_data() {
        assert_eq!(
            BigInteger::from_u64_be_unsigned(&[0x8000_0000_0000_0000]),
            BigInteger::from_u128(1u128 << 63)
        );
    }

    // --- from_u64_le ---

    #[test]
    fn from_u64_le_matches_be_reversed() {
        let be = [
            0x0000_0000_0000_0001u64,
            0x2345_6789_ABCD_EF01,
            0xFEDC_BA98_7654_3210,
        ];
        let mut le = be;
        le.reverse();
        assert_eq!(BigInteger::from_u64_le(&le), BigInteger::from_u64_be(&be));
    }

    #[test]
    fn from_u64_le_minus_one() {
        assert_eq!(
            BigInteger::from_u64_le(&[0xFFFF_FFFF_FFFF_FFFF]),
            BigInteger::from_i32(-1)
        );
    }

    // --- to_u64_be / _unsigned ---

    #[test]
    fn to_u64_be_signed_needs_sign_word() {
        // 2^63 最高字最高位為 1 → 需前導 0 字保持正號
        assert_eq!(
            BigInteger::from_u128(1u128 << 63).to_u64_be(),
            vec![0x0000_0000_0000_0000, 0x8000_0000_0000_0000]
        );
    }

    #[test]
    fn to_u64_be_unsigned_no_sign_word() {
        assert_eq!(
            BigInteger::from_u128(1u128 << 63).to_u64_be_unsigned(),
            vec![0x8000_0000_0000_0000]
        );
    }

    #[test]
    fn to_u64_be_minus_one() {
        assert_eq!(
            BigInteger::from_i32(-1).to_u64_be(),
            vec![0xFFFF_FFFF_FFFF_FFFF]
        );
    }

    #[test]
    fn to_u64_be_zero() {
        assert_eq!(BigInteger::from_i32(0).to_u64_be(), vec![0]);
        assert_eq!(BigInteger::from_i32(0).to_u64_be_unsigned(), vec![0]);
    }

    #[test]
    fn to_u64_le_matches_be_reversed() {
        let n = BigInteger::from_u128((1u128 << 127) + 7);
        let mut be = n.to_u64_be();
        be.reverse();
        assert_eq!(n.to_u64_le(), be);
    }

    // --- roundtrips ---

    #[test]
    fn to_from_u64_be_roundtrip_signed() {
        for v in [0i64, 1, -1, 5, -5, i64::MIN, i64::MAX, 1 << 40, -(1 << 40)] {
            let n = BigInteger::from_i64(v);
            assert_eq!(BigInteger::from_u64_be(&n.to_u64_be()), n, "v = {v}");
            assert_eq!(BigInteger::from_u64_le(&n.to_u64_le()), n, "v = {v}");
        }
    }

    #[test]
    fn to_from_u64_be_roundtrip_unsigned() {
        for v in [0u128, 1, 5, 1 << 63, 1 << 64, 1 << 100, u128::MAX] {
            let n = BigInteger::from_u128(v);
            assert_eq!(
                BigInteger::from_u64_be_unsigned(&n.to_u64_be_unsigned()),
                n,
                "v = {v}"
            );
            assert_eq!(
                BigInteger::from_u64_le_unsigned(&n.to_u64_le_unsigned()),
                n,
                "v = {v}"
            );
        }
    }

    // --- *_into ---

    #[test]
    fn try_to_u64_into_ok_and_err() {
        let n = BigInteger::from_u128(1u128 << 64); // u64_length = 2
        let mut buf = [0u64; 4];
        assert_eq!(n.try_to_u64_be_into(&mut buf), Ok(2));
        assert_eq!(&buf[..2], &[0x0000_0000_0000_0001, 0x0000_0000_0000_0000]);

        let mut tiny = [0u64; 1];
        let err = n.try_to_u64_be_into(&mut tiny).unwrap_err();
        assert_eq!(err.needed, 2);
        assert_eq!(err.available, 1);
    }

    #[test]
    fn to_u64_into_matches_allocating() {
        let n = BigInteger::from_i64(-(1 << 40));
        let mut buf = [0u64; 8];
        let len = n.to_u64_be_into(&mut buf);
        assert_eq!(&buf[..len], n.to_u64_be().as_slice());
    }

    #[test]
    #[should_panic(expected = "to_u64_be_into")]
    fn to_u64_be_into_panics_when_too_small() {
        let n = BigInteger::from_u128(1u128 << 64); // 需要 2 字
        let mut buf = [0u64; 1];
        n.to_u64_be_into(&mut buf);
    }

    // --- length accessors ---

    #[test]
    fn u64_length_matches_output() {
        for v in [0i64, 1, -1, i64::MIN, 1 << 40, -(1 << 40)] {
            let n = BigInteger::from_i64(v);
            assert_eq!(n.u64_length(), n.to_u64_be().len(), "signed v = {v}");
            assert_eq!(
                n.u64_length_unsigned(),
                n.to_u64_be_unsigned().len(),
                "unsigned v = {v}"
            );
        }
        for v in [1u128 << 63, 1 << 64, u128::MAX] {
            let n = BigInteger::from_u128(v);
            assert_eq!(n.u64_length(), n.to_u64_be().len(), "signed v = {v}");
            assert_eq!(
                n.u64_length_unsigned(),
                n.to_u64_be_unsigned().len(),
                "unsigned v = {v}"
            );
        }
    }
}

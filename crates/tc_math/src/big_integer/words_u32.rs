//! Big-endian / little-endian **u32-word** (de)serialization for [`BigInteger`].
//!
//! The `u32` counterpart of [`super::bytes`]: the same be/le × signed/unsigned ×
//! from/to/into family, but the unit is a 32-bit word instead of a byte. Because
//! the internal magnitude is already a big-endian `u32` array, these are lighter
//! than the byte versions — words are copied, never bit-shuffled.
//!
//! Word ordering mirrors the byte ordering: **big-endian** puts the
//! most-significant word first (`words[0]`), **little-endian** puts it last. Each
//! word is a native `u32`; endianness here is the order of *words*, not of the
//! bytes inside a word. Signed forms read/write the whole word array as a base-2³²
//! two's-complement integer (sign = top bit of the most-significant word).

use super::{bit_len, BigInteger, BufferTooSmall, WORD_BITS};

// no_std 下沒有 std prelude，`vec!` 巨集與 `Vec` 型別需從 alloc 顯式引入；
// std build 由 prelude 提供，故僅在關閉 std 時引入，避免重複 import 警告。
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use crate::big_integer::limb::{mag_from_u32_be, Limb, mag_to_u32_be};

impl BigInteger {
    /// Creates a `BigInteger` from a big-endian, two's-complement `u32` slice.
    ///
    /// The most-significant word comes first. A set top bit (bit 31) in that word
    /// means the value is negative (two's complement). An empty slice is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u32_be(&[0xFFFF_FFFF]), BigInteger::from_i32(-1));
    /// assert_eq!(BigInteger::from_u32_be(&[1, 0]), BigInteger::from_u64(1 << 32));
    /// ```
    pub fn from_u32_be(words: &[u32]) -> Self {
        if words.is_empty() {
            return BigInteger::new(0, Vec::new());
        }
        if words[0] & 0x8000_0000 != 0 {
            // 最高字的最高位為 1：兩補數負數
            BigInteger::new(-1, make_magnitude_be_u32_negative(words))
        } else {
            // 非負：magnitude 為空時代表 0
            let magnitude = make_magnitude_be_u32(words);
            let sign = if magnitude.is_empty() { 0 } else { 1 };
            BigInteger::new(sign, magnitude)
        }
    }

    /// Creates a non-negative `BigInteger` from a big-endian, **unsigned** `u32`
    /// slice: the top bit is data, never a sign. An empty (or all-zero) slice is
    /// zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// // 有別於 from_u32_be：0x8000_0000 是 2^31，不是 -2^31
    /// assert_eq!(BigInteger::from_u32_be_unsigned(&[0x8000_0000]), BigInteger::from_u64(1 << 31));
    /// ```
    pub fn from_u32_be_unsigned(words: &[u32]) -> Self {
        // 一律非負：最高位是資料，不是符號
        let magnitude = make_magnitude_be_u32(words);
        let sign = if magnitude.is_empty() { 0 } else { 1 };
        BigInteger::new(sign, magnitude)
    }

    /// Creates a `BigInteger` from a little-endian, two's-complement `u32` slice.
    ///
    /// The least-significant word comes first, so the sign lives in the top bit of
    /// the *last* word. An empty slice is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u32_le(&[0xFFFF_FFFF]), BigInteger::from_i32(-1));
    /// assert_eq!(BigInteger::from_u32_le(&[0, 1]), BigInteger::from_u64(1 << 32));
    /// ```
    pub fn from_u32_le(words: &[u32]) -> Self {
        if words.is_empty() {
            return BigInteger::new(0, Vec::new());
        }
        // little-endian：最高位字在尾端，符號位取最後一個字
        if words[words.len() - 1] & 0x8000_0000 != 0 {
            BigInteger::new(-1, make_magnitude_le_u32_negative(words))
        } else {
            let magnitude = make_magnitude_le_u32(words);
            let sign = if magnitude.is_empty() { 0 } else { 1 };
            BigInteger::new(sign, magnitude)
        }
    }

    /// Creates a non-negative `BigInteger` from a little-endian, **unsigned** `u32`
    /// slice: the top bit (of the last word) is data, never a sign. An empty (or
    /// all-zero) slice is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u32_le_unsigned(&[0, 0x8000_0000]), BigInteger::from_u64(1 << 63));
    /// ```
    pub fn from_u32_le_unsigned(words: &[u32]) -> Self {
        let magnitude = make_magnitude_le_u32(words);
        let sign = if magnitude.is_empty() { 0 } else { 1 };
        BigInteger::new(sign, magnitude)
    }

    /// Returns the number of `u32` words in the minimal two's-complement (signed)
    /// representation — the length [`BigInteger::to_u32_be`] produces.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_i32(0).u32_length(), 1);
    /// assert_eq!(BigInteger::from_u64(1 << 31).u32_length(), 2); // 需符號字 → [0000_0000, 8000_0000]
    /// assert_eq!(BigInteger::from_i32(i32::MIN).u32_length(), 1); // [8000_0000]
    /// ```
    pub fn u32_length(&self) -> usize {
        // bit_length() 已含符號與負 2 次方的處理；+1 容納符號位。零 → 0/32+1 = 1
        self.bit_length() as usize / 32 + 1
    }

    /// Returns the number of `u32` words in the minimal unsigned (magnitude)
    /// representation — the length [`BigInteger::to_u32_be_unsigned`] produces.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u64(1 << 31).u32_length_unsigned(), 1); // [8000_0000]
    /// assert_eq!(BigInteger::from_u64(1 << 32).u32_length_unsigned(), 2); // [0000_0001, 0000_0000]
    /// ```
    pub fn u32_length_unsigned(&self) -> usize {
        if self.sign == 0 {
            return 1; // 零輸出 [0]
        }
        // |self| 位元長度 → ⌈/32⌉ 個 u32 字（與 mag_to_u32_be 的輸出字數一致）
        let bits = WORD_BITS * (self.magnitude.len() - 1) + bit_len(self.magnitude[0]) as usize;
        bits.div_ceil(32)
    }

    /// 把 `n = out.len()` 個 u32 詞的 big-endian 編碼寫進 `out`（零配置核心）。
    ///
    /// 先把 `|self|` 的字右對齊寫入、左邊補 0（超出 magnitude 的高位、以及零，自然補 0）；
    /// `signed` 且為負時再對整段取兩補數。`out.len()` 須等於對應的 `u32_length*`。
    fn write_magnitude_be_u32(&self, out: &mut [u32], signed: bool) {
        // magnitude 是 Limb 字，先轉成最小 u32 字（無前導零）
        let words = mag_to_u32_be(&self.magnitude);
        let n = out.len();
        let len = words.len();
        for i in 0..n {
            // 第 i 個低位字：取自 words 的第 i 個低位字（不足則補 0）
            out[n - 1 - i] = if i < len { words[len - 1 - i] } else { 0 };
        }
        if signed && self.sign < 0 {
            twos_complement_in_place_u32(out); // 負數：整段兩補數
        }
    }

    /// Returns the magnitude (absolute value) as minimal big-endian `u32` words,
    /// **without** any sign. Zero is `[0]`; the top bit is data, not a sign.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u64(1 << 31).to_u32_be_unsigned(), vec![0x8000_0000]);
    /// assert_eq!(BigInteger::from_i32(i32::MIN).to_u32_be_unsigned(), vec![0x8000_0000]); // 只看絕對值
    /// ```
    pub fn to_u32_be_unsigned(&self) -> Vec<u32> {
        let mut v = vec![0u32; self.u32_length_unsigned()];
        self.write_magnitude_be_u32(&mut v, false);
        v
    }

    /// Little-endian counterpart of [`BigInteger::to_u32_be_unsigned`].
    pub fn to_u32_le_unsigned(&self) -> Vec<u32> {
        let mut v = self.to_u32_be_unsigned();
        v.reverse(); // BE 最高字在前，反轉即 LE
        v
    }

    /// Returns the minimal two's-complement big-endian `u32` words (with sign).
    ///
    /// Inverse of [`BigInteger::from_u32_be`]. Zero is `[0]`. A leading all-zero
    /// (non-negative) or all-ones (negative) word is included when needed so the
    /// sign bit reads correctly.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u64(1 << 31).to_u32_be(), vec![0x0000_0000, 0x8000_0000]);
    /// assert_eq!(BigInteger::from_i32(-1).to_u32_be(), vec![0xFFFF_FFFF]);
    /// ```
    pub fn to_u32_be(&self) -> Vec<u32> {
        let mut v = vec![0u32; self.u32_length()];
        self.write_magnitude_be_u32(&mut v, true);
        v
    }

    /// Little-endian counterpart of [`BigInteger::to_u32_be`].
    pub fn to_u32_le(&self) -> Vec<u32> {
        let mut v = self.to_u32_be();
        v.reverse();
        v
    }

    /// Writes the signed (two's-complement) big-endian encoding into the front of
    /// `dst`, returning the number of words written (= [`BigInteger::u32_length`]),
    /// or [`BufferTooSmall`] if `dst` is too short. Allocation-free.
    ///
    /// Note: `BufferTooSmall`'s `needed`/`available` here count **u32 words**.
    pub fn try_to_u32_be_into(&self, dst: &mut [u32]) -> Result<usize, BufferTooSmall> {
        let n = self.u32_length();
        if dst.len() < n {
            return Err(BufferTooSmall { needed: n, available: dst.len() });
        }
        self.write_magnitude_be_u32(&mut dst[..n], true);
        Ok(n)
    }

    /// Little-endian counterpart of [`BigInteger::try_to_u32_be_into`].
    pub fn try_to_u32_le_into(&self, dst: &mut [u32]) -> Result<usize, BufferTooSmall> {
        let n = self.u32_length();
        if dst.len() < n {
            return Err(BufferTooSmall { needed: n, available: dst.len() });
        }
        self.write_magnitude_be_u32(&mut dst[..n], true);
        dst[..n].reverse();
        Ok(n)
    }

    /// Unsigned (magnitude) big-endian counterpart of [`BigInteger::try_to_u32_be_into`].
    pub fn try_to_u32_be_unsigned_into(&self, dst: &mut [u32]) -> Result<usize, BufferTooSmall> {
        let n = self.u32_length_unsigned();
        if dst.len() < n {
            return Err(BufferTooSmall { needed: n, available: dst.len() });
        }
        self.write_magnitude_be_u32(&mut dst[..n], false);
        Ok(n)
    }

    /// Little-endian counterpart of [`BigInteger::try_to_u32_be_unsigned_into`].
    pub fn try_to_u32_le_unsigned_into(&self, dst: &mut [u32]) -> Result<usize, BufferTooSmall> {
        let n = self.u32_length_unsigned();
        if dst.len() < n {
            return Err(BufferTooSmall { needed: n, available: dst.len() });
        }
        self.write_magnitude_be_u32(&mut dst[..n], false);
        dst[..n].reverse();
        Ok(n)
    }

    /// Panicking version of [`BigInteger::try_to_u32_be_into`]; returns the number
    /// of words written. Allocation-free.
    ///
    /// # Panics
    ///
    /// Panics if `dst.len() < self.u32_length()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_u64(1 << 31);
    /// let mut buf = [0u32; 4];
    /// let len = n.to_u32_be_into(&mut buf);
    /// assert_eq!(&buf[..len], &[0x0000_0000, 0x8000_0000]);
    /// ```
    pub fn to_u32_be_into(&self, dst: &mut [u32]) -> usize {
        self.try_to_u32_be_into(dst).unwrap_or_else(|e| panic!("to_u32_be_into: {e}"))
    }

    /// Little-endian counterpart of [`BigInteger::to_u32_be_into`].
    ///
    /// # Panics
    ///
    /// Panics if `dst.len() < self.u32_length()`.
    pub fn to_u32_le_into(&self, dst: &mut [u32]) -> usize {
        self.try_to_u32_le_into(dst).unwrap_or_else(|e| panic!("to_u32_le_into: {e}"))
    }

    /// Panicking version of [`BigInteger::try_to_u32_be_unsigned_into`].
    ///
    /// # Panics
    ///
    /// Panics if `dst.len() < self.u32_length_unsigned()`.
    pub fn to_u32_be_unsigned_into(&self, dst: &mut [u32]) -> usize {
        self.try_to_u32_be_unsigned_into(dst).unwrap_or_else(|e| panic!("to_u32_be_unsigned_into: {e}"))
    }

    /// Little-endian counterpart of [`BigInteger::to_u32_be_unsigned_into`].
    ///
    /// # Panics
    ///
    /// Panics if `dst.len() < self.u32_length_unsigned()`.
    pub fn to_u32_le_unsigned_into(&self, dst: &mut [u32]) -> usize {
        self.try_to_u32_le_unsigned_into(dst).unwrap_or_else(|e| panic!("to_u32_le_unsigned_into: {e}"))
    }
}

/// 對 u32 陣列原地取兩補數：`words = ~words + 1`（同寬度，進位由低位端往高位傳）。
fn twos_complement_in_place_u32(words: &mut [u32]) {
    let mut carry = true; // 加 1：一開始就有一個進位待處理
    for w in words.iter_mut().rev() {
        *w = !*w;
        if carry {
            let (v, c) = w.overflowing_add(1);
            *w = v;
            carry = c;
        }
    }
}

/// big-endian u32 詞 → magnitude：去除前導零字；全零（或空）得到空 Vec。
fn make_magnitude_be_u32(words: &[u32]) -> Vec<Limb> {
    mag_from_u32_be(words)
}

/// 將 big-endian 兩補數負數的 u32 詞還原成其絕對值的 magnitude。
///
/// 前提：`words` 代表負數（最高字的最高位為 1）。
fn make_magnitude_be_u32_negative(words: &[u32]) -> Vec<Limb> {
    // 兩補數轉絕對值：全部反相，再從最低字（尾端）加 1
    let mut inverse: Vec<u32> = words.iter().map(|&w| !w).collect();
    for w in inverse.iter_mut().rev() {
        let (v, carry) = w.overflowing_add(1);
        *w = v;
        if !carry {
            break; // 沒有進位，結束
        }
    }
    // 反相後即為絕對值的 BE 詞，交給既有 helper 去零
    make_magnitude_be_u32(&inverse)
}

/// little-endian u32 詞 → magnitude：反轉成 big-endian 後去前導零。
fn make_magnitude_le_u32(words: &[u32]) -> Vec<Limb> {
    // little-endian：最高字在尾端，反轉讓最高字排在前面
    let be: Vec<u32> = words.iter().rev().copied().collect();
    make_magnitude_be_u32(&be)
}

/// 將 little-endian 兩補數負數的 u32 詞還原成其絕對值的 magnitude。
///
/// 前提：`words` 代表負數（最高字的最高位為 1；最高字在尾端）。
fn make_magnitude_le_u32_negative(words: &[u32]) -> Vec<Limb> {
    // 兩補數轉絕對值：全部反相，再從最低字（前端）加 1
    let mut inverse: Vec<u32> = words.iter().map(|&w| !w).collect();
    for w in inverse.iter_mut() {
        let (v, carry) = w.overflowing_add(1);
        *w = v;
        if !carry {
            break; // 沒有進位，結束
        }
    }
    // 反相後即為絕對值的 LE 詞，交給既有 helper 反轉去零
    make_magnitude_le_u32(&inverse)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- from_u32_be / _unsigned ---

    #[test]
    fn from_u32_be_empty_is_zero() {
        assert_eq!(BigInteger::from_u32_be(&[]), BigInteger::from_i32(0));
    }

    #[test]
    fn from_u32_be_all_zero_is_zero() {
        assert_eq!(BigInteger::from_u32_be(&[0, 0, 0]), BigInteger::from_i32(0));
    }

    #[test]
    fn from_u32_be_positive_multiword() {
        assert_eq!(BigInteger::from_u32_be(&[1, 0]), BigInteger::from_u64(1 << 32));
    }

    #[test]
    fn from_u32_be_strips_leading_zero_words() {
        assert_eq!(BigInteger::from_u32_be(&[0, 0, 5]), BigInteger::from_u32(5));
    }

    #[test]
    fn from_u32_be_leading_zero_word_forces_positive() {
        // 最高字為 0 → 非負，即使下個字最高位為 1
        assert_eq!(
            BigInteger::from_u32_be(&[0, 0x8000_0000]),
            BigInteger::from_u64(1 << 31)
        );
    }

    #[test]
    fn from_u32_be_minus_one() {
        assert_eq!(BigInteger::from_u32_be(&[0xFFFF_FFFF]), BigInteger::from_i32(-1));
    }

    #[test]
    fn from_u32_be_min_i32_word() {
        // 0x8000_0000 最高位為 1 → 負數 = -2^31
        assert_eq!(BigInteger::from_u32_be(&[0x8000_0000]), BigInteger::from_i32(i32::MIN));
    }

    #[test]
    fn from_u32_be_unsigned_top_bit_is_data() {
        // 有別於 from_u32_be：不看符號
        assert_eq!(
            BigInteger::from_u32_be_unsigned(&[0x8000_0000]),
            BigInteger::from_u64(1 << 31)
        );
    }

    // --- from_u32_le ---

    #[test]
    fn from_u32_le_matches_be_reversed() {
        let be = [0x0000_0001u32, 0x2345_6789, 0xABCD_EF01];
        let mut le = be;
        le.reverse();
        assert_eq!(BigInteger::from_u32_le(&le), BigInteger::from_u32_be(&be));
    }

    #[test]
    fn from_u32_le_minus_one() {
        assert_eq!(BigInteger::from_u32_le(&[0xFFFF_FFFF]), BigInteger::from_i32(-1));
    }

    #[test]
    fn from_u32_le_negative_multiword_matches_be() {
        // 尾端字最高位為 1 → 負數；與 BE(reversed) 一致
        let be = [0xFFFF_FFFFu32, 0x0000_0000];
        let mut le = be;
        le.reverse();
        assert_eq!(BigInteger::from_u32_le(&le), BigInteger::from_u32_be(&be));
    }

    // --- to_u32_be / _unsigned ---

    #[test]
    fn to_u32_be_signed_needs_sign_word() {
        // 2^31 的最高字最高位為 1 → 需前導 0 字保持正號
        assert_eq!(
            BigInteger::from_u64(1 << 31).to_u32_be(),
            vec![0x0000_0000, 0x8000_0000]
        );
    }

    #[test]
    fn to_u32_be_unsigned_no_sign_word() {
        assert_eq!(BigInteger::from_u64(1 << 31).to_u32_be_unsigned(), vec![0x8000_0000]);
    }

    #[test]
    fn to_u32_be_minus_one() {
        assert_eq!(BigInteger::from_i32(-1).to_u32_be(), vec![0xFFFF_FFFF]);
    }

    #[test]
    fn to_u32_be_zero() {
        assert_eq!(BigInteger::from_i32(0).to_u32_be(), vec![0]);
        assert_eq!(BigInteger::from_i32(0).to_u32_be_unsigned(), vec![0]);
    }

    #[test]
    fn to_u32_le_matches_be_reversed() {
        let n = BigInteger::from_u64((1 << 63) + 7);
        let mut be = n.to_u32_be();
        be.reverse();
        assert_eq!(n.to_u32_le(), be);
    }

    // --- roundtrips ---

    #[test]
    fn to_from_u32_be_roundtrip_signed() {
        for v in [0i64, 1, -1, 5, -5, i32::MIN as i64, i32::MAX as i64, 1 << 40, -(1 << 40)] {
            let n = BigInteger::from_i64(v);
            assert_eq!(BigInteger::from_u32_be(&n.to_u32_be()), n, "v = {v}");
            assert_eq!(BigInteger::from_u32_le(&n.to_u32_le()), n, "v = {v}");
        }
    }

    #[test]
    fn to_from_u32_be_roundtrip_unsigned() {
        for v in [0u64, 1, 5, 1 << 31, 1 << 32, u64::MAX] {
            let n = BigInteger::from_u64(v);
            assert_eq!(BigInteger::from_u32_be_unsigned(&n.to_u32_be_unsigned()), n, "v = {v}");
            assert_eq!(BigInteger::from_u32_le_unsigned(&n.to_u32_le_unsigned()), n, "v = {v}");
        }
    }

    // --- *_into ---

    #[test]
    fn try_to_u32_into_ok_and_err() {
        let n = BigInteger::from_u64(1 << 32); // u32_length = 2
        let mut buf = [0u32; 4];
        assert_eq!(n.try_to_u32_be_into(&mut buf), Ok(2));
        assert_eq!(&buf[..2], &[0x0000_0001, 0x0000_0000]);

        let mut tiny = [0u32; 1];
        let err = n.try_to_u32_be_into(&mut tiny).unwrap_err();
        assert_eq!(err.needed, 2);
        assert_eq!(err.available, 1);
    }

    #[test]
    fn to_u32_into_matches_allocating() {
        let n = BigInteger::from_i64(-(1 << 40));
        let mut buf = [0u32; 8];
        let len = n.to_u32_be_into(&mut buf);
        assert_eq!(&buf[..len], n.to_u32_be().as_slice());
    }

    #[test]
    #[should_panic(expected = "to_u32_be_into")]
    fn to_u32_be_into_panics_when_too_small() {
        let n = BigInteger::from_u64(1 << 32); // 需要 2 字
        let mut buf = [0u32; 1];
        n.to_u32_be_into(&mut buf);
    }

    // --- length accessors ---

    #[test]
    fn u32_length_matches_output() {
        for v in [0i64, 1, -1, i32::MIN as i64, 1 << 31, 1 << 32, -(1 << 40)] {
            let n = BigInteger::from_i64(v);
            assert_eq!(n.u32_length(), n.to_u32_be().len(), "signed v = {v}");
            assert_eq!(n.u32_length_unsigned(), n.to_u32_be_unsigned().len(), "unsigned v = {v}");
        }
    }
}

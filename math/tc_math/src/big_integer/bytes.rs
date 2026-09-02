//! Big-endian / little-endian byte (de)serialization for [`BigInteger`].
//!
//! Split into a submodule to keep `big_integer.rs` shorter. As a descendant
//! module this reaches the parent's private items (`sign`, `magnitude`,
//! `BigInteger::new`, `byte_length*`, and the `make_magnitude_*` /
//! `twos_complement_in_place` helpers), so nothing there needs widening.

use super::{
    BigInteger, BufferTooSmall, WORD_BITS, make_magnitude_be, make_magnitude_be_negative,
    make_magnitude_le, make_magnitude_le_negative, twos_complement_in_place,
};

// no_std 下沒有 std prelude，`vec!` 巨集與 `Vec` 型別需從 alloc 顯式引入；
// std build 由 prelude 提供，故僅在關閉 std 時引入，避免重複 import 警告。
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

impl BigInteger {
    /// Creates a `BigInteger` from a big-endian, two's-complement byte slice.
    ///
    /// The most-significant byte comes first. A set top bit in that byte means
    /// the value is negative (two's complement). An empty slice is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_bytes_be(&[0xFF]); // -1
    /// ```
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return BigInteger::new(0, Vec::new());
        }
        if bytes[0] & 0x80 != 0 {
            // 最高位為 1：兩補數負數
            BigInteger::new(-1, make_magnitude_be_negative(bytes))
        } else {
            // 非負：magnitude 為空時代表 0
            let magnitude = make_magnitude_be(bytes);
            let sign = if magnitude.is_empty() { 0 } else { 1 };
            BigInteger::new(sign, magnitude)
        }
    }

    /// Creates a non-negative `BigInteger` from a big-endian, **unsigned** byte
    /// slice: the top bit is data, never a sign. An empty (or all-zero) slice
    /// is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// // 有別於 from_bytes_be：0x80 是 128，不是 -128
    /// assert_eq!(BigInteger::from_bytes_be_unsigned(&[0x80]), BigInteger::from_u32(128));
    /// ```
    pub fn from_bytes_be_unsigned(bytes: &[u8]) -> Self {
        // 一律非負：最高位是資料，不是符號
        let magnitude = make_magnitude_be(bytes);
        let sign = if magnitude.is_empty() { 0 } else { 1 };
        BigInteger::new(sign, magnitude)
    }

    /// Creates a `BigInteger` from a little-endian, two's-complement byte slice.
    ///
    /// The least-significant byte comes first, so the sign lives in the top bit
    /// of the *last* byte. An empty slice is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_bytes_le(&[0xFF]); // -1
    /// ```
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return BigInteger::new(0, Vec::new());
        }
        // little-endian：最高位元組在尾端，符號位取最後一個位元組
        if bytes[bytes.len() - 1] & 0x80 != 0 {
            BigInteger::new(-1, make_magnitude_le_negative(bytes))
        } else {
            let magnitude = make_magnitude_le(bytes);
            let sign = if magnitude.is_empty() { 0 } else { 1 };
            BigInteger::new(sign, magnitude)
        }
    }

    /// Creates a non-negative `BigInteger` from a little-endian, **unsigned**
    /// byte slice: the top bit (of the last byte) is data, never a sign. An
    /// empty (or all-zero) slice is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_bytes_le_unsigned(&[0x00, 0x80]), BigInteger::from_u32(0x8000));
    /// ```
    pub fn from_bytes_le_unsigned(bytes: &[u8]) -> Self {
        let magnitude = make_magnitude_le(bytes);
        let sign = if magnitude.is_empty() { 0 } else { 1 };
        BigInteger::new(sign, magnitude)
    }

    /// 把 `n = out.len()` 個位元組的 big-endian 編碼寫進 `out`（零配置核心）。
    ///
    /// 先把 `|self|` 右對齊寫入、左邊補 0（超出 magnitude 的高位、以及零，自然補 0）；
    /// `signed` 且為負時再對整段取兩補數。`out.len()` 須等於對應的 `byte_length*`。
    fn write_magnitude_be(&self, out: &mut [u8], signed: bool) {
        let n = out.len();
        let bpw = WORD_BITS / 8; // 每個 Limb 的位元組數（u32→4、u64→8）
        for j in 0..n {
            // 第 j 個低位位元組：取自第 j/bpw 個低位字的第 j%bpw 個位元組
            out[n - 1 - j] = if j / bpw < self.magnitude.len() {
                (self.magnitude[self.magnitude.len() - 1 - j / bpw] >> (8 * (j % bpw))) as u8
            } else {
                0
            };
        }
        if signed && self.sign < 0 {
            twos_complement_in_place(out); // 負數：整段兩補數
        }
    }

    /// Returns the magnitude (absolute value) as minimal big-endian bytes,
    /// **without** any sign. Zero is `[0]`; the top bit is data, not a sign.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u32(128).to_bytes_be_unsigned(), vec![0x80]);
    /// assert_eq!(BigInteger::from_i32(-128).to_bytes_be_unsigned(), vec![0x80]); // 只看絕對值
    /// ```
    pub fn to_bytes_be_unsigned(&self) -> Vec<u8> {
        let mut v = vec![0u8; self.byte_length_unsigned()];
        self.write_magnitude_be(&mut v, false);
        v
    }

    /// Little-endian counterpart of [`BigInteger::to_bytes_be_unsigned`].
    pub fn to_bytes_le_unsigned(&self) -> Vec<u8> {
        let mut v = self.to_bytes_be_unsigned();
        v.reverse(); // BE 最小位元組反轉即 LE
        v
    }

    /// Returns the minimal two's-complement big-endian bytes (with sign).
    ///
    /// Inverse of [`BigInteger::from_bytes_be`]. Zero is `[0]`. A leading
    /// `0x00` (non-negative) or `0xFF` (negative) byte is included when needed
    /// so the sign bit reads correctly.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_i32(128).to_bytes_be(), vec![0x00, 0x80]);
    /// assert_eq!(BigInteger::from_i32(-129).to_bytes_be(), vec![0xFF, 0x7F]);
    /// ```
    pub fn to_bytes_be(&self) -> Vec<u8> {
        let mut v = vec![0u8; self.byte_length()];
        self.write_magnitude_be(&mut v, true);
        v
    }

    /// Little-endian counterpart of [`BigInteger::to_bytes_be`].
    pub fn to_bytes_le(&self) -> Vec<u8> {
        let mut v = self.to_bytes_be();
        v.reverse();
        v
    }

    /// Writes the signed (two's-complement) big-endian encoding into the front
    /// of `dst`, returning the number of bytes written (= [`BigInteger::byte_length`]),
    /// or [`BufferTooSmall`] if `dst` is too short. Allocation-free.
    pub fn try_to_bytes_be_into(&self, dst: &mut [u8]) -> Result<usize, BufferTooSmall> {
        let n = self.byte_length();
        if dst.len() < n {
            return Err(BufferTooSmall { needed: n, available: dst.len() });
        }
        self.write_magnitude_be(&mut dst[..n], true);
        Ok(n)
    }

    /// Little-endian counterpart of [`BigInteger::try_to_bytes_be_into`].
    pub fn try_to_bytes_le_into(&self, dst: &mut [u8]) -> Result<usize, BufferTooSmall> {
        let n = self.byte_length();
        if dst.len() < n {
            return Err(BufferTooSmall { needed: n, available: dst.len() });
        }
        self.write_magnitude_be(&mut dst[..n], true);
        dst[..n].reverse();
        Ok(n)
    }

    /// Unsigned (magnitude) big-endian counterpart of [`BigInteger::try_to_bytes_be_into`].
    pub fn try_to_bytes_be_unsigned_into(&self, dst: &mut [u8]) -> Result<usize, BufferTooSmall> {
        let n = self.byte_length_unsigned();
        if dst.len() < n {
            return Err(BufferTooSmall { needed: n, available: dst.len() });
        }
        self.write_magnitude_be(&mut dst[..n], false);
        Ok(n)
    }

    /// Little-endian counterpart of [`BigInteger::try_to_bytes_be_unsigned_into`].
    pub fn try_to_bytes_le_unsigned_into(&self, dst: &mut [u8]) -> Result<usize, BufferTooSmall> {
        let n = self.byte_length_unsigned();
        if dst.len() < n {
            return Err(BufferTooSmall { needed: n, available: dst.len() });
        }
        self.write_magnitude_be(&mut dst[..n], false);
        dst[..n].reverse();
        Ok(n)
    }

    /// Panicking version of [`BigInteger::try_to_bytes_be_into`]; returns the
    /// number of bytes written. Allocation-free.
    ///
    /// # Panics
    ///
    /// Panics if `dst.len() < self.byte_length()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_i32(-129);
    /// let mut buf = [0u8; 8];
    /// let len = n.to_bytes_be_into(&mut buf);
    /// assert_eq!(&buf[..len], &[0xFF, 0x7F]);
    /// ```
    pub fn to_bytes_be_into(&self, dst: &mut [u8]) -> usize {
        self.try_to_bytes_be_into(dst).unwrap_or_else(|e| panic!("to_bytes_be_into: {e}"))
    }

    /// Little-endian counterpart of [`BigInteger::to_bytes_be_into`].
    ///
    /// # Panics
    ///
    /// Panics if `dst.len() < self.byte_length()`.
    pub fn to_bytes_le_into(&self, dst: &mut [u8]) -> usize {
        self.try_to_bytes_le_into(dst).unwrap_or_else(|e| panic!("to_bytes_le_into: {e}"))
    }

    /// Panicking version of [`BigInteger::try_to_bytes_be_unsigned_into`].
    ///
    /// # Panics
    ///
    /// Panics if `dst.len() < self.byte_length_unsigned()`.
    pub fn to_bytes_be_unsigned_into(&self, dst: &mut [u8]) -> usize {
        self.try_to_bytes_be_unsigned_into(dst).unwrap_or_else(|e| panic!("to_bytes_be_unsigned_into: {e}"))
    }

    /// Little-endian counterpart of [`BigInteger::to_bytes_be_unsigned_into`].
    ///
    /// # Panics
    ///
    /// Panics if `dst.len() < self.byte_length_unsigned()`.
    pub fn to_bytes_le_unsigned_into(&self, dst: &mut [u8]) -> usize {
        self.try_to_bytes_le_unsigned_into(dst).unwrap_or_else(|e| panic!("to_bytes_le_unsigned_into: {e}"))
    }
}

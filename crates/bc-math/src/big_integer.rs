use std::sync::OnceLock;

#[derive(Clone, Debug)]
pub struct BigInteger {
    sign: i32,
    /// 不可變、big-endian、無前導零；不可變型別故用 `Box<[u32]>` 而非 `Vec<u32>`。
    magnitude: Box<[u32]>,
    /// 惰性快取：設定位元數 (population count)。
    bits: OnceLock<u32>,
    /// 惰性快取：位元長度。
    bit_length: OnceLock<u32>,
}

impl BigInteger {
    // 施工端用 `Vec<u32>` 傳入，儲存時落地成 `Box<[u32]>`。
    fn new(sign: i32, magnitude: Vec<u32>) -> Self {
        BigInteger {
            sign,
            magnitude: magnitude.into_boxed_slice(),
            bits: OnceLock::new(),
            bit_length: OnceLock::new(),
        }
    }

    /// Returns the sign of this value: `-1` (negative), `0` (zero), or `1` (positive).
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_i32(-5).sign(), -1);
    /// assert_eq!(BigInteger::from_i32(0).sign(), 0);
    /// assert_eq!(BigInteger::from_i32(5).sign(), 1);
    /// ```
    pub fn sign(&self) -> i32 {
        self.sign
    }

    /// Returns `true` if this value is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
    ///
    /// assert!(BigInteger::from_u32(0).is_zero());
    /// assert!(!BigInteger::from_u32(5).is_zero());
    /// ```
    pub fn is_zero(&self) -> bool {
        self.sign == 0
    }

    /// Creates a `BigInteger` from an unsigned 32-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_u32(5);
    /// ```
    pub fn from_u32(value: u32) -> Self {
        if value == 0 {
            BigInteger::new(0, Vec::new())
        } else {
            BigInteger::new(1, vec![value])
        }
    }

    /// Creates a `BigInteger` from an unsigned 16-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_u16(5);
    /// ```
    pub fn from_u16(value: u16) -> Self {
        BigInteger::from_u32(u32::from(value))
    }

    /// Creates a `BigInteger` from an unsigned 8-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_u8(5);
    /// ```
    pub fn from_u8(value: u8) -> Self {
        BigInteger::from_u32(u32::from(value))
    }

    /// Creates a `BigInteger` from an unsigned 64-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_u64(5);
    /// ```
    pub fn from_u64(value: u64) -> Self {
        if value == 0 {
            return BigInteger::new(0, Vec::new());
        }
        let high = (value >> 32) as u32;
        let low = value as u32;
        // Big-endian, no leading zero word: drop the high word when it is zero.
        let magnitude = if high == 0 { vec![low] } else { vec![high, low] };
        BigInteger::new(1, magnitude)
    }

    /// Creates a `BigInteger` from a signed 32-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_i32(-5);
    /// ```
    pub fn from_i32(value: i32) -> Self {
        if value == 0 {
            return BigInteger::new(0, Vec::new());
        }
        let sign = if value < 0 { -1 } else { 1 };
        // `unsigned_abs` yields the magnitude as `u32`, avoiding overflow on `i32::MIN`.
        BigInteger::new(sign, vec![value.unsigned_abs()])
    }

    /// Creates a `BigInteger` from a signed 16-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_i16(-5);
    /// ```
    pub fn from_i16(value: i16) -> Self {
        BigInteger::from_i32(i32::from(value))
    }

    /// Creates a `BigInteger` from a signed 8-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_i8(-5);
    /// ```
    pub fn from_i8(value: i8) -> Self {
        BigInteger::from_i32(i32::from(value))
    }

    /// Creates a `BigInteger` from a signed 64-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_i64(-5);
    /// ```
    pub fn from_i64(value: i64) -> Self {
        if value == 0 {
            return BigInteger::new(0, Vec::new());
        }
        // `unsigned_abs` avoids overflow on `i64::MIN`; reuse `from_u64`'s word split.
        let magnitude = Vec::from(BigInteger::from_u64(value.unsigned_abs()).magnitude);
        let sign = if value < 0 { -1 } else { 1 };
        BigInteger::new(sign, magnitude)
    }

    /// Creates a `BigInteger` from a signed 128-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_i128(-5);
    /// ```
    pub fn from_i128(value: i128) -> Self {
        if value == 0 {
            return BigInteger::new(0, Vec::new());
        }
        // `unsigned_abs` avoids overflow on `i128::MIN`; reuse `from_u128`'s word split.
        let magnitude = Vec::from(BigInteger::from_u128(value.unsigned_abs()).magnitude);
        let sign = if value < 0 { -1 } else { 1 };
        BigInteger::new(sign, magnitude)
    }

    /// Creates a `BigInteger` from an unsigned 128-bit value.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
    ///
    /// let n = BigInteger::from_u128(5);
    /// ```
    pub fn from_u128(value: u128) -> Self {
        if value == 0 {
            return BigInteger::new(0, Vec::new());
        }
        // Split into 4 big-endian words (most-significant first).
        let words = [
            (value >> 96) as u32,
            (value >> 64) as u32,
            (value >> 32) as u32,
            value as u32,
        ];
        // Skip leading zero words. `value != 0` guarantees at least one non-zero.
        let start = words.iter().position(|&w| w != 0).unwrap();
        BigInteger::new(1, words[start..].to_vec())
    }

    /// Creates a `BigInteger` from a big-endian, two's-complement byte slice.
    ///
    /// The most-significant byte comes first. A set top bit in that byte means
    /// the value is negative (two's complement). An empty slice is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
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

    /// Creates a `BigInteger` from a little-endian, two's-complement byte slice.
    ///
    /// The least-significant byte comes first, so the sign lives in the top bit
    /// of the *last* byte. An empty slice is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
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
}

impl PartialEq for BigInteger {
    /// 相等只看數值（`sign` + `magnitude`），刻意忽略惰性快取欄位。
    fn eq(&self, other: &Self) -> bool {
        self.sign == other.sign && self.magnitude == other.magnitude
    }
}

impl Eq for BigInteger {}

fn make_magnitude_be(buffer: &[u8]) -> Vec<u32> {
    // 去除前導零位元組；全零（或空）緩衝區會得到空切片
    let start = buffer.iter().position(|&b| b != 0).unwrap_or(buffer.len());

    buffer[start..]
        .rchunks(size_of::<u32>()) // 從低位端每 4 位元組切一塊
        .rev() // 反轉，讓最高位的字排在前面
        .map(|chunk| chunk.iter().fold(0u32, |acc, &b| (acc << 8) | b as u32))
        .collect()
}

/// 將 big-endian 兩補數負數位元組還原成其絕對值的 magnitude。
///
/// 前提：`buffer` 代表負數（最高位元組的最高位為 1）。
fn make_magnitude_be_negative(buffer: &[u8]) -> Vec<u32> {
    // 兩補數轉絕對值：全部反相，再從最低位 (尾端) 加 1
    let mut inverse: Vec<u8> = buffer.iter().map(|&b| !b).collect();
    for b in inverse.iter_mut().rev() {
        if *b == 0xFF {
            *b = 0; // 0xFF + 1 = 0x00，進位繼續往高位
        } else {
            *b += 1; // 沒有進位，結束
            break;
        }
    }
    // 反相後即為絕對值的 BE 位元組，交給既有 helper 去零、打包
    make_magnitude_be(&inverse)
}

fn make_magnitude_le(buffer: &[u8]) -> Vec<u32> {
    // little-endian：最高位在尾端，所以去除「尾端」的零位元組
    let end = buffer.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);

    buffer[..end]
        .chunks(size_of::<u32>()) // 從低位端每 4 位元組切一塊（低位字先出）
        .rev() // 反轉，讓最高位的字排在前面
        .map(|chunk| chunk.iter().rev().fold(0u32, |acc, &b| (acc << 8) | b as u32))
        .collect()
}

/// 將 little-endian 兩補數負數位元組還原成其絕對值的 magnitude。
///
/// 前提：`buffer` 代表負數（最高位元組的最高位為 1；最高位元組在尾端）。
fn make_magnitude_le_negative(buffer: &[u8]) -> Vec<u32> {
    // 兩補數轉絕對值：全部反相，再從最低位 (前端) 加 1
    let mut inverse: Vec<u8> = buffer.iter().map(|&b| !b).collect();
    for b in inverse.iter_mut() {
        if *b == 0xFF {
            *b = 0; // 0xFF + 1 = 0x00，進位繼續往高位
        } else {
            *b += 1; // 沒有進位，結束
            break;
        }
    }
    // 反相後即為絕對值的 LE 位元組，交給既有 helper 去零、打包
    make_magnitude_le(&inverse)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u32_zero() {
        let n = BigInteger::from_u32(0);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }

    #[test]
    fn sign_reports_all_three_states() {
        assert_eq!(BigInteger::from_i32(-42).sign(), -1);
        assert_eq!(BigInteger::from_i32(0).sign(), 0);
        assert_eq!(BigInteger::from_i32(42).sign(), 1);
    }

    #[test]
    fn is_zero_matches_sign() {
        assert!(BigInteger::from_i32(0).is_zero());
        assert!(!BigInteger::from_i32(1).is_zero());
        assert!(!BigInteger::from_i32(-1).is_zero());
        // 空位元組與全零位元組都應是零
        assert!(BigInteger::from_bytes_be(&[]).is_zero());
        assert!(BigInteger::from_bytes_be(&[0, 0, 0]).is_zero());
    }

    #[test]
    fn eq_same_value_from_different_sources() {
        // 同一個數、不同建構路徑，應相等
        assert_eq!(BigInteger::from_i32(128), BigInteger::from_bytes_be(&[0x00, 0x80]));
        assert_eq!(BigInteger::from_u64(0), BigInteger::from_i32(0));
    }

    #[test]
    fn eq_distinguishes_sign_and_magnitude() {
        assert_ne!(BigInteger::from_i32(5), BigInteger::from_i32(-5)); // 同 magnitude、異號
        assert_ne!(BigInteger::from_i32(5), BigInteger::from_i32(6)); // 同號、異 magnitude
    }

    #[test]
    fn eq_ignores_cache_state() {
        // 兩個相同的值，其中一個先觸發快取欄位，相等性不應改變
        let a = BigInteger::from_i32(42);
        let b = BigInteger::from_i32(42);
        // 對 a 的快取寫入值（模擬已計算），b 保持未計算
        a.bit_length.set(6).unwrap();
        a.bits.set(3).unwrap();
        assert!(b.bit_length.get().is_none());
        assert_eq!(a, b); // 快取狀態不同，仍相等
    }

    #[test]
    fn from_u32_positive() {
        let n = BigInteger::from_u32(5);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![5]);
    }

    #[test]
    fn from_u32_max() {
        let n = BigInteger::from_u32(u32::MAX);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![u32::MAX]);
    }

    #[test]
    fn from_u16_zero_and_max() {
        let zero = BigInteger::from_u16(0);
        assert_eq!(zero.sign, 0);
        assert!(zero.magnitude.is_empty());

        let max = BigInteger::from_u16(u16::MAX);
        assert_eq!(max.sign, 1);
        assert_eq!(max.magnitude.to_vec(), vec![u32::from(u16::MAX)]);
    }

    #[test]
    fn from_u8_zero_and_max() {
        let zero = BigInteger::from_u8(0);
        assert_eq!(zero.sign, 0);
        assert!(zero.magnitude.is_empty());

        let max = BigInteger::from_u8(u8::MAX);
        assert_eq!(max.sign, 1);
        assert_eq!(max.magnitude.to_vec(), vec![u32::from(u8::MAX)]);
    }

    #[test]
    fn from_u64_zero() {
        let n = BigInteger::from_u64(0);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }

    #[test]
    fn from_u64_single_word() {
        // Fits in one word -> no leading zero word.
        let n = BigInteger::from_u64(5);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![5]);
    }

    #[test]
    fn from_u64_two_words() {
        // 0x0000_0001_0000_0002 -> [1, 2] big-endian.
        let n = BigInteger::from_u64((1 << 32) | 2);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![1, 2]);
    }

    #[test]
    fn from_u64_max() {
        let n = BigInteger::from_u64(u64::MAX);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![u32::MAX, u32::MAX]);
    }

    #[test]
    fn from_i32_zero() {
        let n = BigInteger::from_i32(0);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }

    #[test]
    fn from_i32_positive() {
        let n = BigInteger::from_i32(5);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![5]);
    }

    #[test]
    fn from_i32_negative() {
        let n = BigInteger::from_i32(-5);
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude.to_vec(), vec![5]);
    }

    #[test]
    fn from_i32_min() {
        // -i32::MIN would overflow; magnitude is 2^31.
        let n = BigInteger::from_i32(i32::MIN);
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude.to_vec(), vec![1 << 31]);
    }

    #[test]
    fn from_i32_max() {
        let n = BigInteger::from_i32(i32::MAX);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![i32::MAX as u32]);
    }

    #[test]
    fn from_i16_negative_and_min() {
        let neg = BigInteger::from_i16(-5);
        assert_eq!(neg.sign, -1);
        assert_eq!(neg.magnitude.to_vec(), vec![5]);

        let min = BigInteger::from_i16(i16::MIN);
        assert_eq!(min.sign, -1);
        assert_eq!(min.magnitude.to_vec(), vec![i16::MIN.unsigned_abs() as u32]);
    }

    #[test]
    fn from_i8_negative_and_min() {
        let neg = BigInteger::from_i8(-5);
        assert_eq!(neg.sign, -1);
        assert_eq!(neg.magnitude.to_vec(), vec![5]);

        let min = BigInteger::from_i8(i8::MIN);
        assert_eq!(min.sign, -1);
        assert_eq!(min.magnitude.to_vec(), vec![i8::MIN.unsigned_abs() as u32]);
    }

    #[test]
    fn from_i64_negative_two_words() {
        let n = BigInteger::from_i64(-((1i64 << 32) | 2));
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude.to_vec(), vec![1, 2]);
    }

    #[test]
    fn from_i64_min() {
        // -i64::MIN would overflow; magnitude is 2^63 -> high word 0x8000_0000.
        let n = BigInteger::from_i64(i64::MIN);
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude.to_vec(), vec![1 << 31, 0]);
    }

    #[test]
    fn from_i128_negative_and_min() {
        let neg = BigInteger::from_i128(-5);
        assert_eq!(neg.sign, -1);
        assert_eq!(neg.magnitude.to_vec(), vec![5]);

        // magnitude of i128::MIN is 2^127 -> top word 0x8000_0000, rest zero.
        let min = BigInteger::from_i128(i128::MIN);
        assert_eq!(min.sign, -1);
        assert_eq!(min.magnitude.to_vec(), vec![1 << 31, 0, 0, 0]);
    }

    #[test]
    fn from_u128_zero() {
        let n = BigInteger::from_u128(0);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }

    #[test]
    fn from_u128_single_word() {
        let n = BigInteger::from_u128(5);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![5]);
    }

    #[test]
    fn from_u128_strips_leading_zero_words() {
        // 0x0000_0000_0000_0003_0000_0000_0000_0004
        // = word3<<96 | ... ; top two words are zero and must be dropped.
        let value = (3u128 << 64) | 4;
        let n = BigInteger::from_u128(value);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![3, 0, 4]);
    }

    #[test]
    fn from_u128_max() {
        let n = BigInteger::from_u128(u128::MAX);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![u32::MAX, u32::MAX, u32::MAX, u32::MAX]);
    }

    #[test]
    fn make_magnitude_be_empty() {
        assert_eq!(make_magnitude_be(&[]), Vec::<u32>::new());
    }

    #[test]
    fn make_magnitude_be_all_zero() {
        // 全零位元組視同 0，得到空 magnitude
        assert_eq!(make_magnitude_be(&[0, 0, 0]), Vec::<u32>::new());
    }

    #[test]
    fn make_magnitude_be_single_byte() {
        assert_eq!(make_magnitude_be(&[0x05]), vec![0x05]);
    }

    #[test]
    fn make_magnitude_be_strips_leading_zeros() {
        // 前導零 + 殘塊：只保留有效位元組
        assert_eq!(make_magnitude_be(&[0, 0, 0xAA, 0xBB]), vec![0xAABB]);
    }

    #[test]
    fn make_magnitude_be_partial_then_full_word() {
        // 殘塊(AABB) + 一個滿字(CCDDEEFF)
        let buffer = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(make_magnitude_be(&buffer), vec![0x0000_AABB, 0xCCDD_EEFF]);
    }

    #[test]
    fn make_magnitude_be_exact_word() {
        // 剛好 4 位元組，單一滿字
        assert_eq!(make_magnitude_be(&[1, 2, 3, 4]), vec![0x0102_0304]);
    }

    #[test]
    fn make_magnitude_be_keeps_interior_zero() {
        // 中間的零位元組必須保留，只有最高位端的零才剝除
        let buffer = [0x01, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(make_magnitude_be(&buffer), vec![0x01, 0x0000_0000]);
    }

    #[test]
    fn make_magnitude_le_empty() {
        assert_eq!(make_magnitude_le(&[]), Vec::<u32>::new());
    }

    #[test]
    fn make_magnitude_le_all_zero() {
        // 全零位元組視同 0，得到空 magnitude
        assert_eq!(make_magnitude_le(&[0, 0, 0]), Vec::<u32>::new());
    }

    #[test]
    fn make_magnitude_le_single_byte() {
        assert_eq!(make_magnitude_le(&[0x05]), vec![0x05]);
    }

    #[test]
    fn make_magnitude_le_strips_trailing_zeros() {
        // little-endian 的無意義零在尾端；[00,01] 代表 0x0100
        assert_eq!(make_magnitude_le(&[0x00, 0x01]), vec![0x0100]);
    }

    #[test]
    fn make_magnitude_le_partial_high_word() {
        // 0xAABBCCDDEEFF 的 LE 表示；最高位字 (AABB) 為殘塊
        let buffer = [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA];
        assert_eq!(make_magnitude_le(&buffer), vec![0x0000_AABB, 0xCCDD_EEFF]);
    }

    #[test]
    fn make_magnitude_le_two_words() {
        // 2^32：LE 為 [00,00,00,00,01]，magnitude 為 [1, 0]
        let buffer = [0x00, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(make_magnitude_le(&buffer), vec![1, 0]);
    }

    #[test]
    fn make_magnitude_le_matches_be_reversed() {
        // 同一個數：BE 輸入反轉即為其 LE 輸入，兩者 magnitude 必須相同
        let be = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let le: Vec<u8> = be.iter().rev().copied().collect();
        assert_eq!(make_magnitude_be(&be), make_magnitude_le(&le));
    }

    #[test]
    fn make_magnitude_be_negative_minus_one() {
        // 0xFF = -1，絕對值 magnitude 為 [1]
        assert_eq!(make_magnitude_be_negative(&[0xFF]), vec![1]);
        // 多位元組的 -1：0xFFFF 仍是 -1
        assert_eq!(make_magnitude_be_negative(&[0xFF, 0xFF]), vec![1]);
    }

    #[test]
    fn make_magnitude_be_negative_minus_128() {
        // 0x80 = -128
        assert_eq!(make_magnitude_be_negative(&[0x80]), vec![128]);
    }

    #[test]
    fn make_magnitude_be_negative_carry_propagates() {
        // 0xFF0000 = -65536；反相加 1 的進位會傳到新的高位字
        assert_eq!(make_magnitude_be_negative(&[0xFF, 0x00, 0x00]), vec![0x0001_0000]);
    }

    #[test]
    fn make_magnitude_be_negative_strips_sign_extension() {
        // 0xFFFFFF80 = -128，前導的 0xFF 符號延伸不影響絕對值
        assert_eq!(
            make_magnitude_be_negative(&[0xFF, 0xFF, 0xFF, 0x80]),
            vec![128]
        );
    }

    #[test]
    fn make_magnitude_le_negative_matches_be_reversed() {
        // 對同一個負數：BE 輸入反轉即為 LE 輸入，兩者絕對值 magnitude 必須相同
        let be = [0xFF, 0x00, 0x00]; // -65536
        let le: Vec<u8> = be.iter().rev().copied().collect();
        assert_eq!(
            make_magnitude_be_negative(&be),
            make_magnitude_le_negative(&le)
        );
    }

    #[test]
    fn make_magnitude_le_negative_minus_128() {
        // LE 的 0x80（單一位元組）= -128
        assert_eq!(make_magnitude_le_negative(&[0x80]), vec![128]);
    }

    #[test]
    fn from_bytes_be_empty_is_zero() {
        let n = BigInteger::from_bytes_be(&[]);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }

    #[test]
    fn from_bytes_be_zero() {
        let n = BigInteger::from_bytes_be(&[0x00, 0x00]);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }

    #[test]
    fn from_bytes_be_positive() {
        let n = BigInteger::from_bytes_be(&[0x05]);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![5]);
    }

    #[test]
    fn from_bytes_be_leading_zero_forces_positive() {
        // 0x80 單獨會被當負數；前綴一個 0x00 才是正的 128
        let n = BigInteger::from_bytes_be(&[0x00, 0x80]);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![128]);
    }

    #[test]
    fn from_bytes_be_minus_one() {
        let n = BigInteger::from_bytes_be(&[0xFF]);
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude.to_vec(), vec![1]);
    }

    #[test]
    fn from_bytes_be_minus_128() {
        let n = BigInteger::from_bytes_be(&[0x80]);
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude.to_vec(), vec![128]);
    }

    #[test]
    fn from_bytes_be_matches_from_i32() {
        // 用 i32 的 big-endian 位元組重建，應與 from_i32 結果一致
        for value in [0, 1, -1, 5, -5, 255, -255, 65536, -65536, i32::MAX, i32::MIN] {
            let n = BigInteger::from_bytes_be(&value.to_be_bytes());
            let expected = BigInteger::from_i32(value);
            assert_eq!(n.sign, expected.sign, "sign mismatch for {value}");
            assert_eq!(n.magnitude, expected.magnitude, "magnitude mismatch for {value}");
        }
    }

    #[test]
    fn from_bytes_le_empty_is_zero() {
        let n = BigInteger::from_bytes_le(&[]);
        assert_eq!(n.sign, 0);
        assert!(n.magnitude.is_empty());
    }

    #[test]
    fn from_bytes_le_leading_zero_forces_positive() {
        // LE：符號在尾端。[0x80, 0x00] 尾端最高位為 0 → 正的 128
        let n = BigInteger::from_bytes_le(&[0x80, 0x00]);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude.to_vec(), vec![128]);
    }

    #[test]
    fn from_bytes_le_minus_one() {
        let n = BigInteger::from_bytes_le(&[0xFF]);
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude.to_vec(), vec![1]);
    }

    #[test]
    fn from_bytes_le_matches_from_i32() {
        // 用 i32 的 little-endian 位元組重建，應與 from_i32 結果一致
        for value in [0, 1, -1, 5, -5, 255, -255, 65536, -65536, i32::MAX, i32::MIN] {
            let n = BigInteger::from_bytes_le(&value.to_le_bytes());
            let expected = BigInteger::from_i32(value);
            assert_eq!(n.sign, expected.sign, "sign mismatch for {value}");
            assert_eq!(n.magnitude, expected.magnitude, "magnitude mismatch for {value}");
        }
    }

    #[test]
    fn from_bytes_le_matches_be_reversed() {
        // 同一個數：BE 位元組反轉即為 LE 位元組，兩者結果必須相同
        let be = [0xFF, 0x00, 0x00]; // -65536
        let le: Vec<u8> = be.iter().rev().copied().collect();
        let a = BigInteger::from_bytes_be(&be);
        let b = BigInteger::from_bytes_le(&le);
        assert_eq!(a.sign, b.sign);
        assert_eq!(a.magnitude, b.magnitude);
    }
}
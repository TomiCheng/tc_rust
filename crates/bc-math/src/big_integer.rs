use std::cmp::Ordering;
use std::ops::{Add, Neg, Sub};
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

    /// Returns the absolute value.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_i32(-5).abs(), BigInteger::from_i32(5));
    /// ```
    pub fn abs(self) -> BigInteger {
        if self.sign >= 0 {
            // 已非負：原封不動（連已算好的快取都保留）
            self
        } else {
            // 負 → 正：搬移 buffer 重用；快取須重置（|n| 的 bit_length 等與 n 不同）
            BigInteger::new(1, Vec::from(self.magnitude))
        }
    }

    /// Returns the number of bits in the minimal two's-complement representation
    /// of this value, excluding the sign bit. Zero has a bit length of `0`.
    ///
    /// The result is computed once and cached.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u32(0).bit_length(), 0);
    /// assert_eq!(BigInteger::from_u32(5).bit_length(), 3); // 0b101
    /// assert_eq!(BigInteger::from_i32(-8).bit_length(), 3); // 負的 2 次方少 1
    /// ```
    pub fn bit_length(&self) -> u32 {
        *self
            .bit_length
            .get_or_init(|| calc_bit_length(self.sign, &self.magnitude))
    }

    /// Returns the number of bits in the two's-complement representation of this
    /// value that differ from the sign bit. For non-negative values this is the
    /// ordinary population count; for negative values it is `popcount(|n| - 1)`.
    ///
    /// The result is computed once and cached.
    ///
    /// # Examples
    ///
    /// ```
    /// use bc_math::big_integer::BigInteger;
    ///
    /// assert_eq!(BigInteger::from_u32(0b101).bit_count(), 2);
    /// assert_eq!(BigInteger::from_i32(-1).bit_count(), 0);
    /// assert_eq!(BigInteger::from_i32(-8).bit_count(), 3);
    /// ```
    pub fn bit_count(&self) -> u32 {
        *self.bits.get_or_init(|| {
            if self.sign < 0 {
                // 負數：bitCount = popcount(|n| - 1)
                bit_count_negative(&self.magnitude)
            } else {
                self.magnitude.iter().map(|w| w.count_ones()).sum()
            }
        })
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

impl Ord for BigInteger {
    fn cmp(&self, other: &Self) -> Ordering {
        // 符號不同：負 < 零 < 正，直接由符號決定
        if self.sign != other.sign {
            return self.sign.cmp(&other.sign);
        }
        // 同號（含兩者皆零，magnitude 皆空 → Equal）：比絕對值，負號時翻轉
        let mag = compare_magnitude(&self.magnitude, &other.magnitude);
        if self.sign < 0 { mag.reverse() } else { mag }
    }
}

impl PartialOrd for BigInteger {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other)) // 全序，永遠有結果
    }
}

impl Neg for BigInteger {
    type Output = BigInteger;

    /// 取負：只翻轉符號，magnitude 長度不變，故直接搬移（重用）buffer。
    fn neg(self) -> BigInteger {
        // `Vec::from` 接手 Box 的配置（O(1)），`new` 再 `into_boxed_slice` 收回（O(1)）；
        // 全程無新配置。快取則透過 `new` 重置（`-n` 的 bit_length/bit_count 與 `n` 不同）。
        BigInteger::new(-self.sign, Vec::from(self.magnitude))
    }
}

impl Neg for &BigInteger {
    type Output = BigInteger;

    fn neg(self) -> BigInteger {
        BigInteger::new(-self.sign, Vec::from(&*self.magnitude))
    }
}

impl Add for &BigInteger {
    type Output = BigInteger;

    fn add(self, rhs: &BigInteger) -> BigInteger {
        if self.sign == 0 {
            rhs.clone()
        } else if rhs.sign == 0 {
            self.clone()
        } else if self.sign == rhs.sign {
            // 同號：magnitude 相加，沿用符號
            BigInteger::new(self.sign, add_magnitudes(&self.magnitude, &rhs.magnitude))
        } else if rhs.sign < 0 {
            self - &(-rhs)
        } else {
            rhs - &(-self)
        }
    }
}

impl Sub for &BigInteger {
    type Output = BigInteger;

    fn sub(self, rhs: &BigInteger) -> BigInteger {
        if rhs.sign == 0 {
            return self.clone();
        } else if self.sign == 0 {
            return -rhs;
        } else if self.sign != rhs.sign {
            return self + &(-rhs);
        } else {
            // 同號：比 magnitude，大減小，結果符號 = 較大者的符號
            match compare_magnitude(&self.magnitude, &rhs.magnitude) {
                Ordering::Equal => BigInteger::from_u32(0),
                Ordering::Greater => {
                    BigInteger::new(self.sign, sub_magnitudes(&self.magnitude, &rhs.magnitude))
                }
                Ordering::Less => {
                    BigInteger::new(-self.sign, sub_magnitudes(&rhs.magnitude, &self.magnitude))
                }
            }
        }
    }
}

/// 計算 magnitude（big-endian、無前導零）的位元長度，不含符號位。
fn calc_bit_length(sign: i32, magnitude: &[u32]) -> u32 {
    // 無前導零，故第一個字即最高位字；空 magnitude 代表 0
    let Some((&first, rest)) = magnitude.split_first() else {
        return 0;
    };

    // 低位每個滿字貢獻 u32::BITS 位，加上最高位字的有效位數
    let mut bit_length = u32::BITS * rest.len() as u32 + bit_len(first);

    // 負的 2 次方（整個 magnitude 只有單一設定位元）時，少 1 位
    if sign < 0 && first.is_power_of_two() && rest.iter().all(|&w| w == 0) {
        bit_length -= 1;
    }
    bit_length
}

/// 單一字的位元長度（最高設定位元的位置 + 1）；`x` 為 0 時得 0。
fn bit_len(x: u32) -> u32 {
    u32::BITS - x.leading_zeros()
}

/// 比較兩個 magnitude（big-endian、無前導零）代表的絕對值大小。
fn compare_magnitude(x: &[u32], y: &[u32]) -> Ordering {
    // 無前導零：字數多者絕對值大；字數相同再逐字（最高位在前）比字典序
    x.len().cmp(&y.len()).then_with(|| x.cmp(y))
}

/// 去除 big-endian magnitude 的前導零字。
fn trim_leading_zeros(mut v: Vec<u32>) -> Vec<u32> {
    let start = v.iter().position(|&w| w != 0).unwrap_or(v.len());
    v.drain(..start);
    v
}

/// 兩個 magnitude（big-endian、無前導零）相加，回傳結果（無前導零）。
fn add_magnitudes(x: &[u32], y: &[u32]) -> Vec<u32> {
    let (long, short) = if x.len() >= y.len() { (x, y) } else { (y, x) };

    // 預留一個前導字容納最高位進位；長者先放入 result[1..]
    let mut result = vec![0u32; long.len() + 1];
    result[1..].copy_from_slice(long);

    // 從最低位（尾端）把 short 加進去，進位隨 u64 高位帶著走
    let mut carry = 0u64;
    let mut ri = result.len();
    for i in (0..short.len()).rev() {
        ri -= 1;
        carry += result[ri] as u64 + short[i] as u64;
        result[ri] = carry as u32;
        carry >>= 32;
    }
    // 剩餘進位繼續往更高位傳（result[0] 為 0，必能吸收，不會下溢）
    while carry != 0 {
        ri -= 1;
        carry += result[ri] as u64;
        result[ri] = carry as u32;
        carry >>= 32;
    }

    trim_leading_zeros(result)
}

/// 兩個 magnitude（big-endian、無前導零）相減，回傳 `x - y`（無前導零）。
///
/// 前提：數值上 `x >= y`（呼叫端用 `compare_magnitude` 確保），故結果非負。
fn sub_magnitudes(x: &[u32], y: &[u32]) -> Vec<u32> {
    debug_assert!(
        compare_magnitude(x, y) != Ordering::Less,
        "sub_magnitudes 需要 x >= y"
    );

    let mut result = x.to_vec();
    let offset = result.len() - y.len(); // y 對齊 result 低位端
    let mut borrow = 0i64;
    for i in (0..y.len()).rev() {
        let diff = result[offset + i] as i64 - y[i] as i64 - borrow;
        result[offset + i] = diff as u32; // 負則回繞，等同借位
        borrow = (diff < 0) as i64; // 0 或 1
    }
    // 剩餘借位往更高位傳
    let mut i = offset;
    while borrow != 0 && i > 0 {
        i -= 1;
        let (v, b) = result[i].overflowing_sub(1);
        result[i] = v;
        borrow = b as i64;
    }

    trim_leading_zeros(result) // 高位相消可能縮短
}

/// 計算負數的 bitCount，等於 `popcount(magnitude - 1)`。
///
/// `magnitude` 為 big-endian、非空（負數必非零）。減 1 從最低位（尾端）借位。
fn bit_count_negative(magnitude: &[u32]) -> u32 {
    let mut borrow = true; // 減 1：一開始就欠一個借位
    let mut count = 0;
    for &w in magnitude.iter().rev() {
        let v = if borrow {
            let (r, b) = w.overflowing_sub(1);
            borrow = b; // w == 0 時借位繼續往高位傳
            r
        } else {
            w
        };
        count += v.count_ones();
    }
    count
}

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
    fn bit_length_zero() {
        assert_eq!(BigInteger::from_u32(0).bit_length(), 0);
    }

    #[test]
    fn bit_length_positive() {
        assert_eq!(BigInteger::from_u32(1).bit_length(), 1); // 0b1
        assert_eq!(BigInteger::from_u32(5).bit_length(), 3); // 0b101
        assert_eq!(BigInteger::from_u32(8).bit_length(), 4); // 0b1000
        assert_eq!(BigInteger::from_u32(255).bit_length(), 8);
        assert_eq!(BigInteger::from_u32(256).bit_length(), 9);
    }

    #[test]
    fn bit_length_negative_non_power_of_two() {
        // 非 2 次方的負數，位元長度與正數相同
        assert_eq!(BigInteger::from_i32(-5).bit_length(), 3);
        assert_eq!(BigInteger::from_i32(-7).bit_length(), 3);
    }

    #[test]
    fn bit_length_negative_power_of_two_is_one_less() {
        // 負的 2 次方少 1 位：-8 為 3（+8 為 4）
        assert_eq!(BigInteger::from_i32(-8).bit_length(), 3);
        assert_eq!(BigInteger::from_i32(-1).bit_length(), 0); // -1 = -2^0
        assert_eq!(BigInteger::from_i32(-256).bit_length(), 8);
    }

    #[test]
    fn bit_length_multi_word() {
        // 2^32：magnitude [1, 0]，位元長度 33；負的則為 32
        assert_eq!(BigInteger::from_u64(1 << 32).bit_length(), 33);
        assert_eq!(BigInteger::from_i64(-(1 << 32)).bit_length(), 32);
        // u64::MAX 佔滿 64 位
        assert_eq!(BigInteger::from_u64(u64::MAX).bit_length(), 64);
    }

    #[test]
    fn bit_length_is_cached_and_stable() {
        // 多次呼叫結果一致（第一次計算後快取）
        let n = BigInteger::from_u32(5);
        assert_eq!(n.bit_length(), 3);
        assert_eq!(n.bit_length(), 3);
        assert!(n.bit_length.get().is_some()); // 快取已填入
    }

    #[test]
    fn bit_count_zero() {
        assert_eq!(BigInteger::from_u32(0).bit_count(), 0);
    }

    #[test]
    fn bit_count_positive() {
        assert_eq!(BigInteger::from_u32(0b101).bit_count(), 2);
        assert_eq!(BigInteger::from_u32(0b111).bit_count(), 3);
        assert_eq!(BigInteger::from_u32(0xFF).bit_count(), 8);
        assert_eq!(BigInteger::from_u32(u32::MAX).bit_count(), 32);
    }

    #[test]
    fn bit_count_positive_multi_word() {
        // u64::MAX 全為 1，共 64 個
        assert_eq!(BigInteger::from_u64(u64::MAX).bit_count(), 64);
    }

    #[test]
    fn bit_count_negative() {
        // 負數：popcount(|n| - 1)
        assert_eq!(BigInteger::from_i32(-1).bit_count(), 0); // |−1|−1 = 0
        assert_eq!(BigInteger::from_i32(-2).bit_count(), 1); // 1 = 0b1
        assert_eq!(BigInteger::from_i32(-8).bit_count(), 3); // 7 = 0b111
    }

    #[test]
    fn bit_count_negative_multi_word_borrow() {
        // -(2^32)：|n|-1 = 2^32-1 = 0xFFFF_FFFF，借位跨字，共 32 個 1
        assert_eq!(BigInteger::from_i64(-(1 << 32)).bit_count(), 32);
    }

    #[test]
    fn bit_count_is_cached() {
        let n = BigInteger::from_u32(0b101);
        assert_eq!(n.bit_count(), 2);
        assert_eq!(n.bit_count(), 2);
        assert!(n.bits.get().is_some());
    }

    #[test]
    fn cmp_same_sign_positive() {
        assert_eq!(BigInteger::from_i32(5).cmp(&BigInteger::from_i32(3)), Ordering::Greater);
        assert_eq!(BigInteger::from_i32(3).cmp(&BigInteger::from_i32(5)), Ordering::Less);
        assert_eq!(BigInteger::from_i32(5).cmp(&BigInteger::from_i32(5)), Ordering::Equal);
    }

    #[test]
    fn cmp_same_sign_negative_is_flipped() {
        // 同負號：絕對值大者反而小
        assert_eq!(BigInteger::from_i32(-5).cmp(&BigInteger::from_i32(-3)), Ordering::Less);
        assert_eq!(BigInteger::from_i32(-3).cmp(&BigInteger::from_i32(-5)), Ordering::Greater);
    }

    #[test]
    fn cmp_different_signs() {
        assert_eq!(BigInteger::from_i32(5).cmp(&BigInteger::from_i32(-8)), Ordering::Greater);
        assert_eq!(BigInteger::from_i32(-8).cmp(&BigInteger::from_i32(5)), Ordering::Less);
    }

    #[test]
    fn cmp_with_zero() {
        assert_eq!(BigInteger::from_i32(0).cmp(&BigInteger::from_i32(-3)), Ordering::Greater);
        assert_eq!(BigInteger::from_i32(0).cmp(&BigInteger::from_i32(5)), Ordering::Less);
        assert_eq!(BigInteger::from_i32(0).cmp(&BigInteger::from_i32(0)), Ordering::Equal);
    }

    #[test]
    fn cmp_by_word_count() {
        // 字數多者絕對值大（依賴無前導零不變量）
        let big = BigInteger::from_u64(1 << 32); // magnitude [1, 0]，2 字
        let small = BigInteger::from_u32(u32::MAX); // magnitude [0xFFFFFFFF]，1 字
        assert_eq!(big.cmp(&small), Ordering::Greater);
    }

    #[test]
    fn cmp_operators_and_min_max() {
        // 實作 Ord 後，運算子與 min/max/sort 自動可用
        let a = BigInteger::from_i32(-10);
        let b = BigInteger::from_i32(7);
        assert!(a < b);
        assert!(b >= a);
        assert_eq!(a.clone().min(b.clone()), a);
        assert_eq!(a.clone().max(b.clone()), b);

        let mut v = vec![
            BigInteger::from_i32(3),
            BigInteger::from_i32(-5),
            BigInteger::from_i32(0),
            BigInteger::from_i32(1),
        ];
        v.sort();
        // 排序後應為 -5, 0, 1, 3（由小到大）
        let expected = [-5, 0, 1, 3].map(BigInteger::from_i32);
        assert_eq!(v, expected);
    }

    #[test]
    fn neg_flips_sign_keeps_magnitude() {
        let n = -BigInteger::from_i32(5);
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude.to_vec(), vec![5]);

        let p = -BigInteger::from_i32(-5);
        assert_eq!(p.sign, 1);
        assert_eq!(p.magnitude.to_vec(), vec![5]);
    }

    #[test]
    fn neg_zero_is_zero() {
        let z = -BigInteger::from_i32(0);
        assert_eq!(z.sign, 0);
        assert!(z.magnitude.is_empty());
    }

    #[test]
    fn neg_is_involution() {
        // -(-a) == a
        let a = BigInteger::from_i64(-123456789);
        assert_eq!(-(-a.clone()), a);
    }

    #[test]
    fn neg_resets_cache() {
        // 對 8 先算好 bit_length（快取 4），取負後應重算為 3（負的 2 次方少 1）
        let a = BigInteger::from_i32(8);
        assert_eq!(a.bit_length(), 4);
        let b = -a; // a 的 magnitude buffer 搬進 b，快取重置
        assert_eq!(b.bit_length(), 3);
    }

    #[test]
    fn abs_of_negative_and_positive() {
        assert_eq!(BigInteger::from_i32(-5).abs(), BigInteger::from_i32(5));
        assert_eq!(BigInteger::from_i32(5).abs(), BigInteger::from_i32(5));
    }

    #[test]
    fn abs_zero_is_zero() {
        let z = BigInteger::from_i32(0).abs();
        assert_eq!(z.sign, 0);
        assert!(z.magnitude.is_empty());
    }

    #[test]
    fn abs_resets_cache_for_negative() {
        // -8 的 bit_length 為 3；取絕對值後為 8，應重算為 4
        let a = BigInteger::from_i32(-8);
        assert_eq!(a.bit_length(), 3);
        assert_eq!(a.abs().bit_length(), 4);
    }

    #[test]
    fn abs_is_idempotent() {
        let a = BigInteger::from_i64(-123456789);
        assert_eq!(a.clone().abs().abs(), a.abs());
    }

    #[test]
    fn add_magnitudes_simple() {
        assert_eq!(add_magnitudes(&[5], &[3]), vec![8]);
    }

    #[test]
    fn add_magnitudes_carry_grows_word() {
        // 0xFFFFFFFF + 1 = 0x1_0000_0000
        assert_eq!(add_magnitudes(&[u32::MAX], &[1]), vec![1, 0]);
    }

    #[test]
    fn add_magnitudes_carry_chain() {
        // (2^64 - 1) + 1 = 2^64
        assert_eq!(add_magnitudes(&[u32::MAX, u32::MAX], &[1]), vec![1, 0, 0]);
    }

    #[test]
    fn add_magnitudes_different_lengths() {
        // 2^32 + 5 = 0x1_0000_0005
        assert_eq!(add_magnitudes(&[1, 0], &[5]), vec![1, 5]);
    }

    #[test]
    fn add_magnitudes_with_empty_is_identity() {
        assert_eq!(add_magnitudes(&[5], &[]), vec![5]);
        assert_eq!(add_magnitudes(&[], &[5]), vec![5]);
        assert_eq!(add_magnitudes(&[], &[]), Vec::<u32>::new());
    }

    #[test]
    fn add_magnitudes_is_commutative() {
        let a = [0x1234_5678, 0x9ABC_DEF0];
        let b = [0xFFFF_FFFF];
        assert_eq!(add_magnitudes(&a, &b), add_magnitudes(&b, &a));
    }

    #[test]
    fn sub_magnitudes_simple() {
        assert_eq!(sub_magnitudes(&[8], &[3]), vec![5]);
    }

    #[test]
    fn sub_magnitudes_borrow_across_word() {
        // 2^32 - 1 = 0xFFFF_FFFF
        assert_eq!(sub_magnitudes(&[1, 0], &[1]), vec![u32::MAX]);
    }

    #[test]
    fn sub_magnitudes_borrow_chain() {
        // 2^64 - 1 = 0xFFFF_FFFF_FFFF_FFFF
        assert_eq!(sub_magnitudes(&[1, 0, 0], &[1]), vec![u32::MAX, u32::MAX]);
    }

    #[test]
    fn sub_magnitudes_equal_is_zero() {
        assert_eq!(sub_magnitudes(&[5], &[5]), Vec::<u32>::new());
    }

    #[test]
    fn sub_magnitudes_shrinks_result() {
        // (2^32 + 5) - (2^32 + 3) = 2；高位相消，結果縮成一字
        assert_eq!(sub_magnitudes(&[1, 5], &[1, 3]), vec![2]);
    }

    #[test]
    fn sub_magnitudes_with_empty_is_identity() {
        assert_eq!(sub_magnitudes(&[7], &[]), vec![7]);
    }

    #[test]
    fn sub_magnitudes_inverts_add() {
        // (a + b) - b == a
        let a = [0x1234_5678, 0x9ABC_DEF0];
        let b = [0xFEDC_BA98];
        let sum = add_magnitudes(&a, &b);
        assert_eq!(sub_magnitudes(&sum, &b), a.to_vec());
    }

    #[test]
    fn add_operator_same_sign() {
        assert_eq!(&BigInteger::from_i32(5) + &BigInteger::from_i32(3), BigInteger::from_i32(8));
        assert_eq!(&BigInteger::from_i32(-5) + &BigInteger::from_i32(-3), BigInteger::from_i32(-8));
    }

    #[test]
    fn add_operator_different_signs() {
        assert_eq!(&BigInteger::from_i32(5) + &BigInteger::from_i32(-3), BigInteger::from_i32(2));
        assert_eq!(&BigInteger::from_i32(-5) + &BigInteger::from_i32(3), BigInteger::from_i32(-2));
        assert_eq!(&BigInteger::from_i32(3) + &BigInteger::from_i32(-5), BigInteger::from_i32(-2));
        assert_eq!(&BigInteger::from_i32(5) + &BigInteger::from_i32(-5), BigInteger::from_i32(0));
    }

    #[test]
    fn add_operator_with_zero() {
        assert_eq!(&BigInteger::from_i32(0) + &BigInteger::from_i32(7), BigInteger::from_i32(7));
        assert_eq!(&BigInteger::from_i32(7) + &BigInteger::from_i32(0), BigInteger::from_i32(7));
    }

    #[test]
    fn sub_operator_basic() {
        assert_eq!(&BigInteger::from_i32(8) - &BigInteger::from_i32(3), BigInteger::from_i32(5));
        assert_eq!(&BigInteger::from_i32(3) - &BigInteger::from_i32(8), BigInteger::from_i32(-5));
        assert_eq!(&BigInteger::from_i32(5) - &BigInteger::from_i32(-3), BigInteger::from_i32(8));
        assert_eq!(&BigInteger::from_i32(-5) - &BigInteger::from_i32(3), BigInteger::from_i32(-8));
        assert_eq!(&BigInteger::from_i32(5) - &BigInteger::from_i32(5), BigInteger::from_i32(0));
    }

    #[test]
    fn add_matches_i128_reference() {
        // 用原生 i128 算和當獨立參照，涵蓋各種符號與大小組合
        let vals = [0i64, 1, -1, 5, -5, 255, -256, 1 << 32, -(1 << 32), i64::MAX, i64::MIN];
        for &a in &vals {
            for &b in &vals {
                let got = &BigInteger::from_i64(a) + &BigInteger::from_i64(b);
                let want = BigInteger::from_i128(a as i128 + b as i128);
                assert_eq!(got, want, "{a} + {b}");
            }
        }
    }

    #[test]
    fn sub_matches_i128_reference() {
        let vals = [0i64, 1, -1, 5, -5, 255, -256, 1 << 32, -(1 << 32), i64::MAX, i64::MIN];
        for &a in &vals {
            for &b in &vals {
                let got = &BigInteger::from_i64(a) - &BigInteger::from_i64(b);
                let want = BigInteger::from_i128(a as i128 - b as i128);
                assert_eq!(got, want, "{a} - {b}");
            }
        }
    }

    #[test]
    fn add_commutative_and_sub_relation() {
        let a = BigInteger::from_i64(123456789012);
        let b = BigInteger::from_i64(-98765432109);
        assert_eq!(&a + &b, &b + &a); // a + b == b + a
        assert_eq!(&a - &b, -(&b - &a)); // a - b == -(b - a)
    }

    #[test]
    fn add_multi_word_carry() {
        // (2^64 - 1) + 1 = 2^64
        let a = BigInteger::from_u64(u64::MAX);
        let one = BigInteger::from_u32(1);
        assert_eq!(&a + &one, BigInteger::from_i128(u64::MAX as i128 + 1));
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
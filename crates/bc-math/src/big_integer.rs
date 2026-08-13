#[derive(Clone, Debug)]
pub struct BigInteger {
    sign: i32,
    magnitude: Vec<u32>,
}

impl BigInteger {
    fn new(sign: i32, magnitude: Vec<u32>) -> Self {
        BigInteger {
            sign,
            magnitude,
            //bits: OnceLock::new(),
            //bit_length: OnceLock::new(),
        }
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
    fn from_u32_positive() {
        let n = BigInteger::from_u32(5);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude, vec![5]);
    }

    #[test]
    fn from_u32_max() {
        let n = BigInteger::from_u32(u32::MAX);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude, vec![u32::MAX]);
    }

    #[test]
    fn from_u16_zero_and_max() {
        let zero = BigInteger::from_u16(0);
        assert_eq!(zero.sign, 0);
        assert!(zero.magnitude.is_empty());

        let max = BigInteger::from_u16(u16::MAX);
        assert_eq!(max.sign, 1);
        assert_eq!(max.magnitude, vec![u32::from(u16::MAX)]);
    }

    #[test]
    fn from_u8_zero_and_max() {
        let zero = BigInteger::from_u8(0);
        assert_eq!(zero.sign, 0);
        assert!(zero.magnitude.is_empty());

        let max = BigInteger::from_u8(u8::MAX);
        assert_eq!(max.sign, 1);
        assert_eq!(max.magnitude, vec![u32::from(u8::MAX)]);
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
        assert_eq!(n.magnitude, vec![5]);
    }

    #[test]
    fn from_u64_two_words() {
        // 0x0000_0001_0000_0002 -> [1, 2] big-endian.
        let n = BigInteger::from_u64((1 << 32) | 2);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude, vec![1, 2]);
    }

    #[test]
    fn from_u64_max() {
        let n = BigInteger::from_u64(u64::MAX);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude, vec![u32::MAX, u32::MAX]);
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
        assert_eq!(n.magnitude, vec![5]);
    }

    #[test]
    fn from_i32_negative() {
        let n = BigInteger::from_i32(-5);
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude, vec![5]);
    }

    #[test]
    fn from_i32_min() {
        // -i32::MIN would overflow; magnitude is 2^31.
        let n = BigInteger::from_i32(i32::MIN);
        assert_eq!(n.sign, -1);
        assert_eq!(n.magnitude, vec![1 << 31]);
    }

    #[test]
    fn from_i32_max() {
        let n = BigInteger::from_i32(i32::MAX);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude, vec![i32::MAX as u32]);
    }

    #[test]
    fn from_i16_negative_and_min() {
        let neg = BigInteger::from_i16(-5);
        assert_eq!(neg.sign, -1);
        assert_eq!(neg.magnitude, vec![5]);

        let min = BigInteger::from_i16(i16::MIN);
        assert_eq!(min.sign, -1);
        assert_eq!(min.magnitude, vec![i16::MIN.unsigned_abs() as u32]);
    }

    #[test]
    fn from_i8_negative_and_min() {
        let neg = BigInteger::from_i8(-5);
        assert_eq!(neg.sign, -1);
        assert_eq!(neg.magnitude, vec![5]);

        let min = BigInteger::from_i8(i8::MIN);
        assert_eq!(min.sign, -1);
        assert_eq!(min.magnitude, vec![i8::MIN.unsigned_abs() as u32]);
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
        assert_eq!(n.magnitude, vec![5]);
    }

    #[test]
    fn from_u128_strips_leading_zero_words() {
        // 0x0000_0000_0000_0003_0000_0000_0000_0004
        // = word3<<96 | ... ; top two words are zero and must be dropped.
        let value = (3u128 << 64) | 4;
        let n = BigInteger::from_u128(value);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude, vec![3, 0, 4]);
    }

    #[test]
    fn from_u128_max() {
        let n = BigInteger::from_u128(u128::MAX);
        assert_eq!(n.sign, 1);
        assert_eq!(n.magnitude, vec![u32::MAX, u32::MAX, u32::MAX, u32::MAX]);
    }
}
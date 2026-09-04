//! Little-endian array conversion for [`BigInt`].

use alloc::vec::Vec;
use core::convert::Infallible;

use crate::{ArrayEncoding, BigInt, ConversionError, encoding};

impl BigInt {
    /// Decodes signed little-endian two's-complement bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint3::BigInt;
    ///
    /// assert_eq!(BigInt::from_le_bytes(&[0xfe]), BigInt::from(-2_i8));
    /// ```
    pub fn from_le_bytes(input: &[u8]) -> Self {
        Self::from_limbs(encoding::from_le_bytes(input, true))
    }

    /// Decodes signed little-endian two's-complement 32-bit words.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint3::BigInt;
    ///
    /// assert_eq!(BigInt::from_le_u32(&[u32::MAX - 1]), BigInt::from(-2_i8));
    /// ```
    pub fn from_le_u32(input: &[u32]) -> Self {
        Self::from_limbs(encoding::from_le_u32(input, true))
    }

    /// Decodes signed little-endian two's-complement 64-bit words.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint3::BigInt;
    ///
    /// assert_eq!(BigInt::from_le_u64(&[u64::MAX - 1]), BigInt::from(-2_i8));
    /// ```
    pub fn from_le_u64(input: &[u64]) -> Self {
        Self::from_limbs(encoding::from_le_u64(input, true))
    }

    /// Decodes signed big-endian two's-complement bytes.
    pub fn from_be_bytes(input: &[u8]) -> Self {
        Self::from_limbs(encoding::from_be_bytes(input, true))
    }

    /// Decodes signed big-endian two's-complement 32-bit words.
    pub fn from_be_u32(input: &[u32]) -> Self {
        Self::from_limbs(encoding::from_be_u32(input, true))
    }

    /// Decodes signed big-endian two's-complement 64-bit words.
    pub fn from_be_u64(input: &[u64]) -> Self {
        Self::from_limbs(encoding::from_be_u64(input, true))
    }

    /// Decodes an unsigned little-endian byte magnitude.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint3::BigInt;
    ///
    /// assert_eq!(BigInt::from_unsigned_le_bytes(&[0xfe]), BigInt::from(254_u16));
    /// ```
    pub fn from_unsigned_le_bytes(input: &[u8]) -> Self {
        Self::from_sign_magnitude(false, encoding::from_le_bytes(input, false))
    }

    /// Decodes an unsigned little-endian 32-bit magnitude.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint3::BigInt;
    ///
    /// assert_eq!(BigInt::from_unsigned_le_u32(&[u32::MAX]), BigInt::from(u32::MAX));
    /// ```
    pub fn from_unsigned_le_u32(input: &[u32]) -> Self {
        Self::from_sign_magnitude(false, encoding::from_le_u32(input, false))
    }

    /// Decodes an unsigned little-endian 64-bit magnitude.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint3::BigInt;
    ///
    /// assert_eq!(BigInt::from_unsigned_le_u64(&[u64::MAX]), BigInt::from(u64::MAX));
    /// ```
    pub fn from_unsigned_le_u64(input: &[u64]) -> Self {
        Self::from_sign_magnitude(false, encoding::from_le_u64(input, false))
    }

    /// Decodes an unsigned big-endian byte magnitude.
    pub fn from_unsigned_be_bytes(input: &[u8]) -> Self {
        Self::from_sign_magnitude(false, encoding::from_be_bytes(input, false))
    }

    /// Decodes an unsigned big-endian 32-bit magnitude.
    pub fn from_unsigned_be_u32(input: &[u32]) -> Self {
        Self::from_sign_magnitude(false, encoding::from_be_u32(input, false))
    }

    /// Decodes an unsigned big-endian 64-bit magnitude.
    pub fn from_unsigned_be_u64(input: &[u64]) -> Self {
        Self::from_sign_magnitude(false, encoding::from_be_u64(input, false))
    }

    /// Encodes canonical signed little-endian two's-complement bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint3::BigInt;
    ///
    /// assert_eq!(BigInt::from(-2_i8).to_le_bytes(), [0xfe]);
    /// ```
    pub fn to_le_bytes(&self) -> Vec<u8> {
        encoding::signed_to_le_bytes(&self.limbs)
    }

    /// Encodes canonical signed little-endian two's-complement 32-bit words.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint3::BigInt;
    ///
    /// assert_eq!(BigInt::from(-2_i8).to_le_u32(), [u32::MAX - 1]);
    /// ```
    pub fn to_le_u32(&self) -> Vec<u32> {
        encoding::signed_to_le_u32(&self.limbs)
    }

    /// Encodes canonical signed little-endian two's-complement 64-bit words.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint3::BigInt;
    ///
    /// assert_eq!(BigInt::from(-2_i8).to_le_u64(), [u64::MAX - 1]);
    /// ```
    pub fn to_le_u64(&self) -> Vec<u64> {
        encoding::signed_to_le_u64(&self.limbs)
    }

    /// Encodes canonical signed big-endian two's-complement bytes.
    pub fn to_be_bytes(&self) -> Vec<u8> {
        encoding::signed_to_be_bytes(&self.limbs)
    }

    /// Encodes canonical signed big-endian two's-complement 32-bit words.
    pub fn to_be_u32(&self) -> Vec<u32> {
        encoding::signed_to_be_u32(&self.limbs)
    }

    /// Encodes canonical signed big-endian two's-complement 64-bit words.
    pub fn to_be_u64(&self) -> Vec<u64> {
        encoding::signed_to_be_u64(&self.limbs)
    }

    /// Encodes the absolute value as canonical little-endian bytes.
    pub fn to_unsigned_le_bytes(&self) -> Vec<u8> {
        encoding::magnitude_to_le_bytes(&self.limbs)
    }

    /// Encodes the absolute value as canonical little-endian 32-bit words.
    pub fn to_unsigned_le_u32(&self) -> Vec<u32> {
        encoding::magnitude_to_le_u32(&self.limbs)
    }

    /// Encodes the absolute value as canonical little-endian 64-bit words.
    pub fn to_unsigned_le_u64(&self) -> Vec<u64> {
        encoding::magnitude_to_le_u64(&self.limbs)
    }

    /// Encodes the absolute value as canonical big-endian bytes.
    pub fn to_unsigned_be_bytes(&self) -> Vec<u8> {
        encoding::magnitude_to_be_bytes(&self.limbs)
    }

    /// Encodes the absolute value as canonical big-endian 32-bit words.
    pub fn to_unsigned_be_u32(&self) -> Vec<u32> {
        encoding::magnitude_to_be_u32(&self.limbs)
    }

    /// Encodes the absolute value as canonical big-endian 64-bit words.
    pub fn to_unsigned_be_u64(&self) -> Vec<u64> {
        encoding::magnitude_to_be_u64(&self.limbs)
    }

    /// Writes canonical signed little-endian bytes into `output`.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint3::BigInt;
    ///
    /// let mut output = [0_u8; 1];
    /// assert_eq!(BigInt::from(-2_i8).write_le_bytes(&mut output), Ok(1));
    /// assert_eq!(output, [0xfe]);
    /// ```
    pub fn write_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        encoding::write_signed_le_bytes(&self.limbs, output)
    }

    /// Writes canonical signed little-endian 32-bit words into `output`.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint3::BigInt;
    ///
    /// let mut output = [0_u32; 1];
    /// assert_eq!(BigInt::from(-2_i8).write_le_u32(&mut output), Ok(1));
    /// assert_eq!(output, [u32::MAX - 1]);
    /// ```
    pub fn write_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        encoding::write_signed_le_u32(&self.limbs, output)
    }

    /// Writes canonical signed little-endian 64-bit words into `output`.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint3::BigInt;
    ///
    /// let mut output = [0_u64; 1];
    /// assert_eq!(BigInt::from(-2_i8).write_le_u64(&mut output), Ok(1));
    /// assert_eq!(output, [u64::MAX - 1]);
    /// ```
    pub fn write_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        encoding::write_signed_le_u64(&self.limbs, output)
    }

    /// Writes canonical signed big-endian bytes into `output`.
    pub fn write_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        encoding::write_signed_be_bytes(&self.limbs, output)
    }

    /// Writes canonical signed big-endian 32-bit words into `output`.
    pub fn write_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        encoding::write_signed_be_u32(&self.limbs, output)
    }

    /// Writes canonical signed big-endian 64-bit words into `output`.
    pub fn write_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        encoding::write_signed_be_u64(&self.limbs, output)
    }

    /// Writes the absolute value as canonical little-endian bytes.
    pub fn write_unsigned_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        encoding::write_magnitude_le_bytes(&self.limbs, output)
    }

    /// Writes the absolute value as canonical little-endian 32-bit words.
    pub fn write_unsigned_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        encoding::write_magnitude_le_u32(&self.limbs, output)
    }

    /// Writes the absolute value as canonical little-endian 64-bit words.
    pub fn write_unsigned_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        encoding::write_magnitude_le_u64(&self.limbs, output)
    }

    /// Writes the absolute value as canonical big-endian bytes.
    pub fn write_unsigned_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        encoding::write_magnitude_be_bytes(&self.limbs, output)
    }

    /// Writes the absolute value as canonical big-endian 32-bit words.
    pub fn write_unsigned_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        encoding::write_magnitude_be_u32(&self.limbs, output)
    }

    /// Writes the absolute value as canonical big-endian 64-bit words.
    pub fn write_unsigned_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        encoding::write_magnitude_be_u64(&self.limbs, output)
    }

    /// Returns the canonical signed byte length.
    pub fn byte_length(&self) -> usize {
        encoding::signed_len(&self.limbs, 8)
    }

    /// Returns the canonical byte length of the absolute value.
    pub fn byte_length_unsigned(&self) -> usize {
        encoding::magnitude_len(&self.limbs, 8, true)
    }

    /// Returns the canonical signed 32-bit-word length.
    pub fn u32_length(&self) -> usize {
        encoding::signed_len(&self.limbs, 32)
    }

    /// Returns the canonical 32-bit-word length of the absolute value.
    pub fn u32_length_unsigned(&self) -> usize {
        encoding::magnitude_len(&self.limbs, 32, true)
    }

    /// Returns the canonical signed 64-bit-word length.
    pub fn u64_length(&self) -> usize {
        encoding::signed_len(&self.limbs, 64)
    }

    /// Returns the canonical 64-bit-word length of the absolute value.
    pub fn u64_length_unsigned(&self) -> usize {
        encoding::magnitude_len(&self.limbs, 64, true)
    }
}

impl ArrayEncoding for BigInt {
    type DecodeError = Infallible;

    fn from_le_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        Ok(BigInt::from_le_bytes(input))
    }

    fn from_le_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        Ok(BigInt::from_le_u32(input))
    }

    fn from_le_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        Ok(BigInt::from_le_u64(input))
    }

    fn from_be_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        Ok(BigInt::from_be_bytes(input))
    }

    fn from_be_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        Ok(BigInt::from_be_u32(input))
    }

    fn from_be_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        Ok(BigInt::from_be_u64(input))
    }

    fn from_unsigned_le_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        Ok(BigInt::from_unsigned_le_bytes(input))
    }

    fn from_unsigned_le_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        Ok(BigInt::from_unsigned_le_u32(input))
    }

    fn from_unsigned_le_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        Ok(BigInt::from_unsigned_le_u64(input))
    }

    fn from_unsigned_be_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        Ok(BigInt::from_unsigned_be_bytes(input))
    }

    fn from_unsigned_be_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        Ok(BigInt::from_unsigned_be_u32(input))
    }

    fn from_unsigned_be_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        Ok(BigInt::from_unsigned_be_u64(input))
    }

    fn write_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        BigInt::write_le_bytes(self, output)
    }

    fn write_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        BigInt::write_le_u32(self, output)
    }

    fn write_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        BigInt::write_le_u64(self, output)
    }

    fn write_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        BigInt::write_be_bytes(self, output)
    }

    fn write_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        BigInt::write_be_u32(self, output)
    }

    fn write_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        BigInt::write_be_u64(self, output)
    }

    fn write_unsigned_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        BigInt::write_unsigned_le_bytes(self, output)
    }

    fn write_unsigned_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        BigInt::write_unsigned_le_u32(self, output)
    }

    fn write_unsigned_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        BigInt::write_unsigned_le_u64(self, output)
    }

    fn write_unsigned_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        BigInt::write_unsigned_be_bytes(self, output)
    }

    fn write_unsigned_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        BigInt::write_unsigned_be_u32(self, output)
    }

    fn write_unsigned_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        BigInt::write_unsigned_be_u64(self, output)
    }

    fn byte_length(&self) -> usize {
        BigInt::byte_length(self)
    }

    fn byte_length_unsigned(&self) -> usize {
        BigInt::byte_length_unsigned(self)
    }

    fn u32_length(&self) -> usize {
        BigInt::u32_length(self)
    }

    fn u32_length_unsigned(&self) -> usize {
        BigInt::u32_length_unsigned(self)
    }

    fn u64_length(&self) -> usize {
        BigInt::u64_length(self)
    }

    fn u64_length_unsigned(&self) -> usize {
        BigInt::u64_length_unsigned(self)
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        BigInt::to_le_bytes(self)
    }

    fn to_le_u32(&self) -> Vec<u32> {
        BigInt::to_le_u32(self)
    }

    fn to_le_u64(&self) -> Vec<u64> {
        BigInt::to_le_u64(self)
    }

    fn to_be_bytes(&self) -> Vec<u8> {
        BigInt::to_be_bytes(self)
    }

    fn to_be_u32(&self) -> Vec<u32> {
        BigInt::to_be_u32(self)
    }

    fn to_be_u64(&self) -> Vec<u64> {
        BigInt::to_be_u64(self)
    }

    fn to_unsigned_le_bytes(&self) -> Vec<u8> {
        BigInt::to_unsigned_le_bytes(self)
    }

    fn to_unsigned_le_u32(&self) -> Vec<u32> {
        BigInt::to_unsigned_le_u32(self)
    }

    fn to_unsigned_le_u64(&self) -> Vec<u64> {
        BigInt::to_unsigned_le_u64(self)
    }

    fn to_unsigned_be_bytes(&self) -> Vec<u8> {
        BigInt::to_unsigned_be_bytes(self)
    }

    fn to_unsigned_be_u32(&self) -> Vec<u32> {
        BigInt::to_unsigned_be_u32(self)
    }

    fn to_unsigned_be_u64(&self) -> Vec<u64> {
        BigInt::to_unsigned_be_u64(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_big_endian_round_trips_and_preserves_sign_bytes() {
        let cases = [
            BigInt::from(-129_i16),
            BigInt::from(-128_i16),
            BigInt::from(-1_i8),
            BigInt::default(),
            BigInt::from(127_u8),
            BigInt::from(128_u16),
            BigInt::from(u64::MAX),
            BigInt::from(i128::MIN),
            BigInt::from(u128::MAX),
        ];

        for value in cases {
            let bytes = value.to_be_bytes();
            let words32 = value.to_be_u32();
            let words64 = value.to_be_u64();
            assert_eq!(BigInt::from_be_bytes(&bytes), value);
            assert_eq!(BigInt::from_be_u32(&words32), value);
            assert_eq!(BigInt::from_be_u64(&words64), value);
            assert_eq!(value.byte_length(), bytes.len());
            assert_eq!(value.u32_length(), words32.len());
            assert_eq!(value.u64_length(), words64.len());

            let mut written_bytes = bytes.clone();
            let mut written_u32 = words32.clone();
            let mut written_u64 = words64.clone();
            written_bytes.fill(0);
            written_u32.fill(0);
            written_u64.fill(0);
            assert_eq!(value.write_be_bytes(&mut written_bytes), Ok(bytes.len()));
            assert_eq!(value.write_be_u32(&mut written_u32), Ok(words32.len()));
            assert_eq!(value.write_be_u64(&mut written_u64), Ok(words64.len()));
            assert_eq!(written_bytes, bytes);
            assert_eq!(written_u32, words32);
            assert_eq!(written_u64, words64);
        }

        assert_eq!(BigInt::from(128_u16).to_be_bytes(), [0x00, 0x80]);
        assert_eq!(BigInt::from(-129_i16).to_be_bytes(), [0xff, 0x7f]);
    }

    #[test]
    fn unsigned_output_is_the_absolute_magnitude_without_a_sign_unit() {
        let value = BigInt::from(-0x1234_5678_9abc_def0_i64);
        let expected_bytes = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];

        assert_eq!(value.to_unsigned_be_bytes(), expected_bytes);
        assert_eq!(
            value.to_unsigned_le_bytes(),
            expected_bytes.into_iter().rev().collect::<Vec<_>>()
        );
        assert_eq!(value.to_unsigned_be_u32(), [0x1234_5678, 0x9abc_def0]);
        assert_eq!(value.to_unsigned_le_u32(), [0x9abc_def0, 0x1234_5678]);
        assert_eq!(value.to_unsigned_be_u64(), [0x1234_5678_9abc_def0]);
        assert_eq!(value.to_unsigned_le_u64(), [0x1234_5678_9abc_def0]);
        assert_eq!(BigInt::from_unsigned_be_bytes(&expected_bytes), value.abs());
        assert_eq!(
            BigInt::from_unsigned_be_u32(&[0x1234_5678, 0x9abc_def0]),
            value.abs()
        );
        assert_eq!(
            BigInt::from_unsigned_be_u64(&[0x1234_5678_9abc_def0]),
            value.abs()
        );

        let mut bytes = [0_u8; 8];
        let mut bytes_le = [0_u8; 8];
        let mut words32 = [0_u32; 2];
        let mut words32_le = [0_u32; 2];
        let mut words64 = [0_u64; 1];
        let mut words64_le = [0_u64; 1];
        assert_eq!(
            value.write_unsigned_be_bytes(&mut bytes),
            Ok(value.byte_length_unsigned())
        );
        assert_eq!(value.write_unsigned_le_bytes(&mut bytes_le), Ok(8));
        assert_eq!(value.write_unsigned_be_u32(&mut words32), Ok(2));
        assert_eq!(value.write_unsigned_le_u32(&mut words32_le), Ok(2));
        assert_eq!(value.write_unsigned_be_u64(&mut words64), Ok(1));
        assert_eq!(value.write_unsigned_le_u64(&mut words64_le), Ok(1));
        assert_eq!(bytes, expected_bytes);
        assert_eq!(bytes_le, value.to_unsigned_le_bytes().as_slice());
        assert_eq!(words32, [0x1234_5678, 0x9abc_def0]);
        assert_eq!(words32_le, [0x9abc_def0, 0x1234_5678]);
        assert_eq!(words64, [0x1234_5678_9abc_def0]);
        assert_eq!(words64_le, words64);
        assert_eq!(
            value.byte_length_unsigned(),
            value.to_unsigned_be_bytes().len()
        );
        assert_eq!(
            value.u32_length_unsigned(),
            value.to_unsigned_be_u32().len()
        );
        assert_eq!(
            value.u64_length_unsigned(),
            value.to_unsigned_be_u64().len()
        );

        let minimum = BigInt::from(i128::MIN);
        let minimum_magnitude = minimum.to_unsigned_be_bytes();
        assert_eq!(minimum_magnitude.len(), 16);
        assert_eq!(minimum_magnitude[0], 0x80);
        assert!(minimum_magnitude[1..].iter().all(|byte| *byte == 0));
        assert_eq!(BigInt::from_unsigned_be_bytes(&minimum_magnitude), -minimum);
    }

    #[test]
    fn array_trait_exposes_big_endian_and_magnitude_forms() {
        let value = BigInt::from(-129_i16);
        assert_eq!(ArrayEncoding::to_be_bytes(&value), [0xff, 0x7f]);
        assert_eq!(ArrayEncoding::to_unsigned_be_bytes(&value), [0x81]);
        assert_eq!(
            <BigInt as ArrayEncoding>::from_unsigned_be_bytes(&[0x81]),
            Ok(BigInt::from(129_u16))
        );
        assert_eq!(
            value.write_unsigned_be_bytes(&mut []),
            Err(ConversionError::BufferTooSmall)
        );
    }
}

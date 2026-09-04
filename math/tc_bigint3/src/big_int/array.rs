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
        write_output(&self.to_le_bytes(), output)
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
        write_output(&self.to_le_u32(), output)
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
        write_output(&self.to_le_u64(), output)
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

    fn from_unsigned_le_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        Ok(BigInt::from_unsigned_le_bytes(input))
    }

    fn from_unsigned_le_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        Ok(BigInt::from_unsigned_le_u32(input))
    }

    fn from_unsigned_le_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        Ok(BigInt::from_unsigned_le_u64(input))
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

    fn to_le_bytes(&self) -> Vec<u8> {
        BigInt::to_le_bytes(self)
    }

    fn to_le_u32(&self) -> Vec<u32> {
        BigInt::to_le_u32(self)
    }

    fn to_le_u64(&self) -> Vec<u64> {
        BigInt::to_le_u64(self)
    }
}

fn write_output<T: Copy>(values: &[T], output: &mut [T]) -> Result<usize, ConversionError> {
    if output.len() < values.len() {
        return Err(ConversionError::BufferTooSmall);
    }
    output[..values.len()].copy_from_slice(values);
    Ok(values.len())
}

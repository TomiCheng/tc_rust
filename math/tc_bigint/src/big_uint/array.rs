//! Little-endian array conversion for [`BigUint`].

use alloc::vec::Vec;
use core::convert::Infallible;

use crate::{ArrayEncoding, BigUint, ConversionError, encoding};

impl BigUint {
    /// Decodes an unsigned little-endian byte slice.
    pub fn from_le_bytes(input: &[u8]) -> Self {
        Self::from_limbs(encoding::from_le_bytes(input, false))
    }

    /// Decodes unsigned little-endian 32-bit words.
    pub fn from_le_u32(input: &[u32]) -> Self {
        Self::from_limbs(encoding::from_le_u32(input, false))
    }

    /// Decodes unsigned little-endian 64-bit words.
    pub fn from_le_u64(input: &[u64]) -> Self {
        Self::from_limbs(encoding::from_le_u64(input, false))
    }

    /// Decodes an unsigned big-endian byte slice.
    pub fn from_be_bytes(input: &[u8]) -> Self {
        Self::from_limbs(encoding::from_be_bytes(input, false))
    }

    /// Decodes unsigned big-endian 32-bit words.
    pub fn from_be_u32(input: &[u32]) -> Self {
        Self::from_limbs(encoding::from_be_u32(input, false))
    }

    /// Decodes unsigned big-endian 64-bit words.
    pub fn from_be_u64(input: &[u64]) -> Self {
        Self::from_limbs(encoding::from_be_u64(input, false))
    }

    /// Encodes the canonical unsigned value as little-endian bytes.
    pub fn to_le_bytes(&self) -> Vec<u8> {
        encoding::unsigned_to_le_bytes(&self.limbs)
    }

    /// Encodes the canonical unsigned value as little-endian 32-bit words.
    pub fn to_le_u32(&self) -> Vec<u32> {
        encoding::unsigned_to_le_u32(&self.limbs)
    }

    /// Encodes the canonical unsigned value as little-endian 64-bit words.
    pub fn to_le_u64(&self) -> Vec<u64> {
        encoding::unsigned_to_le_u64(&self.limbs)
    }

    /// Encodes the canonical unsigned value as big-endian bytes.
    pub fn to_be_bytes(&self) -> Vec<u8> {
        encoding::unsigned_to_be_bytes(&self.limbs)
    }

    /// Encodes the canonical unsigned value as big-endian 32-bit words.
    pub fn to_be_u32(&self) -> Vec<u32> {
        encoding::unsigned_to_be_u32(&self.limbs)
    }

    /// Encodes the canonical unsigned value as big-endian 64-bit words.
    pub fn to_be_u64(&self) -> Vec<u64> {
        encoding::unsigned_to_be_u64(&self.limbs)
    }

    /// Writes the canonical little-endian bytes into `output`.
    pub fn write_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        encoding::write_unsigned_le_bytes(&self.limbs, output)
    }

    /// Writes the canonical little-endian 32-bit words into `output`.
    pub fn write_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        encoding::write_unsigned_le_u32(&self.limbs, output)
    }

    /// Writes the canonical little-endian 64-bit words into `output`.
    pub fn write_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        encoding::write_unsigned_le_u64(&self.limbs, output)
    }

    /// Writes the canonical big-endian bytes into `output`.
    pub fn write_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        encoding::write_unsigned_be_bytes(&self.limbs, output)
    }

    /// Writes the canonical big-endian 32-bit words into `output`.
    pub fn write_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        encoding::write_unsigned_be_u32(&self.limbs, output)
    }

    /// Writes the canonical big-endian 64-bit words into `output`.
    pub fn write_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        encoding::write_unsigned_be_u64(&self.limbs, output)
    }

    /// Returns the canonical byte length.
    pub fn byte_length(&self) -> usize {
        encoding::unsigned_len(&self.limbs, 8)
    }

    /// Returns the canonical unsigned byte-magnitude length.
    pub fn byte_length_unsigned(&self) -> usize {
        self.byte_length()
    }

    /// Returns the canonical 32-bit-word length.
    pub fn u32_length(&self) -> usize {
        encoding::unsigned_len(&self.limbs, 32)
    }

    /// Returns the canonical unsigned 32-bit-word magnitude length.
    pub fn u32_length_unsigned(&self) -> usize {
        self.u32_length()
    }

    /// Returns the canonical 64-bit-word length.
    pub fn u64_length(&self) -> usize {
        encoding::unsigned_len(&self.limbs, 64)
    }

    /// Returns the canonical unsigned 64-bit-word magnitude length.
    pub fn u64_length_unsigned(&self) -> usize {
        self.u64_length()
    }
}

impl ArrayEncoding for BigUint {
    type DecodeError = Infallible;

    fn from_le_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        Ok(BigUint::from_le_bytes(input))
    }

    fn from_le_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        Ok(BigUint::from_le_u32(input))
    }

    fn from_le_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        Ok(BigUint::from_le_u64(input))
    }

    fn from_be_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        Ok(BigUint::from_be_bytes(input))
    }

    fn from_be_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        Ok(BigUint::from_be_u32(input))
    }

    fn from_be_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        Ok(BigUint::from_be_u64(input))
    }

    fn from_unsigned_le_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        Ok(BigUint::from_le_bytes(input))
    }

    fn from_unsigned_le_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        Ok(BigUint::from_le_u32(input))
    }

    fn from_unsigned_le_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        Ok(BigUint::from_le_u64(input))
    }

    fn from_unsigned_be_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        Ok(BigUint::from_be_bytes(input))
    }

    fn from_unsigned_be_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        Ok(BigUint::from_be_u32(input))
    }

    fn from_unsigned_be_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        Ok(BigUint::from_be_u64(input))
    }

    fn write_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        BigUint::write_le_bytes(self, output)
    }

    fn write_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        BigUint::write_le_u32(self, output)
    }

    fn write_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        BigUint::write_le_u64(self, output)
    }

    fn write_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        BigUint::write_be_bytes(self, output)
    }

    fn write_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        BigUint::write_be_u32(self, output)
    }

    fn write_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        BigUint::write_be_u64(self, output)
    }

    fn write_unsigned_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        BigUint::write_le_bytes(self, output)
    }

    fn write_unsigned_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        BigUint::write_le_u32(self, output)
    }

    fn write_unsigned_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        BigUint::write_le_u64(self, output)
    }

    fn write_unsigned_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        BigUint::write_be_bytes(self, output)
    }

    fn write_unsigned_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        BigUint::write_be_u32(self, output)
    }

    fn write_unsigned_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        BigUint::write_be_u64(self, output)
    }

    fn byte_length(&self) -> usize {
        BigUint::byte_length(self)
    }

    fn byte_length_unsigned(&self) -> usize {
        BigUint::byte_length_unsigned(self)
    }

    fn u32_length(&self) -> usize {
        BigUint::u32_length(self)
    }

    fn u32_length_unsigned(&self) -> usize {
        BigUint::u32_length_unsigned(self)
    }

    fn u64_length(&self) -> usize {
        BigUint::u64_length(self)
    }

    fn u64_length_unsigned(&self) -> usize {
        BigUint::u64_length_unsigned(self)
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        BigUint::to_le_bytes(self)
    }

    fn to_le_u32(&self) -> Vec<u32> {
        BigUint::to_le_u32(self)
    }

    fn to_le_u64(&self) -> Vec<u64> {
        BigUint::to_le_u64(self)
    }

    fn to_be_bytes(&self) -> Vec<u8> {
        BigUint::to_be_bytes(self)
    }

    fn to_be_u32(&self) -> Vec<u32> {
        BigUint::to_be_u32(self)
    }

    fn to_be_u64(&self) -> Vec<u64> {
        BigUint::to_be_u64(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_endian_and_unsigned_contracts_are_symmetric() {
        let value = BigUint::from_be_bytes(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert_eq!(
            value.to_be_bytes(),
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );
        assert_eq!(value.to_be_u32(), [0x1122_3344, 0x5566_7788]);
        assert_eq!(value.to_be_u64(), [0x1122_3344_5566_7788]);
        assert_eq!(BigUint::from_be_u32(&value.to_be_u32()), value);
        assert_eq!(BigUint::from_be_u64(&value.to_be_u64()), value);

        let mut bytes = [0_u8; 8];
        let mut words32 = [0_u32; 2];
        let mut words64 = [0_u64; 1];
        assert_eq!(value.write_be_bytes(&mut bytes), Ok(value.byte_length()));
        assert_eq!(value.write_be_u32(&mut words32), Ok(value.u32_length()));
        assert_eq!(value.write_be_u64(&mut words64), Ok(value.u64_length()));
        assert_eq!(bytes, value.to_be_bytes().as_slice());
        assert_eq!(words32, value.to_be_u32().as_slice());
        assert_eq!(words64, value.to_be_u64().as_slice());

        assert_eq!(
            ArrayEncoding::to_unsigned_be_bytes(&value),
            value.to_be_bytes()
        );
        assert_eq!(
            ArrayEncoding::to_unsigned_le_bytes(&value),
            value.to_le_bytes()
        );
        assert_eq!(ArrayEncoding::to_unsigned_be_u32(&value), value.to_be_u32());
        assert_eq!(ArrayEncoding::to_unsigned_le_u32(&value), value.to_le_u32());
        assert_eq!(ArrayEncoding::to_unsigned_be_u64(&value), value.to_be_u64());
        assert_eq!(ArrayEncoding::to_unsigned_le_u64(&value), value.to_le_u64());
        assert_eq!(
            <BigUint as ArrayEncoding>::from_unsigned_be_bytes(&bytes),
            Ok(value.clone())
        );
        assert_eq!(
            <BigUint as ArrayEncoding>::from_unsigned_be_u32(&words32),
            Ok(value.clone())
        );
        assert_eq!(
            <BigUint as ArrayEncoding>::from_unsigned_be_u64(&words64),
            Ok(value)
        );
    }

    #[test]
    fn lengths_are_exact_and_zero_uses_one_unit() {
        for value in [
            BigUint::default(),
            BigUint::from(0x80_u8),
            BigUint::from(u64::MAX),
        ] {
            assert_eq!(value.byte_length(), value.to_le_bytes().len());
            assert_eq!(value.byte_length(), value.to_be_bytes().len());
            assert_eq!(value.u32_length(), value.to_le_u32().len());
            assert_eq!(value.u64_length(), value.to_le_u64().len());
        }
        assert_eq!(BigUint::default().to_be_bytes(), [0]);
        assert_eq!(
            BigUint::from(0x100_u16).write_be_bytes(&mut [0_u8; 1]),
            Err(ConversionError::BufferTooSmall)
        );
    }
}

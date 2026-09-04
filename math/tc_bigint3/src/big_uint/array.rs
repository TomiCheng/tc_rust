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

    /// Writes the canonical little-endian bytes into `output`.
    pub fn write_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        write_output(&self.to_le_bytes(), output)
    }

    /// Writes the canonical little-endian 32-bit words into `output`.
    pub fn write_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        write_output(&self.to_le_u32(), output)
    }

    /// Writes the canonical little-endian 64-bit words into `output`.
    pub fn write_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        write_output(&self.to_le_u64(), output)
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

    fn from_unsigned_le_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        Ok(BigUint::from_le_bytes(input))
    }

    fn from_unsigned_le_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        Ok(BigUint::from_le_u32(input))
    }

    fn from_unsigned_le_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        Ok(BigUint::from_le_u64(input))
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

    fn to_le_bytes(&self) -> Vec<u8> {
        BigUint::to_le_bytes(self)
    }

    fn to_le_u32(&self) -> Vec<u32> {
        BigUint::to_le_u32(self)
    }

    fn to_le_u64(&self) -> Vec<u64> {
        BigUint::to_le_u64(self)
    }
}

fn write_output<T: Copy>(values: &[T], output: &mut [T]) -> Result<usize, ConversionError> {
    if output.len() < values.len() {
        return Err(ConversionError::BufferTooSmall);
    }
    output[..values.len()].copy_from_slice(values);
    Ok(values.len())
}

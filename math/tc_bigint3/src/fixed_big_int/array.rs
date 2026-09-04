//! Little-endian array conversion for [`FixedBigInt`].

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

#[cfg(feature = "alloc")]
use crate::Word;
use crate::{ArrayEncoding, ConversionError, FixedBigInt, encoding};

impl<const N: usize> FixedBigInt<N> {
    /// Decodes signed little-endian two's-complement bytes.
    pub fn from_le_bytes(input: &[u8]) -> Result<Self, ConversionError> {
        Ok(Self {
            limbs: encoding::fixed_from_le_bytes(input, true)?,
        })
    }

    /// Decodes signed little-endian two's-complement 32-bit words.
    pub fn from_le_u32(input: &[u32]) -> Result<Self, ConversionError> {
        Ok(Self {
            limbs: encoding::fixed_from_le_u32(input, true)?,
        })
    }

    /// Decodes signed little-endian two's-complement 64-bit words.
    pub fn from_le_u64(input: &[u64]) -> Result<Self, ConversionError> {
        Ok(Self {
            limbs: encoding::fixed_from_le_u64(input, true)?,
        })
    }

    /// Decodes an unsigned little-endian byte magnitude.
    pub fn from_unsigned_le_bytes(input: &[u8]) -> Result<Self, ConversionError> {
        let magnitude = encoding::fixed_from_le_bytes(input, false)?;
        Self::from_sign_magnitude(false, magnitude).ok_or(ConversionError::InputTooLarge)
    }

    /// Decodes an unsigned little-endian 32-bit magnitude.
    pub fn from_unsigned_le_u32(input: &[u32]) -> Result<Self, ConversionError> {
        let magnitude = encoding::fixed_from_le_u32(input, false)?;
        Self::from_sign_magnitude(false, magnitude).ok_or(ConversionError::InputTooLarge)
    }

    /// Decodes an unsigned little-endian 64-bit magnitude.
    pub fn from_unsigned_le_u64(input: &[u64]) -> Result<Self, ConversionError> {
        let magnitude = encoding::fixed_from_le_u64(input, false)?;
        Self::from_sign_magnitude(false, magnitude).ok_or(ConversionError::InputTooLarge)
    }

    /// Writes the full fixed width as signed little-endian bytes.
    pub fn write_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        encoding::write_fixed_le_bytes(&self.limbs, true, output)
    }

    /// Writes the full fixed width as signed little-endian 32-bit words.
    pub fn write_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        encoding::write_fixed_le_u32(&self.limbs, true, output)
    }

    /// Writes the full fixed width as signed little-endian 64-bit words.
    pub fn write_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        encoding::write_fixed_le_u64(&self.limbs, true, output)
    }
}

impl<const N: usize> ArrayEncoding for FixedBigInt<N> {
    type DecodeError = ConversionError;

    fn from_le_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        FixedBigInt::from_le_bytes(input)
    }

    fn from_le_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        FixedBigInt::from_le_u32(input)
    }

    fn from_le_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        FixedBigInt::from_le_u64(input)
    }

    fn from_unsigned_le_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        FixedBigInt::from_unsigned_le_bytes(input)
    }

    fn from_unsigned_le_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        FixedBigInt::from_unsigned_le_u32(input)
    }

    fn from_unsigned_le_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        FixedBigInt::from_unsigned_le_u64(input)
    }

    fn write_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        FixedBigInt::write_le_bytes(self, output)
    }

    fn write_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        FixedBigInt::write_le_u32(self, output)
    }

    fn write_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        FixedBigInt::write_le_u64(self, output)
    }

    #[cfg(feature = "alloc")]
    fn to_le_bytes(&self) -> Vec<u8> {
        let mut output = vec![0; N * Word::BITS as usize / 8];
        FixedBigInt::write_le_bytes(self, &mut output).expect("output has the fixed byte width");
        output
    }

    #[cfg(feature = "alloc")]
    fn to_le_u32(&self) -> Vec<u32> {
        let mut output = vec![0; (N * Word::BITS as usize).div_ceil(32)];
        FixedBigInt::write_le_u32(self, &mut output)
            .expect("output has the fixed 32-bit-word width");
        output
    }

    #[cfg(feature = "alloc")]
    fn to_le_u64(&self) -> Vec<u64> {
        let mut output = vec![0; (N * Word::BITS as usize).div_ceil(64)];
        FixedBigInt::write_le_u64(self, &mut output)
            .expect("output has the fixed 64-bit-word width");
        output
    }
}

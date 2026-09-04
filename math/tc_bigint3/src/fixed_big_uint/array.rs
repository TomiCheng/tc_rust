//! Array conversion for [`FixedBigUint`].

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

use crate::Word;
use crate::{ArrayEncoding, ConversionError, FixedBigUint, encoding};

impl<const N: usize> FixedBigUint<N> {
    /// Decodes unsigned little-endian bytes.
    pub fn from_le_bytes(input: &[u8]) -> Result<Self, ConversionError> {
        Ok(Self {
            limbs: encoding::fixed_from_le_bytes(input, false)?,
        })
    }

    /// Decodes unsigned little-endian 32-bit words.
    pub fn from_le_u32(input: &[u32]) -> Result<Self, ConversionError> {
        Ok(Self {
            limbs: encoding::fixed_from_le_u32(input, false)?,
        })
    }

    /// Decodes unsigned little-endian 64-bit words.
    pub fn from_le_u64(input: &[u64]) -> Result<Self, ConversionError> {
        Ok(Self {
            limbs: encoding::fixed_from_le_u64(input, false)?,
        })
    }

    /// Decodes unsigned big-endian bytes.
    pub fn from_be_bytes(input: &[u8]) -> Result<Self, ConversionError> {
        Ok(Self {
            limbs: encoding::fixed_from_be_bytes(input, false)?,
        })
    }

    /// Decodes unsigned big-endian 32-bit words.
    pub fn from_be_u32(input: &[u32]) -> Result<Self, ConversionError> {
        Ok(Self {
            limbs: encoding::fixed_from_be_u32(input, false)?,
        })
    }

    /// Decodes unsigned big-endian 64-bit words.
    pub fn from_be_u64(input: &[u64]) -> Result<Self, ConversionError> {
        Ok(Self {
            limbs: encoding::fixed_from_be_u64(input, false)?,
        })
    }

    /// Writes the full fixed width as little-endian bytes.
    pub fn write_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        encoding::write_fixed_le_bytes(&self.limbs, false, output)
    }

    /// Writes the full fixed width as little-endian 32-bit words.
    pub fn write_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        encoding::write_fixed_le_u32(&self.limbs, false, output)
    }

    /// Writes the full fixed width as little-endian 64-bit words.
    pub fn write_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        encoding::write_fixed_le_u64(&self.limbs, false, output)
    }

    /// Writes the full fixed width as big-endian bytes.
    pub fn write_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        encoding::write_fixed_be_bytes(&self.limbs, false, output)
    }

    /// Writes the full fixed width as big-endian 32-bit words.
    pub fn write_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        encoding::write_fixed_be_u32(&self.limbs, false, output)
    }

    /// Writes the full fixed width as big-endian 64-bit words.
    pub fn write_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        encoding::write_fixed_be_u64(&self.limbs, false, output)
    }

    /// Writes the shortest little-endian magnitude as bytes.
    pub fn write_unsigned_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        encoding::write_fixed_magnitude_le_bytes(&self.limbs, false, output)
    }

    /// Writes the shortest little-endian magnitude as 32-bit words.
    pub fn write_unsigned_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        encoding::write_fixed_magnitude_le_u32(&self.limbs, false, output)
    }

    /// Writes the shortest little-endian magnitude as 64-bit words.
    pub fn write_unsigned_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        encoding::write_fixed_magnitude_le_u64(&self.limbs, false, output)
    }

    /// Writes the shortest big-endian magnitude as bytes.
    pub fn write_unsigned_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        encoding::write_fixed_magnitude_be_bytes(&self.limbs, false, output)
    }

    /// Writes the shortest big-endian magnitude as 32-bit words.
    pub fn write_unsigned_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        encoding::write_fixed_magnitude_be_u32(&self.limbs, false, output)
    }

    /// Writes the shortest big-endian magnitude as 64-bit words.
    pub fn write_unsigned_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        encoding::write_fixed_magnitude_be_u64(&self.limbs, false, output)
    }

    /// Returns the full fixed byte width.
    pub const fn byte_length(&self) -> usize {
        N * Word::BITS as usize / 8
    }

    /// Returns the shortest unsigned byte-magnitude length.
    pub fn byte_length_unsigned(&self) -> usize {
        encoding::magnitude_len(&self.limbs, 8, false)
    }

    /// Returns the full fixed width in 32-bit words.
    pub const fn u32_length(&self) -> usize {
        (N * Word::BITS as usize).div_ceil(32)
    }

    /// Returns the shortest unsigned 32-bit-word magnitude length.
    pub fn u32_length_unsigned(&self) -> usize {
        encoding::magnitude_len(&self.limbs, 32, false)
    }

    /// Returns the full fixed width in 64-bit words.
    pub const fn u64_length(&self) -> usize {
        (N * Word::BITS as usize).div_ceil(64)
    }

    /// Returns the shortest unsigned 64-bit-word magnitude length.
    pub fn u64_length_unsigned(&self) -> usize {
        encoding::magnitude_len(&self.limbs, 64, false)
    }
}

impl<const N: usize> ArrayEncoding for FixedBigUint<N> {
    type DecodeError = ConversionError;

    fn from_le_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        FixedBigUint::from_le_bytes(input)
    }

    fn from_le_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        FixedBigUint::from_le_u32(input)
    }

    fn from_le_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        FixedBigUint::from_le_u64(input)
    }

    fn from_be_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        FixedBigUint::from_be_bytes(input)
    }

    fn from_be_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        FixedBigUint::from_be_u32(input)
    }

    fn from_be_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        FixedBigUint::from_be_u64(input)
    }

    fn from_unsigned_le_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        FixedBigUint::from_le_bytes(input)
    }

    fn from_unsigned_le_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        FixedBigUint::from_le_u32(input)
    }

    fn from_unsigned_le_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        FixedBigUint::from_le_u64(input)
    }

    fn from_unsigned_be_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        FixedBigUint::from_be_bytes(input)
    }

    fn from_unsigned_be_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        FixedBigUint::from_be_u32(input)
    }

    fn from_unsigned_be_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        FixedBigUint::from_be_u64(input)
    }

    fn write_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        FixedBigUint::write_le_bytes(self, output)
    }

    fn write_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        FixedBigUint::write_le_u32(self, output)
    }

    fn write_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        FixedBigUint::write_le_u64(self, output)
    }

    fn write_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        FixedBigUint::write_be_bytes(self, output)
    }

    fn write_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        FixedBigUint::write_be_u32(self, output)
    }

    fn write_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        FixedBigUint::write_be_u64(self, output)
    }

    fn write_unsigned_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        FixedBigUint::write_unsigned_le_bytes(self, output)
    }

    fn write_unsigned_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        FixedBigUint::write_unsigned_le_u32(self, output)
    }

    fn write_unsigned_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        FixedBigUint::write_unsigned_le_u64(self, output)
    }

    fn write_unsigned_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        FixedBigUint::write_unsigned_be_bytes(self, output)
    }

    fn write_unsigned_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        FixedBigUint::write_unsigned_be_u32(self, output)
    }

    fn write_unsigned_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        FixedBigUint::write_unsigned_be_u64(self, output)
    }

    fn byte_length(&self) -> usize {
        FixedBigUint::byte_length(self)
    }

    fn byte_length_unsigned(&self) -> usize {
        FixedBigUint::byte_length_unsigned(self)
    }

    fn u32_length(&self) -> usize {
        FixedBigUint::u32_length(self)
    }

    fn u32_length_unsigned(&self) -> usize {
        FixedBigUint::u32_length_unsigned(self)
    }

    fn u64_length(&self) -> usize {
        FixedBigUint::u64_length(self)
    }

    fn u64_length_unsigned(&self) -> usize {
        FixedBigUint::u64_length_unsigned(self)
    }

    #[cfg(feature = "alloc")]
    fn to_le_bytes(&self) -> Vec<u8> {
        let mut output = vec![0; N * Word::BITS as usize / 8];
        FixedBigUint::write_le_bytes(self, &mut output).expect("output has the fixed byte width");
        output
    }

    #[cfg(feature = "alloc")]
    fn to_le_u32(&self) -> Vec<u32> {
        let mut output = vec![0; (N * Word::BITS as usize).div_ceil(32)];
        FixedBigUint::write_le_u32(self, &mut output)
            .expect("output has the fixed 32-bit-word width");
        output
    }

    #[cfg(feature = "alloc")]
    fn to_le_u64(&self) -> Vec<u64> {
        let mut output = vec![0; (N * Word::BITS as usize).div_ceil(64)];
        FixedBigUint::write_le_u64(self, &mut output)
            .expect("output has the fixed 64-bit-word width");
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type U = FixedBigUint<2>;

    #[test]
    fn fixed_big_endian_io_uses_the_full_width_without_alloc() {
        let value = U::from_be_bytes(&[0x12, 0x34, 0x56, 0x78]).unwrap();
        let mut bytes = [0_u8; 2 * Word::BITS as usize / 8];
        let mut words32 = [0_u32; 2 * Word::BITS as usize / 32];
        let mut words64 = [0_u64; (2 * Word::BITS as usize).div_ceil(64)];

        assert_eq!(value.write_be_bytes(&mut bytes), Ok(value.byte_length()));
        assert_eq!(value.write_be_u32(&mut words32), Ok(value.u32_length()));
        assert_eq!(value.write_be_u64(&mut words64), Ok(value.u64_length()));
        assert_eq!(&bytes[bytes.len() - 4..], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(U::from_be_bytes(&bytes), Ok(value));
        assert_eq!(U::from_be_u32(&words32), Ok(value));
        assert_eq!(U::from_be_u64(&words64), Ok(value));
        assert_eq!(
            <U as ArrayEncoding>::from_unsigned_be_u32(&words32),
            Ok(value)
        );
        assert_eq!(
            <U as ArrayEncoding>::from_unsigned_be_u64(&words64),
            Ok(value)
        );
    }

    #[test]
    fn fixed_unsigned_writers_are_canonical_and_lengths_are_exact() {
        let value = U::from(0x1234_u16);
        let mut be = [0_u8; 2];
        let mut le = [0_u8; 2];

        assert_eq!(value.write_unsigned_be_bytes(&mut be), Ok(2));
        assert_eq!(value.write_unsigned_le_bytes(&mut le), Ok(2));
        assert_eq!(value.write_unsigned_be_u32(&mut [0_u32; 1]), Ok(1));
        assert_eq!(value.write_unsigned_le_u32(&mut [0_u32; 1]), Ok(1));
        assert_eq!(value.write_unsigned_be_u64(&mut [0_u64; 1]), Ok(1));
        assert_eq!(value.write_unsigned_le_u64(&mut [0_u64; 1]), Ok(1));
        assert_eq!(be, [0x12, 0x34]);
        assert_eq!(le, [0x34, 0x12]);
        assert_eq!(value.byte_length_unsigned(), 2);
        assert_eq!(value.u32_length_unsigned(), 1);
        assert_eq!(value.u64_length_unsigned(), 1);
        assert_eq!(U::zero().byte_length_unsigned(), 1);
        assert_eq!(
            value.write_unsigned_be_bytes(&mut [0_u8; 1]),
            Err(ConversionError::BufferTooSmall)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn trait_allocates_exact_fixed_and_canonical_magnitude_outputs() {
        let value = U::from(0x1234_u16);
        assert_eq!(
            ArrayEncoding::to_be_bytes(&value).len(),
            value.byte_length()
        );
        assert_eq!(ArrayEncoding::to_be_u32(&value).len(), value.u32_length());
        assert_eq!(ArrayEncoding::to_be_u64(&value).len(), value.u64_length());
        assert_eq!(ArrayEncoding::to_unsigned_be_bytes(&value), [0x12, 0x34]);
    }
}

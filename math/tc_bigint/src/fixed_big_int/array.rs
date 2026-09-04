//! Array conversion for [`FixedBigInt`].

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

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

    /// Decodes signed big-endian two's-complement bytes.
    pub fn from_be_bytes(input: &[u8]) -> Result<Self, ConversionError> {
        Ok(Self {
            limbs: encoding::fixed_from_be_bytes(input, true)?,
        })
    }

    /// Decodes signed big-endian two's-complement 32-bit words.
    pub fn from_be_u32(input: &[u32]) -> Result<Self, ConversionError> {
        Ok(Self {
            limbs: encoding::fixed_from_be_u32(input, true)?,
        })
    }

    /// Decodes signed big-endian two's-complement 64-bit words.
    pub fn from_be_u64(input: &[u64]) -> Result<Self, ConversionError> {
        Ok(Self {
            limbs: encoding::fixed_from_be_u64(input, true)?,
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

    /// Decodes an unsigned big-endian byte magnitude.
    pub fn from_unsigned_be_bytes(input: &[u8]) -> Result<Self, ConversionError> {
        let magnitude = encoding::fixed_from_be_bytes(input, false)?;
        Self::from_sign_magnitude(false, magnitude).ok_or(ConversionError::InputTooLarge)
    }

    /// Decodes an unsigned big-endian 32-bit magnitude.
    pub fn from_unsigned_be_u32(input: &[u32]) -> Result<Self, ConversionError> {
        let magnitude = encoding::fixed_from_be_u32(input, false)?;
        Self::from_sign_magnitude(false, magnitude).ok_or(ConversionError::InputTooLarge)
    }

    /// Decodes an unsigned big-endian 64-bit magnitude.
    pub fn from_unsigned_be_u64(input: &[u64]) -> Result<Self, ConversionError> {
        let magnitude = encoding::fixed_from_be_u64(input, false)?;
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

    /// Writes the full fixed width as signed big-endian bytes.
    pub fn write_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        encoding::write_fixed_be_bytes(&self.limbs, true, output)
    }

    /// Writes the full fixed width as signed big-endian 32-bit words.
    pub fn write_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        encoding::write_fixed_be_u32(&self.limbs, true, output)
    }

    /// Writes the full fixed width as signed big-endian 64-bit words.
    pub fn write_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        encoding::write_fixed_be_u64(&self.limbs, true, output)
    }

    /// Writes the shortest little-endian absolute magnitude as bytes.
    pub fn write_unsigned_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        encoding::write_fixed_magnitude_le_bytes(&self.limbs, true, output)
    }

    /// Writes the shortest little-endian absolute magnitude as 32-bit words.
    pub fn write_unsigned_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        encoding::write_fixed_magnitude_le_u32(&self.limbs, true, output)
    }

    /// Writes the shortest little-endian absolute magnitude as 64-bit words.
    pub fn write_unsigned_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        encoding::write_fixed_magnitude_le_u64(&self.limbs, true, output)
    }

    /// Writes the shortest big-endian absolute magnitude as bytes.
    pub fn write_unsigned_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        encoding::write_fixed_magnitude_be_bytes(&self.limbs, true, output)
    }

    /// Writes the shortest big-endian absolute magnitude as 32-bit words.
    pub fn write_unsigned_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        encoding::write_fixed_magnitude_be_u32(&self.limbs, true, output)
    }

    /// Writes the shortest big-endian absolute magnitude as 64-bit words.
    pub fn write_unsigned_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        encoding::write_fixed_magnitude_be_u64(&self.limbs, true, output)
    }

    /// Returns the full fixed byte width.
    pub const fn byte_length(&self) -> usize {
        N * Word::BITS as usize / 8
    }

    /// Returns the shortest byte length of the absolute value.
    pub fn byte_length_unsigned(&self) -> usize {
        encoding::magnitude_len(&self.limbs, 8, true)
    }

    /// Returns the full fixed width in 32-bit words.
    pub const fn u32_length(&self) -> usize {
        (N * Word::BITS as usize).div_ceil(32)
    }

    /// Returns the shortest 32-bit-word length of the absolute value.
    pub fn u32_length_unsigned(&self) -> usize {
        encoding::magnitude_len(&self.limbs, 32, true)
    }

    /// Returns the full fixed width in 64-bit words.
    pub const fn u64_length(&self) -> usize {
        (N * Word::BITS as usize).div_ceil(64)
    }

    /// Returns the shortest 64-bit-word length of the absolute value.
    pub fn u64_length_unsigned(&self) -> usize {
        encoding::magnitude_len(&self.limbs, 64, true)
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

    fn from_be_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        FixedBigInt::from_be_bytes(input)
    }

    fn from_be_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        FixedBigInt::from_be_u32(input)
    }

    fn from_be_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        FixedBigInt::from_be_u64(input)
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

    fn from_unsigned_be_bytes(input: &[u8]) -> Result<Self, Self::DecodeError> {
        FixedBigInt::from_unsigned_be_bytes(input)
    }

    fn from_unsigned_be_u32(input: &[u32]) -> Result<Self, Self::DecodeError> {
        FixedBigInt::from_unsigned_be_u32(input)
    }

    fn from_unsigned_be_u64(input: &[u64]) -> Result<Self, Self::DecodeError> {
        FixedBigInt::from_unsigned_be_u64(input)
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

    fn write_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        FixedBigInt::write_be_bytes(self, output)
    }

    fn write_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        FixedBigInt::write_be_u32(self, output)
    }

    fn write_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        FixedBigInt::write_be_u64(self, output)
    }

    fn write_unsigned_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        FixedBigInt::write_unsigned_le_bytes(self, output)
    }

    fn write_unsigned_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        FixedBigInt::write_unsigned_le_u32(self, output)
    }

    fn write_unsigned_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        FixedBigInt::write_unsigned_le_u64(self, output)
    }

    fn write_unsigned_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError> {
        FixedBigInt::write_unsigned_be_bytes(self, output)
    }

    fn write_unsigned_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError> {
        FixedBigInt::write_unsigned_be_u32(self, output)
    }

    fn write_unsigned_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError> {
        FixedBigInt::write_unsigned_be_u64(self, output)
    }

    fn byte_length(&self) -> usize {
        FixedBigInt::byte_length(self)
    }

    fn byte_length_unsigned(&self) -> usize {
        FixedBigInt::byte_length_unsigned(self)
    }

    fn u32_length(&self) -> usize {
        FixedBigInt::u32_length(self)
    }

    fn u32_length_unsigned(&self) -> usize {
        FixedBigInt::u32_length_unsigned(self)
    }

    fn u64_length(&self) -> usize {
        FixedBigInt::u64_length(self)
    }

    fn u64_length_unsigned(&self) -> usize {
        FixedBigInt::u64_length_unsigned(self)
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

#[cfg(test)]
mod tests {
    use super::*;

    type I = FixedBigInt<2>;

    #[test]
    fn fixed_signed_big_endian_io_sign_extends_to_the_full_width() {
        let value = I::from(-129_i16);
        let mut bytes = [0_u8; 2 * Word::BITS as usize / 8];
        let mut words32 = [0_u32; 2 * Word::BITS as usize / 32];
        let mut words64 = [0_u64; (2 * Word::BITS as usize).div_ceil(64)];

        assert_eq!(value.write_be_bytes(&mut bytes), Ok(value.byte_length()));
        assert_eq!(value.write_be_u32(&mut words32), Ok(value.u32_length()));
        assert_eq!(value.write_be_u64(&mut words64), Ok(value.u64_length()));
        assert!(bytes[..bytes.len() - 1].iter().all(|byte| *byte == 0xff));
        assert_eq!(bytes[bytes.len() - 1], 0x7f);
        assert_eq!(I::from_be_bytes(&bytes), Ok(value));
        assert_eq!(I::from_be_u32(&words32), Ok(value));
        assert_eq!(I::from_be_u64(&words64), Ok(value));
    }

    #[test]
    fn fixed_signed_unsigned_output_uses_the_absolute_magnitude() {
        let value = I::from(-0x1234_i16);
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
        assert_eq!(I::from_unsigned_be_bytes(&be), Ok(I::from(0x1234_i16)));
        assert_eq!(I::from_unsigned_be_u32(&[0x1234]), Ok(I::from(0x1234_i16)));
        assert_eq!(I::from_unsigned_be_u64(&[0x1234]), Ok(I::from(0x1234_i16)));
        assert_eq!(value.sign(), -1);

        let minimum = I::MIN;
        let mut minimum_magnitude = [0_u8; 2 * Word::BITS as usize / 8];
        assert_eq!(
            minimum.write_unsigned_be_bytes(&mut minimum_magnitude),
            Ok(minimum_magnitude.len())
        );
        assert_eq!(minimum_magnitude[0], 0x80);
        assert!(minimum_magnitude[1..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn fixed_signed_unsigned_decode_rejects_the_sign_bit_as_magnitude_overflow() {
        let input = [0x80_u8; 2 * Word::BITS as usize / 8];
        assert_eq!(
            I::from_unsigned_be_bytes(&input),
            Err(ConversionError::InputTooLarge)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn trait_allocates_exact_fixed_and_canonical_magnitude_outputs() {
        let value = I::from(-0x1234_i16);
        assert_eq!(
            ArrayEncoding::to_be_bytes(&value).len(),
            value.byte_length()
        );
        assert_eq!(ArrayEncoding::to_be_u32(&value).len(), value.u32_length());
        assert_eq!(ArrayEncoding::to_be_u64(&value).len(), value.u64_length());
        assert_eq!(ArrayEncoding::to_unsigned_be_bytes(&value), [0x12, 0x34]);
    }
}

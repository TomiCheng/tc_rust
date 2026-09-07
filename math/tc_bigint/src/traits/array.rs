//! Array conversion contracts.

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

/// Conversion between integers and byte or word slices.
///
/// Signed implementations decode `from_le_*` and `from_be_*` inputs as two's
/// complement. `from_unsigned_*` always decodes a non-negative magnitude.
/// Fixed-width implementations report inputs which do not fit through
/// [`Self::DecodeError`]. Their regular writers retain the full fixed width;
/// explicit unsigned writers emit the shortest magnitude.
///
/// # Examples
///
/// ```
/// use tc_bigint::{ArrayEncoding, U128};
///
/// let value = <U128 as ArrayEncoding>::from_unsigned_le_bytes(&[42]).unwrap();
/// let mut output = [0_u8; 16];
/// assert_eq!(value.write_le_bytes(&mut output), Ok(16));
/// assert_eq!(output[0], 42);
/// ```
pub trait ArrayEncoding: Sized {
    /// Error returned when an input cannot be represented by `Self`.
    type DecodeError;

    /// Decodes little-endian bytes using this integer type's signedness.
    fn from_le_bytes(input: &[u8]) -> Result<Self, Self::DecodeError>;

    /// Decodes little-endian 32-bit words using this integer type's signedness.
    fn from_le_u32(input: &[u32]) -> Result<Self, Self::DecodeError>;

    /// Decodes little-endian 64-bit words using this integer type's signedness.
    fn from_le_u64(input: &[u64]) -> Result<Self, Self::DecodeError>;

    /// Decodes big-endian bytes using this integer type's signedness.
    fn from_be_bytes(input: &[u8]) -> Result<Self, Self::DecodeError>;

    /// Decodes big-endian 32-bit words using this integer type's signedness.
    fn from_be_u32(input: &[u32]) -> Result<Self, Self::DecodeError>;

    /// Decodes big-endian 64-bit words using this integer type's signedness.
    fn from_be_u64(input: &[u64]) -> Result<Self, Self::DecodeError>;

    /// Decodes a non-negative little-endian byte magnitude.
    fn from_unsigned_le_bytes(input: &[u8]) -> Result<Self, Self::DecodeError>;

    /// Decodes a non-negative little-endian 32-bit-word magnitude.
    fn from_unsigned_le_u32(input: &[u32]) -> Result<Self, Self::DecodeError>;

    /// Decodes a non-negative little-endian 64-bit-word magnitude.
    fn from_unsigned_le_u64(input: &[u64]) -> Result<Self, Self::DecodeError>;

    /// Decodes a non-negative big-endian byte magnitude.
    fn from_unsigned_be_bytes(input: &[u8]) -> Result<Self, Self::DecodeError>;

    /// Decodes a non-negative big-endian 32-bit-word magnitude.
    fn from_unsigned_be_u32(input: &[u32]) -> Result<Self, Self::DecodeError>;

    /// Decodes a non-negative big-endian 64-bit-word magnitude.
    fn from_unsigned_be_u64(input: &[u64]) -> Result<Self, Self::DecodeError>;

    /// Writes little-endian bytes into caller-provided storage.
    fn write_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError>;

    /// Writes little-endian 32-bit words into caller-provided storage.
    fn write_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError>;

    /// Writes little-endian 64-bit words into caller-provided storage.
    fn write_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError>;

    /// Writes big-endian bytes into caller-provided storage.
    fn write_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError>;

    /// Writes big-endian 32-bit words into caller-provided storage.
    fn write_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError>;

    /// Writes big-endian 64-bit words into caller-provided storage.
    fn write_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError>;

    /// Writes the shortest non-negative little-endian byte magnitude.
    fn write_unsigned_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError>;

    /// Writes the shortest non-negative little-endian 32-bit-word magnitude.
    fn write_unsigned_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError>;

    /// Writes the shortest non-negative little-endian 64-bit-word magnitude.
    fn write_unsigned_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError>;

    /// Writes the shortest non-negative big-endian byte magnitude.
    fn write_unsigned_be_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError>;

    /// Writes the shortest non-negative big-endian 32-bit-word magnitude.
    fn write_unsigned_be_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError>;

    /// Writes the shortest non-negative big-endian 64-bit-word magnitude.
    fn write_unsigned_be_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError>;

    /// Exact output length of [`Self::write_le_bytes`] and [`Self::write_be_bytes`].
    fn byte_length(&self) -> usize;

    /// Exact output length of the unsigned byte-magnitude writers.
    fn byte_length_unsigned(&self) -> usize;

    /// Exact output length of [`Self::write_le_u32`] and [`Self::write_be_u32`].
    fn u32_length(&self) -> usize;

    /// Exact output length of the unsigned `u32`-magnitude writers.
    fn u32_length_unsigned(&self) -> usize;

    /// Exact output length of [`Self::write_le_u64`] and [`Self::write_be_u64`].
    fn u64_length(&self) -> usize;

    /// Exact output length of the unsigned `u64`-magnitude writers.
    fn u64_length_unsigned(&self) -> usize;

    /// Allocates and returns little-endian bytes.
    #[cfg(feature = "alloc")]
    fn to_le_bytes(&self) -> Vec<u8> {
        let mut output = vec![0; self.byte_length()];
        self.write_le_bytes(&mut output)
            .expect("output has the exact byte length");
        output
    }

    /// Allocates and returns little-endian 32-bit words.
    #[cfg(feature = "alloc")]
    fn to_le_u32(&self) -> Vec<u32> {
        let mut output = vec![0; self.u32_length()];
        self.write_le_u32(&mut output)
            .expect("output has the exact u32 length");
        output
    }

    /// Allocates and returns little-endian 64-bit words.
    #[cfg(feature = "alloc")]
    fn to_le_u64(&self) -> Vec<u64> {
        let mut output = vec![0; self.u64_length()];
        self.write_le_u64(&mut output)
            .expect("output has the exact u64 length");
        output
    }

    /// Allocates and returns big-endian bytes.
    #[cfg(feature = "alloc")]
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut output = vec![0; self.byte_length()];
        self.write_be_bytes(&mut output)
            .expect("output has the exact byte length");
        output
    }

    /// Allocates and returns big-endian 32-bit words.
    #[cfg(feature = "alloc")]
    fn to_be_u32(&self) -> Vec<u32> {
        let mut output = vec![0; self.u32_length()];
        self.write_be_u32(&mut output)
            .expect("output has the exact u32 length");
        output
    }

    /// Allocates and returns big-endian 64-bit words.
    #[cfg(feature = "alloc")]
    fn to_be_u64(&self) -> Vec<u64> {
        let mut output = vec![0; self.u64_length()];
        self.write_be_u64(&mut output)
            .expect("output has the exact u64 length");
        output
    }

    /// Allocates and returns the shortest little-endian byte magnitude.
    #[cfg(feature = "alloc")]
    fn to_unsigned_le_bytes(&self) -> Vec<u8> {
        let mut output = vec![0; self.byte_length_unsigned()];
        self.write_unsigned_le_bytes(&mut output)
            .expect("output has the exact unsigned byte length");
        output
    }

    /// Allocates and returns the shortest little-endian `u32` magnitude.
    #[cfg(feature = "alloc")]
    fn to_unsigned_le_u32(&self) -> Vec<u32> {
        let mut output = vec![0; self.u32_length_unsigned()];
        self.write_unsigned_le_u32(&mut output)
            .expect("output has the exact unsigned u32 length");
        output
    }

    /// Allocates and returns the shortest little-endian `u64` magnitude.
    #[cfg(feature = "alloc")]
    fn to_unsigned_le_u64(&self) -> Vec<u64> {
        let mut output = vec![0; self.u64_length_unsigned()];
        self.write_unsigned_le_u64(&mut output)
            .expect("output has the exact unsigned u64 length");
        output
    }

    /// Allocates and returns the shortest big-endian byte magnitude.
    #[cfg(feature = "alloc")]
    fn to_unsigned_be_bytes(&self) -> Vec<u8> {
        let mut output = vec![0; self.byte_length_unsigned()];
        self.write_unsigned_be_bytes(&mut output)
            .expect("output has the exact unsigned byte length");
        output
    }

    /// Allocates and returns the shortest big-endian `u32` magnitude.
    #[cfg(feature = "alloc")]
    fn to_unsigned_be_u32(&self) -> Vec<u32> {
        let mut output = vec![0; self.u32_length_unsigned()];
        self.write_unsigned_be_u32(&mut output)
            .expect("output has the exact unsigned u32 length");
        output
    }

    /// Allocates and returns the shortest big-endian `u64` magnitude.
    #[cfg(feature = "alloc")]
    fn to_unsigned_be_u64(&self) -> Vec<u64> {
        let mut output = vec![0; self.u64_length_unsigned()];
        self.write_unsigned_be_u64(&mut output)
            .expect("output has the exact unsigned u64 length");
        output
    }
}

use crate::ConversionError;

#[cfg(test)]
mod tests {
    use super::ArrayEncoding;
    use crate::{FixedBigInt, FixedBigUint};

    #[test]
    fn fixed_types_implement_the_shared_contract_without_alloc() {
        type U = FixedBigUint<2>;
        type I = FixedBigInt<2>;

        assert_eq!(
            <U as ArrayEncoding>::from_unsigned_le_bytes(&[42]),
            Ok(U::from(42_u8))
        );
        assert_eq!(
            <I as ArrayEncoding>::from_le_bytes(&[0xfe]),
            Ok(I::from(-2_i8))
        );
        assert_eq!(
            <I as ArrayEncoding>::from_unsigned_le_bytes(&[0xfe]),
            Ok(I::from(254_u16))
        );
        assert_eq!(
            <U as ArrayEncoding>::from_unsigned_be_bytes(&[0x01, 0x00]),
            Ok(U::from(256_u16))
        );
        assert_eq!(
            <I as ArrayEncoding>::from_be_bytes(&[0xff, 0x7f]),
            Ok(I::from(-129_i16))
        );

        let value = I::from(-129_i16);
        let mut magnitude = [0_u8; 1];
        assert_eq!(value.write_unsigned_be_bytes(&mut magnitude), Ok(1));
        assert_eq!(magnitude, [0x81]);
        assert_eq!(value.byte_length_unsigned(), 1);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_types_implement_the_shared_contract() {
        use crate::{BigInt, BigUint};

        assert_eq!(
            <BigUint as ArrayEncoding>::from_le_u32(&[42]),
            Ok(BigUint::from(42_u8))
        );
        assert_eq!(
            <BigInt as ArrayEncoding>::from_le_bytes(&[0xfe]),
            Ok(BigInt::from(-2_i8))
        );
        assert_eq!(ArrayEncoding::to_le_bytes(&BigInt::from(-2_i8)), [0xfe]);
        assert_eq!(
            ArrayEncoding::to_be_bytes(&BigInt::from(-129_i16)),
            [0xff, 0x7f]
        );
        assert_eq!(
            ArrayEncoding::to_unsigned_be_bytes(&BigInt::from(-129_i16)),
            [0x81]
        );
    }
}

//! Little-endian array conversion contracts.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Conversion between integers and little-endian byte or word slices.
///
/// Signed implementations decode `from_le_*` inputs as two's complement.
/// `from_unsigned_le_*` always decodes a non-negative magnitude. Fixed-width
/// implementations report inputs which do not fit through [`Self::DecodeError`].
///
/// # Examples
///
/// ```
/// use tc_bigint3::{ArrayEncoding, U128};
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

    /// Decodes a non-negative little-endian byte magnitude.
    fn from_unsigned_le_bytes(input: &[u8]) -> Result<Self, Self::DecodeError>;

    /// Decodes a non-negative little-endian 32-bit-word magnitude.
    fn from_unsigned_le_u32(input: &[u32]) -> Result<Self, Self::DecodeError>;

    /// Decodes a non-negative little-endian 64-bit-word magnitude.
    fn from_unsigned_le_u64(input: &[u64]) -> Result<Self, Self::DecodeError>;

    /// Writes little-endian bytes into caller-provided storage.
    fn write_le_bytes(&self, output: &mut [u8]) -> Result<usize, ConversionError>;

    /// Writes little-endian 32-bit words into caller-provided storage.
    fn write_le_u32(&self, output: &mut [u32]) -> Result<usize, ConversionError>;

    /// Writes little-endian 64-bit words into caller-provided storage.
    fn write_le_u64(&self, output: &mut [u64]) -> Result<usize, ConversionError>;

    /// Allocates and returns little-endian bytes.
    #[cfg(feature = "alloc")]
    fn to_le_bytes(&self) -> Vec<u8>;

    /// Allocates and returns little-endian 32-bit words.
    #[cfg(feature = "alloc")]
    fn to_le_u32(&self) -> Vec<u32>;

    /// Allocates and returns little-endian 64-bit words.
    #[cfg(feature = "alloc")]
    fn to_le_u64(&self) -> Vec<u64>;
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
    }
}

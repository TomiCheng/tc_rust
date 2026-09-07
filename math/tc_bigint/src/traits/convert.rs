//! Bounds and conversions to and from primitive integers.

/// Values with finite lower and upper bounds.
pub trait Bounded: Sized {
    /// Lowest representable value.
    const MIN: Self;
    /// Highest representable value.
    const MAX: Self;

    /// Returns [`Self::MIN`].
    fn min_value() -> Self {
        Self::MIN
    }

    /// Returns [`Self::MAX`].
    fn max_value() -> Self {
        Self::MAX
    }
}

/// Conversion from primitive numeric types.
pub trait FromPrimitive: Sized {
    /// Converts an `isize`.
    fn from_isize(value: isize) -> Option<Self> {
        Self::from_i64(value as i64)
    }

    /// Converts an `i8`.
    fn from_i8(value: i8) -> Option<Self> {
        Self::from_i64(i64::from(value))
    }

    /// Converts an `i16`.
    fn from_i16(value: i16) -> Option<Self> {
        Self::from_i64(i64::from(value))
    }

    /// Converts an `i32`.
    fn from_i32(value: i32) -> Option<Self> {
        Self::from_i64(i64::from(value))
    }

    /// Converts an `i64`.
    fn from_i64(value: i64) -> Option<Self>;

    /// Converts an `i128`.
    fn from_i128(value: i128) -> Option<Self> {
        i64::try_from(value).ok().and_then(Self::from_i64)
    }

    /// Converts a `usize`.
    fn from_usize(value: usize) -> Option<Self> {
        u64::try_from(value).ok().and_then(Self::from_u64)
    }

    /// Converts a `u8`.
    fn from_u8(value: u8) -> Option<Self> {
        Self::from_u64(u64::from(value))
    }

    /// Converts a `u16`.
    fn from_u16(value: u16) -> Option<Self> {
        Self::from_u64(u64::from(value))
    }

    /// Converts a `u32`.
    fn from_u32(value: u32) -> Option<Self> {
        Self::from_u64(u64::from(value))
    }

    /// Converts a `u64`.
    fn from_u64(value: u64) -> Option<Self>;

    /// Converts a `u128`.
    fn from_u128(value: u128) -> Option<Self> {
        u64::try_from(value).ok().and_then(Self::from_u64)
    }

    /// Converts an `f32`, truncating its fractional part.
    fn from_f32(value: f32) -> Option<Self> {
        Self::from_f64(f64::from(value))
    }

    /// Converts an `f64`, truncating its fractional part.
    fn from_f64(value: f64) -> Option<Self> {
        if value >= i64::MIN as f64 && value < -(i64::MIN as f64) {
            Self::from_i64(value as i64)
        } else if value >= 0.0 && value < u64::MAX as f64 {
            Self::from_u64(value as u64)
        } else {
            None
        }
    }
}

/// Conversion to primitive numeric types.
pub trait ToPrimitive {
    /// Converts to `isize` when representable.
    fn to_isize(&self) -> Option<isize> {
        self.to_i64().and_then(|value| isize::try_from(value).ok())
    }

    /// Converts to `i8` when representable.
    fn to_i8(&self) -> Option<i8> {
        self.to_i64().and_then(|value| i8::try_from(value).ok())
    }

    /// Converts to `i16` when representable.
    fn to_i16(&self) -> Option<i16> {
        self.to_i64().and_then(|value| i16::try_from(value).ok())
    }

    /// Converts to `i32` when representable.
    fn to_i32(&self) -> Option<i32> {
        self.to_i64().and_then(|value| i32::try_from(value).ok())
    }

    /// Converts to `i64` when representable.
    fn to_i64(&self) -> Option<i64>;

    /// Converts to `i128` when representable.
    fn to_i128(&self) -> Option<i128> {
        self.to_i64().map(i128::from)
    }

    /// Converts to `usize` when representable.
    fn to_usize(&self) -> Option<usize> {
        self.to_u64().and_then(|value| usize::try_from(value).ok())
    }

    /// Converts to `u8` when representable.
    fn to_u8(&self) -> Option<u8> {
        self.to_u64().and_then(|value| u8::try_from(value).ok())
    }

    /// Converts to `u16` when representable.
    fn to_u16(&self) -> Option<u16> {
        self.to_u64().and_then(|value| u16::try_from(value).ok())
    }

    /// Converts to `u32` when representable.
    fn to_u32(&self) -> Option<u32> {
        self.to_u64().and_then(|value| u32::try_from(value).ok())
    }

    /// Converts to `u64` when representable.
    fn to_u64(&self) -> Option<u64>;

    /// Converts to `u128` when representable.
    fn to_u128(&self) -> Option<u128> {
        self.to_u64().map(u128::from)
    }

    /// Converts to `f32`.
    fn to_f32(&self) -> Option<f32> {
        self.to_f64().map(|value| value as f32)
    }

    /// Converts to `f64`.
    fn to_f64(&self) -> Option<f64> {
        self.to_i64()
            .map(|value| value as f64)
            .or_else(|| self.to_u64().map(|value| value as f64))
    }
}

#[cfg(test)]
mod tests {
    use super::{Bounded, FromPrimitive, ToPrimitive};
    use crate::{FixedBigInt, FixedBigUint, Word};

    type I = FixedBigInt<{ 128 / Word::BITS as usize }>;
    type U = FixedBigUint<{ 128 / Word::BITS as usize }>;

    #[derive(Debug, Eq, PartialEq)]
    struct PrimitiveProbe(i64);

    impl FromPrimitive for PrimitiveProbe {
        fn from_i64(value: i64) -> Option<Self> {
            Some(Self(value))
        }

        fn from_u64(value: u64) -> Option<Self> {
            i64::try_from(value).ok().map(Self)
        }
    }

    #[test]
    fn bounded_contracts_expose_the_representable_limits() {
        assert_eq!(<U as Bounded>::MIN, U::zero());
        assert_eq!(<U as Bounded>::MAX, U::max_value());
        assert_eq!(<I as Bounded>::MIN, I::min_value());
        assert_eq!(<I as Bounded>::MAX, I::max_value());
    }

    #[test]
    fn from_primitive_default_methods_cover_all_source_types() {
        assert_eq!(U::from_isize(1), Some(U::from(1_u8)));
        assert_eq!(U::from_i8(2), Some(U::from(2_u8)));
        assert_eq!(U::from_i16(3), Some(U::from(3_u8)));
        assert_eq!(U::from_i32(4), Some(U::from(4_u8)));
        assert_eq!(U::from_i128(5), Some(U::from(5_u8)));
        assert_eq!(U::from_usize(6), Some(U::from(6_u8)));
        assert_eq!(U::from_u8(7), Some(U::from(7_u8)));
        assert_eq!(U::from_u16(8), Some(U::from(8_u8)));
        assert_eq!(U::from_u32(9), Some(U::from(9_u8)));
        assert_eq!(U::from_u128(10), Some(U::from(10_u8)));
        assert_eq!(U::from_f32(11.75), Some(U::from(11_u8)));
        assert_eq!(U::from_f64(12.75), Some(U::from(12_u8)));

        assert_eq!(U::from_i8(-1), None);
        assert_eq!(U::from_i128(i128::MAX), Some(U::from(i128::MAX as u128)));
        assert_eq!(U::from_f64(f64::NAN), None);
        assert_eq!(U::from_f64(f64::INFINITY), None);

        assert_eq!(PrimitiveProbe::from_i128(i128::MAX), None);
        assert_eq!(PrimitiveProbe::from_u128(u128::MAX), None);
    }

    #[test]
    fn to_primitive_default_methods_cover_all_destination_types() {
        let value = I::from(42_i8);
        assert_eq!(value.to_isize(), Some(42));
        assert_eq!(value.to_i8(), Some(42));
        assert_eq!(value.to_i16(), Some(42));
        assert_eq!(value.to_i32(), Some(42));
        assert_eq!(value.to_i128(), Some(42));
        assert_eq!(value.to_usize(), Some(42));
        assert_eq!(value.to_u8(), Some(42));
        assert_eq!(value.to_u16(), Some(42));
        assert_eq!(value.to_u32(), Some(42));
        assert_eq!(value.to_u128(), Some(42));
        assert_eq!(value.to_f32(), Some(42.0));
        assert_eq!(value.to_f64(), Some(42.0));

        let negative = I::from(-1_i8);
        assert_eq!(negative.to_usize(), None);
        assert_eq!(negative.to_u8(), None);

        let too_large = U::from(u64::MAX);
        assert_eq!(too_large.to_i8(), None);
        assert_eq!(too_large.to_i64(), None);
        assert_eq!(too_large.to_f64(), Some(u64::MAX as f64));
    }
}

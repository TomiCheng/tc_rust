use crate::invert::invert;
use crate::{BinField, BinPolyError};
use alloc::boxed::Box;
use alloc::vec;
use core::fmt;
use tc_constant_time::{Choice, ConstantTimeEq};
use tc_zeroize::Zeroize;

#[derive(Clone)]
pub struct PaddedBinPoly {
    limbs: Box<[u64]>,
    field: BinField,
}

impl PaddedBinPoly {
    pub fn zero(field: BinField) -> Self {
        Self {
            limbs: vec![0; field.size()].into_boxed_slice(),
            field,
        }
    }

    pub fn one(field: BinField) -> Self {
        let mut value = Self::zero(field);
        value.limbs[0] = 1;
        value
    }

    /// Little-endian limbs. Fails unless there are `field.size()` of them and no bit at
    /// or above `field.n()` is set.
    pub fn from_limbs(field: BinField, limbs: Box<[u64]>) -> Result<Self, BinPolyError> {
        field.check_reduced(&limbs)?;
        Ok(Self { limbs, field })
    }

    pub fn limbs(&self) -> &[u64] {
        &self.limbs
    }

    /// `x + y`, a coefficient-wise XOR. Constant time. Panics when the fields differ.
    pub fn add(&self, rhs: &Self) -> Self {
        assert_eq!(self.field, rhs.field, "polynomials of different fields");
        Self {
            limbs: self
                .limbs
                .iter()
                .zip(&rhs.limbs)
                .map(|(x, y)| x ^ y)
                .collect(),
            field: self.field,
        }
    }

    /// `x · y`. Not constant time on the scalar backend: its table lookups are indexed by
    /// bits of the operands, a cache-timing side channel. Panics when the fields differ.
    pub fn multiply(&self, rhs: &Self) -> Self {
        assert_eq!(self.field, rhs.field, "polynomials of different fields");
        let mut limbs = vec![0; self.limbs.len()].into_boxed_slice();
        self.field.multiply(&self.limbs, &rhs.limbs, &mut limbs);
        Self {
            limbs,
            field: self.field,
        }
    }

    /// `x²`. Constant time.
    pub fn square(&self) -> Self {
        let mut limbs = vec![0; self.limbs.len()].into_boxed_slice();
        self.field.square(&self.limbs, &mut limbs);
        Self {
            limbs,
            field: self.field,
        }
    }

    /// `x^(2^count)`: `count` squarings over one product buffer, `x` itself for `0`.
    /// Constant time; the work grows with `count`, which is public.
    pub fn square_n(&self, count: usize) -> Self {
        if count == 0 {
            return self.clone();
        }
        let mut limbs = vec![0; self.limbs.len()].into_boxed_slice();
        self.field.square_n(&self.limbs, count, &mut limbs);
        Self {
            limbs,
            field: self.field,
        }
    }

    /// `x⁻¹`, and `0` for `0`, by Itoh–Tsujii. Meaningful only when the modulus is
    /// irreducible, which is not checked. As constant time as [`Self::multiply`]: the chain
    /// depends on the degree alone.
    pub fn invert(&self) -> Self {
        let size = self.limbs.len();
        let mut limbs = vec![0; size].into_boxed_slice();
        let mut scratch = vec![0; 2 * size];
        let (b, t) = scratch.split_at_mut(size);
        invert(&self.field, &self.limbs, &mut limbs, b, t);
        Self {
            limbs,
            field: self.field,
        }
    }
}

/// Constant time in the limbs; the fields, and so the lengths, are public.
impl ConstantTimeEq for PaddedBinPoly {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        Choice::from_lsb(u8::from(self.field == rhs.field)) & self.limbs[..].ct_eq(&rhs.limbs[..])
    }
}

/// [`ConstantTimeEq::ct_eq`], revealing only the answer.
impl PartialEq for PaddedBinPoly {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1
    }
}

impl Eq for PaddedBinPoly {}

/// Shows the field only: the value may be secret.
impl fmt::Debug for PaddedBinPoly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaddedBinPoly")
            .field("field", &self.field)
            .finish_non_exhaustive()
    }
}

/// Leaves zero in the same field. Not done on drop: the caller knows if the value is secret.
impl Zeroize for PaddedBinPoly {
    fn zeroize(&mut self) {
        self.limbs.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::PaddedBinPoly;
    use crate::{BinField, BinPolyError};
    use alloc::boxed::Box;
    use tc_constant_time::ConstantTimeEq;
    use tc_zeroize::Zeroize;

    #[test]
    fn zero_and_one_take_their_length_from_the_field() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        assert_eq!(PaddedBinPoly::zero(field).limbs(), [0, 0, 0]);
        assert_eq!(PaddedBinPoly::one(field).limbs(), [1, 0, 0]);
    }

    #[test]
    fn from_limbs_refuses_a_wrong_length_or_bits_at_or_above_the_degree() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let top = (1 << 35) - 1;
        let value = PaddedBinPoly::from_limbs(field, Box::new([u64::MAX, 2, top])).unwrap();
        assert_eq!(value.limbs(), [u64::MAX, 2, top]);
        assert_eq!(
            PaddedBinPoly::from_limbs(field, Box::new([0, 0, 1 << 35])).err(),
            Some(BinPolyError::UnreducedValue)
        );
        assert_eq!(
            PaddedBinPoly::from_limbs(field, Box::new([0, 0])).err(),
            Some(BinPolyError::InvalidLength {
                expected: 3,
                actual: 2
            })
        );

        let aligned = BinField::trinomial(128, 7).unwrap();
        assert!(PaddedBinPoly::from_limbs(aligned, Box::new([u64::MAX; 2])).is_ok());
    }

    #[test]
    fn add_is_a_coefficient_wise_xor_and_every_value_is_its_own_negative() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let x = PaddedBinPoly::from_limbs(field, Box::new([0b1100, 1, 3])).unwrap();
        let y = PaddedBinPoly::from_limbs(field, Box::new([0b1010, 1, 5])).unwrap();
        assert_eq!(x.add(&y).limbs(), [0b0110, 0, 6]);
        assert_eq!(x.add(&x).limbs(), [0, 0, 0]);
    }

    #[test]
    #[should_panic(expected = "polynomials of different fields")]
    fn adding_polynomials_of_different_fields_panics() {
        let x = PaddedBinPoly::one(BinField::pentanomial(163, 3, 6, 7).unwrap());
        let y = PaddedBinPoly::one(BinField::trinomial(163, 7).unwrap());
        x.add(&y);
    }

    #[test]
    fn multiply_folds_x_to_the_n_onto_the_lower_terms_and_keeps_one_as_identity() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let top = PaddedBinPoly::from_limbs(field, Box::new([0, 0, 1 << 34])).unwrap();
        let x = PaddedBinPoly::from_limbs(field, Box::new([0b10, 0, 0])).unwrap();
        assert_eq!(top.multiply(&x).limbs(), [0b1100_1001, 0, 0]);

        let y = PaddedBinPoly::from_limbs(field, Box::new([u64::MAX, 7, (1 << 35) - 1])).unwrap();
        let one = PaddedBinPoly::one(field);
        assert_eq!(y.multiply(&one).limbs(), y.limbs());
    }

    #[test]
    fn squaring_is_multiplying_by_itself() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let x = PaddedBinPoly::from_limbs(field, Box::new([u64::MAX, 7, (1 << 35) - 1])).unwrap();
        assert_eq!(x.square().limbs(), x.multiply(&x).limbs());
    }

    #[test]
    fn square_n_is_squaring_n_times_and_zero_times_is_the_value() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let x = PaddedBinPoly::from_limbs(field, Box::new([u64::MAX, 7, (1 << 35) - 1])).unwrap();
        assert_eq!(x.square_n(0), x);
        assert_eq!(x.square_n(3), x.square().square().square());
    }

    #[test]
    fn invert_gives_the_aes_inverse_and_a_value_times_its_inverse_is_one() {
        let aes = BinField::pentanomial(8, 1, 3, 4).unwrap();
        let x = PaddedBinPoly::from_limbs(aes, Box::new([0x53])).unwrap();
        assert_eq!(x.invert().limbs(), [0xCA]);

        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let y = PaddedBinPoly::from_limbs(field, Box::new([u64::MAX, 7, (1 << 35) - 1])).unwrap();
        assert_eq!(y.multiply(&y.invert()).limbs(), [1, 0, 0]);
    }

    #[test]
    #[should_panic(expected = "polynomials of different fields")]
    fn multiplying_polynomials_of_different_fields_panics() {
        let x = PaddedBinPoly::one(BinField::pentanomial(163, 3, 6, 7).unwrap());
        let y = PaddedBinPoly::one(BinField::trinomial(163, 7).unwrap());
        x.multiply(&y);
    }

    #[test]
    fn equality_needs_every_limb_and_the_field_to_match() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let other = BinField::trinomial(163, 7).unwrap();
        let x = PaddedBinPoly::from_limbs(field, Box::new([1, 2, 3])).unwrap();
        let y = PaddedBinPoly::from_limbs(field, Box::new([1, 2, 2])).unwrap();
        let z = PaddedBinPoly::from_limbs(other, Box::new([1, 2, 3])).unwrap();
        assert_eq!(x.clone(), x);
        assert_ne!(y, x);
        assert_ne!(z, x);
        assert_eq!(
            [x.clone(), y, z].map(|v| v.ct_eq(&x).unwrap_u8()),
            [1, 0, 0]
        );
    }

    #[test]
    fn debug_shows_the_field_but_not_the_value() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let x = PaddedBinPoly::from_limbs(field, Box::new([0xDEAD_BEEF, 0, 0])).unwrap();
        let shown = alloc::format!("{x:?}");
        assert!(shown.starts_with("PaddedBinPoly { field: BinField"));
        assert!(
            !shown.contains("limbs") && !shown.contains(&alloc::format!("{}", 0xDEAD_BEEF_u64))
        );
    }

    #[test]
    fn zeroize_leaves_zero_in_the_same_field() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let mut value = PaddedBinPoly::from_limbs(field, Box::new([u64::MAX, 2, 3])).unwrap();
        value.zeroize();
        assert_eq!(value.limbs(), [0, 0, 0]);
        assert_eq!(value.field, field);
    }
}

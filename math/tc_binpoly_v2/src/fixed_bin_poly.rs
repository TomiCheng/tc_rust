use crate::invert::invert;
use crate::{BinField, BinPolyError};
use core::fmt;
use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
use tc_zeroize::Zeroize;

#[derive(Clone)]
pub struct FixedBinPoly<const N: usize> {
    limbs: [u64; N],
    field: BinField,
}

impl<const N: usize> FixedBinPoly<N> {
    /// Fails unless `N` is `field.size()`.
    pub fn zero(field: BinField) -> Result<Self, BinPolyError> {
        field.check_size(N)?;
        Ok(Self {
            limbs: [0; N],
            field,
        })
    }

    /// Fails unless `N` is `field.size()`.
    pub fn one(field: BinField) -> Result<Self, BinPolyError> {
        let mut value = Self::zero(field)?;
        value.limbs[0] = 1;
        Ok(value)
    }

    /// Little-endian limbs. Fails unless `N` is `field.size()` and no bit at or above
    /// `field.n()` is set.
    pub fn from_limbs(field: BinField, limbs: [u64; N]) -> Result<Self, BinPolyError> {
        field.check_reduced(&limbs)?;
        Ok(Self { limbs, field })
    }

    pub fn limbs(&self) -> &[u64; N] {
        &self.limbs
    }

    pub fn field(&self) -> BinField {
        self.field
    }

    /// `x + y`, a coefficient-wise XOR. Constant time. Panics when the fields differ.
    pub fn add(&self, rhs: &Self) -> Self {
        assert_eq!(self.field, rhs.field, "polynomials of different fields");
        Self {
            limbs: core::array::from_fn(|i| self.limbs[i] ^ rhs.limbs[i]),
            field: self.field,
        }
    }

    /// `x · y`. Not constant time on the scalar backend: its table lookups are indexed by
    /// bits of the operands, a cache-timing side channel. Panics when the fields differ.
    pub fn multiply(&self, rhs: &Self) -> Self {
        assert_eq!(self.field, rhs.field, "polynomials of different fields");
        let mut limbs = [0; N];
        self.field.multiply(&self.limbs, &rhs.limbs, &mut limbs);
        Self {
            limbs,
            field: self.field,
        }
    }

    /// `x²`. Constant time.
    pub fn square(&self) -> Self {
        let mut limbs = [0; N];
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
        let mut limbs = [0; N];
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
        let (mut limbs, mut b, mut t) = ([0; N], [0; N], [0; N]);
        invert(&self.field, &self.limbs, &mut limbs, &mut b, &mut t);
        Self {
            limbs,
            field: self.field,
        }
    }
}

/// Constant time in the limbs; the fields are public.
impl<const N: usize> ConstantTimeEq for FixedBinPoly<N> {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        Choice::from_lsb(u8::from(self.field == rhs.field)) & self.limbs.ct_eq(&rhs.limbs)
    }
}

/// Constant time in the limbs and the choice. Panics when the fields differ.
impl<const N: usize> ConditionallySelectable for FixedBinPoly<N> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        assert_eq!(a.field, b.field, "polynomials of different fields");
        Self {
            limbs: <[u64; N]>::conditional_select(&a.limbs, &b.limbs, choice),
            field: a.field,
        }
    }

    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        assert_eq!(self.field, other.field, "polynomials of different fields");
        self.limbs.conditional_assign(&other.limbs, choice);
    }

    fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        assert_eq!(a.field, b.field, "polynomials of different fields");
        <[u64; N]>::conditional_swap(&mut a.limbs, &mut b.limbs, choice);
    }
}

/// [`ConstantTimeEq::ct_eq`], revealing only the answer.
impl<const N: usize> PartialEq for FixedBinPoly<N> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1
    }
}

impl<const N: usize> Eq for FixedBinPoly<N> {}

/// Shows the field only: the value may be secret.
impl<const N: usize> fmt::Debug for FixedBinPoly<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedBinPoly")
            .field("field", &self.field)
            .finish_non_exhaustive()
    }
}

/// Leaves zero in the same field. Not done on drop: the caller knows if the value is secret.
impl<const N: usize> Zeroize for FixedBinPoly<N> {
    fn zeroize(&mut self) {
        self.limbs.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::FixedBinPoly;
    use crate::{BinField, BinPolyError};
    use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
    use tc_zeroize::Zeroize;

    #[test]
    fn zero_and_one_need_n_to_match_the_field_size() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        assert_eq!(FixedBinPoly::<3>::zero(field).unwrap().limbs(), &[0, 0, 0]);
        assert_eq!(FixedBinPoly::<3>::one(field).unwrap().limbs(), &[1, 0, 0]);
        assert_eq!(
            FixedBinPoly::<4>::zero(field).err(),
            Some(BinPolyError::InvalidLength {
                expected: 3,
                actual: 4
            })
        );
        assert!(FixedBinPoly::<2>::one(field).is_err());
    }

    #[test]
    fn from_limbs_refuses_bits_at_or_above_the_degree() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let top = (1 << 35) - 1;
        let value = FixedBinPoly::from_limbs(field, [u64::MAX, 2, top]).unwrap();
        assert_eq!(value.limbs(), &[u64::MAX, 2, top]);
        assert_eq!(
            FixedBinPoly::from_limbs(field, [0, 0, 1 << 35]).err(),
            Some(BinPolyError::UnreducedValue)
        );
        assert!(FixedBinPoly::from_limbs(field, [0; 4]).is_err());

        let aligned = BinField::trinomial(128, 7).unwrap();
        assert!(FixedBinPoly::from_limbs(aligned, [u64::MAX; 2]).is_ok());
    }

    #[test]
    fn add_is_a_coefficient_wise_xor_and_every_value_is_its_own_negative() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let x = FixedBinPoly::from_limbs(field, [0b1100, 1, 3]).unwrap();
        let y = FixedBinPoly::from_limbs(field, [0b1010, 1, 5]).unwrap();
        assert_eq!(x.add(&y).limbs(), &[0b0110, 0, 6]);
        assert_eq!(x.add(&x).limbs(), &[0, 0, 0]);
    }

    #[test]
    #[should_panic(expected = "polynomials of different fields")]
    fn adding_polynomials_of_different_fields_panics() {
        let x = FixedBinPoly::<3>::one(BinField::pentanomial(163, 3, 6, 7).unwrap()).unwrap();
        let y = FixedBinPoly::<3>::one(BinField::trinomial(163, 7).unwrap()).unwrap();
        x.add(&y);
    }

    #[test]
    fn multiply_folds_x_to_the_n_onto_the_lower_terms_and_keeps_one_as_identity() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let top = FixedBinPoly::from_limbs(field, [0, 0, 1 << 34]).unwrap();
        let x = FixedBinPoly::from_limbs(field, [0b10, 0, 0]).unwrap();
        assert_eq!(top.multiply(&x).limbs(), &[0b1100_1001, 0, 0]);

        let y = FixedBinPoly::from_limbs(field, [u64::MAX, 7, (1 << 35) - 1]).unwrap();
        let one = FixedBinPoly::one(field).unwrap();
        assert_eq!(y.multiply(&one).limbs(), y.limbs());
    }

    #[test]
    fn squaring_is_multiplying_by_itself() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let x = FixedBinPoly::from_limbs(field, [u64::MAX, 7, (1 << 35) - 1]).unwrap();
        assert_eq!(x.square().limbs(), x.multiply(&x).limbs());
    }

    #[test]
    fn square_n_is_squaring_n_times_and_zero_times_is_the_value() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let x = FixedBinPoly::from_limbs(field, [u64::MAX, 7, (1 << 35) - 1]).unwrap();
        assert_eq!(x.square_n(0), x);
        assert_eq!(x.square_n(3), x.square().square().square());
    }

    #[test]
    fn invert_gives_the_aes_inverse_and_a_value_times_its_inverse_is_one() {
        let aes = BinField::pentanomial(8, 1, 3, 4).unwrap();
        let x = FixedBinPoly::from_limbs(aes, [0x53]).unwrap();
        assert_eq!(x.invert().limbs(), &[0xCA]);

        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let y = FixedBinPoly::from_limbs(field, [u64::MAX, 7, (1 << 35) - 1]).unwrap();
        assert_eq!(y.multiply(&y.invert()).limbs(), &[1, 0, 0]);
    }

    #[test]
    #[should_panic(expected = "polynomials of different fields")]
    fn multiplying_polynomials_of_different_fields_panics() {
        let x = FixedBinPoly::<3>::one(BinField::pentanomial(163, 3, 6, 7).unwrap()).unwrap();
        let y = FixedBinPoly::<3>::one(BinField::trinomial(163, 7).unwrap()).unwrap();
        x.multiply(&y);
    }

    #[test]
    fn select_assign_and_swap_follow_the_choice() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let x = FixedBinPoly::from_limbs(field, [1, 2, 3]).unwrap();
        let y = FixedBinPoly::from_limbs(field, [4, 5, 6]).unwrap();
        let (no, yes) = (Choice::from_lsb(0), Choice::from_lsb(1));
        assert_eq!(FixedBinPoly::conditional_select(&x, &y, no), x);
        assert_eq!(FixedBinPoly::conditional_select(&x, &y, yes), y);

        let mut z = x.clone();
        z.conditional_assign(&y, no);
        assert_eq!(z, x);
        z.conditional_assign(&y, yes);
        assert_eq!(z, y);

        let (mut a, mut b) = (x.clone(), y.clone());
        FixedBinPoly::conditional_swap(&mut a, &mut b, no);
        assert_eq!((&a, &b), (&x, &y));
        FixedBinPoly::conditional_swap(&mut a, &mut b, yes);
        assert_eq!((&a, &b), (&y, &x));
    }

    #[test]
    fn equality_needs_every_limb_and_the_field_to_match() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let other = BinField::trinomial(163, 7).unwrap();
        let x = FixedBinPoly::from_limbs(field, [1, 2, 3]).unwrap();
        let y = FixedBinPoly::from_limbs(field, [1, 2, 2]).unwrap();
        let z = FixedBinPoly::from_limbs(other, [1, 2, 3]).unwrap();
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
        let x = FixedBinPoly::from_limbs(field, [0xDEAD_BEEF, 0, 0]).unwrap();
        let shown = alloc::format!("{x:?}");
        assert!(shown.starts_with("FixedBinPoly { field: BinField"));
        assert!(
            !shown.contains("limbs") && !shown.contains(&alloc::format!("{}", 0xDEAD_BEEF_u64))
        );
    }

    #[test]
    fn zeroize_leaves_zero_in_the_same_field() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        let mut value = FixedBinPoly::from_limbs(field, [u64::MAX, 2, 3]).unwrap();
        value.zeroize();
        assert_eq!(value.limbs(), &[0, 0, 0]);
        assert_eq!(value.field, field);
    }
}

//! Selection primitives for fixed-width integers. Dynamic BigUint is excluded:
//! its allocation length and normalization depend on the represented value.
use crate::{Choice, ConditionallySelectable, ConstantTimeEq, FixedBigUint, LimbArray};

impl<const N: usize> ConditionallySelectable for FixedBigUint<N> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            limbs: LimbArray::conditional_select(&a.limbs, &b.limbs, choice),
        }
    }
}
impl<const N: usize> ConstantTimeEq for FixedBigUint<N> {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.limbs.ct_eq(&rhs.limbs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Odd, U128,
        modular::{FixedMontyForm, FixedMontyParams},
    };
    #[test]
    fn fixed_selection_and_secret_montgomery_match_public_arithmetic() {
        for modulus in [
            U128::from(1_u8),
            U128::from(101_u8),
            U128::MAX,
            U128::MAX - U128::from(158_u8),
        ] {
            let params = FixedMontyParams::new(Odd::new(modulus).unwrap());
            for value in [
                U128::zero(),
                U128::from(1_u8),
                U128::MAX,
                U128::MAX - U128::from(1_u8),
            ] {
                let a = FixedMontyForm::new_ct(&value, params);
                let b = FixedMontyForm::new(&value, params);
                assert_eq!(a.ct_eq(&b).unwrap_u8(), 1);
                assert_eq!(a.retrieve(), b.retrieve());
                let zero = FixedMontyForm::zero(params);
                assert_eq!(
                    FixedMontyForm::conditional_select(&zero, &a, Choice::from_lsb(1)),
                    a
                );
                for exponent in [U128::zero(), U128::from(19_u8), U128::MAX] {
                    assert_eq!(a.pow_ct(&exponent), b.pow(&exponent));
                }
            }
        }
        assert_eq!(U128::MAX.ct_eq(&U128::zero()).unwrap_u8(), 0);
        assert_eq!(
            U128::conditional_select(&U128::MAX, &U128::zero(), Choice::from_lsb(0)),
            U128::MAX
        );
    }
}

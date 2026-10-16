use crate::{BinField, BinPolyError};
use alloc::boxed::Box;
use alloc::vec;
use tc_zeroize::Zeroize;

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
    #[should_panic(expected = "polynomials of different fields")]
    fn multiplying_polynomials_of_different_fields_panics() {
        let x = PaddedBinPoly::one(BinField::pentanomial(163, 3, 6, 7).unwrap());
        let y = PaddedBinPoly::one(BinField::trinomial(163, 7).unwrap());
        x.multiply(&y);
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

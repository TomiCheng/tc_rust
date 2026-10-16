use crate::{BinField, BinPolyError};
use alloc::boxed::Box;
use alloc::vec;

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
}

#[cfg(test)]
mod tests {
    use super::PaddedBinPoly;
    use crate::{BinField, BinPolyError};
    use alloc::boxed::Box;

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
}

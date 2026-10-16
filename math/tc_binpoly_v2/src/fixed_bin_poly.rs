use crate::{BinField, BinPolyError};

pub struct FixedBinPoly<const N: usize> {
    limbs: [u64; N],
    field: BinField,
}

impl<const N: usize> FixedBinPoly<N> {
    /// Fails unless `N` is `field.size()`.
    pub fn zero(field: BinField) -> Result<Self, BinPolyError> {
        if N != field.size() {
            return Err(BinPolyError::InvalidLength {
                expected: field.size(),
                actual: N,
            });
        }
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
}

#[cfg(test)]
mod tests {
    use super::FixedBinPoly;
    use crate::{BinField, BinPolyError};

    #[test]
    fn zero_and_one_need_n_to_match_the_field_size() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        assert_eq!(FixedBinPoly::<3>::zero(field).unwrap().limbs, [0, 0, 0]);
        assert_eq!(FixedBinPoly::<3>::one(field).unwrap().limbs, [1, 0, 0]);
        assert_eq!(
            FixedBinPoly::<4>::zero(field).err(),
            Some(BinPolyError::InvalidLength {
                expected: 3,
                actual: 4
            })
        );
        assert!(FixedBinPoly::<2>::one(field).is_err());
    }
}

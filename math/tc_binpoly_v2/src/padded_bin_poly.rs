use crate::BinField;
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
}

#[cfg(test)]
mod tests {
    use super::PaddedBinPoly;
    use crate::BinField;

    #[test]
    fn zero_and_one_take_their_length_from_the_field() {
        let field = BinField::pentanomial(163, 3, 6, 7).unwrap();
        assert_eq!(*PaddedBinPoly::zero(field).limbs, [0, 0, 0]);
        assert_eq!(*PaddedBinPoly::one(field).limbs, [1, 0, 0]);
    }
}
